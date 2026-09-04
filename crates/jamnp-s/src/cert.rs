//! Ed25519 self-signed X.509 certificate generation and verification per
//! `jam-np/simple.md:7-23,30-43`.
//!
//! A peer certificate must: be signed with Ed25519, carry the peer's Ed25519
//! key, and have exactly one DNS SAN equal to `"e"` ++ base32 of the key
//! (`simple.md:12-16`). Certificates are self-signed; the signature itself is
//! not cryptographically verified (`simple.md:18`), but the key/SAN
//! consistency always is (`simple.md:22-23`).

use ed25519_consensus::{SigningKey, VerificationKey};
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use x509_parser::{
    extensions::{GeneralName, ParsedExtension},
    prelude::{parse_x509_certificate, AlgorithmIdentifier},
};

use crate::base32;

/// The DER content of the Ed25519 algorithm OID (`1.3.101.112`).
const ED25519_OID: &[u8] = &[0x2b, 0x65, 0x70];

fn is_ed25519(alg: &AlgorithmIdentifier<'_>) -> bool {
    alg.algorithm.as_bytes() == ED25519_OID
}

/// `N(k) = "e" ++ B(E_32^-1(k), 52)` (`simple.md:41`).
pub fn san_for_key(pubkey: &VerificationKey) -> String {
    let mut san = String::with_capacity(1 + base32::LEN);
    san.push('e');
    san.push_str(&base32::encode(pubkey.as_bytes()));
    san
}

/// RFC 5958 PKCS#8 v1 DER wrapping the 32-byte Ed25519 seed.
///
/// `ed25519-consensus` exposes only the raw seed (`SigningKey::to_bytes`),
/// which IS the Ed25519 private key. ring (rcgen's backend) compares the
/// `AlgorithmIdentifier` byte-for-byte with its template, which is
/// `SEQUENCE { OID 1.3.101.112 }` with no `NULL` parameters, so the structure
/// is fixed and always valid:
/// `SEQUENCE { INTEGER 0, SEQUENCE { OID Ed25519 }, OCTET STRING { OCTET
/// STRING { seed } } }`.
fn pkcs8_ed25519(seed: &[u8; 32]) -> Vec<u8> {
    let mut der = Vec::with_capacity(48);
    der.extend_from_slice(&[
        0x30, 0x2e, // SEQUENCE (46 content bytes)
        0x02, 0x01, 0x00, // version 0
        0x30, 0x05, // AlgorithmIdentifier SEQUENCE
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
        0x04, 0x22, // outer OCTET STRING (34)
        0x04, 0x20, // inner OCTET STRING (32)
    ]);
    der.extend_from_slice(seed);
    der
}

/// Sign the self-signed certificate for `secret`, returning it with the
/// verification key it embeds.
fn signed_cert(
    secret: &SigningKey,
) -> Result<(CertificateDer<'static>, VerificationKey), rcgen::Error> {
    let vk = secret.verification_key();
    // rcgen's default validity (1975-01-01..4096-01-01) is a generous window,
    // so no explicit dates are needed.
    let params = CertificateParams::new([san_for_key(&vk)])?;
    let keypair = KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(pkcs8_ed25519(secret.as_bytes()).as_slice()),
        &PKCS_ED25519,
    )?;
    let cert = params.self_signed(&keypair)?;
    Ok((cert.der().clone(), vk))
}

/// Builds the self-signed Ed25519 X.509 certificate for `secret`
/// (`simple.md:9-18`): exactly one DNS SAN `"e"` ++ base32 of the key, signed
/// by the corresponding key.
pub fn build_cert(
    secret: &SigningKey,
) -> Result<(CertificateDer<'static>, VerificationKey), CertError> {
    signed_cert(secret).map_err(CertError::from)
}

/// Verified peer certificate: the extracted Ed25519 key and its SAN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCert {
    pub pubkey: VerificationKey,
    pub san: String,
}

/// Error returned when a peer certificate fails JAMNP-S validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertError {
    /// The DER could not be parsed as an X.509 certificate.
    Parse,
    /// Certificate generation failed.
    Rcgen(String),
    /// The certificate signature algorithm is not Ed25519.
    NotEd25519Signature,
    /// Not exactly one SAN extension with exactly one name.
    BadSanCount,
    /// The single SAN is not a DNSName equal to the key's base32 form.
    BadSan,
    /// The subject public key is not a 32-byte Ed25519 key.
    BadPublicKey,
    /// The certificate key does not match the expected key.
    KeyMismatch,
}

impl From<rcgen::Error> for CertError {
    fn from(e: rcgen::Error) -> Self {
        CertError::Rcgen(e.to_string())
    }
}

impl core::fmt::Display for CertError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            CertError::Parse => "malformed X.509 certificate",
            CertError::Rcgen(e) => return write!(f, "certificate generation failed: {e}"),
            CertError::NotEd25519Signature => "certificate is not signed with Ed25519",
            CertError::BadSanCount => "certificate must have exactly one SAN with exactly one name",
            CertError::BadSan => "SAN does not match the certificate's Ed25519 key",
            CertError::BadPublicKey => "subject public key is not a 32-byte Ed25519 key",
            CertError::KeyMismatch => "certificate key does not match the expected key",
        })
    }
}

/// Verifies a peer certificate per `simple.md:12-16,20-23`, returning the
/// extracted key and SAN.
///
/// Checks: the DER parses, the signature algorithm is Ed25519, the subject
/// public key is a 32-byte Ed25519 key, there is exactly one SAN extension
/// with exactly one DNSName equal to `san_for_key(key)`, and (if given) the
/// key matches `expected_key`.
pub fn verify_cert<'a>(
    der: &CertificateDer<'a>,
    expected_key: Option<&VerificationKey>,
) -> Result<PeerCert, CertError> {
    let (remainder, cert) = parse_x509_certificate(der.as_ref()).map_err(|_| CertError::Parse)?;
    if !remainder.is_empty() {
        return Err(CertError::Parse);
    }

    // (1) signature algorithm is Ed25519 (`simple.md:12`).
    if !is_ed25519(&cert.signature_algorithm) {
        return Err(CertError::NotEd25519Signature);
    }

    // (3) subject public key is a 32-byte Ed25519 key (`simple.md:13`).
    let pki = &cert.subject_pki;
    if !is_ed25519(&pki.algorithm) {
        return Err(CertError::BadPublicKey);
    }
    if pki.subject_public_key.unused_bits != 0 {
        return Err(CertError::BadPublicKey);
    }
    let key_bytes: [u8; 32] = pki
        .subject_public_key
        .as_ref()
        .try_into()
        .map_err(|_| CertError::BadPublicKey)?;
    let pubkey = VerificationKey::try_from(key_bytes).map_err(|_| CertError::BadPublicKey)?;

    // (4) expected key, if any, must match (`simple.md:21-23`).
    if let Some(expected) = expected_key {
        if expected.as_bytes() != &key_bytes {
            return Err(CertError::KeyMismatch);
        }
    }

    // (2) exactly one SAN extension with exactly one DNSName equal to the
    // key's base32 form (`simple.md:15-16`).
    let mut san = None;
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(ext_san) = ext.parsed_extension() {
            if san.is_some() {
                return Err(CertError::BadSanCount);
            }
            san = Some(ext_san);
        }
    }
    let san = san.ok_or(CertError::BadSanCount)?;
    let [GeneralName::DNSName(name)] = san.general_names.as_slice() else {
        return Err(CertError::BadSanCount);
    };
    if *name != san_for_key(&pubkey) {
        return Err(CertError::BadSan);
    }

    Ok(PeerCert {
        pubkey,
        san: name.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::{build_cert, pkcs8_ed25519, san_for_key, verify_cert, CertError, PeerCert};
    use ed25519_consensus::SigningKey;
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
    use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use x509_parser::{
        extensions::{GeneralName, ParsedExtension},
        prelude::parse_x509_certificate,
    };

    fn test_secret() -> SigningKey {
        SigningKey::from([7u8; 32])
    }

    fn other_secret() -> SigningKey {
        SigningKey::from([9u8; 32])
    }

    /// KeyPair for `secret` via the same RFC 5958 PKCS#8 path as `build_cert`.
    fn keypair(secret: &SigningKey) -> KeyPair {
        KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(pkcs8_ed25519(secret.as_bytes()).as_slice()),
            &PKCS_ED25519,
        )
        .expect("pkcs8 from seed parses")
    }

    fn only_san<'a>(der: &'a CertificateDer<'static>) -> &'a str {
        let (rem, cert) = parse_x509_certificate(der.as_ref()).expect("parses");
        assert!(rem.is_empty());
        let mut san_exts =
            cert.extensions()
                .iter()
                .filter_map(|ext| match ext.parsed_extension() {
                    ParsedExtension::SubjectAlternativeName(san) => Some(san),
                    _ => None,
                });
        let san = san_exts.next().expect("exactly one SAN extension");
        assert!(san_exts.next().is_none(), "exactly one SAN extension");
        assert_eq!(san.general_names.len(), 1, "exactly one general name");
        let GeneralName::DNSName(name) = &san.general_names[0] else {
            panic!("SAN must be a DNSName");
        };
        name
    }

    #[test]
    fn build_cert_verifies_with_matching_key_and_san() {
        let secret = test_secret();
        let (der, vk) = build_cert(&secret).unwrap();
        assert_eq!(vk, secret.verification_key());
        let peer = verify_cert(&der, None).expect("verify_cert accepts build_cert output");
        assert_eq!(peer.pubkey, vk);
        assert_eq!(peer.san, san_for_key(&vk));
        assert_eq!(peer.san.len(), 1 + 52);
        assert!(peer.san.starts_with('e'));
    }

    #[test]
    fn build_cert_has_exactly_one_dnsname_san() {
        let secret = test_secret();
        let (der, _vk) = build_cert(&secret).unwrap();
        assert_eq!(only_san(&der), san_for_key(&secret.verification_key()));
    }

    #[test]
    fn build_cert_uses_ed25519_signature_algorithm() {
        let (der, _vk) = build_cert(&test_secret()).unwrap();
        let (rem, cert) = parse_x509_certificate(der.as_ref()).expect("parses");
        assert!(rem.is_empty());
        assert_eq!(
            cert.signature_algorithm.algorithm.as_bytes(),
            super::ED25519_OID
        );
        assert_eq!(
            cert.subject_pki.algorithm.algorithm.as_bytes(),
            super::ED25519_OID
        );
    }

    #[test]
    fn verify_cert_accepts_matching_expected_key() {
        let secret = test_secret();
        let (der, vk) = build_cert(&secret).unwrap();
        let peer = verify_cert(&der, Some(&vk)).expect("expected key matches");
        assert_eq!(peer.pubkey, vk);
    }

    #[test]
    fn verify_cert_rejects_wrong_expected_key() {
        let (der, _vk) = build_cert(&test_secret()).unwrap();
        let wrong = other_secret().verification_key();
        assert_eq!(verify_cert(&der, Some(&wrong)), Err(CertError::KeyMismatch));
    }

    #[test]
    fn verify_cert_rejects_san_of_a_different_key() {
        let secret = test_secret();
        let other_vk = other_secret().verification_key();
        let params = CertificateParams::new([san_for_key(&other_vk)]).expect("valid SAN");
        let cert = params.self_signed(&keypair(&secret)).expect("self-signs");
        let der = cert.der().clone();
        assert_eq!(verify_cert(&der, None), Err(CertError::BadSan));
    }

    #[test]
    fn verify_cert_rejects_non_ed25519_certificate() {
        let ec = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ec keypair");
        let params = CertificateParams::new(["example.com".to_string()]).expect("valid SAN");
        let cert = params.self_signed(&ec).expect("ec self-signs");
        let der = cert.der().clone();
        assert_eq!(verify_cert(&der, None), Err(CertError::NotEd25519Signature));
    }

    #[test]
    fn verify_cert_rejects_malformed_der() {
        let der = CertificateDer::from(vec![0x30, 0x03, 0x01, 0x02, 0x03]);
        assert_eq!(verify_cert(&der, None), Err(CertError::Parse));
    }

    #[test]
    fn peer_cert_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<PeerCert>();
    }
}

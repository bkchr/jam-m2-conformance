//! QUIC/TLS endpoint: certificate-authenticated connections per
//! `jam-np/simple.md:5-99`.
//!
//! [`Endpoint::serve`] binds a QUIC listener presenting a self-signed Ed25519
//! certificate; [`Endpoint::connect`] dials a peer and authenticates it against
//! the expected key's SAN. Both sides use TLS 1.3 with the JAMNP-S ALPN
//! identifiers from `crate::alpn` (`simple.md:48-59`).

use std::net::SocketAddr;
use std::sync::Arc;

use ed25519_consensus::{SigningKey, VerificationKey};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

use crate::alpn::{builder_protocol_id, protocol_id};
use crate::cert::{self, CertError};

/// Preferred Initiator tie-break for pairwise connections (`simple.md:70-80`).
pub use crate::preferred::preferred_initiator;

/// Endpoint configuration: chain identity and builder role (`simple.md:48-59`).
#[derive(Clone, Debug)]
pub struct EndpointConfig {
    /// Genesis header hash; its first 8 nibbles form the ALPN chain id.
    pub genesis_hash: [u8; 32],
    /// Whether this endpoint identifies as a work-package builder when dialing.
    pub builder: bool,
}

/// Errors constructing or dialing an endpoint.
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    /// Certificate handling failed.
    #[error("certificate error: {0}")]
    Cert(CertError),
    /// The TLS configuration is not usable with QUIC.
    #[error("TLS configuration error: {0}")]
    Tls(String),
    /// Dialing the peer failed.
    #[error("QUIC connect error: {0}")]
    Quic(#[from] quinn::ConnectError),
    /// The handshake or established connection failed.
    #[error("connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),
    /// Binding or I/O failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// A QUIC/TLS endpoint presenting `secret`'s Ed25519 identity.
#[derive(Debug)]
pub struct Endpoint {
    quic: quinn::Endpoint,
    addr: SocketAddr,
}

impl Endpoint {
    /// Bind a QUIC listener presenting a self-signed certificate for `secret`.
    ///
    /// The server advertises both the plain and `/builder` ALPN identifiers
    /// (`simple.md:55`) and requires a JAMNP-S-valid client certificate.
    pub async fn serve(
        config: EndpointConfig,
        secret: SigningKey,
        addr: SocketAddr,
    ) -> Result<Self, EndpointError> {
        let certified_key = certified_key(secret)?;

        let mut server = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| EndpointError::Tls(e.to_string()))?
            .with_client_cert_verifier(Arc::new(ClientVerifier))
            .with_cert_resolver(Arc::new(certified_key));
        server.alpn_protocols = vec![
            protocol_id(&config.genesis_hash),
            builder_protocol_id(&config.genesis_hash),
        ];

        let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(server)
            .map_err(|e| EndpointError::Tls(e.to_string()))?;
        let quic = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(quic_server)),
            addr,
        )?;
        let addr = quic.local_addr()?;
        Ok(Self { quic, addr })
    }

    /// Dial `addr`, authenticating the peer against `server_name` (the expected
    /// peer key's SAN). The client presents its own certificate for `secret`.
    pub async fn connect(
        config: EndpointConfig,
        secret: SigningKey,
        server_name: String,
        addr: SocketAddr,
    ) -> Result<quinn::Connection, EndpointError> {
        let certified_key = certified_key(secret)?;

        let mut client = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| EndpointError::Tls(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ServerVerifier))
            .with_client_cert_resolver(Arc::new(certified_key));
        client.alpn_protocols = if config.builder {
            vec![builder_protocol_id(&config.genesis_hash)]
        } else {
            vec![protocol_id(&config.genesis_hash)]
        };

        let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(client)
            .map_err(|e| EndpointError::Tls(e.to_string()))?;
        let quic = quinn::Endpoint::client((std::net::Ipv4Addr::LOCALHOST, 0).into())?;
        let connecting = quic.connect_with(
            quinn::ClientConfig::new(Arc::new(quic_client)),
            addr,
            &server_name,
        )?;
        Ok(connecting.await?)
    }

    /// Accept the next incoming connection attempt.
    pub fn accept(&self) -> quinn::Accept<'_> {
        self.quic.accept()
    }

    /// The bound local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Close all connections and stop accepting new ones.
    pub fn close(&self) {
        self.quic.close(quinn::VarInt::from_u32(0), b"");
    }
}

/// The shared crypto provider (ring).
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The certificate chain and signing key for `secret`, shared between the
/// client and server certificate resolvers.
fn certified_key(secret: SigningKey) -> Result<rustls::sign::SingleCertAndKey, EndpointError> {
    let (cert, _vk) = cert::build_cert(&secret).map_err(EndpointError::Cert)?;
    Ok(rustls::sign::SingleCertAndKey::from(
        rustls::sign::CertifiedKey {
            cert: vec![cert],
            key: Arc::new(Ed25519SigningKey(secret)),
            ocsp: None,
        },
    ))
}

/// A `rustls::sign::SigningKey` backed by an Ed25519 secret key.
#[derive(Clone, Debug)]
struct Ed25519SigningKey(SigningKey);

impl rustls::sign::Signer for Ed25519SigningKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        Ok(self.0.sign(message).to_bytes().to_vec())
    }

    fn scheme(&self) -> rustls::SignatureScheme {
        rustls::SignatureScheme::ED25519
    }
}

impl rustls::sign::SigningKey for Ed25519SigningKey {
    fn choose_scheme(
        &self,
        offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        offered
            .contains(&rustls::SignatureScheme::ED25519)
            .then(|| Box::new(self.clone()) as Box<dyn rustls::sign::Signer>)
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ED25519
    }
}

/// Server certificate verifier (client side): the peer cert must meet the
/// JAMNP-S requirements and its key must match the expected peer key, derived
/// from the requested SAN (`simple.md:21-23`).
#[derive(Debug)]
struct ServerVerifier;

impl rustls::client::danger::ServerCertVerifier for ServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let ServerName::DnsName(name) = server_name else {
            return Err(not_valid_for_name());
        };
        let expected = san_to_key(name.as_ref()).ok_or_else(not_valid_for_name)?;
        cert::verify_cert(end_entity, Some(&expected)).map_err(cert_err)?;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(tls12_unsupported())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}

/// Client certificate verifier (server side): a client certificate is required
/// and must meet the JAMNP-S requirements (`simple.md:9-23`).
#[derive(Debug)]
struct ClientVerifier;

impl rustls::server::danger::ClientCertVerifier for ClientVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        cert::verify_cert(end_entity, None).map_err(cert_err)?;
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(tls12_unsupported())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }
}

/// Verify the TLS 1.3 handshake signature against the Ed25519 key embedded in
/// the peer's certificate.
fn verify_tls13_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &rustls::DigitallySignedStruct,
) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
    use rustls::client::danger::HandshakeSignatureValid;

    if dss.scheme != rustls::SignatureScheme::ED25519 {
        return Err(rustls::Error::PeerMisbehaved(
            rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
        ));
    }
    let peer = cert::verify_cert(cert, None).map_err(cert_err)?;
    let signature =
        ed25519_consensus::Signature::try_from(dss.signature()).map_err(|_| bad_signature())?;
    peer.pubkey
        .verify(&signature, message)
        .map_err(|_| bad_signature())?;
    Ok(HandshakeSignatureValid::assertion())
}

/// Decode the JAMNP-S alternative name back into the expected peer key.
fn san_to_key(san: &str) -> Option<VerificationKey> {
    let bytes = crate::base32::decode(san.strip_prefix('e')?)?;
    VerificationKey::try_from(bytes).ok()
}

/// Map a JAMNP-S certificate error onto a TLS certificate error.
fn cert_err(err: CertError) -> rustls::Error {
    use rustls::CertificateError;
    match err {
        CertError::Parse | CertError::BadPublicKey => {
            rustls::Error::InvalidCertificate(CertificateError::BadEncoding)
        }
        CertError::NotEd25519Signature | CertError::BadSanCount | CertError::BadSan => {
            rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
        }
        CertError::Rcgen(_) => {
            rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
        }
        CertError::KeyMismatch => {
            rustls::Error::InvalidCertificate(CertificateError::NotValidForName)
        }
    }
}

fn bad_signature() -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature)
}

fn not_valid_for_name() -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName)
}

fn tls12_unsupported() -> rustls::Error {
    rustls::Error::General("TLS 1.2 is not supported".into())
}

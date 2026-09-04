//! Codecs for CE 141 (assurance), 142 (preimage announcement), 143 (preimage
//! request), 144 (audit announcement) and 145 (judgment) per `jam-np/simple.md`
//! (`:675-833`).

use codec::{Decode, Encode, Input, Output};
use jam_types::HeaderHash;

/// CE 141: Assurance distribution (`simple.md:675-695`).
///
/// `Assurance = Header Hash (Anchor) ++ Bitfield ++ Ed25519 Signature`
/// (`simple.md:688`). The bitfield is `[u8; ceil(C / 8)]` in the GP; it is
/// modelled as a `Vec<u8>` and length-checked by the validator, not the codec.
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct Assurance {
    /// Header hash of the block being assured.
    pub anchor: HeaderHash,
    /// One bit per core; one byte covers 8 cores.
    pub bitfield: Vec<u8>,
    /// Ed25519 signature over the assurance.
    pub signature: [u8; 64],
}

/// CE 142: Preimage announcement (`simple.md:697-721`).
///
/// `Service ID ++ Hash ++ Preimage Length` (`simple.md:718`).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct PreimageAnnouncement {
    /// The service the preimage was requested by.
    pub service_id: u32,
    /// Hash of the announced preimage.
    pub hash: [u8; 32],
    /// Length of the announced preimage.
    pub length: u32,
}

/// CE 143: Preimage request (`simple.md:723-741`).
///
/// `--> Hash` (`simple.md:737`).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct PreimageRequest {
    /// Hash of the requested preimage.
    pub hash: [u8; 32],
}

/// CE 143 reply: `Preimage = [u8]` (`simple.md:733,739`).
///
/// The preimage is sent as raw bytes with no length prefix: its length is
/// already known from the CE 142 announcement. Decoding consumes the whole
/// remaining message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreimageReply {
    /// The raw preimage bytes.
    pub preimage: Vec<u8>,
}

impl Encode for PreimageReply {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        dest.write(&self.preimage);
    }
}

impl Decode for PreimageReply {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        // The preimage has no length prefix on the wire; the whole remaining
        // message is the preimage.
        let mut preimage = Vec::new();
        while let Ok(byte) = input.read_byte() {
            preimage.push(byte);
        }
        Ok(Self { preimage })
    }
}

/// CE 144: Audit announcement (`simple.md:743-793`).
///
/// `Announcement = len++[Core Index ++ Work-Report Hash] ++ Ed25519 Signature`
/// (`simple.md:779`).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct Announcement {
    /// Cores and work-report hashes the auditor intends to audit.
    pub entries: Vec<(u16, [u8; 32])>,
    /// Ed25519 signature over the announcement.
    pub signature: [u8; 64],
}

/// CE 144 first message: `Header Hash ++ Tranche ++ Announcement`
/// (`simple.md:789`). The `Evidence` for the tranche is sent as a separate
/// follow-up message.
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct AuditAnnouncementMsg {
    /// Header hash of the block being audited.
    pub header_hash: HeaderHash,
    /// Tranche in which the auditor committed to the work.
    pub tranche: u8,
    /// The announced work-reports.
    pub announcement: Announcement,
}

/// CE 144 subsequent-tranche evidence for one announced work-report
/// (`simple.md:784`): `Bandersnatch Signature ++ len++[No-Show]`.
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct SubsequentEvidence {
    /// Bandersnatch signature `s_n(w)` over the work-report.
    pub s_n: [u8; 96],
    /// `No-Show = Validator Index ++ Announcement` (`simple.md:783`).
    pub no_shows: Vec<(u16, Announcement)>,
}

/// CE 144 evidence (`simple.md:785`): first-tranche evidence is a single
/// Bandersnatch signature; later tranches carry one [`SubsequentEvidence`] per
/// announced work-report. There is no on-wire discriminant — the variant is
/// determined by the tranche from the preceding [`AuditAnnouncementMsg`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Evidence {
    /// `First Tranche Evidence = Bandersnatch Signature (s_0 in GP)`
    /// (`simple.md:782`).
    Tranche0([u8; 96]),
    /// `Subsequent Tranche Evidence = [Bandersnatch Signature ++
    /// len++[No-Show]]` (`simple.md:784`).
    Subsequent(Vec<SubsequentEvidence>),
}

impl Encode for Evidence {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        match self {
            Evidence::Tranche0(sig) => dest.write(sig),
            Evidence::Subsequent(evidence) => evidence.encode_to(dest),
        }
    }
}

impl Evidence {
    /// Decode evidence given the tranche from the preceding announcement.
    pub fn decode_with_tranche<I: Input>(input: &mut I, tranche: u8) -> Result<Self, codec::Error> {
        if tranche == 0 {
            let mut sig = [0u8; 96];
            input.read(&mut sig)?;
            Ok(Evidence::Tranche0(sig))
        } else {
            Vec::<SubsequentEvidence>::decode(input).map(Evidence::Subsequent)
        }
    }
}

/// CE 145: Judgment publication (`simple.md:795-833`).
///
/// `GuaranteeSignature = Validator Index ++ Ed25519 Signature` (`simple.md:824`).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct GuaranteeSignature {
    /// Index of the guaranteeing validator.
    pub validator_index: u16,
    /// Ed25519 signature over the work-report.
    pub signature: [u8; 64],
}

/// `Guarantee = Slot ++ len++[GuaranteeSignature]` (`simple.md:825`).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct Guarantee {
    /// Slot in which the report could be included on chain.
    pub slot: u32,
    /// Guaranteeing validator signatures (2 or 3 in practice).
    pub signatures: Vec<GuaranteeSignature>,
}

/// CE 145 message: `Epoch Index ++ Validator Index ++ Validity ++ Work-Report
/// Hash ++ Ed25519 Signature`, followed by an optional [`Guarantee`] present if
/// and only if `Validity == 0` (`simple.md:829-830`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Judgment {
    /// Epoch the reporting validator belongs to.
    pub epoch_index: u32,
    /// Index of the judging validator.
    pub validator_index: u16,
    /// `Validity = 0 (Invalid) OR 1 (Valid) (Single byte)` (`simple.md:823`).
    pub validity: bool,
    /// Hash of the judged work-report.
    pub report_hash: [u8; 32],
    /// Ed25519 signature over the judgment.
    pub signature: [u8; 64],
    /// Guarantees supporting the report; present iff `validity == false`.
    pub guarantee: Option<Guarantee>,
}

impl Encode for Judgment {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        self.epoch_index.encode_to(dest);
        self.validator_index.encode_to(dest);
        dest.push_byte(u8::from(self.validity));
        dest.write(&self.report_hash);
        dest.write(&self.signature);
        if !self.validity {
            if let Some(guarantee) = &self.guarantee {
                guarantee.encode_to(dest);
            }
        }
    }
}

impl Decode for Judgment {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        let epoch_index = u32::decode(input)?;
        let validator_index = u16::decode(input)?;
        let validity = match input.read_byte()? {
            0 => false,
            1 => true,
            _other => return Err(codec::Error::from("judgment validity byte must be 0 or 1")),
        };
        let mut report_hash = [0u8; 32];
        input.read(&mut report_hash)?;
        let mut signature = [0u8; 64];
        input.read(&mut signature)?;
        let guarantee = if validity {
            None
        } else {
            Some(Guarantee::decode(input)?)
        };
        Ok(Self {
            epoch_index,
            validator_index,
            validity,
            report_hash,
            signature,
            guarantee,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::{Decode, Encode};
    use jam_types::HeaderHash;

    /// 64-byte Ed25519 signature with `sig[i] = (i + offset) mod 256`.
    fn sig64(offset: u8) -> [u8; 64] {
        core::array::from_fn(|i| (i as u8).wrapping_add(offset))
    }

    /// 96-byte Bandersnatch signature with `sig[i] = (i + offset) mod 256`.
    fn sig96(offset: u8) -> [u8; 96] {
        core::array::from_fn(|i| (i as u8).wrapping_add(offset))
    }

    // --- CE 141: Assurance -------------------------------------------------

    #[test]
    fn assurance_vector_2byte_bitfield() {
        let a = Assurance {
            anchor: HeaderHash::from([0x11; 32]),
            bitfield: vec![0xaa, 0xbb],
            signature: sig64(0x30),
        };
        let bytes = a.encode();
        let mut expected = vec![0x11; 32]; // Header Hash (Anchor)
        expected.extend_from_slice(&[0x02, 0xaa, 0xbb]); // compact(2) ++ Bitfield
        expected.extend_from_slice(&sig64(0x30)); // Ed25519 Signature
        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), 32 + 3 + 64);
    }

    #[test]
    fn assurance_roundtrip() {
        let a = Assurance {
            anchor: HeaderHash::from([0x22; 32]),
            bitfield: vec![0xcc],
            signature: sig64(0x10),
        };
        let bytes = a.encode();
        let mut input: &[u8] = &bytes[..];
        let decoded = Assurance::decode(&mut input).unwrap();
        assert!(input.is_empty());
        assert_eq!(decoded, a);
    }

    #[test]
    fn assurance_truncated_errs() {
        // Header hash only.
        let mut input: &[u8] = &[0x11; 32];
        assert!(Assurance::decode(&mut input).is_err());
        // Header hash + bitfield but missing the 64-byte signature.
        let mut bytes = vec![0x11; 32];
        bytes.extend_from_slice(&[0x02, 0xaa, 0xbb]);
        bytes.extend_from_slice(&[0u8; 63]);
        let mut input: &[u8] = &bytes[..];
        assert!(Assurance::decode(&mut input).is_err());
        // Empty.
        let mut input: &[u8] = &[];
        assert!(Assurance::decode(&mut input).is_err());
    }

    // --- CE 142: Preimage announcement --------------------------------------

    #[test]
    fn preimage_announcement_vector() {
        let p = PreimageAnnouncement {
            service_id: 0x0403_0201,
            hash: [0x42; 32],
            length: 0x0807_0605,
        };
        let bytes = p.encode();
        let mut expected = vec![0x01, 0x02, 0x03, 0x04]; // Service ID (u32 LE)
        expected.extend_from_slice(&[0x42; 32]); // Hash
        expected.extend_from_slice(&[0x05, 0x06, 0x07, 0x08]); // Preimage Length (u32 LE)
        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), 4 + 32 + 4);
    }

    #[test]
    fn preimage_announcement_roundtrip() {
        let p = PreimageAnnouncement {
            service_id: 9,
            hash: [0x24; 32],
            length: 1000,
        };
        let bytes = p.encode();
        let mut input: &[u8] = &bytes[..];
        let decoded = PreimageAnnouncement::decode(&mut input).unwrap();
        assert!(input.is_empty());
        assert_eq!(decoded, p);
    }

    #[test]
    fn preimage_announcement_truncated_errs() {
        // Only the service id.
        let mut input: &[u8] = &[0x01, 0x02, 0x03, 0x04];
        assert!(PreimageAnnouncement::decode(&mut input).is_err());
        // Missing the trailing length.
        let mut bytes = vec![0x01, 0x02, 0x03, 0x04];
        bytes.extend_from_slice(&[0x42; 32]);
        bytes.extend_from_slice(&[0x05, 0x06]);
        let mut input: &[u8] = &bytes[..];
        assert!(PreimageAnnouncement::decode(&mut input).is_err());
    }

    // --- CE 143: Preimage request/reply -------------------------------------

    #[test]
    fn preimage_request_vector() {
        let r = PreimageRequest { hash: [0x13; 32] };
        assert_eq!(r.encode(), vec![0x13; 32]);
    }

    #[test]
    fn preimage_reply_vector_raw_bytes() {
        // `Preimage = [u8]` (simple.md:733): raw bytes, no length prefix.
        let reply = PreimageReply {
            preimage: vec![0xde, 0xad, 0xbe, 0xef],
        };
        assert_eq!(reply.encode(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn preimage_roundtrips() {
        let req = PreimageRequest { hash: [0x31; 32] };
        let bytes = req.encode();
        let mut input: &[u8] = &bytes[..];
        assert_eq!(PreimageRequest::decode(&mut input).unwrap(), req);
        assert!(input.is_empty());

        let reply = PreimageReply {
            preimage: vec![0x01, 0x02, 0x03],
        };
        let bytes = reply.encode();
        let mut input: &[u8] = &bytes[..];
        assert_eq!(PreimageReply::decode(&mut input).unwrap(), reply);
        assert!(input.is_empty());
    }

    #[test]
    fn preimage_request_truncated_errs() {
        // Hash truncated to 16 bytes.
        let mut input: &[u8] = &[0x13; 16];
        assert!(PreimageRequest::decode(&mut input).is_err());
    }

    // --- CE 144: Audit announcement ------------------------------------------

    fn sample_announcement() -> Announcement {
        Announcement {
            entries: vec![(0x0102, [0x01; 32]), (0x0304, [0x02; 32])],
            signature: sig64(0x50),
        }
    }

    #[test]
    fn announcement_vector_2_entries() {
        let ann = sample_announcement();
        let bytes = ann.encode();
        let mut expected = vec![0x02]; // compact(2) entries
        for (idx, hash) in [(0x0102u16, [0x01u8; 32]), (0x0304, [0x02; 32])] {
            expected.extend_from_slice(&idx.to_le_bytes()); // Core Index
            expected.extend_from_slice(&hash); // Work-Report Hash
        }
        expected.extend_from_slice(&sig64(0x50)); // Ed25519 Signature
        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), 1 + 2 * 34 + 64);
    }

    #[test]
    fn announcement_roundtrip() {
        let ann = sample_announcement();
        let bytes = ann.encode();
        let mut input: &[u8] = &bytes[..];
        let decoded = Announcement::decode(&mut input).unwrap();
        assert!(input.is_empty());
        assert_eq!(decoded, ann);
    }

    #[test]
    fn announcement_truncated_errs() {
        // Length prefix claims 2 entries but only one is present.
        let mut bytes = vec![0x02];
        bytes.extend_from_slice(&0x0102u16.to_le_bytes());
        bytes.extend_from_slice(&[0x01; 32]);
        bytes.extend_from_slice(&sig64(0x50));
        let mut input: &[u8] = &bytes[..];
        assert!(Announcement::decode(&mut input).is_err());
        // Missing the 64-byte signature.
        let mut bytes = vec![0x01];
        bytes.extend_from_slice(&0x0102u16.to_le_bytes());
        bytes.extend_from_slice(&[0x01; 32]);
        let mut input: &[u8] = &bytes[..];
        assert!(Announcement::decode(&mut input).is_err());
    }

    #[test]
    fn audit_announcement_msg_vector() {
        let msg = AuditAnnouncementMsg {
            header_hash: HeaderHash::from([0x55; 32]),
            tranche: 0,
            announcement: sample_announcement(),
        };
        let bytes = msg.encode();
        let mut expected = vec![0x55; 32]; // Header Hash
        expected.push(0x00); // Tranche
        expected.extend_from_slice(&sample_announcement().encode()); // Announcement
        assert_eq!(bytes, expected);
    }

    #[test]
    fn audit_announcement_msg_roundtrip() {
        let msg = AuditAnnouncementMsg {
            header_hash: HeaderHash::from([0x66; 32]),
            tranche: 7,
            announcement: sample_announcement(),
        };
        let bytes = msg.encode();
        let mut input: &[u8] = &bytes[..];
        let decoded = AuditAnnouncementMsg::decode(&mut input).unwrap();
        assert!(input.is_empty());
        assert_eq!(decoded, msg);
    }

    #[test]
    fn evidence_tranche0_vector() {
        // First Tranche Evidence = Bandersnatch Signature (96 bytes) (simple.md:782).
        let ev = Evidence::Tranche0(sig96(0x20));
        let bytes = ev.encode();
        assert_eq!(bytes.len(), 96);
        assert_eq!(bytes, sig96(0x20));
        // Decoded via tranche == 0.
        let mut input: &[u8] = &bytes[..];
        assert_eq!(Evidence::decode_with_tranche(&mut input, 0).unwrap(), ev);
        assert!(input.is_empty());
    }

    #[test]
    fn evidence_subsequent_vector_with_no_shows() {
        // Subsequent Tranche Evidence = [Bandersnatch Signature ++ len++[No-Show]]
        // (simple.md:784); No-Show = Validator Index ++ Announcement (simple.md:783).
        let no_show_ann = Announcement {
            entries: vec![(0x0001, [0x0a; 32])],
            signature: sig64(0x60),
        };
        let ev = Evidence::Subsequent(vec![SubsequentEvidence {
            s_n: sig96(0x77),
            no_shows: vec![(0x0102, no_show_ann.clone())],
        }]);
        let bytes = ev.encode();
        let mut expected = vec![0x01]; // compact(1) subsequent-evidence entries
        expected.extend_from_slice(&sig96(0x77)); // Bandersnatch Signature
        expected.push(0x01); // compact(1) no-shows
        expected.extend_from_slice(&0x0102u16.to_le_bytes()); // Validator Index
        expected.extend_from_slice(&no_show_ann.encode()); // Announcement
        assert_eq!(bytes, expected);
        // Decoded via tranche != 0.
        let mut input: &[u8] = &bytes[..];
        assert_eq!(Evidence::decode_with_tranche(&mut input, 1).unwrap(), ev);
        assert!(input.is_empty());
    }

    #[test]
    fn evidence_roundtrips() {
        let ev0 = Evidence::Tranche0(sig96(0x33));
        let bytes = ev0.encode();
        let mut input: &[u8] = &bytes[..];
        assert_eq!(Evidence::decode_with_tranche(&mut input, 0).unwrap(), ev0);
        assert!(input.is_empty());

        let ev1 = Evidence::Subsequent(vec![
            SubsequentEvidence {
                s_n: sig96(0x44),
                no_shows: vec![],
            },
            SubsequentEvidence {
                s_n: sig96(0x55),
                no_shows: vec![
                    (0x0001, sample_announcement()),
                    (0x0002, sample_announcement()),
                ],
            },
        ]);
        let bytes = ev1.encode();
        let mut input: &[u8] = &bytes[..];
        assert_eq!(Evidence::decode_with_tranche(&mut input, 1).unwrap(), ev1);
        assert!(input.is_empty());
    }

    #[test]
    fn evidence_tranche0_truncated_errs() {
        // Fewer than 96 bytes.
        let mut input: &[u8] = &[0u8; 95];
        assert!(Evidence::decode_with_tranche(&mut input, 0).is_err());
    }

    // --- CE 145: Judgment ----------------------------------------------------

    fn sample_guarantee() -> Guarantee {
        Guarantee {
            slot: 0x5060_7080,
            signatures: vec![
                GuaranteeSignature {
                    validator_index: 0x0102,
                    signature: sig64(0x00),
                },
                GuaranteeSignature {
                    validator_index: 0x0304,
                    signature: sig64(0x40),
                },
            ],
        }
    }

    #[test]
    fn judgment_valid_vector_no_guarantee() {
        let j = Judgment {
            epoch_index: 0x1020_3040,
            validator_index: 0x0102,
            validity: true,
            report_hash: [0x99; 32],
            signature: sig64(0x70),
            guarantee: None,
        };
        let bytes = j.encode();
        let mut expected = vec![0x40, 0x30, 0x20, 0x10]; // Epoch Index (u32 LE)
        expected.extend_from_slice(&0x0102u16.to_le_bytes()); // Validator Index
        expected.push(0x01); // Validity (1 byte, 1 = Valid)
        expected.extend_from_slice(&[0x99; 32]); // Work-Report Hash
        expected.extend_from_slice(&sig64(0x70)); // Ed25519 Signature
        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), 4 + 2 + 1 + 32 + 64);
    }

    #[test]
    fn judgment_invalid_vector_with_guarantee() {
        let guarantee = sample_guarantee();
        let j = Judgment {
            epoch_index: 7,
            validator_index: 0x0005,
            validity: false,
            report_hash: [0xab; 32],
            signature: sig64(0x71),
            guarantee: Some(guarantee.clone()),
        };
        let bytes = j.encode();
        let mut expected = 7u32.to_le_bytes().to_vec(); // Epoch Index
        expected.extend_from_slice(&0x0005u16.to_le_bytes()); // Validator Index
        expected.push(0x00); // Validity (0 = Invalid)
        expected.extend_from_slice(&[0xab; 32]); // Work-Report Hash
        expected.extend_from_slice(&sig64(0x71)); // Ed25519 Signature
                                                  // Guarantee (present iff Validity == 0)
        expected.extend_from_slice(&guarantee.encode());
        assert_eq!(bytes, expected);
    }

    #[test]
    fn judgment_roundtrips() {
        let valid = Judgment {
            epoch_index: 11,
            validator_index: 0x0100,
            validity: true,
            report_hash: [0x11; 32],
            signature: sig64(0x10),
            guarantee: None,
        };
        let bytes = valid.encode();
        let mut input: &[u8] = &bytes[..];
        assert_eq!(Judgment::decode(&mut input).unwrap(), valid);
        assert!(input.is_empty());

        let invalid = Judgment {
            epoch_index: 22,
            validator_index: 0x0200,
            validity: false,
            report_hash: [0x22; 32],
            signature: sig64(0x20),
            guarantee: Some(sample_guarantee()),
        };
        let bytes = invalid.encode();
        let mut input: &[u8] = &bytes[..];
        assert_eq!(Judgment::decode(&mut input).unwrap(), invalid);
        assert!(input.is_empty());
    }

    #[test]
    fn judgment_rejects_invalid_validity_byte() {
        let mut bytes = Judgment {
            epoch_index: 1,
            validator_index: 0,
            validity: true,
            report_hash: [0x99; 32],
            signature: sig64(0x00),
            guarantee: None,
        }
        .encode();
        // Validity byte sits right after epoch(4) ++ validator(2) = offset 6.
        for bad in [0x02u8, 0x7f, 0xff] {
            bytes[6] = bad;
            assert!(
                Judgment::decode(&mut &bytes[..]).is_err(),
                "validity byte {bad} must be rejected"
            );
        }
    }

    #[test]
    fn judgment_truncated_errs() {
        // Valid judgment truncated before the signature.
        let mut bytes = vec![0x40, 0x30, 0x20, 0x10];
        bytes.extend_from_slice(&0x0102u16.to_le_bytes());
        bytes.push(0x01);
        bytes.extend_from_slice(&[0x99; 32]);
        bytes.extend_from_slice(&[0u8; 20]); // only part of the 64-byte signature
        let mut input: &[u8] = &bytes[..];
        assert!(Judgment::decode(&mut input).is_err());
        // Invalid judgment: validity == 0 but no guarantee follows.
        let mut bytes = vec![0x40, 0x30, 0x20, 0x10];
        bytes.extend_from_slice(&0x0102u16.to_le_bytes());
        bytes.push(0x00);
        bytes.extend_from_slice(&[0x99; 32]);
        bytes.extend_from_slice(&sig64(0x70));
        let mut input: &[u8] = &bytes[..];
        assert!(Judgment::decode(&mut input).is_err());
        // Invalid judgment: guarantee truncated.
        let bytes = Judgment {
            epoch_index: 7,
            validator_index: 0x0005,
            validity: false,
            report_hash: [0xab; 32],
            signature: sig64(0x71),
            guarantee: Some(sample_guarantee()),
        }
        .encode();
        let truncated = &bytes[..bytes.len() - 1];
        assert!(Judgment::decode(&mut &truncated[..]).is_err());
    }
}

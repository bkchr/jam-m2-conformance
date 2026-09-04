//! SAN base-32 encoding/decoding per `jam-np/simple.md:30-43`.
//!
//! The SAN suffix is the Ed25519 public key, read as a 256-bit little-endian
//! unsigned integer (`E_32^-1(k)`), written as 52 base-32 digits using the
//! alphabet `abcdefghijklmnopqrstuvwxyz234567`, least-significant digit first.
//! This is integer base-32 (repeated `n mod 32; n /= 32`), NOT RFC 4648
//! bit-stream encoding, so no external base32 crate is used.

/// Base-32 alphabet, digit `i` has value `i` (`simple.md:39`).
pub const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Number of base-32 digits in the SAN suffix: `B(n, 52)` (`simple.md:41`).
pub const LEN: usize = 52;

/// Reads the 5-bit base-32 digit starting at bit `start` (LSB-first) of `key`.
///
/// Bits past bit 255 read as 0; `2^256 < 32^52`, so the top digit of any real
/// key is 0 or 1 and the highest read bit (255) is the only one that can be set.
fn digit_at(key: &[u8; 32], start: usize) -> u8 {
    let mut digit = 0u8;
    for b in 0..5 {
        let bit = start + b;
        if bit < 256 {
            digit |= ((key[bit / 8] >> (bit % 8)) & 1) << b;
        }
    }
    digit
}

/// Value of one ASCII alphabet character, or `None` if not in the alphabet.
fn digit_value(c: u8) -> Option<u8> {
    match c {
        b'a'..=b'z' => Some(c - b'a'),
        b'2'..=b'7' => Some(c - b'2' + 26),
        _ => None,
    }
}

/// Encodes an Ed25519 public key as the 52-character SAN suffix
/// (no `e` prefix — the prefix is applied at the cert layer).
pub fn encode(key: &[u8; 32]) -> String {
    let mut s = String::with_capacity(LEN);
    for i in 0..LEN {
        s.push(ALPHABET[digit_at(key, i * 5) as usize] as char);
    }
    s
}

/// Decodes a 52-character SAN suffix back into the 32-byte key, or `None` for
/// invalid characters, wrong length, or a value that overflows 256 bits.
pub fn decode(s: &str) -> Option<[u8; 32]> {
    if s.len() != LEN {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, c) in s.bytes().enumerate() {
        let digit = digit_value(c)?;
        if i == LEN - 1 && digit > 1 {
            return None; // digit_51 > 1 => value >= 2^256
        }
        for b in 0..5 {
            if ((digit >> b) & 1) == 1 {
                let bit = i * 5 + b;
                out[bit / 8] |= 1 << (bit % 8);
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::{decode, encode, ALPHABET, LEN};

    #[test]
    fn encode_zero_key_is_52_as() {
        assert_eq!(encode(&[0u8; 32]), "a".repeat(LEN));
    }

    #[test]
    fn encode_key_with_lsb_1() {
        // n = 1 -> digit_0 = 'b', all higher digits 'a'.
        let mut key = [0u8; 32];
        key[0] = 1;
        let expected = "b".to_string() + &"a".repeat(LEN - 1);
        assert_eq!(encode(&key), expected);
    }

    #[test]
    fn encode_all_ff_key() {
        // n = 2^256 - 1 = 1*32^51 + 31*sum(32^i for i in 0..50)
        // -> digits 0..=50 are 31 ('7'), digit 51 is 1 ('b').
        let expected = "7".repeat(LEN - 1) + "b";
        assert_eq!(encode(&[0xff; 32]), expected);
    }

    #[test]
    fn encode_known_key() {
        // Derived by hand from the spec formula: n read little-endian from the
        // key bytes, then 52 digits `alphabet[n % 32]; n /= 32`.
        let key = [
            0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c,
        ];
        assert_eq!(
            encode(&key),
            "6ol53xhacyaiqcyahacsafmbmid4qhacrqegbkucwyfqrmid3aha"
        );
        assert_eq!(encode(&key).len(), LEN);
    }

    #[test]
    fn roundtrip_matches_key() {
        let keys: [[u8; 32]; 5] = [
            [0u8; 32],
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            [0xff; 32],
            [
                0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ], // 2^255: top digit exactly 1
            [
                0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                0x19, 0x1a, 0x1b, 0x1c,
            ],
        ];
        for key in keys {
            assert_eq!(decode(&encode(&key)), Some(key));
        }
    }

    #[test]
    fn decode_top_bit_key() {
        // 1 * 32^51 = 2^255: valid, decodes to byte 31 == 0x80.
        let s = "a".repeat(LEN - 1) + "b";
        let mut expected = [0u8; 32];
        expected[31] = 0x80;
        assert_eq!(decode(&s), Some(expected));
    }

    #[test]
    fn decode_rejects_invalid_char() {
        assert_eq!(decode(&("a".repeat(LEN - 1) + "!")), None);
        assert_eq!(decode(&("a".repeat(LEN - 1) + "A")), None); // uppercase not in alphabet
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert_eq!(decode(""), None);
        assert_eq!(decode(&"a".repeat(LEN + 1)), None);
        assert_eq!(decode(&"a".repeat(LEN - 1)), None);
    }

    #[test]
    fn decode_rejects_overflow_top_digit() {
        // digit_51 = 2 -> n = 2 * 32^51 = 2^256, does not fit in 256 bits.
        assert_eq!(decode(&("a".repeat(LEN - 1) + "c")), None);
        // digit_51 = 31 -> n >= 2^256.
        assert_eq!(decode(&("a".repeat(LEN - 1) + "7")), None);
    }

    #[test]
    fn alphabet_has_32_lowercase_first_chars() {
        assert_eq!(ALPHABET.len(), 32);
        assert_eq!(ALPHABET, b"abcdefghijklmnopqrstuvwxyz234567");
    }
}

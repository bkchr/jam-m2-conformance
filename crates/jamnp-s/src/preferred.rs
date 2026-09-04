//! Preferred Initiator tie-break for pairwise validator connections.
//!
//! Per `jam-np/simple.md:70-80`, the Preferred Initiator `P(a, b)` of two Ed25519 public keys
//! `(a, b)` is `a` when `(a_31 > 127) XOR (b_31 > 127) XOR (a < b)` and `b` otherwise, where
//! `a < b` is lexicographic byte-array comparison.

/// Reasonable timeout after which the non-preferred validator may initiate the connection.
pub const INITIATOR_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Returns `true` if `a` is the preferred initiator over `b`.
pub fn preferred_initiator(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let a_msb = a[31] > 127;
    let b_msb = b[31] > 127;
    let a_lt_b = a < b;
    a_msb ^ b_msb ^ a_lt_b
}

/// Returns the winning (preferred initiator) key of `a` and `b`.
pub fn initiator(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    if preferred_initiator(a, b) {
        *a
    } else {
        *b
    }
}

#[cfg(test)]
mod tests {
    use super::{initiator, preferred_initiator};

    /// `k[0]` controls lexicographic ordering vs the peer; `k[31]` controls the `> 127` MSB bit.
    const fn key(first: u8, last: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = first;
        k[31] = last;
        k
    }

    /// (a_first, a_last, b_first, b_last, expected winner) for all 8 boolean-input combinations.
    ///
    /// Booleans: A = (a[31] > 127), B = (b[31] > 127), C = (a < b).
    /// Winner is `a` iff A XOR B XOR C is true.
    const CASES: [([u8; 32], [u8; 32], [u8; 32]); 8] = [
        // A=F B=F C=F -> b
        (key(0x01, 0x00), key(0x00, 0x00), key(0x00, 0x00)),
        // A=F B=F C=T -> a
        (key(0x00, 0x00), key(0x01, 0x00), key(0x00, 0x00)),
        // A=F B=T C=F -> a
        (key(0x01, 0x00), key(0x00, 0x80), key(0x01, 0x00)),
        // A=F B=T C=T -> b
        (key(0x00, 0x00), key(0x01, 0x80), key(0x01, 0x80)),
        // A=T B=F C=F -> a
        (key(0x01, 0x80), key(0x00, 0x00), key(0x01, 0x80)),
        // A=T B=F C=T -> b
        (key(0x00, 0x80), key(0x01, 0x00), key(0x01, 0x00)),
        // A=T B=T C=F -> b
        (key(0x01, 0x80), key(0x00, 0x80), key(0x00, 0x80)),
        // A=T B=T C=T -> a
        (key(0x00, 0x80), key(0x01, 0x80), key(0x00, 0x80)),
    ];

    #[test]
    fn preferred_initiator_covers_all_8_combinations() {
        for (a, b, expected_winner) in CASES {
            let a_preferred = a == expected_winner;
            assert_eq!(
                preferred_initiator(&a, &b),
                a_preferred,
                "a={a:02x?} b={b:02x?} expected winner {}",
                if a_preferred { "a" } else { "b" }
            );
        }
    }

    #[test]
    fn initiator_returns_the_winning_key() {
        for (a, b, expected_winner) in CASES {
            assert_eq!(initiator(&a, &b), expected_winner);
        }
    }

    #[test]
    fn initiator_is_symmetric_in_winner() {
        for (a, b, _) in CASES {
            let w = initiator(&a, &b);
            let w2 = initiator(&b, &a);
            assert_eq!(w, w2, "winner must not depend on argument order");
        }
    }

    #[test]
    fn msb_boundary_127_is_not_greater_than_127_but_128_is() {
        // a[31]=127 (NOT > 127, A=F), b[31]=128 (> 127, B=T), a<b via byte 31 -> C=T.
        // F XOR T XOR T = F -> winner b.
        let a = key(0x00, 127);
        let b = key(0x00, 128);
        assert!(!preferred_initiator(&a, &b));
        assert_eq!(initiator(&a, &b), b);

        // a[31]=128 (A=T), b[31]=127 (B=F), a<b false (a[31] > b[31]) -> C=F.
        // T XOR F XOR F = T -> winner a.
        let a = key(0x00, 128);
        let b = key(0x00, 127);
        assert!(preferred_initiator(&a, &b));
        assert_eq!(initiator(&a, &b), a);
    }

    #[test]
    fn equal_keys_resolve_from_msb_xor_only() {
        // Equal keys: a<b false, A==B -> result is A XOR B XOR false = false -> winner b.
        let lo = [0u8; 32];
        let lo2 = [0u8; 32];
        assert!(!preferred_initiator(&lo, &lo2));
        assert_eq!(initiator(&lo, &lo2), lo2);

        let hi = {
            let mut k = [0u8; 32];
            k[31] = 0x80;
            k
        };
        let hi2 = hi;
        // A=T B=T C=F -> T XOR T XOR F = F -> winner b.
        assert!(!preferred_initiator(&hi, &hi2));
        assert_eq!(initiator(&hi, &hi2), hi2);
    }

    #[test]
    fn lexicographic_ordering_on_first_byte() {
        // a=[0x00,..] < b=[0x01,..] -> C=T; both MSB low -> A=F B=F -> winner a.
        let a = key(0x00, 0x00);
        let b = key(0x01, 0x00);
        assert!(a < b);
        assert!(preferred_initiator(&a, &b));
        assert_eq!(initiator(&a, &b), a);
    }
}

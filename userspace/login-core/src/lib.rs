//! Password hashing + `/etc/shadow` verification for NARF getty/login.
//!
//! Pure logic, no syscalls: this is the part of the login flow that can be
//! unit-tested on the host (`cargo test` in this directory). getty does the
//! file I/O (read `/etc/shadow`) and prompting; it hands the bytes here.
//!
//! Password storage uses the NARF scheme **`$n1$<salt>$<hexhash>`**, where
//! `hexhash` is lowercase-hex `SHA-256(salt || password)`. This replaces the
//! pre-shadow plaintext field — there is no plaintext password on disk now.
//!
//! HONESTY NOTE: SHA-256 is a real FIPS-180-4 hash, but a *single round* is
//! NOT a slow password KDF (bcrypt / scrypt / argon2 / yescrypt) — it offers
//! no work-factor against offline guessing. NARF has no `crypt(3)` and a
//! capability-based authority model (POSIX uids are cosmetic), so this gates
//! the login *flow* rather than enforcing a security boundary. The shape
//! (salt + hash, scheme id, shadow lookup) is the real thing; swapping in a
//! real KDF would be a localized change to `hash_password`.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod sha256;
pub use sha256::{sha256, Sha256};

/// Lowercase-hex-encode a 32-byte digest into `out` (64 ASCII bytes).
pub fn hex_encode(digest: &[u8; 32], out: &mut [u8; 64]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, &b) in digest.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
}

/// NARF password hash: lowercase-hex `SHA-256(salt || password)` written
/// into `out` (64 ASCII bytes). See the module note on the single-round
/// caveat.
pub fn hash_password(salt: &[u8], password: &[u8], out: &mut [u8; 64]) {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(password);
    hex_encode(&h.finalize(), out);
}

/// Length-checked, difference-accumulating byte equality (no early return
/// on the first mismatched byte).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Parse a stored password field `$n1$<salt>$<hexhash>` into (salt, hash).
/// `None` for any other shape — empty, a locked account (`*` / `!...`), or
/// an unknown scheme — so those never verify against a real password.
pub fn parse_n1_field(field: &[u8]) -> Option<(&[u8], &[u8])> {
    let rest = field.strip_prefix(b"$n1$")?;
    let sep = rest.iter().position(|&b| b == b'$')?;
    let salt = &rest[..sep];
    let hash = &rest[sep + 1..];
    if salt.is_empty() || hash.len() != 64 {
        return None;
    }
    Some((salt, hash))
}

/// Verify `password` against a stored shadow field. An EMPTY field is a
/// no-password account (matches an empty password); a `$n1$salt$hash` field
/// is matched by recomputing the salted hash; anything else (locked /
/// unknown scheme) never matches.
pub fn verify_field(stored: &[u8], password: &[u8]) -> bool {
    if stored.is_empty() {
        return password.is_empty();
    }
    let (salt, want) = match parse_n1_field(stored) {
        Some(v) => v,
        None => return false,
    };
    let mut got = [0u8; 64];
    hash_password(salt, password, &mut got);
    ct_eq(&got, want)
}

/// Look up `user`'s password field (field 2) in an `/etc/shadow` buffer —
/// newline-separated `user:field:...` lines. Lines without a `:` are
/// skipped. Returns the field bytes, or `None` if the user is absent.
pub fn shadow_lookup<'a>(shadow: &'a [u8], user: &[u8]) -> Option<&'a [u8]> {
    for line in shadow.split(|&b| b == b'\n') {
        let c1 = match line.iter().position(|&b| b == b':') {
            Some(i) => i,
            None => continue,
        };
        if &line[..c1] != user {
            continue;
        }
        let rest = &line[c1 + 1..];
        let c2 = rest.iter().position(|&b| b == b':').unwrap_or(rest.len());
        return Some(&rest[..c2]);
    }
    None
}

/// Authenticate `(user, password)` against an `/etc/shadow` buffer: look up
/// the user, then verify the password against their stored field.
pub fn authenticate(shadow: &[u8], user: &[u8], password: &[u8]) -> bool {
    match shadow_lookup(shadow, user) {
        Some(field) => verify_field(field, password),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NIST FIPS-180-4 SHA-256("abc") known-answer vector.
    #[test]
    fn sha256_abc_vector() {
        let mut hex = [0u8; 64];
        hex_encode(&sha256(b"abc"), &mut hex);
        assert_eq!(
            &hex,
            b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    // Cross-checked against the system `sha256sum` of "n4rf" || "narf".
    #[test]
    fn hash_password_matches_reference() {
        let mut out = [0u8; 64];
        hash_password(b"n4rf", b"narf", &mut out);
        assert_eq!(
            &out,
            b"366fcdb3a40735e32d92d92d11fe1b9593d98d7e7546262e66cfeb72bd07ddec"
        );
    }

    const FIELD: &[u8] =
        b"$n1$n4rf$366fcdb3a40735e32d92d92d11fe1b9593d98d7e7546262e66cfeb72bd07ddec";

    #[test]
    fn verify_accepts_correct_rejects_wrong() {
        assert!(verify_field(FIELD, b"narf"));
        assert!(!verify_field(FIELD, b"wrong"));
        assert!(!verify_field(FIELD, b""));
        assert!(!verify_field(FIELD, b"narf ")); // trailing space differs
    }

    #[test]
    fn empty_field_is_no_password() {
        assert!(verify_field(b"", b""));
        assert!(!verify_field(b"", b"x"));
    }

    #[test]
    fn locked_or_unknown_never_matches() {
        assert!(!verify_field(b"*", b""));
        assert!(!verify_field(b"!", b"narf"));
        assert!(!verify_field(b"$bogus$x$y", b"narf"));
        // Wrong hash length is rejected by the parser.
        assert!(!verify_field(b"$n1$n4rf$deadbeef", b"narf"));
    }

    #[test]
    fn shadow_lookup_and_authenticate() {
        let shadow = b"root:$n1$n4rf$366fcdb3a40735e32d92d92d11fe1b9593d98d7e7546262e66cfeb72bd07ddec:0:0:99999:7:::\ndaemon:*:0\n";
        assert!(shadow_lookup(shadow, b"root").is_some());
        assert!(shadow_lookup(shadow, b"nobody").is_none());
        assert!(authenticate(shadow, b"root", b"narf"));
        assert!(!authenticate(shadow, b"root", b"bad"));
        assert!(!authenticate(shadow, b"nobody", b"narf")); // unknown user
        assert!(!authenticate(shadow, b"daemon", b"")); // locked account
    }
}

# userspace/login-core — login-core

Password hashing and `/etc/shadow` verification for getty/login, as a
library. It is pure logic with no syscalls, so it is unit-tested on the
host (`cargo test` in this directory); getty does the file I/O and
prompting and hands the shadow bytes here.

Passwords are stored in the NARF scheme `$n1$<salt>$<hexhash>`, where
the hash is lowercase-hex `SHA-256(salt || password)`. `src/lib.rs`
provides `hash_password`, `parse_n1_field`, `verify_field`,
`shadow_lookup`, and `authenticate`; `src/sha256.rs` is the SHA-256
implementation. Verification is length-checked and
difference-accumulating rather than early-returning. An empty stored
field is a no-password account; a locked account (`*`, `!...`) or an
unknown scheme never matches.

One honesty note, from the code: a single round of SHA-256 is a real
hash, not a slow password KDF — it offers no work factor against
offline guessing. The shape (salt + hash, scheme id, shadow lookup) is
the real thing, so swapping in a real KDF would be a localized change
to `hash_password`.

# userspace/getty — getty

The first userspace login agent on the boot console. It sets up a login
session, authenticates a user, and hands off to the shell: `setsid()` to
become session and process-group leader, `TIOCSCTTY` to claim the
console as the controlling terminal, `TIOCSPGRP` to foreground its
group, then a login loop — prompt `NARF login:`, read an echoed
username; prompt `Password:`, read the password with terminal echo
disabled — verified against `/etc/shadow`. A failed login prints `Login
incorrect` and retries after a one-second delay. On success it prints a
welcome line and `execve`s `/bin/shell` with argv[0] `-shell`, so the
shell inherits the session, controlling terminal, and foreground group.

Credential hashing and shadow parsing live in the host-unit-tested
`login-core` crate; getty only does the prompting and file I/O. The
password gates the login flow, not a security boundary: POSIX uids are
cosmetic under NARF's capability-based authority model, and the stored
hash is a single round of salted SHA-256, not a slow password KDF (see
`login-core`). The whole program is `src/main.rs`, a `no_std` binary on
`narf-libc` and `narf-user-runtime`.

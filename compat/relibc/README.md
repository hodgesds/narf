# compat/relibc — relibc Compatibility Shim

`narf-compat-relibc` is a packaging shim that lets user binaries built
against Redox's relibc — the Rust-implemented POSIX libc most non-Linux
Rust user programs link against — link unchanged on NARF. It does not
reimplement relibc. NARF already has a POSIX libc (`narf-libc`) that
exports the standard C symbol surface (`open`, `read`, `write`, `malloc`,
`printf`, `strlen`, `exit`, and the rest) under their canonical names;
this crate simply presents that surface under the name a relibc-targeting
consumer expects.

## What it provides

Three things, all in service of making the link step succeed. First, a
Cargo-level presence: a crate a consumer can depend on so its `crt0` /
dynamic loader finds the expected symbols on the linker search path — the
crate pulls in `narf-libc` as a transitive dependency and keeps its
`#[no_mangle]` exports from being stripped. Second, symbol-name aliases
for the small set of cases where relibc uses Redox-specific names whose
`narf-libc` equivalent carries the standard POSIX name; each alias is a
one-line forwarding wrapper. Third, compile-time symbol-presence
assertions, so a regression in `narf-libc` that drops an exported function
trips a build error *here*, with a clear pointer at the missing symbol,
instead of surfacing as an opaque link failure in a downstream binary.

## Scope

The implementation lives entirely in `narf-libc`; this crate is only
packaging and aliasing. It does not ship C headers (header generation via
`cbindgen` is a separate follow-up) and does not bundle a dynamic loader —
NARF binaries are statically linked for the current bring-up arc. The
crate depends on `verification/kernel-test` so its presence assertions can
be registered as kernel-test smokes alongside the rest of the suite.

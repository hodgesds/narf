# verification/busybox — BusyBox Verification Asset

`narf-busybox` bakes a static BusyBox binary into the build so the
linux-compat demo has a real, unmodified upstream userspace program to run
under NARF. The crate's `build.rs` downloads the pinned BusyBox source,
verifies its SHA-256, builds it statically against musl, and links it to
load at NARF's PML4[1] user virtual address (the same range `narf-libc`
uses, which is where NARF's ELF loader maps user-visible `PT_LOAD`
segments). The resulting ELF is exposed to kernel-side consumers as a
`pub const` byte slice via `include_bytes!`, so the demo binary travels
with the build with no runtime download or filesystem dependency.

The build is gated on `musl-gcc` being present on the host. When it is
absent — so the static binary can't be produced — the published path
falls back to `/dev/null`, the exported slice is empty, and the
kernel-side consumer simply skips seeding `/bin/busybox`. All artifacts
live under `OUT_DIR`, so Cargo's incremental-build machinery handles
caching: the download-and-build runs once per clean cycle. Only x86_64 is
built today; aarch64 resolves to the empty fallback.

This is a verification asset rather than a kernel component: it provides
the input that exercises NARF's ELF loader, syscall surface, and
musl-compatibility path with stock third-party code. The crate's source
documents the current state of that path in detail, including which
applets work (those using raw syscalls, like `echo` and `true`) and the
open stdio-relocation issue that stdio-bound applets still hit.

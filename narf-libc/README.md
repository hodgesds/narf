# narf-libc — POSIX libc shim for NARF user binaries

`narf-libc` is an in-tree, `no_std`, no-alloc-by-default libc for NARF user
binaries — the "Path B" alternative to linking an external libc. It supplies
the standard SysV C startup contract (`_start` → `__libc_start_main` →
user `main`) plus a minimum libc surface (write/printf-shim, exit, getpid,
malloc-on-brk, errno-via-TLS, mem/str helpers) following POSIX.1-2017,
enough to validate the Stage-4 user-mode toolchain end to end. Every
libc-style entry delegates into `narf-user-runtime` for the actual syscall;
this crate adds the C-ABI startup glue and a printf-shim parser, nothing
more. A real C-variadic `printf` needs `core::ffi::VaList` (still unstable
as of Rust 1.85), so the crate ships a tagged-union `Arg` + `printf_str`
pair instead.

One module per area — `string`, `stdio`/`stdio_c` (the `FILE*` layer plus
the C-ABI veneer), `stdlib`, `heap`, `math`, `net`, `pthread`, `signal`,
`process`, `time`, `fd`/`fs`/`posix`, and the rest listed in `src/lib.rs`.
TLS uses the initial-exec model: the kernel programs `IA32_FS_BASE` to the
per-thread TCB self-pointer, and errno lives in the last bytes of the TLS
template.

Consumers: the in-tree coreutils (`cat`, `echo`, `ls`), the
`compat/relibc` shim (which re-exports these symbols under the names
Redox's relibc uses, so relibc-built user binaries link unchanged), and the
[`validate`](./validate/README.md) smoke binary.

- Spec: the userspace spec documents the libc surface contract —
  [`userspace/specification/spec.md`](../userspace/specification/spec.md)

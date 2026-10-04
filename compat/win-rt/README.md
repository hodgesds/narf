# compat/win-rt — Win32 User-Mode Runtime

`narf-compat-win-rt` is the userspace half of NARF's Win32 compatibility
layer: the `kernel32` / `user32` / `ntdll`-shaped thunks that unmodified
Windows PE binaries call. It is the counterpart to the kernel-side
`narf-compat-win`, which parses the PE, materialises the WinProcess
address space, and patches each PE's Import Address Table so its imported
calls land on the matching exported function in this crate. The runtime is
mapped into every WinProcess as a system DLL at a fixed virtual address;
calls reach it directly through the patched IAT with no kernel syscall, no
trampoline, and no ring transition.

## How it fits together

Each exported thunk is declared with the architectural PE calling
convention — `extern "win64"` on x86_64, `extern "C"` on aarch64 (AAPCS64
matches the Win32 ARM64 ABI) — so a PE caller's indirect `call` through
its IAT slot lands on a correctly-ABI'd function. The thunks implement no
I/O themselves; they delegate to `narf-user-runtime` for the actual native
syscalls (write, task exit, and so on). That is the same runtime relibc
and other userspace consumers sit on top of, so the Win32 surface is one
of many compatibility layers over a single native-first ABI, and the crate
adds zero new kernel syscalls.

The crate also publishes an export table pairing each
`"module.dll!Symbol"` with the thunk's link-time virtual address. The
kernel-side loader maps the runtime's read-only metadata section and walks
this table to populate the PE's IAT slots at load time.

## Scope

This is the minimum-viable Win32 surface needed to run simple PEs: the
exported signatures match Microsoft's exactly so a patched IAT slot calls
in with the right ABI, and the runtime models the standard handles and the
sentinel handle values returned to PE callers. It is a bring-up surface,
not a complete Win32 implementation.

- Spec: see `compat/win/specification/spec.md` §8 (the Win32 compatibility
  specification covering both the kernel and userspace halves).

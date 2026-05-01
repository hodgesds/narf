# compat/win — Specification

> Status: **v1.0** (Stage 4+ design lock). v0.1 prototyped a
> kernel-side thunk dispatcher (`SYS_WIN_THUNK`); v1.0 commits
> to the userspace-thunk architecture (option 2 in v0.1 §8) per
> the locked design rules in `userspace/spec` §8.1 (native-first
> ABI + relibc-style compat) and `drivers/spec` §12 (user-mode
> hosting via the SDK). No new kernel syscall number is added
> for Win32 — thunks live in a userspace runtime crate and call
> existing NARF native syscalls.

## 1. Purpose & scope

**Owns:** Win32-on-NARF compatibility. PE32+ image loader, NT-shaped
process model (`WinProcess`), Win32 API thunk layer that bottoms out
on NARF caps + abi rings.

**Does NOT own:** Graphics (GDI / Direct3D / DXGI), audio (XAudio2 /
WASAPI), input (DirectInput / XInput), networking (Winsock).
Those are downstream subsystems consuming this one once the kernel-
level surfaces (`drivers/gpu`, audio HAL, input HAL, `net/`) exist.

**Initial milestone (M0):** load and run a PE32+ console executable
that calls only `kernel32!{GetStdHandle, WriteConsole, ExitProcess}`.
This proves the loader, the thunk dispatch, and the cap/domain
plumbing without dragging in any of the GUI subsystems.

**Why a Stage 4+ subsystem and not part of `userspace/`:** running a
foreign ABI image is a strictly larger problem than running NARF's
own ELF binaries. It requires (a) a second loader for a different
image format, (b) a per-process Win32 personality (TEB/PEB,
`fs`/`gs` selector contract, structured-exception dispatch), and (c)
a userspace shadow library implementing thousands of API entrypoints.
Keeping it in its own crate prevents that surface from leaking back
into the `userspace/` core.

## 2. Assumptions

- `userspace/` provides the syscall surface (`SyscallTable`,
  `RawSyscallHandler`, `TrapContext`), the per-task AS lookup
  (`active_user_as`), and the exit-landing hook
  (`set_exit_landing` / `exit_landing`). `compat/win` does *not*
  wrap `narf_userspace::UserProcess` — `WinProcess` is a sibling
  primitive that owns its own `AddressSpace` and Win32-flavoured
  personality (PEB / TEB / IAT / trampoline / Win-style stack).
  The two primitives compose via the shared `AddressSpace` /
  `SyscallTable` infrastructure rather than by inheritance.
- `arch/` exposes the Stage-4 user-mode primitives: `enter_user_mode`
  (iretq), `set_user_fs_base` (used by native NARF), and
  `set_user_gs_base` (added in this branch for the Win32 TEB
  pointer).
- `capabilities/` mints `Cap<T, R>` and supports per-task cap tables.
- `memory/` provides the frame allocator, `AddressSpace`, and
  per-region permissions used to enforce W^X on PE sections.
- `filesystem/` can resolve a host path and hand back a byte slice
  for the loader to consume (M1 — DLL loading).
- The host CPU is amd64 (PE32+ AMD64) or aarch64 (PE32+ ARM64).
  PE32 (i386) is **out of scope** for the initial milestone — no
  WoW64 thunk is provided.

## 3. Public interface

```rust
/// Loaded PE32+ image, parsed but not yet mapped.
pub struct PeImage<'a> { /* headers, sections, imports, relocs */ }

pub fn parse_pe(bytes: &[u8]) -> Result<PeImage<'_>, PeError>;

/// A Win32 process: the NARF address space + the NT personality
/// (PEB / TEB pages, IAT, trampoline page, user stack).
#[derive(Debug)]
pub struct WinProcess {
    pub address_space: Arc<AddressSpace>,
    pub entry:         VirtAddr,
    pub image_base:    u64,
    pub size_of_image: u32,
    pub peb_va:        VirtAddr,
    pub teb_va:        VirtAddr,
    pub stack_base:    VirtAddr,
    pub stack_top:     VirtAddr,
    pub trampoline_va: VirtAddr,
}

/// Spawn-authority alias for a loaded Win32 image. `Invoke` is
/// the cap-rights tag for "execute / activate / trigger an
/// object's behavior" — symmetric with how
/// `Cap<CpuLifecycle, Invoke>` authorises bringing up a CPU.
pub type Spawn = narf_capabilities::Invoke;

/// Resolve `(module, symbol)` to a stable thunk id (the
/// trampoline-page slot index). The loader handles the
/// `trampoline_va + id * STUB_BYTES` arithmetic internally.
pub type ImportResolver = fn(&str, &str) -> Option<u16>;

pub unsafe fn load_pe(
    bytes:   &[u8],
    resolve: ImportResolver,
    pid:     u64,
    tid:     u64,
) -> Result<WinProcess, LoadError>;

/// Per-arch user-mode entry. Activates the AS, programs the
/// TEB-pointer system register (`IA32_KERNEL_GS_BASE` on amd64,
/// `TPIDR_EL0` on aarch64), and `iretq` / `eret`s into
/// `proc.entry`.
pub unsafe fn enter_winprocess(proc: &WinProcess) -> !;

/// Win32 API thunk. `entry_addr` is the kernel-mode function
/// the `SYS_WIN_THUNK` dispatcher transmutes to a unified
/// `extern "win64" fn(u64, u64, u64, u64) -> u64` (amd64) /
/// `extern "C" fn(u64, u64, u64, u64) -> u64` (aarch64) and
/// invokes after the user's `int 0x80` / `svc #0` traps in.
pub trait Thunk: Send + Sync + core::fmt::Debug {
    fn name(&self) -> (&'static str, &'static str);
    fn entry_addr(&self) -> u64;
}

pub fn install_registry(table: &'static &'static [&'static dyn Thunk]);
pub fn dispatch_thunk(module: &str, symbol: &str) -> Option<&'static dyn Thunk>;
pub fn thunk_id(module: &str, symbol: &str) -> Option<u16>;
pub fn thunk_by_id(id: u16) -> Option<&'static dyn Thunk>;
```

The `kernel32` thunk set for M0 (`GetStdHandle`,
`WriteConsole{A,W}`, `ExitProcess`) lives in
`src/thunks/kernel32.rs` as `KERNEL32_THUNKS`. The kernel boot
path calls `install_registry(&&KERNEL32_THUNKS)` once. The
dedicated dispatch syscall is `Syscall::WinThunk = 300` —
see §8 for the rationale.

## 4. Invariants & safety properties

- **No ambient authority.** A `Cap<WinProcess, Spawn>` only authorises
  spawning; reading the image bytes still requires the caller's
  `Cap<File, Read>`, and any thunk that touches a NARF resource
  (console, FS, time) goes through that resource's existing cap
  contract. The Win32 facade does not get to bypass NARF's cap rules.
- **PE image is parsed before mapping.** No `mmap`-then-trust flow.
  The loader rejects malformed sections, overlapping RVAs, and any
  relocation that would land outside a `PT_LOAD`-equivalent section
  before the AS gets touched.
- **W^X.** Every PE section maps with at most one of W or X.
  `IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE` is rejected (it
  exists in the wild only in packed/obfuscated images and is the
  load-time fingerprint of malware; we refuse the pattern).
- **The Win32 personality lives in user pages.** PEB, TEB, IAT, and
  the SEH dispatcher table all sit in user-RW mappings inside the
  process's own AS. The kernel never exposes a kernel pointer to
  user code through the Win32 surface.
- **No silent fabrication of return values.** An unimplemented
  import is refused at *load time* with
  `LoadError::UnresolvedImport` rather than installing a stub that
  silently returns `STATUS_NOT_IMPLEMENTED`. There is no
  "registry of unimplemented thunks" — a binary that imports a
  symbol we don't model fails to load. The implemented thunks
  (`kernel32!{GetStdHandle, WriteConsole, ExitProcess}`) document
  every transformation they perform: `WriteConsole` substitutes
  non-ASCII bytes with `'?'` for the early console (the early
  16550A / PL011 backend cannot render UTF-8); `GetStdHandle`
  echoes the documented Win32 sentinel for the standard streams.
  Both behaviours match Win32's documented failure modes for the
  matching call shapes; neither fabricates a success that doesn't
  reflect what happened.
- **OS-version personality is explicit.** The PEB exposes an
  OS-version triple that PE binaries gate on. `Layout::os_version`
  defaults to `OsVersion::WIN10_LATE = (10, 0, 19045)` because
  modern toolchains require `OSMajorVersion >= 6`; this is a
  *declared lie*. Tests / strict-mode loaders can flip to
  `OsVersion::NARF_HONEST = (0, 0, 0)` and observe a binary's
  rejection behaviour. The lie is never silent.

## 5. Architecture notes

### x86_64
- PE32+ AMD64 uses **MS x64 calling convention**: first 4 args in
  `rcx, rdx, r8, r9`, further args at `[rsp + 0x28..]` after a
  32-byte shadow space pre-reserved by the caller. NARF's native
  ABI uses SystemV. Both ABIs are first-class in Rust on x86_64
  (`extern "win64"` for MS-x64, `extern "C"` for SysV) — every M0
  thunk is declared `extern "win64"` so the compiler emits the
  right prologue / shadow-space spill, and no per-thunk asm stub
  is required.
- **TEB pointer at `gs:[0x30]` (self), PEB pointer at `gs:[0x60]`.**
  On entry to user mode for a Win32 process, the kernel programs
  `IA32_KERNEL_GS_BASE` to the per-thread TEB; `enter_user_mode`'s
  `swapgs` swings it into the live `IA32_GS_BASE`. Native NARF
  user threads use a different per-task `gs` pointer; the two
  regimes are mutually exclusive per thread.
- The user trampoline page sits in the WinProcess's own AS at
  `peb_va + 0x1000`. Each 16-byte stub does
  `mov rsi, rcx; mov edi, <id>; mov eax, SYS_WIN_THUNK; int 0x80; ret` —
  shuffling MS-x64 arg0 into the SysV arg1 slot the kernel reads
  via `SyscallArgs.arg1`, and the thunk id into SysV arg0.
- Structured exceptions: dispatch via `.pdata` / `.xdata` (no
  legacy x86 FS-chain). Not yet implemented; deferred to M2.

### aarch64
- PE32+ ARM64 (PEMACHINE = `IMAGE_FILE_MACHINE_ARM64`, `0xAA64`).
- AAPCS64 is identical between Win32 ARM64 and NARF native, so a
  thunk's `extern "C" fn` (which is AAPCS64 on aarch64 targets) is
  the same calling convention the PE caller uses. No register
  shuffle is required.
- TEB pointer: TPIDR_EL0 (Win32 ARM64 also uses TPIDR_EL0). NARF
  native uses TPIDR_EL0 for its own TLS too — same constraint as
  x86_64: a thread is either Win32-personality or native, not both.
- The user trampoline page does
  `movz x4, #<id>; movz x8, SYS_WIN_THUNK; svc #0; ret` per stub
  — thunk id → SysV arg4 (NARF's aarch64 `SyscallArgs.arg4`),
  Win32 args left untouched in `x0..x3`.
- Structured exceptions: ARM64 unwind (`.pdata`-equivalent) tables
  embedded in the PE. Not yet implemented; deferred to M2.
- aarch64 user-mode entry primitive does not yet exist in
  `arch/aarch64/` — `enter_winprocess` panics. Unblocks once a
  parallel to `arch/x86_64/user_mode.rs` lands. `load_pe` already
  returns `LoadError::AddressSpace` from `new_for_user` on
  aarch64, so this path is currently unreachable in practice.

## 6. Dependencies

- **Consumes:** `arch/` (`set_user_gs_base`, `enter_user_mode`),
  `capabilities/` (`Cap<>`, `Invoke` rights tag),
  `memory/` (frame allocator, `AddressSpace`, `Region`,
  `RegionPerms` for W^X mapping), `userspace/` (`SyscallTable`,
  `RawSyscallHandler`, `active_user_as`, `exit_landing`,
  `Syscall::WinThunk` slot), `console/` (M0 `WriteConsole`
  backend).
- **Pending consumers:** `tracing/` (M1 — unimplemented-thunk
  events, ASCII-substitution events, OS-version-lie reads),
  `filesystem/` (M1 — DLL bytes for recursive load).
- **Provides to:** the eventual `compat/win-gui/`, `compat/win-d3d/`,
  `compat/win-xaudio/` subsystems — not in this milestone.

## 7. Stage assignment

Stage 4+. Lands **after** `userspace/` reaches its Stage 4 exit gate
("native ELF binary calls relibc, returns, exits cleanly"). The PE
loader and thunk plumbing have no value before that gate; they
compose on top of it.

## 8. Architecture (locked at v1.0)

### 8.1 Two-crate split

```text
┌─────────────────────────── kernel space ──────────────────────────┐
│  compat/win/                                                      │
│    pe.rs              — PE32+ parser (headers / sections / imports / relocs) │
│    user_ptr.rs        — cap-checked user-pointer accessor (kept)  │
│    process.rs         — WinProcess struct, AS materialisation,    │
│                         IAT patching against userspace symbols    │
│  (no syscall.rs, no trampoline.rs, no thunks/ — all moved out)    │
└───────────────────────────────────────────────────────────────────┘

┌────────────────────────── user space ─────────────────────────────┐
│  compat/win-rt/                                                   │
│    rt entry           — `_NarfWinStart` user-mode entry           │
│    kernel32.dll       — GetStdHandle, WriteConsole, ExitProcess,  │
│                         ... (each fn calls narf-userspace-runtime  │
│                         native syscalls)                          │
│    user32.dll, …      — added incrementally                        │
│    PEB / TEB setup    — populated by rt entry from cap-passed ptrs │
└───────────────────────────────────────────────────────────────────┘
```

### 8.2 Why no new syscall

Per `userspace/spec` §4.1 the syscall enum is **append-only,
forever**, so adding `Syscall::WinThunk` would burn a slot
indefinitely for an architectural shape we now reject. Moving
thunks to userspace means:

- Win32 callers issue ordinary `call` instructions to the
  user-mode thunk function — no ring transition, no
  trampoline.
- Thunks call existing NARF native syscalls (`write`, `exit`,
  etc.) for I/O. This is the same shape as relibc per
  `userspace/spec` §8.1.
- The kernel's syscall numberspace stays clean.

### 8.3 IAT patching

The PE loader (`compat/win::process::load_pe`, runs at PT_INTERP
time per `userspace/spec` §8.4) populates each imported
slot with the address of the corresponding symbol in the
already-mapped `compat-win-rt` library:

```rust
fn resolve_iat(
    name:    &str,                          // "kernel32.dll!ExitProcess"
    win_rt:  &MappedLibrary,                // compat-win-rt mapping in this AS
) -> Option<VirtAddr> {
    win_rt.lookup_export(name).map(|e| e.va)
}
```

Each IAT slot ends up holding a **user-mode VA**. Win32 calls
through these slots are ordinary user-mode indirect calls.
The kernel is not involved in the call path.

### 8.4 ExitProcess

`kernel32!ExitProcess` is implemented in the rt crate as:

```rust
#[no_mangle]
pub extern "win64" fn ExitProcess(code: u32) -> ! {
    // SAFETY: SYS_EXIT_TASK never returns.
    unsafe { narf_userspace_runtime::exit_task(code as i32) }
}
```

That's it. No kernel-side `redirect_to_kernel` plumbing needed
— the existing `Syscall::ExitTask` does the work.

### 8.5 Per-process compat-win-rt mapping

`compat-win-rt` is a kernel-blessed system DLL — analogous to
Linux's `vDSO` page or NARF's own `narf-ld.so` — mapped into
every WinProcess at a fixed VA at load time. The loader
treats it specially:

- Bytes are pre-built and stored in the kernel image (or
  served from `/lib/narf/compat-win-rt.so` once
  `filesystem/` is up).
- Mapped read-only-execute into every WinProcess at the same
  fixed VA across processes (KASLR-randomised once per boot).
- Cap minted to the WinProcess at load is `Cap<WinRtBinding,
  Read>` — read-only access to the rt's exports table for
  IAT resolution. The rt itself runs purely in user mode and
  has no special privilege.

### 8.6 Migration from v0.1 prototype

The v0.1 code shipped:

- `compat/win/src/syscall.rs` (`SYS_WIN_THUNK` handler) —
  **removed in v1.0**.
- `compat/win/src/trampoline.rs` (per-process syscall stub
  page) — **removed in v1.0**.
- `compat/win/src/thunks/` (kernel-mode thunk impls) —
  **moved to `compat/win-rt/`** and rewritten as user-mode
  functions.
- `compat/win/src/{pe.rs, process.rs, user_ptr.rs,
  personality.rs, dll.rs, entry.rs, lib.rs}` — **kept**, with
  `process.rs::load_pe` updated to patch IAT against the
  rt mapping instead of the trampoline.
- `Syscall::WinThunk` slot — **removed from the kernel
  enum**. The branch was never merged, so `userspace/spec`
  §4.1 append-only rule does not apply.

The wine branch had a v0.1 audit commit (`94b4f02`) that
documented the v0.1 implementation; v1.0 explicitly supersedes
it.

## 9. ABI versioning

`compat/win` (kernel side) exports through SDK at `@v0`:

- `WinProcess` (opaque to drivers; consumed only by the
  process-spawn syscall path).
- `parse_pe`, `load_pe` (used by the spawn-Win32 syscall
  handler).
- `Cap<WinRtBinding, _>` cap kind.
- `user_ptr` cap-checked accessor (re-exported for any
  kernel code that needs to read user memory; not Win32-
  specific).

`compat/win-rt` (user side) is a versioned shared library
loaded into every WinProcess. Its export table is the Win32
ABI surface; adds and removes follow the standard symbol-
versioning model (per `lib/spec` §9 / Linux glibc conventions).

`COMPAT_WIN_ABI_MAJOR = 1`, `COMPAT_WIN_ABI_MINOR = 0`.

## 10. Resolved decisions

### 10.1 WoW64 / PE32 (resolved)

**Decision:** **out of scope, indefinitely**. NARF supports
PE32+ AMD64 (x86_64) and PE32+ ARM64 (aarch64). 32-bit
binaries are not supported. The cost of WoW64 thunking
(32-bit usermode mapping, ABI translation per syscall) is
prohibitive for niche value; users with 32-bit Windows
binaries should run them on Windows or under WINE-on-Linux.

### 10.2 DLL model (resolved)

**Decision:** standard PE DLL loading via recursive
`load_pe` re-entry, mirroring how Linux's `ld.so` resolves
shared library imports. Rt-side mock DLLs (`kernel32.dll`,
`user32.dll`, etc.) live in `compat/win-rt`; real PE DLLs
load from `filesystem/` per their `IMAGE_DIRECTORY_ENTRY_IMPORT`
chain.

The `compat-win-rt` mock DLLs are tried first by the
import resolver; falls through to filesystem-loaded real
DLLs if the symbol isn't in the rt. This means:

- Microsoft system DLLs (`kernel32`, `ntdll`, `user32`,
  `gdi32`, `kernel32`, etc.) → rt provides; no real DLL
  needed.
- Application or vendor DLLs (the binary's own DLLs,
  third-party libraries) → loaded from disk.

`DllMain(hinst, DLL_PROCESS_ATTACH, 0)` is called via
ordinary user-mode call (no trampoline) once the IAT is
patched. Forwarder chasing follows the standard PE rules.
Bound-import directory ignored (always-relocate-on-load).
Delay-load (`__delayLoadHelper2`) is also user-mode call —
the helper is a rt export.
### 10.3 GDI / Direct3D backend (resolved)

**Decision:** **DXVK port targeting `drivers/gpu` Vulkan
backend** when `drivers/gpu` lands a Vulkan-capable surface
(Stage 5+). Per `drivers/gpu/spec` §8.1, 3D rendering lives in
userspace; DXVK fits that model directly — it's a userspace
shared library translating D3D9/10/11/12 to Vulkan. No kernel
changes needed beyond the existing user-mode-domain GPU
driver.

D3D headers / surface types in `compat-win-rt` ship as part
of the Win32 ABI surface. The DXVK shim is a separate crate
(`compat/win-d3d-rt` or similar) that links into the
WinProcess at load time when the binary imports D3D APIs.

### 10.4 Thunk domain isolation (resolved)

**Decision:** **rt thunks run in the WinProcess's
`DOMAIN_USERSPACE_K` shadow** (the standard user-process
kernel-side mirror domain per `security-model/spec` §4.1
slot 8). Since v1.0 thunks are user-mode functions, they
have no kernel-mode domain at all in the calling process —
the only kernel-side thunk-related state is the IAT mapping
(read-only after load).

Cross-domain calls (a thunk reaching into a driver via cap)
follow the standard cap+domain rules already in the
security model. No special compat-only domain is needed.

### 10.5 Tracing events (resolved)

**Decision:** v1.0 emits `tracing/` events from the rt for:

- `compat_win.unresolved_import` — load-time unresolved
  symbol (loader logs name + module).
- `compat_win.ascii_substitution` — `WriteConsoleA` /
  `MultiByteToWideChar` did a lossy conversion.
- `compat_win.os_version_lie` — application read
  `GetVersion*` and got a synthetic Windows 10 response.
- `compat_win.exit_process` — application called
  `ExitProcess` with the exit code.

`compat-win-rt` takes a `Cap<Probe, Emit>` at process spawn
to populate these.

### 10.6 Anti-cheat (resolved)

**Decision:** **out of scope, permanently**. Windows
kernel anti-cheat modules (Vanguard, EAC kernel-mode, BattlEye)
expect to load as Windows kernel drivers (.sys). There is no
analogue under NARF's cap model — kernel-mode third-party
code is forbidden by the framework. Games using
kernel-mode anti-cheat are unsupported.

User-mode anti-cheat (BattlEye user-mode component, EAC
user-mode component) works normally — same Win32 thunks,
no special handling.

### 10.7 Filesystem semantics (resolved)

**Decision:** Win32 path translation lives in `compat-win-rt`,
applied per-syscall. `\\?\` is stripped, drive letters map to
configured VFS prefixes (`C:\` → cap-rooted VFS path
configured per-process), case-insensitive lookups walk via
`filesystem/`'s case-fold helper (which `filesystem/spec`
§8.3 keeps internal to compat filesystems).

The mapping table is per-process state in PEB. Default mapping
matches WINE convention (`Z:\` → root, `C:\` → user home
equivalent), overridable via `compat-win-rt` config.

## 11. Open questions

(none — all v0.1 questions resolved in §10)

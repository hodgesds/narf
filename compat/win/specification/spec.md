# compat/win — Specification

> Status: **Outline v0.1** (Stage 4+, post-userspace).

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

## 8. Open questions

- **Ring-3 → kernel call path for thunks (load-bearing).**
  An IAT slot patched with a kernel-mode function address cannot
  be `call`-ed from a Ring-3 PE caller — `call` does not perform a
  privilege transition; `syscall` / `int` do. Two options on the
  table:

  1. **Per-process user-RX trampoline page.** Loader allocates a
     user-RX page in the WinProcess AS containing one tiny stub
     per imported thunk: `mov rax, <thunk_id>; syscall; ret`
     (amd64) / equivalent on aarch64. IAT slots get patched with
     trampoline VAs, not kernel function addresses. A new syscall
     number `SYS_WIN_THUNK` reads `rax`, dispatches to the
     registered thunk's entry function (running in kernel mode),
     and returns the result in `rax`. Closest to NARF's existing
     model — every cross-ring call goes through abi/syscall.
  2. **User-mode thunk crate** (WINE-style). Thunks compile as a
     user-mode `narf_compat_win_user` library, mapped into the
     WinProcess AS. IAT slots point at user-mode functions; the
     thunks themselves use abi rings to talk to the kernel. More
     code, but no new syscall surface and a tighter parity with
     how WINE actually works.

  M0 ships the kernel-side thunk entries + the loader pipeline
  (parse, materialize, IAT patching, PEB/TEB) but not the
  trampoline mechanism that makes the patched IAT slots actually
  callable from Ring 3. M0.5 picks one of the two options above.
  Lean toward (1) — fewer moving parts and the existing syscall
  surface already does the work; (2) becomes interesting once we
  want to load the equivalent of `winemenubuilder` or other
  optional Win32 services.

- **Thunk ABI codegen.** Hand-written asm stubs per thunk vs. a
  single generated trampoline that consults a per-symbol metadata
  table. The generated route saves binary size and centralises
  shadow-space handling but costs an indirection on every thunk
  call. Lean toward a `win_thunk!` macro that picks per-target
  (a generated stub on x86_64 where the ABI conversion is
  non-trivial; a direct branch on aarch64 where it isn't).
- **WoW64 / PE32.** Do we want to run 32-bit Windows binaries at
  all? On amd64 this needs a 32-bit usermode mapping + a thunk-down
  layer; on aarch64 there is no Microsoft-supplied path
  (`xtajit64` is closed-source). Default answer: no, defer
  indefinitely, document as unsupported.
- **DLL model.** Real `.dll` loading lives behind
  `compat/win/src/dll.rs` (currently a design-only module). M1
  ships:
  1. Recursive `load_pe` re-entry — every unmet import walks the
     filesystem (`compat/win/src/dll.rs::ModuleTable`) for the
     missing DLL and loads it under cap rules already enforced by
     `filesystem/`.
  2. `DllMain(hinst, DLL_PROCESS_ATTACH, 0)` invocation per
     loaded DLL via the same syscall-trampoline path the import
     IAT goes through — once the M0.5 trampoline lands a DLL's
     entry point is just another thunk-id from the loader's
     perspective.
  3. Forwarder chasing — exports whose RVA points inside the
     export directory are `module.symbol` strings to be re-resolved.
  4. Bound-import directory acknowledged but ignored — bound RVAs
     break under our always-relocate-on-load policy.
  5. Delay-load (`__delayLoadHelper2`) deferred to M2.
  Built-in thunk sets (`thunks::kernel32` etc.) remain valid for
  Microsoft DLLs we don't want to ship binaries of — the resolver
  walks the built-ins first, then the loaded `ModuleTable`.
- **GDI / Direct3D backend.** When we get there: Vulkan via DXVK
  re-port (the DXVK author's path), or a from-scratch D3D→narf-gpu
  translation? Defer until `drivers/gpu` is real.
- **Domain isolation for thunks (deferred).** An earlier draft of
  §4 claimed "thunks are domain-isolated — a thunk that calls into
  a driver domain crosses the same PKS/MTE/PCID barrier any NARF
  caller would." That isn't true today: the M0 dispatcher runs
  every thunk inline in the kernel-side syscall handler, in the
  same domain as the rest of `narf_userspace::handlers`. Calls
  *out* of the thunk into a driver (e.g. console) cross the
  driver's domain barrier the same way any kernel caller does, but
  the thunk itself does not run in a private compat-only domain.
  M2 work: assign `compat-win` its own `DomainId`, route all
  thunk dispatch through a `DomainEnter` so a buggy thunk is
  blast-radius-limited to a private heap. Acceptable to defer
  because the M0 thunk surface is read-only Microsoft-specified
  shape with no allocation; the blast radius in practice is the
  console driver, which is already domain-isolated against the
  rest of the kernel.

- **Tracing events.** Spec §4 used to say "an unimplemented
  import...raises a `tracing` event." We removed that wording
  because we don't currently take a `narf-tracing` dependency from
  `compat/win`. M1 adds the dep and emits events for: load-time
  unresolved imports, ASCII substitutions in `WriteConsole`,
  `OsVersion::WIN10_LATE` reads (so the lie is observable in
  prod traces).

- **Anti-cheat.** Out of scope, possibly forever — kernel anti-cheat
  modules expect to load as Windows kernel drivers, which has no
  analogue under NARF's cap model.
- **Filesystem semantics.** Win32 path resolution (`\\?\`, drive
  letters, case-insensitive lookups) layered over NARF's
  cap-addressed VFS. M0 sidesteps this by giving the test image
  zero filesystem access.

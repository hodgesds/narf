//! User-process bundle.
//!
//! `UserProcess` is everything the kernel needs to actually run a
//! loaded ELF: the address space, the entry point, a freshly-
//! allocated user stack (mapped into the AS with R+W+U perms), and
//! the monotonic `ProcessId`. `load_user_process(bytes)` is the
//! one-shot wrapper around `load_elf_bytes` that also carves out
//! the user stack.
//!
//! Once you have a `UserProcess` the remaining steps to run it are:
//! 1. `proc.address_space.activate()` — MOV CR3 to its PML4.
//! 2. `enter_user_mode(proc.entry.0.raw(), proc.stack_top.as_u64())`
//!    — iretq into user.
//! 3. Register syscall handlers (the core set lives in
//!    `handlers::install_core_syscalls`) so `int 0x80` from the
//!    running user program routes into the kernel.

use alloc::sync::Arc;

use narf_memory::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

use crate::{
    alloc_pid, interp, load_elf_bytes, loader::apply_relocations, loader::load_elf_into_at,
    loader::LoadBytesError, AuxEntry, EntryPoint, ProcessId,
};

/// Default user stack size: 128 KiB. The stack auto-grows on demand
/// (`AddressSpace::try_grow_stack` extends it a frame-allocation at a
/// time down to the mmap-window floor), so this is just the eagerly
/// mapped floor — kept generous enough that ordinary startup +
/// moderately deep call chains (e.g. musl `realpath`'s ~8 KiB frame,
/// recursive library walks) don't immediately fault-grow.
pub const DEFAULT_USER_STACK_BYTES: u64 = 128 * 1024;

/// Virtual address the user stack is mapped at — just below the
/// 128-TiB low-half canonical boundary, inside PML4[127]. Stage-4
/// refinement will let the loader pick per-process.
pub const DEFAULT_USER_STACK_BASE: u64 = 0x0000_7FFF_FFFC_0000;

/// Everything the kernel holds about a loaded-but-not-yet-running
/// user process.
#[derive(Debug)]
pub struct UserProcess {
    pub pid: ProcessId,
    pub address_space: Arc<AddressSpace>,
    pub entry: EntryPoint,
    /// Virtual address of the highest user-stack byte (RSP starts
    /// here). RSP grows downward into the mapped region.
    pub stack_top: VirtAddr,
    /// Per-task TLS thread-pointer (FS base on x86_64). `Some` when
    /// the binary's PT_TLS template was staged; `None` when the
    /// binary has no thread-local storage. The polling future and
    /// the testbin runner write this into `IA32_FS_BASE` before
    /// each user-mode entry so `mov rax, fs:[N]` lands in the
    /// per-task TLS block.
    pub fs_base: Option<u64>,
    /// First-arg value to pass into the entry point (as RDI on
    /// x86_64). Used by `clone(2)` so a thread's start routine
    /// receives its argument; ordinary `_start` doesn't read RDI
    /// (argc/argv come off the stack). `None` defers to whatever
    /// is in the trap frame's RDI at first iretq (= 0 for fresh
    /// tasks), preserving the historical no-arg behaviour.
    pub entry_arg: Option<u64>,
}

/// Errors from `load_user_process`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProcessLoadError {
    Load(LoadBytesError),
    StackAllocFailed,
    StackMapFailed,
    StackMaterializeFailed,
    /// argv / envp / aux total exceeded the user stack region.
    StackOverflow,
    /// PT_TLS staging (allocate + map + populate the per-task TLS
    /// block) failed. Per-thread TLS is required by relibc Path B,
    /// so a binary with `PT_TLS` that fails to stage is unrunnable.
    #[cfg(target_arch = "x86_64")]
    Tls(crate::tls::TlsError),
}

#[cfg(target_arch = "x86_64")]
impl From<crate::tls::TlsError> for ProcessLoadError {
    fn from(e: crate::tls::TlsError) -> Self {
        ProcessLoadError::Tls(e)
    }
}

impl From<LoadBytesError> for ProcessLoadError {
    fn from(e: LoadBytesError) -> Self {
        ProcessLoadError::Load(e)
    }
}

/// Parse + load `bytes` into a fresh `UserProcess` with a mapped
/// stack at `DEFAULT_USER_STACK_BASE ..+ DEFAULT_USER_STACK_BYTES`.
/// `stack_top` points at the highest mapped byte; nothing is laid
/// out on the stack — `_start` reads zeroes if it tries to fetch
/// argc.
///
/// For a process that needs argv / envp / auxv on the stack at
/// entry, use `load_user_process_with` instead.
///
/// # Safety
/// - Identity mapping of the low 4 GiB must still be live (the
///   Stage-4 structural contract all of `load_elf_bytes` rides on).
/// - Frame allocator must be initialised.
pub unsafe fn load_user_process(bytes: &[u8]) -> Result<UserProcess, ProcessLoadError> {
    // SAFETY: thin forwarder — the caller's `# Safety` contract (live
    // low-4-GiB identity map + initialised frame allocator) is exactly
    // what `load_user_process_with` requires; empty argv/envp/aux are valid.
    // SAFETY: Valid memory or trusted environment
    unsafe { load_user_process_with(bytes, &[], &[], &[]) }
}

/// Parse + load `bytes` into a fresh `UserProcess`, initialising
/// the user stack with the System V x86_64 startup contract:
/// argc + argv pointers + envp pointers + aux vector + the strings
/// they name. `stack_top` in the returned process is updated to
/// the new RSP value (the address `_start` should be invoked with),
/// not the highest stack byte.
///
/// # Safety
/// Same contract as [`load_user_process`]: identity-mapped low
/// 4 GiB + initialised frame allocator.
pub unsafe fn load_user_process_with(
    bytes: &[u8],
    argv: &[&str],
    envp: &[&str],
    aux: &[AuxEntry],
) -> Result<UserProcess, ProcessLoadError> {
    // SAFETY: caller upholds this fn's `# Safety` contract (live low-4-GiB
    // identity map + initialised frame allocator), which is precisely what
    // `load_elf_bytes` needs to map the program's PT_LOAD segments.
    // SAFETY: Valid memory or trusted environment
    let (address_space, program_entry) = unsafe { load_elf_bytes(bytes) }?;

    // PT_INTERP follow-through: if the program names an interpreter
    // and we have its bytes registered, load it at a fixed bias and
    // hand the scheduler the interpreter's entry. The interpreter
    // is then responsible for relocating the program and jumping to
    // `AT_ENTRY`. Bias is well-separated from the typical low-half
    // program load address so the two ranges never collide.
    const INTERP_BIAS: u64 = 0x0000_4000_0000_0000;
    let image = crate::parse_elf(bytes).map_err(LoadBytesError::Elf)?;
    let mut entry = program_entry;
    let mut interp_loaded = false;

    // Program-side relocations. PT_DYNAMIC may name R_X86_64_RELATIVE
    // entries that need patching before the interpreter (or the
    // program itself) starts; the program loads at vaddr 0 by
    // convention so the bias passed in is 0. Materialize already
    // happened inside `load_elf_bytes`, so the patch sites are
    // walkable through `paging::translate`.
    //
    // ONLY apply when there's no PT_INTERP. When the binary names a
    // dynamic linker, ld-musl resolves every program relocation
    // (including symbol-bound R_X86_64_GLOB_DAT / JUMP_SLOT against
    // `write`, `__libc_start_main`, `__cxa_finalize`, …) after the
    // kernel hands control to its entry point. Running the kernel's
    // own relocation pass first would `UnresolvedSymbol`-fail on
    // those externals — they're defined inside libc.so, which
    // ld-musl hasn't mapped yet at this point.
    // Must match the bias `loader::load_elf_bytes` picked. PIE
    // (ET_DYN) binaries get `PROGRAM_DYN_BASE`; ET_EXEC stays
    // at 0.
    // PML4[1] base. Bit 39 set, bit 47 clear → user range, NOT
    // the kernel high half.
    const PROGRAM_DYN_BASE: u64 = 0x0000_0080_0000_0000;
    let program_bias = match image.kind {
        crate::ExecKind::Elf64Dyn => PROGRAM_DYN_BASE,
        _ => 0,
    };
    // Static-PIE binaries (no interpreter, but PT_DYNAMIC is present)
    // use rcrt1.o from musl to self-relocate using AT_PHDR. The kernel
    // must NOT apply relocations itself, otherwise R_X86_64_RELATIVE
    // biases will be applied twice and crash the process!
    // FS-backed PT_INTERP fallback: when the in-memory `interp::`
    // registry misses, read the path through the VFS. The mount the
    // path lives under is whatever `registry().resolve_absolute`
    // finds — initramfs at "/" handles `/lib/ld-musl-...` once the
    // CPIO stages the interpreter there. The FS API is async; we
    // wrap with `poll_blocking` (same pattern Wave-59 used for
    // `sys_listdir`). Bytes are owned for the duration of this
    // function; `load_elf_into_at` copies them into freshly-mapped
    // user pages so a borrowed slice is sufficient.
    // PT_INTERP resolves under the execing task's chroot: a container
    // execs a dynamic binary whose interpreter (/lib/ld-musl-...) must
    // come from its *own* bundle rootfs, not the host's /lib. The
    // execve already ran in this (the child) task's context, which set
    // its chroot before exec, so `apply_chroot` keyed on the current
    // task rewrites the interpreter path into the rootfs. Outside any
    // chroot, `apply_chroot` returns the path unchanged.
    #[cfg(feature = "linux-compat")]
    let interp_fs_owned: Option<alloc::vec::Vec<u8>> = image
        .interp
        .as_deref()
        .filter(|name| interp::lookup_interpreter(name).is_none())
        .and_then(|name| {
            let resolved = crate::handlers::apply_chroot(name);
            read_path_from_vfs(&resolved)
        });
    #[cfg(not(feature = "linux-compat"))]
    let interp_fs_owned: Option<alloc::vec::Vec<u8>> = None;

    if let Some(name) = image.interp.as_deref() {
        let registered: Option<&[u8]> = interp::lookup_interpreter(name).map(|s| s as &[u8]);
        let interp_bytes_opt: Option<&[u8]> = registered.or(interp_fs_owned.as_deref());
        if let Some(interp_bytes) = interp_bytes_opt {
            let interp_entry =
                // SAFETY: `address_space` is the live AS from `load_elf_bytes`;
                // INTERP_BIAS is a fixed user-range offset well-separated from the
                // program's load range, so appending the interp's segments here
                // cannot collide with pages already mapped.
                // SAFETY: Valid memory or trusted environment
                unsafe { load_elf_into_at(interp_bytes, &address_space, INTERP_BIAS) }?;
            // SAFETY: AS already has its PML4 from `load_elf_bytes`;
            // we just appended interp regions and materialize is
            // idempotent for the program pages already installed.
            // SAFETY: Valid memory or trusted environment
            unsafe { address_space.materialize() }
                .map_err(|e| LoadBytesError::Load(crate::loader::LoadError::AddressSpace(e)))?;

            // Re-parse so we can drive the interpreter's PT_DYNAMIC
            // through the same relocation pass — the interpreter is
            // typically an ET_DYN object with its own .rela.dyn that
            // needs the INTERP_BIAS applied as the load offset.
            let interp_image = crate::parse_elf(interp_bytes).map_err(LoadBytesError::Elf)?;
            if !interp_image.dynamic.is_empty() {
                // SAFETY: the interp's segments were just mapped + materialized
                // at INTERP_BIAS above, so its PT_DYNAMIC relocation sites are
                // walkable; INTERP_BIAS is the matching load offset to apply.
                // SAFETY: Valid memory or trusted environment
                unsafe {
                    apply_relocations(interp_bytes, &interp_image, &address_space, INTERP_BIAS)
                }?;
            }

            entry = EntryPoint(VirtAddr::new(interp_entry));
            interp_loaded = true;
        }
    }

    // Allocate + map a user stack. Pages come from the global
    // frame allocator (a freelist — frames are not contiguous in
    // general), so we collect each one into a per-page scatter list
    // for the Region.
    let pages = (DEFAULT_USER_STACK_BYTES + 0xFFF) >> 12;
    let mut stack_phys_list: alloc::vec::Vec<PhysAddr> =
        alloc::vec::Vec::with_capacity(pages as usize);
    for _ in 0..pages {
        let f = narf_memory::alloc_frame().map_err(|_| ProcessLoadError::StackAllocFailed)?;
        let phys = f.start_address();
        // Zero the stack page.
        // SAFETY: identity-mapped in low 4 GiB.
        unsafe {
            core::ptr::write_bytes(phys.raw() as *mut u8, 0, 4096);
        }
        stack_phys_list.push(phys);
    }

    let mut stack_perms = RegionPerms::READ | RegionPerms::WRITE;
    if let Some(flags) = image.stack_flags {
        if flags.contains(crate::SegmentFlags::EXEC) {
            stack_perms = stack_perms | RegionPerms::EXEC;
        }
    } else {
        // SysV ABI historical default is executable stack if no PT_GNU_STACK.
        stack_perms = stack_perms | RegionPerms::EXEC;
    }

    address_space
        .map_region(Region {
            base: VirtAddr::new(DEFAULT_USER_STACK_BASE),
            len: pages * 4096,
            perms: stack_perms,
            phys: stack_phys_list,
        })
        .map_err(|_| ProcessLoadError::StackMapFailed)?;

    // Stack guard: a single STACK_GUARD region one page BELOW
    // the stack base. Carries no POSIX prot bits so materialize()
    // skips installing a PTE — a stack-overflow access faults
    // with P=0 and the user-mode #PF handler routes it into
    // `AddressSpace::try_grow_stack`, which promotes the guard
    // to R+W and installs a new one-page guard directly below
    // (POSIX.1-2017 §2.2.2 leaves stack auto-extension
    // implementation-defined). When the new guard would collide
    // with an existing region the grow fails and the user gets
    // a real SEGV — the explicit interval keeps the stack arena
    // distinct from heap / mmap.
    let guard_base = DEFAULT_USER_STACK_BASE - 0x1000;
    address_space
        .map_region(Region {
            base: VirtAddr::new(guard_base),
            len: 0x1000,
            perms: RegionPerms::STACK_GUARD,
            phys: alloc::vec![PhysAddr::new(0)],
        })
        .map_err(|_| ProcessLoadError::StackMapFailed)?;

    // Map the vDSO (+ its vvar page) read-only / RX into the process, so
    // libc can read the clock without a syscall. `vdso_base` (the ELF
    // header address) is published below as AT_SYSINFO_EHDR. `None` when no
    // vDSO image is registered (build host lacked clang) — programs then
    // fall back to plain syscalls.
    let vdso_base = crate::vdso::map_into(&address_space);

    // SAFETY: AS is from `load_elf_bytes` (hence `new_for_user`)
    // and stack region was just pushed.
    // SAFETY: Valid memory or trusted environment
    unsafe { address_space.materialize() }.map_err(|_| ProcessLoadError::StackMaterializeFailed)?;

    let stack_bytes = pages * 4096;
    let stack_top_v = DEFAULT_USER_STACK_BASE + stack_bytes;

    // AT_RANDOM: 16 bytes of CSPRNG-grade entropy living at the top
    // of the user stack. musl's __init_libc reads these for ASLR
    // cookies + stack canaries. We carve the entropy off the top
    // and shrink `stack_top_v` so init_sysv_stack lays argv strings
    // BELOW the entropy block (no overwrite).
    //
    // Source preference: RDSEED → RDRAND → TSC fallback, via the
    // arch hwrng path. fill_key_32 writes 32 bytes; we only need 16
    // but using the same call keeps the entropy source uniform with
    // the rest of NARF's seed-material code.
    //
    // Only emitted when an interpreter was actually loaded — the
    // NARF-native (no-interpreter) path keeps the all-zero top-of-
    // stack contract that the smoke tests assert against. We determine
    // this by checking if args/envp/auxv are completely empty.
    #[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
    let (stack_top_v, at_random_vaddr) =
        if interp_loaded || !argv.is_empty() || !envp.is_empty() || !aux.is_empty() {
            let entropy_va = stack_top_v - 16;
            let mut key = [0u8; 32];
            let _src = narf_arch::x86_64::hwrng::fill_key_32(&mut key);
            let root = address_space.root;
            for (i, &byte) in key[..16].iter().enumerate() {
                if let Some(phys) = resolve_user_phys_byte(root, entropy_va + i as u64) {
                    // SAFETY: stack region is mapped+materialised R+W
                    // above; identity-mapped low 4 GiB.
                    // SAFETY: Valid memory or trusted environment
                    unsafe {
                        *(phys as *mut u8) = byte;
                    }
                }
            }
            (entropy_va, Some(entropy_va))
        } else {
            (stack_top_v, None)
        };
    #[cfg(not(all(feature = "linux-compat", target_arch = "x86_64")))]
    let (stack_top_v, at_random_vaddr): (u64, Option<u64>) = (stack_top_v, None);

    // Build the final aux vector: caller-supplied entries take
    // precedence; we append interp-related defaults (AT_ENTRY,
    // AT_BASE, AT_PAGESZ) only when the caller didn't already set
    // them. This is what relibc / a Shiva-style ld-narf needs to
    // find the program after the interpreter starts.
    // AT_PHDR / AT_PHENT / AT_PHNUM let the dynamic linker walk
    // the program's program-header table at runtime. ld-musl
    // needs these to find PT_DYNAMIC (and from there the
    // .dynsym / .dynstr / .rela.* tables) so it can patch the
    // program's relocations. Without them ld-musl loads an
    // uninitialised pointer from the auxv block, dereferences
    // it, and SIGSEGVs at vaddr 0 before reaching its symbol
    // resolver. Computed from the ELF header + the first
    // PT_LOAD segment: the phdr table sits at file-offset
    // e_phoff, which the first PT_LOAD maps into memory at
    // (first_load.vaddr - first_load.file_off + e_phoff).
    let e_phoff = u64::from_le_bytes(bytes[0x20..0x28].try_into().unwrap_or([0; 8]));
    let e_phentsize = u16::from_le_bytes(bytes[0x36..0x38].try_into().unwrap_or([0; 2]));
    let e_phnum = u16::from_le_bytes(bytes[0x38..0x3a].try_into().unwrap_or([0; 2]));
    let first_load = image.segments.first();
    // ET_DYN binaries' PT_LOAD vaddrs are 0-relative; bias them
    // by `program_bias` so AT_PHDR points at the actual
    // runtime mapping. ET_EXEC stays at the declared vaddr.
    let at_phdr = first_load
        .map(|s| {
            s.vaddr
                .wrapping_sub(s.file_off)
                .wrapping_add(e_phoff)
                .wrapping_add(program_bias)
        })
        .unwrap_or(0);

    let mut final_aux = aux.to_vec();
    if interp_loaded || !argv.is_empty() || !envp.is_empty() || !aux.is_empty() {
        for default in [
            AuxEntry::Pagesz(4096),
            AuxEntry::Entry(program_entry.0.as_u64()),
            AuxEntry::Base(if interp_loaded { INTERP_BIAS } else { 0 }),
            AuxEntry::Phdr(at_phdr),
            AuxEntry::PhEnt(e_phentsize as u32),
            AuxEntry::PhNum(e_phnum as u32),
            // musl's __init_libc enters "secure mode" (issetugid()/
            // secure_getenv() report set-uid) UNLESS the auxv presents
            // AT_UID==AT_EUID, AT_GID==AT_EGID, and AT_SECURE==0. Real Linux
            // always emits these; NARF must too, or every process looks
            // set-uid — which makes libdbus (via issetugid) refuse the
            // session bus ("Unable to autolaunch when setuid") and stalls
            // startplasma/plasmashell. NARF processes are uid 0 (root) with
            // uid==euid, so emit a consistent, non-secure set.
            AuxEntry::Uid(0),
            AuxEntry::Euid(0),
            AuxEntry::Gid(0),
            AuxEntry::Egid(0),
            AuxEntry::Secure(false),
        ] {
            let tag = default.tag();
            if !final_aux.iter().any(|e| e.tag() == tag) {
                final_aux.push(default);
            }
        }
        // Linux-compat AT_RANDOM stamp. Only emitted when the entropy
        // block was actually written (x86_64 + linux-compat feature).
        if let Some(va) = at_random_vaddr {
            let tag = AuxEntry::Random(0).tag();
            if !final_aux.iter().any(|e| e.tag() == tag) {
                final_aux.push(AuxEntry::Random(va));
            }
        }
    }

    // AT_SYSINFO_EHDR: hand libc the vDSO base so it can resolve the
    // __vdso_* / __kernel_* symbols (added regardless of interpreter; a
    // static binary that calls getauxval(AT_SYSINFO_EHDR) wants it too).
    if let Some(base) = vdso_base {
        let tag = AuxEntry::SysInfoEhdr(0).tag();
        if !final_aux.iter().any(|e| e.tag() == tag) {
            final_aux.push(AuxEntry::SysInfoEhdr(base));
        }
    }

    // Lay out argc/argv/envp/auxv if anything was supplied; an
    // entirely empty (no-args) process keeps the all-zero stack.
    let rsp = if argv.is_empty() && envp.is_empty() && final_aux.is_empty() {
        stack_top_v
    } else {
        // SAFETY: the stack region [stack_top_v - stack_bytes .. stack_top_v]
        // was just mapped + materialized RW above, and the low-4-GiB identity
        // map is live (this fn's `# Safety` contract) — both preconditions
        // `init_sysv_stack` documents.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            init_sysv_stack(
                &address_space,
                stack_top_v,
                stack_bytes,
                argv,
                envp,
                &final_aux,
            )
        }
        .map_err(|_| ProcessLoadError::StackOverflow)?
    };

    // PT_TLS staging: if the binary names a TLS template, allocate
    // a per-task block + initial image and program the thread
    // pointer. Even when PT_TLS is *absent*, we stage a minimal
    // TCB-only TLS region — the Rust stdlib's lazy thread-locals,
    // narf-libc's errno + stdio statics, and `narf_user_runtime::
    // thread_pointer()` itself all emit `mov fs:[0]` to read the
    // TCB self-pointer; with FS_BASE = 0 that load reads linear
    // address 0 and the user task #PFs before reaching `main`.
    // Synthesising an empty `TlsTemplate { mem_size = 0 }` makes
    // `stage_tls` allocate a 4-KiB region whose first qword holds
    // `*fs:[0] = fs_base`, satisfying the read.
    #[cfg(target_arch = "x86_64")]
    let fs_base = {
        // The synthetic-TLS path needs room *before* the TCB for
        // negative-offset thread-local accesses. SysV-AMD64
        // (and glibc / relibc / Rust stdlib) use the
        // initial-exec model: TLS variables live at NEGATIVE
        // offsets from `fs_base`; only the TCB self-pointer +
        // dtv-vector fields sit at positive offsets. Errno in
        // particular is generated as `*(fs:[0] - 8)` (see the
        // narf_libc::stdio::fwrite disassembly that drove this).
        // 4 KiB is overkill for narf-libc's small TLS surface
        // today (errno + STDOUT slots) but matches the page-round
        // already done downstream and leaves headroom for a
        // future relibc swap.
        const SYNTHETIC_TLS_HEADROOM: u64 = 4096;
        let template = image.tls.clone().unwrap_or(crate::TlsTemplate {
            file_off: 0,
            file_size: 0,
            mem_size: SYNTHETIC_TLS_HEADROOM,
            align: 8,
            vaddr: 0,
        });
        let synthetic_image = crate::ExecImage {
            tls: Some(template),
            ..image.clone()
        };
        // SAFETY: low-4-GiB identity map + frame allocator are the
        // same Stage-4 invariants the rest of this routine rides on.
        // SAFETY: Valid memory or trusted environment
        Some(unsafe { crate::tls::stage_tls(&synthetic_image, bytes, &address_space) }?)
    };
    #[cfg(not(target_arch = "x86_64"))]
    let fs_base: Option<u64> = None;

    Ok(UserProcess {
        pid: alloc_pid(),
        address_space,
        entry,
        stack_top: VirtAddr::new(rsp),
        fs_base,
        entry_arg: None,
    })
}

// ── System V x86_64 startup-stack layout ────────────────────────────
//
// The SysV-AMD64 ABI ("System V Application Binary Interface,
// x86-64 Architecture Processor Supplement", §3.4.1) pins the
// initial process stack:
//
//   high  ┌──────────────────────────┐
//         │ string area              │  envp[*], argv[*] bytes
//         │ ...                      │
//         ├──────────────────────────┤
//         │ aux vector               │  AT_* (key, val) pairs, terminated AT_NULL
//         ├──────────────────────────┤
//         │ envp[n] = NULL           │
//         │ envp[n-1] ptr            │
//         │ ...                      │
//         │ envp[0] ptr              │
//         ├──────────────────────────┤
//         │ argv[argc] = NULL        │
//         │ argv[argc-1] ptr         │
//         │ ...                      │
//         │ argv[0] ptr              │
//         ├──────────────────────────┤  ← rsp on entry to _start, 16-byte aligned
//         │ argc                     │
//   low   └──────────────────────────┘
//
// _start reads `argc` at [rsp]; the loader convention is that the
// stack is 16-byte aligned at this point so XMM stores work without
// `movups`. We arrange that explicitly.
//
// The string area lives above the aux/env/argv pointer arrays so
// the pointers can name absolute addresses inside the stack region
// without forward-references; we lay out strings first (top-down),
// then walk back filling the arrays.

/// Errors `init_sysv_stack` can surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SysVStackError {
    /// Total bytes argv + envp + auxv + arrays + alignment exceed
    /// the supplied stack region.
    Overflow,
}

/// Resolve the page-table-installed phys backing for a user vaddr,
/// going via the address-space root. Returns the byte the kernel
/// would write to (identity-mapped low-4-GiB cast). Returns `None`
/// when the vaddr isn't materialised.
#[cfg(target_arch = "x86_64")]
fn resolve_user_phys_byte(root: PhysAddr, vaddr: u64) -> Option<u64> {
    let page = vaddr & !0xFFFu64;
    let off = vaddr & 0xFFFu64;
    // SAFETY: `root` is the address space's PML4 phys frame and `page` is a
    // page-aligned user vaddr; `translate` only reads the page-table hierarchy
    // through the live low-4-GiB identity map, performing no writes.
    // SAFETY: Valid memory or trusted environment
    let p = unsafe { narf_memory::x86_64::paging::translate(root, VirtAddr::new(page)) }?;
    Some(p.as_u64() + off)
}

#[cfg(not(target_arch = "x86_64"))]
fn resolve_user_phys_byte(_root: PhysAddr, _vaddr: u64) -> Option<u64> {
    // aarch64 paging::translate isn't in narf-memory yet; the
    // SysV-stack init path is x86_64-only at Stage 4 first cut.
    None
}

/// Initialise a user stack with the System V x86_64 startup
/// contract: argc + argv pointers + envp pointers + aux vector +
/// the strings they name. Returns the new RSP — the user vaddr
/// the entry point should be invoked with so `[rsp] = argc`.
///
/// # Layout
/// See module-level diagram. Strings live at the top, pointer
/// arrays + argc at the bottom, and the result is 16-byte aligned.
///
/// # Safety
/// - The stack region must already be mapped + materialised in
///   the address space at `stack_top_vaddr - stack_bytes ..
///   stack_top_vaddr` with READ+WRITE perms.
/// - The low-4-GiB identity map must be live; this routine writes
///   through the kernel's identity view of each page's phys.
pub unsafe fn init_sysv_stack(
    address_space: &AddressSpace,
    stack_top_vaddr: u64,
    stack_bytes: u64,
    argv: &[&str],
    envp: &[&str],
    aux: &[AuxEntry],
) -> Result<u64, SysVStackError> {
    // 1. Compute total string bytes (each str + a NUL).
    let mut strings_bytes: u64 = 0;
    for s in argv.iter().chain(envp.iter()) {
        strings_bytes = strings_bytes.saturating_add(s.len() as u64 + 1);
    }
    // Round up to 8-byte alignment so the aux/env/argv arrays below
    // sit aligned; SysV doesn't require it for correctness but it
    // matches Linux's startup layout and keeps inspection sane.
    let strings_padded = (strings_bytes + 7) & !7;

    // 2. Aux array: each AuxEntry occupies 16 bytes (key u64 + val u64).
    //    Add a final AT_NULL terminator.
    let aux_bytes = ((aux.len() as u64) + 1) * 16;

    // 3. envp pointer array: one u64 per entry + NULL terminator.
    let envp_bytes = ((envp.len() as u64) + 1) * 8;

    // 4. argv pointer array: one u64 per entry + NULL terminator.
    let argv_bytes = ((argv.len() as u64) + 1) * 8;

    // 5. argc (one u64).
    let argc_bytes = 8u64;

    // 6. The bottom of the structure must be 16-byte aligned at argc.
    //    Compute a tentative total, then pad on top.
    let tentative = strings_padded + aux_bytes + envp_bytes + argv_bytes + argc_bytes;
    let final_pad = (16 - (tentative & 0xF)) & 0xF;
    let total = tentative + final_pad;

    if total > stack_bytes {
        return Err(SysVStackError::Overflow);
    }

    let root = address_space.root;

    // Per-byte writer that resolves the destination phys per-page
    // through the AS — multi-page user stacks aren't necessarily
    // physically contiguous, so we can't precompute a single base.
    let write_u8 = |vaddr: u64, byte: u8| -> Result<(), SysVStackError> {
        let phys = resolve_user_phys_byte(root, vaddr).ok_or(SysVStackError::Overflow)?;
        // SAFETY: `phys` is a materialized stack-page phys returned by
        // `resolve_user_phys_byte`, reachable through the live low-4-GiB
        // identity map; a single byte write is in-bounds for that page.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            *(phys as *mut u8) = byte;
        }
        Ok(())
    };
    let write_u64 = |vaddr: u64, val: u64| -> Result<(), SysVStackError> {
        // u64 writes never cross a page boundary if vaddr is 8-aligned
        // (which all our targets are by construction).
        let phys = resolve_user_phys_byte(root, vaddr).ok_or(SysVStackError::Overflow)?;
        // SAFETY: `phys` is a materialized stack-page phys via the live
        // low-4-GiB identity map; callers only pass 8-aligned vaddrs so the
        // u64 store stays within the single resolved page.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            *(phys as *mut u64) = val;
        }
        Ok(())
    };

    // String area: layout top-down. Walk argv first (highest addrs),
    // then envp. Track each string's user vaddr in two parallel
    // Vecs; we'll spill the pointer arrays in step 2.
    let mut argv_ptrs = alloc::vec::Vec::with_capacity(argv.len());
    let mut envp_ptrs = alloc::vec::Vec::with_capacity(envp.len());
    let mut cursor_vaddr = stack_top_vaddr;
    for s in argv.iter() {
        let len = s.len() as u64 + 1;
        cursor_vaddr -= len;
        for (i, &b) in s.as_bytes().iter().enumerate() {
            write_u8(cursor_vaddr + i as u64, b)?;
        }
        write_u8(cursor_vaddr + s.len() as u64, 0)?;
        argv_ptrs.push(cursor_vaddr);
    }
    for s in envp.iter() {
        let len = s.len() as u64 + 1;
        cursor_vaddr -= len;
        for (i, &b) in s.as_bytes().iter().enumerate() {
            write_u8(cursor_vaddr + i as u64, b)?;
        }
        write_u8(cursor_vaddr + s.len() as u64, 0)?;
        envp_ptrs.push(cursor_vaddr);
    }

    // The bottom of the layout (lowest addr, the user RSP) sits
    // `total` bytes below the top. From there going up: argc,
    // argv*, envp*, aux*, then strings.
    let rsp_vaddr = stack_top_vaddr - total;
    let mut wv = rsp_vaddr;

    write_u64(wv, argv.len() as u64)?;
    wv += 8;

    for &p in argv_ptrs.iter() {
        write_u64(wv, p)?;
        wv += 8;
    }
    write_u64(wv, 0)?;
    wv += 8; // argv NULL term.

    for &p in envp_ptrs.iter() {
        write_u64(wv, p)?;
        wv += 8;
    }
    write_u64(wv, 0)?;
    wv += 8; // envp NULL term.

    for e in aux.iter() {
        let (key, val) = aux_pair(e);
        write_u64(wv, key as u64)?;
        write_u64(wv + 8, val)?;
        wv += 16;
    }
    write_u64(wv, 0)?; // AT_NULL key
    write_u64(wv + 8, 0)?; // AT_NULL val

    Ok(rsp_vaddr)
}

fn aux_pair(e: &AuxEntry) -> (u32, u64) {
    let key = e.tag();
    let val = match *e {
        AuxEntry::Null => 0,
        AuxEntry::Entry(v) => v,
        AuxEntry::Phdr(v) => v,
        AuxEntry::PhEnt(v) => v as u64,
        AuxEntry::PhNum(v) => v as u64,
        AuxEntry::Base(v) => v,
        AuxEntry::ExecFn(v) => v,
        AuxEntry::Pagesz(v) => v as u64,
        AuxEntry::Hwcap(v) => v,
        AuxEntry::Random(v) => v,
        AuxEntry::Secure(b) => {
            if b {
                1
            } else {
                0
            }
        }
        AuxEntry::Uid(v) => v as u64,
        AuxEntry::Euid(v) => v as u64,
        AuxEntry::Gid(v) => v as u64,
        AuxEntry::Egid(v) => v as u64,
        AuxEntry::SysInfoEhdr(v) => v,
    };
    (key, val)
}

// ── FS-backed PT_INTERP lookup ──────────────────────────────────────
//
// When the in-memory `interp::` registry misses, we read the
// interpreter from the VFS. The mount the path lives under is
// whatever `registry().resolve_absolute` finds — initramfs at "/"
// covers `/lib/ld-musl-x86_64.so.1` once the CPIO stages it there.
//
// The narf-filesystem API is async; we spin-pump each future to
// completion with the same shape `handlers::poll_blocking` uses —
// in-memory FSes (initramfs / memfs) return Ready on the first poll,
// and the disk-backed FSes (ext2 / FAT) drive their own block I/O
// to completion. A bounded poll loop prevents wedging on a broken
// future; on overrun the caller falls through to its no-interpreter
// path (the program runs without one, which is the right failure
// mode for a missing-interpreter ld-musl-style ELF).

#[cfg(feature = "linux-compat")]
fn poll_blocking<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn raw_waker() -> RawWaker {
        unsafe fn no_clone(_: *const ()) -> RawWaker {
            raw_waker()
        }
        unsafe fn no_op(_: *const ()) {}
        const VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
        RawWaker::new(core::ptr::null(), &VTAB)
    }

    // SAFETY: vtable is null-pointer-clean; waker is never woken.
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut ctx = Context::from_waker(&waker);
    // SAFETY: own `fut` by value; pin to stack temporary.
    let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };
    for _ in 0..4_000_000u64 {
        match pinned.as_mut().poll(&mut ctx) {
            Poll::Ready(v) => return Some(v),
            Poll::Pending => continue,
        }
    }
    None
}

/// Read `abs_path` (a POSIX-style absolute path like
/// `/lib/ld-musl-x86_64.so.1`) through the VFS into an owned byte
/// vector. Returns `None` when the path doesn't resolve, the file
/// is empty, the read exceeds 64 MiB (defensive cap — a sane ld-musl
/// is <200 KiB), or any read short-circuits with `FsError`.
#[cfg(feature = "linux-compat")]
fn read_path_from_vfs(abs_path: &str) -> Option<alloc::vec::Vec<u8>> {
    use narf_filesystem::{registry, resolve_async};

    // 1. Walk the VFS to a FileOps for `abs_path`.
    let file = registry()
        .resolve_absolute(abs_path, |fs, rel| {
            poll_blocking(resolve_async(fs.root(), rel)).and_then(|r| r.ok())
        })
        .flatten()?;

    // 2. stat() to size the read; cap at 64 MiB.
    const MAX_INTERP_BYTES: u64 = 64 * 1024 * 1024;
    let stat = poll_blocking(file.stat_async()).and_then(|r| r.ok())?;
    let size = stat.size;
    if size == 0 || size > MAX_INTERP_BYTES {
        return None;
    }

    // 3. Read in one shot. Most FSes (initramfs / memfs / FAT /
    //    ext2 file read) honour a full-length read; we loop on
    //    short reads defensively.
    let mut buf = alloc::vec![0u8; size as usize];
    let mut filled: u64 = 0;
    while filled < size {
        let n =
            poll_blocking(file.read(filled, &mut buf[filled as usize..])).and_then(|r| r.ok())?;
        if n == 0 {
            // EOF before we hit `size` — truncate to what we got.
            buf.truncate(filled as usize);
            break;
        }
        filled = filled.saturating_add(n as u64);
    }
    Some(buf)
}

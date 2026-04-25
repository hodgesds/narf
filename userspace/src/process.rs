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
    alloc_pid, interp, load_elf_bytes, loader::apply_relocations,
    loader::load_elf_into_at, loader::LoadBytesError, AuxEntry,
    EntryPoint, ProcessId,
};

/// Default user stack size: 16 KiB. Small enough to fit on boot
/// images comfortably, big enough for relibc-style startup + a few
/// argv/envp/auxv qwords on the stack.
pub const DEFAULT_USER_STACK_BYTES: u64 = 16 * 1024;

/// Virtual address the user stack is mapped at — just below the
/// 128-TiB low-half canonical boundary, inside PML4[127]. Stage-4
/// refinement will let the loader pick per-process.
pub const DEFAULT_USER_STACK_BASE: u64 = 0x0000_7FFF_FFFC_0000;

/// Everything the kernel holds about a loaded-but-not-yet-running
/// user process.
#[derive(Debug)]
pub struct UserProcess {
    pub pid:          ProcessId,
    pub address_space: Arc<AddressSpace>,
    pub entry:        EntryPoint,
    /// Virtual address of the highest user-stack byte (RSP starts
    /// here). RSP grows downward into the mapped region.
    pub stack_top:    VirtAddr,
    /// Per-task TLS thread-pointer (FS base on x86_64). `Some` when
    /// the binary's PT_TLS template was staged; `None` when the
    /// binary has no thread-local storage. The polling future and
    /// the testbin runner write this into `IA32_FS_BASE` before
    /// each user-mode entry so `mov rax, fs:[N]` lands in the
    /// per-task TLS block.
    pub fs_base:      Option<u64>,
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
    fn from(e: crate::tls::TlsError) -> Self { ProcessLoadError::Tls(e) }
}

impl From<LoadBytesError> for ProcessLoadError {
    fn from(e: LoadBytesError) -> Self { ProcessLoadError::Load(e) }
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
    argv:  &[&str],
    envp:  &[&str],
    aux:   &[AuxEntry],
) -> Result<UserProcess, ProcessLoadError> {
    let (address_space, program_entry) = unsafe { load_elf_bytes(bytes) }?;

    // PT_INTERP follow-through: if the program names an interpreter
    // and we have its bytes registered, load it at a fixed bias and
    // hand the scheduler the interpreter's entry. The interpreter
    // is then responsible for relocating the program and jumping to
    // `AT_ENTRY`. Bias is well-separated from the typical low-half
    // program load address so the two ranges never collide.
    const INTERP_BIAS: u64 = 0x0000_4000_0000_0000;
    let image = crate::parse_elf(bytes).map_err(|e| LoadBytesError::Elf(e))?;
    let mut entry = program_entry;
    let mut interp_loaded = false;

    // Program-side relocations. PT_DYNAMIC may name R_X86_64_RELATIVE
    // entries that need patching before the interpreter (or the
    // program itself) starts; the program loads at vaddr 0 by
    // convention so the bias passed in is 0. Materialize already
    // happened inside `load_elf_bytes`, so the patch sites are
    // walkable through `paging::translate`.
    if !image.dynamic.is_empty() {
        unsafe { apply_relocations(bytes, &image, &address_space, 0) }?;
    }

    if let Some(name) = image.interp.as_deref() {
        if let Some(interp_bytes) = interp::lookup_interpreter(name) {
            let interp_entry = unsafe {
                load_elf_into_at(interp_bytes, &address_space, INTERP_BIAS)
            }?;
            // SAFETY: AS already has its PML4 from `load_elf_bytes`;
            // we just appended interp regions and materialize is
            // idempotent for the program pages already installed.
            unsafe { address_space.materialize() }
                .map_err(|e| LoadBytesError::Load(crate::loader::LoadError::AddressSpace(e)))?;

            // Re-parse so we can drive the interpreter's PT_DYNAMIC
            // through the same relocation pass — the interpreter is
            // typically an ET_DYN object with its own .rela.dyn that
            // needs the INTERP_BIAS applied as the load offset.
            let interp_image = crate::parse_elf(interp_bytes)
                .map_err(|e| LoadBytesError::Elf(e))?;
            if !interp_image.dynamic.is_empty() {
                unsafe {
                    apply_relocations(interp_bytes, &interp_image,
                                      &address_space, INTERP_BIAS)
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
        let f = narf_memory::alloc_frame()
            .map_err(|_| ProcessLoadError::StackAllocFailed)?;
        let phys = f.start_address();
        // Zero the stack page.
        // SAFETY: identity-mapped in low 4 GiB.
        unsafe {
            core::ptr::write_bytes(phys.raw() as *mut u8, 0, 4096);
        }
        stack_phys_list.push(phys);
    }

    address_space.map_region(Region {
        base:  VirtAddr::new(DEFAULT_USER_STACK_BASE),
        len:   pages * 4096,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys:  stack_phys_list,
    }).map_err(|_| ProcessLoadError::StackMapFailed)?;

    // SAFETY: AS is from `load_elf_bytes` (hence `new_for_user`)
    // and stack region was just pushed.
    unsafe { address_space.materialize() }
        .map_err(|_| ProcessLoadError::StackMaterializeFailed)?;

    let stack_bytes  = pages * 4096;
    let stack_top_v  = DEFAULT_USER_STACK_BASE + stack_bytes;

    // Build the final aux vector: caller-supplied entries take
    // precedence; we append interp-related defaults (AT_ENTRY,
    // AT_BASE, AT_PAGESZ) only when the caller didn't already set
    // them. This is what relibc / a Shiva-style ld-narf needs to
    // find the program after the interpreter starts.
    let final_aux: alloc::vec::Vec<AuxEntry> = if interp_loaded {
        let mut v: alloc::vec::Vec<AuxEntry> = aux.iter().copied().collect();
        for default in [
            AuxEntry::Pagesz(4096),
            AuxEntry::Entry(program_entry.0.as_u64()),
            AuxEntry::Base(INTERP_BIAS),
        ] {
            let tag = default.tag();
            if !v.iter().any(|e| e.tag() == tag) { v.push(default); }
        }
        v
    } else {
        aux.iter().copied().collect()
    };

    // Lay out argc/argv/envp/auxv if anything was supplied; an
    // entirely empty (no-args) process keeps the all-zero stack.
    let rsp = if argv.is_empty() && envp.is_empty() && final_aux.is_empty() {
        stack_top_v
    } else {
        unsafe { init_sysv_stack(&address_space, stack_top_v, stack_bytes, argv, envp, &final_aux) }
            .map_err(|_| ProcessLoadError::StackOverflow)?
    };

    // PT_TLS staging: if the binary names a TLS template, allocate
    // a per-task block and program a thread pointer (returned as
    // `fs_base`). The polling future + testbin runner plant this
    // into `IA32_FS_BASE` on each user-mode entry. A binary without
    // PT_TLS keeps `fs_base = None` and the entry path skips the
    // wrmsr. aarch64 wires its tpidr_el0 equivalent in a follow-up
    // round; until then `fs_base` stays `None` on non-x86_64.
    #[cfg(target_arch = "x86_64")]
    let fs_base = if image.tls.is_some() {
        // SAFETY: low-4-GiB identity map + frame allocator are the
        // same Stage-4 invariants the rest of this routine rides on.
        Some(unsafe { crate::tls::stage_tls(&image, bytes, &address_space) }?)
    } else {
        None
    };
    #[cfg(not(target_arch = "x86_64"))]
    let fs_base: Option<u64> = None;

    Ok(UserProcess {
        pid:           alloc_pid(),
        address_space,
        entry,
        stack_top:     VirtAddr::new(rsp),
        fs_base,
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
    let off  = vaddr & 0xFFFu64;
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
    address_space:     &AddressSpace,
    stack_top_vaddr:   u64,
    stack_bytes:       u64,
    argv:              &[&str],
    envp:              &[&str],
    aux:               &[AuxEntry],
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

    if total > stack_bytes { return Err(SysVStackError::Overflow); }

    let root = address_space.root;

    // Per-byte writer that resolves the destination phys per-page
    // through the AS — multi-page user stacks aren't necessarily
    // physically contiguous, so we can't precompute a single base.
    let write_u8 = |vaddr: u64, byte: u8| -> Result<(), SysVStackError> {
        let phys = resolve_user_phys_byte(root, vaddr).ok_or(SysVStackError::Overflow)?;
        unsafe { *(phys as *mut u8) = byte; }
        Ok(())
    };
    let write_u64 = |vaddr: u64, val: u64| -> Result<(), SysVStackError> {
        // u64 writes never cross a page boundary if vaddr is 8-aligned
        // (which all our targets are by construction).
        let phys = resolve_user_phys_byte(root, vaddr).ok_or(SysVStackError::Overflow)?;
        unsafe { *(phys as *mut u64) = val; }
        Ok(())
    };

    // String area: layout top-down. Walk argv first (highest addrs),
    // then envp. Track each string's user vaddr in two parallel
    // Vecs; we'll spill the pointer arrays in step 2.
    let mut argv_ptrs = alloc::vec::Vec::with_capacity(argv.len());
    let mut envp_ptrs = alloc::vec::Vec::with_capacity(envp.len());
    let mut cursor_vaddr  = stack_top_vaddr;
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
    let mut wv    = rsp_vaddr;

    write_u64(wv, argv.len() as u64)?;
    wv += 8;

    for &p in argv_ptrs.iter() { write_u64(wv, p)?; wv += 8; }
    write_u64(wv, 0)?; wv += 8;  // argv NULL term.

    for &p in envp_ptrs.iter() { write_u64(wv, p)?; wv += 8; }
    write_u64(wv, 0)?; wv += 8;  // envp NULL term.

    for e in aux.iter() {
        let (key, val) = aux_pair(e);
        write_u64(wv, key as u64)?;
        write_u64(wv + 8, val)?;
        wv += 16;
    }
    write_u64(wv, 0)?;        // AT_NULL key
    write_u64(wv + 8, 0)?;    // AT_NULL val

    Ok(rsp_vaddr)
}

fn aux_pair(e: &AuxEntry) -> (u32, u64) {
    let key = e.tag();
    let val = match *e {
        AuxEntry::Null         => 0,
        AuxEntry::Entry(v)     => v,
        AuxEntry::Phdr(v)      => v,
        AuxEntry::PhEnt(v)     => v as u64,
        AuxEntry::PhNum(v)     => v as u64,
        AuxEntry::Base(v)      => v,
        AuxEntry::ExecFn(v)    => v,
        AuxEntry::Pagesz(v)    => v as u64,
        AuxEntry::Hwcap(v)     => v,
        AuxEntry::Random(v)    => v,
        AuxEntry::Secure(b)    => if b { 1 } else { 0 },
    };
    (key, val)
}

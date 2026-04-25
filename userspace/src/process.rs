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

use crate::{alloc_pid, load_elf_bytes, loader::LoadBytesError, AuxEntry, EntryPoint, ProcessId};

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
}

/// Errors from `load_user_process`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProcessLoadError {
    Load(LoadBytesError),
    StackAllocFailed,
    StackMapFailed,
    StackMaterializeFailed,
}

impl From<LoadBytesError> for ProcessLoadError {
    fn from(e: LoadBytesError) -> Self { ProcessLoadError::Load(e) }
}

/// Parse + load `bytes` into a fresh `UserProcess` with a mapped
/// stack at `DEFAULT_USER_STACK_BASE ..+ DEFAULT_USER_STACK_BYTES`.
///
/// # Safety
/// - Identity mapping of the low 4 GiB must still be live (the
///   Stage-4 structural contract all of `load_elf_bytes` rides on).
/// - Frame allocator must be initialised.
pub unsafe fn load_user_process(bytes: &[u8]) -> Result<UserProcess, ProcessLoadError> {
    let (address_space, entry) = unsafe { load_elf_bytes(bytes) }?;

    // Allocate + map a user stack. Pages come from the global
    // frame allocator; they live in the AS's region table.
    let pages = (DEFAULT_USER_STACK_BYTES + 0xFFF) >> 12;
    let mut stack_first_phys = None;
    for i in 0..pages {
        let f = narf_memory::alloc_frame()
            .map_err(|_| ProcessLoadError::StackAllocFailed)?;
        let phys = f.start_address();
        if i == 0 { stack_first_phys = Some(phys); }
        // Zero the stack page.
        // SAFETY: identity-mapped in low 4 GiB.
        unsafe {
            core::ptr::write_bytes(phys.raw() as *mut u8, 0, 4096);
        }
    }
    let stack_phys = stack_first_phys.ok_or(ProcessLoadError::StackAllocFailed)?;

    address_space.map_region(Region {
        base:  VirtAddr::new(DEFAULT_USER_STACK_BASE),
        len:   pages * 4096,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys:  stack_phys,
    }).map_err(|_| ProcessLoadError::StackMapFailed)?;

    // SAFETY: AS is from `load_elf_bytes` (hence `new_for_user`)
    // and stack region was just pushed.
    unsafe { address_space.materialize() }
        .map_err(|_| ProcessLoadError::StackMaterializeFailed)?;

    Ok(UserProcess {
        pid:           alloc_pid(),
        address_space,
        entry,
        stack_top:     VirtAddr::new(DEFAULT_USER_STACK_BASE + pages * 4096),
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
/// - `stack_phys` must be the physical base of a contiguous run of
///   pages identity-mapped in the low 4 GiB. The stack region built
///   by `load_user_process` satisfies this when its allocation
///   loop yields contiguous frames.
/// - `stack_top_vaddr` must be the user vaddr corresponding to
///   `stack_phys + stack_bytes` (i.e. one past the last byte the
///   user can write).
/// - `stack_bytes` must equal the size of the mapped region.
pub unsafe fn init_sysv_stack(
    stack_phys:        PhysAddr,
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

    // Compute offsets from the top of the stack (highest address).
    // `top_phys` is the kernel-side identity-mapped writable
    // pointer to (stack_top_vaddr - 1) + 1.
    let top_phys = stack_phys.raw() + stack_bytes;

    // String area: layout top-down. Walk argv first (highest addrs),
    // then envp. Track each string's user vaddr in two parallel
    // Vecs; we'll spill the pointer arrays in step 2.
    let mut argv_ptrs = alloc::vec::Vec::with_capacity(argv.len());
    let mut envp_ptrs = alloc::vec::Vec::with_capacity(envp.len());
    let mut cursor_kernel = top_phys; // shrinks downward
    let mut cursor_vaddr  = stack_top_vaddr;
    for s in argv.iter() {
        let len = s.len() as u64 + 1;
        cursor_kernel -= len;
        cursor_vaddr  -= len;
        // SAFETY: identity-mapped, bounds-checked above.
        unsafe {
            core::ptr::copy_nonoverlapping(s.as_ptr(), cursor_kernel as *mut u8, s.len());
            *((cursor_kernel + s.len() as u64) as *mut u8) = 0;
        }
        argv_ptrs.push(cursor_vaddr);
    }
    for s in envp.iter() {
        let len = s.len() as u64 + 1;
        cursor_kernel -= len;
        cursor_vaddr  -= len;
        unsafe {
            core::ptr::copy_nonoverlapping(s.as_ptr(), cursor_kernel as *mut u8, s.len());
            *((cursor_kernel + s.len() as u64) as *mut u8) = 0;
        }
        envp_ptrs.push(cursor_vaddr);
    }
    // Drop kernel cursor down to the 8-byte boundary that anchors
    // the array region. The padded gap is left as zeroes by the
    // caller's stack zero-fill.
    let _ = cursor_kernel; // strings_padded already accounted for

    // Now compute the array positions. The bottom of the layout
    // (lowest addr, the user RSP) sits `total` bytes below the top.
    // From there going up: argc, argv*, envp*, aux*, then strings.
    let rsp_vaddr   = stack_top_vaddr - total;
    let rsp_kernel  = top_phys - total;

    // Walk up from the RSP, writing each section.
    let mut wp = rsp_kernel;
    let mut wv = rsp_vaddr;

    // argc.
    unsafe { *(wp as *mut u64) = argv.len() as u64; }
    wp += 8; wv += 8;

    // argv pointers.
    for &p in argv_ptrs.iter() {
        unsafe { *(wp as *mut u64) = p; }
        wp += 8; wv += 8;
    }
    unsafe { *(wp as *mut u64) = 0; } // NULL term.
    wp += 8; wv += 8;

    // envp pointers.
    for &p in envp_ptrs.iter() {
        unsafe { *(wp as *mut u64) = p; }
        wp += 8; wv += 8;
    }
    unsafe { *(wp as *mut u64) = 0; } // NULL term.
    wp += 8; wv += 8;

    // aux entries.
    for e in aux.iter() {
        let (key, val) = aux_pair(e);
        unsafe {
            *(wp as *mut u64) = key as u64;
            *((wp + 8) as *mut u64) = val;
        }
        wp += 16; wv += 16;
    }
    // AT_NULL terminator.
    unsafe {
        *(wp as *mut u64) = 0;
        *((wp + 8) as *mut u64) = 0;
    }

    let _ = wv; // walked-up vaddr cursor; final value isn't returned

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

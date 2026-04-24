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

use narf_memory::{AddressSpace, Region, RegionPerms, VirtAddr};

use crate::{alloc_pid, load_elf_bytes, loader::LoadBytesError, EntryPoint, ProcessId};

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

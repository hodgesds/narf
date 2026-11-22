//! The per-arch halves of hibernation (S4 lane 8): Linux's
//! `swsusp_arch_suspend` and `swsusp_arch_resume`.
//!
//! - [`capture`] runs in the hibernating kernel. It saves the CPU state
//!   the image resumes into, then takes the snapshot. It returns twice:
//!   once with the snapshot's result, and once more in the restored image,
//!   with [`Captured::Restored`].
//! - [`ArchRecord`] is what the boot kernel needs to resume that state. It
//!   travels in the payload header.
//! - [`restore`] runs in the boot kernel: the temporary page table and the
//!   relocated copy loop, then the jump. It never returns.
//!
//! x86_64 reuses the S3 resume context and wake trampoline
//! (`narf_arch::x86_64::s3_resume`), with the copy loop of
//! `narf_arch::x86_64::s4_restore`. aarch64 has no restore yet and
//! answers [`ArchError::NotImplemented`].

use super::payload::ARCH_RECORD_LEN;

/// Whether this architecture can hibernate and restore yet.
pub const SUPPORTED: bool = cfg!(target_arch = "x86_64");

/// What [`capture`] came back from.
#[derive(Debug)]
pub enum Captured<R> {
    /// The snapshot was taken; this is the hibernating kernel.
    Snapshot(R),
    /// This is the image, restored.
    Restored,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchError {
    /// No hibernation restore on this architecture yet.
    NotImplemented,
    /// A kernel address the restore needs did not translate.
    Untranslatable,
    /// The record is not this architecture's, or not this version.
    ForeignRecord,
    /// RAM reaches past what the temporary page table maps.
    TooMuchRam,
    /// No frame for the temporary page table or the copy loop.
    NoMemory,
}

/// The resume point: where the boot kernel jumps once the pages are back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchRecord {
    /// x86_64: the physical address of the image's S3 wake entry.
    pub entry_phys: u64,
}

const RECORD_TAG: u32 = if cfg!(target_arch = "x86_64") {
    0x8664_0001
} else {
    0xaa64_0001
};

impl ArchRecord {
    pub fn encode(&self) -> [u8; ARCH_RECORD_LEN] {
        let mut out = [0u8; ARCH_RECORD_LEN];
        out[..4].copy_from_slice(&RECORD_TAG.to_le_bytes());
        out[8..16].copy_from_slice(&self.entry_phys.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8; ARCH_RECORD_LEN]) -> Result<Self, ArchError> {
        if u32::from_le_bytes(bytes[..4].try_into().unwrap()) != RECORD_TAG {
            return Err(ArchError::ForeignRecord);
        }
        Ok(Self {
            entry_phys: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        })
    }
}

/// `swsusp_arch_suspend`: save the state the image resumes into, then run
/// `snapshot` with the record that resumes it.
///
/// # Safety
/// Interrupts are off on the only CPU running. The caller's frame stays
/// live until `snapshot` returns, because the restored image resumes
/// there. This function must not be inlined into a frame that returns
/// before the snapshot.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
pub unsafe fn capture<R>(snapshot: impl FnOnce(ArchRecord) -> R) -> Result<Captured<R>, ArchError> {
    use narf_arch::x86_64::{s3_resume, setjmp};
    use narf_memory::{PhysAddr, VirtAddr};
    // SAFETY: the caller's contract; the S3 suspend path saves the same.
    unsafe {
        s3_resume::save_resume_context();
        s3_resume::save_lapic_state();
    }
    save_cpu_state();
    let mut jmp = setjmp::JmpBuf::default();
    // SAFETY: `jmp` lives in this frame, which stays live until the
    // snapshot is taken; the restore long-jumps back into it.
    if unsafe { setjmp::setjmp(&mut jmp) } == s3_resume::S3_RESUMED_SENTINEL {
        return Ok(Captured::Restored);
    }
    *s3_resume::S3_CALLER_JMP.lock() = jmp;
    // SAFETY: CPL0 on the only CPU.
    let pml4 = PhysAddr::new(unsafe { narf_arch::x86_64::cr::read_cr3() } & !0xFFF);
    let phys = |virt: u64| {
        // SAFETY: `pml4` is the live root, identity-reachable as
        // `translate` needs; `virt` is a kernel address.
        unsafe { narf_memory::x86_64::paging::translate(pml4, VirtAddr::new(virt)) }
            .map(|p| p.raw() | (virt & 0xFFF))
            .ok_or(ArchError::Untranslatable)
    };
    let entry_phys = phys(s3_resume::s3_wake_entry as usize as u64)?;
    let ctx_phys = phys(s3_resume::resume_context_static_addr() as u64)?;
    s3_resume::set_resume_context_phys(ctx_phys);
    Ok(Captured::Snapshot(snapshot(ArchRecord { entry_phys })))
}

/// The CPU state the S3 context does not carry and a restore must put
/// back, as Linux's `restore_processor_state` does: the syscall entry MSRs,
/// which the boot kernel pointed at its own entry, and `IA32_TSC_AUX`, the
/// CPU number `rdtscp` reports.
#[cfg(target_arch = "x86_64")]
const SAVED_MSRS: [u32; 5] = [
    0xC000_0081, // STAR
    0xC000_0082, // LSTAR
    0xC000_0083, // CSTAR
    0xC000_0084, // SFMASK
    0xC000_0103, // TSC_AUX
];
#[cfg(target_arch = "x86_64")]
static MSR_VALUES: [core::sync::atomic::AtomicU64; SAVED_MSRS.len()] =
    [const { core::sync::atomic::AtomicU64::new(0) }; SAVED_MSRS.len()];

#[cfg(target_arch = "x86_64")]
fn save_cpu_state() {
    for (msr, slot) in SAVED_MSRS.iter().zip(&MSR_VALUES) {
        // SAFETY: architectural MSRs, read at CPL0.
        let value = unsafe { narf_arch::x86_64::msr::rdmsr(*msr) };
        slot.store(value, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Put back what [`capture`] saved beyond the S3 context, in the restored
/// image, before interrupts come back: the syscall MSRs and TSC_AUX, then
/// the task register (the S3 wake path ran in the image's GDT, but TR still
/// caches the boot kernel's TSS).
///
/// # Safety
/// CPL0 with interrupts off, in the image just restored, on the CPU that
/// took the snapshot.
#[cfg(target_arch = "x86_64")]
pub unsafe fn fix_cpu_after_restore() {
    for (msr, slot) in SAVED_MSRS.iter().zip(&MSR_VALUES) {
        // SAFETY: the values this CPU held when it took the snapshot.
        unsafe { narf_arch::x86_64::msr::wrmsr(*msr, slot.load(core::sync::atomic::Ordering::Relaxed)) };
    }
    let tss = (narf_arch::x86_64::segments::GDT_ENTRY_TSS * 8) as u16;
    // SAFETY: the image's GDT is live and holds its TSS at that entry.
    unsafe { narf_arch::x86_64::s4_restore::reload_task_register(tss) };
}

/// No hibernation restore on this architecture yet.
///
/// # Safety
/// As the x86_64 version.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn capture<R>(
    _snapshot: impl FnOnce(ArchRecord) -> R,
) -> Result<Captured<R>, ArchError> {
    Err(ArchError::NotImplemented)
}

/// Frames for the restore's own pages, which no image page may overwrite.
pub trait SafeFrames {
    /// A zeroed frame no image page is copied to, by physical address.
    fn safe_frame(&mut self) -> Option<u64>;
}

/// `swsusp_arch_resume`: build the temporary page table over `ram` (frame
/// ranges), copy the loop into a safe frame and jump: the loop copies the
/// restore list at `first_pb_phys` into place and enters the image at
/// `record`.
///
/// # Safety
/// Interrupts are off on the only CPU running, and every device is
/// quiesced. The restore list names every image page with a copy in a safe
/// frame, and `safe` hands out only frames no pair writes.
#[cfg(target_arch = "x86_64")]
pub unsafe fn restore(
    record: &ArchRecord,
    ram: &[(u64, u64)],
    first_pb_phys: u64,
    safe: &mut dyn SafeFrames,
) -> Result<core::convert::Infallible, ArchError> {
    use narf_memory::PhysAddr;
    const GIB: u64 = 1 << 30;
    const MIB2: u64 = 1 << 21;
    const PRESENT_RW: u64 = 0b11;
    const LEAF_2M: u64 = 1 << 7;
    let top = ram.last().map_or(0, |&(_, end)| end << 12);
    if top > 512 * GIB {
        return Err(ArchError::TooMuchRam);
    }
    let table = |phys: u64| PhysAddr::new(phys).kernel_mut_ptr::<u64>();
    let pml4 = safe.safe_frame().ok_or(ArchError::NoMemory)?;
    let pdpt = safe.safe_frame().ok_or(ArchError::NoMemory)?;
    // SAFETY: fresh, zeroed safe frames through the direct map.
    unsafe { *table(pml4) = pdpt | PRESENT_RW };
    // Identity 2 MiB leaves, executable, over every 2 MiB block that holds
    // RAM (Linux's `kernel_ident_mapping_init` over the mapped ranges).
    let mut pds = [0u64; 512];
    for &(start, end) in ram {
        let mut block = (start << 12) & !(MIB2 - 1);
        while block < end << 12 {
            let gib = (block / GIB) as usize;
            if pds[gib] == 0 {
                pds[gib] = safe.safe_frame().ok_or(ArchError::NoMemory)?;
                // SAFETY: as above.
                unsafe { *table(pdpt).add(gib) = pds[gib] | PRESENT_RW };
            }
            let slot = ((block % GIB) / MIB2) as usize;
            // SAFETY: as above.
            unsafe { *table(pds[gib]).add(slot) = block | PRESENT_RW | LEAF_2M };
            block += MIB2;
        }
    }
    // The kernel half of the live table, so the instruction after the CR3
    // write still fetches. Only the jump to the loop runs under it.
    // SAFETY: CPL0; the live PML4 is reachable through the direct map.
    let live = unsafe { narf_arch::x86_64::cr::read_cr3() } & !0xFFF;
    for slot in 256..512 {
        // SAFETY: both are whole PML4 pages.
        unsafe { *table(pml4).add(slot) = *table(live).add(slot) };
    }
    let code = narf_arch::x86_64::s4_restore::copy_loop();
    let loop_phys = safe.safe_frame().ok_or(ArchError::NoMemory)?;
    // SAFETY: a safe frame, written through the direct map; the loop is
    // smaller than a page.
    unsafe {
        core::ptr::copy_nonoverlapping(
            code.as_ptr(),
            PhysAddr::new(loop_phys).kernel_mut_ptr::<u8>(),
            code.len(),
        );
        narf_arch::x86_64::s4_restore::jump(pml4, loop_phys, first_pb_phys, record.entry_phys)
    }
}

/// No hibernation restore on this architecture yet.
///
/// # Safety
/// As the x86_64 version.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn restore(
    _record: &ArchRecord,
    _ram: &[(u64, u64)],
    _first_pb_phys: u64,
    _safe: &mut dyn SafeFrames,
) -> Result<core::convert::Infallible, ArchError> {
    Err(ArchError::NotImplemented)
}

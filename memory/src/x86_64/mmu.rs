//! MMU bring-up and the `console/` §3.1 handoff protocol.
//!
//! Builds the kernel's final PML4 — low identity map, high MMIO window,
//! optional high-half direct map, and the `-2 GiB` kernel window — executes
//! the handoff sequence in `console/` §3.1, and swaps CR3 to it.
//!
//! **Every leaf is `NO_EXEC` except the two ranges something demonstrably
//! fetches from.** That is what makes an RX mapping elsewhere in the address
//! space (BPF JIT text, most obviously) mean anything at all: before it, the
//! same physical bytes were writable *and* executable at their identity
//! address and again through the kernel window. The exceptions and how they
//! were derived are on [`kernel_exec_phys_range`] and
//! [`AP_TRAMPOLINE_EXEC_BASE`].
//!
//! The handoff sequence, verbatim from `console/` §3.1:
//!
//!   1. Build final page tables (including identity + kernel-virtual
//!      for the UART region).
//!   2. Call `console::write_str("mmu: handoff...\n")` via the current
//!      phys base — guaranteed visible.
//!   3. Execute MMU enable / CR3 load, then immediately call
//!      `console::remap_to_virtual(VIRT)`.
//!   4. Tear down identity mapping for the UART (kernel-virtual
//!      mapping is now sole).
//!
//! Stage 1 keeps the UART identity-mapped (no higher-half), so step
//! 4 is a no-op — the protocol still runs so future callers don't
//! have to retrofit the sequence.

#![cfg(target_arch = "x86_64")]

use crate::paging::{write_cr3, write_identity, PageTable, PageTableEntry, PtFlags};
use crate::{FrameAllocError, PhysAddr};

/// Errors from `init_mmu`. Stage-1 failure modes are limited to
/// frame exhaustion and alloc-before-init.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MmuError {
    FramesExhausted,
    AllocatorUninitialised,
}

impl From<FrameAllocError> for MmuError {
    fn from(e: FrameAllocError) -> Self {
        match e {
            FrameAllocError::Exhausted => MmuError::FramesExhausted,
            FrameAllocError::Uninitialised => MmuError::AllocatorUninitialised,
            // `NotSupported` (e.g. bump-impl free) and `AuthorityRevoked`
            // (Cap::check_live failure on install) shouldn't reach the
            // MMU alloc path — collapse to the closest existing error.
            FrameAllocError::NotSupported | FrameAllocError::AuthorityRevoked => {
                MmuError::AllocatorUninitialised
            }
        }
    }
}

/// PML4 index of the higher-half kernel base (-2 GiB). Virtual address
/// `0xFFFF_FFFF_8000_0000` decomposes as PML4=511, PDPT=510.
pub const HIGHER_HALF_PML4_INDEX: usize = 511;
/// PDPT index of the higher-half kernel base (-2 GiB).
pub const HIGHER_HALF_PDPT_INDEX: usize = 510;

/// Static-BSS storage for the four early page tables.
///
/// The frame allocator can return frames anywhere in usable RAM,
/// including above 4 GiB on machines where QEMU/UEFI splits RAM
/// around the PCI hole (q35 with -m ≥ 4G puts ~1 GiB of RAM at
/// 0x100000000+; real Zen2 laptops with 16 GiB do the same).
/// The boot.S identity map only covers 0..4 GiB, so a
/// high-frame return would page-fault on the first
/// `zero_at`/`write_identity` call.
///
/// Putting the tables in BSS guarantees they live within the
/// kernel image's load region (0x1000000+, well under 4 GiB)
/// and are therefore always reachable. Each `PageTable` is
/// `#[repr(C, align(4096))]` so the BSS layout is correct
/// for direct CR3 use.
#[repr(C, align(4096))]
struct EarlyPageTables {
    pml4: PageTable,
    pdpt_lo: PageTable,
    pdpt_hi_mmio: PageTable,
    pdpt_hi: PageTable,
    /// Demotion of the low identity map's first 1 GiB into 2-MiB leaves.
    pd_lo_0: PageTable,
    /// Demotion of that PD's first 2 MiB into 4-KiB leaves, so the AP
    /// trampoline window can be executable at page granularity.
    pt_lo_0: PageTable,
    /// Demotion of the higher-half kernel window (phys 0..1 GiB) into
    /// 2-MiB leaves, so only the kernel's own text stays executable.
    pd_hi_kernel: PageTable,
    /// PDPT for the FIRST direct-map chunk (physical [0, 512 GiB) at
    /// `KERNEL_DIRECT_MAP_BASE`) — i.e. the whole direct map on every
    /// machine with <= 512 GiB of RAM, which is all of them in practice.
    ///
    /// Static, like every other table here, rather than `alloc_frame()`.
    /// It used to come from the buddy, and the frame's contents were being
    /// overwritten at runtime: `smoke_direct_map_installed` found PDPT[0]
    /// holding a 4-KiB table pointer instead of its 1-GiB leaf, while
    /// PML4[384] still pointed at the original frame. A buddy frame that
    /// backs live kernel page tables but is not tracked as one is exactly
    /// the "kernel page table returned to the allocator, handed to a
    /// driver, memset to zero" failure the teardown code in
    /// `x86_64/paging.rs` documents. Static storage takes the frame out of
    /// the allocator's reach entirely.
    ///
    /// Chunks >= 1 (only on > 512 GiB machines) still allocate.
    pdpt_direct_0: PageTable,
}

const ZERO_ENTRIES: [PageTableEntry; 512] = [PageTableEntry::EMPTY; 512];
static mut EARLY_PAGE_TABLES: EarlyPageTables = EarlyPageTables {
    pml4: PageTable {
        entries: ZERO_ENTRIES,
    },
    pdpt_lo: PageTable {
        entries: ZERO_ENTRIES,
    },
    pdpt_hi_mmio: PageTable {
        entries: ZERO_ENTRIES,
    },
    pdpt_hi: PageTable {
        entries: ZERO_ENTRIES,
    },
    pd_lo_0: PageTable {
        entries: ZERO_ENTRIES,
    },
    pt_lo_0: PageTable {
        entries: ZERO_ENTRIES,
    },
    pd_hi_kernel: PageTable {
        entries: ZERO_ENTRIES,
    },
    pdpt_direct_0: PageTable {
        entries: ZERO_ENTRIES,
    },
};

/// Base of the executable window the SMP AP trampoline is copied into.
///
/// `frame/src/x86_64/smp.rs` copies the blob to physical `0x8000` (the SIPI
/// vector page) and the AP, having just set `CR0.PG` with *this* PML4 in CR3,
/// keeps fetching instructions from `0x8000 + off` through the `lgdt`, the far
/// jump into `_ap_long_mode_start`, and the indirect `jmp rax` that finally
/// leaves for the higher half. Those fetches walk the low identity map, so
/// this window — and nothing else below 1 GiB outside the kernel image — must
/// stay executable.
pub const AP_TRAMPOLINE_EXEC_BASE: u64 = 0x8000;

/// Bytes of the AP-trampoline executable window. Two 4-KiB pages; the blob is
/// a few hundred bytes of code plus its parameter block and a 32-bit GDT.
/// `install_trampoline` asserts the blob fits, so growing it past this fails
/// loudly at boot instead of as an AP that never checks in.
pub const AP_TRAMPOLINE_EXEC_LEN: u64 = 0x2000;

/// Higher-half base the kernel image is linked at.
const KERNEL_VIRT_BASE: u64 = 0xFFFF_FFFF_8000_0000;

unsafe extern "C" {
    /// First byte of the kernel image, as a *physical* address: the linker
    /// script declares it before `. += KERNEL_VIRT_BASE`.
    static __kernel_start: u8;
    /// End of `.text`, as a *kernel-virtual* address.
    static __text_end: u8;
}

/// The one physical range that must remain executable through *both* the low
/// identity map and the higher-half kernel window: `[__kernel_start,
/// __text_end)`.
///
/// It spans `.boot` (whose VMA equals its LMA, so `long_mode_start` and the
/// `call _start_rust` return address live at identity addresses) and `.text`.
/// `.text` needs its identity alias because the ACPI S3 wake vector is armed
/// with `s3_wake_entry`'s *physical* address: firmware re-enters it in low
/// memory and it keeps fetching there across its own `mov cr3` until the
/// `longjmp` restores a higher-half RIP (`arch/src/x86_64/s3_resume.rs`).
///
/// Everything past `__text_end` — `.rodata`, `.data`, `.bss` (which holds the
/// bootstrap heap arena), `.got` — and every frame the buddy ever hands out is
/// outside this range and is therefore NX in every kernel mapping.
fn kernel_exec_phys_range() -> (u64, u64) {
    let start = core::ptr::addr_of!(__kernel_start) as u64;
    let end = (core::ptr::addr_of!(__text_end) as u64).wrapping_sub(KERNEL_VIRT_BASE);
    // Defensive: a linker-script edit that inverted these, or moved the image
    // out of the first GiB, would otherwise silently produce an unbootable
    // (or silently over-permissive) map. Clamp to "whole first GiB
    // executable" — that boots, and `smoke_kernel_text_executable_bss_is_not`
    // goes red so the regression is visible rather than latent.
    if end <= start || end > (1u64 << 30) {
        return (0, 1u64 << 30);
    }
    (start, end)
}

/// Does `[base, base + len)` overlap `[lo, hi)`?
#[inline]
const fn overlaps(base: u64, len: u64, lo: u64, hi: u64) -> bool {
    base < hi && lo < base + len
}

/// True if a leaf covering `[phys, phys + len)` must be executable through the
/// *kernel image* window — the higher-half `-2 GiB` map, where only the
/// kernel's own text is ever fetched.
fn kernel_window_leaf_needs_exec(phys: u64, len: u64) -> bool {
    let (kstart, kend) = kernel_exec_phys_range();
    overlaps(phys, len, kstart, kend)
}

/// True if a leaf covering `[phys, phys + len)` must be executable through the
/// *low identity* map. Same set as the kernel window plus the AP trampoline
/// window, which only exists at an identity address.
/// Unmap PML4[0] — the AP trampoline window — once SMP bring-up is done.
///
/// The window is mapped `PRESENT | WRITABLE` and executable, because an AP
/// executes from it in real mode before it can reach any high-half address.
/// That leaves two RWX pages at a fixed, well-known physical address
/// (`AP_TRAMPOLINE_EXEC_BASE`) for the life of the boot — and since the
/// kernel stopped identity-mapping RAM, they are the *only* thing in the low
/// half, which makes them a precise target rather than a needle in 512 GiB.
/// An arbitrary kernel write lands shellcode there and it is immediately
/// executable, with no page-table manipulation needed: exactly the property
/// `text_poke`'s W^X machinery exists to deny everywhere else.
///
/// Linux keeps its equivalent window and settles for splitting it — see
/// `arch/x86/realmode/init.c::set_real_mode_permissions`, which marks the
/// blob NX+RO and re-marks only its text executable — because it reuses the
/// realmode trampoline for S3 resume. NARF does not: `s3_wake_entry` is a
/// naked-asm function in the kernel image that firmware identity-maps during
/// the wake handoff and which loads CR3 itself, so nothing needs this window
/// after bring-up. That lets us drop the mapping outright instead.
///
/// Ordering: an AP touches the window only until it jumps to
/// `_ap_start_rust` in the high half, and `start_aps` spins until every AP
/// has marked itself online from inside that function. So once `start_aps`
/// returns, no CPU can be executing here.
///
/// If CPU hotplug ever lands it will need this window back — re-establish it
/// around the bring-up rather than keeping it mapped for the whole boot.
///
/// # Safety
/// Call only after `start_aps` has returned. Unmapping while an AP is still
/// in the trampoline triple-faults it.
pub unsafe fn drop_ap_trampoline_window() {
    use crate::paging::{PageTable, PageTableEntry};
    // SAFETY: CPL=0; CR3 names the live kernel PML4.
    let cr3 = unsafe { crate::paging::read_cr3() };
    // SAFETY: the live PML4 is reachable through the direct map.
    let pml4 = unsafe { &mut *cr3.kernel_mut_ptr::<PageTable>() };
    if !pml4.entries[0].is_present() {
        return;
    }
    pml4.entries[0] = PageTableEntry::from_raw(0);
    // Every online CPU shares this PML4, so the stale top-level translation
    // has to be dropped everywhere, not just here.
    // SAFETY: invalidating a mapping we just removed.
    unsafe {
        crate::paging::invlpg_global(crate::VirtAddr::new(AP_TRAMPOLINE_EXEC_BASE));
    }
}

/// Pick the PML4 slot the direct map is built at.
///
/// The base used to be the fixed `KERNEL_DIRECT_MAP_BASE` (slot 384), so a
/// leaked physical address became a kernel VA with one OR against a constant
/// an attacker already knows. Randomizing the slot puts that behind a value
/// chosen at boot — the same reasoning behind Linux randomizing
/// `page_offset_base` (`arch/x86/mm/kaslr.c`).
///
/// Entropy is bounded by the OR: `PhysAddr::kernel_ptr` computes
/// `phys | base`, which equals `base + phys` only while the base has zeros in
/// every bit a physical address can set. A `chunks`-slot map lets `phys` reach
/// into the next `chunks - 1` slot indices, so the base must be aligned to the
/// next power of two at or above `chunks`. With RAM under 512 GiB that is one
/// slot and any of PML4[384..=510] will do — about 7 bits. Coarser than
/// Linux's 1 GiB-granular randomization, which is the price of OR; switching
/// to ADD would buy more, but the OR is deliberate (it keeps the accessor
/// idempotent for a kernel VA a caller wrapped in a `PhysAddr`), so it stays.
///
/// Falls back to the fixed base when no entropy is available, rather than
/// pretending to randomize with something predictable.
fn pick_direct_map_slot(chunks: u64) -> usize {
    const FIRST: usize = crate::addr::KERNEL_DIRECT_MAP_PML4_BASE;
    const SLOTS: usize = crate::addr::KERNEL_DIRECT_MAP_PML4_SLOTS;
    let align = (chunks as usize).next_power_of_two();
    // Slots that both fit `chunks` and keep `FIRST + k*align` aligned.
    let first_aligned = FIRST.div_ceil(align) * align;
    if first_aligned + chunks as usize > FIRST + SLOTS {
        return FIRST;
    }
    let choices = (FIRST + SLOTS - (first_aligned + chunks as usize)) / align + 1;
    if choices <= 1 {
        return FIRST;
    }
    // SAFETY: RDRAND is a plain instruction; the helper reports absence.
    let Some(r) = (unsafe { narf_arch::x86_64::hwrng::try_rdrand_u32() }) else {
        return FIRST;
    };
    first_aligned + (r as usize % choices) * align
}

fn identity_leaf_needs_exec(phys: u64, len: u64) -> bool {
    kernel_window_leaf_needs_exec(phys, len)
        || overlaps(
            phys,
            len,
            AP_TRAMPOLINE_EXEC_BASE,
            AP_TRAMPOLINE_EXEC_BASE + AP_TRAMPOLINE_EXEC_LEN,
        )
}

/// Build a fresh PML4 with:
///   * PML4[0] → PDPT covering the low 512 GiB identity-mapped. Keeps
///     low-half addresses live for the BSP boot stack, the AP stacks, and
///     every kernel pointer derived from a `PhysAddr`. **NX everywhere
///     except the kernel image's text and the AP trampoline window** — see
///     [`identity_leaf_needs_exec`]; the first 1 GiB is demoted to 2-MiB
///     leaves and its first 2 MiB again to 4-KiB leaves so those two
///     exceptions can be stated at page granularity.
///   * PML4[511] → a second PDPT whose PDPT[510] maps
///     `0xFFFF_FFFF_8000_0000..0xFFFF_FFFF_C000_0000` to physical
///     `0x0..0x4000_0000`. This is the higher-half window the linker
///     script places `.text/.rodata/.data/.bss` into — the same physical
///     pages become reachable at both low and high virtual addresses.
///     Demoted to 2-MiB leaves and NX outside `[__kernel_start,
///     __text_end)`, because a 1-GiB RWX block here aliases the whole of
///     a small machine's buddy arena and would undo the identity map's NX.
///
///   * PML4[384 + i] → the high-half **kernel direct map**: one PDPT
///     per 512 GiB of installed RAM (`max_ram_phys`), each mapping
///     `KERNEL_DIRECT_MAP_BASE + P` to physical `P` via 1-GiB huge
///     pages. This is what lets the kernel reach RAM above 512 GiB —
///     the low identity map stops at PML4[0] (512 GiB) because
///     PML4[1..255] is claimed by user address space, so high RAM needs
///     its own kernel-only window. `direct_map_activate` publishes it
///     after the CR3 swap; `PhysAddr::kernel_mut_ptr` then adds the
///     offset.
///
/// Returns the physical address of the new PML4.
///
/// `max_ram_phys` is the exclusive top of installed RAM (bytes); the
/// direct map is sized to cover `[0, max_ram_phys)` rounded up to a
/// 512 GiB PML4-slot boundary.
///
/// This function is the *memory/* half of the `console/` §3.1
/// handoff protocol; the caller (`frame/main.rs`) is responsible for
/// the `mmu: handoff...` print immediately before and the
/// `console::remap_to_virtual(...)` call immediately after.
///
/// # Safety
/// - Must be called once, on the BSP, with interrupts disabled and no
///   concurrent MMU activity.
/// - `memory::init_from_map` must have populated the frame allocator.
/// - Every address range the kernel will access after this call must
///   be covered by the identity map being built (currently the low
///   4 GiB + the high-half -2 GiB window).
pub unsafe fn init_mmu(max_ram_phys: u64) -> Result<PhysAddr, MmuError> {
    // Use BSS-resident page tables (see `EarlyPageTables` doc) so
    // the four storage buffers are guaranteed to be in the
    // boot.S 4-GiB identity-mapped window. Asking the frame
    // allocator could return a frame above 4 GiB on machines
    // with the PCI-hole RAM split, which would fault on the
    // first write.
    //
    // The address-of yields a HIGH-HALF VIRTUAL address (kernel
    // is linked at `KERNEL_VIRT_BASE = 0xFFFFFFFF80000000`).
    // CR3 + PageTableEntry::new both want PHYSICAL addresses, so
    // subtract the kernel virt base to convert. The boot.S
    // higher-half mapping makes `phys = virt - 0xFFFFFFFF80000000`
    // exact for kernel-image symbols.
    //
    // SAFETY: single-threaded boot path; this is the only writer
    // to `EARLY_PAGE_TABLES`.
    let tables_ptr = core::ptr::addr_of_mut!(EARLY_PAGE_TABLES);
    // SAFETY: MMIO access to the device's mapped register block; the offset lies within the mapped BAR.
    let pml4_virt = unsafe { core::ptr::addr_of_mut!((*tables_ptr).pml4) } as u64;
    // SAFETY: MMIO access to the device's mapped register block; the offset lies within the mapped BAR.
    let pdpt_lo_virt = unsafe { core::ptr::addr_of_mut!((*tables_ptr).pdpt_lo) } as u64;
    // SAFETY: MMIO access to the device's mapped register block; the offset lies within the mapped BAR.
    let pdpt_hi_mmio_virt = unsafe { core::ptr::addr_of_mut!((*tables_ptr).pdpt_hi_mmio) } as u64;
    // SAFETY: single-threaded boot-time access to this static; no concurrent mutation is possible.
    let pdpt_hi_virt = unsafe { core::ptr::addr_of_mut!((*tables_ptr).pdpt_hi) } as u64;
    // SAFETY: single-threaded boot-time access to this static; no concurrent mutation is possible.
    let pd_lo_0_virt = unsafe { core::ptr::addr_of_mut!((*tables_ptr).pd_lo_0) } as u64;
    // SAFETY: single-threaded boot-time access to this static; no concurrent mutation is possible.
    let pt_lo_0_virt = unsafe { core::ptr::addr_of_mut!((*tables_ptr).pt_lo_0) } as u64;
    // SAFETY: single-threaded boot-time access to this static; no concurrent mutation is possible.
    let pd_hi_kernel_virt = unsafe { core::ptr::addr_of_mut!((*tables_ptr).pd_hi_kernel) } as u64;
    let pml4_addr = PhysAddr::new(pml4_virt.wrapping_sub(KERNEL_VIRT_BASE));
    let pdpt_lo_addr = PhysAddr::new(pdpt_lo_virt.wrapping_sub(KERNEL_VIRT_BASE));
    let pdpt_hi_mmio_addr = PhysAddr::new(pdpt_hi_mmio_virt.wrapping_sub(KERNEL_VIRT_BASE));
    let pdpt_hi_addr = PhysAddr::new(pdpt_hi_virt.wrapping_sub(KERNEL_VIRT_BASE));
    let pd_lo_0_addr = PhysAddr::new(pd_lo_0_virt.wrapping_sub(KERNEL_VIRT_BASE));
    let pt_lo_0_addr = PhysAddr::new(pt_lo_0_virt.wrapping_sub(KERNEL_VIRT_BASE));
    let pd_hi_kernel_addr = PhysAddr::new(pd_hi_kernel_virt.wrapping_sub(KERNEL_VIRT_BASE));
    // SAFETY: single-threaded boot-time access to this static; no concurrent mutation is possible.
    let pdpt_direct_0_virt = unsafe { core::ptr::addr_of_mut!((*tables_ptr).pdpt_direct_0) } as u64;
    let pdpt_direct_0_addr = PhysAddr::new(pdpt_direct_0_virt.wrapping_sub(KERNEL_VIRT_BASE));

    // These frames came from the allocator and are identity-mapped in
    // the boot.S page tables (the low 1 GiB huge page covers them),
    // so the raw pointer is valid for a 4 KiB write.
    PageTable::zero_at(pml4_addr.kernel_mut_ptr::<PageTable>());
    PageTable::zero_at(pdpt_lo_addr.kernel_mut_ptr::<PageTable>());
    PageTable::zero_at(pdpt_hi_mmio_addr.kernel_mut_ptr::<PageTable>());
    PageTable::zero_at(pdpt_hi_addr.kernel_mut_ptr::<PageTable>());
    PageTable::zero_at(pd_lo_0_addr.kernel_mut_ptr::<PageTable>());
    PageTable::zero_at(pt_lo_0_addr.kernel_mut_ptr::<PageTable>());
    PageTable::zero_at(pd_hi_kernel_addr.kernel_mut_ptr::<PageTable>());

    // Step 2: populate.
    //
    // **Every leaf is NX unless something demonstrably executes there.**
    // Before this, all four windows were `PRESENT | WRITABLE | HUGE_PAGE`,
    // which made every physical frame simultaneously writable *and*
    // executable at its identity address — so mapping BPF JIT text RX at a
    // private kernel VA bought nothing, and any kernel data the attacker
    // could write was directly runnable. `identity_leaf_needs_exec` /
    // `kernel_window_leaf_needs_exec` derive the exceptions from the linker
    // symbols and the SIPI vector, not from a guess.
    let flags_ptr = PtFlags::PRESENT | PtFlags::WRITABLE;
    let flags_1gb = PtFlags::PRESENT | PtFlags::WRITABLE | PtFlags::HUGE_PAGE | PtFlags::NO_EXEC;
    // SAFETY: the PML4/PDPT storage is identity-mapped (low 1 GiB of
    // boot.S's table), so writes go to the intended physical memory.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        // Low-identity PML4 + PDPT. Fill the whole PDPT (512 × 1 GiB
        // huge pages) so virt 0..512 GiB identity-maps phys 0..512 GiB.
        // The old map stopped at 4 GiB, which forced the frame
        // allocator's `EARLY_PHYS_CEILING` to permanently exclude all
        // RAM above 4 GiB: on a q35 PCI-hole split (QEMU -m ≥ 4G, real
        // 16 GiB laptops) usable RAM is relocated to start at phys
        // 4 GiB, so anything past the boundary was untouchable and a
        // direct `phys.kernel_mut_ptr::<T>()` access would #PF. Blanketing
        // the low 512 GiB makes every installed frame reachable by an
        // identity (phys == virt) pointer; unpopulated gaps in that
        // range are simply never accessed (the buddy only hands out
        // real RAM). 512 GiB is the PDPT's full reach and dwarfs any
        // supported machine. Caller releases the ceiling once this
        // map is live.
        let pml4_lo_entry = PageTableEntry::new(pdpt_lo_addr, flags_ptr);
        write_identity::<PageTableEntry>(pml4_addr, pml4_lo_entry);
        // Slot 0 is the only 1-GiB slot with anything executable in it, so it
        // is the only one that gets demoted. Slots 1..512 stay 1-GiB NX
        // leaves: 511 huge pages, one iTLB-irrelevant entry each, exactly as
        // before except for bit 63.
        // PDPT[1..512] are left EMPTY. They used to identity-map
        // 1 GiB..512 GiB of RAM, which is what made `phys as *mut T` work
        // anywhere in the kernel and hid a whole class of bug: a physical
        // address dereferenced by the CPU still "worked" on the kernel CR3,
        // so it only failed once a user address space was active. The
        // virtqueue ring accessors survived four grep sweeps, a newtype, two
        // code reviews and a CI guard exactly that way.
        //
        // Kernel access to RAM goes through the high-half direct map
        // (KERNEL_DIRECT_MAP_BASE). With these slots gone, a leftover
        // identity deref faults IMMEDIATELY, in any context, so the existing
        // test suite finds it instead of a userspace-driven CI job.
        //
        // Linux has no identity map of RAM at all for the same reason;
        // `__va()` is the only way there.
        let _ = flags_1gb;

        // ── Demotion, level 1: identity 0..1 GiB, 1 GiB → 512 × 2 MiB ──
        //
        // Built here rather than by splitting a live mapping. `demote_page`
        // in `address_space.rs` is unrelated (it is NUMA *tier* demotion —
        // it moves a page to a slower node and never changes leaf size), and
        // splitting the huge page the kernel is standing on, after the CR3
        // swap and with APs running, would need a break-before-make on the
        // window that holds the BSP stack. Constructing the table *before*
        // the swap makes the whole hazard class disappear: the first CR3
        // that ever sees these addresses already has them at 2-MiB / 4-KiB
        // granularity, so there is no TLB entry of the old size to conflict
        // with and no INVLPG to get wrong.
        write_identity::<PageTableEntry>(
            pdpt_lo_addr,
            PageTableEntry::new(pd_lo_0_addr, flags_ptr),
        );
        // PD[0] is demoted again (below); PD[1..512] are 2-MiB leaves,
        // executable only where the kernel image's text lives.
        // PD[1..512] are left EMPTY — see the PDPT comment above. Only the
        // first 2 MiB survives, and only for the AP trampoline.

        // ── Demotion, level 2: identity 0..2 MiB, 2 MiB → 512 × 4 KiB ──
        //
        // Only so the AP trampoline window can be executable at page
        // granularity. Leaving the whole first 2 MiB executable would hand
        // an attacker 2 MiB of RWX at a fixed, well-known address; this
        // narrows it to the two pages the SIPI vector actually needs.
        write_identity::<PageTableEntry>(
            pd_lo_0_addr,
            PageTableEntry::new(pt_lo_0_addr, flags_ptr),
        );
        // ONLY the AP trampoline pages are mapped. An AP starts in real mode
        // at the SIPI vector, enables paging with THIS PML4 in CR3, and keeps
        // fetching from `AP_TRAMPOLINE_EXEC_BASE + off` until the far jump —
        // so those pages must be identity-mapped and executable. Linux keeps
        // a dedicated trampoline PGD entry for exactly this reason.
        //
        // Every other page of the first 2 MiB is left unmapped, so the low
        // half of the kernel address space now contains nothing but the
        // trampoline.
        let tramp_first = AP_TRAMPOLINE_EXEC_BASE >> 12;
        let tramp_last = (AP_TRAMPOLINE_EXEC_BASE + AP_TRAMPOLINE_EXEC_LEN - 1) >> 12;
        for page in tramp_first..=tramp_last {
            let phys = page << 12;
            let mut flags = PtFlags::PRESENT | PtFlags::WRITABLE;
            if !identity_leaf_needs_exec(phys, 1 << 12) {
                flags |= PtFlags::NO_EXEC;
            }
            let slot = PhysAddr::new(pt_lo_0_addr.raw() + page * 8);
            write_identity::<PageTableEntry>(slot, PageTableEntry::new(PhysAddr::new(phys), flags));
        }

        // High-MMIO identity (PML4[1]: virt 512 GiB ≤ V < 1 TiB →
        // phys 512 GiB ≤ P < 1 TiB). Covers UEFI-assigned 64-bit
        // BARs whose phys address sits above the low-4 GiB window.
        // OVMF on QEMU q35 places NVMe / virtio-PCI BARs around
        // phys 0xC0_0000_0000 (768 GiB); on real consumer hardware
        // the BARs typically sit between 0x80_0000_0000 and
        // 0xFE_0000_0000.
        //
        // PDPT[0] of this PML4 slot is reserved: user-mode binaries
        // (init / shell / testbin) link at virt
        // 0x0000_0080_0000_1000 which decodes to PML4[1] PDPT[0]
        // PD[0] PT[1]. Mapping PDPT[0] as a 1-GiB huge page would
        // collide with the user `materialize`'s 4-KiB descent.
        // Skipping it costs nothing — phys 512 GiB ≤ P < 513 GiB
        // is RAM territory in any sane laptop, never MMIO.
        let pml4_hi_mmio_entry = PageTableEntry::new(pdpt_hi_mmio_addr, flags_ptr);
        // PML4[1]: entry index 1 * 8 bytes per entry = byte offset 8.
        let pml4_hi_mmio_slot = PhysAddr::new(pml4_addr.raw() + 8);
        write_identity::<PageTableEntry>(pml4_hi_mmio_slot, pml4_hi_mmio_entry);
        for gib in 1u64..512 {
            // Each PDPT entry covers virt 512 GiB + gib * 1 GiB,
            // identity-mapped to the matching phys.
            let phys = PhysAddr::new((512 + gib) << 30);
            let entry = PageTableEntry::new(phys, flags_1gb);
            let slot = PhysAddr::new(pdpt_hi_mmio_addr.raw() + gib * 8);
            write_identity::<PageTableEntry>(slot, entry);
        }

        // High-half PML4[511] + PDPT[510] → phys 0..1 GiB.
        // Virtual 0xFFFF_FFFF_8000_0000 + x maps to physical 0 + x.
        let pml4_hi_entry = PageTableEntry::new(pdpt_hi_addr, flags_ptr);
        let pml4_hi_slot = PhysAddr::new(pml4_addr.raw() + (HIGHER_HALF_PML4_INDEX as u64) * 8);
        write_identity::<PageTableEntry>(pml4_hi_slot, pml4_hi_entry);

        // This used to be one 1-GiB RWX huge page, and closing only the
        // *identity* map would have left it as a complete replacement for
        // it: it aliases phys 0..1 GiB — where a small-RAM boot does all of
        // its buddy allocation, including BPF prog packs — writable and
        // executable at `KERNEL_VIRT_BASE + phys`. Demoting it to 2-MiB
        // leaves and marking every block outside `[__kernel_start,
        // __text_end)` NX is what makes "no writable+executable alias of
        // heap memory" true rather than true-of-one-window.
        //
        // The kernel's own text stays WRITABLE here on purpose: `patch_word`,
        // alternatives patching and the static-key machinery all write kernel
        // text through this window. Making kernel text read-only is a
        // separate, larger change (it needs a text-poke path of its own) and
        // is *not* claimed by this work.
        write_identity::<PageTableEntry>(
            PhysAddr::new(pdpt_hi_addr.raw() + (HIGHER_HALF_PDPT_INDEX as u64) * 8),
            PageTableEntry::new(pd_hi_kernel_addr, flags_ptr),
        );
        for two_mb in 0u64..512 {
            let phys = two_mb << 21;
            let mut flags = PtFlags::PRESENT | PtFlags::WRITABLE | PtFlags::HUGE_PAGE;
            if !kernel_window_leaf_needs_exec(phys, 1 << 21) {
                flags |= PtFlags::NO_EXEC;
            }
            let slot = PhysAddr::new(pd_hi_kernel_addr.raw() + two_mb * 8);
            write_identity::<PageTableEntry>(slot, PageTableEntry::new(PhysAddr::new(phys), flags));
        }
    }

    // High-half kernel direct map (PML4[384 + chunk]). Give the kernel a
    // window that reaches RAM above 512 GiB, which the low identity map
    // can't cover (PML4[1..255] is user address space). Slot 384 clears
    // both the PCID per-domain private range (PML4[256..271], which
    // domain.rs *overwrites* per domain) and the kernel image
    // (PML4[511]); see KERNEL_DIRECT_MAP_BASE. Each PML4 slot spans
    // 512 GiB, so one BSS PDPT of 512 × 1-GiB huge pages covers each
    // 512-GiB chunk of RAM. PML4[256..512] is copied verbatim into every
    // per-domain / user PML4 (see x86_64/paging.rs), so the direct map
    // reaches every address space without extra work.
    //
    // Built UNCONDITIONALLY. It used to be built only when installed RAM
    // exceeded the low identity map (512 GiB), on the reasoning that below
    // that every frame is reachable at `phys == virt` so the map is pure
    // overhead.
    //
    // That reasoning holds only while the kernel is willing to spend PML4[0]
    // on an identity map — and that is what stops NARF running an ordinary
    // Linux static binary. `gcc -static` emits ET_EXEC with PT_LOAD at
    // 0x400000, which lands in PML4[0]; with the identity map there, user
    // VA 0x400000 aliases PHYSICAL 0x400000, kernel memory mapped U=0, and
    // `load_elf_bytes` has to refuse it. Freeing the low half means the
    // kernel needs a way to reach physical memory that is not the identity
    // map, and this is it.
    //
    // Making it unconditional is step one: nothing yet depends on it, so a
    // small-RAM boot simply gains a second, redundant view of RAM. The
    // switchover (`kernel_ptr` routing through it, then dropping PML4[0])
    // comes after this is proven present and harmless.
    const CHUNK_BYTES: u64 = 512u64 << 30; // one PML4 slot = 512 GiB
    let build_direct_map = true;
    // Base the map ends up at; 0 until it is built. Published to the
    // accessors after the CR3 swap.
    let mut dmap_base: u64 = 0;
    if build_direct_map {
        let want_chunks = max_ram_phys.div_ceil(CHUNK_BYTES).max(1);
        let dmap_chunks = want_chunks.min(crate::addr::KERNEL_DIRECT_MAP_PML4_SLOTS as u64);
        let dmap_pml4_base = pick_direct_map_slot(dmap_chunks);
        // Sign-extend: every slot here is >= 256, so bit 47 is set and a
        // canonical VA needs bits 63..48 set too. Without this the base is
        // non-canonical and the first access #GPs rather than faulting.
        dmap_base = 0xFFFF_0000_0000_0000 | ((dmap_pml4_base as u64) << 39);
        for chunk in 0..dmap_chunks {
            // PDPT frames come from the buddy: the early phys ceiling is
            // still armed (the caller releases it only after we return),
            // so each is < 4 GiB and reachable through the boot identity
            // map for the fill writes below. This alloc only runs on
            // > 512 GiB machines, so a small-RAM boot's frame layout is
            // untouched.
            // Chunk 0 uses static storage (see `pdpt_direct_0`); only the
            // >512 GiB chunks come from the allocator.
            let pdpt = if chunk == 0 {
                pdpt_direct_0_addr
            } else {
                crate::frame::alloc_frame()?.start_address()
            };
            // SAFETY: `pdpt` is < 4 GiB, identity-mapped by boot.S, so the
            // raw pointer is valid for a 4 KiB zero + entry writes.
            unsafe {
                PageTable::zero_at(pdpt.kernel_mut_ptr::<PageTable>());
                for gib in 0u64..512 {
                    let phys = PhysAddr::new(chunk * CHUNK_BYTES + (gib << 30));
                    let entry = PageTableEntry::new(phys, flags_1gb);
                    let slot = PhysAddr::new(pdpt.raw() + gib * 8);
                    write_identity::<PageTableEntry>(slot, entry);
                }
                let pml4_idx = dmap_pml4_base as u64 + chunk;
                let pml4_slot = PhysAddr::new(pml4_addr.raw() + pml4_idx * 8);
                write_identity::<PageTableEntry>(pml4_slot, PageTableEntry::new(pdpt, flags_ptr));
            }
        }
    }

    // Step 3 from console/ §3.1: *caller* prints the handoff line
    // before calling us so a panic across the CR3 swap is visible.
    //
    // Step 4: swap CR3. Any access from this instruction forward uses
    // the new PML4. The new mapping identity-covers 0..512 GiB, which
    // includes:
    //   - the kernel image (loaded at phys 0x100000)
    //   - the UART (I/O ports, not memory, so MMU-irrelevant)
    //   - the heap + allocator bookkeeping (in the kernel image's .bss)
    //   - the newly-allocated PML4 + PDPT themselves
    // so control-flow continues uninterrupted.
    //
    // SAFETY: invariants above; caller supplied the single-CPU BSP
    // precondition.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        write_cr3(pml4_addr);
    }

    // If we installed the high-half direct map, publish it so the
    // kernel RAM accessors switch >= 512 GiB frames to the offset
    // window. AFTER the CR3 swap: until now kernel_mut_ptr must stay on
    // identity (the boot CR3 has no high-half map). When no direct map
    // was built (RAM <= 512 GiB) the flag stays false and every frame is
    // reached at `phys == virt` through the low identity map.
    if build_direct_map {
        crate::addr::direct_map_activate_at(dmap_base);
        // `narf-arch` cannot call `kernel_ptr` (narf-memory depends on it, so
        // the reverse would be a cycle), and its ACPI table parser can no
        // longer rely on a low identity map — that is gone as of this
        // function, bar the AP trampoline. Hand it the same offset the kernel
        // accessors use, before any table is touched.
        narf_lib::directmap::set_offset(dmap_base);
    }

    // Step 5: *caller* notifies the console with a post-switch
    // `remap_to_virtual(virt)`.
    //
    // Step 6 from console/ §3.1 is "tear down the identity map for
    // UART now that the kernel-virtual mapping is sole." At Stage 1
    // there *is* no separate kernel-virtual mapping, so this step is
    // intentionally a no-op. Wave 2 higher-half migration adds the
    // kernel-virtual map and the tear-down.

    Ok(pml4_addr)
}

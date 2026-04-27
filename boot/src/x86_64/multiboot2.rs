//! Xen PVH `hvm_start_info` parser.
//!
//! (File named `multiboot2` for forward-compat with the eventual Limine /
//! v2 integration; Stage 1 uses PVH because it's the only ELF64 path
//! `qemu-system-x86_64 -kernel` supports out of the box. See `boot/` spec
//! §5 for the design-time target; boot.S has the deviation note.)
//!
//! `hvm_start_info` layout (all little-endian):
//!
//! ```text
//! offset  field              type
//! 0x00    magic              u32  = 0x336e_c578 ("xEn3")
//! 0x04    version            u32
//! 0x08    flags              u32
//! 0x0C    nr_modules         u32
//! 0x10    modlist_paddr      u64
//! 0x18    cmdline_paddr      u64
//! 0x20    rsdp_paddr         u64
//! 0x28    memmap_paddr       u64
//! 0x30    memmap_entries     u32
//! 0x34    reserved           u32
//! ```
//!
//! Each memmap entry is 24 bytes:
//!
//! ```text
//! offset  field    type
//! 0x00    addr     u64
//! 0x08    size     u64
//! 0x10    type     u32   (1 RAM, 2 reserved, 3 ACPI reclaim, 4 NVS,
//!                         5 unusable, 6 disabled)
//! 0x14    reserved u32
//! ```

use narf_memory::PhysAddr;

use crate::info::{MemRegion, MemRegionKind};

/// Magic at offset 0 of a `hvm_start_info` struct.
pub const MAGIC: u32 = 0x336e_c578;

#[repr(C)]
#[derive(Copy, Clone)]
struct HvmStartInfo {
    magic:          u32,
    _version:       u32,
    _flags:         u32,
    _nr_modules:    u32,
    _modlist:       u64,
    _cmdline:       u64,
    rsdp_paddr:     u64,
    memmap_paddr:   u64,
    memmap_entries: u32,
    _reserved:      u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct MemmapEntry {
    addr:      u64,
    size:      u64,
    ty:        u32,
    _reserved: u32,
}

/// Check whether the given physical address points at something that looks
/// like an `hvm_start_info` (has the PVH magic at offset 0). Reads are
/// done via `read_unaligned` so we never UB on a misaligned pointer.
///
/// # Safety
/// `payload` must point at at least 4 bytes of readable memory.
pub unsafe fn is_hvm_start_info(payload: PhysAddr) -> bool {
    // SAFETY: caller promises 4-byte readability.
    let magic = unsafe { (payload.raw() as *const u32).read_unaligned() };
    magic == MAGIC
}

/// Read the RSDP physical address advertised in the PVH `hvm_start_info`
/// struct. Returns `None` if the field is zero.
///
/// # Safety
/// `info_ptr` must point at a valid `hvm_start_info`.
pub unsafe fn rsdp_phys(info_ptr: usize) -> Option<u64> {
    // SAFETY: caller-provided pointer to a valid PVH header.
    let hdr = unsafe { (info_ptr as *const HvmStartInfo).read_unaligned() };
    if hdr.magic != MAGIC || hdr.rsdp_paddr == 0 { None }
    else { Some(hdr.rsdp_paddr) }
}

/// Walk the `hvm_start_info` at `info_ptr`, writing up to `out_cap` parsed
/// memory regions into `out`. Returns the count written.
///
/// # Safety
/// - `info_ptr` must point at a valid `hvm_start_info`.
/// - `out` must be writable for `out_cap` `MemRegion` entries.
pub unsafe fn parse_memory_map(
    info_ptr: usize,
    out:      *mut MemRegion,
    out_cap:  usize,
) -> usize {
    // SAFETY: caller guarantees a valid hvm_start_info at info_ptr.
    let hdr = unsafe { (info_ptr as *const HvmStartInfo).read_unaligned() };
    if hdr.magic != MAGIC || out_cap == 0 {
        return 0;
    }
    let count = (hdr.memmap_entries as usize).min(out_cap);
    let base  = hdr.memmap_paddr as usize;

    for i in 0..count {
        let entry_ptr = base + i * core::mem::size_of::<MemmapEntry>();
        // SAFETY: caller contract: memmap covers
        // `memmap_entries * sizeof(MemmapEntry)` bytes of valid memory.
        let e = unsafe { (entry_ptr as *const MemmapEntry).read_unaligned() };
        let kind = match e.ty {
            1 => MemRegionKind::Usable,
            3 => MemRegionKind::AcpiReclaimable,
            4 => MemRegionKind::AcpiNvs,
            _ => MemRegionKind::Reserved,
        };
        // SAFETY: out valid for out_cap MemRegions; i < count <= out_cap.
        unsafe {
            out.add(i).write(MemRegion {
                start: PhysAddr::new(e.addr),
                len:   e.size,
                kind,
            });
        }
    }
    count
}

//! aarch64 U-Boot / FDT handoff.
//!
//! Entry: `x0` holds the physical address of a device tree blob. The
//! bootloader hands that to `frame::_start`, which packs it into a
//! `RawBootInfo` and calls `parse_raw`.

use narf_memory::{PhysAddr, VirtAddr};

use crate::info::{BootError, BootInfo, MemRegion, MemRegionKind, RawBootInfo};

/// DTB magic per Devicetree Specification (big-endian on the wire).
pub const DTB_MAGIC_BE: u32 = 0xd00d_feed;

/// QEMU `virt` machine's PL011 base MMIO address.
pub const PL011_QEMU_VIRT: u64 = 0x0900_0000;

/// Maximum number of memory regions we track pre-parse. FDT parsing is
/// deferred to Wave 2; for Wave 1 we synthesise a single "all of RAM"
/// region from platform knowledge.
pub const MAX_MEM_REGIONS: usize = 16;

static mut MEMORY_MAP: [MemRegion; MAX_MEM_REGIONS] = [MemRegion {
    start: PhysAddr::new(0),
    len: 0,
    kind: MemRegionKind::Reserved,
}; MAX_MEM_REGIONS];
static mut MEMORY_MAP_LEN: usize = 0;

static CMDLINE: &str = "";

/// Parse a U-Boot-style handoff. Wave 1 trusts QEMU `virt` defaults — the
/// full FDT walker lands with `memory/` at a later wave.
///
/// Tolerates a null or bogus DTB pointer: when QEMU's `-kernel` path
/// doesn't populate X0 with an FDT address (observed on ELF inputs
/// without an explicit `-dtb`), we synthesise a plausible memory
/// map from the standard QEMU `virt` layout instead of faulting.
/// Real FDT parsing becomes load-bearing only when Stage 3 needs the
/// device tree for peripherals.
///
/// # Safety
/// `raw.payload` may be null; we check before dereferencing.
pub unsafe fn parse_raw(raw: &RawBootInfo) -> Result<BootInfo, BootError> {
    // Validate DTB magic only if the bootloader gave us a non-null
    // pointer. Null → treat as "no DTB, use defaults."
    if raw.payload.raw() != 0 {
        // SAFETY: non-null pointer into identity-mapped RAM; read of
        // 4 unaligned bytes is defined on aarch64.
        let magic_ptr = raw.payload.raw() as *const u32;
        let magic = unsafe { magic_ptr.read_unaligned() }.to_be();
        if magic != DTB_MAGIC_BE {
            // Non-null but bad magic — really wrong, bail.
            return Err(BootError::BadDtbMagic);
        }
    }

    // Wave-1 placeholder: a single 128-MiB usable region starting at the
    // standard virt-machine RAM base. Real FDT parsing in Wave 2 replaces
    // this with the actual `/memory` node.
    let region = MemRegion {
        start: PhysAddr::new(0x4000_0000),
        len: 0x0800_0000, // 128 MiB
        kind: MemRegionKind::Usable,
    };
    // SAFETY: single-threaded boot path writes to the static buffer.
    unsafe {
        core::ptr::addr_of_mut!(MEMORY_MAP)
            .cast::<MemRegion>()
            .write(region);
        core::ptr::addr_of_mut!(MEMORY_MAP_LEN).write(1);
    }
    // SAFETY: slice refers to the static we just wrote.
    let regions = unsafe {
        core::slice::from_raw_parts(core::ptr::addr_of!(MEMORY_MAP).cast::<MemRegion>(), 1)
    };

    // Locate the DTB. The bootloader-provided pointer is the
    // canonical source, but QEMU's `-kernel <elf>` path doesn't set
    // up x0 = DTB the way the Linux Image format expects, so the
    // pointer is often null/garbage. As a fallback, scan the first
    // few MiB of RAM for the FDT magic at 4-byte-aligned offsets.
    // QEMU loads the DTB just past the kernel image, well within
    // this window.
    let dtb_phys = if raw.payload.raw() != 0 {
        // SAFETY: non-null caller-provided pointer; we already
        // confirmed magic above, so dereferencing is defined.
        Some(raw.payload)
    } else {
        // SAFETY: scanning 0x4000_0000 + 0..32 MiB only reads
        // identity-mapped Normal memory in lo_L1[1].
        unsafe { scan_for_dtb() }
    };

    // FDT initramfs handoff: find `/chosen`, read
    // `linux,initrd-start` + `linux,initrd-end` (u32 or u64).
    // Returns `None` when no DTB was located, when no `/chosen`
    // node exists, or when neither property is present.
    let initramfs = match dtb_phys {
        // SAFETY: dtb_phys came from the scan above + identity-
        // mapped 256 MiB virt RAM range.
        Some(p) => unsafe { scan_initramfs_chosen(p.raw()) },
        None => None,
    };

    Ok(BootInfo {
        memory_map: regions,
        cmdline: CMDLINE,
        uart_phys: PhysAddr::new(PL011_QEMU_VIRT),
        uart_virt: VirtAddr::new(PL011_QEMU_VIRT), // pre-MMU identity
        dtb_phys,
        acpi_rsdp_phys: None,
        initramfs,
        framebuffer: None,
    })
}

/// FDT structure-block tokens (Devicetree Specification §5.4.1).
const FDT_BEGIN_NODE: u32 = 0x0000_0001;
const FDT_END_NODE: u32 = 0x0000_0002;
const FDT_PROP: u32 = 0x0000_0003;
const FDT_NOP: u32 = 0x0000_0004;
const FDT_END: u32 = 0x0000_0009;

/// Find the `/chosen` node in the DTB at `dtb_phys`, read
/// `linux,initrd-start` and `linux,initrd-end`, return the
/// covered phys range. Properties are u32 OR u64 — the FDT spec
/// allows either; we accept both.
///
/// # Safety
/// `dtb_phys` must point at a 4-byte-aligned valid Devicetree
/// blob whose `totalsize` covers the structure + strings blocks.
unsafe fn scan_initramfs_chosen(dtb_phys: u64) -> Option<MemRegion> {
    // Read header fields (all big-endian u32).
    // SAFETY: caller-asserted readability; identity-mapped Normal.
    let read_be32 = |off: u64| -> u32 {
        unsafe { core::ptr::read_volatile((dtb_phys + off) as *const u32) }.to_be()
    };
    if read_be32(0) != 0xd00d_feed {
        return None;
    }
    let off_dt_struct = read_be32(8) as u64;
    let off_dt_strings = read_be32(12) as u64;
    let size_dt_struct = read_be32(36) as u64;

    let strings_base = dtb_phys + off_dt_strings;
    let mut p = dtb_phys + off_dt_struct;
    let end = p + size_dt_struct;

    // Track whether we're inside `/chosen`. The DTB always starts
    // with a single root node (`""`); we walk the immediate
    // children looking for "chosen".
    let mut depth = 0i32;
    let mut in_chosen = false;
    let mut chosen_depth = -1i32;
    let mut start: Option<u64> = None;
    let mut end_addr: Option<u64> = None;

    while p + 4 <= end {
        // SAFETY: identity-mapped DTB; bounds-checked above.
        let tok = unsafe { core::ptr::read_volatile(p as *const u32) }.to_be();
        p += 4;
        match tok {
            FDT_BEGIN_NODE => {
                depth += 1;
                // Name: NUL-terminated, 4-byte aligned.
                let name_start = p;
                let mut len = 0;
                while p < end {
                    // SAFETY: bounds-checked.
                    let b = unsafe { core::ptr::read_volatile(p as *const u8) };
                    p += 1;
                    if b == 0 {
                        break;
                    }
                    len += 1;
                }
                // Round up to 4-byte boundary.
                let consumed = (p - name_start) as u64;
                let pad = (4 - (consumed & 3)) & 3;
                p += pad;
                // SAFETY: name spans `len` bytes from name_start.
                let name = unsafe { core::slice::from_raw_parts(name_start as *const u8, len) };
                if depth == 2 && name.starts_with(b"chosen") {
                    in_chosen = true;
                    chosen_depth = depth;
                }
            }
            FDT_END_NODE => {
                if depth == chosen_depth {
                    in_chosen = false;
                    chosen_depth = -1;
                }
                depth -= 1;
            }
            FDT_PROP => {
                if p + 8 > end {
                    return None;
                }
                let plen = read_be32(p - dtb_phys) as u64;
                let nameoff = read_be32(p - dtb_phys + 4) as u64;
                p += 8;
                if p + plen > end {
                    return None;
                }
                if in_chosen {
                    // Read property name from strings block.
                    let mut nlen = 0;
                    while nlen < 64 {
                        // SAFETY: strings block is bounded by
                        // size_dt_strings; cap at 64 for safety.
                        let b = unsafe {
                            core::ptr::read_volatile((strings_base + nameoff + nlen) as *const u8)
                        };
                        if b == 0 {
                            break;
                        }
                        nlen += 1;
                    }
                    // SAFETY: name spans nlen bytes.
                    let name = unsafe {
                        core::slice::from_raw_parts(
                            (strings_base + nameoff) as *const u8,
                            nlen as usize,
                        )
                    };
                    let val = if plen == 4 {
                        Some(read_be32(p - dtb_phys) as u64)
                    } else if plen == 8 {
                        let hi = read_be32(p - dtb_phys) as u64;
                        let lo = read_be32(p - dtb_phys + 4) as u64;
                        Some((hi << 32) | lo)
                    } else {
                        None
                    };
                    if let Some(v) = val {
                        if name == b"linux,initrd-start" {
                            start = Some(v);
                        } else if name == b"linux,initrd-end" {
                            end_addr = Some(v);
                        }
                    }
                }
                p += plen;
                // 4-byte align.
                let pad = (4 - (plen & 3)) & 3;
                p += pad;
            }
            FDT_NOP => {}
            FDT_END => break,
            _ => return None, // Bad token; bail out.
        }
    }

    match (start, end_addr) {
        (Some(s), Some(e)) if e > s => Some(MemRegion {
            start: PhysAddr::new(s),
            len: e - s,
            kind: MemRegionKind::Reserved,
        }),
        _ => None,
    }
}

/// Search low RAM for the FDT magic (`0xd00dfeed` big-endian). QEMU
/// loads the DTB at an address determined by kernel size, so the
/// exact offset isn't predictable from outside; scanning is the
/// reliable fallback when the bootloader-provided pointer is absent.
///
/// Walks 4-byte-aligned positions in the first 32 MiB of the virt
/// RAM region (0x4000_0000..0x4200_0000). Returns the first match.
///
/// # Safety
/// The scanned range is identity-mapped Normal memory by the boot
/// stub (lo_L1[1] = 1 GiB block at PA 0x4000_0000).
unsafe fn scan_for_dtb() -> Option<PhysAddr> {
    // First, fast-path: xtask force-loads the QEMU virt DTB at a
    // fixed `DTB_LOAD_ADDR` via `-device loader`, so a single
    // direct check usually wins.
    const DTB_LOAD_ADDR: u64 = 0x4F00_0000;
    // SAFETY: address is inside the lo_L1[1] Normal-mapped block.
    let v = unsafe { core::ptr::read_volatile(DTB_LOAD_ADDR as *const u32) }.to_be();
    if v == 0xd00d_feed {
        return Some(PhysAddr::new(DTB_LOAD_ADDR));
    }

    // Fallback: scan low RAM in case some other loader placed the
    // DTB elsewhere. virt has 256 MiB by default; the DTB is
    // typically near the top of RAM. Scan the full window in
    // 4-byte strides — bounded.
    const RAM_BASE: u64 = 0x4000_0000;
    const SCAN_LIMIT: u64 = 256 * 1024 * 1024;
    let mut p = RAM_BASE;
    let end = RAM_BASE + SCAN_LIMIT;
    while p + 4 <= end {
        // SAFETY: identity-mapped RAM; 4-byte read is aligned.
        let v = unsafe { core::ptr::read_volatile(p as *const u32) }.to_be();
        if v == 0xd00d_feed {
            return Some(PhysAddr::new(p));
        }
        p += 4;
    }
    None
}

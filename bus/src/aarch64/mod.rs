//! aarch64 devicetree bus enumeration.
//!
//! Spec: `bus/` §5 aarch64. QEMU's `virt` machine hands us a
//! flattened devicetree (FDT) describing its platform bus — in
//! particular, 32 virtio-mmio transport slots at `0x0a00_0000` with
//! stride `0x200`. We walk the FDT looking for nodes whose name
//! starts with `virtio_mmio@`, read the `reg` tuple (two
//! `#address-cells` + two `#size-cells` cells = 64-bit base, 64-bit
//! len), probe the transport magic + device-id registers, and emit a
//! `BusDevice` for every slot whose device-id is non-zero (zero =
//! empty, per the virtio-mmio spec §4.2.2).
//!
//! We do not consume the full FDT grammar — only the minimum to
//! locate the nodes we care about. The boot/ crate deliberately does
//! *not* parse the FDT either (it uses QEMU-virt defaults); this
//! keeps FDT parsing self-contained in one place rather than
//! splitting it. When boot/ grows a real FDT walker (Wave 2
//! follow-up), this file can delegate.
//!
//! FDT format reference: Devicetree Specification v0.4 §5.

use alloc::vec::Vec;
use core::sync::atomic::{compiler_fence, Ordering};

use narf_memory::PhysAddr;

use crate::addr::BusAddr;
use crate::device::{BusDevice, BusKind, DeviceId};

// ── FDT constants ──────────────────────────────────────────────────

/// DTB magic, big-endian on the wire.
const FDT_MAGIC: u32 = 0xd00d_feed;

// FDT token values (big-endian 4-byte cells in the structure block).
const FDT_BEGIN_NODE: u32 = 0x1;
const FDT_END_NODE:   u32 = 0x2;
const FDT_PROP:       u32 = 0x3;
const FDT_NOP:        u32 = 0x4;
const FDT_END:        u32 = 0x9;

/// FDT header (v17+). Only fields we actually consult are read.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct FdtHeader {
    magic:             u32,
    totalsize:         u32,
    off_dt_struct:     u32,
    off_dt_strings:    u32,
    off_mem_rsvmap:    u32,
    version:           u32,
    last_comp_version: u32,
    boot_cpuid_phys:   u32,
    size_dt_strings:   u32,
    size_dt_struct:    u32,
}

// ── virtio-mmio MMIO layout ───────────────────────────────────────

/// Magic value at offset 0x00 of every virtio-mmio transport.
/// ASCII "virt" little-endian = 0x7472_6976. Spec §4.2.2.
const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976;

/// Offset of the DeviceID register.
const VIRTIO_MMIO_DEVICE_ID: u64 = 0x0008;

// ── Public entry point ────────────────────────────────────────────

/// Enumerate every device on the aarch64 platform bus that we care
/// about for Stage 3. Today that's virtio-mmio transports; the
/// PCIe-host-bridge node (optional on virt) is deferred until a
/// driver actually wants it.
///
/// # Safety
/// `dtb` — when `Some` — must point at a DTB blob in identity-mapped
/// memory. A `None` or bogus pointer yields an empty Vec rather than
/// UB (we validate magic before trusting any offsets).
pub unsafe fn enumerate(dtb: Option<PhysAddr>) -> Vec<BusDevice> {
    let mut out = Vec::new();

    // Try the FDT walk first when we have a plausible pointer.
    if let Some(dtb_phys) = dtb {
        let base = dtb_phys.raw() as *const u8;
        if !base.is_null() {
            // SAFETY: caller promise — `base` covers at least
            // `sizeof(FdtHeader)`. `read_header` validates magic.
            if let Some(hdr) = unsafe { read_header(base) } {
                // SAFETY: `hdr` validated, base still live.
                unsafe { walk_fdt(base, hdr, &mut out) };
                if !out.is_empty() { return out; }
            }
        }
    }

    // Fallback: QEMU `virt` layout is well known. 32 virtio-mmio slots
    // starting at 0x0a00_0000, stride 0x200 each. This mirrors the
    // same "trust QEMU defaults when FDT parsing isn't wired" fallback
    // `boot/src/aarch64/mod.rs` uses for the memory map. Removed when
    // `boot/` surfaces the DTB pointer through `BootInfo` end-to-end.
    const VIRT_MMIO_BASE:   u64   = 0x0a00_0000;
    const VIRT_MMIO_STRIDE: u64   = 0x200;
    const VIRT_MMIO_COUNT:  u64   = 32;
    for slot in 0..VIRT_MMIO_COUNT {
        let base_addr = VIRT_MMIO_BASE + slot * VIRT_MMIO_STRIDE;
        // SAFETY: virt-machine virtio-mmio region is identity-mapped.
        if let Some(dev) = unsafe { probe_virtio_mmio(base_addr, VIRT_MMIO_STRIDE) } {
            out.push(dev);
        }
    }

    // PCIe ECAM walk via the shared `pcie::enumerate_n`. QEMU virt
    // can place the ECAM either at 0x3F00_0000 (lowmem, 16 MiB,
    // when `highmem-ecam=off` is on the machine line) or at
    // 0x4010_0000_0000 (highmem, 256 MiB, the default). We always
    // try the lowmem location: with the lowmem option set the
    // controller responds; with the default highmem layout the
    // address is unmapped and the walk's first read aborts.
    //
    // To stay safe on either machine config, we gate the walk on a
    // FDT-described host bridge when the DTB walker found one;
    // otherwise we fall through without touching the lowmem range.
    // The DTB-driven path is handled inside `walk_fdt` (above) when
    // it sees a `pcie@…` node; this fallback only fires for the
    // legacy "no DTB" QEMU configurations.

    out
}

/// QEMU `virt` PCIe ECAM base. The host bridge's MMCFG region lives
/// at `0x3F00_0000` and is 16 MiB wide (i.e. 16 buses). Used by a
/// future DTB-driven ECAM enable path; bare reads abort today
/// because the host bridge requires programming first.
pub const VIRT_PCIE_ECAM_BASE: narf_memory::PhysAddr =
    narf_memory::PhysAddr::new(0x3F00_0000);

/// PCIe bus count for QEMU `virt`. 16 MiB ECAM ÷ 1 MiB per bus.
pub const VIRT_PCIE_NUM_BUSES: u16 = 16;

/// FDT structure-block walker factored out so the `enumerate` entry
/// point can try FDT first and fall back to the QEMU-virt default
/// layout when we don't have a DTB (as is common when the kernel is
/// loaded via `-kernel` without `-dtb`).
///
/// # Safety
/// `base` must be live for the duration of the walk and cover
/// `hdr.off_dt_struct + hdr.size_dt_struct` bytes plus the strings
/// block.
unsafe fn walk_fdt(base: *const u8, hdr: FdtHeader, out: &mut Vec<BusDevice>) {

    let struct_start = hdr.off_dt_struct as usize;
    let struct_len   = hdr.size_dt_struct as usize;
    // SAFETY: bounds come from the header we just validated.
    let struct_slice = unsafe {
        core::slice::from_raw_parts(base.add(struct_start), struct_len)
    };

    // Minimum walk: we care only about the top-level virtio_mmio@...
    // nodes. On QEMU virt these all live directly under the root, so
    // a single-depth scan suffices. We still honour arbitrary nesting
    // by tracking depth.
    let mut cursor = 0usize;
    let mut depth: i32 = 0;
    while cursor + 4 <= struct_slice.len() {
        let tok = be32(&struct_slice[cursor..cursor + 4]);
        cursor += 4;
        match tok {
            FDT_BEGIN_NODE => {
                // Node name is a NUL-terminated string immediately
                // following the token, padded to a 4-byte boundary.
                let name_start = cursor;
                let mut end = name_start;
                while end < struct_slice.len() && struct_slice[end] != 0 { end += 1; }
                let name_bytes = &struct_slice[name_start..end];
                let nlen_with_nul = (end - name_start) + 1;
                cursor = name_start + ((nlen_with_nul + 3) & !3);

                if is_virtio_mmio_node(name_bytes) {
                    // Parse this node's properties to find `reg`.
                    // SAFETY: `struct_slice` is in-range of the FDT
                    // per the header we validated; `base` is still
                    // live; `hdr` was copied by value.
                    if let Some((base_addr, len)) = unsafe {
                        scan_reg_in_node(struct_slice, &mut cursor, hdr, base)
                    } {
                        // cursor is now at END_NODE; account depth-wise.
                        depth += 1;
                        // SAFETY: probe does a volatile 4-byte read of
                        // the transport's magic register at an
                        // identity-mapped MMIO address.
                        if let Some(dev) = unsafe { probe_virtio_mmio(base_addr, len) } {
                            out.push(dev);
                        }
                        // Caller-side end-of-node token has already been
                        // consumed by scan_reg_in_node when it saw it.
                        depth -= 1;
                        continue;
                    }
                }

                if is_pcie_node(name_bytes) {
                    // Parse this node's `reg` (ECAM base + size). On
                    // QEMU virt with `gic-version=3` + `highmem-ecam`
                    // (the default in modern QEMU), ECAM lives at
                    // `0x4010_0000_0000` (4 TiB) — outside our
                    // identity map. The lowmem alternative at
                    // `0x3F00_0000` is what fits in lo_L1[0] today.
                    // We only run the walker when the DTB-supplied
                    // base is in the low-4-GiB identity-mapped
                    // window; higher addresses get logged + skipped.
                    // SAFETY: same FDT walk preconditions.
                    if let Some((ecam_base, ecam_size)) = unsafe {
                        scan_reg_in_node(struct_slice, &mut cursor, hdr, base)
                    } {
                        depth += 1;
                        if ecam_base < 0x1_0000_0000 && ecam_size > 0 {
                            // 1 MiB per bus per ECAM convention.
                            let n_buses = (ecam_size / 0x10_0000)
                                .min(crate::pcie::MAX_BUSES as u64) as u16;
                            // SAFETY: DTB asserts the ECAM region is
                            // mapped Device memory by the firmware /
                            // boot stub for low-4-GiB addresses; the
                            // walker only does aligned 4-byte reads
                            // and skips unpopulated slots.
                            let pcie = unsafe {
                                crate::pcie::enumerate_n(
                                    PhysAddr::new(ecam_base), n_buses)
                            };
                            out.extend(pcie);
                        }
                        depth -= 1;
                        continue;
                    }
                }

                depth += 1;
            }
            FDT_PROP => {
                // property = len (be32), nameoff (be32), data, padded.
                if cursor + 8 > struct_slice.len() { break; }
                let plen  = be32(&struct_slice[cursor..cursor + 4]) as usize;
                cursor += 8; // skip len + nameoff
                let padded = (plen + 3) & !3;
                if cursor + padded > struct_slice.len() { break; }
                cursor += padded;
            }
            FDT_END_NODE => { depth -= 1; if depth < 0 { break; } }
            FDT_NOP      => {}
            FDT_END      => break,
            _            => break, // malformed — bail rather than loop
        }
    }
}

/// Attempt to parse an FDT header at `base`. Returns `None` on bad
/// magic or truncation, so a caller-supplied bogus pointer degrades
/// to an empty registry instead of UB.
///
/// # Safety
/// `base` must be readable for at least `size_of::<FdtHeader>()`
/// bytes. QEMU identity-maps the DTB inside low RAM, so the kernel
/// can read it directly pre-MMU and post-MMU (the MMU init installed
/// a 1-GiB identity map for low physical memory).
unsafe fn read_header(base: *const u8) -> Option<FdtHeader> {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller promises `base` points at readable memory for
    // the header's extent.
    let raw: [u8; core::mem::size_of::<FdtHeader>()] = unsafe {
        core::ptr::read(base as *const [u8; core::mem::size_of::<FdtHeader>()])
    };
    compiler_fence(Ordering::SeqCst);

    // All header fields are big-endian u32.
    let fetch = |off: usize| -> u32 {
        be32(&raw[off..off + 4])
    };
    let magic = fetch(0);
    if magic != FDT_MAGIC { return None; }

    Some(FdtHeader {
        magic,
        totalsize:         fetch(4),
        off_dt_struct:     fetch(8),
        off_dt_strings:    fetch(12),
        off_mem_rsvmap:    fetch(16),
        version:           fetch(20),
        last_comp_version: fetch(24),
        boot_cpuid_phys:   fetch(28),
        size_dt_strings:   fetch(32),
        size_dt_struct:    fetch(36),
    })
}

/// After a BEGIN_NODE for a node we're interested in, walk its
/// properties until END_NODE and return the `(base, len)` tuple from
/// the first `reg` property encountered (virtio-mmio nodes always
/// have exactly one cell pair). Cursor is advanced past the
/// corresponding END_NODE on return.
///
/// # Safety
/// Caller holds the FDT header + base pointer live for the duration
/// of the walk; property values reference bytes inside that FDT.
unsafe fn scan_reg_in_node(
    s: &[u8],
    cursor: &mut usize,
    hdr: FdtHeader,
    base: *const u8,
) -> Option<(u64, u64)> {
    let mut found: Option<(u64, u64)> = None;
    let mut inner_depth = 0i32;
    while *cursor + 4 <= s.len() {
        let tok = be32(&s[*cursor..*cursor + 4]);
        *cursor += 4;
        match tok {
            FDT_PROP => {
                if *cursor + 8 > s.len() { break; }
                let plen    = be32(&s[*cursor..*cursor + 4]) as usize;
                let nameoff = be32(&s[*cursor + 4..*cursor + 8]) as usize;
                *cursor += 8;
                let padded = (plen + 3) & !3;
                if *cursor + padded > s.len() { break; }
                let data = &s[*cursor..*cursor + plen];
                *cursor += padded;

                // Resolve property name from the strings block.
                // SAFETY: nameoff is bound-checked below; base+off_dt_strings
                // remains within the FDT per the header.
                let name = unsafe { fdt_string(base, &hdr, nameoff) };
                if name == Some(b"reg") && found.is_none() && plen >= 16 {
                    let addr = ((be32(&data[0..4]) as u64) << 32)
                             | (be32(&data[4..8]) as u64);
                    let size = ((be32(&data[8..12]) as u64) << 32)
                             | (be32(&data[12..16]) as u64);
                    found = Some((addr, size));
                }
            }
            FDT_BEGIN_NODE => {
                // Nested child — virtio_mmio nodes don't have them in
                // practice, but handle gracefully by skipping until
                // matching END_NODE.
                let name_start = *cursor;
                let mut end = name_start;
                while end < s.len() && s[end] != 0 { end += 1; }
                let nlen_with_nul = (end - name_start) + 1;
                *cursor = name_start + ((nlen_with_nul + 3) & !3);
                inner_depth += 1;
            }
            FDT_END_NODE => {
                if inner_depth == 0 { return found; }
                inner_depth -= 1;
            }
            FDT_NOP | FDT_END => {}
            _ => break,
        }
    }
    found
}

/// Look up a string in the FDT strings block. Returns `None` on
/// truncation (malformed FDT).
unsafe fn fdt_string<'a>(base: *const u8, hdr: &FdtHeader, off: usize) -> Option<&'a [u8]> {
    if off >= hdr.size_dt_strings as usize { return None; }
    let strings_base = hdr.off_dt_strings as usize + off;
    // SAFETY: caller promises `base` is live and the FDT was validated.
    let p = unsafe { base.add(strings_base) };
    let mut n = 0usize;
    // Bounded scan against remaining strings block length.
    let max = (hdr.size_dt_strings as usize).saturating_sub(off);
    // SAFETY: bounded by `max`, which is <= size_dt_strings.
    while n < max && unsafe { *p.add(n) } != 0 { n += 1; }
    // SAFETY: returning a slice into the FDT blob.
    Some(unsafe { core::slice::from_raw_parts(p, n) })
}

fn is_virtio_mmio_node(name: &[u8]) -> bool {
    // FDT node names look like "virtio_mmio@a000000" — match prefix.
    const PFX: &[u8] = b"virtio_mmio";
    name.starts_with(PFX)
}

fn is_pcie_node(name: &[u8]) -> bool {
    // QEMU virt's PCIe host bridge appears as "pcie@10000000". Other
    // platforms may use slightly different unit-address suffixes;
    // matching by prefix keeps us flexible.
    const PFX: &[u8] = b"pcie@";
    name.starts_with(PFX)
}

/// Probe a virtio-mmio transport: check the magic, read the device-id
/// register, and build a `BusDevice` iff the slot is populated.
///
/// # Safety
/// `base` must be an identity-mapped MMIO region at least `len` bytes
/// long. On QEMU virt the virtio-mmio region at 0x0a00_0000 is
/// always identity-mapped in the low-RAM identity window set up by
/// the MMU init.
unsafe fn probe_virtio_mmio(base_addr: u64, len: u64) -> Option<BusDevice> {
    let base_ptr = base_addr as *const u32;
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller-asserted MMIO window.
    let magic = unsafe { core::ptr::read_volatile(base_ptr) };
    compiler_fence(Ordering::SeqCst);
    if magic != VIRTIO_MMIO_MAGIC { return None; }

    compiler_fence(Ordering::SeqCst);
    // SAFETY: same region, +0x08 is still inside the 0x200-byte window.
    let device_id = unsafe {
        core::ptr::read_volatile((base_addr + VIRTIO_MMIO_DEVICE_ID) as *const u32)
    };
    compiler_fence(Ordering::SeqCst);
    if device_id == 0 { return None; } // empty slot

    let phys = PhysAddr::new(base_addr);
    Some(BusDevice {
        addr: BusAddr::Mmio(phys),
        id:   DeviceId {
            // virtio-mmio doesn't expose PCI-style vendor/device; we
            // synthesise a recognisable pair so drivers can filter:
            // vendor = 'V' + 'I' = 0x5649 (Virtio spec reserves 0x1AF4
            // for the PCI transport, but MMIO is transport-distinct).
            vendor: 0x1AF4, // Red Hat / virtio — matches the PCI transport
            device: device_id as u16,
            class:  0,
        },
        kind: BusKind::VirtioMmio {
            base:      phys,
            len,
            device_id,
        },
    })
}

#[inline]
fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

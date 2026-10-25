//! aarch64 U-Boot / FDT handoff.
//!
//! Entry: `x0` holds the physical address of a device tree blob. The
//! bootloader hands that to `frame::_start`, which packs it into a
//! `RawBootInfo` and calls `parse_raw`.

use narf_memory::{PhysAddr, VirtAddr};

use crate::info::{
    validate_memory_map, BootError, BootInfo, MemRegion, MemRegionKind, RawBootInfo,
};
use narf_firmware_fdt::{Reservation, ReservedRegion};

/// DTB magic per Devicetree Specification (big-endian on the wire).
pub const DTB_MAGIC_BE: u32 = 0xd00d_feed;

/// QEMU `virt` machine's PL011 base MMIO address.
pub const PL011_QEMU_VIRT: u64 = 0x0900_0000;

/// Maximum number of normalized memory regions handed to the framekernel.
pub const MAX_MEM_REGIONS: usize = 16;

static mut MEMORY_MAP: [MemRegion; MAX_MEM_REGIONS] = [MemRegion {
    start: PhysAddr::new(0),
    len: 0,
    kind: MemRegionKind::Reserved,
}; MAX_MEM_REGIONS];
static mut MEMORY_MAP_LEN: usize = 0;

/// Backing buffer for the bootloader-supplied command-line. Copied
/// out of the DTB during `parse_raw`, then borrowed as a `&'static
/// str` for the rest of boot.
///
/// Sized to match Linux's `COMMAND_LINE_SIZE` (2048 on arm64) and the
/// x86_64 store, so the full cmdline survives into `/proc/cmdline` —
/// userspace (systemd's `systemd.*` params, etc.) reads its own
/// tokens from there, so any truncation here silently drops them.
/// The test harness's tokens ride the same string: on affected-filter
/// runs xtask appends `test_subsystem=<~430-byte list>
/// test_subsystem_exclude=drivers/gpu` (~480 bytes), and the previous
/// 256-byte cap silently ate the exclude token — and the last wanted
/// subsystems — on this arch only (#960).
const CMDLINE_CAP: usize = 2048;
static mut CMDLINE_BYTES: [u8; CMDLINE_CAP] = [0; CMDLINE_CAP];
static mut CMDLINE_LEN: usize = 0;
static mut CMDLINE_TRUNCATED: bool = false;

/// Borrow the DTB-supplied command line as a `&'static str`.
///
/// The bytes come from `/chosen/bootargs`, which is where QEMU's `-append`
/// lands on aarch64 — `parse_raw` already copies them into [`CMDLINE_BYTES`]
/// for `BootInfo::cmdline`. This accessor exists because the crate-level
/// [`crate::cmdline`] had no aarch64 arm and returned `""` unconditionally, so
/// every cmdline-driven feature was silently inert on this architecture even
/// though the parsing worked. The visible symptom was
/// `cargo xtask test --subsystem <name>` filtering nothing on aarch64: xtask
/// passes the filter as `test_subsystem=` via `-append`, the kernel read an
/// empty cmdline, and `run_all_and_exit()` was taken every time — quietly, with
/// the run still reporting success.
///
/// Empty before `parse_raw` runs, or when the DTB carried no `bootargs`.
#[must_use]
pub fn cmdline() -> &'static str {
    // SAFETY: written once by `parse_raw` on the single-threaded boot path,
    // immutable afterwards — the same contract the x86_64 arm documents.
    unsafe {
        let len = *core::ptr::addr_of!(CMDLINE_LEN);
        let bytes =
            core::slice::from_raw_parts(core::ptr::addr_of!(CMDLINE_BYTES).cast::<u8>(), len);
        core::str::from_utf8(bytes).unwrap_or("")
    }
}

/// Whether the stored cmdline was truncated by [`store_cmdline`]
/// because the DTB's `bootargs` exceeded the buffer. Recorded on
/// every store, so it always describes the currently stored string.
///
/// Truncation also emits a warning on the boot UART at store time
/// (see [`warn_cmdline_truncated`]); this flag exists so the outcome
/// is observable programmatically — and testable — after the fact.
#[must_use]
pub fn cmdline_truncated() -> bool {
    // SAFETY: same single-writer contract as `cmdline()`.
    unsafe { *core::ptr::addr_of!(CMDLINE_TRUNCATED) }
}

/// Copy a DTB-supplied cmdline byte slice into the static backing
/// buffer. Truncates at `CMDLINE_CAP - 1` bytes, mirroring the
/// x86_64 store's contract.
///
/// Truncation is LOUD, never silent (#960): the store records it in
/// [`cmdline_truncated`] and prints a warning to the boot UART.
/// Because the FDT layer's cap (`narf_firmware_fdt::BOOTARGS_CAP`)
/// equals `CMDLINE_CAP`, a value clipped there arrives here at full
/// width and trips this same warning — one check at the single
/// consumer covers both layers.
///
/// # Safety
/// Single-threaded boot path: caller must invoke before any other
/// thread observes `cmdline()`.
unsafe fn store_cmdline(src: &[u8]) {
    let kept = src.len().min(CMDLINE_CAP - 1);
    let truncated = kept < src.len();
    // SAFETY: single-threaded boot initialization owns the statics.
    unsafe {
        let dst = &mut *core::ptr::addr_of_mut!(CMDLINE_BYTES);
        dst[..kept].copy_from_slice(&src[..kept]);
        core::ptr::addr_of_mut!(CMDLINE_LEN).write(kept);
        core::ptr::addr_of_mut!(CMDLINE_TRUNCATED).write(truncated);
    }
    if truncated {
        warn_cmdline_truncated(src.len(), kept);
    }
}

/// Fixed-capacity `core::fmt::Write` sink for the truncation
/// warning's single line — the boot crate has no allocator-backed
/// formatting path at `parse_raw` time.
#[derive(Debug)]
struct LineBuf<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> LineBuf<N> {
    fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl<const N: usize> core::fmt::Write for LineBuf<N> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let n = bytes.len().min(N - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
        Ok(())
    }
}

/// PL011 flag-register bit: transmit FIFO full.
const PL011_FR_TXFF: u32 = 1 << 5;

/// Write one byte to the PL011, polling the FIFO-full flag first.
///
/// The poll is generously bounded: a draining FIFO clears in a
/// handful of iterations, and the bound exists only so a platform
/// where the UART is not really at [`PL011_QEMU_VIRT`] cannot hang
/// boot forever to deliver a warning — dropping the tail of the
/// warning beats never booting.
fn uart_putc(byte: u8) {
    let fr = (PL011_QEMU_VIRT as *const u32).wrapping_byte_add(0x18);
    let dr = (PL011_QEMU_VIRT as *mut u32).wrapping_byte_add(0x00);
    for _ in 0..100_000 {
        // SAFETY: identity-mapped UART base — the same access the
        // console crate's early PL011 backend performs before
        // `parse_raw` runs; FR is a read-only status register.
        if unsafe { fr.read_volatile() } & PL011_FR_TXFF == 0 {
            break;
        }
    }
    // SAFETY: same mapping contract; DR is the transmit register.
    unsafe { dr.write_volatile(u32::from(byte)) };
}

/// Emit the cmdline-truncation warning straight to the boot UART.
///
/// `narf-boot` cannot reach the console crate (frame owns it; boot
/// is frame's dependency), but frame's Step 1 has already brought
/// the PL011 up by the time `parse_raw` runs, and this module
/// already hard-codes its address for `BootInfo` — so a polled
/// register write is the available channel, and the line lands in
/// the same serial boot log as every other early message, naming
/// the sizes involved. Never silent: silent cmdline scope loss is
/// the failure species #960 exists to retire.
fn warn_cmdline_truncated(received: usize, kept: usize) {
    use core::fmt::Write as _;
    let mut line = LineBuf::<160>::new();
    let _ = core::write!(
        line,
        "boot: WARN: kernel cmdline truncated: bootargs of {received} bytes \
         exceeds the {CMDLINE_CAP}-byte capacity; kept the first {kept} \
         bytes - trailing tokens dropped\r\n"
    );
    for &b in line.as_slice() {
        uart_putc(b);
    }
}

/// Parse a Linux-compatible U-Boot-style FDT handoff.
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
        let magic_ptr = raw.payload.kernel_ptr::<u32>();
        // SAFETY: `raw.payload` is non-null (checked above) and points into
        // identity-mapped RAM the bootloader handed us; an unaligned 4-byte
        // read of the DTB magic is defined on aarch64.
        // SAFETY: Valid memory or trusted environment
        let magic = unsafe { magic_ptr.read_unaligned() }.to_be();
        if magic != DTB_MAGIC_BE {
            // Non-null but bad magic — really wrong, bail.
            return Err(BootError::BadDtbMagic);
        }
    }

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
        // SAFETY: Valid memory or trusted environment
        unsafe { scan_for_dtb() }
    };

    const MAX_DTB_SIZE: usize = 2 * 1024 * 1024;
    let dtb = match dtb_phys {
        // SAFETY: U-Boot places the DTB in identity-mapped RAM; the
        // parser caps firmware's totalsize at MAX_DTB_SIZE.
        Some(p) => unsafe { narf_firmware_fdt::discover(p.raw() as usize, MAX_DTB_SIZE) },
        None => None,
    };

    let initramfs = dtb
        .and_then(narf_firmware_fdt::chosen_initrd_range)
        .map(|r| MemRegion {
            start: PhysAddr::new(r.addr),
            len: r.size,
            kind: MemRegionKind::Reserved,
        });

    let regions = if let Some(blob) = dtb {
        // Linux-compatible early scan: obtain RAM from `/memory`, then
        // subtract both reservation mechanisms plus the DTB and initrd.
        let mut memory = [Reservation::default(); MAX_MEM_REGIONS];
        let memory_len = narf_firmware_fdt::copy_memory_ranges(blob, &mut memory);
        let mut reservations = [Reservation::default(); MAX_MEM_REGIONS * 2];
        let mut reservation_len = narf_firmware_fdt::copy_reservations(blob, &mut reservations);
        let mut reserved_nodes = [ReservedRegion::default(); MAX_MEM_REGIONS];
        let reserved_len =
            narf_firmware_fdt::copy_reserved_memory_ranges(blob, &mut reserved_nodes);
        for node in reserved_nodes[..reserved_len].iter() {
            if reservation_len == reservations.len() {
                return Err(BootError::MemoryMapTooLarge);
            }
            reservations[reservation_len] = Reservation {
                addr: node.addr,
                size: node.size,
            };
            reservation_len += 1;
        }
        if reservation_len == reservations.len() {
            return Err(BootError::MemoryMapTooLarge);
        }
        reservations[reservation_len] = Reservation {
            addr: dtb_phys.expect("DTB slice requires physical address").raw(),
            size: blob.len() as u64,
        };
        reservation_len += 1;
        if let Some(initrd) = initramfs {
            if reservation_len == reservations.len() {
                return Err(BootError::MemoryMapTooLarge);
            }
            reservations[reservation_len] = Reservation {
                addr: initrd.start.raw(),
                size: initrd.len,
            };
            reservation_len += 1;
        }
        // SAFETY: single-threaded boot path owns the static output.
        unsafe {
            normalize_memory_map(
                &memory[..memory_len],
                &reservations[..reservation_len],
                &mut *core::ptr::addr_of_mut!(MEMORY_MAP),
                &mut *core::ptr::addr_of_mut!(MEMORY_MAP_LEN),
            )?;
        }
        // A present `/memory` node is not sufficient if firmware
        // reservations consume every byte.
        // SAFETY: single-threaded boot initialization owns the static map.
        if memory_len == 0 || unsafe { *core::ptr::addr_of!(MEMORY_MAP_LEN) } == 0 {
            return Err(BootError::NoUsableRam);
        }
        if let Some(args) = narf_firmware_fdt::chosen_bootargs(blob) {
            // SAFETY: single-threaded boot initialization; the store
            // owns the CMDLINE statics from here on.
            unsafe { store_cmdline(args.as_bytes()) };
        }
        // SAFETY: the static map was initialized immediately above.
        unsafe {
            core::slice::from_raw_parts(
                core::ptr::addr_of!(MEMORY_MAP).cast::<MemRegion>(),
                *core::ptr::addr_of!(MEMORY_MAP_LEN),
            )
        }
    } else {
        // Preserve direct-QEMU fallback for ELF boots that provide no
        // discoverable DTB.
        // SAFETY: single-threaded boot owns the static map and the
        // returned slice becomes immutable before secondary CPUs start.
        unsafe {
            core::ptr::addr_of_mut!(MEMORY_MAP)
                .cast::<MemRegion>()
                .write(MemRegion {
                    start: PhysAddr::new(0x4000_0000),
                    len: 0x0800_0000,
                    kind: MemRegionKind::Usable,
                });
            core::ptr::addr_of_mut!(MEMORY_MAP_LEN).write(1);
            core::slice::from_raw_parts(core::ptr::addr_of!(MEMORY_MAP).cast::<MemRegion>(), 1)
        }
    };
    // SAFETY: initialized above and immutable after boot handoff.
    let cmdline = unsafe {
        let bytes = core::slice::from_raw_parts(
            core::ptr::addr_of!(CMDLINE_BYTES).cast::<u8>(),
            *core::ptr::addr_of!(CMDLINE_LEN),
        );
        core::str::from_utf8_unchecked(bytes)
    };

    validate_memory_map(regions)?;

    Ok(BootInfo {
        memory_map: regions,
        cmdline,
        uart_phys: PhysAddr::new(PL011_QEMU_VIRT),
        // High-VA alias: TTBR1's hi_L1[0] (installed by boot.S)
        // maps PA 0x00000000-0x40000000 → VA 0xFFFFFF80_00000000
        // -0xFFFFFF80_40000000 as Device memory. After the boot
        // identity TTBR0 is swapped for a user task's private
        // root, the kernel keeps reaching the UART through this
        // high-VA window.
        uart_virt: VirtAddr::new(0xFFFF_FF80_0000_0000 | PL011_QEMU_VIRT),
        dtb_phys,
        acpi_rsdp_phys: None,
        initramfs,
        framebuffer: None,
    })
}

/// Subtract reserved intervals from FDT `/memory` ranges.
///
/// This produces a non-overlapping usable map like Linux memblock,
/// bounded by the boot ABI's fixed region capacity.
fn normalize_memory_map(
    memory: &[Reservation],
    reserved: &[Reservation],
    out: &mut [MemRegion; MAX_MEM_REGIONS],
    out_len: &mut usize,
) -> Result<(), BootError> {
    *out_len = 0;
    for range in memory {
        let mut pieces = [Reservation::default(); MAX_MEM_REGIONS];
        let mut piece_len = 1;
        pieces[0] = *range;
        for cut in reserved {
            if cut.size == 0 {
                continue;
            }
            let cut_end = cut
                .addr
                .checked_add(cut.size)
                .ok_or(BootError::AddressOverflow)?;
            let mut next = [Reservation::default(); MAX_MEM_REGIONS];
            let mut next_len = 0;
            for piece in pieces[..piece_len].iter() {
                let end = piece
                    .addr
                    .checked_add(piece.size)
                    .ok_or(BootError::AddressOverflow)?;
                if cut_end <= piece.addr || cut.addr >= end {
                    if next_len == next.len() {
                        return Err(BootError::MemoryMapTooLarge);
                    }
                    next[next_len] = *piece;
                    next_len += 1;
                    continue;
                }
                if cut.addr > piece.addr {
                    if next_len == next.len() {
                        return Err(BootError::MemoryMapTooLarge);
                    }
                    next[next_len] = Reservation {
                        addr: piece.addr,
                        size: cut.addr - piece.addr,
                    };
                    next_len += 1;
                }
                if cut_end < end {
                    if next_len == next.len() {
                        return Err(BootError::MemoryMapTooLarge);
                    }
                    next[next_len] = Reservation {
                        addr: cut_end,
                        size: end - cut_end,
                    };
                    next_len += 1;
                }
            }
            pieces = next;
            piece_len = next_len;
        }
        for piece in pieces[..piece_len].iter() {
            if piece.size != 0 {
                if *out_len == out.len() {
                    return Err(BootError::MemoryMapTooLarge);
                }
                out[*out_len] = MemRegion {
                    start: PhysAddr::new(piece.addr),
                    len: piece.size,
                    kind: MemRegionKind::Usable,
                };
                *out_len += 1;
            }
        }
    }
    Ok(())
}

/// FDT structure-block tokens (Devicetree Specification §5.4.1).
#[allow(dead_code)]
const FDT_BEGIN_NODE: u32 = 0x0000_0001;
#[allow(dead_code)]
const FDT_END_NODE: u32 = 0x0000_0002;
#[allow(dead_code)]
const FDT_PROP: u32 = 0x0000_0003;
#[allow(dead_code)]
const FDT_NOP: u32 = 0x0000_0004;
#[allow(dead_code)]
const FDT_END: u32 = 0x0000_0009;

/// Find the `/chosen` node in the DTB at `dtb_phys`, read
/// `linux,initrd-start` and `linux,initrd-end`, return the
/// covered phys range. Properties are u32 OR u64 — the FDT spec
/// allows either; we accept both.
///
/// # Safety
/// `dtb_phys` must point at a 4-byte-aligned valid Devicetree
/// blob whose `totalsize` covers the structure + strings blocks.
#[allow(dead_code)]
unsafe fn scan_initramfs_chosen(dtb_phys: u64) -> Option<MemRegion> {
    // Read header fields (all big-endian u32).
    let read_be32 = |off: u64| -> u32 {
        // SAFETY: per this fn's contract `dtb_phys` is a 4-byte-aligned,
        // identity-mapped Normal-memory DTB; `off` indexes within its
        // `totalsize`, so the u32 read is in-bounds and aligned.
        // SAFETY: Valid memory or trusted environment
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
                let consumed = p - name_start;
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
                        // SAFETY: Valid memory or trusted environment
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

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// The guest cmdline xtask builds on an affected-filter test
    /// run (#960): a ~430-byte `test_subsystem=` include list
    /// followed by the `test_subsystem_exclude=` token, ~480 bytes
    /// total — past both old 256-byte caps, well inside the new one.
    const AFFECTED_FILTER_APPEND: &str = concat!(
        "test_subsystem=",
        "aarch64,audio,bluetooth,drivers/gpu,drivers/graphics,drivers/input,",
        "drivers/sound,drivers/usb,drivers/virtio,drivers/wireless/ath10k,",
        "drivers/wireless/ath11k,drivers/wireless/ath9k,drivers/wireless/brcmfmac,",
        "drivers/wireless/cyw43439,drivers/wireless/e2e,drivers/wireless/iwlwifi,",
        "drivers/wireless/qualcomm,drivers/wireless/rtl8xxxu,drivers/wireless/rtlwifi,",
        "drivers/wireless/rtw88,drivers/wireless/rtw89,fb,frame,verification,wireless",
        " test_subsystem_exclude=drivers/gpu",
    );

    /// Transport-layer regression for #960: a long bootargs must
    /// survive the boot store whole — including the trailing
    /// exclude token the 256-byte cap used to eat — and an oversized
    /// one must trip the (loud) truncation path instead of losing
    /// its tail silently.
    fn smoke_aarch64_cmdline_store_keeps_long_bootargs() -> TestResult {
        // The statics are global boot state; save the guest's real
        // cmdline and restore it before returning so later smokes
        // still observe the boot-provided string.
        let mut saved = [0u8; CMDLINE_CAP];
        let saved_str = cmdline();
        saved[..saved_str.len()].copy_from_slice(saved_str.as_bytes());
        let saved_len = saved_str.len();

        // SAFETY: kernel-test smokes run single-threaded on the BSP
        // before any secondary CPU or cmdline consumer races us; the
        // save/restore brackets every mutation.
        let result = unsafe {
            store_cmdline(AFFECTED_FILTER_APPEND.as_bytes());
            let kept_whole = cmdline() == AFFECTED_FILTER_APPEND && !cmdline_truncated();

            let oversized = [b'a'; CMDLINE_CAP + 64];
            store_cmdline(&oversized);
            let capped_loudly = cmdline().len() == CMDLINE_CAP - 1 && cmdline_truncated();

            store_cmdline(&saved[..saved_len]);
            kept_whole && capped_loudly
        };
        if !result {
            return TestResult::Fail(
                "long bootargs truncated by the boot store, or oversized one not flagged",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "boot/aarch64",
        smoke_aarch64_cmdline_store_keeps_long_bootargs
    );
}

//! Minimal ACPI table walker.
//!
//! Today's scope: locate the RSDP (passed by the bootloader via
//! `BootInfo::acpi_rsdp_phys` on x86_64 / PVH), validate its
//! checksum, walk the XSDT, and parse the SRAT (System Resource
//! Affinity Table) into a CPU↔node + memory-range↔node topology
//! the scheduler / memory subsystems can consult.
//!
//! Non-goals (deliberately left for later waves):
//! - DSDT / SSDT bytecode (AML interpreter).
//! - MADT / MCFG parsing — both have their own narrow consumers
//!   that are easier to grow alongside their drivers; this crate
//!   exposes a generic `walk_xsdt` that those can build on.
//! - HMAT / PMTT (heterogeneous memory + memory topology).
//!
//! Layout safety: every read goes through `read_unaligned` because
//! ACPI tables are typically 4-byte aligned but their fields are
//! often not naturally aligned for the wider integer types. We
//! also bound every read against the table's advertised length so
//! malformed firmware can't push us past the end of the table.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use narf_lib::percpu::MAX_CPUS;
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::PhysAddr;

/// Maximum number of memory-affinity ranges we track. Stage-4
/// QEMU configs publish ≤ 4; real silicon maxes around 16-32 per
/// node. 32 covers any sane single-socket-multi-node host.
pub const MAX_NUMA_RANGES: usize = 32;

/// Maximum NUMA proximity domains we care about. Fits a u8 → u32
/// proximity-domain field; we cap at 16 (one cache-line per node
/// when we add per-node allocators).
pub const MAX_NUMA_NODES: usize = 16;

/// CPU → proximity domain table. `[i] = u8::MAX` means "no SRAT
/// entry seen for CPU `i`" (treat as node 0 for routing).
static CPU_NODE: [AtomicU32; MAX_CPUS] = {
    // const initializer
    [const { AtomicU32::new(u32::MAX) }; MAX_CPUS]
};

/// Memory affinity ranges discovered from SRAT. Held under one lock
/// because the table is small and reads are typically cold (during
/// allocator setup or NUMA-aware steal target selection).
static MEMORY_RANGES: IrqSafeSpinLock<MemRangeTable> =
    IrqSafeSpinLock::new(MemRangeTable::EMPTY);

/// Sticky flag: set once `parse_srat` has run successfully.
static SRAT_PARSED: AtomicBool = AtomicBool::new(false);

/// RSDP physical address cached on the first successful `parse_srat`.
/// `0` = no cached RSDP. Tests can re-derive the boot topology from
/// this cache after running synthetic-body tests that mutate the
/// shared CPU/memory tables.
static CACHED_RSDP: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Number of distinct proximity domains observed. Saturates at
/// `MAX_NUMA_NODES`; exposed as the kernel's "NUMA node count".
static NODE_COUNT: AtomicU32 = AtomicU32::new(0);

/// One SRAT memory-affinity range.
#[derive(Copy, Clone, Debug, Default)]
pub struct MemRange {
    pub base:    u64,
    pub length:  u64,
    pub node:    u32,
    pub enabled: bool,
}

#[derive(Copy, Clone, Debug)]
struct MemRangeTable {
    entries: [MemRange; MAX_NUMA_RANGES],
    len:     usize,
}

impl MemRangeTable {
    const EMPTY: Self = Self {
        entries: [MemRange { base: 0, length: 0, node: 0, enabled: false };
            MAX_NUMA_RANGES],
        len:     0,
    };
}

/// Errors from RSDP/XSDT/SRAT parsing.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AcpiError {
    /// The RSDP signature `"RSD PTR "` did not match.
    BadRsdpSignature,
    /// RSDP checksum failed (sum of first 20 bytes != 0).
    BadRsdpChecksum,
    /// XSDT pointer is zero or out of the identity-mapped window.
    NoXsdt,
    /// XSDT signature mismatch.
    BadXsdtSignature,
    /// SRAT not present in the XSDT.
    NoSrat,
    /// Generic table-header checksum failed.
    BadTableChecksum,
}

/// Common SDT header. All ACPI tables (XSDT, MADT, SRAT, MCFG, ...)
/// start with this 36-byte header.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SdtHeader {
    pub signature:        [u8; 4],
    pub length:           u32,
    pub revision:         u8,
    pub checksum:         u8,
    pub oem_id:           [u8; 6],
    pub oem_table_id:     [u8; 8],
    pub oem_revision:     u32,
    pub creator_id:       u32,
    pub creator_revision: u32,
}

const SDT_HEADER_SIZE: usize = 36;

/// True iff `sig` matches the table signature in `hdr`.
#[inline]
pub fn sig_matches(hdr: &SdtHeader, sig: &[u8; 4]) -> bool {
    hdr.signature == *sig
}

/// Compute the 8-bit ACPI checksum: every byte summed mod 256 must be 0.
fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |a, b| a.wrapping_add(*b))
}

/// Scan the legacy BIOS area for an RSDP signature on 16-byte
/// boundaries. The ACPI spec mandates the RSDP lives in either
/// the EBDA's first 1 KiB or the 0xE_0000..0x10_0000 ROM region
/// on PC-compatible firmware. Stage-1 / PVH bootloaders sometimes
/// don't populate the `rsdp_paddr` field even though ACPI is
/// present (notably QEMU's `-kernel` path), so we scan the ROM
/// window as a fallback.
///
/// # Safety
/// The scanned range (0xE_0000..0x10_0000) is identity-mapped low
/// RAM on every PC firmware path the kernel boots through; reads
/// are 8-byte-bounded against the upper limit.
#[cfg(target_arch = "x86_64")]
pub unsafe fn scan_bios_for_rsdp() -> Option<PhysAddr> {
    const SIG: &[u8; 8] = b"RSD PTR ";
    const START: u64 = 0x000E_0000;
    const END:   u64 = 0x0010_0000;
    let mut p = START;
    while p + 20 <= END {
        // SAFETY: identity-mapped low ROM; 8-byte read at 16-byte
        // alignment is defined.
        let bytes = unsafe { core::slice::from_raw_parts(p as *const u8, 8) };
        if bytes == SIG {
            // Verify checksum before declaring victory; firmware
            // sometimes lays down a stale "RSD PTR " marker that
            // doesn't validate.
            // SAFETY: 20-byte read at p; bounded by END check above.
            let v1 = unsafe {
                core::slice::from_raw_parts(p as *const u8, 20)
            };
            if checksum(v1) == 0 {
                return Some(PhysAddr::new(p));
            }
        }
        p += 16;
    }
    None
}

/// Parse a v1 / v2 RSDP at `phys`. Returns the XSDT physical address
/// when the RSDP is v2+ and exposes one; falls back to RSDT for v1.
///
/// # Safety
/// `phys` must point at identity-mapped memory of at least 36 bytes
/// (v2 RSDP length).
pub unsafe fn parse_rsdp(phys: PhysAddr) -> Result<u64, AcpiError> {
    const RSDP_SIG: [u8; 8] = *b"RSD PTR ";
    let p = phys.raw() as *const u8;
    // SAFETY: caller asserts ≥36 readable bytes.
    let signature = unsafe { core::slice::from_raw_parts(p, 8) };
    if signature != RSDP_SIG {
        return Err(AcpiError::BadRsdpSignature);
    }
    // First 20 bytes must checksum to 0 for v1 validity.
    // SAFETY: same range bound as above.
    let v1_bytes = unsafe { core::slice::from_raw_parts(p, 20) };
    if checksum(v1_bytes) != 0 {
        return Err(AcpiError::BadRsdpChecksum);
    }

    // SAFETY: revision is at offset 15.
    let revision = unsafe { *p.add(15) };
    if revision >= 2 {
        // v2: full struct is 36 bytes, length at offset 20.
        // SAFETY: caller asserted 36 readable bytes.
        let xsdt_addr = unsafe {
            (p.add(24) as *const u64).read_unaligned()
        };
        if xsdt_addr != 0 { return Ok(xsdt_addr); }
    }
    // v1 fallback or v2 with null XSDT: use RSDT (32-bit pointer at offset 16).
    // SAFETY: offset 16+4 still inside the 20-byte v1 region.
    let rsdt_addr = unsafe {
        (p.add(16) as *const u32).read_unaligned()
    };
    if rsdt_addr == 0 { return Err(AcpiError::NoXsdt); }
    Ok(rsdt_addr as u64)
}

/// Walk the XSDT (or RSDT) at `phys`, calling `f` with each child
/// table's physical pointer + header. The walker tolerates either
/// flavour by inferring entry width from the signature.
///
/// # Safety
/// `phys` must point at identity-mapped memory covering at least
/// the table's advertised `length`.
pub unsafe fn walk_xsdt<F>(phys: u64, mut f: F) -> Result<(), AcpiError>
where
    F: FnMut(u64, &SdtHeader),
{
    let p = phys as *const u8;
    // SAFETY: caller-asserted readable region.
    let hdr = unsafe { (p as *const SdtHeader).read_unaligned() };
    let is_xsdt = &hdr.signature == b"XSDT";
    let is_rsdt = &hdr.signature == b"RSDT";
    if !is_xsdt && !is_rsdt {
        return Err(AcpiError::BadXsdtSignature);
    }
    let total = hdr.length as usize;
    if total < SDT_HEADER_SIZE { return Err(AcpiError::BadXsdtSignature); }
    // SAFETY: caller-asserted region covers `total`.
    let body_bytes = unsafe { core::slice::from_raw_parts(p, total) };
    if checksum(body_bytes) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }

    let entry_size = if is_xsdt { 8 } else { 4 };
    let n_entries  = (total - SDT_HEADER_SIZE) / entry_size;
    let entries    = &body_bytes[SDT_HEADER_SIZE..];

    for i in 0..n_entries {
        let off = i * entry_size;
        let phys = if is_xsdt {
            // SAFETY: bounds-checked above.
            unsafe {
                (entries.as_ptr().add(off) as *const u64).read_unaligned()
            }
        } else {
            // SAFETY: bounds-checked above.
            unsafe {
                (entries.as_ptr().add(off) as *const u32).read_unaligned()
                    as u64
            }
        };
        if phys == 0 { continue; }
        // SAFETY: caller-asserted: every XSDT entry is identity-mapped.
        let child = unsafe { (phys as *const SdtHeader).read_unaligned() };
        f(phys, &child);
    }
    Ok(())
}

/// Discover and parse the SRAT — System Resource Affinity Table.
/// Records CPU APIC-id → proximity domain (LAPIC type 0, x2APIC
/// type 2) and memory base/length → proximity domain (type 1)
/// into the static topology tables.
///
/// Idempotent: returns the entry count parsed; `is_topology_known()`
/// flips to `true` after the first successful call.
///
/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → SRAT pointers it leads to must also be identity-mapped
/// (boot's 1 GiB low identity map covers all sane QEMU layouts).
pub unsafe fn parse_srat(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    CACHED_RSDP.store(rsdp_phys.raw(), Ordering::Release);
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };

    let mut srat: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"SRAT" && srat.is_none() {
                srat = Some(phys);
            }
        })?;
    }
    let srat = srat.ok_or(AcpiError::NoSrat)?;

    // SAFETY: caller assertion: SRAT is identity-mapped.
    let total = unsafe {
        (srat as *const SdtHeader).read_unaligned().length as usize
    };
    if total < SDT_HEADER_SIZE + 12 { return Err(AcpiError::BadXsdtSignature); }
    // SAFETY: caller assertion.
    let body = unsafe {
        core::slice::from_raw_parts(srat as *const u8, total)
    };
    if checksum(body) != 0 { return Err(AcpiError::BadTableChecksum); }

    // SRAT body starts at +44 (header 36 + reserved 4 + reserved 8).
    let mut cur = SDT_HEADER_SIZE + 12;
    let mut count = 0u32;
    let mut node_seen = [false; MAX_NUMA_NODES];

    let mut ranges = MEMORY_RANGES.lock();
    ranges.len = 0;

    while cur + 2 <= body.len() {
        let kind = body[cur];
        let len  = body[cur + 1] as usize;
        if len < 2 || cur + len > body.len() { break; }
        let entry = &body[cur..cur + len];

        match kind {
            0 if entry.len() >= 16 => {
                // Type 0: Processor Local APIC/SAPIC affinity.
                // [0] type, [1] len, [2] PD low, [3] APIC id,
                // [4..8] flags, [8] local SAPIC EID, [9..12] PD high,
                // [12..16] clock domain.
                let pd_low  = entry[2] as u32;
                let pd_high = u32::from_le_bytes([
                    entry[9], entry[10], entry[11], 0,
                ]) << 8;
                let proximity = pd_high | pd_low;
                let apic = entry[3] as u32;
                let flags = u32::from_le_bytes([
                    entry[4], entry[5], entry[6], entry[7],
                ]);
                let enabled = flags & 1 != 0;
                if enabled && (apic as usize) < MAX_CPUS {
                    CPU_NODE[apic as usize].store(proximity, Ordering::Release);
                    if (proximity as usize) < MAX_NUMA_NODES {
                        node_seen[proximity as usize] = true;
                    }
                    count += 1;
                }
            }
            1 if entry.len() >= 40 => {
                // Type 1: Memory affinity.
                // [2..6] proximity domain, [8..16] base, [16..24] length,
                // [28..32] flags.
                let proximity = u32::from_le_bytes([
                    entry[2], entry[3], entry[4], entry[5],
                ]);
                let base = u64::from_le_bytes([
                    entry[8], entry[9], entry[10], entry[11],
                    entry[12], entry[13], entry[14], entry[15],
                ]);
                let length = u64::from_le_bytes([
                    entry[16], entry[17], entry[18], entry[19],
                    entry[20], entry[21], entry[22], entry[23],
                ]);
                let flags = u32::from_le_bytes([
                    entry[28], entry[29], entry[30], entry[31],
                ]);
                let enabled = flags & 1 != 0;
                if ranges.len < MAX_NUMA_RANGES {
                    let i = ranges.len;
                    ranges.entries[i] = MemRange {
                        base, length, node: proximity, enabled,
                    };
                    ranges.len = i + 1;
                }
                if enabled && (proximity as usize) < MAX_NUMA_NODES {
                    node_seen[proximity as usize] = true;
                }
                count += 1;
            }
            2 if entry.len() >= 24 => {
                // Type 2: Processor Local x2APIC affinity.
                // [4..8] proximity, [8..12] x2APIC id, [12..16] flags.
                let proximity = u32::from_le_bytes([
                    entry[4], entry[5], entry[6], entry[7],
                ]);
                let x2apic = u32::from_le_bytes([
                    entry[8], entry[9], entry[10], entry[11],
                ]);
                let flags = u32::from_le_bytes([
                    entry[12], entry[13], entry[14], entry[15],
                ]);
                let enabled = flags & 1 != 0;
                if enabled && (x2apic as usize) < MAX_CPUS {
                    CPU_NODE[x2apic as usize].store(proximity, Ordering::Release);
                    if (proximity as usize) < MAX_NUMA_NODES {
                        node_seen[proximity as usize] = true;
                    }
                    count += 1;
                }
            }
            _ => {}
        }

        cur += len;
    }

    let nodes = node_seen.iter().filter(|s| **s).count() as u32;
    NODE_COUNT.store(nodes.min(MAX_NUMA_NODES as u32), Ordering::Release);
    SRAT_PARSED.store(true, Ordering::Release);
    Ok(count)
}

/// True once `parse_srat` has succeeded at least once.
pub fn is_topology_known() -> bool {
    SRAT_PARSED.load(Ordering::Acquire)
}

/// Number of distinct proximity domains seen by the most recent SRAT
/// parse. Returns 0 before SRAT has been parsed.
pub fn node_count() -> u32 {
    NODE_COUNT.load(Ordering::Acquire)
}

/// Cached RSDP physical address from the boot-time `parse_srat` call.
/// Returns `None` if SRAT has never been parsed. Diagnostics + tests
/// can re-parse from this address to refresh the topology after
/// running synthetic-body tests that mutated the shared tables.
pub fn cached_rsdp() -> Option<PhysAddr> {
    let v = CACHED_RSDP.load(Ordering::Acquire);
    if v == 0 { None } else { Some(PhysAddr::new(v)) }
}

/// Number of enabled CPUs the SRAT advertised — counts every entry
/// in `CPU_NODE` whose value isn't the `u32::MAX` sentinel. Useful
/// when CPUID-based discovery is unreliable (multi-socket QEMU
/// configs leave leaf 0xB sub-1 returning per-core counts).
/// Returns 0 before `parse_srat` has succeeded.
pub fn cpu_count_from_srat() -> u32 {
    if !SRAT_PARSED.load(Ordering::Acquire) { return 0; }
    let mut n = 0u32;
    for c in CPU_NODE.iter() {
        if c.load(Ordering::Acquire) != u32::MAX { n += 1; }
    }
    n
}

/// Look up the NUMA node a CPU belongs to. Returns `None` when the
/// CPU was not present in the SRAT (caller should default to node 0
/// or apply a same-socket fallback).
pub fn cpu_node(cpu: u32) -> Option<u32> {
    if (cpu as usize) >= MAX_CPUS { return None; }
    let v = CPU_NODE[cpu as usize].load(Ordering::Acquire);
    if v == u32::MAX { None } else { Some(v) }
}

/// Look up which NUMA node owns a physical address. `None` if the
/// address falls outside any SRAT memory range.
pub fn memory_node(phys: u64) -> Option<u32> {
    let g = MEMORY_RANGES.lock();
    for r in &g.entries[..g.len] {
        if !r.enabled { continue; }
        let end = r.base.checked_add(r.length)?;
        if phys >= r.base && phys < end { return Some(r.node); }
    }
    None
}

/// Snapshot the parsed SRAT memory-range table into `out`. Returns
/// the number of entries written. Callers (allocator init, topology
/// dump) read this once and cache.
pub fn copy_memory_ranges(out: &mut [MemRange]) -> usize {
    let g = MEMORY_RANGES.lock();
    let n = g.len.min(out.len());
    out[..n].copy_from_slice(&g.entries[..n]);
    n
}

/// Test/diagnostic helper: clear the parsed topology so a subsequent
/// `parse_srat` call starts from a clean slate. Intended for unit
/// tests; production code calls `parse_srat` exactly once.
#[doc(hidden)]
pub fn __reset_for_test() {
    for c in CPU_NODE.iter() { c.store(u32::MAX, Ordering::Release); }
    *MEMORY_RANGES.lock() = MemRangeTable::EMPTY;
    SRAT_PARSED.store(false, Ordering::Release);
    NODE_COUNT.store(0, Ordering::Release);
}

/// Raw SRAT entry kinds. Exposed for tests/diagnostics that want to
/// validate decoding against synthetic blobs.
#[derive(Copy, Clone, Debug)]
pub enum SratEntryKind {
    LocalApic,
    Memory,
    LocalX2Apic,
    /// Anything we don't decode. Carries the raw type byte so a
    /// caller can decide what to do.
    Other(u8),
}

/// Parse a synthetic SRAT body slice for tests. Public surface
/// mirrors `parse_srat` but takes the body bytes directly so unit
/// tests don't need a full RSDP/XSDT chain. Body must already be the
/// post-header SRAT contents (everything after offset 48).
#[doc(hidden)]
pub unsafe fn __parse_srat_body_for_test(body: &[u8]) -> u32 {
    __reset_for_test();
    let mut count = 0u32;
    let mut cur = 0usize;
    let mut node_seen = [false; MAX_NUMA_NODES];
    let mut ranges = MEMORY_RANGES.lock();
    while cur + 2 <= body.len() {
        let kind = body[cur];
        let len  = body[cur + 1] as usize;
        if len < 2 || cur + len > body.len() { break; }
        let entry = &body[cur..cur + len];
        match kind {
            0 if entry.len() >= 16 => {
                let pd_low  = entry[2] as u32;
                let pd_high = u32::from_le_bytes([
                    entry[9], entry[10], entry[11], 0,
                ]) << 8;
                let proximity = pd_high | pd_low;
                let apic = entry[3] as u32;
                let flags = u32::from_le_bytes([
                    entry[4], entry[5], entry[6], entry[7],
                ]);
                if flags & 1 != 0 && (apic as usize) < MAX_CPUS {
                    CPU_NODE[apic as usize].store(proximity, Ordering::Release);
                    if (proximity as usize) < MAX_NUMA_NODES {
                        node_seen[proximity as usize] = true;
                    }
                    count += 1;
                }
            }
            1 if entry.len() >= 40 => {
                let proximity = u32::from_le_bytes([
                    entry[2], entry[3], entry[4], entry[5],
                ]);
                let base = u64::from_le_bytes([
                    entry[8], entry[9], entry[10], entry[11],
                    entry[12], entry[13], entry[14], entry[15],
                ]);
                let length = u64::from_le_bytes([
                    entry[16], entry[17], entry[18], entry[19],
                    entry[20], entry[21], entry[22], entry[23],
                ]);
                let flags = u32::from_le_bytes([
                    entry[28], entry[29], entry[30], entry[31],
                ]);
                let enabled = flags & 1 != 0;
                if ranges.len < MAX_NUMA_RANGES {
                    let i = ranges.len;
                    ranges.entries[i] = MemRange {
                        base, length, node: proximity, enabled,
                    };
                    ranges.len = i + 1;
                }
                if enabled && (proximity as usize) < MAX_NUMA_NODES {
                    node_seen[proximity as usize] = true;
                }
                count += 1;
            }
            2 if entry.len() >= 24 => {
                let proximity = u32::from_le_bytes([
                    entry[4], entry[5], entry[6], entry[7],
                ]);
                let x2apic = u32::from_le_bytes([
                    entry[8], entry[9], entry[10], entry[11],
                ]);
                let flags = u32::from_le_bytes([
                    entry[12], entry[13], entry[14], entry[15],
                ]);
                if flags & 1 != 0 && (x2apic as usize) < MAX_CPUS {
                    CPU_NODE[x2apic as usize].store(proximity, Ordering::Release);
                    if (proximity as usize) < MAX_NUMA_NODES {
                        node_seen[proximity as usize] = true;
                    }
                    count += 1;
                }
            }
            _ => {}
        }
        cur += len;
    }
    let nodes = node_seen.iter().filter(|s| **s).count() as u32;
    NODE_COUNT.store(nodes.min(MAX_NUMA_NODES as u32), Ordering::Release);
    SRAT_PARSED.store(true, Ordering::Release);
    count
}

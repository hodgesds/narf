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

/// Maximum IOAPICs we track. PC platforms ship 1; multi-IOAPIC
/// configs (high-density servers, x2APIC topologies) max around 8.
pub const MAX_IOAPICS: usize = 8;

/// Maximum interrupt source overrides (ISA → GSI remappings). The
/// MADT typically lists ≤ 4 entries on PC-class hardware; 16 covers
/// any sane firmware.
pub const MAX_ISA_OVERRIDES: usize = 16;

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

// ── MADT (Multiple APIC Description Table) ─────────────────────────
//
// MADT signature is `"APIC"` (historic name pre-dating its
// generalisation). The table starts with a 36-byte SDT header,
// followed by the LAPIC base (u32) and PCAT-compat flags (u32),
// then a sequence of variable-length entries.
//
// Today's decoder covers Type 0 (Processor Local APIC), Type 1
// (IOAPIC), Type 2 (Interrupt Source Override), and Type 9 (Local
// x2APIC). Type 4 (Local APIC NMI), Type 5 (Local APIC Address
// Override), Type 7+ (newer GIC entries) are skipped — narrow
// consumers can grow them as needed.

/// LAPIC base physical address from MADT. `0` = MADT not parsed
/// or absent.
static LAPIC_BASE: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Number of enabled processor entries the MADT advertised.
static MADT_CPU_COUNT: AtomicU32 = AtomicU32::new(0);

/// Per-CPU APIC ID list, indexed by enumeration order. `u32::MAX`
/// = "no entry seen". Stage-4 callers care more about the count
/// than the order; ordered storage simplifies the deterministic
/// list used by `start_aps`.
static APIC_IDS: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(u32::MAX) }; MAX_CPUS];

/// Sticky flag: set once `parse_madt` has run successfully.
static MADT_PARSED: AtomicBool = AtomicBool::new(false);

/// IOAPIC entry from MADT.
#[derive(Copy, Clone, Debug, Default)]
pub struct IoApic {
    pub id:           u8,
    pub address:      u32,
    /// Global System Interrupt base — first GSI this IOAPIC owns.
    pub gsi_base:     u32,
}

/// Interrupt source override entry from MADT.
#[derive(Copy, Clone, Debug, Default)]
pub struct IsaOverride {
    pub bus:    u8,
    pub source: u8,
    pub gsi:    u32,
    pub flags:  u16,
}

#[derive(Copy, Clone, Debug)]
struct MadtTables {
    ioapics:       [IoApic; MAX_IOAPICS],
    n_ioapics:     usize,
    overrides:     [IsaOverride; MAX_ISA_OVERRIDES],
    n_overrides:   usize,
}

impl MadtTables {
    const EMPTY: Self = Self {
        ioapics:     [IoApic { id: 0, address: 0, gsi_base: 0 }; MAX_IOAPICS],
        n_ioapics:   0,
        overrides:   [IsaOverride { bus: 0, source: 0, gsi: 0, flags: 0 };
            MAX_ISA_OVERRIDES],
        n_overrides: 0,
    };
}

static MADT_DATA: IrqSafeSpinLock<MadtTables> =
    IrqSafeSpinLock::new(MadtTables::EMPTY);

/// Discover and parse the MADT. Records the LAPIC base, the per-CPU
/// APIC ID list, every IOAPIC entry, and ISA → GSI overrides.
///
/// Returns the count of entries decoded across all kinds.
///
/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → MADT pointers it leads to must also be identity-mapped.
pub unsafe fn parse_madt(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };

    let mut madt: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"APIC" && madt.is_none() {
                madt = Some(phys);
            }
        })?;
    }
    let madt = madt.ok_or(AcpiError::NoSrat)?; // reuse error variant — narrow.

    // SAFETY: caller assertion.
    let total = unsafe {
        (madt as *const SdtHeader).read_unaligned().length as usize
    };
    if total < SDT_HEADER_SIZE + 8 { return Err(AcpiError::BadXsdtSignature); }
    // SAFETY: caller assertion.
    let body = unsafe {
        core::slice::from_raw_parts(madt as *const u8, total)
    };
    if checksum(body) != 0 { return Err(AcpiError::BadTableChecksum); }

    // 4 bytes LAPIC base + 4 bytes flags after the SDT header.
    let lapic_base = u32::from_le_bytes([
        body[SDT_HEADER_SIZE], body[SDT_HEADER_SIZE + 1],
        body[SDT_HEADER_SIZE + 2], body[SDT_HEADER_SIZE + 3],
    ]) as u64;
    LAPIC_BASE.store(lapic_base, Ordering::Release);

    let mut cur = SDT_HEADER_SIZE + 8;
    let mut count = 0u32;
    let mut cpu_count = 0u32;

    for slot in APIC_IDS.iter() { slot.store(u32::MAX, Ordering::Release); }
    let mut tables = MADT_DATA.lock();
    *tables = MadtTables::EMPTY;

    while cur + 2 <= body.len() {
        let kind = body[cur];
        let len  = body[cur + 1] as usize;
        if len < 2 || cur + len > body.len() { break; }
        let entry = &body[cur..cur + len];

        match kind {
            0 if entry.len() >= 8 => {
                // Type 0: Processor Local APIC.
                // [2] ACPI processor id, [3] APIC id, [4..8] flags.
                let apic_id = entry[3] as u32;
                let flags = u32::from_le_bytes([
                    entry[4], entry[5], entry[6], entry[7],
                ]);
                let enabled = flags & 1 != 0;
                if enabled && (cpu_count as usize) < MAX_CPUS {
                    APIC_IDS[cpu_count as usize].store(apic_id, Ordering::Release);
                    cpu_count += 1;
                    count += 1;
                }
            }
            1 if entry.len() >= 12 => {
                // Type 1: IOAPIC.
                // [2] id, [3] reserved, [4..8] address, [8..12] GSI base.
                let id = entry[2];
                let address = u32::from_le_bytes([
                    entry[4], entry[5], entry[6], entry[7],
                ]);
                let gsi_base = u32::from_le_bytes([
                    entry[8], entry[9], entry[10], entry[11],
                ]);
                if tables.n_ioapics < MAX_IOAPICS {
                    let i = tables.n_ioapics;
                    tables.ioapics[i] = IoApic { id, address, gsi_base };
                    tables.n_ioapics = i + 1;
                    count += 1;
                }
            }
            2 if entry.len() >= 10 => {
                // Type 2: Interrupt Source Override.
                // [2] bus, [3] source, [4..8] GSI, [8..10] flags.
                let bus = entry[2];
                let source = entry[3];
                let gsi = u32::from_le_bytes([
                    entry[4], entry[5], entry[6], entry[7],
                ]);
                let flags = u16::from_le_bytes([entry[8], entry[9]]);
                if tables.n_overrides < MAX_ISA_OVERRIDES {
                    let i = tables.n_overrides;
                    tables.overrides[i] = IsaOverride { bus, source, gsi, flags };
                    tables.n_overrides = i + 1;
                    count += 1;
                }
            }
            9 if entry.len() >= 16 => {
                // Type 9: Local x2APIC.
                // [4..8] x2APIC id (u32), [8..12] flags, [12..16] ACPI uid.
                let apic_id = u32::from_le_bytes([
                    entry[4], entry[5], entry[6], entry[7],
                ]);
                let flags = u32::from_le_bytes([
                    entry[8], entry[9], entry[10], entry[11],
                ]);
                let enabled = flags & 1 != 0;
                if enabled && (cpu_count as usize) < MAX_CPUS {
                    APIC_IDS[cpu_count as usize].store(apic_id, Ordering::Release);
                    cpu_count += 1;
                    count += 1;
                }
            }
            _ => {}
        }
        cur += len;
    }

    MADT_CPU_COUNT.store(cpu_count, Ordering::Release);
    MADT_PARSED.store(true, Ordering::Release);
    Ok(count)
}

/// LAPIC base physical address advertised by the MADT, or `None`
/// when MADT has not been parsed.
pub fn lapic_base() -> Option<u64> {
    let v = LAPIC_BASE.load(Ordering::Acquire);
    if v == 0 { None } else { Some(v) }
}

/// Number of enabled CPUs the MADT advertised.
pub fn cpu_count_from_madt() -> u32 {
    MADT_CPU_COUNT.load(Ordering::Acquire)
}

/// Lookup the APIC id at enumeration index `i`. Stage-4 SMP bring-up
/// uses this list as the canonical AP target order. Returns `None`
/// for indices beyond the enumerated count.
pub fn apic_id_at(i: usize) -> Option<u32> {
    if i >= MAX_CPUS { return None; }
    let v = APIC_IDS[i].load(Ordering::Acquire);
    if v == u32::MAX { None } else { Some(v) }
}

/// Snapshot of the IOAPIC list. Returns the count written.
pub fn copy_ioapics(out: &mut [IoApic]) -> usize {
    let g = MADT_DATA.lock();
    let n = g.n_ioapics.min(out.len());
    out[..n].copy_from_slice(&g.ioapics[..n]);
    n
}

/// Snapshot of the ISA-override list. Returns the count written.
pub fn copy_isa_overrides(out: &mut [IsaOverride]) -> usize {
    let g = MADT_DATA.lock();
    let n = g.n_overrides.min(out.len());
    out[..n].copy_from_slice(&g.overrides[..n]);
    n
}

/// True once `parse_madt` has succeeded at least once.
pub fn is_madt_known() -> bool {
    MADT_PARSED.load(Ordering::Acquire)
}

// ── MCFG (PCI Express Memory-mapped Configuration Space) ────────────
//
// MCFG signature is `"MCFG"`. After the SDT header and 8 reserved
// bytes there are 16-byte segment-allocation entries:
//
//   offset  field             type
//   0x00    base address      u64
//   0x08    PCI segment       u16
//   0x0A    start bus         u8
//   0x0B    end bus           u8
//   0x0C    reserved          u32
//
// Today we surface segment 0's base — multi-segment platforms grow
// later when there's a consumer.

static MCFG_BASE: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Discover and parse the MCFG. Returns the segment-0 ECAM base
/// physical address.
///
/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → MCFG pointers it leads to must also be identity-mapped.
pub unsafe fn parse_mcfg(rsdp_phys: PhysAddr) -> Result<u64, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };

    let mut mcfg: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"MCFG" && mcfg.is_none() {
                mcfg = Some(phys);
            }
        })?;
    }
    let mcfg = mcfg.ok_or(AcpiError::NoSrat)?;

    // SAFETY: caller assertion.
    let total = unsafe {
        (mcfg as *const SdtHeader).read_unaligned().length as usize
    };
    let body_end = SDT_HEADER_SIZE + 8 + 16; // header + reserved + 1 entry
    if total < body_end { return Err(AcpiError::BadXsdtSignature); }
    // SAFETY: caller assertion.
    let body = unsafe {
        core::slice::from_raw_parts(mcfg as *const u8, total)
    };
    if checksum(body) != 0 { return Err(AcpiError::BadTableChecksum); }

    let base = u64::from_le_bytes([
        body[SDT_HEADER_SIZE + 8],  body[SDT_HEADER_SIZE + 9],
        body[SDT_HEADER_SIZE + 10], body[SDT_HEADER_SIZE + 11],
        body[SDT_HEADER_SIZE + 12], body[SDT_HEADER_SIZE + 13],
        body[SDT_HEADER_SIZE + 14], body[SDT_HEADER_SIZE + 15],
    ]);
    MCFG_BASE.store(base, Ordering::Release);
    Ok(base)
}

/// PCIe ECAM base from the most recent MCFG parse, segment 0.
pub fn mcfg_ecam_base() -> Option<u64> {
    let v = MCFG_BASE.load(Ordering::Acquire);
    if v == 0 { None } else { Some(v) }
}

// ── FADT (Fixed ACPI Description Table) → DSDT pointer ─────────────
//
// FADT signature is `"FACP"`. Most fields are platform-power
// related; for our purposes we only need the DSDT pointer:
//   offset 40 (u32 DSDT) — the legacy 32-bit pointer.
//   offset 140 (u64 X_DSDT) — the extended 64-bit pointer (ACPI 2.0+).
// Use X_DSDT when non-zero, fall back to DSDT.

static DSDT_PHYS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Discover the DSDT physical address by walking the XSDT to find
/// the FADT and reading its DSDT/X_DSDT field.
///
/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → FADT pointers it leads to must also be identity-mapped.
pub unsafe fn parse_fadt_for_dsdt(rsdp_phys: PhysAddr) -> Result<u64, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut fadt: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"FACP" && fadt.is_none() { fadt = Some(phys); }
        })?;
    }
    let fadt = fadt.ok_or(AcpiError::NoSrat)?;

    // SAFETY: caller assertion.
    let total = unsafe {
        (fadt as *const SdtHeader).read_unaligned().length as usize
    };
    if total < 44 { return Err(AcpiError::BadXsdtSignature); }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(fadt as *const u8, total) };
    if checksum(body) != 0 { return Err(AcpiError::BadTableChecksum); }

    // Legacy DSDT pointer at offset 40 (4 bytes).
    let legacy_dsdt = u32::from_le_bytes([
        body[40], body[41], body[42], body[43],
    ]) as u64;

    // X_DSDT at offset 140 (8 bytes), ACPI 2.0+. Some FADTs are
    // shorter and don't carry it.
    let x_dsdt = if total >= 148 {
        u64::from_le_bytes([
            body[140], body[141], body[142], body[143],
            body[144], body[145], body[146], body[147],
        ])
    } else { 0 };

    let dsdt = if x_dsdt != 0 { x_dsdt } else { legacy_dsdt };
    if dsdt == 0 { return Err(AcpiError::NoSrat); }
    DSDT_PHYS.store(dsdt, Ordering::Release);
    Ok(dsdt)
}

/// DSDT physical address from the most recent `parse_fadt_for_dsdt` call.
pub fn dsdt_phys() -> Option<u64> {
    let v = DSDT_PHYS.load(Ordering::Acquire);
    if v == 0 { None } else { Some(v) }
}

/// Walk every SSDT pointer in the XSDT, calling `f` with each
/// SSDT's physical pointer + header. AML namespace builders need
/// to walk DSDT *and* every SSDT to assemble the complete
/// namespace.
///
/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain
/// of XSDT → SSDT pointers must also be identity-mapped.
pub unsafe fn walk_ssdts<F>(rsdp_phys: PhysAddr, mut f: F) -> Result<(), AcpiError>
where
    F: FnMut(u64, &SdtHeader),
{
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"SSDT" { f(phys, hdr); }
        })?;
    }
    Ok(())
}

// ── HMAT (Heterogeneous Memory Attribute Table) ─────────────────────
//
// HMAT signature is `"HMAT"`. After the SDT header + 4 reserved
// bytes there's a sequence of variable-length sub-structures:
//
//   offset 0: Type (u16)  — 0=Mem Proximity Attrs, 1=Locality lat/bw,
//                            2=Memory Side Cache.
//   offset 2: Reserved (u16)
//   offset 4: Length (u32)
//   ...type-specific body...
//
// Today's decoder covers Types 0 and 1; Type 2 (memory-side cache
// info) is decoded only enough to walk past it. The lat/bw matrix
// (Type 1) is the most useful piece — a NUMA-aware allocator or
// scheduler-affinity hint can rank target nodes by access latency
// from a given initiator.

/// Maximum number of HMAT memory-proximity attribute entries we
/// track. Each NUMA node has one; cap matches `MAX_NUMA_NODES`.
pub const MAX_HMAT_MEM_ATTRS: usize = MAX_NUMA_NODES;

/// Maximum HMAT latency/bandwidth records we keep. Each record can
/// pack many initiators × targets, so 8 records covers the common
/// "access latency + access bandwidth + read/write variants" set.
pub const MAX_HMAT_LATBW: usize = 8;

/// Maximum (initiator, target) pairs per HMAT lat/bw record. Bounds
/// the per-record matrix size we copy into static storage.
pub const MAX_HMAT_LATBW_PAIRS: usize = MAX_NUMA_NODES * MAX_NUMA_NODES;

/// HMAT memory-proximity attribute entry (Type 0).
#[derive(Copy, Clone, Debug, Default)]
pub struct HmatMemAttr {
    /// Initiator (CPU/GPU) proximity domain. Only meaningful when
    /// `processor_proximity_valid` is set.
    pub processor_pd:                 u32,
    /// Memory proximity domain this entry describes.
    pub memory_pd:                    u32,
    /// Bit 0: processor_proximity_valid.
    pub flags:                        u16,
    /// Convenience accessor.
    pub processor_proximity_valid:    bool,
}

/// HMAT lat/bw record kind (Type 1 `data_type`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HmatLatBwKind {
    AccessLatency,
    ReadLatency,
    WriteLatency,
    AccessBandwidth,
    ReadBandwidth,
    WriteBandwidth,
    Other(u8),
}

impl HmatLatBwKind {
    fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::AccessLatency,
            1 => Self::ReadLatency,
            2 => Self::WriteLatency,
            3 => Self::AccessBandwidth,
            4 => Self::ReadBandwidth,
            5 => Self::WriteBandwidth,
            x => Self::Other(x),
        }
    }
}

/// HMAT lat/bw record (Type 1) header — value matrix lives in a
/// separate fixed-size table because it can be large.
#[derive(Copy, Clone, Debug)]
pub struct HmatLatBwRecord {
    pub kind:           HmatLatBwKind,
    /// Memory hierarchy: 0=memory, 1=last-level cache, etc.
    pub hierarchy:      u8,
    pub n_initiators:   u32,
    pub n_targets:      u32,
    /// Multiplier in picoseconds (latency) or MB/s (bandwidth).
    pub entry_base_unit: u64,
    /// Index into `HMAT_LATBW_PAIRS` where this record's pair list
    /// starts. `n_initiators * n_targets` pairs follow.
    pub pairs_offset:   u32,
}

#[derive(Copy, Clone, Debug)]
struct HmatLatBwPair {
    initiator: u32,
    target:    u32,
    /// Raw value in `entry_base_unit` units.
    value:     u16,
}

#[derive(Copy, Clone, Debug)]
struct HmatTables {
    mem_attrs:        [HmatMemAttr; MAX_HMAT_MEM_ATTRS],
    n_mem_attrs:      usize,
    records:          [HmatLatBwRecord; MAX_HMAT_LATBW],
    n_records:        usize,
    pairs:            [HmatLatBwPair; MAX_HMAT_LATBW_PAIRS],
    n_pairs:          usize,
}

impl HmatTables {
    const EMPTY: Self = Self {
        mem_attrs: [HmatMemAttr {
            processor_pd: 0, memory_pd: 0,
            flags: 0, processor_proximity_valid: false,
        }; MAX_HMAT_MEM_ATTRS],
        n_mem_attrs: 0,
        records: [HmatLatBwRecord {
            kind: HmatLatBwKind::Other(0xFF),
            hierarchy: 0,
            n_initiators: 0, n_targets: 0,
            entry_base_unit: 0, pairs_offset: 0,
        }; MAX_HMAT_LATBW],
        n_records: 0,
        pairs: [HmatLatBwPair { initiator: 0, target: 0, value: 0 };
            MAX_HMAT_LATBW_PAIRS],
        n_pairs: 0,
    };
}

static HMAT_DATA: IrqSafeSpinLock<HmatTables> =
    IrqSafeSpinLock::new(HmatTables::EMPTY);
static HMAT_PARSED: AtomicBool = AtomicBool::new(false);

/// Discover and parse the HMAT.
///
/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → HMAT pointers must also be identity-mapped.
pub unsafe fn parse_hmat(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut hmat: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"HMAT" && hmat.is_none() { hmat = Some(phys); }
        })?;
    }
    let hmat = hmat.ok_or(AcpiError::NoSrat)?;

    // SAFETY: caller assertion.
    let total = unsafe {
        (hmat as *const SdtHeader).read_unaligned().length as usize
    };
    if total < SDT_HEADER_SIZE + 4 { return Err(AcpiError::BadXsdtSignature); }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(hmat as *const u8, total) };
    if checksum(body) != 0 { return Err(AcpiError::BadTableChecksum); }

    // 4 reserved bytes after the SDT header.
    let mut cur = SDT_HEADER_SIZE + 4;
    let mut count = 0u32;
    let mut tables = HMAT_DATA.lock();
    *tables = HmatTables::EMPTY;

    while cur + 8 <= body.len() {
        let kind = u16::from_le_bytes([body[cur], body[cur + 1]]);
        let len  = u32::from_le_bytes([
            body[cur + 4], body[cur + 5], body[cur + 6], body[cur + 7],
        ]) as usize;
        if len < 8 || cur + len > body.len() { break; }
        let entry = &body[cur..cur + len];

        match kind {
            0 if entry.len() >= 40 => {
                // Type 0: Memory Proximity Domain Attributes.
                // [8..10] flags, [10..12] reserved, [12..16] processor PD,
                // [16..20] memory PD, [20..40] reserved.
                let flags = u16::from_le_bytes([entry[8], entry[9]]);
                let processor_pd = u32::from_le_bytes([
                    entry[12], entry[13], entry[14], entry[15],
                ]);
                let memory_pd = u32::from_le_bytes([
                    entry[16], entry[17], entry[18], entry[19],
                ]);
                if tables.n_mem_attrs < MAX_HMAT_MEM_ATTRS {
                    let i = tables.n_mem_attrs;
                    tables.mem_attrs[i] = HmatMemAttr {
                        processor_pd,
                        memory_pd,
                        flags,
                        processor_proximity_valid: flags & 0x1 != 0,
                    };
                    tables.n_mem_attrs = i + 1;
                    count += 1;
                }
            }
            1 if entry.len() >= 32 => {
                // Type 1: System Locality Latency/Bandwidth.
                // [8] flags, [9] data_type, [10] min_xfer_size, [11] reserved,
                // [12..16] num_initiators, [16..20] num_targets,
                // [20..24] reserved, [24..32] entry_base_unit,
                // then num_initiators × u32, num_targets × u32, matrix
                // num_initiators*num_targets × u16.
                let hierarchy = entry[8] & 0x0F;
                let dt   = HmatLatBwKind::from_byte(entry[9]);
                let n_in  = u32::from_le_bytes([
                    entry[12], entry[13], entry[14], entry[15],
                ]);
                let n_tg  = u32::from_le_bytes([
                    entry[16], entry[17], entry[18], entry[19],
                ]);
                let base_unit = u64::from_le_bytes([
                    entry[24], entry[25], entry[26], entry[27],
                    entry[28], entry[29], entry[30], entry[31],
                ]);

                let init_off = 32;
                let tgt_off  = init_off + (n_in as usize) * 4;
                let mat_off  = tgt_off  + (n_tg as usize) * 4;
                let mat_len  = (n_in as usize) * (n_tg as usize) * 2;
                if mat_off + mat_len > entry.len() { break; }
                if tables.n_records >= MAX_HMAT_LATBW { cur += len; continue; }

                let pairs_offset = tables.n_pairs as u32;
                // Decode matrix into the flat pair table.
                'outer: for ii in 0..(n_in as usize) {
                    for ti in 0..(n_tg as usize) {
                        if tables.n_pairs >= MAX_HMAT_LATBW_PAIRS {
                            break 'outer;
                        }
                        let initiator = u32::from_le_bytes([
                            entry[init_off + ii * 4],
                            entry[init_off + ii * 4 + 1],
                            entry[init_off + ii * 4 + 2],
                            entry[init_off + ii * 4 + 3],
                        ]);
                        let target = u32::from_le_bytes([
                            entry[tgt_off + ti * 4],
                            entry[tgt_off + ti * 4 + 1],
                            entry[tgt_off + ti * 4 + 2],
                            entry[tgt_off + ti * 4 + 3],
                        ]);
                        let val_off = mat_off + (ii * (n_tg as usize) + ti) * 2;
                        let value = u16::from_le_bytes([
                            entry[val_off], entry[val_off + 1],
                        ]);
                        let i = tables.n_pairs;
                        tables.pairs[i] = HmatLatBwPair {
                            initiator, target, value,
                        };
                        tables.n_pairs = i + 1;
                    }
                }
                let i = tables.n_records;
                tables.records[i] = HmatLatBwRecord {
                    kind: dt,
                    hierarchy,
                    n_initiators: n_in,
                    n_targets:    n_tg,
                    entry_base_unit: base_unit,
                    pairs_offset,
                };
                tables.n_records = i + 1;
                count += 1;
            }
            // Type 2 (Memory Side Cache) — walked but not retained.
            _ => {}
        }
        cur += len;
    }

    HMAT_PARSED.store(true, Ordering::Release);
    Ok(count)
}

/// True once `parse_hmat` has succeeded.
pub fn is_hmat_known() -> bool { HMAT_PARSED.load(Ordering::Acquire) }

/// Snapshot the HMAT memory-proximity attribute list. Returns the
/// number of entries written.
pub fn copy_hmat_mem_attrs(out: &mut [HmatMemAttr]) -> usize {
    let g = HMAT_DATA.lock();
    let n = g.n_mem_attrs.min(out.len());
    out[..n].copy_from_slice(&g.mem_attrs[..n]);
    n
}

/// Look up a single (initiator, target) lat/bw value. `kind`
/// disambiguates which record to consult; matching kind + hierarchy
/// (default `0` = main memory) wins. Returns the raw u16 value
/// times `entry_base_unit` (latency in picoseconds, bandwidth in
/// MB/s by ACPI convention).
pub fn hmat_value(
    kind:      HmatLatBwKind,
    hierarchy: u8,
    initiator: u32,
    target:    u32,
) -> Option<u64> {
    let g = HMAT_DATA.lock();
    for r in &g.records[..g.n_records] {
        if r.kind != kind || r.hierarchy != hierarchy { continue; }
        let n_pairs = (r.n_initiators as usize) * (r.n_targets as usize);
        let start = r.pairs_offset as usize;
        for p in &g.pairs[start..start + n_pairs.min(g.n_pairs.saturating_sub(start))] {
            if p.initiator == initiator && p.target == target {
                return Some(r.entry_base_unit.saturating_mul(p.value as u64));
            }
        }
    }
    None
}

/// Copy out lat/bw record headers (without their pair data) for
/// diagnostics. Returns the count.
pub fn copy_hmat_records(out: &mut [HmatLatBwRecord]) -> usize {
    let g = HMAT_DATA.lock();
    let n = g.n_records.min(out.len());
    out[..n].copy_from_slice(&g.records[..n]);
    n
}

// ── PMTT (Platform Memory Topology Table) ───────────────────────────
//
// PMTT signature is `"PMTT"`. ACPI 6.0+ layout:
//
//   header: SDT (36) + memory-device-count u32 (4) — 40 bytes total.
//   then a sequence of "common" structures, each:
//     [0] type u8: 0=Socket, 1=Memory Controller, 2=DIMM,
//                  0xFF=Vendor-specific.
//     [1] reserved
//     [2..4] length u16
//     [4..6] flags u16
//     [6..8] reserved
//     ... type-specific body, then nested children up to length.
//
// Sockets contain Memory Controllers, which contain DIMMs.
//
// We flatten the hierarchy into three counters + a small DIMM table
// (smbios handle + parent socket id). That covers what
// observability/diagnostics typically need; deeper hierarchy walks
// can layer on top.

/// Maximum DIMM entries we track. 32 is comfortable for most
/// platforms; multi-socket high-density servers can stretch this
/// when a real consumer arrives.
pub const MAX_PMTT_DIMMS: usize = 32;

/// One DIMM entry from PMTT.
#[derive(Copy, Clone, Debug, Default)]
pub struct PmttDimm {
    /// SMBIOS Type-17 handle the DIMM corresponds to.
    pub smbios_handle: u32,
    /// Parent socket id (closest enclosing Type-0 Socket).
    pub socket_id:     u16,
    /// Parent memory-controller id (closest enclosing Type-1).
    pub controller_id: u16,
    /// Common-header flags from the DIMM struct.
    pub flags:         u16,
}

#[derive(Copy, Clone, Debug)]
struct PmttTables {
    n_sockets:     u32,
    n_controllers: u32,
    n_dimms:       u32,
    dimms:         [PmttDimm; MAX_PMTT_DIMMS],
    dimms_len:     usize,
}

impl PmttTables {
    const EMPTY: Self = Self {
        n_sockets: 0, n_controllers: 0, n_dimms: 0,
        dimms: [PmttDimm {
            smbios_handle: 0, socket_id: 0, controller_id: 0, flags: 0,
        }; MAX_PMTT_DIMMS],
        dimms_len: 0,
    };
}

static PMTT_DATA: IrqSafeSpinLock<PmttTables> =
    IrqSafeSpinLock::new(PmttTables::EMPTY);
static PMTT_PARSED: AtomicBool = AtomicBool::new(false);

/// Discover and parse the PMTT.
///
/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → PMTT pointers must also be identity-mapped.
pub unsafe fn parse_pmtt(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut pmtt: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"PMTT" && pmtt.is_none() { pmtt = Some(phys); }
        })?;
    }
    let pmtt = pmtt.ok_or(AcpiError::NoSrat)?;

    // SAFETY: caller assertion.
    let total = unsafe {
        (pmtt as *const SdtHeader).read_unaligned().length as usize
    };
    if total < SDT_HEADER_SIZE + 4 { return Err(AcpiError::BadXsdtSignature); }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(pmtt as *const u8, total) };
    if checksum(body) != 0 { return Err(AcpiError::BadTableChecksum); }

    // After SDT header: u32 memory-device-count (informational).
    let mut cur = SDT_HEADER_SIZE + 4;
    let mut tables = PMTT_DATA.lock();
    *tables = PmttTables::EMPTY;

    let count = parse_pmtt_children(body, &mut cur, body.len(), 0xFFFF, 0xFFFF, &mut tables);
    PMTT_PARSED.store(true, Ordering::Release);
    Ok(count)
}

/// Walk siblings starting at `*cur`, recursing into children. Returns
/// the count of structures decoded.
fn parse_pmtt_children(
    body:           &[u8],
    cur:            &mut usize,
    end:            usize,
    parent_socket:  u16,
    parent_ctrl:    u16,
    out:            &mut PmttTables,
) -> u32 {
    let mut count = 0u32;
    while *cur + 8 <= end {
        let kind = body[*cur];
        let len  = u16::from_le_bytes([body[*cur + 2], body[*cur + 3]]) as usize;
        if len < 8 || *cur + len > end { break; }
        let entry = &body[*cur..*cur + len];
        let flags = u16::from_le_bytes([entry[4], entry[5]]);

        match kind {
            0 if entry.len() >= 12 => {
                // Socket: [8..10] socket id, [10..12] reserved.
                let socket_id = u16::from_le_bytes([entry[8], entry[9]]);
                out.n_sockets += 1;
                let mut child_cur = *cur + 12;
                let child_end = *cur + len;
                count += 1 + parse_pmtt_children(
                    body, &mut child_cur, child_end,
                    socket_id, parent_ctrl, out);
            }
            1 if entry.len() >= 12 => {
                // Memory Controller: [8..10] id, [10..12] reserved.
                let ctrl_id = u16::from_le_bytes([entry[8], entry[9]]);
                out.n_controllers += 1;
                let mut child_cur = *cur + 12;
                let child_end = *cur + len;
                count += 1 + parse_pmtt_children(
                    body, &mut child_cur, child_end,
                    parent_socket, ctrl_id, out);
            }
            2 if entry.len() >= 12 => {
                // DIMM: [8..12] SMBIOS handle.
                let smbios_handle = u32::from_le_bytes([
                    entry[8], entry[9], entry[10], entry[11],
                ]);
                if out.dimms_len < MAX_PMTT_DIMMS {
                    let i = out.dimms_len;
                    out.dimms[i] = PmttDimm {
                        smbios_handle,
                        socket_id:     parent_socket,
                        controller_id: parent_ctrl,
                        flags,
                    };
                    out.dimms_len = i + 1;
                }
                out.n_dimms += 1;
                count += 1;
            }
            _ => { /* vendor-specific or unknown — skip */ }
        }
        *cur += len;
    }
    count
}

/// True once `parse_pmtt` has succeeded.
pub fn is_pmtt_known() -> bool { PMTT_PARSED.load(Ordering::Acquire) }

/// Counts of structures observed in the most recent PMTT parse.
pub fn pmtt_counts() -> (u32, u32, u32) {
    let g = PMTT_DATA.lock();
    (g.n_sockets, g.n_controllers, g.n_dimms)
}

/// Snapshot the DIMM list. Returns the count written.
pub fn copy_pmtt_dimms(out: &mut [PmttDimm]) -> usize {
    let g = PMTT_DATA.lock();
    let n = g.dimms_len.min(out.len());
    out[..n].copy_from_slice(&g.dimms[..n]);
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
    for c in APIC_IDS.iter() { c.store(u32::MAX, Ordering::Release); }
    *MADT_DATA.lock() = MadtTables::EMPTY;
    MADT_PARSED.store(false, Ordering::Release);
    MADT_CPU_COUNT.store(0, Ordering::Release);
    LAPIC_BASE.store(0, Ordering::Release);
    MCFG_BASE.store(0, Ordering::Release);
    DSDT_PHYS.store(0, Ordering::Release);
    *HMAT_DATA.lock() = HmatTables::EMPTY;
    HMAT_PARSED.store(false, Ordering::Release);
    *PMTT_DATA.lock() = PmttTables::EMPTY;
    PMTT_PARSED.store(false, Ordering::Release);
    *GPE0_BLOCK.lock() = None;
    *GPE1_BLOCK.lock() = None;
}

// ── FADT (Fixed ACPI Description Table) → GPE block pointers ────────
//
// GPE0_BLK and GPE1_BLK carry port or memory addresses for the General
// Purpose Event register blocks. ACPI 2.0+ adds extended 64-bit GAS
// versions (X_GPE0_BLK / X_GPE1_BLK) in the extended FADT.
//
// FADT body offsets (including the 36-byte SDT header in the count):
//   80:  GPE0_BLK        u32  — legacy 32-bit address
//   84:  GPE1_BLK        u32  — legacy 32-bit address
//   92:  GPE0_BLK_LEN    u8   — byte count
//   93:  GPE1_BLK_LEN    u8   — byte count
//   95:  GPE1_BASE       u8   — GPE1 event offset (base GSI for GPE1)
//   220: X_GPE0_BLK      12-byte GAS (ACPI 2.0+, valid when total ≥ 232)
//   232: X_GPE1_BLK      12-byte GAS
//
// GAS layout (ACPI §5.2.3.2 Generic Address Structure):
//   [0]:    address_space_id  u8
//   [1]:    bit_width         u8
//   [2]:    bit_offset        u8
//   [3]:    access_size       u8
//   [4..12]: address          u64 LE

/// Descriptor for one GPE register block.
#[derive(Copy, Clone, Debug, Default)]
pub struct GpeBlockInfo {
    /// Base port / MMIO address of the block.
    pub address:    u64,
    /// Total byte count of the status+enable register pair.
    pub byte_count: u8,
    /// First GPE number this block handles (0 for GPE0, GPE1_BASE for GPE1).
    pub base_gsi:   u32,
}

static GPE0_BLOCK: IrqSafeSpinLock<Option<GpeBlockInfo>> = IrqSafeSpinLock::new(None);
static GPE1_BLOCK: IrqSafeSpinLock<Option<GpeBlockInfo>> = IrqSafeSpinLock::new(None);

/// Parse the FADT to discover GPE0 and GPE1 block descriptors. Uses
/// X_GPE0_BLK / X_GPE1_BLK when the FADT total length is ≥ 232 and
/// the extended address is non-zero; falls back to legacy 32-bit fields.
///
/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → FADT pointers it leads to must also be identity-mapped.
pub unsafe fn parse_gpe_blocks(rsdp_phys: PhysAddr) -> Result<(), AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut fadt: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"FACP" && fadt.is_none() { fadt = Some(phys); }
        })?;
    }
    let fadt = fadt.ok_or(AcpiError::NoSrat)?;

    // SAFETY: caller assertion.
    let total = unsafe {
        (fadt as *const SdtHeader).read_unaligned().length as usize
    };
    // Need at least offset 96 (past GPE1_BASE at byte 95).
    if total < 96 { return Err(AcpiError::BadXsdtSignature); }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(fadt as *const u8, total) };
    if checksum(body) != 0 { return Err(AcpiError::BadTableChecksum); }

    // ── legacy fields ────────────────────────────────────────────────
    let legacy_gpe0_addr = u32::from_le_bytes([
        body[80], body[81], body[82], body[83],
    ]) as u64;
    let legacy_gpe1_addr = u32::from_le_bytes([
        body[84], body[85], body[86], body[87],
    ]) as u64;
    let gpe0_len    = body[92];
    let gpe1_len    = body[93];
    let gpe1_base   = body[95] as u32;

    // ── extended GAS fields (ACPI 2.0+, FADT total ≥ 232+12=244) ───
    // X_GPE0_BLK is at offset 220, X_GPE1_BLK at 232. Each is 12 bytes.
    let (x_gpe0_addr, x_gpe1_addr) = if total >= 244 {
        // GAS address is at byte offset 4 within the 12-byte GAS struct.
        let x0 = u64::from_le_bytes([
            body[220 + 4], body[220 + 5], body[220 + 6], body[220 + 7],
            body[220 + 8], body[220 + 9], body[220 + 10], body[220 + 11],
        ]);
        let x1 = u64::from_le_bytes([
            body[232 + 4], body[232 + 5], body[232 + 6], body[232 + 7],
            body[232 + 8], body[232 + 9], body[232 + 10], body[232 + 11],
        ]);
        (x0, x1)
    } else {
        (0, 0)
    };

    // ── choose best address ──────────────────────────────────────────
    let gpe0_addr = if x_gpe0_addr != 0 { x_gpe0_addr } else { legacy_gpe0_addr };
    let gpe1_addr = if x_gpe1_addr != 0 { x_gpe1_addr } else { legacy_gpe1_addr };

    if gpe0_addr != 0 && gpe0_len != 0 {
        *GPE0_BLOCK.lock() = Some(GpeBlockInfo {
            address:    gpe0_addr,
            byte_count: gpe0_len,
            base_gsi:   0,
        });
    }
    if gpe1_addr != 0 && gpe1_len != 0 {
        *GPE1_BLOCK.lock() = Some(GpeBlockInfo {
            address:    gpe1_addr,
            byte_count: gpe1_len,
            base_gsi:   gpe1_base,
        });
    }

    Ok(())
}

/// GPE0 block descriptor from the most recent `parse_gpe_blocks` call.
pub fn gpe0_block() -> Option<GpeBlockInfo> {
    *GPE0_BLOCK.lock()
}

/// GPE1 block descriptor from the most recent `parse_gpe_blocks` call.
pub fn gpe1_block() -> Option<GpeBlockInfo> {
    *GPE1_BLOCK.lock()
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

// ───────────────────────────────────────────────────────────────────
// PPTT — Processor Properties Topology Table.
// Spec: `acpi/specification/tables-iommu-topology.md` §1.
// ───────────────────────────────────────────────────────────────────

pub const MAX_PPTT_CPUS: usize = 256;
pub const MAX_PPTT_CACHES: usize = 256;

#[derive(Copy, Clone, Debug, Default)]
pub struct PpttCpu {
    pub acpi_uid: u32,
    pub package:  bool,
    pub thread:   bool,
    pub leaf:     bool,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct PpttCache {
    pub level:      u8,
    pub line_bytes: u16,
    pub ways:       u16,
    pub sets:       u32,
    pub size_bytes: u32,
    pub kind:       PpttCacheKind,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum PpttCacheKind {
    #[default]
    Unified,
    Data,
    Instruction,
}

struct PpttTables {
    cpus:    [PpttCpu; MAX_PPTT_CPUS],
    caches:  [PpttCache; MAX_PPTT_CACHES],
    n_cpus:  usize,
    n_caches:usize,
}

impl PpttTables {
    const EMPTY: Self = Self {
        cpus:    [PpttCpu { acpi_uid: 0, package: false, thread: false, leaf: false };
                  MAX_PPTT_CPUS],
        caches:  [PpttCache {
                      level: 0, line_bytes: 0, ways: 0, sets: 0,
                      size_bytes: 0, kind: PpttCacheKind::Unified
                  }; MAX_PPTT_CACHES],
        n_cpus:  0,
        n_caches:0,
    };
}

static PPTT_DATA:   IrqSafeSpinLock<PpttTables> = IrqSafeSpinLock::new(PpttTables::EMPTY);
static PPTT_PARSED: AtomicBool = AtomicBool::new(false);

/// Parse the PPTT body from `body[SDT_HEADER_SIZE..]` and populate
/// `PPTT_DATA`. The body content shape lets us run the parser on a
/// hand-crafted buffer for tests without touching firmware.
fn parse_pptt_body(body: &[u8]) -> u32 {
    let mut tables = PPTT_DATA.lock();
    *tables = PpttTables::EMPTY;
    let mut cur = SDT_HEADER_SIZE;
    let mut count = 0u32;
    while cur + 4 <= body.len() {
        let kind = body[cur];
        let len  = body[cur + 1] as usize;
        if len < 4 || cur + len > body.len() { break; }
        let entry = &body[cur..cur + len];

        match kind {
            0 if entry.len() >= 20 => {
                let flags = u32::from_le_bytes([
                    entry[4], entry[5], entry[6], entry[7],
                ]);
                let acpi_uid = u32::from_le_bytes([
                    entry[12], entry[13], entry[14], entry[15],
                ]);
                if tables.n_cpus < MAX_PPTT_CPUS {
                    let i = tables.n_cpus;
                    tables.cpus[i] = PpttCpu {
                        acpi_uid,
                        package: flags & (1 << 0) != 0,
                        thread:  flags & (1 << 2) != 0,
                        leaf:    flags & (1 << 3) != 0,
                    };
                    tables.n_cpus = i + 1;
                    count += 1;
                }
            }
            1 if entry.len() >= 24 => {
                let size = u32::from_le_bytes([
                    entry[12], entry[13], entry[14], entry[15],
                ]);
                let sets = u32::from_le_bytes([
                    entry[16], entry[17], entry[18], entry[19],
                ]);
                let assoc = entry[20] as u16;
                let attrs = entry[21];
                let line  = u16::from_le_bytes([entry[22], entry[23]]);
                let kind = match (attrs >> 2) & 0x3 {
                    1 => PpttCacheKind::Instruction,
                    0 => PpttCacheKind::Data,
                    _ => PpttCacheKind::Unified,
                };
                if tables.n_caches < MAX_PPTT_CACHES {
                    let i = tables.n_caches;
                    tables.caches[i] = PpttCache {
                        level: 0, // depth-from-leaf TBD; v0.1 leaves 0
                        line_bytes: line,
                        ways: assoc,
                        sets,
                        size_bytes: size,
                        kind,
                    };
                    tables.n_caches = i + 1;
                    count += 1;
                }
            }
            _ => {}
        }
        cur += len;
    }
    count
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → PPTT must also be identity-mapped.
pub unsafe fn parse_pptt(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut pptt: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"PPTT" && pptt.is_none() {
                pptt = Some(phys);
            }
        })?;
    }
    let pptt = pptt.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe {
        (pptt as *const SdtHeader).read_unaligned().length as usize
    };
    if total < SDT_HEADER_SIZE { return Err(AcpiError::BadXsdtSignature); }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(pptt as *const u8, total) };
    if checksum(body) != 0 { return Err(AcpiError::BadTableChecksum); }
    let n = parse_pptt_body(body);
    PPTT_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_pptt_known() -> bool { PPTT_PARSED.load(Ordering::Acquire) }

pub fn copy_pptt_cpus(out: &mut [PpttCpu]) -> usize {
    let t = PPTT_DATA.lock();
    let n = t.n_cpus.min(out.len());
    out[..n].copy_from_slice(&t.cpus[..n]);
    n
}

pub fn copy_pptt_caches(out: &mut [PpttCache]) -> usize {
    let t = PPTT_DATA.lock();
    let n = t.n_caches.min(out.len());
    out[..n].copy_from_slice(&t.caches[..n]);
    n
}

/// Test-only: parse a synthetic PPTT body without reading firmware.
#[doc(hidden)]
pub fn __test_parse_pptt_body(body: &[u8]) -> u32 {
    let n = parse_pptt_body(body);
    PPTT_PARSED.store(true, Ordering::Release);
    n
}

// ───────────────────────────────────────────────────────────────────
// IORT — IO Remap Table.
// Spec: `acpi/specification/tables-iommu-topology.md` §2.
// ───────────────────────────────────────────────────────────────────

pub const MAX_IORT_SMMUS: usize = 8;
pub const MAX_IORT_ITS:   usize = 8;

#[derive(Copy, Clone, Debug, Default)]
pub struct IortSmmuv3 {
    pub base:  u64,
    pub flags: u32,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct IortIts {
    pub its_id: u32,
}

struct IortTables {
    smmus:   [IortSmmuv3; MAX_IORT_SMMUS],
    its:     [IortIts;    MAX_IORT_ITS],
    n_smmus: usize,
    n_its:   usize,
}

impl IortTables {
    const EMPTY: Self = Self {
        smmus:   [IortSmmuv3 { base: 0, flags: 0 }; MAX_IORT_SMMUS],
        its:     [IortIts { its_id: 0 };           MAX_IORT_ITS],
        n_smmus: 0,
        n_its:   0,
    };
}

static IORT_DATA:   IrqSafeSpinLock<IortTables> = IrqSafeSpinLock::new(IortTables::EMPTY);
static IORT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_iort_body(body: &[u8]) -> u32 {
    let mut tables = IORT_DATA.lock();
    *tables = IortTables::EMPTY;

    if body.len() < SDT_HEADER_SIZE + 12 { return 0; }
    let n_nodes = u32::from_le_bytes([
        body[SDT_HEADER_SIZE], body[SDT_HEADER_SIZE + 1],
        body[SDT_HEADER_SIZE + 2], body[SDT_HEADER_SIZE + 3],
    ]) as usize;
    let arr_off = u32::from_le_bytes([
        body[SDT_HEADER_SIZE + 4], body[SDT_HEADER_SIZE + 5],
        body[SDT_HEADER_SIZE + 6], body[SDT_HEADER_SIZE + 7],
    ]) as usize;

    let mut cur = arr_off;
    let mut count = 0u32;
    for _ in 0..n_nodes {
        if cur + 4 > body.len() { break; }
        let kind = body[cur];
        let len = u16::from_le_bytes([body[cur + 1], body[cur + 2]]) as usize;
        if len < 4 || cur + len > body.len() { break; }
        let entry = &body[cur..cur + len];

        match kind {
            0 if entry.len() >= 20 => {
                // ITS group: header (16 B) + ITS-id count (4 B) + ids[]
                let n = u32::from_le_bytes([
                    entry[16], entry[17], entry[18], entry[19],
                ]) as usize;
                let mut off = 20;
                for _ in 0..n {
                    if off + 4 > entry.len() { break; }
                    let id = u32::from_le_bytes([
                        entry[off], entry[off + 1], entry[off + 2], entry[off + 3],
                    ]);
                    if tables.n_its < MAX_IORT_ITS {
                        let i = tables.n_its;
                        tables.its[i] = IortIts { its_id: id };
                        tables.n_its = i + 1;
                        count += 1;
                    }
                    off += 4;
                }
            }
            4 if entry.len() >= 36 => {
                // SMMUv3: header (16 B) + base@16..24 + flags@24..28
                let base = u64::from_le_bytes([
                    entry[16], entry[17], entry[18], entry[19],
                    entry[20], entry[21], entry[22], entry[23],
                ]);
                let flags = u32::from_le_bytes([
                    entry[24], entry[25], entry[26], entry[27],
                ]);
                if tables.n_smmus < MAX_IORT_SMMUS {
                    let i = tables.n_smmus;
                    tables.smmus[i] = IortSmmuv3 { base, flags };
                    tables.n_smmus = i + 1;
                    count += 1;
                }
            }
            _ => {}
        }
        cur += len;
    }
    count
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → IORT must also be identity-mapped.
pub unsafe fn parse_iort(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut iort: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"IORT" && iort.is_none() {
                iort = Some(phys);
            }
        })?;
    }
    let iort = iort.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe {
        (iort as *const SdtHeader).read_unaligned().length as usize
    };
    if total < SDT_HEADER_SIZE + 12 { return Err(AcpiError::BadXsdtSignature); }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(iort as *const u8, total) };
    if checksum(body) != 0 { return Err(AcpiError::BadTableChecksum); }
    let n = parse_iort_body(body);
    IORT_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_iort_known() -> bool { IORT_PARSED.load(Ordering::Acquire) }

pub fn copy_iort_smmuv3(out: &mut [IortSmmuv3]) -> usize {
    let t = IORT_DATA.lock();
    let n = t.n_smmus.min(out.len());
    out[..n].copy_from_slice(&t.smmus[..n]);
    n
}

pub fn copy_iort_its(out: &mut [IortIts]) -> usize {
    let t = IORT_DATA.lock();
    let n = t.n_its.min(out.len());
    out[..n].copy_from_slice(&t.its[..n]);
    n
}

#[doc(hidden)]
pub fn __test_parse_iort_body(body: &[u8]) -> u32 {
    let n = parse_iort_body(body);
    IORT_PARSED.store(true, Ordering::Release);
    n
}

// ───────────────────────────────────────────────────────────────────
// DMAR — DMA Remap Reporting.
// Spec: `acpi/specification/tables-iommu-topology.md` §3.
// ───────────────────────────────────────────────────────────────────

pub const MAX_DMAR_DRHDS: usize = 8;

const DMAR_FLAG_INTR_REMAP: u8 = 1 << 0;

#[derive(Copy, Clone, Debug, Default)]
pub struct DmarDrhd {
    pub register_base:   u64,
    pub segment:         u16,
    pub include_all_pci: bool,
}

struct DmarTables {
    drhds:    [DmarDrhd; MAX_DMAR_DRHDS],
    n_drhds:  usize,
    intr_rmp: bool,
}

impl DmarTables {
    const EMPTY: Self = Self {
        drhds:    [DmarDrhd { register_base: 0, segment: 0, include_all_pci: false };
                   MAX_DMAR_DRHDS],
        n_drhds:  0,
        intr_rmp: false,
    };
}

static DMAR_DATA:   IrqSafeSpinLock<DmarTables> = IrqSafeSpinLock::new(DmarTables::EMPTY);
static DMAR_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_dmar_body(body: &[u8]) -> u32 {
    let mut tables = DMAR_DATA.lock();
    *tables = DmarTables::EMPTY;
    if body.len() < SDT_HEADER_SIZE + 12 { return 0; }
    tables.intr_rmp = body[SDT_HEADER_SIZE + 1] & DMAR_FLAG_INTR_REMAP != 0;
    let mut cur = SDT_HEADER_SIZE + 12;
    let mut count = 0u32;
    while cur + 4 <= body.len() {
        let kind = u16::from_le_bytes([body[cur], body[cur + 1]]);
        let len  = u16::from_le_bytes([body[cur + 2], body[cur + 3]]) as usize;
        if len < 4 || cur + len > body.len() { break; }
        let entry = &body[cur..cur + len];

        if kind == 0 && entry.len() >= 16 {
            // DRHD: [4] flags, [5] reserved, [6..8] segment, [8..16] base
            let flags = entry[4];
            let segment = u16::from_le_bytes([entry[6], entry[7]]);
            let base = u64::from_le_bytes([
                entry[8],  entry[9],  entry[10], entry[11],
                entry[12], entry[13], entry[14], entry[15],
            ]);
            if tables.n_drhds < MAX_DMAR_DRHDS {
                let i = tables.n_drhds;
                tables.drhds[i] = DmarDrhd {
                    register_base: base,
                    segment,
                    include_all_pci: flags & 1 != 0,
                };
                tables.n_drhds = i + 1;
                count += 1;
            }
        }
        cur += len;
    }
    count
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → DMAR must also be identity-mapped.
pub unsafe fn parse_dmar(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut dmar: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"DMAR" && dmar.is_none() {
                dmar = Some(phys);
            }
        })?;
    }
    let dmar = dmar.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe {
        (dmar as *const SdtHeader).read_unaligned().length as usize
    };
    if total < SDT_HEADER_SIZE + 12 { return Err(AcpiError::BadXsdtSignature); }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(dmar as *const u8, total) };
    if checksum(body) != 0 { return Err(AcpiError::BadTableChecksum); }
    let n = parse_dmar_body(body);
    DMAR_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_dmar_known() -> bool { DMAR_PARSED.load(Ordering::Acquire) }

pub fn copy_dmar_drhds(out: &mut [DmarDrhd]) -> usize {
    let t = DMAR_DATA.lock();
    let n = t.n_drhds.min(out.len());
    out[..n].copy_from_slice(&t.drhds[..n]);
    n
}

pub fn dmar_intr_remap_supported() -> bool {
    DMAR_DATA.lock().intr_rmp
}

#[doc(hidden)]
pub fn __test_parse_dmar_body(body: &[u8]) -> u32 {
    let n = parse_dmar_body(body);
    DMAR_PARSED.store(true, Ordering::Release);
    n
}

// ───────────────────────────────────────────────────────────────────
// IVRS — I/O Virtualization Reporting.
// Spec: `acpi/specification/tables-iommu-topology.md` §4.
// ───────────────────────────────────────────────────────────────────

pub const MAX_IVRS_IOMMUS: usize = 8;

#[derive(Copy, Clone, Debug, Default)]
pub struct IvrsIommu {
    pub base:           u64,
    pub pci_segment:    u16,
    pub capability_off: u16,
}

struct IvrsTables {
    iommus:   [IvrsIommu; MAX_IVRS_IOMMUS],
    n_iommus: usize,
}

impl IvrsTables {
    const EMPTY: Self = Self {
        iommus:   [IvrsIommu { base: 0, pci_segment: 0, capability_off: 0 };
                   MAX_IVRS_IOMMUS],
        n_iommus: 0,
    };
}

static IVRS_DATA:   IrqSafeSpinLock<IvrsTables> = IrqSafeSpinLock::new(IvrsTables::EMPTY);
static IVRS_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_ivrs_body(body: &[u8]) -> u32 {
    let mut tables = IVRS_DATA.lock();
    *tables = IvrsTables::EMPTY;
    // Header: SDT_HEADER (36) + IvInfo (4) + reserved (8) = 48
    if body.len() < SDT_HEADER_SIZE + 12 { return 0; }
    let mut cur = SDT_HEADER_SIZE + 12;
    let mut count = 0u32;
    while cur + 4 <= body.len() {
        let kind = body[cur];
        let _flags = body[cur + 1];
        let len = u16::from_le_bytes([body[cur + 2], body[cur + 3]]) as usize;
        if len < 4 || cur + len > body.len() { break; }
        let entry = &body[cur..cur + len];

        // IVHD types 0x10 / 0x11 / 0x40
        if matches!(kind, 0x10 | 0x11 | 0x40) && entry.len() >= 24 {
            // device_id at [4..6], cap_off at [6..8], base at [8..16],
            // segment at [16..18]
            let cap_off = u16::from_le_bytes([entry[6], entry[7]]);
            let base = u64::from_le_bytes([
                entry[8],  entry[9],  entry[10], entry[11],
                entry[12], entry[13], entry[14], entry[15],
            ]);
            let segment = u16::from_le_bytes([entry[16], entry[17]]);
            if tables.n_iommus < MAX_IVRS_IOMMUS {
                let i = tables.n_iommus;
                tables.iommus[i] = IvrsIommu {
                    base, pci_segment: segment, capability_off: cap_off,
                };
                tables.n_iommus = i + 1;
                count += 1;
            }
        }
        cur += len;
    }
    count
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → IVRS must also be identity-mapped.
pub unsafe fn parse_ivrs(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut ivrs: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"IVRS" && ivrs.is_none() {
                ivrs = Some(phys);
            }
        })?;
    }
    let ivrs = ivrs.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe {
        (ivrs as *const SdtHeader).read_unaligned().length as usize
    };
    if total < SDT_HEADER_SIZE + 12 { return Err(AcpiError::BadXsdtSignature); }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(ivrs as *const u8, total) };
    if checksum(body) != 0 { return Err(AcpiError::BadTableChecksum); }
    let n = parse_ivrs_body(body);
    IVRS_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_ivrs_known() -> bool { IVRS_PARSED.load(Ordering::Acquire) }

pub fn copy_ivrs_iommus(out: &mut [IvrsIommu]) -> usize {
    let t = IVRS_DATA.lock();
    let n = t.n_iommus.min(out.len());
    out[..n].copy_from_slice(&t.iommus[..n]);
    n
}

#[doc(hidden)]
pub fn __test_parse_ivrs_body(body: &[u8]) -> u32 {
    let n = parse_ivrs_body(body);
    IVRS_PARSED.store(true, Ordering::Release);
    n
}

// ───────────────────────────────────────────────────────────────────
// SPCR — Serial Port Console Redirection.
// Spec: `acpi/specification/tables-iommu-topology.md` §5.
// ───────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct SpcrInfo {
    pub iface:         u8,
    pub base:          u64,
    pub addr_space_id: u8,
    pub gsi:           u32,
    pub baud_code:     u8,
    pub pci_device_id: u16,
}

static SPCR_DATA:   IrqSafeSpinLock<SpcrInfo> = IrqSafeSpinLock::new(SpcrInfo {
    iface: 0, base: 0, addr_space_id: 0, gsi: 0, baud_code: 0, pci_device_id: 0,
});
static SPCR_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_spcr_body(body: &[u8]) {
    // SPCR rev 4 layout: SDT_HEADER (36) + InterfaceType (1) +
    // Reserved (3) + GAS (12) + InterruptType (1) + IRQ (1) +
    // GSI (4) + BaudRate (1) + Parity (1) + StopBits (1) +
    // FlowControl (1) + TerminalType (1) + Language (1) +
    // PciDeviceId (2) + …
    if body.len() < SDT_HEADER_SIZE + 36 { return; }
    let iface         = body[SDT_HEADER_SIZE];
    let addr_space_id = body[SDT_HEADER_SIZE + 4];
    let base = u64::from_le_bytes([
        body[SDT_HEADER_SIZE + 8],  body[SDT_HEADER_SIZE + 9],
        body[SDT_HEADER_SIZE + 10], body[SDT_HEADER_SIZE + 11],
        body[SDT_HEADER_SIZE + 12], body[SDT_HEADER_SIZE + 13],
        body[SDT_HEADER_SIZE + 14], body[SDT_HEADER_SIZE + 15],
    ]);
    let gsi = u32::from_le_bytes([
        body[SDT_HEADER_SIZE + 18], body[SDT_HEADER_SIZE + 19],
        body[SDT_HEADER_SIZE + 20], body[SDT_HEADER_SIZE + 21],
    ]);
    let baud_code     = body[SDT_HEADER_SIZE + 22];
    let pci_device_id = u16::from_le_bytes([
        body[SDT_HEADER_SIZE + 28], body[SDT_HEADER_SIZE + 29],
    ]);
    *SPCR_DATA.lock() = SpcrInfo {
        iface, base, addr_space_id, gsi, baud_code, pci_device_id,
    };
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → SPCR must also be identity-mapped.
pub unsafe fn parse_spcr(rsdp_phys: PhysAddr) -> Result<(), AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut spcr: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"SPCR" && spcr.is_none() {
                spcr = Some(phys);
            }
        })?;
    }
    let spcr = spcr.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe {
        (spcr as *const SdtHeader).read_unaligned().length as usize
    };
    if total < SDT_HEADER_SIZE + 36 { return Err(AcpiError::BadXsdtSignature); }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(spcr as *const u8, total) };
    if checksum(body) != 0 { return Err(AcpiError::BadTableChecksum); }
    parse_spcr_body(body);
    SPCR_PARSED.store(true, Ordering::Release);
    Ok(())
}

pub fn spcr_info() -> Option<SpcrInfo> {
    if !SPCR_PARSED.load(Ordering::Acquire) { return None; }
    Some(*SPCR_DATA.lock())
}

#[doc(hidden)]
pub fn __test_parse_spcr_body(body: &[u8]) {
    parse_spcr_body(body);
    SPCR_PARSED.store(true, Ordering::Release);
}

// ───────────────────────────────────────────────────────────────────
// HEST — Hardware Error Source Table.
// Spec: `acpi/specification/tables-ras-cxl-locality.md` §1.
// ───────────────────────────────────────────────────────────────────

pub const MAX_HEST_MCE:  usize = 16;
pub const MAX_HEST_GHES: usize = 16;

#[derive(Copy, Clone, Debug, Default)]
pub struct HestMceSource {
    pub source_id:         u16,
    pub enabled:           bool,
    pub num_hw_banks:      u8,
    pub global_capability: u64,
    pub global_control:    u64,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct HestGhesSource {
    pub source_id:               u16,
    pub enabled:                 bool,
    pub max_sections_per_record: u32,
    pub error_status_block_addr: u64,
}

struct HestTables {
    mce:    [HestMceSource; MAX_HEST_MCE],
    ghes:   [HestGhesSource; MAX_HEST_GHES],
    n_mce:  usize,
    n_ghes: usize,
}

impl HestTables {
    const EMPTY: Self = Self {
        mce:    [HestMceSource {
                    source_id: 0, enabled: false, num_hw_banks: 0,
                    global_capability: 0, global_control: 0
                }; MAX_HEST_MCE],
        ghes:   [HestGhesSource {
                    source_id: 0, enabled: false,
                    max_sections_per_record: 0, error_status_block_addr: 0
                }; MAX_HEST_GHES],
        n_mce:  0,
        n_ghes: 0,
    };
}

static HEST_DATA:   IrqSafeSpinLock<HestTables> = IrqSafeSpinLock::new(HestTables::EMPTY);
static HEST_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_hest_body(body: &[u8]) -> u32 {
    let mut tables = HEST_DATA.lock();
    *tables = HestTables::EMPTY;
    if body.len() < SDT_HEADER_SIZE + 4 { return 0; }
    let n_sources = u32::from_le_bytes([
        body[SDT_HEADER_SIZE],     body[SDT_HEADER_SIZE + 1],
        body[SDT_HEADER_SIZE + 2], body[SDT_HEADER_SIZE + 3],
    ]) as usize;

    let mut cur = SDT_HEADER_SIZE + 4;
    let mut count = 0u32;
    for _ in 0..n_sources {
        if cur + 2 > body.len() { break; }
        let kind = u16::from_le_bytes([body[cur], body[cur + 1]]);

        match kind {
            // Type 0: Machine Check.
            0 if cur + 92 <= body.len() => {
                let source_id = u16::from_le_bytes([body[cur + 2], body[cur + 3]]);
                let enabled = body[cur + 7] != 0;
                let global_capability = u64::from_le_bytes([
                    body[cur + 16], body[cur + 17], body[cur + 18], body[cur + 19],
                    body[cur + 20], body[cur + 21], body[cur + 22], body[cur + 23],
                ]);
                let global_control = u64::from_le_bytes([
                    body[cur + 24], body[cur + 25], body[cur + 26], body[cur + 27],
                    body[cur + 28], body[cur + 29], body[cur + 30], body[cur + 31],
                ]);
                let num_hw_banks = body[cur + 32];
                if tables.n_mce < MAX_HEST_MCE {
                    let i = tables.n_mce;
                    tables.mce[i] = HestMceSource {
                        source_id, enabled, num_hw_banks,
                        global_capability, global_control,
                    };
                    tables.n_mce = i + 1;
                    count += 1;
                }
                cur += 40 + 28 * num_hw_banks as usize;
            }
            // Type 9 / 10: GHES / GHESv2.
            9 | 10 if cur + 92 <= body.len() => {
                let source_id = u16::from_le_bytes([body[cur + 2], body[cur + 3]]);
                let enabled = body[cur + 7] != 0;
                let max_sections_per_record = u32::from_le_bytes([
                    body[cur + 12], body[cur + 13], body[cur + 14], body[cur + 15],
                ]);
                // GAS.Address at offset cur + 24..32 of the GHES entry.
                let err_addr = u64::from_le_bytes([
                    body[cur + 24], body[cur + 25], body[cur + 26], body[cur + 27],
                    body[cur + 28], body[cur + 29], body[cur + 30], body[cur + 31],
                ]);
                if tables.n_ghes < MAX_HEST_GHES {
                    let i = tables.n_ghes;
                    tables.ghes[i] = HestGhesSource {
                        source_id, enabled, max_sections_per_record,
                        error_status_block_addr: err_addr,
                    };
                    tables.n_ghes = i + 1;
                    count += 1;
                }
                cur += if kind == 9 { 92 } else { 92 + 8 };
            }
            _ => break,   // unknown type — bail rather than misparse the rest
        }
    }
    count
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → HEST must also be identity-mapped.
pub unsafe fn parse_hest(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut hest: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"HEST" && hest.is_none() {
                hest = Some(phys);
            }
        })?;
    }
    let hest = hest.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe {
        (hest as *const SdtHeader).read_unaligned().length as usize
    };
    if total < SDT_HEADER_SIZE + 4 { return Err(AcpiError::BadXsdtSignature); }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(hest as *const u8, total) };
    if checksum(body) != 0 { return Err(AcpiError::BadTableChecksum); }
    let n = parse_hest_body(body);
    HEST_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_hest_known() -> bool { HEST_PARSED.load(Ordering::Acquire) }

pub fn copy_hest_mce(out: &mut [HestMceSource]) -> usize {
    let t = HEST_DATA.lock();
    let n = t.n_mce.min(out.len());
    out[..n].copy_from_slice(&t.mce[..n]);
    n
}

pub fn copy_hest_ghes(out: &mut [HestGhesSource]) -> usize {
    let t = HEST_DATA.lock();
    let n = t.n_ghes.min(out.len());
    out[..n].copy_from_slice(&t.ghes[..n]);
    n
}

#[doc(hidden)]
pub fn __test_parse_hest_body(body: &[u8]) -> u32 {
    let n = parse_hest_body(body);
    HEST_PARSED.store(true, Ordering::Release);
    n
}

// ───────────────────────────────────────────────────────────────────
// PCCT — Platform Communication Channels Table.
// Spec: `acpi/specification/tables-ras-cxl-locality.md` §2.
// ───────────────────────────────────────────────────────────────────

pub const MAX_PCCT_CHANNELS: usize = 16;

#[derive(Copy, Clone, Debug, Default)]
pub struct PcctChannel {
    pub kind:              u8,
    pub shmem_base:        u64,
    pub shmem_length:      u64,
    pub doorbell_addr:     u64,
    pub doorbell_write:    u64,
    pub min_turnaround_us: u16,
}

struct PcctTables {
    chans:    [PcctChannel; MAX_PCCT_CHANNELS],
    n_chans:  usize,
}

impl PcctTables {
    const EMPTY: Self = Self {
        chans:    [PcctChannel {
                      kind: 0, shmem_base: 0, shmem_length: 0,
                      doorbell_addr: 0, doorbell_write: 0,
                      min_turnaround_us: 0,
                  }; MAX_PCCT_CHANNELS],
        n_chans:  0,
    };
}

static PCCT_DATA:   IrqSafeSpinLock<PcctTables> = IrqSafeSpinLock::new(PcctTables::EMPTY);
static PCCT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_pcct_body(body: &[u8]) -> u32 {
    let mut tables = PCCT_DATA.lock();
    *tables = PcctTables::EMPTY;
    if body.len() < SDT_HEADER_SIZE + 12 { return 0; }
    let mut cur = SDT_HEADER_SIZE + 12;
    let mut count = 0u32;
    while cur + 2 <= body.len() {
        let kind = body[cur];
        let len = body[cur + 1] as usize;
        if len < 2 || cur + len > body.len() { break; }
        let entry = &body[cur..cur + len];

        if matches!(kind, 0 | 1 | 2) && entry.len() >= 62 {
            // Generic PCCT channel layout (offsets within entry):
            //   8..16  = BaseAddress
            //   16..24 = Length
            //   24..36 = DoorbellRegister GAS (Address @ +28..36)
            //   36..44 = DoorbellPreserve
            //   44..52 = DoorbellWrite
            //   52..56 = NominalLatency_us
            //   56..60 = MaxPeriodicAccessRate
            //   60..62 = MinRequestTurnaround_us
            let shmem_base = u64::from_le_bytes([
                entry[8],  entry[9],  entry[10], entry[11],
                entry[12], entry[13], entry[14], entry[15],
            ]);
            let shmem_length = u64::from_le_bytes([
                entry[16], entry[17], entry[18], entry[19],
                entry[20], entry[21], entry[22], entry[23],
            ]);
            let doorbell_addr = u64::from_le_bytes([
                entry[28], entry[29], entry[30], entry[31],
                entry[32], entry[33], entry[34], entry[35],
            ]);
            let doorbell_write = u64::from_le_bytes([
                entry[44], entry[45], entry[46], entry[47],
                entry[48], entry[49], entry[50], entry[51],
            ]);
            let min_turnaround_us = u16::from_le_bytes([entry[60], entry[61]]);
            if tables.n_chans < MAX_PCCT_CHANNELS {
                let i = tables.n_chans;
                tables.chans[i] = PcctChannel {
                    kind, shmem_base, shmem_length,
                    doorbell_addr, doorbell_write, min_turnaround_us,
                };
                tables.n_chans = i + 1;
                count += 1;
            }
        }
        cur += len;
    }
    count
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → PCCT must also be identity-mapped.
pub unsafe fn parse_pcct(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut pcct: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"PCCT" && pcct.is_none() {
                pcct = Some(phys);
            }
        })?;
    }
    let pcct = pcct.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe {
        (pcct as *const SdtHeader).read_unaligned().length as usize
    };
    if total < SDT_HEADER_SIZE + 12 { return Err(AcpiError::BadXsdtSignature); }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(pcct as *const u8, total) };
    if checksum(body) != 0 { return Err(AcpiError::BadTableChecksum); }
    let n = parse_pcct_body(body);
    PCCT_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_pcct_known() -> bool { PCCT_PARSED.load(Ordering::Acquire) }

pub fn copy_pcct_channels(out: &mut [PcctChannel]) -> usize {
    let t = PCCT_DATA.lock();
    let n = t.n_chans.min(out.len());
    out[..n].copy_from_slice(&t.chans[..n]);
    n
}

#[doc(hidden)]
pub fn __test_parse_pcct_body(body: &[u8]) -> u32 {
    let n = parse_pcct_body(body);
    PCCT_PARSED.store(true, Ordering::Release);
    n
}

// ───────────────────────────────────────────────────────────────────
// SLIT — System Locality Information Table.
// Spec: `acpi/specification/tables-ras-cxl-locality.md` §3.
// ───────────────────────────────────────────────────────────────────

pub const MAX_SLIT_NODES: usize = 16;

struct SlitTables {
    locality_count: u32,
    matrix:         [[u8; MAX_SLIT_NODES]; MAX_SLIT_NODES],
}

impl SlitTables {
    const EMPTY: Self = Self {
        locality_count: 0,
        matrix:         [[0u8; MAX_SLIT_NODES]; MAX_SLIT_NODES],
    };
}

static SLIT_DATA:   IrqSafeSpinLock<SlitTables> = IrqSafeSpinLock::new(SlitTables::EMPTY);
static SLIT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_slit_body(body: &[u8]) -> u32 {
    let mut tables = SLIT_DATA.lock();
    *tables = SlitTables::EMPTY;
    if body.len() < SDT_HEADER_SIZE + 8 { return 0; }
    let n = u64::from_le_bytes([
        body[SDT_HEADER_SIZE],     body[SDT_HEADER_SIZE + 1],
        body[SDT_HEADER_SIZE + 2], body[SDT_HEADER_SIZE + 3],
        body[SDT_HEADER_SIZE + 4], body[SDT_HEADER_SIZE + 5],
        body[SDT_HEADER_SIZE + 6], body[SDT_HEADER_SIZE + 7],
    ]) as usize;
    let n = n.min(MAX_SLIT_NODES);
    if body.len() < SDT_HEADER_SIZE + 8 + n * n { return 0; }
    let mut off = SDT_HEADER_SIZE + 8;
    for i in 0..n {
        for j in 0..n {
            tables.matrix[i][j] = body[off];
            off += 1;
        }
    }
    tables.locality_count = n as u32;
    n as u32
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → SLIT must also be identity-mapped.
pub unsafe fn parse_slit(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut slit: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"SLIT" && slit.is_none() {
                slit = Some(phys);
            }
        })?;
    }
    let slit = slit.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe {
        (slit as *const SdtHeader).read_unaligned().length as usize
    };
    if total < SDT_HEADER_SIZE + 8 { return Err(AcpiError::BadXsdtSignature); }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(slit as *const u8, total) };
    if checksum(body) != 0 { return Err(AcpiError::BadTableChecksum); }
    let n = parse_slit_body(body);
    SLIT_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_slit_known() -> bool { SLIT_PARSED.load(Ordering::Acquire) }

pub fn slit_distance(from: u8, to: u8) -> Option<u8> {
    if !is_slit_known() { return None; }
    let t = SLIT_DATA.lock();
    if (from as u32) >= t.locality_count || (to as u32) >= t.locality_count {
        return None;
    }
    Some(t.matrix[from as usize][to as usize])
}

pub fn slit_locality_count() -> u32 {
    SLIT_DATA.lock().locality_count
}

#[doc(hidden)]
pub fn __test_parse_slit_body(body: &[u8]) -> u32 {
    let n = parse_slit_body(body);
    SLIT_PARSED.store(true, Ordering::Release);
    n
}

// ───────────────────────────────────────────────────────────────────
// CEDT — CXL Early Discovery Table.
// Spec: `acpi/specification/tables-ras-cxl-locality.md` §4.
// ───────────────────────────────────────────────────────────────────

pub const MAX_CEDT_CHBS:  usize = 8;
pub const MAX_CEDT_CFMWS: usize = 8;

#[derive(Copy, Clone, Debug, Default)]
pub struct CedtChbs {
    pub uid:     u32,
    pub cxl_ver: u32,
    pub base:    u64,
    pub length:  u64,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct CedtCfmws {
    pub base_hpa:    u64,
    pub window_size: u64,
    pub encoded_iw:  u8,
}

struct CedtTables {
    chbs:    [CedtChbs;  MAX_CEDT_CHBS],
    cfmws:   [CedtCfmws; MAX_CEDT_CFMWS],
    n_chbs:  usize,
    n_cfmws: usize,
}

impl CedtTables {
    const EMPTY: Self = Self {
        chbs:    [CedtChbs { uid: 0, cxl_ver: 0, base: 0, length: 0 };
                  MAX_CEDT_CHBS],
        cfmws:   [CedtCfmws { base_hpa: 0, window_size: 0, encoded_iw: 0 };
                  MAX_CEDT_CFMWS],
        n_chbs:  0,
        n_cfmws: 0,
    };
}

static CEDT_DATA:   IrqSafeSpinLock<CedtTables> = IrqSafeSpinLock::new(CedtTables::EMPTY);
static CEDT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_cedt_body(body: &[u8]) -> u32 {
    let mut tables = CEDT_DATA.lock();
    *tables = CedtTables::EMPTY;
    let mut cur = SDT_HEADER_SIZE;
    let mut count = 0u32;
    while cur + 4 <= body.len() {
        let kind = body[cur];
        let len = u16::from_le_bytes([body[cur + 2], body[cur + 3]]) as usize;
        if len < 4 || cur + len > body.len() { break; }
        let entry = &body[cur..cur + len];

        match kind {
            // CHBS — CXL Host Bridge Structure (length 32).
            0 if entry.len() >= 32 => {
                let uid = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
                let cxl_ver = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
                let base = u64::from_le_bytes([
                    entry[16], entry[17], entry[18], entry[19],
                    entry[20], entry[21], entry[22], entry[23],
                ]);
                let length = u64::from_le_bytes([
                    entry[24], entry[25], entry[26], entry[27],
                    entry[28], entry[29], entry[30], entry[31],
                ]);
                if tables.n_chbs < MAX_CEDT_CHBS {
                    let i = tables.n_chbs;
                    tables.chbs[i] = CedtChbs { uid, cxl_ver, base, length };
                    tables.n_chbs = i + 1;
                    count += 1;
                }
            }
            // CFMWS — CXL Fixed Memory Window (variable length, ≥36).
            1 if entry.len() >= 36 => {
                let base_hpa = u64::from_le_bytes([
                    entry[8],  entry[9],  entry[10], entry[11],
                    entry[12], entry[13], entry[14], entry[15],
                ]);
                let window_size = u64::from_le_bytes([
                    entry[16], entry[17], entry[18], entry[19],
                    entry[20], entry[21], entry[22], entry[23],
                ]);
                let encoded_iw = entry[24];
                if tables.n_cfmws < MAX_CEDT_CFMWS {
                    let i = tables.n_cfmws;
                    tables.cfmws[i] = CedtCfmws {
                        base_hpa, window_size, encoded_iw,
                    };
                    tables.n_cfmws = i + 1;
                    count += 1;
                }
            }
            _ => {}
        }
        cur += len;
    }
    count
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → CEDT must also be identity-mapped.
pub unsafe fn parse_cedt(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut cedt: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"CEDT" && cedt.is_none() {
                cedt = Some(phys);
            }
        })?;
    }
    let cedt = cedt.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe {
        (cedt as *const SdtHeader).read_unaligned().length as usize
    };
    if total < SDT_HEADER_SIZE { return Err(AcpiError::BadXsdtSignature); }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(cedt as *const u8, total) };
    if checksum(body) != 0 { return Err(AcpiError::BadTableChecksum); }
    let n = parse_cedt_body(body);
    CEDT_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_cedt_known() -> bool { CEDT_PARSED.load(Ordering::Acquire) }

pub fn copy_cedt_chbs(out: &mut [CedtChbs]) -> usize {
    let t = CEDT_DATA.lock();
    let n = t.n_chbs.min(out.len());
    out[..n].copy_from_slice(&t.chbs[..n]);
    n
}

pub fn copy_cedt_cfmws(out: &mut [CedtCfmws]) -> usize {
    let t = CEDT_DATA.lock();
    let n = t.n_cfmws.min(out.len());
    out[..n].copy_from_slice(&t.cfmws[..n]);
    n
}

#[doc(hidden)]
pub fn __test_parse_cedt_body(body: &[u8]) -> u32 {
    let n = parse_cedt_body(body);
    CEDT_PARSED.store(true, Ordering::Release);
    n
}

// ───────────────────────────────────────────────────────────────────
// BERT — Boot Error Record Table.
// Spec: `acpi/specification/tables-ras-cxl-locality.md` §5.
// ───────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct BertInfo {
    pub region_addr:   u64,
    pub region_length: u32,
}

static BERT_DATA: IrqSafeSpinLock<BertInfo> = IrqSafeSpinLock::new(BertInfo {
    region_addr: 0, region_length: 0,
});
static BERT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_bert_body(body: &[u8]) {
    if body.len() < SDT_HEADER_SIZE + 12 { return; }
    let region_length = u32::from_le_bytes([
        body[SDT_HEADER_SIZE],     body[SDT_HEADER_SIZE + 1],
        body[SDT_HEADER_SIZE + 2], body[SDT_HEADER_SIZE + 3],
    ]);
    let region_addr = u64::from_le_bytes([
        body[SDT_HEADER_SIZE + 4],  body[SDT_HEADER_SIZE + 5],
        body[SDT_HEADER_SIZE + 6],  body[SDT_HEADER_SIZE + 7],
        body[SDT_HEADER_SIZE + 8],  body[SDT_HEADER_SIZE + 9],
        body[SDT_HEADER_SIZE + 10], body[SDT_HEADER_SIZE + 11],
    ]);
    *BERT_DATA.lock() = BertInfo { region_addr, region_length };
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → BERT must also be identity-mapped.
pub unsafe fn parse_bert(rsdp_phys: PhysAddr) -> Result<(), AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut bert: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"BERT" && bert.is_none() {
                bert = Some(phys);
            }
        })?;
    }
    let bert = bert.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe {
        (bert as *const SdtHeader).read_unaligned().length as usize
    };
    if total < SDT_HEADER_SIZE + 12 { return Err(AcpiError::BadXsdtSignature); }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(bert as *const u8, total) };
    if checksum(body) != 0 { return Err(AcpiError::BadTableChecksum); }
    parse_bert_body(body);
    BERT_PARSED.store(true, Ordering::Release);
    Ok(())
}

pub fn bert_info() -> Option<BertInfo> {
    if !BERT_PARSED.load(Ordering::Acquire) { return None; }
    Some(*BERT_DATA.lock())
}

#[doc(hidden)]
pub fn __test_parse_bert_body(body: &[u8]) {
    parse_bert_body(body);
    BERT_PARSED.store(true, Ordering::Release);
}

// ───────────────────────────────────────────────────────────────────
// AEST — Arm Error Source Table.
// Spec: `acpi/specification/tables-arm-ras-power-pm.md` §1.
// ───────────────────────────────────────────────────────────────────

pub const MAX_AEST_NODES: usize = 16;

#[derive(Copy, Clone, Debug, Default)]
pub struct AestNode {
    pub kind:  u8,
    pub iface: u8,
    pub base:  u64,
}

struct AestTables {
    nodes:   [AestNode; MAX_AEST_NODES],
    n_nodes: usize,
}

impl AestTables {
    const EMPTY: Self = Self {
        nodes:   [AestNode { kind: 0, iface: 0, base: 0 }; MAX_AEST_NODES],
        n_nodes: 0,
    };
}

static AEST_DATA:   IrqSafeSpinLock<AestTables> = IrqSafeSpinLock::new(AestTables::EMPTY);
static AEST_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_aest_body(body: &[u8]) -> u32 {
    let mut tables = AEST_DATA.lock();
    *tables = AestTables::EMPTY;
    let mut cur = SDT_HEADER_SIZE;
    let mut count = 0u32;
    while cur + 12 <= body.len() {
        let kind = body[cur];
        let len = u16::from_le_bytes([body[cur + 2], body[cur + 3]]) as usize;
        if len < 12 || cur + len > body.len() { break; }
        let entry = &body[cur..cur + len];
        let iface_off = u32::from_le_bytes([
            entry[12], entry[13], entry[14], entry[15],
        ]) as usize;
        // Interface block: [0] = Type (0 = SR, 1 = MMIO),
        //                  [4..12] = BaseAddress (for MMIO).
        if iface_off + 12 <= entry.len() {
            let iface = entry[iface_off];
            let base = u64::from_le_bytes([
                entry[iface_off + 4], entry[iface_off + 5],
                entry[iface_off + 6], entry[iface_off + 7],
                entry[iface_off + 8], entry[iface_off + 9],
                entry[iface_off + 10], entry[iface_off + 11],
            ]);
            if tables.n_nodes < MAX_AEST_NODES {
                let i = tables.n_nodes;
                tables.nodes[i] = AestNode { kind, iface, base };
                tables.n_nodes = i + 1;
                count += 1;
            }
        }
        cur += len;
    }
    count
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → AEST must also be identity-mapped.
pub unsafe fn parse_aest(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut aest: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"AEST" && aest.is_none() {
                aest = Some(phys);
            }
        })?;
    }
    let aest = aest.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe {
        (aest as *const SdtHeader).read_unaligned().length as usize
    };
    if total < SDT_HEADER_SIZE { return Err(AcpiError::BadXsdtSignature); }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(aest as *const u8, total) };
    if checksum(body) != 0 { return Err(AcpiError::BadTableChecksum); }
    let n = parse_aest_body(body);
    AEST_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_aest_known() -> bool { AEST_PARSED.load(Ordering::Acquire) }

pub fn copy_aest_nodes(out: &mut [AestNode]) -> usize {
    let t = AEST_DATA.lock();
    let n = t.n_nodes.min(out.len());
    out[..n].copy_from_slice(&t.nodes[..n]);
    n
}

#[doc(hidden)]
pub fn __test_parse_aest_body(body: &[u8]) -> u32 {
    let n = parse_aest_body(body);
    AEST_PARSED.store(true, Ordering::Release);
    n
}

// ───────────────────────────────────────────────────────────────────
// SDEI — Software Delegated Exception Interface.
// Spec: `acpi/specification/tables-arm-ras-power-pm.md` §2.
// ───────────────────────────────────────────────────────────────────

static SDEI_PARSED: AtomicBool = AtomicBool::new(false);

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → SDEI must also be identity-mapped.
pub unsafe fn parse_sdei(rsdp_phys: PhysAddr) -> Result<(), AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut sdei: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"SDEI" && sdei.is_none() {
                sdei = Some(phys);
            }
        })?;
    }
    let sdei = sdei.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe {
        (sdei as *const SdtHeader).read_unaligned().length as usize
    };
    if total < SDT_HEADER_SIZE { return Err(AcpiError::BadXsdtSignature); }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(sdei as *const u8, total) };
    if checksum(body) != 0 { return Err(AcpiError::BadTableChecksum); }
    SDEI_PARSED.store(true, Ordering::Release);
    Ok(())
}

pub fn is_sdei_known() -> bool { SDEI_PARSED.load(Ordering::Acquire) }

#[doc(hidden)]
pub fn __test_set_sdei_known() {
    SDEI_PARSED.store(true, Ordering::Release);
}

// ───────────────────────────────────────────────────────────────────
// WDDT — Watchdog Description Table.
// Spec: `acpi/specification/tables-arm-ras-power-pm.md` §3.
// ───────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct WddtInfo {
    pub timer_max_count: u16,
    pub timer_min_count: u16,
    pub period_us:       u16,
    pub status:          u16,
    pub capability:      u16,
    pub base:            u64,
}

static WDDT_DATA: IrqSafeSpinLock<WddtInfo> = IrqSafeSpinLock::new(WddtInfo {
    timer_max_count: 0, timer_min_count: 0, period_us: 0,
    status: 0, capability: 0, base: 0,
});
static WDDT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_wddt_body(body: &[u8]) {
    // Body fields start at SDT_HEADER_SIZE + 4 (after the 4-byte
    // SpecVersion + TableVersion + PciVendorId block per spec).
    // Actual layout per WDDT 1.0:
    //   SDT_HEADER (36)
    //   SpecVersion (2)
    //   TableVersion (2)
    //   PciVendorId (2)
    //   Address (12, GAS)
    //   MaxCount (2), MinCount (2), Period (2)
    //   Status (2), Capability (2)
    if body.len() < SDT_HEADER_SIZE + 6 + 12 + 10 { return; }
    let off = SDT_HEADER_SIZE + 6;
    // GAS at off..off+12; address at off+4..off+12.
    let base = u64::from_le_bytes([
        body[off + 4], body[off + 5], body[off + 6], body[off + 7],
        body[off + 8], body[off + 9], body[off + 10], body[off + 11],
    ]);
    let mc_off = off + 12;
    let timer_max_count = u16::from_le_bytes([body[mc_off],     body[mc_off + 1]]);
    let timer_min_count = u16::from_le_bytes([body[mc_off + 2], body[mc_off + 3]]);
    let period_us       = u16::from_le_bytes([body[mc_off + 4], body[mc_off + 5]]);
    let status          = u16::from_le_bytes([body[mc_off + 6], body[mc_off + 7]]);
    let capability      = u16::from_le_bytes([body[mc_off + 8], body[mc_off + 9]]);
    *WDDT_DATA.lock() = WddtInfo {
        timer_max_count, timer_min_count, period_us,
        status, capability, base,
    };
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → WDDT must also be identity-mapped.
pub unsafe fn parse_wddt(rsdp_phys: PhysAddr) -> Result<(), AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut wddt: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"WDDT" && wddt.is_none() {
                wddt = Some(phys);
            }
        })?;
    }
    let wddt = wddt.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe {
        (wddt as *const SdtHeader).read_unaligned().length as usize
    };
    if total < SDT_HEADER_SIZE { return Err(AcpiError::BadXsdtSignature); }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(wddt as *const u8, total) };
    if checksum(body) != 0 { return Err(AcpiError::BadTableChecksum); }
    parse_wddt_body(body);
    WDDT_PARSED.store(true, Ordering::Release);
    Ok(())
}

pub fn wddt_info() -> Option<WddtInfo> {
    if !WDDT_PARSED.load(Ordering::Acquire) { return None; }
    Some(*WDDT_DATA.lock())
}

#[doc(hidden)]
pub fn __test_parse_wddt_body(body: &[u8]) {
    parse_wddt_body(body);
    WDDT_PARSED.store(true, Ordering::Release);
}

// ───────────────────────────────────────────────────────────────────
// LPIT — Low Power Idle Table.
// Spec: `acpi/specification/tables-arm-ras-power-pm.md` §4.
// ───────────────────────────────────────────────────────────────────

pub const MAX_LPIT_STATES: usize = 16;

#[derive(Copy, Clone, Debug, Default)]
pub struct LpitState {
    pub uid:          u32,
    pub trigger_addr: u64,
    pub residency:    u32,
    pub latency:      u32,
    pub counter_addr: u64,
    pub counter_freq: u64,
}

struct LpitTables {
    states:   [LpitState; MAX_LPIT_STATES],
    n_states: usize,
}

impl LpitTables {
    const EMPTY: Self = Self {
        states:   [LpitState {
                      uid: 0, trigger_addr: 0, residency: 0,
                      latency: 0, counter_addr: 0, counter_freq: 0
                  }; MAX_LPIT_STATES],
        n_states: 0,
    };
}

static LPIT_DATA:   IrqSafeSpinLock<LpitTables> = IrqSafeSpinLock::new(LpitTables::EMPTY);
static LPIT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_lpit_body(body: &[u8]) -> u32 {
    let mut tables = LPIT_DATA.lock();
    *tables = LpitTables::EMPTY;
    let mut cur = SDT_HEADER_SIZE;
    let mut count = 0u32;
    while cur + 8 <= body.len() {
        let kind = u32::from_le_bytes([
            body[cur],     body[cur + 1],
            body[cur + 2], body[cur + 3],
        ]);
        let len = u32::from_le_bytes([
            body[cur + 4], body[cur + 5],
            body[cur + 6], body[cur + 7],
        ]) as usize;
        if len < 8 || cur + len > body.len() { break; }
        let entry = &body[cur..cur + len];

        // Type 0: Native C-State. Layout (offsets within entry):
        //   8..12  Flags
        //   12..16 UID (we read this as the ACPI proc UID — note the
        //         spec field "Reserved (4)" comes after; our v0.1
        //         spec doc places UID at 8 to keep the surface lean.
        //         Reread the actual layout: header is 8 bytes, then
        //         UID at 8, Reserved at 12, EntryTrigger at 16..28).
        //   16..28 EntryTrigger GAS (address @ 20..28)
        //   28..32 Residency
        //   32..36 Latency
        //   36..48 ResidencyCounter GAS (address @ 40..48)
        //   48..56 ResidencyFreq
        if kind == 0 && entry.len() >= 56 {
            let uid = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
            let trigger_addr = u64::from_le_bytes([
                entry[20], entry[21], entry[22], entry[23],
                entry[24], entry[25], entry[26], entry[27],
            ]);
            let residency = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);
            let latency   = u32::from_le_bytes([entry[32], entry[33], entry[34], entry[35]]);
            let counter_addr = u64::from_le_bytes([
                entry[40], entry[41], entry[42], entry[43],
                entry[44], entry[45], entry[46], entry[47],
            ]);
            let counter_freq = u64::from_le_bytes([
                entry[48], entry[49], entry[50], entry[51],
                entry[52], entry[53], entry[54], entry[55],
            ]);
            if tables.n_states < MAX_LPIT_STATES {
                let i = tables.n_states;
                tables.states[i] = LpitState {
                    uid, trigger_addr, residency, latency,
                    counter_addr, counter_freq,
                };
                tables.n_states = i + 1;
                count += 1;
            }
        }
        cur += len;
    }
    count
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → LPIT must also be identity-mapped.
pub unsafe fn parse_lpit(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut lpit: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"LPIT" && lpit.is_none() {
                lpit = Some(phys);
            }
        })?;
    }
    let lpit = lpit.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe {
        (lpit as *const SdtHeader).read_unaligned().length as usize
    };
    if total < SDT_HEADER_SIZE { return Err(AcpiError::BadXsdtSignature); }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(lpit as *const u8, total) };
    if checksum(body) != 0 { return Err(AcpiError::BadTableChecksum); }
    let n = parse_lpit_body(body);
    LPIT_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_lpit_known() -> bool { LPIT_PARSED.load(Ordering::Acquire) }

pub fn copy_lpit_states(out: &mut [LpitState]) -> usize {
    let t = LPIT_DATA.lock();
    let n = t.n_states.min(out.len());
    out[..n].copy_from_slice(&t.states[..n]);
    n
}

#[doc(hidden)]
pub fn __test_parse_lpit_body(body: &[u8]) -> u32 {
    let n = parse_lpit_body(body);
    LPIT_PARSED.store(true, Ordering::Release);
    n
}

// ───────────────────────────────────────────────────────────────────
// NFIT — NVDIMM Firmware Interface Table.
// Spec: `acpi/specification/tables-arm-ras-power-pm.md` §5.
// ───────────────────────────────────────────────────────────────────

pub const MAX_NFIT_SPA_RANGES: usize = 16;

#[derive(Copy, Clone, Debug, Default)]
pub struct NfitSpaRange {
    pub range_index: u16,
    pub proximity:   u32,
    pub base:        u64,
    pub length:      u64,
    pub mem_attr:    u64,
}

struct NfitTables {
    spa_ranges:   [NfitSpaRange; MAX_NFIT_SPA_RANGES],
    n_spa_ranges: usize,
}

impl NfitTables {
    const EMPTY: Self = Self {
        spa_ranges:   [NfitSpaRange {
                          range_index: 0, proximity: 0, base: 0,
                          length: 0, mem_attr: 0
                      }; MAX_NFIT_SPA_RANGES],
        n_spa_ranges: 0,
    };
}

static NFIT_DATA:   IrqSafeSpinLock<NfitTables> = IrqSafeSpinLock::new(NfitTables::EMPTY);
static NFIT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_nfit_body(body: &[u8]) -> u32 {
    let mut tables = NFIT_DATA.lock();
    *tables = NfitTables::EMPTY;
    // NFIT body starts at SDT_HEADER_SIZE + 4 (4-byte Reserved).
    if body.len() < SDT_HEADER_SIZE + 4 { return 0; }
    let mut cur = SDT_HEADER_SIZE + 4;
    let mut count = 0u32;
    while cur + 4 <= body.len() {
        let kind = u16::from_le_bytes([body[cur], body[cur + 1]]);
        let len = u16::from_le_bytes([body[cur + 2], body[cur + 3]]) as usize;
        if len < 4 || cur + len > body.len() { break; }
        let entry = &body[cur..cur + len];

        // SPA Range subtable: type 0, length 56.
        // Layout:
        //   0..2 Type, 2..4 Length, 4..6 RangeIndex, 6..8 Flags,
        //   8..12 Reserved, 12..16 Proximity, 16..32 Guid,
        //   32..40 Base, 40..48 Length, 48..56 MemoryMappingAttribute
        if kind == 0 && entry.len() >= 56 {
            let range_index = u16::from_le_bytes([entry[4], entry[5]]);
            let proximity = u32::from_le_bytes([
                entry[12], entry[13], entry[14], entry[15],
            ]);
            let base = u64::from_le_bytes([
                entry[32], entry[33], entry[34], entry[35],
                entry[36], entry[37], entry[38], entry[39],
            ]);
            let length = u64::from_le_bytes([
                entry[40], entry[41], entry[42], entry[43],
                entry[44], entry[45], entry[46], entry[47],
            ]);
            let mem_attr = u64::from_le_bytes([
                entry[48], entry[49], entry[50], entry[51],
                entry[52], entry[53], entry[54], entry[55],
            ]);
            if tables.n_spa_ranges < MAX_NFIT_SPA_RANGES {
                let i = tables.n_spa_ranges;
                tables.spa_ranges[i] = NfitSpaRange {
                    range_index, proximity, base, length, mem_attr,
                };
                tables.n_spa_ranges = i + 1;
                count += 1;
            }
        }
        cur += len;
    }
    count
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → NFIT must also be identity-mapped.
pub unsafe fn parse_nfit(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut nfit: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"NFIT" && nfit.is_none() {
                nfit = Some(phys);
            }
        })?;
    }
    let nfit = nfit.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe {
        (nfit as *const SdtHeader).read_unaligned().length as usize
    };
    if total < SDT_HEADER_SIZE + 4 { return Err(AcpiError::BadXsdtSignature); }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(nfit as *const u8, total) };
    if checksum(body) != 0 { return Err(AcpiError::BadTableChecksum); }
    let n = parse_nfit_body(body);
    NFIT_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_nfit_known() -> bool { NFIT_PARSED.load(Ordering::Acquire) }

pub fn copy_nfit_spa_ranges(out: &mut [NfitSpaRange]) -> usize {
    let t = NFIT_DATA.lock();
    let n = t.n_spa_ranges.min(out.len());
    out[..n].copy_from_slice(&t.spa_ranges[..n]);
    n
}

#[doc(hidden)]
pub fn __test_parse_nfit_body(body: &[u8]) -> u32 {
    let n = parse_nfit_body(body);
    NFIT_PARSED.store(true, Ordering::Release);
    n
}

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

extern crate alloc;

pub mod ac_adapter;
pub mod battery;
pub mod buttons;
pub mod fan;
pub mod ioapic;
pub mod lid;
pub mod smbios;

mod tests;

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

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
static MEMORY_RANGES: IrqSafeSpinLock<MemRangeTable> = IrqSafeSpinLock::new(MemRangeTable::EMPTY);

/// Sticky flag: set once `parse_srat` has run successfully.
static SRAT_PARSED: AtomicBool = AtomicBool::new(false);

/// RSDP physical address cached on the first successful `parse_srat`.
/// `0` = no cached RSDP. Tests can re-derive the boot topology from
/// this cache after running synthetic-body tests that mutate the
/// shared CPU/memory tables.
static CACHED_RSDP: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Number of distinct proximity domains observed. Saturates at
/// `MAX_NUMA_NODES`; exposed as the kernel's "NUMA node count".
static NODE_COUNT: AtomicU32 = AtomicU32::new(0);

/// One SRAT memory-affinity range.
#[derive(Copy, Clone, Debug, Default)]
pub struct MemRange {
    pub base: u64,
    pub length: u64,
    pub node: u32,
    pub enabled: bool,
}

#[derive(Copy, Clone, Debug)]
struct MemRangeTable {
    entries: [MemRange; MAX_NUMA_RANGES],
    len: usize,
}

impl MemRangeTable {
    const EMPTY: Self = Self {
        entries: [MemRange {
            base: 0,
            length: 0,
            node: 0,
            enabled: false,
        }; MAX_NUMA_RANGES],
        len: 0,
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
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: u32,
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
    const END: u64 = 0x0010_0000;
    let mut p = START;
    while p + 20 <= END {
        // SAFETY: identity-mapped low ROM; 8-byte read at 16-byte
        // alignment is defined.
        // SAFETY: Valid memory or trusted environment
        let bytes = unsafe { core::slice::from_raw_parts(p as *const u8, 8) };
        if bytes == SIG {
            // Verify checksum before declaring victory; firmware
            // sometimes lays down a stale "RSD PTR " marker that
            // doesn't validate.
            // SAFETY: 20-byte read at p; bounded by END check above.
            let v1 = unsafe { core::slice::from_raw_parts(p as *const u8, 20) };
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
    let p = phys.kernel_ptr::<u8>();
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
        let xsdt_addr = unsafe { (p.add(24) as *const u64).read_unaligned() };
        if xsdt_addr != 0 {
            return Ok(xsdt_addr);
        }
    }
    // v1 fallback or v2 with null XSDT: use RSDT (32-bit pointer at offset 16).
    // SAFETY: offset 16+4 still inside the 20-byte v1 region.
    let rsdt_addr = unsafe { (p.add(16) as *const u32).read_unaligned() };
    if rsdt_addr == 0 {
        return Err(AcpiError::NoXsdt);
    }
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
    if total < SDT_HEADER_SIZE {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller-asserted region covers `total`.
    let body_bytes = unsafe { core::slice::from_raw_parts(p, total) };
    if checksum(body_bytes) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }

    let entry_size = if is_xsdt { 8 } else { 4 };
    let n_entries = (total - SDT_HEADER_SIZE) / entry_size;
    let entries = &body_bytes[SDT_HEADER_SIZE..];

    for i in 0..n_entries {
        let off = i * entry_size;
        let phys = if is_xsdt {
            // SAFETY: bounds-checked above.
            unsafe { (entries.as_ptr().add(off) as *const u64).read_unaligned() }
        } else {
            // SAFETY: bounds-checked above.
            unsafe { (entries.as_ptr().add(off) as *const u32).read_unaligned() as u64 }
        };
        if phys == 0 {
            continue;
        }
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
    let total = unsafe { (srat as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 12 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(srat as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }

    // SRAT body starts at +44 (header 36 + reserved 4 + reserved 8).
    let mut cur = SDT_HEADER_SIZE + 12;
    let mut count = 0u32;
    let mut node_seen = [false; MAX_NUMA_NODES];

    let mut ranges = MEMORY_RANGES.lock();
    ranges.len = 0;

    while cur + 2 <= body.len() {
        let kind = body[cur];
        let len = body[cur + 1] as usize;
        if len < 2 || cur + len > body.len() {
            break;
        }
        let entry = &body[cur..cur + len];

        match kind {
            0 if entry.len() >= 16 => {
                // Type 0: Processor Local APIC/SAPIC affinity.
                // [0] type, [1] len, [2] PD low, [3] APIC id,
                // [4..8] flags, [8] local SAPIC EID, [9..12] PD high,
                // [12..16] clock domain.
                let pd_low = entry[2] as u32;
                let pd_high = u32::from_le_bytes([entry[9], entry[10], entry[11], 0]) << 8;
                let proximity = pd_high | pd_low;
                let apic = entry[3] as u32;
                let flags = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
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
                let proximity = u32::from_le_bytes([entry[2], entry[3], entry[4], entry[5]]);
                let base = u64::from_le_bytes([
                    entry[8], entry[9], entry[10], entry[11], entry[12], entry[13], entry[14],
                    entry[15],
                ]);
                let length = u64::from_le_bytes([
                    entry[16], entry[17], entry[18], entry[19], entry[20], entry[21], entry[22],
                    entry[23],
                ]);
                let flags = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);
                let enabled = flags & 1 != 0;
                if ranges.len < MAX_NUMA_RANGES {
                    let i = ranges.len;
                    ranges.entries[i] = MemRange {
                        base,
                        length,
                        node: proximity,
                        enabled,
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
                let proximity = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
                let x2apic = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
                let flags = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]);
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
    if v == 0 {
        None
    } else {
        Some(PhysAddr::new(v))
    }
}

/// Number of enabled CPUs the SRAT advertised — counts every entry
/// in `CPU_NODE` whose value isn't the `u32::MAX` sentinel. Useful
/// when CPUID-based discovery is unreliable (multi-socket QEMU
/// configs leave leaf 0xB sub-1 returning per-core counts).
/// Returns 0 before `parse_srat` has succeeded.
pub fn cpu_count_from_srat() -> u32 {
    if !SRAT_PARSED.load(Ordering::Acquire) {
        return 0;
    }
    let mut n = 0u32;
    for c in CPU_NODE.iter() {
        if c.load(Ordering::Acquire) != u32::MAX {
            n += 1;
        }
    }
    n
}

/// Look up the NUMA node a CPU belongs to. Returns `None` when the
/// CPU was not present in the SRAT (caller should default to node 0
/// or apply a same-socket fallback).
pub fn cpu_node(cpu: u32) -> Option<u32> {
    if (cpu as usize) >= MAX_CPUS {
        return None;
    }
    let v = CPU_NODE[cpu as usize].load(Ordering::Acquire);
    if v == u32::MAX {
        None
    } else {
        Some(v)
    }
}

/// Look up which NUMA node owns a physical address. `None` if the
/// address falls outside any SRAT memory range.
pub fn memory_node(phys: u64) -> Option<u32> {
    let g = MEMORY_RANGES.lock();
    for r in &g.entries[..g.len] {
        if !r.enabled {
            continue;
        }
        let end = r.base.checked_add(r.length)?;
        if phys >= r.base && phys < end {
            return Some(r.node);
        }
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
static LAPIC_BASE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

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
    pub id: u8,
    pub address: u32,
    /// Global System Interrupt base — first GSI this IOAPIC owns.
    pub gsi_base: u32,
}

/// Interrupt source override entry from MADT.
#[derive(Copy, Clone, Debug, Default)]
pub struct IsaOverride {
    pub bus: u8,
    pub source: u8,
    pub gsi: u32,
    pub flags: u16,
}

#[derive(Copy, Clone, Debug)]
struct MadtTables {
    ioapics: [IoApic; MAX_IOAPICS],
    n_ioapics: usize,
    overrides: [IsaOverride; MAX_ISA_OVERRIDES],
    n_overrides: usize,
}

impl MadtTables {
    const EMPTY: Self = Self {
        ioapics: [IoApic {
            id: 0,
            address: 0,
            gsi_base: 0,
        }; MAX_IOAPICS],
        n_ioapics: 0,
        overrides: [IsaOverride {
            bus: 0,
            source: 0,
            gsi: 0,
            flags: 0,
        }; MAX_ISA_OVERRIDES],
        n_overrides: 0,
    };
}

static MADT_DATA: IrqSafeSpinLock<MadtTables> = IrqSafeSpinLock::new(MadtTables::EMPTY);

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
    let total = unsafe { (madt as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 8 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(madt as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }

    // 4 bytes LAPIC base + 4 bytes flags after the SDT header.
    let lapic_base = u32::from_le_bytes([
        body[SDT_HEADER_SIZE],
        body[SDT_HEADER_SIZE + 1],
        body[SDT_HEADER_SIZE + 2],
        body[SDT_HEADER_SIZE + 3],
    ]) as u64;
    LAPIC_BASE.store(lapic_base, Ordering::Release);

    let mut cur = SDT_HEADER_SIZE + 8;
    let mut count = 0u32;
    let mut cpu_count = 0u32;

    for slot in APIC_IDS.iter() {
        slot.store(u32::MAX, Ordering::Release);
    }
    let mut tables = MADT_DATA.lock();
    *tables = MadtTables::EMPTY;

    while cur + 2 <= body.len() {
        let kind = body[cur];
        let len = body[cur + 1] as usize;
        if len < 2 || cur + len > body.len() {
            break;
        }
        let entry = &body[cur..cur + len];

        match kind {
            0 if entry.len() >= 8 => {
                // Type 0: Processor Local APIC.
                // [2] ACPI processor id, [3] APIC id, [4..8] flags.
                let apic_id = entry[3] as u32;
                let flags = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
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
                let address = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
                let gsi_base = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
                if tables.n_ioapics < MAX_IOAPICS {
                    let i = tables.n_ioapics;
                    tables.ioapics[i] = IoApic {
                        id,
                        address,
                        gsi_base,
                    };
                    tables.n_ioapics = i + 1;
                    count += 1;
                }
            }
            2 if entry.len() >= 10 => {
                // Type 2: Interrupt Source Override.
                // [2] bus, [3] source, [4..8] GSI, [8..10] flags.
                let bus = entry[2];
                let source = entry[3];
                let gsi = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
                let flags = u16::from_le_bytes([entry[8], entry[9]]);
                if tables.n_overrides < MAX_ISA_OVERRIDES {
                    let i = tables.n_overrides;
                    tables.overrides[i] = IsaOverride {
                        bus,
                        source,
                        gsi,
                        flags,
                    };
                    tables.n_overrides = i + 1;
                    count += 1;
                }
            }
            9 if entry.len() >= 16 => {
                // Type 9: Local x2APIC.
                // [4..8] x2APIC id (u32), [8..12] flags, [12..16] ACPI uid.
                let apic_id = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
                let flags = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
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
    if v == 0 {
        None
    } else {
        Some(v)
    }
}

/// Number of enabled CPUs the MADT advertised.
pub fn cpu_count_from_madt() -> u32 {
    MADT_CPU_COUNT.load(Ordering::Acquire)
}

/// Lookup the APIC id at enumeration index `i`. Stage-4 SMP bring-up
/// uses this list as the canonical AP target order. Returns `None`
/// for indices beyond the enumerated count.
pub fn apic_id_at(i: usize) -> Option<u32> {
    if i >= MAX_CPUS {
        return None;
    }
    let v = APIC_IDS[i].load(Ordering::Acquire);
    if v == u32::MAX {
        None
    } else {
        Some(v)
    }
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

static MCFG_BASE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

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
    let total = unsafe { (mcfg as *const SdtHeader).read_unaligned().length as usize };
    let body_end = SDT_HEADER_SIZE + 8 + 16; // header + reserved + 1 entry
    if total < body_end {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(mcfg as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }

    let base = u64::from_le_bytes([
        body[SDT_HEADER_SIZE + 8],
        body[SDT_HEADER_SIZE + 9],
        body[SDT_HEADER_SIZE + 10],
        body[SDT_HEADER_SIZE + 11],
        body[SDT_HEADER_SIZE + 12],
        body[SDT_HEADER_SIZE + 13],
        body[SDT_HEADER_SIZE + 14],
        body[SDT_HEADER_SIZE + 15],
    ]);
    MCFG_BASE.store(base, Ordering::Release);
    Ok(base)
}

/// PCIe ECAM base from the most recent MCFG parse, segment 0.
pub fn mcfg_ecam_base() -> Option<u64> {
    let v = MCFG_BASE.load(Ordering::Acquire);
    if v == 0 {
        None
    } else {
        Some(v)
    }
}

// ── FADT (Fixed ACPI Description Table) → DSDT pointer ─────────────
//
// FADT signature is `"FACP"`. Most fields are platform-power
// related; for our purposes we only need the DSDT pointer:
//   offset 40 (u32 DSDT) — the legacy 32-bit pointer.
//   offset 140 (u64 X_DSDT) — the extended 64-bit pointer (ACPI 2.0+).
// Use X_DSDT when non-zero, fall back to DSDT.

static DSDT_PHYS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

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
            if &hdr.signature == b"FACP" && fadt.is_none() {
                fadt = Some(phys);
            }
        })?;
    }
    let fadt = fadt.ok_or(AcpiError::NoSrat)?;

    // SAFETY: caller assertion.
    let total = unsafe { (fadt as *const SdtHeader).read_unaligned().length as usize };
    if total < 44 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(fadt as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }

    // Legacy DSDT pointer at offset 40 (4 bytes).
    let legacy_dsdt = u32::from_le_bytes([body[40], body[41], body[42], body[43]]) as u64;

    // X_DSDT at offset 140 (8 bytes), ACPI 2.0+. Some FADTs are
    // shorter and don't carry it.
    let x_dsdt = if total >= 148 {
        u64::from_le_bytes([
            body[140], body[141], body[142], body[143], body[144], body[145], body[146], body[147],
        ])
    } else {
        0
    };

    let dsdt = if x_dsdt != 0 { x_dsdt } else { legacy_dsdt };
    if dsdt == 0 {
        return Err(AcpiError::NoSrat);
    }
    DSDT_PHYS.store(dsdt, Ordering::Release);
    Ok(dsdt)
}

/// DSDT physical address from the most recent `parse_fadt_for_dsdt` call.
pub fn dsdt_phys() -> Option<u64> {
    let v = DSDT_PHYS.load(Ordering::Acquire);
    if v == 0 {
        None
    } else {
        Some(v)
    }
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
            if &hdr.signature == b"SSDT" {
                f(phys, hdr);
            }
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
    pub processor_pd: u32,
    /// Memory proximity domain this entry describes.
    pub memory_pd: u32,
    /// Bit 0: processor_proximity_valid.
    pub flags: u16,
    /// Convenience accessor.
    pub processor_proximity_valid: bool,
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
    pub kind: HmatLatBwKind,
    /// Memory hierarchy: 0=memory, 1=last-level cache, etc.
    pub hierarchy: u8,
    pub n_initiators: u32,
    pub n_targets: u32,
    /// Multiplier in picoseconds (latency) or MB/s (bandwidth).
    pub entry_base_unit: u64,
    /// Index into `HMAT_LATBW_PAIRS` where this record's pair list
    /// starts. `n_initiators * n_targets` pairs follow.
    pub pairs_offset: u32,
}

#[derive(Copy, Clone, Debug)]
struct HmatLatBwPair {
    initiator: u32,
    target: u32,
    /// Raw value in `entry_base_unit` units.
    value: u16,
}

#[derive(Copy, Clone, Debug)]
struct HmatTables {
    mem_attrs: [HmatMemAttr; MAX_HMAT_MEM_ATTRS],
    n_mem_attrs: usize,
    records: [HmatLatBwRecord; MAX_HMAT_LATBW],
    n_records: usize,
    pairs: [HmatLatBwPair; MAX_HMAT_LATBW_PAIRS],
    n_pairs: usize,
}

impl HmatTables {
    const EMPTY: Self = Self {
        mem_attrs: [HmatMemAttr {
            processor_pd: 0,
            memory_pd: 0,
            flags: 0,
            processor_proximity_valid: false,
        }; MAX_HMAT_MEM_ATTRS],
        n_mem_attrs: 0,
        records: [HmatLatBwRecord {
            kind: HmatLatBwKind::Other(0xFF),
            hierarchy: 0,
            n_initiators: 0,
            n_targets: 0,
            entry_base_unit: 0,
            pairs_offset: 0,
        }; MAX_HMAT_LATBW],
        n_records: 0,
        pairs: [HmatLatBwPair {
            initiator: 0,
            target: 0,
            value: 0,
        }; MAX_HMAT_LATBW_PAIRS],
        n_pairs: 0,
    };
}

static HMAT_DATA: IrqSafeSpinLock<HmatTables> = IrqSafeSpinLock::new(HmatTables::EMPTY);
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
            if &hdr.signature == b"HMAT" && hmat.is_none() {
                hmat = Some(phys);
            }
        })?;
    }
    let hmat = hmat.ok_or(AcpiError::NoSrat)?;

    // SAFETY: caller assertion.
    let total = unsafe { (hmat as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 4 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(hmat as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }

    // 4 reserved bytes after the SDT header.
    let mut cur = SDT_HEADER_SIZE + 4;
    let mut count = 0u32;
    let mut tables = HMAT_DATA.lock();
    *tables = HmatTables::EMPTY;

    while cur + 8 <= body.len() {
        let kind = u16::from_le_bytes([body[cur], body[cur + 1]]);
        let len = u32::from_le_bytes([body[cur + 4], body[cur + 5], body[cur + 6], body[cur + 7]])
            as usize;
        if len < 8 || cur + len > body.len() {
            break;
        }
        let entry = &body[cur..cur + len];

        match kind {
            0 if entry.len() >= 40 => {
                // Type 0: Memory Proximity Domain Attributes.
                // [8..10] flags, [10..12] reserved, [12..16] processor PD,
                // [16..20] memory PD, [20..40] reserved.
                let flags = u16::from_le_bytes([entry[8], entry[9]]);
                let processor_pd = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]);
                let memory_pd = u32::from_le_bytes([entry[16], entry[17], entry[18], entry[19]]);
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
                let dt = HmatLatBwKind::from_byte(entry[9]);
                let n_in = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]);
                let n_tg = u32::from_le_bytes([entry[16], entry[17], entry[18], entry[19]]);
                let base_unit = u64::from_le_bytes([
                    entry[24], entry[25], entry[26], entry[27], entry[28], entry[29], entry[30],
                    entry[31],
                ]);

                let init_off = 32;
                let tgt_off = init_off + (n_in as usize) * 4;
                let mat_off = tgt_off + (n_tg as usize) * 4;
                let mat_len = (n_in as usize) * (n_tg as usize) * 2;
                if mat_off + mat_len > entry.len() {
                    break;
                }
                if tables.n_records >= MAX_HMAT_LATBW {
                    cur += len;
                    continue;
                }

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
                        let value = u16::from_le_bytes([entry[val_off], entry[val_off + 1]]);
                        let i = tables.n_pairs;
                        tables.pairs[i] = HmatLatBwPair {
                            initiator,
                            target,
                            value,
                        };
                        tables.n_pairs = i + 1;
                    }
                }
                let i = tables.n_records;
                tables.records[i] = HmatLatBwRecord {
                    kind: dt,
                    hierarchy,
                    n_initiators: n_in,
                    n_targets: n_tg,
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
pub fn is_hmat_known() -> bool {
    HMAT_PARSED.load(Ordering::Acquire)
}

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
pub fn hmat_value(kind: HmatLatBwKind, hierarchy: u8, initiator: u32, target: u32) -> Option<u64> {
    let g = HMAT_DATA.lock();
    for r in &g.records[..g.n_records] {
        if r.kind != kind || r.hierarchy != hierarchy {
            continue;
        }
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
    pub socket_id: u16,
    /// Parent memory-controller id (closest enclosing Type-1).
    pub controller_id: u16,
    /// Common-header flags from the DIMM struct.
    pub flags: u16,
}

#[derive(Copy, Clone, Debug)]
struct PmttTables {
    n_sockets: u32,
    n_controllers: u32,
    n_dimms: u32,
    dimms: [PmttDimm; MAX_PMTT_DIMMS],
    dimms_len: usize,
}

impl PmttTables {
    const EMPTY: Self = Self {
        n_sockets: 0,
        n_controllers: 0,
        n_dimms: 0,
        dimms: [PmttDimm {
            smbios_handle: 0,
            socket_id: 0,
            controller_id: 0,
            flags: 0,
        }; MAX_PMTT_DIMMS],
        dimms_len: 0,
    };
}

static PMTT_DATA: IrqSafeSpinLock<PmttTables> = IrqSafeSpinLock::new(PmttTables::EMPTY);
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
            if &hdr.signature == b"PMTT" && pmtt.is_none() {
                pmtt = Some(phys);
            }
        })?;
    }
    let pmtt = pmtt.ok_or(AcpiError::NoSrat)?;

    // SAFETY: caller assertion.
    let total = unsafe { (pmtt as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 4 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(pmtt as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }

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
    body: &[u8],
    cur: &mut usize,
    end: usize,
    parent_socket: u16,
    parent_ctrl: u16,
    out: &mut PmttTables,
) -> u32 {
    let mut count = 0u32;
    while *cur + 8 <= end {
        let kind = body[*cur];
        let len = u16::from_le_bytes([body[*cur + 2], body[*cur + 3]]) as usize;
        if len < 8 || *cur + len > end {
            break;
        }
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
                    body,
                    &mut child_cur,
                    child_end,
                    socket_id,
                    parent_ctrl,
                    out,
                );
            }
            1 if entry.len() >= 12 => {
                // Memory Controller: [8..10] id, [10..12] reserved.
                let ctrl_id = u16::from_le_bytes([entry[8], entry[9]]);
                out.n_controllers += 1;
                let mut child_cur = *cur + 12;
                let child_end = *cur + len;
                count += 1 + parse_pmtt_children(
                    body,
                    &mut child_cur,
                    child_end,
                    parent_socket,
                    ctrl_id,
                    out,
                );
            }
            2 if entry.len() >= 12 => {
                // DIMM: [8..12] SMBIOS handle.
                let smbios_handle = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
                if out.dimms_len < MAX_PMTT_DIMMS {
                    let i = out.dimms_len;
                    out.dimms[i] = PmttDimm {
                        smbios_handle,
                        socket_id: parent_socket,
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
pub fn is_pmtt_known() -> bool {
    PMTT_PARSED.load(Ordering::Acquire)
}

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
    for c in CPU_NODE.iter() {
        c.store(u32::MAX, Ordering::Release);
    }
    *MEMORY_RANGES.lock() = MemRangeTable::EMPTY;
    SRAT_PARSED.store(false, Ordering::Release);
    NODE_COUNT.store(0, Ordering::Release);
    for c in APIC_IDS.iter() {
        c.store(u32::MAX, Ordering::Release);
    }
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
    pub address: u64,
    /// Total byte count of the status+enable register pair.
    pub byte_count: u8,
    /// First GPE number this block handles (0 for GPE0, GPE1_BASE for GPE1).
    pub base_gsi: u32,
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
            if &hdr.signature == b"FACP" && fadt.is_none() {
                fadt = Some(phys);
            }
        })?;
    }
    let fadt = fadt.ok_or(AcpiError::NoSrat)?;

    // SAFETY: caller assertion.
    let total = unsafe { (fadt as *const SdtHeader).read_unaligned().length as usize };
    // Need at least offset 96 (past GPE1_BASE at byte 95).
    if total < 96 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(fadt as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }

    // ── legacy fields ────────────────────────────────────────────────
    let legacy_gpe0_addr = u32::from_le_bytes([body[80], body[81], body[82], body[83]]) as u64;
    let legacy_gpe1_addr = u32::from_le_bytes([body[84], body[85], body[86], body[87]]) as u64;
    let gpe0_len = body[92];
    let gpe1_len = body[93];
    let gpe1_base = body[95] as u32;

    // ── extended GAS fields (ACPI 2.0+, FADT total ≥ 232+12=244) ───
    // X_GPE0_BLK is at offset 220, X_GPE1_BLK at 232. Each is 12 bytes.
    let (x_gpe0_addr, x_gpe1_addr) = if total >= 244 {
        // GAS address is at byte offset 4 within the 12-byte GAS struct.
        let x0 = u64::from_le_bytes([
            body[220 + 4],
            body[220 + 5],
            body[220 + 6],
            body[220 + 7],
            body[220 + 8],
            body[220 + 9],
            body[220 + 10],
            body[220 + 11],
        ]);
        let x1 = u64::from_le_bytes([
            body[232 + 4],
            body[232 + 5],
            body[232 + 6],
            body[232 + 7],
            body[232 + 8],
            body[232 + 9],
            body[232 + 10],
            body[232 + 11],
        ]);
        (x0, x1)
    } else {
        (0, 0)
    };

    // ── choose best address ──────────────────────────────────────────
    let gpe0_addr = if x_gpe0_addr != 0 {
        x_gpe0_addr
    } else {
        legacy_gpe0_addr
    };
    let gpe1_addr = if x_gpe1_addr != 0 {
        x_gpe1_addr
    } else {
        legacy_gpe1_addr
    };

    if gpe0_addr != 0 && gpe0_len != 0 {
        *GPE0_BLOCK.lock() = Some(GpeBlockInfo {
            address: gpe0_addr,
            byte_count: gpe0_len,
            base_gsi: 0,
        });
    }
    if gpe1_addr != 0 && gpe1_len != 0 {
        *GPE1_BLOCK.lock() = Some(GpeBlockInfo {
            address: gpe1_addr,
            byte_count: gpe1_len,
            base_gsi: gpe1_base,
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

/// Enable a GPE by number. Correctly identifies the block and
/// offset within the enable register set.
pub fn enable_gpe(gpe_num: u32) {
    let (block, bit) = if let Some(b) = gpe0_block() {
        if gpe_num >= b.base_gsi && gpe_num < b.base_gsi + (b.byte_count as u32 * 4) {
            (Some(b), gpe_num - b.base_gsi)
        } else {
            (None, 0)
        }
    } else {
        (None, 0)
    };
    let (block, bit) = if block.is_none() {
        if let Some(b) = gpe1_block() {
            if gpe_num >= b.base_gsi && gpe_num < b.base_gsi + (b.byte_count as u32 * 4) {
                (Some(b), gpe_num - b.base_gsi)
            } else {
                (None, 0)
            }
        } else {
            (block, bit)
        }
    } else {
        (block, bit)
    };

    if let Some(b) = block {
        // GPE enable is an x86 port-I/O write; a no-op on other arches.
        #[cfg(target_arch = "x86_64")]
        {
            let half = b.byte_count as u64 / 2;
            let reg_idx = bit / 8;
            let reg_bit = bit % 8;
            let port = b.address + half + reg_idx as u64;
            // SAFETY: part of the validated GPE block.
            unsafe {
                let val = narf_arch::x86_64::io_port::inb(port as u16);
                narf_arch::x86_64::io_port::outb(port as u16, val | (1 << reg_bit));
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        let _ = (&b, bit);
    }
}

// ── FADT power-management fields (SCI_INT, PM1, SMI_CMD) ───────────
//
// FADT body offsets — every field below is well-known per ACPI 6.5
// §5.2.9, but for clarity:
//   46:  SCI_INT          u16  — system control interrupt (8259 IRQ #)
//   48:  SMI_CMD          u32  — IO port for ACPI mode enable/disable
//   52:  ACPI_ENABLE      u8   — write to SMI_CMD to enter ACPI mode
//   53:  ACPI_DISABLE     u8   — write to SMI_CMD to leave ACPI mode
//   56:  PM1A_EVT_BLK     u32  — legacy 32-bit IO addr (status+enable)
//   60:  PM1B_EVT_BLK     u32  — legacy 32-bit IO addr (optional)
//   64:  PM1A_CNT_BLK     u32  — legacy 32-bit IO addr
//   68:  PM1B_CNT_BLK     u32  — optional
//   88:  PM1_EVT_LEN      u8   — byte length of each EVT block
//   89:  PM1_CNT_LEN      u8   — byte length of each CNT block
//   148: X_PM1A_EVT_BLK   GAS  (ACPI 2.0+)
//   160: X_PM1B_EVT_BLK   GAS
//   172: X_PM1A_CNT_BLK   GAS
//   184: X_PM1B_CNT_BLK   GAS

/// FADT power-management surface. Addresses are post-X_-fallback —
/// when the extended GAS variant is non-zero we use it, else the
/// legacy 32-bit field. `0` for any optional block (PM1B is rare on
/// modern hardware).
#[derive(Copy, Clone, Debug, Default)]
pub struct FadtPm {
    pub sci_int: u16,
    pub smi_cmd: u32,
    pub acpi_enable: u8,
    pub acpi_disable: u8,
    pub pm1a_evt: u64,
    pub pm1b_evt: u64,
    pub pm1a_cnt: u64,
    pub pm1b_cnt: u64,
    pub pm1_evt_len: u8,
    pub pm1_cnt_len: u8,
    /// FADT RESET_REG (12-byte GAS at offset 116, present when
    /// flags bit 10 is set). The address-space id selects how to
    /// write `reset_value`: 1 = legacy I/O port, 0 = system memory
    /// (MMIO), 2 = PCI config space.
    pub reset_reg_addr_space: u8,
    pub reset_reg_addr: u64,
    pub reset_value: u8,
}

static FADT_PM: IrqSafeSpinLock<Option<FadtPm>> = IrqSafeSpinLock::new(None);

/// Parse the FADT power-management surface. Idempotent; the parsed
/// `FadtPm` is cached and returned on subsequent calls.
///
/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → FADT pointers must also be identity-mapped.
pub unsafe fn parse_fadt_pm(rsdp_phys: PhysAddr) -> Result<FadtPm, AcpiError> {
    if let Some(cached) = *FADT_PM.lock() {
        return Ok(cached);
    }
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut fadt: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"FACP" && fadt.is_none() {
                fadt = Some(phys);
            }
        })?;
    }
    let fadt = fadt.ok_or(AcpiError::NoSrat)?;

    // SAFETY: caller assertion.
    let total = unsafe { (fadt as *const SdtHeader).read_unaligned().length as usize };
    if total < 90 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(fadt as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }

    let sci_int = u16::from_le_bytes([body[46], body[47]]);
    let smi_cmd = u32::from_le_bytes([body[48], body[49], body[50], body[51]]);
    let acpi_enable = body[52];
    let acpi_disable = body[53];
    let legacy_pm1a_evt = u32::from_le_bytes([body[56], body[57], body[58], body[59]]) as u64;
    let legacy_pm1b_evt = u32::from_le_bytes([body[60], body[61], body[62], body[63]]) as u64;
    let legacy_pm1a_cnt = u32::from_le_bytes([body[64], body[65], body[66], body[67]]) as u64;
    let legacy_pm1b_cnt = u32::from_le_bytes([body[68], body[69], body[70], body[71]]) as u64;
    let pm1_evt_len = body[88];
    let pm1_cnt_len = body[89];

    // Helper to extract address from a 12-byte GAS at offset `o`.
    let gas_addr = |o: usize| -> u64 {
        if total < o + 12 {
            return 0;
        }
        u64::from_le_bytes([
            body[o + 4],
            body[o + 5],
            body[o + 6],
            body[o + 7],
            body[o + 8],
            body[o + 9],
            body[o + 10],
            body[o + 11],
        ])
    };
    let x_pm1a_evt = gas_addr(148);
    let x_pm1b_evt = gas_addr(160);
    let x_pm1a_cnt = gas_addr(172);
    let x_pm1b_cnt = gas_addr(184);

    // RESET_REG: 12-byte GAS at offset 116, RESET_VALUE byte at 128.
    // FADT minor revisions before 2.0 didn't carry these — guard on
    // table length (must include through byte 128).
    let (reset_reg_addr_space, reset_reg_addr, reset_value) = if total >= 129 {
        let asid = body[116];
        let addr = u64::from_le_bytes([
            body[120], body[121], body[122], body[123], body[124], body[125], body[126], body[127],
        ]);
        (asid, addr, body[128])
    } else {
        (0, 0, 0)
    };

    let pick = |x: u64, l: u64| if x != 0 { x } else { l };

    let pm = FadtPm {
        sci_int,
        smi_cmd,
        acpi_enable,
        acpi_disable,
        pm1a_evt: pick(x_pm1a_evt, legacy_pm1a_evt),
        pm1b_evt: pick(x_pm1b_evt, legacy_pm1b_evt),
        pm1a_cnt: pick(x_pm1a_cnt, legacy_pm1a_cnt),
        pm1b_cnt: pick(x_pm1b_cnt, legacy_pm1b_cnt),
        pm1_evt_len,
        pm1_cnt_len,
        reset_reg_addr_space,
        reset_reg_addr,
        reset_value,
    };
    *FADT_PM.lock() = Some(pm);
    Ok(pm)
}

/// Last-parsed FADT power-management surface, if any.
pub fn fadt_pm() -> Option<FadtPm> {
    *FADT_PM.lock()
}

// ── PM1 status / control I/O helpers ────────────────────────────────
//
// PM1 status bits we care about (ACPI 6.5 §4.8.3.1.1):
pub const PM1_STS_TMR: u16 = 1 << 0;
pub const PM1_STS_BM: u16 = 1 << 4;
pub const PM1_STS_GBL: u16 = 1 << 5;
pub const PM1_STS_PWRBTN: u16 = 1 << 8;
pub const PM1_STS_SLPBTN: u16 = 1 << 9;
pub const PM1_STS_RTC: u16 = 1 << 10;
pub const PM1_STS_WAK: u16 = 1 << 15;

/// Read the OR of PM1a and PM1b status registers. Status block lives
/// in the first half of `pm1*_evt`.
#[cfg(target_arch = "x86_64")]
pub fn pm1_status_read() -> u16 {
    let pm = match fadt_pm() {
        Some(p) => p,
        None => return 0,
    };
    let mut s = 0u16;
    if pm.pm1a_evt != 0 {
        // SAFETY: PM1A_EVT_BLK address from a checksummed FADT.
        s |= unsafe { narf_arch::x86_64::io_port::inw(pm.pm1a_evt as u16) };
    }
    if pm.pm1b_evt != 0 {
        // SAFETY: PM1B_EVT_BLK address from a checksummed FADT.
        s |= unsafe { narf_arch::x86_64::io_port::inw(pm.pm1b_evt as u16) };
    }
    s
}

/// Clear PM1 status bits by writing 1s to both PM1a and PM1b status
/// registers (W1C semantics per ACPI §4.8.3.1.1).
#[cfg(target_arch = "x86_64")]
pub fn pm1_status_clear(bits: u16) {
    let pm = match fadt_pm() {
        Some(p) => p,
        None => return,
    };
    if pm.pm1a_evt != 0 {
        // SAFETY: PM1A_EVT_BLK address from a checksummed FADT.
        unsafe { narf_arch::x86_64::io_port::outw(pm.pm1a_evt as u16, bits) };
    }
    if pm.pm1b_evt != 0 {
        // SAFETY: PM1B_EVT_BLK address from a checksummed FADT.
        unsafe { narf_arch::x86_64::io_port::outw(pm.pm1b_evt as u16, bits) };
    }
}

/// Write SLP_TYP and SLP_EN to PM1a/b control registers to enter the
/// requested sleep state. `slp_typ` is the 3-bit value from `\_Sx_`,
/// shifted to bits 10..12; SLP_EN is bit 13 (0x2000).
///
/// # Safety
/// Caller must have already invoked `_PTS(slp_state)` and saved any
/// state that won't survive the transition. Returns immediately on
/// S1; never returns on S3/S4/S5 unless wake fires.
#[cfg(target_arch = "x86_64")]
pub unsafe fn pm1_enter_sleep(slp_typ_a: u8, slp_typ_b: u8) {
    let pm = match fadt_pm() {
        Some(p) => p,
        None => return,
    };
    let val_a = ((slp_typ_a as u16 & 0x7) << 10) | 0x2000;
    if pm.pm1a_cnt != 0 {
        // SAFETY: PM1A_CNT_BLK address from a checksummed FADT;
        // caller has prepared sleep state per ACPI §16.
        // SAFETY: Valid memory or trusted environment
        unsafe { narf_arch::x86_64::io_port::outw(pm.pm1a_cnt as u16, val_a) };
    }
    if pm.pm1b_cnt != 0 {
        let val_b = ((slp_typ_b as u16 & 0x7) << 10) | 0x2000;
        // SAFETY: PM1B_CNT_BLK address from a checksummed FADT.
        unsafe { narf_arch::x86_64::io_port::outw(pm.pm1b_cnt as u16, val_b) };
    }
}

/// PM1 enable register bit positions (mirror PM1_STS_*; ACPI 6.5
/// §4.8.3.1.2). Setting the corresponding enable bit gates SCI
/// generation on the matching status bit.
pub const PM1_EN_TMR: u16 = 1 << 0;
pub const PM1_EN_GBL: u16 = 1 << 5;
pub const PM1_EN_PWRBTN: u16 = 1 << 8;
pub const PM1_EN_SLPBTN: u16 = 1 << 9;
pub const PM1_EN_RTC: u16 = 1 << 10;

/// Arm the power-button enable bit so PM1.PWRBTN status triggers
/// an SCI when pressed. Without this the platform may still latch
/// the status bit but won't fire the interrupt — polling
/// `pm1_status_read() & PM1_STS_PWRBTN` still works.
///
/// Returns `false` if the FADT hasn't been parsed yet or the
/// PM1 control block is absent.
#[cfg(target_arch = "x86_64")]
pub fn power_button_arm() -> bool {
    let pm = match fadt_pm() {
        Some(p) => p,
        None => return false,
    };
    // PM1 enable register sits at PM1*_EVT + (pm1_evt_len / 2)
    // per ACPI 6.5 §4.8.3.1 — status occupies the lower half,
    // enable the upper half.
    if pm.pm1_evt_len == 0 {
        return false;
    }
    let half = (pm.pm1_evt_len / 2) as u16;
    let mut armed = false;
    if pm.pm1a_evt != 0 {
        let port = pm.pm1a_evt as u16 + half;
        // SAFETY: PM1 enable port from a checksummed FADT.
        unsafe {
            let cur = narf_arch::x86_64::io_port::inw(port);
            narf_arch::x86_64::io_port::outw(port, cur | PM1_EN_PWRBTN);
        }
        armed = true;
    }
    if pm.pm1b_evt != 0 {
        let port = pm.pm1b_evt as u16 + half;
        // SAFETY: same.
        unsafe {
            let cur = narf_arch::x86_64::io_port::inw(port);
            narf_arch::x86_64::io_port::outw(port, cur | PM1_EN_PWRBTN);
        }
        armed = true;
    }
    armed
}

/// Returns `true` if PM1 status reports a pending power-button
/// press. Caller is responsible for clearing the latch via
/// `pm1_status_clear(PM1_STS_PWRBTN)` after acting on it.
#[cfg(target_arch = "x86_64")]
pub fn power_button_pressed() -> bool {
    pm1_status_read() & PM1_STS_PWRBTN != 0
}

/// Reboot via FADT.RESET_REG. Returns `false` when the FADT
/// didn't carry a reset register (set `Some` only on ACPI 2.0+
/// revisions and platforms that opt in via the FACP fixed-feature
/// flag), or when the address space is unsupported on this arch.
/// On success the call doesn't return — the platform issues a
/// hard reset within microseconds.
///
/// Address spaces (ACPI 6.5 §5.2.3.1):
///   1 → System I/O   (port write, x86 outb)
///   0 → System Memory (MMIO write)
///   2 → PCI Config (not supported here yet — falls through to false)
///
/// # Safety
/// The platform resets immediately on the write. Caller must have
/// drained anything that needs to land first (file syncs, etc.).
#[cfg(target_arch = "x86_64")]
pub unsafe fn reboot_via_fadt() -> bool {
    let pm = match fadt_pm() {
        Some(p) => p,
        None => return false,
    };
    if pm.reset_reg_addr == 0 {
        return false;
    }
    match pm.reset_reg_addr_space {
        1 => {
            // SAFETY: address space 1 = System I/O. RESET_REG_ADDR
            // fits in u16 by spec; outb to that port issues the
            // reset. Returns architecturally — but the platform
            // resets before the next instruction retires.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                narf_arch::x86_64::io_port::outb(pm.reset_reg_addr as u16, pm.reset_value);
            }
            true
        }
        0 => {
            // SAFETY: address space 0 = System Memory. We don't
            // know the access size from the GAS without parsing
            // bit_width; assume byte access (matches ICH/PCH and
            // most x86 platforms).
            // SAFETY: Valid memory or trusted environment
            unsafe {
                core::ptr::write_volatile(pm.reset_reg_addr as *mut u8, pm.reset_value);
            }
            true
        }
        _ => false,
    }
}

/// `\_S5` shutdown. Walks the AML namespace for the `\_S5_`
/// package + writes the resulting SLP_TYPa / SLP_TYPb to
/// PM1a_CNT / PM1b_CNT with SLP_EN set. Returns `false` when
/// the namespace isn't loaded or `\_S5` is missing; on success
/// the platform powers off and the call doesn't return.
///
/// Common QEMU defaults are SLP_TYPa = 5, SLP_TYPb = 0; real
/// firmware varies (Linux's acpi/sleep.c does the same AML walk).
/// Until the AML walk lands here we accept caller-supplied values
/// — the wrapper at narf-acpi-runtime side picks them.
///
/// # Safety
/// Platform powers off; caller must have flushed anything that
/// needs to survive.
#[cfg(target_arch = "x86_64")]
pub unsafe fn shutdown_via_pm1(slp_typ_a: u8, slp_typ_b: u8) {
    // SAFETY: forwarded to pm1_enter_sleep which is documented
    // to never return on S5.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        pm1_enter_sleep(slp_typ_a, slp_typ_b);
    }
}

/// Write `acpi_enable` to `smi_cmd` to switch the platform from legacy
/// (SMI-driven) to ACPI (SCI-driven) mode. No-op when SMI_CMD is 0
/// (system already in ACPI mode, or hardware-reduced platform).
#[cfg(target_arch = "x86_64")]
pub fn acpi_enable() {
    let pm = match fadt_pm() {
        Some(p) => p,
        None => return,
    };
    if pm.smi_cmd == 0 || pm.acpi_enable == 0 {
        return;
    }
    // SAFETY: SMI_CMD port from a checksummed FADT.
    unsafe { narf_arch::x86_64::io_port::outb(pm.smi_cmd as u16, pm.acpi_enable) };
}

// ── GPE status read / clear ─────────────────────────────────────────

/// Read both halves (status + enable) of a GPE block. Returns
/// `(status, enable)`; each `Vec` has `byte_count/2` bytes (status
/// block is the lower half, enable the upper).
#[cfg(target_arch = "x86_64")]
pub fn gpe_block_status(b: GpeBlockInfo) -> alloc::vec::Vec<u8> {
    let half = (b.byte_count / 2) as usize;
    let mut out = alloc::vec![0u8; half];
    for (i, slot) in out.iter_mut().enumerate() {
        let port = (b.address + i as u64) as u16;
        // SAFETY: GPE block address from a checksummed FADT.
        *slot = unsafe { narf_arch::x86_64::io_port::inb(port) };
    }
    out
}

/// IRQ-safe variant: read GPE block status registers into a
/// fixed-size stack buffer — no heap allocation. Returns the
/// buffer and how many bytes are valid. Capped at 32 bytes
/// (= 256 GPE bits) which covers every real platform.
///
/// Called from `dispatch_sci` (ISR context); the sleepable
/// allocator is not available there.
#[cfg(target_arch = "x86_64")]
pub fn gpe_block_status_irq(b: GpeBlockInfo) -> ([u8; 32], usize) {
    let half = (b.byte_count / 2) as usize;
    let count = half.min(32);
    let mut buf = [0u8; 32];
    for (i, slot) in buf.iter_mut().enumerate().take(count) {
        let port = (b.address + i as u64) as u16;
        // SAFETY: GPE block address from a checksummed FADT.
        *slot = unsafe { narf_arch::x86_64::io_port::inb(port) };
    }
    (buf, count)
}

/// Clear a single GPE status bit by writing 1 to its status-register
/// position (W1C). No-op if `gpe_num` is outside both blocks.
#[cfg(target_arch = "x86_64")]
pub fn gpe_status_clear_bit(gpe_num: u32) {
    let block = gpe0_block()
        .filter(|b| gpe_num >= b.base_gsi && gpe_num < b.base_gsi + (b.byte_count as u32 * 4))
        .or_else(|| {
            gpe1_block().filter(|b| {
                gpe_num >= b.base_gsi && gpe_num < b.base_gsi + (b.byte_count as u32 * 4)
            })
        });
    if let Some(b) = block {
        let bit = gpe_num - b.base_gsi;
        let reg_idx = bit / 8;
        let reg_bit = bit % 8;
        let port = (b.address + reg_idx as u64) as u16;
        // SAFETY: GPE block address from a checksummed FADT. W1C
        // means writing other bits as 0 leaves them untouched.
        // SAFETY: Valid memory or trusted environment
        unsafe { narf_arch::x86_64::io_port::outb(port, 1 << reg_bit) };
    }
}

// ── ECDT (Embedded Controller Boot Resources Table) ──────────────────

/// Descriptor for the ACPI Embedded Controller.
#[derive(Copy, Clone, Debug, Default)]
pub struct EcdtInfo {
    pub control_addr: u64,
    pub data_addr: u64,
    pub uid: u32,
    pub gpe_bit: u8,
}

static ECDT_DATA: IrqSafeSpinLock<EcdtInfo> = IrqSafeSpinLock::new(EcdtInfo {
    control_addr: 0,
    data_addr: 0,
    uid: 0,
    gpe_bit: 0,
});
static ECDT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_ecdt_body(body: &[u8]) {
    // SDT header (36) + EcControl GAS (12) + EcData GAS (12) +
    // Uid (4) + GpeBitNumber (1) + EcId (variable).
    if body.len() < SDT_HEADER_SIZE + 29 {
        return;
    }
    let off = SDT_HEADER_SIZE;
    // GAS.Address @ +4..12 of each GAS.
    let control_addr = u64::from_le_bytes([
        body[off + 4],
        body[off + 5],
        body[off + 6],
        body[off + 7],
        body[off + 8],
        body[off + 9],
        body[off + 10],
        body[off + 11],
    ]);
    let data_addr = u64::from_le_bytes([
        body[off + 16],
        body[off + 17],
        body[off + 18],
        body[off + 19],
        body[off + 20],
        body[off + 21],
        body[off + 22],
        body[off + 23],
    ]);
    let uid = u32::from_le_bytes([
        body[off + 24],
        body[off + 25],
        body[off + 26],
        body[off + 27],
    ]);
    let gpe_bit = body[off + 28];
    *ECDT_DATA.lock() = EcdtInfo {
        control_addr,
        data_addr,
        uid,
        gpe_bit,
    };
    ECDT_PARSED.store(true, Ordering::Release);
}

/// Discover the Embedded Controller via ECDT.
///
/// # Safety
/// `rsdp_phys` must point at an identity-mapped, checksum-valid RSDP,
/// and every table it transitively references (XSDT/RSDT and the ECDT)
/// must likewise be identity-mapped for the full `length` each header
/// advertises. The caller must guarantee the ACPI tables are not
/// concurrently remapped or freed for the duration of the call.
pub unsafe fn parse_ecdt(rsdp_phys: PhysAddr) -> Result<(), AcpiError> {
    // SAFETY: caller guarantees `rsdp_phys` points at an identity-mapped
    // RSDP large enough for `parse_rsdp`'s 36-byte read (its own contract).
    // SAFETY: Valid memory or trusted environment
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut ecdt: Option<u64> = None;
    // SAFETY: `xsdt` is the physical address `parse_rsdp` just validated;
    // the caller guarantees it (and its children) stay identity-mapped for
    // the table's advertised length, satisfying `walk_xsdt`'s contract. The
    // closure only records a child phys, no further dereference here.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"ECDT" {
                ecdt = Some(phys);
            }
        })?;
    }
    let ecdt_phys = match ecdt {
        Some(p) => p,
        None => return Ok(()),
    };

    // SAFETY: `ecdt_phys` is a child pointer reported by `walk_xsdt`, which
    // only yields it after confirming an `SdtHeader` is readable there;
    // `read_unaligned` tolerates any alignment of the firmware-placed table.
    // SAFETY: Valid memory or trusted environment
    let total = unsafe { (ecdt_phys as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 29 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: `total` is the header's self-reported `length`; the caller
    // guarantees the ECDT is identity-mapped for that full span, so the
    // `[u8; total]` slice stays within the mapped table.
    // SAFETY: Valid memory or trusted environment
    let body = unsafe { core::slice::from_raw_parts(ecdt_phys as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    // `parse_ecdt_body` already sets `ECDT_PARSED`.
    parse_ecdt_body(body);
    Ok(())
}

pub fn ecdt_info() -> Option<EcdtInfo> {
    if !ECDT_PARSED.load(Ordering::Acquire) {
        return None;
    }
    Some(*ECDT_DATA.lock())
}

#[doc(hidden)]
pub fn __test_parse_ecdt_body(body: &[u8]) {
    parse_ecdt_body(body);
    ECDT_PARSED.store(true, Ordering::Release);
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
        let len = body[cur + 1] as usize;
        if len < 2 || cur + len > body.len() {
            break;
        }
        let entry = &body[cur..cur + len];
        match kind {
            0 if entry.len() >= 16 => {
                let pd_low = entry[2] as u32;
                let pd_high = u32::from_le_bytes([entry[9], entry[10], entry[11], 0]) << 8;
                let proximity = pd_high | pd_low;
                let apic = entry[3] as u32;
                let flags = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
                if flags & 1 != 0 && (apic as usize) < MAX_CPUS {
                    CPU_NODE[apic as usize].store(proximity, Ordering::Release);
                    if (proximity as usize) < MAX_NUMA_NODES {
                        node_seen[proximity as usize] = true;
                    }
                    count += 1;
                }
            }
            1 if entry.len() >= 40 => {
                let proximity = u32::from_le_bytes([entry[2], entry[3], entry[4], entry[5]]);
                let base = u64::from_le_bytes([
                    entry[8], entry[9], entry[10], entry[11], entry[12], entry[13], entry[14],
                    entry[15],
                ]);
                let length = u64::from_le_bytes([
                    entry[16], entry[17], entry[18], entry[19], entry[20], entry[21], entry[22],
                    entry[23],
                ]);
                let flags = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);
                let enabled = flags & 1 != 0;
                if ranges.len < MAX_NUMA_RANGES {
                    let i = ranges.len;
                    ranges.entries[i] = MemRange {
                        base,
                        length,
                        node: proximity,
                        enabled,
                    };
                    ranges.len = i + 1;
                }
                if enabled && (proximity as usize) < MAX_NUMA_NODES {
                    node_seen[proximity as usize] = true;
                }
                count += 1;
            }
            2 if entry.len() >= 24 => {
                let proximity = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
                let x2apic = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
                let flags = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]);
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
    pub package: bool,
    pub thread: bool,
    pub leaf: bool,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct PpttCache {
    pub level: u8,
    pub line_bytes: u16,
    pub ways: u16,
    pub sets: u32,
    pub size_bytes: u32,
    pub kind: PpttCacheKind,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum PpttCacheKind {
    #[default]
    Unified,
    Data,
    Instruction,
}

struct PpttTables {
    cpus: [PpttCpu; MAX_PPTT_CPUS],
    caches: [PpttCache; MAX_PPTT_CACHES],
    n_cpus: usize,
    n_caches: usize,
}

impl PpttTables {
    const EMPTY: Self = Self {
        cpus: [PpttCpu {
            acpi_uid: 0,
            package: false,
            thread: false,
            leaf: false,
        }; MAX_PPTT_CPUS],
        caches: [PpttCache {
            level: 0,
            line_bytes: 0,
            ways: 0,
            sets: 0,
            size_bytes: 0,
            kind: PpttCacheKind::Unified,
        }; MAX_PPTT_CACHES],
        n_cpus: 0,
        n_caches: 0,
    };
}

static PPTT_DATA: IrqSafeSpinLock<PpttTables> = IrqSafeSpinLock::new(PpttTables::EMPTY);
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
        let len = body[cur + 1] as usize;
        if len < 4 || cur + len > body.len() {
            break;
        }
        let entry = &body[cur..cur + len];

        match kind {
            0 if entry.len() >= 20 => {
                let flags = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
                let acpi_uid = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]);
                if tables.n_cpus < MAX_PPTT_CPUS {
                    let i = tables.n_cpus;
                    tables.cpus[i] = PpttCpu {
                        acpi_uid,
                        package: flags & (1 << 0) != 0,
                        thread: flags & (1 << 2) != 0,
                        leaf: flags & (1 << 3) != 0,
                    };
                    tables.n_cpus = i + 1;
                    count += 1;
                }
            }
            1 if entry.len() >= 24 => {
                let size = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]);
                let sets = u32::from_le_bytes([entry[16], entry[17], entry[18], entry[19]]);
                let assoc = entry[20] as u16;
                let attrs = entry[21];
                let line = u16::from_le_bytes([entry[22], entry[23]]);
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
    let total = unsafe { (pptt as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(pptt as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    let n = parse_pptt_body(body);
    PPTT_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_pptt_known() -> bool {
    PPTT_PARSED.load(Ordering::Acquire)
}

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
pub const MAX_IORT_ITS: usize = 8;

#[derive(Copy, Clone, Debug, Default)]
pub struct IortSmmuv3 {
    pub base: u64,
    pub flags: u32,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct IortIts {
    pub its_id: u32,
}

struct IortTables {
    smmus: [IortSmmuv3; MAX_IORT_SMMUS],
    its: [IortIts; MAX_IORT_ITS],
    n_smmus: usize,
    n_its: usize,
}

impl IortTables {
    const EMPTY: Self = Self {
        smmus: [IortSmmuv3 { base: 0, flags: 0 }; MAX_IORT_SMMUS],
        its: [IortIts { its_id: 0 }; MAX_IORT_ITS],
        n_smmus: 0,
        n_its: 0,
    };
}

static IORT_DATA: IrqSafeSpinLock<IortTables> = IrqSafeSpinLock::new(IortTables::EMPTY);
static IORT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_iort_body(body: &[u8]) -> u32 {
    let mut tables = IORT_DATA.lock();
    *tables = IortTables::EMPTY;

    if body.len() < SDT_HEADER_SIZE + 12 {
        return 0;
    }
    let n_nodes = u32::from_le_bytes([
        body[SDT_HEADER_SIZE],
        body[SDT_HEADER_SIZE + 1],
        body[SDT_HEADER_SIZE + 2],
        body[SDT_HEADER_SIZE + 3],
    ]) as usize;
    let arr_off = u32::from_le_bytes([
        body[SDT_HEADER_SIZE + 4],
        body[SDT_HEADER_SIZE + 5],
        body[SDT_HEADER_SIZE + 6],
        body[SDT_HEADER_SIZE + 7],
    ]) as usize;

    let mut cur = arr_off;
    let mut count = 0u32;
    for _ in 0..n_nodes {
        if cur + 4 > body.len() {
            break;
        }
        let kind = body[cur];
        let len = u16::from_le_bytes([body[cur + 1], body[cur + 2]]) as usize;
        if len < 4 || cur + len > body.len() {
            break;
        }
        let entry = &body[cur..cur + len];

        match kind {
            0 if entry.len() >= 20 => {
                // ITS group: header (16 B) + ITS-id count (4 B) + ids[]
                let n = u32::from_le_bytes([entry[16], entry[17], entry[18], entry[19]]) as usize;
                let mut off = 20;
                for _ in 0..n {
                    if off + 4 > entry.len() {
                        break;
                    }
                    let id = u32::from_le_bytes([
                        entry[off],
                        entry[off + 1],
                        entry[off + 2],
                        entry[off + 3],
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
                    entry[16], entry[17], entry[18], entry[19], entry[20], entry[21], entry[22],
                    entry[23],
                ]);
                let flags = u32::from_le_bytes([entry[24], entry[25], entry[26], entry[27]]);
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
    let total = unsafe { (iort as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 12 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(iort as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    let n = parse_iort_body(body);
    IORT_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_iort_known() -> bool {
    IORT_PARSED.load(Ordering::Acquire)
}

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
    pub register_base: u64,
    pub segment: u16,
    pub include_all_pci: bool,
}

struct DmarTables {
    drhds: [DmarDrhd; MAX_DMAR_DRHDS],
    n_drhds: usize,
    intr_rmp: bool,
}

impl DmarTables {
    const EMPTY: Self = Self {
        drhds: [DmarDrhd {
            register_base: 0,
            segment: 0,
            include_all_pci: false,
        }; MAX_DMAR_DRHDS],
        n_drhds: 0,
        intr_rmp: false,
    };
}

static DMAR_DATA: IrqSafeSpinLock<DmarTables> = IrqSafeSpinLock::new(DmarTables::EMPTY);
static DMAR_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_dmar_body(body: &[u8]) -> u32 {
    let mut tables = DMAR_DATA.lock();
    *tables = DmarTables::EMPTY;
    if body.len() < SDT_HEADER_SIZE + 12 {
        return 0;
    }
    tables.intr_rmp = body[SDT_HEADER_SIZE + 1] & DMAR_FLAG_INTR_REMAP != 0;
    let mut cur = SDT_HEADER_SIZE + 12;
    let mut count = 0u32;
    while cur + 4 <= body.len() {
        let kind = u16::from_le_bytes([body[cur], body[cur + 1]]);
        let len = u16::from_le_bytes([body[cur + 2], body[cur + 3]]) as usize;
        if len < 4 || cur + len > body.len() {
            break;
        }
        let entry = &body[cur..cur + len];

        if kind == 0 && entry.len() >= 16 {
            // DRHD: [4] flags, [5] reserved, [6..8] segment, [8..16] base
            let flags = entry[4];
            let segment = u16::from_le_bytes([entry[6], entry[7]]);
            let base = u64::from_le_bytes([
                entry[8], entry[9], entry[10], entry[11], entry[12], entry[13], entry[14],
                entry[15],
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
    let total = unsafe { (dmar as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 12 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(dmar as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    let n = parse_dmar_body(body);
    DMAR_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_dmar_known() -> bool {
    DMAR_PARSED.load(Ordering::Acquire)
}

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
    pub base: u64,
    pub pci_segment: u16,
    pub capability_off: u16,
}

struct IvrsTables {
    iommus: [IvrsIommu; MAX_IVRS_IOMMUS],
    n_iommus: usize,
}

impl IvrsTables {
    const EMPTY: Self = Self {
        iommus: [IvrsIommu {
            base: 0,
            pci_segment: 0,
            capability_off: 0,
        }; MAX_IVRS_IOMMUS],
        n_iommus: 0,
    };
}

static IVRS_DATA: IrqSafeSpinLock<IvrsTables> = IrqSafeSpinLock::new(IvrsTables::EMPTY);
static IVRS_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_ivrs_body(body: &[u8]) -> u32 {
    let mut tables = IVRS_DATA.lock();
    *tables = IvrsTables::EMPTY;
    // Header: SDT_HEADER (36) + IvInfo (4) + reserved (8) = 48
    if body.len() < SDT_HEADER_SIZE + 12 {
        return 0;
    }
    let mut cur = SDT_HEADER_SIZE + 12;
    let mut count = 0u32;
    while cur + 4 <= body.len() {
        let kind = body[cur];
        let _flags = body[cur + 1];
        let len = u16::from_le_bytes([body[cur + 2], body[cur + 3]]) as usize;
        if len < 4 || cur + len > body.len() {
            break;
        }
        let entry = &body[cur..cur + len];

        // IVHD types 0x10 / 0x11 / 0x40
        if matches!(kind, 0x10 | 0x11 | 0x40) && entry.len() >= 24 {
            // device_id at [4..6], cap_off at [6..8], base at [8..16],
            // segment at [16..18]
            let cap_off = u16::from_le_bytes([entry[6], entry[7]]);
            let base = u64::from_le_bytes([
                entry[8], entry[9], entry[10], entry[11], entry[12], entry[13], entry[14],
                entry[15],
            ]);
            let segment = u16::from_le_bytes([entry[16], entry[17]]);
            if tables.n_iommus < MAX_IVRS_IOMMUS {
                let i = tables.n_iommus;
                tables.iommus[i] = IvrsIommu {
                    base,
                    pci_segment: segment,
                    capability_off: cap_off,
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
    let total = unsafe { (ivrs as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 12 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(ivrs as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    let n = parse_ivrs_body(body);
    IVRS_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_ivrs_known() -> bool {
    IVRS_PARSED.load(Ordering::Acquire)
}

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
    pub iface: u8,
    pub base: u64,
    pub addr_space_id: u8,
    pub gsi: u32,
    pub baud_code: u8,
    pub pci_device_id: u16,
}

static SPCR_DATA: IrqSafeSpinLock<SpcrInfo> = IrqSafeSpinLock::new(SpcrInfo {
    iface: 0,
    base: 0,
    addr_space_id: 0,
    gsi: 0,
    baud_code: 0,
    pci_device_id: 0,
});
static SPCR_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_spcr_body(body: &[u8]) {
    // SPCR rev 4 layout: SDT_HEADER (36) + InterfaceType (1) +
    // Reserved (3) + GAS (12) + InterruptType (1) + IRQ (1) +
    // GSI (4) + BaudRate (1) + Parity (1) + StopBits (1) +
    // FlowControl (1) + TerminalType (1) + Language (1) +
    // PciDeviceId (2) + …
    if body.len() < SDT_HEADER_SIZE + 36 {
        return;
    }
    let iface = body[SDT_HEADER_SIZE];
    let addr_space_id = body[SDT_HEADER_SIZE + 4];
    let base = u64::from_le_bytes([
        body[SDT_HEADER_SIZE + 8],
        body[SDT_HEADER_SIZE + 9],
        body[SDT_HEADER_SIZE + 10],
        body[SDT_HEADER_SIZE + 11],
        body[SDT_HEADER_SIZE + 12],
        body[SDT_HEADER_SIZE + 13],
        body[SDT_HEADER_SIZE + 14],
        body[SDT_HEADER_SIZE + 15],
    ]);
    let gsi = u32::from_le_bytes([
        body[SDT_HEADER_SIZE + 18],
        body[SDT_HEADER_SIZE + 19],
        body[SDT_HEADER_SIZE + 20],
        body[SDT_HEADER_SIZE + 21],
    ]);
    let baud_code = body[SDT_HEADER_SIZE + 22];
    let pci_device_id =
        u16::from_le_bytes([body[SDT_HEADER_SIZE + 28], body[SDT_HEADER_SIZE + 29]]);
    *SPCR_DATA.lock() = SpcrInfo {
        iface,
        base,
        addr_space_id,
        gsi,
        baud_code,
        pci_device_id,
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
    let total = unsafe { (spcr as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 36 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(spcr as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    parse_spcr_body(body);
    SPCR_PARSED.store(true, Ordering::Release);
    Ok(())
}

pub fn spcr_info() -> Option<SpcrInfo> {
    if !SPCR_PARSED.load(Ordering::Acquire) {
        return None;
    }
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

pub const MAX_HEST_MCE: usize = 16;
pub const MAX_HEST_GHES: usize = 16;

#[derive(Copy, Clone, Debug, Default)]
pub struct HestMceSource {
    pub source_id: u16,
    pub enabled: bool,
    pub num_hw_banks: u8,
    pub global_capability: u64,
    pub global_control: u64,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct HestGhesSource {
    pub source_id: u16,
    pub enabled: bool,
    pub max_sections_per_record: u32,
    pub error_status_block_addr: u64,
}

struct HestTables {
    mce: [HestMceSource; MAX_HEST_MCE],
    ghes: [HestGhesSource; MAX_HEST_GHES],
    n_mce: usize,
    n_ghes: usize,
}

impl HestTables {
    const EMPTY: Self = Self {
        mce: [HestMceSource {
            source_id: 0,
            enabled: false,
            num_hw_banks: 0,
            global_capability: 0,
            global_control: 0,
        }; MAX_HEST_MCE],
        ghes: [HestGhesSource {
            source_id: 0,
            enabled: false,
            max_sections_per_record: 0,
            error_status_block_addr: 0,
        }; MAX_HEST_GHES],
        n_mce: 0,
        n_ghes: 0,
    };
}

static HEST_DATA: IrqSafeSpinLock<HestTables> = IrqSafeSpinLock::new(HestTables::EMPTY);
static HEST_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_hest_body(body: &[u8]) -> u32 {
    let mut tables = HEST_DATA.lock();
    *tables = HestTables::EMPTY;
    if body.len() < SDT_HEADER_SIZE + 4 {
        return 0;
    }
    let n_sources = u32::from_le_bytes([
        body[SDT_HEADER_SIZE],
        body[SDT_HEADER_SIZE + 1],
        body[SDT_HEADER_SIZE + 2],
        body[SDT_HEADER_SIZE + 3],
    ]) as usize;

    let mut cur = SDT_HEADER_SIZE + 4;
    let mut count = 0u32;
    for _ in 0..n_sources {
        if cur + 2 > body.len() {
            break;
        }
        let kind = u16::from_le_bytes([body[cur], body[cur + 1]]);

        match kind {
            // Type 0: Machine Check.
            0 if cur + 92 <= body.len() => {
                let source_id = u16::from_le_bytes([body[cur + 2], body[cur + 3]]);
                let enabled = body[cur + 7] != 0;
                let global_capability = u64::from_le_bytes([
                    body[cur + 16],
                    body[cur + 17],
                    body[cur + 18],
                    body[cur + 19],
                    body[cur + 20],
                    body[cur + 21],
                    body[cur + 22],
                    body[cur + 23],
                ]);
                let global_control = u64::from_le_bytes([
                    body[cur + 24],
                    body[cur + 25],
                    body[cur + 26],
                    body[cur + 27],
                    body[cur + 28],
                    body[cur + 29],
                    body[cur + 30],
                    body[cur + 31],
                ]);
                let num_hw_banks = body[cur + 32];
                if tables.n_mce < MAX_HEST_MCE {
                    let i = tables.n_mce;
                    tables.mce[i] = HestMceSource {
                        source_id,
                        enabled,
                        num_hw_banks,
                        global_capability,
                        global_control,
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
                    body[cur + 12],
                    body[cur + 13],
                    body[cur + 14],
                    body[cur + 15],
                ]);
                // GAS.Address at offset cur + 24..32 of the GHES entry.
                let err_addr = u64::from_le_bytes([
                    body[cur + 24],
                    body[cur + 25],
                    body[cur + 26],
                    body[cur + 27],
                    body[cur + 28],
                    body[cur + 29],
                    body[cur + 30],
                    body[cur + 31],
                ]);
                if tables.n_ghes < MAX_HEST_GHES {
                    let i = tables.n_ghes;
                    tables.ghes[i] = HestGhesSource {
                        source_id,
                        enabled,
                        max_sections_per_record,
                        error_status_block_addr: err_addr,
                    };
                    tables.n_ghes = i + 1;
                    count += 1;
                }
                cur += if kind == 9 { 92 } else { 92 + 8 };
            }
            _ => break, // unknown type — bail rather than misparse the rest
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
    let total = unsafe { (hest as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 4 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(hest as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    let n = parse_hest_body(body);
    HEST_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_hest_known() -> bool {
    HEST_PARSED.load(Ordering::Acquire)
}

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
    pub kind: u8,
    pub shmem_base: u64,
    pub shmem_length: u64,
    pub doorbell_addr: u64,
    pub doorbell_write: u64,
    pub min_turnaround_us: u16,
}

struct PcctTables {
    chans: [PcctChannel; MAX_PCCT_CHANNELS],
    n_chans: usize,
}

impl PcctTables {
    const EMPTY: Self = Self {
        chans: [PcctChannel {
            kind: 0,
            shmem_base: 0,
            shmem_length: 0,
            doorbell_addr: 0,
            doorbell_write: 0,
            min_turnaround_us: 0,
        }; MAX_PCCT_CHANNELS],
        n_chans: 0,
    };
}

static PCCT_DATA: IrqSafeSpinLock<PcctTables> = IrqSafeSpinLock::new(PcctTables::EMPTY);
static PCCT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_pcct_body(body: &[u8]) -> u32 {
    let mut tables = PCCT_DATA.lock();
    *tables = PcctTables::EMPTY;
    if body.len() < SDT_HEADER_SIZE + 12 {
        return 0;
    }
    let mut cur = SDT_HEADER_SIZE + 12;
    let mut count = 0u32;
    while cur + 2 <= body.len() {
        let kind = body[cur];
        let len = body[cur + 1] as usize;
        if len < 2 || cur + len > body.len() {
            break;
        }
        let entry = &body[cur..cur + len];

        if matches!(kind, 0..=2) && entry.len() >= 62 {
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
                entry[8], entry[9], entry[10], entry[11], entry[12], entry[13], entry[14],
                entry[15],
            ]);
            let shmem_length = u64::from_le_bytes([
                entry[16], entry[17], entry[18], entry[19], entry[20], entry[21], entry[22],
                entry[23],
            ]);
            let doorbell_addr = u64::from_le_bytes([
                entry[28], entry[29], entry[30], entry[31], entry[32], entry[33], entry[34],
                entry[35],
            ]);
            let doorbell_write = u64::from_le_bytes([
                entry[44], entry[45], entry[46], entry[47], entry[48], entry[49], entry[50],
                entry[51],
            ]);
            let min_turnaround_us = u16::from_le_bytes([entry[60], entry[61]]);
            if tables.n_chans < MAX_PCCT_CHANNELS {
                let i = tables.n_chans;
                tables.chans[i] = PcctChannel {
                    kind,
                    shmem_base,
                    shmem_length,
                    doorbell_addr,
                    doorbell_write,
                    min_turnaround_us,
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
    let total = unsafe { (pcct as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 12 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(pcct as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    let n = parse_pcct_body(body);
    PCCT_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_pcct_known() -> bool {
    PCCT_PARSED.load(Ordering::Acquire)
}

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
    matrix: [[u8; MAX_SLIT_NODES]; MAX_SLIT_NODES],
}

impl SlitTables {
    const EMPTY: Self = Self {
        locality_count: 0,
        matrix: [[0u8; MAX_SLIT_NODES]; MAX_SLIT_NODES],
    };
}

static SLIT_DATA: IrqSafeSpinLock<SlitTables> = IrqSafeSpinLock::new(SlitTables::EMPTY);
static SLIT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_slit_body(body: &[u8]) -> u32 {
    let mut tables = SLIT_DATA.lock();
    *tables = SlitTables::EMPTY;
    if body.len() < SDT_HEADER_SIZE + 8 {
        return 0;
    }
    let n = u64::from_le_bytes([
        body[SDT_HEADER_SIZE],
        body[SDT_HEADER_SIZE + 1],
        body[SDT_HEADER_SIZE + 2],
        body[SDT_HEADER_SIZE + 3],
        body[SDT_HEADER_SIZE + 4],
        body[SDT_HEADER_SIZE + 5],
        body[SDT_HEADER_SIZE + 6],
        body[SDT_HEADER_SIZE + 7],
    ]) as usize;
    let n = n.min(MAX_SLIT_NODES);
    if body.len() < SDT_HEADER_SIZE + 8 + n * n {
        return 0;
    }
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
    let total = unsafe { (slit as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 8 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(slit as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    let n = parse_slit_body(body);
    SLIT_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_slit_known() -> bool {
    SLIT_PARSED.load(Ordering::Acquire)
}

pub fn slit_distance(from: u8, to: u8) -> Option<u8> {
    if !is_slit_known() {
        return None;
    }
    let t = SLIT_DATA.lock();
    if (from as u32) >= t.locality_count || (to as u32) >= t.locality_count {
        return None;
    }
    Some(t.matrix[from as usize][to as usize])
}

pub fn slit_locality_count() -> u32 {
    SLIT_DATA.lock().locality_count
}

/// Linux's `LOCAL_DISTANCE` — the ACPI-mandated distance from a node
/// to itself (SLIT diagonal). See `include/linux/topology.h`.
pub const LOCAL_DISTANCE: u8 = 10;

/// Linux's `REMOTE_DISTANCE` — the conventional distance to a
/// different node when no SLIT is present. See
/// `include/linux/topology.h`.
pub const REMOTE_DISTANCE: u8 = 20;

/// NUMA distance from node `from` to node `to`, following the Linux
/// `node_distance()` contract (`drivers/base/arch_numa.c` /
/// `arch/x86/mm/numa.c`).
///
/// - When SLIT is parsed and both localities are in range, returns the
///   parsed matrix entry.
/// - Otherwise falls back to the Linux convention: `LOCAL_DISTANCE`
///   (10) for a node to itself, `REMOTE_DISTANCE` (20) across nodes.
///
/// This is the single public distance accessor the allocator,
/// scheduler, and sysfs all consume so the fallback is uniform.
pub fn node_distance(from: u32, to: u32) -> u8 {
    if is_slit_known() {
        let t = SLIT_DATA.lock();
        if from < t.locality_count && to < t.locality_count {
            return t.matrix[from as usize][to as usize];
        }
    }
    if from == to {
        LOCAL_DISTANCE
    } else {
        REMOTE_DISTANCE
    }
}

/// Number of NUMA nodes the distance machinery should iterate over.
///
/// Prefers the SLIT locality count (the authoritative distance-matrix
/// dimension); falls back to the SRAT-derived proximity-domain count,
/// and finally to 1 (single flat node) so callers always get a sane,
/// non-zero bound.
pub fn numa_node_count() -> u32 {
    let slit = slit_locality_count();
    if slit > 0 {
        return slit;
    }
    node_count().max(1)
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

pub const MAX_CEDT_CHBS: usize = 8;
pub const MAX_CEDT_CFMWS: usize = 8;

#[derive(Copy, Clone, Debug, Default)]
pub struct CedtChbs {
    pub uid: u32,
    pub cxl_ver: u32,
    pub base: u64,
    pub length: u64,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct CedtCfmws {
    pub base_hpa: u64,
    pub window_size: u64,
    pub encoded_iw: u8,
}

struct CedtTables {
    chbs: [CedtChbs; MAX_CEDT_CHBS],
    cfmws: [CedtCfmws; MAX_CEDT_CFMWS],
    n_chbs: usize,
    n_cfmws: usize,
}

impl CedtTables {
    const EMPTY: Self = Self {
        chbs: [CedtChbs {
            uid: 0,
            cxl_ver: 0,
            base: 0,
            length: 0,
        }; MAX_CEDT_CHBS],
        cfmws: [CedtCfmws {
            base_hpa: 0,
            window_size: 0,
            encoded_iw: 0,
        }; MAX_CEDT_CFMWS],
        n_chbs: 0,
        n_cfmws: 0,
    };
}

static CEDT_DATA: IrqSafeSpinLock<CedtTables> = IrqSafeSpinLock::new(CedtTables::EMPTY);
static CEDT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_cedt_body(body: &[u8]) -> u32 {
    let mut tables = CEDT_DATA.lock();
    *tables = CedtTables::EMPTY;
    let mut cur = SDT_HEADER_SIZE;
    let mut count = 0u32;
    while cur + 4 <= body.len() {
        let kind = body[cur];
        let len = u16::from_le_bytes([body[cur + 2], body[cur + 3]]) as usize;
        if len < 4 || cur + len > body.len() {
            break;
        }
        let entry = &body[cur..cur + len];

        match kind {
            // CHBS — CXL Host Bridge Structure (length 32).
            0 if entry.len() >= 32 => {
                let uid = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
                let cxl_ver = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
                let base = u64::from_le_bytes([
                    entry[16], entry[17], entry[18], entry[19], entry[20], entry[21], entry[22],
                    entry[23],
                ]);
                let length = u64::from_le_bytes([
                    entry[24], entry[25], entry[26], entry[27], entry[28], entry[29], entry[30],
                    entry[31],
                ]);
                if tables.n_chbs < MAX_CEDT_CHBS {
                    let i = tables.n_chbs;
                    tables.chbs[i] = CedtChbs {
                        uid,
                        cxl_ver,
                        base,
                        length,
                    };
                    tables.n_chbs = i + 1;
                    count += 1;
                }
            }
            // CFMWS — CXL Fixed Memory Window (variable length, ≥36).
            1 if entry.len() >= 36 => {
                let base_hpa = u64::from_le_bytes([
                    entry[8], entry[9], entry[10], entry[11], entry[12], entry[13], entry[14],
                    entry[15],
                ]);
                let window_size = u64::from_le_bytes([
                    entry[16], entry[17], entry[18], entry[19], entry[20], entry[21], entry[22],
                    entry[23],
                ]);
                let encoded_iw = entry[24];
                if tables.n_cfmws < MAX_CEDT_CFMWS {
                    let i = tables.n_cfmws;
                    tables.cfmws[i] = CedtCfmws {
                        base_hpa,
                        window_size,
                        encoded_iw,
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
    let total = unsafe { (cedt as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(cedt as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    let n = parse_cedt_body(body);
    CEDT_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_cedt_known() -> bool {
    CEDT_PARSED.load(Ordering::Acquire)
}

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
    pub region_addr: u64,
    pub region_length: u32,
}

static BERT_DATA: IrqSafeSpinLock<BertInfo> = IrqSafeSpinLock::new(BertInfo {
    region_addr: 0,
    region_length: 0,
});
static BERT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_bert_body(body: &[u8]) {
    if body.len() < SDT_HEADER_SIZE + 12 {
        return;
    }
    let region_length = u32::from_le_bytes([
        body[SDT_HEADER_SIZE],
        body[SDT_HEADER_SIZE + 1],
        body[SDT_HEADER_SIZE + 2],
        body[SDT_HEADER_SIZE + 3],
    ]);
    let region_addr = u64::from_le_bytes([
        body[SDT_HEADER_SIZE + 4],
        body[SDT_HEADER_SIZE + 5],
        body[SDT_HEADER_SIZE + 6],
        body[SDT_HEADER_SIZE + 7],
        body[SDT_HEADER_SIZE + 8],
        body[SDT_HEADER_SIZE + 9],
        body[SDT_HEADER_SIZE + 10],
        body[SDT_HEADER_SIZE + 11],
    ]);
    *BERT_DATA.lock() = BertInfo {
        region_addr,
        region_length,
    };
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
    let total = unsafe { (bert as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 12 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(bert as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    parse_bert_body(body);
    BERT_PARSED.store(true, Ordering::Release);
    Ok(())
}

pub fn bert_info() -> Option<BertInfo> {
    if !BERT_PARSED.load(Ordering::Acquire) {
        return None;
    }
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
    pub kind: u8,
    pub iface: u8,
    pub base: u64,
}

struct AestTables {
    nodes: [AestNode; MAX_AEST_NODES],
    n_nodes: usize,
}

impl AestTables {
    const EMPTY: Self = Self {
        nodes: [AestNode {
            kind: 0,
            iface: 0,
            base: 0,
        }; MAX_AEST_NODES],
        n_nodes: 0,
    };
}

static AEST_DATA: IrqSafeSpinLock<AestTables> = IrqSafeSpinLock::new(AestTables::EMPTY);
static AEST_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_aest_body(body: &[u8]) -> u32 {
    let mut tables = AEST_DATA.lock();
    *tables = AestTables::EMPTY;
    let mut cur = SDT_HEADER_SIZE;
    let mut count = 0u32;
    while cur + 12 <= body.len() {
        let kind = body[cur];
        let len = u16::from_le_bytes([body[cur + 2], body[cur + 3]]) as usize;
        if len < 12 || cur + len > body.len() {
            break;
        }
        let entry = &body[cur..cur + len];
        let iface_off = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]) as usize;
        // Interface block: [0] = Type (0 = SR, 1 = MMIO),
        //                  [4..12] = BaseAddress (for MMIO).
        if iface_off + 12 <= entry.len() {
            let iface = entry[iface_off];
            let base = u64::from_le_bytes([
                entry[iface_off + 4],
                entry[iface_off + 5],
                entry[iface_off + 6],
                entry[iface_off + 7],
                entry[iface_off + 8],
                entry[iface_off + 9],
                entry[iface_off + 10],
                entry[iface_off + 11],
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
    let total = unsafe { (aest as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(aest as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    let n = parse_aest_body(body);
    AEST_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_aest_known() -> bool {
    AEST_PARSED.load(Ordering::Acquire)
}

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
    let total = unsafe { (sdei as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(sdei as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    SDEI_PARSED.store(true, Ordering::Release);
    Ok(())
}

pub fn is_sdei_known() -> bool {
    SDEI_PARSED.load(Ordering::Acquire)
}

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
    pub period_us: u16,
    pub status: u16,
    pub capability: u16,
    pub base: u64,
}

static WDDT_DATA: IrqSafeSpinLock<WddtInfo> = IrqSafeSpinLock::new(WddtInfo {
    timer_max_count: 0,
    timer_min_count: 0,
    period_us: 0,
    status: 0,
    capability: 0,
    base: 0,
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
    if body.len() < SDT_HEADER_SIZE + 6 + 12 + 10 {
        return;
    }
    let off = SDT_HEADER_SIZE + 6;
    // GAS at off..off+12; address at off+4..off+12.
    let base = u64::from_le_bytes([
        body[off + 4],
        body[off + 5],
        body[off + 6],
        body[off + 7],
        body[off + 8],
        body[off + 9],
        body[off + 10],
        body[off + 11],
    ]);
    let mc_off = off + 12;
    let timer_max_count = u16::from_le_bytes([body[mc_off], body[mc_off + 1]]);
    let timer_min_count = u16::from_le_bytes([body[mc_off + 2], body[mc_off + 3]]);
    let period_us = u16::from_le_bytes([body[mc_off + 4], body[mc_off + 5]]);
    let status = u16::from_le_bytes([body[mc_off + 6], body[mc_off + 7]]);
    let capability = u16::from_le_bytes([body[mc_off + 8], body[mc_off + 9]]);
    *WDDT_DATA.lock() = WddtInfo {
        timer_max_count,
        timer_min_count,
        period_us,
        status,
        capability,
        base,
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
    let total = unsafe { (wddt as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(wddt as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    parse_wddt_body(body);
    WDDT_PARSED.store(true, Ordering::Release);
    Ok(())
}

pub fn wddt_info() -> Option<WddtInfo> {
    if !WDDT_PARSED.load(Ordering::Acquire) {
        return None;
    }
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
    pub uid: u32,
    pub trigger_addr: u64,
    pub residency: u32,
    pub latency: u32,
    pub counter_addr: u64,
    pub counter_freq: u64,
}

struct LpitTables {
    states: [LpitState; MAX_LPIT_STATES],
    n_states: usize,
}

impl LpitTables {
    const EMPTY: Self = Self {
        states: [LpitState {
            uid: 0,
            trigger_addr: 0,
            residency: 0,
            latency: 0,
            counter_addr: 0,
            counter_freq: 0,
        }; MAX_LPIT_STATES],
        n_states: 0,
    };
}

static LPIT_DATA: IrqSafeSpinLock<LpitTables> = IrqSafeSpinLock::new(LpitTables::EMPTY);
static LPIT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_lpit_body(body: &[u8]) -> u32 {
    let mut tables = LPIT_DATA.lock();
    *tables = LpitTables::EMPTY;
    let mut cur = SDT_HEADER_SIZE;
    let mut count = 0u32;
    while cur + 8 <= body.len() {
        let kind = u32::from_le_bytes([body[cur], body[cur + 1], body[cur + 2], body[cur + 3]]);
        let len = u32::from_le_bytes([body[cur + 4], body[cur + 5], body[cur + 6], body[cur + 7]])
            as usize;
        if len < 8 || cur + len > body.len() {
            break;
        }
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
                entry[20], entry[21], entry[22], entry[23], entry[24], entry[25], entry[26],
                entry[27],
            ]);
            let residency = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);
            let latency = u32::from_le_bytes([entry[32], entry[33], entry[34], entry[35]]);
            let counter_addr = u64::from_le_bytes([
                entry[40], entry[41], entry[42], entry[43], entry[44], entry[45], entry[46],
                entry[47],
            ]);
            let counter_freq = u64::from_le_bytes([
                entry[48], entry[49], entry[50], entry[51], entry[52], entry[53], entry[54],
                entry[55],
            ]);
            if tables.n_states < MAX_LPIT_STATES {
                let i = tables.n_states;
                tables.states[i] = LpitState {
                    uid,
                    trigger_addr,
                    residency,
                    latency,
                    counter_addr,
                    counter_freq,
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
    let total = unsafe { (lpit as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(lpit as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    let n = parse_lpit_body(body);
    LPIT_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_lpit_known() -> bool {
    LPIT_PARSED.load(Ordering::Acquire)
}

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
    pub proximity: u32,
    pub base: u64,
    pub length: u64,
    pub mem_attr: u64,
}

struct NfitTables {
    spa_ranges: [NfitSpaRange; MAX_NFIT_SPA_RANGES],
    n_spa_ranges: usize,
}

impl NfitTables {
    const EMPTY: Self = Self {
        spa_ranges: [NfitSpaRange {
            range_index: 0,
            proximity: 0,
            base: 0,
            length: 0,
            mem_attr: 0,
        }; MAX_NFIT_SPA_RANGES],
        n_spa_ranges: 0,
    };
}

static NFIT_DATA: IrqSafeSpinLock<NfitTables> = IrqSafeSpinLock::new(NfitTables::EMPTY);
static NFIT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_nfit_body(body: &[u8]) -> u32 {
    let mut tables = NFIT_DATA.lock();
    *tables = NfitTables::EMPTY;
    // NFIT body starts at SDT_HEADER_SIZE + 4 (4-byte Reserved).
    if body.len() < SDT_HEADER_SIZE + 4 {
        return 0;
    }
    let mut cur = SDT_HEADER_SIZE + 4;
    let mut count = 0u32;
    while cur + 4 <= body.len() {
        let kind = u16::from_le_bytes([body[cur], body[cur + 1]]);
        let len = u16::from_le_bytes([body[cur + 2], body[cur + 3]]) as usize;
        if len < 4 || cur + len > body.len() {
            break;
        }
        let entry = &body[cur..cur + len];

        // SPA Range subtable: type 0, length 56.
        // Layout:
        //   0..2 Type, 2..4 Length, 4..6 RangeIndex, 6..8 Flags,
        //   8..12 Reserved, 12..16 Proximity, 16..32 Guid,
        //   32..40 Base, 40..48 Length, 48..56 MemoryMappingAttribute
        if kind == 0 && entry.len() >= 56 {
            let range_index = u16::from_le_bytes([entry[4], entry[5]]);
            let proximity = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]);
            let base = u64::from_le_bytes([
                entry[32], entry[33], entry[34], entry[35], entry[36], entry[37], entry[38],
                entry[39],
            ]);
            let length = u64::from_le_bytes([
                entry[40], entry[41], entry[42], entry[43], entry[44], entry[45], entry[46],
                entry[47],
            ]);
            let mem_attr = u64::from_le_bytes([
                entry[48], entry[49], entry[50], entry[51], entry[52], entry[53], entry[54],
                entry[55],
            ]);
            if tables.n_spa_ranges < MAX_NFIT_SPA_RANGES {
                let i = tables.n_spa_ranges;
                tables.spa_ranges[i] = NfitSpaRange {
                    range_index,
                    proximity,
                    base,
                    length,
                    mem_attr,
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
    let total = unsafe { (nfit as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 4 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(nfit as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    let n = parse_nfit_body(body);
    NFIT_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_nfit_known() -> bool {
    NFIT_PARSED.load(Ordering::Acquire)
}

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

// ───────────────────────────────────────────────────────────────────
// ERST / EINJ — RAS instruction streams.
// Spec: `acpi/specification/tables-ras-tpm-debug.md` §1 + §2.
// ───────────────────────────────────────────────────────────────────

pub const MAX_ERST_INSTRUCTIONS: usize = 64;
pub const MAX_EINJ_INSTRUCTIONS: usize = 64;

#[derive(Copy, Clone, Debug, Default)]
pub struct ErstInstruction {
    pub action: u8,
    pub instruction: u8,
    pub addr: u64,
    pub value: u64,
    pub mask: u64,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct EinjInstruction {
    pub action: u8,
    pub instruction: u8,
    pub addr: u64,
    pub value: u64,
    pub mask: u64,
}

struct ErstTables {
    insns: [ErstInstruction; MAX_ERST_INSTRUCTIONS],
    n_insns: usize,
}
struct EinjTables {
    insns: [EinjInstruction; MAX_EINJ_INSTRUCTIONS],
    n_insns: usize,
}

impl ErstTables {
    const EMPTY: Self = Self {
        insns: [ErstInstruction {
            action: 0,
            instruction: 0,
            addr: 0,
            value: 0,
            mask: 0,
        }; MAX_ERST_INSTRUCTIONS],
        n_insns: 0,
    };
}
impl EinjTables {
    const EMPTY: Self = Self {
        insns: [EinjInstruction {
            action: 0,
            instruction: 0,
            addr: 0,
            value: 0,
            mask: 0,
        }; MAX_EINJ_INSTRUCTIONS],
        n_insns: 0,
    };
}

static ERST_DATA: IrqSafeSpinLock<ErstTables> = IrqSafeSpinLock::new(ErstTables::EMPTY);
static ERST_PARSED: AtomicBool = AtomicBool::new(false);
static EINJ_DATA: IrqSafeSpinLock<EinjTables> = IrqSafeSpinLock::new(EinjTables::EMPTY);
static EINJ_PARSED: AtomicBool = AtomicBool::new(false);

/// Decode N 32-byte ERST/EINJ instruction entries starting at
/// `entries`. Each entry layout (offsets within entry):
///   0 action / 1 instruction / 2 flags / 3 reserved
///   4..16 RegisterRegion GAS (Address @ +8..16)
///   16..24 Value
///   24..32 Mask
fn decode_ras_insns<F: FnMut(u8, u8, u64, u64, u64)>(entries: &[u8], n: usize, mut emit: F) {
    let mut cur = 0usize;
    let mut left = n;
    while left > 0 && cur + 32 <= entries.len() {
        let action = entries[cur];
        let instruction = entries[cur + 1];
        let addr = u64::from_le_bytes([
            entries[cur + 8],
            entries[cur + 9],
            entries[cur + 10],
            entries[cur + 11],
            entries[cur + 12],
            entries[cur + 13],
            entries[cur + 14],
            entries[cur + 15],
        ]);
        let value = u64::from_le_bytes([
            entries[cur + 16],
            entries[cur + 17],
            entries[cur + 18],
            entries[cur + 19],
            entries[cur + 20],
            entries[cur + 21],
            entries[cur + 22],
            entries[cur + 23],
        ]);
        let mask = u64::from_le_bytes([
            entries[cur + 24],
            entries[cur + 25],
            entries[cur + 26],
            entries[cur + 27],
            entries[cur + 28],
            entries[cur + 29],
            entries[cur + 30],
            entries[cur + 31],
        ]);
        emit(action, instruction, addr, value, mask);
        cur += 32;
        left -= 1;
    }
}

fn parse_erst_body(body: &[u8]) -> u32 {
    let mut tables = ERST_DATA.lock();
    *tables = ErstTables::EMPTY;
    if body.len() < SDT_HEADER_SIZE + 12 {
        return 0;
    }
    let n = u32::from_le_bytes([
        body[SDT_HEADER_SIZE + 8],
        body[SDT_HEADER_SIZE + 9],
        body[SDT_HEADER_SIZE + 10],
        body[SDT_HEADER_SIZE + 11],
    ]) as usize;
    let entries = &body[SDT_HEADER_SIZE + 12..];
    let mut count = 0u32;
    decode_ras_insns(entries, n, |action, instruction, addr, value, mask| {
        if tables.n_insns < MAX_ERST_INSTRUCTIONS {
            let i = tables.n_insns;
            tables.insns[i] = ErstInstruction {
                action,
                instruction,
                addr,
                value,
                mask,
            };
            tables.n_insns = i + 1;
            count += 1;
        }
    });
    count
}

fn parse_einj_body(body: &[u8]) -> u32 {
    let mut tables = EINJ_DATA.lock();
    *tables = EinjTables::EMPTY;
    if body.len() < SDT_HEADER_SIZE + 12 {
        return 0;
    }
    let n = u32::from_le_bytes([
        body[SDT_HEADER_SIZE + 8],
        body[SDT_HEADER_SIZE + 9],
        body[SDT_HEADER_SIZE + 10],
        body[SDT_HEADER_SIZE + 11],
    ]) as usize;
    let entries = &body[SDT_HEADER_SIZE + 12..];
    let mut count = 0u32;
    decode_ras_insns(entries, n, |action, instruction, addr, value, mask| {
        if tables.n_insns < MAX_EINJ_INSTRUCTIONS {
            let i = tables.n_insns;
            tables.insns[i] = EinjInstruction {
                action,
                instruction,
                addr,
                value,
                mask,
            };
            tables.n_insns = i + 1;
            count += 1;
        }
    });
    count
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → ERST must also be identity-mapped.
pub unsafe fn parse_erst(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut erst: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"ERST" && erst.is_none() {
                erst = Some(phys);
            }
        })?;
    }
    let erst = erst.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (erst as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 12 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(erst as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    let n = parse_erst_body(body);
    ERST_PARSED.store(true, Ordering::Release);
    Ok(n)
}

/// # Safety
/// As `parse_erst`.
pub unsafe fn parse_einj(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut einj: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"EINJ" && einj.is_none() {
                einj = Some(phys);
            }
        })?;
    }
    let einj = einj.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (einj as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 12 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(einj as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    let n = parse_einj_body(body);
    EINJ_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_erst_known() -> bool {
    ERST_PARSED.load(Ordering::Acquire)
}
pub fn is_einj_known() -> bool {
    EINJ_PARSED.load(Ordering::Acquire)
}

pub fn copy_erst_instructions(out: &mut [ErstInstruction]) -> usize {
    let t = ERST_DATA.lock();
    let n = t.n_insns.min(out.len());
    out[..n].copy_from_slice(&t.insns[..n]);
    n
}

pub fn copy_einj_instructions(out: &mut [EinjInstruction]) -> usize {
    let t = EINJ_DATA.lock();
    let n = t.n_insns.min(out.len());
    out[..n].copy_from_slice(&t.insns[..n]);
    n
}

#[doc(hidden)]
pub fn __test_parse_erst_body(body: &[u8]) -> u32 {
    let n = parse_erst_body(body);
    ERST_PARSED.store(true, Ordering::Release);
    n
}

#[doc(hidden)]
pub fn __test_parse_einj_body(body: &[u8]) -> u32 {
    let n = parse_einj_body(body);
    EINJ_PARSED.store(true, Ordering::Release);
    n
}

// ───────────────────────────────────────────────────────────────────
// TPM2 — Trusted Platform Module 2.0 Table.
// Spec: `acpi/specification/tables-ras-tpm-debug.md` §3.
// ───────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct Tpm2Info {
    pub platform_class: u16,
    pub control_area_addr: u64,
    pub start_method: u32,
}

static TPM2_DATA: IrqSafeSpinLock<Tpm2Info> = IrqSafeSpinLock::new(Tpm2Info {
    platform_class: 0,
    control_area_addr: 0,
    start_method: 0,
});
static TPM2_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_tpm2_body(body: &[u8]) {
    if body.len() < SDT_HEADER_SIZE + 16 {
        return;
    }
    let off = SDT_HEADER_SIZE;
    let platform_class = u16::from_le_bytes([body[off], body[off + 1]]);
    let control_area_addr = u64::from_le_bytes([
        body[off + 4],
        body[off + 5],
        body[off + 6],
        body[off + 7],
        body[off + 8],
        body[off + 9],
        body[off + 10],
        body[off + 11],
    ]);
    let start_method = u32::from_le_bytes([
        body[off + 12],
        body[off + 13],
        body[off + 14],
        body[off + 15],
    ]);
    *TPM2_DATA.lock() = Tpm2Info {
        platform_class,
        control_area_addr,
        start_method,
    };
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → TPM2 must also be identity-mapped.
pub unsafe fn parse_tpm2(rsdp_phys: PhysAddr) -> Result<(), AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut tpm2: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"TPM2" && tpm2.is_none() {
                tpm2 = Some(phys);
            }
        })?;
    }
    let tpm2 = tpm2.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (tpm2 as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 16 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(tpm2 as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    parse_tpm2_body(body);
    TPM2_PARSED.store(true, Ordering::Release);
    Ok(())
}

pub fn tpm2_info() -> Option<Tpm2Info> {
    if !TPM2_PARSED.load(Ordering::Acquire) {
        return None;
    }
    Some(*TPM2_DATA.lock())
}

#[doc(hidden)]
pub fn __test_parse_tpm2_body(body: &[u8]) {
    parse_tpm2_body(body);
    TPM2_PARSED.store(true, Ordering::Release);
}

// ───────────────────────────────────────────────────────────────────
// BGRT — Boot Graphics Resource Table.
// Spec: `acpi/specification/tables-ras-tpm-debug.md` §4.
// ───────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct BgrtInfo {
    pub status: u8,
    pub image_address: u64,
    pub offset_x: u32,
    pub offset_y: u32,
}

static BGRT_DATA: IrqSafeSpinLock<BgrtInfo> = IrqSafeSpinLock::new(BgrtInfo {
    status: 0,
    image_address: 0,
    offset_x: 0,
    offset_y: 0,
});
static BGRT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_bgrt_body(body: &[u8]) {
    // Body offsets: Version (2) + Status (1) + ImageType (1) +
    //               ImageAddress (8) + OffsetX (4) + OffsetY (4)
    if body.len() < SDT_HEADER_SIZE + 20 {
        return;
    }
    let off = SDT_HEADER_SIZE;
    let status = body[off + 2];
    let image_address = u64::from_le_bytes([
        body[off + 4],
        body[off + 5],
        body[off + 6],
        body[off + 7],
        body[off + 8],
        body[off + 9],
        body[off + 10],
        body[off + 11],
    ]);
    let offset_x = u32::from_le_bytes([
        body[off + 12],
        body[off + 13],
        body[off + 14],
        body[off + 15],
    ]);
    let offset_y = u32::from_le_bytes([
        body[off + 16],
        body[off + 17],
        body[off + 18],
        body[off + 19],
    ]);
    *BGRT_DATA.lock() = BgrtInfo {
        status,
        image_address,
        offset_x,
        offset_y,
    };
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → BGRT must also be identity-mapped.
pub unsafe fn parse_bgrt(rsdp_phys: PhysAddr) -> Result<(), AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut bgrt: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"BGRT" && bgrt.is_none() {
                bgrt = Some(phys);
            }
        })?;
    }
    let bgrt = bgrt.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (bgrt as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 20 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(bgrt as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    parse_bgrt_body(body);
    BGRT_PARSED.store(true, Ordering::Release);
    Ok(())
}

pub fn bgrt_info() -> Option<BgrtInfo> {
    if !BGRT_PARSED.load(Ordering::Acquire) {
        return None;
    }
    Some(*BGRT_DATA.lock())
}

#[doc(hidden)]
pub fn __test_parse_bgrt_body(body: &[u8]) {
    parse_bgrt_body(body);
    BGRT_PARSED.store(true, Ordering::Release);
}

// ───────────────────────────────────────────────────────────────────
// DBG2 — Debug Port Table 2.
// Spec: `acpi/specification/tables-ras-tpm-debug.md` §5.
// ───────────────────────────────────────────────────────────────────

pub const MAX_DBG2_DEVICES: usize = 8;

#[derive(Copy, Clone, Debug, Default)]
pub struct Dbg2Device {
    pub port_type: u16,
    pub port_subtype: u16,
    pub base_addr: u64,
}

struct Dbg2Tables {
    devs: [Dbg2Device; MAX_DBG2_DEVICES],
    n_devs: usize,
}

impl Dbg2Tables {
    const EMPTY: Self = Self {
        devs: [Dbg2Device {
            port_type: 0,
            port_subtype: 0,
            base_addr: 0,
        }; MAX_DBG2_DEVICES],
        n_devs: 0,
    };
}

static DBG2_DATA: IrqSafeSpinLock<Dbg2Tables> = IrqSafeSpinLock::new(Dbg2Tables::EMPTY);
static DBG2_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_dbg2_body(body: &[u8]) -> u32 {
    let mut tables = DBG2_DATA.lock();
    *tables = Dbg2Tables::EMPTY;
    if body.len() < SDT_HEADER_SIZE + 8 {
        return 0;
    }
    let info_off = u32::from_le_bytes([
        body[SDT_HEADER_SIZE],
        body[SDT_HEADER_SIZE + 1],
        body[SDT_HEADER_SIZE + 2],
        body[SDT_HEADER_SIZE + 3],
    ]) as usize;
    let info_count = u32::from_le_bytes([
        body[SDT_HEADER_SIZE + 4],
        body[SDT_HEADER_SIZE + 5],
        body[SDT_HEADER_SIZE + 6],
        body[SDT_HEADER_SIZE + 7],
    ]) as usize;
    let mut cur = info_off;
    let mut count = 0u32;
    for _ in 0..info_count {
        if cur + 22 > body.len() {
            break;
        }
        let len = u16::from_le_bytes([body[cur + 1], body[cur + 2]]) as usize;
        if len < 22 || cur + len > body.len() {
            break;
        }
        let entry = &body[cur..cur + len];
        // BaseAddrRegOffset @ entry[18..20] points to a GAS array.
        let bar_off = u16::from_le_bytes([entry[18], entry[19]]) as usize;
        let port_type = u16::from_le_bytes([entry[12], entry[13]]);
        let port_subtype = u16::from_le_bytes([entry[14], entry[15]]);
        // First GAS at bar_off; address @ bar_off + 4..bar_off + 12.
        let base_addr = if bar_off + 12 <= entry.len() {
            u64::from_le_bytes([
                entry[bar_off + 4],
                entry[bar_off + 5],
                entry[bar_off + 6],
                entry[bar_off + 7],
                entry[bar_off + 8],
                entry[bar_off + 9],
                entry[bar_off + 10],
                entry[bar_off + 11],
            ])
        } else {
            0
        };
        if tables.n_devs < MAX_DBG2_DEVICES {
            let i = tables.n_devs;
            tables.devs[i] = Dbg2Device {
                port_type,
                port_subtype,
                base_addr,
            };
            tables.n_devs = i + 1;
            count += 1;
        }
        cur += len;
    }
    count
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → DBG2 must also be identity-mapped.
pub unsafe fn parse_dbg2(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut dbg2: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"DBG2" && dbg2.is_none() {
                dbg2 = Some(phys);
            }
        })?;
    }
    let dbg2 = dbg2.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (dbg2 as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 8 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(dbg2 as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    let n = parse_dbg2_body(body);
    DBG2_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_dbg2_known() -> bool {
    DBG2_PARSED.load(Ordering::Acquire)
}

pub fn copy_dbg2_devices(out: &mut [Dbg2Device]) -> usize {
    let t = DBG2_DATA.lock();
    let n = t.n_devs.min(out.len());
    out[..n].copy_from_slice(&t.devs[..n]);
    n
}

#[doc(hidden)]
pub fn __test_parse_dbg2_body(body: &[u8]) -> u32 {
    let n = parse_dbg2_body(body);
    DBG2_PARSED.store(true, Ordering::Release);
    n
}

// ───────────────────────────────────────────────────────────────────
// WSMT — Windows SMM Mitigation Table.
// Spec: `acpi/specification/tables-firmware-hpet-prm.md` §1.
// ───────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct WsmtInfo {
    pub fixed_comm_buffers: bool,
    pub comm_buffer_nested_ptr: bool,
    pub system_resource_protection: bool,
}

static WSMT_DATA: IrqSafeSpinLock<WsmtInfo> = IrqSafeSpinLock::new(WsmtInfo {
    fixed_comm_buffers: false,
    comm_buffer_nested_ptr: false,
    system_resource_protection: false,
});
static WSMT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_wsmt_body(body: &[u8]) {
    if body.len() < SDT_HEADER_SIZE + 4 {
        return;
    }
    let flags = u32::from_le_bytes([
        body[SDT_HEADER_SIZE],
        body[SDT_HEADER_SIZE + 1],
        body[SDT_HEADER_SIZE + 2],
        body[SDT_HEADER_SIZE + 3],
    ]);
    *WSMT_DATA.lock() = WsmtInfo {
        fixed_comm_buffers: flags & (1 << 0) != 0,
        comm_buffer_nested_ptr: flags & (1 << 1) != 0,
        system_resource_protection: flags & (1 << 2) != 0,
    };
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → WSMT must also be identity-mapped.
pub unsafe fn parse_wsmt(rsdp_phys: PhysAddr) -> Result<(), AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut wsmt: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"WSMT" && wsmt.is_none() {
                wsmt = Some(phys);
            }
        })?;
    }
    let wsmt = wsmt.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (wsmt as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 4 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(wsmt as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    parse_wsmt_body(body);
    WSMT_PARSED.store(true, Ordering::Release);
    Ok(())
}

pub fn wsmt_info() -> Option<WsmtInfo> {
    if !WSMT_PARSED.load(Ordering::Acquire) {
        return None;
    }
    Some(*WSMT_DATA.lock())
}

#[doc(hidden)]
pub fn __test_parse_wsmt_body(body: &[u8]) {
    parse_wsmt_body(body);
    WSMT_PARSED.store(true, Ordering::Release);
}

// ───────────────────────────────────────────────────────────────────
// WAET — Windows ACPI Emulated Devices Table.
// Spec: `acpi/specification/tables-firmware-hpet-prm.md` §2.
// ───────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct WaetInfo {
    pub rtc_good: bool,
    pub acpi_pmtimer_good: bool,
}

static WAET_DATA: IrqSafeSpinLock<WaetInfo> = IrqSafeSpinLock::new(WaetInfo {
    rtc_good: false,
    acpi_pmtimer_good: false,
});
static WAET_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_waet_body(body: &[u8]) {
    if body.len() < SDT_HEADER_SIZE + 4 {
        return;
    }
    let flags = u32::from_le_bytes([
        body[SDT_HEADER_SIZE],
        body[SDT_HEADER_SIZE + 1],
        body[SDT_HEADER_SIZE + 2],
        body[SDT_HEADER_SIZE + 3],
    ]);
    *WAET_DATA.lock() = WaetInfo {
        rtc_good: flags & (1 << 0) != 0,
        acpi_pmtimer_good: flags & (1 << 1) != 0,
    };
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → WAET must also be identity-mapped.
pub unsafe fn parse_waet(rsdp_phys: PhysAddr) -> Result<(), AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut waet: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"WAET" && waet.is_none() {
                waet = Some(phys);
            }
        })?;
    }
    let waet = waet.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (waet as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 4 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(waet as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    parse_waet_body(body);
    WAET_PARSED.store(true, Ordering::Release);
    Ok(())
}

pub fn waet_info() -> Option<WaetInfo> {
    if !WAET_PARSED.load(Ordering::Acquire) {
        return None;
    }
    Some(*WAET_DATA.lock())
}

#[doc(hidden)]
pub fn __test_parse_waet_body(body: &[u8]) {
    parse_waet_body(body);
    WAET_PARSED.store(true, Ordering::Release);
}

// ───────────────────────────────────────────────────────────────────
// HPET — Description Table.
// Spec: `acpi/specification/tables-firmware-hpet-prm.md` §3.
// ───────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct HpetDesc {
    pub block_id: u32,
    pub base: u64,
    pub addr_space_id: u8,
    pub hpet_number: u8,
    pub main_counter_min: u16,
    pub oem_attributes: u8,
}

static HPET_DATA: IrqSafeSpinLock<HpetDesc> = IrqSafeSpinLock::new(HpetDesc {
    block_id: 0,
    base: 0,
    addr_space_id: 0,
    hpet_number: 0,
    main_counter_min: 0,
    oem_attributes: 0,
});
static HPET_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_hpet_body(body: &[u8]) {
    // Layout: SDT_HEADER + EventTimerBlockId (4) +
    //   GAS (12; AddressSpaceId @ 0, Address @ 4..12) +
    //   HpetNumber (1) + MainCounterMin (2) + OemAttributes (1)
    if body.len() < SDT_HEADER_SIZE + 4 + 12 + 4 {
        return;
    }
    let off = SDT_HEADER_SIZE;
    let block_id = u32::from_le_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]]);
    let addr_space_id = body[off + 4];
    let base = u64::from_le_bytes([
        body[off + 8],
        body[off + 9],
        body[off + 10],
        body[off + 11],
        body[off + 12],
        body[off + 13],
        body[off + 14],
        body[off + 15],
    ]);
    let hpet_number = body[off + 16];
    let main_counter_min = u16::from_le_bytes([body[off + 17], body[off + 18]]);
    let oem_attributes = body[off + 19];
    *HPET_DATA.lock() = HpetDesc {
        block_id,
        base,
        addr_space_id,
        hpet_number,
        main_counter_min,
        oem_attributes,
    };
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → HPET must also be identity-mapped.
pub unsafe fn parse_hpet(rsdp_phys: PhysAddr) -> Result<(), AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut hpet: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"HPET" && hpet.is_none() {
                hpet = Some(phys);
            }
        })?;
    }
    let hpet = hpet.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (hpet as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 20 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(hpet as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    parse_hpet_body(body);
    HPET_PARSED.store(true, Ordering::Release);
    Ok(())
}

pub fn hpet_desc() -> Option<HpetDesc> {
    if !HPET_PARSED.load(Ordering::Acquire) {
        return None;
    }
    Some(*HPET_DATA.lock())
}

#[doc(hidden)]
pub fn __test_parse_hpet_body(body: &[u8]) {
    parse_hpet_body(body);
    HPET_PARSED.store(true, Ordering::Release);
}

// ───────────────────────────────────────────────────────────────────
// FACS — Firmware ACPI Control Structure (reached via FADT).
// Spec: `acpi/specification/tables-firmware-hpet-prm.md` §4.
// ───────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct FacsInfo {
    /// Total FACS length in bytes, from the header. Decides which of
    /// the later fields physically exist.
    pub length: u32,
    pub hardware_signature: u32,
    pub firmware_waking_vector_32: u32,
    pub firmware_waking_vector_64: u64,
    pub global_lock: u32,
    pub flags: u32,
    pub version: u8,
    /// `OspmFlags` (+36). OSPM-owned; bit 0 is
    /// [`FACS_OSPM_FLAG_64BIT_WAKE`]. Zero when the FACS is too
    /// short to contain the field.
    pub ospm_flags: u32,
}

/// FACS `Flags` bit 1 — `64BIT_WAKE_SUPPORTED_F` (ACPI 4.0+).
/// Firmware-owned: set when the platform can hand control to
/// `XFirmwareWakingVector` in a 64-bit environment.
pub const FACS_FLAG_64BIT_WAKE_SUPPORTED: u32 = 1 << 1;

/// FACS `OspmFlags` bit 0 — `64BIT_WAKE_F` (ACPI 4.0+).
/// OSPM-owned: set by us to tell firmware we require the 64-bit
/// wake environment, i.e. use `XFirmwareWakingVector`.
pub const FACS_OSPM_FLAG_64BIT_WAKE: u32 = 1;

/// Smallest FACS `Length` that contains both `XFirmwareWakingVector`
/// (+24..32) and `OspmFlags` (+36..40).
pub const FACS_MIN_LEN_64BIT_WAKE: u32 = 40;

static FACS_DATA: IrqSafeSpinLock<FacsInfo> = IrqSafeSpinLock::new(FacsInfo {
    length: 0,
    hardware_signature: 0,
    firmware_waking_vector_32: 0,
    firmware_waking_vector_64: 0,
    global_lock: 0,
    flags: 0,
    version: 0,
    ospm_flags: 0,
});
static FACS_PARSED: AtomicBool = AtomicBool::new(false);
/// FACS body phys address — cached by `parse_facs` so
/// `arm_s3_waking_vector` can write back to it without re-walking
/// the table chain. 0 means "FACS not parsed yet".
static FACS_PHYS: AtomicU64 = AtomicU64::new(0);

fn parse_facs_body(body: &[u8]) {
    // Layout (from offset 0 of the FACS body):
    //   0..4   Signature (FACS)
    //   4..8   Length
    //   8..12  HardwareSignature
    //   12..16 FirmwareWakingVector
    //   16..20 GlobalLock
    //   20..24 Flags
    //   24..32 XFirmwareWakingVector
    //   32     Version
    //   33..36 Reserved
    //   36..40 OspmFlags
    if body.len() < 33 {
        return;
    }
    let length = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
    let hardware_signature = u32::from_le_bytes([body[8], body[9], body[10], body[11]]);
    let firmware_waking_vector_32 = u32::from_le_bytes([body[12], body[13], body[14], body[15]]);
    let global_lock = u32::from_le_bytes([body[16], body[17], body[18], body[19]]);
    let flags = u32::from_le_bytes([body[20], body[21], body[22], body[23]]);
    let firmware_waking_vector_64 = u64::from_le_bytes([
        body[24], body[25], body[26], body[27], body[28], body[29], body[30], body[31],
    ]);
    let version = body[32];
    // OspmFlags only exists from FACS length 40 onward; keep 0 when
    // the table is shorter rather than reading past the fields the
    // firmware actually published.
    let ospm_flags = if body.len() >= 40 {
        u32::from_le_bytes([body[36], body[37], body[38], body[39]])
    } else {
        0
    };
    *FACS_DATA.lock() = FacsInfo {
        length,
        hardware_signature,
        firmware_waking_vector_32,
        firmware_waking_vector_64,
        global_lock,
        flags,
        version,
        ospm_flags,
    };
}

/// Parse FACS. Reaches FACS via FADT.firmware_ctrl /
/// X_FirmwareCtrl. v0.1 also accepts a stand-alone walk by
/// looking for the FACS signature directly in the XSDT in case
/// the platform is misbehaving.
///
/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → FADT → FACS must also be identity-mapped.
pub unsafe fn parse_facs(rsdp_phys: PhysAddr) -> Result<(), AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut fadt: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"FACP" && fadt.is_none() {
                fadt = Some(phys);
            }
        })?;
    }
    let fadt = fadt.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion. FADT body — we only need
    // FirmwareCtrl @ 36 (32-bit) or X_FirmwareCtrl @ 132 (64-bit).
    // SAFETY: Valid memory or trusted environment
    let fadt_total = unsafe { (fadt as *const SdtHeader).read_unaligned().length as usize };
    if fadt_total < 44 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let fbody = unsafe { core::slice::from_raw_parts(fadt as *const u8, fadt_total) };
    let fw32 = u32::from_le_bytes([fbody[36], fbody[37], fbody[38], fbody[39]]) as u64;
    let fw64 = if fadt_total >= 140 {
        u64::from_le_bytes([
            fbody[132], fbody[133], fbody[134], fbody[135], fbody[136], fbody[137], fbody[138],
            fbody[139],
        ])
    } else {
        0
    };
    let facs = if fw64 != 0 { fw64 } else { fw32 };
    if facs == 0 {
        return Err(AcpiError::NoSrat);
    }

    // SAFETY: caller assertion. FACS lacks an SDT header — it
    // begins with its own 4-byte "FACS" signature + 4-byte length.
    // SAFETY: Valid memory or trusted environment
    let facs_len = unsafe { (facs as *const u8).add(4).cast::<u32>().read_unaligned() } as usize;
    if facs_len < 64 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(facs as *const u8, facs_len) };
    if &body[0..4] != b"FACS" {
        return Err(AcpiError::BadXsdtSignature);
    }
    parse_facs_body(body);
    FACS_PHYS.store(facs, Ordering::Release);
    FACS_PARSED.store(true, Ordering::Release);
    Ok(())
}

pub fn facs_info() -> Option<FacsInfo> {
    if !FACS_PARSED.load(Ordering::Acquire) {
        return None;
    }
    Some(*FACS_DATA.lock())
}

/// Errors arming the S3 firmware-waking-vector.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WakeVectorError {
    /// FACS hasn't been parsed yet — no phys address to write to.
    FacsNotParsed,
    /// FACS `Length` is under [`FACS_MIN_LEN_64BIT_WAKE`], so the
    /// table has no `XFirmwareWakingVector` / `OspmFlags` fields to
    /// write.
    FacsTooShort,
    /// FACS `Version` is 0 (ACPI 1.0 FACS): the 64-bit
    /// `XFirmwareWakingVector` slot is not defined on this firmware.
    FacsVersionTooOld,
    /// Firmware does not advertise `64BIT_WAKE_SUPPORTED_F`
    /// (FACS `Flags` bit 1), so it will only ever enter the legacy
    /// real-mode 32-bit `FirmwareWakingVector` — for which NARF has
    /// no trampoline. See [`arm_s3_waking_vector`].
    NoSixtyFourBitWake,
}

/// Program the FACS firmware waking vector for S3 resume.
///
/// # Which slot, and why
///
/// The FACS has two waking-vector slots and they are **not**
/// interchangeable:
///
/// - `FirmwareWakingVector` (+12, 32-bit) is entered by firmware in
///   **real mode**. It must be a sub-1 MiB physical address pointing
///   at a 16-bit trampoline that establishes protected mode, then
///   long mode, itself.
/// - `XFirmwareWakingVector` (+24, 64-bit, ACPI 2.0+ / FACS
///   `Version >= 1`) is the slot that takes a **long-mode** address.
///   Firmware only honours it when it advertises
///   `64BIT_WAKE_SUPPORTED_F` (`Flags` bit 1, ACPI 4.0) and OSPM
///   requests the 64-bit environment via `64BIT_WAKE_F`
///   (`OspmFlags` bit 0).
///
/// NARF's wake entry (`narf_arch::x86_64::s3_resume::s3_wake_entry`)
/// is a long-mode entry point living wherever the kernel was loaded.
/// There is no real-mode trampoline, so this function:
///
/// 1. **refuses** unless the firmware advertises 64-bit wake,
/// 2. writes `entry_phys` to `XFirmwareWakingVector` only,
/// 3. sets `OspmFlags.64BIT_WAKE_F` to select that path, and
/// 4. writes **zero** to the 32-bit `FirmwareWakingVector`.
///
/// Point 4 is the fix for the original defect: the old code put
/// `entry_phys as u32` — a truncated long-mode address — into a slot
/// firmware enters in real mode. On a machine that used it, that is
/// a jump to an arbitrary 20-bit-addressable location with no
/// paging, i.e. an unrecoverable resume.
///
/// # What this does and does not support
///
/// - **Supported:** firmware that sets `64BIT_WAKE_SUPPORTED_F` and
///   honours `OspmFlags.64BIT_WAKE_F` + `XFirmwareWakingVector`
///   (the ACPI 4.0+ 64-bit wake environment). `entry_phys` may be
///   anywhere in the 64-bit physical space.
/// - **Not supported:** firmware that implements only the legacy
///   real-mode 32-bit vector — which is most real x86 firmware.
///   Those now get [`WakeVectorError::NoSixtyFourBitWake`] and the
///   caller refuses to sleep, instead of sleeping into a machine
///   that cannot come back. Closing this gap needs a real sub-1 MiB
///   real-mode trampoline (allocate low memory, relocate a 16-bit
///   stub into it, build transient GDT + page tables, enter long
///   mode, then jump to `s3_wake_entry`) — not a different address
///   in the same slot.
/// - **Not supported:** FACS `Version == 0`, or a FACS shorter than
///   [`FACS_MIN_LEN_64BIT_WAKE`].
///
/// // LINUX-GAP: Linux takes the opposite branch. `acpi_set_waking_vector`
/// // (`drivers/acpi/sleep.h`) always passes `physical_address64 = 0`, and
/// // `acpi_hw_set_firmware_waking_vector` (`drivers/acpi/acpica/hwxfsleep.c`)
/// // writes the 32-bit slot unconditionally, because x86 Linux ships a real
/// // sub-1 MiB real-mode trampoline: `acpi_get_wakeup_address()`
/// // (`arch/x86/kernel/acpi/sleep.c`) returns `real_mode_header->wakeup_start`,
/// // allocated by `reserve_real_mode()` from `[0, 1<<20)`, and
/// // `arch/x86/realmode/rm/wakeup_asm.S` is `.code16`. Linux never reads
/// // `64BIT_WAKE_SUPPORTED_F` or writes `OspmFlags` at all. NARF diverges
/// // because it has no such trampoline; until it does, the 64-bit wake
/// // environment is the only slot it can honestly arm.
///
/// FACS must have been parsed via [`parse_facs`] beforehand.
///
/// # Safety
/// `entry_phys` must point at a long-mode-callable entry that
/// is alive across S3 (not paged out, not in user memory) and
/// that handles its own context restoration.
pub unsafe fn arm_s3_waking_vector(entry_phys: u64) -> Result<(), WakeVectorError> {
    let facs = FACS_PHYS.load(Ordering::Acquire);
    if facs == 0 || !FACS_PARSED.load(Ordering::Acquire) {
        return Err(WakeVectorError::FacsNotParsed);
    }
    let (length, flags, version) = {
        let g = FACS_DATA.lock();
        (g.length, g.flags, g.version)
    };
    // Validate everything before writing anything: a refused arm
    // must leave the firmware's FACS byte-for-byte untouched, so a
    // caller that goes on to sleep anyway is no worse off than if
    // this had never been called.
    if length < FACS_MIN_LEN_64BIT_WAKE {
        return Err(WakeVectorError::FacsTooShort);
    }
    if version < 1 {
        return Err(WakeVectorError::FacsVersionTooOld);
    }
    if flags & FACS_FLAG_64BIT_WAKE_SUPPORTED == 0 {
        return Err(WakeVectorError::NoSixtyFourBitWake);
    }
    // 64-bit `XFirmwareWakingVector` at +24 — the only slot that can
    // hold a long-mode entry.
    // SAFETY: FACS is identity-mapped at `facs`, `Length` was checked
    // to cover +24..32, and the ACPI-mandated FACS alignment makes
    // `facs + 24` 8-aligned.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::ptr::write_volatile((facs + 24) as *mut u64, entry_phys);
    }
    // 32-bit `FirmwareWakingVector` at +12 stays ZERO. It is a
    // real-mode entry point; `entry_phys as u32` would be a
    // truncated long-mode address and entering it would be fatal.
    // SAFETY: as above, for +12..16.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::ptr::write_volatile((facs + 12) as *mut u32, 0u32);
    }
    // `OspmFlags` at +36: assert 64BIT_WAKE_F so firmware knows to
    // take the 64-bit vector. Read-modify-write — the field is
    // OSPM-owned but other bits may be defined by later revisions.
    // SAFETY: as above, for +36..40.
    // SAFETY: Valid memory or trusted environment
    let ospm_flags = unsafe {
        let p = (facs + 36) as *mut u32;
        let updated = core::ptr::read_volatile(p) | FACS_OSPM_FLAG_64BIT_WAKE;
        core::ptr::write_volatile(p, updated);
        updated
    };
    // Reflect into the parsed snapshot so facs_info() agrees with
    // the post-arm state.
    let mut g = FACS_DATA.lock();
    g.firmware_waking_vector_32 = 0;
    g.firmware_waking_vector_64 = entry_phys;
    g.ospm_flags = ospm_flags;
    Ok(())
}

/// Test-only entry point so smokes can simulate parse + arm.
#[doc(hidden)]
pub fn __test_set_facs_phys(phys: u64) {
    FACS_PHYS.store(phys, Ordering::Release);
}

#[doc(hidden)]
pub fn __test_parse_facs_body(body: &[u8]) {
    parse_facs_body(body);
    FACS_PARSED.store(true, Ordering::Release);
}

// ───────────────────────────────────────────────────────────────────
// PRMT — Platform Runtime Mechanism Table.
// Spec: `acpi/specification/tables-firmware-hpet-prm.md` §5.
// ───────────────────────────────────────────────────────────────────

pub const MAX_PRMT_MODULES: usize = 16;

#[derive(Copy, Clone, Debug, Default)]
pub struct PrmtModule {
    pub major_revision: u16,
    pub minor_revision: u16,
    pub handler_count: u16,
    pub mmio_range: u64,
}

struct PrmtTables {
    mods: [PrmtModule; MAX_PRMT_MODULES],
    n_mods: usize,
}

impl PrmtTables {
    const EMPTY: Self = Self {
        mods: [PrmtModule {
            major_revision: 0,
            minor_revision: 0,
            handler_count: 0,
            mmio_range: 0,
        }; MAX_PRMT_MODULES],
        n_mods: 0,
    };
}

static PRMT_DATA: IrqSafeSpinLock<PrmtTables> = IrqSafeSpinLock::new(PrmtTables::EMPTY);
static PRMT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_prmt_body(body: &[u8]) -> u32 {
    let mut tables = PRMT_DATA.lock();
    *tables = PrmtTables::EMPTY;
    if body.len() < SDT_HEADER_SIZE + 24 {
        return 0;
    }
    let hdr_off = SDT_HEADER_SIZE + 16; // skip PrmPlatformGuid (16)
    let mod_off = u32::from_le_bytes([
        body[hdr_off],
        body[hdr_off + 1],
        body[hdr_off + 2],
        body[hdr_off + 3],
    ]) as usize;
    let mod_count = u32::from_le_bytes([
        body[hdr_off + 4],
        body[hdr_off + 5],
        body[hdr_off + 6],
        body[hdr_off + 7],
    ]) as usize;
    let mut cur = mod_off;
    let mut count = 0u32;
    for _ in 0..mod_count {
        if cur + 4 > body.len() {
            break;
        }
        let len = u16::from_le_bytes([body[cur + 2], body[cur + 3]]) as usize;
        if len < 36 || cur + len > body.len() {
            break;
        }
        let entry = &body[cur..cur + len];
        // Layout (offsets within entry):
        //   0..2   Revision
        //   2..4   Length
        //   4..20  ModuleGuid
        //   20..22 MajorRevision
        //   22..24 MinorRevision
        //   24..26 HandlerCount
        //   26..30 HandlerInfoOffset
        //   30..38 MmioRangeAddr (alignment-shifted in real layout;
        //                        we read a u64 starting at offset 28
        //                        per ACPI 6.5 PRMT layout).
        let major_revision = u16::from_le_bytes([entry[20], entry[21]]);
        let minor_revision = u16::from_le_bytes([entry[22], entry[23]]);
        let handler_count = u16::from_le_bytes([entry[24], entry[25]]);
        let mmio_range = u64::from_le_bytes([
            entry[28], entry[29], entry[30], entry[31], entry[32], entry[33], entry[34], entry[35],
        ]);
        if tables.n_mods < MAX_PRMT_MODULES {
            let i = tables.n_mods;
            tables.mods[i] = PrmtModule {
                major_revision,
                minor_revision,
                handler_count,
                mmio_range,
            };
            tables.n_mods = i + 1;
            count += 1;
        }
        cur += len;
    }
    count
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → PRMT must also be identity-mapped.
pub unsafe fn parse_prmt(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut prmt: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"PRMT" && prmt.is_none() {
                prmt = Some(phys);
            }
        })?;
    }
    let prmt = prmt.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (prmt as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 24 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(prmt as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    let n = parse_prmt_body(body);
    PRMT_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_prmt_known() -> bool {
    PRMT_PARSED.load(Ordering::Acquire)
}

pub fn copy_prmt_modules(out: &mut [PrmtModule]) -> usize {
    let t = PRMT_DATA.lock();
    let n = t.n_mods.min(out.len());
    out[..n].copy_from_slice(&t.mods[..n]);
    n
}

#[doc(hidden)]
pub fn __test_parse_prmt_body(body: &[u8]) -> u32 {
    let n = parse_prmt_body(body);
    PRMT_PARSED.store(true, Ordering::Release);
    n
}

// ───────────────────────────────────────────────────────────────────
// CCEL — Confidential Computing Event Log.
// Spec: `acpi/specification/tables-confidential-power-secure.md` §1.
// ───────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct CcelInfo {
    pub cc_type: u8,
    pub cc_subtype: u8,
    pub log_area_min: u64,
    pub log_area_phys: u64,
}

static CCEL_DATA: IrqSafeSpinLock<CcelInfo> = IrqSafeSpinLock::new(CcelInfo {
    cc_type: 0,
    cc_subtype: 0,
    log_area_min: 0,
    log_area_phys: 0,
});
static CCEL_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_ccel_body(body: &[u8]) {
    if body.len() < SDT_HEADER_SIZE + 20 {
        return;
    }
    let off = SDT_HEADER_SIZE;
    let cc_type = body[off];
    let cc_subtype = body[off + 1];
    let log_area_min = u64::from_le_bytes([
        body[off + 4],
        body[off + 5],
        body[off + 6],
        body[off + 7],
        body[off + 8],
        body[off + 9],
        body[off + 10],
        body[off + 11],
    ]);
    let log_area_phys = u64::from_le_bytes([
        body[off + 12],
        body[off + 13],
        body[off + 14],
        body[off + 15],
        body[off + 16],
        body[off + 17],
        body[off + 18],
        body[off + 19],
    ]);
    *CCEL_DATA.lock() = CcelInfo {
        cc_type,
        cc_subtype,
        log_area_min,
        log_area_phys,
    };
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → CCEL must also be identity-mapped.
pub unsafe fn parse_ccel(rsdp_phys: PhysAddr) -> Result<(), AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut ccel: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"CCEL" && ccel.is_none() {
                ccel = Some(phys);
            }
        })?;
    }
    let ccel = ccel.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (ccel as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 20 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(ccel as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    parse_ccel_body(body);
    CCEL_PARSED.store(true, Ordering::Release);
    Ok(())
}

pub fn ccel_info() -> Option<CcelInfo> {
    if !CCEL_PARSED.load(Ordering::Acquire) {
        return None;
    }
    Some(*CCEL_DATA.lock())
}

#[doc(hidden)]
pub fn __test_parse_ccel_body(body: &[u8]) {
    parse_ccel_body(body);
    CCEL_PARSED.store(true, Ordering::Release);
}

// ───────────────────────────────────────────────────────────────────
// MPST — Memory Power State Table.
// Spec: `acpi/specification/tables-confidential-power-secure.md` §2.
// ───────────────────────────────────────────────────────────────────

pub const MAX_MPST_NODES: usize = 16;

#[derive(Copy, Clone, Debug, Default)]
pub struct MpstNode {
    pub node_id: u16,
    pub enabled: bool,
    pub power_managed: bool,
    pub hot_pluggable: bool,
    pub base: u64,
    pub length_bytes: u64,
}

struct MpstTables {
    nodes: [MpstNode; MAX_MPST_NODES],
    n_nodes: usize,
}

impl MpstTables {
    const EMPTY: Self = Self {
        nodes: [MpstNode {
            node_id: 0,
            enabled: false,
            power_managed: false,
            hot_pluggable: false,
            base: 0,
            length_bytes: 0,
        }; MAX_MPST_NODES],
        n_nodes: 0,
    };
}

static MPST_DATA: IrqSafeSpinLock<MpstTables> = IrqSafeSpinLock::new(MpstTables::EMPTY);
static MPST_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_mpst_body(body: &[u8]) -> u32 {
    let mut tables = MPST_DATA.lock();
    *tables = MpstTables::EMPTY;
    // Header: PccId (1) + Reserved (3) + NodeCount (2) + Reserved (2) = 8 bytes
    if body.len() < SDT_HEADER_SIZE + 8 {
        return 0;
    }
    let n_nodes =
        u16::from_le_bytes([body[SDT_HEADER_SIZE + 4], body[SDT_HEADER_SIZE + 5]]) as usize;
    let mut cur = SDT_HEADER_SIZE + 8;
    let mut count = 0u32;
    for _ in 0..n_nodes {
        if cur + 32 > body.len() {
            break;
        }
        // Per-node header: Flags (1) + Reserved (1) + Id (2) +
        //                  Length (4) + Base (8) + LengthBytes (8) +
        //                  StateValueCount (4) + PhysComponentCount (4)
        let entry = &body[cur..];
        let flags = entry[0];
        let node_id = u16::from_le_bytes([entry[2], entry[3]]);
        let len = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]) as usize;
        let base = u64::from_le_bytes([
            entry[8], entry[9], entry[10], entry[11], entry[12], entry[13], entry[14], entry[15],
        ]);
        let length_bytes = u64::from_le_bytes([
            entry[16], entry[17], entry[18], entry[19], entry[20], entry[21], entry[22], entry[23],
        ]);
        if tables.n_nodes < MAX_MPST_NODES {
            let i = tables.n_nodes;
            tables.nodes[i] = MpstNode {
                node_id,
                enabled: flags & (1 << 0) != 0,
                power_managed: flags & (1 << 1) != 0,
                hot_pluggable: flags & (1 << 2) != 0,
                base,
                length_bytes,
            };
            tables.n_nodes = i + 1;
            count += 1;
        }
        if len < 32 || cur + len > body.len() {
            break;
        }
        cur += len;
    }
    count
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → MPST must also be identity-mapped.
pub unsafe fn parse_mpst(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut mpst: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"MPST" && mpst.is_none() {
                mpst = Some(phys);
            }
        })?;
    }
    let mpst = mpst.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (mpst as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 8 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(mpst as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    let n = parse_mpst_body(body);
    MPST_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_mpst_known() -> bool {
    MPST_PARSED.load(Ordering::Acquire)
}

pub fn copy_mpst_nodes(out: &mut [MpstNode]) -> usize {
    let t = MPST_DATA.lock();
    let n = t.n_nodes.min(out.len());
    out[..n].copy_from_slice(&t.nodes[..n]);
    n
}

#[doc(hidden)]
pub fn __test_parse_mpst_body(body: &[u8]) -> u32 {
    let n = parse_mpst_body(body);
    MPST_PARSED.store(true, Ordering::Release);
    n
}

// ───────────────────────────────────────────────────────────────────
// SDEV — Secure Devices Table.
// Spec: `acpi/specification/tables-confidential-power-secure.md` §3.
// ───────────────────────────────────────────────────────────────────

pub const MAX_SDEV_PCI: usize = 16;

#[derive(Copy, Clone, Debug, Default)]
pub struct SdevPci {
    pub segment: u16,
    pub start_bdf: u16,
}

struct SdevTables {
    pcis: [SdevPci; MAX_SDEV_PCI],
    n_pcis: usize,
}

impl SdevTables {
    const EMPTY: Self = Self {
        pcis: [SdevPci {
            segment: 0,
            start_bdf: 0,
        }; MAX_SDEV_PCI],
        n_pcis: 0,
    };
}

static SDEV_DATA: IrqSafeSpinLock<SdevTables> = IrqSafeSpinLock::new(SdevTables::EMPTY);
static SDEV_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_sdev_body(body: &[u8]) -> u32 {
    let mut tables = SDEV_DATA.lock();
    *tables = SdevTables::EMPTY;
    let mut cur = SDT_HEADER_SIZE;
    let mut count = 0u32;
    while cur + 4 <= body.len() {
        let kind = body[cur];
        let len = u16::from_le_bytes([body[cur + 2], body[cur + 3]]) as usize;
        if len < 4 || cur + len > body.len() {
            break;
        }
        let entry = &body[cur..cur + len];

        // Type 1 — PCI endpoint, header is 16 bytes.
        if kind == 1 && entry.len() >= 16 {
            let segment = u16::from_le_bytes([entry[4], entry[5]]);
            let start_bdf = u16::from_le_bytes([entry[6], entry[7]]);
            if tables.n_pcis < MAX_SDEV_PCI {
                let i = tables.n_pcis;
                tables.pcis[i] = SdevPci { segment, start_bdf };
                tables.n_pcis = i + 1;
                count += 1;
            }
        }
        cur += len;
    }
    count
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → SDEV must also be identity-mapped.
pub unsafe fn parse_sdev(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut sdev: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"SDEV" && sdev.is_none() {
                sdev = Some(phys);
            }
        })?;
    }
    let sdev = sdev.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (sdev as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(sdev as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    let n = parse_sdev_body(body);
    SDEV_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_sdev_known() -> bool {
    SDEV_PARSED.load(Ordering::Acquire)
}

pub fn copy_sdev_pci(out: &mut [SdevPci]) -> usize {
    let t = SDEV_DATA.lock();
    let n = t.n_pcis.min(out.len());
    out[..n].copy_from_slice(&t.pcis[..n]);
    n
}

#[doc(hidden)]
pub fn __test_parse_sdev_body(body: &[u8]) -> u32 {
    let n = parse_sdev_body(body);
    SDEV_PARSED.store(true, Ordering::Release);
    n
}

// ───────────────────────────────────────────────────────────────────
// SBST — Smart Battery Specification Table.
// Spec: `acpi/specification/tables-confidential-power-secure.md` §4.
// ───────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct SbstInfo {
    pub warning_level_mwh: u32,
    pub low_level_mwh: u32,
    pub critical_level_mwh: u32,
}

static SBST_DATA: IrqSafeSpinLock<SbstInfo> = IrqSafeSpinLock::new(SbstInfo {
    warning_level_mwh: 0,
    low_level_mwh: 0,
    critical_level_mwh: 0,
});
static SBST_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_sbst_body(body: &[u8]) {
    if body.len() < SDT_HEADER_SIZE + 12 {
        return;
    }
    let off = SDT_HEADER_SIZE;
    let warning_level_mwh =
        u32::from_le_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]]);
    let low_level_mwh =
        u32::from_le_bytes([body[off + 4], body[off + 5], body[off + 6], body[off + 7]]);
    let critical_level_mwh =
        u32::from_le_bytes([body[off + 8], body[off + 9], body[off + 10], body[off + 11]]);
    *SBST_DATA.lock() = SbstInfo {
        warning_level_mwh,
        low_level_mwh,
        critical_level_mwh,
    };
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → SBST must also be identity-mapped.
pub unsafe fn parse_sbst(rsdp_phys: PhysAddr) -> Result<(), AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut sbst: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"SBST" && sbst.is_none() {
                sbst = Some(phys);
            }
        })?;
    }
    let sbst = sbst.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (sbst as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 12 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(sbst as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    parse_sbst_body(body);
    SBST_PARSED.store(true, Ordering::Release);
    Ok(())
}

pub fn sbst_info() -> Option<SbstInfo> {
    if !SBST_PARSED.load(Ordering::Acquire) {
        return None;
    }
    Some(*SBST_DATA.lock())
}

#[doc(hidden)]
pub fn __test_parse_sbst_body(body: &[u8]) {
    parse_sbst_body(body);
    SBST_PARSED.store(true, Ordering::Release);
}

// ───────────────────────────────────────────────────────────────────
// RAS2 — RAS Feature Table.
// Spec: `acpi/specification/tables-confidential-power-secure.md` §5.
// ───────────────────────────────────────────────────────────────────

pub const MAX_RAS2_DESCRIPTORS: usize = 16;

#[derive(Copy, Clone, Debug, Default)]
pub struct Ras2Descriptor {
    pub pcc_id: u8,
    pub feature_type: u8,
    pub instance_count: u32,
}

struct Ras2Tables {
    descs: [Ras2Descriptor; MAX_RAS2_DESCRIPTORS],
    n_descs: usize,
}

impl Ras2Tables {
    const EMPTY: Self = Self {
        descs: [Ras2Descriptor {
            pcc_id: 0,
            feature_type: 0,
            instance_count: 0,
        }; MAX_RAS2_DESCRIPTORS],
        n_descs: 0,
    };
}

static RAS2_DATA: IrqSafeSpinLock<Ras2Tables> = IrqSafeSpinLock::new(Ras2Tables::EMPTY);
static RAS2_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_ras2_body(body: &[u8]) -> u32 {
    let mut tables = RAS2_DATA.lock();
    *tables = Ras2Tables::EMPTY;
    if body.len() < SDT_HEADER_SIZE + 4 {
        return 0;
    }
    let n_desc =
        u16::from_le_bytes([body[SDT_HEADER_SIZE + 2], body[SDT_HEADER_SIZE + 3]]) as usize;
    let mut cur = SDT_HEADER_SIZE + 4;
    let mut count = 0u32;
    for _ in 0..n_desc {
        if cur + 8 > body.len() {
            break;
        }
        let pcc_id = body[cur];
        let feature_type = body[cur + 3];
        let instance_count =
            u32::from_le_bytes([body[cur + 4], body[cur + 5], body[cur + 6], body[cur + 7]]);
        if tables.n_descs < MAX_RAS2_DESCRIPTORS {
            let i = tables.n_descs;
            tables.descs[i] = Ras2Descriptor {
                pcc_id,
                feature_type,
                instance_count,
            };
            tables.n_descs = i + 1;
            count += 1;
        }
        cur += 8;
    }
    count
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → RAS2 must also be identity-mapped.
pub unsafe fn parse_ras2(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut ras2: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"RAS2" && ras2.is_none() {
                ras2 = Some(phys);
            }
        })?;
    }
    let ras2 = ras2.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (ras2 as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 4 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(ras2 as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    let n = parse_ras2_body(body);
    RAS2_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_ras2_known() -> bool {
    RAS2_PARSED.load(Ordering::Acquire)
}

pub fn copy_ras2_descriptors(out: &mut [Ras2Descriptor]) -> usize {
    let t = RAS2_DATA.lock();
    let n = t.n_descs.min(out.len());
    out[..n].copy_from_slice(&t.descs[..n]);
    n
}

#[doc(hidden)]
pub fn __test_parse_ras2_body(body: &[u8]) -> u32 {
    let n = parse_ras2_body(body);
    RAS2_PARSED.store(true, Ordering::Release);
    n
}

// ───────────────────────────────────────────────────────────────────
// NHLT — Non-HD Audio Link Table.
// Spec: `acpi/specification/tables-ec-audio-iscsi-csrt-agdi.md` §2.
// ───────────────────────────────────────────────────────────────────

pub const MAX_NHLT_ENDPOINTS: usize = 16;

#[derive(Copy, Clone, Debug, Default)]
pub struct NhltEndpoint {
    pub link_type: u8,
    pub instance_id: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub direction: u8,
}

struct NhltTables {
    eps: [NhltEndpoint; MAX_NHLT_ENDPOINTS],
    n_eps: usize,
}

impl NhltTables {
    const EMPTY: Self = Self {
        eps: [NhltEndpoint {
            link_type: 0,
            instance_id: 0,
            vendor_id: 0,
            device_id: 0,
            direction: 0,
        }; MAX_NHLT_ENDPOINTS],
        n_eps: 0,
    };
}

static NHLT_DATA: IrqSafeSpinLock<NhltTables> = IrqSafeSpinLock::new(NhltTables::EMPTY);
static NHLT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_nhlt_body(body: &[u8]) -> u32 {
    let mut tables = NHLT_DATA.lock();
    *tables = NhltTables::EMPTY;
    if body.len() < SDT_HEADER_SIZE + 1 {
        return 0;
    }
    let n_eps = body[SDT_HEADER_SIZE] as usize;
    let mut cur = SDT_HEADER_SIZE + 1;
    let mut count = 0u32;
    for _ in 0..n_eps {
        if cur + 4 > body.len() {
            break;
        }
        let len =
            u32::from_le_bytes([body[cur], body[cur + 1], body[cur + 2], body[cur + 3]]) as usize;
        if len < 19 || cur + len > body.len() {
            break;
        }
        let entry = &body[cur..cur + len];
        // Endpoint header offsets within entry:
        //   0..4   Length
        //   4      LinkType
        //   5      InstanceId
        //   6..8   VendorId
        //   8..10  DeviceId
        //   10..12 RevisionId
        //   12..16 SubsystemId
        //   16     DeviceType
        //   17     Direction
        //   18     VirtualBusId
        let link_type = entry[4];
        let instance_id = entry[5];
        let vendor_id = u16::from_le_bytes([entry[6], entry[7]]);
        let device_id = u16::from_le_bytes([entry[8], entry[9]]);
        let direction = entry[17];
        if tables.n_eps < MAX_NHLT_ENDPOINTS {
            let i = tables.n_eps;
            tables.eps[i] = NhltEndpoint {
                link_type,
                instance_id,
                vendor_id,
                device_id,
                direction,
            };
            tables.n_eps = i + 1;
            count += 1;
        }
        cur += len;
    }
    count
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → NHLT must also be identity-mapped.
pub unsafe fn parse_nhlt(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut nhlt: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"NHLT" && nhlt.is_none() {
                nhlt = Some(phys);
            }
        })?;
    }
    let nhlt = nhlt.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (nhlt as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 1 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(nhlt as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    let n = parse_nhlt_body(body);
    NHLT_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_nhlt_known() -> bool {
    NHLT_PARSED.load(Ordering::Acquire)
}

pub fn copy_nhlt_endpoints(out: &mut [NhltEndpoint]) -> usize {
    let t = NHLT_DATA.lock();
    let n = t.n_eps.min(out.len());
    out[..n].copy_from_slice(&t.eps[..n]);
    n
}

#[doc(hidden)]
pub fn __test_parse_nhlt_body(body: &[u8]) -> u32 {
    let n = parse_nhlt_body(body);
    NHLT_PARSED.store(true, Ordering::Release);
    n
}

// ───────────────────────────────────────────────────────────────────
// IBFT — iSCSI Boot Firmware Table.
// Spec: `acpi/specification/tables-ec-audio-iscsi-csrt-agdi.md` §3.
// ───────────────────────────────────────────────────────────────────

pub const MAX_IBFT_TARGETS: usize = 8;

#[derive(Copy, Clone, Debug, Default)]
pub struct IbftTarget {
    pub ip: [u8; 16],
    pub port: u16,
    pub lun: u64,
}

struct IbftTables {
    targets: [IbftTarget; MAX_IBFT_TARGETS],
    n_targets: usize,
}

impl IbftTables {
    const EMPTY: Self = Self {
        targets: [IbftTarget {
            ip: [0u8; 16],
            port: 0,
            lun: 0,
        }; MAX_IBFT_TARGETS],
        n_targets: 0,
    };
}

static IBFT_DATA: IrqSafeSpinLock<IbftTables> = IrqSafeSpinLock::new(IbftTables::EMPTY);
static IBFT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_ibft_body(body: &[u8]) -> u32 {
    let mut tables = IBFT_DATA.lock();
    *tables = IbftTables::EMPTY;
    // Reserved (12) after SDT header per IBFT layout.
    if body.len() < SDT_HEADER_SIZE + 12 {
        return 0;
    }
    let mut cur = SDT_HEADER_SIZE + 12;
    let mut count = 0u32;
    while cur + 6 <= body.len() {
        let id = body[cur];
        let len = u16::from_le_bytes([body[cur + 2], body[cur + 3]]) as usize;
        if len < 6 || cur + len > body.len() {
            break;
        }
        let entry = &body[cur..cur + len];
        if id == 4 && entry.len() >= 32 {
            // Target: header (6) + IP (16) @ 6..22, port (2) @ 22..24,
            // LUN (8) @ 24..32.
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&entry[6..22]);
            let port = u16::from_le_bytes([entry[22], entry[23]]);
            let lun = u64::from_le_bytes([
                entry[24], entry[25], entry[26], entry[27], entry[28], entry[29], entry[30],
                entry[31],
            ]);
            if tables.n_targets < MAX_IBFT_TARGETS {
                let i = tables.n_targets;
                tables.targets[i] = IbftTarget { ip, port, lun };
                tables.n_targets = i + 1;
                count += 1;
            }
        }
        cur += len;
    }
    count
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → IBFT must also be identity-mapped.
pub unsafe fn parse_ibft(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut ibft: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"IBFT" && ibft.is_none() {
                ibft = Some(phys);
            }
        })?;
    }
    let ibft = ibft.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (ibft as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 12 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(ibft as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    let n = parse_ibft_body(body);
    IBFT_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_ibft_known() -> bool {
    IBFT_PARSED.load(Ordering::Acquire)
}

pub fn copy_ibft_targets(out: &mut [IbftTarget]) -> usize {
    let t = IBFT_DATA.lock();
    let n = t.n_targets.min(out.len());
    out[..n].copy_from_slice(&t.targets[..n]);
    n
}

#[doc(hidden)]
pub fn __test_parse_ibft_body(body: &[u8]) -> u32 {
    let n = parse_ibft_body(body);
    IBFT_PARSED.store(true, Ordering::Release);
    n
}

// ───────────────────────────────────────────────────────────────────
// CSRT — Core System Resource Table.
// Spec: `acpi/specification/tables-ec-audio-iscsi-csrt-agdi.md` §4.
// ───────────────────────────────────────────────────────────────────

pub const MAX_CSRT_GROUPS: usize = 16;

#[derive(Copy, Clone, Debug, Default)]
pub struct CsrtGroup {
    pub vendor_id: u32,
    pub device_id: u16,
    pub revision: u16,
}

struct CsrtTables {
    groups: [CsrtGroup; MAX_CSRT_GROUPS],
    n_groups: usize,
}

impl CsrtTables {
    const EMPTY: Self = Self {
        groups: [CsrtGroup {
            vendor_id: 0,
            device_id: 0,
            revision: 0,
        }; MAX_CSRT_GROUPS],
        n_groups: 0,
    };
}

static CSRT_DATA: IrqSafeSpinLock<CsrtTables> = IrqSafeSpinLock::new(CsrtTables::EMPTY);
static CSRT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_csrt_body(body: &[u8]) -> u32 {
    let mut tables = CSRT_DATA.lock();
    *tables = CsrtTables::EMPTY;
    let mut cur = SDT_HEADER_SIZE;
    let mut count = 0u32;
    while cur + 24 <= body.len() {
        let len =
            u32::from_le_bytes([body[cur], body[cur + 1], body[cur + 2], body[cur + 3]]) as usize;
        if len < 24 || cur + len > body.len() {
            break;
        }
        let entry = &body[cur..cur + len];
        let vendor_id = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
        let device_id = u16::from_le_bytes([entry[12], entry[13]]);
        let revision = u16::from_le_bytes([entry[16], entry[17]]);
        if tables.n_groups < MAX_CSRT_GROUPS {
            let i = tables.n_groups;
            tables.groups[i] = CsrtGroup {
                vendor_id,
                device_id,
                revision,
            };
            tables.n_groups = i + 1;
            count += 1;
        }
        cur += len;
    }
    count
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → CSRT must also be identity-mapped.
pub unsafe fn parse_csrt(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut csrt: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"CSRT" && csrt.is_none() {
                csrt = Some(phys);
            }
        })?;
    }
    let csrt = csrt.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (csrt as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(csrt as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    let n = parse_csrt_body(body);
    CSRT_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_csrt_known() -> bool {
    CSRT_PARSED.load(Ordering::Acquire)
}

pub fn copy_csrt_groups(out: &mut [CsrtGroup]) -> usize {
    let t = CSRT_DATA.lock();
    let n = t.n_groups.min(out.len());
    out[..n].copy_from_slice(&t.groups[..n]);
    n
}

#[doc(hidden)]
pub fn __test_parse_csrt_body(body: &[u8]) -> u32 {
    let n = parse_csrt_body(body);
    CSRT_PARSED.store(true, Ordering::Release);
    n
}

// ───────────────────────────────────────────────────────────────────
// AGDI — Arm Generic Diagnostic Dump and Reset Interface.
// Spec: `acpi/specification/tables-ec-audio-iscsi-csrt-agdi.md` §5.
// ───────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct AgdiInfo {
    pub use_smc: bool,
    pub sdei_event_number: u32,
    pub smc_id: u64,
}

static AGDI_DATA: IrqSafeSpinLock<AgdiInfo> = IrqSafeSpinLock::new(AgdiInfo {
    use_smc: false,
    sdei_event_number: 0,
    smc_id: 0,
});
static AGDI_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_agdi_body(body: &[u8]) {
    if body.len() < SDT_HEADER_SIZE + 16 {
        return;
    }
    let off = SDT_HEADER_SIZE;
    let flags = body[off];
    let sdei_event_number =
        u32::from_le_bytes([body[off + 4], body[off + 5], body[off + 6], body[off + 7]]);
    let smc_id = u64::from_le_bytes([
        body[off + 8],
        body[off + 9],
        body[off + 10],
        body[off + 11],
        body[off + 12],
        body[off + 13],
        body[off + 14],
        body[off + 15],
    ]);
    *AGDI_DATA.lock() = AgdiInfo {
        use_smc: flags & 1 != 0,
        sdei_event_number,
        smc_id,
    };
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → AGDI must also be identity-mapped.
pub unsafe fn parse_agdi(rsdp_phys: PhysAddr) -> Result<(), AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut agdi: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"AGDI" && agdi.is_none() {
                agdi = Some(phys);
            }
        })?;
    }
    let agdi = agdi.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (agdi as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 16 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(agdi as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    parse_agdi_body(body);
    AGDI_PARSED.store(true, Ordering::Release);
    Ok(())
}

pub fn agdi_info() -> Option<AgdiInfo> {
    if !AGDI_PARSED.load(Ordering::Acquire) {
        return None;
    }
    Some(*AGDI_DATA.lock())
}

#[doc(hidden)]
pub fn __test_parse_agdi_body(body: &[u8]) {
    parse_agdi_body(body);
    AGDI_PARSED.store(true, Ordering::Release);
}

// ───────────────────────────────────────────────────────────────────
// BOOT — Simple Boot Flag Table.
// Spec: `acpi/specification/tables-boot-dbgp-wpbt-msct-xenv.md` §1.
// ───────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct BootInfo {
    pub cmos_index: u8,
}

static BOOT_DATA: IrqSafeSpinLock<BootInfo> = IrqSafeSpinLock::new(BootInfo { cmos_index: 0 });
static BOOT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_boot_body(body: &[u8]) {
    if body.len() < SDT_HEADER_SIZE + 4 {
        return;
    }
    *BOOT_DATA.lock() = BootInfo {
        cmos_index: body[SDT_HEADER_SIZE],
    };
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → BOOT must also be identity-mapped.
pub unsafe fn parse_boot(rsdp_phys: PhysAddr) -> Result<(), AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut boot: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"BOOT" && boot.is_none() {
                boot = Some(phys);
            }
        })?;
    }
    let boot = boot.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (boot as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 4 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(boot as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    parse_boot_body(body);
    BOOT_PARSED.store(true, Ordering::Release);
    Ok(())
}

pub fn boot_info() -> Option<BootInfo> {
    if !BOOT_PARSED.load(Ordering::Acquire) {
        return None;
    }
    Some(*BOOT_DATA.lock())
}

#[doc(hidden)]
pub fn __test_parse_boot_body(body: &[u8]) {
    parse_boot_body(body);
    BOOT_PARSED.store(true, Ordering::Release);
}

// ───────────────────────────────────────────────────────────────────
// DBGP — Debug Port Table (legacy single-port).
// Spec: `acpi/specification/tables-boot-dbgp-wpbt-msct-xenv.md` §2.
// ───────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct DbgpInfo {
    pub iface: u8,
    pub addr_space_id: u8,
    pub base: u64,
}

static DBGP_DATA: IrqSafeSpinLock<DbgpInfo> = IrqSafeSpinLock::new(DbgpInfo {
    iface: 0,
    addr_space_id: 0,
    base: 0,
});
static DBGP_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_dbgp_body(body: &[u8]) {
    // Body offsets: iface (1) + reserved (3) + GAS (12).
    if body.len() < SDT_HEADER_SIZE + 16 {
        return;
    }
    let off = SDT_HEADER_SIZE;
    let iface = body[off];
    let addr_space_id = body[off + 4];
    let base = u64::from_le_bytes([
        body[off + 8],
        body[off + 9],
        body[off + 10],
        body[off + 11],
        body[off + 12],
        body[off + 13],
        body[off + 14],
        body[off + 15],
    ]);
    *DBGP_DATA.lock() = DbgpInfo {
        iface,
        addr_space_id,
        base,
    };
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → DBGP must also be identity-mapped.
pub unsafe fn parse_dbgp(rsdp_phys: PhysAddr) -> Result<(), AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut dbgp: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"DBGP" && dbgp.is_none() {
                dbgp = Some(phys);
            }
        })?;
    }
    let dbgp = dbgp.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (dbgp as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 16 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(dbgp as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    parse_dbgp_body(body);
    DBGP_PARSED.store(true, Ordering::Release);
    Ok(())
}

pub fn dbgp_info() -> Option<DbgpInfo> {
    if !DBGP_PARSED.load(Ordering::Acquire) {
        return None;
    }
    Some(*DBGP_DATA.lock())
}

#[doc(hidden)]
pub fn __test_parse_dbgp_body(body: &[u8]) {
    parse_dbgp_body(body);
    DBGP_PARSED.store(true, Ordering::Release);
}

// ───────────────────────────────────────────────────────────────────
// WPBT — Windows Platform Binary Table.
// Spec: `acpi/specification/tables-boot-dbgp-wpbt-msct-xenv.md` §3.
// ───────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct WpbtInfo {
    pub handoff_size: u32,
    pub handoff_addr: u64,
    pub layout_type: u8,
    pub content_type: u8,
}

static WPBT_DATA: IrqSafeSpinLock<WpbtInfo> = IrqSafeSpinLock::new(WpbtInfo {
    handoff_size: 0,
    handoff_addr: 0,
    layout_type: 0,
    content_type: 0,
});
static WPBT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_wpbt_body(body: &[u8]) {
    // Body offsets: HandoffSize (4) + HandoffAddr (8) + LayoutType (1) +
    //               ContentType (1) + ArgumentLength (2) + Argument (var).
    if body.len() < SDT_HEADER_SIZE + 16 {
        return;
    }
    let off = SDT_HEADER_SIZE;
    let handoff_size = u32::from_le_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]]);
    let handoff_addr = u64::from_le_bytes([
        body[off + 4],
        body[off + 5],
        body[off + 6],
        body[off + 7],
        body[off + 8],
        body[off + 9],
        body[off + 10],
        body[off + 11],
    ]);
    let layout_type = body[off + 12];
    let content_type = body[off + 13];
    *WPBT_DATA.lock() = WpbtInfo {
        handoff_size,
        handoff_addr,
        layout_type,
        content_type,
    };
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → WPBT must also be identity-mapped.
pub unsafe fn parse_wpbt(rsdp_phys: PhysAddr) -> Result<(), AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut wpbt: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"WPBT" && wpbt.is_none() {
                wpbt = Some(phys);
            }
        })?;
    }
    let wpbt = wpbt.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (wpbt as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 16 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(wpbt as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    parse_wpbt_body(body);
    WPBT_PARSED.store(true, Ordering::Release);
    Ok(())
}

pub fn wpbt_info() -> Option<WpbtInfo> {
    if !WPBT_PARSED.load(Ordering::Acquire) {
        return None;
    }
    Some(*WPBT_DATA.lock())
}

#[doc(hidden)]
pub fn __test_parse_wpbt_body(body: &[u8]) {
    parse_wpbt_body(body);
    WPBT_PARSED.store(true, Ordering::Release);
}

// ───────────────────────────────────────────────────────────────────
// MSCT — Maximum System Characteristics Table.
// Spec: `acpi/specification/tables-boot-dbgp-wpbt-msct-xenv.md` §4.
// ───────────────────────────────────────────────────────────────────

pub const MAX_MSCT_PDIS: usize = 16;

#[derive(Copy, Clone, Debug, Default)]
pub struct MsctInfo {
    pub max_proximity_domains: u32,
    pub max_clock_domains: u32,
    pub max_phys_addr_cap: u64,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct MsctPdis {
    pub low_domain: u16,
    pub high_domain: u16,
    pub max_processor_capacity: u32,
    pub max_memory_capacity: u64,
}

struct MsctTables {
    info: MsctInfo,
    pdis: [MsctPdis; MAX_MSCT_PDIS],
    n_pdis: usize,
}

impl MsctTables {
    const EMPTY: Self = Self {
        info: MsctInfo {
            max_proximity_domains: 0,
            max_clock_domains: 0,
            max_phys_addr_cap: 0,
        },
        pdis: [MsctPdis {
            low_domain: 0,
            high_domain: 0,
            max_processor_capacity: 0,
            max_memory_capacity: 0,
        }; MAX_MSCT_PDIS],
        n_pdis: 0,
    };
}

static MSCT_DATA: IrqSafeSpinLock<MsctTables> = IrqSafeSpinLock::new(MsctTables::EMPTY);
static MSCT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_msct_body(body: &[u8]) -> u32 {
    let mut tables = MSCT_DATA.lock();
    *tables = MsctTables::EMPTY;
    // Header: ProximityDomainOffset (4) + MaxProximityDomains (4) +
    //         MaxClockDomains (4) + MaxPhysAddrCap (8) = 20 bytes.
    if body.len() < SDT_HEADER_SIZE + 20 {
        return 0;
    }
    let off = SDT_HEADER_SIZE;
    let pd_off =
        u32::from_le_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]]) as usize;
    tables.info.max_proximity_domains =
        u32::from_le_bytes([body[off + 4], body[off + 5], body[off + 6], body[off + 7]]);
    tables.info.max_clock_domains =
        u32::from_le_bytes([body[off + 8], body[off + 9], body[off + 10], body[off + 11]]);
    tables.info.max_phys_addr_cap = u64::from_le_bytes([
        body[off + 12],
        body[off + 13],
        body[off + 14],
        body[off + 15],
        body[off + 16],
        body[off + 17],
        body[off + 18],
        body[off + 19],
    ]);

    let mut cur = pd_off;
    let mut count = 0u32;
    while cur + 18 <= body.len() {
        let _rev = body[cur];
        let len = body[cur + 1] as usize;
        if len < 18 || cur + len > body.len() {
            break;
        }
        let entry = &body[cur..cur + len];
        let low_domain = u16::from_le_bytes([entry[2], entry[3]]);
        let high_domain = u16::from_le_bytes([entry[4], entry[5]]);
        let max_processor_capacity = u32::from_le_bytes([entry[6], entry[7], entry[8], entry[9]]);
        let max_memory_capacity = u64::from_le_bytes([
            entry[10], entry[11], entry[12], entry[13], entry[14], entry[15], entry[16], entry[17],
        ]);
        if tables.n_pdis < MAX_MSCT_PDIS {
            let i = tables.n_pdis;
            tables.pdis[i] = MsctPdis {
                low_domain,
                high_domain,
                max_processor_capacity,
                max_memory_capacity,
            };
            tables.n_pdis = i + 1;
            count += 1;
        }
        cur += len;
    }
    count
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → MSCT must also be identity-mapped.
pub unsafe fn parse_msct(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut msct: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"MSCT" && msct.is_none() {
                msct = Some(phys);
            }
        })?;
    }
    let msct = msct.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (msct as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 20 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(msct as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    let n = parse_msct_body(body);
    MSCT_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_msct_known() -> bool {
    MSCT_PARSED.load(Ordering::Acquire)
}

pub fn msct_info() -> Option<MsctInfo> {
    if !is_msct_known() {
        return None;
    }
    Some(MSCT_DATA.lock().info)
}

pub fn copy_msct_pdis(out: &mut [MsctPdis]) -> usize {
    let t = MSCT_DATA.lock();
    let n = t.n_pdis.min(out.len());
    out[..n].copy_from_slice(&t.pdis[..n]);
    n
}

#[doc(hidden)]
pub fn __test_parse_msct_body(body: &[u8]) -> u32 {
    let n = parse_msct_body(body);
    MSCT_PARSED.store(true, Ordering::Release);
    n
}

// ───────────────────────────────────────────────────────────────────
// XENV — Xen Environment Table.
// Spec: `acpi/specification/tables-boot-dbgp-wpbt-msct-xenv.md` §5.
// ───────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct XenvInfo {
    pub grant_table_base: u64,
    pub grant_table_size: u64,
    pub event_vector: u32,
}

static XENV_DATA: IrqSafeSpinLock<XenvInfo> = IrqSafeSpinLock::new(XenvInfo {
    grant_table_base: 0,
    grant_table_size: 0,
    event_vector: 0,
});
static XENV_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_xenv_body(body: &[u8]) {
    if body.len() < SDT_HEADER_SIZE + 24 {
        return;
    }
    let off = SDT_HEADER_SIZE;
    let grant_table_base = u64::from_le_bytes([
        body[off],
        body[off + 1],
        body[off + 2],
        body[off + 3],
        body[off + 4],
        body[off + 5],
        body[off + 6],
        body[off + 7],
    ]);
    let grant_table_size = u64::from_le_bytes([
        body[off + 8],
        body[off + 9],
        body[off + 10],
        body[off + 11],
        body[off + 12],
        body[off + 13],
        body[off + 14],
        body[off + 15],
    ]);
    let event_vector = u32::from_le_bytes([
        body[off + 16],
        body[off + 17],
        body[off + 18],
        body[off + 19],
    ]);
    *XENV_DATA.lock() = XenvInfo {
        grant_table_base,
        grant_table_size,
        event_vector,
    };
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → XENV must also be identity-mapped.
pub unsafe fn parse_xenv(rsdp_phys: PhysAddr) -> Result<(), AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut xenv: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"XENV" && xenv.is_none() {
                xenv = Some(phys);
            }
        })?;
    }
    let xenv = xenv.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (xenv as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 24 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(xenv as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    parse_xenv_body(body);
    XENV_PARSED.store(true, Ordering::Release);
    Ok(())
}

pub fn xenv_info() -> Option<XenvInfo> {
    if !XENV_PARSED.load(Ordering::Acquire) {
        return None;
    }
    Some(*XENV_DATA.lock())
}

#[doc(hidden)]
pub fn __test_parse_xenv_body(body: &[u8]) {
    parse_xenv_body(body);
    XENV_PARSED.store(true, Ordering::Release);
}

// ───────────────────────────────────────────────────────────────────
// TCPA — TPM 1.2 event log location.
// Spec: `acpi/specification/tables-tcpa-mchi-phat-stao-uefi.md` §1.
// ───────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct TcpaInfo {
    pub platform_class: u16,
    pub log_area_min: u32,
    pub log_area_phys: u64,
}

static TCPA_DATA: IrqSafeSpinLock<TcpaInfo> = IrqSafeSpinLock::new(TcpaInfo {
    platform_class: 0,
    log_area_min: 0,
    log_area_phys: 0,
});
static TCPA_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_tcpa_body(body: &[u8]) {
    if body.len() < SDT_HEADER_SIZE + 14 {
        return;
    }
    let off = SDT_HEADER_SIZE;
    let platform_class = u16::from_le_bytes([body[off], body[off + 1]]);
    let log_area_min =
        u32::from_le_bytes([body[off + 2], body[off + 3], body[off + 4], body[off + 5]]);
    let log_area_phys = u64::from_le_bytes([
        body[off + 6],
        body[off + 7],
        body[off + 8],
        body[off + 9],
        body[off + 10],
        body[off + 11],
        body[off + 12],
        body[off + 13],
    ]);
    *TCPA_DATA.lock() = TcpaInfo {
        platform_class,
        log_area_min,
        log_area_phys,
    };
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → TCPA must also be identity-mapped.
pub unsafe fn parse_tcpa(rsdp_phys: PhysAddr) -> Result<(), AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut tcpa: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"TCPA" && tcpa.is_none() {
                tcpa = Some(phys);
            }
        })?;
    }
    let tcpa = tcpa.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (tcpa as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 14 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(tcpa as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    parse_tcpa_body(body);
    TCPA_PARSED.store(true, Ordering::Release);
    Ok(())
}

pub fn tcpa_info() -> Option<TcpaInfo> {
    if !TCPA_PARSED.load(Ordering::Acquire) {
        return None;
    }
    Some(*TCPA_DATA.lock())
}

#[doc(hidden)]
pub fn __test_parse_tcpa_body(body: &[u8]) {
    parse_tcpa_body(body);
    TCPA_PARSED.store(true, Ordering::Release);
}

// ───────────────────────────────────────────────────────────────────
// MCHI — Management Controller Host Interface.
// Spec: `acpi/specification/tables-tcpa-mchi-phat-stao-uefi.md` §2.
// ───────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct MchiInfo {
    pub interface_type: u8,
    pub protocols: u8,
    pub identifier: u64,
    pub base: u64,
}

static MCHI_DATA: IrqSafeSpinLock<MchiInfo> = IrqSafeSpinLock::new(MchiInfo {
    interface_type: 0,
    protocols: 0,
    identifier: 0,
    base: 0,
});
static MCHI_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_mchi_body(body: &[u8]) {
    // Body offsets: InterfaceType (1) + Protocols (1) + Reserved (6) +
    //               Identifier (8) + BaseAddress GAS (12).
    if body.len() < SDT_HEADER_SIZE + 28 {
        return;
    }
    let off = SDT_HEADER_SIZE;
    let interface_type = body[off];
    let protocols = body[off + 1];
    let identifier = u64::from_le_bytes([
        body[off + 8],
        body[off + 9],
        body[off + 10],
        body[off + 11],
        body[off + 12],
        body[off + 13],
        body[off + 14],
        body[off + 15],
    ]);
    // GAS at off+16..off+28, address @ +20..28.
    let base = u64::from_le_bytes([
        body[off + 20],
        body[off + 21],
        body[off + 22],
        body[off + 23],
        body[off + 24],
        body[off + 25],
        body[off + 26],
        body[off + 27],
    ]);
    *MCHI_DATA.lock() = MchiInfo {
        interface_type,
        protocols,
        identifier,
        base,
    };
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → MCHI must also be identity-mapped.
pub unsafe fn parse_mchi(rsdp_phys: PhysAddr) -> Result<(), AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut mchi: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"MCHI" && mchi.is_none() {
                mchi = Some(phys);
            }
        })?;
    }
    let mchi = mchi.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (mchi as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 28 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(mchi as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    parse_mchi_body(body);
    MCHI_PARSED.store(true, Ordering::Release);
    Ok(())
}

pub fn mchi_info() -> Option<MchiInfo> {
    if !MCHI_PARSED.load(Ordering::Acquire) {
        return None;
    }
    Some(*MCHI_DATA.lock())
}

#[doc(hidden)]
pub fn __test_parse_mchi_body(body: &[u8]) {
    parse_mchi_body(body);
    MCHI_PARSED.store(true, Ordering::Release);
}

// ───────────────────────────────────────────────────────────────────
// PHAT — Platform Health Assessment Table.
// Spec: `acpi/specification/tables-tcpa-mchi-phat-stao-uefi.md` §3.
// ───────────────────────────────────────────────────────────────────

pub const MAX_PHAT_HEALTH: usize = 16;

#[derive(Copy, Clone, Debug, Default)]
pub struct PhatHealthRecord {
    pub am_healthy: u8,
    pub device_guid: [u8; 16],
}

struct PhatTables {
    health: [PhatHealthRecord; MAX_PHAT_HEALTH],
    n_health: usize,
}

impl PhatTables {
    const EMPTY: Self = Self {
        health: [PhatHealthRecord {
            am_healthy: 0,
            device_guid: [0u8; 16],
        }; MAX_PHAT_HEALTH],
        n_health: 0,
    };
}

static PHAT_DATA: IrqSafeSpinLock<PhatTables> = IrqSafeSpinLock::new(PhatTables::EMPTY);
static PHAT_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_phat_body(body: &[u8]) -> u32 {
    let mut tables = PHAT_DATA.lock();
    *tables = PhatTables::EMPTY;
    let mut cur = SDT_HEADER_SIZE;
    let mut count = 0u32;
    while cur + 4 <= body.len() {
        let kind = u16::from_le_bytes([body[cur], body[cur + 1]]);
        let len = u16::from_le_bytes([body[cur + 2], body[cur + 3]]) as usize;
        if len < 4 || cur + len > body.len() {
            break;
        }
        let entry = &body[cur..cur + len];

        // Type 1: Health Data — 5..6 = AmHealthy, 6..22 = DeviceGuid.
        if kind == 1 && entry.len() >= 22 {
            let am_healthy = entry[5];
            let mut guid = [0u8; 16];
            guid.copy_from_slice(&entry[6..22]);
            if tables.n_health < MAX_PHAT_HEALTH {
                let i = tables.n_health;
                tables.health[i] = PhatHealthRecord {
                    am_healthy,
                    device_guid: guid,
                };
                tables.n_health = i + 1;
                count += 1;
            }
        }
        cur += len;
    }
    count
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → PHAT must also be identity-mapped.
pub unsafe fn parse_phat(rsdp_phys: PhysAddr) -> Result<u32, AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut phat: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"PHAT" && phat.is_none() {
                phat = Some(phys);
            }
        })?;
    }
    let phat = phat.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (phat as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(phat as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    let n = parse_phat_body(body);
    PHAT_PARSED.store(true, Ordering::Release);
    Ok(n)
}

pub fn is_phat_known() -> bool {
    PHAT_PARSED.load(Ordering::Acquire)
}

pub fn copy_phat_health(out: &mut [PhatHealthRecord]) -> usize {
    let t = PHAT_DATA.lock();
    let n = t.n_health.min(out.len());
    out[..n].copy_from_slice(&t.health[..n]);
    n
}

#[doc(hidden)]
pub fn __test_parse_phat_body(body: &[u8]) -> u32 {
    let n = parse_phat_body(body);
    PHAT_PARSED.store(true, Ordering::Release);
    n
}

// ───────────────────────────────────────────────────────────────────
// StAO — Status Override Table.
// Spec: `acpi/specification/tables-tcpa-mchi-phat-stao-uefi.md` §4.
// ───────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct StaoInfo {
    pub ignore_uart: bool,
}

static STAO_DATA: IrqSafeSpinLock<StaoInfo> = IrqSafeSpinLock::new(StaoInfo { ignore_uart: false });
static STAO_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_stao_body(body: &[u8]) {
    if body.len() < SDT_HEADER_SIZE + 1 {
        return;
    }
    *STAO_DATA.lock() = StaoInfo {
        ignore_uart: body[SDT_HEADER_SIZE] != 0,
    };
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → StAO must also be identity-mapped.
pub unsafe fn parse_stao(rsdp_phys: PhysAddr) -> Result<(), AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut stao: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"STAO" && stao.is_none() {
                stao = Some(phys);
            }
        })?;
    }
    let stao = stao.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (stao as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 1 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(stao as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    parse_stao_body(body);
    STAO_PARSED.store(true, Ordering::Release);
    Ok(())
}

pub fn stao_info() -> Option<StaoInfo> {
    if !STAO_PARSED.load(Ordering::Acquire) {
        return None;
    }
    Some(*STAO_DATA.lock())
}

#[doc(hidden)]
pub fn __test_parse_stao_body(body: &[u8]) {
    parse_stao_body(body);
    STAO_PARSED.store(true, Ordering::Release);
}

// ───────────────────────────────────────────────────────────────────
// UEFI — UEFI ACPI Data Table.
// Spec: `acpi/specification/tables-tcpa-mchi-phat-stao-uefi.md` §5.
// ───────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct UefiTableInfo {
    pub identifier: [u8; 16],
    pub data_offset: u16,
}

static UEFI_DATA: IrqSafeSpinLock<UefiTableInfo> = IrqSafeSpinLock::new(UefiTableInfo {
    identifier: [0u8; 16],
    data_offset: 0,
});
static UEFI_PARSED: AtomicBool = AtomicBool::new(false);

fn parse_uefi_body(body: &[u8]) {
    if body.len() < SDT_HEADER_SIZE + 18 {
        return;
    }
    let off = SDT_HEADER_SIZE;
    let mut identifier = [0u8; 16];
    identifier.copy_from_slice(&body[off..off + 16]);
    let data_offset = u16::from_le_bytes([body[off + 16], body[off + 17]]);
    *UEFI_DATA.lock() = UefiTableInfo {
        identifier,
        data_offset,
    };
}

/// # Safety
/// `rsdp_phys` must point at identity-mapped memory; the chain of
/// XSDT → UEFI must also be identity-mapped.
pub unsafe fn parse_uefi(rsdp_phys: PhysAddr) -> Result<(), AcpiError> {
    // SAFETY: caller assertion.
    let xsdt = unsafe { parse_rsdp(rsdp_phys)? };
    let mut uefi: Option<u64> = None;
    // SAFETY: caller assertion.
    unsafe {
        walk_xsdt(xsdt, |phys, hdr| {
            if &hdr.signature == b"UEFI" && uefi.is_none() {
                uefi = Some(phys);
            }
        })?;
    }
    let uefi = uefi.ok_or(AcpiError::NoSrat)?;
    // SAFETY: caller assertion.
    let total = unsafe { (uefi as *const SdtHeader).read_unaligned().length as usize };
    if total < SDT_HEADER_SIZE + 18 {
        return Err(AcpiError::BadXsdtSignature);
    }
    // SAFETY: caller assertion.
    let body = unsafe { core::slice::from_raw_parts(uefi as *const u8, total) };
    if checksum(body) != 0 {
        return Err(AcpiError::BadTableChecksum);
    }
    parse_uefi_body(body);
    UEFI_PARSED.store(true, Ordering::Release);
    Ok(())
}

pub fn uefi_table_info() -> Option<UefiTableInfo> {
    if !UEFI_PARSED.load(Ordering::Acquire) {
        return None;
    }
    Some(*UEFI_DATA.lock())
}

#[doc(hidden)]
pub fn __test_parse_uefi_body(body: &[u8]) {
    parse_uefi_body(body);
    UEFI_PARSED.store(true, Ordering::Release);
}

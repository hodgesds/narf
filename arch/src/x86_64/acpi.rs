//! ACPI table parser — clean-room.
//!
//! Reference: **"Advanced Configuration and Power Interface (ACPI)
//! Specification" v6.5** (free PDF, uefi.org). Section numbers
//! below (`§5.x`) point at that document.
//!
//! ## Discovery
//!
//! The Root System Description Pointer (RSDP) lives at one of two
//! places on a BIOS-booted x86_64 system (§5.2.5.1):
//!
//!   1. The first 1 KiB of the EBDA — base = `*(u16*)0x40E << 4`.
//!   2. The BIOS read-only area `0xE0000 .. 0xFFFFF`.
//!
//! In both cases the RSDP starts with the 8-byte signature
//! `b"RSD PTR "` on a 16-byte boundary. UEFI passes the RSDP via
//! the boot protocol's configuration table — Limine surfaces it
//! through `LimineRsdpRequest`. Stage cut: scan EBDA + the BIOS
//! window; an explicit `set_rsdp_phys` lets a Limine-aware boot
//! path override the discovery.
//!
//! ## Tables we surface
//!
//! - **MADT (`APIC`)** — multi-APIC description table. The entries
//!   tell us the LAPIC base + every per-CPU LAPIC + IOAPICs.
//! - **HPET** — high-precision event timer base address.
//! - **MCFG** — PCIe ECAM base address (replaces the hard-coded
//!   `0xE0000000` we use today).
//! - **FADT (`FACP`)** — fixed ACPI description table; we pull
//!   the IA-PC boot architecture flags + reset-register info.
//!
//! Stage cut: pure-data parsers + a `Tables` snapshot. Wiring
//! into `narf-bus` (PCIe ECAM base override), `narf-time` (HPET
//! base override), and `narf-interrupts` (MADT-discovered APIC
//! topology) is a separate follow-up — this lands the parser
//! alone so all consumers can switch over.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use core::sync::atomic::{AtomicU64, Ordering};

/// 8-byte ASCII RSDP signature.
pub const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";

/// 4-byte SDT signatures we recognise.
pub const SIG_MADT: &[u8; 4] = b"APIC";
pub const SIG_HPET: &[u8; 4] = b"HPET";
pub const SIG_MCFG: &[u8; 4] = b"MCFG";
pub const SIG_FADT: &[u8; 4] = b"FACP";

/// Where RSDP discovery starts looking when no override is set.
const EBDA_PTR_PHYS: u64 = 0x40E;
const BIOS_AREA_LO: u64 = 0xE_0000;
const BIOS_AREA_HI: u64 = 0xF_FFFF;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AcpiError {
    NoRsdp,
    BadChecksum,
    NoXsdt,
    BadTable,
}

/// Decoded RSDP (revision 2.0 form — has `xsdt_address`).
#[derive(Copy, Clone, Debug)]
pub struct Rsdp {
    pub revision: u8,
    pub oem_id: [u8; 6],
    pub rsdt_address: u32,
    pub xsdt_address: u64,
}

/// Common SDT header (§5.2.6).
#[derive(Copy, Clone, Debug)]
pub struct SdtHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub oem_id: [u8; 6],
}

/// MADT entries we decode.
#[derive(Copy, Clone, Debug)]
pub enum MadtEntry {
    /// Local APIC: `(processor_uid, apic_id, flags)`. Bit 0 of
    /// `flags` = enabled.
    LocalApic {
        processor_uid: u8,
        apic_id: u8,
        flags: u32,
    },
    /// IO APIC: `(id, address, gsi_base)`.
    IoApic { id: u8, address: u32, gsi_base: u32 },
    /// Interrupt Source Override: `(bus, source, gsi, flags)`.
    IntOverride {
        bus: u8,
        source: u8,
        gsi: u32,
        flags: u16,
    },
    /// Local x2APIC: `(x2apic_id, flags, processor_uid)`.
    LocalX2Apic {
        x2apic_id: u32,
        flags: u32,
        processor_uid: u32,
    },
}

/// Aggregated table snapshot.
#[derive(Debug, Default)]
pub struct Tables {
    pub local_apic_base: Option<u64>,
    pub local_apics: Vec<MadtEntry>,
    pub io_apics: Vec<MadtEntry>,
    pub overrides: Vec<MadtEntry>,
    pub hpet_base: Option<u64>,
    /// PCIe ECAM segments: `(base_phys, segment, start_bus, end_bus)`.
    pub mcfg_segments: Vec<(u64, u16, u8, u8)>,
    /// IA-PC boot flags from FADT (§5.2.9.3).
    pub iapc_boot_flags: Option<u16>,
}

// ── RSDP scan ───────────────────────────────────────────────────────

static RSDP_OVERRIDE: AtomicU64 = AtomicU64::new(0);

/// Override the RSDP physical address. Called from a Limine-aware
/// boot path with the address Limine surfaces; otherwise the
/// discovery scan kicks in.
pub fn set_rsdp_phys(phys: u64) {
    RSDP_OVERRIDE.store(phys, Ordering::Release);
}

/// Find the RSDP. Tries the override first, then EBDA, then the
/// BIOS read-only area.
///
/// # Safety
/// Caller asserts low memory `0x000..0xFFFFF` is readable through the
/// direct map (see [`pv`])
/// (true on x86_64 boot).
pub unsafe fn find_rsdp() -> Result<u64, AcpiError> {
    let over = RSDP_OVERRIDE.load(Ordering::Acquire);
    if over != 0 {
        // SAFETY: caller-asserted.
        if unsafe { check_rsdp(over) } {
            return Ok(over);
        }
    }
    // EBDA pointer (segment, shifted left 4).
    // SAFETY: low-memory phys, reached through the direct map.
    let ebda_seg = unsafe { core::ptr::read_volatile(pv(EBDA_PTR_PHYS) as *const u16) } as u64;
    let ebda_base = ebda_seg << 4;
    if ebda_base != 0 {
        // SAFETY: same.
        if let Some(p) = unsafe { scan_for_rsdp(ebda_base, ebda_base + 0x400) } {
            return Ok(p);
        }
    }
    // BIOS area.
    // SAFETY: same.
    if let Some(p) = unsafe { scan_for_rsdp(BIOS_AREA_LO, BIOS_AREA_HI) } {
        return Ok(p);
    }
    Err(AcpiError::NoRsdp)
}

unsafe fn scan_for_rsdp(lo: u64, hi: u64) -> Option<u64> {
    let mut p = lo & !0xF; // 16-byte aligned
    while p < hi {
        // SAFETY: low-memory range, reached through the direct map by
        // `check_rsdp`.
        if unsafe { check_rsdp(p) } {
            return Some(p);
        }
        p += 16;
    }
    None
}

/// Kernel-reachable pointer for a physical address.
///
/// `narf-memory` depends on `narf-arch`, so this crate cannot call
/// `PhysAddr::kernel_ptr` — it would be a dependency cycle. The offset
/// lives in `narf-lib`, which both crates depend on; `narf-memory`
/// publishes it there once the direct map is live.
///
/// Zero until published: before the MMU handoff, boot.S identity-maps low
/// memory so `phys == virt` and the early scan works unchanged. Afterwards the
/// kernel's low identity map is gone — only the AP trampoline survives — so
/// every ACPI table access has to go through the direct map or fault. The RSDP
/// scan over the BIOS area at 0xE0000 was the first thing to do so.
#[inline]
fn pv(phys: u64) -> u64 {
    narf_lib::directmap::pv(phys)
}

unsafe fn check_rsdp(phys: u64) -> bool {
    // SAFETY: caller-asserted readable.
    let sig = unsafe {
        let mut s = [0u8; 8];
        for (i, byte) in s.iter_mut().enumerate() {
            *byte = core::ptr::read_volatile(pv(phys + i as u64) as *const u8);
        }
        s
    };
    if &sig != RSDP_SIGNATURE {
        return false;
    }
    // Verify the revision-1 (20-byte) checksum first.
    let mut sum: u8 = 0;
    for i in 0..20 {
        // SAFETY: the signature matched above, so `phys` points at an RSDP whose
        // first 20 bytes (the revision-1 structure) are readable; `i < 20`.
        // SAFETY: Valid memory or trusted environment
        sum =
            sum.wrapping_add(unsafe { core::ptr::read_volatile(pv(phys + i as u64) as *const u8) });
    }
    if sum != 0 {
        return false;
    }
    // For revision >= 2, also verify the 36-byte checksum.
    // SAFETY: byte 15 (revision) is within the already-validated 20-byte RSDP.
    let rev = unsafe { core::ptr::read_volatile(pv(phys + 15) as *const u8) };
    if rev >= 2 {
        let mut sum: u8 = 0;
        for i in 0..36 {
            sum = sum
                // SAFETY: revision >= 2 means the RSDP is the 36-byte extended
                // form, so bytes 0..36 at `phys` are all readable; `i < 36`.
                // SAFETY: Valid memory or trusted environment
                .wrapping_add(unsafe {
                    core::ptr::read_volatile(pv(phys + i as u64) as *const u8)
                });
        }
        if sum != 0 {
            return false;
        }
    }
    true
}

/// Decode the RSDP at `phys`.
///
/// # Safety
/// Caller asserts `phys` is a validated RSDP (`check_rsdp`-passed).
pub unsafe fn decode_rsdp(phys: u64) -> Rsdp {
    // SAFETY: caller-asserted.
    let revision = unsafe { core::ptr::read_volatile(pv(phys + 15) as *const u8) };
    let mut oem_id = [0u8; 6];
    for (i, byte) in oem_id.iter_mut().enumerate() {
        // SAFETY: `check_rsdp` validated this RSDP, so bytes 9..15 (the 6-byte
        // OEMID field) lie within the readable RSDP region at `phys`.
        // SAFETY: Valid memory or trusted environment
        *byte = unsafe { core::ptr::read_volatile(pv(phys + 9 + i as u64) as *const u8) };
    }
    // SAFETY: same.
    let rsdt_address = unsafe { core::ptr::read_volatile(pv(phys + 16) as *const u32) };
    let xsdt_address = if revision >= 2 {
        // SAFETY: same.
        unsafe { core::ptr::read_volatile(pv(phys + 24) as *const u64) }
    } else {
        0
    };
    Rsdp {
        revision,
        oem_id,
        rsdt_address,
        xsdt_address,
    }
}

// ── SDT walk ────────────────────────────────────────────────────────

unsafe fn read_sdt_header(phys: u64) -> SdtHeader {
    let mut signature = [0u8; 4];
    let mut oem_id = [0u8; 6];
    // SAFETY: caller-asserted SDT phys.
    unsafe {
        for (i, byte) in signature.iter_mut().enumerate() {
            *byte = core::ptr::read_volatile(pv(phys + i as u64) as *const u8);
        }
        for (i, byte) in oem_id.iter_mut().enumerate() {
            *byte = core::ptr::read_volatile(pv(phys + 10 + i as u64) as *const u8);
        }
    }
    // SAFETY: same.
    let length = unsafe { core::ptr::read_volatile(pv(phys + 4) as *const u32) };
    // SAFETY: same.
    let revision = unsafe { core::ptr::read_volatile(pv(phys + 9) as *const u8) };
    SdtHeader {
        signature,
        length,
        revision,
        oem_id,
    }
}

unsafe fn checksum_ok(phys: u64, length: u32) -> bool {
    let mut sum: u8 = 0;
    // SAFETY: caller-asserted readable + bounded.
    for i in 0..length as u64 {
        // SAFETY: MMIO access to the device's mapped register block; the offset lies within the mapped BAR.
        sum = sum.wrapping_add(unsafe { core::ptr::read_volatile(pv(phys + i) as *const u8) });
    }
    sum == 0
}

/// Parse the XSDT at `phys` and walk every child SDT, populating
/// `Tables` for the SDTs we recognise.
///
/// # Safety
/// Caller asserts `phys` is a valid checksummed XSDT.
pub unsafe fn parse_xsdt(phys: u64) -> Result<Tables, AcpiError> {
    // SAFETY: caller-asserted.
    let h = unsafe { read_sdt_header(phys) };
    if &h.signature != b"XSDT" {
        return Err(AcpiError::NoXsdt);
    }
    // SAFETY: same.
    if !unsafe { checksum_ok(phys, h.length) } {
        return Err(AcpiError::BadChecksum);
    }
    let entries = (h.length as usize - 36) / 8;
    let mut t = Tables::default();
    for i in 0..entries {
        let sdt_phys =
            // SAFETY: same.
            unsafe { core::ptr::read_volatile(pv(phys + 36 + (i * 8) as u64) as *const u64) };
        // SAFETY: caller-trusted XSDT entry.
        let sh = unsafe { read_sdt_header(sdt_phys) };
        // Bad checksum on a child table is non-fatal — skip it.
        // SAFETY: same.
        if !unsafe { checksum_ok(sdt_phys, sh.length) } {
            continue;
        }
        match &sh.signature {
            // SAFETY: parsed below.
            SIG_MADT => unsafe { parse_madt(sdt_phys, sh.length, &mut t) },
            // SAFETY: the operation upholds its documented invariant (see surrounding context).
            SIG_HPET => unsafe { parse_hpet(sdt_phys, sh.length, &mut t) },
            // SAFETY: the operation upholds its documented invariant (see surrounding context).
            SIG_MCFG => unsafe { parse_mcfg(sdt_phys, sh.length, &mut t) },
            // SAFETY: the operation upholds its documented invariant (see surrounding context).
            SIG_FADT => unsafe { parse_fadt(sdt_phys, sh.length, &mut t) },
            _ => {}
        }
    }
    Ok(t)
}

// ── MADT (§5.2.12) ──────────────────────────────────────────────────

unsafe fn parse_madt(phys: u64, length: u32, t: &mut Tables) {
    // header (36) + local apic addr (4) + flags (4) + entries...
    if length < 44 {
        return;
    }
    // SAFETY: caller-asserted SDT phys.
    let lapic_addr = unsafe { core::ptr::read_volatile(pv(phys + 36) as *const u32) };
    t.local_apic_base = Some(lapic_addr as u64);
    let mut off: u64 = 44;
    while (off as u32) + 2 <= length {
        // SAFETY: same.
        let kind = unsafe { core::ptr::read_volatile(pv(phys + off) as *const u8) };
        // SAFETY: same.
        let len = unsafe { core::ptr::read_volatile(pv(phys + off + 1) as *const u8) } as u64;
        if len < 2 {
            break;
        }
        match kind {
            0 if len >= 8 => {
                // Local APIC entry.
                // SAFETY: same.
                let pid = unsafe { core::ptr::read_volatile(pv(phys + off + 2) as *const u8) };
                // SAFETY: same.
                let aid = unsafe { core::ptr::read_volatile(pv(phys + off + 3) as *const u8) };
                // SAFETY: same.
                let flags = unsafe { core::ptr::read_volatile(pv(phys + off + 4) as *const u32) };
                t.local_apics.push(MadtEntry::LocalApic {
                    processor_uid: pid,
                    apic_id: aid,
                    flags,
                });
            }
            1 if len >= 12 => {
                // IOAPIC entry.
                // SAFETY: same.
                let id = unsafe { core::ptr::read_volatile(pv(phys + off + 2) as *const u8) };
                // SAFETY: same.
                let addr = unsafe { core::ptr::read_volatile(pv(phys + off + 4) as *const u32) };
                // SAFETY: same.
                let gsi = unsafe { core::ptr::read_volatile(pv(phys + off + 8) as *const u32) };
                t.io_apics.push(MadtEntry::IoApic {
                    id,
                    address: addr,
                    gsi_base: gsi,
                });
            }
            2 if len >= 10 => {
                // Interrupt Source Override.
                // SAFETY: same.
                let bus = unsafe { core::ptr::read_volatile(pv(phys + off + 2) as *const u8) };
                // SAFETY: same.
                let source = unsafe { core::ptr::read_volatile(pv(phys + off + 3) as *const u8) };
                // SAFETY: same.
                let gsi = unsafe { core::ptr::read_volatile(pv(phys + off + 4) as *const u32) };
                // SAFETY: same.
                let flags = unsafe { core::ptr::read_volatile(pv(phys + off + 8) as *const u16) };
                t.overrides.push(MadtEntry::IntOverride {
                    bus,
                    source,
                    gsi,
                    flags,
                });
            }
            9 if len >= 16 => {
                // Local x2APIC entry.
                // SAFETY: same.
                let xid = unsafe { core::ptr::read_volatile(pv(phys + off + 4) as *const u32) };
                // SAFETY: same.
                let flags = unsafe { core::ptr::read_volatile(pv(phys + off + 8) as *const u32) };
                // SAFETY: same.
                let pid = unsafe { core::ptr::read_volatile(pv(phys + off + 12) as *const u32) };
                t.local_apics.push(MadtEntry::LocalX2Apic {
                    x2apic_id: xid,
                    flags,
                    processor_uid: pid,
                });
            }
            _ => {}
        }
        off += len;
    }
}

// ── HPET (Intel HPET 1.0a §3.2.4) ───────────────────────────────────

unsafe fn parse_hpet(phys: u64, length: u32, t: &mut Tables) {
    // header (36) + event_timer_block_id (4) + base_address (12) + ...
    if length < 56 {
        return;
    }
    // The 64-bit base lives in the GAS at offset 44, address field
    // at +4 within the GAS.
    // SAFETY: caller-asserted.
    let base = unsafe { core::ptr::read_volatile(pv(phys + 44 + 4) as *const u64) };
    t.hpet_base = Some(base);
}

// ── MCFG (PCIe firmware spec §4.1.2) ────────────────────────────────

unsafe fn parse_mcfg(phys: u64, length: u32, t: &mut Tables) {
    // header (36) + reserved (8) + per-segment entries (16 each).
    if length < 44 {
        return;
    }
    let mut off: u64 = 44;
    while (off as u32) + 16 <= length {
        // SAFETY: caller-asserted.
        let base = unsafe { core::ptr::read_volatile(pv(phys + off) as *const u64) };
        // SAFETY: same.
        let seg = unsafe { core::ptr::read_volatile(pv(phys + off + 8) as *const u16) };
        // SAFETY: same.
        let start_b = unsafe { core::ptr::read_volatile(pv(phys + off + 10) as *const u8) };
        // SAFETY: same.
        let end_b = unsafe { core::ptr::read_volatile(pv(phys + off + 11) as *const u8) };
        t.mcfg_segments.push((base, seg, start_b, end_b));
        off += 16;
    }
}

// ── FADT (§5.2.9) ───────────────────────────────────────────────────

unsafe fn parse_fadt(phys: u64, length: u32, t: &mut Tables) {
    // IA-PC Boot Architecture Flags at offset 109 (u16).
    if length < 111 {
        return;
    }
    // SAFETY: caller-asserted.
    let flags = unsafe { core::ptr::read_volatile(pv(phys + 109) as *const u16) };
    t.iapc_boot_flags = Some(flags);
}

// ── Top-level helper ────────────────────────────────────────────────

/// One-shot: discover RSDP, decode it, walk the XSDT, return the
/// aggregated table snapshot.
///
/// # Safety
/// Caller asserts low memory + the SDT physical addresses are
/// reachable through the direct map (see [`pv`]).
pub unsafe fn discover() -> Result<Tables, AcpiError> {
    // SAFETY: caller-asserted.
    let rsdp_phys = unsafe { find_rsdp() }?;
    // SAFETY: validated by find_rsdp.
    let rsdp = unsafe { decode_rsdp(rsdp_phys) };
    if rsdp.xsdt_address == 0 {
        // ACPI 1.0 RSDT path — not used by any modern QEMU/firmware
        // we care about; reject for now.
        return Err(AcpiError::NoXsdt);
    }
    // SAFETY: caller-asserted; checksum verified inside parse_xsdt.
    unsafe { parse_xsdt(rsdp.xsdt_address) }
}

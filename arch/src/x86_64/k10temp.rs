//! AMD k10temp — CPU temperature via SMN (System Management Network).
//!
//! On Family 0x17 / 0x19 the Northbridge exposes a SMN port through
//! PCI device 0:18.3 (function 3 of the data-fabric host). The SMN
//! is an in-die routing network linking the cores, the IOD, and the
//! various IP blocks; the SMU's per-package thermal sensor lives
//! at SMN address **0x59800** on Family 0x17 (Zen / Zen2 / Zen3) and
//! **0x59800** on Family 0x19 (Zen4) — same offset, different
//! decoding for the part-specific T-control offset (Tctl_offset).
//!
//! The SMN port is two registers in PCI config space of D0F3:
//!
//! | offset | name              | direction        |
//! |--------|-------------------|------------------|
//! | 0x60   | SMN_INDEX         | host → SMN addr  |
//! | 0x64   | SMN_DATA          | SMN → host data  |
//!
//! Read sequence:
//!   1. Write the 32-bit SMN address (`0x59800`) into D0F3:0x60.
//!   2. Read 32 bits from D0F3:0x64.
//!   3. Bits[31:21] = raw 11-bit Tctl reading in 0.125 °C units.
//!   4. Compute Tctl_c = (raw * 125) / 1000.
//!   5. Subtract the per-part Tctl_offset (see `tctl_offset_for`).
//!
//! Tctl is a "control temperature" — it tracks Tdie (die junction)
//! with a part-specific offset for thermal-management dispatch.
//! For OS-visible reading we usually want Tdie = Tctl - Tctl_offset.
//!
//! Linux reference (post 2026-05-20 GPL relicense — direct citation
//! allowed): `drivers/hwmon/k10temp.c` (`read_tempreg_nb_zen` +
//! `read_tempreg_ccd_zen` + the per-SKU offset table).

extern crate alloc;

// ── SMN port + register addresses ──────────────────────────────────

/// PCI bus:device.function of the SMN host on Family 0x17 / 0x19.
pub const SMN_PCI_BDF: (u8, u8, u8) = (0, 0x18, 0x3);
/// SMN_INDEX register offset in D0F3 config space.
pub const SMN_INDEX_OFF: u8 = 0x60;
/// SMN_DATA register offset.
pub const SMN_DATA_OFF: u8 = 0x64;
/// SMU report for package Tctl on Zen2 / Zen3 / Zen4.
pub const SMN_ADDR_TEMP_REPORT: u32 = 0x0005_9800;
/// Bit position of the raw Tctl reading in SMN_DATA.
pub const TCTL_SHIFT: u32 = 21;
/// Width of the raw Tctl field — 11 bits.
pub const TCTL_MASK: u32 = (1 << 11) - 1;

// ── Per-part Tctl offsets ──────────────────────────────────────────
//
// Tctl is biased so the SMU's thermal-throttle target is around
// 100 °C across the SKU mix; for OS-side display we subtract the
// per-part offset to get Tdie. The table below mirrors Linux's
// k10temp.c k10temp_specific_quirks — only the SKUs the bring-up
// arc targets are listed.

/// Family-Model pairs that ship a 49 °C Tctl_offset (Threadripper
/// 1xxx, EPYC Naples). Bring-up arc doesn't target these but the
/// constant documents the encoding.
pub const TCTL_OFFSET_49C: i32 = 49;
/// Tctl_offset for Ryzen 7 1700X / 1800X / Threadripper 1900X.
pub const TCTL_OFFSET_20C: i32 = 20;
/// Tctl_offset = 0 for laptop Zen2 (Renoir / Lucienne / Cezanne)
/// and Zen4 mobile (Phoenix). The bring-up targets.
pub const TCTL_OFFSET_LAPTOP: i32 = 0;

/// Pick the Tctl_offset for a known Family-Model. Caller obtains
/// `family` from CPUID `0x0` extended-family + family, `model`
/// from extended-model + model.
pub fn tctl_offset_for(family: u8, model: u8) -> i32 {
    match (family, model) {
        // Renoir / Lucienne / Cezanne — Family 0x17, Model 0x30-0xAF
        (0x17, 0x30..=0xAF) => TCTL_OFFSET_LAPTOP,
        // Phoenix / Phoenix2 / HawkPoint — Family 0x19, Model 0x40-0x4F + 0x70-0x7F
        (0x19, 0x40..=0x4F) | (0x19, 0x70..=0x7F) => TCTL_OFFSET_LAPTOP,
        // First-gen Ryzen high-end SKUs (1700X / 1800X) — 20 °C.
        // Must come BEFORE the 0x00..=0x0F arm or it gets shadowed.
        (0x17, 0x01) => TCTL_OFFSET_20C,
        // Threadripper / EPYC Naples / older first-gen — 49 °C offset.
        (0x17, 0x00..=0x0F) => TCTL_OFFSET_49C,
        // Unknown — assume 0 (matches all laptop SKUs).
        _ => TCTL_OFFSET_LAPTOP,
    }
}

// ── Decoder ────────────────────────────────────────────────────────

/// Errors reading the temperature sensor.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum K10TempError {
    /// SMN port returned all-ones (no D0F3 device or wedged controller).
    NoSensor,
}

/// Decode a raw 32-bit SMN_DATA reading to milli-degrees Celsius
/// (m°C) after subtracting `tctl_offset` (degrees C).
///
/// Returns `NoSensor` when the raw value is 0xFFFFFFFF — typical
/// when D0F3 wasn't enumerated or the SMN is gated for power.
pub fn decode_tdie_millicelsius(raw: u32, tctl_offset_c: i32) -> Result<i32, K10TempError> {
    if raw == 0xFFFF_FFFF {
        return Err(K10TempError::NoSensor);
    }
    // raw[31:21] is Tctl in units of 0.125 °C — multiply by 125 to
    // get milli-degrees, then subtract the per-part offset.
    let tctl_raw = ((raw >> TCTL_SHIFT) & TCTL_MASK) as i32;
    let tctl_mc = tctl_raw * 125;
    let tdie_mc = tctl_mc - tctl_offset_c * 1000;
    Ok(tdie_mc)
}

/// Caller-supplied SMN port operations. Plugged in by the driver
/// glue so the decoder is unit-testable against a mock. Real
/// implementation hits `narf_bus::pci_config_*` against
/// `SMN_PCI_BDF`.
pub trait SmnPort {
    /// Write `addr` to SMN_INDEX (D0F3:0x60).
    fn write_index(&mut self, addr: u32);
    /// Read SMN_DATA (D0F3:0x64).
    fn read_data(&mut self) -> u32;
}

/// One-shot temperature read through any [`SmnPort`].
/// Returns Tdie in m°C.
pub fn read_tdie_millicelsius<P: SmnPort>(
    port: &mut P,
    tctl_offset_c: i32,
) -> Result<i32, K10TempError> {
    port.write_index(SMN_ADDR_TEMP_REPORT);
    let raw = port.read_data();
    decode_tdie_millicelsius(raw, tctl_offset_c)
}

pub mod test_support {
    //! Mock SMN port for smokes — captures the index write and
    //! returns a scripted data value.
    use super::SmnPort;

    #[derive(Debug, Default)]
    pub struct MockSmn {
        pub last_index: u32,
        pub data: u32,
    }
    impl MockSmn {
        #[allow(dead_code)]
        pub fn new(data: u32) -> Self {
            Self {
                last_index: 0,
                data,
            }
        }
    }
    impl SmnPort for MockSmn {
        fn write_index(&mut self, addr: u32) {
            self.last_index = addr;
        }
        fn read_data(&mut self) -> u32 {
            self.data
        }
    }
}

pub use test_support::MockSmn;

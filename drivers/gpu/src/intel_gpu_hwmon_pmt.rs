//! BMG PUNIT PMT energy, using the GPU's own BAR0 and SoC remapper.
//! Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad:
//! xe_vsec.c::{bmg_telemetry,xe_guid_decode,xe_pmt_telem_read},
//! xe_soc_remapper.c, regs/{xe_pmt,xe_soc_remapper_regs}.h;
//! platform/x86/intel/pmt/{telemetry,class}.c descriptor bounds/units;
//! xe_hwmon.c::{xe_hwmon_energy_get,xe_hwmon_get_preregistration_info}.
//!
//! BMG supplies synthetic VSEC headers, not a discovered PCI DVSEC table.
//! This narrow reader admits the actual first BAR0 discovery record and its
//! PUNIT telemetry GUID, then uses Xe's fixed callback aperture. It exposes
//! no arbitrary telemetry ranges. The retained GT mutex owns selector RMW,
//! readback and payload; no other NARF GPU/platform consumer uses this selector.
//! Future SoC/remapper users must join this owner before being admitted.

use super::{Io, MAX_AGE_NS};

pub(super) const DISCOVERY: u64 = 0x35b000;
pub(super) const SELECTOR: u64 = 0x280008;
pub(super) const ENERGY: u64 = 0x360230; // SOC_BASE +0xe0000 +PUNIT0x200 +energy0x30
const TABLE_BYTES: u64 = 2 * 16;
const TELEMETRY_MASK: u32 = 0xff00_0000;
const SHIFT: u8 = 14;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity([u32; 3]);
impl Identity {
    fn read(io: &mut impl Io) -> Option<Self> {
        let words = [
            io.read(DISCOVERY)?,
            io.read(DISCOVERY + 4)?,
            io.read(DISCOVERY + 8)?,
        ];
        (!words.contains(&u32::MAX)).then_some(Self(words))
    }
    fn qualifies(self, bar_len: u64) -> bool {
        let [header, guid, base] = self.0;
        let size = u64::from((header >> 12) & 0xffff) * 4;
        // PUNIT telemetry, BMG device field (not the PCI DID). The source
        // ignores GUID iteration/segment/SKU bits; the entire GUID is still
        // retained and compared on every sample to detect identity changes.
        if (guid >> 12) & 0xffff != 0xe2f8
            || (guid >> 28) & 3 != 1
            || guid >> 30 != 0
            || (header >> 4) & 0xf != 0
            || size < 0x38
            || base & 7 != 0
        {
            return false;
        }
        let resolved = match header & 0xf {
            2 => u64::from(base),                  // ACCESS_BARID with BIR0
            3 => DISCOVERY + 16 + u64::from(base), // ACCESS_LOCAL: first entry end
            _ => return false,
        };
        // Descriptor base describes a resource; BMG's callback overrides
        // its generic address with the fixed GUID-decoded remap aperture.
        resolved.checked_add(size).is_some_and(|end| end <= bar_len)
    }
}

#[derive(Clone, Copy, Debug)]
struct Series {
    identity: Identity,
    raw: [u32; 2], // pkg, card; two independent aligned32-bit counters
    total: [u64; 2],
    at: u64,
}
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Energy {
    series: Option<Series>,
    lost: bool,
}
impl Energy {
    pub(super) fn invalidate(&mut self) {
        self.series = None;
        self.lost = true;
    }
    pub(super) fn sample(&mut self, bar_len: u64, now: u64, io: &mut impl Io) -> Option<[u64; 2]> {
        if self.lost {
            return None;
        }
        let observed = self.capture(bar_len, now, io);
        if observed.is_none() {
            self.invalidate()
        }
        observed
    }
    fn capture(&mut self, bar_len: u64, now: u64, io: &mut impl Io) -> Option<[u64; 2]> {
        // No BAR sizing/remapping while the GT runs. The exclusive PCI probe
        // already mapped this actual BAR; every fixed access is checked before
        // touching discovery or a selector outside that resource.
        if DISCOVERY.checked_add(TABLE_BYTES)? > bar_len
            || ENERGY.checked_add(8)? > bar_len
            || SELECTOR.checked_add(4)? > bar_len
            || self
                .series
                .is_some_and(|old| now <= old.at || now - old.at > MAX_AGE_NS)
        {
            return None;
        }
        let identity = Identity::read(io)?;
        if !identity.qualifies(bar_len) || self.series.is_some_and(|old| old.identity != identity) {
            return None;
        }
        let selector = io.read(SELECTOR).filter(|&v| v != u32::MAX)?;
        let selected = selector & !TELEMETRY_MASK; // PUNIT region index0
        if selector != selected && !io.write(SELECTOR, selected) {
            return None;
        }
        if io.read(SELECTOR) != Some(selected) {
            return None;
        }
        // Xe memcpy_fromio promises no atomic two-counter snapshot. Each
        // field is an aligned32-bit counter; never splice halves of one value.
        let raw = [io.read(ENERGY)?, io.read(ENERGY + 4)?];
        if raw.contains(&u32::MAX)
            || io.read(SELECTOR) != Some(selected)
            || Identity::read(io)? != identity
        {
            return None;
        }
        let total = if let Some(old) = self.series {
            [
                old.total[0].checked_add(u64::from(raw[0].wrapping_sub(old.raw[0])))?,
                old.total[1].checked_add(u64::from(raw[1].wrapping_sub(old.raw[1])))?,
            ]
        } else {
            [u64::from(raw[0]), u64::from(raw[1])]
        };
        let values = [
            u64::try_from((u128::from(total[0]) * 1_000_000) >> SHIFT).ok()?,
            u64::try_from((u128::from(total[1]) * 1_000_000) >> SHIFT).ok()?,
        ];
        self.series = Some(Series {
            identity,
            raw,
            total,
            at: now,
        });
        Some(values)
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn exhaust_for_test(&mut self) {
        self.series.as_mut().expect("PMT series").total = [u64::MAX; 2];
    }
}

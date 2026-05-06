//! AMD PowerPlay (DPM) PPTable walker — clean-room.
//!
//! Reference: AMD `smu_v11_0_pptable.h` (MIT-licensed; structure
//! definitions are non-GPL) and the public AMD PowerPlay
//! Programming Guide. The PPTable carries the silicon-specific
//! DPM (Dynamic Power Management) state space — clock + voltage
//! tuples the SMU steps through for `pm-runtime` policy.
//!
//! ## Layout (V11.0 — Vega+ baseline)
//!
//! ```text
//! +0x00   ATOM_COMMON_TABLE_HEADER (4 B)
//! +0x04   ulPlatformDescriptorOffset        u32
//! +0x08   ulOverdriveTable8Offset           u32
//! +0x0C   ulOverdriveLimitsMaxOffset        u32
//! +0x10   ulOverdriveLimitsMinOffset        u32
//! +0x14   ulFanTableOffset                  u32
//! +0x18   ulPowerTuneTableOffset            u32
//! +0x1C   ulSocClockDependencyTableOffset   u32
//! +0x20   ulMemClockDependencyTableOffset   u32
//! +0x24   ulVdciClockDependencyTableOffset  u32
//! +0x28   ulPCIeClockDependencyTableOffset  u32
//! +0x2C   ulMVddVoltageTableOffset          u32
//! +0x30   ulVddciVoltageTableOffset         u32
//! +0x34   ulVddcVoltageTableOffset          u32
//! +0x38   ulPpmTableOffset                  u32
//! +0x3C   ulSrambitTableOffset              u32
//! +0x40   ulHardLimitTableOffset            u32
//! ...
//! ```
//!
//! Each `ul*Offset` field is BIOS-relative; `0` means the table
//! isn't present on this chip. The clock-dependency tables are
//! arrays of `(clock_10khz, voltage_index)` pairs that the SMU
//! interpolates between for DPM transitions.
//!
//! ## Stage-6 scope
//!
//! Decode the offset directory + header revision check; expose
//! per-table-offset accessors so a future SMU bring-up path can
//! follow them. Decoding individual clock-dependency or voltage
//! tables is deliberately deferred — each one is a per-family
//! struct shape, and Stage-6 only needs the directory.

use core::fmt;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PpTableError {
    /// Table too short for the offset directory.
    Truncated,
    /// `ucTableContentRevision` not in the supported range.
    UnsupportedVersion(u8),
    /// Caller asked for an offset that isn't present on this chip.
    TableAbsent,
    /// Stored offset overflows the table image bounds.
    OffsetOutOfBounds,
}

/// Decoded PowerPlay table header + offset directory.
#[derive(Copy, Clone)]
pub struct PpTable {
    pub structure_size: u16,
    pub format_revision: u8,
    pub content_revision: u8,
    /// Stored BIOS-relative offsets, one per table. `0` means
    /// "not present on this chip".
    offsets: [u32; 16],
}

impl fmt::Debug for PpTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let present = self.offsets.iter().filter(|&&o| o != 0).count();
        f.debug_struct("PpTable")
            .field("rev", &(self.format_revision, self.content_revision))
            .field("size", &self.structure_size)
            .field("tables_present", &present)
            .finish()
    }
}

/// Per-table offsets, indexed by `PpTable::Subtable`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Subtable {
    PlatformDescriptor = 0,
    OverdriveTable8 = 1,
    OverdriveLimitsMax = 2,
    OverdriveLimitsMin = 3,
    FanTable = 4,
    PowerTuneTable = 5,
    SocClockDependency = 6,
    MemClockDependency = 7,
    VdciClockDependency = 8,
    PcieClockDependency = 9,
    MvddVoltage = 10,
    VddciVoltage = 11,
    VddcVoltage = 12,
    PpmTable = 13,
    SrambitTable = 14,
    HardLimitTable = 15,
}

impl PpTable {
    /// Decode the offset directory from raw bytes. Caller obtains
    /// the slice via `Atombios::data_table(0x32)` (PowerPlay table
    /// id per AtomBios.h).
    pub fn parse(raw: &[u8]) -> Result<Self, PpTableError> {
        // 4-byte common header + 16 × u32 offsets = 68 bytes minimum.
        if raw.len() < 68 {
            return Err(PpTableError::Truncated);
        }
        let structure_size = u16::from_le_bytes([raw[0], raw[1]]);
        let format_revision = raw[2];
        let content_revision = raw[3];
        // V11.x is the Vega+ baseline; earlier (V8/V9) revisions
        // need a separate path.
        if format_revision != 11 {
            return Err(PpTableError::UnsupportedVersion(format_revision));
        }
        let mut offsets = [0u32; 16];
        for (i, slot) in offsets.iter_mut().enumerate() {
            let o = 4 + i * 4;
            *slot = u32::from_le_bytes([raw[o], raw[o + 1], raw[o + 2], raw[o + 3]]);
        }
        Ok(Self {
            structure_size,
            format_revision,
            content_revision,
            offsets,
        })
    }

    /// BIOS-relative offset for `tbl`. Returns `TableAbsent` if
    /// the chip doesn't carry that subtable.
    pub fn offset(&self, tbl: Subtable) -> Result<u32, PpTableError> {
        let o = self.offsets[tbl as usize];
        if o == 0 {
            return Err(PpTableError::TableAbsent);
        }
        Ok(o)
    }

    /// Borrow the bytes covering `tbl`'s payload, starting at the
    /// table's first byte. The first 2 bytes are
    /// `ATOM_COMMON_TABLE_HEADER::usStructureSize` so caller can
    /// bound the payload from there. `bios_image` is the FULL
    /// BIOS image (the same slice fed to `Atombios::parse`).
    pub fn subtable<'a>(
        &self,
        bios_image: &'a [u8],
        tbl: Subtable,
    ) -> Result<&'a [u8], PpTableError> {
        let off = self.offset(tbl)? as usize;
        if off + 2 > bios_image.len() {
            return Err(PpTableError::OffsetOutOfBounds);
        }
        let len = u16::from_le_bytes([bios_image[off], bios_image[off + 1]]) as usize;
        if off + len > bios_image.len() {
            return Err(PpTableError::OffsetOutOfBounds);
        }
        Ok(&bios_image[off..off + len])
    }

    /// Number of subtables actually present (offset != 0). Useful
    /// for diagnostics + observability snapshots.
    pub fn present_count(&self) -> usize {
        self.offsets.iter().filter(|&&o| o != 0).count()
    }
}

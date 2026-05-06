//! ATOM_FIRMWARE_INFO table walker — clean-room.
//!
//! Reference: AMD `AtomBios.h` (MIT-licensed; structure
//! definitions are non-GPL). The `ATOM_FIRMWARE_INFO_V*` family
//! of tables carries BIOS-level metadata: BIOS revision, ROM
//! checksum, default engine clock, default memory clock, default
//! voltage. Used during bring-up to know what frequencies the
//! firmware programmed before the kernel took over.
//!
//! ## Layout (V3.4 — current Vega/Navi default)
//!
//! ```text
//! offset  field                              type
//! +0x00   ATOM_COMMON_TABLE_HEADER (4 B)     ucTable* + usSize
//! +0x04   ulFirmwareRevision                 u32
//! +0x08   ulDefaultEngineClock               u32 (in 10 kHz units)
//! +0x0C   ulDefaultMemoryClock               u32 (in 10 kHz units)
//! +0x10   ulSPLL_OutputFreq                  u32 (10 kHz)
//! +0x14   ulGPUPLL_OutputFreq                u32 (10 kHz)
//! +0x18   ulReserved1                        u32
//! +0x1C   ulReserved2                        u32
//! +0x20   ulMaxPixelClockPLL_Output          u32 (10 kHz)
//! +0x24   ulBinaryAlteredInfo                u32
//! +0x28   ulDefaultDispEngineClkFreq         u32 (10 kHz)
//! +0x2C   ucReserved3                        u8
//! +0x2D   ucMinAllowedBL_Level               u8
//! +0x2E   usBootUpVDDCVoltage                u16 (mV)
//! +0x30   usLcdMinPixelClockPLL_Output       u16 (MHz)
//! +0x32   usLcdMaxPixelClockPLL_Output       u16 (MHz)
//! +0x34   ulReserved4                        u32
//! +0x38   ucRemoteDisplayConfig              u8
//! +0x39   ucReserved5[8]
//! +0x41   ulReserved6                        u32
//! +0x45   ulReserved7                        u32
//! +0x49   ulReserved8                        u32
//! +0x4D   usReserved11[2]                    u16 × 2
//! +0x51   usFirmwareCapability               u16
//! +0x53   usCoreReferenceClock               u16 (10 kHz)
//! +0x55   usMemoryReferenceClock             u16 (10 kHz)
//! +0x57   usUniphyDPModeExtClkFreq           u16 (10 kHz)
//! +0x59   ucMemoryModule_ID                  u8
//! +0x5A   ucCoolingSolution_ID               u8
//! +0x5B   ucReserved9[5]
//! ```
//!
//! Older revisions (V1.x / V2.x) have shorter layouts; the
//! `ucTableContentRevision` byte at the start of the
//! `ATOM_COMMON_TABLE_HEADER` discriminates. Stage-5 ships V3.4
//! decoding (the format every Vega+ chip emits); older Bonaire /
//! Hawaii variants need a separate path.

use core::fmt;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FwInfoError {
    /// Table too short for even the common header.
    Truncated,
    /// `ucTableContentRevision` not in the supported range
    /// (Stage-5 ships v3.x).
    UnsupportedVersion(u8),
}

/// Decoded `ATOM_FIRMWARE_INFO_V3_4` payload. Frequencies are in
/// 10 kHz units (the on-the-wire encoding); voltage is mV.
#[derive(Copy, Clone)]
pub struct FwInfoV3 {
    pub structure_size: u16,
    pub format_revision: u8,
    pub content_revision: u8,
    pub firmware_revision: u32,
    pub default_engine_clock_10khz: u32,
    pub default_memory_clock_10khz: u32,
    pub spll_output_freq_10khz: u32,
    pub gpupll_output_freq_10khz: u32,
    pub max_pixel_clock_pll_10khz: u32,
    pub default_disp_engine_clk_10khz: u32,
    pub bootup_vddc_mv: u16,
    pub firmware_capability: u16,
    pub core_reference_clock_10khz: u16,
    pub memory_reference_clock_10khz: u16,
    pub uniphy_dp_mode_ext_clk_10khz: u16,
    pub memory_module_id: u8,
    pub cooling_solution_id: u8,
}

impl fmt::Debug for FwInfoV3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FwInfoV3")
            .field("rev", &(self.format_revision, self.content_revision))
            .field("firmware_revision", &self.firmware_revision)
            .field(
                "default_engine_mhz",
                &(self.default_engine_clock_10khz / 100),
            )
            .field(
                "default_memory_mhz",
                &(self.default_memory_clock_10khz / 100),
            )
            .field(
                "max_pixel_clock_mhz",
                &(self.max_pixel_clock_pll_10khz / 100),
            )
            .field("bootup_vddc_mv", &self.bootup_vddc_mv)
            .finish_non_exhaustive()
    }
}

impl FwInfoV3 {
    /// Engine clock in MHz (lossy — the on-the-wire encoding is
    /// 10 kHz units, so this is `freq_10khz / 100`).
    pub fn default_engine_mhz(&self) -> u32 {
        self.default_engine_clock_10khz / 100
    }
    /// Memory clock in MHz.
    pub fn default_memory_mhz(&self) -> u32 {
        self.default_memory_clock_10khz / 100
    }
}

/// Decode a `ATOM_FIRMWARE_INFO_V3_x` table from raw bytes.
///
/// Caller obtains the slice via `Atombios::data_table(table_id)`.
/// `table_id` for FIRMWARE_INFO is `0x04` per AtomBios.h.
pub fn parse(raw: &[u8]) -> Result<FwInfoV3, FwInfoError> {
    if raw.len() < 0x5B {
        return Err(FwInfoError::Truncated);
    }
    let structure_size = u16::from_le_bytes([raw[0], raw[1]]);
    let format_revision = raw[2];
    let content_revision = raw[3];
    if content_revision >> 4 != 3 {
        // We only ship V3.x decoding.
        return Err(FwInfoError::UnsupportedVersion(content_revision));
    }
    let read_u32 = |o: usize| u32::from_le_bytes([raw[o], raw[o + 1], raw[o + 2], raw[o + 3]]);
    let read_u16 = |o: usize| u16::from_le_bytes([raw[o], raw[o + 1]]);

    Ok(FwInfoV3 {
        structure_size,
        format_revision,
        content_revision,
        firmware_revision: read_u32(0x04),
        default_engine_clock_10khz: read_u32(0x08),
        default_memory_clock_10khz: read_u32(0x0C),
        spll_output_freq_10khz: read_u32(0x10),
        gpupll_output_freq_10khz: read_u32(0x14),
        max_pixel_clock_pll_10khz: read_u32(0x20),
        default_disp_engine_clk_10khz: read_u32(0x28),
        bootup_vddc_mv: read_u16(0x2E),
        firmware_capability: read_u16(0x51),
        core_reference_clock_10khz: read_u16(0x53),
        memory_reference_clock_10khz: read_u16(0x55),
        uniphy_dp_mode_ext_clk_10khz: read_u16(0x57),
        memory_module_id: raw[0x59],
        cooling_solution_id: raw[0x5A],
    })
}

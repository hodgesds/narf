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
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FwInfoV3 {
    pub structure_size: u16,
    pub format_revision: u8,
    pub content_revision: u8,
    pub firmware_revision: u32,
    /// `bootup_sclk_in10khz` — the shader clock VBIOS left running.
    pub bootup_sclk_10khz: u32,
    /// `bootup_mclk_in10khz`.
    pub bootup_mclk_10khz: u32,
    /// `enum atombios_firmware_capability`, a **32-bit** mask.
    pub firmware_capability: u32,
    pub main_call_parser_entry: u32,
    pub bios_scratch_reg_startaddr: u32,
    pub bootup_vddc_mv: u16,
    pub bootup_vddci_mv: u16,
    pub bootup_mvddc_mv: u16,
    pub bootup_vddgfx_mv: u16,
    pub mem_module_id: u8,
    pub coolingsolution_id: u8,
    pub mc_baseaddr_high: u32,
    pub mc_baseaddr_low: u32,
    /// v3.4 and up: when non-zero, the driver takes the PowerPlay table from
    /// its own firmware blob rather than from VBIOS.
    pub pplib_pptable_id: Option<u32>,
}

/// `ATOM_FIRMWARE_CAP_FIRMWARE_POSTED` — VBIOS has run its POST.
pub const ATOM_FIRMWARE_CAP_FIRMWARE_POSTED: u32 = 0x0000_0001;
/// `ATOM_FIRMWARE_CAP_GPU_VIRTUALIZATION`.
pub const ATOM_FIRMWARE_CAP_GPU_VIRTUALIZATION: u32 = 0x0000_0002;
/// `ATOM_FIRMWARE_CAP_SRAM_ECC`.
pub const ATOM_FIRMWARE_CAP_SRAM_ECC: u32 = 0x0000_0200;

/// `sizeof(struct atom_firmware_info_v3_1)` — also v3.2 and v3.3, which add
/// no fields. v3.4 is 108 bytes and v3.5 is 172.
pub const FWINFO_V3_1_BYTES: usize = 72;
/// `sizeof(struct atom_firmware_info_v3_4)`. The `pplib_pptable_id` field this
/// parser exposes needs this much.
pub const FWINFO_V3_4_BYTES: usize = 108;

impl FwInfoV3 {
    /// Boot-up shader clock in MHz (lossy — the on-the-wire encoding is
    /// 10 kHz units).
    pub fn bootup_sclk_mhz(&self) -> u32 {
        self.bootup_sclk_10khz / 100
    }
    /// Boot-up memory clock in MHz.
    pub fn bootup_mclk_mhz(&self) -> u32 {
        self.bootup_mclk_10khz / 100
    }
    /// `ATOM_FIRMWARE_CAP_FIRMWARE_POSTED`: VBIOS has POSTed the card, so the
    /// clocks and apertures it left behind are meaningful.
    pub fn firmware_posted(&self) -> bool {
        self.firmware_capability & ATOM_FIRMWARE_CAP_FIRMWARE_POSTED != 0
    }
}

/// Decode an `atom_firmware_info_v3_x` table.
///
/// Caller obtains the slice via `Atombios::data_table`. FIRMWARE_INFO is index
/// 4 of `atom_master_list_of_data_tables_v2_1`.
///
/// LINUX-GAP: this used to decode the legacy `ATOM_FIRMWARE_INFO_V1_4` layout
/// from the pre-atomfirmware `AtomBios.h`, under a header comment reading
/// "Layout (V3.4 — current Vega/Navi default)". The two tables share only
/// their first three fields. Everything from offset 0x10 on was a different
/// field:
///
///   0x10  spll_output_freq            ->  firmware_capability
///   0x14  gpupll_output_freq          ->  main_call_parser_entry
///   0x20  max_pixel_clock_pll         ->  bootup_mvddc_mv
///   0x28  default_disp_engine_clk     ->  mc_baseaddr_high
///   0x2e  bootup_vddc_mv              ->  the top half of mc_baseaddr_low
///   0x51  firmware_capability         ->  past the end of the structure
///   0x53  core_reference_clock        ->  does not exist
///   0x55  memory_reference_clock      ->  does not exist
///   0x57  uniphy_dp_mode_ext_clk      ->  does not exist
///   0x59  memory_module_id            ->  really 0x24
///   0x5a  cooling_solution_id         ->  really 0x25
///
/// `firmware_capability` is also 32 bits, not 16. And the length guard
/// demanded 0x5B bytes against a v3.1/v3.2/v3.3 structure of 72 (0x48), so a
/// real table from any of those minors was rejected as truncated before any of
/// the offsets mattered.
pub fn parse(raw: &[u8]) -> Result<FwInfoV3, FwInfoError> {
    if raw.len() < FWINFO_V3_1_BYTES {
        return Err(FwInfoError::Truncated);
    }
    let structure_size = u16::from_le_bytes([raw[0], raw[1]]);
    let format_revision = raw[2];
    let content_revision = raw[3];
    // `atom_common_table_header.content_revision` is the minor, whole — not a
    // nibble pair. Shifting it right by four made every real v3.x table look
    // like version zero.
    if format_revision != 3 {
        return Err(FwInfoError::UnsupportedVersion(format_revision));
    }
    let read_u32 = |o: usize| u32::from_le_bytes([raw[o], raw[o + 1], raw[o + 2], raw[o + 3]]);
    let read_u16 = |o: usize| u16::from_le_bytes([raw[o], raw[o + 1]]);

    Ok(FwInfoV3 {
        structure_size,
        format_revision,
        content_revision,
        firmware_revision: read_u32(0x04),
        bootup_sclk_10khz: read_u32(0x08),
        bootup_mclk_10khz: read_u32(0x0c),
        firmware_capability: read_u32(0x10),
        main_call_parser_entry: read_u32(0x14),
        bios_scratch_reg_startaddr: read_u32(0x18),
        bootup_vddc_mv: read_u16(0x1c),
        bootup_vddci_mv: read_u16(0x1e),
        bootup_mvddc_mv: read_u16(0x20),
        bootup_vddgfx_mv: read_u16(0x22),
        mem_module_id: raw[0x24],
        coolingsolution_id: raw[0x25],
        mc_baseaddr_high: read_u32(0x28),
        mc_baseaddr_low: read_u32(0x2c),
        // v3.4 added the field; a v3.1..v3.3 table simply ends before it.
        pplib_pptable_id: if raw.len() >= FWINFO_V3_4_BYTES {
            Some(read_u32(0x3c))
        } else {
            None
        },
    })
}

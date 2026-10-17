//! Navi22 board PowerPlay preparation. Linux smu_v11_0_setup_pptable and
//! sienna_cichlid_setup_pptable select the SKU table, then overlay VBIOS board
//! wiring. Layouts: smu_v11_0_7_pptable.h, smu11_driver_if_sienna_cichlid.h,
//! atomfirmware.h. No ATOM execution or overdrive settings are applied.
use crate::{amdgpu_smu_navi22 as smu, amdgpu_vbios::Vbios, atombios};
use alloc::vec::Vec;
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, CapError, CapOp, Write};

// sizeof/offsetof from the primary headers. Navy Flounder's observed wire
// revision is 16.0 / format 0x81 / SMC version 1, with the shared 1668-byte
// PPTable_t layout (not Sienna Cichlid's 15.0 / 0x80 / version 7).
// linux: n/a (smu_11_0_7_powerplay_table.smc_pptable at byte 802, probe-verified; header not in checker sets)
const DRIVER_BYTES: usize = 802;
pub(crate) const SMC_BYTES: usize = 1668; // linux: sizeof(PPTable_t)
const TABLE_BYTES: usize = DRIVER_BYTES + SMC_BYTES;
// linux: offsetof(PPTable_t, I2cControllers)
const BOARD_START: usize = 1344;
// after BoardReserved[11], before MmHubPadding
// linux: offsetof(PPTable_t, MmHubPadding)
const BOARD_END: usize = 1636;
// linux: offsetof(PPTable_t, FreqTableGfx)
const GFX_CLOCKS: usize = 524; // FreqTableGfx[16]
const BOARD_RESERVED: usize = 1592; // linux: offsetof(PPTable_t, BoardReserved)

// smu11_driver_if_sienna_cichlid.h. Retain posted display/memory/link clocks
// until DCN owns their constraints. No deep sleep, BACO, hub gating or GFXOFF.
// RSMU_SMN_CG (44) and DF_CSTATE (45) are in every
// sienna_cichlid_init_allowed_features mask; with PMFW-centralized C-state
// management (MP0 11.0.11) PMFW owns the DF C-states.
// linux: (1ULL << FEATURE_DPM_PREFETCHER_BIT) | (1ULL << FEATURE_DPM_GFXCLK_BIT) | (1ULL << FEATURE_PPT_BIT) | (1ULL << FEATURE_TDC_BIT) | (1ULL << FEATURE_VR0HOT_BIT) | (1ULL << FEATURE_FW_CTF_BIT) | (1ULL << FEATURE_FAN_CONTROL_BIT) | (1ULL << FEATURE_THERMAL_BIT) | (1ULL << FEATURE_GFX_SS_BIT) | (1ULL << FEATURE_OUT_OF_BAND_MONITOR_BIT) | (1ULL << FEATURE_APCC_DFLL_BIT) | (1ULL << FEATURE_RSMU_SMN_CG_BIT) | (1ULL << FEATURE_DF_CSTATE_BIT)
const BOOT_ALLOWED: u64 = (1 << 0)
    | (1 << 1)
    | (1 << 24)
    | (1 << 25)
    | (1 << 29)
    | (1 << 31)
    | (1 << 32)
    | (1 << 33)
    | (1 << 37)
    | (1 << 38)
    | (1 << 42)
    | (1 << 44)
    | (1 << 45);
/// Features whose activity would break this boot's ownership assumptions if
/// PMFW reported them without being allowed: memory/link/display DPM and
/// rail scaling (3,4,5,7,8,10,11), deep sleep (12..17), ULV (18), GFXOFF (20),
/// BACO (21), MM_DPM_PG (22) and MMHUB/ATHUB power gating (40, 41). Linux
/// never checks the running set; any other extra feature is tolerated.
// linux: (1ULL << FEATURE_DPM_UCLK_BIT) | (1ULL << FEATURE_DPM_FCLK_BIT) | (1ULL << FEATURE_DPM_SOCCLK_BIT) | (1ULL << FEATURE_DPM_LINK_BIT) | (1ULL << FEATURE_DPM_DCEFCLK_BIT) | (1ULL << FEATURE_MEM_VDDCI_SCALING_BIT) | (1ULL << FEATURE_MEM_MVDD_SCALING_BIT) | (0x3fULL << FEATURE_DS_GFXCLK_BIT) | (1ULL << FEATURE_GFX_ULV_BIT) | (1ULL << FEATURE_GFXOFF_BIT) | (1ULL << FEATURE_BACO_BIT) | (1ULL << FEATURE_MM_DPM_PG_BIT) | (1ULL << FEATURE_MMHUB_PG_BIT) | (1ULL << FEATURE_ATHUB_PG_BIT)
const BOOT_HAZARDS: u64 = (1 << 3)
    | (1 << 4)
    | (1 << 5)
    | (1 << 7)
    | (1 << 8)
    | (1 << 10)
    | (1 << 11)
    | (0x3f << 12)
    | (1 << 18)
    | (1 << 20)
    | (1 << 21)
    | (1 << 22)
    | (1 << 40)
    | (1 << 41);
// linux: (1ULL << FEATURE_DPM_GFXCLK_BIT) | (1ULL << FEATURE_PPT_BIT) | (1ULL << FEATURE_TDC_BIT) | (1ULL << FEATURE_FW_CTF_BIT) | (1ULL << FEATURE_FAN_CONTROL_BIT) | (1ULL << FEATURE_THERMAL_BIT)
const BOOT_REQUIRED: u64 = (1 << 1) | (1 << 24) | (1 << 25) | (1 << 31) | (1 << 32) | (1 << 33);
// DPM_UCLK/FCLK/SOCCLK/DCEFCLK plus board-supported memory rail scaling.
// Deep sleep, link DPM, BACO and clock/power gating stay excluded.
// linux: (1ULL << FEATURE_DPM_UCLK_BIT) | (1ULL << FEATURE_DPM_FCLK_BIT) | (1ULL << FEATURE_DPM_SOCCLK_BIT) | (1ULL << FEATURE_DPM_DCEFCLK_BIT)
const DISPLAY_REQUIRED: u64 = (1 << 3) | (1 << 4) | (1 << 5) | (1 << 8);
// linux-lit: 10=FEATURE_MEM_VDDCI_SCALING_BIT; 11=FEATURE_MEM_MVDD_SCALING_BIT
const DISPLAY_ALLOWED: u64 = DISPLAY_REQUIRED | (1 << 10) | (1 << 11);

/// Board-supported GFX DPM and autonomous power/fan/thermal protection only.
/// Memory, link and display clock transitions require a later DCN policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootPolicy {
    allowed: u64,
    board_features: u64,
}
impl BootPolicy {
    pub fn allowed(self) -> u64 {
        self.allowed
    }
    pub(crate) fn from_features(features: u64) -> Result<Self, Error> {
        if features & BOOT_REQUIRED != BOOT_REQUIRED {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            allowed: features & BOOT_ALLOWED,
            board_features: features,
        })
    }
    pub(crate) fn validate_enabled(self, enabled: u64) -> bool {
        enabled & BOOT_REQUIRED == BOOT_REQUIRED && enabled & !self.allowed & BOOT_HAZARDS == 0
    }
    pub(crate) fn display_allowed(self) -> Result<u64, Error> {
        if self.board_features & DISPLAY_REQUIRED != DISPLAY_REQUIRED {
            return Err(Error::Unsupported);
        }
        Ok(self.allowed | (self.board_features & DISPLAY_ALLOWED))
    }
    pub(crate) fn validate_display(self, enabled: u64) -> bool {
        let required = BOOT_REQUIRED | DISPLAY_REQUIRED;
        self.display_allowed().is_ok_and(|allowed| {
            enabled & required == required && enabled & !allowed & BOOT_HAZARDS == 0
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    MissingVbios,
    MissingTable,
    Allocation,
    Authority,
    Firmware(smu::Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub revision: u8,
    pub subsystem_vendor: u16,
    pub subsystem_device: u16,
}
struct ReadIdentity<'a>(&'a BusDevice);
impl CapOp<BusDeviceCap, Write> for ReadIdentity<'_> {
    type Output = Result<Identity, Error>;
    fn execute(self, cap: &Cap<BusDeviceCap, Write>) -> Result<Self::Output, CapError> {
        Ok((|| {
            let read = |offset| {
                narf_bus::pci::read_config32(cap, self.0, offset).map_err(|_| Error::Authority)
            };
            // linux: n/a (PCI id 1002:73df, pdev->device check in sienna_cichlid_patch_pptable_quirk)
            if read(0)? != 0x73df_1002 {
                return Err(Error::Unsupported);
            }
            let revision = read(8)?;
            let subsystem = read(0x2c)?;
            if revision == u32::MAX || subsystem == u32::MAX {
                return Err(Error::Invalid);
            }
            Ok(Identity {
                revision: revision as u8,
                subsystem_vendor: subsystem as u16,
                subsystem_device: (subsystem >> 16) as u16,
            })
        })())
    }
}
impl Identity {
    pub(crate) fn read(device: &BusDevice, cap: &Cap<BusDeviceCap, Write>) -> Result<Self, Error> {
        cap.invoke(ReadIdentity(device))
            .map_err(|_| Error::Authority)?
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Vbios,
    SmcFirmware,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub source: Source,
    pub table_id: u32,
    pub platform_caps: u32,
    pub thermal_controller: u8,
    pub software_shutdown_celsius: u16,
    pub oem_quirk: bool,
}
/// Immutable board configuration. Bytes can be inspected but not modified;
/// only this module constructs the image accepted by the SMU upload path.
#[derive(Debug)]
pub struct Prepared {
    bytes: Vec<u8>,
    info: Info,
}
impl Prepared {
    pub fn new(vbios: &Vbios, firmware: &smu::Firmware, identity: Identity) -> Result<Self, Error> {
        prepare(
            vbios.bytes(),
            firmware.image().map_err(Error::Firmware)?.powerplay(),
            identity,
        )
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn info(&self) -> Info {
        self.info
    }
    /// Validate a restricted cold-boot policy before hardware is claimed.
    /// The table's own feature bits remain an upper bound on driver policy.
    pub fn boot_policy(&self) -> Result<BootPolicy, Error> {
        boot_policy(&self.bytes)
    }
}
fn boot_policy(bytes: &[u8]) -> Result<BootPolicy, Error> {
    // linux-lit: 4=offsetof(PPTable_t, FeaturesToRun); 12=offsetof(PPTable_t, FeaturesToRun) + 8
    let features = u64::from_le_bytes(bytes.get(4..12).ok_or(Error::Invalid)?.try_into().unwrap());
    BootPolicy::from_features(features)
}
fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn validate_table(table: &[u8]) -> Result<(), Error> {
    // linux-lit: 0=offsetof(struct atom_common_table_header, structuresize)
    if table.len() != TABLE_BYTES || usize::from(u16_at(table, 0)) != TABLE_BYTES {
        return Err(Error::Invalid);
    }
    // linux: n/a (smu_11_0_7_powerplay_table: format_revision @2, table_size @5, format_id @15, probe-verified)
    if table[2..5] != [16, 0, 2] || u16_at(table, 15) != 0x81 || u32_at(table, DRIVER_BYTES) != 1 {
        return Err(Error::Unsupported);
    }
    // linux: n/a (smu_11_0_7_powerplay_table.table_size at byte 5, probe-verified; header not in checker sets)
    if usize::from(u16_at(table, 5)) != DRIVER_BYTES {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn prepare(
    vbios: &[u8],
    firmware_table: Option<&[u8]>,
    identity: Identity,
) -> Result<Prepared, Error> {
    let header = atombios::header::parse_rom_header(vbios).map_err(|_| Error::Invalid)?;
    let tables =
        atombios::tables::MasterDataTable::parse(vbios, &header).map_err(|_| Error::Invalid)?;
    if (tables.format_revision, tables.content_revision) != (2, 1) {
        return Err(Error::Unsupported);
    }
    // linux-lit: 4=offsetof(struct atom_master_list_of_data_tables_v2_1, firmwareinfo) / 2
    let fw_info = tables.table_slice(4).ok_or(Error::MissingTable)?;
    if fw_info.len() < 64 {
        return Err(Error::Invalid);
    }
    // linux-lit: 2=offsetof(struct atom_common_table_header, format_revision); 3=offsetof(struct atom_common_table_header, content_revision)
    if !matches!((fw_info[2], fw_info[3]), (3, 4) | (3, 5)) {
        return Err(Error::Unsupported);
    }
    // linux-lit: 60=offsetof(struct atom_firmware_info_v3_4, pplib_pptable_id)
    let table_id = u32_at(fw_info, 60);
    // SMC v2.0 contains one table; its table ID only chooses firmware vs VBIOS.
    // No fallback to the other source is allowed after the board selected one.
    let (source, table) = if table_id == 0 {
        (
            Source::Vbios,
            // linux-lit: 15=offsetof(struct atom_master_list_of_data_tables_v2_1, powerplayinfo) / 2
            tables.table_slice(15).ok_or(Error::MissingTable)?,
        )
    } else {
        (
            Source::SmcFirmware,
            firmware_table.ok_or(Error::MissingTable)?,
        )
    };
    validate_table(table)?;
    // linux-lit: 2=offsetof(struct atom_master_list_of_data_tables_v2_1, smc_dpm_info) / 2
    let board = tables.table_slice(2).ok_or(Error::MissingTable)?;
    // linux-lit: 296=sizeof(struct atom_smc_dpm_info_v4_9)
    if board.len() != 296 {
        return Err(Error::Invalid);
    }
    if board[2..4] != [4, 9] {
        return Err(Error::Unsupported);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(SMC_BYTES)
        .map_err(|_| Error::Allocation)?;
    bytes.extend_from_slice(&table[DRIVER_BYTES..]);
    // Linux smu_memcpy_trailing: all 292 board bytes, including the repurposed
    // tail for UMC flags / UCLK spread percentages. Keep GamingClk and the
    // final 32 bytes of SMU-private MmHubPadding from the selected SKU table.
    // linux-lit: 4=offsetof(struct atom_smc_dpm_info_v4_9, I2cControllers)
    bytes[BOARD_START..BOARD_END].copy_from_slice(&board[4..]);
    // linux: n/a (literal revision 0xC3 / vendor 0x1043 in sienna_cichlid_ppt.c:sienna_cichlid_patch_pptable_quirk)
    let oem_quirk = identity.revision == 0xc3
        && identity.subsystem_vendor == 0x1043
        && matches!(identity.subsystem_device, 0x16c2 | 0x133c);
    if oem_quirk {
        if identity.subsystem_device == 0x16c2 {
            // linux: n/a (literal BoardReserved[0] = 1387 in sienna_cichlid_ppt.c:sienna_cichlid_patch_pptable_quirk)
            bytes[BOARD_RESERVED..BOARD_RESERVED + 4].copy_from_slice(&1387u32.to_le_bytes());
        }
        // linux-lit: 32=NUM_GFXCLK_DPM_LEVELS * sizeof(uint16_t)
        for clock in bytes[GFX_CLOCKS..GFX_CLOCKS + 32].chunks_exact_mut(2) {
            // linux: n/a (literal 2500 MHz cap in sienna_cichlid_ppt.c:sienna_cichlid_patch_pptable_quirk)
            let value = u16::from_le_bytes(clock.try_into().unwrap()).min(2500);
            clock.copy_from_slice(&value.to_le_bytes());
        }
    }
    Ok(Prepared {
        bytes,
        info: Info {
            source,
            table_id,
            // linux: n/a (smu_11_0_7_powerplay_table.platform_caps at byte 17, probe-verified; header not in checker sets)
            platform_caps: u32_at(table, 17),
            // linux: n/a (smu_11_0_7_powerplay_table.thermal_controller_type at byte 21, probe-verified; header not in checker sets)
            thermal_controller: table[21],
            // linux: n/a (smu_11_0_7_powerplay_table.software_shutdown_temp at byte 28, probe-verified; header not in checker sets)
            software_shutdown_celsius: u16_at(table, 28),
            oem_quirk,
        },
    })
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_power_navi22_tests.rs"]
mod tests;

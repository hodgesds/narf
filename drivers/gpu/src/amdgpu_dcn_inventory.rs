//! Board routing for Navi22/DCN3.0, Phoenix/DCN3.1.4 and Navi48/DCN4.0.1, plus the APU memory
//! and reference-clock inventory. AUX, HPD and transmitter identities are
//! independently decoded from connector records and the GPIO pin LUT.
//!
//! None of it may be defaulted. The memory configuration sets every watermark,
//! the reference clock scales every latency register, and the VCO decides which
//! clock frequencies the dividers can produce — a plausible-looking guess for
//! any of them yields a picture that tears under load rather than an error. So
//! every value here is read from the platform's own tables, and a table that is
//! missing, the wrong version or self-inconsistent fails closed.
//!
//! Table layouts follow `atomfirmware.h`
//! (`atom_display_controller_info_v4_*`, `atom_integrated_system_info_v2_*`,
//! `display_object_info_table_v1_4`). Object ids use `ObjectID.h`, the values
//! Linux's `bios_parser_common.c` decodes these tables with (never the
//! unused `displayobject.h` numbering); the transmitter
//! mapping follows Linux `link_factory.c::translate_encoder_to_transmitter` and
//! the VCO read follows `dcn314_clk_mgr.c::get_vco_frequency_from_reg`.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_dcn_clk::Levels,
    amdgpu_dcn_display::Platform,
    amdgpu_dcn_profile::Profile,
    amdgpu_dml::{Memory, MemoryKind},
    atombios,
};
use alloc::vec::Vec;
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

/// Master data table indices from `atom_master_list_of_data_tables_v2_1`.
// linux: offsetof(struct atom_master_list_of_data_tables_v2_1, displayobjectinfo) / 2
const TABLE_DISPLAY_OBJECT_INFO: u16 = 22;
// linux: offsetof(struct atom_master_list_of_data_tables_v2_1, gpio_pin_lut) / 2
const TABLE_GPIO_PIN_LUT: u16 = 12;
// linux: offsetof(struct atom_master_list_of_data_tables_v2_1, dce_info) / 2
const TABLE_DCE_INFO: u16 = 27;
// linux: offsetof(struct atom_master_list_of_data_tables_v2_1, integratedsysteminfo) / 2
const TABLE_INTEGRATED_SYSTEM_INFO: u16 = 30;

/// `atom_display_object_path_v2` is sixteen bytes, and the paths follow the
/// four-byte common header plus `supporteddevices` and `number_of_path`.
const PATH_SIZE: usize = 16; // linux: sizeof(struct atom_display_object_path_v2)
                             // linux: offsetof(struct display_object_info_table_v1_4, display_path)
const PATHS_OFFSET: usize = 8;
/// `ObjectID.h` object-id encoding.
// linux: n/a (amdgpu/ObjectID.h OBJECT_ID_MASK 0x00FF; header not in checker set)
const OBJECT_ID_MASK: u16 = 0x00ff;
// linux: n/a (amdgpu/ObjectID.h ENUM_ID_SHIFT 0x08; header not in checker set)
const ENUM_ID_SHIFT: u32 = 8;
// linux: n/a (MISMATCH: amdgpu/ObjectID.h ENUM_ID_MASK = 0x0700; header not in checker set)
const ENUM_ID_MASK: u16 = 0x0f00;
// linux: n/a (amdgpu/ObjectID.h OBJECT_TYPE_SHIFT 0x0C; header not in checker set)
const OBJECT_TYPE_SHIFT: u32 = 12;
// linux: n/a (MISMATCH: amdgpu/ObjectID.h OBJECT_TYPE_MASK = 0x7000; header not in checker set)
const OBJECT_TYPE_MASK: u16 = 0xf000;
const TYPE_ENCODER: u16 = 0x02; // linux: OBJECT_TYPE_ENCODER@dc
const TYPE_CONNECTOR: u16 = 0x03; // linux: OBJECT_TYPE_CONNECTOR@dc
/// `atom_common_record_header` is two bytes, and `atom_hpd_int_record` adds the
/// pin id and its plug state. The list ends with a terminator record type.
const RECORD_HEADER: usize = 2; // linux: sizeof(struct atom_common_record_header)
const RECORD_I2C: u8 = 1; // linux: ATOM_I2C_RECORD_TYPE
const RECORD_HPD_INT: u8 = 2; // linux: ATOM_HPD_INT_RECORD_TYPE
const RECORD_CONNECTOR_SPEED: u8 = 4; // linux: ATOM_CONNECTOR_SPEED_UPTO
const RECORD_END: u8 = 0xff; // linux: ATOM_RECORD_END_TYPE
/// A connector's record list is short; this only bounds a malformed one.
const MAX_RECORDS: usize = 64; // linux: n/a (NARF bound on a malformed record list)
/// `num_dig_link_enc` for DCN314, and its four tunnelling endpoints.
pub const DIG_COUNT: u8 = 5; // linux: n/a (DCN 3.1.4 path)
pub const DPIA_COUNT: u8 = 4; // linux: n/a (DCN 3.1.4 path)
/// GPIO ids in the VBIOS are keys into the GPIO LUT, not hardware indices.
/// Both supported DCN generations use these GPIO registers at base index 2.
// linux-ctx: hdr=dcn seg=2
const GPIO_DDC1_A: u32 = 0x28d1; // linux: mmDC_GPIO_DDC1_A
const GPIO_HPD_A: u32 = 0x28f5; // linux: mmDC_GPIO_HPD_A
                                // linux: DC_GPIO_HPD_A__DC_GPIO_HPD1_A__SHIFT
                                // linux: DC_GPIO_HPD_A__DC_GPIO_HPD2_A__SHIFT
                                // linux: DC_GPIO_HPD_A__DC_GPIO_HPD3_A__SHIFT
                                // linux: DC_GPIO_HPD_A__DC_GPIO_HPD4_A__SHIFT
                                // linux: DC_GPIO_HPD_A__DC_GPIO_HPD5_A__SHIFT
                                // linux: DC_GPIO_HPD_A__DC_GPIO_HPD6_A__SHIFT
const HPD_SHIFTS: [u8; 6] = [0, 8, 16, 24, 26, 28];

/// `DIG0_DIG_BE_EN_CNTL`, per-DIG stride 0x100, at DCN base index 2. Bit zero
/// says the backend is already driving a link.
// DCN 3.1.4's offset; Navi22 uses DIG_BE_EN_CNTL - 1 (DCN30 mmDIG0_DIG_BE_EN_CNTL).
// linux: mmDIG0_DIG_BE_EN_CNTL + 1
const DIG_BE_EN_CNTL: u64 = 0x20b2;
const DIG_STRIDE: u64 = 0x100; // linux: mmDIG1_DIG_BE_EN_CNTL - mmDIG0_DIG_BE_EN_CNTL
                               // linux-ctx: reset

/// Routing compatibility does not grant access to DCN3 plane/timing methods.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Routing {
    Legacy(Profile),
    Navi48,
}
impl From<Profile> for Routing {
    fn from(profile: Profile) -> Self {
        Self::Legacy(profile)
    }
}
impl Routing {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        if gpu.chip.vid == crate::amdgpu::AMD_VENDOR && gpu.chip.did == crate::amdgpu::NAVI48 {
            crate::amdgpu_psp_ring::bank(
                gpu,
                crate::amdgpu_discovery::HW_ID_GC,
                &[(12, 0, 1)],
                0,
                0,
            )
            .map_err(|_| Error::Unsupported)?;
            Self::Navi48.bank(gpu, GPIO_HPD_A)?;
            Ok(Self::Navi48)
        } else {
            Profile::resolve(gpu)
                .map(Self::Legacy)
                .map_err(|_| Error::Unsupported)
        }
    }
    fn streams(self) -> u8 {
        match self {
            Self::Legacy(p) => p.streams(),
            Self::Navi48 => 4,
        }
    }
    fn hpd_count(self) -> u8 {
        if self == Self::Navi48 {
            4
        } else {
            6
        }
    }
    fn bank(self, gpu: &AmdGpu, last: u32) -> Result<u64, Error> {
        match self {
            // linux-lit: 2=mmDC_GPIO_HPD_A_BASE_IDX@dcn
            Self::Legacy(p) => p.bank(gpu, 2, last).map_err(|_| Error::Unsupported),
            Self::Navi48 => crate::amdgpu_psp_ring::bank(
                gpu,
                crate::amdgpu_discovery::HW_ID_DCN,
                &[(4, 0, 1), (4, 1, 0)],
                2,
                last,
            )
            .map_err(|_| Error::Unsupported),
        }
    }
    fn backend(self) -> (u64, u64) {
        match self {
            Self::Legacy(Profile::Navi22) => (DIG_BE_EN_CNTL - 1, DIG_STRIDE),
            Self::Legacy(Profile::Dcn314) => (DIG_BE_EN_CNTL, DIG_STRIDE),
            // dcn_4_1_0_offset.h DIG0..3_DIG_BE_EN_CNTL.
            Self::Navi48 => (0x20bd, 0x124), // linux: n/a (DCN 4.0.1 path)
        }
    }
}
/// `atom_dmi_t17_mem_type_def`: DDR5 is 34 and LPDDR5 is 35.
const MEM_TYPE_DDR5: u8 = 34; // linux: n/a (DCN 3.1.4 path)
const MEM_TYPE_LPDDR5: u8 = 35; // linux: n/a (DCN 3.1.4 path)
/// Linux derives the channel width from the memory type rather than reading it.
const DDR5_CHANNEL_WIDTH_BYTES: u32 = 8; // linux: n/a (DCN 3.1.4 path)
const LPDDR5_CHANNEL_WIDTH_BYTES: u32 = 4; // linux: n/a (DCN 3.1.4 path)
/// `atom_display_controller_info_v4_*` places `dce_refclk_10khz` here, in every
/// content revision from 4.1 to 4.5.
// linux: offsetof(struct atom_display_controller_info_v4_1, dce_refclk_10khz)
const DCE_REFCLK_OFFSET: usize = 12;
// linux: offsetof(struct atom_display_controller_info_v4_1, display_caps)
const DCE_DISPLAY_CAPS_OFFSET: usize = 4;
const DCE_INFO_CAPS_LTTPR_SUPPORT_ENABLE: u32 = 0x20; // linux: DCE_INFO_CAPS_LTTPR_SUPPORT_ENABLE
/// `atom_integrated_system_info_v2_*` field offsets, the same in v2.1 and v2.2.
const MEMORY_TYPE_OFFSET: usize = 26; // linux: n/a (DCN 3.1.4 path)
const CHANNEL_COUNT_OFFSET: usize = 27; // linux: n/a (DCN 3.1.4 path)

/// The CLK block is absent from the IP discovery table, so Linux hardcodes its
/// base too (`CLK_BASE` in `dcn314_clk_mgr.c`). This is the one register address
/// here that discovery cannot confirm, which is why the value it produces is
/// range-checked before being believed.
const CLK_BASE_DWORD: u64 = 0x0001_6c00; // linux: n/a (DCN 3.1.4 path)
const CLK1_CLK_PLL_REQ: u64 = 0x0237; // linux: n/a (DCN 3.1.4 path)
/// `dfs_ref_freq_khz` for DCN314.
const DFS_REF_KHZ: u64 = 48_000; // linux: n/a (DCN 3.1.4 path)
/// The DENTIST VCO is a few GHz; anything outside this cannot be one, and a
/// register read that produces it is a read of something else.
const VCO_MIN_KHZ: u32 = 600_000; // linux: n/a (DCN 3.1.4 path; NARF sanity bound)
const VCO_MAX_KHZ: u32 = 6_000_000; // linux: n/a (DCN 3.1.4 path; NARF sanity bound)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The table is absent, or the directory does not reach it.
    Missing,
    /// Present but a revision or shape this does not read.
    Unsupported,
    /// Present and the right shape, but self-inconsistent.
    Invalid,
    Revoked,
    DeviceGone,
}

/// A connector as the display-object table describes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Connector {
    DisplayPort,
    EmbeddedDisplayPort,
    HdmiTypeA,
    Other(u8),
}
/// One display path: a connector, and the physical transmitter its first
/// encoder drives. The transmitter is what a `Route`'s `backend` must be —
/// never a UCSI connector number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Path {
    pub connector: Connector,
    /// One-based instance from the object's enum id, as the table encodes it.
    pub connector_instance: u8,
    pub transmitter: u8,
    /// Physical DDC/AUX channel resolved from the I2C record and GPIO LUT.
    /// DP uses AUX, HDMI uses native I2C on these pins. None means no usable route.
    pub aux: Option<u8>,
    /// One-based ATOM HPD selector from the connector's record list, or zero
    /// when the board declares none for this connector.
    pub hpd: u8,
    pub device_tag: u16,
    /// ATOM_CONNECTOR_SPEED_UPTO's connector_max_speed in MHz, zero when the
    /// board declares none: the source's DP rate ceiling (UHBR10 from 10000,
    /// UHBR13.5 from 13500, UHBR20 from 20000; Linux's
    /// bios_parser_get_connector_speed_cap_info).
    pub max_speed_mhz: u32,
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}
/// The four-byte `atom_common_table_header`: size, then format and content
/// revision. A table whose declared size does not match what the directory
/// gave us is not a table we can read fields out of by offset.
fn header(table: &[u8], format: u8, content: &[u8]) -> Result<(), Error> {
    // linux-lit: 4=sizeof(struct atom_common_table_header)
    if table.len() < 4 {
        return Err(Error::Missing);
    }
    let size = u16_at(table, 0) as usize;
    // linux-lit: 4=sizeof(struct atom_common_table_header)
    if size < 4 || size > table.len() {
        return Err(Error::Invalid);
    }
    // linux-lit: 2=offsetof(struct atom_common_table_header, format_revision)
    // linux-lit: 3=offsetof(struct atom_common_table_header, content_revision)
    if table[2] != format || !content.contains(&table[3]) {
        return Err(Error::Unsupported);
    }
    Ok(())
}
fn directory(vbios: &[u8]) -> Result<atombios::tables::MasterDataTable<'_>, Error> {
    let rom = atombios::header::parse_rom_header(vbios).map_err(|_| Error::Invalid)?;
    let dir = atombios::tables::MasterDataTable::parse(vbios, &rom).map_err(|_| Error::Invalid)?;
    if (dir.format_revision, dir.content_revision) != (2, 1) {
        return Err(Error::Unsupported);
    }
    Ok(dir)
}
fn table(vbios: &[u8], index: u16) -> Result<&[u8], Error> {
    let dir = directory(vbios)?;
    if dir.n_tables <= index || dir.table_offset(index).is_none_or(|offset| offset == 0) {
        return Err(Error::Missing);
    }
    dir.table_slice(index).ok_or(Error::Missing)
}

/// `translate_encoder_to_transmitter`: UNIPHY and its numbered siblings each
/// carry two transmitters, selected by the object's enum id.
fn transmitter(encoder_objid: u16) -> Result<u8, Error> {
    if (encoder_objid & OBJECT_TYPE_MASK) >> OBJECT_TYPE_SHIFT != TYPE_ENCODER {
        return Err(Error::Unsupported);
    }
    let enum_id = (encoder_objid & ENUM_ID_MASK) >> ENUM_ID_SHIFT;
    // UNIPHY (0x1e), UNIPHY1 (0x20) and UNIPHY2 (0x21) each pair two
    // transmitters; UNIPHY3 (0x25) carries only G.
    let (pair, enums) = match encoder_objid & OBJECT_ID_MASK {
        // linux: n/a (amdgpu/ObjectID.h ENCODER_OBJECT_ID_INTERNAL_UNIPHY 0x1E; not in checker set)
        0x1e => (0, 2),
        // linux: n/a (amdgpu/ObjectID.h ENCODER_OBJECT_ID_INTERNAL_UNIPHY1 0x20; not in checker set)
        0x20 => (1, 2),
        // linux: n/a (amdgpu/ObjectID.h ENCODER_OBJECT_ID_INTERNAL_UNIPHY2 0x21; not in checker set)
        0x21 => (2, 2),
        // linux: n/a (amdgpu/ObjectID.h ENCODER_OBJECT_ID_INTERNAL_UNIPHY3 0x25; not in checker set)
        0x25 => (3, 1),
        _ => return Err(Error::Unsupported),
    };
    if !(1..=enums).contains(&enum_id) {
        return Err(Error::Unsupported);
    }
    Ok(pair * 2 + (enum_id as u8 - 1))
}
fn connector(objid: u16) -> Result<(Connector, u8), Error> {
    if (objid & OBJECT_TYPE_MASK) >> OBJECT_TYPE_SHIFT != TYPE_CONNECTOR {
        return Err(Error::Unsupported);
    }
    let instance = ((objid & ENUM_ID_MASK) >> ENUM_ID_SHIFT) as u8;
    if instance == 0 {
        return Err(Error::Invalid);
    }
    let kind = match (objid & OBJECT_ID_MASK) as u8 {
        0x0c => Connector::HdmiTypeA, // linux-lit: 0x0c=CONNECTOR_ID_HDMI_TYPE_A
        0x13 => Connector::DisplayPort, // linux-lit: 0x13=CONNECTOR_ID_DISPLAY_PORT
        0x14 => Connector::EmbeddedDisplayPort, // linux-lit: 0x14=CONNECTOR_ID_EDP
        other => Connector::Other(other),
    };
    Ok((kind, instance))
}

/// A connector's record offsets are relative to the display-object table.
/// Preserve absence, but reject malformed/duplicate records instead of turning
/// corrupted routing metadata into a plausible unassigned pin.
#[derive(Default)]
struct Wiring {
    i2c: Option<u8>,
    hpd: Option<u8>,
    /// The first connector-speed record's MHz (Linux takes the first).
    speed: Option<u32>,
}
fn wiring(vbios: &[u8], base: usize, offset: u16, paths_end: usize) -> Result<Wiring, Error> {
    let mut result = Wiring::default();
    if offset == 0 {
        return Ok(result);
    }
    let mut at = base
        .checked_add(usize::from(offset))
        .ok_or(Error::Invalid)?;
    if at < paths_end {
        return Err(Error::Invalid);
    }
    for _ in 0..MAX_RECORDS {
        let head = vbios.get(at..at + RECORD_HEADER).ok_or(Error::Invalid)?;
        if head[0] == RECORD_END {
            return Ok(result);
        }
        let size = usize::from(head[1]);
        if size < RECORD_HEADER {
            return Err(Error::Invalid);
        }
        let record = vbios.get(at..at + size).ok_or(Error::Invalid)?;
        // atom_connector_speed_record: header, u32 MHz, u16 reserved.
        // linux-lit: 8=sizeof(struct atom_connector_speed_record)
        if head[0] == RECORD_CONNECTOR_SPEED && size >= 8 && result.speed.is_none() {
            // linux-lit: 2=offsetof(struct atom_connector_speed_record, connector_max_speed)
            // linux-lit: 6=offsetof(struct atom_connector_speed_record, reserved)
            result.speed = Some(u32::from_le_bytes(record[2..6].try_into().unwrap()));
        }
        let field = match head[0] {
            RECORD_I2C => Some(&mut result.i2c),
            RECORD_HPD_INT => Some(&mut result.hpd),
            _ => None,
        };
        if let Some(field) = field {
            // linux-lit: 4=sizeof(struct atom_hpd_int_record)
            // linux-lit: 2=offsetof(struct atom_hpd_int_record, pin_id)
            if size < 4 || field.replace(record[2]).is_some() {
                return Err(Error::Invalid);
            }
        }
        at += size;
    }
    Err(Error::Invalid)
}
/// atom_gpio_pin_assignment: u32 register index, bit shift, mask shift, id,
/// reserved. Exact matching follows bios_parser2.c; neither uid nor its low
/// nibble is assumed to identify the physical AUX/HPD endpoint.
fn gpio(vbios: &[u8], uid: u8) -> Result<(u32, u8), Error> {
    let pins = table(vbios, TABLE_GPIO_PIN_LUT)?;
    header(pins, 2, &[1])?;
    // linux-lit: 4=sizeof(struct atom_common_table_header)
    // linux-lit: 8=sizeof(struct atom_gpio_pin_assignment)
    if pins.len() < 12 || (pins.len() - 4) % 8 != 0 {
        return Err(Error::Invalid);
    }
    // linux-lit: 4=sizeof(struct atom_common_table_header)
    // linux-lit: 8=sizeof(struct atom_gpio_pin_assignment)
    // linux-lit: 6=offsetof(struct atom_gpio_pin_assignment, gpio_id)
    let mut matches = pins[4..].chunks_exact(8).filter(|pin| pin[6] == uid);
    let pin = matches.next().ok_or(Error::Missing)?;
    // linux-lit: 4=offsetof(struct atom_gpio_pin_assignment, gpio_bitshift)
    if matches.next().is_some() || pin[4] >= 32 {
        return Err(Error::Invalid);
    }
    // linux-lit: 4=offsetof(struct atom_gpio_pin_assignment, gpio_bitshift)
    Ok((u32::from_le_bytes(pin[..4].try_into().unwrap()), pin[4]))
}
fn aux_channel(vbios: &[u8], uid: u8, dcn: u32, count: u8) -> Result<u8, Error> {
    let (register, shift) = gpio(vbios, uid)?;
    let first = dcn.checked_add(GPIO_DDC1_A).ok_or(Error::Invalid)?;
    let relative = register.checked_sub(first).ok_or(Error::Unsupported)?;
    // DC_GPIO_DDCnCLK_A is bit 0. The DATA bit (8) is not a clock pin.
    // linux-lit: 0=DC_GPIO_DDC1_A__DC_GPIO_DDC1CLK_A__SHIFT@dcn
    // linux-lit: 4=mmDC_GPIO_DDC2_A@dcn - mmDC_GPIO_DDC1_A@dcn
    if shift != 0 || relative % 4 != 0 || relative / 4 >= u32::from(count) {
        return Err(Error::Unsupported);
    }
    Ok((relative / 4) as u8) // linux-lit: 4=mmDC_GPIO_DDC2_A@dcn - mmDC_GPIO_DDC1_A@dcn
}
fn hpd_selector(vbios: &[u8], uid: u8, dcn: u32) -> Result<u8, Error> {
    let (register, shift) = gpio(vbios, uid)?;
    if register != dcn.checked_add(GPIO_HPD_A).ok_or(Error::Invalid)? {
        return Err(Error::Unsupported);
    }
    HPD_SHIFTS
        .iter()
        .position(|&s| s == shift)
        .map(|i| i as u8 + 1)
        .ok_or(Error::Unsupported)
}

/// Walk `display_object_info_table_v1_4/v1_5`. Paths whose encoder or connector this
/// does not understand are skipped rather than failing the whole table: a board
/// may wire something alongside the DisplayPort connectors we care about.
pub fn display_paths(gpu: &AmdGpu, vbios: &[u8]) -> Result<Vec<Path>, Error> {
    let profile = Routing::resolve(gpu)?;
    let dcn = profile.bank(gpu, GPIO_HPD_A)? / 4;
    let paths = display_paths_at(
        vbios,
        u32::try_from(dcn).map_err(|_| Error::Invalid)?,
        profile.streams(),
    )?;
    if paths.iter().any(|path| path.hpd > profile.hpd_count()) {
        return Err(Error::Unsupported);
    }
    Ok(paths)
}
fn display_paths_at(vbios: &[u8], dcn: u32, dig_count: u8) -> Result<Vec<Path>, Error> {
    let info = table(vbios, TABLE_DISPLAY_OBJECT_INFO)?;
    let base = usize::from(
        directory(vbios)?
            .table_offset(TABLE_DISPLAY_OBJECT_INFO)
            .ok_or(Error::Missing)?,
    );
    header(info, 1, &[4, 5])?;
    if info.len() < PATHS_OFFSET {
        return Err(Error::Invalid);
    }
    // linux-lit: 6=offsetof(struct display_object_info_table_v1_4, number_of_path)
    let count = info[6] as usize;
    let declared = u16_at(info, 0) as usize;
    if count == 0 || PATHS_OFFSET + count * PATH_SIZE > declared {
        return Err(Error::Invalid);
    }
    let mut paths = Vec::new();
    paths.try_reserve_exact(count).map_err(|_| Error::Invalid)?;
    for index in 0..count {
        let entry = &info[PATHS_OFFSET + index * PATH_SIZE..][..PATH_SIZE];
        let Ok((kind, instance)) = connector(u16_at(entry, 0)) else {
            continue;
        };
        // linux-lit: 4=offsetof(struct atom_display_object_path_v2, encoderobjid)
        let Ok(transmitter) = transmitter(u16_at(entry, 4)) else {
            continue;
        };
        // An external encoder needs a separate bridge driver; the downstream
        // id cannot be treated as an on-chip transmitter.
        // v1.5 keeps the field positions but replaces extencoderobjid with a
        // reserved USB-C field. It no longer describes an external encoder.
        // linux-lit: 3=offsetof(struct atom_common_table_header, content_revision)
        // linux-lit: 6=offsetof(struct atom_display_object_path_v2, extencoderobjid)
        if (info[3] == 4 && u16_at(entry, 6) != 0) || transmitter >= dig_count {
            continue;
        }
        let pins = wiring(
            vbios,
            base,
            // linux-lit: 2=offsetof(struct atom_display_object_path_v2, disp_recordoffset)
            u16_at(entry, 2),
            base + PATHS_OFFSET + count * PATH_SIZE,
        )?;
        let aux = pins
            .i2c
            .map(|uid| aux_channel(vbios, uid, dcn, dig_count))
            .transpose()?;
        let hpd = pins
            .hpd
            .map(|uid| hpd_selector(vbios, uid, dcn))
            .transpose()?
            .unwrap_or(0);
        paths.push(Path {
            connector: kind,
            connector_instance: instance,
            transmitter,
            aux,
            hpd,
            // linux-lit: 12=offsetof(struct atom_display_object_path_v2, device_tag)
            device_tag: u16_at(entry, 12),
            max_speed_mhz: pins.speed.unwrap_or(0),
        });
    }
    if paths.is_empty() {
        return Err(Error::Unsupported);
    }
    Ok(paths)
}

/// `atom_master_list_of_data_tables_v2_1::vram_info`.
// linux: offsetof(struct atom_master_list_of_data_tables_v2_1, vram_info) / 2
const TABLE_VRAM_INFO: u16 = 28;
/// `atom_vram_info_header_v2_5`: the four-byte header, eight u16 offsets and
/// four u8 counts precede `vram_module[0]` (`atom_vram_module_v11`), whose
/// `channel_num` and `channel_width` sit 14 and 15 bytes in.
// linux: offsetof(struct atom_vram_info_header_v2_5, vram_module_num)
const VRAM_MODULE_NUM_OFFSET: usize = 20;
// linux: offsetof(struct atom_vram_info_header_v2_5, vram_module)
const VRAM_MODULE0_OFFSET: usize = 24;
const VRAM_CHANNEL_NUM: usize = 14; // linux: offsetof(struct atom_vram_module_v11, channel_num)
const VRAM_CHANNEL_WIDTH: usize = 15; // linux: offsetof(struct atom_vram_module_v11, channel_width)

/// Discrete-GPU DRAM channels as `bios_parser2.c::get_vram_info_v25` reads
/// them for DML: `(channel_num, (1 << channel_width) / 8 bytes)` of module 0.
/// Navi2x uses content revision 2.5; any other revision is refused rather
/// than read at the wrong offsets.
pub fn vram_channels(vbios: &[u8]) -> Result<(u32, u32), Error> {
    let info = table(vbios, TABLE_VRAM_INFO)?;
    header(info, 2, &[5])?;
    if (u16_at(info, 0) as usize) < VRAM_MODULE0_OFFSET + VRAM_CHANNEL_WIDTH + 1
        || info[VRAM_MODULE_NUM_OFFSET] == 0
    {
        return Err(Error::Invalid);
    }
    let module = &info[VRAM_MODULE0_OFFSET..];
    let channels = u32::from(module[VRAM_CHANNEL_NUM]);
    let width = module[VRAM_CHANNEL_WIDTH];
    // CHANNEL_16BIT..CHANNEL_64BIT encode log2 bits: 4, 5 and 6.
    if channels == 0 || channels > 32 || !(4..=6).contains(&width) {
        return Err(Error::Invalid);
    }
    Ok((channels, (1u32 << width) / 8))
}

/// The DCHUB reference clock every DLG and TTU field is expressed in, from
/// `atom_display_controller_info_v4_*`. Linux falls back to 27 MHz when the
/// table reports zero; that fallback is taken here too, because it is the
/// documented reference rather than a guess at this board's wiring.
pub fn dchub_refclk_khz(vbios: &[u8]) -> Result<u32, Error> {
    let info = table(vbios, TABLE_DCE_INFO)?;
    header(info, 4, &[1, 2, 3, 4, 5])?;
    if (u16_at(info, 0) as usize) < DCE_REFCLK_OFFSET + 2 {
        return Err(Error::Invalid);
    }
    let refclk = u16_at(info, DCE_REFCLK_OFFSET) as u32 * 10;
    Ok(if refclk == 0 { 27_000 } else { refclk })
}

/// `atom_display_controller_info_v4_*.display_caps`
/// DCE_INFO_CAPS_LTTPR_SUPPORT_ENABLE: the board wants DP repeaters
/// (LTTPRs) trained hop by hop (non-transparent mode). Linux's DCN401 is
/// always VBIOS-LTTPR-aware, so without the bit a present repeater is used
/// in transparent mode (dp_decide_8b_10b_lttpr_mode); a missing or unknown
/// table reads as the bit clear, as bios_get_lttpr_caps' failure does.
pub fn lttpr_non_transparent(vbios: &[u8]) -> Result<bool, Error> {
    let info = table(vbios, TABLE_DCE_INFO)?;
    header(info, 4, &[1, 2, 3, 4, 5])?;
    if (u16_at(info, 0) as usize) < DCE_DISPLAY_CAPS_OFFSET + 4 {
        return Err(Error::Invalid);
    }
    let caps = u32::from(u16_at(info, DCE_DISPLAY_CAPS_OFFSET))
        | u32::from(u16_at(info, DCE_DISPLAY_CAPS_OFFSET + 2)) << 16;
    Ok(caps & DCE_INFO_CAPS_LTTPR_SUPPORT_ENABLE != 0)
}

/// The memory configuration, from `atom_integrated_system_info_v2_*` for the
/// type and channel count and from the firmware's own DPM table for the data
/// rate. A zero channel count is refused: Linux substitutes four, but that is a
/// guess, and the channel count multiplies straight into every watermark.
pub fn memory_config(vbios: &[u8], levels: &Levels) -> Result<Memory, Error> {
    let info = table(vbios, TABLE_INTEGRATED_SYSTEM_INFO)?;
    header(info, 2, &[1, 2])?;
    if (u16_at(info, 0) as usize) < CHANNEL_COUNT_OFFSET + 1 {
        return Err(Error::Invalid);
    }
    let (kind, channel_width_bytes) = match info[MEMORY_TYPE_OFFSET] {
        MEM_TYPE_DDR5 => (MemoryKind::Ddr5, DDR5_CHANNEL_WIDTH_BYTES),
        MEM_TYPE_LPDDR5 => (MemoryKind::Lpddr5, LPDDR5_CHANNEL_WIDTH_BYTES),
        _ => return Err(Error::Unsupported),
    };
    let channels = info[CHANNEL_COUNT_OFFSET] as u32;
    if channels == 0 || channels > 16 {
        return Err(Error::Invalid);
    }
    let speed_mts = levels.max_dram_speed_mts();
    if speed_mts == 0 {
        return Err(Error::Invalid);
    }
    Ok(Memory {
        kind,
        channels,
        channel_width_bytes,
        speed_mts,
    })
}

/// Derive the link route for a discovered sink, validated against the board's
/// own topology rather than assumed from the sink's index.
///
/// A native sink's instance identifies its AUX channel. Its transmitter and
/// HPD line are independently resolved from the board's connector records.
/// Ambiguous shared channels are refused; choosing the first path could drive
/// a different connector. DPIA routing exists only on the Phoenix profile.
pub fn routes_for_sink(
    gpu: &AmdGpu,
    paths: &[Path],
    sink: &crate::amdgpu_usbc::Sink,
    frontend: u8,
) -> Result<Vec<crate::amdgpu_dio::Route>, Error> {
    routes_for_profile(Routing::resolve(gpu)?, paths, sink, frontend)
}
fn routes_for_profile(
    profile: impl Into<Routing>,
    paths: &[Path],
    sink: &crate::amdgpu_usbc::Sink,
    frontend: u8,
) -> Result<Vec<crate::amdgpu_dio::Route>, Error> {
    let profile = profile.into();
    if frontend >= profile.streams() {
        return Err(Error::Invalid);
    }
    let mut routes = Vec::new();
    match sink.channel {
        crate::amdgpu_dmub::Channel::Legacy => {
            if sink.instance >= profile.streams() {
                return Err(Error::Invalid);
            }
            // Include non-DP paths in the ambiguity check too: a shared AUX
            // needs mux/bridge ownership this native SST path does not have.
            let mut matches = paths.iter().filter(|path| path.aux == Some(sink.instance));
            let path = matches.next().ok_or(Error::Unsupported)?;
            if matches.next().is_some() {
                return Err(Error::Invalid);
            }
            if paths
                .iter()
                .filter(|other| other.transmitter == path.transmitter)
                .count()
                != 1
            {
                return Err(Error::Invalid);
            }
            if path.transmitter >= profile.streams() || path.hpd > profile.hpd_count() {
                return Err(Error::Invalid);
            }
            if !matches!(
                path.connector,
                Connector::DisplayPort | Connector::EmbeddedDisplayPort
            ) {
                return Err(Error::Unsupported);
            }
            routes.try_reserve_exact(1).map_err(|_| Error::Invalid)?;
            routes.push(crate::amdgpu_dio::Route {
                channel: sink.channel,
                aux: sink.instance,
                backend: path.transmitter,
                frontend,
                hpd: path.hpd,
            });
        }
        crate::amdgpu_dmub::Channel::Dpia => {
            if profile != Routing::Legacy(Profile::Dcn314) {
                return Err(Error::Unsupported);
            }
            if sink.instance >= DPIA_COUNT {
                return Err(Error::Invalid);
            }
            routes
                .try_reserve_exact(DIG_COUNT as usize)
                .map_err(|_| Error::Invalid)?;
            // Transmitters the board wired to no connector come first: borrowing
            // one of those cannot deprive a later native plug of its fixed
            // transmitter. The wired ones follow, usable while their own
            // connector is idle.
            for wired in [false, true] {
                for dig in 0..DIG_COUNT {
                    if paths.iter().any(|path| path.transmitter == dig) != wired {
                        continue;
                    }
                    routes.push(crate::amdgpu_dio::Route {
                        channel: sink.channel,
                        aux: sink.instance,
                        backend: dig,
                        // A tunnelled link has no board hot-plug line; the
                        // tunnel itself reports presence.
                        frontend,
                        hpd: 0,
                    });
                }
            }
        }
    }
    if routes.is_empty() {
        return Err(Error::Unsupported);
    }
    Ok(routes)
}

/// Whether a transmitter's backend is already driving a link.
///
/// Borrowing a transmitter for a tunnelled link must not steal one that is
/// already carrying a stream — the panel's, at boot. This is the cheap probe
/// that lets a candidate be rejected before a whole pipeline is built for it;
/// the link encoder re-checks the same bit when it is actually claimed, which
/// closes the gap between the two.
///
/// # Safety
/// Caller holds matching PCI authority and a permanent register mapping.
pub unsafe fn transmitter_busy(
    gpu: &AmdGpu,
    authority: &Cap<BusDeviceCap, Write>,
    dig: u8,
) -> Result<bool, Error> {
    let profile = Routing::resolve(gpu)?;
    if dig >= profile.streams() {
        return Err(Error::Invalid);
    }
    let (enable, stride) = profile.backend();
    let base = profile.bank(
        gpu,
        (enable + (u64::from(profile.streams()) - 1) * stride) as u32,
    )?;
    let regs: MmioRegion = gpu.regs;
    let offset = base + (enable + u64::from(dig) * stride) * 4;
    let value = authority
        .invoke(Op(|| {
            // SAFETY: the bank bounds every DIG instance.
            unsafe { regs.read32(offset) }
        }))
        .map_err(|_| Error::Revoked)?;
    if value == u32::MAX {
        return Err(Error::DeviceGone);
    }
    Ok(value & 1 != 0) // linux-lit: 1=DIG0_DIG_BE_EN_CNTL__DIG_ENABLE_MASK@dcn
}

struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
/// `get_vco_frequency_from_reg`: the PLL feedback multiplier is 8.16 fixed
/// point against the DFS reference.
pub(crate) fn vco_from_pll_request(request: u32) -> Option<u32> {
    if request == u32::MAX {
        return None;
    }
    let integer = (request & 0x1ff) as u64;
    let fraction = (request >> 16) as u64;
    // (integer + fraction/65536) * reference, floored, without losing the
    // fraction to an early divide.
    let khz = (integer * 65_536 + fraction) * DFS_REF_KHZ / 65_536;
    let khz = u32::try_from(khz).ok()?;
    (VCO_MIN_KHZ..=VCO_MAX_KHZ).contains(&khz).then_some(khz)
}
/// Read the DENTIST VCO.
///
/// # Safety
/// Caller holds matching PCI authority and a permanent register mapping, and
/// the GPU must not be reconfiguring its clock tree concurrently.
pub unsafe fn dentist_vco_khz(
    gpu: &AmdGpu,
    authority: &Cap<BusDeviceCap, Write>,
) -> Result<u32, Error> {
    let offset = (CLK_BASE_DWORD + CLK1_CLK_PLL_REQ) * 4;
    if offset + 4 > gpu.regs.len {
        return Err(Error::Unsupported);
    }
    let regs: MmioRegion = gpu.regs;
    let request = authority
        .invoke(Op(|| {
            // SAFETY: bounds checked against the mapping above.
            unsafe { regs.read32(offset) }
        }))
        .map_err(|_| Error::Revoked)?;
    vco_from_pll_request(request).ok_or(Error::DeviceGone)
}

/// Gather the platform constants the mode math needs.
///
/// The display topology is read separately by [`display_paths`], because a route
/// has to be chosen before a pipeline exists, while the memory data rate only
/// becomes known once that pipeline has latched the firmware's DPM table.
///
/// # Safety
/// Same contract as [`dentist_vco_khz`]. `vbios` must be the validated snapshot
/// retained for this device, not another board's image.
pub unsafe fn platform(
    gpu: &AmdGpu,
    authority: &Cap<BusDeviceCap, Write>,
    vbios: &[u8],
    levels: &Levels,
) -> Result<Platform, Error> {
    let memory = memory_config(vbios, levels)?;
    let dchub_refclk_khz = dchub_refclk_khz(vbios)?;
    // SAFETY: forwarded unchanged from this function's contract.
    let dentist_vco_khz = unsafe { dentist_vco_khz(gpu, authority) }?;
    Ok(Platform {
        memory,
        dchub_refclk_khz,
        dentist_vco_khz,
    })
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn_inventory_tests.rs"]
mod tests;

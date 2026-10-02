//! The platform inventory the DCN314 bring-up needs: which transmitter a
//! connector is wired to, how memory is configured, what the DCHUB reference
//! clock is, and what the DENTIST VCO runs at.
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
//! `display_object_info_table_v1_4`) and `displayobject.h`; the transmitter
//! mapping follows Linux `link_factory.c::translate_encoder_to_transmitter` and
//! the VCO read follows `dcn314_clk_mgr.c::get_vco_frequency_from_reg`.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_dcn_clk::Levels,
    amdgpu_dcn_display::Platform,
    amdgpu_dml::{Memory, MemoryKind},
    atombios,
};
use alloc::vec::Vec;
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

/// Master data table indices from `atom_master_list_of_data_tables_v2_1`.
const TABLE_DISPLAY_OBJECT_INFO: u16 = 22;
const TABLE_DCE_INFO: u16 = 27;
const TABLE_INTEGRATED_SYSTEM_INFO: u16 = 30;

/// `atom_display_object_path_v2` is sixteen bytes, and the paths follow the
/// four-byte common header plus `supporteddevices` and `number_of_path`.
const PATH_SIZE: usize = 16;
const PATHS_OFFSET: usize = 8;
/// `displayobject.h` object-id encoding.
const OBJECT_ID_MASK: u16 = 0x00ff;
const ENUM_ID_SHIFT: u32 = 8;
const ENUM_ID_MASK: u16 = 0x0f00;
const OBJECT_TYPE_SHIFT: u32 = 12;
const OBJECT_TYPE_MASK: u16 = 0xf000;
const TYPE_ENCODER: u16 = 0x02;
const TYPE_CONNECTOR: u16 = 0x03;
/// `atom_common_record_header` is two bytes, and `atom_hpd_int_record` adds the
/// pin id and its plug state. The list ends with a terminator record type.
const RECORD_HEADER: usize = 2;
const RECORD_HPD_INT: u8 = 2;
const RECORD_END: u8 = 0xff;
/// A connector's record list is short; this only bounds a malformed one.
const MAX_RECORDS: usize = 64;
/// There are six HPD lines, and the ATOM selector is one-based.
const MAX_HPD: u8 = 6;
/// `num_dig_link_enc` for DCN314, and its four tunnelling endpoints.
pub const DIG_COUNT: u8 = 5;
pub const DPIA_COUNT: u8 = 4;
/// `DIG0_DIG_BE_EN_CNTL`, per-DIG stride 0x100, at DCN base index 2. Bit zero
/// says the backend is already driving a link.
const DIG_BE_EN_CNTL: u64 = 0x20b2;
const DIG_STRIDE: u64 = 0x100;
/// `atom_dmi_t17_mem_type_def`: DDR5 is 34 and LPDDR5 is 35.
const MEM_TYPE_DDR5: u8 = 34;
const MEM_TYPE_LPDDR5: u8 = 35;
/// Linux derives the channel width from the memory type rather than reading it.
const DDR5_CHANNEL_WIDTH_BYTES: u32 = 8;
const LPDDR5_CHANNEL_WIDTH_BYTES: u32 = 4;
/// `atom_display_controller_info_v4_*` places `dce_refclk_10khz` here, in every
/// content revision from 4.1 to 4.4.
const DCE_REFCLK_OFFSET: usize = 12;
/// `atom_integrated_system_info_v2_*` field offsets, the same in v2.1 and v2.2.
const MEMORY_TYPE_OFFSET: usize = 26;
const CHANNEL_COUNT_OFFSET: usize = 27;

/// The CLK block is absent from the IP discovery table, so Linux hardcodes its
/// base too (`CLK_BASE` in `dcn314_clk_mgr.c`). This is the one register address
/// here that discovery cannot confirm, which is why the value it produces is
/// range-checked before being believed.
const CLK_BASE_DWORD: u64 = 0x0001_6c00;
const CLK1_CLK_PLL_REQ: u64 = 0x0237;
/// `dfs_ref_freq_khz` for DCN314.
const DFS_REF_KHZ: u64 = 48_000;
/// The DENTIST VCO is a few GHz; anything outside this cannot be one, and a
/// register read that produces it is a read of something else.
const VCO_MIN_KHZ: u32 = 600_000;
const VCO_MAX_KHZ: u32 = 6_000_000;

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
    /// One-based ATOM HPD selector from the connector's record list, or zero
    /// when the board declares none for this connector.
    pub hpd: u8,
    pub device_tag: u16,
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}
/// The four-byte `atom_common_table_header`: size, then format and content
/// revision. A table whose declared size does not match what the directory
/// gave us is not a table we can read fields out of by offset.
fn header(table: &[u8], format: u8, content: &[u8]) -> Result<(), Error> {
    if table.len() < 4 {
        return Err(Error::Missing);
    }
    let size = u16_at(table, 0) as usize;
    if size < 4 || size > table.len() {
        return Err(Error::Invalid);
    }
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
    // UNIPHY is 1, UNIPHY1 is 2, UNIPHY2 is 3; each pairs two transmitters.
    let pair = match encoder_objid & OBJECT_ID_MASK {
        1 => 0,
        2 => 1,
        3 => 2,
        _ => return Err(Error::Unsupported),
    };
    match enum_id {
        1 | 2 => Ok(pair * 2 + (enum_id as u8 - 1)),
        _ => Err(Error::Unsupported),
    }
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
        0x03 => Connector::HdmiTypeA,
        0x05 => Connector::DisplayPort,
        0x06 => Connector::EmbeddedDisplayPort,
        other => Connector::Other(other),
    };
    Ok((kind, instance))
}

/// Walk a connector's record list for its hot-plug line. A list that is absent,
/// truncated, cyclic or declares a line outside the six that exist yields zero,
/// which `Route` reads as "this board assigns none" rather than guessing one.
fn hpd_selector(vbios: &[u8], offset: u16) -> u8 {
    let mut at = offset as usize;
    if at == 0 {
        return 0;
    }
    for _ in 0..MAX_RECORDS {
        if at + RECORD_HEADER > vbios.len() {
            return 0;
        }
        let kind = vbios[at];
        let size = vbios[at + 1] as usize;
        if kind == RECORD_END || size < RECORD_HEADER || at + size > vbios.len() {
            return 0;
        }
        if kind == RECORD_HPD_INT && size >= 4 {
            let pin = vbios[at + 2];
            return if (1..=MAX_HPD).contains(&pin) { pin } else { 0 };
        }
        at += size;
    }
    0
}

/// Walk `display_object_info_table_v1_4`. Paths whose encoder or connector this
/// does not understand are skipped rather than failing the whole table: a board
/// may wire something alongside the DisplayPort connectors we care about.
pub fn display_paths(vbios: &[u8]) -> Result<Vec<Path>, Error> {
    let info = table(vbios, TABLE_DISPLAY_OBJECT_INFO)?;
    header(info, 1, &[4])?;
    if info.len() < PATHS_OFFSET {
        return Err(Error::Invalid);
    }
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
        let Ok(transmitter) = transmitter(u16_at(entry, 4)) else {
            continue;
        };
        paths.push(Path {
            connector: kind,
            connector_instance: instance,
            transmitter,
            hpd: hpd_selector(vbios, u16_at(entry, 2)),
            device_tag: u16_at(entry, 12),
        });
    }
    if paths.is_empty() {
        return Err(Error::Unsupported);
    }
    Ok(paths)
}

/// The DCHUB reference clock every DLG and TTU field is expressed in, from
/// `atom_display_controller_info_v4_*`. Linux falls back to 27 MHz when the
/// table reports zero; that fallback is taken here too, because it is the
/// documented reference rather than a guess at this board's wiring.
pub fn dchub_refclk_khz(vbios: &[u8]) -> Result<u32, Error> {
    let info = table(vbios, TABLE_DCE_INFO)?;
    header(info, 4, &[1, 2, 3, 4])?;
    if (u16_at(info, 0) as usize) < DCE_REFCLK_OFFSET + 2 {
        return Err(Error::Invalid);
    }
    let refclk = u16_at(info, DCE_REFCLK_OFFSET) as u32 * 10;
    Ok(if refclk == 0 { 27_000 } else { refclk })
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
/// A native sink's DMUB link instance *is* its transmitter, so the topology is
/// used to confirm that transmitter really is wired to a DisplayPort connector —
/// a USB-C port carrying DP alt-mode appears as one — and to pick up its
/// hot-plug line. Driving a transmitter the board wired to something else is
/// refused.
///
/// A tunnelled sink is refused: its transmitter is assigned from a link-encoder
/// pool at stream time rather than fixed by the board, and no such pool exists
/// here yet. VBIOS cannot answer for it.
pub fn routes_for_sink(
    paths: &[Path],
    sink: &crate::amdgpu_usbc::Sink,
    frontend: u8,
) -> Result<Vec<crate::amdgpu_dio::Route>, Error> {
    let mut routes = Vec::new();
    match sink.channel {
        crate::amdgpu_dmub::Channel::Legacy => {
            let path = paths
                .iter()
                .find(|path| {
                    path.transmitter == sink.instance
                        && matches!(
                            path.connector,
                            Connector::DisplayPort | Connector::EmbeddedDisplayPort
                        )
                })
                .ok_or(Error::Unsupported)?;
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
    if dig >= DIG_COUNT {
        return Err(Error::Invalid);
    }
    let base = crate::amdgpu_psp_ring::bank(
        gpu,
        crate::amdgpu_discovery::HW_ID_DCN,
        &[(3, 1, 4)],
        2,
        (DIG_BE_EN_CNTL + (DIG_COUNT as u64 - 1) * DIG_STRIDE) as u32,
    )
    .map_err(|_| Error::Unsupported)?;
    let regs: MmioRegion = gpu.regs;
    let offset = (base + (DIG_BE_EN_CNTL + dig as u64 * DIG_STRIDE) * 4) as u64;
    let value = authority
        .invoke(Op(|| {
            // SAFETY: the bank bounds every DIG instance.
            unsafe { regs.read32(offset) }
        }))
        .map_err(|_| Error::Revoked)?;
    if value == u32::MAX {
        return Err(Error::DeviceGone);
    }
    Ok(value & 1 != 0)
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

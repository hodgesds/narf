//! The VBIOS command tables Linux DC executes for Navi22 display bring-up.
//!
//! DCN3.0 (`dcn30_resource.c`) does not set `debug.dmub_command_table`, so
//! `command_table2.c` runs these through the ATOM interpreter
//! (`amdgpu_atom_execute_table`), not DMUB: `enable_disp_power_gating_v2_1`
//! (`dcn10_bios_golden_init`), `set_pixel_clock_v7` (the PHY PLL for HDMI/DVI,
//! via `dce112_program_pix_clk`), `encoder_control_digx_v1_5` (STREAM_SETUP from
//! `enc3_stream_encoder_hdmi_set_stream_attribute`) and
//! `transmitter_control_v1_6`/`v1_7` (`dcn10_link_encoder_enable_tmds_output`
//! and the disable path). Parameter layouts are the `atomfirmware.h` structs,
//! filled exactly as those functions and the `command_table_helper2_dce112.c`
//! translations do; the parameter-space sizes are Linux's.
//!
//! Register accesses from the bytecode go to BAR5 by dword index, bounded by
//! the mapping: an index outside it is recorded and the table fails, rather
//! than reaching another device (Linux would go through PCIE index/data; no
//! display table is expected to need that). PLL and MC accessors return zero,
//! as Linux's SOC15 `cail_pll_read`/`cail_mc_read` do; port I/O is refused.
use crate::{
    amdgpu_atom_vm::{self as vm, AtomError, AtomState, ResolvedTable},
    amdgpu_atombios::{Atombios, ATOM_CT_WS_PTR},
};
use alloc::{boxed::Box, rc::Rc, vec::Vec};
use core::cell::RefCell;

// atom_master_list_of_command_functions_v2_1 indices.
const DIGX_ENCODER_CONTROL: u16 = 4;
const SET_PIXEL_CLOCK: u16 = 12;
const ENABLE_DISP_POWER_GATING: u16 = 13;
const DIG1_TRANSMITTER_CONTROL: u16 = 76;
// atomfirmware.h enumerations.
const ATOM_ENCODER_MODE_HDMI: u8 = 3;
const ATOM_ENCODER_CMD_STREAM_SETUP: u8 = 0x0f;
const ATOM_COMBOPHY_PLL0: u8 = 20;
/// `ENCODER_OBJECT_ID_INTERNAL_UNIPHY`, `_UNIPHY1`, `_UNIPHY2`.
const UNIPHY_OBJECT_IDS: [u8; 3] = [0x1e, 0x20, 0x21];
const ATOM_DISABLE: u8 = 0;
const ATOM_ENABLE: u8 = 1;
const ATOM_INIT: u8 = 7;
/// DCN30 drives six streams and six PHY PLLs.
const STREAMS: u8 = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The VBIOS has no such table.
    Missing(u16),
    /// The table's content revision is not one this path fills.
    Revision {
        table: u16,
        revision: u8,
    },
    Invalid,
    Atom(AtomError),
    /// The bytecode reached outside the register window or used port I/O.
    Bus,
}

/// The action `dcn10_bios_golden_init` passes per pipe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipeAction {
    Init,
    Disable,
    Enable,
}

/// `bp_transmitter_control` actions this path issues
/// (`atom_dig_transmitter_control_action`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransmitterAction {
    Disable = 0,
    Enable = 1,
    /// `TRANSMITTER_CONTROL_SET_VOLTAGE_AND_PREEMPASIS`.
    SetupVsemph = 11,
}
/// `signal_type_to_atom_dig_mode` (`command_table_helper2_dce112.c`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransmitterMode {
    DisplayPort = 0,
    /// Also what `SIGNAL_TYPE_NONE` maps to (the power-down path).
    Dvi = 2,
    Hdmi = 3,
}

/// The register bus the interpreter drives.
pub trait Bus {
    fn read(&mut self, dword: u32) -> Option<u32>;
    fn write(&mut self, dword: u32, value: u32) -> bool;
    /// `udelay`/`msleep` from DELAY_* opcodes.
    fn delay_us(&mut self, us: u64);
}

/// Pack a little-endian parameter block into the dword PS Linux hands
/// `amdgpu_atom_execute_table`.
fn ps(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
        .collect()
}

/// The validated tables of this GPU's VBIOS.
pub struct Tables<'a> {
    bios: &'a [u8],
    atom: Atombios<'a>,
    data_table: usize,
}
impl core::fmt::Debug for Tables<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tables")
            .field("len", &self.bios.len())
            .finish()
    }
}
impl<'a> Tables<'a> {
    pub fn new(bios: &'a [u8]) -> Result<Self, Error> {
        let atom = Atombios::parse(bios).map_err(|_| Error::Invalid)?;
        let rom = crate::atombios::header::parse_rom_header(bios).map_err(|_| Error::Invalid)?;
        Ok(Self {
            bios,
            atom,
            data_table: rom.master_data_table_offset as usize,
        })
    }
    /// `amdgpu_atom_parse_cmd_header`'s content revision.
    pub fn revision(&self, table: u16) -> Result<u8, Error> {
        let header = self
            .atom
            .cmd_table(table)
            .map_err(|_| Error::Missing(table))?;
        header.get(3).copied().ok_or(Error::Missing(table))
    }
    fn require(&self, table: u16, revisions: &[u8]) -> Result<u8, Error> {
        let revision = self.revision(table)?;
        if !revisions.contains(&revision) {
            return Err(Error::Revision { table, revision });
        }
        Ok(revision)
    }
    /// `amdgpu_atom_execute_table`: fresh per-execution state, the image bound
    /// for data-block and ID operands, and the bus for register and delays.
    pub fn execute<B: Bus + 'static>(
        &self,
        bus: Rc<RefCell<B>>,
        table: u16,
        params: &mut [u32],
    ) -> Result<(), Error> {
        let faulted = Rc::new(RefCell::new(false));
        let mut state = AtomState::new(1, 4096);
        state.bios = self.bios;
        state.data_table = self.data_table;
        let atom = &self.atom;
        state.table_resolver = Box::new(move |id| {
            let full = atom.cmd_table(u16::from(id)).ok()?;
            let (body, ps_dwords) = atom.cmd_table_body_and_ps(u16::from(id)).ok()?;
            Some(ResolvedTable {
                body,
                ps_dwords,
                start: atom.cmd_table_offset(u16::from(id)).ok()? as usize,
                ws_dwords: Some(usize::from(*full.get(ATOM_CT_WS_PTR)?)),
            })
        });
        let (b, f) = (bus.clone(), faulted.clone());
        state.reg_read = Box::new(move |dword| {
            b.borrow_mut().read(dword).unwrap_or_else(|| {
                *f.borrow_mut() = true;
                0
            })
        });
        let (b, f) = (bus.clone(), faulted.clone());
        state.reg_write = Box::new(move |dword, value| {
            if !b.borrow_mut().write(dword, value) {
                *f.borrow_mut() = true;
            }
        });
        let b = bus.clone();
        state.delay_us = Box::new(move |us| b.borrow_mut().delay_us(us));
        state.pll_read = Box::new(|_| 0);
        state.pll_write = Box::new(|_, _| {});
        state.mc_read = Box::new(|_| 0);
        state.mc_write = Box::new(|_, _| {});
        let f = faulted.clone();
        state.port_read = Box::new(move |_| {
            *f.borrow_mut() = true;
            0
        });
        let f = faulted.clone();
        state.port_write = Box::new(move |_, _| *f.borrow_mut() = true);
        let id = u8::try_from(table).map_err(|_| Error::Invalid)?;
        let result = vm::execute_table(&mut state, id, params);
        drop(state);
        if *faulted.borrow() {
            return Err(Error::Bus);
        }
        result.map_err(Error::Atom)
    }

    /// `enable_disp_power_gating_v2_1` (`enable_disp_power_gating_parameters_v2_1`).
    pub fn pipe_power_gating<B: Bus + 'static>(
        &self,
        bus: Rc<RefCell<B>>,
        pipe: u8,
        action: PipeAction,
    ) -> Result<(), Error> {
        self.require(ENABLE_DISP_POWER_GATING, &[1])?;
        let mut params = ps(&pipe_power_gating_params(pipe, action)?);
        self.execute(bus, ENABLE_DISP_POWER_GATING, &mut params)
    }
    /// `set_pixel_clock_v7` for an HDMI/DVI stream on combo PHY PLL `pll`.
    pub fn set_pixel_clock<B: Bus + 'static>(
        &self,
        bus: Rc<RefCell<B>>,
        clock: &PixelClock,
    ) -> Result<(), Error> {
        self.require(SET_PIXEL_CLOCK, &[7])?;
        let mut params = ps(&clock.params()?);
        self.execute(bus, SET_PIXEL_CLOCK, &mut params)
    }
    /// `encoder_control_digx_v1_5` ENCODER_CONTROL_SETUP for HDMI.
    pub fn hdmi_stream_setup<B: Bus + 'static>(
        &self,
        bus: Rc<RefCell<B>>,
        dig: u8,
        pixel_khz: u32,
    ) -> Result<(), Error> {
        self.require(DIGX_ENCODER_CONTROL, &[5])?;
        let mut params = ps(&hdmi_stream_setup_params(dig, pixel_khz)?);
        self.execute(bus, DIGX_ENCODER_CONTROL, &mut params)
    }
    /// `transmitter_control_v1_6`/`v1_7` as `dcn10_link_encoder_enable_tmds_output`
    /// (four lanes, no connector id, hpd_source) or its disable counterpart.
    pub fn transmitter<B: Bus + 'static>(
        &self,
        bus: Rc<RefCell<B>>,
        control: &Transmitter,
    ) -> Result<(), Error> {
        self.transmitter_lane(bus, control, 0)
    }
    /// [`Tables::transmitter`] with the DP_LANE_SET byte a SETUP_VSEMPH
    /// request carries (`dcn10_link_encoder_dp_set_lane_settings`).
    pub fn transmitter_lane<B: Bus + 'static>(
        &self,
        bus: Rc<RefCell<B>>,
        control: &Transmitter,
        lane_set: u8,
    ) -> Result<(), Error> {
        let revision = self.require(DIG1_TRANSMITTER_CONTROL, &[6, 7])?;
        let bytes = control.params(revision, lane_set)?;
        // dig_transmitter_control_ps_allocation_v1_6 is 32 bytes; the v1.7
        // payload is 60.
        let len = if revision == 7 { 60 } else { 32 };
        let mut params = ps(&bytes[..len]);
        self.execute(bus, DIG1_TRANSMITTER_CONTROL, &mut params)
    }
}

pub(crate) fn pipe_power_gating_params(pipe: u8, action: PipeAction) -> Result<[u8; 16], Error> {
    if pipe >= STREAMS {
        return Err(Error::Invalid);
    }
    // enable_disp_power_gating_ps_allocation: the 4-byte parameters plus
    // ATOM_COMMON_ROM_COMMAND_TABLE_HEADER-sized reserve; ATOM_CRTC1 = 0.
    let mut p = [0u8; 16];
    p[0] = pipe;
    p[1] = match action {
        PipeAction::Init => ATOM_INIT,
        PipeAction::Disable => ATOM_DISABLE,
        PipeAction::Enable => ATOM_ENABLE,
    };
    Ok(p)
}

/// `bp_pixel_clock_parameters` for one TMDS stream at 8 bpc.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PixelClock {
    /// OTG instance (`CONTROLLER_ID_D0 + otg`, `ATOM_CRTC1 + otg`).
    pub otg: u8,
    /// Combo PHY PLL index (`CLOCK_SOURCE_COMBO_PHY_PLL0 + pll`): the first
    /// free one, as `dc_resource_find_first_free_pll` picks.
    pub pll: u8,
    /// The path's physical transmitter, which names the UNIPHY encoder.
    pub transmitter: u8,
    /// Pixel clock in kHz; zero powers the PLL down.
    pub pixel_khz: u32,
}
impl PixelClock {
    fn params(&self) -> Result<[u8; 16], Error> {
        if self.otg >= STREAMS || self.pll >= STREAMS || self.transmitter >= STREAMS {
            return Err(Error::Invalid);
        }
        let mut p = [0u8; 16];
        // pixclk_100hz (actual = requested at 24 bpp), pll_id, encoderobjid,
        // encoder_mode, miscinfo (XTALIN reference: 0), crtc_id, and
        // deep_color_ratio (PIXEL_CLOCK_V7_DEEPCOLOR_RATIO_DIS: 0).
        p[..4].copy_from_slice(
            &self
                .pixel_khz
                .checked_mul(10)
                .ok_or(Error::Invalid)?
                .to_le_bytes(),
        );
        p[4] = ATOM_COMBOPHY_PLL0 + self.pll;
        p[5] = UNIPHY_OBJECT_IDS[usize::from(self.transmitter / 2)];
        p[6] = ATOM_ENCODER_MODE_HDMI;
        p[7] = 0;
        p[8] = self.otg;
        p[9] = 0;
        Ok(p)
    }
}

pub(crate) fn hdmi_stream_setup_params(dig: u8, pixel_khz: u32) -> Result<[u8; 12], Error> {
    if dig >= STREAMS || pixel_khz == 0 {
        return Err(Error::Invalid);
    }
    // dig_encoder_stream_setup_parameters_v1_5. The HDMI caller never sets
    // a colour depth, so bitpercolor stays 0, and lanenum is LANE_COUNT_FOUR.
    let mut p = [0u8; 12];
    p[0] = dig;
    p[1] = ATOM_ENCODER_CMD_STREAM_SETUP;
    p[2] = ATOM_ENCODER_MODE_HDMI;
    p[3] = 4;
    p[4..8].copy_from_slice(&(pixel_khz / 10).to_le_bytes());
    Ok(p)
}

/// `bp_transmitter_control` for one PHY, marshalled as
/// `transmitter_control_v1_6`/`v1_7` do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transmitter {
    pub action: TransmitterAction,
    pub transmitter: u8,
    /// The DIG mode; for [`TransmitterAction::SetupVsemph`] the byte carries
    /// `lane_set` instead.
    pub mode: TransmitterMode,
    /// `lanes_number`: four for TMDS enable, the trained count for DP, zero
    /// when the caller leaves it unset (disable).
    pub lanes: u8,
    /// Zero-based `hpd_source`, or `None` for `HPD_SOURCEID_UNKNOWN`.
    pub hpd: Option<u8>,
    /// `connector_obj_id.id`: set by the disable and lane-setting callers,
    /// zero for enable (`dcn10_link_encoder_enable_{tmds,dp}_output`).
    pub connector: u8,
    /// The PHY clock in kHz (`cntl->pixel_clock`): the TMDS character rate,
    /// or the DP link rate code x 27000.
    pub symbol_khz: u32,
}
impl Transmitter {
    fn params(&self, revision: u8, lane_set: u8) -> Result<[u8; 60], Error> {
        if self.transmitter >= STREAMS
            || self.hpd.is_some_and(|h| h >= STREAMS)
            || !matches!(self.lanes, 0 | 1 | 2 | 4)
        {
            return Err(Error::Invalid);
        }
        // dig_transmitter_control_parameters_v1_6 / dmub_dig_transmitter_
        // control_data_v1_7: phyid, action, digmode|dplaneset, lanenum,
        // symclk_10khz, hpdsel (1-based), digfe_sel (always 0 on DCN: the
        // driver routes the frontend), connobj_id. v1.7 adds HPO_instance,
        // which Linux derives from an unset hpo_engine_id on the DIO path;
        // DCN3.0 has no HPO, so it is sent as instance 0.
        let mut p = [0u8; 60];
        p[0] = self.transmitter;
        p[1] = self.action as u8;
        p[2] = if self.action == TransmitterAction::SetupVsemph {
            lane_set
        } else {
            self.mode as u8
        };
        p[3] = self.lanes;
        p[4..8].copy_from_slice(&(self.symbol_khz / 10).to_le_bytes());
        p[8] = self.hpd.map_or(0, |h| h + 1);
        p[9] = 0;
        p[10] = self.connector;
        if revision == 7 {
            p[11] = 0;
        }
        Ok(p)
    }
}

/// BAR5 dword bus with bounds, for the real device.
#[derive(Debug)]
pub struct Mmio {
    regs: crate::amdgpu_reg_window::Window,
    authority: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
}
impl Mmio {
    /// # Safety
    /// Caller exclusively owns the GPU registers the display tables touch and
    /// holds matching PCI authority with a permanent mapping.
    pub unsafe fn new(
        regs: narf_bus::MmioRegion,
        authority: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    ) -> Self {
        Self {
            regs: crate::amdgpu_reg_window::Window::new(regs),
            authority,
        }
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> narf_capabilities::CapOp<narf_bus::BusDeviceCap, narf_capabilities::Write>
    for Op<F>
{
    type Output = T;
    fn execute(
        self,
        _: &narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    ) -> Result<T, narf_capabilities::CapError> {
        Ok((self.0)())
    }
}
impl Bus for Mmio {
    fn read(&mut self, dword: u32) -> Option<u32> {
        let offset = u64::from(dword) * 4;
        if offset + 4 > self.regs.len() {
            return None;
        }
        let regs = self.regs;
        // SAFETY: bounded inside the permanent mapping (constructor contract).
        self.authority
            .invoke(Op(|| unsafe { regs.read32(offset) }))
            .ok()
    }
    fn write(&mut self, dword: u32, value: u32) -> bool {
        let offset = u64::from(dword) * 4;
        if offset + 4 > self.regs.len() {
            return false;
        }
        let regs = self.regs;
        // SAFETY: as above.
        self.authority
            .invoke(Op(|| unsafe { regs.write32(offset, value) }))
            .is_ok()
    }
    fn delay_us(&mut self, us: u64) {
        // The interpreter runs synchronously, as Linux's does; command tables
        // only delay for PLL/PHY lock, microseconds to a few milliseconds.
        let deadline = narf_time::Deadline::after_us(us);
        while !deadline.expired() {
            core::hint::spin_loop();
        }
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_bios_tests.rs"]
mod tests;

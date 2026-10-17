//! The VBIOS command tables Linux DC executes for Navi22 display bring-up.
//!
//! DCN3.0 sets `debug.dmub_command_table` (`dcn30_resource.c`), so while
//! DMUB runs `command_table2.c` sends every one of these to DMCUB as a
//! `DMUB_CMD__VBIOS` command (`*_dmcub`, dmub_cmd.h) instead of running the
//! ATOM interpreter: `enable_disp_power_gating_v2_1` (`dcn10_bios_golden_init`),
//! `set_pixel_clock_v7` (the PHY PLL for HDMI/DVI, via
//! `dce112_program_pix_clk`), `encoder_control_digx_v1_5` (STREAM_SETUP from
//! `enc3_stream_encoder_hdmi_set_stream_attribute`) and
//! `transmitter_control_v1_6`/`v1_7` (`dcn10_link_encoder_enable_tmds_output`
//! and the disable path). [`Tables::with_dmub`] selects that path; without
//! a running DMUB the tables run in NARF's ATOM interpreter
//! (`amdgpu_atom_execute_table`), the logged fallback. Parameter layouts are
//! the `atomfirmware.h` structs, filled exactly as those functions and the
//! `command_table_helper2_dce112.c` translations do; the parameter-space
//! sizes are Linux's.
//!
//! Register accesses from the bytecode go to BAR5 by dword index, bounded by
//! the mapping: an index outside it is recorded and the table fails, rather
//! than reaching another device (Linux would go through PCIE index/data; no
//! display table is expected to need that). PLL and MC accessors return zero,
//! as Linux's SOC15 `cail_pll_read`/`cail_mc_read` do; port I/O is refused.
use crate::{
    amdgpu_atom_vm::{self as vm, AtomError, AtomState, ResolvedTable},
    amdgpu_atombios::{Atombios, ATOM_CT_WS_PTR},
    amdgpu_dmub_navi22::{Dmub, VbiosCommand},
};
use alloc::{boxed::Box, rc::Rc, vec::Vec};
use core::cell::RefCell;

// atom_master_list_of_command_functions_v2_1 indices.
// linux: offsetof(struct atom_master_list_of_command_functions_v2_1, digxencodercontrol) / 2
const DIGX_ENCODER_CONTROL: u16 = 4;
// linux: offsetof(struct atom_master_list_of_command_functions_v2_1, setpixelclock) / 2
const SET_PIXEL_CLOCK: u16 = 12;
// linux: offsetof(struct atom_master_list_of_command_functions_v2_1, enabledisppowergating) / 2
const ENABLE_DISP_POWER_GATING: u16 = 13;
// linux: offsetof(struct atom_master_list_of_command_functions_v2_1, dig1transmittercontrol) / 2
const DIG1_TRANSMITTER_CONTROL: u16 = 76;
// atomfirmware.h enumerations.
const ATOM_ENCODER_MODE_HDMI: u8 = 3; // linux: ATOM_ENCODER_MODE_HDMI
const ATOM_ENCODER_CMD_STREAM_SETUP: u8 = 0x0f; // linux: ATOM_ENCODER_CMD_STREAM_SETUP
const ATOM_COMBOPHY_PLL0: u8 = 20; // linux: ATOM_COMBOPHY_PLL0
/// `ENCODER_OBJECT_ID_INTERNAL_UNIPHY`, `_UNIPHY1`, `_UNIPHY2`.
// linux: n/a (ENCODER_OBJECT_ID_INTERNAL_UNIPHY{,1,2} = 0x1E/0x20/0x21, amdgpu/ObjectID.h; not in checker sets)
const UNIPHY_OBJECT_IDS: [u8; 3] = [0x1e, 0x20, 0x21];
const ATOM_DISABLE: u8 = 0; // linux: ATOM_DISABLE
const ATOM_ENABLE: u8 = 1; // linux: ATOM_ENABLE
const ATOM_INIT: u8 = 7; // linux: ATOM_INIT
/// DCN30 drives six streams and six PHY PLLs.
const STREAMS: u8 = 6; // linux: n/a (DCN30 pipe/PHY count)

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
    /// DMCUB did not execute the `DMUB_CMD__VBIOS` command.
    Dmub(crate::amdgpu_dmub_navi22::Error),
    /// One interpreted table ran past [`TABLE_MS`] of wall clock.
    Timeout,
}

/// Wall-clock cap on one interpreted display table, the counterpart of
/// ASIC_Init's `POST_MS`. Linux bounds only each *loop*
/// (`ATOM_CMD_TIMEOUT_SEC` in `atom_op_jump`), so bytecode that keeps
/// changing its jump target, or keeps delaying, never ends there; NARF caps
/// the whole run. Above the 20 s per-loop guard so that guard still reports
/// a single stuck loop first.
pub const TABLE_MS: u64 = 30_000; // linux: n/a (NARF bound)

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
    Disable = 0, // linux-lit: 0=ATOM_TRANSMITTER_ACTION_DISABLE
    Enable = 1,  // linux-lit: 1=ATOM_TRANSMITTER_ACTION_ENABLE
    /// `TRANSMITTER_CONTROL_SET_VOLTAGE_AND_PREEMPASIS`.
    SetupVsemph = 11, // linux-lit: 11=ATOM_TRANSMITTER_ACTION_SETUP_VSEMPH
}
/// `signal_type_to_atom_dig_mode` (`command_table_helper2_dce112.c`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransmitterMode {
    DisplayPort = 0, // linux-lit: 0=ATOM_TRANSMITTER_DIGMODE_V6_DP
    /// Also what `SIGNAL_TYPE_NONE` maps to (the power-down path).
    Dvi = 2, // linux-lit: 2=ATOM_TRANSMITTER_DIGMODE_V6_DVI
    Hdmi = 3,        // linux-lit: 3=ATOM_TRANSMITTER_DIGMODE_V6_HDMI
}

/// The register bus the interpreter drives.
pub trait Bus {
    fn read(&mut self, dword: u32) -> Option<u32>;
    fn write(&mut self, dword: u32, value: u32) -> bool;
    /// `udelay`/`msleep` from DELAY_* opcodes.
    fn delay_us(&mut self, us: u64);
    /// Monotonic milliseconds for atom_op_jump's 20 s stuck guard; `None`
    /// keeps the interpreter's clockless repeat bound.
    fn now_ms(&mut self) -> Option<u64> {
        None
    }
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
    /// `amdgpu_atomfirmware_allocate_fb_scratch`'s size, in dwords.
    fb_words: usize,
    /// The running DMUB the tables go to (`dc->ctx->dmub_srv`).
    dmub: Option<&'a dyn VbiosDmub>,
}
/// Where `DMUB_CMD__VBIOS` commands go: [`DmubRoute`] on hardware.
pub trait VbiosDmub: Sync {
    fn execute_vbios(
        &self,
        command: VbiosCommand,
        payload: &[u8],
    ) -> Result<(), crate::amdgpu_dmub_navi22::Error>;
}
/// A running DMUB borrowed for one modeset. The lock only gives the `&self`
/// table calls exclusive use of the mailbox; it is never contended.
pub struct DmubRoute<'d>(MailboxLock<&'d mut Dmub>);

/// Exclusive use of a mailbox for `&self` callers *without* masking
/// interrupts. A VBIOS command waits up to 100 ms for the DMCUB to drain
/// its inbox; Linux runs that wait (`dc_wake_and_execute_dmub_cmd` →
/// `dmub_srv_wait_for_idle`) under `dc_lock`, a mutex, with IRQs on. The
/// previous `IrqSafeSpinLock` kept interrupts off for the whole wait (the
/// HPD/IH, timer and every other device starved, and a wait that depends
/// on an IRQ could never finish).
pub(crate) struct MailboxLock<T>(narf_lib::mutex::Mutex<T>);
impl<T> MailboxLock<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self(narf_lib::mutex::Mutex::new(value))
    }
    /// Run `f` with exclusive access; `None` when already held.
    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        let mut guard = self.0.try_lock()?;
        Some(f(&mut guard))
    }
}
impl core::fmt::Debug for DmubRoute<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DmubRoute")
    }
}
impl<'d> DmubRoute<'d> {
    /// The DMUB path when `dmub` runs with an idle mailbox (DCN3.0's
    /// `dmub_command_table`); otherwise `None`, logged: the ATOM
    /// interpreter is the fallback.
    pub fn new(dmub: Option<&'d mut Dmub>) -> Option<Self> {
        match dmub {
            Some(dmub) if dmub.vbios_ready() => Some(Self(MailboxLock::new(dmub))),
            _ => {
                use core::fmt::Write;
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: navi22 VBIOS display tables via ATOM interpreter (DMUB not running)"
                );
                None
            }
        }
    }
}
impl VbiosDmub for DmubRoute<'_> {
    fn execute_vbios(
        &self,
        command: VbiosCommand,
        payload: &[u8],
    ) -> Result<(), crate::amdgpu_dmub_navi22::Error> {
        self.0
            .with(|dmub| dmub.execute_vbios(command, payload))
            .ok_or(crate::amdgpu_dmub_navi22::Error::Busy)?
    }
}
impl core::fmt::Debug for Tables<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tables")
            .field("len", &self.bios.len())
            .field("dmub", &self.dmub.is_some())
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
            fb_words: crate::amdgpu_reset_navi22::atom_fb_scratch_bytes(bios).div_ceil(4),
            dmub: None,
        })
    }
    /// Send every table to `dmub` (command_table2.c's `dmub_command_table`
    /// branches) instead of the ATOM interpreter.
    pub fn with_dmub(mut self, dmub: Option<&'a dyn VbiosDmub>) -> Self {
        self.dmub = dmub;
        self
    }
    /// True when the tables go to DMCUB.
    pub fn uses_dmub(&self) -> bool {
        self.dmub.is_some()
    }
    /// command_table2.c `*_dmcub`; `None` without a DMUB route.
    fn dmub(&self, command: VbiosCommand, payload: &[u8]) -> Option<Result<(), Error>> {
        let dmub = self.dmub?;
        Some(dmub.execute_vbios(command, payload).map_err(Error::Dmub))
    }
    /// The VBIOS image the tables run from (data tables such as the
    /// display-object records).
    pub fn image(&self) -> &'a [u8] {
        self.bios
    }
    /// `amdgpu_atom_parse_cmd_header`'s content revision.
    pub fn revision(&self, table: u16) -> Result<u8, Error> {
        let header = self
            .atom
            .cmd_table(table)
            .map_err(|_| Error::Missing(table))?;
        // linux-lit: 3=offsetof(struct atom_common_table_header, content_revision)
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
        let mut state = AtomState::new(1, self.fb_words);
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
        if bus.borrow_mut().now_ms().is_some() {
            let b = bus.clone();
            state.now_ms = Some(Box::new(move || b.borrow_mut().now_ms().unwrap_or(0)));
        }
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
        // `vm::execute_table`'s drive loop, plus the TABLE_MS cap.
        let began = bus.borrow_mut().now_ms();
        let result = match vm::Machine::start(&mut state, id, params) {
            Err(e) => Err(Error::Atom(e)),
            Ok(mut machine) => loop {
                match machine.step(&mut state) {
                    Err(e) => break Err(Error::Atom(e)),
                    Ok(vm::Step::Done) => break Ok(()),
                    Ok(vm::Step::Delay(us)) => bus.borrow_mut().delay_us(us),
                    Ok(vm::Step::Continue) => {}
                }
                let now = bus.borrow_mut().now_ms();
                if let (Some(began), Some(now)) = (began, now) {
                    if now.saturating_sub(began) > TABLE_MS {
                        break Err(Error::Timeout);
                    }
                }
            },
        };
        drop(state);
        if *faulted.borrow() {
            return Err(Error::Bus);
        }
        result
    }

    /// `enable_disp_power_gating_v2_1` (`enable_disp_power_gating_parameters_v2_1`).
    pub fn pipe_power_gating<B: Bus + 'static>(
        &self,
        bus: Rc<RefCell<B>>,
        pipe: u8,
        action: PipeAction,
    ) -> Result<(), Error> {
        let block = pipe_power_gating_params(pipe, action)?;
        // enable_disp_power_gating_dmcub sends `ps.param` alone.
        if let Some(result) = self.dmub(VbiosCommand::EnableDispPowerGating, &block[..4]) {
            return result;
        }
        self.require(ENABLE_DISP_POWER_GATING, &[1])?;
        let mut params = ps(&block);
        self.execute(bus, ENABLE_DISP_POWER_GATING, &mut params)
    }
    /// `set_pixel_clock_v7` for an HDMI/DVI stream on combo PHY PLL `pll`.
    pub fn set_pixel_clock<B: Bus + 'static>(
        &self,
        bus: Rc<RefCell<B>>,
        clock: &PixelClock,
    ) -> Result<(), Error> {
        let block = clock.params()?;
        if let Some(result) = self.dmub(VbiosCommand::SetPixelClock, &block) {
            return result;
        }
        self.require(SET_PIXEL_CLOCK, &[7])?;
        let mut params = ps(&block);
        self.execute(bus, SET_PIXEL_CLOCK, &mut params)
    }
    /// `encoder_control_digx_v1_5` ENCODER_CONTROL_SETUP for HDMI.
    pub fn hdmi_stream_setup<B: Bus + 'static>(
        &self,
        bus: Rc<RefCell<B>>,
        dig: u8,
        pixel_khz: u32,
    ) -> Result<(), Error> {
        let block = hdmi_stream_setup_params(dig, pixel_khz)?;
        if let Some(result) = self.dmub(VbiosCommand::DigxEncoderControl, &block) {
            return result;
        }
        self.require(DIGX_ENCODER_CONTROL, &[5])?;
        let mut params = ps(&block);
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
        if self.dmub.is_some() {
            // init_transmitter_control: crev 6 marshals the v1.6 parameters;
            // 7, or any other (transmitter_control_fallback), the v1.7 data.
            // Either sits in the 60-byte dig1_transmitter_control union.
            let revision = match self.revision(DIG1_TRANSMITTER_CONTROL) {
                Ok(6) => 6,
                _ => 7,
            };
            let bytes = control.params(revision, lane_set)?;
            if let Some(result) = self.dmub(VbiosCommand::Dig1TransmitterControl, &bytes) {
                return result;
            }
        }
        let revision = self.require(DIG1_TRANSMITTER_CONTROL, &[6, 7])?;
        let bytes = control.params(revision, lane_set)?;
        // dig_transmitter_control_ps_allocation_v1_6 is 32 bytes; the v1.7
        // payload is 60.
        // linux-lit: 60=sizeof(struct dmub_dig_transmitter_control_data_v1_7); 32=sizeof(struct dig_transmitter_control_ps_allocation_v1_6)
        let len = if revision == 7 { 60 } else { 32 };
        let mut params = ps(&bytes[..len]);
        self.execute(bus, DIG1_TRANSMITTER_CONTROL, &mut params)
    }
}

// linux-lit: 16=sizeof(struct enable_disp_power_gating_parameters_v2_1) * 4
pub(crate) fn pipe_power_gating_params(pipe: u8, action: PipeAction) -> Result<[u8; 16], Error> {
    if pipe >= STREAMS {
        return Err(Error::Invalid);
    }
    // enable_disp_power_gating_ps_allocation: the 4-byte parameters plus
    // ATOM_COMMON_ROM_COMMAND_TABLE_HEADER-sized reserve; ATOM_CRTC1 = 0.
    // linux-lit: 16=sizeof(struct enable_disp_power_gating_parameters_v2_1) * 4
    let mut p = [0u8; 16];
    // linux-lit: 0=offsetof(struct enable_disp_power_gating_parameters_v2_1, disp_pipe_id)
    p[0] = pipe;
    // linux-lit: 1=offsetof(struct enable_disp_power_gating_parameters_v2_1, enable)
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
    /// `bp_params->target_pixel_clock_100hz`: the PLL target in 100 Hz
    /// units (`actual_pix_clk_100hz`, deep-colour scaled), sent verbatim as
    /// `pixclk_100hz`; zero powers the PLL down.
    pub pixel_100hz: u32,
    /// `transmitter_color_depth_to_atom`: PIXEL_CLOCK_V7_DEEPCOLOR_RATIO_DIS
    /// (0), _5_4 (1), _3_2 (2) or _2_1 (3).
    pub deep_color: u8,
}
impl PixelClock {
    fn params(&self) -> Result<[u8; 16], Error> {
        if self.otg >= STREAMS
            || self.pll >= STREAMS
            || self.transmitter >= STREAMS
            || self.deep_color > 3
        {
            return Err(Error::Invalid);
        }
        // linux-lit: 16=sizeof(struct set_pixel_clock_parameter_v1_7)
        let mut p = [0u8; 16];
        // set_pixel_clock_v7: pixclk_100hz, pll_id, encoderobjid,
        // encoder_mode, miscinfo (XTALIN reference: 0), crtc_id and
        // deep_color_ratio.
        p[..4].copy_from_slice(&self.pixel_100hz.to_le_bytes());
        // linux-lit: 4=offsetof(struct set_pixel_clock_parameter_v1_7, pll_id)
        p[4] = ATOM_COMBOPHY_PLL0 + self.pll;
        // linux-lit: 5=offsetof(struct set_pixel_clock_parameter_v1_7, encoderobjid)
        p[5] = UNIPHY_OBJECT_IDS[usize::from(self.transmitter / 2)];
        // linux-lit: 6=offsetof(struct set_pixel_clock_parameter_v1_7, encoder_mode)
        p[6] = ATOM_ENCODER_MODE_HDMI;
        p[7] = 0; // linux-lit: 7=offsetof(struct set_pixel_clock_parameter_v1_7, miscinfo)
        p[8] = self.otg; // linux-lit: 8=offsetof(struct set_pixel_clock_parameter_v1_7, crtc_id)
        p[9] = self.deep_color;
        Ok(p)
    }
}

// linux-lit: 12=sizeof(struct dig_encoder_stream_setup_parameters_v1_5)
pub(crate) fn hdmi_stream_setup_params(dig: u8, pixel_khz: u32) -> Result<[u8; 12], Error> {
    if dig >= STREAMS || pixel_khz == 0 {
        return Err(Error::Invalid);
    }
    // dig_encoder_stream_setup_parameters_v1_5. The HDMI caller never sets
    // a colour depth, so bitpercolor stays 0, and lanenum is LANE_COUNT_FOUR.
    // linux-lit: 12=sizeof(struct dig_encoder_stream_setup_parameters_v1_5)
    let mut p = [0u8; 12];
    // linux-lit: 0=offsetof(struct dig_encoder_stream_setup_parameters_v1_5, digid)
    p[0] = dig;
    // linux-lit: 1=offsetof(struct dig_encoder_stream_setup_parameters_v1_5, action)
    p[1] = ATOM_ENCODER_CMD_STREAM_SETUP;
    // linux-lit: 2=offsetof(struct dig_encoder_stream_setup_parameters_v1_5, digmode)
    p[2] = ATOM_ENCODER_MODE_HDMI;
    // linux-lit: 3=offsetof(struct dig_encoder_stream_setup_parameters_v1_5, lanenum)
    p[3] = 4;
    // linux-lit: 4=offsetof(struct dig_encoder_stream_setup_parameters_v1_5, pclk_10khz); 8=offsetof(struct dig_encoder_stream_setup_parameters_v1_5, bitpercolor)
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
        // linux-lit: 0=offsetof(struct dig_transmitter_control_parameters_v1_6, phyid)
        p[0] = self.transmitter;
        // linux-lit: 1=offsetof(struct dig_transmitter_control_parameters_v1_6, action)
        p[1] = self.action as u8;
        // linux-lit: 2=offsetof(struct dig_transmitter_control_parameters_v1_6, mode_laneset)
        p[2] = if self.action == TransmitterAction::SetupVsemph {
            lane_set
        } else {
            self.mode as u8
        };
        // linux-lit: 3=offsetof(struct dig_transmitter_control_parameters_v1_6, lanenum)
        p[3] = self.lanes;
        // linux-lit: 4=offsetof(struct dig_transmitter_control_parameters_v1_6, symclk_10khz); 8=offsetof(struct dig_transmitter_control_parameters_v1_6, hpdsel)
        p[4..8].copy_from_slice(&(self.symbol_khz / 10).to_le_bytes());
        // linux-lit: 8=offsetof(struct dig_transmitter_control_parameters_v1_6, hpdsel)
        p[8] = self.hpd.map_or(0, |h| h + 1);
        p[9] = 0; // linux-lit: 9=offsetof(struct set_pixel_clock_parameter_v1_7, deep_color_ratio)
                  // linux-lit: 10=offsetof(struct dig_transmitter_control_parameters_v1_6, connobj_id)
        p[10] = self.connector;
        if revision == 7 {
            // linux-lit: 11=offsetof(struct dmub_dig_transmitter_control_data_v1_7, HPO_instance)
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
    fn now_ms(&mut self) -> Option<u64> {
        Some(narf_time::wall::monotonic_ns() / 1_000_000)
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_bios_tests.rs"]
mod tests;

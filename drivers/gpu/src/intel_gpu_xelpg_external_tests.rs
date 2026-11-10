//! Native register/sink conversations for the owned MTL external route.
extern crate alloc;

use super::*;
use crate::intel_gpu_aux::{
    AUX_CTL_DONE, AUX_CTL_MSGSIZE_MASK, AUX_CTL_MSGSIZE_SHIFT, AUX_CTL_SEND_BUSY, AUX_CTL_TBT_IO,
    XELPDP_AUX_CH_CTL_POWER_REQUEST,
};
use crate::intel_gpu_gmbus::tests::FakeGmbus;
use crate::intel_gpu_modeset::PixelFormat;
use crate::intel_gpu_xelpg::tests::FakePhy;
use crate::intel_gpu_xelpg::{TCSS_POWER_REQUEST, TC_PHY_OWNERSHIP};
use crate::intel_gpu_xelpg_hpd::{
    pica_dp_alt_hotplug, pica_tbt_hotplug, port_hotplug_ctl, shotplug_ddi_long, LiveMode,
    MtlHpdConfig, MtlHpdMonitor, DP_ALT_HPD_LONG_DETECT, PICA_IIR, PICA_ISR, SDE_IIR, SDE_ISR,
    SHOTPLUG_CTL_DDI, SHOTPLUG_CTL_TC,
};
use crate::intel_gpu_xelpg_tc::{
    pin_assignment_shift, port_tx_dflexpa1, tcss_ddi_status, PIN_ASSIGNMENT_C,
    TCSS_DDI_STATUS_READY,
};
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use narf_kernel_test::{kernel_test_in, TestResult};

// ── DP sink: native DPCD, link-training state, I2C EDID at 0x50 ─────

#[derive(Debug)]
pub struct Sink {
    caps: [u8; 16],
    edid: Vec<u8>,
    i2c_ptr: usize,
    lanes_set: u8,
    pattern: u8,
    cr_locked: bool,
    eq_locked: bool,
    polls: u32,
    pub powered: bool,
    /// CR never locks with more lanes than this (0 = no limit).
    pub max_good_lanes: u8,
    pub nack_all: bool,
    pub power_log: Vec<u8>,
    /// DSC capabilities at DPCD 0x060..=0x06F.
    pub dsc: [u8; 16],
    /// `DP_FEC_CAPABILITY`.
    pub fec_cap: u8,
    /// `DP_FEC_CONFIGURATION`, `DP_DSC_ENABLE` and `DP_FEC_STATUS`.
    pub fec_config: u8,
    pub dsc_enable: u8,
    pub fec_status: u8,
    /// Native writes to the DSC/FEC registers, in order.
    pub dsc_log: Vec<(u32, u8)>,
}

impl Sink {
    pub fn new(max_bw: u8, edid: Vec<u8>) -> Self {
        let mut caps = [0u8; 16];
        caps[0] = 0x14;
        caps[1] = max_bw;
        caps[2] = 4 | 0x40 | 0x80;
        Self {
            caps,
            edid,
            i2c_ptr: 0,
            lanes_set: 0,
            pattern: 0,
            cr_locked: false,
            eq_locked: false,
            polls: 0,
            powered: false,
            max_good_lanes: 0,
            nack_all: false,
            power_log: Vec::new(),
            dsc: [0; 16],
            fec_cap: 0,
            fec_config: 0,
            dsc_enable: 0,
            fec_status: 0,
            dsc_log: Vec::new(),
        }
    }
    pub fn drop_lock(&mut self) {
        self.cr_locked = false;
        self.eq_locked = false;
    }
    fn lanes_ok(&self) -> bool {
        self.max_good_lanes == 0 || self.lanes_set <= self.max_good_lanes
    }
    fn status_byte(&self) -> u8 {
        let mut nibble = 0;
        if self.cr_locked {
            nibble |= 0x1;
        }
        if self.eq_locked {
            nibble |= 0x6;
        }
        nibble | (nibble << 4)
    }
    fn read_byte(&mut self, addr: u32) -> u8 {
        match addr {
            0x000..=0x00F => self.caps[addr as usize],
            0x202 => {
                self.polls += 1;
                if self.powered && self.pattern == 1 && self.lanes_ok() {
                    self.cr_locked = true;
                }
                if self.pattern >= 2 && self.cr_locked && self.polls >= 1 {
                    self.eq_locked = true;
                }
                self.status_byte()
            }
            0x203 => self.status_byte(),
            0x204 => self.eq_locked as u8,
            0x060..=0x06F => self.dsc[(addr - 0x060) as usize],
            0x090 => self.fec_cap,
            0x120 => self.fec_config,
            0x160 => self.dsc_enable,
            // The decoder reports FEC once the source sends it (ready, and
            // the link trained).
            0x280 => {
                if self.fec_config & 1 != 0 && self.eq_locked {
                    self.fec_status | 1
                } else {
                    self.fec_status
                }
            }
            _ => 0,
        }
    }
    fn write_byte(&mut self, addr: u32, value: u8) {
        match addr {
            0x100 => {
                self.drop_lock();
                self.polls = 0;
            }
            0x101 => {
                self.lanes_set = value & 0x1F;
                self.drop_lock();
            }
            0x102 => {
                self.pattern = value & 0x7;
                self.polls = 0;
            }
            0x120 | 0x160 | 0x280 => {
                self.dsc_log.push((addr, value));
                match addr {
                    0x120 => self.fec_config = value,
                    0x160 => self.dsc_enable = value,
                    _ => self.fec_status &= !value,
                }
            }
            0x600 => {
                self.power_log.push(value);
                self.powered = value & 0x3 == 1;
                if !self.powered {
                    self.drop_lock();
                }
            }
            _ => {}
        }
    }
    fn transact(&mut self, wire: &[u8]) -> Vec<u8> {
        if self.nack_all {
            return alloc::vec![0x10];
        }
        let cmd = wire[0] >> 4;
        let addr = (((wire[0] & 0xF) as u32) << 16) | ((wire[1] as u32) << 8) | wire[2] as u32;
        if cmd & 0x8 == 0 && addr != 0x50 {
            return alloc::vec![0x40];
        }
        if wire.len() == 3 {
            return alloc::vec![0x00];
        }
        let len = wire[3] as usize + 1;
        match cmd {
            0x8 => {
                for i in 0..len {
                    self.write_byte(addr + i as u32, wire[4 + i]);
                }
                alloc::vec![0x00]
            }
            0x9 => {
                let mut reply = alloc::vec![0x00];
                for i in 0..len {
                    let b = self.read_byte(addr + i as u32);
                    reply.push(b);
                }
                reply
            }
            0x0 | 0x4 => {
                self.i2c_ptr = wire[4] as usize;
                alloc::vec![0x00]
            }
            0x1 | 0x5 => {
                let mut reply = alloc::vec![0x00];
                for i in 0..len {
                    reply.push(self.edid.get(self.i2c_ptr + i).copied().unwrap_or(0));
                }
                self.i2c_ptr += len;
                reply
            }
            _ => alloc::vec![0x10],
        }
    }
}

/// A one-block EDID whose preferred detailed timing is the given mode.
#[allow(clippy::too_many_arguments)]
pub fn edid_for(
    pclk_khz: u32,
    h: u16,
    hblank: u16,
    hso: u16,
    hsw: u16,
    v: u16,
    vblank: u16,
    vso: u16,
    vsw: u16,
) -> Vec<u8> {
    let mut e = alloc::vec![0u8; 128];
    e[0..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
    let mfr: u16 = (14 << 10) | (1 << 5) | 18;
    e[8] = (mfr >> 8) as u8;
    e[9] = mfr as u8;
    e[18] = 1;
    e[19] = 4;
    let d = &mut e[0x36..0x36 + 18];
    let clk = (pclk_khz / 10) as u16;
    d[0] = clk as u8;
    d[1] = (clk >> 8) as u8;
    d[2] = h as u8;
    d[3] = hblank as u8;
    d[4] = (((h >> 8) & 0xF) << 4) as u8 | ((hblank >> 8) & 0xF) as u8;
    d[5] = v as u8;
    d[6] = vblank as u8;
    d[7] = (((v >> 8) & 0xF) << 4) as u8 | ((vblank >> 8) & 0xF) as u8;
    d[8] = hso as u8;
    d[9] = hsw as u8;
    d[10] = (((vso & 0xF) << 4) | (vsw & 0xF)) as u8;
    d[11] = ((((hso >> 8) & 3) << 6)
        | (((hsw >> 8) & 3) << 4)
        | (((vso >> 4) & 3) << 2)
        | ((vsw >> 4) & 3)) as u8;
    d[17] = 0x18 | 0x4 | 0x2;
    let sum: u32 = e[..127].iter().map(|&b| b as u32).sum();
    e[127] = ((256 - (sum % 256)) % 256) as u8;
    e
}

fn edid_1024() -> Vec<u8> {
    edid_for(65_000, 1024, 320, 24, 136, 768, 38, 3, 6)
}

fn edid_1080() -> Vec<u8> {
    edid_for(148_500, 1920, 280, 88, 44, 1080, 45, 4, 5)
}

const CDCLK_PLL: u64 = 0x4_6070;

// Pipe/transcoder registers of the route. With Pipe A dark or lit by the
// panel, the route takes Pipe B: the external route never drives Pipe A.
/// `TRANSCONF(A)`, the internal panel's pipe.
pub const PIPECONF_A: u64 = 0x7_0008;
/// `TRANSCONF(B)`.
pub const PIPECONF_B: u64 = 0x7_1008;
/// Primary `PLANE_CTL` / `PLANE_SURF` of Pipe A.
pub const PLANE_CTL_1_A: u64 = 0x7_0180;
pub const PLANE_SURF_1_A: u64 = 0x7_019C;
/// Primary `PLANE_CTL` / `PLANE_SURF` of Pipe B.
pub const PLANE_CTL_1_B: u64 = 0x7_1180;
pub const PLANE_SURF_1_B: u64 = 0x7_119C;
/// `TRANS_DDI_FUNC_CTL(B)`, `TRANS_CLK_SEL(B)`, `TGL_DP_TP_CTL(B)`.
pub const TRANS_DDI_FUNC_CTL_B: u64 = 0x6_1400;
pub const TRANS_CLK_SEL_B: u64 = 0x4_6144;
pub const DP_TP_CTL_B: u64 = 0x6_1540;
/// The Pipe A/transcoder A function control and clock select.
pub const TRANS_DDI_FUNC_CTL_A: u64 = 0x6_0400;
pub const TRANS_CLK_SEL_A: u64 = 0x4_6140;
/// `XELPDP_INITIATE_PMDEMAND_REQUEST(1)`.
pub const PMDEMAND_REQUEST1: u64 = 0x4_5234;
/// The lit panel's scanout surface (distinct from the external's).
pub const PANEL_SURFACE: u32 = 0x0080_0000;

/// `TRANSCONF(pipe)` when `off` is one, with the pipe.
fn conf_pipe(off: u64) -> Option<usize> {
    (0..4).find(|p| off == 0x7_0008 + *p as u64 * 0x1000)
}
/// `PIPE_FRMCOUNT_G4X(pipe)` when `off` is one.
fn frame_pipe(off: u64) -> Option<usize> {
    (0..4).find(|p| off == 0x7_0040 + *p as u64 * 0x1000)
}
/// Primary `PLANE_SURFLIVE(pipe)` when `off` is one.
fn surflive_pipe(off: u64) -> Option<usize> {
    (0..4).find(|p| off == 0x7_01AC + *p as u64 * 0x1000)
}

/// MTL display model for one external port: `FakePhy` (message bus, PLL
/// acks, BUF_CTL1 D2D/PHY_IDLE/TCSS mirrors), HSW-encoded power wells,
/// the CDCLK PLL lock and crawl ACK, the display-14 resource ACKs (PM
/// demand completion, DBUF slice power state) and WM latencies, every
/// pipe's TRANSCONF state, frame counter and LIVE surface, Type-C IOM/FIA
/// facts, PICA/SDE levels and W1C latches, and a DP sink behind the port's
/// Xe-LPDP AUX channel. [`ExtFake::with_panel`] lights the owned panel
/// profile on Pipe A.
#[derive(Debug)]
pub struct ExtFake {
    pub phy: FakePhy,
    pub port: XeLpgPort,
    pub access: Cell<bool>,
    pub pica_isr: Cell<u32>,
    pub sde_isr: Cell<u32>,
    pub pin: Cell<u8>,
    pub ready: Cell<bool>,
    cdclk_pll: Cell<u32>,
    confs: [Cell<u32>; 4],
    /// No TRANSCONF ever acknowledges a disable.
    pub pipeconf_stuck: Cell<bool>,
    pub act_stuck: Cell<bool>,
    frames: [Cell<u32>; 4],
    /// `narf_arch::interrupts_enabled()` at every `PIPEDSL` sample and
    /// primary `PLANE_SURF` write: (register, enabled).
    pub irq_log: RefCell<Vec<(u64, bool)>>,
    pub sink: RefCell<Sink>,
    aux_data: RefCell<[u32; 5]>,
    aux_reply: RefCell<Vec<u8>>,
    aux_done: Cell<u32>,
    aux_power: Cell<bool>,
    pub aux_ctl_writes: RefCell<Vec<u32>>,
    pub writes: RefCell<Vec<(u64, u32)>>,
    /// The DDC side (GMBUS controller + EDID/SCDC slaves); absent by default.
    pub ddc: FakeGmbus,
}

/// Whether `off` is one of the GMBUS0..GMBUS5 registers.
fn is_gmbus(off: u64) -> bool {
    (crate::intel_gpu_gmbus::GMBUS0..=crate::intel_gpu_gmbus::GMBUS5).contains(&off)
}

impl ExtFake {
    pub fn new(port: XeLpgPort, sink: Sink) -> Self {
        let phy = FakePhy::new(port);
        phy.model_d2d.set(true);
        phy.model_ddi_idle.set(true);
        phy.model_tcss.set(true);
        let pica = port.tc_index().map_or(0, pica_dp_alt_hotplug);
        let sde = if port == XeLpgPort::B { 1 << 17 } else { 0 };
        // MTL_LATENCY_LP0_LP1..LP4_LP5 (the live/pipes fixture's values).
        for (r, v) in [
            (0x4_5780, 6 | (8 << 16)),
            (0x4_5784, 10 | (12 << 16)),
            (0x4_5788, 14 | (16 << 16)),
        ] {
            phy.write32(r, v);
        }
        phy.writes.borrow_mut().clear();
        Self {
            phy,
            port,
            access: Cell::new(true),
            pica_isr: Cell::new(pica),
            sde_isr: Cell::new(sde),
            pin: Cell::new(PIN_ASSIGNMENT_C),
            ready: Cell::new(true),
            cdclk_pll: Cell::new(0),
            confs: Default::default(),
            pipeconf_stuck: Cell::new(false),
            act_stuck: Cell::new(false),
            frames: Default::default(),
            irq_log: RefCell::new(Vec::new()),
            sink: RefCell::new(sink),
            aux_data: RefCell::new([0; 5]),
            aux_reply: RefCell::new(Vec::new()),
            aux_done: Cell::new(0),
            aux_power: Cell::new(false),
            aux_ctl_writes: RefCell::new(Vec::new()),
            writes: RefCell::new(Vec::new()),
            ddc: FakeGmbus::absent(),
        }
    }
    pub fn writes_to(&self, off: u64) -> Vec<u32> {
        self.writes
            .borrow()
            .iter()
            .filter(|(o, _)| *o == off)
            .map(|(_, v)| *v)
            .collect()
    }
    /// Force `pipe`'s TRANSCONF (as firmware or another owner left it).
    pub fn set_conf(&self, pipe: usize, value: u32) {
        self.confs[pipe].set(value & !STATE);
    }
    /// Index of the first logged write matching `f`.
    pub fn first_write(&self, f: impl Fn(u64, u32) -> bool) -> Option<usize> {
        self.writes.borrow().iter().position(|&(o, v)| f(o, v))
    }
    /// Index of the last logged write matching `f`.
    pub fn last_write(&self, f: impl Fn(u64, u32) -> bool) -> Option<usize> {
        self.writes.borrow().iter().rposition(|&(o, v)| f(o, v))
    }
    /// Light the owned 1024x768 internal panel on Pipe A exactly as the
    /// owned MTL modeset leaves it: display 14.00, IPC on, the computed
    /// display-14 resource state committed, TRANSCONF and the linear
    /// primary on. The write log is cleared; the panel mode is returned
    /// (`None` if the fixture could not commit it).
    pub fn light_panel(&self) -> Option<Mode> {
        let mode = Mode::VESA_1024X768_60;
        self.phy.write32(0x5_10A0, 14 << 22);
        self.phy.write32(0x4_5004, 1 << 3);
        let latency = crate::intel_gpu_xelpg_wm::Latency::read(self).ok()?;
        let state = crate::intel_gpu_xelpg_resources::compute(
            &crate::intel_gpu_display_resources::request(
                &mode,
                crate::intel_gpu_xelpg_wm::Tiling::Linear,
                0,
            ),
            &latency,
        )
        .ok()?;
        crate::intel_gpu_xelpg_resources::commit(self, &state).ok()?;
        self.write32(PIPECONF_A, ENABLE);
        self.write32(PLANE_CTL_1_A, ENABLE);
        self.write32(PLANE_SURF_1_A, PANEL_SURFACE);
        self.writes.borrow_mut().clear();
        self.phy.writes.borrow_mut().clear();
        self.irq_log.borrow_mut().clear();
        Some(mode)
    }
    fn w1c(&self, off: u64) -> u32 {
        if (0..4).any(|p| off == 0x60544 + p * 0x1000) {
            return 1 << 24;
        }
        if off == PICA_IIR || off == SDE_IIR {
            return u32::MAX;
        }
        if off == SHOTPLUG_CTL_DDI {
            return 0x3333;
        }
        if off == SHOTPLUG_CTL_TC {
            return 0x33_3333;
        }
        if (0..4).any(|tc| off == port_hotplug_ctl(tc)) {
            return 0x33;
        }
        0
    }
    fn aux_send(&self, ctl: u32) {
        let mut wire = [0u8; 20];
        for (i, d) in self.aux_data.borrow().iter().enumerate() {
            wire[i * 4..i * 4 + 4].copy_from_slice(&d.to_be_bytes());
        }
        let n = ((ctl & AUX_CTL_MSGSIZE_MASK) >> AUX_CTL_MSGSIZE_SHIFT) as usize;
        let address =
            (u32::from(wire[0] & 15) << 16) | (u32::from(wire[1]) << 8) | u32::from(wire[2]);
        if wire[0] >> 4 == 8 && address == 0x102 {
            // BSpec DP_TP_CTL patterns must reach the source before the
            // corresponding DPCD write. A sink-only trainer cannot lock.
            let expected = match wire[4] & 7 {
                0 => 3,
                1 => 0,
                2 => 1,
                3 => 4,
                7 => 5,
                _ => 7,
            };
            let correct = (0..4).any(|pipe| {
                let source = self.phy.read32(0x60540 + pipe * 0x1000);
                source & (1 << 31) != 0 && (source >> 8) & 7 == expected
            });
            if !correct {
                self.aux_done
                    .set(AUX_CTL_DONE | (1 << AUX_CTL_MSGSIZE_SHIFT));
                *self.aux_reply.borrow_mut() = alloc::vec![0x10];
                return;
            }
        }
        let reply = self.sink.borrow_mut().transact(&wire[..n.clamp(3, 20)]);
        self.aux_done
            .set(AUX_CTL_DONE | ((reply.len() as u32) << AUX_CTL_MSGSIZE_SHIFT));
        *self.aux_reply.borrow_mut() = reply;
    }
}

impl MmioWindow for ExtFake {
    fn display_access_ok(&self) -> bool {
        self.access.get()
    }
    fn read32(&self, off: u64) -> u32 {
        if !self.access.get() {
            return u32::MAX;
        }
        if (0..4).any(|p| off == 0x60544 + p * 0x1000) {
            let mut value = self.phy.read32(off);
            if self.phy.read32(off - 4) & (7 << 8) == 2 << 8 {
                value |= 1 << 25;
            }
            return value;
        }
        if off == PWR_WELL_CTL2 {
            let s = self.phy.read32(off);
            return s | ((s & 0xAAAA_AAAA) >> 1);
        }
        if off == CDCLK_PLL {
            // LOCK follows ENABLE; FREQ_REQ_ACK follows FREQ_REQ (crawl).
            let mut s = self.cdclk_pll.get();
            if s & ENABLE != 0 {
                s |= STATE;
            }
            if s & (1 << 23) != 0 {
                s |= 1 << 22;
            }
            return s;
        }
        if let Some(pipe) = conf_pipe(off) {
            let s = self.confs[pipe].get();
            return if s & ENABLE != 0 || self.pipeconf_stuck.get() {
                s | STATE
            } else {
                s
            };
        }
        if let Some(pipe) = frame_pipe(off) {
            if self.confs[pipe].get() & ENABLE != 0 {
                self.frames[pipe].set(self.frames[pipe].get().wrapping_add(1));
            }
            return self.frames[pipe].get();
        }
        if let Some(pipe) = surflive_pipe(off) {
            return if self.confs[pipe].get() & ENABLE != 0 {
                self.phy.read32(off - 0x10)
            } else {
                0
            };
        }
        if (0..4).any(|p| off == 0x7_0000 + p * 0x1000) {
            // PIPEDSL: line 0, outside every evasion window.
            self.irq_log
                .borrow_mut()
                .push((off, narf_arch::interrupts_enabled()));
            return 0;
        }
        if is_gmbus(off) {
            return self.ddc.read32(off);
        }
        if off == PICA_ISR {
            return self.pica_isr.get();
        }
        if off == SDE_ISR {
            return self.sde_isr.get();
        }
        if let Some(tc) = self.port.tc_index() {
            if off == tcss_ddi_status(tc) {
                let requested = self.phy.read32(self.port.buf_ctl1()) & TCSS_POWER_REQUEST != 0;
                return if requested && self.ready.get() {
                    TCSS_DDI_STATUS_READY
                } else {
                    0
                };
            }
            if off == port_tx_dflexpa1(tc) {
                return (self.pin.get() as u32) << pin_assignment_shift(tc);
            }
        }
        if off == self.port.aux_ctl() {
            let power = if self.aux_power.get() {
                XELPDP_AUX_CH_CTL_POWER_REQUEST
            } else {
                0
            };
            return self.aux_done.get() | power;
        }
        let data = self.port.aux_ctl() + 4;
        if (data..data + 20).contains(&off) {
            let idx = ((off - data) / 4) as usize;
            let reply = self.aux_reply.borrow();
            let mut v = 0u32;
            for b in 0..4 {
                v |= (reply.get(idx * 4 + b).copied().unwrap_or(0) as u32) << (24 - 8 * b);
            }
            return v;
        }
        self.phy.read32(off)
    }
    fn write32(&self, off: u64, value: u32) {
        if !self.access.get() {
            return;
        }
        self.writes.borrow_mut().push((off, value));
        if (0..4).any(|p| off == 0x60400 + p * 0x1000)
            && (self.phy.read32(off) ^ value) & (1 << 8) != 0
            && !self.act_stuck.get()
        {
            let master = (value >> 10) & 3;
            let status = 0x60544 + u64::from(master) * 0x1000;
            self.phy
                .write32(status, self.phy.read32(status) | (1 << 24));
        }
        if is_gmbus(off) {
            self.ddc.write32(off, value);
            return;
        }
        let mask = self.w1c(off);
        if mask != 0 {
            let old = self.phy.read32(off);
            self.phy
                .write32(off, (old & mask & !value) | (value & !mask));
            return;
        }
        if off == CDCLK_PLL {
            self.cdclk_pll.set(value & !(STATE | (1 << 22)));
            return;
        }
        if let Some(pipe) = conf_pipe(off) {
            self.confs[pipe].set(value & !STATE);
            return;
        }
        if (0..4).any(|p| off == PLANE_SURF_1_A + p * 0x1000) {
            self.irq_log
                .borrow_mut()
                .push((off, narf_arch::interrupts_enabled()));
        }
        if off == PMDEMAND_REQUEST1 {
            // The PM demand request completes at once.
            self.phy.write32(off, value & !ENABLE);
            return;
        }
        if [0x4_5008, 0x4_4FE8, 0x4_4300, 0x4_4304].contains(&off) {
            // DBUF_CTL_S(n): POWER_STATE follows POWER_REQUEST.
            self.phy
                .write32(off, (value & !STATE) | ((value >> 1) & STATE));
            return;
        }
        if off == self.port.aux_ctl() {
            self.aux_ctl_writes.borrow_mut().push(value);
            self.aux_power
                .set(value & XELPDP_AUX_CH_CTL_POWER_REQUEST != 0);
            if value & AUX_CTL_SEND_BUSY != 0 {
                self.aux_send(value);
            }
            return;
        }
        let data = self.port.aux_ctl() + 4;
        if (data..data + 20).contains(&off) {
            self.aux_data.borrow_mut()[((off - data) / 4) as usize] = value;
            return;
        }
        self.phy.write32(off, value);
    }
}

fn fb_for(mode: &Mode) -> Option<Framebuffer> {
    Some(Framebuffer {
        phys_addr: 0x100_0000,
        stride_bytes: (u32::from(mode.h_active) * 4).next_multiple_of(64),
        format: PixelFormat::Xrgb8888,
    })
}

fn live_route(io: &ExtFake, port: XeLpgPort) -> Result<MtlExternalRoute, &'static str> {
    let probe =
        probe_sink(io, Generation::MeteorLake, port, false).map_err(|_| "probe must succeed")?;
    let fb = fb_for(&probe.mode).unwrap();
    match activate(io, probe, fb, &MtlDisplay::NONE) {
        Ok(route) if route.state() == RouteState::Live => Ok(route),
        _ => Err("activation must produce a live route"),
    }
}

struct NoAccess;
impl MmioWindow for NoAccess {
    fn read32(&self, _: u64) -> u32 {
        panic!("refused route read a register");
    }
    fn write32(&self, _: u64, _: u32) {
        panic!("refused route wrote a register");
    }
}

fn smoke_mtl_external_tc_dp_alt_full_route() -> TestResult {
    let io = ExtFake::new(XeLpgPort::Tc2, Sink::new(0x14, edid_1024()));
    let route = match live_route(&io, XeLpgPort::Tc2) {
        Ok(route) => route,
        Err(e) => return TestResult::Fail(e),
    };
    if route.probe.mode.h_active != 1024
        || route.trained.lanes != 4
        || route.trained.rate != TrainRate::Rbr
        || route.probe.tc.map(|c| c.mode) != Some(TcMode::DpAlt)
    {
        return TestResult::Fail("route must train the negotiated RBR x4 DP-alt link");
    }
    // Type-C ownership and AUX power held for the live route.
    let buf = io.read32(XeLpgPort::Tc2.buf_ctl1());
    if buf & (TCSS_POWER_REQUEST | TC_PHY_OWNERSHIP) != TCSS_POWER_REQUEST | TC_PHY_OWNERSHIP {
        return TestResult::Fail("live TC route must own the PHY with TCSS power");
    }
    let aux = io.aux_ctl_writes.borrow();
    if aux.is_empty()
        || aux
            .iter()
            .any(|w| w & XELPDP_AUX_CH_CTL_POWER_REQUEST == 0 || w & AUX_CTL_TBT_IO != 0)
    {
        return TestResult::Fail("AUX writes must keep power and never select TBT IO");
    }
    drop(aux);
    // The route runs on Pipe B (not Pipe A, which stays the panel's): PW_1,
    // PW_2 (pipes B–D and the TC DDI lanes) and PW_B.
    if route.pipe() != Pipe::B || !route.reserved() {
        return TestResult::Fail("the route must hold a Pipe B reservation");
    }
    let wells = io.read32(PWR_WELL_CTL2);
    for idx in [PW_1_IDX, PW_2_IDX, pipe_well(Pipe::B)] {
        if wells & pwr_well_req(idx) == 0 {
            return TestResult::Fail("PW_1/PW_2/PW_B must be requested");
        }
    }
    for off in [
        PIPECONF_A,
        PLANE_CTL_1_A,
        TRANS_DDI_FUNC_CTL_A,
        TRANS_CLK_SEL_A,
    ] {
        if !io.writes_to(off).is_empty() {
            return TestResult::Fail("the external route must never program Pipe A");
        }
    }
    // Source port/PHY numbering: PHY_G for TC2, PORT_TC2 = 4.
    if io.writes_to(TRANS_CLK_SEL_B).first() != Some(&0x7000_0000) {
        return TestResult::Fail("TRANS_CLK_SEL must select PHY_G for TC2");
    }
    let func = io.writes_to(TRANS_DDI_FUNC_CTL_B);
    let want = crate::intel_gpu_pipes::build_trans_ddi_func_ctl(
        4,
        crate::intel_gpu_pipes::TRANS_DDI_MODE_DP_SST,
        4,
    );
    if func.first() != Some(&(want & !TRANS_DDI_FUNC_ENABLE))
        || func.last() != Some(&want)
        || (want >> 27) & 0xF != 5
    {
        return TestResult::Fail("TRANS_DDI_FUNC_CTL must select PORT_TC2, enabled last");
    }
    if io.read32(0x6_4400) != DDI_BUF_CTL_ENABLE | (3 << 1) {
        return TestResult::Fail("DDI_CTL_DE(TC2) must be enabled at four lanes");
    }
    if io.phy.writes_to(0x6_4430) != [162_000] {
        return TestResult::Fail("DDI_CLK_VALFREQ(TC2) must carry the RBR port clock");
    }
    let tp = io.writes_to(DP_TP_CTL_B);
    if tp.first() != Some(&(DP_TP_CTL_ENABLE | DP_TP_CTL_ENHANCED_FRAME))
        || tp.last()
            != Some(&(DP_TP_CTL_ENABLE | DP_TP_CTL_ENHANCED_FRAME | DP_TP_CTL_LINK_TRAIN_NORMAL))
    {
        return TestResult::Fail("DP_TP_CTL must run TPS1 then NORMAL with enhanced framing");
    }
    // DDI A and Gen12 DPLL/DPCLKA registers are never touched.
    for off in [
        0x6_4000u64,
        0x6_4040,
        0x6_40E0,
        0x16_4280,
        0x16_4284,
        0x4_6010,
    ] {
        if !io.writes_to(off).is_empty() || !io.phy.writes_to(off).is_empty() {
            return TestResult::Fail("external TC route touched DDI A or a Gen12 register");
        }
    }
    // Sink powered to D0 by training.
    if io.sink.borrow().power_log.first() != Some(&1) {
        return TestResult::Fail("sink must be set to D0 before training");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_tc_dp_alt_full_route
);

fn smoke_mtl_external_ddi_b_route_stop_and_release() -> TestResult {
    let io = ExtFake::new(XeLpgPort::B, Sink::new(0x14, edid_1024()));
    let mut route = match live_route(&io, XeLpgPort::B) {
        Ok(route) => route,
        Err(e) => return TestResult::Fail(e),
    };
    if route.probe.tc.is_some() || io.writes_to(TRANS_CLK_SEL_B).first() != Some(&0x2000_0000) {
        return TestResult::Fail("DDI B route must use PHY_B without Type-C ownership");
    }
    // Pipe B needs PW_2 even on DDI B: on Xe-LPDP it carries pipes and
    // transcoders B–D (XELPDP_PW_2_POWER_DOMAINS), not only the TC lanes.
    // Pipe A's well is the panel's and is not requested by the route.
    let wells = io.read32(PWR_WELL_CTL2);
    if wells & pwr_well_req(PW_2_IDX) == 0
        || wells & pwr_well_req(pipe_well(Pipe::B)) == 0
        || wells & pwr_well_req(PW_A_IDX) != 0
    {
        return TestResult::Fail("DDI B on Pipe B must request PW_2 and PW_B, not PW_A");
    }
    if route.stop(&io).is_err() || route.state() != RouteState::Stopped || route.reserved() {
        return TestResult::Fail("local stop must be proven and release the pipe");
    }
    let port = XeLpgPort::B;
    if io.read32(PIPECONF_B) & (ENABLE | STATE) != 0
        || io.read32(port.ddi_buf_ctl()) & DDI_BUF_CTL_ENABLE != 0
        || io.read32(port.buf_ctl1()) & PORT_BUF_PHY_IDLE == 0
        || io.read32(port.port_clock_ctl()) & 0xCC00_0000 != 0
        || io.read32(TRANS_CLK_SEL_B) != 0
        || io.read32(TRANS_DDI_FUNC_CTL_B) & (TRANS_DDI_FUNC_ENABLE | TRANS_DDI_PORT_AND_MODE) != 0
        || io.read32(DP_TP_CTL_B) & DP_TP_CTL_ENABLE != 0
    {
        return TestResult::Fail("stop must leave pipe, DDI, PLL, clock and transport off");
    }
    if io.phy.writes_to(0x6_4130).last() != Some(&0) {
        return TestResult::Fail("complete PLL disable must zero DDI_CLK_VALFREQ(B)");
    }
    if io.sink.borrow().power_log.last() != Some(&DP_SET_POWER_D3) {
        return TestResult::Fail("sink must be put to D3 during stop");
    }
    // Stop ordering: plane off before pipe off before DDI off.
    let writes = io.writes.borrow();
    let last_plane_off = writes
        .iter()
        .rposition(|&(o, v)| o == PLANE_CTL_1_B && v & ENABLE == 0);
    let pipe_off = writes
        .iter()
        .rposition(|&(o, v)| o == PIPECONF_B && v & ENABLE == 0);
    let ddi_off = writes
        .iter()
        .rposition(|&(o, v)| o == port.ddi_buf_ctl() && v & DDI_BUF_CTL_ENABLE == 0);
    match (last_plane_off, pipe_off, ddi_off) {
        (Some(a), Some(b), Some(c)) if a < b && b < c => {}
        _ => return TestResult::Fail("stop order must be plane, pipe, then DDI"),
    }
    drop(writes);
    if route.release(&io).is_err() || io.aux_power.get() {
        return TestResult::Fail("release must drop the AUX power request");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_ddi_b_route_stop_and_release
);

fn smoke_mtl_external_refuses_busy_pipe_or_port_before_programming() -> TestResult {
    for (busy_pipe, label) in [(true, "pipe"), (false, "port")] {
        let io = ExtFake::new(XeLpgPort::Tc1, Sink::new(0x14, edid_1024()));
        let probe = match probe_sink(&io, Generation::MeteorLake, XeLpgPort::Tc1, false) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("probe must succeed"),
        };
        if busy_pipe {
            io.set_conf(0, ENABLE);
        } else {
            io.phy
                .write32(XeLpgPort::Tc1.ddi_buf_ctl(), DDI_BUF_CTL_ENABLE);
        }
        let before = io.writes.borrow().len();
        let fb = fb_for(&probe.mode).unwrap();
        let probe = match activate(&io, probe, fb, &MtlDisplay::NONE) {
            Err(ActivateError::Refused(probe, ExternalError::PipeBusy)) if busy_pipe => probe,
            Err(ActivateError::Refused(probe, ExternalError::PortBusy)) if !busy_pipe => probe,
            _ => {
                let _ = label;
                return TestResult::Fail("busy pipe/port must refuse before programming");
            }
        };
        if io.writes.borrow().len() != before {
            return TestResult::Fail("refusal must not write any register");
        }
        if release_probe(&io, &probe).is_err()
            || io.read32(XeLpgPort::Tc1.buf_ctl1()) & (TC_PHY_OWNERSHIP | TCSS_POWER_REQUEST) != 0
        {
            return TestResult::Fail("refused probe must release Type-C ownership");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_refuses_busy_pipe_or_port_before_programming
);

fn smoke_mtl_external_lane_fallback_retries_at_trained_width() -> TestResult {
    let mut sink = Sink::new(0x14, edid_1024());
    sink.max_good_lanes = 2;
    let io = ExtFake::new(XeLpgPort::Tc3, sink);
    let route = match live_route(&io, XeLpgPort::Tc3) {
        Ok(route) => route,
        Err(e) => return TestResult::Fail(e),
    };
    if route.trained.lanes != 2 || route.trained.rate != TrainRate::Rbr {
        return TestResult::Fail("fallback must settle at RBR x2");
    }
    // Retune the source at the fallback width during CR, then restage
    // the stream through a full stop/retry at the trained configuration.
    if io.phy.writes_to(0x6_4530) != [162_000, 0, 162_000, 0, 162_000] {
        return TestResult::Fail("retry must stop and re-enable the PLL");
    }
    let want = crate::intel_gpu_pipes::build_trans_ddi_func_ctl(
        5,
        crate::intel_gpu_pipes::TRANS_DDI_MODE_DP_SST,
        2,
    );
    if io.read32(TRANS_DDI_FUNC_CTL_B) != want
        || io.read32(XeLpgPort::Tc3.ddi_buf_ctl()) != DDI_BUF_CTL_ENABLE | (1 << 1)
    {
        return TestResult::Fail("retry must program a two-lane function and DDI width");
    }
    // A fallback that cannot carry the stream refuses (no DSC).
    let mut narrow = Sink::new(0x0A, edid_1080());
    narrow.max_good_lanes = 1;
    let io = ExtFake::new(XeLpgPort::Tc3, narrow);
    let probe = match probe_sink(&io, Generation::MeteorLake, XeLpgPort::Tc3, false) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("1080p probe must succeed"),
    };
    let fb = fb_for(&probe.mode).unwrap();
    match activate(&io, probe, fb, &MtlDisplay::NONE) {
        Err(ActivateError::Failed(route, ExternalError::OverBudget { .. }))
            if route.state() == RouteState::Stopped =>
        {
            if route.release(&io).is_err() {
                return TestResult::Fail("stopped over-budget route must release");
            }
        }
        _ => return TestResult::Fail("over-budget fallback must refuse with a stopped route"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_lane_fallback_retries_at_trained_width
);

fn smoke_mtl_external_refusals_before_mmio_and_tbt() -> TestResult {
    if probe_sink(&NoAccess, Generation::TigerLake, XeLpgPort::Tc1, false).err()
        != Some(ExternalError::UnsupportedGeneration)
        || probe_sink(&NoAccess, Generation::MeteorLake, XeLpgPort::A, false).err()
            != Some(ExternalError::UnsupportedPort)
    {
        return TestResult::Fail("generation/port refusals must precede MMIO");
    }
    let io = ExtFake::new(XeLpgPort::Tc4, Sink::new(0x14, edid_1024()));
    io.pica_isr.set(pica_tbt_hotplug(3));
    let mut service = MtlExternalService::new();
    let event = MtlHpdEvent {
        pin: MtlHpdPin::Tc4,
        kind: MtlHpdKind::Connected(LiveMode::TbtAlt),
    };
    let outcome = service.handle(&io, event, &mut fb_for);
    if !matches!(outcome, ServiceOutcome::Activated { .. }) {
        use core::fmt::Write as _;
        let _ = writeln!(narf_console::Writer, "TBT activation: {outcome:?}");
        return TestResult::Fail("live TBT route must activate through the fabric clock");
    }
    let port = XeLpgPort::Tc4;
    if io.phy.writes.borrow().iter().any(|(off, _)| {
        (*off >= port.msgbus_ctl_ln0() && *off < port.msgbus_ctl_ln0() + 0x20)
            || *off == port.buf_ctl2()
    }) || io.phy.read32(port.buf_ctl1()) & TC_PHY_OWNERSHIP != 0
        || !io
            .aux_ctl_writes
            .borrow()
            .iter()
            .any(|v| v & AUX_CTL_TBT_IO != 0)
    {
        return TestResult::Fail("TBT must select tunnelled AUX and leave the C20 PHY alone");
    }
    if !service.teardown(&io) {
        return TestResult::Fail("TBT route must stop before releasing AUX");
    }
    if service_mtl_external(
        &NoAccess,
        Generation::AlderLake,
        &MtlDisplay::NONE,
        &mut fb_for,
    )
    .is_some()
        || !teardown_mtl_external(&NoAccess, Generation::TigerLake)
    {
        return TestResult::Fail("non-MTL process entries must not touch registers");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_refusals_before_mmio_and_tbt
);

fn smoke_mtl_external_probe_failures_roll_back_type_c() -> TestResult {
    // No EDID EEPROM data: parse failure after TC connect + AUX power.
    let io = ExtFake::new(XeLpgPort::Tc1, Sink::new(0x14, Vec::new()));
    if !matches!(
        probe_sink(&io, Generation::MeteorLake, XeLpgPort::Tc1, false),
        Err(ExternalError::Edid(_))
    ) {
        return TestResult::Fail("unreadable EDID must refuse with Edid");
    }
    if io.read32(XeLpgPort::Tc1.buf_ctl1()) & (TC_PHY_OWNERSHIP | TCSS_POWER_REQUEST) != 0
        || io.aux_power.get()
    {
        return TestResult::Fail("probe failure must release ownership and AUX power");
    }
    // The IOM never hands the PHY over: no AUX power is requested.
    let io = ExtFake::new(XeLpgPort::Tc1, Sink::new(0x14, edid_1024()));
    io.ready.set(false);
    if probe_sink(&io, Generation::MeteorLake, XeLpgPort::Tc1, false).err()
        != Some(ExternalError::Tc(TcError::PhyNotReady))
        || !io.aux_ctl_writes.borrow().is_empty()
    {
        return TestResult::Fail("unready PHY must refuse before AUX power");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_probe_failures_roll_back_type_c
);

fn smoke_mtl_external_unplug_mid_activation_and_failed_stop() -> TestResult {
    // The sink vanishes between probe and training: activation fails,
    // the local stop is still proven and the route releases.
    let io = ExtFake::new(XeLpgPort::Tc2, Sink::new(0x14, edid_1024()));
    let probe = match probe_sink(&io, Generation::MeteorLake, XeLpgPort::Tc2, false) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("probe must succeed"),
    };
    io.sink.borrow_mut().nack_all = true;
    let fb = fb_for(&probe.mode).unwrap();
    match activate(&io, probe, fb, &MtlDisplay::NONE) {
        Err(ActivateError::Failed(route, ExternalError::Link(_)))
            if route.state() == RouteState::Stopped =>
        {
            if route.release(&io).is_err()
                || io.read32(XeLpgPort::Tc2.buf_ctl1()) & TC_PHY_OWNERSHIP != 0
            {
                return TestResult::Fail("stopped route must release Type-C ownership");
            }
        }
        _ => return TestResult::Fail("training loss must fail with a stopped route"),
    }
    // A stop that never observes the transcoder off quarantines the route;
    // release refuses and every lease stays owned.
    let io = ExtFake::new(XeLpgPort::Tc2, Sink::new(0x14, edid_1024()));
    let mut route = match live_route(&io, XeLpgPort::Tc2) {
        Ok(route) => route,
        Err(e) => return TestResult::Fail(e),
    };
    io.pipeconf_stuck.set(true);
    if route.stop(&io).is_ok() || route.state() != RouteState::Quarantined {
        return TestResult::Fail("unobserved transcoder stop must quarantine");
    }
    let mut route = match route.release(&io) {
        Err((route, ExternalError::Quarantined)) => route,
        _ => return TestResult::Fail("quarantined route must refuse release"),
    };
    if route.stop(&io) != Err(ExternalError::Quarantined)
        || io.read32(XeLpgPort::Tc2.buf_ctl1()) & TC_PHY_OWNERSHIP == 0
    {
        return TestResult::Fail("quarantine must retain Type-C ownership");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_unplug_mid_activation_and_failed_stop
);

fn smoke_mtl_external_service_hotplug_lifecycle() -> TestResult {
    let io = ExtFake::new(XeLpgPort::Tc1, Sink::new(0x14, edid_1024()));
    let mut monitor = MtlHpdMonitor::new(MtlHpdConfig::TYPE_C);
    let mut service = MtlExternalService::new();
    // Initial detection publishes the DP-alt sink; the service lights it.
    let event = match monitor.poll(&io) {
        Some(event) => event,
        None => return TestResult::Fail("live DP-alt sink must be detected"),
    };
    match service.handle(&io, event, &mut fb_for) {
        ServiceOutcome::Activated {
            port: XeLpgPort::Tc1,
            mode,
            ..
        } if mode.h_active == 1024 => {}
        _ => return TestResult::Fail("connect event must activate the TC1 route"),
    }
    // IRQ_HPD with an intact link changes nothing.
    io.phy
        .write32(port_hotplug_ctl(0), io.phy.read32(port_hotplug_ctl(0)) | 1);
    match monitor.poll(&io) {
        Some(event) if event.kind == MtlHpdKind::ShortPulse => {
            if !matches!(
                service.handle(&io, event, &mut fb_for),
                ServiceOutcome::Unchanged
            ) {
                return TestResult::Fail("healthy short pulse must not retrain");
            }
        }
        _ => return TestResult::Fail("short pulse must be reported"),
    }
    // IRQ_HPD after the sink lost lock: stop and re-activate in place.
    io.sink.borrow_mut().drop_lock();
    io.phy
        .write32(port_hotplug_ctl(0), io.phy.read32(port_hotplug_ctl(0)) | 1);
    match monitor.poll(&io) {
        Some(event) => {
            if !matches!(
                service.handle(&io, event, &mut fb_for),
                ServiceOutcome::Activated { .. }
            ) || service.route().map(MtlRoute::live) != Some(true)
            {
                return TestResult::Fail("lost link must retrain to a live route");
            }
        }
        None => return TestResult::Fail("second short pulse must be reported"),
    }
    // Unplug: long pulse with the level low withdraws and releases.
    io.pica_isr.set(0);
    io.phy.write32(
        port_hotplug_ctl(0),
        io.phy.read32(port_hotplug_ctl(0)) | DP_ALT_HPD_LONG_DETECT,
    );
    match monitor.poll(&io) {
        Some(event) if event.kind == MtlHpdKind::Disconnected => {
            if !matches!(
                service.handle(&io, event, &mut fb_for),
                ServiceOutcome::Withdrawn {
                    port: XeLpgPort::Tc1
                }
            ) {
                return TestResult::Fail("disconnect must withdraw the route");
            }
        }
        _ => return TestResult::Fail("unplug must be reported"),
    }
    if service.route().is_some()
        || io.read32(XeLpgPort::Tc1.buf_ctl1()) & (TC_PHY_OWNERSHIP | TCSS_POWER_REQUEST) != 0
        || io.aux_power.get()
    {
        return TestResult::Fail("withdrawal must release Type-C ownership and AUX power");
    }
    // Reset/suspend teardown with nothing owned is complete.
    if !service.teardown(&io) || !monitor.teardown(&io) {
        return TestResult::Fail("teardown must report a complete withdrawal");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_service_hotplug_lifecycle
);

// ── DC-state join: the real pass bracket over the display-14 DC core ─────

/// One `DcUser::External` reference taken on `core` and released at `now`
/// on drop, as the DC service's `DcRef` does; the release deadline is kept.
struct DcPass<'a> {
    core: &'a narf_lib::sync::IrqSafeSpinLock<crate::intel_gpu_dc_states::DcCore>,
    now: u64,
    released: &'a Cell<Option<u64>>,
}

impl Drop for DcPass<'_> {
    fn drop(&mut self) {
        let due = self
            .core
            .lock()
            .put(crate::intel_gpu_dc_states::DcUser::External, self.now);
        self.released.set(due);
    }
}

/// The DC core on the same register model as the route, past probe with
/// the MTL DMC program loaded and DC6 entered.
fn dc6_core(
    io: &impl MmioWindow,
) -> Option<narf_lib::sync::IrqSafeSpinLock<crate::intel_gpu_dc_states::DcCore>> {
    use crate::intel_gpu_dc_states::{
        publication_step, ArmGates, DcCore, DcUser, DC_STATE_EN_UPTO_DC6, XELPDP_ALLOWED_DC_MASK,
    };
    let core = narf_lib::sync::IrqSafeSpinLock::new(DcCore::new(XELPDP_ALLOWED_DC_MASK));
    {
        let mut c = core.lock();
        c.sanitize(io).ok()?;
        c.get(io, DcUser::Init).ok()?;
    }
    let due = publication_step(&core, io, 0, crate::intel_gpu_dc_states::tests::firmware)?;
    let armed = core.lock().arm_if_due(io, due, ArmGates::default());
    (armed == Ok(DC_STATE_EN_UPTO_DC6)).then_some(core)
}

/// Drops every `DC_STATE_EN` write: a DC exit that never sticks.
struct DcNeverSticks<'a>(&'a ExtFake);

impl MmioWindow for DcNeverSticks<'_> {
    fn display_access_ok(&self) -> bool {
        self.0.display_access_ok()
    }
    fn read32(&self, off: u64) -> u32 {
        self.0.read32(off)
    }
    fn write32(&self, off: u64, value: u32) {
        if off != crate::intel_gpu_dmc::DC_STATE_EN {
            self.0.write32(off, value);
        }
    }
}

fn smoke_mtl_external_dc_off_join_brackets_passes_and_blocks_dc6_while_live() -> TestResult {
    use crate::intel_gpu_dc_states::{
        ArmBlock, ArmGates, DcUser, DC_REENABLE_DELAY_NS, DC_STATE_EN_UPTO_DC6,
    };
    use crate::intel_gpu_dmc::DC_STATE_EN;
    const MS: u64 = 1_000_000;
    let io = ExtFake::new(XeLpgPort::Tc1, Sink::new(0x14, edid_1024()));
    let Some(core) = dc6_core(&io) else {
        return TestResult::Fail("the DC core must load the program and enter DC6");
    };
    let released = Cell::new(None);
    let pass = |now: u64| {
        let (core, io, released) = (&core, &io, &released);
        move || {
            core.lock().get(io, DcUser::External).map(|()| DcPass {
                core,
                now,
                released,
            })
        }
    };
    let gates = |service: &MtlExternalService| ArmGates {
        external_route_active: service_blocks_dc(service),
    };
    let mut monitor = MtlHpdMonitor::new(MtlHpdConfig::TYPE_C);
    let mut service = MtlExternalService::new();

    // Plug-in: the hotplug pass exits DC6 before its first register write,
    // then the service pass lights the route.
    io.writes.borrow_mut().clear();
    let Ok(Some(event)) = pass_bracket(pass(10 * MS), || monitor.poll(&io)) else {
        return TestResult::Fail("the DP-alt sink must be detected inside a pass");
    };
    if io.writes.borrow().first() != Some(&(DC_STATE_EN, 0)) {
        return TestResult::Fail("DC exit must precede the pass's first register write");
    }
    match pass_bracket(pass(20 * MS), || service.handle(&io, event, &mut fb_for)) {
        Ok(ServiceOutcome::Activated {
            port: XeLpgPort::Tc1,
            ..
        }) => {}
        _ => return TestResult::Fail("the connect pass must activate the TC1 route"),
    }
    let Some(due) = released.get() else {
        return TestResult::Fail("the last pass reference must schedule re-entry");
    };
    // Between passes the live route refuses re-entry and writes nothing.
    let before = io.writes.borrow().len();
    if core.lock().arm_if_due(&io, due, gates(&service)) != Err(ArmBlock::ExternalRoute)
        || io.writes.borrow().len() != before
    {
        return TestResult::Fail("a live external route must refuse DC6 without a write");
    }

    // Unplug: the stop pass withdraws the route; DC6 re-enters 17 ms after
    // that pass releases, not before.
    io.pica_isr.set(0);
    io.phy.write32(
        port_hotplug_ctl(0),
        io.phy.read32(port_hotplug_ctl(0)) | DP_ALT_HPD_LONG_DETECT,
    );
    let event = match pass_bracket(pass(30 * MS), || monitor.poll(&io)) {
        Ok(Some(event)) if event.kind == MtlHpdKind::Disconnected => event,
        _ => return TestResult::Fail("the unplug must be reported inside a pass"),
    };
    match pass_bracket(pass(40 * MS), || service.handle(&io, event, &mut fb_for)) {
        Ok(ServiceOutcome::Withdrawn {
            port: XeLpgPort::Tc1,
        }) => {}
        _ => return TestResult::Fail("the disconnect pass must withdraw the route"),
    }
    let stopped = 40 * MS + DC_REENABLE_DELAY_NS;
    if released.get() != Some(stopped)
        || core.lock().arm_if_due(&io, stopped - 1, gates(&service))
            != Err(ArmBlock::NotDue(stopped))
        || core.lock().arm_if_due(&io, stopped, gates(&service)) != Ok(DC_STATE_EN_UPTO_DC6)
    {
        return TestResult::Fail("DC6 must re-enter 17 ms after the verified stop");
    }
    if !service.teardown(&io) || !monitor.teardown(&io) {
        return TestResult::Fail("teardown must report a complete withdrawal");
    }

    // A quarantined route keeps DC6 refused.
    let io = ExtFake::new(XeLpgPort::Tc1, Sink::new(0x14, edid_1024()));
    let Some(core) = dc6_core(&io) else {
        return TestResult::Fail("the second DC core must enter DC6");
    };
    let pass = |now: u64| {
        let (core, io, released) = (&core, &io, &released);
        move || {
            core.lock().get(io, DcUser::External).map(|()| DcPass {
                core,
                now,
                released,
            })
        }
    };
    let mut monitor = MtlHpdMonitor::new(MtlHpdConfig::TYPE_C);
    let mut service = MtlExternalService::new();
    let Ok(Some(event)) = pass_bracket(pass(10 * MS), || monitor.poll(&io)) else {
        return TestResult::Fail("the second sink must be detected");
    };
    if !matches!(
        pass_bracket(pass(20 * MS), || service.handle(&io, event, &mut fb_for)),
        Ok(ServiceOutcome::Activated { .. })
    ) {
        return TestResult::Fail("the second route must activate");
    }
    io.pipeconf_stuck.set(true);
    io.pica_isr.set(0);
    io.phy.write32(
        port_hotplug_ctl(0),
        io.phy.read32(port_hotplug_ctl(0)) | DP_ALT_HPD_LONG_DETECT,
    );
    let Ok(Some(event)) = pass_bracket(pass(30 * MS), || monitor.poll(&io)) else {
        return TestResult::Fail("the second unplug must be reported");
    };
    if !matches!(
        pass_bracket(pass(40 * MS), || service.handle(&io, event, &mut fb_for)),
        Ok(ServiceOutcome::Retained { .. })
    ) || !service
        .route()
        .is_some_and(|route| !route.live() && !route.stopped())
    {
        return TestResult::Fail("an unobserved stop must quarantine the route");
    }
    let Some(due) = released.get() else {
        return TestResult::Fail("the quarantining pass must release its reference");
    };
    if core.lock().arm_if_due(&io, due, gates(&service)) != Err(ArmBlock::ExternalRoute) {
        return TestResult::Fail("a quarantined route must keep DC6 refused");
    }

    // A DC exit that never sticks refuses the pass before it runs: no route
    // register is touched.
    let io = ExtFake::new(XeLpgPort::Tc1, Sink::new(0x14, edid_1024()));
    let Some(core) = dc6_core(&io) else {
        return TestResult::Fail("the third DC core must enter DC6");
    };
    let stuck = DcNeverSticks(&io);
    io.writes.borrow_mut().clear();
    let mut ran = false;
    let refused = pass_bracket(
        || {
            core.lock().get(&stuck, DcUser::External).map(|()| DcPass {
                core: &core,
                now: 10 * MS,
                released: &released,
            })
        },
        || ran = true,
    );
    if refused.is_ok() || ran || !io.writes.borrow().is_empty() {
        return TestResult::Fail("a failed DC exit must refuse the pass and touch nothing");
    }

    // Production wiring with no display-14 DC service (this kernel): the
    // bracket is inert, and the registered predicate reads an idle service.
    let previous =
        crate::intel_gpu_dc_states::register_external_live(Some(external_route_blocks_dc));
    let live = crate::intel_gpu_dc_states::external_live();
    let _ = crate::intel_gpu_dc_states::register_external_live(previous);
    if live || with_dc_off(|| 7) != Ok(7) {
        return TestResult::Fail("an idle service must not block DC and the bracket must run");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_dc_off_join_brackets_passes_and_blocks_dc6_while_live
);

// ── DP/HDMI selection (item: HDMI in the hotplug service) ───────────

/// DDI B with no DPCD (every AUX request NACKs) and an HDMI sink on DDC
/// pin 2 (`gmbus_pins_mtp` "dpb").
pub fn hdmi_on_ddi_b(edid: Vec<u8>) -> ExtFake {
    let mut sink = Sink::new(0x14, Vec::new());
    sink.nack_all = true;
    let mut io = ExtFake::new(XeLpgPort::B, sink);
    io.ddc = FakeGmbus::with_edid(&edid);
    io.ddc.set_pin(2);
    io
}

fn ddi_b_event(kind: MtlHpdKind) -> MtlHpdEvent {
    MtlHpdEvent {
        pin: MtlHpdPin::DdiB,
        kind,
    }
}

fn smoke_mtl_external_route_plan_policy_decisions() -> TestResult {
    use LiveMode::{DpAlt, Legacy, Native, TbtAlt};
    let p = MtlPortPolicy::NO_VBT;
    let cases = [
        (
            XeLpgPort::B,
            p.decl(XeLpgPort::B),
            Native,
            RoutePlan::DpThenHdmi,
        ),
        (XeLpgPort::Tc1, p.decl(XeLpgPort::Tc1), DpAlt, RoutePlan::Dp),
        // No legacy Type-C port is declared without a VBT.
        (
            XeLpgPort::Tc2,
            p.decl(XeLpgPort::Tc2),
            Legacy,
            RoutePlan::Refuse,
        ),
        (
            XeLpgPort::Tc3,
            p.decl(XeLpgPort::Tc3),
            TbtAlt,
            RoutePlan::Dp,
        ),
        (
            XeLpgPort::A,
            p.decl(XeLpgPort::A),
            Native,
            RoutePlan::Refuse,
        ),
        // A declared legacy HDMI connector: HDMI only, never over DP-alt.
        (
            XeLpgPort::Tc4,
            MtlPortDecl::LEGACY_HDMI,
            Legacy,
            RoutePlan::Hdmi,
        ),
        (
            XeLpgPort::Tc4,
            MtlPortDecl::LEGACY_HDMI,
            DpAlt,
            RoutePlan::Refuse,
        ),
        (
            XeLpgPort::Tc1,
            MtlPortDecl {
                lane_reversal: false,
                dp: true,
                hdmi: true,
                legacy: true,
                ddc_pin: None,
            },
            Legacy,
            RoutePlan::DpThenHdmi,
        ),
        // DP + HDMI declared on a USB-C port: DP-alt carries DP only.
        (
            XeLpgPort::Tc1,
            MtlPortDecl::COMBO_DP_HDMI,
            DpAlt,
            RoutePlan::Dp,
        ),
        // A DP-only DDI B never tries HDMI.
        (XeLpgPort::B, MtlPortDecl::USB_C, Native, RoutePlan::Dp),
    ];
    for (port, decl, live, want) in cases {
        if route_plan(port, decl, live) != want {
            return TestResult::Fail("route plan differs from the declared policy");
        }
    }
    // intel_ddi_init: non-legacy + HDMI without DP is legacy.
    let hdmi_only = MtlPortDecl {
        lane_reversal: false,
        dp: false,
        hdmi: true,
        legacy: false,
        ddc_pin: None,
    };
    if !hdmi_only.legacy_effective() || MtlPortDecl::COMBO_DP_HDMI.legacy_effective() {
        return TestResult::Fail("effective legacy flag must follow intel_ddi_init");
    }
    // The process-wide service and hotplug owner agree on legacy pins.
    if MtlPortPolicy::NO_VBT.hpd_config() != MtlHpdConfig::TYPE_C
        || MtlExternalService::new().policy() != MtlPortPolicy::NO_VBT
    {
        return TestResult::Fail("no-VBT policy must match the TYPE_C hotplug config");
    }
    let mut legacy = MtlPortPolicy::NO_VBT;
    legacy.tc[2] = MtlPortDecl::LEGACY_HDMI;
    if legacy.hpd_config().legacy_tc != [false, false, true, false] {
        return TestResult::Fail("a legacy declaration must own its SDE TC source");
    }
    // Only a DPCD that never answered lets HDMI be tried.
    if !dpcd_absent(&ExternalError::Link(LinkError::AuxFailure(
        crate::dp_aux::AuxError::Nacked,
    ))) || dpcd_absent(&ExternalError::Edid(EdidReadError::Aux(
        crate::dp_aux::AuxError::Nacked,
    ))) || dpcd_absent(&ExternalError::OverBudget {
        demand_kbps: 2,
        payload_kbps: 1,
    }) || dpcd_absent(&ExternalError::Tc(TcError::PhyNotReady))
    {
        return TestResult::Fail("HDMI fallback must need an absent DPCD");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_route_plan_policy_decisions
);

fn smoke_mtl_external_service_ddi_b_hdmi_lifecycle() -> TestResult {
    let io = hdmi_on_ddi_b(edid_1024());
    let mut monitor = MtlHpdMonitor::new(MtlHpdConfig::TYPE_C);
    let mut service = MtlExternalService::new();
    let event = match monitor.poll(&io) {
        Some(event) if event == ddi_b_event(MtlHpdKind::Connected(LiveMode::Native)) => event,
        _ => return TestResult::Fail("live DDI B sink must be detected"),
    };
    match service.handle(&io, event, &mut fb_for) {
        ServiceOutcome::Activated {
            port: XeLpgPort::B,
            protocol: MtlProtocol::Hdmi,
            mode,
            ..
        } if mode.h_active == 1024 => {}
        _ => return TestResult::Fail("DDI B without DPCD must light the HDMI route"),
    }
    // The DP attempt released its AUX power; HDMI owns Pipe B on DDI B.
    let func = crate::intel_gpu_pipes::build_trans_ddi_func_ctl_hdmi(1, false, false);
    if io.aux_power.get()
        || io.read32(TRANS_DDI_FUNC_CTL_B) != func
        || io.read32(XeLpgPort::B.ddi_buf_ctl()) & DDI_BUF_CTL_ENABLE == 0
        || service.route().map(MtlRoute::protocol) != Some(MtlProtocol::Hdmi)
        || service.route().map(MtlRoute::live) != Some(true)
        || !io.writes_to(DP_TP_CTL_B).is_empty()
    {
        return TestResult::Fail("HDMI route must own DDI B in TMDS mode without DP state");
    }
    // HDMI has no IRQ_HPD; a short pulse changes nothing.
    if !matches!(
        service.handle(&io, ddi_b_event(MtlHpdKind::ShortPulse), &mut fb_for),
        ServiceOutcome::Unchanged
    ) || service.route().map(MtlRoute::live) != Some(true)
    {
        return TestResult::Fail("short pulse must not disturb an HDMI route");
    }
    // A long pulse that stays connected re-runs detection: stop, release,
    // and the same HDMI decision again.
    match service.handle(&io, ddi_b_event(MtlHpdKind::Redetect), &mut fb_for) {
        ServiceOutcome::Activated {
            protocol: MtlProtocol::Hdmi,
            ..
        } => {}
        _ => return TestResult::Fail("redetect must re-light the HDMI route"),
    }
    // Unplug: long pulse with the level low withdraws the route.
    io.sde_isr.set(0);
    io.phy.write32(
        SHOTPLUG_CTL_DDI,
        io.phy.read32(SHOTPLUG_CTL_DDI) | shotplug_ddi_long(1),
    );
    match monitor.poll(&io) {
        Some(event) if event.kind == MtlHpdKind::Disconnected => {
            if !matches!(
                service.handle(&io, event, &mut fb_for),
                ServiceOutcome::Withdrawn { port: XeLpgPort::B }
            ) {
                return TestResult::Fail("disconnect must withdraw the HDMI route");
            }
        }
        _ => return TestResult::Fail("DDI B unplug must be reported"),
    }
    if service.route().is_some()
        || io.read32(XeLpgPort::B.ddi_buf_ctl()) & DDI_BUF_CTL_ENABLE != 0
        || io.read32(PIPECONF_B) & (ENABLE | STATE) != 0
        || io.read32(XeLpgPort::B.port_clock_ctl()) & 0xCC00_0000 != 0
    {
        return TestResult::Fail("withdrawn HDMI route must leave DDI, pipe and PLL off");
    }
    if !service.teardown(&io) || !monitor.teardown(&io) {
        return TestResult::Fail("teardown after withdrawal must be complete");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_service_ddi_b_hdmi_lifecycle
);

fn smoke_mtl_external_service_dp_precedence_and_hdmi_refusals() -> TestResult {
    let connect = ddi_b_event(MtlHpdKind::Connected(LiveMode::Native));
    // A DPCD that answers wins even when DDC would answer too.
    let io = ExtFake::new(XeLpgPort::B, Sink::new(0x14, edid_1024()));
    io.ddc.set_edid_present(true);
    let mut service = MtlExternalService::new();
    if !matches!(
        service.handle(&io, connect, &mut fb_for),
        ServiceOutcome::Activated {
            protocol: MtlProtocol::Dp,
            ..
        }
    ) || !io.ddc.writes().is_empty()
    {
        return TestResult::Fail("answering DPCD must take DP without touching DDC");
    }
    if !service.teardown(&io) {
        return TestResult::Fail("DP route teardown must complete");
    }
    // DPCD answered but its EDID is unreadable: a DP refusal, no HDMI.
    let io = ExtFake::new(XeLpgPort::B, Sink::new(0x14, Vec::new()));
    io.ddc.set_edid_present(true);
    let mut service = MtlExternalService::new();
    if !matches!(
        service.handle(&io, connect, &mut fb_for),
        ServiceOutcome::Refused {
            error: RouteError::Dp(ExternalError::Edid(_)),
            ..
        }
    ) || !io.ddc.writes().is_empty()
    {
        return TestResult::Fail("a DP sink failure must not fall back to HDMI");
    }
    // No DPCD and no DDC slave: an HDMI DDC refusal, nothing owned.
    let mut io = hdmi_on_ddi_b(edid_1024());
    io.ddc = FakeGmbus::absent();
    let mut service = MtlExternalService::new();
    if !matches!(
        service.handle(&io, connect, &mut fb_for),
        ServiceOutcome::Refused {
            error: RouteError::Hdmi(HdmiError::Ddc(_)),
            ..
        }
    ) || service.route().is_some()
        || io.aux_power.get()
        || !io.writes_to(XeLpgPort::B.ddi_buf_ctl()).is_empty()
    {
        return TestResult::Fail("silent DDC must refuse HDMI before programming");
    }
    // A DP-only declaration never reaches DDC.
    let io = hdmi_on_ddi_b(edid_1024());
    let mut dp_only = MtlPortPolicy::NO_VBT;
    dp_only.ddi_b = MtlPortDecl::USB_C;
    let mut service = MtlExternalService::with_policy(dp_only);
    if !matches!(
        service.handle(&io, connect, &mut fb_for),
        ServiceOutcome::Refused {
            error: RouteError::Dp(ExternalError::Link(_)),
            ..
        }
    ) || !io.ddc.writes().is_empty()
    {
        return TestResult::Fail("DP-only DDI B must refuse without DDC traffic");
    }
    // An HDMI clock without a source table refuses after the probe.
    let io = hdmi_on_ddi_b(edid_for(123_450, 1024, 320, 24, 136, 768, 38, 3, 6));
    let mut service = MtlExternalService::new();
    if !matches!(
        service.handle(&io, connect, &mut fb_for),
        ServiceOutcome::Refused {
            error: RouteError::Hdmi(HdmiError::UnsupportedClock(123_450)),
            ..
        }
    ) || service.route().is_some()
    {
        return TestResult::Fail("untabled TMDS clock must refuse with its clock");
    }
    // No scanout memory: refused, nothing owned.
    let io = hdmi_on_ddi_b(edid_1024());
    let mut service = MtlExternalService::new();
    if !matches!(
        service.handle(&io, connect, &mut |_| None),
        ServiceOutcome::Refused {
            error: RouteError::Hdmi(HdmiError::Route(ExternalError::Modeset(
                ModesetError::InvalidFramebuffer
            ))),
            ..
        }
    ) || service.route().is_some()
    {
        return TestResult::Fail("missing scanout must refuse the HDMI route");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_service_dp_precedence_and_hdmi_refusals
);

fn smoke_mtl_external_service_hdmi_unplug_mid_redetect_and_failed_stop() -> TestResult {
    let io = hdmi_on_ddi_b(edid_1024());
    let mut service = MtlExternalService::new();
    let connect = ddi_b_event(MtlHpdKind::Connected(LiveMode::Native));
    if !matches!(
        service.handle(&io, connect, &mut fb_for),
        ServiceOutcome::Activated { .. }
    ) {
        return TestResult::Fail("HDMI route must light");
    }
    // The sink leaves between the long pulse and re-detection: the route
    // is stopped and released, the reconnect finds neither DPCD nor DDC.
    io.ddc.set_edid_present(false);
    match service.handle(&io, ddi_b_event(MtlHpdKind::Redetect), &mut fb_for) {
        ServiceOutcome::Refused {
            port: XeLpgPort::B,
            error: RouteError::Hdmi(HdmiError::Ddc(_)),
        } => {}
        _ => return TestResult::Fail("vanished sink must refuse after a clean withdrawal"),
    }
    if service.route().is_some() || io.read32(XeLpgPort::B.ddi_buf_ctl()) & DDI_BUF_CTL_ENABLE != 0
    {
        return TestResult::Fail("re-detection loss must leave nothing owned");
    }
    // A live HDMI route whose transcoder never stops: teardown reports the
    // retention and the route stays quarantined (neither live nor stopped).
    io.ddc.set_edid_present(true);
    if !matches!(
        service.handle(&io, connect, &mut fb_for),
        ServiceOutcome::Activated { .. }
    ) {
        return TestResult::Fail("HDMI route must relight");
    }
    io.pipeconf_stuck.set(true);
    if service.teardown(&io)
        || service
            .route()
            .is_none_or(|r| r.live() || r.stopped() || r.protocol() != MtlProtocol::Hdmi)
    {
        return TestResult::Fail("unobserved HDMI stop must be retained, not released");
    }
    if !matches!(
        service.handle(&io, ddi_b_event(MtlHpdKind::Disconnected), &mut fb_for),
        ServiceOutcome::Retained {
            error: RouteError::Hdmi(HdmiError::Route(ExternalError::Quarantined)),
            ..
        }
    ) {
        return TestResult::Fail("a quarantined HDMI route must stay retained on unplug");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_service_hdmi_unplug_mid_redetect_and_failed_stop
);

fn smoke_mtl_external_service_legacy_tc_hdmi_on_tc_ddc_pin() -> TestResult {
    use crate::intel_gpu_xelpg_hpd::{icp_tc_hpd_long, sde_tc_hotplug};
    // TC2 declared as a native HDMI connector (the VBT fact Linux would
    // read); its DDC is gmbus_pins_mtp "tc2" = GMBUS_PIN_10_TC2_ICP.
    let mut policy = MtlPortPolicy::NO_VBT;
    policy.tc[1] = MtlPortDecl::LEGACY_HDMI;
    policy.tc[1].lane_reversal = true;
    let edid_720p = edid_for(74_250, 1280, 370, 110, 40, 720, 30, 5, 5);
    let mut sink = Sink::new(0x14, Vec::new());
    sink.nack_all = true;
    let mut io = ExtFake::new(XeLpgPort::Tc2, sink);
    io.pica_isr.set(0);
    io.sde_isr.set(sde_tc_hotplug(1));
    io.ddc = FakeGmbus::with_edid(&edid_720p);
    io.ddc.set_pin(10);
    let mut monitor = MtlHpdMonitor::new(policy.hpd_config());
    let mut service = MtlExternalService::with_policy(policy);
    let event = match monitor.poll(&io) {
        Some(event) if event.kind == MtlHpdKind::Connected(LiveMode::Legacy) => event,
        _ => return TestResult::Fail("declared legacy TC2 sink must be detected as legacy"),
    };
    match service.handle(&io, event, &mut fb_for) {
        ServiceOutcome::Activated {
            port: XeLpgPort::Tc2,
            protocol: MtlProtocol::Hdmi,
            mode,
            ..
        } if mode.h_active == 1280 && mode.pixel_clock_khz == 74_250 => {}
        _ => return TestResult::Fail("legacy TC2 must light HDMI over its tc2 DDC pin"),
    }
    let buf = io.read32(XeLpgPort::Tc2.buf_ctl1());
    if buf & (TCSS_POWER_REQUEST | TC_PHY_OWNERSHIP) != TCSS_POWER_REQUEST | TC_PHY_OWNERSHIP
        || buf & crate::intel_gpu_xelpg::PORT_BUF_REVERSAL == 0
        || io.ddc.writes_to(crate::intel_gpu_gmbus::GMBUS0).first() != Some(&10)
        || io.read32(TRANS_CLK_SEL_B) != 0x7000_0000
        || io.aux_power.get()
    {
        return TestResult::Fail("legacy HDMI must own the PHY, use pin 10 and PHY_G clocking");
    }
    // Unplug: SDE TC long pulse with the level low.
    io.sde_isr.set(0);
    io.phy.write32(
        SHOTPLUG_CTL_TC,
        io.phy.read32(SHOTPLUG_CTL_TC) | icp_tc_hpd_long(1),
    );
    match monitor.poll(&io) {
        Some(event) if event.kind == MtlHpdKind::Disconnected => {
            if !matches!(
                service.handle(&io, event, &mut fb_for),
                ServiceOutcome::Withdrawn {
                    port: XeLpgPort::Tc2
                }
            ) {
                return TestResult::Fail("legacy unplug must withdraw the HDMI route");
            }
        }
        _ => return TestResult::Fail("legacy TC2 unplug must be reported"),
    }
    if io.read32(XeLpgPort::Tc2.buf_ctl1()) & (TC_PHY_OWNERSHIP | TCSS_POWER_REQUEST) != 0 {
        return TestResult::Fail("withdrawal must release legacy Type-C ownership");
    }
    // The IOM never hands the PHY over: refused before any DDC traffic.
    let mut sink = Sink::new(0x14, Vec::new());
    sink.nack_all = true;
    let mut io = ExtFake::new(XeLpgPort::Tc2, sink);
    io.pica_isr.set(0);
    io.sde_isr.set(sde_tc_hotplug(1));
    io.ddc = FakeGmbus::with_edid(&edid_720p);
    io.ready.set(false);
    let mut service = MtlExternalService::with_policy(policy);
    let event = MtlHpdEvent {
        pin: MtlHpdPin::Tc2,
        kind: MtlHpdKind::Connected(LiveMode::Legacy),
    };
    if !matches!(
        service.handle(&io, event, &mut fb_for),
        ServiceOutcome::Refused {
            error: RouteError::Hdmi(HdmiError::Route(ExternalError::Tc(TcError::PhyNotReady))),
            ..
        }
    ) || !io.ddc.writes().is_empty()
        || io.read32(XeLpgPort::Tc2.buf_ctl1()) & TC_PHY_OWNERSHIP != 0
    {
        return TestResult::Fail("unready legacy PHY must refuse before DDC");
    }
    // The same port over DP-alt is refused by policy without MMIO.
    let event = MtlHpdEvent {
        pin: MtlHpdPin::Tc2,
        kind: MtlHpdKind::Connected(LiveMode::DpAlt),
    };
    if !matches!(
        service.handle(&NoAccess, event, &mut fb_for),
        ServiceOutcome::Refused {
            error: RouteError::Dp(ExternalError::UnsupportedPort),
            ..
        }
    ) {
        return TestResult::Fail("HDMI-only legacy port must refuse DP-alt");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_service_legacy_tc_hdmi_on_tc_ddc_pin
);

// ── VBT-derived policy (intel_bios.c / intel_ddi_init) ──────────────

fn smoke_mtl_vbt_policy_from_reference_board() -> TestResult {
    use crate::intel_gpu_vbt::tests::mtl_reference_vbt;
    let vbt = match crate::intel_gpu_vbt::Vbt::parse(&mtl_reference_vbt(250, true)) {
        Ok(vbt) => vbt,
        Err(_) => return TestResult::Fail("reference VBT must parse"),
    };
    let policy = MtlPortPolicy::from_vbt(&vbt);
    let want = MtlPortPolicy {
        ddi_b: MtlPortDecl {
            lane_reversal: false,
            dp: true,
            hdmi: true,
            legacy: false,
            ddc_pin: Some(PinPair::Pin2Bxt),
        },
        tc: [
            MtlPortDecl::USB_C,
            MtlPortDecl {
                lane_reversal: false,
                dp: false,
                hdmi: true,
                legacy: true,
                ddc_pin: Some(PinPair::Pin10Tc2),
            },
            MtlPortDecl {
                lane_reversal: false,
                dp: true,
                hdmi: true,
                legacy: false,
                ddc_pin: Some(PinPair::Pin11Tc3),
            },
            MtlPortDecl::NONE,
        ],
        use_ssc: true,
    };
    if policy != want {
        return TestResult::Fail("VBT policy must follow the board's child devices");
    }
    if policy.hpd_config().legacy_tc != [false, true, false, false] {
        return TestResult::Fail("only the VBT legacy port owns an SDE TC source");
    }
    use LiveMode::{DpAlt, Legacy, Native};
    let plans = [
        (XeLpgPort::B, Native, RoutePlan::DpThenHdmi),
        (XeLpgPort::Tc1, DpAlt, RoutePlan::Dp),
        (XeLpgPort::Tc1, Legacy, RoutePlan::Refuse),
        (XeLpgPort::Tc2, Legacy, RoutePlan::Hdmi),
        (XeLpgPort::Tc2, DpAlt, RoutePlan::Refuse),
        (XeLpgPort::Tc3, DpAlt, RoutePlan::Dp),
        (XeLpgPort::Tc3, Legacy, RoutePlan::Refuse),
        (XeLpgPort::Tc4, DpAlt, RoutePlan::Refuse),
    ];
    for (port, live, plan) in plans {
        if route_plan(port, policy.decl(port), live) != plan {
            return TestResult::Fail("route plans must follow the VBT declarations");
        }
    }
    if policy.ddc_pin(XeLpgPort::Tc2) != Some(PinPair::Pin10Tc2)
        || policy.ddc_pin(XeLpgPort::B) != Some(PinPair::Pin2Bxt)
    {
        return TestResult::Fail("HDMI DDC pins come from the VBT");
    }
    // enable_ssc clear in the general-features block turns SSC off.
    let no_ssc = crate::intel_gpu_vbt::Vbt::parse(&mtl_reference_vbt(250, false)).unwrap();
    if MtlPortPolicy::from_vbt(&no_ssc).use_ssc {
        return TestResult::Fail("the VBT's SSC preference must reach the policy");
    }
    // A VBT with no child devices declares no external port (Linux only
    // generates defaults when no VBT exists at all).
    let empty =
        crate::intel_gpu_vbt::Vbt::parse(&crate::intel_gpu_vbt::tests::VbtImage::new(250).build())
            .unwrap();
    let p = MtlPortPolicy::from_vbt(&empty);
    if p.ddi_b != MtlPortDecl::NONE || p.tc != [MtlPortDecl::NONE; 4] || !p.use_ssc {
        return TestResult::Fail("a childless VBT declares nothing and keeps SSC on");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_vbt_policy_from_reference_board
);

fn smoke_mtl_vbt_policy_fails_closed_on_undrivable_ports() -> TestResult {
    use crate::intel_gpu_vbt::device_type::{DP, DP_DUAL_MODE, EDP, MIPI_OUTPUT};
    use crate::intel_gpu_vbt::tests::{general_definitions, Child, VbtImage};
    use crate::intel_gpu_vbt::{block, dp_aux, dvo_port, Vbt};
    let policy = |version: u16, children: &[Child]| {
        let vbt = Vbt::parse(
            &VbtImage::new(version)
                .block(
                    block::GENERAL_DEFINITIONS,
                    general_definitions(44, children),
                )
                .build(),
        )
        .unwrap();
        MtlPortPolicy::from_vbt(&vbt)
    };
    // Board lane reversal is retained for the Cx0 PLL/clock/TX sequence.
    let p = policy(
        250,
        &[Child::new(DP_DUAL_MODE, dvo_port::DPB).lane_reversal()],
    );
    if !p.ddi_b.dp || !p.ddi_b.lane_reversal {
        return TestResult::Fail("a lane-reversed port must retain its wiring");
    }
    // TC1 on TC2's AUX channel (unclaimed): AUX is keyed by port here.
    let p = policy(250, &[Child::new(DP, dvo_port::DPF).aux(dp_aux::G).typec()]);
    if p.tc[0] != MtlPortDecl::NONE {
        return TestResult::Fail("a foreign VBT AUX channel must refuse the port");
    }
    // eDP declared on DDI B, DSI on DDI B, and a dedicated-external TC1.
    let p = policy(250, &[Child::new(EDP, dvo_port::DPB)]);
    let q = policy(250, &[Child::new(MIPI_OUTPUT, dvo_port::MIPIC)]);
    let r = policy(
        264,
        &[Child::new(DP, dvo_port::DPF).typec().dedicated_external()],
    );
    if p.ddi_b != MtlPortDecl::NONE || q.ddi_b != MtlPortDecl::NONE || r.tc[0] != MtlPortDecl::NONE
    {
        return TestResult::Fail("eDP, DSI and dedicated-external ports are not external routes");
    }
    // The same TC1 without the dedicated bit is a plain USB-C port.
    let s = policy(264, &[Child::new(DP, dvo_port::DPF).typec()]);
    if s.tc[0] != MtlPortDecl::USB_C {
        return TestResult::Fail("a USB-C VBT child is a DP-alt port");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_vbt_policy_fails_closed_on_undrivable_ports
);

fn smoke_mtl_vbt_ddc_override_reaches_hdmi_probe() -> TestResult {
    use crate::intel_gpu_vbt::device_type::DP_DUAL_MODE;
    use crate::intel_gpu_vbt::tests::{general_definitions, Child, VbtImage};
    use crate::intel_gpu_vbt::{block, dp_aux, dvo_port, Vbt};
    // DDI B declares DDC code 1 (ICL_DDC_BUS_DDI_A -> GMBUS pin 1 "dpa");
    // the sink answers only there and has no DPCD.
    let vbt = Vbt::parse(
        &VbtImage::new(250)
            .block(
                block::GENERAL_DEFINITIONS,
                general_definitions(
                    44,
                    &[Child::new(DP_DUAL_MODE, dvo_port::DPB)
                        .aux(dp_aux::B)
                        .ddc(1)],
                ),
            )
            .build(),
    )
    .unwrap();
    let policy = MtlPortPolicy::from_vbt(&vbt);
    if policy.ddc_pin(XeLpgPort::B) != Some(PinPair::Pin1Bxt) {
        return TestResult::Fail("DDC code 1 maps to GMBUS pin 1 on MTL");
    }
    let connect = ddi_b_event(MtlHpdKind::Connected(LiveMode::Native));
    let io = hdmi_on_ddi_b(edid_1024());
    io.ddc.set_pin(1);
    let mut service = MtlExternalService::with_policy(policy);
    match service.handle(&io, connect, &mut fb_for) {
        ServiceOutcome::Activated {
            protocol: MtlProtocol::Hdmi,
            ..
        } => {}
        _ => return TestResult::Fail("HDMI must probe on the VBT DDC pin"),
    }
    match service.route() {
        Some(MtlRoute::Hdmi(route)) if route.probe.ddc == PinPair::Pin1Bxt => {}
        _ => return TestResult::Fail("the HDMI route must keep the VBT DDC pin"),
    }
    if !service.teardown(&io) {
        return TestResult::Fail("the VBT HDMI route must tear down");
    }
    // The no-VBT policy uses dpb and finds nothing on this board.
    let io = hdmi_on_ddi_b(edid_1024());
    io.ddc.set_pin(1);
    let mut service = MtlExternalService::new();
    if !matches!(
        service.handle(&io, connect, &mut fb_for),
        ServiceOutcome::Refused {
            error: RouteError::Hdmi(HdmiError::Ddc(_)),
            ..
        }
    ) {
        return TestResult::Fail("the default pin must not reach a sink wired elsewhere");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_vbt_ddc_override_reaches_hdmi_probe
);

fn smoke_mtl_dp_ssc_follows_vbt_and_sink_downspread() -> TestResult {
    use crate::intel_gpu_xelpg::{Cx0PllState, SSC_ENABLE_PLLB};
    let connect = ddi_b_event(MtlHpdKind::Connected(LiveMode::Native));
    // intel_cx0pll_update_ssc: SSC = VBT preference && DP_MAX_DOWNSPREAD_0_5.
    for (use_ssc, downspread, want) in [
        (true, 0x01u8, true),
        (true, 0x00, false),
        (false, 0x01, false),
    ] {
        let io = ExtFake::new(XeLpgPort::B, Sink::new(0x14, edid_1024()));
        io.sink.borrow_mut().caps[3] = downspread;
        let mut policy = MtlPortPolicy::NO_VBT;
        policy.use_ssc = use_ssc;
        let mut service = MtlExternalService::with_policy(policy);
        if !matches!(
            service.handle(&io, connect, &mut fb_for),
            ServiceOutcome::Activated {
                protocol: MtlProtocol::Dp,
                ..
            }
        ) {
            return TestResult::Fail("DDI B DP must activate");
        }
        let probe_ssc = match service.route() {
            Some(MtlRoute::Dp(route)) if route.probe.max_downspread == downspread => {
                route.probe.ssc
            }
            _ => return TestResult::Fail("a DP route with the sink's downspread must be owned"),
        };
        let clock_ssc = io.read32(XeLpgPort::B.port_clock_ctl()) & SSC_ENABLE_PLLB != 0;
        if probe_ssc != want || clock_ssc != want {
            return TestResult::Fail("PORT_CLOCK_CTL SSC must follow the VBT and the sink");
        }
        if !service.teardown(&io) {
            return TestResult::Fail("the DP route must tear down");
        }
    }
    // intel_c10pll_update_pll: the non-SSC C10 state zeroes PLL bytes 4..8
    // and keeps the rest; C20 tables are used as shipped.
    let rate = crate::intel_gpu_pll::LinkRate::DpHbr2;
    let c10 = |ssc| dp_pll_request(XeLpgPort::B, rate, 4, false, false, ssc).unwrap();
    match (c10(true).state, c10(false).state) {
        (Cx0PllState::C10(on), Cx0PllState::C10(off))
            if on.pll[4..9] != [0; 5]
                && off.pll[4..9] == [0; 5]
                && on.pll[..4] == off.pll[..4]
                && on.pll[9..] == off.pll[9..]
                && c10(true).ssc
                && !c10(false).ssc => {}
        _ => return TestResult::Fail("C10 non-SSC form must zero PLL bytes 4..8 only"),
    }
    let c20 = |ssc| dp_pll_request(XeLpgPort::Tc1, rate, 4, true, false, ssc).unwrap();
    if c20(true).state != c20(false).state || !c20(true).ssc || c20(false).ssc {
        return TestResult::Fail("C20 keeps its table; only the SSC request differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_dp_ssc_follows_vbt_and_sink_downspread
);

fn smoke_mtl_no_vbt_install_keeps_missing_defaults() -> TestResult {
    use crate::intel_gpu::Generation;
    use crate::intel_gpu_gt::Gen12Platform;
    use crate::intel_gpu_vbt::{
        gen12_ddc_overrides, install_for_probe, Gen12DdcOverrides, VbtInstall,
    };
    // No readable ASLS, or ASLS 0: no VBT, the NO_VBT policy stays
    // (init_vbt_missing_defaults: DDI B DP+HDMI, USB-C DP-alt TC ports,
    // no legacy hotplug source, SSC by sink downspread).
    if install_for_probe(Generation::MeteorLake, None, None) != VbtInstall::Missing
        || install_for_probe(Generation::MeteorLake, None, Some(0)) != VbtInstall::Missing
    {
        return TestResult::Fail("no OpRegion must report a missing VBT");
    }
    if installed_mtl_port_policy() != Some(MtlPortPolicy::NO_VBT)
        || MtlPortPolicy::NO_VBT.hpd_config() != MtlHpdConfig::TYPE_C
        || !MtlPortPolicy::NO_VBT.use_ssc
    {
        return TestResult::Fail("a missing VBT must keep the NO_VBT policy");
    }
    if install_for_probe(Generation::TigerLake, Some(Gen12Platform::TigerLake), None)
        != VbtInstall::Missing
        || gen12_ddc_overrides() != Gen12DdcOverrides::NONE
    {
        return TestResult::Fail("Gen12 without a VBT keeps the default DDC pins");
    }
    if install_for_probe(Generation::LunarLake, None, Some(0x1234_5000))
        != VbtInstall::NotApplicable
        || install_for_probe(Generation::TigerLake, None, Some(0x1234_5000))
            != VbtInstall::NotApplicable
    {
        return TestResult::Fail("generations without a consumer must not read the OpRegion");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_no_vbt_install_keeps_missing_defaults
);

// ── External on Pipe B next to the lit panel (Pipe B–D owner join) ──────

/// A `'static` pipe-DMC sink recording (pipe, enabled) in call order.
#[derive(Debug)]
pub struct DmcEvents(narf_lib::sync::IrqSafeSpinLock<Vec<(u32, bool)>>);

impl PipeDmc for DmcEvents {
    fn enable_pipe(&self, pipe: u32) {
        self.0.lock().push((pipe, true));
    }
    fn disable_pipe(&self, pipe: u32) {
        self.0.lock().push((pipe, false));
    }
}

impl DmcEvents {
    /// A fresh sink that lives for the rest of the run (one per test).
    pub fn leak() -> &'static Self {
        alloc::boxed::Box::leak(alloc::boxed::Box::new(Self(
            narf_lib::sync::IrqSafeSpinLock::new(Vec::new()),
        )))
    }
    /// The events so far.
    pub fn events(&self) -> Vec<(u32, bool)> {
        self.0.lock().clone()
    }
}

/// The display context of a lit owned panel with `dmc` as its sink.
fn beside(panel: Mode, dmc: &'static DmcEvents) -> MtlDisplay {
    MtlDisplay {
        panel: Some(panel),
        pipe_dmc: dmc,
    }
}

/// The panel stayed lit and was never replaned: no write turned Pipe A's
/// transcoder or primary off or moved it, and both still read on.
fn panel_never_blanked(io: &ExtFake) -> bool {
    io.writes_to(PIPECONF_A).is_empty()
        && io.writes_to(PLANE_CTL_1_A).is_empty()
        && io
            .writes_to(PLANE_SURF_1_A)
            .iter()
            .all(|v| *v == PANEL_SURFACE)
        && io.read32(PIPECONF_A) & (ENABLE | STATE) == ENABLE | STATE
        && io.read32(PLANE_CTL_1_A) & ENABLE != 0
        && io.read32(PLANE_SURF_1_A) == PANEL_SURFACE
}

/// Pipe A and the global resources hold exactly the owned panel profile
/// again (the KMS fixed-profile contract), with Pipe B's image cleared.
fn panel_profile_restored(io: &ExtFake, mode: &Mode) -> bool {
    let Ok(latency) = crate::intel_gpu_xelpg_wm::Latency::read(io) else {
        return false;
    };
    let Ok(state) = crate::intel_gpu_xelpg_resources::compute(
        &crate::intel_gpu_display_resources::request(
            mode,
            crate::intel_gpu_xelpg_wm::Tiling::Linear,
            0,
        ),
        &latency,
    ) else {
        return false;
    };
    let Some(image) = state.plane_registers() else {
        return false;
    };
    image.iter().all(|&(r, v)| io.read32(r) == v)
        && crate::intel_gpu_display_resources::Profile::capture(io, mode).is_ok()
        && crate::intel_gpu_pmdemand::Params::decode(
            io.read32(0x4_5230),
            io.read32(PMDEMAND_REQUEST1),
        ) == state.pmdemand
}

fn smoke_mtl_external_dp_on_pipe_b_beside_lit_panel() -> TestResult {
    let io = ExtFake::new(XeLpgPort::Tc1, Sink::new(0x14, edid_1080()));
    let Some(panel) = io.light_panel() else {
        return TestResult::Fail("the fixture must light the owned panel");
    };
    let dmc = DmcEvents::leak();
    let probe = match probe_sink(&io, Generation::MeteorLake, XeLpgPort::Tc1, false) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("probe must succeed"),
    };
    let fb = fb_for(&probe.mode).unwrap();
    let mut route = match activate(&io, probe, fb, &beside(panel, dmc)) {
        Ok(route) if route.state() == RouteState::Live => route,
        _ => return TestResult::Fail("DP must light Pipe B next to the lit panel"),
    };
    // The route owns Pipe B / transcoder B; the panel's pipe was adopted.
    let want = crate::intel_gpu_pipes::build_trans_ddi_func_ctl(
        3,
        crate::intel_gpu_pipes::TRANS_DDI_MODE_DP_SST,
        route.trained.lanes,
    );
    if route.pipe() != Pipe::B
        || io.read32(TRANS_DDI_FUNC_CTL_B) != want
        || io.read32(TRANS_CLK_SEL_B) != 0x6000_0000
        || io.read32(PIPECONF_B) & (ENABLE | STATE) != ENABLE | STATE
        || io.read32(PLANE_SURF_1_B) != 0x100_0000
        || !io.writes_to(TRANS_DDI_FUNC_CTL_A).is_empty()
    {
        return TestResult::Fail("the DP route must run on Pipe B and transcoder B");
    }
    if !panel_never_blanked(&io) {
        return TestResult::Fail("adding the external must keep the panel lit and unplaned");
    }
    // Linux order: the live resource transaction (MBUS unjoined for two
    // pipes) precedes the port PLL; then pipe source size and timings, the
    // transcoder function, the transcoder, and the primary arm last.
    let unjoin = io.first_write(|o, _| o == crate::intel_gpu_xelpg_dbuf::MBUS_CTL);
    let pll = io.first_write(|o, _| o == XeLpgPort::Tc1.port_clock_ctl());
    let timings = io.first_write(|o, _| o == 0x6_101C);
    let func_on =
        io.first_write(|o, v| o == TRANS_DDI_FUNC_CTL_B && v & TRANS_DDI_FUNC_ENABLE != 0);
    let pipe_on = io.first_write(|o, v| o == PIPECONF_B && v & ENABLE != 0);
    let arm = io.first_write(|o, _| o == PLANE_SURF_1_B);
    match (unjoin, pll, timings, func_on, pipe_on, arm) {
        (Some(a), Some(b), Some(c), Some(d), Some(e), Some(f))
            if a < b && b < c && c < d && d < e && e < f => {}
        _ => return TestResult::Fail("resources, PLL, timings, function, pipe, arm order"),
    }
    // Two lit pipes leave the joined single-pipe profile: MBUS unjoins and
    // the panel's proof now holds only Pipe A's half of the DBUF.
    let unjoined = io.read32(crate::intel_gpu_xelpg_dbuf::MBUS_CTL)
        & crate::intel_gpu_xelpg_dbuf::MBUS_CTL_MASK
        == 0;
    match crate::intel_gpu_display_resources::Profile::capture(&io, &panel) {
        Ok(profile) if unjoined && profile.cursor_start < 2048 => {}
        _ => return TestResult::Fail("two lit pipes must leave the joined single-pipe profile"),
    }
    if dmc.events() != [(1, true)] {
        return TestResult::Fail("Pipe B's DMC must be enabled once for its crtc");
    }
    // Remove: the external stops and Pipe A gets its whole profile back.
    if route.stop(&io).is_err() || route.state() != RouteState::Stopped || route.reserved() {
        return TestResult::Fail("the stop must be proven and release Pipe B");
    }
    if io.read32(PIPECONF_B) & (ENABLE | STATE) != 0
        || io.read32(TRANS_CLK_SEL_B) != 0
        || dmc.events() != [(1, true), (1, false)]
    {
        return TestResult::Fail("Pipe B must be off with its DMC disabled");
    }
    if !panel_never_blanked(&io) || !panel_profile_restored(&io, &panel) {
        return TestResult::Fail("removal must restore the panel profile without blanking it");
    }
    if route.release(&io).is_err() {
        return TestResult::Fail("the stopped route must release Type-C and AUX");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_dp_on_pipe_b_beside_lit_panel
);

fn smoke_mtl_external_hdmi_on_pipe_b_beside_lit_panel() -> TestResult {
    let io = hdmi_on_ddi_b(edid_1024());
    let Some(panel) = io.light_panel() else {
        return TestResult::Fail("the fixture must light the owned panel");
    };
    let dmc = DmcEvents::leak();
    let mut service = MtlExternalService::new();
    service.set_display(beside(panel, dmc));
    let event = ddi_b_event(MtlHpdKind::Connected(LiveMode::Native));
    match service.handle(&io, event, &mut fb_for) {
        ServiceOutcome::Activated {
            port: XeLpgPort::B,
            protocol: MtlProtocol::Hdmi,
            pipe: Pipe::B,
            ..
        } => {}
        _ => return TestResult::Fail("HDMI must light Pipe B next to the lit panel"),
    }
    let func = crate::intel_gpu_pipes::build_trans_ddi_func_ctl_hdmi(1, false, false);
    let dip =
        crate::intel_gpu_pipes::Transcoder::B.base() + crate::intel_gpu_hdmi::VIDEO_DIP_CTL_OFFSET;
    if io.read32(TRANS_DDI_FUNC_CTL_B) != func
        || io.read32(TRANS_CLK_SEL_B) != 0x2000_0000
        || io.read32(dip) & crate::intel_gpu_hdmi::VIDEO_DIP_ENABLE_AVI == 0
        || service.route().map(MtlRoute::pipe) != Some(Pipe::B)
        || !panel_never_blanked(&io)
    {
        return TestResult::Fail("HDMI must own transcoder B with the panel kept lit");
    }
    // intel_ddi_enable then intel_ddi_enable_hdmi: transcoder before
    // DDI_CTL_DE, the primary armed last.
    let pipe_on = io.first_write(|o, v| o == PIPECONF_B && v & ENABLE != 0);
    let ddi_on =
        io.first_write(|o, v| o == XeLpgPort::B.ddi_buf_ctl() && v & DDI_BUF_CTL_ENABLE != 0);
    let arm = io.first_write(|o, _| o == PLANE_SURF_1_B);
    match (pipe_on, ddi_on, arm) {
        (Some(a), Some(b), Some(c)) if a < b && b < c => {}
        _ => return TestResult::Fail("HDMI order must be transcoder, DDI, then the arm"),
    }
    // Unplug withdraws it and repartitions back to the panel alone.
    match service.handle(&io, ddi_b_event(MtlHpdKind::Disconnected), &mut fb_for) {
        ServiceOutcome::Withdrawn { port: XeLpgPort::B } => {}
        _ => return TestResult::Fail("the HDMI route must withdraw"),
    }
    if io.read32(PIPECONF_B) & (ENABLE | STATE) != 0
        || io.read32(dip) & crate::intel_gpu_hdmi::VIDEO_DIP_ENABLE_AVI != 0
        || dmc.events() != [(1, true), (1, false)]
        || !panel_never_blanked(&io)
        || !panel_profile_restored(&io, &panel)
    {
        return TestResult::Fail("HDMI removal must restore the panel profile unblanked");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_hdmi_on_pipe_b_beside_lit_panel
);

fn smoke_mtl_external_no_free_pipe_or_resources_refuse_before_mmio() -> TestResult {
    // Pipes B–D all lit: NoFreePipe before any write, probe handed back.
    let io = ExtFake::new(XeLpgPort::Tc1, Sink::new(0x14, edid_1024()));
    let Some(panel) = io.light_panel() else {
        return TestResult::Fail("the fixture must light the owned panel");
    };
    let dmc = DmcEvents::leak();
    let probe = match probe_sink(&io, Generation::MeteorLake, XeLpgPort::Tc1, false) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("probe must succeed"),
    };
    for pipe in 1..4 {
        io.set_conf(pipe, ENABLE);
    }
    let before = io.writes.borrow().len();
    let fb = fb_for(&probe.mode).unwrap();
    let probe = match activate(&io, probe, fb, &beside(panel, dmc)) {
        Err(ActivateError::Refused(probe, ExternalError::NoFreePipe)) => probe,
        _ => return TestResult::Fail("no free Pipe B–D must refuse NoFreePipe"),
    };
    if io.writes.borrow().len() != before || !dmc.events().is_empty() {
        return TestResult::Fail("the no-pipe refusal must precede every write");
    }
    // A free pipe but no resources for the mode: the resource owner's
    // typed refusal, still before any write.
    for pipe in 1..4 {
        io.set_conf(pipe, 0);
    }
    let mut huge = probe;
    huge.mode.pixel_clock_khz = 1_400_000;
    let fb = fb_for(&huge.mode).unwrap();
    let probe = match activate(&io, huge, fb, &beside(panel, dmc)) {
        Err(ActivateError::Refused(probe, ExternalError::Pipe(_))) => probe,
        _ => return TestResult::Fail("unsatisfiable resources must refuse typed"),
    };
    if io.writes.borrow().len() != before || !dmc.events().is_empty() {
        return TestResult::Fail("the resource refusal must precede every write");
    }
    // An unowned lit Pipe A (no panel profile in the context) refuses too.
    let fb = fb_for(&probe.mode).unwrap();
    let probe = match activate(&io, probe, fb, &MtlDisplay::NONE) {
        Err(ActivateError::Refused(probe, ExternalError::PipeBusy)) => probe,
        _ => return TestResult::Fail("an unowned lit Pipe A must refuse PipeBusy"),
    };
    if io.writes.borrow().len() != before || !panel_never_blanked(&io) {
        return TestResult::Fail("refusals must leave the panel untouched");
    }
    if release_probe(&io, &probe).is_err() {
        return TestResult::Fail("the refused probe must release");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_no_free_pipe_or_resources_refuse_before_mmio
);

fn smoke_mtl_external_failed_activation_repartitions_back() -> TestResult {
    // The sink vanishes after probe: training fails with Pipe B already
    // reserved next to the lit panel. The local stop disables Pipe B's
    // DMC and repartitions back; the panel never blanks.
    let io = ExtFake::new(XeLpgPort::Tc2, Sink::new(0x14, edid_1024()));
    let Some(panel) = io.light_panel() else {
        return TestResult::Fail("the fixture must light the owned panel");
    };
    let dmc = DmcEvents::leak();
    let probe = match probe_sink(&io, Generation::MeteorLake, XeLpgPort::Tc2, false) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("probe must succeed"),
    };
    io.sink.borrow_mut().nack_all = true;
    let fb = fb_for(&probe.mode).unwrap();
    let route = match activate(&io, probe, fb, &beside(panel, dmc)) {
        Err(ActivateError::Failed(route, ExternalError::Link(_)))
            if route.state() == RouteState::Stopped =>
        {
            route
        }
        _ => return TestResult::Fail("training loss must fail with a stopped route"),
    };
    // The reservation did happen (MBUS unjoined, then rejoined) and was
    // undone by the post-plane release.
    if io.writes_to(crate::intel_gpu_xelpg_dbuf::MBUS_CTL).len() < 2
        || route.reserved()
        || dmc.events() != [(1, true), (1, false)]
    {
        return TestResult::Fail("the failed activation must reserve, then release Pipe B");
    }
    if io.read32(PIPECONF_B) & (ENABLE | STATE) != 0
        || !panel_never_blanked(&io)
        || !panel_profile_restored(&io, &panel)
    {
        return TestResult::Fail("the repartition must return the panel profile, unblanked");
    }
    if route.release(&io).is_err() {
        return TestResult::Fail("the stopped route must release Type-C ownership");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_failed_activation_repartitions_back
);

fn smoke_mtl_external_pm_demand_at_route_port_clock() -> TestResult {
    use crate::intel_gpu_pmdemand::Params;
    let demand = |io: &ExtFake| Params::decode(io.read32(0x4_5230), io.read32(PMDEMAND_REQUEST1));
    // No panel: the DP route's PM demand carries its negotiated RBR port
    // clock (162 MHz), not the HBR3 reservation of the panel profile.
    let io = ExtFake::new(XeLpgPort::Tc1, Sink::new(0x14, edid_1024()));
    let route = match live_route(&io, XeLpgPort::Tc1) {
        Ok(route) => route,
        Err(e) => return TestResult::Fail(e),
    };
    if route.trained.rate != TrainRate::Rbr || demand(&io).ddiclk_max != 162 {
        return TestResult::Fail("DP PM demand must run at the trained RBR port clock");
    }
    // A lane fallback retrains at the same rate on the same reservation:
    // the demand stays exact.
    let mut sink = Sink::new(0x14, edid_1024());
    sink.max_good_lanes = 2;
    let io = ExtFake::new(XeLpgPort::Tc3, sink);
    let route = match live_route(&io, XeLpgPort::Tc3) {
        Ok(route) => route,
        Err(e) => return TestResult::Fail(e),
    };
    if route.trained.lanes != 2 || demand(&io).ddiclk_max != 162 {
        return TestResult::Fail("a lane fallback must keep the trained-rate demand");
    }
    // HDMI: the TMDS clock (65 MHz).
    let io = hdmi_on_ddi_b(edid_1024());
    let mut service = MtlExternalService::new();
    if !matches!(
        service.handle(
            &io,
            ddi_b_event(MtlHpdKind::Connected(LiveMode::Native)),
            &mut fb_for
        ),
        ServiceOutcome::Activated { .. }
    ) || demand(&io).ddiclk_max != 65
    {
        return TestResult::Fail("HDMI PM demand must run at the TMDS clock");
    }
    // Next to the lit panel the panel's HBR3 reservation still bounds the
    // maximum (the documented over-request the KMS profile requires).
    let io = ExtFake::new(XeLpgPort::Tc1, Sink::new(0x14, edid_1024()));
    let Some(panel) = io.light_panel() else {
        return TestResult::Fail("the fixture must light the owned panel");
    };
    let probe = match probe_sink(&io, Generation::MeteorLake, XeLpgPort::Tc1, false) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("probe must succeed"),
    };
    let fb = fb_for(&probe.mode).unwrap();
    match activate(&io, probe, fb, &beside(panel, DmcEvents::leak())) {
        Ok(_) if demand(&io).ddiclk_max == 810 => {}
        _ => return TestResult::Fail("the panel's HBR3 reservation must bound the demand"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_pm_demand_at_route_port_clock
);

/// A DP 1.4 monitor's DSC 1.2 capabilities: 1/2/4 slices, 9-bit line
/// buffer, block prediction, no maximum bpp, 1/16 bpp increments and an
/// 850/340 MP/s per-slice throughput.
const MONITOR_DSC: [u8; 16] = [
    0x01, 0x21, 0x00, 0x0f, 0x0b, 0x00, 0x01, 0x00, 0x00, 0x01, 0x06, 0x0b, 0x08, 0x00, 0x00, 0x00,
];

/// 3840x2160@60 (CTA VIC 97 timing) on a one-lane HBR3 DSC sink.
fn dsc_monitor(fec: bool) -> Sink {
    let mut sink = Sink::new(0x1e, edid_for(594_000, 3840, 560, 176, 88, 2160, 90, 8, 10));
    sink.caps[2] = 1 | 0x40 | 0x80;
    sink.dsc = MONITOR_DSC;
    sink.fec_cap = u8::from(fec);
    sink
}

fn smoke_mtl_external_dp_dsc_with_fec_lights_and_stops() -> TestResult {
    use crate::intel_gpu_xelpg_dsc::{
        decide_dp, DpDscSink, DscDpcd, DscSink, LinkDecision, LinkLimits, DP_TP_CTL_FEC_ENABLE,
        DP_TP_STATUS_FEC_ENABLE_LIVE, PIPE_BPP,
    };
    // 594 MHz needs 1782000 kBps at 24 bpp and 1336500 at 18; one HBR3
    // lane carries 810000. Linux compresses with FEC: 169/16 bpp, two
    // slices on two engines, HBR3 x1.
    let io = ExtFake::new(XeLpgPort::B, dsc_monitor(true));
    io.phy.write32(0x6_1544, DP_TP_STATUS_FEC_ENABLE_LIVE);
    let probe = match probe_sink(&io, Generation::MeteorLake, XeLpgPort::B, false) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("the DSC monitor must probe"),
    };
    let sink = DpDscSink {
        dsc: DscSink {
            dpcd: DscDpcd(MONITOR_DSC),
            is_edp: false,
            fec_capable: true,
        },
        branch: false,
    };
    let Ok(LinkDecision::Dsc(plan)) = decide_dp(
        &sink,
        &LinkLimits::standard(810_000, 1),
        &probe.mode,
        PIPE_BPP,
    ) else {
        return TestResult::Fail("the monitor must need DSC");
    };
    if probe.dsc != Some(plan)
        || (
            plan.link_rate,
            plan.lanes,
            plan.compressed_bpp_x16,
            plan.slice_count,
        ) != (810_000, 1, 169, 2)
        || probe.negotiated.rate != TrainRate::Hbr3
        || probe.negotiated.lanes != 1
        || probe.negotiated.over_budget
    {
        return TestResult::Fail("the probe must carry Linux's DSC plan and its link");
    }
    let fb = fb_for(&probe.mode).unwrap();
    let mut route = match activate(&io, probe, fb, &MtlDisplay::NONE) {
        Ok(route) if route.state() == RouteState::Live => route,
        _ => return TestResult::Fail("the compressed route must light"),
    };
    let writes = io.writes.borrow().clone();
    // Pipe B's engines, transcoder B's PPS SDP and compressed M/N.
    let engines: Vec<(u64, u32)> = writes
        .iter()
        .copied()
        .filter(|&(r, _)| (0x7_8200..0x7_8400).contains(&r))
        .collect();
    let sdp = plan.pps_sdp();
    let mn = plan.m_n(&route.probe.mode);
    if engines != plan.engine_writes(Pipe::B)
        || (0..33).any(|i| io.writes_to(0x6_1350 + 4 * i as u64) != [sdp[i]])
        || io.read32(0x6_1200) & (1 << 24) == 0
        || io.writes_to(0x6_1030) != [mn[0]]
        || io.writes_to(0x6_1044) != [mn[3]]
        || io.read32(DP_TP_CTL_B) & DP_TP_CTL_FEC_ENABLE == 0
    {
        return TestResult::Fail("Pipe B must compress with the plan's engines, SDP and M/N");
    }
    // The sink: D0, decompression and FEC ready before training; FEC
    // decode detected after the transcoder enable.
    let sink = io.sink.borrow();
    if sink.dsc_log[..3] != [(0x160, 1), (0x120, 1), (0x280, 3)] || !sink.powered {
        return TestResult::Fail("DSC and FEC ready must reach the sink before training");
    }
    drop(sink);
    let pos = |f: &dyn Fn(u64, u32) -> bool| writes.iter().position(|&(o, v)| f(o, v));
    let fec = pos(&|o, v| o == DP_TP_CTL_B && v & DP_TP_CTL_FEC_ENABLE != 0);
    let normal = pos(&|o, v| o == DP_TP_CTL_B && v & (7 << 8) == 3 << 8);
    let pps = pos(&|o, _| o == 0x6_1350);
    let ctl2 = pos(&|o, _| o == 0x7_8204);
    let enable = pos(&|o, v| o == PIPECONF_B && v & ENABLE != 0);
    match (normal, fec, pps, ctl2, enable) {
        (Some(n), Some(f), Some(p), Some(c), Some(e)) if n < f && f < p && p < c && c < e => {}
        _ => return TestResult::Fail("FEC, the PPS SDP and the engines precede TRANSCONF"),
    }
    // PM demand takes the plan's HBR3 port clock.
    let demand = crate::intel_gpu_pmdemand::Params::decode(
        io.read32(0x4_5230),
        io.read32(PMDEMAND_REQUEST1),
    );
    if demand.ddiclk_max != 810 {
        return TestResult::Fail("PM demand must run at the compressed link's HBR3");
    }
    // Stop: sink decompression off before TRANSCONF, engines and the SDP
    // after the function deselect, FEC after DP_TP_CTL, then FEC ready.
    io.writes.borrow_mut().clear();
    io.sink.borrow_mut().dsc_log.clear();
    if route.stop(&io).is_err() || route.state() != RouteState::Stopped {
        return TestResult::Fail("the compressed route must stop");
    }
    let writes = io.writes.borrow().clone();
    let pos = |f: &dyn Fn(u64, u32) -> bool| writes.iter().position(|&(o, v)| f(o, v));
    let off = pos(&|o, v| o == PIPECONF_B && v & ENABLE == 0);
    let func = pos(&|o, v| o == TRANS_DDI_FUNC_CTL_B && v & TRANS_DDI_FUNC_ENABLE == 0);
    let ctl2 = pos(&|o, v| o == 0x7_8204 && v == 0);
    let dip = pos(&|o, v| o == 0x6_1200 && v & (1 << 24) == 0);
    let tp_off = pos(&|o, v| o == DP_TP_CTL_B && v & DP_TP_CTL_ENABLE == 0);
    let fec_off =
        pos(&|o, v| o == DP_TP_CTL_B && v & (DP_TP_CTL_ENABLE | DP_TP_CTL_FEC_ENABLE) == 0);
    let sink = io.sink.borrow();
    if sink.dsc_log != [(0x160, 0), (0x120, 0)] || sink.dsc_enable != 0 || sink.fec_config != 0 {
        return TestResult::Fail("the sink's decompression and FEC ready must go off");
    }
    drop(sink);
    match (off, func, ctl2, dip, tp_off, fec_off) {
        (Some(o), Some(f), Some(c), Some(d), Some(t), Some(x))
            if o < f && f < c && c < d && d < t && t < x => {}
        _ => return TestResult::Fail("the DSC stop must follow intel_ddi_post_disable"),
    }
    if io.read32(0x7_8204) != 0 || io.read32(DP_TP_CTL_B) & DP_TP_CTL_FEC_ENABLE != 0 {
        return TestResult::Fail("the engines and FEC must end off");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_dp_dsc_with_fec_lights_and_stops
);

fn smoke_mtl_external_dp_dsc_refusals_precede_programming() -> TestResult {
    use crate::intel_gpu_xelpg_dsc::DscRefusal;
    // Without FEC a DP sink cannot take DSC; 4K60 on one HBR3 lane has no
    // uncompressed fit either. Refused at probe, before any pipe write.
    let io = ExtFake::new(XeLpgPort::B, dsc_monitor(false));
    if probe_sink(&io, Generation::MeteorLake, XeLpgPort::B, false).err()
        != Some(ExternalError::Dsc(DscRefusal::FecUnsupported))
        || !io.writes_to(PIPECONF_B).is_empty()
        || io.aux_power.get()
    {
        return TestResult::Fail("a sink without FEC must refuse DSC at probe");
    }
    // Two HBR3 lanes carry 18 bpp: Linux drives 6 bpc uncompressed before
    // it tries DSC (intel_dp_compute_link_config_wide's bpp descent).
    let mut sink = dsc_monitor(true);
    sink.caps[2] = 2 | 0x40 | 0x80;
    let io = ExtFake::new(XeLpgPort::B, sink);
    match probe_sink(&io, Generation::MeteorLake, XeLpgPort::B, false) {
        Ok(probe)
            if probe.dsc.is_none()
                && probe.pipe_bpp == 18
                && (probe.negotiated.rate, probe.negotiated.lanes) == (TrainRate::Hbr3, 2) => {}
        _ => return TestResult::Fail("an 18 bpp fit must take 6 bpc before DSC"),
    }
    // A sink that does not decompress keeps the uncompressed refusal.
    let mut sink = dsc_monitor(true);
    sink.dsc = [0; 16];
    let io = ExtFake::new(XeLpgPort::B, sink);
    if !matches!(
        probe_sink(&io, Generation::MeteorLake, XeLpgPort::B, false),
        Err(ExternalError::OverBudget { .. })
    ) {
        return TestResult::Fail("a sink without DSC keeps OverBudget");
    }
    // A DSC sink whose link carries 24 bpp is not compressed.
    let mut sink = Sink::new(0x14, edid_1080());
    sink.dsc = MONITOR_DSC;
    sink.fec_cap = 1;
    let io = ExtFake::new(XeLpgPort::B, sink);
    match probe_sink(&io, Generation::MeteorLake, XeLpgPort::B, false) {
        Ok(probe) if probe.dsc.is_none() => {}
        _ => return TestResult::Fail("an uncompressed fit must not compress"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_dp_dsc_refusals_precede_programming
);

fn smoke_mtl_external_dp_six_bpc_route_from_edid_bpc() -> TestResult {
    use crate::intel_gpu_xelpg_dsc::link_m_n;
    // An EDID 1.4 digital 6 bpc 1080p sink on HBR2 x4: compute_sink_pipe_bpp
    // limits the pipe to 18 bpp, and intel_dp_compute_link_config_wide
    // takes the slowest, narrowest link carrying 334125 kBps: RBR x4.
    let mut edid = edid_1080();
    edid[20] = 0x90;
    edid[127] = edid[127].wrapping_sub(0x90);
    let io = ExtFake::new(XeLpgPort::B, Sink::new(0x14, edid));
    let probe = match probe_sink(&io, Generation::MeteorLake, XeLpgPort::B, false) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("the 6 bpc sink must probe"),
    };
    if probe.pipe_bpp != 18
        || probe.dsc.is_some()
        || (probe.negotiated.rate, probe.negotiated.lanes) != (TrainRate::Rbr, 4)
    {
        return TestResult::Fail("the probe must take 18 bpp on Linux's RBR x4");
    }
    let fb = fb_for(&probe.mode).unwrap();
    let mut route = match activate(&io, probe, fb, &MtlDisplay::NONE) {
        Ok(route) if route.state() == RouteState::Live => route,
        _ => return TestResult::Fail("the 6 bpc route must light"),
    };
    // TRANS_DDI_FUNC_CTL BPC_6, the Pipes owner's dithered PIPE_MISC, the
    // 6 bpc MSA and intel_link_compute_m_n at 18 bpp, TU 64.
    let mn = link_m_n(18 * 16, 4, 148_500, 162_000, false);
    if io.read32(TRANS_DDI_FUNC_CTL_B) & (7 << 20) != 2 << 20
        || io.writes_to(0x7_1030) != [(1 << 23) | 0x150]
        || io.writes_to(0x6_1410) != [0x01]
        || io.writes_to(0x6_1030) != [mn[0]]
        || io.writes_to(0x6_1044) != [mn[3]]
    {
        return TestResult::Fail("Pipe B must run 6 bpc with its MSA and M/N");
    }
    // The MSA follows the normal pattern and precedes TRANSCONF.
    let writes = io.writes.borrow().clone();
    let pos = |f: &dyn Fn(u64, u32) -> bool| writes.iter().position(|&(o, v)| f(o, v));
    match (
        pos(&|o, v| o == DP_TP_CTL_B && v & (7 << 8) == 3 << 8),
        pos(&|o, _| o == 0x6_1410),
        pos(&|o, v| o == PIPECONF_B && v & ENABLE != 0),
    ) {
        (Some(n), Some(m), Some(e)) if n < m && m < e => {}
        _ => return TestResult::Fail("intel_ddi_set_dp_msa must end the pre-enable"),
    }
    // The stop leaves the MSA at 8 bpc for the next route.
    if route.stop(&io).is_err()
        || route.state() != RouteState::Stopped
        || io.read32(0x6_1410) != 0x21
    {
        return TestResult::Fail("the 6 bpc route must stop and restore an 8 bpc MSA");
    }
    // An 8 bpc sink on the same port keeps the existing route: no MSA write
    // and PIPE_MISC BPC_8.
    let io = ExtFake::new(XeLpgPort::B, Sink::new(0x14, edid_1080()));
    match live_route(&io, XeLpgPort::B) {
        Ok(route) if route.probe.pipe_bpp == 24 => {}
        _ => return TestResult::Fail("the 8 bpc sink must light at 24 bpp"),
    }
    if !io.writes_to(0x6_1410).is_empty()
        || io.writes_to(0x7_1030) != [(1 << 23) | 0x100]
        || io.read32(TRANS_DDI_FUNC_CTL_B) & (7 << 20) != 0
    {
        return TestResult::Fail("the 8 bpc route must keep its write stream");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_dp_six_bpc_route_from_edid_bpc
);

fn smoke_mtl_external_route_arm_runs_inside_irq_masked_evasion() -> TestResult {
    // The live update of the panel and the arm of Pipe B both sample the
    // scanline and write PLANE_SURF with local interrupts masked.
    let irqs = narf_arch::interrupts_enabled();
    let io = ExtFake::new(XeLpgPort::Tc1, Sink::new(0x14, edid_1024()));
    let Some(panel) = io.light_panel() else {
        return TestResult::Fail("the fixture must light the owned panel");
    };
    let probe = match probe_sink(&io, Generation::MeteorLake, XeLpgPort::Tc1, false) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("probe must succeed"),
    };
    let fb = fb_for(&probe.mode).unwrap();
    if activate(&io, probe, fb, &beside(panel, DmcEvents::leak())).is_err() {
        return TestResult::Fail("the route must light");
    }
    let log = io.irq_log.borrow();
    let regs: Vec<u64> = log.iter().map(|(r, _)| *r).collect();
    // PIPEDSL(A) + the panel's SURF re-arm, then PIPEDSL(B) + Pipe B's SURF.
    if regs != [0x7_0000, PLANE_SURF_1_A, 0x7_1000, PLANE_SURF_1_B] {
        return TestResult::Fail("each arm must follow its own evasion sample");
    }
    if irqs && log.iter().any(|(_, enabled)| *enabled) {
        return TestResult::Fail("evasion samples and arms must run IRQ-masked");
    }
    if narf_arch::interrupts_enabled() != irqs {
        return TestResult::Fail("the local interrupt state must be restored");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_route_arm_runs_inside_irq_masked_evasion
);

fn smoke_mtl_external_route_presence_has_no_transient_readers() -> TestResult {
    // Lock-free readers of a service's route presence see the last
    // completed pass, never a "not stopped" because a pass merely holds
    // the service. A live route reports live/not stopped until the pass
    // that stops it completes; a quarantined one stays not stopped.
    static PRESENCE_UNDER_TEST: RoutePresence = RoutePresence::new();
    let presence = &PRESENCE_UNDER_TEST;
    let io = ExtFake::new(XeLpgPort::Tc1, Sink::new(0x14, edid_1024()));
    let mut service = MtlExternalService::with_presence(presence);
    if !service.teardown(&io) || !presence.stopped() || presence.live() {
        return TestResult::Fail("an empty service must publish stopped");
    }
    let mut monitor = MtlHpdMonitor::new(MtlHpdConfig::TYPE_C);
    let Some(event) = monitor.poll(&io) else {
        return TestResult::Fail("the DP-alt sink must be detected");
    };
    // Mid-pass (the service is held): still the previous pass's "absent".
    let mut mid = Vec::new();
    let mut alloc = |mode: &Mode| {
        mid.push((presence.stopped(), presence.live()));
        fb_for(mode)
    };
    let activated = matches!(
        service.handle(&io, event, &mut alloc),
        ServiceOutcome::Activated { .. }
    );
    if !activated || mid != [(true, false)] || presence.stopped() || !presence.live() {
        return TestResult::Fail("activation must publish live only when the pass ends");
    }
    // A pass that changes nothing republishes the same state.
    let idle = MtlHpdEvent {
        pin: MtlHpdPin::Tc2,
        kind: MtlHpdKind::Disconnected,
    };
    if !matches!(
        service.handle(&io, idle, &mut fb_for),
        ServiceOutcome::Unchanged
    ) || presence.stopped()
        || !presence.live()
    {
        return TestResult::Fail("an unrelated pass must keep the live presence");
    }
    // A quarantined stop publishes "not stopped, not live".
    io.pipeconf_stuck.set(true);
    let gone = MtlHpdEvent {
        pin: MtlHpdPin::Tc1,
        kind: MtlHpdKind::Disconnected,
    };
    if !matches!(
        service.handle(&io, gone, &mut fb_for),
        ServiceOutcome::Retained { .. }
    ) || presence.stopped()
        || presence.live()
        || !service_blocks_dc(&service)
    {
        return TestResult::Fail("a quarantined route must publish not stopped");
    }
    // The process-wide readers: a held service (a pass in progress, here
    // with nothing owned) reads stopped without a transient, while DC
    // re-entry stays refused for the contended service.
    let Some(held) = SERVICE.try_lock() else {
        return TestResult::Fail("the process-wide service must be free");
    };
    let owned = held.route().is_some();
    let stopped = routes_stopped();
    let blocks = external_route_blocks_dc();
    let live = route_live();
    drop(held);
    if owned || !stopped || live || !blocks {
        return TestResult::Fail("a held idle service must read stopped and block DC");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_route_presence_has_no_transient_readers
);

// ── The panel's KMS proofs beside a lit external (multi-pipe layout) ──────

/// `PLANE_BUF_CFG` / `CUR_BUF_CFG` of `pipe`.
fn ddb_regs(pipe: usize) -> [u64; 2] {
    [
        crate::intel_gpu_xelpg_resources::plane_buf_cfg(pipe, 0),
        crate::intel_gpu_xelpg_resources::cursor_buf_cfg(pipe),
    ]
}

/// The fixed timing of the owned panel `mode`.
fn panel_timing(mode: &Mode) -> crate::intel_gpu_dsb::Timing {
    crate::intel_gpu_dsb::Timing {
        clock: mode.pixel_clock_khz,
        width: mode.h_active,
        height: mode.v_active,
        htotal: mode.h_total,
        vtotal: mode.v_total,
        flags: 0,
    }
}

fn smoke_mtl_panel_profile_proves_its_share_beside_external() -> TestResult {
    use crate::intel_gpu_display_resources::{Primary, Profile};
    use crate::intel_gpu_xelpg_pipes::{published_layout, reset_published_layout};
    reset_published_layout();
    let io = ExtFake::new(XeLpgPort::Tc1, Sink::new(0x14, edid_1080()));
    let Some(panel) = io.light_panel() else {
        return TestResult::Fail("the fixture must light the owned panel");
    };
    // The owned modeset's no-DPT chicken on the panel primary.
    io.phy.write32(0x7_026C, 1 << 19);
    let Ok(single) = Profile::capture(&io, &panel) else {
        return TestResult::Fail("the owned single-pipe profile must hold first");
    };
    let dmc = DmcEvents::leak();
    let Ok(probe) = probe_sink(&io, Generation::MeteorLake, XeLpgPort::Tc1, false) else {
        return TestResult::Fail("probe must succeed");
    };
    let fb = fb_for(&probe.mode).unwrap();
    let mut route = match activate(&io, probe, fb, &beside(panel, dmc)) {
        Ok(route) if route.state() == RouteState::Live => route,
        _ => return TestResult::Fail("DP must light Pipe B next to the lit panel"),
    };
    // The Pipe B–D owner published what it programmed: the owned panel on
    // Pipe A, the route on Pipe B, and the route's scanout surface.
    let Some(layout) = published_layout() else {
        return TestResult::Fail("the Pipe B–D owner must publish the multi-pipe layout");
    };
    let panel_request = crate::intel_gpu_display_resources::request(
        &panel,
        crate::intel_gpu_xelpg_wm::Tiling::Linear,
        0,
    )
    .pipes[0];
    if layout.state.requests[0] != panel_request
        || layout.state.requests[1].is_none()
        || layout.surfaces != [None, Some(0x100_0000), None, None]
    {
        return TestResult::Fail("the published layout must name the panel and Pipe B");
    }
    // The panel's profile is now its share of the two-pipe layout: half
    // the DBUF, the multi-pipe cursor budget, the same wm_level_disabled.
    crate::intel_gpu_xelpg_wm::publish_pipe_a(None);
    let multi = match Profile::capture(&io, &panel) {
        Ok(profile) => profile,
        Err(_) => return TestResult::Fail("the panel profile must hold beside the external"),
    };
    let share = &layout.state.dbuf.pipes[0];
    if multi.cursor_start != share.cursor.start
        || multi.cursor_start >= 2048
        || multi.cursor_start == single.cursor_start
        || multi.primary != share.wm[0]
        || multi.cursor != share.cursor_wm
        || io.read32(ddb_regs(0)[1]) != share.cursor.reg()
        || multi.cursor_registers(true).last() != Some(&(ddb_regs(0)[1], share.cursor.reg()))
    {
        return TestResult::Fail("the profile must use Pipe A's actual multi-pipe allocation");
    }
    if multi.wm_level_disabled != single.wm_level_disabled
        || crate::intel_gpu_xelpg_wm::pipe_a_wm_level_disabled() != Some(multi.wm_level_disabled)
    {
        return TestResult::Fail("the proof must publish Pipe A's wm_level_disabled");
    }
    // The retained primary owner stages the Tile4 image of this layout.
    let Ok(mut primary) = Primary::capture(&io, panel_timing(&panel)) else {
        return TestResult::Fail("the primary owner must capture beside the external");
    };
    let Ok(latency) = crate::intel_gpu_xelpg_wm::Latency::read(&io) else {
        return TestResult::Fail("latencies must read");
    };
    let Ok(tile4) = layout
        .state
        .retile(0, crate::intel_gpu_xelpg_wm::Tiling::Tile4, &latency)
    else {
        return TestResult::Fail("Tile4 must retile within Pipe A's allocation");
    };
    let want = crate::intel_gpu_xelpg_resources::plane_wm_image(0, 0, &tile4.dbuf.pipes[0].wm[0])
        .map(|image| image.to_vec());
    match primary.stage(&io, true) {
        Ok(image) if Some(&image) == want.as_ref() => {}
        _ => return TestResult::Fail("Tile4 must take the multi-pipe Tile4 watermarks"),
    }
    primary.rollback();
    // The KMS takeover inventory admits exactly the route's primary.
    if crate::intel_gpu_kms::inherited_fetchers_idle(&io, Generation::MeteorLake).is_err() {
        return TestResult::Fail("the route's own Pipe B primary is not an inherited fetcher");
    }
    io.phy.write32(PLANE_SURF_1_B, 0x0A00_0000);
    let foreign_surface =
        crate::intel_gpu_kms::inherited_fetchers_idle(&io, Generation::MeteorLake)
            == Err(narf_filesystem::FsError::Unsupported);
    io.phy.write32(PLANE_SURF_1_B, 0x100_0000);
    // Diverged or foreign multi-pipe states still refuse.
    io.set_conf(2, ENABLE);
    let foreign_pipe = Profile::capture(&io, &panel).is_err();
    io.set_conf(2, 0);
    let [plane_b, _] = ddb_regs(1);
    let held = io.read32(plane_b);
    io.phy.write32(plane_b, held + 1);
    let moved_ddb = Profile::capture(&io, &panel).is_err();
    io.phy.write32(plane_b, held);
    let [plane_a, _] = ddb_regs(0);
    let held = io.read32(plane_a);
    io.phy.write32(plane_a, 2047 << 16);
    let grown_panel = Profile::capture(&io, &panel).is_err();
    io.phy.write32(plane_a, held);
    let mbus = io.read32(crate::intel_gpu_xelpg_dbuf::MBUS_CTL);
    io.phy.write32(
        crate::intel_gpu_xelpg_dbuf::MBUS_CTL,
        (mbus & !(7 << 26)) | (2 << 26),
    );
    let dark_select = Profile::capture(&io, &panel).is_err();
    io.phy.write32(crate::intel_gpu_xelpg_dbuf::MBUS_CTL, mbus);
    reset_published_layout();
    let unpublished = Profile::capture(&io, &panel).is_err();
    let unknown = crate::intel_gpu_xelpg_wm::pipe_a_wm_level_disabled().is_none();
    crate::intel_gpu_xelpg_pipes::publish_layout_for_test(Some(layout));
    if !foreign_surface || !foreign_pipe || !moved_ddb || !grown_panel || !dark_select {
        return TestResult::Fail("a foreign or diverged multi-pipe state must refuse");
    }
    if !unpublished || !unknown {
        return TestResult::Fail("an unpublished layout must refuse and publish unknown");
    }
    if Profile::capture(&io, &panel) != Ok(multi) {
        return TestResult::Fail("the restored layout must prove again");
    }
    // Removal: the single-pipe profile holds again and nothing is published.
    if route.stop(&io).is_err() || published_layout().is_some() {
        return TestResult::Fail("the release must withdraw the published layout");
    }
    if Profile::capture(&io, &panel) != Ok(single) || route.release(&io).is_err() {
        return TestResult::Fail("the panel must prove its single-pipe profile again");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_panel_profile_proves_its_share_beside_external
);

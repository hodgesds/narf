//! Native register/sink conversations for the owned MTL external route.
extern crate alloc;

use super::*;
use crate::intel_gpu_aux::{
    AUX_CTL_DONE, AUX_CTL_MSGSIZE_MASK, AUX_CTL_MSGSIZE_SHIFT, AUX_CTL_SEND_BUSY, AUX_CTL_TBT_IO,
    XELPDP_AUX_CH_CTL_POWER_REQUEST,
};
use crate::intel_gpu_modeset::PixelFormat;
use crate::intel_gpu_xelpg::tests::FakePhy;
use crate::intel_gpu_xelpg::{TCSS_POWER_REQUEST, TC_PHY_OWNERSHIP};
use crate::intel_gpu_xelpg_hpd::{
    pica_dp_alt_hotplug, pica_tbt_hotplug, port_hotplug_ctl, LiveMode, MtlHpdConfig, MtlHpdMonitor,
    DP_ALT_HPD_LONG_DETECT, PICA_IIR, PICA_ISR, SDE_IIR, SDE_ISR, SHOTPLUG_CTL_DDI,
    SHOTPLUG_CTL_TC,
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

const PIPECONF: u64 = 0x7_0008;
const CDCLK_PLL: u64 = 0x4_6070;

/// MTL display model for one external port: `FakePhy` (message bus, PLL
/// acks, BUF_CTL1 D2D/PHY_IDLE/TCSS mirrors), HSW-encoded power wells,
/// the CDCLK PLL lock, pipe A state and frame counter, the LIVE surface,
/// Type-C IOM/FIA facts, PICA/SDE levels and W1C latches, and a DP sink
/// behind the port's Xe-LPDP AUX channel.
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
    pipeconf: Cell<u32>,
    pub pipeconf_stuck: Cell<bool>,
    frame: Cell<u32>,
    pub sink: RefCell<Sink>,
    aux_data: RefCell<[u32; 5]>,
    aux_reply: RefCell<Vec<u8>>,
    aux_done: Cell<u32>,
    aux_power: Cell<bool>,
    pub aux_ctl_writes: RefCell<Vec<u32>>,
    pub writes: RefCell<Vec<(u64, u32)>>,
}

impl ExtFake {
    pub fn new(port: XeLpgPort, sink: Sink) -> Self {
        let phy = FakePhy::new(port);
        phy.model_d2d.set(true);
        phy.model_ddi_idle.set(true);
        phy.model_tcss.set(true);
        let pica = port.tc_index().map_or(0, pica_dp_alt_hotplug);
        let sde = if port == XeLpgPort::B { 1 << 17 } else { 0 };
        Self {
            phy,
            port,
            access: Cell::new(true),
            pica_isr: Cell::new(pica),
            sde_isr: Cell::new(sde),
            pin: Cell::new(PIN_ASSIGNMENT_C),
            ready: Cell::new(true),
            cdclk_pll: Cell::new(0),
            pipeconf: Cell::new(0),
            pipeconf_stuck: Cell::new(false),
            frame: Cell::new(0),
            sink: RefCell::new(sink),
            aux_data: RefCell::new([0; 5]),
            aux_reply: RefCell::new(Vec::new()),
            aux_done: Cell::new(0),
            aux_power: Cell::new(false),
            aux_ctl_writes: RefCell::new(Vec::new()),
            writes: RefCell::new(Vec::new()),
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
    fn w1c(&self, off: u64) -> u32 {
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
        if off == PWR_WELL_CTL2 {
            let s = self.phy.read32(off);
            return s | ((s & 0xAAAA_AAAA) >> 1);
        }
        if off == CDCLK_PLL {
            let s = self.cdclk_pll.get();
            return if s & ENABLE != 0 { s | STATE } else { s };
        }
        let enabled = self.pipeconf.get() & ENABLE != 0;
        if off == PIPECONF {
            let s = self.pipeconf.get();
            return if enabled || self.pipeconf_stuck.get() {
                s | STATE
            } else {
                s
            };
        }
        if off == PIPE_FRMCOUNT_A {
            if enabled {
                self.frame.set(self.frame.get().wrapping_add(1));
            }
            return self.frame.get();
        }
        if off == PLANE_SURFLIVE_1_A {
            return if enabled {
                self.phy.read32(PLANE_SURF_1_A)
            } else {
                0
            };
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
        let mask = self.w1c(off);
        if mask != 0 {
            let old = self.phy.read32(off);
            self.phy
                .write32(off, (old & mask & !value) | (value & !mask));
            return;
        }
        if off == CDCLK_PLL {
            self.cdclk_pll.set(value);
            return;
        }
        if off == PIPECONF {
            self.pipeconf.set(value & !STATE);
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
    match activate(io, probe, fb) {
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
    // PW_1, PW_2 (TC DDI lanes) and PW_A.
    let wells = io.read32(PWR_WELL_CTL2);
    for idx in [PW_1_IDX, PW_2_IDX, PW_A_IDX] {
        if wells & pwr_well_req(idx) == 0 {
            return TestResult::Fail("PW_1/PW_2/PW_A must be requested");
        }
    }
    // Source port/PHY numbering: PHY_G for TC2, PORT_TC2 = 4.
    if io.writes_to(TRANS_CLK_SEL_A).first() != Some(&0x7000_0000) {
        return TestResult::Fail("TRANS_CLK_SEL must select PHY_G for TC2");
    }
    let func = io.writes_to(TRANS_DDI_FUNC_CTL_A);
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
    let tp = io.writes_to(DP_TP_CTL_A);
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
    if route.probe.tc.is_some() || io.writes_to(TRANS_CLK_SEL_A).first() != Some(&0x2000_0000) {
        return TestResult::Fail("DDI B route must use PHY_B without Type-C ownership");
    }
    if io.read32(PWR_WELL_CTL2) & pwr_well_req(PW_2_IDX) != 0 {
        return TestResult::Fail("DDI B must not request the TC lane well");
    }
    if route.stop(&io).is_err() || route.state() != RouteState::Stopped {
        return TestResult::Fail("local stop must be proven");
    }
    let port = XeLpgPort::B;
    if io.read32(PIPECONF) & (ENABLE | STATE) != 0
        || io.read32(port.ddi_buf_ctl()) & DDI_BUF_CTL_ENABLE != 0
        || io.read32(port.buf_ctl1()) & PORT_BUF_PHY_IDLE == 0
        || io.read32(port.port_clock_ctl()) & 0xCC00_0000 != 0
        || io.read32(TRANS_CLK_SEL_A) != 0
        || io.read32(TRANS_DDI_FUNC_CTL_A) & (TRANS_DDI_FUNC_ENABLE | TRANS_DDI_PORT_AND_MODE) != 0
        || io.read32(DP_TP_CTL_A) & DP_TP_CTL_ENABLE != 0
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
        .rposition(|&(o, v)| o == PLANE_CTL_1_A && v & ENABLE == 0);
    let pipe_off = writes
        .iter()
        .rposition(|&(o, v)| o == PIPECONF && v & ENABLE == 0);
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
            io.pipeconf.set(ENABLE);
        } else {
            io.phy
                .write32(XeLpgPort::Tc1.ddi_buf_ctl(), DDI_BUF_CTL_ENABLE);
        }
        let before = io.writes.borrow().len();
        let fb = fb_for(&probe.mode).unwrap();
        let probe = match activate(&io, probe, fb) {
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
    // Full retry: PLL zeroed by the local stop, then re-enabled.
    if io.phy.writes_to(0x6_4530) != [162_000, 0, 162_000] {
        return TestResult::Fail("retry must stop and re-enable the PLL");
    }
    let want = crate::intel_gpu_pipes::build_trans_ddi_func_ctl(
        5,
        crate::intel_gpu_pipes::TRANS_DDI_MODE_DP_SST,
        2,
    );
    if io.read32(TRANS_DDI_FUNC_CTL_A) != want
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
    match activate(&io, probe, fb) {
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
    if probe_sink(&io, Generation::MeteorLake, XeLpgPort::Tc4, false).err()
        != Some(ExternalError::Tc(TcError::TbtAltUnsupported))
        || !io.writes.borrow().is_empty()
    {
        return TestResult::Fail("TBT-alt sink must refuse without writes");
    }
    let mut service = MtlExternalService::new();
    let event = MtlHpdEvent {
        pin: MtlHpdPin::Tc4,
        kind: MtlHpdKind::Connected(LiveMode::TbtAlt),
    };
    match service.handle(&NoAccess, event, &mut fb_for) {
        ServiceOutcome::Refused {
            error: ExternalError::Tc(TcError::TbtAltUnsupported),
            ..
        } => {}
        _ => return TestResult::Fail("TBT connect event must be refused without MMIO"),
    }
    if service_mtl_external(&NoAccess, Generation::AlderLake, &mut fb_for).is_some()
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
    match activate(&io, probe, fb) {
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
            ) || service.route().map(MtlExternalRoute::state) != Some(RouteState::Live)
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

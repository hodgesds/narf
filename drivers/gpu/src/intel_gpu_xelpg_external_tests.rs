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
            error: RouteError::Dp(ExternalError::Tc(TcError::TbtAltUnsupported)),
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
            RoutePlan::Refuse,
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
                dp: true,
                hdmi: true,
                legacy: true,
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
        dp: false,
        hdmi: true,
        legacy: false,
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
    // The DP attempt released its AUX power; HDMI owns pipe A on DDI B.
    let func = crate::intel_gpu_pipes::build_trans_ddi_func_ctl_hdmi(1, false, false);
    if io.aux_power.get()
        || io.read32(TRANS_DDI_FUNC_CTL_A) != func
        || io.read32(XeLpgPort::B.ddi_buf_ctl()) & DDI_BUF_CTL_ENABLE == 0
        || service.route().map(MtlRoute::protocol) != Some(MtlProtocol::Hdmi)
        || service.route().map(MtlRoute::live) != Some(true)
        || !io.writes_to(DP_TP_CTL_A).is_empty()
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
        || io.read32(PIPECONF_A) & (ENABLE | STATE) != 0
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
        || io.ddc.writes_to(crate::intel_gpu_gmbus::GMBUS0).first() != Some(&10)
        || io.read32(TRANS_CLK_SEL_A) != 0x7000_0000
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

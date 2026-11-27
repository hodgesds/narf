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
    TCSS_DDI_STATUS_PIN_ASSIGNMENT_SHIFT, TCSS_DDI_STATUS_READY,
};
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use narf_kernel_test::{kernel_test_in, TestResult};

// ── DP sink: native DPCD, link-training state, I2C EDID at 0x50 ─────

#[derive(Debug)]
pub struct Sink {
    caps: [u8; 16],
    extended_caps: Option<[u8; 15]>,
    edid: Vec<u8>,
    i2c_ptr: usize,
    lanes_set: u8,
    pattern: u8,
    training_writes: Vec<(u32, u8)>,
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
    /// Inject NACKs on DP_FEC_STATUS reads while the link is trained.
    fec_status_nacks: u8,
    /// Native writes to the DSC/FEC registers, in order.
    pub dsc_log: Vec<(u32, u8)>,
    /// DP 2.0: `DP_128B132B_SUPPORTED_LINK_RATES` (0 for an 8b/10b sink).
    pub uhbr_rates: u8,
    /// `DP_MAIN_LINK_CHANNEL_CODING_SET`.
    pub coding: u8,
    /// The TX FFE preset the 128b/132b sink asks for on each lane.
    pub ffe_request: [u8; 4],
    /// `DP_PAYLOAD_TABLE_UPDATE_STATUS`.
    pub payload_status: u8,
    /// Native writes to the 128b/132b and payload registers, in order.
    pub uhbr_log: Vec<(u32, u8)>,
    /// Native reads of the 128b/132b capability registers.
    pub uhbr_reads: Vec<u32>,
    /// The last `DP_LINK_BW_SET`.
    pub link_bw: u8,
    /// A `DP_LINK_BW_SET` code at which 128b/132b training reports
    /// `DP_128B132B_LT_FAILED` (0: never).
    pub uhbr_lt_fail_bw: u8,
    /// 128b/132b training reports `DP_128B132B_LT_FAILED` with more lanes
    /// than this (0: never).
    pub uhbr_lt_fail_lanes: u8,
    /// Further DPCD bytes the sink reports.
    pub extra: Vec<(u32, u8)>,
    /// Native writes to `DP_PROTOCOL_CONVERTER_CONTROL_0..=2`, in order.
    pub pcon_log: Vec<(u32, u8)>,
    /// A USB4 DP IN adapter's tunnel DPCD (0xe0000..=0xe0031) in front of
    /// the sink: its connection manager grants every `DP_REQUEST_BW` at once
    /// (`DP_ALLOCATED_BW` takes the request, `DP_BW_REQUEST_SUCCEEDED`).
    pub tunnel: Option<[u8; 0x32]>,
    /// Native writes to the tunnel registers, in order.
    pub tunnel_log: Vec<(u32, u8)>,
}

impl Sink {
    pub fn new(max_bw: u8, edid: Vec<u8>) -> Self {
        let mut caps = [0u8; 16];
        caps[0] = 0x14;
        caps[1] = max_bw;
        caps[2] = 4 | 0x40 | 0x80;
        Self {
            caps,
            extended_caps: None,
            edid,
            i2c_ptr: 0,
            lanes_set: 0,
            pattern: 0,
            training_writes: Vec::new(),
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
            fec_status_nacks: 0,
            dsc_log: Vec::new(),
            uhbr_rates: 0,
            coding: 0,
            ffe_request: [0; 4],
            payload_status: 0,
            uhbr_log: Vec::new(),
            uhbr_reads: Vec::new(),
            link_bw: 0,
            uhbr_lt_fail_bw: 0,
            uhbr_lt_fail_lanes: 0,
            extra: Vec::new(),
            pcon_log: Vec::new(),
            tunnel: None,
            tunnel_log: Vec::new(),
        }
    }
    /// A DP 2.0 sink: `DP_CAP_ANSI_128B132B` with `uhbr_rates`.
    pub fn dp20(max_bw: u8, edid: Vec<u8>, uhbr_rates: u8) -> Self {
        let mut sink = Self::new(max_bw, edid);
        sink.caps[6] |= 1 << 1;
        sink.uhbr_rates = uhbr_rates;
        sink
    }
    fn uhbr(&self) -> bool {
        self.coding == uhbr::DP_SET_ANSI_128B132B
    }
    /// The 128b/132b lane status of lanes `2 * pair` and `2 * pair + 1`:
    /// CHANNEL_EQ_DONE from TPS2 on, SYMBOL_LOCKED from the CDS phase on.
    fn uhbr_status(&self, pair: usize) -> u8 {
        let mut nibble = 0;
        if self.eq_locked {
            nibble |= uhbr::DP_LANE_CHANNEL_EQ_DONE;
        }
        if self.cr_locked {
            nibble |= uhbr::DP_LANE_SYMBOL_LOCKED;
        }
        let lanes = usize::from(self.lanes_set);
        let mut byte = 0;
        for half in 0..2 {
            if pair * 2 + half < lanes {
                byte |= nibble << (half * 4);
            }
        }
        byte
    }
    pub fn drop_lock(&mut self) {
        self.cr_locked = false;
        self.eq_locked = false;
    }
    pub(super) fn training_writes_to(&self, reg: u32) -> Vec<u8> {
        self.training_writes
            .iter()
            .filter_map(|&(r, v)| (r == reg).then_some(v))
            .collect()
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
        if self.uhbr() {
            // 128b/132b: TPS2 equalizes (CHANNEL_EQ_DONE with the interlane
            // and EQ-interlane alignment), TPS2_CDS locks symbols and aligns
            // the CDS; disabling the pattern keeps the trained state.
            match addr {
                0x202 => return self.uhbr_status(0),
                0x203 => return self.uhbr_status(1),
                0x204 if self.uhbr_lt_fail_bw != 0 && self.link_bw == self.uhbr_lt_fail_bw => {
                    return uhbr::DP_128B132B_LT_FAILED;
                }
                0x204
                    if self.uhbr_lt_fail_lanes != 0 && self.lanes_set > self.uhbr_lt_fail_lanes =>
                {
                    return uhbr::DP_128B132B_LT_FAILED;
                }
                0x204 => {
                    return match (self.eq_locked, self.cr_locked) {
                        (true, true) => {
                            uhbr::DP_INTERLANE_ALIGN_DONE
                                | uhbr::DP_128B132B_DPRX_EQ_INTERLANE_ALIGN_DONE
                                | uhbr::DP_128B132B_DPRX_CDS_INTERLANE_ALIGN_DONE
                        }
                        (true, false) => {
                            uhbr::DP_INTERLANE_ALIGN_DONE
                                | uhbr::DP_128B132B_DPRX_EQ_INTERLANE_ALIGN_DONE
                        }
                        _ => 0,
                    }
                }
                0x205 => return 0,
                0x206 => return self.ffe_request[0] | (self.ffe_request[1] << 4),
                0x207 => return self.ffe_request[2] | (self.ffe_request[3] << 4),
                _ => {}
            }
        }
        if let Some(t) = &self.tunnel {
            if (0xe_0000..=0xe_0031).contains(&addr) {
                return t[(addr - 0xe_0000) as usize];
            }
        }
        match addr {
            0x000..=0x00F => self.caps[addr as usize],
            uhbr::DP_128B132B_SUPPORTED_LINK_RATES => {
                self.uhbr_reads.push(addr);
                self.uhbr_rates
            }
            0xf_0000..=0xf_0007 => {
                self.uhbr_reads.push(addr);
                self.extra
                    .iter()
                    .find(|(a, _)| *a == addr)
                    .map_or(0, |(_, v)| *v)
            }
            uhbr::DP_PAYLOAD_TABLE_UPDATE_STATUS => self.payload_status,
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
            0x280 => self.fec_status,
            _ => self
                .extra
                .iter()
                .find(|(a, _)| *a == addr)
                .map_or(0, |(_, v)| *v),
        }
    }
    fn write_byte(&mut self, addr: u32, value: u8) {
        if let Some(t) = self.tunnel.as_mut() {
            if (0xe_0000..=0xe_0031).contains(&addr) {
                self.tunnel_log.push((addr, value));
                match addr {
                    tunnel::DP_TUNNELING_STATUS => t[0x25] &= !value,
                    tunnel::DP_REQUEST_BW => {
                        t[0x31] = value;
                        t[0x24] = value;
                        t[0x25] |= tunnel::DP_BW_REQUEST_SUCCEEDED;
                    }
                    _ => t[(addr - 0xe_0000) as usize] = value,
                }
                return;
            }
        }
        match addr {
            0x101 => {
                self.training_writes.push((addr, value));
                self.lanes_set = value & 0x1F;
                self.drop_lock();
            }
            0x102 if self.uhbr() => {
                self.training_writes.push((addr, value));
                self.uhbr_log.push((addr, value));
                match value {
                    1 => self.drop_lock(),
                    2 => self.eq_locked = self.powered,
                    3 => self.cr_locked = self.eq_locked,
                    _ => {}
                }
                self.pattern = value & 0x7;
            }
            0x102 => {
                self.training_writes.push((addr, value));
                self.pattern = value & 0x7;
                self.polls = 0;
            }
            0x100 | 0x107 | 0x108 | 0x119 | 0x121 | 0x1c0..=0x1c2 | 0xf_0003 | 0xf_0005 => {
                self.uhbr_log.push((addr, value));
                match addr {
                    0x100 => {
                        self.drop_lock();
                        self.polls = 0;
                        self.link_bw = value;
                    }
                    0x108 => self.coding = value,
                    // DP_PAYLOAD_ALLOCATE_SET's last byte updates the table.
                    0x1c2 => self.payload_status |= uhbr::DP_PAYLOAD_TABLE_UPDATED,
                    _ => {}
                }
            }
            uhbr::DP_PAYLOAD_TABLE_UPDATE_STATUS => {
                self.uhbr_log.push((addr, value));
                self.payload_status &= !value;
            }
            // The PHY repeaters' training registers (per-hop 8b/10b): logged,
            // the pattern sets also in order with the DPRX's.
            0xf_0010..=0xf_02ff => {
                self.uhbr_log.push((addr, value));
                if (addr - 0xf_0010) % 0x50 == 0 {
                    self.training_writes.push((addr, value));
                }
            }
            0x120 | 0x160 | 0x280 => {
                self.dsc_log.push((addr, value));
                match addr {
                    0x120 => self.fec_config = value,
                    0x160 => self.dsc_enable = value,
                    _ => self.fec_status &= !value,
                }
            }
            0x3050..=0x3052 => self.pcon_log.push((addr, value)),
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
        if cmd == 0x9 && addr == dsc::DP_FEC_STATUS && self.fec_status_nacks != 0 {
            self.fec_status_nacks -= 1;
            return alloc::vec![0x10];
        }
        if cmd & 0x8 == 0 && addr != 0x50 {
            return alloc::vec![0x40];
        }
        if wire.len() == 3 {
            return alloc::vec![0x00];
        }
        let len = wire[3] as usize + 1;
        if cmd == 0x9 && addr == 0x2200 {
            if let Some(extended) = self.extended_caps.filter(|caps| len == caps.len()) {
                let mut reply = alloc::vec![0x00];
                reply.extend_from_slice(&extended);
                return reply;
            }
            return alloc::vec![0x10];
        }
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

pub(crate) fn edid_1024() -> Vec<u8> {
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
    display_ip: Cell<DisplayIp>,
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
    /// Number of FEC rising edges the source will fail to acknowledge.
    fec_missed_enables: Cell<u8>,
    /// Override Pipe B's transport status after FEC has been disabled.
    fec_stop_status: Cell<Option<u32>>,
    /// Drop Pipe B's live FEC indication on enabling this register.
    fec_drop_on_enable: Cell<Option<u64>>,
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
            display_ip: Cell::new(DisplayIp::Xelpdp),
            access: Cell::new(true),
            pica_isr: Cell::new(pica),
            sde_isr: Cell::new(sde),
            pin: Cell::new(PIN_ASSIGNMENT_C),
            ready: Cell::new(true),
            cdclk_pll: Cell::new(0),
            confs: Default::default(),
            pipeconf_stuck: Cell::new(false),
            act_stuck: Cell::new(false),
            fec_missed_enables: Cell::new(0),
            fec_stop_status: Cell::new(None),
            fec_drop_on_enable: Cell::new(None),
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
        self.light_panel_ip(DisplayIp::Xelpdp)
    }

    /// Light the owned panel with `ip`'s resource state.
    pub(crate) fn light_panel_ip(&self, ip: DisplayIp) -> Option<Mode> {
        let mode = Mode::VESA_1024X768_60;
        self.display_ip.set(ip);
        self.phy.c20_port_b.set(ip == DisplayIp::Xe3Lpd);
        let release = if ip == DisplayIp::WildcatLake { 2 } else { 0 };
        self.phy
            .write32(0x5_10A0, (u32::from(ip.ver()) << 22) | (release << 14));
        self.phy.write32(0x4_5004, 1 << 3);
        // Display 35 reads its latencies without the reported level 0, as
        // the Pipe B-D owner's panel adoption does.
        let latency = if ip == DisplayIp::NovaLakeS {
            crate::intel_gpu_xelpg_wm::Latency::read_ip(self, ip)
        } else {
            crate::intel_gpu_xelpg_wm::Latency::read(self)
        }
        .ok()?;
        let mut vblank_start = [None; 4];
        if ip.is_display30() {
            let guardband =
                crate::intel_gpu_xe3lpd::vrr_guardband_for(self, ip, &mode, None, &latency).ok()?;
            vblank_start[0] = Some(mode.v_total - guardband);
        }
        let state = crate::intel_gpu_xelpg_resources::compute_ip_vblank(
            ip,
            &crate::intel_gpu_display_resources::request(
                &mode,
                crate::intel_gpu_xelpg_wm::Tiling::Linear,
                0,
            ),
            &latency,
            vblank_start,
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
            // On 128b/132b the source keeps TPS2 through the CDS phase and
            // the pattern disable (intel_dp_128b132b_link_train).
            let expected = match (self.sink.borrow().uhbr(), wire[4] & 7) {
                (true, 1) => 0,
                (true, 0 | 2 | 3) => 1,
                (_, 0) => 3,
                (_, 1) => 0,
                (_, 2) => 1,
                (_, 3) => 4,
                (_, 7) => 5,
                _ => 7,
            };
            let correct = (0..4).any(|pipe| {
                let source = self.phy.read32(0x60540 + pipe * 0x1000);
                source & (1 << 31) != 0
                    && (source >> 8) & 7 == expected
                    && (source & (1 << 7) != 0) == (wire[4] & (1 << 5) != 0)
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
    fn cx0_xe3(&self) -> bool {
        self.display_ip.get().is_display30()
    }
    fn cx0_c20_port_b(&self) -> bool {
        self.phy.c20_port_b.get()
    }
    fn read32(&self, off: u64) -> u32 {
        if !self.access.get() {
            return u32::MAX;
        }
        if off == crate::intel_gpu_xelpg_tc::TCSS_DISP_MAILBOX_IN_CMD {
            return self.phy.read32(off) & !crate::intel_gpu_xelpg_tc::TCSS_DISP_MAILBOX_RUN_BUSY;
        }
        if (0..4).any(|p| off == 0x60544 + p * 0x1000) {
            if off == DP_TP_CTL_B + 4
                && self.phy.read32(DP_TP_CTL_B) & dsc::DP_TP_CTL_FEC_ENABLE == 0
            {
                if let Some(status) = self.fec_stop_status.get() {
                    return status;
                }
            }
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
        if off == crate::intel_gpu_xe2lpd::PICA_PW_CTL {
            let value = self.phy.read32(off);
            return (value & !crate::intel_gpu_xe2lpd::PICA_POWER_STATUS)
                | if value & crate::intel_gpu_xe2lpd::PICA_POWER_REQUEST != 0 {
                    crate::intel_gpu_xe2lpd::PICA_POWER_STATUS
                } else {
                    0
                };
        }
        if off == self.port.ddi_buf_ctl() && self.display_ip.get().xe2_plus() {
            let value = self.phy.read32(off);
            return (value & !crate::intel_gpu_xe2lpd::DDI_BUF_D2D_LINK_STATE)
                | if value & crate::intel_gpu_xe2lpd::DDI_BUF_D2D_LINK_ENABLE != 0 {
                    crate::intel_gpu_xe2lpd::DDI_BUF_D2D_LINK_STATE
                } else {
                    0
                };
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
                        | (u32::from(self.pin.get()) << TCSS_DDI_STATUS_PIN_ASSIGNMENT_SHIFT)
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
        if self.fec_drop_on_enable.get() == Some(off) && value & ENABLE != 0 {
            let status = DP_TP_CTL_B + 4;
            self.phy.write32(
                status,
                self.phy.read32(status) & !dsc::DP_TP_STATUS_FEC_ENABLE_LIVE,
            );
        }
        if (0..4).any(|p| off == 0x60540 + p * 0x1000)
            && (self.phy.read32(off) ^ value) & dsc::DP_TP_CTL_FEC_ENABLE != 0
        {
            let mut status = self.phy.read32(off + 4) & !dsc::DP_TP_STATUS_FEC_ENABLE_LIVE;
            if value & dsc::DP_TP_CTL_FEC_ENABLE != 0 {
                if self.fec_missed_enables.get() == 0 {
                    status |= dsc::DP_TP_STATUS_FEC_ENABLE_LIVE;
                    let mut sink = self.sink.borrow_mut();
                    if sink.eq_locked && sink.fec_config & 1 != 0 {
                        // DP_FEC_DECODE_EN_DETECTED is latched until W1C.
                        sink.fec_status |= 1;
                    }
                } else {
                    self.fec_missed_enables
                        .set(self.fec_missed_enables.get() - 1);
                }
            }
            self.phy.write32(off + 4, status);
        }
        if (0..4).any(|p| off == 0x60400 + p * 0x1000)
            && (self.phy.read32(off) ^ value) & (1 << 8) != 0
            && !self.act_stuck.get()
        {
            let master = (value >> 10) & 3;
            let status = 0x60544 + u64::from(master) * 0x1000;
            self.phy
                .write32(status, self.phy.read32(status) | (1 << 24));
            let mut sink = self.sink.borrow_mut();
            if sink.uhbr() {
                sink.payload_status |= uhbr::DP_PAYLOAD_ACT_HANDLED;
            }
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

pub(crate) fn fb_for(mode: &Mode) -> Option<Framebuffer> {
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

fn smoke_lnl_external_tc_dp_alt_uses_display20_d2d() -> TestResult {
    let io = ExtFake::new(XeLpgPort::Tc1, Sink::new(0x14, edid_1024()));
    let Some(panel) = io.light_panel_ip(DisplayIp::Xe2Lpd) else {
        return TestResult::Fail("the fixture must light the display-20 panel");
    };
    let probe = match probe_sink(&io, Generation::LunarLake, XeLpgPort::Tc1, false) {
        Ok(probe) => probe,
        Err(_) => return TestResult::Fail("LNL TC1 probe must own PICA/TCSS/AUX"),
    };
    if probe.display_version() != 20
        || probe
            .tc
            .is_none_or(|tc| tc.profile != TcDisplayProfile::Xe2Lpd)
    {
        return TestResult::Fail("the sink probe must retain the display-20 layout");
    }
    let fb = fb_for(&probe.mode).unwrap();
    let display = MtlDisplay {
        panel: Some(panel),
        pipe_dmc: &NoPipeDmc,
    };
    let mut route = match activate(&io, probe, fb, &display) {
        Ok(route) => route,
        Err(_) => return TestResult::Fail("LNL USB-C DP must activate beside Pipe A"),
    };
    let ddi = io.read32(XeLpgPort::Tc1.ddi_buf_ctl());
    if ddi
        & (DDI_BUF_CTL_ENABLE
            | crate::intel_gpu_xe2lpd::DDI_BUF_D2D_LINK_ENABLE
            | crate::intel_gpu_xe2lpd::DDI_BUF_D2D_LINK_STATE)
        != DDI_BUF_CTL_ENABLE
            | crate::intel_gpu_xe2lpd::DDI_BUF_D2D_LINK_ENABLE
            | crate::intel_gpu_xe2lpd::DDI_BUF_D2D_LINK_STATE
        || io.read32(XeLpgPort::Tc1.buf_ctl1()) & crate::intel_gpu_xelpg::PORT_BUF_D2D_LINK_ENABLE
            != 0
    {
        return TestResult::Fail("display 20 must keep D2D in DDI_BUF_CTL only");
    }
    if io
        .writes_to(XeLpgPort::Tc1.ddi_buf_ctl())
        .iter()
        .all(|value| value & crate::intel_gpu_xe2lpd::DDI_BUF_D2D_LINK_ENABLE == 0)
    {
        return TestResult::Fail("the full DDI enable must preserve the D2D request");
    }
    // Display 20 has no PLANE_CHICKEN_DISABLE_DPT and does not set the
    // display-14 FEC jitter workaround in CHICKEN_TRANS.
    for plane in 0..4u64 {
        if !io
            .writes_to(Pipe::B.base() + 0x180 + plane * 0x100 + 0xec)
            .is_empty()
        {
            return TestResult::Fail("display 20 must not write the no-DPT chicken");
        }
    }
    if io.read32(Pipe::B.transcoder().base() + 0x4e0) & crate::intel_gpu_xe2lpd::DP_FEC_BS_JITTER_WA
        != 0
    {
        return TestResult::Fail("display 20 must leave the display-14 FEC WA clear");
    }
    if route.stop(&io).is_err()
        || route.release(&io).is_err()
        || io.read32(crate::intel_gpu_xe2lpd::PICA_PW_CTL)
            & crate::intel_gpu_xe2lpd::PICA_POWER_REQUEST
            != 0
    {
        return TestResult::Fail("LNL stop must drop D2D and release PICA ownership");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_lnl_external_tc_dp_alt_uses_display20_d2d
);

/// Panther Lake's DDI B is a non-Type-C C20 (`intel_encoder_is_c10phy`):
/// the route programs it without Type-C ownership, stages a DP 1.4
/// `mtl_c20_dp_*` MPLLB state through the C20 SRAM window (the states
/// `xe3lpd_c20_dp_edp_tables` carries at those rates), never opens the C10
/// VDR batch, and powers the PHY down to P4PG when it stops.
fn smoke_ptl_external_ddi_b_programs_its_c20() -> TestResult {
    use crate::intel_gpu_xelpg::{
        c20_pll_state, lane_powerdown_new_state, phy_kind, PhyKind, C10_VDR_CONTROL_1,
        P4PG_STATE_DISABLE, POWERDOWN_NEW_STATE_MASK_BOTH,
    };
    let port = XeLpgPort::B;
    let io = ExtFake::new(port, Sink::new(0x14, edid_1024()));
    let Some(panel) = io.light_panel_ip(DisplayIp::Xe3Lpd) else {
        return TestResult::Fail("the fixture must light the display-30 panel");
    };
    if phy_kind(&io, port) != PhyKind::C20 {
        return TestResult::Fail("Panther Lake DDI B must be a C20");
    }
    let probe = match probe_sink(&io, Generation::PantherLake, port, false) {
        Ok(probe) => probe,
        Err(_) => return TestResult::Fail("PTL DDI B probe must succeed"),
    };
    if probe.tc.is_some() || probe.display_version() != 30 {
        return TestResult::Fail("PTL DDI B has no Type-C ownership and keeps display 30");
    }
    let fb = fb_for(&probe.mode).unwrap();
    let display = MtlDisplay {
        panel: Some(panel),
        pipe_dmc: &NoPipeDmc,
    };
    let mut route = match activate(&io, probe, fb, &display) {
        Ok(route) if route.state() == RouteState::Live => route,
        _ => return TestResult::Fail("PTL DDI B DP must activate beside Pipe A"),
    };
    let words = io.phy.sram_values();
    let staged = [162_000u32, 270_000, 540_000, 810_000].iter().any(|clock| {
        c20_pll_state(*clock).is_some_and(|s| s.mpllb.iter().all(|w| words.contains(w)))
    });
    if !staged {
        return TestResult::Fail("the C20 SRAM must hold a DP 1.4 MPLLB state");
    }
    if (0..2).any(|lane| io.phy.vdr_get(lane, C10_VDR_CONTROL_1) != 0) {
        return TestResult::Fail("a C20 port must never open the C10 VDR batch");
    }
    if route.stop(&io).is_err() || route.state() != RouteState::Stopped {
        return TestResult::Fail("PTL DDI B must stop");
    }
    let p4pg = lane_powerdown_new_state(0, P4PG_STATE_DISABLE)
        | lane_powerdown_new_state(1, P4PG_STATE_DISABLE);
    if !io
        .phy
        .writes_to(port.buf_ctl2())
        .iter()
        .any(|w| w & POWERDOWN_NEW_STATE_MASK_BOTH == p4pg)
    {
        return TestResult::Fail("the C20 DDI B must power down to P4PG");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_ptl_external_ddi_b_programs_its_c20
);

fn smoke_ptl_external_tc_dp_uses_fixed_vrr_tg() -> TestResult {
    let io = ExtFake::new(XeLpgPort::Tc1, Sink::new(0x14, edid_1024()));
    let Some(panel) = io.light_panel_ip(DisplayIp::Xe3Lpd) else {
        return TestResult::Fail("the fixture must light the display-30 panel");
    };
    let probe = match probe_sink(&io, Generation::PantherLake, XeLpgPort::Tc1, false) {
        Ok(probe) => probe,
        Err(_) => return TestResult::Fail("PTL TC1 probe must own PICA/TCSS/AUX"),
    };
    if probe.display_version() != 30
        || probe
            .tc
            .is_none_or(|tc| tc.profile != TcDisplayProfile::Xe3Lpd)
    {
        return TestResult::Fail("the sink probe must retain the display-30 layout");
    }
    if io.writes_to(crate::intel_gpu_xelpg_tc::TCSS_DISP_MAILBOX_IN_DATA) != [1]
        || io.writes_to(crate::intel_gpu_xelpg_tc::TCSS_DISP_MAILBOX_IN_CMD)
            != [crate::intel_gpu_xelpg_tc::TCSS_DISP_MAILBOX_RUN_BUSY | 1]
    {
        return TestResult::Fail("PTL TCSS power-up must run Wa_14020908590 first");
    }
    let fb = fb_for(&probe.mode).unwrap();
    let display = MtlDisplay {
        panel: Some(panel),
        pipe_dmc: &NoPipeDmc,
    };
    let mut route = match activate(&io, probe, fb, &display) {
        Ok(route) => route,
        Err(_) => return TestResult::Fail("PTL USB-C DP must activate beside Pipe A"),
    };
    let pipe = Pipe::B;
    let trans = pipe.transcoder();
    let base = trans.base();
    let ctl = io.read32(base + crate::intel_gpu_vrr::TRANS_VRR_CTL_OFFSET);
    if ctl & (crate::intel_gpu_vrr::VRR_CTL_VRR_ENABLE | crate::intel_gpu_vrr::VRR_CTL_FLIP_LINE_EN)
        != crate::intel_gpu_vrr::VRR_CTL_VRR_ENABLE | crate::intel_gpu_vrr::VRR_CTL_FLIP_LINE_EN
        || ctl & crate::intel_gpu_vrr::VRR_CTL_GUARDBAND_MASK == 0
        || io.read32(base + crate::intel_gpu_pipes::TRANS_VTOTAL_OFFSET) != 767
        || io.read32(base + 0x0ac) != 0
    {
        return TestResult::Fail("display 30 must program its fixed-refresh VRR TG");
    }
    let func =
        io.first_write(|o, v| o == trans_ddi_func_ctl(trans) && v & TRANS_DDI_FUNC_ENABLE != 0);
    let timings = io.first_write(|o, _| o == base + crate::intel_gpu_vrr::TRANS_VRR_VMIN_OFFSET);
    let tg = io.first_write(|o, v| {
        o == base + crate::intel_gpu_vrr::TRANS_VRR_CTL_OFFSET
            && v & crate::intel_gpu_vrr::VRR_CTL_VRR_ENABLE != 0
    });
    let transcoder = io.first_write(|o, v| o == pipe.base() + CONF && v & ENABLE != 0);
    if !matches!((func, timings, tg, transcoder), (Some(a), Some(b), Some(c), Some(d)) if a < b && b < c && c < d)
    {
        return TestResult::Fail("fixed TG must start between function and transcoder enable");
    }
    if route.stop(&io).is_err() || route.release(&io).is_err() {
        return TestResult::Fail("PTL USB-C DP must stop and release");
    }
    if io.read32(base + crate::intel_gpu_vrr::TRANS_VRR_CTL_OFFSET)
        & crate::intel_gpu_vrr::VRR_CTL_VRR_ENABLE
        != 0
        || io.read32(base + crate::intel_gpu_vrr::TRANS_PUSH_OFFSET) != 0
    {
        return TestResult::Fail("display 30 stop must disable the fixed TG");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_ptl_external_tc_dp_uses_fixed_vrr_tg
);

fn smoke_wcl_external_tc_dp_uses_c20_and_three_pipe_profile() -> TestResult {
    let io = ExtFake::new(XeLpgPort::Tc1, Sink::new(0x14, edid_1024()));
    let Some(panel) = io.light_panel_ip(DisplayIp::WildcatLake) else {
        return TestResult::Fail("the fixture must light the WCL panel profile");
    };
    // Pipe D does not decode on 30.02. The third FBC is real and must be idle.
    io.confs[Pipe::D as usize].set(u32::MAX);
    let fbc_c = 0x43288;
    io.phy.write32(fbc_c, ENABLE);
    if crate::intel_gpu_xelpg_live::check_pipes(&io, DisplayIp::WildcatLake, 1)
        != Err(crate::intel_gpu_xelpg_resources::ResourceError::Busy)
    {
        return TestResult::Fail("WCL must refuse live repartition while FBC C is enabled");
    }
    io.phy.write32(fbc_c, 0);
    let mut service = MtlExternalService::new();
    service.set_profile(ExternalDisplayProfile::WILDCAT_LAKE);
    service.set_display(MtlDisplay {
        panel: Some(panel),
        pipe_dmc: &NoPipeDmc,
    });
    let event = MtlHpdEvent {
        pin: MtlHpdPin::Tc1,
        kind: MtlHpdKind::Connected(LiveMode::DpAlt),
    };
    if !matches!(
        service.handle(&io, event, &mut fb_for),
        ServiceOutcome::Activated {
            port: XeLpgPort::Tc1,
            protocol: MtlProtocol::Dp,
            pipe: Pipe::B,
            ..
        }
    ) {
        return TestResult::Fail("WCL TC1 must activate on its first real external pipe");
    }
    let port = XeLpgPort::Tc1;
    if io.writes_to(port.msgbus_ctl_ln0()).is_empty()
        || !io.writes_to(0x16_f234).is_empty()
        || io.read32(port.ddi_buf_ctl()) & DDI_BUF_CTL_ENABLE == 0
    {
        return TestResult::Fail("WCL must use C20 and never the Nova Lake LT registers");
    }
    if !matches!(
        service.handle(
            &io,
            MtlHpdEvent {
                pin: MtlHpdPin::Tc1,
                kind: MtlHpdKind::Disconnected,
            },
            &mut fb_for,
        ),
        ServiceOutcome::Withdrawn {
            port: XeLpgPort::Tc1
        }
    ) {
        return TestResult::Fail("WCL TC1 must stop and release on detach");
    }
    if io
        .first_write(|r, _| {
            (0x73000..0x74000).contains(&r) || r == crate::intel_gpu_xelpg_dbuf::dbox_ctl(3)
        })
        .is_some()
    {
        return TestResult::Fail("WCL connect and release must skip Pipe D registers");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_wcl_external_tc_dp_uses_c20_and_three_pipe_profile
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

fn smoke_xe3_usb_c_uses_receiver_training_patterns() -> TestResult {
    for (ip, revision, lane_cap, spread_cap, expected_rate, expected_patterns) in [
        // The extended block supplies TPS4. CR fails at four lanes, then
        // succeeds at two; the final modeset retries that trained width.
        (
            DisplayIp::Xe3Lpd,
            0x14,
            4,
            0x80,
            TrainRate::Rbr,
            &[0x21, 0, 0x21, 7, 0, 0x21, 7, 0][..],
        ),
        // The TPS4 bit is reserved before DPCD 1.4.
        (
            DisplayIp::WildcatLake,
            0x13,
            0xc1,
            0x80,
            TrainRate::Hbr2,
            &[0x21, 0x23, 0][..],
        ),
        // Some HBR2 receivers do not advertise TPS3.
        (
            DisplayIp::WildcatLake,
            0x14,
            1,
            0,
            TrainRate::Hbr2,
            &[0x21, 0x22, 0][..],
        ),
    ] {
        let fallback = expected_rate == TrainRate::Rbr;
        let edid = if fallback { edid_1024() } else { edid_1080() };
        let mut sink = Sink::new(0x14, edid);
        let mut caps = [0; 15];
        caps[..4].copy_from_slice(&[revision, 0x14, lane_cap, spread_cap]);
        if fallback {
            sink.caps[2] = 0x84;
            sink.caps[14] = 0x80;
            sink.extended_caps = Some(caps);
            sink.max_good_lanes = 2;
        } else {
            sink.caps[..15].copy_from_slice(&caps);
        }
        let io = ExtFake::new(XeLpgPort::Tc2, sink);
        let Some(panel) = io.light_panel_ip(ip) else {
            return TestResult::Fail("could not light the panel");
        };
        let mut service = MtlExternalService::new();
        service.set_profile(ExternalDisplayProfile::for_ip(ip));
        service.set_display(MtlDisplay {
            panel: Some(panel),
            pipe_dmc: &NoPipeDmc,
        });
        let result = service.handle(
            &io,
            tc2_event(MtlHpdKind::Connected(LiveMode::DpAlt)),
            &mut fb_for,
        );
        if !matches!(result, ServiceOutcome::Activated { pipe: Pipe::B, .. }) {
            return TestResult::Fail("the USB-C receiver must train and reach scanout");
        }
        let Some(MtlRoute::Dp(route)) = service.route() else {
            return TestResult::Fail("the service must own the trained DP route");
        };
        assert_eq!(route.trained.rate, expected_rate);
        assert_eq!(
            io.sink.borrow().training_writes_to(0x102),
            expected_patterns
        );
        let expected_lanes = match (fallback, lane_cap & 0x80 != 0) {
            (true, _) => &[4, 2, 2][..],
            (false, true) => &[0x81],
            (false, false) => &[1],
        };
        assert_eq!(io.sink.borrow().training_writes_to(0x101), expected_lanes);
        let enhanced = lane_cap & 0x80 != 0;
        assert!(io
            .writes_to(DP_TP_CTL_B)
            .iter()
            .filter(|v| **v & ENABLE != 0)
            .all(|v| (v & (1 << 18) != 0) == enhanced));
        assert!(service.teardown(&io));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_xe3_usb_c_uses_receiver_training_patterns
);

fn smoke_xe3_usb_c_receiver_training_poll_intervals() -> TestResult {
    use crate::intel_gpu_modeset::training::{Change, State, TrainingAux};
    for (rev, interval, width, expected) in [
        (0x12, 0x80, 2, &[100, 400][..]),
        (0x12, 0x82, 2, &[8_000, 8_000][..]),
        // Above the specified interval range Linux still waits the reported duration.
        (0x12, 0x85, 2, &[20_000, 20_000][..]),
        // Five CR polls at four lanes fail. The two-lane retry needs one CR
        // and one EQ poll, with the DP 1.4 fixed CR delay on both attempts.
        (0x14, 0x82, 4, &[100, 100, 100, 100, 100, 100, 8_000][..]),
    ] {
        let mut sink = Sink::new(0x06, edid_1024());
        sink.caps[0] = rev;
        sink.caps[14] = 0x80;
        let mut extended = [0; 15];
        extended.copy_from_slice(&sink.caps[..15]);
        extended[14] = interval;
        sink.extended_caps = Some(extended);
        sink.max_good_lanes = 2;
        let io = ExtFake::new(XeLpgPort::Tc2, sink);
        let mut aux = IntelAux::xelpdp(&io, io.port.aux_base(), false);
        aux_power_enable(&io, io.port).unwrap();
        let caps = crate::dp_link_training::read_caps(&mut aux).unwrap();
        let receiver = ReceiverTraining::for_receiver(&caps, 0, false);
        let mut aux = TrainingAux::new(
            aux,
            State::new(crate::intel_gpu_pll::LinkRate::DpRbr, width),
            |state: &State, change| {
                if change == Change::Pattern {
                    io.phy.write32(DP_TP_CTL_B, ENABLE | state.pattern_bits()?);
                }
                Ok(())
            },
        );
        let delays = RefCell::new(Vec::new());
        let result =
            train_link_with_receiver(&mut aux, TrainRate::Rbr, width, Some(receiver), |us| {
                delays.borrow_mut().push(us)
            })
            .unwrap();
        assert_eq!(result.lanes, 2);
        assert_eq!(delays.borrow().as_slice(), expected);
        aux_power_disable(&io, io.port).unwrap();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_xe3_usb_c_receiver_training_poll_intervals
);

fn smoke_mtl_external_refusals_before_mmio_and_tbt() -> TestResult {
    if probe_sink(&NoAccess, Generation::TigerLake, XeLpgPort::Tc1, false).err()
        != Some(ExternalError::UnsupportedGeneration)
        || probe_sink(&NoAccess, Generation::MeteorLake, XeLpgPort::A, false).err()
            != Some(ExternalError::UnsupportedPort)
        || probe_sink(&NoAccess, Generation::PantherLake, XeLpgPort::A, false).err()
            != Some(ExternalError::UnsupportedPort)
        || !ExternalDisplayProfile::for_ip(DisplayIp::Xe2Lpd).admits_port(XeLpgPort::B)
        || ExternalDisplayProfile::for_ip(DisplayIp::Xe2Lpd).admits_port(XeLpgPort::A)
        || !ExternalDisplayProfile::for_ip(DisplayIp::Xe3Lpd).admits_port(XeLpgPort::B)
        || ExternalDisplayProfile::WILDCAT_LAKE.admits_port(XeLpgPort::B)
        || !ExternalDisplayProfile::for_ip(DisplayIp::Xe3Lpd).c20_port_b()
        || ExternalDisplayProfile::WILDCAT_LAKE.c20_port_b()
        || ExternalDisplayProfile::for_ip(DisplayIp::Xe2Lpd).c20_port_b()
        || probe_link_profile(
            &NoAccess,
            ExternalDisplayProfile::WILDCAT_LAKE,
            XeLpgPort::Tc3,
            false,
        )
        .err()
            != Some(ExternalError::UnsupportedPort)
    {
        return TestResult::Fail("generation/port refusals must precede MMIO");
    }
    if !ExternalDisplayProfile::WILDCAT_LAKE.admits_port(XeLpgPort::Tc1)
        || !ExternalDisplayProfile::WILDCAT_LAKE.admits_port(XeLpgPort::Tc2)
        || ExternalDisplayProfile::WILDCAT_LAKE.admits_port(XeLpgPort::Tc3)
        || ExternalDisplayProfile::WILDCAT_LAKE.display_ip() != DisplayIp::WildcatLake
    {
        return TestResult::Fail("WCL must retain its TC1/TC2 profile");
    }
    if !matches!(
        free_pipe(
            &ExtFake::new(XeLpgPort::Tc1, Sink::new(0x14, edid_1024())),
            ExternalDisplayProfile::WILDCAT_LAKE
        ),
        Ok(Pipe::B)
    ) {
        return TestResult::Fail("WCL must allocate its real Pipe B");
    }
    let pipes = ExtFake::new(XeLpgPort::Tc1, Sink::new(0x14, edid_1024()));
    pipes.set_conf(1, ENABLE);
    pipes.set_conf(2, ENABLE);
    if free_pipe(&pipes, ExternalDisplayProfile::WILDCAT_LAKE) != Err(ExternalError::NoFreePipe)
        || free_pipe(&pipes, ExternalDisplayProfile::for_ip(DisplayIp::Xe3Lpd)) != Ok(Pipe::D)
    {
        return TestResult::Fail("WCL must not scan or allocate absent Pipe D");
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

fn smoke_tc_dp_extended_receiver_caps() -> TestResult {
    // Linux selects the entire extension at equal or newer revision, even
    // when the base revision predates DP 1.3. SSC uses the same snapshot.
    for (base_rev, ext_rev, use_extended) in
        [(0x12, 0x14, true), (0x14, 0x14, true), (0x14, 0x13, false)]
    {
        let mut sink = Sink::new(0x14, edid_1024());
        sink.caps[0] = base_rev;
        sink.caps[14] = 0x82;
        let mut extended = [0; 15];
        extended[..4].copy_from_slice(&[ext_rev, 0x0a, 0x82, 1]);
        extended[7] = 0x40;
        extended[14] = 1;
        sink.extended_caps = Some(extended);
        let io = ExtFake::new(XeLpgPort::Tc1, sink);
        let Ok(probe) = probe_sink(&io, Generation::MeteorLake, XeLpgPort::Tc1, false) else {
            return TestResult::Fail("USB-C sink with extended capabilities should probe");
        };
        let expected = if use_extended {
            (ext_rev, TrainRate::Hbr, 2, 4_000)
        } else {
            (base_rev, TrainRate::Hbr2, 4, 8_000)
        };
        let caps = probe.caps;
        assert_eq!(
            (
                caps.dpcd_rev,
                caps.max_rate,
                caps.max_lanes,
                caps.aux_rd_interval_us()
            ),
            expected
        );
        assert_eq!(probe.negotiated.lanes, caps.max_lanes);
        assert_eq!(probe.ssc, use_extended);
        assert_eq!(caps.msa_timing_par_ignored, use_extended);
    }

    for (rev, error) in [
        (0x14, crate::dp_aux::AuxError::Nacked),
        (0, crate::dp_aux::AuxError::InvalidDpcdRevision),
    ] {
        let mut sink = Sink::new(0x14, edid_1024());
        sink.caps[0] = rev;
        sink.caps[14] = 0x80;
        let io = ExtFake::new(XeLpgPort::Tc1, sink);
        assert_eq!(
            probe_sink(&io, Generation::MeteorLake, XeLpgPort::Tc1, false).err(),
            Some(ExternalError::Link(LinkError::AuxFailure(error)))
        );
        assert_eq!(
            io.read32(XeLpgPort::Tc1.buf_ctl1()) & (TC_PHY_OWNERSHIP | TCSS_POWER_REQUEST),
            0
        );
        assert!(!io.aux_power.get());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_tc_dp_extended_receiver_caps
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

/// Light HDMI on DDI B beside the display-`ip` panel and return the live
/// route, or why not.
fn hdmi_ddi_b_route(
    io: &ExtFake,
    ip: DisplayIp,
    generation: Generation,
) -> Result<crate::intel_gpu_xelpg_hdmi::MtlHdmiRoute, &'static str> {
    use crate::intel_gpu_xelpg_hdmi::{activate_hdmi, ddc_pin, probe_hdmi, HdmiRouteState};
    let panel = io
        .light_panel_ip(ip)
        .ok_or("the fixture must light the panel")?;
    let port = XeLpgPort::B;
    let probe = probe_hdmi(io, generation, port, false, ddc_pin(port))
        .map_err(|_| "the DDI B HDMI probe must read the sink's EDID")?;
    let fb = fb_for(&probe.mode).ok_or("the mode must have a scanout")?;
    let display = MtlDisplay {
        panel: Some(panel),
        pipe_dmc: &NoPipeDmc,
    };
    match activate_hdmi(io, probe, fb, &display) {
        Ok(route) if route.state() == HdmiRouteState::Live && route.pipe() == Pipe::B => Ok(route),
        _ => Err("DDI B HDMI must light Pipe B beside the panel"),
    }
}

/// Lunar Lake HDMI on its C10 DDI B: display 20 keeps the D2D request in
/// `DDI_BUF_CTL` (`mtl_ddi_enable_d2d`, and `intel_ddi_enable_hdmi`'s
/// `XE2LPD_DDI_BUF_D2D_LINK_ENABLE` in the full DDI write), never in the
/// display-14 `PORT_BUF_CTL1`, and the stop clears it there.
fn smoke_lnl_hdmi_ddi_b_keeps_d2d_in_ddi_buf_ctl() -> TestResult {
    use crate::intel_gpu_xe2lpd::{DDI_BUF_D2D_LINK_ENABLE, DDI_BUF_D2D_LINK_STATE};
    let io = hdmi_on_ddi_b(edid_1024());
    let mut route = match hdmi_ddi_b_route(&io, DisplayIp::Xe2Lpd, Generation::LunarLake) {
        Ok(route) => route,
        Err(e) => return TestResult::Fail(e),
    };
    let port = XeLpgPort::B;
    let func = crate::intel_gpu_pipes::build_trans_ddi_func_ctl_hdmi(1, false, false);
    let ddi = io.read32(port.ddi_buf_ctl());
    let d2d = DDI_BUF_CTL_ENABLE | DDI_BUF_D2D_LINK_ENABLE | DDI_BUF_D2D_LINK_STATE;
    if io.read32(TRANS_DDI_FUNC_CTL_B) != func
        || ddi & d2d != d2d
        || io
            .writes_to(port.buf_ctl1())
            .iter()
            .any(|v| v & crate::intel_gpu_xelpg::PORT_BUF_D2D_LINK_ENABLE != 0)
    {
        return TestResult::Fail("display-20 HDMI must hold D2D in DDI_BUF_CTL only");
    }
    if route.stop(&io).is_err()
        || io.read32(port.ddi_buf_ctl()) & (DDI_BUF_CTL_ENABLE | DDI_BUF_D2D_LINK_ENABLE) != 0
        || io.read32(PIPECONF_B) & (ENABLE | STATE) != 0
    {
        return TestResult::Fail("the stop must drop the DDI and its D2D request");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_lnl_hdmi_ddi_b_keeps_d2d_in_ddi_buf_ctl
);

/// Panther Lake HDMI on its C20 DDI B: the TMDS state from
/// `mtl_c20_hdmi_tables` goes through the C20 SRAM window, and display 30
/// scans the transcoder out through the fixed-refresh VRR timing
/// generator, started after `TRANS_DDI_FUNC_CTL` and before `TRANSCONF`.
fn smoke_ptl_hdmi_ddi_b_runs_its_c20_through_the_vrr_tg() -> TestResult {
    use crate::intel_gpu_vrr::{TRANS_VRR_CTL_OFFSET, VRR_CTL_VRR_ENABLE};
    let io = hdmi_on_ddi_b(edid_1080());
    let mut route = match hdmi_ddi_b_route(&io, DisplayIp::Xe3Lpd, Generation::PantherLake) {
        Ok(route) => route,
        Err(e) => return TestResult::Fail(e),
    };
    if route.probe.pll.port_clock_khz != 148_500
        || !matches!(
            route.probe.pll.state,
            crate::intel_gpu_xelpg::Cx0PllState::C20(..)
        )
        || io.phy.sram_values().is_empty()
        || (0..2).any(|lane| {
            io.phy
                .vdr_get(lane, crate::intel_gpu_xelpg::C10_VDR_CONTROL_1)
                != 0
        })
    {
        return TestResult::Fail("PTL DDI B HDMI must program its C20 at 148.5 MHz");
    }
    let base = Pipe::B.transcoder().base();
    let func = io.first_write(|o, v| o == TRANS_DDI_FUNC_CTL_B && v & TRANS_DDI_FUNC_ENABLE != 0);
    let tg = io.first_write(|o, v| o == base + TRANS_VRR_CTL_OFFSET && v & VRR_CTL_VRR_ENABLE != 0);
    let conf = io.first_write(|o, v| o == PIPECONF_B && v & ENABLE != 0);
    match (func, tg, conf) {
        (Some(f), Some(t), Some(c)) if f < t && t < c => {}
        _ => {
            return TestResult::Fail(
                "display 30 must start the VRR TG between FUNC_CTL and TRANSCONF",
            )
        }
    }
    if route.stop(&io).is_err()
        || io.read32(base + TRANS_VRR_CTL_OFFSET) & VRR_CTL_VRR_ENABLE != 0
        || io.read32(XeLpgPort::B.ddi_buf_ctl()) & DDI_BUF_CTL_ENABLE != 0
    {
        return TestResult::Fail("the stop must turn the VRR TG and the DDI off");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_ptl_hdmi_ddi_b_runs_its_c20_through_the_vrr_tg
);

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
                c20_uhbr_vspeo: None,
                dp14_vspeo: None,
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
        c20_uhbr_vspeo: None,
        dp14_vspeo: None,
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
    // A TMDS clock past the 600 MHz source maximum refuses after the probe
    // (C10 computes any untabled clock below it).
    let io = hdmi_on_ddi_b(edid_for(620_000, 1024, 320, 24, 136, 768, 38, 3, 6));
    let mut service = MtlExternalService::new();
    if !matches!(
        service.handle(&io, connect, &mut fb_for),
        ServiceOutcome::Refused {
            error: RouteError::Hdmi(HdmiError::UnsupportedClock(620_000)),
            ..
        }
    ) || service.route().is_some()
    {
        return TestResult::Fail("a TMDS clock past the source maximum must refuse with its clock");
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
            c20_uhbr_vspeo: None,
            dp14_vspeo: None,
        },
        tc: [
            MtlPortDecl::USB_C,
            MtlPortDecl {
                lane_reversal: false,
                dp: false,
                hdmi: true,
                legacy: true,
                ddc_pin: Some(PinPair::Pin10Tc2),
                c20_uhbr_vspeo: None,
                dp14_vspeo: None,
            },
            MtlPortDecl {
                lane_reversal: false,
                dp: true,
                hdmi: true,
                legacy: false,
                ddc_pin: Some(PinPair::Pin11Tc3),
                c20_uhbr_vspeo: None,
                dp14_vspeo: None,
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
    let c10 = |ssc| {
        dp_pll_request(
            crate::intel_gpu_xelpg::PhyKind::C10,
            XeLpgPort::B,
            rate,
            4,
            false,
            false,
            ssc,
        )
        .unwrap()
    };
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
    let c20 = |ssc| {
        dp_pll_request(
            crate::intel_gpu_xelpg::PhyKind::C20,
            XeLpgPort::Tc1,
            rate,
            4,
            true,
            false,
            ssc,
        )
        .unwrap()
    };
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
    if install_for_probe(Generation::LunarLake, None, None) != VbtInstall::Missing
        || install_for_probe(Generation::PantherLake, None, None) != VbtInstall::Missing
        || install_for_probe(Generation::TigerLake, None, Some(0x1234_5000))
            != VbtInstall::NotApplicable
    {
        return TestResult::Fail("LNL/PTL use the port policy; consumer-less routes read nothing");
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
pub(crate) const MONITOR_DSC: [u8; 16] = [
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

// One HBR lane cannot carry 1080p60 even at 6 bpc, forcing DSC with FEC.
fn compressed_tc(nacks: u8) -> ExtFake {
    let mut sink = dsc_monitor(true);
    sink.edid = edid_1080();
    sink.caps[1] = 0x0a;
    sink.fec_status_nacks = nacks;
    let io = ExtFake::new(XeLpgPort::Tc2, sink);
    io.pin.set(crate::intel_gpu_xelpg_tc::PIN_ASSIGNMENT_D);
    io
}

fn smoke_mtl_external_dp_dsc_with_fec_lights_and_stops() -> TestResult {
    use crate::intel_gpu_xelpg_dsc::{
        decide_dp, DpDscSink, DscDpcd, DscSink, LinkDecision, LinkLimits, DP_TP_CTL_FEC_ENABLE,
        PIPE_BPP,
    };
    // 594 MHz needs 1782000 kBps at 24 bpp and 1336500 at 18; one HBR3
    // lane carries 810000. Linux compresses with FEC: 169/16 bpp, two
    // slices on two engines, HBR3 x1.
    let io = ExtFake::new(XeLpgPort::B, dsc_monitor(true));
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

fn smoke_xe3_external_dsc_confirms_fec_before_pps() -> TestResult {
    for (ip, missed, nacks, expected_enables) in [
        (DisplayIp::Xe2Lpd, 1, 0, 1),
        (DisplayIp::Xe3Lpd, 1, 0, 2),
        (DisplayIp::WildcatLake, 0, 1, 2),
        (DisplayIp::WildcatLake, 0, 4, 4),
    ] {
        let io = compressed_tc(nacks);
        io.fec_missed_enables.set(missed);
        let Some(panel) = io.light_panel_ip(ip) else {
            return TestResult::Fail("could not light the panel for the FEC fixture");
        };
        let probe =
            match probe_link_profile(&io, ExternalDisplayProfile::for_ip(ip), io.port, false)
                .and_then(|link| probe_sink_link(&io, link, false, false))
            {
                Ok(probe) if probe.dsc.is_some_and(|plan| plan.fec) => probe,
                _ => return TestResult::Fail("the USB-C sink must need DSC and FEC"),
            };
        let fb = fb_for(&probe.mode).unwrap();
        let display = MtlDisplay {
            panel: Some(panel),
            pipe_dmc: &NoPipeDmc,
        };
        let result = activate(&io, probe, fb, &display);
        if io
            .sink
            .borrow()
            .dsc_log
            .iter()
            .filter(|&&(addr, value)| addr == 0x280 && value == 3)
            .count()
            != 1
        {
            return TestResult::Fail(
                "clear the sink's FEC detected flags once when setting FEC_READY",
            );
        }
        let pps = io.first_write(|off, _| off == 0x6_1350);
        let mut enabled = false;
        let mut rising = 0;
        // A successful handshake precedes the first PPS. On a failure all
        // attempts precede rollback, which only clears FEC.
        for &(off, value) in io.writes.borrow().iter().take(pps.unwrap_or(usize::MAX)) {
            if off == DP_TP_CTL_B {
                let next = value & dsc::DP_TP_CTL_FEC_ENABLE != 0;
                rising += usize::from(next && !enabled);
                enabled = next;
            }
        }
        if rising != expected_enables {
            return TestResult::Fail("wrong number of FEC enables before the first PPS");
        }
        if nacks == 4 {
            let Err(ActivateError::Failed(route, ExternalError::FecNotReady)) = result else {
                return TestResult::Fail("the fourth failed FEC handshake must roll back");
            };
            if pps.is_some()
                || io
                    .first_write(|o, v| o == PIPECONF_B && v & ENABLE != 0)
                    .is_some()
                || route.state() != RouteState::Stopped
                || route.reserved()
                || io.sink.borrow().fec_config != 0
                || io.sink.borrow().dsc_enable != 0
                || route.release(&io).is_err()
            {
                return TestResult::Fail("failed FEC must leave the compressed stream stopped");
            }
        } else {
            let Ok(mut route) = result else {
                return TestResult::Fail(
                    "the compressed route must activate after its FEC sequence",
                );
            };
            if pps.is_none() || !enabled || route.stop(&io).is_err() || route.release(&io).is_err()
            {
                return TestResult::Fail("the compressed route must send PPS and stop cleanly");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_xe3_external_dsc_confirms_fec_before_pps
);

fn fec_service(io: &ExtFake, ip: DisplayIp, dmc: &'static DmcEvents) -> Option<MtlExternalService> {
    let mut service = MtlExternalService::new();
    service.set_profile(ExternalDisplayProfile::for_ip(ip));
    service.set_display(beside(io.light_panel_ip(ip)?, dmc));
    Some(service)
}

fn tc2_event(kind: MtlHpdKind) -> MtlHpdEvent {
    MtlHpdEvent {
        pin: MtlHpdPin::Tc2,
        kind,
    }
}

fn smoke_xe3_external_dsc_requires_live_fec_through_scanout() -> TestResult {
    for (ip, drop_on) in [
        (DisplayIp::Xe3Lpd, PIPECONF_B),
        (DisplayIp::WildcatLake, PLANE_CTL_1_B),
    ] {
        let io = compressed_tc(0);
        let dmc = DmcEvents::leak();
        let Some(mut service) = fec_service(&io, ip, dmc) else {
            return TestResult::Fail("could not light the panel");
        };
        io.fec_drop_on_enable.set(Some(drop_on));
        let result = service.handle(
            &io,
            tc2_event(MtlHpdKind::Connected(LiveMode::DpAlt)),
            &mut fb_for,
        );
        if !matches!(
            result,
            ServiceOutcome::Refused {
                error: RouteError::Dp(ExternalError::FecNotReady),
                ..
            }
        ) || service.route().is_some()
            || io.writes_to(0x6_1350).is_empty()
            || io
                .first_write(|r, v| r == PIPECONF_B && v & ENABLE != 0)
                .is_none()
            || io
                .first_write(|r, v| r == PLANE_CTL_1_B && v & ENABLE != 0)
                .is_some()
                != (drop_on == PLANE_CTL_1_B)
            || io.read32(TRANS_CLK_SEL_B) != 0
            || io.aux_power.get()
            || dmc.events() != [(1, true), (1, false)]
            || !panel_never_blanked(&io)
        {
            return TestResult::Fail(
                "lost source FEC must withdraw the compressed stream before publication",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_xe3_external_dsc_requires_live_fec_through_scanout
);

fn smoke_xe3_external_dsc_retains_clock_until_fec_stops() -> TestResult {
    for (ip, stop_status, error, rollback) in [
        (
            DisplayIp::Xe3Lpd,
            dsc::DP_TP_STATUS_FEC_ENABLE_LIVE,
            ExternalError::FecStopTimeout,
            false,
        ),
        (
            DisplayIp::WildcatLake,
            u32::MAX,
            ExternalError::AccessLost,
            false,
        ),
        (
            DisplayIp::WildcatLake,
            dsc::DP_TP_STATUS_FEC_ENABLE_LIVE,
            ExternalError::FecStopTimeout,
            true,
        ),
    ] {
        let io = compressed_tc(u8::from(rollback));
        let dmc = DmcEvents::leak();
        let Some(mut service) = fec_service(&io, ip, dmc) else {
            return TestResult::Fail("could not light the panel");
        };
        if rollback {
            io.fec_stop_status.set(Some(stop_status));
        }
        let connect = tc2_event(MtlHpdKind::Connected(LiveMode::DpAlt));
        let disconnect = tc2_event(MtlHpdKind::Disconnected);
        let mut outcome = service.handle(&io, connect, &mut fb_for);
        if !rollback {
            if !matches!(outcome, ServiceOutcome::Activated { pipe: Pipe::B, .. }) {
                return TestResult::Fail("the compressed route must light before the forced stop");
            }
            io.fec_stop_status.set(Some(stop_status));
            outcome = service.handle(&io, disconnect, &mut fb_for);
        }
        if !matches!(outcome, ServiceOutcome::Retained { error: RouteError::Dp(e), .. } if e == error)
            || !matches!(service.route(), Some(MtlRoute::Dp(r)) if r.state() == RouteState::Quarantined && r.reserved())
            || io.read32(DP_TP_CTL_B) & (DP_TP_CTL_ENABLE | dsc::DP_TP_CTL_FEC_ENABLE) != 0
            || io.read32(TRANS_CLK_SEL_B) == 0
            || io.read32(io.port.buf_ctl1()) & TC_PHY_OWNERSHIP == 0
            || !io.aux_power.get()
            || dmc.events() != [(1, true)]
        {
            return TestResult::Fail(
                "an unproven FEC stop must retain the pipe, clock, Type-C and AUX",
            );
        }
        io.writes.borrow_mut().clear();
        if !matches!(service.handle(&io, disconnect, &mut fb_for), ServiceOutcome::Retained { error: RouteError::Dp(e), .. } if e == error)
            || !io.writes.borrow().is_empty()
        {
            return TestResult::Fail("a retry while FEC is unproven may only sample source status");
        }
        io.fec_stop_status.set(None);
        io.sink.borrow_mut().nack_all = true; // A detached sink cannot acknowledge AUX.
        if !matches!(
            service.handle(&io, disconnect, &mut fb_for),
            ServiceOutcome::Withdrawn { .. }
        ) || service.route().is_some()
            || io.read32(TRANS_CLK_SEL_B) != 0
            || io.read32(io.port.buf_ctl1()) & TC_PHY_OWNERSHIP != 0
            || io.aux_power.get()
            || dmc.events() != [(1, true), (1, false)]
            || !panel_never_blanked(&io)
        {
            return TestResult::Fail(
                "after source FEC stops the same reservation must release on unplug",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_xe3_external_dsc_retains_clock_until_fec_stops
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

// ── narf.intel.uhbr: DP 2.0 UHBR (128b/132b) routes ────────────────

/// 3840x2160 with the CTA 4K timing (htotal 4400, vtotal 2250) at `pclk`.
fn edid_uhd(pclk_khz: u32) -> Vec<u8> {
    edid_for(pclk_khz, 3840, 560, 176, 88, 2160, 90, 8, 10)
}

/// A DP 2.0 4K60 monitor behind TC2 in pin assignment D (two lanes) whose
/// 8b/10b ceiling is HBR2: two HBR2 lanes carry 1080000 kBps, the mode needs
/// 1782000 at 24 bpp and 1336500 at 18 (`intel_dp_link_required`), so only
/// UHBR10 x2 (2417750) carries it. The sink asks for TX FFE presets 4 / 9.
fn uhbr_tc() -> ExtFake {
    let mut sink = Sink::dp20(0x14, edid_uhd(594_000), uhbr::DP_UHBR10 | uhbr::DP_UHBR20);
    sink.ffe_request = [4, 9, 0, 0];
    let io = ExtFake::new(XeLpgPort::Tc2, sink);
    io.pin.set(crate::intel_gpu_xelpg_tc::PIN_ASSIGNMENT_D);
    io
}

/// Without `narf.intel.uhbr=1` the route stays 8b/10b exactly as before: a
/// DP 2.0 sink whose stream only UHBR carries is refused over budget, and
/// no 128b/132b register (`DP_128B132B_SUPPORTED_LINK_RATES`, the LTTPR
/// caps, `DP_MAIN_LINK_CHANNEL_CODING_SET`, the payload table) is touched;
/// the Type-C ownership is rolled back.
fn smoke_mtl_external_uhbr_option_off_refuses_over_budget() -> TestResult {
    let io = uhbr_tc();
    let profile = ExternalDisplayProfile::for_ip(DisplayIp::Xelpdp);
    match probe_sink_profile_uhbr(&io, profile, XeLpgPort::Tc2, false, false) {
        Err(ExternalError::OverBudget { .. }) => {}
        _ => return TestResult::Fail("without narf.intel.uhbr the 8b/10b route must refuse"),
    }
    let sink = io.sink.borrow();
    if !sink.uhbr_reads.is_empty() || !sink.uhbr_log.is_empty() || sink.coding != 0 {
        return TestResult::Fail("the option off must not touch a 128b/132b register");
    }
    drop(sink);
    if io.read32(XeLpgPort::Tc2.buf_ctl1()) & TC_PHY_OWNERSHIP != 0 {
        return TestResult::Fail("the refused probe must release the Type-C PHY");
    }
    // The production entry reads the strict boot option, which this boot
    // does not carry.
    if uhbr::opted_in() {
        return TestResult::Fail("narf.intel.uhbr must default off");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_uhbr_option_off_refuses_over_budget
);

/// `narf.intel.uhbr=1` on Meteor Lake TC2: `intel_dp_compute_link_config_wide`
/// picks UHBR10 x2 at 24 bpp; `mtl_ddi_pre_enable_dp` and `intel_ddi_enable`
/// then run the 128b/132b route: the C20 MPLLA UHBR10 image with
/// `DDI_CLK_VALFREQ` = 312500 (the 32-bit symbol clock), `TRANS_DP2_CTL`
/// 128b/132b, `TRANS_DDI_FUNC_CTL` in 128b/132b mode with the route's own
/// MST transport, `DP_TP_CTL` in MST mode (no enhanced framing) through
/// TPS1, TPS2 and NORMAL, the 40-bit `PORT_BUF_CTL1` and `DDI_CTL_DE`, the
/// sink's channel coding before its rate, the TX FFE presets it asked for
/// (`mtl_c20_trans_uhbr` 4 and 9, the last lane's for lanes past the count),
/// the VC payload (VCPID 1, slot 0, 48 slots) and its ACT, the MTP M/N
/// (`TU_SIZE(48)`) and the `TRANS_DP2_VFREQ` pair. The stop clears the
/// payload, then the function (port and mode after the sink's D3), hands the
/// sink back to 8b/10b and clears `TRANS_DP2_CTL`.
fn smoke_mtl_external_uhbr_tc_route_lights_and_stops() -> TestResult {
    use crate::intel_gpu_pipes::{
        PIPE_DATA_M1_OFFSET, PIPE_DATA_N1_OFFSET, PIPE_LINK_M1_OFFSET, PIPE_LINK_N1_OFFSET,
    };
    let io = uhbr_tc();
    let profile = ExternalDisplayProfile::for_ip(DisplayIp::Xelpdp);
    let probe = match probe_sink_profile_uhbr(&io, profile, XeLpgPort::Tc2, false, true) {
        Ok(probe) => probe,
        Err(_) => return TestResult::Fail("the DP 2.0 sink must probe with UHBR on"),
    };
    let Some(plan) = probe.uhbr.as_deref().copied() else {
        return TestResult::Fail("only UHBR carries 4K60 on two HBR2 lanes");
    };
    let mn = [(47 << 25) | 0x5e_579e, 0x80_0000, 0xf_34d6, 0x8_0000];
    if plan.link
        != (uhbr::UhbrLink {
            rate: uhbr::UhbrRate::Uhbr10,
            lanes: 2,
            pipe_bpp: 24,
        })
        || plan.stream.tu != 48
        || plan.stream.m_n != mn
        || plan.post_lt_adj_req
        || probe.pipe_bpp != 24
        || probe.negotiated.lanes != 2
        || probe.dsc.is_some()
    {
        return TestResult::Fail("the probe must carry Linux's UHBR10 x2 link and MTP");
    }
    let fb = fb_for(&probe.mode).unwrap();
    let mut route = match activate(&io, probe, fb, &MtlDisplay::NONE) {
        Ok(route) if route.state() == RouteState::Live && route.pipe() == Pipe::B => route,
        _ => return TestResult::Fail("the 128b/132b route must light Pipe B"),
    };
    // Source PHY: C20 MPLLA, width 2, no SSC (no sink downspread).
    if io.phy.writes_to(0x6_4430) != [312_500]
        || io.phy.sram_get(0xCCE5) != 0x3104
        || io.phy.sram_get(0xCCE5 - 9) != 0x0001
        || io
            .phy
            .vdr_get(0, crate::intel_gpu_xelpg::C20_VDR_CUSTOM_WIDTH)
            & 3
            != 2
        || io.read32(XeLpgPort::Tc2.port_clock_ctl())
            & (crate::intel_gpu_xelpg::SSC_ENABLE_PLLA | crate::intel_gpu_xelpg::SSC_ENABLE_PLLB)
            != 0
    {
        return TestResult::Fail("UHBR10 must run the C20 MPLLA image at the symbol clock");
    }
    // TX FFE presets 4 (33, 0, 15) and 9 (33, 2, 13) on PHY lane 0.
    let vdr = |a: u16| io.phy.vdr_get(0, a);
    if [vdr(0xD80), vdr(0xD81), vdr(0xD82)] != [0, 33, 15]
        || [vdr(0xD90), vdr(0xD91), vdr(0xD92)] != [2, 33, 13]
        || route.uhbr.map(|u| u.presets) != Some([4, 9, 9, 9])
    {
        return TestResult::Fail("the trained TX FFE presets must reach the C20");
    }
    let want = (crate::intel_gpu_pipes::build_trans_ddi_func_ctl(
        4,
        crate::intel_gpu_pipes::TRANS_DDI_MODE_DP_SST,
        2,
    ) & !(7 << 24))
        | (4 << 24)
        | (1 << 10);
    let func = io.writes_to(TRANS_DDI_FUNC_CTL_B);
    if func != [want & !TRANS_DDI_FUNC_ENABLE, want, want | (1 << 8)] {
        return TestResult::Fail("TRANS_DDI_FUNC_CTL: 128b/132b, enabled, then VC payload");
    }
    if io.writes_to(0x6_10a0) != [1 << 31]
        || io.writes_to(0x6_10a4) != [0x2300]
        || io.writes_to(0x6_10a8) != [0x67b8_8000]
    {
        return TestResult::Fail("TRANS_DP2_CTL and the VFREQ pair (594 MHz) differ");
    }
    let tp = io.writes_to(DP_TP_CTL_B);
    if tp.first() != Some(&(DP_TP_CTL_ENABLE | (1 << 27)))
        || !tp.contains(&(DP_TP_CTL_ENABLE | (1 << 27) | (1 << 8)))
        || tp.last() != Some(&(DP_TP_CTL_ENABLE | (1 << 27) | DP_TP_CTL_LINK_TRAIN_NORMAL))
    {
        return TestResult::Fail("DP_TP_CTL: MST mode through TPS1, TPS2, NORMAL");
    }
    if io.read32(XeLpgPort::Tc2.buf_ctl1()) & (3 << 18) != 2 << 18
        || io.read32(0x6_4400) != DDI_BUF_CTL_ENABLE | (1 << 1) | (2 << 18)
    {
        return TestResult::Fail("PORT_BUF_CTL1 and DDI_CTL_DE must carry the 40-bit width");
    }
    let base = Transcoder::B.base();
    let got = [
        io.read32(base + PIPE_DATA_M1_OFFSET),
        io.read32(base + PIPE_DATA_N1_OFFSET),
        io.read32(base + PIPE_LINK_M1_OFFSET),
        io.read32(base + PIPE_LINK_N1_OFFSET),
    ];
    if got != mn {
        return TestResult::Fail("the MTP M/N must be programmed with TU_SIZE(48)");
    }
    {
        let sink = io.sink.borrow();
        let log = &sink.uhbr_log;
        let at = |w: (u32, u8)| log.iter().position(|&e| e == w);
        let (Some(crc), Some(coding), Some(bw)) = (
            at((uhbr::DP_SDP_ERROR_DETECTION_CONFIGURATION, 1)),
            at((
                uhbr::DP_MAIN_LINK_CHANNEL_CODING_SET,
                uhbr::DP_SET_ANSI_128B132B,
            )),
            at((0x100, 0x01)),
        ) else {
            return TestResult::Fail("SDP CRC16, 128b/132b coding and DP_LINK_BW_10 must be set");
        };
        let patterns: Vec<u8> = sink.training_writes_to(0x102);
        if !(crc < coding && coding < bw)
            || sink.training_writes_to(0x101) != [2]
            || patterns != [1, 2, 3, 0]
            || !log.ends_with(&[(0x1c0, 1), (0x1c1, 0), (0x1c2, 48)])
            || sink.payload_status & uhbr::DP_PAYLOAD_ACT_HANDLED == 0
        {
            return TestResult::Fail("the sink's 128b/132b DPCD sequence differs from Linux");
        }
    }
    if route.link_ok(&io) != Ok(true) {
        return TestResult::Fail("the trained 128b/132b link must revalidate");
    }
    if route.stop(&io).is_err() || route.state() != RouteState::Stopped {
        return TestResult::Fail("the 128b/132b route must stop");
    }
    let func = io.writes_to(TRANS_DDI_FUNC_CTL_B);
    if func[3..]
        != [
            want,
            want & !TRANS_DDI_FUNC_ENABLE,
            want & !(TRANS_DDI_FUNC_ENABLE | TRANS_DDI_PORT_AND_MODE),
        ]
    {
        return TestResult::Fail("stop: VC payload, then ENABLE, then port and mode");
    }
    {
        let sink = io.sink.borrow();
        let log = &sink.uhbr_log;
        let clear = log
            .windows(3)
            .position(|w| w == [(0x1c0, 1), (0x1c1, 0), (0x1c2, 0)]);
        let back = log.iter().rposition(|&e| {
            e == (
                uhbr::DP_MAIN_LINK_CHANNEL_CODING_SET,
                uhbr::DP_SET_ANSI_8B10B,
            )
        });
        if clear.is_none() || back.is_none() || clear > back || sink.power_log.last() != Some(&2) {
            return TestResult::Fail("stop: payload clear, 8b/10b coding back, then D3");
        }
    }
    if io.writes_to(0x6_10a0).last() != Some(&0)
        || io.read32(XeLpgPort::Tc2.port_clock_ctl())
            & crate::intel_gpu_xelpg::lane_pclk_pll_request(0)
            != 0
    {
        return TestResult::Fail("stop: TRANS_DP2_CTL off and the PLL released");
    }
    if route.release(&io).is_err() {
        return TestResult::Fail("the stopped route must release");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_uhbr_tc_route_lights_and_stops
);

/// `intel_dp_start_link_train`'s failure on 128b/132b, then
/// `intel_dp_get_link_train_fallback_values` and the modeset retry: a
/// one-lane DP 2.0 sink (UHBR10/20) whose 3840x2160 495 MHz stream takes
/// UHBR20 x1 at 24 bpp (`TU` 40) reports `DP_128B132B_LT_FAILED` there; the
/// route stops, UHBR20 x1 is disabled with the limits at UHBR10 x1, and the
/// retry lights UHBR10 x1 at 18 bpp: `TU` 60, `DATA_M` = `TU_SIZE(60)` |
/// 0x75ed85, `LINK_M` 0xcac08 (495000 / 312500 at N 0x80000), the
/// `TRANS_DDI_FUNC_CTL` BPC_6, the C20 UHBR10 image after the UHBR20 one.
fn smoke_mtl_external_uhbr_training_fallback_retry() -> TestResult {
    use crate::intel_gpu_pipes::{
        PIPE_DATA_M1_OFFSET, PIPE_DATA_N1_OFFSET, PIPE_LINK_M1_OFFSET, PIPE_LINK_N1_OFFSET,
    };
    let mut sink = Sink::dp20(0x14, edid_uhd(495_000), uhbr::DP_UHBR10 | uhbr::DP_UHBR20);
    sink.caps[2] = 1 | 0x40 | 0x80;
    sink.uhbr_lt_fail_bw = 0x02;
    sink.ffe_request = [4, 0, 0, 0];
    let io = ExtFake::new(XeLpgPort::Tc2, sink);
    io.pin.set(crate::intel_gpu_xelpg_tc::PIN_ASSIGNMENT_D);
    let profile = ExternalDisplayProfile::for_ip(DisplayIp::Xelpdp);
    let Ok(probe) = probe_sink_profile_uhbr(&io, profile, XeLpgPort::Tc2, false, true) else {
        return TestResult::Fail("the one-lane DP 2.0 sink must probe");
    };
    match probe.uhbr.as_deref() {
        Some(p)
            if p.link
                == (uhbr::UhbrLink {
                    rate: uhbr::UhbrRate::Uhbr20,
                    lanes: 1,
                    pipe_bpp: 24,
                })
                && p.stream.tu == 40 => {}
        _ => return TestResult::Fail("495 MHz on one lane plans UHBR20 x1 at 24 bpp"),
    }
    let fb = fb_for(&probe.mode).unwrap();
    let route = match activate(&io, probe, fb, &MtlDisplay::NONE) {
        Ok(route) if route.state() == RouteState::Live => route,
        Ok(_) | Err(_) => return TestResult::Fail("the reduced retry must light the route"),
    };
    let mn = [(59 << 25) | 0x75_ed85, 0x80_0000, 0xc_ac08, 0x8_0000];
    match route.probe.uhbr.as_deref() {
        Some(p)
            if p.link
                == (uhbr::UhbrLink {
                    rate: uhbr::UhbrRate::Uhbr10,
                    lanes: 1,
                    pipe_bpp: 18,
                })
                && p.stream.tu == 60
                && p.stream.m_n == mn
                && !p.caps.allowed(2_000_000, 1)
                && p.caps.max_limits() == (1_000_000, 1) => {}
        _ => return TestResult::Fail("the retry must run Linux's UHBR10 x1 at 18 bpp"),
    }
    if route.probe.pipe_bpp != 18 {
        return TestResult::Fail("the retry's pipe runs 6 bpc");
    }
    {
        let sink = io.sink.borrow();
        let bw: Vec<u8> = sink
            .uhbr_log
            .iter()
            .filter_map(|&(a, v)| (a == 0x100).then_some(v))
            .collect();
        if bw != [0x02, 0x01] {
            return TestResult::Fail("training must try UHBR20, then UHBR10");
        }
    }
    let valfreq = io.phy.writes_to(0x6_4430);
    if valfreq.first() != Some(&625_000) || valfreq.last() != Some(&312_500) {
        return TestResult::Fail("the C20 must run UHBR20, then UHBR10");
    }
    let base = Transcoder::B.base();
    let got = [
        io.read32(base + PIPE_DATA_M1_OFFSET),
        io.read32(base + PIPE_DATA_N1_OFFSET),
        io.read32(base + PIPE_LINK_M1_OFFSET),
        io.read32(base + PIPE_LINK_N1_OFFSET),
    ];
    if got != mn || io.read32(TRANS_DDI_FUNC_CTL_B) & (7 << 20) != dsc::trans_ddi_bpc(18) {
        return TestResult::Fail("the retry's M/N and BPC_6 must be programmed");
    }
    let mut route = route;
    if route.stop(&io).is_err() || route.release(&io).is_err() {
        return TestResult::Fail("the retried route must stop and release");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_uhbr_training_fallback_retry
);

/// The modeset retry's link choice ([`uhbr_fallback`]): after UHBR10 x2
/// fails for a 440 MHz 3840x2160 stream on an HBR2 x2 sink, the limits
/// drop to HBR2 x2 (descending lane/rate order) and only 18 bpp fits
/// (990000 <= 1080000 kBps): the probe goes back to the 8b/10b route at
/// HBR2 x2, 6 bpc. The 594 MHz stream of [`uhbr_tc`] fits nothing after its
/// fallback: no retry.
fn smoke_mtl_external_uhbr_fallback_to_8b10b_or_none() -> TestResult {
    let mut sink = Sink::dp20(0x14, edid_uhd(440_000), uhbr::DP_UHBR10);
    sink.ffe_request = [4, 9, 0, 0];
    let io = ExtFake::new(XeLpgPort::Tc2, sink);
    io.pin.set(crate::intel_gpu_xelpg_tc::PIN_ASSIGNMENT_D);
    let profile = ExternalDisplayProfile::for_ip(DisplayIp::Xelpdp);
    let Ok(probe) = probe_sink_profile_uhbr(&io, profile, XeLpgPort::Tc2, false, true) else {
        return TestResult::Fail("the DP 2.0 sink must probe");
    };
    if probe
        .uhbr
        .as_deref()
        .map(|p| (p.link.rate, p.link.lanes, p.link.pipe_bpp))
        != Some((uhbr::UhbrRate::Uhbr10, 2, 24))
    {
        return TestResult::Fail("440 MHz on two HBR2 lanes plans UHBR10 x2");
    }
    match uhbr_fallback(&probe) {
        Some(next)
            if next.uhbr.is_none()
                && next.pipe_bpp == 18
                && next.negotiated.rate == TrainRate::Hbr2
                && next.negotiated.lanes == 2
                && !next.negotiated.over_budget => {}
        _ => return TestResult::Fail("the retry must hand the stream to 8b/10b HBR2 x2 at 18 bpp"),
    }
    let _ = release_probe(&io, &probe);
    let io = uhbr_tc();
    let Ok(probe) = probe_sink_profile_uhbr(&io, profile, XeLpgPort::Tc2, false, true) else {
        return TestResult::Fail("the DP 2.0 sink must probe");
    };
    if uhbr_fallback(&probe).is_some() {
        return TestResult::Fail("4K60 fits nothing below UHBR10 x2 on two lanes");
    }
    let _ = release_probe(&io, &probe);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_uhbr_fallback_to_8b10b_or_none
);

/// DSC over 128b/132b SST (Linux 7.4 `intel_dp_dsc_compute_config` with
/// `intel_dp_mtp_tu_compute_config(dsc)`): a one-lane DP 2.0 sink (HBR2,
/// UHBR10) with the monitor's DSC caps and a 3840x2160 594 MHz stream that
/// fits nothing uncompressed (UHBR10 x1 carries 1208875 kBps; 24 and 18 bpp
/// need 1782000 and 1336500). The compressed bpp walks down from 383/16:
/// HBR2 x1 would need below 8 bpp with FEC; UHBR10 x1 first fits at 259/16
/// bpp with two slices (the 340000 kP/s throughput floor), 64 slots,
/// `DATA_M` = `TU_SIZE(64)` | 0x7fe2e3 at the slice-aware MST overhead of
/// 1004891 ppm. The route enables the sink's decompression with no
/// `DP_FEC_READY` and no `DP_TP_CTL` FEC (implicit on 128b/132b), runs both
/// VDSC engines, and turns decompression off at the stop.
fn smoke_mtl_external_uhbr_dsc_route_without_fec() -> TestResult {
    use crate::intel_gpu_pipes::{
        PIPE_DATA_M1_OFFSET, PIPE_DATA_N1_OFFSET, PIPE_LINK_M1_OFFSET, PIPE_LINK_N1_OFFSET,
    };
    let mut sink = Sink::dp20(0x14, edid_uhd(594_000), uhbr::DP_UHBR10);
    sink.caps[2] = 1 | 0x40 | 0x80;
    sink.dsc = MONITOR_DSC;
    sink.fec_cap = dsc::DP_FEC_CAPABLE;
    sink.ffe_request = [4, 0, 0, 0];
    let io = ExtFake::new(XeLpgPort::Tc2, sink);
    io.pin.set(crate::intel_gpu_xelpg_tc::PIN_ASSIGNMENT_D);
    let profile = ExternalDisplayProfile::for_ip(DisplayIp::Xelpdp);
    let probe = match probe_sink_profile_uhbr(&io, profile, XeLpgPort::Tc2, false, true) {
        Ok(probe) => probe,
        Err(e) => {
            use core::fmt::Write as _;
            let _ = writeln!(narf_console::Writer, "UHBR DSC probe: {e:?}");
            return TestResult::Fail("the DSC DP 2.0 sink must probe with UHBR on");
        }
    };
    let mn = [(63 << 25) | 0x7f_e2e3, 0x80_0000, 0xf_34d6, 0x8_0000];
    match (probe.dsc, probe.uhbr.as_deref()) {
        (Some(d), Some(u))
            if d.link_rate == 1_000_000
                && d.lanes == 1
                && d.compressed_bpp_x16 == 259
                && d.slice_count == 2
                && d.num_streams == 2
                && !d.fec
                && d.pipe_bpp == 24
                && u.link
                    == (uhbr::UhbrLink {
                        rate: uhbr::UhbrRate::Uhbr10,
                        lanes: 1,
                        pipe_bpp: 24,
                    })
                && u.stream.tu == 64
                && u.stream.m_n == mn => {}
        _ => return TestResult::Fail("the probe must compress over UHBR10 x1 at 259/16 bpp"),
    }
    let dss = probe.dsc.map(|d| d.dss_ctl()).unwrap_or_default();
    let fb = fb_for(&probe.mode).unwrap();
    let mut route = match activate(&io, probe, fb, &MtlDisplay::NONE) {
        Ok(route) if route.state() == RouteState::Live => route,
        _ => return TestResult::Fail("the compressed 128b/132b route must light"),
    };
    {
        let sink = io.sink.borrow();
        if !sink
            .dsc_log
            .contains(&(dsc::DP_DSC_ENABLE, dsc::DP_DECOMPRESSION_EN))
            || sink
                .dsc_log
                .iter()
                .any(|&(a, _)| a == dsc::DP_FEC_CONFIGURATION)
        {
            return TestResult::Fail("decompression on, and no DP_FEC_READY on 128b/132b");
        }
    }
    if io
        .writes_to(DP_TP_CTL_B)
        .iter()
        .any(|v| v & dsc::DP_TP_CTL_FEC_ENABLE != 0)
    {
        return TestResult::Fail("DP_TP_CTL must not enable FEC on 128b/132b");
    }
    let base = Transcoder::B.base();
    let got = [
        io.read32(base + PIPE_DATA_M1_OFFSET),
        io.read32(base + PIPE_DATA_N1_OFFSET),
        io.read32(base + PIPE_LINK_M1_OFFSET),
        io.read32(base + PIPE_LINK_N1_OFFSET),
    ];
    if got != mn
        || io.read32(dsc::dss_ctl1(Pipe::B)) != dss.0
        || io.read32(dsc::dss_ctl2(Pipe::B)) != dss.1
        || dss.1 & (dsc::VDSC0_ENABLE | dsc::VDSC1_ENABLE) != dsc::VDSC0_ENABLE | dsc::VDSC1_ENABLE
    {
        return TestResult::Fail("the compressed MTP M/N and both VDSC engines must be live");
    }
    if route.stop(&io).is_err() || route.release(&io).is_err() {
        return TestResult::Fail("the compressed 128b/132b route must stop and release");
    }
    let sink = io.sink.borrow();
    let on = sink
        .dsc_log
        .iter()
        .position(|&e| e == (dsc::DP_DSC_ENABLE, dsc::DP_DECOMPRESSION_EN));
    let off = sink
        .dsc_log
        .iter()
        .rposition(|&e| e == (dsc::DP_DSC_ENABLE, 0));
    if !matches!((on, off), (Some(a), Some(b)) if a < b) {
        return TestResult::Fail("stop: the sink's decompression off");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_uhbr_dsc_route_without_fec
);

/// The reduced-parameter retry with DSC (`intel_dp_get_link_train_fallback_values`,
/// then the retry's `intel_dp_compute_config`: the uncompressed search,
/// then Linux 7.4's DSC search over what is still allowed), on one-lane
/// DP 2.0 sinks with the monitor's DSC caps and a 3840x2160 594 MHz stream:
///
/// - UHBR10/20 and HBR2: UHBR20 x1 carries the stream uncompressed at
///   24 bpp; its training fails (`DP_128B132B_LT_FAILED`), the limits drop
///   to UHBR10 x1 (`reduce_link_params`, descending lane/rate order), where
///   nothing fits uncompressed, so the retry compresses: UHBR10 x1 at
///   259/16 bpp with two slices, 64 slots and the `DATA_M` / `LINK_M` of
///   [`smoke_mtl_external_uhbr_dsc_route_without_fec`].
/// - UHBR10 and HBR3: the compressed UHBR10 x1 stream (259/16 bpp) fails
///   to train; the limits drop to HBR3 x1 and the retry's DSC search lands
///   on 8b/10b: 169/16 bpp with FEC and two slices at HBR3 x1, the plan of
///   [`smoke_mtl_external_dp_dsc_with_fec_lights_and_stops`], with
///   `DP_TP_CTL` FEC on.
/// - UHBR10 and HBR2: the compressed UHBR10 x1 stream's fallback (HBR2 x1)
///   carries nothing, even compressed (below the 8 bpp minimum): no retry,
///   the route is stopped and refused typed.
fn smoke_mtl_external_uhbr_compressed_fallback_retry() -> TestResult {
    let sink = |max_bw: u8, rates: u8, fail_bw: u8| {
        let mut sink = Sink::dp20(max_bw, edid_uhd(594_000), rates);
        sink.caps[2] = 1 | 0x40 | 0x80;
        sink.dsc = MONITOR_DSC;
        sink.fec_cap = dsc::DP_FEC_CAPABLE;
        sink.ffe_request = [4, 0, 0, 0];
        sink.uhbr_lt_fail_bw = fail_bw;
        let io = ExtFake::new(XeLpgPort::Tc2, sink);
        io.pin.set(crate::intel_gpu_xelpg_tc::PIN_ASSIGNMENT_D);
        io
    };
    let profile = ExternalDisplayProfile::for_ip(DisplayIp::Xelpdp);
    let uhbr10 = uhbr::UhbrLink {
        rate: uhbr::UhbrRate::Uhbr10,
        lanes: 1,
        pipe_bpp: 24,
    };
    // Uncompressed UHBR20 x1, then compressed UHBR10 x1.
    let io = sink(0x14, uhbr::DP_UHBR10 | uhbr::DP_UHBR20, 0x02);
    let Ok(probe) = probe_sink_profile_uhbr(&io, profile, XeLpgPort::Tc2, false, true) else {
        return TestResult::Fail("the DSC DP 2.0 sink must probe with UHBR on");
    };
    match probe.uhbr.as_deref() {
        Some(p)
            if probe.dsc.is_none()
                && p.dsc_sink.is_some()
                && p.link
                    == (uhbr::UhbrLink {
                        rate: uhbr::UhbrRate::Uhbr20,
                        lanes: 1,
                        pipe_bpp: 24,
                    }) => {}
        _ => return TestResult::Fail("UHBR20 x1 carries 594 MHz uncompressed"),
    }
    let fb = fb_for(&probe.mode).unwrap();
    let mut route = match activate(&io, probe, fb, &MtlDisplay::NONE) {
        Ok(route) if route.state() == RouteState::Live => route,
        _ => return TestResult::Fail("the retry must light the compressed route"),
    };
    let mn = [(63 << 25) | 0x7f_e2e3, 0x80_0000, 0xf_34d6, 0x8_0000];
    match (route.probe.dsc, route.probe.uhbr.as_deref()) {
        (Some(d), Some(u))
            if (d.link_rate, d.lanes, d.compressed_bpp_x16, d.slice_count, d.fec)
                == (1_000_000, 1, 259, 2, false)
                && u.link == uhbr10
                && u.stream.tu == 64
                && u.stream.m_n == mn
                && !u.caps.allowed(2_000_000, 1)
                && u.caps.max_limits() == (1_000_000, 1) => {}
        _ => return TestResult::Fail("the retry compresses over UHBR10 x1 at 259/16 bpp"),
    }
    {
        let sink = io.sink.borrow();
        let bw: Vec<u8> = sink
            .uhbr_log
            .iter()
            .filter_map(|&(a, v)| (a == 0x100).then_some(v))
            .collect();
        if bw != [0x02, 0x01]
            || !sink
                .dsc_log
                .contains(&(dsc::DP_DSC_ENABLE, dsc::DP_DECOMPRESSION_EN))
        {
            return TestResult::Fail("UHBR20, then UHBR10 with the sink decompressing");
        }
    }
    if route.stop(&io).is_err() || route.release(&io).is_err() {
        return TestResult::Fail("the retried compressed route must stop and release");
    }
    // Compressed UHBR10 x1, then 8b/10b DSC with FEC at HBR3 x1.
    let io = sink(0x1e, uhbr::DP_UHBR10, 0x01);
    let Ok(probe) = probe_sink_profile_uhbr(&io, profile, XeLpgPort::Tc2, false, true) else {
        return TestResult::Fail("the HBR3 DSC DP 2.0 sink must probe with UHBR on");
    };
    match (probe.dsc, probe.uhbr.as_deref()) {
        (Some(d), Some(u)) if d.compressed_bpp_x16 == 259 && u.link == uhbr10 => {}
        _ => return TestResult::Fail("the probe compresses over UHBR10 x1 at 259/16 bpp"),
    }
    let fb = fb_for(&probe.mode).unwrap();
    let mut route = match activate(&io, probe, fb, &MtlDisplay::NONE) {
        Ok(route) if route.state() == RouteState::Live => route,
        _ => return TestResult::Fail("the retry must light the 8b/10b compressed route"),
    };
    match route.probe.dsc {
        Some(d)
            if route.probe.uhbr.is_none()
                && (d.link_rate, d.lanes, d.compressed_bpp_x16, d.slice_count, d.fec)
                    == (810_000, 1, 169, 2, true)
                && route.probe.negotiated.rate == TrainRate::Hbr3
                && route.probe.negotiated.lanes == 1 => {}
        _ => return TestResult::Fail("the retry runs Linux's 8b/10b DSC plan at HBR3 x1"),
    }
    if io.read32(DP_TP_CTL_B) & dsc::DP_TP_CTL_FEC_ENABLE == 0
        || !io
            .sink
            .borrow()
            .dsc_log
            .contains(&(dsc::DP_FEC_CONFIGURATION, 1))
    {
        return TestResult::Fail("the 8b/10b retry enables FEC on source and sink");
    }
    if route.stop(&io).is_err() || route.release(&io).is_err() {
        return TestResult::Fail("the 8b/10b compressed route must stop and release");
    }
    // Compressed UHBR10 x1 on an HBR2 sink: nothing to retry.
    let io = sink(0x14, uhbr::DP_UHBR10, 0x01);
    let Ok(probe) = probe_sink_profile_uhbr(&io, profile, XeLpgPort::Tc2, false, true) else {
        return TestResult::Fail("the HBR2 DSC DP 2.0 sink must probe with UHBR on");
    };
    if probe.dsc.is_none() || uhbr_fallback(&probe).is_some() {
        return TestResult::Fail("HBR2 x1 carries 594 MHz at no compressed bpp");
    }
    let fb = fb_for(&probe.mode).unwrap();
    match activate(&io, probe, fb, &MtlDisplay::NONE) {
        Err(ActivateError::Failed(
            route,
            ExternalError::Uhbr(uhbr::UhbrRefusal::Training(uhbr::TrainFailure::LtFailed)),
        )) if route.state() == RouteState::Stopped => {
            let _ = route.release(&io);
        }
        _ => return TestResult::Fail("no reduced configuration: the stopped route is refused"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_uhbr_compressed_fallback_retry
);

/// The 128b/132b route through one 128b/132b LTTPR (`DP_PHY_REPEATER_CNT`
/// 0x80, revision 2.0, UHBR10/20, a 20 ms extended wait request):
/// `mtl_ddi_pre_enable_dp` switches it non-transparent (0x55, 0xaa) and
/// grants its wait (`DP_EXTENDED_WAKE_TIMEOUT_GRANT`), then
/// `intel_dp_start_link_train` re-initializes it (0x55, 0xaa) before the
/// 128b/132b channel coding; the stop hands it back transparent after the
/// sink's 8b/10b coding.
fn smoke_mtl_external_uhbr_lttpr_non_transparent_route() -> TestResult {
    let io = uhbr_tc();
    for (i, b) in [0x20u8, 0x1e, 0x80, 0x55, 4, 0x02, 1, 0x03]
        .into_iter()
        .enumerate()
    {
        io.sink
            .borrow_mut()
            .extra
            .push((uhbr::DP_LTTPR_COMMON_CAPS + i as u32, b));
    }
    let profile = ExternalDisplayProfile::for_ip(DisplayIp::Xelpdp);
    let Ok(probe) = probe_sink_profile_uhbr(&io, profile, XeLpgPort::Tc2, false, true) else {
        return TestResult::Fail("the DP 2.0 sink must probe through its LTTPR");
    };
    if probe.uhbr.as_deref().map(|p| (p.link.rate, p.link.lanes))
        != Some((uhbr::UhbrRate::Uhbr10, 2))
    {
        return TestResult::Fail("the LTTPR keeps Linux's UHBR10 x2 link");
    }
    if !io.sink.borrow().uhbr_log.is_empty() {
        return TestResult::Fail("the probe must not change the LTTPR mode");
    }
    let fb = fb_for(&probe.mode).unwrap();
    let mut route = match activate(&io, probe, fb, &MtlDisplay::NONE) {
        Ok(route) => route,
        Err(_) => return TestResult::Fail("the route must light through the LTTPR"),
    };
    let mode = uhbr::DP_PHY_REPEATER_MODE;
    let (t, n) = (
        uhbr::DP_PHY_REPEATER_MODE_TRANSPARENT,
        uhbr::DP_PHY_REPEATER_MODE_NON_TRANSPARENT,
    );
    {
        let sink = io.sink.borrow();
        let lttpr: Vec<(u32, u8)> = sink
            .uhbr_log
            .iter()
            .copied()
            .filter(|&(a, _)| a == mode || a == uhbr::DP_PHY_REPEATER_EXTENDED_WAIT_TIMEOUT)
            .collect();
        let last_mode = sink.uhbr_log.iter().rposition(|&(a, _)| a == mode);
        let coding = sink.uhbr_log.iter().position(|&e| {
            e == (
                uhbr::DP_MAIN_LINK_CHANNEL_CODING_SET,
                uhbr::DP_SET_ANSI_128B132B,
            )
        });
        if lttpr
            != [
                (mode, t),
                (mode, n),
                (
                    uhbr::DP_PHY_REPEATER_EXTENDED_WAIT_TIMEOUT,
                    uhbr::DP_EXTENDED_WAKE_TIMEOUT_GRANT,
                ),
                (mode, t),
                (mode, n),
            ]
            || !matches!((last_mode, coding), (Some(m), Some(c)) if m < c)
        {
            return TestResult::Fail(
                "the LTTPR must go non-transparent, then the 128b/132b coding",
            );
        }
    }
    if route.uhbr.map(|u| u.lttpr_count) != Some(1) {
        return TestResult::Fail("the route must record its non-transparent LTTPR");
    }
    io.sink.borrow_mut().uhbr_log.clear();
    if route.stop(&io).is_err() {
        return TestResult::Fail("the route must stop");
    }
    {
        let sink = io.sink.borrow();
        let back = sink.uhbr_log.iter().position(|&e| {
            e == (
                uhbr::DP_MAIN_LINK_CHANNEL_CODING_SET,
                uhbr::DP_SET_ANSI_8B10B,
            )
        });
        let transparent = sink.uhbr_log.iter().position(|&e| e == (mode, t));
        if !matches!((back, transparent), (Some(b), Some(m)) if b < m) {
            return TestResult::Fail("stop: 8b/10b coding, then the LTTPR transparent");
        }
    }
    if route.release(&io).is_err() {
        return TestResult::Fail("the route must release");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_uhbr_lttpr_non_transparent_route
);

/// An 8b/10b DPRX (HBR2 x4) behind one LTTPR (`DP_PHY_REPEATER_CNT` 0x80,
/// revision 1.4, HBR2 x4) whose PHY status reports CR, channel EQ, symbol
/// lock and alignment.
fn lttpr_8b10b_sink() -> Sink {
    let mut sink = Sink::new(0x14, edid_1024());
    for (i, b) in [0x14u8, 0x14, 0x80, 0x55, 4, 0, 0, 0].into_iter().enumerate() {
        sink.extra.push((uhbr::DP_LTTPR_COMMON_CAPS + i as u32, b));
    }
    sink.extra.push((0xf_0030, 0x77));
    sink.extra.push((0xf_0031, 0x77));
    sink.extra.push((0xf_0032, 0x01));
    sink
}

/// Per-hop 8b/10b training through an LTTPR (`narf.intel.uhbr=1`, Meteor
/// Lake TC1, RBR x4): `mtl_ddi_pre_enable_dp` switches the repeater
/// non-transparent (`DP_PHY_REPEATER_MODE` 0x55, then 0xaa) before
/// `drm_dp_lttpr_wake_timeout_setup`, `intel_dp_start_link_train`
/// re-initializes it (0x55, 0xaa), then `intel_dp_link_train_all_phys`
/// trains the LTTPR at `DP_TRAINING_PATTERN_SET_PHY_REPEATER1` (TPS1 without
/// scrambling 0x21, TPS4 0x07, disabled) and then the DPRX at
/// `DP_TRAINING_PATTERN_SET` (0x21, its TPS3 without scrambling 0x23,
/// disabled). The source's `DP_TP_CTL` follows every pattern but the
/// repeater's disable (`intel_dp_disable_dpcd_training_pattern` is DPCD
/// only): PAT1 at the port enable, PAT1, PAT4, PAT1, PAT3, normal, then
/// the normal of `intel_dp_stop_link_train`. The stop hands the repeater
/// back transparent. Without the option the repeater keeps its mode and
/// the link trains end to end at the DPRX (0x21, 0x23, 0).
fn smoke_mtl_external_lttpr_per_hop_8b10b_route() -> TestResult {
    let profile = ExternalDisplayProfile::for_ip(DisplayIp::Xelpdp);
    let mode = uhbr::DP_PHY_REPEATER_MODE;
    for uhbr_on in [true, false] {
        let io = ExtFake::new(XeLpgPort::Tc1, lttpr_8b10b_sink());
        let Ok(probe) = probe_sink_profile_uhbr(&io, profile, XeLpgPort::Tc1, false, uhbr_on)
        else {
            return TestResult::Fail("the DPRX must probe through its LTTPR");
        };
        if probe.uhbr.is_some() || probe.lttpr_per_hop != uhbr_on {
            return TestResult::Fail("an 8b/10b probe trains per hop only with the option");
        }
        let fb = fb_for(&probe.mode).unwrap();
        let mut route = match activate(&io, probe, fb, &MtlDisplay::NONE) {
            Ok(route) if route.state() == RouteState::Live => route,
            _ => return TestResult::Fail("the 8b/10b route must light through the LTTPR"),
        };
        {
            let sink = io.sink.borrow();
            let modes: Vec<u8> = sink
                .uhbr_log
                .iter()
                .filter_map(|&(a, v)| (a == mode).then_some(v))
                .collect();
            let patterns: Vec<(u32, u8)> = sink
                .training_writes
                .iter()
                .copied()
                .filter(|&(a, _)| a != 0x101)
                .collect();
            let (want_modes, want_patterns): (&[u8], &[(u32, u8)]) = if uhbr_on {
                (
                    &[0x55, 0xaa, 0x55, 0xaa],
                    &[
                        (0xf_0010, 0x21),
                        (0xf_0010, 0x07),
                        (0xf_0010, 0x00),
                        (0x102, 0x21),
                        (0x102, 0x23),
                        (0x102, 0x00),
                    ],
                )
            } else {
                (&[], &[(0x102, 0x21), (0x102, 0x23), (0x102, 0x00)])
            };
            if modes != want_modes || patterns != want_patterns {
                return TestResult::Fail("the LTTPR trains first, only with the option");
            }
        }
        let fields: Vec<u32> = io
            .writes_to(DP_TP_CTL_B)
            .iter()
            .filter(|&&v| v & DP_TP_CTL_ENABLE != 0)
            .map(|v| (v >> 8) & 7)
            .collect();
        let want: &[u32] = if uhbr_on {
            &[0, 0, 5, 0, 4, 3, 3]
        } else {
            &[0, 0, 4, 3, 3]
        };
        if fields != want || route.lttprs != u8::from(uhbr_on) {
            return TestResult::Fail("the source pattern follows each hop's training");
        }
        if route.stop(&io).is_err() || route.release(&io).is_err() {
            return TestResult::Fail("the route must stop and release");
        }
        let last_mode = io
            .sink
            .borrow()
            .uhbr_log
            .iter()
            .rev()
            .find(|&&(a, _)| a == mode)
            .map(|&(_, v)| v);
        if last_mode != uhbr_on.then_some(uhbr::DP_PHY_REPEATER_MODE_TRANSPARENT) {
            return TestResult::Fail("the stop hands a per-hop repeater back transparent");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_lttpr_per_hop_8b10b_route
);

/// `BDB_VSWING_PREEMPH` with `tables` tables of sixteen rows and `columns`
/// columns: table `t`, row `r` is (0x1_0000 + 20 + r + t, t, r), then 0xee
/// in any further column (the high bits are lost to the `snps` bytes).
pub(crate) fn vspeo_block(tables: usize, columns: usize) -> Vec<u8> {
    let mut b = alloc::vec![tables as u8, columns as u8];
    for t in 0..tables as u32 {
        for r in 0..16u32 {
            for c in 0..columns {
                let v = match c {
                    0 => 0x1_0000 + 20 + r + t,
                    1 => t,
                    2 => r,
                    _ => 0xee,
                };
                b.extend_from_slice(&v.to_le_bytes());
            }
        }
    }
    b
}

/// `mtl_get_c20_buf_trans_override` on a 128b/132b C20 link: a VBT whose
/// TC2 DP child sets `use_vbt_vswing` (218+) and carries
/// `BDB_VSWING_PREEMPH` gives the port table 5
/// (`intel_bios_get_c20_vspeo(..., is_uhbr = true)`); the service hands it
/// to the probe and `intel_ddi_buf_trans_get` takes it over
/// `mtl_c20_trans_uhbr`, so the sink's TX FFE presets 4 and 9 program rows
/// 4 (29, 5, 4) and 9 (34, 5, 9) as [pre, swing, post] on PHY lane 0's TX1
/// and TX2.
fn smoke_mtl_external_uhbr_vbt_c20_override() -> TestResult {
    use crate::intel_gpu_vbt::tests::{general_definitions, Child, VbtImage};
    use crate::intel_gpu_vbt::{block, device_type, dp_aux, dvo_port, Vbt};
    let child = Child::new(device_type::DP, dvo_port::DPG)
        .aux(dp_aux::G)
        .typec()
        .byte(23, 1 << 5);
    let image = VbtImage::new(250)
        .block(
            block::GENERAL_DEFINITIONS,
            general_definitions(44, &[child]),
        )
        .block(block::VSWING_PREEMPH, vspeo_block(6, 3))
        .build();
    let Ok(vbt) = Vbt::parse(&image) else {
        return TestResult::Fail("the VBT must parse");
    };
    let policy = MtlPortPolicy::from_vbt(&vbt);
    let Some(table) = policy.tc[1].c20_uhbr_vspeo else {
        return TestResult::Fail("TC2's DP child must carry the C20 UHBR override");
    };
    for (r, e) in table.iter().enumerate() {
        let r = r as u8;
        if *e != crate::intel_gpu_xelpg::snps(25 + r, 5, r) {
            return TestResult::Fail("the override must be table 5, truncated to bytes");
        }
    }
    if policy.tc[0].c20_uhbr_vspeo.is_some() || !policy.tc[1].dp {
        return TestResult::Fail("only the requesting DP child gets an override");
    }
    let io = uhbr_tc();
    let mut service = MtlExternalService::new();
    service.set_generation(Generation::MeteorLake);
    service.set_uhbr(true);
    if !service.set_policy(policy) {
        return TestResult::Fail("the policy must install with no route");
    }
    let event = MtlHpdEvent {
        pin: MtlHpdPin::Tc2,
        kind: MtlHpdKind::Connected(LiveMode::DpAlt),
    };
    match service.handle(&io, event, &mut fb_for) {
        ServiceOutcome::Activated { .. } => {}
        other => {
            use core::fmt::Write as _;
            let _ = writeln!(narf_console::Writer, "override route: {other:?}");
            return TestResult::Fail("the 128b/132b route must light with the override");
        }
    }
    let vdr = |a: u16| io.phy.vdr_get(0, a);
    if [vdr(0xD80), vdr(0xD81), vdr(0xD82)] != [5, 29, 4]
        || [vdr(0xD90), vdr(0xD91), vdr(0xD92)] != [5, 34, 9]
    {
        return TestResult::Fail("presets 4 and 9 must take the VBT rows, not mtl_c20_trans_uhbr");
    }
    match service.route() {
        Some(MtlRoute::Dp(r)) if r.probe.c20_uhbr_vspeo.as_deref() == Some(&table) => {}
        _ => return TestResult::Fail("the probe must keep the port's override"),
    }
    if !service.teardown(&io) {
        return TestResult::Fail("the override route must stop and release");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_uhbr_vbt_c20_override
);

/// The VBT's DP 1.4 overrides on 8b/10b links (`mtl_get_c10_buf_trans_override`,
/// `mtl_get_c20_buf_trans_override` with `is_uhbr` false): DP children on
/// DDI B (C10 on Meteor Lake) and TC1 (C20) with `use_vbt_vswing` and a
/// six-table `BDB_VSWING_PREEMPH` (table `t` row 0 is vswing 20 + t,
/// pre-cursor t, post-cursor 0). Under `narf.intel.uhbr=1` the trained level
/// (swing 0, pre-emphasis 0: row 0) on PHY lane 0 is [pre, swing, post] =
/// [0, 20, 0] from table 0 at RBR on DDI B (`intel_bios_get_c10_vspeo`:
/// `port_clock <= 270000`), [1, 21, 0] from table 1 at HBR2, and [4, 24, 0]
/// from table 4 on TC1 (`intel_bios_get_c20_vspeo`). Without the option the
/// same routes keep `mtl_c10_trans_dp14` row 0 [0, 26, 0] and
/// `mtl_c20_trans_dp14` row 0 [0, 20, 0], and the probe carries no override.
fn smoke_mtl_external_vbt_dp14_overrides() -> TestResult {
    use crate::intel_gpu_vbt::tests::{general_definitions, Child, VbtImage};
    use crate::intel_gpu_vbt::{block, device_type, dp_aux, dvo_port, Vbt};
    let ddi_b = Child::new(device_type::DP, dvo_port::DPB)
        .aux(dp_aux::B)
        .byte(23, 1 << 5);
    let tc1 = Child::new(device_type::DP, dvo_port::DPF)
        .aux(dp_aux::F)
        .typec()
        .byte(23, 1 << 5);
    let image = VbtImage::new(250)
        .block(
            block::GENERAL_DEFINITIONS,
            general_definitions(44, &[ddi_b, tc1]),
        )
        .block(block::VSWING_PREEMPH, vspeo_block(6, 3))
        .build();
    let Ok(vbt) = Vbt::parse(&image) else {
        return TestResult::Fail("the VBT must parse");
    };
    let policy = MtlPortPolicy::from_vbt(&vbt);
    let row0 = |t: u8| crate::intel_gpu_xelpg::snps(20 + t, t, 0);
    let Some(b) = policy.ddi_b.dp14_vspeo else {
        return TestResult::Fail("DDI B's DP child must carry the DP 1.4 overrides");
    };
    if b.c10.map(|t| t.map(|t| t[0])) != [Some(row0(0)), Some(row0(1))]
        || b.c20.map(|t| t[0]) != Some(row0(4))
        || policy.tc[0].dp14_vspeo.is_none()
        || policy.tc[1].dp14_vspeo.is_some()
    {
        return TestResult::Fail("tables 0, 1 and 4 for each requesting DP child");
    }
    let b = ddi_b_event(MtlHpdKind::Connected(LiveMode::Native));
    let tc = MtlHpdEvent {
        pin: MtlHpdPin::Tc1,
        kind: MtlHpdKind::Connected(LiveMode::DpAlt),
    };
    let cases: [(XeLpgPort, MtlHpdEvent, Vec<u8>, bool, [u8; 3]); 5] = [
        (XeLpgPort::B, b, edid_1024(), true, [0, 20, 0]),
        (XeLpgPort::B, b, edid_uhd(594_000), true, [1, 21, 0]),
        (XeLpgPort::B, b, edid_1024(), false, [0, 26, 0]),
        (XeLpgPort::Tc1, tc, edid_1024(), true, [4, 24, 0]),
        (XeLpgPort::Tc1, tc, edid_1024(), false, [0, 20, 0]),
    ];
    for (port, event, edid, uhbr_on, want) in cases {
        let io = ExtFake::new(port, Sink::new(0x14, edid));
        let mut service = MtlExternalService::new();
        service.set_generation(Generation::MeteorLake);
        service.set_uhbr(uhbr_on);
        if !service.set_policy(policy) {
            return TestResult::Fail("the policy must install with no route");
        }
        match service.handle(&io, event, &mut fb_for) {
            ServiceOutcome::Activated { .. } => {}
            other => {
                use core::fmt::Write as _;
                let _ = writeln!(narf_console::Writer, "DP 1.4 override route: {other:?}");
                return TestResult::Fail("the 8b/10b route must light");
            }
        }
        let vdr = |a: u16| io.phy.vdr_get(0, a);
        if [vdr(0xD80), vdr(0xD81), vdr(0xD82)] != want {
            return TestResult::Fail("the trained level takes the override only with the option");
        }
        match service.route() {
            Some(MtlRoute::Dp(r))
                if r.probe.uhbr.is_none() && r.probe.dp14_vspeo.is_some() == uhbr_on => {}
            _ => return TestResult::Fail("the probe holds the override only with the option"),
        }
        if !service.teardown(&io) {
            return TestResult::Fail("the route must stop and release");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_vbt_dp14_overrides
);

/// HDCP on a live 128b/132b SST route (`_intel_hdcp_enable` outside
/// `INTEL_OUTPUT_DP_MST`): the DP SST shim on the route's own CPU
/// transcoder (B), its port and native AUX, no MST streams (no
/// `stream_encryption`); the stopped route offers nothing.
fn smoke_mtl_external_uhbr_route_offers_sst_hdcp() -> TestResult {
    use crate::intel_hdcp_live::{MstStreams, RouteLink, XelpgRoute};
    let io = uhbr_tc();
    let profile = ExternalDisplayProfile::for_ip(DisplayIp::Xelpdp);
    let Ok(probe) = probe_sink_profile_uhbr(&io, profile, XeLpgPort::Tc2, false, true) else {
        return TestResult::Fail("the DP 2.0 sink must probe with UHBR on");
    };
    let fb = fb_for(&probe.mode).unwrap();
    let route = match activate(&io, probe, fb, &MtlDisplay::NONE) {
        Ok(route) if route.probe.uhbr.is_some() && route.state() == RouteState::Live => route,
        _ => return TestResult::Fail("the 128b/132b route must light"),
    };
    let mut route = MtlRoute::Dp(route);
    let want = XelpgRoute {
        port: XeLpgPort::Tc2 as u8,
        transcoder: Transcoder::B as u8,
        protocol: crate::intel_hdcp::Protocol::Dp,
        link: RouteLink::Dp(crate::intel_hdcp_shim::AuxPort::XeLpdp {
            base: XeLpgPort::Tc2.aux_base(),
            tbt_io: false,
        }),
        mst: MstStreams::default(),
    };
    if hdcp_route_of(&route) != Some(want) {
        return TestResult::Fail("a 128b/132b SST route must be offered as DP SST HDCP");
    }
    let MtlRoute::Dp(r) = &mut route else {
        return TestResult::Fail("the route is DP");
    };
    if r.stop(&io).is_err() || route.live() {
        return TestResult::Fail("the route must stop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_uhbr_route_offers_sst_hdcp
);

/// A sparse DPCD image for [`plan_uhbr`].
struct Dpcd(Vec<(u32, u8)>);

impl crate::dp_aux::AuxChannel for Dpcd {
    fn transact<'a>(
        &mut self,
        req: &crate::dp_aux::AuxRequest<'_>,
        reply: &'a mut [u8],
    ) -> Result<crate::dp_aux::AuxResponse<'a>, crate::dp_aux::AuxError> {
        use crate::dp_aux::{AuxCommand, AuxResponse, AuxStatus};
        reply[0] = 0;
        let n = match req.cmd {
            AuxCommand::NativeRead => req.data.len(),
            _ => 0,
        };
        for i in 0..n {
            let a = req.address + i as u32;
            reply[1 + i] = self.0.iter().find(|(x, _)| *x == a).map_or(0, |(_, v)| *v);
        }
        Ok(AuxResponse {
            status: AuxStatus::Ack,
            data: &reply[1..1 + n],
        })
    }
}

/// What `plan_uhbr` decides (nothing programmed): a stream only DSC carries
/// compresses over UHBR (a branch device refuses), UHBR over display-14
/// Thunderbolt alt mode is refused typed; an LTTPR that
/// masks the rates to UHBR10; and what keeps the 8b/10b negotiation: no common UHBR rate, a C10 PHY or
/// Wildcat Lake as the source, a DSC-less sink nothing fits.
fn smoke_mtl_external_uhbr_typed_refusals() -> TestResult {
    let mut raw = [0u8; 16];
    raw[0] = 0x14;
    raw[1] = 0x14;
    raw[2] = 2 | 0x40 | 0x80;
    raw[6] = 1 << 1;
    let link = |display_ip, mode| LinkProbe {
        display_ip,
        port: XeLpgPort::Tc2,
        tc: Some(TcConnection {
            port: XeLpgPort::Tc2,
            tc: 1,
            mode,
            legacy_port: false,
            pin_assignment: crate::intel_gpu_xelpg_tc::PIN_ASSIGNMENT_D,
            max_lanes: 2,
            profile: TcDisplayProfile::XeLpdp,
        }),
        raw,
    };
    let rates = |r: u8| Dpcd(alloc::vec![(uhbr::DP_128B132B_SUPPORTED_LINK_RATES, r)]);
    let limits = dsc::LinkLimits::standard(540_000, 2);
    let uhd60 = crate::intel_gpu_dp::mode_from_edid(&edid_uhd(594_000)).unwrap();
    let uhd120 = Mode {
        pixel_clock_khz: 1_188_000,
        ..uhd60
    };
    let dp_alt = link(DisplayIp::Xelpdp, TcMode::DpAlt);
    let refusal = |r| Err::<Option<UhbrChoice>, _>(ExternalError::Uhbr(r));
    // 4K120 fits neither HBR2 x2 nor UHBR10 x2 at 18 bpp: Linux 7.4's DSC
    // search walks the compressed bpp down (four slices: the 340000 kP/s
    // slice throughput; display 14's DPT limit is 17 bpp on UHBR10) and
    // lands on UHBR10 x2 at 258/16 bpp, 64 slots (8b/10b HBR2 x2 would need
    // 113/16 bpp, below the 8 bpp minimum).
    let monitor = dsc::DpDscSink {
        dsc: dsc::DscSink {
            dpcd: dsc::DscDpcd(MONITOR_DSC),
            is_edp: false,
            fec_capable: true,
        },
        branch: false,
    };
    match plan_uhbr(
        &mut rates(uhbr::DP_UHBR10),
        &dp_alt,
        false,
        &limits,
        &uhd120,
        24,
        Some(&monitor),
    ) {
        Ok(Some(c))
            if c.dsc.is_some_and(|d| {
                d.link_rate == 1_000_000
                    && d.lanes == 2
                    && !d.fec
                    && d.compressed_bpp_x16 == 258
                    && d.slice_count == 4
            }) && c.plan.stream.tu == 64
                && c.plan.link.lanes == 2 => {}
        _ => return TestResult::Fail("4K120 must compress over UHBR10 x2 at 258/16 bpp"),
    }
    let branch = dsc::DpDscSink {
        branch: true,
        ..monitor
    };
    if plan_uhbr(
        &mut rates(uhbr::DP_UHBR10),
        &dp_alt,
        false,
        &limits,
        &uhd120,
        24,
        Some(&branch),
    ) != Err(ExternalError::Dsc(DscRefusal::BranchDevice))
        || plan_uhbr(
            &mut rates(uhbr::DP_UHBR10),
            &dp_alt,
            false,
            &limits,
            &uhd120,
            24,
            None,
        ) != Ok(None)
    {
        return TestResult::Fail("a branch device refuses, a DSC-less sink keeps 8b/10b");
    }
    let tbt = link(DisplayIp::Xelpdp, TcMode::TbtAlt);
    if plan_uhbr(
        &mut rates(uhbr::DP_UHBR10),
        &tbt,
        false,
        &limits,
        &uhd60,
        24,
        None,
    ) != refusal(uhbr::UhbrRefusal::Tbt)
    {
        return TestResult::Fail("UHBR over Thunderbolt alt mode must refuse typed");
    }
    let mut lttpr = rates(uhbr::DP_UHBR10 | uhbr::DP_UHBR20);
    for (i, b) in [0x20u8, 0x1e, 0x80, 0x55, 4, 0, 1, uhbr::DP_UHBR10]
        .into_iter()
        .enumerate()
    {
        lttpr.0.push((uhbr::DP_LTTPR_COMMON_CAPS + i as u32, b));
    }
    // Through a 128b/132b LTTPR (UHBR10 only): UHBR10 x2.
    match plan_uhbr(&mut lttpr, &dp_alt, false, &limits, &uhd60, 24, None) {
        Ok(Some(c)) if c.plan.link.rate == uhbr::UhbrRate::Uhbr10 && c.plan.link.lanes == 2 => {}
        _ => return TestResult::Fail("an LTTPR masks the rates and keeps UHBR10 x2"),
    }
    // What leaves the 8b/10b route alone.
    let wcl = link(DisplayIp::WildcatLake, TcMode::DpAlt);
    if plan_uhbr(
        &mut rates(uhbr::DP_UHBR13_5),
        &dp_alt,
        false,
        &limits,
        &uhd60,
        24,
        None,
    ) != Ok(None)
        || plan_uhbr(
            &mut rates(uhbr::DP_UHBR10),
            &dp_alt,
            true,
            &limits,
            &uhd60,
            24,
            None,
        ) != Ok(None)
        || plan_uhbr(
            &mut rates(uhbr::DP_UHBR10),
            &wcl,
            false,
            &limits,
            &uhd60,
            24,
            None,
        ) != Ok(None)
    {
        return TestResult::Fail("no common UHBR rate, a C10 or WCL source keeps 8b/10b");
    }
    match plan_uhbr(
        &mut rates(uhbr::DP_UHBR20),
        &dp_alt,
        false,
        &limits,
        &uhd60,
        24,
        None,
    ) {
        Ok(Some(c)) if c.plan.link.rate == uhbr::UhbrRate::Uhbr20 && c.plan.link.lanes == 1 => {}
        _ => return TestResult::Fail("a UHBR20-only sink takes UHBR20 x1"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_uhbr_typed_refusals
);

/// A UHBR-capable MST hub under `narf.intel.uhbr=1` in display-14
/// Thunderbolt alt mode is refused typed at connect, before any sideband
/// message (128b/132b MST would need the TBT UHBR clock display 14 does not
/// have), and leaves nothing owned.
fn smoke_mtl_external_uhbr_mst_hub_refused() -> TestResult {
    let mut sink = Sink::dp20(0x1e, edid_1024(), uhbr::DP_UHBR10 | uhbr::DP_UHBR20);
    // DP_MSTM_CAP.
    sink.extra.push((0x21, 1));
    let io = ExtFake::new(XeLpgPort::Tc2, sink);
    io.pica_isr.set(pica_tbt_hotplug(1));
    let event = MtlHpdEvent {
        pin: MtlHpdPin::Tc2,
        kind: MtlHpdKind::Connected(LiveMode::TbtAlt),
    };
    let mut service = MtlExternalService::new();
    service.set_generation(Generation::MeteorLake);
    service.set_uhbr(true);
    match service.handle(&io, event, &mut fb_for) {
        ServiceOutcome::Refused {
            error: RouteError::Dp(ExternalError::Uhbr(uhbr::UhbrRefusal::Tbt)),
            ..
        } => {}
        other => {
            use core::fmt::Write as _;
            let _ = writeln!(narf_console::Writer, "TBT UHBR MST hub: {other:?}");
            return TestResult::Fail("a display-14 TBT UHBR MST hub must refuse typed");
        }
    }
    if service.route().is_some()
        || !io.sink.borrow().uhbr_log.is_empty()
        || io.sink.borrow().uhbr_reads.first() != Some(&uhbr::DP_128B132B_SUPPORTED_LINK_RATES)
    {
        return TestResult::Fail("the refused hub must leave nothing owned or written");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_uhbr_mst_hub_refused
);

/// The tunnel DPCD of a USB4 DP IN adapter with BW allocation: tunneling and
/// BW allocation support, USB4 driver 1 (with its BW allocation support),
/// group 1, 0.25 Gbps granularity, 72 units (2250000 kBps) estimated,
/// nothing allocated, and a DPRX of HBR3 x2 with UHBR10 and the 128b/132b
/// lane 0 mapping.
pub(crate) fn usb4_adapter() -> [u8; 0x32] {
    let mut t = [0u8; 0x32];
    t[0x0d] = tunnel::DP_TUNNELING_SUPPORT | tunnel::DP_IN_BW_ALLOCATION_MODE_SUPPORT;
    t[0x0f] = 1;
    t[0x20] = tunnel::DP_USB4_DRIVER_BW_ALLOCATION_MODE_SUPPORT;
    t[0x21] = 1;
    t[0x23] = 72;
    t[0x28] = 0x1e;
    t[0x29] = 2;
    t[0x2b] = tunnel::DP_128B132B_DP_SUPPORTED;
    t[0x2c] = 0x01 | tunnel::DP_TUNNELING_128B132B_LL_LANE0_MAPPING_SUPPORT;
    t
}

/// `narf.intel.uhbr=1` on Panther Lake TC2 in Thunderbolt alt mode: the
/// tunnelled 4K60 DPRX reports HBR2 and no 128b/132b rate in its own DPCD
/// (DP 2.1 5.14.3); after the unconditional
/// `DP_128B132B_SUPPORTED_LINK_RATES` read, `drm_dp_tunnel_detect` and
/// `drm_dp_tunnel_enable_bw_alloc` (`DP_DPTX_BW_ALLOCATION_MODE_CONTROL`
/// 0xc0) the tunnel's UHBR10, HBR3 x2 and 2250000 kBps make
/// `intel_dp_compute_link_config_wide` pick UHBR10 x2 at 24 bpp (HBR3 x2
/// carries 1620000 kBps, the mode needs 1782000; UHBR10 x2's 2417750 is
/// capped at 2250000). Before the port, `drm_dp_tunnel_alloc_bw` asks for
/// `DIV_ROUND_UP(1782000, 31250)` = 58 units; the port clock is the
/// fabric's `XELPDP_DDI_CLOCK_SELECT_TBT_312_5` (0x18 in the five-bit field)
/// with `DDI_CLK_VALFREQ` 312500 and the TBT IO select, and no PHY PLL,
/// message-bus or level transaction. The stop frees the 58 units and
/// disables BW allocation.
fn smoke_ptl_external_uhbr_over_tbt_tunnel() -> TestResult {
    let port = XeLpgPort::Tc2;
    let mut sink = Sink::new(0x14, edid_uhd(594_000));
    sink.caps[2] = 2 | 0x40 | 0x80;
    sink.tunnel = Some(usb4_adapter());
    let io = ExtFake::new(port, sink);
    let Some(panel) = io.light_panel_ip(DisplayIp::Xe3Lpd) else {
        return TestResult::Fail("the fixture must light the display-30 panel");
    };
    io.pica_isr.set(pica_tbt_hotplug(1));
    let profile = ExternalDisplayProfile::for_ip(DisplayIp::Xe3Lpd);
    let probe = match probe_sink_profile_uhbr(&io, profile, port, false, true) {
        Ok(probe) => probe,
        Err(e) => {
            use core::fmt::Write as _;
            let _ = writeln!(narf_console::Writer, "TBT UHBR probe: {e:?}");
            return TestResult::Fail("the tunnelled DP 2.0 sink must probe with UHBR on");
        }
    };
    let Some(plan) = probe.uhbr.as_deref().copied() else {
        return TestResult::Fail("only the tunnel's UHBR10 carries 4K60 on two lanes");
    };
    let mn = [(47 << 25) | 0x5e_579e, 0x80_0000, 0xf_34d6, 0x8_0000];
    let Some(t) = plan.tunnel else {
        return TestResult::Fail("the plan must keep the BW-allocation tunnel");
    };
    if !probe.tbt()
        || plan.link
            != (uhbr::UhbrLink {
                rate: uhbr::UhbrRate::Uhbr10,
                lanes: 2,
                pipe_bpp: 24,
            })
        || plan.stream.tu != 48
        || plan.stream.m_n != mn
        || !t.bw_alloc_enabled
        || t.available_bw != Some(2_250_000)
        || t.allocated_bw.is_some()
    {
        return TestResult::Fail("the tunnel's caps must give Linux's UHBR10 x2 link");
    }
    {
        let sink = io.sink.borrow();
        if sink.uhbr_reads.first() != Some(&uhbr::DP_128B132B_SUPPORTED_LINK_RATES)
            || sink.tunnel_log != [(tunnel::DP_DPTX_BW_ALLOCATION_MODE_CONTROL, 0xc0)]
        {
            return TestResult::Fail("probe: the 128b/132b rates read, then BWA enabled");
        }
    }
    let fb = fb_for(&probe.mode).unwrap();
    let display = MtlDisplay {
        panel: Some(panel),
        pipe_dmc: &NoPipeDmc,
    };
    io.phy.writes.borrow_mut().clear();
    let mut route = match activate(&io, probe, fb, &display) {
        Ok(route) if route.state() == RouteState::Live => route,
        Ok(_) => return TestResult::Fail("the TBT 128b/132b route must be live"),
        Err(ActivateError::Refused(_, e)) | Err(ActivateError::Failed(_, e)) => {
            use core::fmt::Write as _;
            let _ = writeln!(narf_console::Writer, "TBT UHBR activate: {e:?}");
            return TestResult::Fail("the TBT 128b/132b route must light");
        }
    };
    let req = tunnel::DP_BW_REQUEST_SUCCEEDED | tunnel::DP_BW_REQUEST_FAILED;
    {
        let sink = io.sink.borrow();
        if sink.tunnel_log[1..]
            != [
                (tunnel::DP_TUNNELING_STATUS, req),
                (tunnel::DP_REQUEST_BW, 58),
                (tunnel::DP_TUNNELING_STATUS, req),
            ]
        {
            return TestResult::Fail("the stream's 58 units must be requested and acknowledged");
        }
    }
    if route
        .probe
        .uhbr
        .as_deref()
        .and_then(|p| p.tunnel)
        .and_then(|t| t.allocated_bw)
        != Some(58 * 31_250)
    {
        return TestResult::Fail("the route must record the granted allocation");
    }
    let clock = io.read32(port.port_clock_ctl());
    if clock & crate::intel_gpu_xelpg::XE3_DDI_CLOCK_SELECT_MASK
        != crate::intel_gpu_xelpg::DDI_CLOCK_SELECT_TBT_312_5 << 12
        || clock & crate::intel_gpu_xelpg::TBT_CLOCK_REQUEST == 0
        || io.read32(port.clk_valfreq().unwrap()) != 312_500
        || io.read32(port.buf_ctl1()) & PORT_BUF_IO_SELECT_TBT == 0
        || io.read32(port.buf_ctl1()) & (3 << 18) != 2 << 18
    {
        return TestResult::Fail("UHBR10 over TBT runs the fabric's 312.5 MHz select, 40-bit");
    }
    if io.phy.writes.borrow().iter().any(|(off, _)| {
        (*off >= port.msgbus_ctl_ln0() && *off < port.msgbus_ctl_ln0() + 0x20)
            || *off == port.buf_ctl2()
    }) || io.read32(port.buf_ctl1()) & TC_PHY_OWNERSHIP != 0
    {
        return TestResult::Fail("TBT UHBR must leave the C20 PHY to the fabric");
    }
    if io.writes_to(0x6_10a0) != [1 << 31]
        || io
            .writes_to(TRANS_DDI_FUNC_CTL_B)
            .last()
            .map(|v| v & (7 << 24))
            != Some(4 << 24)
    {
        return TestResult::Fail("the transcoder must run 128b/132b");
    }
    if route.stop(&io).is_err() || route.state() != RouteState::Stopped {
        return TestResult::Fail("the TBT 128b/132b route must stop");
    }
    {
        let sink = io.sink.borrow();
        let log = &sink.tunnel_log;
        let free = log.iter().rposition(|&w| w == (tunnel::DP_REQUEST_BW, 0));
        let off = log
            .iter()
            .rposition(|&w| w == (tunnel::DP_DPTX_BW_ALLOCATION_MODE_CONTROL, 0x00));
        if !matches!((free, off), (Some(f), Some(o)) if f < o)
            || sink.tunnel.map(|t| t[0x24]) != Some(0)
        {
            return TestResult::Fail("stop: the allocation freed, then BWA disabled");
        }
    }
    if io.read32(port.port_clock_ctl())
        & (crate::intel_gpu_xelpg::TBT_CLOCK_REQUEST
            | crate::intel_gpu_xelpg::XE3_DDI_CLOCK_SELECT_MASK)
        != 0
    {
        return TestResult::Fail("stop: the TBT clock must be off");
    }
    let before = io.sink.borrow().tunnel_log.len();
    if route.release(&io).is_err() || io.sink.borrow().tunnel_log.len() != before {
        return TestResult::Fail("release must not touch the already handed-back tunnel");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_ptl_external_uhbr_over_tbt_tunnel
);

/// What keeps the tunnel out of a route: an 8b/10b stream through a
/// BW-allocation tunnel hands the tunnel back at probe
/// (`DP_DPTX_BW_ALLOCATION_MODE_CONTROL` 0xc0, then 0x00); a tunnel
/// without the 128b/132b lane 0 mapping drops the two-lane UHBR
/// configurations (`intel_dp_tunnel_uhbr_lanes_wa_apply`), so no UHBR link
/// carries 4K60 (the tunnel's HBR3 x2 at 18 bpp would), the tunnel is
/// handed back and the 8b/10b route, on the DPRX's own HBR2 x2, stays over
/// budget (Linux would keep BW allocation and run HBR3 x2); display 14
/// never reads the tunnel and a UHBR rate there is the typed `Tbt`
/// refusal.
fn smoke_external_uhbr_tbt_tunnel_refusals() -> TestResult {
    let port = XeLpgPort::Tc2;
    let profile = ExternalDisplayProfile::for_ip(DisplayIp::Xe3Lpd);
    // 1080p60 fits HBR3 x2: 8b/10b, the tunnel handed back.
    let mut sink = Sink::new(0x14, edid_1080());
    sink.caps[2] = 2 | 0x40 | 0x80;
    sink.tunnel = Some(usb4_adapter());
    let io = ExtFake::new(port, sink);
    if io.light_panel_ip(DisplayIp::Xe3Lpd).is_none() {
        return TestResult::Fail("the fixture must light the display-30 panel");
    }
    io.pica_isr.set(pica_tbt_hotplug(1));
    match probe_sink_profile_uhbr(&io, profile, port, false, true) {
        Ok(probe) if probe.uhbr.is_none() => {
            let _ = release_probe(&io, &probe);
        }
        _ => return TestResult::Fail("an 8b/10b stream must keep the 8b/10b route"),
    }
    let ctl = tunnel::DP_DPTX_BW_ALLOCATION_MODE_CONTROL;
    if io.sink.borrow().tunnel_log != [(ctl, 0xc0), (ctl, 0x00)] {
        return TestResult::Fail("an 8b/10b probe must hand the tunnel back");
    }
    // No lane 0 mapping: UHBR10 x2 is disabled, 4K60 fits nothing.
    let mut adapter = usb4_adapter();
    adapter[0x2c] = 0x01;
    let mut sink = Sink::new(0x14, edid_uhd(594_000));
    sink.caps[2] = 2 | 0x40 | 0x80;
    sink.tunnel = Some(adapter);
    let io = ExtFake::new(port, sink);
    if io.light_panel_ip(DisplayIp::Xe3Lpd).is_none() {
        return TestResult::Fail("the fixture must light the display-30 panel");
    }
    io.pica_isr.set(pica_tbt_hotplug(1));
    if !matches!(
        probe_sink_profile_uhbr(&io, profile, port, false, true),
        Err(ExternalError::OverBudget { .. })
    ) || io.sink.borrow().tunnel_log != [(ctl, 0xc0), (ctl, 0x00)]
    {
        return TestResult::Fail("without the lane 0 mapping two-lane UHBR must be dropped");
    }
    // Display 14 over TBT: no tunnel read; a UHBR rate refuses typed.
    let mut sink = Sink::dp20(0x14, edid_uhd(594_000), uhbr::DP_UHBR10);
    sink.caps[2] = 2 | 0x40 | 0x80;
    sink.tunnel = Some(usb4_adapter());
    let io = ExtFake::new(port, sink);
    io.pica_isr.set(pica_tbt_hotplug(1));
    let mtl = ExternalDisplayProfile::for_ip(DisplayIp::Xelpdp);
    if probe_sink_profile_uhbr(&io, mtl, port, false, true).err()
        != Some(ExternalError::Uhbr(uhbr::UhbrRefusal::Tbt))
        || !io.sink.borrow().tunnel_log.is_empty()
    {
        return TestResult::Fail("display 14 has no TBT UHBR clock: typed Tbt, no tunnel");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_external_uhbr_tbt_tunnel_refusals
);

/// A second 128b/132b route (`narf.intel.ext_routes=2`) whose tunnel shares
/// a BW allocation group with the sibling's (`lookup_or_alloc_group`: driver
/// 1, group 1, `drv_group_id` 9). The new tunnel is the Panther Lake TC2
/// probe's (0.25 Gbps = 31250 kBps units, 72 units = 2250000 kBps estimated,
/// nothing allocated, a UHBR10 x2 DPRX: `get_max_dprx_bw` =
/// roundup(2417750, 31250) = 2437500); its 4K60 stream needs 1782000 kBps
/// at UHBR10 x2 and 24 bpp. The sibling carries the same stream with 58
/// units (1812500) allocated. `calc_group_available_bw` = 1812500 +
/// (2250000 - 0) = 4062500; `drm_dp_tunnel_atomic_check_group_bw` sums
/// roundup(1782000, 31250) twice = 3625000: admitted, and Linux's first
/// link choice at the group cap is the probe's (HBR3 x2 and UHBR10 x1 carry
/// 1620000 and 1208875). With only 50 units (1562500) free the group has
/// 3375000 < 3625000 available and Linux would reduce the bpp of the
/// group's highest-bpp pipe, the lit sibling's (`intel_link_bw_reduce_bpp`):
/// refused typed. Tunnels in different groups, or with group ID 0, never
/// share; a probe whose link Linux's group-capped search would not pick is
/// refused too.
fn smoke_ptl_second_route_tunnel_group_bw() -> TestResult {
    let port = XeLpgPort::Tc2;
    let mut sink = Sink::new(0x14, edid_uhd(594_000));
    sink.caps[2] = 2 | 0x40 | 0x80;
    sink.tunnel = Some(usb4_adapter());
    let io = ExtFake::new(port, sink);
    if io.light_panel_ip(DisplayIp::Xe3Lpd).is_none() {
        return TestResult::Fail("the fixture must light the display-30 panel");
    }
    io.pica_isr.set(pica_tbt_hotplug(1));
    let profile = ExternalDisplayProfile::for_ip(DisplayIp::Xe3Lpd);
    let Ok(probe) = probe_sink_profile_uhbr(&io, profile, port, false, true) else {
        return TestResult::Fail("the tunnelled DP 2.0 sink must probe with UHBR on");
    };
    let Some((new, required)) = probe_tunnel_stream(&probe) else {
        return TestResult::Fail("the probe must run through the BW-allocation tunnel");
    };
    if required != 1_782_000 || new.drv_group_id != 9 || new.estimated_bw != 2_250_000 {
        return TestResult::Fail("the tunnel's stream and group facts must be the probe's");
    }
    let sibling = tunnel::Tunnel {
        allocated_bw: Some(58 * 31_250),
        ..new
    };
    if !tunnels_share_group(&sibling, &new)
        || group_available_bw(&sibling, &new) != 4_062_500
        || !group_bw_fits([(&sibling, 1_782_000), (&new, 1_782_000)], 3_625_000)
        || group_bw_fits([(&sibling, 1_782_000), (&new, 1_782_000)], 3_624_999)
        || group_bw_fits([(&sibling, 1_782_000), (&new, 2_437_501)], u32::MAX)
        || tunnel_group_admits(Some((sibling, 1_782_000)), &probe).is_err()
    {
        return TestResult::Fail("one group: 4062500 available carries both 1812500 shares");
    }
    // 50 units free: 3375000 available, the group check fails.
    let mut short = probe.clone();
    let mut plan = *short.uhbr.as_deref().expect("UHBR plan");
    plan.tunnel = Some(tunnel::Tunnel {
        estimated_bw: 50 * 31_250,
        ..new
    });
    short.uhbr = Some(alloc::boxed::Box::new(plan));
    let other_group = tunnel::Tunnel {
        drv_group_id: (1 << 3) | 2,
        ..sibling
    };
    let group_zero = tunnel::Tunnel {
        drv_group_id: 1 << 3,
        ..sibling
    };
    if plan.tunnel.map(|t| group_available_bw(&sibling, &t)) != Some(3_375_000)
        || tunnel_group_admits(Some((sibling, 1_782_000)), &short)
            != Err(SecondRouteRefusal::TunnelGroupBw)
        || tunnel_group_admits(Some((other_group, 1_782_000)), &short).is_err()
        || tunnels_share_group(&group_zero, &group_zero)
        || tunnel_group_admits(None, &short).is_err()
    {
        return TestResult::Fail("an overallocated group refuses; other groups never share");
    }
    // A probe at 18 bpp where the group cap admits 24: not Linux's choice.
    let mut low = probe.clone();
    let mut plan = *low.uhbr.as_deref().expect("UHBR plan");
    plan.link.pipe_bpp = 18;
    low.uhbr = Some(alloc::boxed::Box::new(plan));
    if tunnel_group_admits(Some((sibling, 1_782_000)), &low)
        != Err(SecondRouteRefusal::TunnelGroupBw)
    {
        return TestResult::Fail("a link Linux's group-capped search would not pick refuses");
    }
    let _ = release_probe(&io, &probe);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_ptl_second_route_tunnel_group_bw
);

// ── Nova Lake-S display 35: the routes through the LT PHY ───────────

#[cfg(feature = "kernel-test")]
pub(crate) mod nova {
    use super::*;

    /// Display 35 around [`ExtFake`], behind which the route runs through the
    /// display-35 view ([`crate::intel_gpu_xe3plpd::View`]): the LT PHY model
    /// (`intel_gpu_lt_phy::tests::FakeLtMmio`) answers the port's LT-only
    /// registers at their PICA offsets (`PORT_BUF_CTL2`, `PORT_BUF_CTL5`, the
    /// lane-0/1 message bus, `PORT_CLOCK_CTL`, the P2P status), DDI B's other
    /// relocated PHY/AUX registers map back to the display-14 offsets the model
    /// answers at, and an access to DDI B's display-14 PHY offsets is a stray.
    /// AUX power status follows its request (the LT handshake).
    pub(crate) struct NovaExt {
        pub(crate) ext: ExtFake,
        pub(crate) lt: crate::intel_gpu_lt_phy::tests::FakeLtMmio,
        pub(crate) strays: RefCell<Vec<u64>>,
    }

    impl NovaExt {
        pub(crate) fn new(ext: ExtFake) -> Self {
            Self {
                ext,
                lt: crate::intel_gpu_lt_phy::tests::FakeLtMmio::default(),
                strays: RefCell::new(Vec::new()),
            }
        }
        /// The port's PHY block at its PICA (TC1-layout) offset.
        fn pica_base(&self) -> u64 {
            match self.ext.port {
                XeLpgPort::B => 0x16_fc00,
                XeLpgPort::Tc1 => 0x16_f200,
                XeLpgPort::Tc2 => 0x16_f400,
                _ => 0,
            }
        }
        pub(crate) fn lt_reg(&self, r: u64) -> bool {
            let base = self.pica_base();
            base != 0
                && [0x04, 0x34, 0x40, 0x44, 0x48, 0x4c, 0x60, 0xa0, 0xa4]
                    .contains(&(r.wrapping_sub(base)))
        }
        /// DDI B's relocated `PORT_BUF_CTL1/3`, AUX and message-bus timer.
        fn display14_offset(&self, r: u64) -> Option<u64> {
            if self.ext.port != XeLpgPort::B {
                return None;
            }
            match r {
                0x16_fc00 | 0x16_fc08 => Some(r - 0x16_fc00 + 0x6_4104),
                0x16_fc10..=0x16_fc24 => Some(r - 0x16_fc00 + 0x6_4100),
                0x16_fc58 | 0x16_fc5c => Some(r - 0x16_fc00 + 0x6_4180),
                _ => None,
            }
        }
        fn display14_phy(&self, r: u64) -> bool {
            self.ext.port == XeLpgPort::B
                && matches!(r, 0x6_4104..=0x6_4124 | 0x6_4140..=0x6_414c | 0x6_41d8 | 0x6_41dc | 0x6_41e0)
        }
        fn aux_ctl(&self) -> u64 {
            match self.ext.port {
                XeLpgPort::B => 0x16_fc10,
                port => port.aux_ctl(),
            }
        }
    }

    impl MmioWindow for NovaExt {
        fn display_access_ok(&self) -> bool {
            self.ext.display_access_ok()
        }
        fn has_lt_phy(&self) -> bool {
            true
        }
        fn read32(&self, r: u64) -> u32 {
            if self.display14_phy(r) {
                self.strays.borrow_mut().push(r);
                return u32::MAX;
            }
            if self.lt_reg(r) {
                return self.lt.read32(r);
            }
            let value = self.ext.read32(self.display14_offset(r).unwrap_or(r));
            if r == self.aux_ctl() && value & XELPDP_AUX_CH_CTL_POWER_REQUEST != 0 {
                value | crate::intel_gpu_aux::XELPDP_AUX_CH_CTL_POWER_STATUS
            } else {
                value
            }
        }
        fn write32(&self, r: u64, v: u32) {
            if self.display14_phy(r) {
                self.strays.borrow_mut().push(r);
                return;
            }
            if self.lt_reg(r) {
                self.ext.writes.borrow_mut().push((r, v));
                return self.lt.write32(r, v);
            }
            self.ext.write32(self.display14_offset(r).unwrap_or(r), v)
        }
    }

    /// What the LT PHY of DDI B must hold after a lit external route: the
    /// PLL image `image` (`VDR0..2_CONFIG` on lane 0), MacCLK requested and
    /// acknowledged on lane 0 (`intel_lt_phy_pll_enable`), and each link lane's
    /// main cursor from its `levels` entry; no display-14 PHY access
    /// and no Cx0 message-bus transaction on the display-14 model.
    pub(crate) fn nova_lt_lit(
        io: &NovaExt,
        image: &crate::intel_gpu_lt_phy::LtPllState,
        levels: &[crate::intel_gpu_lt_phy::LtTxLevel],
    ) -> Result<(), &'static str> {
        use crate::intel_gpu_lt_phy::{
            txy_ctl, LT_PHY_VDR_0_CONFIG, LT_PHY_VDR_1_CONFIG, LT_PHY_VDR_2_CONFIG,
        };
        let vdr = |lane: u8, address: u16| io.lt.vdr.borrow().get(&(lane, address)).copied();
        for (n, address) in [
            LT_PHY_VDR_0_CONFIG,
            LT_PHY_VDR_1_CONFIG,
            LT_PHY_VDR_2_CONFIG,
        ]
        .into_iter()
        .enumerate()
        {
            if vdr(0, address) != Some(image.config[n]) {
                return Err("the LT PLL must hold the route's image");
            }
        }
        if io.lt.read32(io.pica_base() + 0x60) & (3 << 30) != 3 << 30 {
            return Err("MacCLK must be requested and acknowledged on lane 0");
        }
        for (link_lane, level) in (0u8..).zip(levels) {
            let main = vdr(link_lane / 2, txy_ctl(link_lane % 2, 3).unwrap());
            if main.map(|v| v & 0x3f) != Some(level.main_cursor) {
                return Err("every link lane must carry the LT DP 1.4 level");
            }
        }
        if !io.strays.borrow().is_empty() || !io.ext.phy.msgbus_txns(0).is_empty() {
            return Err("display 35 must never reach a Cx0 or display-14 PHY register");
        }
        Ok(())
    }

    /// Nova Lake-S native DP on LT port B (Pipe B beside the lit panel): the
    /// display-35 view, `intel_lt_phy_pll_enable` with the DP 1.4 image of the
    /// link's rate (`xe3plpd_lt_dp_tables`, no eDP mark), the trained level from
    /// `xe3plpd_lt_trans_dp14` (`intel_lt_phy_set_signal_levels`), the display
    /// 20+ D2D link in `DDI_BUF_CTL`; the stop releases MacCLK
    /// (`intel_lt_phy_pll_disable`) and the DDI.
    fn smoke_nvl_external_dp_on_lt_port_b() -> TestResult {
        use crate::intel_gpu_lt_phy::{dp_pll_state, signal_level, LtDpRate, LtSignalProtocol};
        let port = XeLpgPort::B;
        let io = NovaExt::new(ExtFake::new(port, Sink::new(0x14, edid_1024())));
        let Some(panel) = io.ext.light_panel_ip(DisplayIp::NovaLakeS) else {
            return TestResult::Fail("the fixture must light the display-35 panel");
        };
        let view = crate::intel_gpu_xe3plpd::View(&io);
        let profile = ExternalDisplayProfile::for_ip(DisplayIp::NovaLakeS);
        let probe = match probe_sink_profile(&view, profile, port, false) {
            Ok(probe) => probe,
            Err(_) => return TestResult::Fail("Nova DDI B probe must read the sink over PICA AUX"),
        };
        if probe.tc.is_some() || probe.display_version() != 35 {
            return TestResult::Fail("Nova DDI B owns no Type-C PHY and keeps display 35");
        }
        let fb = fb_for(&probe.mode).unwrap();
        let display = MtlDisplay {
            panel: Some(panel),
            pipe_dmc: &NoPipeDmc,
        };
        let mut route = match activate(&view, probe, fb, &display) {
            Ok(route) if route.state() == RouteState::Live && route.pipe == Pipe::B => route,
            _ => return TestResult::Fail("Nova DDI B DP must light Pipe B beside the panel"),
        };
        let clock = io.read32(port.clk_valfreq().unwrap());
        let Some(rate) = LtDpRate::from_clock_khz(clock).filter(|rate| !rate.is_uhbr()) else {
            return TestResult::Fail("DDI_CLK_VALFREQ must name a DP 1.4 link rate");
        };
        let image = dp_pll_state(rate);
        if image.config[2] != 0 {
            return TestResult::Fail("an external DP image carries no eDP mark");
        }
        // Each trained lane's intel_ddi_dp_level in xe3plpd_lt_trans_dp14.
        let levels: Vec<_> = route.trained.vswing_pe.lanes[..usize::from(route.trained.lanes)]
            .iter()
            .map(|lane| {
                signal_level(
                    LtSignalProtocol::Dp14,
                    crate::intel_gpu_xelpg::preset_index(lane.swing, lane.pre_emph),
                )
                .unwrap()
            })
            .collect();
        if let Err(e) = nova_lt_lit(&io, image, &levels) {
            return TestResult::Fail(e);
        }
        if io.read32(port.ddi_buf_ctl())
            & (DDI_BUF_CTL_ENABLE | crate::intel_gpu_xe2lpd::DDI_BUF_D2D_LINK_ENABLE)
            != DDI_BUF_CTL_ENABLE | crate::intel_gpu_xe2lpd::DDI_BUF_D2D_LINK_ENABLE
        {
            return TestResult::Fail("DDI_CTL_DE must carry the display-20+ D2D enable");
        }
        if route.stop(&view).is_err() || route.state() != RouteState::Stopped {
            return TestResult::Fail("Nova DDI B DP must stop");
        }
        if io.lt.read32(0x16_fc60) & (3 << 30) != 0
            || io.read32(port.ddi_buf_ctl()) & DDI_BUF_CTL_ENABLE != 0
            || !io.strays.borrow().is_empty()
        {
            return TestResult::Fail("the stop must release MacCLK and the DDI through the LT PHY");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xelpg_external",
        smoke_nvl_external_dp_on_lt_port_b
    );

    /// `narf.intel.uhbr=1` on Nova Lake-S LT port B: a DP 2.0 4K30 monitor
    /// whose 8b/10b ceiling is RBR (four RBR lanes carry 648000 kBps, the
    /// mode needs 891000 at 24 bpp and 668250 at 18) takes UHBR10 x1 at 24
    /// bpp (1208875 kBps, `tu` 48). The route enables the LT PHY at the
    /// `xe3plpd_lt_dp_uhbr10` image with `DDI_CLK_VALFREQ` = 312500, the
    /// requested `xe3plpd_lt_trans_uhbr` preset 15, `TRANS_DP2_CTL`, the
    /// 128b/132b function and the 40-bit `DDI_CTL_DE` beside its display-20+
    /// D2D enable, never a Cx0 or display-14 PHY register; the stop releases
    /// MacCLK and clears `TRANS_DP2_CTL`.
    fn smoke_nvl_external_uhbr_on_lt_port_b() -> TestResult {
        use crate::intel_gpu_lt_phy::{dp_pll_state, LtDpRate, UHBR_LEVELS};
        let port = XeLpgPort::B;
        let mut sink = Sink::dp20(0x06, edid_uhd(297_000), uhbr::DP_UHBR10 | uhbr::DP_UHBR20);
        sink.ffe_request = [15, 0, 0, 0];
        let io = NovaExt::new(ExtFake::new(port, sink));
        let Some(panel) = io.ext.light_panel_ip(DisplayIp::NovaLakeS) else {
            return TestResult::Fail("the fixture must light the display-35 panel");
        };
        let view = crate::intel_gpu_xe3plpd::View(&io);
        let profile = ExternalDisplayProfile::for_ip(DisplayIp::NovaLakeS);
        let probe = match probe_sink_profile_uhbr(&view, profile, port, false, true) {
            Ok(probe) => probe,
            Err(_) => return TestResult::Fail("the Nova DP 2.0 sink must probe with UHBR on"),
        };
        if probe
            .uhbr
            .as_deref()
            .map(|p| (p.link.rate, p.link.lanes, p.link.pipe_bpp, p.stream.tu))
            != Some((uhbr::UhbrRate::Uhbr10, 1, 24, 48))
        {
            return TestResult::Fail("4K30 over an RBR ceiling must take UHBR10 x1");
        }
        let fb = fb_for(&probe.mode).unwrap();
        let display = MtlDisplay {
            panel: Some(panel),
            pipe_dmc: &NoPipeDmc,
        };
        let mut route = match activate(&view, probe, fb, &display) {
            Ok(route) if route.state() == RouteState::Live && route.pipe == Pipe::B => route,
            _ => return TestResult::Fail("the Nova 128b/132b route must light Pipe B"),
        };
        if io.read32(port.clk_valfreq().unwrap()) != 312_500 {
            return TestResult::Fail("DDI_CLK_VALFREQ must be the UHBR10 symbol clock");
        }
        if let Err(e) = nova_lt_lit(&io, dp_pll_state(LtDpRate::Uhbr10), &[UHBR_LEVELS[15]]) {
            return TestResult::Fail(e);
        }
        if io.lt.read32(0x16_fc60)
            & (crate::intel_gpu_xelpg::SSC_ENABLE_PLLA | crate::intel_gpu_xelpg::SSC_ENABLE_PLLB)
            != 0
        {
            return TestResult::Fail("no sink downspread: no LT SSC");
        }
        if io.ext.writes_to(0x6_10a0).first() != Some(&(1 << 31))
            || io.read32(TRANS_DDI_FUNC_CTL_B) & (7 << 24) != 4 << 24
            || io.read32(port.ddi_buf_ctl())
                & (DDI_BUF_CTL_ENABLE
                    | crate::intel_gpu_xe2lpd::DDI_BUF_D2D_LINK_ENABLE
                    | (3 << 18))
                != DDI_BUF_CTL_ENABLE | crate::intel_gpu_xe2lpd::DDI_BUF_D2D_LINK_ENABLE | (2 << 18)
        {
            return TestResult::Fail("TRANS_DP2_CTL, the 128b/132b mode and the 40-bit DDI");
        }
        if route.stop(&view).is_err() || route.state() != RouteState::Stopped {
            return TestResult::Fail("the Nova 128b/132b route must stop");
        }
        if io.lt.read32(0x16_fc60) & (3 << 30) != 0
            || io.ext.writes_to(0x6_10a0).last() != Some(&0)
            || !io.strays.borrow().is_empty()
        {
            return TestResult::Fail("the stop must release MacCLK and TRANS_DP2_CTL");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xelpg_external",
        smoke_nvl_external_uhbr_on_lt_port_b
    );

    /// Nova Lake-S USB-C DP-alt on LT TC1: the Type-C connect under the exact
    /// display-35 profile (PICA power and TCSS, no Wa_14020908590 mailbox),
    /// then the LT PHY in DP-alt mode (`intel_lt_phy_pll_enable` with the
    /// connection's lanes) at the link's DP 1.4 image, never a C20 transaction;
    /// stop and release return the PHY and the Type-C ownership.
    fn smoke_nvl_external_tc_dp_alt_on_lt_tc1() -> TestResult {
        use crate::intel_gpu_lt_phy::{dp_pll_state, signal_level, LtDpRate, LtSignalProtocol};
        let port = XeLpgPort::Tc1;
        let io = NovaExt::new(ExtFake::new(port, Sink::new(0x14, edid_1024())));
        let Some(panel) = io.ext.light_panel_ip(DisplayIp::NovaLakeS) else {
            return TestResult::Fail("the fixture must light the display-35 panel");
        };
        let view = crate::intel_gpu_xe3plpd::View(&io);
        let profile = ExternalDisplayProfile::for_ip(DisplayIp::NovaLakeS);
        let probe = match probe_sink_profile(&view, profile, port, false) {
            Ok(probe) => probe,
            Err(_) => return TestResult::Fail("Nova TC1 probe must own PICA/TCSS/AUX"),
        };
        if probe
            .tc
            .is_none_or(|tc| tc.profile != TcDisplayProfile::NovaLakeS || tc.mode != TcMode::DpAlt)
            || !io
                .ext
                .writes_to(crate::intel_gpu_xelpg_tc::TCSS_DISP_MAILBOX_IN_CMD)
                .is_empty()
        {
            return TestResult::Fail("the DP-alt connect must keep the display-35 Type-C profile");
        }
        let fb = fb_for(&probe.mode).unwrap();
        let display = MtlDisplay {
            panel: Some(panel),
            pipe_dmc: &NoPipeDmc,
        };
        let mut route = match activate(&view, probe, fb, &display) {
            Ok(route) if route.state() == RouteState::Live => route,
            _ => return TestResult::Fail("Nova USB-C DP must activate beside Pipe A"),
        };
        let clock = io.read32(port.clk_valfreq().unwrap());
        let Some(rate) = LtDpRate::from_clock_khz(clock).filter(|rate| !rate.is_uhbr()) else {
            return TestResult::Fail("DDI_CLK_VALFREQ must name a DP 1.4 link rate");
        };
        let levels: Vec<_> = route.trained.vswing_pe.lanes[..usize::from(route.trained.lanes)]
            .iter()
            .map(|lane| {
                signal_level(
                    LtSignalProtocol::Dp14,
                    crate::intel_gpu_xelpg::preset_index(lane.swing, lane.pre_emph),
                )
                .unwrap()
            })
            .collect();
        if let Err(e) = nova_lt_lit(&io, dp_pll_state(rate), &levels) {
            return TestResult::Fail(e);
        }
        if io
            .ext
            .phy
            .writes
            .borrow()
            .iter()
            .any(|(off, _)| (port.msgbus_ctl_ln0()..port.msgbus_ctl_ln0() + 0x10).contains(off))
            || !io.ext.phy.sram_values().is_empty()
        {
            return TestResult::Fail("the TC1 PHY must take only LT transactions");
        }
        if route.stop(&view).is_err() || route.release(&view).is_err() {
            return TestResult::Fail("Nova USB-C DP must stop and release");
        }
        if io.lt.read32(0x16_f260) & (3 << 30) != 0
            || io.read32(port.buf_ctl1()) & TC_PHY_OWNERSHIP != 0
        {
            return TestResult::Fail("the release must drop MacCLK and the Type-C ownership");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xelpg_external",
        smoke_nvl_external_tc_dp_alt_on_lt_tc1
    );

    /// Nova Lake-S Thunderbolt alt mode on LT TC1. The live TBT HPD connects
    /// through the fabric (`xelpdp_tc_phy_connect`: no TCSS request, no PHY
    /// ownership) with PICA_TC powered for the tunnel's AUX_TBT and DDI-lane
    /// domains, and AUX selects TBT IO. `mtl_ddi_pre_enable_dp` selects TBT IO
    /// in `PORT_BUF_CTL1` before the port clock, which is the fabric's
    /// (`intel_mtl_tbt_pll_enable_clock`): `intel_mtl_tbt_clock_select` in the
    /// display-30 five-bit field with the forward clock ungated, the TBT
    /// request and its ACK, then `DDI_CLK_VALFREQ` at the link rate. The LT
    /// PHY takes no lane reset, PLL, transmitter or signal-level transaction
    /// (the TBT PLL's enable is a no-op, `intel_lt_phy_set_signal_levels`
    /// returns in TBT alt mode). The stop gates the TBT clock, clears
    /// VALFREQ and the IO select (`intel_mtl_tbt_pll_disable_clock`,
    /// `intel_ddi_post_disable_dp`); the release drops AUX power and PICA.
    fn smoke_nvl_external_tbt_alt_on_lt_tc1() -> TestResult {
        use crate::intel_gpu_xe2lpd::{PICA_POWER_REQUEST, PICA_PW_CTL};
        use crate::intel_gpu_xelpg::{
            lane_pclk_pll_request, FORWARD_CLOCK_UNGATE, PORT_BUF_IO_SELECT_TBT, TBT_CLOCK_ACK,
            TBT_CLOCK_REQUEST, XE3_DDI_CLOCK_SELECT_MASK,
        };
        let port = XeLpgPort::Tc1;
        let io = NovaExt::new(ExtFake::new(port, Sink::new(0x14, edid_1024())));
        io.ext.pica_isr.set(pica_tbt_hotplug(0));
        let Some(panel) = io.ext.light_panel_ip(DisplayIp::NovaLakeS) else {
            return TestResult::Fail("the fixture must light the display-35 panel");
        };
        let view = crate::intel_gpu_xe3plpd::View(&io);
        let profile = ExternalDisplayProfile::for_ip(DisplayIp::NovaLakeS);
        let probe = match probe_sink_profile(&view, profile, port, false) {
            Ok(probe)
                if probe.tc.is_some_and(|tc| {
                    tc.mode == TcMode::TbtAlt
                        && tc.max_lanes == 4
                        && tc.profile == TcDisplayProfile::NovaLakeS
                }) =>
            {
                probe
            }
            _ => return TestResult::Fail("Nova TBT-alt must probe the sink through the tunnel"),
        };
        if io.ext.read32(PICA_PW_CTL) & PICA_POWER_REQUEST == 0
            || io.ext.read32(port.buf_ctl1()) & (TCSS_POWER_REQUEST | TC_PHY_OWNERSHIP) != 0
            || !io
                .ext
                .aux_ctl_writes
                .borrow()
                .iter()
                .any(|v| v & AUX_CTL_TBT_IO != 0)
        {
            return TestResult::Fail("the tunnel must power PICA and select TBT AUX, not the PHY");
        }
        let fb = fb_for(&probe.mode).unwrap();
        let display = MtlDisplay {
            panel: Some(panel),
            pipe_dmc: &NoPipeDmc,
        };
        io.ext.writes.borrow_mut().clear();
        let mut route = match activate(&view, probe, fb, &display) {
            Ok(route) if route.state() == RouteState::Live && route.pipe == Pipe::B => route,
            _ => return TestResult::Fail("Nova TBT-alt DP must light Pipe B beside the panel"),
        };
        // intel_mtl_tbt_clock_select for the DP 1.4 rates.
        let khz = link_clock_khz(route.trained.rate);
        let Some(select) = [
            (162_000, 0xc),
            (270_000, 0xd),
            (540_000, 0xe),
            (810_000, 0xf),
        ]
        .into_iter()
        .find_map(|(rate, select)| (rate == khz).then_some(select)) else {
            return TestResult::Fail("the tunnel trains at a DP 1.4 rate");
        };
        let clock = io.read32(port.port_clock_ctl());
        if clock & XE3_DDI_CLOCK_SELECT_MASK != select << 12
            || clock & (FORWARD_CLOCK_UNGATE | TBT_CLOCK_REQUEST | TBT_CLOCK_ACK)
                != FORWARD_CLOCK_UNGATE | TBT_CLOCK_REQUEST | TBT_CLOCK_ACK
            || clock & lane_pclk_pll_request(0) != 0
            || io.read32(port.clk_valfreq().unwrap()) != khz
        {
            return TestResult::Fail("the port clock must be the fabric's at the trained rate");
        }
        let io_select = io
            .ext
            .first_write(|r, v| r == port.buf_ctl1() && v & PORT_BUF_IO_SELECT_TBT != 0);
        let request = io
            .ext
            .first_write(|r, v| r == port.port_clock_ctl() && v & TBT_CLOCK_REQUEST != 0);
        if !matches!((io_select, request), (Some(s), Some(r)) if s < r)
            || io.read32(port.buf_ctl1()) & PORT_BUF_IO_SELECT_TBT == 0
        {
            return TestResult::Fail("TBT IO must be selected before the TBT clock request");
        }
        // Nothing but PORT_CLOCK_CTL of the LT-only registers: no BUF_CTL2/5,
        // message-bus or P2P access, and no LT or Cx0 transaction.
        let lt_only = |r: u64| r != port.port_clock_ctl() && io.lt_reg(r);
        if io.ext.writes.borrow().iter().any(|&(r, _)| lt_only(r))
            || !io.lt.transactions.borrow().is_empty()
            || !io.lt.vdr.borrow().is_empty()
            || !io.ext.phy.msgbus_txns(0).is_empty()
            || !io.strays.borrow().is_empty()
        {
            return TestResult::Fail("the fabric's PHY must take no LT transaction");
        }
        if io.read32(port.ddi_buf_ctl())
            & (DDI_BUF_CTL_ENABLE | crate::intel_gpu_xe2lpd::DDI_BUF_D2D_LINK_ENABLE)
            != DDI_BUF_CTL_ENABLE | crate::intel_gpu_xe2lpd::DDI_BUF_D2D_LINK_ENABLE
        {
            return TestResult::Fail("DDI_CTL_DE must carry the display-20+ D2D enable");
        }
        if route.stop(&view).is_err() || route.state() != RouteState::Stopped {
            return TestResult::Fail("Nova TBT-alt DP must stop");
        }
        if io.read32(port.port_clock_ctl())
            & (XE3_DDI_CLOCK_SELECT_MASK | FORWARD_CLOCK_UNGATE | TBT_CLOCK_REQUEST | TBT_CLOCK_ACK)
            != 0
            || io.read32(port.clk_valfreq().unwrap()) != 0
            || io.read32(port.buf_ctl1()) & PORT_BUF_IO_SELECT_TBT != 0
            || io.read32(port.ddi_buf_ctl()) & DDI_BUF_CTL_ENABLE != 0
        {
            return TestResult::Fail("the stop must gate the TBT clock and deselect TBT IO");
        }
        if route.release(&view).is_err()
            || io.ext.read32(PICA_PW_CTL) & PICA_POWER_REQUEST != 0
            || io.ext.aux_power.get()
            || !io.lt.transactions.borrow().is_empty()
            || io.ext.writes.borrow().iter().any(|&(r, _)| lt_only(r))
        {
            return TestResult::Fail("the release must drop AUX power and PICA");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xelpg_external",
        smoke_nvl_external_tbt_alt_on_lt_tc1
    );

    /// Nova Lake-S DSC with FEC over LT TC2 (DP-alt, pin D) beside the lit
    /// panel. One HBR lane cannot carry 1080p60 even at 18 bpp, so the probe
    /// compresses with FEC (`intel_dp_compute_link_config`) on a one-lane HBR
    /// link. The LT PHY runs that link on PHY lane 0 alone
    /// (`intel_lt_phy_get_owned_lane_mask` for pin D): `xe3plpd_lt_dp_hbr1`,
    /// the pin-D single-lane transmitter 0 (`intel_lt_phy_enable_disable_tx`)
    /// and the lane's trained level. Display 30+ confirms the source FEC live
    /// before the PPS SDP, then Pipe B's engines and TRANSCONF; the stop
    /// waits for FEC off before the LT PHY releases MacCLK
    /// (`intel_lt_phy_pll_disable`), and the release returns the Type-C PHY.
    /// No Cx0 transaction or C20 SRAM state is staged.
    fn smoke_nvl_external_dsc_fec_over_lt_tc2() -> TestResult {
        use crate::intel_gpu_lt_phy::{dp_pll_state, signal_level, LtDpRate, LtSignalProtocol};
        use crate::intel_gpu_xelpg::lane_pclk_pll_request;
        let io = NovaExt::new(compressed_tc(0));
        let port = io.ext.port;
        let Some(panel) = io.ext.light_panel_ip(DisplayIp::NovaLakeS) else {
            return TestResult::Fail("the fixture must light the display-35 panel");
        };
        let view = crate::intel_gpu_xe3plpd::View(&io);
        let profile = ExternalDisplayProfile::for_ip(DisplayIp::NovaLakeS);
        let probe = match probe_sink_profile(&view, profile, port, false) {
            Ok(probe) => probe,
            Err(_) => return TestResult::Fail("the Nova USB-C DSC sink must probe"),
        };
        let Some(plan) = probe.dsc.filter(|plan| plan.fec) else {
            return TestResult::Fail("one HBR lane must compress 1080p60 with FEC");
        };
        if (plan.link_rate, plan.lanes) != (270_000, 1)
            || probe.negotiated.rate != TrainRate::Hbr
            || probe.negotiated.lanes != 1
            || probe
                .tc
                .is_none_or(|tc| tc.mode != TcMode::DpAlt || tc.max_lanes != 2)
        {
            return TestResult::Fail("the plan must keep the sink's one-lane HBR link");
        }
        let fb = fb_for(&probe.mode).unwrap();
        let display = MtlDisplay {
            panel: Some(panel),
            pipe_dmc: &NoPipeDmc,
        };
        io.ext.writes.borrow_mut().clear();
        let mut route = match activate(&view, probe, fb, &display) {
            Ok(route) if route.state() == RouteState::Live && route.pipe == Pipe::B => route,
            _ => return TestResult::Fail("the compressed Nova route must light Pipe B"),
        };
        let lane = &route.trained.vswing_pe.lanes[0];
        let level = signal_level(
            LtSignalProtocol::Dp14,
            crate::intel_gpu_xelpg::preset_index(lane.swing, lane.pre_emph),
        )
        .unwrap();
        if let Err(e) = nova_lt_lit(&io, dp_pll_state(LtDpRate::Hbr), &[level]) {
            return TestResult::Fail(e);
        }
        let vdr = |lane: u8, address: u16| io.lt.vdr.borrow().get(&(lane, address)).copied();
        if vdr(0, 0x040a) != Some(1)
            || vdr(0, 0x060a) != Some(0)
            || io.read32(port.clk_valfreq().unwrap()) != 270_000
            || !io.ext.phy.sram_values().is_empty()
        {
            return TestResult::Fail("pin D must drive transmitter 0 of PHY lane 0 at HBR");
        }
        let writes = io.ext.writes.borrow().clone();
        let pos = |f: &dyn Fn(u64, u32) -> bool| writes.iter().position(|&(o, v)| f(o, v));
        let fec = pos(&|o, v| o == DP_TP_CTL_B && v & dsc::DP_TP_CTL_FEC_ENABLE != 0);
        let pps = pos(&|o, _| o == 0x6_1350);
        let engines = pos(&|o, _| o == 0x7_8204);
        let enable = pos(&|o, v| o == PIPECONF_B && v & ENABLE != 0);
        let sdp = plan.pps_sdp();
        match (fec, pps, engines, enable) {
            (Some(f), Some(p), Some(c), Some(e)) if f < p && p < c && c < e => {}
            _ => return TestResult::Fail("FEC, the PPS SDP and the engines precede TRANSCONF"),
        }
        // The plan's Pipe B engine writes, in order (the display-30 Pipes
        // owner may program other DSS state around them).
        let mut log = writes.iter();
        if !plan
            .engine_writes(Pipe::B)
            .iter()
            .all(|write| log.any(|logged| logged == write))
            || (0..33).any(|i| io.ext.writes_to(0x6_1350 + 4 * i as u64) != [sdp[i]])
            || io.ext.read32(DP_TP_CTL_B) & dsc::DP_TP_CTL_FEC_ENABLE == 0
        {
            return TestResult::Fail("Pipe B must compress with the plan's engines and SDP");
        }
        io.ext.writes.borrow_mut().clear();
        if route.stop(&view).is_err() || route.state() != RouteState::Stopped {
            return TestResult::Fail("the compressed Nova route must stop");
        }
        let writes = io.ext.writes.borrow().clone();
        let pos = |f: &dyn Fn(u64, u32) -> bool| writes.iter().position(|&(o, v)| f(o, v));
        let fec_off = pos(&|o, v| {
            o == DP_TP_CTL_B && v & (DP_TP_CTL_ENABLE | dsc::DP_TP_CTL_FEC_ENABLE) == 0
        });
        let macclk_off =
            pos(&|o, v| o == port.port_clock_ctl() && v & lane_pclk_pll_request(0) == 0);
        if !matches!((fec_off, macclk_off), (Some(f), Some(m)) if f < m)
            || io.read32(port.port_clock_ctl()) & (3 << 30) != 0
            || io.ext.read32(0x7_8204) != 0
            || io.ext.read32(DP_TP_CTL_B) & dsc::DP_TP_CTL_FEC_ENABLE != 0
        {
            return TestResult::Fail("FEC must stop before the LT PHY releases MacCLK");
        }
        if route.release(&view).is_err()
            || io.read32(port.buf_ctl1()) & TC_PHY_OWNERSHIP != 0
            || !io.strays.borrow().is_empty()
            || !io.ext.phy.msgbus_txns(0).is_empty()
        {
            return TestResult::Fail("the release must return the Type-C PHY");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xelpg_external",
        smoke_nvl_external_dsc_fec_over_lt_tc2
    );

    /// Nova Lake-S HDMI TMDS on LT port B: 1080p60's 148.5 MHz TMDS clock takes
    /// the LT HDMI image (`xe3plpd_lt_hdmi_148_5`, `intel_lt_phy_pll_enable`),
    /// and `intel_lt_phy_set_signal_levels` the DP 1.4 table's default HDMI
    /// level on all four transmitters (`intel_ddi_hdmi_level`, no VBT level).
    /// No C10/C20 state is programmed; the stop releases the LT PLL.
    fn smoke_nvl_external_hdmi_tmds_on_lt_port_b() -> TestResult {
        use crate::intel_gpu_lt_phy::{hdmi_pll_state, hdmi_signal_level};
        use crate::intel_gpu_xelpg_hdmi::{
            activate_hdmi, ddc_pin, probe_hdmi_profile, HdmiRouteState,
        };
        let port = XeLpgPort::B;
        let io = NovaExt::new(hdmi_on_ddi_b(edid_1080()));
        let Some(panel) = io.ext.light_panel_ip(DisplayIp::NovaLakeS) else {
            return TestResult::Fail("the fixture must light the display-35 panel");
        };
        let view = crate::intel_gpu_xe3plpd::View(&io);
        let profile = ExternalDisplayProfile::for_ip(DisplayIp::NovaLakeS);
        let probe = match probe_hdmi_profile(&view, profile, port, false, ddc_pin(port)) {
            Ok(probe) => probe,
            Err(_) => return TestResult::Fail("Nova DDI B HDMI probe must read the EDID over DDC"),
        };
        if probe.pll.port_clock_khz != 148_500 {
            return TestResult::Fail("1080p60 RGB runs at a 148.5 MHz TMDS clock");
        }
        let fb = fb_for(&probe.mode).unwrap();
        let display = MtlDisplay {
            panel: Some(panel),
            pipe_dmc: &NoPipeDmc,
        };
        let mut route = match activate_hdmi(&view, probe, fb, &display) {
            Ok(route) if route.state() == HdmiRouteState::Live && route.pipe() == Pipe::B => route,
            _ => return TestResult::Fail("Nova DDI B HDMI must light Pipe B beside the panel"),
        };
        let image = hdmi_pll_state(148_500).unwrap();
        if io.read32(port.clk_valfreq().unwrap()) != 148_500 {
            return TestResult::Fail("DDI_CLK_VALFREQ must carry the TMDS clock");
        }
        if let Err(e) = nova_lt_lit(&io, &image, &[hdmi_signal_level(None).1; 4]) {
            return TestResult::Fail(e);
        }
        if !io.ext.phy.sram_values().is_empty() {
            return TestResult::Fail("no C20 SRAM state may be staged on display 35");
        }
        if route.stop(&view).is_err()
            || io.lt.read32(0x16_fc60) & (3 << 30) != 0
            || io.read32(port.ddi_buf_ctl()) & DDI_BUF_CTL_ENABLE != 0
        {
            return TestResult::Fail("Nova DDI B HDMI must stop through the LT PHY");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xelpg_external",
        smoke_nvl_external_hdmi_tmds_on_lt_port_b
    );

    /// The display-35 profile's refusals, each before any register access:
    /// port A (the panel's) and TC3/TC4 (absent on Nova Lake-S), a Cx0 view
    /// behind the Nova profile, and an LT view behind a Cx0 profile, for DP and
    /// HDMI alike.
    fn smoke_nvl_external_refusals_precede_mmio() -> TestResult {
        use crate::intel_gpu_xelpg_hdmi::{probe_hdmi_profile, HdmiError};
        struct LtNoAccess;
        impl MmioWindow for LtNoAccess {
            fn has_lt_phy(&self) -> bool {
                true
            }
            fn read32(&self, _: u64) -> u32 {
                panic!("refused route read a register");
            }
            fn write32(&self, _: u64, _: u32) {
                panic!("refused route wrote a register");
            }
        }
        let nova = ExternalDisplayProfile::for_ip(DisplayIp::NovaLakeS);
        let ptl = ExternalDisplayProfile::for_ip(DisplayIp::Xe3Lpd);
        for port in [XeLpgPort::A, XeLpgPort::Tc3, XeLpgPort::Tc4] {
            if probe_sink_profile(&LtNoAccess, nova, port, false).err()
                != Some(ExternalError::UnsupportedPort)
            {
                return TestResult::Fail("Nova must refuse ports outside B/TC1/TC2 before MMIO");
            }
        }
        for (view_lt, profile) in [(false, nova), (true, ptl)] {
            let refused = if view_lt {
                probe_sink_profile(&LtNoAccess, profile, XeLpgPort::B, false).err()
            } else {
                probe_sink_profile(&NoAccess, profile, XeLpgPort::B, false).err()
            };
            if refused != Some(ExternalError::UnsupportedGeneration) {
                return TestResult::Fail("the PHY family must match the profile before MMIO");
            }
        }
        let pin = crate::intel_gpu_xelpg_hdmi::ddc_pin(XeLpgPort::B);
        if !matches!(
            probe_hdmi_profile(&NoAccess, nova, XeLpgPort::B, false, pin),
            Err(HdmiError::Route(ExternalError::UnsupportedGeneration))
        ) || !matches!(
            probe_hdmi_profile(&LtNoAccess, ptl, XeLpgPort::B, false, pin),
            Err(HdmiError::Route(ExternalError::UnsupportedGeneration))
        ) {
            return TestResult::Fail("HDMI must refuse a mismatched PHY family before MMIO");
        }
        if !nova.admits_view(&LtNoAccess)
            || nova.admits_view(&NoAccess)
            || ptl.admits_view(&LtNoAccess)
        {
            return TestResult::Fail("only the LT view admits the display-35 profile");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xelpg_external",
        smoke_nvl_external_refusals_precede_mmio
    );
}

/// Deep colour on the display-14 DP route (`narf.intel.hdmi14_ext=1`): an
/// EDID 1.4 digital 10 bpc and a 12 bpc 1080p60 sink on HBR2 x4 raise the
/// pipe maximum to 30 and 36 bpp (`compute_sink_pipe_bpp`), and
/// `intel_dp_compute_link_config_wide` takes the slowest, narrowest link
/// that carries it: RBR x4 for 556875 kBps, HBR x4 for 668250 kBps. The
/// route carries the depth in `TRANS_DDI_FUNC_CTL` (BPC_10 / _12),
/// `PIPE_MISC` (BPC_10 / BPC_12_ADLP), the MSA (`DP_MSA_MISC_10_BPC` /
/// `_12_BPC`) and `intel_link_compute_m_n` at its bpp; the stop restores
/// the 8 bpc MSA. Without the option the same sinks run 24 bpp.
fn smoke_mtl_external_dp_deep_colour_10_and_12_bpc() -> TestResult {
    use crate::intel_gpu_xelpg_dsc::link_m_n;
    let profile = ExternalDisplayProfile::for_ip(DisplayIp::Xelpdp);
    for (input, bpp, rate, link_khz, func_bpc, misc, msa) in [
        (
            0xB0u8,
            30u32,
            TrainRate::Rbr,
            162_000u32,
            1u32 << 20,
            0x120u32,
            0x41u32,
        ),
        (0xC0, 36, TrainRate::Hbr, 270_000, 3 << 20, 0x180, 0x61),
    ] {
        let mut edid = edid_1080();
        edid[20] = input;
        edid[127] = edid[127].wrapping_sub(input);
        let io = ExtFake::new(XeLpgPort::B, Sink::new(0x14, edid.clone()));
        let probe = match probe_sink_profile_ext(&io, profile, XeLpgPort::B, false, true) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("a deep-colour DP sink must probe"),
        };
        if probe.pipe_bpp != bpp
            || probe.dsc.is_some()
            || (probe.negotiated.rate, probe.negotiated.lanes) != (rate, 4)
        {
            return TestResult::Fail("the deep bpp must take Linux's slowest x4 link");
        }
        let fb = fb_for(&probe.mode).unwrap();
        let mut route = match activate(&io, probe, fb, &MtlDisplay::NONE) {
            Ok(route) if route.state() == RouteState::Live => route,
            _ => return TestResult::Fail("the deep-colour DP route must light"),
        };
        let mn = link_m_n(bpp * 16, 4, 148_500, link_khz, false);
        if io.read32(TRANS_DDI_FUNC_CTL_B) & (7 << 20) != func_bpc
            || io.writes_to(0x7_1030) != [(1 << 23) | misc]
            || io.writes_to(0x6_1410) != [msa]
            || io.writes_to(0x6_1030) != [mn[0]]
            || io.writes_to(0x6_1044) != [mn[3]]
        {
            return TestResult::Fail(
                "Pipe B must carry the depth in FUNC_CTL, PIPE_MISC, MSA, M/N",
            );
        }
        if route.stop(&io).is_err() || io.read32(0x6_1410) != 0x21 {
            return TestResult::Fail("the deep route must stop and restore an 8 bpc MSA");
        }
        // narf.intel.hdmi14_ext off: 24 bpp.
        let io = ExtFake::new(XeLpgPort::B, Sink::new(0x14, edid));
        match probe_sink_profile_ext(&io, profile, XeLpgPort::B, false, false) {
            Ok(p) if p.pipe_bpp == 24 => {}
            _ => return TestResult::Fail("without the option the sink must run 24 bpp"),
        }
    }
    // An 8 bpc sink stays at 24 bpp with the option.
    let io = ExtFake::new(XeLpgPort::B, Sink::new(0x14, edid_1080()));
    match probe_sink_profile_ext(&io, profile, XeLpgPort::B, false, true) {
        Ok(p) if p.pipe_bpp == 24 => TestResult::Pass,
        _ => TestResult::Fail("an undefined-depth sink must stay at 24 bpp"),
    }
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_dp_deep_colour_10_and_12_bpc
);

/// The YCbCr 4:4:4 route (`narf.intel.hdmi14_ext=1`): a DPCD 1.4 PCON whose
/// HDMI DFP converts 4:4:4 to 4:2:0 (not RGB to YCbCr) in front of a
/// 4:2:0-only 4K60 HDMI sink. `intel_dp_output_format` drives YCbCr 4:4:4:
/// D0 and `intel_dp_configure_protocol_converter` (HDMI mode, 4:2:0
/// conversion on, RGB conversion cleared) before training, the MSA's
/// `DP_MSA_MISC_COLOR_YCBCR_444_BT709`, `PIPE_MISC` YUV and the BT.709
/// output CSC; the stop clears both and restores the 8 bpc RGB MSA.
fn smoke_mtl_external_dp_ycbcr444_pcon_route() -> TestResult {
    use crate::intel_gpu_xelpg_external::color::{tests, PconConfig};
    let mut sink = Sink::new(0x14, tests::edid_4k60_with(&tests::HDMI_420_ONLY_BLOCKS));
    sink.caps[5] = 0x11;
    sink.extra.push((0x80, 3));
    sink.extra.push((0x83, 0x10));
    let io = ExtFake::new(XeLpgPort::B, sink);
    let profile = ExternalDisplayProfile::for_ip(DisplayIp::Xelpdp);
    let probe = match probe_sink_profile_ext(&io, profile, XeLpgPort::B, false, true) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("the PCON sink must probe"),
    };
    if !probe.output.ycbcr444
        || probe.output.pcon
            != Some(PconConfig {
                hdmi_sink: true,
                ycbcr444_to_420: true,
                rgb_to_ycbcr: false,
            })
        || probe.pipe_bpp != 24
        || (probe.negotiated.rate, probe.negotiated.lanes) != (TrainRate::Hbr2, 4)
    {
        return TestResult::Fail("the PCON route must drive YCbCr 4:4:4 at 24 bpp on HBR2 x4");
    }
    let fb = fb_for(&probe.mode).unwrap();
    let mut route = match activate(&io, probe, fb, &MtlDisplay::NONE) {
        Ok(route) if route.state() == RouteState::Live => route,
        _ => return TestResult::Fail("the YCbCr 4:4:4 route must light"),
    };
    {
        let sink = io.sink.borrow();
        if sink.pcon_log != [(0x3050, 1), (0x3051, 1), (0x3052, 0)]
            || sink.power_log.first() != Some(&1)
        {
            return TestResult::Fail("the PCON must be powered and configured for 4:2:0");
        }
        // The PCON setup precedes link training.
        if sink.training_writes.is_empty() {
            return TestResult::Fail("the route must train");
        }
    }
    let csc_mode = 0x4_9028 + 0x100 * Pipe::B as u64;
    let coeff = 0x4_9050 + 0x100 * Pipe::B as u64;
    if io.writes_to(0x6_1410) != [0x3D]
        || io.writes_to(0x7_1030) != [(1 << 23) | 0x100, (1 << 23) | 0x100 | (1 << 11)]
        || io.read32(csc_mode) & (1 << 30) == 0
        || io.read32(coeff) != (0x1e08 << 16 | 0x9cc0)
    {
        return TestResult::Fail("the pipe must run the YCbCr 4:4:4 MSA, PIPE_MISC and CSC");
    }
    if route.stop(&io).is_err()
        || io.read32(0x6_1410) != 0x21
        || io.read32(0x7_1030) & (1 << 11) != 0
        || io.read32(csc_mode) & (1 << 30) != 0
    {
        return TestResult::Fail("the stop must clear the CSC and YUV and restore the MSA");
    }
    // The same PCON without the option: RGB, no PCON writes.
    let mut sink = Sink::new(0x14, tests::edid_4k60_with(&tests::HDMI_420_ONLY_BLOCKS));
    sink.caps[5] = 0x11;
    sink.extra.push((0x80, 3));
    sink.extra.push((0x83, 0x10));
    let io = ExtFake::new(XeLpgPort::B, sink);
    match probe_sink_profile_ext(&io, profile, XeLpgPort::B, false, false) {
        Ok(p) if p.output == crate::intel_gpu_xelpg_external::color::DpOutput::default() => {
            TestResult::Pass
        }
        _ => TestResult::Fail("without the option the route keeps RGB"),
    }
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_dp_ycbcr444_pcon_route
);

/// The DP route's ELD/audio enable sequence with a scripted HDA side
/// (`narf.intel.hdmi14_ext=1`): after the plane update the route runs
/// `enable_audio_dsc_wa`'s `HBLANK_EARLY_ENABLE_TGL` for Transcoder B,
/// raises `AUDIO_OUTPUT_ENABLE`, sets `N_VALUE_INDEX` (hardware Maud/Naud)
/// and notifies `pin_eld_notify(PORT_B, -1)`; the codec reads the unpruned
/// DP ELD (three SADs) through pin 0x6. The stop latches the timestamps off
/// (`N_PROG_ENABLE | N_VALUE_INDEX`) and withdraws the ELD.
fn smoke_mtl_external_dp_audio_route_with_scripted_hda() -> TestResult {
    use crate::intel_gpu_audio::{aud_cfg_off, AUD_CONFIG_N_PROG_ENABLE, AUD_CONFIG_N_VALUE_INDEX};
    use crate::intel_gpu_xelpg_external::audio::{self, tests as at};
    use core::sync::atomic::Ordering as AtomicOrdering;
    use narf_drivers_sound::display_audio as acomp;
    audio::reset_for_test();
    acomp::register_display_audio_codec(&at::SCRIPTED_HDA);
    let result = (|| {
        let io = ExtFake::new(XeLpgPort::B, Sink::new(0x14, at::audio_edid()));
        let profile = ExternalDisplayProfile::for_ip(DisplayIp::Xelpdp);
        let probe = match probe_sink_profile_ext(&io, profile, XeLpgPort::B, false, true) {
            Ok(p) if p.audio.is_some() => p,
            _ => return TestResult::Fail("a DP sink with SADs must probe with audio"),
        };
        let fb = fb_for(&probe.mode).unwrap();
        let before = at::NOTIFY_COUNT.load(AtomicOrdering::SeqCst);
        let mut route = match activate(&io, probe, fb, &MtlDisplay::NONE) {
            Ok(route) if route.state() == RouteState::Live => route,
            _ => return TestResult::Fail("the DP audio route must light"),
        };
        if io.writes_to(audio::AUD_CONFIG_BE) != [audio::hblank_early_enable_tgl(Transcoder::B)]
            || io.writes_to(aud_cfg_off(Transcoder::B)) != [AUD_CONFIG_N_VALUE_INDEX]
            || at::NOTIFY_COUNT.load(AtomicOrdering::SeqCst) != before + 1
            || at::NOTIFY_PORT.load(AtomicOrdering::SeqCst) != 1
            || at::NOTIFY_PIPE.load(AtomicOrdering::SeqCst) != -1
        {
            return TestResult::Fail("the DP route must enable audio and notify PORT_B");
        }
        let component = audio::XelpgAudioComponent { io: &io };
        let mut buf = [0u8; 128];
        match acomp::acomp_get_eld(Some(&component), Some(&at::SCRIPTED_HDA), 0x6, 0, &mut buf) {
            Ok((true, _)) if buf[5] >> 4 == 3 && buf[5] & (3 << 2) == 1 << 2 => {}
            _ => return TestResult::Fail("the codec must read the DP ELD on pin 0x6"),
        }
        if route.stop(&io).is_err()
            || io.writes_to(aud_cfg_off(Transcoder::B)).last()
                != Some(&(AUD_CONFIG_N_VALUE_INDEX | AUD_CONFIG_N_PROG_ENABLE))
            || at::NOTIFY_COUNT.load(AtomicOrdering::SeqCst) != before + 2
            || acomp::acomp_get_eld(Some(&component), Some(&at::SCRIPTED_HDA), 0x6, 0, &mut buf)
                .is_ok()
        {
            return TestResult::Fail("the DP stop must disable audio and withdraw the ELD");
        }
        TestResult::Pass
    })();
    acomp::unregister_display_audio_codec();
    audio::reset_for_test();
    result
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_external",
    smoke_mtl_external_dp_audio_route_with_scripted_hda
);

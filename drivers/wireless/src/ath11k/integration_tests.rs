//! End-to-end ath11k tests: FW_READY → QMI firmware start → CE / HTC /
//! WMI → DP rings + HTT → mac layer → `wlan%d`, then scan, a WPA2-PSK
//! connect with EAPOL over the real DP rings, data TX / RX through the
//! netdev, disconnect and link loss — the whole post-FW_READY driver on
//! one fake device.
//!
//! The device ([`Dev`]) composes the existing models, each of which only
//! knows what the host programmed:
//!
//! - `core_tests::Fw` — the HTC / WMI bring-up target behind
//!   `ce_tests::FakeChip` (frames through the real CE rings);
//! - `mac_tests::World` — firmware WMI answers + an access point with a
//!   real WPA2 authenticator, fed the decoded WMI commands
//!   (MGMT_TX_SEND carries its frame inline);
//! - a DP ring model like `dp_tests`': UMAC rings from the programmed
//!   registers (TCL1, WBM2SW0, REO2SW1, REO command / status), LMAC rings
//!   from the HTT SRING_SETUP messages, descriptors and buffers moved by
//!   physical address; HTT PEER_MAP / UNMAP on PEER_CREATE / DELETE.
//!
//! Expected bytes are literals derived by hand from Linux
//! (`net/mac80211/tx.c::ieee80211_build_hdr`, `ath11k/dp_tx.c`,
//! `hal_tx.c`), not re-encoded with the code under test.

#![cfg(target_arch = "x86_64")]

extern crate alloc;

use alloc::collections::VecDeque;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::future::Future;
use core::pin::pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::Interface;
use narf_wireless::{AssociateRequest, ScanRequest, SecurityConfig, WirelessNetIface};

use super::ce::{self, Ce, CeIrq, CeMsi};
use super::ce_tests::{phys_rd32, phys_read, phys_wr32, phys_write, FakeChip};
use super::core::{Ath11kCore, CeHif, CoreHooks, CoreState, QmiFw};
use super::core_tests::{self, Fw, Script, CTRL_DL, FW_MAC, HTT_EID, WMI_DL, WMI_EID};
use super::dp_ring::{self, buf_addr_get, DpHwParams, DpRingSizes};
use super::dp_tests::{good_rxd, reo_dest, rx_desc_bytes, wbm_htt, wbm_tqm, FIRST, LAST, SMALL};
use super::hal::TransportError;
use super::hal_tests::wcn6855;
use super::htc::{self, HtcHdr};
use super::htt;
use super::hw::{HwRev, MSI_CONFIG_ONE, MSI_CONFIG_QCA6390, RING_MASK_QCA6390};
use super::iface::{Ath11kNetdev, Sinks};
use super::mac::{Mac, MacConfig};
use super::mac_tests::{beacon, FwCfg, World, BSSID, OWN, PMK, SSID};
use super::power::ChipIo;
use super::runtime::{self, DpHooks, DpIrq, Port, Rt, Shared};
use super::tx_hdr::{self, SeqState, StaTx};
use super::wlfw::WlfwError;
use super::wmi::{self, WmiCmd};

type R = Result<(), &'static str>;

macro_rules! ensure {
    ($c:expr, $m:expr) => {
        if !$c {
            return Err($m);
        }
    };
}

fn check(f: impl FnOnce() -> R) -> TestResult {
    match f() {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}

/// Drive a future whose waits are all immediately ready (the device
/// model runs inside every wait).
fn run<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..2_000_000 {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
    panic!("integration test future did not complete");
}

/// Run `f` with the Wi-Fi diag latch cleared; return what it latched
/// (step, detail, stage) and restore the previous diag state.
fn latched<T>(f: impl FnOnce() -> T) -> (T, u32, u32, narf_memory::diag::WifiStage) {
    use narf_memory::diag;
    let s = diag::snapshot();
    diag::__reset_for_test();
    let v = f();
    let got = diag::snapshot();
    diag::__reset_for_test();
    diag::set_phase(s.phase);
    diag::set_heap_kb(s.heap_used_kb, s.heap_total_kb);
    if s.first_pf_seen {
        diag::note_pf(s.first_pf_cr2, s.first_pf_rip);
    }
    if s.panic_latched {
        diag::latch_panic(s.panic_marker);
    }
    diag::set_wifi_stage(s.wifi_stage);
    diag::latch_wifi_error(s.wifi_err, s.wifi_detail);
    (v, got.wifi_err, got.wifi_detail, got.wifi_stage)
}

fn le(ws: &[u32]) -> Vec<u8> {
    ws.iter().flat_map(|w| w.to_le_bytes()).collect()
}

fn tlv(tag: u16, value: &[u8]) -> Vec<u8> {
    let mut v = le(&[((tag as u32) << 16) | value.len() as u32]);
    v.extend_from_slice(value);
    v
}

fn wmi_event(id: u32, tlvs: &[Vec<u8>]) -> Vec<u8> {
    let mut v = le(&[id]);
    for t in tlvs {
        v.extend_from_slice(t);
    }
    v
}

fn rd32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

// ── clock, chip, QMI ──────────────────────────────────────────────

static NOW: AtomicU64 = AtomicU64::new(0);

fn clock() -> u64 {
    NOW.load(Ordering::Relaxed)
}

fn noop() {}

fn test_rng(out: &mut [u8]) {
    out.fill(0x22);
}

/// The fake chip, shareable between the HIF and the device model.
struct Chip(FakeChip);
// SAFETY: kernel tests run one at a time inside a single task; the chip
// model (RefCell / Cell inside FakeChip) is only ever touched from the
// test's own future on that task, never concurrently.
unsafe impl Send for Chip {}
// SAFETY: as above — no two CPUs or tasks access it at once.
unsafe impl Sync for Chip {}

#[derive(Clone)]
struct Io(Arc<Chip>);

impl ChipIo for Io {
    fn read32(&self, offset: u32) -> u32 {
        self.0 .0.read32(offset)
    }
    fn write32(&self, offset: u32, value: u32) {
        self.0 .0.write32(offset, value)
    }
    fn delay_ms(&self, _ms: u32) {}
    fn restore_window(&self) {}
}

/// QMI half of firmware start / stop (counts only).
#[derive(Default)]
struct TestQmi {
    starts: u32,
    stops: u32,
    services: u32,
    fail: Option<WlfwError>,
}

impl QmiFw for TestQmi {
    async fn firmware_start(&mut self, _mode: u32, _shadow: &[u32]) -> Result<(), WlfwError> {
        self.starts += 1;
        match self.fail {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
    async fn firmware_stop(&mut self) {
        self.stops += 1;
    }
    fn service(&mut self) {
        self.services += 1;
    }
}

// ── the device's DP ring view ─────────────────────────────────────

#[derive(Copy, Clone, Debug)]
enum Host {
    Reg(u32),
    Mem(u64),
}

/// One ring as the hardware sees it (`idx` in words: TP of a SRC ring,
/// HP of a DST ring).
#[derive(Copy, Clone, Debug)]
struct DevRing {
    base: u64,
    size: u32,
    esz: u32,
    hw_ptr: u64,
    host: Host,
    idx: u32,
}

impl DevRing {
    fn host(&self, chip: &FakeChip) -> u32 {
        match self.host {
            Host::Reg(o) => chip.reg(o),
            Host::Mem(pa) => phys_rd32(pa),
        }
    }
    fn publish(&self) {
        if self.hw_ptr != 0 {
            phys_wr32(self.hw_ptr, self.idx);
        }
    }
    fn produce(&mut self, chip: &FakeChip, w: &[u32]) -> bool {
        if (self.idx + self.esz) % self.size == self.host(chip) {
            return false;
        }
        for (i, &v) in w.iter().enumerate() {
            phys_wr32(self.base + (self.idx as u64 + i as u64) * 4, v);
        }
        self.idx = (self.idx + self.esz) % self.size;
        self.publish();
        true
    }
    fn consume(&mut self, chip: &FakeChip) -> Option<Vec<u32>> {
        if self.idx == self.host(chip) {
            return None;
        }
        let w = (0..self.esz)
            .map(|i| phys_rd32(self.base + (self.idx as u64 + i as u64) * 4))
            .collect();
        self.idx = (self.idx + self.esz) % self.size;
        self.publish();
        Some(w)
    }
}

fn reg64(chip: &FakeChip, lo: u32) -> u64 {
    chip.reg(lo) as u64 | ((chip.reg(lo + 4) as u64 & 0xff) << 32)
}

/// A UMAC ring from its R0 registers once the host set it up. DST
/// rings publish their HP at R0 + 0x14, SRC rings their TP at R0 + 0x1c;
/// `host_reg` is the host's pointer register (written through its shadow
/// register, which the chip mirrors).
fn umac(chip: &FakeChip, r0: u32, host_reg: u32, dst: bool) -> Option<DevRing> {
    let base = reg64(chip, r0);
    let size = (chip.reg(r0 + 4) >> 8) & 0xf_ffff;
    if base == 0 || size == 0 {
        return None;
    }
    let p = if dst { r0 + 0x14 } else { r0 + 0x1c };
    Some(DevRing {
        base,
        size,
        esz: chip.reg(r0 + 8) & 0xff,
        hw_ptr: chip.reg(p) as u64 | ((chip.reg(p + 4) as u64) << 32),
        host: Host::Reg(host_reg),
        idx: 0,
    })
}

/// An LMAC ring from its HTT SRING_SETUP message.
fn lmac(m: &[u8]) -> DevRing {
    let info0 = rd32(m, 0);
    let info1 = rd32(m, 12);
    let hp = rd32(m, 16) as u64 | ((rd32(m, 20) as u64) << 32);
    let tp = rd32(m, 24) as u64 | ((rd32(m, 28) as u64) << 32);
    let hw_to_sw = (info0 >> 24) == 0;
    DevRing {
        base: rd32(m, 4) as u64 | ((rd32(m, 8) as u64) << 32),
        size: info1 & 0xffff,
        esz: (info1 >> 16) & 0xff,
        hw_ptr: if hw_to_sw { hp } else { tp },
        host: Host::Mem(if hw_to_sw { tp } else { hp }),
        idx: 0,
    }
}

// WCN6855 UMAC ring R0 / pointer registers (HAL_SEQ_WCSS_UMAC_*_REG +
// `wcn6855_regs`; every pointer register is in the QMI shadow list).
const TCL1_R0: u32 = 0x00a4_4690;
const TCL1_HP: u32 = 0x00a4_6000;
const WBM2SW0_R0: u32 = 0x00a3_4920;
const WBM2SW0_TP: u32 = 0x00a3_70c4;
const REO2SW1_R0: u32 = 0x00a3_8244;
const REO2SW1_TP: u32 = 0x00a3_b034;
const REO_CMD_R0: u32 = 0x00a3_8194;
const REO_CMD_HP: u32 = 0x00a3_b020;
const REO_STATUS_R0: u32 = 0x00a3_855c;
const REO_STATUS_TP: u32 = 0x00a3_b07c;

/// The AP's data-path peer id (HTT PEER_MAP).
const AP_PEER_ID: u16 = 3;

// ── the device ────────────────────────────────────────────────────

#[derive(Default)]
struct Rings {
    tcl: Option<DevRing>,
    wbm: Option<DevRing>,
    reo: Option<DevRing>,
    reo_cmd: Option<DevRing>,
    reo_status: Option<DevRing>,
    lmac: Vec<DevRing>,
}

/// One frame the host queued on the TCL ring.
#[derive(Clone, Debug)]
struct TclTx {
    desc: Vec<u32>,
    frame: Vec<u8>,
}

/// A WBM2SW0 release: TQM (reason, peer id; ack rssi 40) or firmware
/// (`HAL_WBM_REL_HTT_TX_COMP_STATUS_*`, ack rssi, peer id if valid).
#[derive(Copy, Clone, Debug)]
enum TxRel {
    Tqm {
        reason: u32,
        peer: u32,
    },
    Htt {
        status: u32,
        rssi: u32,
        peer: Option<u32>,
    },
}

impl Default for TxRel {
    fn default() -> Self {
        TxRel::Tqm {
            reason: 0,
            peer: AP_PEER_ID as u32,
        }
    }
}

struct DevState {
    fw: Fw,
    world: World,
    credit_size: u32,
    rings: Rings,
    /// HTT messages host → target (HTC payload).
    htt_h2t: Vec<Vec<u8>>,
    /// WMI commands after the core bring-up, in order.
    wmi: Vec<WmiCmd>,
    tcl_tx: Vec<TclTx>,
    /// Ethernet frames the AP side sends to the station.
    rx_queue: VecDeque<Vec<u8>>,
    rx_delivered: u32,
    reo_cmds: u32,
    dp_pending: u32,
    /// Withhold every DP interrupt (the poll fallback must find the work).
    mute_dp_irq: bool,
    /// `rx_attention.info1` of every RX descriptor (checksum-fail bits).
    rx_attn1: u32,
    /// How the device releases transmitted MSDUs on WBM2SW0.
    tx_rel: TxRel,
    peers: Vec<(u32, [u8; 6], u16)>,
}

struct Dev {
    chip: Arc<Chip>,
    st: RefCell<DevState>,
}
// SAFETY: as `Chip` — single-task kernel test, no concurrent access.
unsafe impl Send for Dev {}
// SAFETY: as above.
unsafe impl Sync for Dev {}

impl Dev {
    fn new(chip: Arc<Chip>, script: Script, cfg: FwCfg) -> Arc<Dev> {
        let credit_size = script.credit_size as u32;
        Arc::new(Dev {
            chip,
            st: RefCell::new(DevState {
                fw: Fw::new(script),
                world: World {
                    cfg: Some(cfg),
                    next_desc: 1,
                    ..Default::default()
                },
                credit_size,
                rings: Rings::default(),
                htt_h2t: Vec::new(),
                wmi: Vec::new(),
                tcl_tx: Vec::new(),
                rx_queue: VecDeque::new(),
                rx_delivered: 0,
                reo_cmds: 0,
                dp_pending: 0,
                mute_dp_irq: false,
                rx_attn1: 0,
                tx_rel: TxRel::default(),
                peers: Vec::new(),
            }),
        })
    }

    fn chip(&self) -> &FakeChip {
        &self.chip.0
    }

    /// A host → target frame (after `Fw` saw it): the WMI commands the
    /// mac layer sends, HTT ring setup.
    fn on_frame(&self, st: &mut DevState, f: &[u8]) {
        let Some(h) = HtcHdr::parse(f) else { return };
        let len = h.payload_len as usize;
        let p = &f[8..8 + len.min(f.len() - 8)];
        if h.eid == WMI_EID && p.len() >= 4 {
            let cmd_id = rd32(p, 0) & 0x00ff_ffff;
            if cmd_id == wmi::WMI_INIT_CMDID || cmd_id == wmi::WMI_PDEV_SET_HW_MODE_CMDID {
                return; // Fw answered (and credited) it.
            }
            // The credit back, as a trailer-only frame.
            let credits = (f.len() as u32).div_ceil(st.credit_size) as u8;
            let tr = htc::credit_report_trailer(&[(WMI_EID, credits)]);
            st.fw
                .out
                .push_back((WMI_DL, htc::target_frame(WMI_EID, &[], &tr)));
            let cmd = WmiCmd {
                cmd_id,
                buf: p[4..].to_vec(),
            };
            let b = &cmd.buf;
            match cmd_id {
                wmi::WMI_MGMT_TX_SEND_CMDID => {
                    let desc = rd32(b, 8);
                    let n = rd32(b, 28) as usize;
                    let frame = b[40..40 + n].to_vec();
                    st.world.on_mgmt_desc(&frame, desc);
                }
                wmi::WMI_PEER_CREATE_CMDID => {
                    let vdev = rd32(b, 4);
                    let mac: [u8; 6] = b[8..14].try_into().unwrap();
                    if st.world.cfg().peer_map {
                        let m = le(&[
                            0x03 | (vdev & 0xff) << 8 | (AP_PEER_ID as u32) << 16,
                            u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]),
                            u16::from_le_bytes([mac[4], mac[5]]) as u32,
                        ]);
                        st.fw
                            .out
                            .push_back((CTRL_DL, htc::target_frame(HTT_EID, &m, &[])));
                        st.peers.push((vdev, mac, AP_PEER_ID));
                    }
                }
                wmi::WMI_PEER_DELETE_CMDID => {
                    let vdev = rd32(b, 4);
                    let mac: [u8; 6] = b[8..14].try_into().unwrap();
                    if let Some(i) = st.peers.iter().position(|p| p.0 == vdev && p.1 == mac) {
                        let (_, _, id) = st.peers.remove(i);
                        let m = le(&[0x04 | (id as u32) << 16, 0, 0]);
                        st.fw
                            .out
                            .push_back((CTRL_DL, htc::target_frame(HTT_EID, &m, &[])));
                    }
                }
                _ => {}
            }
            st.world.on_cmd(&cmd);
            st.wmi.push(cmd);
        } else if h.eid == HTT_EID && !p.is_empty() {
            st.htt_h2t.push(p.to_vec());
            if p[0] == htt::h2t::SRING_SETUP as u8 {
                st.rings.lmac.push(lmac(p));
            }
        }
    }

    /// The UMAC rings appear as the host programs them.
    fn learn_rings(&self, st: &mut DevState) {
        let c = self.chip();
        let r = &mut st.rings;
        if r.tcl.is_none() {
            r.tcl = umac(c, TCL1_R0, TCL1_HP, false);
        }
        if r.wbm.is_none() {
            r.wbm = umac(c, WBM2SW0_R0, WBM2SW0_TP, true);
        }
        if r.reo.is_none() {
            r.reo = umac(c, REO2SW1_R0, REO2SW1_TP, true);
        }
        if r.reo_cmd.is_none() {
            r.reo_cmd = umac(c, REO_CMD_R0, REO_CMD_HP, false);
        }
        if r.reo_status.is_none() {
            r.reo_status = umac(c, REO_STATUS_R0, REO_STATUS_TP, true);
        }
    }

    /// TCL → air: record the frame, hand EAPOL to the authenticator
    /// (802.11 ToDS → 802.3: DA = addr3, SA = addr2, type from SNAP) and
    /// release it acked on WBM2SW0.
    fn tcl(&self, st: &mut DevState) {
        let c = self.chip();
        let (Some(mut tcl), Some(mut wbm)) = (st.rings.tcl, st.rings.wbm) else {
            return;
        };
        while let Some(w) = tcl.consume(c) {
            let (pa, desc_id, _) = buf_addr_get(w[1], w[2]);
            let len = (w[4] & 0xffff) as usize;
            let mut f = vec![0u8; len];
            phys_read(pa, &mut f);
            st.tcl_tx.push(TclTx {
                desc: w.clone(),
                frame: f.clone(),
            });
            let fc = u16::from_le_bytes([f[0], f[1]]);
            let hl = if fc & 0x0080 != 0 { 26 } else { 24 };
            if f.len() >= hl + 8 && f[hl..hl + 6] == dp_ring::RFC1042_HEADER {
                let mut eth = f[16..22].to_vec();
                eth.extend_from_slice(&f[10..16]);
                eth.extend_from_slice(&f[hl + 6..]);
                if eth[12..14] == [0x88, 0x8e] {
                    st.world.on_eth(&eth);
                }
            }
            let rel = match st.tx_rel {
                TxRel::Tqm { reason, peer } => wbm_tqm(desc_id, reason, 1, 1, 40, peer, 0),
                TxRel::Htt { status, rssi, peer } => wbm_htt(desc_id, status, rssi, peer),
            };
            if wbm.produce(c, &rel) {
                st.dp_pending |= 1 << 0;
            }
        }
        st.rings.tcl = Some(tcl);
        st.rings.wbm = Some(wbm);
    }

    /// REO command ring: answer every command that asks for a status
    /// with SUCCESS.
    fn reo(&self, st: &mut DevState) {
        let c = self.chip();
        let (Some(mut cmd), Some(mut status)) = (st.rings.reo_cmd, st.rings.reo_status) else {
            return;
        };
        while let Some(w) = cmd.consume(c) {
            st.reo_cmds += 1;
            if w[1] & super::dp_peer::HAL_REO_CMD_HDR_INFO0_STATUS_REQUIRED == 0 {
                continue;
            }
            let tag = match (w[0] >> 1) & 0x1ff {
                0x1a3 => 0x99,
                0x134 => 0x139,
                _ => 0x137,
            };
            let mut s = vec![0u32; status.esz as usize];
            s[0] = tag << 1;
            s[1] = w[1] & 0xffff;
            if status.produce(c, &s) {
                st.dp_pending |= 1 << 0;
            }
        }
        st.rings.reo_cmd = Some(cmd);
        st.rings.reo_status = Some(status);
    }

    /// The AP's frames to the station: Ethernet → native-wifi MSDU
    /// (FromDS: addr1 = DA, addr2 = BSSID, addr3 = SA, SNAP) in the next
    /// posted RX buffer, reported on REO2SW1.
    fn rx(&self, st: &mut DevState) {
        let c = self.chip();
        while let Some(f) = st.world.eapol_rx.pop_front() {
            st.rx_queue.push_back(f);
        }
        let (Some(mut reo), Some(mut refill)) = (st.rings.reo, st.rings.lmac.first().copied())
        else {
            return;
        };
        while let Some(eth) = st.rx_queue.front().cloned() {
            let Some(w) = refill.consume(c) else { break };
            let (pa, cookie, _) = buf_addr_get(w[0], w[1]);
            let mut msdu = vec![0x08, 0x02, 0, 0];
            msdu.extend_from_slice(&eth[0..6]);
            msdu.extend_from_slice(&BSSID);
            msdu.extend_from_slice(&eth[6..12]);
            msdu.extend_from_slice(&[0x10, 0x00]);
            msdu.extend_from_slice(&dp_ring::RFC1042_HEADER);
            msdu.extend_from_slice(&eth[12..]);
            let mut d = good_rxd(msdu.len(), 1);
            d.attn1 = st.rx_attn1;
            let mut buf = rx_desc_bytes(&d);
            buf.extend_from_slice(&msdu);
            phys_write(pa, &buf);
            if !reo.produce(
                c,
                &reo_dest(
                    pa,
                    cookie,
                    FIRST | LAST | (msdu.len() as u32) << 3,
                    1,
                    0,
                    AP_PEER_ID as u32,
                ),
            ) {
                break;
            }
            st.rx_queue.pop_front();
            st.rx_delivered += 1;
            st.dp_pending |= 1 << 7;
        }
        st.rings.reo = Some(reo);
        st.rings.lmac[0] = refill;
    }

    /// What the target does between two host waits.
    fn step(&self) {
        let mut st = self.st.borrow_mut();
        let st = &mut *st;
        if !st.fw.started {
            st.fw.on_start();
        }
        for pipe in [0u32, 3, 4] {
            for (meta, data) in self.chip().target_consume(pipe) {
                st.fw.on_tx(pipe as u8, meta as u16, &data);
                self.on_frame(st, &data);
            }
        }
        while let Some(ev) = st.world.events.pop_front() {
            st.fw
                .out
                .push_back((WMI_DL, htc::target_frame(WMI_EID, &ev, &[])));
        }
        self.learn_rings(st);
        self.tcl(st);
        self.reo(st);
        self.rx(st);
        while let Some((pipe, data)) = st.fw.out.pop_front() {
            if !self.chip().target_deliver(pipe, &data, None) {
                st.fw.out.push_front((pipe, data));
                break;
            }
        }
        if st.mute_dp_irq {
            st.dp_pending = 0;
        }
        // FakeChip records every register access; keep the log short.
        self.chip().clear();
    }
}

/// The interrupt + time source over the device.
#[derive(Clone)]
struct DevIrq(Arc<Dev>);

impl CeIrq for DevIrq {
    fn take_pending(&self) -> u32 {
        self.0.chip().take_pending()
    }
    fn wait(&self, ms: u32) -> impl Future<Output = ()> + Send {
        NOW.fetch_add(ms.max(1) as u64, Ordering::Relaxed);
        self.0.step();
        core::future::ready(())
    }
}

impl DpIrq for DevIrq {
    fn take_dp_pending(&self) -> u32 {
        core::mem::take(&mut self.0.st.borrow_mut().dp_pending)
    }
}

// ── rig ───────────────────────────────────────────────────────────

type TCore = Ath11kCore<CeHif<Io, DevIrq>, TestQmi>;
type TShared = Shared<Io, DevIrq, TestQmi>;
type TNetdev = Ath11kNetdev<Io, DevIrq, TestQmi>;

const EP_BASE: u32 = 0x40;

fn msi(config: &'static super::hw::MsiConfig) -> CeMsi {
    CeMsi {
        addr: 0xfee0_1000,
        ep_base_data: EP_BASE,
        config,
    }
}

/// `dp_tests`' small rings, with REO command / status rings big enough
/// for the 17 PN updates `ath11k_dp_peer_rx_pn_replay_config` queues at
/// once (Linux: 128 / 2048 entries).
const SIZES: DpRingSizes = DpRingSizes {
    reo_cmd: 64,
    reo_status: 64,
    ..SMALL
};

/// The bring-up target: one WMI credit of 2304 bytes covers every
/// command (the WMI endpoint's `max_msg_len` is 2048).
fn script() -> Script {
    Script {
        credit_size: 2304,
        ..Script::default()
    }
}

fn wpa2_cfg() -> FwCfg {
    FwCfg {
        beacons: vec![(6, 50, beacon(&BSSID, SSID, 6, true))],
        eapol: true,
        ..FwCfg::default()
    }
}

/// A core + DP hooks on a fresh chip, before `qmi_firmware_ready`.
fn rig(script: Script, cfg: FwCfg, sizes: DpRingSizes) -> (TCore, DpHooks, Arc<Dev>) {
    NOW.store(0, Ordering::Relaxed);
    let ce = Ce::alloc(&wcn6855(), msi(&MSI_CONFIG_QCA6390), clock).expect("Ce::alloc");
    let chip = Arc::new(Chip(FakeChip::new(ce.shadow_reg_v2())));
    let dev = Dev::new(chip.clone(), script, cfg);
    let hif = CeHif {
        ce,
        io: Io(chip),
        irq: DevIrq(dev.clone()),
        on_start: noop,
        clock,
    };
    let core = match Ath11kCore::new(hif, TestQmi::default(), core_tests::cfg()) {
        Ok(c) => c,
        Err(_) => panic!("Ath11kCore::new"),
    };
    let hooks = DpHooks::new(
        DpHwParams::for_rev(HwRev::Wcn6855Hw21),
        HwRev::Wcn6855Hw21 as u32,
        sizes,
        Some(msi(&MSI_CONFIG_QCA6390)),
    );
    (core, hooks, dev)
}

/// Bring a rig up (core + DP); restores the CE / DP interrupt flags the
/// hooks set.
fn bring_up<D: CoreHooks<CeHif<Io, DevIrq>, TestQmi>>(
    core: &mut TCore,
    hooks: &mut D,
) -> (
    Result<(), TransportError>,
    u32,
    u32,
    narf_memory::diag::WifiStage,
) {
    let r = latched(|| run(core.qmi_firmware_ready(hooks)));
    ce::set_ce_irqs_enabled(false);
    runtime::set_dp_irqs_enabled(false);
    r
}

static RX_SEEN: IrqSafeSpinLock<Vec<Vec<u8>>> = IrqSafeSpinLock::new(Vec::new());
static LINK_SEEN: IrqSafeSpinLock<Vec<bool>> = IrqSafeSpinLock::new(Vec::new());
static TEST_DEV: IrqSafeSpinLock<Option<Arc<TNetdev>>> = IrqSafeSpinLock::new(None);

fn rx_sink(_name: &str, f: &mut [u8]) {
    RX_SEEN.lock().push(f.to_vec());
}

fn link_sink(_name: &str, up: bool) {
    LINK_SEEN.lock().push(up);
}

fn admin_sink(name: &str, up: bool) {
    narf_net::iface::set_link_state(name, up);
}

fn test_open_stop(_name: &str, up: bool) {
    if let Some(dev) = TEST_DEV.lock().clone() {
        dev.request_admin(up);
    }
}

static DISC_SEEN: IrqSafeSpinLock<Vec<(u16, bool)>> = IrqSafeSpinLock::new(Vec::new());

fn disc_sink(_name: &str, d: super::mac::Disconnect) {
    DISC_SEEN.lock().push((d.reason, d.from_ap));
}

fn test_send(bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let dev = TEST_DEV.lock().clone().ok_or(())?;
    dev.queue_tx(bytes, meta)
}

struct Up {
    dev: Arc<Dev>,
    shared: Arc<TShared>,
    netdev: Arc<TNetdev>,
    tx_cons: narf_ipc::Consumer<narf_net::Frame, { narf_net::TX_RING_N }>,
    name: &'static str,
}

impl Drop for Up {
    fn drop(&mut self) {
        narf_net::iface::unregister(self.name);
        *TEST_DEV.lock() = None;
    }
}

/// `start_pci` + `ip link set up` for the test device: [`up_down`],
/// then IFF_UP through the stack (`ndo_open` → mac start + vif on the
/// next runtime pass).
fn up(cfg: FwCfg) -> Result<Up, &'static str> {
    let u = up_down(cfg)?;
    ensure!(narf_net::iface::set_link_state(u.name, true), "IFF_UP");
    let (_, err, _, _) = latched(|| pump(&u, 1));
    ensure!(err == 0, "mac start over the runtime");
    ensure!(
        run(u.netdev.mac.lock())
            .vif()
            .is_some_and(|v| v.vdev_id == 0),
        "vif 0"
    );
    LINK_SEEN.lock().clear();
    Ok(u)
}

/// `start_pci` for the test device: core + DP up, the mac layer
/// registered, the netdev registered with the stack under a `wlan%d`
/// name, still down (hardware not started).
fn up_down(cfg: FwCfg) -> Result<Up, &'static str> {
    let (mut core, mut hooks, dev) = rig(script(), cfg, SIZES);
    let (r, err, _, stage) = bring_up(&mut core, &mut hooks);
    ensure!(r.is_ok() && err == 0, "bring-up with the DP");
    ensure!(
        stage == narf_memory::diag::WifiStage::DataPath,
        "stage data-path once the DP is up"
    );
    let dp = hooks.dp.take().ok_or("hooks keep the DP")?;
    let rt = Rt::new(core, dp);
    let caps = rt.device_caps().map_err(|_| "device caps")?;
    let reg = rt.core.reg_info.clone();
    let shared = Shared::new(rt, test_rng);
    let mac = Mac::new(
        Port(shared.clone()),
        Port(shared.clone()),
        caps.clone(),
        MacConfig::wcn6855(),
        reg.as_deref(),
    );
    let name = narf_net::iface::reserve_name("wlan%d");
    let (nd, tx_cons) = Ath11kNetdev::new(
        name,
        shared.clone(),
        mac,
        caps.mac_addr,
        Sinks {
            rx: rx_sink,
            link: link_sink,
            admin: admin_sink,
            disconnected: disc_sink,
        },
    );
    let netdev = Arc::new(nd);
    *TEST_DEV.lock() = Some(netdev.clone());
    narf_net::iface::register(name, caps.mac_addr, test_send);
    narf_net::iface::set_offloads(name, super::tx_offload::OFFLOADS);
    narf_net::iface::set_open_stop(name, test_open_stop);
    RX_SEEN.lock().clear();
    LINK_SEEN.lock().clear();
    DISC_SEEN.lock().clear();
    Ok(Up {
        dev,
        shared,
        netdev,
        tx_cons,
        name,
    })
}

/// Runtime-loop passes (service + deliver + mac housekeeping + wait).
fn pump(u: &Up, n: u32) {
    for _ in 0..n {
        run(u.netdev.service_once());
        run(u.shared.irq.wait(10));
    }
}

fn wpa2_req() -> AssociateRequest {
    AssociateRequest {
        bssid: BSSID,
        ssid: SSID.to_vec(),
        channel: 6,
        security: SecurityConfig::Wpa2 { psk: PMK },
    }
}

fn scan6(u: &Up) -> Result<Vec<narf_wireless::BssInfo>, &'static str> {
    run(u.netdev.scan(ScanRequest {
        ssids: Vec::new(),
        channels: vec![6],
        active: false,
    }))
    .map_err(|_| "scan")
}

fn connect(u: &Up) -> R {
    scan6(u)?;
    let (r, err, _, stage) = latched(|| run(u.netdev.associate(wpa2_req())));
    ensure!(r.is_ok() && err == 0, "WPA2 associate");
    ensure!(
        stage == narf_memory::diag::WifiStage::Connected,
        "stage connected"
    );
    Ok(())
}

/// An IPv4 / UDP frame from the station (DSCP `tos`).
fn ipv4_frame(da: &[u8; 6], sa: &[u8; 6], tos: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = da.to_vec();
    f.extend_from_slice(sa);
    f.extend_from_slice(&[0x08, 0x00]);
    f.extend_from_slice(&[0x45, tos, 0x00, 0x1c + payload.len() as u8]);
    f.extend_from_slice(&[0, 1, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1]);
    f.extend_from_slice(&[0x13, 0x88, 0x13, 0x89, 0, 8 + payload.len() as u8, 0, 0]);
    f.extend_from_slice(payload);
    f
}

const GW: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

// ── tests ─────────────────────────────────────────────────────────

/// Linux `ath11k_pcic_ext_irq_config` for WCN6855: one vector per group
/// with rings, `(grp % 18) + 14` of the 32-vector table; group 3 has no
/// ring; one shared vector 0 in the single-MSI fallback. The ring side
/// (`dp_ring::srng_msi`) programs the same vector as MSI data.
fn smoke_ath11k_int_dp_msi_vectors() -> TestResult {
    check(|| {
        let m = &RING_MASK_QCA6390;
        let want: [Option<u32>; 11] = [
            Some(14),
            Some(15),
            Some(16),
            None,
            Some(18),
            Some(19),
            Some(20),
            Some(21),
            Some(22),
            Some(23),
            Some(24),
        ];
        for (g, w) in want.iter().enumerate() {
            ensure!(
                runtime::dp_irq_vector(m, &MSI_CONFIG_QCA6390, g) == *w,
                "32-vector DP map"
            );
        }
        ensure!(
            runtime::dp_vector_cookie(m, &MSI_CONFIG_QCA6390, 14) == Some(1)
                && runtime::dp_vector_cookie(m, &MSI_CONFIG_QCA6390, 21) == Some(1 << 7)
                && runtime::dp_vector_cookie(m, &MSI_CONFIG_QCA6390, 17).is_none(),
            "per-vector group cookies"
        );
        ensure!(
            (0..11).all(|g| runtime::dp_irq_vector(m, &MSI_CONFIG_ONE, g)
                == if g == 3 { None } else { Some(0) }),
            "single MSI: every group on vector 0"
        );
        ensure!(
            runtime::dp_vector_cookie(m, &MSI_CONFIG_ONE, 0) == Some(0x7f7),
            "single MSI cookie: groups 0-2, 4-10"
        );
        // REO2SW1 (rx group 7), WBM2SW0 TX completion (group 0), monitor
        // status ring 1 (group 5): MSI data = vector + ep_base.
        let msi = msi(&MSI_CONFIG_QCA6390);
        use super::hal::HalRingType as T;
        for (ty, ring, grp) in [
            (T::ReoDst, 0, 7),
            (T::Wbm2SwRelease, 0, 0),
            (T::RxdmaMonitorStatus, 1, 5),
        ] {
            let data = dp_ring::srng_msi(m, Some(&msi), ty, ring).map(|v| v.1);
            ensure!(
                data == runtime::dp_irq_vector(m, &MSI_CONFIG_QCA6390, grp).map(|v| v + EP_BASE),
                "ring MSI data = its group's vector"
            );
        }
        ensure!(
            runtime::install_dp_irq_handlers(
                m,
                &super::hw::MsiConfig {
                    total_vectors: 1,
                    users: &[],
                },
                0,
                1
            )
            .map_err(|e| e.step)
                == Err(runtime::step::DP_IRQ_CONFIG),
            "no DP user: config fails"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_int_dp_msi_vectors);

/// FW_READY → DP up → mac start → vif → `wlan%d` registered.
fn smoke_ath11k_int_bring_up_to_netdev() -> TestResult {
    check(|| {
        let u = up(FwCfg::default())?;
        let st = u.dev.st.borrow();
        // HTT: VERSION_REQ, the seven SRING_SETUPs in Linux's order, the
        // PPDU stats config (×2 rxdma), the two monitor-status filters.
        let types: Vec<u8> = st.htt_h2t.iter().map(|m| m[0]).collect();
        ensure!(
            types == [0x0, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0x11, 0x11, 0xc, 0xc],
            "HTT: VERSION_REQ, 7 × SRING_SETUP, 2 × PPDU_STATS_CFG, 2 × RX_RING_SELECTION_CFG"
        );
        ensure!(
            st.rings.lmac.len() == 7,
            "LMAC rings learned from SRING_SETUP"
        );
        ensure!(
            st.rings.tcl.is_some() && st.rings.reo.is_some() && st.rings.wbm.is_some(),
            "UMAC rings programmed"
        );
        ensure!(
            st.wmi
                .iter()
                .any(|c| c.cmd_id == wmi::WMI_VDEV_CREATE_CMDID),
            "vdev created over the real WMI endpoint"
        );
        drop(st);
        let snap = narf_net::iface::lookup(u.name).ok_or("registered with the stack")?;
        ensure!(
            snap.mac == FW_MAC && snap.link_up && !snap.carrier,
            "MAC from WMI READY, IFF_UP, carrier off"
        );
        ensure!(u.name.starts_with("wlan"), "wlan%d name");
        let nd = &u.netdev;
        ensure!(
            nd.mac() == FW_MAC && nd.mtu() == 1500 && !nd.link_up(),
            "Interface view"
        );
        let info = nd.get_wireless_info();
        ensure!(info.base_mac == FW_MAC, "wireless info MAC");
        ensure!(
            info.bands
                .iter()
                .any(|b| b.freq_mhz == 2400 && b.channels.contains(&6)),
            "2.4 GHz band from hal_reg_cap + the regulatory rules"
        );
        ensure!(
            info.bands
                .iter()
                .any(|b| b.freq_mhz == 5000 && b.channels.contains(&36)),
            "5 GHz band"
        );
        // The fixture's MAC/PHY caps carry no HT capability bits
        // (`ht_cap_info` 0) but a 5 GHz VHT capability.
        ensure!(
            !info.hw_caps.ht_supported
                && info.hw_caps.ht_supported == nd.radio().ht
                && info.hw_caps.vht_supported == nd.radio().vht
                && !info.hw_caps.he_supported,
            "HT / VHT from the firmware caps, no HE"
        );
        let g = run(u.shared.lock());
        ensure!(g.link.vif.is_some(), "DP vdev TX attach");
        ensure!(
            g.mon_reap_at.is_some(),
            "monitor reap timer armed by mac start"
        );
        ensure!(g.core.state == CoreState::Ready, "core ready");
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_int_bring_up_to_netdev
);

/// A passive scan through WMI events over the CE rings.
fn smoke_ath11k_int_scan() -> TestResult {
    check(|| {
        let u = up(wpa2_cfg())?;
        let (r, _, _, stage) = latched(|| scan6(&u));
        let bss = r?;
        ensure!(stage == narf_memory::diag::WifiStage::Scan, "stage scan");
        ensure!(bss.len() == 1, "one BSS");
        ensure!(
            bss[0].bssid == BSSID && bss[0].ssid == SSID && bss[0].channel == 6,
            "BSS from the beacon"
        );
        ensure!(
            matches!(bss[0].security, narf_wireless::scan::BssSecurity::Wpa2),
            "WPA2"
        );
        ensure!(
            u.netdev.scan_information_elements(BSSID).is_some(),
            "scan IEs kept"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_int_scan);

/// WPA2-PSK: auth / assoc as WMI management frames, HTT PEER_MAP, REO
/// queues, the 4-way handshake as EAPOL over the TCL / REO rings, PTK +
/// GTK installed, carrier on.
fn smoke_ath11k_int_wpa2_connect() -> TestResult {
    check(|| {
        let u = up(wpa2_cfg())?;
        connect(&u)?;
        ensure!(u.netdev.link_up(), "carrier on");
        ensure!(*LINK_SEEN.lock() == [true], "one carrier-on event");
        ensure!(u.netdev.connected_bssid() == Some(BSSID), "connected BSSID");
        let st = u.dev.st.borrow();
        ensure!(
            st.world.ap.m2_mic_ok && st.world.ap.m2_rsn_ok && st.world.ap.m4_ok,
            "M2 / M4 reached the authenticator through the TCL ring, MICs good"
        );
        let eapol: Vec<&TclTx> = st
            .tcl_tx
            .iter()
            .filter(|t| t.frame.len() > 32 && t.frame[30..32] == [0x88, 0x8e])
            .collect();
        ensure!(eapol.len() == 2, "M2 + M4 as native-wifi data");
        // M2: QoS AP → TID 7 (ieee80211_select_queue: control port),
        // QoS control stripped (ath11k_dp_tx_encap_nwifi): FC = data |
        // ToDS (0x0108), not protected (no PTK yet), BSSID / own / AP.
        let m2 = &eapol[0].frame;
        ensure!(
            m2[0..2] == [0x08, 0x01]
                && m2[4..10] == BSSID
                && m2[10..16] == OWN
                && m2[16..22] == BSSID,
            "M2 802.11 header"
        );
        ensure!((eapol[0].desc[5] >> 22) & 0xf == 7, "M2 TCL TID 7");
        // M4 goes out before the PTK is installed (wpa_supplicant order).
        ensure!(eapol[1].frame[1] & 0x40 == 0, "M4 unprotected");
        let keys = st
            .wmi
            .iter()
            .filter(|c| c.cmd_id == wmi::WMI_VDEV_INSTALL_KEY_CMDID)
            .count();
        ensure!(keys == 2, "PTK + GTK installed");
        // Fresh REO queues need no REO command; the pairwise PN config
        // (ath11k_dp_peer_rx_pn_replay_config) updates all 17 TIDs.
        ensure!(st.reo_cmds == 17, "17 REO UPDATE_RX_QUEUE for the PTK");
        drop(st);
        let g = run(u.shared.lock());
        ensure!(
            g.link.authorized && g.link.ptk && g.link.wme,
            "port open, PTK, WMM"
        );
        let p =
            g.dp.peers
                .iter()
                .find(|p| p.addr == BSSID)
                .ok_or("AP peer mapped")?;
        ensure!(
            p.peer_id == AP_PEER_ID
                && p.sec_type == dp_ring::enc::CCMP_128
                && p.sec_type_grp == dp_ring::enc::CCMP_128,
            "peer cipher set by key install"
        );
        ensure!(
            g.dp.peer_rx
                .peer(0, &BSSID)
                .is_some_and(|r| r.dp_setup_done),
            "REO TID queues set up"
        );
        ensure!(g.stats.rx_eapol >= 2, "M1 + M3 arrived through REO2SW1");
        ensure!(g.mgmt.pending == 0, "every management frame completed");
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_int_wpa2_connect);

/// An Ethernet frame sent through the stack (`send_on` → TX ring → TX
/// pump) reaches the TCL ring as the native-wifi frame mac80211 + ath11k
/// build; an RX'd native-wifi MSDU reaches the RX ring and the stack as
/// Ethernet II.
fn smoke_ath11k_int_data_tx_rx() -> TestResult {
    check(|| {
        let mut u = up(wpa2_cfg())?;
        ensure!(
            narf_net::iface::send_on(u.name, &ipv4_frame(&GW, &OWN, 0, &[1])).is_err(),
            "no TX before carrier"
        );
        connect(&u)?;
        let before = u.dev.st.borrow().tcl_tx.len();
        let payload = [0xde, 0xad, 0xbe, 0xef];
        // DSCP 0 → UP 0 (AC BE); DSCP 46 (EF, TOS 0xb8) → UP 6 (AC VO).
        for tos in [0x00u8, 0xb8] {
            let eth = ipv4_frame(&GW, &OWN, tos, &payload);
            ensure!(
                narf_net::iface::send_on(u.name, &eth).is_ok(),
                "stack send hook queues on the TX ring"
            );
            let f = u
                .tx_cons
                .try_recv()
                .ok()
                .flatten()
                .ok_or("frame on the TX ring")?;
            ensure!(
                f.payload() == &eth[..],
                "TX ring carries the Ethernet frame"
            );
            run(u.netdev.tx_one(&f)).map_err(|_| "TX pump → dp.tx")?;
        }
        pump(&u, 3);
        let st = u.dev.st.borrow();
        ensure!(
            st.tcl_tx.len() == before + 2,
            "two data frames on the TCL ring"
        );
        // ieee80211_build_hdr (STA, QoS AP) + ath11k_dp_tx_encap_nwifi:
        // FC data | ToDS | Protected (PTK installed), QoS control
        // stripped; addr1 BSSID, addr2 SA (own), addr3 DA; seq 0 (first
        // frame of TID 0); RFC 1042 SNAP + 0x0800; the IP datagram.
        let mut golden = vec![0x08, 0x41, 0x00, 0x00];
        golden.extend_from_slice(&BSSID);
        golden.extend_from_slice(&OWN);
        golden.extend_from_slice(&GW);
        golden.extend_from_slice(&[0x00, 0x00]);
        golden.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00]);
        golden.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x20, 0, 1, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1, 0x13, 0x88,
            0x13, 0x89, 0, 12, 0, 0, 0xde, 0xad, 0xbe, 0xef,
        ]);
        let t0 = &st.tcl_tx[before];
        ensure!(t0.frame == golden, "native-wifi golden (BE)");
        // hal_tcl_data_cmd: TLV, buffer, rbm SW0 | desc id, DESC_TYPE 0 |
        // ENCAP NATIVE_WIFI (1 << 2) | ADDRY_EN (2 << 14) | CMD_NUM
        // (tcl_metadata 1) << 16, length 64 (no checksum offload), TID
        // overwrite | TID 0, AST 0 (HTT peer map v1), 0.
        let id = (t0.desc[2] >> 11) & 0x1f_ffff;
        ensure!(
            id >> 19 == 2 && id & 3 == 0,
            "desc id: pool = AC BE (2), MAC 0"
        );
        ensure!(
            t0.desc[0] == dp_ring::TCL_DATA_TLV_HDR
                && t0.desc[2] & 0x7ff == 0x300
                && t0.desc[3] == 0x0001_8004
                && t0.desc[4] == 64
                && t0.desc[5] == 0x0020_0000
                && t0.desc[6] == 0
                && t0.desc[7] == 0,
            "TCL descriptor golden (BE)"
        );
        let t1 = &st.tcl_tx[before + 1];
        ensure!(
            t1.frame[0..2] == [0x08, 0x41] && t1.frame[22..24] == [0x00, 0x00],
            "EF: QoS stripped, seq 0 of TID 6, protected"
        );
        let id1 = (t1.desc[2] >> 11) & 0x1f_ffff;
        ensure!(
            t1.desc[5] == 0x0020_0000 | 6 << 22 && id1 >> 19 == 0,
            "EF → TID 6, pool AC VO (0)"
        );
        drop(st);

        // RX: the AP forwards a datagram from the gateway.
        let rx = ipv4_frame(&OWN, &GW, 0, &[9, 8, 7, 6]);
        let mut rx_cons = u.netdev.rx_ring().lock().take().ok_or("RX ring consumer")?;
        RX_SEEN.lock().clear();
        u.dev.st.borrow_mut().rx_queue.push_back(rx.clone());
        pump(&u, 3);
        ensure!(
            *RX_SEEN.lock() == [rx.clone()],
            "stack got the Ethernet II frame"
        );
        let f = rx_cons
            .try_recv()
            .ok()
            .flatten()
            .ok_or("frame on the RX ring")?;
        ensure!(
            f.payload() == &rx[..],
            "RX ring carries the Ethernet II frame"
        );
        // A group frame we sent, relayed back by the AP, is dropped.
        let echo = ipv4_frame(&[0xff; 6], &OWN, 0, &[1]);
        u.dev.st.borrow_mut().rx_queue.push_back(echo);
        pump(&u, 3);
        ensure!(RX_SEEN.lock().len() == 1, "own multicast echo dropped");
        let g = run(u.shared.lock());
        ensure!(
            g.stats.rx_dropped_echo == 1 && g.stats.tx_completed >= 4,
            "echo counted; TX completions reaped"
        );
        ensure!(
            g.stats.dp_irqs[0] > 0 && g.stats.dp_irqs[7] > 0,
            "TX completion (group 0) and RX (group 7) serviced from interrupts"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_int_data_tx_rx);

/// With every DP interrupt lost, the poll fallback still drives the
/// connect (EAPOL in / out) and data RX.
fn smoke_ath11k_int_dp_poll_fallback() -> TestResult {
    check(|| {
        let u = up(wpa2_cfg())?;
        u.dev.st.borrow_mut().mute_dp_irq = true;
        connect(&u)?;
        u.dev
            .st
            .borrow_mut()
            .rx_queue
            .push_back(ipv4_frame(&OWN, &GW, 0, &[5]));
        RX_SEEN.lock().clear();
        pump(&u, 3);
        ensure!(RX_SEEN.lock().len() == 1, "RX without interrupts");
        let g = run(u.shared.lock());
        ensure!(
            g.stats.dp_irqs.iter().all(|&n| n == 0),
            "no DP interrupt seen"
        );
        ensure!(g.stats.dp_polled_without_irq > 0, "work found by polling");
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_int_dp_poll_fallback);

/// Before the port opens only EAPOL passes; after a disconnect the
/// carrier drops, the AP peer is unmapped and data is refused.
fn smoke_ath11k_int_unauthorized_and_disconnect() -> TestResult {
    check(|| {
        let u = up(wpa2_cfg())?;
        u.dev
            .st
            .borrow_mut()
            .rx_queue
            .push_back(ipv4_frame(&OWN, &GW, 0, &[1]));
        pump(&u, 3);
        ensure!(
            RX_SEEN.lock().is_empty(),
            "data before authorization dropped"
        );
        ensure!(
            run(u.shared.lock()).stats.rx_dropped_unauth == 1,
            "counted as unauthorized"
        );
        connect(&u)?;
        let (r, _, _, _) = latched(|| run(u.netdev.disassociate()));
        ensure!(r.is_ok(), "disassociate");
        ensure!(!u.netdev.link_up(), "carrier off");
        ensure!(*LINK_SEEN.lock() == [true, false], "carrier on, then off");
        ensure!(
            *DISC_SEEN.lock() == [(3, false)],
            "nl80211: local disconnect, reason 3 (DEAUTH_LEAVING)"
        );
        ensure!(u.netdev.connected_bssid().is_none(), "no BSSID");
        let st = u.dev.st.borrow();
        ensure!(
            st.world
                .mgmt
                .last()
                .is_some_and(|f| f[0] == 0xc0 && f[24..26] == [3, 0]),
            "Deauthentication (reason 3) sent"
        );
        ensure!(
            st.wmi
                .iter()
                .any(|c| c.cmd_id == wmi::WMI_PEER_DELETE_CMDID),
            "peer deleted"
        );
        drop(st);
        let g = run(u.shared.lock());
        ensure!(
            g.dp.peers.is_empty() && g.link.bss.is_none() && !g.link.authorized && !g.link.ptk,
            "HTT unmap cleared the data-path peer state"
        );
        drop(g);
        ensure!(
            narf_net::iface::send_on(u.name, &ipv4_frame(&GW, &OWN, 0, &[1])).is_err(),
            "no TX after disconnect"
        );
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_int_unauthorized_and_disconnect
);

/// `ieee80211_frame_allowed` for EAPOL: to our address or the PAE group
/// address (01-80-C2-00-00-03) it reaches the supplicant queue, before
/// and after authorization; to the broadcast or another group address it
/// is dropped; unicast to another station is not ours at all.
fn smoke_ath11k_int_eapol_filter() -> TestResult {
    use super::mac_frame as frame;
    check(|| {
        let u = up(wpa2_cfg())?;
        let pdu = [0x02, 0x03, 0x00, 0x00];
        let feed = |da: &[u8; 6]| {
            u.dev
                .st
                .borrow_mut()
                .rx_queue
                .push_back(frame::eapol_eth(da, &BSSID, &pdu));
            pump(&u, 3);
        };
        let other = [0x00, 0x03, 0x7F, 0x99, 0x99, 0x99];
        feed(&[0xff; 6]);
        feed(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]);
        feed(&other);
        {
            let g = run(u.shared.lock());
            ensure!(
                g.stats.rx_dropped_eapol_da == 2 && g.stats.rx_dropped_not_ours == 1,
                "group EAPOL dropped, foreign unicast not ours"
            );
            ensure!(
                g.link.eapol_rx.is_empty() && g.stats.rx_eapol == 0,
                "nothing queued for the supplicant"
            );
        }
        feed(&super::runtime::PAE_GROUP_ADDR);
        feed(&OWN);
        let g = run(u.shared.lock());
        ensure!(
            g.stats.rx_eapol == 2 && g.link.eapol_rx.len() == 2,
            "PAE group and unicast EAPOL queued"
        );
        ensure!(
            g.link.eapol_rx[0][..6] == super::runtime::PAE_GROUP_ADDR,
            "PAE group frame delivered as received"
        );
        ensure!(RX_SEEN.lock().is_empty(), "EAPOL never reaches the stack");
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_int_eapol_filter);

/// PEER_STA_KICKOUT for the AP: the runtime loop's mac housekeeping
/// tears the link down and drops the carrier.
fn smoke_ath11k_int_link_loss() -> TestResult {
    check(|| {
        let u = up(wpa2_cfg())?;
        connect(&u)?;
        let w = [
            u32::from_le_bytes([BSSID[0], BSSID[1], BSSID[2], BSSID[3]]),
            u32::from_le_bytes([BSSID[4], BSSID[5], 0, 0]),
        ];
        u.dev.st.borrow_mut().world.events.push_back(wmi_event(
            wmi::WMI_PEER_STA_KICKOUT_EVENTID,
            &[tlv(wmi::WMI_TAG_PEER_STA_KICKOUT_EVENT, &le(&w))],
        ));
        let (_, err, _, stage) = latched(|| pump(&u, 5));
        ensure!(err == super::mac::step::LINK_KICKOUT, "kickout latched");
        ensure!(
            stage == narf_memory::diag::WifiStage::Scan,
            "stage back to scan"
        );
        ensure!(!u.netdev.link_up(), "carrier off");
        ensure!(*LINK_SEEN.lock() == [true, false], "carrier on, then off");
        ensure!(
            *DISC_SEEN.lock() == [(4, false)],
            "nl80211: local deauth, reason 4 (DISASSOC_DUE_TO_INACTIVITY)"
        );
        ensure!(
            u.netdev.stats.link_losses.load(Ordering::Relaxed) == 1,
            "one link loss"
        );
        ensure!(run(u.shared.lock()).dp.peers.is_empty(), "AP peer gone");
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_int_link_loss);

/// The reason cfg80211 reports when the association goes away
/// (`__cfg80211_disconnected` → `nl80211_send_disconnected`): a
/// Deauthentication / Disassociation from the AP gives its reason code
/// and `DISCONNECTED_BY_AP`; a local disconnect gives the reason of the
/// frame mac80211 sent (3); beacon / connection loss reason 4. The
/// nl80211 attributes are pinned as bytes.
fn smoke_ath11k_int_disconnect_reason() -> TestResult {
    use super::mac_frame as frame;
    use super::mac_tests::mgmt_rx_event;
    check(|| {
        // nl80211 attribute bytes (native endian; x86_64 LE): ifindex 5,
        // REASON_CODE (54) = 7, DISCONNECTED_BY_AP (71) flag.
        let a = narf_wireless::nl80211::disconnect_attrs(5, 7, true);
        ensure!(
            a == [
                8, 0, 3, 0, 5, 0, 0, 0, // IFINDEX
                6, 0, 54, 0, 7, 0, 0, 0, // REASON_CODE + pad
                4, 0, 71, 0, // DISCONNECTED_BY_AP
            ],
            "disconnect attrs from the AP"
        );
        ensure!(
            narf_wireless::nl80211::disconnect_attrs(5, 0, false) == [8, 0, 3, 0, 5, 0, 0, 0],
            "reason 0 omitted, no flag for a local disconnect"
        );

        for (stype, reason) in [(frame::stype::DEAUTH, 7u16), (frame::stype::DISASSOC, 8)] {
            let u = up(wpa2_cfg())?;
            connect(&u)?;
            let mut f = frame::mgmt_hdr(stype, &OWN, &BSSID, &BSSID);
            f.extend_from_slice(&reason.to_le_bytes());
            u.dev
                .st
                .borrow_mut()
                .world
                .events
                .push_back(mgmt_rx_event(6, 60, 2437, 0, &f));
            let (_, err, _, _) = latched(|| pump(&u, 5));
            ensure!(err == super::mac::step::LINK_DEAUTH_RX, "deauth RX latched");
            ensure!(!u.netdev.link_up(), "carrier off");
            ensure!(
                *DISC_SEEN.lock() == [(reason, true)],
                "nl80211: the AP's reason, DISCONNECTED_BY_AP"
            );
            ensure!(
                u.dev
                    .st
                    .borrow()
                    .world
                    .mgmt
                    .last()
                    .is_some_and(|f| f[0] != 0xc0),
                "a deauth from the AP is not answered"
            );
        }

        // A deauth for another BSSID or another station is ignored.
        let u = up(wpa2_cfg())?;
        connect(&u)?;
        let other = [0x02, 0x99, 0x99, 0x99, 0x99, 0x99];
        let mut f = frame::mgmt_hdr(frame::stype::DEAUTH, &other, &BSSID, &BSSID);
        f.extend_from_slice(&7u16.to_le_bytes());
        u.dev
            .st
            .borrow_mut()
            .world
            .events
            .push_back(mgmt_rx_event(6, 60, 2437, 0, &f));
        pump(&u, 5);
        ensure!(
            u.netdev.link_up() && DISC_SEEN.lock().is_empty(),
            "deauth to another DA ignored"
        );

        // Beacon loss: WMI_ROAM BEACON_MISS, no beacon for 3 s.
        let w = |v: u32| v.to_le_bytes();
        let mut roam = Vec::new();
        for v in [0u32, super::mac::WMI_ROAM_REASON_BEACON_MISS, 0] {
            roam.extend_from_slice(&w(v));
        }
        u.dev.st.borrow_mut().world.events.push_back(wmi_event(
            wmi::WMI_ROAM_EVENTID,
            &[tlv(wmi::WMI_TAG_ROAM_EVENT, &roam)],
        ));
        let (_, err, _, _) = latched(|| pump(&u, 400));
        ensure!(
            err == super::mac::step::LINK_BEACON_LOSS,
            "beacon loss latched"
        );
        ensure!(
            *DISC_SEEN.lock() == [(4, false)],
            "nl80211: reason 4, locally generated"
        );
        ensure!(
            u.dev
                .st
                .borrow()
                .world
                .mgmt
                .last()
                .is_some_and(|f| f[0] == 0xc0 && f[24..26] == [4, 0]),
            "Deauthentication reason 4 sent"
        );
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_int_disconnect_reason
);

/// PEER_MAP never arrives: the connect fails with the mac step, the
/// carrier stays off.
fn smoke_ath11k_int_peer_map_timeout() -> TestResult {
    check(|| {
        let u = up(FwCfg {
            peer_map: false,
            ..wpa2_cfg()
        })?;
        scan6(&u)?;
        let (r, err, _, _) = latched(|| run(u.netdev.associate(wpa2_req())));
        ensure!(r.is_err(), "associate fails");
        ensure!(
            err == super::mac::step::PEER_MAP_TIMEOUT,
            "PEER_MAP timeout latched"
        );
        ensure!(
            !u.netdev.link_up() && LINK_SEEN.lock().is_empty(),
            "carrier never on"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_int_peer_map_timeout);

/// Bring-up failures in the DP phase: each latches its own step, the
/// firmware is stopped (`wlan_mode OFF`) and the core is left failed.
fn smoke_ath11k_int_dp_bring_up_failures() -> TestResult {
    check(|| {
        // No DP parameters for the chip.
        let (mut core, mut hooks, _dev) = rig(script(), FwCfg::default(), SIZES);
        hooks.cfg = None;
        let (r, err, _, _) = bring_up(&mut core, &mut hooks);
        ensure!(
            r.map_err(|e| e.step) == Err(runtime::step::DP_UNSUPPORTED)
                && err == runtime::step::DP_UNSUPPORTED,
            "DP unsupported → 250"
        );
        ensure!(
            core.qmi.stops == 1 && matches!(core.state, CoreState::Failed(_)),
            "firmware stopped, core failed"
        );

        // DP alloc fails (the idle list would need the scatter path).
        let big = DpRingSizes {
            n_link_desc: Some(dp_ring::DP_LINK_DESC_ALLOC_SIZE_THRESH / 8 + 1),
            ..SMALL
        };
        let (mut core, mut hooks, _dev) = rig(script(), FwCfg::default(), big);
        let (r, err, _, _) = bring_up(&mut core, &mut hooks);
        let s = r.map_err(|e| e.step).err().ok_or("DP alloc must fail")?;
        ensure!(
            (s == dp_ring::step::LINK_DESC_BANKS || s == dp_ring::step::SCATTER_UNSUPPORTED)
                && err == s,
            "DP alloc failure latched with its dp_ring step"
        );
        ensure!(
            core.qmi.stops == 1 && !core.hif_started && hooks.dp.is_none(),
            "before HIF start: firmware stopped, no DP"
        );

        // The target never answers HTT VERSION_REQ.
        let (mut core, mut hooks, _dev) = rig(
            Script {
                htt_version_conf: false,
                ..script()
            },
            FwCfg::default(),
            SMALL,
        );
        let t0 = clock();
        let (r, err, _, _) = bring_up(&mut core, &mut hooks);
        ensure!(
            r.map_err(|e| e.step) == Err(htt::step::VERSION_TIMEOUT)
                && err == htt::step::VERSION_TIMEOUT,
            "HTT version timeout → 225"
        );
        ensure!(
            clock() - t0 >= htt::HTT_TARGET_VERSION_TIMEOUT_MS,
            "after 3 s"
        );
        ensure!(
            core.qmi.stops == 1 && !core.hif_started,
            "HIF stopped, firmware stopped"
        );
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_int_dp_bring_up_failures
);

/// `DpHooks` with the HTT endpoint lost before `pdev_create`: the first
/// SRING_SETUP cannot be sent.
struct LoseHtt(DpHooks);

impl CoreHooks<CeHif<Io, DevIrq>, TestQmi> for LoseHtt {
    fn dp_alloc(&mut self, core: &mut TCore) -> Result<(), TransportError> {
        self.0.dp_alloc(core)
    }
    fn pdev_reo_setup(&mut self, core: &mut TCore) -> Result<(), TransportError> {
        self.0.pdev_reo_setup(core)
    }
    async fn htt_ver_req(&mut self, core: &mut TCore) -> Result<(), TransportError> {
        self.0.htt_ver_req(core).await
    }
    async fn pdev_create(&mut self, core: &mut TCore) -> Result<(), TransportError> {
        core.htt_ep = None;
        self.0.pdev_create(core).await
    }
    fn irq_enable(&mut self, core: &mut TCore) {
        self.0.irq_enable(core)
    }
}

fn smoke_ath11k_int_pdev_create_failure() -> TestResult {
    check(|| {
        let (mut core, hooks, _dev) = rig(script(), FwCfg::default(), SIZES);
        let mut h = LoseHtt(hooks);
        let (r, err, detail, stage) = bring_up(&mut core, &mut h);
        ensure!(
            r.map_err(|e| e.step) == Err(runtime::step::SRING_SETUP_SEND)
                && err == runtime::step::SRING_SETUP_SEND
                && detail == super::core::step::HTT_SEND,
            "SRING_SETUP #0 send failure → 253 (detail 0 << 16 | 139)"
        );
        ensure!(
            stage == narf_memory::diag::WifiStage::Commands,
            "stage stays commands (no data path)"
        );
        ensure!(
            core.qmi.stops == 1 && !core.hif_started && !h.0.irqs_enabled,
            "unwound before irq enable"
        );
        // The mac layer needs the bring-up events.
        let (core, _h, _dev) = rig(script(), FwCfg::default(), SIZES);
        ensure!(
            runtime::device_caps(&core).map_err(|e| (e.step, e.detail))
                == Err((runtime::step::MAC_CAPS, 3)),
            "no EXT / READY → 255 detail 3"
        );
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_int_pdev_create_failure
);

// ── Ethernet → 802.11 (tx_hdr) ────────────────────────────────────

fn sta(wme: bool, authorized: bool, protected: bool) -> StaTx {
    StaTx {
        own: OWN,
        bssid: BSSID,
        wme,
        authorized,
        protected,
    }
}

/// `ieee80211_build_hdr` for a station, `cfg80211_classify8021d`,
/// `ieee80211_select_queue`, port control and the encapsulations.
fn smoke_ath11k_int_tx_hdr_golden() -> TestResult {
    check(|| {
        let mut seq = SeqState::default();
        let eth = ipv4_frame(&GW, &OWN, 0xb8, &[0xaa]);
        let b = tx_hdr::build_sta_data(&eth, &sta(false, true, false), &mut seq)
            .map_err(|_| "build")?;
        // Non-QoS: FC 0x0108, no QoS control, seq from the vif counter,
        // priority forced to 0 / AC BE ("required for correct WPA/11i MIC").
        let mut g = vec![0x08, 0x01, 0, 0];
        g.extend_from_slice(&BSSID);
        g.extend_from_slice(&OWN);
        g.extend_from_slice(&GW);
        g.extend_from_slice(&[0x00, 0x00]);
        g.extend_from_slice(&[0xaa, 0xaa, 0x03, 0, 0, 0, 0x08, 0x00]);
        g.extend_from_slice(&eth[14..]);
        ensure!(
            b.frame == g && b.tid == 0 && b.ac == tx_hdr::ac::BE,
            "non-QoS golden"
        );
        let b2 = tx_hdr::build_sta_data(&eth, &sta(false, true, false), &mut seq)
            .map_err(|_| "build")?;
        ensure!(
            b2.frame[22..24] == [0x10, 0x00],
            "next sequence number (+0x10)"
        );

        // QoS: QoS Data subtype + QoS control (TID, normal ack), per-TID seq.
        let mut seq = SeqState::default();
        let b =
            tx_hdr::build_sta_data(&eth, &sta(true, true, true), &mut seq).map_err(|_| "build")?;
        ensure!(
            b.frame[0..2] == [0x88, 0x41]
                && b.frame[24..26] == [6, 0]
                && b.tid == 6
                && b.ac == tx_hdr::ac::VO,
            "QoS + Protected, EF → TID 6 / VO"
        );
        ensure!(
            seq.tid[6] == 0x10 && seq.global == 0,
            "TID 6 counter advanced"
        );

        // cfg80211_classify8021d (RFC 8325 §2.3 / §4).
        let cases: [(u8, u8); 9] = [
            (0x00, 0), // DF
            (0x20, 1), // CS1 (dscp 8)
            (0x28, 0), // AF11 (dscp 10)
            (0x48, 3), // AF21 (dscp 18)
            (0x60, 4), // CS3 (dscp 24)
            (0x88, 4), // AF41 (dscp 34)
            (0xa0, 5), // CS5 (dscp 40)
            (0xb8, 6), // EF (dscp 46)
            (0xc0, 7), // CS6 (dscp 48)
        ];
        for (tos, up) in cases {
            ensure!(
                tx_hdr::classify8021d(&ipv4_frame(&GW, &OWN, tos, &[0])) == up,
                "DSCP → UP"
            );
        }
        let mut v6 = GW.to_vec();
        v6.extend_from_slice(&OWN);
        v6.extend_from_slice(&[0x86, 0xdd, 0x6b, 0x80, 0, 0]); // TC 0xb8
        ensure!(tx_hdr::classify8021d(&v6) == 6, "IPv6 traffic class");
        let mut arp = GW.to_vec();
        arp.extend_from_slice(&OWN);
        arp.extend_from_slice(&[0x08, 0x06, 0, 1]);
        ensure!(
            tx_hdr::select_queue(&arp, true) == (0, tx_hdr::ac::BE),
            "ARP → BE"
        );
        let mut pae = BSSID.to_vec();
        pae.extend_from_slice(&OWN);
        pae.extend_from_slice(&[0x88, 0x8e, 1, 3]);
        ensure!(
            tx_hdr::select_queue(&pae, true) == (7, tx_hdr::ac::VO),
            "EAPOL → 7"
        );

        // Port control: before authorization only our own EAPOL.
        let mut seq = SeqState::default();
        ensure!(
            tx_hdr::build_sta_data(&eth, &sta(true, false, false), &mut seq) == Err(1),
            "data before authorization: -EPERM"
        );
        ensure!(
            tx_hdr::build_sta_data(&pae, &sta(true, false, false), &mut seq).is_ok(),
            "own EAPOL passes"
        );
        let mut foreign = pae.clone();
        foreign[6..12].copy_from_slice(&GW);
        ensure!(
            tx_hdr::build_sta_data(&foreign, &sta(true, false, false), &mut seq) == Err(1),
            "bridged EAPOL refused"
        );

        // Bridge tunnel for IPX / AARP; 802.3 length frames keep their LLC.
        let mut ipx = GW.to_vec();
        ipx.extend_from_slice(&OWN);
        ipx.extend_from_slice(&[0x81, 0x37, 0xff, 0xff]);
        let b = tx_hdr::build_sta_data(&ipx, &sta(false, true, false), &mut seq)
            .map_err(|_| "build")?;
        ensure!(
            b.frame[24..32] == [0xaa, 0xaa, 0x03, 0, 0, 0xf8, 0x81, 0x37],
            "IPX: bridge-tunnel SNAP"
        );
        let mut llc = GW.to_vec();
        llc.extend_from_slice(&OWN);
        llc.extend_from_slice(&[0x00, 0x03, 0x42, 0x42, 0x03]);
        let b = tx_hdr::build_sta_data(&llc, &sta(false, true, false), &mut seq)
            .map_err(|_| "build")?;
        ensure!(
            b.frame.len() == 24 + 3 && b.frame[24..] == [0x42, 0x42, 0x03],
            "802.3 length frame: no encapsulation"
        );
        ensure!(
            tx_hdr::build_sta_data(&[0; 13], &sta(false, true, false), &mut seq) == Err(22),
            "short frame: -EINVAL"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_int_tx_hdr_golden);

/// `ieee80211_tx_h_sequence`: management frames, non-QoS data and
/// group-addressed QoS data share `sdata->sequence_number`; unicast QoS
/// data uses `sta->tid_seq[tid]`; control frames and QoS Null keep their
/// sequence control. Over the device: the authentication, association
/// and deauthentication frames the firmware receives carry 0x000, 0x010,
/// 0x020 (EAPOL to the WMM AP is QoS data on TID 7), and the counter
/// survives the disconnect (the vif outlives the AP's `sta_info`).
fn smoke_ath11k_int_mgmt_seq_shared() -> TestResult {
    use super::mac_frame as frame;
    check(|| {
        let mut seq = SeqState::default();
        // Open System Authentication, sequence control 0 from the builder.
        let mut auth = frame::build_auth_open(&OWN, &BSSID);
        tx_hdr::tx_h_sequence(&mut auth, &mut seq);
        let mut g = vec![0xb0, 0x00, 0x00, 0x00];
        g.extend_from_slice(&BSSID);
        g.extend_from_slice(&OWN);
        g.extend_from_slice(&BSSID);
        g.extend_from_slice(&[0x00, 0x00]);
        g.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
        ensure!(auth == g, "auth golden: seq 0");
        // Non-QoS data continues the same counter: 0x010.
        let eth = ipv4_frame(&GW, &OWN, 0, &[1]);
        let d = tx_hdr::build_sta_data(&eth, &sta(false, true, false), &mut seq)
            .map_err(|_| "build")?;
        ensure!(d.frame[22..24] == [0x10, 0x00], "non-QoS data: 0x010");
        // The next management frame: 0x020.
        let mut deauth = frame::build_deauth(&OWN, &BSSID, 3);
        tx_hdr::tx_h_sequence(&mut deauth, &mut seq);
        ensure!(deauth[22..24] == [0x20, 0x00], "deauth: 0x020");
        // Unicast QoS data: TID 5's own counter; the vif counter stays.
        let mut q = vec![0x88, 0x01, 0, 0];
        q.extend_from_slice(&BSSID);
        q.extend_from_slice(&OWN);
        q.extend_from_slice(&GW);
        q.extend_from_slice(&[0xff, 0xff, 0x05, 0x00]);
        tx_hdr::tx_h_sequence(&mut q, &mut seq);
        ensure!(
            q[22..24] == [0x00, 0x00] && seq.tid[5] == 0x10 && seq.global == 0x30,
            "QoS unicast: tid_seq[5]"
        );
        // Group-addressed QoS data: the vif counter (802.11-2012 9.3.2.10).
        let mut gq = q.clone();
        gq[4..10].copy_from_slice(&[0xff; 6]);
        tx_hdr::tx_h_sequence(&mut gq, &mut seq);
        ensure!(gq[22..24] == [0x30, 0x00], "group QoS: 0x030");
        // QoS Null (FC 0x00c8) and a control frame (PS-Poll, FC 0x00a4)
        // are left alone.
        let mut qn = q.clone();
        qn[0] = 0xc8;
        qn[22..24].copy_from_slice(&[0xab, 0xcd]);
        tx_hdr::tx_h_sequence(&mut qn, &mut seq);
        let mut ctl = vec![0xa4, 0x00, 0x01, 0xc0];
        ctl.extend_from_slice(&BSSID);
        ctl.extend_from_slice(&OWN);
        ctl.extend_from_slice(&[0u8; 10]);
        let ctl0 = ctl.clone();
        tx_hdr::tx_h_sequence(&mut ctl, &mut seq);
        ensure!(
            qn[22..24] == [0xab, 0xcd] && ctl == ctl0 && seq.global == 0x40,
            "QoS Null / control untouched"
        );
        // sta_info freed: tid_seq goes, sdata->sequence_number stays.
        seq.sta_destroyed();
        ensure!(seq.tid == [0; 16] && seq.global == 0x40, "sta destroyed");
        // u16 wrap (frag bits stay 0).
        seq.global = 0xfff0;
        let mut w = frame::build_deauth(&OWN, &BSSID, 3);
        tx_hdr::tx_h_sequence(&mut w, &mut seq);
        ensure!(w[22..24] == [0xf0, 0xff] && seq.global == 0, "wrap");

        // Over the device.
        let u = up(wpa2_cfg())?;
        connect(&u)?;
        let (r, _, _, _) = latched(|| run(u.netdev.disassociate()));
        ensure!(r.is_ok(), "disassociate");
        let st = u.dev.st.borrow();
        let seqs: Vec<(u8, [u8; 2])> = st
            .world
            .mgmt
            .iter()
            .map(|f| (f[0], [f[22], f[23]]))
            .collect();
        ensure!(
            seqs == [
                (0xb0, [0x00, 0x00]),
                (0x00, [0x10, 0x00]),
                (0xc0, [0x20, 0x00])
            ],
            "auth 0x000, assoc 0x010, deauth 0x020"
        );
        drop(st);
        ensure!(
            run(u.shared.lock()).link.seq.global == 0x30,
            "vif counter survives the AP's sta_info"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_int_mgmt_seq_shared);

// ── command-line autoconnect (bring-up aid) ───────────────────────

/// `ath11k.*` parameters: parse, key derivation, rejects.
fn smoke_ath11k_int_autoconnect_cmdline() -> TestResult {
    use super::autoconnect::{parse, unescape, AutoCfg, CfgError};
    check(|| {
        ensure!(
            parse("quiet root=PARTLABEL=NARF_ROOT") == Ok(None),
            "nothing asked"
        );
        ensure!(parse("ath11k.scan=0") == Ok(None), "scan=0 is off");
        ensure!(
            parse("ath11k.scan=1")
                == Ok(Some(AutoCfg {
                    ssid: None,
                    pmk: None
                })),
            "scan only"
        );
        ensure!(
            parse("ath11k.ssid=narf-ap")
                == Ok(Some(AutoCfg {
                    ssid: Some(SSID.to_vec()),
                    pmk: None
                })),
            "open network"
        );
        let hex: alloc::string::String = PMK.iter().map(|b| alloc::format!("{:02x}", b)).collect();
        let line = alloc::format!("ath11k.ssid=narf-ap ath11k.psk={}", hex);
        ensure!(
            parse(&line)
                == Ok(Some(AutoCfg {
                    ssid: Some(SSID.to_vec()),
                    pmk: Some(PMK)
                })),
            "WPA2 with a PMK"
        );
        // IEEE 802.11-2020 Annex J.4.2 test vector: passphrase
        // "password", SSID "IEEE".
        let want: [u8; 32] = [
            0xf4, 0x2c, 0x6f, 0xc5, 0x2d, 0xf0, 0xeb, 0xef, 0x9e, 0xbb, 0x4b, 0x90, 0xb3, 0x8a,
            0x5f, 0x90, 0x2e, 0x83, 0xfe, 0x1b, 0x13, 0x5a, 0x70, 0xe2, 0x3a, 0xed, 0x76, 0x2e,
            0x97, 0x10, 0xa1, 0x2e,
        ];
        ensure!(
            parse("ath11k.passphrase=password ath11k.ssid=IEEE")
                == Ok(Some(AutoCfg {
                    ssid: Some(b"IEEE".to_vec()),
                    pmk: Some(want)
                })),
            "passphrase → PBKDF2-SHA1 PMK"
        );
        ensure!(
            unescape("my%20net") == Some(b"my net".to_vec()) && unescape("bad%2").is_none(),
            "%XX escapes"
        );
        ensure!(
            parse("ath11k.ssid=") == Err(CfgError::BadSsid),
            "empty SSID"
        );
        ensure!(
            parse("ath11k.ssid=0123456789012345678901234567890123") == Err(CfgError::BadSsid),
            "SSID > 32 bytes"
        );
        ensure!(
            parse("ath11k.ssid=x ath11k.psk=abcd") == Err(CfgError::BadPsk),
            "short PSK"
        );
        ensure!(
            parse("ath11k.ssid=x ath11k.passphrase=short") == Err(CfgError::BadPassphrase),
            "passphrase < 8"
        );
        ensure!(
            parse(&alloc::format!("ath11k.psk={}", hex)) == Err(CfgError::KeyWithoutSsid),
            "key without SSID"
        );
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_int_autoconnect_cmdline
);

/// The autoconnect attempt on the fake device: directed scan, strongest
/// matching WPA2 BSS, connect, carrier on.
fn smoke_ath11k_int_autoconnect_attempt() -> TestResult {
    use super::autoconnect::{attempt, pick, AutoCfg};
    use narf_wireless::scan::BssSecurity;
    check(|| {
        let mk = |b: u8, rssi: i8, security| narf_wireless::BssInfo {
            bssid: [2, 0, 0, 0, 0, b],
            ssid: SSID.to_vec(),
            channel: 6,
            rssi,
            security,
        };
        let list = [
            mk(1, -70, BssSecurity::Wpa2),
            mk(2, -40, BssSecurity::Wpa2),
            mk(3, -30, BssSecurity::Wpa3),
            mk(4, -20, BssSecurity::Open),
        ];
        ensure!(
            pick(&list, SSID, true).map(|b| b.bssid[5]) == Some(2),
            "strongest WPA2 BSS"
        );
        ensure!(
            pick(&list, SSID, false).map(|b| b.bssid[5]) == Some(4),
            "open BSS"
        );
        ensure!(pick(&list, b"other", true).is_none(), "SSID must match");

        let u = up(wpa2_cfg())?;
        let cfg = AutoCfg {
            ssid: Some(SSID.to_vec()),
            pmk: Some(PMK),
        };
        let (r, err, _, stage) = latched(|| run(attempt(u.netdev.as_ref(), &cfg)));
        ensure!(r == Ok(Some(BSSID)) && err == 0, "connected");
        ensure!(
            stage == narf_memory::diag::WifiStage::Connected && u.netdev.link_up(),
            "stage connected, carrier on"
        );
        let st = u.dev.st.borrow();
        let scan = st
            .wmi
            .iter()
            .find(|c| c.cmd_id == wmi::WMI_START_SCAN_CMDID)
            .ok_or("START_SCAN")?;
        ensure!(
            scan.buf.windows(SSID.len()).any(|w| w == SSID),
            "directed (active) scan carries the SSID"
        );
        drop(st);
        let wrong = AutoCfg {
            ssid: Some(b"nope".to_vec()),
            pmk: None,
        };
        let (r, _, _, _) = latched(|| run(attempt(u.netdev.as_ref(), &wrong)));
        ensure!(r.is_err(), "no matching BSS → error, no association");
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_int_autoconnect_attempt
);

// ── checksum offload ──────────────────────────────────────────────

/// An IPv4 / TCP frame (checksum field 0) 10.0.0.2:5000 → 10.0.0.1:5001.
fn tcp4_frame(da: &[u8; 6], sa: &[u8; 6], payload: &[u8]) -> Vec<u8> {
    let mut f = da.to_vec();
    f.extend_from_slice(sa);
    f.extend_from_slice(&[0x08, 0x00]);
    let total = 40 + payload.len() as u8;
    f.extend_from_slice(&[0x45, 0, 0, total, 0, 1, 0x40, 0, 64, 6, 0, 0]);
    f.extend_from_slice(&[10, 0, 0, 2, 10, 0, 0, 1]);
    f.extend_from_slice(&[0x13, 0x88, 0x13, 0x89, 0, 0, 0, 1, 0, 0, 0, 0]);
    f.extend_from_slice(&[0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
    f.extend_from_slice(payload);
    f
}

/// An IPv6 / UDP frame fe80::1:5000 → fe80::2:5001 (checksum field 0).
fn udp6_frame(payload: &[u8]) -> Vec<u8> {
    let mut f = GW.to_vec();
    f.extend_from_slice(&OWN);
    f.extend_from_slice(&[0x86, 0xdd]);
    let ulen = 8 + payload.len() as u16;
    f.extend_from_slice(&[0x60, 0, 0, 0]);
    f.extend_from_slice(&ulen.to_be_bytes());
    f.extend_from_slice(&[17, 64]);
    let mut a = [0u8; 16];
    a[0] = 0xfe;
    a[1] = 0x80;
    a[15] = 1;
    f.extend_from_slice(&a);
    a[15] = 2;
    f.extend_from_slice(&a);
    f.extend_from_slice(&[0x13, 0x88, 0x13, 0x89]);
    f.extend_from_slice(&ulen.to_be_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(payload);
    f
}

/// `CHECKSUM_PARTIAL` seeds and refusals, RX checksum verdicts. Seeds
/// are the folded pseudo-header sums Linux leaves in the field
/// (`tcp_v4_send_check`: `~tcp_v4_check(len, saddr, daddr, 0)`), worked
/// by hand: IPv4 0x0a00 + 0x0002 + 0x0a00 + 0x0001 + 6 + 24 = 0x1421;
/// IPv6 2 × 0xfe80 + 1 + 2 + 17 + 12 = 0x1fd20 → 0xfd21.
fn smoke_ath11k_tx_csum_prepare() -> TestResult {
    use super::tx_offload::{csum_partial_prepare, rx_meta};
    use narf_net::L4CsumKind::{Tcp, Udp};
    check(|| {
        let mut f = tcp4_frame(&GW, &OWN, &[1, 2, 3, 4]);
        ensure!(csum_partial_prepare(&mut f, Tcp) == Ok(()), "IPv4 TCP");
        ensure!(f[14 + 20 + 16..14 + 20 + 18] == [0x14, 0x21], "TCP seed");
        let mut g = f.clone();
        ensure!(
            csum_partial_prepare(&mut g, Tcp) == Ok(()) && g == f,
            "re-preparing a seeded frame is idempotent"
        );
        let mut u = udp6_frame(&[9, 9, 9, 9]);
        ensure!(csum_partial_prepare(&mut u, Udp) == Ok(()), "IPv6 UDP");
        ensure!(u[14 + 40 + 6..14 + 40 + 8] == [0xfd, 0x21], "UDP seed");

        // Refusals: frame untouched, the stack must checksum it.
        let mut mf = tcp4_frame(&GW, &OWN, &[1]);
        mf[14 + 6] = 0x20;
        let mut off = tcp4_frame(&GW, &OWN, &[1]);
        off[14 + 6] = 0;
        off[14 + 7] = 8;
        let mut pad = tcp4_frame(&GW, &OWN, &[1]);
        pad.push(0);
        let mut doff = tcp4_frame(&GW, &OWN, &[1]);
        doff[14 + 20 + 12] = 0x40;
        let mut ext = udp6_frame(&[1]);
        ext[14 + 6] = 0;
        let mut ulen = udp6_frame(&[1]);
        ulen[14 + 40 + 5] += 1;
        let mut vlan = tcp4_frame(&GW, &OWN, &[1]);
        vlan[12] = 0x81;
        vlan[13] = 0x00;
        let mut arp = ipv4_frame(&GW, &OWN, 0, &[1]);
        arp[12] = 0x08;
        arp[13] = 0x06;
        let bad: [(&str, Vec<u8>, narf_net::L4CsumKind); 10] = [
            ("UDP kind on TCP", tcp4_frame(&GW, &OWN, &[1]), Udp),
            ("TCP kind on UDP", udp6_frame(&[1]), Tcp),
            ("IPv4 MF fragment", mf, Tcp),
            ("IPv4 fragment offset", off, Tcp),
            ("IPv4 length != frame (padding)", pad, Tcp),
            ("TCP data offset < 5", doff, Tcp),
            ("IPv6 extension header", ext, Udp),
            ("UDP length != payload length", ulen, Udp),
            ("in-band VLAN tag", vlan, Tcp),
            ("ARP", arp.clone(), Tcp),
        ];
        for (what, frame, kind) in bad.iter() {
            let mut x = frame.clone();
            if csum_partial_prepare(&mut x, *kind) != Err(super::tx_offload::EINVAL) || x != *frame
            {
                return Err(what);
            }
        }

        // RX: ath11k_dp_rx_h_csum_offload, narrowed to the ring contract.
        let m = rx_meta(&f, true);
        ensure!(m.csum_l3 && m.csum_l4, "IPv4 TCP verified");
        let m = rx_meta(&u, true);
        ensure!(
            !m.csum_l3 && m.csum_l4,
            "IPv6: no L3 checksum, UDP verified"
        );
        let m = rx_meta(&f, false);
        ensure!(!m.csum_l3 && !m.csum_l4, "a fail bit: nothing verified");
        let mut icmp = tcp4_frame(&GW, &OWN, &[1]);
        icmp[14 + 9] = 1;
        let m = rx_meta(&icmp, true);
        ensure!(m.csum_l3 && !m.csum_l4, "ICMP: IPv4 header only");
        let mut frag = tcp4_frame(&GW, &OWN, &[1]);
        frag[14 + 6] = 0x20;
        let m = rx_meta(&frag, true);
        ensure!(m.csum_l3 && !m.csum_l4, "fragment: L4 not claimed");
        let m = rx_meta(&arp, true);
        ensure!(!m.csum_l3 && !m.csum_l4, "ARP: nothing");
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_tx_csum_prepare);

/// NETIF_F_HW_CSUM end to end: the netdev advertises TX / RX checksum
/// offload; a `TxMeta::csum_l4` frame from the stack reaches TCL with
/// the five `HAL_TCL_DATA_CMD_INFO1_*_CKSUM_EN` bits (16..20, Linux
/// `hal_desc.h`) and its seed; a plain frame without them; TSO / VLAN
/// requests and impossible checksum requests are refused; the RX ring
/// reports the RX attention checksum verdict.
fn smoke_ath11k_int_tx_csum_offload() -> TestResult {
    check(|| {
        let mut u = up(wpa2_cfg())?;
        let want = super::tx_offload::OFFLOADS;
        ensure!(
            u.netdev.offloads() == want
                && narf_net::iface::lookup(u.name).is_some_and(|s| s.offloads == want),
            "TX + RX checksum advertised, no TSO / VLAN"
        );
        connect(&u)?;
        let snap = narf_net::iface::lookup(u.name).ok_or("snapshot")?;
        let csum = narf_net::TxMeta::with_csum(narf_net::L4CsumKind::Tcp);
        let eth = tcp4_frame(&GW, &OWN, &[0xde, 0xad, 0xbe, 0xef]);
        let before = u.dev.st.borrow().tcl_tx.len();
        for meta in [csum, narf_net::TxMeta::plain()] {
            ensure!(snap.xmit_meta(&eth, meta).is_ok(), "send hook queues");
            let f = u
                .tx_cons
                .try_recv()
                .ok()
                .flatten()
                .ok_or("frame on the TX ring")?;
            ensure!(f.tx_meta() == meta, "the offload request rides the frame");
            run(u.netdev.tx_one(&f)).map_err(|_| "TX pump → dp.tx")?;
        }
        pump(&u, 3);
        let st = u.dev.st.borrow();
        ensure!(st.tcl_tx.len() == before + 2, "two frames on TCL");
        // 24 (QoS stripped) + 8 SNAP + 44 IP = 76 bytes.
        let (t0, t1) = (&st.tcl_tx[before], &st.tcl_tx[before + 1]);
        ensure!(
            t0.desc[3] == 0x0001_8004 && t0.desc[4] == 0x001f_0000 | 76,
            "CHECKSUM_PARTIAL: IP4 | UDP4 | UDP6 | TCP4 | TCP6 CKSUM_EN | len 76"
        );
        ensure!(
            t0.frame[68..70] == [0x14, 0x21],
            "TCP seed in the TCL frame"
        );
        ensure!(
            t1.desc[3] == 0x0001_8004 && t1.desc[4] == 76,
            "plain frame: no checksum bits"
        );
        ensure!(t1.frame[68..70] == [0, 0], "plain frame untouched");
        drop(st);

        let refused = |u: &Up| u.netdev.stats.tx_offload_refused.load(Ordering::Relaxed);
        let vlan = narf_net::TxMeta {
            vlan_tag: Some(5),
            ..narf_net::TxMeta::plain()
        };
        ensure!(
            snap.xmit_meta(&eth, narf_net::TxMeta::with_tso(1400))
                .is_err()
                && snap.xmit_meta(&eth, vlan).is_err()
                && refused(&u) == 2,
            "TSO and VLAN insertion refused at the send hook"
        );
        let udp = narf_net::TxMeta::with_csum(narf_net::L4CsumKind::Udp);
        ensure!(snap.xmit_meta(&eth, udp).is_ok(), "queued");
        let f = u.tx_cons.try_recv().ok().flatten().ok_or("frame")?;
        ensure!(
            run(u.netdev.tx_one(&f)) == Err(super::tx_offload::EINVAL) && refused(&u) == 3,
            "UDP checksum on a TCP segment refused before TCL"
        );
        pump(&u, 2);
        ensure!(
            u.dev.st.borrow().tcl_tx.len() == before + 2,
            "nothing sent half-checksummed"
        );

        // RX: the attention checksum-fail bits → the ring's RxMeta.
        let mut rx_cons = u.netdev.rx_ring().lock().take().ok_or("RX ring consumer")?;
        let rx = tcp4_frame(&OWN, &GW, &[7]);
        for (attn1, l3, l4) in [
            (0u32, true, true),
            (super::dp::RX_ATTENTION_INFO1_IP_CKSUM_FAIL, false, false),
            (
                super::dp::RX_ATTENTION_INFO1_TCP_UDP_CKSUM_FAIL,
                false,
                false,
            ),
        ] {
            {
                let mut st = u.dev.st.borrow_mut();
                st.rx_attn1 = attn1;
                st.rx_queue.push_back(rx.clone());
            }
            pump(&u, 3);
            let f = rx_cons.try_recv().ok().flatten().ok_or("RX ring frame")?;
            let m = f.rx_meta();
            if f.payload() != &rx[..] || m.csum_l3 != l3 || m.csum_l4 != l4 {
                return Err("RX checksum verdict on the ring");
            }
        }
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_int_tx_csum_offload);

// ── per-AC TX queues ──────────────────────────────────────────────

/// mac80211's TXQ rules on the pure queues: `vif->hw_queue[ac] = ac % 3`
/// (`ath11k_mac_op_add_interface`), VO → BK service order, per-queue
/// stop reasons (a queue runs only with none left), `fq` overlimit
/// drops from the fattest queue's head, purge.
fn smoke_ath11k_txq_queues() -> TestResult {
    use super::tx_hdr::ac;
    use super::txq::{hw_queue, reason, Queued, TxQueues};
    let q = |b: u8| Queued {
        eth: vec![b; 6],
        csum_partial: false,
        ack_id: None,
    };
    check(|| {
        ensure!(
            [
                hw_queue(ac::VO),
                hw_queue(ac::VI),
                hw_queue(ac::BE),
                hw_queue(ac::BK)
            ] == [0, 1, 2, 0],
            "hw_queue = ac % (ATH11K_HW_MAX_QUEUES - 1)"
        );
        ensure!(TxQueues::vif_queues() == 0b111, "vif queues 0..2");
        let mut t = TxQueues::default();
        for (a, b) in [
            (ac::BK, 1),
            (ac::BE, 2),
            (ac::VI, 3),
            (ac::VO, 4),
            (ac::BE, 5),
        ] {
            ensure!(t.enqueue(a, q(b)).is_empty(), "under the fq limits");
        }
        let order: Vec<u8> = core::iter::from_fn(|| t.dequeue())
            .map(|(_, f)| f.eth[0])
            .collect();
        ensure!(
            order == [4, 3, 2, 5, 1],
            "backlog drains VO, VI, BE (FIFO), BK"
        );

        // Hardware queue 0 (VO + BK) stopped by two reasons.
        t.enqueue(ac::VO, q(1));
        t.enqueue(ac::BK, q(2));
        t.enqueue(ac::BE, q(3));
        t.stop(1 << 0, reason::DRIVER);
        t.stop(1 << 0, reason::FLUSH);
        ensure!(
            t.stop_reasons(0) == (1 << reason::DRIVER) | (1 << reason::FLUSH),
            "two stop reasons on queue 0"
        );
        ensure!(
            t.dequeue().map(|(a, f)| (a, f.eth[0])) == Some((ac::BE, 3)) && t.dequeue().is_none(),
            "VO / BK held, BE flows"
        );
        t.wake(1 << 0, reason::FLUSH);
        ensure!(t.dequeue().is_none(), "one reason left: still stopped");
        t.wake(1 << 0, reason::DRIVER);
        ensure!(
            t.dequeue().map(|(a, _)| a) == Some(ac::VO)
                && t.dequeue().map(|(a, _)| a) == Some(ac::BK),
            "woken: VO then BK"
        );

        // fq_tin_enqueue overlimit (packets, then bytes).
        let mut t = TxQueues::with_limits(3, 1 << 20);
        t.enqueue(ac::BE, q(1));
        t.enqueue(ac::BE, q(2));
        t.enqueue(ac::VO, q(3));
        let d = t.enqueue(ac::VI, q(4));
        ensure!(
            d.len() == 1 && d[0].eth[0] == 1 && t.backlog() == 3 && t.stats.overlimit == 1,
            "over fq->limit: the fattest queue's head dropped"
        );
        let mut t = TxQueues::with_limits(100, 10);
        t.enqueue(ac::BK, q(1));
        let d = t.enqueue(ac::VO, q(2));
        ensure!(
            d.len() == 1 && t.backlog() == 1 && t.len(ac::VO) == 1,
            "over memory_limit: dropped until it fits"
        );
        ensure!(
            t.purge() == 1 && t.is_empty() && t.stats.purged == 1,
            "purge"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_txq_queues);

/// The TXQs on the fake device: frames reach TCL at once while the
/// queues run; with the vif's hardware queues stopped (reason DRIVER, as
/// `ath11k_core_pre_reconfigure_recovery`'s `ieee80211_stop_queues`) they
/// wait, and the wake sends them VO, VI, BE, BK whatever the arrival
/// order (TID 6, 4, 0, 1; descriptor pool = AC); one stopped hardware
/// queue holds only its ACs; a dropping flush purges; frames for no
/// station are refused.
fn smoke_ath11k_int_tx_ac_priority() -> TestResult {
    use super::txq::{reason, TxQueues};
    check(|| {
        let mut u = up(wpa2_cfg())?;
        connect(&u)?;
        let tcl = |u: &Up| {
            pump(u, 1);
            u.dev.st.borrow().tcl_tx.len()
        };
        let send = |u: &mut Up, tos: u8| -> R {
            let eth = ipv4_frame(&GW, &OWN, tos, &[tos]);
            ensure!(narf_net::iface::send_on(u.name, &eth).is_ok(), "send hook");
            let fr = u.tx_cons.try_recv().ok().flatten().ok_or("TX ring")?;
            ensure!(run(u.netdev.tx_one(&fr)).is_ok(), "queued");
            Ok(())
        };
        // BK (CS1 → UP 1), BE (0), VI (CS4 → UP 4), VO (EF → UP 6).
        let arrivals = [0x20u8, 0x00, 0x80, 0xb8];
        let base = tcl(&u);
        send(&mut u, 0x00)?;
        ensure!(tcl(&u) == base + 1, "running queues: straight to TCL");

        run(u.shared.lock()).stop_queues(TxQueues::vif_queues(), reason::DRIVER);
        let base = tcl(&u);
        for tos in arrivals {
            send(&mut u, tos)?;
        }
        pump(&u, 2);
        ensure!(tcl(&u) == base, "stopped: nothing reaches TCL");
        ensure!(
            run(u.shared.lock()).txq.backlog() == 4,
            "four frames queued"
        );
        let sent = run(u.shared.lock()).wake_queues(TxQueues::vif_queues(), reason::DRIVER);
        ensure!(sent == 4, "the wake pushes all four");
        pump(&u, 2);
        let st = u.dev.st.borrow();
        let got: Vec<(u32, u32, u8)> = st.tcl_tx[base..]
            .iter()
            .map(|t| {
                let id = (t.desc[2] >> 11) & 0x1f_ffff;
                ((t.desc[5] >> 22) & 0xf, id >> 19, *t.frame.last().unwrap())
            })
            .collect();
        ensure!(
            got == [(6, 0, 0xb8), (4, 1, 0x80), (0, 2, 0x00), (1, 3, 0x20)],
            "VO, VI, BE, BK: TID 6/4/0/1, pool = AC"
        );
        drop(st);

        // Only hardware queue 2 (BE) stopped: VO passes, BE waits.
        run(u.shared.lock()).stop_queues(1 << 2, reason::FLUSH);
        let base = tcl(&u);
        send(&mut u, 0x00)?;
        send(&mut u, 0xb8)?;
        ensure!(tcl(&u) == base + 1, "VO sent past the stopped BE queue");
        run(u.shared.lock()).wake_queues(1 << 2, reason::FLUSH);
        ensure!(tcl(&u) == base + 2, "BE sent on wake");

        // A dropping flush purges what is queued.
        run(u.shared.lock()).stop_queues(TxQueues::vif_queues(), reason::DRIVER);
        send(&mut u, 0x00)?;
        send(&mut u, 0x80)?;
        run(u.shared.flush_queues(true));
        let base = tcl(&u);
        run(u.shared.lock()).wake_queues(TxQueues::vif_queues(), reason::DRIVER);
        let after = tcl(&u);
        let g = run(u.shared.lock());
        ensure!(
            after == base && g.txq.is_empty() && g.stats.tx_queue_dropped == 2,
            "flush(drop): both purged, nothing sent"
        );
        drop(g);
        // Non-dropping flush with nothing pending returns at once.
        run(u.shared.flush_queues(false));
        ensure!(
            run(u.shared.lock()).txq.stop_reasons(0) == 0,
            "flush leaves the queues running"
        );

        // No station: ieee80211_build_hdr refuses before the TXQ.
        let (r, _, _, _) = latched(|| run(u.netdev.disassociate()));
        ensure!(r.is_ok(), "disassociate");
        let eth = ipv4_frame(&GW, &OWN, 0, &[1]);
        let r = run(u.shared.tx_frames(vec![(eth, false)]));
        ensure!(r == [Err(runtime::ENOTCONN)], "no station → ENOTCONN");
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_int_tx_ac_priority);

// ── ndo_open / ndo_stop ───────────────────────────────────────────

/// `ieee80211_do_open` / `ieee80211_do_stop` on IFF_UP: registered down
/// with the hardware not started (no WMI after bring-up, scan refused as
/// nl80211's -ENETDOWN); `set_link_state(up)` starts the pdev
/// (`ath11k_mac_op_start`: PMF_QOS first) and creates the vdev; down
/// while associated sends the Deauthentication (reason 3,
/// `cfg80211_leave`), drops the carrier, deletes the vdev (VDEV_DELETE,
/// answered) and turns the monitor-status filter off (`op_stop`); a
/// second up restarts everything and connects again; repeated or
/// unchanged requests send nothing.
fn smoke_ath11k_int_open_stop() -> TestResult {
    check(|| {
        let u = up_down(wpa2_cfg())?;
        let wmi_len = |u: &Up| u.dev.st.borrow().wmi.len();
        let n0 = wmi_len(&u);
        pump(&u, 2);
        ensure!(
            wmi_len(&u) == n0 && run(u.netdev.mac.lock()).vif().is_none(),
            "down: hardware not started"
        );
        ensure!(
            run(u.netdev.scan(ScanRequest {
                ssids: Vec::new(),
                channels: vec![6],
                active: false,
            }))
            .err()
                == Some(narf_wireless::WirelessError::HardwareError),
            "scan on a down interface refused"
        );
        ensure!(
            !narf_net::iface::set_link_state("wlan-none", true),
            "unknown"
        );

        ensure!(narf_net::iface::set_link_state(u.name, true), "IFF_UP");
        ensure!(u.netdev.admin_up(), "ndo_open reached the driver");
        let (_, err, _, _) = latched(|| pump(&u, 1));
        ensure!(err == 0, "open latched nothing");
        let opened = |u: &Up, from: usize| -> Vec<u32> {
            u.dev.st.borrow().wmi[from..]
                .iter()
                .map(|c| c.cmd_id)
                .collect()
        };
        let cmds = opened(&u, n0);
        ensure!(
            cmds.first() == Some(&wmi::WMI_PDEV_SET_PARAM_CMDID)
                && cmds.contains(&wmi::WMI_VDEV_CREATE_CMDID),
            "op_start then add_interface"
        );
        ensure!(
            run(u.shared.lock()).link.vif.is_some(),
            "ath11k_dp_vdev_tx_attach"
        );
        let n1 = wmi_len(&u);
        ensure!(narf_net::iface::set_link_state(u.name, true), "again");
        pump(&u, 2);
        ensure!(wmi_len(&u) == n1, "IFF_UP twice: nothing new");

        connect(&u)?;
        ensure!(u.netdev.link_up(), "carrier on");
        let n2 = wmi_len(&u);
        let htt0 = u.dev.st.borrow().htt_h2t.len();
        ensure!(narf_net::iface::set_link_state(u.name, false), "IFF_DOWN");
        ensure!(!u.netdev.admin_up(), "ndo_stop reached the driver");
        let (_, err, _, _) = latched(|| pump(&u, 1));
        ensure!(err == 0, "stop latched nothing");
        let cmds = opened(&u, n2);
        let st = u.dev.st.borrow();
        ensure!(
            st.world
                .mgmt
                .last()
                .is_some_and(|f| f[0] == 0xc0 && f[24..26] == [3, 0]),
            "Deauthentication, reason 3 (DEAUTH_LEAVING)"
        );
        ensure!(
            cmds.contains(&wmi::WMI_PEER_DELETE_CMDID)
                && cmds.last() == Some(&wmi::WMI_VDEV_DELETE_CMDID),
            "peer gone, then the vdev deleted"
        );
        ensure!(
            st.htt_h2t.len() > htt0,
            "op_stop: monitor-status RX filter cleared over HTT"
        );
        drop(st);
        ensure!(
            !u.netdev.link_up() && *LINK_SEEN.lock() == [true, false],
            "carrier off"
        );
        ensure!(
            run(u.netdev.mac.lock()).vif().is_none() && !run(u.netdev.mac.lock()).is_started(),
            "vif removed, hardware stopped"
        );
        let g = run(u.shared.lock());
        ensure!(
            g.link.vif.is_none() && g.mgmt.pending == 0 && g.txq.is_empty(),
            "DP vif state, mgmt IDR and TXQs cleared"
        );
        drop(g);
        let n3 = wmi_len(&u);
        ensure!(narf_net::iface::set_link_state(u.name, false), "down again");
        pump(&u, 2);
        ensure!(wmi_len(&u) == n3, "IFF_DOWN twice: nothing new");

        // Up again: started from scratch, connects.
        ensure!(narf_net::iface::set_link_state(u.name, true), "IFF_UP");
        let (_, err, _, _) = latched(|| pump(&u, 1));
        ensure!(err == 0, "reopen");
        let cmds = opened(&u, n3);
        ensure!(
            cmds.first() == Some(&wmi::WMI_PDEV_SET_PARAM_CMDID)
                && cmds.contains(&wmi::WMI_VDEV_CREATE_CMDID),
            "restarted"
        );
        connect(&u)?;
        ensure!(u.netdev.link_up(), "connected after reopen");
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_int_open_stop);

/// The open runs from whichever task holds the mac layer first: a
/// control operation right after IFF_UP (autoconnect's scan, before any
/// runtime pass) opens the interface itself, then connects.
fn smoke_ath11k_int_open_from_control_op() -> TestResult {
    use super::autoconnect::{attempt, AutoCfg};
    check(|| {
        let u = up_down(wpa2_cfg())?;
        ensure!(narf_net::iface::set_link_state(u.name, true), "IFF_UP");
        let cfg = AutoCfg {
            ssid: Some(SSID.to_vec()),
            pmk: Some(PMK),
        };
        let (r, err, _, _) = latched(|| run(attempt(u.netdev.as_ref(), &cfg)));
        ensure!(r == Ok(Some(BSSID)) && err == 0, "opened and connected");
        ensure!(u.netdev.link_up(), "carrier on");
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_int_open_from_control_op
);

// ── TX status ─────────────────────────────────────────────────────

/// `ath11k_dp_tx_htt_tx_complete_buf` / `ath11k_dp_tx_complete_msdu`
/// status rules: ACK + `ack_rssi + ATH11K_DEFAULT_NOISE_FLOOR` (-95)
/// unless the firmware converts to dBm itself; no ACK without a signal;
/// freed (dropped) without a vif or a peer station.
fn smoke_ath11k_tx_status_rules() -> TestResult {
    use super::txq::{tx_status, TxStatus};
    check(|| {
        let acked = |s: Option<i32>| TxStatus {
            acked: true,
            dropped: false,
            ack_signal: s,
        };
        ensure!(
            tx_status(true, 40, false, true, true) == acked(Some(-55)),
            "acked, rssi 40 + noise floor"
        );
        ensure!(
            tx_status(true, 40, true, true, true) == acked(Some(40)),
            "HW_DB2DBM_CONVERSION_SUPPORT: rssi already dBm"
        );
        ensure!(
            tx_status(false, 40, false, true, true)
                == TxStatus {
                    acked: false,
                    dropped: false,
                    ack_signal: None,
                },
            "no ACK: no signal"
        );
        ensure!(
            tx_status(true, 40, false, false, true) == TxStatus::DROPPED
                && tx_status(true, 40, false, true, false) == TxStatus::DROPPED,
            "no vif / no peer station: ieee80211_free_txskb"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_tx_status_rules);

/// TX status end to end: a frame sent asking for its status gets it from
/// the WBM release the device writes — TQM FRAME_ACKED (ACK, -55 dBm),
/// TQM REMOVE_TX (no ACK), firmware HTT_TX_COMP OK / DROP / TTL (the
/// EAPOL / null-data path), an invalid or unknown peer id (dropped), a
/// REINJECT release (no status at all, as Linux: the wait times out and
/// the ack id is freed); a purged or interface-down frame reports
/// dropped; frames without a request only feed the counters.
fn smoke_ath11k_int_tx_status() -> TestResult {
    use super::dp_ring::{htt_comp, tqm};
    use super::txq::{reason, TxQueues, TxStatus};
    check(|| {
        let u = up(wpa2_cfg())?;
        connect(&u)?;
        let eth = ipv4_frame(&GW, &OWN, 0, &[1]);
        let ack = |s: i32| TxStatus {
            acked: true,
            dropped: false,
            ack_signal: Some(s),
        };
        let noack = TxStatus {
            acked: false,
            dropped: false,
            ack_signal: None,
        };
        let peer = AP_PEER_ID as u32;
        let cases: [(&str, TxRel, Result<TxStatus, i32>); 8] = [
            (
                "TQM acked",
                TxRel::Tqm {
                    reason: tqm::FRAME_ACKED,
                    peer,
                },
                Ok(ack(-55)),
            ),
            (
                "TQM removed",
                TxRel::Tqm {
                    reason: tqm::CMD_REMOVE_TX,
                    peer,
                },
                Ok(noack),
            ),
            (
                "HTT OK",
                TxRel::Htt {
                    status: htt_comp::OK,
                    rssi: 30,
                    peer: Some(peer),
                },
                Ok(ack(-65)),
            ),
            (
                "HTT DROP",
                TxRel::Htt {
                    status: htt_comp::DROP,
                    rssi: 30,
                    peer: Some(peer),
                },
                Ok(noack),
            ),
            (
                "HTT TTL",
                TxRel::Htt {
                    status: htt_comp::TTL,
                    rssi: 30,
                    peer: Some(peer),
                },
                Ok(noack),
            ),
            (
                "HTT invalid peer",
                TxRel::Htt {
                    status: htt_comp::OK,
                    rssi: 30,
                    peer: None,
                },
                Ok(TxStatus::DROPPED),
            ),
            (
                "TQM unknown peer",
                TxRel::Tqm {
                    reason: tqm::FRAME_ACKED,
                    peer: 99,
                },
                Ok(TxStatus::DROPPED),
            ),
            (
                "HTT REINJECT",
                TxRel::Htt {
                    status: htt_comp::REINJ,
                    rssi: 0,
                    peer: Some(peer),
                },
                Err(runtime::ETIMEDOUT),
            ),
        ];
        for (what, rel, want) in cases {
            u.dev.st.borrow_mut().tx_rel = rel;
            if run(u.shared.send_eth_tx_status(&eth, 200)) != want {
                return Err(what);
            }
        }
        u.dev.st.borrow_mut().tx_rel = TxRel::default();
        {
            let g = run(u.shared.lock());
            ensure!(
                g.ack_frames.is_empty() && g.ack_status.is_empty(),
                "every ack id resolved or freed"
            );
            ensure!(
                g.link.last_ack_signal == Some(-65) && g.link.last_ack_ms.is_some(),
                "last_ack_signal from the last ACK"
            );
        }
        let before = run(u.shared.lock()).stats;
        ensure!(narf_net::iface::send_on(u.name, &eth).is_ok(), "plain send");
        let mut u = u;
        let f = u.tx_cons.try_recv().ok().flatten().ok_or("TX ring")?;
        ensure!(run(u.netdev.tx_one(&f)).is_ok(), "queued");
        pump(&u, 3);
        let g = run(u.shared.lock());
        ensure!(
            g.stats.tx_status_acked == before.tx_status_acked + 1 && g.ack_status.is_empty(),
            "a plain frame's status only counts"
        );
        drop(g);

        // Purged before TCL → dropped.
        let id = {
            let mut g = run(u.shared.lock());
            g.stop_queues(TxQueues::vif_queues(), reason::DRIVER);
            let id = g.tx_enqueue_status(eth.clone()).map_err(|_| "enqueue")?;
            g.purge_txqs();
            g.wake_queues(TxQueues::vif_queues(), reason::DRIVER);
            id
        };
        ensure!(
            run(u.shared.lock())
                .ack_status
                .pop_front()
                .is_some_and(|(i, s)| i == id && s == TxStatus::DROPPED),
            "purged: dropped"
        );
        // Interface down with a frame waiting → dropped.
        let id = {
            let mut g = run(u.shared.lock());
            g.stop_queues(TxQueues::vif_queues(), reason::DRIVER);
            g.tx_enqueue_status(eth.clone()).map_err(|_| "enqueue")?
        };
        ensure!(narf_net::iface::set_link_state(u.name, false), "down");
        pump(&u, 1);
        let mut g = run(u.shared.lock());
        ensure!(
            g.ack_status
                .pop_front()
                .is_some_and(|(i, s)| i == id && s == TxStatus::DROPPED)
                && g.ack_frames.is_empty(),
            "interface down: dropped"
        );
        ensure!(
            g.tx_enqueue_status(eth.clone()) == Err(runtime::ENOTCONN) && g.ack_frames.is_empty(),
            "no station: refused, ack id freed"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_int_tx_status);

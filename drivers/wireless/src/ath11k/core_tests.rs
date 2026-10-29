//! Core bring-up tests: FW_READY → QMI firmware start → CE → HTC → WMI
//! READY (`core.rs`, Linux `core.c::ath11k_core_qmi_firmware_ready` /
//! `ath11k_core_start`).
//!
//! [`Fw`] is a scripted WCN6855 target at the HTC/WMI level: it answers
//! the frames the host posts (CONNECT_SERVICE, SETUP_COMPLETE_EX, WMI
//! INIT, SET_HW_MODE) the way the firmware does, with knobs to withhold
//! or corrupt each answer. It runs behind two transports:
//!
//! - [`FakeHif`] — records every HIF call in a shared trace (with the
//!   QMI fake and the DP hooks), so the exact Linux order is asserted;
//! - the real [`CeHif`] over `ce_tests`' `FakeChip` — the frames go
//!   through the real CE rings in DMA32 memory, the target consumes the
//!   source descriptors and answers into posted RX buffers.
//!
//! Expected frames are literals hand-derived from Linux (`htc.c`
//! builders, `wmi.c::ath11k_init_cmd_send` via `wmi_tests`' WCN6855
//! resource-config golden), never re-encoded with the code under test.

#![cfg(target_arch = "x86_64")]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::future::Future;
use core::pin::pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

use narf_kernel_test::{kernel_test_in, TestResult};

use super::ce::{self, CeIrq, CeMsi, CeRecv, HOST_CE_CONFIG_QCA6390};
use super::ce_tests::FakeChip;
use super::core::*;
use super::hal::TransportError;
use super::hal_tests::{wcn6855, QCA6390_SHADOW_REG_V2, WCN6855_SHADOW_REG_V2};
use super::htc::{self, conn_status, msg_id, svc_id, HtcHdr};
use super::hw::{HwRev, MSI_CONFIG_QCA6390};
use super::power::ChipIo;
use super::qmi_wlfw::ATH11K_FIRMWARE_MODE_NORMAL;
use super::wlfw::{self, WlfwError};
use super::wmi::{self, hw_mode, WmiCmd, WmiEvent};
use super::wmi_tests::{
    cat, event, ext_fixed, ext_rule, frame, le, service_ready_fixed, svc_rdy_ext_payload, tlv,
    wcn6855_resource_config_words,
};

macro_rules! ensure {
    ($c:expr, $m:literal) => {
        if !$c {
            return TestResult::Fail($m);
        }
    };
}

fn run<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..100_000 {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
    panic!("core test future did not complete");
}

/// Run `f` with the Wi-Fi diag latch cleared; return what it latched
/// (step, detail, stage) and restore the previous diag state.
fn latched<R>(f: impl FnOnce() -> R) -> (R, u32, u32, narf_memory::diag::WifiStage) {
    use narf_memory::diag;
    let s = diag::snapshot();
    diag::__reset_for_test();
    let r = f();
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
    (r, got.wifi_err, got.wifi_detail, got.wifi_stage)
}

// ── trace ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
enum Ev {
    QmiStart { mode: u32, shadow: Vec<u32> },
    QmiStop,
    InitPipes,
    HifStart,
    HifStop,
    PollAll,
    Tx { pipe: u8, tid: u16, frame: Vec<u8> },
    Hook(&'static str),
}

type Trace = Rc<RefCell<Vec<Ev>>>;

/// Trace without the TX payloads, for order checks.
fn shape(t: &Trace) -> Vec<Ev> {
    t.borrow()
        .iter()
        .map(|e| match e {
            Ev::Tx { pipe, tid, .. } => Ev::Tx {
                pipe: *pipe,
                tid: *tid,
                frame: Vec::new(),
            },
            Ev::QmiStart { mode, .. } => Ev::QmiStart {
                mode: *mode,
                shadow: Vec::new(),
            },
            o => o.clone(),
        })
        .collect()
}

fn tx(pipe: u8, tid: u16) -> Ev {
    Ev::Tx {
        pipe,
        tid,
        frame: Vec::new(),
    }
}

fn qmi_start() -> Ev {
    Ev::QmiStart {
        mode: ATH11K_FIRMWARE_MODE_NORMAL,
        shadow: Vec::new(),
    }
}

// ── QMI fake ──────────────────────────────────────────────────────

struct FakeQmi {
    trace: Trace,
    fail: Option<WlfwError>,
}

impl QmiFw for FakeQmi {
    async fn firmware_start(&mut self, mode: u32, shadow_reg_v2: &[u32]) -> Result<(), WlfwError> {
        self.trace.borrow_mut().push(Ev::QmiStart {
            mode,
            shadow: shadow_reg_v2.to_vec(),
        });
        match self.fail {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
    async fn firmware_stop(&mut self) {
        self.trace.borrow_mut().push(Ev::QmiStop);
    }
}

// ── scripted firmware ─────────────────────────────────────────────

pub(super) const HTT_EID: u8 = 1;
pub(super) const WMI_EID: u8 = 2;
/// Control and HTT answers arrive on CE1, WMI on CE2, pktlog on CE5.
pub(super) const CTRL_DL: u32 = 1;
pub(super) const WMI_DL: u32 = 2;

/// WMI_TLV_SERVICE_EXT2_MSG (220): SERVICE_AVAILABLE segment word 2
/// bit 28. WMI_TLV_SERVICE_REG_CC_EXT_EVENT_SUPPORT (281): trailing
/// ARRAY_UINT32 word 0 bit 25.
const EXT2_MSG_SEG_W2: u32 = 1 << 28;
const REG_CC_EXT_W0: u32 = 1 << 25;

#[derive(Clone)]
pub(super) struct Script {
    pub(super) credits: u16,
    pub(super) credit_size: u16,
    pub(super) send_ready: bool,
    /// READY only shows up once the host polls every CE.
    pub(super) ready_on_poll: bool,
    pub(super) htt_reply: bool,
    pub(super) htt_status: u8,
    pub(super) wmi_reply: bool,
    pub(super) wmi_status: u8,
    pub(super) svc_ready: bool,
    pub(super) advertise_ext2: bool,
    pub(super) send_ext2: bool,
    pub(super) reg_cc_ext: bool,
    /// Replace SERVICE_READY_EXT with this payload.
    pub(super) ext_override: Option<Vec<u8>>,
    pub(super) ready_event: bool,
    /// READY event without its READY TLV.
    pub(super) ready_missing_tlv: bool,
    /// Credit for INIT returned with the READY event.
    pub(super) return_init_credit: bool,
    /// Extra frames sent right after SETUP_COMPLETE_EX's events.
    pub(super) extra: Vec<(u32, Vec<u8>)>,
    /// Answer HTT VERSION_REQ (msg type 0) with VERSION_CONF.
    pub(super) htt_version_conf: bool,
}

impl Default for Script {
    fn default() -> Self {
        Script {
            credits: 15,
            credit_size: 1792,
            send_ready: true,
            ready_on_poll: false,
            htt_reply: true,
            htt_status: conn_status::SUCCESS,
            wmi_reply: true,
            wmi_status: conn_status::SUCCESS,
            svc_ready: true,
            advertise_ext2: true,
            send_ext2: true,
            reg_cc_ext: true,
            ext_override: None,
            ready_event: true,
            ready_missing_tlv: false,
            return_init_credit: true,
            extra: Vec::new(),
            htt_version_conf: true,
        }
    }
}

/// READY: 00:03:7f:12:34:56 (`wmi_ready_event`, wmi_tests' layout).
pub(super) const FW_MAC: [u8; 6] = [0x00, 0x03, 0x7f, 0x12, 0x34, 0x56];

fn ready_fixed() -> Vec<u8> {
    le(&[
        1,
        2,
        3,
        4,
        5,
        6,
        0x127f_0300,
        0x0000_5634,
        0,
        0,
        0,
        512,
        0,
        0x1000,
        0xcafe_babe,
    ])
}

fn service_ready_event() -> Vec<u8> {
    let mut bm = vec![0u32; 32];
    bm[0] = 0b0101;
    event(
        wmi::WMI_SERVICE_READY_EVENTID,
        &[
            tlv(wmi::WMI_TAG_SERVICE_READY_EVENT, &service_ready_fixed(2)),
            tlv(wmi::WMI_TAG_ARRAY_UINT32, &le(&bm)),
        ],
    )
}

fn service_available_event(ext2: bool, reg_cc_ext: bool) -> Vec<u8> {
    let w2 = if ext2 { EXT2_MSG_SEG_W2 } else { 0 };
    let a0 = if reg_cc_ext { REG_CC_EXT_W0 } else { 0 };
    event(
        wmi::WMI_SERVICE_AVAILABLE_EVENTID,
        &[
            tlv(wmi::WMI_TAG_SERVICE_AVAILABLE_EVENT, &le(&[0, 0, 0, w2, 0])),
            tlv(wmi::WMI_TAG_ARRAY_UINT32, &le(&[a0, 0, 0, 0])),
        ],
    )
}

fn ext2_event() -> Vec<u8> {
    event(
        wmi::WMI_SERVICE_READY_EXT2_EVENTID,
        &[tlv(
            wmi::WMI_TAG_ARRAY_STRUCT,
            &tlv(wmi::WMI_TAG_DMA_RING_CAPABILITIES, &le(&[1, 1, 8, 1024, 8])),
        )],
    )
}

fn reg_ext_event() -> Vec<u8> {
    event(
        wmi::WMI_REG_CHAN_LIST_CC_EXT_EVENTID,
        &[
            tlv(
                wmi::WMI_TAG_REG_CHAN_LIST_CC_EXT_EVENT,
                &le(&ext_fixed(1, 1, 0, 0)),
            ),
            tlv(
                wmi::WMI_TAG_ARRAY_STRUCT,
                &cat(&[
                    ext_rule(2402, 2482, 40, 20, 0),
                    ext_rule(5170, 5730, 160, 23, 0),
                ]),
            ),
        ],
    )
}

/// An HTT T2H message (`HTT_T2H_MSG_TYPE_VERSION_CONF` = 0 in the low
/// byte) — opaque to the core, which only routes it.
const HTT_VERSION_CONF: [u8; 4] = [0x00, 0x51, 0x03, 0x00];

pub(super) struct Fw {
    pub(super) s: Script,
    pub(super) out: VecDeque<(u32, Vec<u8>)>,
    pub(super) started: bool,
    ready_sent: bool,
    /// Host→target frames as `(pipe, transfer_id, bytes)`.
    pub(super) seen: Vec<(u8, u16, Vec<u8>)>,
}

impl Fw {
    pub(super) fn new(s: Script) -> Self {
        Fw {
            s,
            out: VecDeque::new(),
            started: false,
            ready_sent: false,
            seen: Vec::new(),
        }
    }

    fn ctrl(&mut self, payload: &[u8]) {
        self.out
            .push_back((CTRL_DL, htc::target_frame(0, payload, &[])));
    }

    fn wmi(&mut self, ev: Vec<u8>, trailer: &[u8]) {
        self.out
            .push_back((WMI_DL, htc::target_frame(WMI_EID, &ev, trailer)));
    }

    fn send_ready(&mut self) {
        if !self.ready_sent {
            self.ready_sent = true;
            self.ctrl(&htc::ready_msg(self.s.credits, self.s.credit_size, 8));
        }
    }

    /// RX buffers posted: the target sends HTC READY.
    pub(super) fn on_start(&mut self) {
        self.started = true;
        if self.s.send_ready && !self.s.ready_on_poll {
            self.send_ready();
        }
    }

    fn on_poll(&mut self) {
        if self.s.send_ready && self.s.ready_on_poll {
            self.send_ready();
        }
    }

    pub(super) fn on_tx(&mut self, pipe: u8, tid: u16, f: &[u8]) {
        self.seen.push((pipe, tid, f.to_vec()));
        let Some(h) = HtcHdr::parse(f) else { return };
        let p = &f[8..];
        if h.eid == 0 && p.len() >= 4 {
            let id = u16::from_le_bytes([p[0], p[1]]);
            let svc = u16::from_le_bytes([p[2], p[3]]);
            match id {
                msg_id::CONNECT_SERVICE if svc == svc_id::HTT_DATA_MSG => {
                    if self.s.htt_reply {
                        let r =
                            htc::connect_service_resp_msg(svc, self.s.htt_status, HTT_EID, 1024, 0);
                        self.ctrl(&r);
                    }
                }
                msg_id::CONNECT_SERVICE if svc == svc_id::WMI_CONTROL => {
                    if self.s.wmi_reply {
                        let r =
                            htc::connect_service_resp_msg(svc, self.s.wmi_status, WMI_EID, 2048, 0);
                        self.ctrl(&r);
                    }
                }
                msg_id::SETUP_COMPLETE_EX => {
                    if self.s.svc_ready {
                        self.wmi(service_ready_event(), &[]);
                        let a = service_available_event(self.s.advertise_ext2, self.s.reg_cc_ext);
                        self.wmi(a, &[]);
                        let ext = match &self.s.ext_override {
                            Some(p) => {
                                let mut v = le(&[wmi::WMI_SERVICE_READY_EXT_EVENTID]);
                                v.extend_from_slice(p);
                                v
                            }
                            None => {
                                let mut v = le(&[wmi::WMI_SERVICE_READY_EXT_EVENTID]);
                                v.extend_from_slice(&svc_rdy_ext_payload());
                                v
                            }
                        };
                        self.wmi(ext, &[]);
                        if self.s.send_ext2 {
                            self.wmi(ext2_event(), &[]);
                        }
                    }
                    for (pipe, fr) in core::mem::take(&mut self.s.extra) {
                        self.out.push_back((pipe, fr));
                    }
                }
                _ => {}
            }
        } else if h.eid == WMI_EID && p.len() >= 4 {
            let cmd = u32::from_le_bytes([p[0], p[1], p[2], p[3]]) & 0x00ff_ffff;
            let credit = htc::credit_report_trailer(&[(WMI_EID, 1)]);
            if cmd == wmi::WMI_INIT_CMDID {
                let tr: &[u8] = if self.s.return_init_credit {
                    &credit
                } else {
                    &[]
                };
                if self.s.ready_event {
                    let ev = if self.s.ready_missing_tlv {
                        event(wmi::WMI_READY_EVENTID, &[])
                    } else {
                        event(
                            wmi::WMI_READY_EVENTID,
                            &[tlv(wmi::WMI_TAG_READY_EVENT, &ready_fixed())],
                        )
                    };
                    self.wmi(ev, tr);
                    if self.s.reg_cc_ext {
                        self.wmi(reg_ext_event(), &[]);
                    }
                } else if !tr.is_empty() {
                    // Credit report alone (trailer-only frame).
                    self.out
                        .push_back((WMI_DL, htc::target_frame(WMI_EID, &[], tr)));
                }
            } else if cmd == wmi::WMI_PDEV_SET_HW_MODE_CMDID {
                // Credit back + the (unsolicited for the core) response.
                let ev = event(
                    wmi::WMI_PDEV_SET_HW_MODE_RESP_EVENTID,
                    &[tlv(0x0201, &le(&[0, 1, 0]))],
                );
                self.wmi(ev, &credit);
            }
        } else if h.eid == HTT_EID && p.first() == Some(&0) && self.s.htt_version_conf {
            self.out
                .push_back((CTRL_DL, htc::target_frame(HTT_EID, &HTT_VERSION_CONF, &[])));
        }
    }
}

// ── fake HIF ──────────────────────────────────────────────────────

struct FakeHif {
    trace: Trace,
    fw: Fw,
    rx: VecDeque<(u32, Vec<u8>)>,
    now: u64,
    fail_init_pipes: bool,
    /// CE refuses sends on this pipe (`-ENOBUFS`).
    fail_send_pipe: Option<u8>,
}

impl FakeHif {
    fn new(trace: Trace, s: Script) -> Self {
        FakeHif {
            trace,
            fw: Fw::new(s),
            rx: VecDeque::new(),
            now: 0,
            fail_init_pipes: false,
            fail_send_pipe: None,
        }
    }
    fn collect(&mut self) {
        while let Some(f) = self.fw.out.pop_front() {
            self.rx.push_back(f);
        }
    }
}

impl Hif for FakeHif {
    fn shadow_reg_v2(&self) -> Vec<u32> {
        WCN6855_SHADOW_REG_V2.to_vec()
    }
    fn init_pipes(&mut self) -> Result<(), TransportError> {
        self.trace.borrow_mut().push(Ev::InitPipes);
        if self.fail_init_pipes {
            return Err(TransportError::new(ce::step::INIT_RING, 3, 22));
        }
        Ok(())
    }
    fn start(&mut self) {
        self.trace.borrow_mut().push(Ev::HifStart);
        self.fw.on_start();
        self.collect();
    }
    fn stop(&mut self) {
        self.trace.borrow_mut().push(Ev::HifStop);
    }
    fn send(&mut self, pipe: u8, frame: &[u8], transfer_id: u16) -> Result<(), TransportError> {
        if self.fail_send_pipe == Some(pipe) {
            return Err(TransportError::new(ce::step::RING_FULL, pipe as u32, 105));
        }
        self.trace.borrow_mut().push(Ev::Tx {
            pipe,
            tid: transfer_id,
            frame: frame.to_vec(),
        });
        self.fw.on_tx(pipe, transfer_id, frame);
        self.collect();
        Ok(())
    }
    fn take_rx(&mut self) -> Option<(u32, Vec<u8>)> {
        self.rx.pop_front()
    }
    fn recv_kind(&self, pipe: u32) -> Option<CeRecv> {
        HOST_CE_CONFIG_QCA6390.get(pipe as usize)?.recv_cb
    }
    fn poll_all(&mut self) {
        self.trace.borrow_mut().push(Ev::PollAll);
        self.fw.on_poll();
        self.collect();
    }
    async fn wait(&mut self, ms: u32) {
        self.now += ms as u64;
    }
    fn now_ms(&self) -> u64 {
        self.now
    }
}

// ── DP hooks recorder ─────────────────────────────────────────────

struct RecHooks {
    trace: Trace,
    htt_reply: Option<Vec<u8>>,
}

impl<H: Hif, Q: QmiFw> CoreHooks<H, Q> for RecHooks {
    fn dp_alloc(&mut self, core: &mut Ath11kCore<H, Q>) -> Result<(), TransportError> {
        // Before core_start: no endpoint yet.
        let _ = core.htt_ep.is_none();
        self.trace.borrow_mut().push(Ev::Hook("dp_alloc"));
        Ok(())
    }
    fn pdev_reo_setup(&mut self, core: &mut Ath11kCore<H, Q>) -> Result<(), TransportError> {
        let _ = core.svc_ext.is_some();
        self.trace.borrow_mut().push(Ev::Hook("reo_setup"));
        Ok(())
    }
    async fn htt_ver_req(&mut self, core: &mut Ath11kCore<H, Q>) -> Result<(), TransportError> {
        self.trace.borrow_mut().push(Ev::Hook("htt_ver_req"));
        // HTT_H2T_MSG_TYPE_VERSION_REQ (0), as the DP layer will send it.
        core.htt_send(&[0, 0, 0, 0])?;
        self.htt_reply = core.wait_htt(3000).await;
        Ok(())
    }
    async fn pdev_create(&mut self, _core: &mut Ath11kCore<H, Q>) -> Result<(), TransportError> {
        self.trace.borrow_mut().push(Ev::Hook("pdev_create"));
        Ok(())
    }
    fn irq_enable(&mut self, _core: &mut Ath11kCore<H, Q>) {
        self.trace.borrow_mut().push(Ev::Hook("irq_enable"));
    }
}

pub(super) fn cfg() -> CoreConfig {
    CoreConfig::for_hw(&wcn6855()).expect("WCN6855 core config")
}

type Fake = Ath11kCore<FakeHif, FakeQmi>;

fn fake_core(s: Script) -> (Fake, Trace) {
    let trace: Trace = Rc::new(RefCell::new(Vec::new()));
    let hif = FakeHif::new(trace.clone(), s);
    let qmi = FakeQmi {
        trace: trace.clone(),
        fail: None,
    };
    let core = match Ath11kCore::new(hif, qmi, cfg()) {
        Ok(c) => c,
        Err(_) => panic!("Ath11kCore::new"),
    };
    (core, trace)
}

fn hooks(trace: &Trace) -> RecHooks {
    RecHooks {
        trace: trace.clone(),
        htt_reply: None,
    }
}

/// Bring a fake core up; (result, latched step, detail, stage).
fn bring_up(
    core: &mut Fake,
    h: &mut RecHooks,
) -> (
    Result<(), TransportError>,
    u32,
    u32,
    narf_memory::diag::WifiStage,
) {
    latched(|| run(core.qmi_firmware_ready(h)))
}

// ── goldens ───────────────────────────────────────────────────────

/// HTC header words: `eid | flags << 8 | len << 16`, `seq << 8`.
fn htc_hdr(eid: u32, flags: u32, len: u32, seq: u32) -> Vec<u32> {
    vec![eid | flags << 8 | len << 16, seq << 8]
}

/// CONNECT_SERVICE(HTT_DATA_MSG): seq 0, RECV_ALLOC 0 |
/// DISABLE_CREDIT_FLOW_CTRL (htc.c, only WMI control keeps credit flow).
fn golden_htt_connect() -> Vec<u8> {
    le(&[0x0008_0000, 0x0000_0000, 0x0300_0002, 0x0000_0008])
}

/// CONNECT_SERVICE(WMI_CONTROL): seq 1, RECV_ALLOC 1 (the single
/// shadow-register credit) << 8.
fn golden_wmi_connect() -> Vec<u8> {
    le(&[0x0008_0000, 0x0000_0100, 0x0100_0002, 0x0000_0100])
}

/// SETUP_COMPLETE_EX: seq 2, len 12, {5, flags 0 (credit flow), 0}.
fn golden_setup_complete() -> Vec<u8> {
    le(&[0x000c_0000, 0x0000_0200, 5, 0, 0])
}

/// WMI INIT on the WMI endpoint: HTC {eid 2, NEED_CREDIT_UPDATE, 332,
/// seq 0} + `wmi_cmd_hdr(1)` + wmi_init_cmd (abi zero, 0 chunks) +
/// the WCN6855 resource config (2 RF chains, REG_CC_EXT) + an empty
/// host-mem-chunk ARRAY_STRUCT; no hw-mode TLVs (single_pdev_only).
fn golden_init() -> Vec<u8> {
    let mut body = vec![0x004a_001c, 0, 0, 0, 0, 0, 0, 0];
    body.extend_from_slice(&wcn6855_resource_config_words());
    body.push(0x0012_0000);
    let mut v = le(&htc_hdr(2, 1, 332, 0));
    v.extend_from_slice(&frame(0x1, &body));
    v
}

/// SET_HW_MODE(DBS): HTC {eid 2, NEED_CREDIT_UPDATE, 20, seq 1} +
/// `wmi_cmd_hdr(0x401e)` + {tlv(0x203, 12), pdev_id SOC 0,
/// hw_mode_index DBS 1, num_band_to_mac 0}.
fn golden_set_hw_mode() -> Vec<u8> {
    let mut v = le(&htc_hdr(2, 1, 20, 1));
    v.extend_from_slice(&frame(0x401e, &[0x0203_000c, 0, 1, 0]));
    v
}

fn tx_frames(t: &Trace) -> Vec<(u8, u16, Vec<u8>)> {
    t.borrow()
        .iter()
        .filter_map(|e| match e {
            Ev::Tx { pipe, tid, frame } => Some((*pipe, *tid, frame.clone())),
            _ => None,
        })
        .collect()
}

// ── tests ─────────────────────────────────────────────────────────

fn smoke_ath11k_core_config_wcn6855() -> TestResult {
    let c = cfg();
    ensure!(c.fw_mode == ATH11K_FIRMWARE_MODE_NORMAL, "fw_mode NORMAL");
    ensure!(
        c.single_pdev_only && c.num_rxdma_per_pdev == 2 && c.max_radios == 3,
        "WCN6855 hw_params"
    );
    ensure!(c.num_vdevs == 4, "Linux QCA6390/WCN6855 four-vdev profile");
    ensure!(
        c.initial_hw_mode() == hw_mode::SINGLE,
        "wmi_attach: SINGLE (single_pdev_only, 2 rxdma)"
    );
    let h = c.htc();
    ensure!(
        h.wmi_ep_count == 1 && h.credit_flow && h.supports_shadow_regs,
        "htc: one WMI endpoint, credit flow, shadow regs"
    );
    ensure!(
        (
            c.htc_wait_ms,
            c.htc_conn_ms,
            c.service_ready_ms,
            c.wmi_send_ms
        ) == (1000, 1000, 5000, 3000),
        "Linux timeouts"
    );
    let q = HwRev::Qcn9074Hw10.params().expect("qcn9074 params");
    ensure!(
        CoreConfig::for_hw(&q).is_some_and(|c| c.max_radios == 1 && !c.single_pdev_only),
        "QCN9074 multi-pdev core config"
    );
    let q = HwRev::Qca6390Hw20.params().expect("qca6390 params");
    ensure!(
        CoreConfig::for_hw(&q).is_some_and(|cfg| cfg.num_vdevs == 4 && cfg.num_rxdma_per_pdev == 2),
        "QCA6390 native RX/DP shares the four-vdev core resource profile"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_core_config_wcn6855);

fn smoke_ath11k_core_bring_up_order_wcn6855() -> TestResult {
    let (mut core, trace) = fake_core(Script::default());
    let mut h = hooks(&trace);
    let (r, err, _, stage) = bring_up(&mut core, &mut h);
    ensure!(r.is_ok(), "bring-up succeeds");
    ensure!(err == 0, "nothing latched");
    ensure!(
        stage == narf_memory::diag::WifiStage::Commands,
        "stage commands after WMI READY"
    );
    ensure!(core.is_ready(), "state Ready");
    // The exact Linux order.
    let want = vec![
        qmi_start(),
        Ev::InitPipes,
        Ev::Hook("dp_alloc"),
        Ev::HifStart,
        tx(0, 0), // CONNECT HTT_DATA_MSG
        tx(0, 0), // CONNECT WMI_CONTROL
        tx(0, 0), // SETUP_COMPLETE_EX
        Ev::Hook("reo_setup"),
        tx(3, 2), // WMI INIT
        tx(3, 2), // PDEV_SET_HW_MODE(DBS)
        Ev::Hook("htt_ver_req"),
        tx(4, 1), // HTT VERSION_REQ on the HTT endpoint (CE4)
        Ev::Hook("pdev_create"),
        Ev::Hook("irq_enable"),
    ];
    ensure!(shape(&trace) == want, "Linux core start order");
    // QMI: the HAL's WCN6855 shadow list, mode NORMAL.
    match trace.borrow().first() {
        Some(Ev::QmiStart { mode, shadow }) => ensure!(
            *mode == 0 && shadow[..] == WCN6855_SHADOW_REG_V2,
            "firmware_start(NORMAL, WCN6855 shadow v2)"
        ),
        _ => return TestResult::Fail("first event is QMI firmware start"),
    }
    let f = tx_frames(&trace);
    ensure!(f[0].2 == golden_htt_connect(), "HTT connect golden");
    ensure!(f[1].2 == golden_wmi_connect(), "WMI connect golden");
    ensure!(f[2].2 == golden_setup_complete(), "setup complete golden");
    ensure!(f[3].2 == golden_init(), "WMI INIT golden");
    ensure!(f[4].2 == golden_set_hw_mode(), "SET_HW_MODE DBS golden");
    ensure!(
        f[5].2 == le(&[0x0004_0001, 0, 0]),
        "HTT VERSION_REQ: eid 1, no credit flag, len 4"
    );
    // What the firmware told us.
    ensure!(core.mac_addr == Some(FW_MAC), "MAC from WMI READY");
    let ready = core.ready.as_ref().unwrap();
    ensure!(
        ready.num_total_peers == 512 && ready.pktlog_defs_checksum == 0xcafe_babe,
        "READY fields"
    );
    ensure!(core.target_caps.num_rf_chains == 2, "rf chains");
    ensure!(core.target_caps.ht_cap_info == 0x19ef, "ht cap");
    ensure!(core.fw_build_vers == 0x0100_0042, "fw build");
    ensure!(
        core.svc_map.test(0) && core.svc_map.test(2) && !core.svc_map.test(1),
        "SERVICE_READY bitmap"
    );
    ensure!(
        core.svc_map.test(wmi::WMI_TLV_SERVICE_EXT2_MSG)
            && core
                .svc_map
                .test(wmi::WMI_TLV_SERVICE_REG_CC_EXT_EVENT_SUPPORT),
        "SERVICE_AVAILABLE ext / ext2 bits"
    );
    let ext = core.svc_ext.as_ref().unwrap();
    ensure!(
        core.preferred_hw_mode == hw_mode::DBS && ext.num_radios == 1,
        "ext: DBS preferred, one pdev"
    );
    ensure!(
        ext.pdevs.len() == 1 && ext.pdevs[0].supported_bands == wmi::WMI_HOST_WLAN_2G_5G_CAP,
        "pdev band caps for the mac layer"
    );
    ensure!(
        ext.pdevs[0].band_5g.max_bw_supported == 3 && ext.pdevs[0].vht_cap == 0x339b_79fa,
        "5G VHT caps"
    );
    ensure!(
        core.dma_ring_caps.len() == 1 && core.dma_ring_caps[0].min_buf_sz == 2048,
        "EXT dma ring caps win over EXT2's"
    );
    ensure!(
        core.seen
            == seen::SERVICE_READY
                | seen::SERVICE_AVAILABLE
                | seen::SERVICE_READY_EXT
                | seen::EXT2_EXPECTED
                | seen::SERVICE_READY_EXT2
                | seen::READY
                | seen::REG_CHAN_LIST,
        "every bring-up event seen"
    );
    let reg = core.reg_info.as_ref().unwrap();
    ensure!(
        reg.alpha2 == *b"DE" && reg.rules_2ghz.len() == 1,
        "regulatory channel list kept"
    );
    // Endpoints.
    let w = core.wmi_ep.unwrap();
    ensure!(
        w.eid == 2 && w.ul_pipe == 3 && w.dl_pipe == 2 && w.max_msg_len == 2048 && w.credit_flow,
        "WMI endpoint"
    );
    let t = core.htt_ep.unwrap();
    ensure!(
        t.eid == 1 && t.ul_pipe == 4 && !t.credit_flow,
        "HTT endpoint"
    );
    // 1 credit: INIT takes it, READY's trailer returns it, HW_MODE takes
    // it, the HW_MODE response returns it (processed by the HTT wait).
    ensure!(core.htc.endpoints[2].tx_credits == 1, "WMI credits balance");
    ensure!(core.stats.credit_reports == 2, "two credit reports");
    // REG event and the SET_HW_MODE response are in the stream.
    let e1 = core.take_event().unwrap();
    let e2 = core.take_event().unwrap();
    ensure!(
        e1.id == wmi::WMI_REG_CHAN_LIST_CC_EXT_EVENTID
            && e2.id == wmi::WMI_PDEV_SET_HW_MODE_RESP_EVENTID,
        "unsolicited events queued in order"
    );
    ensure!(
        matches!(wmi::decode_event(&e1.frame), Ok(WmiEvent::RegChanList(_))),
        "queued frame decodes"
    );
    ensure!(core.take_event().is_none(), "nothing else");
    ensure!(
        h.htt_reply.as_deref() == Some(&HTT_VERSION_CONF[..]),
        "HTT reply routed to the DP hook (header stripped)"
    );
    ensure!(core.hif.now == 0, "no waiting on a prompt firmware");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_core_bring_up_order_wcn6855
);

/// Without EXT2_MSG advertised, SERVICE_READY_EXT completes service
/// ready; with NoDp nothing else is sent.
fn smoke_ath11k_core_ext_only_no_dp() -> TestResult {
    let (mut core, trace) = fake_core(Script {
        advertise_ext2: false,
        send_ext2: false,
        reg_cc_ext: false,
        ..Script::default()
    });
    let (r, err, _, _) = latched(|| run(core.qmi_firmware_ready(&mut NoDp)));
    ensure!(r.is_ok() && err == 0, "ext-only bring-up");
    ensure!(
        core.seen & seen::SERVICE_READY_EXT2 == 0 && core.seen & seen::EXT2_EXPECTED == 0,
        "no EXT2 awaited"
    );
    let f = tx_frames(&trace);
    ensure!(f.len() == 5, "3 HTC control + INIT + HW_MODE, no HTT");
    // No REG_CC_EXT advertised ⇒ host_service_flags 0 in INIT
    // (resource config word 69 → byte 8 + 4 + 32 + 276).
    ensure!(
        f[3].2[8 + 4 + 32 + 276..8 + 4 + 32 + 280] == [0, 0, 0, 0],
        "INIT without REG_CC_EXT"
    );
    ensure!(core.reg_info.is_none(), "no reg event");
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_core_ext_only_no_dp);

/// `ath11k_htc_wait_target`: no READY in 1 s ⇒ poll every CE, wait 1 s
/// more.
fn smoke_ath11k_core_htc_ready_after_poll() -> TestResult {
    let (mut core, trace) = fake_core(Script {
        ready_on_poll: true,
        ..Script::default()
    });
    let mut h = hooks(&trace);
    let (r, err, _, _) = bring_up(&mut core, &mut h);
    ensure!(r.is_ok() && err == 0, "READY found by the poll");
    let s = shape(&trace);
    ensure!(
        s[3] == Ev::HifStart && s[4] == Ev::PollAll && s[5] == tx(0, 0),
        "poll after the first second, then connect"
    );
    ensure!(core.hif.now == 1000, "waited exactly 1 s");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_core_htc_ready_after_poll
);

/// A failure after firmware start: (step, detail, errno) + the unwind.
fn expect_fail(
    s: Script,
    step: u32,
    errno: i32,
) -> Result<(Fake, Trace, u32, TransportError), &'static str> {
    let (mut core, trace) = fake_core(s);
    let mut h = hooks(&trace);
    let (r, err, detail, stage) = bring_up(&mut core, &mut h);
    let e = r.err().ok_or("expected failure")?;
    if e.step != step || err != step {
        return Err("wrong step latched");
    }
    if e.errno != errno {
        return Err("wrong errno");
    }
    if e.detail != detail {
        return Err("latched detail differs");
    }
    if stage == narf_memory::diag::WifiStage::Commands && step != step::WMI_SEND_CREDITS {
        return Err("stage advanced on failure");
    }
    if core.state != CoreState::Failed(e) {
        return Err("state Failed");
    }
    // Linux unwind: hif_stop (once started), then firmware_stop.
    let sh = shape(&trace);
    let n = sh.len();
    if n < 2 || sh[n - 2] != Ev::HifStop || sh[n - 1] != Ev::QmiStop {
        return Err("unwind: HifStop then QmiStop");
    }
    Ok((core, trace, detail, e))
}

fn smoke_ath11k_core_htc_ready_timeout() -> TestResult {
    match expect_fail(
        Script {
            send_ready: false,
            ..Script::default()
        },
        step::HTC_READY_TIMEOUT,
        110,
    ) {
        Ok((core, trace, _, _)) => {
            ensure!(core.hif.now == 2000, "1 s + poll + 1 s");
            ensure!(
                shape(&trace).contains(&Ev::PollAll),
                "polled before giving up"
            );
            ensure!(tx_frames(&trace).is_empty(), "nothing sent");
            TestResult::Pass
        }
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_core_htc_ready_timeout
);

fn smoke_ath11k_core_htc_bad_ready() -> TestResult {
    match expect_fail(
        Script {
            credits: 0,
            ..Script::default()
        },
        step::HTC_BAD_READY,
        70,
    ) {
        Ok((_, _, detail, _)) => {
            ensure!(detail == 11 << 16, "BadReady detail");
            TestResult::Pass
        }
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_core_htc_bad_ready);

fn smoke_ath11k_core_service_connect_failures() -> TestResult {
    // HTT refused (status FAILED) ⇒ -EPROTO.
    match expect_fail(
        Script {
            htt_status: conn_status::FAILED,
            ..Script::default()
        },
        step::HTT_CONNECT,
        71,
    ) {
        Ok((_, trace, detail, _)) => {
            ensure!(detail == 13 << 16 | 2, "refused, status 2");
            ensure!(tx_frames(&trace).len() == 1, "only the HTT connect");
        }
        Err(m) => return TestResult::Fail(m),
    }
    // HTT silent ⇒ 1 s timeout.
    match expect_fail(
        Script {
            htt_reply: false,
            ..Script::default()
        },
        step::HTT_CONNECT_TIMEOUT,
        110,
    ) {
        Ok((core, _, detail, _)) => {
            ensure!(
                detail == svc_id::HTT_DATA_MSG as u32,
                "timeout detail = svc"
            );
            ensure!(core.hif.now == 1000, "1 s");
        }
        Err(m) => return TestResult::Fail(m),
    }
    // WMI refused (NO_RESOURCES).
    match expect_fail(
        Script {
            wmi_status: conn_status::NO_RESOURCES,
            ..Script::default()
        },
        step::WMI_CONNECT,
        71,
    ) {
        Ok((core, trace, detail, _)) => {
            ensure!(detail == 13 << 16 | 3, "status 3");
            ensure!(core.htt_ep.is_some() && core.wmi_ep.is_none(), "HTT only");
            ensure!(tx_frames(&trace).len() == 2, "no SETUP_COMPLETE");
        }
        Err(m) => return TestResult::Fail(m),
    }
    // WMI silent.
    match expect_fail(
        Script {
            wmi_reply: false,
            ..Script::default()
        },
        step::WMI_CONNECT_TIMEOUT,
        110,
    ) {
        Ok((_, _, detail, _)) => {
            ensure!(detail == svc_id::WMI_CONTROL as u32, "svc");
        }
        Err(m) => return TestResult::Fail(m),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_core_service_connect_failures
);

fn smoke_ath11k_core_service_ready_failures() -> TestResult {
    // Nothing after SETUP_COMPLETE_EX ⇒ 5 s.
    match expect_fail(
        Script {
            svc_ready: false,
            ..Script::default()
        },
        step::SERVICE_READY_TIMEOUT,
        110,
    ) {
        Ok((core, trace, detail, _)) => {
            ensure!(detail == 0, "nothing seen");
            ensure!(core.hif.now == 5000, "5 s");
            ensure!(tx_frames(&trace).len() == 3, "no INIT");
        }
        Err(m) => return TestResult::Fail(m),
    }
    // EXT2 advertised but never sent: EXT alone does not complete.
    match expect_fail(
        Script {
            send_ext2: false,
            ..Script::default()
        },
        step::SERVICE_READY_TIMEOUT,
        110,
    ) {
        Ok((_, _, detail, _)) => ensure!(
            detail
                == seen::SERVICE_READY
                    | seen::SERVICE_AVAILABLE
                    | seen::SERVICE_READY_EXT
                    | seen::EXT2_EXPECTED,
            "EXT2 awaited"
        ),
        Err(m) => return TestResult::Fail(m),
    }
    // A SERVICE_READY_EXT whose TLV overruns: decode failure, at once.
    match expect_fail(
        Script {
            ext_override: Some(le(&[
                (wmi::WMI_TAG_SERVICE_READY_EXT_EVENT as u32) << 16 | 200
            ])),
            ..Script::default()
        },
        step::SERVICE_READY_DECODE,
        22,
    ) {
        Ok((core, _, detail, _)) => {
            ensure!(
                detail == wmi::WMI_SERVICE_READY_EXT_EVENTID << 16 | 22,
                "event id + EINVAL"
            );
            ensure!(core.hif.now == 0, "no 5 s wait");
            ensure!(core.stats.wmi_bad_events == 1, "counted");
        }
        Err(m) => return TestResult::Fail(m),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_core_service_ready_failures
);

fn smoke_ath11k_core_ready_failures() -> TestResult {
    match expect_fail(
        Script {
            ready_event: false,
            ..Script::default()
        },
        step::READY_TIMEOUT,
        110,
    ) {
        Ok((core, trace, detail, _)) => {
            ensure!(detail & seen::READY == 0, "READY not seen");
            ensure!(core.mac_addr.is_none(), "no MAC");
            ensure!(core.hif.now == 5000, "5 s");
            ensure!(tx_frames(&trace).len() == 4, "INIT sent, no HW_MODE");
        }
        Err(m) => return TestResult::Fail(m),
    }
    match expect_fail(
        Script {
            ready_missing_tlv: true,
            ..Script::default()
        },
        step::READY_DECODE,
        71,
    ) {
        Ok((core, _, _, _)) => ensure!(core.mac_addr.is_none(), "no MAC"),
        Err(m) => return TestResult::Fail(m),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_core_ready_failures);

/// The INIT credit never comes back: SET_HW_MODE waits 3 s for credits
/// (`ath11k_wmi_cmd_send` → `-EAGAIN`).
fn smoke_ath11k_core_credit_starvation() -> TestResult {
    match expect_fail(
        Script {
            return_init_credit: false,
            ..Script::default()
        },
        step::WMI_SEND_CREDITS,
        11,
    ) {
        Ok((core, trace, detail, _)) => {
            ensure!(detail == wmi::WMI_PDEV_SET_HW_MODE_CMDID, "detail = cmd id");
            ensure!(core.mac_addr == Some(FW_MAC), "READY did arrive");
            ensure!(core.hif.now == 3000, "3 s credit wait");
            ensure!(core.stats.credit_waits >= 3000 / 25, "waited in slices");
            ensure!(tx_frames(&trace).len() == 4, "HW_MODE never posted");
            ensure!(core.htc.endpoints[2].tx_credits == 0, "no credits");
        }
        Err(m) => return TestResult::Fail(m),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_core_credit_starvation
);

/// Unexpected traffic during bring-up is handled like Linux: unknown
/// events queued (logged and dropped by Linux's switch), frames for an
/// unconnected endpoint dropped, malformed HTC dropped, pktlog (CE5)
/// straight to the HTT queue; the bring-up still completes.
fn smoke_ath11k_core_unexpected_traffic() -> TestResult {
    let temp = event(
        wmi::WMI_PDEV_TEMPERATURE_EVENTID,
        &[tlv(wmi::WMI_TAG_PDEV_TEMPERATURE_EVENT, &le(&[45, 0]))],
    );
    let (mut core, trace) = fake_core(Script {
        extra: vec![
            (WMI_DL, htc::target_frame(WMI_EID, &le(&[0x00ab_cdef]), &[])),
            (WMI_DL, htc::target_frame(WMI_EID, &temp, &[])),
            (CTRL_DL, htc::target_frame(5, &[1, 2, 3, 4], &[])),
            (CTRL_DL, vec![0, 0, 0xff]),
            (5, vec![0xaa, 0xbb]),
            (CTRL_DL, htc::target_frame(0, &htc::ready_msg(1, 1, 1), &[])),
        ],
        htt_version_conf: false,
        ..Script::default()
    });
    let (r, err, _, _) = latched(|| run(core.qmi_firmware_ready(&mut NoDp)));
    ensure!(r.is_ok() && err == 0, "bring-up unaffected");
    ensure!(
        core.stats.htc_rx_errors == 2,
        "unconnected eid 5 + short frame dropped"
    );
    ensure!(
        core.stats.htc_unsolicited == 0,
        "late READY stored, not waited on"
    );
    ensure!(core.take_htt() == Some(vec![0xaa, 0xbb]), "CE5 → HTT queue");
    let _ = tx_frames(&trace);
    // Queue: unknown 0xabcdef, temperature, REG ext, HW_MODE resp.
    let got = run(core.wait_event(wmi::WMI_PDEV_TEMPERATURE_EVENTID, 0));
    let t = match got {
        Ok(e) => e,
        Err(_) => return TestResult::Fail("temperature event queued"),
    };
    ensure!(
        matches!(wmi::decode_event(&t.frame), Ok(WmiEvent::PdevTemperature(p)) if p.temp == 45),
        "temperature decodes"
    );
    let ids: Vec<u32> = core.queued_event_ids();
    ensure!(
        ids == [
            0x00ab_cdef,
            wmi::WMI_REG_CHAN_LIST_CC_EXT_EVENTID,
            wmi::WMI_PDEV_SET_HW_MODE_RESP_EVENTID
        ],
        "others stay queued in order"
    );
    // wait_event for something absent times out without latching.
    let now = core.hif.now;
    let (r, err, _, _) = latched(|| run(core.wait_event(wmi::WMI_SCAN_EVENTID, 100)));
    ensure!(
        matches!(r, Err(e) if e.step == step::EVENT_TIMEOUT && e.errno == 110),
        "EVENT_TIMEOUT"
    );
    ensure!(err == 0, "API timeouts are not latched");
    ensure!(core.hif.now == now + 100, "waited 100 ms");
    ensure!(
        run(core.next_event(0)).map(|e| e.id) == Some(0x00ab_cdef),
        "next_event"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_core_unexpected_traffic
);

fn smoke_ath11k_core_early_failures() -> TestResult {
    // QMI firmware_start fails (wlan_cfg): Linux returns without
    // firmware_stop; the wlfw step is latched as is.
    let (mut core, trace) = fake_core(Script::default());
    core.qmi.fail = Some(WlfwError::new(wlfw::step::WLAN_CFG, 2 << 16 | 0x1e, 22));
    let (r, err, detail, _) = latched(|| run(core.qmi_firmware_ready(&mut NoDp)));
    ensure!(
        matches!(r, Err(e) if e.step == wlfw::step::WLAN_CFG),
        "wlan_cfg failure returned"
    );
    ensure!(
        err == wlfw::step::WLAN_CFG && detail == 2 << 16 | 0x1e,
        "latched"
    );
    ensure!(shape(&trace) == [qmi_start()], "nothing after it");

    // ath11k_ce_init_pipes fails: firmware_stop, no hif_stop.
    let (mut core, trace) = fake_core(Script::default());
    core.hif.fail_init_pipes = true;
    let (r, err, _, _) = latched(|| run(core.qmi_firmware_ready(&mut NoDp)));
    ensure!(
        matches!(r, Err(e) if e.step == ce::step::INIT_RING) && err == ce::step::INIT_RING,
        "init_pipes failure"
    );
    ensure!(
        shape(&trace) == [qmi_start(), Ev::InitPipes, Ev::QmiStop],
        "firmware stopped, HIF never started"
    );

    // CE refuses the WMI INIT: -ENOBUFS is not retried under credit
    // flow; the credit is given back.
    let (mut core, trace) = fake_core(Script::default());
    core.hif.fail_send_pipe = Some(3);
    let (r, err, detail, _) = latched(|| run(core.qmi_firmware_ready(&mut NoDp)));
    ensure!(
        matches!(r, Err(e) if e.step == step::WMI_SEND && e.errno == 105),
        "WMI_SEND -ENOBUFS"
    );
    ensure!(
        err == step::WMI_SEND && detail == wmi::WMI_INIT_CMDID,
        "latched cmd id"
    );
    ensure!(core.htc.endpoints[2].tx_credits == 1, "credit reverted");
    ensure!(core.hif.now == 0, "no retry");
    let sh = shape(&trace);
    ensure!(sh.ends_with(&[Ev::HifStop, Ev::QmiStop]), "unwind");
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_core_early_failures);

fn smoke_ath11k_core_api_negatives() -> TestResult {
    let (mut core, _) = fake_core(Script::default());
    let cmd = WmiCmd {
        cmd_id: wmi::WMI_INIT_CMDID,
        buf: vec![0; 4],
    };
    let r = run(core.wmi_cmd_send(&cmd));
    ensure!(
        matches!(r, Err(e) if e.step == step::NO_WMI_EP),
        "no WMI endpoint before connect"
    );
    ensure!(
        matches!(core.htt_send(&[0]), Err(e) if e.step == step::HTT_SEND),
        "no HTT endpoint"
    );
    ensure!(!core.is_ready() && core.state == CoreState::Idle, "idle");
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_core_api_negatives);

// ── the real CE transport under the core ──────────────────────────

static NOW: AtomicU64 = AtomicU64::new(0);

fn clock() -> u64 {
    NOW.load(Ordering::Relaxed)
}

fn noop() {}

struct ChipRef<'a>(&'a FakeChip);

impl ChipIo for ChipRef<'_> {
    fn read32(&self, offset: u32) -> u32 {
        self.0.read32(offset)
    }
    fn write32(&self, offset: u32, value: u32) {
        self.0.write32(offset, value)
    }
    fn delay_ms(&self, _ms: u32) {}
    fn restore_window(&self) {}
}

/// The target side behind `FakeChip`: each wait it drains the host's
/// source rings (CE0 control, CE3 WMI, CE4 HTT), feeds [`Fw`], and
/// delivers its answers into the posted RX buffers.
struct FwIrq<'a> {
    chip: &'a FakeChip,
    fw: RefCell<Fw>,
}

impl CeIrq for FwIrq<'_> {
    fn take_pending(&self) -> u32 {
        self.chip.take_pending()
    }
    fn wait(&self, ms: u32) -> impl Future<Output = ()> + Send {
        NOW.fetch_add(ms as u64, Ordering::Relaxed);
        let mut fw = self.fw.borrow_mut();
        if !fw.started {
            fw.on_start();
        }
        for pipe in [0u32, 3, 4] {
            for (meta, data) in self.chip.target_consume(pipe) {
                fw.on_tx(pipe as u8, meta as u16, &data);
            }
        }
        while let Some((pipe, data)) = fw.out.pop_front() {
            if !self.chip.target_deliver(pipe, &data, None) {
                fw.out.push_front((pipe, data));
                break;
            }
        }
        core::future::ready(())
    }
}

fn core_over_real_ce(revision: HwRev) -> TestResult {
    let params = revision.params().expect("checked production profile");
    let config = CoreConfig::for_hw(&params).expect("checked production core config");
    NOW.store(0, Ordering::Relaxed);
    let msi = CeMsi {
        addr: 0xfee0_1000,
        ep_base_data: 0x40,
        config: &MSI_CONFIG_QCA6390,
    };
    let ce = match ce::Ce::alloc(&params, msi, clock) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("Ce::alloc"),
    };
    let chip = FakeChip::for_revision(revision, ce.shadow_reg_v2());
    let irq = FwIrq {
        chip: &chip,
        fw: RefCell::new(Fw::new(Script::default())),
    };
    let hif = CeHif {
        ce,
        io: ChipRef(&chip),
        irq,
        on_start: noop,
        clock,
    };
    let trace: Trace = Rc::new(RefCell::new(Vec::new()));
    let qmi = FakeQmi {
        trace: trace.clone(),
        fail: None,
    };
    let mut core = match Ath11kCore::new(hif, qmi, config) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("Ath11kCore::new"),
    };
    let mut h = hooks(&trace);
    let (r, err, _, stage) = latched(|| run(core.qmi_firmware_ready(&mut h)));
    ce::set_ce_irqs_enabled(false);
    ensure!(r.is_ok(), "bring-up over the CE rings");
    ensure!(
        err == 0 && stage == narf_memory::diag::WifiStage::Commands,
        "no latch, stage commands"
    );
    match trace.borrow().first() {
        Some(Ev::QmiStart { shadow, .. }) => ensure!(
            shadow[..]
                == if revision == HwRev::Qca6390Hw20 {
                    QCA6390_SHADOW_REG_V2
                } else {
                    WCN6855_SHADOW_REG_V2
                },
            "QMI got the CE's shadow list"
        ),
        _ => return TestResult::Fail("QMI start first"),
    }
    ensure!(core.mac_addr == Some(FW_MAC), "MAC through the rings");
    let fw = core.hif.irq.fw.borrow();
    let seen: Vec<(u8, u16, Vec<u8>)> = fw.seen.clone();
    drop(fw);
    ensure!(seen.len() == 6, "6 frames reached the target");
    ensure!(
        seen[0] == (0, 0, golden_htt_connect())
            && seen[1] == (0, 0, golden_wmi_connect())
            && seen[2] == (0, 0, golden_setup_complete()),
        "HTC control on CE0, transfer id = eid 0"
    );
    ensure!(
        seen[3] == (3, 2, golden_init()) && seen[4] == (3, 2, golden_set_hw_mode()),
        "WMI on CE3, transfer id = WMI eid"
    );
    ensure!(seen[5].0 == 4 && seen[5].1 == 1, "HTT on CE4");
    ensure!(
        h.htt_reply.as_deref() == Some(&HTT_VERSION_CONF[..]),
        "HTT reply through CE1"
    );
    let st = core.hif.ce.stats;
    ensure!(
        st.irqs[1] >= 1 && st.irqs[2] >= 1,
        "control + WMI RX serviced from interrupts"
    );
    ensure!(st.polled_without_irq == 0, "no RX found only by polling");
    ensure!(
        core.hif.ce.pipe(2).unwrap().stats.rx_completed == 7,
        "7 WMI events on CE2 (SR, AVAIL, EXT, EXT2, READY, REG, HW_MODE resp)"
    );
    TestResult::Pass
}
fn smoke_ath11k_core_over_real_ce() -> TestResult {
    core_over_real_ce(HwRev::Wcn6855Hw21)
}
fn smoke_ath11k_qca6390_core_over_real_ce() -> TestResult {
    core_over_real_ce(HwRev::Qca6390Hw20)
}
kernel_test_in!(
    "drivers/wireless/ath11k/qca6390",
    smoke_ath11k_qca6390_core_over_real_ce
);
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_core_over_real_ce);

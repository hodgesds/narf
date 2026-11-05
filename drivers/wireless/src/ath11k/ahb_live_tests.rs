//! Live AHB bring-up smokes: [`LiveAhb`] over RAM fixtures shaped like
//! `ipq6018.dtsi` (host-reset WCSS) and `sc7280.dtsi` (TrustZone PAS
//! WPSS). The fixture environment hands out [`FakeRegs`] windows, plays
//! the remote's SMP2P bits from [`AhbEnv::remote_tick`] and records the
//! interrupt binding.
//!
//! The GLINK edge has a fake WLFW server behind it
//! ([`GlinkWlfwServer`]): it plays the remote's GLINK open handshake,
//! answers QRTR HELLO with the WLFW service announcement, and serves the
//! QMI handshake (ind register, host cap, memory, target cap, DEVICE_INFO,
//! BDF download, M3 info) through FW_READY, so `qmi_ready` no longer
//! times out when the server is attached. The same server drives
//! [`Wlfw`] directly over [`GlinkQrtr`] for the handshake tests.
//!
//! Fixture-only; nothing has run on IPQ / WCN6750 silicon. Core start
//! past FW_READY (CE/HTC/WMI target responses) still has no fixture:
//! the LiveAhb WLFW test stops at the documented boundary (the core is
//! stranded waiting for HTC target-ready).

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::pin;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

use narf_drivers_qcom_soc::fixtures::{
    build_mdt, build_smem_v12_sized, glink_cmd, glink_data, glink_remote_open, glink_smem_edge,
    ipq6018_wifi_dt, remote_item, run, sc7280_wifi_dt, CountingKick, FakeAlloc, FakeDelay,
    FakeRegs, FakeSmc, GlinkRemote, Seg,
};
use narf_drivers_qcom_soc::glink::{
    GLINK_CMD_INTENT, GLINK_CMD_OPEN, GLINK_CMD_OPEN_ACK, GLINK_CMD_RX_DONE,
    GLINK_CMD_RX_DONE_W_REUSE, GLINK_CMD_RX_INTENT_REQ, GLINK_CMD_RX_INTENT_REQ_ACK,
    GLINK_CMD_TX_DATA, GLINK_CMD_TX_DATA_CONT, GLINK_CMD_VERSION, GLINK_FEATURE_INTENT_REUSE,
    SMEM_GLINK_NATIVE_XPRT_DESCRIPTOR, SMEM_GLINK_NATIVE_XPRT_FIFO_0,
    SMEM_GLINK_NATIVE_XPRT_FIFO_1,
};
use narf_drivers_qcom_soc::hwlock::TcsrMutex;
use narf_drivers_qcom_soc::mdt::{PT_LOAD, QCOM_MDT_TYPE_HASH};
use narf_drivers_qcom_soc::platform::GlinkEdgeDt;
use narf_drivers_qcom_soc::rproc::RprocState;
use narf_drivers_qcom_soc::smem::Smem;
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use super::super::ahb::find_ahb_devices;
use super::super::ahb::AhbChip;
use super::super::ahb_hif::AhbLine;
use super::super::ahb_probe::{bring_up, AhbBringUp, AhbPlatform, BringUpStep};
use super::super::qmi::{
    decode_tlvs, encode_message, split_message, tlv_i32, tlv_u32, tlv_u8, tlv_var_struct_array,
    LenSize, QmiError, QmiResponse, StructReader, TlvWriter, QMI_INDICATION, QMI_RESPONSE,
};
use super::super::qmi_client::QrtrPipe;
use super::super::qmi_wlfw::*;
use super::super::qrtr::*;
use super::super::qrtr_glink::{GlinkBus, GlinkQrtr, QRTR_GLINK_CHANNEL};
use super::super::runtime::{
    recovery_gated, ATH11K_RESET_MAX_FAIL_COUNT_FINAL, ATH11K_RESET_MAX_FAIL_COUNT_FIRST,
};
use super::super::wlfw::{step, CoherentMem, DmaAllocator, FirmwareLoader, Wlfw, WlfwConfig};
use super::*;
use narf_drivers_qcom_soc::q6v5::{Crash, Q6Event};
use narf_drivers_qcom_soc::smp2p::{FLAGS_RESTART_ACK_BIT, FLAGS_RESTART_DONE_BIT};

static CLOCK: AtomicU64 = AtomicU64::new(0);
/// Every read of the fixture clock advances it 50 ms, so QMI timeouts
/// expire after a bounded number of polls.
fn fast_clock() -> u64 {
    CLOCK.fetch_add(50, Ordering::Relaxed)
}

struct Files(BTreeMap<String, Vec<u8>>);
impl FirmwareLoader for Files {
    type Blob = Vec<u8>;
    fn request(&mut self, path: &str) -> Result<Vec<u8>, i32> {
        self.0.get(path).cloned().ok_or(2)
    }
}

struct Mem(u64, Vec<u8>);
impl CoherentMem for Mem {
    fn dma_addr(&self) -> u64 {
        self.0
    }
    fn size(&self) -> usize {
        self.1.len()
    }
    fn write(&mut self, off: usize, data: &[u8]) {
        self.1[off..off + data.len()].copy_from_slice(data);
    }
    fn bytes(&self) -> &[u8] {
        &self.1
    }
}
struct Dma;
impl DmaAllocator for Dma {
    type Mem = Mem;
    fn alloc_coherent(&mut self, size: usize) -> Option<Mem> {
        Some(Mem(0x1000_0000, alloc::vec![0; size]))
    }
}

/// A future that pends exactly once, then completes: the host's QMI
/// waits go through [`GlinkBus::wait_irq`], so a wait that completed
/// immediately would run the whole handshake (or its timeout) inside a
/// single poll and the [`GlinkWlfwServer`] pump between polls would
/// never run. Yielding once per wait interleaves one host step with
/// one server pump per outer poll. The existing timeout smokes are
/// unaffected: their timeouts are clock-driven (`fast_clock`), not
/// poll-count-driven, and `run` polls to completion.
struct YieldOnce(bool);

impl Future for YieldOnce {
    type Output = ();
    fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

struct Bus;
impl GlinkBus for Bus {
    fn wait_irq(&self, _ms: u32) -> impl core::future::Future<Output = ()> + Send {
        YieldOnce(false)
    }
    fn now_ms(&self) -> u64 {
        fast_clock()
    }
}

/// The fixture [`AhbEnv`].
struct Env {
    maps: BTreeMap<(u64, u64), &'static FakeRegs>,
    smem: &'static FakeRegs,
    smem_size: u32,
    pid: u16,
    smem_out: u32,
    /// The remote's SMP2P item (offset of its header).
    remote: u32,
    /// The host's outbound `stop` bit and the remote's ack bits.
    stop_bit: u32,
    ready_bits: u32,
    ack_bits: u32,
    ticks: AtomicU32,
    stop_seen: AtomicU32,
    files: BTreeMap<String, Vec<u8>>,
    lines: IrqSafeSpinLock<Vec<AhbLine>>,
    q6_gic: AtomicU32,
    glink_irq: AtomicU32,
}

static DELAY: FakeDelay = FakeDelay::new();

impl AhbEnv for Env {
    type Regs = FakeRegs;
    type Delay = FakeDelay;
    type Smc = FakeSmc;
    type ScmAlloc = FakeAlloc;
    type Fw = Files;
    type Dma = Dma;
    type Bus = Bus;

    fn map(&mut self, phys: u64, len: u64) -> Result<&'static FakeRegs, AhbError> {
        Ok(self
            .maps
            .entry((phys, len))
            .or_insert_with(|| Box::leak(Box::new(FakeRegs::quiet()))))
    }
    fn carveout(&mut self, _phys: u64, _len: u64) -> Result<&'static mut [u8], AhbError> {
        Ok(Box::leak(alloc::vec![0u8; 0x4000].into_boxed_slice()))
    }
    fn delay(&self) -> &'static FakeDelay {
        &DELAY
    }
    fn firmware(&mut self) -> Option<Files> {
        Some(Files(self.files.clone()))
    }
    fn scm(&mut self) -> (FakeSmc, FakeAlloc) {
        (FakeSmc::ok(), FakeAlloc::default())
    }
    fn dma(&mut self) -> Dma {
        Dma
    }
    fn bind_lines(
        &mut self,
        lines: Vec<AhbLine>,
        params: super::super::ahb::AhbHwParams,
    ) -> Result<AhbIrq, AhbError> {
        *self.lines.lock() = lines.clone();
        Ok(AhbIrq::new(lines, params, |_, _| {}))
    }
    fn bind_q6_gic(&mut self, irqs: &Q6Irqs, _q6: &'static Q6v5) -> Result<(), AhbError> {
        self.q6_gic
            .store(irqs.gic_lines().len() as u32, Ordering::Relaxed);
        Ok(())
    }
    fn glink_bus(&mut self, _blob: &[u8], edge: &GlinkEdgeDt) -> Result<Bus, AhbError> {
        self.glink_irq.store(
            edge.irq.cells.get(1).copied().unwrap_or(0),
            Ordering::Relaxed,
        );
        Ok(Bus)
    }
    fn clock(&self) -> fn() -> u64 {
        fast_clock
    }
    /// The remote: raise `ready` (+ `handover`) on the second wait
    /// iteration; ack once the host's `stop` bit is up.
    fn remote_tick(&self) {
        let t = self.ticks.fetch_add(1, Ordering::Relaxed);
        let v = self.remote + 20 + 16;
        if t == 1 {
            self.smem.set(v, self.smem.get(v) | self.ready_bits);
        }
        let Ok(smem) = Smem::probe(self.smem, self.smem_size) else {
            return;
        };
        let Ok(out) = smem.get(self.pid, self.smem_out) else {
            return;
        };
        if self.smem.get(out.offset + 20 + 16) & (1 << self.stop_bit) != 0 {
            self.stop_seen.store(1, Ordering::Relaxed);
            self.smem.set(v, self.smem.get(v) | self.ack_bits);
        }
    }
}

fn segs(base: u32) -> [Seg; 3] {
    [
        Seg {
            p_type: 0,
            flags: 0x0700_0000,
            paddr: 0,
            filesz: 0,
            memsz: 0,
            fill: 0,
        },
        Seg {
            p_type: 0,
            flags: QCOM_MDT_TYPE_HASH,
            paddr: base,
            filesz: 0x40,
            memsz: 0x1000,
            fill: 0xaa,
        },
        Seg {
            p_type: PT_LOAD,
            flags: 0,
            paddr: base,
            filesz: 0x100,
            memsz: 0x200,
            fill: 0x11,
        },
    ]
}

/// Build the environment for `p`: SMEM (one private partition with the
/// remote), the remote's SMP2P item, and the remoteproc image.
fn env_for(p: &AhbPlatform, ready_bits: u32, ack_bits: u32) -> Box<Env> {
    let s = p.remote.platform.smem.clone().unwrap();
    let edge = &p.remote.platform.edges[0];
    let (_, _, stop_bit) = p.remote.platform.stop.clone().unwrap();
    let smem_regs: &'static FakeRegs = Box::leak(Box::new(FakeRegs::quiet()));
    let size = s.region.1 as u32;
    build_smem_v12_sized(smem_regs, size, edge.cfg.remote_pid, 1024, 0x10000);
    let lock_regs: &'static FakeRegs = Box::leak(Box::new(FakeRegs::new()));
    let lock = TcsrMutex::new(lock_regs, &DELAY, s.hwlock_id).unwrap();
    let smem = Smem::probe(smem_regs, size).unwrap();
    let remote = remote_item(&smem, &lock, edge.cfg, &[("slave-kernel", 0)], false);
    // The remote's GLINK TX FIFO (host RX, item 480): the Q6 allocates
    // it before it starts, so a WLFW server can attach once the host
    // registers the edge. Pre-allocating it changes nothing for the
    // no-server smokes (register only touches items 478/479).
    run(smem.alloc(
        &lock,
        edge.cfg.remote_pid,
        SMEM_GLINK_NATIVE_XPRT_FIFO_1,
        0x4000,
    ))
    .expect("pending")
    .expect("alloc remote glink fifo");
    let mut maps = BTreeMap::new();
    maps.insert(s.region, smem_regs);
    maps.insert(s.hwlock_base, lock_regs);
    let mut env = Box::new(Env {
        maps,
        smem: smem_regs,
        smem_size: size,
        pid: edge.cfg.remote_pid,
        smem_out: edge.cfg.smem_out,
        remote,
        stop_bit,
        ready_bits,
        ack_bits,
        ticks: AtomicU32::new(0),
        stop_seen: AtomicU32::new(0),
        files: BTreeMap::new(),
        lines: IrqSafeSpinLock::new(Vec::new()),
        q6_gic: AtomicU32::new(0),
        glink_irq: AtomicU32::new(0),
    });
    let base = p.remote.platform.carveout.0 as u32;
    let (img, _) = build_mdt(base, &segs(base), true);
    env.files
        .insert(String::from(p.remote.platform.firmware), img);
    // WCSS: RMB reports SSCAON powered, the halt ports idle.
    if let (Some(rmb), Some(h)) = (p.remote.platform.rmb, p.remote.platform.halt.clone()) {
        let r = env.map(rmb.0, rmb.1).unwrap();
        r.set(narf_drivers_qcom_soc::wcss::SSCAON_STATUS, 0x400);
        let t = env.map(h.tcsr.0, h.tcsr.1).unwrap();
        t.set(h.wcss + narf_drivers_qcom_soc::wcss::AXI_IDLE_REG, 1);
        t.set(h.q6 + narf_drivers_qcom_soc::wcss::AXI_IDLE_REG, 1);
    }
    env
}

const SPIS: [u32; 52] = [
    320, 319, 318, 317, 316, 315, 314, 311, 310, 411, 410, 40, 39, 302, 301, 37, 36, 296, 295, 294,
    293, 292, 291, 290, 289, 288, 239, 236, 235, 234, 233, 232, 231, 230, 229, 228, 224, 223, 203,
    183, 180, 179, 178, 177, 176, 163, 162, 160, 159, 158, 157, 156,
];

/// IPQ6018: WiFi window mapped, WCSS boots through SMP2P `ready`, the
/// GLINK descriptor is allocated in SMEM, the CE/DP lines bind, QMI
/// times out and the WCSS is stopped through the SMP2P `stop` bit.
fn smoke_ath11k_ahb_live_ipq6018_wcss() -> TestResult {
    let blob: &'static [u8] =
        Box::leak(ipq6018_wifi_dt("qcom,ipq6018-wifi", &SPIS).into_boxed_slice());
    let node = find_ahb_devices(blob)[0].0.clone();
    let p = Box::new(AhbPlatform::probe(blob, &node).unwrap());
    // fatal 0, ready 1, handover 2, stop-ack 3.
    let env = env_for(&p, (1 << 1) | (1 << 2), 1 << 3);
    let smem_regs = env.smem;
    let (pid, size) = (env.pid, env.smem_size);
    let gcc = p.remote.platform.reset("wcss_reset").unwrap().gcc_base;
    let mut live = Box::new(LiveAhb::new(*env, blob));
    let r = run(bring_up(&p, &mut *live));
    kt_assert!(
        matches!(r, Some(Err((BringUpStep::QmiReady, AhbError::Failed(_))))),
        "QMI has no server: fails at qmi_ready"
    );
    // hal_ce_alloc: the WiFi window is the IPQ HIF's register space.
    kt_assert!(live.hif().is_some(), "IPQ HIF built at hal_ce_alloc");
    kt_assert!(live.env.maps.contains_key(&p.res.mem.unwrap()));
    // config_irq: every CE / DP line, and the HIF carries them.
    kt_assert_eq!(live.env.lines.lock().len(), p.lines.len());
    kt_assert_eq!(live.hif().unwrap().irq.lines().len(), p.lines.len());
    // rproc_irqs: the `wdog` GIC line.
    kt_assert_eq!(live.env.q6_gic.load(Ordering::Relaxed), 1);
    // rproc_boot ran to Running (the ready edge arrived), then the unwind
    // raised `stop`, the remote acked and the WCSS is back in reset.
    kt_assert_eq!(live.env.stop_seen.load(Ordering::Relaxed), 1);
    kt_assert_eq!(live.rproc_state(), Some(RprocState::Offline));
    let g = live.env.maps.get(&gcc).copied().unwrap();
    kt_assert_eq!(
        (g.get(0x18000), g.get(0x18100)),
        (1, 1),
        "WCSS/Q6 BCR asserted"
    );
    kt_assert_eq!(g.get(0x59010), 1, "WCSSAON asserted");
    // glink_start: descriptor + TX FIFO allocated in the remote partition.
    let smem = Smem::probe(smem_regs, size).unwrap();
    kt_assert!(smem.get(pid, SMEM_GLINK_NATIVE_XPRT_DESCRIPTOR).is_ok());
    kt_assert!(!live.qrtr_open(), "IPCRTR never opened by the fixture");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_ahb_live_ipq6018_wcss
);

/// WCN6750: PAS boot through SCM (init / mem_setup / auth_and_reset),
/// the IPCC-routed GLINK edge, CE pipes without a register window until
/// DEVICE_INFO, the hybrid MSI lines, `wlan-smp2p-out` resolved; QMI
/// times out and the WPSS is stopped.
fn smoke_ath11k_ahb_live_wcn6750_pas() -> TestResult {
    let blob: &'static [u8] = Box::leak(sc7280_wifi_dt().into_boxed_slice());
    let node = find_ahb_devices(blob)[0].0.clone();
    let p = Box::new(AhbPlatform::probe(blob, &node).unwrap());
    // fatal 0, ready 1, handover 2, stop-ack 3, shutdown-ack 7.
    let env = env_for(&p, (1 << 1) | (1 << 2), (1 << 3) | (1 << 7));
    let mut live = Box::new(LiveAhb::new(*env, blob));
    let r = run(bring_up(&p, &mut *live));
    kt_assert!(
        matches!(r, Some(Err((BringUpStep::QmiReady, AhbError::Failed(_))))),
        "fails at qmi_ready"
    );
    kt_assert!(
        live.hif().is_none(),
        "no register window before DEVICE_INFO"
    );
    kt_assert_eq!(live.env.lines.lock().len(), p.lines.len());
    kt_assert!(!p.lines.is_empty());
    // glink-edge: <&ipcc 24 0 1> (IPCC_MPROC_SIGNAL_GLINK_QMP = 0).
    kt_assert_eq!(live.env.glink_irq.load(Ordering::Relaxed), 0);
    kt_assert_eq!(live.env.q6_gic.load(Ordering::Relaxed), 1);
    kt_assert_eq!(live.env.stop_seen.load(Ordering::Relaxed), 1);
    kt_assert_eq!(live.rproc_state(), Some(RprocState::Offline));
    kt_assert_eq!(live.set_wlan_smp2p(0x0001_0002), Some(()), "wlan-smp2p-out");
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_ahb_live_wcn6750_pas);

// ── fake WLFW server over GLINK ──────────────────────────────────

/// The device side of the QRTR name service, as `net/qrtr/ns.c`
/// announces it: node 3, WLFW on port 1.
const DEV_NODE: u32 = 3;
const SRV_PORT: u32 = 1;
const DEV_CTRL: QrtrAddr = QrtrAddr {
    node: DEV_NODE,
    port: QRTR_PORT_CTRL,
};
const HOST_CTRL_BCAST: QrtrAddr = QrtrAddr {
    node: QRTR_NODE_BCAST,
    port: QRTR_PORT_CTRL,
};
/// The remote channel id the server opens with (mirrors the
/// `qrtr_glink_tests` remote).
const SRV_RCID: u16 = 4;
/// The DEVICE_INFO BAR the WCN6750 server reports: a fixture RAM
/// window; the size must equal `ATH11K_QMI_DEVICE_BAR_SIZE`.
const SRV_BAR_ADDR: u64 = 0x0b00_0000;
/// One remote intent (8 KiB) for host→server traffic: it fits the
/// largest frame in this handshake — a 6144-byte BDF segment plus
/// QRTR/QMI headers — in a single intent, so no RX_INTENT_REQ round
/// trip is needed (the handler below still answers one if asked).
const SRV_INTENT_SIZE: u32 = 8192;

/// Which AHB handshake the server plays.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ServerChip {
    /// Hybrid bus, `fixed_fw_mem`: no REQUEST_MEM / FW_MEM_READY;
    /// DEVICE_INFO, then BDF download, then FW_READY.
    Wcn6750,
    /// `fixed_mem_region` + `fixed_bdf_addr`: REQUEST_MEM with fixed
    /// assignment, BDF through the window, cold-boot calibration
    /// (FW_INIT_DONE, COLD_BOOT mode, COLD_BOOT_CAL_DONE, FW_INIT_DONE).
    Ipq6018,
}

impl ServerChip {
    fn ins_id(self) -> u32 {
        match self {
            ServerChip::Wcn6750 => ATH11K_QMI_WLFW_SERVICE_INS_ID_V01_WCN6750,
            ServerChip::Ipq6018 => ATH11K_QMI_WLFW_SERVICE_INS_ID_V01_IPQ8074,
        }
    }
}

/// A scripted WLFW firmware behind a [`GlinkRemote`] edge: the Q6 side
/// of `IPCRTR`, speaking QRTR (`net/qrtr/ns.c`) and QMI WLFW
/// (`drivers/net/wireless/ath/ath11k/qmi.c`) exactly as the MHI-path
/// `FakeFw` in `qmi_handshake_tests.rs` does, but transported over
/// GLINK commands instead of a fake pipe.
///
/// The server is driven by [`Self::pump`], once per host poll: it
/// drains the host's GLINK output, answers the open handshake, tracks
/// both sides' intents (host intents freed by the host's
/// RX_DONE_W_REUSE, remote intents freed by the server's own
/// RX_DONE_W_REUSE after consuming a message), and serves QMI
/// requests in order. Two attach modes:
///
/// - [`Self::attached`]: the open handshake already ran (the
///   `glink_remote_open` fixture helper); the host lcid is known and
///   the host's advertised intents arrive in the first drain.
/// - [`Self::unattached`]: the server plays the remote open itself
///   (VERSION + OPEN on the first pump), for edges the host created
///   (the `LiveAhb` bring-up).
///
/// Every QMI value the server sends comes from the `qmi_wlfw`
/// encoders or the constants below — never from the production
/// handshake under test. The one deliberate exception is the cap
/// payload: its chip/board/soc/version numbers are fixture-chosen
/// (the test asserts the client echoes them, not that they match
/// silicon).
struct GlinkWlfwServer<'a> {
    r: GlinkRemote<'a>,
    host_lcid: Option<u32>,
    /// Host intents currently free, in advertised order.
    free_intents: VecDeque<(u32, u32)>,
    /// Host intent id → size, for RX_DONE matching.
    intent_sizes: BTreeMap<u32, u32>,
    /// Next remote intent id to offer (1 is the initial offer).
    next_remote_intent: u32,
    /// VERSION + OPEN already pushed (attached mode starts here).
    started: bool,
    hello_sent: bool,
    announced: bool,
    chip: ServerChip,
    cap: CapResp,
    /// REQUEST_MEM rounds the server plays (IPQ path).
    mem_rounds: Vec<Vec<MemSeg>>,
    mem_round: usize,
    device_bar: Option<(u64, u32)>,
    /// Fail this QMI request with this error code, no side effects
    /// (tampered-response case).
    fail_req: Option<(u16, u16)>,
    fw_ready_sent: bool,
    init_done_sent: usize,
    /// Observations for the tests.
    reqs: Vec<u16>,
    respond_mem: Vec<(u64, u32, i32)>,
    bdf_segs: Vec<(u32, u8)>,
    /// Whether each BDF request carried a data segment: the
    /// `fixed_bdf_addr` path sends one request with no data TLV (the
    /// bytes went through the DMA window instead).
    bdf_data: Vec<bool>,
    decode_errs: usize,
    /// Reassembly for host→server data (one channel, one buffer).
    rx_buf: Vec<u8>,
    /// QRTR packets waiting for a free host intent.
    out_qrtr: VecDeque<Vec<u8>>,
    host_addr: Option<QrtrAddr>,
}

const QMI_OK: [u8; 7] = [0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];

/// Test-side decode of a host-sent RESPOND_MEM request payload.
/// `RespondMemReq` implements only the encode side (`WlfwRequest`);
/// there is no `WlfwMessage` impl to call, so the server decodes the
/// mandatory TLV 0x01 (u8 count + `MemSegResp` structs in the exact
/// `write` order: u64 addr, u32 size, i32 mem_type, u8 restore)
/// with the same helpers the production decoders use.
fn decode_respond_mem_req(payload: &[u8]) -> Result<RespondMemReq, QmiError> {
    let mut mem_seg = Vec::new();
    let seen = decode_tlvs(payload, &[0x01], |ty, v| {
        mem_seg = tlv_var_struct_array(
            ty,
            v,
            LenSize::U8,
            ATH11K_QMI_WLANFW_MAX_NUM_MEM_SEG_V01,
            |r| {
                Ok(MemSegResp {
                    addr: r.u64()?,
                    size: r.u32()?,
                    mem_type: r.i32()?,
                    restore: r.u8()?,
                })
            },
        )?;
        Ok(())
    })?;
    if !seen.contains(0x01) {
        return Err(QmiError::Truncated { tlv: 0x01 });
    }
    Ok(RespondMemReq { mem_seg })
}

/// Test-side decode of a host-sent BDF_DOWNLOAD request payload.
/// Same situation as above: `BdfDownloadReq` implements only
/// `WlfwRequest`, so the server decodes the TLVs in the exact
/// `write` order (0x01 valid, 0x10 file_id, 0x11 total_size,
/// 0x12 seg_id, 0x13 data, 0x14 end, 0x15 bdf_type). The data slice
/// borrows from the payload; the caller only records its presence.
fn decode_bdf_download_req<'a>(payload: &'a [u8]) -> Result<BdfDownloadReq<'a>, QmiError> {
    let mut req = BdfDownloadReq::default();
    let seen = decode_tlvs(
        payload,
        &[0x01, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15],
        |ty, v| {
            match ty {
                0x01 => req.valid = tlv_u8(ty, v)?,
                0x10 => req.file_id = Some(tlv_i32(ty, v)?),
                0x11 => req.total_size = Some(tlv_u32(ty, v)?),
                0x12 => req.seg_id = Some(tlv_u32(ty, v)?),
                0x13 => {
                    let mut r = StructReader::new(ty, v);
                    let n = r.data_len(LenSize::U16)?;
                    if n > QMI_WLANFW_MAX_DATA_SIZE_V01 {
                        return Err(QmiError::ArrayTooLong {
                            tlv: ty,
                            len: n,
                            max: QMI_WLANFW_MAX_DATA_SIZE_V01,
                        });
                    }
                    let data = r.rest();
                    if data.len() != n {
                        return Err(QmiError::LengthMismatch {
                            tlv: ty,
                            expected: LenSize::U16.bytes() + n,
                            got: v.len(),
                        });
                    }
                    req.data = Some(data);
                }
                0x14 => req.end = Some(tlv_u8(ty, v)?),
                0x15 => req.bdf_type = Some(tlv_u8(ty, v)?),
                _ => {}
            }
            Ok(())
        },
    )?;
    if !seen.contains(0x01) {
        return Err(QmiError::Truncated { tlv: 0x01 });
    }
    Ok(req)
}

impl<'a> GlinkWlfwServer<'a> {
    fn attached(
        r: GlinkRemote<'a>,
        host_lcid: u32,
        chip: ServerChip,
        cap: CapResp,
        mem_rounds: Vec<Vec<MemSeg>>,
        device_bar: Option<(u64, u32)>,
    ) -> Self {
        Self::new(r, Some(host_lcid), true, chip, cap, mem_rounds, device_bar)
    }

    fn unattached(
        r: GlinkRemote<'a>,
        chip: ServerChip,
        cap: CapResp,
        mem_rounds: Vec<Vec<MemSeg>>,
        device_bar: Option<(u64, u32)>,
    ) -> Self {
        Self::new(r, None, false, chip, cap, mem_rounds, device_bar)
    }

    fn new(
        r: GlinkRemote<'a>,
        host_lcid: Option<u32>,
        started: bool,
        chip: ServerChip,
        cap: CapResp,
        mem_rounds: Vec<Vec<MemSeg>>,
        device_bar: Option<(u64, u32)>,
    ) -> Self {
        Self {
            r,
            host_lcid,
            free_intents: VecDeque::new(),
            intent_sizes: BTreeMap::new(),
            next_remote_intent: 2,
            started,
            hello_sent: false,
            announced: false,
            chip,
            cap,
            mem_rounds,
            mem_round: 0,
            device_bar,
            fail_req: None,
            fw_ready_sent: false,
            init_done_sent: 0,
            reqs: Vec::new(),
            respond_mem: Vec::new(),
            bdf_segs: Vec::new(),
            bdf_data: Vec::new(),
            decode_errs: 0,
            rx_buf: Vec::new(),
            out_qrtr: VecDeque::new(),
            host_addr: None,
        }
    }

    /// One server step: play the open handshake if needed, drain the
    /// host's GLINK output, then flush queued QRTR packets onto free
    /// host intents.
    fn pump(&mut self) {
        if !self.started {
            self.r.push(&glink_cmd(
                GLINK_CMD_VERSION,
                1,
                GLINK_FEATURE_INTENT_REUSE,
                &[],
            ));
            let mut nm = Vec::from(QRTR_GLINK_CHANNEL.as_bytes());
            nm.push(0);
            self.r
                .push(&glink_cmd(GLINK_CMD_OPEN, SRV_RCID, nm.len() as u32, &nm));
            self.started = true;
        }
        for (cmd, p1, p2, body) in self.r.pop() {
            match cmd {
                GLINK_CMD_OPEN => {
                    // The host's OPEN carries its lcid; answer with
                    // OPEN_ACK + one remote intent.
                    self.host_lcid = Some(p1 as u32);
                    self.r.push(&glink_cmd(GLINK_CMD_OPEN_ACK, p1, 0, &[]));
                    let mut b = Vec::new();
                    b.extend_from_slice(&SRV_INTENT_SIZE.to_le_bytes());
                    b.extend_from_slice(&1u32.to_le_bytes());
                    self.r.push(&glink_cmd(GLINK_CMD_INTENT, SRV_RCID, 1, &b));
                }
                GLINK_CMD_INTENT => {
                    // Host offers intents: (size, id) pairs.
                    for pair in body.chunks_exact(8) {
                        let size = u32::from_le_bytes([pair[0], pair[1], pair[2], pair[3]]);
                        let id = u32::from_le_bytes([pair[4], pair[5], pair[6], pair[7]]);
                        self.intent_sizes.insert(id, size);
                        self.free_intents.push_back((size, id));
                    }
                }
                GLINK_CMD_RX_DONE_W_REUSE => {
                    // Host freed one of its intents for reuse.
                    if let Some(size) = self.intent_sizes.get(&p2).copied() {
                        self.free_intents.push_back((size, p2));
                    }
                }
                GLINK_CMD_RX_DONE => {
                    // Non-reuse done: the intent is gone.
                    self.intent_sizes.remove(&p2);
                }
                GLINK_CMD_RX_INTENT_REQ => {
                    // Host needs a bigger intent: grant, then ack
                    // (the INTENT must precede the ack).
                    let id = self.next_remote_intent;
                    self.next_remote_intent += 1;
                    let mut b = Vec::new();
                    b.extend_from_slice(&p2.to_le_bytes());
                    b.extend_from_slice(&id.to_le_bytes());
                    self.r.push(&glink_cmd(GLINK_CMD_INTENT, SRV_RCID, 1, &b));
                    self.r
                        .push(&glink_cmd(GLINK_CMD_RX_INTENT_REQ_ACK, SRV_RCID, 1, &[]));
                }
                GLINK_CMD_TX_DATA | GLINK_CMD_TX_DATA_CONT => {
                    // body = [chunk_len, left, chunk...].
                    if body.len() < 8 {
                        self.decode_errs += 1;
                        continue;
                    }
                    let left = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
                    self.rx_buf.extend_from_slice(&body[8..]);
                    if left == 0 {
                        let pkt = core::mem::take(&mut self.rx_buf);
                        self.handle_qrtr(&pkt);
                    }
                    // Free the host's intent for reuse.
                    self.r
                        .push(&glink_cmd(GLINK_CMD_RX_DONE_W_REUSE, SRV_RCID, p2, &[]));
                }
                _ => {}
            }
        }
        // The channel is open and the host offered intents: announce.
        if self.host_lcid.is_some() && !self.hello_sent && !self.free_intents.is_empty() {
            self.ctrl(CtrlPkt::Hello);
            self.hello_sent = true;
        }
        // Flush queued QRTR packets onto the smallest fitting free
        // host intent (like `__qcom_glink_send`).
        while let Some(pkt) = self.out_qrtr.front() {
            let mut best: Option<usize> = None;
            for (i, (size, _)) in self.free_intents.iter().enumerate() {
                if (*size as usize) < pkt.len() {
                    continue;
                }
                match best {
                    Some(b) if self.free_intents[b].0 <= *size => {}
                    _ => best = Some(i),
                }
            }
            let Some(b) = best else { break };
            let (_, liid) = self.free_intents.remove(b).unwrap();
            let pkt = self.out_qrtr.pop_front().unwrap();
            // Every packet this server sends fits one host intent
            // (1024 bytes); anything larger would stall the handshake
            // and fail loudly at the test's out_qrtr assertion.
            self.r.push(&glink_data(false, SRV_RCID, liid, &pkt, 0));
        }
    }

    fn ctrl(&mut self, pkt: CtrlPkt) {
        let f = encode_packet(pkt.cmd(), DEV_CTRL, HOST_CTRL_BCAST, false, &pkt.to_bytes())
            .expect("ctrl encode");
        self.out_qrtr.push_back(f);
    }

    fn data(&mut self, qmi: Vec<u8>) {
        let dst = self.host_addr.expect("server data before host addr");
        let src = QrtrAddr {
            node: DEV_NODE,
            port: SRV_PORT,
        };
        let f = encode_packet(QRTR_TYPE_DATA, src, dst, false, &qmi).expect("data encode");
        self.out_qrtr.push_back(f);
    }

    fn resp(&mut self, msg_id: u16, txn: u16, payload: &[u8]) {
        self.data(encode_message(QMI_RESPONSE, msg_id, txn, payload));
    }

    fn ind(&mut self, msg_id: u16, payload: &[u8]) {
        self.data(encode_message(QMI_INDICATION, msg_id, 0, payload));
    }

    fn mem_ind(&mut self) {
        let Some(round) = self.mem_rounds.get(self.mem_round).cloned() else {
            return;
        };
        let mut w = TlvWriter::new(QMI_WLANFW_REQUEST_MEM_IND_MSG_V01_MAX_LEN);
        RequestMemInd { mem_seg: round }
            .write(&mut w)
            .expect("mem ind");
        let p = w.finish().expect("mem ind finish");
        self.ind(QMI_WLFW_REQUEST_MEM_IND_V01, &p);
    }

    fn handle_qrtr(&mut self, frame: &[u8]) {
        let Ok(p) = decode_packet(frame) else {
            self.decode_errs += 1;
            return;
        };
        if p.dst_port == QRTR_PORT_CTRL {
            if let Ok(CtrlPkt::Hello) = CtrlPkt::parse(p.payload) {
                if !self.announced {
                    self.announced = true;
                    self.ctrl(CtrlPkt::NewServer {
                        service: ATH11K_QMI_WLFW_SERVICE_ID_V01,
                        instance: qmi_instance(
                            ATH11K_QMI_WLFW_SERVICE_VERS_V01,
                            self.chip.ins_id(),
                        ),
                        node: DEV_NODE,
                        port: SRV_PORT,
                    });
                }
            }
            return;
        }
        if p.dst_port != SRV_PORT {
            return;
        }
        if p.confirm_rx {
            // `qrtr_send_resume_tx` from the server port.
            let dst = QrtrAddr {
                node: p.src_node,
                port: p.src_port,
            };
            let f = encode_packet(
                QRTR_TYPE_RESUME_TX,
                QrtrAddr {
                    node: DEV_NODE,
                    port: SRV_PORT,
                },
                dst,
                false,
                &CtrlPkt::ResumeTx {
                    node: DEV_NODE,
                    port: SRV_PORT,
                }
                .to_bytes(),
            )
            .expect("resume encode");
            self.out_qrtr.push_back(f);
        }
        self.host_addr = Some(QrtrAddr {
            node: p.src_node,
            port: p.src_port,
        });
        let Ok((hdr, payload)) = split_message(p.payload) else {
            self.decode_errs += 1;
            return;
        };
        self.on_request(hdr.msg_id, hdr.txn_id, payload);
    }

    fn on_request(&mut self, msg_id: u16, txn: u16, payload: &[u8]) {
        self.reqs.push(msg_id);
        if let Some((m, err)) = self.fail_req {
            if m == msg_id {
                self.resp(
                    msg_id,
                    txn,
                    &[0x02, 0x04, 0x00, 0x01, 0x00, err as u8, (err >> 8) as u8],
                );
                return;
            }
        }
        match msg_id {
            QMI_WLANFW_HOST_CAP_REQ_V01 => {
                self.resp(msg_id, txn, &QMI_OK);
                // Non-fixed-mem parts answer host_cap with the
                // memory request; fixed_fw_mem parts (WCN6750) run
                // their BDF load from the client instead.
                if self.chip == ServerChip::Ipq6018 {
                    self.mem_ind();
                }
            }
            QMI_WLANFW_RESPOND_MEM_REQ_V01 => {
                match decode_respond_mem_req(payload) {
                    Ok(req) => {
                        self.respond_mem = req
                            .mem_seg
                            .iter()
                            .map(|m| (m.addr, m.size, m.mem_type))
                            .collect();
                    }
                    Err(_) => self.decode_errs += 1,
                }
                self.resp(msg_id, txn, &QMI_OK);
                self.mem_round += 1;
                if self.mem_round < self.mem_rounds.len() {
                    self.mem_ind();
                } else {
                    self.ind(QMI_WLFW_FW_MEM_READY_IND_V01, &[]);
                }
            }
            QMI_WLANFW_CAP_REQ_V01 => {
                let mut w = TlvWriter::new(QMI_WLANFW_CAP_RESP_MSG_V01_MAX_LEN);
                self.cap.write(&mut w).expect("cap encode");
                let p = w.finish().expect("cap finish");
                self.resp(msg_id, txn, &p);
            }
            QMI_WLANFW_DEVICE_INFO_REQ_V01 => {
                let mut w = TlvWriter::new(64);
                w.u32(0x02, 0);
                if let Some((addr, size)) = self.device_bar {
                    w.u64(0x10, addr);
                    w.u32(0x11, size);
                }
                let p = w.finish().expect("device info finish");
                self.resp(msg_id, txn, &p);
            }
            QMI_WLANFW_BDF_DOWNLOAD_REQ_V01 => {
                match decode_bdf_download_req(payload) {
                    Ok(req) => {
                        self.bdf_segs
                            .push((req.seg_id.unwrap_or(u32::MAX), req.end.unwrap_or(0)));
                        self.bdf_data.push(req.data.is_some());
                    }
                    Err(_) => self.decode_errs += 1,
                }
                self.resp(msg_id, txn, &QMI_OK);
                // Fixed_fw_mem parts never see REQUEST_MEM /
                // FW_MEM_READY: FW_READY follows the first BDF
                // download (queued after the response).
                if self.chip == ServerChip::Wcn6750 && !self.fw_ready_sent {
                    self.fw_ready_sent = true;
                    self.ind(QMI_WLFW_FW_READY_IND_V01, &[]);
                }
            }
            QMI_WLANFW_M3_INFO_REQ_V01 => {
                self.resp(msg_id, txn, &QMI_OK);
                // IPQ parts finish on FW_INIT_DONE (cold-boot
                // calibration follows); the second FW_INIT_DONE
                // comes after the COLD_BOOT mode request.
                if self.chip == ServerChip::Ipq6018 && self.init_done_sent == 0 {
                    self.init_done_sent = 1;
                    self.ind(QMI_WLFW_FW_INIT_DONE_IND_V01, &[]);
                }
            }
            QMI_WLANFW_WLAN_MODE_REQ_V01 => {
                self.resp(msg_id, txn, &QMI_OK);
                // The only mode request before registration on the
                // IPQ path is COLD_BOOT: answer with calibration
                // done, then the second FW_INIT_DONE.
                if self.chip == ServerChip::Ipq6018 && self.init_done_sent == 1 {
                    self.init_done_sent = 2;
                    self.ind(QMI_WLFW_COLD_BOOT_CAL_DONE_IND_V01, &[]);
                    self.ind(QMI_WLFW_FW_INIT_DONE_IND_V01, &[]);
                }
            }
            _ => self.resp(msg_id, txn, &QMI_OK),
        }
    }
}

/// The pump bus for the direct WLFW tests: the clock never advances,
/// so QMI timeouts cannot fire spuriously, and every wait yields once
/// so the server pump between polls can answer.
#[derive(Default)]
struct PumpBus {
    now: AtomicU64,
}

impl GlinkBus for PumpBus {
    fn wait_irq(&self, _ms: u32) -> impl Future<Output = ()> + Send {
        YieldOnce(false)
    }
    fn now_ms(&self) -> u64 {
        self.now.load(Ordering::Relaxed)
    }
}

/// Drive a future whose waits yield once, pumping the server between
/// polls, until it settles or the bound is hit.
fn pump_to_ready<F: Future>(fut: F, server: &mut GlinkWlfwServer<'_>) -> Option<F::Output> {
    let mut fut = pin!(fut);
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    for _ in 0..200_000 {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return Some(v);
        }
        server.pump();
    }
    None
}

/// An ELF board file: `bdf_type_for` classifies the `\x7fELF` magic
/// as ELF, so no caldata file is needed.
fn elf_board(len: usize) -> Vec<u8> {
    let mut v = alloc::vec![0; len];
    v[0..4].copy_from_slice(b"\x7fELF");
    v
}

/// Fixture cap payload: the numbers are fixture-chosen; the tests
/// assert the client echoes them, not that they match silicon.
fn fixture_cap(chip_id: u32, board_id: u32, soc_id: u32, fw_version: u32) -> CapResp {
    CapResp {
        resp: QmiResponse::default(),
        chip_info: Some(RfChipInfo {
            chip_id,
            chip_family: 0x34,
        }),
        board_id: Some(board_id),
        soc_id: Some(soc_id),
        fw_version_info: Some(FwVersionInfo {
            fw_version,
            fw_build_timestamp: b"2024-01-01 00:00".to_vec(),
        }),
        fw_build_id: Some(b"QC_IMAGE_VERSION_STRING=FIXTURE".to_vec()),
        num_macs: None,
        voltage_mv: None,
        time_freq_hz: None,
        otp_version: None,
        eeprom_read_timeout: None,
    }
}

/// DMA for the direct tests: RAM buffers plus a recorded BDF window
/// (`fixed_bdf_addr` parts write the board file through it).
struct TestDma {
    iomem: Vec<(u64, usize, Vec<u8>)>,
}

impl DmaAllocator for TestDma {
    type Mem = Mem;
    fn alloc_coherent(&mut self, size: usize) -> Option<Mem> {
        Some(Mem(0x1000_0000, alloc::vec![0; size]))
    }
    fn iomem_write(
        &mut self,
        phys: u64,
        map_len: usize,
        off: usize,
        data: &[u8],
    ) -> Result<(), i32> {
        if off.checked_add(data.len()).is_none_or(|end| end > map_len) {
            return Err(super::super::wlfw::EINVAL);
        }
        self.iomem.push((phys, off, data.to_vec()));
        Ok(())
    }
}

fn smoke_ath11k_wlfw_over_glink_wcn6750() -> TestResult {
    let regs = FakeRegs::quiet();
    let lr = FakeRegs::new();
    let d = FakeDelay::new();
    let k = CountingKick::default();
    let bus = PumpBus::default();
    let (g, r) = glink_smem_edge(&regs, &lr, &d, &k, 1);
    let mut pipe = GlinkQrtr::new(g, bus);
    let Some(lcid) = glink_remote_open(&mut pipe.glink, &r, QRTR_GLINK_CHANNEL, 4, &[(8192, 1)])
    else {
        return TestResult::Fail("no OPEN");
    };
    pipe.poll();
    kt_assert_eq!(pipe.lcid(), Some(u32::from(lcid)));
    let board = elf_board(6144 * 2 + 100);
    let mut files = Files(BTreeMap::new());
    files.0.insert(
        String::from("ath11k/WCN6750/hw1.0/board.bin"),
        board.clone(),
    );
    let mut server = GlinkWlfwServer::attached(
        r,
        u32::from(lcid),
        ServerChip::Wcn6750,
        fixture_cap(0x12, 0x56, 0x7890, 0x1),
        Vec::new(),
        Some((SRV_BAR_ADDR, ATH11K_QMI_DEVICE_BAR_SIZE)),
    );
    let cfg = WlfwConfig::ahb(AhbChip::Wcn6750Hw10, String::from("c000000.wifi"), None);
    let mut w = match Wlfw::new(pipe, files, TestDma { iomem: Vec::new() }, cfg) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("wlfw new"),
    };
    let Some(info) = pump_to_ready(w.run_to_fw_ready(), &mut server) else {
        return TestResult::Fail("pump exhausted");
    };
    let info = match info {
        Ok(info) => info,
        Err(_) => return TestResult::Fail("wlfw handshake failed"),
    };
    // Post-FW_READY state: the client echoes the server's cap, the
    // board choice is the API-1 file, and the hybrid BAR is learned.
    kt_assert_eq!(info.target.chip_id, 0x12);
    kt_assert_eq!(info.target.board_id, 0x56);
    kt_assert_eq!(info.target.soc_id, 0x7890);
    kt_assert_eq!(info.target.fw_version, 0x1);
    let Some(board_choice) = info.board else {
        return TestResult::Fail("no board choice");
    };
    kt_assert_eq!(board_choice.name.as_str(), "board.bin");
    kt_assert_eq!(board_choice.api, 1);
    kt_assert_eq!(board_choice.bdf_type, ATH11K_QMI_BDF_TYPE_ELF);
    kt_assert_eq!(board_choice.sent, board.len());
    kt_assert_eq!(info.regdb_sent, None);
    kt_assert_eq!(info.m3_addr, 0);
    kt_assert_eq!(info.m3_size, 0);
    kt_assert!(info.target_mem.is_empty());
    kt_assert_eq!(
        w.device_bar(),
        Some((SRV_BAR_ADDR, ATH11K_QMI_DEVICE_BAR_SIZE))
    );
    // The exact request sequence: no REQUEST_MEM / FW_MEM_READY on
    // the fixed_fw_mem path, no M3 info, three BDF segments with
    // `end` only on the last (a tail-slice server would drop the
    // first segments and the count would not match).
    kt_assert_eq!(
        server.reqs,
        alloc::vec![
            QMI_WLANFW_IND_REGISTER_REQ_V01,
            QMI_WLANFW_HOST_CAP_REQ_V01,
            QMI_WLANFW_CAP_REQ_V01,
            QMI_WLANFW_DEVICE_INFO_REQ_V01,
            QMI_WLANFW_BDF_DOWNLOAD_REQ_V01,
            QMI_WLANFW_BDF_DOWNLOAD_REQ_V01,
            QMI_WLANFW_BDF_DOWNLOAD_REQ_V01,
        ]
    );
    kt_assert_eq!(server.bdf_segs, alloc::vec![(0, 0), (1, 0), (2, 1)]);
    kt_assert_eq!(server.decode_errs, 0);
    kt_assert!(server.out_qrtr.is_empty());
    kt_assert!(server.fw_ready_sent);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wlfw_over_glink_wcn6750
);

fn smoke_ath11k_wlfw_over_glink_ipq6018() -> TestResult {
    let regs = FakeRegs::quiet();
    let lr = FakeRegs::new();
    let d = FakeDelay::new();
    let k = CountingKick::default();
    let bus = PumpBus::default();
    let (g, r) = glink_smem_edge(&regs, &lr, &d, &k, 1);
    let mut pipe = GlinkQrtr::new(g, bus);
    let Some(lcid) = glink_remote_open(&mut pipe.glink, &r, QRTR_GLINK_CHANNEL, 4, &[(8192, 1)])
    else {
        return TestResult::Fail("no OPEN");
    };
    pipe.poll();
    kt_assert_eq!(pipe.lcid(), Some(u32::from(lcid)));
    let board = elf_board(128);
    let mut files = Files(BTreeMap::new());
    files.0.insert(
        String::from("ath11k/IPQ6018/hw1.0/board.bin"),
        board.clone(),
    );
    let mut server = GlinkWlfwServer::attached(
        r,
        u32::from(lcid),
        ServerChip::Ipq6018,
        fixture_cap(0x21, 0x65, 0x9870, 0x2),
        alloc::vec![alloc::vec![
            MemSeg {
                size: 0x10_0000,
                mem_type: HOST_DDR_REGION_TYPE as i32,
                mem_cfg: Vec::new(),
            },
            MemSeg {
                size: 0x4_0000,
                mem_type: BDF_MEM_REGION_TYPE as i32,
                mem_cfg: Vec::new(),
            },
        ]],
        None,
    );
    let cfg = WlfwConfig::ahb(
        AhbChip::Ipq6018Hw10,
        String::from("1c00000.wifi"),
        Some((0x8000_0000, 0x20_0000)),
    );
    let mut w = match Wlfw::new(pipe, files, TestDma { iomem: Vec::new() }, cfg) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("wlfw new"),
    };
    let Some(info) = pump_to_ready(w.run_to_fw_ready(), &mut server) else {
        return TestResult::Fail("pump exhausted");
    };
    let info = match info {
        Ok(info) => info,
        Err(_) => return TestResult::Fail("wlfw handshake failed"),
    };
    kt_assert_eq!(info.target.chip_id, 0x21);
    kt_assert_eq!(info.target.board_id, 0x65);
    let Some(board_choice) = info.board else {
        return TestResult::Fail("no board choice");
    };
    kt_assert_eq!(board_choice.name.as_str(), "board.bin");
    kt_assert_eq!(board_choice.api, 1);
    kt_assert_eq!(board_choice.bdf_type, ATH11K_QMI_BDF_TYPE_ELF);
    kt_assert_eq!(board_choice.sent, board.len());
    // Masking-defeating: the fixed assignment must list BOTH
    // requested segments, in order, with the region base and the
    // chip's BDF address — a tail-only list would fail here.
    kt_assert_eq!(
        info.target_mem,
        alloc::vec![
            (0x8000_0000, 0x10_0000, HOST_DDR_REGION_TYPE as i32),
            (0x4abc_0000, 0x4_0000, BDF_MEM_REGION_TYPE as i32),
        ]
    );
    kt_assert_eq!(server.respond_mem, info.target_mem);
    kt_assert_eq!(server.init_done_sent, 2);
    kt_assert_eq!(info.mem_delayed_rounds, 0);
    // The fixed-BDF path sends exactly one BDF request, with no data
    // TLV: the board bytes went through the DMA window instead.
    kt_assert_eq!(server.bdf_segs, alloc::vec![(0, 1)]);
    kt_assert_eq!(server.bdf_data, alloc::vec![false]);
    // ...and the window write is exactly the board file at the
    // chip's BDF address (read back through `Wlfw`'s public DMA).
    kt_assert_eq!(w.dma.iomem, alloc::vec![(0x4abc_0000, 0, board.clone())]);
    kt_assert_eq!(server.decode_errs, 0);
    kt_assert!(server.out_qrtr.is_empty());
    kt_assert_eq!(
        server.reqs,
        alloc::vec![
            QMI_WLANFW_IND_REGISTER_REQ_V01,
            QMI_WLANFW_HOST_CAP_REQ_V01,
            QMI_WLANFW_RESPOND_MEM_REQ_V01,
            QMI_WLANFW_CAP_REQ_V01,
            QMI_WLANFW_BDF_DOWNLOAD_REQ_V01,
            QMI_WLANFW_M3_INFO_REQ_V01,
            QMI_WLANFW_WLAN_MODE_REQ_V01,
        ]
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wlfw_over_glink_ipq6018
);

fn smoke_ath11k_wlfw_over_glink_host_cap_failure() -> TestResult {
    let regs = FakeRegs::quiet();
    let lr = FakeRegs::new();
    let d = FakeDelay::new();
    let k = CountingKick::default();
    let bus = PumpBus::default();
    let (g, r) = glink_smem_edge(&regs, &lr, &d, &k, 1);
    let mut pipe = GlinkQrtr::new(g, bus);
    let Some(lcid) = glink_remote_open(&mut pipe.glink, &r, QRTR_GLINK_CHANNEL, 4, &[(8192, 1)])
    else {
        return TestResult::Fail("no OPEN");
    };
    pipe.poll();
    kt_assert_eq!(pipe.lcid(), Some(u32::from(lcid)));
    let mut server = GlinkWlfwServer::attached(
        r,
        u32::from(lcid),
        ServerChip::Wcn6750,
        fixture_cap(0x12, 0x56, 0x7890, 0x1),
        Vec::new(),
        Some((SRV_BAR_ADDR, ATH11K_QMI_DEVICE_BAR_SIZE)),
    );
    server.fail_req = Some((QMI_WLANFW_HOST_CAP_REQ_V01, 1));
    let cfg = WlfwConfig::ahb(AhbChip::Wcn6750Hw10, String::from("c000000.wifi"), None);
    let mut w = match Wlfw::new(
        pipe,
        Files(BTreeMap::new()),
        TestDma { iomem: Vec::new() },
        cfg,
    ) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("wlfw new"),
    };
    let Some(r) = pump_to_ready(w.run_to_fw_ready(), &mut server) else {
        return TestResult::Fail("pump exhausted");
    };
    // Verification where it belongs: a failed result is refused, and
    // the handshake stops before any later request.
    kt_assert!(matches!(r, Err(e) if e.step == step::HOST_CAP));
    kt_assert_eq!(
        server.reqs,
        alloc::vec![QMI_WLANFW_IND_REGISTER_REQ_V01, QMI_WLANFW_HOST_CAP_REQ_V01,]
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wlfw_over_glink_host_cap_failure
);

/// Byte-for-byte pins for the QRTR control frames the server sends,
/// written out by hand from the `uapi/linux/qrtr.h` header layout and
/// `net/qrtr/ns.c` (`struct qrtr_ctrl_pkt`: 5 LE words, unused words
/// zero), not from the encoder under test.
fn test_ath11k_qrtr_hello_newserver_bytes() -> TestResult {
    let hello = match encode_packet(
        QRTR_TYPE_HELLO,
        DEV_CTRL,
        HOST_CTRL_BCAST,
        false,
        &CtrlPkt::Hello.to_bytes(),
    ) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("hello encode"),
    };
    let mut want = Vec::new();
    for w in [
        1u32,
        2,
        DEV_NODE,
        QRTR_PORT_CTRL,
        0,
        20,
        QRTR_NODE_BCAST,
        QRTR_PORT_CTRL,
    ] {
        want.extend_from_slice(&w.to_le_bytes());
    }
    for w in [QRTR_TYPE_HELLO, 0, 0, 0, 0] {
        want.extend_from_slice(&w.to_le_bytes());
    }
    kt_assert_eq!(hello, want);
    let ns = match encode_packet(
        QRTR_TYPE_NEW_SERVER,
        DEV_CTRL,
        HOST_CTRL_BCAST,
        false,
        &CtrlPkt::NewServer {
            service: ATH11K_QMI_WLFW_SERVICE_ID_V01,
            instance: qmi_instance(
                ATH11K_QMI_WLFW_SERVICE_VERS_V01,
                ATH11K_QMI_WLFW_SERVICE_INS_ID_V01_WCN6750,
            ),
            node: DEV_NODE,
            port: SRV_PORT,
        }
        .to_bytes(),
    ) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("new server encode"),
    };
    let mut want = Vec::new();
    for w in [
        1u32,
        4,
        DEV_NODE,
        QRTR_PORT_CTRL,
        0,
        20,
        QRTR_NODE_BCAST,
        QRTR_PORT_CTRL,
    ] {
        want.extend_from_slice(&w.to_le_bytes());
    }
    for w in [
        QRTR_TYPE_NEW_SERVER,
        ATH11K_QMI_WLFW_SERVICE_ID_V01,
        qmi_instance(
            ATH11K_QMI_WLFW_SERVICE_VERS_V01,
            ATH11K_QMI_WLFW_SERVICE_INS_ID_V01_WCN6750,
        ),
        DEV_NODE,
        SRV_PORT,
    ] {
        want.extend_from_slice(&w.to_le_bytes());
    }
    kt_assert_eq!(ns, want);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    test_ath11k_qrtr_hello_newserver_bytes
);

/// WCN6750 through the real bring-up with the fake server behind the
/// GLINK edge: the WLFW phase completes (DEVICE_INFO BAR mapped into
/// the HIF's register space, firmware_start's QMI sent), and the core
/// is stranded waiting for HTC target-ready — the CE/HTC/WMI target
/// fake is the next fixture, not this lane's scope.
fn smoke_ath11k_ahb_live_wcn6750_wlfw_server() -> TestResult {
    let blob: &'static [u8] = Box::leak(sc7280_wifi_dt().into_boxed_slice());
    let node = find_ahb_devices(blob)[0].0.clone();
    let p = Box::new(AhbPlatform::probe(blob, &node).unwrap());
    // fatal 0, ready 1, handover 2, stop-ack 3, shutdown-ack 7.
    let mut env = env_for(&p, (1 << 1) | (1 << 2), (1 << 3) | (1 << 7));
    env.files.insert(
        String::from("ath11k/WCN6750/hw1.0/board.bin"),
        elf_board(6144 * 2 + 100),
    );
    let smem_regs = env.smem;
    let (pid, size) = (env.pid, env.smem_size);
    let smem = Smem::probe(smem_regs, size).unwrap();
    let mut live = Box::new(LiveAhb::new(*env, blob));
    // The pinned bring-up future borrows `live` until the future
    // itself drops, and `drop()` on the `pin!` guard does not drop
    // the future — so the poll loop lives in its own block, and the
    // borrow ends at the block's close, before anything below reads
    // `live` again.
    let mut server: Option<GlinkWlfwServer<'_>> = None;
    let out = {
        let mut fut = pin!(bring_up(&p, &mut *live));
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut out = None;
        for _ in 0..200_000 {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                out = Some(v);
                break;
            }
            if server.is_none() {
                // Attach once the host registered the edge (descriptor
                // 478 + host TX FIFO 479 + pre-allocated remote FIFO 480).
                if let (Ok(d), Ok(tx), Ok(rx)) = (
                    smem.get(pid, SMEM_GLINK_NATIVE_XPRT_DESCRIPTOR),
                    smem.get(pid, SMEM_GLINK_NATIVE_XPRT_FIFO_0),
                    smem.get(pid, SMEM_GLINK_NATIVE_XPRT_FIFO_1),
                ) {
                    server = Some(GlinkWlfwServer::unattached(
                        GlinkRemote {
                            regs: smem_regs,
                            desc: d.offset,
                            host_tx: (tx.offset, tx.len),
                            host_rx: (rx.offset, rx.len),
                        },
                        ServerChip::Wcn6750,
                        fixture_cap(0x12, 0x56, 0x7890, 0x1),
                        Vec::new(),
                        Some((SRV_BAR_ADDR, ATH11K_QMI_DEVICE_BAR_SIZE)),
                    ));
                }
            }
            if let Some(s) = server.as_mut() {
                s.pump();
            }
        }
        out
    };
    let Some(r) = out else {
        return TestResult::Fail("bring_up did not settle");
    };
    // The WLFW phase passed: the failure is in qmi_ready's core half,
    // not in the handshake — and the core is kept, not freed.
    kt_assert!(matches!(r, Err((BringUpStep::QmiReady, _))));
    kt_assert!(matches!(&live.outcome, Some(LiveOutcome::Stranded(..))));
    let Some(s) = server else {
        return TestResult::Fail("server never attached");
    };
    // DEVICE_INFO BAR mapping: the bring-up mapped exactly the BAR
    // the server reported.
    kt_assert!(live
        .env
        .maps
        .contains_key(&(SRV_BAR_ADDR, ATH11K_QMI_DEVICE_BAR_SIZE as u64)));
    // firmware_start's QMI went out over the server: the WLFW phase
    // ran to completion through the real bring-up path, and the
    // stranded core's unwind told the firmware wlan_mode OFF
    // (firmware_stop in firmware_ready_inner's error path, as Linux
    // does on core-start failure) — that trailing WLAN_MODE is the
    // unwind's, not a second firmware_start.
    kt_assert_eq!(
        s.reqs,
        alloc::vec![
            QMI_WLANFW_IND_REGISTER_REQ_V01,
            QMI_WLANFW_HOST_CAP_REQ_V01,
            QMI_WLANFW_CAP_REQ_V01,
            QMI_WLANFW_DEVICE_INFO_REQ_V01,
            QMI_WLANFW_BDF_DOWNLOAD_REQ_V01,
            QMI_WLANFW_BDF_DOWNLOAD_REQ_V01,
            QMI_WLANFW_BDF_DOWNLOAD_REQ_V01,
            QMI_WLANFW_WLAN_CFG_REQ_V01,
            QMI_WLANFW_WLAN_MODE_REQ_V01,
            // Unwind: firmware_stop's wlan_mode OFF after the
            // stranded core-start failure.
            QMI_WLANFW_WLAN_MODE_REQ_V01,
        ]
    );
    kt_assert_eq!(s.bdf_segs, alloc::vec![(0, 0), (1, 0), (2, 1)]);
    kt_assert_eq!(s.decode_errs, 0);
    kt_assert!(s.out_qrtr.is_empty());
    kt_assert!(s.fw_ready_sent);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_ahb_live_wcn6750_wlfw_server
);

// ── post-boot SMP2P crash monitoring / recovery ─────────────────────

/// Boot the IPQ6018 fixture remote to `Running` without the WLFW leg
/// (no server behind the GLINK edge): the state a post-boot crash
/// monitor observes. Step failures surface at the caller's `Running`
/// assertion.
fn booted_live() -> (Box<LiveAhb<Env>>, Box<AhbPlatform>) {
    let blob: &'static [u8] =
        Box::leak(ipq6018_wifi_dt("qcom,ipq6018-wifi", &SPIS).into_boxed_slice());
    let node = find_ahb_devices(blob)[0].0.clone();
    let p = Box::new(AhbPlatform::probe(blob, &node).unwrap());
    // fatal 0, ready 1, handover 2, stop-ack 3.
    let env = env_for(&p, (1 << 1) | (1 << 2), 1 << 3);
    let mut live = Box::new(LiveAhb::new(*env, blob));
    let _ = live.hal_ce_alloc(&p);
    let _ = live.qmi_init_service(&p);
    let _ = run(live.rproc_irqs(&p));
    let _ = run(live.rproc_boot(&p));
    let _ = run(live.glink_start(&p));
    (live, p)
}

/// The fixture remote's `slave-kernel` value word.
fn slave_kernel_word(live: &LiveAhb<Env>) -> u32 {
    live.env.remote + 20 + 16
}

/// Post-boot crash monitor: no crash while the remote runs clean, then
/// the remote's SMP2P `fatal` bit is observed as `Crash::Fatal` and the
/// remoteproc latches `Crashed`.
fn smoke_ath11k_ahb_live_smp2p_crash_fatal() -> TestResult {
    let (mut live, p) = booted_live();
    kt_assert_eq!(live.rproc_state(), Some(RprocState::Running));
    kt_assert!(live.monitor_tick(&p).is_none(), "clean while running");
    let word = slave_kernel_word(&live);
    live.env.smem.set(word, (1 << 1) | (1 << 2) | (1 << 0));
    kt_assert_eq!(live.monitor_tick(&p), Some(Crash::Fatal), "fatal observed");
    kt_assert_eq!(live.rproc_state(), Some(RprocState::Crashed));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_ahb_live_smp2p_crash_fatal
);

/// Same, for the `wdog` GIC line: the IRQ handler's effect is simulated
/// by signalling the Q6 directly (the fixture binds the line but has no
/// GIC to raise it), and the monitor observes `Crash::Watchdog`.
fn smoke_ath11k_ahb_live_smp2p_crash_wdog() -> TestResult {
    let (mut live, p) = booted_live();
    kt_assert_eq!(live.rproc_state(), Some(RprocState::Running));
    kt_assert!(live.rproc.is_some(), "remoteproc exists after boot");
    let q6 = match &live.rproc {
        Some(super::Rproc::Wcss { w, .. }) => w.q6,
        Some(super::Rproc::Pas { p: pas, .. }) => pas.q6,
        None => unreachable!("remoteproc exists"),
    };
    q6.signal(Q6Event::Wdog);
    kt_assert_eq!(
        live.monitor_tick(&p),
        Some(Crash::Watchdog),
        "wdog observed"
    );
    kt_assert_eq!(live.rproc_state(), Some(RprocState::Crashed));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_ahb_live_smp2p_crash_wdog
);

/// Crash recovery through the remote restart: after a `fatal` crash the
/// restart shuts the dead remote down, boots it again (the fixture
/// remote re-asserts `ready` on the next boot) and re-registers GLINK;
/// the WLFW leg then times out — there is no WLFW server behind the
/// fixture edge (that fixture is the WLFW lane's) — so the restart
/// reports the timeout while the remote is back `Running`.
fn smoke_ath11k_ahb_live_smp2p_crash_restart() -> TestResult {
    let (mut live, p) = booted_live();
    kt_assert_eq!(live.rproc_state(), Some(RprocState::Running));
    let word = slave_kernel_word(&live);
    live.env.smem.set(word, (1 << 1) | (1 << 2) | (1 << 0));
    kt_assert_eq!(live.monitor_tick(&p), Some(Crash::Fatal));
    kt_assert_eq!(live.rproc_state(), Some(RprocState::Crashed));
    // Script the fake remote for the next boot: its item value drops
    // (the restarted remote recreates it) and the tick script restarts
    // so `ready` is re-asserted on the re-boot's second tick. The
    // shutdown from `Crashed` runs no pump, so the ticks survive it.
    live.env.smem.set(word, 0);
    live.env.ticks.store(0, Ordering::Relaxed);
    let r = run(live.restart_transport(&p));
    kt_assert!(
        matches!(r, Some(Err(AhbError::Failed(_)))),
        "WLFW leg times out without a server"
    );
    kt_assert_eq!(
        live.rproc_state(),
        Some(RprocState::Running),
        "remote restarted"
    );
    // `glink_start` re-ran: the GLINK descriptor is allocated.
    let smem = Smem::probe(live.env.smem, live.env.smem_size).unwrap();
    kt_assert!(
        smem.get(live.env.pid, SMEM_GLINK_NATIVE_XPRT_DESCRIPTOR)
            .is_ok(),
        "glink re-registered"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_ahb_live_smp2p_crash_restart
);

/// SMP2P SSR restart ack: when the restarted remote raises
/// `RESTART_DONE`, the monitor's edge pass raises the host's
/// `RESTART_ACK` bit (Linux `qcom_smp2p_do_ssr_ack`), without
/// reporting a crash.
fn smoke_ath11k_ahb_live_smp2p_ssr_ack() -> TestResult {
    let (mut live, p) = booted_live();
    kt_assert_eq!(live.rproc_state(), Some(RprocState::Running));
    live.env
        .smem
        .set(live.env.remote + 16, 1 << FLAGS_RESTART_DONE_BIT);
    kt_assert!(live.monitor_tick(&p).is_none(), "ack is not a crash");
    let out_off = {
        let g = live.edges.lock();
        g[0].smp2p.outbound_item().offset
    };
    kt_assert_eq!(
        live.env.smem.get(out_off + 16) & (1 << FLAGS_RESTART_ACK_BIT),
        1 << FLAGS_RESTART_ACK_BIT,
        "SSR ack bit set"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_ahb_live_smp2p_ssr_ack
);

/// The `ath11k_core_reset` failure gate, shared by the runtime loop and
/// the AHB crash monitor: FINAL gates regardless of the window, FIRST
/// gates only inside it, and the window boundary itself does not gate.
fn smoke_ath11k_ahb_live_recovery_gated() -> TestResult {
    kt_assert!(!recovery_gated(0, 20_000, 0), "zero failures");
    kt_assert!(
        !recovery_gated(ATH11K_RESET_MAX_FAIL_COUNT_FIRST - 1, 20_000, 0),
        "below FIRST"
    );
    kt_assert!(
        recovery_gated(ATH11K_RESET_MAX_FAIL_COUNT_FIRST, 20_000, 19_999),
        "FIRST inside window"
    );
    kt_assert!(
        !recovery_gated(ATH11K_RESET_MAX_FAIL_COUNT_FIRST, 20_000, 20_000),
        "window boundary does not gate"
    );
    kt_assert!(
        recovery_gated(ATH11K_RESET_MAX_FAIL_COUNT_FINAL, 20_000, 999_999),
        "FINAL gates regardless of window"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_ahb_live_recovery_gated
);

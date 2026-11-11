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
//! past FW_READY has a CE/HTC/WMI target fake ([`CeTargetFake`]): it
//! plays the target's CE rings (HTC READY, CONNECT_SERVICE, WMI
//! SERVICE_READY / READY, HTT VERSION_CONF), so the WCN6750 core-start
//! test runs past `firmware_start` to `LiveOutcome::Ready`. The IPQ6018
//! variant drives a direct IPQ6018 core (its WLFW leg is the separate
//! `smoke_ath11k_wlfw_over_glink_ipq6018`) on the IPQ6018 service map
//! through two-radio core start and `runtime::start_ahb`
//! (`smoke_ath11k_ahb_ipq6018_core_start_ce_fake`).

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
// ── CE/HTC/WMI target fake ──────────────────────────────────────────
//
// The target side of the copy engines: a `CeTargetFake` plays the
// firmware's CE rings (Linux `ath11k_ce_recv_process_cb` /
// `ath11k_ce_send` in reverse) so the post-FW_READY core-start path
// runs past `firmware_start` in fixtures. It is pumped once per host
// poll next to the WLFW server: it consumes host→target frames from
// the source rings, answers them on the destination rings, and raises
// the CE interrupt for each CE it delivered on
// (`ce::raise_ce`, the same wake the AHB per-CE GIC lines use).
//
// Grounding (every constant / format / transition below cites its
// source; nothing is copied from production or from the HIF-level
// `Fw` in `core_tests.rs`, which is the cross-check party, not the
// source):
// - HTC header + control messages + credit records: Linux
//   `drivers/net/wireless/ath/ath11k/htc.h` (TI 11.00.09),
//   `ath11k_htc_hdr`, `ath11k_htc_ready`,
//   `ath11k_htc_conn_svc_resp`, `ath11k_htc_record_hdr` /
//   `ath11k_htc_credit_report`, `ATH11K_HTC_FLAG_TRAILER_PRESENT =
//   0x02`, `ATH11K_HTC_RECORD_CREDITS = 1`.
// - Service → CE map: Linux `hw.c`
//   `ath11k_target_service_to_ce_map_wlan_qca6390` (the table passed
//   to the target at startup): WMI_CONTROL OUT→3 IN→2, RSVD_CTRL
//   OUT→0 IN→2, HTT_DATA_MSG OUT→4 IN→1. The control answers
//   therefore go on CE2, not CE1: the CE-config comment "CE1:
//   target->host HTT + HTC control" describes the CE, while the
//   service map governs where the target sends each service (and
//   QCN9074's map differs — RSVD_CTRL IN→1). The host routes by HTC
//   endpoint id either way, so this is fidelity, not function — but
//   the fake follows the map, and the test passing proves the host
//   does not depend on the CE1 assumption the HIF-level fixture
//   (`core_tests.rs` `CTRL_DL = 1`) makes.
// - WMI event ids + TLV tags + service bits: Linux `wmi.h`
//   (`enum wmi_tlv_event_id`, `enum wmi_tlv_tag`,
//   `enum wmi_tlv_service`), cross-checked against in-tree
//   `wmi_ids.rs` and the passing HIF-level fixture, which exercises
//   the same host decoders with the same values.
// - WMI fixed structs: Linux `wmi.h` `struct wmi_service_ready_event`
//   (caps at the offsets the host decodes), `struct
//   wmi_service_available_event`, `struct wmi_service_ready_ext_event`
//   (+ `wmi_ppe_threshold`, 10 words: `WMI_MAX_NUM_SS =
//   MAX_HE_NSS = 8`), `struct wmi_soc_mac_phy_hw_mode_caps`,
//   `struct wmi_hw_mode_capabilities`, `struct
//   wmi_mac_phy_capabilities` (59 words in-tree, incl. the
//   wireless-modes / channel / nss_ratio tail), `struct
//   wmi_hal_reg_capabilities_ext`, `struct wmi_dma_ring_capabilities`,
//   `struct wmi_ready_event` (+ `wmi_ready_event_min`).
// - CE ring protocol: in-tree `hal.rs` / `ce.rs` (the documented
//   contract): source-ring TP in words via `rdp[ring_id]`
//   (`hw_ptr_idx = ring_id`), descriptors zeroed after consume (the
//   host rewrites all words on reuse, so a stale nonzero descriptor
//   would be re-consumed on wrap); destination status word 0 =
//   `len << 16`, HP in words via `rdp[status_ring_id]`; RX slot ==
//   the host's destination `sw_index`, lockstep from 0.
// - HTT version: `htt.rs` `version_ok` checks the major only
//   (`HTT_TARGET_VERSION_MAJOR = 3`); the minor is target-reported
//   (0x51, as in the HIF-level fixture).
//
// What the fake does NOT do: it never advertises
// `WMI_TLV_SERVICE_REG_CC_EXT_EVENT_SUPPORT` (281) — the
// `REG_CHAN_LIST_CC_EXT` fixed struct is ~78 words and its Linux
// definition was not located in `wmi.h` (only the decoder's word
// indices), so a fake event would be half-grounded; core start does
// not wait for reg info, and the HIF-level fixture already covers
// the reg path. A future lane can add it once the struct is
// grounded.
//
// The fake answers CONNECT_SERVICE for HTT_DATA_MSG, WMI_CONTROL and
// WMI_CONTROL_MAC1: WCN6750 is single-pdev (`wmi_ep_count = 1`) and
// never connects MAC1; IPQ6018 (`max_radios = 2`, `wmi_ep_count = 2`)
// does, and its MAC1 commands arrive on CE7. WMI_CONTROL_MAC2 (IPQ8074
// only, three radios) is not answered.
//
// The fake holds raw pointers to the ring / bounce buffers, captured
// after `hal_ce_alloc` while the test owns `live`: the buffers never
// move (only the owning `Ce` / `DmaMem` structs do, when `core_ready`
// takes the `Ce` into the core), so the pointers stay valid across
// the bring-up future. The capture fails (`None`) if a pipe's
// geometry is inconsistent — the test then fails loudly instead of
// playing a target on the wrong rings.
use super::super::ce::Ce;
use super::super::hal::{ce_get_desc_size, get_ring_id, HalCeDesc, HalRingType};

/// Target→host CE pipes for one service map (Linux `hw.c`
/// `ath11k_target_service_to_ce_map_*`).
#[derive(Copy, Clone, Debug)]
struct TargetCeMap {
    /// HTC control answers (READY, CONNECT_SERVICE_RESP).
    ctrl_dl: u32,
    /// WMI events.
    wmi_dl: u32,
    /// HTT target→host messages.
    htt_dl: u32,
}

/// QCA6390 / WCN6750 (Linux `hw.c`
/// `ath11k_target_service_to_ce_map_wlan_qca6390`): RSVD_CTRL IN→2,
/// WMI_CONTROL IN→2, HTT_DATA_MSG IN→1.
const TARGET_CE_MAP_QCA6390: TargetCeMap = TargetCeMap {
    ctrl_dl: 2,
    wmi_dl: 2,
    htt_dl: 1,
};

/// IPQ6018 (Linux `hw.c` `ath11k_target_service_to_ce_map_wlan_ipq6018`):
/// RSVD_CTRL IN→1, WMI_CONTROL and WMI_CONTROL_MAC1 IN→2, HTT_DATA_MSG
/// IN→1. Host→target: RSVD_CTRL OUT→0, WMI_CONTROL OUT→3,
/// WMI_CONTROL_MAC1 OUT→7, HTT_DATA_MSG OUT→4.
const TARGET_CE_MAP_IPQ6018: TargetCeMap = TargetCeMap {
    ctrl_dl: 1,
    wmi_dl: 2,
    htt_dl: 1,
};

/// The target MAC the fake reports in the WMI READY event — the same
/// fixture value as the HIF-level `Fw` (`core_tests.rs` `FW_MAC`), so
/// the core's `mac_addr` assertion matches the established fixture.
const TGT_MAC: [u8; 6] = [0x00, 0x03, 0x7f, 0x12, 0x34, 0x56];

/// HTC message ids (Linux `htc.h` `enum ath11k_htc_msg_id`).
mod htc_msg {
    pub const READY: u16 = 1;
    pub const CONNECT_SERVICE: u16 = 2;
    pub const CONNECT_SERVICE_RESP: u16 = 3;
    pub const SETUP_COMPLETE_EX: u16 = 5;
}

/// HTC service ids (Linux `htc.h` `ATH11K_HTC_SVC_ID_*`).
mod htc_svc {
    pub const WMI_CONTROL: u16 = 0x0100;
    /// `SVC(ATH11K_HTC_SVC_GRP_WMI, 5)`.
    pub const WMI_CONTROL_MAC1: u16 = 0x0105;
    pub const HTT_DATA_MSG: u16 = 0x0300;
}

/// HTC endpoint ids (Linux `htc.h` `enum ath11k_htc_ep_id`). The
/// target assigns them in CONNECT_SERVICE_RESP; the fake hands out the
/// next free id per connected service.
mod htc_ep {
    pub const HTT: u8 = 1;
    pub const WMI: u8 = 2;
    pub const WMI_MAC1: u8 = 3;
}

/// WMI event ids (Linux `wmi.h` `enum wmi_tlv_event_id`).
mod wmi_ev {
    pub const SERVICE_READY: u32 = 0x1;
    pub const READY: u32 = 0x2;
    pub const SERVICE_AVAILABLE: u32 = 0x3;
    pub const SERVICE_READY_EXT: u32 = 0x4009;
    pub const SERVICE_READY_EXT2: u32 = 0x4022;
}

/// WMI TLV tags (Linux `wmi.h` `enum wmi_tlv_tag`).
mod wmi_tag {
    pub const ARRAY_UINT32: u16 = 0x10;
    pub const ARRAY_STRUCT: u16 = 0x12;
    pub const ARRAY_FIXED_STRUCT: u16 = 0x13;
    pub const SERVICE_READY_EVENT: u16 = 0x20;
    pub const READY_EVENT: u16 = 0x23;
    pub const SERVICE_READY_EXT_EVENT: u16 = 0x1ac;
    pub const MAC_PHY_CAPABILITIES: u16 = 0x210;
    pub const HW_MODE_CAPABILITIES: u16 = 0x211;
    pub const SOC_MAC_PHY_HW_MODE_CAPS: u16 = 0x212;
    pub const HAL_REG_CAPABILITIES_EXT: u16 = 0x213;
    pub const SOC_HAL_REG_CAPABILITIES: u16 = 0x214;
    pub const SERVICE_AVAILABLE_EVENT: u16 = 0x22f;
    pub const DMA_RING_CAPABILITIES: u16 = 0x2bf;
}

/// WMI service bits (Linux `wmi.h` `enum wmi_tlv_service`).
mod wmi_svc_bit {
    /// `WMI_TLV_SERVICE_EXT2_MSG` (220): SERVICE_AVAILABLE segment
    /// word 2 bit 28 (services 128..256, word (220-128)/32 = 2).
    pub const EXT2_MSG_SEG_W2: u32 = 1 << 28;
}

/// WMI command ids (Linux `wmi.h` `enum wmi_tlv_cmd_id`).
mod wmi_cmd {
    pub const INIT: u32 = 0x1;
}

/// Hardware modes (Linux `wmi.h` `enum wmi_phy_mode` is the channel
/// mode; the hw-mode enum is `SINGLE = 0, DBS = 1, ...`).
mod hw_mode {
    pub const SINGLE: u32 = 0;
    pub const DBS: u32 = 1;
}

/// What the fake target does: the default mirrors the HIF-level `Fw`
/// script where the host constrains the values (credits, credit
/// size, endpoint ids, max message sizes, HTT version), and the
/// negative knobs let a test prove the host actually consults the
/// target's answers.
#[derive(Clone, Debug)]
struct CeTargetScript {
    /// HTC READY credit count (host rejects 0).
    credits: u16,
    /// HTC READY credit size.
    credit_size: u16,
    /// Answer HTT CONNECT_SERVICE.
    htt_reply: bool,
    /// Status in the HTT CONNECT_SERVICE_RESP (0 = SUCCESS).
    htt_status: u8,
    /// Answer WMI_CONTROL CONNECT_SERVICE.
    wmi_reply: bool,
    /// Status in the WMI CONNECT_SERVICE_RESP (0 = SUCCESS).
    wmi_status: u8,
    /// Send SERVICE_READY / AVAILABLE / EXT on SETUP_COMPLETE_EX.
    svc_ready: bool,
    /// Advertise `WMI_TLV_SERVICE_EXT2_MSG` in SERVICE_AVAILABLE.
    advertise_ext2: bool,
    /// Send the EXT2 event (only meaningful with `advertise_ext2`).
    send_ext2: bool,
    /// Send the READY event on WMI INIT.
    ready_event: bool,
    /// Return the INIT command's credit with the READY event.
    return_init_credit: bool,
    /// Answer HTT VERSION_REQ with VERSION_CONF.
    htt_version_conf: bool,
    /// MAC reported in the READY event.
    mac: [u8; 6],
    /// Per-radio MACs in the READY event's `ARRAY_FIXED_STRUCT`
    /// (`num_extra_mac_addr`; Linux `ath11k_wmi_tlv_rdy_parse` uses
    /// them only when `num_radios > 1`). Empty on single-pdev parts.
    extra_macs: Vec<[u8; 6]>,
}

impl Default for CeTargetScript {
    fn default() -> Self {
        CeTargetScript {
            credits: 15,
            credit_size: 1792,
            htt_reply: true,
            htt_status: 0,
            wmi_reply: true,
            wmi_status: 0,
            svc_ready: true,
            advertise_ext2: true,
            send_ext2: true,
            ready_event: true,
            return_init_credit: true,
            htt_version_conf: true,
            mac: TGT_MAC,
            extra_macs: Vec::new(),
        }
    }
}

/// One CE ring as the target sees it: descriptor memory + the rdp
/// word the target publishes, all in 32-bit words (the HAL's units).
struct FakeRing {
    /// CPU pointer to the descriptor memory (stable: the buffer never
    /// moves).
    mem: *mut u8,
    /// HAL ring id == rdp word index (`hw_ptr_idx = ring_id`).
    ring_id: u32,
    nentries: u32,
    /// Descriptor size in words.
    entry_words: u32,
    /// The fake's own position in words: read position (source
    /// rings) / next status entry (status rings).
    pos_words: u32,
}

/// One DMA bounce buffer as the target sees it.
struct FakeBuf {
    mem: *mut u8,
    paddr: u64,
}

/// One CE pipe as the target sees it.
struct FakePipe {
    ce: u32,
    buf_sz: u32,
    src: Option<FakeRing>,
    dst: Option<FakeRing>,
    status: Option<FakeRing>,
    tx_buf: Option<FakeBuf>,
    rx_buf: Option<FakeBuf>,
    /// Next RX slot to fill (== the host's destination `sw_index`,
    /// lockstep from 0).
    rx_next: u32,
}

/// The CE/HTC/WMI target fake. Holds raw pointers only (see the
/// module docs); `pump` is single-threaded with the host poll loop,
/// so no locking is needed.
struct CeTargetFake {
    script: CeTargetScript,
    map: TargetCeMap,
    pipes: Vec<FakePipe>,
    /// `rdp` CPU pointer (one word per HAL ring id).
    rdp: *mut u32,
    /// Queued target→host HTC frames per destination CE.
    dl_queue: [VecDeque<Vec<u8>>; 9],
    /// Observations for the tests.
    ready_sent: bool,
    conn_resp_htt: bool,
    conn_resp_wmi: bool,
    svc_ready_sent: bool,
    svc_avail_sent: bool,
    svc_ext_sent: bool,
    ext2_sent: bool,
    ready_event_sent: bool,
    ver_conf_sent: bool,
    connect_htt_seen: bool,
    connect_wmi_seen: bool,
    /// WMI_CONTROL_MAC1 connect seen / answered (multi-pdev only).
    connect_wmi1_seen: bool,
    conn_resp_wmi1: bool,
    /// WMI commands consumed on the MAC1 endpoint.
    wmi1_cmds: usize,
    setup_complete_seen: bool,
    init_seen: bool,
    ver_req_seen: bool,
    sring_setup_seen: usize,
    /// Host→target frames consumed (all UL pipes).
    ul_frames: usize,
    /// Protocol violations observed (bad descriptor paddr / length,
    /// unparseable frame, undeliverable DL frame). The tests assert 0.
    errors: usize,
}

/// Volatile u32 read at a byte offset (the host reads ring words
/// through `DmaMem::rd32`, volatile; the fake matches).
unsafe fn tgt_rd32(ptr: *const u8, byte_off: usize) -> u32 {
    // SAFETY: caller guarantees `ptr + byte_off` is a mapped, aligned
    // u32 inside a captured buffer.
    unsafe { core::ptr::read_volatile(ptr.add(byte_off) as *const u32) }
}

/// Volatile u32 write at a byte offset.
unsafe fn tgt_wr32(ptr: *mut u8, byte_off: usize, v: u32) {
    // SAFETY: as `tgt_rd32`; the protocol never has both sides write
    // the same word.
    unsafe { core::ptr::write_volatile(ptr.add(byte_off) as *mut u32, v) }
}

impl CeTargetFake {
    /// Capture the CE ring handles from `ce` (after `hal_ce_alloc`,
    /// before the bring-up future moves the `Ce`). `None` when the CE
    /// is missing or a pipe's geometry is inconsistent.
    fn capture(ce: &Ce, map: TargetCeMap, script: CeTargetScript) -> Option<Self> {
        let mut pipes = Vec::new();
        for i in 0..ce.ce_count() as u32 {
            let Some(p) = ce.pipe(i) else {
                continue;
            };
            let src = Self::capture_ring(
                ce,
                p.src_ring_mem(),
                p.src_indices().map(|(n, _, _)| n),
                HalRingType::CeSrc,
                HalCeDesc::Src,
                i,
            )?;
            let dst = Self::capture_ring(
                ce,
                p.dst_ring_mem(),
                p.dest_indices().map(|(n, _, _)| n),
                HalRingType::CeDst,
                HalCeDesc::Dst,
                i,
            )?;
            // The status ring has one entry per destination entry.
            let status = Self::capture_ring(
                ce,
                p.status_ring_mem(),
                p.dest_indices().map(|(n, _, _)| n),
                HalRingType::CeDstStatus,
                HalCeDesc::DstStatus,
                i,
            )?;
            let tx_buf = p.tx_buf_mem().map(|b| FakeBuf {
                mem: b.cpu_mut_ptr(),
                paddr: b.paddr(),
            });
            let rx_buf = p.rx_buf_mem().map(|b| FakeBuf {
                mem: b.cpu_mut_ptr(),
                paddr: b.paddr(),
            });
            // A pipe with neither rings nor buffers (CE6/CE8
            // autonomous) has nothing for the target to do.
            if src.is_none() && dst.is_none() && status.is_none() && tx_buf.is_none() {
                continue;
            }
            pipes.push(FakePipe {
                ce: i,
                buf_sz: p.buf_sz,
                src,
                dst,
                status,
                tx_buf,
                rx_buf,
                rx_next: 0,
            });
        }
        let rdp = ce.hal.rdp.cpu_mut_ptr() as *mut u32;
        let mut fake = CeTargetFake {
            script,
            map,
            pipes,
            rdp,
            dl_queue: core::array::from_fn(|_| VecDeque::new()),
            ready_sent: false,
            conn_resp_htt: false,
            conn_resp_wmi: false,
            svc_ready_sent: false,
            svc_avail_sent: false,
            svc_ext_sent: false,
            ext2_sent: false,
            ready_event_sent: false,
            ver_conf_sent: false,
            connect_htt_seen: false,
            connect_wmi_seen: false,
            connect_wmi1_seen: false,
            conn_resp_wmi1: false,
            wmi1_cmds: 0,
            setup_complete_seen: false,
            init_seen: false,
            ver_req_seen: false,
            sring_setup_seen: 0,
            ul_frames: 0,
            errors: 0,
        };
        // The target's first word, as soon as the host posts RX: HTC
        // READY (the host's `htc_wait_target` waits for it). Queued
        // now, delivered on the first pump with a posted RX buffer —
        // `rx_post_buf` runs in `hif.start()`, before the wait.
        let ready = Self::ready_msg(fake.script.credits, fake.script.credit_size, 8);
        fake.queue_ctrl(&ready);
        fake.ready_sent = true;
        Some(fake)
    }

    /// One ring's capture: descriptor memory + HAL ring id + geometry.
    /// `mem` is `None` for pipes without that ring; returns `None`
    /// (capture fails) on inconsistent geometry.
    fn capture_ring(
        ce: &Ce,
        mem: Option<&super::super::hal::DmaMem>,
        nentries: Option<u32>,
        ty: HalRingType,
        desc: HalCeDesc,
        ce_id: u32,
    ) -> Option<Option<FakeRing>> {
        let (Some(mem), Some(nentries)) = (mem, nentries) else {
            return Some(None);
        };
        let desc_bytes = ce_get_desc_size(desc);
        if nentries == 0 || desc_bytes % 4 != 0 || mem.len() != nentries as usize * desc_bytes {
            return None;
        }
        let ring_id = get_ring_id(&ce.hal.config, ty, ce_id, 0).ok()?;
        Some(Some(FakeRing {
            mem: mem.cpu_mut_ptr(),
            ring_id,
            nentries,
            entry_words: (desc_bytes / 4) as u32,
            pos_words: 0,
        }))
    }

    /// One pump: consume host→target frames, then deliver queued
    /// target→host frames. Called once per host poll, next to the
    /// WLFW server's pump.
    fn pump(&mut self) {
        for i in 0..self.pipes.len() {
            self.consume_src(i);
        }
        for ce in 0..9u32 {
            while let Some(frame) = self.dl_queue[ce as usize].front().cloned() {
                if !self.deliver(ce, &frame) {
                    break;
                }
                self.dl_queue[ce as usize].pop_front();
            }
        }
    }

    /// Consume posted source-ring entries on pipe `idx`: read the
    /// descriptor, cross-check its paddr against the TX bounce buffer
    /// slot, copy the payload out, zero the descriptor (so the slot
    /// is not re-consumed on wrap), and publish the new TP through
    /// `rdp` — exactly the target side of `ath11k_ce_send`.
    fn consume_src(&mut self, idx: usize) {
        let (src, tx, buf_sz) = {
            let p = &self.pipes[idx];
            let (Some(src), Some(tx)) = (p.src.as_ref(), p.tx_buf.as_ref()) else {
                return;
            };
            // Copy the (Copy) ring/buffer handles out so the frame
            // handler below can borrow `self` mutably.
            (FakeRingView::from(src), FakeBufView::from(tx), p.buf_sz)
        };
        let ring_words = src.nentries * src.entry_words;
        let mut tp = src.pos;
        loop {
            let off = tp as usize * 4;
            // SAFETY: every word below is inside the captured ring
            // memory (capture checked `mem.len() == nentries *
            // desc_bytes`, and `tp < ring_words`).
            let (w0, w1, w2, w3) = unsafe {
                (
                    tgt_rd32(src.mem, off),
                    tgt_rd32(src.mem, off + 4),
                    tgt_rd32(src.mem, off + 8),
                    tgt_rd32(src.mem, off + 12),
                )
            };
            if w0 == 0 && w1 == 0 && w2 == 0 && w3 == 0 {
                break;
            }
            // `struct hal_ce_srng_src_desc`: word 0 = buffer addr
            // low; word 1 = addr hi (7:0) + len (31:16); word 2 =
            // meta (transfer id 15:0); word 3 = flags.
            let paddr = w0 as u64 | ((w1 & 0xff) as u64) << 32;
            let len = (w1 >> 16) as usize;
            let transfer_id = (w2 & 0xffff) as u16;
            let slot = tp / src.entry_words;
            let expect = tx.paddr + slot as u64 * buf_sz as u64;
            if paddr != expect || len == 0 || len > buf_sz as usize {
                self.errors += 1;
            }
            let mut frame = alloc::vec![0u8; len.min(buf_sz as usize)];
            if !frame.is_empty() {
                // SAFETY: the TX slot is inside the captured bounce
                // buffer (`slot < nentries`, `len <= buf_sz`).
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        tx.mem.add(slot as usize * buf_sz as usize),
                        frame.as_mut_ptr(),
                        frame.len(),
                    );
                }
            }
            self.ul_frames += 1;
            // Zero the descriptor before advancing: the host rewrites
            // all words on reuse, so a stale nonzero entry would be
            // consumed again on wrap.
            for k in 0..src.entry_words as usize {
                // SAFETY: `off + k * 4` is inside the captured ring
                // memory (same bounds as the descriptor read above).
                unsafe { tgt_wr32(src.mem, off + k * 4, 0) };
            }
            tp = (tp + src.entry_words) % ring_words;
            // SAFETY: `ring_id` is a HAL ring id, and `rdp` covers
            // every HAL ring id (`DmaMem::alloc(4 *
            // HAL_SRNG_RING_ID_MAX, 1)` in `Hal::new`).
            unsafe {
                core::ptr::write_volatile(self.rdp.add(src.ring_id as usize), tp);
            }
            self.pipes[idx].src.as_mut().unwrap().pos_words = tp;
            self.on_ul_frame(self.pipes[idx].ce, transfer_id, &frame);
        }
    }

    /// Deliver one queued frame on destination CE `ce`: write the
    /// payload into the posted RX slot, write the status descriptor
    /// (`len << 16`), publish the new status HP through `rdp`, and
    /// raise the CE interrupt. `false` when no RX buffer is posted
    /// yet on that slot (the frame stays queued for the next pump).
    fn deliver(&mut self, ce: u32, frame: &[u8]) -> bool {
        let Some(idx) = self.pipes.iter().position(|p| p.ce == ce) else {
            self.errors += 1;
            return true;
        };
        let (dst, status, rx, buf_sz, slot) = {
            let p = &self.pipes[idx];
            let (Some(dst), Some(status), Some(rx)) =
                (p.dst.as_ref(), p.status.as_ref(), p.rx_buf.as_ref())
            else {
                self.errors += 1;
                return true;
            };
            (
                FakeRingView::from(dst),
                FakeRingView::from(status),
                FakeBufView::from(rx),
                p.buf_sz,
                p.rx_next % dst.nentries,
            )
        };
        if frame.len() > buf_sz as usize {
            self.errors += 1;
            return true;
        }
        // The slot must be posted: the host's destination descriptor
        // (`struct hal_ce_srng_dest_desc`: word 0 = buffer addr low,
        // word 1 = addr hi 7:0) holds the RX buffer's paddr.
        let dst_off = slot as usize * dst.entry_words as usize * 4;
        // SAFETY: both words are inside the captured dest-ring
        // memory (capture checked the geometry, and `slot <
        // nentries`).
        let (d0, d1) = unsafe { (tgt_rd32(dst.mem, dst_off), tgt_rd32(dst.mem, dst_off + 4)) };
        if d0 == 0 && d1 == 0 {
            return false;
        }
        let paddr = d0 as u64 | ((d1 & 0xff) as u64) << 32;
        let expect = rx.paddr + slot as u64 * buf_sz as u64;
        if paddr != expect {
            self.errors += 1;
            return true;
        }
        // SAFETY: the RX slot is inside the captured RX buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(
                frame.as_ptr(),
                rx.mem.add(slot as usize * buf_sz as usize),
                frame.len(),
            );
        }
        // Status descriptor (`struct hal_ce_srng_dst_status_desc`):
        // word 0 = flags with `len` at 31:16; the host's
        // `ce_dst_status_get_length` reads it and clears it.
        let st_off = status.pos as usize * 4;
        // SAFETY: all four words are inside the captured status-ring
        // memory (`status.pos < status ring words`, advanced modulo
        // the ring size).
        unsafe {
            tgt_wr32(status.mem, st_off, (frame.len() as u32) << 16);
            tgt_wr32(status.mem, st_off + 4, 0);
            tgt_wr32(status.mem, st_off + 8, 0);
            tgt_wr32(status.mem, st_off + 12, 0);
        }
        let status_words = status.nentries * status.entry_words;
        let hp = (status.pos + status.entry_words) % status_words;
        // SAFETY: `ring_id` is a HAL ring id, and `rdp` covers
        // every HAL ring id (`DmaMem::alloc(4 *
        // HAL_SRNG_RING_ID_MAX, 1)` in `Hal::new`).
        unsafe {
            core::ptr::write_volatile(self.rdp.add(status.ring_id as usize), hp);
        }
        self.pipes[idx].status.as_mut().unwrap().pos_words = hp;
        self.pipes[idx].rx_next = self.pipes[idx].rx_next.wrapping_add(1);
        // Publish before the interrupt: the host reads the payload
        // only after the status length is visible.
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        super::super::ce::raise_ce(1 << ce);
        true
    }

    /// Handle one consumed host→target HTC frame (after its 8-byte
    /// header): answer it per the script and queue the responses.
    fn on_ul_frame(&mut self, ce: u32, _transfer_id: u16, frame: &[u8]) {
        if frame.len() < 8 {
            self.errors += 1;
            return;
        }
        let htc_info = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]);
        let eid = (htc_info & 0xff) as u8;
        let payload_len = (htc_info >> 16) as usize;
        if frame.len() < 8 + payload_len {
            self.errors += 1;
            return;
        }
        let p = &frame[8..8 + payload_len];
        match ce {
            // CE0: host→target HTC control (EP0).
            0 if eid == 0 && p.len() >= 4 => {
                let id = u16::from_le_bytes([p[0], p[1]]);
                let svc = u16::from_le_bytes([p[2], p[3]]);
                match id {
                    htc_msg::CONNECT_SERVICE if svc == htc_svc::HTT_DATA_MSG => {
                        self.connect_htt_seen = true;
                        if self.script.htt_reply {
                            let r =
                                Self::conn_svc_resp(svc, self.script.htt_status, htc_ep::HTT, 1024);
                            self.queue_ctrl(&r);
                            if self.script.htt_status == 0 {
                                self.conn_resp_htt = true;
                            }
                        }
                    }
                    htc_msg::CONNECT_SERVICE if svc == htc_svc::WMI_CONTROL => {
                        self.connect_wmi_seen = true;
                        if self.script.wmi_reply {
                            let r =
                                Self::conn_svc_resp(svc, self.script.wmi_status, htc_ep::WMI, 2048);
                            self.queue_ctrl(&r);
                            if self.script.wmi_status == 0 {
                                self.conn_resp_wmi = true;
                            }
                        }
                    }
                    htc_msg::CONNECT_SERVICE if svc == htc_svc::WMI_CONTROL_MAC1 => {
                        self.connect_wmi1_seen = true;
                        let r = Self::conn_svc_resp(svc, 0, htc_ep::WMI_MAC1, 2048);
                        self.queue_ctrl(&r);
                        self.conn_resp_wmi1 = true;
                    }
                    htc_msg::SETUP_COMPLETE_EX => {
                        self.setup_complete_seen = true;
                        if self.script.svc_ready {
                            self.queue_wmi(&Self::service_ready_event(), &[]);
                            self.svc_ready_sent = true;
                            let a = Self::service_available_event(self.script.advertise_ext2);
                            self.queue_wmi(&a, &[]);
                            self.svc_avail_sent = true;
                            let e = Self::service_ready_ext_event();
                            self.queue_wmi(&e, &[]);
                            self.svc_ext_sent = true;
                            if self.script.advertise_ext2 && self.script.send_ext2 {
                                let x = Self::ext2_event();
                                self.queue_wmi(&x, &[]);
                                self.ext2_sent = true;
                            }
                        }
                    }
                    _ => {}
                }
            }
            // CE3: host→target WMI (mac0).
            3 if eid == htc_ep::WMI && p.len() >= 4 => {
                let cmd = u32::from_le_bytes([p[0], p[1], p[2], p[3]]) & 0x00ff_ffff;
                if cmd == wmi_cmd::INIT {
                    self.init_seen = true;
                    let tr: &[u8] = if self.script.return_init_credit {
                        &Self::credit_trailer(&[(htc_ep::WMI, 1)])
                    } else {
                        &[]
                    };
                    if self.script.ready_event {
                        let ev = Self::ready_event(self.script.mac, &self.script.extra_macs);
                        self.queue_wmi(&ev, tr);
                        self.ready_event_sent = true;
                    } else if !tr.is_empty() {
                        // Credit report alone (trailer-only frame).
                        let f = Self::htc_frame(htc_ep::WMI, &[], tr);
                        self.dl_queue[self.map.wmi_dl as usize].push_back(f);
                    }
                } else {
                    // Any other WMI command: return its credit with a
                    // trailer-only frame; no event is owed.
                    let tr = Self::credit_trailer(&[(htc_ep::WMI, 1)]);
                    let f = Self::htc_frame(htc_ep::WMI, &[], &tr);
                    self.dl_queue[self.map.wmi_dl as usize].push_back(f);
                }
            }
            // CE7: host→target WMI on the MAC1 endpoint (IPQ6018 map
            // WMI_CONTROL_MAC1 OUT→7): no event is owed during core
            // start; return the credit.
            7 if eid == htc_ep::WMI_MAC1 && p.len() >= 4 => {
                self.wmi1_cmds += 1;
                let tr = Self::credit_trailer(&[(htc_ep::WMI_MAC1, 1)]);
                let f = Self::htc_frame(htc_ep::WMI_MAC1, &[], &tr);
                self.dl_queue[self.map.wmi_dl as usize].push_back(f);
            }
            // CE4: host→target HTT.
            4 if eid == htc_ep::HTT && p.first() == Some(&0) => {
                self.ver_req_seen = true;
                if self.script.htt_version_conf {
                    // `HTT_T2H_MSG_TYPE_VERSION_CONF` = 0 in the low
                    // byte; major 3 (`HTT_TARGET_VERSION_MAJOR`),
                    // minor target-reported.
                    let conf = [0x00u8, 0x51, 0x03, 0x00];
                    let f = Self::htc_frame(htc_ep::HTT, &conf, &[]);
                    self.dl_queue[self.map.htt_dl as usize].push_back(f);
                    self.ver_conf_sent = true;
                }
            }
            // CE4: HTT SRING_SETUP and friends — reaped already, no
            // answer is owed.
            4 if eid == htc_ep::HTT => {
                self.sring_setup_seen += 1;
            }
            _ => {}
        }
    }

    fn queue_ctrl(&mut self, payload: &[u8]) {
        let f = Self::htc_frame(0, payload, &[]);
        self.dl_queue[self.map.ctrl_dl as usize].push_back(f);
    }

    fn queue_wmi(&mut self, ev: &[u8], trailer: &[u8]) {
        let f = Self::htc_frame(htc_ep::WMI, ev, trailer);
        self.dl_queue[self.map.wmi_dl as usize].push_back(f);
    }

    // ── Target-side encoders (own code from the Linux headers cited
    // above; same shapes as the production encoders, independently
    // written) ────────────────────────────────────────────────────

    /// `struct ath11k_htc_hdr`: `htc_info` = eid (7:0) | flags
    /// (15:8) | payload length (31:16); `ctrl_info` = ctrl0 (trailer
    /// length, RX) | ctrl1. `TRAILER_PRESENT` + `ctrl0 = trailer.len()`
    /// when a trailer is present.
    fn htc_frame(eid: u8, payload: &[u8], trailer: &[u8]) -> Vec<u8> {
        let flags: u8 = if trailer.is_empty() { 0 } else { 0x02 };
        let htc_info =
            eid as u32 | (flags as u32) << 8 | ((payload.len() + trailer.len()) as u32) << 16;
        let ctrl_info = trailer.len() as u32;
        let mut v = Vec::with_capacity(8 + payload.len() + trailer.len());
        v.extend_from_slice(&htc_info.to_le_bytes());
        v.extend_from_slice(&ctrl_info.to_le_bytes());
        v.extend_from_slice(payload);
        v.extend_from_slice(trailer);
        v
    }

    /// `struct ath11k_htc_ready`: `id_credit_count` = msg id (15:0)
    /// | credit count (31:16); `size_ep` = credit size (15:0) | max
    /// endpoints (23:16).
    fn ready_msg(credit_count: u16, credit_size: u16, max_endpoints: u8) -> Vec<u8> {
        let mut v = Vec::with_capacity(8);
        v.extend_from_slice(&(htc_msg::READY as u32 | (credit_count as u32) << 16).to_le_bytes());
        v.extend_from_slice(&(credit_size as u32 | (max_endpoints as u32) << 16).to_le_bytes());
        v
    }

    /// `struct ath11k_htc_conn_svc_resp`: `msg_svc_id` = msg id |
    /// service id (31:16); `flags_len` = status (7:0) | endpoint
    /// (15:8) | max message size (31:16); `svc_meta_pad` = meta
    /// length (7:0).
    fn conn_svc_resp(service_id: u16, status: u8, eid: u8, max_msg_size: u16) -> Vec<u8> {
        let mut v = Vec::with_capacity(12);
        v.extend_from_slice(
            &(htc_msg::CONNECT_SERVICE_RESP as u32 | (service_id as u32) << 16).to_le_bytes(),
        );
        v.extend_from_slice(
            &(status as u32 | (eid as u32) << 8 | (max_msg_size as u32) << 16).to_le_bytes(),
        );
        v.extend_from_slice(&0u32.to_le_bytes());
        v
    }

    /// A trailer of `ATH11K_HTC_RECORD_CREDITS` records: one record
    /// header (`id, len, pad, pad`) + `len / 4` credit reports
    /// (`eid, credits, pad, pad`).
    fn credit_trailer(reports: &[(u8, u8)]) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + 4 * reports.len());
        v.extend_from_slice(&[1, (4 * reports.len()) as u8, 0, 0]);
        for &(eid, credits) in reports {
            v.extend_from_slice(&[eid, credits, 0, 0]);
        }
        v
    }

    /// WMI TLV: header `(tag << 16) | len` + value (`struct wmi_tlv`).
    fn tlv(tag: u16, value: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + value.len());
        v.extend_from_slice(&(((tag as u32) << 16) | value.len() as u32).to_le_bytes());
        v.extend_from_slice(value);
        v
    }

    /// Little-endian words → bytes.
    fn le(ws: &[u32]) -> Vec<u8> {
        let mut v = Vec::with_capacity(ws.len() * 4);
        for w in ws {
            v.extend_from_slice(&w.to_le_bytes());
        }
        v
    }

    /// WMI event: `[event id] ++ TLVs` (the host's `split_event`
    /// reads the id from the first word, low 24 bits).
    fn event(id: u32, tlvs: &[Vec<u8>]) -> Vec<u8> {
        let mut v = Self::le(&[id]);
        for t in tlvs {
            v.extend_from_slice(t);
        }
        v
    }

    /// `WMI_SERVICE_READY_EVENTID`: `struct wmi_service_ready_event`
    /// (32 words: fw_build_vers, fw_abi_vers[6], then the caps at the
    /// offsets the host decodes) + the 32-word service bitmap
    /// (`WMI_SERVICE_BM_SIZE`). Fixture values: 2 RF chains, 1 MAC.
    fn service_ready_event() -> Vec<u8> {
        let mut w = [0u32; 32];
        w[0] = 0x0100_0042; // fw_build_vers
        w[9] = 2; // num_rf_chains @36
        w[10] = 0x19ef; // ht_cap_info @40
        w[19] = 64; // max_num_scan_channels @76
        w[26] = 1; // max_supported_macs @104
        w[29] = 0x0303_0303; // txrx_chainmask @116
        let mut bm = [0u32; 32];
        bm[0] = 0b0101; // services 0, 2
        Self::event(
            wmi_ev::SERVICE_READY,
            &[
                Self::tlv(wmi_tag::SERVICE_READY_EVENT, &Self::le(&w)),
                Self::tlv(wmi_tag::ARRAY_UINT32, &Self::le(&bm)),
            ],
        )
    }

    /// `WMI_SERVICE_AVAILABLE_EVENTID`: `struct
    /// wmi_service_available_event` (segment offset + 4-word bitmap)
    /// plus the 4-word extended bitmap. EXT2 (220) lives in the
    /// 128..256 segment: word (220-128)/32 = 2, bit (220-128)%32 = 28.
    fn service_available_event(advertise_ext2: bool) -> Vec<u8> {
        let w2 = if advertise_ext2 {
            wmi_svc_bit::EXT2_MSG_SEG_W2
        } else {
            0
        };
        Self::event(
            wmi_ev::SERVICE_AVAILABLE,
            &[
                Self::tlv(
                    wmi_tag::SERVICE_AVAILABLE_EVENT,
                    &Self::le(&[0, 0, 0, w2, 0]),
                ),
                Self::tlv(wmi_tag::ARRAY_UINT32, &Self::le(&[0, 0, 0, 0])),
            ],
        )
    }

    /// `struct wmi_hw_mode_capabilities` as a TLV value: the outer
    /// header is the struct's own `tlv_header`, then hw_mode_id,
    /// phy_id_map, hw_mode_config_type.
    fn hw_mode_cap(id: u32, phy_map: u32) -> Vec<u8> {
        Self::tlv(wmi_tag::HW_MODE_CAPABILITIES, &Self::le(&[id, phy_map, 0]))
    }

    /// `struct wmi_mac_phy_capabilities` (59 words in-tree, incl. the
    /// wireless-modes / channel / nss_ratio tail): SINGLE (phy 0,
    /// 2G+5G) and DBS (phy 0 = 2G, phy 1 = 5G) modes, two phys.
    fn mac_phy(hw_mode_id: u32, pdev_id: u32, phy_id: u32, bands: u32, chains: u32) -> Vec<u8> {
        let mut w = [0u32; 59];
        w[0] = hw_mode_id;
        w[1] = pdev_id;
        w[2] = phy_id;
        w[4] = bands;
        w[5] = 7; // ampdu_density
        w[6] = 1; // max_bw_supported_2g
        w[12] = chains; // tx_chain_mask_2g
        w[13] = chains; // rx_chain_mask_2g
        w[14] = 3; // max_bw_supported_5g
        w[16] = 0x339b_79fa; // vht_cap_info_5g
        w[20] = chains; // tx_chain_mask_5g
        w[21] = chains; // rx_chain_mask_5g
        w[58] = 0b1_0101; // nss_ratio: enabled, info 0xa
        Self::tlv(wmi_tag::MAC_PHY_CAPABILITIES, &Self::le(&w))
    }

    /// `struct wmi_hal_reg_capabilities_ext` as a TLV value: phy_id,
    /// eeprom_reg_domain, eeprom_reg_domain_ext, regcap1, regcap2,
    /// wireless_modes, low/high 2 GHz, low/high 5 GHz channels.
    fn hal_reg(phy_id: u32, lo2: u32, hi2: u32, lo5: u32, hi5: u32) -> Vec<u8> {
        Self::tlv(
            wmi_tag::HAL_REG_CAPABILITIES_EXT,
            &Self::le(&[phy_id, 0x6c, 0, 0, 0, 0, lo2, hi2, lo5, hi5]),
        )
    }

    /// `WMI_SERVICE_READY_EXT_EVENTID`: the ext fixed struct (19
    /// words: conc-scan + fw-config bits, 10-word ppet, he_cap_info,
    /// mpdu_density, max_bssid_rx_filters, ...), the SOC caps, the
    /// ARRAY_STRUCT entries in the decoder's order (hw-mode caps,
    /// mac-phy caps, HAL reg caps, combo, cap, OEM DMA, DMA ring
    /// caps).
    fn service_ready_ext_event() -> Vec<u8> {
        let mut hw_modes = Vec::new();
        hw_modes.extend_from_slice(&Self::hw_mode_cap(hw_mode::SINGLE, 0x1));
        hw_modes.extend_from_slice(&Self::hw_mode_cap(hw_mode::DBS, 0x3));
        let mut mac_phys = Vec::new();
        mac_phys.extend_from_slice(&Self::mac_phy(0, 1, 0, 3, 0x3));
        mac_phys.extend_from_slice(&Self::mac_phy(1, 1, 0, 1, 0x1));
        mac_phys.extend_from_slice(&Self::mac_phy(1, 2, 1, 2, 0x2));
        let mut hal_regs = Vec::new();
        hal_regs.extend_from_slice(&Self::hal_reg(0, 2312, 2732, 0, 0));
        hal_regs.extend_from_slice(&Self::hal_reg(1, 0, 0, 5150, 7125));
        let dma = Self::tlv(
            wmi_tag::DMA_RING_CAPABILITIES,
            &Self::le(&[1, 0, 16, 2048, 4]),
        );
        Self::event(
            wmi_ev::SERVICE_READY_EXT,
            &[
                Self::tlv(wmi_tag::SERVICE_READY_EXT_EVENT, &[0; 76]),
                Self::tlv(wmi_tag::SOC_MAC_PHY_HW_MODE_CAPS, &Self::le(&[2, 0])),
                Self::tlv(wmi_tag::ARRAY_STRUCT, &hw_modes),
                Self::tlv(wmi_tag::ARRAY_STRUCT, &mac_phys),
                Self::tlv(wmi_tag::SOC_HAL_REG_CAPABILITIES, &Self::le(&[2])),
                Self::tlv(wmi_tag::ARRAY_STRUCT, &hal_regs),
                Self::tlv(wmi_tag::ARRAY_STRUCT, &[]),
                Self::tlv(wmi_tag::ARRAY_STRUCT, &[]),
                Self::tlv(wmi_tag::ARRAY_STRUCT, &[]),
                Self::tlv(wmi_tag::ARRAY_STRUCT, &dma),
            ],
        )
    }

    /// `WMI_SERVICE_READY_EXT2_EVENTID`: one ARRAY_STRUCT holding a
    /// DMA ring cap (`struct wmi_dma_ring_capabilities`: pdev_id,
    /// module_id, min_elem, min_buf_sz, min_buf_align).
    fn ext2_event() -> Vec<u8> {
        Self::event(
            wmi_ev::SERVICE_READY_EXT2,
            &[Self::tlv(
                wmi_tag::ARRAY_STRUCT,
                &Self::tlv(
                    wmi_tag::DMA_RING_CAPABILITIES,
                    &Self::le(&[1, 1, 8, 1024, 8]),
                ),
            )],
        )
    }

    /// `WMI_READY_EVENTID`: `struct wmi_ready_event` (15 words:
    /// fw_abi_vers[6], mac_addr, status, num_dscp_table,
    /// num_extra_mac_addr, num_total_peers, num_extra_peers,
    /// max_ast_index, pktlog_defs_checksum). The MAC is two words:
    /// bytes 0..3 LE, then bytes 4..5 in the low half (`struct
    /// wmi_mac_addr`). With `extra` MACs, `num_extra_mac_addr` is their
    /// count and an `ARRAY_FIXED_STRUCT` of `wmi_mac_addr`s (8 bytes
    /// each) follows, as `ath11k_wmi_tlv_rdy_parse` reads it.
    fn ready_event(mac: [u8; 6], extra: &[[u8; 6]]) -> Vec<u8> {
        let mac_words = |m: [u8; 6]| {
            [
                u32::from_le_bytes([m[0], m[1], m[2], m[3]]),
                u32::from_le_bytes([m[4], m[5], 0, 0]),
            ]
        };
        let [w0, w1] = mac_words(mac);
        let mut tlvs = alloc::vec![Self::tlv(
            wmi_tag::READY_EVENT,
            &Self::le(&[
                1,
                2,
                3,
                4,
                5,
                6,
                w0,
                w1,
                0,
                0,
                extra.len() as u32,
                512,
                0,
                0x1000,
                0xcafe_babe,
            ]),
        )];
        if !extra.is_empty() {
            let words: Vec<u32> = extra.iter().flat_map(|m| mac_words(*m)).collect();
            tlvs.push(Self::tlv(wmi_tag::ARRAY_FIXED_STRUCT, &Self::le(&words)));
        }
        Self::event(wmi_ev::READY, &tlvs)
    }
}

/// Copyable views of a captured ring / buffer, so `consume_src` and
/// `deliver` can hold the geometry while `self` is borrowed mutably
/// for the frame handler / observations.
#[derive(Copy, Clone)]
struct FakeRingView {
    mem: *mut u8,
    ring_id: u32,
    nentries: u32,
    entry_words: u32,
    pos: u32,
}

impl From<&FakeRing> for FakeRingView {
    fn from(r: &FakeRing) -> Self {
        FakeRingView {
            mem: r.mem,
            ring_id: r.ring_id,
            nentries: r.nentries,
            entry_words: r.entry_words,
            pos: r.pos_words,
        }
    }
}

#[derive(Copy, Clone)]
struct FakeBufView {
    mem: *mut u8,
    paddr: u64,
}

impl From<&FakeBuf> for FakeBufView {
    fn from(b: &FakeBuf) -> Self {
        FakeBufView {
            mem: b.mem,
            paddr: b.paddr,
        }
    }
}

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

// ── core start against the CE/HTC/WMI target fake ───────────────────

use super::super::ahb::AhbError;

/// Observations from the WLFW server leg, for the core-start tests.
struct WlfwObs {
    reqs: Vec<u16>,
    bdf_segs: Vec<(u32, u8)>,
    decode_errs: usize,
    fw_ready_sent: bool,
    out_qrtr_empty: bool,
}

/// Outcome of [`drive_wcn6750_core_start`]: the `qmi_ready` result
/// (`None` when it did not settle), the fake with its observations,
/// the WLFW observations, and `live` for the outcome assertions.
type CoreStartOutcome = (
    Option<Result<(), AhbError>>,
    CeTargetFake,
    WlfwObs,
    Box<LiveAhb<Env>>,
);

/// Drive the WCN6750 bring-up through `qmi_ready` with the WLFW
/// server and a `CeTargetFake` pumped once per host poll. Steps are
/// driven individually (as `booted_live` does) so the fake can be
/// captured after `hal_ce_alloc`, while the test still owns `live`.
/// The unwind `rproc_shutdown` that `bring_up` runs after a failed
/// `qmi_ready` is skipped: it sends no QMI, and the `firmware_stop`
/// unwind (the trailing WLAN_MODE) already ran inside `qmi_ready`'s
/// error path.
fn drive_wcn6750_core_start(script: CeTargetScript) -> CoreStartOutcome {
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
    let _ = live.hal_ce_alloc(&p);
    let mut fake = CeTargetFake::capture(
        live.ce().expect("hal_ce_alloc built the CE"),
        TARGET_CE_MAP_QCA6390,
        script,
    )
    .expect("CE geometry is consistent");
    let _ = live.qmi_init_service(&p);
    let _ = run(live.rproc_irqs(&p));
    let _ = run(live.rproc_boot(&p));
    let _ = run(live.glink_start(&p));
    // The SMEM GLINK descriptor exists now: attach the server (the
    // same construction as the WLFW test).
    let mut server = {
        let (d, tx, rx) = (
            smem.get(pid, SMEM_GLINK_NATIVE_XPRT_DESCRIPTOR).unwrap(),
            smem.get(pid, SMEM_GLINK_NATIVE_XPRT_FIFO_0).unwrap(),
            smem.get(pid, SMEM_GLINK_NATIVE_XPRT_FIFO_1).unwrap(),
        );
        GlinkWlfwServer::unattached(
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
        )
    };
    let _ = live.config_irq(&p);
    // The pinned `qmi_ready` future borrows `live` until the future
    // itself drops, and `drop()` on the `pin!` guard does not drop
    // the future — so the poll loop lives in its own block, and the
    // borrow ends at the block's close, before anything below reads
    // `live` again.
    let out = {
        let mut fut = pin!(live.qmi_ready(&p));
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut out = None;
        for _ in 0..200_000 {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                out = Some(v);
                break;
            }
            server.pump();
            fake.pump();
        }
        // The final poll can post host frames synchronously — the
        // SRING_SETUPs `pdev_create` sends inside the completing
        // `qmi_ready` poll — and then return Ready with no further
        // pump in between, so reap them here or the fake's
        // observations lag the host by one pump. The server needs no
        // trailing pump: its QMI traffic spans awaits, so the in-loop
        // pumps already reaped it.
        fake.pump();
        out
    };
    let obs = WlfwObs {
        reqs: server.reqs.clone(),
        bdf_segs: server.bdf_segs.clone(),
        decode_errs: server.decode_errs,
        fw_ready_sent: server.fw_ready_sent,
        out_qrtr_empty: server.out_qrtr.is_empty(),
    };
    (out, fake, obs, live)
}

/// WCN6750 core start past `firmware_start` against the CE/HTC/WMI
/// target fake: HTC READY → CONNECT_SERVICE (HTT + WMI_CONTROL) →
/// SETUP_COMPLETE_EX → SERVICE_READY / AVAILABLE / EXT (+ EXT2) →
/// WMI INIT → READY event → HTT VERSION_REQ → VERSION_CONF, ending
/// in `LiveOutcome::Ready` with the fake's MAC.
fn smoke_ath11k_ahb_live_wcn6750_core_start_ce_fake() -> TestResult {
    let (out, fake, wlfw, live) = drive_wcn6750_core_start(CeTargetScript::default());
    let Some(Ok(())) = out else {
        return TestResult::Fail("qmi_ready did not succeed");
    };
    let Some(LiveOutcome::Ready(core, _dp)) = &live.outcome else {
        return TestResult::Fail("bring-up did not reach Ready");
    };
    kt_assert!(core.is_ready());
    kt_assert_eq!(core.mac_addr, Some(TGT_MAC));
    // The WLFW phase ran to completion through the real bring-up
    // path, and bring-up succeeded, so there is no unwind
    // `firmware_stop` (no trailing WLAN_MODE).
    kt_assert_eq!(
        wlfw.reqs,
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
        ]
    );
    kt_assert_eq!(wlfw.bdf_segs, alloc::vec![(0, 0), (1, 0), (2, 1)]);
    kt_assert_eq!(wlfw.decode_errs, 0);
    kt_assert!(wlfw.out_qrtr_empty);
    kt_assert!(wlfw.fw_ready_sent);
    // The fake saw the whole core-start handshake and answered every
    // leg; nothing violated the ring protocol.
    kt_assert_eq!(fake.errors, 0);
    kt_assert!(fake.ready_sent);
    kt_assert!(fake.connect_htt_seen);
    kt_assert!(fake.conn_resp_htt);
    kt_assert!(fake.connect_wmi_seen);
    kt_assert!(fake.conn_resp_wmi);
    kt_assert!(fake.setup_complete_seen);
    kt_assert!(fake.svc_ready_sent);
    kt_assert!(fake.svc_avail_sent);
    kt_assert!(fake.svc_ext_sent);
    kt_assert!(fake.ext2_sent);
    kt_assert!(fake.init_seen);
    kt_assert!(fake.ready_event_sent);
    kt_assert!(fake.ver_req_seen);
    kt_assert!(fake.ver_conf_sent);
    kt_assert!(fake.sring_setup_seen > 0);
    kt_assert!(fake.ul_frames > 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_ahb_live_wcn6750_core_start_ce_fake
);

/// Tampered-target case: a READY with zero credits must strand the
/// core at HTC_READY — if the host did not consult the credit count,
/// this test would reach Ready and fail.
fn smoke_ath11k_ahb_live_wcn6750_ce_fake_ready_zero_credits() -> TestResult {
    let script = CeTargetScript {
        credits: 0,
        ..CeTargetScript::default()
    };
    let (out, fake, wlfw, live) = drive_wcn6750_core_start(script);
    let Some(Err(_)) = out else {
        return TestResult::Fail("qmi_ready did not fail on zero-credit READY");
    };
    kt_assert!(matches!(&live.outcome, Some(LiveOutcome::Stranded(..))));
    kt_assert!(!fake.connect_htt_seen);
    kt_assert!(!fake.connect_wmi_seen);
    kt_assert_eq!(fake.errors, 0);
    kt_assert!(wlfw.fw_ready_sent);
    kt_assert_eq!(wlfw.decode_errs, 0);
    // The stranded core's unwind told the firmware wlan_mode OFF.
    kt_assert_eq!(
        wlfw.reqs,
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
            QMI_WLANFW_WLAN_MODE_REQ_V01,
        ]
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_ahb_live_wcn6750_ce_fake_ready_zero_credits
);

/// Tampered-target case: refusing the WMI_CONTROL connect must
/// strand the core at `wmi_connect` — the HTT connect still succeeds
/// first, proving the refusal (not an earlier failure) is what
/// stranded it.
fn smoke_ath11k_ahb_live_wcn6750_ce_fake_refuse_wmi() -> TestResult {
    let script = CeTargetScript {
        wmi_status: 1,
        ..CeTargetScript::default()
    };
    let (out, fake, wlfw, live) = drive_wcn6750_core_start(script);
    let Some(Err(_)) = out else {
        return TestResult::Fail("qmi_ready did not fail on refused WMI connect");
    };
    kt_assert!(matches!(&live.outcome, Some(LiveOutcome::Stranded(..))));
    kt_assert!(fake.connect_htt_seen);
    kt_assert!(fake.conn_resp_htt);
    kt_assert!(fake.connect_wmi_seen);
    kt_assert!(!fake.conn_resp_wmi);
    kt_assert!(!fake.setup_complete_seen);
    kt_assert_eq!(fake.errors, 0);
    kt_assert!(wlfw.fw_ready_sent);
    kt_assert_eq!(wlfw.decode_errs, 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_ahb_live_wcn6750_ce_fake_refuse_wmi
);

// ── IPQ6018 core start against the CE/HTC/WMI target fake ──────────

/// Zeroed MMIO for the direct IPQ6018 core: reads 0, writes ignored. The
/// fake plays the target through ring memory and `rdp` only (see the
/// fake's module notes), so no register model is needed.
#[derive(Clone, Copy, Default)]
struct ZeroIo;

impl super::super::power::ChipIo for ZeroIo {
    fn read32(&self, _offset: u32) -> u32 {
        0
    }
    fn write32(&self, _offset: u32, _value: u32) {}
    fn delay_ms(&self, _ms: u32) {}
    fn restore_window(&self) {}
}

/// The WLFW leg for IPQ6018 is its own fixture
/// (`smoke_ath11k_wlfw_over_glink_ipq6018`); this core starts right at
/// `firmware_start`, which the firmware accepts.
struct StartedQmi;

impl super::super::core::QmiFw for StartedQmi {
    async fn firmware_start(
        &mut self,
        _mode: u32,
        _shadow_reg_v2: &[u32],
    ) -> Result<(), super::super::wlfw::WlfwError> {
        Ok(())
    }
    async fn firmware_stop(&mut self) {}
}

/// Small DP rings (the no-MSI rig `ahb_netdev_tests` uses).
const IPQ_SIZES: super::super::dp_ring::DpRingSizes = super::super::dp_ring::DpRingSizes {
    wbm_release: 16,
    tcl_cmd: 8,
    tcl_status: 8,
    tcl_data: Some(8),
    tx_comp: 16,
    reo_reinject: 8,
    rx_release: 16,
    reo_exception: 16,
    reo_cmd: 8,
    reo_status: 16,
    reo_dst: 16,
    rxdma_buf: 16,
    rx_mac_buf: 16,
    rxdma_err_dst: 16,
    rxdma_mon_status: 8,
    rxdma_mon_buf: 8,
    rxdma_mon_dst: 8,
    rxdma_mon_desc: 8,
    tx_status_fifo: 8,
    n_link_desc: Some(64),
};

/// IPQ6018 core start past `firmware_start` against the CE/HTC/WMI
/// target fake on the IPQ6018 service map, then `runtime::start_ahb`:
///
/// - HTC: READY on CE1 (RSVD_CTRL IN→1), CONNECT_SERVICE for HTT,
///   WMI_CONTROL *and* WMI_CONTROL_MAC1 (`max_radios = 2` → Linux
///   `ath11k_htc_init` `wmi_ep_count = 2` with no preferred hw mode at
///   attach), SETUP_COMPLETE_EX;
/// - WMI: SERVICE_READY / AVAILABLE / EXT (+EXT2); the EXT's DBS mode
///   (preferred over SINGLE, `ath11k_hw_mode_pri_map`) yields two radios
///   with firmware pdev ids 1 and 2; INIT is the multi-pdev
///   `ath11k_init_wmi_config_ipq8074` command on the WMI_CONTROL
///   endpoint; READY carries one extra MAC per radio;
/// - HTT VERSION_CONF, then `pdev_create` allocates both pdevs (HTT
///   SRING_SETUP on CE4 for each);
/// - `start_ahb` registers one netdev per radio with that radio's READY
///   extra MAC, resolving the DP mac id (0, 1) to the firmware pdev id
///   (1, 2) by index.
fn smoke_ath11k_ahb_ipq6018_core_start_ce_fake() -> TestResult {
    use super::super::ce::{monotonic_ms, Ce as HostCe, CeMsi, MsiCeIrq};
    use super::super::core::{Ath11kCore, CeHif, CoreConfig};
    use super::super::dp_ring::DpHwParams;
    use super::super::hw::{HwRev, MSI_CONFIG_NONE};
    use super::super::runtime::DpHooks;
    const RADIO_MACS: [[u8; 6]; 2] = [
        [0x00, 0x03, 0x7f, 0x12, 0x34, 0x60],
        [0x00, 0x03, 0x7f, 0x12, 0x34, 0x61],
    ];
    let hw = AhbChip::Ipq6018Hw10.params().hw_params(HwRev::Ipq6018Hw10);
    let Ok(ce) = HostCe::alloc(
        &hw,
        CeMsi {
            addr: 0,
            ep_base_data: 0,
            config: &MSI_CONFIG_NONE,
        },
        monotonic_ms,
    ) else {
        return TestResult::Fail("IPQ6018 CE alloc");
    };
    let script = CeTargetScript {
        extra_macs: RADIO_MACS.to_vec(),
        ..CeTargetScript::default()
    };
    let Some(mut fake) = CeTargetFake::capture(&ce, TARGET_CE_MAP_IPQ6018, script) else {
        return TestResult::Fail("IPQ6018 CE geometry");
    };
    let hif = CeHif {
        ce,
        io: ZeroIo,
        irq: MsiCeIrq,
        on_start: || {},
        clock: monotonic_ms,
    };
    let Some(cfg) = CoreConfig::for_hw(&hw) else {
        return TestResult::Fail("IPQ6018 core config");
    };
    let Ok(mut core) = Ath11kCore::new(hif, StartedQmi, cfg) else {
        return TestResult::Fail("IPQ6018 core new");
    };
    let mut hooks = DpHooks::new(
        DpHwParams::for_rev(hw.hw_rev),
        hw.hw_rev as u32,
        IPQ_SIZES,
        None,
    );
    let out = {
        let mut fut = pin!(core.qmi_firmware_ready(&mut hooks));
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut out = None;
        for _ in 0..200_000 {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                out = Some(v);
                break;
            }
            fake.pump();
        }
        // The completing poll posts `pdev_create`'s SRING_SETUPs
        // synchronously (see `drive_wcn6750_core_start`).
        fake.pump();
        out
    };
    let Some(Ok(())) = out else {
        return TestResult::Fail("IPQ6018 core start did not succeed");
    };
    kt_assert!(core.is_ready());
    kt_assert_eq!(core.mac_addr, Some(TGT_MAC));
    kt_assert_eq!(core.num_radios(), 2);
    kt_assert_eq!(core.wmi_pdev_eps.len(), 2);
    kt_assert_eq!(fake.errors, 0);
    kt_assert!(fake.conn_resp_htt && fake.conn_resp_wmi && fake.conn_resp_wmi1);
    kt_assert!(fake.setup_complete_seen && fake.svc_ext_sent && fake.ext2_sent);
    kt_assert!(fake.init_seen && fake.ready_event_sent);
    kt_assert!(fake.ver_req_seen && fake.ver_conf_sent);
    kt_assert!(fake.sring_setup_seen > 0);
    let Some(dp) = hooks.dp.take() else {
        return TestResult::Fail("IPQ6018 DP missing after core start");
    };
    kt_assert_eq!(dp.pdev_mac_ids(), alloc::vec![0, 1]);
    let ext = core
        .svc_ext
        .as_ref()
        .map(|e| e.pdevs.iter().map(|p| p.pdev_id).collect::<Vec<u32>>());
    kt_assert_eq!(ext, Some(alloc::vec![1, 2]));
    let (_shared, r) = super::super::runtime::start_ahb(core, dp);
    let Ok(macs) = r else {
        return TestResult::Fail("IPQ6018 start_ahb registered no radio");
    };
    kt_assert_eq!(macs, RADIO_MACS.to_vec());
    for mac in RADIO_MACS {
        kt_assert!(
            narf_wireless::registry::list()
                .into_iter()
                .any(|p| p.mac() == mac),
            "IPQ6018 radio netdev registered"
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_ahb_ipq6018_core_start_ce_fake
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

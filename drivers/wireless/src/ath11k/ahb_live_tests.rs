//! Live AHB bring-up smokes: [`LiveAhb`] over RAM fixtures shaped like
//! `ipq6018.dtsi` (host-reset WCSS) and `sc7280.dtsi` (TrustZone PAS
//! WPSS). The fixture environment hands out [`FakeRegs`] windows, plays
//! the remote's SMP2P bits from [`AhbEnv::remote_tick`] and records the
//! interrupt binding. There is no WLFW server behind the GLINK edge, so
//! the QMI step times out and the bring-up must unwind through
//! `rproc_shutdown`. Fixture-only; nothing has run on IPQ / WCN6750
//! silicon.

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use narf_drivers_qcom_soc::fixtures::{
    build_mdt, build_smem_v12_sized, ipq6018_wifi_dt, remote_item, run, sc7280_wifi_dt, FakeAlloc,
    FakeDelay, FakeRegs, FakeSmc, Seg,
};
use narf_drivers_qcom_soc::glink::SMEM_GLINK_NATIVE_XPRT_DESCRIPTOR;
use narf_drivers_qcom_soc::hwlock::TcsrMutex;
use narf_drivers_qcom_soc::mdt::{PT_LOAD, QCOM_MDT_TYPE_HASH};
use narf_drivers_qcom_soc::platform::GlinkEdgeDt;
use narf_drivers_qcom_soc::rproc::RprocState;
use narf_drivers_qcom_soc::smem::Smem;
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use super::super::ahb::find_ahb_devices;
use super::super::ahb_hif::AhbLine;
use super::super::ahb_probe::{bring_up, AhbPlatform, BringUpStep};
use super::super::qrtr_glink::GlinkBus;
use super::super::wlfw::{CoherentMem, DmaAllocator, FirmwareLoader};
use super::*;

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

struct Bus;
impl GlinkBus for Bus {
    fn wait_irq(&self, _ms: u32) -> impl core::future::Future<Output = ()> + Send {
        core::future::ready(())
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

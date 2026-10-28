//! Interrupt-delivery smokes: SMP2P virtual interrupts and GIC handler
//! cookies routed into `Q6v5::signal`, IPCC demux. RAM/MMIO fixtures
//! (no Qualcomm hardware); the GIC distributor path itself is covered
//! by `interrupts`' `smoke_gic_spi_configure_and_deliver` on QEMU virt.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};

use crate::fixtures::*;
use crate::hwlock::TcsrMutex;
use crate::irq::*;
use crate::q6v5::{Crash, Q6Event, Q6v5};
use crate::smem::Smem;
use crate::smp2p::{Smp2p, Smp2pConfig};

const EDGE: &str = "/soc/wcss-smp2p";

fn routes() -> Q6Irqs {
    let s = |entry: &str, bit, event| Q6Route::Smp2p {
        edge: String::from(EDGE),
        entry: String::from(entry),
        bit,
        event,
    };
    Q6Irqs {
        routes: vec![
            Q6Route::Gic {
                intid: 357,
                event: Q6Event::Wdog,
            },
            s("master-kernel", 0, Q6Event::Fatal),
            s("master-kernel", 1, Q6Event::Ready),
            s("master-kernel", 2, Q6Event::Handover),
            s("master-kernel", 3, Q6Event::StopAck),
        ],
    }
}

struct FakeLine(AtomicU32);
impl IrqLine for FakeLine {
    fn wait(&self, _ms: u32) -> impl Future<Output = bool> + Send {
        // Fires on every other wait.
        let n = self.0.fetch_add(1, Ordering::Relaxed);
        core::future::ready(n % 2 == 0)
    }
}

fn smoke_qcom_irq_smp2p_routes_to_q6v5() -> TestResult {
    const SMEM_SIZE: u32 = 0x10000;
    let regs = FakeRegs::quiet();
    build_smem_v12(&regs, SMEM_SIZE, 1, 512);
    let lr = FakeRegs::new();
    let d = FakeDelay::new();
    let lock = TcsrMutex::new(&lr, &d, 3).unwrap();
    let smem = Smem::probe(&regs, SMEM_SIZE).unwrap();
    let cfg = Smp2pConfig {
        smem_in: 435,
        smem_out: 428,
        local_pid: 0,
        remote_pid: 1,
    };
    let k = CountingKick::default();
    let mut e = run(Smp2p::new(&smem, &lock, cfg, &k)).unwrap().unwrap();
    let r = routes();
    kt_assert_eq!(r.gic_lines(), vec![(357, Q6Event::Wdog)]);
    // One inbound entry, four rising-edge bits.
    let handles = r.attach_smp2p(EDGE, &mut e).unwrap();
    kt_assert_eq!(handles.len(), 1);
    kt_assert!(r.attach_smp2p("/soc/other", &mut e).unwrap().is_empty());
    let q6 = Q6v5::new();
    q6.prepare();
    // Remote publishes the entry, then raises ready (bit 1).
    let ri = crate::tests::remote_item(&smem, &lock, cfg, &[("master-kernel", 0)], false);
    kt_assert_eq!(smp2p_dispatch(&mut e, &smem, EDGE, &handles, &r, &q6), 0);
    regs.set(ri + 36, 1 << 1);
    kt_assert_eq!(smp2p_dispatch(&mut e, &smem, EDGE, &handles, &r, &q6), 1);
    // Ready → start_done; handover (bit 2) recorded while enabled.
    regs.set(ri + 36, (1 << 1) | (1 << 2));
    kt_assert_eq!(smp2p_dispatch(&mut e, &smem, EDGE, &handles, &r, &q6), 1);
    kt_assert!(q6.handover_issued());
    // Wrong edge name: nothing routed.
    regs.set(ri + 36, (1 << 1) | (1 << 2) | 1);
    let fired = e.handle_interrupt(&smem);
    kt_assert_eq!(r.route_smp2p("/soc/other", &handles, &fired, &q6), 0);
    kt_assert!(q6.crash().is_none());
    // The threaded loop: fatal arrives on the next line wake.
    regs.set(ri + 36, 0);
    smp2p_dispatch(&mut e, &smem, EDGE, &handles, &r, &q6);
    regs.set(ri + 36, 1);
    let line = FakeLine(AtomicU32::new(0));
    let mut rounds = 0;
    run(service_smp2p(
        &mut e,
        &smem,
        &line,
        EDGE,
        &handles,
        &r,
        &q6,
        10,
        &mut || {
            rounds += 1;
            rounds <= 2
        },
    ))
    .unwrap();
    kt_assert_eq!(q6.crash(), Some(Crash::Fatal));
    kt_assert!(!q6.running());
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_irq_smp2p_routes_to_q6v5);

fn smoke_qcom_irq_gic_cookie_and_ipcc() -> TestResult {
    // A leaked Q6v5 like a probed remoteproc's.
    let q6: &'static Q6v5 = Box::leak(Box::new(Q6v5::new()));
    q6.prepare();
    let ready = q6v5_cookie(q6, Q6Event::Ready);
    let wdog = q6v5_cookie(q6, Q6Event::Wdog);
    kt_assert!(matches!(
        q6v5_gic_handler(0),
        narf_interrupts::IrqStatus::None
    ));
    kt_assert!(matches!(
        q6v5_gic_handler(ready),
        narf_interrupts::IrqStatus::Handled
    ));
    kt_assert!(q6.running());
    q6v5_gic_handler(wdog);
    kt_assert_eq!(q6.crash(), Some(Crash::Watchdog));
    // The handler chained on a dispatch slot runs from on_irq.
    narf_interrupts::install_handler_named(126, "q6v5-test", wdog, q6v5_gic_handler);
    q6.prepare();
    narf_interrupts::on_irq(126);
    narf_interrupts::remove_handler(126, "q6v5-test", wdog);
    kt_assert_eq!(q6.crash(), Some(Crash::Watchdog));
    // DT trigger flags.
    kt_assert!(dt_flags_edge(1) && dt_flags_edge(3));
    kt_assert!(!dt_flags_edge(4));
    // GIC binding refuses non-SPIs (aarch64) / is unsupported (x86_64).
    #[cfg(target_arch = "aarch64")]
    kt_assert_eq!(GicSpi::bind(16, true), Err(IrqBindError::OutOfRange(16)));
    #[cfg(not(target_arch = "aarch64"))]
    kt_assert_eq!(GicSpi::bind(64, true), Err(IrqBindError::NotSupported));
    // IPCC demux: nothing pending, then one (client 24, signal 2).
    let ip = FakeRegs::new();
    ip.set(IPCC_REG_RECV_ID, IPCC_NO_PENDING_IRQ);
    kt_assert!(ipcc_pending(&ip, 8).is_empty());
    ip.set(IPCC_REG_RECV_ID, (24 << 16) | 2);
    ip.clear_log();
    kt_assert_eq!(ipcc_pending(&ip, 1), vec![(24u16, 2u16)]);
    kt_assert_eq!(
        ip.writes(),
        vec![(IPCC_REG_RECV_SIGNAL_CLEAR, (24 << 16) | 2)]
    );
    ipcc_set_enabled(&ip, 24, 2, true);
    ipcc_set_enabled(&ip, 24, 2, false);
    let w: Vec<(u32, u32)> = ip.writes().into_iter().skip(1).collect();
    kt_assert_eq!(
        w,
        vec![
            (IPCC_REG_RECV_SIGNAL_ENABLE, (24 << 16) | 2),
            (IPCC_REG_RECV_SIGNAL_DISABLE, (24 << 16) | 2)
        ]
    );
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_irq_gic_cookie_and_ipcc);

/// `GicSpi::set_enabled` on QEMU virt's GICv3: an edge pended while the
/// line is masked (`disable_irq_nosync`) is not delivered, and is
/// delivered once on unmask (`enable_irq`) — the protocol the ath11k AHB
/// HIF relies on.
#[cfg(target_arch = "aarch64")]
fn smoke_qcom_irq_gic_spi_mask_latches() -> TestResult {
    use narf_interrupts::aarch64::gic;
    static HITS: AtomicU32 = AtomicU32::new(0);
    fn handler(_cookie: u64) -> narf_interrupts::IrqStatus {
        HITS.fetch_add(1, Ordering::AcqRel);
        narf_interrupts::IrqStatus::Handled
    }
    fn wait_hits(n: u32, ms: u64) {
        let start = narf_time::Instant::now();
        while HITS.load(Ordering::Acquire) < n
            && narf_time::Instant::now().cycles_since(start)
                < narf_time::ns_to_cycles(ms * 1_000_000)
        {
            core::hint::spin_loop();
        }
    }
    let Some(line) = (200u32..240)
        .filter(|i| *i < gic::spi_limit())
        .find_map(|i| GicSpi::bind(i, true).ok())
    else {
        return TestResult::Skip("no free SPI dispatch slot");
    };
    line.install("qcom-irq-mask-test", 1, handler);
    HITS.store(0, Ordering::Release);
    let was = narf_arch::interrupts_enabled();
    line.set_enabled(false);
    let _ = gic::pend_spi(line.intid());
    // SAFETY: the GIC is initialised at boot and the SPI is ours.
    unsafe { narf_arch::enable_interrupts() };
    wait_hits(1, 50);
    let while_masked = HITS.load(Ordering::Acquire);
    line.set_enabled(true);
    wait_hits(1, 500);
    let after = HITS.load(Ordering::Acquire);
    if !was {
        // SAFETY: restore the caller's mask.
        unsafe { narf_arch::disable_interrupts() };
    }
    line.release("qcom-irq-mask-test", 1);
    kt_assert_eq!(while_masked, 0);
    kt_assert_eq!(after, 1);
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("drivers/soc/qcom", smoke_qcom_irq_gic_spi_mask_latches);

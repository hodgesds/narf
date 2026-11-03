//! Display runtime-PM fixtures: the real runtime-PM core and PCI layer
//! over a model config space and a fake clock, with a driver whose park
//! runs this module's admission over its own registry. Nothing sleeps.

use super::*;
use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use core::task::{Context, Poll, Waker};
use narf_bus::pci::{PciError, PciPowerState};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_power::runtime_pm::{ManualEnv, RpmError, RpmFuture, RuntimePmOps};
use narf_power::runtime_pm_pci::{register_with_io, PciPmIo, PciRuntimeNode, PciTarget};

fn run<T>(future: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}

/// A BAR identity no probed function uses.
const BAR: u64 = 0xdead_0000_0000;

struct Pci {
    power: IrqSafeSpinLock<PciPowerState>,
    accesses: AtomicU32,
    env: Arc<ManualEnv>,
}
impl PciPmIo for Pci {
    fn power_state(&self) -> Result<Option<PciPowerState>, PciError> {
        self.accesses.fetch_add(1, Ordering::Relaxed);
        Ok(Some(*self.power.lock()))
    }
    fn set_power_state(&self, state: PciPowerState) -> Result<(), PciError> {
        self.accesses.fetch_add(1, Ordering::Relaxed);
        *self.power.lock() = state;
        Ok(())
    }
    fn save_state(&self) -> Result<(), PciError> {
        Ok(())
    }
    fn restore_state(&self) -> Result<(), PciError> {
        Ok(())
    }
    fn delay_ms(&self, ms: u64) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move { self.env.advance_ms(ms) })
    }
}

/// A park that can be held open to observe the Suspending window. The
/// fixture re-polls the suspend future itself, so no waker is kept.
#[derive(Default)]
struct Gate {
    closed: AtomicBool,
}
impl Gate {
    fn wait(&self) -> impl Future<Output = ()> + '_ {
        core::future::poll_fn(move |_| {
            if self.closed.load(Ordering::Acquire) {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
    }
}

/// The owner's park admission over this fixture's registry: a running,
/// idle integrated GT with an owned display and no local memory.
struct Owner {
    registry: Arc<Registry>,
    parks: AtomicU32,
    refused: AtomicU32,
    resumes: AtomicU32,
    gate: Gate,
}
impl RuntimePmOps for Owner {
    fn runtime_suspend(&self) -> RpmFuture<'_> {
        Box::pin(async move {
            let display = classify(Facts {
                lit: self.registry.lit(BAR),
                ..Facts::default()
            });
            if park_refusal(false, true, Ok(Profile::Display), None, display).is_some() {
                self.refused.fetch_add(1, Ordering::Relaxed);
                return Err(RpmError::Busy);
            }
            self.gate.wait().await;
            self.parks.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
    }
    fn runtime_resume(&self) -> RpmFuture<'_> {
        Box::pin(async move {
            self.resumes.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
    }
}

struct Fixture {
    env: Arc<ManualEnv>,
    pci: Arc<Pci>,
    owner: Arc<Owner>,
    node: PciRuntimeNode,
    registry: Arc<Registry>,
}
impl Fixture {
    /// Probe order: KMS install reports Pipe A lit (when `lit`), then the
    /// GT owner registers, binds the display and arms autosuspend.
    fn new(lit: bool) -> Self {
        let env = ManualEnv::new();
        let registry = Arc::new(Registry::new());
        if lit {
            registry.pipe_lit(BAR, 0);
        }
        let pci = Arc::new(Pci {
            power: IrqSafeSpinLock::new(PciPowerState::D0),
            accesses: AtomicU32::new(0),
            env: env.clone(),
        });
        let owner = Arc::new(Owner {
            registry: registry.clone(),
            parks: AtomicU32::new(0),
            refused: AtomicU32::new(0),
            resumes: AtomicU32::new(0),
            gate: Gate::default(),
        });
        let node = register_with_io(
            "intel-display-rpm-fixture",
            pci.clone(),
            owner.clone(),
            None,
            None,
            env.clone(),
        )
        .unwrap();
        assert_eq!(registry.bind(BAR, node.device.clone()), u32::from(lit));
        run(node.device.set_autosuspend_delay(1000));
        run(node.device.use_autosuspend(true));
        node.device.mark_last_busy();
        node.device.allow();
        node.device.put_autosuspend().unwrap();
        Self {
            env,
            pci,
            owner,
            node,
            registry,
        }
    }
    fn after(&self, ms: u64) {
        self.env.advance_ms(ms);
        run(self.env.run_pending());
    }
    fn status(&self) -> RpmStatus {
        self.node.device.status()
    }
    fn usage(&self) -> i32 {
        self.node.device.state().usage_count
    }
}

fn smoke_display_rpm_lit_panel_keeps_d0_and_dark_panel_autosuspends() -> TestResult {
    let f = Fixture::new(true);
    assert_eq!(f.usage(), 1, "the lit panel holds exactly one wakeref");
    f.after(60_000);
    assert_eq!(f.status(), RpmStatus::Active);
    assert_eq!(f.node.pci.current(), PciTarget::D0);
    assert_eq!(
        f.owner.parks.load(Ordering::Relaxed) + f.owner.refused.load(Ordering::Relaxed),
        0,
        "a lit panel must keep the RPM core from even trying to park"
    );
    // The pipe goes dark (crtc disable): its wakeref is put with
    // autosuspend, and the function parks one delay later.
    f.registry.pipe_dark(BAR, 0);
    assert_eq!(f.usage(), 0);
    f.after(999);
    assert_eq!(f.status(), RpmStatus::Active, "parked before the delay");
    f.after(1);
    assert_eq!(f.status(), RpmStatus::Suspended);
    assert_eq!(f.node.pci.current(), PciTarget::D3Hot);
    assert_eq!(f.owner.parks.load(Ordering::Relaxed), 1);
    // A dark pipe reported again is not a second release.
    f.registry.pipe_dark(BAR, 0);
    assert_eq!(f.usage(), 0, "an unbalanced dark report underflowed");
    // Lighting it again: the producer resumes first, then the pipe holds
    // its own wakeref; dropping the resume reference keeps D0.
    run(f.node.device.resume_and_get()).unwrap();
    assert_eq!(f.owner.resumes.load(Ordering::Relaxed), 1);
    f.registry.pipe_lit(BAR, 0);
    f.registry.pipe_lit(BAR, 0);
    assert_eq!(f.usage(), 2, "a repeated lit report took a second wakeref");
    f.node.device.put_autosuspend().unwrap();
    f.after(10_000);
    assert_eq!(f.status(), RpmStatus::Active);
    assert_eq!(f.owner.parks.load(Ordering::Relaxed), 1);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_power",
    smoke_display_rpm_lit_panel_keeps_d0_and_dark_panel_autosuspends
);

fn smoke_display_rpm_wakeref_races_with_suspend_fail_closed() -> TestResult {
    let f = Fixture::new(false);
    // Probe-time references before the bind hold nothing.
    let unbound = Registry::new();
    assert!(matches!(unbound.wakeref_if_active(BAR), Ok(None)));
    // A display conversation that started first holds the function: the
    // RPM core refuses the suspend without calling the driver.
    let wakeref = f.registry.wakeref_if_active(BAR).unwrap().unwrap();
    assert_eq!(f.usage(), 1);
    assert!(run(f.node.device.suspend()).is_err());
    f.after(5000);
    assert_eq!(f.status(), RpmStatus::Active);
    assert_eq!(f.owner.parks.load(Ordering::Relaxed), 0);
    // Its release re-arms autosuspend (xe_pm_runtime_put).
    drop(wakeref);
    // A park in flight: new display work fails closed before any access.
    f.owner.gate.closed.store(true, Ordering::Release);
    f.env.advance_ms(1000);
    let mut suspend = core::pin::pin!(f.node.device.suspend());
    let mut cx = Context::from_waker(Waker::noop());
    assert!(suspend.as_mut().poll(&mut cx).is_pending());
    assert_eq!(f.status(), RpmStatus::Suspending);
    let accesses = f.pci.accesses.load(Ordering::Relaxed);
    assert_eq!(f.registry.wakeref_if_active(BAR).err(), Some(Suspended));
    assert_eq!(f.usage(), 0, "a refused acquisition leaked a reference");
    f.owner.gate.closed.store(false, Ordering::Release);
    assert!(matches!(suspend.as_mut().poll(&mut cx), Poll::Ready(Ok(_))));
    assert_eq!(f.status(), RpmStatus::Suspended);
    assert_eq!(f.owner.parks.load(Ordering::Relaxed), 1);
    assert_eq!(f.registry.wakeref_if_active(BAR).err(), Some(Suspended));
    assert!(
        f.pci.accesses.load(Ordering::Relaxed) > accesses,
        "the park itself must reach D3hot"
    );
    // After a resume the same conversation succeeds and holds D0.
    run(f.node.device.resume_and_get()).unwrap();
    let wakeref = f.registry.wakeref_if_active(BAR).unwrap();
    assert!(wakeref.is_some());
    f.node.device.put_autosuspend().unwrap();
    f.after(5000);
    assert_eq!(f.status(), RpmStatus::Active);
    drop(wakeref);
    f.after(1000);
    assert_eq!(f.status(), RpmStatus::Suspended);
    // Runtime PM disabled on an active function: nothing can suspend it,
    // so a conversation proceeds without a reference.
    run(f.node.device.resume_and_get()).unwrap();
    run(f.node.device.disable());
    assert!(matches!(f.registry.wakeref_if_active(BAR), Ok(None)));
    f.node.device.enable();
    f.node.device.put_autosuspend().unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_power",
    smoke_display_rpm_wakeref_races_with_suspend_fail_closed
);

fn smoke_display_rpm_bind_counts_lit_pipes_and_rebind_returns_refs() -> TestResult {
    let f = Fixture::new(false);
    let registry = Registry::new();
    registry.pipe_lit(BAR, 0);
    registry.pipe_lit(BAR, 2);
    registry.pipe_lit(BAR, 2);
    registry.pipe_dark(BAR, 3);
    registry.pipe_lit(BAR, 32);
    assert_eq!(registry.lit(BAR), 0b101);
    assert_eq!(registry.lit(BAR + 1), 0);
    let before = f.usage();
    assert_eq!(registry.bind(BAR, f.node.device.clone()), 2);
    assert_eq!(f.usage(), before + 2);
    assert_eq!(
        registry.bind(BAR, f.node.device.clone()),
        0,
        "rebind is idempotent"
    );
    assert_eq!(f.usage(), before + 2);
    // A second owner of the same BAR takes over: the old device's
    // references are returned, the new one holds them.
    let g = Fixture::new(false);
    let other = g.usage();
    assert_eq!(registry.bind(BAR, g.node.device.clone()), 2);
    assert_eq!(f.usage(), before);
    assert_eq!(g.usage(), other + 2);
    registry.pipe_dark(BAR, 0);
    registry.pipe_dark(BAR, 2);
    assert_eq!(g.usage(), other);
    registry.forget(BAR);
    assert_eq!(registry.lit(BAR), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_power",
    smoke_display_rpm_bind_counts_lit_pipes_and_rebind_returns_refs
);

fn smoke_display_rpm_park_admission_holds_and_system_memory_mappings() -> TestResult {
    let display = Ok(Profile::Display);
    let discrete = Ok(Profile::DisplayLess);
    // Hold order: lit pipes, DC_off, deferred re-entry, external, KMS.
    let all = Facts {
        lit: 1,
        dc_refs: 2,
        dc_reentry: true,
        external: true,
        kms: true,
    };
    assert_eq!(classify(all), Some(Hold::PipesLit(1)));
    let all = Facts { lit: 0, ..all };
    assert_eq!(classify(all), Some(Hold::DcOff(2)));
    let all = Facts { dc_refs: 0, ..all };
    assert_eq!(classify(all), Some(Hold::DcReentry));
    let all = Facts {
        dc_reentry: false,
        ..all
    };
    assert_eq!(classify(all), Some(Hold::ExternalRoute));
    let all = Facts {
        external: false,
        ..all
    };
    assert_eq!(classify(all), Some(Hold::Kms));
    assert_eq!(classify(Facts::default()), None);
    // An integrated function has no local memory: live CPU mappings of its
    // system-memory objects are not an input and never refuse the park.
    assert_eq!(park_refusal(false, true, display, None, None), None);
    assert_eq!(
        park_refusal(false, true, display, None, Some(Hold::PipesLit(1))),
        Some(ParkRefusal::Display(Hold::PipesLit(1)))
    );
    // A discrete function refuses while local memory is allocated, and a
    // display hold is no input there.
    assert_eq!(
        park_refusal(false, true, discrete, Some(4096), None),
        Some(ParkRefusal::LocalMemory(4096))
    );
    assert_eq!(park_refusal(false, true, discrete, Some(0), None), None);
    assert_eq!(
        park_refusal(false, true, discrete, None, Some(Hold::Kms)),
        None
    );
    // System sleep, a non-running GT and a refused profile come first.
    assert_eq!(
        park_refusal(true, true, display, None, None),
        Some(ParkRefusal::SystemSuspend)
    );
    assert_eq!(
        park_refusal(false, false, display, None, None),
        Some(ParkRefusal::NotRunning)
    );
    assert_eq!(
        park_refusal(
            false,
            true,
            Err(ProfileRefusal::SmallBar),
            Some(1),
            Some(Hold::Kms)
        ),
        Some(ParkRefusal::Profile(ProfileRefusal::SmallBar))
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_power",
    smoke_display_rpm_park_admission_holds_and_system_memory_mappings
);

fn smoke_display_rpm_profiles_admit_integrated_displays_only() -> TestResult {
    let platform = |device: u16| GtPlatform::from_pci(0x8086, device);
    for (device, name) in [
        (0x7d55, "MTL"),
        (crate::intel_gpu::ARL_7D41, "ARL"),
        (0x9a49, "TGL"),
        (0x46a6, "ADL-P"),
        (0x4680, "ADL-S"),
    ] {
        assert!(platform(device).is_some(), "{name} not admitted");
        assert_eq!(
            profile(platform(device), true, false),
            Ok(Profile::Display),
            "{name}"
        );
        assert_eq!(
            profile(platform(device), false, false),
            Err(ProfileRefusal::NoDisplayOwner),
            "{name}"
        );
    }
    // The existing refusal for a display-less TGL owner is unchanged.
    assert!(!crate::intel_gpu_gt_runtime::autosuspend_profile_eligible(
        platform(0x9a49),
        false
    ));
    assert!(crate::intel_gpu_gt_runtime::autosuspend_profile_eligible(
        platform(0x9a49),
        true
    ));
    for device in [0x6420, 0xb080] {
        assert_eq!(
            profile(platform(device), false, false),
            Err(ProfileRefusal::HeadlessTakeover)
        );
    }
    assert_eq!(
        profile(platform(0x56a0), false, false),
        Ok(Profile::DisplayLess)
    );
    assert_eq!(
        profile(platform(0x56a0), true, false),
        Err(ProfileRefusal::DiscreteDisplay)
    );
    assert_eq!(
        profile(platform(0xe20b), false, true),
        Err(ProfileRefusal::SmallBar)
    );
    assert_eq!(
        profile(platform(0xe20b), false, false),
        Ok(Profile::DisplayLess)
    );
    assert_eq!(profile(None, true, false), Err(ProfileRefusal::Unsupported));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_power",
    smoke_display_rpm_profiles_admit_integrated_displays_only
);

fn smoke_display_rpm_hpd_poll_waits_one_period_per_detect() -> TestResult {
    let mut poll = HpdPoll::default();
    assert!(
        !poll.due(100),
        "the first suspended iteration only starts the period"
    );
    assert!(!poll.due(100 + HPD_POLL_PERIOD_NS - 1));
    assert!(poll.due(100 + HPD_POLL_PERIOD_NS));
    assert!(!poll.due(100 + HPD_POLL_PERIOD_NS + 1));
    assert!(poll.due(100 + 2 * HPD_POLL_PERIOD_NS));
    // Active again: the per-iteration pass runs and the period restarts.
    poll.active();
    assert!(!poll.due(100 + 3 * HPD_POLL_PERIOD_NS));
    assert!(poll.due(100 + 4 * HPD_POLL_PERIOD_NS));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_power",
    smoke_display_rpm_hpd_poll_waits_one_period_per_detect
);

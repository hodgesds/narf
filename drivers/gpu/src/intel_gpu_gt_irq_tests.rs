use super::*;
use alloc::{collections::BTreeMap, task::Wake, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

// Authored register model: level source -> bank -> W1C graphics/tile latches.
// Identities are independent fixed wire words, never production encodings.
struct Registers {
    words: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    events: Vec<&'static str>,
    vector: Option<u8>,
    identity: u32,
    delay: bool,
    unavailable: bool,
    program_fail: bool,
    enable_fail: bool,
    disable_fail: bool,
    reject: Option<u64>,
}
#[derive(Clone)]
struct Window(Arc<IrqSafeSpinLock<Registers>>);
impl Window {
    fn new() -> Self {
        let words = [
            (0x190008, 0),
            (0x190010, 0),
            (0x190018, 0),
            (0x190030, 0x20000001),
            (0x190090, 0xffff0001),
            (0x1900a0, 0xffff0002),
            (0x190038, 0x10),
            (0x1900e8, 0xffff9234),
            (0x20a8, 0xffffffff),
            (0x220a8, 0xfffffffe),
            (0x19011c, 0x5a5affff),
            (0x3ee0a8, 0xa5a5ffff),
            (0x190048, 0x0000_0003),
            (0x190100, 0xffff_0004),
            (0x1a0a8, 0xffff_ffff),
            (0x1c0a8, 0x1234_ffff),
            (0x1e0a8, 0x5678_ffff),
            (0x260a8, 0x9abc_ffff),
            (0x190104, 0xabcd_ffff),
        ]
        .into_iter()
        .collect();
        Self(Arc::new(IrqSafeSpinLock::new(Registers {
            words,
            writes: Vec::new(),
            events: Vec::new(),
            vector: None,
            identity: 0,
            delay: false,
            unavailable: false,
            program_fail: false,
            enable_fail: false,
            disable_fail: false,
            reject: None,
        })))
    }
    fn raise(&self, bits: u32) {
        let vector = {
            let mut r = self.0.lock();
            *r.words.get_mut(&0x190018).unwrap() |= bits;
            *r.words.get_mut(&0x190010).unwrap() |= 1;
            *r.words.get_mut(&0x190008).unwrap() |= 1;
            r.vector
        };
        narf_interrupts::dispatch::on_irq(vector.expect("installed MSI route"));
    }
}
impl MmioWindow for Window {
    fn read32(&self, offset: u64) -> u32 {
        let r = self.0.lock();
        if r.unavailable {
            return u32::MAX;
        }
        if offset == 0x190060 {
            return if r.delay { 0 } else { r.identity };
        }
        *r.words.get(&offset).unwrap_or(&0)
    }
    fn write32(&self, offset: u64, value: u32) {
        let mut r = self.0.lock();
        r.writes.push((offset, value));
        if r.unavailable || r.reject == Some(offset) {
            return;
        }
        match offset {
            0x190008 | 0x190010 => {
                let old = *r.words.get(&offset).unwrap_or(&0);
                r.words
                    .insert(offset, (old & !value & 0x7fffffff) | (value & 0x80000000));
            }
            0x190018 => {
                assert!(r.identity == 0, "bank ack preceded identity ack");
                let old = *r.words.get(&offset).unwrap_or(&0);
                r.words.insert(offset, old & !value);
            }
            0x190070 => {
                r.identity = match value {
                    1 => 0x80000001,          // valid RCS0 MI_USER_INTERRUPT
                    0x8000 => 0x80030010,     // valid COPY0 FLUSH_COMPLETE
                    0x00800000 => 0x80830010, // valid COPY hardware8 FLUSH_COMPLETE
                    0x10 => 0x80050001,
                    0x20 => 0x80150001,
                    0x40 => 0x80250001,
                    0x80 => 0x80350001,       // valid COMPUTE0 MI_USER_INTERRUPT
                    0x02000000 => 0x80048000, // valid OTHER0 GUC2HOST
                    _ => panic!("selected an unowned interrupt"),
                };
            }
            0x190060 => {
                assert_eq!(value, r.identity);
                r.identity = 0;
            }
            _ => {
                r.words.insert(offset, value);
            }
        }
    }
}
struct Route(Window);
impl MessageRoute for Route {
    fn program(&mut self, vector: u8) -> Result<(), IrqError> {
        let mut r = self.0 .0.lock();
        r.events.push("program");
        r.vector = Some(vector);
        if r.program_fail {
            Err(IrqError::Route)
        } else {
            Ok(())
        }
    }
    fn enable(&mut self) -> Result<(), IrqError> {
        let mut r = self.0 .0.lock();
        let vector = r.vector.unwrap();
        assert!(narf_interrupts::dispatch::installed_handler_names(vector).contains(&"intel-gt"));
        assert_eq!(r.words[&0x190008] & 0x80000000, 0);
        r.events.push("enable");
        if r.enable_fail {
            Err(IrqError::Route)
        } else {
            Ok(())
        }
    }
    fn disable(&mut self) -> bool {
        let mut r = self.0 .0.lock();
        if !r.unavailable {
            assert_eq!(
                r.words[&0x190008] & 0x80000000,
                0,
                "MSI disabled before device mask"
            );
        }
        r.events.push("disable");
        !r.disable_fail && !r.unavailable
    }
}
struct Wakes(core::sync::atomic::AtomicU32);
impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
}
fn install(w: &Window) -> Delivery<Window, Route> {
    Delivery::install(w.clone(), Route(w.clone())).unwrap()
}

fn smoke_gt_irq_route_decode_wait_and_teardown() -> TestResult {
    let w = Window::new();
    let saved = w.0.lock().words.clone();
    let irq = install(&w);
    let vector = irq.vector();
    assert_eq!(irq.service(0), Ok(false));
    assert_eq!(w.read32(0x190030), 0x20110011);
    assert_eq!(w.read32(0x190090), 0xffee0001);
    assert_eq!(w.read32(0x1900a0), 0xffee0002);
    assert_eq!(w.read32(0x190038), 0x80000010);
    assert_eq!(w.read32(0x1900e8), 0x7fff9234);
    assert_eq!(w.read32(0x20a8), 0xffffffee);
    assert_eq!(w.read32(0x220a8), 0xffffffee);
    let wakes = Arc::new(Wakes(core::sync::atomic::AtomicU32::new(0)));
    let waker = Waker::from(wakes.clone());
    let mut cx = Context::from_waker(&waker);
    let mut wait = narf_interrupts::wait_for_irq(vector);
    // Raise before the first poll: the captured epoch must still observe it.
    w.raise(0x02000001);
    assert!(matches!(Pin::new(&mut wait).poll(&mut cx), Poll::Ready(_)));
    assert_eq!(w.read32(0x190008) & 0x80000000, 0);
    assert_eq!(irq.service(10), Ok(true));
    assert_eq!(irq.service(20), Ok(true));
    assert_eq!(irq.service(30), Ok(false));
    assert_eq!(w.read32(0x190018), 0);
    drop(wait);
    let mut wait = narf_interrupts::wait_for_irq(vector);
    assert!(Pin::new(&mut wait).poll(&mut cx).is_pending());
    w.raise(1);
    assert!(wakes.0.load(core::sync::atomic::Ordering::Relaxed) != 0);
    assert!(Pin::new(&mut wait).poll(&mut cx).is_ready());
    assert_eq!(irq.service(40), Ok(true));
    assert_eq!(irq.service(50), Ok(false));
    drop(wait);
    // BCS0 shares bank zero; its identity must decode as COPY instance 0.
    let mut wait = narf_interrupts::wait_for_irq(vector);
    assert!(Pin::new(&mut wait).poll(&mut cx).is_pending());
    w.raise(0x8001);
    assert!(Pin::new(&mut wait).poll(&mut cx).is_ready());
    assert_eq!(irq.service(51), Ok(true)); // RCS0 first
    assert_eq!(irq.service(52), Ok(true)); // then BCS0
    assert_eq!(irq.service(53), Ok(false));
    assert_eq!(w.read32(0x190018), 0);
    drop(wait);
    // A missed physical MSI is still decoded and rearmed by the watchdog.
    {
        let mut r = w.0.lock();
        r.words.insert(0x190008, 0x80000001);
        r.words.insert(0x190010, 0x80000001);
        r.words.insert(0x190018, 1);
    }
    assert_eq!(irq.service(60), Ok(true));
    assert_eq!(irq.service(70), Ok(false));
    drop(irq);
    assert!(!narf_interrupts::vector::is_allocated(vector));
    assert!(!narf_interrupts::dispatch::installed_handler_names(vector).contains(&"intel-gt"));
    for offset in [
        0x190010, 0x190030, 0x190090, 0x1900a0, 0x190038, 0x1900e8, 0x20a8, 0x220a8,
    ] {
        assert_eq!(w.read32(offset), saved[&offset]);
    }
    assert_eq!(w.0.lock().events, ["program", "enable", "disable"]);
    // Suspend/reset starts a fresh delivery graph after the first is quiet.
    let again = install(&w);
    assert_eq!(again.service(100), Ok(false));
    // A newly unmasked media GuC retains the shared enable bit on teardown.
    w.write32(0x1900e8, 0x7fff1234);
    drop(again);
    assert_eq!(w.read32(0x190038), 0x80000010);
    assert_eq!(w.read32(0x1900e8), 0xffff1234);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gt_irq",
    smoke_gt_irq_route_decode_wait_and_teardown
);

fn smoke_gt_irq_compute_routes_decode_and_teardown() -> TestResult {
    let w = Window::new();
    let saved = w.0.lock().words.clone();
    let irq = Delivery::install_with(
        w.clone(),
        Route(w.clone()),
        EngineSet::of(&[Engine::Rcs0, Engine::Bcs0, Engine::Ccs0]),
    )
    .unwrap();
    assert_eq!(irq.service(0), Ok(false));
    // ENGINE1 (CCS0) halves only; CCS1 bits and unrelated bits preserved.
    assert_eq!(w.read32(0x190048), 0x0011_0003);
    assert_eq!(w.read32(0x190100), 0xffee_0004);
    assert_eq!(w.read32(0x1a0a8), 0xffff_ffee);
    // INTR_CCS(0) decodes as COMPUTE class instance 0.
    w.raise(0x10);
    assert_eq!(irq.service(1), Ok(true));
    assert_eq!(irq.service(2), Ok(false));
    assert_eq!(w.read32(0x190018), 0);
    drop(irq);
    for offset in [0x190048, 0x190100, 0x1a0a8] {
        assert_eq!(w.read32(offset), saved[&offset]);
    }
    // Without a published CCS0, its bank bit is a foreign cause.
    let w = Window::new();
    let irq = install(&w);
    irq.service(0).unwrap();
    w.raise(0x10);
    assert_eq!(irq.service(1), Err(IrqError::Conflict));
    drop(irq);
    assert_eq!(w.read32(0x190048), 3, "unowned CCS sources were enabled");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gt_irq",
    smoke_gt_irq_compute_routes_decode_and_teardown
);

fn smoke_gt_irq_multi_compute_physical_masks_and_foreign_identity() -> TestResult {
    for engines in [
        EngineSet::of(&[Engine::Rcs0, Engine::Bcs0, Engine::Ccs1, Engine::Ccs3]),
        EngineSet::of(&Engine::ALL),
    ] {
        let w = Window::new();
        let saved = w.0.lock().words.clone();
        let irq = Delivery::install_with(w.clone(), Route(w.clone()), engines).unwrap();
        assert_eq!(irq.service(0), Ok(false));
        let sparse = !engines.contains(Engine::Ccs0);
        assert_eq!(
            w.read32(0x190100),
            if sparse {
                0xffff_0004 & !0x11
            } else {
                0xffee_0004 & !0x11
            }
        );
        assert_eq!(
            w.read32(0x190104),
            if sparse { 0xabcd_ffee } else { 0xabcc_ffee }
        );
        for (n, bit) in [0x10u32, 0x20, 0x40, 0x80].into_iter().enumerate() {
            if sparse && n % 2 == 0 {
                continue;
            }
            w.raise(bit);
            assert_eq!(irq.service(10 + n as u64 * 2), Ok(true));
            assert_eq!(irq.service(11 + n as u64 * 2), Ok(false));
        }
        drop(irq);
        for offset in [
            0x190048, 0x190100, 0x190104, 0x1a0a8, 0x1c0a8, 0x1e0a8, 0x260a8,
        ] {
            assert_eq!(w.read32(offset), saved[&offset]);
        }
    }
    let w = Window::new();
    let irq = Delivery::install_with(
        w.clone(),
        Route(w.clone()),
        EngineSet::of(&[Engine::Rcs0, Engine::Bcs0, Engine::Ccs3]),
    )
    .unwrap();
    irq.service(0).unwrap();
    w.raise(0x80);
    assert_eq!(irq.service(1), Ok(true));
    w.0.lock().identity = 0x80050001;
    assert_eq!(irq.service(2), Err(IrqError::Identity));
    assert_eq!(w.read32(0x190018), 0x80);
    drop(irq);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_multi_ccs",
    smoke_gt_irq_multi_compute_physical_masks_and_foreign_identity
);

fn smoke_gt_irq_copy8_identity_shared_mask_and_teardown() -> TestResult {
    let w = Window::new();
    let irq = Delivery::install_with(
        w.clone(),
        Route(w.clone()),
        EngineSet::of(&[Engine::Rcs0, Engine::Bcs0, Engine::Bcs8]),
    )
    .unwrap();
    assert_eq!(w.read32(0x19011c), 0x5a5affee);
    assert_eq!(w.read32(0x3ee0a8), 0xa5a5ffee);
    irq.service(0).unwrap();
    w.raise(0x00800000);
    assert_eq!(irq.service(1), Ok(true));
    assert_eq!(irq.service(2), Ok(false));
    assert_eq!(w.read32(0x190018), 0);
    // BCS7's high-half owner may change independently. Preserve its latest
    // bits while restoring only BCS8's saved low-half event mask.
    w.0.lock().words.insert(0x19011c, 0x1234ffee);
    drop(irq);
    assert_eq!(w.read32(0x19011c), 0x1234ffff);
    assert_eq!(w.read32(0x3ee0a8), 0xa5a5ffff);
    let irq = Delivery::install_with(
        w.clone(),
        Route(w.clone()),
        EngineSet::of(&[Engine::Rcs0, Engine::Bcs0, Engine::Bcs8]),
    )
    .unwrap();
    irq.service(3).unwrap();
    w.raise(0x00800000);
    assert_eq!(irq.service(4), Ok(true));
    w.0.lock().identity = 0x80030010; // class COPY but wrong physical instance
    assert_eq!(irq.service(5), Err(IrqError::Identity));
    assert_eq!(w.read32(0x190018), 0x00800000);
    drop(irq);
    // Without published COPY1, the same bank cause is foreign and remains
    // masked; no decoder may pretend that it came from COPY0.
    // Raise a fresh hierarchy: the rejected identity above retained DW but
    // its MASTER bank indication had already been acknowledged. Like Linux
    // xe_irq.c::gt_irq_handler, service only reads a bank indicated by MASTER.
    let w = Window::new();
    let irq = install(&w);
    assert_eq!(irq.service(6), Ok(false));
    let writes = w.0.lock().writes.len();
    w.raise(0x00800000);
    assert_eq!(irq.service(7), Err(IrqError::Conflict));
    assert_eq!(w.read32(0x190018), 0x00800000);
    assert_eq!(w.read32(0x19011c), 0x5a5affff);
    assert_eq!(w.read32(0x3ee0a8), 0xa5a5ffff);
    assert!(!w.0.lock().writes[writes..]
        .iter()
        .any(|(offset, _)| matches!(*offset, 0x190018 | 0x190060 | 0x190070)));
    drop(irq);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gt_irq",
    smoke_gt_irq_copy8_identity_shared_mask_and_teardown
);

fn smoke_gt_irq_delayed_identity_timeout_and_foreign_causes() -> TestResult {
    let w = Window::new();
    let irq = install(&w);
    irq.service(0).unwrap();
    w.0.lock().delay = true;
    w.raise(1);
    assert_eq!(irq.service(100), Ok(true));
    let writes = w.0.lock().writes.len();
    assert_eq!(irq.service(100_099), Ok(true));
    assert_eq!(w.0.lock().writes.len(), writes); // never spin or ack an invalid identity
    assert_eq!(irq.service(100_100), Err(IrqError::Timeout));
    w.0.lock().delay = false;
    assert_eq!(irq.service(100_101), Ok(false));
    drop(irq);
    for (offset, value) in [(0x190010, 0x10000), (0x190018, 0x1000000)] {
        let w = Window::new();
        let irq = install(&w);
        irq.service(0).unwrap();
        w.raise(1);
        w.0.lock().words.insert(offset, value);
        assert_eq!(irq.service(1), Err(IrqError::Conflict));
        drop(irq);
        assert_eq!(w.read32(offset), value); // unrelated W1C status is preserved
        assert_eq!(w.read32(0x190008) & 0x80000000, 0);
    }
    let w = Window::new();
    let irq = install(&w);
    irq.service(0).unwrap();
    w.raise(0x02000000);
    assert_eq!(irq.service(0), Ok(true));
    w.0.lock().identity = 0x81048000; // media OTHER16, never our primary GuC
    assert_eq!(irq.service(1), Err(IrqError::Identity));
    drop(irq);
    assert_eq!(w.0.lock().identity, 0x81048000);
    // A render or BCS1 identity behind the BCS0 bank bit is never acked.
    for identity in [0x80000001, 0x80130001] {
        let w = Window::new();
        let irq = install(&w);
        irq.service(0).unwrap();
        w.raise(0x8000);
        assert_eq!(irq.service(0), Ok(true));
        w.0.lock().identity = identity;
        assert_eq!(irq.service(1), Err(IrqError::Identity));
        drop(irq);
        assert_eq!(w.0.lock().identity, identity);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gt_irq",
    smoke_gt_irq_delayed_identity_timeout_and_foreign_causes
);

fn smoke_gt_irq_install_conflict_source_readback_and_route_rollback() -> TestResult {
    let absent = Window::new();
    absent.0.lock().unavailable = true;
    assert!(matches!(
        Delivery::install(absent.clone(), Route(absent.clone())),
        Err(IrqError::Unavailable)
    ));
    assert!(absent.0.lock().writes.is_empty());
    for (offset, value) in [(0x190008, 0x80000000), (0x190010, 0x10000), (0x190008, 2)] {
        let w = Window::new();
        w.0.lock().words.insert(offset, value);
        assert!(matches!(
            Delivery::install(w.clone(), Route(w.clone())),
            Err(IrqError::Conflict)
        ));
        assert!(w.0.lock().events.is_empty());
        assert!(w.0.lock().writes.is_empty());
    }
    for stage in 0..3 {
        let w = Window::new();
        {
            let mut r = w.0.lock();
            r.program_fail = stage == 0;
            r.enable_fail = stage == 1;
            r.reject = (stage == 2).then_some(0x190090);
        }
        assert!(matches!(
            Delivery::install(w.clone(), Route(w.clone())),
            Err(IrqError::Route)
        ));
        let vector = w.0.lock().vector.unwrap();
        assert!(!narf_interrupts::vector::is_allocated(vector));
        assert!(!narf_interrupts::dispatch::installed_handler_names(vector).contains(&"intel-gt"));
        assert_eq!(w.0.lock().events.last(), Some(&"disable"));
    }
    for offset in [0x190008, 0x190010] {
        let w = Window::new();
        w.0.lock().reject = Some(offset);
        let irq = install(&w);
        let vector = irq.vector();
        assert_eq!(irq.service(0), Err(IrqError::Route));
        drop(irq);
        assert!(!narf_interrupts::vector::is_allocated(vector));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gt_irq",
    smoke_gt_irq_install_conflict_source_readback_and_route_rollback
);

fn smoke_gt_irq_uncertain_teardown_keeps_vector_and_cookie() -> TestResult {
    for unavailable in [false, true] {
        let w = Window::new();
        let irq = install(&w);
        irq.service(0).unwrap();
        let vector = irq.vector();
        {
            let mut r = w.0.lock();
            r.disable_fail = !unavailable;
            r.unavailable = unavailable;
        }
        if unavailable {
            assert_eq!(irq.service(1), Err(IrqError::Unavailable));
        }
        drop(irq);
        assert!(narf_interrupts::vector::is_allocated(vector));
        assert!(narf_interrupts::dispatch::is_masked(vector));
        assert!(narf_interrupts::dispatch::installed_handler_names(vector).contains(&"intel-gt"));
        // A late device message is dropped rather than calling a freed cookie.
        narf_interrupts::dispatch::on_irq(vector);
        // The fixture can independently prove its synthetic device is quiet.
        // Production keeps this quarantine until real reset proof.
        w.0.lock().unavailable = false;
        w.write32(0x190008, 0);
        narf_interrupts::dispatch::clear_handler(vector);
        narf_interrupts::dispatch::synchronize_irq(vector);
        narf_interrupts::vector::free(vector).unwrap();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gt_irq",
    smoke_gt_irq_uncertain_teardown_keeps_vector_and_cookie
);

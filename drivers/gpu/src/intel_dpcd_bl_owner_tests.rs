//! Native panel/MMIO conversations through the actual retained owner, shared
//! IntelAux transport, arbitration and worker. No protocol callbacks replace
//! probe, readback, mode/enable programming or PPS/T8 completion.
use super::*;
use crate::intel_gpu_aux::{AUX_CTL_DONE, AUX_CTL_MSGSIZE_SHIFT, AUX_CTL_SEND_BUSY};
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::task::{Context, Poll, Waker};
use narf_kernel_test::{kernel_test_in, TestResult};

const CTL: u64 = 0x64010;
const DATA: u64 = 0x64014;
#[derive(Debug)]
struct Hardware {
    regs: BTreeMap<u64, u32>,
    dpcd: [u8; 0x800],
    wires: Vec<Vec<u8>>,
    writes: Vec<(u64, u32)>,
    authorized: bool,
    d0: bool,
    drop_dpcd: Option<u32>,
    nack: Option<u32>,
    lose_after: Option<u32>,
    defers: u8,
    control_reads: usize,
    fail_control_at: Option<usize>,
    now: u64,
}
#[derive(Clone, Debug)]
struct Panel(Arc<IrqSafeSpinLock<Hardware>>);
impl Panel {
    fn new(wide: bool, bits: u8) -> Self {
        let mut dpcd = [0; 0x800];
        dpcd[0x700..0x704].copy_from_slice(&[5, 5, if wide { 6 } else { 2 }, 0]);
        dpcd[0x720] = 0xa1; // preserve unrelated display controls
        dpcd[0x721] = 2;
        dpcd[0x722] = if wide { 1 } else { 77 };
        dpcd[0x723] = if wide { 0x23 } else { 0x5a };
        dpcd[0x724..0x727].copy_from_slice(&[bits, bits, bits]);
        Self(Arc::new(IrqSafeSpinLock::new(Hardware {
            regs: [
                (0x70008, 3 << 30),
                (0x60400, 0x8a000006),
                (0xc7200, 0x80000008),
                (0xc7204, 5),
            ]
            .into_iter()
            .collect(),
            dpcd,
            wires: Vec::new(),
            writes: Vec::new(),
            authorized: true,
            d0: true,
            drop_dpcd: None,
            nack: None,
            lose_after: None,
            defers: 0,
            control_reads: 0,
            fail_control_at: None,
            now: 1000,
        })))
    }
    fn set(&self, address: u32, value: u8) {
        self.0.lock().dpcd[address as usize] = value;
    }
    fn get(&self, address: u32) -> u8 {
        self.0.lock().dpcd[address as usize]
    }
    fn writes_to(&self, address: u32) -> Vec<Vec<u8>> {
        self.0
            .lock()
            .wires
            .iter()
            .filter(|wire| {
                wire[0] >> 4 == 8
                    && (u32::from(wire[0] & 15) << 16
                        | u32::from(wire[1]) << 8
                        | u32::from(wire[2]))
                        == address
            })
            .cloned()
            .collect()
    }
    fn send(hw: &mut Hardware, ctl: u32) {
        let length = ((ctl >> AUX_CTL_MSGSIZE_SHIFT) & 31) as usize;
        let wire: Vec<u8> = (0..length)
            .map(|i| {
                (hw.regs
                    .get(&(DATA + (i / 4) as u64 * 4))
                    .copied()
                    .unwrap_or(0)
                    >> (24 - i % 4 * 8)) as u8
            })
            .collect();
        let address =
            (u32::from(wire[0] & 15) << 16) | (u32::from(wire[1]) << 8) | u32::from(wire[2]);
        let n = usize::from(wire[3]) + 1;
        let mut reply = vec![0];
        let is_write = wire[0] >> 4 == 8;
        if hw.defers != 0 && address == LEVEL {
            hw.defers -= 1;
            reply[0] = 0x20;
        } else if hw.nack == Some(address) {
            reply[0] = 0x10;
        } else if wire[0] >> 4 == 9 {
            reply.extend_from_slice(&hw.dpcd[address as usize..address as usize + n]);
        } else {
            assert_eq!(wire.len(), 4 + n);
            if hw.drop_dpcd != Some(address) {
                hw.dpcd[address as usize..address as usize + n].copy_from_slice(&wire[4..]);
            }
        }
        hw.wires.push(wire);
        for (i, bytes) in reply.chunks(4).enumerate() {
            let mut word = [0; 4];
            word[..bytes.len()].copy_from_slice(bytes);
            hw.regs
                .insert(DATA + i as u64 * 4, u32::from_be_bytes(word));
        }
        hw.regs.insert(
            CTL,
            AUX_CTL_DONE | (reply.len() as u32) << AUX_CTL_MSGSIZE_SHIFT,
        );
        if is_write && hw.lose_after == Some(address) {
            hw.d0 = false;
        }
    }
}
impl MmioWindow for Panel {
    fn read32(&self, reg: u64) -> u32 {
        let mut hw = self.0.lock();
        if reg == crate::intel_gpu_edp::PP_CONTROL {
            hw.control_reads += 1;
            if hw.fail_control_at == Some(hw.control_reads) {
                return u32::MAX;
            }
        }
        if !hw.authorized || !hw.d0 {
            return u32::MAX;
        }
        hw.regs.get(&reg).copied().unwrap_or(0)
    }
    fn write32(&self, reg: u64, value: u32) {
        let mut hw = self.0.lock();
        if !hw.authorized || !hw.d0 {
            return;
        }
        hw.writes.push((reg, value));
        hw.regs.insert(reg, value);
        if reg == CTL {
            if value & AUX_CTL_SEND_BUSY != 0 {
                Self::send(&mut hw, value);
            } else {
                hw.regs.insert(CTL, 0);
            }
        }
        if reg == 0xc7204 {
            hw.regs
                .insert(0xc7200, if value & 1 != 0 { 0x80000008 } else { 0 });
        }
    }
}
impl PanelAccess for Panel {
    fn available(&self) -> bool {
        panel_live(self)
    }
    fn now(&self) -> u64 {
        self.0.lock().now
    }
    fn wait(&self, deadline: u64) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let panel = self.clone();
        let mut yielded = false;
        Box::pin(core::future::poll_fn(move |cx| {
            if !yielded {
                yielded = true;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            panel.0.lock().now = deadline;
            Poll::Ready(())
        }))
    }
}
type Native = Vesa<Channel<Panel>>;
fn owner(panel: &Panel) -> Arc<Native> {
    Vesa::probe(NAME, Channel(panel.clone())).unwrap()
}
fn run<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    for _ in 0..128 {
        if let Poll::Ready(value) = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            return value;
        }
    }
    panic!("retained AUX worker did not finish");
}
struct Registry(Vec<Arc<dyn BacklightDevice>>);
impl Registry {
    fn save() -> Self {
        let saved = narf_drivers_backlight::backlight_devices();
        for dev in &saved {
            narf_drivers_backlight::unregister_backlight(dev.name());
        }
        Self(saved)
    }
}
impl Drop for Registry {
    fn drop(&mut self) {
        for dev in narf_drivers_backlight::backlight_devices() {
            narf_drivers_backlight::unregister_backlight(dev.name());
        }
        for dev in &self.0 {
            narf_drivers_backlight::register_backlight(dev.clone());
        }
    }
}

fn smoke_intel_aux_backlight_production_probe_wire_width_bitcount_and_worker() -> TestResult {
    let _registry = Registry::save();
    for wide in [false, true] {
        let panel = Panel::new(wide, if wide { 12 } else { 8 });
        if wide {
            panel.set(0x702, 6 | 32);
            panel.set(MODE, 10);
            panel.set(FREQUENCY, 73);
        }
        let owner = owner(&panel);
        assert_eq!(owner.max_brightness(), if wide { 4095 } else { 255 });
        assert_eq!(owner.register(), Ownership::Owner);
        assert_eq!(panel.get(CONTROL), 0xa1);
        let before = panel.writes_to(LEVEL).len();
        owner.set_brightness(u32::MAX);
        assert_eq!(
            panel.writes_to(LEVEL).len(),
            before,
            "setter publishes owned work without polling AUX"
        );
        run(owner.process());
        assert_eq!(owner.current_brightness(), owner.max_brightness());
        let writes = panel.writes_to(LEVEL);
        assert_eq!(
            writes.last().unwrap().as_slice(),
            if wide {
                &[0x80, 7, 0x22, 1, 15, 255][..]
            } else {
                &[0x80, 7, 0x22, 0, 255][..]
            }
        );
        assert_eq!(panel.get(MODE), if wide { 10 } else { 2 });
        assert!(panel.writes_to(FREQUENCY).iter().all(|wire| wire[4] == 73));
        if !wide {
            assert_eq!(panel.get(0x723), 0x5a, "8-bit writes never touch LSB");
        }
        owner.set_brightness(0);
        run(owner.process());
        assert_eq!(panel.get(CONTROL), 0xa0);
        assert_eq!(owner.current_brightness(), 0);
        narf_drivers_backlight::unregister_backlight(NAME);
    }
    let panel = Panel::new(false, 8);
    panel.set(CONTROL, 0xa0); // disabled firmware state with stale level77
    let owner = owner(&panel);
    assert_eq!(owner.requested.load(Ordering::Acquire), 0);
    assert_eq!(owner.register(), Ownership::Owner);
    assert_eq!(owner.current_brightness(), 0);
    assert_eq!(panel.get(CONTROL), 0xa0);
    assert_eq!(panel.get(LEVEL), 0);
    assert!(
        panel.writes_to(CONTROL).iter().all(|wire| wire[4] & 1 == 0),
        "registration cannot infer an enable request from stale brightness"
    );
    narf_drivers_backlight::unregister_backlight(NAME);
    let panel = Panel::new(false, 8);
    panel.0.lock().regs.insert(0xc7204, 1); // powered but initially dark PPS gate
    assert!(Vesa::probe(NAME, Channel(panel.clone())).is_err());
    assert!(
        panel.0.lock().writes.is_empty(),
        "initial closed gate is refused without AUX/PPS writes or guessed T8"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_aux",
    smoke_intel_aux_backlight_production_probe_wire_width_bitcount_and_worker
);

fn smoke_intel_aux_backlight_unsupported_profiles_never_write_panel_controls() -> TestResult {
    let _registry = Registry::save();
    for (address, value) in [
        (0x700, 6),
        (0x701, 1),
        (0x702, 0),
        (0x702, 3),
        (0x702, 10),
        (0x703, 16),
        (MODE, 0),
        (MODE, 3),
        (MODE, 0x82),
        (PWM_BITS, 9),
        (PWM_BITS + 1, 9),
        (0x340, 1),
    ] {
        let panel = Panel::new(false, 8);
        panel.set(address, value);
        assert!(Vesa::probe(NAME, Channel(panel.clone())).is_err());
        assert!(panel.0.lock().wires.iter().all(|wire| wire[0] >> 4 == 9));
        assert!(narf_drivers_backlight::panel_owner().is_none());
    }
    let panel = Panel::new(false, 8);
    panel.set(0x702, 2 | 32);
    panel.set(MODE, 10);
    panel.set(FREQUENCY, 0);
    assert!(Vesa::probe(NAME, Channel(panel.clone())).is_err());
    assert!(panel.0.lock().wires.iter().all(|wire| wire[0] >> 4 == 9));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_aux",
    smoke_intel_aux_backlight_unsupported_profiles_never_write_panel_controls
);

fn smoke_intel_aux_backlight_suspend_relight_waits_t8_and_replays_latest_intent() -> TestResult {
    let _registry = Registry::save();
    let panel = Panel::new(true, 12);
    let owner = owner(&panel);
    owner.register();
    owner.set_brightness(876);
    run(owner.process());
    let started = panel.now();
    let mut suspend = Box::pin(owner.suspend_complete());
    assert!(suspend
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    let off_deadline = owner.state.try_lock().unwrap().off_deadline.unwrap();
    assert!(off_deadline > started);
    assert_eq!(panel.read32(0xc7204) & 4, 0);
    run(suspend).unwrap();
    assert!(
        panel.now() >= off_deadline,
        "system-PM prepare cannot finish before T9"
    );
    assert_eq!(owner.requested.load(Ordering::Acquire), 876);
    assert_eq!(panel.get(CONTROL) & 1, 0);
    let writes = panel.0.lock().wires.len();
    owner.set_brightness(1111);
    run(owner.process());
    assert_eq!(
        panel.0.lock().wires.len(),
        writes,
        "parked intent cannot issue AUX"
    );
    // S3 loses panel mode/waveform; only fresh qualified video can replay it.
    panel.set(MODE, 0);
    panel.set(PWM_BITS, 1);
    panel.set(CONTROL, 0xa0);
    owner.prepare_relight().unwrap();
    let deadline = owner.state.try_lock().unwrap().relight.unwrap().deadline;
    assert_eq!(panel.read32(0xc7204) & 4, 0);
    owner.set_brightness(1112);
    let before = panel.0.lock().wires.len();
    panel.0.lock().now = deadline + 1;
    run(owner.process());
    assert_eq!(
        panel.0.lock().wires.len(),
        before,
        "prepared but unpublished video cannot admit a setter or old worker"
    );
    assert_eq!(panel.read32(0xc7204) & 4, 0);
    assert!(!owner.state.try_lock().unwrap().relight.unwrap().admitted);
    // A later fresh relight followed by successful video publication admits
    // its newly stamped deadline; model time remains monotonic throughout.
    owner.prepare_relight().unwrap();
    let deadline = owner.state.try_lock().unwrap().relight.unwrap().deadline;
    owner.resume().unwrap(); // queues only; synchronous PM relight can return
    let mut work = Box::pin(owner.process());
    assert!(work
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    assert!(panel.now() < deadline);
    assert_eq!(panel.read32(0xc7204) & 4, 0);
    owner.set_brightness(1234);
    run(work);
    assert!(panel.now() >= deadline);
    assert_eq!(owner.current_brightness(), 1234);
    assert_eq!(panel.get(MODE), 2);
    assert_eq!(panel.get(PWM_BITS), 12);
    assert_eq!(panel.read32(0xc7204) & 4, 4);
    // A concurrent newer video preparation invalidates the old suspend's T9
    // witness, although PPS remains parked/closed. It cannot authorize sleep.
    let mut stale = Box::pin(owner.suspend_complete());
    assert!(stale
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    owner.prepare_relight().unwrap();
    assert!(matches!(run(stale), Err(AuxError::UnknownStatus)));
    assert!(!owner.state.try_lock().unwrap().relight.unwrap().admitted);
    owner.resume().unwrap();
    run(owner.process());
    // A failed-GTprepare rollback admitting the original live video also
    // invalidates an older suspend waiter before the worker may reopen PPS.
    let mut stale = Box::pin(owner.suspend_complete());
    assert!(stale
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    owner.resume().unwrap();
    assert!(matches!(run(stale), Err(AuxError::UnknownStatus)));
    run(owner.process());
    assert_eq!(owner.current_brightness(), 1234);
    assert_eq!(panel.read32(0xc7204) & 4, 4);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_aux",
    smoke_intel_aux_backlight_suspend_relight_waits_t8_and_replays_latest_intent
);

fn smoke_intel_aux_backlight_cancelled_relight_and_power_loss_retain_parked_intent() -> TestResult {
    let _registry = Registry::save();
    let panel = Panel::new(false, 8);
    let owner = owner(&panel);
    owner.register();
    owner.suspend().unwrap();
    owner.prepare_relight().unwrap();
    owner.resume().unwrap();
    owner.set_brightness(91);
    let mut work = Box::pin(owner.process());
    assert!(work
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    drop(work);
    assert!(!owner.scheduled.load(Ordering::Acquire));
    assert!(owner.state.try_lock().unwrap().parked);
    assert!(owner.state.try_lock().unwrap().relight.is_some());
    assert_eq!(panel.read32(0xc7204) & 4, 0);
    panel.0.lock().d0 = false;
    let writes = panel.0.lock().writes.len();
    run(owner.process());
    assert!(owner.state.try_lock().unwrap().failed);
    assert_eq!(owner.requested.load(Ordering::Acquire), 91);
    assert_eq!(panel.0.lock().writes.len(), writes);
    panel.0.lock().d0 = true;
    owner.resume().unwrap();
    run(owner.process());
    assert_eq!(owner.current_brightness(), 91);
    assert_eq!(panel.read32(0xc7204) & 4, 4);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_aux",
    smoke_intel_aux_backlight_cancelled_relight_and_power_loss_retain_parked_intent
);

fn smoke_intel_aux_backlight_partial_write_readback_and_route_loss_fail_closed() -> TestResult {
    let _registry = Registry::save();
    for loss in 0..5 {
        let panel = Panel::new(false, 8);
        let owner = owner(&panel);
        owner.register();
        let confirmed = owner.current_brightness();
        let before = panel.writes_to(LEVEL).len();
        match loss {
            0 => panel.0.lock().drop_dpcd = Some(LEVEL),
            1 => panel.0.lock().nack = Some(LEVEL),
            2 => panel.0.lock().lose_after = Some(LEVEL),
            3 => {
                panel.0.lock().regs.insert(0x60400, 0x92000006);
            }
            _ => panel.0.lock().authorized = false,
        }
        owner.set_brightness(92);
        run(owner.process());
        assert!(owner.state.try_lock().unwrap().failed);
        assert_eq!(owner.state.try_lock().unwrap().confirmed, confirmed);
        assert_eq!(owner.requested.load(Ordering::Acquire), 92);
        assert_eq!(owner.current_brightness(), 0);
        if loss >= 3 {
            assert_eq!(panel.writes_to(LEVEL).len(), before);
        }
        if loss == 2 {
            assert_eq!(
                panel.get(LEVEL),
                92,
                "post-write D0 loss must not publish confirmation"
            );
            assert_eq!(panel.writes_to(LEVEL).len(), before + 1);
        }
        narf_drivers_backlight::unregister_backlight(NAME);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_aux",
    smoke_intel_aux_backlight_partial_write_readback_and_route_loss_fail_closed
);

fn smoke_intel_aux_backlight_deferred_and_replaced_candidates_cannot_drive_panel() -> TestResult {
    let _registry = Registry::save();
    let panel = Panel::new(false, 8);
    let first = Vesa::probe("aux-incumbent", Channel(panel.clone())).unwrap();
    assert_eq!(first.register(), Ownership::Owner);
    let second_panel = Panel::new(false, 8);
    let second = Vesa::probe("aux-deferred", Channel(second_panel.clone())).unwrap();
    let writes = second_panel.0.lock().wires.len();
    assert_eq!(second.register(), Ownership::Deferred);
    second.set_brightness(99);
    run(second.process());
    second.suspend().unwrap();
    second.prepare_relight().unwrap();
    second.resume().unwrap();
    assert_eq!(second_panel.0.lock().wires.len(), writes);
    assert!(
        second_panel
            .0
            .lock()
            .writes
            .iter()
            .all(|(reg, _)| !matches!(*reg, 0xc7204 | 0xc7208 | 0xc720c)),
        "deferred candidate cannot touch PPS either"
    );
    let replacement = Vesa::probe("aux-incumbent", Channel(panel.clone())).unwrap();
    assert_eq!(replacement.register(), Ownership::Owner);
    let writes = panel.0.lock().wires.len();
    first.set_brightness(88);
    run(first.process());
    assert_eq!(
        panel.0.lock().wires.len(),
        writes,
        "stale Arc with same name has no elected identity"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_aux",
    smoke_intel_aux_backlight_deferred_and_replaced_candidates_cannot_drive_panel
);

fn smoke_intel_aux_backlight_deferred_worker_retry_and_interior_pps_loss() -> TestResult {
    let _registry = Registry::save();
    let panel = Panel::new(false, 8);
    let owner = owner(&panel);
    owner.register();
    panel.0.lock().defers = 2;
    owner.set_brightness(93);
    let start = panel.now();
    let mut work = Box::pin(owner.process());
    assert!(work
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    assert_eq!(owner.requested.load(Ordering::Acquire), 93);
    run(work);
    assert!(panel.now() >= start + 2_000_000);
    assert_eq!(owner.current_brightness(), 93);
    // Persistent contention is bounded and retains the last intent for a later
    // store/resume; it does not busy-loop forever or manufacture confirmation.
    panel.0.lock().defers = u8::MAX;
    owner.set_brightness(94);
    run(owner.process());
    assert!(owner.state.try_lock().unwrap().failed);
    assert_eq!(owner.state.try_lock().unwrap().confirmed, 93);
    assert_eq!(owner.requested.load(Ordering::Acquire), 94);
    panel.0.lock().defers = 0;
    owner.set_brightness(94);
    run(owner.process());
    assert_eq!(owner.current_brightness(), 94);
    // Fault inside init_registers' PP_CONTROL RMW, after the initial checked
    // preflight, must suppress the derived write and all remaining PPS writes.
    let before = panel.0.lock().writes.len();
    {
        let mut hw = panel.0.lock();
        hw.fail_control_at = Some(hw.control_reads + 2);
    }
    assert!(owner.prepare_relight().is_err());
    assert!(owner.state.try_lock().unwrap().parked);
    assert!(owner.state.try_lock().unwrap().relight.is_none());
    let hw = panel.0.lock();
    assert!(hw.writes[before..]
        .iter()
        .all(|(reg, _)| *reg != crate::intel_gpu_edp::PP_CONTROL));
    assert_eq!(owner.requested.load(Ordering::Acquire), 94);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_aux",
    smoke_intel_aux_backlight_deferred_worker_retry_and_interior_pps_loss
);

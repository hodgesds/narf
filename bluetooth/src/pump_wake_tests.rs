//! The HCI pump task is event-driven (`bluetooth/pump`): an idle step parks
//! the task until the transport reports a completion, an API call touches
//! the slot, or a stop arrives — never a timer, never a spin (Linux btusb:
//! `btusb_intr_complete` / `btusb_bulk_complete` hand the packet up and
//! resubmit their URBs).

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::task::Wake;
use core::future::Future;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Waker};

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use super::{find_slot_mut, pump_task, stop_pump, PumpCore, PumpSlot, PumpStats, PUMPS};
use crate::controller::ControllerInfo;
use crate::hci::{Command, Event};
use crate::transport::{HciTransport, TransportError};

/// A controller index no other test uses.
const INDEX: usize = 0x7e;

/// An idle transport that counts polls and keeps the pump's waker, as the
/// USB transport's endpoint completions do.
#[derive(Debug)]
struct WakeTransport {
    polls: AtomicUsize,
    registrations: AtomicUsize,
    waker: IrqSafeSpinLock<Option<Waker>>,
}

impl WakeTransport {
    fn new() -> Self {
        Self {
            polls: AtomicUsize::new(0),
            registrations: AtomicUsize::new(0),
            waker: IrqSafeSpinLock::new(None),
        }
    }
}

impl HciTransport for WakeTransport {
    fn send_command(&self, _cmd: &Command) -> Result<(), TransportError> {
        Ok(())
    }
    fn recv_event(&self) -> Result<Option<Event>, TransportError> {
        self.polls.fetch_add(1, Ordering::AcqRel);
        Ok(None)
    }
    fn send_acl(&self, _data: &[u8]) -> Result<(), TransportError> {
        Ok(())
    }
    fn recv_acl(&self) -> Result<Option<alloc::vec::Vec<u8>>, TransportError> {
        Ok(None)
    }
    fn register_rx_waker(&self, waker: &Waker) -> bool {
        self.registrations.fetch_add(1, Ordering::AcqRel);
        *self.waker.lock() = Some(waker.clone());
        true
    }
    fn clear_rx_waker(&self) {
        self.waker.lock().take();
    }
    fn name(&self) -> &'static str {
        "wake-test"
    }
}

struct Count(AtomicUsize);
impl Wake for Count {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

fn smoke_pump_parks_until_completion_api_or_stop() -> TestResult {
    let transport = Arc::new(WakeTransport::new());
    PUMPS.lock().push(PumpSlot {
        index: INDEX,
        core: Some(PumpCore::new(
            INDEX,
            transport.clone(),
            ControllerInfo::default(),
        )),
        socket_events: VecDeque::new(),
        stats: PumpStats::default(),
        stop: false,
        task_running: true,
        active: true,
        waker: None,
    });
    let woken = Arc::new(Count(AtomicUsize::new(0)));
    let waker = Waker::from(woken.clone());
    let mut cx = Context::from_waker(&waker);
    let mut task = Box::pin(pump_task(INDEX));
    let polls = || transport.polls.load(Ordering::Acquire);
    let wakes = || woken.0.load(Ordering::Acquire);
    let result = (|| {
        // One step, then the task parks: no further step without a wake.
        if task.as_mut().poll(&mut cx).is_ready() || polls() != 1 || wakes() != 0 {
            return TestResult::Fail("an idle pump did not park after one step");
        }
        if task.as_mut().poll(&mut cx).is_pending() && polls() != 2 {
            return TestResult::Fail("a re-poll did not run exactly one more step");
        }
        let after_spurious = polls();
        // The transport's completion wakes it.
        let Some(w) = transport.waker.lock().clone() else {
            return TestResult::Fail("the pump registered no completion waker");
        };
        w.wake_by_ref();
        if wakes() != 1 {
            return TestResult::Fail("a completion did not wake the pump task");
        }
        if task.as_mut().poll(&mut cx).is_ready() || polls() != after_spurious + 1 {
            return TestResult::Fail("a completion did not run one step");
        }
        // An API call that touches the slot (outbound work) wakes it.
        {
            let mut pumps = PUMPS.lock();
            let _ = find_slot_mut(&mut pumps, INDEX);
        }
        if wakes() != 2 {
            return TestResult::Fail("an API call did not wake the pump task");
        }
        let _ = task.as_mut().poll(&mut cx);
        // A stop wakes it and it exits, dropping its registrations.
        stop_pump(INDEX);
        if wakes() != 3 {
            return TestResult::Fail("a stop did not wake the pump task");
        }
        if task.as_mut().poll(&mut cx).is_pending() {
            return TestResult::Fail("a stopped pump task did not exit");
        }
        if transport.waker.lock().is_some() {
            return TestResult::Fail("an exited pump left its completion waker");
        }
        TestResult::Pass
    })();
    PUMPS.lock().retain(|s| s.index != INDEX);
    result
}
kernel_test_in!(
    "bluetooth/pump",
    smoke_pump_parks_until_completion_api_or_stop
);

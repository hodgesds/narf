use super::*;
use alloc::{sync::Arc, vec, vec::Vec};
use core::{
    future::poll_fn,
    pin::pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::Waker,
};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Default)]
struct State {
    rx_polls: usize,
    key_epoch: usize,
    failed: bool,
    retained_dma: Vec<u32>,
}

fn smoke_iwl_retained_control_waiter_drop_and_sync_drain() -> TestResult {
    let state = Arc::new(Mutex::new(State {
        retained_dma: vec![17, 23],
        ..State::default()
    }));
    let completion = Arc::new(AtomicUsize::new(0));
    let owned = state.clone();
    let receipt = completion.clone();
    let slot = Mutex::new(Some(Work::new(async move {
        let mut state = owned.lock().await;
        poll_fn(|cx| {
            state.rx_polls += 1;
            if receipt.load(Ordering::Acquire) == 0 {
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
        state.key_epoch += 1;
    })));
    let mut cx = Context::from_waker(Waker::noop());
    {
        let mut waiter = pin!(poll_fn(|cx| poll_work(&slot, cx)));
        if waiter.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail(
                "control fixture did not suspend with active device ownership",
            );
        }
    }
    if state.try_lock().is_some() || slot.try_lock().unwrap().is_none() {
        return TestResult::Fail("dropping the async waiter released in-flight control ownership");
    }
    // The async waiter is gone. A synchronous network drain still advances
    // the same future and its DMA receive polls while the receipt is absent.
    for _ in 0..4 {
        if poll_work(&slot, &mut cx).is_ready() {
            return TestResult::Fail("control completed without its hardware receipt");
        }
    }
    completion.store(1, Ordering::Release);
    if poll_work(&slot, &mut cx).is_pending() || poll_work(&slot, &mut cx).is_pending() {
        return TestResult::Fail("synchronous drain could not complete retained control work");
    }
    let state = state.try_lock().unwrap();
    if state.rx_polls != 6 || state.key_epoch != 1 || state.retained_dma != [17, 23] {
        return TestResult::Fail(
            "duplicate key commit, skipped RX progress or premature DMA release",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/progress",
    smoke_iwl_retained_control_waiter_drop_and_sync_drain
);

fn smoke_iwl_control_failure_keeps_owner_until_terminal_poll() -> TestResult {
    let state = Arc::new(Mutex::new(State {
        retained_dma: vec![41],
        ..State::default()
    }));
    let receipt = Arc::new(AtomicUsize::new(0));
    let owned = state.clone();
    let completion = receipt.clone();
    let slot = Mutex::new(Some(Work::new(async move {
        let mut state = owned.lock().await;
        poll_fn(|_| {
            if completion.load(Ordering::Acquire) == 0 {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
        state.failed = true;
    })));
    let mut cx = Context::from_waker(Waker::noop());
    if poll_work(&slot, &mut cx).is_ready() || state.try_lock().is_some() {
        return TestResult::Fail("failed-control fixture did not retain exclusive ownership");
    }
    receipt.store(2, Ordering::Release);
    if poll_work(&slot, &mut cx).is_pending() || Arc::strong_count(&state) != 1 {
        return TestResult::Fail("terminal control poll failed to release its retained future");
    }
    let state = state.try_lock().unwrap();
    if !state.failed || state.key_epoch != 0 || state.retained_dma != [41] {
        return TestResult::Fail("failed control committed authority or released unquiesced DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/progress",
    smoke_iwl_control_failure_keeps_owner_until_terminal_poll
);

fn smoke_iwl_pending_tx_busy_timeout_and_original_packet() -> TestResult {
    let pending = PendingTx::new(vec![0xaa, 0xbb, 0xcc]);
    let mut attempts = 0;
    for _ in 0..4 {
        if pending.progress(|frame| {
            attempts += 1;
            if frame != &[0xaa, 0xbb, 0xcc] {
                return Err(());
            }
            Ok(false)
        }) != Ok(Transmit::Busy)
        {
            return TestResult::Fail("busy credit mutated or retired the pending original packet");
        }
    }
    if attempts != 4 || pending.progress(|_| Ok::<_, ()>(true)) != Ok(Transmit::Sent) {
        return TestResult::Fail("bounded credit retry did not reach submission");
    }
    let expired = PendingTx {
        frame: vec![1],
        deadline: narf_time::Deadline::after_ms(0),
    };
    let mut touched = false;
    if expired.progress(|_| {
        touched = true;
        Ok::<_, ()>(true)
    }) != Ok(Transmit::Expired)
        || touched
    {
        return TestResult::Fail("expired packet reached a device submission");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/progress",
    smoke_iwl_pending_tx_busy_timeout_and_original_packet
);

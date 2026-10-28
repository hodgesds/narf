//! PCIe mailbox interrupt and mailbox-data smokes over the msgbuf model.
use super::*;
use crate::brcmfmac::irq::{fallback_ms, Signal};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use runtime::mailbox::*;

fn ready<F: Future>(future: F) -> Option<F::Output> {
    let mut future = core::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}

fn mask(s: &State) -> u32 {
    *s.registers.get(&(PCIE + 0x4c)).unwrap_or(&0)
}
fn status(s: &State) -> u32 {
    *s.registers.get(&(PCIE + 0x48)).unwrap_or(&0)
}

/// Post one correlated IOCTL response so the D2H doorbell has real work.
fn post_response(st: &mut State, ticket_command: u32) {
    let ring = pointer(st, RINGS + 8);
    let post = st.dma.get(&ring).unwrap()[..40].to_vec();
    let id = u32::from_le_bytes(post[4..8].try_into().unwrap());
    complete(st, 0, 0xc, id, (0, 0), 1, ticket_command);
}

fn smoke_brcmf_pcie_msi_mailbox_service_and_release() -> TestResult {
    let (bus, s) = model();
    s.lock().msi = true;
    let mut owner = match runtime::Runtime::attach(booted(bus)) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("attach with MSI failed"),
    };
    {
        let st = s.lock();
        let masks: Vec<u32> = st
            .writes
            .iter()
            .filter(|&&(a, _)| a == PCIE + 0x4c)
            .map(|&(_, v)| v)
            .collect();
        // brcmf_pcie_request_irq masks first; preinit enables D2H_DB | FN0.
        if st.armed != 1 || masks != [0, MB_INT_D2H_DB | MB_INT_FN0] || !owner.interrupt().1 {
            return TestResult::Fail("mailbox not masked before MSI and enabled after");
        }
    }
    let ticket = match owner.begin_ioctl(262, b"ver\0", 4) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("IOCTL submit failed"),
    };
    let seen = owner.interrupt().0.count();
    {
        let mut st = s.lock();
        post_response(&mut st, 262);
        raise_status(&mut st, 0x10000);
    }
    if owner.interrupt().0.count() == seen {
        return TestResult::Fail("D2H doorbell did not raise the owner signal");
    }
    if owner.poll() != Ok(1) || !matches!(owner.take_response(&ticket), Ok(Some(Ok(_)))) {
        return TestResult::Fail("isr thread did not service the D2H completion ring");
    }
    {
        let st = s.lock();
        if status(&st) != 0
            || mask(&st) != MB_INT_D2H_DB | MB_INT_FN0
            || !st.writes.contains(&(PCIE + 0x48, 0x10000))
            || owner.interrupt_stats().services != 1
        {
            return TestResult::Fail("MAILBOXINT not acknowledged or mask not re-enabled");
        }
    }
    // Deep-sleep request: Linux answers H2D_HOST_DS_ACK from the thread.
    raise_mailbox(&mut s.lock(), D2H_DEV_DS_ENTER_REQ);
    if owner.poll().is_err() || s.lock().sbmbx != [H2D_HOST_DS_ACK] {
        return TestResult::Fail("deep-sleep request not acknowledged");
    }
    // Firmware halt is terminal for this generation.
    raise_mailbox(&mut s.lock(), D2H_DEV_FWHALT);
    if owner.poll() != Err(runtime::Error::Failed) || !owner.is_failed() {
        return TestResult::Fail("D2H FWHALT did not fail the owner");
    }
    drop(owner);
    let st = s.lock();
    if st.disarmed != 1 || st.signal.is_some() || mask(&st) != 0 {
        return TestResult::Fail("release_irq did not mask and free the vector");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_pcie_msi_mailbox_service_and_release
);

fn smoke_brcmf_pcie_polled_mailbox_fallback_and_gone_device() -> TestResult {
    let (bus, s) = model();
    let mut owner = match runtime::Runtime::attach(booted(bus)) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("attach without MSI failed"),
    };
    if owner.interrupt().1 || s.lock().armed != 0 || owner.interrupt_stats().delivered {
        return TestResult::Fail("polled owner claimed a delivered vector");
    }
    // A prior H2D word is still pending: the DS_ACK is deferred, not lost.
    {
        let mut st = s.lock();
        put(&mut st, HTOD_MB, &H2D_HOST_D0_INFORM.to_le_bytes());
        raise_mailbox(&mut st, D2H_DEV_DS_ENTER_REQ);
    }
    if owner.poll().is_err() || !s.lock().sbmbx.is_empty() {
        return TestResult::Fail("DS_ACK overwrote a pending H2D mailbox word");
    }
    put(&mut s.lock(), HTOD_MB, &0u32.to_le_bytes());
    if owner.poll().is_err() || s.lock().sbmbx != [H2D_HOST_DS_ACK] {
        return TestResult::Fail("deferred DS_ACK not sent after the mailbox drained");
    }
    // A function that left the bus reads all-ones: fail, never spin.
    s.lock().registers.insert(PCIE + 0x48, u32::MAX);
    if owner.poll() != Err(runtime::Error::Access) || !owner.is_failed() {
        return TestResult::Fail("all-ones MAILBOXINT was not treated as device loss");
    }
    drop(owner);
    if s.lock().disarmed != 0 {
        return TestResult::Fail("polled owner released a vector it never bound");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_pcie_polled_mailbox_fallback_and_gone_device
);

fn smoke_brcmf_pcie_signal_wait_and_reginfo() -> TestResult {
    let signal = Signal::new();
    let seen = signal.count();
    let pending = core::future::pending::<()>();
    let mut wait = core::pin::pin!(signal.wait(seen, pending));
    if wait
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_ready()
    {
        return TestResult::Fail("wait resolved without a vector");
    }
    signal.raise();
    if wait.as_mut().poll(&mut Context::from_waker(Waker::noop())) != Poll::Ready(true) {
        return TestResult::Fail("vector raise did not end the wait");
    }
    if ready(signal.wait(signal.count(), core::future::ready(()))) != Some(false) {
        return TestResult::Fail("fallback timer did not end the wait");
    }
    let legacy = Reginfo::for_core(0x1000, 13);
    let wide = Reginfo::for_core(0x1000, 64);
    if legacy.mailboxint != 0x1048
        || legacy.enabled() != 0x00ff_0300
        || wide.mailboxint != 0x1c30
        || wide.mailboxmask != 0x1c34
        || wide.intmask != 0x1c14
        || wide.enabled() != 0xffff
        || fallback_ms(true) != 10
        || fallback_ms(false) != 1
    {
        return TestResult::Fail("Linux reginfo/fallback selection differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_pcie_signal_wait_and_reginfo
);

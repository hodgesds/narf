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

/// Event buffer 9 (first of the eight posted event buffers) completes.
fn post_event(st: &mut State, slot: usize) {
    let at = pointer(st, RINGS + 2 * 16 + 8);
    let entry = &mut st.dma.get_mut(&at).unwrap()[slot * 24..slot * 24 + 24];
    entry[0] = 0xe;
    entry[4..8].copy_from_slice(&9u32.to_le_bytes());
    entry[12..14].copy_from_slice(&4u16.to_le_bytes());
    put(st, D2HW, &((slot + 1) as u16).to_le_bytes());
}

fn smoke_brcmf_confirmed_stop_reclaims_published_dma() -> TestResult {
    let (bus, s) = model();
    {
        let mut st = s.lock();
        st.msi = true;
        st.d3_ack = true;
    }
    let mut owner = match runtime::Runtime::attach(booted(bus)) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("attach failed"),
    };
    if owner.enable_data().is_err() {
        return TestResult::Fail("RX posting failed");
    }
    // A completion published before the ack is drained, not abandoned.
    post_event(&mut s.lock(), 0);
    let proof = match ready(owner.quiesce()) {
        Some(Ok(proof)) => proof,
        _ => return TestResult::Fail("acknowledged D3 stop did not complete"),
    };
    {
        let st = s.lock();
        if proof.drained != 1
            || proof.indices != [1, 0, 0]
            || !owner.is_reclaimable()
            || !owner.is_down()
            || st.dma_enable
            || st.sbmbx != [H2D_HOST_D3_INFORM]
            || st.disarmed != 1
            || mask(&st) != 0
        {
            return TestResult::Fail("D3 ack / drain / IRQ release / BME proof incomplete");
        }
    }
    if owner.pop_event().is_none() {
        return TestResult::Fail("drained event completion was lost");
    }
    if owner.begin_ioctl(262, b"ver\0", 4).err() != Some(runtime::Error::Busy)
        || owner.open_flow([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2], 0) != Err(runtime::Error::Busy)
        || ready(owner.quiesce()) != Some(Err(runtime::Error::Busy))
    {
        return TestResult::Fail("stopped owner accepted a new H2D post or second stop");
    }
    drop(owner);
    let st = s.lock();
    if st.dropped != st.allocated || st.unsafe_free != 0 {
        return TestResult::Fail("confirmed stop did not reclaim every published mapping");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_confirmed_stop_reclaims_published_dma
);

fn smoke_brcmf_unacknowledged_d3_reverts_and_retains_dma() -> TestResult {
    let (bus, s) = model();
    let mut owner = match runtime::Runtime::attach(booted(bus)) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("attach failed"),
    };
    // Firmware never answers D3_INFORM: Linux times out after 2 s and
    // returns the bus to UP.
    if narf_scheduler::block_on(owner.quiesce()) != Err(runtime::Error::Timeout)
        || owner.is_down()
        || owner.is_reclaimable()
        || owner.is_failed()
        || mask(&s.lock()) != MB_INT_D2H_DB | MB_INT_FN0
        || owner.begin_ioctl(262, b"ver\0", 4).is_err()
    {
        return TestResult::Fail("D3 timeout did not revert to a usable UP owner");
    }
    drop(owner);
    if s.lock().dropped != 0 {
        return TestResult::Fail("unproven stop released published DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_unacknowledged_d3_reverts_and_retains_dma
);

fn smoke_brcmf_late_dma_or_halt_fails_stop_proof() -> TestResult {
    // A device write observed by the post-BME flush read voids the proof.
    let (bus, s) = model();
    {
        let mut st = s.lock();
        st.d3_ack = true;
        st.late_dma = true;
    }
    let mut owner = match runtime::Runtime::attach(booted(bus)) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("attach failed"),
    };
    if ready(owner.quiesce()) != Some(Err(runtime::Error::Protocol))
        || owner.is_reclaimable()
        || !owner.is_failed()
        || s.lock().parks == 0
    {
        return TestResult::Fail("post-BME DMA activity was accepted as quiescence");
    }
    drop(owner);
    if s.lock().dropped != 0 {
        return TestResult::Fail("failed flush proof released published DMA");
    }
    // Firmware halts instead of acknowledging D3.
    let (bus, s) = model();
    let mut owner = match runtime::Runtime::attach(booted(bus)) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("attach failed"),
    };
    raise_mailbox(&mut s.lock(), D2H_DEV_FWHALT);
    if ready(owner.quiesce()) != Some(Err(runtime::Error::Failed))
        || !owner.is_failed()
        || owner.is_reclaimable()
    {
        return TestResult::Fail("FWHALT during D3 wait did not fail the owner");
    }
    drop(owner);
    if s.lock().dropped != 0 {
        return TestResult::Fail("halted firmware stop released published DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_late_dma_or_halt_fails_stop_proof
);

fn adapter(
    d3_ack: bool,
) -> Option<(
    crate::brcmfmac::station_transport::Adapter<Model>,
    Rc<IrqSafeSpinLock<State>>,
)> {
    let (bus, s) = model();
    {
        let mut st = s.lock();
        st.msi = true;
        st.d3_ack = d3_ack;
        // brcmf_pcie_pm_leave_D3 reads INTMASK: nonzero = still powered.
        st.registers.insert(PCIE + 0x24, 0x300);
    }
    let owner = runtime::Runtime::attach(booted(bus)).ok()?;
    let adapter = crate::brcmfmac::station_transport::Adapter::new(owner).ok()?;
    Some((adapter, s))
}

fn smoke_brcmf_system_suspend_resume_d3_d0_handshake() -> TestResult {
    use crate::cyw43439::fullmac::Fullmac;
    let Some((mut adapter, s)) = adapter(true) else {
        return TestResult::Fail("msgbuf adapter setup failed");
    };
    if ready(adapter.suspend_transport()) != Some(Ok(())) {
        return TestResult::Fail("D3_INFORM/D3_ACK suspend failed");
    }
    {
        let st = s.lock();
        if st.sbmbx != [H2D_HOST_D3_INFORM] || mask(&st) != 0 {
            return TestResult::Fail("suspend did not send D3_INFORM and keep the mailbox masked");
        }
    }
    let flushed = s.lock().dma.len();
    if ready(adapter.resume_transport()) != Some(Ok(())) || adapter.poll().is_err() {
        return TestResult::Fail("hot D0_INFORM resume failed");
    }
    {
        let st = s.lock();
        if st.sbmbx != [H2D_HOST_D3_INFORM, H2D_HOST_D0_INFORM]
            || mask(&st) != MB_INT_D2H_DB | MB_INT_FN0
            || st.dma.len() != flushed
            || st.dropped != 0
        {
            return TestResult::Fail("resume did not re-enable mailbox on retained rings");
        }
    }
    // Second cycle: the dongle lost power across suspend (INTMASK reads 0).
    if ready(adapter.suspend_transport()) != Some(Ok(())) {
        return TestResult::Fail("second suspend failed");
    }
    s.lock().registers.insert(PCIE + 0x24, 0);
    if ready(adapter.resume_transport()) != Some(Err(crate::cyw43439::runtime::Error::Failed))
        || adapter.poll().is_ok()
        || s.lock().sbmbx.len() != 3
    {
        return TestResult::Fail("cold resume was treated as a live firmware generation");
    }
    drop(adapter);
    let st = s.lock();
    if st.dropped != 0 || st.disarmed != 1 {
        return TestResult::Fail("terminal resume freed DMA or kept the vector");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_system_suspend_resume_d3_d0_handshake
);

fn smoke_brcmf_system_suspend_timeout_unwinds_usable() -> TestResult {
    use crate::cyw43439::fullmac::Fullmac;
    let Some((mut adapter, s)) = adapter(false) else {
        return TestResult::Fail("msgbuf adapter setup failed");
    };
    if narf_scheduler::block_on(adapter.suspend_transport())
        != Err(crate::cyw43439::runtime::Error::Timeout)
        || adapter.poll().is_err()
        || mask(&s.lock()) != MB_INT_D2H_DB | MB_INT_FN0
    {
        return TestResult::Fail("D3 timeout did not leave a usable UP transport");
    }
    // Resume without a successful suspend is refused, not replayed.
    if ready(adapter.resume_transport()).is_none_or(|r| r.is_ok()) {
        return TestResult::Fail("resume of an UP transport was accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_system_suspend_timeout_unwinds_usable
);

/// Flow budget follows firmware `max_flowrings` (Linux
/// `brcmf_pcie_init_ringbuffers`), capped at `BRCMF_FLOWRING_HASHSIZE - 1`.
fn smoke_brcmf_flow_budget_follows_firmware_max_flowrings() -> TestResult {
    let (bus, s) = model();
    {
        let mut st = s.lock();
        put(&mut st, INFO + 52, &12u16.to_le_bytes());
        put(&mut st, INFO + 54, &14u16.to_le_bytes());
    }
    let mut owner = match runtime::Runtime::attach(booted(bus)) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("12-flowring firmware rejected"),
    };
    if owner.enable_data().is_err() {
        return TestResult::Fail("RX posting failed");
    }
    let source = [2, 0, 0, 0, 0, 0x10];
    let mut tokens = Vec::new();
    for i in 0..12u8 {
        match owner.open_flow(source, [2, 0, 0, 0, 1, i], i % 8) {
            Ok(token) => tokens.push(token),
            Err(_) => return TestResult::Fail("flow within firmware max_flowrings refused"),
        }
    }
    let ids: BTreeSet<u16> = {
        let st = s.lock();
        let ctrl = pointer(&st, RINGS + 8);
        let ring = st.dma.get(&ctrl).unwrap();
        // Create requests follow the 16 control-buffer posts and RX posts
        // went to ring 1; read every create's flow ring id.
        ring.chunks(40)
            .filter(|e| e[0] == 3)
            .map(|e| u16::from_le_bytes([e[22], e[23]]))
            .collect()
    };
    if ids != (2..14).collect::<BTreeSet<u16>>()
        || tokens
            .iter()
            .any(|&t| owner.flow_state(t) != Ok(runtime::FlowState::Creating))
    {
        return TestResult::Fail("flow ring ids beyond the old fixed budget differ");
    }
    if owner.open_flow(source, [2, 0, 0, 0, 2, 0], 0) != Err(runtime::Error::Exhausted)
        || owner.is_failed()
    {
        return TestResult::Fail("flow beyond firmware max_flowrings admitted or fatal");
    }
    drop(owner);
    if s.lock().dropped != 0 {
        return TestResult::Fail("flow-budget teardown freed published DMA");
    }
    // Firmware reporting fewer rings still bounds the budget.
    let (bus, _s) = model();
    let mut owner = match runtime::Runtime::attach(booted(bus)) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("2-flowring firmware rejected"),
    };
    let _ = owner.enable_data();
    for i in 0..2u8 {
        if owner.open_flow(source, [2, 0, 0, 0, 3, i], 0).is_err() {
            return TestResult::Fail("flow within small firmware budget refused");
        }
    }
    if owner.open_flow(source, [2, 0, 0, 0, 3, 9], 0) != Err(runtime::Error::Exhausted) {
        return TestResult::Fail("small firmware flow budget exceeded");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_flow_budget_follows_firmware_max_flowrings
);

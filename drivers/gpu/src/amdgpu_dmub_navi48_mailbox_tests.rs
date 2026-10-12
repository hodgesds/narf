use super::*;

fn ready() -> (Pool, Engine<Fake>) {
    let (pool, mut engine) = fixture();
    run(engine.quiesce()).unwrap();
    run(engine.start(tmr())).unwrap();
    run(engine.initialize_mailbox()).unwrap();
    (pool, engine)
}
fn dp_path(phy: u8, hpd: u8) -> crate::amdgpu_dcn_inventory::Path {
    use crate::amdgpu_dcn_inventory::{Connector, Path};
    Path {
        connector: Connector::DisplayPort,
        connector_instance: 1,
        transmitter: phy,
        aux: Some((phy + 1) % 4),
        hpd,
        device_tag: 8,
    }
}
fn dmub_navi48_native_transmitter_disable_uses_v17_board_fields() -> TestResult {
    for phy in 0..4 {
        for hpd in 1..=4 {
            let (_pool, mut e) = ready();
            let offset = e.io.mailbox + e.io.regs[&(DCN + 0x1d6 * 4)] as usize;
            run(e.disable_dp_sst(dp_path(phy, hpd))).unwrap();
            let mut golden = [0; 64];
            golden[..4].copy_from_slice(&[128, 1, 0, 60]);
            golden[4] = phy;
            golden[12] = hpd;
            golden[14] = 19;
            golden[15] = 244;
            assert_eq!(e.io.slot(offset), golden);
            assert_eq!(e.mailbox.state, MailboxState::Ready);
        }
    }
    TestResult::Pass
}
fn dmub_navi48_hpo_disable_uses_native_zeroed_connector_and_explicit_signal() -> TestResult {
    for phy in 0..4 {
        for hpd in 1..=4 {
            for (signal, mode) in [(DpSignal::Sst, 0), (DpSignal::Mst, 5)] {
                let (_pool, mut e) = ready();
                let offset = e.io.mailbox + e.io.regs[&(DCN + 0x1d6 * 4)] as usize;
                run(e.disable_hpo_dp(dp_path(phy, hpd), signal)).unwrap();
                let mut golden = [0; 64];
                golden[..4].copy_from_slice(&[128, 1, 0, 60]);
                golden[4] = phy;
                golden[6] = mode;
                golden[12] = hpd;
                golden[15] = 244; // zero-initialized native DISABLE HPO id, not link instance
                assert_eq!(e.io.slot(offset), golden);
                assert_eq!(e.mailbox.state, MailboxState::Ready);
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_hpo_disable_uses_native_zeroed_connector_and_explicit_signal
);

fn dmub_navi48_hpo_disable_invalid_and_cancelled_requests_never_replay() -> TestResult {
    for signal in [DpSignal::Sst, DpSignal::Mst] {
        let (_pool, mut e) = ready();
        let mut path = dp_path(4, 1);
        let before = e.io.bytes.clone();
        assert_eq!(run(e.disable_hpo_dp(path, signal)), Err(Error::Invalid));
        path = dp_path(2, 0);
        assert_eq!(run(e.disable_hpo_dp(path, signal)), Err(Error::Invalid));
        path = dp_path(2, 1);
        path.connector = crate::amdgpu_dcn_inventory::Connector::EmbeddedDisplayPort;
        assert_eq!(run(e.disable_hpo_dp(path, signal)), Err(Error::Invalid));
        assert_eq!(e.io.bytes, before);
        assert_eq!(e.mailbox.state, MailboxState::Ready);
        e.io.commands = false;
        {
            let mut f = core::pin::pin!(e.disable_hpo_dp(dp_path(2, 1), signal));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(e.mailbox.state, MailboxState::InFlight);
        assert_eq!(
            run(e.disable_hpo_dp(dp_path(2, 1), signal)),
            Err(Error::Busy)
        );
        assert_eq!(run(e.disable_dp_sst(dp_path(2, 1))), Err(Error::Busy));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_hpo_disable_invalid_and_cancelled_requests_never_replay
);
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_native_transmitter_disable_uses_v17_board_fields
);

fn dmub_navi48_native_disable_invalid_or_uncertain_requests_never_replay() -> TestResult {
    for case in 0..4 {
        let (_pool, mut e) = ready();
        let mut path = dp_path(0, 1);
        match case {
            0 => path.transmitter = 4,
            1 => path.hpd = 0,
            2 => path.hpd = 5,
            _ => path.connector = crate::amdgpu_dcn_inventory::Connector::HdmiTypeA,
        }
        let bytes = e.io.bytes.clone();
        let writes = e.io.writes.len();
        assert_eq!(run(e.disable_dp_sst(path)), Err(Error::Invalid));
        assert_eq!(e.io.bytes, bytes);
        assert_eq!(e.io.writes.len(), writes);
        assert_eq!(e.mailbox.state, MailboxState::Ready);
    }
    for cancel in [false, true] {
        let (pool, mut e) = ready();
        e.io.commands = false;
        if cancel {
            let mut future = core::pin::pin!(e.disable_dp_sst(dp_path(0, 1)));
            assert!(future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        } else {
            assert_eq!(
                run(e.disable_dp_sst(dp_path(0, 1))),
                Err(Error::CommandTimeout)
            );
        }
        assert_eq!(
            e.mailbox.state,
            if cancel {
                MailboxState::InFlight
            } else {
                MailboxState::Failed
            }
        );
        assert_eq!(run(e.disable_dp_sst(dp_path(0, 1))), Err(Error::Busy));
        assert_eq!(run(e.hpd(0)), Err(Error::Busy));
        drop(e);
        assert_eq!(pool.available(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_native_disable_invalid_or_uncertain_requests_never_replay
);
fn dmub_navi48_mailbox_proves_version_caps_and_wraparound() -> TestResult {
    let (pool, mut engine) = ready();
    let mut caps = [0; 14];
    caps[0] = 1;
    caps[1] = 0x21;
    caps[12] = 1;
    if engine.mailbox.state != MailboxState::Ready
        || engine.status.unwrap().capabilities != Some(FeatureCaps(caps))
    {
        return TestResult::Fail("version/capabilities handshake");
    }
    // Cross the 8-KiB inbox boundary twice, including the final slot reply.
    for i in 0..260u32 {
        if run(engine.hpd((i % 4) as u8)) != Ok(true) {
            return TestResult::Fail("HPD or inbox wraparound");
        }
    }
    if engine.io.regs[&(DCN + 0x1d7 * 4)] != 5 * 64 {
        return TestResult::Fail("inbox pointers use bytes");
    }
    engine.io.notify = true;
    for _ in 0..130 {
        let mut data = [0; 6];
        if run(engine.aux(3, 0x90, 0x202, &mut data)) != Ok(())
            || data != [0x40, 0x41, 0x42, 0x43, 0x44, 0x45]
        {
            return TestResult::Fail("AUX read or outbox wraparound");
        }
        let event = engine.poll_notification().unwrap().unwrap();
        if event[..8] != [2, 0, 0, 4, 3, 0, 1, 0] || engine.poll_notification() != Ok(None) {
            return TestResult::Fail("unrelated HPD notification lost");
        }
    }
    if engine.io.regs[&(DCN + 0x1df * 4)] != 4 * 64 {
        return TestResult::Fail("outbox pointer did not wrap");
    }
    for action in [0, 0x10, 0x20, 0x40, 0x50, 0x60, 0x80] {
        if run(engine.aux(2, action, 0x50, &mut [1, 2, 3])).is_err() {
            return TestResult::Fail("native I2C/AUX action encoding");
        }
        engine.poll_notification().unwrap();
    }
    drop(engine);
    if pool.available() != 0 {
        return TestResult::Fail("mailbox storage recycled while firmware runs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_mailbox_proves_version_caps_and_wraparound
);

fn dmub_navi48_mailbox_handshake_rejects_stale_firmware() -> TestResult {
    for case in 0..4 {
        let (_pool, mut engine) = fixture();
        run(engine.quiesce()).unwrap();
        run(engine.start(tmr())).unwrap();
        let expected = match case {
            0 => {
                engine.io.caps = false;
                Ok(())
            }
            1 => {
                engine.io.version ^= 1;
                Err(Error::Protocol)
            }
            2 => {
                engine.io.gpint = false;
                Err(Error::CommandTimeout)
            }
            _ => {
                engine.io.commands = false;
                Err(Error::CommandTimeout)
            }
        };
        if run(engine.initialize_mailbox()) != expected {
            return TestResult::Fail("GPINT/caps handshake failure classification");
        }
        if case == 0 {
            if engine.status.unwrap().capabilities.is_some() || run(engine.hpd(0)) != Ok(true) {
                return TestResult::Fail("unsupported capability query invented features");
            }
        } else if engine.mailbox.state != MailboxState::Failed
            || run(engine.hpd(0)) != Err(Error::Busy)
        {
            return TestResult::Fail("failed handshake reused");
        }
        if run(engine.initialize_mailbox()) != Err(Error::Busy) {
            return TestResult::Fail("mailbox handshake replayed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_mailbox_handshake_rejects_stale_firmware
);

fn dmub_navi48_mailbox_checks_ownership_before_writes() -> TestResult {
    for (reg, value) in [
        (0x1bd, 0),
        (0x1be, 0),
        (0x1a9, 0),
        (0x1b1, 0),
        (0x1d4, 0),
        (0x1d5, 4096),
        (0x1dc, 0),
        (0x1dd, 4096),
        (0x1d6, 128),
        (0x1d7, 128),
        (0x1df, 64),
        (0x1de, 1),
        (0x1de, 8192),
        (0x1de, u32::MAX),
        (0x200, 1),
        (0x1e3, 0),
        (0x341, 0x100),
    ] {
        let (_pool, mut engine) = ready();
        engine.io.regs.insert(DCN + reg * 4, value);
        let writes = engine.io.writes.len();
        let bytes = engine.io.bytes.clone();
        if run(engine.hpd(0)).is_ok()
            || engine.mailbox.state != MailboxState::Failed
            || engine.io.writes.len() != writes
            || engine.io.bytes != bytes
        {
            return TestResult::Fail("foreign/malformed mailbox touched VRAM or pointers");
        }
    }
    let (_pool, mut engine) = ready();
    engine.authority.revoke();
    let writes = engine.io.writes.len();
    if run(engine.hpd(0)) != Err(Error::Revoked) || engine.io.writes.len() != writes {
        return TestResult::Fail("revoked mailbox authority used");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_mailbox_checks_ownership_before_writes
);

fn dmub_navi48_mailbox_rejects_bad_replies_and_invalid_requests() -> TestResult {
    for pointer in [1, 192, 8192, u32::MAX] {
        let (_pool, mut engine) = ready();
        engine.io.complete_pointer = Some(pointer);
        let expected = if pointer == u32::MAX {
            Error::DeviceGone
        } else {
            Error::Protocol
        };
        if run(engine.hpd(0)) != Err(expected) || engine.mailbox.state != MailboxState::Failed {
            return TestResult::Fail("malformed completion pointer accepted");
        }
    }
    for corrupt in [
        (0, 6),
        (1, 1),
        (2, 2),
        (2, 4),
        (2, 0x80),
        (3, 0xff),
        (3, 8),
        (4, 2),
        (5, 2),
        (8, 1),
    ] {
        let (_pool, mut engine) = ready();
        engine.io.corrupt = Some(corrupt);
        if run(engine.hpd(0)) != Err(Error::Protocol)
            || engine.mailbox.state != MailboxState::Failed
        {
            return TestResult::Fail("malformed reply left mailbox reusable");
        }
    }
    let (_pool, mut engine) = ready();
    let writes = engine.io.writes.len();
    if run(engine.hpd(4)) != Err(Error::Invalid)
        || run(engine.aux(4, 0x90, 0x202, &mut [0])) != Err(Error::Invalid)
        || run(engine.aux(0, 0x91, 0x202, &mut [0])) != Err(Error::Invalid)
        || run(engine.aux(0, 0x90, 0x100000, &mut [0])) != Err(Error::Invalid)
        || run(engine.aux(0, 0x90, 0x202, &mut [])) != Err(Error::Invalid)
        || run(engine.aux(0, 0x90, 0x202, &mut [0; 17])) != Err(Error::Invalid)
        || engine.io.writes.len() != writes
        || engine.mailbox.state != MailboxState::Ready
    {
        return TestResult::Fail("invalid caller input performed I/O or poisoned mailbox");
    }
    engine.io.corrupt = Some((12, 7));
    if run(engine.hpd(0)) != Err(Error::CommandRejected(7))
        || engine.mailbox.state != MailboxState::Ready
    {
        return TestResult::Fail("drained HPD firmware error poisoned transport");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_mailbox_rejects_bad_replies_and_invalid_requests
);

fn dmub_navi48_mailbox_aux_preserves_notifications_and_rejects_stale() -> TestResult {
    let (_pool, mut engine) = ready();
    let mut malformed = [0; 64];
    malformed[..4].copy_from_slice(&[2, 0, 4, 4]);
    engine.io.event(malformed);
    if engine.poll_notification() != Err(Error::Protocol) || engine.io.regs[&(DCN + 0x1df * 4)] != 0
    {
        return TestResult::Fail("malformed notification consumed");
    }
    for corrupt in [(1, 1), (3, 27), (8, 5), (13, 17), (13, 2)] {
        let (_pool, mut engine) = ready();
        engine.io.aux_corrupt = Some(corrupt);
        let mut data = [0xee; 6];
        if run(engine.aux(0, 0x90, 0x202, &mut data)) != Err(Error::Protocol)
            || data != [0xee; 6]
            || engine.mailbox.state != MailboxState::Failed
        {
            return TestResult::Fail("malformed AUX reply accepted");
        }
    }
    for poll in [false, true] {
        let (_pool, mut engine) = ready();
        let mut stale = [0; 64];
        stale[0] = 1;
        stale[3] = 28;
        engine.io.event(stale);
        let wp = engine.io.regs[&(DCN + 0x1d6 * 4)];
        let result = if poll {
            engine.poll_notification().map(|_| ())
        } else {
            run(engine.aux(0, 0x90, 0x202, &mut [0; 6]))
        };
        if result != Err(Error::Protocol) || engine.io.regs[&(DCN + 0x1d6 * 4)] != wp {
            return TestResult::Fail("stale AUX reply attributed to new request");
        }
    }
    let (_pool, mut engine) = ready();
    for status in [0x10, 0x20] {
        engine.io.aux_status = status;
        if run(engine.aux(0, 0x90, 0x202, &mut [0; 6])) != Err(Error::Aux(status >> 4))
            || engine.mailbox.state != MailboxState::Ready
        {
            return TestResult::Fail("NACK/DEFER poisoned drained transport");
        }
    }
    engine.io.aux_status = 0;
    engine.io.aux_corrupt = Some((9, 3));
    if run(engine.aux(0, 0x90, 0x202, &mut [0; 6])) != Err(Error::CommandRejected(3))
        || engine.mailbox.state != MailboxState::Ready
    {
        return TestResult::Fail("firmware AUX error classification");
    }
    let (_pool, mut engine) = ready();
    let mut event = [0; 64];
    event[..8].copy_from_slice(&[2, 0, 0, 4, 1, 1, 0, 0]);
    for _ in 0..17 {
        engine.io.event(event);
    }
    if run(engine.aux(0, 0x90, 0x202, &mut [0; 6])) != Err(Error::NotificationOverflow)
        || engine.mailbox.state != MailboxState::Failed
    {
        return TestResult::Fail("notification overflow silently lost events");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_mailbox_aux_preserves_notifications_and_rejects_stale
);

fn dmub_navi48_mailbox_cancellation_timeout_and_revocation_quarantine() -> TestResult {
    let (pool, mut engine) = fixture();
    run(engine.quiesce()).unwrap();
    run(engine.start(tmr())).unwrap();
    engine.io.gpint = false;
    {
        let mut future = core::pin::pin!(engine.initialize_mailbox());
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return TestResult::Fail("stalled GPINT completed");
        }
    }
    if engine.mailbox.state != MailboxState::InFlight
        || run(engine.initialize_mailbox()) != Err(Error::Busy)
    {
        return TestResult::Fail("cancelled GPINT handshake replayed");
    }
    drop(engine);
    if pool.available() != 0 {
        return TestResult::Fail("GPINT cancellation reclaimed running backing");
    }
    for aux in [false, true] {
        for cancel in [false, true] {
            let (pool, mut engine) = ready();
            if aux {
                engine.io.aux = false;
            } else {
                engine.io.commands = false;
            }
            {
                let op = async {
                    if aux {
                        engine.aux(0, 0x90, 0x202, &mut [0; 6]).await
                    } else {
                        engine.hpd(0).await.map(|_| ())
                    }
                };
                if cancel {
                    let mut future = core::pin::pin!(op);
                    if future
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_ready()
                    {
                        return TestResult::Fail("stalled transaction completed");
                    }
                } else if run(op) != Err(Error::CommandTimeout) {
                    return TestResult::Fail("uncompleted transaction did not time out");
                }
            }
            let state = if cancel {
                MailboxState::InFlight
            } else {
                MailboxState::Failed
            };
            let writes = engine.io.writes.len();
            if engine.mailbox.state != state
                || run(engine.hpd(0)) != Err(Error::Busy)
                || engine.poll_notification() != Err(Error::Busy)
                || engine.io.writes.len() != writes
            {
                return TestResult::Fail("cancelled/timed out command replayed");
            }
            drop(engine);
            if pool.available() != 0 {
                return TestResult::Fail("published mailbox reclaimed");
            }
        }
    }
    let (_pool, mut engine) = ready();
    engine.io.revoke = Some((0x1d6, engine.authority));
    if run(engine.hpd(0)) != Err(Error::Revoked) || engine.mailbox.state != MailboxState::Failed {
        return TestResult::Fail("post-publication revocation ignored");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_mailbox_cancellation_timeout_and_revocation_quarantine
);

use super::*;

fn ready() -> (Pool, Engine<Fake>) {
    let (pool, mut engine) = fixture();
    run(engine.quiesce()).unwrap();
    run(engine.start(tmr(), fb())).unwrap();
    run(engine.initialize_mailbox()).unwrap();
    (pool, engine)
}
fn dmub_navi22_mailbox_proves_version_caps_and_wraparound() -> TestResult {
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
        if run(engine.hpd((i % 6) as u8)) != Ok(true) {
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
    "drivers/gpu/dmub-navi22",
    dmub_navi22_mailbox_proves_version_caps_and_wraparound
);

fn dmub_navi22_mailbox_handshake_rejects_stale_firmware() -> TestResult {
    for case in 0..4 {
        let (_pool, mut engine) = fixture();
        run(engine.quiesce()).unwrap();
        run(engine.start(tmr(), fb())).unwrap();
        let expected = match case {
            0 => {
                engine.io.caps = false;
                Ok(())
            }
            1 => {
                // dm_dmub_hw_init never compares the reply with the header.
                engine.io.version ^= 1;
                Ok(())
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
        } else if case == 1 {
            if engine.mailbox.state == MailboxState::Failed
                || engine.status.unwrap().capabilities.is_none()
            {
                return TestResult::Fail("version reply mismatch failed the handshake");
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
    "drivers/gpu/dmub-navi22",
    dmub_navi22_mailbox_handshake_rejects_stale_firmware
);

fn dmub_navi22_mailbox_checks_ownership_before_writes() -> TestResult {
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
        (0x1f6, 0x30000),
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
    "drivers/gpu/dmub-navi22",
    dmub_navi22_mailbox_checks_ownership_before_writes
);

fn dmub_navi22_mailbox_rejects_bad_replies_and_invalid_requests() -> TestResult {
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
    if run(engine.hpd(6)) != Err(Error::Invalid)
        || run(engine.aux(6, 0x90, 0x202, &mut [0])) != Err(Error::Invalid)
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
    "drivers/gpu/dmub-navi22",
    dmub_navi22_mailbox_rejects_bad_replies_and_invalid_requests
);

fn dmub_navi22_mailbox_aux_preserves_notifications_and_rejects_stale() -> TestResult {
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
    "drivers/gpu/dmub-navi22",
    dmub_navi22_mailbox_aux_preserves_notifications_and_rejects_stale
);

fn dmub_navi22_mailbox_cancellation_timeout_and_revocation_quarantine() -> TestResult {
    let (pool, mut engine) = fixture();
    run(engine.quiesce()).unwrap();
    run(engine.start(tmr(), fb())).unwrap();
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
    "drivers/gpu/dmub-navi22",
    dmub_navi22_mailbox_cancellation_timeout_and_revocation_quarantine
);

fn freesync_edid() -> Vec<u8> {
    use crate::amdgpu_dcn30_hdmi::tests::{edid, vsdb, DTD_1080P};
    edid(DTD_1080P, &[vsdb(0, 68), alloc::vec![0x64, 0x1a, 0, 0, 1]])
}
fn dmub_navi22_hdmi_freesync_authenticates_exact_cea_chunks() -> TestResult {
    use crate::amdgpu_freesync::AmdVsdb;
    let (_pool, mut engine) = ready();
    let e = freesync_edid();
    let caps = AmdVsdb {
        version: 1,
        min_hz: 40,
        max_hz: 144,
        vcp_code: 0,
    };
    engine.io.edid_caps = Some(caps);
    if run(engine.hdmi_freesync_caps(&e)) != Ok(Some(caps))
        || engine.mailbox.state != MailboxState::Ready
        || engine.io.edid_chunks.len() != 16
        || engine
            .io
            .edid_chunks
            .iter()
            .enumerate()
            .any(|(i, (offset, chunk))| {
                usize::from(*offset) != i * 8 || chunk[..] != e[128 + i * 8..136 + i * 8]
            })
    {
        return TestResult::Fail("FreeSync CEA chunk/firmware reply ABI");
    }
    let writes = engine.io.writes.len();
    let mut bad = e.clone();
    bad[255] ^= 1;
    for edid in [&bad[..], &e[..128], &e[..200]] {
        if run(engine.hdmi_freesync_caps(edid)) != Ok(None) || engine.io.writes.len() != writes {
            return TestResult::Fail("invalid/missing CTA touched mailbox");
        }
    }
    // An older firmware may consume without implementing this command.
    engine.io.edid_caps = None;
    if run(engine.hdmi_freesync_caps(&e)) != Ok(None) || engine.mailbox.state != MailboxState::Ready
    {
        return TestResult::Fail("optional query absence poisoned mailbox");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi22",
    dmub_navi22_hdmi_freesync_authenticates_exact_cea_chunks
);

fn dmub_navi22_hdmi_freesync_bad_ack_and_cancel_keep_mailbox_owned() -> TestResult {
    use crate::amdgpu_freesync::AmdVsdb;
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll},
    };
    let e = freesync_edid();
    let (_pool, mut engine) = ready();
    engine.io.edid_caps = Some(AmdVsdb {
        version: 1,
        min_hz: 40,
        max_hz: 144,
        vcp_code: 0,
    });
    engine.io.corrupt = Some((5, 1)); // ACK must name the posted offset.
    if run(engine.hdmi_freesync_caps(&e)) != Err(Error::Protocol)
        || engine.mailbox.state != MailboxState::Failed
    {
        return TestResult::Fail("mismatched CEA ACK accepted");
    }
    let (_pool, mut engine) = ready();
    engine.io.commands = false;
    {
        let mut future = pin!(engine.hdmi_freesync_caps(&e));
        if !matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(core::task::Waker::noop())),
            Poll::Pending
        ) {
            return TestResult::Fail("missing firmware command did not wait");
        }
    }
    if engine.mailbox.state != MailboxState::InFlight || run(engine.hpd(0)) != Err(Error::Busy) {
        return TestResult::Fail("cancelled CEA operation released shared mailbox");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi22",
    dmub_navi22_hdmi_freesync_bad_ack_and_cancel_keep_mailbox_owned
);

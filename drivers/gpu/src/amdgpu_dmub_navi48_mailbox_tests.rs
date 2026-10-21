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
        max_speed_mhz: 0,
    }
}
fn dmub_navi48_dp_drive_preserves_native_v17_zero_signal_encoding() -> TestResult {
    use crate::dp_link_training::LinkRate;
    for phy in 0..4 {
        for lanes in [1, 2, 4] {
            for (rate, clock) in [
                (LinkRate::Rbr, 16200u32),
                (LinkRate::Hbr, 27000),
                (LinkRate::Hbr2, 54000),
                (LinkRate::Hbr3, 81000),
            ] {
                for swing in 0..4 {
                    for pre_emphasis in 0..=3 - swing {
                        let (_pool, mut e) = ready();
                        let path = dp_path(phy, (phy + 2) % 4 + 1);
                        let offset = e.io.mailbox + e.io.regs[&(DCN + 0x1d6 * 4)] as usize;
                        run(e.set_dp_drive(
                            path,
                            DpPhySettings {
                                lanes,
                                rate,
                                mst: false,
                            },
                            DpDriveSettings {
                                swing,
                                pre_emphasis,
                            },
                        ))
                        .unwrap();
                        let mut golden = [0; 64];
                        golden[..4].copy_from_slice(&[128, 1, 0, 16]);
                        golden[4] = phy;
                        golden[5] = 11;
                        golden[6] = swing | pre_emphasis << 3; // no MAX flags in VBIOS packet
                        golden[7] = lanes;
                        golden[8..12].copy_from_slice(&clock.to_le_bytes());
                        golden[12] = path.hpd;
                        golden[14] = 19;
                        golden[15] = 246; // signal defaults to NONE, unlike ENABLE's DP
                        for lane in 0..lanes {
                            assert_eq!(e.io.slot(offset + usize::from(lane) * 64), golden);
                        }
                        assert_eq!(e.mailbox.state, MailboxState::Ready);
                    }
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_dp_drive_preserves_native_v17_zero_signal_encoding
);
fn dmub_navi48_dp_drive_validates_electrical_levels_and_quarantines_cancellation() -> TestResult {
    let (_pool, mut e) = ready();
    let settings = DpPhySettings {
        lanes: 4,
        rate: crate::dp_link_training::LinkRate::Hbr3,
        mst: false,
    };
    for drive in [
        DpDriveSettings {
            swing: 4,
            pre_emphasis: 0,
        },
        DpDriveSettings {
            swing: 0,
            pre_emphasis: 255,
        },
        DpDriveSettings {
            swing: 2,
            pre_emphasis: 2,
        },
    ] {
        let bytes = e.io.bytes.clone();
        let writes = e.io.writes.len();
        assert_eq!(
            run(e.set_dp_drive(dp_path(2, 1), settings, drive)),
            Err(Error::Invalid)
        );
        assert_eq!(e.io.bytes, bytes);
        assert_eq!(e.io.writes.len(), writes);
    }
    e.io.commands = false;
    {
        let mut f =
            core::pin::pin!(e.set_dp_drive(dp_path(2, 1), settings, DpDriveSettings::default()));
        assert!(f
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    assert_eq!(e.mailbox.state, MailboxState::InFlight);
    assert_eq!(run(e.disable_dp_sst(dp_path(2, 1))), Err(Error::Busy));
    assert_eq!(
        run(e.set_dp_drive(dp_path(2, 1), settings, DpDriveSettings::default())),
        Err(Error::Busy)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_dp_drive_validates_electrical_levels_and_quarantines_cancellation
);
fn dmub_navi48_dp_enable_uses_native_lane_rate_and_zero_connector_fields() -> TestResult {
    use crate::dp_link_training::LinkRate;
    for phy in 0..4 {
        for hpd in 1..=4 {
            for lanes in [1, 2, 4] {
                for (rate, clock) in [
                    (LinkRate::Rbr, 16200u32),
                    (LinkRate::Hbr, 27000),
                    (LinkRate::Hbr2, 54000),
                    (LinkRate::Hbr3, 81000),
                ] {
                    let (_pool, mut e) = ready();
                    let offset = e.io.mailbox + e.io.regs[&(DCN + 0x1d6 * 4)] as usize;
                    run(e.enable_dp_sst(
                        dp_path(phy, hpd),
                        DpPhySettings {
                            lanes,
                            rate,
                            mst: false,
                        },
                    ))
                    .unwrap();
                    let mut golden = [0; 64];
                    golden[..4].copy_from_slice(&[128, 1, 0, 16]);
                    golden[4] = phy;
                    golden[5] = 1;
                    golden[7] = lanes;
                    golden[8..12].copy_from_slice(&clock.to_le_bytes());
                    golden[12] = hpd;
                    golden[15] = 244;
                    assert_eq!(e.io.slot(offset), golden);
                    assert_eq!(e.mailbox.state, MailboxState::Ready);
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_dp_enable_uses_native_lane_rate_and_zero_connector_fields
);
fn dmub_navi48_dp_enable_validates_before_submission_and_retains_cancelled_transport() -> TestResult
{
    let (_pool, mut e) = ready();
    for (phy, hpd, lanes, dp) in [
        (4, 1, 4, true),
        (2, 0, 4, true),
        (2, 5, 4, true),
        (2, 1, 0, true),
        (2, 1, 3, true),
        (2, 1, 8, true),
        (2, 1, 4, false),
    ] {
        let mut path = dp_path(phy, hpd);
        if !dp {
            path.connector = crate::amdgpu_dcn_inventory::Connector::HdmiTypeA;
        }
        let bytes = e.io.bytes.clone();
        let writes = e.io.writes.len();
        assert_eq!(
            run(e.enable_dp_sst(
                path,
                DpPhySettings {
                    lanes,
                    rate: crate::dp_link_training::LinkRate::Hbr3,
                    mst: false,
                }
            )),
            Err(Error::Invalid)
        );
        assert_eq!(e.io.bytes, bytes);
        assert_eq!(e.io.writes.len(), writes);
    }
    e.io.commands = false;
    let settings = DpPhySettings {
        lanes: 2,
        rate: crate::dp_link_training::LinkRate::Hbr2,
        mst: false,
    };
    {
        let mut future = core::pin::pin!(e.enable_dp_sst(dp_path(0, 1), settings));
        assert!(future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    assert_eq!(e.mailbox.state, MailboxState::InFlight);
    assert_eq!(
        run(e.enable_dp_sst(dp_path(0, 1), settings)),
        Err(Error::Busy)
    );
    assert_eq!(run(e.disable_dp_sst(dp_path(0, 1))), Err(Error::Busy));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_dp_enable_validates_before_submission_and_retains_cancelled_transport
);
fn dmub_navi48_tmds_disable_uses_native_hdmi_mode_connector_and_hpo_default() -> TestResult {
    for phy in 0..4 {
        for hpd in 1..=4 {
            let (_pool, mut e) = ready();
            let mut path = dp_path(phy, hpd);
            path.connector = crate::amdgpu_dcn_inventory::Connector::HdmiTypeA;
            let offset = e.io.mailbox + e.io.regs[&(DCN + 0x1d6 * 4)] as usize;
            run(e.disable_tmds(path)).unwrap();
            let mut golden = [0; 64];
            golden[..4].copy_from_slice(&[128, 1, 0, 16]);
            golden[4] = phy;
            golden[6] = 3;
            golden[12] = hpd;
            golden[14] = 12;
            golden[15] = 246; // native zero engine id minus HPO_0(10), not HPO_DP_0
            assert_eq!(e.io.slot(offset), golden);
            assert_eq!(e.mailbox.state, MailboxState::Ready);
        }
    }
    TestResult::Pass
}
fn dmub_navi48_frl_disable_uses_native_frl_mode_and_zero_engine_encoding() -> TestResult {
    for phy in 0..4 {
        for hpd in 1..=4 {
            let (_pool, mut e) = ready();
            let mut path = dp_path(phy, hpd);
            path.connector = crate::amdgpu_dcn_inventory::Connector::HdmiTypeA;
            let offset = e.io.mailbox + e.io.regs[&(DCN + 0x1d6 * 4)] as usize;
            run(e.disable_frl(path)).unwrap();
            let mut golden = [0; 64];
            golden[..4].copy_from_slice(&[128, 1, 0, 16]);
            golden[4] = phy;
            golden[6] = 4; // DCE112 HDMI_FRL, distinct from TMDS mode 3
            golden[12] = hpd;
            golden[14] = 12;
            golden[15] = 246; // zero-initialized DIGA minus HPO_0
            assert_eq!(e.io.slot(offset), golden);
            assert_eq!(e.mailbox.state, MailboxState::Ready);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_frl_disable_uses_native_frl_mode_and_zero_engine_encoding
);

fn dmub_navi48_frl_disable_validates_path_and_retains_cancelled_mailbox() -> TestResult {
    let (_pool, mut e) = ready();
    for (phy, hpd, hdmi) in [(4, 1, true), (2, 0, true), (2, 5, true), (2, 1, false)] {
        let mut path = dp_path(phy, hpd);
        if hdmi {
            path.connector = crate::amdgpu_dcn_inventory::Connector::HdmiTypeA;
        }
        let bytes = e.io.bytes.clone();
        let writes = e.io.writes.len();
        assert_eq!(run(e.disable_frl(path)), Err(Error::Invalid));
        assert_eq!(e.io.bytes, bytes);
        assert_eq!(e.io.writes.len(), writes);
    }
    let mut path = dp_path(2, 1);
    path.connector = crate::amdgpu_dcn_inventory::Connector::HdmiTypeA;
    e.io.commands = false;
    {
        let mut f = core::pin::pin!(e.disable_frl(path));
        assert!(f
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    assert_eq!(e.mailbox.state, MailboxState::InFlight);
    assert_eq!(run(e.disable_frl(path)), Err(Error::Busy));
    assert_eq!(run(e.disable_tmds(path)), Err(Error::Busy));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_frl_disable_validates_path_and_retains_cancelled_mailbox
);
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_tmds_disable_uses_native_hdmi_mode_connector_and_hpo_default
);

fn dmub_navi48_tmds_disable_rejects_invalid_paths_and_never_replays_cancelled_commands(
) -> TestResult {
    let (_pool, mut e) = ready();
    for (phy, hpd, hdmi) in [(4, 1, true), (2, 0, true), (2, 5, true), (2, 1, false)] {
        let mut path = dp_path(phy, hpd);
        if hdmi {
            path.connector = crate::amdgpu_dcn_inventory::Connector::HdmiTypeA;
        }
        let bytes = e.io.bytes.clone();
        let writes = e.io.writes.len();
        assert_eq!(run(e.disable_tmds(path)), Err(Error::Invalid));
        assert_eq!(e.io.bytes, bytes);
        assert_eq!(e.io.writes.len(), writes);
    }
    let mut path = dp_path(2, 1);
    path.connector = crate::amdgpu_dcn_inventory::Connector::HdmiTypeA;
    e.io.commands = false;
    {
        let mut f = core::pin::pin!(e.disable_tmds(path));
        assert!(f
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    assert_eq!(e.mailbox.state, MailboxState::InFlight);
    assert_eq!(run(e.disable_tmds(path)), Err(Error::Busy));
    assert_eq!(run(e.disable_dp_sst(dp_path(2, 1))), Err(Error::Busy));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_tmds_disable_rejects_invalid_paths_and_never_replays_cancelled_commands
);
fn dmub_navi48_native_transmitter_disable_uses_v17_board_fields() -> TestResult {
    for phy in 0..4 {
        for hpd in 1..=4 {
            let (_pool, mut e) = ready();
            let offset = e.io.mailbox + e.io.regs[&(DCN + 0x1d6 * 4)] as usize;
            run(e.disable_dp_sst(dp_path(phy, hpd))).unwrap();
            let mut golden = [0; 64];
            golden[..4].copy_from_slice(&[128, 1, 0, 16]);
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
                golden[..4].copy_from_slice(&[128, 1, 0, 16]);
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

fn hdmi_path(phy: u8, hpd: u8) -> crate::amdgpu_dcn_inventory::Path {
    let mut path = dp_path(phy, hpd);
    path.connector = crate::amdgpu_dcn_inventory::Connector::HdmiTypeA;
    path
}
fn dmub_navi48_tmds_bringup_commands_match_native_v15_v17_encodings() -> TestResult {
    for phy in 0..4 {
        for hpd in 1..=4 {
            for pipe in 0..4 {
                let (_pool, mut e) = ready();
                let path = hdmi_path(phy, hpd);
                let offset = e.io.mailbox + e.io.regs[&(DCN + 0x1d6 * 4)] as usize;
                run(e.set_tmds_pixel_clock(path, pipe, 148_500, TmdsDepth::Bpc8)).unwrap();
                let mut golden = [0; 64];
                golden[..4].copy_from_slice(&[128, 2, 0, 16]);
                golden[4..8].copy_from_slice(&1_485_000u32.to_le_bytes()); // 100 Hz
                golden[8] = 20 + phy; // COMBOPHY_PLL0 + matching PHY
                golden[9] = if phy < 2 { 0x1e } else { 0x20 }; // UNIPHY, UNIPHY1
                golden[10] = 3;
                golden[12] = pipe;
                assert_eq!(e.io.slot(offset), golden);
                assert_eq!(e.mailbox.state, MailboxState::Ready);
            }
            let (_pool, mut e) = ready();
            let offset = e.io.mailbox + e.io.regs[&(DCN + 0x1d6 * 4)] as usize;
            run(e.enable_tmds(hdmi_path(phy, hpd), 148_500)).unwrap();
            let mut golden = [0; 64];
            golden[..4].copy_from_slice(&[128, 1, 0, 16]);
            golden[4] = phy;
            golden[5] = 1;
            golden[6] = 3;
            golden[7] = 4;
            golden[8..12].copy_from_slice(&14_850u32.to_le_bytes());
            golden[12] = hpd;
            golden[15] = 246;
            assert_eq!(e.io.slot(offset), golden);
        }
    }
    for stream in 0..4 {
        let (_pool, mut e) = ready();
        let offset = e.io.mailbox + e.io.regs[&(DCN + 0x1d6 * 4)] as usize;
        run(e.setup_hdmi_stream(stream, 297_000)).unwrap();
        let mut golden = [0; 64];
        golden[..4].copy_from_slice(&[128, 0, 0, 12]);
        golden[4] = stream;
        golden[5] = 0x0f;
        golden[6] = 3;
        golden[7] = 4;
        golden[8..12].copy_from_slice(&29_700u32.to_le_bytes());
        assert_eq!(e.io.slot(offset), golden);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_tmds_bringup_commands_match_native_v15_v17_encodings
);
fn dmub_navi48_tmds_bringup_commands_reject_invalid_requests_without_submission() -> TestResult {
    let (_pool, mut e) = ready();
    let before = e.io.bytes.clone();
    for path in [
        hdmi_path(4, 1),
        hdmi_path(1, 0),
        hdmi_path(1, 5),
        dp_path(1, 1),
    ] {
        assert_eq!(
            run(e.set_tmds_pixel_clock(path, 0, 148_500, TmdsDepth::Bpc8)),
            Err(Error::Invalid)
        );
        assert_eq!(run(e.enable_tmds(path, 148_500)), Err(Error::Invalid));
    }
    let path = hdmi_path(1, 2);
    for khz in [0, 600_001] {
        assert_eq!(
            run(e.set_tmds_pixel_clock(path, 0, khz, TmdsDepth::Bpc8)),
            Err(Error::Invalid)
        );
        assert_eq!(run(e.enable_tmds(path, khz)), Err(Error::Invalid));
        assert_eq!(run(e.setup_hdmi_stream(0, khz)), Err(Error::Invalid));
    }
    assert_eq!(
        run(e.set_tmds_pixel_clock(path, 4, 148_500, TmdsDepth::Bpc8)),
        Err(Error::Invalid)
    );
    assert_eq!(run(e.setup_hdmi_stream(4, 148_500)), Err(Error::Invalid));
    assert_eq!(e.io.bytes, before);
    assert_eq!(e.mailbox.state, MailboxState::Ready);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_tmds_bringup_commands_reject_invalid_requests_without_submission
);

fn dmub_navi48_tmds_pixel_clock_scales_deep_colour_like_linux() -> TestResult {
    let path = hdmi_path(2, 3);
    for (depth, clock, ratio) in [
        (TmdsDepth::Bpc8, 2_970_000u32, 0),
        (TmdsDepth::Bpc10, 3_712_500, 1),
        (TmdsDepth::Bpc12, 4_455_000, 2),
    ] {
        let (_pool, mut e) = ready();
        let offset = e.io.mailbox + e.io.regs[&(DCN + 0x1d6 * 4)] as usize;
        run(e.set_tmds_pixel_clock(path, 1, 297_000, depth)).unwrap();
        let slot = e.io.slot(offset);
        if slot[4..8] != clock.to_le_bytes() || slot[13] != ratio {
            return TestResult::Fail("deep-colour pixel clock");
        }
    }
    // 594 MHz at 10 bpc is a 742.5 MHz character clock: above TMDS.
    let (_pool, mut e) = ready();
    assert_eq!(
        run(e.set_tmds_pixel_clock(path, 0, 594_000, TmdsDepth::Bpc10)),
        Err(Error::Invalid)
    );
    // phy_pix_clk truncation matches get_norm_pix_clk.
    assert_eq!(TmdsDepth::Bpc10.character_khz(148_351), 185_438);
    assert_eq!(TmdsDepth::Bpc12.character_khz(148_351), 222_526);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_tmds_pixel_clock_scales_deep_colour_like_linux
);

/// UHBR enable and FFE as Linux's HPO link encoder sends them: DP_MST mode,
/// the 128b/132b symbol clock, HPD and HPO instance on ENABLE; the preset
/// in the lane-set byte with HPD1 and instance 244 on FFE.
fn dmub_navi48_uhbr_enable_and_ffe_use_hpo_v17_fields() -> TestResult {
    use crate::amdgpu_dmub_navi48::UhbrRate::{Uhbr10, Uhbr13_5, Uhbr20};
    for (rate, symclk) in [(Uhbr10, 100_000u32), (Uhbr13_5, 135_000), (Uhbr20, 200_000)] {
        for link in 0..4 {
            let (_pool, mut e) = ready();
            let offset = e.io.mailbox + e.io.regs[&(DCN + 0x1d6 * 4)] as usize;
            run(e.enable_uhbr(dp_path(2, 3), 4, rate, link)).unwrap();
            let mut golden = [0; 64];
            golden[..4].copy_from_slice(&[128, 1, 0, 16]);
            golden[4] = 2;
            golden[5] = 1;
            golden[6] = 5;
            golden[7] = 4;
            golden[8..12].copy_from_slice(&symclk.to_le_bytes());
            golden[12] = 3;
            golden[15] = link;
            assert_eq!(e.io.slot(offset), golden);
            run(e.set_uhbr_ffe(dp_path(2, 3), 2, rate, 9)).unwrap();
            let mut ffe = golden;
            (ffe[5], ffe[6], ffe[7], ffe[12], ffe[15]) = (11, 9, 2, 1, 244);
            assert_eq!(e.io.slot(offset + 64), ffe);
            assert_eq!(e.mailbox.state, MailboxState::Ready);
        }
    }
    let (_pool, mut e) = ready();
    assert_eq!(
        run(e.enable_uhbr(dp_path(2, 3), 3, Uhbr10, 0)),
        Err(Error::Invalid)
    );
    assert_eq!(
        run(e.enable_uhbr(dp_path(2, 3), 4, Uhbr10, 4)),
        Err(Error::Invalid)
    );
    assert_eq!(
        run(e.set_uhbr_ffe(dp_path(2, 3), 4, Uhbr10, 16)),
        Err(Error::Invalid)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_uhbr_enable_and_ffe_use_hpo_v17_fields
);

/// FRL enable and TxFFE as Linux's HPO FRL path sends them: digmode 4,
/// the character clock in 10 kHz (100 kHz units on FFE, divided twice),
/// HPO 0 with no connector on ENABLE, the HDMI-A connector and HPO 0xF6
/// on FFE.
fn dmub_navi48_frl_enable_and_ffe_use_linux_v17_fields() -> TestResult {
    let hdmi = |phy, hpd| crate::amdgpu_dcn_inventory::Path {
        connector: crate::amdgpu_dcn_inventory::Connector::HdmiTypeA,
        ..dp_path(phy, hpd)
    };
    let (_pool, mut e) = ready();
    let offset = e.io.mailbox + e.io.regs[&(DCN + 0x1d6 * 4)] as usize;
    run(e.enable_frl(hdmi(1, 2), 4, 666_667)).unwrap();
    let mut golden = [0; 64];
    golden[..4].copy_from_slice(&[128, 1, 0, 16]);
    (golden[4], golden[5], golden[6], golden[7], golden[12]) = (1, 1, 4, 4, 2);
    golden[8..12].copy_from_slice(&66_666u32.to_le_bytes());
    assert_eq!(e.io.slot(offset), golden);
    run(e.set_frl_ffe(hdmi(1, 2), 3, 333_333, 0x22)).unwrap();
    let mut ffe = [0; 64];
    ffe[..4].copy_from_slice(&[128, 1, 0, 16]);
    (ffe[4], ffe[5], ffe[6], ffe[7], ffe[12], ffe[14], ffe[15]) = (1, 11, 0x22, 3, 2, 12, 0xf6);
    ffe[8..12].copy_from_slice(&3_333u32.to_le_bytes());
    assert_eq!(e.io.slot(offset + 64), ffe);
    assert_eq!(
        run(e.enable_frl(dp_path(1, 2), 4, 666_667)),
        Err(Error::Invalid)
    );
    assert_eq!(
        run(e.enable_frl(hdmi(1, 2), 2, 666_667)),
        Err(Error::Invalid)
    );
    assert_eq!(
        run(e.set_frl_ffe(hdmi(1, 2), 4, 666_667, 0x80)),
        Err(Error::Invalid)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_frl_enable_and_ffe_use_linux_v17_fields
);

/// An MST link as dcn10_link_encoder_enable_dp_mst_output and
/// disable_output command it: transmitter control v1.7 with
/// ATOM_TRANSMITTER_DIGMODE_V6_DP_MST (5), otherwise as for SST.
fn dmub_navi48_dp_mst_uses_digmode_5() -> TestResult {
    use crate::dp_link_training::LinkRate;
    let (_pool, mut e) = ready();
    let offset = e.io.mailbox + e.io.regs[&(DCN + 0x1d6 * 4)] as usize;
    run(e.enable_dp_sst(
        dp_path(1, 2),
        DpPhySettings {
            lanes: 4,
            rate: LinkRate::Hbr2,
            mst: true,
        },
    ))
    .unwrap();
    let mut golden = [0; 64];
    golden[..4].copy_from_slice(&[128, 1, 0, 16]);
    golden[4] = 1;
    golden[5] = 1;
    golden[6] = 5;
    golden[7] = 4;
    golden[8..12].copy_from_slice(&54000u32.to_le_bytes());
    golden[12] = 2;
    golden[15] = 244;
    if e.io.slot(offset) != golden {
        return TestResult::Fail("MST enable");
    }
    let (_pool, mut e) = ready();
    let offset = e.io.mailbox + e.io.regs[&(DCN + 0x1d6 * 4)] as usize;
    run(e.disable_dp_transmitter(dp_path(1, 2), DpSignal::Mst, 19)).unwrap();
    let mut golden = [0; 64];
    golden[..4].copy_from_slice(&[128, 1, 0, 16]);
    golden[4] = 1;
    golden[6] = 5;
    golden[12] = 2;
    golden[14] = 19;
    golden[15] = 244;
    if e.io.slot(offset) != golden {
        return TestResult::Fail("MST disable");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dmub-navi48", dmub_navi48_dp_mst_uses_digmode_5);

/// ready() with the caps query reporting FAMS version `fams`.
fn ready_fams(fams: u8) -> (Pool, Engine<Fake>) {
    let (pool, mut engine) = fixture();
    engine.io.fams_version = fams;
    run(engine.quiesce()).unwrap();
    run(engine.start(tmr())).unwrap();
    run(engine.initialize_mailbox()).unwrap();
    (pool, engine)
}
fn dmub_navi48_fams2_follows_the_firmware_version() -> TestResult {
    // FAMS 1.1 firmware: DC turns FAMS2 off; 2.1 keeps it.
    let (_pool, e) = ready();
    let caps = e.status.unwrap().capabilities.unwrap();
    if caps.fams_version() != 0x21 || caps.fams2() {
        return TestResult::Fail("FAMS 1.1 firmware kept FAMS2");
    }
    let (_pool, e) = ready_fams(0x41);
    let caps = e.status.unwrap().capabilities.unwrap();
    if caps.fams_version() != FAMS_VERSION || !caps.fams2() {
        return TestResult::Fail("FAMS 2.1 firmware");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_fams2_follows_the_firmware_version
);

fn dmub_navi48_hw_lock_posts_inbox0_and_waits_for_the_ack() -> TestResult {
    let (_pool, mut e) = ready();
    for (lock, word) in [(true, 0x0080_0001u32), (false, 0x0100_0001)] {
        e.io.writes.clear();
        e.io.regs.insert(DCN + 0x1f4 * 4, 7);
        let command = if lock {
            HW_LOCK | HW_LOCK_LOCK
        } else {
            HW_LOCK | HW_LOCK_RELEASE
        };
        if run(e.inbox0(command)).is_err() {
            return TestResult::Fail("inbox0 command");
        }
        // The stale acknowledgement is cleared before the command is posted.
        let ack = e.io.writes.iter().position(|w| *w == (DCN + 0x1f4 * 4, 0));
        let post =
            e.io.writes
                .iter()
                .position(|w| *w == (DCN + 0x1d2 * 4, word));
        if ack.is_none() || post.is_none() || ack > post || e.mailbox.state != MailboxState::Ready {
            return TestResult::Fail("inbox0 lock sequence");
        }
    }
    // Firmware that never acknowledges times out and fails the mailbox.
    e.io.inbox0 = false;
    if run(e.inbox0(HW_LOCK | HW_LOCK_LOCK)) != Err(Error::CommandTimeout)
        || e.mailbox.state != MailboxState::Failed
    {
        return TestResult::Fail("inbox0 timeout");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_hw_lock_posts_inbox0_and_waits_for_the_ack
);

fn fams2_stream() -> Fams2StreamConfig {
    Fams2StreamConfig {
        base: crate::amdgpu_dcn401_dml::pstate::Fams2Stream {
            kind: 2,
            otg_vline_time_ns: 14814,
            htotal: 2200,
            vtotal: 1125,
            vblank_start: 1121,
            vblank_end: 41,
            max_vtotal: 1125,
            allow_start_otg_vline: 1092,
            allow_end_otg_vline: 1094,
            drr_keepout_otg_vline: 1118,
            scheduling_delay_otg_vlines: 38,
            contention_delay_otg_vlines: 17,
            vline_int_ack_delay_otg_vlines: 3,
            allow_to_target_delay_otg_vlines: 5,
            is_drr: false,
            clamp_vtotal_min: true,
            min_ttu_vblank_usable: true,
            vactive_det_fill_delay_otg_vlines: 27,
        },
        otg_inst: 2,
        pipe_mask: 0b0110,
        num_planes: 1,
        plane_pipe_masks: [0b0110, 0, 0, 0, 0, 0],
    }
}

fn dmub_navi48_fams2_config_matches_dmub_cmd_layout() -> TestResult {
    // Disabled (what the hardware-exclusive methods send): the global
    // command alone, every field zero.
    let global = Fams2Global {
        max_allow_delay_us: 100_000,
        lock_wait_time_us: 5000,
        num_streams: 2,
        features: Fams2Features {
            enable: true,
            enable_stall_recovery: true,
            enable_offload_flip: true,
            allow_delay_check_mode: 1,
            ..Fams2Features::default()
        },
        recovery_timeout_us: 5000,
        hwfq_flip_programming_delay_us: 300,
        max_allow_to_target_delta_us: 0,
    };
    let off = fams2_config_commands(false, &global, &[fams2_stream()]);
    let mut golden = [0u8; 64];
    golden[..4].copy_from_slice(&[76, 4, 0, 60]);
    if off != [golden] {
        return TestResult::Fail("disabled FAMS2 config");
    }
    // Enabled with two streams: global, both bases, both sub-states, every
    // command but the last chained.
    let streams = [fams2_stream(), fams2_stream()];
    let on = fams2_config_commands(true, &global, &streams);
    if on.len() != 5
        || on[..4].iter().any(|c| c[2] != 2)
        || on[4][2] != 0
        || on.iter().any(|c| c[..2] != [76, 4] || c[3] != 60)
    {
        return TestResult::Fail("FAMS2 command chain");
    }
    let word = |c: &[u8; 64], at: usize| u32::from_le_bytes(c[4 + at..8 + at].try_into().unwrap());
    let half = |c: &[u8; 64], at: usize| u16::from_le_bytes(c[4 + at..6 + at].try_into().unwrap());
    // dmub_cmd_fams2_global_config: features bit 0 enable, 2 stall
    // recovery, 4 offload flip, 6-7 allow delay check mode.
    if [0, 4, 8, 12, 16, 20, 24].map(|at| word(&on[0], at))
        != [100_000, 5000, 2, 1 | 1 << 2 | 1 << 4 | 1 << 6, 5000, 300, 0]
    {
        return TestResult::Fail("FAMS2 global layout");
    }
    let b = &on[1];
    if word(b, 0) != 2
        || word(b, 4) != 14814
        || word(b, 8) != 0
        || [12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34].map(|at| half(b, at))
            != [2200, 1125, 1121, 41, 1125, 1092, 1094, 1118, 38, 17, 3, 5]
        || b[4 + 36..4 + 46] != [0b110, 2, 0b0110, 1, 0b0110, 0, 0, 0, 0, 0]
    {
        return TestResult::Fail("FAMS2 base layout");
    }
    if half(&on[3], 0) != 27 || on[3][4 + 2..].iter().any(|&x| x != 0) {
        return TestResult::Fail("FAMS2 legacy sub-state");
    }
    // The owner posts the single disabled command, and refuses a chain it
    // cannot mark pending.
    let (_pool, mut e) = ready_fams(0x41);
    let offset = e.io.mailbox + e.io.regs[&(DCN + 0x1d6 * 4)] as usize;
    if run(e.fams2_update_config(&off)).is_err() || e.io.slot(offset) != golden {
        return TestResult::Fail("FAMS2 disable posted");
    }
    let next = e.io.regs[&(DCN + 0x1d6 * 4)];
    if run(e.fams2_update_config(&on)) != Err(Error::Unsupported)
        || e.io.regs[&(DCN + 0x1d6 * 4)] != next
        || e.mailbox.state != MailboxState::Ready
    {
        return TestResult::Fail("FAMS2 chain posted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dmub-navi48",
    dmub_navi48_fams2_config_matches_dmub_cmd_layout
);

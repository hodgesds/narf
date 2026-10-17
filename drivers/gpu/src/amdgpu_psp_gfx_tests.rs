use super::*;
use crate::amdgpu_gfx_navi22::tests::fixture as firmware;

fn prepared() -> (Pool, Session<Fake>) {
    let (pool, mut s) = session();
    run(s.engine.start()).unwrap();
    run(s.setup_tmr_payload(None)).unwrap();
    run(s.load_smc(&[1, 2, 3, 4])).unwrap();
    (pool, s)
}
fn psp_navi22_graphics_order_lengths_and_autoload() -> TestResult {
    for mec2 in [true, false] {
        let firmware = firmware();
        let mut images = firmware.images().unwrap();
        if !mec2 {
            images[5] = None;
        }
        let (pool, mut s) = prepared();
        if run(s.load_gfx(&images)).is_err() || s.gfx_state != GfxLoadState::Accepted {
            return TestResult::Fail("graphics set not accepted");
        }
        let expected = [
            (9, 16),
            (3, 16),
            (2, 16),
            (1, 16),
            (4, 12),
            (4, 12),
            (27, 4),
            (28, 4),
            (29, 4),
            (65, 4),
            (66, 4),
            (22, 4),
            (20, 4),
            (21, 4),
            (26, 4),
            (48, 4),
            (8, 16),
            (13, 16),
            (51, 12),
        ];
        let expected: Vec<_> = expected
            .into_iter()
            .enumerate()
            .filter(|(i, _)| mec2 || *i != 5)
            .map(|(_, v)| v)
            .collect();
        let submissions = &s.engine.io.submissions[2..];
        if submissions.len() != expected.len() + 1 || s.engine.io.violation {
            return TestResult::Fail("wrong command count/flush sequence");
        }
        let autoload_index = expected.len() - 2;
        for (cmd, (kind, len)) in submissions
            .iter()
            .filter(|cmd| cmd[2] != 0x21)
            .zip(expected)
        {
            if cmd[2] != 6
                || cmd[7..11] != [0x6000, 8, len, kind]
                || cmd[11..].iter().any(|v| *v != 0)
            {
                return TestResult::Fail("wrong graphics order, size, address or firmware type");
            }
        }
        let autoload = &submissions[autoload_index];
        if autoload[2] != 0x21
            || autoload[3..].iter().any(|v| *v != 0)
            || run(s.load_gfx(&images)) != Err(Error::Busy)
            || s.payload.is_some()
            || s.media_firmware
                != (MediaFirmware {
                    vcn: Some(0x8_0010_1000),
                    dmcub: Some(0x8_0020_0000),
                    vcn1: None,
                })
            || pool.available() != (16 << 20) - BUFFER_SIZE - (4 << 20)
        {
            return TestResult::Fail("wrong autoload/replay/ownership behavior");
        }
        // SAFETY: model firmware has no running GC/SDMA/SMU consumers.
        unsafe { run(s.stop()) }.unwrap();
        drop(s);
        if pool.available() != 16 << 20 {
            return TestResult::Fail("verified graphics teardown leaked");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_navi22_graphics_order_lengths_and_autoload
);

/// `amdgpu_vcn_setup_ucode` per unharvested instance: VCN (13) then VCN1
/// (58), both before DMCUB, each with its own PSP-reported TMR address.
fn psp_navi22_loads_one_vcn_image_per_unharvested_instance() -> TestResult {
    for (mask, kinds, vcn, vcn1) in [
        (3, &[13, 58][..], Some(0x8_0010_1000), Some(0x8_0018_0000)),
        (2, &[58][..], None, Some(0x8_0018_0000)),
        (0, &[][..], None, None),
    ] {
        let mut firmware = crate::amdgpu_gfx_navi22::tests::fixture_with_vcn(3);
        firmware.harvest_vcn(!mask & 3);
        let images = firmware.images().unwrap();
        let (_pool, mut s) = prepared();
        if firmware.vcn_instances() != mask || run(s.load_gfx(&images)).is_err() {
            return TestResult::Fail("harvested VCN set not accepted");
        }
        let media: Vec<u32> = s.engine.io.submissions[2..]
            .iter()
            .filter(|cmd| cmd[2] == 6 && matches!(cmd[10], 13 | 58 | 51))
            .map(|cmd| cmd[10])
            .collect();
        let mut want = kinds.to_vec();
        want.push(51);
        if media != want
            || s.media_firmware
                != (MediaFirmware {
                    vcn,
                    dmcub: Some(0x8_0020_0000),
                    vcn1,
                })
        {
            return TestResult::Fail("wrong per-instance VCN upload or TMR address");
        }
        // SAFETY: model firmware has no running consumers.
        unsafe { run(s.stop()) }.unwrap();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_navi22_loads_one_vcn_image_per_unharvested_instance
);

fn psp_navi22_graphics_requires_smc_and_complete_set() -> TestResult {
    let firmware = firmware();
    let images = firmware.images().unwrap();
    let (_, mut s) = session();
    run(s.engine.start()).unwrap();
    run(s.setup_tmr_payload(None)).unwrap();
    if run(s.load_gfx(&images)) != Err(Error::Busy) || s.engine.io.submissions.len() != 1 {
        return TestResult::Fail("graphics sent before SMC");
    }
    run(s.load_smc(&[1, 2, 3, 4])).unwrap();
    for index in [0, 1, 2, 3, 4, 6, 7, 8] {
        let mut missing = images;
        missing[index] = None;
        if run(s.load_gfx(&missing)) != Err(Error::Invalid)
            || s.engine.io.submissions.len() != 2
            || s.gfx_state != GfxLoadState::Absent
            || s.payload.is_some()
        {
            return TestResult::Fail("incomplete set partially published");
        }
    }
    let mut wrong_order = images;
    wrong_order.swap(1, 2);
    if run(s.load_gfx(&wrong_order)) != Err(Error::Invalid) || s.engine.io.submissions.len() != 2 {
        return TestResult::Fail("reordered graphics set accepted");
    }
    // SAFETY: no real hardware consumers.
    unsafe { run(s.stop()) }.unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_navi22_graphics_requires_smc_and_complete_set
);

fn psp_navi22_graphics_rejects_partial_load_and_autoload_failure() -> TestResult {
    let firmware = firmware();
    let images = firmware.images().unwrap();
    // First payload, a middle payload, final RLC_G and autoload itself.
    for (command, kind) in [
        (6, Some(9)),
        (6, Some(20)),
        (6, Some(8)),
        (0x21, None),
        (6, Some(13)),
        (6, Some(51)),
    ] {
        let (pool, mut s) = prepared();
        s.engine.io.reject = 0xffff000a;
        s.engine.io.reject_command = Some(command);
        s.engine.io.reject_type = kind;
        if run(s.load_gfx(&images)) != Err(Error::Rejected(0xffff000a))
            || s.gfx_state != GfxLoadState::Failed
        {
            return TestResult::Fail("partial graphics failure reported as accepted");
        }
        let last = s.engine.io.submissions.last().unwrap();
        if last[2] != command || kind.is_some_and(|k| last[10] != k) || s.payload.is_some() {
            return TestResult::Fail(
                "commands continued after rejection or fenced staging retained",
            );
        }
        let before = s.engine.io.submissions.len();
        if run(s.load_gfx(&images)) != Err(Error::Busy) || s.engine.io.submissions.len() != before {
            return TestResult::Fail("partially loaded set replayed");
        }
        s.engine.io.reject = 0;
        // SAFETY: all modeled consumers are stopped, ring is still responsive.
        unsafe { run(s.stop()) }.unwrap();
        drop(s);
        if pool.available() != 16 << 20 {
            return TestResult::Fail("rejected graphics teardown leaked");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_navi22_graphics_rejects_partial_load_and_autoload_failure
);

fn psp_navi22_graphics_cancel_revoke_and_timeout() -> TestResult {
    let firmware = firmware();
    let images = firmware.images().unwrap();
    for kind in [Some(20), None, Some(13), Some(51)] {
        let autoload = kind.is_none();
        for revoke in [false, true] {
            let (pool, mut s) = prepared();
            s.engine.io.stall_command = Some(if autoload { 0x21 } else { 6 });
            s.engine.io.stall_type = kind;
            let authority = s.engine.authority;
            {
                let mut future = core::pin::pin!(s.load_gfx(&images));
                // Each one-chunk staging copy yields once; enough polls to
                // reach the selected outstanding command, not a wall-time wait.
                for _ in 0..24 {
                    if future
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_ready()
                    {
                        return TestResult::Fail("unacknowledged graphics command completed");
                    }
                }
                if revoke {
                    authority.revoke();
                    if run(future) != Err(Error::Revoked) {
                        return TestResult::Fail("graphics ignored revocation");
                    }
                }
            }
            let last = s.engine.io.submissions.last().unwrap();
            if last[2] != if autoload { 0x21 } else { 6 }
                || kind.is_some_and(|kind| last[10] != kind)
                || s.gfx_state
                    != if revoke {
                        GfxLoadState::Failed
                    } else {
                        GfxLoadState::Loading
                    }
                || run(s.load_gfx(&images)) != Err(Error::Busy)
            {
                return TestResult::Fail("cancel/revoke completed later stages or permitted retry");
            }
            // SAFETY: model has no consumers, but incomplete commands must block teardown.
            if unsafe { run(s.stop()) } != Err(Error::Busy) {
                return TestResult::Fail("unacknowledged graphics freed TMR");
            }
            drop(s);
            let retained = BUFFER_SIZE + (4 << 20) + if autoload { 0 } else { 4096 };
            if pool.available() != (16 << 20) - retained {
                return TestResult::Fail("cancel/revoke lost device ownership");
            }
        }
    }
    let (_, mut s) = prepared();
    s.engine.io.stall_command = Some(0x21);
    if run(s.load_gfx(&images)) != Err(Error::Timeout) || s.gfx_state != GfxLoadState::Failed {
        return TestResult::Fail("autoload lacked bounded timeout");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_navi22_graphics_cancel_revoke_and_timeout
);

fn psp_navi22_rlc_boot_requires_accepted_autoload_and_both_statuses() -> TestResult {
    let firmware = firmware();
    let images = firmware.images().unwrap();
    let (pool, mut s) = prepared();
    if run(s.wait_gfx_boot()) != Err(Error::Busy) || s.engine.io.gfx_reads != 0 {
        return TestResult::Fail("RLC checked before autoload acceptance");
    }
    run(s.load_gfx(&images)).unwrap();
    s.engine.io.gfx_samples = vec![
        GfxBootStatus {
            cp_stat: 1,
            rlc_bootload: 1 << 31,
        },
        GfxBootStatus {
            cp_stat: 0,
            rlc_bootload: 0x7fffffff,
        },
        GfxBootStatus {
            cp_stat: 0,
            rlc_bootload: 0x80000005,
        },
    ];
    let writes = s.engine.io.writes.len();
    let commands = s.engine.io.submissions.len();
    let available = pool.available();
    let result = GfxBootStatus {
        cp_stat: 0,
        rlc_bootload: 0x80000005,
    };
    if run(s.wait_gfx_boot()) != Ok(result)
        || s.gfx_status != Some(result)
        || s.gfx_state != GfxLoadState::BootComplete
        || s.engine.io.gfx_reads != 3
        || s.engine.io.writes.len() != writes
        || s.engine.io.submissions.len() != commands
        || pool.available() != available
        || run(s.wait_gfx_boot()) != Err(Error::Busy)
    {
        return TestResult::Fail("RLC status check ignored CP/bit31 or changed ownership/hardware");
    }
    // SAFETY: no real firmware consumers in the model.
    unsafe { run(s.stop()) }.unwrap();
    drop(s);
    if pool.available() != 16 << 20 {
        return TestResult::Fail("completed RLC session leaked after verified stop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_navi22_rlc_boot_requires_accepted_autoload_and_both_statuses
);

fn psp_navi22_rlc_boot_removal_timeout_and_revocation() -> TestResult {
    let firmware = firmware();
    let images = firmware.images().unwrap();
    for (status, expected) in [
        (
            GfxBootStatus {
                cp_stat: u32::MAX,
                rlc_bootload: 1 << 31,
            },
            Error::DeviceGone,
        ),
        (
            GfxBootStatus {
                cp_stat: 0,
                rlc_bootload: u32::MAX,
            },
            Error::DeviceGone,
        ),
        (
            GfxBootStatus {
                cp_stat: 0,
                rlc_bootload: 0,
            },
            Error::Timeout,
        ),
        (
            GfxBootStatus {
                cp_stat: 1,
                rlc_bootload: 1 << 31,
            },
            Error::Timeout,
        ),
    ] {
        let (pool, mut s) = prepared();
        run(s.load_gfx(&images)).unwrap();
        s.engine.io.gfx_samples = vec![status];
        if run(s.wait_gfx_boot()) != Err(expected)
            || s.gfx_state != GfxLoadState::Failed
            || s.gfx_status != Some(status)
            || run(s.wait_gfx_boot()) != Err(Error::Busy)
        {
            return TestResult::Fail("RLC removal/timeout lost failure or last sample");
        }
        drop(s);
        if pool.available() != (16 << 20) - BUFFER_SIZE - (4 << 20) {
            return TestResult::Fail("RLC failure recycled running firmware memory");
        }
    }
    let (_, mut s) = prepared();
    run(s.load_gfx(&images)).unwrap();
    s.engine.authority.revoke();
    if run(s.wait_gfx_boot()) != Err(Error::Revoked)
        || s.engine.io.gfx_reads != 0
        || s.gfx_status.is_some()
    {
        return TestResult::Fail("revoked status check performed MMIO");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_navi22_rlc_boot_removal_timeout_and_revocation
);

fn psp_navi22_rlc_boot_cancellation_keeps_tmr_owned() -> TestResult {
    let firmware = firmware();
    let images = firmware.images().unwrap();
    for revoke in [false, true] {
        let (pool, mut s) = prepared();
        run(s.load_gfx(&images)).unwrap();
        s.engine.io.gfx_samples = vec![GfxBootStatus {
            cp_stat: 0,
            rlc_bootload: 0,
        }];
        let authority = s.engine.authority;
        {
            let mut future = core::pin::pin!(s.wait_gfx_boot());
            if future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return TestResult::Fail("pending RLC boot completed");
            }
            if revoke {
                authority.revoke();
                if run(future) != Err(Error::Revoked) {
                    return TestResult::Fail("RLC poll ignored revocation");
                }
            }
        }
        if s.gfx_state
            != if revoke {
                GfxLoadState::Failed
            } else {
                GfxLoadState::Checking
            }
            || s.engine.io.gfx_reads != 1
            || run(s.wait_gfx_boot()) != Err(Error::Busy)
            || run(s.load_gfx(&images)) != Err(Error::Busy)
        {
            return TestResult::Fail("cancelled RLC poll retried or continued MMIO");
        }
        drop(s);
        if pool.available() != (16 << 20) - BUFFER_SIZE - (4 << 20) {
            return TestResult::Fail("cancelled RLC poll released running firmware memory");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_navi22_rlc_boot_cancellation_keeps_tmr_owned
);

fn psp_navi22_media_entry_points_must_belong_to_retained_tmr() -> TestResult {
    let firmware = firmware();
    let images = firmware.images().unwrap();
    for address in [0, 0x8_0040_1001, 0x8_0080_0000, u64::MAX] {
        let (_pool, mut s) = prepared();
        s.engine.io.media_address = Some(address);
        if run(s.load_gfx(&images)) != Err(Error::Invalid)
            || s.gfx_state != GfxLoadState::Failed
            || s.media_firmware != MediaFirmware::default()
            || s.engine.io.submissions.last().unwrap()[10] != 13
        {
            return TestResult::Fail("media entry point escaped TMR or continued after error");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_navi22_media_entry_points_must_belong_to_retained_tmr
);

fn psp_navi48_graphics_global_order_autoload_and_media() -> TestResult {
    let firmware = crate::amdgpu_navi48_firmware::fixture();
    let images = firmware.images().unwrap();
    let (pool, mut s) = prepared();
    if run(s.load_gfx12(&images)).is_err() || s.gfx_state != GfxLoadState::Accepted {
        return TestResult::Fail("GC12 graphics set not accepted");
    }
    let submissions = &s.engine.io.submissions[2..];
    let expected = &crate::amdgpu_navi48_ucode::UPLOAD_ORDER[1..];
    let types: Vec<_> = submissions
        .iter()
        .filter(|c| c[2] == 6)
        .map(|c| c[10])
        .collect();
    let auto = submissions.iter().position(|c| c[2] == 0x21).unwrap();
    if types != expected
        || submissions.len() != expected.len() + 1
        || submissions[auto - 1][10] != 8
        || submissions[auto + 1][10] != 13
        || s.engine.io.violation
        || s.payload.is_some()
        || s.media_firmware.vcn != Some(0x8_0010_1000)
        || s.media_firmware.dmcub != Some(0x8_0020_0000)
        || run(s.load_gfx12(&images)) != Err(Error::Busy)
    {
        return TestResult::Fail("GC12 global UCODE order, autoload, media bounds or replay");
    }
    // SAFETY: model has no firmware consumers or real GPU memory.
    unsafe { run(s.stop()) }.unwrap();
    drop(s);
    if pool.available() != 16 << 20 {
        return TestResult::Fail("GC12 verified stop leaked memory");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_navi48_graphics_global_order_autoload_and_media
);

fn psp_navi48_interrupted_upload_preserves_ownership() -> TestResult {
    let firmware = crate::amdgpu_navi48_firmware::fixture();
    let images = firmware.images().unwrap();
    for kind in [71, 94, 82, 8, 13, 51] {
        let (pool, mut s) = prepared();
        s.engine.io.stall_command = Some(6);
        s.engine.io.stall_type = Some(kind);
        {
            let mut future = core::pin::pin!(s.load_gfx12(&images));
            for _ in 0..50 {
                if future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
                {
                    return TestResult::Fail("stalled GC12 upload completed");
                }
            }
        }
        if s.gfx_state != GfxLoadState::Loading
            || s.engine.state != State::Pending
            || s.engine.io.submissions.last().unwrap()[10] != kind
            || run(s.load_gfx12(&images)) != Err(Error::Busy)
        {
            return TestResult::Fail("cancelled GC12 upload lost stage or allowed replay");
        }
        drop(s);
        if pool.available() != (16 << 20) - BUFFER_SIZE - (4 << 20) - 4096 {
            return TestResult::Fail("cancelled GC12 upload recycled PSP-owned payload/TMR");
        }
    }
    let (_, mut s) = prepared();
    s.engine.io.reject = 7;
    s.engine.io.reject_command = Some(6);
    s.engine.io.reject_type = Some(94);
    if run(s.load_gfx12(&images)) != Err(Error::Rejected(7))
        || s.gfx_state != GfxLoadState::Failed
        || s.engine.io.submissions.iter().any(|c| c[2] == 0x21)
    {
        return TestResult::Fail("failed RS64 stack load still started RLC");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_navi48_interrupted_upload_preserves_ownership
);

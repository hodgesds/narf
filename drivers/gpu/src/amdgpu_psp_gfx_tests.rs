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
        for (cmd, (kind, len)) in submissions.iter().zip(expected) {
            if cmd[2] != 6
                || cmd[7..11] != [0x6000, 8, len, kind]
                || cmd[11..].iter().any(|v| *v != 0)
            {
                return TestResult::Fail("wrong graphics order, size, address or firmware type");
            }
        }
        let autoload = submissions.last().unwrap();
        if autoload[2] != 0x21
            || autoload[3..].iter().any(|v| *v != 0)
            || run(s.load_gfx(&images)) != Err(Error::Busy)
            || s.payload.is_some()
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
    for index in [0, 1, 2, 3, 4, 6] {
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
    for (command, kind) in [(6, Some(9)), (6, Some(20)), (6, Some(8)), (0x21, None)] {
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
    for autoload in [false, true] {
        for revoke in [false, true] {
            let (pool, mut s) = prepared();
            s.engine.io.stall_command = Some(if autoload { 0x21 } else { 6 });
            s.engine.io.stall_type = (!autoload).then_some(20);
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
                || !autoload && last[10] != 20
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

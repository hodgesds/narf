use super::*;
use alloc::vec::Vec;
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Model {
    progress: Teardowns,
    attempts: Vec<(u8, TeardownStep, bool)>,
    writes: Vec<(u8, TeardownStep)>,
    blocked: Option<TeardownStep>,
    failed: Option<TeardownStep>,
    pending: Option<(TeardownStep, bool)>,
    poisoned: bool,
    retired: [bool; 4],
    released: [bool; 4],
}
impl Model {
    fn new() -> Self {
        Self {
            progress: Teardowns::new(),
            attempts: Vec::new(),
            writes: Vec::new(),
            blocked: None,
            failed: None,
            pending: None,
            poisoned: false,
            retired: [false; 4],
            released: [false; 4],
        }
    }
}
impl Backend for Model {
    fn teardowns(&mut self) -> &mut Teardowns {
        &mut self.progress
    }
    fn completed(&mut self, r: Request) -> Result<(), ModesetError> {
        if self.retired[usize::from(r.pipe)] {
            Ok(())
        } else {
            Err(otg::Error::Busy.into())
        }
    }
    async unsafe fn step(&mut self, r: Request, s: TeardownStatus) -> Result<(), ModesetError> {
        self.attempts.push((r.pipe, s.next, s.unplugged));
        if self.poisoned || self.blocked == Some(s.next) {
            return Err(otg::Error::Busy.into());
        }
        if s.next == TeardownStep::Release && !self.retired[usize::from(r.pipe)] {
            return Err(otg::Error::Busy.into());
        }
        if self.pending == Some((s.next, false)) {
            core::future::pending::<()>().await;
        }
        self.writes.push((r.pipe, s.next));
        if self.failed == Some(s.next) {
            self.poisoned = true;
            return Err(otg::Error::Readback(0).into());
        }
        if self.pending == Some((s.next, true)) {
            // Model the native owner's sticky in-flight state after a write.
            self.poisoned = true;
            core::future::pending::<()>().await;
        }
        if s.next == TeardownStep::Planes {
            self.retired[usize::from(r.pipe)] = true;
        }
        if s.next == TeardownStep::Release {
            self.released[usize::from(r.pipe)] = true;
        }
        Ok(())
    }
}
fn run_model(
    m: &mut Model,
    r: Request,
    unplugged: bool,
) -> impl Future<Output = Result<(), ModesetError>> + '_ {
    // SAFETY: this backend owns only bookkeeping; no CPU or hardware access exists.
    unsafe { run(m, r, unplugged) }
}
fn finish<T>(f: impl Future<Output = T>) -> T {
    let mut f = core::pin::pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(r) => r,
        Poll::Pending => panic!("model unexpectedly waited"),
    }
}
fn cancel(f: impl Future) {
    let mut f = core::pin::pin!(f);
    assert!(f
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
}
fn request(protocol: Protocol) -> Request {
    Request {
        pipe: 1,
        odm: None,
        port: 3,
        protocol,
        audio: true,
        scdc: protocol == Protocol::Tmds,
        dsc: protocol == Protocol::Sst,
        scanout: Some(ScanoutWitness {
            address: 0x8_0000_1000,
            stream: 2,
            frames: (7, 8),
        }),
    }
}
fn cases() -> [(Protocol, &'static [TeardownStep]); 5] {
    use TeardownStep::*;
    [
        (
            Protocol::Tmds,
            &[Audio, Scanout, Video, Scdc, Link, Timing, Planes],
        ),
        (
            Protocol::Sst,
            &[
                Audio, Scanout, Video, Frontend, Link, Timing, DscClock, Planes,
            ],
        ),
        (
            Protocol::Mst,
            &[
                Audio, Scanout, Video, Payload, Frontend, Link, Timing, Planes,
            ],
        ),
        (
            Protocol::Uhbr,
            &[Audio, Scanout, Video, Link, Timing, Planes],
        ),
        (
            Protocol::Frl,
            &[Audio, Scanout, Video, Scdc, Link, Timing, Planes],
        ),
    ]
}

fn navi48_teardown_orders_every_protocol_and_rearms_only_after_completion() -> TestResult {
    for (protocol, steps) in cases() {
        let r = request(protocol);
        let mut m = Model::new();
        // SAFETY: model-only operations, no CPU or device references.
        assert_eq!(finish(run_model(&mut m, r, false)), Ok(()));
        let expected: Vec<_> = steps.iter().map(|&s| (r.pipe, s)).collect();
        assert_eq!(m.writes, expected);
        assert_eq!(m.progress.check_idle(), Ok(()));
        // Completion is idempotent, but cannot mask a raw lower-level restart.
        // SAFETY: model-only operations.
        assert_eq!(finish(run_model(&mut m, r, false)), Ok(()));
        m.retired[usize::from(r.pipe)] = false;
        // SAFETY: model-only operations.
        assert_eq!(
            finish(run_model(&mut m, r, false)),
            Err(otg::Error::Busy.into())
        );
        assert_eq!(m.writes, expected);
        m.progress.rearm(r.pipe).unwrap();
        assert_eq!(m.progress.status(r.pipe), None);
        let next = Request {
            scanout: Some(ScanoutWitness {
                address: r.scanout.unwrap().address + 4096,
                ..r.scanout.unwrap()
            }),
            ..r
        };
        // SAFETY: fresh model incarnation with no CPU or device references.
        assert_eq!(finish(run_model(&mut m, next, false)), Ok(()));
        assert_eq!(m.writes.len(), 2 * expected.len());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-teardown",
    navi48_teardown_orders_every_protocol_and_rearms_only_after_completion
);

fn navi48_teardown_resumes_preflight_rejections_without_replaying_successes() -> TestResult {
    for (protocol, steps) in cases() {
        for (index, &step) in steps.iter().enumerate() {
            let r = request(protocol);
            let mut m = Model::new();
            m.blocked = Some(step);
            // SAFETY: model-only operations; rejection occurs before writes.
            assert_eq!(
                finish(run_model(&mut m, r, false)),
                Err(otg::Error::Busy.into())
            );
            assert_eq!(m.writes.len(), index);
            assert_eq!(m.progress.status(r.pipe).unwrap().next, step);
            assert!(!m.progress.status(r.pipe).unwrap().in_flight);
            assert_eq!(m.progress.check_idle(), Err(otg::Error::Busy.into()));
            assert_eq!(m.progress.rearm(r.pipe), Err(otg::Error::Busy.into()));
            assert!(!m.retired[usize::from(r.pipe)]);
            m.blocked = None;
            // SAFETY: model preflight obstruction removed, ownership retained.
            assert_eq!(finish(run_model(&mut m, r, false)), Ok(()));
            let expected: Vec<_> = steps.iter().map(|&s| (r.pipe, s)).collect();
            assert_eq!(m.writes, expected, "replayed a completed teardown step");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-teardown",
    navi48_teardown_resumes_preflight_rejections_without_replaying_successes
);

fn navi48_teardown_cancellation_preserves_progress_and_native_quarantine() -> TestResult {
    for (protocol, steps) in cases() {
        for &step in steps {
            for after_write in [false, true] {
                let r = request(protocol);
                let mut m = Model::new();
                m.pending = Some((step, after_write));
                // SAFETY: model-only; dropping an unfinished operation retains it.
                cancel(run_model(&mut m, r, false));
                assert_eq!(m.progress.status(r.pipe).unwrap().next, step);
                assert!(m.progress.status(r.pipe).unwrap().in_flight);
                assert!(!m.retired[usize::from(r.pipe)]);
                let before = m.writes.clone();
                let attempts = m.attempts.len();
                m.pending = None;
                // The orchestrator cannot know whether an interrupted compound
                // phase wrote. Refuse replay before consulting the native owner.
                let result = finish(run_model(&mut m, r, false));
                assert_eq!(result, Err(otg::Error::Busy.into()));
                assert_eq!(m.attempts.len(), attempts);
                assert_eq!(m.writes, before);
                assert_eq!(m.progress.check_idle(), Err(otg::Error::Busy.into()));
                assert_eq!(m.progress.rearm(r.pipe), Err(otg::Error::Busy.into()));
            }
            // A returned failure clears the orchestration in-flight bit, but
            // does not reset or bypass the native owner's own quarantine.
            let r = request(protocol);
            let mut m = Model::new();
            m.failed = Some(step);
            assert_eq!(
                finish(run_model(&mut m, r, false)),
                Err(otg::Error::Readback(0).into())
            );
            assert!(!m.progress.status(r.pipe).unwrap().in_flight);
            assert_eq!(m.progress.status(r.pipe).unwrap().next, step);
            let before = m.writes.clone();
            m.failed = None;
            assert_eq!(
                finish(run_model(&mut m, r, false)),
                Err(otg::Error::Busy.into())
            );
            assert_eq!(m.writes, before);
            assert!(!m.retired[usize::from(r.pipe)]);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-teardown",
    navi48_teardown_cancellation_preserves_progress_and_native_quarantine
);

fn navi48_teardown_resumes_after_cancelled_cpu_drain() -> TestResult {
    use crate::scanout_access;
    let r = request(Protocol::Sst);
    let mut m = Model::new();
    // SAFETY: the value contains no pointer and replacement uses the barrier.
    let view = unsafe { scanout_access::snapshot(|| ()) };
    scanout_access::replace(|| {});
    m.progress.begin(r, false).unwrap();
    // Single polls do not yield this CPU or suspend the live view's owner.
    cancel(async {
        scanout_access::wait_retired().await;
        run_model(&mut m, r, false).await
    });
    assert!(!m.progress.status(r.pipe).unwrap().in_flight);
    assert!(m.attempts.is_empty());
    assert!(m.writes.is_empty());
    assert!(!m.retired[usize::from(r.pipe)]);
    drop(view);
    assert_eq!(
        finish(async {
            scanout_access::wait_retired().await;
            run_model(&mut m, r, false).await
        }),
        Ok(())
    );
    assert!(m.retired[usize::from(r.pipe)]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-teardown",
    navi48_teardown_resumes_after_cancelled_cpu_drain
);

fn navi48_teardown_keeps_identity_siblings_and_unplug_intent() -> TestResult {
    let r = request(Protocol::Mst);
    let mut m = Model::new();
    // Record intent before a potentially cancelled CPU withdrawal.
    m.progress.begin(r, false).unwrap();
    assert!(m.writes.is_empty());
    assert_eq!(m.progress.check_idle(), Err(otg::Error::Busy.into()));
    m.blocked = Some(TeardownStep::Link);
    // SAFETY: model-only operations.
    assert!(finish(run_model(&mut m, r, false)).is_err());
    let before = m.attempts.len();
    for other in [
        Request { port: 2, ..r },
        Request {
            protocol: Protocol::Sst,
            ..r
        },
        Request {
            scanout: Some(ScanoutWitness {
                address: r.scanout.unwrap().address + 4096,
                ..r.scanout.unwrap()
            }),
            ..r
        },
        Request {
            scanout: Some(ScanoutWitness {
                frames: (9, 10),
                ..r.scanout.unwrap()
            }),
            ..r
        },
        Request {
            scanout: Some(ScanoutWitness {
                stream: 3,
                ..r.scanout.unwrap()
            }),
            ..r
        },
        Request {
            audio: !r.audio,
            ..r
        },
        Request { scdc: true, ..r },
        Request { dsc: true, ..r },
    ] {
        // SAFETY: mismatched logical requests must not reach even the model.
        assert_eq!(
            finish(run_model(&mut m, other, false)),
            Err(otg::Error::Busy.into())
        );
    }
    assert_eq!(m.attempts.len(), before);
    // SAFETY: physical removal upgrades the retained teardown monotonically.
    assert!(finish(run_model(&mut m, r, true)).is_err());
    let saved = m.progress.status(r.pipe);
    let sibling = Request {
        pipe: 2,
        ..request(Protocol::Uhbr)
    };
    m.progress.begin(sibling, false).unwrap();
    assert_eq!(m.progress.status(r.pipe), saved);
    assert_eq!(m.progress.rearm(r.pipe), Err(otg::Error::Busy.into()));
    m.blocked = None;
    // SAFETY: model-only; normal stop may not downgrade prior physical removal.
    assert_eq!(finish(run_model(&mut m, r, false)), Ok(()));
    assert!(m.attempts.iter().skip(before).all(|a| a.2));
    assert_eq!(
        m.progress.status(sibling.pipe).unwrap().next,
        TeardownStep::Audio
    );
    // SAFETY: invalid pipe rejected before indexing or native operations.
    assert_eq!(
        finish(run_model(&mut m, Request { pipe: 4, ..r }, false)),
        Err(otg::Error::Invalid.into())
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-teardown",
    navi48_teardown_keeps_identity_siblings_and_unplug_intent
);

fn abort_model(m: &mut Model, pipe: u8) -> impl Future<Output = Result<(), ModesetError>> + '_ {
    // SAFETY: this backend owns only bookkeeping and no hardware or CPU views.
    unsafe { abort(m, pipe) }
}

fn activation(protocol: Protocol) -> Request {
    Request {
        scanout: None,
        ..request(protocol)
    }
}

fn abort_steps(r: Request) -> Vec<TeardownStep> {
    use TeardownStep::*;
    if r.dsc {
        alloc::vec![Timing, DscClock, Planes, Release]
    } else {
        alloc::vec![Timing, Planes, Release]
    }
}

fn navi48_activation_completion_and_cancellation_preserve_ownership() -> TestResult {
    for (protocol, _) in cases() {
        let r = activation(protocol);
        let mut m = Model::new();
        cancel(async {
            m.progress.start_activation(r).unwrap();
            core::future::pending::<()>().await;
            m.progress.finish_activation(r.pipe, true);
        });
        let status = m.progress.status(r.pipe).unwrap();
        assert!(status.activation && status.in_flight);
        assert_eq!(status.next, TeardownStep::Timing);
        assert_eq!(
            finish(abort_model(&mut m, r.pipe)),
            Err(otg::Error::Busy.into())
        );
        assert!(m.attempts.is_empty());
        assert!(!m.released[usize::from(r.pipe)]);
        assert_eq!(m.progress.check_idle(), Err(otg::Error::Busy.into()));
        assert_eq!(m.progress.start_activation(r), Err(otg::Error::Busy.into()));
        assert_eq!(
            finish(run_model(&mut m, request(protocol), false)),
            Err(otg::Error::Busy.into())
        );

        let mut m = Model::new();
        m.progress.start_activation(r).unwrap();
        m.progress.finish_activation(r.pipe, true);
        assert_eq!(m.progress.status(r.pipe), None);
        assert_eq!(m.progress.check_idle(), Ok(()));
        // A successful Modeset has its normal teardown, never the unlit abort.
        m.progress.begin(request(protocol), false).unwrap();
        assert_eq!(
            finish(abort_model(&mut m, r.pipe)),
            Err(otg::Error::Invalid.into())
        );
        assert!(m.attempts.is_empty());
        assert_eq!(finish(run_model(&mut m, request(protocol), false)), Ok(()));
        assert!(!m.released[usize::from(r.pipe)]);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-teardown",
    navi48_activation_completion_and_cancellation_preserve_ownership
);

fn navi48_activation_abort_resumes_without_replaying_or_touching_siblings() -> TestResult {
    for (protocol, _) in cases() {
        let r = activation(protocol);
        let steps = abort_steps(r);
        for (index, &step) in steps.iter().enumerate() {
            let mut m = Model::new();
            m.progress.start_activation(r).unwrap();
            m.progress.finish_activation(r.pipe, false);
            let sibling = Request {
                pipe: 2,
                ..request(Protocol::Sst)
            };
            m.progress.begin(sibling, false).unwrap();
            let saved = m.progress.status(sibling.pipe);
            m.blocked = Some(step);
            assert_eq!(
                finish(abort_model(&mut m, r.pipe)),
                Err(otg::Error::Busy.into())
            );
            assert_eq!(m.writes.len(), index);
            let status = m.progress.status(r.pipe).unwrap();
            assert!(status.activation && !status.in_flight);
            assert_eq!(status.next, step);
            assert!(!m.released[usize::from(r.pipe)]);
            m.blocked = None;
            assert_eq!(finish(abort_model(&mut m, r.pipe)), Ok(()));
            assert!(m.released[usize::from(r.pipe)]);
            assert!(!m.released[usize::from(sibling.pipe)]);
            assert_eq!(m.progress.status(r.pipe), None);
            assert_eq!(m.progress.status(sibling.pipe), saved);
            let expected: Vec<_> = steps.iter().map(|&s| (r.pipe, s)).collect();
            assert_eq!(m.writes, expected);
            // A second abort has no retained activation to operate on.
            assert_eq!(
                finish(abort_model(&mut m, r.pipe)),
                Err(otg::Error::Invalid.into())
            );
            assert_eq!(m.writes, expected);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-teardown",
    navi48_activation_abort_resumes_without_replaying_or_touching_siblings
);

fn navi48_activation_abort_quarantines_cancelled_and_failed_native_steps() -> TestResult {
    for (protocol, _) in cases() {
        let r = activation(protocol);
        for step in abort_steps(r) {
            for after_write in [false, true] {
                let mut m = Model::new();
                m.progress.start_activation(r).unwrap();
                m.progress.finish_activation(r.pipe, false);
                m.pending = Some((step, after_write));
                cancel(abort_model(&mut m, r.pipe));
                let attempts = m.attempts.len();
                let writes = m.writes.clone();
                m.pending = None;
                assert_eq!(
                    finish(abort_model(&mut m, r.pipe)),
                    Err(otg::Error::Busy.into())
                );
                assert_eq!(m.attempts.len(), attempts);
                assert_eq!(m.writes, writes);
                assert!(m.progress.status(r.pipe).unwrap().in_flight);
                assert!(!m.released[usize::from(r.pipe)]);
            }
            let mut m = Model::new();
            m.progress.start_activation(r).unwrap();
            m.progress.finish_activation(r.pipe, false);
            m.failed = Some(step);
            assert_eq!(
                finish(abort_model(&mut m, r.pipe)),
                Err(otg::Error::Readback(0).into())
            );
            let writes = m.writes.clone();
            m.failed = None;
            assert_eq!(
                finish(abort_model(&mut m, r.pipe)),
                Err(otg::Error::Busy.into())
            );
            assert_eq!(m.writes, writes);
            assert!(!m.released[usize::from(r.pipe)]);
            assert!(!m.progress.status(r.pipe).unwrap().in_flight);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-teardown",
    navi48_activation_abort_quarantines_cancelled_and_failed_native_steps
);

fn activation_checkpoints() -> [(Protocol, &'static [TeardownStep]); 5] {
    use TeardownStep::*;
    [
        (Protocol::Tmds, &[PreLinkScdc, Scdc, Video, Scanout]),
        (Protocol::Sst, &[Link, Frontend, Video, Scanout]),
        (Protocol::Uhbr, &[Link, Video, Scanout]),
        (Protocol::Frl, &[Scdc, Video, Scanout]),
        (Protocol::Mst, &[Link, Frontend, Payload, Video, Scanout]),
    ]
}

fn navi48_partial_activation_unwinds_only_completed_phases_and_releases() -> TestResult {
    for (protocol, checkpoints) in activation_checkpoints() {
        for (index, &next) in checkpoints.iter().enumerate() {
            let r = activation(protocol);
            let normal = cases().into_iter().find(|c| c.0 == protocol).unwrap().1;
            let mut steps = if next == TeardownStep::PreLinkScdc {
                // Sink configuration does not prove a native link exists:
                // restore the sink, then retire staging without a link stop.
                alloc::vec![
                    TeardownStep::PreLinkScdc,
                    TeardownStep::Timing,
                    TeardownStep::Planes,
                ]
            } else {
                let start = normal.iter().position(|&s| s == next).unwrap();
                normal[start..].to_vec()
            };
            steps.push(TeardownStep::Release);
            // Every cleanup boundary can reject before writing and resume.
            for (blocked_at, &blocked) in steps.iter().enumerate() {
                let mut m = Model::new();
                m.progress.start_activation(r).unwrap();
                for &step in &checkpoints[..=index] {
                    m.progress.checkpoint_activation(r.pipe, step);
                }
                let saved = m.progress.0[usize::from(r.pipe)].unwrap();
                assert!(saved.status.activation && saved.status.in_flight);
                assert_eq!(saved.status.next, next);
                assert!(
                    saved.request.scanout.is_none(),
                    "invented a Modeset witness"
                );
                m.progress.finish_activation(r.pipe, false);
                let sibling = Request {
                    pipe: 2,
                    ..request(Protocol::Mst)
                };
                m.progress.begin(sibling, false).unwrap();
                let sibling_before = m.progress.status(2);
                m.blocked = Some(blocked);
                assert_eq!(
                    finish(abort_model(&mut m, r.pipe)),
                    Err(otg::Error::Busy.into())
                );
                assert_eq!(m.writes.len(), blocked_at);
                assert!(!m.released[usize::from(r.pipe)]);
                m.blocked = None;
                assert_eq!(finish(abort_model(&mut m, r.pipe)), Ok(()));
                let expected: Vec<_> = steps.iter().map(|&s| (r.pipe, s)).collect();
                assert_eq!(m.writes, expected);
                assert!(m.released[usize::from(r.pipe)]);
                assert_eq!(m.progress.status(r.pipe), None);
                assert_eq!(m.progress.status(2), sibling_before);
                assert!(!m.released[2]);
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-teardown",
    navi48_partial_activation_unwinds_only_completed_phases_and_releases
);

fn navi48_partial_activation_checkpoints_never_override_uncertain_completion() -> TestResult {
    for (protocol, checkpoints) in activation_checkpoints() {
        for &next in checkpoints {
            let r = activation(protocol);
            let mut m = Model::new();
            cancel(async {
                m.progress.start_activation(r).unwrap();
                m.progress.checkpoint_activation(r.pipe, next);
                // Dropped during the following startup phase, before return.
                core::future::pending::<()>().await;
                m.progress.finish_activation(r.pipe, false);
            });
            assert_eq!(
                finish(abort_model(&mut m, r.pipe)),
                Err(otg::Error::Busy.into())
            );
            assert!(m.attempts.is_empty());
            assert!(m.progress.status(r.pipe).unwrap().in_flight);
            assert_eq!(m.progress.check_idle(), Err(otg::Error::Busy.into()));

            let mut m = Model::new();
            m.progress.start_activation(r).unwrap();
            m.progress.checkpoint_activation(r.pipe, next);
            m.progress.finish_activation(r.pipe, false);
            // A returned failure after writes keeps native quarantine binding.
            m.poisoned = true;
            assert_eq!(
                finish(abort_model(&mut m, r.pipe)),
                Err(otg::Error::Busy.into())
            );
            assert!(m.writes.is_empty());
            assert!(!m.released[usize::from(r.pipe)]);
            assert_eq!(m.progress.status(r.pipe).unwrap().next, next);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-teardown",
    navi48_partial_activation_checkpoints_never_override_uncertain_completion
);

fn navi48_activation_checkpoints_do_not_create_or_replace_published_teardowns() -> TestResult {
    let mut m = Model::new();
    for (protocol, checkpoints) in activation_checkpoints() {
        let r = request(protocol);
        for &step in checkpoints {
            // start_link is also used by retraining a published Modeset.
            m.progress.checkpoint_activation(r.pipe, step);
            assert_eq!(m.progress.status(r.pipe), None);
        }
        m.progress.begin(r, true).unwrap();
        let before = m.progress.status(r.pipe);
        for &step in checkpoints {
            m.progress.checkpoint_activation(r.pipe, step);
            assert_eq!(m.progress.status(r.pipe), before);
        }
        assert_eq!(finish(run_model(&mut m, r, false)), Ok(()));
        let before = m.progress.status(r.pipe);
        m.progress.checkpoint_activation(r.pipe, TeardownStep::Link);
        assert_eq!(m.progress.status(r.pipe), before);
        m.progress.rearm(r.pipe).unwrap();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-teardown",
    navi48_activation_checkpoints_do_not_create_or_replace_published_teardowns
);

/// A link-loss retrain journals the published modeset in flight. Success
/// forgets it; a refused retrain whose link stopped again resumes ordinary
/// teardown at timing, never replaying the stream/link stops it performed.
/// Until finished (a dropped or uncertain retrain) teardown refuses to run.
fn navi48_retrain_journal_hands_refused_links_to_teardown() -> TestResult {
    use TeardownStep::*;
    for (protocol, tail) in [
        (Protocol::Sst, &[Timing, DscClock, Planes][..]),
        (Protocol::Uhbr, &[Timing, Planes][..]),
    ] {
        let r = request(protocol);
        let mut m = Model::new();
        m.progress.start_activation(r).unwrap();
        assert!(m.progress.check_idle().is_err());
        assert_eq!(
            finish(run_model(&mut m, r, false)),
            Err(otg::Error::Busy.into())
        );
        assert!(m.attempts.is_empty());
        m.progress.finish_retrain(r.pipe, None);
        assert!(m.progress.status(r.pipe).is_none());
        assert!(m.progress.check_idle().is_ok());

        let mut m = Model::new();
        m.progress.start_activation(r).unwrap();
        m.progress.finish_retrain(r.pipe, Some(Timing));
        let s = m.progress.status(r.pipe).unwrap();
        assert!(!s.in_flight && !s.activation && s.next == Timing);
        // Another incarnation cannot take the slot meanwhile.
        let mut other = r;
        other.scanout.as_mut().unwrap().address += 0x1000;
        assert!(m.progress.start_activation(other).is_err());
        finish(run_model(&mut m, r, false)).unwrap();
        let writes: Vec<_> = m.writes.iter().map(|w| w.1).collect();
        assert_eq!(writes, tail);
        assert_eq!(m.progress.status(r.pipe).unwrap().next, Complete);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-teardown",
    navi48_retrain_journal_hands_refused_links_to_teardown
);

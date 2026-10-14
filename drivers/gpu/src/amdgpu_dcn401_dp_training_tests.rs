use super::super::super::dp_phy::training::Transport;
use super::*;
use crate::dp_link_training::TrainingPattern;
use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicU32, AtomicU64};
#[path = "amdgpu_dcn401_dp_frontend_tests.rs"]
mod frontend;
#[path = "amdgpu_dcn401_dp_link_status_tests.rs"]
mod link_status;
#[path = "amdgpu_dcn401_uhbr_link_tests.rs"]
mod uhbr;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    Aux(u8, u32, Vec<u8>),
    Drive(DpDriveSettings),
    Delay(u64),
}
struct LinkIo {
    inner: PhyIo,
    source: Arc<AtomicU32>,
    change: Arc<AtomicU64>,
}
impl Io for LinkIo {
    fn read(&mut self, at: u64) -> u32 {
        let change = self.change.swap(0, Ordering::SeqCst);
        if change != 0 {
            self.inner.inner.regs.insert(change >> 32, change as u32);
        }
        self.inner.read(at)
    }
    fn write(&mut self, at: u64, value: u32) {
        self.inner.write(at, value);
        let p = self.inner.phy;
        let pattern = self
            .inner
            .inner
            .regs
            .get(&dio(p, 0x212e))
            .copied()
            .unwrap_or(0)
            & 3;
        let complete = self
            .inner
            .inner
            .regs
            .get(&dio(p, 0x211e))
            .copied()
            .unwrap_or(0)
            & 0x10;
        self.source.store(pattern | complete, Ordering::SeqCst);
    }
}
struct Link {
    fw: Firmware,
    path: inventory::Path,
    settings: DpPhySettings,
    bytes: BTreeMap<u32, u8>,
    status: VecDeque<[u8; 6]>,
    events: Vec<Event>,
    source: Arc<AtomicU32>,
    change: Arc<AtomicU64>,
    change_at: Option<(usize, u64, u32)>,
    sink_change: Option<(usize, u32, u8)>,
    pending: Option<usize>,
    fail: Option<(usize, dmub::Error)>,
    revoke: Option<(usize, Cap<BusDeviceCap, Write>)>,
    defer: u8,
    ignore: Option<u32>,
    /// The sink departed: the PHY may stop without its D3.
    unplugged: bool,
    step: usize,
    progress: Arc<AtomicU32>,
}
impl Link {
    async fn step(&mut self) -> Result<(), dmub::Error> {
        self.step += 1;
        self.progress.store(self.step as u32, Ordering::SeqCst);
        if let Some((n, at, value)) = self.sink_change {
            if self.step == n {
                self.bytes.insert(at, value);
            }
        }
        if let Some((n, at, value)) = self.change_at {
            if self.step == n {
                self.change
                    .store(at << 32 | u64::from(value), Ordering::SeqCst);
            }
        }
        if let Some((n, cap)) = self.revoke {
            if self.step == n {
                cap.revoke();
            }
        }
        if self.pending == Some(self.step) {
            core::future::pending::<()>().await;
        }
        if let Some((n, e)) = self.fail {
            if self.step == n {
                return Err(e);
            }
        }
        Ok(())
    }
    fn set(&mut self, at: u32, data: &[u8]) {
        for (i, b) in data.iter().enumerate() {
            self.bytes.insert(at + i as u32, *b);
        }
    }
}
impl super::super::super::dp_phy::Firmware for Link {
    fn ready(&self) -> bool {
        self.fw.ready
    }
    async fn enable(
        &mut self,
        path: inventory::Path,
        settings: DpPhySettings,
    ) -> Result<(), dmub::Error> {
        self.fw.command(path, Some(settings)).await
    }
    async fn disable(&mut self, path: inventory::Path) -> Result<(), dmub::Error> {
        // Sink D3 before native transmitter disable, unless the sink left.
        assert!(self.unplugged || self.bytes[&0x600] == 2);
        self.fw.command(path, None).await
    }
}
impl Transport for Link {
    async fn aux(
        &mut self,
        instance: u8,
        action: u8,
        address: u32,
        data: &mut [u8],
    ) -> Result<(), dmub::Error> {
        assert_eq!(Some(instance), self.path.aux); // AUX is not the PHY or HPD index
        self.events.push(Event::Aux(action, address, data.to_vec()));
        self.step().await?;
        if self.defer != 0 {
            self.defer -= 1;
            return Err(dmub::Error::Aux(2));
        }
        match action {
            0x80 => {
                if address == 0x102 && data[0] != 0 {
                    assert_eq!(data.len(), usize::from(self.settings.lanes) + 1);
                    let pattern = data[0] & 7;
                    assert_eq!(
                        self.source.load(Ordering::SeqCst),
                        if pattern == 7 {
                            3
                        } else {
                            u32::from(pattern - 1)
                        }
                    );
                    assert_eq!(data[0] & 0x20 != 0, pattern != 7);
                }
                if self.ignore != Some(address) {
                    self.set(address, data);
                }
            }
            0x90 => {
                for (i, b) in data.iter_mut().enumerate() {
                    *b = self.bytes.get(&(address + i as u32)).copied().unwrap_or(0);
                }
                if address == 0x202 {
                    let status = self.status.pop_front().unwrap_or([0x77, 0x77, 1, 0, 0, 0]);
                    data.copy_from_slice(&status);
                    if self.bytes[&0x102] == 0 {
                        assert_eq!(self.source.load(Ordering::SeqCst) & 0x10, 0x10);
                    }
                }
            }
            _ => panic!("unexpected AUX action"),
        }
        Ok(())
    }
    async fn drive(
        &mut self,
        path: inventory::Path,
        settings: DpPhySettings,
        drive: DpDriveSettings,
    ) -> Result<(), dmub::Error> {
        assert_eq!(path, self.path);
        assert_eq!(settings, self.settings);
        assert!(drive.swing + drive.pre_emphasis <= 3);
        assert_eq!(self.source.load(Ordering::SeqCst) & 0x10, 0);
        self.events.push(Event::Drive(drive));
        self.step().await
    }
    async fn delay(&mut self, us: u64) {
        self.events.push(Event::Delay(us));
        // Delay cannot return an I/O error; tests inject cancellation here.
        self.step().await.unwrap();
    }
}
fn fixture(p: u8, lanes: u8, rate: LinkRate, pattern: TrainingPattern) -> (Engine<LinkIo>, Link) {
    let (mut e, mut f) = super::fixture(
        p,
        if lanes == 1 {
            8
        } else if lanes == 2 {
            10
        } else {
            15
        },
    );
    let settings = DpPhySettings { lanes, rate };
    run(e.enable_dp_phy(&mut f, path(p), settings)).unwrap();
    let source = Arc::new(AtomicU32::new(0));
    let change = Arc::new(AtomicU64::new(0));
    let mut link = Link {
        fw: f,
        path: path(p),
        settings,
        bytes: BTreeMap::new(),
        status: VecDeque::from([[0x11, 0x11, 0, 0, 0, 0]]),
        events: Vec::new(),
        source: source.clone(),
        change: change.clone(),
        change_at: None,
        sink_change: None,
        pending: None,
        fail: None,
        revoke: None,
        defer: 0,
        ignore: None,
        unplugged: false,
        step: 0,
        progress: Arc::new(AtomicU32::new(0)),
    };
    link.set(
        0,
        &[
            0x14,
            0x1e,
            0x84 | if pattern == TrainingPattern::Tps3 {
                0x40
            } else {
                0
            },
            1 | if pattern == TrainingPattern::Tps4 {
                0x80
            } else {
                0
            },
            0,
            0,
            1,
        ],
    );
    link.set(0x600, &[2]);
    (
        Engine {
            io: LinkIo {
                inner: e.io,
                source,
                change,
            },
            authority: e.authority,
            layout: e.layout,
            status: e.status,
            displays: e.displays,
        },
        link,
    )
}
fn dcn401_dp_training_handles_native_patterns_phys_rates_lanes_and_sink_shutdown() -> TestResult {
    for p in 0..4 {
        for lanes in [1, 2, 4] {
            for (rate, pattern) in [
                (LinkRate::Rbr, TrainingPattern::Tps2),
                (LinkRate::Hbr, TrainingPattern::Tps2),
                (LinkRate::Hbr2, TrainingPattern::Tps3),
                (LinkRate::Hbr3, TrainingPattern::Tps4),
            ] {
                let (mut e, mut io) = fixture(p, lanes, rate, pattern);
                let trained = run(e.train_dp_link(&mut io, path(p), true, false)).unwrap();
                assert_eq!(e.status.state, State::DpLinkTrained(p));
                assert_eq!(trained.equalization, pattern);
                assert_eq!((trained.cr_attempts, trained.eq_attempts), (1, 1));
                assert_eq!(trained.drive, DpDriveSettings::default());
                assert!(!e.status.state.reusable());
                assert_eq!(io.bytes[&0x600], 1);
                assert_eq!(io.bytes[&0x100], rate as u8);
                assert_eq!(io.bytes[&0x101], lanes | 0x80); // never grant post-LT adjustment
                assert_eq!(io.bytes[&0x102], 0);
                assert_eq!(io.bytes[&0x107], 0x10);
                assert_eq!(io.bytes[&0x108], 1);
                assert_eq!(
                    e.io.inner.inner.regs[&dio(p, 0x2129)] & 0x1103ffff,
                    0x10002000
                );
                assert_eq!(e.io.inner.inner.regs[&dio(p, 0x2134)] & 0x3ff00, 0x1ff00);
                assert!(io.events.contains(&Event::Delay(1000)));
                assert!(io.events.contains(&Event::Delay(100)));
                assert!(io.events.contains(&Event::Delay(400)));
                assert!(io.events.contains(&Event::Delay(5000)));
                assert_eq!(
                    run(e.train_dp_link(&mut io, path(p), true, false)),
                    Err(Error::Busy)
                );
                assert_eq!(run(e.disable_dp_phy(&mut io, path(p))), Err(Error::Busy));
                run(e.stop_dp_link(&mut io, path(p))).unwrap();
                assert_eq!(e.status.state, State::DpPhyDisabled);
                assert_eq!(e.status.dp_link_trained, Some(trained)); // history only
                assert_eq!(io.bytes[&0x600], 2);
                assert_eq!(e.io.inner.inner.regs[&dio(p, 0x211e)] & 0x10, 0);
                assert_eq!(e.io.inner.inner.regs[&dio(p, 0x212e)] & 3, 0);
                assert_eq!(run(e.stop_dp_link(&mut io, path(p))), Err(Error::Busy));
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_training_handles_native_patterns_phys_rates_lanes_and_sink_shutdown
);

fn dcn401_dp_training_uses_maximum_requested_drive_with_native_clamping_and_limits() -> TestResult {
    let (mut e, mut io) = fixture(2, 4, LinkRate::Hbr2, TrainingPattern::Tps3);
    io.status = VecDeque::from([
        [0, 0, 0, 0, 0x81, 0x42], // maximum VS=2, PE=2 -> clamp PE=1
        [0x11, 0x11, 0, 0, 0, 0],
        [0x11, 0x11, 0, 0, 0xcc, 0xcc], // VS=0 PE=3 -> MAX_PRE flag
        [0x77, 0x77, 1, 0, 0, 0],
    ]);
    let trained = run(e.train_dp_link(&mut io, path(2), false, false)).unwrap();
    let drives: Vec<_> = io
        .events
        .iter()
        .filter_map(|event| {
            if let Event::Drive(d) = event {
                Some(*d)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        drives,
        vec![
            DpDriveSettings::default(),
            DpDriveSettings {
                swing: 2,
                pre_emphasis: 1
            },
            DpDriveSettings {
                swing: 2,
                pre_emphasis: 1
            },
            DpDriveSettings {
                swing: 0,
                pre_emphasis: 3
            }
        ]
    );
    assert_eq!((trained.cr_attempts, trained.eq_attempts), (2, 2));
    assert!(io.events.contains(&Event::Aux(0x80, 0x103, vec![10; 4])));
    assert!(io.events.contains(&Event::Aux(0x80, 0x103, vec![0x38; 4])));
    assert_eq!(io.bytes[&0x107], 0);
    let (mut e, mut io) = fixture(0, 1, LinkRate::Rbr, TrainingPattern::Tps2);
    io.status = VecDeque::from([[0, 0, 0, 0, 3, 0], [1, 0, 0, 0, 0, 0]]);
    run(e.train_dp_link(&mut io, path(0), false, false)).unwrap();
    assert!(io.events.contains(&Event::Aux(0x80, 0x103, vec![7]))); // MAX_SWING, no PE
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_training_uses_maximum_requested_drive_with_native_clamping_and_limits
);

fn dcn401_dp_training_honors_extended_caps_intervals_and_defer_limits() -> TestResult {
    for interval in 0..=6 {
        let (mut e, mut io) = fixture(1, 2, LinkRate::Hbr2, TrainingPattern::Tps2);
        io.set(14, &[0x80 | interval]);
        io.set(0x2200, &[0x14, 0x14, 0xc2, 1, 0, 0, 1]);
        io.defer = 2;
        let result = run(e.train_dp_link(&mut io, path(1), false, false)).unwrap();
        assert_eq!(result.equalization, TrainingPattern::Tps3);
        assert!(io.events.contains(&Event::Delay(if interval == 0 {
            400
        } else {
            u64::from(interval) * 4000
        })));
        assert!(io.events.contains(&Event::Delay(
            [400, 4000, 8000, 12000, 16000, 32000, 64000][usize::from(interval)]
        )));
    }
    let (mut e, mut io) = fixture(1, 2, LinkRate::Hbr2, TrainingPattern::Tps3);
    io.defer = 7;
    assert_eq!(
        run(e.train_dp_link(&mut io, path(1), false, false)),
        Err(Error::Firmware(dmub::Error::Aux(2)))
    );
    assert_eq!(
        io.events
            .iter()
            .filter(|e| matches!(e, Event::Aux(..)))
            .count(),
        7
    );
    assert!(matches!(e.status.state, State::Failed(_)));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_training_honors_extended_caps_intervals_and_defer_limits
);

fn dcn401_dp_training_rejects_unsupported_topologies_caps_and_unacknowledged_sink_config(
) -> TestResult {
    for (address, bytes) in [
        (0, vec![0x10]),
        (1, vec![0xff]),
        (1, vec![6]),
        (2, vec![0xc3]),
        (2, vec![0x42]),
        (2, vec![0xc1]),
        (3, vec![0]),
        (5, vec![1]),
        (6, vec![0]),
        (14, vec![7]),
        (0x111, vec![1]),
    ] {
        let (mut e, mut io) = fixture(1, 2, LinkRate::Hbr2, TrainingPattern::Tps3);
        io.set(address, &bytes);
        let writes = e.io.inner.inner.writes.len();
        assert!(
            run(e.train_dp_link(&mut io, path(1), true, false)).is_err(),
            "{address:x}"
        );
        assert_eq!(e.io.inner.inner.writes.len(), writes);
        assert!(!io.events.iter().any(|e| matches!(e, Event::Drive(_))));
    }
    let (mut e, mut io) = fixture(0, 4, LinkRate::Hbr3, TrainingPattern::Tps3);
    assert_eq!(
        run(e.train_dp_link(&mut io, path(0), false, false)),
        Err(Error::Unsupported)
    );
    // A sink's FEC configuration ignored: training sets it FEC-ready.
    let (mut e, mut io) = fixture(0, 4, LinkRate::Hbr3, TrainingPattern::Tps4);
    io.set(0x90, &[1]);
    io.ignore = Some(0x120);
    assert_eq!(
        run(e.train_dp_link(&mut io, path(0), false, false)),
        Err(Error::DpTraining(DpTrainingError::SinkReadback(0x120)))
    );
    for address in [0x600, 0x100, 0x101, 0x102, 0x107, 0x108] {
        let (mut e, mut io) = fixture(0, 2, LinkRate::Hbr2, TrainingPattern::Tps3);
        io.ignore = Some(address);
        io.set(address, &[0xff]);
        assert!(matches!(
            run(e.train_dp_link(&mut io, path(0), true, false)),
            Err(Error::DpTraining(DpTrainingError::SinkReadback(_)))
        ));
        assert!(!io.events.iter().any(|e| matches!(e, Event::Drive(_))));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_training_rejects_unsupported_topologies_caps_and_unacknowledged_sink_config
);

fn dcn401_dp_training_bounds_cr_eq_and_detects_link_loss_after_idle() -> TestResult {
    for (statuses, error, rounds) in [
        (vec![[0; 6]; 5], DpTrainingError::ClockRecovery, 5),
        (
            vec![[0, 0, 0, 0, 3, 0], [0; 6]],
            DpTrainingError::ClockRecovery,
            2,
        ),
        (
            {
                let mut v = vec![[0x11, 0x11, 0, 0, 0, 0]; 7];
                v[0][2] = 1;
                v
            },
            DpTrainingError::Equalization,
            7,
        ),
        (
            vec![[0x11, 0x11, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0]],
            DpTrainingError::LinkLost,
            2,
        ),
        (
            vec![
                [0x11, 0x11, 0, 0, 0, 0],
                [0x77, 0x77, 1, 0, 0, 0],
                [0x77, 0x77, 0, 0, 0, 0],
            ],
            DpTrainingError::LinkLost,
            2,
        ),
        (
            (0..100)
                .map(|n| [0, 0, 0, 0, if n % 2 == 0 { 1 } else { 0 }, 0])
                .collect(),
            DpTrainingError::ClockRecovery,
            100,
        ),
    ] {
        let (mut e, mut io) = fixture(3, 1, LinkRate::Hbr, TrainingPattern::Tps2);
        io.status = statuses.into();
        assert_eq!(
            run(e.train_dp_link(&mut io, path(3), false, false)),
            Err(Error::DpTraining(error))
        );
        assert_eq!(
            io.events
                .iter()
                .filter(|e| matches!(e, Event::Drive(_)))
                .count(),
            rounds
        );
        // Confirmed training failures exit to idle; the refused link is
        // retained for stop_dp_link only (Linux disables before fallback).
        assert_eq!(io.bytes[&0x102], 0);
        assert_eq!(e.status.state, State::DpLinkRefused(3));
        assert!(e.status.dp_link_trained.is_some());
        assert_eq!(
            run(e.train_dp_link(&mut io, path(3), false, false)),
            Err(Error::Busy)
        );
        assert_eq!(e.status.state, State::DpLinkRefused(3));
        assert_eq!(run(e.stop_dp_link(&mut io, path(3))), Ok(()));
        assert_eq!(e.status.state, State::DpPhyDisabled);
        assert_eq!(io.bytes[&0x600], 2); // sink D3 before PHY disable
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_training_bounds_cr_eq_and_detects_link_loss_after_idle
);

fn dcn401_dp_training_cancellation_at_each_await_retains_ownership_and_blocks_replay() -> TestResult
{
    let (mut e, mut io) = fixture(1, 2, LinkRate::Hbr2, TrainingPattern::Tps3);
    run(e.train_dp_link(&mut io, path(1), false, false)).unwrap();
    let count = io.step;
    for step in 1..=count {
        let (mut e, mut io) = fixture(1, 2, LinkRate::Hbr2, TrainingPattern::Tps3);
        io.pending = Some(step);
        {
            let mut f = core::pin::pin!(e.train_dp_link(&mut io, path(1), false, false));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(e.status.state, State::TrainingDp(1));
        assert!(e.status.dp_link_trained.is_none());
        assert_eq!(
            run(e.train_dp_link(&mut io, path(1), false, false)),
            Err(Error::Busy)
        );
        assert_eq!(run(e.disable_dp_phy(&mut io, path(1))), Err(Error::Busy));
        assert_eq!(run(e.stop_dp_link(&mut io, path(1))), Err(Error::Busy));
        assert_eq!(io.step, step);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_training_cancellation_at_each_await_retains_ownership_and_blocks_replay
);

fn dcn401_dp_training_rejects_late_routes_revocation_and_transport_failures() -> TestResult {
    let (mut e, mut io) = fixture(2, 2, LinkRate::Hbr2, TrainingPattern::Tps3);
    run(e.train_dp_link(&mut io, path(2), false, false)).unwrap();
    let events = io.events;
    for (index, event) in events.iter().enumerate() {
        let step = index + 1;
        for revoked in [false, true] {
            if !revoked && matches!(event, Event::Delay(_)) {
                continue;
            }
            let (mut e, mut io) = fixture(2, 2, LinkRate::Hbr2, TrainingPattern::Tps3);
            if revoked {
                io.revoke = Some((step, e.authority));
            } else {
                io.fail = Some((step, dmub::Error::CommandTimeout));
            }
            assert_eq!(
                run(e.train_dp_link(&mut io, path(2), false, false)),
                Err(if revoked {
                    Error::Revoked
                } else {
                    Error::Firmware(dmub::Error::CommandTimeout)
                })
            );
            assert!(matches!(e.status.state, State::Failed(_)));
            assert!(e.status.dp_link_trained.is_none());
        }
    }
    for (at, value) in [
        (dio(2, 0x20bc), 0x100),
        (dio(0, 0x2141), 1),
        (phy(2, 0x2943), 0x03030303),
        (dio(2, 0x2134), 0),
        (dio(2, 0x212e), 3),
    ] {
        let (mut e, mut io) = fixture(2, 2, LinkRate::Hbr2, TrainingPattern::Tps3);
        io.change_at = Some((events.len(), at, value)); // after final sink read
        assert!(run(e.train_dp_link(&mut io, path(2), false, false)).is_err());
        assert!(matches!(e.status.state, State::Failed(_)));
        assert!(e.status.dp_link_trained.is_none());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_training_rejects_late_routes_revocation_and_transport_failures
);

fn dcn401_dp_training_shutdown_rejects_sink_failure_and_cancellation() -> TestResult {
    for cancel in [false, true] {
        let (mut e, mut io) = fixture(2, 2, LinkRate::Hbr2, TrainingPattern::Tps3);
        run(e.train_dp_link(&mut io, path(2), false, false)).unwrap();
        let commands = io.fw.commands.len();
        if cancel {
            io.pending = Some(io.step + 1);
        } else {
            io.fail = Some((io.step + 1, dmub::Error::Aux(1)));
        }
        if cancel {
            let mut f = core::pin::pin!(e.stop_dp_link(&mut io, path(2)));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        } else {
            assert_eq!(
                run(e.stop_dp_link(&mut io, path(2))),
                Err(Error::Firmware(dmub::Error::Aux(1)))
            );
        }
        assert!(!e.status.state.reusable());
        assert_eq!(io.fw.commands.len(), commands); // never disable PHY before sink ACK
        assert_eq!(run(e.stop_dp_link(&mut io, path(2))), Err(Error::Busy));
    }
    let (mut e, mut io) = fixture(2, 2, LinkRate::Hbr2, TrainingPattern::Tps3);
    run(e.train_dp_link(&mut io, path(2), false, false)).unwrap();
    io.fw.pending = true;
    {
        let mut f = core::pin::pin!(e.stop_dp_link(&mut io, path(2)));
        assert!(f
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    assert_eq!(e.status.state, State::StoppingDpLink(2));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_training_shutdown_rejects_sink_failure_and_cancellation
);

fn dcn401_dp_training_final_completion_requires_unchanged_sink_and_no_post_lt_work() -> TestResult {
    let (mut e, mut io) = fixture(1, 2, LinkRate::Hbr2, TrainingPattern::Tps3);
    run(e.train_dp_link(&mut io, path(1), false, false)).unwrap();
    let idle_delay = io
        .events
        .iter()
        .position(|e| *e == Event::Delay(5000))
        .unwrap()
        + 1;
    for (at, value) in [
        (0x100, 6),
        (0x101, 0x81),
        (0x102, 0x21),
        (0x107, 0x10),
        (0x108, 2),
        (0x600, 2),
    ] {
        let (mut e, mut io) = fixture(1, 2, LinkRate::Hbr2, TrainingPattern::Tps3);
        io.sink_change = Some((idle_delay, at, value));
        assert!(matches!(
            run(e.train_dp_link(&mut io, path(1), false, false)),
            Err(Error::DpTraining(DpTrainingError::SinkReadback(_)))
        ));
        assert!(e.status.dp_link_trained.is_none());
    }
    for status in [[0xff; 6], [0x77, 0x77, 3, 0, 0, 0]] {
        let (mut e, mut io) = fixture(1, 2, LinkRate::Hbr2, TrainingPattern::Tps3);
        io.status = VecDeque::from([[0x11, 0x11, 0, 0, 0, 0], [0x77, 0x77, 1, 0, 0, 0], status]);
        assert_eq!(
            run(e.train_dp_link(&mut io, path(1), false, false)),
            Err(Error::DpTraining(DpTrainingError::LinkLost))
        );
        // The finish's idle exit stands: refused, retained only for stop.
        assert_eq!(e.status.state, State::DpLinkRefused(1));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_training_final_completion_requires_unchanged_sink_and_no_post_lt_work
);

fn dcn401_dp_training_checks_source_writes_and_drive_handshake_completion() -> TestResult {
    let (mut e, mut io) = fixture(1, 2, LinkRate::Hbr2, TrainingPattern::Tps3);
    let first = e.io.inner.inner.writes.len();
    let mut registers = e.io.inner.inner.regs.clone();
    run(e.train_dp_link(&mut io, path(1), false, false)).unwrap();
    let writes = e.io.inner.inner.writes;
    for (index, &(at, value)) in writes.iter().enumerate().skip(first) {
        if registers.get(&at).copied().unwrap_or(0) != value {
            let (mut e, mut io) = fixture(1, 2, LinkRate::Hbr2, TrainingPattern::Tps3);
            e.io.inner.inner.reject = Some(index + 1);
            assert!(matches!(
                run(e.train_dp_link(&mut io, path(1), false, false)),
                Err(Error::Readback(_))
            ));
            assert!(matches!(e.status.state, State::Failed(_)));
            assert!(e.status.dp_link_trained.is_none());
        }
        registers.insert(at, value);
        for gone in [false, true] {
            let (mut e, mut io) = fixture(1, 2, LinkRate::Hbr2, TrainingPattern::Tps3);
            if gone {
                e.io.inner.inner.gone = Some(index + 1);
            } else {
                e.io.inner.inner.revoke = Some((index + 1, e.authority));
            }
            assert_eq!(
                run(e.train_dp_link(&mut io, path(1), false, false)),
                Err(if gone {
                    Error::DeviceGone
                } else {
                    Error::Revoked
                })
            );
            assert!(e.status.dp_link_trained.is_none());
        }
    }
    let drive_step = io
        .events
        .iter()
        .position(|e| matches!(e, Event::Drive(_)))
        .unwrap()
        + 1;
    let (mut e, mut io) = fixture(1, 2, LinkRate::Hbr2, TrainingPattern::Tps3);
    io.change_at = Some((drive_step, phy(1, 0x2943), 0x0c030c13)); // unused lane stuck REQ
    assert_eq!(
        run(e.train_dp_link(&mut io, path(1), false, false)),
        Err(Error::Timeout(phy(1, 0x2943)))
    );
    assert!(e.status.dp_link_trained.is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_training_checks_source_writes_and_drive_handshake_completion
);

/// The AUX engine's AUX_DPHY_RX_CONTROL1 timeout fields (length, multiplier).
fn aux_timeout(e: &Engine<LinkIo>, p: u8) -> (u32, u32) {
    let aux = u64::from(path(p).aux.unwrap());
    let v =
        e.io.inner
            .inner
            .regs
            .get(&(BASE + (0x16bd + 0x1c * aux) * 4))
            .copied()
            .unwrap_or(0);
    ((v >> 8) & 0x7f, (v >> 15) & 3)
}

fn dcn401_dp_training_uses_lttprs_like_linux_dcn401() -> TestResult {
    // No repeater: the default 552-us AUX timeout (69 x 8 us) after the probe.
    let (mut e, mut io) = fixture(1, 4, LinkRate::Hbr2, TrainingPattern::Tps3);
    run(e.train_dp_link(&mut io, path(1), true, false)).unwrap();
    if aux_timeout(&e, 1) != (69, 0) || io.bytes.contains_key(&0xf0003) {
        return TestResult::Fail("no LTTPR");
    }
    // One repeater, VBIOS without the non-transparent bit: transparent mode,
    // the 3.2-ms timeout (100 x 32 us), count echoed, no hop training.
    let (mut e, mut io) = fixture(1, 4, LinkRate::Hbr2, TrainingPattern::Tps3);
    io.set(0xf0000, &[0x14, 0x1e, 0x80, 0, 4]);
    run(e.train_dp_link(&mut io, path(1), true, false)).unwrap();
    if aux_timeout(&e, 1) != (100, 2)
        || io.bytes[&0xf0003] != 0x55
        || io.bytes[&0xf000a] != 0x80
        || io.bytes.contains_key(&0xf0010)
    {
        return TestResult::Fail("transparent LTTPR");
    }
    // The repeater bounds the link like the sink does.
    for caps in [[0x14, 0x1e, 0x80, 0, 2], [0x14, 0x0a, 0x80, 0, 4]] {
        let (mut e, mut io) = fixture(1, 4, LinkRate::Hbr2, TrainingPattern::Tps3);
        io.set(0xf0000, &caps);
        if run(e.train_dp_link(&mut io, path(1), true, false)) != Err(Error::Unsupported) {
            return TestResult::Fail("LTTPR link limits");
        }
    }
    // An invalid lane count means no repeater (dp_is_lttpr_present).
    let (mut e, mut io) = fixture(1, 4, LinkRate::Hbr2, TrainingPattern::Tps3);
    io.set(0xf0000, &[0x14, 0x1e, 0x80, 0, 0]);
    if run(e.train_dp_link(&mut io, path(1), true, false)).is_err() || io.bytes[&0xf0003] != 0 {
        return TestResult::Fail("invalid LTTPR ignored");
    }
    // Two repeaters, non-transparent: repeater 2 (farthest from the sink)
    // trains first, each CR on TPS1 then EQ on TPS4 at its own interval,
    // then "training done"; the sink last.
    let (mut e, mut io) = fixture(1, 4, LinkRate::Hbr2, TrainingPattern::Tps3);
    io.set(0xf0000, &[0x14, 0x1e, 0x40, 0, 4]);
    io.set(0xf0020, &[0x81]); // repeater 1: 4 ms (bit 7 masked)
    io.set(0xf0070, &[2]); // repeater 2: 8 ms
    for hop in [0xf0030, 0xf0080] {
        io.set(hop, &[0x77, 0x77, 1, 0, 0]);
    }
    run(e.train_dp_link(&mut io, path(1), true, true)).unwrap();
    let writes: Vec<(u32, u8)> = io
        .events
        .iter()
        .filter_map(|ev| match ev {
            Event::Aux(0x80, at, data) if (0xf0010..0xf0100).contains(at) || *at == 0x102 => {
                Some((*at, data[0]))
            }
            _ => None,
        })
        .collect();
    let expected = [
        (0x102, 0),      // sink link configuration (training off) first
        (0xf0060, 0x21), // repeater 2 CR: TPS1, scrambling off
        (0xf0060, 0x07), // repeater 2 EQ: TPS4
        (0xf0060, 0),    // repeater 2 done
        (0xf0010, 0x21),
        (0xf0010, 0x07),
        (0xf0010, 0),
        (0x102, 0x21), // sink CR
        (0x102, 0x23), // sink EQ: TPS3
        (0x102, 0),    // idle
    ];
    if writes != expected || io.bytes[&0xf0003] != 0xaa {
        return TestResult::Fail("non-transparent hop order");
    }
    let delays: Vec<u64> = io
        .events
        .iter()
        .filter_map(|ev| match ev {
            Event::Delay(us) if [4000, 8000].contains(us) => Some(*us),
            _ => None,
        })
        .collect();
    if delays != [8000, 4000] {
        return TestResult::Fail("per-repeater EQ intervals");
    }
    // A repeater that never locks fails CR, is told training is done, and
    // the source returns to idle.
    let (mut e, mut io) = fixture(1, 4, LinkRate::Hbr2, TrainingPattern::Tps3);
    io.set(0xf0000, &[0x14, 0x1e, 0x80, 0, 4]);
    io.set(0xf0030, &[0, 0, 0, 0, 0]);
    if run(e.train_dp_link(&mut io, path(1), true, true))
        != Err(Error::DpTraining(DpTrainingError::ClockRecovery))
        || io.bytes[&0xf0010] != 0
        || e.status.state != State::DpLinkRefused(1)
        || io
            .events
            .iter()
            .any(|ev| matches!(ev, Event::Aux(0x80, 0x102, d) if d[0] != 0))
    {
        return TestResult::Fail("repeater CR failure");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_training_uses_lttprs_like_linux_dcn401
);

/// FEC as Linux keeps it on 8b/10b: a FEC-capable DPCD 1.4 sink gets
/// DP_FEC_CONFIGURATION 1 after the training exit and before channel
/// coding, the source DPHY_FEC_READY_SHADOW, and once trained, 7 us later,
/// DPHY_FEC_EN. Stop clears the source's enable, then ready, once the PHY
/// is down, then the sink's configuration. A DPCD 1.2 sink never gets it.
fn dcn401_dp_training_sets_fec_ready_and_enable_like_linux() -> TestResult {
    let (mut e, mut io) = fixture(1, 4, LinkRate::Hbr3, TrainingPattern::Tps4);
    io.set(0x90, &[1]);
    let trained = run(e.train_dp_link(&mut io, path(1), true, false)).unwrap();
    let writes: Vec<u32> = io
        .events
        .iter()
        .filter_map(|ev| match ev {
            Event::Aux(0x80, at, _) => Some(*at),
            _ => None,
        })
        .collect();
    let fec_at = writes.iter().position(|&a| a == 0x120);
    let coding_at = writes.iter().position(|&a| a == 0x108);
    if !trained.fec
        || io.bytes[&0x120] != 1
        || fec_at.is_none()
        || fec_at > coding_at
        || e.io.inner.inner.regs[&dio(1, 0x212d)] & 0x30 != 0x30
    {
        return TestResult::Fail("FEC ready/enable");
    }
    let delay7 = io.events.iter().rposition(|ev| *ev == Event::Delay(7));
    let finish = io.events.iter().rposition(|ev| *ev == Event::Delay(5000));
    if delay7.is_none() || delay7 < finish {
        return TestResult::Fail("FEC enable delay");
    }
    run(e.stop_dp_link(&mut io, path(1))).unwrap();
    if io.bytes[&0x120] != 0 || e.io.inner.inner.regs[&dio(1, 0x212d)] & 0x70 != 0 {
        return TestResult::Fail("FEC stop");
    }
    // DPCD 1.2: FEC_CAPABILITY is not read, FEC stays off.
    let (mut e, mut io) = fixture(1, 4, LinkRate::Hbr2, TrainingPattern::Tps3);
    io.set(0, &[0x12]);
    io.set(0x90, &[1]);
    let trained = run(e.train_dp_link(&mut io, path(1), true, false)).unwrap();
    if trained.fec
        || io.bytes.contains_key(&0x120)
        || e.io.inner.inner.regs[&dio(1, 0x212d)] & 0x30 != 0
        || io
            .events
            .iter()
            .any(|ev| matches!(ev, Event::Aux(0x90, 0x90, _)))
    {
        return TestResult::Fail("FEC on DPCD 1.2");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_training_sets_fec_ready_and_enable_like_linux
);

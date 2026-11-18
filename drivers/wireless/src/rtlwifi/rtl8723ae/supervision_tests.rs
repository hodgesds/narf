// SPDX-License-Identifier: GPL-2.0-or-later
//! One coherent native firmware/RF/physical-EFUSE trajectory. No extracted
//! source tests, fake stop receipt, global regulatory mutation or RF hardware.
use super::super::super::{
    factory,
    radio_policy::{self, ColdBinding, Program, QualifiedProgram},
    supervision::{Stage, Status, Work},
};
use super::*;
use narf_wireless::reg::db::Database;

fn initialized() -> (
    CheckedPort,
    Arc<FirmwareOwner<CheckedPort>>,
    Arc<Retained<CheckedPort>>,
) {
    let expected = factory::tests::expected();
    let mut port = CheckedPort::new();
    port.factory = Some(factory::tests::Port::new(&expected, 0xee));
    let owner = Arc::new(FirmwareOwner::new(port.clone(), DEV_ID));
    assert!(run(owner.initialize(&firmware_image())).is_ok());
    let root = Retained::allocate(owner.clone(), expected).unwrap();
    root.attach_name("ae-supervision-inert-model").unwrap();
    assert!(root.commit(port.address(), &owner));
    assert!(run(root.acquire_factory()).is_ok());
    assert!(run(owner.ae_fixture_lock()).is_none());
    assert!(run(root.state.lock()).factory.cleanup_receipt().is_some());
    (port, owner, root)
}
type Registered = (
    CheckedPort,
    Arc<Retained<CheckedPort>>,
    [narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>; 2],
    Arc<Database>,
);
fn registered() -> Registered {
    let (port, owner, root) = initialized();
    let inputs = run(root.state.lock()).factory.inputs().unwrap();
    let op = envelope::Operating::twenty(6);
    let caps = [Cap::bootstrap(), Cap::bootstrap()];
    let bytes = radio_policy::tests::napc(&inputs, op, radio_policy::tests::curves());
    let base = envelope::Calibration::from_verified(&bytes, Some([1; 32]), inputs.factory())
        .unwrap()
        .bind_fixture_authority(caps[0]);
    let program = Program::bind(
        inputs,
        Arc::new(base),
        owner.identity().unwrap(),
        Arc::new(ColdBinding::from_native(root.cold.bound().unwrap())),
        op,
    )
    .unwrap();
    let record = radio_policy::tests::record(&program, 80);
    let q = Arc::new(QualifiedProgram::parse(program, &record, Some([1; 32]), caps[1]).unwrap());
    let database = Arc::new(Database::new());
    database.install(radio_policy::tests::domain());
    let work = run(Work::fixture(root.clone(), q, database.clone(), op)).unwrap();
    {
        let mut state = run(root.state.lock());
        state.phase = super::super::super::retained::Phase::Calibrating;
        state.work = Some(work);
    }
    // Literal independent IQK result words: two matching valid TX/RX trials.
    for (reg, value) in [
        (0xe94, 0x0100_0000u32),
        (0xe9c, 0x0005_0000),
        (0xea4, 0x0100_0000),
        (0xeac, 0x0005_0000),
    ] {
        port.port.0.lock().regs[reg..reg + 4].copy_from_slice(&value.to_le_bytes());
    }
    (port, root, caps, database)
}
fn step(root: &Retained<CheckedPort>) -> Poll<Result<(), Error>> {
    root.poll_preparation(&mut Context::from_waker(Waker::noop()))
}
fn status(root: &Retained<CheckedPort>) -> Status {
    run(root.state.lock())
        .work
        .as_ref()
        .unwrap()
        .status_fixture()
}
fn cancel(root: &Retained<CheckedPort>) {
    run(root.state.lock())
        .work
        .as_ref()
        .unwrap()
        .cancel_fixture();
}
fn finish(root: &Retained<CheckedPort>) -> Result<(), Error> {
    for _ in 0..128 {
        if let Poll::Ready(result) = step(root) {
            return result;
        }
    }
    Err(Error::PacketTimeout)
}
fn smoke_ae_retained_native_factory_calibration_pa_and_power_source_order() -> TestResult {
    let (port, root, _, _) = registered();
    let at = port.port.writes().len();
    kt_assert_eq!(finish(&root), Ok(()));
    kt_assert_eq!(status(&root), Status::Complete);
    let writes = port.port.writes();
    let writes = &writes[at..];
    let find = |reg, value| {
        writes
            .iter()
            .position(|(_, r, v)| *r == reg && *v == value)
            .unwrap()
    };
    let iqk = find(0xe48, 0xf900_0000);
    let lck = writes
        .iter()
        .enumerate()
        .find(|(n, (_, r, v))| *n > iqk && *r == 0x840 && *v >> 20 == 0x18)
        .unwrap()
        .0;
    let pa = writes
        .iter()
        .position(|(_, r, v)| *r == 0x840 && *v >> 20 == 0x15 && *v & 15 == 5)
        .unwrap();
    let txagc = writes.iter().position(|(_, r, _)| *r == 0xe08).unwrap();
    let channel = writes
        .iter()
        .position(|(_, r, v)| *r == 0x840 && *v >> 20 == 0x18 && *v & 0x3ff == 6)
        .unwrap();
    let bw = writes
        .iter()
        .rposition(|(width, r, v)| *width == 1 && *r == 0x603 && *v & 4 != 0)
        .unwrap();
    kt_assert!(iqk < lck && lck < pa && pa < txagc && txagc < channel && channel < bw);
    kt_assert!(writes
        .iter()
        .any(|(w, r, v)| *w == 1 && *r == 0x16 && *v & 0xf0 == 0x80));
    kt_assert!(writes
        .iter()
        .any(|(w, r, v)| *w == 1 && *r == 0x16 && *v & 0xf0 == 0x90));
    kt_assert_eq!(port.port.reg32(0xe00), 0x0707_0707);
    kt_assert_eq!(port.port.reg32(0xe04), 0x0707_0707);
    kt_assert_eq!(port.port.reg32(0xe10), 0x0707_0707);
    kt_assert_eq!(port.port.reg32(0xe14), 0x0707_0707);
    kt_assert_eq!(port.port.reg32(0x3a8), 0);
    kt_assert_eq!(port.port.reg32(0x3ac), 0);
    kt_assert_eq!(port.port.0.lock().regs[0x100] & 0xcf, 0);
    // No source LLT replay, ring base, DMA/MAC enable or H2C packet command.
    kt_assert!(!writes.iter().any(|(_, r, _)| *r == 0x1e0
        || (0x308..=0x340).contains(r)
        || (0x1d0..=0x1df).contains(r)));
    TestResult::Pass
}
fn smoke_ae_retained_native_cancel_drains_only_started_iqk() -> TestResult {
    let (port, root, _, _) = registered();
    port.port.0.lock().pause_delay = Some(1_000);
    for _ in 0..16 {
        if status(&root) == Status::Running(Stage::Iqk) {
            break;
        }
        kt_assert!(step(&root).is_pending());
    }
    kt_assert_eq!(status(&root), Status::Running(Stage::Iqk));
    let at = port.port.writes().len();
    cancel(&root);
    kt_assert!(step(&root).is_pending()); // mandatory source wait remains owned
    port.port.0.lock().pause_delay = None;
    kt_assert_eq!(finish(&root), Err(Error::State));
    kt_assert_eq!(status(&root), Status::CancelledAfterStage(Stage::Iqk));
    let writes = port.port.writes();
    kt_assert!(!writes[at..]
        .iter()
        .any(|(_, r, v)| *r == 0x840 && *v >> 20 == 0x18)); // no LCK
    kt_assert!(run(root.state.lock()).work.is_some());
    kt_assert!(root.cold.bound().is_ok());
    TestResult::Pass
}
fn smoke_ae_retained_native_revocation_and_boundary_cancel_never_start_next_stage() -> TestResult {
    for source in 0..4 {
        let (port, root, caps, database) = registered();
        // First poll completes preflight and constructs Identity, but starts
        // no Identity write. Retirement/cancel at this boundary must stay so.
        kt_assert!(step(&root).is_pending());
        let at = port.port.writes().len();
        match source {
            0 => {
                caps[0].revoke();
            }
            1 => {
                caps[1].revoke();
            }
            2 => {
                database.install(radio_policy::tests::domain());
            }
            _ => cancel(&root),
        }
        kt_assert!(matches!(step(&root), Poll::Ready(Err(_))));
        kt_assert_eq!(port.port.writes().len(), at);
        kt_assert!(run(root.state.lock()).work.is_some());
        kt_assert!(root.cold.bound().is_ok());
    }
    TestResult::Pass
}
kernel_test_in! {"drivers/wireless/rtlwifi/rtl8723ae", smoke_ae_retained_native_factory_calibration_pa_and_power_source_order}
kernel_test_in! {"drivers/wireless/rtlwifi/rtl8723ae", smoke_ae_retained_native_cancel_drains_only_started_iqk}
kernel_test_in! {"drivers/wireless/rtlwifi/rtl8723ae", smoke_ae_retained_native_revocation_and_boundary_cancel_never_start_next_stage}

#[path = "nasr_tests.rs"]
mod nasr_tests;

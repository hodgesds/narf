//! AOSS QMP smokes. The fake AOSS acks every handshake step and
//! consumes every message on kick, mirroring the AOSS side of
//! `qcom_aoss.c` (link/channel ack words, length-word clear on
//! consume). Expected descriptor offsets and the `load_state` message
//! text come from `qcom_aoss.c` / `qcom_q6v5.c`, not from the code
//! under test.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};

use crate::aoss::{Qmp, QmpError};
use crate::fixtures::{run, FakeDelay, FakeRegs};
use crate::io::read_bytes;
use crate::ipc::Kick;

const SUB: &str = "drivers/soc/qcom";
/// Descriptor offsets (`QMP_DESC_*`).
const DESC_MAGIC: u32 = 0x00;
const DESC_VERSION: u32 = 0x04;
const DESC_UCORE_LINK_STATE: u32 = 0x0c;
const DESC_UCORE_LINK_STATE_ACK: u32 = 0x10;
const DESC_UCORE_CH_STATE: u32 = 0x14;
const DESC_UCORE_CH_STATE_ACK: u32 = 0x18;
const DESC_MCORE_LINK_STATE: u32 = 0x24;
const DESC_MCORE_LINK_STATE_ACK: u32 = 0x28;
const DESC_MCORE_CH_STATE: u32 = 0x2c;
const DESC_MCORE_CH_STATE_ACK: u32 = 0x30;
const DESC_MCORE_MBOX_SIZE: u32 = 0x34;
const DESC_MCORE_MBOX_OFFSET: u32 = 0x38;
const STATE_UP: u32 = 0x0000_ffff;
const STATE_DOWN: u32 = 0xffff_0000;
/// Negotiated mailbox offset used by every test.
const MBOX: u32 = 0x100;

/// A kick that plays a responsive AOSS: every kick acks the link and
/// channel and consumes any pending message (clears its length word).
/// `responsive` can be switched off mid-test to force timeouts. The
/// flag is shared by reference so a test can still flip it after the
/// kick has moved into `Qmp::open`.
struct AckKick<'a> {
    regs: &'a FakeRegs,
    responsive: &'a AtomicBool,
}

impl<'a> AckKick<'a> {
    fn new(regs: &'a FakeRegs, responsive: &'a AtomicBool) -> Self {
        Self { regs, responsive }
    }
}

impl Kick for AckKick<'_> {
    fn kick(&self) {
        if !self.responsive.load(Ordering::Relaxed) {
            return;
        }
        self.regs.set(DESC_MCORE_LINK_STATE_ACK, STATE_UP);
        self.regs.set(DESC_UCORE_CH_STATE, STATE_UP);
        self.regs.set(DESC_MCORE_CH_STATE_ACK, STATE_UP);
        let off = self.regs.get(DESC_MCORE_MBOX_OFFSET);
        self.regs.set(off, 0);
    }
}

/// A kick that never acks anything.
#[derive(Debug)]
struct NoopKick;

impl Kick for NoopKick {
    fn kick(&self) {}
}

/// A msgram preset for a healthy AOSS: magic, version 1, a 64-byte
/// mailbox at MBOX, and a distinctive remote link-state value so the
/// ack echo is checkable.
fn msgram() -> FakeRegs {
    let r = FakeRegs::new();
    r.set(DESC_MAGIC, 0x4d41_494c);
    r.set(DESC_VERSION, 1);
    r.set(DESC_MCORE_MBOX_OFFSET, MBOX);
    r.set(DESC_MCORE_MBOX_SIZE, 64);
    r.set(DESC_UCORE_LINK_STATE, 0x1234);
    r
}

fn msg_at(regs: &FakeRegs) -> Vec<u8> {
    let mut buf = [0u8; 64];
    read_bytes(regs, MBOX + 4, &mut buf);
    // The message is NUL-terminated by the zero padding.
    let end = buf.iter().position(|b| *b == 0).unwrap_or(64);
    buf[..end].to_vec()
}

fn smoke_qcom_aoss_open_handshake() -> TestResult {
    let d = FakeDelay::new();
    let regs = msgram();
    let responsive = AtomicBool::new(true);
    let kick = AckKick::new(&regs, &responsive);
    let q = run(Qmp::open(&regs, kick, &d));
    kt_assert!(q.is_some());
    let q = q.unwrap().unwrap();
    kt_assert_eq!(q.mbox_size(), 64);
    // The remote link state was echoed into its ack word.
    kt_assert_eq!(regs.get(DESC_UCORE_LINK_STATE_ACK), 0x1234);
    kt_assert_eq!(regs.get(DESC_MCORE_LINK_STATE), STATE_UP);
    kt_assert_eq!(regs.get(DESC_MCORE_CH_STATE), STATE_UP);
    kt_assert_eq!(regs.get(DESC_UCORE_CH_STATE_ACK), STATE_UP);
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_aoss_open_handshake);

fn smoke_qcom_aoss_open_rejects() -> TestResult {
    let d = FakeDelay::new();
    let mut r = msgram();
    r.set(DESC_MAGIC, 0);
    kt_assert_eq!(
        run(Qmp::open(&r, NoopKick, &d)).unwrap().unwrap_err(),
        QmpError::BadMagic
    );
    r = msgram();
    r.set(DESC_VERSION, 2);
    kt_assert_eq!(
        run(Qmp::open(&r, NoopKick, &d)).unwrap().unwrap_err(),
        QmpError::BadVersion
    );
    r = msgram();
    r.set(DESC_MCORE_MBOX_SIZE, 0);
    kt_assert_eq!(
        run(Qmp::open(&r, NoopKick, &d)).unwrap().unwrap_err(),
        QmpError::BadMbox
    );
    // An unresponsive AOSS times out and unwinds the link to DOWN.
    r = msgram();
    kt_assert_eq!(
        run(Qmp::open(&r, NoopKick, &d)).unwrap().unwrap_err(),
        QmpError::Timeout
    );
    kt_assert_eq!(r.get(DESC_MCORE_LINK_STATE), STATE_DOWN);
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_aoss_open_rejects);

fn smoke_qcom_aoss_send_and_load_state() -> TestResult {
    let d = FakeDelay::new();
    let regs = msgram();
    let responsive = AtomicBool::new(true);
    let kick = AckKick::new(&regs, &responsive);
    let q = run(Qmp::open(&regs, kick, &d)).unwrap().unwrap();
    kt_assert_eq!(run(q.send(&d, "hello")), Some(Ok(())));
    kt_assert_eq!(msg_at(&regs), b"hello".to_vec());
    // The length word was written (64) and cleared on consume.
    kt_assert_eq!(regs.get(MBOX), 0);
    kt_assert!(regs.writes_to(MBOX).contains(&64));
    // The load-state message is byte-exact per qcom_q6v5.c.
    kt_assert_eq!(run(q.load_state(&d, "wpss", true)), Some(Ok(())));
    kt_assert_eq!(
        msg_at(&regs),
        b"{class: image, res: load_state, name: wpss, val: on}".to_vec()
    );
    kt_assert_eq!(run(q.load_state(&d, "wpss", false)), Some(Ok(())));
    kt_assert_eq!(
        msg_at(&regs),
        b"{class: image, res: load_state, name: wpss, val: off}".to_vec()
    );
    // Over-long messages are refused before touching the mailbox.
    let long = [b'x'; 64];
    let long = core::str::from_utf8(&long).unwrap();
    kt_assert_eq!(run(q.send(&d, long)), Some(Err(QmpError::TooLong)));
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_aoss_send_and_load_state);

fn smoke_qcom_aoss_send_timeout() -> TestResult {
    let d = FakeDelay::new();
    let regs = msgram();
    let responsive = AtomicBool::new(true);
    let kick = AckKick::new(&regs, &responsive);
    let q = run(Qmp::open(&regs, kick, &d)).unwrap().unwrap();
    // The AOSS stops responding after open: the send times out and
    // the length word is cleared.
    responsive.store(false, Ordering::Relaxed);
    kt_assert_eq!(run(q.send(&d, "hello")), Some(Err(QmpError::Timeout)));
    kt_assert_eq!(regs.get(MBOX), 0);
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_aoss_send_timeout);

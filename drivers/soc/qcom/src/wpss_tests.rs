//! WPSS power-sequence smokes: the prepare/unprepare order from
//! `wpss.rs` (votes, then load-state `on`; load-state `off` only on
//! stop), checked against the same RSC + AOSS fakes as the module
//! tests, rebuilt locally so this file stands alone.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};

use crate::aoss::Qmp;
use crate::cmd_db::CmdDb;
use crate::fixtures::{run, FakeDelay, FakeRegs};
use crate::io::{read_bytes, RegIo};
use crate::ipc::Kick;
use crate::rpmh::{Rpmh, Rsc};
use crate::wpss::{WpssPower, WpssPowerError};

const SUB: &str = "drivers/soc/qcom";
const TCS_BASE: u32 = 0x1000;
const MBOX: u32 = 0x100;
const STATE_UP: u32 = 0x0000_ffff;

/// Completes TCS 0 when triggered (see `rpmh_tests.rs`).
struct RscFake {
    inner: FakeRegs,
}

impl RscFake {
    fn writes_to(&self, off: u32) -> Vec<u32> {
        self.inner.writes_to(off)
    }
}

impl RegIo for RscFake {
    fn read32(&self, off: u32) -> u32 {
        self.inner.read32(off)
    }

    fn write32(&self, off: u32, value: u32) {
        self.inner.write32(off, value);
        if off == TCS_BASE + 0x14 && value & (1 << 24) != 0 {
            self.inner.set(0x04, 1);
        }
        if off == 0x08 && value & 1 != 0 {
            self.inner.set(0x04, 0);
        }
    }
}

/// Responsive-AOSS kick (see `aoss_tests.rs`).
struct AckKick<'a> {
    regs: &'a FakeRegs,
    responsive: AtomicBool,
}

impl<'a> AckKick<'a> {
    fn new(regs: &'a FakeRegs) -> Self {
        Self {
            regs,
            responsive: AtomicBool::new(true),
        }
    }
}

impl Kick for AckKick<'_> {
    fn kick(&self) {
        if !self.responsive.load(Ordering::Relaxed) {
            return;
        }
        self.regs.set(0x28, STATE_UP); // MCORE_LINK_STATE_ACK
        self.regs.set(0x14, STATE_UP); // UCORE_CH_STATE
        self.regs.set(0x30, STATE_UP); // MCORE_CH_STATE_ACK
        let off = self.regs.get(0x38);
        self.regs.set(off, 0);
    }
}

fn table(with_mx: bool) -> Vec<u8> {
    let n = if with_mx { 3 } else { 2 };
    let mut b = alloc::vec![0u8; 112 + n * 24];
    b[0..4].copy_from_slice(&1u32.to_le_bytes());
    b[4..8].copy_from_slice(&[0xdb, 0x30, 0x03, 0x0c]);
    b[8..10].copy_from_slice(&1u16.to_le_bytes());
    b[14..16].copy_from_slice(&(n as u16).to_le_bytes());
    let mut put = |i: usize, id: &[u8; 8], addr: u32| {
        let e = 112 + i * 24;
        b[e..e + 8].copy_from_slice(id);
        b[e + 16..e + 20].copy_from_slice(&addr.to_le_bytes());
    };
    put(0, b"cx.lvl\0\0", 0x0011_0000);
    if with_mx {
        put(1, b"mx.lvl\0\0", 0x0022_0000);
        put(2, b"xo.lvl\0\0", 0x0033_0000);
    } else {
        put(1, b"xo.lvl\0\0", 0x0033_0000);
    }
    b
}

fn msgram() -> FakeRegs {
    let r = FakeRegs::new();
    r.set(0x00, 0x4d41_494c);
    r.set(0x04, 1);
    r.set(0x38, MBOX);
    r.set(0x34, 64);
    r.set(0x0c, 0x1234);
    r
}

fn msg_at(regs: &FakeRegs) -> Vec<u8> {
    let mut buf = [0u8; 64];
    read_bytes(regs, MBOX + 4, &mut buf);
    let end = buf.iter().position(|b| *b == 0).unwrap_or(64);
    buf[..end].to_vec()
}

fn smoke_qcom_wpss_prepare_unprepare() -> TestResult {
    let d = FakeDelay::new();
    let t = table(true);
    let db = CmdDb::parse(&t).unwrap();
    let rsc_fake = RscFake {
        inner: FakeRegs::new(),
    };
    let rpmh = Rpmh::new(db, Rsc::probe(&rsc_fake, TCS_BASE));
    let regs = msgram();
    let kick = AckKick::new(&regs);
    let qmp = run(Qmp::open(&regs, kick, &d)).unwrap().unwrap();
    let p = WpssPower::new(rpmh, qmp);
    kt_assert_eq!(run(p.prepare(&d, 0x10, 0x20)), Some(Ok(())));
    // Votes landed in order cx, mx, xo (each overwrote slot 0).
    kt_assert_eq!(
        rsc_fake.writes_to(TCS_BASE + 0x34),
        alloc::vec![0x0011_0000, 0x0022_0000, 0x0033_0000]
    );
    kt_assert_eq!(
        rsc_fake.writes_to(TCS_BASE + 0x38),
        alloc::vec![0x10, 0x20, 0x3]
    );
    kt_assert_eq!(
        msg_at(&regs),
        b"{class: image, res: load_state, name: wpss, val: on}".to_vec()
    );
    let addr_writes = rsc_fake.writes_to(TCS_BASE + 0x34).len();
    // Unprepare sends load-state off and casts no new vote.
    kt_assert_eq!(run(p.unprepare(&d)), Some(Ok(())));
    kt_assert_eq!(
        msg_at(&regs),
        b"{class: image, res: load_state, name: wpss, val: off}".to_vec()
    );
    kt_assert_eq!(rsc_fake.writes_to(TCS_BASE + 0x34).len(), addr_writes);
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_wpss_prepare_unprepare);

fn smoke_qcom_wpss_prepare_vote_failure() -> TestResult {
    let d = FakeDelay::new();
    // No `mx.lvl` entry: prepare fails after the cx vote, before the
    // xo vote and before any load-state message.
    let t = table(false);
    let db = CmdDb::parse(&t).unwrap();
    let rsc_fake = RscFake {
        inner: FakeRegs::new(),
    };
    let rpmh = Rpmh::new(db, Rsc::probe(&rsc_fake, TCS_BASE));
    let regs = msgram();
    let kick = AckKick::new(&regs);
    let qmp = run(Qmp::open(&regs, kick, &d)).unwrap().unwrap();
    let p = WpssPower::new(rpmh, qmp);
    kt_assert_eq!(
        run(p.prepare(&d, 0x10, 0x20)),
        Some(Err(WpssPowerError::Vote(
            crate::rpmh::VoteError::UnknownResource
        )))
    );
    kt_assert_eq!(
        rsc_fake.writes_to(TCS_BASE + 0x34),
        alloc::vec![0x0011_0000]
    );
    kt_assert!(regs.writes_to(MBOX).is_empty());
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_wpss_prepare_vote_failure);

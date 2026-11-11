//! WPSS power-sequence smokes: the `qcom_q6v5_pas.c` start / handover /
//! stop order from `wpss.rs`, checked against the same RSC + AOSS fakes
//! as the module tests, rebuilt locally so this file stands alone.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_kernel_test::{kernel_test_in, kt_assert_eq, TestResult};

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

/// cmd-db with `cx.lvl`, optionally `mx.lvl`, and `xo.lvl`. Aux data
/// (u16 vlvl per hlvl, `rpmhpd_update_level_mapping`): cx
/// `[0, 16 (retention), 48, 64, 128, 0, 0]` (zero padding ends the map
/// after hlvl 4) and mx `[0, 48, 64, 128, 256, 384]` (no padding).
fn table(with_mx: bool) -> Vec<u8> {
    let cx: &[u16] = &[0, 16, 48, 64, 128, 0, 0];
    let mx: &[u16] = &[0, 48, 64, 128, 256, 384];
    let mut ids: Vec<(&[u8; 8], u32, &[u16])> = alloc::vec![(b"cx.lvl\0\0", 0x0011_0000, cx)];
    if with_mx {
        ids.push((b"mx.lvl\0\0", 0x0022_0000, mx));
    }
    ids.push((b"xo.lvl\0\0", 0x0033_0000, &[]));
    let n = ids.len();
    let data_offset = n * 24;
    let aux_len: usize = ids.iter().map(|(_, _, a)| a.len() * 2).sum();
    let mut b = alloc::vec![0u8; 112 + data_offset + aux_len];
    b[0..4].copy_from_slice(&1u32.to_le_bytes());
    b[4..8].copy_from_slice(&[0xdb, 0x30, 0x03, 0x0c]);
    b[8..10].copy_from_slice(&1u16.to_le_bytes());
    b[12..14].copy_from_slice(&(data_offset as u16).to_le_bytes());
    b[14..16].copy_from_slice(&(n as u16).to_le_bytes());
    let mut at = 0usize;
    for (i, (id, addr, aux)) in ids.iter().enumerate() {
        let e = 112 + i * 24;
        b[e..e + 8].copy_from_slice(*id);
        b[e + 16..e + 20].copy_from_slice(&addr.to_le_bytes());
        b[e + 20..e + 22].copy_from_slice(&((aux.len() * 2) as u16).to_le_bytes());
        b[e + 22..e + 24].copy_from_slice(&(at as u16).to_le_bytes());
        for (k, v) in aux.iter().enumerate() {
            let o = 112 + data_offset + at + 2 * k;
            b[o..o + 2].copy_from_slice(&v.to_le_bytes());
        }
        at += aux.len() * 2;
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

const RAILS: &[&str] = &["cx", "mx"];

/// `qcom_pas_start` → handover → `qcom_pas_stop` order: load-state
/// `on`; cx and mx at their highest corner; xo on; then xo off, cx 0,
/// mx 0; then load-state `off`.
fn smoke_qcom_wpss_pas_proxy_sequence() -> TestResult {
    let d = FakeDelay::new();
    let t = table(true);
    let db = CmdDb::parse(&t).unwrap();
    kt_assert_eq!(
        crate::rpmh::arc_max_corner(db.read_aux_data("cx.lvl").unwrap()),
        Some(4)
    );
    kt_assert_eq!(
        crate::rpmh::arc_max_corner(db.read_aux_data("mx.lvl").unwrap()),
        Some(5)
    );
    let rsc_fake = RscFake {
        inner: FakeRegs::new(),
    };
    let rpmh = Rpmh::new(db, Rsc::probe(&rsc_fake, TCS_BASE));
    let regs = msgram();
    let kick = AckKick::new(&regs);
    let qmp = run(Qmp::open(&regs, kick, &d)).unwrap().unwrap();
    let p = WpssPower::new(rpmh, Some(qmp), RAILS);
    kt_assert_eq!(run(p.start(&d)), Some(Ok(())));
    kt_assert_eq!(
        msg_at(&regs),
        b"{class: image, res: load_state, name: wpss, val: on}".to_vec()
    );
    kt_assert_eq!(
        rsc_fake.writes_to(TCS_BASE + 0x34),
        alloc::vec![0x0011_0000, 0x0022_0000, 0x0033_0000]
    );
    kt_assert_eq!(rsc_fake.writes_to(TCS_BASE + 0x38), alloc::vec![4, 5, 0x3]);
    // Handover: xo off first, then the rails to corner 0.
    kt_assert_eq!(run(p.proxy_disable(&d)), Some(Ok(())));
    kt_assert_eq!(
        rsc_fake.writes_to(TCS_BASE + 0x34)[3..].to_vec(),
        alloc::vec![0x0033_0000, 0x0011_0000, 0x0022_0000]
    );
    kt_assert_eq!(
        rsc_fake.writes_to(TCS_BASE + 0x38)[3..].to_vec(),
        alloc::vec![0, 0, 0]
    );
    let votes = rsc_fake.writes_to(TCS_BASE + 0x34).len();
    kt_assert_eq!(run(p.load_state(&d, false)), Some(Ok(())));
    kt_assert_eq!(
        msg_at(&regs),
        b"{class: image, res: load_state, name: wpss, val: off}".to_vec()
    );
    kt_assert_eq!(rsc_fake.writes_to(TCS_BASE + 0x34).len(), votes);
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_wpss_pas_proxy_sequence);

/// No `mx.lvl` entry: the cx vote is unrolled to corner 0, xo is never
/// voted, and load-state `off` follows the `on` (`disable_irqs`).
fn smoke_qcom_wpss_pas_vote_failure_unrolls() -> TestResult {
    let d = FakeDelay::new();
    let t = table(false);
    let db = CmdDb::parse(&t).unwrap();
    let rsc_fake = RscFake {
        inner: FakeRegs::new(),
    };
    let rpmh = Rpmh::new(db, Rsc::probe(&rsc_fake, TCS_BASE));
    let regs = msgram();
    let kick = AckKick::new(&regs);
    let qmp = run(Qmp::open(&regs, kick, &d)).unwrap().unwrap();
    let p = WpssPower::new(rpmh, Some(qmp), RAILS);
    kt_assert_eq!(
        run(p.start(&d)),
        Some(Err(WpssPowerError::Vote(
            crate::rpmh::VoteError::UnknownResource
        )))
    );
    kt_assert_eq!(
        rsc_fake.writes_to(TCS_BASE + 0x34),
        alloc::vec![0x0011_0000, 0x0011_0000]
    );
    kt_assert_eq!(rsc_fake.writes_to(TCS_BASE + 0x38), alloc::vec![4, 0]);
    kt_assert_eq!(regs.writes_to(MBOX), alloc::vec![64, 64]);
    kt_assert_eq!(
        msg_at(&regs),
        b"{class: image, res: load_state, name: wpss, val: off}".to_vec()
    );
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_wpss_pas_vote_failure_unrolls);

/// `rpmhpd_update_level_mapping` corner bounds: empty and oversized
/// maps are refused, a one-entry map is corner 0, and a retention entry
/// is not mistaken for padding.
fn smoke_qcom_rpmh_arc_max_corner() -> TestResult {
    use crate::rpmh::arc_max_corner;
    let le = |v: &[u16]| -> Vec<u8> { v.iter().flat_map(|x| x.to_le_bytes()).collect() };
    kt_assert_eq!(arc_max_corner(&[]), None);
    kt_assert_eq!(arc_max_corner(&le(&[1; 33])), None);
    kt_assert_eq!(arc_max_corner(&le(&[0])), Some(0));
    kt_assert_eq!(arc_max_corner(&le(&[0, 0, 0])), Some(0));
    kt_assert_eq!(arc_max_corner(&le(&[16, 16, 48])), Some(2));
    kt_assert_eq!(arc_max_corner(&le(&[0, 48, 0, 64])), Some(1));
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_rpmh_arc_max_corner);

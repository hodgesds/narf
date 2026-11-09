//! RPMh RSC + vote smokes. Expected register addresses come from the
//! `rpmh-rsc.c` tables transcribed in `rpmh.rs` (2.7: command stride
//! 20, control 0x14, msgid 0x30, addr 0x34, data 0x38, enable 0x1c;
//! 3.0: stride 24, control 0x24, msgid 0x34, addr 0x38, data 0x3c,
//! enable 0x2c; TCS stride 672, IRQ status 0x04, IRQ clear 0x08),
//! not from the code under test. The fake RSC completes a TCS when
//! the driver triggers it, mirroring hardware completion.

use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};

use crate::cmd_db::CmdDb;
use crate::fixtures::{run, FakeDelay, FakeRegs};
use crate::io::RegIo;
use crate::rpmh::{Rpmh, Rsc, RscError, VoteError};

const SUB: &str = "drivers/soc/qcom";
/// TCS region base used by every test (the DT `qcom,tcs-offset`).
const TCS_BASE: u32 = 0x1000;
/// AMC trigger/enable bits (`TCS_AMC_MODE_TRIGGER/ENABLE`).
const AMC_TRIGGER: u32 = 1 << 24;
const AMC_ENABLE: u32 = 1 << 16;

/// A FakeRegs that completes TCS 0 when the driver triggers it: any
/// write to the TCS0 CONTROL register with the TRIGGER bit set raises
/// the IRQ_STATUS bit, as the RSC does on transfer completion.
struct RscFake {
    inner: FakeRegs,
    control: u32,
}

impl RscFake {
    fn new(control: u32) -> Self {
        Self {
            inner: FakeRegs::new(),
            control,
        }
    }

    fn writes_to(&self, off: u32) -> Vec<u32> {
        self.inner.writes_to(off)
    }

    fn get(&self, off: u32) -> u32 {
        self.inner.get(off)
    }
}

impl RegIo for RscFake {
    fn read32(&self, off: u32) -> u32 {
        self.inner.read32(off)
    }

    fn write32(&self, off: u32, value: u32) {
        self.inner.write32(off, value);
        if off == self.control && value & AMC_TRIGGER != 0 {
            // RSC_DRV_IRQ_STATUS, TCS 0 bit.
            self.inner.set(0x04, 1);
        }
        if off == 0x08 && value & 1 != 0 {
            // IRQ_CLEAR drops the status bit again.
            self.inner.set(0x04, 0);
        }
    }
}

/// The cmd-db table from `cmd_db_tests` (same layout, rebuilt here so
/// this module does not depend on another test module's helpers).
fn table() -> Vec<u8> {
    let mut b = alloc::vec![0u8; 112 + 3 * 24];
    b[0..4].copy_from_slice(&1u32.to_le_bytes());
    b[4..8].copy_from_slice(&[0xdb, 0x30, 0x03, 0x0c]);
    b[8..10].copy_from_slice(&1u16.to_le_bytes());
    b[14..16].copy_from_slice(&3u16.to_le_bytes());
    let mut put = |i: usize, id: &[u8; 8], addr: u32| {
        let e = 112 + i * 24;
        b[e..e + 8].copy_from_slice(id);
        b[e + 16..e + 20].copy_from_slice(&addr.to_le_bytes());
    };
    put(0, b"cx.lvl\0\0", 0x0011_0000);
    put(1, b"mx.lvl\0\0", 0x0022_0000);
    put(2, b"xo.lvl\0\0", 0x0033_0000);
    b
}

fn smoke_qcom_rpmh_tcs_write_v27() -> TestResult {
    let d = FakeDelay::new();
    // ID register reads 0: major 0 selects the 2.7 table.
    let fake = RscFake::new(TCS_BASE + 0x14);
    let rsc = Rsc::probe(&fake, TCS_BASE);
    let r = run(rsc.write_active(&d, &[(0x0000_a000, 0x1111), (0x0000_b000, 0x2222)], true));
    kt_assert_eq!(r, Some(Ok(())));
    // MSGID = LEN(8) | WRITE(1<<16) | RESP_REQ(1<<8), per slot.
    kt_assert_eq!(fake.get(TCS_BASE + 0x30), 8 | (1 << 16) | (1 << 8));
    kt_assert_eq!(fake.get(TCS_BASE + 0x30 + 20), 8 | (1 << 16) | (1 << 8));
    kt_assert_eq!(fake.get(TCS_BASE + 0x34), 0x0000_a000);
    kt_assert_eq!(fake.get(TCS_BASE + 0x34 + 20), 0x0000_b000);
    kt_assert_eq!(fake.get(TCS_BASE + 0x38), 0x1111);
    kt_assert_eq!(fake.get(TCS_BASE + 0x38 + 20), 0x2222);
    // Enable mask rose to 0b11 then tore down to 0; the IRQ bit cleared.
    let en = fake.writes_to(TCS_BASE + 0x1c);
    kt_assert!(en.contains(&0b11));
    kt_assert_eq!(en.last(), Some(&0));
    kt_assert_eq!(fake.writes_to(0x08).last(), Some(&1));
    // Trigger sequence: ENABLE then ENABLE|TRIGGER.
    let ctl = fake.writes_to(TCS_BASE + 0x14);
    kt_assert!(ctl
        .windows(2)
        .any(|w| w == [AMC_ENABLE, AMC_ENABLE | AMC_TRIGGER]));
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_rpmh_tcs_write_v27);

fn smoke_qcom_rpmh_tcs_write_v30() -> TestResult {
    let d = FakeDelay::new();
    let fake = RscFake::new(TCS_BASE + 0x24);
    // ID register: major 3 selects the 3.0 table (stride 24).
    fake.inner.set(0, 3 << 16);
    let rsc = Rsc::probe(&fake, TCS_BASE);
    let r = run(rsc.write_active(&d, &[(0x0000_a000, 0x1111), (0x0000_b000, 0x2222)], true));
    kt_assert_eq!(r, Some(Ok(())));
    kt_assert_eq!(fake.get(TCS_BASE + 0x34), 8 | (1 << 16) | (1 << 8));
    kt_assert_eq!(fake.get(TCS_BASE + 0x38), 0x0000_a000);
    kt_assert_eq!(fake.get(TCS_BASE + 0x38 + 24), 0x0000_b000);
    kt_assert_eq!(fake.get(TCS_BASE + 0x3c), 0x1111);
    kt_assert_eq!(fake.get(TCS_BASE + 0x3c + 24), 0x2222);
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_rpmh_tcs_write_v30);

fn smoke_qcom_rpmh_write_timeout_and_async() -> TestResult {
    let d = FakeDelay::new();
    // Plain FakeRegs never completes: the waited write times out but
    // still tears the TCS down (enable back to 0, IRQ bit cleared).
    let regs = FakeRegs::new();
    let rsc = Rsc::probe(&regs, TCS_BASE);
    let r = run(rsc.write_active(&d, &[(0x0000_a000, 0x1111)], true));
    kt_assert_eq!(r, Some(Err(RscError::Timeout)));
    kt_assert_eq!(regs.get(TCS_BASE + 0x1c), 0);
    kt_assert!(regs.writes_to(0x08).contains(&1));
    // The async shape never polls: no sleep elapsed, still programmed.
    let d2 = FakeDelay::new();
    let regs2 = FakeRegs::new();
    let rsc2 = Rsc::probe(&regs2, TCS_BASE);
    let r = run(rsc2.write_active(&d2, &[(0x0000_a000, 0x1111)], false));
    kt_assert_eq!(r, Some(Ok(())));
    kt_assert_eq!(d2.slept_us.load(core::sync::atomic::Ordering::Relaxed), 0);
    kt_assert_eq!(regs2.get(TCS_BASE + 0x1c), 1);
    // Argument validation.
    let r = run(rsc2.write_active(&d2, &[], true));
    kt_assert_eq!(r, Some(Err(RscError::Empty)));
    let many = [(0u32, 0u32); 17];
    let r = run(rsc2.write_active(&d2, &many, true));
    kt_assert_eq!(r, Some(Err(RscError::TooManyCmds)));
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_rpmh_write_timeout_and_async);

fn smoke_qcom_rpmh_votes() -> TestResult {
    let d = FakeDelay::new();
    let t = table();
    let db = CmdDb::parse(&t).unwrap();
    let fake = RscFake::new(TCS_BASE + 0x14);
    let rpmh = Rpmh::new(db, Rsc::probe(&fake, TCS_BASE));
    kt_assert_eq!(run(rpmh.vote_rail(&d, "cx", 7)), Some(Ok(())));
    kt_assert_eq!(fake.get(TCS_BASE + 0x34), 0x0011_0000);
    kt_assert_eq!(fake.get(TCS_BASE + 0x38), 7);
    kt_assert_eq!(run(rpmh.vote_xo(&d, true)), Some(Ok(())));
    kt_assert_eq!(fake.get(TCS_BASE + 0x34), 0x0033_0000);
    kt_assert_eq!(fake.get(TCS_BASE + 0x38), 0x3);
    kt_assert_eq!(run(rpmh.vote_xo(&d, false)), Some(Ok(())));
    kt_assert_eq!(fake.get(TCS_BASE + 0x38), 0);
    // Unknown resource and over-long rail names fail typed, not silent.
    kt_assert_eq!(
        run(rpmh.vote(&d, "ebi.lvl", 1)),
        Some(Err(VoteError::UnknownResource))
    );
    kt_assert_eq!(
        run(rpmh.vote_rail(&d, "toolong", 1)),
        Some(Err(VoteError::BadRail))
    );
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_rpmh_votes);

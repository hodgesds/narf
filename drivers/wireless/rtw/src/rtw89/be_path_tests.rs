// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Write(u32, u32),
    Pause,
    Resume(u32),
    Delay(u64),
}
struct Model {
    words: BTreeMap<u32, u32>,
    ops: Vec<Op>,
    count: usize,
    fail_at: Option<usize>,
    failed: bool,
}
impl Model {
    fn new() -> Self {
        Self {
            words: [(0x11440, 0x6d)].into_iter().collect(),
            ops: Vec::new(),
            count: 0,
            fail_at: None,
            failed: false,
        }
    }
    fn access(&mut self) -> Result<(), super::super::power::Error> {
        if self.failed {
            return Err(super::super::power::Error::Access);
        }
        self.count += 1;
        if self.fail_at == Some(self.count) {
            self.failed = true;
            return Err(super::super::power::Error::Access);
        }
        Ok(())
    }
}
impl super::super::power::Io for Model {
    fn read8(&mut self, _: u32) -> Result<u8, super::super::power::Error> {
        Err(super::super::power::Error::Access)
    }
    fn read16(&mut self, _: u32) -> Result<u16, super::super::power::Error> {
        Err(super::super::power::Error::Access)
    }
    fn read32(&mut self, a: u32) -> Result<u32, super::super::power::Error> {
        self.access()?;
        if (0x14000..0x18000).contains(&a) {
            return Err(super::super::power::Error::Access);
        }
        Ok(*self.words.get(&a).unwrap_or(&0))
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), super::super::power::Error> {
        Err(super::super::power::Error::Access)
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), super::super::power::Error> {
        Err(super::super::power::Error::Access)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), super::super::power::Error> {
        self.access()?;
        if (0x14000..0x18000).contains(&a) {
            return Err(super::super::power::Error::Access);
        }
        self.words.insert(a, v);
        self.ops.push(Op::Write(a, v));
        Ok(())
    }
    fn now_us(&self) -> u64 {
        0
    }
    async fn delay_us(&mut self, us: u64) {
        self.ops.push(Op::Delay(us));
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, super::super::power::Error> {
        Err(super::super::power::Error::Unsupported)
    }
}
impl Interface for Model {
    fn admit(&mut self) -> Result<(), Error> {
        self.access().map_err(Error::from)
    }
    async fn rf_read(&mut self, _: u8, _: u32, _: u32) -> Result<u32, Error> {
        Err(Error::Terminal)
    }
    async fn rf_write(&mut self, _: u8, _: u32, _: u32, _: u32) -> Result<(), Error> {
        Err(Error::Terminal)
    }
    async fn begin(&mut self, _: super::super::rfk::Kind) -> Result<(), Error> {
        Err(Error::Terminal)
    }
    async fn end(&mut self, _: super::super::rfk::Kind) -> Result<(), Error> {
        Err(Error::Terminal)
    }
    async fn pause(&mut self) -> Result<u32, Error> {
        self.access()?;
        self.ops.push(Op::Pause);
        Ok(0xa5a7f123)
    }
    async fn resume(&mut self, saved: u32) -> Result<(), Error> {
        self.access()?;
        self.ops.push(Op::Resume(saved));
        Ok(())
    }
}
fn ready<T>(future: impl Future<Output = T>) -> Option<T> {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}
fn smoke_rtw8922a_txrx_path_source_bracket_and_scc_duplicate_writes() -> TestResult {
    let mut io = Model::new();
    let mut owner = Paths::default();
    // SAFETY: private inert BB/scheduler protocol model, no hardware.
    let result = unsafe { owner.configure(&mut io, Config { tx: 3, rx: 3 }, Band::Ghz2) };
    kt_assert_eq!(ready(result), Some(Ok(())));
    kt_assert_eq!(owner.state(), State::Programmed);
    kt_assert_eq!(
        &io.ops[..13],
        &[
            Op::Pause,
            Op::Write(0x11440, 0x6c),
            Op::Write(0x22800, 0),
            Op::Write(0x22900, 0),
            Op::Write(0x2e610, 8),
            Op::Write(0x2e710, 8),
            Op::Write(0x210fc, 0x1000000),
            Op::Write(0x210fc, 0x3000000),
            Op::Delay(40),
            Op::Write(0x20520, 1),
            Op::Write(0x20c3c, 0x200),
            Op::Delay(1),
            Op::Write(0x20704, 0),
        ]
    );
    kt_assert_eq!(
        &io.ops[14..21],
        &[
            Op::Write(0x11a00, 0x21c86900),
            Op::Write(0x11a04, 0xe4e433),
            Op::Write(0x11a08, 0x39390cc9),
            Op::Write(0x11a0c, 0x4e433240),
            Op::Write(0x11a10, 0x90cc900e),
            Op::Write(0x11a14, 0x240393),
            Op::Write(0x11a18, 0x201c8600),
        ]
    );
    let n = io.ops.len();
    kt_assert_eq!(
        &io.ops[n - 12..],
        &[
            Op::Write(0x9c30, 3),
            Op::Write(0x11440, 0x6d),
            Op::Write(0x210fc, 0x2000000),
            Op::Write(0x210fc, 0),
            Op::Write(0x22800, 2),
            Op::Write(0x22900, 2),
            Op::Write(0x2e610, 0),
            Op::Write(0x2e710, 0),
            Op::Write(0x20704, 2),
            Op::Write(0x20520, 0),
            Op::Write(0x20c3c, 0),
            Op::Resume(0xa5a7f123),
        ]
    );
    // PHY1/non-DBCC repeats the PHY0 BB fields, while TX MAC-table writes
    // occur only once. RX-path nss and ctrl_trx_path nss are both preserved.
    kt_assert_eq!(
        io.ops
            .iter()
            .filter(|op| matches!(op, Op::Write(0x209a4, _)))
            .count(),
        2
    );
    kt_assert_eq!(
        io.ops
            .iter()
            .filter(|op| matches!(op, Op::Write(0x11a00, _)))
            .count(),
        1
    );
    kt_assert_eq!(
        io.ops
            .iter()
            .filter(|op| matches!(op, Op::Write(0x20418, _)))
            .count(),
        8
    );
    kt_assert_eq!(
        io.ops
            .iter()
            .filter(|op| matches!(op, Op::Write(0x2e60c, _)))
            .count(),
        4
    );
    kt_assert_eq!(io.words.get(&0x26b54).copied(), Some(3));
    kt_assert_eq!(io.words.get(&0x26b50).copied(), Some(0xc000));
    kt_assert_eq!(owner.config, Some(Config { tx: 3, rx: 3 }));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_txrx_path_source_bracket_and_scc_duplicate_writes
);
fn smoke_rtw8922a_txrx_paths_literal_antennas_and_first_error_ownership() -> TestResult {
    for (path, word, limit) in [(1, 0x21c82900, 0), (2, 0x21c04900, 0), (3, 0x21c86900, 1)] {
        let mut io = Model::new();
        let mut owner = Paths::default();
        // SAFETY: inert source profile per actual antenna-path branch.
        let result = unsafe { owner.configure(&mut io, Config { tx: path, rx: path }, Band::Ghz5) };
        kt_assert_eq!(ready(result), Some(Ok(())));
        kt_assert_eq!(io.words.get(&0x11a00).copied(), Some(word));
        kt_assert_eq!(io.words.get(&0x20418).copied().unwrap() & 0x300, limit << 8);
        kt_assert_eq!(io.words.get(&0x20520).copied(), Some(1)); // source 5GHz leaves CCK disabled
    }
    let mut io = Model::new();
    let mut owner = Paths::default();
    // SAFETY: inert complete source program bounds the failure matrix.
    let result = unsafe { owner.configure(&mut io, Config { tx: 3, rx: 3 }, Band::Ghz2) };
    kt_assert_eq!(ready(result), Some(Ok(())));
    for at in 1..=io.count {
        let mut bad = Model::new();
        bad.fail_at = Some(at);
        let mut owner = Paths::default();
        // SAFETY: independent inert first-error model.
        let result = unsafe { owner.configure(&mut bad, Config { tx: 3, rx: 3 }, Band::Ghz2) };
        kt_assert!(matches!(ready(result), Some(Err(_))));
        kt_assert_eq!(owner.state(), State::Busy);
        kt_assert_eq!(owner.config, None);
        let before = bad.ops.len();
        // SAFETY: same failed inert owner must refuse all later effects.
        let retry = unsafe { owner.configure(&mut bad, Config { tx: 3, rx: 3 }, Band::Ghz2) };
        kt_assert_eq!(ready(retry), Some(Err(Error::Terminal)));
        kt_assert_eq!(bad.ops.len(), before);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_txrx_paths_literal_antennas_and_first_error_ownership
);

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
#[derive(Clone, Debug, PartialEq, Eq)]
enum Op {
    Write(u32, u32),
    Delay(u64),
}
#[derive(Clone, Default)]
struct Model {
    words: BTreeMap<u32, u32>,
    rf: BTreeMap<(u8, u8), u32>,
    ops: Vec<Op>,
    now: u64,
    accesses: usize,
    fail_at: Option<usize>,
    failed: bool,
    pause: bool,
    busy: bool,
    no_done: bool,
}
impl Model {
    fn access(&mut self) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Access);
        }
        self.accesses += 1;
        if self.fail_at == Some(self.accesses) {
            self.failed = true;
            return Err(Error::Access);
        }
        Ok(())
    }
    fn word(&self, a: u32) -> u32 {
        self.words.get(&a).copied().unwrap_or(0)
    }
}
impl Io for Model {
    fn read8(&mut self, _: u32) -> Result<u8, Error> {
        Err(Error::Unsupported)
    }
    fn read16(&mut self, _: u32) -> Result<u16, Error> {
        Err(Error::Unsupported)
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn read32(&mut self, a: u32) -> Result<u32, Error> {
        self.access()?;
        let v = self.word(a);
        Ok(if self.busy && [0x22c24, 0x22d24].contains(&a) {
            v | 0x2000_0000
        } else {
            v
        })
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), Error> {
        self.access()?;
        self.ops.push(Op::Write(a, v));
        let old = self.word(a);
        self.words.insert(a, v);
        for path in 0..2u8 {
            let p = usize::from(path);
            if a == [0x22adc, 0x22bdc][p] && old & 4 == 0 && v & 4 != 0 && !self.no_done {
                let address = ((v >> 4) & 0xff) as u8;
                let data = self.rf.get(&(path, address)).copied().unwrap_or(0);
                self.words.insert([0x22c24, 0x22d24][p], 0x8000_0000 | data);
            }
            if a == [0x22ae0, 0x22be0][p] {
                self.rf.insert((path, v as u8), (v >> 8) & 0xfffff);
            }
        }
        Ok(())
    }
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn delay_us(&mut self, us: u64) {
        self.now += us;
        self.ops.push(Op::Delay(us));
        if self.pause {
            core::future::pending::<()>().await;
        }
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, Error> {
        Err(Error::Unsupported)
    }
}
fn run<F: Future>(future: F) -> Option<F::Output> {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}
fn write(
    rf: &mut Rf,
    io: &mut Model,
    path: u8,
    address: u32,
    mask: u32,
    value: u32,
) -> Option<Result<(), Error>> {
    // SAFETY: exclusively owned inert source HWSI model; no real RF/DMA or
    // producer exists, and the model cannot create a native qualification.
    let future = unsafe { rf.write(io, path, address, mask, value) };
    run(future)
}
fn smoke_rtw8922a_rf_v2_literal_hwsi_partial_and_direct_programs() -> TestResult {
    let mut io = Model::default();
    io.rf.insert((1, 0x60), 0xabcde);
    let mut rf = Rf::default();
    kt_assert_eq!(write(&mut rf, &mut io, 1, 0x60, 0xf00, 5), Some(Ok(())));
    kt_assert_eq!(
        io.ops,
        vec![
            Op::Write(0x22bdc, 1),
            Op::Write(0x22bdc, 0x601),
            Op::Write(0x22bdc, 0x605),
            Op::Delay(2),
            Op::Write(0x22bdc, 0x604),
            Op::Write(0x22be0, 0x0ab5_de60)
        ]
    );
    kt_assert_eq!(io.rf.get(&(1, 0x60)), Some(&0xab5de));
    kt_assert_eq!(rf.state(), State::Idle);
    let mut io = Model::default();
    kt_assert_eq!(
        write(&mut Rf::default(), &mut io, 0, 0x60, 0xfffff, 0x12345),
        Some(Ok(()))
    );
    kt_assert_eq!(io.ops, vec![Op::Write(0x22ae0, 0x0123_4560)]);
    let mut io = Model::default();
    io.words.insert(0x2e154, 0xa000_005a);
    kt_assert_eq!(
        write(&mut Rf::default(), &mut io, 0, 0x10055, 0xfffff, 0x12345),
        Some(Ok(()))
    );
    kt_assert_eq!(io.ops, vec![Op::Write(0x2e154, 0xa001_2345), Op::Delay(1)]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_rf_v2_literal_hwsi_partial_and_direct_programs
);
fn smoke_rtw8922a_rf_v2_first_error_timeout_and_cancel_are_terminal() -> TestResult {
    let mut reference = Model::default();
    reference.rf.insert((1, 0x60), 0xabcde);
    let initial = reference.clone();
    kt_assert_eq!(
        write(&mut Rf::default(), &mut reference, 1, 0x60, 0xf00, 5),
        Some(Ok(()))
    );
    for at in 1..=reference.accesses {
        let mut io = initial.clone();
        io.fail_at = Some(at);
        let mut rf = Rf::default();
        kt_assert_eq!(
            write(&mut rf, &mut io, 1, 0x60, 0xf00, 5),
            Some(Err(Error::Access))
        );
        let effects = io.ops.len();
        kt_assert_eq!(rf.state(), State::Terminal);
        kt_assert_eq!(
            write(&mut rf, &mut io, 1, 0x60, 0xf00, 5),
            Some(Err(Error::Terminal))
        );
        kt_assert_eq!(io.ops.len(), effects);
    }
    let mut busy = Model {
        busy: true,
        ..Model::default()
    };
    let mut rf = Rf::default();
    kt_assert_eq!(
        write(&mut rf, &mut busy, 0, 0x60, 0xfffff, 1),
        Some(Err(Error::Timeout))
    );
    kt_assert!(!busy.ops.iter().any(|op| matches!(op, Op::Write(..))));
    let mut timeout = Model {
        no_done: true,
        ..Model::default()
    };
    let mut rf = Rf::default();
    kt_assert_eq!(
        write(&mut rf, &mut timeout, 1, 0x60, 0xf00, 5),
        Some(Err(Error::Timeout))
    );
    kt_assert_eq!(timeout.ops.last(), Some(&Op::Write(0x22bdc, 0x604)));
    kt_assert_eq!(rf.state(), State::Terminal);
    let mut paused = initial;
    paused.pause = true;
    let mut rf = Rf::default();
    kt_assert_eq!(write(&mut rf, &mut paused, 1, 0x60, 0xf00, 5), None);
    kt_assert_eq!(rf.state(), State::Busy);
    let effects = paused.ops.len();
    kt_assert_eq!(
        write(&mut rf, &mut paused, 1, 0x60, 0xf00, 5),
        Some(Err(Error::Terminal))
    );
    kt_assert_eq!(paused.ops.len(), effects);
    for (path, address, mask) in [
        (2, 0x60, 0xfffff),
        (0, 0x100, 0xfffff),
        (0, 0x60, 0),
        (0, 0x60, 0x100000),
    ] {
        let mut io = Model::default();
        kt_assert_eq!(
            write(&mut Rf::default(), &mut io, path, address, mask, 0),
            Some(Err(Error::Unsupported))
        );
        kt_assert!(io.ops.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_rf_v2_first_error_timeout_and_cancel_are_terminal
);

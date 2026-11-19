// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
use super::*;
use alloc::vec;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
struct Model {
    bytes: Vec<u8>,
    writes: Vec<(u8, u32, u32)>,
    commands: Vec<(link::LinkCmd, Vec<u8>)>,
    calls: usize,
    fail: Option<usize>,
    hold: bool,
}
impl Model {
    fn new() -> Self {
        let mut bytes = vec![0; 0x40000];
        bytes[0x1040c..0x10410].copy_from_slice(&0x77770000u32.to_le_bytes());
        bytes[0x9d00..0x9d04].copy_from_slice(&0xf3fu32.to_le_bytes());
        bytes[0x9d04] = 3;
        Self {
            bytes,
            writes: Vec::new(),
            commands: Vec::new(),
            calls: 0,
            fail: None,
            hold: false,
        }
    }
    fn check(&mut self) -> Result<(), power::Error> {
        self.calls += 1;
        if self.fail.is_some_and(|at| self.calls >= at) {
            Err(power::Error::Access)
        } else {
            Ok(())
        }
    }
}
impl Io for Model {
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        self.check()?;
        Ok(self.bytes[a as usize])
    }
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        self.check()?;
        Ok(u16::from_le_bytes(
            self.bytes[a as usize..a as usize + 2].try_into().unwrap(),
        ))
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.check()?;
        Ok(u32::from_le_bytes(
            self.bytes[a as usize..a as usize + 4].try_into().unwrap(),
        ))
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        self.check()?;
        self.writes.push((1, a, u32::from(v)));
        self.bytes[a as usize] = v;
        Ok(())
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), power::Error> {
        self.check()?;
        self.writes.push((2, a, u32::from(v)));
        self.bytes[a as usize..a as usize + 2].copy_from_slice(&v.to_le_bytes());
        Ok(())
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.check()?;
        self.writes.push((4, a, v));
        self.bytes[a as usize..a as usize + 4].copy_from_slice(&v.to_le_bytes());
        Ok(())
    }
    fn now_us(&self) -> u64 {
        0
    }
    async fn delay_us(&mut self, us: u64) {
        assert_eq!(us, 20);
        if self.hold {
            core::future::pending::<()>().await;
        }
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl Interface for Model {
    fn current(&mut self) -> Result<(), power::Error> {
        self.check()
    }
    async fn command(&mut self, c: link::LinkCmd, b: &[u8]) -> Result<(), power::Error> {
        self.check()?;
        self.commands.push((c, b.to_vec()));
        Ok(())
    }
}
fn ready<T>(f: impl Future<Output = T>) -> Option<T> {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}
fn smoke_rtw8922a_source_mlme_no_link_uses_be_widths_versions_and_exact_ack_flags() -> TestResult {
    for (version, cam_len) in [([0, 35, 83, 255], 60), ([0, 35, 84, 0], 64)] {
        let mut io = Model::new();
        let mut owner = Controller::default();
        kt_assert_eq!(
            // SAFETY: the sole controller borrows bounded private register
            // RAM and retained command bytes for this complete poll. There
            // are no physical rings, peer or RF/firmware readiness receipts.
            ready(unsafe {
                owner.initialize(&mut io, [2, 1, 2, 3, 4, 5], Features::fixture(version))
            }),
            Some(Ok(()))
        );
        kt_assert_eq!(owner.state(), State::Passive);
        kt_assert_eq!(io.read32(0x1040c), Ok(0x700500a0)); // halfword1040e survives overlapping word update
        kt_assert_eq!(io.read32(0x9d00), Ok(0x700));
        kt_assert_eq!(io.read32(0x9d04), Ok(0));
        kt_assert_eq!(io.read16(0x10814), Ok(0x2ff));
        kt_assert!(io.writes.contains(&(2, 0x1040e, 0x7005)));
        kt_assert!(io.writes.contains(&(1, 0x10590, 0)));
        kt_assert!(io
            .writes
            .iter()
            .all(|(_, a, _)| *a != 0x10000 && *a != 0xb010 && *a < 0x14000));
        let commands = io
            .commands
            .iter()
            .map(|(c, _)| (c.cmd.cat, c.cmd.class, c.cmd.func, c.rec_ack, c.done_ack))
            .collect::<Vec<_>>();
        kt_assert_eq!(
            commands,
            vec![
                (1, 12, 2, false, true),
                (1, 12, 2, false, true),
                (1, 9, 0x28, true, false),
                (1, 8, 4, false, true),
                (1, 8, 0, false, true),
                (1, 6, 0, false, true),
                (1, 5, 0x11, false, true),
                (1, 5, 0xc, false, false)
            ]
        );
        kt_assert_eq!(&io.commands[0].1, &1u32.to_le_bytes());
        kt_assert_eq!(&io.commands[1].1, &0x01004001u32.to_le_bytes());
        kt_assert_eq!(io.commands[5].1.len(), cam_len);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_source_mlme_no_link_uses_be_widths_versions_and_exact_ack_flags
);
fn smoke_rtw8922a_source_mlme_refusal_error_and_pending_delay_drop_cannot_retry() -> TestResult {
    let features = Features::fixture([0, 35, 84, 0]);
    let mut good = Model::new();
    let mut owner = Controller::default();
    kt_assert_eq!(
        // SAFETY: private bounded RAM and a sole fresh controller model
        // source register/command order only; all bytes remain owned and no
        // native RF, DMA or MLME admission is supplied by this model.
        ready(unsafe { owner.initialize(&mut good, [2, 1, 2, 3, 4, 5], features) }),
        Some(Ok(()))
    );
    for at in 1..=good.calls {
        let mut io = Model::new();
        io.fail = Some(at);
        let mut owner = Controller::default();
        kt_assert!(matches!(
            // SAFETY: this fresh controller exclusively borrows the bounded
            // RAM/command model. Failure keeps its original Busy state and
            // retained bytes; there is no real device or competing producer.
            ready(unsafe { owner.initialize(&mut io, [2, 1, 2, 3, 4, 5], features) }),
            Some(Err(_))
        ));
        kt_assert_eq!(owner.state(), State::Busy);
        let writes = io.writes.len();
        let cmds = io.commands.len();
        kt_assert_eq!(
            // SAFETY: the same failed Busy owner and RAM mappings remain
            // retained; the replay must reject before any modeled mutation.
            ready(unsafe { owner.initialize(&mut io, [2, 1, 2, 3, 4, 5], features) }),
            Some(Err(power::Error::Terminal))
        );
        kt_assert_eq!((io.writes.len(), io.commands.len()), (writes, cmds));
    }
    let mut io = Model::new();
    io.hold = true;
    let mut owner = Controller::default();
    kt_assert_eq!(
        // SAFETY: ready polls once and drops the pending future while this
        // sole controller and its private RAM/command vectors remain alive.
        // No physical mapping, ACK or station readiness is inferred.
        ready(unsafe { owner.initialize(&mut io, [2, 1, 2, 3, 4, 5], features) }),
        None
    );
    kt_assert_eq!(owner.state(), State::Busy);
    kt_assert_eq!(io.commands.len(), 2); // no role/CAM/default command after drop
    let mut io = Model::new();
    io.bytes[0x10400] = 4;
    let mut owner = Controller::default();
    kt_assert_eq!(
        // SAFETY: unexpected active-port metadata is seeded in bounded
        // private RAM solely to test pre-effect refusal by this fresh owner;
        // it supplies no authority to adopt a physical or previously live BSS.
        ready(unsafe { owner.initialize(&mut io, [2, 1, 2, 3, 4, 5], features) }),
        Some(Err(power::Error::Unsupported))
    );
    kt_assert!(io.writes.iter().all(|(_, a, _)| *a != 0x10400));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_source_mlme_refusal_error_and_pending_delay_drop_cannot_retry
);

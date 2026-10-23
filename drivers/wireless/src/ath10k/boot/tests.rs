use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Debug)]
struct Buffer {
    bytes: Vec<u8>,
    dma: u64,
    completion: bool,
}
impl Buffer {
    fn new(size: usize, dma: u64, completion: bool) -> Self {
        Self {
            bytes: vec![0; size],
            dma,
            completion,
        }
    }
}
impl Memory for Buffer {
    fn len(&self) -> usize {
        self.bytes.len()
    }
    fn dma_address(&self) -> u64 {
        self.dma
    }
    fn read(&self, offset: usize) -> u8 {
        self.bytes[offset]
    }
    fn write(&mut self, offset: usize, value: u8) {
        self.bytes[offset] = value;
    }
    fn read16(&self, offset: usize) -> u16 {
        if self.completion {
            4
        } else {
            u16::from_le_bytes([self.bytes[offset], self.bytes[offset + 1]])
        }
    }
}
#[derive(Default)]
struct Io {
    values: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    complete: bool,
}
impl Ath10kMmio for Io {
    fn read32(&mut self, offset: u64) -> u32 {
        if self.complete
            && offset >= 0x34400
            && (offset - 0x34400) % 0x400 == hw::ce_off::CURRENT_SRRI
        {
            return self.values.get(&(offset - 8)).copied().unwrap_or(0);
        }
        self.values.get(&offset).copied().unwrap_or(0)
    }
    fn write32(&mut self, offset: u64, value: u32) {
        self.values.insert(offset, value);
        self.writes.push((offset, value));
    }
}
fn rig(complete: bool) -> (Resources<Buffer>, Io) {
    let mut io = Io {
        complete,
        ..Io::default()
    };
    let make = |pipe, direction, dma| {
        Ring::new(
            Buffer::new(16, dma, complete),
            HwRev::Qca6174,
            pipe,
            2,
            direction,
        )
        .unwrap()
    };
    let mut resources = Resources {
        tx: make(0, Direction::Source, 0x100000),
        rx: make(1, Direction::Destination, 0x101000),
        diag_tx: make(7, Direction::Source, 0x102000),
        diag_rx: make(7, Direction::Destination, 0x103000),
        request: Buffer::new(256, 0x104000, false),
        response: Buffer::new(2048, 0x105000, false),
        diag: Buffer::new(2048, 0x106000, false),
    };
    for (ring, pipe) in [
        (&mut resources.tx, 0),
        (&mut resources.rx, 1),
        (&mut resources.diag_tx, 7),
        (&mut resources.diag_rx, 7),
    ] {
        ring.initialize(&mut io, HwRev::Qca6174, pipe, 2048)
            .unwrap();
    }
    io.writes.clear();
    (resources, io)
}
fn once<F: Future>(future: F) -> Poll<F::Output> {
    let mut future = pin!(future);
    future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
}

fn smoke_ath10k_bmi_cancel_after_publication_retains_bounce_ownership() -> TestResult {
    let (mut resources, mut io) = rig(false);
    let mut poisoned = false;
    let mut response = [0; 4];
    if !matches!(
        once(resources.bmi_exchange(&mut io, &mut poisoned, &[8, 0, 0, 0], &mut response)),
        Poll::Pending
    ) || !poisoned
        || io.values.get(&(0x34400 + hw::ce_off::SR_WR_INDEX)) != Some(&1)
        || io.values.get(&(0x34800 + hw::ce_off::DR_WR_INDEX)) != Some(&1)
    {
        return TestResult::Fail("BMI did not publish actual CE descriptors before cancellation");
    }
    let retained = resources.request.bytes.clone();
    let publications = io.writes.len();
    if once(resources.bmi_exchange(&mut io, &mut poisoned, &[1, 2, 3, 4], &mut response))
        != Poll::Ready(Err(BmiError::BadResponse))
        || resources.request.bytes != retained
        || io.writes.len() != publications
    {
        return TestResult::Fail(
            "cancelled BMI overwrote device-owned bounce bytes or republished CE",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/boot",
    smoke_ath10k_bmi_cancel_after_publication_retains_bounce_ownership
);

fn smoke_ath10k_diag_cancel_preserves_inflight_write_and_poison() -> TestResult {
    let (mut resources, mut io) = rig(false);
    let mut poisoned = false;
    if !matches!(
        once(resources.diag_exchange(&mut io, &mut poisoned, 0x100000, &mut [1; 4], true)),
        Poll::Pending
    ) || !poisoned
        || io.values.get(&(0x36000 + hw::ce_off::SR_WR_INDEX)) != Some(&1)
        || io.values.get(&(0x36000 + hw::ce_off::DR_WR_INDEX)) != Some(&1)
    {
        return TestResult::Fail("diagnostic did not publish source/destination CE descriptors");
    }
    let retained = resources.diag.bytes.clone();
    let publications = io.writes.len();
    if once(resources.diag_exchange(&mut io, &mut poisoned, 0x100000, &mut [2; 4], true))
        != Poll::Ready(Err(BmiError::BadResponse))
        || resources.diag.bytes != retained
        || io.writes.len() != publications
    {
        return TestResult::Fail("cancelled CE7 write changed still-owned diagnostic memory");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/boot",
    smoke_ath10k_diag_cancel_preserves_inflight_write_and_poison
);

fn smoke_ath10k_boot_clears_poison_only_after_validated_completion() -> TestResult {
    let (mut resources, mut io) = rig(true);
    let mut poisoned = false;
    let mut response = [0; 4];
    if once(resources.bmi_exchange(&mut io, &mut poisoned, &[8, 0, 0, 0], &mut response))
        != Poll::Ready(Ok(4))
        || poisoned
    {
        return TestResult::Fail(
            "terminal BMI source/RX completion did not release transaction poison",
        );
    }
    if once(resources.diag_exchange(&mut io, &mut poisoned, 0x100000, &mut [2; 4], true))
        != Poll::Ready(Ok(()))
        || poisoned
    {
        return TestResult::Fail(
            "terminal diagnostic completion did not release transaction poison",
        );
    }
    let mut short = [0; 2];
    if once(resources.bmi_exchange(&mut io, &mut poisoned, &[8, 0, 0, 0], &mut short))
        != Poll::Ready(Err(BmiError::BadResponse))
        || !poisoned
    {
        return TestResult::Fail(
            "malformed completed response incorrectly reopened boot transport",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/boot",
    smoke_ath10k_boot_clears_poison_only_after_validated_completion
);

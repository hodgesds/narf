use super::*;
use alloc::{collections::BTreeMap, rc::Rc, vec, vec::Vec};
use core::{
    cell::RefCell,
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Clone, Debug)]
struct Buffer {
    address: u64,
    bytes: Rc<RefCell<Vec<u8>>>,
}
impl Memory for Buffer {
    fn len(&self) -> usize {
        self.bytes.borrow().len()
    }
    fn dma_address(&self) -> u64 {
        self.address
    }
    fn read(&self, i: usize) -> u8 {
        self.bytes.borrow()[i]
    }
    fn write(&mut self, i: usize, b: u8) {
        self.bytes.borrow_mut()[i] = b;
    }
}
#[derive(Default)]
struct Io {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
}
impl Ath10kMmio for Io {
    fn read32(&mut self, r: u64) -> u32 {
        *self.regs.get(&r).unwrap_or(&0)
    }
    fn write32(&mut self, r: u64, v: u32) {
        self.regs.insert(r, v);
        self.writes.push((r, v));
    }
}
fn once<F: Future>(f: F) -> Poll<F::Output> {
    let mut f = core::pin::pin!(f);
    f.as_mut().poll(&mut Context::from_waker(Waker::noop()))
}
fn allocate_runtime(hw: HwRev) -> (Runtime<Buffer>, Vec<Buffer>) {
    let mut allocations = Vec::new();
    let mut address = 0x100000;
    let runtime = Runtime::allocate(hw, |n| {
        let buffer = Buffer {
            address,
            bytes: Rc::new(RefCell::new(vec![0; n])),
        };
        address += n.next_multiple_of(4096) as u64;
        allocations.push(buffer.clone());
        Ok(buffer)
    })
    .unwrap();
    (runtime, allocations)
}
fn smoke_ath10k_runtime_ce_profiles_receive_refill() -> TestResult {
    for (hw, want) in [
        (HwRev::Qca6174, vec![2, 3, 4]),
        (HwRev::Qca9377, vec![2, 3, 4]),
        (HwRev::Qca988x, vec![2, 3, 4, 5]),
        (HwRev::Qca9984, vec![2, 3, 4, 5, 8]),
    ] {
        let (mut runtime, allocations) = allocate_runtime(hw);
        if runtime.pipes.iter().map(|p| p.number).collect::<Vec<_>>() != want {
            return TestResult::Fail("runtime host CE5/CE8 overrides differ from Linux");
        }
        let mut io = Io::default();
        if runtime.initialize(&mut io, hw).is_err() {
            return TestResult::Fail("runtime CE initialization failed");
        }
        let ce4 = hw.registers().unwrap().ce_base(4).unwrap();
        if io.regs[&(ce4 + crate::ath10k::hw::ce_off::SR_SIZE)] != 8192 {
            return TestResult::Fail("HTT CE4 must retain all8192 Linux source slots");
        }
        let ce2 = hw.registers().unwrap().ce_base(2).unwrap();
        let desc = io.regs[&(ce2 + crate::ath10k::hw::ce_off::DR_BASE_LO)] as u64;
        let descriptors = allocations.iter().find(|m| m.address == desc).unwrap();
        let target = {
            let mut d = descriptors.bytes.borrow_mut();
            d[4..6].copy_from_slice(&3u16.to_le_bytes());
            u32::from_le_bytes(d[..4].try_into().unwrap()) as u64
        };
        let payload = allocations.iter().find(|m| m.address == target).unwrap();
        payload.bytes.borrow_mut()[..3].copy_from_slice(b"abc");
        if runtime.poll(&mut io).is_err()
            || runtime.received.pop_front() != Some((2, b"abc".to_vec()))
        {
            return TestResult::Fail("device DMA CE2 reply did not reach owned payload queue");
        }
        if io.regs[&(ce2 + crate::ath10k::hw::ce_off::DR_WR_INDEX)] != 2 {
            return TestResult::Fail(
                "CE2 receive allocation not reposted after terminal completion",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/hif",
    smoke_ath10k_runtime_ce_profiles_receive_refill
);

fn smoke_ath10k_runtime_ce_cancel_after_publication() -> TestResult {
    let (mut runtime, _) = allocate_runtime(HwRev::Qca6174);
    let mut io = Io::default();
    runtime.initialize(&mut io, HwRev::Qca6174).unwrap();
    let pipe = runtime.pipes.iter_mut().find(|p| p.number == 3).unwrap();
    let mut poisoned = false;
    if once(send(
        &mut pipe.ring,
        &mut pipe.buffer,
        &mut io,
        &mut poisoned,
        b"published",
    )) != Poll::Pending
        || !poisoned
    {
        return TestResult::Fail("runtime CE3 did not publish before cancelled await");
    }
    let bytes = pipe.buffer.bytes.borrow().clone();
    let writes = io.writes.len();
    if once(send(
        &mut pipe.ring,
        &mut pipe.buffer,
        &mut io,
        &mut poisoned,
        b"overwrite",
    )) != Poll::Ready(Err(BmiError::BadResponse))
        || *pipe.buffer.bytes.borrow() != bytes
        || io.writes.len() != writes
    {
        return TestResult::Fail("cancelled runtime CE3 reused device-owned DMA or doorbell");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/hif",
    smoke_ath10k_runtime_ce_cancel_after_publication
);

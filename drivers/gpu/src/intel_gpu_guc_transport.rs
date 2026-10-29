//! Xe-LPG graphics-GuC CT ownership and MMIO registration.
//!
//! References: MIT i915 `intel_guc.c`, `intel_guc_ct.c`, `intel_guc_reg.h`
//! and GuC actions/KLV/message ABI headers. The GT owner supplies coherent
//! GGTT memory, holds forcewake and serializes the graphics-GuC mailbox. This
//! does not boot firmware, program WOPCM or register a render context.

use crate::intel_gpu::Generation;
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_gt::{GtPlatform, GUC_GGTT_MIN};
use crate::intel_gpu_guc::{CtMemory, CtReceiver, CtSender, GuCError, GuCMessage};
use crate::intel_gpu_rcs::{GpuAllocator, GpuBacking, SubmitError};
use alloc::sync::Arc;
use core::mem::ManuallyDrop;
use core::sync::atomic::{fence, Ordering};
use core::task::Poll;

const SCRATCH: u64 = 0x190240;
const NOTIFY: u64 = 0x1901f0;
const GUC_STATUS: u64 = 0xc000;
const MMIO_TIMEOUT_NS: u64 = 10_000_000;
const PAGES: u32 = 6;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TransportError {
    Unsupported,
    Allocation(SubmitError),
    Address,
    State,
    NotReady,
    NonCoherent,
    Timeout,
    Protocol(u32),
    Rejected(u32),
    Poisoned,
    Ct(GuCError),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TransportState {
    Allocated,
    Registering(u8),
    Enabling,
    Enabled,
    Disabling,
    Disabled,
    Lost,
}

struct SharedCtb<B: GpuBacking> {
    blob: Arc<B>,
    desc: u64,
    data: u64,
    words: u32,
}

impl<B: GpuBacking> CtMemory for SharedCtb<B> {
    fn capacity(&self) -> u32 {
        self.words
    }
    fn descriptor(&self, word: usize) -> u32 {
        assert!(word < 16);
        self.blob.read32(self.desc + word as u64 * 4)
    }
    fn set_descriptor(&self, word: usize, value: u32) {
        assert!(word < 16);
        self.blob.write32(self.desc + word as u64 * 4, value);
    }
    fn data(&self, word: u32) -> u32 {
        assert!(word < self.words);
        self.blob.read32(self.data + word as u64 * 4)
    }
    fn set_data(&self, word: u32, value: u32) {
        assert!(word < self.words);
        self.blob.write32(self.data + word as u64 * 4, value);
    }
}

struct Mailbox<M: MmioWindow> {
    mmio: M,
    request: [u32; 4],
    length: usize,
    deadline: Option<u64>,
    retries: u8,
    poisoned: bool,
}

impl<M: MmioWindow> Mailbox<M> {
    fn begin(&mut self, words: &[u32], now: u64) -> Result<(), TransportError> {
        if self.poisoned {
            return Err(TransportError::Poisoned);
        }
        if self.deadline.is_some() || words.is_empty() || words.len() > 4 || words[0] >> 28 != 0 {
            return Err(TransportError::State);
        }
        let deadline = now
            .checked_add(MMIO_TIMEOUT_NS)
            .ok_or(TransportError::Timeout)?;
        self.request[..words.len()].copy_from_slice(words);
        self.length = words.len();
        self.deadline = Some(deadline);
        self.retries = 0;
        self.publish();
        Ok(())
    }

    fn publish(&self) {
        for i in 0..self.length {
            self.mmio.write32(SCRATCH + i as u64 * 4, self.request[i]);
        }
        let _ = self.mmio.read32(SCRATCH + (self.length as u64 - 1) * 4);
        self.notify();
    }

    fn notify(&self) {
        fence(Ordering::Release);
        self.mmio.write32(NOTIFY, 1);
        let _ = self.mmio.read32(NOTIFY);
    }

    /// One bounded sample per call. BUSY/RETRY never starts a new timeout.
    fn poll(&mut self, now: u64) -> Poll<Result<u32, TransportError>> {
        let Some(deadline) = self.deadline else {
            return Poll::Ready(Err(TransportError::State));
        };
        let header = self.mmio.read32(SCRATCH);
        if now >= deadline {
            self.poisoned = true;
            self.deadline = None;
            return Poll::Ready(Err(TransportError::Timeout));
        }
        if header & (1 << 31) == 0 || (header >> 28) & 7 == 3 {
            return Poll::Pending;
        }
        fence(Ordering::Acquire);
        let result = match (header >> 28) & 7 {
            5 if self.retries < 3 => {
                self.retries += 1;
                self.publish();
                return Poll::Pending;
            }
            7 => Ok(header & 0x0fff_ffff),
            6 => Err(TransportError::Rejected(header)),
            _ => {
                self.poisoned = true;
                Err(TransportError::Protocol(header))
            }
        };
        self.deadline = None;
        Poll::Ready(result)
    }
}

/// The complete shared allocation stays pinned if this owner is dropped
/// during registration, after a timeout, or while firmware can still access
/// it. Explicit `release` succeeds only before publication or after DISABLE.
pub struct XeLpgTransport<M: MmioWindow, A: GpuAllocator> {
    mailbox: Mailbox<M>,
    resources: ManuallyDrop<CtResources<A>>,
    state: TransportState,
    released: bool,
}

struct CtResources<A: GpuAllocator> {
    allocator: A,
    blob: Arc<A::Backing>,
    sender: CtSender<SharedCtb<A::Backing>>,
    receiver: CtReceiver<SharedCtb<A::Backing>>,
}

impl<M: MmioWindow, A: GpuAllocator> core::fmt::Debug for XeLpgTransport<M, A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XeLpgTransport")
            .field("state", &self.state)
            .field("ggtt", &self.resources.blob.ggtt_offset())
            .finish_non_exhaustive()
    }
}

impl<M: MmioWindow, A: GpuAllocator> XeLpgTransport<M, A> {
    /// No MMIO is touched by allocation, including on unsupported hardware.
    pub fn allocate(generation: Generation, mmio: M, allocator: A) -> Result<Self, TransportError> {
        Self::allocate_for_platform(GtPlatform::Integrated(generation), mmio, allocator)
    }

    pub fn allocate_for_platform(
        platform: GtPlatform,
        mmio: M,
        mut allocator: A,
    ) -> Result<Self, TransportError> {
        if platform.guc().is_none() {
            return Err(TransportError::Unsupported);
        }
        let backing = allocator.alloc(PAGES).map_err(TransportError::Allocation)?;
        if platform.is_discrete() && !backing.coherent_for_device() {
            allocator.free(backing);
            return Err(TransportError::NonCoherent);
        }
        let base = backing.ggtt_offset();
        if base < GUC_GGTT_MIN
            || base % 4096 != 0
            || backing.size_pages() != PAGES
            || base
                .checked_add(PAGES * 4096)
                .is_none_or(|end| end > 0xfee0_0000)
        {
            allocator.free(backing);
            return Err(TransportError::Address);
        }
        backing.zero_fill();
        let blob = Arc::new(backing);
        // Fresh zeroed descriptors, fixed capacities and validated extents:
        // construction cannot observe firmware-owned state yet.
        let sender = CtSender::new(SharedCtb {
            blob: blob.clone(),
            desc: 0,
            data: 0x1000,
            words: 1024,
        })
        .expect("fresh H2G CTB");
        let receiver = CtReceiver::new(SharedCtb {
            blob: blob.clone(),
            desc: 0x800,
            data: 0x2000,
            words: 4096,
        })
        .expect("fresh G2H CTB");
        Ok(Self {
            mailbox: Mailbox {
                mmio,
                request: [0; 4],
                length: 0,
                deadline: None,
                retries: 0,
                poisoned: false,
            },
            resources: ManuallyDrop::new(CtResources {
                allocator,
                blob,
                sender,
                receiver,
            }),
            state: TransportState::Allocated,
            released: false,
        })
    }

    pub fn state(&self) -> TransportState {
        self.state
    }

    fn register(&mut self, index: u8, now: u64) -> Result<(), TransportError> {
        let base = self.resources.blob.ggtt_offset();
        // GuC requires receive registration before send registration. Address
        // KLVs have two value dwords even when the GGTT address fits in u32.
        let (key, len, value) = match index {
            0 => (0x0906, 2, base + 0x800),
            1 => (0x0905, 2, base + 0x2000),
            2 => (0x0907, 1, 0x4000),
            3 => (0x0903, 2, base),
            4 => (0x0902, 2, base + 0x1000),
            5 => (0x0904, 1, 0x1000),
            _ => return Err(TransportError::State),
        };
        self.state = TransportState::Registering(index);
        self.mailbox
            .begin(&[0x0508, (key << 16) | len, value, 0], now)
    }

    pub fn begin_enable(&mut self, now: u64) -> Result<(), TransportError> {
        if self.state != TransportState::Allocated {
            return Err(TransportError::State);
        }
        let status = self.mailbox.mmio.read32(GUC_STATUS);
        if status & 1 != 0 || status & 0xc000_0000 != 0x8000_0000 || (status >> 8) & 0xff != 0xf0 {
            return Err(TransportError::NotReady);
        }
        self.register(0, now)
    }

    pub fn begin_disable(&mut self, now: u64) -> Result<(), TransportError> {
        if !matches!(self.state, TransportState::Enabled | TransportState::Lost)
            || self.mailbox.poisoned
        {
            return Err(TransportError::State);
        }
        self.state = TransportState::Disabling;
        if let Err(error) = self.mailbox.begin(&[0x4509, 0], now) {
            self.state = TransportState::Lost;
            return Err(error);
        }
        Ok(())
    }

    /// Advance a registration/enable/disable transaction without spinning.
    /// Dropping an async waiter leaves this transaction and memory owned here.
    pub fn poll_transition(&mut self, now: u64) -> Poll<Result<TransportState, TransportError>> {
        if !matches!(
            self.state,
            TransportState::Registering(_) | TransportState::Enabling | TransportState::Disabling
        ) {
            return Poll::Ready(Err(TransportError::State));
        }
        let value = match self.mailbox.poll(now) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(value)) => value,
            Poll::Ready(Err(error)) => {
                self.state = TransportState::Lost;
                return Poll::Ready(Err(error));
            }
        };
        let next = match self.state {
            TransportState::Registering(index) if value == 1 => {
                if index < 5 {
                    self.register(index + 1, now)
                } else {
                    self.state = TransportState::Enabling;
                    self.mailbox.begin(&[0x4509, 1], now)
                }
            }
            TransportState::Enabling if value == 0 => {
                self.state = TransportState::Enabled;
                return Poll::Ready(Ok(self.state));
            }
            TransportState::Disabling if value == 0 => {
                self.state = TransportState::Disabled;
                return Poll::Ready(Ok(self.state));
            }
            _ => Err(TransportError::Protocol(value)),
        };
        if let Err(error) = next {
            self.state = TransportState::Lost;
            return Poll::Ready(Err(error));
        }
        Poll::Pending
    }

    /// Timer-driven bridge for executor callers. Holds no IRQ lock across an
    /// await; cancellation does not reset the mailbox or reclaim CT memory.
    pub async fn wait_transition(&mut self) -> Result<TransportState, TransportError> {
        loop {
            if let Poll::Ready(result) = self.poll_transition(narf_time::monotonic_ns()) {
                return result;
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(50).as_instant()).await;
        }
    }

    /// The action owner reserves/matches CT fences. A CT reply acknowledges an
    /// action; it is never a render-job completion or permission to free BOs.
    pub fn send(
        &mut self,
        id: u16,
        action: u16,
        data0: u16,
        payload: &[u32],
        fast: bool,
    ) -> Result<(), TransportError> {
        if self.state != TransportState::Enabled {
            return Err(TransportError::State);
        }
        if let Err(error) = self
            .resources
            .sender
            .request(id, action, data0, payload, fast)
        {
            if error != GuCError::Full && error != GuCError::Message {
                self.state = TransportState::Lost;
            }
            return Err(TransportError::Ct(error));
        }
        self.mailbox.notify();
        Ok(())
    }

    pub fn receive(&mut self) -> Result<Option<GuCMessage>, TransportError> {
        if self.state != TransportState::Enabled {
            return Err(TransportError::State);
        }
        self.resources.receiver.receive().map_err(|error| {
            self.state = TransportState::Lost;
            TransportError::Ct(error)
        })
    }

    /// Return an unsafe-to-release owner intact to its GT reset path.
    // Keep the pinned owner inline: refusal must not allocate or drop it.
    #[allow(clippy::result_large_err)]
    pub fn release(mut self) -> Result<(), Self> {
        if !matches!(
            self.state,
            TransportState::Allocated | TransportState::Disabled
        ) {
            return Err(self);
        }
        self.free_memory();
        Ok(())
    }

    /// # Safety
    /// The GT owner proved GuC and all DMA users stopped, invalidated stale
    /// CT addresses, and will not issue any mailbox/CT access through this owner.
    pub unsafe fn release_after_reset(mut self) {
        self.free_memory();
    }

    fn free_memory(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        // SAFETY: resources are taken exactly once. Only pre-publication,
        // acknowledged DISABLE, or the unsafe proven-reset path reaches here.
        let CtResources {
            mut allocator,
            blob,
            sender,
            receiver,
        } = unsafe { ManuallyDrop::take(&mut self.resources) };
        drop(sender);
        drop(receiver);
        match Arc::try_unwrap(blob) {
            Ok(backing) => allocator.free(backing),
            Err(_) => unreachable!("private CT memory has no outside owners"),
        }
    }
}

impl<M: MmioWindow, A: GpuAllocator> Drop for XeLpgTransport<M, A> {
    fn drop(&mut self) {
        if matches!(
            self.state,
            TransportState::Allocated | TransportState::Disabled
        ) {
            self.free_memory();
        }
        // Every other state deliberately retains allocator, CT views and
        // backing together. Even an allocator with RAII cannot unmap DMA.
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::rc::{Rc, Weak};
    use alloc::vec::Vec;
    use core::cell::{Cell, RefCell};
    use narf_kernel_test::{kernel_test_in, TestResult};

    #[derive(Clone)]
    struct Regs(Rc<RefCell<BTreeMap<u64, u32>>>, Rc<RefCell<Vec<Vec<u32>>>>);
    impl MmioWindow for Regs {
        fn read32(&self, offset: u64) -> u32 {
            *self.0.borrow().get(&offset).unwrap_or(&0)
        }
        fn write32(&self, offset: u64, value: u32) {
            self.0.borrow_mut().insert(offset, value);
            if offset == 0x1901f0 && self.read32(0x190240) & 0x8000_0000 == 0 {
                let len = if self.read32(0x190240) == 0x0508 {
                    4
                } else {
                    2
                };
                self.1
                    .borrow_mut()
                    .push((0..len).map(|i| self.read32(0x190240 + i * 4)).collect());
            }
        }
    }

    struct Backing(Rc<RefCell<Vec<u32>>>);
    impl GpuBacking for Backing {
        fn ggtt_offset(&self) -> u32 {
            0x2000_0000
        }
        fn size_pages(&self) -> u32 {
            6
        }
        fn read32(&self, byte: u64) -> u32 {
            self.0.borrow()[byte as usize / 4]
        }
        fn write32(&self, byte: u64, value: u32) {
            self.0.borrow_mut()[byte as usize / 4] = value;
        }
    }

    struct Arena {
        live: Rc<Cell<usize>>,
        memory: Rc<RefCell<Weak<RefCell<Vec<u32>>>>>,
    }
    impl GpuAllocator for Arena {
        type Backing = Backing;
        fn alloc(&mut self, pages: u32) -> Result<Backing, SubmitError> {
            if pages != 6 {
                return Err(SubmitError::OutOfMemory);
            }
            let bytes = Rc::new(RefCell::new(alloc::vec![0; 6 * 1024]));
            *self.memory.borrow_mut() = Rc::downgrade(&bytes);
            self.live.set(self.live.get() + 1);
            Ok(Backing(bytes))
        }
        fn free(&mut self, _backing: Backing) {
            self.live.set(self.live.get() - 1);
        }
        fn live_allocations(&self) -> usize {
            self.live.get()
        }
        fn live_pages(&self) -> u32 {
            self.live.get() as u32 * 6
        }
    }

    struct Model {
        regs: Regs,
        live: Rc<Cell<usize>>,
        memory: Rc<RefCell<Weak<RefCell<Vec<u32>>>>>,
    }
    impl Model {
        fn new() -> (Self, Arena) {
            let model = Self {
                regs: Regs(
                    Rc::new(RefCell::new(BTreeMap::new())),
                    Rc::new(RefCell::new(Vec::new())),
                ),
                live: Rc::new(Cell::new(0)),
                memory: Rc::new(RefCell::new(Weak::new())),
            };
            let arena = Arena {
                live: model.live.clone(),
                memory: model.memory.clone(),
            };
            (model, arena)
        }
        fn ready(&self) {
            self.regs.0.borrow_mut().insert(0xc000, 0x8000_f000);
        }
        fn reply(&self, header: u32) {
            self.regs.0.borrow_mut().insert(0x190240, header);
        }
        fn allocate(&self, arena: Arena) -> XeLpgTransport<Regs, Arena> {
            XeLpgTransport::allocate(Generation::MeteorLake, self.regs.clone(), arena).unwrap()
        }
        fn enable(&self, transport: &mut XeLpgTransport<Regs, Arena>) {
            self.ready();
            transport.begin_enable(0).unwrap();
            for i in 0..6 {
                self.reply(0xf000_0001);
                assert!(transport.poll_transition(i).is_pending());
            }
            self.reply(0xf000_0000);
            assert_eq!(
                transport.poll_transition(7),
                Poll::Ready(Ok(TransportState::Enabled))
            );
        }
    }

    fn smoke_transport_registration_and_disable() -> TestResult {
        let (model, arena) = Model::new();
        let mut transport = model.allocate(arena);
        if transport.begin_enable(0) != Err(TransportError::NotReady)
            || !model.regs.1.borrow().is_empty()
        {
            return TestResult::Fail("transport published before authenticated firmware ready");
        }
        model.enable(&mut transport);
        // Literal GuC ABI vectors: RECV first, address KLV length2, byte
        // sizes length1; finally CONTROL_CTB enable over graphics MMIO.
        if *model.regs.1.borrow()
            != alloc::vec![
                alloc::vec![0x0508, 0x0906_0002, 0x2000_0800, 0],
                alloc::vec![0x0508, 0x0905_0002, 0x2000_2000, 0],
                alloc::vec![0x0508, 0x0907_0001, 0x4000, 0],
                alloc::vec![0x0508, 0x0903_0002, 0x2000_0000, 0],
                alloc::vec![0x0508, 0x0902_0002, 0x2000_1000, 0],
                alloc::vec![0x0508, 0x0904_0001, 0x1000, 0],
                alloc::vec![0x4509, 1],
            ]
        {
            return TestResult::Fail("GuC registration wire/order mismatch");
        }
        transport.send(9, 0x1000, 0, &[0x55], true).unwrap();
        {
            let memory = model.memory.borrow().upgrade().unwrap();
            let mut words = memory.borrow_mut();
            if words[1] != 3
                || words[0x1000 / 4..0x1000 / 4 + 3] != [0x0009_0002, 0x2000_1000, 0x55]
            {
                return TestResult::Fail("production CT backing did not publish request");
            }
            words[0x2000 / 4..0x2000 / 4 + 3].copy_from_slice(&[0x0009_0002, 0xf000_0000, 0xbeef]);
            words[0x800 / 4 + 1] = 3;
        }
        let message = transport.receive().unwrap().unwrap();
        if message.fence != 9 || message.kind != 7 || message.payload != [0xbeef] {
            return TestResult::Fail("coherent receive did not decode firmware reply");
        }
        transport.begin_disable(8).unwrap();
        let mut transport = transport.release().unwrap_err();
        if model.live.get() != 1 {
            return TestResult::Fail("disable request released live CT memory");
        }
        model.reply(0xf000_0000);
        if transport.poll_transition(9) != Poll::Ready(Ok(TransportState::Disabled)) {
            return TestResult::Fail("GuC disable acknowledgment rejected");
        }
        transport.release().unwrap();
        if model.live.get() != 0 || model.memory.borrow().upgrade().is_some() {
            return TestResult::Fail("disabled CT memory leaked");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc_transport",
        smoke_transport_registration_and_disable
    );

    fn smoke_transport_timeout_quarantines() -> TestResult {
        let (model, arena) = Model::new();
        let mut transport = model.allocate(arena);
        model.ready();
        transport.begin_enable(0).unwrap();
        if transport.poll_transition(10_000_000) != Poll::Ready(Err(TransportError::Timeout)) {
            return TestResult::Fail("registration timeout not terminal for mailbox");
        }
        let mut transport = transport.release().unwrap_err();
        model.reply(0xf000_0001); // late reply cannot revive a poisoned owner
        if transport.state() != TransportState::Lost
            || model.live.get() != 1
            || transport.begin_disable(10_000_001).is_ok()
            || transport.send(1, 0x1000, 0, &[], true).is_ok()
        {
            return TestResult::Fail("timeout admitted work or reclaimed shared memory");
        }
        // SAFETY: the only modelled firmware peer is stopped; no DMA exists.
        unsafe {
            transport.release_after_reset();
        }
        if model.live.get() != 0 {
            return TestResult::Fail("reset did not release CT allocation");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc_transport",
        smoke_transport_timeout_quarantines
    );

    fn smoke_transport_rejected_key_and_retry_bound() -> TestResult {
        let (model, arena) = Model::new();
        let mut transport = model.allocate(arena);
        model.ready();
        transport.begin_enable(0).unwrap();
        model.reply(0xf000_0000); // SELF_CFG key unrecognized, not success
        if transport.poll_transition(1) != Poll::Ready(Err(TransportError::Protocol(0)))
            || model.regs.1.borrow().len() != 1
        {
            return TestResult::Fail("unrecognized KLV enabled transport");
        }
        transport.begin_disable(2).unwrap();
        model.reply(0xf000_0000);
        assert_eq!(
            transport.poll_transition(3),
            Poll::Ready(Ok(TransportState::Disabled))
        );
        transport.release().unwrap();

        let (model, arena) = Model::new();
        let mut transport = model.allocate(arena);
        model.ready();
        transport.begin_enable(0).unwrap();
        model.reply(0xb000_0000); // BUSY, no response yet
        if transport.poll_transition(1).is_ready() {
            return TestResult::Fail("BUSY completed request");
        }
        for i in 0..3 {
            model.reply(0xd000_0000);
            if transport.poll_transition(2 + i).is_ready() {
                return TestResult::Fail("bounded retry rejected");
            }
        }
        model.reply(0xd000_0000);
        if transport.poll_transition(5) != Poll::Ready(Err(TransportError::Protocol(0xd000_0000)))
            || model.regs.1.borrow().len() != 4
        {
            return TestResult::Fail("unbounded GuC retry/republication");
        }
        // SAFETY: the modelled firmware peer is stopped; no DMA exists.
        unsafe {
            transport.release_after_reset();
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc_transport",
        smoke_transport_rejected_key_and_retry_bound
    );

    fn smoke_transport_generation_gate() -> TestResult {
        let (model, arena) = Model::new();
        if !matches!(
            XeLpgTransport::allocate(Generation::TigerLake, model.regs.clone(), arena),
            Err(TransportError::Unsupported)
        ) || model.live.get() != 0
            || !model.regs.0.borrow().is_empty()
        {
            return TestResult::Fail("unsupported generation touched MMIO or allocated");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc_transport",
        smoke_transport_generation_gate
    );

    fn smoke_unpublished_transport_drop_reclaims() -> TestResult {
        let (model, arena) = Model::new();
        let transport = model.allocate(arena);
        drop(transport);
        if model.live.get() != 0 || model.memory.borrow().upgrade().is_some() {
            return TestResult::Fail("unpublished CT owner leaked memory");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc_transport",
        smoke_unpublished_transport_drop_reclaims
    );

    fn smoke_transport_corrupt_receive_retains() -> TestResult {
        let (model, arena) = Model::new();
        let mut transport = model.allocate(arena);
        model.enable(&mut transport);
        {
            let memory = model.memory.borrow().upgrade().unwrap();
            let mut words = memory.borrow_mut();
            words[0x800 / 4 + 2] = 1; // firmware reports a broken receive CTB
        }
        if transport.receive() != Err(TransportError::Ct(GuCError::DescriptorStatus(1))) {
            return TestResult::Fail("broken receive descriptor accepted");
        }
        let mut transport = transport.release().unwrap_err();
        if model.live.get() != 1
            || transport.state() != TransportState::Lost
            || transport.send(1, 0x1000, 0, &[], true).is_ok()
        {
            return TestResult::Fail("corrupt transport released memory or published work");
        }
        // CT corruption does not corrupt the independent MMIO mailbox. Its
        // successful DISABLE acknowledgment can still end CT ownership.
        transport.begin_disable(10).unwrap();
        model.reply(0xf000_0000);
        assert_eq!(
            transport.poll_transition(11),
            Poll::Ready(Ok(TransportState::Disabled))
        );
        transport.release().unwrap();
        if model.live.get() != 0 {
            return TestResult::Fail("disabled broken CT leaked");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc_transport",
        smoke_transport_corrupt_receive_retains
    );
}

use super::*;
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
include!("prepare/golden.rs");
#[derive(Default)]
struct Model {
    regs: Vec<u8>,
    trace: Vec<(u8, u16, u32)>,
    accesses: usize,
    fail: Option<usize>,
    stall: bool,
    pending: bool,
    gone: bool,
    ignore: Option<u16>,
}
#[derive(Clone)]
struct Port(Arc<IrqSafeSpinLock<Model>>);
impl Port {
    fn new() -> Self {
        let mut model = Model {
            regs: vec![0; 0x1000],
            ..Model::default()
        };
        model.regs[0x100] = 0xff;
        Self(Arc::new(IrqSafeSpinLock::new(model)))
    }
}
fn access(model: &mut Model) -> Result<(), AccessError> {
    let at = model.accesses;
    model.accesses += 1;
    if model.fail == Some(at) {
        Err(AccessError::Access)
    } else {
        Ok(())
    }
}
#[async_trait::async_trait]
impl Io for Port {
    fn read8(&self, reg: u16) -> Result<u8, AccessError> {
        let mut m = self.0.lock();
        access(&mut m)?;
        Ok(m.regs[usize::from(reg)])
    }
    fn read32(&self, reg: u16) -> Result<u32, AccessError> {
        let mut m = self.0.lock();
        access(&mut m)?;
        let at = usize::from(reg);
        if reg == 0x1e0 && m.gone {
            return Ok(u32::MAX);
        }
        if reg == 0x1e0 && !m.stall {
            m.regs[at + 3] &= 0x3f;
        }
        Ok(u32::from_le_bytes(m.regs[at..at + 4].try_into().unwrap()))
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), AccessError> {
        let mut m = self.0.lock();
        access(&mut m)?;
        m.trace.push((8, reg, u32::from(value)));
        if m.ignore != Some(reg) {
            m.regs[usize::from(reg)] = value;
        }
        Ok(())
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), AccessError> {
        let mut m = self.0.lock();
        access(&mut m)?;
        m.trace.push((32, reg, value));
        let at = usize::from(reg);
        if m.ignore != Some(reg) {
            m.regs[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        Ok(())
    }
    fn write_bytes(&self, _: u16, _: &[u8]) -> Result<(), AccessError> {
        unreachable!()
    }
    async fn delay_us(&self, _: u64) {
        let pending = self.0.lock().pending;
        if pending {
            core::future::pending::<()>().await;
        }
    }
}
struct Block {
    address: u64,
    bytes: Vec<u8>,
    drops: Arc<AtomicUsize>,
}
// SAFETY: Inert byte storage/unique synthetic DMA extents for model tests;
// the model never exposes an address to a physical device.
unsafe impl Memory for Block {
    fn address(&self) -> u64 {
        self.address
    }
    fn len(&self) -> usize {
        self.bytes.len()
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        self.bytes
            .get_mut(offset..offset + 4)
            .ok_or(Error::Memory)?
            .copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
    fn sync(&self) {}
}
impl Drop for Block {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
    }
}
fn allocated(port: Port, depth: usize, drops: Arc<AtomicUsize>) -> Prepared<Port, Block> {
    let mut address = 0x10000;
    Prepared::allocate(port, depth, |bytes| {
        address = (address + 255) & !255;
        let block = Block {
            address,
            bytes: vec![0xa5; bytes],
            drops: drops.clone(),
        };
        address += bytes as u64;
        Ok(block)
    })
    .unwrap()
}
fn word(block: &Block, offset: usize) -> u32 {
    u32::from_le_bytes(block.bytes[offset..offset + 4].try_into().unwrap())
}
pub(crate) fn smoke_rtl8188ee_distinct_linked_rings_and_rx_storage_before_publication() -> TestResult
{
    for depth in [4, 16, 256] {
        let port = Port::new();
        let drops = Arc::new(AtomicUsize::new(0));
        let owner = allocated(port.clone(), depth, drops.clone());
        if owner.tx.len() != 7 || owner.buffers.len() != depth || port.0.lock().accesses != 0 {
            return TestResult::Fail("allocation touched hardware or aliased queue resources");
        }
        for ring in &owner.tx {
            for slot in 0..depth {
                for dword in 0..16 {
                    let wanted = if dword == 10 {
                        ring.address as u32 + (((slot + 1) % depth) * 64) as u32
                    } else {
                        0
                    };
                    if word(ring, slot * 64 + dword * 4) != wanted {
                        return TestResult::Fail(
                            "linked RTL8188EE TX ring does not match trx.h DW10",
                        );
                    }
                }
            }
        }
        let receive = owner.receive.as_ref().unwrap();
        for slot in 0..depth {
            let end = if slot == depth - 1 { 1 << 30 } else { 0 };
            if word(receive, slot * 32) != 4096 | end | (1 << 31)
                || word(receive, slot * 32 + 24) != owner.buffers[slot].address as u32
                || word(receive, slot * 32 + 28) != 0
            {
                return TestResult::Fail("RTL8188EE RX OWN/EOR/address/32-bit profile mismatch");
            }
        }
        drop(owner);
        if drops.load(Ordering::Acquire) != depth + 8 {
            return TestResult::Fail("unpublished DMA storage was leaked");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtl8188ee_distinct_linked_rings_and_rx_storage_before_publication
);
pub(crate) fn smoke_rtl8188ee_fifo_llt_matches_actual_linux_and_pins_published_rings() -> TestResult
{
    let port = Port::new();
    let drops = Arc::new(AtomicUsize::new(0));
    let mut owner = allocated(port.clone(), 16, drops.clone());
    narf_scheduler::block_on(owner.prepare()).unwrap();
    let m = port.0.lock();
    let begin = m
        .trace
        .iter()
        .position(|row| *row == (8, 0x214, 1))
        .unwrap();
    if m.trace[begin..begin + LINUX_LLT.len()] != *LINUX_LLT
        || owner.phase() != Phase::Prepared
        || !owner.published
    {
        return TestResult::Fail("actual Linux 8188EE FIFO/0xab-0xaf LLT trace differs");
    }
    // Independently compiled original RTL8188EE reg.h and actual hw.c
    // init_mac base-publication order. Never share the driver's Rust map.
    for (address, ring) in LINUX_TX_BASES.iter().zip(&owner.tx) {
        if !m.trace.contains(&(32, *address, ring.address as u32)) {
            return TestResult::Fail("per-chip distinct native queue base omitted");
        }
    }
    let receive = owner.receive.as_ref().unwrap();
    if !m
        .trace
        .contains(&(32, LINUX_RX_BASE, receive.address as u32))
    {
        return TestResult::Fail("RX ring base not published at REG_RX_DESA");
    }
    if m.regs[0x301] != 255
        || m.regs[0x100] & 0xcf != 0
        || m.trace
            .iter()
            .any(|(_, reg, _)| matches!(*reg, 0x380 | 0x384 | 0x386 | 0x388 | 0x38a))
    {
        return TestResult::Fail("preparation enabled DMA or used unsupported 8192EE BD registers");
    }
    let accesses = m.accesses;
    drop(m);
    if narf_scheduler::block_on(owner.prepare()) != Err(Error::State)
        || port.0.lock().accesses != accesses
    {
        return TestResult::Fail("prepared owner replayed FIFO/descriptor publication");
    }
    drop(owner);
    if drops.load(Ordering::Acquire) != 0 {
        return TestResult::Fail(
            "published resources were freed without device reset/prefetch fence",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtl8188ee_fifo_llt_matches_actual_linux_and_pins_published_rings
);
pub(crate) fn smoke_rtl8188ee_prepare_every_io_failure_and_cancel_are_terminal() -> TestResult {
    let reference = Port::new();
    let mut ready = allocated(reference.clone(), 4, Arc::new(AtomicUsize::new(0)));
    narf_scheduler::block_on(ready.prepare()).unwrap();
    let count = reference.0.lock().accesses;
    for failed in 0..count {
        let port = Port::new();
        port.0.lock().fail = Some(failed);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut owner = allocated(port.clone(), 4, drops.clone());
        if narf_scheduler::block_on(owner.prepare()).is_ok() || owner.phase() != Phase::Failed {
            return TestResult::Fail("failed hardware access claimed prepared native rings");
        }
        let before = port.0.lock().accesses;
        let published = owner.published;
        if narf_scheduler::block_on(owner.prepare()) != Err(Error::State)
            || port.0.lock().accesses != before
        {
            return TestResult::Fail("failed FIFO publication retried hardware");
        }
        drop(owner);
        if drops.load(Ordering::Acquire) != if published { 0 } else { 12 } {
            return TestResult::Fail(
                "failure reclaimed published mappings or leaked unpublished pages",
            );
        }
    }
    let port = Port::new();
    {
        let mut m = port.0.lock();
        m.stall = true;
        m.pending = true;
    }
    let drops = Arc::new(AtomicUsize::new(0));
    let mut owner = allocated(port.clone(), 4, drops.clone());
    let mut future = Box::pin(owner.prepare());
    if future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        != Poll::Pending
    {
        return TestResult::Fail("fixture did not await actual outstanding LLT command");
    }
    drop(future);
    let before = port.0.lock().accesses;
    if owner.phase() != Phase::Failed
        || narf_scheduler::block_on(owner.prepare()) != Err(Error::State)
        || port.0.lock().accesses != before
    {
        return TestResult::Fail("cancelled LLT owner replayed native setup");
    }
    drop(owner);
    if drops.load(Ordering::Acquire) != 12 {
        return TestResult::Fail("pre-publication LLT cancellation leaked host storage");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtl8188ee_prepare_every_io_failure_and_cancel_are_terminal
);
pub(crate) fn smoke_rtl8188ee_prepare_rejects_dma_geometry_before_bar_access() -> TestResult {
    for (address, len) in [(0x10001, 256), (0xffff_ff00, 512), (0x10000, 128)] {
        let port = Port::new();
        let drops = Arc::new(AtomicUsize::new(0));
        if Prepared::allocate(port.clone(), 4, |_| {
            Ok(Block {
                address,
                bytes: vec![0; len],
                drops: drops.clone(),
            })
        })
        .is_ok()
            || port.0.lock().accesses != 0
        {
            return TestResult::Fail("unmapped/misaligned/truncated native DMA extent reached BAR");
        }
    }
    for fail in 0..12 {
        let port = Port::new();
        let drops = Arc::new(AtomicUsize::new(0));
        let mut calls = 0;
        if Prepared::allocate(port.clone(), 4, |len| {
            let at = calls;
            calls += 1;
            if at == fail {
                return Err(Error::Memory);
            }
            Ok(Block {
                address: 0x10000 + at as u64 * 0x10000,
                bytes: vec![0; len],
                drops: drops.clone(),
            })
        })
        .is_ok()
            || port.0.lock().accesses != 0
            || drops.load(Ordering::Acquire) != fail
        {
            return TestResult::Fail(
                "allocation failure exposed BAR resources or leaked unpublished pages",
            );
        }
    }
    let port = Port::new();
    let drops = Arc::new(AtomicUsize::new(0));
    if Prepared::allocate(port.clone(), 4, |len| {
        Ok(Block {
            address: 0x10000,
            bytes: vec![0; len],
            drops: drops.clone(),
        })
    })
    .is_ok()
        || port.0.lock().accesses != 0
    {
        return TestResult::Fail("overlapping DMA allocations were accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtl8188ee_prepare_rejects_dma_geometry_before_bar_access
);

pub(crate) fn smoke_rtl8188ee_prepare_timeout_gone_and_readback_retain_boundary() -> TestResult {
    for (stall, gone, ignore, wanted, published) in [
        (true, false, None, Error::LltTimeout, false),
        (false, true, None, Error::Access(AccessError::Gone), false),
        (false, false, Some(0x301), Error::Readback, false),
        (false, false, Some(0x308), Error::Readback, true),
    ] {
        let port = Port::new();
        {
            let mut model = port.0.lock();
            model.stall = stall;
            model.gone = gone;
            model.ignore = ignore;
        }
        let drops = Arc::new(AtomicUsize::new(0));
        let mut owner = allocated(port.clone(), 4, drops.clone());
        if narf_scheduler::block_on(owner.prepare()) != Err(wanted)
            || owner.phase() != Phase::Failed
            || owner.published != published
        {
            return TestResult::Fail(
                "timeout/gone/readback failure crossed native publication boundary",
            );
        }
        let before = port.0.lock().accesses;
        if (stall && before > 100)
            || narf_scheduler::block_on(owner.prepare()) != Err(Error::State)
            || port.0.lock().accesses != before
        {
            return TestResult::Fail("failed LLT/native owner was unbounded or retried registers");
        }
        drop(owner);
        if drops.load(Ordering::Acquire) != if published { 0 } else { 12 } {
            return TestResult::Fail("readback ambiguity reclaimed published native DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtl8188ee_prepare_timeout_gone_and_readback_retain_boundary
);

pub(crate) fn smoke_rtl8188ee_retained_worker_cancel_keeps_terminal_owner() -> TestResult {
    let port = Port::new();
    {
        let mut model = port.0.lock();
        model.stall = true;
        model.pending = true;
    }
    let drops = Arc::new(AtomicUsize::new(0));
    let owner = allocated(port.clone(), 4, drops.clone());
    let retained = narf_lib::mutex::Mutex::new(None);
    let mut future = Box::pin(retain_and_prepare(&retained, owner));
    if future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        != Poll::Pending
    {
        return TestResult::Fail("retained worker did not await actual published LLT command");
    }
    drop(future);
    let Some(mut storage) = retained.try_lock() else {
        return TestResult::Fail("cancel retained async mutex guard");
    };
    let Some(owner) = storage.as_mut() else {
        return TestResult::Fail("cancel dropped retained native DMA owner");
    };
    let before = port.0.lock().accesses;
    if owner.phase() != Phase::Failed
        || narf_scheduler::block_on(owner.prepare()) != Err(Error::State)
        || port.0.lock().accesses != before
        || drops.load(Ordering::Acquire) != 0
    {
        return TestResult::Fail("cancel reopened LLT owner or freed its retained resources");
    }
    drop(storage);
    let other = allocated(port.clone(), 4, drops.clone());
    if narf_scheduler::block_on(retain_and_prepare(&retained, other)) != Err(Error::State)
        || port.0.lock().accesses != before
        || drops.load(Ordering::Acquire) != 12
    {
        return TestResult::Fail("worker overwrote an existing retained native owner");
    }
    drop(retained);
    if drops.load(Ordering::Acquire) != 24 {
        return TestResult::Fail("unpublished cancelled resources leaked at final owner teardown");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtl8188ee_retained_worker_cancel_keeps_terminal_owner
);

fn smoke_rtl8188ee_drive_scheduled_retries_and_terminates() -> TestResult {
    let attempts = core::cell::Cell::new(0);
    let waits = core::cell::Cell::new(0);
    let retryable = core::cell::Cell::new(true);

    // Case 1: retries while retryable and succeeds
    let result = narf_scheduler::block_on(crate::rtlwifi::pci::drive_scheduled(
        5,
        || retryable.get(),
        || {
            let n = attempts.get();
            attempts.set(n + 1);
            async move {
                if n < 2 {
                    Err(Error::State)
                } else {
                    Ok(())
                }
            }
        },
        || {
            waits.set(waits.get() + 1);
            async {}
        },
    ));
    if result.is_err() || attempts.get() != 3 || waits.get() != 2 {
        return TestResult::Fail("rtlwifi drive_scheduled failed to retry");
    }

    // Case 2: stops early when retryable returns false
    attempts.set(0);
    waits.set(0);
    retryable.set(false);
    let result = narf_scheduler::block_on(crate::rtlwifi::pci::drive_scheduled(
        10,
        || retryable.get(),
        || {
            let n = attempts.get();
            attempts.set(n + 1);
            async move { Err(Error::State) }
        },
        || {
            waits.set(waits.get() + 1);
            async {}
        },
    ));
    if result != Err(Error::State) || attempts.get() != 1 || waits.get() != 0 {
        return TestResult::Fail("rtlwifi drive_scheduled did not exit early when unretryable");
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtl8188ee_drive_scheduled_retries_and_terminates
);

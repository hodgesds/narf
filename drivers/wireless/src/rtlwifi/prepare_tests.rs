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
    fn write16(&self, reg: u16, value: u16) -> Result<(), AccessError> {
        let mut m = self.0.lock();
        access(&mut m)?;
        m.trace.push((16, reg, u32::from(value)));
        let at = usize::from(reg);
        if m.ignore != Some(reg) {
            m.regs[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        Ok(())
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
            if word(receive, slot * 32) != 9100 | end | (1 << 31)
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
    // Fixed RTL8188EE register-map reference and documented publication order.
    // Never obtain expected addresses from the driver's Rust map.
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

/// RTL8821AE profile of the same retained owner: next descriptor at dword 12
/// (`rtl8821ae/trx.h`), the 8821AE LLT (`_rtl8821ae_llt_table_init`) and the
/// shared `REG_*_DESA` publication; radio qualification stays EE-only.
pub(crate) fn smoke_rtl8821ae_retained_rings_dw12_and_exact_llt() -> TestResult {
    let port = Port::new();
    let drops = Arc::new(AtomicUsize::new(0));
    let mut address = 0x10000;
    let mut owner = Prepared::allocate_for(Chip::Rtl8821ae, port.clone(), 4, |bytes| {
        address = (address + 255) & !255;
        let block = Block {
            address,
            bytes: vec![0xa5; bytes],
            drops: drops.clone(),
        };
        address += bytes as u64;
        Ok(block)
    })
    .unwrap();
    for ring in &owner.tx {
        let base = ring.address as u32;
        for slot in 0..4 {
            if word(ring, slot * 64 + 48) != base + (((slot + 1) % 4) * 64) as u32
                || word(ring, slot * 64 + 40) != 0
            {
                return TestResult::Fail("8821AE next-descriptor dword / cleared buffer dword");
            }
        }
    }
    if owner.chip() != Chip::Rtl8821ae
        || Chip::from_device(0x8821) != Some(Chip::Rtl8821ae)
        || Chip::from_device(0x8178) != Some(Chip::Rtl8192ce)
    {
        return TestResult::Fail("8821AE ring profile selection");
    }
    narf_scheduler::block_on(owner.prepare()).unwrap();
    let m = port.0.lock();
    let llt: Vec<_> = m.trace.iter().filter(|row| row.1 == 0x1e0).collect();
    if llt.len() != 256
        || *llt[0] != (32, 0x1e0, 0x4000_0001)
        || *llt[0xf6] != (32, 0x1e0, 0x4000_f6ff)
        || *llt[255] != (32, 0x1e0, 0x4000_fff7)
        || !m.trace.contains(&(8, 0x114, 0xf7))
        || !m.trace.contains(&(16, 0x116, 0x3e7f))
        || !m.trace.contains(&(32, 0x200, 0x80e6_0808))
        || m.trace.contains(&(32, 0x200, 0x8073_0d29))
        || !m.trace.contains(&(8, 0x214, 0))
    {
        return TestResult::Fail("8821AE LLT/RQPN trace differs from Linux");
    }
    for (at, ring) in LINUX_TX_BASES.iter().zip(&owner.tx) {
        if !m.trace.contains(&(32, *at, ring.address as u32)) {
            return TestResult::Fail("8821AE queue base not published");
        }
    }
    if m.regs[0x301] != 255 || m.regs[0x100] & 0xcf != 0 || owner.phase() != Phase::Prepared {
        return TestResult::Fail("8821AE preparation opened DMA gates");
    }
    drop(m);
    let profile_gate = narf_scheduler::block_on(
        owner.configure_radio(super::super::radio::Profile::gate_fixture()),
    );
    if profile_gate != Err(Error::State) || owner.phase() != Phase::Prepared {
        return TestResult::Fail("EE radio tables qualified an 8821AE owner");
    }
    drop(owner);
    if drops.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("published 8821AE rings freed without quiescence");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtl8821ae_retained_rings_dw12_and_exact_llt
);

/// RTL8723BE profile of the retained owner: next link at byte 48
/// (`rtl8723be/trx.h`), the `_rtl8723be_init_mac` pre-CR / `REG_CR = 0xff`
/// / clock segment before the gates are closed again, `_rtl8723be_llt_table_init`
/// (boundary 245) and the shared `REG_*_DESA` publication behind the 0x301
/// DMA stop. No radio, packet or station path qualifies the owner.
pub(crate) fn smoke_rtl8723be_retained_rings_init_mac_prefix_and_llt() -> TestResult {
    let port = Port::new();
    port.0.lock().regs[0xf3] = 1; // REG_SYS_CFG[24]: the 0x7c[6] branch
    let drops = Arc::new(AtomicUsize::new(0));
    let mut address = 0x10000;
    let mut owner = Prepared::allocate_for(Chip::Rtl8723be, port.clone(), 4, |bytes| {
        address = (address + 255) & !255;
        let block = Block {
            address,
            bytes: vec![0xa5; bytes],
            drops: drops.clone(),
        };
        address += bytes as u64;
        Ok(block)
    })
    .unwrap();
    for ring in &owner.tx {
        let base = ring.address as u32;
        for slot in 0..4 {
            if word(ring, slot * 64 + 48) != base + (((slot + 1) % 4) * 64) as u32
                || word(ring, slot * 64 + 40) != 0
            {
                return TestResult::Fail("8723BE next link at byte 48 / cleared buffer dword");
            }
        }
    }
    if Chip::from_device(0xb723) != Some(Chip::Rtl8723be)
        || Chip::from_device(0x8723).is_some()
        || Chip::Rtl8723be.next_desc_offset() != Some(48)
    {
        return TestResult::Fail("8723BE ring profile selection (8723AE excluded)");
    }
    // `rtl_pci_start` → `btc_init_variables` precedes `hw_init`; an unbound
    // owner refuses before the 0x301 stop's successor writes.
    {
        use super::super::btcoex::btc::{ChipInterface, ChipType, HwPg};
        let pg = HwPg {
            bt_exist: true,
            ant_num: 2,
            single_ant_path: 0,
            chip_type: ChipType::Rtl8723b,
            package_type: 0,
            rfe_type: 0,
            interface: ChipInterface::Pci,
        };
        let unbound_port = Port::new();
        let mut at = 0x80_0000u64;
        let mut unbound = Prepared::allocate_for(Chip::Rtl8723be, unbound_port, 4, |bytes| {
            at = (at + 255) & !255;
            let block = Block {
                address: at,
                bytes: vec![0; bytes],
                drops: Arc::new(AtomicUsize::new(0)),
            };
            at += bytes as u64;
            Ok(block)
        })
        .unwrap();
        if narf_scheduler::block_on(unbound.prepare()) != Err(Error::State) {
            return TestResult::Fail("8723BE prepared without its coexistence owner");
        }
        drop(unbound);
        if owner.bind_rtl8723be_coex(pg).is_err() || owner.bind_rtl8723be_coex(pg).is_ok() {
            return TestResult::Fail("8723BE coexistence bind");
        }
    }
    narf_scheduler::block_on(owner.prepare()).unwrap();
    let m = port.0.lock();
    // `ex_btc8723b2ant_power_on_setting` between the enable flow and
    // `REG_MULTI_FUNC_CTRL |= BIT(3)` (`hw.c:827`).
    let coex_on = m.trace.iter().position(|r| *r == (8, 0x67, 0x20));
    let func_at = m.trace.iter().position(|r| *r == (8, 0x68, 0x08));
    if !matches!((coex_on, func_at), (Some(c), Some(f)) if c < f)
        || !m.trace.contains(&(32, 0x948, 0))
    {
        return TestResult::Fail("8723BE btc_power_on_setting not at hw.c:827");
    }
    let at = |row: (u8, u16, u32)| m.trace.iter().position(|r| *r == row);
    let (Some(stop), Some(func), Some(open), Some(hwseq), Some(clkr), Some(close)) = (
        at((8, 0x301, 0xff)),
        at((8, 0x68, 0x08)),
        at((8, 0x100, 0xff)),
        at((8, 0x423, 0x7f)),
        at((8, 0x08, 0x08)),
        at((8, 0x100, 0x30)),
    ) else {
        return TestResult::Fail("8723BE init_mac prefix rows missing");
    };
    if !(stop < func && func < open && open < hwseq && hwseq < clkr && clkr < close)
        || at((8, 0x04, 0x10)).is_none_or(|aps| aps < func || aps > open)
        || at((8, 0x7c, 0x40)).is_none()
    {
        return TestResult::Fail("8723BE init_mac prefix order differs from Linux");
    }
    let llt: Vec<_> = m.trace.iter().filter(|row| row.1 == 0x1e0).collect();
    if llt.len() != 256
        || *llt[0] != (32, 0x1e0, 0x4000_0001)
        || *llt[244] != (32, 0x1e0, 0x4000_f4ff)
        || *llt[255] != (32, 0x1e0, 0x4000_fff5)
        || at((32, 0x114, 0x27ff_00f5)).is_none_or(|b| b < close)
        || at((32, 0x200, 0x80e4_0808)).is_none()
        || at((8, 0x214, 0)).is_none()
        || at((32, 0x200, 0x8073_0d29)).is_some()
    {
        return TestResult::Fail("8723BE LLT/RQPN trace differs from Linux");
    }
    for (row, ring) in LINUX_TX_BASES.iter().zip(&owner.tx) {
        if !m.trace.contains(&(32, *row, ring.address as u32)) {
            return TestResult::Fail("8723BE queue base not published");
        }
    }
    if m.regs[0x301] != 255
        || m.regs[0x100] & 0xcf != 0
        || m.regs[0xb0..0xb4] != [0; 4]
        || m.regs[0xb8..0xbc] != [0; 4]
        || owner.phase() != Phase::Prepared
    {
        return TestResult::Fail("8723BE preparation opened DMA/IRQ gates");
    }
    drop(m);
    let profile_gate = narf_scheduler::block_on(
        owner.configure_radio(super::super::radio::Profile::gate_fixture()),
    );
    if profile_gate != Err(Error::State) || owner.phase() != Phase::Prepared {
        return TestResult::Fail("EE radio tables qualified an 8723BE owner");
    }
    drop(owner);
    if drops.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("published 8723BE rings freed without quiescence");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtl8723be_retained_rings_init_mac_prefix_and_llt
);

/// Test board factory for the RTL8192DE native-admission test
/// (synthetic values, not any board's).
fn de_factory() -> super::super::efuse::Factory {
    super::super::efuse::Factory {
        mac: [0x00, 0xe0, 0x4c, 0x81, 0x92, 0xde],
        logical: [0u8; 512],
    }
}

/// US regulatory domain covering both bands: 2402-2472 MHz at 20 dBm
/// plus the UNII-1/2/3 blocks at 30 dBm (no flags, so no DFS rule
/// overlaps the test spans).
fn de_domain() -> narf_wireless::reg::RegulatoryDomain {
    use narf_wireless::reg::*;
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![
            RegRule {
                freq_start_mhz: 2402,
                freq_end_mhz: 2472,
                max_bandwidth_mhz: 40,
                max_power_dbm: 20,
                flags: RegFlags::empty(),
            },
            RegRule {
                freq_start_mhz: 5140,
                freq_end_mhz: 5360,
                max_bandwidth_mhz: 80,
                max_power_dbm: 30,
                flags: RegFlags::empty(),
            },
            RegRule {
                freq_start_mhz: 5460,
                freq_end_mhz: 5860,
                max_bandwidth_mhz: 80,
                max_power_dbm: 30,
                flags: RegFlags::empty(),
            },
        ],
    }
}

/// NAPC v3 fixture for the 8192DE native-admission test: 20 MHz rows
/// on channels 6 (2.4 GHz), 36 and 165 (5 GHz), flat rising curves
/// (`2 * index`, so a 20/30 dBm ceiling admits index 40 on every
/// rate), CCK unmeasured on 5 GHz rows as the format requires.
fn de_napc_v3_native() -> Vec<u8> {
    let factory = de_factory();
    let identity = super::super::radio::factory_identity(&factory);
    let rows: [(u8, u8); 3] = [(6, 0), (36, 1), (165, 1)];
    let total = 96 + rows.len() * 516;
    let mut bytes = vec![0u8; total];
    bytes[0..4].copy_from_slice(b"NAPC");
    bytes[4..6].copy_from_slice(&3u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&96u16.to_le_bytes());
    bytes[8..12].copy_from_slice(&(total as u32).to_le_bytes());
    bytes[12..14].copy_from_slice(&0x10ecu16.to_le_bytes());
    bytes[14..16].copy_from_slice(&0x8193u16.to_le_bytes());
    bytes[16..48].copy_from_slice(&identity);
    bytes[48..54].copy_from_slice(&factory.mac);
    bytes[56..58].copy_from_slice(&0i16.to_le_bytes());
    bytes[58..60].copy_from_slice(&80i16.to_le_bytes());
    bytes[60..62].copy_from_slice(&(rows.len() as u16).to_le_bytes());
    for (i, (channel, band)) in rows.iter().enumerate() {
        let row = &mut bytes[96 + i * 516..96 + (i + 1) * 516];
        row[0] = *channel;
        row[1] = *band;
        row[2] = 20;
        row[3] = 0;
        for curve in 0..4u8 {
            for idx in 0..64u8 {
                let value = if *band == 1 && curve == 0 {
                    i16::MAX
                } else {
                    i16::from(idx) * 2
                };
                let at = 4 + (usize::from(curve) * 64 + usize::from(idx)) * 2;
                row[at..at + 2].copy_from_slice(&value.to_le_bytes());
            }
        }
    }
    bytes
}

/// A dual-dual RTL8192DE owner in `RadioConfigured` on `interface_index`
/// (0 = MAC0 on 5 GHz, 1 = MAC1 on 2.4 GHz), with a zeroed factory
/// power store (`txpwr_fromeprom` clear, so the channel step takes the
/// no-EEPROM levels) and a fresh IQK matrix — the state
/// `configure_rtl8192de` leaves before `admit_rtl8192de` runs.
fn de_owner(factory: &super::super::efuse::Factory, interface_index: u8) -> Prepared<Port, Block> {
    use super::super::rtl8192de::{
        calib::IqkMatrix,
        dm::Dm,
        init::Radio,
        lck::LcOutcome,
        phy::{PgStore, MAX_PG_GROUP},
        txpower::{Efuse, PowerLevels, CHANNEL_MAX_NUMBER},
        Band, BandSet, MacPhyMode, RfType,
    };
    let port = Port::new();
    let drops = Arc::new(AtomicUsize::new(0));
    let mut address = 0x10000;
    let mut owner = Prepared::allocate_for(Chip::Rtl8192de, port, 4, |bytes| {
        address = (address + 255) & !255;
        let block = Block {
            address,
            bytes: vec![0xa5; bytes],
            drops: drops.clone(),
        };
        address += bytes as u64;
        Ok(block)
    })
    .unwrap();
    owner
        .bind_rtl8192de_mode(MacPhyMode::DualMacDualPhy)
        .unwrap();
    let band = if interface_index == 0 {
        Band::On5Ghz
    } else {
        Band::On2Ghz
    };
    let bandset = if interface_index == 0 {
        BandSet::On5Ghz
    } else {
        BandSet::On2Ghz
    };
    owner.rtl8192de = Some(Box::new(super::de92_radio::De92Radio {
        identity: super::super::radio::factory_identity(factory),
        radio: Radio {
            mode: MacPhyMode::DualMacDualPhy,
            interface_index,
            band,
            rf_type: RfType::OneT1R,
            chnlval: [0; 2],
            iqk: IqkMatrix::new(),
            receive_config: 0,
            cck_high_power: false,
            initialgain: [0; 4],
            framesync: 0,
            framesync_c34: 0,
            power_levels: PowerLevels {
                cck: [0; 2],
                ofdm: [0; 2],
                current: None,
                from_eeprom: false,
            },
            pg: Some(PgStore {
                mcs_offset: [[0; 16]; MAX_PG_GROUP],
                pwrgroup_cnt: 0,
            }),
            rf_on: true,
            // Fresh `rtl92de_dm_init` state, exactly what
            // `configure()` stores (init.rs); the DM state is
            // report-only for the prepare/admit path under test.
            dm: Dm::new(),
            // `lc_calibrate`'s initial outcome for this 1-path RF
            // (lck.rs); the fixture never runs calibration, and
            // `path_count` is the load-bearing field (cf. the
            // `configure` end-to-end test asserting it).
            lc: LcOutcome {
                scan_wait_us: 0,
                path_count: RfType::OneT1R.paths(),
                poll_ms: [0; 2],
                poll_timed_out: [false; 2],
            },
        },
        efuse: Efuse {
            cck: [[0; CHANNEL_MAX_NUMBER]; 2],
            ht40_1s: [[0; CHANNEL_MAX_NUMBER]; 2],
            ht40_2s: [[0; CHANNEL_MAX_NUMBER]; 2],
            ht20_diff: [[0; CHANNEL_MAX_NUMBER]; 2],
            legacy_ht_diff: [[0; CHANNEL_MAX_NUMBER]; 2],
            pwrgroup_ht20: [[0; CHANNEL_MAX_NUMBER]; 2],
            pwrgroup_ht40: [[0; CHANNEL_MAX_NUMBER]; 2],
            regulatory: 0,
            thermalmeter: 0,
            crystalcap: 0,
            delta_iqk: 0,
            delta_lck: 0,
            internal_pa_5g: [false; 2],
            eeprom_c9: 0,
            eeprom_cc: 0,
            txpwr_fromeprom: false,
            tssi_a: [0; 3],
            tssi_b: [0; 3],
        },
        bandset,
    }));
    owner.phase = Phase::RadioConfigured;
    owner
}

/// RTL8192DE native 5 GHz admission at the prepare layer: a dual-dual
/// MAC0 function admits 5 GHz channels 36/165, a dual-dual MAC1 function
/// admits 2.4 GHz channel 6, and the cross-band requests (MAC0 on 6,
/// MAC1 on 36) are refused before any calibration is staged —
/// mirroring `smoke_rtl8192de_native_channel` at the `admit_rtl8192de`
/// layer, over a signed v3 NAPC fixture in the firmware registry.
pub(crate) fn smoke_rtl8192de_native_channel_admission() -> TestResult {
    let factory = de_factory();
    let domain = de_domain();
    let (write, _read) = narf_firmware::bootstrap_authority();
    narf_firmware::install_trusted_loader_authority(write);
    match crate::firmware_asset::tests::install(
        &write,
        "rtlwifi/rtl8192de-cal-v3-00e04c8192de.bin",
        &de_napc_v3_native(),
        true,
    ) {
        Ok(()) => {}
        Err(_) => {
            return TestResult::Fail("8192DE native admission fixture NAPC install");
        }
    }
    for (interface_index, channel) in [(0u8, 36u8), (0, 165), (1, 6)] {
        let mut owner = de_owner(&factory, interface_index);
        match narf_scheduler::block_on(super::super::prepare_native::admit_rtl8192de(
            &mut owner, &factory, &domain, channel,
        )) {
            Ok(()) => {}
            Err(_) => {
                return TestResult::Fail("8192DE native admission refused an in-band channel");
            }
        }
        if owner.phase() != Phase::MacConfigured
            || owner.rtl8192de_permission().map(|p| p.channel()) != Some(channel)
        {
            return TestResult::Fail("8192DE native admission did not reach MacConfigured");
        }
    }
    for (interface_index, channel) in [(0u8, 6u8), (1, 36)] {
        let mut owner = de_owner(&factory, interface_index);
        if narf_scheduler::block_on(super::super::prepare_native::admit_rtl8192de(
            &mut owner, &factory, &domain, channel,
        ))
        .is_ok()
            || owner.phase() != Phase::RadioConfigured
            || owner.rtl8192de_permission().is_some()
        {
            return TestResult::Fail("8192DE native admission admitted a cross-band channel");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtl8192de_native_channel_admission
);

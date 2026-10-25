use super::firmware_transport::Io;
use super::*;
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
#[derive(Clone, Debug)]
struct BlockState {
    address: u64,
    bytes: Vec<u8>,
    writes: usize,
    syncs: usize,
    acquires: usize,
    published_at: Option<usize>,
}
struct Block {
    state: Arc<IrqSafeSpinLock<BlockState>>,
    drops: Arc<AtomicUsize>,
}
impl Drop for Block {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}
// SAFETY: the sole Block is the model's CPU writer; register simulator reads
// the device-side snapshot only on doorbells. All storage is inert host bytes.
unsafe impl Memory for Block {
    fn address(&self) -> u64 {
        self.state.lock().address
    }
    fn len(&self) -> usize {
        self.state.lock().bytes.len()
    }
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        let mut state = self.state.lock();
        if state.published_at == Some(state.acquires) {
            return Err(Error::Memory);
        }
        state
            .bytes
            .get_mut(offset..offset + bytes.len())
            .ok_or(Error::Memory)?
            .copy_from_slice(bytes);
        state.writes += 1;
        Ok(())
    }
    fn sync(&self) {
        self.state.lock().syncs += 1;
    }
    fn acquire(&self) {
        self.state.lock().acquires += 1;
    }
}
struct Model {
    bytes: Vec<u8>,
    calls: usize,
    fail: Option<usize>,
    pending: bool,
    stale_valid: bool,
    stall: bool,
    ready: bool,
    doorbells: usize,
    packets: Vec<Vec<u8>>,
    continuation: u8,
    pending_rf: bool,
    revoke_on_rf: bool,
    rf_written: bool,
    commands: Vec<[u8; 32]>,
    command_ring: crate::rtw88::command::Ring,
    command_index: u32,
    command_stall: bool,
    iqk_armed: bool,
    iqk_complete: bool,
    iqk_reads: usize,
    hold_delay: Option<u64>,
    ignore_rf: bool,
    ring: Arc<IrqSafeSpinLock<BlockState>>,
    frame: Arc<IrqSafeSpinLock<BlockState>>,
}
#[derive(Clone)]
struct Port(Arc<IrqSafeSpinLock<Model>>);
impl Port {
    fn access(&self) -> Result<(), Error> {
        let mut model = self.0.lock();
        let at = model.calls;
        model.calls += 1;
        if model.fail == Some(at) {
            Err(Error::Access)
        } else {
            Ok(())
        }
    }
}
#[async_trait::async_trait]
// SAFETY: no physical PCI/DMA. The simulator holds all synthetic device
// mappings, observes OWN before claiming, and only reads published storage.
unsafe impl Registers for Port {
    fn claim_firmware_dma(&mut self, base: u32) -> Result<(), Error> {
        self.access()?;
        let model = self.0.lock();
        let ring = model.ring.lock();
        if u64::from(base) != ring.address || ring.bytes[..16] != [0; 16] || ring.syncs == 0 {
            return Err(Error::Prerequisite);
        }
        Ok(())
    }
    fn read8(&mut self, reg: u16) -> Result<u8, Error> {
        self.access()?;
        Ok(self.0.lock().bytes[usize::from(reg)])
    }
    fn read16(&mut self, reg: u16) -> Result<u16, Error> {
        self.access()?;
        let model = self.0.lock();
        let at = usize::from(reg);
        let mut value = u16::from_le_bytes(model.bytes[at..at + 2].try_into().unwrap());
        if reg == 0x204 && model.stale_valid {
            value |= 1 << 15;
        }
        Ok(value)
    }
    fn read32(&mut self, reg: u16) -> Result<u32, Error> {
        self.access()?;
        let mut model = self.0.lock();
        let at = usize::from(reg);
        if reg == 0x2820 && model.iqk_armed {
            model.iqk_reads += 1;
            if model.iqk_complete && model.iqk_reads >= 2 {
                model.bytes[at..at + 4].copy_from_slice(&0xabcdeu32.to_le_bytes());
            }
        }
        let mut value = u32::from_le_bytes(model.bytes[at..at + 4].try_into().unwrap());
        if reg == 0x1208 {
            value &= !(1 << 31);
        }
        if reg == 0x208 {
            value &= !1;
        }
        if reg == 0x80 && model.ready && value & 1 << 14 != 0 {
            value |= 1 << 15;
        }
        Ok(value)
    }
    fn write8(&mut self, reg: u16, value: u8) -> Result<(), Error> {
        self.access()?;
        let mut model = self.0.lock();
        model.bytes[usize::from(reg)] = value;
        // H2C initialization is an 8-bit REG_H2C_INFO write in mac.c.
        // Its bit2 receipt exposes both empty pointers at the configured head.
        if reg == 0x254 && value & 4 != 0 {
            let head = word(&model.bytes, 0x244) & 0x3ffff;
            model.bytes[0x10d0..0x10d4].copy_from_slice(&head.to_le_bytes());
            model.bytes[0x10d4..0x10d8].copy_from_slice(&head.to_le_bytes());
        }
        if reg == 0x383 && value & 16 != 0 {
            {
                let mut ring = model.ring.lock();
                ring.published_at = Some(ring.acquires);
            }
            {
                let mut frame = model.frame.lock();
                frame.published_at = Some(frame.acquires);
            }
            let frame = model.frame.lock().bytes.clone();
            let length = usize::from(u16::from_le_bytes([frame[0], frame[1]]));
            model.packets.push(frame[..DESC + length].to_vec());
            model.doorbells += 1;
            if !model.stall {
                model.bytes[0x205] |= 0x80;
            }
        }
        Ok(())
    }
    fn write16(&mut self, reg: u16, mut value: u16) -> Result<(), Error> {
        self.access()?;
        let mut model = self.0.lock();
        let at = usize::from(reg);
        if reg == 0x204 {
            value &= !(1 << 15);
        }
        model.bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
    fn write32(&mut self, reg: u16, value: u32) -> Result<(), Error> {
        self.access()?;
        let mut model = self.0.lock();
        let at = usize::from(reg);
        model.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        if reg == 0xc90 {
            model.rf_written = true;
            if !model.ignore_rf {
                let address = ((value >> 20) & 255) as usize;
                let offset = 0x2800 + address * 4;
                model.bytes[offset..offset + 4].copy_from_slice(&(value & 0xfffff).to_le_bytes());
                if address == 8 && value & 0xfffff == 0 {
                    model.iqk_armed = false;
                }
            }
            if model.revoke_on_rf {
                model.fail = Some(model.calls);
            }
        }
        Ok(())
    }
    async fn delay_us(&mut self, us: u64) {
        core::future::poll_fn(|_| {
            let model = self.0.lock();
            if model.pending || model.pending_rf && model.rf_written || model.hold_delay == Some(us)
            {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
    }
    async fn lte_backup(&mut self) -> Result<u32, Error> {
        self.access()?;
        Ok(0x12345678)
    }
    async fn lte_restore(&mut self, value: u32) -> Result<(), Error> {
        self.access()?;
        if value != 0x12345678 {
            return Err(Error::State);
        }
        Ok(())
    }
    async fn finish_dma(&mut self) -> Result<(), Error> {
        self.access()
    }
    fn begin_mac(&mut self) -> Result<(), Error> {
        self.access()?;
        let mut model = self.0.lock();
        if model.continuation != 0 {
            return Err(Error::State);
        }
        model.continuation = 1;
        Ok(())
    }
    fn finish_mac(&mut self) -> Result<(), Error> {
        self.access()?;
        let mut model = self.0.lock();
        if model.continuation != 1 || model.bytes[0x100] & 0xcf != 0 || model.bytes[0x522] != 255 {
            return Err(Error::Prerequisite);
        }
        model.continuation = 2;
        Ok(())
    }
    fn begin_phy(&mut self) -> Result<(), Error> {
        self.access()?;
        let mut model = self.0.lock();
        if model.continuation != 2 {
            return Err(Error::State);
        }
        model.continuation = 3;
        Ok(())
    }
    fn finish_phy(&mut self) -> Result<(), Error> {
        self.access()?;
        let mut model = self.0.lock();
        if model.continuation != 3 || model.bytes[0x100] & 0xcf != 0 || model.bytes[0x522] != 255 {
            return Err(Error::Prerequisite);
        }
        model.continuation = 4;
        Ok(())
    }
    fn begin_calibration8821c(&mut self) -> Result<(), Error> {
        self.access()?;
        let mut model = self.0.lock();
        if model.continuation != 4 || model.bytes[0x100] & 0xcf != 0 || model.bytes[0x522] != 255 {
            return Err(Error::Prerequisite);
        }
        model.continuation = 5;
        Ok(())
    }
    fn begin_commands(&mut self) -> Result<(), Error> {
        self.access()?;
        let mut model = self.0.lock();
        if model.continuation != 5 {
            return Err(Error::State);
        }
        model.continuation = 6;
        model.bytes[0x100] = 0x33;
        Ok(())
    }
    fn submit_h2c(&mut self, packet: &[u8; 32]) -> Result<(), Error> {
        self.access()?;
        let mut model = self.0.lock();
        if model.continuation != 6 {
            return Err(Error::State);
        }
        let index = model.command_index;
        let (_, next) = model.command_ring.reserve(index)?;
        model.commands.push(*packet);
        model.command_index = (index & 0xffff0000) | u32::from(next);
        Ok(())
    }
    fn poll_h2c(&mut self) -> Result<bool, Error> {
        self.access()?;
        let mut model = self.0.lock();
        if !model.command_stall {
            model.command_index = (model.command_index & 0xffff) * 0x10001;
        }
        let index = model.command_index;
        let done = model.command_ring.poll(index)?;
        if done && model.commands.len() == 3 {
            model.iqk_armed = true;
        }
        Ok(done)
    }
    fn park_radio(&mut self) -> Result<(), Error> {
        self.access()?;
        let mut model = self.0.lock();
        if model.continuation != 6 || model.command_ring.pending() {
            return Err(Error::State);
        }
        model.bytes[0x100] = 0;
        model.continuation = 7;
        Ok(())
    }
    fn finish_calibration8821c(&mut self) -> Result<(), Error> {
        self.access()?;
        let mut model = self.0.lock();
        if model.continuation != 7 || model.bytes[0x100] & 0xcf != 0 || model.bytes[0x522] != 255 {
            return Err(Error::Prerequisite);
        }
        model.continuation = 8;
        Ok(())
    }
}
fn allocated() -> (Backend<Port, Block>, Port, Arc<AtomicUsize>) {
    let drops = Arc::new(AtomicUsize::new(0));
    let ring = Arc::new(IrqSafeSpinLock::new(BlockState {
        address: 0x10000,
        bytes: vec![0xa5; 16],
        writes: 0,
        syncs: 0,
        acquires: 0,
        published_at: None,
    }));
    let frame = Arc::new(IrqSafeSpinLock::new(BlockState {
        address: 0x20000,
        bytes: vec![0xa5; DESC + PAYLOAD],
        writes: 0,
        syncs: 0,
        acquires: 0,
        published_at: None,
    }));
    let port = Port(Arc::new(IrqSafeSpinLock::new(Model {
        bytes: vec![0; 0x2c00],
        calls: 0,
        fail: None,
        pending: false,
        stale_valid: false,
        stall: false,
        ready: true,
        doorbells: 0,
        packets: Vec::new(),
        continuation: 0,
        pending_rf: false,
        revoke_on_rf: false,
        rf_written: false,
        commands: Vec::new(),
        command_ring: crate::rtw88::command::Ring::default(),
        command_index: 0,
        command_stall: false,
        iqk_armed: false,
        iqk_complete: true,
        iqk_reads: 0,
        hold_delay: None,
        ignore_rf: false,
        ring: ring.clone(),
        frame: frame.clone(),
    })));
    let backend = Backend::new(
        port.clone(),
        Block {
            state: ring,
            drops: drops.clone(),
        },
        Block {
            state: frame,
            drops: drops.clone(),
        },
        0x123,
    )
    .unwrap();
    (backend, port, drops)
}
fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn smoke_rtw88_persistent_reserved_page_native_descriptor_and_reuse() -> TestResult {
    let (mut backend, port, drops) = allocated();
    backend.claim_pristine().unwrap();
    for length in [1, 80, 81, 4096, 7] {
        let bytes = vec![0x12; length];
        narf_scheduler::block_on(backend.reserved_page(&bytes)).unwrap();
        let model = port.0.lock();
        let frame = model.frame.lock();
        let ring = model.ring.lock();
        if frame.bytes[DESC..DESC + length] != bytes
            || word(&frame.bytes, 0) != length as u32 | 48 << 16 | 1 << 26 | 1 << 31
            || word(&frame.bytes, 4) != 0x81000
            || word(&frame.bytes, 12) != 0x500
            || word(&frame.bytes, 32) != 0x8000
        {
            return TestResult::Fail(
                "native firmware packet descriptor/offset/legacy profile mismatch",
            );
        }
        if word(&ring.bytes, 0) != 48 | (((DESC + length).div_ceil(128) as u32 | 0x8000) << 16)
            || word(&ring.bytes, 4) != 0x20000
            || word(&ring.bytes, 8) != length as u32
            || word(&ring.bytes, 12) != 0x20030
        {
            return TestResult::Fail(
                "native reserved-page PCI two-segment BD/pagecount/OWN mismatch",
            );
        }
        if ring.acquires != model.doorbells || frame.acquires != model.doorbells {
            return TestResult::Fail("fresh valid lacked device completion acquire before reuse");
        }
        if backend.state != PageState::Idle
            || u16::from_le_bytes(model.bytes[0x204..0x206].try_into().unwrap()) != 0x123
        {
            return TestResult::Fail(
                "completed page did not restore reserved boundary/reopen serial owner",
            );
        }
    }
    if port.0.lock().doorbells != 5 {
        return TestResult::Fail("native descriptor path did not publish every exact transfer");
    }
    drop(backend);
    if drops.load(Ordering::SeqCst) != 0 {
        return TestResult::Fail("published native mappings were reclaimed without reset proof");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_persistent_reserved_page_native_descriptor_and_reuse
);
fn smoke_rtw88_reserved_page_every_access_fault_and_post_publication_cancel() -> TestResult {
    let (mut reference, reference_port, _) = allocated();
    reference.claim_pristine().unwrap();
    let start = reference_port.0.lock().calls;
    narf_scheduler::block_on(reference.reserved_page(&[0x12; 80])).unwrap();
    let end = reference_port.0.lock().calls;
    for fail in start..end {
        let (mut backend, port, _) = allocated();
        backend.claim_pristine().unwrap();
        port.0.lock().fail = Some(fail);
        if narf_scheduler::block_on(backend.reserved_page(&[0x12; 80])) != Err(Error::Access)
            || backend.state != PageState::Terminal
        {
            return TestResult::Fail("failed page I/O reopened or claimed completion");
        }
        let model = port.0.lock();
        let calls = model.calls;
        let frame = model.frame.lock().bytes.clone();
        let ring = model.ring.lock().bytes.clone();
        drop(model);
        if calls != fail + 1
            || narf_scheduler::block_on(backend.reserved_page(&[0x34; 80])) != Err(Error::State)
        {
            return TestResult::Fail("ambiguous native transfer performed cleanup or retry");
        }
        let model = port.0.lock();
        if model.calls != calls
            || model.frame.lock().bytes != frame
            || model.ring.lock().bytes != ring
        {
            return TestResult::Fail("failed native buffer overwritten before quiescence");
        }
    }
    let (mut backend, port, _) = allocated();
    backend.claim_pristine().unwrap();
    {
        let mut model = port.0.lock();
        model.pending = true;
        model.stall = true;
    }
    let mut future = Box::pin(backend.reserved_page(&[0x12; 80]));
    if future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        != Poll::Pending
    {
        return TestResult::Fail("cancel fixture did not reach actual TD publication");
    }
    drop(future);
    let model = port.0.lock();
    let calls = model.calls;
    let frame = model.frame.lock().bytes.clone();
    let ring = model.ring.lock().bytes.clone();
    let doorbells = model.doorbells;
    drop(model);
    if doorbells != 1
        || backend.state != PageState::Terminal
        || narf_scheduler::block_on(backend.reserved_page(&[0x34; 80])) != Err(Error::State)
    {
        return TestResult::Fail("cancelled actual TD was not terminally retained");
    }
    let model = port.0.lock();
    if model.calls != calls || model.frame.lock().bytes != frame || model.ring.lock().bytes != ring
    {
        return TestResult::Fail("cancelled native TD scratch was overwritten");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_reserved_page_every_access_fault_and_post_publication_cancel
);
fn smoke_rtw88_reserved_page_stale_valid_and_timeout_never_reuse() -> TestResult {
    for stale in [false, true] {
        let (mut backend, port, _) = allocated();
        backend.claim_pristine().unwrap();
        {
            let mut model = port.0.lock();
            model.stall = true;
            model.stale_valid = stale;
        }
        let wanted = if stale {
            Error::Prerequisite
        } else {
            Error::Timeout
        };
        if narf_scheduler::block_on(backend.reserved_page(&[0; 80])) != Err(wanted)
            || backend.state != PageState::Terminal
            || port.0.lock().doorbells != usize::from(!stale)
        {
            return TestResult::Fail("stale page-valid or timeout passed completion gate");
        }
        let calls = port.0.lock().calls;
        if narf_scheduler::block_on(backend.reserved_page(&[0; 80])) != Err(Error::State)
            || port.0.lock().calls != calls
        {
            return TestResult::Fail("unproven beacon-page completion was retried");
        }
    }
    let (backend, _, drops) = allocated();
    drop(backend);
    if drops.load(Ordering::SeqCst) != 2 {
        return TestResult::Fail("unpublished page allocations leaked");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_reserved_page_stale_valid_and_timeout_never_reuse
);
fn image() -> Vec<u8> {
    let mut bytes = vec![0; 64 + 4093 + 8 + 9 + 8 + 5 + 8];
    bytes[..2].copy_from_slice(&[0x22, 0x88]);
    bytes[0x18] = 0x10;
    for (offset, value) in [
        (0x20, 0x80200000u32),
        (0x24, 4093),
        (0x30, 9),
        (0x34, 5),
        (0x38, 0x80100000),
        (0x3c, 0x80030000),
    ] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (index, byte) in bytes[64..].iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }
    bytes
}
fn smoke_rtw88_actual_reserved_page_backend_composes_whole_firmware() -> TestResult {
    for did in [0xc821, 0xc822] {
        if let TestResult::Fail(error) = composed_firmware(did) {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
fn composed_firmware(did: u16) -> TestResult {
    let (backend, port, _) = allocated();
    let mut bytes = image();
    bytes[0] = if did == 0xc821 { 0x21 } else { 0x22 };
    let mut owner = firmware_transport::Owner::new(backend, did);
    if narf_scheduler::block_on(owner.download(&bytes)).is_err()
        || owner.phase() != firmware_transport::Phase::Ready
    {
        return TestResult::Fail("real section owner/native page backend did not compose");
    }
    let model = port.0.lock();
    let payloads: Vec<_> = model.packets.iter().map(|packet| &packet[48..]).collect();
    if payloads
        != vec![
            &bytes[64..4160],
            &bytes[4160..4165],
            &bytes[4165..4182],
            &bytes[4182..4195],
        ]
    {
        return TestResult::Fail(
            "composed page DMA did not carry exact firmware sections/trailers",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_actual_reserved_page_backend_composes_whole_firmware
);

fn smoke_rtw8821ce_real_reserved_dma_owner_survives_phy_success_cancel_and_revocation() -> TestResult
{
    for outcome in 0..5 {
        let (backend, port, drops) = allocated();
        let mut bytes = image();
        bytes[0] = 0x21;
        let lifecycle = crate::rtw88::firmware_lifecycle::Lifecycle::new(0xc821);
        if narf_scheduler::block_on(lifecycle.initialize_bytes(|| Ok(backend), bytes)).is_err() {
            return TestResult::Fail("composed C21 fixture failed retained firmware setup");
        }
        {
            let mut model = port.0.lock();
            model.bytes[0xf0..0xf4].copy_from_slice(&(3u32 << 12).to_le_bytes());
            model.bytes[0x1a0] = 0x19;
            model.bytes[0x1a6..0x1aa]
                .copy_from_slice(&((7u32 << 16) | (1 << 19) | (1 << 21) | (3 << 26)).to_le_bytes());
        }
        if narf_scheduler::block_on(lifecycle.prepare_mac()).is_err() {
            return TestResult::Fail("composed C21 fixture failed inactive MAC/H2C setup");
        }
        {
            let model = port.0.lock();
            if word(&model.bytes, 0x10d0) & 0x3ffff != 500 << 7
                || word(&model.bytes, 0x10d4) & 0x3ffff != 500 << 7
            {
                return TestResult::Fail(
                    "C21 byte H2C initialization missed configured empty pointers",
                );
            }
        }
        let (frame, ring, doorbells) = {
            let model = port.0.lock();
            let frame = model.frame.lock().bytes.clone();
            let ring = model.ring.lock().bytes.clone();
            (frame, ring, model.doorbells)
        };
        let mut raw = [255; 512];
        raw[0xd0..0xd6].copy_from_slice(&[2, 4, 6, 8, 10, 12]);
        raw[0xb9] = 0x33;
        raw[0xca] = 4;
        let factory = match crate::rtw88::efuse::Factory8821c::for_test(raw) {
            Ok(factory) => factory,
            Err(_) => return TestResult::Fail("composed C21 fixture has invalid factory identity"),
        };
        {
            let mut model = port.0.lock();
            model.pending = outcome == 1;
            model.pending_rf = outcome == 2;
            model.revoke_on_rf = outcome == 4;
            if outcome == 3 {
                model.fail = Some(model.calls);
            }
        }
        if matches!(outcome, 1 | 2) {
            let mut future = Box::pin(lifecycle.prepare_phy8821c(&factory));
            if future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                != Poll::Pending
            {
                return TestResult::Fail(
                    "composed C21 PHY cancellation missed real retained DMA owner",
                );
            }
            drop(future);
        } else {
            let expected = if outcome == 0 {
                None
            } else {
                Some(Error::Access)
            };
            if narf_scheduler::block_on(lifecycle.prepare_phy8821c(&factory)).err() != expected {
                return TestResult::Fail(
                    "composed C21 PHY success/current-authority failure differed",
                );
            }
        }
        let status = lifecycle.status();
        if (outcome == 0
            && status.stage != crate::rtw88::firmware_lifecycle::Stage::PhyTablesPrepared)
            || (outcome != 0 && status.stage != crate::rtw88::firmware_lifecycle::Stage::Failed)
            || drops.load(Ordering::SeqCst) != 0
        {
            return TestResult::Fail(
                "C21 PHY result freed retained native DMA or claimed readiness",
            );
        }
        let calls = {
            let model = port.0.lock();
            if model.frame.lock().bytes != frame
                || model.ring.lock().bytes != ring
                || model.doorbells != doorbells
                || model.bytes[0x100] & 0xcf != 0
                || model.bytes[0x522] != 255
            {
                return TestResult::Fail("C21 PHY rewrote retained page buffers or opened MAC");
            }
            model.calls
        };
        if narf_scheduler::block_on(lifecycle.prepare_phy8821c(&factory)) != Err(Error::State)
            || narf_scheduler::block_on(lifecycle.initialize_bytes(|| Err(Error::Memory), vec![]))
                != Err(Error::State)
            || port.0.lock().calls != calls
        {
            return TestResult::Fail(
                "C21 PHY replayed native DMA owner after terminal/completed result",
            );
        }
        // Keep the actual Backend's published buffers pinned on destruction.
        drop(lifecycle);
        if drops.load(Ordering::SeqCst) != 0 {
            return TestResult::Fail("C21 PHY terminal/completed owner reclaimed published DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c",
    smoke_rtw8821ce_real_reserved_dma_owner_survives_phy_success_cancel_and_revocation
);

#[path = "reserved_calibration8821c_tests.rs"]
mod calibration8821c_tests;

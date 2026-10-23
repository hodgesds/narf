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
        let model = self.0.lock();
        let at = usize::from(reg);
        let mut value = u32::from_le_bytes(model.bytes[at..at + 4].try_into().unwrap());
        if reg == 0x1208 {
            value &= !(1 << 31);
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
        Ok(())
    }
    async fn delay_us(&mut self, _: u64) {
        let pending = self.0.lock().pending;
        if pending {
            core::future::pending::<()>().await;
        }
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
        bytes: vec![0; 0x1400],
        calls: 0,
        fail: None,
        pending: false,
        stale_valid: false,
        stall: false,
        ready: true,
        doorbells: 0,
        packets: Vec::new(),
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
    let (backend, port, _) = allocated();
    let bytes = image();
    let mut owner = firmware_transport::Owner::new(backend, 0xc822);
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

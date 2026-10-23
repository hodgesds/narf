use super::{boot, chip, runtime, shared};
use alloc::{collections::BTreeMap, rc::Rc, vec, vec::Vec};
use core::cell::RefCell;
use narf_kernel_test::{kernel_test_in, TestResult};
use runtime::Memory;
const BASE: u32 = 0x180000;
const SIZE: u32 = 0x40000;
const ARM: u32 = 0x18002000;
const WRAP: u32 = 0x18114000;
const SHARED: u32 = BASE + 0x100;
const INFO: u32 = BASE + 0x200;
const RINGS: u32 = BASE + 0x300;
const H2DW: u32 = BASE + 0x400;
const H2DR: u32 = BASE + 0x440;
const D2HW: u32 = BASE + 0x480;
const D2HR: u32 = BASE + 0x4c0;
#[derive(Default)]
struct State {
    registers: BTreeMap<u32, u32>,
    tcm: BTreeMap<u32, u8>,
    dma: BTreeMap<u64, Vec<u8>>,
    writes: Vec<(u32, u32)>,
    dma_enable: bool,
    next: u64,
    allocated: usize,
    dropped: usize,
    doorbells: usize,
    fail_allocate: Option<usize>,
    fail_tcm: bool,
    started: bool,
    unreleased_read: bool,
    unsafe_free: usize,
}
struct Model(Rc<RefCell<State>>);
struct Mem {
    state: Rc<RefCell<State>>,
    address: u64,
    len: usize,
}
impl Drop for Mem {
    fn drop(&mut self) {
        let mut state = self.state.borrow_mut();
        state.dropped += 1;
        if state.unreleased_read {
            state.unsafe_free += 1;
        }
    }
}
impl Memory for Mem {
    fn address(&self) -> u64 {
        self.address
    }
    fn len(&self) -> usize {
        self.len
    }
    fn write(&mut self, at: usize, bytes: &[u8]) -> Result<(), runtime::Error> {
        let mut s = self.state.borrow_mut();
        let buf = s.dma.get_mut(&self.address).unwrap();
        let out = buf
            .get_mut(at..at.checked_add(bytes.len()).ok_or(runtime::Error::Bounds)?)
            .ok_or(runtime::Error::Bounds)?;
        out.copy_from_slice(bytes);
        Ok(())
    }
    fn read(&mut self, at: usize, bytes: &mut [u8]) -> Result<(), runtime::Error> {
        let mut s = self.state.borrow_mut();
        s.unreleased_read = true;
        let buf = s.dma.get(&self.address).unwrap();
        let data = buf
            .get(at..at.checked_add(bytes.len()).ok_or(runtime::Error::Bounds)?)
            .ok_or(runtime::Error::Bounds)?;
        bytes.copy_from_slice(data);
        Ok(())
    }
    fn to_device(&mut self, _: usize, _: usize) {}
    fn sync_from_device(&mut self, _: usize, _: usize) {}
    fn release(&mut self) {
        self.state.borrow_mut().unreleased_read = false;
    }
}
impl chip::Backplane for Model {
    fn read32(&mut self, at: u32) -> Result<u32, chip::Error> {
        let s = self.0.borrow();
        if at == ARM + 0x44 {
            return Ok(15);
        }
        Ok(*s.registers.get(&at).unwrap_or(&0))
    }
    fn write32(&mut self, at: u32, value: u32) -> Result<(), chip::Error> {
        let mut s = self.0.borrow_mut();
        s.registers.insert(at, value);
        s.writes.push((at, value));
        if at == WRAP + 0x408
            && value & 0x20 == 0
            && s.writes.iter().any(|&(a, v)| a == 0 && v == 0x11223344)
        {
            s.started = true;
            put(&mut s, BASE + SIZE - 4, &SHARED.to_le_bytes());
        }
        Ok(())
    }
}
impl boot::Bus for Model {
    fn tcm_extent(&self) -> u32 {
        BASE + SIZE
    }
    fn read_tcm(&mut self, at: u32, bytes: &mut [u8]) -> Result<(), boot::Error> {
        let s = self.0.borrow();
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = *s.tcm.get(&(at + i as u32)).unwrap_or(&0);
        }
        Ok(())
    }
    fn write_tcm(&mut self, at: u32, bytes: &[u8]) -> Result<(), boot::Error> {
        let mut s = self.0.borrow_mut();
        if (D2HR..D2HR + 12).contains(&at) && s.unreleased_read {
            return Err(boot::Error::State);
        }
        if s.fail_tcm {
            return Err(boot::Error::Access);
        }
        put(&mut s, at, bytes);
        if at == 0 && bytes.len() == 4 {
            s.writes
                .push((0, u32::from_le_bytes(bytes.try_into().unwrap())));
        }
        Ok(())
    }
    fn dma_enabled(&mut self) -> Result<bool, boot::Error> {
        Ok(self.0.borrow().dma_enable)
    }
}
impl runtime::Bus for Model {
    type Memory = Mem;
    fn allocate(&mut self, len: usize) -> Result<Mem, runtime::Error> {
        let mut s = self.0.borrow_mut();
        if s.fail_allocate == Some(s.allocated) {
            return Err(runtime::Error::Access);
        }
        s.allocated += 1;
        let at = s.next;
        s.next += ((len + 4095) & !4095) as u64;
        s.dma.insert(at, vec![0; len]);
        Ok(Mem {
            state: self.0.clone(),
            address: at,
            len,
        })
    }
    fn enable_dma(&mut self) -> Result<(), runtime::Error> {
        let mut s = self.0.borrow_mut();
        if s.allocated != 24 {
            return Err(runtime::Error::Protocol);
        }
        s.dma_enable = true;
        Ok(())
    }
    fn park_dma(&mut self) -> Result<(), runtime::Error> {
        self.0.borrow_mut().dma_enable = false;
        Ok(())
    }
    fn doorbell(&mut self) -> Result<(), runtime::Error> {
        self.0.borrow_mut().doorbells += 1;
        Ok(())
    }
    fn host_ready(&mut self, _: bool) -> Result<(), runtime::Error> {
        Ok(())
    }
}
fn put(s: &mut State, at: u32, bytes: &[u8]) {
    for (i, &b) in bytes.iter().enumerate() {
        s.tcm.insert(at + i as u32, b);
    }
}
fn word(s: &State, at: u32) -> u32 {
    u32::from_le_bytes(core::array::from_fn(|i| {
        *s.tcm.get(&(at + i as u32)).unwrap_or(&0)
    }))
}
fn pointer(s: &State, at: u32) -> u64 {
    u64::from_le_bytes(core::array::from_fn(|i| {
        *s.tcm.get(&(at + i as u32)).unwrap_or(&0)
    }))
}
fn model() -> (Model, Rc<RefCell<State>>) {
    let mut s = State {
        next: 0x10000000,
        ..State::default()
    };
    s.registers.insert(chip::ENUM_BASE, 0x1003aa52);
    s.registers.insert(chip::ENUM_BASE + 0xfc, 0x18100000);
    let erom = [
        0x4bf80001,
        0x28080001,
        0x18000005,
        0x18110085,
        0x4bf83c01,
        0x0d004001,
        3,
        0x18012005,
        0x181120c5,
        0x4bf83e01,
        0x07080001,
        ARM | 5,
        WRAP | 0x85,
        0x4bf80e01,
        0x14080001,
        0x18004005,
        0x18116085,
        0x4bf81201,
        0x18080001,
        0x18006005,
        0x18118085,
        15,
    ];
    for (i, w) in erom.into_iter().enumerate() {
        s.registers.insert(0x18100000 + i as u32 * 4, w);
    }
    s.registers.insert(ARM + 4, 2);
    let mut shared = [0; 76];
    shared[0..4].copy_from_slice(&6u32.to_le_bytes());
    shared[36..40].copy_from_slice(&0u32.to_le_bytes());
    shared[40..44].copy_from_slice(&(BASE + 0x500).to_le_bytes());
    shared[44..48].copy_from_slice(&(BASE + 0x504).to_le_bytes());
    shared[48..52].copy_from_slice(&INFO.to_le_bytes());
    put(&mut s, SHARED, &shared);
    for (at, value) in [
        (INFO, RINGS),
        (INFO + 4, H2DW),
        (INFO + 8, H2DR),
        (INFO + 12, D2HW),
        (INFO + 16, D2HR),
    ] {
        put(&mut s, at, &value.to_le_bytes());
    }
    put(&mut s, INFO + 52, &2u16.to_le_bytes());
    put(&mut s, INFO + 54, &4u16.to_le_bytes());
    put(&mut s, INFO + 56, &3u16.to_le_bytes());
    let rc = Rc::new(RefCell::new(s));
    (Model(rc.clone()), rc)
}
fn pci() -> boot::PciIdentity {
    boot::PciIdentity {
        vendor: 0x14e4,
        device: 0x43ba,
        subsystem_vendor: 0x106b,
        subsystem_device: 0x0133,
    }
}
fn profile() -> boot::BoardProfile {
    boot::BoardProfile {
        chip: 43602,
        revision_mask: 8,
        pci: pci(),
        firmware: "brcm/fixture.bin",
        nvram: "brcm/fixture.txt",
    }
}
fn booted(bus: Model) -> boot::Booted<Model> {
    let s = bus.0.borrow();
    let mut bytes = [0; 76];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = *s.tcm.get(&(SHARED + i as u32)).unwrap_or(&0);
    }
    drop(s);
    boot::Booted {
        bus,
        ram: boot::Ram {
            base: BASE,
            size: SIZE,
        },
        shared_address: SHARED,
        shared: shared::SharedInfo::parse(&bytes).unwrap(),
        chip: chip::Chip {
            id: 43602,
            revision: 3,
            cores: vec![],
        },
    }
}
fn complete(
    s: &mut State,
    slot: usize,
    kind: u8,
    id: u32,
    result: (i16, u16),
    transaction: u16,
    command: u32,
) {
    let at = pointer(s, RINGS + 2 * 16 + 8);
    let entry = &mut s.dma.get_mut(&at).unwrap()[slot * 24..slot * 24 + 24];
    entry[0] = kind;
    entry[4..8].copy_from_slice(&id.to_le_bytes());
    entry[8..10].copy_from_slice(&result.0.to_le_bytes());
    entry[12..14].copy_from_slice(&result.1.to_le_bytes());
    entry[14..16].copy_from_slice(&transaction.to_le_bytes());
    entry[16..20].copy_from_slice(&command.to_le_bytes());
    put(s, D2HW, &((slot + 1) as u16).to_le_bytes());
}
fn smoke_brcmf_cr4_board_policy_and_real_boot_transcript() -> TestResult {
    let (bus, s) = model();
    let mut wrong = profile();
    wrong.pci.subsystem_device ^= 1;
    if !matches!(boot::Cr4::claim(bus, pci(), wrong), Err(boot::Error::Board))
        || !s.borrow().writes.is_empty()
    {
        return TestResult::Fail("board policy must precede hardware writes");
    }
    let (bus, s) = model();
    let nvram = match boot::pack_nvram(b"boardrev=1\n") {
        Ok(n) => n,
        Err(_) => return TestResult::Fail("single-board calibration rejected"),
    };
    if nvram != b"boardrev=1\0\0\x03\0\xfc\xff"
        || boot::pack_nvram(b"devpath0=pcie/1/1\nboardrev=1\n").is_ok()
    {
        return TestResult::Fail("NVRAM list padding/token or multi-device gate differs");
    }
    let firmware = [0x44, 0x33, 0x22, 0x11, 9, 8, 7, 6];
    let boot = match boot::Cr4::claim(bus, pci(), profile()).and_then(|o| o.boot(&firmware, &nvram))
    {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("actual CR4 ownership/firmware path failed"),
    };
    let state = s.borrow();
    if boot.ram.size != SIZE
        || boot.shared_address != SHARED
        || !state.started
        || state.dma_enable
        || word(&state, BASE) != 0x11223344
        || word(&state, 0) != 0x11223344
        || !state
            .writes
            .windows(2)
            .any(|w| w == [(ARM + 0x40, 5), (ARM + 0x4c, 0)])
        || !state
            .writes
            .windows(2)
            .any(|w| w == [(ARM + 0x40, 7), (ARM + 0x4c, 0)])
    {
        return TestResult::Fail("CR4 bank/remap/resetvector/shared readiness sequence differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_cr4_board_policy_and_real_boot_transcript
);
fn smoke_brcmf_msgbuf_actual_dma_request_completion() -> TestResult {
    let (bus, s) = model();
    let mut owner = match runtime::Runtime::attach(booted(bus)) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("common ring initialization failed"),
    };
    let ticket = match owner.begin_ioctl(262, b"ver\0", 64) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("production IOCTL submit failed"),
    };
    {
        let mut st = s.borrow_mut();
        if !st.dma_enable
            || st.allocated != 24
            || st.doorbells != 17
            || word(&st, H2DW) & 0xffff != 17
        {
            return TestResult::Fail(
                "rings/input/control buffers not published under retained owner",
            );
        }
        let ring = pointer(&st, RINGS + 8);
        let request = &st.dma.get(&ring).unwrap()[16 * 40..17 * 40];
        if request[0] != 9
            || &request[8..12] != 262u32.to_le_bytes().as_slice()
            || &request[12..14] != 1u16.to_le_bytes().as_slice()
            || &request[14..16] != 64u16.to_le_bytes().as_slice()
            || &request[16..18] != 64u16.to_le_bytes().as_slice()
        {
            return TestResult::Fail("literal Linux IOCTL request fields differ");
        }
        let input = u64::from_le_bytes(request[24..32].try_into().unwrap());
        if st
            .dma
            .get(&input)
            .is_none_or(|b| &b[..4] != b"ver\0" || b[4..64].iter().any(|&x| x != 0))
        {
            return TestResult::Fail("query input not zero padded to physical query extent");
        }
        let post = &st.dma.get(&ring).unwrap()[..40];
        let id = u32::from_le_bytes(post[4..8].try_into().unwrap());
        let address = u64::from_le_bytes(post[16..24].try_into().unwrap());
        st.dma.get_mut(&address).unwrap()[..4].copy_from_slice(b"v1\0\0");
        complete(&mut st, 0, 0xc, id, (0, 4), 1, 262);
    }
    if owner.poll() != Ok(1)
        || !matches!(owner.take_response(&ticket),Ok(Some(Ok(data))) if data==b"v1\0\0")
    {
        return TestResult::Fail("correlated posted-buffer IOCTL response failed");
    }
    drop(owner);
    let st = s.borrow();
    if st.dma_enable || st.dropped != 0 {
        return TestResult::Fail("published DMA was freed before device/IOMMU quiescence");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_msgbuf_actual_dma_request_completion
);
fn smoke_brcmf_msgbuf_event_repost_and_bad_identity_terminal() -> TestResult {
    let (bus, s) = model();
    let mut owner = match runtime::Runtime::attach(booted(bus)) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("common ring initialization failed"),
    };
    let old_id;
    {
        let mut st = s.borrow_mut();
        let ring = pointer(&st, RINGS + 8);
        let post = &st.dma.get(&ring).unwrap()[8 * 40..9 * 40];
        old_id = u32::from_le_bytes(post[4..8].try_into().unwrap());
        let address = u64::from_le_bytes(post[16..24].try_into().unwrap());
        st.dma.get_mut(&address).unwrap()[..4].copy_from_slice(b"evt!");
        complete(&mut st, 0, 0xe, old_id, (0, 4), 0, 0);
    }
    if owner.poll() != Ok(1) || owner.pop_event().as_deref() != Some(b"evt!".as_slice()) {
        return TestResult::Fail("event did not copy before repost");
    }
    {
        let mut st = s.borrow_mut();
        let ring = pointer(&st, RINGS + 8);
        let repost = &st.dma.get(&ring).unwrap()[16 * 40..17 * 40];
        if repost[0] != 0xd || u32::from_le_bytes(repost[4..8].try_into().unwrap()) == old_id {
            return TestResult::Fail("control buffer ID reused");
        }
        complete(&mut st, 1, 0xe, old_id, (0, 4), 0, 0);
    }
    if owner.poll() != Err(runtime::Error::Protocol)
        || !owner.is_failed()
        || owner.begin_ioctl(1, &[], 4).is_ok()
    {
        return TestResult::Fail("stale posted-buffer completion did not poison runtime");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_msgbuf_event_repost_and_bad_identity_terminal
);
fn smoke_brcmf_msgbuf_allocation_publication_retention() -> TestResult {
    for published in [false, true] {
        let (bus, s) = model();
        {
            let mut st = s.borrow_mut();
            if published {
                st.fail_tcm = true;
            } else {
                st.fail_allocate = Some(3);
            }
        }
        if runtime::Runtime::attach(booted(bus)).is_ok() {
            return TestResult::Fail("injected setup failure accepted");
        }
        let st = s.borrow();
        if (published && st.dropped != 0)
            || (!published && st.dropped != st.allocated)
            || st.dma_enable
        {
            return TestResult::Fail(
                "DMA setup ownership crossed publication boundary incorrectly",
            );
        }
    }
    let (bus, s) = model();
    put(&mut s.borrow_mut(), SHARED + 36, &8u32.to_le_bytes());
    if !matches!(
        runtime::Runtime::attach(booted(bus)),
        Err(runtime::Error::Protocol)
    ) || s.borrow().allocated != 0
    {
        return TestResult::Fail("unsupported descriptor prefix allocated/published DMA");
    }
    let (bus, s) = model();
    let mut owner = runtime::Runtime::attach(booted(bus)).unwrap();
    put(&mut s.borrow_mut(), D2HW, &64u16.to_le_bytes());
    if owner.poll() != Err(runtime::Error::Protocol) || !owner.is_failed() {
        return TestResult::Fail("out-of-range peer index admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_msgbuf_allocation_publication_retention
);

fn smoke_brcmf_msgbuf_dropped_command_retains_dma_and_input() -> TestResult {
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    let (bus, s) = model();
    let mut owner = runtime::Runtime::attach(booted(bus)).unwrap();
    {
        let mut future = pin!(owner.command(263, b"secret", 0));
        if !matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ) {
            return TestResult::Fail("uncompleted command did not retain waiter");
        }
    }
    if !owner.is_failed() || owner.begin_ioctl(1, &[], 4).is_ok() {
        return TestResult::Fail("cancelled waiter allowed input DMA overwrite");
    }
    let st = s.borrow();
    let ring = pointer(&st, RINGS + 8);
    let req = &st.dma.get(&ring).unwrap()[16 * 40..17 * 40];
    let input = u64::from_le_bytes(req[24..32].try_into().unwrap());
    if &st.dma.get(&input).unwrap()[..6] != b"secret" || st.dropped != 0 {
        return TestResult::Fail("cancel returned still-active input mapping");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_msgbuf_dropped_command_retains_dma_and_input
);
fn ethernet() -> [u8; 60] {
    let mut frame = [0xa5; 60];
    frame[..6].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame[12..14].copy_from_slice(&[8, 0]);
    frame
}
fn flow_reply(st: &mut State, slot: usize, kind: u8, flow: u16) {
    complete(st, slot, kind, 0, (0, 0), 0, 0);
    let address = pointer(st, RINGS + 2 * 16 + 8);
    st.dma.get_mut(&address).unwrap()[slot * 24 + 10..slot * 24 + 12]
        .copy_from_slice(&flow.to_le_bytes());
}
fn smoke_brcmf_actual_flow_tx_lifecycle_and_retirement() -> TestResult {
    let (bus, s) = model();
    let mut owner = runtime::Runtime::attach(booted(bus)).unwrap();
    owner.enable_data().unwrap();
    let frame = ethernet();
    let flow = owner
        .open_flow(
            frame[6..12].try_into().unwrap(),
            frame[..6].try_into().unwrap(),
            3,
        )
        .unwrap();
    if owner.flow_state(flow) != Ok(runtime::FlowState::Creating)
        || owner.send(flow, &frame) != Err(runtime::Error::Busy)
    {
        return TestResult::Fail("TX admitted before correlated create completion");
    }
    let flow_address;
    {
        let mut st = s.borrow_mut();
        let ctrl = pointer(&st, RINGS + 8);
        let req = &st.dma.get(&ctrl).unwrap()[16 * 40..17 * 40];
        if req[0] != 3
            || req[8..14] != frame[..6]
            || req[14..20] != frame[6..12]
            || req[20] != 3
            || req[22..24] != [2, 0]
            || req[28..32] != [0, 2, 48, 0]
        {
            return TestResult::Fail("literal flow create request differs from Linux");
        }
        flow_address = u64::from_le_bytes(req[32..40].try_into().unwrap());
        flow_reply(&mut st, 0, 4, 2);
    }
    if owner.poll() != Ok(1) || owner.flow_state(flow) != Ok(runtime::FlowState::Open) {
        return TestResult::Fail("flow create completion not correlated");
    }
    let id = owner.send(flow, &frame).unwrap();
    if owner.close_flow(flow) != Err(runtime::Error::Busy) {
        return TestResult::Fail("flow deleted before TX completion");
    }
    {
        let mut st = s.borrow_mut();
        let desc = &st.dma.get(&flow_address).unwrap()[..48];
        if desc[0] != 0xf
            || desc[8..22] != frame[..14]
            || desc[22..24] != [0x61, 1]
            || desc[40..44] != [0, 0, 46, 0]
        {
            return TestResult::Fail(
                "actual TX path used wrong Ethernet/header/flags/body-length layout",
            );
        }
        let address = u64::from_le_bytes(desc[32..40].try_into().unwrap());
        if st.dma.get(&address).unwrap()[..46] != frame[14..] {
            return TestResult::Fail("TX DMA payload must omit copied Ethernet header");
        }
        let tx_ring = pointer(&st, RINGS + 3 * 16 + 8);
        let entry = &mut st.dma.get_mut(&tx_ring).unwrap()[..16];
        entry[0] = 0x10;
        entry[4..8].copy_from_slice(&id.to_le_bytes());
        entry[10..12].copy_from_slice(&2u16.to_le_bytes());
        put(&mut st, D2HW + 4, &1u16.to_le_bytes());
    }
    if owner.poll() != Ok(1)
        || owner.pop_tx_receipt()
            != Some(runtime::TxReceipt {
                id,
                status: 0,
                tx_status: 0,
            })
        || s.borrow().dropped != 1
        || s.borrow().unsafe_free != 0
    {
        return TestResult::Fail("exact TX completion did not safely retire body DMA");
    }
    owner.close_flow(flow).unwrap();
    {
        flow_reply(&mut s.borrow_mut(), 1, 6, 2);
    }
    if owner.poll() != Ok(1)
        || owner.flow_state(flow) != Ok(runtime::FlowState::Closed)
        || owner.send(flow, &frame) != Err(runtime::Error::Busy)
        || s.borrow().dropped != 1
    {
        return TestResult::Fail("flow delete state or retained ring allocation differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_actual_flow_tx_lifecycle_and_retirement
);
fn smoke_brcmf_actual_rx_copy_repost_and_stale_id() -> TestResult {
    let (bus, s) = model();
    let mut owner = runtime::Runtime::attach(booted(bus)).unwrap();
    owner.enable_data().unwrap();
    let frame = ethernet();
    let id;
    {
        let mut st = s.borrow_mut();
        let rxpost = pointer(&st, RINGS + 16 + 8);
        let post = &st.dma.get(&rxpost).unwrap()[..32];
        id = u32::from_le_bytes(post[4..8].try_into().unwrap());
        if post[0] != 0x11 || post[10..12] != [0, 8] || post[16..24] != [0; 8] {
            return TestResult::Fail("actual RX post metadata/data positions differ");
        }
        let body = u64::from_le_bytes(post[24..32].try_into().unwrap());
        st.dma.get_mut(&body).unwrap()[256..316].copy_from_slice(&frame);
        let complete = pointer(&st, RINGS + 4 * 16 + 8);
        let entry = &mut st.dma.get_mut(&complete).unwrap()[..32];
        entry[0] = 0x12;
        entry[4..8].copy_from_slice(&id.to_le_bytes());
        entry[14..20].copy_from_slice(&[60, 0, 0, 1, 1, 0]);
        put(&mut st, D2HW + 8, &1u16.to_le_bytes());
    }
    if owner.poll() != Ok(1) || owner.pop_received().as_deref() != Some(frame.as_slice()) {
        return TestResult::Fail("wide RX offset/copy-before-repost failed");
    }
    {
        let mut st = s.borrow_mut();
        let post_ring = pointer(&st, RINGS + 16 + 8);
        let repost = &st.dma.get(&post_ring).unwrap()[32 * 32..33 * 32];
        if u32::from_le_bytes(repost[4..8].try_into().unwrap()) == id {
            return TestResult::Fail("RX buffer token reused");
        }
        let complete = pointer(&st, RINGS + 4 * 16 + 8);
        let bytes = st.dma.get_mut(&complete).unwrap();
        let old = bytes[..32].to_vec();
        bytes[32..64].copy_from_slice(&old);
        put(&mut st, D2HW + 8, &2u16.to_le_bytes());
    }
    if owner.poll() != Err(runtime::Error::Protocol) || !owner.is_failed() || s.borrow().dma_enable
    {
        return TestResult::Fail("stale RX completion failed to stop DMA owner");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_actual_rx_copy_repost_and_stale_id
);
fn smoke_brcmf_control_pressure_cannot_starve_data_completion() -> TestResult {
    let (bus, s) = model();
    let mut owner = runtime::Runtime::attach(booted(bus)).unwrap();
    owner.enable_data().unwrap();
    let frame = ethernet();
    let flow = owner
        .open_flow(
            frame[6..12].try_into().unwrap(),
            frame[..6].try_into().unwrap(),
            0,
        )
        .unwrap();
    flow_reply(&mut s.borrow_mut(), 0, 4, 2);
    owner.poll().unwrap();
    let id = owner.send(flow, &frame).unwrap();
    {
        let mut st = s.borrow_mut();
        for slot in 1..33 {
            complete(&mut st, slot, 1, 0, (0, 0), 0, 0);
        }
        let ring = pointer(&st, RINGS + 3 * 16 + 8);
        let tx = &mut st.dma.get_mut(&ring).unwrap()[..16];
        tx[0] = 0x10;
        tx[4..8].copy_from_slice(&id.to_le_bytes());
        tx[10..12].copy_from_slice(&2u16.to_le_bytes());
        put(&mut st, D2HW + 4, &1u16.to_le_bytes());
    }
    if owner.poll() != Ok(11)
        || owner.pop_tx_receipt().is_none()
        || word(&s.borrow(), D2HR) & 0xffff != 11
    {
        return TestResult::Fail(
            "bounded control batch starved TX or exceeded per-ring work bound",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_control_pressure_cannot_starve_data_completion
);
fn smoke_brcmf_data_bad_completion_cannot_retire_dma() -> TestResult {
    for bad_rx in [false, true] {
        let (bus, s) = model();
        let mut owner = runtime::Runtime::attach(booted(bus)).unwrap();
        owner.enable_data().unwrap();
        if bad_rx {
            let mut st = s.borrow_mut();
            let posts = pointer(&st, RINGS + 16 + 8);
            let id = u32::from_le_bytes(st.dma.get(&posts).unwrap()[4..8].try_into().unwrap());
            let ring = pointer(&st, RINGS + 4 * 16 + 8);
            let entry = &mut st.dma.get_mut(&ring).unwrap()[..32];
            entry[0] = 0x12;
            entry[4..8].copy_from_slice(&id.to_le_bytes());
            entry[14..20].copy_from_slice(&[0xea, 5, 0, 4, 1, 0]);
            put(&mut st, D2HW + 8, &1u16.to_le_bytes());
        } else {
            let frame = ethernet();
            let flow = owner
                .open_flow(
                    frame[6..12].try_into().unwrap(),
                    frame[..6].try_into().unwrap(),
                    0,
                )
                .unwrap();
            flow_reply(&mut s.borrow_mut(), 0, 4, 2);
            owner.poll().unwrap();
            let id = owner.send(flow, &frame).unwrap();
            let mut st = s.borrow_mut();
            let ring = pointer(&st, RINGS + 3 * 16 + 8);
            let entry = &mut st.dma.get_mut(&ring).unwrap()[..16];
            entry[0] = 0x10;
            entry[4..8].copy_from_slice(&id.to_le_bytes());
            entry[10..12].copy_from_slice(&3u16.to_le_bytes());
            put(&mut st, D2HW + 4, &1u16.to_le_bytes());
        }
        if owner.poll().is_ok()
            || !owner.is_failed()
            || s.borrow().dropped != 0
            || s.borrow().dma_enable
        {
            return TestResult::Fail(
                "bad RX extent or wrong-flow TX completion freed/kept-running DMA",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_data_bad_completion_cannot_retire_dma
);

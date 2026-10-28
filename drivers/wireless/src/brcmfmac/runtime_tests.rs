use super::{boot, chip, runtime, shared};
use alloc::sync::Arc as Rc;
use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    vec,
    vec::Vec,
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
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
struct Firmware {
    control_read: u16,
    completion_write: u16,
    responses: VecDeque<(u32, u64)>,
    commands: Vec<(u32, Vec<u8>, u16)>,
    station: Option<station_model::Firmware>,
}
#[derive(Default)]
struct State {
    registers: BTreeMap<u32, u32>,
    tcm: BTreeMap<u32, u8>,
    dma: BTreeMap<u64, Vec<u8>>,
    writes: Vec<(u32, u32)>,
    dma_enable: bool,
    dma_enables: usize,
    next: u64,
    allocated: usize,
    dropped: usize,
    dropped_addresses: BTreeSet<u64>,
    doorbells: usize,
    fail_allocate: Option<usize>,
    fail_tcm: bool,
    started: bool,
    unreleased_read: bool,
    unsafe_free: usize,
    firmware: Option<Firmware>,
    /// MSI binding offered by the platform model.
    msi: bool,
    armed: usize,
    disarmed: usize,
    /// H2D mailbox words observed at each SBMBX doorbell.
    sbmbx: Vec<u32>,
    /// Firmware answers D3_INFORM with D3_ACK on the FN0 mailbox.
    d3_ack: bool,
    /// Firmware answers D0_INFORM by restoring INTMASK (still powered).
    d0_alive: bool,
    signal: Option<Rc<super::irq::Signal>>,
    parks: usize,
    /// A device posted write lands after BME clear (flush proof must fail).
    late_dma: bool,
}
pub(crate) struct Model(Rc<IrqSafeSpinLock<State>>);
pub(crate) struct Mem {
    state: Rc<IrqSafeSpinLock<State>>,
    address: u64,
    len: usize,
}
impl Drop for Mem {
    fn drop(&mut self) {
        let mut state = self.state.lock();
        state.dropped += 1;
        state.dropped_addresses.insert(self.address);
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
        let mut s = self.state.lock();
        let buf = s.dma.get_mut(&self.address).unwrap();
        let out = buf
            .get_mut(at..at.checked_add(bytes.len()).ok_or(runtime::Error::Bounds)?)
            .ok_or(runtime::Error::Bounds)?;
        out.copy_from_slice(bytes);
        Ok(())
    }
    fn read(&mut self, at: usize, bytes: &mut [u8]) -> Result<(), runtime::Error> {
        let mut s = self.state.lock();
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
        self.state.lock().unreleased_read = false;
    }
}
impl chip::Backplane for Model {
    fn read32(&mut self, at: u32) -> Result<u32, chip::Error> {
        let s = self.0.lock();
        if at == ARM + 0x44 {
            return Ok(15);
        }
        Ok(*s.registers.get(&at).unwrap_or(&0))
    }
    fn write32(&mut self, at: u32, value: u32) -> Result<(), chip::Error> {
        let mut s = self.0.lock();
        if at == PCIE + 0x48 {
            // MAILBOXINT is write-one-to-clear.
            let old = *s.registers.get(&at).unwrap_or(&0);
            s.registers.insert(at, old & !value);
            s.writes.push((at, value));
            return Ok(());
        }
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
        let s = self.0.lock();
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = *s.tcm.get(&(at + i as u32)).unwrap_or(&0);
        }
        Ok(())
    }
    fn write_tcm(&mut self, at: u32, bytes: &[u8]) -> Result<(), boot::Error> {
        let mut s = self.0.lock();
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
        Ok(self.0.lock().dma_enable)
    }
}
impl runtime::Bus for Model {
    type Memory = Mem;
    fn allocate(&mut self, len: usize) -> Result<Mem, runtime::Error> {
        let mut s = self.0.lock();
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
        let mut s = self.0.lock();
        if s.allocated != 24 {
            return Err(runtime::Error::Protocol);
        }
        s.dma_enable = true;
        s.dma_enables += 1;
        Ok(())
    }
    fn park_dma(&mut self) -> Result<(), runtime::Error> {
        let mut s = self.0.lock();
        s.dma_enable = false;
        s.parks += 1;
        if s.late_dma {
            // A completion index write still in flight across the BME clear.
            let index = word(&s, D2HW) as u16;
            put(&mut s, D2HW, &(index + 1).to_le_bytes());
        }
        Ok(())
    }
    fn doorbell(&mut self) -> Result<(), runtime::Error> {
        let mut state = self.0.lock();
        state.doorbells += 1;
        firmware_step(&mut state);
        Ok(())
    }
    fn host_ready(&mut self, _: bool) -> Result<(), runtime::Error> {
        Ok(())
    }
    fn mailbox(&self) -> Option<runtime::mailbox::Reginfo> {
        Some(runtime::mailbox::Reginfo::for_core(PCIE, 11))
    }
    fn ring_mailbox(&mut self) -> Result<(), runtime::Error> {
        let mut s = self.0.lock();
        let value = word(&s, HTOD_MB);
        s.sbmbx.push(value);
        mailbox_firmware(&mut s, value);
        Ok(())
    }
    fn arm_interrupts(&mut self, signal: &Rc<super::irq::Signal>) -> bool {
        let mut s = self.0.lock();
        if !s.msi {
            return false;
        }
        s.armed += 1;
        s.signal = Some(signal.clone());
        true
    }
    fn disarm_interrupts(&mut self) {
        let mut s = self.0.lock();
        s.disarmed += 1;
        s.signal = None;
    }
}
const PCIE: u32 = 0x18003000;
const HTOD_MB: u32 = BASE + 0x500;
const DTOH_MB: u32 = BASE + 0x504;
/// Firmware half of the host<->dongle mailbox: consumes the H2D word and
/// posts D2H mailbox data with an FN0 status (Linux `brcmf_pcie_send_mb_data`
/// peer behaviour).
fn mailbox_firmware(s: &mut State, value: u32) {
    use runtime::mailbox::*;
    let mut reply = 0;
    if value & H2D_HOST_D3_INFORM != 0 && s.d3_ack {
        reply |= D2H_DEV_D3_ACK;
    }
    if value & H2D_HOST_D0_INFORM != 0 && s.d0_alive {
        s.registers.insert(PCIE + 0x24, 0x300);
    }
    if value & (H2D_HOST_D3_INFORM | H2D_HOST_D0_INFORM | H2D_HOST_DS_ACK) != 0 {
        put(s, HTOD_MB, &0u32.to_le_bytes());
    }
    if reply != 0 {
        raise_mailbox(s, reply);
    }
}
/// Firmware posts D2H mailbox data and asserts FN0 (and the vector).
fn raise_mailbox(s: &mut State, value: u32) {
    let old = word(s, DTOH_MB);
    put(s, DTOH_MB, &(old | value).to_le_bytes());
    raise_status(s, 0x100);
}
/// Firmware asserts MAILBOXINT bits; an armed MSI raises the owner signal.
fn raise_status(s: &mut State, bits: u32) {
    let old = *s.registers.get(&(PCIE + 0x48)).unwrap_or(&0);
    s.registers.insert(PCIE + 0x48, old | bits);
    if let Some(signal) = s.signal.clone() {
        if *s.registers.get(&(PCIE + 0x4c)).unwrap_or(&0) & bits != 0 {
            signal.raise();
        }
    }
}
/// Independent firmware fixture consumes the actual posted 40-byte control
/// descriptors and their DMA input, and writes actual correlated completions.
fn firmware_step(state: &mut State) {
    let Some(mut firmware) = state.firmware.take() else {
        return;
    };
    let address = pointer(state, RINGS + 8);
    if address != 0 {
        let producer = word(state, H2DW) as u16;
        let depth = word(state, RINGS + 4) as u16;
        while firmware.control_read != producer {
            let offset = usize::from(firmware.control_read) * 40;
            let descriptor = state.dma[&address][offset..offset + 40].to_vec();
            let id = u32::from_le_bytes(descriptor[4..8].try_into().unwrap());
            if descriptor[0] == 0xb {
                firmware.responses.push_back((
                    id,
                    u64::from_le_bytes(descriptor[16..24].try_into().unwrap()),
                ));
            } else if descriptor[0] == 0xd && firmware.station.is_some() {
                firmware.station.as_mut().unwrap().post_event(&descriptor);
            } else if matches!(descriptor[0], 3 | 5) {
                let field = if descriptor[0] == 3 { 22 } else { 8 };
                let flow = u16::from_le_bytes(descriptor[field..field + 2].try_into().unwrap());
                if let Some(station) = firmware.station.as_mut() {
                    station.flow(&descriptor);
                }
                flow_reply(
                    state,
                    usize::from(firmware.completion_write),
                    descriptor[0] + 1,
                    flow,
                );
                firmware.completion_write =
                    (firmware.completion_write + 1) % (word(state, RINGS + 2 * 16 + 4) as u16);
                put(state, D2HW, &firmware.completion_write.to_le_bytes());
            } else if descriptor[0] == 9 {
                let command = u32::from_le_bytes(descriptor[8..12].try_into().unwrap());
                let transaction = u16::from_le_bytes(descriptor[12..14].try_into().unwrap());
                let input_len = u16::from_le_bytes(descriptor[14..16].try_into().unwrap());
                let output_len = u16::from_le_bytes(descriptor[16..18].try_into().unwrap());
                let input_dma = u64::from_le_bytes(descriptor[24..32].try_into().unwrap());
                let input = state.dma[&input_dma][..usize::from(input_len)].to_vec();
                firmware.commands.push((command, input.clone(), output_len));
                let response = if let Some(station) = firmware.station.as_mut() {
                    station.command(command, &input, output_len)
                } else {
                    match command {
                        1 => 2u32.to_le_bytes().to_vec(),
                        217 => [3u32, 1, 6, 11]
                            .into_iter()
                            .flat_map(u32::to_le_bytes)
                            .collect(),
                        262 if input.starts_with(b"cur_etheraddr\0") => {
                            // Include the physical query tail: the common station
                            // must still receive exactly its six requested bytes.
                            let mut bytes = vec![0; usize::from(output_len)];
                            bytes[..6].copy_from_slice(&[2, 6, 7, 8, 9, 10]);
                            bytes
                        }
                        262 if input.starts_with(b"sup_wpa\0") => vec![0; usize::from(output_len)],
                        262 if input.starts_with(b"nmode\0") => vec![0; usize::from(output_len)],
                        262 if input.starts_with(b"vhtmode\0") => 0u32.to_le_bytes().to_vec(),
                        262 if input.starts_with(b"mfp\0") => vec![0; usize::from(output_len)],
                        262 if input.starts_with(b"bw_cap\0") => {
                            let mut bytes = vec![0; usize::from(output_len)];
                            bytes[..4].copy_from_slice(&1u32.to_le_bytes());
                            bytes
                        }
                        _ => Vec::new(),
                    }
                };
                if firmware
                    .station
                    .as_ref()
                    .is_some_and(|station| station.hold_mfp_reply(command, &input))
                {
                    // Consume the real control descriptor but withhold its
                    // correlated receipt. Cancellation must retain its DMA.
                    firmware.control_read = (firmware.control_read + 1) % depth;
                    put(state, H2DR, &firmware.control_read.to_le_bytes());
                    continue;
                }
                let (response_id, response_dma) = firmware.responses.pop_front().unwrap();
                let status = firmware
                    .station
                    .as_ref()
                    .map_or(0, |station| station.status(command));
                state.dma.get_mut(&response_dma).unwrap()[..response.len()]
                    .copy_from_slice(&response);
                complete(
                    state,
                    usize::from(firmware.completion_write),
                    0xc,
                    response_id,
                    (status, response.len() as u16),
                    transaction,
                    command,
                );
                firmware.completion_write =
                    (firmware.completion_write + 1) % (word(state, RINGS + 2 * 16 + 4) as u16);
                put(state, D2HW, &firmware.completion_write.to_le_bytes());
            }
            firmware.control_read = (firmware.control_read + 1) % depth;
            put(state, H2DR, &firmware.control_read.to_le_bytes());
        }
    }
    if let Some(mut station) = firmware.station.take() {
        station.step(state, &mut firmware);
        firmware.station = Some(station);
    }
    state.firmware = Some(firmware);
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
fn model() -> (Model, Rc<IrqSafeSpinLock<State>>) {
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
    let rc = Rc::new(IrqSafeSpinLock::new(s));
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
    let s = bus.0.lock();
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
        || !s.lock().writes.is_empty()
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
    let state = s.lock();
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
        let mut st = s.lock();
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
    let st = s.lock();
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
        let mut st = s.lock();
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
        let mut st = s.lock();
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
            let mut st = s.lock();
            if published {
                st.fail_tcm = true;
            } else {
                st.fail_allocate = Some(3);
            }
        }
        if runtime::Runtime::attach(booted(bus)).is_ok() {
            return TestResult::Fail("injected setup failure accepted");
        }
        let st = s.lock();
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
    put(&mut s.lock(), SHARED + 36, &8u32.to_le_bytes());
    if !matches!(
        runtime::Runtime::attach(booted(bus)),
        Err(runtime::Error::Protocol)
    ) || s.lock().allocated != 0
    {
        return TestResult::Fail("unsupported descriptor prefix allocated/published DMA");
    }
    let (bus, s) = model();
    let mut owner = runtime::Runtime::attach(booted(bus)).unwrap();
    put(&mut s.lock(), D2HW, &64u16.to_le_bytes());
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
    let st = s.lock();
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
    flow_reply_status(st, slot, kind, flow, 0);
}
fn flow_reply_status(st: &mut State, slot: usize, kind: u8, flow: u16, status: i16) {
    complete(st, slot, kind, 0, (status, 0), 0, 0);
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
        let mut st = s.lock();
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
        let mut st = s.lock();
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
        || s.lock().dropped != 1
        || s.lock().unsafe_free != 0
    {
        return TestResult::Fail("exact TX completion did not safely retire body DMA");
    }
    owner.close_flow(flow).unwrap();
    {
        flow_reply(&mut s.lock(), 1, 6, 2);
    }
    if owner.poll() != Ok(1)
        || owner.flow_state(flow) != Ok(runtime::FlowState::Closed)
        || owner.send(flow, &frame) != Err(runtime::Error::Busy)
        || s.lock().dropped != 1
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
        let mut st = s.lock();
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
        let mut st = s.lock();
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
    if owner.poll() != Err(runtime::Error::Protocol) || !owner.is_failed() || s.lock().dma_enable {
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
    flow_reply(&mut s.lock(), 0, 4, 2);
    owner.poll().unwrap();
    let id = owner.send(flow, &frame).unwrap();
    {
        let mut st = s.lock();
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
        || word(&s.lock(), D2HR) & 0xffff != 11
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
            let mut st = s.lock();
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
            flow_reply(&mut s.lock(), 0, 4, 2);
            owner.poll().unwrap();
            let id = owner.send(flow, &frame).unwrap();
            let mut st = s.lock();
            let ring = pointer(&st, RINGS + 3 * 16 + 8);
            let entry = &mut st.dma.get_mut(&ring).unwrap()[..16];
            entry[0] = 0x10;
            entry[4..8].copy_from_slice(&id.to_le_bytes());
            entry[10..12].copy_from_slice(&3u16.to_le_bytes());
            put(&mut st, D2HW + 4, &1u16.to_le_bytes());
        }
        if owner.poll().is_ok()
            || !owner.is_failed()
            || s.lock().dropped != 0
            || s.lock().dma_enable
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
fn smoke_fullmac_msgbuf_set_uses_input_extent_and_cancel_retains() -> TestResult {
    use crate::cyw43439::{fullmac::Fullmac, ioctl::Direction};
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    let (bus, s) = model();
    let runtime = runtime::Runtime::attach(booted(bus)).unwrap();
    let mut adapter = super::station_transport::Adapter::new(runtime).unwrap();
    {
        let input = 0u32.to_le_bytes();
        let mut command = pin!(adapter.command(Direction::Set, 86, &input, 1502));
        if !matches!(
            command
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ) {
            return TestResult::Fail("SET did not retain awaited completion");
        }
        let st = s.lock();
        let ring = pointer(&st, RINGS + 8);
        let req = &st.dma.get(&ring).unwrap()[16 * 40..17 * 40];
        if req[14..18] != [4, 0, 4, 0] {
            return TestResult::Fail(
                "msgbuf SET advertised CYW maximum rather than actual input length",
            );
        }
    }
    if adapter.poll().is_ok() || s.lock().dma_enable || s.lock().dropped != 0 {
        return TestResult::Fail("cancelled shared command owner reused/freed input DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_fullmac_msgbuf_set_uses_input_extent_and_cancel_retains
);
fn smoke_fullmac_msgbuf_event_does_not_authorize_port() -> TestResult {
    use crate::cyw43439::fullmac::Fullmac;
    let (bus, s) = model();
    let runtime = runtime::Runtime::attach(booted(bus)).unwrap();
    let mut adapter = super::station_transport::Adapter::new(runtime).unwrap();
    let mut event = [0; 75];
    event[12..14].copy_from_slice(&[0x88, 0x6c]);
    event[14..24].copy_from_slice(&[0x80, 1, 0, 0, 0, 0, 0x10, 0x18, 0, 1]);
    event[24..28].copy_from_slice(&[0, 2, 0, 1]);
    event[28..32].copy_from_slice(&16u32.to_be_bytes());
    event[44..48].copy_from_slice(&3u32.to_be_bytes());
    event[48..54].copy_from_slice(&[2, 0, 0, 0, 0, 9]);
    event[72..].copy_from_slice(b"evt");
    {
        let mut st = s.lock();
        let ring = pointer(&st, RINGS + 8);
        let post = &st.dma.get(&ring).unwrap()[8 * 40..9 * 40];
        let id = u32::from_le_bytes(post[4..8].try_into().unwrap());
        let address = u64::from_le_bytes(post[16..24].try_into().unwrap());
        st.dma.get_mut(&address).unwrap()[..event.len()].copy_from_slice(&event);
        complete(&mut st, 0, 0xe, id, (0, event.len() as u16), 0, 0);
    }
    if adapter.poll() != Ok(1)
        || !matches!(adapter.pop_event(),Some(event) if event.header.event_type==16 && event.payload==b"evt")
        || adapter.send_data(&ethernet(), 0) != Err(crate::cyw43439::runtime::Error::Failed)
    {
        return TestResult::Fail(
            "real msgbuf event framing or pre-authorization data gate differs",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_fullmac_msgbuf_event_does_not_authorize_port
);
fn smoke_fullmac_msgbuf_link_down_closes_prior_flows() -> TestResult {
    use crate::cyw43439::fullmac::Fullmac;
    let (bus, s) = model();
    let runtime = runtime::Runtime::attach(booted(bus)).unwrap();
    let mut adapter = super::station_transport::Adapter::new(runtime).unwrap();
    let peer = [2, 0, 0, 0, 0, 9];
    let frame = ethernet();
    adapter.set_link(Some(peer));
    if adapter.send_data(&frame, 0) != Err(crate::cyw43439::runtime::Error::Busy) {
        return TestResult::Fail("flow creation did not backpressure retained frame");
    }
    flow_reply(&mut s.lock(), 0, 4, 2);
    adapter.poll().unwrap();
    adapter.send_data(&frame, 0).unwrap();
    let id;
    {
        let st = s.lock();
        let ctrl = pointer(&st, RINGS + 8);
        let create = &st.dma.get(&ctrl).unwrap()[16 * 40..17 * 40];
        let flow = u64::from_le_bytes(create[32..40].try_into().unwrap());
        id = u32::from_le_bytes(st.dma.get(&flow).unwrap()[4..8].try_into().unwrap());
    }
    adapter.set_link(None);
    adapter.poll().unwrap();
    if adapter.send_data(&frame, 0) != Err(crate::cyw43439::runtime::Error::Failed)
        || s.lock().dropped != 0
    {
        return TestResult::Fail("link-down admitted data or released pending TX");
    }
    {
        let mut st = s.lock();
        let ring = pointer(&st, RINGS + 3 * 16 + 8);
        let entry = &mut st.dma.get_mut(&ring).unwrap()[..16];
        entry[0] = 0x10;
        entry[4..8].copy_from_slice(&id.to_le_bytes());
        entry[10..12].copy_from_slice(&2u16.to_le_bytes());
        put(&mut st, D2HW + 4, &1u16.to_le_bytes());
    }
    adapter.poll().unwrap();
    flow_reply(&mut s.lock(), 1, 6, 2);
    adapter.poll().unwrap();
    adapter.set_link(Some([2, 0, 0, 0, 0, 10]));
    if adapter.send_data(&frame, 0) != Err(crate::cyw43439::runtime::Error::Busy) {
        return TestResult::Fail("next peer reused old flow instead of fresh create");
    }
    let st = s.lock();
    let ring = pointer(&st, RINGS + 8);
    let create = &st.dma.get(&ring).unwrap()[18 * 40..19 * 40];
    if create[0] != 3 || create[22..24] != [2, 0] || st.dropped != 1 || st.unsafe_free != 0 {
        return TestResult::Fail("old peer flow was not recycled after confirmed deletion");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_fullmac_msgbuf_link_down_closes_prior_flows
);

fn smoke_fullmac_msgbuf_query_returns_requested_extent() -> TestResult {
    use crate::cyw43439::{fullmac::Fullmac, ioctl::Direction};
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    let (bus, state) = model();
    state.lock().firmware = Some(Firmware::default());
    let runtime = runtime::Runtime::attach(booted(bus)).unwrap();
    let mut adapter = super::station_transport::Adapter::new(runtime).unwrap();
    let mut query = pin!(adapter.command(Direction::Get, 262, b"cur_etheraddr\0", 6));
    if query.as_mut().poll(&mut Context::from_waker(Waker::noop()))
        != Poll::Ready(Ok(vec![2, 6, 7, 8, 9, 10]))
    {
        return TestResult::Fail("long iovar query envelope leaked into the station reply");
    }
    let state = state.lock();
    let command = &state.firmware.as_ref().unwrap().commands[0];
    if command.0 != 262 || command.1 != b"cur_etheraddr\0" || command.2 != 14 {
        return TestResult::Fail("actual query descriptor lost its logical input extent");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_fullmac_msgbuf_query_returns_requested_extent
);

fn smoke_brcmf_confirmed_delete_recycles_retained_ring_and_host_generation() -> TestResult {
    let (bus, state) = model();
    state.lock().firmware = Some(Firmware::default());
    let mut runtime = runtime::Runtime::attach(booted(bus)).unwrap();
    runtime.enable_data().unwrap();
    let initial = state.lock().allocated;
    let frame = ethernet();
    let mut previous = None;
    let mut previous_tx = None;
    for cycle in 0..40u16 {
        let flow = runtime
            .open_flow(
                frame[6..12].try_into().unwrap(),
                frame[..6].try_into().unwrap(),
                0,
            )
            .unwrap();
        if let Some(old) = previous {
            if flow == old
                || runtime.flow_state(old) != Err(runtime::Error::Protocol)
                || runtime.send(old, &frame) != Err(runtime::Error::Protocol)
                || runtime.close_flow(old) != Err(runtime::Error::Protocol)
            {
                return TestResult::Fail("recycled firmware flow accepted an earlier host token");
            }
        }
        runtime.poll().unwrap();
        let id = runtime.send(flow, &frame).unwrap();
        if previous_tx.is_some_and(|previous| id <= previous)
            || runtime.close_flow(flow) != Err(runtime::Error::Busy)
        {
            return TestResult::Fail("pending TX was aliased or flow deleted before retirement");
        }
        {
            let mut state = state.lock();
            let ring = pointer(&state, RINGS + 3 * 16 + 8);
            let at = usize::from(cycle) * 16;
            let entry = &mut state.dma.get_mut(&ring).unwrap()[at..at + 16];
            entry[0] = 0x10;
            entry[4..8].copy_from_slice(&id.to_le_bytes());
            entry[10..12].copy_from_slice(&2u16.to_le_bytes());
            put(&mut state, D2HW + 4, &(cycle + 1).to_le_bytes());
        }
        runtime.poll().unwrap();
        if runtime.pop_tx_receipt().map(|receipt| receipt.id) != Some(id) {
            return TestResult::Fail("recycled ring lost its exact TX receipt");
        }
        runtime.close_flow(flow).unwrap();
        runtime.poll().unwrap();
        if runtime.flow_state(flow) != Ok(runtime::FlowState::Closed) {
            return TestResult::Fail("confirmed delete did not fence and close the ring");
        }
        previous = Some(flow);
        previous_tx = Some(id);
    }
    let state = state.lock();
    if state.allocated != initial + 1 + 40 || state.dropped != 40 || state.unsafe_free != 0 {
        return TestResult::Fail(
            "reconnect leaked flow mappings or released DMA before completion",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_confirmed_delete_recycles_retained_ring_and_host_generation
);
fn smoke_brcmf_refused_flow_ops_retire_flow_not_runtime() -> TestResult {
    let (bus, s) = model();
    let mut owner = runtime::Runtime::attach(booted(bus)).unwrap();
    owner.enable_data().unwrap();
    let frame = ethernet();
    let source: [u8; 6] = frame[6..12].try_into().unwrap();
    let destination: [u8; 6] = frame[..6].try_into().unwrap();

    // A refused create retires the flow as Closed; it must not fail-stop
    // the runtime (regression fixture for the flow-refusal poisoning).
    let flow = owner.open_flow(source, destination, 3).unwrap();
    if owner.flow_state(flow) != Ok(runtime::FlowState::Creating) {
        return TestResult::Fail("flow not Creating before refused create completion");
    }
    flow_reply_status(&mut s.lock(), 0, 4, 2, 5);
    if owner.poll() != Ok(1) || owner.flow_state(flow) != Ok(runtime::FlowState::Closed) {
        return TestResult::Fail("refused create did not retire the flow as Closed");
    }
    if owner.send(flow, &frame) != Err(runtime::Error::Busy) {
        return TestResult::Fail("refused flow admitted TX");
    }

    // The runtime is still usable: the retained slot recycles under a new
    // generation, and a granted create opens and carries traffic.
    let flow = owner.open_flow(source, destination, 3).unwrap();
    if owner.flow_state(flow) != Ok(runtime::FlowState::Creating) {
        return TestResult::Fail("recycled flow not Creating after refused create");
    }
    flow_reply(&mut s.lock(), 1, 4, 2);
    if owner.poll() != Ok(1) || owner.flow_state(flow) != Ok(runtime::FlowState::Open) {
        return TestResult::Fail("create after a refused create did not open");
    }
    let id = owner.send(flow, &frame).unwrap();
    {
        let mut st = s.lock();
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
    {
        return TestResult::Fail("TX after a refused create did not retire exactly");
    }

    // A refused delete also retires the flow as Closed — this is the
    // transition station_transport's flow-cache eviction relies on — and
    // the runtime keeps working afterwards.
    owner.close_flow(flow).unwrap();
    if owner.flow_state(flow) != Ok(runtime::FlowState::Deleting) {
        return TestResult::Fail("flow not Deleting before refused delete completion");
    }
    flow_reply_status(&mut s.lock(), 2, 6, 2, 5);
    if owner.poll() != Ok(1) || owner.flow_state(flow) != Ok(runtime::FlowState::Closed) {
        return TestResult::Fail("refused delete did not retire the flow as Closed");
    }
    let flow = owner.open_flow(source, destination, 3).unwrap();
    flow_reply(&mut s.lock(), 3, 4, 2);
    if owner.poll() != Ok(1) || owner.flow_state(flow) != Ok(runtime::FlowState::Open) {
        return TestResult::Fail("runtime unusable after a refused delete");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmf_refused_flow_ops_retire_flow_not_runtime
);

#[cfg(feature = "kernel-test")]
fn smoke_fullmac_station_initializes_over_actual_msgbuf() -> TestResult {
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    let (bus, state) = model();
    state.lock().firmware = Some(Firmware::default());
    let runtime = runtime::Runtime::attach(booted(bus)).unwrap();
    let adapter = super::station_transport::Adapter::new(runtime).unwrap();
    let domain = narf_wireless::reg::RegulatoryDomain {
        country_code: *b"US",
        rules: vec![narf_wireless::reg::RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2472,
            max_bandwidth_mhz: 20,
            max_power_dbm: 17,
            flags: narf_wireless::reg::RegFlags::empty(),
        }],
    };
    let mut initialization = pin!(crate::cyw43439::station::Station::initialize(
        adapter,
        &[],
        domain
    ));
    let station = match initialization
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(Ok(station)) => station,
        _ => return TestResult::Fail("common station did not consume actual msgbuf replies"),
    };
    if station.mac != [2, 6, 7, 8, 9, 10]
        || station.channels != [1, 6, 11]
        || station.bssid.is_some()
        || !station.supplicant
        || station.vht_capabilities() != [None, None]
        || station.vht_connection()
    {
        return TestResult::Fail(
            "firmware-derived station identity/channel/security state differs",
        );
    }
    let state = state.lock();
    let commands = &state.firmware.as_ref().unwrap().commands;
    if !commands
        .iter()
        .any(|(cmd, input, _)| *cmd == 263 && input.starts_with(b"country\0US"))
        || !commands
            .iter()
            .any(|(cmd, input, _)| *cmd == 263 && input == b"roam_off\0\x01\0\0\0")
        || !commands
            .iter()
            .any(|(cmd, input, _)| *cmd == 262 && input.starts_with(b"vhtmode\0"))
        || commands.iter().any(|(_, input, _)| {
            input.starts_with(b"bus:")
                || input.starts_with(b"clmload")
                || input.starts_with(b"txstreams\0")
        })
    {
        return TestResult::Fail(
            "PCIe initialization sent SDIO glom/CLM or omitted station policy",
        );
    }
    TestResult::Pass
}

#[path = "station_model.rs"]
pub(crate) mod station_model;
#[cfg(feature = "kernel-test")]
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_fullmac_station_initializes_over_actual_msgbuf
);

#[path = "mailbox_tests.rs"]
mod mailbox_tests;

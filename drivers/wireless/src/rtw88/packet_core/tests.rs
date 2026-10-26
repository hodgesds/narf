use super::*;
use alloc::{collections::VecDeque, sync::Arc, vec};
use core::sync::atomic::{AtomicBool, Ordering};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
const OWN: [u8; 6] = [2, 1, 2, 3, 4, 5];
fn frame() -> Vec<u8> {
    let mut bytes = vec![0x59; 100];
    bytes[..2].copy_from_slice(&[8, 1]);
    bytes[4..10].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    bytes[10..16].copy_from_slice(&OWN);
    bytes[22..24].fill(0);
    bytes
}
struct Received {
    descriptor: [u8; 8],
    bytes: Vec<u8>,
}
pub(in crate::rtw88) type Reaction =
    dyn Fn(&[u8]) -> Result<(Vec<Vec<u8>>, bool), Error> + Send + Sync;
#[derive(Clone, Copy)]
struct Submission {
    queue: Queue,
    report: Option<u8>,
    length: usize,
}
pub(in crate::rtw88) struct Controls {
    pub(in crate::rtw88) held: AtomicBool,
    pub(in crate::rtw88) release: AtomicBool,
    pub(in crate::rtw88) corrupt_receipt: AtomicBool,
    pub(in crate::rtw88) incoming: IrqSafeSpinLock<VecDeque<Vec<u8>>>,
    pub(in crate::rtw88) incoming_profiles: IrqSafeSpinLock<VecDeque<(Vec<u8>, u8, u8)>>,
}
impl Default for Controls {
    fn default() -> Self {
        Self {
            held: AtomicBool::new(false),
            release: AtomicBool::new(false),
            corrupt_receipt: AtomicBool::new(false),
            incoming: IrqSafeSpinLock::new(VecDeque::new()),
            incoming_profiles: IrqSafeSpinLock::new(VecDeque::new()),
        }
    }
}
pub(in crate::rtw88) struct Model {
    pub(in crate::rtw88) receive_chip: crate::rtw88::packet_phy::Chip,
    indices: [u32; 3],
    pub(in crate::rtw88) now: u64,
    pub(in crate::rtw88) live: bool,
    pub(in crate::rtw88) allowed: bool,
    pub(in crate::rtw88) active: bool,
    allocations: usize,
    pub(in crate::rtw88) publications: usize,
    pub(in crate::rtw88) tx_publications: usize,
    ignore: bool,
    bodies: [Option<Vec<u8>>; 2],
    rx: VecDeque<Received>,
    tag: u16,
    payload_cpu: Option<usize>,
    payload_dma: Option<u64>,
    pub(in crate::rtw88) reaction: Option<Arc<Reaction>>,
    pub(in crate::rtw88) authority: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    pub(in crate::rtw88) after_descriptor: Option<Arc<dyn Fn() + Send + Sync>>,
    pub(in crate::rtw88) after_idle: Option<Arc<dyn Fn() + Send + Sync>>,
    pub(in crate::rtw88) last_descriptor: Option<[u8; 48]>,
    submission: Option<Submission>,
    held: Option<Submission>,
    pub(in crate::rtw88) controls: Arc<Controls>,
}
impl Model {
    pub(in crate::rtw88) fn payload_identity(&self) -> Option<(usize, u64)> {
        Some((self.payload_cpu?, self.payload_dma?))
    }
    pub(in crate::rtw88) fn new() -> Self {
        Self {
            receive_chip: crate::rtw88::packet_phy::Chip::C22,
            indices: [0; 3],
            now: 0,
            live: true,
            allowed: true,
            active: false,
            allocations: 0,
            publications: 0,
            tx_publications: 0,
            ignore: false,
            bodies: [None, None],
            rx: VecDeque::new(),
            tag: 0,
            payload_cpu: None,
            payload_dma: None,
            reaction: None,
            authority: None,
            after_descriptor: None,
            after_idle: None,
            last_descriptor: None,
            submission: None,
            held: None,
            controls: Arc::new(Controls::default()),
        }
    }
    fn slot(register: u16) -> Result<usize, Error> {
        match register {
            0x3b0 => Ok(0),
            0x3a8 => Ok(1),
            0x3b4 => Ok(2),
            _ => Err(Error::Address),
        }
    }
    pub(in crate::rtw88) fn guard(&self) -> Result<(), Error> {
        if self.live {
            Ok(())
        } else {
            Err(Error::Access)
        }
    }
    pub(in crate::rtw88) fn consumed(&mut self, queue: Queue) {
        let i = queue_slot(queue);
        let host = self.indices[i] & 0xfff;
        self.indices[i] = host | host << 16;
    }
    pub(in crate::rtw88) fn receive(&mut self, body: &[u8], c2h: bool, bad_crc: bool) {
        let mut bytes = vec![0; format::RX_DESC];
        let first = (body.len() + if c2h { 0 } else { 4 }) as u32 | u32::from(bad_crc) << 14;
        bytes[..4].copy_from_slice(&first.to_le_bytes());
        bytes[8..12].copy_from_slice(&(u32::from(c2h) << 28).to_le_bytes());
        bytes.extend_from_slice(body);
        if !c2h {
            bytes.extend_from_slice(&[0; 4]);
        }
        let mut descriptor = [0; 8];
        descriptor[2..4].copy_from_slice(&self.tag.to_le_bytes());
        self.tag = (self.tag + 1) % 8192;
        self.rx.push_back(Received { descriptor, bytes });
        let next = (((self.indices[2] >> 16) & 0xfff) + 1) % 512;
        self.indices[2] = self.indices[2] & 0xfff | next << 16;
    }
    pub(in crate::rtw88) fn receive_rate(&mut self, body: &[u8], rate: u8, bw: u8) {
        self.receive(body, false, false);
        let packet = self.rx.back_mut().unwrap();
        packet.bytes[12] = rate;
        packet.bytes[16] = bw << 4;
    }
    /// Authored native descriptor/status bytes. No production status encoder
    /// is used to create expectations for the parser under test.
    pub(in crate::rtw88) fn receive_status(
        &mut self,
        body: &[u8],
        status: &[u8],
        info: u8,
        present: bool,
        shift: u8,
    ) {
        self.receive_rate(body, 19, 0);
        let packet = self.rx.back_mut().unwrap();
        let first = (body.len() + 4) as u32
            | u32::from(info) << 16
            | u32::from(present) << 26
            | u32::from(shift) << 24;
        packet.bytes[..4].copy_from_slice(&first.to_le_bytes());
        let mut raw = packet.bytes[..24].to_vec();
        raw.resize(24 + usize::from(shift), 0xe5);
        raw.extend_from_slice(status);
        raw.extend_from_slice(body);
        raw.extend_from_slice(&[0; 4]);
        packet.bytes = raw;
    }
    pub(in crate::rtw88) fn report(&mut self, sequence: u8, success: bool) {
        let mut body = [0; 12];
        body[0] = 255;
        body[2] = 15;
        body[10] = sequence;
        body[11] = if success { 0 } else { 0x40 };
        self.receive(&body, true, false);
    }
    pub(in crate::rtw88) fn mutate_payload(&mut self) {
        if let Some(address) = self.payload_cpu {
            // SAFETY: Model records the live CPU provenance from allocation;
            // it is retained by Core, and no concurrent CPU/model access runs.
            unsafe {
                (address as *mut u8)
                    .add(format::TX_DESC + 50)
                    .write_volatile(0xee);
            }
        }
    }
    pub(in crate::rtw88) fn complete_held(&mut self) -> bool {
        let Some(submission) = self.held.take() else {
            return false;
        };
        self.consumed(submission.queue);
        self.controls.held.store(false, Ordering::Release);
        if let Some(sequence) = submission.report {
            self.report(sequence, true);
        }
        true
    }
    fn actual_body(&self, submission: Submission) -> Result<Vec<u8>, Error> {
        let pointer = self.payload_cpu.ok_or(Error::Memory)? as *const u8;
        // SAFETY: the model records the CPU pointer from this same retained
        // allocation; tx_descriptor checked the complete submission extent.
        Ok(unsafe {
            core::slice::from_raw_parts(pointer.add(format::TX_DESC), submission.length).to_vec()
        })
    }
    fn asynchronous_device_progress(&mut self) {
        loop {
            let next = self.controls.incoming_profiles.lock().pop_front();
            let Some((bytes, rate, bw)) = next else {
                break;
            };
            self.receive_rate(&bytes, rate, bw);
        }
        if self.controls.corrupt_receipt.swap(false, Ordering::AcqRel) {
            self.mutate_payload();
        }
        if self.controls.release.swap(false, Ordering::AcqRel) {
            self.complete_held();
        }
        loop {
            let next = self.controls.incoming.lock().pop_front();
            let Some(bytes) = next else { break };
            self.receive(&bytes, false, false);
        }
    }
}
// SAFETY: inert single-threaded model owns unique real coherent allocations;
// simulated bus addresses only match complete owned maps, never become CPU pointers.
unsafe impl Port for Model {
    fn receive_chip(&self) -> Result<crate::rtw88::packet_phy::Chip, Error> {
        Ok(self.receive_chip)
    }
    fn transmit_allowed(&mut self) -> Result<(), Error> {
        self.guard()?;
        if self.allowed && self.authority.as_ref().is_none_or(|check| check()) {
            Ok(())
        } else {
            Err(Error::Access)
        }
    }
    fn memory<T>(&mut self, op: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        self.guard()?;
        self.asynchronous_device_progress();
        op()
    }
    fn allocate(&mut self, length: usize) -> Result<DmaBuffer, Error> {
        self.guard()?;
        self.allocations += 1;
        let buffer = narf_io::alloc_coherent_masked(
            length,
            narf_lib::id::DomainId::DRIVER_0,
            u64::from(u32::MAX),
        )
        .map_err(|_| Error::Memory)?;
        self.payload_cpu = Some(buffer.cpu_mut_ptr_at::<u8>(0) as usize);
        self.payload_dma = Some(buffer.dma_addr().raw());
        Ok(buffer)
    }
    fn index(&mut self, reg: u16) -> Result<u32, Error> {
        self.guard()?;
        self.asynchronous_device_progress();
        let value = self.indices[Self::slot(reg)?];
        // Device-side hook after the exact final RX-idle register read was
        // authorized and observed, before its consumer publishes host state.
        if reg == 0x3b4 && value & 0xfff == (value >> 16) & 0xfff {
            if let Some(callback) = self.after_idle.clone() {
                callback();
            }
        }
        Ok(value)
    }
    fn publish(&mut self, reg: u16, host: u16) -> Result<(), Error> {
        self.guard()?;
        self.publications += 1;
        if self.ignore {
            return Err(Error::Access);
        }
        let index = Self::slot(reg)?;
        if index < 2 {
            self.tx_publications += 1;
        }
        self.indices[index] = self.indices[index] & 0xffff_0000 | u32::from(host);
        if let Some(submission) = self
            .submission
            .filter(|submission| submission.queue.index() == reg)
        {
            self.submission = None;
            if let Some(reaction) = self.reaction.clone() {
                // The simulated device consumes current DMA bytes at the
                // doorbell, independently of the earlier descriptor write.
                let body = self.actual_body(submission)?;
                self.bodies[queue_slot(submission.queue)] = Some(body.clone());
                let (responses, hold) = reaction(&body)?;
                for response in responses {
                    self.receive(&response, false, false);
                }
                if hold {
                    self.held = Some(submission);
                    self.controls.held.store(true, Ordering::Release);
                } else {
                    self.consumed(submission.queue);
                    if let Some(sequence) = submission.report {
                        self.report(sequence, true);
                    }
                }
            }
        }
        Ok(())
    }
    fn tx_descriptor(
        &mut self,
        queue: Queue,
        _slot: usize,
        descriptor: &[u8; 16],
    ) -> Result<(), Error> {
        self.guard()?;
        let address = u32::from_le_bytes(descriptor[4..8].try_into().unwrap()) as u64;
        let length = u32::from_le_bytes(descriptor[8..12].try_into().unwrap()) as usize;
        if Some(address) != self.payload_dma || length > format::MAX_MPDU {
            return Err(Error::Address);
        }
        let pointer = self.payload_cpu.ok_or(Error::Memory)? as *const u8;
        // SAFETY: this CPU pointer was recorded from this exact allocation;
        // full extent is validated, synchronous model observes published data.
        let body = unsafe { core::slice::from_raw_parts(pointer.add(format::TX_DESC), length) };
        self.bodies[queue_slot(queue)] = Some(body.to_vec());
        // SAFETY: descriptor is the first48 bytes of this same validated live
        // mapping. Observe actual requested CCX identity, never synthesize one
        // from the host station's pending state.
        let descriptor = unsafe { core::slice::from_raw_parts(pointer, format::TX_DESC) };
        self.last_descriptor = Some(descriptor.try_into().map_err(|_| Error::Packet)?);
        let status = u32::from_le_bytes(descriptor[8..12].try_into().unwrap());
        let sequence = descriptor[24] & 0xfc;
        self.submission = Some(Submission {
            queue,
            report: (status & (1 << 19) != 0).then_some(sequence),
            length,
        });
        if let Some(callback) = self.after_descriptor.clone() {
            callback();
        }
        Ok(())
    }
    fn rx_descriptor(&mut self, _slot: usize) -> Result<[u8; 8], Error> {
        self.guard()?;
        Ok(self.rx.front().ok_or(Error::State)?.descriptor)
    }
    fn rx_bytes(&mut self, _slot: usize, offset: usize, length: usize) -> Result<Vec<u8>, Error> {
        self.guard()?;
        self.rx
            .front()
            .ok_or(Error::State)?
            .bytes
            .get(offset..offset + length)
            .map(|bytes| bytes.to_vec())
            .ok_or(Error::Address)
    }
    fn rx_repost(&mut self, _slot: usize) -> Result<(), Error> {
        self.guard()?;
        self.rx.pop_front().ok_or(Error::State)?;
        Ok(())
    }
    fn start(&mut self) -> Result<(), Error> {
        self.guard()?;
        self.active = true;
        Ok(())
    }
    fn stop(&mut self) -> Result<(), Error> {
        self.guard()?;
        self.active = false;
        Ok(())
    }
    fn now_us(&self) -> u64 {
        self.now
    }
}
fn check_native_ccx_and_real_rx_idle() -> Result<(), &'static str> {
    let mut model = Model::new();
    let mut core = Core::prepare(&mut model, OWN, 0).map_err(|_| "prepare")?;
    core.start(&mut model).map_err(|_| "start")?;
    let bytes = frame();
    let id = core
        .submit(&mut model, &bytes, true)
        .map_err(|_| "submit")?;
    if model.bodies[1].as_ref() != Some(&bytes) {
        return Err("actual DMA body differs");
    }
    model.consumed(Queue::Data);
    if core.poll(&mut model).map_err(|_| "poll")?.receipt.is_some() {
        return Err("DMA alone delivered security reply");
    }
    model.receive(&bytes, false, true);
    let bad = core.poll(&mut model).map_err(|_| "bad CRC consumed")?;
    if !bad.consumed_rx || bad.frame.is_some() || core.rx_idle {
        return Err("CRC became frame/idle fence");
    }
    model.report(0, true);
    let done = core.poll(&mut model).map_err(|_| "report")?;
    let receipt = done.receipt.ok_or("missing exact CCX receipt")?;
    if receipt.id != id
        || receipt.bytes != bytes
        || !receipt.radio_acknowledged
        || !done.consumed_rx
        || core.rx_idle
    {
        return Err("CCX/fence identity mismatch");
    }
    if core.poll(&mut model).map_err(|_| "idle")?.consumed_rx || !core.rx_idle {
        return Err("missing genuine RX idle");
    }
    // Wrap all64 report identities only after each exact terminal report.
    for _ in 1..130 {
        core.submit(&mut model, &bytes, true)
            .map_err(|_| "wrapped submit")?;
        let sn = core
            .pending
            .as_ref()
            .and_then(|p| p.sequence)
            .ok_or("report identity")?;
        model.report(sn, true); // report may precede transport retirement.
        if core
            .poll(&mut model)
            .map_err(|_| "early report")?
            .receipt
            .is_some()
        {
            return Err("CCX alone retired DMA");
        }
        model.consumed(Queue::Data);
        if core
            .poll(&mut model)
            .map_err(|_| "retire")?
            .receipt
            .is_none()
        {
            return Err("wrapped receipt missing");
        }
    }
    core.stop(&mut model).map_err(|_| "stop")?;
    if core.ready() || core.submit(&mut model, &bytes, false).is_ok() {
        return Err("stopped generation reused");
    }
    Ok(())
}
fn check_native_failure_policy_and_actual_payload() -> Result<(), &'static str> {
    for mode in 0..6 {
        let mut model = Model::new();
        let mut core = Core::prepare(&mut model, OWN, 0).map_err(|_| "prepare")?;
        core.start(&mut model).map_err(|_| "start")?;
        let bytes = frame();
        core.submit(&mut model, &bytes, true)
            .map_err(|_| "submit")?;
        match mode {
            0 => model.live = false,
            1 => model.allowed = false,
            2 => model.now = 1_000_000,
            3 => {
                model.report(0, false);
                model.consumed(Queue::Data);
            }
            4 => model.indices[1] |= 4 << 16,
            _ => {
                model.mutate_payload();
                model.report(0, true);
                model.consumed(Queue::Data);
            }
        }
        let result = core.poll(&mut model);
        if mode == 5 {
            let receipt = result
                .map_err(|_| "modified native payload")?
                .receipt
                .ok_or("modified receipt absent")?;
            if receipt.bytes == bytes || receipt.bytes[50] != 0xee {
                return Err("receipt used cached CPU reply");
            }
        } else if result.is_ok() || core.ready() || core.submit(&mut model, &bytes, true).is_ok() {
            return Err("failed packet owner replayed");
        }
        if !core.published || core.frame.is_none() {
            return Err("uncertain payload not retained");
        }
    }
    Ok(())
}
fn smoke_rtw8822ce_native_packet_ccx_rx_idle_and_wrap() -> TestResult {
    match check_native_ccx_and_real_rx_idle() {
        Ok(()) => TestResult::Pass,
        Err(error) => TestResult::Fail(error),
    }
}
fn smoke_rtw8822ce_native_packet_policy_failure_and_dma_bytes() -> TestResult {
    match check_native_failure_policy_and_actual_payload() {
        Ok(()) => TestResult::Pass,
        Err(error) => TestResult::Fail(error),
    }
}
kernel_test_in!(
    "drivers/wireless/rtw88/packet",
    smoke_rtw8822ce_native_packet_ccx_rx_idle_and_wrap
);
kernel_test_in!(
    "drivers/wireless/rtw88/packet",
    smoke_rtw8822ce_native_packet_policy_failure_and_dma_bytes
);

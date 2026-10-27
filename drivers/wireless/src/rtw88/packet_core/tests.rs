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
    address: u64,
    next: u16,
}
pub(in crate::rtw88) struct Controls {
    pub(in crate::rtw88) held: AtomicBool,
    pub(in crate::rtw88) release: AtomicBool,
    pub(in crate::rtw88) corrupt_receipt: AtomicBool,
    pub(in crate::rtw88) fifo_stuck: AtomicBool,
    pub(in crate::rtw88) fifo_invalid: AtomicBool,
    pub(in crate::rtw88) incoming: IrqSafeSpinLock<VecDeque<Vec<u8>>>,
    pub(in crate::rtw88) incoming_profiles: IrqSafeSpinLock<VecDeque<(Vec<u8>, u8, u8)>>,
}
impl Default for Controls {
    fn default() -> Self {
        Self {
            held: AtomicBool::new(false),
            release: AtomicBool::new(false),
            corrupt_receipt: AtomicBool::new(false),
            fifo_stuck: AtomicBool::new(false),
            fifo_invalid: AtomicBool::new(false),
            incoming: IrqSafeSpinLock::new(VecDeque::new()),
            incoming_profiles: IrqSafeSpinLock::new(VecDeque::new()),
        }
    }
}
pub(in crate::rtw88) struct Model {
    pub(in crate::rtw88) originator_ba: bool,
    pub(in crate::rtw88) recipient_ba: bool,
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
    payloads: Vec<(u64, usize, usize)>,
    pub(in crate::rtw88) reaction: Option<Arc<Reaction>>,
    pub(in crate::rtw88) authority: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    pub(in crate::rtw88) after_descriptor: Option<Arc<dyn Fn() + Send + Sync>>,
    pub(in crate::rtw88) after_idle: Option<Arc<dyn Fn() + Send + Sync>>,
    pub(in crate::rtw88) last_descriptor: Option<[u8; 48]>,
    submissions: VecDeque<Submission>,
    held: VecDeque<Submission>,
    pub(in crate::rtw88) descriptors: Vec<[u8; 48]>,
    pub(in crate::rtw88) controls: Arc<Controls>,
}
impl Model {
    pub(in crate::rtw88) fn payload_identity(&self) -> Option<(usize, u64)> {
        Some((self.payload_cpu?, self.payload_dma?))
    }
    pub(in crate::rtw88) fn new() -> Self {
        Self {
            recipient_ba: false,
            originator_ba: false,
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
            payloads: Vec::new(),
            reaction: None,
            authority: None,
            after_descriptor: None,
            after_idle: None,
            last_descriptor: None,
            submissions: VecDeque::new(),
            held: VecDeque::new(),
            descriptors: Vec::new(),
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
        let Some(submission) = self
            .held
            .front()
            .or_else(|| self.submissions.front())
            .copied()
        else {
            return;
        };
        if let Some(&(_, address, extent)) =
            self.payloads.iter().find(|p| p.0 == submission.address)
        {
            if submission.length == 0 || format::TX_DESC + submission.length > extent {
                return;
            }
            // Corrupt the actual submitted body, including a33-byte ADDBA
            // response or20-byte BAR. Byte50 could otherwise hit only DMA
            // padding and leave the immutable receipt completely unchanged.
            let offset = 50.min(submission.length - 1);
            // SAFETY: Model records the live CPU provenance from allocation;
            // the complete submitted extent is checked and retained by Core,
            // with no concurrent CPU/model access.
            unsafe {
                let byte = (address as *mut u8).add(format::TX_DESC + offset);
                let value = byte.read_volatile();
                byte.write_volatile(if value == 0xee { 0xed } else { 0xee });
            }
        }
    }
    pub(in crate::rtw88) fn complete_held(&mut self) -> bool {
        if self.held.is_empty() {
            return false;
        }
        while let Some(submission) = self.held.pop_front() {
            let i = queue_slot(submission.queue);
            self.indices[i] = self.indices[i] & 0xffff | u32::from(submission.next) << 16;
            if let Some(sequence) = submission.report {
                self.report(sequence, true);
            }
        }
        self.controls.held.store(false, Ordering::Release);
        true
    }
    fn actual_body(&self, submission: Submission) -> Result<Vec<u8>, Error> {
        let (_, pointer, extent) = *self
            .payloads
            .iter()
            .find(|p| p.0 == submission.address)
            .ok_or(Error::Address)?;
        if format::TX_DESC + submission.length > extent {
            return Err(Error::Address);
        }
        let pointer = pointer as *const u8;
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
    fn originator_ba_allowed(&self) -> bool {
        self.originator_ba
    }
    fn recipient_ba_allowed(&self) -> bool {
        self.recipient_ba
    }
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
        let cpu = buffer.cpu_mut_ptr_at::<u8>(0) as usize;
        let dma = buffer.dma_addr().raw();
        self.payload_cpu.get_or_insert(cpu);
        self.payload_dma.get_or_insert(dma);
        self.payloads.push((dma, cpu, buffer.len()));
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
        if let Some(reaction) = self.reaction.clone() {
            while let Some(position) = self.submissions.iter().position(|s| s.queue.index() == reg)
            {
                let submission = self.submissions.remove(position).ok_or(Error::State)?;
                // The simulated device consumes current DMA bytes at the
                // doorbell, independently of the earlier descriptor write.
                let body = self.actual_body(submission)?;
                self.bodies[queue_slot(submission.queue)] = Some(body.clone());
                let (responses, hold) = reaction(&body)?;
                for response in responses {
                    self.receive(&response, false, false);
                }
                if hold {
                    self.held.push_back(submission);
                    self.controls.held.store(true, Ordering::Release);
                } else {
                    let i = queue_slot(submission.queue);
                    self.indices[i] = self.indices[i] & 0xffff | u32::from(submission.next) << 16;
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
        slot: usize,
        descriptor: &[u8; 16],
    ) -> Result<(), Error> {
        self.guard()?;
        let address = u32::from_le_bytes(descriptor[4..8].try_into().unwrap()) as u64;
        let length = u32::from_le_bytes(descriptor[8..12].try_into().unwrap()) as usize;
        let (_, pointer, extent) = *self
            .payloads
            .iter()
            .find(|p| p.0 == address)
            .ok_or(Error::Address)?;
        if length > format::MAX_MPDU || format::TX_DESC + length > extent {
            return Err(Error::Address);
        }
        let pointer = pointer as *const u8;
        // SAFETY: this CPU pointer was recorded from this exact allocation;
        // full extent is validated, synchronous model observes published data.
        let body = unsafe { core::slice::from_raw_parts(pointer.add(format::TX_DESC), length) };
        self.bodies[queue_slot(queue)] = Some(body.to_vec());
        // SAFETY: descriptor is the first48 bytes of this same validated live
        // mapping. Observe actual requested CCX identity, never synthesize one
        // from the host station's pending state.
        let descriptor = unsafe { core::slice::from_raw_parts(pointer, format::TX_DESC) };
        self.last_descriptor = Some(descriptor.try_into().map_err(|_| Error::Packet)?);
        self.descriptors
            .push(descriptor.try_into().map_err(|_| Error::Packet)?);
        let status = u32::from_le_bytes(descriptor[8..12].try_into().unwrap());
        let sequence = descriptor[24] & 0xfc;
        self.submissions.push_back(Submission {
            queue,
            report: (status & (1 << 19) != 0).then_some(sequence),
            length,
            address,
            next: ((slot + 1) % queue.depth()) as u16,
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

fn smoke_rtw88_rx_ba_native_emitter_requires_separate_grant_and_ccx() -> TestResult {
    let result = (|| -> Result<(), &'static str> {
        let mut model = Model::new();
        let mut core = Core::prepare(&mut model, OWN, 0).map_err(|_| "recipient packet prepare")?;
        core.start(&mut model)
            .map_err(|_| "recipient packet start")?;
        core.configure_data(format::DataProfile {
            rates: 0xfff,
            qos: true,
            mcs: 255,
            sgi: false,
        })
        .map_err(|_| "recipient H profile")?;
        let ap = [2, 0, 0, 0, 0, 1];
        let mut response = vec![0xd0, 0, 0, 0];
        response.extend_from_slice(&ap);
        response.extend_from_slice(&OWN);
        response.extend_from_slice(&ap);
        response.extend_from_slice(&[0, 0, 3, 1, 1, 0, 0, 3, 2, 0, 0]);
        if core.submit(&mut model, &response, true) != Err(Error::Access)
            || core.pending.is_some()
            || model.last_descriptor.is_some()
        {
            return Err("H alone published BA success");
        }
        model.recipient_ba = true;
        let id = core
            .submit(&mut model, &response, true)
            .map_err(|_| "recipient success actual DMA")?;
        model.consumed(Queue::Management);
        if core
            .poll(&mut model)
            .map_err(|_| "recipient DMA progress")?
            .receipt
            .is_some()
        {
            return Err("PCI consumption invented CCX");
        }
        model.report(0, true);
        let receipt = core
            .poll(&mut model)
            .map_err(|_| "recipient actual CCX")?
            .receipt
            .ok_or("recipient CCX missing")?;
        if receipt.id != id || receipt.bytes != response || !receipt.radio_acknowledged {
            return Err("recipient exact native response receipt");
        }
        Ok(())
    })();
    match result {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/rtw88/rx_ba",
    smoke_rtw88_rx_ba_native_emitter_requires_separate_grant_and_ccx
);
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

fn qos_frames() -> Vec<Vec<u8>> {
    (0..4)
        .map(|i| {
            let mut b = frame();
            b[0] = 0x88;
            b[24..26].fill(0);
            b[22..24].copy_from_slice(&((4094u16 + i) & 4095).wrapping_shl(4).to_le_bytes());
            b[30] = i as u8;
            b
        })
        .collect()
}
fn batch_core(model: &mut Model) -> Result<Core, &'static str> {
    let mut core = Core::prepare(model, OWN, 0).map_err(|_| "batch parked allocation")?;
    core.start(model).map_err(|_| "batch core start")?;
    core.configure_data(format::DataProfile {
        rates: 0xfff,
        qos: true,
        mcs: 255,
        sgi: true,
    })
    .map_err(|_| "batch HT profile")?;
    core.aggregation(Some(format::Aggregation {
        density: 4,
        count: 4,
        bytes: 8191,
        airtime: 4000,
    }))
    .map_err(|_| "batch geometry")?;
    Ok(core)
}
fn native_batch_order() -> Result<(), &'static str> {
    let mut model = Model::new();
    model.originator_ba = true;
    let mut core = batch_core(&mut model)?;
    let frames = qos_frames();
    let ids = core
        .submit_batch(&mut model, &frames)
        .map_err(|_| "native batch publication")?;
    if model.allocations != 5
        || model.tx_publications != 1
        || model.submissions.len() != 4
        || model.descriptors.len() != 4
    {
        return Err("batch did not use four parked allocations and one actual WP");
    }
    let mut addresses = Vec::new();
    for (i, s) in model.submissions.iter().enumerate() {
        if addresses.contains(&s.address)
            || model.actual_body(*s).map_err(|_| "actual DMA body")? != frames[i]
        {
            return Err("batch aliased DMA or descriptor/body identity");
        }
        addresses.push(s.address);
        let d = model.descriptors[i];
        if u32::from_le_bytes(d[8..12].try_into().unwrap()) & 0x0078_1000 != 0x0048_1000
            || u32::from_le_bytes(d[12..16].try_into().unwrap()) >> 17 & 31 != 3
        {
            return Err("literal native AMPDU/CCX/density/factor TXD");
        }
    }
    // Firmware reports can arrive backwards; neither CCX nor consumed PCI
    // alone returns ownership, and receipts remain original FIFO order.
    for sequence in [12, 8, 4] {
        model.report(sequence, true);
        if core
            .poll(&mut model)
            .map_err(|_| "reverse CCX")?
            .receipt
            .is_some()
        {
            return Err("out-of-order CCX returned prefix early");
        }
    }
    model.indices[1] = 4 | (2 << 16);
    model.report(0, true);
    let first = core
        .poll(&mut model)
        .map_err(|_| "first consumed prefix")?
        .receipt
        .ok_or("first prefix receipt")?;
    let second = core
        .poll(&mut model)
        .map_err(|_| "second consumed prefix")?
        .receipt
        .ok_or("second prefix receipt")?;
    if first.id != ids[0]
        || first.bytes != frames[0]
        || second.id != ids[1]
        || second.bytes != frames[1]
        || core
            .poll(&mut model)
            .map_err(|_| "unconsumed suffix")?
            .receipt
            .is_some()
    {
        return Err("prefix order/bytes or unconsumed suffix changed");
    }
    model.indices[1] = 4 | (4 << 16);
    for i in 2..4 {
        let r = core
            .poll(&mut model)
            .map_err(|_| "final consumed prefix")?
            .receipt
            .ok_or("final receipt")?;
        if r.id != ids[i] || r.bytes != frames[i] || !r.radio_acknowledged {
            return Err("final per-MPDU CCX/bytes order");
        }
    }
    if !core.ready() {
        return Err("all exact receipts did not release CPU credits");
    }
    Ok(())
}
fn native_batch_failures() -> Result<(), &'static str> {
    for mode in 0..6 {
        let mut model = Model::new();
        model.originator_ba = true;
        let mut core = batch_core(&mut model)?;
        let frames = qos_frames();
        core.submit_batch(&mut model, &frames)
            .map_err(|_| "failure batch submit")?;
        match mode {
            0 => model.allowed = false,
            1 => model.now = 1_000_000,
            2 => {
                model.indices[1] = 4 | (4 << 16);
                model.report(12, false);
            }
            3 => model.indices[1] = 4 | (5 << 16),
            4 => {
                model.report(12, true);
                core.poll(&mut model).map_err(|_| "first suffix CCX")?;
                model.report(12, true);
            }
            _ => {
                copy_to(&core.batch_buffers[0], format::TX_DESC + 50, &[0xee])
                    .map_err(|_| "actual batch DMA modification")?;
                model.indices[1] = 4 | (1 << 16);
                model.report(0, true);
            }
        }
        let result = core.poll(&mut model);
        if mode == 5 {
            let r = result
                .map_err(|_| "actual modified batch receipt")?
                .receipt
                .ok_or("modified batch receipt absent")?;
            if r.bytes == frames[0] || r.bytes[50] != 0xee {
                return Err("batch receipt used cached host bytes");
            }
        } else if result.is_ok() || core.ready() || core.submit_batch(&mut model, &frames).is_ok() {
            return Err("failed native batch remained reusable");
        }
        if !core.batch_published || core.batch_buffers.len() != 4 {
            return Err("ambiguous batch reclaimed DMA");
        }
    }
    Ok(())
}
fn native_batch_bounds() -> Result<(), &'static str> {
    let mut model = Model::new();
    let mut core = batch_core(&mut model)?;
    let frames = qos_frames();
    if core.submit_batch(&mut model, &frames) != Err(Error::Access) || model.tx_publications != 0 {
        return Err("H/R alone emitted TX aggregate");
    }
    model.originator_ba = true;
    let profile = format::DataProfile {
        rates: 0xfff,
        qos: true,
        mcs: 1,
        sgi: false,
    };
    let cfg = format::Aggregation {
        density: 7,
        count: 4,
        bytes: 8191,
        airtime: 4000,
    };
    if cfg.admits_lengths(profile, [usize::MAX].into_iter())
        || cfg.admits_lengths(profile, [1514; 4].into_iter())
        || !cfg.admits_lengths(profile, [100].into_iter())
    {
        return Err("checked length/symbol/time budget changed");
    }
    let admitted = format::Aggregation {
        density: 0,
        count: 4,
        bytes: 8191,
        airtime: 4000,
    };
    if core.aggregation(Some(admitted)).is_err() {
        return Err("bounded current config");
    }
    let alive = Arc::new(AtomicBool::new(true));
    let authority = alive.clone();
    model.authority = Some(Arc::new(move || authority.load(Ordering::Acquire)));
    let calls = Arc::new(core::sync::atomic::AtomicUsize::new(0));
    let observed = calls.clone();
    model.after_descriptor = Some(Arc::new(move || {
        if observed.fetch_add(1, Ordering::AcqRel) == 1 {
            alive.store(false, Ordering::Release);
        }
    }));
    if core.submit_batch(&mut model, &frames) != Err(Error::Access)
        || model.submissions.len() != 2
        || model.tx_publications != 0
        || !core.batch_published
        || core.batch_buffers.len() != 4
    {
        return Err("between-BD revocation escaped current source fence or DMA pin");
    }
    Ok(())
}
fn smoke_rtw88_tx_ba_four_native_dma_ccx_consumed_prefix() -> TestResult {
    match native_batch_order() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
fn smoke_rtw88_tx_ba_native_failures_duplicates_timeout_and_bytes() -> TestResult {
    match native_batch_failures() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
fn smoke_rtw88_tx_ba_native_limits_authority_and_partial_publication() -> TestResult {
    match native_batch_bounds() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/rtw88/tx_ba",
    smoke_rtw88_tx_ba_four_native_dma_ccx_consumed_prefix
);
kernel_test_in!(
    "drivers/wireless/rtw88/tx_ba",
    smoke_rtw88_tx_ba_native_failures_duplicates_timeout_and_bytes
);
kernel_test_in!(
    "drivers/wireless/rtw88/tx_ba",
    smoke_rtw88_tx_ba_native_limits_authority_and_partial_publication
);

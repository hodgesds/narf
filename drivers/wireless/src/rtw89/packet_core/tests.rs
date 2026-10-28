use super::*;
use alloc::{sync::Arc, vec};
use core::sync::atomic::{AtomicBool, Ordering};
use narf_bus::BusDeviceCap;
use narf_capabilities::{object_table, Cap, CapKind, CapSlot, Rights, Write};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

pub(in crate::rtw89) const OWN: [u8; 6] = [2, 1, 2, 3, 4, 5];
pub(in crate::rtw89) fn frame() -> Vec<u8> {
    let mut bytes = vec![0x59; 100];
    bytes[..2].copy_from_slice(&[8, 1]);
    bytes[4..10].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    bytes[10..16].copy_from_slice(&OWN);
    bytes[22..24].fill(0);
    bytes
}
#[derive(Clone, Copy)]
struct Region {
    dma: u64,
    cpu: usize,
    length: usize,
}
#[derive(Clone, Copy, Debug)]
pub(in crate::rtw89) struct Submission {
    pub(in crate::rtw89) legacy_rate: u16,
    /// INFO0 USE_RATE: false when firmware RA owns the DATA rate.
    pub(in crate::rtw89) fixed_rate: bool,
    /// INFO1 DATA_RTY_LOWEST_RATE.
    pub(in crate::rtw89) retry_lowest: u16,
    pub(in crate::rtw89) sequence: u16,
    pub(in crate::rtw89) channel: u8,
    pub(in crate::rtw89) qsel: u8,
    pub(in crate::rtw89) mac_id: u8,
    body: u64,
    length: usize,
    next: u16,
}
pub(in crate::rtw89) type Reaction =
    dyn Fn(&[u8]) -> Result<(Vec<Vec<u8>>, bool), Error> + Send + Sync;
pub(in crate::rtw89) struct Controls {
    pub(in crate::rtw89) held: AtomicBool,
    pub(in crate::rtw89) release: AtomicBool,
    pub(in crate::rtw89) corrupt: AtomicBool,
    pub(in crate::rtw89) incoming: IrqSafeSpinLock<VecDeque<Vec<u8>>>,
}
impl Default for Controls {
    fn default() -> Self {
        Self {
            held: AtomicBool::new(false),
            release: AtomicBool::new(false),
            corrupt: AtomicBool::new(false),
            incoming: IrqSafeSpinLock::new(VecDeque::new()),
        }
    }
}
pub(in crate::rtw89) struct Model {
    registers: Vec<u8>,
    regions: Vec<Region>,
    incoming: VecDeque<rx_packet::Event>,
    pub(in crate::rtw89) authority: Cap<BusDeviceCap, Write>,
    inside: bool,
    pub(in crate::rtw89) allowed: bool,
    peer_live: bool,
    pub(in crate::rtw89) peer: Option<crate::rtw89::station_control::Peer>,
    deny_after_allocation: Option<bool>,
    pub(in crate::rtw89) now: u64,
    accesses: usize,
    allocations: usize,
    pub(in crate::rtw89) publications: usize,
    pub(in crate::rtw89) transmitted: Vec<Vec<u8>>,
    pub(in crate::rtw89) last: Option<Submission>,
    pub(in crate::rtw89) reaction: Option<Arc<Reaction>>,
    pub(in crate::rtw89) consume: bool,
    pub(in crate::rtw89) release: bool,
    ignore: bool,
    pub(in crate::rtw89) controls: Arc<Controls>,
}
impl Model {
    pub(in crate::rtw89) fn new() -> Self {
        let (index, generation) = object_table::register(CapKind::BusDevice);
        // SAFETY: private fresh fixture object has exact BusDevice/Write type.
        let authority = unsafe {
            Cap::mint(CapSlot::new(
                generation,
                index,
                Write::BITS,
                CapKind::BusDevice as u32,
            ))
        };
        let mut registers = vec![0; 65536];
        registers[0x1010..0x1014].copy_from_slice(&format::STOP_ALL.to_le_bytes());
        Self {
            registers,
            regions: Vec::new(),
            incoming: VecDeque::new(),
            authority,
            inside: false,
            allowed: true,
            peer_live: true,
            peer: None,
            deny_after_allocation: None,
            now: 0,
            accesses: 0,
            allocations: 0,
            publications: 0,
            transmitted: Vec::new(),
            last: None,
            reaction: None,
            consume: false,
            release: false,
            ignore: false,
            controls: Arc::new(Controls::default()),
        }
    }
    fn guard(&mut self) -> Result<(), power::Error> {
        if !self.inside {
            return Err(power::Error::Access);
        }
        self.accesses += 1;
        if self.controls.corrupt.swap(false, Ordering::AcqRel) {
            if let Some(submission) = self.last {
                let pointer = self
                    .pointer(submission.body, submission.length)
                    .map_err(|_| power::Error::Access)?;
                // SAFETY: exact retained live mapping resolved through its
                // recorded CPU provenance; no concurrent model/CPU operation.
                unsafe {
                    let byte = pointer.add(submission.length - 1);
                    byte.write_volatile(byte.read_volatile() ^ 1);
                }
            }
        }
        if self.controls.release.swap(false, Ordering::AcqRel) {
            self.complete().map_err(|_| power::Error::Access)?;
        }
        loop {
            let next = self.controls.incoming.lock().pop_front();
            let Some(bytes) = next else { break };
            self.inject(&bytes).map_err(|_| power::Error::Access)?;
        }
        Ok(())
    }
    pub(in crate::rtw89) fn word(&self, address: u32) -> u32 {
        u32::from_le_bytes(
            self.registers[address as usize..address as usize + 4]
                .try_into()
                .unwrap(),
        )
    }
    fn put(&mut self, address: u32, value: u32) {
        self.registers[address as usize..address as usize + 4]
            .copy_from_slice(&value.to_le_bytes());
    }
    fn pointer(&self, address: u64, length: usize) -> Result<*mut u8, Error> {
        let region = self
            .regions
            .iter()
            .find(|region| {
                address.checked_sub(region.dma).is_some_and(|offset| {
                    offset
                        .checked_add(length as u64)
                        .is_some_and(|end| end <= region.length as u64)
                })
            })
            .ok_or(Error::Address)?;
        let offset = address.checked_sub(region.dma).ok_or(Error::Address)? as usize;
        Ok((region.cpu + offset) as *mut u8)
    }
    fn bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, Error> {
        let pointer = self.pointer(address, length)?;
        // SAFETY: exact bounded region resolves through recorded CPU provenance;
        // Core retains this mapping throughout the synchronous device reaction.
        Ok(unsafe { core::slice::from_raw_parts(pointer, length).to_vec() })
    }
    pub(in crate::rtw89) fn inject(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let mut wire = vec![0; 20];
        let size = (20 + bytes.len() + 4) as u32;
        wire[..4].copy_from_slice(&(size | 1 << 15 | 1 << 14).to_le_bytes());
        wire[4..8].copy_from_slice(&((bytes.len() + 4) as u32).to_le_bytes());
        wire.extend_from_slice(bytes);
        wire.extend_from_slice(&[0; 4]);
        let event = rx_packet::Assembler::default()
            .segment(&wire, false)
            .map_err(|_| Error::Packet)?
            .ok_or(Error::Packet)?;
        self.incoming.push_back(event);
        Ok(())
    }
    pub(in crate::rtw89) fn report(
        &mut self,
        submission: Submission,
        status: u8,
    ) -> Result<(), Error> {
        // Independently encode actual firmware RPQ bytes, then use the real
        // RXBD/RXD parser. No direct queue call or invented completion shortcut.
        let mut bytes = vec![0; 24];
        bytes[..4].copy_from_slice(&(24u32 | 1 << 15 | 1 << 14).to_le_bytes());
        bytes[4..8].copy_from_slice(&(4u32 | 7 << 24).to_le_bytes());
        let report = u32::from(submission.sequence) << 16
            | u32::from(status) << 13
            | u32::from(submission.qsel) << 8
            | u32::from(submission.mac_id);
        bytes[20..24].copy_from_slice(&report.to_le_bytes());
        let event = rx_packet::Assembler::default()
            .segment(&bytes, true)
            .map_err(|_| Error::Packet)?
            .ok_or(Error::Packet)?;
        self.incoming.push_back(event);
        Ok(())
    }
    pub(in crate::rtw89) fn consumed(&mut self, submission: Submission) {
        let queue = [
            format::Queue::Data,
            format::Queue::Management,
            format::Queue::Background,
            format::Queue::Video,
            format::Queue::Voice,
        ]
        .into_iter()
        .find(|queue| queue.channel() == submission.channel)
        .unwrap_or(format::Queue::Management);
        let index = queue.regs().idx as u32;
        self.put(
            index,
            u32::from(submission.next) << 16 | self.word(index) & 0xffff,
        );
    }
    pub(in crate::rtw89) fn complete(&mut self) -> Result<(), Error> {
        let submission = self.last.ok_or(Error::State)?;
        self.consumed(submission);
        self.controls.held.store(false, Ordering::Release);
        self.report(submission, 0)
    }
    fn doorbell(&mut self, kind: format::Queue, next: u16, previous: u16) -> Result<(), Error> {
        let regs = kind.regs();
        let base = u64::from(self.word(regs.desa_l as u32))
            | u64::from(self.word(regs.desa_h as u32)) << 32;
        if self.word(0x1010) & (1 << (8 + kind.channel()) | 1 << 19) != 0
            || self.word(0xc000) & (1 << 29) == 0
            || next != (previous + 1) % format::DEPTH
            || self.word(regs.num as u32) & 0x0fff != u32::from(format::DEPTH)
        {
            return Err(Error::State);
        }
        let descriptor = self.bytes(base + u64::from(previous) * 8, 8)?;
        let length = u16::from_le_bytes(descriptor[..2].try_into().unwrap()) as usize;
        let option = u16::from_le_bytes(descriptor[2..4].try_into().unwrap());
        let header_dma = u64::from(u32::from_le_bytes(descriptor[4..8].try_into().unwrap()))
            | u64::from((option & 0x3fc0) >> 6) << 32;
        if length != 64 || option & !0x3fc0 != 1 << 14 || header_dma > 0xf_ffff_ffff {
            return Err(Error::Packet);
        }
        let header = self.bytes(header_dma, length)?;
        let word =
            |offset: usize| u32::from_le_bytes(header[offset..offset + 4].try_into().unwrap());
        let packet_len = (word(8) & 0x3fff) as usize;
        let body_dma = u64::from(word(60))
            | u64::from((u16::from_le_bytes(header[58..60].try_into().unwrap()) & 0x3fc0) >> 6)
                << 32;
        if packet_len < 24 {
            return Err(Error::Packet);
        }
        let body = self.bytes(body_dma, packet_len)?;
        // Decode independently from the descriptor: the raw QoS data header
        // contributes its two actual control bytes to ieee80211_hdrlen/2.
        let header_words = if body[0] & 0xfc == 0x88 {
            // Independent decode of the QoS TID -> AC -> ACH mapping.
            let tid = body.get(24).copied().ok_or(Error::Packet)?;
            let expected = match tid {
                0 | 3 => format::Queue::Data,
                1 | 2 => format::Queue::Background,
                4 | 5 => format::Queue::Video,
                6 | 7 => format::Queue::Voice,
                _ => return Err(Error::Packet),
            };
            if kind != expected
                || body.get(25) != Some(&0)
                || (word(8) >> 23 & 1 == 1) != matches!(tid, 2 | 3 | 5 | 7)
            {
                return Err(Error::Packet);
            }
            13
        } else {
            12
        };
        let expected0 = 1 << 22
            | u32::from(kind.channel()) << 16
            | header_words << 11
            | 1 << 7
            | if kind == format::Queue::Management {
                5
            } else {
                0
            };
        let sequence = u16::from_le_bytes(header[48..50].try_into().unwrap());
        if word(0) != expected0
            || word(4) != 0
            || word(8) >> 24 != 0
            || body[0] != 0x88 && word(8) >> 23 & 1 != 0
            || word(8) >> 17 & 0x3f != u32::from(kind.qsel())
            || header[16..24] != [0; 8]
            // Either a fixed source rate (USE_RATE|DISDATAFB, INFO1 zero) or
            // firmware RA data (INFO0 zero, INFO1 lowest retry rate only).
            || !(word(24) & !(0x1ff << 16) == 1 << 30 | 1 << 10
                && (word(24) >> 16) & 0x1ff <= 11
                && word(28) == 0
                || kind != format::Queue::Management
                    && word(24) == 0
                    && word(28) & !(0x1ff << 16) == 0
                    && (word(28) >> 16) & 0x1ff <= 11)
            || kind == format::Queue::Management && word(24) & (0x1ff << 16) != 0
            || word(32) != 0
            || word(36) & !(1 << 10) != 0
            || word(40) != 1 << 31 | 1 << 27
            || word(44) != 0
            || sequence & 0x8000 == 0
            || sequence & 0x7fff >= 512
            || header[50..56] != [0; 6]
            || u16::from_le_bytes(header[56..58].try_into().unwrap()) as usize != packet_len
            || u16::from_le_bytes(header[58..60].try_into().unwrap()) & !0x3fc0 != 0x8001
            || body_dma
                .checked_add(packet_len as u64 - 1)
                .is_none_or(|end| end > 0xf_ffff_ffff)
        {
            return Err(Error::Packet);
        }
        let submission = Submission {
            legacy_rate: ((word(24) >> 16) & 0x1ff) as u16,
            fixed_rate: word(24) & 1 << 30 != 0,
            retry_lowest: ((word(28) >> 16) & 0x1ff) as u16,
            sequence: sequence & 0x7fff,
            channel: kind.channel(),
            qsel: kind.qsel(),
            mac_id: (word(8) >> 24) as u8,
            body: body_dma,
            length: packet_len,
            next,
        };
        self.publications += 1;
        self.transmitted.push(body.clone());
        self.last = Some(submission);
        let (responses, hold) = if let Some(reaction) = self.reaction.clone() {
            reaction(&body)?
        } else {
            (Vec::new(), false)
        };
        for bytes in responses {
            self.inject(&bytes)?;
        }
        self.controls.held.store(hold, Ordering::Release);
        if !hold {
            if self.consume {
                self.consumed(submission);
            }
            if self.release {
                self.report(submission, 0)?;
            }
        }
        Ok(())
    }
}
impl power::Io for Model {
    fn read8(&mut self, address: u32) -> Result<u8, power::Error> {
        self.guard()?;
        Ok(self.registers[address as usize])
    }
    fn read16(&mut self, address: u32) -> Result<u16, power::Error> {
        self.guard()?;
        Ok(u16::from_le_bytes(
            self.registers[address as usize..address as usize + 2]
                .try_into()
                .unwrap(),
        ))
    }
    fn read32(&mut self, address: u32) -> Result<u32, power::Error> {
        self.guard()?;
        Ok(self.word(address))
    }
    fn write8(&mut self, address: u32, value: u8) -> Result<(), power::Error> {
        self.guard()?;
        self.registers[address as usize] = value;
        Ok(())
    }
    fn write16(&mut self, address: u32, value: u16) -> Result<(), power::Error> {
        self.guard()?;
        let previous = u16::from_le_bytes(
            self.registers[address as usize..address as usize + 2]
                .try_into()
                .unwrap(),
        );
        if !self.ignore {
            self.registers[address as usize..address as usize + 2]
                .copy_from_slice(&value.to_le_bytes());
        }
        for kind in [
            format::Queue::Data,
            format::Queue::Management,
            format::Queue::Background,
            format::Queue::Video,
            format::Queue::Voice,
        ] {
            if kind.regs().idx == u64::from(address) && !self.ignore {
                self.doorbell(kind, value, previous)
                    .map_err(|_| power::Error::Access)?;
            }
        }
        Ok(())
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), power::Error> {
        self.guard()?;
        self.put(address, value);
        Ok(())
    }
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn delay_us(&mut self, us: u64) {
        self.now = self.now.saturating_add(us);
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Ok(None)
    }
}
// SAFETY: one synchronous inert device model; exact current epoch invocation
// surrounds CPU/MMIO/DMA, and native addresses resolve only through owned maps.
// The model is the sole producer and never grants any production RF receipt.
unsafe impl Port for Model {
    fn current<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let authority = self.authority;
        crate::rtw88::pci_park::invoke(&authority, || {
            if self.inside {
                return Err(Error::State);
            }
            self.inside = true;
            let result = operation(self);
            self.inside = false;
            result
        })
        .map_err(|_| Error::Access)?
    }
    fn ordinary_allowed(&mut self) -> Result<(), Error> {
        self.guard()?;
        if self.allowed {
            Ok(())
        } else {
            Err(Error::Access)
        }
    }
    fn peer_allowed(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.guard()?;
        if let Some(peer) = self.peer.as_ref() {
            return if peer.admits(bytes) {
                Ok(())
            } else {
                Err(Error::Access)
            };
        }
        if self.peer_live
            && bytes.len() >= 24
            && bytes[10..16] == OWN
            && bytes[4..10] == [2, 0, 0, 0, 0, 1]
        {
            Ok(())
        } else {
            Err(Error::Access)
        }
    }
    fn allocate(&mut self, length: usize) -> Result<DmaBuffer, Error> {
        self.guard()?;
        let memory = narf_io::alloc_coherent_masked(
            length,
            narf_lib::id::DomainId::DRIVER_0,
            format::DMA_MASK,
        )
        .map_err(|_| Error::Memory)?;
        self.regions.push(Region {
            dma: memory.dma_addr().raw(),
            cpu: memory.cpu_mut_ptr::<u8>() as usize,
            length: memory.len(),
        });
        self.allocations += 1;
        if self.allocations == 4 {
            match self.deny_after_allocation {
                Some(true) => self.allowed = false,
                Some(false) => self.peer_live = false,
                None => {}
            }
        }
        Ok(memory)
    }
    fn receive(&mut self) -> Result<RxStep, Error> {
        self.guard()?;
        let event = self.incoming.pop_front();
        Ok(RxStep {
            consumed: event.is_some(),
            event,
        })
    }
    fn start(&mut self, open: u32) -> Result<(), Error> {
        self.ordinary_allowed()?;
        if open & STOP != STOP || open & !format::STOP_ALL != 0 {
            return Err(Error::State);
        }
        self.put(0x1010, self.word(0x1010) & !open);
        self.put(0xc000, self.word(0xc000) | 1 << 29);
        Ok(())
    }
    fn stop(&mut self) -> Result<(), Error> {
        self.guard()?;
        self.put(0x1010, self.word(0x1010) | format::STOP_ALL);
        self.put(0xc000, self.word(0xc000) & !(1 << 29));
        Ok(())
    }
}
pub(in crate::rtw89) fn fixture() -> Result<(Core, Model), &'static str> {
    let mut model = Model::new();
    let mut core = Core::prepare(&mut model, OWN, 0).map_err(|_| "B native packet preparation")?;
    core.start(&mut model)
        .map_err(|_| "B native packet start")?;
    Ok((core, model))
}

fn smoke_rtw89_b_packet_joint_rp_rpq_actual_dma_receipt() -> TestResult {
    for report_first in [false, true] {
        let (mut core, mut model) = match fixture() {
            Ok(value) => value,
            Err(error) => return TestResult::Fail(error),
        };
        let bytes = frame();
        let id = core.submit(&mut model, &bytes, true).unwrap();
        let submission = model.last.unwrap();
        if model.transmitted != [bytes.clone()]
            || core.ready()
            || core.poll(&mut model).unwrap().receipt.is_some()
        {
            return TestResult::Fail(
                "packet publication did not follow actual BD/header/payload DMA",
            );
        }
        if report_first {
            model.report(submission, 0).unwrap();
        } else {
            model.consumed(submission);
        }
        if core.poll(&mut model).unwrap().receipt.is_some() || core.ready() {
            return TestResult::Fail("one native ownership fact completed a packet");
        }
        // A source-snapshot receipt would miss this actual retained DMA change.
        let pointer = model.pointer(submission.body, submission.length).unwrap();
        // SAFETY: the exact pending body is retained, no concurrent producer.
        unsafe {
            pointer.add(50).write_volatile(0xef);
        }
        if report_first {
            model.consumed(submission);
        } else {
            model.report(submission, 0).unwrap();
        }
        let Some(receipt) = core.poll(&mut model).unwrap().receipt else {
            return TestResult::Fail("joint native completion missing");
        };
        let mut expected = bytes;
        expected[50] = 0xef;
        if receipt.id != id
            || receipt.bytes != expected
            || !receipt.radio_acknowledged
            || !core.ready()
        {
            return TestResult::Fail("terminal receipt did not acquire exact held DMA bytes");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_packet_joint_rp_rpq_actual_dma_receipt
);

fn smoke_rtw89_b_packet_wrong_duplicate_and_stale_release_fail_closed() -> TestResult {
    for fault in 0..6 {
        let (mut core, mut model) = fixture().unwrap();
        core.submit(&mut model, &frame(), true).unwrap();
        let original = model.last.unwrap();
        let mut bad = original;
        match fault {
            0 => bad.mac_id = 1,
            1 => bad.qsel = 0x12,
            2 => bad.sequence += 1,
            3 => {
                model.report(original, 0).unwrap();
                if core.poll(&mut model).is_err() {
                    return TestResult::Fail("first release before RP");
                }
            }
            4 => model.consumed(original),
            5 => {}
            _ => unreachable!(),
        }
        model.report(bad, if fault == 4 { 1 } else { 0 }).unwrap();
        if fault == 5 {
            model.consumed(original);
            if core.poll(&mut model).unwrap().receipt.is_none() {
                return TestResult::Fail("prior terminal fixture");
            }
            core.submit(&mut model, &frame(), true).unwrap();
            model.report(original, 0).unwrap();
        }
        if core.poll(&mut model).is_ok()
            || core.ready()
            || core.submit(&mut model, &frame(), false) != Err(Error::State)
        {
            return TestResult::Fail(
                "wrong/duplicate/stale/failed RPQ did not terminally close packet owner",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_packet_wrong_duplicate_and_stale_release_fail_closed
);

fn smoke_rtw89_b_packet_current_epoch_rf_gate_and_stop_retention() -> TestResult {
    let mut model = Model::new();
    model.allowed = false;
    let mut core = Core::prepare(&mut model, OWN, 0).unwrap();
    let bases: Vec<_> = core
        .rings
        .iter()
        .map(|ring| ring.descriptors.as_ref().unwrap().dma_addr().raw())
        .collect();
    if core.start(&mut model) != Err(Error::Access)
        || model.word(0x1010) & STOP != STOP
        || model.word(0xc000) & (1 << 29) != 0
    {
        return TestResult::Fail("stopped DMA preparation granted ordinary RF authority");
    }
    if core
        .rings
        .iter()
        .map(|ring| ring.descriptors.as_ref().unwrap().dma_addr().raw())
        .collect::<Vec<_>>()
        != bases
    {
        return TestResult::Fail("failed start discarded published descriptor maps");
    }
    let (mut core, mut model) = fixture().unwrap();
    model.authority.revoke();
    let before = (
        model.accesses,
        model.allocations,
        model.publications,
        model.registers.clone(),
    );
    if core.submit(&mut model, &frame(), true) != Err(Error::Access)
        || before
            != (
                model.accesses,
                model.allocations,
                model.publications,
                model.registers.clone(),
            )
    {
        return TestResult::Fail("real revoked epoch accessed DMA/config/register publication");
    }
    let (mut core, mut model) = fixture().unwrap();
    core.submit(&mut model, &frame(), true).unwrap();
    let body = model.last.unwrap().body;
    if core.stop(&mut model).is_err()
        || core.pending.is_none()
        || core.ready()
        || core
            .rings
            .iter()
            .any(|ring| !ring.armed || ring.descriptors.is_none())
        || model.word(0x1010) & STOP != STOP
        || model.bytes(body, 100).unwrap() != frame()
    {
        return TestResult::Fail("bounded stop released or rebuilt an unretired native packet");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_packet_current_epoch_rf_gate_and_stop_retention
);

fn smoke_rtw89_b_packet_impossible_rp_timeout_and_reused_identity_rejected() -> TestResult {
    for fault in 0..4 {
        let (mut core, mut model) = fixture().unwrap();
        core.submit(&mut model, &frame(), true).unwrap();
        let index = format::Queue::Data.regs().idx as u32;
        match fault {
            0 => model.put(index, 2 << 16 | 1),
            1 => model.put(index, 1 << 16 | 2),
            2 => model.now = 1_000_000,
            3 => {
                model.ignore = true;
                model.complete().unwrap();
                if core.poll(&mut model).is_err() {
                    return TestResult::Fail("identity exhaustion baseline");
                }
                //512 is Linux's page-pool bound. Exercise the boundary via
                // real sequential reserve/publish/joint-retire operations.
                model.ignore = false;
                model.consume = true;
                model.release = true;
                for _ in 1..512 {
                    core.submit(&mut model, &frame(), false).unwrap();
                    if core.poll(&mut model).unwrap().receipt.is_none() {
                        return TestResult::Fail("bounded page identity progress");
                    }
                }
                let before = model.publications;
                if core.submit(&mut model, &frame(), false) != Err(Error::State)
                    || model.publications != before
                {
                    return TestResult::Fail("unsupported or reused WD-page identity published");
                }
                continue;
            }
            _ => unreachable!(),
        }
        if core.poll(&mut model).is_ok() || core.ready() {
            return TestResult::Fail("impossible native RP or deadline did not close packet owner");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_packet_impossible_rp_timeout_and_reused_identity_rejected
);

fn smoke_rtw89_b_packet_rechecks_peer_rf_before_bd_and_retains_uncertain_doorbell() -> TestResult {
    for radio in [false, true] {
        let (mut core, mut model) = fixture().unwrap();
        model.deny_after_allocation = Some(radio);
        let base = core.rings[0].descriptors.as_ref().unwrap().dma_addr().raw();
        if core.submit(&mut model, &frame(), true) != Err(Error::Access)
            || model.publications != 0
            || model.bytes(base, 8).unwrap() != [0; 8]
            || core.pending.is_some()
            || core.ready()
            || model.word(0x1010) & STOP != STOP
        {
            return TestResult::Fail("late peer/RF closure reached actual native BD/doorbell");
        }
    }
    let (mut core, mut model) = fixture().unwrap();
    model.ignore = true;
    if core.submit(&mut model, &frame(), true) != Err(Error::Access) {
        return TestResult::Fail("unacknowledged actual doorbell accepted");
    }
    let pending = core.pending.as_ref().unwrap();
    let queue = pending.queue;
    let Some(ring) = core.rings.iter_mut().find(|ring| ring.kind == queue) else {
        return TestResult::Fail("pending ring missing");
    };
    let base = ring.descriptors.as_ref().unwrap().dma_addr().raw();
    if ring.queue.write_pointer() != 1
        || ring.queue.reserved_mut(pending.ticket).is_ok()
        || model.bytes(base, 8).unwrap() == [0; 8]
        || model.publications != 0
        || model.word(0x1010) & STOP != STOP
        || core.poll(&mut model).is_ok()
    {
        return TestResult::Fail("uncertain descriptor publication was rolled back/reusable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_packet_rechecks_peer_rf_before_bd_and_retains_uncertain_doorbell
);

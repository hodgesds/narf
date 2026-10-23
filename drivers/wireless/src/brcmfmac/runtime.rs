// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained PCIe common-ring/msgbuf control owner. Local Linux references:
//! brcmfmac/{pcie,msgbuf,commonring}.c. Initial profile shared v5/v6,
//! TCM indices, one serialized IOCTL, eight response/eight event buffers.
//! DMA mappings are never freed merely because a waiter/owner is dropped.
use super::{
    boot::{Booted, Bus as BootBus, Error as BootError, Ram},
    msgbuf::{self, BufAddr, CommonHdr, IoctlReq},
    shared::{RingInfo, RINGINFO_SIZE},
};
use alloc::{collections::VecDeque, vec, vec::Vec};

const INPUT: usize = 1518;
const CONTROL: usize = 8192;
const POOL: usize = 8;
const BUDGET: usize = 32;
const EVENTS: usize = 32;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Access,
    Bounds,
    Protocol,
    Busy,
    Failed,
    Exhausted,
    Firmware(i16),
    Timeout,
}
impl From<BootError> for Error {
    fn from(_: BootError) -> Self {
        Self::Access
    }
}

/// CPU and device addresses are separate. Reads/writes check their extent;
/// sync transitions include platform cache maintenance plus DMA barriers.
pub trait Memory {
    fn address(&self) -> u64;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error>;
    fn read(&mut self, offset: usize, bytes: &mut [u8]) -> Result<(), Error>;
    fn to_device(&mut self, offset: usize, length: usize);
    fn sync_from_device(&mut self, offset: usize, length: usize);
    /// Complete prior CPU DMA reads before returning a slot to the device.
    /// A barrier before the read does not provide this release edge.
    fn release(&mut self);
}
pub trait Bus: BootBus {
    type Memory: Memory;
    fn allocate(&mut self, length: usize) -> Result<Self::Memory, Error>;
    /// Verifies live PCI authority and BME state. No DMA before all common
    /// addresses/indices have been published under retained ownership.
    fn enable_dma(&mut self) -> Result<(), Error>;
    fn park_dma(&mut self) -> Result<(), Error>;
    fn doorbell(&mut self) -> Result<(), Error>;
    fn host_ready(&mut self, db1: bool) -> Result<(), Error>;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Response,
    Event,
}
struct Posted<M: Memory> {
    memory: M,
    id: u32,
    kind: Kind,
    posted: bool,
}
struct Ring<M: Memory> {
    memory: M,
    read: u16,
    write: u16,
    depth: u16,
    size: usize,
    wptr: u32,
    rptr: u32,
    h2d: bool,
}
struct Resources<M: Memory> {
    rings: Vec<Ring<M>>,
    buffers: Vec<Posted<M>>,
    input: M,
    scratch: M,
    ring_update: M,
    data: Option<Data<M>>,
}
const RX_BYTES: usize = 2048;
const RX_POOL: usize = 32;
const TX_PENDING: usize = 64;
const FLOW_LIMIT: usize = 8;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowState {
    Creating,
    Open,
    Deleting,
    Closed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowToken {
    id: u16,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxReceipt {
    pub id: u32,
    pub status: u16,
    pub tx_status: u16,
}
struct Flow<M: Memory> {
    ring: Ring<M>,
    state: FlowState,
    deadline: Option<narf_time::Deadline>,
    source: [u8; 6],
    destination: [u8; 6],
    priority: u8,
    outstanding: usize,
}
struct Tx<M: Memory> {
    memory: M,
    id: u32,
    flow: u16,
}
struct Data<M: Memory> {
    rx: Vec<Posted<M>>,
    flows: Vec<Flow<M>>,
    tx: Vec<Tx<M>>,
    received: VecDeque<Vec<u8>>,
    receipts: VecDeque<TxReceipt>,
    dropped: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Pending {
    id: u16,
    command: u32,
    maximum: usize,
}
#[derive(Debug)]
pub struct Ticket {
    id: u16,
    command: u32,
}

pub struct Runtime<B: Bus> {
    bus: B,
    ram: Ram,
    resources: Option<Resources<B::Memory>>,
    published: bool,
    failed: bool,
    next_buffer: u32,
    next_transaction: u16,
    pending: Option<Pending>,
    response: Option<Result<Vec<u8>, Error>>,
    events: VecDeque<Vec<u8>>,
    rx_offset: usize,
    h2d_write: u32,
    h2d_read: u32,
    max_flows: u16,
    max_rx: u16,
}
impl<B: Bus> core::fmt::Debug for Runtime<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BrcmMsgbuf")
            .field("failed", &self.failed)
            .field("pending", &self.pending)
            .finish_non_exhaustive()
    }
}
impl<B: Bus> Drop for Runtime<B> {
    fn drop(&mut self) {
        if self.published {
            let _ = self.bus.park_dma();
            // BME readback cannot prove all old posted PCI writes drained.
            // No physical stop/IOMMU quiescence API exists yet. Leak this
            // bounded per-device owner rather than returning live DMA pages.
            if let Some(resources) = self.resources.take() {
                core::mem::forget(resources);
            }
        }
    }
}
impl<B: Bus> Runtime<B> {
    pub fn attach(boot: Booted<B>) -> Result<Self, Error> {
        let Booted {
            mut bus,
            ram,
            shared_address,
            shared,
            ..
        } = boot;
        if bus.dma_enabled()? || !(5..=6).contains(&shared.version) || shared.rx_dataoffset != 0 {
            return Err(Error::Protocol);
        }
        let mut bytes = [0; RINGINFO_SIZE];
        bus.read_tcm(shared.ring_info_addr, &mut bytes)?;
        let info = RingInfo::parse(&bytes).ok_or(Error::Protocol)?;
        let submissions = if shared.version >= 6 {
            info.max_submissionrings
        } else {
            info.max_flowrings
        };
        let flows = if shared.version >= 6 {
            info.max_flowrings
        } else {
            submissions.checked_sub(2).ok_or(Error::Protocol)?
        };
        let completions = if shared.version >= 6 {
            info.max_completionrings
        } else {
            3
        };
        if !(2..=514).contains(&submissions)
            || flows > 512
            || completions != 3
            || submissions < u16::saturating_add(flows, 2)
        {
            return Err(Error::Protocol);
        }
        let ranges = [
            (shared_address, 76),
            (shared.ring_info_addr, 58),
            (info.ringmem, 80),
            (info.h2d_w_idx_ptr, usize::from(submissions) * 4),
            (info.h2d_r_idx_ptr, usize::from(submissions) * 4),
            (info.d2h_w_idx_ptr, 12),
            (info.d2h_r_idx_ptr, 12),
        ];
        for (i, &(start, len)) in ranges.iter().enumerate() {
            if start & 3 != 0 || !ram.contains(start, len) {
                return Err(Error::Bounds);
            }
            for &(other, size) in &ranges[..i] {
                if start < u32::try_from(size).unwrap() + other && other < start + len as u32 {
                    return Err(Error::Bounds);
                }
            }
        }
        let mut rings = Vec::new();
        for id in 0..5u8 {
            let layout = msgbuf::ring_layout(id, true).ok_or(Error::Protocol)?;
            let mut memory =
                bus.allocate(usize::from(layout.depth) * usize::from(layout.item_len))?;
            if memory.len() < usize::from(layout.depth) * usize::from(layout.item_len) {
                return Err(Error::Bounds);
            }
            zero(&mut memory)?;
            let (wptr, rptr) = if id < 2 {
                (
                    info.h2d_w_idx_ptr + u32::from(id) * 4,
                    info.h2d_r_idx_ptr + u32::from(id) * 4,
                )
            } else {
                (
                    info.d2h_w_idx_ptr + u32::from(id - 2) * 4,
                    info.d2h_r_idx_ptr + u32::from(id - 2) * 4,
                )
            };
            rings.push(Ring {
                memory,
                read: 0,
                write: 0,
                depth: layout.depth,
                size: usize::from(layout.item_len),
                wptr,
                rptr,
                h2d: id < 2,
            });
        }
        let mut buffers = Vec::new();
        for kind in [Kind::Response, Kind::Event] {
            for _ in 0..POOL {
                let mut memory = allocate(&mut bus, CONTROL)?;
                zero(&mut memory)?;
                buffers.push(Posted {
                    memory,
                    id: 0,
                    kind,
                    posted: false,
                });
            }
        }
        let mut input = allocate(&mut bus, INPUT)?;
        zero(&mut input)?;
        let mut scratch = allocate(&mut bus, 8)?;
        zero(&mut scratch)?;
        let mut ring_update = allocate(&mut bus, 1024)?;
        zero(&mut ring_update)?;
        let mut runtime = Self {
            bus,
            ram,
            resources: Some(Resources {
                rings,
                buffers,
                input,
                scratch,
                ring_update,
                data: None,
            }),
            published: false,
            failed: false,
            next_buffer: 1,
            next_transaction: 0,
            pending: None,
            response: None,
            events: VecDeque::new(),
            rx_offset: shared.rx_dataoffset as usize,
            h2d_write: info.h2d_w_idx_ptr,
            h2d_read: info.h2d_r_idx_ptr,
            max_flows: flows,
            max_rx: shared.max_rxbufpost,
        };
        // Device may observe host addresses as soon as these fields change.
        // Ownership is retained across every later write/error/Drop.
        runtime.published = true;
        let result: Result<(), Error> = (|| {
            // Explicitly negotiate TCM index fallback (Linux also uses it
            // when optional host-index allocation is unavailable).
            runtime
                .bus
                .write_tcm(shared.ring_info_addr + 20, &[0; 32])?;
            let resources = runtime.resources.as_mut().unwrap();
            for (id, ring) in resources.rings.iter_mut().enumerate() {
                let mut descriptor = [0; 16];
                descriptor[4..6].copy_from_slice(&ring.depth.to_le_bytes());
                descriptor[6..8].copy_from_slice(&(ring.size as u16).to_le_bytes());
                descriptor[8..16].copy_from_slice(&ring.memory.address().to_le_bytes());
                runtime
                    .bus
                    .write_tcm(info.ringmem + id as u32 * 16, &descriptor)?;
                runtime.bus.write_tcm(ring.wptr, &[0; 2])?;
                runtime.bus.write_tcm(ring.rptr, &[0; 2])?;
            }
            runtime
                .bus
                .write_tcm(shared_address + 52, &8u32.to_le_bytes())?;
            runtime.bus.write_tcm(
                shared_address + 56,
                &resources.scratch.address().to_le_bytes(),
            )?;
            runtime
                .bus
                .write_tcm(shared_address + 64, &1024u32.to_le_bytes())?;
            runtime.bus.write_tcm(
                shared_address + 68,
                &resources.ring_update.address().to_le_bytes(),
            )?;
            runtime.bus.enable_dma()?;
            runtime.bus.host_ready(shared.hostrdy_db1())?;
            runtime.replenish()?;
            Ok(())
        })();
        result?;
        Ok(runtime)
    }
    /// A dropped command future poisons this owner: no second request may
    /// overwrite input DMA until a correlated completion or quiescence.
    pub async fn command(
        &mut self,
        command: u32,
        input: &[u8],
        maximum: usize,
    ) -> Result<Vec<u8>, Error> {
        let ticket = self.begin_ioctl(command, input, maximum)?;
        let mut transaction = Transaction {
            runtime: self,
            retired: false,
        };
        let deadline = narf_time::Deadline::after_ms(2000);
        loop {
            transaction.runtime.poll()?;
            if let Some(result) = transaction.runtime.take_response(&ticket)? {
                transaction.retired = true;
                return result;
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
        }
    }
    pub fn is_failed(&self) -> bool {
        self.failed
    }
    pub fn fail(&mut self) {
        self.failed = true;
        let _ = self.bus.park_dma();
    }
    pub fn pop_event(&mut self) -> Option<Vec<u8>> {
        self.events.pop_front()
    }
    fn next_id(&mut self) -> Result<u32, Error> {
        let id = self.next_buffer;
        self.next_buffer = self.next_buffer.checked_add(1).ok_or(Error::Exhausted)?;
        Ok(id)
    }
    fn publish(&mut self, ring_id: usize, entry: &[u8]) -> Result<(), Error> {
        publish_ring(
            &mut self.bus,
            &mut self.resources.as_mut().unwrap().rings[ring_id],
            entry,
        )
    }
    fn replenish(&mut self) -> Result<(), Error> {
        let count = self.resources.as_ref().unwrap().buffers.len();
        for index in 0..count {
            if self.resources.as_ref().unwrap().buffers[index].posted {
                continue;
            }
            let id = self.next_id()?;
            let buffer = &mut self.resources.as_mut().unwrap().buffers[index];
            buffer.memory.to_device(0, CONTROL);
            let mut entry = [0; 40];
            entry[0] = if buffer.kind == Kind::Response {
                0xb
            } else {
                0xd
            };
            entry[4..8].copy_from_slice(&id.to_le_bytes());
            entry[8..10].copy_from_slice(&(CONTROL as u16).to_le_bytes());
            entry[16..24].copy_from_slice(&buffer.memory.address().to_le_bytes());
            buffer.id = id;
            buffer.posted = true;
            match self.publish(0, &entry) {
                Ok(()) => {}
                Err(Error::Busy) => {
                    self.resources.as_mut().unwrap().buffers[index].posted = false;
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    pub fn begin_ioctl(
        &mut self,
        command: u32,
        input: &[u8],
        maximum: usize,
    ) -> Result<Ticket, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        if input.len() > INPUT || maximum > CONTROL {
            return Err(Error::Bounds);
        }
        let id = self
            .next_transaction
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        let logical = maximum.max(input.len());
        let wire_length = logical.min(INPUT);
        let memory = &mut self.resources.as_mut().unwrap().input;
        zero(memory)?;
        memory.write(0, input)?;
        memory.to_device(0, wire_length);
        let request = IoctlReq {
            hdr: CommonHdr {
                msgtype: 9,
                ifidx: 0,
                flags: 0,
                request_id: 0xfffe,
            },
            cmd: command,
            trans_id: id,
            input_buf_len: wire_length as u16,
            output_buf_len: logical as u16,
            req_buf_addr: BufAddr(memory.address()),
        };
        let mut entry = [0; 40];
        request.encode(&mut entry).ok_or(Error::Protocol)?;
        // Retain request identity before publishing the input DMA address.
        self.next_transaction = id;
        self.pending = Some(Pending {
            id,
            command,
            maximum: logical,
        });
        self.response = None;
        if let Err(error) = self.publish(0, &entry) {
            if error == Error::Busy {
                self.pending = None;
                return Err(error);
            }
            self.fail();
            return Err(error);
        }
        Ok(Ticket { id, command })
    }
    pub fn take_response(
        &mut self,
        ticket: &Ticket,
    ) -> Result<Option<Result<Vec<u8>, Error>>, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        if self.pending.map(|p| (p.id, p.command)) != Some((ticket.id, ticket.command)) {
            return Err(Error::Protocol);
        }
        let Some(result) = self.response.take() else {
            return Ok(None);
        };
        self.pending = None;
        // Completion retires request DMA. Clear key/request material only now.
        zero(&mut self.resources.as_mut().unwrap().input)?;
        Ok(Some(result))
    }
    pub fn poll(&mut self) -> Result<usize, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        let result = self.poll_inner();
        if result.is_err() {
            self.fail();
        }
        result
    }
    fn poll_inner(&mut self) -> Result<usize, Error> {
        if self
            .resources
            .as_ref()
            .unwrap()
            .data
            .as_ref()
            .is_some_and(|data| {
                data.flows
                    .iter()
                    .any(|f| f.deadline.is_some_and(|d| d.expired()))
            })
        {
            return Err(Error::Timeout);
        }
        let mut processed = 0;
        for ring_id in 2..5 {
            let mut ring_budget = 0;
            while processed < BUDGET && ring_budget < BUDGET / 3 {
                let ring = &mut self.resources.as_mut().unwrap().rings[ring_id];
                let peer = read16(&mut self.bus, ring.wptr)?;
                if peer >= ring.depth {
                    return Err(Error::Protocol);
                }
                if peer == ring.read {
                    break;
                }
                let offset = usize::from(ring.read) * ring.size;
                let mut entry = vec![0; ring.size];
                ring.memory.sync_from_device(offset, ring.size);
                ring.memory.read(offset, &mut entry)?;
                // Before a handler can retire a TX DMA allocation, complete
                // reads of its matching completion descriptor into owned memory.
                ring.memory.release();
                match ring_id {
                    2 => self.control_completion(&entry)?,
                    3 => self.tx_completion(&entry)?,
                    4 => self.rx_completion(&entry)?,
                    _ => return Err(Error::Protocol),
                }
                let ring = &mut self.resources.as_mut().unwrap().rings[ring_id];
                ring.read = if ring.read + 1 == ring.depth {
                    0
                } else {
                    ring.read + 1
                };
                ring.memory.release();
                self.bus.write_tcm(ring.rptr, &ring.read.to_le_bytes())?;
                processed += 1;
                ring_budget += 1;
            }
        }
        self.replenish()?;
        self.replenish_rx()?;
        Ok(processed)
    }
    fn control_completion(&mut self, entry: &[u8]) -> Result<(), Error> {
        if entry.len() != 24 || entry[1] != 0 {
            return Err(Error::Protocol);
        }
        let kind = entry[0];
        if matches!(kind, 4 | 6) {
            return self.flow_completion(entry);
        }
        let status = i16::from_le_bytes(entry[8..10].try_into().unwrap());
        if matches!(kind, 1 | 2 | 0xa) {
            return if status == 0 {
                Ok(())
            } else {
                Err(Error::Firmware(status))
            };
        }
        if !matches!(kind, 0xc | 0xe) {
            return Err(Error::Protocol);
        }
        let id = u32::from_le_bytes(entry[4..8].try_into().unwrap());
        let expected = if kind == 0xc {
            Kind::Response
        } else {
            Kind::Event
        };
        let buffers = &mut self.resources.as_mut().unwrap().buffers;
        let buffer = buffers
            .iter_mut()
            .find(|b| b.posted && b.id == id && b.kind == expected)
            .ok_or(Error::Protocol)?;
        let length = usize::from(u16::from_le_bytes(entry[12..14].try_into().unwrap()));
        let offset = if kind == 0xe { self.rx_offset } else { 0 };
        if offset
            .checked_add(length)
            .filter(|&end| end <= CONTROL)
            .is_none()
        {
            return Err(Error::Bounds);
        }
        buffer.memory.sync_from_device(offset, length);
        let mut bytes = vec![0; length];
        buffer.memory.read(offset, &mut bytes)?;
        buffer.posted = false;
        if kind == 0xe {
            if status != 0 {
                return Err(Error::Firmware(status));
            }
            if self.events.len() == EVENTS {
                return Err(Error::Bounds);
            }
            self.events.push_back(bytes);
            return Ok(());
        }
        let transaction = u16::from_le_bytes(entry[14..16].try_into().unwrap());
        let command = u32::from_le_bytes(entry[16..20].try_into().unwrap());
        let pending = self.pending.ok_or(Error::Protocol)?;
        if pending.id != transaction || pending.command != command || self.response.is_some() {
            return Err(Error::Protocol);
        }
        if length > pending.maximum {
            return Err(Error::Bounds);
        }
        self.response = Some(if status == 0 {
            Ok(bytes)
        } else {
            Err(Error::Firmware(status))
        });
        Ok(())
    }
}
fn read16(bus: &mut impl BootBus, address: u32) -> Result<u16, Error> {
    let mut bytes = [0; 2];
    bus.read_tcm(address, &mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}
fn zero(memory: &mut impl Memory) -> Result<(), Error> {
    let zeros = [0; 256];
    let mut at = 0;
    while at < memory.len() {
        let length = (memory.len() - at).min(zeros.len());
        memory.write(at, &zeros[..length])?;
        at += length;
    }
    memory.to_device(0, memory.len());
    Ok(())
}

fn allocate<B: Bus>(bus: &mut B, length: usize) -> Result<B::Memory, Error> {
    let memory = bus.allocate(length)?;
    if memory.len() < length || memory.address() == 0 || memory.address() & 7 != 0 {
        return Err(Error::Bounds);
    }
    Ok(memory)
}

struct Transaction<'a, B: Bus> {
    runtime: &'a mut Runtime<B>,
    retired: bool,
}
impl<B: Bus> Drop for Transaction<'_, B> {
    fn drop(&mut self) {
        if !self.retired {
            self.runtime.fail();
        }
    }
}

fn publish_ring<B: Bus>(
    bus: &mut B,
    ring: &mut Ring<B::Memory>,
    entry: &[u8],
) -> Result<(), Error> {
    if !ring.h2d || entry.len() != ring.size {
        return Err(Error::Protocol);
    }
    let peer = read16(bus, ring.rptr)?;
    if peer >= ring.depth {
        return Err(Error::Protocol);
    }
    let next = if ring.write + 1 == ring.depth {
        0
    } else {
        ring.write + 1
    };
    if next == peer {
        return Err(Error::Busy);
    }
    let offset = usize::from(ring.write) * ring.size;
    ring.memory.write(offset, entry)?;
    ring.memory.to_device(offset, entry.len());
    bus.write_tcm(ring.wptr, &next.to_le_bytes())?;
    ring.write = next;
    bus.doorbell()?;
    Ok(())
}
impl<B: Bus> Runtime<B> {
    /// Data rings remain transport-only: a station must authorize the link and
    /// controlled port before exposing send/received Ethernet to the network.
    pub fn enable_data(&mut self) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        if self.resources.as_ref().unwrap().data.is_some() {
            return Err(Error::Busy);
        }
        let mut rx = Vec::new();
        for _ in 0..RX_POOL.min(usize::from(self.max_rx)) {
            let mut memory = allocate(&mut self.bus, RX_BYTES)?;
            zero(&mut memory)?;
            rx.push(Posted {
                memory,
                id: 0,
                kind: Kind::Response,
                posted: false,
            });
        }
        if rx.is_empty() {
            return Err(Error::Protocol);
        }
        self.resources.as_mut().unwrap().data = Some(Data {
            rx,
            flows: Vec::new(),
            tx: Vec::new(),
            received: VecDeque::new(),
            receipts: VecDeque::new(),
            dropped: 0,
        });
        if let Err(e) = self.replenish_rx() {
            self.fail();
            return Err(e);
        }
        Ok(())
    }
    fn replenish_rx(&mut self) -> Result<(), Error> {
        let Some(data) = self.resources.as_ref().unwrap().data.as_ref() else {
            return Ok(());
        };
        let count = data.rx.len();
        for index in 0..count {
            if self.resources.as_ref().unwrap().data.as_ref().unwrap().rx[index].posted {
                continue;
            }
            let id = self.next_id()?;
            let slot = &mut self.resources.as_mut().unwrap().data.as_mut().unwrap().rx[index];
            slot.memory.to_device(0, RX_BYTES);
            let mut entry = [0; 32];
            entry[0] = 0x11;
            entry[4..8].copy_from_slice(&id.to_le_bytes());
            entry[10..12].copy_from_slice(&(RX_BYTES as u16).to_le_bytes());
            entry[24..32].copy_from_slice(&slot.memory.address().to_le_bytes());
            slot.id = id;
            slot.posted = true;
            match self.publish(1, &entry) {
                Ok(()) => {}
                Err(Error::Busy) => {
                    self.resources.as_mut().unwrap().data.as_mut().unwrap().rx[index].posted =
                        false;
                    return Ok(());
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    pub fn open_flow(
        &mut self,
        source: [u8; 6],
        destination: [u8; 6],
        priority: u8,
    ) -> Result<FlowToken, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        if source == [0; 6] || source[0] & 1 != 0 || destination == [0; 6] || priority > 7 {
            return Err(Error::Protocol);
        }
        let Some(data) = self.resources.as_ref().unwrap().data.as_ref() else {
            return Err(Error::Protocol);
        };
        if data.flows.iter().any(|f| {
            f.state != FlowState::Closed
                && f.source == source
                && f.destination == destination
                && f.priority == priority
        }) {
            return Err(Error::Busy);
        }
        let index = data.flows.len();
        if index >= FLOW_LIMIT || index >= usize::from(self.max_flows) {
            return Err(Error::Exhausted);
        }
        self.control_available()?;
        let id = index as u16 + 2;
        let mut memory = allocate(&mut self.bus, 512 * 48)?;
        zero(&mut memory)?;
        let address = memory.address();
        let ring = Ring {
            memory,
            read: 0,
            write: 0,
            depth: 512,
            size: 48,
            wptr: self.h2d_write + u32::from(id) * 4,
            rptr: self.h2d_read + u32::from(id) * 4,
            h2d: true,
        };
        let wptr = ring.wptr;
        let rptr = ring.rptr;
        self.resources
            .as_mut()
            .unwrap()
            .data
            .as_mut()
            .unwrap()
            .flows
            .push(Flow {
                ring,
                state: FlowState::Creating,
                deadline: Some(narf_time::Deadline::after_ms(2000)),
                source,
                destination,
                priority,
                outstanding: 0,
            });
        let mut entry = [0; 40];
        entry[0] = 3;
        entry[8..14].copy_from_slice(&destination);
        entry[14..20].copy_from_slice(&source);
        entry[20] = priority;
        entry[22..24].copy_from_slice(&id.to_le_bytes());
        entry[28..30].copy_from_slice(&512u16.to_le_bytes());
        entry[30..32].copy_from_slice(&48u16.to_le_bytes());
        entry[32..40].copy_from_slice(&address.to_le_bytes());
        let result = (|| {
            self.bus.write_tcm(wptr, &[0; 2])?;
            self.bus.write_tcm(rptr, &[0; 2])?;
            self.publish(0, &entry)
        })();
        if let Err(e) = result {
            self.fail();
            return Err(e);
        }
        Ok(FlowToken { id })
    }
    fn control_available(&mut self) -> Result<(), Error> {
        let ring = &self.resources.as_ref().unwrap().rings[0];
        let peer = read16(&mut self.bus, ring.rptr)?;
        if peer >= ring.depth {
            self.fail();
            return Err(Error::Protocol);
        }
        let next = if ring.write + 1 == ring.depth {
            0
        } else {
            ring.write + 1
        };
        if peer == next {
            Err(Error::Busy)
        } else {
            Ok(())
        }
    }
    pub fn flow_state(&self, token: FlowToken) -> Result<FlowState, Error> {
        let index = token.id.checked_sub(2).ok_or(Error::Protocol)?;
        self.resources
            .as_ref()
            .unwrap()
            .data
            .as_ref()
            .and_then(|d| d.flows.get(usize::from(index)))
            .map(|f| f.state)
            .ok_or(Error::Protocol)
    }
    pub fn close_flow(&mut self, token: FlowToken) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        self.control_available()?;
        let data = self
            .resources
            .as_mut()
            .unwrap()
            .data
            .as_mut()
            .ok_or(Error::Protocol)?;
        let flow = data
            .flows
            .get_mut(usize::from(token.id.checked_sub(2).ok_or(Error::Protocol)?))
            .ok_or(Error::Protocol)?;
        if flow.state != FlowState::Open || flow.outstanding != 0 {
            return Err(Error::Busy);
        }
        flow.state = FlowState::Deleting;
        flow.deadline = Some(narf_time::Deadline::after_ms(2000));
        let mut entry = [0; 40];
        entry[0] = 5;
        entry[8..10].copy_from_slice(&token.id.to_le_bytes());
        if let Err(e) = self.publish(0, &entry) {
            self.fail();
            return Err(e);
        }
        Ok(())
    }
    fn flow_completion(&mut self, entry: &[u8]) -> Result<(), Error> {
        let id = u16::from_le_bytes(entry[10..12].try_into().unwrap());
        let status = u16::from_le_bytes(entry[8..10].try_into().unwrap());
        let data = self
            .resources
            .as_mut()
            .unwrap()
            .data
            .as_mut()
            .ok_or(Error::Protocol)?;
        let flow = data
            .flows
            .get_mut(usize::from(id.checked_sub(2).ok_or(Error::Protocol)?))
            .ok_or(Error::Protocol)?;
        match (entry[0], flow.state) {
            (4, FlowState::Creating) => {
                flow.state = if status == 0 {
                    FlowState::Open
                } else {
                    FlowState::Closed
                }
            }
            (6, FlowState::Deleting) if flow.outstanding == 0 => flow.state = FlowState::Closed,
            _ => return Err(Error::Protocol),
        }
        flow.deadline = None;
        if status != 0 {
            return Err(Error::Firmware(status as i16));
        }
        Ok(())
    }
    pub fn send(&mut self, token: FlowToken, frame: &[u8]) -> Result<u32, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        if !(15..=1514).contains(&frame.len()) || u16::from_be_bytes([frame[12], frame[13]]) < 0x600
        {
            return Err(Error::Bounds);
        }
        let data = self
            .resources
            .as_ref()
            .unwrap()
            .data
            .as_ref()
            .ok_or(Error::Protocol)?;
        if data.tx.len() + data.receipts.len() >= TX_PENDING {
            return Err(Error::Busy);
        }
        let index = usize::from(token.id.checked_sub(2).ok_or(Error::Protocol)?);
        let flow = data.flows.get(index).ok_or(Error::Protocol)?;
        if flow.state != FlowState::Open {
            return Err(Error::Busy);
        }
        if frame[..6] != flow.destination || frame[6..12] != flow.source {
            return Err(Error::Protocol);
        }
        let priority = flow.priority;
        let id = self.next_id()?;
        let mut memory = allocate(&mut self.bus, frame.len() - 14)?;
        memory.write(0, &frame[14..])?;
        memory.to_device(0, frame.len() - 14);
        let descriptor = msgbuf::TxPost {
            hdr: CommonHdr {
                msgtype: 0xf,
                ifidx: 0,
                flags: 0,
                request_id: id,
            },
            tx_header: frame[..14].try_into().unwrap(),
            flags: 1 | priority << 5,
            segments: 1,
            metadata_buf_addr: BufAddr(0),
            data_buf_addr: BufAddr(memory.address()),
            metadata_len: 0,
            data_len: (frame.len() - 14) as u16,
        };
        let mut entry = [0; 48];
        descriptor.encode(&mut entry).ok_or(Error::Protocol)?;
        let data = self.resources.as_mut().unwrap().data.as_mut().unwrap();
        data.tx.push(Tx {
            memory,
            id,
            flow: token.id,
        });
        data.flows[index].outstanding += 1;
        match publish_ring(&mut self.bus, &mut data.flows[index].ring, &entry) {
            Ok(()) => Ok(id),
            Err(Error::Busy) => {
                data.tx.pop();
                data.flows[index].outstanding -= 1;
                Err(Error::Busy)
            }
            Err(e) => {
                self.fail();
                Err(e)
            }
        }
    }
    fn tx_completion(&mut self, entry: &[u8]) -> Result<(), Error> {
        let status = msgbuf::TxStatus::decode(entry).ok_or(Error::Protocol)?;
        if status.hdr.ifidx != 0 || status.metadata_len != 0 {
            return Err(Error::Protocol);
        }
        let data = self
            .resources
            .as_mut()
            .unwrap()
            .data
            .as_mut()
            .ok_or(Error::Protocol)?;
        let index = data
            .tx
            .iter()
            .position(|tx| tx.id == status.hdr.request_id && tx.flow == status.flow_ring_id)
            .ok_or(Error::Protocol)?;
        let flow = data
            .flows
            .get_mut(usize::from(
                status.flow_ring_id.checked_sub(2).ok_or(Error::Protocol)?,
            ))
            .ok_or(Error::Protocol)?;
        if flow.state != FlowState::Open || flow.outstanding == 0 {
            return Err(Error::Protocol);
        }
        flow.outstanding -= 1;
        data.tx.remove(index);
        data.receipts.push_back(TxReceipt {
            id: status.hdr.request_id,
            status: status.status,
            tx_status: status.tx_status,
        });
        Ok(())
    }
    fn rx_completion(&mut self, entry: &[u8]) -> Result<(), Error> {
        let complete = msgbuf::RxComplete::decode(entry).ok_or(Error::Protocol)?;
        if complete.hdr.ifidx != 0
            || complete.status != 0
            || complete.metadata_len != 0
            || !matches!(complete.flags & 7, 0 | 1)
        {
            return Err(Error::Protocol);
        }
        let data = self
            .resources
            .as_mut()
            .unwrap()
            .data
            .as_mut()
            .ok_or(Error::Protocol)?;
        let slot = data
            .rx
            .iter_mut()
            .find(|r| r.posted && r.id == complete.hdr.request_id)
            .ok_or(Error::Protocol)?;
        let offset = usize::from(complete.data_offset);
        let length = usize::from(complete.data_len);
        if !(14..=1514).contains(&length)
            || offset.checked_add(length).is_none_or(|end| end > RX_BYTES)
        {
            return Err(Error::Bounds);
        }
        let mut frame = vec![0; length];
        slot.memory.sync_from_device(offset, length);
        slot.memory.read(offset, &mut frame)?;
        slot.posted = false;
        if u16::from_be_bytes([frame[12], frame[13]]) < 0x600
            || frame[6..12] == [0; 6]
            || frame[6] & 1 != 0
        {
            return Err(Error::Protocol);
        }
        if data.received.len() == 32 {
            data.dropped += 1;
        } else {
            data.received.push_back(frame);
        }
        Ok(())
    }
    pub fn pop_received(&mut self) -> Option<Vec<u8>> {
        self.resources.as_mut()?.data.as_mut()?.received.pop_front()
    }
    pub fn pop_tx_receipt(&mut self) -> Option<TxReceipt> {
        self.resources.as_mut()?.data.as_mut()?.receipts.pop_front()
    }
}

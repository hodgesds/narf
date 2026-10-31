//! Queue ownership. Every posted TX packet remains owned through its final
//! DD, or a successful device-wide DMA quiesce. An error is never a fence.

use super::{
    hardware::Registers,
    igc::{AdvTxDataDesc, IgcError},
    packet::{rx_metadata, TxPlan, MAX_MTU},
};
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::{
    ptr,
    sync::atomic::{fence, Ordering},
};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::{id::DomainId, sync::IrqSafeSpinLock};
use narf_net::bypass::{
    umem::DmaLease,
    xdp::{UmemSlot, XdpSocket},
};
use narf_net::{Frame, TxMeta};
#[derive(Debug)]
enum Packet {
    Frame(Frame),
    Umem {
        lease: DmaLease,
        socket: Arc<XdpSocket>,
        len: u32,
    },
}
impl Packet {
    fn len(&self) -> u32 {
        match self {
            Self::Frame(f) => f.len(),
            Self::Umem { len, .. } => *len,
        }
    }
}
#[derive(Debug)]
struct Completed {
    lease: DmaLease,
    socket: Arc<XdpSocket>,
    len: u32,
}

pub(crate) const COUNT: usize = 256;
const BUFFER: usize = 2048;

#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RxRead {
    pub address: u64,
    pub header: u64,
}
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RxWriteback {
    pub info: u32,
    pub hash: u32,
    pub status: u32,
    pub length: u16,
    pub vlan: u16,
}

#[derive(Debug)]
struct Pending {
    end: usize,
    frame: Packet,
    since: u64,
    smd: u8,
}
#[derive(Debug, Default)]
struct Tx {
    next: usize,
    clean: usize,
    pending: VecDeque<Pending>,
    last_launch_cycle: Option<u64>,
    last_tx_cycle: Option<u64>,
    completed_umem: VecDeque<Completed>,
    submitted: u64,
    completed: u64,
    bytes: u64,
    rejects: u64,
}
#[derive(Debug)]
struct Rx {
    head: usize,
    buffers: Vec<DmaBuffer>,
    xsk: Option<Arc<XdpSocket>>,
    leases: Vec<Option<DmaLease>>,
    recycled: VecDeque<DmaLease>,
    partial: Option<Frame>,
    timestamp: Option<u64>,
    dropping: bool,
    packets: u64,
    bytes: u64,
    drops: u64,
}

#[derive(Debug)]
pub(crate) struct Queue {
    pub tx_ring: DmaBuffer,
    pub rx_ring: DmaBuffer,
    tx_count: usize,
    rx_count: usize,
    gate_closed: core::sync::atomic::AtomicBool,
    owner: IrqSafeSpinLock<&'static str>,
    tx: IrqSafeSpinLock<Tx>,
    merge_events: core::sync::atomic::AtomicU8,
    rx: IrqSafeSpinLock<Rx>,
}

fn allocate(bytes: usize) -> Result<DmaBuffer, IgcError> {
    alloc_coherent(bytes, DomainId::DRIVER_0).map_err(|_| IgcError::Other("DMA allocation failed"))
}

impl Queue {
    pub(crate) fn new() -> Result<Self, IgcError> {
        Self::new_sized(COUNT, COUNT)
    }

    pub(crate) fn new_sized(tx_count: usize, rx_count: usize) -> Result<Self, IgcError> {
        if [tx_count, rx_count]
            .iter()
            .any(|n| !(64..=4096).contains(n) || n % 8 != 0)
        {
            return Err(IgcError::QueueTooSmall);
        }
        let mut buffers = Vec::with_capacity(rx_count);
        for _ in 0..rx_count {
            buffers.push(allocate(BUFFER)?);
        }
        let q = Self {
            tx_ring: allocate(tx_count * 16)?,
            rx_ring: allocate(rx_count * 16)?,
            tx_count,
            rx_count,
            gate_closed: core::sync::atomic::AtomicBool::new(false),
            owner: IrqSafeSpinLock::new(""),
            tx: IrqSafeSpinLock::new(Tx::default()),
            merge_events: core::sync::atomic::AtomicU8::new(0),
            rx: IrqSafeSpinLock::new(Rx {
                head: 0,
                buffers,
                xsk: None,
                leases: (0..rx_count).map(|_| None).collect(),
                recycled: VecDeque::new(),
                partial: None,
                timestamp: None,
                dropping: false,
                packets: 0,
                bytes: 0,
                drops: 0,
            }),
        };
        // SAFETY: newly allocated queues have never been exposed to the device.
        unsafe {
            q.reset_after_quiesce();
        }
        Ok(q)
    }

    pub(crate) fn set_owner(&self, name: &'static str) {
        *self.owner.lock() = name;
    }
    pub(crate) fn counts(&self) -> (usize, usize) {
        (self.tx_count, self.rx_count)
    }

    pub(crate) fn statistics(&self) -> [u64; 8] {
        let t = self.tx.lock();
        let r = self.rx.lock();
        [
            t.submitted,
            t.completed,
            t.bytes,
            t.rejects,
            t.pending.len() as u64,
            r.packets,
            r.bytes,
            r.drops,
        ]
    }

    /// # Safety
    /// The device must have acknowledged that DMA is quiescent, or these
    /// queues must never have been exposed to hardware.
    pub(crate) unsafe fn reset_after_quiesce(&self) {
        let mut tx = self.tx.lock();
        tx.next = 0;
        tx.clean = 0;
        while let Some(p) = tx.pending.pop_front() {
            if let Packet::Umem { lease, socket, len } = p.frame {
                tx.completed_umem
                    .push_back(Completed { lease, socket, len });
            }
        }
        Self::drain_completions(&mut tx);
        tx.last_launch_cycle = None;
        tx.last_tx_cycle = None;
        drop(tx);
        let mut rx = self.rx.lock();
        rx.head = 0;
        rx.partial = None;
        rx.timestamp = None;
        if rx.xsk.as_ref().is_some_and(|s| s.is_closed()) {
            rx.xsk = None;
            rx.recycled.clear();
            for slot in &mut rx.leases {
                *slot = None;
            }
        }
        rx.dropping = false;
        // SAFETY: caller's quiescence contract, queue locks exclude CPU access.
        unsafe {
            ptr::write_bytes(self.tx_ring.cpu_mut_ptr_at::<u8>(0), 0, self.tx_count * 16);
        }
        for slot in 0..self.rx_count {
            self.refill_rx(&mut rx, slot);
        }
        fence(Ordering::Release);
    }

    fn refill(&self, slot: usize, buffer: &DmaBuffer) {
        // SAFETY: slot is in the ring; RX lock and DD/quiescence establish ownership.
        unsafe {
            ptr::write_volatile(
                self.rx_ring.cpu_mut_ptr_at::<RxRead>((slot * 16) as u64),
                RxRead {
                    address: buffer.dma_addr().raw(),
                    header: 0,
                },
            );
        }
    }

    /// # Safety
    /// All RX/TX DMA is quiescent. Existing UMEM leases are released only here.
    pub(crate) unsafe fn bind_xsk(&self, socket: Option<Arc<XdpSocket>>) {
        let mut rx = self.rx.lock();
        rx.xsk = socket;
        rx.recycled.clear();
        for slot in 0..self.rx_count {
            rx.leases[slot] = None;
            self.refill_rx(&mut rx, slot);
        }
    }
    pub(crate) fn busy_umem(&self) -> bool {
        let attached = self.rx.lock().xsk.is_some();
        let tx = self.tx.lock();
        attached
            || !tx.completed_umem.is_empty()
            || tx
                .pending
                .iter()
                .any(|p| matches!(p.frame, Packet::Umem { .. }))
    }
    pub(crate) fn xsk(&self) -> Option<Arc<XdpSocket>> {
        self.rx.lock().xsk.clone()
    }
    fn refill_rx(&self, rx: &mut Rx, slot: usize) {
        if let Some(lease) = &rx.leases[slot] {
            // SAFETY: quiescent or DD-released descriptor; lease remains retained.
            unsafe {
                ptr::write_volatile(
                    self.rx_ring.cpu_mut_ptr_at::<RxRead>((slot * 16) as u64),
                    RxRead {
                        address: lease.address(),
                        header: 0,
                    },
                );
            }
            return;
        }
        if let Some(socket) = rx.xsk.as_ref() {
            for _ in 0..64 {
                let lease = if !socket.is_closed() && !rx.recycled.is_empty() {
                    rx.recycled.pop_front()
                } else {
                    let Some(fill) = socket.pop_fill() else {
                        break;
                    };
                    socket.umem().lease(fill.frame_idx).ok()
                };
                if let Some(lease) = lease {
                    let address = lease.address();
                    rx.leases[slot] = Some(lease);
                    // SAFETY: software owns this descriptor; lease pins the DMA target.
                    unsafe {
                        ptr::write_volatile(
                            self.rx_ring.cpu_mut_ptr_at::<RxRead>((slot * 16) as u64),
                            RxRead { address, header: 0 },
                        );
                    }
                    return;
                }
                if socket.is_closed() {
                    break;
                }
            }
        }
        self.refill(slot, &rx.buffers[slot]);
    }
    fn drain_completions(tx: &mut Tx) {
        while let Some(done) = tx.completed_umem.pop_front() {
            let slot = UmemSlot {
                frame_idx: done.lease.index(),
                len: done.len,
            };
            if done.socket.push_completion(slot).is_err() {
                tx.completed_umem.push_front(done);
                break;
            }
            drop(done);
        }
    }
    fn done(&self, slot: usize) -> bool {
        // SAFETY: aligned completion dword in the allocated ring. Device writes DD last.
        let done =
            unsafe { ptr::read_volatile(self.tx_ring.cpu_ptr_at::<u32>((slot * 16 + 12) as u64)) }
                & 1
                != 0;
        if done {
            fence(Ordering::Acquire);
        }
        done
    }

    fn reclaim_locked(&self, tx: &mut Tx) -> usize {
        let mut reclaimed = 0;
        while tx.pending.front().is_some_and(|p| self.done(p.end)) {
            let p = tx.pending.pop_front().unwrap();
            if p.smd == 1 {
                self.merge_events.fetch_or(4, Ordering::Release);
            }
            tx.completed += 1;
            tx.bytes += u64::from(p.frame.len());
            tx.clean = (p.end + 1) % self.tx_count;
            // Owned Frames may come from the stack's DMA pool; return them
            // using its existing release hook after completion.
            match p.frame {
                Packet::Frame(frame) => {
                    let q = frame.queue();
                    narf_net::iface::tx_release_on(*self.owner.lock(), q, frame.into_parts().0);
                }
                Packet::Umem { lease, socket, len } => {
                    tx.completed_umem
                        .push_back(Completed { lease, socket, len })
                }
            }
            reclaimed += 1;
        }
        Self::drain_completions(tx);
        reclaimed
    }

    pub(crate) fn reclaim(&self) -> usize {
        self.reclaim_locked(&mut self.tx.lock())
    }

    pub(crate) fn stalled(&self, now: u64, timeout: u64) -> bool {
        self.tx
            .lock()
            .pending
            .front()
            .is_some_and(|p| now.wrapping_sub(p.since) > timeout)
    }

    pub(crate) fn flush(&self, r: &impl Registers, q: usize) {
        let tx = self.tx.lock();
        fence(Ordering::Release);
        r.write(0xe018 + q as u64 * 0x40, tx.next as u32);
    }

    pub(crate) fn set_gate_closed(&self, closed: bool) {
        self.gate_closed.store(closed, Ordering::Release);
    }

    pub(crate) fn post(
        &self,
        r: &impl Registers,
        q: usize,
        frame: Frame,
        meta: TxMeta,
        mtu: u32,
    ) -> Result<(), IgcError> {
        self.post_options(r, q, frame, meta, mtu, TxOptions::default())
    }
    pub(crate) fn post_options(
        &self,
        r: &impl Registers,
        q: usize,
        mut frame: Frame,
        meta: TxMeta,
        mtu: u32,
        options: TxOptions,
    ) -> Result<(), IgcError> {
        if self.gate_closed.load(Ordering::Acquire) {
            self.tx.lock().rejects += 1;
            return Err(IgcError::Other("traffic gate closed"));
        }
        let mut plan = TxPlan::prepare(frame.payload_mut(), meta, q, mtu)?;
        plan.command |= options.command;
        plan.info |= options.info;
        if let Some(launch) = options.launch {
            let context = plan.context.get_or_insert(super::igc::AdvTxCtxtDesc {
                type_tucmd_mlhl: 0x20200000,
                ..Default::default()
            });
            context.launch_time = launch.offset;
        }
        let address = frame.buf().dma_addr_at(u64::from(frame.offset())).raw();
        let length = frame.len() as usize;
        // Split at 4 KiB boundaries; every descriptor length fits the device field.
        let data_count = ((address as usize & 4095) + length).div_ceil(4096);
        let empty_candidate = if options.launch.is_some_and(|l| l.next) {
            let mut b = allocate(60)?;
            b.as_mut_slice()[..60].fill(0);
            Some(Frame::new(b, 60))
        } else {
            None
        };
        let mut tx = self.tx.lock();
        self.reclaim_locked(&mut tx);
        let first = options
            .launch
            .is_some_and(|l| l.next && tx.last_launch_cycle != Some(l.cycle));
        let empty = first
            && options
                .launch
                .is_some_and(|l| tx.last_tx_cycle != Some(l.cycle));
        let needed = data_count + usize::from(plan.context.is_some()) + if empty { 2 } else { 0 };
        let free = (tx.clean + self.tx_count - tx.next - 1) % self.tx_count;
        if needed > free {
            tx.rejects += 1;
            fence(Ordering::Release);
            r.write(0xe018 + q as u64 * 0x40, tx.next as u32);
            return Err(IgcError::QueueTooSmall);
        }
        let mut slot = tx.next;
        if empty {
            let frame = empty_candidate.expect("future launch allocated empty frame");
            let context = super::igc::AdvTxCtxtDesc {
                type_tucmd_mlhl: 0x20200000,
                ..Default::default()
            };
            // SAFETY: reservation includes both workaround descriptors.
            unsafe {
                ptr::write_volatile(
                    self.tx_ring
                        .cpu_mut_ptr_at::<super::igc::AdvTxCtxtDesc>((slot * 16) as u64),
                    context,
                );
            }
            slot = (slot + 1) % self.tx_count;
            let desc = AdvTxDataDesc {
                buffer_addr: frame.buf().dma_addr().raw(),
                cmd_type_len: 0x2b300000 | 60,
                olinfo_status: 60 << 14,
            };
            // SAFETY: reserved software slot; frame ownership installed before TDT.
            unsafe {
                ptr::write_volatile(
                    self.tx_ring
                        .cpu_mut_ptr_at::<AdvTxDataDesc>((slot * 16) as u64),
                    desc,
                );
            }
            tx.pending.push_back(Pending {
                end: slot,
                frame: Packet::Frame(frame),
                since: narf_time::now_cycles(),
                smd: 0,
            });
            slot = (slot + 1) % self.tx_count;
        }
        if let Some(launch) = options.launch {
            tx.last_tx_cycle = Some(launch.cycle);
            if first {
                tx.last_launch_cycle = Some(launch.cycle);
            }
        }
        if let Some(mut context) = plan.context {
            if first {
                context.mss_l4len_idx |= 0x80;
            }
            // SAFETY: all reserved slots belong to software, protected by tx.
            unsafe {
                ptr::write_volatile(self.tx_ring.cpu_mut_ptr_at((slot * 16) as u64), context);
            }
            slot = (slot + 1) % self.tx_count;
        }
        let mut offset = 0;
        let mut end = slot;
        while offset < length {
            let addr = address + offset as u64;
            let count = (4096 - (addr as usize & 4095)).min(length - offset);
            let last = offset + count == length;
            let desc = AdvTxDataDesc {
                buffer_addr: addr,
                cmd_type_len: plan.command
                    | count as u32
                    | if last { (1 << 24) | (1 << 27) } else { 0 },
                olinfo_status: if offset == 0 { plan.info } else { 0 },
            };
            // SAFETY: reserved descriptor; device cannot access it until TDT.
            unsafe {
                ptr::write_volatile(self.tx_ring.cpu_mut_ptr_at((slot * 16) as u64), desc);
            }
            end = slot;
            slot = (slot + 1) % self.tx_count;
            offset += count;
        }
        // Establish ownership BEFORE publishing any descriptor to DMA.
        tx.pending.push_back(Pending {
            end,
            frame: Packet::Frame(frame),
            smd: ((options.info >> 12) & 3) as u8,
            since: narf_time::now_cycles(),
        });
        tx.next = slot;
        tx.submitted += 1;
        fence(Ordering::Release);
        if !meta.more || free - needed < 20 {
            r.write(0xe018 + q as u64 * 0x40, slot as u32);
        }
        Ok(())
    }

    pub(crate) fn poll_xsk(&self, r: &impl Registers, q: usize, mtu: u32) {
        self.reclaim();
        let Some(socket) = self.xsk() else {
            return;
        };
        // Backpressure on COMPLETION must not consume more ownership than the
        // bounded ring can retain. A socket cannot alias its pending leases.
        if self.tx.lock().completed_umem.len() >= 64 {
            return;
        }
        for _ in 0..32 {
            let Some(slot) = socket.pop_tx() else {
                break;
            };
            if !(14..=mtu + 18).contains(&slot.len) || slot.len > socket.umem().frame_size() {
                continue;
            }
            if let Ok(lease) = socket.umem().lease(slot.frame_idx) {
                let _ = self.post_umem(r, q, lease, socket.clone(), slot.len);
            }
        }
    }
    fn post_umem(
        &self,
        r: &impl Registers,
        q: usize,
        lease: DmaLease,
        socket: Arc<XdpSocket>,
        len: u32,
    ) -> Result<(), IgcError> {
        let mut tx = self.tx.lock();
        self.reclaim_locked(&mut tx);
        let next = (tx.next + 1) % self.tx_count;
        if next == tx.clean || self.gate_closed.load(Ordering::Acquire) {
            tx.rejects += 1;
            tx.completed_umem
                .push_back(Completed { lease, socket, len });
            Self::drain_completions(&mut tx);
            return Err(IgcError::QueueTooSmall);
        }
        let desc = AdvTxDataDesc {
            buffer_addr: lease.address(),
            cmd_type_len: 0x2b300000 | len,
            olinfo_status: len << 14,
        };
        let slot = tx.next;
        // SAFETY: reserved software descriptor; lease retained before publishing TDT.
        unsafe {
            ptr::write_volatile(
                self.tx_ring
                    .cpu_mut_ptr_at::<AdvTxDataDesc>((slot * 16) as u64),
                desc,
            );
        }
        tx.pending.push_back(Pending {
            end: slot,
            frame: Packet::Umem { lease, socket, len },
            smd: 0,
            since: narf_time::now_cycles(),
        });
        tx.next = next;
        tx.submitted += 1;
        fence(Ordering::Release);
        r.write(0xe018 + q as u64 * 0x40, next as u32);
        Ok(())
    }
    pub(crate) fn merge_events(&self) -> u8 {
        self.merge_events.swap(0, Ordering::AcqRel)
    }
    pub(crate) fn post_smd(&self, r: &impl Registers, kind: u8) -> Result<(), IgcError> {
        let mut buffer = allocate(60)?;
        buffer.as_mut_slice()[..60].fill(0);
        self.post_options(
            r,
            0,
            Frame::new(buffer, 60),
            TxMeta::plain(),
            1500,
            TxOptions {
                info: u32::from(kind) << 12,
                ..Default::default()
            },
        )
    }
    pub(crate) fn pending_rx(&self) -> bool {
        let rx = self.rx.lock();
        // SAFETY: aligned DD dword in the allocated ring; read-only inspection.
        unsafe {
            ptr::read_volatile(self.rx_ring.cpu_ptr_at::<u32>((rx.head * 16 + 8) as u64)) & 1 != 0
        }
    }

    /// Budget counts descriptors, including corrupt and incomplete packets.
    pub(crate) fn receive(
        &self,
        r: &impl Registers,
        q: usize,
        mtu: u32,
        budget: usize,
    ) -> (Vec<Frame>, u64) {
        let mut rx = self.rx.lock();
        let mut frames = Vec::new();
        let mut native = Vec::new();
        let mut drops = 0;
        let mut consumed = 0;
        for _ in 0..budget {
            let slot = rx.head;
            // SAFETY: DD is the device's release of this descriptor and packet buffer.
            let status = unsafe {
                ptr::read_volatile(self.rx_ring.cpu_ptr_at::<u32>((slot * 16 + 8) as u64))
            };
            if status & 1 == 0 {
                break;
            }
            fence(Ordering::Acquire);
            // SAFETY: DD observed above; hardware no longer writes this slot.
            let wb = unsafe {
                ptr::read_volatile(self.rx_ring.cpu_ptr_at::<RxWriteback>((slot * 16) as u64))
            };
            let smd = (status >> 13) & 3;
            if matches!(smd, 1 | 2) && rx.leases[slot].is_none() {
                let prefix = if status & 0x8000 != 0 { 16 } else { 0 };
                if usize::from(wb.length) == 60 + prefix && status & 0x80000002 == 2 {
                    // SAFETY: DD releases the bounded 60-byte control packet.
                    let packet = unsafe {
                        core::slice::from_raw_parts(
                            rx.buffers[slot].cpu_ptr_at::<u8>(prefix as u64),
                            60,
                        )
                    };
                    if packet.iter().all(|b| *b == 0) {
                        self.merge_events
                            .fetch_or(if smd == 1 { 1 } else { 2 }, Ordering::Release);
                    }
                }
                self.refill_rx(&mut rx, slot);
                rx.head = (slot + 1) % self.rx_count;
                consumed += 1;
                continue;
            }
            if let Some(mut lease) = rx.leases[slot].take() {
                let mut len = usize::from(wb.length);
                let socket = rx
                    .xsk
                    .clone()
                    .expect("UMEM binding retained until quiescence");
                if status & 0x80008002 == 2
                    && (14..=BUFFER).contains(&len)
                    && len <= mtu as usize + 18
                {
                    // SAFETY: DD releases this unique lease; valid length is bounded.
                    let bytes =
                        unsafe { lease.bytes_mut(len + if status & 8 != 0 { 4 } else { 0 }) };
                    if status & 8 != 0 {
                        bytes.copy_within(12..len, 16);
                        bytes[12..14].copy_from_slice(&[0x81, 0]);
                        bytes[14..16].copy_from_slice(&wb.vlan.to_be_bytes());
                        len += 4;
                    }
                    let (action, n) = narf_net::bypass::classifier::run_xdp(
                        *self.owner.lock(),
                        &mut bytes[..len],
                    );
                    native.push((lease, socket, n, action));
                    rx.packets += 1;
                    rx.bytes += n as u64;
                } else {
                    drops += 1;
                    rx.leases[slot] = Some(lease);
                }
                self.refill_rx(&mut rx, slot);
                rx.head = (slot + 1) % self.rx_count;
                consumed += 1;
                continue;
            }
            if rx.xsk.is_some() {
                // No FILL slot was available when this descriptor was armed.
                // The queue is exclusively owned by AF_XDP; do not leak it to
                // the protocol stack while the daemon is starved.
                drops += 1;
                self.refill_rx(&mut rx, slot);
                rx.head = (slot + 1) % self.rx_count;
                consumed += 1;
                continue;
            }
            let raw_len = usize::from(wb.length);
            let prefix = if status & 0x8000 != 0 { 16 } else { 0 };
            if rx.partial.is_none() && !rx.dropping {
                rx.timestamp = None;
            }
            if prefix != 0 && raw_len >= 16 {
                // SAFETY: DD releases the timestamp prefix inside the RX allocation.
                let stamp =
                    unsafe { core::slice::from_raw_parts(rx.buffers[slot].cpu_ptr_at::<u8>(8), 8) };
                let ns = u32::from_le_bytes(stamp[..4].try_into().unwrap());
                let sec = u32::from_le_bytes(stamp[4..].try_into().unwrap());
                if ns < 1_000_000_000 {
                    rx.timestamp = Some(u64::from(sec) * 1_000_000_000 + u64::from(ns));
                }
            }
            let len = raw_len.saturating_sub(prefix);
            let eop = status & 2 != 0;
            if status & 0x80000000 != 0 || len == 0 || raw_len > BUFFER || raw_len < prefix {
                rx.dropping = true;
                rx.partial = None;
            }
            if !rx.dropping {
                let previous = rx.partial.as_ref().map_or(0, |f| f.len() as usize);
                if previous + len > mtu as usize + 18 {
                    rx.dropping = true;
                    rx.partial = None;
                } else if eop && rx.partial.is_none() && status & 8 == 0 {
                    if let Ok(replacement) = allocate(BUFFER) {
                        let filled = core::mem::replace(&mut rx.buffers[slot], replacement);
                        let mut frame = Frame::with_offset_on_queue(
                            filled,
                            prefix as u32,
                            len as u32,
                            q as u16,
                        );
                        let mut metadata = rx_metadata(status, wb.hash);
                        metadata.timestamp_ns = rx
                            .timestamp
                            .map(|t| t.saturating_sub(super::ptp::rx_latency(r.read(8))));
                        frame.set_rx_meta(metadata);
                        if valid_received(&frame, mtu) {
                            frames.push(frame);
                        } else {
                            rx.dropping = true;
                        }
                    } else {
                        rx.dropping = true;
                    }
                } else {
                    // A bounded assembly buffer handles scatter jumbo frames and
                    // reinserts a VLAN stripped by CTRL.VME before stack dispatch.
                    if rx.partial.is_none() {
                        rx.partial = allocate(MAX_MTU as usize + 22)
                            .ok()
                            .map(|b| Frame::with_offset_on_queue(b, 0, 0, q as u16));
                    }
                    if let Some(mut frame) = rx.partial.take() {
                        // SAFETY: validated length, coherent RX buffer, no alias with assembly.
                        unsafe {
                            ptr::copy_nonoverlapping(
                                rx.buffers[slot].cpu_ptr_at::<u8>(prefix as u64),
                                frame.buf().cpu_mut_ptr_at::<u8>(previous as u64),
                                len,
                            );
                        }
                        frame = resize(frame, previous + len, q);
                        if eop {
                            if status & 8 != 0 {
                                if frame.len() < 14 {
                                    rx.dropping = true;
                                } else {
                                    let n = frame.len() as usize;
                                    frame = resize(frame, n + 4, q);
                                    let bytes = frame.payload_mut();
                                    bytes.copy_within(12..n, 16);
                                    bytes[12..14].copy_from_slice(&[0x81, 0]);
                                    bytes[14..16].copy_from_slice(&wb.vlan.to_be_bytes());
                                }
                            }
                            if !rx.dropping && valid_received(&frame, mtu) {
                                let mut metadata = rx_metadata(status, wb.hash);
                                metadata.timestamp_ns = rx
                                    .timestamp
                                    .map(|t| t.saturating_sub(super::ptp::rx_latency(r.read(8))));
                                frame.set_rx_meta(metadata);
                                frames.push(frame);
                            } else {
                                rx.dropping = true;
                            }
                        } else {
                            rx.partial = Some(frame);
                        }
                    } else {
                        rx.dropping = true;
                    }
                }
            }
            self.refill_rx(&mut rx, slot);
            rx.head = (slot + 1) % self.rx_count;
            consumed += 1;
            if eop {
                if rx.dropping {
                    drops += 1;
                }
                rx.dropping = false;
                rx.partial = None;
            }
        }
        if consumed != 0 {
            fence(Ordering::Release);
            r.write(
                0xc018 + q as u64 * 0x40,
                ((rx.head + self.rx_count - 1) % self.rx_count) as u32,
            );
        }
        rx.packets += frames.len() as u64;
        rx.bytes += frames.iter().map(|f| u64::from(f.len())).sum::<u64>();
        drop(rx);
        for (mut lease, socket, len, action) in native {
            use narf_net::bypass::classifier::XdpAction;
            match action {
                XdpAction::Pass => {
                    let slot = UmemSlot {
                        frame_idx: lease.index(),
                        len: len as u32,
                    };
                    if socket.push_rx(slot).is_err() {
                        // RX backpressure must recycle an unpublished buffer;
                        // userspace never received an index it could return.
                        drops += 1;
                        let mut rx = self.rx.lock();
                        if rx.xsk.as_ref().is_some_and(|s| Arc::ptr_eq(s, &socket)) {
                            rx.recycled.push_back(lease);
                        }
                    }
                }
                XdpAction::Tx => {
                    let _ = self.post_umem(r, q, lease, socket, len as u32);
                    continue;
                }
                other => {
                    if matches!(other, XdpAction::Drop | XdpAction::Aborted) {
                        drops += 1;
                    }
                    // SAFETY: completed unique lease remains CPU owned until dispatch ends.
                    let bytes = unsafe { lease.bytes_mut(len) };
                    super::igc::native_redirect(*self.owner.lock(), bytes, other, None);
                    let mut rx = self.rx.lock();
                    if rx.xsk.as_ref().is_some_and(|s| Arc::ptr_eq(s, &socket)) {
                        rx.recycled.push_back(lease);
                    }
                }
            }
        }
        self.rx.lock().drops += drops;
        (frames, drops)
    }
}

fn resize(frame: Frame, length: usize, queue: usize) -> Frame {
    Frame::with_offset_on_queue(frame.into_parts().0, 0, length as u32, queue as u16)
}

fn valid_received(frame: &Frame, mtu: u32) -> bool {
    let bytes = frame.payload();
    if bytes.len() < 14 {
        return false;
    }
    let tagged = bytes[12..14] == [0x81, 0] || bytes[12..14] == [0x88, 0xa8];
    bytes.len() <= mtu as usize + if tagged { 18 } else { 14 }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TxOptions {
    pub info: u32,
    pub command: u32,
    pub launch: Option<super::traffic::Launch>,
}

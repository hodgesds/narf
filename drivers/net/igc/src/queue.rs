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
/// Most descriptors one frame can take (Linux igc `DESC_NEEDED`): the
/// largest frame split at every 4 KiB boundary it can straddle, one context
/// descriptor, and the two descriptors of the launch-time workaround.
pub(crate) const MAX_FRAME_DESCS: u32 = (crate::packet::MAX_TSO + 4095).div_ceil(4096) as u32 + 3;
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
    /// Completed frames whose descriptor reported an L3/L4 checksum error
    /// (Linux `rx_queue_%u_csum_err`).
    csum_err: u64,
    /// Frames dropped because no RX buffer could be allocated (Linux
    /// `rx_queue_%u_alloc_failed`).
    alloc_failed: u64,
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
    /// Stop/wake state and waiters shared with the stack. Its thresholds
    /// come from this ring's length, whatever `ethtool -G` made it.
    txq: Arc<narf_net::txq::TxQueue>,
    merge_events: core::sync::atomic::AtomicU8,
    rx: IrqSafeSpinLock<Rx>,
}

/// Read-only evidence for a failed completion path, collected before reset.
/// Each descriptor word is sampled independently while DMA may still run;
/// this snapshot is never proof that the device released a buffer.
#[derive(Debug)]
pub(crate) struct CompletionSnapshot {
    pub tx_dma: u64,
    pub tx_cpu: usize,
    pub tx_next: usize,
    pub tx_clean: usize,
    pub tx_end: Option<usize>,
    pub tx_words: [u32; 4],
    pub rx_dma: u64,
    pub rx_cpu: usize,
    pub rx_head: usize,
    pub rx_words: [u32; 4],
    pub tx_mapping: Option<CpuMappingSnapshot>,
    pub rx_mapping: Option<CpuMappingSnapshot>,
}

#[derive(Debug)]
pub(crate) struct QuiescedWritebackSnapshot {
    pub tx_dd: usize,
    pub rx_dd: usize,
    pub rx_nonzero_prefixes: usize,
    pub rx_leased_skipped: usize,
    pub first_changed_rx: Option<usize>,
    pub first_rx_words: [u32; 8],
}

/// Read-only evidence of the CPU mapping, not a DMA-completion fence.
#[cfg(target_arch = "x86_64")]
#[derive(Debug)]
pub(crate) struct CpuMappingSnapshot {
    pub physical: u64,
    pub translated: Option<u64>,
    pub end_translated: Option<u64>,
    pub pages_match: bool,
    pub root: u64,
    pub leaf_flags: Option<u64>,
    pub leaf_bytes: Option<u64>,
    pub pat: u64,
    pub pat_type: Option<u8>,
    pub mtrr_default: Option<u64>,
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) type CpuMappingSnapshot = ();

#[cfg(target_arch = "x86_64")]
pub(crate) fn cpu_mapping_snapshot(buffer: &DmaBuffer) -> Option<CpuMappingSnapshot> {
    use narf_memory::{x86_64::paging, VirtAddr};
    let cpu = buffer.cpu_ptr::<u8>() as u64;
    let physical = buffer.phys_addr().raw();
    // SAFETY: CPL0, current live address space. The owned buffer pins its
    // RAM; the permanent direct map/page tables remain live during this walk.
    let root = unsafe { paging::read_cr3() };
    let translate = |offset| {
        // SAFETY: same live root and stable direct-map pages, read-only walk.
        unsafe { paging::translate(root, VirtAddr::new(cpu + offset)) }.map(|p| p.raw())
    };
    // SAFETY: same current root, only reading its mapping of the owned buffer.
    let leaf = unsafe { paging::leaf_flags_at(root, VirtAddr::new(cpu)) };
    let pat = narf_arch::x86_64::pat::read();
    let pat_type = leaf.map(|(flags, size)| {
        let flags = flags.bits();
        let pat_bit = if size == 4096 { 7 } else { 12 };
        let index = ((flags >> 3) & 3) | (((flags >> pat_bit) & 1) << 2);
        ((pat >> (index * 8)) & 0xff) as u8
    });
    let last = buffer.len() as u64 - 1;
    Some(CpuMappingSnapshot {
        physical,
        translated: translate(0),
        end_translated: translate(last),
        pages_match: (0..buffer.len())
            .step_by(4096)
            .all(|offset| translate(offset as u64) == Some(physical + offset as u64))
            && translate(last) == Some(physical + last),
        root: root.raw(),
        leaf_flags: leaf.map(|(flags, _)| flags.bits()),
        leaf_bytes: leaf.map(|(_, size)| size),
        pat,
        pat_type,
        mtrr_default: narf_arch::x86_64::msr::rdmsr_or_gp(0x2ff).ok(),
    })
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn cpu_mapping_snapshot(_: &DmaBuffer) -> Option<CpuMappingSnapshot> {
    None
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
            txq: narf_net::txq::TxQueue::new(narf_net::txq::TxQueueGeometry {
                ring_len: tx_count as u32,
                max_frame_descs: MAX_FRAME_DESCS,
            }),
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
                csum_err: 0,
                alloc_failed: 0,
            }),
        };
        // SAFETY: newly allocated queues have never been exposed to the device.
        unsafe {
            q.reset_after_quiesce();
        }
        Ok(q)
    }

    pub(crate) fn txq(&self) -> &Arc<narf_net::txq::TxQueue> {
        &self.txq
    }
    pub(crate) fn set_owner(&self, name: &'static str) {
        *self.owner.lock() = name;
    }
    pub(crate) fn counts(&self) -> (usize, usize) {
        (self.tx_count, self.rx_count)
    }

    pub(crate) fn statistics(&self) -> [u64; 10] {
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
            r.csum_err,
            r.alloc_failed,
        ]
    }

    pub(crate) fn completion_snapshot(&self) -> CompletionSnapshot {
        let (tx_next, tx_clean, tx_end, tx_words) = {
            let tx = self.tx.lock();
            let end = tx.pending.front().map(|packet| packet.end);
            let slot = end.unwrap_or(tx.clean);
            // SAFETY: the TX lock pins this in-bounds descriptor slot. Read
            // individual words as in done(); do not reclaim or modify DMA.
            let words = core::array::from_fn(|i| unsafe {
                ptr::read_volatile(self.tx_ring.cpu_ptr_at::<u32>((slot * 16 + i * 4) as u64))
            });
            (tx.next, tx.clean, end, words)
        };
        let (rx_head, rx_words) = {
            let rx = self.rx.lock();
            // SAFETY: lock pins the next-to-clean slot. Observing words does
            // not claim DD, read payload, rearm or change DMA ownership.
            let words = core::array::from_fn(|i| unsafe {
                ptr::read_volatile(
                    self.rx_ring
                        .cpu_ptr_at::<u32>((rx.head * 16 + i * 4) as u64),
                )
            });
            (rx.head, words)
        };
        CompletionSnapshot {
            tx_dma: self.tx_ring.dma_addr().raw(),
            tx_cpu: self.tx_ring.cpu_ptr::<u8>() as usize,
            tx_next,
            tx_clean,
            tx_end,
            tx_words,
            rx_dma: self.rx_ring.dma_addr().raw(),
            rx_cpu: self.rx_ring.cpu_ptr::<u8>() as usize,
            rx_head,
            rx_words,
            tx_mapping: cpu_mapping_snapshot(&self.tx_ring),
            rx_mapping: cpu_mapping_snapshot(&self.rx_ring),
        }
    }

    /// Inspect retained payloads only after the device-wide DMA drain, before
    /// reset clears the rings. No flush, cache invalidation or ownership change.
    ///
    /// # Safety
    /// All packet operations have stopped and hardware::quiesce acknowledged
    /// the controller's complete DMA drain. DMA must remain stopped throughout.
    pub(crate) unsafe fn quiesced_writeback_snapshot(&self) -> QuiescedWritebackSnapshot {
        let rx = self.rx.lock();
        let mut result = QuiescedWritebackSnapshot {
            tx_dd: 0,
            rx_dd: 0,
            rx_nonzero_prefixes: 0,
            rx_leased_skipped: 0,
            first_changed_rx: None,
            first_rx_words: [0; 8],
        };
        for slot in 0..self.tx_count {
            // SAFETY: slot is bounded; caller proved no device writer remains.
            let status = unsafe {
                ptr::read_volatile(self.tx_ring.cpu_ptr_at::<u32>((slot * 16 + 12) as u64))
            };
            result.tx_dd += usize::from(status & 1 != 0);
        }
        for slot in 0..self.rx_count {
            // SAFETY: same quiescence proof and bounded descriptor index.
            let status = unsafe {
                ptr::read_volatile(self.rx_ring.cpu_ptr_at::<u32>((slot * 16 + 8) as u64))
            };
            result.rx_dd += usize::from(status & 1 != 0);
            if rx.leases[slot].is_some() {
                result.rx_leased_skipped += 1;
                continue;
            }
            // Read the retained allocation, never an address from a descriptor
            // that the NIC may have replaced with writeback metadata. Sample
            // a bounded prefix; reused buffers can contain earlier traffic.
            let words: [u32; 8] = core::array::from_fn(|word| {
                // SAFETY: retained RX buffers are >= 2048 bytes; DMA drained.
                unsafe { ptr::read_volatile(rx.buffers[slot].cpu_ptr_at::<u32>((word * 4) as u64)) }
            });
            if words != [0; 8] {
                result.rx_nonzero_prefixes += 1;
                if result.first_changed_rx.is_none() {
                    result.first_changed_rx = Some(slot);
                    result.first_rx_words = words;
                }
            }
        }
        result
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
        // Linux `netdev_tx_reset_queue`: the ring is empty again. Frames it
        // held were dropped above (returning their connections' charges);
        // whoever waited for room is released by the next wake pass.
        self.txq.reset();
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
        let mut bytes = 0u64;
        while tx.pending.front().is_some_and(|p| self.done(p.end)) {
            let p = tx.pending.pop_front().unwrap();
            if p.smd == 1 {
                self.merge_events.fetch_or(4, Ordering::Release);
            }
            tx.completed += 1;
            tx.bytes += u64::from(p.frame.len());
            bytes += u64::from(p.frame.len());
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
        if reclaimed != 0 {
            // Linux `igc_clean_tx_irq`: one report per cleaned batch, which
            // wakes the queue once `TX_WAKE_THRESHOLD` descriptors are free.
            let free = (tx.clean + self.tx_count - tx.next - 1) % self.tx_count;
            self.txq.completed(reclaimed as u32, bytes, free as u32);
        }
        reclaimed
    }

    pub(crate) fn reclaim(&self) -> usize {
        self.reclaim_locked(&mut self.tx.lock())
    }

    /// Linux `dev_watchdog`: `time_after(jiffies, trans_start + timeout)` is a
    /// signed comparison, so a transmit stamped after the watchdog sampled the
    /// clock is young, not stalled. `now` is read before this takes the TX
    /// lock; a sender that held the lock meanwhile stamps its frame later than
    /// `now`, and an unsigned difference turned that into a 2^64-cycle stall
    /// and a full controller reset in the middle of a busy transmit.
    pub(crate) fn stalled(&self, now: u64, timeout: u64) -> bool {
        self.tx
            .lock()
            .pending
            .front()
            .is_some_and(|p| now.saturating_sub(p.since) > timeout)
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
        // A caller that honours backpressure is refused while the queue is
        // stopped and when its frame does not fit, as `igc_xmit_frame_ring`
        // returns NETDEV_TX_BUSY: the frame is not posted and not counted
        // as rejected. A frame no empty ring could hold is an error instead,
        // or its owner would wait for room that never comes.
        if options.backpressure
            && (self.txq.is_stopped() || (needed > free && self.txq.fits_empty_ring(needed as u32)))
        {
            self.txq.refused();
            fence(Ordering::Release);
            r.write(0xe018 + q as u64 * 0x40, tx.next as u32);
            return Err(IgcError::TxBusy);
        }
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
        // Linux `igc_maybe_stop_tx(tx_ring, DESC_NEEDED)` after every frame,
        // whoever sent it: stop while fewer descriptors remain than one more
        // worst-case frame needs. Completions run under this lock, so the
        // free count cannot change behind the check.
        let free_after = (free - needed) as u32;
        self.txq.sent(length as u32, || free_after);
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
                        rx.alloc_failed += 1;
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
                        // Reachable only when the assembly allocation just
                        // above failed: `rx.partial` is assigned from
                        // `allocate(..).ok()` and taken immediately after.
                        rx.alloc_failed += 1;
                        rx.dropping = true;
                    }
                }
            }
            self.refill_rx(&mut rx, slot);
            rx.head = (slot + 1) % self.rx_count;
            consumed += 1;
            if eop {
                // Linux igc_rx_checksum counts one csum_err per completed
                // frame whose descriptor reports an L3/L4 checksum error
                // (IPE/L4E), except when IXSM says the checksum result is
                // not meaningful (same gate as rx_metadata). The 60-byte
                // SCTP errata exception is not applied: NARF has no
                // per-ring SCTP checksum flag to condition it on.
                if status & 4 == 0 && status & 0x60000000 != 0 {
                    rx.csum_err += 1;
                }
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
    /// The caller honours [`IgcError::TxBusy`]: refuse instead of using the
    /// descriptors kept free below the stop threshold.
    pub backpressure: bool,
}

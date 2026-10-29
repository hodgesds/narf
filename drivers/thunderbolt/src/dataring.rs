//! NHI high-speed DMA data rings for the ThunderboltIP netdev:
//! one frame-mode TX/RX ring pair per bound peer, implementing
//! the [`super::tbnet::DataLink`] seam over the same BAR as
//! ring 0.
//!
//! Register and descriptor layout follows Linux `nhi_regs.h`
//! and the ring programming in `nhi.c` (`tb_ring_alloc`,
//! `tb_ring_start`, `tb_ring_stop`, `ring_write_descriptors`,
//! `tb_ring_poll`); ring parameters follow the reference
//! networking driver (`drivers/net/thunderbolt/main.c`:
//! `TBNET_RING_SIZE`, `TBNET_FRAME_SIZE`, the frame-start/end
//! PDF masks, and `tbnet_open`'s ring flags). The crate's ring 0
//! (`ring.rs`) is the house discipline this mirrors: descriptors
//! are posted with the flags dword last behind a release fence,
//! completions are consumed in tail order behind an acquire
//! fence, `stop` verifies the ENABLE bits cleared before the DMA
//! allocations may be released, and a failed stop quarantines
//! the allocations instead of freeing them.
//!
//! Differences from ring 0, all from the frame-mode model:
//! buffers are 4 KiB (a descriptor length of 0 encodes a full
//! 4096-byte frame), the rings hold 256 entries, descriptors
//! carry SOF/EOF PDF values instead of a raw packet kind, and
//! the RX ring runs with the end-to-end workaround enabled
//! (`RING_FLAG_E2E`): its options fold `RING_FLAG_E2E_FLOW_CONTROL`
//! and the reserved credit-sink HopID into the ENABLE write, as
//! `tb_ring_start` does. The rings are harvested by polling from
//! the connection-manager pass — the descriptor INTERRUPT bit is
//! never set and no interrupt bank is touched, so ring 0's
//! MSI-X routing and global interrupt masking are undisturbed.

use alloc::vec::Vec;
use core::{
    mem::ManuallyDrop,
    sync::atomic::{fence, Ordering},
};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;

use super::{
    ring::{Error, IoOp},
    tbnet::{DataLink, PDF_FRAME_END, PDF_FRAME_START},
};

/// Entries per data ring (`TBNET_RING_SIZE`).
pub(crate) const RING_SIZE: usize = 256;
/// Bytes per data frame (`TBNET_FRAME_SIZE`); also the frame
/// size a frame-mode ring is programmed with (descriptor-count
/// register frame-size field 0 means 4096, `tb_ring_start`).
pub(crate) const FRAME_SIZE: usize = 4096;
/// First HopID a data ring may take (`TB_PATH_MIN_HOPID`, the
/// `nhi_alloc_hop` automatic-allocation floor; HopIDs below it
/// are reserved, with 0 the control channel).
pub(crate) const MIN_HOPID: u16 = 8;
/// TX HopID reserved as the E2E credit sink (`RING_E2E_UNUSED_HOPID`
/// in `nhi.c`); `tb_ring_alloc` refuses it for transmit rings.
const E2E_UNUSED_HOPID: u16 = 2;

// NHI register bases (`nhi_regs.h`): per-hop register blocks are
// 16 bytes in the ring bases and 32 bytes in the options bases.
const TX_RING_BASE: u64 = 0x00000;
const RX_RING_BASE: u64 = 0x08000;
const TX_OPTIONS_BASE: u64 = 0x19800;
const RX_OPTIONS_BASE: u64 = 0x29800;

// Descriptor dword 2 fields (`struct ring_desc`): length in bits
// 0..12, EOF PDF in bits 12..16, SOF PDF in bits 16..20, and the
// `ring_desc_flags` in bits 20..32.
const DESC_POSTED: u32 = 4 << 20;
const DESC_COMPLETED: u32 = 2 << 20;

// Ring options (`enum ring_flags` in `nhi_regs.h`).
const OPT_ENABLE: u32 = 1 << 31;
const OPT_E2E_FLOW_CONTROL: u32 = 1 << 28;
/// Shift of the E2E credit-sink HopID in RX options
/// (`REG_RX_OPTIONS_E2E_HOP_SHIFT`).
const E2E_HOP_SHIFT: u32 = 12;

/// RX options +4: the SOF/EOF PDF masks `tb_ring_start` programs
/// for a frame-mode receive ring — `sof_mask << 16 | eof_mask`
/// with `sof_mask = BIT(TBIP_PDF_FRAME_START)` and
/// `eof_mask = BIT(TBIP_PDF_FRAME_END)` from `tbnet_open`.
const RX_PDF_MASKS: u32 = ((1 << PDF_FRAME_START) << 16) | (1 << PDF_FRAME_END);

/// One peer's NHI data-ring pair: a frame-mode TX ring at
/// `tx_hop` and a frame-mode RX ring at `rx_hop`, with one 4 KiB
/// DMA buffer per descriptor slot (the reference driver's
/// per-frame page model). Ownership of the HopIDs themselves
/// stays with the control channel that allocated them; dropping
/// the pair stops the rings but does not release HopIDs.
#[derive(Debug)]
pub(crate) struct DataRingPair {
    bar: MmioRegion,
    tx_hop: u16,
    rx_hop: u16,
    tx_descriptors: ManuallyDrop<DmaBuffer>,
    rx_descriptors: ManuallyDrop<DmaBuffer>,
    tx_buffers: ManuallyDrop<Vec<DmaBuffer>>,
    rx_buffers: ManuallyDrop<Vec<DmaBuffer>>,
    tx_head: usize,
    tx_tail: usize,
    rx_head: usize,
    rx_tail: usize,
    running: bool,
    authority: Option<Cap<BusDeviceCap, Write>>,
    /// Frames posted to the TX ring.
    pub tx_frames: u64,
    /// Frames refused at the seam (ring stopped, full, or
    /// oversize, or the bus authority revoked): counted, never
    /// posted into a dead or full ring.
    pub tx_dropped: u64,
    /// Frames harvested from the RX ring.
    pub rx_frames: u64,
}

impl DataRingPair {
    /// # Safety
    /// Caller exclusively owns the NHI (the same contract as
    /// ring 0's constructor) and the two HopIDs for the life of
    /// the pair.
    pub(crate) unsafe fn new(
        bar: MmioRegion,
        nhi_hops: u16,
        tx_hop: u16,
        rx_hop: u16,
    ) -> Result<Self, Error> {
        // `tb_ring_alloc` validation: HopIDs are allocated from
        // the non-reserved range and must exist on this NHI; the
        // E2E credit-sink HopID is refused for transmit rings.
        // The BAR bound matches ring 0's (the options banks of
        // the highest ring must fit the validated aperture).
        if nhi_hops == 0
            || nhi_hops > 256
            || bar.len < 0x39948
            || tx_hop < MIN_HOPID
            || rx_hop < MIN_HOPID
            || tx_hop >= nhi_hops
            || rx_hop >= nhi_hops
            || tx_hop == E2E_UNUSED_HOPID
        {
            return Err(Error::Invalid);
        }
        let tx_descriptors =
            alloc_coherent(RING_SIZE * 16, DomainId::DRIVER_0).map_err(|_| Error::Allocation)?;
        let rx_descriptors =
            alloc_coherent(RING_SIZE * 16, DomainId::DRIVER_0).map_err(|_| Error::Allocation)?;
        let mut tx_buffers = Vec::with_capacity(RING_SIZE);
        let mut rx_buffers = Vec::with_capacity(RING_SIZE);
        for _ in 0..RING_SIZE {
            tx_buffers.push(
                alloc_coherent(FRAME_SIZE, DomainId::DRIVER_0).map_err(|_| Error::Allocation)?,
            );
            rx_buffers.push(
                alloc_coherent(FRAME_SIZE, DomainId::DRIVER_0).map_err(|_| Error::Allocation)?,
            );
        }
        Ok(Self {
            bar,
            tx_hop,
            rx_hop,
            tx_descriptors: ManuallyDrop::new(tx_descriptors),
            rx_descriptors: ManuallyDrop::new(rx_descriptors),
            tx_buffers: ManuallyDrop::new(tx_buffers),
            rx_buffers: ManuallyDrop::new(rx_buffers),
            tx_head: 0,
            tx_tail: 0,
            rx_head: RING_SIZE - 1,
            rx_tail: 0,
            running: false,
            authority: None,
            tx_frames: 0,
            tx_dropped: 0,
            rx_frames: 0,
        })
    }

    pub(crate) fn bind_authority(&mut self, cap: Option<Cap<BusDeviceCap, Write>>) {
        self.authority = cap;
    }

    fn tx_ring(&self) -> u64 {
        TX_RING_BASE + self.tx_hop as u64 * 16
    }
    fn rx_ring(&self) -> u64 {
        RX_RING_BASE + self.rx_hop as u64 * 16
    }
    fn tx_options(&self) -> u64 {
        TX_OPTIONS_BASE + self.tx_hop as u64 * 32
    }
    fn rx_options(&self) -> u64 {
        RX_OPTIONS_BASE + self.rx_hop as u64 * 32
    }

    fn write(&self, offset: u64, value: u32) {
        // SAFETY: register offsets are inside the validated BAR
        // and bounded by the constructor's HopID checks.
        unsafe { self.bar.write32(offset, value) };
    }
    fn read(&self, offset: u64) -> u32 {
        // SAFETY: as `write`.
        unsafe { self.bar.read32(offset) }
    }

    fn descriptors(&self, rx: bool) -> &DmaBuffer {
        if rx {
            &self.rx_descriptors
        } else {
            &self.tx_descriptors
        }
    }
    fn desc(&self, rx: bool, index: usize) -> *mut u32 {
        self.descriptors(rx)
            .cpu_mut_ptr_at::<u32>(index as u64 * 16)
    }
    fn flags(&self, rx: bool, index: usize) -> u32 {
        // SAFETY: indices are modulo RING_SIZE; dword 2 is the
        // device-updated status, read like ring 0's.
        let flags = unsafe { self.desc(rx, index).add(2).read_volatile() };
        if flags & DESC_COMPLETED != 0 {
            fence(Ordering::Acquire);
        }
        flags
    }

    /// Post one descriptor. The flags dword is written last,
    /// behind a release fence, exactly like ring 0's post and
    /// `ring_write_descriptors`: address, zero time dword, then
    /// the posted flags/length/PDF dword that hands the slot to
    /// the device.
    fn post(&self, rx: bool, index: usize, flags: u32) {
        let buffers = if rx {
            &self.rx_buffers
        } else {
            &self.tx_buffers
        };
        let address = buffers[index].dma_addr_at(0).raw();
        // SAFETY: software owns this slot until the head doorbell
        // is advanced past it.
        unsafe {
            let p = self.desc(rx, index);
            p.write_volatile(address as u32);
            p.add(1).write_volatile((address >> 32) as u32);
            p.add(3).write_volatile(0);
            p.add(2).write_volatile(flags);
        }
        fence(Ordering::Release);
    }

    /// Program and enable both rings (`tb_ring_start` for
    /// frame mode), priming the RX ring with `RING_SIZE - 1`
    /// posted buffers before the ENABLE writes so a frame can
    /// never arrive at an unprimed ring; the caller approves the
    /// in-router paths only after this returns.
    pub(crate) fn start(&mut self) {
        self.tx_head = 0;
        self.tx_tail = 0;
        self.rx_head = RING_SIZE - 1;
        self.rx_tail = 0;
        // Clear any stale enables before programming.
        self.write(self.tx_options(), 0);
        self.write(self.rx_options(), 0);
        let tx_desc = self.tx_descriptors.dma_addr_at(0).raw();
        self.write(self.tx_ring(), tx_desc as u32);
        self.write(self.tx_ring() + 4, (tx_desc >> 32) as u32);
        self.write(self.tx_ring() + 8, 0);
        self.write(self.tx_ring() + 12, RING_SIZE as u32);
        let rx_desc = self.rx_descriptors.dma_addr_at(0).raw();
        self.write(self.rx_ring(), rx_desc as u32);
        self.write(self.rx_ring() + 4, (rx_desc >> 32) as u32);
        self.write(self.rx_ring() + 8, 0);
        // Frame-size field 0 encodes 4096 in frame mode.
        self.write(self.rx_ring() + 12, RING_SIZE as u32);
        self.write(self.tx_options() + 4, 0);
        self.write(self.rx_options() + 4, RX_PDF_MASKS);
        // Leave one empty entry to distinguish full and empty.
        for index in 0..RING_SIZE - 1 {
            self.post(true, index, DESC_POSTED);
        }
        // TX: RING_FLAG_ENABLE alone (frame mode drops RAW).
        self.write(self.tx_options(), OPT_ENABLE);
        // RX: ENABLE | E2E_FLOW_CONTROL | credit-sink HopID.
        self.write(
            self.rx_options(),
            OPT_ENABLE | OPT_E2E_FLOW_CONTROL | (E2E_UNUSED_HOPID as u32) << E2E_HOP_SHIFT,
        );
        // Consumer doorbell: expose the primed RX buffers.
        self.write(self.rx_ring() + 8, self.rx_head as u32);
        self.running = true;
    }

    /// Disable both rings (`tb_ring_stop`, with ring 0's
    /// verification discipline): clear the options, confirm the
    /// ENABLE bits read back clear, then zero the descriptor
    /// registers. Returns whether the hardware acknowledged the
    /// stop; on `false` the caller must treat the DMA as live
    /// (the Drop impl quarantines it).
    pub(crate) fn stop(&mut self) -> bool {
        self.write(self.tx_options(), 0);
        self.write(self.rx_options(), 0);
        let stopped = self.read(self.tx_options()) & OPT_ENABLE == 0
            && self.read(self.rx_options()) & OPT_ENABLE == 0;
        if stopped {
            for base in [self.tx_ring(), self.rx_ring()] {
                for offset in [0, 4, 8, 12] {
                    self.write(base + offset, 0);
                }
            }
            self.write(self.tx_options() + 4, 0);
            self.write(self.rx_options() + 4, 0);
            let _ = self.read(self.rx_ring() + 12);
        }
        self.running = false;
        stopped
    }

    /// Submit one ThunderboltIP data frame to the TX ring.
    /// Refusals (ring stopped, frame oversize, ring full,
    /// authority revoked) are counted in `tx_dropped`; a frame
    /// is never posted into a dead or full ring.
    pub(crate) fn submit(&mut self, pdf: u8, frame: &[u8]) {
        let posted = if let Some(cap) = self.authority {
            cap.invoke(IoOp(|| self.submit_owned(pdf, frame)))
                .unwrap_or(false)
        } else {
            self.submit_owned(pdf, frame)
        };
        if !posted {
            self.tx_dropped += 1;
        }
    }

    fn submit_owned(&mut self, pdf: u8, frame: &[u8]) -> bool {
        if !self.running || frame.is_empty() || frame.len() > FRAME_SIZE {
            return false;
        }
        self.harvest_tx_completions();
        let next = (self.tx_head + 1) % RING_SIZE;
        if next == self.tx_tail {
            return false;
        }
        let out = self.tx_buffers[self.tx_head].cpu_mut_ptr::<u8>();
        // SAFETY: the slot is not posted; the frame length was
        // bounded by the buffer size above.
        unsafe { core::ptr::copy_nonoverlapping(frame.as_ptr(), out, frame.len()) };
        // Descriptor dword 2: length, EOF PDF, SOF PDF, POSTED —
        // the SOF/EOF fields carry the frame's PDF values (the
        // masks programmed in RX options key on the same values).
        let sof = (pdf & PDF_FRAME_START) as u32;
        let eof = (pdf & PDF_FRAME_END) as u32;
        let flags = DESC_POSTED | frame.len() as u32 | (eof << 12) | (sof << 16);
        self.post(false, self.tx_head, flags);
        self.tx_head = next;
        // Producer doorbell (head in the high half of +8).
        self.write(self.tx_ring() + 8, (next as u32) << 16);
        self.tx_frames += 1;
        true
    }

    /// Advance the TX tail past completed descriptors, freeing
    /// their slots (the completion half of `ring_work`).
    fn harvest_tx_completions(&mut self) {
        while self.tx_tail != self.tx_head && self.flags(false, self.tx_tail) & DESC_COMPLETED != 0
        {
            self.tx_tail = (self.tx_tail + 1) % RING_SIZE;
        }
    }

    /// Harvest every completed RX frame, in ring order,
    /// replenishing each consumed slot before advancing past it
    /// (ring 0's receive discipline). A frame-mode length of 0
    /// decodes as a full 4096-byte frame.
    pub(crate) fn harvest(&mut self) -> Vec<(u8, Vec<u8>)> {
        if let Some(cap) = self.authority {
            return cap
                .invoke(IoOp(|| self.harvest_owned()))
                .unwrap_or_default();
        }
        self.harvest_owned()
    }

    fn harvest_owned(&mut self) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        if !self.running {
            return out;
        }
        self.harvest_tx_completions();
        loop {
            let flags = self.flags(true, self.rx_tail);
            if flags & DESC_COMPLETED == 0 || flags & DESC_POSTED != 0 {
                break;
            }
            let raw_len = (flags & 0xfff) as usize;
            let len = if raw_len == 0 { FRAME_SIZE } else { raw_len };
            let mut bytes = alloc::vec![0u8; len];
            // SAFETY: the completed descriptor transfers this
            // bounded buffer to the CPU until it is reposted.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.rx_buffers[self.rx_tail].cpu_ptr_at::<u8>(0),
                    bytes.as_mut_ptr(),
                    len,
                );
            }
            let sof = (flags >> 16) & 15;
            let eof = (flags >> 12) & 15;
            let pdf = (if sof == PDF_FRAME_START as u32 {
                PDF_FRAME_START
            } else {
                0
            }) | (if eof == PDF_FRAME_END as u32 {
                PDF_FRAME_END
            } else {
                0
            });
            // Replenish the previously empty slot, then release
            // the consumed one (ring 0's repost order).
            self.post(true, self.rx_head, DESC_POSTED);
            self.rx_head = (self.rx_head + 1) % RING_SIZE;
            self.rx_tail = (self.rx_tail + 1) % RING_SIZE;
            self.write(self.rx_ring() + 8, self.rx_head as u32);
            self.rx_frames += 1;
            out.push((pdf, bytes));
        }
        out
    }
}

impl DataLink for DataRingPair {
    fn send_frame(&mut self, pdf: u8, frame: &[u8]) {
        self.submit(pdf, frame);
    }
    fn poll_frames(&mut self) -> Vec<(u8, Vec<u8>)> {
        self.harvest()
    }
}

impl Drop for DataRingPair {
    fn drop(&mut self) {
        // Mirror ring 0: a stop the hardware did not acknowledge
        // quarantines the DMA allocations rather than freeing
        // memory a wedged device may still write.
        if self.stop() {
            // SAFETY: both ring enables read back clear, so no
            // device write can target these allocations again.
            unsafe {
                ManuallyDrop::drop(&mut self.tx_buffers);
                ManuallyDrop::drop(&mut self.rx_buffers);
                ManuallyDrop::drop(&mut self.tx_descriptors);
                ManuallyDrop::drop(&mut self.rx_descriptors);
            }
        }
    }
}

/// The hop-allocation half of the binding, owned by the control
/// channel: NHI ring HopIDs are allocated per direction from the
/// non-reserved range, first free, exactly like `nhi_alloc_hop`
/// (ring 0 is outside the range, so it never collides).
#[derive(Debug, Default)]
pub(crate) struct HopAllocator {
    tx_used: [u64; 4],
    rx_used: [u64; 4],
}

impl HopAllocator {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Allocate the first free HopID in `MIN_HOPID..nhi_hops`
    /// for one direction. Transmit allocation also refuses the
    /// E2E credit-sink HopID, as `tb_ring_alloc` does (it is
    /// below the range floor today, but the rule is the
    /// reference's, not the range's).
    pub(crate) fn alloc(&mut self, nhi_hops: u16, tx: bool) -> Option<u16> {
        let used = if tx {
            &mut self.tx_used
        } else {
            &mut self.rx_used
        };
        let limit = nhi_hops.min(256);
        for hop in MIN_HOPID..limit {
            if tx && hop == E2E_UNUSED_HOPID {
                continue;
            }
            let bit = 1u64 << (hop % 64);
            if used[(hop / 64) as usize] & bit == 0 {
                used[(hop / 64) as usize] |= bit;
                return Some(hop);
            }
        }
        None
    }

    pub(crate) fn free(&mut self, hop: u16, tx: bool) {
        let used = if tx {
            &mut self.tx_used
        } else {
            &mut self.rx_used
        };
        if hop < 256 {
            used[(hop / 64) as usize] &= !(1u64 << (hop % 64));
        }
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// A fake NHI: the BAR is a dword array the test inspects,
    /// and the model's "hardware" completes descriptors by
    /// writing their flags dword, exactly where ring 0's fixture
    /// puts its model.
    #[derive(Debug)]
    struct FakeNhi {
        mmio: Vec<u32>,
    }

    impl FakeNhi {
        fn new() -> Self {
            Self {
                mmio: alloc::vec![0u32; 0x3a000 / 4],
            }
        }
        fn bar(&mut self) -> MmioRegion {
            MmioRegion {
                phys: narf_memory::PhysAddr::new(0),
                virt: self.mmio.as_mut_ptr() as u64,
                len: 0x3a000,
                kind: narf_bus::BarKind::Mmio32 {
                    prefetchable: false,
                },
            }
        }
        fn reg(&self, offset: u64) -> u32 {
            self.mmio[(offset / 4) as usize]
        }
    }

    fn make_pair(fake: &mut FakeNhi, tx_hop: u16, rx_hop: u16) -> Option<DataRingPair> {
        // SAFETY: the model owns the backing array; all DMA
        // buffers are real coherent allocations only this test
        // and the pair touch.
        unsafe { DataRingPair::new(fake.bar(), 32, tx_hop, rx_hop) }.ok()
    }

    fn desc_flags(pair: &DataRingPair, rx: bool, index: usize) -> u32 {
        // SAFETY: the test owns the pair's descriptors.
        unsafe { pair.desc(rx, index).add(2).read_volatile() }
    }
    fn desc_addr(pair: &DataRingPair, rx: bool, index: usize) -> u64 {
        // SAFETY: as above.
        unsafe {
            let p = pair.desc(rx, index);
            (p.read_volatile() as u64) | ((p.add(1).read_volatile() as u64) << 32)
        }
    }

    fn usb4_data_ring_start_programs_frame_mode() -> TestResult {
        let mut fake = FakeNhi::new();
        let Some(mut pair) = make_pair(&mut fake, 8, 9) else {
            return TestResult::Fail("pair allocation");
        };
        // Hop validation: reserved and out-of-range HopIDs are
        // refused like tb_ring_alloc refuses them.
        if make_pair(&mut fake, 0, 9).is_some()
            || make_pair(&mut fake, 8, 32).is_some()
            || make_pair(&mut fake, 2, 9).is_some()
        {
            return TestResult::Fail("reserved/out-of-range HopID accepted");
        }
        pair.start();
        let tx_ring = TX_RING_BASE + 8 * 16;
        let rx_ring = RX_RING_BASE + 9 * 16;
        let tx_opt = TX_OPTIONS_BASE + 8 * 32;
        let rx_opt = RX_OPTIONS_BASE + 9 * 32;
        let tx_desc_addr = pair.tx_descriptors.dma_addr_at(0).raw();
        let rx_desc_addr = pair.rx_descriptors.dma_addr_at(0).raw();
        if fake.reg(tx_ring) != tx_desc_addr as u32
            || fake.reg(tx_ring + 4) != (tx_desc_addr >> 32) as u32
            || fake.reg(tx_ring + 12) != RING_SIZE as u32
            || fake.reg(rx_ring) != rx_desc_addr as u32
            || fake.reg(rx_ring + 12) != RING_SIZE as u32
        {
            return TestResult::Fail("descriptor base/count registers");
        }
        // TX options: ENABLE alone (frame mode). RX options:
        // ENABLE | E2E_FLOW_CONTROL | credit sink HopID 2 at
        // shift 12; RX options +4 carries the PDF masks.
        if fake.reg(tx_opt) != OPT_ENABLE
            || fake.reg(tx_opt + 4) != 0
            || fake.reg(rx_opt) != OPT_ENABLE | OPT_E2E_FLOW_CONTROL | (2 << 12)
            || fake.reg(rx_opt + 4) != RX_PDF_MASKS
        {
            return TestResult::Fail("options registers");
        }
        // The RX ring is primed: RING_SIZE - 1 buffers posted,
        // the last slot left empty, consumer doorbell at the
        // empty slot; TX descriptors are untouched.
        for index in 0..RING_SIZE - 1 {
            if desc_flags(&pair, true, index) != DESC_POSTED
                || desc_addr(&pair, true, index) != pair.rx_buffers[index].dma_addr_at(0).raw()
            {
                return TestResult::Fail("RX ring not primed");
            }
        }
        if desc_flags(&pair, true, RING_SIZE - 1) != 0
            || fake.reg(rx_ring + 8) != (RING_SIZE - 1) as u32
            || desc_flags(&pair, false, 0) != 0
        {
            return TestResult::Fail("RX priming boundary / TX touched");
        }
        if !pair.stop() {
            return TestResult::Fail("stop not acknowledged by the model");
        }
        if fake.reg(tx_opt) != 0
            || fake.reg(rx_opt) != 0
            || fake.reg(tx_ring) != 0
            || fake.reg(rx_ring) != 0
            || fake.reg(rx_ring + 12) != 0
        {
            return TestResult::Fail("stopped rings retained registers");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/thunderbolt/dataring",
        usb4_data_ring_start_programs_frame_mode
    );

    fn usb4_data_ring_tx_byte_for_byte_and_refusals() -> TestResult {
        let mut fake = FakeNhi::new();
        let Some(mut pair) = make_pair(&mut fake, 8, 8) else {
            return TestResult::Fail("pair allocation");
        };
        // Refusal before start: counted, nothing posted.
        pair.submit(3, &[1, 2, 3]);
        if pair.tx_dropped != 1 || pair.tx_frames != 0 {
            return TestResult::Fail("submit into a stopped ring was not refused");
        }
        pair.start();
        let frame: Vec<u8> = (0..100u32).map(|i| (i * 7 + 3) as u8).collect();
        pair.submit(PDF_FRAME_START | PDF_FRAME_END, &frame);
        // Descriptor 0, byte-for-byte: buffer address, time 0,
        // and dword 2 = POSTED | length 100 | EOF PDF 2 at
        // bits 12..16 | SOF PDF 1 at bits 16..20.
        let want_flags = DESC_POSTED | 100 | (2 << 12) | (1 << 16);
        if desc_flags(&pair, false, 0) != want_flags
            || desc_addr(&pair, false, 0) != pair.tx_buffers[0].dma_addr_at(0).raw()
        {
            return TestResult::Fail("TX descriptor 0 differs from the frame-mode layout");
        }
        // SAFETY: the test owns slot 0's buffer until the model
        // completes it.
        let payload_ok = unsafe {
            let p = pair.tx_buffers[0].cpu_ptr_at::<u8>(0);
            (0..100).all(|i| *p.add(i) == frame[i])
        };
        let tx_ring = TX_RING_BASE + 8 * 16;
        if !payload_ok || fake.reg(tx_ring + 8) != 1 << 16 || pair.tx_frames != 1 {
            return TestResult::Fail("TX payload copy or producer doorbell");
        }
        // Oversize frames are refused and counted.
        let big = alloc::vec![0u8; FRAME_SIZE + 1];
        pair.submit(3, &big);
        if pair.tx_dropped != 2 || desc_flags(&pair, false, 1) != 0 {
            return TestResult::Fail("oversize frame was posted");
        }
        // Fill the ring: 255 frames in flight (one slot stays
        // empty). Completing slot 0 frees exactly one more.
        for _ in 1..RING_SIZE - 1 {
            pair.submit(3, &[9u8; 16]);
        }
        if pair.tx_frames != (RING_SIZE - 1) as u64 {
            return TestResult::Fail("ring did not fill to capacity");
        }
        pair.submit(3, &[9u8; 16]);
        if pair.tx_dropped != 3 {
            return TestResult::Fail("submit into a full ring was not refused");
        }
        // SAFETY: the model completes descriptor 0.
        unsafe {
            pair.desc(false, 0).add(2).write_volatile(DESC_COMPLETED);
        }
        pair.submit(3, &[9u8; 16]);
        if pair.tx_frames != RING_SIZE as u64 || pair.tx_dropped != 3 {
            return TestResult::Fail("TX completion did not free a slot");
        }
        // Stop refuses further submits.
        if !pair.stop() {
            return TestResult::Fail("stop not acknowledged");
        }
        pair.submit(3, &[1]);
        if pair.tx_dropped != 4 {
            return TestResult::Fail("submit after stop was not refused");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/thunderbolt/dataring",
        usb4_data_ring_tx_byte_for_byte_and_refusals
    );

    fn usb4_data_ring_rx_completion_harvest() -> TestResult {
        let mut fake = FakeNhi::new();
        let Some(mut pair) = make_pair(&mut fake, 8, 8) else {
            return TestResult::Fail("pair allocation");
        };
        pair.start();
        // The model delivers a 64-byte frame into RX slot 0:
        // payload bytes in the buffer, completion dword with
        // length, SOF/EOF PDFs, POSTED clear.
        let frame: Vec<u8> = (0..64u32).map(|i| (i * 5 + 1) as u8).collect();
        // SAFETY: slot 0 is posted and owned by the model until
        // it marks the descriptor completed.
        unsafe {
            let p = pair.rx_buffers[0].cpu_mut_ptr::<u8>();
            core::ptr::copy_nonoverlapping(frame.as_ptr(), p, frame.len());
            pair.desc(true, 0)
                .add(2)
                .write_volatile(DESC_COMPLETED | 64 | (2 << 12) | (1 << 16));
        }
        let got = pair.harvest();
        if got.len() != 1 || got[0] != (PDF_FRAME_START | PDF_FRAME_END, frame) {
            return TestResult::Fail("RX completion did not harvest the frame");
        }
        // The consumed slot's replacement was posted into the
        // previously empty slot (RING_SIZE - 1) and the consumer
        // doorbell now points at slot 0, the new empty slot.
        let rx_ring = RX_RING_BASE + 8 * 16;
        if desc_flags(&pair, true, RING_SIZE - 1) != DESC_POSTED
            || desc_addr(&pair, true, RING_SIZE - 1)
                != pair.rx_buffers[RING_SIZE - 1].dma_addr_at(0).raw()
            || fake.reg(rx_ring + 8) != 0
            || pair.rx_frames != 1
        {
            return TestResult::Fail("RX repost/doorbell discipline");
        }
        // A full-size frame: length field 0 decodes as 4096.
        let big: Vec<u8> = (0..FRAME_SIZE as u32).map(|i| (i % 253) as u8).collect();
        // SAFETY: slot 1 is the next posted slot in ring order.
        unsafe {
            let p = pair.rx_buffers[1].cpu_mut_ptr::<u8>();
            core::ptr::copy_nonoverlapping(big.as_ptr(), p, big.len());
            pair.desc(true, 1)
                .add(2)
                .write_volatile(DESC_COMPLETED | (2 << 12) | (1 << 16));
        }
        let got = pair.harvest();
        if got.len() != 1 || got[0].1 != big || got[0].0 != PDF_FRAME_START | PDF_FRAME_END {
            return TestResult::Fail("zero-length completion did not decode as 4096");
        }
        // A descriptor still marked POSTED is not a completion:
        // nothing is harvested and the tail does not move.
        // SAFETY: slot 2 is next; mark it completed-but-posted.
        unsafe {
            pair.desc(true, 2)
                .add(2)
                .write_volatile(DESC_COMPLETED | DESC_POSTED | 16);
        }
        if !pair.harvest().is_empty() || pair.rx_frames != 2 {
            return TestResult::Fail("posted descriptor harvested as a completion");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/thunderbolt/dataring",
        usb4_data_ring_rx_completion_harvest
    );

    fn usb4_data_ring_pairs_are_independent() -> TestResult {
        let mut fake = FakeNhi::new();
        let Some(mut a) = make_pair(&mut fake, 8, 8) else {
            return TestResult::Fail("pair A allocation");
        };
        let Some(mut b) = make_pair(&mut fake, 9, 9) else {
            return TestResult::Fail("pair B allocation");
        };
        a.start();
        b.start();
        a.submit(3, &[0xa5u8; 32]);
        // Only A's hop-8 registers and descriptors moved.
        if fake.reg(TX_RING_BASE + 8 * 16 + 8) != 1 << 16
            || fake.reg(TX_RING_BASE + 9 * 16 + 8) != 0
            || desc_flags(&b, false, 0) != 0
            || b.tx_frames != 0
        {
            return TestResult::Fail("pairs share ring state");
        }
        // The hop allocator hands out first-free per direction
        // and recycles freed HopIDs.
        let mut hops = HopAllocator::new();
        let first = hops.alloc(32, true);
        let second = hops.alloc(32, true);
        let rx_first = hops.alloc(32, false);
        if first != Some(8) || second != Some(9) || rx_first != Some(8) {
            return TestResult::Fail("hop allocation is not first-free per direction");
        }
        hops.free(8, true);
        if hops.alloc(32, true) != Some(8) {
            return TestResult::Fail("freed HopID was not recycled");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/thunderbolt/dataring",
        usb4_data_ring_pairs_are_independent
    );
}

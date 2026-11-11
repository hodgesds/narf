//! PCI backend for x86_64 and aarch64.
//! Linux reference: ecd997b0189a mt792x_dma.c.
//!
//! Descriptor rings and frame buffers are allocated with
//! `narf_io::alloc_coherent_for` against the function's firmware DMA
//! configuration (`narf_bus::dma::configure`, Linux `dma_alloc_coherent`):
//! write-back RAM on a snooping interconnect, the device's reserved
//! non-cacheable pool on a non-coherent one, and refusal otherwise.
use super::{
    Backend, CapturedData, Error, Firmware, RadioInfo, Report, Retained, Session, State, MAX_FRAME,
};
use crate::mt7921::{packet_tx, registers, regs::*};
use alloc::{collections::VecDeque, sync::Arc, vec, vec::Vec};
#[cfg(not(target_arch = "aarch64"))]
use core::sync::atomic::fence;
use core::sync::atomic::Ordering;
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_io::DmaBuffer;

#[path = "ap_timing.rs"]
mod ap_timing;
#[path = "p2p_management_hw.rs"]
mod p2p_management;

#[path = "wowlan_hardware.rs"]
mod wake;

// A CPU atomic fence is inner-shareable on ARM. Device ownership also needs
// the outer-shareable domain used by PCI DMA (Linux dma_rmb/dma_wmb).
fn dma_barrier() {
    #[cfg(target_arch = "aarch64")]
    {
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        // SAFETY: DMB only orders accesses; no register or memory operand.
        unsafe {
            core::arch::asm!("dmb osh", options(nostack, preserves_flags));
        }
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
    }
    #[cfg(not(target_arch = "aarch64"))]
    fence(Ordering::SeqCst);
}

const DEPTH: usize = packet_tx::RING_SLOTS;
const GLOBAL: u32 = 0xd4208;
const BUSY: u32 = 0xa;
const ENABLE: u32 = 5;
const OMIT: u32 = (1 << 15) | (1 << 21) | (1 << 27) | (1 << 28);
const DONE: u32 = 1 << 31;
const LAST: u32 = 1 << 30;
const TX_FWDL: u32 = 0xd4300 + 16 * 16;
const TX_WM: u32 = 0xd4300 + 17 * 16;
const RX_PRE: u32 = 0xd4500;
const RX_POST: u32 = 0xd4540;
const RX_DATA: u32 = 0xd4520;
const TX_DATA: u32 = 0xd4300;
/// `MT_WFDMA_DUMMY_CR` / `MT_WFDMA_NEED_REINIT`, set by every DMA enable.
const WFDMA_DUMMY_CR: u32 = 0x54000120;
const WFDMA_NEED_REINIT: u32 = 1 << 1;

#[derive(Debug)]
struct Ring {
    descriptors: DmaBuffer,
    buffers: Vec<DmaBuffer>,
    index: usize,
    pending: bool,
    base: u32,
}
impl Ring {
    /// [`Self::allocate_for`] on a coherent device.
    fn allocate(base: u32, rx: bool) -> Result<Self, Error> {
        Self::allocate_for(&narf_io::DmaDevice::coherent(), base, rx)
    }
    /// Linux `mt76_dma_alloc_queue`: descriptors and per-slot frame buffers
    /// from `dma_alloc_coherent(dev, …)`. The device writes DONE bits into
    /// 16-byte descriptors that share cache lines, so a non-coherent device
    /// must get its reserved non-cacheable pool; without one this fails.
    fn allocate_for(dma: &narf_io::DmaDevice, base: u32, rx: bool) -> Result<Self, Error> {
        let descriptors = narf_io::alloc_coherent_for(
            dma,
            DEPTH * 16,
            narf_lib::id::DomainId::DRIVER_0,
            u64::from(u32::MAX),
        )
        .map_err(|_| Error::Allocation)?;
        // Hardware descriptor-base registers have no upper-address field.
        if descriptors
            .dma_addr()
            .raw()
            .checked_add((DEPTH * 16 - 1) as u64)
            .is_none_or(|end| end > u64::from(u32::MAX))
        {
            return Err(Error::DmaAddress);
        }
        let mut buffers = Vec::with_capacity(DEPTH);
        for _ in 0..DEPTH {
            // Behind a per-domain IOMMU every mapping honours the function's
            // streaming mask, `dma_set_mask(&pdev->dev, DMA_BIT_MASK(32))`
            // (mt7921/pci.c:mt7921_pci_probe). Identity keeps the 36-bit
            // descriptor address reach for non-data rings.
            let mask = if base == TX_DATA || dma.iommu_domain().is_some() {
                u64::from(u32::MAX)
            } else {
                (1u64 << 36) - 1
            };
            let buffer =
                narf_io::alloc_coherent_for(dma, MAX_FRAME, narf_lib::id::DomainId::DRIVER_0, mask)
                    .map_err(|_| Error::Allocation)?;
            if buffer
                .dma_addr()
                .raw()
                .checked_add((MAX_FRAME - 1) as u64)
                .is_none_or(|end| end >= 1 << 36)
            {
                return Err(Error::DmaAddress);
            }
            buffers.push(buffer);
        }
        let ring = Self {
            descriptors,
            buffers,
            index: 0,
            pending: false,
            base,
        };
        for index in 0..DEPTH {
            if rx {
                ring.arm_rx(index);
            } else {
                ring.set_word(index, 1, DONE);
            }
        }
        Ok(ring)
    }
    fn word(&self, slot: usize, word: usize) -> u32 {
        // SAFETY: fixed descriptor geometry; coherent device-owned field sampled volatile.
        u32::from_le(unsafe {
            self.descriptors
                .cpu_ptr::<u32>()
                .add(slot * 4 + word)
                .read_volatile()
        })
    }
    fn set_word(&self, slot: usize, word: usize, value: u32) {
        // SAFETY: fixed geometry; caller owns this descriptor or has stopped DMA.
        unsafe {
            self.descriptors
                .cpu_mut_ptr::<u32>()
                .add(slot * 4 + word)
                .write_volatile(value.to_le())
        };
    }
    fn arm_rx(&self, slot: usize) {
        let address = self.buffers[slot].dma_addr().raw();
        self.set_word(slot, 0, address as u32);
        self.set_word(slot, 2, 0); // buf1 is a second segment, NOT address-high bits.
        self.set_word(slot, 3, (address >> 32) as u32 & 15);
        self.set_word(slot, 1, (MAX_FRAME as u32) << 16);
    }
}
#[derive(Debug)]
struct Storage {
    wm: Ring,
    fwdl: Ring,
    rx: [Ring; 3],
    data: Ring,
    data_dma: usize,
    tokens: packet_tx::Tokens,
    tx_sequence: crate::mt7921::tx_sequence::Owner,
    pending_events: VecDeque<Vec<u8>>,
    pending_data: VecDeque<CapturedData>,
    receive_epoch: u64,
    receive_open: bool,
    p2p_capture: super::p2p_management_capture::Queue,
}
impl Storage {
    // Caller has proved device quiescence and retired every hardware ring reference.
    fn recycle(&mut self) {
        for ring in [&mut self.wm, &mut self.fwdl, &mut self.data] {
            ring.index = 0;
            ring.pending = false;
            for slot in 0..DEPTH {
                for word in 0..4 {
                    ring.set_word(slot, word, 0);
                }
                ring.set_word(slot, 1, DONE);
            }
            for buffer in &mut ring.buffers {
                buffer.as_mut_slice().fill(0);
            }
        }
        for ring in &mut self.rx {
            ring.index = 0;
            ring.pending = false;
            for slot in 0..DEPTH {
                ring.arm_rx(slot);
            }
        }
        self.tokens = packet_tx::Tokens::new();
        self.tx_sequence.clear_after_quiescence();
        self.data_dma = 0;
        self.pending_events.clear();
        self.pending_data.clear();
        self.receive_epoch = 0;
        self.receive_open = false;
        self.p2p_capture.close();
        dma_barrier();
    }
}
/// IOMMU requester ID of `device`; `narf_bus::dma::configure` attaches
/// only PCI segment 0 functions to a default domain.
fn iommu_bdf(device: &BusDevice) -> Option<narf_io::iommu::Bdf> {
    match device.kind {
        narf_bus::BusKind::Pcie { addr, .. } if addr.segment == 0 => Some(
            narf_io::iommu::Bdf::new(addr.bus, addr.device, addr.function),
        ),
        _ => None,
    }
}
/// Re-attach a function blocked by an earlier generation's stop/reset to
/// its retained default domain before the first allocation (Linux
/// `pci_dev_reset_iommu_done`). The caller holds the stop proof: bus
/// mastering verified off and exclusive device ownership. A no-op outside
/// `PerDomain` and for a function that is not blocked.
fn restore_function_dma(device: &BusDevice) -> Result<(), Error> {
    if narf_io::iommu::mode() != narf_io::iommu::IommuMode::PerDomain {
        return Ok(());
    }
    let bdf = iommu_bdf(device).ok_or(Error::Allocation)?;
    if !narf_io::iommu::device_dma_blocked(bdf) {
        return Ok(());
    }
    narf_io::iommu::restore_device_dma(bdf).map_err(|_| Error::Authority)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SequenceReset {
    None,
    Asserted,
    Released,
    Ready,
}
#[derive(Debug)]
struct Hardware {
    mmio: MmioRegion,
    device: BusDevice,
    authority: Cap<BusDeviceCap, Write>,
    owner: Retained<Storage>,
    /// Linux `wcid->amsdu` for the station peer (TXD7 HW_AMSDU).
    hw_amsdu: bool,
    sequence_reset: SequenceReset,
    wake: wake::Wake,
}
impl Drop for Hardware {
    /// An owner dropped while its rings are still published (dead firmware,
    /// a failed stop or recovery, unproven removal) never proved the device
    /// stopped. Behind a per-domain IOMMU the blocking detach is that proof
    /// (Linux: the blocked release domain, then `iommu_dma_free`), so the
    /// rings are freed with strict invalidation; otherwise
    /// `Retained` keeps them forever, exactly as before.
    fn drop(&mut self) {
        let _ = self.block_for_reclaim();
    }
}
impl Hardware {
    /// Block the function's DMA at its IOMMU (Linux
    /// `pci_dev_reset_iommu_prepare`). Deliberately ungated by the
    /// firmware/BAR proof: a dead or revoked generation must still be
    /// blockable. Outside `PerDomain` this is `Untranslated` and touches no
    /// hardware; the device-side evidence is then the only proof.
    fn block_dma(&self) -> Result<narf_io::iommu::DmaBlock, Error> {
        if narf_io::iommu::mode() != narf_io::iommu::IommuMode::PerDomain {
            return Ok(narf_io::iommu::DmaBlock::Untranslated);
        }
        let bdf = iommu_bdf(&self.device).ok_or(Error::Authority)?;
        // A detach timeout means the device may still translate.
        narf_io::iommu::block_device_dma(bdf).map_err(|_| Error::Timeout)
    }
    /// Re-attach the retained default domain before rings are published
    /// again (Linux `pci_dev_reset_iommu_done`). Only the holder of the
    /// stop/reset proof calls this: `initialize` after its idle proof.
    fn restore_dma(&self) -> Result<(), Error> {
        restore_function_dma(&self.device)
    }
    /// Unpublish after the device-side stop proof (DMA disabled and idle,
    /// bus mastering off, ring bases cleared). Under `PerDomain` the
    /// function is blocked first, so every later free of these rings
    /// follows a completed blocking detach.
    fn unpublish(&mut self) -> Result<(), Error> {
        self.block_dma()?;
        self.owner.published = false;
        Ok(())
    }
    /// Drop path for a still-published owner: true when the IOMMU block
    /// completed and the rings may be freed.
    fn block_for_reclaim(&mut self) -> bool {
        if !self.owner.published || self.owner.storage.is_none() {
            return false;
        }
        if self.block_dma() != Ok(narf_io::iommu::DmaBlock::Blocked) {
            return false;
        }
        self.owner.published = false;
        true
    }
    fn receive_ring(&mut self, which: usize) -> Result<Option<Vec<u8>>, Error> {
        self.check()?;
        let storage = self.owner.storage.as_ref().ok_or(Error::Busy)?;
        let ring = &storage.rx[which];
        let didx = self.read(ring.base + 12)? as usize;
        if didx >= DEPTH {
            return Err(Error::Ring);
        }
        if didx == ring.index {
            return Ok(None);
        }
        dma_barrier();
        let ctrl = ring.word(ring.index, 1);
        let len = ((ctrl >> 16) & 0x3fff) as usize;
        if ctrl & (DONE | LAST) != (DONE | LAST) || !(8..=MAX_FRAME).contains(&len) {
            return Err(Error::MalformedEvent);
        }
        dma_barrier(); // device payload writes precede observed DDONE
        let mut frame = vec![0u8; len];
        // SAFETY: completion/length verified; copy before returning buffer to DMA.
        unsafe {
            core::ptr::copy_nonoverlapping(
                ring.buffers[ring.index].cpu_ptr::<u8>(),
                frame.as_mut_ptr(),
                len,
            )
        };
        let rxd = u32::from_le_bytes(frame[..4].try_into().map_err(|_| Error::MalformedEvent)?);
        let packet_len = (rxd & 0xffff) as usize;
        if !(8..=len).contains(&packet_len) {
            return Err(Error::MalformedEvent);
        }
        frame.truncate(packet_len);
        let slot = ring.index;
        ring.arm_rx(slot);
        dma_barrier();
        let base = ring.base;
        self.write(base + 8, slot as u32)?;
        self.owner.storage.as_mut().ok_or(Error::Busy)?.rx[which].index = (slot + 1) % DEPTH;
        Ok(Some(frame))
    }
    fn route_rx(&mut self, event: Option<bool>) -> Result<Option<CapturedData>, Error> {
        self.check()?;
        let storage = self.owner.storage.as_mut().ok_or(Error::Busy)?;
        if let Some(packet) = match event {
            Some(true) => storage
                .pending_events
                .pop_front()
                .map(|bytes| CapturedData {
                    bytes,
                    epoch: 0,
                    port_open: false,
                }),
            Some(false) => storage.pending_data.pop_front(),
            None => None,
        } {
            return Ok(Some(packet));
        }
        for which in 0..3 {
            let Some(packet) = self.receive_ring(which)? else {
                continue;
            };
            if let Some(packet) = self.route_packet(packet, event)? {
                return Ok(Some(packet));
            }
            // TX-status and unknown reports do not satisfy a command waiter.
        }
        Ok(None)
    }

    fn route_packet(
        &mut self,
        bytes: Vec<u8>,
        event: Option<bool>,
    ) -> Result<Option<CapturedData>, Error> {
        let now = self.now_ns();
        let rxd = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        let kind = rxd >> 27;
        let normal = kind == 2 || kind == 7 && (rxd >> 16) & 15 == 1;
        let storage = self.owner.storage.as_mut().ok_or(Error::Busy)?;
        if kind == 0 {
            storage
                .tokens
                .firmware_done(&packet_tx::releases(&bytes)?)?;
        } else if kind == 1 {
            storage.tx_sequence.receive(&bytes)?;
        } else if normal {
            storage.p2p_capture.copy(&bytes, now);
            let packet = CapturedData {
                bytes,
                epoch: storage.receive_epoch,
                port_open: storage.receive_open,
            };
            if event == Some(false) {
                return Ok(Some(packet));
            }
            if storage.pending_data.len() == 32 {
                storage.pending_data.pop_front(); // bounded RX loss under overload
            }
            storage.pending_data.push_back(packet);
        } else if kind == 7 {
            if bytes.len() < 32 {
                return Err(Error::MalformedEvent);
            }
            if event == Some(true) {
                return Ok(Some(CapturedData {
                    bytes,
                    epoch: 0,
                    port_open: false,
                }));
            }
            if storage.pending_events.len() == 32 {
                return Err(Error::EventOverflow);
            }
            storage.pending_events.push_back(bytes);
        }
        Ok(None)
    }

    fn open_receive_capture(&mut self, epoch: u64) -> Result<(), Error> {
        self.check()?;
        let storage = self.owner.storage.as_ref().ok_or(Error::Busy)?;
        if epoch == 0 || epoch != storage.receive_epoch {
            return Err(Error::Busy);
        }
        if storage.receive_open {
            return Ok(());
        }
        // Snapshot the finite completed prefix on all actual RX rings. Copies
        // made while waiting for key/port receipts and this prefix keep their
        // original closed admission facts. New arrivals do not extend the cut.
        let mut cuts = [0; 3];
        for (which, ring) in storage.rx.iter().enumerate() {
            cuts[which] = self.read(ring.base + 12)? as usize;
            if cuts[which] >= DEPTH {
                return Err(Error::Ring);
            }
        }
        for (which, cut) in cuts.into_iter().enumerate() {
            for _ in 0..DEPTH {
                if self.owner.storage.as_ref().ok_or(Error::Busy)?.rx[which].index == cut {
                    break;
                }
                let packet = self.receive_ring(which)?.ok_or(Error::Ring)?;
                let _ = self.route_packet(packet, None)?;
            }
            if self.owner.storage.as_ref().ok_or(Error::Busy)?.rx[which].index != cut {
                return Err(Error::Ring);
            }
        }
        self.check()?;
        self.owner.storage.as_mut().ok_or(Error::Busy)?.receive_open = true;
        Ok(())
    }

    // Private until association supplies a verified transmit-capable channel.
    fn submit_management(
        &mut self,
        vif: crate::mt7921::vif_slots::Vif,
        frame: &[u8],
        wcid: u16,
        rate: crate::mt7921::association::LegacyRate,
    ) -> Result<(), Error> {
        self.submit_80211(frame, None, |payload, token| {
            let mut header = packet_tx::management(frame, payload, token, wcid, rate)?;
            packet_tx::on_vif(&mut header, vif)?;
            Ok(header)
        })
    }
    fn submit_fragment(
        &mut self,
        link: crate::mt7921::vif_slots::Link,
        frame: &[u8],
    ) -> Result<(), Error> {
        // A final real QoS fragment has the actual MSDU sequence. Every
        // predecessor already retired in the serialized fragment owner.
        let sample_tid = if frame.first() == Some(&0x88)
            && frame.get(1).is_some_and(|flags| flags & 4 == 0)
            && frame.get(22).is_some_and(|sc| sc & 15 != 0)
        {
            frame.get(24).map(|tid| tid & 7)
        } else {
            None
        };
        // The armed sample owner is the home peer's (`arm` = WCID 1).
        let sample_tid = sample_tid.filter(|_| link == crate::mt7921::vif_slots::Link::HOME);
        self.submit_80211(frame, sample_tid, |payload, token| {
            let mut header = packet_tx::fragment(frame, payload, token, link.peer().into())?;
            packet_tx::on_vif(&mut header, link.vif())?;
            Ok(header)
        })
    }
    /// Publish one native 802.11 MPDU with the TXD `encode` builds for its
    /// DMA payload address and token.
    fn submit_80211(
        &mut self,
        frame: &[u8],
        sample_tid: Option<u8>,
        encode: impl FnOnce(u64, u16) -> Result<[u8; packet_tx::HEADER], Error>,
    ) -> Result<(), Error> {
        self.check()?;
        if !self.owner.published {
            return Err(Error::Busy);
        }
        let storage = self.owner.storage.as_ref().ok_or(Error::Busy)?;
        let token = storage.tokens.available()?;
        let sample_pid = match sample_tid {
            Some(tid) => storage.tx_sequence.pid(tid)?,
            None => None,
        };
        let ring = &storage.data;
        let slot = ring.index;
        if ring.pending || ring.word(slot, 1) & DONE == 0 {
            return Err(Error::Busy);
        }
        let address = ring.buffers[slot].dma_addr().raw();
        let payload = address
            .checked_add(packet_tx::HEADER as u64)
            .ok_or(Error::DmaAddress)?;
        let mut header = encode(payload, token)?;
        if let Some(pid) = sample_pid {
            crate::mt7921::tx_sequence::request(&mut header, pid)?;
        }
        // SAFETY: fully validated lengths; this slot has neither DMA nor
        // firmware ownership until the publication below.
        unsafe {
            core::ptr::copy_nonoverlapping(
                header.as_ptr(),
                ring.buffers[slot].cpu_mut_ptr::<u8>(),
                header.len(),
            );
            core::ptr::copy_nonoverlapping(
                frame.as_ptr(),
                ring.buffers[slot].cpu_mut_ptr::<u8>().add(header.len()),
                frame.len(),
            );
        }
        let storage = self.owner.storage.as_mut().ok_or(Error::Busy)?;
        storage.tokens.begin_at(token, slot)?;
        if sample_pid.is_some() {
            storage.tx_sequence.begin(sample_tid.unwrap(), token)?;
        }
        let ring = &mut storage.data;
        ring.pending = true; // conservative on any later doorbell failure
        ring.index = (slot + 1) % DEPTH;
        ring.set_word(slot, 0, address as u32);
        ring.set_word(slot, 2, 0);
        ring.set_word(slot, 3, (address >> 32) as u32 & 15);
        dma_barrier();
        ring.set_word(slot, 1, ((packet_tx::HEADER as u32) << 16) | LAST);
        dma_barrier();
        self.write(TX_DATA + 8, ((slot + 1) % DEPTH) as u32)
    }
    fn submit_data(
        &mut self,
        link: crate::mt7921::vif_slots::Link,
        frame: &[u8],
        protected: bool,
        qos: bool,
    ) -> Result<(), Error> {
        self.submit_data_mode(link, frame, protected, qos, false)
    }
    fn submit_data_mode(
        &mut self,
        link: crate::mt7921::vif_slots::Link,
        frame: &[u8],
        protected: bool,
        qos: bool,
        pipelined: bool,
    ) -> Result<(), Error> {
        self.submit_data_profile(link, frame, protected, qos, pipelined, false)
    }
    fn submit_data_profile(
        &mut self,
        link: crate::mt7921::vif_slots::Link,
        frame: &[u8],
        protected: bool,
        qos: bool,
        pipelined: bool,
        aggregated: bool,
    ) -> Result<(), Error> {
        self.submit_data_txd(link, frame, protected, qos, pipelined, aggregated, 0)
    }
    /// Linux mt76_connac2_mac_write_txwi: WCID = the link's peer, TXD1
    /// OWN_MAC = omac_idx and LMAC queue = wmm_idx * 4 + ac (`on_vif`).
    #[allow(clippy::too_many_arguments)]
    fn submit_data_txd(
        &mut self,
        link: crate::mt7921::vif_slots::Link,
        frame: &[u8],
        protected: bool,
        qos: bool,
        pipelined: bool,
        aggregated: bool,
        tid: u8,
    ) -> Result<(), Error> {
        if tid >= 8 || tid != 0 && !qos {
            return Err(Error::Bounds);
        }
        if aggregated && (!qos || !pipelined) {
            return Err(Error::Bounds);
        }
        if pipelined && !qos {
            return Err(Error::Bounds);
        }
        self.check()?;
        if !self.owner.published {
            return Err(Error::Busy);
        }
        let storage = self.owner.storage.as_ref().ok_or(Error::Busy)?;
        let token = if pipelined {
            storage.tokens.available_pipelined()?
        } else {
            storage.tokens.available()?
        };
        // The armed sample owner is the home peer's (`arm` = WCID 1).
        let sample_pid = if qos && link == crate::mt7921::vif_slots::Link::HOME {
            storage.tx_sequence.pid(tid)?
        } else {
            None
        };
        if sample_pid.is_some() && !storage.tokens.is_empty() {
            return Err(Error::Busy);
        }
        let ring = &storage.data;
        let slot = ring.index;
        if storage.tokens.owns_slot(slot) || ring.word(slot, 1) & DONE == 0 {
            return Err(Error::Busy);
        }
        let address = ring.buffers[slot].dma_addr().raw();
        let payload = address
            .checked_add(packet_tx::HEADER as u64)
            .ok_or(Error::DmaAddress)?;
        let mut header = packet_tx::station_data(
            link,
            frame,
            payload,
            token,
            protected,
            qos.then_some(tid),
            aggregated,
        )?;
        if qos && self.hw_amsdu {
            packet_tx::set_hw_amsdu(&mut header);
        }
        if let Some(pid) = sample_pid {
            crate::mt7921::tx_sequence::request(&mut header, pid)?;
        }
        // SAFETY: fully validated lengths; this slot has neither DMA nor
        // firmware ownership until the publication below.
        unsafe {
            core::ptr::copy_nonoverlapping(
                header.as_ptr(),
                ring.buffers[slot].cpu_mut_ptr::<u8>(),
                header.len(),
            );
            core::ptr::copy_nonoverlapping(
                frame.as_ptr(),
                ring.buffers[slot].cpu_mut_ptr::<u8>().add(header.len()),
                frame.len(),
            );
        }
        let storage = self.owner.storage.as_mut().ok_or(Error::Busy)?;
        storage.tokens.begin_at(token, slot)?;
        if sample_pid.is_some() {
            storage.tx_sequence.begin(tid, token)?;
        }
        let ring = &mut storage.data;
        ring.pending = true; // conservative on any later doorbell failure
        ring.index = (slot + 1) % DEPTH;
        ring.set_word(slot, 0, address as u32);
        ring.set_word(slot, 2, 0);
        ring.set_word(slot, 3, (address >> 32) as u32 & 15);
        dma_barrier();
        ring.set_word(slot, 1, ((packet_tx::HEADER as u32) << 16) | LAST);
        dma_barrier();
        self.write(TX_DATA + 8, ((slot + 1) % DEPTH) as u32)
    }
    fn management_complete(&mut self) -> Result<Option<packet_tx::Completion>, Error> {
        self.check()?;
        let ring = &self.owner.storage.as_ref().ok_or(Error::Busy)?.data;
        if !ring.pending {
            return Err(Error::Ring);
        }
        let read = self.owner.storage.as_ref().ok_or(Error::Busy)?.data_dma;
        let didx = self.read(TX_DATA + 12)? as usize;
        dma_barrier();
        let submitted = (ring.index + DEPTH - read) % DEPTH;
        let advanced = if didx < DEPTH {
            (didx + DEPTH - read) % DEPTH
        } else {
            DEPTH
        };
        if advanced > submitted {
            return Err(Error::Ring);
        }
        for offset in 0..advanced {
            let slot = (read + offset) % DEPTH;
            if !self.owner.storage.as_ref().unwrap().tokens.owns_slot(slot) {
                return Err(Error::Ring);
            }
            if ring.word(slot, 1) & DONE == 0 {
                return Ok(None);
            }
        }
        dma_barrier();
        let storage = self.owner.storage.as_mut().ok_or(Error::Busy)?;
        for offset in 0..advanced {
            storage.tokens.dma_done_at((read + offset) % DEPTH)?;
        }
        storage.data_dma = didx;
        let mut result = storage.tokens.finish();
        if result.is_none() {
            // Poll reports without consuming queued/fresh MCU replies.
            let _ = self.route_rx(None)?;
            let storage = self.owner.storage.as_mut().ok_or(Error::Busy)?;
            result = storage.tokens.finish();
        }
        if let Some(completion) = result {
            let storage = self.owner.storage.as_mut().ok_or(Error::Busy)?;
            storage.tx_sequence.terminal(completion);
            storage.data.pending = !storage.tokens.is_empty();
        }
        Ok(result)
    }
    fn read(&self, addr: u32) -> Result<u32, Error> {
        if !self.wake.mmio_ready() {
            return Err(Error::Busy);
        }
        crate::mt7921::pci::invoke(&self.authority, || {
            // SAFETY: exclusive retained aperture/L1 latch inside current invocation.
            let value =
                unsafe { registers::read32(&self.mmio, addr) }.map_err(|_| Error::Register)?;
            if value == u32::MAX {
                Err(Error::DeviceGone)
            } else {
                Ok(value)
            }
        })
        .map_err(|_| Error::Authority)?
    }
    fn write(&self, addr: u32, value: u32) -> Result<(), Error> {
        if !self.wake.mmio_ready() {
            return Err(Error::Busy);
        }
        crate::mt7921::pci::invoke(&self.authority, || {
            // SAFETY: bounded register plan and current retained PCI invocation.
            unsafe { registers::write32(&self.mmio, addr, value) }.map_err(|_| Error::Register)
        })
        .map_err(|_| Error::Authority)?
    }
    fn command(&self, clear: u16, set: u16) -> Result<u16, Error> {
        if !self.wake.mmio_ready() {
            return Err(Error::Busy);
        }
        crate::mt7921::pci::invoke(&self.authority, || {
            if clear != 0 {
                narf_bus::pci::clear_command(&self.authority, &self.device, clear)
                    .map_err(|_| Error::Authority)?;
            }
            if set != 0 {
                narf_bus::pci::set_command(&self.authority, &self.device, set)
                    .map_err(|_| Error::Authority)?;
            }
            let value = narf_bus::pci::read_command(&self.authority, &self.device)
                .map_err(|_| Error::Authority)?;
            if value == u16::MAX {
                Err(Error::DeviceGone)
            } else {
                Ok(value)
            }
        })
        .map_err(|_| Error::Authority)?
    }
    fn update(&self, addr: u32, clear: u32, set: u32) -> Result<(), Error> {
        self.write(addr, (self.read(addr)? & !clear) | set)
    }
    fn program(&self, ring: &Ring, rx: bool) -> Result<(), Error> {
        self.write(ring.base, ring.descriptors.dma_addr().raw() as u32)?;
        self.write(ring.base + 4, DEPTH as u32)?;
        self.write(ring.base + 8, if rx { (DEPTH - 1) as u32 } else { 0 })?;
        self.write(ring.base + 12, 0)
    }
    fn clear_rings(&self) -> Result<(), Error> {
        // Clear inherited ring bases too: enabling a global DMA engine must
        // not expose buffers belonging to the previous OS/firmware client.
        for (base, count) in [(0xd4300, 18), (0xd4500, 6)] {
            for ring in 0..count {
                for word in 0..4 {
                    self.write(base + ring * 16 + word * 4, 0)?;
                }
            }
        }
        Ok(())
    }
}
impl Backend for Hardware {
    fn close_p2p_capture(&mut self) {
        if let Some(storage) = self.owner.storage.as_mut() {
            storage.p2p_capture.close();
        }
    }
    fn configure_p2p_capture(
        &mut self,
        spec: Option<super::p2p_management_capture::Spec>,
    ) -> Result<(), Error> {
        Hardware::configure_p2p_capture(self, spec)
    }
    fn receive_p2p_management(
        &mut self,
    ) -> Result<Option<super::p2p_management_capture::Captured>, Error> {
        Hardware::receive_p2p_management(self)
    }
    fn progress(&mut self, stage: super::Stage) {
        use core::fmt::Write;
        let _ = writeln!(narf_console::Writer, "mt76: firmware {stage:?}");
    }
    fn now_ns(&self) -> u64 {
        narf_time::wall::monotonic_ns()
    }
    fn check(&self) -> Result<(), Error> {
        crate::mt7921::pci::invoke(&self.authority, || ()).map_err(|_| Error::Authority)
    }
    fn chip_id(&self) -> Result<u16, Error> {
        let chip = (self.read(MT_HW_CHIPID)? & 0xffff) as u16;
        matches!(chip, MTK_DEV_MT7961 | MTK_DEV_MT7922 | MTK_DEV_MT7920)
            .then_some(chip)
            .ok_or(Error::InvalidIdentity)
    }
    fn check_tx_permission(
        &self,
        permission: crate::mt7921::association::TxPermission,
    ) -> Result<(), Error> {
        self.check()?;
        super::current_station_permission(permission, narf_wireless::reg::db::snapshot())
    }
    fn suspend_dma(&mut self) -> Result<(), Error> {
        self.update(GLOBAL, ENABLE, 0)?;
        self.write(MT_WFDMA0_HOST_INT_ENA, 0)?;
        self.write(MT_PCIE_MAC_INT_ENABLE, 0)?;
        let _ = self.read(GLOBAL)?; // push the disable before the idle poll
        Ok(())
    }
    fn request_firmware_own(&mut self) -> Result<(), Error> {
        self.write(MT_CONN_ON_LPCTL, PCIE_LPCR_HOST_SET_OWN)
    }
    fn firmware_owned(&mut self) -> Result<bool, Error> {
        Ok(self.read(MT_CONN_ON_LPCTL)? & PCIE_LPCR_HOST_OWN_SYNC != 0)
    }
    fn prepare_wake_route(
        &mut self,
        target: narf_power::system_pm::SystemSleepState,
    ) -> Result<(), Error> {
        Hardware::prepare_wake_route(self, target)
    }
    fn arm_wake_route(
        &mut self,
        target: narf_power::system_pm::SystemSleepState,
    ) -> Result<(), Error> {
        Hardware::arm_wake_route(self, target)
    }
    fn wake_power_settled(&self) -> bool {
        self.wake.settled(self.now_ns())
    }
    fn enter_wake_d3hot(&mut self) -> Result<(), Error> {
        Hardware::enter_wake_d3hot(self)
    }
    fn verify_wake_d3hot(&mut self) -> Result<(), Error> {
        Hardware::verify_wake_d3hot(self)
    }
    fn begin_wake_d0(&mut self) -> Result<bool, Error> {
        Hardware::begin_wake_d0(self)
    }
    fn verify_wake_d0(&mut self) -> Result<(), Error> {
        Hardware::verify_wake_d0(self)
    }
    fn disarm_wake_route(&mut self) -> Result<(), Error> {
        Hardware::disarm_wake_route(self)
    }
    fn restore_bus(&mut self) -> Result<(), Error> {
        use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
        // Bus mastering returns only once retained rings are proven current.
        let command = self.command(BUS_MASTER, MEM_SPACE | INTX_DISABLE)?;
        if command & (BUS_MASTER | MEM_SPACE | INTX_DISABLE) != MEM_SPACE | INTX_DISABLE {
            return Err(Error::Authority);
        }
        Ok(())
    }
    fn dma_needs_reinit(&mut self) -> Result<bool, Error> {
        Ok(self.read(WFDMA_DUMMY_CR)? & WFDMA_NEED_REINIT == 0)
    }
    fn reinit_dma(&mut self) -> Result<(), Error> {
        if !self.idle()? || self.read(GLOBAL)? & ENABLE != 0 {
            return Err(Error::Busy);
        }
        // Same verified ownership sequence as reset recovery, minus WFSYS
        // reset: unpublish, retire every slot/token, then reprogram.
        self.release()?;
        self.recycle()?;
        self.initialize()
    }
    fn resume_dma(&mut self) -> Result<(), Error> {
        // A blocked function lost its stop proof's rings; only a verified
        // reinit/recovery (initialize) restores it.
        if !self.owner.published
            || iommu_bdf(&self.device).is_some_and(narf_io::iommu::device_dma_blocked)
        {
            return Err(Error::Busy);
        }
        use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
        if self.command(0, BUS_MASTER)? & (BUS_MASTER | MEM_SPACE | INTX_DISABLE)
            != BUS_MASTER | MEM_SPACE | INTX_DISABLE
        {
            return Err(Error::Authority);
        }
        // The native owner is polled: host interrupt enables stay masked,
        // exactly as initialize() leaves them.
        self.update(GLOBAL, 0, ENABLE)?;
        let _ = self.read(GLOBAL)?;
        Ok(())
    }
    fn park_bus_master(&mut self) -> Result<(), Error> {
        if self.command(narf_bus::pci::cmd::BUS_MASTER, 0)? & narf_bus::pci::cmd::BUS_MASTER != 0 {
            return Err(Error::Busy);
        }
        // Recovery parks before the WFSYS reset; block there too, so a
        // reset or recovery that dies leaves the function blocked and its
        // rings reclaimable (Linux `pci_dev_reset_iommu_prepare` precedes
        // a function reset). Idempotent when already blocked.
        self.block_dma().map(|_| ())
    }
    fn assert_reset(&mut self) -> Result<(), Error> {
        self.sequence_reset = SequenceReset::None;
        self.update(MT_WFSYS_SW_RST_B, 1, 0)?;
        if self.read(MT_WFSYS_SW_RST_B)? & 1 != 0 {
            return Err(Error::Register);
        }
        self.sequence_reset = SequenceReset::Asserted;
        Ok(())
    }
    fn request_link_own(&mut self) -> Result<(), Error> {
        self.write(MT_CONN_ON_LPCTL, PCIE_LPCR_HOST_CLR_OWN)
    }
    fn link_owned(&mut self) -> Result<bool, Error> {
        Ok(self.read(MT_CONN_ON_LPCTL)? & PCIE_LPCR_HOST_OWN_SYNC == 0)
    }
    fn release_reset(&mut self) -> Result<(), Error> {
        self.update(MT_WFSYS_SW_RST_B, 0, 1)?;
        if self.read(MT_WFSYS_SW_RST_B)? & 1 == 0 {
            return Err(Error::Register);
        }
        self.sequence_reset = if self.sequence_reset == SequenceReset::Asserted {
            SequenceReset::Released
        } else {
            SequenceReset::None
        };
        Ok(())
    }
    fn reset_done(&mut self) -> Result<bool, Error> {
        let ready = self.read(MT_WFSYS_SW_RST_B)? & (1 << 4) != 0;
        if ready && self.sequence_reset == SequenceReset::Released {
            self.sequence_reset = SequenceReset::Ready;
        }
        Ok(ready)
    }
    fn recycle(&mut self) -> Result<(), Error> {
        if self.owner.published || !self.idle()? || self.read(GLOBAL)? & ENABLE != 0 {
            return Err(Error::Busy);
        }
        if self.command(0, 0)? & narf_bus::pci::cmd::BUS_MASTER != 0 {
            return Err(Error::Busy);
        }
        let storage = self.owner.storage.as_mut().ok_or(Error::Busy)?;
        storage.recycle();
        if self.sequence_reset == SequenceReset::Ready {
            storage.tx_sequence.firmware_reset();
            self.sequence_reset = SequenceReset::None;
        }
        Ok(())
    }
    fn quiesce(&mut self) -> Result<(), Error> {
        self.write(MT_PCIE_MAC_INT_ENABLE, 0)?;
        self.write(MT_WFDMA0_HOST_INT_ENA, 0)?;
        self.write(MT_MCU2HOST_SW_INT_ENA, 0)?;
        self.update(GLOBAL, ENABLE | OMIT, 0)?;
        let _ = self.read(GLOBAL)?; // push disable before waiting for idle
        Ok(())
    }
    fn idle(&mut self) -> Result<bool, Error> {
        Ok(self.read(GLOBAL)? & BUSY == 0)
    }
    fn initialize(&mut self) -> Result<(), Error> {
        if !self.idle()? {
            return Err(Error::Busy);
        }
        self.write(0x0041f23c, 0)?; // MT_SWDEF_MODE: normal firmware operation.
        self.update(0xd42b0, 1 << 6, 0)?; // disable DMASHDL
        self.update(0x7c026004, 0, 1 << 28)?; // bypass scheduler
        self.update(MT_WFDMA0_RST, 0x30, 0)?;
        self.update(MT_WFDMA0_RST, 0, 0x30)?;
        self.clear_rings()?;
        self.write(0xd420c, u32::MAX)?;
        // Idle proven and bus mastering still off: a function blocked by
        // stop/recovery gets its retained domain back before any ring
        // base is programmed.
        self.restore_dma()?;
        // Conservatively mark published BEFORE the first ring base write.
        self.owner.published = true;
        let storage = self.owner.storage.as_ref().ok_or(Error::Busy)?;
        dma_barrier();
        self.program(&storage.wm, false)?;
        self.program(&storage.fwdl, false)?;
        self.program(&storage.data, false)?;
        for ring in &storage.rx {
            self.program(ring, true)?;
        }
        for (index, base) in [(0, 0), (2, 0x40), (3, 0x80), (4, 0xc0), (5, 0x100)] {
            self.write(0xd4680 + index * 4, (base << 16) | 4)?;
        }
        for (index, base) in [
            (0, 0x140),
            (1, 0x180),
            (2, 0x1c0),
            (3, 0x200),
            (4, 0x240),
            (5, 0x280),
            (6, 0x2c0),
            (16, 0x340),
            (17, 0x380),
        ] {
            self.write(0xd4600 + index * 4, (base << 16) | 4)?;
        }
        self.write(0xd42f0, 0)?;
        self.update(
            GLOBAL,
            ENABLE | (1 << 27),
            (3 << 4)
                | (1 << 6)
                | (1 << 11)
                | (1 << 12)
                | (1 << 13)
                | (1 << 15)
                | (1 << 21)
                | (1 << 28)
                | (1 << 30),
        )?;
        self.update(WFDMA_DUMMY_CR, 0, WFDMA_NEED_REINIT)?;
        self.update(MT_PCIE_MAC_PM, 0, MT_PCIE_MAC_PM_L0S_DIS)?;
        // All published addresses are owned and bounded before enabling DMA.
        use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
        if self.command(0, BUS_MASTER)? & (BUS_MASTER | MEM_SPACE | INTX_DISABLE)
            != BUS_MASTER | MEM_SPACE | INTX_DISABLE
        {
            return Err(Error::Authority);
        }
        self.update(GLOBAL, 0, ENABLE)?;
        let _ = self.read(GLOBAL)?;
        Ok(())
    }
    fn request_driver_own(&mut self) -> Result<(), Error> {
        self.write(0x18060010, 2)
    }
    fn driver_owned(&mut self) -> Result<bool, Error> {
        Ok(self.read(0x18060010)? & 1 == 0)
    }
    fn fw_state(&mut self) -> Result<u32, Error> {
        self.read(0x7c0600f0)
    }
    fn pause_ap_timing(&mut self) -> Result<(), Error> {
        Hardware::pause_ap_timing(self)
    }
    fn finish_ap_timing(&mut self, five: bool, short_slot: bool) -> Result<(), Error> {
        Hardware::finish_ap_timing(self, five, short_slot)
    }
    fn configure_mac(&mut self) -> Result<(), Error> {
        self.update(0x820cd004, 0xfff8, 1536 << 3)?;
        self.update(0x820cd000, 0, (1 << 15) | (1 << 19))?;
        for band in [0u32, 0x10000] {
            self.update(0x820e40f4 + band, 0x3f, 0x3f | (3 << 17))?;
            self.update(0x820e53c4 + band, 0, 1 << 30)?;
            self.update(0x820e5380 + band, 0, 1 << 30)?;
            self.update(0x820ed004 + band, 0, 3 << 8)?;
            self.update(0x820e7000 + band, 0xfff8 | (1 << 23), 1536 << 3)?;
            self.update(0x820e9008 + band, (3 << 30) | (3 << 24), 3 << 24)?;
        }
        Ok(())
    }
    fn clear_wtbl(&mut self, index: u8) -> Result<(), Error> {
        if index >= 20 {
            return Err(Error::Bounds);
        }
        self.update(0x820d4230, 0x3ff, u32::from(index) | (1 << 12))
    }
    fn wtbl_idle(&mut self) -> Result<bool, Error> {
        Ok(self.read(0x820d4230)? & (1 << 31) == 0)
    }
    fn submit(&mut self, scatter: bool, frame: &[u8]) -> Result<(), Error> {
        self.check()?;
        if frame.is_empty() || frame.len() > MAX_FRAME {
            return Err(Error::Bounds);
        }
        let storage = self.owner.storage.as_mut().ok_or(Error::Busy)?;
        let ring = if scatter {
            &mut storage.fwdl
        } else {
            &mut storage.wm
        };
        if ring.pending {
            return Err(Error::Busy);
        }
        let slot = ring.index;
        // SAFETY: TX completion was verified before this slot is reused.
        unsafe {
            core::ptr::copy_nonoverlapping(
                frame.as_ptr(),
                ring.buffers[slot].cpu_mut_ptr::<u8>(),
                frame.len(),
            )
        };
        let address = ring.buffers[slot].dma_addr().raw();
        ring.set_word(slot, 0, address as u32);
        ring.set_word(slot, 2, 0);
        ring.set_word(slot, 3, (address >> 32) as u32 & 15);
        dma_barrier();
        ring.set_word(slot, 1, ((frame.len() as u32) << 16) | LAST);
        dma_barrier();
        ring.pending = true;
        let base = ring.base;
        let next = (slot + 1) % DEPTH;
        self.write(base + 8, next as u32)
    }
    fn tx_complete(&mut self, scatter: bool) -> Result<bool, Error> {
        self.check()?;
        let storage = self.owner.storage.as_ref().ok_or(Error::Busy)?;
        let ring = if scatter { &storage.fwdl } else { &storage.wm };
        let didx = self.read(ring.base + 12)? as usize;
        if didx >= DEPTH {
            return Err(Error::Ring);
        }
        if !ring.pending {
            return Err(Error::Ring);
        }
        let next = (ring.index + 1) % DEPTH;
        if didx != ring.index && didx != next {
            return Err(Error::Ring);
        }
        dma_barrier();
        if didx != next || ring.word(ring.index, 1) & DONE == 0 {
            return Ok(false);
        }
        let storage = self.owner.storage.as_mut().ok_or(Error::Busy)?;
        let ring = if scatter {
            &mut storage.fwdl
        } else {
            &mut storage.wm
        };
        ring.index = next;
        ring.pending = false;
        Ok(true)
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.route_rx(Some(true))
            .map(|packet| packet.map(|packet| packet.bytes))
    }
    fn receive_data(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.route_rx(Some(false))
            .map(|packet| packet.map(|packet| packet.bytes))
    }
    fn receive_data_captured(&mut self) -> Result<Option<CapturedData>, Error> {
        self.route_rx(Some(false))
    }
    fn close_receive_capture(&mut self, epoch: u64) {
        if let Some(storage) = &mut self.owner.storage {
            storage.receive_epoch = epoch;
            storage.receive_open = false;
        }
    }
    fn open_receive_capture(&mut self, epoch: u64) -> Result<(), Error> {
        Hardware::open_receive_capture(self, epoch)
    }
    fn release(&mut self) -> Result<(), Error> {
        if !self.idle()? || self.read(GLOBAL)? & ENABLE != 0 {
            return Err(Error::Busy);
        }
        self.park_bus_master()?;
        self.clear_rings()?;
        let _ = self.read(GLOBAL)?;
        self.unpublish()
    }
    fn submit_management(
        &mut self,
        vif: crate::mt7921::vif_slots::Vif,
        frame: &[u8],
        wcid: u16,
        rate: crate::mt7921::association::LegacyRate,
    ) -> Result<(), Error> {
        self.submit_management(vif, frame, wcid, rate)
    }
    fn submit_fragment(
        &mut self,
        link: crate::mt7921::vif_slots::Link,
        frame: &[u8],
    ) -> Result<(), Error> {
        self.submit_fragment(link, frame)
    }
    fn submit_data(
        &mut self,
        link: crate::mt7921::vif_slots::Link,
        frame: &[u8],
        protected: bool,
        qos: bool,
    ) -> Result<(), Error> {
        self.submit_data(link, frame, protected, qos)
    }
    fn submit_ap_frame(
        &mut self,
        vif: crate::mt7921::vif_slots::Vif,
        frame: &[u8],
        wcid: u8,
        rate: crate::mt7921::association::LegacyRate,
    ) -> Result<(), Error> {
        self.submit_80211(frame, None, |payload, token| {
            super::ap_packet::descriptor_on(vif, frame, payload, token, wcid, rate)
        })
    }
    fn arm_ap_management(
        &mut self,
        vif: crate::mt7921::vif_slots::Vif,
        wcid: u8,
    ) -> Result<(), Error> {
        self.check()?;
        if !self.owner.published {
            return Err(Error::Busy);
        }
        let storage = self.owner.storage.as_mut().ok_or(Error::Busy)?;
        if !storage.tokens.is_empty() {
            return Err(Error::Busy);
        }
        storage.tx_sequence.arm_ap_management_on(vif, wcid)
    }
    fn submit_ap_management(
        &mut self,
        vif: crate::mt7921::vif_slots::Vif,
        frame: &[u8],
        wcid: u8,
        rate: crate::mt7921::association::LegacyRate,
    ) -> Result<(), Error> {
        self.submit_80211(frame, Some(0), |payload, token| {
            super::ap_packet::descriptor_on(vif, frame, payload, token, wcid, rate)
        })
    }
    fn poll_ap_management_ack(&mut self) -> Result<Option<bool>, Error> {
        self.check()?;
        for _ in 0..3 {
            let _ = self.route_rx(None)?;
        }
        self.owner
            .storage
            .as_mut()
            .ok_or(Error::Busy)?
            .tx_sequence
            .take_ap_ack()
    }
    fn arm_p2p_management(
        &mut self,
        vif: crate::mt7921::vif_slots::Vif,
        tid: u8,
    ) -> Result<(), Error> {
        self.check()?;
        if !self.owner.published {
            return Err(Error::Busy);
        }
        let storage = self.owner.storage.as_mut().ok_or(Error::Busy)?;
        if !storage.tokens.is_empty() {
            return Err(Error::Busy);
        }
        storage.tx_sequence.arm_p2p_management(vif, tid)
    }
    fn submit_p2p_management(
        &mut self,
        frame: &[u8],
        vif: crate::mt7921::vif_slots::Vif,
        rate: crate::mt7921::association::LegacyRate,
    ) -> Result<(), Error> {
        let local = frame
            .get(10..16)
            .ok_or(Error::Bounds)?
            .try_into()
            .map_err(|_| Error::Bounds)?;
        let header = super::p2p_management_tx_wire::Header::prepare(frame, local)?;
        self.submit_80211(
            frame,
            (!header.multicast).then_some(header.tid),
            |payload, token| {
                super::p2p_management_tx_wire::descriptor(
                    frame,
                    payload,
                    token,
                    vif,
                    rate,
                    header.multicast,
                )
            },
        )
    }
    fn poll_p2p_management_ack(&mut self) -> Result<Option<bool>, Error> {
        self.poll_ap_management_ack()
    }
    fn submit_data_pipelined(
        &mut self,
        link: crate::mt7921::vif_slots::Link,
        frame: &[u8],
        protected: bool,
        qos: bool,
    ) -> Result<(), Error> {
        if !qos {
            return Err(Error::Bounds);
        }
        self.submit_data_mode(link, frame, protected, qos, true)
    }
    fn submit_data_aggregated(
        &mut self,
        link: crate::mt7921::vif_slots::Link,
        frame: &[u8],
        protected: bool,
    ) -> Result<(), Error> {
        self.submit_data_profile(link, frame, protected, true, true, true)
    }
    fn submit_data_tid_aggregated(
        &mut self,
        link: crate::mt7921::vif_slots::Link,
        frame: &[u8],
        protected: bool,
        tid: u8,
    ) -> Result<(), Error> {
        self.submit_data_txd(link, frame, protected, true, true, true, tid)
    }
    fn submit_data_tid(
        &mut self,
        link: crate::mt7921::vif_slots::Link,
        frame: &[u8],
        protected: bool,
        tid: u8,
        pipelined: bool,
    ) -> Result<(), Error> {
        if tid == 0 {
            return Err(Error::Bounds);
        }
        self.submit_data_txd(link, frame, protected, true, pipelined, false, tid)
    }
    fn arm_transmit_sequence(&mut self, tid: u8) -> Result<(), Error> {
        self.check()?;
        if !self.owner.published {
            return Err(Error::Busy);
        }
        let storage = self.owner.storage.as_mut().ok_or(Error::Busy)?;
        if !storage.tokens.is_empty() {
            return Err(Error::Busy);
        }
        storage.tx_sequence.arm(tid)
    }
    fn transmit_sequence_published(&self, tid: u8) -> bool {
        self.owner
            .storage
            .as_ref()
            .is_some_and(|storage| storage.tx_sequence.published(tid))
    }
    fn poll_transmit_sequence(&mut self, tid: u8) -> Result<Option<u16>, Error> {
        self.check()?;
        // Bounded native report progress, preserving data/MCU ownership.
        for _ in 0..3 {
            let _ = self.route_rx(None)?;
        }
        self.owner
            .storage
            .as_mut()
            .ok_or(Error::Busy)?
            .tx_sequence
            .take(tid)
    }
    fn cancel_transmit_sequence(&mut self) {
        if let Some(storage) = self.owner.storage.as_mut() {
            storage.tx_sequence.cancel();
        }
    }
    fn set_hw_amsdu(&mut self, enabled: bool) {
        self.hw_amsdu = enabled;
    }
    fn receive_idle(&self) -> Result<bool, Error> {
        self.check()?;
        let storage = self.owner.storage.as_ref().ok_or(Error::Busy)?;
        dma_barrier();
        Ok(storage.pending_data.is_empty()
            && storage
                .rx
                .iter()
                .all(|ring| ring.word(ring.index, 1) & DONE == 0))
    }
    fn management_complete(
        &mut self,
    ) -> Result<Option<crate::mt7921::packet_tx::Completion>, Error> {
        self.management_complete()
    }
}
/// Retained coherent MCU/FWDL transport with verified reset/recovery.
#[derive(Debug)]
pub struct Transport {
    session: Session<Hardware>,
    /// PCI binding generation this transport was claimed under.
    generation: u64,
}

#[path = "firmware_transport_hw_tests.rs"]
mod tests;
impl Transport {
    pub(crate) async fn transmit_p2p_management(
        &mut self,
        iface: alloc::sync::Weak<crate::iface::p2p::P2pDeviceIface>,
        authority: Arc<narf_wireless::ap_control::RadioControlAuthority>,
        cookie: u64,
        request: narf_wireless::MgmtTxRequest,
        alive: Arc<core::sync::atomic::AtomicBool>,
        expected_mac: [u8; 6],
    ) -> Result<bool, Error> {
        super::boot_p2p::management_tx::run_session(
            &mut self.session,
            iface,
            authority,
            cookie,
            request,
            alive,
            expected_mac,
        )
        .await
    }
    pub(crate) fn register_p2p_management(
        &mut self,
        iface: alloc::sync::Weak<crate::iface::p2p::P2pDeviceIface>,
        authority: Arc<narf_wireless::ap_control::RadioControlAuthority>,
        frame_type: u16,
        prefix: &[u8],
        expected_mac: [u8; 6],
    ) -> Result<(), i32> {
        super::boot_p2p::management::register_session(
            &mut self.session,
            iface,
            authority,
            frame_type,
            prefix,
            expected_mac,
        )
    }
    pub(crate) fn p2p_profile(&self) -> Result<super::P2pProfile, Error> {
        self.session.backend.check()?;
        self.session.firmware.p2p_profile()
    }

    pub(crate) fn module_firmware_chunk(
        &self,
        image: u8,
        offset: usize,
        len: usize,
    ) -> Result<Vec<u8>, Error> {
        self.session.backend.check()?;
        if !crate::mt7921::pci::module_generation_current(self.generation) {
            return Err(Error::DeviceGone);
        }
        let bytes = match image {
            0 => &self.session.firmware.patch,
            1 => &self.session.firmware.ram,
            _ => return Err(Error::Bounds),
        };
        if len == 0 || len > crate::module_protocol::MAX_FIRMWARE_CHUNK || offset > bytes.len() {
            return Err(Error::Bounds);
        }
        let end = offset.saturating_add(len).min(bytes.len());
        let mut reply = Vec::with_capacity(40 + end - offset);
        reply.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        reply.extend_from_slice(&(offset as u32).to_le_bytes());
        let mut digest = narf_crypto::sha256::Sha256::new();
        digest.update(bytes);
        reply.extend_from_slice(&digest.finalize());
        reply.extend_from_slice(&bytes[offset..end]);
        self.session.backend.check()?;
        Ok(reply)
    }
    pub(crate) async fn run_p2p_request(
        &mut self,
        iface: alloc::sync::Weak<crate::iface::p2p::P2pDeviceIface>,
        authority: Arc<narf_wireless::ap_control::RadioControlAuthority>,
        operation: super::boot_p2p::Request,
        alive: Arc<core::sync::atomic::AtomicBool>,
        expected_mac: [u8; 6],
    ) -> Result<(), Error> {
        super::boot_p2p::run_session(
            &mut self.session,
            iface,
            authority,
            operation,
            alive,
            expected_mac,
        )
        .await
    }
    pub(crate) async fn maintain_p2p_device(
        &mut self,
        iface: alloc::sync::Weak<crate::iface::p2p::P2pDeviceIface>,
        expected_mac: [u8; 6],
    ) -> Result<(), Error> {
        super::boot_p2p::maintain_session(&mut self.session, iface, expected_mac).await
    }
    pub(crate) async fn run_p2p_delete(
        &mut self,
        iface: alloc::sync::Weak<crate::iface::p2p::P2pDeviceIface>,
        authority: Arc<narf_wireless::ap_control::RadioControlAuthority>,
        alive: Arc<core::sync::atomic::AtomicBool>,
        expected_mac: [u8; 6],
    ) -> Result<narf_wireless::ap_control::RadioControlRetirement, Error> {
        super::boot_p2p::delete_session(&mut self.session, iface, authority, alive, expected_mac)
            .await
    }
    pub(crate) async fn start_p2p_device(
        &mut self,
        authority: Arc<narf_wireless::ap_control::RadioControlAuthority>,
    ) -> Result<(), Error> {
        self.session.start_p2p_device(authority).await
    }
    pub(crate) fn commit_p2p_device(
        &mut self,
        authority: &narf_wireless::ap_control::RadioControlAuthority,
    ) -> Result<narf_wireless::ap_control::RadioInterfaceIdentity, Error> {
        self.session.commit_p2p_device(authority)
    }
    pub(crate) async fn stop_p2p_device(
        &mut self,
        authority: &narf_wireless::ap_control::RadioControlAuthority,
    ) -> Result<(), Error> {
        self.session.stop_p2p_device(authority).await
    }
    pub(crate) async fn acquire_p2p_roc(
        &mut self,
        authority: Arc<narf_wireless::ap_control::RadioControlAuthority>,
        cookie: u64,
        frequency_mhz: u32,
        duration_ms: u32,
    ) -> Result<u32, Error> {
        self.session
            .acquire_p2p_roc(authority, cookie, frequency_mhz, duration_ms)
            .await
    }
    pub(crate) fn commit_p2p_roc(
        &mut self,
        authority: &narf_wireless::ap_control::RadioControlAuthority,
    ) -> Result<super::p2p::RocReceipt, Error> {
        self.session.commit_p2p_roc(authority)
    }
    pub(crate) fn p2p_roc_current(&self, cookie: u64, frequency_mhz: u32) -> Result<bool, Error> {
        self.session.p2p_roc_current(cookie, frequency_mhz)
    }
    pub(crate) async fn expire_p2p_roc(&mut self) -> Result<bool, Error> {
        self.session.expire_p2p_roc().await
    }
    pub(crate) async fn cancel_p2p_roc(
        &mut self,
        authority: Arc<narf_wireless::ap_control::RadioControlAuthority>,
        cookie: u64,
    ) -> Result<(), Error> {
        self.session.cancel_p2p_roc(authority, cookie).await
    }
    pub(crate) async fn run_ap_request(
        &mut self,
        iface: alloc::sync::Weak<crate::iface::Mt76Iface>,
        authority: Arc<narf_wireless::ap_control::ApControlAuthority>,
        request: super::boot_ap::Request,
        alive: Arc<core::sync::atomic::AtomicBool>,
        expected_mac: [u8; 6],
    ) -> Result<super::boot_ap::Reply, Error> {
        super::boot_ap::run_session(
            &mut self.session,
            iface,
            authority,
            request,
            alive,
            expected_mac,
        )
        .await
    }
    pub(crate) fn ap_owned(&self) -> bool {
        self.session.ap_owner.is_some()
    }
    pub(crate) fn ap_retired(&self) -> bool {
        self.session.ap_owner.is_none()
            && matches!(
                self.session.state,
                State::RadioReady(_) | State::ScanReady(_)
            )
    }
    pub(crate) async fn stop_ap_owned(&mut self) -> Result<(), Error> {
        self.session.stop_ap_owned().await
    }
    pub(crate) async fn cleanup_ap(&mut self, expected_mac: [u8; 6]) -> Result<(), Error> {
        if self.session.ap_owner.is_some() {
            return self.session.stop_ap_owned().await;
        }
        match self.session.state {
            State::RadioReady(_) | State::ScanReady(_) => Ok(()),
            State::Failed { .. } | State::Running(_) | State::Stopped => {
                self.session.recover(expected_mac).await.map(|_| ())
            }
            _ => Err(Error::Busy),
        }
    }
    /// Allocate all rings without device writes.
    ///
    /// # Safety
    /// Caller exclusively owns this posted CONNAC2 device, its BAR0/L1 latch,
    /// DMA/reset/power controls and permanent mappings. No other client may
    /// access them until verified shutdown. Under a per-domain IOMMU the
    /// function's default domain (from `narf_bus::dma::configure`) maps
    /// every ring and frame buffer, and the programmed addresses are those
    /// IOVAs (Linux mt76 via `dma_alloc_coherent` → iommu-dma); without
    /// one the bus addresses are physical. A non-coherent function needs
    /// a reserved `shared-dma-pool` (see `narf_bus::dma::configure`). This is not VF/reset
    /// recovery. Firmware must be prepared for this exact chip. Initially
    /// PCI bus mastering must be disabled by the caller.
    pub unsafe fn new(
        mmio: MmioRegion,
        device: BusDevice,
        authority: Cap<BusDeviceCap, Write>,
        firmware: Firmware,
        generation: u64,
    ) -> Result<Self, Error> {
        crate::mt7921::pci::invoke(&authority, || {
            authority.check_live().map_err(|_| Error::Authority)?;
            if !matches!(device.id.vendor, 0x14c3 | 0x0e8d)
                || !matches!(device.id.device, 0x0616 | 0x0608 | 0x7922 | 0x7961 | 0x7920)
            {
                return Err(Error::Bounds);
            }
            if narf_bus::pci::read_command(&authority, &device).map_err(|_| Error::Authority)?
                & narf_bus::pci::cmd::BUS_MASTER
                != 0
            {
                return Err(Error::Busy);
            }
            // Highest programmed register and the L1 selector must be mapped.
            for addr in [0xd46ff, MT_HIF_REMAP_L1] {
                if u64::from(addr) + 4 > mmio.len {
                    return Err(Error::Bounds);
                }
            }
            // A function blocked by the previous generation's stop is
            // re-attached before its first mapping (bus mastering off).
            restore_function_dma(&device)?;
            let dma = narf_bus::dma::configure(&device).map_err(|_| Error::Allocation)?;
            let storage = Storage {
                wm: Ring::allocate_for(&dma, TX_WM, false)?,
                fwdl: Ring::allocate_for(&dma, TX_FWDL, false)?,
                data: Ring::allocate_for(&dma, TX_DATA, false)?,
                data_dma: 0,
                tokens: packet_tx::Tokens::new(),
                tx_sequence: crate::mt7921::tx_sequence::Owner::new(),
                pending_events: VecDeque::new(),
                pending_data: VecDeque::new(),
                receive_epoch: 0,
                receive_open: false,
                p2p_capture: super::p2p_management_capture::Queue::new(),
                rx: [
                    Ring::allocate_for(&dma, RX_PRE, true)?,
                    Ring::allocate_for(&dma, RX_POST, true)?,
                    Ring::allocate_for(&dma, RX_DATA, true)?,
                ],
            };
            Ok(Self {
                session: Session::new(
                    Hardware {
                        mmio,
                        device,
                        authority,
                        owner: Retained {
                            storage: Some(storage),
                            published: false,
                        },
                        hw_amsdu: false,
                        sequence_reset: SequenceReset::None,
                        wake: wake::Wake::default(),
                    },
                    firmware,
                ),
                generation,
            })
        })
        .map_err(|_| Error::Authority)?
    }
    /// Start once. Dropping this borrowed future requests no reset/replay.
    pub async fn run(&mut self) -> Result<Report, Error> {
        self.session.run().await
    }
    /// Query the real radio identity and select on-chip EFUSE calibration.
    /// This does not yet enable packet transmission or register an interface.
    pub async fn initialize_radio(&mut self) -> Result<RadioInfo, Error> {
        self.session.initialize_radio().await
    }
    /// Configure a native AP BSS/beacon under the actual current delegated
    /// request. Cancellation retains the transport owner until cleanup.
    /// Host peer/packet admission is a separate interface publication.
    pub async fn start_ap(
        &mut self,
        authority: Arc<narf_wireless::ap_control::ApControlAuthority>,
        config: narf_wireless::ApConfig,
    ) -> Result<(), Error> {
        self.session.start_ap(authority, config).await
    }
    pub(crate) async fn start_ap_with_settings(
        &mut self,
        authority: Arc<narf_wireless::ap_control::ApControlAuthority>,
        config: narf_wireless::ApConfig,
        settings: narf_wireless::ApStartSettings,
    ) -> Result<(), Error> {
        self.session
            .start_ap_with_settings(authority, config, settings)
            .await
    }
    /// Stop the AP and verify a fresh MAC/FW generation before returning.
    pub async fn stop_ap(
        &mut self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
    ) -> Result<(), Error> {
        self.session.stop_ap(authority).await
    }
    /// Concrete registered interface commits capture only after native START
    /// and its own current authority/identity check; no peer port opens here.
    pub(crate) fn commit_ap_start(
        &mut self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
    ) -> Result<u64, Error> {
        self.session.commit_ap_start(authority)
    }
    pub(crate) async fn add_ap_station(
        &mut self,
        authority: Arc<narf_wireless::ap_control::ApControlAuthority>,
        config: narf_wireless::StationConfig,
    ) -> Result<(), Error> {
        self.session.ap_add_station(authority, config).await
    }
    pub(crate) fn authorize_ap_station(
        &mut self,
        authority: &narf_wireless::ap_control::ApControlAuthority,
        peer: [u8; 6],
        authorized: bool,
    ) -> Result<(), Error> {
        self.session
            .ap_authorize_station(authority, peer, authorized)
    }
    pub(crate) async fn delete_ap_station(
        &mut self,
        authority: Arc<narf_wireless::ap_control::ApControlAuthority>,
        peer: Option<[u8; 6]>,
    ) -> Result<(), Error> {
        self.session.ap_delete_station(authority, peer).await
    }
    /// Secret staging happens before construction of the returned future.
    /// Even a never-polled operation erases the moved temporal key.
    pub(crate) fn add_ap_key(
        &mut self,
        authority: Arc<narf_wireless::ap_control::ApControlAuthority>,
        key: narf_wireless::KeyParams,
    ) -> impl core::future::Future<Output = Result<(), Error>> + '_ {
        let key = super::ap_crypto::Install::prepare(key).map_err(|_| Error::Bounds);
        async move { self.session.ap_install_key(authority, key?).await }
    }
    pub(crate) fn add_owned_ap_key(
        &mut self,
        authority: Arc<narf_wireless::ap_control::ApControlAuthority>,
        key: narf_wireless::OwnedKey,
    ) -> impl core::future::Future<Output = Result<(), Error>> + '_ {
        let key = super::ap_crypto::Install::from_params(key.params()).map_err(|_| Error::Bounds);
        async move { self.session.ap_install_key(authority, key?).await }
    }
    pub(crate) async fn delete_ap_key(
        &mut self,
        authority: Arc<narf_wireless::ap_control::ApControlAuthority>,
        index: u8,
        pairwise: bool,
        peer: Option<[u8; 6]>,
    ) -> Result<(), Error> {
        self.session
            .ap_delete_key(authority, index, pairwise, peer)
            .await
    }
    pub(crate) async fn default_ap_key(
        &mut self,
        authority: Arc<narf_wireless::ap_control::ApControlAuthority>,
        index: u8,
    ) -> Result<(), Error> {
        self.session.ap_default_key(authority, index).await
    }
    pub(crate) fn step_ap_network(
        &mut self,
        frame: Option<&[u8]>,
    ) -> Result<super::PacketStep, Error> {
        self.session.step_ap_network(frame)
    }
    pub(crate) fn ap_receive_current(&self, epoch: u64) -> Result<bool, Error> {
        self.session.ap_receive_current(epoch)
    }
    pub(crate) fn ap_station_macs(&self) -> Result<Vec<[u8; 6]>, Error> {
        if !self
            .session
            .ap_receive_current(self.session.receive_epoch)?
        {
            return Ok(Vec::new());
        }
        Ok(self
            .session
            .ap_owner
            .as_ref()
            .ok_or(Error::Busy)?
            .peers
            .addresses())
    }
    pub(crate) fn pop_ap_event(&mut self) -> Result<Option<super::ApRxEvent>, Error> {
        self.session.pop_ap_event()
    }
    pub(crate) async fn transmit_ap_management(
        &mut self,
        authority: Arc<narf_wireless::ap_control::ApControlAuthority>,
        frame: &[u8],
    ) -> Result<bool, Error> {
        self.session.ap_send_management(authority, frame).await
    }
    pub(crate) async fn transmit_ap_control(
        &mut self,
        authority: Arc<narf_wireless::ap_control::ApControlAuthority>,
        request: narf_wireless::ControlPortTxRequest,
    ) -> Result<bool, Error> {
        self.session.ap_send_control(authority, request).await
    }
    pub(crate) async fn update_ap_station(
        &mut self,
        authority: Arc<narf_wireless::ap_control::ApControlAuthority>,
        config: narf_wireless::StationConfig,
    ) -> Result<(), Error> {
        self.session.ap_update_station(authority, config).await
    }
    pub(crate) async fn update_ap_beacon(
        &mut self,
        authority: Arc<narf_wireless::ap_control::ApControlAuthority>,
        head: Option<Vec<u8>>,
        tail: Option<Vec<u8>>,
        probe: Option<Vec<u8>>,
    ) -> Result<(), Error> {
        self.session
            .ap_update_beacon(authority, head, tail, probe)
            .await
    }
    /// Perform a bounded, receive-only scan on world 2.4 GHz channels 1..=11.
    pub async fn scan_passive(&mut self, channels: &[u8]) -> Result<super::ScanReport, Error> {
        self.session.scan_passive(channels).await
    }
    /// Directed/wildcard probes on currently policy-authorized 20 MHz channels.
    /// Nonempty SSID lists (up to four, including wildcard entries) select
    /// active scanning. A completed scan returns to a NO_IR-only idle domain.
    pub async fn scan_active(
        &mut self,
        channels: &[u8],
        ssids: &[Vec<u8>],
    ) -> Result<super::ScanReport, Error> {
        self.scan_active_with_ies(channels, ssids, &[]).await
    }
    /// Complete optional Probe Request elements in the native fixed IE field.
    pub async fn scan_active_with_ies(
        &mut self,
        channels: &[u8],
        ssids: &[Vec<u8>],
        extra_ies: &[u8],
    ) -> Result<super::ScanReport, Error> {
        if ssids.is_empty() {
            return Err(Error::Bounds);
        }
        self.scan_with_options(
            channels,
            ssids,
            super::ScanOptions {
                extra_ies,
                random_mac: None,
            },
        )
        .await
    }
    pub async fn scan_with_options(
        &mut self,
        channels: &[u8],
        ssids: &[Vec<u8>],
        options: super::ScanOptions<'_>,
    ) -> Result<super::ScanReport, Error> {
        super::validate_scan_options(options)?;
        // Bootstrap only at this explicit admission boundary. The running
        // scan must observe a cleared installation rather than reload it.
        if !ssids.is_empty() {
            narf_wireless::reg::db::ensure_domain().map_err(|_| Error::Authority)?;
        }
        self.session
            .scan_with_options_and_policy(channels, ssids, options, || {
                narf_wireless::reg::db::get_domain().ok_or(Error::Authority)
            })
            .await
    }
    /// Prepare the bounded native HT20 RX/A-MSDU owner from actual radio/AP
    /// capabilities. This does not enable HT MLME, peer firmware state or TX.
    /// Legacy association invalidates the preparation; no HT facade is exposed.
    pub fn prepare_ht20_receive(
        &mut self,
        bss: &super::ScanBss,
    ) -> Result<super::Ht20ReceiveInfo, Error> {
        self.session.prepare_ht20_receive(bss)
    }
    /// Associate with an Access Point using legacy rates on channels 1..=11.
    pub async fn associate_station(
        &mut self,
        bss: &super::ScanBss,
        ssid: &[u8],
        security: crate::mt7921::association::Security,
    ) -> Result<u16, Error> {
        self.associate_station_with_ies(bss, ssid, security, &[])
            .await
    }
    /// Associate while retaining checked optional SME association elements.
    pub async fn associate_station_with_ies(
        &mut self,
        bss: &super::ScanBss,
        ssid: &[u8],
        security: crate::mt7921::association::Security,
        extra_ies: &[u8],
    ) -> Result<u16, Error> {
        self.associate_station_as(
            bss,
            ssid,
            security,
            extra_ies,
            crate::mt7921::p2p_wire::Network::Infrastructure,
            false,
        )
        .await
    }
    /// Join as the BSS0 infrastructure station or P2P client. The P2P role
    /// uses the same qualified station grant, peer/key/data owners and
    /// native records; only the BSS-basic connection type differs.
    pub(crate) async fn associate_station_as(
        &mut self,
        bss: &super::ScanBss,
        ssid: &[u8],
        security: crate::mt7921::association::Security,
        extra_ies: &[u8],
        network: crate::mt7921::p2p_wire::Network,
        heard_beacon: bool,
    ) -> Result<u16, Error> {
        let domain = narf_wireless::reg::db::ensure_domain().map_err(|_| Error::Authority)?;
        let info = match self.session.state {
            State::RadioReady(info) | State::ScanReady(info) => info,
            _ => return Err(Error::Busy),
        };
        // `heard_beacon`: the latest scan received this BSS's Beacon, so a
        // radar/NO_IR channel it operates on may be joined (never probed).
        let permission = crate::mt7921::association::TxPermission::from_ap_heard(
            &domain,
            info,
            bss,
            heard_beacon,
        )
        .ok_or(Error::Authority)?;
        let aid = self
            .session
            .associate_station_as(bss, ssid, security, permission, extra_ies, network)
            .await?;
        self.session.service_keys().await?;
        self.session.negotiate_transmit_ba().await?;
        self.session.service_keys().await?;
        Ok(aid)
    }
    /// Negotiate only before this native peer's first QoS Ethernet MPDU.
    /// Metadata alone does not grant current transmit permission.
    pub async fn negotiate_transmit_ba(&mut self) -> Result<bool, Error> {
        self.session.negotiate_transmit_ba().await
    }
    /// Negotiate an independent originator agreement for an unused TID0..7.
    pub async fn negotiate_transmit_ba_tid(&mut self, tid: u8) -> Result<bool, Error> {
        self.session.negotiate_transmit_ba_tid(tid).await
    }
    pub fn transmit_ba_tid_active(&self, tid: u8) -> bool {
        matches!(self.session.state, State::Associated { .. })
            && !self.session.station.peer_lost
            && self.session.station.tx_ba.active_tid(tid)
    }
    pub fn transmit_ba_active(&self) -> bool {
        matches!(self.session.state, State::Associated { .. })
            && !self.session.station.peer_lost
            && self.session.station.tx_ba.active()
    }
    /// Send deauthentication and tear down peer station record.
    pub async fn disassociate_station(&mut self) -> Result<(), Error> {
        self.session.disassociate_station().await
    }
    /// Stop DMA, verify idle, clear bus mastering and retire ring bases.
    pub async fn shutdown(&mut self) -> Result<(), Error> {
        self.session.shutdown().await
    }
    pub(super) fn generation(&self) -> u64 {
        self.generation
    }
    /// Synchronous removal teardown; true only when DMA retirement was
    /// proven and the ring memory may be returned.
    pub(super) fn retire_removed(&mut self) -> bool {
        self.session.retire_removed()
    }
    /// PCIe low-power handoff for system suspend; leaves any association.
    pub async fn suspend(&mut self) -> Result<(), Error> {
        self.session.suspend().await
    }
    /// Leave the low-power handoff, or reset with the same identity.
    pub async fn resume(&mut self, expected_mac: [u8; 6]) -> Result<RadioInfo, Error> {
        if let State::WowSuspended { info, .. } = self.session.state {
            self.session.resume_wowlan(expected_mac).await?;
            Ok(info)
        } else {
            self.session.resume(expected_mac).await
        }
    }
    pub async fn suspend_wowlan(
        &mut self,
        config: &narf_wireless::WowlanConfig,
        target: narf_power::system_pm::SystemSleepState,
    ) -> Result<(), Error> {
        self.session.suspend_wowlan(config, target).await
    }
    pub fn wake_route_available(&self) -> Result<bool, Error> {
        self.session.backend.wake_route_available()
    }
    pub(super) fn validate_rekey_data(
        &self,
        data: &narf_wireless::GtkRekeyData,
    ) -> Result<(), Error> {
        if !matches!(self.session.state, State::Associated { .. }) {
            return Err(Error::Busy);
        }
        self.session
            .station
            .security
            .as_ref()
            .ok_or(Error::Busy)?
            .validate_wow_gtk_data(data)
    }
    /// Park DMA, reset WFSYS, retire old ring ownership, and reload firmware.
    /// The caller closes carrier before awaiting. No association/key replay is
    /// attempted; a fresh scan/association is required after successful recovery.
    pub async fn recover(&mut self, expected_mac: [u8; 6]) -> Result<RadioInfo, Error> {
        self.session.recover(expected_mac).await
    }
    pub(super) async fn recover_unregistered(&mut self) -> Result<RadioInfo, Error> {
        self.session.recover_unregistered().await
    }
    /// Retire the old originator and queue one true-user-MPDU sequence
    /// sample, then let the ordinary service owner perform ADDBA at SN+1.
    pub async fn request_transmit_ba_restart_tid(&mut self, tid: u8) -> Result<(), Error> {
        self.session.request_transmit_ba_restart_tid(tid).await
    }

    /// Enable native passive sniffer and channel configuration with current
    /// policy checks. Monitor mode owns no station frame/key grant.
    pub async fn start_monitor(
        &mut self,
        channel: narf_wireless::monitor::Channel,
    ) -> Result<(), Error> {
        narf_wireless::reg::db::ensure_domain().map_err(|_| Error::Authority)?;
        self.session
            .start_monitor_with_policy(channel, || {
                narf_wireless::reg::db::get_domain().ok_or(Error::Authority)
            })
            .await
    }
    pub(super) fn step_monitor(
        &mut self,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<super::MonitorCapture, Error> {
        self.session.step_monitor(domain)
    }
    pub async fn stop_monitor(&mut self) -> Result<(), Error> {
        self.session.stop_monitor().await
    }

    /// Last observed boot stage/result, also preserved after cancellation.
    pub fn state(&self) -> State {
        self.session.state
    }
    /// Drain unrelated bounded MCU notifications retained while awaiting replies.
    pub fn pop_event(&mut self) -> Option<Vec<u8>> {
        self.session.events.pop_front()
    }
    /// Transmit an 802.3 Ethernet data frame.
    pub async fn transmit_ethernet(&mut self, frame: &[u8]) -> Result<(), Error> {
        self.session.send_ethernet(frame).await.map(|_| ())
    }
    /// Receive a data frame from the data queue.
    pub async fn receive_data_frame(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.session.receive_ethernet()
    }

    pub(super) fn step_network(&mut self, tx: Option<&[u8]>) -> Result<super::PacketStep, Error> {
        self.session.frag_threshold =
            super::BOOT_FRAG_THRESHOLD.load(core::sync::atomic::Ordering::Relaxed);
        self.session.step_network(tx)
    }
    pub(super) fn receive_current(&self, epoch: u64) -> Result<bool, Error> {
        self.session.receive_current(epoch)
    }
    pub(super) fn current_receive_epoch(&self) -> Result<Option<u64>, Error> {
        let epoch = self.session.receive_epoch;
        self.session
            .receive_current(epoch)
            .map(|current| current.then_some(epoch))
    }
    pub(super) fn publish_receive(
        &self,
        epoch: u64,
        publish: impl FnOnce(),
    ) -> Result<bool, Error> {
        self.session.publish_receive(epoch, publish)
    }

    /// Home key service, then the group link's (`service_group_keys`). A
    /// group failure is recorded in the group role (`State::Failed`) and
    /// surfaces on its own entries; it never fails the home step.
    pub(super) async fn service_keys(&mut self) -> Result<(), Error> {
        self.session.service_keys().await?;
        if let Some(link) = self.session.group_link() {
            if self.session.group_keys_pending(link) {
                let _ = self.session.service_group_keys(link).await;
            }
        }
        Ok(())
    }

    pub(super) fn keys_pending(&self) -> bool {
        self.session.keys_pending()
            || self
                .session
                .group_link()
                .is_some_and(|link| self.session.group_keys_pending(link))
    }

    /// Publish a concurrent P2P-client group vif (`start_group_link`:
    /// Linux `mt7921_add_interface` for a second STATION|P2P_CLIENT vif).
    pub(crate) async fn start_group_link(
        &mut self,
        vif: crate::mt7921::vif_slots::Vif,
        own: [u8; 6],
    ) -> Result<crate::mt7921::vif_slots::Link, Error> {
        self.session.start_group_link(vif, own).await
    }
    /// Retire an idle group vif (`mt792x_remove_interface`).
    pub(crate) async fn stop_group_link(
        &mut self,
        link: crate::mt7921::vif_slots::Link,
    ) -> Result<(), Error> {
        self.session.stop_group_link(link).await
    }
    /// Join the group link as a P2P client (or a second station): the
    /// qualified grant comes from the target's regulatory power type, as
    /// for the home join, and must equal any live owner's channel context.
    /// Key, BA and key service follow exactly as `associate_station_as`.
    pub(crate) async fn associate_group(
        &mut self,
        link: crate::mt7921::vif_slots::Link,
        bss: &super::ScanBss,
        ssid: &[u8],
        security: crate::mt7921::association::Security,
        extra_ies: &[u8],
        network: crate::mt7921::p2p_wire::Network,
    ) -> Result<u16, Error> {
        let domain = narf_wireless::reg::db::ensure_domain().map_err(|_| Error::Authority)?;
        let info = match self.session.group_state() {
            Some(State::RadioReady(info) | State::ScanReady(info)) => info,
            _ => return Err(Error::Busy),
        };
        let permission = crate::mt7921::association::TxPermission::from_ap(&domain, info, bss)
            .ok_or(Error::Authority)?;
        let aid = self
            .session
            .associate_group(link, bss, ssid, security, permission, extra_ies, network)
            .await?;
        self.session.service_group_keys(link).await?;
        self.session.negotiate_group_transmit_ba(link).await?;
        self.session.service_group_keys(link).await?;
        Ok(aid)
    }
    pub(crate) async fn disassociate_group(
        &mut self,
        link: crate::mt7921::vif_slots::Link,
    ) -> Result<(), Error> {
        self.session.disassociate_group(link).await
    }
    pub(crate) async fn negotiate_group_transmit_ba_tid(
        &mut self,
        link: crate::mt7921::vif_slots::Link,
        tid: u8,
    ) -> Result<bool, Error> {
        self.session
            .negotiate_group_transmit_ba_tid(link, tid)
            .await
    }
    pub(crate) fn step_group_network(
        &mut self,
        link: crate::mt7921::vif_slots::Link,
        tx: Option<&[u8]>,
    ) -> Result<super::PacketStep, Error> {
        self.session.frag_threshold =
            super::BOOT_FRAG_THRESHOLD.load(core::sync::atomic::Ordering::Relaxed);
        self.session.step_group_network(link, tx)
    }
    pub(crate) fn group_receive_current(
        &self,
        link: crate::mt7921::vif_slots::Link,
        epoch: u64,
    ) -> Result<bool, Error> {
        self.session.group_receive_current(link, epoch)
    }
    pub(crate) fn group_link(&self) -> Option<crate::mt7921::vif_slots::Link> {
        self.session.group_link()
    }
    pub(crate) fn group_state(&self) -> Option<State> {
        self.session.group_state()
    }
    /// Reserve the concurrent GO vif (`go_link::open_go`).
    pub(crate) fn open_go(
        &mut self,
        vif: crate::mt7921::vif_slots::Vif,
        own: [u8; 6],
    ) -> Result<(), Error> {
        self.session.open_go(vif, own)
    }
    /// START the GO beside the home station; returns its receive epoch.
    pub(crate) async fn start_go(
        &mut self,
        authority: Arc<narf_wireless::ap_control::ApControlAuthority>,
        config: narf_wireless::ApConfig,
        settings: narf_wireless::ApStartSettings,
    ) -> Result<u64, Error> {
        self.session.start_go(authority, config, settings).await
    }
    /// STOP the GO without a reset (`go_link::stop_go`).
    pub(crate) async fn stop_go(&mut self) -> Result<(), Error> {
        self.session.stop_go().await
    }
    pub(crate) fn close_go(&mut self) -> Result<(), Error> {
        self.session.close_go()
    }
    pub(crate) async fn go_request(
        &mut self,
        authority: Arc<narf_wireless::ap_control::ApControlAuthority>,
        request: super::boot_ap::Request,
    ) -> Result<super::boot_ap::Reply, Error> {
        self.session.go_request(authority, request).await
    }
    pub(crate) fn step_go_network(
        &mut self,
        tx: Option<&[u8]>,
    ) -> Result<(super::PacketStep, Vec<super::ApRxEvent>), Error> {
        self.session.step_go_network(tx)
    }
    pub(crate) fn go_receive_current(&self, epoch: u64) -> Result<bool, Error> {
        self.session.go_receive_current(epoch)
    }
    pub(crate) fn go_state(&self) -> Option<(crate::mt7921::vif_slots::Vif, State)> {
        self.session.go_state()
    }
    pub(crate) fn go_station_macs(&self) -> Vec<[u8; 6]> {
        self.session.go_station_macs()
    }
}

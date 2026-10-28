// SPDX-License-Identifier: GPL-2.0-or-later
//! Native RTL8188EE linked-descriptor packet ownership, initially polled.
//! No host receipt implies AP acknowledgement. OWN clear is the vendor's
//! terminal host/DMA receipt; publication, RX and stop keep exact DMA owners.
use super::{
    extent, Error, Io, Memory, Phase, Prepared, RX_BASE, RX_BUFFER, RX_BYTES, TX_BASES, TX_BYTES,
};
use alloc::vec::Vec;

/// A transport operation executes inside current PCI authority, including
/// actual descriptor/payload accesses. No DMA pointer or authority escapes.
pub trait Port: Io {
    type Buffer: Memory;
    fn authority<T>(
        &self,
        active: bool,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error>;
    fn allocate_packet(&self, bytes: usize) -> Result<Self::Buffer, Error>;
    fn master(&self, enabled: bool) -> Result<(), Error>;
    fn kick(&self, queue_bit: u16) -> Result<(), Error>;
    fn publication(&self) -> Result<Publication, Error> {
        Err(Error::State)
    }
}
/// Owned current PCI invocation, without a borrowed native owner or lock.
#[derive(Clone)]
pub struct Publication(PublicationSource);
impl core::fmt::Debug for Publication {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Rtl8188eeCurrentPublication")
    }
}
#[derive(Clone)]
enum PublicationSource {
    Native(
        narf_bus::BusDevice,
        narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    ),
    #[cfg(any(test, feature = "kernel-test"))]
    Model(alloc::sync::Arc<dyn Fn() -> Result<(), Error> + Send + Sync>),
}
impl Publication {
    pub(crate) fn native(
        device: narf_bus::BusDevice,
        cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    ) -> Self {
        Self(PublicationSource::Native(device, cap))
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn model(
        check: alloc::sync::Arc<dyn Fn() -> Result<(), Error> + Send + Sync>,
    ) -> Self {
        Self(PublicationSource::Model(check))
    }
    pub(crate) fn invoke<T>(
        &self,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        match &self.0 {
            PublicationSource::Native(device, cap) => crate::rtw88::pci_park::invoke(cap, || {
                let cmd = narf_bus::pci::read_command(cap, device)
                    .map_err(|_| Error::Access(super::AccessError::Access))?;
                let bits = narf_bus::pci::cmd::MEM_SPACE
                    | narf_bus::pci::cmd::BUS_MASTER
                    | narf_bus::pci::cmd::INTX_DISABLE;
                if cmd == u16::MAX || cmd & bits != bits {
                    return Err(Error::State);
                }
                operation()
            })
            .map_err(|_| Error::Access(super::AccessError::Access))?,
            #[cfg(any(test, feature = "kernel-test"))]
            PublicationSource::Model(check) => {
                check()?;
                operation()
            }
        }
    }
}

pub(super) struct State<M: Memory> {
    pub(super) local: Option<[u8; 6]>,
    next: [usize; 7],
    receive: usize,
    serial: u64,
    pending: Option<Pending<M>>,
    mailbox: super::super::station_control::Mailbox,
    reserved: Option<M>,
    pub(super) qos: bool,
    pub(super) ht: bool,
    /// HIMR/HIMRE/HSIMR currently carry the Linux 88EE masks.
    interrupts: bool,
    /// Firmware leisure power save (fw_current_inpsmode) is active.
    leisure: bool,
}
impl<M: Memory> State<M> {
    pub(super) fn new() -> Self {
        Self {
            local: None,
            next: [0; 7],
            receive: 0,
            serial: 0,
            pending: None,
            mailbox: super::super::station_control::Mailbox::default(),
            reserved: None,
            qos: false,
            ht: false,
            interrupts: false,
            leisure: false,
        }
    }
    pub(super) fn retain(&mut self) {
        // Published descriptors may still name the current TX allocation.
        // BME clear alone never permits releasing it at a terminal stop.
        core::mem::forget(self.pending.take());
        core::mem::forget(self.reserved.take());
    }
}
struct Pending<M: Memory> {
    buffer: M,
    id: u64,
    queue: usize,
    slot: usize,
    length: usize,
    prefix: [u32; 10],
}
#[derive(Debug, PartialEq, Eq)]
pub struct Delivery {
    pub id: u64,
    /// Bytes read from the retained DMA payload after matching OWN clear.
    pub bytes: Vec<u8>,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Mpdu {
    bytes: Vec<u8>,
    channel: u8,
    ht: bool,
    /// Native RXD DW1 PAGGR/FAGGR: this MPDU arrived inside an A-MPDU.
    aggregated: bool,
}
/// Consuming a rejected packet/report is progress, never a receive-idle
/// proof. Station output waits for a genuine OWN-owned next descriptor.
pub(crate) struct ReceiveStep {
    pub consumed: bool,
    pub packet: Option<Mpdu>,
}
impl Mpdu {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn channel(&self) -> u8 {
        self.channel
    }
    pub(super) fn ht(&self) -> bool {
        self.ht
    }
    /// Only the station's recipient BA owner may admit such an MPDU.
    pub(super) fn aggregated(&self) -> bool {
        self.aggregated
    }
}
impl narf_wireless::station_security::RawFrame for Mpdu {
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    fn unmodified(&self) -> bool {
        true
    }
}

const OWN: u32 = 1 << 31;
const MAX_MPDU: usize = 2304;
/// `rtl8188ee_tx_fill_desc`: `set_tx_desc_max_agg_num(pdesc, 0x14)`.
const MAX_AGG_NUM: u32 = 0x14;

fn queue(frame: &[u8], local: [u8; 6], qos: bool) -> Result<(usize, u16, u8), Error> {
    if !(24..=MAX_MPDU).contains(&frame.len()) || frame[10..16] != local || frame[22] & 15 != 0 {
        return Err(Error::Packet);
    }
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    if fc & 0x9403 != 0 {
        return Err(Error::Packet); // version, fragments, order, PM.
    }
    match (fc >> 2) & 3 {
        0 if fc & 0x4300 == 0
            && (matches!((fc >> 4) & 15, 0 | 4 | 10 | 11 | 12)
                || qos
                    && (fc >> 4) & 15 == 13
                    && (frame.len() == 33 && matches!(frame[24..26], [3, 0] | [3, 1])
                        || frame.len() == 30 && frame[24..26] == [3, 2])) =>
        {
            // MGMT vector1, Linux MGNT_QUEUE6, QSLT_MGNT0x12.
            Ok((1, 1 << 6, 0x12))
        }
        // Non-QoS DATA: mac80211 skb->priority0 on BE.
        2 if fc & 0x03f0 == 0x0100 => Ok((4, 1 << 1, 0)),
        // QoS DATA TID0..7 with normal ACK, no EOSP/A-MSDU/TXOP/queue size.
        // rtl_pci_tx queues `ieee802_1d_to_ac[priority]` on its own linked
        // ring and rtl88ee `_rtl88ee_map_hwqueue_to_fwqueue` sets TXD1
        // QSEL to skb->priority (the TID). Vectors follow TX_BASES; doorbells
        // are REG_PCIE_CTRL BIT(hw_queue): BK0, BE1, VI2, VO3.
        2 if qos && fc & 0x03f0 == 0x0180 => match frame.get(24..26) {
            Some(&[tid, 0]) if tid & 0xf8 == 0 => {
                let (vector, doorbell) = access_category_queue(tid);
                Ok((vector, doorbell, tid))
            }
            _ => Err(Error::Packet),
        },
        _ => Err(Error::Packet),
    }
}

/// Linux `ieee802_1d_to_ac` followed by `_rtl_mac_to_hwqueue`: the EE
/// linked-ring vector (TX_BASES order) and its REG_PCIE_CTRL doorbell.
pub(super) const fn access_category_queue(tid: u8) -> (usize, u16) {
    match tid & 7 {
        1 | 2 => (5, 1 << 0), // BK_QUEUE0 at REG_BKQ_DESA.
        4 | 5 => (3, 1 << 2), // VI_QUEUE2 at REG_VIQ_DESA.
        6 | 7 => (2, 1 << 3), // VO_QUEUE3 at REG_VOQ_DESA.
        _ => (4, 1 << 1),     // BE_QUEUE1 at REG_BEQ_DESA.
    }
}

impl<I: Port<Buffer = M>, M: Memory> Prepared<I, M> {
    pub(crate) fn local(&self) -> Option<[u8; 6]> {
        self.packet.local
    }
    pub(crate) fn transmit_ready(&self) -> bool {
        self.phase == Phase::Running && self.packet.pending.is_none() && !self.packet.mailbox.failed
    }
    pub(crate) async fn awake_station(&mut self) -> Result<(), Error> {
        if self.phase != Phase::MacConfigured {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        self.packet.mailbox.awake(&self.io).await?;
        self.phase = Phase::MacConfigured;
        Ok(())
    }
    pub(crate) async fn prepare_station_peer(
        &mut self,
        peer: [u8; 6],
        rates: u16,
        basic: u16,
        capability: u16,
    ) -> Result<(), Error> {
        if !self.transmit_ready() || self.packet.reserved.is_some() {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        super::super::station_control::prepare_peer(&self.io, peer, rates, basic, capability)
            .await?;
        self.phase = Phase::Running;
        Ok(())
    }
    /// Keep the command-beacon DMA body for the lifetime of this firmware
    /// claim. Its OWN bit may remain set: fresh BCN_VALID is its separate
    /// upload receipt and never retires ordinary MGMT/BE payload ownership.
    pub(crate) async fn complete_station_peer(
        &mut self,
        peer: [u8; 6],
        aid: u16,
    ) -> Result<(), Error> {
        self.complete_station_peer_admitted(peer, aid, None, |_| Ok(()))
            .await
    }
    pub(crate) async fn complete_station_peer_admitted(
        &mut self,
        peer: [u8; 6],
        aid: u16,
        admission: Option<&super::station::Admission>,
        policy: impl Fn(&Self) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if !self.transmit_ready() || self.packet.reserved.is_some() {
            return Err(Error::State);
        }
        let bytes = super::super::station_control::reserved_pages(
            self.local().ok_or(Error::State)?,
            peer,
            aid,
        )?;
        let mut buffer = self.io.allocate_packet(bytes.len())?;
        let address = extent(&buffer, bytes.len(), 4)?;
        let end = u64::from(address) + bytes.len() as u64;
        if self
            .tx
            .iter()
            .chain(self.receive.iter())
            .chain(self.buffers.iter())
            .any(|other| {
                u64::from(address) < other.address() + other.len() as u64 && other.address() < end
            })
        {
            return Err(Error::Address);
        }
        self.io.authority(true, || {
            buffer.write_bytes(0, &bytes)?;
            buffer.sync();
            Ok(())
        })?;
        self.packet.reserved = Some(buffer);
        self.phase = Phase::Failed;
        super::super::station_control::radio_on(&self.io)?;
        // Source core.c enables keepalive before its media/JOIN continuation.
        // The firmware still has no connected media or reserved-page location.
        self.packet
            .mailbox
            .send_admitted(&self.io, 3, &[0xff, 10], admission)
            .await?;
        if admission
            .is_some_and(|control| control.closed.load(core::sync::atomic::Ordering::Acquire))
        {
            return Err(Error::State);
        }
        super::super::station_control::associated(&self.io, aid)?;
        let cr = self.io.read8(0x101)?;
        let txq = self.io.read8(0x422)?;
        let beacon = self.io.read8(0x550)?;
        self.io.write8(0x101, cr | 1)?;
        self.io.write8(0x550, (beacon & !8) | 16)?;
        self.io.write8(0x422, txq & !64)?;
        let stale = self.io.read8(0x20a)?;
        self.io.write8(0x20a, stale | 1)?;
        if self.io.read8(0x20a)? & 1 != 0 {
            return Err(Error::Readback);
        }
        let mut prefix = [0u32; 10];
        prefix[0] = 768 | (32 << 16) | (1 << 26) | (1 << 27);
        prefix[1] = (7 << 16) | (0x10 << 8);
        prefix[3] = 1 << 31;
        prefix[4] = 1 << 8;
        prefix[7] = 768;
        prefix[8] = address;
        {
            let _publication = admission.map(|control| control.publication.lock());
            if admission
                .is_some_and(|control| control.closed.load(core::sync::atomic::Ordering::Acquire))
            {
                return Err(Error::State);
            }
            policy(self)?;
            let ring = &mut self.tx[0];
            self.io.authority(true, || {
                ring.sync();
                if ring.read32(0)? & OWN != 0 {
                    return Err(Error::Descriptor);
                }
                for (index, value) in prefix.into_iter().enumerate() {
                    ring.write32(index * 4, value)?;
                }
                ring.sync();
                ring.write32(0, prefix[0] | OWN)?;
                ring.sync();
                Ok(())
            })?;
            self.io.kick(1 << 4)?;
        }
        self.packet
            .mailbox
            .send_admitted(&self.io, 0, &[4, 2, 3, 0, 0], admission)
            .await?;
        let mut complete = false;
        for _ in 0..100 {
            if admission
                .is_some_and(|control| control.closed.load(core::sync::atomic::Ordering::Acquire))
            {
                return Err(Error::State);
            }
            super::super::station_control::radio_on(&self.io)?;
            let status = self.io.read8(0x20a)?;
            if status == 255 {
                return Err(Error::Access(super::AccessError::Gone));
            }
            if status & 1 != 0 {
                complete = true;
                break;
            }
            self.io.delay_us(10).await;
        }
        if !complete {
            return Err(Error::CommandTimeout);
        }
        self.io.write8(0x20a, 1)?;
        self.io.write8(0x550, (beacon | 8) & !16)?;
        if txq & 64 != 0 {
            self.io.write8(0x422, txq)?;
        }
        self.io.write8(0x101, cr & !1)?;
        if self.io.read8(0x20a)? & 1 != 0
            || self.io.read8(0x101)? != cr & !1
            || self.io.read8(0x550)? != (beacon | 8) & !16
            || self.io.read8(0x422)? != txq
        {
            return Err(Error::Readback);
        }
        policy(self)?;
        self.packet
            .mailbox
            .send_admitted(&self.io, 1, &[1], admission)
            .await?;
        if admission
            .is_some_and(|control| control.closed.load(core::sync::atomic::Ordering::Acquire))
        {
            return Err(Error::State);
        }
        self.phase = Phase::Running;
        Ok(())
    }
    /// True while the firmware is in leisure power save.
    pub(crate) fn leisure(&self) -> bool {
        self.packet.leisure
    }
    /// Linux `rtl_lps_set_psmode(EAUTOPS)` → HW_VAR_FW_LPS_ACTION(true):
    /// only a running, idle owner may hand the radio to firmware LPS.
    pub(crate) async fn enter_leisure(&mut self) -> Result<(), Error> {
        if !self.transmit_ready() || self.packet.leisure || self.packet.local.is_none() {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        self.packet.mailbox.doze(&self.io).await?;
        self.packet.leisure = true;
        self.phase = Phase::Running;
        Ok(())
    }
    /// Linux `rtl_lps_set_psmode(EACTIVE)` → HW_VAR_FW_LPS_ACTION(false):
    /// `_rtl88ee_fwlps_leave` RPWM ALL_ON then H2C FW_PS_ACTIVE_MODE.
    pub(crate) async fn leave_leisure(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Running || !self.packet.leisure {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        self.packet.mailbox.awake(&self.io).await?;
        self.packet.leisure = false;
        self.phase = Phase::Running;
        Ok(())
    }
    pub(crate) async fn disconnect_station_peer(&mut self) -> Result<(), Error> {
        if !matches!(self.phase, Phase::Running | Phase::Failed) {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        // mac80211 disassociation leaves PS before the join report clears.
        let awake = if core::mem::take(&mut self.packet.leisure) {
            self.packet.mailbox.awake(&self.io).await
        } else {
            Ok(())
        };
        let report = match awake {
            Ok(()) => self.packet.mailbox.send(&self.io, 1, &[0]).await,
            Err(error) => Err(error),
        };
        let mac = super::super::station_control::disconnected(&self.io);
        let stopped = self.stop_packets();
        report.and(mac).and(stopped)
    }
    /// Open the already owned native rings. The one-shot operational MAC,
    /// factory IQ/LC calibration and opaque channel/power grant are required.
    /// Device interrupts remain masked; no native netdev is raised here.
    pub(crate) fn start_packets(&mut self) -> Result<(), Error> {
        if self.phase != Phase::MacConfigured
            || self.packet.local.is_none()
            || self.permission.is_none()
        {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        self.io.authority(false, || self.validate_rings())?;
        super::super::radio::parked(&self.io).map_err(Error::Radio)?;
        if self.io.read32(0x608)? != super::super::packet_mac::RCR
            || self.io.read32(0x604)? != super::super::packet_mac::TCR
            || self.io.read8(0x680)? != 0
        {
            return Err(Error::Readback);
        }
        self.io.master(true)?;
        // Linux init_mac CR2ff then CR+1=06. DMA remains independently
        // stopped until the complete owned descriptor/MAC state is ready.
        self.io.write_bytes(0x100, &[0xff, 6])?;
        self.io.write8(0x301, 0)?;
        self.io.write8(0x522, 0)?;
        if self.io.read8(0x100)? != 0xff
            || self.io.read8(0x101)? != 6
            || self.io.read8(0x301)? != 0
            || self.io.read32(0xb0)? != 0
            || self.io.read32(0xb8)? != 0
        {
            return Err(Error::Readback);
        }
        self.phase = Phase::Running;
        Ok(())
    }
    /// True while the Linux 88EE masks are programmed (IRQ profile).
    pub(crate) fn interrupts_enabled(&self) -> bool {
        self.packet.interrupts
    }
    /// Linux `rtl88ee_enable_interrupt`: HIMR/HIMRE = irq_mask[0]/[1],
    /// clear firmware-notified C2H events (REG_C2HEVT_CLEAR = 0) so the
    /// firmware keeps scheduling commands, then HSIMR = sys_irq_mask. Only
    /// a running owner whose vector is bound may unmask; the polling
    /// fallback keeps every mask clear.
    pub(crate) fn enable_interrupts(&mut self) -> Result<(), Error> {
        use super::super::irq::*;
        if self.phase != Phase::Running || self.packet.interrupts {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        self.io.authority(true, || Ok(()))?;
        self.io.write32(0xb0, IRQ_MASK0_88E)?;
        self.io.write32(0xb8, IRQ_MASK1_88E)?;
        self.packet.interrupts = true;
        self.io.write8(REG_C2HEVT_CLEAR_88E, 0)?;
        self.io.write32(REG_HSIMR_88E, SYS_IRQ_MASK_88E)?;
        if self.io.read32(0xb0)? != IRQ_MASK0_88E
            || self.io.read32(0xb8)? != IRQ_MASK1_88E
            || self.io.read32(REG_HSIMR_88E)? != SYS_IRQ_MASK_88E
        {
            return Err(Error::Readback);
        }
        self.phase = Phase::Running;
        Ok(())
    }
    /// Linux `rtl88ee_disable_interrupt` (HIMR/HIMRE = IMR_DISABLED). Used
    /// when the bound vector is withdrawn while the owner keeps polling.
    pub(crate) fn disable_interrupts(&mut self) -> Result<(), Error> {
        self.packet.interrupts = false;
        self.io.write32(0xb0, 0)?;
        self.io.write32(0xb8, 0)?;
        if self.io.read32(0xb0)? != 0 || self.io.read32(0xb8)? != 0 {
            return Err(Error::Readback);
        }
        Ok(())
    }
    /// One `_rtl_pci_interrupt` bottom-half pass: mask (disable_interrupt),
    /// `rtl88ee_interrupt_recognized` W1C of HISR/HISRE under irq_mask,
    /// `_rtl_pci_hs_interrupt` HSISR W1C when IMR_HSISR_IND_ON_INT is set,
    /// then unmask (enable_interrupt). RX/TX ring service follows in the
    /// caller's existing ring walk, exactly where Linux calls
    /// `_rtl_pci_rx_interrupt`/`_rtl_pci_tx_isr`. An all-ones status means
    /// the function vanished and is terminal.
    pub(crate) fn recognize_interrupts(&mut self) -> Result<super::super::irq::Recognized, Error> {
        use super::super::irq::*;
        if self.phase != Phase::Running || !self.packet.interrupts {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        self.io.write32(0xb0, 0)?;
        self.io.write32(0xb8, 0)?;
        let raw = self.io.read32(0xb4)?;
        if raw == u32::MAX {
            return Err(Error::Access(super::AccessError::Gone));
        }
        let inta = raw & IRQ_MASK0_88E;
        self.io.write32(0xb4, inta)?;
        let intb = self.io.read32(0xbc)? & IRQ_MASK1_88E;
        self.io.write32(0xbc, intb)?;
        if inta & IMR_HSISR_IND_ON_INT != 0 {
            let hsisr = self.io.read8(REG_HSISR_88E)?;
            self.io
                .write8(REG_HSISR_88E, hsisr | SYS_IRQ_MASK_88E as u8)?;
        }
        self.io.write32(0xb0, IRQ_MASK0_88E)?;
        self.io.write32(0xb8, IRQ_MASK1_88E)?;
        self.phase = Phase::Running;
        Ok(Recognized { inta, intb })
    }
    fn validate_rings(&self) -> Result<(), Error> {
        for (queue, ring) in self.tx.iter().enumerate() {
            ring.sync();
            let base = extent(ring, self.depth * TX_BYTES, 256)?;
            if self.io.read32(TX_BASES[queue])? != base {
                return Err(Error::Readback);
            }
            for slot in 0..self.depth {
                if ring.read32(slot * TX_BYTES)? & OWN != 0
                    || ring.read32(slot * TX_BYTES + 40)?
                        != base + (((slot + 1) % self.depth) * TX_BYTES) as u32
                    || ring.read32(slot * TX_BYTES + 44)? != 0
                {
                    return Err(Error::Descriptor);
                }
            }
        }
        let receive = self.receive.as_ref().ok_or(Error::State)?;
        receive.sync();
        if self.io.read32(RX_BASE)? != extent(receive, self.depth * RX_BYTES, 256)? {
            return Err(Error::Readback);
        }
        for (slot, buffer) in self.buffers.iter().enumerate() {
            let end = if slot + 1 == self.depth { 1 << 30 } else { 0 };
            if receive.read32(slot * RX_BYTES)? != RX_BUFFER as u32 | OWN | end
                || receive.read32(slot * RX_BYTES + 24)? != extent(buffer, RX_BUFFER, 4)?
                || receive.read32(slot * RX_BYTES + 28)? != 0
            {
                return Err(Error::Descriptor);
            }
        }
        Ok(())
    }
    /// One outstanding native frame is retained across all active queues.
    /// A free descriptor alone cannot substitute a different pending payload.
    pub(crate) fn submit(&mut self, frame: &[u8], rate: u8) -> Result<u64, Error> {
        self.submit_aggregate(frame, rate, None)
    }
    /// `submit` with `rtl8188ee_tx_fill_desc` aggregation fields for QoS
    /// DATA to an HT station: `aggregate = (ampdu_density, ampdu)` sets
    /// TXD DW2 AMPDU_DENSITY and, for an `IEEE80211_TX_CTL_AMPDU` frame,
    /// DW2 AGG_EN + DW6 MAX_AGG_NUM 0x14.
    pub(crate) fn submit_aggregate(
        &mut self,
        frame: &[u8],
        rate: u8,
        aggregate: Option<(u8, bool)>,
    ) -> Result<u64, Error> {
        if self.phase != Phase::Running || self.packet.pending.is_some() {
            return Err(Error::State);
        }
        if aggregate.is_some_and(|(density, _)| density > 7)
            || aggregate.is_some() && !(self.packet.ht && frame.first() == Some(&0x88))
        {
            return Err(Error::Packet);
        }
        if rate > 11
            && !(self.packet.ht && (12..=19).contains(&rate) && frame.first() == Some(&0x88))
        {
            return Err(Error::Packet);
        }
        let (queue, poll, selector) = queue(
            frame,
            self.packet.local.ok_or(Error::State)?,
            self.packet.qos,
        )?;
        let id = self.packet.serial.checked_add(1).ok_or(Error::State)?;
        let mut buffer = self.io.allocate_packet(frame.len())?;
        let address = extent(&buffer, frame.len(), 4)?;
        let end = u64::from(address) + frame.len() as u64;
        if self
            .tx
            .iter()
            .chain(self.receive.iter())
            .chain(self.buffers.iter())
            .any(|other| {
                u64::from(address) < other.address() + other.len() as u64 && other.address() < end
            })
        {
            return Err(Error::Address);
        }
        let slot = self.packet.next[queue];
        let mut prefix = [0; 10];
        prefix[0] = frame.len() as u32 | (32 << 16) | (1 << 26) | (1 << 27);
        let destination = if (2..=5).contains(&queue) {
            &frame[16..22]
        } else {
            &frame[4..10]
        };
        if destination[0] & 1 != 0 {
            prefix[0] |= 1 << 24;
        }
        prefix[1] = u32::from(selector) << 8; // MACID0, rateID0, security0.
        prefix[3] = u32::from(u16::from_le_bytes([frame[22], frame[23]]) >> 4) << 16;
        prefix[4] = (1 << 8) | (1 << 10); // forced checked rate, no fallback/BW/SGI/AGG.
        if frame[0] == 0x88 {
            prefix[4] |= 1 << 6;
        } // EE TXD.QOS; host SSN retained.
        if let Some((density, ampdu)) = aggregate {
            prefix[2] |= u32::from(density) << 20;
            if ampdu {
                prefix[2] |= 1 << 12;
                prefix[6] |= MAX_AGG_NUM << 11;
            }
        }
        prefix[5] = u32::from(rate) | (0x1f << 8) | (15 << 13);
        prefix[7] = frame.len() as u32;
        prefix[8] = address;
        // Fill through the actual live DMA mapping before it can be named
        // by OWN. Retain its owner before the first descriptor mutation.
        self.io.authority(true, || {
            buffer.write_bytes(0, frame)?;
            buffer.sync();
            Ok(())
        })?;
        self.packet.pending = Some(Pending {
            buffer,
            id,
            queue,
            slot,
            length: frame.len(),
            prefix,
        });
        self.packet.serial = id;
        self.phase = Phase::Failed;
        let ring = &mut self.tx[queue];
        self.io.authority(true, || {
            ring.sync();
            let offset = slot * TX_BYTES;
            if ring.read32(offset)? & OWN != 0 {
                return Err(Error::Descriptor);
            }
            // clear_pci_tx_desc_content preserves DW10's linked-next pointer.
            for (word, value) in prefix.iter().copied().enumerate() {
                ring.write32(offset + word * 4, value)?;
            }
            ring.sync();
            ring.write32(offset, prefix[0] | OWN)?;
            ring.sync();
            Ok(())
        })?;
        self.io.kick(poll)?;
        self.phase = Phase::Running;
        Ok(id)
    }
    fn delivery(&mut self) -> Result<Option<Delivery>, Error> {
        let Some(pending) = self.packet.pending.as_ref() else {
            return Ok(None);
        };
        let ring = &self.tx[pending.queue];
        let delivery = self.io.authority(true, || {
            ring.sync();
            let offset = pending.slot * TX_BYTES;
            if ring.read32(offset)? & OWN != 0 {
                return Ok(None);
            }
            // Retry counters and hardware FIFO page fields are not receipt
            // identities. Match the stable buffer/queue/length fields that
            // Linux uses to retire this exact descriptor, not mutable status.
            for word in [0, 1, 7, 8, 9] {
                if ring.read32(offset + word * 4)? != pending.prefix[word] {
                    return Err(Error::Descriptor);
                }
            }
            if ring.read32(offset + 40)?
                != ring.address() as u32 + (((pending.slot + 1) % self.depth) * TX_BYTES) as u32
                || ring.read32(offset + 44)? != 0
            {
                return Err(Error::Descriptor);
            }
            pending.buffer.sync();
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(pending.length)
                .map_err(|_| Error::Memory)?;
            bytes.resize(pending.length, 0);
            pending.buffer.read_bytes(0, &mut bytes)?;
            Ok(Some(Delivery {
                id: pending.id,
                bytes,
            }))
        })?;
        if delivery.is_some() {
            let queue = pending.queue;
            self.packet.next[queue] = (pending.slot + 1) % self.depth;
            self.packet.pending = None; // exact vendor terminal DMA receipt.
        }
        Ok(delivery)
    }
    pub(crate) fn poll_delivery(&mut self) -> Result<Option<Delivery>, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let result = self.delivery()?;
        self.phase = Phase::Running;
        Ok(result)
    }
    /// The complete owner stays retained if this future is dropped at any
    /// actual wait. No re-submission or completion can reopen the phase.
    pub(crate) async fn wait_delivery(&mut self, budget: usize) -> Result<Delivery, Error> {
        if self.phase != Phase::Running || self.packet.pending.is_none() || budget == 0 {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        for _ in 0..budget.min(10_000) {
            if let Some(delivery) = self.delivery()? {
                self.phase = Phase::Running;
                return Ok(delivery);
            }
            self.io.delay_us(100).await;
        }
        Err(Error::PacketTimeout)
    }
    pub(crate) fn poll_receive(&mut self) -> Result<Option<Mpdu>, Error> {
        self.poll_receive_step().map(|step| step.packet)
    }
    pub(crate) fn poll_receive_step(&mut self) -> Result<ReceiveStep, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let slot = self.packet.receive;
        let ring = self.receive.as_mut().ok_or(Error::State)?;
        let buffer = &self.buffers[slot];
        let channel = self.permission.ok_or(Error::State)?.channel();
        let (consumed, packet) = self.io.authority(true, || {
            ring.sync();
            let offset = slot * RX_BYTES;
            let status = ring.read32(offset)?;
            if status & OWN != 0 {
                return Ok((false, None));
            }
            let end = if slot + 1 == self.depth { 1 << 30 } else { 0 };
            if status & (1 << 30) != end
                || ring.read32(offset + 24)? != extent(buffer, RX_BUFFER, 4)?
                || ring.read32(offset + 28)? != 0
            {
                return Err(Error::Descriptor);
            }
            let extra = ring.read32(offset + 4)?;
            let sequence = ring.read32(offset + 8)?;
            let report = ring.read32(offset + 12)?;
            let length = (status & 0x3fff) as usize;
            let start = (((status >> 16) & 15) * 8 + ((status >> 24) & 3)) as usize;
            let ordinary = report & 0xc000 == 0;
            if ordinary && (length < 4 || start.checked_add(length).is_none_or(|n| n > RX_BUFFER)) {
                return Err(Error::Descriptor);
            }
            let mut packet = None;
            let ht = report & (1 << 6) != 0;
            let ht_profile = self.packet.ht
                && ht
                && (12..=19).contains(&(report & 63))
                && report & ((1 << 7) | (1 << 8) | (1 << 9)) == 0;
            let legacy_profile = !ht && report & (1 << 9) == 0 && report & 63 <= 11;
            // DW1 PAGGR/FAGGR (rtl8188ee trx.h): A-MPDU membership is only
            // admissible on the HT profile, where the station BA owner gates it.
            let aggregated = extra & (3 << 14) != 0;
            if ordinary
                && status & 0xc000 == 0
                && status & 0x3000_0000 == 0x3000_0000
                && extra & (1 << 27) == 0
                && (!aggregated || ht_profile)
                && sequence & 0xf000 == 0
                && (legacy_profile || ht_profile)
                && (24..=if self.packet.ht {
                    26 + 16 + narf_wireless::amsdu::MAX_BYTES + 4
                } else {
                    MAX_MPDU + 4
                })
                    .contains(&length)
            {
                buffer.sync();
                // EE's PHY info is its own28-byte structure inside drvinfo,
                // not rtw88 page1. RXD owns rate/BW; no channel field exists.
                if status & (1 << 26) != 0 {
                    let info = (((status >> 16) & 15) * 8) as usize;
                    if info < 28 {
                        return Err(Error::Descriptor);
                    }
                    let mut phy = [0; 28];
                    buffer.read_bytes(((status >> 24) & 3) as usize, &mut phy)?;
                    if ht && phy[27] & 2 != 0 {
                        // sgi_en: LGI-only receive profile.
                        for word in 0..6 {
                            ring.write32(offset + word * 4, 0)?;
                        }
                        buffer.sync();
                        ring.sync();
                        ring.write32(offset, RX_BUFFER as u32 | end | OWN)?;
                        ring.sync();
                        return Ok((true, None));
                    }
                }
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(length - 4)
                    .map_err(|_| Error::Memory)?;
                bytes.resize(length - 4, 0);
                buffer.read_bytes(start, &mut bytes)?;
                let fc = u16::from_le_bytes([bytes[0], bytes[1]]);
                // Open frames may legitimately have SWDEC clear (Linux trx.c).
                // Protected frames must retain their IV/CCMP ciphertext/MIC.
                if bytes.len() == 20 {
                    // BlockAckReq: RCR_ACF stays set (rtl8188ee sw.c receive_config;
                    // mac80211 never toggles FIF_CONTROL in station mode).
                    if fc == 0x84 && !aggregated && status & (1 << 23) == 0 {
                        packet = Some(Mpdu {
                            bytes,
                            channel,
                            ht,
                            aggregated,
                        });
                    }
                } else if bytes.len() >= 24
                    && fc & 0x400 == 0
                    && bytes[22] & 15 == 0
                    && (status & (1 << 23) != 0) == (fc & 0x8c == 0x88)
                    && (fc & 0x4000 == 0 || status & (1 << 27) != 0)
                    && (!aggregated || fc & 0xfc == 0x88)
                {
                    packet = Some(Mpdu {
                        bytes,
                        channel,
                        ht,
                        aggregated,
                    });
                }
            }
            for word in 0..6 {
                ring.write32(offset + word * 4, 0)?;
            }
            buffer.sync();
            ring.sync();
            ring.write32(offset, RX_BUFFER as u32 | end | OWN)?;
            ring.sync();
            Ok((true, packet))
        })?;
        if consumed {
            self.packet.receive = (slot + 1) % self.depth;
        }
        self.phase = Phase::Running;
        Ok(ReceiveStep { consumed, packet })
    }
    /// Terminal stop closes host admission first, attempts all independent
    /// packet/IRQ/PCI gates, and retains every published allocation. A parked
    /// command register is not presented as a DMA-prefetch reclamation proof.
    pub(crate) fn stop_packets(&mut self) -> Result<(), Error> {
        if matches!(
            self.phase,
            Phase::Stopped | Phase::Stopping | Phase::Allocated
        ) {
            return Err(Error::State);
        }
        self.phase = Phase::Stopping;
        self.packet.interrupts = false;
        self.packet.leisure = false;
        let mut result = Ok(());
        for operation in [
            self.io.write32(0xb0, 0).map_err(Error::from),
            self.io.write32(0xb8, 0).map_err(Error::from),
            self.io.write8(0x522, 0xff).map_err(Error::from),
            self.io.write8(0x301, 0xff).map_err(Error::from),
        ] {
            if result.is_ok() {
                result = operation;
            }
        }
        let close = (|| {
            let cr = self.io.read8(0x100)?;
            self.io.write8(0x100, cr & !0xcf)?;
            if self.io.read8(0x100)? & 0xcf != 0
                || self.io.read8(0x301)? != 0xff
                || self.io.read32(0xb0)? != 0
                || self.io.read32(0xb8)? != 0
            {
                return Err(Error::Readback);
            }
            Ok(())
        })();
        if result.is_ok() {
            result = close;
        }
        let park = self.io.master(false);
        if result.is_ok() {
            result = park;
        }
        self.phase = if result.is_ok() {
            Phase::Stopped
        } else {
            Phase::Failed
        };
        result
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "packet_tests.rs"]
pub(crate) mod tests;

// SPDX-License-Identifier: GPL-2.0-or-later
//! Live SDPCM/BCDC F2 service. References: Linux brcmfmac/{sdio,bcdc}.c.
//! One serialized IOCTL owns its transaction until completion; event/data
//! traffic can never satisfy its waiter. Host FIFO access is explicit.

use super::{events, ioctl, sdpcm::*, PacketTransport, TransportError};
use alloc::{collections::VecDeque, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};

pub const MAX_CONTROL: usize = 8192;
// Linux BRCMF_TX_IOCTL_MAX_MSG_SIZE (1518) includes the 16-byte dcmd header.
const MAX_CONTROL_INPUT: usize = 1502;
pub const MAX_PACKET: usize = 12 + 16 + MAX_CONTROL;
pub const QUEUE_DEPTH: usize = 32;
const RECEIVE_BUDGET: usize = 16;

#[path = "runtime_ap.rs"]
mod ap;
#[path = "runtime_pm.rs"]
mod pm;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Transport(TransportError),
    Malformed,
    Unsupported,
    Authority,
    Busy,
    Timeout,
    Failed,
    EventOverflow,
    Firmware(u32),
}
impl From<TransportError> for Error {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

#[derive(Debug)]
pub struct Event {
    pub header: events::EventHeader,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
struct Pending {
    id: u16,
    command: u32,
    direction: ioctl::Direction,
    maximum: usize,
}

/// One interface (firmware ifidx zero), with no aggregation or firmware
/// signalling offload. A caller serializes access with an async mutex.
pub struct Runtime<T: PacketTransport> {
    transport: Option<T>,
    stopped: bool,
    ap_live: Arc<AtomicBool>,
    ap: Option<alloc::boxed::Box<ap::Owner>>,
    /// Secondary-ifidx firmware-SME AP owners (one per open ifidx).
    vif_ap: Vec<ap::Owner>,
    tx_sequence: u8,
    tx_max: u8,
    flow_control: u8,
    /// Current 802.1D-to-AC rank map from negotiated firmware WMM state.
    ac_priority: [u8; 8],
    previous_rx: Option<u8>,
    transaction: u16,
    pending: Option<Pending>,
    response: Option<Result<Vec<u8>, Error>>,
    events: VecDeque<Event>,
    data: VecDeque<Vec<u8>>,
    /// Secondary-ifidx records; interface 0 keeps `events`/`data` above.
    vif: crate::brcmfmac::vif_demux::Demux,
    failed: bool,
    vendor: super::fullmac::FirmwareVendor,
    /// The bus is system-suspended (`runtime_pm.rs`): no FIFO access.
    suspended: bool,
    /// Linux `sdiodev->wowl_enabled` (`brcmf_bus_wowl_config`).
    wowl_enabled: bool,
}
impl<T: PacketTransport> Drop for Runtime<T> {
    fn drop(&mut self) {
        self.ap_live.store(false, Ordering::Release);
        if !self.stopped {
            // A dropped operation/runtime is no native device-stop receipt.
            // Keep the original host/card/register owner pinned on uncertainty.
            if let Some(transport) = self.transport.take() {
                core::mem::forget(transport);
            }
        }
    }
}
impl<T: PacketTransport> core::fmt::Debug for Runtime<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CywRuntime")
            .field("tx_sequence", &self.tx_sequence)
            .field("tx_max", &self.tx_max)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl<T: PacketTransport> Runtime<T> {
    /// Attach only after the firmware loader completed. Credit begins at
    /// zero: a real firmware SDPCM header must grant the initial TX window.
    pub fn new(transport: T) -> Self {
        Self {
            transport: Some(transport),
            stopped: false,
            ap_live: Arc::new(AtomicBool::new(true)),
            ap: None,
            vif_ap: Vec::new(),
            tx_sequence: 0,
            tx_max: 0,
            flow_control: 0,
            ac_priority: super::station::wmm::DEFAULT_AC_PRIORITY,
            previous_rx: None,
            transaction: 0,
            pending: None,
            response: None,
            events: VecDeque::new(),
            data: VecDeque::new(),
            vif: crate::brcmfmac::vif_demux::Demux::new(),
            failed: false,
            vendor: super::fullmac::FirmwareVendor::Wcc,
            suspended: false,
            wowl_enabled: false,
        }
    }

    /// Record the SDIO match's firmware vendor (Linux `brcmf_sdmmc_ids`:
    /// Broadcom-ID 43439 is WCC, Cypress-ID 43439 is CYW).
    pub fn with_firmware_vendor(mut self, vendor: super::fullmac::FirmwareVendor) -> Self {
        self.vendor = vendor;
        self
    }

    pub fn firmware_vendor(&self) -> super::fullmac::FirmwareVendor {
        self.vendor
    }

    pub fn is_failed(&self) -> bool {
        self.failed
    }

    pub fn fail(&mut self) {
        self.ap_live.store(false, Ordering::Release);
        self.failed = true;
        self.vif.clear();
        self.vif_ap.clear();
    }
    pub(crate) fn ap_source(&self) -> Option<crate::brcmfmac::ap_source::Source> {
        if self.failed || self.stopped {
            return None;
        }
        Some(self.transport.as_ref()?.ap_source()?.retain(&self.ap_live))
    }

    /// Close ordinary work first and retain the original transport through
    /// the full actual native receipt chain, even after a protocol failure.
    pub(crate) fn stop_transport(&mut self) -> Result<(), Error> {
        self.fail();
        if self.stopped {
            return Ok(());
        }
        self.transport
            .as_mut()
            .ok_or(Error::Failed)?
            .confirmed_stop()?;
        self.stopped = true;
        self.pending = None;
        self.response = None;
        self.events.clear();
        self.data.clear();
        self.vif.clear();
        Ok(())
    }
    pub(crate) fn release_transport(&mut self) -> bool {
        if !self.stopped {
            return false;
        }
        // Every native PIO borrow ended before its synchronous command
        // returned. The complete stop proof, not that fact alone, permits
        // dropping this original Card/register owner now.
        drop(self.transport.take());
        true
    }

    /// Install the station's negotiated AC rank map. SDPCM `fc_mask` bits
    /// name host precedences (`brcmf_map_prio_to_prec`), not 802.1D values.
    pub fn set_ac_priority(&mut self, ac_priority: [u8; 8]) {
        self.ac_priority = ac_priority;
    }

    pub fn pop_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    pub fn pop_data(&mut self) -> Option<Vec<u8>> {
        self.data.pop_front()
    }

    fn credits(&self) -> u8 {
        let count = self.tx_max.wrapping_sub(self.tx_sequence);
        if count & 0x80 == 0 {
            count
        } else {
            0
        }
    }

    /// Bounded FIFO service, also driven by an IOCTL waiter while it owns
    /// the device mutex. No other scheduler task is needed for completion.
    pub fn poll(&mut self) -> Result<usize, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        if self.suspended {
            // brcmf_sdiod_freezer: the DPC does not run while suspended.
            return Ok(0);
        }
        let result = self.poll_inner();
        if result.is_err() {
            self.fail();
        } else {
            // The SDIO IRQ thread re-enables the card interrupt after its
            // function handlers ran; a still-asserted line fires again.
            self.transport
                .as_mut()
                .ok_or(Error::Failed)?
                .interrupt_serviced();
            if result == Ok(0) {
                self.transport.as_mut().ok_or(Error::Failed)?.idle();
            }
        }
        result
    }
    pub fn interrupt(&self) -> Option<alloc::sync::Arc<crate::brcmfmac::irq::Signal>> {
        self.transport.as_ref()?.interrupt()
    }

    fn poll_inner(&mut self) -> Result<usize, Error> {
        let mut bytes = vec![0; MAX_PACKET];
        for count in 0..RECEIVE_BUDGET {
            let length = self
                .transport
                .as_mut()
                .ok_or(Error::Failed)?
                .receive_packet(&mut bytes)?;
            if length == 0 {
                return Ok(count);
            }
            let packet = bytes.get(..length).ok_or(Error::Malformed)?;
            self.receive(packet)?;
        }
        Ok(RECEIVE_BUDGET)
    }

    fn receive(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let hw = HwHeader::decode(bytes).map_err(|_| Error::Malformed)?;
        let length = usize::from(hw.length);
        if !(12..=MAX_PACKET).contains(&length) || length > bytes.len() {
            return Err(Error::Malformed);
        }
        let bytes = &bytes[..length];
        let sw = SwHeader::decode(&bytes[4..]).map_err(|_| Error::Malformed)?;
        let offset = usize::from(sw.data_offset);
        if !(12..=length).contains(&offset) || sw.flags != 0 {
            return Err(Error::Malformed);
        }
        if sw.channel > CHANNEL_DATA {
            return Err(Error::Unsupported); // GLOM was not negotiated.
        }
        if self.previous_rx == Some(sw.seq) {
            return Ok(()); // Never dispatch a duplicate control/event twice.
        }
        self.previous_rx = Some(sw.seq);
        self.flow_control = sw.fc_mask;
        // Linux guards nonsensical windows with the same 64-packet limit,
        // then grants two recovery credits rather than an arbitrary window.
        self.tx_max = if sw.max_seq.wrapping_sub(self.tx_sequence) > 0x40 {
            self.tx_sequence.wrapping_add(2)
        } else {
            sw.max_seq
        };
        let payload = &bytes[offset..];
        if payload.is_empty() {
            return Ok(()); // Header-only credit update.
        }
        match sw.channel {
            CHANNEL_CONTROL => self.control(payload),
            CHANNEL_EVENT | CHANNEL_DATA => {
                // BDC data header, distinct from the 16-byte IOCTL header.
                let bdc = payload.get(..4).ok_or(Error::Malformed)?;
                if bdc[0] >> 4 != 2 {
                    return Err(Error::Malformed);
                }
                // `BCDC_GET_IF_IDX`: flags2 low nibble names the interface.
                let if_idx = bdc[2] & 15;
                let body = payload
                    .get(4 + usize::from(bdc[3]) * 4..)
                    .ok_or(Error::Malformed)?;
                if sw.channel == CHANNEL_EVENT {
                    let event = events::parse_event(body).map_err(|_| Error::Malformed)?;
                    let header = event.header;
                    use crate::brcmfmac::vif_demux::{route, Route};
                    match route(header.event_type, header.if_idx, header.bsscfg_idx) {
                        Route::Primary => {}
                        Route::Secondary => {
                            return self
                                .vif
                                .push_event(Event {
                                    header,
                                    payload: event.payload.to_vec(),
                                })
                                .map_err(|_| Error::EventOverflow);
                        }
                        Route::Invalid => return Ok(()),
                    }
                    if self.events.len() == QUEUE_DEPTH {
                        return Err(Error::EventOverflow);
                    }
                    self.events.push_back(Event {
                        header,
                        payload: event.payload.to_vec(),
                    });
                } else {
                    if !(14..=1514).contains(&body.len())
                        || u16::from_be_bytes([body[12], body[13]]) < 0x600
                    {
                        return Err(Error::Malformed);
                    }
                    // Firmware events may not escape on the Ethernet path.
                    if body[12..14] == [0x88, 0x6c] {
                        return Err(Error::Malformed);
                    }
                    if if_idx != 0 {
                        // `brcmf_proto_bcdc_hdrpull`: an ifidx without a
                        // registered interface is dropped, not fatal.
                        self.vif.push_data(if_idx, body.to_vec());
                        return Ok(());
                    }
                    if self.data.len() == QUEUE_DEPTH {
                        self.data.pop_front();
                    }
                    self.data.push_back(body.to_vec());
                }
                Ok(())
            }
            _ => Err(Error::Unsupported),
        }
    }

    fn control(&mut self, payload: &[u8]) -> Result<(), Error> {
        let header = BcdcHeader::decode(payload).map_err(|_| Error::Malformed)?;
        let Some(pending) = self.pending else {
            return Ok(());
        };
        // Stale and wrong-command replies cannot affect the current
        // operation, including replies carrying an ERROR flag. As in Linux
        // bcdc.c (`brcmf_proto_bcdc_cmplt`/`brcmf_proto_bcdc_query_dcmd`),
        // a reply is correlated by its BCDC_DCMD_ID request id; the
        // BCDC_DCMD_IF_SHIFT ifidx of the reply is not consulted, so a
        // secondary-interface reply with a zeroed or different echo still
        // completes its own request.
        if header.xact_id() != pending.id
            || header.cmd != pending.command
            || header.is_set() != (pending.direction == ioctl::Direction::Set)
        {
            return Ok(());
        }
        // ERROR replies may retain the requested/needed length without
        // returning an information buffer. SET completion likewise consumes
        // only status in Linux bcdc.c; neither may be mistaken for a short
        // successful GET response.
        if header.flags & bcdc_flag::ERROR != 0 || header.status != 0 {
            self.response = Some(Err(Error::Firmware(header.status)));
            return Ok(());
        }
        if pending.direction == ioctl::Direction::Set {
            self.response = Some(Ok(Vec::new()));
            return Ok(());
        }
        let length = (header.len & 0xffff) as usize;
        if length > pending.maximum || length > payload.len() - BCDC_HEADER_LEN {
            return Err(Error::Malformed);
        }
        self.response = Some(Ok(payload[16..16 + length].to_vec()));
        Ok(())
    }

    /// Issue a serialized control command. Dropping this future after it
    /// starts poisons the session: a late reply may never complete a new
    /// request, and ambiguous commands are not automatically replayed.
    pub async fn command(
        &mut self,
        direction: ioctl::Direction,
        command: u32,
        payload: &[u8],
        maximum: usize,
    ) -> Result<Vec<u8>, Error> {
        self.command_scoped(0, direction, command, payload, maximum, None)
            .await
    }
    /// [`Self::command`] addressed to firmware interface `if_idx`
    /// (`brcmf_proto_bcdc_msg` `BCDC_DCMD_IF_SHIFT`). Interface 0 is the
    /// ordinary [`Self::command`]; a secondary ifidx carries no AP scope.
    pub async fn command_on(
        &mut self,
        if_idx: u8,
        direction: ioctl::Direction,
        command: u32,
        payload: &[u8],
        maximum: usize,
    ) -> Result<Vec<u8>, Error> {
        if if_idx >= crate::brcmfmac::vif_wire::MAX_IFS {
            return Err(Error::Malformed);
        }
        self.command_scoped(if_idx, direction, command, payload, maximum, None)
            .await
    }
    async fn command_scoped(
        &mut self,
        if_idx: u8,
        direction: ioctl::Direction,
        command: u32,
        payload: &[u8],
        maximum: usize,
        original: Option<&crate::brcmfmac::ap_scope::Capture>,
    ) -> Result<Vec<u8>, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        if self.pending.is_some() || self.suspended {
            return Err(Error::Busy);
        }
        if payload.len() > MAX_CONTROL_INPUT || maximum > MAX_CONTROL {
            return Err(Error::Malformed);
        }
        self.transaction = self.transaction.wrapping_add(1);
        let pending = Pending {
            id: self.transaction,
            command,
            direction,
            maximum,
        };
        self.pending = Some(pending);
        self.response = None;
        let mut transaction = Transaction {
            runtime: self,
            finished: false,
        };
        let deadline = narf_time::Deadline::after_ms(2000);
        while transaction.runtime.credits() == 0 {
            transaction.runtime.poll()?;
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            if transaction.runtime.credits() == 0 {
                delay().await;
            }
        }
        // Linux bcdc.c advertises the logical query buffer length and
        // transmits its zero-filled prefix (at most 1518 minus the dcmd
        // header). Firmware reads query arguments from that buffer.
        let logical_length = if direction == ioctl::Direction::Get {
            maximum.max(payload.len())
        } else {
            payload.len()
        };
        let wire_length = logical_length.min(MAX_CONTROL_INPUT);
        let mut body = zeroize::Zeroizing::new(vec![0; wire_length]);
        body[..payload.len()].copy_from_slice(payload);
        let mut request = zeroize::Zeroizing::new(ioctl::build_request(
            transaction.runtime.tx_sequence,
            pending.id,
            if_idx,
            direction,
            command,
            &body,
        ));
        if direction == ioctl::Direction::Get {
            request[16..20].copy_from_slice(&(logical_length as u32).to_le_bytes());
        }
        // The hardware header excludes physical alignment padding.
        request[..4].copy_from_slice(
            &HwHeader {
                length: (28 + wire_length) as u16,
            }
            .encode(),
        );
        loop {
            if direction == ioctl::Direction::Set
                && original.is_some_and(|original| {
                    if if_idx == 0 {
                        transaction
                            .runtime
                            .events
                            .iter()
                            .any(|event| original.program_event_blocks(&event.header))
                    } else {
                        transaction
                            .runtime
                            .vif
                            .events()
                            .filter(|event| event.header.if_idx == if_idx)
                            .any(|event| original.program_event_blocks(&event.header))
                    }
                })
            {
                // Do not program past a consumed native denial/replacement.
                // Benign BSS-UP and same-drain EAPOL stay queued, and actual
                // GET queries can inspect firmware without new RF/key/port
                // authority. Session still applies every record afterward.
                transaction.runtime.pending = None;
                transaction.finished = true;
                return Err(Error::Busy);
            }
            let transport = transaction
                .runtime
                .transport
                .as_mut()
                .ok_or(Error::Failed)?;
            let result = match original {
                Some(original) => transport.transmit_ap_control(&request, original),
                None => transport.transmit_packet(&request),
            };
            match result {
                Ok(()) => break,
                Err(super::TransportError::Busy) => {
                    transaction.runtime.poll()?;
                    if deadline.expired() {
                        return Err(Error::Timeout);
                    }
                    delay().await;
                }
                Err(super::TransportError::Denied) if original.is_some() => {
                    // No COMMAND entered. Clear only this unissued waiter;
                    // preserve sequence, queued native records and transport.
                    transaction.runtime.pending = None;
                    transaction.runtime.response = None;
                    transaction.finished = true;
                    return Err(Error::Authority);
                }
                Err(error) => return Err(error.into()),
            }
        }
        transaction.runtime.tx_sequence = transaction.runtime.tx_sequence.wrapping_add(1);
        loop {
            transaction.runtime.poll()?;
            if let Some(response) = transaction.runtime.response.take() {
                transaction.runtime.pending = None;
                transaction.finished = true;
                return response;
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            delay().await;
        }
    }

    pub fn send_data(&mut self, ethernet: &[u8], priority: u8) -> Result<(), Error> {
        if self.ap.is_some() {
            return Err(Error::Authority);
        }
        self.send_data_inner(0, ethernet, priority, None)
    }
    /// Transmit on secondary firmware interface `if_idx` (BDC
    /// `BCDC_SET_IF_IDX`). Only an ifidx its owner opened is admitted. The
    /// primary AP session owns interface 0 data only: BCDC addresses every
    /// packet by ifidx (`brcmf_proto_bcdc_hdrpush`), so a secondary
    /// interface keeps its own data beside it (Linux combo0).
    pub fn send_data_on(&mut self, if_idx: u8, ethernet: &[u8], priority: u8) -> Result<(), Error> {
        // A secondary AP owns its ifidx's data (`ap_send_if` only), as the
        // primary AP owns interface 0's.
        if if_idx == 0 || !self.vif.is_open(if_idx) || self.ap_owns_if(if_idx) {
            return Err(Error::Authority);
        }
        self.send_data_inner(if_idx, ethernet, priority, None)
    }
    pub fn vif_listen(&mut self, on: bool) {
        self.vif.listen(on);
    }
    pub fn event_composition(&mut self) -> &mut crate::brcmfmac::event_mask::Composition {
        self.vif.event_mask()
    }
    pub fn vif_open(&mut self, if_idx: u8) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        self.vif.open(if_idx)
    }
    /// BCDC holds no per-interface native resource; closing is immediate.
    pub fn vif_close(&mut self, if_idx: u8) -> bool {
        // An AP owner of this ifidx keeps it until its own stop retires it.
        if self.ap_owns_if(if_idx) {
            return false;
        }
        self.vif.close(if_idx);
        true
    }
    pub fn pop_vif_event(&mut self) -> Option<Event> {
        self.vif.pop_event()
    }
    pub fn pop_vif_data(&mut self, if_idx: u8) -> Option<Vec<u8>> {
        self.vif.pop_data(if_idx)
    }
    fn send_data_inner(
        &mut self,
        if_idx: u8,
        ethernet: &[u8],
        priority: u8,
        original: Option<&crate::brcmfmac::ap_scope::Capture>,
    ) -> Result<(), Error> {
        if self.suspended {
            return Err(Error::Busy);
        }
        if self.failed {
            return Err(Error::Failed);
        }
        if !(14..=1514).contains(&ethernet.len())
            || priority > 7
            || u16::from_be_bytes([ethernet[12], ethernet[13]]) < 0x600
        {
            return Err(Error::Malformed);
        }
        // Reserve two credits for control traffic, as Linux SDPCM does.
        let precedence = super::station::wmm::precedence(&self.ac_priority, priority);
        if self.credits() <= 2 || self.flow_control & (1 << precedence) != 0 {
            return Err(Error::Busy);
        }
        let length = 16 + ethernet.len();
        let mut bytes = vec![0; length.next_multiple_of(4)];
        bytes[..4].copy_from_slice(
            &HwHeader {
                length: length as u16,
            }
            .encode(),
        );
        bytes[4..12].copy_from_slice(
            &SwHeader {
                seq: self.tx_sequence,
                channel: CHANNEL_DATA,
                flags: 0,
                next_len_16: 0,
                data_offset: 12,
                fc_mask: 0,
                max_seq: 0,
            }
            .encode(),
        );
        bytes[12..16].copy_from_slice(&[0x20, priority, if_idx & 15, 0]);
        bytes[16..length].copy_from_slice(ethernet);
        let transport = self.transport.as_mut().ok_or(Error::Failed)?;
        let result = match original {
            Some(original) => transport.transmit_ap_packet(&bytes, original),
            None => transport.transmit_packet(&bytes),
        };
        if let Err(error) = result {
            if error == super::TransportError::Busy {
                return Err(Error::Busy);
            }
            if error == super::TransportError::Denied {
                return Err(Error::Authority);
            }
            self.fail();
            return Err(error.into());
        }
        self.tx_sequence = self.tx_sequence.wrapping_add(1);
        Ok(())
    }
}

async fn delay() {
    narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
}

struct Transaction<'a, T: PacketTransport> {
    runtime: &'a mut Runtime<T>,
    finished: bool,
}
impl<T: PacketTransport> Drop for Transaction<'_, T> {
    fn drop(&mut self) {
        if !self.finished {
            self.runtime.fail();
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "runtime_tests.rs"]
mod tests;

// SPDX-License-Identifier: GPL-2.0-or-later
//! Live SDPCM/BCDC F2 service. References: Linux brcmfmac/{sdio,bcdc}.c.
//! One serialized IOCTL owns its transaction until completion; event/data
//! traffic can never satisfy its waiter. Host FIFO access is explicit.

use super::{events, ioctl, sdpcm::*, PacketTransport, TransportError};
use alloc::{collections::VecDeque, vec, vec::Vec};

pub const MAX_CONTROL: usize = 8192;
// Linux BRCMF_TX_IOCTL_MAX_MSG_SIZE (1518) includes the 16-byte dcmd header.
const MAX_CONTROL_INPUT: usize = 1502;
pub const MAX_PACKET: usize = 12 + 16 + MAX_CONTROL;
pub const QUEUE_DEPTH: usize = 32;
const RECEIVE_BUDGET: usize = 16;

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
    transport: T,
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
    failed: bool,
    vendor: super::fullmac::FirmwareVendor,
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
            transport,
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
            failed: false,
            vendor: super::fullmac::FirmwareVendor::Wcc,
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
        self.failed = true;
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
        let result = self.poll_inner();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn poll_inner(&mut self) -> Result<usize, Error> {
        let mut bytes = vec![0; MAX_PACKET];
        for count in 0..RECEIVE_BUDGET {
            let length = self.transport.receive_packet(&mut bytes)?;
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
                if bdc[0] >> 4 != 2 || bdc[2] & 15 != 0 {
                    return Err(Error::Malformed);
                }
                let body = payload
                    .get(4 + usize::from(bdc[3]) * 4..)
                    .ok_or(Error::Malformed)?;
                if sw.channel == CHANNEL_EVENT {
                    let event = events::parse_event(body).map_err(|_| Error::Malformed)?;
                    let header = event.header;
                    if header.if_idx != 0 || header.bsscfg_idx != 0 {
                        return Ok(());
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
        // Stale, foreign-interface and wrong-command replies cannot affect
        // the current operation, including replies carrying an ERROR flag.
        if header.xact_id() != pending.id
            || header.if_idx() != 0
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
        if self.failed {
            return Err(Error::Failed);
        }
        if self.pending.is_some() {
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
            0,
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
            match transaction.runtime.transport.transmit_packet(&request) {
                Ok(()) => break,
                Err(super::TransportError::Busy) => {
                    transaction.runtime.poll()?;
                    if deadline.expired() {
                        return Err(Error::Timeout);
                    }
                    delay().await;
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
        bytes[12..16].copy_from_slice(&[0x20, priority, 0, 0]);
        bytes[16..length].copy_from_slice(ethernet);
        if let Err(error) = self.transport.transmit_packet(&bytes) {
            if error == super::TransportError::Busy {
                return Err(Error::Busy);
            }
            self.failed = true;
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
            self.runtime.failed = true;
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "runtime_tests.rs"]
mod tests;

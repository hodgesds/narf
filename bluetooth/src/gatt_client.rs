//! GATT client — ATT/GATT client role (issue #1313).
//!
//! Spec: Bluetooth Core Specification 5.3 Vol 3 Part F (ATT) and
//! Vol 3 Part G (GATT). Public Bluetooth SIG documents. No GPL
//! Linux source consulted.
//!   <https://www.bluetooth.com/specifications/specs/core-specification/>
//!
//! The client issues ATT requests over the pump's outbound ACL path
//! and demultiplexes responses, one connection at a time:
//!
//! - Discovery: Read By Group Type (primary services), Read By Type
//!   (characteristics), Find Information (descriptors), each looped
//!   from the last returned handle until the range end or an
//!   Attribute Not Found terminator.
//! - Read (Read Request), Write (Write Request), and notify/indicate
//!   subscription (Write Request to the CCCD).
//!
//! ## Invariants
//!
//! - ATT lock-step: at most one outstanding request per connection.
//!   A second issue while one is pending fails with
//!   [`GattClientError::RequestPending`]; the pending request
//!   completes only on its matching response, an Error Response, or
//!   a malformed-response failure — never on a stray PDU.
//! - Role separation lives in the pump, not here: this state machine
//!   only ever sees PDUs from a central-role connection (the pump
//!   demultiplexes on `gap::Central::connected_handle`). A response
//!   opcode that does not match the pending request, and a discovery
//!   response that does not parse to at least one record, fail the
//!   operation instead of silently completing it.
//! - Notifications are server-initiated and never disturb a pending
//!   request. Indications additionally queue a confirmation.
//! - No consumer exists yet: notifications accumulate in a bounded
//!   queue (oldest dropped past the cap) drained via
//!   [`Client::take_notifications`]. Routing them to input (#1314
//!   HOGP) is a follow-on lane.
//!
//! Out of scope here: MTU exchange (default ATT MTU 23 governs, so
//! writes longer than MTU-3 are rejected), Read Blob / long reads,
//! Prepare / Execute writes, and ATT over BR/EDR.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::att::{
    self, Pdu, ATT_ECODE_ATTRIBUTE_NOT_FOUND, ATT_ERROR_RSP, ATT_FIND_INFORMATION_RSP,
    ATT_HANDLE_VALUE_IND, ATT_HANDLE_VALUE_NTF, ATT_READ_BY_GROUP_TYPE_RSP, ATT_READ_BY_TYPE_RSP,
    ATT_READ_RSP, ATT_WRITE_RSP,
};
use crate::gatt::{CharacteristicRecord, DescriptorRecord, ServiceRecord};

/// Default ATT MTU on a fresh BLE link (Vol 3 Part F §3.4.2).
/// Either side may initiate Exchange MTU to grow it; this lane
/// does not, so it caps every request to this MTU.
const ATT_MTU: u16 = att::ATT_DEFAULT_MTU;

/// Notification queue cap. No consumer exists yet, so unbounded
/// growth would be a memory leak with no reader; oldest dropped.
const NOTIFICATION_QUEUE_CAP: usize = 16;

/// Errors from the GATT client API (issue #1313).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GattClientError {
    /// No pump registered for this controller index.
    NoPump,
    /// A pump step currently owns the core; retry after the step.
    Busy,
    /// No connection with this handle exists.
    NoConnection,
    /// The connection exists but is not central-role (the client
    /// only operates over connections this host initiated).
    NotCentral,
    /// An ATT request is already outstanding on this connection
    /// (ATT lock-step: one request at a time).
    RequestPending,
    /// Bad handle range: start handle 0, or end before start.
    BadRange,
    /// Write value exceeds the ATT MTU minus the 3-byte
    /// opcode+handle header (MTU exchange is out of scope).
    ValueTooLong,
}

/// Why a client operation terminated in failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ClientFailure {
    /// The peer answered with an Error Response.
    ErrorResponse(att::ErrorResponse),
    /// The peer answered with a PDU that is not the expected
    /// response, or a discovery response that does not parse to
    /// at least one record. The offending opcode is recorded.
    Malformed { opcode: u8 },
}

/// One outstanding ATT request. The `end` bound is the discovery
/// termination condition; `acc` accumulates records across
/// continuation responses.
#[derive(Debug)]
enum Pending {
    DiscoverServices {
        end: u16,
        acc: Vec<ServiceRecord>,
    },
    DiscoverCharacteristics {
        end: u16,
        acc: Vec<CharacteristicRecord>,
    },
    DiscoverDescriptors {
        end: u16,
        acc: Vec<DescriptorRecord>,
    },
    Read {
        handle: u16,
    },
    Write,
    Subscribe {
        cccd_handle: u16,
    },
}

impl Pending {
    /// The response opcode this pending request waits for.
    fn response_opcode(&self) -> u8 {
        match self {
            Pending::DiscoverServices { .. } => ATT_READ_BY_GROUP_TYPE_RSP,
            Pending::DiscoverCharacteristics { .. } => ATT_READ_BY_TYPE_RSP,
            Pending::DiscoverDescriptors { .. } => ATT_FIND_INFORMATION_RSP,
            Pending::Read { .. } => ATT_READ_RSP,
            Pending::Write | Pending::Subscribe { .. } => ATT_WRITE_RSP,
        }
    }

    /// The request opcode this pending request issued, used to
    /// validate that an Error Response answers this request.
    fn request_opcode(&self) -> u8 {
        match self {
            Pending::DiscoverServices { .. } => att::ATT_READ_BY_GROUP_TYPE_REQ,
            Pending::DiscoverCharacteristics { .. } => att::ATT_READ_BY_TYPE_REQ,
            Pending::DiscoverDescriptors { .. } => att::ATT_FIND_INFORMATION_REQ,
            Pending::Read { .. } => att::ATT_READ_REQ,
            Pending::Write | Pending::Subscribe { .. } => att::ATT_WRITE_REQ,
        }
    }
}

/// Per-connection GATT client state. Created by the pump when a
/// central-role connection lands, dropped with the connection.
#[derive(Debug, Default)]
pub struct Client {
    pending: Option<Pending>,
    services: Vec<ServiceRecord>,
    characteristics: Vec<CharacteristicRecord>,
    descriptors: Vec<DescriptorRecord>,
    subscribed: Vec<u16>,
    last_read: Option<(u16, Vec<u8>)>,
    last_error: Option<ClientFailure>,
    notifications: VecDeque<(u16, Vec<u8>)>,
}

impl Client {
    pub fn new() -> Self {
        Self::default()
    }

    /// `true` while an ATT request awaits its response.
    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Services from the last completed primary-service discovery.
    /// A fresh discovery replaces this list.
    pub fn services(&self) -> &[ServiceRecord] {
        &self.services
    }

    /// Characteristics accumulated across completed characteristic
    /// discoveries (range-scoped, so discoveries append).
    pub fn characteristics(&self) -> &[CharacteristicRecord] {
        &self.characteristics
    }

    /// Descriptors accumulated across completed descriptor
    /// discoveries (range-scoped, so discoveries append).
    pub fn descriptors(&self) -> &[DescriptorRecord] {
        &self.descriptors
    }

    /// CCCD handles with a live subscription from this client.
    pub fn subscribed(&self) -> &[u16] {
        &self.subscribed
    }

    /// Value from the last completed read, if any.
    pub fn last_read(&self) -> Option<(u16, Vec<u8>)> {
        self.last_read.clone()
    }

    /// Failure that terminated the last operation, if any.
    pub fn last_error(&self) -> Option<ClientFailure> {
        self.last_error
    }

    /// Drain queued notifications (handle, value). Indications are
    /// queued here too; their confirmation is sent immediately on
    /// receipt, not when drained.
    pub fn take_notifications(&mut self) -> Vec<(u16, Vec<u8>)> {
        self.notifications.drain(..).collect()
    }

    fn check_idle(&self) -> Result<(), GattClientError> {
        if self.pending.is_some() {
            return Err(GattClientError::RequestPending);
        }
        Ok(())
    }

    fn check_range(&self, start: u16, end: u16) -> Result<(), GattClientError> {
        self.check_idle()?;
        if start == 0 || end < start {
            return Err(GattClientError::BadRange);
        }
        Ok(())
    }

    /// Discover all primary services in `[start, end]`. Loops from
    /// the last returned end handle until the range end or an
    /// Attribute Not Found terminator.
    pub fn discover_services(&mut self, start: u16, end: u16) -> Result<Pdu, GattClientError> {
        self.check_range(start, end)?;
        self.pending = Some(Pending::DiscoverServices {
            end,
            acc: Vec::new(),
        });
        Ok(crate::gatt::build_discover_primary_services(start, end))
    }

    /// Discover all characteristics in `[start, end]`. Loops from
    /// the last returned declaration handle + 1.
    pub fn discover_characteristics(
        &mut self,
        start: u16,
        end: u16,
    ) -> Result<Pdu, GattClientError> {
        self.check_range(start, end)?;
        self.pending = Some(Pending::DiscoverCharacteristics {
            end,
            acc: Vec::new(),
        });
        Ok(crate::gatt::build_discover_characteristics(start, end))
    }

    /// Discover all descriptors in `[start, end]`. Loops from the
    /// last returned handle + 1.
    pub fn discover_descriptors(&mut self, start: u16, end: u16) -> Result<Pdu, GattClientError> {
        self.check_range(start, end)?;
        self.pending = Some(Pending::DiscoverDescriptors {
            end,
            acc: Vec::new(),
        });
        Ok(crate::gatt::build_discover_descriptors(start, end))
    }

    /// Read one characteristic value by handle.
    pub fn read(&mut self, handle: u16) -> Result<Pdu, GattClientError> {
        self.check_idle()?;
        if handle == 0 {
            return Err(GattClientError::BadRange);
        }
        self.pending = Some(Pending::Read { handle });
        Ok(att::build_read_request(handle))
    }

    /// Write one characteristic value by handle (Write Request,
    /// with response). Rejected when the value cannot fit the
    /// default ATT MTU: no MTU exchange in this lane.
    pub fn write(&mut self, handle: u16, value: &[u8]) -> Result<Pdu, GattClientError> {
        self.check_idle()?;
        if handle == 0 {
            return Err(GattClientError::BadRange);
        }
        if value.len() + 3 > ATT_MTU as usize {
            return Err(GattClientError::ValueTooLong);
        }
        self.pending = Some(Pending::Write);
        Ok(att::build_write_request(handle, value))
    }

    /// Subscribe to notifications (`notify == true`) or indications
    /// on a characteristic: a Write Request to its CCCD. CCCD value
    /// bits (Vol 3 Part G, Client Characteristic Configuration):
    /// bit 0 = notifications, bit 1 = indications.
    pub fn subscribe(&mut self, cccd_handle: u16, notify: bool) -> Result<Pdu, GattClientError> {
        self.check_idle()?;
        if cccd_handle == 0 {
            return Err(GattClientError::BadRange);
        }
        let value = if notify { [0x01, 0x00] } else { [0x02, 0x00] };
        self.pending = Some(Pending::Subscribe { cccd_handle });
        Ok(att::build_write_request(cccd_handle, &value))
    }

    /// Feed one inbound ATT PDU from a central-role connection.
    /// Returns outbound PDUs to send (discovery continuations,
    /// indication confirmations). Notifications never disturb a
    /// pending request; any other unexpected PDU while idle is
    /// dropped.
    pub fn feed(&mut self, pdu: &Pdu) -> Vec<Pdu> {
        match pdu.opcode {
            ATT_HANDLE_VALUE_NTF => {
                if let Some((handle, value)) = att::decode_handle_value(pdu) {
                    self.push_notification(handle, value);
                }
                Vec::new()
            }
            ATT_HANDLE_VALUE_IND => {
                if let Some((handle, value)) = att::decode_handle_value(pdu) {
                    self.push_notification(handle, value);
                    return alloc::vec![att::build_handle_value_confirmation()];
                }
                Vec::new()
            }
            ATT_ERROR_RSP => {
                self.feed_error(pdu);
                Vec::new()
            }
            _ => self.feed_response(pdu),
        }
    }

    fn push_notification(&mut self, handle: u16, value: &[u8]) {
        if self.notifications.len() >= NOTIFICATION_QUEUE_CAP {
            self.notifications.pop_front();
        }
        self.notifications.push_back((handle, value.to_vec()));
    }

    fn feed_error(&mut self, pdu: &Pdu) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        let Some(err) = att::decode_error_response(pdu) else {
            self.last_error = Some(ClientFailure::Malformed { opcode: pdu.opcode });
            return;
        };
        // An Error Response that does not answer this request is a
        // protocol violation, not a terminator.
        if err.request_opcode != pending.request_opcode() {
            self.last_error = Some(ClientFailure::Malformed { opcode: pdu.opcode });
            return;
        }
        if err.error_code == ATT_ECODE_ATTRIBUTE_NOT_FOUND {
            match pending {
                Pending::DiscoverServices { acc, .. } => {
                    // A fresh discovery replaces the service list.
                    self.services = acc;
                }
                Pending::DiscoverCharacteristics { acc, .. } => {
                    self.characteristics.extend(acc);
                }
                Pending::DiscoverDescriptors { acc, .. } => {
                    self.descriptors.extend(acc);
                }
                // Attribute Not Found on a read/write is a real
                // failure (bad handle), not a discovery terminator.
                _ => {
                    self.last_error = Some(ClientFailure::ErrorResponse(err));
                }
            }
        } else {
            self.last_error = Some(ClientFailure::ErrorResponse(err));
        }
    }

    fn feed_response(&mut self, pdu: &Pdu) -> Vec<Pdu> {
        let Some(pending) = self.pending.take() else {
            return Vec::new();
        };
        if pdu.opcode != pending.response_opcode() {
            // A response that does not answer the outstanding
            // request is a protocol violation; fail closed rather
            // than waiting forever for the real response.
            self.last_error = Some(ClientFailure::Malformed { opcode: pdu.opcode });
            return Vec::new();
        }
        match pending {
            Pending::DiscoverServices { end, mut acc } => {
                match parse_services_response(&pdu.params) {
                    Ok(records) => {
                        let last_end = records.last().map(|r| r.end_handle).unwrap_or(0);
                        acc.extend(records);
                        if last_end >= end {
                            self.services = acc;
                            Vec::new()
                        } else {
                            let next = last_end + 1;
                            self.pending = Some(Pending::DiscoverServices { end, acc });
                            alloc::vec![crate::gatt::build_discover_primary_services(next, end)]
                        }
                    }
                    Err(()) => {
                        self.last_error = Some(ClientFailure::Malformed { opcode: pdu.opcode });
                        Vec::new()
                    }
                }
            }
            Pending::DiscoverCharacteristics { end, mut acc } => {
                match parse_characteristics_response(&pdu.params) {
                    Ok(records) => {
                        let last_decl = records.last().map(|r| r.declaration_handle).unwrap_or(0);
                        acc.extend(records);
                        if last_decl >= end {
                            self.characteristics.extend(acc);
                            Vec::new()
                        } else {
                            let next = last_decl + 1;
                            self.pending = Some(Pending::DiscoverCharacteristics { end, acc });
                            alloc::vec![crate::gatt::build_discover_characteristics(next, end)]
                        }
                    }
                    Err(()) => {
                        self.last_error = Some(ClientFailure::Malformed { opcode: pdu.opcode });
                        Vec::new()
                    }
                }
            }
            Pending::DiscoverDescriptors { end, mut acc } => {
                match parse_descriptors_response(&pdu.params) {
                    Ok(records) => {
                        let last_handle = records.last().map(|r| r.handle).unwrap_or(0);
                        acc.extend(records);
                        if last_handle >= end {
                            self.descriptors.extend(acc);
                            Vec::new()
                        } else {
                            let next = last_handle + 1;
                            self.pending = Some(Pending::DiscoverDescriptors { end, acc });
                            alloc::vec![crate::gatt::build_discover_descriptors(next, end)]
                        }
                    }
                    Err(()) => {
                        self.last_error = Some(ClientFailure::Malformed { opcode: pdu.opcode });
                        Vec::new()
                    }
                }
            }
            Pending::Read { handle } => {
                // Read Response params are the value itself, which
                // may legitimately be empty.
                self.last_read = Some((handle, pdu.params.clone()));
                Vec::new()
            }
            Pending::Write => Vec::new(),
            Pending::Subscribe { cccd_handle } => {
                if !self.subscribed.contains(&cccd_handle) {
                    self.subscribed.push(cccd_handle);
                }
                Vec::new()
            }
        }
    }
}

/// A Read By Group Type Response parses to at least one record, or
/// the operation fails: a well-formed response always carries
/// records, so an empty parse means a malformed unit layout.
fn parse_services_response(params: &[u8]) -> Result<Vec<ServiceRecord>, ()> {
    if params.is_empty() {
        return Err(());
    }
    let unit = params[0] as usize;
    if unit < 6 || (params.len() - 1) % unit != 0 {
        return Err(());
    }
    let records = crate::gatt::parse_primary_services(params);
    if records.is_empty() {
        return Err(());
    }
    Ok(records)
}

/// Same structural rule for Read By Type Responses: the value is
/// properties (1) + value handle (2) + UUID (2 or 16), so a unit
/// below 7 cannot hold a record.
fn parse_characteristics_response(params: &[u8]) -> Result<Vec<CharacteristicRecord>, ()> {
    if params.is_empty() {
        return Err(());
    }
    let unit = params[0] as usize;
    if unit < 7 || (params.len() - 1) % unit != 0 {
        return Err(());
    }
    let records = crate::gatt::parse_characteristics(params);
    if records.is_empty() {
        return Err(());
    }
    Ok(records)
}

/// Find Information Responses carry a format byte (0x01 = 16-bit
/// UUIDs, 0x02 = 128-bit UUIDs); anything else is malformed.
fn parse_descriptors_response(params: &[u8]) -> Result<Vec<DescriptorRecord>, ()> {
    if params.is_empty() {
        return Err(());
    }
    let unit = match params[0] {
        0x01 => 4,
        0x02 => 18,
        _ => return Err(()),
    };
    if (params.len() - 1) % unit != 0 {
        return Err(());
    }
    let records = crate::gatt::parse_descriptors(params);
    if records.is_empty() {
        return Err(());
    }
    Ok(records)
}

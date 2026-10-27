// SPDX-License-Identifier: GPL-2.0-or-later
//
// drivers/wwan/src/session.rs — MBIM control-plane session driver
//
// Owns one MBIM conversation with a function: MBIM_OPEN, the Basic
// Connect command set (device caps, subscriber ready, radio state,
// packet service, connect, IP configuration), and MBIM_CLOSE — with
// transaction-id matching, fragmented COMMAND_DONE reassembly, and
// unsolicited INDICATE_STATUS capture (connect-state events are kept,
// never mistaken for a command response).
//
// The driver is transport-agnostic: [`MbimTransport`] is the seam.
// Production binds it to USB (crate::usb_mbim: encapsulated commands
// over the control pipe, NTBs over the bulk pair); fixtures bind it
// to a scripted fake modem. All wire encoding/decoding lives in
// crate::mbim; this module only sequences it.
//
// Concurrency: a modem is driven from one owner at a time
// (`&mut self` methods). The production binding keeps the modem in a
// take/put cell for exactly this reason. The transport itself is
// `Send + Sync` because the datapath pump shares the device handle
// with the control owner.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use crate::mbim::{
    self, ConnectInfo, ConnectSetParams, DeviceCapsInfo, IpConfigurationInfo, MbimHeader,
    MbimMessageType, MbimUuid, PacketServiceInfo, RadioStateInfo, SubscriberReadyInfo, CID_CONNECT,
    CID_DEVICE_CAPS, CID_IP_CONFIGURATION_INFO, CID_PACKET_SERVICE, CID_RADIO_STATE,
    CID_SUBSCRIBER_READY_STATUS, COMMAND_TYPE_QUERY, COMMAND_TYPE_SET, MBIM_STATUS_SUCCESS,
    MBIM_UUID_BASIC_CONNECT,
};
use crate::WwanError;

/// Maximum messages read while waiting for one response. Interleaved
/// notifications are legal, but a function that never answers the
/// outstanding transaction is broken, not chatty.
const MAX_INTERLEAVED_MESSAGES: usize = 64;

/// Maximum empty polls (transport returned 0 bytes) while waiting for
/// one response before declaring the function silent.
const MAX_EMPTY_POLLS: usize = 1000;

/// The transport seam under the MBIM session.
///
/// Control transfers carry whole MBIM messages (or single fragments of
/// them). Data transfers carry whole NTBs (crate::bearer). A receive
/// returning `Ok(0)` means "nothing available right now" — the session
/// driver polls with a bounded budget rather than blocking forever;
/// transports whose receive is a blocking hardware transfer simply
/// never return 0.
pub trait MbimTransport: Send + Sync {
    /// Send one MBIM control message (SEND_ENCAPSULATED_COMMAND on USB).
    async fn control_send(&self, msg: &[u8]) -> Result<(), WwanError>;
    /// Receive one MBIM control message (GET_ENCAPSULATED_RESPONSE on
    /// USB). Returns the number of bytes written into `buf`.
    async fn control_recv(&self, buf: &mut [u8]) -> Result<usize, WwanError>;
    /// Send one framed NTB on the data channel.
    async fn data_send(&self, ntb: &[u8]) -> Result<(), WwanError>;
    /// Receive one NTB from the data channel. Returns bytes written.
    async fn data_recv(&self, buf: &mut [u8]) -> Result<usize, WwanError>;
}

/// One MBIM conversation with a modem function.
pub struct MbimModem<T: MbimTransport> {
    transport: T,
    /// Next host-allocated transaction id (starts at 1; 0 is reserved
    /// by the spec for function-initiated messages).
    next_txn: u32,
    /// Whether MBIM_OPEN completed successfully.
    opened: bool,
    /// The MaxControlTransfer this host declared at OPEN; also the
    /// per-transfer read buffer size.
    max_control_transfer: u32,
    /// Most recent unsolicited CID_CONNECT event, if any.
    pending_connect_event: Option<ConnectInfo>,
    /// Last known activation state per session id, from connect /
    /// disconnect responses and unsolicited events.
    session_states: Vec<(u32, u32)>,
}

impl<T: MbimTransport> MbimModem<T> {
    /// Create a closed modem over `transport`.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            next_txn: 1,
            opened: false,
            max_control_transfer: 4096,
            pending_connect_event: None,
            session_states: Vec::new(),
        }
    }

    /// Borrow the underlying transport (the datapath pump uses the
    /// data channel of the same handle).
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Whether MBIM_OPEN has completed.
    pub fn is_open(&self) -> bool {
        self.opened
    }

    /// Take the most recent unsolicited CID_CONNECT event, if one was
    /// observed since the last take.
    pub fn take_connect_event(&mut self) -> Option<ConnectInfo> {
        self.pending_connect_event.take()
    }

    /// Last known activation state for `session_id`
    /// (mbim::ACTIVATION_STATE_*), if ever observed.
    pub fn session_state(&self, session_id: u32) -> Option<u32> {
        self.session_states
            .iter()
            .find(|(id, _)| *id == session_id)
            .map(|(_, state)| *state)
    }

    fn note_session_state(&mut self, session_id: u32, state: u32) {
        if let Some(slot) = self
            .session_states
            .iter_mut()
            .find(|(id, _)| *id == session_id)
        {
            slot.1 = state;
        } else {
            self.session_states.push((session_id, state));
        }
    }

    fn alloc_txn(&mut self) -> u32 {
        let txn = self.next_txn;
        self.next_txn = self.next_txn.wrapping_add(1);
        if self.next_txn == 0 {
            self.next_txn = 1;
        }
        txn
    }

    /// Read one control message into a fresh buffer. Returns the
    /// message bytes (trimmed to the header's MessageLength) or
    /// `Ok(None)` when the transport had nothing.
    async fn read_message(&self) -> Result<Option<Vec<u8>>, WwanError> {
        let mut buf = alloc::vec![0u8; self.max_control_transfer as usize];
        let n = self.transport.control_recv(&mut buf).await?;
        if n == 0 {
            return Ok(None);
        }
        let header = MbimHeader::decode(&buf[..n]).map_err(|_| WwanError::MalformedFrame)?;
        let len = header.message_length as usize;
        if len > n {
            // The function sent a message larger than the transfer we
            // offered — a spec violation we cannot reassemble from.
            return Err(WwanError::MalformedFrame);
        }
        buf.truncate(len);
        Ok(Some(buf))
    }

    /// Record an unsolicited message's payload if it is a connect
    /// event; anything else is observed and dropped (this driver does
    /// not subscribe to other CIDs' events).
    fn note_unsolicited(&mut self, msg: &[u8]) {
        if let Some(info) = mbim::parse_indicate_connect_event(msg) {
            self.note_session_state(info.session_id, info.activation_state);
            self.pending_connect_event = Some(info);
        }
    }

    /// Feed a message received outside a command exchange (e.g. from
    /// the USB notification drain) into the event state.
    pub fn note_external_message(&mut self, msg: &[u8]) {
        self.note_unsolicited(msg);
    }

    /// Wait for the response of type `expect` carrying transaction
    /// `txn`, skipping (and recording) unsolicited messages. Returns
    /// the raw response message.
    async fn await_response(
        &mut self,
        expect: MbimMessageType,
        txn: u32,
    ) -> Result<Vec<u8>, WwanError> {
        let mut messages = 0usize;
        let mut empty = 0usize;
        loop {
            let Some(msg) = self.read_message().await? else {
                empty += 1;
                if empty > MAX_EMPTY_POLLS {
                    return Err(WwanError::Timeout);
                }
                narf_scheduler::yield_now().await;
                continue;
            };
            messages += 1;
            if messages > MAX_INTERLEAVED_MESSAGES {
                return Err(WwanError::MalformedFrame);
            }
            let header = MbimHeader::decode(&msg).map_err(|_| WwanError::MalformedFrame)?;
            match header.message_type {
                MbimMessageType::IndicateStatus => {
                    self.note_unsolicited(&msg);
                }
                MbimMessageType::FunctionError => {
                    // MBIM_FUNCTION_ERROR_MSG: header + ErrorStatusCode.
                    if msg.len() >= mbim::MBIM_HEADER_SIZE + 4 {
                        let code = u32::from_le_bytes([msg[12], msg[13], msg[14], msg[15]]);
                        return Err(WwanError::ModemStatus(code));
                    }
                    return Err(WwanError::MalformedFrame);
                }
                t if t == expect => {
                    if header.transaction_id != txn {
                        // A late answer to an earlier, abandoned
                        // transaction: not ours, keep waiting.
                        continue;
                    }
                    return Ok(msg);
                }
                _ => {
                    // Any other response type while awaiting this one
                    // is a protocol violation by the function.
                    return Err(WwanError::MalformedFrame);
                }
            }
        }
    }

    /// MBIM_OPEN: declare the host's max control transfer and wait for
    /// MBIM_OPEN_DONE with a success status.
    pub async fn open(&mut self) -> Result<(), WwanError> {
        if self.opened {
            return Ok(());
        }
        let txn = self.alloc_txn();
        let msg = mbim::build_open(txn, self.max_control_transfer);
        self.transport.control_send(&msg).await?;
        let resp = self.await_response(MbimMessageType::OpenDone, txn).await?;
        let status = mbim::parse_done_status(&resp).map_err(|_| WwanError::MalformedFrame)?;
        if status != MBIM_STATUS_SUCCESS {
            return Err(WwanError::ModemStatus(status));
        }
        self.opened = true;
        Ok(())
    }

    /// MBIM_CLOSE: best-effort orderly shutdown of the conversation.
    pub async fn close(&mut self) -> Result<(), WwanError> {
        if !self.opened {
            return Ok(());
        }
        let txn = self.alloc_txn();
        let hdr = MbimHeader {
            message_type: MbimMessageType::Close,
            message_length: mbim::MBIM_HEADER_SIZE as u32,
            transaction_id: txn,
        };
        let mut msg = Vec::with_capacity(mbim::MBIM_HEADER_SIZE);
        msg.extend_from_slice(&hdr.encode());
        // From here the conversation is over whether or not the
        // function answers politely.
        self.opened = false;
        self.transport.control_send(&msg).await?;
        let resp = self.await_response(MbimMessageType::CloseDone, txn).await?;
        let status = mbim::parse_done_status(&resp).map_err(|_| WwanError::MalformedFrame)?;
        if status != MBIM_STATUS_SUCCESS {
            return Err(WwanError::ModemStatus(status));
        }
        Ok(())
    }

    /// Issue one Basic Connect (or other-service) command and return
    /// its `(status, information_buffer)` with fragmentation
    /// reassembled. A non-success status is NOT an error at this
    /// layer — the typed helpers below interpret it — but transport
    /// and framing failures are.
    pub async fn command(
        &mut self,
        service: &MbimUuid,
        cid: u32,
        command_type: u32,
        info: &[u8],
    ) -> Result<(u32, Vec<u8>), WwanError> {
        if !self.opened {
            return Err(WwanError::NotReady);
        }
        let txn = self.alloc_txn();
        let msg = mbim::build_command(txn, service, cid, command_type, info);
        self.transport.control_send(&msg).await?;

        // Reassembly state for the COMMAND_DONE.
        let mut status: Option<u32> = None;
        let mut assembled: Vec<u8> = Vec::new();
        let mut expect_fragment: u32 = 0;
        let mut total_fragments: u32 = 0;
        let mut messages = 0usize;
        let mut empty = 0usize;
        loop {
            let Some(msg) = self.read_message().await? else {
                empty += 1;
                if empty > MAX_EMPTY_POLLS {
                    return Err(WwanError::Timeout);
                }
                narf_scheduler::yield_now().await;
                continue;
            };
            messages += 1;
            if messages > MAX_INTERLEAVED_MESSAGES {
                return Err(WwanError::MalformedFrame);
            }
            let header = MbimHeader::decode(&msg).map_err(|_| WwanError::MalformedFrame)?;
            match header.message_type {
                MbimMessageType::IndicateStatus => {
                    self.note_unsolicited(&msg);
                }
                MbimMessageType::FunctionError => {
                    if msg.len() >= mbim::MBIM_HEADER_SIZE + 4 {
                        let code = u32::from_le_bytes([msg[12], msg[13], msg[14], msg[15]]);
                        return Err(WwanError::ModemStatus(code));
                    }
                    return Err(WwanError::MalformedFrame);
                }
                MbimMessageType::CommandDone => {
                    if header.transaction_id != txn {
                        continue;
                    }
                    let (_, frag, head) =
                        mbim::parse_command_head(&msg).map_err(|_| WwanError::MalformedFrame)?;
                    if frag.current_fragment != expect_fragment {
                        return Err(WwanError::MalformedFrame);
                    }
                    if frag.current_fragment == 0 {
                        // The head of the response must answer the
                        // command we sent — a different service/CID
                        // here means the function's framing is not
                        // trustworthy.
                        if head.service != *service || head.cid != cid {
                            return Err(WwanError::MalformedFrame);
                        }
                        status = head.status;
                        total_fragments = frag.total_fragments;
                    } else if frag.total_fragments != total_fragments {
                        return Err(WwanError::MalformedFrame);
                    }
                    let chunk = &msg[head.info_offset..];
                    assembled.extend_from_slice(chunk);
                    expect_fragment += 1;
                    if frag.current_fragment + 1 >= frag.total_fragments {
                        let status = status.ok_or(WwanError::MalformedFrame)?;
                        return Ok((status, assembled));
                    }
                }
                _ => return Err(WwanError::MalformedFrame),
            }
        }
    }

    /// Run a command that must succeed; map a non-success status to
    /// `WwanError::ModemStatus`.
    async fn command_ok(
        &mut self,
        cid: u32,
        command_type: u32,
        info: &[u8],
    ) -> Result<Vec<u8>, WwanError> {
        let (status, buf) = self
            .command(&MBIM_UUID_BASIC_CONNECT, cid, command_type, info)
            .await?;
        if status != MBIM_STATUS_SUCCESS {
            return Err(WwanError::ModemStatus(status));
        }
        Ok(buf)
    }

    /// Query MBIM_CID_DEVICE_CAPS.
    pub async fn device_caps(&mut self) -> Result<DeviceCapsInfo, WwanError> {
        let buf = self
            .command_ok(CID_DEVICE_CAPS, COMMAND_TYPE_QUERY, &[])
            .await?;
        DeviceCapsInfo::parse(&buf).map_err(|_| WwanError::MalformedFrame)
    }

    /// Query MBIM_CID_SUBSCRIBER_READY_STATUS.
    pub async fn subscriber_ready(&mut self) -> Result<SubscriberReadyInfo, WwanError> {
        let buf = self
            .command_ok(CID_SUBSCRIBER_READY_STATUS, COMMAND_TYPE_QUERY, &[])
            .await?;
        SubscriberReadyInfo::parse(&buf).map_err(|_| WwanError::MalformedFrame)
    }

    /// Query MBIM_CID_RADIO_STATE.
    pub async fn radio_state(&mut self) -> Result<RadioStateInfo, WwanError> {
        let buf = self
            .command_ok(CID_RADIO_STATE, COMMAND_TYPE_QUERY, &[])
            .await?;
        RadioStateInfo::parse(&buf).map_err(|_| WwanError::MalformedFrame)
    }

    /// Set the software radio state (MBIM_CID_RADIO_STATE set);
    /// returns the state the function reports back.
    pub async fn set_radio_state(&mut self, on: bool) -> Result<RadioStateInfo, WwanError> {
        let buf = self
            .command_ok(
                CID_RADIO_STATE,
                COMMAND_TYPE_SET,
                &mbim::build_radio_state_set(on),
            )
            .await?;
        RadioStateInfo::parse(&buf).map_err(|_| WwanError::MalformedFrame)
    }

    /// Query MBIM_CID_PACKET_SERVICE.
    pub async fn packet_service(&mut self) -> Result<PacketServiceInfo, WwanError> {
        let buf = self
            .command_ok(CID_PACKET_SERVICE, COMMAND_TYPE_QUERY, &[])
            .await?;
        PacketServiceInfo::parse(&buf).map_err(|_| WwanError::MalformedFrame)
    }

    /// Attach to or detach from the packet service
    /// (MBIM_CID_PACKET_SERVICE set); returns the reported state.
    pub async fn set_packet_service(
        &mut self,
        attach: bool,
    ) -> Result<PacketServiceInfo, WwanError> {
        let buf = self
            .command_ok(
                CID_PACKET_SERVICE,
                COMMAND_TYPE_SET,
                &mbim::build_packet_service_set(attach),
            )
            .await?;
        PacketServiceInfo::parse(&buf).map_err(|_| WwanError::MalformedFrame)
    }

    /// Activate a session (MBIM_CID_CONNECT set with
    /// ActivationCommand = ACTIVATE). Returns the function's reported
    /// connection state; callers check `activation_state` — a status
    /// of SUCCESS with state ACTIVATING means the bearer is still
    /// coming up (poll with [`Self::connect_query`]).
    pub async fn connect(&mut self, params: &ConnectSetParams) -> Result<ConnectInfo, WwanError> {
        let info = mbim::build_connect_set(params);
        let buf = self
            .command_ok(CID_CONNECT, COMMAND_TYPE_SET, &info)
            .await?;
        let parsed = ConnectInfo::parse(&buf).map_err(|_| WwanError::MalformedFrame)?;
        self.note_session_state(parsed.session_id, parsed.activation_state);
        Ok(parsed)
    }

    /// Query a session's connection state (MBIM_CID_CONNECT query).
    pub async fn connect_query(&mut self, session_id: u32) -> Result<ConnectInfo, WwanError> {
        let query = mbim::build_connect_query(session_id);
        let buf = self
            .command_ok(CID_CONNECT, COMMAND_TYPE_QUERY, &query)
            .await?;
        let parsed = ConnectInfo::parse(&buf).map_err(|_| WwanError::MalformedFrame)?;
        self.note_session_state(parsed.session_id, parsed.activation_state);
        Ok(parsed)
    }

    /// Deactivate a session (MBIM_CID_CONNECT set with
    /// ActivationCommand = DEACTIVATE).
    pub async fn disconnect(&mut self, session_id: u32) -> Result<ConnectInfo, WwanError> {
        let info = mbim::build_disconnect_set(session_id);
        let buf = self
            .command_ok(CID_CONNECT, COMMAND_TYPE_SET, &info)
            .await?;
        let parsed = ConnectInfo::parse(&buf).map_err(|_| WwanError::MalformedFrame)?;
        self.note_session_state(parsed.session_id, parsed.activation_state);
        Ok(parsed)
    }

    /// Query MBIM_CID_IP_CONFIGURATION_INFO for a connected session.
    pub async fn ip_configuration(
        &mut self,
        session_id: u32,
    ) -> Result<IpConfigurationInfo, WwanError> {
        let query = mbim::build_ip_configuration_query(session_id);
        let buf = self
            .command_ok(CID_IP_CONFIGURATION_INFO, COMMAND_TYPE_QUERY, &query)
            .await?;
        IpConfigurationInfo::parse(&buf).map_err(|_| WwanError::MalformedFrame)
    }
}

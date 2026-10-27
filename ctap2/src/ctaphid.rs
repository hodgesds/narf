//! CTAPHID transport framing (FIDO2 CTAP2 specification, CTAPHID
//! section) over a 64-byte HID report pipe.
//!
//! ## Wire facts (from the spec text)
//!
//! - Every report is exactly 64 bytes. An *initialization packet*
//!   is `CID(4, BE) | CMD(1, with the 0x80 bit set) | BCNT(2, BE) |
//!   payload(57)`; *continuation packets* are `CID(4) | SEQ(1,
//!   0x00..=0x7F) | payload(59)`. Unused tail bytes are zero on
//!   the wire from this client (authenticators ignore them).
//! - Commands: PING 0x01, MSG 0x03, LOCK 0x04, INIT 0x06,
//!   WINK 0x08, CBOR 0x10, CANCEL 0x11, KEEPALIVE 0x3B,
//!   ERROR 0x3F. Capability byte bits in the INIT response:
//!   WINK 0x01, CBOR 0x02, NMSG 0x04.
//! - INIT is sent on the broadcast CID 0xFFFFFFFF with an 8-byte
//!   nonce; the response echoes the nonce and carries the
//!   allocated CID (4), protocol version (1, = 2), device version
//!   (3), and capabilities (1) — 17 bytes total.
//! - KEEPALIVE frames arrive while the authenticator waits (e.g.
//!   for a touch); its payload is one status byte (1 = PROCESSING,
//!   2 = UP_NEEDED). ERROR frames carry one CTAPHID error code.
//!
//! The layer below the channel — actually moving reports — is the
//! [`HidPipe`] trait: `drivers/usb` implements it over an xHCI
//! interrupt endpoint pair; the fixture token implements it
//! in-process. Sequencing rules (one command in flight, sequence
//! numbers from 0) are enforced here so both transports inherit
//! them.

extern crate alloc;

use alloc::vec::Vec;

use crate::{Error, RandomSource};

/// HID report length for FIDO devices (fixed by the spec).
pub const REPORT_LEN: usize = 64;
/// Payload capacity of an initialization packet (64 − 7).
pub const INIT_PACKET_PAYLOAD: usize = 57;
/// Payload capacity of a continuation packet (64 − 5).
pub const CONT_PACKET_PAYLOAD: usize = 59;

/// The broadcast channel id, used only for INIT.
pub const CID_BROADCAST: u32 = 0xFFFF_FFFF;

pub const CMD_PING: u8 = 0x01;
pub const CMD_MSG: u8 = 0x03;
pub const CMD_LOCK: u8 = 0x04;
pub const CMD_INIT: u8 = 0x06;
pub const CMD_WINK: u8 = 0x08;
pub const CMD_CBOR: u8 = 0x10;
pub const CMD_CANCEL: u8 = 0x11;
pub const CMD_KEEPALIVE: u8 = 0x3B;
pub const CMD_ERROR: u8 = 0x3F;

/// INIT-response capability: the device supports CTAPHID_CBOR.
pub const CAP_CBOR: u8 = 0x02;
/// INIT-response capability: the device does NOT support
/// CTAPHID_MSG (U2F) — informational only for this client.
pub const CAP_NMSG: u8 = 0x04;
/// INIT-response capability: the device supports CTAPHID_WINK.
pub const CAP_WINK: u8 = 0x01;

/// KEEPALIVE status: the authenticator is processing.
pub const KEEPALIVE_PROCESSING: u8 = 1;
/// KEEPALIVE status: the authenticator needs user presence.
pub const KEEPALIVE_UP_NEEDED: u8 = 2;

/// CTAPHID errors (payload byte of a CMD_ERROR frame).
pub const ERR_INVALID_CMD: u8 = 0x01;
pub const ERR_INVALID_PAR: u8 = 0x02;
pub const ERR_INVALID_LEN: u8 = 0x03;
pub const ERR_INVALID_SEQ: u8 = 0x04;
pub const ERR_MSG_TIMEOUT: u8 = 0x05;
pub const ERR_CHANNEL_BUSY: u8 = 0x06;
pub const ERR_LOCK_REQUIRED: u8 = 0x0A;
pub const ERR_INVALID_CHANNEL: u8 = 0x0B;
pub const ERR_OTHER: u8 = 0x7F;

/// Upper bound on packets consumed by one exchange, keepalives
/// included. Real exchanges are a handful of data packets; a long
/// touch wait produces one keepalive per ~100 ms from YubiKey-class
/// firmware, so 4096 packets is ≫ any legitimate wait while still
/// bounding a babbling or hostile device.
pub const MAX_PACKETS_PER_EXCHANGE: usize = 4096;
/// Upper bound on one reassembled message (128 KiB; CTAP2's own
/// maxmsg cap is advertised via getInfo and enforced by the
/// client layer — this bound only stops memory exhaustion from a
/// lying BCNT).
pub const MAX_MESSAGE_LEN: usize = 128 * 1024;

/// A bidirectional 64-byte HID report pipe. Implementations move
/// exactly one report per call; `read_report` must give up with
/// [`Error::Timeout`] rather than block forever (the production
/// pipe bounds its poll loop; the fixture pipe returns
/// immediately).
pub trait HidPipe {
    fn write_report(&mut self, report: &[u8; REPORT_LEN]) -> Result<(), Error>;
    fn read_report(&mut self, out: &mut [u8; REPORT_LEN]) -> Result<(), Error>;
}

/// The parsed CTAPHID_INIT response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitResponse {
    pub cid: u32,
    pub protocol_version: u8,
    pub version_major: u8,
    pub version_minor: u8,
    pub version_build: u8,
    pub capabilities: u8,
}

/// One allocated CTAPHID channel. Owns the pipe; all CTAP2 traffic
/// for one authenticator goes through one channel.
pub struct Channel<P: HidPipe> {
    pipe: P,
    cid: u32,
    /// Count of UP_NEEDED keepalives seen by the last exchange —
    /// lets callers (and fixtures) prove a touch was actually
    /// required and awaited.
    last_keepalive_up_needed: usize,
}

impl<P: HidPipe> Channel<P> {
    /// Run CTAPHID_INIT on the broadcast channel: send an 8-byte
    /// nonce, validate its echo, adopt the allocated CID.
    pub fn init<R: RandomSource>(mut pipe: P, rng: &mut R) -> Result<(Self, InitResponse), Error> {
        let mut nonce = [0u8; 8];
        rng.fill_random(&mut nonce)?;
        let mut report = [0u8; REPORT_LEN];
        report[0..4].copy_from_slice(&CID_BROADCAST.to_be_bytes());
        report[4] = 0x80 | CMD_INIT;
        report[5..7].copy_from_slice(&8u16.to_be_bytes());
        report[7..15].copy_from_slice(&nonce);
        pipe.write_report(&report)?;

        // The response is a single INIT frame on the broadcast CID.
        let mut packets = 0usize;
        let resp_bytes = loop {
            packets += 1;
            if packets > MAX_PACKETS_PER_EXCHANGE {
                return Err(Error::Timeout);
            }
            let msg = Self::read_message(&mut pipe)?;
            match msg {
                Some((cid, cmd, payload)) => {
                    if cid != CID_BROADCAST {
                        continue; // not for us; keep waiting within budget
                    }
                    if cmd == CMD_ERROR {
                        return Err(Error::Hid(payload.first().copied().unwrap_or(ERR_OTHER)));
                    }
                    if cmd != CMD_INIT {
                        continue;
                    }
                    break payload;
                }
                None => continue,
            }
        };
        if resp_bytes.len() != 17 {
            return Err(Error::Protocol("ctaphid: INIT response length"));
        }
        if resp_bytes[..8] != nonce[..] {
            return Err(Error::Protocol("ctaphid: INIT nonce echo"));
        }
        let info = InitResponse {
            cid: u32::from_be_bytes([resp_bytes[8], resp_bytes[9], resp_bytes[10], resp_bytes[11]]),
            protocol_version: resp_bytes[12],
            version_major: resp_bytes[13],
            version_minor: resp_bytes[14],
            version_build: resp_bytes[15],
            capabilities: resp_bytes[16],
        };
        if info.cid == 0 || info.cid == CID_BROADCAST {
            return Err(Error::Protocol("ctaphid: INIT allocated reserved CID"));
        }
        let ch = Channel {
            pipe,
            cid: info.cid,
            last_keepalive_up_needed: 0,
        };
        Ok((ch, info))
    }

    /// Wrap an already-initialized pipe (fixture construction and
    /// transports that performed INIT themselves).
    pub fn from_parts(pipe: P, cid: u32) -> Self {
        Channel {
            pipe,
            cid,
            last_keepalive_up_needed: 0,
        }
    }

    pub fn cid(&self) -> u32 {
        self.cid
    }

    pub fn pipe_mut(&mut self) -> &mut P {
        &mut self.pipe
    }

    /// UP_NEEDED keepalives observed by the most recent exchange.
    pub fn last_keepalive_up_needed(&self) -> usize {
        self.last_keepalive_up_needed
    }

    /// Send one message and read its response message. Handles
    /// KEEPALIVE (counted, includes the UP_NEEDED count) and ERROR
    /// (surfaced as [`Error::Hid`]). Packets on other CIDs are
    /// skipped within the exchange budget.
    pub fn exchange(&mut self, cmd: u8, payload: &[u8]) -> Result<Vec<u8>, Error> {
        self.send_message(cmd, payload)?;
        self.last_keepalive_up_needed = 0;
        let mut packets = 0usize;
        loop {
            packets += 1;
            if packets > MAX_PACKETS_PER_EXCHANGE {
                return Err(Error::Timeout);
            }
            let Some((cid, rcmd, data)) = Self::read_message(&mut self.pipe)? else {
                continue;
            };
            if cid != self.cid {
                continue;
            }
            match rcmd {
                CMD_KEEPALIVE => {
                    if data.first() == Some(&KEEPALIVE_UP_NEEDED) {
                        self.last_keepalive_up_needed += 1;
                    }
                    continue;
                }
                CMD_ERROR => {
                    return Err(Error::Hid(data.first().copied().unwrap_or(ERR_OTHER)));
                }
                _ if rcmd == cmd => return Ok(data),
                _ => continue,
            }
        }
    }

    /// One CTAPHID_CBOR exchange: request = CTAP command byte ||
    /// CBOR params; response = status byte || CBOR data. A non-zero
    /// status becomes [`Error::Ctap`].
    pub fn exchange_cbor(&mut self, request: &[u8]) -> Result<Vec<u8>, Error> {
        let resp = self.exchange(CMD_CBOR, request)?;
        if resp.is_empty() {
            return Err(Error::Protocol("ctaphid: empty CBOR response"));
        }
        let status = resp[0];
        if status != crate::status::CTAP1_ERR_SUCCESS {
            return Err(Error::Ctap(status));
        }
        Ok(resp[1..].to_vec())
    }

    /// CTAPHID_PING round-trip (echo validation included).
    pub fn ping(&mut self, data: &[u8]) -> Result<(), Error> {
        let resp = self.exchange(CMD_PING, data)?;
        if resp != data {
            return Err(Error::Protocol("ctaphid: PING echo mismatch"));
        }
        Ok(())
    }

    /// CTAPHID_CANCEL — best-effort abort of a pending command.
    pub fn cancel(&mut self) -> Result<(), Error> {
        self.send_message(CMD_CANCEL, &[])
    }

    fn send_message(&mut self, cmd: u8, payload: &[u8]) -> Result<(), Error> {
        if payload.len() > u16::MAX as usize {
            return Err(Error::Protocol("ctaphid: message too large"));
        }
        let mut report = [0u8; REPORT_LEN];
        report[0..4].copy_from_slice(&self.cid.to_be_bytes());
        report[4] = 0x80 | cmd;
        report[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        let first = core::cmp::min(payload.len(), INIT_PACKET_PAYLOAD);
        report[7..7 + first].copy_from_slice(&payload[..first]);
        self.pipe.write_report(&report)?;
        let mut rest = &payload[first..];
        let mut seq: u8 = 0;
        while !rest.is_empty() {
            let mut report = [0u8; REPORT_LEN];
            report[0..4].copy_from_slice(&self.cid.to_be_bytes());
            report[4] = seq;
            seq = seq
                .checked_add(1)
                .ok_or(Error::Protocol("ctaphid: sequence overflow"))?;
            let n = core::cmp::min(rest.len(), CONT_PACKET_PAYLOAD);
            report[5..5 + n].copy_from_slice(&rest[..n]);
            self.pipe.write_report(&report)?;
            rest = &rest[n..];
        }
        Ok(())
    }

    /// Read one full framed message. Returns `None` when a stray
    /// continuation arrived without an opening packet (skipped).
    fn read_message(pipe: &mut P) -> Result<Option<(u32, u8, Vec<u8>)>, Error> {
        let mut report = [0u8; REPORT_LEN];
        pipe.read_report(&mut report)?;
        let cid = u32::from_be_bytes([report[0], report[1], report[2], report[3]]);
        if report[4] & 0x80 == 0 {
            return Ok(None); // continuation with no message in flight
        }
        let cmd = report[4] & 0x7F;
        let bcnt = u16::from_be_bytes([report[5], report[6]]) as usize;
        if bcnt > MAX_MESSAGE_LEN {
            return Err(Error::Protocol("ctaphid: BCNT exceeds bound"));
        }
        let mut buf = Vec::with_capacity(bcnt);
        let take = core::cmp::min(bcnt, INIT_PACKET_PAYLOAD);
        buf.extend_from_slice(&report[7..7 + take]);
        let mut expect_seq: u8 = 0;
        while buf.len() < bcnt {
            pipe.read_report(&mut report)?;
            let pcid = u32::from_be_bytes([report[0], report[1], report[2], report[3]]);
            if pcid != cid {
                return Err(Error::Protocol("ctaphid: CID changed mid-message"));
            }
            if report[4] & 0x80 != 0 {
                return Err(Error::Protocol("ctaphid: nested init packet"));
            }
            if report[4] != expect_seq {
                return Err(Error::Hid(ERR_INVALID_SEQ));
            }
            expect_seq = expect_seq.wrapping_add(1);
            let need = bcnt - buf.len();
            let take = core::cmp::min(need, CONT_PACKET_PAYLOAD);
            buf.extend_from_slice(&report[5..5 + take]);
        }
        Ok(Some((cid, cmd, buf)))
    }
}

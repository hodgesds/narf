//! RPMB (Replay Protected Memory Block) authenticated-frame protocol —
//! clean-room.
//!
//! Reference: **JEDEC Standard JESD84-B51 — "Embedded Multi-Media
//! Card (e•MMC) Electrical Standard (5.1)"** (public document),
//! §6.6.22 (the RPMB section; the issue's "§6.15" is the JESD84-B50
//! numbering — in B51 the section moved to §6.6.22).
//!
//! No GPL Linux source consulted. Cross-checked against the
//! independent public frame definitions in Microsoft's
//! `STORAGE_RPMB_DATA_FRAME` (ntddstor.h) and the QNX
//! `mmcsd_rpmb_frame` documentation, which reproduce the same
//! layout, and the Apache-2.0 armored-witness RPMB implementation,
//! which cites the same JESD84-B51 tables.
//!
//! ## Frame layout (Table 17, §6.6.22.1)
//!
//! One RPMB data frame is a 512-byte block, transmitted MSB first.
//! In buffer order (the order the bytes cross the DAT lines, and
//! the order the `STORAGE_RPMB_DATA_FRAME` struct lays them out):
//!
//! ```text
//!   offset  field           size
//!   0       Stuff bytes     196  (zero)
//!   196     Key / MAC       32   (key to program, or HMAC-SHA-256)
//!   228     Data            256  (one half-sector)
//!   484     Nonce           16   (host random, echoed in responses)
//!   500     Write Counter   4    (big-endian)
//!   504     Address         2    (big-endian half-sector index)
//!   506     Block Count     2    (big-endian half-sector count)
//!   508     Result          2    (big-endian; Table 19/20)
//!   510     Request/Resp    2    (big-endian; Table 18)
//! ```
//!
//! The spec numbers the same bytes [511:0] from the other end
//! (Stuff [511:316] … Type [1:0]); buffer offset `i` is spec byte
//! `511 - i`. The MAC input (§6.6.22.3) is "bytes [283:0] of the
//! data frame in that order" — spec bytes 283 down to 0, i.e.
//! buffer bytes [228..512]: Data || Nonce || Write Counter ||
//! Address || Block Count || Result || Type (284 bytes). The MAC
//! is HMAC-SHA-256 over that span under the programmed key
//! (RFC 2104 / RFC 4634); the MAC field itself and the stuff
//! bytes are excluded. For a multi-frame access the message is the
//! concatenation of each frame's [283:0] in send order and the MAC
//! goes only in the last frame (§6.6.22.3) — this module covers
//! single-frame accesses; multi-frame is a remainder.
//!
//! ## Message types (Table 18) and results (Tables 19/20)
//!
//! Requests 0x0001–0x0007 (key program, counter read, authenticated
//! write, authenticated read, result read, device-config write,
//! device-config read); responses are the request value shifted to
//! the high byte (0x0100–0x0700), except the result read, which has
//! no response type of its own — its response carries the type of
//! the programming access it reports (0x0100 / 0x0300 / 0x0600).
//! Results are 0x0000–0x0007 (OK, general, authentication, counter,
//! address, write, read, key-not-yet-programmed); bit 7 (0x0080)
//! marks a write counter that has reached its maximum
//! (0xFFFF_FFFF) and will never increment again — the parenthesised
//! values 0x0080–0x0086 in Table 20.
//!
//! ## What lives here vs the driver
//!
//! This module is the pure frame codec: layout, builders, field
//! accessors, and response checks that need no cryptography. The
//! HMAC itself (`narf_crypto::hkdf::hmac_sha256`) and the CMD23 +
//! CMD18/CMD25 transport live in the SDHCI driver's `rpmb` module,
//! which also owns the key-custody rule: the key is supplied
//! per-operation by the caller and is never stored by the driver.
//! The transport is CMD23 + CMD18/CMD25 per §6.6.22.4 — the
//! issue's "CMD17/CMD24" is not what B51 specifies for RPMB.

use core::convert::TryInto;

/// One RPMB data frame: 512 bytes on the wire.
pub const RPMB_FRAME_SIZE: usize = 512;

/// Byte span of the MAC input within a frame: buffer bytes
/// [228..512] (Data through Type), 284 bytes (§6.6.22.3).
pub const RPMB_MAC_MESSAGE_LEN: usize = 284;

/// Buffer offsets of the frame fields (see the module docs).
pub const RPMB_OFF_STUFF: usize = 0;
pub const RPMB_OFF_MAC: usize = 196;
pub const RPMB_OFF_DATA: usize = 228;
pub const RPMB_OFF_NONCE: usize = 484;
pub const RPMB_OFF_WRITE_COUNTER: usize = 500;
pub const RPMB_OFF_ADDRESS: usize = 504;
pub const RPMB_OFF_BLOCK_COUNT: usize = 506;
pub const RPMB_OFF_RESULT: usize = 508;
pub const RPMB_OFF_TYPE: usize = 510;

/// Lengths of the frame fields.
pub const RPMB_LEN_STUFF: usize = 196;
pub const RPMB_LEN_MAC: usize = 32;
pub const RPMB_LEN_DATA: usize = 256;
pub const RPMB_LEN_NONCE: usize = 16;

/// One half-sector: the RPMB data unit (§6.6.22.1, Data Address).
/// Addresses count half-sectors, so the partition holds
/// `rpmb_partition_bytes() / 256` of them.
pub const RPMB_HALF_SECTOR_BYTES: usize = 256;

/// Request message types (Table 18).
pub const RPMB_REQ_KEY_PROGRAM: u16 = 0x0001;
pub const RPMB_REQ_READ_COUNTER: u16 = 0x0002;
pub const RPMB_REQ_WRITE: u16 = 0x0003;
pub const RPMB_REQ_READ: u16 = 0x0004;
pub const RPMB_REQ_RESULT_READ: u16 = 0x0005;
pub const RPMB_REQ_CONFIG_WRITE: u16 = 0x0006;
pub const RPMB_REQ_CONFIG_READ: u16 = 0x0007;

/// Response message types (Table 18). 0x0500 is Reserved: the
/// result read has no response type of its own.
pub const RPMB_RESP_KEY_PROGRAM: u16 = 0x0100;
pub const RPMB_RESP_READ_COUNTER: u16 = 0x0200;
pub const RPMB_RESP_WRITE: u16 = 0x0300;
pub const RPMB_RESP_READ: u16 = 0x0400;
pub const RPMB_RESP_CONFIG_WRITE: u16 = 0x0600;
pub const RPMB_RESP_CONFIG_READ: u16 = 0x0700;

/// Operation results (Table 20), low 7 bits of the Result field.
pub const RPMB_RESULT_OK: u16 = 0x0000;
pub const RPMB_RESULT_GENERAL_FAILURE: u16 = 0x0001;
pub const RPMB_RESULT_AUTH_FAILURE: u16 = 0x0002;
pub const RPMB_RESULT_COUNTER_FAILURE: u16 = 0x0003;
pub const RPMB_RESULT_ADDRESS_FAILURE: u16 = 0x0004;
pub const RPMB_RESULT_WRITE_FAILURE: u16 = 0x0005;
pub const RPMB_RESULT_READ_FAILURE: u16 = 0x0006;
pub const RPMB_RESULT_KEY_NOT_PROGRAMMED: u16 = 0x0007;

/// Bit 7 of the Result field (Table 19): set permanently once the
/// write counter has reached 0xFFFF_FFFF (§6.6.22.2).
pub const RPMB_RESULT_COUNTER_EXPIRED: u16 = 0x0080;

/// Mask for the operation-result code within the Result field
/// (Table 19: bits [6:0]).
pub const RPMB_RESULT_CODE_MASK: u16 = 0x007F;

/// The operation-result code within a raw Result field value
/// (Table 19: bits [6:0]; bit 7 is the counter-expired flag).
pub fn result_code(raw: u16) -> u16 {
    raw & RPMB_RESULT_CODE_MASK
}

/// True when the raw Result field reports an expired write
/// counter (bit 7, Table 19).
pub fn counter_expired(raw: u16) -> bool {
    raw & RPMB_RESULT_COUNTER_EXPIRED != 0
}

/// The response type for a request type, or `None` for the result
/// read, which has no response type of its own (Table 18 note).
pub fn response_type_for(request: u16) -> Option<u16> {
    match request {
        RPMB_REQ_KEY_PROGRAM => Some(RPMB_RESP_KEY_PROGRAM),
        RPMB_REQ_READ_COUNTER => Some(RPMB_RESP_READ_COUNTER),
        RPMB_REQ_WRITE => Some(RPMB_RESP_WRITE),
        RPMB_REQ_READ => Some(RPMB_RESP_READ),
        RPMB_REQ_CONFIG_WRITE => Some(RPMB_RESP_CONFIG_WRITE),
        RPMB_REQ_CONFIG_READ => Some(RPMB_RESP_CONFIG_READ),
        _ => None,
    }
}

/// A failure of the RPMB frame protocol: a response that does not
/// authenticate, does not match the request, or reports a device
/// failure (Table 20). Transport failures are the caller's error
/// type, not this one.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RpmbError {
    /// The response MAC does not match the HMAC-SHA-256 computed
    /// under the caller's key.
    MacMismatch,
    /// The response nonce is not the nonce the request carried.
    NonceMismatch,
    /// The response type is not the response to this request.
    TypeMismatch,
    /// The response address is not the requested address.
    AddressMismatch,
    /// The response write counter is not the expected value
    /// (a write result must carry request counter + 1).
    CounterMismatch,
    /// The response block count is not the requested count.
    BlockCountMismatch,
    /// Device result 0x0001: general failure.
    GeneralFailure,
    /// Device result 0x0002: authentication failure (MAC
    /// comparison failed on the device side).
    AuthenticationFailure,
    /// Device result 0x0003: counter failure.
    CounterFailure,
    /// Device result 0x0004: address failure.
    AddressFailure,
    /// Device result 0x0005: write failure.
    WriteFailure,
    /// Device result 0x0006: read failure.
    ReadFailure,
    /// Device result 0x0007: the authentication key has not been
    /// programmed yet — the only valid result until it is.
    KeyNotProgrammed,
    /// A result code outside Table 20 (raw value attached).
    BadResult(u16),
}

impl RpmbError {
    /// Map a raw device Result field to the error it reports
    /// (`Ok` for 0x0000 / 0x0080 — the expired bit is orthogonal
    /// to success and the caller checks it separately).
    pub fn from_result(raw: u16) -> Result<(), RpmbError> {
        match result_code(raw) {
            RPMB_RESULT_OK => Ok(()),
            RPMB_RESULT_GENERAL_FAILURE => Err(RpmbError::GeneralFailure),
            RPMB_RESULT_AUTH_FAILURE => Err(RpmbError::AuthenticationFailure),
            RPMB_RESULT_COUNTER_FAILURE => Err(RpmbError::CounterFailure),
            RPMB_RESULT_ADDRESS_FAILURE => Err(RpmbError::AddressFailure),
            RPMB_RESULT_WRITE_FAILURE => Err(RpmbError::WriteFailure),
            RPMB_RESULT_READ_FAILURE => Err(RpmbError::ReadFailure),
            RPMB_RESULT_KEY_NOT_PROGRAMMED => Err(RpmbError::KeyNotProgrammed),
            _ => Err(RpmbError::BadResult(raw)),
        }
    }
}

/// One 512-byte RPMB data frame, in buffer (wire) order.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RpmbFrame {
    /// The frame bytes: stuff, MAC/key, data, nonce, counter,
    /// address, block count, result, type.
    pub bytes: [u8; RPMB_FRAME_SIZE],
}

// NOTE: manual impl, not `#[derive(Default)]`: the pinned toolchain
// (nightly-2025-09-14) only implements `Default` for arrays up to 32
// elements, and `bytes` is `[u8; RPMB_FRAME_SIZE]` (512).
impl Default for RpmbFrame {
    fn default() -> Self {
        Self::new()
    }
}

impl RpmbFrame {
    /// An all-zero frame.
    pub fn new() -> Self {
        Self {
            bytes: [0u8; RPMB_FRAME_SIZE],
        }
    }

    /// Wrap bytes received from the card.
    pub fn from_bytes(bytes: [u8; RPMB_FRAME_SIZE]) -> Self {
        Self { bytes }
    }

    /// The MAC / key field (32 bytes at [196..228]).
    pub fn mac(&self) -> [u8; RPMB_LEN_MAC] {
        self.bytes[RPMB_OFF_MAC..RPMB_OFF_MAC + RPMB_LEN_MAC]
            .try_into()
            .expect("slice is 32 bytes")
    }

    /// Set the MAC / key field.
    pub fn set_mac(&mut self, mac: &[u8; RPMB_LEN_MAC]) {
        self.bytes[RPMB_OFF_MAC..RPMB_OFF_MAC + RPMB_LEN_MAC].copy_from_slice(mac);
    }

    /// The Data field (256 bytes at [228..484]).
    pub fn data(&self) -> &[u8] {
        &self.bytes[RPMB_OFF_DATA..RPMB_OFF_DATA + RPMB_LEN_DATA]
    }

    /// Set the Data field.
    pub fn set_data(&mut self, data: &[u8; RPMB_LEN_DATA]) {
        self.bytes[RPMB_OFF_DATA..RPMB_OFF_DATA + RPMB_LEN_DATA].copy_from_slice(data);
    }

    /// The Nonce field (16 bytes at [484..500]).
    pub fn nonce(&self) -> [u8; RPMB_LEN_NONCE] {
        self.bytes[RPMB_OFF_NONCE..RPMB_OFF_NONCE + RPMB_LEN_NONCE]
            .try_into()
            .expect("slice is 16 bytes")
    }

    /// Set the Nonce field.
    pub fn set_nonce(&mut self, nonce: &[u8; RPMB_LEN_NONCE]) {
        self.bytes[RPMB_OFF_NONCE..RPMB_OFF_NONCE + RPMB_LEN_NONCE].copy_from_slice(nonce);
    }

    /// The Write Counter field (4 bytes, big-endian, [500..504]).
    pub fn write_counter(&self) -> u32 {
        u32::from_be_bytes(
            self.bytes[RPMB_OFF_WRITE_COUNTER..RPMB_OFF_WRITE_COUNTER + 4]
                .try_into()
                .expect("slice is 4 bytes"),
        )
    }

    /// Set the Write Counter field (big-endian).
    pub fn set_write_counter(&mut self, counter: u32) {
        self.bytes[RPMB_OFF_WRITE_COUNTER..RPMB_OFF_WRITE_COUNTER + 4]
            .copy_from_slice(&counter.to_be_bytes());
    }

    /// The Address field (2 bytes, big-endian, [504..506]): the
    /// half-sector index.
    pub fn address(&self) -> u16 {
        u16::from_be_bytes(
            self.bytes[RPMB_OFF_ADDRESS..RPMB_OFF_ADDRESS + 2]
                .try_into()
                .expect("slice is 2 bytes"),
        )
    }

    /// Set the Address field (big-endian).
    pub fn set_address(&mut self, address: u16) {
        self.bytes[RPMB_OFF_ADDRESS..RPMB_OFF_ADDRESS + 2].copy_from_slice(&address.to_be_bytes());
    }

    /// The Block Count field (2 bytes, big-endian, [506..508]):
    /// the half-sector count.
    pub fn block_count(&self) -> u16 {
        u16::from_be_bytes(
            self.bytes[RPMB_OFF_BLOCK_COUNT..RPMB_OFF_BLOCK_COUNT + 2]
                .try_into()
                .expect("slice is 2 bytes"),
        )
    }

    /// Set the Block Count field (big-endian).
    pub fn set_block_count(&mut self, count: u16) {
        self.bytes[RPMB_OFF_BLOCK_COUNT..RPMB_OFF_BLOCK_COUNT + 2]
            .copy_from_slice(&count.to_be_bytes());
    }

    /// The Result field (2 bytes, big-endian, [508..510]).
    pub fn result(&self) -> u16 {
        u16::from_be_bytes(
            self.bytes[RPMB_OFF_RESULT..RPMB_OFF_RESULT + 2]
                .try_into()
                .expect("slice is 2 bytes"),
        )
    }

    /// Set the Result field (big-endian).
    pub fn set_result(&mut self, result: u16) {
        self.bytes[RPMB_OFF_RESULT..RPMB_OFF_RESULT + 2].copy_from_slice(&result.to_be_bytes());
    }

    /// The Request/Response Type field (2 bytes, big-endian,
    /// [510..512]).
    pub fn req_type(&self) -> u16 {
        u16::from_be_bytes(
            self.bytes[RPMB_OFF_TYPE..RPMB_OFF_TYPE + 2]
                .try_into()
                .expect("slice is 2 bytes"),
        )
    }

    /// Set the Request/Response Type field (big-endian).
    pub fn set_req_type(&mut self, ty: u16) {
        self.bytes[RPMB_OFF_TYPE..RPMB_OFF_TYPE + 2].copy_from_slice(&ty.to_be_bytes());
    }

    /// The HMAC-SHA-256 input for this frame (§6.6.22.3): buffer
    /// bytes [228..512] — Data || Nonce || Write Counter ||
    /// Address || Block Count || Result || Type, 284 bytes.
    pub fn mac_message(&self) -> &[u8] {
        &self.bytes[RPMB_OFF_DATA..]
    }

    /// Constant-time MAC comparison (no early exit): the expected
    /// MAC against the MAC field of this frame.
    pub fn verify_mac(&self, expected: &[u8; RPMB_LEN_MAC]) -> Result<(), RpmbError> {
        if constant_time_eq(&self.mac(), expected) {
            Ok(())
        } else {
            Err(RpmbError::MacMismatch)
        }
    }

    /// Check this response frame against the request it answers:
    /// the type must be the request's response type, and the
    /// result must be OK. The MAC and nonce are checked by the
    /// caller (the MAC needs the key; the nonce needs the
    /// request's nonce — see the driver).
    pub fn check_response_type_and_result(&self, want_type: u16) -> Result<(), RpmbError> {
        if self.req_type() != want_type {
            return Err(RpmbError::TypeMismatch);
        }
        RpmbError::from_result(self.result())
    }

    /// Authentication-key programming request (§6.6.22.4.1,
    /// Table 22): type 0x0001 with the 32-byte key in the
    /// Key/MAC field. Everything else is zero; the key is
    /// write-once and can never be read back.
    pub fn key_program(key: &[u8; RPMB_LEN_MAC]) -> Self {
        let mut f = Self::new();
        f.set_req_type(RPMB_REQ_KEY_PROGRAM);
        f.set_mac(key);
        f
    }

    /// Write-counter read request (§6.6.22.4.2, Table 25): type
    /// 0x0002 with the host nonce. The request carries no MAC
    /// (the MAC field stays zero); the response is MAC'd.
    pub fn counter_read(nonce: &[u8; RPMB_LEN_NONCE]) -> Self {
        let mut f = Self::new();
        f.set_req_type(RPMB_REQ_READ_COUNTER);
        f.set_nonce(nonce);
        f
    }

    /// Result-register read request (§6.6.22.4.1/§6.6.22.4.3,
    /// Tables 23/28): type 0x0005, everything else zero. The
    /// response carries the type of the programming access it
    /// reports — never 0x0500.
    pub fn result_read() -> Self {
        let mut f = Self::new();
        f.set_req_type(RPMB_REQ_RESULT_READ);
        f
    }

    /// Authenticated data write request (§6.6.22.4.3, Table 27):
    /// type 0x0003, block count 1, the current write counter,
    /// the start address, and one half-sector of data. The MAC
    /// field is left zero for the caller to fill with the
    /// HMAC-SHA-256 of [`RpmbFrame::mac_message`]; the nonce
    /// stays zero for writes.
    pub fn data_write(counter: u32, address: u16, data: &[u8; RPMB_LEN_DATA]) -> Self {
        let mut f = Self::new();
        f.set_req_type(RPMB_REQ_WRITE);
        f.set_write_counter(counter);
        f.set_address(address);
        f.set_block_count(1);
        f.set_data(data);
        f
    }

    /// Authenticated data read request (§6.6.22.4.4, Table 30):
    /// type 0x0004 with the host nonce and the start address.
    /// The block count is deliberately zero here: the NOTE in
    /// §6.6.22.4.4 says the read block count is not indicated
    /// in the request packet — the CMD23 count on the CMD18
    /// that reads the data back is the read's block count. The
    /// MAC field is left zero for the caller to fill.
    pub fn data_read(nonce: &[u8; RPMB_LEN_NONCE], address: u16) -> Self {
        let mut f = Self::new();
        f.set_req_type(RPMB_REQ_READ);
        f.set_nonce(nonce);
        f.set_address(address);
        f
    }
}

/// Constant-time equality for two MACs: XOR-accumulate, no early
/// exit, so a comparison failure leaks nothing about the position
/// of the first differing byte.
pub fn constant_time_eq(a: &[u8; RPMB_LEN_MAC], b: &[u8; RPMB_LEN_MAC]) -> bool {
    let mut diff = 0u8;
    for i in 0..RPMB_LEN_MAC {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

//! RPMB authenticated-frame protocol on the eMMC driver — clean-room.
//!
//! Reference: **JEDEC Standard JESD84-B51 — "Embedded Multi-Media
//! Card (e•MMC) Electrical Standard (5.1)"** (public document),
//! §6.6.22 (Tables 17–20, §6.6.22.3 MAC, §6.6.22.4 accesses).
//! The frame codec lives in `crate::rpmb`; this module owns the
//! transport and the authenticated operations.
//!
//! No GPL Linux source consulted.
//!
//! ## Premise corrections (against issue #1622's text)
//!
//! - The section is **§6.6.22 in B51**, not §6.15 — that is the
//!   JESD84-B50 numbering. The spec text was read in-session
//!   (archive.org full text of JESD84-B51).
//! - The transport is **CMD23 + CMD18/CMD25**, not CMD17/CMD24:
//!   §6.6.22.4 says the master "can use the Multiple Block read
//!   and Multiple Block Write commands (CMD23, CMD18 and CMD25)"
//!   after switching PARTITION_CONFIG to the RPMB partition, and
//!   every access sequence in §6.6.22.4.1–§6.6.22.4.6 is written
//!   that way. CMD23 carries the pre-defined block count (bit 31
//!   = reliable-write request, §6.6.8.1); no CMD12 is needed —
//!   the CMD23 count terminates the transfer (§6.6.7.1/§6.6.8.1).
//!
//! ## Operations (single-frame, 256 bytes each)
//!
//! - `rpmb_program_key` — one-time key programming (§6.6.22.4.1).
//! - `rpmb_read_counter` — authenticated counter read
//!   (§6.6.22.4.2).
//! - `rpmb_write` — authenticated data write + result readback
//!   (§6.6.22.4.3), verifying the result counter is exactly the
//!   requested counter + 1 (CVE-2020-13799).
//! - `rpmb_read` — authenticated data read (§6.6.22.4.4).
//!
//! Multi-frame transfers (512 B / 8 KB, §6.6.22.4.3) and the
//! authenticated device-configuration accesses (0x0006/0x0007,
//! §6.6.22.4.5/§6.6.22.4.6) are remainders, not implemented here.
//!
//! ## Key custody
//!
//! The authentication key is supplied per operation by the
//! caller and is **never stored** by the driver — no key field
//! exists on any driver struct. The program-key frame, which
//! carries the key in the clear, is wiped (volatile writes +
//! fence) before `rpmb_program_key` returns on every path. The
//! key itself is the caller's to program out-of-band (OEM
//! production, §6.6.22); the power-suspend KEYS-domain design
//! is the custody pattern a future caller should follow.
//!
//! ## Nonces and MACs
//!
//! Every authenticated read / counter read draws a fresh 16-byte
//! nonce from `narf_crypto::try_fill_random_bytes` (hardware
//! seeded, the same source the wireless drivers use for
//! nonces). An entropy failure aborts the operation — a
//! predictable nonce would defeat the replay protection, so
//! there is no fallback. Frame MACs are HMAC-SHA-256 under the
//! caller's key (`narf_crypto::hkdf::hmac_sha256`, clean-room
//! SHA-256 per FIPS 180-4, RFC 4231-tested in-tree). Responses
//! are MAC-verified before any field they report is trusted,
//! except the key-not-programmed result (0x0007), which by
//! definition carries no MAC — no key exists yet to compute
//! one — and the key-program result, which Table 24 shows
//! un-MAC'd.
//!
//! ## Publication
//!
//! RPMB is exposed only through these authenticated methods —
//! never as a plain block device. The partition switch
//! (PARTITION_CONFIG access 3) is restored to the user area
//! after every operation (§6.6.22.4: "the PARTITION_ACCESS
//! bits should be cleared"), and every operation runs under
//! the caller's `with_controller` request gate, so a
//! multi-command sequence cannot interleave with another
//! controller user mid-sequence.

use core::sync::atomic::{compiler_fence, Ordering};

use narf_crypto::hkdf::hmac_sha256;

use crate::emmc::{PARTITION_ACCESS_RPMB, PARTITION_ACCESS_USER};
use crate::rpmb::{
    result_code, RpmbError as ProtocolError, RpmbFrame, RPMB_FRAME_SIZE, RPMB_LEN_DATA,
    RPMB_LEN_MAC, RPMB_LEN_NONCE, RPMB_RESP_KEY_PROGRAM, RPMB_RESP_READ, RPMB_RESP_READ_COUNTER,
    RPMB_RESP_WRITE, RPMB_RESULT_KEY_NOT_PROGRAMMED,
};

use super::{Sdhci, SdhciError, RESP_48};

/// A failure of an RPMB operation: a transport failure, or a
/// frame-protocol failure (a response that does not
/// authenticate, does not match its request, or reports a
/// device failure per JESD84-B51 Table 20).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RpmbError {
    /// No eMMC card is installed on this controller.
    NoCard,
    /// The card reports a zero-size RPMB partition.
    NoRpmb,
    /// The half-sector address is past the RPMB partition.
    OutOfRange,
    /// The nonce RNG failed; the operation was aborted rather
    /// than run with a predictable nonce.
    NoEntropy,
    /// The SDHCI transport failed (CMD timeout, PIO stall, a
    /// refused SWITCH, …).
    Transport(SdhciError),
    /// The frame protocol failed (MAC, nonce, counter, or a
    /// device-reported result).
    Protocol(ProtocolError),
}

impl From<SdhciError> for RpmbError {
    fn from(e: SdhciError) -> Self {
        RpmbError::Transport(e)
    }
}

impl From<ProtocolError> for RpmbError {
    fn from(e: ProtocolError) -> Self {
        RpmbError::Protocol(e)
    }
}

/// Wipe a buffer that held key material (the program-key frame).
/// Volatile writes + a fence so the wipe survives optimisation;
/// the driver never stores the key, and this keeps the transient
/// copy from lingering on the stack.
fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` references a valid mutable byte slice element in `buf`.
        unsafe { core::ptr::write_volatile(b as *mut u8, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Validate a response frame against its request: the type must
/// be the request's response type; the key-not-programmed result
/// (0x0007) is returned without a MAC check — no key exists yet
/// to compute one; otherwise the MAC over bytes [283:0] under
/// `key` is verified before the nonce echo and the result code
/// are trusted, so a spoofed failure cannot pass as genuine.
fn check_response(
    resp: &RpmbFrame,
    want_type: u16,
    want_nonce: Option<&[u8; RPMB_LEN_NONCE]>,
    key: &[u8; RPMB_LEN_MAC],
) -> Result<(), RpmbError> {
    if resp.req_type() != want_type {
        return Err(RpmbError::Protocol(ProtocolError::TypeMismatch));
    }
    if result_code(resp.result()) == RPMB_RESULT_KEY_NOT_PROGRAMMED {
        return Err(RpmbError::Protocol(ProtocolError::KeyNotProgrammed));
    }
    let expect = hmac_sha256(key, resp.mac_message());
    resp.verify_mac(&expect)?;
    if let Some(nonce) = want_nonce {
        if resp.nonce() != *nonce {
            return Err(RpmbError::Protocol(ProtocolError::NonceMismatch));
        }
    }
    ProtocolError::from_result(resp.result())?;
    Ok(())
}

impl Sdhci {
    /// RPMB capacity in 256-byte half-sectors (§6.6.22.1: the
    /// Data Address counts half-sectors). Errors when no eMMC
    /// card is installed, or the card reports no RPMB partition.
    pub fn rpmb_half_sectors(&self) -> Result<u32, RpmbError> {
        let card = self.emmc.lock().ok_or(RpmbError::NoCard)?;
        let bytes = card.ext_csd.rpmb_partition_bytes();
        if bytes == 0 {
            return Err(RpmbError::NoRpmb);
        }
        Ok((bytes / RPMB_LEN_DATA as u64) as u32)
    }

    /// Fail unless `address` names a half-sector inside the RPMB
    /// partition.
    fn rpmb_check_address(&self, address: u16) -> Result<(), RpmbError> {
        if (address as u32) >= self.rpmb_half_sectors()? {
            return Err(RpmbError::OutOfRange);
        }
        Ok(())
    }

    /// Switch the card to the RPMB partition (PARTITION_CONFIG
    /// access 3, CMD6 + CMD13 via `ensure_partition_access`).
    fn rpmb_switch_to(&self) -> Result<(), RpmbError> {
        self.ensure_partition_access(PARTITION_ACCESS_RPMB)?;
        Ok(())
    }

    /// Switch back to the user area after an RPMB access
    /// (§6.6.22.4: "the PARTITION_ACCESS bits should be
    /// cleared"). Best-effort: a failed switch leaves the card
    /// on RPMB, but the access cache still tracks the card (it
    /// only updates on a verified switch), so the next I/O
    /// re-switches correctly instead of addressing the wrong
    /// partition.
    fn rpmb_switch_back(&self) {
        let _ = self.ensure_partition_access(PARTITION_ACCESS_USER);
    }

    /// SET_BLOCK_COUNT (CMD23, R1) for the immediately following
    /// CMD18/CMD25 (§6.6.7.1/§6.6.8.1): the pre-defined block
    /// count in bits [15:0], with the reliable-write request bit
    /// (bit 31, §6.6.8.1) set for programming accesses.
    fn rpmb_set_block_count(&self, count: u16, reliable: bool) -> Result<(), RpmbError> {
        let arg = (count as u32) | if reliable { 1 << 31 } else { 0 };
        let _ = self.cmd(23, arg, RESP_48, false, 0, 0, 0)?;
        Ok(())
    }

    /// Send one RPMB request frame: CMD23 (count 1,
    /// reliable-write when `reliable`) + CMD25, argument 0 —
    /// the RPMB address lives in the frame; the CMD25 argument
    /// is ignored (§6.6.22.1, Data Address).
    fn rpmb_send_frame(
        &self,
        reliable: bool,
        frame: &[u8; RPMB_FRAME_SIZE],
    ) -> Result<(), RpmbError> {
        self.rpmb_set_block_count(1, reliable)?;
        self.write_pio_block(25, 0, true, frame)?;
        Ok(())
    }

    /// Receive one RPMB response frame: CMD23 (count 1) + CMD18,
    /// argument 0.
    fn rpmb_recv_frame(&self, out: &mut [u8; RPMB_FRAME_SIZE]) -> Result<(), RpmbError> {
        self.rpmb_set_block_count(1, false)?;
        self.read_pio_block(18, 0, true, out)?;
        Ok(())
    }

    /// A fresh 16-byte host nonce (§6.6.22.1: random per
    /// request, echoed in the response). An entropy failure
    /// aborts the operation — there is no fallback to a
    /// predictable nonce.
    fn rpmb_fresh_nonce() -> Result<[u8; RPMB_LEN_NONCE], RpmbError> {
        let mut nonce = [0u8; RPMB_LEN_NONCE];
        narf_crypto::try_fill_random_bytes(&mut nonce).map_err(|_| RpmbError::NoEntropy)?;
        Ok(nonce)
    }

    /// Read the result register after a programming access
    /// (§6.6.22.4.1/§6.6.22.4.3): CMD23(1) + CMD25 with the
    /// type-0x0005 request, then CMD23(1) + CMD18 for the
    /// response, which carries the programming access's response
    /// type. With `key` the response is MAC-verified (the write
    /// result); without it — the key-program result, which
    /// Table 24 shows un-MAC'd — the check is type + result
    /// only.
    fn rpmb_result_read(
        &self,
        want_type: u16,
        key: Option<&[u8; RPMB_LEN_MAC]>,
    ) -> Result<RpmbFrame, RpmbError> {
        self.rpmb_send_frame(false, &RpmbFrame::result_read().bytes)?;
        let mut raw = [0u8; RPMB_FRAME_SIZE];
        self.rpmb_recv_frame(&mut raw)?;
        let resp = RpmbFrame::from_bytes(raw);
        match key {
            Some(key) => {
                check_response(&resp, want_type, None, key)?;
            }
            None => {
                resp.check_response_type_and_result(want_type)?;
            }
        }
        Ok(resp)
    }

    /// Program the RPMB authentication key (§6.6.22.4.1).
    /// One-time and irreversible: the key register is
    /// write-once and can never be overwritten, erased, or read
    /// back, so this must run in a secure environment (OEM
    /// production, §6.6.22). The key is supplied per call and
    /// never stored; the frame carrying it is wiped before
    /// returning. Assumes the caller holds the request gate
    /// (see `with_controller`).
    pub fn rpmb_program_key(&self, key: &[u8; RPMB_LEN_MAC]) -> Result<(), RpmbError> {
        // No address is involved, but the card must exist and
        // have an RPMB partition to program.
        let _ = self.rpmb_half_sectors()?;
        self.rpmb_switch_to()?;
        let mut frame = RpmbFrame::key_program(key);
        let r = self.rpmb_program_key_inner(&frame);
        zeroize(&mut frame.bytes);
        self.rpmb_switch_back();
        r
    }

    fn rpmb_program_key_inner(&self, frame: &RpmbFrame) -> Result<(), RpmbError> {
        self.rpmb_send_frame(true, &frame.bytes)?;
        let _ = self.rpmb_result_read(RPMB_RESP_KEY_PROGRAM, None)?;
        Ok(())
    }

    /// Read the RPMB write counter, authenticated
    /// (§6.6.22.4.2): the request carries a fresh nonce and no
    /// MAC; the response echoes the nonce, carries the counter,
    /// and is MAC-verified. Assumes the caller holds the
    /// request gate.
    pub fn rpmb_read_counter(&self, key: &[u8; RPMB_LEN_MAC]) -> Result<u32, RpmbError> {
        let _ = self.rpmb_half_sectors()?;
        self.rpmb_switch_to()?;
        let r = self.rpmb_read_counter_inner(key);
        self.rpmb_switch_back();
        r
    }

    /// Counter read with the RPMB partition already selected.
    fn rpmb_read_counter_inner(&self, key: &[u8; RPMB_LEN_MAC]) -> Result<u32, RpmbError> {
        let nonce = Self::rpmb_fresh_nonce()?;
        let req = RpmbFrame::counter_read(&nonce);
        self.rpmb_send_frame(false, &req.bytes)?;
        let mut raw = [0u8; RPMB_FRAME_SIZE];
        self.rpmb_recv_frame(&mut raw)?;
        let resp = RpmbFrame::from_bytes(raw);
        check_response(&resp, RPMB_RESP_READ_COUNTER, Some(&nonce), key)?;
        Ok(resp.write_counter())
    }

    /// Authenticated read of one half-sector (256 bytes) at
    /// `address` (§6.6.22.4.4): the request is MAC'd under the
    /// key and carries a fresh nonce; the response is
    /// MAC-verified and its nonce, address, and block count are
    /// checked against the request. The write-counter field of
    /// a read response is 0x00 by spec and carries no meaning
    /// here — it is not checked. Assumes the caller holds the
    /// request gate.
    pub fn rpmb_read(
        &self,
        key: &[u8; RPMB_LEN_MAC],
        address: u16,
        out: &mut [u8; RPMB_LEN_DATA],
    ) -> Result<(), RpmbError> {
        self.rpmb_check_address(address)?;
        self.rpmb_switch_to()?;
        let r = self.rpmb_read_inner(key, address, out);
        self.rpmb_switch_back();
        r
    }

    /// Authenticated read with the RPMB partition already
    /// selected.
    fn rpmb_read_inner(
        &self,
        key: &[u8; RPMB_LEN_MAC],
        address: u16,
        out: &mut [u8; RPMB_LEN_DATA],
    ) -> Result<(), RpmbError> {
        let nonce = Self::rpmb_fresh_nonce()?;
        let mut req = RpmbFrame::data_read(&nonce, address);
        req.set_mac(&hmac_sha256(key, req.mac_message()));
        self.rpmb_send_frame(false, &req.bytes)?;
        let mut raw = [0u8; RPMB_FRAME_SIZE];
        self.rpmb_recv_frame(&mut raw)?;
        let resp = RpmbFrame::from_bytes(raw);
        check_response(&resp, RPMB_RESP_READ, Some(&nonce), key)?;
        if resp.address() != address {
            return Err(RpmbError::Protocol(ProtocolError::AddressMismatch));
        }
        if resp.block_count() != 1 {
            return Err(RpmbError::Protocol(ProtocolError::BlockCountMismatch));
        }
        out.copy_from_slice(resp.data());
        Ok(())
    }

    /// Authenticated write of one half-sector (256 bytes) at
    /// `address` (§6.6.22.4.3): reads the current counter,
    /// sends the MAC'd write request (reliable write), then
    /// reads the result register and verifies the result
    /// counter is exactly the requested counter + 1
    /// (CVE-2020-13799: an uncommitted write left behind by an
    /// interrupted earlier attempt must not pass as this
    /// write's success). Assumes the caller holds the request
    /// gate.
    pub fn rpmb_write(
        &self,
        key: &[u8; RPMB_LEN_MAC],
        address: u16,
        data: &[u8; RPMB_LEN_DATA],
    ) -> Result<(), RpmbError> {
        self.rpmb_check_address(address)?;
        self.rpmb_switch_to()?;
        let r = self.rpmb_write_inner(key, address, data);
        self.rpmb_switch_back();
        r
    }

    /// Authenticated write with the RPMB partition already
    /// selected.
    fn rpmb_write_inner(
        &self,
        key: &[u8; RPMB_LEN_MAC],
        address: u16,
        data: &[u8; RPMB_LEN_DATA],
    ) -> Result<(), RpmbError> {
        // The request carries the counter as the device last
        // reported it; the device increments it on success, so
        // a replayed frame fails the counter comparison.
        let counter = self.rpmb_read_counter_inner(key)?;
        let mut req = RpmbFrame::data_write(counter, address, data);
        req.set_mac(&hmac_sha256(key, req.mac_message()));
        self.rpmb_send_frame(true, &req.bytes)?;
        let resp = self.rpmb_result_read(RPMB_RESP_WRITE, Some(key))?;
        if resp.write_counter() != counter.wrapping_add(1) {
            return Err(RpmbError::Protocol(ProtocolError::CounterMismatch));
        }
        if resp.address() != address {
            return Err(RpmbError::Protocol(ProtocolError::AddressMismatch));
        }
        Ok(())
    }
}

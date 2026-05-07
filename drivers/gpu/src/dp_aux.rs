//! DisplayPort AUX channel framing — clean-room.
//!
//! Reference: VESA DisplayPort 1.4a Standard, §2.7 "AUX channel
//! transactions". The AUX channel is the side-band that lets the
//! source query / configure the sink (panel EDID over native AUX,
//! HPD events, link training command/response, …).
//!   <https://vesa.org/vesa-standards/>
//!
//! ## Frame format
//!
//! Every AUX request is 4 + 0..16 bytes. Header layout:
//!
//! ```text
//! byte 0  bits[7:4]  command   (NATIVE_WRITE/READ, I2C_WRITE/READ, …)
//!         bits[3:0]  high nibble of address
//! byte 1  middle byte of address
//! byte 2  low byte of address
//! byte 3  data length - 1     (0 → 1 byte, 15 → 16 bytes)
//! byte 4..N  data (writes only)
//! ```
//!
//! Replies are 1 + 0..16 bytes. The first byte is a status
//! nibble (`AUX_NACK`, `AUX_DEFER`, `I2C_NACK`, …) shifted up by 4.
//!
//! The transport (writing the request bytes into a DCN AUX
//! channel and waiting for the response) is a per-family DCN
//! register sequence — the framing layer here is transport-
//! agnostic so a future native-AUX impl + a virtio-gpu / passive
//! impl can share the same `AuxRequest` / `AuxResponse` shape.

/// AUX command nibble, encoded in bits[7:4] of byte 0 of the
/// request frame.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuxCommand {
    /// Native AUX write — DPCD register configuration.
    NativeWrite = 0x8,
    /// Native AUX read — DPCD register query.
    NativeRead = 0x9,
    /// I²C-over-AUX write (used for EDID-DDC).
    I2cWrite = 0x0,
    /// I²C-over-AUX read.
    I2cRead = 0x1,
    /// I²C-over-AUX write with stop-on-completion (single transaction).
    I2cWriteMot = 0x4,
    /// I²C-over-AUX read with stop-on-completion.
    I2cReadMot = 0x5,
}

/// Reply status nibble, in bits[7:4] of the response's byte 0.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuxStatus {
    /// Native AUX or I²C transaction succeeded.
    Ack = 0x0,
    /// Native NACK — the sink rejected the address.
    Nack = 0x1,
    /// Native DEFER — sink wants the source to retry later.
    Defer = 0x2,
    /// I²C NACK — slave didn't acknowledge.
    I2cNack = 0x4,
    /// I²C DEFER.
    I2cDefer = 0x8,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AuxError {
    /// Caller passed > 16 bytes of payload — AUX caps at 16.
    TooLong,
    /// Reply length didn't match the requested transfer.
    ShortReply,
    /// Reply status nibble wasn't a documented value.
    UnknownStatus,
    /// Sink returned NACK / I2C_NACK.
    Nacked,
    /// Sink wants the source to back off and retry.
    Deferred,
}

/// One pending AUX transaction. `data` is the write payload for
/// writes; the buffer for reads.
#[derive(Debug)]
pub struct AuxRequest<'a> {
    pub cmd: AuxCommand,
    pub address: u32, // 20-bit DPCD address; high bits ignored.
    pub data: &'a [u8],
}

/// Decoded reply. `data` is empty for write replies; carries the
/// returned bytes for reads.
#[derive(Debug)]
pub struct AuxResponse<'a> {
    pub status: AuxStatus,
    pub data: &'a [u8],
}

/// Encode `req` into the wire 4 + N byte frame. `out` receives
/// the frame; returns the number of bytes written.
pub fn encode_request<'a>(req: &AuxRequest<'a>, out: &mut [u8]) -> Result<usize, AuxError> {
    if req.data.len() > 16 {
        return Err(AuxError::TooLong);
    }
    let n = req.data.len();
    let total = 4 + if matches!(
        req.cmd,
        AuxCommand::NativeWrite | AuxCommand::I2cWrite | AuxCommand::I2cWriteMot
    ) {
        n
    } else {
        0
    };
    if out.len() < total {
        return Err(AuxError::TooLong);
    }
    let cmd = (req.cmd as u8) & 0x0F;
    out[0] = (cmd << 4) | ((req.address >> 16) as u8 & 0x0F);
    out[1] = (req.address >> 8) as u8;
    out[2] = req.address as u8;
    out[3] = if n == 0 { 0 } else { (n - 1) as u8 };
    let writeback = matches!(
        req.cmd,
        AuxCommand::NativeWrite | AuxCommand::I2cWrite | AuxCommand::I2cWriteMot
    );
    if writeback {
        out[4..4 + n].copy_from_slice(req.data);
    }
    Ok(total)
}

/// Decode a wire 1 + N byte reply into `(status, payload)`.
/// `expected_data_len` is the request's length — replies for
/// reads must carry exactly that many data bytes; replies for
/// writes carry zero.
pub fn decode_response<'a>(
    raw: &'a [u8],
    expected_data_len: usize,
) -> Result<AuxResponse<'a>, AuxError> {
    if raw.is_empty() {
        return Err(AuxError::ShortReply);
    }
    let status_nib = (raw[0] >> 4) & 0x0F;
    let status = match status_nib {
        0x0 => AuxStatus::Ack,
        0x1 => AuxStatus::Nack,
        0x2 => AuxStatus::Defer,
        0x4 => AuxStatus::I2cNack,
        0x8 => AuxStatus::I2cDefer,
        _ => return Err(AuxError::UnknownStatus),
    };
    let payload = &raw[1..];
    if payload.len() != expected_data_len {
        return Err(AuxError::ShortReply);
    }
    match status {
        AuxStatus::Ack => Ok(AuxResponse {
            status,
            data: payload,
        }),
        AuxStatus::Nack | AuxStatus::I2cNack => Err(AuxError::Nacked),
        AuxStatus::Defer | AuxStatus::I2cDefer => Err(AuxError::Deferred),
    }
}

/// Transport interface for an AUX channel. A future
/// `narf-drivers-gpu/amdgpu` DCN implementation programs the
/// AUX register block; today the trait exists so any modeset
/// path can be written transport-agnostic.
pub trait AuxChannel {
    /// Send `req` and receive the full reply. The implementation
    /// owns retry / DEFER backoff; the caller sees a single
    /// success/failure result.
    fn transact<'a>(
        &mut self,
        req: &AuxRequest<'_>,
        reply_buf: &'a mut [u8],
    ) -> Result<AuxResponse<'a>, AuxError>;

    /// Read `len` bytes from DPCD address `addr` (NATIVE_READ).
    /// Convenience wrapper around `transact`.
    fn dpcd_read(&mut self, addr: u32, buf: &mut [u8]) -> Result<(), AuxError> {
        let n = buf.len();
        if n == 0 || n > 16 {
            return Err(AuxError::TooLong);
        }
        let req = AuxRequest {
            cmd: AuxCommand::NativeRead,
            address: addr,
            data: &[],
        };
        // Reply buffer = 1 status + n data bytes.
        let mut reply = [0u8; 17];
        let resp = self.transact(&req, &mut reply[..1 + n])?;
        buf.copy_from_slice(resp.data);
        Ok(())
    }

    /// Write the bytes in `value` to DPCD `addr` (NATIVE_WRITE).
    fn dpcd_write(&mut self, addr: u32, value: &[u8]) -> Result<(), AuxError> {
        if value.is_empty() || value.len() > 16 {
            return Err(AuxError::TooLong);
        }
        let req = AuxRequest {
            cmd: AuxCommand::NativeWrite,
            address: addr,
            data: value,
        };
        let mut reply = [0u8; 1];
        let _ = self.transact(&req, &mut reply)?;
        Ok(())
    }
}

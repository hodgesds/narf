//! EDID-over-AUX helper — reads a panel's EDID block via the
//! DisplayPort AUX channel's I²C-over-AUX transport, then hands
//! the bytes to the cross-vendor `narf-graphics::edid` parser.
//!
//! Reference: VESA DisplayPort 1.4a §2.7.6 (I²C-over-AUX) +
//! VESA E-EDID 1.4 §3.
//!
//! ## Wire shape
//!
//! Every DP sink exposes its EDID at I²C address `0x50` (the
//! standard DDC/CI slave). The AUX I²C transport packs the I²C
//! address into bits[19:0] of the AUX address field — bits[7:1]
//! are the I²C address, bit 0 is the read/write flag. The
//! source issues:
//!
//!   1. `I2C_WRITE` to `0x50 << 1` with one byte = the EDID
//!      offset (typically 0).
//!   2. `I2C_READ_MOT` (read with stop) to read the 128-byte
//!      block in 16-byte chunks (AUX caps reads at 16 bytes).
//!
//! Each chunk is one `transact` round-trip; the helper batches
//! them into a single 128-byte read.

use crate::dp_aux::{
    AuxChannel, AuxCommand, AuxError, AuxRequest,
};

/// Standard DDC/CI EDID slave address (left-shifted by 1 to
/// match the AUX wire format).
const EDID_I2C_ADDR_SHIFTED: u32 = 0x50 << 1;

/// AUX caps each read at 16 bytes (DP §2.7.4).
const AUX_CHUNK: usize = 16;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EdidReadError {
    /// The downstream AUX transport returned an error.
    Aux(AuxError),
    /// `narf-graphics::edid` rejected the bytes (header mismatch,
    /// checksum failure, unsupported length).
    Parse(narf_graphics::edid::EdidError),
}

impl From<AuxError> for EdidReadError {
    fn from(e: AuxError) -> Self { EdidReadError::Aux(e) }
}

/// Read a panel's 128-byte base EDID block over DP AUX, then
/// parse it. Returns the parsed `Edid` view borrowing from
/// `out`. `out` must be at least 128 bytes; bytes past 127 are
/// left untouched.
pub fn read_panel_edid<'a, A: AuxChannel>(
    aux: &mut A,
    out: &'a mut [u8],
) -> Result<narf_graphics::edid::Edid<'a>, EdidReadError> {
    if out.len() < 128 {
        return Err(EdidReadError::Parse(
            narf_graphics::edid::EdidError::BadLength));
    }
    // Step 1: write the EDID offset (0) to the slave.
    let offset = [0u8];
    let req = AuxRequest {
        cmd: AuxCommand::I2cWrite,
        address: EDID_I2C_ADDR_SHIFTED,
        data: &offset,
    };
    let mut reply = [0u8; 1];
    let _ = aux.transact(&req, &mut reply)?;

    // Step 2: read 128 bytes in 16-byte chunks.
    let mut read = 0usize;
    while read < 128 {
        let chunk_len = AUX_CHUNK.min(128 - read);
        let req = AuxRequest {
            cmd: AuxCommand::I2cReadMot,
            address: EDID_I2C_ADDR_SHIFTED | 1, // read flag
            data: &[],
        };
        let mut reply = [0u8; AUX_CHUNK + 1];
        let resp = aux.transact(&req, &mut reply[..1 + chunk_len])?;
        out[read..read + chunk_len].copy_from_slice(resp.data);
        read += chunk_len;
    }

    // Step 3: hand off to the cross-vendor parser.
    narf_graphics::edid::Edid::parse(&out[..128])
        .map_err(EdidReadError::Parse)
}

//! EDID-over-AUX helper — reads a panel's EDID block via the
//! DisplayPort AUX channel's I²C-over-AUX transport, then hands
//! the bytes to the cross-vendor `narf-graphics::edid` parser.
//!
//! Reference: VESA DisplayPort 1.4a §2.7.6 (I²C-over-AUX) +
//! VESA E-EDID 1.4 §3.
//!   <https://vesa.org/vesa-standards/>
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

use crate::dp_aux::{AuxChannel, AuxCommand, AuxError, AuxRequest};

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
    fn from(e: AuxError) -> Self {
        EdidReadError::Aux(e)
    }
}

/// Zero placeholder for read requests. Per the `dp_aux`
/// transport convention, a read request's `data` is a *length
/// placeholder* — only its length reaches the wire (as the LEN
/// field); the contents are ignored. Before #1092 the chunk
/// reads below passed `&[]`, encoding LEN = 0 and making every
/// EDID read over a real transport fail.
const ZERO_CHUNK: [u8; AUX_CHUNK] = [0u8; AUX_CHUNK];

/// Read one 128-byte EDID block starting at byte offset
/// `offset` (0 for the base block, 128/256/… for extension
/// blocks) into `block`.
///
/// Wire shape (DP 1.4a §2.7.6): an `I2C_WRITE` sets the slave's
/// offset pointer, then the block is read in 16-byte AUX bursts
/// as ONE I²C read transaction — every burst but the last uses
/// `I2C_READ` (MOT = 0, no STOP, the slave's pointer keeps
/// advancing across the repeated-start), and the final burst
/// uses `I2C_READ_MOT` to close the transaction with a STOP.
/// (Issuing a STOP after every burst happens to work on EEPROM
/// sinks whose pointer persists, but it is not the spec shape
/// and power-cycled DDC muxes are not required to tolerate it.)
fn read_edid_block<A: AuxChannel>(
    aux: &mut A,
    offset: u8,
    block: &mut [u8; 128],
) -> Result<(), EdidReadError> {
    let offset_byte = [offset];
    let req = AuxRequest {
        cmd: AuxCommand::I2cWrite,
        address: EDID_I2C_ADDR_SHIFTED,
        data: &offset_byte,
    };
    let mut reply = [0u8; 1];
    let _ = aux.transact(&req, &mut reply)?;

    let mut read = 0usize;
    while read < 128 {
        let chunk_len = AUX_CHUNK.min(128 - read);
        let last = read + chunk_len == 128;
        let req = AuxRequest {
            cmd: if last {
                AuxCommand::I2cReadMot
            } else {
                AuxCommand::I2cRead
            },
            address: EDID_I2C_ADDR_SHIFTED | 1, // read flag
            data: &ZERO_CHUNK[..chunk_len],
        };
        let mut reply = [0u8; AUX_CHUNK + 1];
        let resp = aux.transact(&req, &mut reply[..1 + chunk_len])?;
        block[read..read + chunk_len].copy_from_slice(resp.data);
        read += chunk_len;
    }
    Ok(())
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
            narf_graphics::edid::EdidError::BadLength,
        ));
    }
    let mut block = [0u8; 128];
    read_edid_block(aux, 0, &mut block)?;
    out[..128].copy_from_slice(&block);

    // Hand off to the cross-vendor parser.
    narf_graphics::edid::Edid::parse(&out[..128]).map_err(EdidReadError::Parse)
}

/// Read the panel's *complete* EDID — the base block plus every
/// extension block the base block advertises (byte 126) — into
/// `out`, returning the total byte count (`128 * (1 + n)`).
///
/// The base block is validated with the cross-vendor parser
/// before any extension is fetched, so a garbage base block
/// fails fast instead of streaming phantom extensions. The
/// returned length is capped by `out`'s capacity: a sink
/// advertising more extensions than fit yields the blocks that
/// fit, with the count byte still reporting the sink's claim —
/// callers that need the CTA block (always extension 1 in
/// practice) are unaffected.
///
/// The display-audio sink (`narf_drivers_sound::display_audio`)
/// consumes this full form: the CTA-861 extension carrying the
/// audio descriptors lives past the base block.
pub fn read_full_edid<A: AuxChannel>(aux: &mut A, out: &mut [u8]) -> Result<usize, EdidReadError> {
    if out.len() < 128 {
        return Err(EdidReadError::Parse(
            narf_graphics::edid::EdidError::BadLength,
        ));
    }
    let mut block = [0u8; 128];
    read_edid_block(aux, 0, &mut block)?;
    out[..128].copy_from_slice(&block);
    narf_graphics::edid::Edid::parse(&out[..128]).map_err(EdidReadError::Parse)?;

    let extensions = out[126] as usize;
    let capacity_blocks = out.len() / 128;
    let mut fetched = 0usize;
    for i in 0..extensions.min(capacity_blocks.saturating_sub(1)) {
        // The DDC offset pointer is one byte within the current
        // 256-byte segment; blocks past offset 255 need the
        // segment pointer at I²C 0x30, which this helper does
        // not drive. The CTA block the consumers need is
        // extension 1 (offset 128), inside the first segment.
        let offset = (i + 1) * 128;
        if offset > u8::MAX as usize {
            break;
        }
        read_edid_block(aux, offset as u8, &mut block)?;
        out[offset..offset + 128].copy_from_slice(&block);
        fetched += 1;
    }
    Ok(128 * (1 + fetched))
}

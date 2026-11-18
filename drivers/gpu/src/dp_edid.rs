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
//! standard DDC/CI slave). I²C-over-AUX carries the 7-bit I²C
//! address itself in the AUX address field — `0x50`, not the
//! `0xA0`/`0xA1` byte a bit-banged bus clocks out; direction is
//! the command (Linux `drm_dp_i2c_xfer` sets `msg.address` to
//! the 7-bit `i2c_msg.addr`, and `intel_dp_aux_header` writes
//! its low byte to the wire). The source issues:
//!
//!   1. `I2C_WRITE_MOT` to `0x50` with one byte = the EDID
//!      offset (typically 0).
//!   2. `I2C_READ_MOT` to read the 128-byte block in 16-byte
//!      chunks (AUX caps reads at 16 bytes).
//!   3. An address-only `I2C_READ` (MOT clear) to issue the
//!      I²C STOP.
//!
//! MOT is DP's Middle-Of-Transaction bit: set means "no STOP
//! after this request". Each chunk is one `transact`
//! round-trip; the helper batches them into a single 128-byte
//! read.

use crate::dp_aux::{AuxChannel, AuxCommand, AuxError, AuxRequest};

/// drm_display_info.monitor_range: the EDID's vertical rate limits in Hz.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MonitorRange {
    pub min_vfreq: u16,
    pub max_vfreq: u16,
}

/// amdgpu_dm's DisplayID dynamic-video-timing-range fallback. Linux
/// searches the first declared DisplayID extension; use only bounds that
/// fit inside that actual block and accept revision0/1, length9 as it does.
pub fn displayid_range(edid: &[u8]) -> Option<MonitorRange> {
    let base = edid.get(..128)?;
    let ext = edid
        .chunks_exact(128)
        .skip(1)
        .take(usize::from(base[126]))
        .find(|b| b[0] == 0x70)?;
    for j in 0..115 {
        if ext[j] == 0x25 && ext[j + 1] & 0xfe == 0 && ext[j + 2] == 9 {
            let min = u16::from(ext[j + 9]);
            let max = u16::from(ext[j + 10])
                | if ext[j + 1] & 7 != 0 {
                    u16::from(ext[j + 11] & 3) << 8
                } else {
                    0
                };
            if min != 0 && max != 0 {
                return Some(MonitorRange {
                    min_vfreq: min,
                    max_vfreq: max,
                });
            }
        }
    }
    None
}

/// The display descriptor tag of a Monitor Range Limits descriptor.
const RANGE_DESCRIPTOR: u8 = 0xfd;
/// DRM_EDID_RANGE_LIMITS_ONLY_FLAG: the only variant promising every timing
/// inside the range, so the only one usable for VRR.
const RANGE_LIMITS_ONLY: u8 = 0x01;
/// DRM_EDID_RANGE_OFFSET_{MIN,MAX}_VFREQ (EDID 1.4): add 255 Hz.
const OFFSET_MIN_VFREQ: u8 = 1 << 0;
const OFFSET_MAX_VFREQ: u8 = 1 << 1;
/// DRM_EDID_FEATURE_CONTINUOUS_FREQ.
const CONTINUOUS_FREQ: u8 = 1 << 0;

/// drm_get_monitor_range over a whole EDID (base block then extensions):
/// EDID 1.4 with continuous frequency, every 18-byte detailed block (the base
/// block's four, a CTA-861 extension's DTD area, a VTB extension's), the
/// last matching "range limits only" descriptor winning, with the 1.4 +255
/// offsets. None when no descriptor qualifies (Linux's 0..0).
pub fn monitor_range(edid: &[u8]) -> Option<MonitorRange> {
    let base = edid.get(..128)?;
    let revision = base[0x13];
    if revision < 4 || base[0x18] & CONTINUOUS_FREQ == 0 {
        return None;
    }
    let mut range = None;
    let mut visit = |d: &[u8]| {
        // is_display_descriptor: pixel clock 0, pad1 0, the tag.
        if d.len() < 18 || d[0] != 0 || d[1] != 0 || d[2] != 0 || d[3] != RANGE_DESCRIPTOR {
            return;
        }
        if d[10] != RANGE_LIMITS_ONLY {
            return;
        }
        let mut r = MonitorRange {
            min_vfreq: u16::from(d[5]),
            max_vfreq: u16::from(d[6]),
        };
        // revision >= 4 already holds.
        if d[4] & OFFSET_MIN_VFREQ != 0 {
            r.min_vfreq += 255;
        }
        if d[4] & OFFSET_MAX_VFREQ != 0 {
            r.max_vfreq += 255;
        }
        range = Some(r);
    };
    for i in 0..4 {
        let at = 54 + 18 * i;
        visit(&base[at..at + 18]);
    }
    // drm_edid_block_count: the declared extensions, limited by the size.
    let blocks = (usize::from(base[0x7e]) + 1).min(edid.len() / 128);
    for ext in edid.chunks_exact(128).take(blocks).skip(1) {
        match ext[0] {
            // cea_for_each_detailed_block
            0x02 => {
                let d = usize::from(ext[2]);
                if !(4..=127).contains(&d) {
                    continue;
                }
                for i in 0..(127 - d) / 18 {
                    visit(&ext[d + 18 * i..d + 18 * i + 18]);
                }
            }
            // vtb_for_each_detailed_block
            0x10 if ext[1] == 1 => {
                for i in 0..usize::from(ext[2]).min(6) {
                    visit(&ext[5 + 18 * i..5 + 18 * i + 18]);
                }
            }
            _ => {}
        }
    }
    range
}

/// Monitor range limits take precedence over the DisplayID fallback.
#[cfg(any(feature = "intel", feature = "amdgpu"))]
pub(crate) fn adaptive_sync_range(edid: &[u8]) -> Option<MonitorRange> {
    monitor_range(edid)
        .filter(|r| r.min_vfreq != 0 && r.max_vfreq != 0)
        .or_else(|| displayid_range(edid))
}

/// Standard DDC/CI EDID slave address — the 7-bit I²C address,
/// as the AUX address field carries it (Linux `DDC_ADDR`).
const EDID_I2C_ADDR: u32 = 0x50;

/// AUX caps each read at 16 bytes (DP §2.7.4).
const AUX_CHUNK: usize = 16;

/// Zero-filled read-length placeholder for EDID chunk reads.
/// Per the `AuxRequest` read convention (see
/// `dp_aux::AuxChannel::dpcd_read`), a read's `data` length is
/// the requested byte count; the contents never reach the wire.
const ZERO_CHUNK: [u8; AUX_CHUNK] = [0; AUX_CHUNK];

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

/// Read one 128-byte EDID block starting at byte offset
/// `offset` (0 for the base block, 128/256/… for extension
/// blocks) into `block`.
///
/// Wire shape (DP 1.4a §2.7.6, as Linux `drm_dp_i2c_xfer`
/// drives the offset-write + block-read message pair): the
/// offset write and every 16-byte read burst carry MOT, so the
/// whole exchange is ONE I²C transaction (write, repeated start,
/// read) and the slave's pointer keeps advancing across bursts;
/// a final address-only `I2C_READ` with MOT clear issues the
/// STOP. (Linux also opens each message with an address-only
/// MOT request; the first data request carries the same
/// address, so the start is not repeated here.)
///
/// The STOP is sent even when a burst fails, as Linux does, so
/// a failed read does not leave the DDC bus mid-transaction.
fn read_edid_block<A: AuxChannel>(
    aux: &mut A,
    offset: u8,
    block: &mut [u8; 128],
) -> Result<(), EdidReadError> {
    let result = read_edid_block_mot(aux, offset, block);
    let stop = AuxRequest {
        cmd: AuxCommand::I2cRead,
        address: EDID_I2C_ADDR,
        data: &[],
    };
    let mut reply = [0u8; 1];
    let stopped = aux.transact(&stop, &mut reply);
    result?;
    stopped?;
    Ok(())
}

/// The MOT half of [`read_edid_block`]: offset write plus the
/// read bursts, all with MOT set (no STOP).
fn read_edid_block_mot<A: AuxChannel>(
    aux: &mut A,
    offset: u8,
    block: &mut [u8; 128],
) -> Result<(), EdidReadError> {
    let offset_byte = [offset];
    let req = AuxRequest {
        cmd: AuxCommand::I2cWriteMot,
        address: EDID_I2C_ADDR,
        data: &offset_byte,
    };
    let mut reply = [0u8; 1];
    let _ = aux.transact(&req, &mut reply)?;

    let mut read = 0usize;
    while read < 128 {
        let chunk_len = AUX_CHUNK.min(128 - read);
        let req = AuxRequest {
            cmd: AuxCommand::I2cReadMot,
            address: EDID_I2C_ADDR,
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

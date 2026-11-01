//! Passive GuC Log File Descriptor (LFD) export from an already-owned copy.
//!
//! MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad:
//! xe_guc_log.c::{xe_guc_log_snapshot_print_lfd,xe_guc_log_add_log_event},
//! abi/{guc_log,guc_lic,guc_lfd}_abi.h. Unlike the source's unchecked walk,
//! every record, LIC KLV and event range is bounded by our fixed allocation.
//! No firmware offset is ever used for a live read. This neither consumes
//! logs nor provides the flush/ack protocol needed for lossless streaming.

use super::{valid_state, Snapshot};
use alloc::vec::Vec;
use core::ops::Range;
use narf_filesystem::FsError;

pub(super) const MAX_BYTES: usize = 4096 + 0x10000 + 0x4000;
const EVENT: usize = 4096;
const CRASH: usize = EVENT + 0x10000;
const LIC: usize = 3 * 36;
const OS: &[u8] = concat!("NARF/", env!("CARGO_PKG_VERSION")).as_bytes();
const COMMENT: &[u8] = b"NARF passive GuC snapshot; sequential copy; no flush acknowledgement; payload may change during capture";

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("bounded LFD dword"))
}
fn header(kind: u16, bytes: usize) -> [u8; 8] {
    let mut result = [0; 8];
    result[..4].copy_from_slice(&((u32::from(kind) << 16) | 0x8086).to_le_bytes());
    result[4..].copy_from_slice(&(bytes.div_ceil(4) as u32).to_le_bytes());
    result
}
fn block(destination: &mut Vec<u8>, kind: u16, payload: &[u8]) -> Result<(), FsError> {
    let padded = payload.len().checked_add(3).ok_or(FsError::InvalidData)? & !3;
    if destination
        .len()
        .checked_add(8 + padded)
        .is_none_or(|length| length > 4096)
    {
        return Err(FsError::InvalidData);
    }
    destination.extend_from_slice(&header(kind, payload.len()));
    destination.extend_from_slice(payload);
    destination.resize(destination.len() + padded - payload.len(), 0);
    Ok(())
}

/// Layout plus the original immutable raw snapshot. Both formats share the
/// same two-per-card permit pool. No second large copy or live BO is retained.
pub(super) struct Export {
    snapshot: Snapshot,
    prefix: Vec<u8>,
    events: [Range<usize>; 2],
    crash: Range<usize>,
    crash_header: [u8; 8],
    len: usize,
}
impl Export {
    pub(super) fn new(snapshot: Snapshot) -> Result<Self, FsError> {
        // Changed/unknown framing remains available from the raw diagnostic
        // file; do not manufacture a well-formed LFD from uncertain headers.
        if word(&snapshot.header, 68) != 7 || word(&snapshot.header, 72) != 0 {
            return Err(FsError::InvalidData);
        }
        let bytes = &snapshot.buffer.bytes;
        for index in 0..3 {
            let state = core::array::from_fn(|n| word(bytes, index * 36 + n * 4));
            if !valid_state(index, &state) {
                return Err(FsError::InvalidData);
            }
        }
        // The admitted firmware profile has exactly three fixed-size states,
        // followed by LIC1.0 inside the 4KiB state page. All five scalar keys
        // are mandatory, exactly once, and have one value dword each.
        if word(bytes, LIC) != 0x8086900d || word(bytes, LIC + 4) != 0x00010000 {
            return Err(FsError::Unsupported);
        }
        let count = word(bytes, LIC + 8) as usize;
        if count != 10 || LIC + 12 + count * 4 > EVENT {
            return Err(FsError::InvalidData);
        }
        let mut values = [None; 5];
        for entry in bytes[LIC + 12..LIC + 12 + count * 4].chunks_exact(8) {
            let kl = word(entry, 0);
            let key = (kl >> 16) as usize;
            if kl & 0xffff != 1 || !(1..=5).contains(&key) || values[key - 1].is_some() {
                return Err(FsError::InvalidData);
            }
            values[key - 1] = Some(word(entry, 4));
        }
        let read = word(bytes, 8) as usize;
        let write = word(bytes, 12) as usize;
        let wrap = word(bytes, 24) as usize;
        // LFD event payloads are DWORD arrays. This narrow profile refuses
        // partial words rather than padding an unproven firmware entry.
        if read & 3 != 0 || write & 3 != 0 || wrap & 3 != 0 {
            return Err(FsError::InvalidData);
        }
        let events = if read < write {
            [EVENT + read..EVENT + write, 0..0]
        } else if read > write {
            if read > wrap {
                return Err(FsError::InvalidData);
            }
            [EVENT + read..EVENT + wrap, EVENT..EVENT + write]
        } else {
            [0..0, 0..0]
        };
        let event_bytes = events.iter().map(Range::len).sum::<usize>();
        if event_bytes > 0x10000 {
            return Err(FsError::InvalidData);
        }
        let crash = if bytes[CRASH..CRASH + 0x4000].iter().any(|byte| *byte != 0) {
            CRASH..CRASH + 0x4000
        } else {
            0..0
        };
        let mut prefix = Vec::new();
        prefix
            .try_reserve_exact(4096)
            .map_err(|_| FsError::OutOfMemory)?;
        prefix.extend_from_slice(&0x8086aaaa474c5346u64.to_le_bytes());
        prefix.extend_from_slice(&0x00010000u32.to_le_bytes());
        for (index, value) in values.into_iter().enumerate() {
            block(
                &mut prefix,
                index as u16 + 1,
                &value.ok_or(FsError::InvalidData)?.to_le_bytes(),
            )?;
        }
        let mut os = [0; 128];
        if OS.len() > os.len() - 4 {
            return Err(FsError::InvalidData);
        }
        os[..4].copy_from_slice(&4u32.to_le_bytes()); // OSID_OTHER, not Linux.
        os[4..4 + OS.len()].copy_from_slice(OS);
        block(&mut prefix, 0x4000, &os[..4 + OS.len()])?;
        block(&mut prefix, 0x6001, COMMENT)?;
        if event_bytes != 0 {
            prefix.extend_from_slice(&header(0x2000, 4 + event_bytes));
            prefix.extend_from_slice(&word(bytes, 32).to_le_bytes());
        }
        let len = prefix.len() + event_bytes + if crash.is_empty() { 0 } else { 8 + crash.len() };
        if len > MAX_BYTES {
            return Err(FsError::InvalidData);
        }
        Ok(Self {
            snapshot,
            prefix,
            events,
            crash,
            crash_header: header(0x2001, 0x4000),
            len,
        })
    }
    pub(super) fn len(&self) -> usize {
        self.len
    }
    pub(super) fn read(&self, offset: u64, output: &mut [u8]) -> usize {
        let Ok(mut skip) = usize::try_from(offset) else {
            return 0;
        };
        let raw = &self.snapshot.buffer.bytes;
        let mut written = 0;
        for segment in [
            self.prefix.as_slice(),
            &raw[self.events[0].clone()],
            &raw[self.events[1].clone()],
            if self.crash.is_empty() {
                &[]
            } else {
                &self.crash_header[..]
            },
            &raw[self.crash.clone()],
        ] {
            if skip >= segment.len() {
                skip -= segment.len();
                continue;
            }
            let count = (segment.len() - skip).min(output.len() - written);
            output[written..written + count].copy_from_slice(&segment[skip..skip + count]);
            written += count;
            skip = 0;
            if written == output.len() {
                break;
            }
        }
        written
    }
}

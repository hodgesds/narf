//! UDF Node — `FileOps` + `DirOps` implementations.
//!
//! Clean-room implementation. Directory walking, identifier decode,
//! and file-extent reads all derive strictly from the public
//! references below — no GPL/LGPL UDF source consulted.
//!
//! References:
//! - ECMA-167 §4/14.4 (FID — directory entries).
//! - ECMA-167 §4/14.6 (icb_tag — file_type byte; alloc-descriptor
//!   format selector).
//! - ECMA-167 §4/14.9 (File Entry — fixed 176-byte header, then
//!   L_EA bytes of EAs, then L_AD bytes of allocation descriptors).
//! - ECMA-167 §4/14.17 (Extended File Entry — adds 40 bytes between
//!   the fixed fields and the L_EA / L_AD pair).
//! - ECMA-167 §4/14.14.2 (`long_ad` — 16 bytes; the default AD
//!   format this driver consumes).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_block::{BlockDevice, BlockError};
use narf_filesystem::{
    DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, Mode, Stat,
};
use narf_lib::sync::IrqSafeSpinLock;

use super::descriptor::read_descriptor_tag;
use super::fid::{decode_fid, Fid};
use super::icb::{
    ad_type, decode_entry_layout, file_type, read_long_ad, EntryLayout, LongAd,
};
use super::volume::{read_extent, UdfVolume};
use super::SECTOR_SIZE;

/// Per-node state.
#[derive(Debug)]
pub struct UdfNodeState {
    /// Absolute LSN of the file's ICB (File Entry / Extended File
    /// Entry) sector. Used by directory walks and stat refresh.
    pub icb_lsn: u64,
    /// File body length in bytes (cached after the first ICB read).
    /// Initialised lazily — `0` means "not yet probed".
    pub size_cache: u64,
    /// `Stat` snapshot. Mode is `DIR_RO` / `FILE_RO`.
    pub stat: Stat,
}

/// A file or directory in a UDF volume.
#[derive(Debug)]
pub struct UdfNode<B: BlockDevice> {
    pub volume: Arc<UdfVolume<B>>,
    pub state: IrqSafeSpinLock<UdfNodeState>,
}

impl<B: BlockDevice + 'static> UdfNode<B> {
    /// Construct the root node from the cached root ICB long_ad.
    pub fn root_from_icb(volume: Arc<UdfVolume<B>>, icb: LongAd) -> Self {
        let lsn = volume
            .translate_long_ad(&icb)
            .unwrap_or(volume.partition.partition_starting_location as u64);
        let stat = Stat {
            size: 0,
            blocks: 0,
            mode: Mode::DIR_RO,
            mtime_cycles: 0,
        };
        Self {
            volume,
            state: IrqSafeSpinLock::new(UdfNodeState {
                icb_lsn: lsn,
                size_cache: 0,
                stat,
            }),
        }
    }

    /// Construct a node from a child FID.
    pub fn from_fid(volume: Arc<UdfVolume<B>>, fid: &Fid) -> Result<Self, FsError> {
        let icb_lsn = volume.translate_long_ad(&fid.icb)?;
        let mode = if fid.is_directory() {
            Mode::DIR_RO
        } else {
            Mode::FILE_RO
        };
        let stat = Stat {
            size: 0,
            blocks: 0,
            mode,
            mtime_cycles: 0,
        };
        Ok(Self {
            volume,
            state: IrqSafeSpinLock::new(UdfNodeState {
                icb_lsn,
                size_cache: 0,
                stat,
            }),
        })
    }
}

// ── ICB decoding ──────────────────────────────────────────────────

/// Decoded view of one ICB sector — enough to enumerate a directory
/// or read file extents.
struct DecodedIcb {
    layout: EntryLayout,
    /// Long-AD list lifted out of the AD area. The MVP only consumes
    /// long_ad descriptors; if `alloc_type != 1` the list is empty
    /// and the caller should surface `FsError::Unsupported`.
    long_ads: Vec<LongAd>,
}

async fn read_and_decode_icb<B: BlockDevice + 'static>(
    volume: &UdfVolume<B>,
    icb_lsn: u64,
) -> Result<DecodedIcb, FsError> {
    let mut sector = alloc::vec![0u8; SECTOR_SIZE];
    volume.read_sector(icb_lsn, &mut sector).await?;
    let tag = read_descriptor_tag(&sector, 0);
    use super::descriptor::tag_id;
    if tag.tag_identifier != tag_id::FILE_ENTRY
        && tag.tag_identifier != tag_id::EXTENDED_FILE_ENTRY
    {
        return Err(FsError::Io(BlockError::IOError));
    }
    let layout = decode_entry_layout(&sector).ok_or(FsError::Io(BlockError::IOError))?;

    // Walk the AD area as long_ads (the only format the MVP
    // consumes). Skip embedded-data and other formats here; the
    // caller can detect via `layout.alloc_type` and surface a
    // dedicated error.
    let mut long_ads: Vec<LongAd> = Vec::new();
    if layout.alloc_type == super::icb::flags::ALLOC_TYPE_LONG {
        let mut off = layout.ad_area_offset;
        let end = off + layout.ad_area_length;
        while off + 16 <= end {
            let ad = read_long_ad(&sector, off);
            if ad.extent_length() == 0 && ad.extent_type() == ad_type::RECORDED {
                // §4/14.14 — a length-0 AD is the terminator marker
                // sometimes emitted by mkudffs even with non-zero
                // L_AD. Stop walking.
                break;
            }
            long_ads.push(ad);
            off += 16;
        }
    }
    Ok(DecodedIcb { layout, long_ads })
}

/// Build a `Stat` from a freshly-decoded ICB.
fn stat_from_layout(layout: &EntryLayout) -> Stat {
    let mode = if layout.file_type == file_type::DIRECTORY {
        Mode::DIR_RO
    } else {
        Mode::FILE_RO
    };
    Stat {
        size: layout.information_length,
        blocks: layout.information_length.div_ceil(SECTOR_SIZE as u64),
        mode,
        mtime_cycles: 0,
    }
}

// ── FileOps ─────────────────────────────────────────────────────────

impl<B: BlockDevice + 'static> FileOps for UdfNode<B> {
    /// Read up to `buf.len()` bytes starting at `offset`.
    ///
    /// UDF file bodies are described by a list of long_ad extents in
    /// the File Entry's AD area. The MVP walks them in order: each
    /// extent has a length in bytes and a starting LBN within a
    /// partition; we map `offset` into the right extent, read
    /// sector-by-sector, and copy the requested slice out.
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let icb_lsn = { self.state.lock().icb_lsn };
            let icb = read_and_decode_icb(&self.volume, icb_lsn).await?;
            // Refresh the cached size + stat under the spinlock.
            {
                let mut g = self.state.lock();
                g.size_cache = icb.layout.information_length;
                g.stat = stat_from_layout(&icb.layout);
            }

            if offset >= icb.layout.information_length {
                return Ok(0);
            }
            let mut remaining = core::cmp::min(
                buf.len() as u64,
                icb.layout.information_length - offset,
            );
            // Embedded-data form: data lives in the AD area itself;
            // we don't currently surface that, so the caller sees
            // an empty read. Real DVD/BD media doesn't use embedded
            // data for the leaf files we care about.
            if icb.layout.alloc_type == super::icb::flags::ALLOC_TYPE_EMBEDDED
                || icb.long_ads.is_empty()
            {
                return Ok(0);
            }

            // Locate the first extent that contains `offset`.
            let mut total_read = 0usize;
            let mut cursor: u64 = 0;
            let mut sector = alloc::vec![0u8; SECTOR_SIZE];

            for ad in &icb.long_ads {
                let ext_len = ad.extent_length() as u64;
                if ext_len == 0 {
                    continue;
                }
                let ext_end = cursor + ext_len;
                // Skip extents entirely before `offset`.
                if ext_end <= offset {
                    cursor = ext_end;
                    continue;
                }
                // Only RECORDED extents have meaningful sectors; the
                // others surface as zeros (NOT_RECORDED_BUT_ALLOCATED)
                // or are not allocated at all.
                let in_extent_off = if cursor < offset {
                    (offset - cursor) as usize
                } else {
                    0
                };
                let bytes_in_extent =
                    core::cmp::min(remaining as usize, ext_len as usize - in_extent_off);

                if ad.extent_type() == ad_type::RECORDED {
                    let extent_lsn = self.volume.translate_long_ad(ad)?;
                    // Walk sectors inside the extent.
                    let mut e_off = in_extent_off;
                    let mut left = bytes_in_extent;
                    while left > 0 {
                        let sec_idx = (e_off / SECTOR_SIZE) as u64;
                        let sec_off = e_off % SECTOR_SIZE;
                        self.volume
                            .read_sector(extent_lsn + sec_idx, &mut sector)
                            .await?;
                        let n = core::cmp::min(left, SECTOR_SIZE - sec_off);
                        buf[total_read..total_read + n]
                            .copy_from_slice(&sector[sec_off..sec_off + n]);
                        total_read += n;
                        e_off += n;
                        left -= n;
                    }
                } else {
                    // Hole — zero-fill the destination slice.
                    for byte in buf[total_read..total_read + bytes_in_extent].iter_mut() {
                        *byte = 0;
                    }
                    total_read += bytes_in_extent;
                }
                remaining -= bytes_in_extent as u64;
                cursor = ext_end;
                if remaining == 0 {
                    break;
                }
            }
            Ok(total_read)
        })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }

    fn stat(&self) -> Stat {
        self.state.lock().stat
    }

    fn truncate<'a>(&'a self, _len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }
}

// ── DirOps ──────────────────────────────────────────────────────────

impl<B: BlockDevice + 'static> DirOps for UdfNode<B> {
    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        // Disk-backed FS — synchronous lookup is unsupported. The
        // VFS prefers `lookup_async` automatically.
        None
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let entries = scan_directory(&self.volume, &self.state).await?;
            for fid in entries {
                if fid.is_deleted() || fid.is_parent() {
                    continue;
                }
                if names_match(&fid.identifier, name) {
                    let node = UdfNode::from_fid(self.volume.clone(), &fid)?;
                    return Ok(Arc::new(node) as Arc<dyn FileOps>);
                }
            }
            Err(FsError::NotFound)
        })
    }

    fn lookup_dir(&self, _name: &str) -> Option<Arc<dyn DirOps>> {
        None
    }

    fn lookup_dir_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            let entries = scan_directory(&self.volume, &self.state).await?;
            for fid in entries {
                if fid.is_deleted() || fid.is_parent() {
                    continue;
                }
                if names_match(&fid.identifier, name) && fid.is_directory() {
                    let node = UdfNode::from_fid(self.volume.clone(), &fid)?;
                    return Ok(Arc::new(node) as Arc<dyn DirOps>);
                }
            }
            Err(FsError::NotFound)
        })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // Disk-backed FS — sync iteration is not supported. Use
        // `enumerate_async`.
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, _cursor: usize, _max: usize) -> Vec<(String, FileType)> {
        Vec::new()
    }

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> FsFuture<'a, Vec<(String, FileType)>> {
        Box::pin(async move {
            let entries = scan_directory(&self.volume, &self.state).await?;
            let visible: Vec<_> = entries
                .into_iter()
                .filter(|f| !f.is_deleted() && !f.is_parent())
                .collect();
            let mut out = Vec::new();
            for (i, fid) in visible.into_iter().enumerate() {
                if i < cursor {
                    continue;
                }
                if out.len() >= max {
                    break;
                }
                let ft = if fid.is_directory() {
                    FileType::Dir
                } else {
                    FileType::File
                };
                out.push((fid.identifier, ft));
            }
            Ok(out)
        })
    }

    // Mutating ops inherit `FsError::Unsupported`.
}

// ── Directory scan ─────────────────────────────────────────────────

/// Read the directory's File Entry, follow its long_ad extents to
/// pull the FID stream into RAM, then walk and decode every FID.
async fn scan_directory<B: BlockDevice + 'static>(
    volume: &Arc<UdfVolume<B>>,
    state: &IrqSafeSpinLock<UdfNodeState>,
) -> Result<Vec<Fid>, FsError> {
    let icb_lsn = { state.lock().icb_lsn };
    let icb = read_and_decode_icb(volume, icb_lsn).await?;
    if icb.layout.file_type != file_type::DIRECTORY {
        return Err(FsError::NotFound);
    }
    if icb.layout.alloc_type != super::icb::flags::ALLOC_TYPE_LONG {
        return Err(FsError::Unsupported);
    }

    // Concatenate the body of every recorded extent.
    let mut body: Vec<u8> = Vec::with_capacity(icb.layout.information_length as usize);
    let mut remaining = icb.layout.information_length as usize;
    for ad in &icb.long_ads {
        if remaining == 0 {
            break;
        }
        let ext_len = ad.extent_length() as usize;
        if ext_len == 0 {
            continue;
        }
        let take = core::cmp::min(remaining, ext_len);
        if ad.extent_type() == ad_type::RECORDED {
            let lsn = volume.translate_long_ad(ad)?;
            let n_sectors = take.div_ceil(SECTOR_SIZE) as u32;
            let chunk = read_extent(volume, lsn, n_sectors).await?;
            body.extend_from_slice(&chunk[..take]);
        } else {
            body.resize(body.len() + take, 0);
        }
        remaining -= take;
    }

    let mut fids: Vec<Fid> = Vec::new();
    let mut off: usize = 0;
    while off + 38 <= body.len() {
        match decode_fid(&body, off) {
            Ok(fid) => {
                let step = fid.record_length;
                if step == 0 || off + step > body.len() {
                    break;
                }
                fids.push(fid);
                off += step;
            }
            Err(_) => break,
        }
    }
    Ok(fids)
}

/// Compare a stored UDF identifier against a user-supplied lookup
/// key. UDF on-medium names are usually case-sensitive — DVD-Video
/// uses uppercase by convention but Blu-ray titles routinely mix
/// case. We do an ASCII-case-insensitive compare so the surface
/// matches the iso9660 / FAT crates in this tree.
pub fn names_match(stored: &str, query: &str) -> bool {
    stored.eq_ignore_ascii_case(query)
}

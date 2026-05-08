//! exFAT directory node + file/dir ops.
//!
//! Clean-room. Directory walk reassembles the §7.4 file directory
//! entry + §7.6 stream extension + §7.7 file-name slots into one
//! logical "file"; `lookup_async` / `lookup_dir_async` /
//! `enumerate_async` all share the scanner. `read` honours the
//! §7.6.5 `NoFatChain` flag for contiguous extents.
//!
//! Write operations (create / mkdir / unlink / rmdir / rename /
//! truncate / write) are NOT implemented in this first cut — they
//! all return `FsError::Unsupported`. Landing them requires the
//! bitmap allocator and on-disk up-case checksum verification,
//! both flagged TODO.
//!
//! References:
//! - exFAT file system specification (Microsoft, 2019),
//!   §6.1 EntryType byte, §7.4 File Directory Entry, §7.6 Stream
//!   Extension Entry (§7.6.5 GeneralSecondaryFlags), §7.7 File
//!   Name Entry, §7.4 + §7.6 lookup semantics (compare on the
//!   up-cased name; the §7.6.8 NameHash is a fast-reject filter).
//!   <https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification>

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::{
    DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, Mode, Stat,
};
use narf_lib::sync::IrqSafeSpinLock;

use super::dir::{
    entry_type, file_attr, name_hash, stream_flags, FileDirectoryEntry, FileNameEntry,
    StreamExtensionEntry, DIR_ENTRY_SIZE,
};
use super::fat::FatEntry;
use super::volume::ExfatVolume;

/// One reassembled directory entry: the primary file entry plus
/// the stream extension and the decoded UTF-16 name.
#[derive(Debug, Clone)]
pub struct ExfatDirent {
    pub file: FileDirectoryEntry,
    pub stream: StreamExtensionEntry,
    pub name_utf16: Vec<u16>,
}

impl ExfatDirent {
    pub fn is_directory(&self) -> bool {
        let attrs = self.file.file_attributes;
        (attrs & file_attr::DIRECTORY) != 0
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ExfatNodeState {
    pub first_cluster: u32,
    pub data_length: u64,
    pub no_fat_chain: bool,
    pub stat: Stat,
}

/// One node in the exFAT VFS surface — either the root directory
/// or a file/directory reached via lookup.
#[derive(Debug)]
pub struct ExfatNode<B: BlockDevice> {
    pub volume: Arc<ExfatVolume<B>>,
    pub state: IrqSafeSpinLock<ExfatNodeState>,
}

impl<B: BlockDevice + 'static> ExfatNode<B> {
    /// Construct the root node from the volume's
    /// `first_cluster_of_root_directory`. The root has no
    /// containing dirent, so its size/attributes are synthetic.
    pub fn new_root(volume: Arc<ExfatVolume<B>>, first_cluster: u32) -> Self {
        Self {
            volume,
            state: IrqSafeSpinLock::new(ExfatNodeState {
                first_cluster,
                data_length: 0,
                no_fat_chain: false,
                stat: Stat {
                    size: 0,
                    blocks: 0,
                    mode: Mode::DIR_RO,
                    mtime_cycles: 0,
                },
            }),
        }
    }

    /// Construct a child node from a reassembled dirent.
    pub fn from_dirent(volume: Arc<ExfatVolume<B>>, dirent: &ExfatDirent) -> Self {
        let bps = volume.bytes_per_sector as u64;
        let stream = dirent.stream;
        let stat = Stat {
            size: stream.data_length,
            blocks: stream.data_length.div_ceil(bps),
            mode: Mode {
                file_type: if dirent.is_directory() {
                    FileType::Dir
                } else {
                    FileType::File
                },
                perms: if (dirent.file.file_attributes & file_attr::READ_ONLY) != 0 {
                    0o444
                } else {
                    0o666
                },
            },
            mtime_cycles: 0,
        };
        Self {
            volume,
            state: IrqSafeSpinLock::new(ExfatNodeState {
                first_cluster: stream.first_cluster,
                data_length: stream.data_length,
                no_fat_chain: (stream.general_secondary_flags & stream_flags::NO_FAT_CHAIN) != 0,
                stat,
            }),
        }
    }
}

// ── Byte-layout helpers — mirror the FAT driver's pattern ───────────

fn read_file_entry(buf: &[u8], offset: usize) -> FileDirectoryEntry {
    debug_assert!(offset + DIR_ENTRY_SIZE <= buf.len());
    // SAFETY: §7.4 — 32-byte packed primary entry. The byte slice
    // was just read off disk into a heap buffer we own; the type
    // byte at `buf[offset]` was already confirmed to be 0x85 by
    // the caller.
    unsafe { core::ptr::read_unaligned(buf.as_ptr().add(offset) as *const FileDirectoryEntry) }
}

fn read_stream_entry(buf: &[u8], offset: usize) -> StreamExtensionEntry {
    debug_assert!(offset + DIR_ENTRY_SIZE <= buf.len());
    // SAFETY: §7.6 — 32-byte packed stream extension entry; same
    // packed-layout argument as `read_file_entry`.
    unsafe { core::ptr::read_unaligned(buf.as_ptr().add(offset) as *const StreamExtensionEntry) }
}

fn read_filename_entry(buf: &[u8], offset: usize) -> FileNameEntry {
    debug_assert!(offset + DIR_ENTRY_SIZE <= buf.len());
    // SAFETY: §7.7 — 32-byte packed file-name entry; same packed-
    // layout argument as `read_file_entry`.
    unsafe { core::ptr::read_unaligned(buf.as_ptr().add(offset) as *const FileNameEntry) }
}

// ── Directory scanner ──────────────────────────────────────────────

/// Reads one 32-byte slot at a time from a directory cluster
/// chain, reassembling §7.4/§7.6/§7.7 groups. Bounded by a
/// safety cap on total slots scanned to defang corrupt FATs.
struct DirectoryScanner<B: BlockDevice> {
    volume: Arc<ExfatVolume<B>>,
    current_cluster: u32,
    sector_in_cluster: u32,
    entry_in_sector: u32,
    sector: Option<(u64, Vec<u8>)>,
    finished: bool,
    slots_scanned: u32,
}

const MAX_DIR_SLOTS: u32 = 1 << 20; // ≥1M entries — defends against pathological loops.

impl<B: BlockDevice + 'static> DirectoryScanner<B> {
    fn new(volume: Arc<ExfatVolume<B>>, first_cluster: u32) -> Self {
        Self {
            volume,
            current_cluster: first_cluster,
            sector_in_cluster: 0,
            entry_in_sector: 0,
            sector: None,
            finished: false,
            slots_scanned: 0,
        }
    }

    fn current_lba(&self) -> u64 {
        self.volume.first_sector_of_cluster(self.current_cluster) + self.sector_in_cluster as u64
    }

    async fn ensure_sector_loaded(&mut self, lba: u64) -> Result<(), FsError> {
        let lbs = self.volume.bytes_per_sector as usize;
        let need_load = match self.sector {
            Some((cached, _)) if cached == lba => false,
            _ => true,
        };
        if need_load {
            let mut buf = vec![0u8; lbs];
            self.volume.read_sector(lba, &mut buf).await?;
            self.sector = Some((lba, buf));
        }
        Ok(())
    }

    /// Pull the next file group (FileEntry + Stream + Name slots),
    /// or `None` if the scan is exhausted.
    async fn next(&mut self) -> Result<Option<ExfatDirent>, FsError> {
        if self.finished {
            return Ok(None);
        }
        loop {
            let lba = self.current_lba();
            self.ensure_sector_loaded(lba).await?;
            let lbs = self.volume.bytes_per_sector as usize;
            let entries_per_sector = (lbs / DIR_ENTRY_SIZE) as u32;

            while self.entry_in_sector < entries_per_sector {
                if self.slots_scanned >= MAX_DIR_SLOTS {
                    self.finished = true;
                    return Ok(None);
                }
                self.slots_scanned += 1;

                let off = (self.entry_in_sector as usize) * DIR_ENTRY_SIZE;
                let etype = self.sector.as_ref().unwrap().1[off];

                if etype == entry_type::END_OF_DIRECTORY {
                    self.finished = true;
                    return Ok(None);
                }
                if !super::dir::is_in_use(etype) {
                    // Tombstoned slot — skip without resetting any
                    // group reassembly (we always start fresh on
                    // each 0x85, so there's nothing to reset).
                    self.entry_in_sector += 1;
                    continue;
                }
                if etype == entry_type::FILE {
                    // Found the start of a group. Read the primary,
                    // then the stream extension, then the name
                    // slots (count derived from
                    // `secondary_count` − 1).
                    let file = read_file_entry(&self.sector.as_ref().unwrap().1, off);
                    let secondary_count = file.secondary_count as u32;
                    self.entry_in_sector += 1;
                    if secondary_count < 2 {
                        // Spec demands ≥1 stream + ≥1 name; if the
                        // count is bogus, skip this entry.
                        continue;
                    }

                    // Stream extension follows the primary.
                    let (stream_lba, stream_off) =
                        self.locate_next_slot(lba).await?;
                    self.ensure_sector_loaded(stream_lba).await?;
                    let stream_etype = self.sector.as_ref().unwrap().1[stream_off];
                    if stream_etype != entry_type::STREAM_EXTENSION {
                        continue;
                    }
                    let stream =
                        read_stream_entry(&self.sector.as_ref().unwrap().1, stream_off);
                    self.advance_one_slot();
                    let name_slot_count = secondary_count - 1;
                    let name_length = stream.name_length as usize;

                    // Reassemble the UTF-16 name across the
                    // following 0xC1 slots; spec §7.7 says the
                    // total slot count is exactly
                    // ceil(name_length / 15).
                    let mut name_utf16: Vec<u16> = Vec::with_capacity(name_length);
                    let mut remaining = name_length;
                    let mut slots_consumed: u32 = 0;
                    while slots_consumed < name_slot_count && remaining > 0 {
                        let (n_lba, n_off) = self.locate_next_slot(lba).await?;
                        self.ensure_sector_loaded(n_lba).await?;
                        let nt = self.sector.as_ref().unwrap().1[n_off];
                        if nt != entry_type::FILE_NAME {
                            break;
                        }
                        let n_entry =
                            read_filename_entry(&self.sector.as_ref().unwrap().1, n_off);
                        let take = remaining.min(15);
                        let n = n_entry.file_name;
                        for &cu in &n[..take] {
                            name_utf16.push(cu);
                        }
                        remaining -= take;
                        slots_consumed += 1;
                        self.advance_one_slot();
                    }
                    self.slots_scanned += slots_consumed;

                    return Ok(Some(ExfatDirent {
                        file,
                        stream,
                        name_utf16,
                    }));
                }

                // Other primary types (Bitmap, Up-case, Volume
                // Label, etc.) are not surfaced by the directory
                // walk — they're metadata for the volume itself.
                self.entry_in_sector += 1;
            }

            // Sector exhausted — advance to next sector / cluster.
            self.entry_in_sector = 0;
            self.sector_in_cluster += 1;
            if self.sector_in_cluster >= self.volume.sectors_per_cluster {
                self.sector_in_cluster = 0;
                match self.volume.next_cluster(self.current_cluster).await? {
                    FatEntry::Next(n) => self.current_cluster = n,
                    _ => {
                        self.finished = true;
                        return Ok(None);
                    }
                }
            }
            self.sector = None;
        }
    }

    /// Compute the (LBA, byte-offset) of the slot AFTER the cursor
    /// without advancing the cursor. Used to peek the next slot
    /// while reassembling a group.
    async fn locate_next_slot(&self, _current_lba: u64) -> Result<(u64, usize), FsError> {
        let lbs = self.volume.bytes_per_sector as usize;
        let entries_per_sector = (lbs / DIR_ENTRY_SIZE) as u32;
        if self.entry_in_sector < entries_per_sector {
            // Same sector.
            Ok((
                self.current_lba(),
                (self.entry_in_sector as usize) * DIR_ENTRY_SIZE,
            ))
        } else {
            // Crossed a sector boundary mid-group.
            let next_sector_in_cluster = self.sector_in_cluster + 1;
            if next_sector_in_cluster < self.volume.sectors_per_cluster {
                let lba = self.volume.first_sector_of_cluster(self.current_cluster)
                    + next_sector_in_cluster as u64;
                Ok((lba, 0))
            } else {
                // Crossed a cluster boundary mid-group. Walk the
                // FAT for the next cluster.
                match self.volume.next_cluster(self.current_cluster).await? {
                    FatEntry::Next(n) => {
                        let lba = self.volume.first_sector_of_cluster(n);
                        Ok((lba, 0))
                    }
                    _ => Err(FsError::Io(narf_block::BlockError::IOError)),
                }
            }
        }
    }

    /// Bump the cursor by one 32-byte slot, crossing sector /
    /// cluster boundaries as required.
    fn advance_one_slot(&mut self) {
        let lbs = self.volume.bytes_per_sector as usize;
        let entries_per_sector = (lbs / DIR_ENTRY_SIZE) as u32;
        self.entry_in_sector += 1;
        if self.entry_in_sector >= entries_per_sector {
            self.entry_in_sector = 0;
            self.sector_in_cluster += 1;
            if self.sector_in_cluster >= self.volume.sectors_per_cluster {
                self.sector_in_cluster = 0;
                // Cluster-walk happens lazily on the next loop
                // iteration in `next()`; clear the cached sector
                // so we re-load.
            }
            self.sector = None;
        }
    }
}

// ── FileOps / DirOps surface ────────────────────────────────────────

impl<B: BlockDevice + 'static> FileOps for ExfatNode<B> {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let (start_cluster, no_fat_chain, data_length) = {
                let g = self.state.lock();
                (g.first_cluster, g.no_fat_chain, g.data_length)
            };
            if start_cluster < 2 || data_length == 0 || offset >= data_length {
                return Ok(0);
            }
            self.volume
                .read_chain(start_cluster, no_fat_chain, data_length, offset, buf)
                .await
        })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        // TODO: write path requires the bitmap allocator + the
        // §7.4.3 SetChecksum recompute. Deferred per the first-cut
        // scope.
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    fn stat(&self) -> Stat {
        let g = self.state.lock();
        g.stat
    }

    fn truncate<'a>(&'a self, _len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }
}

impl<B: BlockDevice + 'static> DirOps for ExfatNode<B> {
    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        // Disk-backed; sync API is unsupported. The VFS prefers
        // `lookup_async` automatically.
        None
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let needle_utf16: Vec<u16> = name.encode_utf16().collect();
            let needle_upcased = self.volume.upcase.upcase(&needle_utf16);
            let needle_hash = name_hash(&needle_upcased);

            let first_cluster = { self.state.lock().first_cluster };
            let mut scanner = DirectoryScanner::new(self.volume.clone(), first_cluster);
            while let Some(d) = scanner.next().await? {
                let stream_hash = d.stream.name_hash;
                if stream_hash != needle_hash {
                    continue;
                }
                let cand_upcased = self.volume.upcase.upcase(&d.name_utf16);
                if self
                    .volume
                    .upcase
                    .equal_ignoring_case(&cand_upcased, &needle_upcased)
                {
                    let node = ExfatNode::from_dirent(self.volume.clone(), &d);
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
            let needle_utf16: Vec<u16> = name.encode_utf16().collect();
            let needle_upcased = self.volume.upcase.upcase(&needle_utf16);
            let needle_hash = name_hash(&needle_upcased);

            let first_cluster = { self.state.lock().first_cluster };
            let mut scanner = DirectoryScanner::new(self.volume.clone(), first_cluster);
            while let Some(d) = scanner.next().await? {
                if !d.is_directory() {
                    continue;
                }
                let stream_hash = d.stream.name_hash;
                if stream_hash != needle_hash {
                    continue;
                }
                let cand_upcased = self.volume.upcase.upcase(&d.name_utf16);
                if self
                    .volume
                    .upcase
                    .equal_ignoring_case(&cand_upcased, &needle_upcased)
                {
                    let node = ExfatNode::from_dirent(self.volume.clone(), &d);
                    return Ok(Arc::new(node) as Arc<dyn DirOps>);
                }
            }
            Err(FsError::NotFound)
        })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
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
            let first_cluster = { self.state.lock().first_cluster };
            let mut scanner = DirectoryScanner::new(self.volume.clone(), first_cluster);
            let mut out = Vec::new();
            let mut count = 0;
            while let Some(d) = scanner.next().await? {
                if count >= cursor {
                    let ft = if d.is_directory() {
                        FileType::Dir
                    } else {
                        FileType::File
                    };
                    out.push((String::from_utf16_lossy(&d.name_utf16), ft));
                    if out.len() >= max {
                        break;
                    }
                }
                count += 1;
            }
            Ok(out)
        })
    }

    // Write paths — all `Unsupported` until the bitmap allocator
    // lands. The default trait impls would already return
    // `Unsupported`; we leave them defaulted rather than override.
}

//! ISO 9660 Node — `FileOps` + `DirOps` implementations.
//!
//! Clean-room implementation. Directory walking, identifier decode,
//! and file-extent reads all derive strictly from the public
//! references below — no GPL/LGPL ISO 9660 source consulted.
//!
//! References:
//! - ECMA-119 §6.8 (Directory Hierarchy — root, ".", ".." semantics).
//! - ECMA-119 §7.6 (File Identifier syntax for files: name `.`
//!   extension `;` version-1-to-32767).
//! - ECMA-119 §9.1 (Directory Record — header, file identifier,
//!   trailing padding to even-byte boundary).
//! - ECMA-119 §9.1.11.1 (special identifiers: 0x00 = ".",
//!   0x01 = "..").
//! - ECMA-119 §6.5.1 / §7.6.3 (file extents are contiguous on the
//!   medium; LBA + offset = byte position, no FAT-style chains).
//! - OSDev Wiki, "ISO 9660 — Reading the Directory Tree".
//!   <https://wiki.osdev.org/ISO_9660>

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_block::{BlockDevice, BlockError};
use narf_filesystem::{
    DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, Mode, Stat,
};
use narf_lib::sync::IrqSafeSpinLock;

use super::dir::{read_directory_record, DirectoryRecord};
use super::volume::{read_extent, Iso9660Volume};
use super::SECTOR_SIZE;

/// Per-node state. ISO 9660 files/directories are immutable — a
/// node only needs its starting extent + size + cached `Stat`.
#[derive(Debug)]
pub struct Iso9660NodeState {
    pub extent_lba: u32,
    pub data_length: u32,
    pub stat: Stat,
}

/// A file or directory in an ISO 9660 volume.
#[derive(Debug)]
pub struct Iso9660Node<B: BlockDevice> {
    pub volume: Arc<Iso9660Volume<B>>,
    pub state: IrqSafeSpinLock<Iso9660NodeState>,
}

impl<B: BlockDevice + 'static> Iso9660Node<B> {
    /// Build a node from a [`DirectoryRecord`].
    pub fn from_record(volume: Arc<Iso9660Volume<B>>, record: &DirectoryRecord) -> Self {
        let extent_lba = record.extent_lba_le();
        let data_length = record.data_length_le();
        let mode = if record.is_directory() {
            Mode::DIR_RO
        } else {
            Mode::FILE_RO
        };
        let stat = Stat {
            size: data_length as u64,
            blocks: (data_length as u64).div_ceil(SECTOR_SIZE as u64),
            mode,
            mtime_cycles: 0,
        };
        Self {
            volume,
            state: IrqSafeSpinLock::new(Iso9660NodeState {
                extent_lba,
                data_length,
                stat,
            }),
        }
    }
}

// ── FileOps ─────────────────────────────────────────────────────────

impl<B: BlockDevice + 'static> FileOps for Iso9660Node<B> {
    /// Read up to `buf.len()` bytes starting at `offset`. ISO 9660
    /// extents are contiguous on the medium (ECMA-119 §6.5.1), so
    /// the byte-to-LBA mapping is trivially:
    ///
    ///   sector_lba    = extent_lba + (offset / SECTOR_SIZE)
    ///   sector_offset = offset % SECTOR_SIZE
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let (extent_lba, data_length) = {
                let g = self.state.lock();
                (g.extent_lba, g.data_length)
            };
            if offset >= data_length as u64 {
                return Ok(0);
            }
            let mut remaining = core::cmp::min(buf.len() as u64, data_length as u64 - offset);
            let mut current_lba = extent_lba as u64 + offset / SECTOR_SIZE as u64;
            let mut sector_offset = (offset % SECTOR_SIZE as u64) as usize;
            let mut total_read = 0usize;

            let mut sector = alloc::vec![0u8; SECTOR_SIZE];
            while remaining > 0 {
                self.volume.read_sector(current_lba, &mut sector).await?;
                let n = core::cmp::min(remaining as usize, SECTOR_SIZE - sector_offset);
                buf[total_read..total_read + n]
                    .copy_from_slice(&sector[sector_offset..sector_offset + n]);
                total_read += n;
                remaining -= n as u64;
                current_lba += 1;
                sector_offset = 0;
            }
            Ok(total_read)
        })
    }

    /// ECMA-119 §6.1: ISO 9660 volumes are non-rewritable — the
    /// medium is authored offline by mkisofs/xorriso. `write`
    /// always fails with `ReadOnly`.
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }

    fn stat(&self) -> Stat {
        self.state.lock().stat
    }

    /// ECMA-119 §6.1 — see `write`. ISO 9660 file extents are
    /// fixed at authoring time.
    fn truncate<'a>(&'a self, _len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }
}

// ── DirOps ──────────────────────────────────────────────────────────

impl<B: BlockDevice + 'static> DirOps for Iso9660Node<B> {
    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        // Disk-backed FS — synchronous lookup is unsupported. The
        // VFS prefers `lookup_async` automatically.
        None
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let entries = scan_directory(&self.volume, &self.state).await?;
            for (found_name, record) in entries {
                if names_match(&found_name, name) {
                    return Ok(Arc::new(Iso9660Node::from_record(
                        self.volume.clone(),
                        &record,
                    )) as Arc<dyn FileOps>);
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
            for (found_name, record) in entries {
                if names_match(&found_name, name) && record.is_directory() {
                    return Ok(Arc::new(Iso9660Node::from_record(
                        self.volume.clone(),
                        &record,
                    )) as Arc<dyn DirOps>);
                }
            }
            Err(FsError::NotFound)
        })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // Disk-backed FS — sync iteration is not supported. Use
        // `enumerate_async` instead.
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
            let mut out = Vec::new();
            // Skip "." and ".." per the convention used elsewhere
            // in NARF (memfs / FAT both omit them from
            // `enumerate_async`); they're surfaced via `..`/`.` at
            // the path-resolution layer instead.
            let user_visible: Vec<_> = entries
                .into_iter()
                .filter(|(name, _)| name != "." && name != "..")
                .collect();
            for (i, (name, record)) in user_visible.into_iter().enumerate() {
                if i < cursor {
                    continue;
                }
                if out.len() >= max {
                    break;
                }
                let ft = if record.is_directory() {
                    FileType::Dir
                } else {
                    FileType::File
                };
                out.push((name, ft));
            }
            Ok(out)
        })
    }

    // ECMA-119 §6.1: ISO 9660 volumes are non-rewritable. We
    // override every mutating directory operation to surface
    // `ReadOnly` rather than the trait-default `Unsupported`, so
    // callers can distinguish "this medium does not accept writes"
    // from "this driver has not implemented writes yet."
    fn unlink<'a>(&'a self, _name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }

    fn create<'a>(&'a self, _name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }

    fn mkdir<'a>(&'a self, _name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }

    fn rmdir<'a>(&'a self, _name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }

    fn symlink<'a>(&'a self, _name: &'a str, _target: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }

    fn rename<'a>(&'a self, _old_name: &'a str, _new_name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }
}

// ── Directory scan ─────────────────────────────────────────────────

/// Read a directory's entire extent into RAM and walk its records,
/// returning `(name, record_header)` pairs. ECMA-119 §9.1.1
/// guarantees a record never crosses a logical-sector boundary, so
/// a `length == 0` byte means "skip to the next sector". We honour
/// that by aligning the cursor up to the next 2KiB boundary.
///
/// The PVD field (§8.4.18) gives us the root extent; nested
/// directory records carry the same `(extent_lba, data_length)`
/// pair for their own bodies.
async fn scan_directory<B: BlockDevice + 'static>(
    volume: &Arc<Iso9660Volume<B>>,
    state: &IrqSafeSpinLock<Iso9660NodeState>,
) -> Result<Vec<(String, DirectoryRecord)>, FsError> {
    let (extent_lba, data_length) = {
        let g = state.lock();
        (g.extent_lba, g.data_length)
    };
    if data_length == 0 {
        return Ok(Vec::new());
    }
    let n_sectors = (data_length as usize).div_ceil(SECTOR_SIZE) as u32;
    let body = read_extent(volume, extent_lba as u64, n_sectors).await?;

    let mut out = Vec::new();
    let mut offset: usize = 0;
    let limit = core::cmp::min(body.len(), data_length as usize);
    while offset < limit {
        // Need at least a header byte to inspect.
        if offset + 1 > body.len() {
            break;
        }
        let length_byte = body[offset];
        if length_byte == 0 {
            // §9.1.1 — zero length marks "no more records in this
            // sector". Round up to the next sector boundary and
            // continue.
            let next = (offset + SECTOR_SIZE) & !(SECTOR_SIZE - 1);
            if next <= offset {
                break;
            }
            offset = next;
            continue;
        }
        if (length_byte as usize) < core::mem::size_of::<DirectoryRecord>() {
            // Malformed: header is shorter than the fixed prefix.
            return Err(FsError::Io(BlockError::IOError));
        }
        if offset + length_byte as usize > body.len() {
            return Err(FsError::Io(BlockError::IOError));
        }
        let record = read_directory_record(&body, offset);
        let id_off = offset + core::mem::size_of::<DirectoryRecord>();
        let id_len = record.file_identifier_length as usize;
        if id_off + id_len > body.len() {
            return Err(FsError::Io(BlockError::IOError));
        }
        let id = &body[id_off..id_off + id_len];
        let name = decode_file_identifier(id);
        out.push((name, record));
        offset += length_byte as usize;
    }
    Ok(out)
}

/// Decode an ISO 9660 file identifier (ECMA-119 §7.6 / §9.1.11) to
/// a printable string.
///
/// - The two special single-byte identifiers `0x00` and `0x01` are
///   reserved for the current directory (".") and parent directory
///   ("..") records (§9.1.11.1).
/// - Otherwise the identifier is `name "." extension ";" version`
///   (`d-` or `d1-` characters). The `;version` suffix is dropped
///   for display purposes — every disc tags every file with `;1`
///   and the visible name conventionally omits it.
/// - Directories carry no extension separator and no version suffix
///   in practice, but our decoder is lenient: anything past `;` is
///   stripped regardless.
pub(crate) fn decode_file_identifier(bytes: &[u8]) -> String {
    if bytes.len() == 1 {
        match bytes[0] {
            0x00 => return String::from("."),
            0x01 => return String::from(".."),
            _ => {}
        }
    }
    let mut s = String::with_capacity(bytes.len());
    for &b in bytes {
        if b == b';' {
            break;
        }
        s.push(b as char);
    }
    // ECMA-119 §7.6 leaves a trailing '.' on extensionless files
    // (the separator is mandatory in d1-form). Strip it for the
    // user-visible name.
    if s.ends_with('.') {
        s.pop();
    }
    s
}

/// Compare a stored ISO 9660 name (always uppercase per ECMA-119
/// §7.4.1) against a user-supplied lookup key. ECMA-119 file
/// identifiers are case-insensitive on the medium; we honour that.
pub(crate) fn names_match(stored: &str, query: &str) -> bool {
    stored.eq_ignore_ascii_case(query)
}

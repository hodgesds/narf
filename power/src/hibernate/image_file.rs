//! The image file (S4 lane 6): Linux's swap-file hibernation, with a file of
//! its own on the persistent filesystem.
//!
//! [`prepare`] runs before the freeze, while the filesystem is live:
//! - it creates the file, or grows it, to the image's size: `fallocate`, or
//!   zeros where the filesystem cannot preallocate (ext2's block-mapped
//!   files);
//! - it maps every 4 KiB block to a device block with `bmap` (FIBMAP), as
//!   Linux's swap-file setup maps a swap file;
//! - it finds the device under the file: the mount's source, or else the
//!   one registered device that holds what the filesystem wrote.
//!
//! The file's first block is its [`Locator`]: the extent list. `prepare`
//! writes it *through the filesystem*, then reads it back from the device
//! at the block `bmap` named. A marker in the last block is checked the
//! same way. A mapping or device that disagrees refuses the file before any
//! raw write, so a wrong guess cannot land on another file's blocks.
//!
//! The image is then written raw, through [`ExtentStore`], to the blocks
//! after the locator, bypassing the filesystem as swap I/O does. The resume
//! finds the locator at `narf.resume=<device> narf.resume_offset=<block>`,
//! Linux's `resume=` and `resume_offset=` (4 KiB units).

use alloc::string::String;
use alloc::vec::Vec;

use narf_filesystem::{FileOps, FsError};

use crate::suspend_service::{BlockStore, ImageStore, ServiceError};

/// The unit the file is mapped in, and the `resume_offset` unit.
pub const BLOCK: u64 = 4096;
pub const LOCATOR_MAGIC: &[u8; 8] = b"NARFHIB1";
const LOCATOR_HEADER: usize = 8 + 4 + 4 + 8;
const EXTENT_LEN: usize = 24;
/// Extents one locator block holds. More fragmentation than this refuses
/// the file (Linux chains swap-map pages instead).
pub const MAX_EXTENTS: usize = (BLOCK as usize - LOCATOR_HEADER) / EXTENT_LEN;

/// A run of file blocks stored in consecutive device blocks, in [`BLOCK`]
/// units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent {
    pub file_block: u64,
    pub device_block: u64,
    pub blocks: u64,
}

/// The image file's first block: where each of its blocks is on the device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Locator {
    pub file_blocks: u64,
    pub extents: Vec<Extent>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocatorError {
    Magic,
    Malformed,
}

impl Locator {
    /// Coalesce a per-block device map (`map[i]` holds file block `i`).
    pub fn from_map(map: &[u64]) -> Self {
        let mut extents: Vec<Extent> = Vec::new();
        for (i, &device_block) in map.iter().enumerate() {
            let i = i as u64;
            match extents.last_mut() {
                Some(e)
                    if e.file_block + e.blocks == i
                        && e.device_block + e.blocks == device_block =>
                {
                    e.blocks += 1
                }
                _ => extents.push(Extent {
                    file_block: i,
                    device_block,
                    blocks: 1,
                }),
            }
        }
        Self {
            file_blocks: map.len() as u64,
            extents,
        }
    }

    /// The device block that holds file block `file_block`.
    pub fn device_block(&self, file_block: u64) -> Option<u64> {
        let e = self
            .extents
            .iter()
            .find(|e| file_block >= e.file_block && file_block - e.file_block < e.blocks)?;
        Some(e.device_block + (file_block - e.file_block))
    }

    pub fn encode(&self) -> Option<[u8; BLOCK as usize]> {
        if self.extents.len() > MAX_EXTENTS {
            return None;
        }
        let mut page = [0u8; BLOCK as usize];
        page[..8].copy_from_slice(LOCATOR_MAGIC);
        page[8..12].copy_from_slice(&1u32.to_le_bytes());
        page[12..16].copy_from_slice(&(self.extents.len() as u32).to_le_bytes());
        page[16..24].copy_from_slice(&self.file_blocks.to_le_bytes());
        for (k, e) in self.extents.iter().enumerate() {
            let at = LOCATOR_HEADER + k * EXTENT_LEN;
            page[at..at + 8].copy_from_slice(&e.file_block.to_le_bytes());
            page[at + 8..at + 16].copy_from_slice(&e.device_block.to_le_bytes());
            page[at + 16..at + 24].copy_from_slice(&e.blocks.to_le_bytes());
        }
        Some(page)
    }

    /// Decode a locator block. The extents must cover the file blocks in
    /// order without gaps; the image's seal authenticates the rest.
    pub fn decode(page: &[u8]) -> Result<Self, LocatorError> {
        if page.len() < BLOCK as usize || &page[..8] != LOCATOR_MAGIC {
            return Err(LocatorError::Magic);
        }
        let u32_at = |at: usize| u32::from_le_bytes(page[at..at + 4].try_into().unwrap());
        let u64_at = |at: usize| u64::from_le_bytes(page[at..at + 8].try_into().unwrap());
        let count = u32_at(12) as usize;
        if u32_at(8) != 1 || count == 0 || count > MAX_EXTENTS {
            return Err(LocatorError::Malformed);
        }
        let file_blocks = u64_at(16);
        let mut extents = Vec::with_capacity(count);
        let mut next = 0u64;
        for k in 0..count {
            let at = LOCATOR_HEADER + k * EXTENT_LEN;
            let e = Extent {
                file_block: u64_at(at),
                device_block: u64_at(at + 8),
                blocks: u64_at(at + 16),
            };
            if e.file_block != next || e.blocks == 0 {
                return Err(LocatorError::Malformed);
            }
            next = e
                .file_block
                .checked_add(e.blocks)
                .ok_or(LocatorError::Malformed)?;
            extents.push(e);
        }
        if next != file_blocks {
            return Err(LocatorError::Malformed);
        }
        Ok(Self {
            file_blocks,
            extents,
        })
    }
}

/// The image region of an image file: file bytes after the locator block,
/// through the locator onto a whole-device store.
#[derive(Debug)]
pub struct ExtentStore<D: ImageStore> {
    device: D,
    locator: Locator,
}

impl<D: ImageStore> ExtentStore<D> {
    pub fn new(device: D, locator: Locator) -> Self {
        Self { device, locator }
    }

    /// Split `[offset, offset + len)` of the image region into device runs.
    fn runs(
        &self,
        offset: u64,
        len: usize,
        mut each: impl FnMut(u64, usize, usize) -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError> {
        let mut done = 0usize;
        while done < len {
            let file_byte = BLOCK + offset + done as u64;
            let block = file_byte / BLOCK;
            let within = file_byte % BLOCK;
            let e = self
                .locator
                .extents
                .iter()
                .find(|e| block >= e.file_block && block - e.file_block < e.blocks)
                .ok_or(ServiceError::Store)?;
            let device_byte = (e.device_block + (block - e.file_block)) * BLOCK + within;
            let extent_left = (e.file_block + e.blocks - block) * BLOCK - within;
            let n = ((len - done) as u64).min(extent_left) as usize;
            each(device_byte, done, n)?;
            done += n;
        }
        Ok(())
    }
}

impl<D: ImageStore> ImageStore for ExtentStore<D> {
    fn len_bytes(&self) -> u64 {
        self.locator.file_blocks.saturating_sub(1) * BLOCK
    }

    fn read_exact(&self, offset: u64, out: &mut [u8]) -> Result<(), ServiceError> {
        if offset + out.len() as u64 > self.len_bytes() {
            return Err(ServiceError::Store);
        }
        let len = out.len();
        let device = &self.device;
        self.runs(offset, len, |at, done, n| {
            device.read_exact(at, &mut out[done..done + n])
        })
    }

    fn write_all(&self, offset: u64, data: &[u8]) -> Result<(), ServiceError> {
        if offset + data.len() as u64 > self.len_bytes() {
            return Err(ServiceError::Store);
        }
        let device = &self.device;
        self.runs(offset, data.len(), |at, done, n| {
            device.write_all(at, &data[done..done + n])
        })
    }

    fn flush(&self) -> Result<(), ServiceError> {
        self.device.flush()
    }
}

/// Why an image file could not be prepared. No raw write has happened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImageFileError {
    /// The path is not absolute or no mount covers it.
    NoMount,
    /// The mount's source is no registered block device, or no device holds
    /// what the filesystem wrote.
    NoDevice(String),
    Fs(FsError),
    /// File block `0` has no device block (a hole, or a block the
    /// filesystem maps only in pieces).
    Unmapped(u64),
    /// More extents than one locator block holds.
    Fragmented(usize),
    /// The named device read back something other than what the
    /// filesystem wrote, or two devices both did: the mapping or the device
    /// is wrong.
    Mismatch,
    Store,
}

impl From<FsError> for ImageFileError {
    fn from(e: FsError) -> Self {
        Self::Fs(e)
    }
}

/// A prepared image file.
#[derive(Debug)]
pub struct ImageFile {
    /// The registry name of the device under the file (`narf.resume=`).
    pub device: String,
    pub locator: Locator,
    dev: BlockStore,
}

impl ImageFile {
    /// `narf.resume_offset=`: the locator's device block, in [`BLOCK`] units.
    pub fn resume_offset(&self) -> u64 {
        self.locator.extents[0].device_block
    }

    /// The image region, for the sealed writer.
    pub fn store(&self) -> ExtentStore<BlockStore> {
        ExtentStore::new(self.dev.clone(), self.locator.clone())
    }
}

/// Write `data` at `offset` through the filesystem, all of it.
async fn write_through(file: &dyn FileOps, offset: u64, data: &[u8]) -> Result<(), FsError> {
    let mut done = 0;
    while done < data.len() {
        let n = file.write(offset + done as u64, &data[done..]).await?;
        if n == 0 {
            return Err(FsError::NoSpace);
        }
        done += n;
    }
    Ok(())
}

/// Grow `file` to `len` bytes of allocated blocks.
async fn allocate(file: &dyn FileOps, len: u64) -> Result<(), FsError> {
    let size = file.stat().size;
    if size >= len {
        return Ok(());
    }
    match file.fallocate(0, 0, len).await {
        Err(FsError::Unsupported) => {
            // `posix_fallocate`'s fallback: write zeros.
            let zeros = alloc::vec![0u8; 1 << 20];
            let mut at = size - size % BLOCK;
            while at < len {
                let n = (len - at).min(zeros.len() as u64) as usize;
                write_through(file, at, &zeros[..n]).await?;
                at += n as u64;
            }
            Ok(())
        }
        other => other,
    }
}

/// Read device block `device_block` (one [`BLOCK`]) raw.
fn read_raw(dev: &BlockStore, device_block: u64) -> Result<Vec<u8>, ImageFileError> {
    let mut buf = alloc::vec![0u8; BLOCK as usize];
    dev.read_exact(device_block * BLOCK, &mut buf)
        .map_err(|_| ImageFileError::Store)?;
    Ok(buf)
}

/// Create or grow the image file at `path` to hold `image_len` bytes after
/// its locator, map it, find its device and prove both.
pub async fn prepare(path: &str, image_len: u64) -> Result<ImageFile, ImageFileError> {
    let ns = narf_filesystem::initial_mount_ns();
    let (dir, leaf) = ns
        .resolve_parent_absolute(path, |_, dir, leaf| (dir, String::from(leaf)))
        .ok_or(ImageFileError::NoMount)?;
    let file = match dir.lookup_async(&leaf).await {
        Ok(file) => file,
        Err(FsError::NotFound) => dir.create(&leaf).await?,
        Err(e) => return Err(e.into()),
    };
    let blocks = 1 + image_len.div_ceil(BLOCK);
    allocate(&*file, blocks * BLOCK).await?;
    file.fsync(false).await?;

    let mut map = Vec::with_capacity(blocks as usize);
    for block in 0..blocks {
        let device_block = file.bmap(block, BLOCK as u32).await?;
        if device_block == 0 {
            return Err(ImageFileError::Unmapped(block));
        }
        map.push(device_block);
    }
    let locator = Locator::from_map(&map);
    let page = locator
        .encode()
        .ok_or(ImageFileError::Fragmented(locator.extents.len()))?;

    // Prove the mapping and find the device: what the filesystem wrote must
    // be what the device holds at the mapped blocks. A mount that names its
    // source must match it. One that does not (`mount_arc` records none,
    // and ext2 has no `show_devname`) is matched against every registered
    // device, and exactly one may hold both writes.
    let mut marker = [0u8; 32];
    for (k, chunk) in marker.chunks_mut(8).enumerate() {
        let (r, _) = narf_memory::kaslr::random_u64();
        chunk.copy_from_slice(&(r ^ k as u64).to_le_bytes());
    }
    write_through(&*file, 0, &page).await?;
    write_through(&*file, (blocks - 1) * BLOCK, &marker).await?;
    file.fsync(false).await?;
    let holds = |dev: &BlockStore| {
        read_raw(dev, map[0]).is_ok_and(|b| b == page[..])
            && read_raw(dev, map[blocks as usize - 1]).is_ok_and(|b| b[..32] == marker)
    };
    let named = ns
        .resolve_absolute(path, |fs, _| fs.show_devname())
        .flatten()
        .or_else(|| ns.mount_devname_at(path));
    let (name, dev) = match named {
        Some(source) => {
            let name = String::from(source.strip_prefix("/dev/").unwrap_or(&source));
            let dev = BlockStore::new(
                narf_block::registry::find_block_device(&name)
                    .ok_or_else(|| ImageFileError::NoDevice(source.clone()))?,
            );
            if !holds(&dev) {
                return Err(ImageFileError::Mismatch);
            }
            (name, dev)
        }
        None => {
            let mut found = None;
            for registered in narf_block::registry::block_devices() {
                let dev = BlockStore::new(registered.dev.clone());
                if holds(&dev) {
                    if found.is_some() {
                        return Err(ImageFileError::Mismatch);
                    }
                    found = Some((String::from(registered.name), dev));
                }
            }
            found.ok_or_else(|| ImageFileError::NoDevice(String::from(path)))?
        }
    };
    Ok(ImageFile {
        device: name,
        locator,
        dev,
    })
}

#[cfg(feature = "kernel-test")]
#[path = "image_file_tests.rs"]
mod tests;

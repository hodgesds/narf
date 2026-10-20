//! An image-file block device that records the ordered write/flush stream.
//!
//! It advertises a volatile write cache with native FUA (an NVMe drive with
//! VWC, the shape the user's root sits on), so the driver must issue real
//! flush barriers; the log is what the crash-consistency pass replays. It
//! also polices the request shapes the driver promises (spec §4: "a
//! superblock copy and every tree node reach the device as one request"),
//! which matters on 512-byte-LBA devices where a node spans many LBAs.

use std::collections::BTreeMap;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use narf_block::{BlockCaps, BlockDeviceSync, BlockIoError};

/// Byte offsets of the superblock copies (`btrfs_sb_offset`).
pub const SB_OFFSETS: [u64; 3] = [0x1_0000, 0x400_0000, 0x40_0000_0000];
pub const SB_LEN: u64 = 4096;
/// `btrfs_super_block::generation`.
const SB_GENERATION: usize = 0x48;

/// One device request, in completion order (the device is synchronous, so
/// completion order is submission order).
#[derive(Clone, Debug)]
pub enum Ev {
    Write {
        off: u64,
        data: std::sync::Arc<[u8]>,
        fua: bool,
    },
    Flush,
}

pub struct RecDev {
    file: File,
    len: u64,
    lba: u32,
    fsid: [u8; 16],
    nodesize: u64,
    recording: AtomicBool,
    log: Mutex<Vec<Ev>>,
    /// Physical extents of tree nodes written this session, by start.
    nodes: Mutex<BTreeMap<u64, u64>>,
    violations: Mutex<Vec<String>>,
    writes: AtomicU64,
    flushes: AtomicU64,
    /// Generation of every primary superblock written, in order.
    sb_gens: Mutex<Vec<u64>>,
}

impl RecDev {
    /// Open `path` read-write as a device of `lba`-byte blocks. `fsid` and
    /// `nodesize` identify tree-node writes for the request-shape checks.
    pub fn open(path: &std::path::Path, lba: u32, fsid: [u8; 16], nodesize: u32) -> Self {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
        let len = file.metadata().unwrap().len();
        assert_eq!(
            len % lba as u64,
            0,
            "image size not a multiple of the LBA size"
        );
        Self {
            file,
            len,
            lba,
            fsid,
            nodesize: nodesize as u64,
            recording: AtomicBool::new(false),
            log: Mutex::new(Vec::new()),
            nodes: Mutex::new(BTreeMap::new()),
            violations: Mutex::new(Vec::new()),
            writes: AtomicU64::new(0),
            flushes: AtomicU64::new(0),
            sb_gens: Mutex::new(Vec::new()),
        }
    }

    pub fn set_recording(&self, on: bool) {
        self.recording.store(on, Ordering::Release);
    }

    pub fn take_log(&self) -> Vec<Ev> {
        std::mem::take(&mut *self.log.lock().unwrap())
    }

    pub fn writes(&self) -> u64 {
        self.writes.load(Ordering::Acquire)
    }

    pub fn flushes(&self) -> u64 {
        self.flushes.load(Ordering::Acquire)
    }

    /// Generations of the primary superblocks written so far.
    pub fn sb_gens(&self) -> Vec<u64> {
        self.sb_gens.lock().unwrap().clone()
    }

    pub fn sb_count(&self) -> usize {
        self.sb_gens.lock().unwrap().len()
    }

    pub fn violations(&self) -> Vec<String> {
        self.violations.lock().unwrap().clone()
    }

    fn violation(&self, v: String) {
        let mut g = self.violations.lock().unwrap();
        if g.len() < 32 {
            g.push(v);
        }
    }

    /// Does `data` start with a tree-node header of this filesystem
    /// (`btrfs_header::fsid` at 0x20, `bytenr` at 0x30)?
    fn is_node(&self, data: &[u8]) -> bool {
        data.len() >= 0x65 && data[0x20..0x30] == self.fsid
    }

    fn police(&self, off: u64, data: &[u8], fua: bool) {
        let end = off + data.len() as u64;
        for (i, &sb) in SB_OFFSETS.iter().enumerate() {
            if off < sb + SB_LEN && sb < end {
                if off != sb || data.len() as u64 != SB_LEN {
                    self.violation(format!(
                        "superblock copy {i} written by a request [{off:#x}, {end:#x}) that is not exactly it"
                    ));
                }
                if i == 0 && !fua {
                    self.violation("primary superblock written without FUA".into());
                }
                if i == 0 && data[0x20..0x30] == self.fsid {
                    self.sb_gens.lock().unwrap().push(sb_generation(data));
                }
                return;
            }
        }
        let mut nodes = self.nodes.lock().unwrap();
        if self.is_node(data) {
            if (data.len() as u64) < self.nodesize {
                self.violation(format!(
                    "tree node at {off:#x} split: request of {} bytes < nodesize {}",
                    data.len(),
                    self.nodesize
                ));
            }
            // Requests that carry several whole nodes are fine; record each.
            let mut o = 0u64;
            while o + self.nodesize <= data.len() as u64 {
                if self.is_node(&data[o as usize..]) {
                    nodes.insert(off + o, off + o + self.nodesize);
                }
                o += self.nodesize;
            }
            return;
        }
        // A non-node request must not land inside a node this session wrote
        // (a partial node rewrite, i.e. one node over several requests).
        if let Some((&s, &e)) = nodes.range(..end).next_back() {
            if e > off && s < end {
                self.violation(format!(
                    "request [{off:#x}, {end:#x}) partially overwrites tree node [{s:#x}, {e:#x}) without a node header"
                ));
                nodes.remove(&s);
            }
        }
    }

    fn do_write(&self, lba: u64, n: u16, data: &[u8], fua: bool) -> Result<(), BlockIoError> {
        let len = n as usize * self.lba as usize;
        let off = lba * self.lba as u64;
        if data.len() < len {
            return Err(BlockIoError::BufferTooSmall);
        }
        if off + len as u64 > self.len {
            return Err(BlockIoError::OutOfRange);
        }
        let data = &data[..len];
        self.police(off, data, fua);
        self.file
            .write_all_at(data, off)
            .map_err(|_| BlockIoError::DriverError)?;
        self.writes.fetch_add(1, Ordering::AcqRel);
        if self.recording.load(Ordering::Acquire) {
            self.log.lock().unwrap().push(Ev::Write {
                off,
                data: data.into(),
                fua,
            });
        }
        Ok(())
    }
}

impl BlockDeviceSync for RecDev {
    fn lba_size(&self) -> u32 {
        self.lba
    }
    fn capacity(&self) -> u64 {
        self.len / self.lba as u64
    }
    fn read(&self, lba: u64, n: u16, out: &mut [u8]) -> Result<(), BlockIoError> {
        let len = n as usize * self.lba as usize;
        let off = lba * self.lba as u64;
        if out.len() < len {
            return Err(BlockIoError::BufferTooSmall);
        }
        if off + len as u64 > self.len {
            return Err(BlockIoError::OutOfRange);
        }
        self.file
            .read_exact_at(&mut out[..len], off)
            .map_err(|_| BlockIoError::DriverError)
    }
    fn write(&self, lba: u64, n: u16, data: &[u8]) -> Result<(), BlockIoError> {
        self.do_write(lba, n, data, false)
    }
    fn write_fua(&self, lba: u64, n: u16, data: &[u8]) -> Result<(), BlockIoError> {
        self.do_write(lba, n, data, true)
    }
    fn flush(&self) -> Result<(), BlockIoError> {
        self.flushes.fetch_add(1, Ordering::AcqRel);
        if self.recording.load(Ordering::Acquire) {
            self.log.lock().unwrap().push(Ev::Flush);
        }
        Ok(())
    }
    fn capabilities(&self) -> BlockCaps {
        BlockCaps {
            volatile_cache: true,
            fua: true,
        }
    }
}

pub fn sb_generation(sb: &[u8]) -> u64 {
    u64::from_le_bytes(sb[SB_GENERATION..SB_GENERATION + 8].try_into().unwrap())
}

/// fsid and nodesize from the primary superblock of an image.
pub fn image_identity(path: &std::path::Path) -> ([u8; 16], u32, u64) {
    let f = File::open(path).unwrap();
    let mut sb = vec![0u8; SB_LEN as usize];
    f.read_exact_at(&mut sb, SB_OFFSETS[0]).unwrap();
    assert_eq!(
        &sb[0x40..0x48],
        b"_BHRfS_M",
        "{}: no btrfs superblock",
        path.display()
    );
    let fsid: [u8; 16] = sb[0x20..0x30].try_into().unwrap();
    let nodesize = u32::from_le_bytes(sb[0x94..0x98].try_into().unwrap());
    (fsid, nodesize, sb_generation(&sb))
}

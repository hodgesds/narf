//! An image-file block device that can record its ordered write/flush
//! stream.
//!
//! It advertises a volatile write cache with native FUA (the shape of an
//! NVMe drive with VWC, where the user's root sits), so the driver must
//! issue real flush barriers. While recording, every write and flush is
//! logged in completion order (the device is synchronous, so that is
//! submission order); the crash scenario replays prefixes of that log.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use narf_block::{BlockCaps, BlockDeviceSync, BlockIoError};

/// One device request.
#[derive(Clone, Debug)]
#[allow(dead_code)] // replayed by the crash scenario
pub enum Ev {
    Write {
        off: u64,
        data: Arc<[u8]>,
        fua: bool,
    },
    Flush,
}

pub struct ImageDev {
    file: File,
    len: u64,
    lba: u32,
    recording: AtomicBool,
    log: Mutex<Vec<Ev>>,
    writes: AtomicU64,
    flushes: AtomicU64,
}

#[allow(dead_code)] // recording is used by the crash scenario
impl ImageDev {
    /// Open `path` read-write as a device of `lba`-byte blocks.
    pub fn open(path: &std::path::Path, lba: u32) -> Self {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
        let len = file.metadata().expect("image metadata").len();
        assert_eq!(
            len % u64::from(lba),
            0,
            "image is not a whole number of LBAs"
        );
        Self {
            file,
            len,
            lba,
            recording: AtomicBool::new(false),
            log: Mutex::new(Vec::new()),
            writes: AtomicU64::new(0),
            flushes: AtomicU64::new(0),
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

    fn do_write(&self, lba: u64, n: u16, data: &[u8], fua: bool) -> Result<(), BlockIoError> {
        let len = n as usize * self.lba as usize;
        let off = lba * u64::from(self.lba);
        if data.len() < len {
            return Err(BlockIoError::BufferTooSmall);
        }
        if off + len as u64 > self.len {
            return Err(BlockIoError::OutOfRange);
        }
        let data = &data[..len];
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

impl BlockDeviceSync for ImageDev {
    fn lba_size(&self) -> u32 {
        self.lba
    }
    fn capacity(&self) -> u64 {
        self.len / u64::from(self.lba)
    }
    fn read(&self, lba: u64, n: u16, out: &mut [u8]) -> Result<(), BlockIoError> {
        let len = n as usize * self.lba as usize;
        let off = lba * u64::from(self.lba);
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
    fn has_real_flush(&self) -> bool {
        true
    }
    fn capabilities(&self) -> BlockCaps {
        BlockCaps {
            volatile_cache: true,
            fua: true,
        }
    }
}

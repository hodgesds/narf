//! ISO 9660 Node and Directory/File Operations.

use alloc::sync::Arc;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::boxed::Box;

use narf_block::BlockDevice;
use narf_filesystem::{DirOps, FileOps, Stat, Mode, FileType, DirEntry, FsFuture, FsError};
use narf_driver_runtime::{DmaBuffer, Cap, alloc_coherent};
use narf_capabilities::Read;
use narf_lib::sync::IrqSafeSpinLock;

use super::volume::Iso9660Volume;
use super::dir::DirectoryRecord;

#[derive(Debug)]
pub struct Iso9660NodeState {
    pub extent_location: u32,
    pub data_length: u32,
    pub stat: Stat,
}

#[derive(Debug)]
pub struct Iso9660Node<B: BlockDevice> {
    pub volume: Arc<Iso9660Volume<B>>,
    pub state: IrqSafeSpinLock<Iso9660NodeState>,
}

impl<B: BlockDevice + 'static> Iso9660Node<B> {
    pub fn new(volume: Arc<Iso9660Volume<B>>, record: &DirectoryRecord) -> Self {
        let extent = record.extent_location[0]; // LE
        let length = record.data_length[0];   // LE
        
        let mode = if record.is_directory() { Mode::DIR_RO } else { Mode::FILE_RO };

        Self {
            volume,
            state: IrqSafeSpinLock::new(Iso9660NodeState {
                extent_location: extent,
                data_length: length,
                stat: Stat {
                    size: length as u64,
                    blocks: (length as u64).div_ceil(2048),
                    mode,
                    mtime_cycles: 0,
                },
            }),
        }
    }
}

impl<B: BlockDevice + 'static> FileOps for Iso9660Node<B> {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let state = self.state.lock();
            if offset >= state.data_length as u64 {
                return Ok(0);
            }
            let mut remaining = core::cmp::min(buf.len() as u64, state.data_length as u64 - offset);
            let start_lba = state.extent_location as u64 + (offset / 2048);
            let mut sector_offset = (offset % 2048) as usize;
            drop(state);

            let mut total_read = 0;
            let mut current_lba = start_lba;

            while remaining > 0 {
                let block_size = 2048;
                let temp_buf = alloc_coherent(block_size, self.volume.domain).map_err(|_| FsError::Io(narf_block::BlockError::IOError))?;
                let cap: Cap<DmaBuffer, Read> = Cap::bootstrap();
                
                let req = narf_block::BlockRequest {
                    op: narf_block::BlockOp::Read,
                    lba: current_lba,
                    blocks: 1,
                    buffer: cap,
                    qos: narf_block::QosHint::Latency,
                    user_tag: 0,
                };
                let completion = self.volume.device.submit(req).await;
                completion.result.map_err(FsError::Io)?;

                let n = core::cmp::min(remaining as usize, block_size - sector_offset);
                let temp_slice = unsafe { core::slice::from_raw_parts(temp_buf.phys_addr().raw() as *const u8, block_size) };
                buf[total_read..total_read + n].copy_from_slice(&temp_slice[sector_offset..sector_offset + n]);

                total_read += n;
                remaining -= n as u64;
                current_lba += 1;
                sector_offset = 0;
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

impl<B: BlockDevice + 'static> DirOps for Iso9660Node<B> {
    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        unimplemented!("Iso9660Node::lookup - disk FS needs lookup_async")
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let mut scanner = DirectoryScanner::new(self.volume.clone(), {
                let state = self.state.lock();
                (state.extent_location, state.data_length)
            });

            while let Some((found_name, record)) = scanner.next().await? {
                if found_name.eq_ignore_ascii_case(name) {
                    return Ok(Arc::new(Iso9660Node::new(self.volume.clone(), &record)) as Arc<dyn FileOps>);
                }
            }
            Err(FsError::NotFound)
        })
    }

    fn lookup_dir(&self, _name: &str) -> Option<Arc<dyn DirOps>> {
        unimplemented!("Iso9660Node::lookup_dir - disk FS needs lookup_dir_async")
    }

    fn lookup_dir_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            let mut scanner = DirectoryScanner::new(self.volume.clone(), {
                let state = self.state.lock();
                (state.extent_location, state.data_length)
            });

            while let Some((found_name, record)) = scanner.next().await? {
                if found_name.eq_ignore_ascii_case(name) && record.is_directory() {
                    return Ok(Arc::new(Iso9660Node::new(self.volume.clone(), &record)) as Arc<dyn DirOps>);
                }
            }
            Err(FsError::NotFound)
        })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        unimplemented!("Iso9660Node::iter - disk FS needs enumerate_async")
    }

    fn enumerate(&self, _cursor: usize, _max: usize) -> Vec<(String, FileType)> {
        Vec::new()
    }

    fn enumerate_async<'a>(&'a self, cursor: usize, max: usize) -> FsFuture<'a, Vec<(String, FileType)>> {
        Box::pin(async move {
            let mut scanner = DirectoryScanner::new(self.volume.clone(), {
                let state = self.state.lock();
                (state.extent_location, state.data_length)
            });
            let mut entries = Vec::new();
            let mut count = 0;
            while let Some((name, record)) = scanner.next().await? {
                if count >= cursor {
                    let ft = if record.is_directory() { FileType::Dir } else { FileType::File };
                    entries.push((name, ft));
                    if entries.len() >= max {
                        break;
                    }
                }
                count += 1;
            }
            Ok(entries)
        })
    }
}

struct DirectoryScanner<B: BlockDevice> {
    volume: Arc<Iso9660Volume<B>>,
    extent_location: u32,
    data_length: u32,
    offset_in_extent: u32,
    buffer: Option<DmaBuffer>,
}

impl<B: BlockDevice + 'static> DirectoryScanner<B> {
    fn new(volume: Arc<Iso9660Volume<B>>, info: (u32, u32)) -> Self {
        Self {
            volume,
            extent_location: info.0,
            data_length: info.1,
            offset_in_extent: 0,
            buffer: None,
        }
    }

    async fn next(&mut self) -> Result<Option<(String, DirectoryRecord)>, FsError> {
        loop {
            if self.offset_in_extent >= self.data_length {
                return Ok(None);
            }

            let sector_in_extent = self.offset_in_extent / 2048;
            let offset_in_sector = (self.offset_in_extent % 2048) as usize;

            if self.buffer.is_none() {
                let lba = self.extent_location as u64 + sector_in_extent as u64;
                let buf = alloc_coherent(2048, self.volume.domain).map_err(|_| FsError::Io(narf_block::BlockError::IOError))?;
                let cap: Cap<DmaBuffer, Read> = Cap::bootstrap();
                
                let req = narf_block::BlockRequest {
                    op: narf_block::BlockOp::Read,
                    lba,
                    blocks: 1,
                    buffer: cap,
                    qos: narf_block::QosHint::Latency,
                    user_tag: 0,
                };
                let completion = self.volume.device.submit(req).await;
                completion.result.map_err(FsError::Io)?;
                self.buffer = Some(buf);
            }

            let buf = self.buffer.as_ref().unwrap();
            let record_ptr = (buf.phys_addr().raw() + offset_in_sector as u64) as *const DirectoryRecord;
            let record = unsafe { *record_ptr };

            if record.length == 0 {
                // End of sector, skip to next sector
                self.offset_in_extent = (sector_in_extent + 1) * 2048;
                self.buffer = None;
                continue;
            }

            let name = if record.file_identifier_length == 1 {
                let id_ptr = (buf.phys_addr().raw() + offset_in_sector as u64 + 33) as *const u8;
                let id = unsafe { *id_ptr };
                match id {
                    0 => String::from("."),
                    1 => String::from(".."),
                    _ => String::from("?"),
                }
            } else {
                let mut s = String::new();
                for i in 0..record.file_identifier_length {
                    let c_ptr = (buf.phys_addr().raw() + offset_in_sector as u64 + 33 + i as u64) as *const u8;
                    let c = unsafe { *c_ptr };
                    if c == b';' { break; } // Ignore version suffix
                    s.push(c as char);
                }
                s
            };

            self.offset_in_extent += record.length as u32;
            if self.offset_in_extent % 2048 == 0 {
                self.buffer = None;
            }

            // ISO 9660 special names: "." and ".." are encoded as bytes 0 and 1.
            return Ok(Some((name, record)));
        }
    }
}

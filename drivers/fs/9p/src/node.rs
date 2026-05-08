//! 9P Node and Directory/File Operations.

use alloc::sync::Arc;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::boxed::Box;

use narf_filesystem::{DirOps, FileOps, Stat, Mode, FileType, DirEntry, FsFuture, FsError};
use super::volume::P9FileSystem;
use super::Qid;

#[derive(Debug)]
pub struct P9Node {
    pub fs: Arc<P9FileSystem>,
    pub fid: u32,
    pub qid: Qid,
}

impl P9Node {
    pub fn new(fs: Arc<P9FileSystem>, fid: u32, qid: Qid) -> Self {
        Self { fs, fid, qid }
    }
}

impl FileOps for P9Node {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let count = buf.len() as u32;
            let resp = self.fs.session.transaction(
                &*self.fs.transport,
                super::message::P9Msg::Tread {
                    fid: self.fid,
                    offset,
                    count,
                },
                self.fs.domain
            ).await?;

            if let super::message::P9Msg::Rread { data } = resp {
                let n = data.len();
                buf[..n].copy_from_slice(&data);
                return Ok(n);
            }
            Err(FsError::Unsupported)
        })
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let data = buf.to_vec();
            let resp = self.fs.session.transaction(
                &*self.fs.transport,
                super::message::P9Msg::Twrite {
                    fid: self.fid,
                    offset,
                    data,
                },
                self.fs.domain
            ).await?;

            if let super::message::P9Msg::Rwrite { count } = resp {
                return Ok(count as usize);
            }
            Err(FsError::Unsupported)
        })
    }

    fn stat(&self) -> Stat {
        // Fallback for sync stat calls
        let ft = if (self.qid.qid_type & 0x80) != 0 { FileType::Dir } else { FileType::File };
        Stat {
            size: 0,
            blocks: 0,
            mode: if ft == FileType::Dir { Mode::DIR_RO } else { Mode::FILE_RO },
            mtime_cycles: 0,
        }
    }

    fn stat_async<'a>(&'a self) -> FsFuture<'a, Stat> {
        Box::pin(async move {
            let resp = self.fs.session.transaction(
                &*self.fs.transport,
                super::message::P9Msg::Tstat { fid: self.fid },
                self.fs.domain
            ).await?;

            if let super::message::P9Msg::Rstat { stat } = resp {
                let ft = if (stat.mode & 0x80000000) != 0 { FileType::Dir } else { FileType::File };
                return Ok(Stat {
                    size: stat.length,
                    blocks: stat.length.div_ceil(512),
                    mode: Mode {
                        file_type: ft,
                        perms: (stat.mode & 0o777) as u16,
                    },
                    mtime_cycles: stat.mtime as u64,
                });
            }
            Err(FsError::Unsupported)
        })
    }

    fn truncate<'a>(&'a self, _len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move {
            // 9P truncate is done via Twstat by setting the length field.
            Err(FsError::Unsupported)
        })
    }
}

impl DirOps for P9Node {
    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        unimplemented!("P9Node::lookup - disk FS needs lookup_async")
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let new_fid = self.fs.session.alloc_fid();
            let resp = self.fs.session.transaction(
                &*self.fs.transport,
                super::message::P9Msg::Twalk {
                    fid: self.fid,
                    newfid: new_fid,
                    wnames: alloc::vec![alloc::string::String::from(name)],
                },
                self.fs.domain
            ).await?;

            if let super::message::P9Msg::Rwalk { qids } = resp {
                if qids.len() == 1 {
                    return Ok(Arc::new(P9Node::new(self.fs.clone(), new_fid, qids[0])) as Arc<dyn FileOps>);
                }
            }
            Err(FsError::NotFound)
        })
    }

    fn lookup_dir(&self, _name: &str) -> Option<Arc<dyn DirOps>> {
        unimplemented!("P9Node::lookup_dir - disk FS needs lookup_dir_async")
    }

    fn lookup_dir_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            let new_fid = self.fs.session.alloc_fid();
            let resp = self.fs.session.transaction(
                &*self.fs.transport,
                super::message::P9Msg::Twalk {
                    fid: self.fid,
                    newfid: new_fid,
                    wnames: alloc::vec![alloc::string::String::from(name)],
                },
                self.fs.domain
            ).await?;

            if let super::message::P9Msg::Rwalk { qids } = resp {
                if qids.len() == 1 {
                    // Check if it's a directory
                    if (qids[0].qid_type & 0x80) != 0 {
                        return Ok(Arc::new(P9Node::new(self.fs.clone(), new_fid, qids[0])) as Arc<dyn DirOps>);
                    }
                }
            }
            Err(FsError::NotFound)
        })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        unimplemented!("P9Node::iter")
    }

    fn enumerate(&self, _cursor: usize, _max: usize) -> Vec<(String, FileType)> {
        unimplemented!("P9Node::enumerate")
    }

    fn enumerate_async<'a>(&'a self, cursor: usize, max: usize) -> FsFuture<'a, Vec<(String, FileType)>> {
        Box::pin(async move {
            let resp = self.fs.session.transaction(
                &*self.fs.transport,
                super::message::P9Msg::Tread {
                    fid: self.fid,
                    offset: cursor as u64, // 9P2000 directory offset is opaque but we'll use cursor
                    count: (max * 128) as u32, // Heuristic: average stat size
                },
                self.fs.domain
            ).await?;

            if let super::message::P9Msg::Rread { data } = resp {
                let mut entries = Vec::new();
                let mut mutable_data = data;
                let mut buf = super::message::P9Buffer::new(&mut mutable_data);
                while buf.offset < buf.data.len() {
                    let s = super::message::P9Stat::decode(&mut buf);
                    let ft = if (s.mode & 0x80000000) != 0 { FileType::Dir } else { FileType::File };
                    entries.push((s.name, ft));
                }
                return Ok(entries);
            }
            Err(FsError::Unsupported)
        })
    }

    fn create<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let new_fid = self.fs.session.alloc_fid();
            let _ = self.fs.session.transaction(
                &*self.fs.transport,
                super::message::P9Msg::Twalk {
                    fid: self.fid,
                    newfid: new_fid,
                    wnames: alloc::vec![],
                },
                self.fs.domain
            ).await?;

            let resp = self.fs.session.transaction(
                &*self.fs.transport,
                super::message::P9Msg::Tcreate {
                    fid: new_fid,
                    name: alloc::string::String::from(name),
                    perm: 0o644,
                    mode: 1, // ORDWR
                },
                self.fs.domain
            ).await?;

            if let super::message::P9Msg::Rcreate { qid, .. } = resp {
                return Ok(Arc::new(P9Node::new(self.fs.clone(), new_fid, qid)) as Arc<dyn FileOps>);
            }
            Err(FsError::Unsupported)
        })
    }

    fn mkdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            let new_fid = self.fs.session.alloc_fid();
            let _ = self.fs.session.transaction(
                &*self.fs.transport,
                super::message::P9Msg::Twalk {
                    fid: self.fid,
                    newfid: new_fid,
                    wnames: alloc::vec![],
                },
                self.fs.domain
            ).await?;

            let resp = self.fs.session.transaction(
                &*self.fs.transport,
                super::message::P9Msg::Tcreate {
                    fid: new_fid,
                    name: alloc::string::String::from(name),
                    perm: 0x80000000 | 0o755, // DMDIR | perms
                    mode: 0, // OREAD
                },
                self.fs.domain
            ).await?;

            if let super::message::P9Msg::Rcreate { qid, .. } = resp {
                return Ok(Arc::new(P9Node::new(self.fs.clone(), new_fid, qid)) as Arc<dyn DirOps>);
            }
            Err(FsError::Unsupported)
        })
    }

    fn unlink<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let temp_fid = self.fs.session.alloc_fid();
            let _ = self.fs.session.transaction(
                &*self.fs.transport,
                super::message::P9Msg::Twalk {
                    fid: self.fid,
                    newfid: temp_fid,
                    wnames: alloc::vec![alloc::string::String::from(name)],
                },
                self.fs.domain
            ).await?;

            let resp = self.fs.session.transaction(
                &*self.fs.transport,
                super::message::P9Msg::Tremove {
                    fid: temp_fid,
                },
                self.fs.domain
            ).await?;

            if let super::message::P9Msg::Rremove = resp {
                return Ok(());
            }
            Err(FsError::Unsupported)
        })
    }

    fn rmdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        self.unlink(name)
    }

    fn rename<'a>(&'a self, _old_name: &'a str, _new_name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            // 9P rename is Twstat on the file's fid
            Err(FsError::Unsupported)
        })
    }
}

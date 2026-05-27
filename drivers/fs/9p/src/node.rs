//! 9P2000 `NinepNode` — VFS adapter that drives the protocol layer.
//!
//! Implements `narf_filesystem::DirOps` + `FileOps` over a per-fid
//! position into the remote tree. Each lookup allocates a fresh fid
//! via `Twalk` (walk(5)). `read`/`stat_async` issue Topen/Tread/Tstat.
//!
//! References: `walk(5)`, `open(5)`, `read(5)`, `stat(5)`, `clunk(5)`.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_filesystem::{
    DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, Mode, Stat,
};

use super::message::{
    decode_header, decode_rerror, decode_rread, decode_rwalk, decode_rwrite, encode_tclunk,
    encode_topen, encode_tread, encode_tstat, encode_twalk, encode_twrite, oflag, qtype,
    MsgType, P9Stat, Qid, WireRead,
};
use super::session::{frame_message, P9Session, Transport};

/// One fid into the remote tree.
pub struct NinepNode {
    transport: Arc<dyn Transport>,
    session: Arc<P9Session>,
    fid: u32,
    qid: Qid,
}

impl core::fmt::Debug for NinepNode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NinepNode")
            .field("fid", &self.fid)
            .field("qid", &self.qid)
            .finish_non_exhaustive()
    }
}

impl NinepNode {
    pub fn new_root(
        transport: Arc<dyn Transport>,
        session: Arc<P9Session>,
        fid: u32,
        qid: Qid,
    ) -> Self {
        Self {
            transport,
            session,
            fid,
            qid,
        }
    }

    fn map_err<E: core::fmt::Debug>(_e: E) -> FsError {
        FsError::Io(narf_block::BlockError::IOError)
    }

    /// Issue a Twalk that clones `self.fid` into a fresh fid (no
    /// names). Used by `lookup_async` so the parent fid stays
    /// valid for subsequent walks.
    async fn walk_clone(&self) -> Result<u32, FsError> {
        let newfid = self.session.alloc_fid();
        let tag = self.session.alloc_tag();
        let req = frame_message(self.session.msize(), MsgType::Twalk, tag, |w| {
            encode_twalk(w, self.fid, newfid, &[])
        })
        .map_err(Self::map_err)?;
        let reply = self
            .transport
            .rpc(&req)
            .await
            .map_err(Self::map_err)?;
        let mut r = WireRead::new(&reply);
        let (_, mt, _) = decode_header(&mut r).map_err(Self::map_err)?;
        match mt {
            MsgType::Rwalk => {
                let _qids = decode_rwalk(&mut r).map_err(Self::map_err)?;
                Ok(newfid)
            }
            MsgType::Rerror => {
                let _ = decode_rerror(&mut r);
                Err(FsError::Io(narf_block::BlockError::IOError))
            }
            _ => Err(FsError::Io(narf_block::BlockError::IOError)),
        }
    }

    /// Twalk by single component, returning the new fid + the qid
    /// of the walked-to file. NotFound surfaces cleanly so the VFS
    /// can route lookup misses without escalating to Io.
    async fn walk_one(&self, name: &str) -> Result<(u32, Qid), FsError> {
        let newfid = self.session.alloc_fid();
        let tag = self.session.alloc_tag();
        let names = [name];
        let req = frame_message(self.session.msize(), MsgType::Twalk, tag, |w| {
            encode_twalk(w, self.fid, newfid, &names)
        })
        .map_err(Self::map_err)?;
        let reply = self
            .transport
            .rpc(&req)
            .await
            .map_err(Self::map_err)?;
        let mut r = WireRead::new(&reply);
        let (_, mt, _) = decode_header(&mut r).map_err(Self::map_err)?;
        match mt {
            MsgType::Rwalk => {
                let qids = decode_rwalk(&mut r).map_err(Self::map_err)?;
                if qids.len() != 1 {
                    // walk(5): zero qids means component not found.
                    return Err(FsError::NotFound);
                }
                Ok((newfid, qids[0]))
            }
            MsgType::Rerror => {
                // walk(5) requires Rerror only when the FIRST
                // component fails (otherwise partial Rwalk). We
                // requested one component, so any Rerror is "not
                // found" semantically.
                let _ = decode_rerror(&mut r);
                Err(FsError::NotFound)
            }
            _ => Err(FsError::Io(narf_block::BlockError::IOError)),
        }
    }

    async fn topen(&self, fid: u32, mode: u8) -> Result<(), FsError> {
        let tag = self.session.alloc_tag();
        let req = frame_message(self.session.msize(), MsgType::Topen, tag, |w| {
            encode_topen(w, fid, mode)
        })
        .map_err(Self::map_err)?;
        let reply = self
            .transport
            .rpc(&req)
            .await
            .map_err(Self::map_err)?;
        let mut r = WireRead::new(&reply);
        let (_, mt, _) = decode_header(&mut r).map_err(Self::map_err)?;
        match mt {
            MsgType::Ropen => Ok(()),
            MsgType::Rerror => {
                let _ = decode_rerror(&mut r);
                Err(FsError::Io(narf_block::BlockError::IOError))
            }
            _ => Err(FsError::Io(narf_block::BlockError::IOError)),
        }
    }

    async fn twrite(
        &self,
        fid: u32,
        offset: u64,
        data: &[u8],
    ) -> Result<u32, FsError> {
        let tag = self.session.alloc_tag();
        let req = frame_message(self.session.msize(), MsgType::Twrite, tag, |w| {
            encode_twrite(w, fid, offset, data)
        })
        .map_err(Self::map_err)?;
        let reply = self
            .transport
            .rpc(&req)
            .await
            .map_err(Self::map_err)?;
        let mut r = WireRead::new(&reply);
        let (_, mt, _) = decode_header(&mut r).map_err(Self::map_err)?;
        match mt {
            MsgType::Rwrite => decode_rwrite(&mut r).map_err(Self::map_err),
            MsgType::Rerror => {
                let _ = decode_rerror(&mut r);
                Err(FsError::Io(narf_block::BlockError::IOError))
            }
            _ => Err(FsError::Io(narf_block::BlockError::IOError)),
        }
    }

    async fn tread(&self, fid: u32, offset: u64, count: u32) -> Result<Vec<u8>, FsError> {
        let tag = self.session.alloc_tag();
        let req = frame_message(self.session.msize(), MsgType::Tread, tag, |w| {
            encode_tread(w, fid, offset, count)
        })
        .map_err(Self::map_err)?;
        let reply = self
            .transport
            .rpc(&req)
            .await
            .map_err(Self::map_err)?;
        let mut r = WireRead::new(&reply);
        let (_, mt, _) = decode_header(&mut r).map_err(Self::map_err)?;
        match mt {
            MsgType::Rread => decode_rread(&mut r).map_err(Self::map_err),
            MsgType::Rerror => {
                let _ = decode_rerror(&mut r);
                Err(FsError::Io(narf_block::BlockError::IOError))
            }
            _ => Err(FsError::Io(narf_block::BlockError::IOError)),
        }
    }

    async fn tstat(&self, fid: u32) -> Result<P9Stat, FsError> {
        let tag = self.session.alloc_tag();
        let req = frame_message(self.session.msize(), MsgType::Tstat, tag, |w| {
            encode_tstat(w, fid)
        })
        .map_err(Self::map_err)?;
        let reply = self
            .transport
            .rpc(&req)
            .await
            .map_err(Self::map_err)?;
        let mut r = WireRead::new(&reply);
        let (_, mt, _) = decode_header(&mut r).map_err(Self::map_err)?;
        match mt {
            MsgType::Rstat => {
                // Rstat outer wrap: nstat[2] precedes the stat
                // structure (stat(5)).
                let _outer = r.read_u16().map_err(Self::map_err)?;
                P9Stat::decode(&mut r).map_err(Self::map_err)
            }
            MsgType::Rerror => {
                let _ = decode_rerror(&mut r);
                Err(FsError::Io(narf_block::BlockError::IOError))
            }
            _ => Err(FsError::Io(narf_block::BlockError::IOError)),
        }
    }

    async fn tclunk(&self, fid: u32) -> Result<(), FsError> {
        let tag = self.session.alloc_tag();
        let req = frame_message(self.session.msize(), MsgType::Tclunk, tag, |w| {
            encode_tclunk(w, fid)
        })
        .map_err(Self::map_err)?;
        let reply = self
            .transport
            .rpc(&req)
            .await
            .map_err(Self::map_err)?;
        let mut r = WireRead::new(&reply);
        let (_, mt, _) = decode_header(&mut r).map_err(Self::map_err)?;
        // Rclunk has no body. Errors are non-fatal — we lose track
        // of a fid but the session remains usable.
        let _ = mt;
        Ok(())
    }

    fn child_node(&self, fid: u32, qid: Qid) -> NinepNode {
        NinepNode {
            transport: self.transport.clone(),
            session: self.session.clone(),
            fid,
            qid,
        }
    }

    /// Stat-derived read of the entire directory's contents in one
    /// or more Tread chunks. Used by `enumerate_async`. Each Tread
    /// returns a stream of `P9Stat` records that we decode in
    /// sequence per read(5).
    async fn read_dir_stream(&self, fid: u32) -> Result<Vec<(String, FileType)>, FsError> {
        // First open the dir for read.
        self.topen(fid, oflag::READ).await?;

        let chunk_size = (self.session.msize().saturating_sub(11)).min(8192);
        let mut all: Vec<u8> = Vec::new();
        let mut offset: u64 = 0;
        loop {
            let chunk = self.tread(fid, offset, chunk_size).await?;
            if chunk.is_empty() {
                break;
            }
            offset += chunk.len() as u64;
            all.extend_from_slice(&chunk);
            if (chunk.len() as u32) < chunk_size {
                break;
            }
        }

        let mut out: Vec<(String, FileType)> = Vec::new();
        let mut r = WireRead::new(&all);
        while r.remaining() > 0 {
            let s = match P9Stat::decode(&mut r) {
                Ok(s) => s,
                Err(_) => break,
            };
            let ft = if (s.mode & super::message::statmode::DIR) != 0 {
                FileType::Dir
            } else {
                FileType::File
            };
            out.push((s.name, ft));
        }
        Ok(out)
    }
}

impl Drop for NinepNode {
    fn drop(&mut self) {
        // We can't .await in Drop; the protocol layer's Tclunk best-
        // effort cleanup happens lazily in the synchronous test
        // contexts. A real driver would post the clunk to a per-
        // session reaper task. For the loopback runner this is a
        // no-op; real transports MUST grow that reaper.
        //
        // Intentionally empty.
    }
}

impl FileOps for NinepNode {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            // open-on-first-read; harmless if already opened (the
            // server will Rerror, which we collapse to Io). The
            // loopback always re-opens cleanly.
            self.topen(self.fid, oflag::READ).await.ok();
            let chunk_size =
                core::cmp::min(buf.len() as u32, self.session.msize().saturating_sub(11));
            let data = self.tread(self.fid, offset, chunk_size).await?;
            let n = core::cmp::min(data.len(), buf.len());
            buf[..n].copy_from_slice(&data[..n]);
            Ok(n)
        })
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            // open(5)-then-write: best-effort re-open for WRITE.
            // The loopback ignores re-open; a real server returns
            // Rerror on a fid that was opened READ which we collapse
            // to a transient IO error so the caller can re-walk.
            let _ = self.topen(self.fid, oflag::WRITE).await;
            // Cap the per-message payload at the server's msize
            // minus the Twrite fixed-header overhead (11 bytes:
            // size[4] type[1] tag[2] fid[4]) per write(5).
            let max_per_msg =
                (self.session.msize().saturating_sub(23)).max(1) as usize;
            let mut total = 0usize;
            while total < buf.len() {
                let n = core::cmp::min(buf.len() - total, max_per_msg);
                let written = self
                    .twrite(self.fid, offset + total as u64, &buf[total..total + n])
                    .await? as usize;
                if written == 0 {
                    break;
                }
                total += written;
            }
            Ok(total)
        })
    }

    fn stat(&self) -> Stat {
        let ft = if (self.qid.qid_type & qtype::DIR) != 0 {
            FileType::Dir
        } else {
            FileType::File
        };
        Stat {
            size: 0,
            blocks: 0,
            mode: if ft == FileType::Dir {
                Mode::DIR_RO
            } else {
                Mode::FILE_RO
            },
            mtime_cycles: 0,
        }
    }

    fn stat_async<'a>(&'a self) -> FsFuture<'a, Stat> {
        Box::pin(async move {
            let st = self.tstat(self.fid).await?;
            let ft = if (st.mode & super::message::statmode::DIR) != 0 {
                FileType::Dir
            } else {
                FileType::File
            };
            Ok(Stat {
                size: st.length,
                blocks: st.length.div_ceil(512),
                mode: Mode {
                    file_type: ft,
                    perms: (st.mode & 0o777) as u16,
                },
                mtime_cycles: st.mtime as u64,
            })
        })
    }
}

impl DirOps for NinepNode {
    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        // Async-only; the VFS routes to lookup_async automatically.
        None
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let (newfid, qid) = self.walk_one(name).await?;
            Ok(Arc::new(self.child_node(newfid, qid)) as Arc<dyn FileOps>)
        })
    }

    fn lookup_dir(&self, _name: &str) -> Option<Arc<dyn DirOps>> {
        None
    }

    fn lookup_dir_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            let (newfid, qid) = self.walk_one(name).await?;
            if (qid.qid_type & qtype::DIR) == 0 {
                let _ = self.tclunk(newfid).await;
                return Err(FsError::InvalidPath);
            }
            Ok(Arc::new(self.child_node(newfid, qid)) as Arc<dyn DirOps>)
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
            // Walk-clone the root fid so the open-for-read leaves the
            // original fid intact (the original may be re-walked by
            // subsequent lookups).
            let read_fid = self.walk_clone().await?;
            let result = self.read_dir_stream(read_fid).await;
            let _ = self.tclunk(read_fid).await;
            let mut entries = result?;
            // Apply (cursor, max) windowing for the VFS contract.
            let start = cursor.min(entries.len());
            let end = (cursor + max).min(entries.len());
            entries.drain(..start);
            entries.truncate(end - start);
            Ok(entries)
        })
    }
}

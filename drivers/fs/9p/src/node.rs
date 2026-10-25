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

use narf_filesystem::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, Mode, Stat};
use narf_lib::sync::IrqSafeSpinLock;

use super::message::{
    decode_header, decode_rerror, decode_rread, decode_rwalk, decode_rwrite, encode_tclunk,
    encode_topen, encode_tread, encode_tstat, encode_twalk, encode_twrite, oflag, qtype, MsgType,
    P9Stat, Qid, WireRead,
};
use super::session::{frame_message, P9Session, Transport};

/// A file's timestamps as the stat path reports them, in wall-clock
/// nanoseconds since the epoch.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct P9Times {
    pub atime_ns: u64,
    pub mtime_ns: u64,
    pub ctime_ns: u64,
}

impl P9Times {
    /// Linux `v9fs_stat2inode` for legacy 9P2000 (`fs/9p/vfs_inode.c`):
    /// `atime = stat->atime`, `mtime = stat->mtime` and — 9P2000 has no
    /// change time — `ctime = stat->mtime`, all with 0 nanoseconds. The
    /// wire fields are unsigned 32-bit seconds (stat(5)), so a value past
    /// 2038 is not negative. Only 9P2000.L's `Rgetattr` carries
    /// nanoseconds; NARF negotiates plain "9P2000".
    pub fn from_stat(st: &P9Stat) -> Self {
        const NS: u64 = 1_000_000_000;
        Self {
            atime_ns: u64::from(st.atime) * NS,
            mtime_ns: u64::from(st.mtime) * NS,
            ctime_ns: u64::from(st.mtime) * NS,
        }
    }
}

/// One fid into the remote tree.
pub struct NinepNode {
    transport: Arc<dyn Transport>,
    session: Arc<P9Session>,
    fid: u32,
    qid: Qid,
    /// Times from the last `Rstat` of this fid: taken at lookup (Linux's
    /// `v9fs_vfs_lookup` stats the new fid to build the inode) and
    /// refreshed by every `stat_async`. The sync `inode_attrs` /
    /// `dir_mtime_ns` report them; `None` only if never stat'd.
    times: IrqSafeSpinLock<Option<P9Times>>,
    /// The file's `qid.version` as last learned from the server:
    /// the walk that minted this node first, then every `Rstat`
    /// reply's qid (`stat_child` / `stat_async`). Per intro(5) the
    /// server changes it on every modification, so it is the
    /// page-cache generation source (#681) — a per-node cell because
    /// the server, not this client, is authoritative for it.
    version: IrqSafeSpinLock<u32>,
    /// The file's length as last learned from the server: taken
    /// from the lookup `Rstat` (`stat_child`) and refreshed by
    /// every `stat_async`, in the same calls that refresh `times`
    /// and `version`, so the three never move independently. The
    /// synchronous `stat()` reports it because the generic fault
    /// path's EOF check consults the sync stat and cannot do a
    /// round trip per fault (#903). A server-side resize goes
    /// stale until the next `Rstat` refresh, exactly the way
    /// `times`/`version` do.
    length: IrqSafeSpinLock<u64>,
    /// The session's shared `MAP_SHARED` identity anchor for this
    /// file's `qid.path`, minted on first use (see
    /// `P9Session::mmap_anchor`). Every node of the same server file
    /// holds the same anchor, so `mmap_backing_identity` is stable
    /// across opens.
    mmap_anchor: narf_lib::sync::OnceLock<Arc<super::session::MmapAnchor>>,
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
        times: Option<P9Times>,
        length: u64,
    ) -> Self {
        Self {
            transport,
            session,
            fid,
            version: IrqSafeSpinLock::new(qid.version),
            qid,
            times: IrqSafeSpinLock::new(times),
            length: IrqSafeSpinLock::new(length),
            mmap_anchor: narf_lib::sync::OnceLock::new(),
        }
    }

    /// Device plus the cached stat times.
    fn attrs(&self) -> narf_filesystem::InodeAttrs {
        let t = (*self.times.lock()).unwrap_or_default();
        narf_filesystem::InodeAttrs {
            dev: self.session.dev(),
            atime_ns: t.atime_ns,
            ctime_ns: t.ctime_ns,
            mtime_ns: t.mtime_ns,
            ..Default::default()
        }
    }

    /// Stat a freshly walked fid and build its node. Like Linux's lookup
    /// (`v9fs_get_new_inode_from_fid` → `p9_client_stat`), a failed stat
    /// fails the lookup; the fid is clunked so it does not leak.
    async fn stat_child(&self, fid: u32, qid: Qid) -> Result<NinepNode, FsError> {
        match self.tstat(fid).await {
            Ok(st) => {
                let node = self.child_node(fid, qid);
                *node.times.lock() = Some(P9Times::from_stat(&st));
                *node.length.lock() = st.length;
                // The Rstat's qid is fresher than the walk's: adopt
                // its version so the new node's page-cache generation
                // starts current (#681).
                if st.qid.path == qid.path {
                    *node.version.lock() = st.qid.version;
                }
                Ok(node)
            }
            Err(e) => {
                let _ = self.tclunk(fid).await;
                Err(e)
            }
        }
    }

    /// `st_ino`: Linux `fs/9p/v9fs_vfs.h::QID2INO` on 64-bit —
    /// `qid.path + 2`. The server's qid.path is its unique file id; the
    /// +2 keeps a path of 0 (commonly the export root) off inode 0.
    pub fn inode_number(&self) -> u64 {
        self.qid.path.wrapping_add(2)
    }

    fn map_err<E: core::fmt::Debug>(_e: E) -> FsError {
        FsError::Io(narf_block::BlockError::IOError)
    }

    /// Tstat `fid` (stat(5)). Public to the crate so `NinepVolume::mount`
    /// can stat the attached root the way Linux's `v9fs_mount` does.
    pub(crate) async fn stat_fid(&self, fid: u32) -> Result<P9Stat, FsError> {
        self.tstat(fid).await
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
        let reply = self.transport.rpc(&req).await.map_err(Self::map_err)?;
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
        let reply = self.transport.rpc(&req).await.map_err(Self::map_err)?;
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
        let reply = self.transport.rpc(&req).await.map_err(Self::map_err)?;
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

    async fn twrite(&self, fid: u32, offset: u64, data: &[u8]) -> Result<u32, FsError> {
        let tag = self.session.alloc_tag();
        let req = frame_message(self.session.msize(), MsgType::Twrite, tag, |w| {
            encode_twrite(w, fid, offset, data)
        })
        .map_err(Self::map_err)?;
        let reply = self.transport.rpc(&req).await.map_err(Self::map_err)?;
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
        let reply = self.transport.rpc(&req).await.map_err(Self::map_err)?;
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
        let reply = self.transport.rpc(&req).await.map_err(Self::map_err)?;
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
        let reply = self.transport.rpc(&req).await.map_err(Self::map_err)?;
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
            version: IrqSafeSpinLock::new(qid.version),
            qid,
            times: IrqSafeSpinLock::new(None),
            length: IrqSafeSpinLock::new(0),
            mmap_anchor: narf_lib::sync::OnceLock::new(),
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
    fn ino(&self) -> u64 {
        self.inode_number()
    }

    fn inode_attrs(&self) -> narf_filesystem::InodeAttrs {
        self.attrs()
    }

    /// Stored file data: no `.poll`, so `epoll_ctl` refuses it. Decided per
    /// inode — a FIFO or device node living in this filesystem dispatches
    /// elsewhere on open and stays pollable. See `fs_inode_can_poll`.
    fn can_poll(&self) -> bool {
        narf_filesystem::fs_inode_can_poll(self.stat().mode.file_type)
    }

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
            let max_per_msg = (self.session.msize().saturating_sub(23)).max(1) as usize;
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
        // The cached length from the last Rstat (lookup /
        // stat_async): the generic fault path's EOF check reads
        // this synchronously, so a hardcoded 0 would refuse every
        // fault (#903). `blocks` follows stat_async's derivation.
        let size = *self.length.lock();
        Stat {
            size,
            blocks: size.div_ceil(512),
            mode: if ft == FileType::Dir {
                Mode::DIR_RO
            } else {
                Mode::FILE_RO
            },
            mtime_cycles: self
                .times
                .lock()
                .map_or(0, |t| narf_time::ns_to_cycles(t.mtime_ns)),
        }
    }

    fn stat_async<'a>(&'a self) -> FsFuture<'a, Stat> {
        Box::pin(async move {
            let st = self.tstat(self.fid).await?;
            let times = P9Times::from_stat(&st);
            *self.times.lock() = Some(times);
            *self.length.lock() = st.length;
            // Refresh the cached qid.version from the reply: this is
            // how a node learns the server changed the file, and the
            // page-cache generation follows it (#681).
            if st.qid.path == self.qid.path {
                *self.version.lock() = st.qid.version;
            }
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
                // Monotonic cycles: encode the wall-clock ns (raw SECONDS
                // used to go in unconverted). The exact value travels in
                // `InodeAttrs::mtime_ns`.
                mtime_cycles: narf_time::ns_to_cycles(times.mtime_ns),
            })
        })
    }

    /// Generic-fallback mmap opt-in (#681): the generation is the
    /// protocol's own coherency token — `qid.version`, which per
    /// intro(5) the server changes on every modification — folded
    /// with `qid.path` (see [`qid_cache_generation`]). The server is
    /// authoritative and can mutate the file externally, so neither
    /// a local counter nor a constant would be sound; the version is
    /// refreshed from walk and `Rstat` replies (see the `version`
    /// field). A server that reports version 0 is not maintaining
    /// the token — 0 there is indistinguishable from "no version" —
    /// so such files keep `None` and stay out of the retained cache.
    fn mmap_cache_generation(&self) -> Option<u64> {
        let version = *self.version.lock();
        if version == 0 {
            None
        } else {
            Some(qid_cache_generation(self.qid.path, version))
        }
    }

    /// The shared-page cache key for this file: the session anchor
    /// for its `qid.path`, stable across opens (every lookup mints a
    /// fresh node around a fresh fid, but the server file is the
    /// same), so retained pages are keyed by the file and not by
    /// whichever node object an open happened to mint.
    fn mmap_backing_identity(&self) -> usize {
        let anchor = self
            .mmap_anchor
            .get_or_init(|| self.session.mmap_anchor(self.qid.path));
        Arc::as_ptr(anchor) as usize
    }
}

/// Fold a qid into a page-cache generation: `path` names the file
/// instance, `version` its mutation epoch. The splitmix64 finalizer
/// is a bijection on the combined input, so at a fixed `path` every
/// distinct `version` yields a distinct generation — a server-side
/// change can never fold back onto the value a retained page was
/// published under.
fn qid_cache_generation(path: u64, version: u32) -> u64 {
    let mut z = path ^ (u64::from(version) << 32) ^ 0x9E37_79B9_7F4A_7C15;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

impl DirOps for NinepNode {
    fn ino(&self) -> u64 {
        self.inode_number()
    }

    fn inode_attrs(&self) -> narf_filesystem::InodeAttrs {
        self.attrs()
    }

    /// The directory's mtime from its last `Rstat`, not the epoch.
    fn dir_mtime_ns(&self) -> u64 {
        self.times.lock().map_or(0, |t| t.mtime_ns)
    }

    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        // Async-only; the VFS routes to lookup_async automatically.
        None
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let (newfid, qid) = self.walk_one(name).await?;
            Ok(Arc::new(self.stat_child(newfid, qid).await?) as Arc<dyn FileOps>)
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
            Ok(Arc::new(self.stat_child(newfid, qid).await?) as Arc<dyn DirOps>)
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

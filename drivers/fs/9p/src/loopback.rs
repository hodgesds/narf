//! In-memory `Transport` implementation for tests + bring-up.
//!
//! References for this file:
//! - `intro(5)` — message framing the synthetic server emits.
//! - `version(5)`, `attach(5)`, `walk(5)`, `open(5)`, `read(5)`,
//!   `clunk(5)`, `stat(5)` — message-by-message handler logic below
//!   mirrors the reference protocol's vanilla 9P2000 surface.
//!
//! The loopback transport owns a tiny in-process tree (a single root
//! directory containing some files) and synthesises R-replies for
//! every supported T-message. Real wire transports (virtio-9p, TCP)
//! never use this — it's a proof point that the protocol layer is
//! correct against a known-good implementation.
//!
//! The synthetic server is intentionally minimal:
//! - One root directory + N children. No nested directories.
//! - Files are byte slices supplied at construction time.
//! - `stat`'s mtime / atime / uid / gid / muid are constants.
//! - Supports only `READ` mode opens; rejects `WRITE`/`RDWR`.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use super::message::{
    decode_header, encode_tread, qtype, statmode, MsgType, P9Stat, Qid, WireRead, WireWrite,
    HEADER_SIZE,
};
use super::session::{frame_message, RpcFuture, Transport, TransportError};

/// One file in the synthetic tree. Directories don't have a `Node`
/// — the synthetic server only exposes a single root directory, so
/// directories are implicit.
#[derive(Debug, Clone)]
pub struct LoopbackFile {
    pub name: String,
    pub data: Vec<u8>,
    /// Numeric path id used in the qid. Stable across a session.
    pub path_id: u64,
}

/// Per-fid state kept by the synthetic server.
#[derive(Debug, Clone, Copy)]
struct FidState {
    /// `None` if this fid points at the root directory; `Some(idx)`
    /// if it points at child file `idx`.
    child: Option<usize>,
    /// `true` once this fid has been `Topen`'d.
    opened: bool,
}

/// Synthetic in-process 9P server fronted by a `Transport` impl.
pub struct LoopbackTransport {
    inner: IrqSafeSpinLock<Inner>,
    rpc_count: AtomicU64,
}

struct Inner {
    files: Vec<LoopbackFile>,
    fids: BTreeMap<u32, FidState>,
    /// Negotiated msize after Tversion. Pre-handshake the server
    /// accepts up to this; the client's proposal is clamped.
    server_msize: u32,
    /// Set once `Tversion` has been received. Subsequent Tversion
    /// resets the session per `version(5)`.
    versioned: bool,
}

impl core::fmt::Debug for LoopbackTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LoopbackTransport")
            .field("rpc_count", &self.rpc_count.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl LoopbackTransport {
    /// Build a loopback whose root directory contains the supplied
    /// `(name, data)` pairs. Names must be unique; assertion-level
    /// invariant — duplicates are a test bug, not a runtime case.
    pub fn new(files: &[(&str, &[u8])]) -> Arc<Self> {
        let mut v = Vec::with_capacity(files.len());
        for (i, (name, data)) in files.iter().enumerate() {
            v.push(LoopbackFile {
                name: (*name).to_string(),
                data: data.to_vec(),
                // Path id 1 is reserved for the root directory; child
                // ids start at 2.
                path_id: 2 + i as u64,
            });
        }
        Arc::new(Self {
            inner: IrqSafeSpinLock::new(Inner {
                files: v,
                fids: BTreeMap::new(),
                server_msize: 8192,
                versioned: false,
            }),
            rpc_count: AtomicU64::new(0),
        })
    }

    /// Number of RPCs the synthetic server has handled. Useful for
    /// asserting on test traffic shape.
    pub fn rpc_count(&self) -> u64 {
        self.rpc_count.load(Ordering::Relaxed)
    }

    fn root_qid() -> Qid {
        Qid {
            qid_type: qtype::DIR,
            version: 0,
            path: 1,
        }
    }

    fn file_qid(file: &LoopbackFile) -> Qid {
        Qid {
            qid_type: qtype::FILE,
            version: 0,
            path: file.path_id,
        }
    }

    /// Build a `P9Stat` for the i-th child file.
    fn file_stat(file: &LoopbackFile) -> P9Stat {
        P9Stat {
            kernel_type: 0,
            kernel_dev: 0,
            qid: Self::file_qid(file),
            mode: 0o444,
            atime: 0,
            mtime: 0,
            length: file.data.len() as u64,
            name: file.name.clone(),
            uid: String::from("narf"),
            gid: String::from("narf"),
            muid: String::from("narf"),
        }
    }

    fn root_stat() -> P9Stat {
        P9Stat {
            kernel_type: 0,
            kernel_dev: 0,
            qid: Self::root_qid(),
            mode: statmode::DIR | 0o555,
            atime: 0,
            mtime: 0,
            length: 0,
            name: String::from("/"),
            uid: String::from("narf"),
            gid: String::from("narf"),
            muid: String::from("narf"),
        }
    }

    /// Handle a single framed T-message and produce the framed
    /// R-message. Pure function over `&Inner` mutable state.
    fn handle(&self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.rpc_count.fetch_add(1, Ordering::Relaxed);

        let mut r = WireRead::new(request);
        let (size, mtype, tag) = decode_header(&mut r)?;
        if size as usize != request.len() {
            return Err(TransportError::ShortReply);
        }

        let mut inner = self.inner.lock();

        // Per version(5): a Tversion at any time resets the session.
        match mtype {
            MsgType::Tversion => {
                let proposed_msize = r.read_u32()?;
                let _proposed_version = r.read_str()?;
                inner.fids.clear();
                inner.versioned = true;
                let agreed = proposed_msize.min(inner.server_msize);
                inner.server_msize = agreed;
                drop(inner);
                return frame_message(agreed, MsgType::Rversion, tag, |w| {
                    w.write_u32(agreed)?;
                    w.write_str(super::volume::PROTO_VERSION)?;
                    Ok(())
                });
            }
            _ => {}
        }

        if !inner.versioned {
            // Reject everything else until the session is versioned.
            drop(inner);
            return rerror(tag, "no version negotiated");
        }

        match mtype {
            MsgType::Tattach => {
                let fid = r.read_u32()?;
                let _afid = r.read_u32()?;
                let _uname = r.read_str()?;
                let _aname = r.read_str()?;
                inner.fids.insert(
                    fid,
                    FidState {
                        child: None,
                        opened: false,
                    },
                );
                let q = Self::root_qid();
                drop(inner);
                frame_message(self.cap(), MsgType::Rattach, tag, |w| w.write_qid(&q))
            }
            MsgType::Twalk => {
                let fid = r.read_u32()?;
                let newfid = r.read_u32()?;
                let nwname = r.read_u16()? as usize;
                let mut names = Vec::with_capacity(nwname);
                for _ in 0..nwname {
                    names.push(r.read_str()?);
                }
                // Source fid must exist.
                let src = match inner.fids.get(&fid).copied() {
                    Some(s) => s,
                    None => {
                        drop(inner);
                        return rerror(tag, "unknown fid");
                    }
                };
                // walk(5): nwname == 0 clones the fid at its current
                // position. The newfid MUST NOT already be in use
                // unless it equals the source fid.
                if nwname == 0 {
                    if newfid != fid && inner.fids.contains_key(&newfid) {
                        drop(inner);
                        return rerror(tag, "newfid in use");
                    }
                    inner.fids.insert(
                        newfid,
                        FidState {
                            child: src.child,
                            opened: false, // walk(5): newfid is never opened
                        },
                    );
                    drop(inner);
                    return frame_message(self.cap(), MsgType::Rwalk, tag, |w| {
                        w.write_u16(0)
                    });
                }
                // Synthetic tree is one level deep. We require the
                // walk to start at the root (child == None).
                if src.child.is_some() {
                    drop(inner);
                    return rerror(tag, "walk past leaf");
                }
                // Walk one component only (we don't model nested
                // dirs).
                if names.len() != 1 {
                    drop(inner);
                    return rerror(tag, "loopback only supports 1-component walk");
                }
                let target = match inner.files.iter().position(|f| f.name == names[0]) {
                    Some(i) => i,
                    None => {
                        drop(inner);
                        // walk(5): if FIRST component fails, return
                        // Rerror; if a later component fails, return
                        // partial Rwalk. We have one-component walks
                        // here so it's always Rerror.
                        return rerror(tag, "no such file");
                    }
                };
                let qid = Self::file_qid(&inner.files[target]);
                inner.fids.insert(
                    newfid,
                    FidState {
                        child: Some(target),
                        opened: false,
                    },
                );
                drop(inner);
                frame_message(self.cap(), MsgType::Rwalk, tag, |w| {
                    w.write_u16(1)?;
                    w.write_qid(&qid)
                })
            }
            MsgType::Topen => {
                let fid = r.read_u32()?;
                let mode = r.read_u8()?;
                if mode & 0x0F != super::message::oflag::READ {
                    drop(inner);
                    return rerror(tag, "loopback is read-only");
                }
                let st = match inner.fids.get_mut(&fid) {
                    Some(s) => s,
                    None => {
                        drop(inner);
                        return rerror(tag, "unknown fid");
                    }
                };
                st.opened = true;
                let qid = if let Some(idx) = st.child {
                    Self::file_qid(&inner.files[idx])
                } else {
                    Self::root_qid()
                };
                drop(inner);
                frame_message(self.cap(), MsgType::Ropen, tag, |w| {
                    w.write_qid(&qid)?;
                    // iounit = 0: server has no preferred unit, client
                    // may use up to msize. (open(5))
                    w.write_u32(0)
                })
            }
            MsgType::Tread => {
                let fid = r.read_u32()?;
                let offset = r.read_u64()?;
                let count = r.read_u32()? as usize;
                let st = match inner.fids.get(&fid).copied() {
                    Some(s) => s,
                    None => {
                        drop(inner);
                        return rerror(tag, "unknown fid");
                    }
                };
                if !st.opened {
                    drop(inner);
                    return rerror(tag, "fid not open");
                }
                match st.child {
                    Some(idx) => {
                        // File read.
                        let file = &inner.files[idx];
                        let start = (offset as usize).min(file.data.len());
                        let end = (start + count).min(file.data.len());
                        let chunk: Vec<u8> = file.data[start..end].to_vec();
                        drop(inner);
                        frame_message(self.cap(), MsgType::Rread, tag, |w| {
                            w.write_u32(chunk.len() as u32)?;
                            for &b in &chunk {
                                w.write_u8(b)?;
                            }
                            Ok(())
                        })
                    }
                    None => {
                        // Directory read: emit stat structures starting
                        // at the cursor implied by `offset`. We treat
                        // `offset` as an opaque cumulative byte count,
                        // matching `read(5)`'s semantics.
                        let stats: Vec<P9Stat> =
                            inner.files.iter().map(Self::file_stat).collect();
                        // Encode all stats into a temporary buffer
                        // first so we can slice from `offset`.
                        let mut all: Vec<u8> = Vec::with_capacity(stats.len() * 64);
                        // Use a generously-sized scratch buffer; resize as needed.
                        let mut scratch = alloc::vec![0u8; 4096];
                        for s in &stats {
                            // grow scratch if we run out
                            loop {
                                let mut w2 = WireWrite::new(&mut scratch);
                                if s.encode(&mut w2).is_ok() {
                                    let used = w2.pos();
                                    all.extend_from_slice(&scratch[..used]);
                                    break;
                                }
                                scratch.resize(scratch.len() * 2, 0);
                            }
                        }
                        let start = (offset as usize).min(all.len());
                        let end = (start + count).min(all.len());
                        let chunk = all[start..end].to_vec();
                        drop(inner);
                        frame_message(self.cap(), MsgType::Rread, tag, |w| {
                            w.write_u32(chunk.len() as u32)?;
                            for &b in &chunk {
                                w.write_u8(b)?;
                            }
                            Ok(())
                        })
                    }
                }
            }
            MsgType::Tstat => {
                let fid = r.read_u32()?;
                let st = match inner.fids.get(&fid).copied() {
                    Some(s) => s,
                    None => {
                        drop(inner);
                        return rerror(tag, "unknown fid");
                    }
                };
                let stat = match st.child {
                    Some(idx) => Self::file_stat(&inner.files[idx]),
                    None => Self::root_stat(),
                };
                drop(inner);
                let stat_body = stat.body_len();
                frame_message(self.cap(), MsgType::Rstat, tag, |w| {
                    // outer nstat[2]: covers the inner size[2] + body.
                    let outer = 2 + stat_body;
                    if outer > 0xFFFF {
                        return Err(super::message::DecodeError::StringTooLong);
                    }
                    w.write_u16(outer as u16)?;
                    stat.encode(w)?;
                    Ok(())
                })
            }
            MsgType::Tclunk => {
                let fid = r.read_u32()?;
                inner.fids.remove(&fid);
                drop(inner);
                frame_message(self.cap(), MsgType::Rclunk, tag, |_w| Ok(()))
            }
            _ => {
                drop(inner);
                rerror(tag, "loopback: unsupported message")
            }
        }
    }

    fn cap(&self) -> u32 {
        self.inner.lock().server_msize
    }
}

impl Transport for LoopbackTransport {
    fn rpc<'a>(&'a self, request: &'a [u8]) -> RpcFuture<'a> {
        Box::pin(async move {
            // Synchronous in-process exchange — no real awaits.
            self.handle(request)
        })
    }
}

/// Encode an `Rerror` reply with the given `ename`.
fn rerror(tag: u16, ename: &str) -> Result<Vec<u8>, TransportError> {
    frame_message(8192, MsgType::Rerror, tag, |w| w.write_str(ename))
}

// Pull `tread` into scope so the reader can find the symbol when
// reading top-down. Not actually used here (the loopback decodes Tread
// inline) — we only re-export from the message module via `pub use`
// when consumers need it. Marker fn keeps the dependency edge
// explicit during refactors.
#[allow(dead_code)]
fn _link_anchor() {
    let mut buf = [0u8; 16];
    let mut w = WireWrite::new(&mut buf);
    let _ = encode_tread(&mut w, 0, 0, 0);
    let _ = HEADER_SIZE;
}

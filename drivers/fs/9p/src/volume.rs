//! 9P2000 volume — `FsInstance` adapter.
//!
//! Mounts a 9P session over any `Transport` impl: issues Tversion +
//! Tattach during `mount`, hands callers a `NinepNode` rooted at the
//! attached fid. Per-call ops (lookup, read, etc.) live on the node.
//!
//! References: `version(5)`, `attach(5)`.

use alloc::sync::Arc;
use core::future::Future;

use narf_driver_runtime::DomainId;
use narf_filesystem::{DirOps, FsError, FsInstance};

use super::message::{
    decode_header, decode_rerror, decode_rversion, encode_tattach, encode_tversion, qtype,
    MsgType, Qid, WireRead, NOFID, NOTAG,
};
use super::node::NinepNode;
use super::session::{frame_message, P9Session, Transport};

/// 9P2000 base protocol version string (version(5)).
pub const PROTO_VERSION: &str = "9P2000";

/// Mounted 9P session.
#[derive(Debug)]
pub struct NinepVolume {
    pub transport: Arc<dyn Transport>,
    pub session: Arc<P9Session>,
    pub root_fid: u32,
    pub root_qid: Qid,
    pub domain: DomainId,
}

impl NinepVolume {
    /// Issue Tversion + Tattach over `transport`, return the mounted
    /// session. uname / aname are empty (anonymous attach).
    pub fn mount(
        transport: Arc<dyn Transport>,
        domain: DomainId,
    ) -> impl Future<Output = Result<Arc<Self>, FsError>> + Send {
        async move {
            let session = Arc::new(P9Session::new());

            // ── Tversion ────────────────────────────────────────────
            let req = frame_message(session.msize(), MsgType::Tversion, NOTAG, |w| {
                encode_tversion(w, session.msize(), PROTO_VERSION)
            })
            .map_err(map_tx_err)?;
            let reply = transport.rpc(&req).await.map_err(map_tx_err)?;
            let mut r = WireRead::new(&reply);
            let (_size, mt, _tag) = decode_header(&mut r).map_err(map_tx_err)?;
            match mt {
                MsgType::Rversion => {
                    let rv = decode_rversion(&mut r).map_err(map_tx_err)?;
                    if rv.version != PROTO_VERSION {
                        return Err(FsError::Unsupported);
                    }
                    session.set_msize(rv.msize);
                }
                MsgType::Rerror => {
                    let _ = decode_rerror(&mut r);
                    return Err(FsError::Unsupported);
                }
                _ => return Err(FsError::Unsupported),
            }

            // ── Tattach ─────────────────────────────────────────────
            let root_fid = session.alloc_fid();
            let tag = session.alloc_tag();
            let req = frame_message(session.msize(), MsgType::Tattach, tag, |w| {
                encode_tattach(w, root_fid, NOFID, "", "")
            })
            .map_err(map_tx_err)?;
            let reply = transport.rpc(&req).await.map_err(map_tx_err)?;
            let mut r = WireRead::new(&reply);
            let (_, mt, _) = decode_header(&mut r).map_err(map_tx_err)?;
            let root_qid = match mt {
                MsgType::Rattach => r.read_qid().map_err(map_tx_err)?,
                MsgType::Rerror => {
                    let _ = decode_rerror(&mut r);
                    return Err(FsError::Unsupported);
                }
                _ => return Err(FsError::Unsupported),
            };
            // Sanity: per attach(5) the root must be a directory.
            if (root_qid.qid_type & qtype::DIR) == 0 {
                return Err(FsError::Unsupported);
            }

            Ok(Arc::new(Self {
                transport,
                session,
                root_fid,
                root_qid,
                domain,
            }))
        }
    }
}

fn map_tx_err<E: core::fmt::Debug>(_e: E) -> FsError {
    FsError::Io(narf_block::BlockError::IOError)
}

impl FsInstance for NinepVolume {
    fn name(&self) -> &str {
        "9p"
    }

    fn root(&self) -> Arc<dyn DirOps> {
        Arc::new(NinepNode::new_root(
            self.transport.clone(),
            self.session.clone(),
            self.root_fid,
            self.root_qid,
        ))
    }
}

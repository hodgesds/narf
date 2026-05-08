//! 9P Volume management.

use alloc::sync::{Arc, Weak};
use narf_filesystem::{FsError, FsInstance, DirOps};
use narf_driver_runtime::DomainId;
use super::session::{P9Session, P9Transport};
use super::message::{P9Msg, Qid};
use super::node::P9Node;

#[derive(Debug)]
pub struct P9FileSystem {
    pub session: Arc<P9Session>,
    pub transport: Arc<dyn P9Transport>,
    pub domain: DomainId,
    pub root_fid: u32,
    pub root_qid: Qid,
    pub self_weak: Weak<P9FileSystem>,
}

impl P9FileSystem {
    pub async fn mount(transport: Arc<dyn P9Transport>, domain: DomainId, uname: &str, aname: &str) -> Result<Arc<Self>, FsError> {
        let session = Arc::new(P9Session::new());
        
        // 1. Version Handshake
        let resp = session.transaction(&*transport, P9Msg::Tversion { 
            msize: session.max_msg_size, 
            version: alloc::string::String::from("9P2000.u") 
        }, domain).await?;

        if let P9Msg::Rversion { .. } = resp {
            // Update session max_msg_size if server suggests smaller
        } else {
            return Err(FsError::Unsupported);
        }

        // 2. Attach
        let root_fid = session.alloc_fid();
        let resp = session.transaction(&*transport, P9Msg::Tattach { 
            fid: root_fid, 
            afid: 0xFFFFFFFF, // NOFID
            uname: alloc::string::String::from(uname), 
            aname: alloc::string::String::from(aname) 
        }, domain).await?;

        let root_qid = if let P9Msg::Rattach { qid } = resp {
            qid
        } else {
            return Err(FsError::Unsupported);
        };

        Ok(Arc::new_cyclic(|self_weak| {
            Self {
                session,
                transport,
                domain,
                root_fid,
                root_qid,
                self_weak: self_weak.clone(),
            }
        }))
    }
}

impl FsInstance for P9FileSystem {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::new(P9Node::new(
            self.self_weak.upgrade().expect("P9FileSystem root called after drop"),
            self.root_fid,
            self.root_qid,
        ))
    }

    fn name(&self) -> &str {
        "9p"
    }
}

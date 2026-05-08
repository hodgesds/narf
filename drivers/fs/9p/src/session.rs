//! 9P Transport abstraction and Transaction manager.

use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU32, AtomicU16, Ordering};
use narf_filesystem::FsError;
use narf_driver_runtime::{alloc_coherent, DomainId};
use super::message::{P9Msg, MsgType, P9Buffer};

use core::fmt::Debug;

pub type P9Future<'a, T> = Pin<Box<dyn Future<Output = Result<T, FsError>> + Send + 'a>>;

pub trait P9Transport: Send + Sync + Debug {
    fn send<'a>(&'a self, data: &'a [u8]) -> P9Future<'a, ()>;
    fn recv<'a>(&'a self, data: &'a mut [u8]) -> P9Future<'a, usize>;
}

#[derive(Debug)]
pub struct P9Session {
    pub next_tag: AtomicU16,
    pub next_fid: AtomicU32,
    pub max_msg_size: u32,
}

impl P9Session {
    pub fn new() -> Self {
        Self {
            next_tag: AtomicU16::new(1), // Tag 0 often reserved or special
            next_fid: AtomicU32::new(1),
            max_msg_size: 8192,
        }
    }

    pub fn alloc_tag(&self) -> u16 {
        self.next_tag.fetch_add(1, Ordering::Relaxed)
    }

    pub fn alloc_fid(&self) -> u32 {
        self.next_fid.fetch_add(1, Ordering::Relaxed)
    }

    pub async fn transaction(&self, transport: &dyn P9Transport, req: P9Msg, domain: DomainId) -> Result<P9Msg, FsError> {
        let tag = self.alloc_tag();
        let block_size = self.max_msg_size as usize;
        let buf = alloc_coherent(block_size, domain).map_err(|_| FsError::Unsupported)?;
        
        // Serialize request
        let mut p9_buf = P9Buffer::new(unsafe { core::slice::from_raw_parts_mut(buf.phys_addr().raw() as *mut u8, block_size) });
        
        // Header placeholder (size, type, tag)
        p9_buf.offset = 7;
        req.encode(&mut p9_buf);
        let total_size = p9_buf.offset as u32;
        
        // Write real header
        p9_buf.offset = 0;
        p9_buf.write_u32(total_size);
        p9_buf.write_u8(req.msg_type() as u8);
        p9_buf.write_u16(tag);
        
        let req_slice = unsafe { core::slice::from_raw_parts(buf.phys_addr().raw() as *const u8, total_size as usize) };
        transport.send(req_slice).await?;
        
        // Receive response
        let resp_buf = alloc_coherent(block_size, domain).map_err(|_| FsError::Unsupported)?;
        let resp_slice = unsafe { core::slice::from_raw_parts_mut(resp_buf.phys_addr().raw() as *mut u8, block_size) };
        let n = transport.recv(resp_slice).await?;
        
        let mut p9_resp_buf = P9Buffer::new(&mut resp_slice[..n]);
        let _r_size = p9_resp_buf.read_u32();
        let r_type = p9_resp_buf.read_u8();
        let r_tag = p9_resp_buf.read_u16();
        
        if r_tag != tag {
            return Err(FsError::Unsupported);
        }

        let msg_type = MsgType::from(r_type);
        let resp = P9Msg::decode(msg_type, &mut p9_resp_buf);

        if let P9Msg::Rerror { ename: _ } = resp {
             // 9P errors are strings. For now, we'll map them all to Io.
             // Real implementation would parse the string or use 9P2000.u numeric codes.
             return Err(FsError::Unsupported);
        }

        Ok(resp)
    }
}

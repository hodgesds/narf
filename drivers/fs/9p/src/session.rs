//! 9P session glue: `Transport` trait, frame helper, per-session
//! tag/fid allocator.
//!
//! References:
//! - `intro(5)` — message framing (`size[4] type[1] tag[2] body...`).
//! - `version(5)` — session msize negotiation.
//! - `attach(5)` — fid allocation discipline.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU16, AtomicU32, Ordering};

use super::message::{DecodeError, MsgType, WireWrite, HEADER_SIZE};

/// Per-RPC future returned by a `Transport`. Resolves to the raw
/// reply frame (a length-prefixed `[size, type, tag, body...]`).
pub type RpcFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<u8>, TransportError>> + Send + 'a>>;

/// Transport surface that the protocol layer drives. Real
/// implementations: virtio-9p (DMA over a virtio queue), TCP-9P
/// (network-stack-backed). Test impl: `crate::loopback::LoopbackTransport`.
///
/// `rpc(request)` MUST atomically send `request` and wait for the
/// matching reply (matched by tag); the trait makes the wait
/// implicit so transports that multiplex tags can do their own
/// dispatch.
pub trait Transport: Send + Sync + core::fmt::Debug {
    fn rpc<'a>(&'a self, request: &'a [u8]) -> RpcFuture<'a>;
}

/// Why a transport-level RPC failed. Distinct from
/// `narf_filesystem::FsError` because the protocol layer can recover
/// from some of these (e.g. a server-side Rerror is `Protocol(Rerror)`,
/// not a transport failure).
#[derive(Clone, Debug)]
pub enum TransportError {
    /// Reply was shorter than the leading `size[4]` claimed, or
    /// shorter than `HEADER_SIZE`.
    ShortReply,
    /// `decode_header` failed on the reply (truncated / unknown
    /// type).
    BadHeader,
    /// Body decode failed (passed through from `message::DecodeError`).
    Decode(DecodeError),
    /// Underlying transport surface (queue, socket, channel) errored
    /// out — implementation-defined string.
    Io,
    /// Server returned an Rerror with the given `ename`.
    Server(alloc::string::String),
    /// Reply's tag didn't match the request's tag.
    TagMismatch { expected: u16, got: u16 },
    /// Reply's type wasn't the expected R-message for the T-message
    /// sent (e.g. a Tread with an Ropen reply).
    UnexpectedType { expected: MsgType, got: MsgType },
    /// `frame_message`'s body callback overran the negotiated msize.
    FrameTooBig,
}

impl From<DecodeError> for TransportError {
    fn from(e: DecodeError) -> Self {
        TransportError::Decode(e)
    }
}

/// Build a fully-framed 9P message in a fresh `Vec`. The caller's
/// closure writes the body using a `WireWrite`; we patch the leading
/// `size[4]` after the body lands so callers don't have to count.
///
/// `cap` bounds the buffer we allocate — the negotiated msize from
/// version(5). `kind` + `tag` populate the header.
pub fn frame_message<F>(
    cap: u32,
    kind: MsgType,
    tag: u16,
    f: F,
) -> Result<Vec<u8>, TransportError>
where
    F: FnOnce(&mut WireWrite) -> Result<(), DecodeError>,
{
    if (cap as usize) < HEADER_SIZE {
        return Err(TransportError::FrameTooBig);
    }
    let mut buf = alloc::vec![0u8; cap as usize];
    let used;
    {
        let mut w = WireWrite::new(&mut buf);
        // Reserve space for size[4]; write type[1] + tag[2].
        w.write_u32(0).map_err(TransportError::Decode)?;
        w.write_u8(kind as u8).map_err(TransportError::Decode)?;
        w.write_u16(tag).map_err(TransportError::Decode)?;
        f(&mut w).map_err(TransportError::Decode)?;
        used = w.pos();
        if used > cap as usize {
            return Err(TransportError::FrameTooBig);
        }
        // Patch the size[4] field with the actual frame length.
        if used > u32::MAX as usize {
            return Err(TransportError::FrameTooBig);
        }
        w.patch_u32_at(0, used as u32)
            .map_err(TransportError::Decode)?;
    }
    buf.truncate(used);
    Ok(buf)
}

/// Per-session monotonic counters for tags + fids. Tags wrap to 1
/// (avoiding NOTAG); fids wrap to 1 (avoiding NOFID).
#[derive(Debug)]
pub struct P9Session {
    next_tag: AtomicU16,
    next_fid: AtomicU32,
    msize: AtomicU32,
}

impl Default for P9Session {
    fn default() -> Self {
        Self::new()
    }
}

impl P9Session {
    pub fn new() -> Self {
        Self {
            // tag 0xFFFF is NOTAG (version-only); start tags at 1.
            next_tag: AtomicU16::new(1),
            // fid 0xFFFFFFFF is NOFID (attach afid hole); start at 1.
            next_fid: AtomicU32::new(1),
            // Default cap before Tversion negotiates a real value.
            msize: AtomicU32::new(8192),
        }
    }

    /// Allocate a fresh tag, wrapping past `NOTAG - 1`.
    pub fn alloc_tag(&self) -> u16 {
        let mut t = self.next_tag.fetch_add(1, Ordering::Relaxed);
        if t == super::message::NOTAG {
            // Skip NOTAG and start over.
            t = 1;
            self.next_tag.store(2, Ordering::Relaxed);
        }
        t
    }

    /// Allocate a fresh fid, wrapping past `NOFID - 1`.
    pub fn alloc_fid(&self) -> u32 {
        let mut f = self.next_fid.fetch_add(1, Ordering::Relaxed);
        if f == super::message::NOFID {
            f = 1;
            self.next_fid.store(2, Ordering::Relaxed);
        }
        f
    }

    /// Currently-negotiated msize. Pre-Tversion this is the
    /// default (8192).
    pub fn msize(&self) -> u32 {
        self.msize.load(Ordering::Relaxed)
    }

    /// Update msize after a successful Rversion. Per version(5)
    /// the agreed msize is the min of client-proposed + server-
    /// reported.
    pub fn set_msize(&self, n: u32) {
        self.msize.store(n, Ordering::Relaxed);
    }
}

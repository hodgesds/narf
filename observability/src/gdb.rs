//! GDB remote-serial stub — protocol surface.
//!
//! Spec: `observability/specification/spec.md` (Stage-4: GDB remote
//! stub, watchpoint install). The real packet handler requires a
//! serial transport, an x86_64 / aarch64 register-dump capture
//! path, and breakpoint-install hardware access — all of which live
//! behind `arch/` work that has not yet landed. What we *can* do
//! cleanly at this layer is pin the protocol shape:
//!
//! - `GdbPacket` — request/response framing, sum-verification.
//! - `GdbCommand` — the subset of RSP commands the stub will handle
//!   (`g`, `G`, `m`, `M`, `c`, `s`, `z0`, `Z0`, `?`, `qSupported`).
//! - `GdbError` — wire-level error variants.
//! - Cap-gated `attach(cap: &Cap<Debugger, Invoke>)` entry point
//!   that returns an error until the arch transport lands.
//!
//! The contract is: once `arch/` exposes `debug_read_regs`,
//! `debug_write_regs`, `debug_peek_memory`, `debug_poke_memory`,
//! `debug_install_watchpoint`, and a serial byte-stream future, the
//! body of `attach` gets filled in without churning the wire shapes.

use alloc::string::String;
use alloc::vec::Vec;

use narf_capabilities::{Cap, CapError, NoopOp};

use crate::Debugger;

/// GDB RSP wire-level error.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GdbError {
    AuthorityRevoked,
    MalformedPacket,
    Unsupported,
    /// The `arch/` transport isn't wired yet. Every entry point
    /// returns this in Stage-4 until the backend lands.
    NotImplemented,
}

impl From<CapError> for GdbError {
    fn from(_: CapError) -> Self {
        GdbError::AuthorityRevoked
    }
}

/// A decoded RSP command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GdbCommand {
    /// `g` — read all general-purpose registers.
    ReadRegs,
    /// `G <hex>` — write general-purpose registers.
    WriteRegs(Vec<u8>),
    /// `m addr,length` — read memory.
    ReadMem { addr: u64, len: u32 },
    /// `M addr,length:hex` — write memory.
    WriteMem { addr: u64, bytes: Vec<u8> },
    /// `c [addr]` — continue.
    Continue { addr: Option<u64> },
    /// `s [addr]` — single-step.
    Step { addr: Option<u64> },
    /// `Z0 addr,kind` — insert software breakpoint.
    InsertBp { addr: u64, kind: u8 },
    /// `z0 addr,kind` — remove software breakpoint.
    RemoveBp { addr: u64, kind: u8 },
    /// `?` — halt reason query.
    HaltReason,
    /// `qSupported:feature-list` — feature negotiation.
    QSupported(String),
}

/// A framed RSP packet — `$payload#checksum`. The Stage-4 stub uses
/// this shape on both RX and TX; the constructor computes the
/// checksum so callers never hand-wire the `#XX` footer.
#[derive(Clone, Debug)]
pub struct GdbPacket {
    pub payload: String,
    pub checksum: u8,
}

impl GdbPacket {
    /// Frame `payload` into a packet with a valid `#XX` checksum.
    pub fn new(payload: &str) -> Self {
        let mut sum: u8 = 0;
        for b in payload.as_bytes() {
            sum = sum.wrapping_add(*b);
        }
        Self {
            payload: String::from(payload),
            checksum: sum,
        }
    }

    /// Verify `self.checksum` matches `payload`'s byte-sum.
    pub fn checksum_valid(&self) -> bool {
        let mut sum: u8 = 0;
        for b in self.payload.as_bytes() {
            sum = sum.wrapping_add(*b);
        }
        sum == self.checksum
    }

    /// Wire-format the packet: `$payload#XX` with `XX` as lowercase
    /// hex.
    pub fn to_wire(&self) -> String {
        use core::fmt::Write as _;
        let mut s = String::new();
        s.push('$');
        s.push_str(&self.payload);
        s.push('#');
        let _ = write!(s, "{:02x}", self.checksum);
        s
    }
}

/// Attach a debugger. Returns `NotImplemented` until the `arch/`
/// transport + register-dump primitives land. The shape is stable;
/// Stage-4's filled-in body replaces the body below without
/// changing callers.
pub fn attach(cap: &Cap<Debugger, narf_capabilities::Invoke>) -> Result<(), GdbError> {
    cap.invoke(NoopOp)?;
    Err(GdbError::NotImplemented)
}

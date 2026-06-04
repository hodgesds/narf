//! AF_BYPASS / AF_XDP-equivalent socket state + dispatcher.
//!
//! NARF's userspace surface for kernel-bypass networking. Mirrors
//! Linux AF_XDP (`linux/net/xdp/xsk.c`) but with NARF-native
//! divergences:
//!
//! - No `mmap(2)` of raw bytes. The kernel returns
//!   `Cap<{Fill,Rx,Tx,Completion}Ring, Invoke>` from
//!   `setsockopt(XDP_*_RING)` and userspace drives them through
//!   `narf_ipc::Ring` rather than poking shared pages.
//! - UMEM is registered via `setsockopt(XDP_UMEM_REG, &reg)`
//!   carrying a size/frame_size pair; the kernel mints a
//!   `Cap<UmemRegion, Invoke>` + returns it through the per-socket
//!   state.
//! - `bind(2)` accepts a NARF-specific sockaddr_xdp: `(iface_name,
//!   queue_id, flags)`. Wire shape: 16-byte iface name + u32
//!   queue_id + u32 flags = 24 bytes.
//!
//! Linux refs:
//! - `linux/net/xdp/xsk.c::xsk_setsockopt` — option dispatch.
//! - `linux/Documentation/networking/af_xdp.rst` — userspace model.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use narf_net::bypass::{FlowKey, Umem, UmemSlot, XdpSocket as KernelXdpSocket, XdpSocketParts};

// ── Address family + ABI constants ──────────────────────────────────

/// NARF-specific AF for the bypass socket. Picks 45 because Linux's
/// AF_XDP is 44 and 45 is currently free in the Linux numbering;
/// keeps the wire ABI close to Linux's so a port doesn't have to
/// rewrite family handling code.
pub const AF_BYPASS: u16 = 45;

/// XDP setsockopt level (Linux: `SOL_XDP = 283`). We mirror.
pub const SOL_XDP: u32 = 283;

/// XDP socket options. Names + numbers match Linux's
/// `linux/include/uapi/linux/if_xdp.h` so a libxdp-style port
/// recognises them.
pub const XDP_MMAP_OFFSETS: u32 = 1;
pub const XDP_RX_RING: u32 = 2;
pub const XDP_TX_RING: u32 = 3;
pub const XDP_UMEM_REG: u32 = 4;
pub const XDP_UMEM_FILL_RING: u32 = 5;
pub const XDP_UMEM_COMPLETION_RING: u32 = 6;
pub const XDP_STATISTICS: u32 = 7;
pub const XDP_OPTIONS: u32 = 8;

/// Wire-shape XDP_UMEM_REG payload. Mirrors Linux's
/// `struct xdp_umem_reg`. `addr` is the user vaddr; NARF doesn't
/// use it for now (alloc happens in the kernel) but keeps the
/// field for ABI compat.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct XdpUmemReg {
    /// User-space base virtual address of the UMEM. Ignored on
    /// NARF — alloc is kernel-side — kept for ABI compat.
    pub addr: u64,
    /// Total size in bytes.
    pub len: u64,
    /// Frame size (power of two; 2048 or 4096).
    pub chunk_size: u32,
    /// Headroom reserved before each frame's payload — ignored.
    pub headroom: u32,
    /// Bit flags. Ignored.
    pub flags: u32,
}

/// Wire-shape sockaddr_xdp body. Family is carried separately by
/// the syscall ABI. Linux uses
/// `struct sockaddr_xdp { __u16 sxdp_family; __u16 sxdp_flags;
/// __u32 sxdp_ifindex; __u32 sxdp_queue_id; __u32
/// sxdp_shared_umem_fd; }` — we serialise the iface name as a
/// 16-byte field instead of an ifindex (NARF doesn't index NICs).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct SockAddrXdp {
    pub flags: u16,
    pub queue_id: u32,
    /// 16-byte fixed-size iface name. Trailing NUL-padded.
    pub iface_name: [u8; 16],
}

// ── XdpSocket state ────────────────────────────────────────────────

/// Userspace-facing socket state. One per `socket(AF_BYPASS,
/// SOCK_RAW, 0)` fd. The kernel-side `XdpSocket` (the four-ring
/// owner) is held in `kernel_parts` after `setsockopt(XDP_UMEM_REG)`
/// completes.
pub struct XdpSocketState {
    /// Set after `setsockopt(XDP_UMEM_REG)`.
    pub umem: IrqSafeSpinLock<Option<Arc<Umem>>>,
    /// Created after the first `XDP_RX_RING` / `XDP_TX_RING` /
    /// `XDP_UMEM_FILL_RING` / `XDP_UMEM_COMPLETION_RING` call. The
    /// four rings are created together at the first of these calls;
    /// subsequent ones are no-ops.
    pub kernel_parts: IrqSafeSpinLock<Option<XdpSocketParts>>,
    /// Set after `bind(2)`.
    pub bound: AtomicBool,
    pub iface_name: IrqSafeSpinLock<Option<String>>,
    /// Claim id returned from `bypass::register_flow`. Cleared on
    /// close.
    pub claim_seq: IrqSafeSpinLock<Option<u32>>,
}

impl core::fmt::Debug for XdpSocketState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XdpSocketState")
            .field("bound", &self.bound.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Default for XdpSocketState {
    fn default() -> Self {
        Self::new()
    }
}

impl XdpSocketState {
    pub const fn new() -> Self {
        Self {
            umem: IrqSafeSpinLock::new(None),
            kernel_parts: IrqSafeSpinLock::new(None),
            bound: AtomicBool::new(false),
            iface_name: IrqSafeSpinLock::new(None),
            claim_seq: IrqSafeSpinLock::new(None),
        }
    }
}

// ── Errors ─────────────────────────────────────────────────────────

/// XDP socket op errors. Mirrors `crate::socket::SockError` shape
/// for the dispatcher to translate into errno.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum XdpOpError {
    InvalidArg,
    AlreadyRegistered,
    UmemNotRegistered,
    RingsNotCreated,
    BindFailed,
    AccessDenied,
}

// ── setsockopt dispatch ────────────────────────────────────────────

/// Apply `XDP_UMEM_REG`. Registers a fresh UMEM and stashes the
/// `Arc<Umem>` (the user-facing cap is the one stored on the Umem
/// itself, retrievable via [`Umem::cap`]).
pub fn handle_umem_reg(state: &XdpSocketState, reg: &XdpUmemReg) -> Result<(), XdpOpError> {
    if state.umem.lock().is_some() {
        return Err(XdpOpError::AlreadyRegistered);
    }
    let size = reg.len as u32;
    let chunk = reg.chunk_size;
    let umem = Umem::register(size, chunk).map_err(|_| XdpOpError::InvalidArg)?;
    *state.umem.lock() = Some(umem);
    Ok(())
}

/// Apply any of `XDP_RX_RING` / `XDP_TX_RING` / `XDP_UMEM_FILL_RING`
/// / `XDP_UMEM_COMPLETION_RING`. NARF creates all four rings at
/// once at the first such call (matches the AF_XDP usage pattern
/// where userspace sets all four sizes in sequence then binds). The
/// ring depth from `value` is ignored — NARF's ring size is fixed
/// per the `XDP_RING_N` const so the four rings stay symmetric.
pub fn handle_ring_setup(state: &XdpSocketState, _value: u32) -> Result<(), XdpOpError> {
    if state.kernel_parts.lock().is_some() {
        return Ok(());
    }
    let umem = match state.umem.lock().clone() {
        Some(u) => u,
        None => return Err(XdpOpError::UmemNotRegistered),
    };
    let parts = KernelXdpSocket::create(umem);
    *state.kernel_parts.lock() = Some(parts);
    Ok(())
}

/// Apply `bind(2)` with a sockaddr_xdp body. Registers a default
/// (wildcard) flow claim against the socket's kernel-side handle
/// and marks the socket bound. A more specific claim can be added
/// later via `setsockopt(SOL_XDP, XDP_OPTIONS)` once that lands.
pub fn handle_bind(state: &XdpSocketState, addr: &SockAddrXdp) -> Result<(), XdpOpError> {
    if state.bound.load(Ordering::Acquire) {
        return Err(XdpOpError::AlreadyRegistered);
    }
    // Trim NUL from the iface name.
    let n = addr
        .iface_name
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(addr.iface_name.len());
    let iface_str = match core::str::from_utf8(&addr.iface_name[..n]) {
        Ok(s) => s.to_string(),
        Err(_) => return Err(XdpOpError::InvalidArg),
    };
    let parts_owned = state.kernel_parts.lock().is_some();
    if !parts_owned {
        return Err(XdpOpError::RingsNotCreated);
    }
    // Take a clone of the kernel Arc<XdpSocket> without moving the
    // parts.
    let kernel_socket = {
        let g = state.kernel_parts.lock();
        g.as_ref().map(|p| p.socket.clone())
    };
    let kernel_socket = match kernel_socket {
        Some(s) => s,
        None => return Err(XdpOpError::RingsNotCreated),
    };
    kernel_socket
        .bind(iface_str.clone(), addr.queue_id)
        .map_err(|_| XdpOpError::BindFailed)?;
    let seq = narf_net::bypass::register_flow(FlowKey::default(), kernel_socket)
        .map_err(|_| XdpOpError::BindFailed)?;
    *state.claim_seq.lock() = Some(seq);
    *state.iface_name.lock() = Some(iface_str);
    state.bound.store(true, Ordering::Release);
    Ok(())
}

/// Pop one RX descriptor from the kernel's RX ring. Returns the
/// frame bytes (copied out of UMEM into an owned Vec — TODO map
/// the UMEM frame into user space when narf-mmap matures). The
/// frame slot must be returned to FILL by the caller via
/// [`return_to_fill`].
pub fn try_recv(
    state: &XdpSocketState,
) -> Result<Option<(UmemSlot, alloc::vec::Vec<u8>)>, XdpOpError> {
    let mut g = state.kernel_parts.lock();
    let parts = g.as_mut().ok_or(XdpOpError::RingsNotCreated)?;
    let umem = state
        .umem
        .lock()
        .clone()
        .ok_or(XdpOpError::UmemNotRegistered)?;
    let v = match parts.rx_cons.try_recv() {
        Ok(Some(v)) => v,
        _ => return Ok(None),
    };
    let slot = UmemSlot::unpack(v);
    let bytes = umem
        .frame_bytes(slot.frame_idx)
        .ok_or(XdpOpError::AccessDenied)?;
    let payload = bytes[..slot.len as usize].to_vec();
    Ok(Some((slot, payload)))
}

/// Re-post a previously-received frame index to FILL so the kernel
/// can refill it on a later RX.
pub fn return_to_fill(state: &XdpSocketState, slot: UmemSlot) -> Result<(), XdpOpError> {
    let mut g = state.kernel_parts.lock();
    let parts = g.as_mut().ok_or(XdpOpError::RingsNotCreated)?;
    parts
        .fill_prod
        .try_send(
            UmemSlot {
                frame_idx: slot.frame_idx,
                len: 0,
            }
            .pack(),
        )
        .map_err(|_| XdpOpError::InvalidArg)
}

/// Push a TX descriptor onto the kernel's TX ring. Userspace must
/// have staged the frame bytes into UMEM at `slot.frame_idx`
/// already (this is the zero-copy contract).
pub fn send_tx(state: &XdpSocketState, slot: UmemSlot) -> Result<(), XdpOpError> {
    let mut g = state.kernel_parts.lock();
    let parts = g.as_mut().ok_or(XdpOpError::RingsNotCreated)?;
    parts
        .tx_prod
        .try_send(slot.pack())
        .map_err(|_| XdpOpError::InvalidArg)
}

/// Drain one COMPLETION entry. Userspace calls this after `send_tx`
/// to reclaim the frame slot once the driver has finished sending.
pub fn try_completion(state: &XdpSocketState) -> Result<Option<UmemSlot>, XdpOpError> {
    let mut g = state.kernel_parts.lock();
    let parts = g.as_mut().ok_or(XdpOpError::RingsNotCreated)?;
    match parts.comp_cons.try_recv() {
        Ok(Some(v)) => Ok(Some(UmemSlot::unpack(v))),
        _ => Ok(None),
    }
}

/// Close hook — unregister the per-flow claim before the socket
/// goes away so a later socket can claim the same flow.
pub fn close(state: &XdpSocketState) {
    if let Some(seq) = state.claim_seq.lock().take() {
        narf_net::bypass::unregister_flow(seq);
    }
}

/// Parse a 24-byte sockaddr_xdp body into the typed shape.
pub fn parse_sockaddr_xdp(body: &[u8]) -> Option<SockAddrXdp> {
    if body.len() < 22 {
        return None;
    }
    let flags = u16::from_ne_bytes([body[0], body[1]]);
    let queue_id = u32::from_ne_bytes([body[2], body[3], body[4], body[5]]);
    let mut iface_name = [0u8; 16];
    let n = core::cmp::min(16, body.len() - 6);
    iface_name[..n].copy_from_slice(&body[6..6 + n]);
    Some(SockAddrXdp {
        flags,
        queue_id,
        iface_name,
    })
}

/// Parse a 28-byte XdpUmemReg body into the typed shape.
pub fn parse_xdp_umem_reg(body: &[u8]) -> Option<XdpUmemReg> {
    if body.len() < 28 {
        return None;
    }
    let addr = u64::from_ne_bytes([
        body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
    ]);
    let len = u64::from_ne_bytes([
        body[8], body[9], body[10], body[11], body[12], body[13], body[14], body[15],
    ]);
    let chunk_size = u32::from_ne_bytes([body[16], body[17], body[18], body[19]]);
    let headroom = u32::from_ne_bytes([body[20], body[21], body[22], body[23]]);
    let flags = u32::from_ne_bytes([body[24], body[25], body[26], body[27]]);
    Some(XdpUmemReg {
        addr,
        len,
        chunk_size,
        headroom,
        flags,
    })
}

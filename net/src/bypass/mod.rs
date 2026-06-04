//! Kernel-bypass networking — NARF's first-class AF_XDP / DPDK
//! analogue.
//!
//! # Why this exists
//!
//! NARF's design intent is that the TCP/IP stack lives in a
//! userspace daemon (`net/src/stack.rs`). The kernel only owns
//! frame rings + cap gating. This module makes that real, and adds
//! a per-flow bypass surface so a single userspace app can claim a
//! 5-tuple without taking over the whole NIC.
//!
//! # Cap model
//!
//! Every bypass primitive is gated on a small set of cap types:
//!
//! - `Cap<UmemRegion, Invoke>` — read/write the registered userspace
//!   memory region. Minted at [`umem::Umem::register`].
//! - `Cap<FillRing, Invoke>` / `Cap<TxRing, Invoke>` — userspace
//!   produces into these (frames to fill / frames to send).
//! - `Cap<RxRing, Invoke>` / `Cap<CompletionRing, Invoke>` —
//!   userspace consumes from these (frames received / frames
//!   completed by the driver).
//! - `Cap<AdminCap, Invoke>` (re-exported from `crate::stack`) —
//!   gates whole-NIC operations: poll-mode toggle, daemon detach,
//!   link/mtu/mac admin (Stage 4+).
//!
//! Revoking any of these is O(1) per spec §4: the next op observes
//! the new epoch and surfaces `AccessDenied` / `Revoked`.
//!
//! # Classifier ordering
//!
//! For every inbound L2 frame, [`classifier::classify`] decides:
//!
//! 1. **Whole-NIC daemon attach.** Is the originating iface
//!    daemon-attached? If so, forward the raw frame to the daemon's
//!    bypass socket and stop.
//! 2. **Per-flow claim.** Parse the 5-tuple. Walk the claim table
//!    most-specific-first. On match, stage into the socket's UMEM
//!    via FILL → RX.
//! 3. **Fallthrough.** No match → existing
//!    [`crate::tcp_stack::rx_handler`].
//!
//! Specificity = count of non-wildcard 5-tuple fields. Tie-break is
//! registration order (FIFO). Wildcards are encoded as `0` per
//! field.
//!
//! # When to use which
//!
//! - **Whole-NIC daemon attach.** A userspace TCP/IP stack
//!   (smoltcp-style, lwip-style) running its own L2-L7. One daemon
//!   per NIC. Use [`daemon_attach::attach`].
//! - **Per-flow bypass socket.** A user app that wants direct ring
//!   access for a small set of flows (CDN, packet broker, custom
//!   protocol) while letting the kernel stack handle SSH/management
//!   traffic. Use [`xdp::XdpSocket::create`] +
//!   [`classifier::register_flow`].
//!
//! Both coexist with the kernel TCP stack: traffic that doesn't
//! match a bypass claim is dispatched into `tcp_stack::rx_handler`
//! as before.
//!
//! # Zero-copy invariant
//!
//! A UMEM frame is owned by exactly one subsystem at any instant:
//!
//! - FILL: free / kernel may write RX into it
//! - RX:   userspace owns it (kernel filled it)
//! - TX:   userspace handed it off / driver owns it
//! - COMPLETION: userspace must reclaim it (driver finished sending)
//!
//! Frame indices never escape these four rings. The driver writes
//! directly into the UMEM-backed page (no kernel-side bounce
//! buffer); the userspace daemon reads the same physical page via
//! its mapping. RX data is visible to userspace as soon as the
//! classifier publishes the RX ring slot.
//!
//! # Relationship to the kernel TCP stack
//!
//! Peaceful coexistence. The kernel stack runs at full speed on any
//! traffic not claimed by a bypass socket. The classifier hook in
//! [`crate::iface::on_rx_frame`] consults this module *before*
//! calling `tcp_stack::rx_handler`; if the verdict is
//! [`classifier::Verdict::Consumed`] the kernel stack never sees
//! the frame.
//!
//! # Deferred (callouts)
//!
//! - eBPF XDP programs — NARF has no eBPF runtime today. The
//!   classifier table is the only matching mechanism.
//! - IOMMU / VFIO pass-through — assumed in DPDK; NARF's
//!   `narf_io::alloc_coherent` is the substitute pinned-DMA path.
//! - sk_msg / SKMSG redirection — Linux's socket-layer redirect
//!   without going through the NIC.
//! - XSK in a namespace — NARF doesn't have netns.
//!
//! # Linux references
//!
//! - `linux/net/xdp/xdp_umem.c::xdp_umem_create` — UMEM registration.
//! - `linux/net/xdp/xsk.c::xsk_setsockopt` — the four-ring setup.
//! - `linux/net/xdp/xsk_queue.h` — SPSC ring shape.
//! - `linux/Documentation/networking/af_xdp.rst` — overall model.

pub mod classifier;
pub mod daemon_attach;
pub mod poll_mode;
pub mod umem;
pub mod xdp;

pub use classifier::{
    attach_daemon, classify, detach_daemon, is_daemon_attached, register_flow, unregister_flow,
    FlowKey, Verdict,
};
pub use daemon_attach::{attach as daemon_attach, detach as daemon_detach, is_attached};
pub use poll_mode::{is_poll_mode, register_driver, rx_irq_enabled, set_poll_mode, PollModeError};
pub use umem::{Umem, UmemDesc, UmemError, UmemRegion};
pub use xdp::{
    CompletionRing, FillRing, RxRing, TxRing, UmemSlot, XdpAuthority, XdpError, XdpSocket,
    XdpSocketParts, XDP_RING_N,
};

/// Test-only reset hook — wipes classifier + daemon-attach +
/// poll-mode state. Tests call this at top to start from a known
/// baseline.
#[doc(hidden)]
pub fn __reset_for_test() {
    classifier::__reset_for_test();
    daemon_attach::__reset_for_test();
    poll_mode::__reset_for_test();
}

//! Shared netdev publication for the PCIe NIC families (issues #784 /
//! #791 — peripherals audit gaps G-1 / G-8).
//!
//! Before this module, only e1000 and igb published into
//! `narf_net::iface` — the registry the in-kernel TCP/IP stack, DHCP and
//! route selection actually read. Every other family registered only in
//! the cap-gated frame-ring registry (`narf_net::registry()`), so a
//! machine whose only NIC was an I225 or an RTL8168 had a working driver
//! and no usable interface.
//!
//! The mechanism here is the e1000/igb probe pattern, generalised once:
//!
//! 1. [`publish_netdev`] registers the driver under a dynamic `eth%d`
//!    name (`dev_alloc_name` picks the first free slot, so two families
//!    on one machine never collide) and stamps the initial link sample.
//! 2. The driver stores the assigned name in an [`IfName`] static and
//!    reports it from `Interface::name` / `HwNic::name`, superseding the
//!    old hardcoded frame-ring names (`"eth3"`, `"igc"`, …). The
//!    frame-ring registration itself is untouched — stack-daemon / XDP
//!    consumers keep working exactly as before.
//! 3. RX pumps fan out through [`dispatch_rx`], which reproduces
//!    e1000's `dispatch_rx_frame` contract (see that function for the
//!    race it was written to close): when — and only when — a
//!    frame-ring consumer has attached (signalled via
//!    [`note_rx_mirror_attached`] from the family's `rx_ring()` take,
//!    the moment e1000 sets its `rx_mirror_enabled`), a pristine copy
//!    of the frame is mirrored to the ring *before* stack dispatch,
//!    because the stack path (XDP) may rewrite or resize the frame in
//!    place and its classifier may consume, drop or redirect it. The
//!    mirror is an observer's copy: it carries the raw hardware bytes
//!    regardless of the stack's verdict, a full ring drops the mirror
//!    rather than the stack's packet, and with no consumer attached
//!    no copy is made at all. The original frame is then dispatched
//!    to the kernel stack in place via [`deliver_rx`].
//! 4. Carrier stops being a probe-time photograph: interrupt / poll
//!    paths that observe a link transition call [`publish_link`] with a
//!    fresh [`LinkSample`], which forwards to
//!    `narf_net::iface::set_link_metadata` (the one place carrier,
//!    speed and duplex live for rtnetlink / ethtool consumers).

use alloc::vec::Vec;

use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::iface::{LinkDuplex, SendCtxFn, SendFn};
use narf_net::Frame;

/// One physical-link sample: carrier plus, when the PHY/firmware
/// reports them, the negotiated speed and duplex. `speed_mbps` /
/// `duplex` are only meaningful when `carrier` is set — the registry
/// drops them on a carrier-down sample, matching Linux's behaviour of
/// reporting speed `-1` / duplex `unknown` on a down link.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkSample {
    /// True when the PHY/firmware reports link.
    pub carrier: bool,
    /// Negotiated speed in Mbit/s, when known. Families whose in-band
    /// status cannot express their headline rate (Realtek multi-gig
    /// parts) report the highest rate the status *does* prove and say
    /// so at the decode site — never an invented rate.
    pub speed_mbps: Option<u32>,
    /// Negotiated duplex, when the status source reports it.
    pub duplex: Option<LinkDuplex>,
}

impl LinkSample {
    /// A carrier-down sample (speed/duplex unknown by definition).
    pub const DOWN: Self = Self {
        carrier: false,
        speed_mbps: None,
        duplex: None,
    };

    /// A carrier-up sample with the negotiated speed/duplex, either of
    /// which may be unknown for status sources that don't report it.
    pub const fn up(speed_mbps: Option<u32>, duplex: Option<LinkDuplex>) -> Self {
        Self {
            carrier: true,
            speed_mbps,
            duplex,
        }
    }

    /// A sample from a status source that reports carrier and nothing
    /// else (legacy parts, MSR/BMSR-only link bits).
    pub const fn carrier_only(carrier: bool) -> Self {
        Self {
            carrier,
            speed_mbps: None,
            duplex: None,
        }
    }
}

/// The interface name `iface::register` assigned a driver, held for
/// the kernel's lifetime. One static per driver family, mirroring
/// e1000's `E1000_IFNAME`: the name is leaked into a `&'static str`
/// because the device — and therefore its registration — lives as long
/// as the kernel.
#[derive(Debug)]
pub struct IfName(IrqSafeSpinLock<Option<&'static str>>);

impl Default for IfName {
    fn default() -> Self {
        Self::new()
    }
}

impl IfName {
    /// An empty slot (pre-probe).
    pub const fn new() -> Self {
        Self(IrqSafeSpinLock::new(None))
    }

    /// Record the name [`publish_netdev`] returned. Called once, from
    /// probe.
    pub fn set(&self, name: alloc::string::String) {
        *self.0.lock() = Some(alloc::boxed::Box::leak(name.into_boxed_str()));
    }

    /// The assigned name, or `""` before probe published one. The
    /// empty string is the tree's existing "not registered" sentinel
    /// (`e1000_ifname()`), and [`deliver_rx`] treats it as such.
    pub fn get(&self) -> &'static str {
        self.0.lock().unwrap_or("")
    }
}

/// Register a singleton NIC family with the kernel-side stack under a
/// dynamic `eth%d` name and stamp its initial link sample. `send` is
/// the family's trampoline: a plain fn pointer that transmits through
/// the family's controller static (the shape `iface::register` has
/// always required, and the reason each family keeps one tiny
/// trampoline of its own). Returns the assigned name.
pub fn publish_netdev(mac: [u8; 6], send: SendFn, initial: LinkSample) -> alloc::string::String {
    let name = narf_net::iface::register("eth%d", mac, send);
    publish_link(&name, initial);
    name
}

/// [`publish_netdev`] for a multi-instance family: the send hook
/// receives the opaque `cookie` the driver registered with (i40e passes
/// its PF index), so one trampoline serves every port.
pub fn publish_netdev_with_context(
    mac: [u8; 6],
    cookie: u64,
    send: SendCtxFn,
    initial: LinkSample,
) -> alloc::string::String {
    let name = narf_net::iface::register_with_context("eth%d", mac, cookie, send);
    publish_link(&name, initial);
    name
}

/// Push a fresh link sample into the registry's per-interface
/// metadata. Returns false when no interface of that name is
/// registered (a carrier event racing ahead of publication), which
/// callers treat as benign: the next sample lands.
pub fn publish_link(name: &str, sample: LinkSample) -> bool {
    narf_net::iface::set_link_metadata(name, sample.carrier, sample.speed_mbps, sample.duplex)
}

/// Hand a received frame to the kernel-side stack. A no-op before
/// publication (empty name), so pumps can call it unconditionally.
///
/// The frame is passed `&mut`: the stack's bypass classifier may run
/// an attached XDP program that rewrites header bytes in place or
/// resizes the frame, and its verdict may consume, drop or redirect
/// the frame instead of delivering it to the stack. Anything that
/// needs the raw hardware bytes must copy them *before* this call —
/// that is exactly what [`dispatch_rx`] does for the frame ring.
pub fn deliver_rx(name: &str, frame: &mut [u8]) {
    if !name.is_empty() {
        narf_net::iface::on_rx_frame_from(name, frame);
    }
}

/// Interfaces whose frame-ring consumer has attached, by `iface`
/// name. This is the shared-mechanism form of e1000's per-device
/// `rx_mirror_enabled` flag: e1000 sets it inside `Interface::rx_ring`
/// at the moment the consumer is taken out of the device, and each
/// family here calls [`note_rx_mirror_attached`] from the identical
/// moment in its own `rx_ring()`. Keyed by name because the singleton
/// families' pumps hold no per-device mirror state of their own —
/// only the published name. Attach is one-way (Stage-3 rings are
/// never handed back), matching e1000's flag, which is never cleared.
static RX_MIRROR_ATTACHED: IrqSafeSpinLock<Vec<&'static str>> = IrqSafeSpinLock::new(Vec::new());

/// Record that a frame-ring consumer has attached to `name` (it took
/// the RX consumer in `rx_ring()`), enabling [`dispatch_rx`]'s ring
/// mirror for that interface. Called once, from the family's
/// `rx_ring()` take site; a no-op for the empty (unpublished) name.
pub fn note_rx_mirror_attached(name: &'static str) {
    if name.is_empty() {
        return;
    }
    let mut attached = RX_MIRROR_ATTACHED.lock();
    if !attached.contains(&name) {
        attached.push(name);
    }
}

/// True once [`note_rx_mirror_attached`] has fired for `name` — the
/// pump-side query, mirroring e1000's `rx_mirror_enabled` load.
pub fn rx_mirror_attached(name: &str) -> bool {
    RX_MIRROR_ATTACHED.lock().contains(&name)
}

/// The RX fan-out every dual-published family's pump runs per frame —
/// e1000's `dispatch_rx_frame`, generalised (see the module header
/// for the contract). `mirror` is the pump's ring producer sink; it
/// is invoked at most once, with a pristine copy of the frame, and
/// only when `mirror_attached` says a ring consumer has taken the
/// interface's RX ring. The sink is expected to be non-blocking
/// (`try_send`): a full or closed ring drops its mirror, never the
/// packet destined for the live stack — the same choice e1000 makes.
///
/// The copy is allocated from `DomainId::DRIVER_0`, the domain every
/// one of these families already allocates its RX frames from, and
/// carries the frame's `rx_meta` across (the payload copy is taken
/// before `payload_mut()` can reset it). An allocation failure drops
/// the mirror, again mirroring e1000's `if let Ok(..)` shape.
pub fn dispatch_rx(
    name: &str,
    frame: &mut Frame,
    mirror_attached: bool,
    mirror: impl FnOnce(Frame),
) {
    if mirror_attached && !name.is_empty() {
        if let Ok(dma_buf) = narf_io::alloc_coherent(frame.len() as usize, DomainId::DRIVER_0) {
            let mut copy = Frame::new(dma_buf, frame.len());
            copy.payload_mut().copy_from_slice(frame.payload());
            copy.set_rx_meta(frame.rx_meta());
            mirror(copy);
        }
    }
    deliver_rx(name, frame.payload_mut());
}

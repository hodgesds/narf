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
//! 3. RX pumps dual-deliver: frames still go to the IPC ring for the
//!    frame-ring consumer, and [`deliver_rx`] also hands them to the
//!    kernel stack — the same dual delivery e1000's RX path performs.
//! 4. Carrier stops being a probe-time photograph: interrupt / poll
//!    paths that observe a link transition call [`publish_link`] with a
//!    fresh [`LinkSample`], which forwards to
//!    `narf_net::iface::set_link_metadata` (the one place carrier,
//!    speed and duplex live for rtnetlink / ethtool consumers).

use narf_lib::sync::IrqSafeSpinLock;
use narf_net::iface::{LinkDuplex, SendCtxFn, SendFn};

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

/// Hand a received frame to the kernel-side stack, in addition to the
/// frame-ring delivery the driver's pump already performs. A no-op
/// before publication (empty name), so pumps can call it
/// unconditionally.
pub fn deliver_rx(name: &str, frame: &mut [u8]) {
    if !name.is_empty() {
        narf_net::iface::on_rx_frame_from(name, frame);
    }
}

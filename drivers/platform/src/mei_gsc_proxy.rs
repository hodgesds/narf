//! MEI GSC proxy client — the CSME end of the GSC proxy.
//!
//! ## Reference
//!
//! Linux `drivers/misc/mei/gsc_proxy/mei_gsc_proxy.c` and
//! `include/drm/intel/i915_gsc_proxy_mei_interface.h`, revision
//! `b90c984d615e8ce2af96f5b1411a962d83fed2ad`; the client matching
//! rules are `drivers/misc/mei/bus.c::mei_cl_device_find` and
//! `bus-fixup.c` (`number_of_connections`, `vt_support`).
//!
//! ## What it is for
//!
//! On Meteor Lake and Arrow Lake the media GT's GSC (graphics security
//! controller) cannot reach the CSME by itself. The display driver's
//! GSC worker relays: it reads a proxy message out of the GSC, hands it
//! to this client's `send`, reads the CSME's answer with `recv`, and
//! writes it back to the GSC, until the GSC says the proxy is done
//! (`xe_gsc_proxy.c::proxy_query`). PXP and HuC-dependent media both
//! need that handshake to have run.
//!
//! ## What this module does
//!
//! - **Client match** (`mei_gsc_proxy_tbl`): the firmware client whose
//!   protocol name is [`MEI_UUID_GSC_PROXY`], any version, and which
//!   the bus would put on the bus at all — at most one connection, or
//!   vtag support (`number_of_connections`, then `vt_support`).
//! - **Probe** (`mei_gsc_proxy_probe`): `mei_cldev_enable` — link a
//!   host client and connect, with the MEI flow control behind it —
//!   then `component_master_add_with_match`, which here is
//!   [`narf_drivers::gsc_proxy::register_master`] with
//!   [`component_match`] as the match.
//! - **Ops** (`mei_gsc_proxy_ops`): `send` is `mei_cldev_send`, `recv`
//!   is `mei_cldev_recv` — see [`MeiDevice::cl_send`] and
//!   [`MeiDevice::cl_recv`] for the errnos and size limits.
//! - **Remove** (`mei_gsc_proxy_remove`): withdraw the master, then
//!   `mei_cldev_disable`.
//!
//! ## How the display driver binds
//!
//! The display side never names this crate. It looks the component up
//! in `narf_drivers::gsc_proxy`, passing its own PCI identity:
//!
//! ```ignore
//! let me = narf_drivers::gsc_proxy::DisplayComponent {
//!     segment, bus, device, function,      // its BusAddr::Pcie
//!     vendor: dev.id.vendor,               // 0x8086
//!     class: dev.id.class,                 // 0x030000
//! };
//! if let Some(binding) = narf_drivers::gsc_proxy::lookup(&me) {
//!     binding.send(&to_csme[..n])?;        // Err(-errno)
//!     let got = binding.recv(&mut from_csme)?;
//! }
//! ```
//!
//! `lookup` returns `None` until this client is connected and only for
//! an Intel VGA-class function on bus 0 — exactly what
//! `mei_gsc_proxy_component_match` accepts — and `None` again once the
//! client is gone (suspend, device loss, firmware disconnect). A new
//! [`GscProxyBinding::generation`](narf_drivers::gsc_proxy::GscProxyBinding)
//! means the client was re-probed (after resume). Ops on an old
//! binding fail with `-ENODEV` without touching hardware.
//!
//! ## NARF restrictions
//!
//! - Linux binds this client on any HECI function that carries the
//!   UUID. NARF only binds on the HECI-1 functions of the platforms
//!   whose media GT runs the GSC proxy — Meteor Lake (`7e70`) and
//!   Arrow Lake (`7f68`, `7770`), all `MEI_ME_PCH15_CFG` in
//!   `pci-me.c` — so the MS-03 (Panther Lake, `e370`) boots exactly as
//!   before. A device outside [`GSC_PROXY_HECI_IDS`] is refused with
//!   [`ProxyProbeError::NotGscProxyHeci`].
//! - The client's `send` / `recv` are bounded (see
//!   [`crate::mei::MeiTimeouts::cl_io_ms`]); Linux's block forever.

extern crate alloc;

use alloc::sync::Arc;

use narf_drivers::gsc_proxy::{
    DisplayComponent, GscProxyMaster, GscProxyOps, PCI_CLASS_DISPLAY_VGA_CODE, PCI_VENDOR_ID_INTEL,
};
use narf_lib::sync::IrqSafeSpinLock;

use crate::mei::{
    uuid_le, BarRegs, HeciRegs, MeClientInfo, MeiClHandle, MeiDevState, MeiDevice, MeiUuid,
    MEI_DEV_ARL_H, MEI_DEV_ARL_S, MEI_DEV_MTL_M,
};

/// `MEI_UUID_GSC_PROXY`: `UUID_LE(0xf73db04, 0x97ab, 0x4125, 0xb8,
/// 0x93, 0xe9, 0x4, 0xad, 0xd, 0x54, 0x64)`, i.e.
/// `0f73db04-97ab-4125-b893-e904ad0d5464`.
pub const MEI_UUID_GSC_PROXY: MeiUuid = uuid_le(
    0x0f73_db04,
    0x97ab,
    0x4125,
    [0xb8, 0x93, 0xe9, 0x04, 0xad, 0x0d, 0x54, 0x64],
);

/// The HECI-1 functions this client binds on: `MEI_DEV_ID_MTL_M`,
/// `MEI_DEV_ID_ARL_S`, `MEI_DEV_ID_ARL_H` (`hw-me-regs.h`).
pub const GSC_PROXY_HECI_IDS: &[u16] = &[MEI_DEV_MTL_M, MEI_DEV_ARL_S, MEI_DEV_ARL_H];

/// `KBUILD_MODNAME` of the Linux driver; the registry's master name.
pub const DRIVER_NAME: &str = "mei_gsc_proxy";

/// `true` iff this client binds on HECI device `did`.
pub fn heci_carries_gsc_proxy(did: u16) -> bool {
    GSC_PROXY_HECI_IDS.contains(&did)
}

/// `mei_gsc_proxy_component_match`: a PCI Intel VGA-class function on
/// bus 0 (built-in graphics; discrete parts sit on another bus).
pub fn component_match(display: &DisplayComponent) -> bool {
    display.class == PCI_CLASS_DISPLAY_VGA_CODE
        && display.vendor == PCI_VENDOR_ID_INTEL
        && display.bus == 0
}

/// The bus side of the match: `mei_cl_device_find` against
/// `mei_gsc_proxy_tbl` (UUID, `MEI_CL_VERSION_ANY`), after the
/// `number_of_connections` and `vt_support` fixups decided whether the
/// client is on the bus.
pub fn client_eligible(client: &MeClientInfo) -> bool {
    client.props.protocol_name == MEI_UUID_GSC_PROXY
        && (client.props.max_number_of_connections <= 1 || client.props.vt_supported)
}

/// Find the GSC proxy firmware client on `dev`.
pub fn find_client<R: HeciRegs>(dev: &MeiDevice<R>) -> Option<MeClientInfo> {
    dev.me_client_by_uuid(&MEI_UUID_GSC_PROXY)
        .filter(client_eligible)
}

/// A connected GSC proxy client — `struct i915_gsc_proxy_component`'s
/// `mei_dev` plus `mei_gsc_proxy_ops`.
pub struct MeiGscProxy<R: HeciRegs + 'static = BarRegs> {
    dev: Arc<MeiDevice<R>>,
    cl: MeiClHandle,
}

impl<R: HeciRegs + 'static> core::fmt::Debug for MeiGscProxy<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MeiGscProxy")
            .field("cl", &self.cl)
            .finish_non_exhaustive()
    }
}

impl<R: HeciRegs + 'static> MeiGscProxy<R> {
    /// The MEI host client this proxy owns.
    pub fn handle(&self) -> MeiClHandle {
        self.cl
    }

    /// The device the client lives on.
    pub fn device(&self) -> &Arc<MeiDevice<R>> {
        &self.dev
    }
}

impl<R: HeciRegs + 'static> GscProxyOps for MeiGscProxy<R> {
    /// `mei_gsc_proxy_send` → `mei_cldev_send`.
    fn send(&self, message: &[u8]) -> Result<usize, i32> {
        self.dev.cl_send(self.cl, message)
    }

    /// `mei_gsc_proxy_recv` → `mei_cldev_recv`.
    fn recv(&self, buffer: &mut [u8]) -> Result<usize, i32> {
        self.dev.cl_recv(self.cl, buffer)
    }

    fn connected(&self) -> bool {
        self.dev.cl_connected(self.cl)
    }
}

/// Why the client did not bind.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProxyProbeError {
    /// The HECI function is not one this client binds on (NARF).
    NotGscProxyHeci(u16),
    /// Firmware does not expose an eligible GSC proxy client.
    NoClient,
    /// `mei_cldev_enable` failed with this errno.
    Enable(i32),
}

/// A bound client: the proxy and the registry generation it holds.
#[derive(Debug)]
pub struct GscProxyBound<R: HeciRegs + 'static = BarRegs> {
    pub generation: u64,
    pub proxy: Arc<MeiGscProxy<R>>,
}

/// `mei_gsc_proxy_probe`: connect to the GSC proxy client on `dev` and
/// publish it as the component master.
pub fn probe<R: HeciRegs + 'static>(
    dev: &Arc<MeiDevice<R>>,
) -> Result<GscProxyBound<R>, ProxyProbeError> {
    if !heci_carries_gsc_proxy(dev.device_id) {
        return Err(ProxyProbeError::NotGscProxyHeci(dev.device_id));
    }
    let client = find_client(dev).ok_or(ProxyProbeError::NoClient)?;
    let cl = dev
        .cl_connect(client.addr)
        .map_err(ProxyProbeError::Enable)?;
    let proxy = Arc::new(MeiGscProxy {
        dev: dev.clone(),
        cl,
    });
    let ops: Arc<dyn GscProxyOps> = proxy.clone();
    let generation = narf_drivers::gsc_proxy::register_master(GscProxyMaster {
        name: DRIVER_NAME,
        matches: component_match,
        ops,
    });
    Ok(GscProxyBound { generation, proxy })
}

/// `mei_gsc_proxy_remove`: withdraw the master (the component unbind),
/// then `mei_cldev_disable`. Returns the disable's result.
pub fn remove<R: HeciRegs + 'static>(bound: &GscProxyBound<R>) -> Result<(), i32> {
    narf_drivers::gsc_proxy::unregister_master(bound.generation);
    bound.proxy.dev.cl_disconnect(bound.proxy.cl)
}

// ── Production binding ──────────────────────────────────────────────

static BOUND: IrqSafeSpinLock<Option<GscProxyBound>> = IrqSafeSpinLock::new(None);

fn gsc_opted_in() -> bool {
    let args = narf_boot::args::KernelCmdline::new(narf_boot::cmdline());
    let mut enabled = false;
    for token in args.tokens().take_while(|token| *token != "--") {
        let Some(rest) = token.strip_prefix("narf.intel.gsc") else {
            continue;
        };
        if rest.is_empty() {
            return false;
        }
        if let Some(value) = rest.strip_prefix('=') {
            if enabled || value != "1" {
                return false;
            }
            enabled = true;
        } else {
            return false;
        }
    }
    enabled
}

/// Bind the client on the probed HECI device, replacing any earlier
/// binding. Called from the MEI probe and after resume. Silent on
/// HECI functions this client does not bind on or when `narf.intel.gsc=1`
/// is not opted in. Spawns asynchronously so probe is non-blocking.
pub fn bind(dev: &Arc<MeiDevice>) {
    if !heci_carries_gsc_proxy(dev.device_id) {
        return;
    }
    if !gsc_opted_in() {
        return;
    }
    unbind();
    let dev = dev.clone();
    narf_scheduler::spawn(async move {
        use core::fmt::Write as _;
        match probe(&dev) {
            Ok(bound) => {
                if dev.state() == MeiDevState::Enabled {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  mei: gsc proxy client connected (host {}, fw {}), component master gen {}",
                        bound.proxy.cl.host_addr,
                        bound.proxy.cl.me_addr,
                        bound.generation,
                    );
                    *BOUND.lock() = Some(bound);
                } else {
                    let _ = remove(&bound);
                }
            }
            Err(e) => {
                let _ = writeln!(narf_console::Writer, "  mei: gsc proxy not bound: {:?}", e);
            }
        }
    });
}

/// Unbind the production client, if bound.
pub fn unbind() {
    let bound = BOUND.lock().take();
    if let Some(bound) = bound {
        let _ = remove(&bound);
    }
}

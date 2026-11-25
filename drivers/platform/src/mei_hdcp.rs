//! MEI HDCP client — the CSME end of HDCP 2.2 on Gen12 display.
//!
//! ## Reference
//!
//! Linux `drivers/misc/mei/hdcp/mei_hdcp.c` (`mei_hdcp_tbl`,
//! `mei_hdcp_probe`, `mei_hdcp_remove`, `mei_hdcp_component_match`) and
//! `include/drm/intel/i915_hdcp_interface.h`; the client matching rules
//! are `drivers/misc/mei/bus.c::mei_cl_device_find` and `bus-fixup.c`
//! (`number_of_connections`, `vt_support`).
//!
//! ## What it is for
//!
//! On Tiger Lake and Alder Lake the HDCP 2.2 transmitter keys, the
//! receiver-certificate check, km/ks generation and the H' / L' / V / M'
//! checks all live in the CSME's HDCP firmware client. The display driver
//! relays the sink's messages to it and back (`intel_hdcp.c`'s
//! `hdcp2_*` helpers through `i915_hdcp_arbiter`). Meteor Lake and later
//! reach the same firmware through the media GT's GSC instead
//! (`intel_hdcp_gsc_message.c`); this client is not used there.
//!
//! ## What this module does
//!
//! - **Client match** (`mei_hdcp_tbl`): the firmware client whose
//!   protocol name is [`MEI_UUID_HDCP`], any version, that the bus would
//!   put on the bus at all (`number_of_connections`, then `vt_support`).
//! - **Probe** (`mei_hdcp_probe`): `mei_cldev_enable`, then
//!   `component_master_add_with_match`, which here is
//!   [`narf_drivers::hdcp_component::register_master`] with
//!   [`component_match`].
//! - **Transport**: one `mei_cldev_send` of a `wired_cmd_*_in` command
//!   and one `mei_cldev_recv` of its reply ([`MeiDevice::cl_send`] and
//!   [`MeiDevice::cl_recv`]). The command encoding lives once, in the
//!   display driver, for both this transport and the GSC one; see
//!   [`narf_drivers::hdcp_component`].
//! - **Remove** (`mei_hdcp_remove`): withdraw the master, then
//!   `mei_cldev_disable`.
//!
//! ## NARF restrictions
//!
//! - Linux binds this client on any HECI function that carries the UUID.
//!   NARF binds only on the HECI-1 functions of the PCHs paired with
//!   display 12 and 13 ([`HDCP_HECI_IDS`]), and only with
//!   `narf.intel.hdcp=1` on the command line, so every other board and
//!   every boot without the option is unchanged. Anything else is refused
//!   with [`HdcpProbeError::NotHdcpHeci`] before any I/O.
//! - The client never logs a command or reply: they carry receiver IDs,
//!   encrypted keys and the topology.

extern crate alloc;

use alloc::sync::Arc;

use narf_drivers::gsc_proxy::{PCI_CLASS_DISPLAY_VGA_CODE, PCI_VENDOR_ID_INTEL};
use narf_drivers::hdcp_component::{DisplayComponent, HdcpMaster, MeiHdcpOps};
use narf_lib::sync::IrqSafeSpinLock;

use crate::mei::{
    uuid_le, BarRegs, HeciRegs, MeClientInfo, MeiClHandle, MeiDevState, MeiDevice, MeiUuid,
    MEI_DEV_ADP_LP, MEI_DEV_ADP_N, MEI_DEV_ADP_P, MEI_DEV_ADP_S, MEI_DEV_RPL_S, MEI_DEV_TGP_H,
    MEI_DEV_TGP_LP,
};

/// `MEI_UUID_HDCP`: `UUID_LE(0xB638AB7E, 0x94E2, 0x4EA2, 0xA5, 0x52,
/// 0xD1, 0xC5, 0x4B, 0x62, 0x7F, 0x04)`, i.e.
/// `b638ab7e-94e2-4ea2-a552-d1c54b627f04`.
pub const MEI_UUID_HDCP: MeiUuid = uuid_le(
    0xB638_AB7E,
    0x94E2,
    0x4EA2,
    [0xA5, 0x52, 0xD1, 0xC5, 0x4B, 0x62, 0x7F, 0x04],
);

/// The HECI-1 functions this client binds on: the Tiger Lake, Alder Lake
/// and Raptor Lake PCHs (`hw-me-regs.h`), whose display (12 and 13) uses
/// the MEI HDCP client (`intel_hdcp.c::is_hdcp2_supported` without
/// `USE_HDCP_GSC`).
pub const HDCP_HECI_IDS: &[u16] = &[
    MEI_DEV_TGP_LP,
    MEI_DEV_TGP_H,
    MEI_DEV_ADP_S,
    MEI_DEV_ADP_LP,
    MEI_DEV_ADP_P,
    MEI_DEV_ADP_N,
    MEI_DEV_RPL_S,
];

/// `KBUILD_MODNAME` of the Linux driver; the registry's master name.
pub const DRIVER_NAME: &str = "mei_hdcp";

/// The boot option that admits this client.
pub const BOOT_OPTION: &str = "narf.intel.hdcp";

/// `true` iff this client binds on HECI device `did`.
pub fn heci_carries_hdcp(did: u16) -> bool {
    HDCP_HECI_IDS.contains(&did)
}

/// `mei_hdcp_component_match`: an Intel VGA-class PCI function whose
/// parent bus is the HECI function's — built-in graphics on bus 0 of
/// segment 0 (a discrete card sits behind its own bridge).
pub fn component_match(display: &DisplayComponent) -> bool {
    display.class == PCI_CLASS_DISPLAY_VGA_CODE
        && display.vendor == PCI_VENDOR_ID_INTEL
        && display.segment == 0
        && display.bus == 0
}

/// `mei_cl_device_find` against `mei_hdcp_tbl` (UUID,
/// `MEI_CL_VERSION_ANY`) after the `number_of_connections` and
/// `vt_support` fixups.
pub fn client_eligible(client: &MeClientInfo) -> bool {
    client.props.protocol_name == MEI_UUID_HDCP
        && (client.props.max_number_of_connections <= 1 || client.props.vt_supported)
}

/// Find the HDCP firmware client on `dev`.
pub fn find_client<R: HeciRegs>(dev: &MeiDevice<R>) -> Option<MeClientInfo> {
    dev.me_client_by_uuid(&MEI_UUID_HDCP)
        .filter(client_eligible)
}

/// A connected HDCP client: the arbiter's `hdcp_dev`.
pub struct MeiHdcp<R: HeciRegs + 'static = BarRegs> {
    dev: Arc<MeiDevice<R>>,
    cl: MeiClHandle,
}

impl<R: HeciRegs + 'static> core::fmt::Debug for MeiHdcp<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MeiHdcp")
            .field("cl", &self.cl)
            .finish_non_exhaustive()
    }
}

impl<R: HeciRegs + 'static> MeiHdcp<R> {
    /// The MEI host client this connection owns.
    pub fn handle(&self) -> MeiClHandle {
        self.cl
    }
}

impl<R: HeciRegs + 'static> MeiHdcpOps for MeiHdcp<R> {
    fn send(&self, message: &[u8]) -> Result<usize, i32> {
        self.dev.cl_send(self.cl, message)
    }

    fn recv(&self, buffer: &mut [u8]) -> Result<usize, i32> {
        self.dev.cl_recv(self.cl, buffer)
    }

    fn connected(&self) -> bool {
        self.dev.cl_connected(self.cl)
    }
}

/// Why the client did not bind.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HdcpProbeError {
    /// The HECI function is not one this client binds on (NARF).
    NotHdcpHeci(u16),
    /// Firmware does not expose an eligible HDCP client.
    NoClient,
    /// `mei_cldev_enable` failed with this errno.
    Enable(i32),
}

/// A bound client and the registry generation it holds.
#[derive(Debug)]
pub struct HdcpBound<R: HeciRegs + 'static = BarRegs> {
    pub generation: u64,
    pub client: Arc<MeiHdcp<R>>,
}

/// `mei_hdcp_probe`: connect to the HDCP client on `dev` and publish it
/// as the component master.
pub fn probe<R: HeciRegs + 'static>(
    dev: &Arc<MeiDevice<R>>,
) -> Result<HdcpBound<R>, HdcpProbeError> {
    if !heci_carries_hdcp(dev.device_id) {
        return Err(HdcpProbeError::NotHdcpHeci(dev.device_id));
    }
    let client = find_client(dev).ok_or(HdcpProbeError::NoClient)?;
    let cl = dev
        .cl_connect(client.addr)
        .map_err(HdcpProbeError::Enable)?;
    let client = Arc::new(MeiHdcp {
        dev: dev.clone(),
        cl,
    });
    let ops: Arc<dyn MeiHdcpOps> = client.clone();
    let generation = narf_drivers::hdcp_component::register_master(HdcpMaster {
        name: DRIVER_NAME,
        matches: component_match,
        ops,
    });
    Ok(HdcpBound { generation, client })
}

/// `mei_hdcp_remove`: withdraw the master, then `mei_cldev_disable`.
pub fn remove<R: HeciRegs + 'static>(bound: &HdcpBound<R>) -> Result<(), i32> {
    narf_drivers::hdcp_component::unregister_master(bound.generation);
    bound.client.dev.cl_disconnect(bound.client.cl)
}

/// A strict `name=1` boot option: present exactly once with value `1`
/// before `--`; any other spelling disables it.
pub fn boot_opt_in(cmdline: &str, name: &str) -> bool {
    let args = narf_boot::args::KernelCmdline::new(cmdline);
    let mut enabled = false;
    for token in args.tokens().take_while(|token| *token != "--") {
        let Some(rest) = token.strip_prefix(name) else {
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
        }
    }
    enabled
}

// ── Production binding ──────────────────────────────────────────────

static BOUND: IrqSafeSpinLock<Option<HdcpBound>> = IrqSafeSpinLock::new(None);

/// Bind the client on the probed HECI device, replacing any earlier
/// binding. Called from the MEI probe and after resume. Silent on HECI
/// functions this client does not bind on and without
/// `narf.intel.hdcp=1`.
pub fn bind(dev: &Arc<MeiDevice>) {
    if !heci_carries_hdcp(dev.device_id) || !boot_opt_in(narf_boot::cmdline(), BOOT_OPTION) {
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
                        "  mei: hdcp client connected (host {}, fw {}), component master gen {}",
                        bound.client.cl.host_addr,
                        bound.client.cl.me_addr,
                        bound.generation,
                    );
                    *BOUND.lock() = Some(bound);
                } else {
                    let _ = remove(&bound);
                }
            }
            Err(e) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  mei: hdcp client not bound: {:?}",
                    e
                );
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

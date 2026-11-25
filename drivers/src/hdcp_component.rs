//! HDCP component hand-off — the meeting point between the MEI HDCP
//! client on the CSME and the Intel display driver's HDCP 2.2 code.
//!
//! ## What Linux does
//!
//! `drivers/misc/mei/hdcp/mei_hdcp.c` registers as the *aggregate
//! master* (`component_master_add_with_match`), matching the display
//! device with `mei_hdcp_component_match` (an Intel VGA-class PCI
//! function whose parent bus is the HECI function's, i.e. built-in
//! graphics), while i915 / xe add a component
//! (`component_add_typed(..., I915_COMPONENT_HDCP)` from
//! `intel_hdcp_component_init`). On bind,
//! `i915_hdcp_component_bind` stores the `struct i915_hdcp_arbiter`
//! (`include/drm/intel/i915_hdcp_interface.h`): the eleven HDCP 2.2
//! ops plus the MEI device they act on. Each op is one
//! `mei_cldev_send` of a `wired_cmd_*_in` command followed by one
//! `mei_cldev_recv` of its `wired_cmd_*_out` reply.
//!
//! ## What this module does
//!
//! The same split without a crate dependency in either direction, in
//! the pattern of [`crate::gsc_proxy`]:
//!
//! - The MEI side (`narf_drivers_platform::mei_hdcp`) publishes an
//!   [`HdcpMaster`] with [`register_master`] once its firmware client
//!   is connected and withdraws it with [`unregister_master`].
//! - The display side asks for the binding with [`lookup`], passing its
//!   own PCI identity. The master's match function decides, as
//!   `mei_hdcp_component_match` does.
//!
//! The binding is a message transport: [`MeiHdcpOps::send`] /
//! [`MeiHdcpOps::recv`] carry one `wired_cmd_*` command and its reply.
//! Linux translates the HDCP 2.2 messages into those commands twice,
//! byte for byte the same, in `mei_hdcp.c` and in the display driver's
//! `intel_hdcp_gsc_message.c`; NARF translates once, in the display
//! driver (`narf_drivers_gpu::intel_hdcp_msg`), for both the MEI and the
//! GSC transport. Every op on a binding whose client has gone away
//! fails with `-ENODEV` without touching hardware.

use alloc::sync::Arc;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

pub use crate::gsc_proxy::DisplayComponent;

/// The MEI HDCP client's transport: `mei_cldev_send` and
/// `mei_cldev_recv` on the connected firmware client.
///
/// Both calls block for a bounded time. Errors are negative errnos.
pub trait MeiHdcpOps: Send + Sync {
    /// Send one `wired_cmd_*_in` command. Returns the bytes sent or a
    /// negative errno.
    fn send(&self, message: &[u8]) -> Result<usize, i32>;
    /// Receive one reply into `buffer` (truncated to its length).
    /// Returns the bytes received or a negative errno.
    fn recv(&self, buffer: &mut [u8]) -> Result<usize, i32>;
    /// `mei_cldev_enabled`: the firmware client is still connected.
    fn connected(&self) -> bool;
}

/// The aggregate master the MEI side publishes.
pub struct HdcpMaster {
    /// Name of the publishing driver, for diagnostics.
    pub name: &'static str,
    /// The master's component match (`mei_hdcp_component_match`).
    pub matches: fn(&DisplayComponent) -> bool,
    /// The transport the display side receives on bind.
    pub ops: Arc<dyn MeiHdcpOps>,
}

impl fmt::Debug for HdcpMaster {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HdcpMaster")
            .field("name", &self.name)
            .field("connected", &self.ops.connected())
            .finish_non_exhaustive()
    }
}

/// A bound component: `display->hdcp.arbiter` as the display driver
/// holds it after `i915_hdcp_component_bind`.
#[derive(Clone)]
pub struct HdcpBinding {
    /// Changes every time a master is registered, so a holder can tell
    /// a rebind (after resume or a reconnect) from its binding.
    pub generation: u64,
    /// The publishing driver's name.
    pub name: &'static str,
    ops: Arc<dyn MeiHdcpOps>,
}

impl fmt::Debug for HdcpBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HdcpBinding")
            .field("generation", &self.generation)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl HdcpBinding {
    /// One command and its reply (`mei_cldev_send` then
    /// `mei_cldev_recv`). Returns the reply length.
    pub fn exchange(&self, command: &[u8], reply: &mut [u8]) -> Result<usize, i32> {
        self.ops.send(command)?;
        self.ops.recv(reply)
    }

    /// The MEI client behind this binding is still connected.
    pub fn connected(&self) -> bool {
        self.ops.connected()
    }
}

static MASTER: IrqSafeSpinLock<Option<(u64, HdcpMaster)>> = IrqSafeSpinLock::new(None);
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// Publish the MEI side. Replaces any earlier master (one HDCP client
/// per CSME) and returns the new generation, which
/// [`unregister_master`] takes.
pub fn register_master(master: HdcpMaster) -> u64 {
    let generation = GENERATION.fetch_add(1, Ordering::Relaxed) + 1;
    let old = MASTER.lock().replace((generation, master));
    drop(old);
    generation
}

/// Withdraw the master registered as `generation`
/// (`component_master_del`). Returns `false` if a different master (or
/// none) is registered.
pub fn unregister_master(generation: u64) -> bool {
    let old = {
        let mut slot = MASTER.lock();
        match slot.as_ref() {
            Some((g, _)) if *g == generation => slot.take(),
            _ => None,
        }
    };
    old.is_some()
}

/// The component bind, from the display side: the binding if a master
/// is registered, its match accepts `display`, and its client is still
/// connected.
pub fn lookup(display: &DisplayComponent) -> Option<HdcpBinding> {
    let (generation, name, matches, ops) = {
        let slot = MASTER.lock();
        let (g, m) = slot.as_ref()?;
        (*g, m.name, m.matches, m.ops.clone())
    };
    if !matches(display) || !ops.connected() {
        return None;
    }
    Some(HdcpBinding {
        generation,
        name,
        ops,
    })
}

#[doc(hidden)]
/// Test-only: forget the registered master.
pub fn __reset_for_test() {
    let old = MASTER.lock().take();
    drop(old);
}

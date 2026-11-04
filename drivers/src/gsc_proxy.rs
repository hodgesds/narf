//! GSC proxy component hand-off — the meeting point between the MEI
//! GSC proxy client and the Intel display device's GSC worker.
//!
//! ## What Linux does
//!
//! `include/drm/intel/i915_gsc_proxy_mei_interface.h` declares the ops
//! table both sides share (`struct i915_gsc_proxy_component_ops`:
//! `send` / `recv`, each returning bytes or a negative errno). Neither
//! driver links against the other: `drivers/misc/mei/gsc_proxy/
//! mei_gsc_proxy.c` registers as the *aggregate master*
//! (`component_master_add_with_match`), matching the display device
//! with `mei_gsc_proxy_component_match` (Intel, PCI class
//! `PCI_CLASS_DISPLAY_VGA << 8`, bus 0), while xe / i915 add a
//! component (`component_add_typed(..., I915_COMPONENT_GSC_PROXY)`).
//! When both exist, `drivers/base/component.c` binds them and the
//! display driver's bind callback (`xe_gsc_proxy_component_bind`)
//! stores the `struct i915_gsc_proxy_component` — the ops plus the
//! MEI device they act on. Removing the MEI client
//! (`mei_gsc_proxy_remove` → `component_master_del`) unbinds it.
//!
//! ## What this module does
//!
//! The same split without a crate dependency in either direction:
//! `narf-drivers-platform` (the MEI side) and `narf-drivers-gpu` (the
//! display side) both already depend on this crate.
//!
//! - The MEI side publishes a [`GscProxyMaster`] with
//!   [`register_master`] once its firmware client is connected, and
//!   withdraws it with [`unregister_master`] on teardown.
//! - The display side asks for the binding with [`lookup`], passing
//!   its own PCI identity as a [`DisplayComponent`]. The master's
//!   match function decides, exactly as `mei_gsc_proxy_component_match`
//!   does. A `Some` is the component bind; a later `None`, or a
//!   different [`GscProxyBinding::generation`], is the unbind / rebind.
//!
//! The pull model replaces the bind/unbind callbacks: the display side
//! looks the binding up whenever it needs the proxy, and every op on a
//! binding whose MEI client has since gone away fails with `-ENODEV`
//! rather than touching hardware, so a stale binding is harmless.
//! `lookup` also refuses a master whose client is no longer connected
//! (`mei_cldev_enabled`), which is how device loss and a firmware-
//! initiated disconnect surface as an unbind.

use alloc::sync::Arc;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

/// Intel's PCI vendor ID.
pub const PCI_VENDOR_ID_INTEL: u16 = 0x8086;
/// `PCI_CLASS_DISPLAY_VGA << 8`: the 24-bit class code (base 0x03,
/// sub-class 0x00, prog-if 0x00) `mei_gsc_proxy_component_match`
/// compares `pdev->class` against.
pub const PCI_CLASS_DISPLAY_VGA_CODE: u32 = 0x03_00_00;

/// `struct i915_gsc_proxy_component_ops`.
///
/// Both calls block. Errors are negative errnos, as in Linux; the
/// meaningful ones are listed on the MEI implementation
/// (`narf_drivers_platform::mei_gsc_proxy`).
pub trait GscProxyOps: Send + Sync {
    /// `ops->send`: send one proxy message to the CSME. Returns the
    /// bytes sent or a negative errno.
    fn send(&self, message: &[u8]) -> Result<usize, i32>;
    /// `ops->recv`: receive one proxy message from the CSME into
    /// `buffer`. Returns the bytes received (truncated to
    /// `buffer.len()`) or a negative errno.
    fn recv(&self, buffer: &mut [u8]) -> Result<usize, i32>;
    /// `mei_cldev_enabled`: the firmware client is still connected.
    fn connected(&self) -> bool;
}

/// The display-side component's PCI identity — exactly the fields
/// `mei_gsc_proxy_component_match` reads from the `struct pci_dev`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DisplayComponent {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor: u16,
    /// 24-bit PCI class code (base class in bits 23:16).
    pub class: u32,
}

/// The aggregate master the MEI side publishes
/// (`component_master_add_with_match` + the ops it binds with).
pub struct GscProxyMaster {
    /// Name of the publishing driver, for diagnostics.
    pub name: &'static str,
    /// The master's component match (`mei_gsc_proxy_component_match`).
    pub matches: fn(&DisplayComponent) -> bool,
    /// The ops the display side receives on bind.
    pub ops: Arc<dyn GscProxyOps>,
}

impl fmt::Debug for GscProxyMaster {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GscProxyMaster")
            .field("name", &self.name)
            .field("connected", &self.ops.connected())
            .finish_non_exhaustive()
    }
}

/// A bound component: `struct i915_gsc_proxy_component` as the
/// display driver holds it.
#[derive(Clone)]
pub struct GscProxyBinding {
    /// Changes every time a master is registered, so a holder can
    /// tell a rebind (after resume or a reconnect) from the binding
    /// it already has.
    pub generation: u64,
    /// The publishing driver's name.
    pub name: &'static str,
    ops: Arc<dyn GscProxyOps>,
}

impl fmt::Debug for GscProxyBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GscProxyBinding")
            .field("generation", &self.generation)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl GscProxyBinding {
    /// `comp->ops->send(comp->mei_dev, buf, size)`.
    pub fn send(&self, message: &[u8]) -> Result<usize, i32> {
        self.ops.send(message)
    }

    /// `comp->ops->recv(comp->mei_dev, buf, size)`.
    pub fn recv(&self, buffer: &mut [u8]) -> Result<usize, i32> {
        self.ops.recv(buffer)
    }

    /// The MEI client behind this binding is still connected.
    pub fn connected(&self) -> bool {
        self.ops.connected()
    }
}

static MASTER: IrqSafeSpinLock<Option<(u64, GscProxyMaster)>> = IrqSafeSpinLock::new(None);
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// Publish the MEI side. Replaces any earlier master (Linux allows one
/// GSC proxy client per system) and returns the new generation, which
/// [`unregister_master`] takes so a stale teardown cannot withdraw a
/// newer master.
pub fn register_master(master: GscProxyMaster) -> u64 {
    let generation = GENERATION.fetch_add(1, Ordering::Relaxed) + 1;
    let old = MASTER.lock().replace((generation, master));
    // Drop the replaced ops outside the lock.
    drop(old);
    generation
}

/// Withdraw the master registered as `generation`
/// (`component_master_del`). Returns `false` if a different master
/// (or none) is registered.
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

/// The component bind, from the display side: the binding if a
/// master is registered, its match accepts `display`, and its client
/// is still connected.
pub fn lookup(display: &DisplayComponent) -> Option<GscProxyBinding> {
    let (generation, name, matches, ops) = {
        let slot = MASTER.lock();
        let (g, m) = slot.as_ref()?;
        (*g, m.name, m.matches, m.ops.clone())
    };
    // Run the match and the liveness check outside the lock: `ops`
    // may take the MEI device lock.
    if !matches(display) || !ops.connected() {
        return None;
    }
    Some(GscProxyBinding {
        generation,
        name,
        ops,
    })
}

/// Generation of the registered master, if any.
pub fn registered_generation() -> Option<u64> {
    MASTER.lock().as_ref().map(|(g, _)| *g)
}

#[doc(hidden)]
/// Test-only: forget the registered master.
pub fn __reset_for_test() {
    let old = MASTER.lock().take();
    drop(old);
}

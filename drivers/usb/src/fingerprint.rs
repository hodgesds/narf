//! USB fingerprint reader transport — Stage 0.
//!
//! ## References (public only)
//!
//! - **USB 2.0 Specification §9.6** — Configuration, Interface, and
//!   Endpoint Descriptor layouts.
//!   <https://www.usb.org/document-library/usb-20-specification>
//! - **libfprint device table** — USB VID/PID pairs for Goodix,
//!   Synaptics-Validity, and ELAN drivers; consulted as a public index
//!   only (no codec internals imported).
//!   <https://gitlab.freedesktop.org/libfprint/libfprint/-/tree/master/libfprint/drivers>
//!   The table itself lives in exactly one place —
//!   `narf_drivers_fingerprint::FINGERPRINT_DEVICES` (issue #918) —
//!   and `classify_vid_pid` below only maps its families to the
//!   transport vendor. There is no second table here to drift.
//! - **Linux `drivers/hid/hid-ids.h`** — vendor/product IDs for cross-
//!   reference. GPL-2.0-or-later; permitted since NARF relicense 2026-05-20.
//!
//! ## Scope — kernel is transport only
//!
//! Every fingerprint reader vendor (Goodix, Synaptics/Validity, ELAN) uses
//! a proprietary image-acquisition and matching protocol that is NOT
//! implemented here. Those codecs live in userspace (libfprint / fprintd)
//! and drive the sensor by writing vendor commands to the bulk-OUT endpoint
//! and reading responses from bulk-IN (or interrupt-IN for ELAN).
//!
//! The kernel's job is:
//!
//! 1. Recognise the device by VID/PID (vendor class 0xFF bypasses the WBDI
//!    cascade for devices that don't advertise MS OS 2.0 descriptors).
//! 2. Discover the bulk-IN + bulk-OUT endpoints (Synaptics, Goodix,
//!    Validity) or interrupt-IN endpoint (ELAN).
//! 3. Configure those endpoints on the xHC.
//! 4. Publish one `/dev/fp<N>` character device per bound reader in
//!    DevFs (provider registry, `lookup_fp` / `enumerate_fp`) so a
//!    userspace daemon (fprintd) can open a reader by registry index
//!    and drive the vendor protocol, including EP0 vendor control
//!    transfers through the `FP_IOC_CTRL_TRANSFER` ioctl. Opens are
//!    gated on the caller's `CAP_SYS_RAWIO` capability (see the
//!    FileOps bridge below); the data plane is unchanged.
//!
//! Out of scope: enrolment, matching, image decoding, any vendor command.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use narf_lib::sync::IrqSafeSpinLock;

use crate::xhci::{EndpointConfig, EndpointKind, Xhci};

// ── Vendor + USB-ID table ─────────────────────────────────────────────

/// Standard USB SET_CONFIGURATION request (USB 2.0 §9.4.7).
const STD_REQ_SET_CONFIGURATION: u8 = 0x09;

/// Fingerprint reader vendor family — the transport selector for
/// the bind path (bulk pair vs interrupt-IN).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FpVendor {
    /// Synaptics (formerly Validity Sensors). Bulk-IN + bulk-OUT.
    Synaptics,
    /// Goodix. Bulk-IN + bulk-OUT.
    Goodix,
    /// ELAN Microelectronics. Interrupt-IN only.
    Elan,
    /// Validity (VID 0x138A, pre-merger silicon still shipped
    /// under the Validity VID). Bulk-IN + bulk-OUT: the live
    /// module's non-ELAN bulk rule covers it, and endpoint
    /// discovery is blob-driven — a Validity device exposing no
    /// bulk pair fails with `EndpointsMissing` and falls through
    /// the cascade rather than mis-binding.
    Validity,
}

/// Look up a (VID, PID) pair in the single match authority and
/// map its family to the transport vendor.
///
/// SINGLE MATCH AUTHORITY (issue #918): the table lives in
/// `narf_drivers_fingerprint::FINGERPRINT_DEVICES` (31 entries:
/// the scaffold table union the pre-#918 USB table). This
/// function owns no table of its own — the pre-#918 tree kept a
/// second 17-entry table here that drifted from the scaffold's
/// 22, agreeing on only 8 of the union and leaving the whole
/// Validity family unbindable. Deleting the second table makes
/// drift structurally impossible: every consumer reads the one
/// table, and `smoke_fp_classify_matches_authority_table` pins
/// the family→vendor mapping for all 31 entries.
pub fn classify_vid_pid(vid: u16, pid: u16) -> Option<FpVendor> {
    use narf_drivers_fingerprint::Family;
    narf_drivers_fingerprint::match_vid_pid(vid, pid).map(|d| match d.family {
        Family::SynapticsPrometheus | Family::SynapticsMisOlder => FpVendor::Synaptics,
        Family::Goodix => FpVendor::Goodix,
        Family::Elan => FpVendor::Elan,
        Family::Validity => FpVendor::Validity,
    })
}

// ── Endpoint discovery ────────────────────────────────────────────────

/// Errors from the fingerprint bind path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FpError {
    /// Neither the USB-ID table nor the WBDI class-path matched.
    NotFingerprint,
    /// Configuration descriptor was missing the required endpoints.
    EndpointsMissing,
    /// xHCI endpoint-context configuration failed.
    EndpointConfig,
    /// SET_CONFIGURATION control transfer failed.
    SetConfiguration,
}

/// Endpoints for a fingerprint device. ELAN uses interrupt-IN;
/// Synaptics, Goodix, and Validity use bulk-IN + bulk-OUT.
#[derive(Copy, Clone, Debug)]
pub enum FpEndpoints {
    /// bulk-IN / bulk-OUT pair (Synaptics, Goodix, Validity).
    Bulk {
        bulk_in: EndpointConfig,
        bulk_out: EndpointConfig,
        /// bInterfaceNumber of the vendor interface.
        interface: u8,
        config_value: u8,
    },
    /// interrupt-IN only (ELAN).
    InterruptIn {
        intr_in: EndpointConfig,
        interface: u8,
        config_value: u8,
    },
}

/// Walk a Configuration Descriptor for the first vendor-class (0xFF)
/// interface and resolve endpoints appropriate for `vendor`.
///
/// - Synaptics / Goodix / Validity: require bulk-IN + bulk-OUT.
/// - ELAN: require interrupt-IN (may also have bulk pair; we take
///   interrupt-IN because that is the polling path libfprint uses).
pub fn find_fp_endpoints(cfg: &[u8], vendor: FpVendor) -> Result<FpEndpoints, FpError> {
    if cfg.len() < 9 || cfg[1] != 0x02 {
        return Err(FpError::NotFingerprint);
    }
    let config_value = cfg[5];

    let mut i = 0usize;
    let mut interface: Option<u8> = None;
    let mut bulk_in: Option<EndpointConfig> = None;
    let mut bulk_out: Option<EndpointConfig> = None;
    let mut intr_in: Option<EndpointConfig> = None;
    let mut in_match = false;

    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        match cfg[i + 1] {
            // Interface Descriptor (USB 2.0 §9.6.5) — bInterfaceClass at +5.
            4 if len >= 9 => {
                in_match = cfg[i + 5] == 0xFF; // vendor class
                if in_match && interface.is_none() {
                    interface = Some(cfg[i + 2]);
                    // Clear any endpoints accumulated for a prior
                    // non-matching interface in a composite device.
                    bulk_in = None;
                    bulk_out = None;
                    intr_in = None;
                }
            }
            // Endpoint Descriptor (§9.6.6) — 7 bytes minimum.
            5 if len >= 7 && in_match => {
                let ep_addr = cfg[i + 2];
                let attr = cfg[i + 3];
                let mps = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]);
                let xfer = attr & 0x03;
                let is_in = ep_addr & 0x80 != 0;
                match (xfer, is_in) {
                    (2, true) if bulk_in.is_none() => {
                        bulk_in = Some(EndpointConfig {
                            ep_addr,
                            max_packet: mps,
                            kind: EndpointKind::BulkIn,
                            interval: 0,
                        });
                    }
                    (2, false) if bulk_out.is_none() => {
                        bulk_out = Some(EndpointConfig {
                            ep_addr,
                            max_packet: mps,
                            kind: EndpointKind::BulkOut,
                            interval: 0,
                        });
                    }
                    (3, true) if intr_in.is_none() => {
                        intr_in = Some(EndpointConfig {
                            ep_addr,
                            max_packet: mps,
                            kind: EndpointKind::InterruptIn,
                            interval: cfg[i + 6],
                        });
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        i += len;
    }

    let iface = interface.ok_or(FpError::EndpointsMissing)?;
    match vendor {
        FpVendor::Elan => {
            let intr = intr_in.ok_or(FpError::EndpointsMissing)?;
            Ok(FpEndpoints::InterruptIn {
                intr_in: intr,
                interface: iface,
                config_value,
            })
        }
        FpVendor::Synaptics | FpVendor::Goodix | FpVendor::Validity => {
            let bi = bulk_in.ok_or(FpError::EndpointsMissing)?;
            let bo = bulk_out.ok_or(FpError::EndpointsMissing)?;
            Ok(FpEndpoints::Bulk {
                bulk_in: bi,
                bulk_out: bo,
                interface: iface,
                config_value,
            })
        }
    }
}

/// DCI encoding per xHCI §4.8.1:
/// `(endpoint_number * 2) + (1 if IN else 0)`.
fn ep_dci(ep_addr: u8, is_in: bool) -> u8 {
    let num = ep_addr & 0x0F;
    (num * 2) + u8::from(is_in)
}

// ── FingerprintDevice ─────────────────────────────────────────────────

/// One bound fingerprint reader. Held in [`FP_DEVICES`] so a userspace
/// daemon can drive vendor commands through `/dev/fp0`.
pub struct FingerprintDevice {
    pub slot_id: u8,
    pub vendor: FpVendor,
    /// DCI of bulk-IN (Synaptics/Goodix/Validity) or interrupt-IN (ELAN).
    pub bulk_in_ep: u8,
    /// DCI of bulk-OUT (Synaptics/Goodix/Validity). 0 for ELAN (no bulk-OUT).
    pub bulk_out_ep: u8,
    /// Max packet size of the primary IN endpoint.
    in_max_packet: u16,
    /// For interrupt-IN (ELAN): `true` after the first arm call.
    armed: AtomicBool,
}

impl core::fmt::Debug for FingerprintDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FingerprintDevice")
            .field("slot_id", &self.slot_id)
            .field("vendor", &self.vendor)
            .field("bulk_in_ep", &self.bulk_in_ep)
            .field("bulk_out_ep", &self.bulk_out_ep)
            .finish_non_exhaustive()
    }
}

impl FingerprintDevice {
    /// Vendor family this device belongs to.
    pub fn vendor(&self) -> FpVendor {
        self.vendor
    }

    /// Whether the ELAN interrupt-IN endpoint is currently armed.
    /// Test/diagnostic accessor for the resume path.
    pub fn is_armed(&self) -> bool {
        self.armed.load(Ordering::Acquire)
    }

    /// Read one response packet from the device (bulk-IN or
    /// interrupt-IN). Returns the byte count written into `buf`.
    ///
    /// For ELAN (interrupt-IN) this arms the endpoint on the first
    /// call and thereafter polls it. For Goodix / Synaptics /
    /// Validity (bulk-IN) it issues a bulk transfer directly.
    ///
    /// Caller must hold an `Arc<Xhci>` — call from async context or
    /// via `narf_scheduler::block_on`.
    pub async fn read_response(&self, xhci: &Xhci, buf: &mut [u8]) -> Result<usize, FpError> {
        match self.vendor {
            FpVendor::Elan => {
                // Arm interrupt-IN once, then poll. `poll_interrupt_in`
                // stages the next TRB after every completed transfer, so
                // keep exactly one TRB outstanding for this endpoint's
                // persistent DMA buffer.
                if !self.armed.swap(true, Ordering::AcqRel) {
                    xhci.arm_interrupt_in(
                        self.slot_id,
                        self.bulk_in_ep,
                        self.in_max_packet.min(64) as u32,
                    )
                    .map_err(|_| FpError::EndpointConfig)?;
                }
                let deadline = narf_time::Deadline::after_ms(500);
                loop {
                    match xhci.poll_interrupt_in(self.slot_id, self.bulk_in_ep, buf) {
                        Ok(Some(n)) => return Ok(n),
                        Ok(None) => {
                            if deadline.expired() {
                                return Ok(0);
                            }
                            narf_scheduler::yield_now().await;
                        }
                        Err(_) => return Err(FpError::EndpointConfig),
                    }
                }
            }
            FpVendor::Synaptics | FpVendor::Goodix | FpVendor::Validity => xhci
                .bulk_in(self.slot_id, self.bulk_in_ep, buf)
                .await
                .map_err(|_| FpError::EndpointConfig),
        }
    }

    /// Send a vendor command to the device (bulk-OUT).
    ///
    /// Not applicable to ELAN (interrupt-IN only). Returns an error
    /// if called on an ELAN device that has no bulk-OUT endpoint.
    pub async fn send_command(&self, xhci: &Xhci, cmd: &[u8]) -> Result<(), FpError> {
        if self.bulk_out_ep == 0 {
            return Err(FpError::EndpointsMissing);
        }
        let transferred = xhci
            .bulk_out(self.slot_id, self.bulk_out_ep, cmd)
            .await
            .map_err(|_| FpError::EndpointConfig)?;
        require_full_transfer(transferred, cmd.len())
    }
}

fn require_full_transfer(transferred: usize, expected: usize) -> Result<(), FpError> {
    if transferred == expected {
        Ok(())
    } else {
        Err(FpError::EndpointConfig)
    }
}

// ── Global registry ───────────────────────────────────────────────────

/// Global registry of bound fingerprint readers. Append-only for now;
/// detach / hotplug is a follow-up.
pub static FP_DEVICES: IrqSafeSpinLock<Vec<Arc<FingerprintDevice>>> =
    IrqSafeSpinLock::new(Vec::new());

/// Number of bound fingerprint readers.
pub fn attached_fp_count() -> usize {
    FP_DEVICES.lock().len()
}

/// Return a clone of the Arc for device at `idx`, if present.
pub fn with_device<R>(idx: usize, f: impl FnOnce(&FingerprintDevice) -> R) -> Option<R> {
    let g = FP_DEVICES.lock();
    g.get(idx).map(|d| f(d))
}

#[doc(hidden)]
pub fn __reset_fp_for_test() {
    FP_DEVICES.lock().clear();
}

/// Test-only: construct a bound-reader record and push it into
/// [`FP_DEVICES`], returning its registry index. The record carries
/// no xHCI state; smokes drive the node through a fake transport
/// (see `__test_fp_node`). Callers must pair this with
/// `__reset_fp_for_test` — the registry is process-global and a
/// leftover entry breaks the no-reader-on-QEMU smoke.
#[doc(hidden)]
pub fn __test_register_device(
    slot_id: u8,
    vendor: FpVendor,
    bulk_in_ep: u8,
    bulk_out_ep: u8,
) -> usize {
    let dev = Arc::new(FingerprintDevice {
        slot_id,
        vendor,
        bulk_in_ep,
        bulk_out_ep,
        in_max_packet: 64,
        armed: AtomicBool::new(false),
    });
    let mut g = FP_DEVICES.lock();
    g.push(dev);
    g.len() - 1
}

// ── Lifecycle: detach + suspend/resume (#922) ────────────────────────

/// Outcome of [`detach_fp`]: how many registry entries were removed
/// for the slot, and whether the `/dev/fp0` node was unregistered.
/// The node decision is part of the outcome (not just a side
/// effect) so fixtures pin it: the node belongs to the entry that
/// was at registry index 0 when it bound — bind only appends, so
/// the owner can only leave index 0 by being removed, and a
/// non-owner at index 0 can only exist once the node is already
/// gone. Unregistering on "a removed entry was at index 0" is
/// therefore exact, and a no-op when the node is already `None`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FpDetachOutcome {
    pub removed: usize,
    pub fp0_unregistered: bool,
}

/// Detach bookkeeping for one slot: remove every registry entry
/// for `slot_id` and unregister `/dev/fp0` if the removed set
/// included the node owner (pre-removal index 0). Infallible and
/// idempotent: a second call for the same slot removes nothing
/// and unregisters nothing.
///
/// No promotion: a surviving reader is NOT promoted to `/dev/fp0`
/// — the node's identity is per-slot (`ino = 0xf90000 | slot+1`),
/// so rebinding the name to a different physical device would lie
/// to a daemon holding fp0. Per-device nodes are #920's surface
/// (draft PR #1238); until that lands, a surviving second reader
/// simply stays unpublished.
///
/// An already-open fp0 handle keeps its `Arc` to the detached
/// device, so its reads fail cleanly at the transfer layer
/// (`EndpointConfig` on the disabled slot) rather than dangling;
/// new opens fail via the devfs proxy's `None` node (`FsError::Io`).
pub fn detach_fp(slot_id: u8) -> FpDetachOutcome {
    let mut g = FP_DEVICES.lock();
    let mut removed = 0usize;
    let mut owned_node = false;
    let mut orig = 0usize;
    g.retain(|dev| {
        let cur = orig;
        orig += 1;
        if dev.slot_id == slot_id {
            if cur == 0 {
                owned_node = true;
            }
            removed += 1;
            false
        } else {
            true
        }
    });
    drop(g);
    let fp0_unregistered = if owned_node {
        narf_filesystem::devfs::unregister_fp();
        true
    } else {
        false
    };
    FpDetachOutcome {
        removed,
        fp0_unregistered,
    }
}

/// Controller-recovery teardown: drop every bound reader and
/// unregister `/dev/fp0`. Called from `attach::detach_all_bindings`
/// after a recovery epoch change invalidated every slot; stale
/// entries must not survive to be re-enumerated alongside fresh
/// binds (the MSC Concern C species: a surviving entry would make
/// re-enumeration append a second live device for the same reader).
pub fn unbind_all_fp() {
    FP_DEVICES.lock().clear();
    narf_filesystem::devfs::unregister_fp();
}

/// Reset the ELAN interrupt-IN arming flag on every bound device.
/// The controller fan-out rebuilds xHCI endpoint state on resume,
/// invalidating the staged interrupt-IN TRB; the next read must
/// re-arm rather than poll a dead staging. Bulk devices carry no
/// equivalent volatile state.
pub fn reset_all_armed() {
    let g = FP_DEVICES.lock();
    for dev in g.iter() {
        dev.armed.store(false, Ordering::Release);
    }
}

/// Resume decision for the system-PM hook, factored out of the
/// async wrapper so fixtures pin it without an xHCI controller.
/// With no controller and bound devices, fail loudly (ACM mirror
/// — the suspend service records the failure best-effort and it
/// does not stop other hooks); with no bound devices, or a live
/// controller, resume proceeds, and the live-controller path
/// resets ELAN arming (see [`reset_all_armed`]).
///
/// A device unplugged while suspended is NOT validated here — it
/// is still in the registry at resume time (the supervisor was not
/// polling during suspend), and resetting its flag is harmless;
/// the supervisor's disconnect polling detaches it on the next
/// cycle, mirroring the serial hook's "absent gets no replay".
pub fn resume_fp_devices(
    controller_present: bool,
) -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    if !controller_present && attached_fp_count() > 0 {
        return Err(narf_power::device_pm::DeviceSuspendError::DriverError);
    }
    if controller_present {
        reset_all_armed();
    }
    Ok(())
}

/// Async system-PM hook for fingerprint (#922). Prepare has
/// nothing to quiesce — no pump, no background task, transfers
/// are synchronous per-call — so it always succeeds. Resume runs
/// [`resume_fp_devices`] after the synchronous device fan-out
/// restores xHCI.
struct FpSystemPm;

impl narf_power::system_pm::AsyncSystemPm for FpSystemPm {
    fn prepare_suspend<'a>(&'a self) -> narf_power::system_pm::SystemPmFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn resume_from_suspend<'a>(&'a self) -> narf_power::system_pm::SystemPmFuture<'a> {
        Box::pin(async { resume_fp_devices(crate::xhci::controller().is_some()) })
    }
}

/// Register the async system-PM hook. Called once from the USB
/// crate's Stage::Subsys initcalls; registration is idempotent
/// on the hook name.
pub fn register_pm() {
    narf_power::system_pm::register_async_system_pm("usb-fp", alloc::sync::Arc::new(FpSystemPm));
}

/// Registry probe that never claims: fingerprint binds through
/// the attach cascade, never the class-registry probe — this
/// entry exists so the registry's unbind dispatch (detach path)
/// can reach [`detach_fp`], mirroring MSC.
fn fp_registry_probe(
    _device: alloc::sync::Arc<crate::device::USBDevice>,
) -> Result<(), crate::class_registry::UsbProbeError> {
    Err(crate::class_registry::UsbProbeError::BindFailed)
}

/// Register fingerprint's unbind hook with the class registry.
/// Called from the crate's Stage::Subsys initcalls (`lib.rs`).
/// [`detach_fp`] is infallible bookkeeping, so the hook adapts
/// it to the fallible [`UsbUnbindFn`] contract with an
/// unconditional `Ok(())` (#893: a hook reports failure with
/// `Err(())`, never by panicking). The matches slice is empty
/// on purpose: the probe must never fire (the cascade binds
/// fingerprint), so the entry is hook-only.
pub fn register_initcalls() {
    let _ = crate::class_registry::register_class_driver_with_unbind(
        "usb-fp",
        &[],
        fp_registry_probe,
        |slot| {
            detach_fp(slot);
            Ok(())
        },
    );
}

/// Test/seeding constructor: one bound-reader record without an
/// xHCI controller. Kernel-test smokes seed the registry with
/// it, then exercise [`detach_fp`] / [`resume_fp_devices`].
/// Not a bind path — endpoint configuration is the cascade's job.
#[cfg(feature = "kernel-test")]
#[doc(hidden)]
pub fn __test_make_device(slot_id: u8, vendor: FpVendor, armed: bool) -> Arc<FingerprintDevice> {
    Arc::new(FingerprintDevice {
        slot_id,
        vendor,
        bulk_in_ep: 3,
        bulk_out_ep: 2,
        in_max_packet: 512,
        armed: AtomicBool::new(armed),
    })
}

/// Test/seeding push: append a record to the registry directly.
/// Kernel-test smokes seed with [`__test_make_device`], then
/// exercise the lifecycle paths.
#[cfg(feature = "kernel-test")]
#[doc(hidden)]
pub fn __test_push(dev: Arc<FingerprintDevice>) {
    FP_DEVICES.lock().push(dev);
}

// ── /dev/fp0 FileOps bridge ───────────────────────────────────────────

/// Test-only: build a `/dev/fp<N>` node for `dev` over an explicit
/// transport, so smokes can drive the ioctl surface without silicon
/// (production nodes come from `lookup_fp` with `XhciFpTransport`).
#[doc(hidden)]
pub fn __test_fp_node(
    dev: Arc<FingerprintDevice>,
    transport: Arc<dyn FpTransport>,
) -> Arc<dyn narf_filesystem::FileOps> {
    Arc::new(FpFileNode { dev, transport })
}

// ── Control-transfer transport seam ───────────────────────────────────

/// The control-transfer operations the `/dev/fp<N>` ioctl surface
/// needs from a bound reader. Production implements it over the
/// global xHCI controller; fixtures implement it with a modelled
/// device so the published surface is exercised without silicon
/// (the CCID bridge's `CcidTransport` seam, same shape).
pub trait FpTransport: Send + Sync {
    /// EP0 control-IN transfer (device-to-host). `out` length must
    /// equal the requested `w_length`; returns bytes actually read.
    fn control_in<'a>(
        &'a self,
        slot_id: u8,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        out: &'a mut [u8],
    ) -> FpFuture<'a, Result<usize, FpError>>;
    /// EP0 control-OUT transfer (host-to-device). Returns bytes
    /// actually written; a short transfer is an error at the call
    /// site, mirroring `send_command`'s full-transfer rule.
    fn control_out<'a>(
        &'a self,
        slot_id: u8,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        data: &'a [u8],
    ) -> FpFuture<'a, Result<usize, FpError>>;
}

/// Boxed future returned by [`FpTransport`] methods.
pub type FpFuture<'a, T> = core::pin::Pin<Box<dyn core::future::Future<Output = T> + Send + 'a>>;

/// Production transport: bound reader driven over `xhci::controller()`.
#[derive(Debug)]
struct XhciFpTransport;

impl FpTransport for XhciFpTransport {
    fn control_in<'a>(
        &'a self,
        slot_id: u8,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        out: &'a mut [u8],
    ) -> FpFuture<'a, Result<usize, FpError>> {
        Box::pin(async move {
            let xhci = crate::xhci::controller().ok_or(FpError::EndpointConfig)?;
            xhci.control_in(slot_id, bm_request_type, b_request, w_value, w_index, out)
                .await
                .map_err(|_| FpError::EndpointConfig)
        })
    }

    fn control_out<'a>(
        &'a self,
        slot_id: u8,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        data: &'a [u8],
    ) -> FpFuture<'a, Result<usize, FpError>> {
        Box::pin(async move {
            let xhci = crate::xhci::controller().ok_or(FpError::EndpointConfig)?;
            xhci.control_out(slot_id, bm_request_type, b_request, w_value, w_index, data)
                .await
                .map_err(|_| FpError::EndpointConfig)
        })
    }
}

// ── /dev/fp<N> ioctl surface ──────────────────────────────────────────

/// Linux capability number for raw hardware access
/// (`include/uapi/linux/capability.h`: `CAP_SYS_RAWIO` = 17,
/// "perform I/O port operations"). DESIGN CHOICE, not a spec claim:
/// no Linux capability names fingerprint sensors; the raw sensor
/// command channel — arbitrary vendor commands plus biometric image
/// reads — is raw-hardware access, so it takes the raw-hardware
/// capability rather than the catch-all `CAP_SYS_ADMIN` the PTY
/// bridge uses for terminal administration.
const CAP_SYS_RAWIO: u32 = 17;

/// NARF-local ioctls, Linux `_IOC` encoding, type 'P' (0x50).
/// 'C' is the CCID bridge's type and 'F' the ALSA helper's; 'P'
/// collides with no in-tree ioctl family.
const fn fp_ioc(nr: u32) -> u32 {
    (0x50 << 8) | nr
}

/// EP0 vendor control transfer (see `FP_CTRL_ARG` layout below).
/// Direction comes from `bm_request_type` bit 7. Returns the actual
/// byte count; for IN transfers the count is also written back
/// into the argument's `data_len` field.
pub const FP_IOC_CTRL_TRANSFER: u32 = fp_ioc(0);

/// Identify the reader behind this node. Returns a packed `u64`:
/// bits 0..8 slot id, bits 8..16 vendor code (Synaptics = 0,
/// Goodix = 1, ELAN = 2, in `FpVendor` declaration order),
/// bits 16..24 bulk/interrupt-IN DCI, bits 24..32 bulk-OUT DCI
/// (0 for ELAN). A daemon enumerating `/dev/fp<N>` nodes uses this
/// to tell readers apart; the kernel does not store VID/PID on the
/// device record, so those are not reported.
pub const FP_IOC_GET_INFO: u32 = fp_ioc(1);

/// Wire layout of the `FP_IOC_CTRL_TRANSFER` argument (24 bytes,
/// little-endian, read through the ioctl context — never
/// transmuted):
/// `[0]` bm_request_type, `[1]` b_request, `[2..4]` w_value,
/// `[4..6]` w_index, `[6..8]` reserved (ignored),
/// `[8..12]` data_len (in: requested length; out: actual length),
/// `[12..16]` reserved (ignored), `[16..24]` data_ptr (userspace
/// buffer holding `data_len` bytes on entry for OUT, receiving the
/// response for IN).
const FP_CTRL_ARG_LEN: usize = 24;

/// xHCI control data-stage cap: `control_in` / `control_out`
/// reject longer buffers (`CmdFailed(0xF9)`), so the ioctl rejects
/// longer requests up front with `InvalidData` instead of issuing
/// a transfer the controller would refuse.
const FP_CTRL_MAX_LEN: u32 = 4096;

// ── /dev/fp<N> FileOps bridge ─────────────────────────────────────────

/// `FileOps` bridge for one `/dev/fp<N>` node. Reads map to
/// `read_response` (one bulk-IN or interrupt-IN packet), writes map
/// to `send_command` (one bulk-OUT packet). Offset is unused — the
/// endpoint is a stream, not a seekable file. Control transfers go
/// through `ioctl_user` (async: they await USB transfers, so the
/// synchronous `ioctl` keeps the trait default `Unsupported`,
/// exactly like the CCID bridge).
struct FpFileNode {
    dev: Arc<FingerprintDevice>,
    transport: Arc<dyn FpTransport>,
}

impl core::fmt::Debug for FpFileNode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FpFileNode")
            .field("slot_id", &self.dev.slot_id)
            .finish_non_exhaustive()
    }
}

impl narf_filesystem::FileOps for FpFileNode {
    // LINUX-GAP: NARF-specific node (Linux has no fingerprint char device;
    // libfprint drives the USB device directly), so there is no Linux inode
    // scheme to follow. A stable nonzero number per reader slot.
    fn ino(&self) -> u64 {
        0xf9_0000 | (u64::from(self.dev.slot_id) + 1)
    }

    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> narf_filesystem::FsFuture<'a, usize> {
        let dev = self.dev.clone();
        Box::pin(async move {
            let xhci = crate::xhci::controller().ok_or(narf_filesystem::FsError::Io(
                narf_block::BlockError::IOError,
            ))?;
            dev.read_response(&xhci, buf)
                .await
                .map_err(|_| narf_filesystem::FsError::Io(narf_block::BlockError::IOError))
        })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> narf_filesystem::FsFuture<'a, usize> {
        let dev = self.dev.clone();
        let len = buf.len();
        // Clone buf into an owned Vec so the future can be 'static.
        let owned: alloc::vec::Vec<u8> = buf.to_vec();
        Box::pin(async move {
            let xhci = crate::xhci::controller().ok_or(narf_filesystem::FsError::Io(
                narf_block::BlockError::IOError,
            ))?;
            dev.send_command(&xhci, &owned)
                .await
                .map(|()| len)
                .map_err(|_| narf_filesystem::FsError::Io(narf_block::BlockError::IOError))
        })
    }

    fn stat(&self) -> narf_filesystem::Stat {
        narf_filesystem::Stat {
            size: 0,
            blocks: 0,
            mode: narf_filesystem::Mode {
                file_type: narf_filesystem::FileType::Special,
                perms: 0o660,
            },
            mtime_cycles: 0,
        }
    }

    /// Capability gate (audit §3: the scaffold's stated design is a
    /// "cap-gated syscall/ioctl surface", but the shipped bridge had
    /// no check — any opener could issue raw sensor commands).
    /// Runs after DAC checks in `sys_open`: the caller must hold
    /// `CAP_SYS_RAWIO`, for reads as well as writes, because reads
    /// return biometric images and writes issue sensor commands.
    /// Fail-closed: the hook answers false while userspace has not
    /// installed it, so an ungated open can never slip through.
    /// Returning `Ok(None)` keeps this node (no per-open clone
    /// state: the device record is shared, as before).
    fn open_instance_checked(
        &self,
        _write: bool,
    ) -> Result<Option<Arc<dyn narf_filesystem::FileOps>>, narf_filesystem::FsError> {
        if narf_filesystem::caller_capable(CAP_SYS_RAWIO) {
            Ok(None)
        } else {
            Err(narf_filesystem::FsError::PermissionDenied)
        }
    }

    /// Async ioctl surface: `FP_IOC_CTRL_TRANSFER` /
    /// `FP_IOC_GET_INFO` (constants above carry the contract).
    /// Validation order matters: the SETUP fields are checked
    /// before any transfer is issued, so a malformed request can
    /// never reach the device.
    fn ioctl_user<'a>(
        &'a self,
        cmd: u32,
        arg: u64,
        ctx: &'a dyn narf_filesystem::IoctlContext,
    ) -> narf_filesystem::FsFuture<'a, u64> {
        let dev = self.dev.clone();
        let transport = self.transport.clone();
        Box::pin(async move {
            match cmd {
                FP_IOC_GET_INFO => {
                    // Vendor codes follow FpVendor declaration order
                    // (Synaptics, Goodix, Elan, Validity); Validity
                    // arrived with main's single-authority rewrite
                    // after this match was written, so it takes the
                    // next code rather than colliding with Synaptics.
                    let vendor_code = match dev.vendor {
                        FpVendor::Synaptics => 0u64,
                        FpVendor::Goodix => 1u64,
                        FpVendor::Elan => 2u64,
                        FpVendor::Validity => 3u64,
                    };
                    Ok(u64::from(dev.slot_id)
                        | (vendor_code << 8)
                        | (u64::from(dev.bulk_in_ep) << 16)
                        | (u64::from(dev.bulk_out_ep) << 24))
                }
                FP_IOC_CTRL_TRANSFER => {
                    use narf_filesystem::FsError;
                    let mut raw = [0u8; FP_CTRL_ARG_LEN];
                    ctx.read(arg, &mut raw)?;
                    let bm_request_type = raw[0];
                    let b_request = raw[1];
                    let w_value = u16::from_le_bytes([raw[2], raw[3]]);
                    let w_index = u16::from_le_bytes([raw[4], raw[5]]);
                    let data_len = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
                    let data_ptr = u64::from_le_bytes([
                        raw[16], raw[17], raw[18], raw[19], raw[20], raw[21], raw[22], raw[23],
                    ]);
                    // Only EP0 VENDOR requests to the DEVICE are
                    // issuable here. Standard requests (including
                    // SET_CONFIGURATION / SET_INTERFACE, which the
                    // driver owns) and class/other-recipient
                    // requests are rejected before any transfer:
                    // the daemon must not reconfigure the device
                    // out from under the driver.
                    if bm_request_type & 0x60 != 0x40 || bm_request_type & 0x1F != 0x00 {
                        return Err(FsError::Unsupported);
                    }
                    if data_len > FP_CTRL_MAX_LEN {
                        return Err(FsError::InvalidData);
                    }
                    let fs_err = |_| FsError::Io(narf_block::BlockError::IOError);
                    if bm_request_type & 0x80 != 0 {
                        // IN: device-to-host. Short reads are normal
                        // (the device returns fewer bytes); the
                        // actual count goes back both as the return
                        // value and in the argument's data_len.
                        let mut buf = alloc::vec![0u8; data_len as usize];
                        let n = transport
                            .control_in(
                                dev.slot_id,
                                bm_request_type,
                                b_request,
                                w_value,
                                w_index,
                                &mut buf,
                            )
                            .await
                            .map_err(fs_err)?;
                        // A zero-length transfer has no data stage, so
                        // the data pointer is never dereferenced (it
                        // may be null for a length-0 request).
                        if n > 0 {
                            ctx.write(data_ptr, &buf[..n])?;
                        }
                        ctx.write(arg + 8, &(n as u32).to_le_bytes())?;
                        Ok(n as u64)
                    } else {
                        // OUT: host-to-device. A short transfer is
                        // an error, mirroring `send_command`'s
                        // full-transfer rule.
                        let mut data = alloc::vec![0u8; data_len as usize];
                        if !data.is_empty() {
                            ctx.read(data_ptr, &mut data)?;
                        }
                        let n = transport
                            .control_out(
                                dev.slot_id,
                                bm_request_type,
                                b_request,
                                w_value,
                                w_index,
                                &data,
                            )
                            .await
                            .map_err(fs_err)?;
                        if n != data.len() {
                            return Err(FsError::Io(narf_block::BlockError::IOError));
                        }
                        ctx.write(arg + 8, &(n as u32).to_le_bytes())?;
                        Ok(n as u64)
                    }
                }
                _ => Err(narf_filesystem::FsError::Unsupported),
            }
        })
    }
}

/// Parse a devfs leaf name into a fingerprint registry index:
/// exactly `fp<N>` with all-digit `N` (the CCID bridge's
/// `ccid<N>` parse, same shape). Anything else is not a
/// fingerprint node.
fn parse_fp_name(name: &str) -> Option<usize> {
    let digits = name.strip_prefix("fp")?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Devfs provider lookup: `/dev/fp<N>` resolves to the bound
/// reader at registry index `N`, or nothing when no such reader
/// is bound. Nodes are built on demand from the registry, so
/// every bound reader publishes — the first-only `/dev/fp0`
/// special case is gone (#920).
pub fn lookup_fp(name: &str) -> Option<Arc<dyn narf_filesystem::FileOps>> {
    let idx = parse_fp_name(name)?;
    let dev = FP_DEVICES.lock().get(idx)?.clone();
    Some(Arc::new(FpFileNode {
        dev,
        transport: Arc::new(XhciFpTransport),
    }) as Arc<dyn narf_filesystem::FileOps>)
}

/// Devfs provider enumeration: one `fp<N>` per bound reader, in
/// registry order. Agrees with `lookup_fp` by construction, so
/// readdir never advertises a phantom node.
pub fn enumerate_fp() -> Vec<(alloc::string::String, narf_filesystem::FileType)> {
    (0..FP_DEVICES.lock().len())
        .map(|i| {
            (
                alloc::format!("fp{}", i),
                narf_filesystem::FileType::Special,
            )
        })
        .collect()
}

// ── Bind entry point ──────────────────────────────────────────────────

/// Post-address fingerprint bind.
///
/// Caller has already driven: port_reset → enable_slot →
/// address_device. This function:
///
/// 1. Looks up `(vid, pid)` in the USB-ID table to determine vendor.
/// 2. Walks the configuration descriptor for matching endpoints.
/// 3. Calls `configure_endpoints` + `SET_CONFIGURATION`.
/// 4. Registers the device in [`FP_DEVICES`].
/// 5. Logs a single summary line.
///
/// Returns `Ok(())` on success. On failure the caller frees the slot.
pub async fn try_bind_fingerprint_already_addressed(
    xhci_dev: &Xhci,
    slot_id: u8,
    vid: u16,
    pid: u16,
    cfg: &[u8],
) -> Result<(), FpError> {
    let vendor = classify_vid_pid(vid, pid).ok_or(FpError::NotFingerprint)?;
    let eps = find_fp_endpoints(cfg, vendor)?;

    // Configure xHC endpoint contexts.
    let ep_configs: alloc::vec::Vec<EndpointConfig> = match eps {
        FpEndpoints::Bulk {
            bulk_in, bulk_out, ..
        } => alloc::vec![bulk_in, bulk_out],
        FpEndpoints::InterruptIn { intr_in, .. } => alloc::vec![intr_in],
    };
    xhci_dev
        .configure_endpoints(slot_id, &ep_configs)
        .await
        .map_err(|_| FpError::EndpointConfig)?;

    // SET_CONFIGURATION (USB 2.0 §9.4.7).
    let cfg_value = match eps {
        FpEndpoints::Bulk { config_value, .. } => config_value,
        FpEndpoints::InterruptIn { config_value, .. } => config_value,
    };
    xhci_dev
        .control_out(
            slot_id,
            0x00,
            STD_REQ_SET_CONFIGURATION,
            cfg_value as u16,
            0,
            &[],
        )
        .await
        .map_err(|_| FpError::SetConfiguration)?;

    // Build the FingerprintDevice record.
    let (bulk_in_dci, bulk_out_dci, in_max_packet) = match eps {
        FpEndpoints::Bulk {
            bulk_in, bulk_out, ..
        } => {
            let bi_dci = ep_dci(bulk_in.ep_addr, true);
            let bo_dci = ep_dci(bulk_out.ep_addr, false);
            (bi_dci, bo_dci, bulk_in.max_packet)
        }
        FpEndpoints::InterruptIn { intr_in, .. } => {
            let dci = ep_dci(intr_in.ep_addr, true);
            (dci, 0, intr_in.max_packet)
        }
    };

    {
        use core::fmt::Write as _;
        let vendor_str = match vendor {
            FpVendor::Synaptics => "Synaptics",
            FpVendor::Goodix => "Goodix",
            FpVendor::Elan => "ELAN",
            FpVendor::Validity => "Validity",
        };
        let _ = writeln!(
            narf_console::Writer,
            "  usb-fp: {} fingerprint reader slot={} vid={:04x}:{:04x} in_dci={} out_dci={}",
            vendor_str,
            slot_id,
            vid,
            pid,
            bulk_in_dci,
            bulk_out_dci
        );
    }

    let dev = Arc::new(FingerprintDevice {
        slot_id,
        vendor,
        bulk_in_ep: bulk_in_dci,
        bulk_out_ep: bulk_out_dci,
        in_max_packet,
        armed: AtomicBool::new(false),
    });

    // No per-device registration here: publication is via the
    // devfs provider registry (`lookup_fp` / `enumerate_fp`,
    // installed by the `usb-fp-devfs` initcall), which resolves
    // every bound reader as /dev/fp<N> by registry index. The
    // provider mechanism is the per-device lookup callback the old
    // first-only code was waiting on — it already existed for
    // ccid/ttyUSB, so the deferred scheme is just fp joining it.
    FP_DEVICES.lock().push(dev);
    Ok(())
}

// ── Unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── USB-ID table match ─────────────────────────────────────────

    #[test]
    fn classify_vid_pid_synaptics() {
        assert_eq!(classify_vid_pid(0x06CB, 0x00BD), Some(FpVendor::Synaptics));
        assert_eq!(classify_vid_pid(0x06CB, 0x00FF), Some(FpVendor::Synaptics));
        // Scaffold-only entry (was never in the old live table).
        assert_eq!(classify_vid_pid(0x06CB, 0x00BE), Some(FpVendor::Synaptics));
    }

    #[test]
    fn classify_vid_pid_goodix() {
        assert_eq!(classify_vid_pid(0x27C6, 0x5110), Some(FpVendor::Goodix));
        assert_eq!(classify_vid_pid(0x27C6, 0x55B4), Some(FpVendor::Goodix));
        assert_eq!(classify_vid_pid(0x27C6, 0x6594), Some(FpVendor::Goodix));
        // Scaffold-only entry (was never in the old live table).
        assert_eq!(classify_vid_pid(0x27C6, 0x609C), Some(FpVendor::Goodix));
    }

    #[test]
    fn classify_vid_pid_elan() {
        assert_eq!(classify_vid_pid(0x04F3, 0x0903), Some(FpVendor::Elan));
        assert_eq!(classify_vid_pid(0x04F3, 0x0C03), Some(FpVendor::Elan));
        // Scaffold-only entry (was never in the old live table).
        assert_eq!(classify_vid_pid(0x04F3, 0x0C42), Some(FpVendor::Elan));
    }

    #[test]
    fn classify_vid_pid_validity() {
        // #918: the whole Validity family was absent from the old
        // live table, so these fell through the cascade to
        // UnknownClass. They now classify.
        assert_eq!(classify_vid_pid(0x138A, 0x0007), Some(FpVendor::Validity));
        assert_eq!(classify_vid_pid(0x138A, 0x0011), Some(FpVendor::Validity));
        assert_eq!(classify_vid_pid(0x138A, 0x0090), Some(FpVendor::Validity));
        assert_eq!(classify_vid_pid(0x138A, 0x0091), Some(FpVendor::Validity));
        assert_eq!(classify_vid_pid(0x138A, 0x0097), Some(FpVendor::Validity));
        assert_eq!(classify_vid_pid(0x138A, 0x00A2), Some(FpVendor::Validity));
        // Validity VID but wrong PID still falls through.
        assert_eq!(classify_vid_pid(0x138A, 0x0001), None);
    }

    #[test]
    fn classify_vid_pid_unknown() {
        assert_eq!(classify_vid_pid(0x1234, 0x5678), None);
        // Synaptics VID but wrong PID.
        assert_eq!(classify_vid_pid(0x06CB, 0x0001), None);
    }

    // ── Vendor classifier ──────────────────────────────────────────
    //
    // These lists are the full #918 union per transport vendor:
    // Synaptics = Prometheus + MIS-older + live carryover,
    // Goodix = scaffold + live carryover, ELAN = scaffold + live
    // carryover, Validity = scaffold only.

    #[test]
    fn vendor_covers_all_synaptics_pids() {
        let synaptics_pids = [
            0x00BD, 0x00BE, 0x00BF, 0x00C2, 0x00C9, 0x00A2, 0x00B7, 0x00C6, 0x00DC, 0x00FF,
        ];
        for pid in synaptics_pids {
            assert_eq!(
                classify_vid_pid(0x06CB, pid),
                Some(FpVendor::Synaptics),
                "Synaptics PID 0x{pid:04x} not in table"
            );
        }
    }

    #[test]
    fn vendor_covers_all_goodix_pids() {
        let goodix_pids = [
            0x5110, 0x5117, 0x530C, 0x533C, 0x5395, 0x55B4, 0x6594, 0x609C, 0x6584,
        ];
        for pid in goodix_pids {
            assert_eq!(
                classify_vid_pid(0x27C6, pid),
                Some(FpVendor::Goodix),
                "Goodix PID 0x{pid:04x} not in table"
            );
        }
    }

    #[test]
    fn vendor_covers_all_elan_pids() {
        let elan_pids = [0x0903, 0x0907, 0x0C00, 0x0C03, 0x0C32, 0x0C42];
        for pid in elan_pids {
            assert_eq!(
                classify_vid_pid(0x04F3, pid),
                Some(FpVendor::Elan),
                "ELAN PID 0x{pid:04x} not in table"
            );
        }
    }

    #[test]
    fn vendor_covers_all_validity_pids() {
        let validity_pids = [0x0007, 0x0011, 0x0090, 0x0091, 0x0097, 0x00A2];
        for pid in validity_pids {
            assert_eq!(
                classify_vid_pid(0x138A, pid),
                Some(FpVendor::Validity),
                "Validity PID 0x{pid:04x} not in table"
            );
        }
    }

    // ── Endpoint discovery on synthetic config blobs ──────────────

    fn make_cfg_bulk(interface_class: u8) -> alloc::vec::Vec<u8> {
        // Config (9) + Interface (9) + bulk-IN (7) + bulk-OUT (7) = 32.
        let mut v = alloc::vec![0u8; 32];
        // Config header
        v[0] = 9;
        v[1] = 0x02;
        v[2] = 32;
        v[3] = 0;
        v[4] = 1;
        v[5] = 1;
        // Interface: class = interface_class, iface# = 0
        v[9] = 9;
        v[10] = 0x04;
        v[11] = 0;
        v[12] = 0;
        v[13] = 2;
        v[14] = interface_class;
        v[15] = 0;
        v[16] = 0;
        // bulk-IN @ ep 0x81
        v[18] = 7;
        v[19] = 0x05;
        v[20] = 0x81;
        v[21] = 0x02;
        v[22] = 0x00;
        v[23] = 0x02; // wMaxPacketSize = 512
                      // bulk-OUT @ ep 0x01
        v[25] = 7;
        v[26] = 0x05;
        v[27] = 0x01;
        v[28] = 0x02;
        v[29] = 0x00;
        v[30] = 0x02;
        v
    }

    fn make_cfg_intr(interface_class: u8) -> alloc::vec::Vec<u8> {
        // Config (9) + Interface (9) + interrupt-IN (7) = 25.
        let mut v = alloc::vec![0u8; 25];
        v[0] = 9;
        v[1] = 0x02;
        v[2] = 25;
        v[3] = 0;
        v[4] = 1;
        v[5] = 1;
        v[9] = 9;
        v[10] = 0x04;
        v[11] = 0;
        v[12] = 0;
        v[13] = 1;
        v[14] = interface_class;
        // interrupt-IN @ ep 0x81 (bmAttributes=3)
        v[18] = 7;
        v[19] = 0x05;
        v[20] = 0x81;
        v[21] = 0x03;
        v[22] = 0x40;
        v[23] = 0x00; // wMaxPacketSize = 64
        v
    }

    #[test]
    fn endpoint_discovery_bulk_vendor_class() {
        let cfg = make_cfg_bulk(0xFF);
        let eps = find_fp_endpoints(&cfg, FpVendor::Goodix).expect("should find bulk pair");
        match eps {
            FpEndpoints::Bulk {
                bulk_in,
                bulk_out,
                interface,
                ..
            } => {
                assert_eq!(bulk_in.ep_addr, 0x81);
                assert_eq!(bulk_in.kind, EndpointKind::BulkIn);
                assert_eq!(bulk_out.ep_addr, 0x01);
                assert_eq!(bulk_out.kind, EndpointKind::BulkOut);
                assert_eq!(interface, 0);
            }
            _ => panic!("expected Bulk endpoints"),
        }
    }

    #[test]
    fn endpoint_discovery_intr_elan() {
        let cfg = make_cfg_intr(0xFF);
        let eps = find_fp_endpoints(&cfg, FpVendor::Elan).expect("should find intr-IN");
        match eps {
            FpEndpoints::InterruptIn {
                intr_in, interface, ..
            } => {
                assert_eq!(intr_in.ep_addr, 0x81);
                assert_eq!(intr_in.kind, EndpointKind::InterruptIn);
                assert_eq!(intr_in.max_packet, 64);
                assert_eq!(interface, 0);
            }
            _ => panic!("expected InterruptIn endpoints"),
        }
    }

    #[test]
    fn endpoint_discovery_bulk_validity() {
        // #918: a Validity reader (VFS5011-class blob: vendor
        // class + bulk pair) resolves to the bulk arm, the same
        // transport Synaptics/Goodix use.
        let cfg = make_cfg_bulk(0xFF);
        let eps = find_fp_endpoints(&cfg, FpVendor::Validity).expect("should find bulk pair");
        match eps {
            FpEndpoints::Bulk {
                bulk_in,
                bulk_out,
                interface,
                ..
            } => {
                assert_eq!(bulk_in.ep_addr, 0x81);
                assert_eq!(bulk_in.kind, EndpointKind::BulkIn);
                assert_eq!(bulk_out.ep_addr, 0x01);
                assert_eq!(bulk_out.kind, EndpointKind::BulkOut);
                assert_eq!(interface, 0);
            }
            _ => panic!("expected Bulk endpoints for Validity"),
        }
    }

    #[test]
    fn endpoint_discovery_validity_without_bulk_pair_fails() {
        // Masking defeat: the bulk mapping must not hallucinate
        // endpoints. A Validity device exposing only interrupt-IN
        // fails discovery (the cascade then falls through, exactly
        // as an unclassifiable device does) instead of binding
        // with a bogus bulk pair.
        let cfg = make_cfg_intr(0xFF);
        assert!(matches!(
            find_fp_endpoints(&cfg, FpVendor::Validity),
            Err(FpError::EndpointsMissing)
        ));
    }

    #[test]
    fn endpoint_discovery_no_vendor_iface() {
        // HID class (0x03) interface — should not match.
        let cfg = make_cfg_bulk(0x03);
        assert!(matches!(
            find_fp_endpoints(&cfg, FpVendor::Synaptics),
            Err(FpError::EndpointsMissing)
        ));
    }

    #[test]
    fn endpoint_discovery_missing_bulk_out() {
        // Config with vendor class but only an interrupt-IN endpoint.
        let cfg = make_cfg_intr(0xFF);
        // Asking for Synaptics (which needs bulk) should fail.
        assert!(matches!(
            find_fp_endpoints(&cfg, FpVendor::Synaptics),
            Err(FpError::EndpointsMissing)
        ));
    }

    #[test]
    fn command_write_requires_the_full_transfer() {
        assert_eq!(require_full_transfer(64, 64), Ok(()));
        assert_eq!(require_full_transfer(63, 64), Err(FpError::EndpointConfig));
    }

    // ── Endpoint-discovery masking defeats ────────────────────
    // The walk clears endpoints accumulated for a prior interface
    // when a new matching interface appears; these cases pin that
    // the resolved pair always belongs to the LAST matching
    // interface, never to an earlier HID or vendor interface.

    fn make_cfg_composite() -> alloc::vec::Vec<u8> {
        // Config (9) + HID iface (9) + intr endpoint (7)
        // + vendor iface (9) + bulk-IN (7) + bulk-OUT (7) = 48.
        let mut v = alloc::vec![0u8; 48];
        v[0] = 9;
        v[1] = 0x02;
        v[2] = 48;
        v[4] = 2;
        v[5] = 1;
        // HID iface 0, class 0x03, with an interrupt-IN endpoint.
        v[9] = 9;
        v[10] = 0x04;
        v[11] = 0;
        v[13] = 1;
        v[14] = 0x03;
        v[18] = 7;
        v[19] = 0x05;
        v[20] = 0x82;
        v[21] = 0x03;
        v[22] = 0x40;
        v[23] = 0x00;
        // Vendor iface 1, class 0xFF, bulk pair 0x81 / 0x02.
        v[25] = 9;
        v[26] = 0x04;
        v[27] = 1;
        v[29] = 2;
        v[30] = 0xFF;
        v[34] = 7;
        v[35] = 0x05;
        v[36] = 0x81;
        v[37] = 0x02;
        v[38] = 0x00;
        v[39] = 0x02;
        v[41] = 7;
        v[42] = 0x05;
        v[43] = 0x02;
        v[44] = 0x02;
        v[45] = 0x00;
        v[46] = 0x02;
        v
    }

    fn make_cfg_two_vendor_ifaces() -> alloc::vec::Vec<u8> {
        // Config (9) + vendor iface 0 (9) + bulk pair (14)
        // + vendor iface 1 (9) + bulk pair (14) = 55.
        let mut v = alloc::vec![0u8; 55];
        v[0] = 9;
        v[1] = 0x02;
        v[2] = 55;
        v[4] = 2;
        v[5] = 1;
        // Vendor iface 0, bulk 0x81 / 0x01.
        v[9] = 9;
        v[10] = 0x04;
        v[11] = 0;
        v[13] = 2;
        v[14] = 0xFF;
        v[18] = 7;
        v[19] = 0x05;
        v[20] = 0x81;
        v[21] = 0x02;
        v[22] = 0x00;
        v[23] = 0x02;
        v[25] = 7;
        v[26] = 0x05;
        v[27] = 0x01;
        v[28] = 0x02;
        v[29] = 0x00;
        v[30] = 0x02;
        // Vendor iface 1, bulk 0x83 / 0x03.
        v[32] = 9;
        v[33] = 0x04;
        v[34] = 1;
        v[36] = 2;
        v[37] = 0xFF;
        v[41] = 7;
        v[42] = 0x05;
        v[43] = 0x83;
        v[44] = 0x02;
        v[45] = 0x00;
        v[46] = 0x02;
        v[48] = 7;
        v[49] = 0x05;
        v[50] = 0x03;
        v[51] = 0x02;
        v[52] = 0x00;
        v[53] = 0x02;
        v
    }

    #[test]
    fn endpoint_discovery_hid_first_then_vendor() {
        // The HID interface's interrupt endpoint must not leak
        // into the vendor interface's resolution.
        let cfg = make_cfg_composite();
        let eps = find_fp_endpoints(&cfg, FpVendor::Goodix).expect("vendor pair");
        match eps {
            FpEndpoints::Bulk {
                bulk_in, bulk_out, ..
            } => {
                assert_eq!(bulk_in.ep_addr, 0x81);
                assert_eq!(bulk_out.ep_addr, 0x02);
            }
            _ => panic!("expected Bulk endpoints"),
        }
        // ELAN on the same blob: the HID interrupt endpoint is on
        // a non-matching interface, so ELAN finds nothing.
        assert!(matches!(
            find_fp_endpoints(&cfg, FpVendor::Elan),
            Err(FpError::EndpointsMissing)
        ));
    }

    #[test]
    fn endpoint_discovery_second_vendor_iface_wins() {
        // The second matching interface clears the first pair.
        let cfg = make_cfg_two_vendor_ifaces();
        let eps = find_fp_endpoints(&cfg, FpVendor::Goodix).expect("vendor pair");
        match eps {
            FpEndpoints::Bulk {
                bulk_in,
                bulk_out,
                interface,
                ..
            } => {
                assert_eq!(bulk_in.ep_addr, 0x83);
                assert_eq!(bulk_out.ep_addr, 0x03);
                // Interface number stays the first matching one;
                // only the endpoints reset.
                assert_eq!(interface, 0);
            }
            _ => panic!("expected Bulk endpoints"),
        }
    }

    #[test]
    fn endpoint_discovery_second_iface_intr_only_fails_bulk() {
        // Vendor iface 0 (bulk pair) then vendor iface 1
        // (interrupt-IN only): the clear discards pair A, and
        // Synaptics still needs bulk, so this must fail — not
        // silently resolve pair A.
        let mut cfg = make_cfg_bulk(0xFF);
        // Append a second vendor interface with only interrupt-IN.
        cfg.extend_from_slice(&[
            9, 0x04, 1, 0, 1, 0xFF, 0, 0, 0, // iface 1, vendor
            7, 0x05, 0x81, 0x03, 0x40, 0x00, 0, // intr-IN
        ]);
        assert!(matches!(
            find_fp_endpoints(&cfg, FpVendor::Synaptics),
            Err(FpError::EndpointsMissing)
        ));
        // ELAN on the same blob resolves the second iface's intr.
        let eps = find_fp_endpoints(&cfg, FpVendor::Elan).expect("intr");
        match eps {
            FpEndpoints::InterruptIn { intr_in, .. } => {
                assert_eq!(intr_in.ep_addr, 0x81);
            }
            _ => panic!("expected InterruptIn endpoints"),
        }
    }

    #[test]
    fn endpoint_discovery_elan_prefers_interrupt_over_bulk() {
        // One vendor iface carrying both a bulk pair and an
        // interrupt-IN endpoint: ELAN takes interrupt-IN.
        let mut cfg = make_cfg_bulk(0xFF);
        cfg.extend_from_slice(&[7, 0x05, 0x82, 0x03, 0x40, 0x00, 0]);
        let eps = find_fp_endpoints(&cfg, FpVendor::Elan).expect("intr");
        match eps {
            FpEndpoints::InterruptIn { intr_in, .. } => {
                assert_eq!(intr_in.ep_addr, 0x82);
                assert_eq!(intr_in.kind, EndpointKind::InterruptIn);
            }
            _ => panic!("expected InterruptIn endpoints"),
        }
    }

    #[test]
    fn endpoint_discovery_truncated_descriptor_no_panic() {
        // Endpoint descriptor header claims 7 bytes but only 3
        // remain: the walk breaks, it must not panic or over-read.
        let mut cfg = make_cfg_bulk(0xFF);
        cfg.truncate(28); // cuts inside the bulk-OUT descriptor
        assert!(matches!(
            find_fp_endpoints(&cfg, FpVendor::Goodix),
            Err(FpError::EndpointsMissing)
        ));
    }

    #[test]
    fn endpoint_discovery_rejects_non_config() {
        // First descriptor is not a Configuration descriptor.
        let mut cfg = make_cfg_bulk(0xFF);
        cfg[1] = 0x04;
        assert!(matches!(
            find_fp_endpoints(&cfg, FpVendor::Goodix),
            Err(FpError::NotFingerprint)
        ));
        // Shorter than a config header.
        assert!(matches!(
            find_fp_endpoints(&[9, 0x02], FpVendor::Goodix),
            Err(FpError::NotFingerprint)
        ));
    }

    // ── DCI encoding pins (xHCI §4.8.1) ──────────────────────

    #[test]
    fn dci_encoding_pins() {
        assert_eq!(ep_dci(0x81, true), 3);
        assert_eq!(ep_dci(0x01, false), 2);
        assert_eq!(ep_dci(0x02, false), 4);
        assert_eq!(ep_dci(0x8F, true), 31);
        assert_eq!(ep_dci(0x0F, false), 30);
    }

    // ── FpFileNode pure surface ───────────────────────────────
    // stat/ino need no controller; read/write without a bound
    // controller must fail closed (Io), never panic. Transfer
    // conversations themselves need a transport seam (PR #1238's
    // FpTransport) and are NOT simulated here — see the PR body.

    fn make_test_device(slot_id: u8) -> Arc<FingerprintDevice> {
        Arc::new(FingerprintDevice {
            slot_id,
            vendor: FpVendor::Goodix,
            bulk_in_ep: 3,
            bulk_out_ep: 2,
            in_max_packet: 512,
            armed: AtomicBool::new(false),
        })
    }

    #[test]
    fn fp_node_stat_and_ino() {
        use narf_filesystem::{FileType, Mode};
        let node = FpFileNode {
            dev: make_test_device(0),
        };
        let stat = node.stat();
        assert_eq!(
            stat.mode,
            Mode {
                file_type: FileType::Special,
                perms: 0o660,
            }
        );
        assert_eq!(node.ino(), 0xf9_0001);
        let node1 = FpFileNode {
            dev: make_test_device(1),
        };
        assert_eq!(node1.ino(), 0xf9_0002);
    }

    struct NoopWaker;
    impl core::task::Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
        fn wake_by_ref(self: &Arc<Self>) {}
    }

    #[test]
    fn fp_node_io_without_controller_fails_closed() {
        use core::task::{Context, Poll, Waker};
        // No host test binds a controller, so the global
        // controller() is None and both directions fail with Io.
        let node = FpFileNode {
            dev: make_test_device(0),
        };
        let waker = Waker::from(Arc::new(NoopWaker));
        let mut cx = Context::from_waker(&waker);
        let mut buf = [0u8; 64];
        let mut read_fut = node.read(0, &mut buf);
        assert!(matches!(
            read_fut.as_mut().poll(&mut cx),
            Poll::Ready(Err(narf_filesystem::FsError::Io(_)))
        ));
        let mut write_fut = node.write(0, b"cmd");
        assert!(matches!(
            write_fut.as_mut().poll(&mut cx),
            Poll::Ready(Err(narf_filesystem::FsError::Io(_)))
        ));
    }
}

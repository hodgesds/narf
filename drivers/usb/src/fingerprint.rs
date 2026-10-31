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
//! 2. Discover the bulk-IN + bulk-OUT endpoints (Synaptics, Goodix) or
//!    interrupt-IN endpoint (ELAN).
//! 3. Configure those endpoints on the xHC.
//! 4. Register a `/dev/fp0` character device in DevFs so a userspace
//!    daemon (fprintd) can open it and drive the vendor protocol.
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

/// Fingerprint reader vendor family.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FpVendor {
    /// Synaptics (formerly Validity Sensors). Bulk-IN + bulk-OUT.
    Synaptics,
    /// Goodix. Bulk-IN + bulk-OUT.
    Goodix,
    /// ELAN Microelectronics. Interrupt-IN only.
    Elan,
}

/// (VID, PID, vendor) table.
///
/// Sources:
///   - Synaptics: `libfprint/drivers/synaptics/synaptics.c` VID/PID list
///   - Goodix:    `libfprint/drivers/goodixmoc/goodix.c` VID/PID list
///   - ELAN:      `libfprint/drivers/elanmoc/elanmoc.c` VID/PID list
const USB_ID_TABLE: &[(u16, u16, FpVendor)] = &[
    // Synaptics / Validity
    (0x06CB, 0x00BD, FpVendor::Synaptics),
    (0x06CB, 0x00C2, FpVendor::Synaptics),
    (0x06CB, 0x00C6, FpVendor::Synaptics),
    (0x06CB, 0x00C9, FpVendor::Synaptics),
    (0x06CB, 0x00DC, FpVendor::Synaptics),
    (0x06CB, 0x00FF, FpVendor::Synaptics),
    // Goodix
    (0x27C6, 0x5110, FpVendor::Goodix),
    (0x27C6, 0x5117, FpVendor::Goodix),
    (0x27C6, 0x530C, FpVendor::Goodix),
    (0x27C6, 0x533C, FpVendor::Goodix),
    (0x27C6, 0x5395, FpVendor::Goodix),
    (0x27C6, 0x55B4, FpVendor::Goodix),
    (0x27C6, 0x6594, FpVendor::Goodix),
    // ELAN
    (0x04F3, 0x0903, FpVendor::Elan),
    (0x04F3, 0x0907, FpVendor::Elan),
    (0x04F3, 0x0C00, FpVendor::Elan),
    (0x04F3, 0x0C03, FpVendor::Elan),
];

/// Look up a (VID, PID) pair in the table. Returns the vendor on hit.
pub fn classify_vid_pid(vid: u16, pid: u16) -> Option<FpVendor> {
    USB_ID_TABLE
        .iter()
        .find(|&&(v, p, _)| v == vid && p == pid)
        .map(|&(_, _, vendor)| vendor)
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
/// Synaptics and Goodix use bulk-IN + bulk-OUT.
#[derive(Copy, Clone, Debug)]
pub enum FpEndpoints {
    /// bulk-IN / bulk-OUT pair (Synaptics, Goodix).
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
/// - Synaptics / Goodix: require bulk-IN + bulk-OUT.
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
        FpVendor::Synaptics | FpVendor::Goodix => {
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
    /// DCI of bulk-IN (Synaptics/Goodix) or interrupt-IN (ELAN).
    pub bulk_in_ep: u8,
    /// DCI of bulk-OUT (Synaptics/Goodix). 0 for ELAN (no bulk-OUT).
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
    /// call and thereafter polls it. For Goodix / Synaptics
    /// (bulk-IN) it issues a bulk transfer directly.
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
            FpVendor::Synaptics | FpVendor::Goodix => xhci
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
    narf_filesystem::devfs::unregister_fp();
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

/// `FileOps` bridge for `/dev/fp0`. Reads map to `read_response`
/// (one bulk-IN or interrupt-IN packet), writes map to
/// `send_command` (one bulk-OUT packet). Offset is unused — the
/// endpoint is a stream, not a seekable file.
struct FpFileNode {
    dev: Arc<FingerprintDevice>,
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

    // Register /dev/fp0 (first device only for now — a dynamic
    // naming scheme is deferred until devfs supports per-device
    // lookup callbacks).
    {
        let idx = FP_DEVICES.lock().len();
        if idx == 0 {
            let node: Arc<dyn narf_filesystem::FileOps> = Arc::new(FpFileNode { dev: dev.clone() });
            narf_filesystem::devfs::register_fp(node);
        }
    }

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
    }

    #[test]
    fn classify_vid_pid_goodix() {
        assert_eq!(classify_vid_pid(0x27C6, 0x5110), Some(FpVendor::Goodix));
        assert_eq!(classify_vid_pid(0x27C6, 0x55B4), Some(FpVendor::Goodix));
        assert_eq!(classify_vid_pid(0x27C6, 0x6594), Some(FpVendor::Goodix));
    }

    #[test]
    fn classify_vid_pid_elan() {
        assert_eq!(classify_vid_pid(0x04F3, 0x0903), Some(FpVendor::Elan));
        assert_eq!(classify_vid_pid(0x04F3, 0x0C03), Some(FpVendor::Elan));
    }

    #[test]
    fn classify_vid_pid_unknown() {
        assert_eq!(classify_vid_pid(0x1234, 0x5678), None);
        // Synaptics VID but wrong PID.
        assert_eq!(classify_vid_pid(0x06CB, 0x0001), None);
    }

    // ── Vendor classifier ──────────────────────────────────────────

    #[test]
    fn vendor_covers_all_synaptics_pids() {
        let synaptics_pids = [0x00BD, 0x00C2, 0x00C6, 0x00C9, 0x00DC, 0x00FF];
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
        let goodix_pids = [0x5110, 0x5117, 0x530C, 0x533C, 0x5395, 0x55B4, 0x6594];
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
        let elan_pids = [0x0903, 0x0907, 0x0C00, 0x0C03];
        for pid in elan_pids {
            assert_eq!(
                classify_vid_pid(0x04F3, pid),
                Some(FpVendor::Elan),
                "ELAN PID 0x{pid:04x} not in table"
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
}

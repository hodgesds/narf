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
                        });
                    }
                    (2, false) if bulk_out.is_none() => {
                        bulk_out = Some(EndpointConfig {
                            ep_addr,
                            max_packet: mps,
                            kind: EndpointKind::BulkOut,
                        });
                    }
                    (3, true) if intr_in.is_none() => {
                        intr_in = Some(EndpointConfig {
                            ep_addr,
                            max_packet: mps,
                            kind: EndpointKind::InterruptIn,
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
                // Arm interrupt-IN once, then busy-poll.
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
                        Ok(Some(n)) => {
                            // Re-arm for next call.
                            let _ = xhci.arm_interrupt_in(
                                self.slot_id,
                                self.bulk_in_ep,
                                self.in_max_packet.min(64) as u32,
                            );
                            return Ok(n);
                        }
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
            FpVendor::Synaptics | FpVendor::Goodix => {
                xhci.bulk_in(self.slot_id, self.bulk_in_ep, buf)
                    .await
                    .map_err(|_| FpError::EndpointConfig)
            }
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
        xhci.bulk_out(self.slot_id, self.bulk_out_ep, cmd)
            .await
            .map(|_| ())
            .map_err(|_| FpError::EndpointConfig)
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
    fn read<'a>(
        &'a self,
        _offset: u64,
        buf: &'a mut [u8],
    ) -> narf_filesystem::FsFuture<'a, usize> {
        let dev = self.dev.clone();
        Box::pin(async move {
            let xhci = crate::xhci::controller()
                .ok_or(narf_filesystem::FsError::Io(narf_block::BlockError::IOError))?;
            dev.read_response(&xhci, buf)
                .await
                .map_err(|_| narf_filesystem::FsError::Io(narf_block::BlockError::IOError))
        })
    }

    fn write<'a>(
        &'a self,
        _offset: u64,
        buf: &'a [u8],
    ) -> narf_filesystem::FsFuture<'a, usize> {
        let dev = self.dev.clone();
        let len = buf.len();
        // Clone buf into an owned Vec so the future can be 'static.
        let owned: alloc::vec::Vec<u8> = buf.to_vec();
        Box::pin(async move {
            let xhci = crate::xhci::controller()
                .ok_or(narf_filesystem::FsError::Io(narf_block::BlockError::IOError))?;
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
        FpEndpoints::Bulk { bulk_in, bulk_out, .. } => alloc::vec![bulk_in, bulk_out],
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
    let mut nothing = [0u8; 0];
    xhci_dev
        .control_in(
            slot_id,
            0x00,
            STD_REQ_SET_CONFIGURATION,
            cfg_value as u16,
            0,
            &mut nothing,
        )
        .await
        .map_err(|_| FpError::SetConfiguration)?;

    // Build the FingerprintDevice record.
    let (bulk_in_dci, bulk_out_dci, in_max_packet) = match eps {
        FpEndpoints::Bulk { bulk_in, bulk_out, .. } => {
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
            vendor_str, slot_id, vid, pid, bulk_in_dci, bulk_out_dci
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
            let node: Arc<dyn narf_filesystem::FileOps> =
                Arc::new(FpFileNode { dev: dev.clone() });
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
        let goodix_pids = [0x5110, 0x5117, 0x530C, 0x533C, 0x5395, 0x55B4];
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
        v[0] = 9; v[1] = 0x02; v[2] = 32; v[3] = 0; v[4] = 1; v[5] = 1;
        // Interface: class = interface_class, iface# = 0
        v[9] = 9; v[10] = 0x04; v[11] = 0; v[12] = 0; v[13] = 2;
        v[14] = interface_class; v[15] = 0; v[16] = 0;
        // bulk-IN @ ep 0x81
        v[18] = 7; v[19] = 0x05; v[20] = 0x81; v[21] = 0x02;
        v[22] = 0x00; v[23] = 0x02; // wMaxPacketSize = 512
        // bulk-OUT @ ep 0x01
        v[25] = 7; v[26] = 0x05; v[27] = 0x01; v[28] = 0x02;
        v[29] = 0x00; v[30] = 0x02;
        v
    }

    fn make_cfg_intr(interface_class: u8) -> alloc::vec::Vec<u8> {
        // Config (9) + Interface (9) + interrupt-IN (7) = 25.
        let mut v = alloc::vec![0u8; 25];
        v[0] = 9; v[1] = 0x02; v[2] = 25; v[3] = 0; v[4] = 1; v[5] = 1;
        v[9] = 9; v[10] = 0x04; v[11] = 0; v[12] = 0; v[13] = 1;
        v[14] = interface_class;
        // interrupt-IN @ ep 0x81 (bmAttributes=3)
        v[18] = 7; v[19] = 0x05; v[20] = 0x81; v[21] = 0x03;
        v[22] = 0x40; v[23] = 0x00; // wMaxPacketSize = 64
        v
    }

    #[test]
    fn endpoint_discovery_bulk_vendor_class() {
        let cfg = make_cfg_bulk(0xFF);
        let eps = find_fp_endpoints(&cfg, FpVendor::Goodix).expect("should find bulk pair");
        match eps {
            FpEndpoints::Bulk { bulk_in, bulk_out, interface, .. } => {
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
            FpEndpoints::InterruptIn { intr_in, interface, .. } => {
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
}

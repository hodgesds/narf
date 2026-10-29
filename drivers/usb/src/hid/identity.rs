//! USB HID evdev identity (issue #874).
//!
//! USB HID producers historically registered `DeviceCaps` with no
//! identity, so every USB keyboard/mouse/touchpad published as the
//! synthetic `narf-input` / `BUS_VIRTUAL` / VID:PID 0 device and
//! `/dev/input/by-id` + `by-path` could not name them. This module
//! derives real identity from the USB device descriptor, the product
//! string, and the bind-time topology, and applies it with
//! `DeviceCaps::set_identity` — the same call the I2C-HID, i8042,
//! and virtio-input producers already use.
//!
//! Design notes (load-bearing, do not silently change):
//!
//! - Best-effort, never bind-failing. Identity is publication, not
//!   function: if the device-descriptor fetch fails, the caller
//!   keeps today's synthetic caps and the bind proceeds. A failed
//!   identity fetch must never regress a working bind.
//! - Descriptor offsets are USB 2.0 §9.6.1: `idVendor` at 8..10,
//!   `idProduct` at 10..12, `bcdDevice` at 12..14, `iProduct` at
//!   14. `Xhci::get_device_descriptor` already guarantees a
//!   complete, validated 18-byte descriptor (see
//!   `drivers/usb/specification/spec.md` §3), so the parse below
//!   trusts the length and reads the offsets directly.
//! - Product-string fetch mirrors `cdc_ncm::fetch_mac_string`:
//!   LANGID from string-0, falling back to en-US (0x0409), then
//!   `GET_DESCRIPTOR(STRING)` for `iProduct`, UTF-16LE decoded.
//!   `iProduct == 0` or any fetch/decode failure falls back to
//!   the per-class name (`"USB HID Mouse"`, …) — never an empty
//!   name, so `by-id` synthesis always has a name component.
//! - `phys` is a NARF-local topology string, NOT a Linux PCI-path
//!   phys (no PCI path is available at bind time): `usb-{port}`
//!   on a root port, `usb-{hub}-{port}` downstream, where `hub`
//!   is the index into `attach::HUBS` at bind time. It is unique
//!   per attached device: two identical devices on different ports
//!   always get distinct phys, which is what `by-path` needs.
//! - `uniq` is always empty, mirroring the I2C-HID producers. The
//!   USB serial string (`iSerialNumber`) is a possible follow-up;
//!   it is not fetched here, so this module adds exactly two
//!   control transfers per bind (descriptor + product string).
//! - Deliberately NOT covered: the live boot-keyboard path
//!   (`hid::BootKeyboard`) feeds the shared input ring and owns no
//!   evdev node by design (see `hid/mod.rs::detach_boot_keyboard`),
//!   so there are no caps to identify there. The evdev-registering
//!   keyboard path (`keyboard::try_bind_keyboard_already_addressed`)
//!   IS wired, as are mouse, touchpad, and generic — even though
//!   the latter two are currently uncalled in production, so they
//!   publish identity correctly if/when they are wired up.
//! - No MT adoption: no USB MT publication exists. The USB
//!   touchpad is relative-mode (`REL_X`/`REL_Y` only);
//!   `MtEvdevState` is used only by the I2C-HID touch driver.
//!   Adopting it here would invent a touch producer that does not
//!   exist.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use narf_input::evdev::{bus, DeviceCaps, InputId};

use crate::xhci::enumerate::USB_DESC_TYPE_STRING;
use crate::xhci::{Xhci, USB_REQ_GET_DESCRIPTOR};

/// Bind-time USB topology for one HID device: the root-hub port plus
/// the hub context the dispatcher passes. Bundled so binders with
/// many parameters (notably the touchpad binder, which would
/// otherwise take 8 arguments against clippy's 7-argument limit)
/// take one topology argument instead of two.
#[derive(Copy, Clone, Debug)]
pub struct BindTopology {
    /// Root-hub port for root-attached devices; downstream port
    /// number for hub-attached ones.
    pub port: u8,
    /// `(index into attach::HUBS, downstream port)` for
    /// hub-attached devices, `None` on a root port.
    pub hub_port: Option<(usize, u8)>,
}

/// Resolved USB identity for one bound HID device: everything
/// `DeviceCaps::set_identity` needs, plus the fallback-aware name.
#[derive(Clone, Debug)]
pub struct UsbIdentity {
    /// `idVendor` from the device descriptor.
    pub vendor: u16,
    /// `idProduct` from the device descriptor.
    pub product: u16,
    /// `bcdDevice` from the device descriptor.
    pub version: u16,
    /// Product string when fetchable, else the per-class fallback.
    pub name: String,
    /// NARF-local topology string (`usb-{port}` / `usb-{hub}-{port}`).
    pub phys: String,
}

/// Parse a complete 18-byte device descriptor (USB 2.0 §9.6.1) into
/// `(idVendor, idProduct, bcdDevice, iProduct)`.
pub fn parse_device_descriptor(desc: &[u8; 18]) -> (u16, u16, u16, u8) {
    (
        u16::from_le_bytes([desc[8], desc[9]]),
        u16::from_le_bytes([desc[10], desc[11]]),
        u16::from_le_bytes([desc[12], desc[13]]),
        desc[14],
    )
}

/// Build the NARF-local phys string from the bind-time topology.
/// `port` is the root-hub port for root-attached devices and the
/// downstream port number for hub-attached ones; `hub_port` is the
/// `(index into attach::HUBS, downstream port)` pair the dispatcher
/// passes, `None` on a root port.
pub fn usb_phys(port: u8, hub_port: Option<(usize, u8)>) -> String {
    match hub_port {
        Some((hub_idx, hub_port_num)) => format!("usb-{hub_idx}-{hub_port_num}"),
        None => format!("usb-{port}"),
    }
}

/// Decode a USB string descriptor buffer (USB 2.0 §9.6.7) into a
/// `String`, or `None` when the buffer is malformed or empty.
/// Layout: `bLength`, `bDescriptorType == 3`, then UTF-16LE units.
/// Unpaired surrogates decode to U+FFFD (lossy, never an error —
/// a name must never fail a bind).
pub fn decode_usb_string_descriptor(buf: &[u8]) -> Option<String> {
    let len = *buf.first()? as usize;
    if len < 2 || len % 2 != 0 || len > buf.len() || buf[1] != USB_DESC_TYPE_STRING {
        return None;
    }
    let units: Vec<u16> = buf[2..len]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let name: String = char::decode_utf16(units)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Fetch one string descriptor (`index`) via `GET_DESCRIPTOR(STRING)`,
/// mirroring `cdc_ncm::fetch_mac_string`: LANGID from string-0,
/// falling back to en-US (0x0409). Returns `None` on any failure.
async fn fetch_product_string(xhci: &Xhci, slot_id: u8, index: u8) -> Option<String> {
    if index == 0 {
        return None;
    }
    let mut lang = [0u8; 4];
    let langid = match xhci
        .control_in(slot_id, 0x80, USB_REQ_GET_DESCRIPTOR, 0x0300, 0, &mut lang)
        .await
    {
        Ok(n) if n >= 4 => u16::from_le_bytes([lang[2], lang[3]]),
        _ => 0x0409,
    };
    let mut buf = [0u8; 256];
    let n = xhci
        .control_in(
            slot_id,
            0x80,
            USB_REQ_GET_DESCRIPTOR,
            0x0300 | index as u16,
            langid,
            &mut buf,
        )
        .await
        .ok()?;
    decode_usb_string_descriptor(&buf[..n])
}

/// Resolve a bound HID device's identity, best-effort: `None` when
/// the device-descriptor fetch fails, in which case the caller keeps
/// today's synthetic caps and the bind proceeds unchanged. The name
/// is the product string when fetchable, else `fallback_name`.
pub async fn resolve_usb_identity(
    xhci: &Xhci,
    slot_id: u8,
    port: u8,
    hub_port: Option<(usize, u8)>,
    fallback_name: &str,
) -> Option<UsbIdentity> {
    let desc = xhci.get_device_descriptor(slot_id).await.ok()?;
    let (vendor, product, version, i_product) = parse_device_descriptor(&desc);
    let name = fetch_product_string(xhci, slot_id, i_product)
        .await
        .unwrap_or_else(|| String::from(fallback_name));
    Some(UsbIdentity {
        vendor,
        product,
        version,
        name,
        phys: usb_phys(port, hub_port),
    })
}

/// Apply a resolved identity to a caps set: `BUS_USB` + descriptor
/// IDs, product (or fallback) name, topology phys, empty uniq
/// (mirrors the I2C-HID producers).
pub fn apply_identity(caps: &mut DeviceCaps, id: &UsbIdentity) {
    caps.set_identity(
        &id.name,
        &id.phys,
        "",
        InputId::new(bus::USB, id.vendor, id.product, id.version),
    );
}

#[cfg(target_arch = "x86_64")]
pub(crate) mod tests {
    use super::*;
    use narf_input::evdev::{key, rel, ROUTER};
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// 18-byte device descriptor fixture: vendor 0x046D (Logitech),
    /// product 0xC52B, bcdDevice 0x0111, iProduct 2, bLength 18,
    /// bDescriptorType 1. Offsets per USB 2.0 §9.6.1.
    fn fixture_descriptor() -> [u8; 18] {
        [
            18, 1, 0x00, 0x02, 0, 0, 0, 64, 0x6D, 0x04, 0x2B, 0xC5, 0x11, 0x01, 2, 0, 0, 1,
        ]
    }

    fn smoke_identity_parse_descriptor() -> TestResult {
        let (vendor, product, version, i_product) = parse_device_descriptor(&fixture_descriptor());
        if vendor != 0x046D {
            return TestResult::Fail("idVendor must parse from bytes 8..10");
        }
        if product != 0xC52B {
            return TestResult::Fail("idProduct must parse from bytes 10..12");
        }
        if version != 0x0111 {
            return TestResult::Fail("bcdDevice must parse from bytes 12..14");
        }
        if i_product != 2 {
            return TestResult::Fail("iProduct must parse from byte 14");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/identity", smoke_identity_parse_descriptor);

    fn smoke_identity_phys() -> TestResult {
        if usb_phys(3, None) != "usb-3" {
            return TestResult::Fail("root phys must be usb-{port}");
        }
        if usb_phys(2, Some((1, 2))) != "usb-1-2" {
            return TestResult::Fail("downstream phys must be usb-{hub}-{port}");
        }
        // Masking-defeating: two identical devices on different ports
        // must get distinct phys — a name-only identity would collide.
        if usb_phys(2, None) == usb_phys(3, None) {
            return TestResult::Fail("distinct ports must yield distinct phys");
        }
        if usb_phys(2, Some((1, 2))) == usb_phys(2, Some((1, 3))) {
            return TestResult::Fail("distinct hub ports must yield distinct phys");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/identity", smoke_identity_phys);

    /// Build a USB string descriptor buffer for `text` (UTF-16LE).
    fn string_descriptor(text: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push((2 + text.encode_utf16().count() * 2) as u8);
        buf.push(USB_DESC_TYPE_STRING);
        for unit in text.encode_utf16() {
            buf.extend_from_slice(&unit.to_le_bytes());
        }
        buf
    }

    fn smoke_identity_string_decode() -> TestResult {
        // Byte-exact: "Logitech" decodes from its UTF-16LE wire form.
        let wire = string_descriptor("Logitech");
        if decode_usb_string_descriptor(&wire).as_deref() != Some("Logitech") {
            return TestResult::Fail("UTF-16LE product string must decode byte-exact");
        }
        // Non-ASCII is preserved, not stripped to ASCII.
        let wire = string_descriptor("Clavieré");
        if decode_usb_string_descriptor(&wire).as_deref() != Some("Clavieré") {
            return TestResult::Fail("non-ASCII string content must survive decode");
        }
        // Wrong descriptor type is not a string.
        let mut bad = string_descriptor("X");
        bad[1] = 2;
        if decode_usb_string_descriptor(&bad).is_some() {
            return TestResult::Fail("non-string descriptor type must decode to None");
        }
        // Claimed length beyond the buffer is not a string.
        let mut truncated = string_descriptor("Logitech");
        truncated[0] = 200;
        if decode_usb_string_descriptor(&truncated).is_some() {
            return TestResult::Fail("over-long bLength must decode to None");
        }
        // Empty payload (bLength 2) is not a name.
        if decode_usb_string_descriptor(&[2, USB_DESC_TYPE_STRING]).is_some() {
            return TestResult::Fail("empty string descriptor must decode to None");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/identity", smoke_identity_string_decode);

    fn smoke_identity_apply_and_router_readback() -> TestResult {
        let id = UsbIdentity {
            vendor: 0x046D,
            product: 0xC52B,
            version: 0x0111,
            name: String::from("Logitech USB Receiver"),
            phys: String::from("usb-2"),
        };
        let mut caps = DeviceCaps::new();
        caps.add_rel(rel::REL_X);
        caps.add_rel(rel::REL_Y);
        caps.add_key(key::BTN_LEFT);
        apply_identity(&mut caps, &id);
        let (dev_id, _node) = ROUTER.register_device(caps);
        let back = match ROUTER.caps(dev_id) {
            Some(c) => c,
            None => {
                ROUTER.unregister_device(dev_id);
                return TestResult::Fail("ROUTER must return caps for a registered device");
            }
        };
        ROUTER.unregister_device(dev_id);
        if back.id.bustype != bus::USB
            || back.id.vendor != 0x046D
            || back.id.product != 0xC52B
            || back.id.version != 0x0111
        {
            return TestResult::Fail(
                "ROUTER readback EVIOCGID quartet must match the applied identity",
            );
        }
        if back.name != "Logitech USB Receiver" {
            return TestResult::Fail("ROUTER readback name must match the applied identity");
        }
        if back.phys != "usb-2" {
            return TestResult::Fail("ROUTER readback phys must match the applied identity");
        }
        if !back.uniq.is_empty() {
            return TestResult::Fail("USB identity uniq must stay empty (serial not fetched)");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/identity",
        smoke_identity_apply_and_router_readback
    );
}

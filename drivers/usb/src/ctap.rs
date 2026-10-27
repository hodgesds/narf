//! FIDO2 authenticator binding: CTAP2 over USB HID (issue #999,
//! power-suspend lane P3).
//!
//! A FIDO authenticator is a HID-class device whose report
//! descriptor declares the FIDO Alliance usage page (0xF1D0) with
//! 64-byte Input and Output reports — that descriptor check, not
//! the interface class alone, is the discrimination: keyboards
//! and CCID readers both fall through to their own binders.
//!
//! This module owns only the *binding*: descriptor walk,
//! report-descriptor fetch + FIDO verification, endpoint
//! configuration, and the token registry. The protocol itself
//! lives in the `narf-ctap2` crate; [`XhciHidPipe`] is the
//! transport seam between the two (an xHCI interrupt endpoint
//! pair, one 64-byte report per TRB — interrupt-OUT support was
//! added to `xhci` alongside this module, mirroring the existing
//! interrupt-IN pair).
//!
//! Service surface for the suspend service (lane P1):
//! [`bound_token`] hands out the registered token; [`open_client`]
//! builds a ready `narf_ctap2::Client` over a fresh pipe with
//! production randomness (`narf_crypto::try_fill_random_bytes`,
//! the P0 entropy surface). Registry removal on detach follows
//! the CCID precedent — class registries are append-only today
//! and are covered by the #748 follow-up; the slot itself is
//! disabled/reclaimed by `attach::detach_slot` as usual.

use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

use narf_ctap2::ctaphid::{HidPipe, REPORT_LEN};
use narf_ctap2::Client;

use crate::hid::report_descriptor::{parse, FieldKind};
use crate::xhci::{EndpointConfig, EndpointKind, Xhci};

/// HID usage page: FIDO Alliance (CTAP2 spec, HID binding).
pub const FIDO_USAGE_PAGE: u16 = 0xF1D0;
/// FIDO application-collection usage on that page.
pub const FIDO_USAGE_AUTHENTICATOR: u16 = 0x01;
/// USB interface class: HID.
pub const HID_INTERFACE_CLASS: u8 = 0x03;
/// HID descriptor type (the class descriptor after the interface).
pub const HID_DESC_TYPE_HID: u8 = 0x21;
/// Report descriptor type (wValue high byte for GET_DESCRIPTOR).
pub const HID_DESC_TYPE_REPORT: u8 = 0x22;
/// bmRequestType for GET_DESCRIPTOR to an interface:
/// device-to-host | standard | interface.
pub const RT_DEV_TO_HOST_STD_IFACE: u8 = 0x81;
/// USB standard request SET_CONFIGURATION.
const STD_REQ_SET_CONFIGURATION: u8 = 0x09;

/// Upper bound on a FIDO report descriptor fetch (the canonical
/// descriptor is 34 bytes; real tokens stay well under 512).
pub const MAX_REPORT_DESCRIPTOR: usize = 512;

/// Poll bound for one interrupt transfer completion. The pipe is
/// deliberately poll-driven (the resume environment, P5, has no
/// IRQ waits either); at xHCI demux cost per poll this bound is
/// far beyond any real token's report latency, and exhaustion is
/// a clean Timeout, never a hang.
pub const MAX_POLLS_PER_REPORT: usize = 4_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CtapError {
    /// Not a FIDO HID device (wrong class, no FIDO usage, or the
    /// report shape isn't 64-byte in/out) — fall through to the
    /// next binder.
    NotFido,
    /// Endpoints missing or not 64-byte interrupt in/out.
    EndpointsMissing,
    /// The report-descriptor length was implausible or absent.
    NoReportDescriptor,
    /// A control/endpoint transfer failed.
    Transfer,
    /// No xHCI controller is registered.
    NoController,
}

/// A bound FIDO authenticator.
#[derive(Debug)]
pub struct CtapToken {
    pub slot_id: u8,
    pub iface_num: u8,
    pub in_ep: EndpointConfig,
    pub out_ep: EndpointConfig,
}

impl CtapToken {
    /// DCI for the interrupt-IN endpoint (§4.8.1: num*2 + 1).
    pub fn in_dci(&self) -> u8 {
        (self.in_ep.ep_addr & 0x0F) * 2 + 1
    }
    /// DCI for the interrupt-OUT endpoint (§4.8.1: num*2).
    pub fn out_dci(&self) -> u8 {
        (self.out_ep.ep_addr & 0x0F) * 2
    }
}

/// Global registry of bound FIDO tokens. Append-only, mirroring
/// `ccid::CCID_READERS` (removal is the #748 follow-up).
pub static CTAP_TOKENS: IrqSafeSpinLock<Vec<Arc<CtapToken>>> = IrqSafeSpinLock::new(Vec::new());

/// Number of FIDO tokens currently registered.
pub fn attached_count() -> usize {
    CTAP_TOKENS.lock().len()
}

/// The first bound token, if any (the suspend service's common
/// case: tokens are enumerated by the service when more than one
/// is present, via [`CTAP_TOKENS`] indices).
pub fn bound_token(index: usize) -> Option<Arc<CtapToken>> {
    CTAP_TOKENS.lock().get(index).cloned()
}

#[doc(hidden)]
pub fn __reset_ctap_for_test() {
    CTAP_TOKENS.lock().clear();
}

// ── Configuration-descriptor walkers ────────────────────────────

/// Walk the configuration descriptor for the first HID-class
/// interface (class 0x03) at or after `from`. Returns
/// (bInterfaceNumber, offset). Composite tokens may carry the
/// FIDO interface behind another HID interface, so the binder
/// iterates this over the whole blob.
pub fn find_hid_interface_from(cfg: &[u8], from: usize) -> Option<(u8, usize)> {
    let mut i = from;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        if cfg[i + 1] == 0x04 && len >= 9 && cfg[i + 5] == HID_INTERFACE_CLASS {
            return Some((cfg[i + 2], i));
        }
        i += len;
    }
    None
}

/// The first HID-class interface in the blob, if any.
pub fn find_hid_interface(cfg: &[u8]) -> Option<(u8, usize)> {
    find_hid_interface_from(cfg, 0)
}

/// Extract the Report Descriptor length from the HID class
/// descriptor (type 0x21) that follows the interface descriptor.
pub fn report_descriptor_length(cfg: &[u8], iface_offset: usize) -> Option<u16> {
    let mut i = iface_offset;
    // Skip the interface descriptor itself.
    if i + 2 <= cfg.len() {
        let skip = cfg[i] as usize;
        if skip >= 2 {
            i += skip;
        }
    }
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let dtype = cfg[i + 1];
        if dtype == HID_DESC_TYPE_HID && len >= 9 {
            if cfg[i + 6] != HID_DESC_TYPE_REPORT {
                return None;
            }
            return Some(u16::from_le_bytes([cfg[i + 7], cfg[i + 8]]));
        }
        if dtype == 0x04 || dtype == 0x05 {
            return None; // reached the next interface / an endpoint first
        }
        i += len;
    }
    None
}

/// Collect the interrupt IN and OUT endpoints following the
/// interface descriptor. Both must be 64-byte max-packet — the
/// CTAPHID report size is fixed, and a smaller endpoint cannot
/// carry one report per transfer.
pub fn find_fido_endpoints(
    cfg: &[u8],
    iface_offset: usize,
) -> Result<(EndpointConfig, EndpointConfig), CtapError> {
    let mut in_ep: Option<EndpointConfig> = None;
    let mut out_ep: Option<EndpointConfig> = None;
    let mut i = iface_offset;
    if i + 2 <= cfg.len() {
        let skip = cfg[i] as usize;
        if skip >= 2 {
            i += skip;
        }
    }
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let dtype = cfg[i + 1];
        if dtype == 0x04 {
            break; // next interface
        }
        if dtype == 0x05 && len >= 7 {
            let addr = cfg[i + 2];
            let attrs = cfg[i + 3];
            let max_packet = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]);
            let interval = cfg[i + 6];
            if attrs & 0x03 == 0x03 && max_packet as usize == REPORT_LEN {
                if addr & 0x80 != 0 && in_ep.is_none() {
                    in_ep = Some(EndpointConfig {
                        ep_addr: addr,
                        max_packet,
                        kind: EndpointKind::InterruptIn,
                        interval,
                    });
                } else if addr & 0x80 == 0 && out_ep.is_none() {
                    out_ep = Some(EndpointConfig {
                        ep_addr: addr,
                        max_packet,
                        kind: EndpointKind::InterruptOut,
                        interval,
                    });
                }
            }
        }
        i += len;
    }
    match (in_ep, out_ep) {
        (Some(a), Some(b)) => Ok((a, b)),
        _ => Err(CtapError::EndpointsMissing),
    }
}

/// True when a fetched HID report descriptor is the FIDO shape:
/// the FIDO Alliance page (0xF1D0) application collection with
/// 64-byte Input and Output fields and no report IDs. This is
/// the check that keeps keyboards (and every other HID device)
/// out of this binder.
pub fn descriptor_is_fido(report_desc: &[u8]) -> bool {
    let Ok(parsed) = parse(report_desc) else {
        return false;
    };
    if parsed.has_report_ids {
        return false;
    }
    if !parsed
        .top_level_apps
        .contains(&(FIDO_USAGE_PAGE, FIDO_USAGE_AUTHENTICATOR))
    {
        return false;
    }
    let has_dir = |kind: FieldKind| {
        parsed.fields.iter().any(|f| {
            f.kind == kind
                && f.usage_page == FIDO_USAGE_PAGE
                && f.report_size as usize * f.report_count as usize == REPORT_LEN * 8
        })
    };
    has_dir(FieldKind::Input) && has_dir(FieldKind::Output)
}

// ── Transport ───────────────────────────────────────────────────

/// Production randomness for the CTAP2 client: narf-crypto's
/// HW-entropy-gated fill (P0 surface). Fails closed when no seed-
/// grade entropy source exists.
#[derive(Debug)]
pub struct CryptoRandom;

impl narf_ctap2::RandomSource for CryptoRandom {
    fn fill_random(&mut self, out: &mut [u8]) -> Result<(), narf_ctap2::Error> {
        narf_crypto::try_fill_random_bytes(out).map_err(|_| narf_ctap2::Error::Random)
    }
}

/// The xHCI-backed HID pipe for one bound token. One TRB per
/// 64-byte report in each direction; completions are polled
/// (see [`MAX_POLLS_PER_REPORT`]).
pub struct XhciHidPipe {
    xhci: Arc<Xhci>,
    slot_id: u8,
    in_dci: u8,
    out_dci: u8,
}

impl core::fmt::Debug for XhciHidPipe {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XhciHidPipe")
            .field("slot_id", &self.slot_id)
            .field("in_dci", &self.in_dci)
            .field("out_dci", &self.out_dci)
            .finish_non_exhaustive()
    }
}

impl XhciHidPipe {
    pub fn new(xhci: Arc<Xhci>, token: &CtapToken) -> Self {
        Self {
            xhci,
            slot_id: token.slot_id,
            in_dci: token.in_dci(),
            out_dci: token.out_dci(),
        }
    }
}

impl HidPipe for XhciHidPipe {
    fn write_report(&mut self, report: &[u8; REPORT_LEN]) -> Result<(), narf_ctap2::Error> {
        self.xhci
            .arm_interrupt_out(self.slot_id, self.out_dci, report)
            .map_err(|_| narf_ctap2::Error::Transport)?;
        for _ in 0..MAX_POLLS_PER_REPORT {
            match self
                .xhci
                .poll_interrupt_out(self.slot_id, self.out_dci, REPORT_LEN as u32)
            {
                Ok(Some(_)) => return Ok(()),
                Ok(None) => core::hint::spin_loop(),
                Err(_) => return Err(narf_ctap2::Error::Transport),
            }
        }
        Err(narf_ctap2::Error::Timeout)
    }

    fn read_report(&mut self, out: &mut [u8; REPORT_LEN]) -> Result<(), narf_ctap2::Error> {
        for _ in 0..MAX_POLLS_PER_REPORT {
            match self.xhci.poll_interrupt_in(self.slot_id, self.in_dci, out) {
                Ok(Some(_)) => return Ok(()),
                Ok(None) => core::hint::spin_loop(),
                Err(_) => return Err(narf_ctap2::Error::Transport),
            }
        }
        Err(narf_ctap2::Error::Timeout)
    }
}

/// Open a CTAP2 client over a bound token, ready for the suspend
/// service: fresh pipe + CTAPHID INIT + getInfo (inside
/// `Client::connect`).
pub fn open_client(
    token: &Arc<CtapToken>,
) -> Result<Client<XhciHidPipe, CryptoRandom>, narf_ctap2::Error> {
    let xhci = crate::xhci::controller().ok_or(narf_ctap2::Error::Transport)?;
    let pipe = XhciHidPipe::new(xhci, token);
    Client::connect(pipe, CryptoRandom)
}

// ── Bind path ───────────────────────────────────────────────────

/// Attempt to bind an already-addressed device as a FIDO
/// authenticator. Returns the registry index on success.
///
/// **Slot lifecycle**: does NOT call `disable_slot` on failure;
/// the dispatcher in `attach.rs` owns the slot.
pub async fn try_bind_ctap_already_addressed(
    xhci_dev: &Xhci,
    slot_id: u8,
    cfg: &[u8],
) -> Result<usize, CtapError> {
    if find_hid_interface(cfg).is_none() {
        return Err(CtapError::NotFido);
    }
    // SET_CONFIGURATION once, before any class request (they
    // STALL without it). Idempotent across the dispatch cascade.
    let config_value = if cfg.len() >= 6 { cfg[5] } else { 1 };
    xhci_dev
        .control_out(
            slot_id,
            0x00,
            STD_REQ_SET_CONFIGURATION,
            config_value as u16,
            0,
            &[],
        )
        .await
        .map_err(|_| CtapError::Transfer)?;

    // Scan every HID interface: on composite tokens the FIDO
    // interface is not necessarily the first HID one. The
    // report-descriptor FIDO check is the discrimination — a
    // non-FIDO HID interface just costs one descriptor fetch.
    let mut scan_from = 0usize;
    while let Some((iface_num, iface_off)) = find_hid_interface_from(cfg, scan_from) {
        scan_from = iface_off + 9;
        let Ok((in_ep, out_ep)) = find_fido_endpoints(cfg, iface_off) else {
            continue;
        };
        let Some(report_len) = report_descriptor_length(cfg, iface_off) else {
            continue;
        };
        if report_len == 0 || report_len as usize > MAX_REPORT_DESCRIPTOR {
            continue;
        }
        let mut blob = alloc::vec![0u8; report_len as usize];
        xhci_dev
            .control_in(
                slot_id,
                RT_DEV_TO_HOST_STD_IFACE,
                crate::xhci::USB_REQ_GET_DESCRIPTOR,
                (HID_DESC_TYPE_REPORT as u16) << 8,
                iface_num as u16,
                &mut blob,
            )
            .await
            .map_err(|_| CtapError::Transfer)?;
        if !descriptor_is_fido(&blob) {
            continue;
        }

        // Configure the interrupt pair and arm the first IN.
        xhci_dev
            .configure_endpoints(slot_id, &[in_ep, out_ep])
            .await
            .map_err(|_| CtapError::Transfer)?;
        let token = Arc::new(CtapToken {
            slot_id,
            iface_num,
            in_ep,
            out_ep,
        });
        xhci_dev
            .arm_interrupt_in(slot_id, token.in_dci(), REPORT_LEN as u32)
            .map_err(|_| CtapError::Transfer)?;

        {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "  usb-ctap: FIDO token on slot={} iface={} (CTAP2/HID)",
                slot_id,
                iface_num,
            );
        }
        let idx = {
            let mut g = CTAP_TOKENS.lock();
            let idx = g.len();
            g.push(token);
            idx
        };
        return Ok(idx);
    }
    Err(CtapError::NotFido)
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    macro_rules! check {
        ($cond:expr, $msg:expr) => {
            if !($cond) {
                return TestResult::Fail($msg);
            }
        };
    }
    macro_rules! check_eq {
        ($a:expr, $b:expr, $msg:expr) => {
            if $a != $b {
                return TestResult::Fail($msg);
            }
        };
    }
    macro_rules! try_some {
        ($e:expr, $msg:expr) => {
            match $e {
                Some(v) => v,
                None => return TestResult::Fail($msg),
            }
        };
    }
    macro_rules! try_ok {
        ($e:expr, $msg:expr) => {
            match $e {
                Ok(v) => v,
                Err(_) => return TestResult::Fail($msg),
            }
        };
    }

    /// The canonical FIDO report descriptor (CTAP2 spec's HID
    /// binding example shape, as shipped by YubiKey-class tokens).
    pub const FIDO_REPORT_DESCRIPTOR: &[u8] = &[
        0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
        0x09, 0x01, // Usage (authenticator)
        0xA1, 0x01, // Collection (Application)
        0x09, 0x20, //   Usage (input data)
        0x15, 0x00, //   Logical Minimum (0)
        0x26, 0xFF, 0x00, //   Logical Maximum (255)
        0x75, 0x08, //   Report Size (8)
        0x95, 0x40, //   Report Count (64)
        0x81, 0x02, //   Input (Data, Var, Abs)
        0x09, 0x21, //   Usage (output data)
        0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, //
        0x91, 0x02, //   Output (Data, Var, Abs)
        0xC0, // End Collection
    ];

    /// A boot-keyboard report descriptor (must NOT match).
    const KEYBOARD_REPORT_DESCRIPTOR: &[u8] = &[
        0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25,
        0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x05,
        0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05, 0x91, 0x02, 0x95, 0x01, 0x75, 0x03, 0x91,
        0x01, 0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65,
        0x81, 0x00, 0xC0,
    ];

    /// Build a config-descriptor blob for a single-interface HID
    /// device with the given endpoints: config(9) + iface(9) +
    /// HID class desc(9) + ep descs(7 each).
    fn cfg_blob(report_desc_len: u16, eps: &[(u8, u8, u16, u8)]) -> Vec<u8> {
        let total = 9 + 9 + 9 + 7 * eps.len();
        let mut cfg = alloc::vec![
            9,
            2,
            (total as u8),
            0, // wTotalLength LE
            1,
            1,
            0,
            0x80,
            50, // 1 iface, config 1
        ];
        cfg.extend_from_slice(&[9, 4, 0, 0, eps.len() as u8, 0x03, 0x00, 0x00, 0]);
        // HID class descriptor: bcdHID 1.11, country 0, 1 sub-desc
        // (Report, length).
        cfg.extend_from_slice(&[9, 0x21, 0x11, 0x01, 0, 1, 0x22]);
        cfg.extend_from_slice(&report_desc_len.to_le_bytes());
        for (addr, attrs, maxp, interval) in eps {
            cfg.extend_from_slice(&[7, 5, *addr, *attrs]);
            cfg.extend_from_slice(&maxp.to_le_bytes());
            cfg.push(*interval);
        }
        cfg
    }

    fn smoke_fido_descriptor_matches_and_keyboard_does_not() -> TestResult {
        check!(
            descriptor_is_fido(FIDO_REPORT_DESCRIPTOR),
            "FIDO descriptor matches"
        );
        check!(
            !descriptor_is_fido(KEYBOARD_REPORT_DESCRIPTOR),
            "keyboard descriptor must not match"
        );
        check!(!descriptor_is_fido(&[]), "empty descriptor must not match");
        check!(
            !descriptor_is_fido(&[0x06, 0xD0]),
            "truncated descriptor must not match"
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/ctap",
        smoke_fido_descriptor_matches_and_keyboard_does_not
    );

    fn smoke_fido_config_blob_binds() -> TestResult {
        let cfg = cfg_blob(
            FIDO_REPORT_DESCRIPTOR.len() as u16,
            &[(0x81, 0x03, 64, 1), (0x01, 0x03, 64, 1)],
        );
        let (iface, off) = try_some!(find_hid_interface(&cfg), "hid iface");
        check_eq!(iface, 0, "iface number");
        let (in_ep, out_ep) = try_ok!(find_fido_endpoints(&cfg, off), "endpoints");
        check_eq!(in_ep.kind, EndpointKind::InterruptIn, "in endpoint kind");
        check_eq!(out_ep.kind, EndpointKind::InterruptOut, "out endpoint kind");
        check_eq!(
            report_descriptor_length(&cfg, off),
            Some(FIDO_REPORT_DESCRIPTOR.len() as u16),
            "report descriptor length"
        );
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/ctap", smoke_fido_config_blob_binds);

    fn smoke_ccid_blob_is_not_fido() -> TestResult {
        // A CCID-shaped blob: class 0x0B interface — the HID finder
        // must not match it at all.
        let mut cfg = alloc::vec![9, 2, 18, 0, 1, 1, 0, 0x80, 50];
        cfg.extend_from_slice(&[9, 4, 0, 0, 0, 0x0B, 0x00, 0x00, 0]);
        check!(
            find_hid_interface(&cfg).is_none(),
            "CCID blob has no HID interface"
        );
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/ctap", smoke_ccid_blob_is_not_fido);

    fn smoke_small_endpoint_is_not_fido() -> TestResult {
        // Interrupt pair but 32-byte packets: cannot carry CTAPHID
        // reports; must fall through.
        let cfg = cfg_blob(34, &[(0x81, 0x03, 32, 1), (0x01, 0x03, 32, 1)]);
        let (_, off) = try_some!(find_hid_interface(&cfg), "hid iface");
        check!(
            matches!(
                find_fido_endpoints(&cfg, off),
                Err(CtapError::EndpointsMissing)
            ),
            "small endpoints refused"
        );
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/ctap", smoke_small_endpoint_is_not_fido);

    fn smoke_registry_publish_lookup() -> TestResult {
        __reset_ctap_for_test();
        check_eq!(attached_count(), 0, "registry starts empty");
        let token = Arc::new(CtapToken {
            slot_id: 7,
            iface_num: 0,
            in_ep: EndpointConfig {
                ep_addr: 0x81,
                max_packet: 64,
                kind: EndpointKind::InterruptIn,
                interval: 1,
            },
            out_ep: EndpointConfig {
                ep_addr: 0x01,
                max_packet: 64,
                kind: EndpointKind::InterruptOut,
                interval: 1,
            },
        });
        check_eq!(token.in_dci(), 3, "in DCI");
        check_eq!(token.out_dci(), 2, "out DCI");
        CTAP_TOKENS.lock().push(token);
        check_eq!(attached_count(), 1, "one token registered");
        check_eq!(
            bound_token(0).map(|t| t.slot_id),
            Some(7),
            "lookup by index"
        );
        check!(bound_token(1).is_none(), "no second token");
        __reset_ctap_for_test();
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/ctap", smoke_registry_publish_lookup);
}

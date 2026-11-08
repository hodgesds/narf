// SPDX-License-Identifier: GPL-2.0-or-later
//! Fake USB HCI controller end-to-end fixture (#822).
//!
//! The peripherals programme endpoint (#746) needs the whole
//! conversation proven as one run — attach → vendor firmware
//! download → bring-up → event/ACL flow — because the loopback /
//! canned-event tests that existed before would pass even with a
//! wiring disconnect between the USB HCI path and the pump
//! (a controller that never sees a command, or a pump whose ACL
//! never reaches the bulk-OUT endpoint, looks identical to a
//! working one when the transport is hand-fed).
//!
//! This module closes that gap with a scripted fake controller
//! that speaks USB: it is attached through the production
//! descriptor recogniser, records every transfer per endpoint
//! (EP0 control / interrupt-IN events / bulk ACL), answers the
//! Intel newgen vendor firmware conversation from bootloader mode,
//! then serves the mandatory bring-up and the pump's event/ACL
//! flow once operational. A disconnect anywhere in that chain —
//! wrong endpoint, dropped event, skipped firmware phase, dead
//! bulk-OUT — fails the test instead of passing silently.
//!
//! ## Spec discipline
//!
//! The fake is built from the specifications, not from production
//! code, so the fake and the code cannot agree on a wrong
//! constant by copying each other. Every fixture-owned constant
//! below is written from the source named next to it; where the
//! production code has an equivalent builder the test asserts the
//! two agree with the spec-literal value, so a wrong production
//! constant fails the test rather than being mirrored.
//!
//! Sources (public only):
//! - **Bluetooth Core Specification 5.3, Vol 4 Part B** — USB
//!   Transport Layer: the four-endpoint split, the HCI Command
//!   Setup packet (§2.2.1, bmRequestType 0x20 / bRequest 0x00).
//! - **Bluetooth Core Specification 5.3, Vol 4 Part E** — HCI
//!   Functional Specification: mandatory bring-up (§3), Command
//!   Complete (§7.7.14), error code 0x12 Invalid HCI Command
//!   Parameters.
//! - **USB 2.0 §9.6.5 / §9.6.6** — Interface / Endpoint
//!   Descriptor layout used by the descriptor builder.
//! - **USB Class Definitions for Wireless Controllers v1.0**,
//!   USB-IF — class triple 0xE0 / 0x01 / 0x01.
//! - **Linux `drivers/bluetooth/btintel.c` + `btusb.c`**
//!   (`btusb_setup_intel_newgen`, `btintel_download_fw_tlv`,
//!   `btintel_secure_send`), GPL-2.0, consulted under NARF's
//!   GPL-2.0-or-later licensing — the Intel newgen vendor
//!   conversation (opcodes 0xFC05 / 0xFC0D / 0xFC09 / 0xFC01,
//!   Secure Send fragment types, the 0xFF/0x02 bootup event).
//!   The same conversation is distilled in
//!   `drivers/usb/src/btusb_intel.rs` (module docs); the fixture
//!   follows that documented sequence, not the loader's code.
//!
//! ## What the fake deliberately does NOT model
//!
//! - The xHCI transfer layer: `try_bind_btusb_already_addressed`
//!   needs a live host controller, so the fixture stops at the
//!   `HciTransport` seam and models the USB transfers (setup
//!   packet + endpoint routing) above it. The descriptor walk it
//!   attaches through is the production one.
//! - Unmodelled HCI commands are recorded but unanswered: the
//!   fake answers exactly the conversation it scripts, so the
//!   event accounting in each test stays exact instead of being
//!   inflated by auto-acked commands the pump may issue.
//! - No real firmware blob: the image is synthetic (a CSS header
//!   and two embedded HCI commands), sized and framed by the
//!   documented rules, so the download proves framing and
//!   ordering, not a vendor signature check.

#![cfg(any(test, feature = "kernel-test"))]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::att;
use crate::event::{CommandComplete, EventCode};
use crate::hci::{AclData, Command, Event};
use crate::l2cap::{BFrame, CID_ATT, CID_SMP, PB_COMPLETE_LE};
use crate::opcode as op;
use crate::smp;
use crate::transport::{HciTransport, TransportError};
use crate::usb_transport::{self, HciEndpoints};
use narf_lib::sync::IrqSafeSpinLock;

// ── Fixture-owned constants (spec-literal; see module docs) ────────

/// USB Class — Wireless Controller (USB-IF Wireless v1.0).
const USB_CLASS_WIRELESS: u8 = 0xE0;
/// USB Subclass — RF Controller.
const USB_SUBCLASS_RF: u8 = 0x01;
/// USB Protocol — Bluetooth Programming Interface.
const USB_PROTOCOL_BLUETOOTH: u8 = 0x01;

/// bmRequestType for an HCI Command control transfer — Class |
/// Interface | Host-to-Device (Vol 4 Part B §2.2.1).
const SETUP_BM_REQUEST_TYPE: u8 = 0x20;
/// bRequest for an HCI Command transfer — zero (§2.2.1).
const SETUP_B_REQUEST: u8 = 0x00;

/// Interrupt-IN endpoint carrying HCI Events (fixture device).
const EP_EVENT_IN: u8 = 0x81;
/// Bulk-IN endpoint carrying ACL data device → host.
const EP_ACL_IN: u8 = 0x82;
/// Bulk-OUT endpoint carrying ACL data host → device.
const EP_ACL_OUT: u8 = 0x02;

/// Intel Read Version (vendor opcode).
const INTEL_OP_READ_VERSION: u16 = 0xFC05;
/// Intel Read Boot Params (vendor opcode).
const INTEL_OP_READ_BOOT_PARAMS: u16 = 0xFC0D;
/// Intel Secure Send (vendor opcode).
const INTEL_OP_SECURE_SEND: u16 = 0xFC09;
/// Intel Reset (vendor opcode).
const INTEL_OP_RESET: u16 = 0xFC01;
/// Write Boot Params command embedded in `.sfi` images.
const INTEL_OP_WRITE_BOOT_PARAMS: u16 = 0xFC0E;

/// Secure Send fragment types (Linux `btintel_secure_send`).
const FRAG_INIT: u8 = 0x00;
const FRAG_PKEY: u8 = 0x03;
const FRAG_SIGN: u8 = 0x02;
const FRAG_DATA: u8 = 0x01;

/// Max payload bytes per Secure Send command: the 253-byte HCI
/// parameter limit minus the fragment-type byte.
const FRAGMENT_PAYLOAD_MAX: usize = 252;

/// Version TLV tags (Linux `btintel.h` INTEL_TLV_*).
const TLV_CNVI_BT: u8 = 0x12;
const TLV_IMAGE_TYPE: u8 = 0x15;
const TLV_LIMITED_CCE: u8 = 0x1E;
const TLV_SBE_TYPE: u8 = 0x1F;

/// `img_type` value for bootloader mode.
const IMG_TYPE_BOOTLOADER: u8 = 0x01;

/// Vendor event code; Intel bootup is subevent 0x02.
const EVENT_VENDOR: u8 = 0xFF;
const INTEL_BOOTUP_SUBEVENT: u8 = 0x02;

/// CSS header version for RSA images (image bytes 8..12).
const CSS_VER_RSA: u32 = 0x0001_0000;
/// RSA secure-boot header length at the start of every `.sfi`.
const RSA_HEADER_LEN: usize = 644;

/// HCI error: Invalid HCI Command Parameters (Vol 4 Part E).
const ERR_INVALID_PARAMS: u8 = 0x12;

/// BD_ADDR the fake operational controller reports.
const FAKE_BD_ADDR: [u8; 6] = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5];

/// Boot address embedded in the synthetic firmware image (the
/// Write Boot Params command's first parameter word). The fake
/// learns it from the downloaded payload and demands the same
/// address on Intel Reset — the download and the boot must agree.
const FAKE_BOOT_ADDR: u32 = 0x0000_1000;

// ── USB Configuration Descriptor builder ────────────────────────────
//
// Fixture-owned, from USB 2.0 §9.6.5 (Interface) / §9.6.6
// (Endpoint). The full descriptor matches the one the existing
// `smoke_btusb_find_endpoints_returns_event_acl` unit smoke uses
// (39 bytes, INT-IN 0x81 + BULK-OUT 0x02 + BULK-IN 0x82); the
// variants below drop one endpoint to prove attach rejects them.

/// Build a Configuration Descriptor for a one-interface HCI
/// controller. `with_event_ep` / `with_acl_eps` drop endpoints to
/// exercise the attach rejections; `class` overrides the
/// interface class triple.
fn fake_config_descriptor(with_event_ep: bool, with_acl_eps: bool, class: u8) -> Vec<u8> {
    let mut eps: Vec<[u8; 7]> = Vec::new();
    if with_event_ep {
        // Interrupt-IN, wMaxPacketSize 16, interval 1.
        eps.push([7, 5, EP_EVENT_IN, 0x03, 16, 0, 1]);
    }
    if with_acl_eps {
        // Bulk-OUT, wMaxPacketSize 64.
        eps.push([7, 5, EP_ACL_OUT, 0x02, 64, 0, 0]);
        // Bulk-IN, wMaxPacketSize 64.
        eps.push([7, 5, EP_ACL_IN, 0x02, 64, 0, 0]);
    }
    let total_len = 9 + 9 + eps.len() * 7;
    let mut cfg = Vec::with_capacity(total_len);
    // Configuration Descriptor (§9.6.3): 1 interface, value 1.
    cfg.extend_from_slice(&[
        9,
        2,
        total_len as u8,
        (total_len >> 8) as u8,
        1,
        1,
        0,
        0x80,
        0,
    ]);
    // Interface Descriptor (§9.6.5): class triple, `num_eps` EPs.
    cfg.extend_from_slice(&[
        9,
        4,
        0,
        0,
        eps.len() as u8,
        class,
        USB_SUBCLASS_RF,
        USB_PROTOCOL_BLUETOOTH,
        0,
    ]);
    for ep in eps {
        cfg.extend_from_slice(&ep);
    }
    cfg
}

// ── Synthetic Intel firmware image ──────────────────────────────────
//
// 644-byte RSA header (CSS version word at bytes 8..12, the rest a
// fixed pattern) + a 16-byte payload of two embedded HCI commands:
// Write Boot Params (0xFC0E, 10 bytes) carrying FAKE_BOOT_ADDR,
// then a 6-byte dummy vendor command — 16 bytes total, so the
// payload is one 4-byte-aligned run per the documented
// `btintel_download_firmware_payload` grouping rule.

/// Build the synthetic `.sfi` image the download script sends.
fn fake_firmware_image() -> Vec<u8> {
    let mut image = alloc::vec![0u8; RSA_HEADER_LEN + 16];
    for (i, b) in image.iter_mut().enumerate() {
        *b = (i & 0xFF) as u8;
    }
    image[8..12].copy_from_slice(&CSS_VER_RSA.to_le_bytes());
    let payload = RSA_HEADER_LEN;
    // Write Boot Params: opcode 0xFC0E, plen 7, boot_addr LE,
    // build (num 0x35, ww 0x28, yy 0x18).
    image[payload..payload + 10].copy_from_slice(&[
        0x0E,
        0xFC,
        0x07,
        (FAKE_BOOT_ADDR & 0xFF) as u8,
        ((FAKE_BOOT_ADDR >> 8) & 0xFF) as u8,
        ((FAKE_BOOT_ADDR >> 16) & 0xFF) as u8,
        ((FAKE_BOOT_ADDR >> 24) & 0xFF) as u8,
        0x35,
        0x28,
        0x18,
    ]);
    // Dummy vendor command: opcode 0xFC00, plen 3.
    image[payload + 10..payload + 16].copy_from_slice(&[0x00, 0xFC, 0x03, 0xAA, 0xBB, 0xCC]);
    image
}

/// Fragment plan for the synthetic image, from the documented
/// rules: RSA header fragments (Init 128 B, PKey 256 B, Sign
/// 256 B) then the payload as one type-0x01 Data fragment.
fn fake_fragment_plan() -> Vec<(u8, usize, usize)> {
    vec![
        (FRAG_INIT, 0, 128),
        (FRAG_PKEY, 128, 256),
        (FRAG_SIGN, 388, 256),
        (FRAG_DATA, RSA_HEADER_LEN, 16),
    ]
}

// ── The fake controller ─────────────────────────────────────────────

/// Controller mode: bootloader (vendor commands only) until the
/// firmware download + Intel Reset boots the operational image.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum FakeMode {
    Bootloader,
    Operational,
}

/// A fake USB HCI controller: a `HciTransport` whose every transfer
/// is routed through simulated USB endpoints and recorded per
/// endpoint, so the test can prove which pipe each byte used.
#[derive(Debug)]
struct FakeUsbHci {
    /// Endpoints resolved at attach (production recogniser).
    endpoints: HciEndpoints,
    mode: IrqSafeSpinLock<FakeMode>,
    /// Interrupt-IN queue: HCI Events waiting for the host.
    events: IrqSafeSpinLock<VecDeque<Event>>,
    /// Bulk-IN queue: ACL packets waiting for the host.
    acl_inbox: IrqSafeSpinLock<VecDeque<Vec<u8>>>,
    /// EP0 control transfers: (Setup packet, command payload).
    control_transfers: IrqSafeSpinLock<Vec<([u8; 8], Vec<u8>)>>,
    /// Bulk-OUT transfers: (endpoint address, ACL bytes).
    bulk_out: IrqSafeSpinLock<Vec<(u8, Vec<u8>)>>,
    /// HCI commands the host issued, in order.
    sent_commands: IrqSafeSpinLock<Vec<Command>>,
    /// Events served from the interrupt-IN endpoint.
    interrupt_in_served: IrqSafeSpinLock<usize>,
    /// ACL packets served from the bulk-IN endpoint.
    bulk_in_served: IrqSafeSpinLock<usize>,
    /// Secure Send bytes received per fragment type (index = type).
    fw_bytes: IrqSafeSpinLock<[usize; 4]>,
    /// Secure Send commands received.
    secure_send_count: IrqSafeSpinLock<usize>,
    /// Type-0x01 payload bytes received (scanned for the boot
    /// address at Intel Reset).
    fw_payload: IrqSafeSpinLock<Vec<u8>>,
    /// Fault injection: bulk-OUT endpoint disconnected.
    bulk_out_disconnected: IrqSafeSpinLock<bool>,
}

impl FakeUsbHci {
    /// Attach through the production descriptor recogniser: the
    /// caller hands in the endpoints `find_endpoints` resolved, so
    /// a descriptor the recogniser rejects never becomes a fake.
    fn attach(endpoints: HciEndpoints) -> Self {
        Self {
            endpoints,
            mode: IrqSafeSpinLock::new(FakeMode::Bootloader),
            events: IrqSafeSpinLock::new(VecDeque::new()),
            acl_inbox: IrqSafeSpinLock::new(VecDeque::new()),
            control_transfers: IrqSafeSpinLock::new(Vec::new()),
            bulk_out: IrqSafeSpinLock::new(Vec::new()),
            sent_commands: IrqSafeSpinLock::new(Vec::new()),
            interrupt_in_served: IrqSafeSpinLock::new(0),
            bulk_in_served: IrqSafeSpinLock::new(0),
            fw_bytes: IrqSafeSpinLock::new([0; 4]),
            secure_send_count: IrqSafeSpinLock::new(0),
            fw_payload: IrqSafeSpinLock::new(Vec::new()),
            bulk_out_disconnected: IrqSafeSpinLock::new(false),
        }
    }

    fn mode(&self) -> FakeMode {
        *self.mode.lock()
    }

    /// Command Complete event for `opcode`; `ret` starts with the
    /// HCI status byte, as on the wire.
    fn cc(opcode: u16, ret: &[u8]) -> Event {
        let mut params = vec![1, (opcode & 0xFF) as u8, (opcode >> 8) as u8];
        params.extend_from_slice(ret);
        Event {
            code: EventCode::CommandComplete as u8,
            params,
        }
    }

    /// Enqueue an event on the interrupt-IN endpoint.
    fn enqueue_event(&self, e: Event) {
        self.events.lock().push_back(e);
    }

    /// Enqueue an ACL packet on the bulk-IN endpoint.
    fn enqueue_acl(&self, bytes: Vec<u8>) {
        self.acl_inbox.lock().push_back(bytes);
    }

    /// Disconnect the bulk-OUT endpoint (fault injection for the
    /// negative test: the pump's ACL replies have nowhere to go).
    fn disconnect_bulk_out(&self) {
        *self.bulk_out_disconnected.lock() = true;
    }

    fn sent_opcodes(&self) -> Vec<u16> {
        self.sent_commands.lock().iter().map(|c| c.opcode).collect()
    }

    fn control_transfers(&self) -> Vec<([u8; 8], Vec<u8>)> {
        self.control_transfers.lock().clone()
    }

    fn bulk_out_transfers(&self) -> Vec<(u8, Vec<u8>)> {
        self.bulk_out.lock().clone()
    }

    fn interrupt_in_served(&self) -> usize {
        *self.interrupt_in_served.lock()
    }

    fn bulk_in_served(&self) -> usize {
        *self.bulk_in_served.lock()
    }

    fn fw_bytes(&self, frag_type: u8) -> usize {
        // Callers only pass the four modelled fragment types.
        self.fw_bytes.lock()[frag_type as usize]
    }

    fn secure_send_count(&self) -> usize {
        *self.secure_send_count.lock()
    }

    /// Scan the downloaded type-0x01 payload for the Write Boot
    /// Params command (opcode 0xFC0E, plen ≥ 7) and return its boot
    /// address — the fixture-owned twin of the loader's
    /// `scan_boot_param`, written from the documented layout.
    fn boot_addr_from_payload(&self) -> Option<u32> {
        let payload = self.fw_payload.lock();
        let mut pos = 0usize;
        while pos + 3 <= payload.len() {
            let opcode = u16::from_le_bytes([payload[pos], payload[pos + 1]]);
            let plen = payload[pos + 2] as usize;
            if pos + 3 + plen > payload.len() {
                return None;
            }
            if opcode == INTEL_OP_WRITE_BOOT_PARAMS && plen >= 7 {
                let p = &payload[pos + 3..];
                return Some(u32::from_le_bytes([p[0], p[1], p[2], p[3]]));
            }
            pos += 3 + plen;
        }
        None
    }

    /// Answer one HCI command per the current mode, enqueueing the
    /// response event on the interrupt-IN endpoint. Only the
    /// modelled conversation is answered; anything else is recorded
    /// and left unanswered (see module docs).
    fn answer_command(&self, cmd: &Command) {
        match self.mode() {
            FakeMode::Bootloader => self.answer_bootloader(cmd),
            FakeMode::Operational => self.answer_operational(cmd),
        }
    }

    fn answer_bootloader(&self, cmd: &Command) {
        match cmd.opcode {
            INTEL_OP_READ_VERSION => {
                // TLV stream: CNVI_BT (platform 0x37, variant
                // 0x17) + IMAGE_TYPE bootloader + LIMITED_CCE 0 +
                // SBE_TYPE 1 (ECDSA). No 0xFF parameter check:
                // legacy devices take none, newgen take [0xFF];
                // either is a version query in bootloader mode.
                let mut ret = vec![0u8];
                ret.extend_from_slice(&[TLV_CNVI_BT, 4, 0x00, 0x00, 0x17, 0x37]);
                ret.extend_from_slice(&[TLV_IMAGE_TYPE, 1, IMG_TYPE_BOOTLOADER]);
                ret.extend_from_slice(&[TLV_LIMITED_CCE, 1, 0x00]);
                ret.extend_from_slice(&[TLV_SBE_TYPE, 1, 0x01]);
                self.enqueue_event(Self::cc(INTEL_OP_READ_VERSION, &ret));
            }
            INTEL_OP_READ_BOOT_PARAMS => {
                // 23-byte `intel_boot_params`: status + otp fields
                // + dev_revid 0x0001 + locks + 6-byte OTP BD_ADDR
                // (zero) + min build (0x35, 0x28, 0x18) +
                // limited_cce 0 + unlocked_state 0.
                let mut ret = vec![0u8, 0, 0, 0, 0x01, 0x00, 1, 0, 0, 0, 0, 0];
                ret.extend_from_slice(&[0; 6]);
                ret.extend_from_slice(&[0x35, 0x28, 0x18, 0, 0]);
                self.enqueue_event(Self::cc(INTEL_OP_READ_BOOT_PARAMS, &ret));
            }
            INTEL_OP_SECURE_SEND => {
                // params = [fragment type, chunk...]; chunk must
                // fit the 252-byte Secure Send budget.
                let ok = cmd.params.len() >= 2 && cmd.params.len() - 1 <= FRAGMENT_PAYLOAD_MAX;
                if !ok {
                    self.enqueue_event(Self::cc(INTEL_OP_SECURE_SEND, &[ERR_INVALID_PARAMS]));
                    return;
                }
                let frag_type = cmd.params[0];
                let chunk = &cmd.params[1..];
                if frag_type > 0x03 {
                    self.enqueue_event(Self::cc(INTEL_OP_SECURE_SEND, &[ERR_INVALID_PARAMS]));
                    return;
                }
                self.fw_bytes.lock()[frag_type as usize] += chunk.len();
                *self.secure_send_count.lock() += 1;
                if frag_type == FRAG_DATA {
                    self.fw_payload.lock().extend_from_slice(chunk);
                }
                self.enqueue_event(Self::cc(INTEL_OP_SECURE_SEND, &[0]));
            }
            INTEL_OP_RESET => {
                // params: {reset_type 0x00, patch_enable 0x01,
                // ddc_reload 0x00, boot_option 0x01, boot_param
                // LE u32} — and the boot address must be the one
                // the downloaded payload embedded.
                let boot_addr = self.boot_addr_from_payload();
                let ok = cmd.params.len() == 8
                    && cmd.params[..4] == [0x00, 0x01, 0x00, 0x01]
                    && boot_addr
                        == Some(u32::from_le_bytes([
                            cmd.params[4],
                            cmd.params[5],
                            cmd.params[6],
                            cmd.params[7],
                        ]));
                if !ok {
                    self.enqueue_event(Self::cc(INTEL_OP_RESET, &[ERR_INVALID_PARAMS]));
                    return;
                }
                *self.mode.lock() = FakeMode::Operational;
                self.enqueue_event(Self::cc(INTEL_OP_RESET, &[0]));
                // The boot emits the asynchronous vendor bootup
                // event (0xFF/0x02) the host must drain before
                // generic bring-up.
                self.enqueue_event(Event {
                    code: EVENT_VENDOR,
                    params: vec![INTEL_BOOTUP_SUBEVENT],
                });
            }
            _ => {
                // Bootloader mode only understands vendor
                // commands: a mandatory HCI command here means the
                // host skipped the firmware download. Answer with
                // an error so bring-up fails instead of passing.
                self.enqueue_event(Self::cc(cmd.opcode, &[0x01]));
            }
        }
    }

    fn answer_operational(&self, cmd: &Command) {
        match cmd.opcode {
            op::HCI_RESET => self.enqueue_event(Self::cc(op::HCI_RESET, &[0])),
            op::HCI_READ_LOCAL_VERSION => {
                // Status, HCI v5.3 (0x0C), rev 0x1234, LMP v5.3,
                // mfr 0x0002 (Intel), subver 0x5678.
                self.enqueue_event(Self::cc(
                    op::HCI_READ_LOCAL_VERSION,
                    &[0, 0x0C, 0x34, 0x12, 0x0C, 0x02, 0x00, 0x78, 0x56],
                ));
            }
            op::HCI_READ_BD_ADDR => {
                let mut ret = vec![0u8];
                ret.extend_from_slice(&FAKE_BD_ADDR);
                self.enqueue_event(Self::cc(op::HCI_READ_BD_ADDR, &ret));
            }
            op::HCI_READ_BUFFER_SIZE => {
                // Status, ACL MTU 1022, SCO MTU 64, ACL total 8,
                // SCO total 4.
                self.enqueue_event(Self::cc(
                    op::HCI_READ_BUFFER_SIZE,
                    &[0, 0xFE, 0x03, 64, 0x08, 0x00, 0x04, 0x00],
                ));
            }
            op::HCI_SET_EVENT_MASK => {
                self.enqueue_event(Self::cc(op::HCI_SET_EVENT_MASK, &[0]));
            }
            _ => {
                // Unmodelled command: recorded, unanswered (see
                // module docs).
            }
        }
    }
}

impl HciTransport for FakeUsbHci {
    fn send_command(&self, cmd: &Command) -> Result<(), TransportError> {
        // Model the USB transfer: the HCI command payload travels
        // as the Data stage of an EP0 control transfer whose Setup
        // packet is the Vol 4 Part B §2.2.1 shape, written here
        // from the spec (the test cross-checks it against the
        // production builder).
        let payload = cmd.encode();
        let setup = [
            SETUP_BM_REQUEST_TYPE,
            SETUP_B_REQUEST,
            0x00,
            0x00,
            self.endpoints.interface,
            0x00,
            (payload.len() & 0xFF) as u8,
            ((payload.len() >> 8) & 0xFF) as u8,
        ];
        self.control_transfers.lock().push((setup, payload));
        self.sent_commands.lock().push(cmd.clone());
        self.answer_command(cmd);
        Ok(())
    }

    fn recv_event(&self) -> Result<Option<Event>, TransportError> {
        let ev = self.events.lock().pop_front();
        if ev.is_some() {
            *self.interrupt_in_served.lock() += 1;
        }
        Ok(ev)
    }

    fn send_acl(&self, data: &[u8]) -> Result<(), TransportError> {
        if *self.bulk_out_disconnected.lock() {
            return Err(TransportError::EndpointStalled);
        }
        let ep = self.endpoints.acl_out_ep.unwrap_or(EP_ACL_OUT);
        self.bulk_out.lock().push((ep, data.to_vec()));
        Ok(())
    }

    fn recv_acl(&self) -> Result<Option<Vec<u8>>, TransportError> {
        let pkt = self.acl_inbox.lock().pop_front();
        if pkt.is_some() {
            *self.bulk_in_served.lock() += 1;
        }
        Ok(pkt)
    }

    fn name(&self) -> &'static str {
        "fake-usb-hci"
    }
}

// ── Test helpers ────────────────────────────────────────────────────

fn reset_all() {
    crate::transport::__test_reset();
    crate::controller::__test_reset_controllers();
    crate::pump::__test_reset();
}

/// Scan a Read Version return-params block for the IMAGE_TYPE TLV
/// (tag 0x15) — fixture-owned TLV walk, independent of any
/// production parser.
fn tlv_image_type(ret: &[u8]) -> Option<u8> {
    let mut i = 0usize;
    while i + 2 <= ret.len() {
        let tag = ret[i];
        let len = ret[i + 1] as usize;
        if i + 2 + len > ret.len() {
            return None;
        }
        if tag == TLV_IMAGE_TYPE && len == 1 {
            return Some(ret[i + 2]);
        }
        i += 2 + len;
    }
    None
}

/// Drive one HCI command through the fake and return its Command
/// Complete return parameters (status byte first).
fn command_and_complete(
    fake: &FakeUsbHci,
    opcode: u16,
    params: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let cmd = Command::with_params(opcode, params);
    fake.send_command(&cmd).map_err(|_| "send_command failed")?;
    let ev = fake
        .recv_event()
        .map_err(|_| "recv_event failed")?
        .ok_or("no Command Complete for vendor command")?;
    let cc = CommandComplete::parse(&ev).ok_or("event was not Command Complete")?;
    if cc.opcode != opcode {
        return Err("Command Complete opcode mismatch");
    }
    Ok(cc.return_params.to_vec())
}

/// The Intel newgen firmware download, scripted host-side from the
/// documented sequence (Linux `btusb_setup_intel_newgen`):
/// Read Version (bootloader) → Read Boot Params → Secure Send
/// fragments (≤252 B chunks) → Intel Reset with the embedded boot
/// address → drain the 0xFF/0x02 bootup event.
fn run_intel_firmware_download(fake: &FakeUsbHci, image: &[u8]) -> Result<(), &'static str> {
    // The loader validates the CSS header before sending anything.
    if image.len() < RSA_HEADER_LEN {
        return Err("image shorter than the RSA header");
    }
    if u32::from_le_bytes([image[8], image[9], image[10], image[11]]) != CSS_VER_RSA {
        return Err("image CSS version is not the RSA one");
    }

    let ret = command_and_complete(fake, INTEL_OP_READ_VERSION, &[0xFF])?;
    if ret.first() != Some(&0) {
        return Err("Read Version status != 0");
    }
    if tlv_image_type(&ret[1..]) != Some(IMG_TYPE_BOOTLOADER) {
        return Err("controller is not in bootloader mode");
    }

    let ret = command_and_complete(fake, INTEL_OP_READ_BOOT_PARAMS, &[])?;
    if ret.first() != Some(&0) || ret.len() < 23 {
        return Err("Read Boot Params reply too short or failed");
    }

    for (frag_type, offset, len) in fake_fragment_plan() {
        for chunk in image[offset..offset + len].chunks(FRAGMENT_PAYLOAD_MAX) {
            let mut params = vec![frag_type];
            params.extend_from_slice(chunk);
            let ret = command_and_complete(fake, INTEL_OP_SECURE_SEND, &params)?;
            if ret.first() != Some(&0) {
                return Err("Secure Send fragment NAKed");
            }
        }
    }

    let mut reset_params = vec![0x00, 0x01, 0x00, 0x01];
    reset_params.extend_from_slice(&FAKE_BOOT_ADDR.to_le_bytes());
    let ret = command_and_complete(fake, INTEL_OP_RESET, &reset_params)?;
    if ret.first() != Some(&0) {
        return Err("Intel Reset failed (boot address mismatch?)");
    }

    // Drain the asynchronous bootup event the reset emits; the
    // generic bring-up that follows expects its first event to be
    // its own Command Complete, so a leftover bootup event here
    // must fail the test, not leak into bring-up.
    let mut saw_bootup = false;
    for _ in 0..8 {
        let ev = fake
            .recv_event()
            .map_err(|_| "recv_event failed")?
            .ok_or("bootup event never arrived")?;
        if ev.code == EVENT_VENDOR && ev.params.first() == Some(&INTEL_BOOTUP_SUBEVENT) {
            saw_bootup = true;
            break;
        }
    }
    if !saw_bootup {
        return Err("Intel bootup event (0xFF/0x02) not seen");
    }
    if fake
        .recv_event()
        .map_err(|_| "recv_event failed")?
        .is_some()
    {
        return Err("stray event left after the bootup drain");
    }
    Ok(())
}

/// LE Connection Complete (LE Meta subevent 0x01) for `handle`.
fn le_connection_complete(handle: u16, peer: [u8; 6]) -> Event {
    let mut params = vec![0x01, 0x00];
    params.extend_from_slice(&handle.to_le_bytes());
    params.push(0x01); // role: Peripheral (we accepted)
    params.push(0x00); // peer address type: public
    params.extend_from_slice(&peer);
    params.extend_from_slice(&0x0028u16.to_le_bytes()); // interval 50 ms
    params.extend_from_slice(&0u16.to_le_bytes()); // latency
    params.extend_from_slice(&0x01F4u16.to_le_bytes()); // timeout 5 s
    params.push(0x00); // central clock accuracy
    Event {
        code: EventCode::LeMeta as u8,
        params,
    }
}

fn acl_packet(handle: u16, frame: &BFrame) -> Vec<u8> {
    AclData {
        handle,
        pb_flag: PB_COMPLETE_LE,
        bc_flag: 0,
        data: frame.encode(),
    }
    .encode()
}

/// Shared prefix of the end-to-end tests: attach the fake through
/// the production recogniser, run the firmware download, and bring
/// the controller up. Returns the fake on success.
fn attach_firmware_bringup() -> Result<Arc<FakeUsbHci>, &'static str> {
    reset_all();
    let desc = fake_config_descriptor(true, true, USB_CLASS_WIRELESS);
    if desc.len() != 39 {
        return Err("fixture descriptor length drifted from the unit smoke's 39 bytes");
    }
    if !usb_transport::is_bluetooth_hci(&desc) {
        return Err("recogniser rejected the fixture descriptor");
    }
    let eps =
        usb_transport::find_endpoints(&desc).ok_or("find_endpoints found no HCI interface")?;
    if eps.interface != 0
        || eps.event_ep != Some(EP_EVENT_IN)
        || eps.acl_in_ep != Some(EP_ACL_IN)
        || eps.acl_out_ep != Some(EP_ACL_OUT)
    {
        return Err("attach resolved the wrong endpoints");
    }
    let fake = Arc::new(FakeUsbHci::attach(eps));
    let transport: Arc<dyn HciTransport> = fake.clone();
    crate::transport::register(transport);

    let image = fake_firmware_image();
    run_intel_firmware_download(&fake, &image)?;
    if fake.mode() != FakeMode::Operational {
        return Err("fake did not reach operational mode after Intel Reset");
    }
    if fake.fw_bytes(FRAG_INIT) != 128
        || fake.fw_bytes(FRAG_PKEY) != 256
        || fake.fw_bytes(FRAG_SIGN) != 256
        || fake.fw_bytes(FRAG_DATA) != 16
    {
        return Err("firmware fragment byte counts wrong");
    }
    if fake.secure_send_count() != 6 {
        return Err("Secure Send command count wrong (want 6: 1+2+2+1 chunks)");
    }

    let cap = crate::bootstrap_bluetooth_authority();
    let outcomes = crate::controller::bring_up_all(&cap);
    if outcomes.len() != 1 || outcomes[0].result.is_err() {
        return Err("bring_up_all failed against the fake");
    }
    let info = outcomes[0]
        .result
        .as_ref()
        .map_err(|_| "bring_up_all failed")?;
    if info.bd_addr != FAKE_BD_ADDR {
        return Err("BD_ADDR not captured from bring-up");
    }
    if crate::controller::controller_count() != 1 {
        return Err("controller registry should hold exactly one controller");
    }
    if crate::pump::connection_count(0) != Some(0) {
        return Err("pump did not adopt the brought-up controller");
    }
    // The mandatory bring-up is the tail of the command trace: the
    // firmware download's 9 commands precede it.
    let sent = fake.sent_opcodes();
    let want_tail = [
        op::HCI_RESET,
        op::HCI_READ_LOCAL_VERSION,
        op::HCI_READ_BD_ADDR,
        op::HCI_READ_BUFFER_SIZE,
        op::HCI_SET_EVENT_MASK,
    ];
    if sent.len() != 14 || sent[9..] != want_tail {
        return Err("bring-up command order/count drifted");
    }
    // Every control transfer's Setup packet must equal the
    // spec-literal shape for its payload length — and agree with
    // the production builder, so a wrong production constant
    // fails here instead of being mirrored.
    for (setup, payload) in fake.control_transfers() {
        let want = [
            SETUP_BM_REQUEST_TYPE,
            SETUP_B_REQUEST,
            0x00,
            0x00,
            eps.interface,
            0x00,
            (payload.len() & 0xFF) as u8,
            ((payload.len() >> 8) & 0xFF) as u8,
        ];
        if setup != want {
            return Err("control Setup packet != Vol 4 Part B §2.2.1 shape");
        }
        if setup != usb_transport::hci_command_setup(eps.interface, payload.len() as u16) {
            return Err("production hci_command_setup disagrees with the spec-literal Setup");
        }
    }
    Ok(fake)
}

// ── 1. Attach: descriptor → endpoints, and the rejections ───────────

fn smoke_fake_usb_hci_attach_endpoints() -> TestResult {
    let desc = fake_config_descriptor(true, true, USB_CLASS_WIRELESS);
    if !usb_transport::is_bluetooth_hci(&desc) {
        return TestResult::Fail("recogniser rejected the HCI class triple");
    }
    let eps = match usb_transport::find_endpoints(&desc) {
        Some(e) => e,
        None => return TestResult::Fail("find_endpoints found no HCI interface"),
    };
    if eps.interface != 0
        || eps.event_ep != Some(EP_EVENT_IN)
        || eps.acl_in_ep != Some(EP_ACL_IN)
        || eps.acl_out_ep != Some(EP_ACL_OUT)
    {
        return TestResult::Fail("endpoint addresses wrong");
    }

    // No interrupt-IN endpoint: attach must reject (events would
    // have no pipe — the disconnect the old tests could not see).
    let no_event = fake_config_descriptor(false, true, USB_CLASS_WIRELESS);
    if usb_transport::find_endpoints(&no_event).is_some() {
        return TestResult::Fail("attach accepted a descriptor with no event endpoint");
    }
    // No ACL endpoints: same.
    let no_acl = fake_config_descriptor(true, false, USB_CLASS_WIRELESS);
    if usb_transport::find_endpoints(&no_acl).is_some() {
        return TestResult::Fail("attach accepted a descriptor with no ACL endpoints");
    }
    // Non-Bluetooth interface class: not an HCI device at all.
    let not_bt = fake_config_descriptor(true, true, 0xFF);
    if usb_transport::is_bluetooth_hci(&not_bt) || usb_transport::find_endpoints(&not_bt).is_some()
    {
        return TestResult::Fail("recogniser accepted a non-Bluetooth class triple");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/fake-usb-hci",
    smoke_fake_usb_hci_attach_endpoints
);

// ── 2. End to end: attach → firmware → bring-up → pump ──────────────

fn smoke_fake_usb_hci_e2e_attach_firmware_bringup_pump() -> TestResult {
    let fake = match attach_firmware_bringup() {
        Ok(f) => f,
        Err(e) => {
            reset_all();
            return TestResult::Fail(e);
        }
    };

    // Peer connects (LE), then speaks ATT and SMP — the same
    // conversation the pump's HCI-seam test drives, now over the
    // USB-routed transport.
    let handle = 0x0040;
    fake.enqueue_event(le_connection_complete(
        handle,
        [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],
    ));
    let mtu_req = att::Pdu {
        opcode: att::ATT_EXCHANGE_MTU_REQ,
        params: 512u16.to_le_bytes().to_vec(),
    };
    fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_ATT, mtu_req.encode())));
    let pairing_req = smp::PairingFeatureExchange {
        io_capability: smp::IoCapability::NoInputNoOutput as u8,
        oob_data_flag: 0,
        auth_req: smp::AUTH_BONDING | smp::AUTH_SC,
        max_encryption_key_size: 16,
        initiator_key_distribution: 0,
        responder_key_distribution: 0,
    }
    .encode(smp::SMP_PAIRING_REQUEST);
    fake.enqueue_acl(acl_packet(
        handle,
        &BFrame::new(CID_SMP, pairing_req.encode()),
    ));

    let step = crate::pump::pump_once(0);
    let fail = |msg: &'static str| {
        reset_all();
        TestResult::Fail(msg)
    };
    if step.events != 1 || step.acl_received != 2 || step.acl_sent != 2 {
        return fail("pump step counts mismatch");
    }
    if crate::pump::connection_count(0) != Some(1) {
        return fail("pump did not track the LE connection");
    }
    if !crate::pump::is_attached(0) {
        return fail("pump did not mark the USB controller attached");
    }
    // Raw-socket fan-out carries the connection event verbatim.
    match crate::hci_sock::drain_event(0) {
        Some(pkt) if pkt.len() > 3 && pkt[0] == 0x04 && pkt[1] == 0x3E => {}
        _ => return fail("socket fan-out lost the connection event"),
    }
    // Host -> controller bytes: ATT MTU response then SMP Pairing
    // Response, both on the connection's handle — and both left
    // on the bulk-OUT endpoint the descriptor resolved.
    let frames: Vec<(u16, BFrame)> = fake
        .bulk_out_transfers()
        .iter()
        .filter_map(|(ep, bytes)| {
            if *ep != EP_ACL_OUT {
                return None;
            }
            AclData::decode(bytes)
                .and_then(|acl| BFrame::decode(&acl.data).map(|f| (acl.handle, f)))
        })
        .collect();
    let ok = frames.len() == 2
        && frames[0].0 == handle
        && frames[0].1.cid == CID_ATT
        && frames[0].1.payload.first() == Some(&att::ATT_EXCHANGE_MTU_RSP)
        && frames[1].0 == handle
        && frames[1].1.cid == CID_SMP
        && frames[1].1.payload.first() == Some(&smp::SMP_PAIRING_RESPONSE);
    if !ok {
        return fail("pump responses missing, misrouted, or off the bulk-OUT endpoint");
    }
    // USB-level accounting: every event the host consumed came off
    // the interrupt-IN endpoint (9 firmware CCs + bootup + 5
    // bring-up CCs + 1 connection event), every inbound ACL off
    // bulk-IN, every outbound ACL onto bulk-OUT.
    if fake.interrupt_in_served() != 16 {
        return fail("interrupt-IN event count wrong");
    }
    if fake.bulk_in_served() != 2 {
        return fail("bulk-IN ACL count wrong");
    }
    if fake.bulk_out_transfers().len() != 2 {
        return fail("bulk-OUT ACL count wrong");
    }

    // Disconnect tears the connection state down.
    fake.enqueue_event(Event {
        code: EventCode::DisconnectionComplete as u8,
        params: vec![0x00, 0x40, 0x00, 0x13],
    });
    let _ = crate::pump::pump_once(0);
    let gone = crate::pump::connection_count(0) == Some(0);
    reset_all();
    if !gone {
        return TestResult::Fail("connection state survived disconnect");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/fake-usb-hci",
    smoke_fake_usb_hci_e2e_attach_firmware_bringup_pump
);

// ── 3. Negative: bulk-OUT disconnect fails the pump ─────────────────
//
// The disconnect the old tests could not see: bring-up still
// succeeds (commands/events never touch bulk), but the pump's ACL
// replies have nowhere to go, so the step must report it instead
// of passing silently.

fn smoke_fake_usb_hci_bulk_out_disconnect_fails_pump() -> TestResult {
    let fake = match attach_firmware_bringup() {
        Ok(f) => f,
        Err(e) => {
            reset_all();
            return TestResult::Fail(e);
        }
    };
    let fail = |msg: &'static str| {
        reset_all();
        TestResult::Fail(msg)
    };
    fake.disconnect_bulk_out();

    let handle = 0x0040;
    fake.enqueue_event(le_connection_complete(
        handle,
        [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],
    ));
    let mtu_req = att::Pdu {
        opcode: att::ATT_EXCHANGE_MTU_REQ,
        params: 512u16.to_le_bytes().to_vec(),
    };
    fake.enqueue_acl(acl_packet(handle, &BFrame::new(CID_ATT, mtu_req.encode())));

    let step = crate::pump::pump_once(0);
    if step.acl_received != 1 {
        return fail("inbound ACL was not received");
    }
    if step.acl_sent != 0 {
        return fail("pump claimed ACL sent with bulk-OUT disconnected");
    }
    if !fake.bulk_out_transfers().is_empty() {
        return fail("ACL bytes reached bulk-OUT despite the disconnect");
    }
    let stats = match crate::pump::stats(0) {
        Some(s) => s,
        None => return fail("no pump stats for controller 0"),
    };
    if stats.transport_errors == 0 {
        return fail("pump recorded no transport error for the dead bulk-OUT");
    }
    // The connection itself still tracks: the disconnect is on
    // the data plane, not the connection state.
    if crate::pump::connection_count(0) != Some(1) {
        return fail("connection state lost on a data-plane disconnect");
    }
    reset_all();
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/fake-usb-hci",
    smoke_fake_usb_hci_bulk_out_disconnect_fails_pump
);

// ── 4. Negative: bring-up before firmware fails ─────────────────────
//
// A host that skips the firmware download and goes straight to
// the mandatory sequence must fail: the bootloader only answers
// vendor commands, so HCI_Reset comes back an error.

fn smoke_fake_usb_hci_bringup_before_firmware_fails() -> TestResult {
    reset_all();
    let desc = fake_config_descriptor(true, true, USB_CLASS_WIRELESS);
    let eps = match usb_transport::find_endpoints(&desc) {
        Some(e) => e,
        None => {
            reset_all();
            return TestResult::Fail("find_endpoints found no HCI interface");
        }
    };
    let fake = Arc::new(FakeUsbHci::attach(eps));
    let transport: Arc<dyn HciTransport> = fake.clone();
    crate::transport::register(transport);

    let cap = crate::bootstrap_bluetooth_authority();
    let outcomes = crate::controller::bring_up_all(&cap);
    let failed = outcomes.len() == 1 && outcomes[0].result.is_err();
    let no_controller = crate::controller::controller_count() == 0;
    let no_pump = crate::pump::connection_count(0).is_none();
    reset_all();
    if !failed {
        return TestResult::Fail("bring-up succeeded without firmware download");
    }
    if !no_controller {
        return TestResult::Fail("controller registered despite failed bring-up");
    }
    if !no_pump {
        return TestResult::Fail("pump adopted a controller that never came up");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bluetooth/fake-usb-hci",
    smoke_fake_usb_hci_bringup_before_firmware_fails
);

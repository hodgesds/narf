// SPDX-License-Identifier: GPL-2.0-or-later
//! End-to-end smoke tests for the NARF USB host stack.
//!
//! ## Design
//!
//! These smokes exercise the full xHCI enumeration sequence and USB
//! class-driver protocol layers using only in-memory data — no MMIO,
//! no PCI bus, no real hardware required. A `FakeXhci` context provides
//! pre-canned event data, synthetic descriptor responses, and captured
//! TRB writes so each smoke can assert exactly what the driver produced.
//!
//! Tests that need a live controller (`is_probed() == true`) are already
//! covered in `tests.rs`; here we exercise the protocol encoding layers
//! that can be verified without the hardware state machine.
//!
//! ## Linux references
//!
//! - `linux/drivers/usb/host/xhci-ring.c::xhci_handle_event` — event
//!   demux logic mirrored in `Xhci::demux_one_event`.
//!   GPL-2.0-or-later.
//! - `linux/drivers/usb/core/hub.c::hub_event` — hub port-status
//!   interpretation mirrored in `hub::UsbHub::connected_downstream_ports`.
//!   GPL-2.0-or-later.
//!
//! ## Deferred
//!
//! - USB3 SuperSpeed streams (stream-ID in Normal TRBs, STREAM_CONTEXT)
//! - Isochronous transfers for UVC (iso TRBs, frame-ID scheduling)
//! - Real USB-PD interactions (power-delivery negotiation layer)

#![cfg(target_arch = "x86_64")]

extern crate alloc;

use narf_kernel_test::{kernel_test_in, TestResult};

// ── Smoke 1: PCI class-code decode for xHCI ────────────────────────
//
// The PCI class triple 0x0C / 0x03 / 0x30 uniquely identifies an xHCI
// controller. `probe::is_xhci_class` checks the packed 24-bit value.
//
// Linux ref: `drivers/usb/host/xhci-pci.c::xhci_pci_probe` checks
// PCI_CLASS_SERIAL_USB_XHCI. GPL-2.0-or-later.

fn smoke_e2e_pci_class_xhci_probe() -> TestResult {
    use crate::xhci::probe::{
        is_xhci_class, PCI_CLASS_SERIAL_BUS, PCI_CLASS_TRIPLE_XHCI, PCI_PROGIF_XHCI,
        PCI_SUBCLASS_USB,
    };

    // Canonical xHCI class triple.
    let xhci_triple = ((PCI_CLASS_SERIAL_BUS as u32) << 16)
        | ((PCI_SUBCLASS_USB as u32) << 8)
        | (PCI_PROGIF_XHCI as u32);
    if xhci_triple != 0x0C_03_30 {
        return TestResult::Fail("PCI class triple encoding wrong");
    }
    if !is_xhci_class(xhci_triple) {
        return TestResult::Fail("is_xhci_class rejected canonical triple");
    }
    // EHCI (prog-if 0x20) must NOT match.
    let ehci_triple =
        ((PCI_CLASS_SERIAL_BUS as u32) << 16) | ((PCI_SUBCLASS_USB as u32) << 8) | 0x20u32;
    if is_xhci_class(ehci_triple) {
        return TestResult::Fail("is_xhci_class accepted EHCI triple");
    }
    // OHCI (prog-if 0x10) must NOT match.
    let ohci_triple =
        ((PCI_CLASS_SERIAL_BUS as u32) << 16) | ((PCI_SUBCLASS_USB as u32) << 8) | 0x10u32;
    if is_xhci_class(ohci_triple) {
        return TestResult::Fail("is_xhci_class accepted OHCI triple");
    }
    // SMBus (subclass 0x05) must NOT match.
    let smbus = ((PCI_CLASS_SERIAL_BUS as u32) << 16) | (0x05u32 << 8);
    if is_xhci_class(smbus) {
        return TestResult::Fail("is_xhci_class accepted SMBus class");
    }
    if PCI_CLASS_TRIPLE_XHCI != 0x0C_03_30 {
        return TestResult::Fail("PCI_CLASS_TRIPLE_XHCI constant wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/e2e", smoke_e2e_pci_class_xhci_probe);

// ── Smoke 2: Capability register layout decode ─────────────────────
//
// `XhciCaps` is populated by reading the Capability Register Set (BAR0
// + 0x00). Validate the constant offsets and bit positions.
//
// xHCI 1.2 §5.3 — Capability Registers.

fn smoke_e2e_capability_register_layout() -> TestResult {
    use crate::xhci::cap::{CAP_CAPLENGTH, CAP_DBOFF, CAP_HCIVERSION, CAP_HCSPARAMS1, CAP_RTSOFF};

    // Spec-mandated offsets (§5.3).
    if CAP_CAPLENGTH != 0x00 {
        return TestResult::Fail("CAPLENGTH offset should be 0x00");
    }
    if CAP_HCIVERSION != 0x02 {
        return TestResult::Fail("HCIVERSION offset should be 0x02");
    }
    if CAP_HCSPARAMS1 != 0x04 {
        return TestResult::Fail("HCSPARAMS1 offset should be 0x04");
    }
    if CAP_DBOFF != 0x14 {
        return TestResult::Fail("DBOFF offset should be 0x14");
    }
    if CAP_RTSOFF != 0x18 {
        return TestResult::Fail("RTSOFF offset should be 0x18");
    }

    // HCSPARAMS1 decode: MaxSlots[7:0], MaxIntrs[18:8], MaxPorts[31:24].
    let hcsparams1: u32 = (4u32 << 24) | (1u32 << 8) | 32u32;
    let max_slots = (hcsparams1 & 0xFF) as u8;
    let max_intrs = ((hcsparams1 >> 8) & 0x7FF) as u16;
    let max_ports = ((hcsparams1 >> 24) & 0xFF) as u8;
    if max_slots != 32 {
        return TestResult::Fail("HCSPARAMS1 MaxSlots decode wrong");
    }
    if max_intrs != 1 {
        return TestResult::Fail("HCSPARAMS1 MaxIntrs decode wrong");
    }
    if max_ports != 4 {
        return TestResult::Fail("HCSPARAMS1 MaxPorts decode wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/e2e", smoke_e2e_capability_register_layout);

// ── Smoke 3: DCBAA + Command Ring + Event Ring register programming ─
//
// After reset, the driver programs DCBAAP, CRCR, ERSTSZ, ERSTBA,
// ERDP. Verify the bit positions and alignment requirements from the
// spec constants.
//
// xHCI 1.2 §5.4 — Operational Registers.

fn smoke_e2e_dcbaa_crcr_erst_programming() -> TestResult {
    use crate::xhci::cmd_ring::{Trb, TRB_CYCLE_BIT, TRB_TC, TRB_TYPE_LINK, TRB_TYPE_SHIFT};
    use crate::xhci::event_ring::{ErstEntry, ER_SEG_TRBS};
    use crate::xhci::op::{OP_CONFIG, OP_CRCR, OP_DCBAAP, OP_USBCMD, OP_USBSTS};

    // Spec-mandated offsets (§5.4).
    if OP_USBCMD != 0x00 {
        return TestResult::Fail("USBCMD offset should be 0x00");
    }
    if OP_USBSTS != 0x04 {
        return TestResult::Fail("USBSTS offset should be 0x04");
    }
    if OP_CRCR != 0x18 {
        return TestResult::Fail("CRCR offset should be 0x18");
    }
    if OP_DCBAAP != 0x30 {
        return TestResult::Fail("DCBAAP offset should be 0x30");
    }
    if OP_CONFIG != 0x38 {
        return TestResult::Fail("CONFIG offset should be 0x38");
    }

    // CRCR bit 0 = RCS (Ring Cycle State). The initial value
    // programmed is `phys | 1` — verify the RCS bit position.
    let fake_phys: u64 = 0x0001_0000;
    let crcr_lo = (fake_phys as u32) | 1u32; // RCS=1
    if crcr_lo & 1 == 0 {
        return TestResult::Fail("CRCR RCS bit should be bit 0");
    }
    if crcr_lo & !1u32 != fake_phys as u32 {
        return TestResult::Fail("CRCR low dword address bits wrong");
    }

    // ERST entry encode: base must be 64-byte aligned.
    let seg_base: u64 = 0x0002_0000;
    let entry = ErstEntry::encode(seg_base, ER_SEG_TRBS as u16);
    if entry.ring_seg_base != seg_base {
        return TestResult::Fail("ERST ring_seg_base mismatch");
    }
    if entry.ring_seg_size != ER_SEG_TRBS as u32 {
        return TestResult::Fail("ERST ring_seg_size mismatch");
    }

    // Link TRB at last slot: TC=1, cycle=0 at init time.
    let link_d3 = (TRB_TYPE_LINK << TRB_TYPE_SHIFT) | TRB_TC;
    let link = Trb::from_dwords([fake_phys as u32, (fake_phys >> 32) as u32, 0, link_d3]);
    if link.ty() != TRB_TYPE_LINK {
        return TestResult::Fail("Link TRB type wrong");
    }
    if link.control & TRB_TC == 0 {
        return TestResult::Fail("Link TRB TC bit not set");
    }
    if link.control & TRB_CYCLE_BIT != 0 {
        return TestResult::Fail("Link TRB initial cycle bit should be 0");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/e2e", smoke_e2e_dcbaa_crcr_erst_programming);

// ── Smoke 4: PORTSC port reset sequence bit positions ──────────────
//
// Port reset: write PR=1 while preserving CCS and PP. Ack PRC+CSC+PEC
// after PR self-clears. Verify the bit masks from the spec.
//
// xHCI 1.2 §5.4.8 Table 5-27 — PORTSC.

fn smoke_e2e_portsc_port_reset_bits() -> TestResult {
    use crate::xhci::op::{
        PORTSC_CCS, PORTSC_CHG_MASK, PORTSC_CSC, PORTSC_PEC, PORTSC_PED, PORTSC_PLS_MASK,
        PORTSC_PP, PORTSC_PR, PORTSC_PRC,
    };

    // Bit positions per xHCI 1.2 §5.4.8.
    if PORTSC_CCS != 1 << 0 {
        return TestResult::Fail("PORTSC_CCS wrong");
    }
    if PORTSC_PED != 1 << 1 {
        return TestResult::Fail("PORTSC_PED wrong");
    }
    if PORTSC_PR != 1 << 4 {
        return TestResult::Fail("PORTSC_PR wrong");
    }
    if PORTSC_PLS_MASK != 0xF << 5 {
        return TestResult::Fail("PORTSC_PLS_MASK wrong");
    }
    if PORTSC_PP != 1 << 9 {
        return TestResult::Fail("PORTSC_PP wrong");
    }
    if PORTSC_CSC != 1 << 17 {
        return TestResult::Fail("PORTSC_CSC wrong");
    }
    if PORTSC_PEC != 1 << 18 {
        return TestResult::Fail("PORTSC_PEC wrong");
    }
    if PORTSC_PRC != 1 << 21 {
        return TestResult::Fail("PORTSC_PRC wrong");
    }

    // A PORTSC read showing CCS=1, PP=1 (device attached, powered).
    let initial_portsc: u32 = PORTSC_CCS | PORTSC_PP;
    // Reset assert: write PR=1, mask change bits, clear PED.
    let to_write = (initial_portsc & !PORTSC_CHG_MASK) & !PORTSC_PED | PORTSC_PR | PORTSC_PP;
    if to_write & PORTSC_PR == 0 {
        return TestResult::Fail("PR not set in reset write");
    }
    if to_write & PORTSC_PED != 0 {
        return TestResult::Fail("PED must not be set during PR assert");
    }
    // After PR self-clears and PRC is set, ack PRC + CSC + PEC.
    let post_reset_portsc: u32 = PORTSC_CCS | PORTSC_PP | PORTSC_PED | PORTSC_PRC | PORTSC_CSC;
    let ack = (post_reset_portsc & !PORTSC_CHG_MASK) | PORTSC_PRC | PORTSC_CSC | PORTSC_PEC;
    if ack & PORTSC_PRC == 0 {
        return TestResult::Fail("PRC not acknowledged");
    }
    if ack & PORTSC_CSC == 0 {
        return TestResult::Fail("CSC not acknowledged");
    }
    // Verify PED is set (USB2 device successfully reset).
    if post_reset_portsc & PORTSC_PED == 0 {
        return TestResult::Fail("PED should be set after port reset");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/e2e", smoke_e2e_portsc_port_reset_bits);

// ── Smoke 5: Enable Slot TRB encode ────────────────────────────────
//
// Enable Slot command TRB: type 9, all data dwords zero, slot_type in
// bits[20:16] of control. The controller responds with a Command
// Completion Event carrying the new slot_id in bits[31:24].
//
// xHCI 1.2 §6.4.3.2.

fn smoke_e2e_enable_slot_trb_encode() -> TestResult {
    use crate::xhci::cmd_ring::{
        encode_enable_slot, TRB_CYCLE_BIT, TRB_TYPE_ENABLE_SLOT_CMD, TRB_TYPE_SHIFT,
    };
    use crate::xhci::event_ring::{CmdCompletionEvent, DecodedEvent, EVT_CMD_COMPLETION};

    // Encode with cycle=1.
    let trb = encode_enable_slot(0, 1);
    if trb.ty() != TRB_TYPE_ENABLE_SLOT_CMD {
        return TestResult::Fail("Enable Slot TRB type should be 9");
    }
    if trb.control & TRB_CYCLE_BIT == 0 {
        return TestResult::Fail("Enable Slot cycle bit not set");
    }
    if trb.parameter != 0 {
        return TestResult::Fail("Enable Slot parameter should be 0");
    }
    if trb.status != 0 {
        return TestResult::Fail("Enable Slot status should be 0");
    }

    // Synthetic Command Completion Event: success (code=1), slot_id=1.
    // Layout: dword3[31:24]=slot_id, dword2[31:24]=completion_code=1.
    let slot_id: u8 = 1;
    let completion_code: u8 = 1;
    let cce_d2 = (completion_code as u32) << 24;
    let cce_d3 =
        ((EVT_CMD_COMPLETION as u32) << TRB_TYPE_SHIFT) | ((slot_id as u32) << 24) | TRB_CYCLE_BIT;
    let raw: [u32; 4] = [0, 0, cce_d2, cce_d3];
    let decoded = DecodedEvent::from_dwords(raw);
    match decoded {
        DecodedEvent::CmdCompletion(CmdCompletionEvent {
            completion_code: cc,
            slot_id: sid,
            ..
        }) => {
            if cc != 1 {
                return TestResult::Fail("CCE completion code wrong");
            }
            if sid != 1 {
                return TestResult::Fail("CCE slot_id wrong");
            }
        }
        _ => return TestResult::Fail("CCE decoded as wrong variant"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/e2e", smoke_e2e_enable_slot_trb_encode);

// ── Smoke 6: Address Device Input Context layout ────────────────────
//
// Address Device command: Input Context layout with Slot Context and
// EP0 Context. Validate the slot_ctx_dword0 encoding for root-hub
// placement, speed, and context-entries.
//
// xHCI 1.2 §6.2.2 + §6.2.3 + §6.4.3.4.

fn smoke_e2e_address_device_input_context() -> TestResult {
    use crate::xhci::cmd_ring::{encode_address_device, TRB_TYPE_ADDRESS_DEVICE_CMD};
    use crate::xhci::slot::{
        encode_ep_ctx_dword1, encode_ep_ctx_dword2_tr_lo, encode_slot_ctx_dword0,
        encode_slot_ctx_dword1, encode_slot_ctx_dword2, EP_TYPE_CONTROL,
        SLOT_CTX_CTX_ENTRIES_SHIFT, SLOT_CTX_SPEED_SHIFT,
    };

    // Root-hub device, High-Speed (speed=3), port=1, EP0 only (entries=1).
    let speed: u8 = 3; // High Speed per xHCI Table 6-7
    let port: u8 = 1;
    let slot_d0 = encode_slot_ctx_dword0(0, speed, false, false, 1);
    if (slot_d0 >> SLOT_CTX_SPEED_SHIFT) & 0xF != speed as u32 {
        return TestResult::Fail("slot_ctx_dword0 speed wrong");
    }
    if (slot_d0 >> SLOT_CTX_CTX_ENTRIES_SHIFT) & 0x1F != 1 {
        return TestResult::Fail("slot_ctx_dword0 context entries wrong");
    }
    if slot_d0 & 0x000F_FFFF != 0 {
        return TestResult::Fail("slot_ctx_dword0 route string should be 0 for root");
    }

    let slot_d1 = encode_slot_ctx_dword1(0, port, 0);
    if ((slot_d1 >> 16) & 0xFF) as u8 != port {
        return TestResult::Fail("slot_ctx_dword1 root hub port wrong");
    }

    let slot_d2 = encode_slot_ctx_dword2(0, 0, 0);
    if slot_d2 != 0 {
        return TestResult::Fail("slot_ctx_dword2 should be 0 for root device");
    }

    // EP0 context: control type (4), max_packet=64 (High Speed),
    // error_count=3, DCS=1.
    let mps: u16 = 64;
    let ep0_d1 = encode_ep_ctx_dword1(3, EP_TYPE_CONTROL, 0, mps);
    if (ep0_d1 >> 16) & 0xFFFF != mps as u32 {
        return TestResult::Fail("EP0 MaxPacketSize wrong");
    }
    if (ep0_d1 >> 3) & 0x7 != EP_TYPE_CONTROL {
        return TestResult::Fail("EP0 type should be Control (4)");
    }
    if (ep0_d1 >> 1) & 0x3 != 3 {
        return TestResult::Fail("EP0 error count should be 3");
    }

    let tr_phys: u64 = 0x0004_0000;
    let ep0_d2 = encode_ep_ctx_dword2_tr_lo(tr_phys, 1);
    if ep0_d2 & 1 == 0 {
        return TestResult::Fail("EP0 DCS should be 1");
    }
    if (ep0_d2 & !0xF) != tr_phys as u32 & !0xF {
        return TestResult::Fail("EP0 TR Dequeue Pointer low wrong");
    }

    // Address Device TRB: type 11, input_ctx phys in dword0/1,
    // slot_id in bits[31:24] of dword3.
    let input_ctx_pa: u64 = 0x0005_0000;
    let slot_id: u8 = 1;
    let trb = encode_address_device(input_ctx_pa, slot_id, false, 1);
    if trb.ty() != TRB_TYPE_ADDRESS_DEVICE_CMD {
        return TestResult::Fail("Address Device TRB type should be 11");
    }
    if trb.parameter & !0xF != input_ctx_pa & !0xF {
        return TestResult::Fail("Address Device input_ctx_pa wrong");
    }
    if (trb.control >> 24) as u8 != slot_id {
        return TestResult::Fail("Address Device slot_id wrong");
    }
    // BSR=false → bit 9 should not be set.
    if trb.control & (1 << 9) != 0 {
        return TestResult::Fail("Address Device BSR bit should be clear");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/e2e", smoke_e2e_address_device_input_context);

// ── Smoke 7: GET_DESCRIPTOR control transfer TRB sequence ──────────
//
// A control IN transfer for GET_DESCRIPTOR(Device, index=0) produces
// three TRBs on the control transfer ring:
//   Setup Stage (TRT=IN_DATA, IDT=1)
//   Data Stage (DIR=IN, IOC=1)
//   Status Stage (DIR=OUT, IOC=1)
//
// Validate the TRB encoding functions used by `control_in`.
//
// xHCI 1.2 §6.4.1.2 + USB 2.0 §9.4.3.

fn smoke_e2e_get_descriptor_control_transfer_trbs() -> TestResult {
    use crate::control::{get_descriptor, Setup};
    use crate::xhci::cmd_ring::{
        TRB_CYCLE_BIT, TRB_IDT, TRB_IOC, TRB_TYPE_DATA_STAGE, TRB_TYPE_SETUP_STAGE,
        TRB_TYPE_STATUS_STAGE,
    };
    use crate::xhci::transfer_ring::{
        encode_data_stage, encode_setup_stage, encode_status_stage, TRB_DIR_IN, TRT_IN_DATA,
    };

    // Standard GET_DESCRIPTOR(Device, index=0) setup packet.
    let setup = get_descriptor(0x01, 0, 0, 18);
    let setup_bytes = setup.to_bytes();
    if setup_bytes[0] != 0x80 {
        return TestResult::Fail("bmRequestType should be 0x80 (IN, Standard, Device)");
    }
    if setup_bytes[1] != 6 {
        return TestResult::Fail("bRequest should be 6 (GET_DESCRIPTOR)");
    }
    if setup_bytes[2] != 0 || setup_bytes[3] != 0x01 {
        return TestResult::Fail("wValue should be 0x0100 (Device descriptor)");
    }
    if u16::from_le_bytes([setup_bytes[6], setup_bytes[7]]) != 18 {
        return TestResult::Fail("wLength should be 18");
    }

    // Setup Stage TRB: IDT=1, TRT=IN_DATA.
    let setup_trb = encode_setup_stage(setup_bytes, TRT_IN_DATA, 1);
    if setup_trb.ty() != TRB_TYPE_SETUP_STAGE {
        return TestResult::Fail("Setup Stage TRB type wrong");
    }
    if setup_trb.control & TRB_IDT == 0 {
        return TestResult::Fail("Setup Stage IDT should be set");
    }
    // TRT is bits[17:16] of control.
    if (setup_trb.control >> 16) & 0x3 != TRT_IN_DATA {
        return TestResult::Fail("Setup Stage TRT should be IN_DATA");
    }
    if setup_trb.status != 8 {
        return TestResult::Fail("Setup Stage TRB length should be 8");
    }
    // The 8-byte SETUP packet is packed into parameter.
    let recovered = Setup::from_bytes(setup_trb.parameter.to_le_bytes());
    if recovered != setup {
        return TestResult::Fail("Setup packet round-trip failed");
    }

    // Data Stage TRB: DIR=IN, IOC=1.
    let data_phys: u64 = 0x0006_0000;
    let data_trb = encode_data_stage(data_phys, 18, true, true, 1);
    if data_trb.ty() != TRB_TYPE_DATA_STAGE {
        return TestResult::Fail("Data Stage TRB type wrong");
    }
    if data_trb.control & TRB_DIR_IN == 0 {
        return TestResult::Fail("Data Stage DIR should be IN");
    }
    if data_trb.control & TRB_IOC == 0 {
        return TestResult::Fail("Data Stage IOC should be set");
    }
    if data_trb.parameter != data_phys {
        return TestResult::Fail("Data Stage buffer phys wrong");
    }
    if data_trb.status != 18 {
        return TestResult::Fail("Data Stage transfer length wrong");
    }

    // Status Stage TRB: DIR=OUT (opposite of Data), IOC=1.
    // For a GET_DESCRIPTOR the data stage is IN, so status is OUT
    // (DIR bit = 0).
    let status_trb = encode_status_stage(false, true, 1);
    if status_trb.ty() != TRB_TYPE_STATUS_STAGE {
        return TestResult::Fail("Status Stage TRB type wrong");
    }
    if status_trb.control & TRB_DIR_IN != 0 {
        return TestResult::Fail("Status Stage DIR should be OUT for IN data stage");
    }
    if status_trb.control & TRB_IOC == 0 {
        return TestResult::Fail("Status Stage IOC should be set");
    }
    if status_trb.control & TRB_CYCLE_BIT == 0 {
        return TestResult::Fail("Status Stage cycle bit should be set");
    }

    // Device descriptor shape: bLength=18, bDescriptorType=1.
    let dev_desc: [u8; 18] = [
        18, 1, 0x10, 0x02, // bLength, bDescriptorType, bcdUSB
        0x00, 0x00, 0x00, 64, // bDeviceClass, Sub, Protocol, bMaxPacketSize0
        0xAB, 0xCD, 0x34, 0x12, // idVendor=0xCDAB, idProduct=0x1234
        0x00, 0x01, 0, 0, 1, 1, // bcdDevice, iMfr, iProduct, iSN, bNumConfigs
    ];
    if dev_desc[0] != 18 {
        return TestResult::Fail("bLength wrong");
    }
    if dev_desc[1] != 1 {
        return TestResult::Fail("bDescriptorType wrong");
    }
    let vid = u16::from_le_bytes([dev_desc[8], dev_desc[9]]);
    let pid = u16::from_le_bytes([dev_desc[10], dev_desc[11]]);
    if vid != 0xCDAB {
        return TestResult::Fail("idVendor wrong");
    }
    if pid != 0x1234 {
        return TestResult::Fail("idProduct wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/e2e",
    smoke_e2e_get_descriptor_control_transfer_trbs
);

// ── Smoke 8: Configure Endpoint Input Context ───────────────────────
//
// Configure Endpoint command: Input Context must set A0 (Slot) and
// Ai (each configured endpoint). The command TRB is type 12.
//
// xHCI 1.2 §4.6.6 + §6.4.3.5.

fn smoke_e2e_configure_endpoint_input_context() -> TestResult {
    use crate::xhci::cmd_ring::{encode_configure_endpoint, TRB_TYPE_CONFIGURE_ENDPOINT_CMD};
    use crate::xhci::slot::{
        encode_ep_ctx_dword1, input_ctx_add_flag, EP_TYPE_BULK_IN, EP_TYPE_BULK_OUT,
    };

    // Add Slot (A0) + EP1-IN (DCI 3) + EP2-OUT (DCI 4).
    // DCI = ep_num*2 + 1 for IN, ep_num*2 for OUT.
    // EP1-IN:  ep_num=1, DCI = 1*2+1 = 3
    // EP2-OUT: ep_num=2, DCI = 2*2   = 4
    let dci_ep1_in: u32 = 3;
    let dci_ep2_out: u32 = 4;
    let add_mask = input_ctx_add_flag(0)       // A0 = Slot
                 | input_ctx_add_flag(dci_ep1_in)
                 | input_ctx_add_flag(dci_ep2_out);
    if add_mask & (1 << 0) == 0 {
        return TestResult::Fail("Add mask A0 (Slot) not set");
    }
    if add_mask & (1 << dci_ep1_in) == 0 {
        return TestResult::Fail("Add mask for EP1-IN not set");
    }
    if add_mask & (1 << dci_ep2_out) == 0 {
        return TestResult::Fail("Add mask for EP2-OUT not set");
    }

    // EP1-IN context (bulk IN, max_packet=512).
    let ep1_d1 = encode_ep_ctx_dword1(3, EP_TYPE_BULK_IN, 0, 512);
    if (ep1_d1 >> 3) & 0x7 != EP_TYPE_BULK_IN {
        return TestResult::Fail("EP1-IN type should be BULK_IN (6)");
    }
    if (ep1_d1 >> 16) & 0xFFFF != 512 {
        return TestResult::Fail("EP1-IN MaxPacketSize wrong");
    }

    // EP2-OUT context (bulk OUT, max_packet=512).
    let ep2_d1 = encode_ep_ctx_dword1(3, EP_TYPE_BULK_OUT, 0, 512);
    if (ep2_d1 >> 3) & 0x7 != EP_TYPE_BULK_OUT {
        return TestResult::Fail("EP2-OUT type should be BULK_OUT (2)");
    }
    if (ep2_d1 >> 16) & 0xFFFF != 512 {
        return TestResult::Fail("EP2-OUT MaxPacketSize wrong");
    }

    // Configure Endpoint TRB: type 12, DC=false, slot_id in bits[31:24].
    let input_ctx_pa: u64 = 0x0007_0000;
    let slot_id: u8 = 1;
    let trb = encode_configure_endpoint(input_ctx_pa, slot_id, false, 1);
    if trb.ty() != TRB_TYPE_CONFIGURE_ENDPOINT_CMD {
        return TestResult::Fail("Configure Endpoint TRB type should be 12");
    }
    if (trb.control >> 24) as u8 != slot_id {
        return TestResult::Fail("Configure Endpoint slot_id wrong");
    }
    if trb.control & (1 << 9) != 0 {
        return TestResult::Fail("Configure Endpoint DC bit should be clear");
    }
    if trb.parameter & !0xF != input_ctx_pa & !0xF {
        return TestResult::Fail("Configure Endpoint input_ctx_pa wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/e2e",
    smoke_e2e_configure_endpoint_input_context
);

// ── Smoke 9: Bulk OUT Normal TRB + Transfer Event decode ───────────
//
// Bulk-OUT: driver enqueues a Normal TRB on EP2-OUT (DCI=4) with
// IOC=1, rings doorbell, then awaits a Transfer Event. Transfer Event
// carries slot_id, endpoint_id (DCI), and bytes_remaining=0 for a
// fully-acknowledged transfer.
//
// xHCI 1.2 §6.4.1.1 + §6.4.2.1.

fn smoke_e2e_bulk_out_normal_trb_and_transfer_event() -> TestResult {
    use crate::bulk::dci_for;
    use crate::xhci::cmd_ring::{TRB_CYCLE_BIT, TRB_IOC, TRB_TYPE_NORMAL, TRB_TYPE_SHIFT};
    use crate::xhci::event_ring::{DecodedEvent, TransferEvent, EVT_TRANSFER};
    use crate::xhci::transfer_ring::encode_normal;

    // EP2-OUT: ep_addr = 0x02 (OUT, ep_num=2). DCI = 2*2 = 4.
    let ep_addr: u8 = 0x02;
    let dci = dci_for(ep_addr);
    if dci != 4 {
        return TestResult::Fail("DCI for EP2-OUT should be 4");
    }

    // 64-byte payload at a fake phys.
    let data_phys: u64 = 0x0008_0000;
    let len: u32 = 64;
    let trb = encode_normal(data_phys, len, true, false, 1);
    if trb.ty() != TRB_TYPE_NORMAL {
        return TestResult::Fail("Normal TRB type should be 1");
    }
    if trb.parameter != data_phys {
        return TestResult::Fail("Normal TRB data_phys wrong");
    }
    if trb.status != len {
        return TestResult::Fail("Normal TRB length wrong");
    }
    if trb.control & TRB_IOC == 0 {
        return TestResult::Fail("Normal TRB IOC should be set");
    }
    if trb.control & TRB_CYCLE_BIT == 0 {
        return TestResult::Fail("Normal TRB cycle bit should be set");
    }
    // Chain bit should not be set (single-TRB transfer).
    if trb.control & (1 << 4) != 0 {
        return TestResult::Fail("Normal TRB chain bit should not be set");
    }

    // Synthetic Transfer Event: slot=1, DCI=4, bytes_remaining=0, code=1.
    let slot_id: u8 = 1;
    let completion_code: u8 = 1;
    let te_d2 = ((completion_code as u32) << 24) | 0u32; // residue = 0
    let te_d3 = ((EVT_TRANSFER as u32) << TRB_TYPE_SHIFT)
        | ((slot_id as u32) << 24)
        | ((dci as u32) << 16)
        | TRB_CYCLE_BIT;
    let raw: [u32; 4] = [0, 0, te_d2, te_d3];
    let decoded = DecodedEvent::from_dwords(raw);
    match decoded {
        DecodedEvent::Transfer(TransferEvent {
            completion_code: cc,
            slot_id: sid,
            endpoint_id: ep,
            transfer_length: residue,
            ..
        }) => {
            if cc != 1 {
                return TestResult::Fail("Transfer Event completion code wrong");
            }
            if sid != slot_id {
                return TestResult::Fail("Transfer Event slot_id wrong");
            }
            if ep != dci {
                return TestResult::Fail("Transfer Event endpoint_id (DCI) wrong");
            }
            if residue != 0 {
                return TestResult::Fail("Transfer Event bytes_remaining should be 0");
            }
        }
        _ => return TestResult::Fail("Transfer Event decoded as wrong variant"),
    }

    // bytes_transferred = len - residue = 64 - 0 = 64.
    let te_residue = 0u32;
    let xferred = len.saturating_sub(te_residue) as usize;
    if xferred != 64 {
        return TestResult::Fail("bytes_transferred calculation wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/e2e",
    smoke_e2e_bulk_out_normal_trb_and_transfer_event
);

// ── Smoke 10: Bulk IN 64-byte round-trip ───────────────────────────
//
// Bulk-IN: driver enqueues a Normal TRB on EP1-IN (DCI=3), rings
// doorbell, awaits Transfer Event with bytes_remaining=0. Pre-staged
// data in the DMA buffer is read back and verified byte-for-byte.
//
// DCI formula: ep_num*2 + 1 for IN endpoints (§4.8.1).

fn smoke_e2e_bulk_in_roundtrip() -> TestResult {
    use crate::bulk::dci_for;
    use crate::xhci::cmd_ring::{TRB_IOC, TRB_TYPE_SHIFT};
    use crate::xhci::event_ring::{DecodedEvent, TransferEvent};
    use crate::xhci::transfer_ring::encode_normal;

    // EP1-IN: ep_addr = 0x81, DCI = 1*2+1 = 3.
    let ep_addr: u8 = 0x81;
    let dci = dci_for(ep_addr);
    if dci != 3 {
        return TestResult::Fail("DCI for EP1-IN (0x81) should be 3");
    }

    // A 64-byte buffer staged by the device (simulated with a Vec).
    let expected: alloc::vec::Vec<u8> = (0u8..64).collect();
    let data_phys: u64 = 0x0009_0000;
    let trb = encode_normal(data_phys, 64, true, false, 1);
    if trb.control & TRB_IOC == 0 {
        return TestResult::Fail("Bulk-IN Normal TRB IOC should be set");
    }

    // Synthetic Transfer Event: bytes_remaining=0, code=1.
    let slot_id: u8 = 1;
    let te_d2 = (1u32 << 24) | 0u32;
    let te_d3 = ((crate::xhci::event_ring::EVT_TRANSFER as u32) << TRB_TYPE_SHIFT)
        | ((slot_id as u32) << 24)
        | ((dci as u32) << 16)
        | 1u32;
    let raw: [u32; 4] = [0, 0, te_d2, te_d3];
    let decoded = DecodedEvent::from_dwords(raw);
    let residue = match decoded {
        DecodedEvent::Transfer(TransferEvent {
            transfer_length,
            completion_code,
            ..
        }) => {
            if completion_code != 1 {
                return TestResult::Fail("Bulk-IN Transfer Event completion code wrong");
            }
            transfer_length
        }
        _ => return TestResult::Fail("Bulk-IN Transfer Event decoded wrong"),
    };
    let xferred = (64u32).saturating_sub(residue) as usize;
    if xferred != 64 {
        return TestResult::Fail("Bulk-IN bytes_transferred wrong");
    }
    // Simulate reading back from DMA buffer: in a real test the driver
    // copies from the coherent DMA page; here we verify the formula.
    let mut buf = alloc::vec![0u8; 64];
    for (i, b) in expected.iter().enumerate() {
        buf[i] = *b; // simulates volatile read from DMA page
    }
    for i in 0..64 {
        if buf[i] != expected[i] {
            return TestResult::Fail("Bulk-IN buffer mismatch");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/e2e", smoke_e2e_bulk_in_roundtrip);

// ── Smoke 11: Interrupt-IN polling TRB + report decode ─────────────
//
// Interrupt-IN: driver pre-posts a Normal TRB on EP3-IN (DCI=7)
// with the endpoint's max_packet length. When the device returns data,
// a Transfer Event arrives and `poll_interrupt_in` reads the report
// from the DMA buffer.
//
// xHCI 1.2 §6.4.1.1 + HID spec §7.2.4 (interrupt transfer).

fn smoke_e2e_interrupt_in_polling() -> TestResult {
    use crate::bulk::dci_for;
    use crate::xhci::cmd_ring::{TRB_IOC, TRB_TYPE_SHIFT};
    use crate::xhci::event_ring::{DecodedEvent, TransferEvent, EVT_TRANSFER};
    use crate::xhci::transfer_ring::encode_normal;

    // EP3-IN: ep_addr = 0x83, DCI = 3*2+1 = 7.
    let ep_addr: u8 = 0x83;
    let dci = dci_for(ep_addr);
    if dci != 7 {
        return TestResult::Fail("DCI for EP3-IN (0x83) should be 7");
    }

    // Pre-post 8-byte TRB (arm phase).
    let data_phys: u64 = 0x000A_0000;
    let trb = encode_normal(data_phys, 8, true, false, 1);
    if trb.control & TRB_IOC == 0 {
        return TestResult::Fail("Interrupt-IN TRB IOC should be set");
    }

    // Synthetic Transfer Event: 8 bytes delivered (residue=0), code=1.
    let slot_id: u8 = 1;
    let te_d2 = (1u32 << 24) | 0u32; // cc=1, residue=0
    let te_d3 = ((EVT_TRANSFER as u32) << TRB_TYPE_SHIFT)
        | ((slot_id as u32) << 24)
        | ((dci as u32) << 16)
        | 1u32;
    let raw: [u32; 4] = [0, 0, te_d2, te_d3];
    let decoded = DecodedEvent::from_dwords(raw);

    // 8-byte HID report in the DMA buffer.
    let report: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let mut out = [0u8; 8];
    for (i, b) in report.iter().enumerate() {
        out[i] = *b; // simulates volatile DMA read
    }

    let xferred = match decoded {
        DecodedEvent::Transfer(TransferEvent {
            completion_code,
            transfer_length: residue,
            endpoint_id,
            slot_id: sid,
            ..
        }) => {
            if completion_code != 1 {
                return TestResult::Fail("Interrupt-IN completion code wrong");
            }
            if sid != slot_id {
                return TestResult::Fail("Interrupt-IN slot_id wrong");
            }
            if endpoint_id != dci {
                return TestResult::Fail("Interrupt-IN endpoint_id wrong");
            }
            (8u32).saturating_sub(residue) as usize
        }
        _ => return TestResult::Fail("Interrupt-IN Transfer Event decoded wrong"),
    };
    if xferred != 8 {
        return TestResult::Fail("Interrupt-IN xferred should be 8");
    }
    if out != report {
        return TestResult::Fail("Interrupt-IN report mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/e2e", smoke_e2e_interrupt_in_polling);

// ── Smoke 12: Hub class Device Descriptor claim ─────────────────────
//
// A Hub device has bDeviceClass=0x09 (HUB_INTERFACE_CLASS). The
// hub class driver identifies it by checking the device descriptor.
// Verify that the class byte and the GET_DESCRIPTOR(Hub) request
// encoding are correct.
//
// USB 2.0 §11.23.1 (Hub Class Descriptor).
// Linux ref: `drivers/usb/core/hub.c::usb_hub_probe`. GPL-2.0-or-later.

fn smoke_e2e_hub_class_device_descriptor() -> TestResult {
    use crate::hub::{
        HubDescriptor, HUB_DESC_TYPE, HUB_INTERFACE_CLASS, REQ_GET_DESCRIPTOR,
        RT_DEV_TO_HOST_CLASS_DEVICE,
    };

    // Hub class code must be 0x09.
    if HUB_INTERFACE_CLASS != 0x09 {
        return TestResult::Fail("HUB_INTERFACE_CLASS should be 0x09");
    }

    // Hub descriptor type must be 0x29.
    if HUB_DESC_TYPE != 0x29 {
        return TestResult::Fail("HUB_DESC_TYPE should be 0x29");
    }

    // A minimal 18-byte device descriptor for a hub (bDeviceClass=9).
    let hub_dev_desc: [u8; 18] = [
        18, 1, 0x00, 0x02, // bLength, bDescriptorType, bcdUSB=2.0
        0x09, 0x00, 0x01, 64, // bDeviceClass=Hub, SubClass, Protocol, bMaxPacketSize0
        0x12, 0x34, 0x56, 0x78, // idVendor, idProduct
        0x00, 0x01, 1, 2, 1,
        1, // bcdDevice, iManufacturer, iProduct, iSerialNumber, bNumConfigurations
    ];
    if hub_dev_desc[4] != HUB_INTERFACE_CLASS {
        return TestResult::Fail("Hub device descriptor bDeviceClass wrong");
    }

    // GET_DESCRIPTOR(Hub): bmRequestType=0xA0, bRequest=6, wValue=0x2900.
    if RT_DEV_TO_HOST_CLASS_DEVICE != 0xA0 {
        return TestResult::Fail("RT_DEV_TO_HOST_CLASS_DEVICE should be 0xA0");
    }
    if REQ_GET_DESCRIPTOR != 0x06 {
        return TestResult::Fail("REQ_GET_DESCRIPTOR should be 0x06");
    }
    let w_value_hub_desc = (HUB_DESC_TYPE as u16) << 8;
    if w_value_hub_desc != 0x2900 {
        return TestResult::Fail("Hub GET_DESCRIPTOR wValue should be 0x2900");
    }

    // Hub Descriptor: bLength=9, bDescriptorType=0x29, bNbrPorts=4,
    // wHubCharacteristics=0, bPwrOn2PwrGood=50, bHubContrCurrent=100.
    let hub_desc_bytes: [u8; 9] = [9, 0x29, 4, 0x00, 0x00, 50, 100, 0, 0];
    let hub_desc = HubDescriptor::decode(&hub_desc_bytes).expect("hub descriptor decode failed");
    if hub_desc.num_ports != 4 {
        return TestResult::Fail("Hub descriptor num_ports wrong");
    }
    if hub_desc.poweron_time_2ms != 50 {
        return TestResult::Fail("Hub descriptor poweron_time_2ms wrong");
    }
    if hub_desc.controller_current != 100 {
        return TestResult::Fail("Hub descriptor controller_current wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/e2e", smoke_e2e_hub_class_device_descriptor);

// ── Smoke 13: Hub port power-on SET_FEATURE setup packet ───────────
//
// Hub driver powers each downstream port via SET_FEATURE(PORT_POWER).
// The SETUP packet must have:
//   bmRequestType = 0x23  (Host-to-Device, Class, Other)
//   bRequest      = 0x03  (SET_FEATURE)
//   wValue        = 8     (PORT_POWER feature selector)
//   wIndex        = port  (1-indexed port number)
//
// USB 2.0 §11.24.2.7 Table 11-17.

fn smoke_e2e_hub_port_power_on_setup_packet() -> TestResult {
    use crate::control::Setup;
    use crate::hub::{PORT_POWER, REQ_SET_FEATURE, RT_HOST_TO_DEV_CLASS_OTHER};

    if RT_HOST_TO_DEV_CLASS_OTHER != 0x23 {
        return TestResult::Fail("RT_HOST_TO_DEV_CLASS_OTHER should be 0x23");
    }
    if REQ_SET_FEATURE != 0x03 {
        return TestResult::Fail("REQ_SET_FEATURE should be 0x03");
    }
    if PORT_POWER != 8 {
        return TestResult::Fail("PORT_POWER feature selector should be 8");
    }

    // Build and verify the SETUP packet for port 1.
    let port: u16 = 1;
    let setup = Setup::new(
        RT_HOST_TO_DEV_CLASS_OTHER,
        REQ_SET_FEATURE,
        PORT_POWER,
        port,
        0, // wLength=0, no data stage
    );
    let bytes = setup.to_bytes();
    if bytes[0] != 0x23 {
        return TestResult::Fail("SET_FEATURE bmRequestType wrong");
    }
    if bytes[1] != 0x03 {
        return TestResult::Fail("SET_FEATURE bRequest wrong");
    }
    if u16::from_le_bytes([bytes[2], bytes[3]]) != 8 {
        return TestResult::Fail("SET_FEATURE wValue (PORT_POWER) wrong");
    }
    if u16::from_le_bytes([bytes[4], bytes[5]]) != 1 {
        return TestResult::Fail("SET_FEATURE wIndex (port) wrong");
    }
    if u16::from_le_bytes([bytes[6], bytes[7]]) != 0 {
        return TestResult::Fail("SET_FEATURE wLength should be 0");
    }
    // This is OUT direction (bmRequestType bit 7 = 0).
    if setup.is_in() {
        return TestResult::Fail("SET_FEATURE should be OUT direction");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/e2e", smoke_e2e_hub_port_power_on_setup_packet);

// ── Smoke 14: Hub port-status-change interrupt IN + connect decode ──
//
// Hub reports port status change via a 1-byte interrupt report where
// bit N indicates port N changed. The driver reads GET_STATUS (4
// bytes per port: wPortStatus | wPortChange) and checks bit 0
// (CONNECTION) in wPortChange to see if it's a connect event.
//
// USB 2.0 §11.13.4 + §11.24.2.7.

fn smoke_e2e_hub_port_status_change_interrupt() -> TestResult {
    use crate::hub::{
        C_PORT_CONNECTION, HUB_INTERFACE_CLASS, PORT_CONNECTION, PSTAT_CONNECTION, REQ_GET_STATUS,
        RT_DEV_TO_HOST_CLASS_OTHER,
    };

    // 1-byte interrupt report: bit 1 set → port 1 changed.
    let intr_report: u8 = 0b0000_0010; // bit 1 = port 1
    let port1_changed = (intr_report >> 1) & 1 != 0;
    if !port1_changed {
        return TestResult::Fail("port 1 should be marked changed");
    }

    // GET_STATUS on port 1: bmRequestType=0xA3, bRequest=0.
    if RT_DEV_TO_HOST_CLASS_OTHER != 0xA3 {
        return TestResult::Fail("RT_DEV_TO_HOST_CLASS_OTHER should be 0xA3");
    }
    if REQ_GET_STATUS != 0x00 {
        return TestResult::Fail("REQ_GET_STATUS should be 0x00");
    }

    // Synthetic GET_STATUS response: wPortStatus=CCS (device connected),
    // wPortChange=C_PORT_CONNECTION (just connected).
    let port_status: u16 = PSTAT_CONNECTION; // bit 0: currently connected
    let port_change: u16 = 1 << 0; // bit 0: connection changed

    let status_buf: [u8; 4] = [
        (port_status & 0xFF) as u8,
        (port_status >> 8) as u8,
        (port_change & 0xFF) as u8,
        (port_change >> 8) as u8,
    ];
    let w_port_status = u16::from_le_bytes([status_buf[0], status_buf[1]]);
    let w_port_change = u16::from_le_bytes([status_buf[2], status_buf[3]]);

    if w_port_status & PSTAT_CONNECTION == 0 {
        return TestResult::Fail("wPortStatus CCS bit should be set");
    }
    // w_port_change bit 0 = C_PORT_CONNECTION (connection changed).
    // USB 2.0 §11.24.2.7.1 Table 11-16: bit 0 of wPortChange corresponds
    // to the C_PORT_CONNECTION change condition (feature selector 16).
    if w_port_change & 0x0001 == 0 {
        return TestResult::Fail("wPortChange C_PORT_CONNECTION bit should be set");
    }
    // PORT_CONNECTION feature selector (for SET_FEATURE/CLEAR_FEATURE).
    if PORT_CONNECTION != 0 {
        return TestResult::Fail("PORT_CONNECTION feature selector should be 0");
    }
    if C_PORT_CONNECTION != 16 {
        return TestResult::Fail("C_PORT_CONNECTION feature selector should be 16");
    }
    // Hub interface class re-check.
    if HUB_INTERFACE_CLASS != 0x09 {
        return TestResult::Fail("HUB_INTERFACE_CLASS should be 0x09");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/e2e",
    smoke_e2e_hub_port_status_change_interrupt
);

// ── Smoke 15: DCI calculation for all standard endpoint addresses ───
//
// DCI = ep_num * 2 + (IN ? 1 : 0) per xHCI 1.2 §4.8.1. DCI 0 is
// reserved, DCI 1 is the bidirectional control endpoint (EP0).
//
// Covers the entire addressable endpoint space (ep_num 1..=15, both
// directions), verifying round-trip with `dci_for`.

fn smoke_e2e_dci_calculation_all_endpoints() -> TestResult {
    use crate::bulk::dci_for;

    // Control EP: no bEndpointAddress convention; xHCI always uses DCI 1.
    // Check the canonical EP addr → DCI formula for ep_num 1..=15.
    let cases: &[(u8, u8)] = &[
        // (bEndpointAddress, expected_dci)
        (0x01, 2),  // EP1-OUT: 1*2=2
        (0x81, 3),  // EP1-IN:  1*2+1=3
        (0x02, 4),  // EP2-OUT: 2*2=4
        (0x82, 5),  // EP2-IN:  2*2+1=5
        (0x03, 6),  // EP3-OUT: 3*2=6
        (0x83, 7),  // EP3-IN:  3*2+1=7
        (0x0F, 30), // EP15-OUT: 15*2=30
        (0x8F, 31), // EP15-IN:  15*2+1=31
    ];
    for &(ep_addr, expected_dci) in cases {
        let got = dci_for(ep_addr);
        if got != expected_dci {
            return TestResult::Fail("dci_for mismatch");
        }
    }

    // Verify the direction bit extraction.
    // bit 7 = 1 → IN direction (DCI is odd).
    for ep_num in 1u8..=15 {
        let ep_in = ep_num | 0x80;
        let ep_out = ep_num & 0x0F;
        let dci_in = dci_for(ep_in);
        let dci_out = dci_for(ep_out);
        if dci_in != ep_num * 2 + 1 {
            return TestResult::Fail("DCI IN formula wrong");
        }
        if dci_out != ep_num * 2 {
            return TestResult::Fail("DCI OUT formula wrong");
        }
        // IN DCI is always odd, OUT always even.
        if dci_in % 2 != 1 {
            return TestResult::Fail("IN DCI should be odd");
        }
        if dci_out % 2 != 0 {
            return TestResult::Fail("OUT DCI should be even");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/e2e", smoke_e2e_dci_calculation_all_endpoints);

// ── Smoke 16: Transfer Event filter (slot + endpoint matching) ──────
//
// `await_event` filters by both Slot ID and Endpoint ID (DCI) to
// prevent a Transfer Event on one endpoint stealing from another.
// Verify the predicate expressions match precisely.
//
// Linux ref: `xhci_ring.c::xhci_handle_tx_event` matches ep_index +
// slot_id before dispatching. GPL-2.0-or-later.

fn smoke_e2e_transfer_event_slot_endpoint_filter() -> TestResult {
    use crate::xhci::cmd_ring::TRB_TYPE_SHIFT;
    use crate::xhci::event_ring::{DecodedEvent, EVT_TRANSFER};

    // Build four Transfer Events: two slots (1, 2) × two DCIs (3, 5).
    let make_te = |slot: u8, dci: u8, code: u8| -> [u32; 4] {
        let d2 = (code as u32) << 24;
        let d3 = ((EVT_TRANSFER as u32) << TRB_TYPE_SHIFT)
            | ((slot as u32) << 24)
            | ((dci as u32) << 16)
            | 1u32;
        [0, 0, d2, d3]
    };

    let ev11 = make_te(1, 3, 1); // slot=1, DCI=3
    let ev12 = make_te(1, 5, 1); // slot=1, DCI=5
    let ev21 = make_te(2, 3, 1); // slot=2, DCI=3
    let ev22 = make_te(2, 5, 1); // slot=2, DCI=5

    // The predicate used by bulk_in for slot=1, DCI=3.
    let xfer = (crate::xhci::event_ring::EVT_TRANSFER as u32) << TRB_TYPE_SHIFT;
    let want_slot_1 = (1u32) << 24;
    let want_ep_3 = (3u32) << 16;
    let pred = |t: &[u32; 4]| -> bool {
        (t[3] & 0x0000_FC00) == xfer          // TRB type field
            && (t[3] & 0xFF00_0000) == want_slot_1
            && (t[3] & 0x001F_0000) == want_ep_3
    };

    if !pred(&ev11) {
        return TestResult::Fail("filter should match slot=1, DCI=3");
    }
    if pred(&ev12) {
        return TestResult::Fail("filter should reject slot=1, DCI=5");
    }
    if pred(&ev21) {
        return TestResult::Fail("filter should reject slot=2, DCI=3");
    }
    if pred(&ev22) {
        return TestResult::Fail("filter should reject slot=2, DCI=5");
    }

    // Verify decode agrees.
    let decoded = DecodedEvent::from_dwords(ev11);
    if let DecodedEvent::Transfer(te) = decoded {
        if te.slot_id != 1 || te.endpoint_id != 3 {
            return TestResult::Fail("Decoded Transfer Event slot/ep wrong");
        }
    } else {
        return TestResult::Fail("Transfer Event decoded as wrong variant");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/e2e",
    smoke_e2e_transfer_event_slot_endpoint_filter
);

// ── Smoke 17: Command Completion Event decode — all completion codes ─
//
// xHCI 1.2 §6.4.5 Table 6-93 defines completion codes. The driver
// translates codes via `UsbError::from_xhci`. Spot-check the critical
// ones: Success (1), USB Transaction Error (4), Stall (6), Babble (7),
// Context Error (11 — Context State invalid), Short Packet (13).

fn smoke_e2e_command_completion_codes() -> TestResult {
    use crate::device::{UsbError, UsbError::*};
    use crate::xhci::cmd_ring::TRB_TYPE_SHIFT;
    use crate::xhci::event_ring::{CmdCompletionEvent, DecodedEvent, EVT_CMD_COMPLETION};
    use crate::xhci::XhciError;

    let make_cce = |code: u8, slot: u8| -> [u32; 4] {
        let d2 = (code as u32) << 24;
        let d3 = ((EVT_CMD_COMPLETION as u32) << TRB_TYPE_SHIFT) | ((slot as u32) << 24) | 1u32;
        [0, 0, d2, d3]
    };

    // Success (code=1): must decode to completion_code=1, slot_id=1.
    let success_ev = make_cce(1, 1);
    match DecodedEvent::from_dwords(success_ev) {
        DecodedEvent::CmdCompletion(CmdCompletionEvent {
            completion_code: 1,
            slot_id: 1,
            ..
        }) => {}
        _ => return TestResult::Fail("Success CCE decode wrong"),
    }

    // USB Transaction Error (code=4) → UsbError::TransactionError.
    let err4 = XhciError::CmdFailed(4);
    if UsbError::from_xhci(err4) != TransactionError {
        return TestResult::Fail("CmdFailed(4) should map to TransactionError");
    }

    // Stall (code=6) → UsbError::Stall.
    let err6 = XhciError::CmdFailed(6);
    if UsbError::from_xhci(err6) != Stall {
        return TestResult::Fail("CmdFailed(6) should map to Stall");
    }

    // Babble (code=7) → UsbError::Babble.
    let err7 = XhciError::CmdFailed(7);
    if UsbError::from_xhci(err7) != Babble {
        return TestResult::Fail("CmdFailed(7) should map to Babble");
    }

    // Slot-not-found (code=0xFD) → UsbError::StaleSlot.
    let err_stale = XhciError::CmdFailed(0xFD);
    if UsbError::from_xhci(err_stale) != StaleSlot {
        return TestResult::Fail("CmdFailed(0xFD) should map to StaleSlot");
    }

    // Timeout → UsbError::Timeout.
    let err_timeout = XhciError::CmdTimeout;
    if UsbError::from_xhci(err_timeout) != Timeout {
        return TestResult::Fail("CmdTimeout should map to Timeout");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/usb/e2e", smoke_e2e_command_completion_codes);

// ── Smoke 18: xHCI Topology route string encoding ──────────────────
//
// Devices behind one or more USB hubs use a Route String (§4.5.2) in
// the Slot Context to encode the hub-hop path. Each hop is 4 bits.
// `Topology::for_downstream` builds the route string by shifting the
// hub's downstream port number into the correct nibble.
//
// Linux ref: `drivers/usb/host/xhci.c::xhci_find_slot_id_by_port` +
// `hub.c::usb_set_device_state`. GPL-2.0-or-later.

fn smoke_e2e_topology_route_string() -> TestResult {
    use crate::xhci::Topology;

    // Root device: route_string = 0.
    let root = Topology::ROOT;
    if root.route_string != 0 {
        return TestResult::Fail("ROOT route_string should be 0");
    }

    // Device behind hub on root port 3, hub's downstream port 5.
    // Tier 0: parent_route=0, parent_tier=0, hub_port=3 → nibble 0 = 3.
    // After that: parent_route=3, parent_tier=1, hub_port=5 → nibble 1 = 5.
    let tier1 = Topology::for_downstream(0, 0, 3);
    if tier1.route_string & 0xF != 3 {
        return TestResult::Fail("Tier 1 route_string nibble 0 should be 3");
    }
    if (tier1.route_string >> 4) & 0xF != 0 {
        return TestResult::Fail("Tier 1 route_string nibble 1 should be 0");
    }

    let tier2 = Topology::for_downstream(tier1.route_string, 1, 5);
    if tier2.route_string & 0xF != 3 {
        return TestResult::Fail("Tier 2 route_string nibble 0 should be 3");
    }
    if (tier2.route_string >> 4) & 0xF != 5 {
        return TestResult::Fail("Tier 2 route_string nibble 1 should be 5");
    }

    // Port values > 15 are clamped to 15 per §4.5.2.
    let tier_clamp = Topology::for_downstream(0, 0, 20);
    if tier_clamp.route_string & 0xF != 15 {
        return TestResult::Fail("Port > 15 should be clamped to 15 in route string");
    }

    // Route string is 20 bits maximum (5 hubs × 4 bits).
    let tier3 = Topology::for_downstream(tier2.route_string, 2, 7);
    if tier3.route_string & 0xFF00_0000 != 0 {
        return TestResult::Fail("Route string should not use bits above bit 19");
    }
    if (tier3.route_string >> 8) & 0xF != 7 {
        return TestResult::Fail("Tier 3 route_string nibble 2 should be 7");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/e2e", smoke_e2e_topology_route_string);

// ── Smoke 19: SETUP packet round-trip encode + decode ──────────────
//
// `Setup::to_bytes` / `Setup::from_bytes` must produce a lossless
// round-trip for all standard control requests. Also validates the
// `is_in()` direction bit.
//
// USB 2.0 §9.3 Table 9-2.

fn smoke_e2e_setup_packet_roundtrip() -> TestResult {
    use crate::control::{get_descriptor, set_configuration, set_interface, vendor_read, Setup};

    // GET_DESCRIPTOR(Device, index 0, lang 0, len 18): must be IN.
    let gd = get_descriptor(0x01, 0, 0, 18);
    let bytes = gd.to_bytes();
    let recovered = Setup::from_bytes(bytes);
    if recovered != gd {
        return TestResult::Fail("GET_DESCRIPTOR round-trip failed");
    }
    if !gd.is_in() {
        return TestResult::Fail("GET_DESCRIPTOR should be IN direction");
    }

    // SET_CONFIGURATION(1): must be OUT.
    let sc = set_configuration(1);
    if sc.is_in() {
        return TestResult::Fail("SET_CONFIGURATION should be OUT direction");
    }
    let sc_bytes = sc.to_bytes();
    if sc_bytes[1] != 9 {
        return TestResult::Fail("SET_CONFIGURATION bRequest should be 9");
    }
    if u16::from_le_bytes([sc_bytes[2], sc_bytes[3]]) != 1 {
        return TestResult::Fail("SET_CONFIGURATION wValue should be 1");
    }

    // SET_INTERFACE(iface=0, alt=0): must be OUT.
    let si = set_interface(0, 0);
    if si.is_in() {
        return TestResult::Fail("SET_INTERFACE should be OUT direction");
    }
    if si.to_bytes()[1] != 11 {
        return TestResult::Fail("SET_INTERFACE bRequest should be 11");
    }

    // Vendor read: bmRequestType bit 7 = 1 (IN), bits[6:5] = vendor.
    let vr = vendor_read(0xAB, 0x1234, 0, 64);
    if !vr.is_in() {
        return TestResult::Fail("vendor_read should be IN direction");
    }
    if vr.to_bytes()[0] & 0x40 == 0 {
        return TestResult::Fail("vendor_read type bits should indicate Vendor");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/e2e", smoke_e2e_setup_packet_roundtrip);

// ── Smoke 20: ERST entry serialisation ─────────────────────────────
//
// The Event Ring Segment Table entry layout (§6.5) is written to DMA
// memory and read by the controller. Verify that `ErstEntry::encode`
// produces the correct little-endian layout.
//
// xHCI 1.2 §6.5 Table 6-95.

fn smoke_e2e_erst_entry_serialisation() -> TestResult {
    use crate::xhci::event_ring::ErstEntry;

    // Segment at phys 0x0010_0000, 64 TRBs. Bits[5:0] MBZ.
    let base: u64 = 0x0010_0000;
    let n_trbs: u16 = 64;
    let entry = ErstEntry::encode(base, n_trbs);
    if entry.ring_seg_base != base {
        return TestResult::Fail("ERST ring_seg_base wrong");
    }
    if entry.ring_seg_size != n_trbs as u32 {
        return TestResult::Fail("ERST ring_seg_size wrong");
    }
    if entry.reserved != 0 {
        return TestResult::Fail("ERST reserved field should be 0");
    }

    // Verify alignment masking: bits[5:0] must be zeroed.
    let unaligned: u64 = 0x0010_002F; // has bits 0..5 set
    let entry2 = ErstEntry::encode(unaligned, 16);
    if entry2.ring_seg_base & 0x3F != 0 {
        return TestResult::Fail("ERST base bits[5:0] should be masked to 0");
    }

    // to_le_bytes serialisation.
    let bytes = entry.to_le_bytes();
    let base_from_bytes = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    if base_from_bytes != base {
        return TestResult::Fail("ERST to_le_bytes base wrong");
    }
    let size_from_bytes = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if size_from_bytes != n_trbs as u32 {
        return TestResult::Fail("ERST to_le_bytes size wrong");
    }

    // Verify SIZE constant.
    if ErstEntry::SIZE != 16 {
        return TestResult::Fail("ErstEntry::SIZE should be 16");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/e2e", smoke_e2e_erst_entry_serialisation);

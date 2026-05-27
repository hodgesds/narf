//! `brcmfmac` smoke tests — co-located per project convention.
//!
//! Stage-0 covers PCI match table + per-id name lookup + firmware
//! filename ladder presence + the live-silicon Skip path. Stage-1
//! and Stage-2 append common-ring cursor invariants + msgbuf
//! encode/decode round-trips.
//!
//! All smokes are pure-data: they Pass on QEMU instead of Skip. The
//! probe-bound live-silicon smoke Skips cleanly when no Broadcom
//! PCIe Wi-Fi is on the bus.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::msgbuf::{
    ring_layout, BufAddr, CommonHdr, IoctlReq, IoctlResp, MsgType, Ring, WlEvent,
    D2H_MSGRING_CONTROL_COMPLETE, D2H_MSGRING_CONTROL_COMPLETE_ITEMSIZE,
    D2H_MSGRING_CONTROL_COMPLETE_MAX_ITEM, D2H_MSGRING_RX_COMPLETE,
    D2H_MSGRING_RX_COMPLETE_ITEMSIZE, D2H_MSGRING_RX_COMPLETE_ITEMSIZE_PRE_V7,
    D2H_MSGRING_TX_COMPLETE, D2H_MSGRING_TX_COMPLETE_ITEMSIZE,
    D2H_MSGRING_TX_COMPLETE_ITEMSIZE_PRE_V7, H2D_MSGRING_CONTROL_SUBMIT,
    H2D_MSGRING_CONTROL_SUBMIT_ITEMSIZE, H2D_MSGRING_CONTROL_SUBMIT_MAX_ITEM,
    H2D_MSGRING_RXPOST_SUBMIT, H2D_MSGRING_RXPOST_SUBMIT_ITEMSIZE,
    H2D_MSGRING_RXPOST_SUBMIT_MAX_ITEM, IOCTL_REQ_SIZE, IOCTL_RESP_SIZE,
    NROF_COMMON_MSGRINGS, NROF_D2H_COMMON_MSGRINGS, NROF_H2D_COMMON_MSGRINGS,
    WL_EVENT_SIZE,
};
use super::pcie::{
    firmware_filename, name_for, register_pci_driver, ALL_DEV_IDS, BRCM_PCIE_43602_DEVICE_ID,
    BRCM_PCIE_4365_DEVICE_ID, BRCM_PCIE_4366_DEVICE_ID, BRCM_PCIE_4371_DEVICE_ID,
    BRCM_PCIE_4378_DEVICE_ID, BROADCOM_VENDOR,
};

// ── PCI match table ────────────────────────────────────────────────

fn smoke_brcmfmac_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    register_pci_driver();
    let registered = registered_pci_drivers();
    for &did in ALL_DEV_IDS {
        let matched = registered.iter().any(|m| {
            matches!(
                m.kind,
                MatchKind::VendorDevice {
                    vendor: BROADCOM_VENDOR,
                    device,
                } if device == did
            )
        });
        if !matched {
            return TestResult::Fail("brcmfmac PCI match table missing a device id");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/brcmfmac", smoke_brcmfmac_pci_match_table);

fn smoke_brcmfmac_name_for_known_ids() -> TestResult {
    if name_for(BRCM_PCIE_43602_DEVICE_ID) != "brcmfmac-43602" {
        return TestResult::Fail("43602 name mismatch");
    }
    if name_for(BRCM_PCIE_4366_DEVICE_ID) != "brcmfmac-4366" {
        return TestResult::Fail("4366 name mismatch");
    }
    if name_for(BRCM_PCIE_4371_DEVICE_ID) != "brcmfmac-4371" {
        return TestResult::Fail("4371 name mismatch");
    }
    if name_for(BRCM_PCIE_4378_DEVICE_ID) != "brcmfmac-4378" {
        return TestResult::Fail("4378 name mismatch");
    }
    if name_for(0xFFFF) != "brcmfmac" {
        return TestResult::Fail("default name mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/brcmfmac", smoke_brcmfmac_name_for_known_ids);

fn smoke_brcmfmac_firmware_filename_lookup() -> TestResult {
    // Every device id with a registered per-chip name also gets a
    // firmware blob name — paths follow the linux-firmware tree's
    // `/firmware/brcm/brcmfmacXXXX-pcie.bin` convention.
    if !firmware_filename(BRCM_PCIE_43602_DEVICE_ID)
        .unwrap_or("")
        .starts_with("/firmware/brcm/")
    {
        return TestResult::Fail("43602 firmware filename missing or wrong prefix");
    }
    if !firmware_filename(BRCM_PCIE_4365_DEVICE_ID)
        .unwrap_or("")
        .starts_with("/firmware/brcm/")
    {
        return TestResult::Fail("4365 firmware filename missing or wrong prefix");
    }
    if firmware_filename(0xFFFF).is_some() {
        return TestResult::Fail("unknown device id should have no firmware name");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_firmware_filename_lookup
);

// ── Ring layout invariants (Stage-1) ───────────────────────────────

fn smoke_brcmfmac_ring_counts() -> TestResult {
    if NROF_H2D_COMMON_MSGRINGS != 2 {
        return TestResult::Fail("NROF_H2D_COMMON_MSGRINGS not 2");
    }
    if NROF_D2H_COMMON_MSGRINGS != 3 {
        return TestResult::Fail("NROF_D2H_COMMON_MSGRINGS not 3");
    }
    if NROF_COMMON_MSGRINGS != 5 {
        return TestResult::Fail("NROF_COMMON_MSGRINGS not 5");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/brcmfmac", smoke_brcmfmac_ring_counts);

fn smoke_brcmfmac_ring_layout_lookup() -> TestResult {
    // Per `msgbuf.h` ~L10..L23. H2D control-submit must be 64 × 40,
    // H2D rxpost-submit 1024 × 32, D2H control-complete 64 × 24.
    let h2d_ctl = match ring_layout(H2D_MSGRING_CONTROL_SUBMIT, false) {
        Some(x) => x,
        None => return TestResult::Fail("h2d-control-submit ring_layout None"),
    };
    if h2d_ctl.depth != H2D_MSGRING_CONTROL_SUBMIT_MAX_ITEM
        || h2d_ctl.item_len != H2D_MSGRING_CONTROL_SUBMIT_ITEMSIZE
        || !h2d_ctl.is_h2d
    {
        return TestResult::Fail("h2d-control-submit layout mismatch");
    }
    let h2d_rxp = match ring_layout(H2D_MSGRING_RXPOST_SUBMIT, false) {
        Some(x) => x,
        None => return TestResult::Fail("h2d-rxpost-submit ring_layout None"),
    };
    if h2d_rxp.depth != H2D_MSGRING_RXPOST_SUBMIT_MAX_ITEM
        || h2d_rxp.item_len != H2D_MSGRING_RXPOST_SUBMIT_ITEMSIZE
        || !h2d_rxp.is_h2d
    {
        return TestResult::Fail("h2d-rxpost-submit layout mismatch");
    }
    let d2h_ctl = match ring_layout(D2H_MSGRING_CONTROL_COMPLETE, false) {
        Some(x) => x,
        None => return TestResult::Fail("d2h-control-complete ring_layout None"),
    };
    if d2h_ctl.depth != D2H_MSGRING_CONTROL_COMPLETE_MAX_ITEM
        || d2h_ctl.item_len != D2H_MSGRING_CONTROL_COMPLETE_ITEMSIZE
        || d2h_ctl.is_h2d
    {
        return TestResult::Fail("d2h-control-complete layout mismatch");
    }
    // TX/RX complete shrink to the pre-v7 item sizes when `pre_v7=true`.
    let tx_v7 = ring_layout(D2H_MSGRING_TX_COMPLETE, false).unwrap();
    let tx_pre = ring_layout(D2H_MSGRING_TX_COMPLETE, true).unwrap();
    if tx_v7.item_len != D2H_MSGRING_TX_COMPLETE_ITEMSIZE
        || tx_pre.item_len != D2H_MSGRING_TX_COMPLETE_ITEMSIZE_PRE_V7
    {
        return TestResult::Fail("tx-complete pre/post v7 size mismatch");
    }
    let rx_v7 = ring_layout(D2H_MSGRING_RX_COMPLETE, false).unwrap();
    let rx_pre = ring_layout(D2H_MSGRING_RX_COMPLETE, true).unwrap();
    if rx_v7.item_len != D2H_MSGRING_RX_COMPLETE_ITEMSIZE
        || rx_pre.item_len != D2H_MSGRING_RX_COMPLETE_ITEMSIZE_PRE_V7
    {
        return TestResult::Fail("rx-complete pre/post v7 size mismatch");
    }
    if ring_layout(99, false).is_some() {
        return TestResult::Fail("unknown ring id should return None");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/brcmfmac", smoke_brcmfmac_ring_layout_lookup);

// ── Common-ring SPSC state machine (Stage-1) ───────────────────────

fn smoke_brcmfmac_ring_empty_and_full() -> TestResult {
    let mut r = Ring::new(8, 40);
    // Empty ring — no read available, full write window (depth - 1).
    if r.read_available() != 0 {
        return TestResult::Fail("fresh ring should be empty");
    }
    if r.write_available() != 7 {
        return TestResult::Fail("fresh ring should have depth-1 write slots");
    }
    if r.read_offset().is_some() {
        return TestResult::Fail("empty ring should have no read_offset");
    }
    // Reserve all 7 slots — write_available should drop to 0.
    for i in 0..7 {
        let off = match r.reserve_one() {
            Some(v) => v,
            None => return TestResult::Fail("reserve_one returned None mid-fill"),
        };
        if off != (i as u32) * 40 {
            return TestResult::Fail("reserve_one returned wrong byte offset");
        }
    }
    if r.write_available() != 0 {
        return TestResult::Fail("ring should be full after depth-1 reservations");
    }
    if r.reserve_one().is_some() {
        return TestResult::Fail("reserve_one should fail on full ring");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/brcmfmac", smoke_brcmfmac_ring_empty_and_full);

fn smoke_brcmfmac_ring_wraparound() -> TestResult {
    // Reservations wrap at `depth`. After publish + read_complete the
    // producer regains the slot.
    let mut r = Ring::new(4, 8);
    let _ = r.reserve_one().unwrap();
    let _ = r.reserve_one().unwrap();
    r.publish();
    // Consumer drains the two committed items.
    if r.read_available() != 2 {
        return TestResult::Fail("read_available wrong after publish");
    }
    r.read_complete(2);
    if r.read_available() != 0 {
        return TestResult::Fail("read_available should be 0 after drain");
    }
    // Now we should be able to reserve 3 more before hitting "full"
    // (depth - 1 = 3 slots, r_ptr is now at 2 too so wrap kicks in).
    for _ in 0..3 {
        if r.reserve_one().is_none() {
            return TestResult::Fail("post-drain reserve_one prematurely None");
        }
    }
    if r.reserve_one().is_some() {
        return TestResult::Fail("reserve_one should fail after slot exhaustion");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/brcmfmac", smoke_brcmfmac_ring_wraparound);

fn smoke_brcmfmac_ring_cancel_restores_wptr() -> TestResult {
    // Reserve 3, cancel the most recent 2 — write_available should
    // return to (depth-1 - 1).
    let mut r = Ring::new(16, 24);
    for _ in 0..3 {
        r.reserve_one().unwrap();
    }
    let before = r.write_available();
    r.write_cancel(2);
    let after = r.write_available();
    if after != before + 2 {
        return TestResult::Fail("write_cancel didn't restore expected w_ptr");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_ring_cancel_restores_wptr
);

fn smoke_brcmfmac_ring_reserve_multi_clamps() -> TestResult {
    // Reserve_multi can never grant a run that would wrap past the
    // end of the buffer in a single reservation — that's how
    // `brcmf_commonring_reserve_for_write_multiple` (commonring.c
    // ~L161..L162) protects against tearing a single contiguous
    // reservation across the wraparound. We need a setup where
    // (alloced + w_ptr > depth), which requires r_ptr to have
    // advanced past 0 so `available` exceeds (depth - w_ptr).
    //
    // depth=8, w_ptr=5, r_ptr=2 → available = depth - w_ptr + r_ptr = 5
    // → min(n_items=5, available-1=4) = 4, then 4 + w_ptr=5 > 8
    // → clamp to depth - w_ptr = 3.
    let mut r = Ring::new(8, 8);
    for _ in 0..5 {
        r.reserve_one().unwrap();
    }
    r.publish();
    r.read_complete(2);
    let (off, granted) = match r.reserve_multi(5) {
        Some(v) => v,
        None => return TestResult::Fail("reserve_multi returned None"),
    };
    if off != 5 * 8 {
        return TestResult::Fail("reserve_multi returned wrong byte offset");
    }
    if granted != 3 {
        return TestResult::Fail("reserve_multi didn't clamp at depth boundary");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_ring_reserve_multi_clamps
);

// ── msgbuf encode/decode round-trips (Stage-2) ─────────────────────

fn smoke_brcmfmac_common_hdr_roundtrip() -> TestResult {
    let h = CommonHdr {
        msgtype: MsgType::IoctlPtrReq as u8,
        ifidx: 0,
        flags: 0,
        request_id: 0xDEAD_BEEF,
    };
    let mut buf = [0u8; 8];
    if h.encode(&mut buf).is_none() {
        return TestResult::Fail("encode CommonHdr failed");
    }
    // Wire ordering: type/ifidx/flags/rsvd0/request_id (little-endian).
    if buf[0] != MsgType::IoctlPtrReq as u8 {
        return TestResult::Fail("CommonHdr msgtype byte mispositioned");
    }
    if buf[4..8] != 0xDEAD_BEEFu32.to_le_bytes() {
        return TestResult::Fail("CommonHdr request_id not little-endian");
    }
    let decoded = match CommonHdr::decode(&buf) {
        Some(v) => v,
        None => return TestResult::Fail("decode CommonHdr failed"),
    };
    if decoded != h {
        return TestResult::Fail("CommonHdr round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_common_hdr_roundtrip
);

fn smoke_brcmfmac_ioctl_req_roundtrip() -> TestResult {
    let req = IoctlReq {
        hdr: CommonHdr {
            msgtype: MsgType::IoctlPtrReq as u8,
            ifidx: 0,
            flags: 0,
            request_id: 0x0000_0001,
        },
        cmd: 262, // BRCMF_C_GET_REVINFO IOCTL.
        trans_id: 7,
        input_buf_len: 0,
        output_buf_len: 256,
        req_buf_addr: BufAddr(0xDEAD_BEEF_CAFE_BABE),
    };
    let mut buf = [0u8; IOCTL_REQ_SIZE];
    if req.encode(&mut buf).is_none() {
        return TestResult::Fail("encode IoctlReq failed");
    }
    if buf.len() != 40 {
        return TestResult::Fail("IOCTL_REQ_SIZE not 40 bytes");
    }
    // Sanity: trans_id should land at offset 12..14.
    if buf[12..14] != 7u16.to_le_bytes() {
        return TestResult::Fail("IoctlReq.trans_id mis-encoded");
    }
    let decoded = match IoctlReq::decode(&buf) {
        Some(v) => v,
        None => return TestResult::Fail("decode IoctlReq failed"),
    };
    if decoded != req {
        return TestResult::Fail("IoctlReq round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_ioctl_req_roundtrip
);

fn smoke_brcmfmac_ioctl_resp_roundtrip() -> TestResult {
    let resp = IoctlResp {
        hdr: CommonHdr {
            msgtype: MsgType::IoctlCmplt as u8,
            ifidx: 0,
            flags: 0,
            request_id: 0x0000_0001,
        },
        status: 0,
        flow_ring_id: 0,
        resp_len: 256,
        trans_id: 7,
        cmd: 262,
    };
    let mut buf = [0u8; IOCTL_RESP_SIZE];
    if resp.encode(&mut buf).is_none() {
        return TestResult::Fail("encode IoctlResp failed");
    }
    if buf.len() != 24 {
        return TestResult::Fail("IOCTL_RESP_SIZE not 24 bytes");
    }
    let decoded = match IoctlResp::decode(&buf) {
        Some(v) => v,
        None => return TestResult::Fail("decode IoctlResp failed"),
    };
    if decoded != resp {
        return TestResult::Fail("IoctlResp round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_ioctl_resp_roundtrip
);

fn smoke_brcmfmac_wl_event_roundtrip() -> TestResult {
    let evt = WlEvent {
        hdr: CommonHdr {
            msgtype: MsgType::WlEvent as u8,
            ifidx: 0,
            flags: 0,
            request_id: 0x4242_4242,
        },
        status: 0,
        flow_ring_id: 0,
        event_data_len: 200,
        seqnum: 9,
    };
    let mut buf = [0u8; WL_EVENT_SIZE];
    if evt.encode(&mut buf).is_none() {
        return TestResult::Fail("encode WlEvent failed");
    }
    if buf.len() != 24 {
        return TestResult::Fail("WL_EVENT_SIZE not 24 bytes");
    }
    let decoded = match WlEvent::decode(&buf) {
        Some(v) => v,
        None => return TestResult::Fail("decode WlEvent failed"),
    };
    if decoded != evt {
        return TestResult::Fail("WlEvent round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_wl_event_roundtrip
);

fn smoke_brcmfmac_buf_addr_high_low() -> TestResult {
    let addr = BufAddr(0x1122_3344_5566_7788);
    let mut buf = [0u8; 8];
    addr.encode(&mut buf).unwrap();
    // low_addr first (LE), then high_addr (LE).
    if buf[0..4] != 0x5566_7788u32.to_le_bytes() {
        return TestResult::Fail("BufAddr.low_addr mis-encoded");
    }
    if buf[4..8] != 0x1122_3344u32.to_le_bytes() {
        return TestResult::Fail("BufAddr.high_addr mis-encoded");
    }
    let decoded = BufAddr::decode(&buf).unwrap();
    if decoded != addr {
        return TestResult::Fail("BufAddr round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_buf_addr_high_low
);

fn smoke_brcmfmac_msgtype_decode() -> TestResult {
    if MsgType::from_u8(0x09) != Some(MsgType::IoctlPtrReq) {
        return TestResult::Fail("0x09 should decode to IoctlPtrReq");
    }
    if MsgType::from_u8(0x0C) != Some(MsgType::IoctlCmplt) {
        return TestResult::Fail("0x0C should decode to IoctlCmplt");
    }
    if MsgType::from_u8(0x0E) != Some(MsgType::WlEvent) {
        return TestResult::Fail("0x0E should decode to WlEvent");
    }
    if MsgType::from_u8(0xFF).is_some() {
        return TestResult::Fail("0xFF should be unknown");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/brcmfmac", smoke_brcmfmac_msgtype_decode);

fn smoke_brcmfmac_encode_buffer_too_small() -> TestResult {
    let req = IoctlReq {
        hdr: CommonHdr {
            msgtype: MsgType::IoctlPtrReq as u8,
            ifidx: 0,
            flags: 0,
            request_id: 0,
        },
        cmd: 0,
        trans_id: 0,
        input_buf_len: 0,
        output_buf_len: 0,
        req_buf_addr: BufAddr(0),
    };
    let mut small = [0u8; IOCTL_REQ_SIZE - 1];
    if req.encode(&mut small).is_some() {
        return TestResult::Fail("encode should fail on too-small buffer");
    }
    if IoctlReq::decode(&small).is_some() {
        return TestResult::Fail("decode should fail on too-small buffer");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_encode_buffer_too_small
);

// ── Live-silicon smoke (Skip on QEMU) ──────────────────────────────

fn smoke_brcmfmac_probe_bound_or_skip() -> TestResult {
    if !super::pcie::is_probed() {
        return TestResult::Skip("brcmfmac: no BCM43xxx PCIe bound (expected on QEMU)");
    }
    let did = match super::pcie::with_controller(|d| d.device_id) {
        Some(d) => d,
        None => return TestResult::Skip("brcmfmac: probed flag set but no controller borrowable"),
    };
    if !ALL_DEV_IDS.contains(&did) {
        return TestResult::Fail("brcmfmac: bound device id not in match table");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_probe_bound_or_skip
);

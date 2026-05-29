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
    ring_layout, BufAddr, CommonHdr, IoctlReq, IoctlResp, MsgType, Ring, RxComplete, TxPost,
    TxStatus, WlEvent,
    chanspec_20mhz, chanspec_channel, chanspec_is5g,
    D2H_MSGRING_CONTROL_COMPLETE, D2H_MSGRING_CONTROL_COMPLETE_ITEMSIZE,
    D2H_MSGRING_CONTROL_COMPLETE_MAX_ITEM, D2H_MSGRING_RX_COMPLETE,
    D2H_MSGRING_RX_COMPLETE_ITEMSIZE, D2H_MSGRING_RX_COMPLETE_ITEMSIZE_PRE_V7,
    D2H_MSGRING_TX_COMPLETE, D2H_MSGRING_TX_COMPLETE_ITEMSIZE,
    D2H_MSGRING_TX_COMPLETE_ITEMSIZE_PRE_V7, H2D_MSGRING_CONTROL_SUBMIT,
    H2D_MSGRING_CONTROL_SUBMIT_ITEMSIZE, H2D_MSGRING_CONTROL_SUBMIT_MAX_ITEM,
    H2D_MSGRING_RXPOST_SUBMIT, H2D_MSGRING_RXPOST_SUBMIT_ITEMSIZE,
    H2D_MSGRING_RXPOST_SUBMIT_MAX_ITEM, IOCTL_REQ_SIZE, IOCTL_RESP_SIZE,
    NROF_COMMON_MSGRINGS, NROF_D2H_COMMON_MSGRINGS, NROF_H2D_COMMON_MSGRINGS,
    RX_COMPLETE_SIZE, TX_POST_SIZE, TX_STATUS_SIZE, WL_EVENT_SIZE,
    WL_CHANSPEC_BAND_5G, WL_CHANSPEC_BW_20,
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

// ── Stage-3: TX/RX frame descriptors + chanspec (new smokes) ──────────

fn smoke_brcmfmac_bcdc_tx_post_encode() -> TestResult {
    // Build a TxPost descriptor for a 100-byte Ethernet frame residing
    // at DMA address 0xDEAD_0000_1234_5678. Mirrors the descriptor the
    // brcmf_msgbuf_txflow path (~L640, core.c) would build.
    let desc = TxPost {
        hdr: CommonHdr {
            msgtype: MsgType::TxPost as u8,
            ifidx: 0,
            flags: 0,
            request_id: 1,
        },
        metadata_buf_addr: BufAddr(0),
        data_buf_addr: BufAddr(0xDEAD_0000_1234_5678),
        metadata_len: 0,
        data_len: 100,
    };
    let mut buf = [0u8; TX_POST_SIZE];
    if desc.encode(&mut buf).is_none() {
        return TestResult::Fail("TxPost encode returned None");
    }
    if buf.len() != 48 {
        return TestResult::Fail("TX_POST_SIZE not 48 bytes");
    }
    // msgtype must be TxPost (0x0F).
    if buf[0] != MsgType::TxPost as u8 {
        return TestResult::Fail("TxPost msgtype byte wrong");
    }
    // data_len at bytes 26-27 LE.
    if buf[26..28] != 100u16.to_le_bytes() {
        return TestResult::Fail("TxPost data_len mis-encoded");
    }
    // Round-trip.
    let decoded = match TxPost::decode(&buf) {
        Some(v) => v,
        None => return TestResult::Fail("TxPost decode failed"),
    };
    if decoded != desc {
        return TestResult::Fail("TxPost round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/brcmfmac", smoke_brcmfmac_bcdc_tx_post_encode);

fn smoke_brcmfmac_rx_complete_decode() -> TestResult {
    // Build an RxComplete for a 1500-byte frame with data_offset=28
    // (standard brcmfmac overhead before the 802.11 payload). Mirrors
    // brcmf_rx_frame (~L502, core.c) stripping the header.
    let rxc = RxComplete {
        hdr: CommonHdr {
            msgtype: MsgType::RxCmplt as u8,
            ifidx: 0,
            flags: 0,
            request_id: 42,
        },
        status: 0,
        flow_ring_id: 0,
        rx_status_0: 0x00C8, // RSSI=0, status bits=0
        rx_status_1: 0,
        data_offset: 28,
        data_len: 1500,
    };
    let mut buf = [0u8; RX_COMPLETE_SIZE];
    if rxc.encode(&mut buf).is_none() {
        return TestResult::Fail("RxComplete encode returned None");
    }
    if buf.len() != 40 {
        return TestResult::Fail("RX_COMPLETE_SIZE not 40 bytes");
    }
    // data_offset must land at byte 16.
    if buf[16] != 28 {
        return TestResult::Fail("RxComplete data_offset mis-encoded");
    }
    let decoded = match RxComplete::decode(&buf) {
        Some(v) => v,
        None => return TestResult::Fail("RxComplete decode failed"),
    };
    if decoded != rxc {
        return TestResult::Fail("RxComplete round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/brcmfmac", smoke_brcmfmac_rx_complete_decode);

fn smoke_brcmfmac_tx_status_roundtrip() -> TestResult {
    let st = TxStatus {
        hdr: CommonHdr {
            msgtype: MsgType::TxStatus as u8,
            ifidx: 0,
            flags: 0,
            request_id: 1,
        },
        status: 0,
        flow_ring_id: 3,
        tx_status: 0,
    };
    let mut buf = [0u8; TX_STATUS_SIZE];
    if st.encode(&mut buf).is_none() {
        return TestResult::Fail("TxStatus encode returned None");
    }
    if buf.len() != 24 {
        return TestResult::Fail("TX_STATUS_SIZE not 24 bytes");
    }
    let decoded = match TxStatus::decode(&buf) {
        Some(v) => v,
        None => return TestResult::Fail("TxStatus decode failed"),
    };
    if decoded != st {
        return TestResult::Fail("TxStatus round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/brcmfmac", smoke_brcmfmac_tx_status_roundtrip);

fn smoke_brcmfmac_chanspec_5g_5180() -> TestResult {
    // 5180 MHz = channel 36 (5 GHz). Mirrors Linux's `ch20mhz_chspec`
    // and the cfg80211.c::brcmf_cfg80211_set_channel path (~L2445).
    //
    // Expected: channel 36 | BW_20 (0x0800) | BAND_5G (0x1000)
    //         = 0x0024 | 0x0800 | 0x1000 = 0x1824
    let chspec = chanspec_20mhz(36);
    if chanspec_channel(chspec) != 36 {
        return TestResult::Fail("chanspec_channel returned wrong channel");
    }
    if !chanspec_is5g(chspec) {
        return TestResult::Fail("chanspec_is5g returned false for ch36");
    }
    if chspec & WL_CHANSPEC_BW_20 == 0 {
        return TestResult::Fail("chanspec missing BW_20 bits");
    }
    if chspec & WL_CHANSPEC_BAND_5G == 0 {
        return TestResult::Fail("chanspec missing BAND_5G bits");
    }
    let expected: u16 = 36 | WL_CHANSPEC_BW_20 | WL_CHANSPEC_BAND_5G;
    if chspec != expected {
        return TestResult::Fail("chanspec_20mhz(36) value mismatch");
    }
    // 2.4 GHz smoke: channel 6 must round-trip the other band.
    let chspec2g = chanspec_20mhz(6);
    if chanspec_is5g(chspec2g) {
        return TestResult::Fail("channel 6 wrongly classified as 5G");
    }
    if chanspec_channel(chspec2g) != 6 {
        return TestResult::Fail("chanspec_channel wrong for 2G channel 6");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/brcmfmac", smoke_brcmfmac_chanspec_5g_5180);

// ── Stage-4: fwil IOCTL + IOVAR encoders ───────────────────────────────

fn smoke_brcmfmac_fwil_command_table_constants() -> TestResult {
    use super::fwil::{
        BRCMF_C_DOWN, BRCMF_C_GET_REVINFO, BRCMF_C_GET_VAR, BRCMF_C_SET_KEY,
        BRCMF_C_SET_SSID, BRCMF_C_SET_VAR, BRCMF_C_SET_WSEC_PMK, BRCMF_C_UP,
    };
    // Per Linux `fwil.h` (lines 14..83 verbatim).
    if BRCMF_C_UP != 2 {
        return TestResult::Fail("BRCMF_C_UP should be 2");
    }
    if BRCMF_C_DOWN != 3 {
        return TestResult::Fail("BRCMF_C_DOWN should be 3");
    }
    if BRCMF_C_SET_SSID != 26 {
        return TestResult::Fail("BRCMF_C_SET_SSID should be 26");
    }
    if BRCMF_C_SET_KEY != 45 {
        return TestResult::Fail("BRCMF_C_SET_KEY should be 45");
    }
    if BRCMF_C_GET_REVINFO != 98 {
        return TestResult::Fail("BRCMF_C_GET_REVINFO should be 98");
    }
    if BRCMF_C_GET_VAR != 262 {
        return TestResult::Fail("BRCMF_C_GET_VAR should be 262");
    }
    if BRCMF_C_SET_VAR != 263 {
        return TestResult::Fail("BRCMF_C_SET_VAR should be 263");
    }
    if BRCMF_C_SET_WSEC_PMK != 268 {
        return TestResult::Fail("BRCMF_C_SET_WSEC_PMK should be 268");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_fwil_command_table_constants
);

fn smoke_brcmfmac_fwil_iovar_payload_encode() -> TestResult {
    use super::fwil::{build_iovar_payload, parse_iovar_payload};
    // Build the canonical `chanspec` IOVAR — a common path the
    // Linux brcmfmac code drives every time the connect IOCTL fires.
    let mut buf = [0u8; 64];
    let chanspec_le = 0x1824u16.to_le_bytes();
    let written = build_iovar_payload("chanspec", &chanspec_le, &mut buf);
    let n = match written {
        Some(v) => v,
        None => return TestResult::Fail("iovar encode returned None"),
    };
    // Expected: "chanspec\0\x24\x18"  (8 + 1 + 2 = 11).
    if n != 11 {
        return TestResult::Fail("iovar payload size mismatch");
    }
    if &buf[..8] != b"chanspec" {
        return TestResult::Fail("iovar name not at start");
    }
    if buf[8] != 0 {
        return TestResult::Fail("missing NUL between name and data");
    }
    if buf[9..11] != [0x24, 0x18] {
        return TestResult::Fail("iovar data bytes mis-encoded");
    }
    // Round-trip via parse_iovar_payload.
    let (name, data) = match parse_iovar_payload(&buf[..n]) {
        Some(v) => v,
        None => return TestResult::Fail("iovar parse returned None"),
    };
    if name != "chanspec" {
        return TestResult::Fail("iovar parse name mismatch");
    }
    if data != [0x24, 0x18] {
        return TestResult::Fail("iovar parse data mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_fwil_iovar_payload_encode
);

fn smoke_brcmfmac_fwil_iovar_too_small_buffer_rejected() -> TestResult {
    use super::fwil::build_iovar_payload;
    // 4-byte buffer can't hold `"chanspec"` even before the NUL.
    let mut tiny = [0u8; 4];
    if build_iovar_payload("chanspec", &[0u8; 0], &mut tiny).is_some() {
        return TestResult::Fail("encode should reject too-small buffer");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_fwil_iovar_too_small_buffer_rejected
);

fn smoke_brcmfmac_fwil_ssid_le_encode() -> TestResult {
    use super::fwil::{decode_ssid_le, encode_ssid_le, SSID_LE_SIZE};
    let ssid = b"NarfTestNet";
    let mut buf = [0u8; SSID_LE_SIZE];
    if encode_ssid_le(ssid, &mut buf).is_none() {
        return TestResult::Fail("encode_ssid_le returned None on valid SSID");
    }
    // Wire ordering: u32 LE length, then 32-byte buffer.
    if buf[..4] != (ssid.len() as u32).to_le_bytes() {
        return TestResult::Fail("ssid length byte mis-encoded");
    }
    if &buf[4..4 + ssid.len()] != ssid {
        return TestResult::Fail("ssid bytes not copied verbatim");
    }
    // Padding bytes after the SSID must be zero.
    for &b in &buf[4 + ssid.len()..SSID_LE_SIZE] {
        if b != 0 {
            return TestResult::Fail("ssid padding not zero");
        }
    }
    // Round-trip.
    let (decoded_len, decoded_buf) = match decode_ssid_le(&buf) {
        Some(v) => v,
        None => return TestResult::Fail("decode_ssid_le returned None"),
    };
    if decoded_len as usize != ssid.len() {
        return TestResult::Fail("decoded ssid length mismatch");
    }
    if &decoded_buf[..ssid.len()] != ssid {
        return TestResult::Fail("decoded ssid bytes mismatch");
    }
    // Over-length SSID rejected.
    let too_long = [b'A'; 64];
    if encode_ssid_le(&too_long, &mut buf).is_some() {
        return TestResult::Fail("encode_ssid_le should reject 64-byte SSID");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_fwil_ssid_le_encode
);

fn smoke_brcmfmac_fwil_join_params_encode() -> TestResult {
    use super::fwil::{encode_join_params, ETH_ALEN, JOIN_PARAMS_BLIND_SIZE};
    use super::msgbuf::chanspec_20mhz;
    let ssid = b"MyHomeWifi";
    let mut buf = [0u8; 64];
    let chanspec = chanspec_20mhz(36); // 5 GHz channel 36, BW20.
    let n = match encode_join_params(ssid, None, chanspec, &mut buf) {
        Some(v) => v,
        None => return TestResult::Fail("encode_join_params returned None"),
    };
    if n != JOIN_PARAMS_BLIND_SIZE {
        return TestResult::Fail("join params size mismatch");
    }
    // SSID length at byte 0.
    if buf[..4] != (ssid.len() as u32).to_le_bytes() {
        return TestResult::Fail("join: ssid length mis-encoded");
    }
    // BSSID at byte 36 — all-zero for "any AP".
    for &b in &buf[36..36 + ETH_ALEN] {
        if b != 0 {
            return TestResult::Fail("join: bssid not zeroed for blind join");
        }
    }
    // chanspec_num = 1 at byte 42..46 (we passed a real chanspec).
    if buf[42..46] != 1u32.to_le_bytes() {
        return TestResult::Fail("join: chanspec_num not 1");
    }
    // chanspec at byte 46..48.
    if buf[46..48] != chanspec.to_le_bytes() {
        return TestResult::Fail("join: chanspec not encoded LE");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_fwil_join_params_encode
);

// ── Stage-5: PCIe shared-RAM layout decode ─────────────────────────────

fn smoke_brcmfmac_shared_info_decode_v6() -> TestResult {
    use super::shared::{
        SharedInfo, DEF_MAX_RXBUFPOST, SHARED_FLAG_DMA_INDEX, SHARED_FLAG_HOSTRDY_DB1,
    };
    // Build a synthetic shared-info block: version 6, DMA-indices on,
    // HOSTRDY-DB1 on, max_rxbufpost = 96, rx_dataoffset = 36 bytes.
    let flags: u32 = 6 | SHARED_FLAG_DMA_INDEX | SHARED_FLAG_HOSTRDY_DB1;
    let mut buf = [0u8; 96];
    buf[0..4].copy_from_slice(&flags.to_le_bytes());
    buf[20..24].copy_from_slice(&0xDEAD_C0DEu32.to_le_bytes());
    buf[34..36].copy_from_slice(&96u16.to_le_bytes());
    buf[36..40].copy_from_slice(&36u32.to_le_bytes());
    buf[40..44].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    buf[44..48].copy_from_slice(&0x0001_0004u32.to_le_bytes());
    buf[48..52].copy_from_slice(&0x0002_0000u32.to_le_bytes());

    let parsed = match SharedInfo::parse(&buf) {
        Some(v) => v,
        None => return TestResult::Fail("SharedInfo::parse returned None"),
    };
    if parsed.version != 6 {
        return TestResult::Fail("SharedInfo version mismatch");
    }
    if parsed.max_rxbufpost != 96 {
        return TestResult::Fail("SharedInfo max_rxbufpost mismatch");
    }
    if parsed.rx_dataoffset != 36 {
        return TestResult::Fail("SharedInfo rx_dataoffset mismatch");
    }
    if parsed.htod_mb_data_addr != 0x0001_0000 {
        return TestResult::Fail("htod_mb_data_addr mismatch");
    }
    if parsed.ring_info_addr != 0x0002_0000 {
        return TestResult::Fail("ring_info_addr mismatch");
    }
    if !parsed.uses_dma_indices() {
        return TestResult::Fail("uses_dma_indices() should be true");
    }
    if !parsed.hostrdy_db1() {
        return TestResult::Fail("hostrdy_db1() should be true");
    }
    if parsed.pre_v7() != true {
        return TestResult::Fail("v6 firmware is pre_v7()");
    }
    buf[34..36].copy_from_slice(&0u16.to_le_bytes());
    let saturated = SharedInfo::parse(&buf).unwrap();
    if saturated.max_rxbufpost != DEF_MAX_RXBUFPOST {
        return TestResult::Fail("max_rxbufpost 0 should saturate to default 255");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_shared_info_decode_v6
);

fn smoke_brcmfmac_shared_info_rejects_bad_version() -> TestResult {
    use super::shared::SharedInfo;
    let mut buf = [0u8; 96];
    buf[0..4].copy_from_slice(&99u32.to_le_bytes());
    if SharedInfo::parse(&buf).is_some() {
        return TestResult::Fail("version 99 should be rejected");
    }
    buf[0..4].copy_from_slice(&4u32.to_le_bytes());
    if SharedInfo::parse(&buf).is_some() {
        return TestResult::Fail("version 4 should be rejected");
    }
    if SharedInfo::parse(&[0u8; 8]).is_some() {
        return TestResult::Fail("short buffer should be rejected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_shared_info_rejects_bad_version
);

fn smoke_brcmfmac_ring_info_decode() -> TestResult {
    use super::shared::{RingInfo, RINGINFO_SIZE};
    let mut buf = [0u8; RINGINFO_SIZE];
    buf[0..4].copy_from_slice(&0x0040_0000u32.to_le_bytes());
    buf[4..8].copy_from_slice(&0x00FFu32.to_le_bytes());
    buf[8..12].copy_from_slice(&0x0100u32.to_le_bytes());
    buf[12..16].copy_from_slice(&0x0101u32.to_le_bytes());
    buf[16..20].copy_from_slice(&0x0102u32.to_le_bytes());
    buf[52..54].copy_from_slice(&5u16.to_le_bytes());
    buf[54..56].copy_from_slice(&5u16.to_le_bytes());
    buf[56..58].copy_from_slice(&3u16.to_le_bytes());

    let info = match RingInfo::parse(&buf) {
        Some(v) => v,
        None => return TestResult::Fail("RingInfo::parse returned None"),
    };
    if info.ringmem != 0x0040_0000 {
        return TestResult::Fail("ringmem TCM addr mismatch");
    }
    if info.max_flowrings != 5 || info.max_submissionrings != 5 || info.max_completionrings != 3 {
        return TestResult::Fail("ring counts mismatch");
    }
    if RingInfo::parse(&buf[..RINGINFO_SIZE - 1]).is_some() {
        return TestResult::Fail("RingInfo::parse on too-small buffer should fail");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/brcmfmac", smoke_brcmfmac_ring_info_decode);

fn smoke_brcmfmac_ring_mem_entry_decode() -> TestResult {
    use super::shared::{RingMemEntry, RING_MEM_SZ};
    let mut buf = [0u8; RING_MEM_SZ as usize];
    buf[4..6].copy_from_slice(&64u16.to_le_bytes());
    buf[6..8].copy_from_slice(&63u16.to_le_bytes());
    buf[8..16].copy_from_slice(&0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());

    let e = match RingMemEntry::parse(&buf) {
        Some(v) => v,
        None => return TestResult::Fail("RingMemEntry::parse returned None"),
    };
    if e.max_item != 64 {
        return TestResult::Fail("ring mem max_item mismatch");
    }
    if e.len_items != 63 {
        return TestResult::Fail("ring mem len_items mismatch");
    }
    if e.base_addr != 0xDEAD_BEEF_CAFE_BABE {
        return TestResult::Fail("ring mem base_addr mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_ring_mem_entry_decode
);

// ── Stage-6: firmware TRX header + NVRAM parser ───────────────────────

fn smoke_brcmfmac_trx_header_decode() -> TestResult {
    use super::firmware::{TrxHeader, TRX_HEADER_SIZE, TRX_MAGIC};
    let mut buf = [0u8; TRX_HEADER_SIZE];
    buf[0..4].copy_from_slice(&TRX_MAGIC.to_le_bytes());
    buf[4..8].copy_from_slice(&0x0010_0000u32.to_le_bytes());
    buf[8..12].copy_from_slice(&0xCAFE_BABEu32.to_le_bytes());
    buf[12..16].copy_from_slice(&0x0001_0002u32.to_le_bytes());
    buf[16..20].copy_from_slice(&28u32.to_le_bytes());
    buf[20..24].copy_from_slice(&0x0004_0000u32.to_le_bytes());
    buf[24..28].copy_from_slice(&0x0008_0000u32.to_le_bytes());

    let h = match TrxHeader::parse(&buf) {
        Some(v) => v,
        None => return TestResult::Fail("TrxHeader::parse returned None"),
    };
    if h.magic != TRX_MAGIC {
        return TestResult::Fail("TRX magic mismatch");
    }
    if h.length != 0x0010_0000 {
        return TestResult::Fail("TRX length mismatch");
    }
    if h.version() != 1 {
        return TestResult::Fail("TRX version mismatch");
    }
    if h.flags() != 2 {
        return TestResult::Fail("TRX flags mismatch");
    }
    if h.offsets[0] != 28 || h.offsets[1] != 0x40000 || h.offsets[2] != 0x80000 {
        return TestResult::Fail("TRX offsets mismatch");
    }
    buf[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    if TrxHeader::parse(&buf).is_some() {
        return TestResult::Fail("wrong magic should be rejected");
    }
    if TrxHeader::parse(&buf[..TRX_HEADER_SIZE - 1]).is_some() {
        return TestResult::Fail("short buffer should be rejected");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/brcmfmac", smoke_brcmfmac_trx_header_decode);

fn smoke_brcmfmac_fw_embedded_ramsize() -> TestResult {
    use super::firmware::{embedded_ramsize, FW_RAMSIZE_MAGIC, FW_RAMSIZE_OFFSET};
    let mut blob = alloc::vec![0u8; FW_RAMSIZE_OFFSET + 8 + 256];
    blob[FW_RAMSIZE_OFFSET..FW_RAMSIZE_OFFSET + 4]
        .copy_from_slice(&FW_RAMSIZE_MAGIC.to_le_bytes());
    blob[FW_RAMSIZE_OFFSET + 4..FW_RAMSIZE_OFFSET + 8]
        .copy_from_slice(&0x0040_0000u32.to_le_bytes());
    match embedded_ramsize(&blob) {
        Some(0x0040_0000) => {}
        _ => return TestResult::Fail("embedded_ramsize didn't return 4 MiB"),
    }
    blob[FW_RAMSIZE_OFFSET] = 0;
    if embedded_ramsize(&blob).is_some() {
        return TestResult::Fail("non-magic should produce None");
    }
    let tiny = [0u8; 4];
    if embedded_ramsize(&tiny).is_some() {
        return TestResult::Fail("tiny blob should produce None");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_fw_embedded_ramsize
);

fn smoke_brcmfmac_nvram_parse_basic() -> TestResult {
    use super::firmware::parse_nvram;
    let input = b"# Broadcom 4356 PCIe NVRAM\n\
                  boardrev=0x1101\n\
                  boardtype=0x07c1\n\
                  # MAC address override\n\
                  macaddr=00:11:22:33:44:55\n\
                  cckdigfilttype=4\n\
                  rxchain=3\n";
    let parsed = parse_nvram(input);
    if !parsed.boardrev_seen {
        return TestResult::Fail("boardrev=… should have been observed");
    }
    if parsed.multi_dev_v1 || parsed.multi_dev_v2 {
        return TestResult::Fail("single-dev file misdetected as multi-dev");
    }
    let entries: alloc::vec::Vec<&[u8]> = parsed
        .bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .collect();
    if entries.len() != 5 {
        return TestResult::Fail("expected 5 entries from sample NVRAM");
    }
    if entries[0] != b"boardrev=0x1101" {
        return TestResult::Fail("first entry mismatch");
    }
    if entries[2] != b"macaddr=00:11:22:33:44:55" {
        return TestResult::Fail("macaddr entry mismatch");
    }
    if entries[4] != b"rxchain=3" {
        return TestResult::Fail("last entry mismatch");
    }
    for e in &entries {
        for &b in *e {
            if b == 0 || b == b'#' {
                return TestResult::Fail("NVRAM entry contains illegal byte");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/brcmfmac", smoke_brcmfmac_nvram_parse_basic);

fn smoke_brcmfmac_nvram_skips_raw1_and_bom() -> TestResult {
    use super::firmware::parse_nvram;
    let mut input: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    input.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
    input.extend_from_slice(b"foo=bar\nRAW1=ignoreme\nbaz=qux\n");
    let parsed = parse_nvram(&input);
    let entries: alloc::vec::Vec<&[u8]> = parsed
        .bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .collect();
    if entries.len() != 2 {
        return TestResult::Fail("RAW1 entry should be dropped");
    }
    if entries[0] != b"foo=bar" || entries[1] != b"baz=qux" {
        return TestResult::Fail("entries around RAW1 lost or reordered");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_nvram_skips_raw1_and_bom
);

fn smoke_brcmfmac_nvram_appends_default_boardrev() -> TestResult {
    use super::firmware::{append_default_boardrev, parse_nvram, NVRAM_DEFAULT_BOARDREV};
    let input = b"foo=1\nbar=2\n";
    let mut parsed = parse_nvram(input);
    if parsed.boardrev_seen {
        return TestResult::Fail("test setup wrong: no boardrev in input");
    }
    append_default_boardrev(&mut parsed);
    if !parsed.boardrev_seen {
        return TestResult::Fail("append_default_boardrev didn't flip boardrev_seen");
    }
    let last_entry: &[u8] = parsed
        .bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .last()
        .unwrap_or(&[]);
    if last_entry != NVRAM_DEFAULT_BOARDREV {
        return TestResult::Fail("default boardrev entry not appended");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_nvram_appends_default_boardrev
);

// ── Stage-7: ring buffer + doorbell ────────────────────────────────────

fn smoke_brcmfmac_ringbuf_buf_size_and_reserve() -> TestResult {
    use super::ringbuf::RingBuf;
    use core::ptr;
    // Build a 64×40 H2D control-submit ring with a null host base — we
    // only exercise the index dance.
    let mut rb = RingBuf::new(0, 64, 40, ptr::null_mut(), 0xDEAD_BEEF, 0x100, 0x102);
    if rb.buf_size() != 64 * 40 {
        return TestResult::Fail("buf_size should be depth × item_len");
    }
    let off = match rb.reserve_one() {
        Some(o) => o,
        None => return TestResult::Fail("reserve_one returned None on empty ring"),
    };
    if off != 0 {
        return TestResult::Fail("first reserve_one should return byte 0");
    }
    rb.publish();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_ringbuf_buf_size_and_reserve
);

fn smoke_brcmfmac_write_complete_doorbell_seq() -> TestResult {
    use super::ringbuf::{
        write_complete, RecordingDoorbell, RecordingIndexIo, RingBuf, DEFAULT_DOORBELL_VALUE,
    };
    use core::ptr;
    // 16×24 ring. w_idx_addr = 0x200, r_idx_addr = 0x202, mailbox at
    // 0x140 (default reginfo H2D_MAILBOX_0).
    let mut rb = RingBuf::new(2, 16, 24, ptr::null_mut(), 0, 0x202, 0x200);
    rb.reserve_one().unwrap();
    rb.reserve_one().unwrap();
    let mut idx = RecordingIndexIo::default();
    let mut door = RecordingDoorbell::default();
    write_complete(&mut rb, &mut idx, &mut door, 0x140, DEFAULT_DOORBELL_VALUE);
    // After publish + push_w_idx + ring_bell:
    //  - idx slot @ 0x200 should hold w_ptr=2
    //  - bells should have one entry (0x140, 1)
    if idx.slots.get(&0x200).copied() != Some(2) {
        return TestResult::Fail("push_w_idx didn't land w_ptr=2 at 0x200");
    }
    if door.bells.len() != 1 || door.bells[0] != (0x140, 1) {
        return TestResult::Fail("doorbell sequence wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_write_complete_doorbell_seq
);

fn smoke_brcmfmac_hostrdy_db1_value() -> TestResult {
    use super::ringbuf::HOSTRDY_DB1_VALUE;
    // Per BRCMF_PCIE_SHARED_HOSTRDY_DB1 (pcie.c ~L222).
    if HOSTRDY_DB1_VALUE != 0x1000_0000 {
        return TestResult::Fail("HOSTRDY_DB1 sentinel value wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_hostrdy_db1_value
);

// ── Stage-8: fweh event decode + EAPOL 4-way handshake ───────────────

fn smoke_brcmfmac_fweh_link_up_decode() -> TestResult {
    use super::fweh::{
        EventMsg, BRCMF_E_LINK, BRCMF_EVENT_MSG_LINK, EVENT_BE_OFFSET, EVENT_ENVELOPE_SIZE,
    };
    let mut buf = [0u8; EVENT_ENVELOPE_SIZE + 16];
    // Fill the BE event_msg fields at offset EVENT_BE_OFFSET.
    let s = EVENT_BE_OFFSET;
    // version=1
    buf[s..s + 2].copy_from_slice(&1u16.to_be_bytes());
    // flags = LINK (= 1)
    buf[s + 2..s + 4].copy_from_slice(&BRCMF_EVENT_MSG_LINK.to_be_bytes());
    // event_code = BRCMF_E_LINK (16)
    buf[s + 4..s + 8].copy_from_slice(&BRCMF_E_LINK.to_be_bytes());
    // status / reason / auth_type / datalen all zero.
    // addr at +24..30 = AP MAC
    buf[s + 24..s + 30].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    // ifidx/bsscfgidx at +46/+47
    buf[s + 46] = 0;
    buf[s + 47] = 0;

    let evt = match EventMsg::parse(&buf) {
        Some(v) => v,
        None => return TestResult::Fail("EventMsg::parse returned None"),
    };
    if !evt.is_link_up() {
        return TestResult::Fail("is_link_up() should be true");
    }
    if evt.event_code != BRCMF_E_LINK {
        return TestResult::Fail("event_code != BRCMF_E_LINK");
    }
    if evt.addr != [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF] {
        return TestResult::Fail("addr decoded incorrectly");
    }
    // Now flip the LINK flag to test the down path.
    buf[s + 2..s + 4].copy_from_slice(&0u16.to_be_bytes());
    let evt_down = EventMsg::parse(&buf).unwrap();
    if !evt_down.is_link_down() {
        return TestResult::Fail("is_link_down() should be true with flags=0");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_fweh_link_up_decode
);

fn smoke_brcmfmac_fweh_assoc_decode() -> TestResult {
    use super::fweh::{
        EventMsg, BRCMF_E_ASSOC, BRCMF_E_STATUS_SUCCESS, EVENT_BE_OFFSET, EVENT_ENVELOPE_SIZE,
    };
    let mut buf = [0u8; EVENT_ENVELOPE_SIZE];
    let s = EVENT_BE_OFFSET;
    buf[s + 4..s + 8].copy_from_slice(&BRCMF_E_ASSOC.to_be_bytes());
    buf[s + 8..s + 12].copy_from_slice(&BRCMF_E_STATUS_SUCCESS.to_be_bytes());
    let evt = EventMsg::parse(&buf).unwrap();
    if !evt.is_assoc_success() {
        return TestResult::Fail("is_assoc_success() should be true");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_fweh_assoc_decode
);

fn smoke_brcmfmac_fweh_psk_sup_done() -> TestResult {
    use super::fweh::{
        EventMsg, BRCMF_E_PSK_SUP, BRCMF_E_STATUS_FWSUP_COMPLETED, EVENT_BE_OFFSET,
        EVENT_ENVELOPE_SIZE,
    };
    let mut buf = [0u8; EVENT_ENVELOPE_SIZE];
    let s = EVENT_BE_OFFSET;
    buf[s + 4..s + 8].copy_from_slice(&BRCMF_E_PSK_SUP.to_be_bytes());
    buf[s + 8..s + 12].copy_from_slice(&BRCMF_E_STATUS_FWSUP_COMPLETED.to_be_bytes());
    let evt = EventMsg::parse(&buf).unwrap();
    if !evt.is_psk_supplicant_done() {
        return TestResult::Fail("PSK_SUP completion not recognised");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_fweh_psk_sup_done
);

fn smoke_brcmfmac_fweh_event_msg_too_short() -> TestResult {
    use super::fweh::{EventMsg, EVENT_ENVELOPE_SIZE};
    // Truncated buffer must reject.
    let buf = [0u8; EVENT_ENVELOPE_SIZE - 1];
    if EventMsg::parse(&buf).is_some() {
        return TestResult::Fail("parse should reject short buffer");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_fweh_event_msg_too_short
);

fn smoke_brcmfmac_eapol_m2_build() -> TestResult {
    use super::fweh::{
        build_m2, EAPOL_KEY_FRAME_FIXED_SIZE, EAPOL_TYPE_KEY, EAPOL_VERSION, ETH_P_PAE,
        KEY_DESCRIPTOR_RSN, KEY_INFO_KEY_MIC, KEY_INFO_PAIRWISE,
    };
    let ap_mac = [0xA0u8, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5];
    let sta_mac = [0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55];
    let snonce = [0xABu8; 32];
    let rsn_ie = b"\x30\x14\x01\x00\x00\x0F\xAC\x04\x01\x00\x00\x0F\xAC\x04\x01\x00\x00\x0F\xAC\x02\x00\x00";
    let m2 = build_m2(ap_mac, sta_mac, snonce, 1, rsn_ie);
    let mut buf = [0u8; EAPOL_KEY_FRAME_FIXED_SIZE + 32];
    let n = match m2.encode(&mut buf) {
        Some(v) => v,
        None => return TestResult::Fail("M2 encode returned None"),
    };
    if n != EAPOL_KEY_FRAME_FIXED_SIZE + rsn_ie.len() {
        return TestResult::Fail("M2 encode wrong total length");
    }
    // ethhdr — dst=AP MAC, src=STA MAC.
    if buf[..6] != ap_mac {
        return TestResult::Fail("M2 ethhdr dst MAC wrong");
    }
    if buf[6..12] != sta_mac {
        return TestResult::Fail("M2 ethhdr src MAC wrong");
    }
    if buf[12..14] != ETH_P_PAE.to_be_bytes() {
        return TestResult::Fail("M2 ethertype wrong (should be 0x888E)");
    }
    // EAPOL header.
    if buf[14] != EAPOL_VERSION {
        return TestResult::Fail("EAPOL version wrong");
    }
    if buf[15] != EAPOL_TYPE_KEY {
        return TestResult::Fail("EAPOL type wrong (should be 3 = Key)");
    }
    // Body length = 95 + 22 (RSN IE) = 117.
    let body_len = u16::from_be_bytes([buf[16], buf[17]]);
    if body_len as usize != 95 + rsn_ie.len() {
        return TestResult::Fail("EAPOL body_len mismatch");
    }
    // Key descriptor type 2 (RSN).
    if buf[18] != KEY_DESCRIPTOR_RSN {
        return TestResult::Fail("Key descriptor not RSN");
    }
    // Key info has PAIRWISE + KEY_MIC + version=2.
    let key_info = u16::from_be_bytes([buf[19], buf[20]]);
    if key_info & KEY_INFO_PAIRWISE == 0 {
        return TestResult::Fail("M2 missing PAIRWISE bit");
    }
    if key_info & KEY_INFO_KEY_MIC == 0 {
        return TestResult::Fail("M2 missing KEY_MIC bit");
    }
    // Replay counter (BE) at byte 23..31.
    let replay = u64::from_be_bytes([
        buf[23], buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30],
    ]);
    if replay != 1 {
        return TestResult::Fail("M2 replay counter mismatch");
    }
    // SNonce starts at byte 31, runs 32 bytes.
    for &b in &buf[31..63] {
        if b != 0xAB {
            return TestResult::Fail("M2 SNonce bytes mismatched");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/brcmfmac", smoke_brcmfmac_eapol_m2_build);

fn smoke_brcmfmac_eapol_m4_secure_bit() -> TestResult {
    use super::fweh::{build_m4, EAPOL_KEY_FRAME_FIXED_SIZE, KEY_INFO_SECURE};
    let ap_mac = [0u8; 6];
    let sta_mac = [0u8; 6];
    let m4 = build_m4(ap_mac, sta_mac, 5);
    let mut buf = [0u8; EAPOL_KEY_FRAME_FIXED_SIZE];
    let _ = m4.encode(&mut buf).unwrap();
    let key_info = u16::from_be_bytes([buf[19], buf[20]]);
    if key_info & KEY_INFO_SECURE == 0 {
        return TestResult::Fail("M4 should have SECURE bit set");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_eapol_m4_secure_bit
);

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

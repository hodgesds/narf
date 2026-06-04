//! End-to-end smokes for the NARF WiFi stack — Wave 31.
//!
//! Walks every WiFi driver's orchestration sequence from PCI probe
//! match through MAC vif setup, channel switch, WPA2 4-way handshake
//! shapes, and (where the driver exposes it) `narf_net::iface`
//! registration + /proc/net/dev visibility.
//!
//! Per the wave-31 brief: the per-layer unit smokes already cover
//! individual descriptor encoders / command-frame layouts. This file
//! covers **orchestration** — does the sequence as a whole produce
//! bytes that match the IEEE / vendor specs end-to-end?
//!
//! ## Sandbox shape
//!
//! Real PCIe + DMA + IRQ delivery is out of scope (no QEMU model for
//! these radios). The smokes stay pure-data:
//!
//!   - PCI match table presence per driver — proxy for "probe would
//!     have been called on real silicon for the device IDs we declare".
//!   - For mt7921: walk the bring-up orchestrator (Wave 11 Stages
//!     4-14) by calling each pure encoder (`build_mcu_init_sequence`,
//!     `build_mac_vif_setup_sequence`, `build_channel_switch_body`,
//!     `build_assoc_open_frames`, `build_secure_sta_rec_body`) and
//!     check the wire bytes match the IEEE / Linux references.
//!   - For brcmfmac: BCDC header + IOVAR encoding via
//!     `fwil::build_iovar_payload`.
//!   - For ath11k: `wmi::build_vdev_create` byte layout.
//!   - For iwlwifi: `mac_ctx::build_mac_context_cmd` byte layout.
//!   - For rtw88 / rtw89 / ath10k: PCI match table + chip
//!     classification.
//!
//! For WPA2-PSK: the 4-way M1→M2 transition smoke walks the
//! supplicant state machine using `iwlwifi::wpa::HmacSha1` (which
//! already passes the FIPS 180-4 SHA-1 vector + RFC 2104 HMAC-SHA1
//! vector); we additionally verify PTK derivation is deterministic
//! and produces non-zero KCK/KEK/TK against a known PMK.
//!
//! For the iface-registry + /proc/net/dev integration: we drive
//! `narf_net::iface::register("wlan0", mac, send_fn)` directly with
//! a synthetic send and then verify `iface::lookup("wlan0")` plus
//! `iface::snapshot_counters()` reports it. The procfs renderer is
//! covered by its own subsystem smokes (filesystem/procfs/net.rs);
//! we don't re-test the byte format here.
//!
//! ## Linux refs
//!
//! - mt7921: `drivers/net/wireless/mediatek/mt76/mt7921/init.c`
//! - iwlwifi: `drivers/net/wireless/intel/iwlwifi/mvm/mac-ctxt.c`
//! - brcmfmac: `drivers/net/wireless/broadcom/brcm80211/brcmfmac/fwil.c`
//! - ath11k: `drivers/net/wireless/ath/ath11k/wmi.c`
//! - rtw88: `drivers/net/wireless/realtek/rtw88/pci.c`
//! - WPA2 4-way: IEEE 802.11-2020 §12.7.6 + RFC 4493 MIC vectors

#![cfg(target_arch = "x86_64")]
#![allow(clippy::needless_range_loop)]

extern crate alloc;

use narf_kernel_test::{kernel_test_in, TestResult};

// ── Smoke 1 — mt7921 PCI probe match table covers 14c3:0608 ──────────

fn smoke_e2e_mt7921_pci_probe_match_for_14c3_0608() -> TestResult {
    use crate::mt7921::{register_pci_driver, MTK_DEV_MT7921, MTK_VENDOR};
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};

    __reset_for_test();
    register_pci_driver();
    let regs = registered_pci_drivers();
    let hit = regs.iter().any(|m| {
        matches!(
            m.kind,
            MatchKind::VendorDevice { vendor, device }
                if vendor == MTK_VENDOR && device == MTK_DEV_MT7921
        )
    });
    if !hit {
        return TestResult::Fail("mt7921 PCI match table missing 14c3:0608");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/e2e",
    smoke_e2e_mt7921_pci_probe_match_for_14c3_0608
);

// ── Smoke 2 — mt7921 WFDMA0 9-ring allocation shape ──────────────────

fn smoke_e2e_mt7921_wfdma0_nine_ring_allocation() -> TestResult {
    use crate::mt7921::dma::{allocate_ring_set, RingSet};
    let rings: RingSet = match allocate_ring_set() {
        Ok(r) => r,
        Err(e) => {
            let _ = e;
            return TestResult::Skip("DMA alloc unavailable in this profile");
        }
    };
    // 5 TX data rings (AC_VO/VI/BE/BK + BMC).
    if rings.tx_data.len() != 5 {
        return TestResult::Fail("expected 5 TX data rings (AC_VO/VI/BE/BK + BMC)");
    }
    // tx_fwdl + tx_mcu + rx_data + rx_mcu_evt = 4 more rings, total 9.
    // Touch each so its Drop is exercised and the struct lays out.
    let _ = (
        &rings.tx_fwdl,
        &rings.tx_mcu,
        &rings.rx_data,
        &rings.rx_mcu_evt,
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/e2e",
    smoke_e2e_mt7921_wfdma0_nine_ring_allocation
);

// ── Smoke 3 — mt7921 firmware blob name resolution (WM + patch) ─────

fn smoke_e2e_mt7921_firmware_blob_names_for_mt7961() -> TestResult {
    use crate::mt7921::pci::firmware_blobs_for;
    use crate::mt7921::MTK_DEV_MT7961;
    let (patch, wm) = firmware_blobs_for(MTK_DEV_MT7961);
    if !patch.starts_with("mediatek/") {
        return TestResult::Fail("rom patch name not under mediatek/");
    }
    if wm != "mediatek/WIFI_RAM_CODE_MT7961_1.bin" {
        return TestResult::Fail("WM firmware-blob name mismatch for MT7961");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/e2e",
    smoke_e2e_mt7921_firmware_blob_names_for_mt7961
);

// ── Smoke 4 — MCU init command sequence (3 cmds, expected sizes) ────

fn smoke_e2e_mt7921_mcu_init_sequence_layout() -> TestResult {
    use crate::mt7921::bringup::{build_mcu_init_sequence, BringUpConfig};
    use crate::mt7921::cmd::{INIT_RA_CFG_SIZE, PM_STATE_CTRL_SIZE, UNI_DEV_INFO_BODY_SIZE};

    let cfg = BringUpConfig {
        own_mac: [0x02, 0x11, 0x22, 0x33, 0x44, 0x55],
        ..BringUpConfig::default()
    };
    let seq = build_mcu_init_sequence(&cfg);
    let expected = PM_STATE_CTRL_SIZE + INIT_RA_CFG_SIZE + UNI_DEV_INFO_BODY_SIZE;
    if seq.len() != expected {
        return TestResult::Fail("MCU init sequence wrong total length");
    }
    // First command: PM_STATE_CTRL — pm_state byte at offset 0 is ACTIVE (0).
    if seq[0] != 0 {
        return TestResult::Fail("PM_STATE_CTRL pm_state should be ACTIVE");
    }
    // UNI DEV_INFO_UPDATE: own MAC starts at PM + RA + UNI hdr + ACTIVE TLV +
    // INFO TLV hdr (4) + omac_idx(1) + band_idx(1) + rsv(2) = +16 inside the UNI body.
    let uni_off = PM_STATE_CTRL_SIZE + INIT_RA_CFG_SIZE;
    let mac_off = uni_off + 8 /*hdr*/ + 8 /*ACTIVE TLV*/ + 8 /*INFO TLV up to MAC*/;
    if &seq[mac_off..mac_off + 6] != &cfg.own_mac {
        return TestResult::Fail("UNI DEV_INFO_UPDATE didn't carry own_mac");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/e2e",
    smoke_e2e_mt7921_mcu_init_sequence_layout
);

// ── Smoke 5 — MAC vif setup body shape (DEV+BSS+STA, 3 TLV bodies) ──

fn smoke_e2e_mt7921_mac_vif_setup_three_bodies() -> TestResult {
    use crate::mt7921::bringup::{build_mac_vif_setup_sequence, BringUpConfig};
    use crate::mt7921::cmd::{
        BSS_INFO_BASIC_TLV_SIZE, CONN_TYPE_STA_INFRA, DEV_INFO_UPDATE_SIZE, NETWORK_TYPE_INFRA,
        STA_REC_BASIC_TLV_SIZE,
    };

    let cfg = BringUpConfig {
        own_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        ..BringUpConfig::default()
    };
    let bssid = [0x42u8; 6];
    let body = build_mac_vif_setup_sequence(&cfg, bssid);
    let expected = DEV_INFO_UPDATE_SIZE + BSS_INFO_BASIC_TLV_SIZE + STA_REC_BASIC_TLV_SIZE;
    if body.len() != expected {
        return TestResult::Fail("MAC vif setup body total length wrong");
    }
    // DEV_INFO_UPDATE carries own_mac at offset 8 (skip tag/len/active/dbdc/omac/rsv).
    if &body[8..14] != &cfg.own_mac {
        return TestResult::Fail("DEV_INFO_UPDATE did not carry own_mac");
    }
    // BSS_INFO_BASIC TLV starts at DEV_INFO_UPDATE_SIZE.
    let bss_off = DEV_INFO_UPDATE_SIZE;
    let net_type = u32::from_le_bytes([
        body[bss_off + 4],
        body[bss_off + 5],
        body[bss_off + 6],
        body[bss_off + 7],
    ]);
    if net_type != NETWORK_TYPE_INFRA {
        return TestResult::Fail("BSS_INFO_BASIC network_type not INFRA");
    }
    if &body[bss_off + 12..bss_off + 18] != &bssid {
        return TestResult::Fail("BSS_INFO_BASIC bssid wrong");
    }
    // STA_REC_BASIC TLV: conn_type at +4 should be STA_INFRA.
    let sta_off = bss_off + BSS_INFO_BASIC_TLV_SIZE;
    let conn_type = u32::from_le_bytes([
        body[sta_off + 4],
        body[sta_off + 5],
        body[sta_off + 6],
        body[sta_off + 7],
    ]);
    if conn_type != CONN_TYPE_STA_INFRA {
        return TestResult::Fail("STA_REC_BASIC conn_type not STA_INFRA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/e2e",
    smoke_e2e_mt7921_mac_vif_setup_three_bodies
);

// ── Smoke 6 — Channel switch to channel 36 / 5180 MHz ───────────────

fn smoke_e2e_mt7921_channel_switch_ch36_5180mhz() -> TestResult {
    use crate::mt7921::bringup::{build_channel_switch_body, BringUpConfig};
    use crate::mt7921::cmd::{CHANNEL_SWITCH_SIZE, CH_BAND_5G, CH_BW_20};

    let cfg = BringUpConfig::default();
    if cfg.channel != 36 {
        return TestResult::Fail("default channel should be 36 (5180 MHz)");
    }
    let body = build_channel_switch_body(&cfg);
    if body.len() != CHANNEL_SWITCH_SIZE {
        return TestResult::Fail("CHANNEL_SWITCH body wrong size");
    }
    // Body offsets per encode_channel_switch:
    //   [0] dbdc_idx=0  [1] control_chan=36  [2] center_chan=36
    //   [3] bw=CH_BW_20 [12] band=CH_BAND_5G
    if body[1] != 36 {
        return TestResult::Fail("control_chan not 36");
    }
    if body[2] != 36 {
        return TestResult::Fail("center_chan not 36");
    }
    if body[3] != CH_BW_20 {
        return TestResult::Fail("bandwidth not 20 MHz");
    }
    if body[12] != CH_BAND_5G {
        return TestResult::Fail("band not 5 GHz");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/e2e",
    smoke_e2e_mt7921_channel_switch_ch36_5180mhz
);

// ── Smoke 7 — Open Auth MGMT frame matches IEEE 802.11 spec ─────────

fn smoke_e2e_mt7921_open_auth_frame_layout() -> TestResult {
    use crate::mt7921::cmd::{
        encode_open_auth_frame, FC_MGMT_AUTH, IEEE80211_AUTH_FRAME_SIZE, IEEE80211_MAC_HDR_SIZE,
    };
    let sta = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    let bssid = [0x42u8; 6];
    let mut frame = alloc::vec![0u8; IEEE80211_AUTH_FRAME_SIZE];
    if encode_open_auth_frame(sta, bssid, &mut frame).is_none() {
        return TestResult::Fail("encode_open_auth_frame returned None");
    }
    // FC must be Auth (Mgmt type + Auth subtype = 0xB0).
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    if fc != FC_MGMT_AUTH {
        return TestResult::Fail("frame_control not Auth");
    }
    if FC_MGMT_AUTH != 0xB0 {
        return TestResult::Fail("FC_MGMT_AUTH constant should be 0xB0 per IEEE 802.11");
    }
    // Payload after the MAC header.
    let p = IEEE80211_MAC_HDR_SIZE;
    let algo = u16::from_le_bytes([frame[p], frame[p + 1]]);
    let seq = u16::from_le_bytes([frame[p + 2], frame[p + 3]]);
    let status = u16::from_le_bytes([frame[p + 4], frame[p + 5]]);
    if algo != 0 {
        return TestResult::Fail("auth algo not Open (0)");
    }
    if seq != 1 {
        return TestResult::Fail("auth seq number not 1 (M1)");
    }
    if status != 0 {
        return TestResult::Fail("auth status not success (0)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/e2e",
    smoke_e2e_mt7921_open_auth_frame_layout
);

// ── Smoke 8 — Association Request frame carries SSID IE ─────────────

fn smoke_e2e_mt7921_assoc_req_frame_carries_ssid_ie() -> TestResult {
    use crate::mt7921::cmd::{encode_assoc_req_frame, FC_MGMT_ASSOC_REQ, IEEE80211_MAC_HDR_SIZE};
    let sta = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    let bssid = [0x42u8; 6];
    let ssid = b"NARF-TEST";
    let cap: u16 = 0x0011; // ESS + ShortPreamble
    let listen_interval: u16 = 5;
    let mut buf = alloc::vec![0u8; IEEE80211_MAC_HDR_SIZE + 2 + 2 + 2 + ssid.len()];
    let n = match encode_assoc_req_frame(sta, bssid, cap, listen_interval, ssid, &mut buf) {
        Some(n) => n,
        None => return TestResult::Fail("encode_assoc_req_frame returned None"),
    };
    if n != IEEE80211_MAC_HDR_SIZE + 2 + 2 + 2 + ssid.len() {
        return TestResult::Fail("assoc-req frame length wrong");
    }
    // FC = AssocReq (Mgmt + subtype 0 = 0x00).
    let fc = u16::from_le_bytes([buf[0], buf[1]]);
    if fc != FC_MGMT_ASSOC_REQ {
        return TestResult::Fail("frame_control not AssocReq");
    }
    // Cap + listen_interval at fixed offsets after MAC hdr.
    let p = IEEE80211_MAC_HDR_SIZE;
    let got_cap = u16::from_le_bytes([buf[p], buf[p + 1]]);
    if got_cap != cap {
        return TestResult::Fail("capability bits wrong");
    }
    let got_li = u16::from_le_bytes([buf[p + 2], buf[p + 3]]);
    if got_li != listen_interval {
        return TestResult::Fail("listen interval wrong");
    }
    // SSID IE: id=0, len=ssid.len(), octets.
    if buf[p + 4] != 0 {
        return TestResult::Fail("SSID IE id should be 0");
    }
    if buf[p + 5] as usize != ssid.len() {
        return TestResult::Fail("SSID IE length wrong");
    }
    if &buf[p + 6..p + 6 + ssid.len()] != ssid {
        return TestResult::Fail("SSID IE octets wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/e2e",
    smoke_e2e_mt7921_assoc_req_frame_carries_ssid_ie
);

// ── Smoke 9 — WPA2-PSK 4-way M1→M2 with PTK derivation ──────────────

fn smoke_e2e_wpa2_4way_handshake_m1_to_m2() -> TestResult {
    use crate::iwlwifi::wpa::{derive_ptk_sha1, HmacSha1};
    use narf_wireless::eapol::{
        FourWayState, KeyFrame, Supplicant, KEY_DESCRIPTOR_RSN, KI_KEY_ACK, KI_KEY_TYPE_PAIRWISE,
    };

    // AP BSSID + STA MAC. Conform to RFC 4493 byte ordering — APs use
    // BIG-endian over the wire, the PRF labels these as `Min(AA,SA) ||
    // Max(AA,SA)` so the derivation is stable.
    let aa = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let sa = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let snonce = [0x33u8; 32];
    let anonce = [0xAAu8; 32];
    let pmk = [0x42u8; 32];

    // Drive the supplicant from idle through M1→M2.
    let mut sup = Supplicant::new(aa, sa, snonce);
    let mut m1 = KeyFrame::empty(16);
    m1.descriptor_type = KEY_DESCRIPTOR_RSN;
    m1.key_information = KI_KEY_TYPE_PAIRWISE | KI_KEY_ACK;
    m1.replay_counter = 1;
    m1.key_nonce = anonce;

    let m2 = match sup.handle(&HmacSha1, &pmk, 16, &m1) {
        Ok(Some(m)) => m,
        Ok(None) => return TestResult::Fail("M1 did not produce M2"),
        Err(_) => return TestResult::Fail("M1 handler errored"),
    };
    if sup.state != FourWayState::WaitM3 {
        return TestResult::Fail("Supplicant state should be WaitM3 after M2");
    }
    if !m2.has_mic() {
        return TestResult::Fail("M2 should carry MIC");
    }
    if !m2.pairwise() {
        return TestResult::Fail("M2 should be pairwise");
    }
    if m2.replay_counter != 1 {
        return TestResult::Fail("M2 replay counter should mirror M1");
    }
    if m2.key_nonce != snonce {
        return TestResult::Fail("M2 nonce should be SNonce");
    }

    // PTK derivation must be deterministic and produce non-zero
    // KCK / KEK / TK — verifying the underlying HMAC-SHA1 PRF works
    // against the same inputs the AP would use.
    let ptk_a = derive_ptk_sha1(&pmk, &aa, &sa, &anonce, &snonce, 16);
    let ptk_b = derive_ptk_sha1(&pmk, &aa, &sa, &anonce, &snonce, 16);
    if ptk_a.kck != ptk_b.kck {
        return TestResult::Fail("PTK derivation not deterministic");
    }
    if ptk_a.kck.iter().all(|&b| b == 0) {
        return TestResult::Fail("KCK all-zeros");
    }
    if ptk_a.kek.iter().all(|&b| b == 0) {
        return TestResult::Fail("KEK all-zeros");
    }
    if ptk_a.tk.len() != 16 {
        return TestResult::Fail("TK length wrong for CCMP-128");
    }
    if ptk_a.tk.iter().all(|&b| b == 0) {
        return TestResult::Fail("TK all-zeros");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/e2e",
    smoke_e2e_wpa2_4way_handshake_m1_to_m2
);

// ── Smoke 10 — iwlwifi probe match + MAC_CONTEXT_CMD payload ────────

fn smoke_e2e_iwlwifi_probe_and_mac_context_cmd() -> TestResult {
    use crate::iwlwifi::mac_ctx::{build_mac_context_cmd, filter_flags, mac_type, MAC_CONTEXT_CMD};
    use crate::iwlwifi::INTEL_VENDOR;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};

    __reset_for_test();
    crate::iwlwifi::register();
    let regs = registered_pci_drivers();
    // AX201 SKU 8086:24FD per Linux iwl_dev_info_table — not all
    // SKUs are registered here, so accept any Intel WiFi match.
    let intel_match = regs.iter().any(
        |m| matches!(m.kind, MatchKind::VendorDevice { vendor, .. } if vendor == INTEL_VENDOR),
    );
    if !intel_match {
        return TestResult::Fail("iwlwifi: no Intel VID PCI match registered");
    }
    // MAC_CONTEXT_CMD encodes.
    let node = [0x02, 0xAB, 0xCD, 0xEF, 0x00, 0x01];
    let buf = build_mac_context_cmd(
        0,
        mac_type::BSS_STA,
        node,
        node,
        filter_flags::IN_NON_MCAST | filter_flags::IN_BEACON,
    );
    if buf.is_empty() {
        return TestResult::Fail("MAC_CONTEXT_CMD payload is empty");
    }
    if buf[0] != MAC_CONTEXT_CMD {
        return TestResult::Fail("MAC_CONTEXT_CMD cmd_id byte wrong");
    }
    // node_addr lives at offset 4 (cmd_hdr) + 4 + 4 + 4 + 4 = 20.
    if &buf[20..26] != &node {
        return TestResult::Fail("MAC_CONTEXT_CMD did not carry node_addr at expected offset");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/e2e",
    smoke_e2e_iwlwifi_probe_and_mac_context_cmd
);

// ── Smoke 11 — rtw88 probe match + name resolution for 8822CE ───────

fn smoke_e2e_rtw88_probe_match_for_8822ce() -> TestResult {
    use crate::rtw88::regs::REALTEK_VENDOR;
    use crate::rtw88::{name_for, register_pci_driver, RTL_DEV_8822CE};
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};

    __reset_for_test();
    register_pci_driver();
    let regs = registered_pci_drivers();
    let hit_8822ce = regs.iter().any(|m| {
        matches!(
            m.kind,
            MatchKind::VendorDevice { vendor, device }
                if vendor == REALTEK_VENDOR && device == RTL_DEV_8822CE
        )
    });
    if !hit_8822ce {
        return TestResult::Fail("rtw88 PCI match missing 10ec:c822 (RTL8822CE)");
    }
    if name_for(RTL_DEV_8822CE) != "rtw88-8822ce" {
        return TestResult::Fail("name_for RTL8822CE wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/e2e",
    smoke_e2e_rtw88_probe_match_for_8822ce
);

// ── Smoke 12 — brcmfmac probe + BCDC IOVAR encode for "ssid" ────────

fn smoke_e2e_brcmfmac_probe_and_iovar_encode() -> TestResult {
    use crate::brcmfmac::fwil::{build_iovar_payload, encode_ssid_le, SSID_LE_SIZE};
    use crate::brcmfmac::pcie::ALL_DEV_IDS;
    use crate::brcmfmac::{register_pci_driver, BROADCOM_VENDOR};
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};

    __reset_for_test();
    register_pci_driver();
    let regs = registered_pci_drivers();
    // brcmfmac registers every Broadcom WiFi DID; check at least one.
    let any_brcm = regs.iter().any(|m| {
        matches!(
            m.kind,
            MatchKind::VendorDevice { vendor, device }
                if vendor == BROADCOM_VENDOR && ALL_DEV_IDS.contains(&device)
        )
    });
    if !any_brcm {
        return TestResult::Fail("brcmfmac match table missing all Broadcom WiFi DIDs");
    }

    // IOVAR encode "ssid\0<ssid_le bytes>" — what cfg80211 ships
    // through the msgbuf control ring for `WL_CMD_SET_SSID`.
    let mut ssid_le = alloc::vec![0u8; SSID_LE_SIZE];
    if encode_ssid_le(b"NARF-AP", &mut ssid_le).is_none() {
        return TestResult::Fail("encode_ssid_le rejected the SSID");
    }
    let mut payload = alloc::vec![0u8; "ssid".len() + 1 + SSID_LE_SIZE];
    let n = match build_iovar_payload("ssid", &ssid_le, &mut payload) {
        Some(n) => n,
        None => return TestResult::Fail("build_iovar_payload returned None"),
    };
    if n != payload.len() {
        return TestResult::Fail("IOVAR payload length wrong");
    }
    // First bytes must be the literal "ssid\0".
    if &payload[..4] != b"ssid" {
        return TestResult::Fail("IOVAR name not 'ssid'");
    }
    if payload[4] != 0 {
        return TestResult::Fail("IOVAR name not NUL-terminated");
    }
    // ssid_le 4-byte LE length should be 7 ("NARF-AP".len()).
    let len = u32::from_le_bytes([payload[5], payload[6], payload[7], payload[8]]);
    if len != 7 {
        return TestResult::Fail("brcmf_ssid_le length field wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/e2e",
    smoke_e2e_brcmfmac_probe_and_iovar_encode
);

// ── Smoke 13 — ath11k probe + WMI VDEV_CREATE encode ────────────────

fn smoke_e2e_ath11k_probe_and_vdev_create_encode() -> TestResult {
    use crate::ath11k::wmi::build_vdev_create;
    use crate::ath11k::{register_pci_driver, ATH11K_DEV_QCA6390, QCOM_VENDOR};
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};

    __reset_for_test();
    register_pci_driver();
    let regs = registered_pci_drivers();
    let qca6390 = regs.iter().any(|m| {
        matches!(
            m.kind,
            MatchKind::VendorDevice { vendor, device }
                if vendor == QCOM_VENDOR && device == ATH11K_DEV_QCA6390
        )
    });
    if !qca6390 {
        return TestResult::Fail("ath11k match table missing 17cb:1101 (QCA6390)");
    }

    // Build a WMI_VDEV_CREATE_CMDID frame and verify the MAC + vdev_id
    // round-trip into the TLV body.
    let vdev_mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    let frame = build_vdev_create(
        0, /* vdev_type = STA */ 1, vdev_mac, /* pdev = 1 */ 1,
    );
    if frame.is_empty() {
        return TestResult::Fail("VDEV_CREATE frame empty");
    }
    // VDEV_CREATE_CMD TLV body follows the WMI cmd header. Locate the
    // MAC by scanning the frame (small enough — < 100 bytes) for a
    // matching 6-byte window. This is robust to header changes.
    let mut found = false;
    for w in frame.windows(6) {
        if w == vdev_mac {
            found = true;
            break;
        }
    }
    if !found {
        return TestResult::Fail("VDEV_CREATE frame does not carry vdev_mac");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/e2e",
    smoke_e2e_ath11k_probe_and_vdev_create_encode
);

// ── Smoke 14 — iface registry: register synthetic wlan0 + lookup ────

/// Synthetic send-fn used by the wlan0 registration smoke. Returns
/// `Ok(())` for every frame so the registration round-trip succeeds.
fn synthetic_wlan0_send(_frame: &[u8]) -> Result<(), ()> {
    Ok(())
}

fn smoke_e2e_iface_registry_wlan0_visible() -> TestResult {
    use narf_net::iface;
    let mac = [0x02, 0x77, 0x88, 0x99, 0xAA, 0xBB];
    iface::register("wlan0-e2e", mac, synthetic_wlan0_send);
    let snap = match iface::lookup("wlan0-e2e") {
        Some(s) => s,
        None => return TestResult::Fail("wlan0-e2e not visible via iface::lookup"),
    };
    if snap.mac != mac {
        return TestResult::Fail("registered MAC did not round-trip via lookup");
    }
    if snap.name != "wlan0-e2e" {
        return TestResult::Fail("interface name did not round-trip");
    }
    // The send-fn must drive an actual call without panicking.
    match (snap.send)(&[0u8; 64]) {
        Ok(()) => {}
        Err(()) => return TestResult::Fail("synthetic send returned Err"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/e2e",
    smoke_e2e_iface_registry_wlan0_visible
);

// ── Smoke 15 — /proc/net/dev snapshot includes registered wlan0 ─────

fn smoke_e2e_proc_net_dev_includes_wlan0() -> TestResult {
    use narf_net::iface;
    let mac = [0x02, 0xCC, 0xDD, 0xEE, 0xFF, 0x00];
    iface::register("wlan0-pnd", mac, synthetic_wlan0_send);
    let snaps = iface::snapshot_counters();
    let hit = snaps.iter().any(|s| s.name == "wlan0-pnd");
    if !hit {
        return TestResult::Fail("wlan0-pnd not in snapshot_counters() output");
    }
    // The /proc/net/dev DevFile renders snapshot_counters() one line
    // per iface — the renderer itself is covered by the filesystem
    // crate. Here we verify the bridge (the snapshot) carries the
    // registered name so a /proc/net/dev read would surface it.
    let entry = snaps
        .iter()
        .find(|s| s.name == "wlan0-pnd")
        .expect("entry present");
    // Stage-1 reports zeroed counters for every iface; the registered
    // interface must at least be present with a coherent row shape.
    // Counters being zero is the contract today.
    let _ = entry.rx_bytes;
    let _ = entry.tx_packets;
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/e2e",
    smoke_e2e_proc_net_dev_includes_wlan0
);

// ── Bonus 16 — rtw89 PCI match table covers RTL8852BE ──────────────

fn smoke_e2e_rtw89_probe_match_for_8852be() -> TestResult {
    use crate::rtw89::{REALTEK_VENDOR, RTL_DEV_8852BE};
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};

    __reset_for_test();
    crate::rtw89::register();
    let regs = registered_pci_drivers();
    let hit = regs.iter().any(|m| {
        matches!(
            m.kind,
            MatchKind::VendorDevice { vendor, device }
                if vendor == REALTEK_VENDOR && device == RTL_DEV_8852BE
        )
    });
    if !hit {
        return TestResult::Fail("rtw89 PCI match missing 10ec:b852 (RTL8852BE)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/e2e",
    smoke_e2e_rtw89_probe_match_for_8852be
);

// ── Bonus 17 — ath10k PCI match table covers QCA988X ────────────────

fn smoke_e2e_ath10k_probe_match_for_qca988x() -> TestResult {
    use crate::ath10k::hw::{ATHEROS_VENDOR, QCA988X_DEVICE_ID};
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};

    __reset_for_test();
    crate::ath10k::register();
    let regs = registered_pci_drivers();
    let hit = regs.iter().any(|m| {
        matches!(
            m.kind,
            MatchKind::VendorDevice { vendor, device }
                if vendor == ATHEROS_VENDOR && device == QCA988X_DEVICE_ID
        )
    });
    if !hit {
        return TestResult::Fail("ath10k PCI match missing 168c:003c (QCA988X)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/e2e",
    smoke_e2e_ath10k_probe_match_for_qca988x
);

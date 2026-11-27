//! MT7925 UNI MCU smoke tests — co-located per project convention.
//!
//! Pure-data: UNI command words, RXD parsing, per-link BA / station
//! add-remove / BSS-info builders, EFUSE UNI requests. They Pass on
//! QEMU. Live-silicon behaviour (actual MCU round-trips on the
//! 14c3:0717 card) is Daniel's hardware validation; these pin the
//! bytes the firmware will receive.

use narf_kernel_test::{kernel_test_in, TestResult};

use super::mcu::*;

fn smoke_mt7925_uni_cmd_words() -> TestResult {
    // mcu_uni_cmd / mcu_wm_uni_cmd / mcu_wm_uni_cmd_query
    // (mt76_connac_mcu.h:1232-1254).
    if mcu_uni_cmd(UNI_CMD_STA_REC_UPDATE) != 0x20003
        || mcu_uni_cmd(UNI_CMD_BSS_INFO_UPDATE) != 0x20002
        || mcu_uni_cmd(UNI_CMD_DEV_INFO_UPDATE) != 0x20001
        || mcu_uni_cmd(UNI_CMD_EFUSE_CTRL) != 0x2002d
        || UNI_STA_REC_UPDATE_CMD != 0x20003
        || UNI_BSS_INFO_UPDATE_CMD != 0x20002
        || UNI_EFUSE_CTRL_CMD != 0x2002d
    {
        return TestResult::Fail("mt7925 UNI command words wrong");
    }
    if mcu_wm_uni_cmd(UNI_CMD_EFUSE_CTRL) != 0x12002d
        || mcu_wm_uni_cmd_query(UNI_CMD_EFUSE_CTRL) != 0x13002d
        || UNI_EFUSE_CTRL_QUERY_CMD != 0x13002d
    {
        return TestResult::Fail("mt7925 WM UNI EFUSE query word wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7925_uni_cmd_words);

fn smoke_mt7925_mcu_rxd_parse() -> TestResult {
    let mut bytes = [0u8; MCU_RXD_SIZE];
    bytes[32..34].copy_from_slice(&64u16.to_le_bytes());
    bytes[34..36].copy_from_slice(&3u16.to_le_bytes());
    bytes[36] = 0x2d; // eid
    bytes[37] = 7; // seq
    bytes[38] = MCU_RXD_OPT_UNSOLICITED_EVENT;
    bytes[40] = 0x11; // ext_eid
    bytes[43] = 2; // s2d_index
    let rxd = match parse_mcu_rxd(&bytes) {
        Some(r) => r,
        None => return TestResult::Fail("mt7925 RXD parse failed on a full header"),
    };
    if rxd.len != 64
        || rxd.pkt_type_id != 3
        || rxd.eid != 0x2d
        || rxd.seq != 7
        || !rxd.is_unsolicited()
        || rxd.is_event()
        || rxd.ext_eid != 0x11
        || rxd.s2d_index != 2
    {
        return TestResult::Fail("mt7925 RXD fields wrong");
    }
    if parse_mcu_rxd(&bytes[..MCU_RXD_SIZE - 1]).is_some() {
        return TestResult::Fail("mt7925 RXD parse accepted a short header");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7925_mcu_rxd_parse);

fn smoke_mt7925_sta_req_hdr() -> TestResult {
    let mut hdr = [0u8; STA_REQ_HDR_SIZE];
    if encode_sta_req_hdr(2, 0x123, 5, &mut hdr).is_none() {
        return TestResult::Fail("mt7925 sta_req_hdr encode failed");
    }
    // bss_idx, wlan_idx_lo, tlv_num 0, append 1, muar, wlan_idx_hi, rsv.
    if hdr != [2, 0x23, 0, 0, 1, 5, 0x01, 0] {
        return TestResult::Fail("mt7925 sta_req_hdr bytes wrong");
    }
    set_sta_req_tlv_count(&mut hdr, 4);
    if hdr[2..4] != [4, 0] {
        return TestResult::Fail("mt7925 sta_req_hdr tlv_num patch wrong");
    }
    let mut bss = [0u8; BSS_REQ_HDR_SIZE];
    if encode_bss_req_hdr(3, &mut bss).is_none() || bss != [3, 0, 0, 0] {
        return TestResult::Fail("mt7925 bss_req_hdr bytes wrong");
    }
    if encode_sta_req_hdr(0, 0, 0, &mut [0u8; STA_REQ_HDR_SIZE - 1]).is_some() {
        return TestResult::Fail("mt7925 sta_req_hdr accepted a short buffer");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7925_sta_req_hdr);

fn smoke_mt7925_uni_ba_reqs() -> TestResult {
    // TX BA, TID 3, AMSDU, enabled, SSN 0x100, winsize 64.
    let tx = match build_uni_tx_ba_req(0, 1, 0, 3, true, true, 0x100, 64) {
        Some(v) => v,
        None => return TestResult::Fail("mt7925 UNI TX BA build failed"),
    };
    if tx.len() != STA_REQ_HDR_SIZE + STA_REC_BA_UNI_TLV_SIZE {
        return TestResult::Fail("mt7925 UNI TX BA length wrong");
    }
    // Header: bss 0, wcid 1, tlv_num 1, append 1, muar 0.
    if tx[0] != 0 || tx[1] != 1 || tx[2] != 1 || tx[4] != 1 || tx[5] != 0 {
        return TestResult::Fail("mt7925 UNI TX BA header wrong");
    }
    let ba = &tx[STA_REQ_HDR_SIZE..];
    if u16::from_le_bytes([ba[0], ba[1]]) != STA_REC_BA
        || u16::from_le_bytes([ba[2], ba[3]]) != STA_REC_BA_UNI_TLV_SIZE as u16
        || ba[4] != 3
        || ba[5] != BA_TYPE_ORIGINATOR
        || ba[6] != 1
        || ba[7] != (1 << 3)
        || u16::from_le_bytes([ba[8], ba[9]]) != 0x100
        || u16::from_le_bytes([ba[10], ba[11]]) != 64
    {
        return TestResult::Fail("mt7925 UNI TX BA TLV bytes wrong");
    }
    // RX BA differs only in ba_type.
    let rx = match build_uni_rx_ba_req(0, 1, 0, 3, true, true, 0x100, 64) {
        Some(v) => v,
        None => return TestResult::Fail("mt7925 UNI RX BA build failed"),
    };
    if rx[STA_REQ_HDR_SIZE + 5] != BA_TYPE_RECIPIENT {
        return TestResult::Fail("mt7925 UNI RX BA type wrong");
    }
    // TID 8 cannot encode ba_en = enable << tid in a u8.
    if build_uni_tx_ba_req(0, 1, 0, 8, false, true, 0, 0).is_some() {
        return TestResult::Fail("mt7925 UNI BA accepted TID 8");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7925_uni_ba_reqs);

fn mld_links(emlsr: bool) -> MldLinks {
    MldLinks {
        own_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        primary: MldLink {
            wcid_idx: 1,
            bss_idx: 0,
        },
        secondary: Some(MldLink {
            wcid_idx: 2,
            bss_idx: 1,
        }),
        eml_cap: 0x0103,
        emlsr,
    }
}

fn sta_params(mld: Option<MldLinks>, state: u8) -> UniStaParams<'static> {
    UniStaParams {
        bss_idx: 0,
        wcid_idx: 1,
        omac_idx: 0,
        // A station vif's peer is the AP (`mt76_connac_mcu_sta_basic_tlv`).
        conn_type: CONN_TYPE_INFRA_AP,
        conn_state: CONN_STATE_PORT_SECURE,
        aid: 7,
        peer_addr: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        qos: true,
        newly: false,
        state,
        phy: UniStaPhy::default(),
        cap_tlvs: &[],
        ra: UniStaRa::default(),
        vht_opmode: 0,
        hdr_trans: UniStaHdrTrans::STATION,
        mld,
    }
}

/// Walk a station request's TLVs (after the 8-byte header) and return
/// their `(tag, len)` pairs in order.
fn sta_tlv_list(req: &[u8]) -> alloc::vec::Vec<(u16, u16)> {
    let mut out = alloc::vec::Vec::new();
    let mut rest = &req[STA_REQ_HDR_SIZE..];
    while rest.len() >= TLV_HDR_SIZE {
        let tag = u16::from_le_bytes([rest[0], rest[1]]);
        let len = u16::from_le_bytes([rest[2], rest[3]]);
        if usize::from(len) < TLV_HDR_SIZE || usize::from(len) > rest.len() {
            break;
        }
        out.push((tag, len));
        rest = &rest[usize::from(len)..];
    }
    out
}

fn smoke_mt7925_uni_sta_update_mld() -> TestResult {
    let req = build_uni_sta_update_req(&sta_params(Some(mld_links(true)), STA_STATE_ASSOC));
    // mt7925_mcu_sta_cmd (v7.0-rc7 mcu.c:1977-2007) with no
    // capability TLVs: BASIC, PHY, RA, STATE_V2, MLD, EHT MLD,
    // HDR_TRANS = 8 + 20 + 12 + 16 + 16 + 28 + 16 + 8.
    if req.len() != 124 {
        return TestResult::Fail("mt7925 UNI station update (MLD) length wrong");
    }
    if u16::from_le_bytes([req[2], req[3]]) != 7 {
        return TestResult::Fail("mt7925 UNI station update (MLD) tlv_num wrong");
    }
    if sta_tlv_list(&req)
        != [
            (STA_REC_BASIC, 20),
            (STA_REC_PHY, 12),
            (STA_REC_RA, 16),
            (STA_REC_STATE, 16),
            (STA_REC_MLD, 28),
            (STA_REC_EHT_MLD, 16),
            (STA_REC_HDR_TRANS, 8),
        ]
    {
        return TestResult::Fail("mt7925 UNI station update (MLD) TLV order wrong");
    }
    // BASIC at 8: conn_type 0x10002, conn_state 2, aid 7, peer, extra 1.
    let basic = &req[8..28];
    if u16::from_le_bytes([basic[0], basic[1]]) != STA_REC_BASIC
        || u32::from_le_bytes([basic[4], basic[5], basic[6], basic[7]]) != 0x10002
        || basic[8] != CONN_STATE_PORT_SECURE
        || u16::from_le_bytes([basic[10], basic[11]]) != 7
        || basic[18..20] != [1, 0]
    {
        return TestResult::Fail("mt7925 UNI station BASIC TLV wrong");
    }
    // STATE_V2 at 56: tag 7, state byte at +4 = ASSOC.
    if u16::from_le_bytes([req[56], req[57]]) != STA_REC_STATE || req[60] != STA_STATE_ASSOC {
        return TestResult::Fail("mt7925 UNI station STATE_V2 TLV wrong");
    }
    // MLD at 72: primary first, secondary second, link_num 2.
    let mld = &req[72..100];
    if u16::from_le_bytes([mld[0], mld[1]]) != STA_REC_MLD
        || mld[4..10] != [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]
        || u16::from_le_bytes([mld[10], mld[11]]) != 1
        || u16::from_le_bytes([mld[12], mld[13]]) != 2
        || u16::from_le_bytes([mld[14], mld[15]]) != 1
        || mld[16] != 2
        || u16::from_le_bytes([mld[20], mld[21]]) != 1
        || mld[22] != 0
        || u16::from_le_bytes([mld[24], mld[25]]) != 2
        || mld[26] != 1
    {
        return TestResult::Fail("mt7925 UNI station MLD TLV wrong");
    }
    // EHT MLD at 100: mld_type 0xff, eml_cap bytes at 10..12.
    let eht = &req[100..116];
    if u16::from_le_bytes([eht[0], eht[1]]) != STA_REC_EHT_MLD
        || eht[5] != 0xff
        || eht[10] != 0x03
        || eht[11] != 0x01
    {
        return TestResult::Fail("mt7925 UNI station EHT MLD TLV wrong");
    }
    // HDR_TRANS closes the enable branch (mcu.c:2005-2007).
    if req[116..124] != [0x2b, 0, 8, 0, 0, 1, 1, 0] {
        return TestResult::Fail("mt7925 UNI station HDR_TRANS tail wrong");
    }
    // No-EMLSR: str_cap[0] = BIT(1) at offset 7, eml_cap bytes zero.
    let req = build_uni_sta_update_req(&sta_params(Some(mld_links(false)), STA_STATE_ASSOC));
    if req[100 + 7] != (1 << 1) || req[100 + 10] != 0 || req[100 + 11] != 0 {
        return TestResult::Fail("mt7925 UNI station EHT MLD STR cap wrong");
    }
    // NONE state: no MLD/EHT MLD TLVs (upstream gates them on
    // state != NONE), even for an MLD vif.
    let single = MldLinks {
        secondary: None,
        ..mld_links(true)
    };
    let req = build_uni_sta_update_req(&sta_params(Some(single), STA_STATE_NONE));
    if req.len() != UNI_STA_UPDATE_BOUND
        || u16::from_le_bytes([req[2], req[3]]) != 5
        || sta_tlv_list(&req)
            != [
                (STA_REC_BASIC, 20),
                (STA_REC_PHY, 12),
                (STA_REC_RA, 16),
                (STA_REC_STATE, 16),
                (STA_REC_HDR_TRANS, 8),
            ]
    {
        return TestResult::Fail("mt7925 UNI station update (NONE) wrong");
    }
    // Non-MLD vif, ASSOC: the MLD TLV is still sent
    // (`mt7925_mcu_sta_mld_tlv` has no MLD gate) with the peer
    // address, primary_id = wlan_id = the WCID, link_num 0; no EHT MLD
    // (`ieee80211_vif_is_mld` gate).
    let req = build_uni_sta_update_req(&sta_params(None, STA_STATE_ASSOC));
    if req.len() != UNI_STA_UPDATE_BOUND + STA_REC_MLD_TLV_SIZE
        || u16::from_le_bytes([req[2], req[3]]) != 6
    {
        return TestResult::Fail("mt7925 UNI station update (non-MLD) wrong");
    }
    let mld = &req[72..100];
    if u16::from_le_bytes([mld[0], mld[1]]) != STA_REC_MLD
        || u16::from_le_bytes([mld[2], mld[3]]) != 28
        || mld[4..10] != [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        || u16::from_le_bytes([mld[10], mld[11]]) != 1
        || u16::from_le_bytes([mld[12], mld[13]]) != 0
        || u16::from_le_bytes([mld[14], mld[15]]) != 1
        || mld[16] != 0
        || mld[17..28].iter().any(|&b| b != 0)
    {
        return TestResult::Fail("mt7925 UNI non-MLD STA_REC_MLD wrong");
    }
    if req[100..108] != [0x2b, 0, 8, 0, 0, 1, 1, 0] {
        return TestResult::Fail("mt7925 UNI non-MLD HDR_TRANS tail wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7925_uni_sta_update_mld);

fn smoke_mt7925_uni_sta_update_fixed_tlvs() -> TestResult {
    // The capability run sits between PHY and RA, verbatim and counted.
    let mut caps = [0u8; STA_REC_HT_TLV_SIZE];
    let _ = encode_sta_rec_ht_tlv(0x01ef, &mut caps);
    let params = UniStaParams {
        phy: UniStaPhy {
            basic_rate: 0x0150,
            phy_type: PHY_TYPE_BIT_OFDM | PHY_TYPE_BIT_HT | PHY_TYPE_BIT_VHT,
            ampdu_factor: 7,
            density: 5,
        },
        cap_tlvs: &caps,
        ra: UniStaRa {
            legacy: 0x3fc0,
            rx_mcs_bitmask: [0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0],
        },
        vht_opmode: sta_state_v2_vht_opmode(2, 2),
        ..sta_params(None, STA_STATE_ASSOC)
    };
    let req = build_uni_sta_update_req(&params);
    if sta_tlv_list(&req)
        != [
            (STA_REC_BASIC, 20),
            (STA_REC_PHY, 12),
            (STA_REC_HT, 8),
            (STA_REC_RA, 16),
            (STA_REC_STATE, 16),
            (STA_REC_MLD, 28),
            (STA_REC_HDR_TRANS, 8),
        ]
        || u16::from_le_bytes([req[2], req[3]]) != 7
    {
        return TestResult::Fail("mt7925 UNI station capability run misplaced");
    }
    // PHY at 28 (`struct sta_rec_phy`): basic_rate LE, phy_type,
    // ampdu = FIELD_PREP(FACTOR, 7) | FIELD_PREP(DENSITY, 5) = 3 | 20,
    // rts_policy 0, rcpi 0 (CONNAC3 never sets it), max_ampdu_len 7.
    if req[28..40] != [0x15, 0, 12, 0, 0x50, 0x01, 0x38, 0x17, 0, 0, 7, 0] {
        return TestResult::Fail("mt7925 STA_REC_PHY bytes wrong");
    }
    if req[40..48] != [9, 0, 8, 0, 0xef, 0x01, 0, 0] {
        return TestResult::Fail("mt7925 STA_REC_HT bytes wrong");
    }
    // RA at 48 (`struct sta_rec_ra_info`): legacy LE, rx_mcs_bitmask[10].
    if req[48..64] != [1, 0, 16, 0, 0xc0, 0x3f, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0] {
        return TestResult::Fail("mt7925 STA_REC_RA bytes wrong");
    }
    // STATE_V2 at 64: state at +4, flags 0, vht_opmode at +12 =
    // BW_80 (2) | rx_nss 2 << 4 (no `- 1` on CONNAC3).
    if req[64..80] != [7, 0, 16, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0x22, 0, 0, 0] {
        return TestResult::Fail("mt7925 STA_REC_STATE_V2 bytes wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7925_uni_sta_update_fixed_tlvs
);

fn smoke_mt7925_sta_rec_cap_encoders() -> TestResult {
    // Tags (mt76_connac_mcu.h:802-836).
    if STA_REC_RA != 1
        || STA_REC_STATE != 7
        || STA_REC_HT != 9
        || STA_REC_VHT != 10
        || STA_REC_APPS != 11
        || STA_REC_HE != 14
        || STA_REC_HW_AMSDU != 15
        || STA_REC_PHY != 0x15
        || STA_REC_HE_6G != 0x17
        || STA_REC_HE_V2 != 0x19
        || STA_REC_HDR_TRANS != 0x2b
    {
        return TestResult::Fail("mt7925 STA_REC tag values wrong");
    }
    // Sizes are the sizeof() of the upstream structs.
    if STA_REC_PHY_TLV_SIZE != 12
        || STA_REC_RA_TLV_SIZE != 16
        || STA_REC_STATE_V2_TLV_SIZE != 16
        || STA_REC_HT_TLV_SIZE != 8
        || STA_REC_VHT_TLV_SIZE != 16
        || STA_REC_HW_AMSDU_TLV_SIZE != 8
        || STA_REC_HE_V2_TLV_SIZE != 28
        || STA_REC_HE_6G_TLV_SIZE != 8
        || STA_REC_HDR_TRANS_TLV_SIZE != 8
    {
        return TestResult::Fail("mt7925 STA_REC sizes wrong");
    }
    // VHT: cap LE32, rx/tx maps LE16, rts_bw_sig + rsv zero.
    let mut vht = [0xaau8; STA_REC_VHT_TLV_SIZE];
    if encode_sta_rec_vht_tlv(0x0380_01b2, 0xfffa, 0xfff5, &mut vht).is_none()
        || vht
            != [
                10, 0, 16, 0, 0xb2, 0x01, 0x80, 0x03, 0xfa, 0xff, 0xf5, 0xff, 0, 0, 0, 0,
            ]
    {
        return TestResult::Fail("mt7925 STA_REC_VHT bytes wrong");
    }
    // HW_AMSDU: eight subframes, CONNAC3 max_mpdu_size enum, enabled.
    if amsdu_max_mpdu_size(11454) != 2
        || amsdu_max_mpdu_size(7991) != 1
        || amsdu_max_mpdu_size(7935) != 1
        || amsdu_max_mpdu_size(3895) != 0
        || amsdu_max_mpdu_size(3839) != 0
    {
        return TestResult::Fail("mt7925 AMSDU max_mpdu_size mapping wrong");
    }
    let mut amsdu = [0u8; STA_REC_HW_AMSDU_TLV_SIZE];
    if encode_sta_rec_amsdu_tlv(AMSDU_MAX_MPDU_11454, &mut amsdu).is_none()
        || amsdu != [15, 0, 8, 0, 8, 2, 1, 0]
    {
        return TestResult::Fail("mt7925 STA_REC_HW_AMSDU bytes wrong");
    }
    // HE_6G: capa LE16, rsv[2].
    let mut he6 = [0xaau8; STA_REC_HE_6G_TLV_SIZE];
    if encode_sta_rec_he_6g_tlv(0x06bd, &mut he6).is_none()
        || he6 != [0x17, 0, 8, 0, 0xbd, 0x06, 0, 0]
    {
        return TestResult::Fail("mt7925 STA_REC_HE_6G bytes wrong");
    }
    // HDR_TRANS for a 3-address station without RX decap offload.
    let mut hdr = [0xaau8; STA_REC_HDR_TRANS_TLV_SIZE];
    if encode_sta_rec_hdr_trans_tlv(&UniStaHdrTrans::STATION, &mut hdr).is_none()
        || hdr != [0x2b, 0, 8, 0, 0, 1, 1, 0]
    {
        return TestResult::Fail("mt7925 STA_REC_HDR_TRANS bytes wrong");
    }
    // RA legacy: 2.4 GHz keeps CCK in 0..3 and moves OFDM to 6..13;
    // 5/6 GHz has only the 8 OFDM rates.
    if ra_legacy(0x0011, true) != 0x0041
        || ra_legacy(0x0fff, true) != 0x3fcf
        || ra_legacy(0x00ff, false) != 0x3fc0
        || ra_legacy(0x0015, false) != 0x0540
    {
        return TestResult::Fail("mt7925 RA legacy mapping wrong");
    }
    // PHY: a VHT exponent above 3 is masked out of `ampdu` only.
    let mut phy = [0u8; STA_REC_PHY_TLV_SIZE];
    let p = UniStaPhy {
        basic_rate: 0x000f,
        phy_type: PHY_TYPE_BIT_HR_DSSS | PHY_TYPE_BIT_ERP,
        ampdu_factor: 3,
        density: 7,
    };
    if encode_sta_rec_phy_tlv(&p, &mut phy).is_none()
        || phy != [0x15, 0, 12, 0, 0x0f, 0, 3, 3 | (7 << 2), 0, 0, 3, 0]
    {
        return TestResult::Fail("mt7925 STA_REC_PHY 2.4 GHz bytes wrong");
    }
    // STATE_V2 for a non-VHT peer: vht_opmode stays 0.
    let mut state = [0xaau8; STA_REC_STATE_V2_TLV_SIZE];
    if encode_sta_rec_state_v2_tlv(STA_STATE_NONE, 0, &mut state).is_none()
        || state != [7, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    {
        return TestResult::Fail("mt7925 STA_REC_STATE_V2 (NONE) bytes wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7925_sta_rec_cap_encoders);

fn smoke_mt7925_uni_sta_remove_req() -> TestResult {
    let req = build_uni_sta_remove_req(1, 2, 3);
    if req.len() != STA_REQ_HDR_SIZE + STA_REC_REMOVE_TLV_SIZE + TLV_HDR_SIZE {
        return TestResult::Fail("mt7925 UNI station remove length wrong");
    }
    if req[0] != 1 || req[1] != 2 || req[2] != 2 || req[5] != 3 {
        return TestResult::Fail("mt7925 UNI station remove header wrong");
    }
    let rem = &req[8..16];
    if u16::from_le_bytes([rem[0], rem[1]]) != STA_REC_REMOVE
        || u16::from_le_bytes([rem[2], rem[3]]) != STA_REC_REMOVE_TLV_SIZE as u16
        || rem[4] != 0
    {
        return TestResult::Fail("mt7925 UNI station REMOVE TLV wrong");
    }
    let off = &req[16..20];
    if u16::from_le_bytes([off[0], off[1]]) != STA_REC_MLD_OFF
        || u16::from_le_bytes([off[2], off[3]]) != TLV_HDR_SIZE as u16
    {
        return TestResult::Fail("mt7925 UNI station MLD_OFF TLV wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7925_uni_sta_remove_req);

fn smoke_mt7925_sta_rec_eht_tlv() -> TestResult {
    let caps = StaEhtCaps {
        tid_bitmap: 0x3f,
        mac_cap: 0x0102,
        phy_cap: 0x1122334455667788,
        phy_cap_ext: 0x99aabbccddeeff00,
        mcs_map_bw20: [0xaa, 0xbb, 0xcc, 0xdd],
        mcs_map_bw80: [0x11, 0x22, 0x33],
        mcs_map_bw160: [0x44, 0x55, 0x66],
        mcs_map_bw320: [0x77, 0x88, 0x99],
    };
    let mut out = [0u8; STA_REC_EHT_TLV_SIZE];
    if encode_sta_rec_eht_tlv(&caps, &mut out).is_none() {
        return TestResult::Fail("mt7925 STA_REC_EHT encode failed");
    }
    if u16::from_le_bytes([out[0], out[1]]) != STA_REC_EHT
        || u16::from_le_bytes([out[2], out[3]]) != STA_REC_EHT_TLV_SIZE as u16
        || out[4] != 0x3f
        || u16::from_le_bytes([out[6], out[7]]) != 0x0102
        || u64::from_le_bytes(out[8..16].try_into().unwrap()) != 0x1122334455667788
        || out[24..28] != [0xaa, 0xbb, 0xcc, 0xdd]
        || out[28..31] != [0x11, 0x22, 0x33]
        || out[31..34] != [0x44, 0x55, 0x66]
        || out[34..37] != [0x77, 0x88, 0x99]
    {
        return TestResult::Fail("mt7925 STA_REC_EHT bytes wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7925_sta_rec_eht_tlv);

fn bss_params(enable: bool) -> UniBssParams {
    UniBssParams {
        bss_idx: 0,
        enable,
        conn_type: CONN_TYPE_INFRA_STA,
        omac_idx: 0,
        hw_bss_idx: 0,
        band_idx: 0,
        wmm_idx: 0,
        bssid: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        bmc_tx_wlan_idx: 19,
        bcn_interval: 100,
        dtim_period: 2,
        phymode: 1,
        sta_idx: 19,
        nonht_basic_phy: 8,
        phymode_ext: 0,
        link_idx: 0,
        sec: UniBssSec {
            mode: BSS_SEC_MODE_OPEN,
            status: 1,
            cipher: 0,
        },
        basic_rate: BSS_BASIC_RATE_5G,
        short_preamble: false,
        fixed_rate_idx: 0,
        qos: true,
        mld: UniBssMld {
            is_mld: false,
            link_id: 0,
            primary_bss_idx: 0,
            own_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            eml_enable: false,
        },
        slot_time: 9,
        he: Some(UniBssHe {
            pe_duration: 4,
            rts_thres: 1023,
            max_nss_mcs: [0x0102, 0x0304, 0x0506],
            color_enabled: true,
            color: 42,
        }),
        rlm: Some(UniBssRlm {
            control_channel: 36,
            center_chan: 42,
            center_chan2: 0,
            bw: RLM_BW_80,
            tx_streams: 2,
            rx_streams: 2,
            band: RLM_BAND_5G,
        }),
        mbssid: Some((0, 0)),
    }
}

fn smoke_mt7925_uni_bss_info_sta_req() -> TestResult {
    let req = build_uni_bss_info_sta_req(&bss_params(true));
    // hdr 4 + BASIC 32 + SEC 8 + RATE 16 + QoS 8 + MLD 20 + IFS 20
    // + HE 16 + COLOR 8 + RLM 16 + MBSSID 8 = 156.
    if req.len() != UNI_BSS_UPDATE_BOUND {
        return TestResult::Fail("mt7925 UNI BSS info length wrong");
    }
    // TLV order: BASIC, SEC, RATE, QoS, MLD, IFS, HE, COLOR, RLM, MBSSID.
    let tags: [u16; 10] = [
        UNI_BSS_INFO_BASIC,
        UNI_BSS_INFO_SEC,
        UNI_BSS_INFO_RATE,
        UNI_BSS_INFO_QBSS,
        UNI_BSS_INFO_MLD,
        UNI_BSS_INFO_IFS_TIME,
        UNI_BSS_INFO_HE_BASIC,
        UNI_BSS_INFO_BSS_COLOR,
        UNI_BSS_INFO_RLM,
        UNI_BSS_INFO_11V_MBSSID,
    ];
    let mut off = BSS_REQ_HDR_SIZE;
    for &tag in &tags {
        if u16::from_le_bytes([req[off], req[off + 1]]) != tag {
            return TestResult::Fail("mt7925 UNI BSS info TLV order wrong");
        }
        off += u16::from_le_bytes([req[off + 2], req[off + 3]]) as usize;
    }
    if off != req.len() {
        return TestResult::Fail("mt7925 UNI BSS info TLV lengths wrong");
    }
    // BASIC body: conn 0x10001, conn_state 0 (enable), bssid, bmc 19,
    // bcn 100, dtim 2, phymode 1, sta 19, nonht 8, link 0.
    let basic = &req[BSS_REQ_HDR_SIZE..BSS_REQ_HDR_SIZE + UNI_BSS_BASIC_TLV_SIZE];
    if u32::from_le_bytes([basic[8], basic[9], basic[10], basic[11]]) != CONN_TYPE_INFRA_STA
        || basic[12] != 0
        || basic[14..20] != [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        || u16::from_le_bytes([basic[20], basic[21]]) != 19
        || u16::from_le_bytes([basic[22], basic[23]]) != 100
        || basic[24] != 2
        || basic[25] != 1
        || u16::from_le_bytes([basic[26], basic[27]]) != 19
        || u16::from_le_bytes([basic[28], basic[29]]) != 8
        || basic[31] != 0
    {
        return TestResult::Fail("mt7925 UNI BSS BASIC TLV wrong");
    }
    // MLD at hdr+32+8+16+8: own_mld_id = bss_idx + 32, link 0xff (not MLD).
    let mld_off = BSS_REQ_HDR_SIZE
        + UNI_BSS_BASIC_TLV_SIZE
        + UNI_BSS_SEC_TLV_SIZE
        + UNI_BSS_RATE_TLV_SIZE
        + UNI_BSS_QOS_TLV_SIZE;
    if req[mld_off + 5] != 32 || req[mld_off + 12] != 0xff || req[mld_off + 13] != 0xff {
        return TestResult::Fail("mt7925 UNI BSS MLD TLV wrong");
    }
    // RLM: control 36 < center 42 -> sco 1 (SCA), ht_op_info 4, band 2.
    let rlm_off = req.len() - UNI_BSS_RLM_TLV_SIZE - UNI_BSS_MBSSID_TLV_SIZE;
    if req[rlm_off + 4] != 36
        || req[rlm_off + 5] != 42
        || req[rlm_off + 7] != RLM_BW_80
        || req[rlm_off + 10] != 4
        || req[rlm_off + 11] != 1
        || req[rlm_off + 12] != RLM_BAND_5G
    {
        return TestResult::Fail("mt7925 UNI BSS RLM TLV wrong");
    }
    // COLOR: enable 1, color 42.
    let color_off = rlm_off - UNI_BSS_COLOR_TLV_SIZE;
    if req[color_off + 4] != 1 || req[color_off + 5] != 42 {
        return TestResult::Fail("mt7925 UNI BSS COLOR TLV wrong");
    }
    // Disable: no RLM/MBSSID, conn_state 1.
    let req = build_uni_bss_info_sta_req(&bss_params(false));
    if req.len() != UNI_BSS_UPDATE_BOUND - UNI_BSS_RLM_TLV_SIZE - UNI_BSS_MBSSID_TLV_SIZE
        || req[BSS_REQ_HDR_SIZE + 12] != 1
    {
        return TestResult::Fail("mt7925 UNI BSS info (disable) wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7925_uni_bss_info_sta_req);

fn smoke_mt7925_uni_bss_basic_matches_in_tree_record() -> TestResult {
    // The UNI BSS BASIC TLV this module emits must be byte-identical
    // to the one the in-tree CONNAC2 record builder already emits
    // (association.rs::bss_record_on) for the same HOME inputs:
    // bss 0, omac 0, wmm 0, bmc 19, bssid, bcn 100, 5 GHz (phymode 1,
    // nonht 8), connected (conn_state 0).
    let mut out = [0u8; UNI_BSS_BASIC_TLV_SIZE];
    if encode_uni_bss_basic_tlv(
        true,
        0,
        0,
        0,
        CONN_TYPE_INFRA_STA,
        0,
        0,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        19,
        100,
        0,
        1,
        19,
        8,
        0,
        0,
        &mut out,
    )
    .is_none()
    {
        return TestResult::Fail("mt7925 UNI BSS BASIC encode failed");
    }
    let expected: [u8; UNI_BSS_BASIC_TLV_SIZE] = [
        0x00, 0x00, 0x20, 0x00, // tag 0, len 32
        0x01, 0x00, 0x00, 0x00, // active, omac, hw_bss, band
        0x01, 0x00, 0x01, 0x00, // conn_type 0x10001 LE
        0x00, 0x00, // conn_state, wmm
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // bssid
        0x13, 0x00, // bmc_tx 19
        0x64, 0x00, // bcn_interval 100
        0x00, 0x01, // dtim, phymode
        0x13, 0x00, // sta_idx 19
        0x08, 0x00, // nonht_basic_phy 8
        0x00, 0x00, // phymode_ext, link_idx
    ];
    if out != expected {
        return TestResult::Fail("mt7925 UNI BSS BASIC differs from the in-tree record");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7925_uni_bss_basic_matches_in_tree_record
);

fn smoke_mt7925_uni_bss_eht_req() -> TestResult {
    let req = build_uni_bss_eht_req(2, 0x00f0);
    if req.len() != BSS_REQ_HDR_SIZE + UNI_BSS_EHT_TLV_SIZE || req[0] != 2 {
        return TestResult::Fail("mt7925 UNI BSS EHT length/header wrong");
    }
    let eht = &req[BSS_REQ_HDR_SIZE..];
    if u16::from_le_bytes([eht[0], eht[1]]) != UNI_BSS_INFO_EHT
        || u16::from_le_bytes([eht[2], eht[3]]) != UNI_BSS_EHT_TLV_SIZE as u16
        || eht[5] != 1
        || u16::from_le_bytes([eht[10], eht[11]]) != 0x00f0
    {
        return TestResult::Fail("mt7925 UNI BSS EHT TLV wrong");
    }
    let req = build_uni_bss_eht_req(2, 0);
    if req[BSS_REQ_HDR_SIZE + 5] != 0 {
        return TestResult::Fail("mt7925 UNI BSS EHT dscb flag wrong when unpunctured");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7925_uni_bss_eht_req);

fn smoke_mt7925_uni_efuse_reqs() -> TestResult {
    // Read: offset 0xa71 (MT_EE_HW_TYPE) rounds down to 0xa70.
    let mut req = [0u8; EFUSE_READ_REQ_SIZE];
    if encode_uni_efuse_read_req(0xa71, &mut req).is_none() {
        return TestResult::Fail("mt7925 UNI EFUSE read encode failed");
    }
    if u16::from_le_bytes([req[4], req[5]]) != UNI_EFUSE_ACCESS
        || u16::from_le_bytes([req[6], req[7]]) != 28
        || u32::from_le_bytes([req[8], req[9], req[10], req[11]]) != 0xa70
    {
        return TestResult::Fail("mt7925 UNI EFUSE read request wrong");
    }
    // Set: tag 2, len 8, mode 0 (EFUSE), format 1 (WHOLE).
    let mut set = [0u8; EFUSE_SET_REQ_SIZE];
    if encode_uni_efuse_set_req(&mut set).is_none() {
        return TestResult::Fail("mt7925 UNI EFUSE set encode failed");
    }
    if u16::from_le_bytes([set[4], set[5]]) != UNI_EFUSE_BUFFER_MODE
        || u16::from_le_bytes([set[6], set[7]]) != 8
        || set[8] != EE_MODE_EFUSE
        || set[9] != EE_FORMAT_WHOLE
        || u16::from_le_bytes([set[10], set[11]]) != 0
    {
        return TestResult::Fail("mt7925 UNI EFUSE set request wrong");
    }
    // Response: addr 0xa70, data byte for 0xa71 at 48 + 1.
    let mut resp = [0u8; EFUSE_READ_RESP_SIZE];
    resp[12..16].copy_from_slice(&0xa70u32.to_le_bytes());
    resp[48 + 1] = 0x5a;
    if parse_uni_efuse_read_resp(&resp, 0xa71) != Some(0x5a) {
        return TestResult::Fail("mt7925 UNI EFUSE response parse wrong");
    }
    if parse_uni_efuse_read_resp(&resp, 0xa81).is_some() {
        return TestResult::Fail("mt7925 UNI EFUSE response accepted a foreign block");
    }
    if parse_uni_efuse_read_resp(&resp[..EFUSE_READ_RESP_SIZE - 1], 0xa71).is_some() {
        return TestResult::Fail("mt7925 UNI EFUSE response accepted a short buffer");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7925_uni_efuse_reqs);

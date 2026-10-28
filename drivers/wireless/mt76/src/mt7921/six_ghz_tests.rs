//! 6 GHz station operation over the production Session: grant/power type,
//! CLC env_6g, 6 GHz channel switch/limits/BSS/RLM records, STA_REC_HE_6G
//! and teardown (Linux v7.2 mt7921 6E; shared `JoinPlan::prepare_6ghz`).
//!
//! No 6 GHz `FakeAp` profile exists. The shared WPA3-SAE (H2E) FakeAp runs
//! on channel 165, which is also a valid 6 GHz PSC number with OFDM-only
//! rates; the hand-built HE / HE 6 GHz Band Capabilities / HE Operation
//! (6 GHz Operation Information) elements make that BSS a 6 GHz one. A real
//! 6 GHz FakeAp profile (no DS Parameter Set, RNR, 6 GHz-only rates) is a
//! shared fixture gap.
use super::*;
use crate::mt7921::association::{SaePassword, Security, TxPermission};
use alloc::boxed::Box;
use narf_wifi_fixtures::{ApPhase, ApSaePwe, FakeAp};
use narf_wireless::association::channel::Band as SharedBand;
use narf_wireless::reg::{PowerType6Ghz, RegFlags, RegRule, RegulatoryDomain};

const AP: [u8; 6] = [2, 1, 2, 3, 4, 5];
const PASSWORD: &[u8] = b"narf-sae-password";
/// 6 GHz channel 165 (PSC), RXD3 CH_FREQ 181 + 164 / 4.
const PRIMARY: u8 = 165;
const RX_TAG: u8 = 222;
/// AP HE 6 GHz Band Capabilities: min MPDU start 5, max A-MPDU exponent 7,
/// max MPDU 11454 (2), SM PS disabled.
const AP_CAPA: u16 = 5 | (7 << 3) | (2 << 6) | (3 << 9);

pub(super) fn domain(flags: RegFlags, power: i8) -> RegulatoryDomain {
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 5925,
            freq_end_mhz: 7125,
            max_bandwidth_mhz: 160,
            max_power_dbm: power,
            flags,
        }],
    }
}

/// HE Capabilities + HE 6 GHz Band Capabilities + HE Operation with 6 GHz
/// Operation Information (`control` width 0..3, REG_INFO `reg`).
pub(super) fn elements(primary: u8, width: u8, ccfs0: u8, ccfs1: u8, reg: u8) -> Vec<u8> {
    let mut ies = super::he_tests::he_elements(true, Some(5));
    // Drop the 2.4/5 GHz HE Operation (the trailing 9-byte element).
    ies.truncate(ies.len() - 9);
    ies.extend_from_slice(&[255, 3, 59]);
    ies.extend_from_slice(&AP_CAPA.to_le_bytes());
    // IEEE80211_HE_OPERATION_6GHZ_OP_INFO (B17) + BSS color 5.
    let params: u32 = 2 | (1023 << 4) | (1 << 17) | (5 << 24);
    ies.extend_from_slice(&[255, 12, 36]);
    ies.extend_from_slice(&params.to_le_bytes());
    ies.extend_from_slice(&0xfffcu16.to_le_bytes());
    ies.extend_from_slice(&[primary, width | (reg << 3), ccfs0, ccfs1, 6]);
    ies
}

/// A boxed radio-ready session whose model AP is a WPA3-SAE (H2E) peer on
/// 6 GHz channel 165, and that BSS.
pub(super) fn prepared(he6: Vec<u8>) -> (Box<Session<Model>>, ScanBss) {
    let ap = FakeAp::wpa3_sae(
        super::wmm_tests::NETWORK,
        b"narf",
        PRIMARY,
        42,
        PASSWORD,
        ApSaePwe::HashToElement,
        [0xaa; 32],
    )
    .unwrap();
    let mut model = Model::new();
    let beacon = ap.beacon();
    let mut bss = ScanBss {
        bssid: AP,
        ssid: b"narf".to_vec(),
        channel: PRIMARY,
        band: Some(SharedBand::Ghz6),
        signal_dbm: Some(-45),
        capability: u16::from_le_bytes([beacon[34], beacon[35]]),
        beacon_interval: 100,
        information_elements: beacon[36..].to_vec(),
    };
    bss.information_elements
        .extend_from_slice(&super::wmm_tests::PARAMETERS);
    bss.information_elements.extend_from_slice(&he6);
    model.wmm_reply = Some(super::wmm_tests::PARAMETERS.to_vec());
    // The association response's HE Capabilities + HE Operation.
    model.vht_reply = Some(he6);
    model.station_channel = RX_TAG;
    model.access_point = Some(ap);
    // Package-selected world CLC tables, so SET_CLC (and env_6g) is posted.
    let mut fw = firmware(32);
    let mut tables = super::clc_table(0, 1, 0xbb);
    tables.extend_from_slice(&super::clc_table(3, 0, 0xcc));
    fw.ram = tables.clone().into();
    fw.clc_regions.push(0..tables.len());
    let mut session = Box::new(Session::new(model, fw));
    run(Box::pin(session.run())).unwrap();
    run(Box::pin(session.initialize_radio())).unwrap();
    (session, bss)
}

fn sae() -> Security {
    Security::Wpa3Sae {
        password: SaePassword::new(PASSWORD).unwrap(),
    }
}

fn info(session: &Session<Model>) -> RadioInfo {
    match session.state {
        State::RadioReady(info) | State::ScanReady(info) => info,
        State::Associated { info, .. } => info,
        _ => panic!("6 GHz fixture radio"),
    }
}

fn join(
    session: &mut Session<Model>,
    bss: &ScanBss,
    security: Security,
    permission: TxPermission,
) -> Result<u16, Error> {
    run(Box::pin(session.associate_station(
        bss,
        b"narf",
        security,
        permission,
        &[],
    )))
}

fn ce(frame: &[u8], id: u8) -> Option<&[u8]> {
    (frame.len() >= 64 && frame[36] == id && frame[43] == 0).then(|| &frame[64..])
}
fn uni(frame: &[u8], id: u16) -> Option<&[u8]> {
    (frame.len() >= 48 && frame[34..36] == id.to_le_bytes() && frame[43] == 7).then(|| &frame[48..])
}

/// The CLC `env_6g` bytes posted (CE SET_CLC 0x5c), in order.
fn clc_envs(session: &Session<Model>) -> Vec<u8> {
    session
        .backend
        .frames
        .iter()
        .filter_map(|(_, f)| ce(f, 0x5c))
        .map(|body| body[12])
        .collect()
}

fn unit() -> Result<(), &'static str> {
    use crate::mt7921::channel::{self, Band};
    // mt792x_get_status_freq_info: 6 GHz values above 180.
    if channel::rx_channel(Band::Ghz6, 1) != Some(181)
        || channel::rx_channel(Band::Ghz6, 233) != Some(239)
        || channel::rx_channel(Band::Ghz6, 3).is_some()
        || channel::from_rx_channel(222) != Some((Band::Ghz6, 165))
        || channel::from_rx_channel(36) != Some((Band::Ghz5, 36))
        || channel::from_rx_channel(240).is_some()
        || channel::rx_channel(Band::Ghz5, 165) != Some(165)
        || channel::channels_6ghz().count() != 59
        || Band::Ghz6.scan_tag() != 3
        || Band::Ghz6.switch_tag() != 2
        || Band::Ghz6.nl80211() != 3
    {
        return Err("6 GHz channel identity / RXD CH_FREQ / band tags");
    }
    // mt7921_init_he_caps 6 GHz branch from the native HT density (7) and
    // VHT capability (MPDU 3895, exponent 0, no antenna-pattern bits).
    let (session, _) = prepared(elements(PRIMARY, 0, PRIMARY, 0, 0));
    let radio = info(&session);
    if crate::mt7921::six_ghz::capability(radio).map(|c| c.bits()) != Ok(7)
        || !crate::mt7921::six_ghz::qualified(radio)
    {
        return Err("mt7921_init_he_caps HE 6 GHz Band Capabilities");
    }
    let mut no6 = radio;
    no6.capabilities.has_6ghz = false;
    let mut no5 = radio;
    no5.capabilities.phy.bands = 1;
    if crate::mt7921::six_ghz::qualified(no6)
        || crate::mt7921::six_ghz::qualified(no5)
        || crate::mt7921::six_ghz::capability(no6).is_ok()
    {
        return Err("6 GHz admitted without MT_NIC_CAP_6G / has_5ghz");
    }
    // Grants: an 80 MHz LPI span 161..173 (centre 167) and power type rules.
    let channel = |width, center| {
        use narf_wireless::association::six_ghz::{SixGhzOperatingChannel, SixGhzWidth};
        let mhz = |ch: u8| 5950 + 5 * u32::from(ch);
        SixGhzOperatingChannel {
            primary: PRIMARY,
            primary_mhz: mhz(PRIMARY),
            width: match width {
                0 => SixGhzWidth::Twenty,
                2 => SixGhzWidth::Eighty,
                _ => SixGhzWidth::ThreeTwenty,
            },
            discontiguous: false,
            center,
            center_mhz: mhz(center),
            center2: None,
            center2_mhz: None,
        }
    };
    let indoor = domain(RegFlags::INDOOR_ONLY, 23);
    let Some(grant) = TxPermission::six_ghz_channel(&indoor, &channel(2, 167), PowerType6Ghz::Lpi)
    else {
        return Err("LPI client of an indoor 6 GHz rule refused");
    };
    let limits = grant.rate_limits();
    if grant.channels() != [161, 165, 169, 173]
        || grant.center_channel() != 167
        || grant.native_width() != crate::mt7921::cmd::CH_BW_80
        || grant.band() != Some(Band::Ghz6)
        || limits[4..7] != [4, 3, 1]
        || limits[44] != 161
        || limits[45] != 46
        || !grant.current(&indoor)
        || grant.current(&domain(RegFlags::INDOOR_ONLY, 20))
        || grant.current(&domain(RegFlags::NO_IR, 23))
    {
        return Err("6 GHz LPI grant geometry / tx_power_limit_tlv band 3 / currency");
    }
    if TxPermission::six_ghz_channel(&indoor, &channel(2, 167), PowerType6Ghz::Vlp).is_some()
        || TxPermission::six_ghz_channel(
            &domain(RegFlags::NO_6GHZ_VLP_CLIENT, 14),
            &channel(0, PRIMARY),
            PowerType6Ghz::Vlp,
        )
        .is_some()
        || TxPermission::six_ghz_channel(
            &domain(RegFlags::NO_6GHZ_AFC_CLIENT, 30),
            &channel(0, PRIMARY),
            PowerType6Ghz::Sp,
        )
        .is_some()
        || TxPermission::six_ghz_channel(
            &domain(RegFlags::empty(), 30),
            &channel(0, PRIMARY),
            PowerType6Ghz::Sp,
        )
        .is_none()
        || TxPermission::six_ghz_channel(&indoor, &channel(9, 175), PowerType6Ghz::Lpi).is_some()
    {
        return Err("cfg80211_6ghz_power_type_valid / indoor / 320 MHz grant policy");
    }
    if crate::mt7921::six_ghz::env_6g(PowerType6Ghz::Lpi) != 2
        || crate::mt7921::six_ghz::env_6g(PowerType6Ghz::Sp) != 3
        || crate::mt7921::six_ghz::env_6g(PowerType6Ghz::Vlp) != 4
    {
        return Err("enum mt792x_reg_power_type");
    }
    Ok(())
}

fn mt76_six_ghz_identity_capability_and_power_type_grants() -> TestResult {
    unit().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/six_ghz",
    mt76_six_ghz_identity_capability_and_power_type_grants
);

fn association() -> Result<(), &'static str> {
    // 80 MHz LPI BSS (REG_INFO 0) at 161..173, primary 165.
    let (mut session, bss) = prepared(elements(PRIMARY, 2, 167, 0, 0));
    let radio = info(&session);
    let indoor = domain(RegFlags::INDOOR_ONLY, 23);
    let grant = TxPermission::from_ap(&indoor, radio, &bss).ok_or("6 GHz grant")?;
    if grant.six.map(|six| (six.center, six.width, six.power))
        != Some((167, crate::mt7921::cmd::CH_BW_80, PowerType6Ghz::Lpi))
    {
        return Err("6 GHz plan channel/power type in the grant");
    }
    if join(&mut session, &bss, sae(), grant) != Ok(42) {
        return Err("6 GHz SAE-H2E association");
    }
    let ap = session.backend.access_point.as_ref().unwrap();
    if ap.phase() != ApPhase::Authorized || !ap.pmf() {
        return Err("6 GHz AP did not authorize the SAE/PMF station");
    }
    if !matches!(
        session.state,
        State::Associated {
            channel: RX_TAG,
            ..
        }
    ) || session.he_profile.is_none()
        || session.ht20_profile.is_some()
        || session.vht_profile.is_some()
    {
        return Err("6 GHz associated state / HE-only profile");
    }
    let frames: Vec<&Vec<u8>> = session.backend.frames.iter().map(|(_, f)| f).collect();
    // The AP power type reaches the CLC before the channel domain.
    let clc = frames
        .iter()
        .position(|f| ce(f, 0x5c).is_some_and(|b| b[12] == 2));
    // The station's channel domain (scan setup posts its own NO_IR one first).
    let domain_cmd = frames
        .iter()
        .position(|f| ce(f, 0x0f).is_some_and(|b| b.len() > 14 && b[10] != 0));
    if clc.is_none() || clc > domain_cmd {
        return Err("mt7921_regd_set_6ghz_power_type env_6g = MT_AP_LPI before the peer");
    }
    let domain_body = ce(frames[domain_cmd.unwrap()], 0x0f).unwrap();
    if domain_body[6] != 2
        || domain_body[10] != 4
        || domain_body[12..14] != [161, 0]
        || domain_body[36..38] != [173, 0]
    {
        return Err("set_channel_domain 6 GHz bw/count/channels");
    }
    if !frames.iter().any(|f| {
        ce(f, 0x5d).is_some_and(|b| b[4..7] == [4, 3, 1] && b[44] == 161 && b[44 + 162] == 165)
    }) {
        return Err("SET_RATE_TX_POWER 6 GHz band 3 rows");
    }
    if !frames.iter().any(|f| {
        f.len() >= 64 + 11
            && f[36] == 0xed
            && f[41] == crate::mt7921::regs::MCU_EXT_CMD_CHANNEL_SWITCH
            && f[64..67] == [PRIMARY, 167, crate::mt7921::cmd::CH_BW_80]
            && f[74] == 2
    }) {
        return Err("mt7921_mcu_set_chan_info channel_band 2 for 6 GHz");
    }
    // BSS basic: phymode A|AN|AC|AX_5G, phymode_ext AX_6G, OFDM basic PHY.
    let bss_basic = |connected: u8| {
        frames.iter().any(|f| {
            uni(f, 2).is_some_and(|b| {
                b.len() >= 36
                    && b[4..8] == [0, 0, 32, 0]
                    && b[16] == connected
                    && b[29] == 0xb1
                    && b[32] == 8
                    && b[34] == 1
            })
        })
    };
    if !bss_basic(1) || !bss_basic(0) {
        return Err("mt76_connac_mcu_uni_add_bss 6 GHz phymode/phymode_ext");
    }
    if !frames.iter().any(|f| {
        uni(f, 2).is_some_and(|b| {
            b.len() == 20
                && b[4..8] == [2, 0, 16, 0]
                && b[8..12] == [PRIMARY, 167, 0, 2]
                && b[17] == 3
        })
    }) {
        return Err("UNI_BSS_INFO_RLM band NL80211_BAND_6GHZ");
    }
    // The association request: HE + HE 6 GHz Band Capabilities, no HT.
    let Some(request) = frames
        .iter()
        .find(|f| f.first() == Some(&0) && f.len() > 28 && f[4..10] == AP)
    else {
        return Err("6 GHz association request");
    };
    let mut ies = &request[28..];
    let (mut ht, mut capa) = (false, None);
    while ies.len() >= 2 {
        let body = &ies[2..2 + usize::from(ies[1])];
        ht |= ies[0] == 45 || ies[0] == 191;
        if ies[0] == 255 && body.first() == Some(&59) {
            capa = Some(u16::from_le_bytes([body[1], body[2]]));
        }
        ies = &ies[2 + body.len()..];
    }
    // ieee80211_put_he_6ghz_cap: our capability with SM PS disabled.
    if ht || capa != Some(7 | (3 << 9)) {
        return Err("6 GHz request HT element / HE 6 GHz Band Capabilities");
    }
    // STA_REC: PHY OFDM|HE, WTBL HT/VHT from he_6ghz_capa, HW_AMSDU large
    // MPDU, HE/HE_V2 and STA_REC_HE_6G with the AP's capability.
    let Some(peer) = frames
        .iter()
        .rev()
        .find(|f| super::vht_tests::record(f, 0x17).is_some())
    else {
        return Err("STA_REC_HE_6G");
    };
    let [lo, hi] = AP_CAPA.to_le_bytes();
    if super::vht_tests::record(peer, 0x17) != Some(&[0x17, 0, 8, 0, lo, hi, 0, 0][..])
        || super::vht_tests::record(peer, 0x15).is_none_or(|r| r[6] != 0x48 || r[7] != 0)
        || super::vht_tests::record(peer, 15).is_none_or(|r| r[4..7] != [8, 1, 1])
        || super::vht_tests::record(peer, 14).is_none()
        || super::vht_tests::record(peer, 0x19).is_none()
        || super::vht_tests::record(peer, 9).is_some()
        || super::vht_tests::record(peer, 10).is_some()
    {
        return Err("6 GHz STA_REC PHY/HW_AMSDU/HE/HE_6G without HT/VHT");
    }
    let wtbl = super::vht_tests::record(peer, 13).ok_or("WTBL")?;
    if wtbl[6] != 6
        || !wtbl.windows(8).any(|w| w == [2, 0, 12, 0, 1, 0, 7, 5])
        || !wtbl.windows(8).any(|w| w == [3, 0, 12, 0, 0, 0, 1, 0])
    {
        return Err("6 GHz WTBL_HT af/mm from he_6ghz_capa and WTBL_VHT");
    }
    // Teardown: the station's removal resets env_6g to MT_AP_UNSET.
    let before = session.backend.frames.len();
    run(Box::pin(session.disassociate_station())).map_err(|_| "6 GHz teardown")?;
    let after: Vec<u8> = session.backend.frames[before..]
        .iter()
        .filter_map(|(_, f)| ce(f, 0x5c))
        .map(|b| b[12])
        .collect();
    if after.is_empty()
        || after.iter().any(|&env| env != 0)
        || !matches!(session.state, State::ScanReady(_))
        || session.he_profile.is_some()
        || session.station_permission.is_some()
    {
        return Err("6 GHz teardown CLC env_6g reset / state");
    }
    if clc_envs(&session).iter().filter(|&&env| env == 2).count() == 0 {
        return Err("LPI env_6g missing from the CLC history");
    }
    Ok(())
}

fn mt76_six_ghz_sae_h2e_association_records_and_teardown() -> TestResult {
    association().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/six_ghz",
    mt76_six_ghz_sae_h2e_association_records_and_teardown
);

fn refusals() -> Result<(), &'static str> {
    let he6 = elements(PRIMARY, 0, PRIMARY, 0, 0);
    let indoor = domain(RegFlags::INDOOR_ONLY, 23);
    // Open and WPA2 are refused on 6 GHz before any MCU command.
    for security in [Security::Open, Security::Wpa2Psk { psk: [0x55; 32] }] {
        let (mut session, bss) = prepared(he6.clone());
        let grant = TxPermission::from_ap(&indoor, info(&session), &bss).ok_or("grant")?;
        let before = session.backend.frames.len();
        if join(&mut session, &bss, security, grant) != Err(Error::Bounds)
            || session.backend.frames.len() != before
        {
            return Err("6 GHz Open/WPA2 refused before MCU I/O");
        }
    }
    // Without MT_NIC_CAP_6G the band is refused.
    let (mut session, bss) = prepared(he6.clone());
    let grant = TxPermission::from_ap(&indoor, info(&session), &bss).ok_or("grant")?;
    if let State::RadioReady(info) = &mut session.state {
        info.capabilities.has_6ghz = false;
    }
    if join(&mut session, &bss, sae(), grant) != Err(Error::InvalidIdentity) {
        return Err("6 GHz joined without MT_NIC_CAP_6G");
    }
    // A 5 GHz grant for the same channel number is not a 6 GHz grant.
    let (mut session, bss) = prepared(he6.clone());
    let five = super::vht_tests::domain();
    let wrong = TxPermission::from_domain(&five, PRIMARY).ok_or("5 GHz grant")?;
    if join(&mut session, &bss, sae(), wrong) != Err(Error::Authority) {
        return Err("5 GHz grant accepted for a 6 GHz BSS");
    }
    // A VLP AP under NO_6GHZ_VLP_CLIENT has no grant at all.
    let (session, bss) = prepared(elements(PRIMARY, 0, PRIMARY, 0, 2));
    if TxPermission::from_ap(
        &domain(RegFlags::NO_6GHZ_VLP_CLIENT, 14),
        info(&session),
        &bss,
    )
    .is_some()
    {
        return Err("VLP AP granted under NO_6GHZ_VLP_CLIENT");
    }
    // A response without HE Operation fails the join and leaves no peer.
    let (mut session, bss) = prepared(he6.clone());
    let grant = TxPermission::from_ap(&indoor, info(&session), &bss).ok_or("grant")?;
    session.backend.vht_reply = None;
    if join(&mut session, &bss, sae(), grant).is_ok()
        || session.he_profile.is_some()
        || session.station_permission.is_some()
    {
        return Err("6 GHz response without HE accepted");
    }
    Ok(())
}

fn mt76_six_ghz_refuses_open_wpa2_missing_capability_and_wrong_band() -> TestResult {
    refusals().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/six_ghz",
    mt76_six_ghz_refuses_open_wpa2_missing_capability_and_wrong_band
);

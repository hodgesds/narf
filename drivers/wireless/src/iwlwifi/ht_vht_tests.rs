use super::super::{connection, rates::Rates, scan_api, station_api};
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn bss(vht: bool) -> Vec<u8> {
    let mut ies = alloc::vec![1, 8, 0x8c, 18, 0x98, 36, 0xb0, 72, 96, 108];
    let mut ht = [0; 26];
    ht[..5].copy_from_slice(&[0x6f, 0, 0x13, 0xff, 0xff]);
    ht[15] = 1;
    let mut op = [0; 22];
    op[..3].copy_from_slice(&[36, 5, 3]);
    op[6] = 0xff;
    ies.extend_from_slice(&[45, 26]);
    ies.extend_from_slice(&ht);
    ies.extend_from_slice(&[61, 22]);
    ies.extend_from_slice(&op);
    if vht {
        ies.extend_from_slice(&[
            191, 12, 0x30, 0, 0x80, 1, 0xfa, 0xff, 0, 0, 0xfa, 0xff, 0, 0,
        ]);
        ies.extend_from_slice(&[192, 5, 1, 42, 0, 0xfc, 0xff]);
    }
    ies
}
fn local() -> Local {
    Local::from_nvm(12, 3, 3)
}

fn smoke_ht_vht_tlc_and_phy_wire() -> TestResult {
    let ies = bss(true);
    let phy = Negotiated::parse(local(), &ies, 36, true, |_, _| true).unwrap();
    let mut tlc = Rates::parse_for_phy(&ies, 36, phy.mode)
        .unwrap()
        .tlc(6, 3)
        .unwrap();
    phy.apply_tlc(&mut tlc);
    if tlc[8..16] != [2, 2, 3, 7, 2, 0, 0xf0, 0x0f]
        || tlc[16..20] != [0xff, 3, 0, 0]
        || tlc[28..32] != [0xff, 3, 0, 0]
        || tlc[20..28] != [0; 8]
        || tlc[32..40] != [0; 8]
    {
        return TestResult::Fail("TLC v6 HT/VHT NSS/bandwidth/MCS wire layout");
    }
    let mut command = station_api::phy(1, 36);
    phy.apply_phy(&mut command, 36);
    if command[8..16] != [36, 0, 0, 0, 0, 2, 1, 0] || command[28] != 5 {
        return TestResult::Fail("VHT80 primary/control-channel encoding");
    }
    let mut peer = station_api::peer([2; 6]);
    phy.apply_peer(&mut peer, 42);
    if peer[28..32] != [42, 0, 0, 0]
        || peer[40..48] != [1, 0, 0, 0, 0, 0, 0, 0]
        || peer[56..64] != [4, 0, 0, 0, 3, 0, 0, 0]
    {
        return TestResult::Fail("peer MIMO/A-MPDU spacing and exponent");
    }
    let mut link = station_api::link(2, [2; 6], true, 36, 100, 1);
    phy.apply_link(&mut link);
    if link[52..60] != [6, 0, 0, 0, 2, 0, 0, 0] {
        return TestResult::Fail("HT protection/QoS firmware flags");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/ht_vht",
    smoke_ht_vht_tlc_and_phy_wire
);

fn smoke_ht_vht_negotiation_fallback_and_smps() -> TestResult {
    let mut ies = bss(true);
    let narrow = Negotiated::parse(local(), &ies, 36, true, |_, _| false).unwrap();
    if narrow.mode != 2 || narrow.width != 0 || narrow.mcs != [0x1ff; 2] || narrow.sgi != 1 {
        return TestResult::Fail("VHT20 must remove MCS9 for one/two streams");
    }
    let request = narrow.association_ies(local(), 36);
    if request[2] & 0x42 != 0 || request[request.len() - 3..] != [199, 1, 0x10] {
        return TestResult::Fail("narrow association advertised wide-channel operation");
    }
    ies[12] &= !12; // AP HT SMPS static
    let one = Negotiated::parse(local(), &ies, 36, true, |_, _| true).unwrap();
    if one.mcs[1] != 0 || one.dynamic_smps {
        return TestResult::Fail("static SMPS allowed MIMO");
    }
    ies[12] |= 4;
    if !Negotiated::parse(local(), &ies, 36, true, |_, _| true)
        .unwrap()
        .dynamic_smps
    {
        return TestResult::Fail("dynamic SMPS lost RTS protection");
    }
    for wmm in [false, true] {
        let mut caps = local();
        caps.ht = wmm;
        if Negotiated::parse(caps, &ies, 36, false, |_, _| true)
            .unwrap()
            .mode
            != 0
        {
            return TestResult::Fail("HT enabled without WMM");
        }
    }
    let ht = Negotiated::parse(local(), &bss(false), 36, true, |_, _| true).unwrap();
    if ht.mode != 1 || ht.width != 1 || ht.mcs != [255; 2] {
        return TestResult::Fail("HT40 rates negotiation");
    }
    let confirmed = ht
        .confirm(local(), &bss(false), &[1, 1, 12], 36, true)
        .unwrap();
    if confirmed.mode != 0 {
        return TestResult::Fail("association response did not confirm HT");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/ht_vht",
    smoke_ht_vht_negotiation_fallback_and_smps
);

fn smoke_ht_vht_malformed_and_required_capabilities() -> TestResult {
    let mut ies = bss(true);
    let phy = Negotiated::parse(local(), &ies, 36, true, |_, _| true).unwrap();
    let mut selectors = ies.clone();
    selectors.extend_from_slice(&[50, 2, 0xff, 0xfe]);
    if Rates::parse_for_phy(&selectors, 36, phy.mode).is_err()
        || Rates::parse(&selectors, 36).is_ok()
    {
        return TestResult::Fail("HT/VHT BSS membership selector gating");
    }
    // Third stream is mandatory in the basic VHT map.
    let n = ies.len();
    ies[n - 2] = 0xc0;
    if Negotiated::parse(local(), &ies, 36, true, |_, _| true).is_ok() {
        return TestResult::Fail("unsupported mandatory VHT NSS accepted");
    }
    ies = bss(true);
    ies.pop();
    if Negotiated::parse(local(), &ies, 36, true, |_, _| true).is_ok() {
        return TestResult::Fail("truncated VHT IE accepted");
    }
    ies = bss(false);
    ies.extend_from_slice(&[45, 26]);
    ies.extend_from_slice(&[0; 26]);
    if Negotiated::parse(local(), &ies, 36, true, |_, _| true).is_ok() {
        return TestResult::Fail("duplicate HT capabilities accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/ht_vht",
    smoke_ht_vht_malformed_and_required_capabilities
);

fn smoke_ht_vht_local_nvm_and_probe_caps() -> TestResult {
    let local = Local::from_nvm(12 | 32, 3, 3);
    let caps = local.capabilities(5000).unwrap();
    if caps.ht[3..5] != [255, 0]
        || caps.vht.unwrap()[4..6] != [0xfe, 0xff]
        || local.capabilities(2400).unwrap().vht.is_some()
        || Local::from_nvm(0, 3, 3).capabilities(5000).is_some()
    {
        return TestResult::Fail("NVM band/MIMO disable capability gating");
    }
    let mut probe = scan_api::active(
        18,
        0,
        &[1, 36],
        &[true, true],
        [2; 6],
        &[b"hidden".to_vec()],
    )
    .unwrap();
    scan_api::with_phy_capabilities(18, &mut probe, local).unwrap();
    let start = 48 + 68 * 8 + 12;
    let count =
        |off| u16::from_le_bytes(probe[start + off..start + off + 2].try_into().unwrap()) as usize;
    if count(6) != 44 || count(10) != 52 || probe[start + 536 + 2..start + 536 + 8] != *b"hidden" {
        return TestResult::Fail("probe PHY capability segments/SSID overlap");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/ht_vht",
    smoke_ht_vht_local_nvm_and_probe_caps
);

fn smoke_ht_vht_regulatory_whole_channel() -> TestResult {
    use narf_wireless::reg::{RegFlags, RegRule, RegulatoryDomain};
    let mut domain = RegulatoryDomain {
        country_code: *b"US",
        rules: alloc::vec![RegRule {
            freq_start_mhz: 5170,
            freq_end_mhz: 5250,
            max_bandwidth_mhz: 80,
            max_power_dbm: 20,
            flags: RegFlags::empty(),
        }],
    };
    let mut permissions = alloc::vec![5 | (1<<9) | (1<<10); 51];
    if connection::channel_power_width(&domain, 36, 2, 42, &permissions) != Some(20) {
        return TestResult::Fail("permitted VHT80 span rejected");
    }
    permissions[station_api::channel_index(48).unwrap()] &= !(1 << 10);
    if connection::channel_power_width(&domain, 36, 2, 42, &permissions).is_some()
        || connection::channel_power_width(&domain, 36, 1, 38, &permissions) != Some(20)
    {
        return TestResult::Fail("secondary channel permission bypass or HT40 fallback lost");
    }
    domain.rules[0].max_bandwidth_mhz = 20;
    if connection::channel_power_width(&domain, 36, 1, 38, &permissions).is_some() {
        return TestResult::Fail("wide PHY ignored signed bandwidth ceiling");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/ht_vht",
    smoke_ht_vht_regulatory_whole_channel
);

fn smoke_ht_protection_matches_operating_bandwidth() -> TestResult {
    let mut ies = bss(false);
    let op = ies.windows(2).position(|w| w == [61, 22]).unwrap() + 2;
    ies[op + 2] = 2; // 20 MHz-only stations present
    let narrow = Negotiated::parse(local(), &ies, 36, true, |_, _| false).unwrap();
    let wide = Negotiated::parse(local(), &ies, 36, true, |_, _| true).unwrap();
    if narrow.protection != 0 || wide.protection != 6 {
        return TestResult::Fail("HT20 coexistence protection ignores selected bandwidth");
    }
    ies[op + 2] = 3; // non-HT mixed mode protects HT20 too
    if Negotiated::parse(local(), &ies, 36, true, |_, _| false)
        .unwrap()
        .protection
        != 6
    {
        return TestResult::Fail("mixed-mode HT protection missing");
    }
    let legacy = Negotiated::parse(local(), &[42, 1, 2], 6, false, |_, _| false).unwrap();
    if legacy.mode != 0 || legacy.protection != 1 {
        return TestResult::Fail("2.4 GHz ERP CTS protection missing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/ht_vht",
    smoke_ht_protection_matches_operating_bandwidth
);

//! Further-link ownership vectors authored from Linux mld/{sta,key,tx,
//! agg,phy}.c semantics. They exercise identity, STA masks and command
//! bodies only and claim no firmware, RF or native receipt behaviour.
use super::super::native_band::Band;
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::association::mlo::BasicMultiLink;

const OWN_MLD: [u8; 6] = [0x02, 0, 0, 0, 0, 0x10];
const AP_MLD: [u8; 6] = [0x02, 0, 0, 0, 0, 0x20];
const OWN_A: [u8; 6] = [0x02, 0, 0, 0, 0, 0x11];
const AP_A: [u8; 6] = [0x02, 0, 0, 0, 0, 0x21];
const OWN_B: [u8; 6] = [0x02, 0, 0, 0, 0, 0x12];
const AP_B: [u8; 6] = [0x02, 0, 0, 0, 0, 0x22];

fn get32(body: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(body[at..at + 4].try_into().unwrap())
}

fn binding() -> Arc<Binding> {
    let mut basic = alloc::vec![0x10, 0, 8];
    basic.extend_from_slice(&AP_MLD);
    basic.push(1);
    let context = Local::single_link(OWN_MLD)
        .unwrap()
        .context(OWN_A, AP_A, &BasicMultiLink::parse(&basic).unwrap())
        .unwrap();
    let channel = Channel {
        band: Band::Five,
        number: 36,
    };
    Binding::new(context, channel, OWN_A, AP_A).unwrap()
}

fn further(spec_link: u8, fw_link: u8, station: u8) -> LinkOwner {
    LinkOwner {
        spec_link,
        fw_link,
        station,
        channel: Channel {
            band: Band::Six,
            number: 37,
        },
        own_link: OWN_B,
        peer_link: AP_B,
    }
}

fn smoke_iwl_mld_further_link_owner_and_sta_mask() -> TestResult {
    let one = binding();
    if one.sta_mask() != 1 || one.active_links() != 1 << 1 || one.secondary().is_some() {
        return TestResult::Fail("single-link binding mask/active links changed");
    }
    // Every aliasing identity is refused before any command.
    for bad in [
        further(1, 1, 1),
        further(2, 0, 1),
        further(2, 1, 0),
        further(15, 1, 1),
        LinkOwner {
            own_link: OWN_A,
            ..further(2, 1, 1)
        },
        LinkOwner {
            peer_link: AP_MLD,
            ..further(2, 1, 1)
        },
    ] {
        if one.with_secondary(bad).is_ok() {
            return TestResult::Fail("aliasing further link admitted");
        }
    }
    let Ok(two) = one.with_secondary(further(2, 1, 1)) else {
        return TestResult::Fail("distinct further link refused");
    };
    if two.sta_mask() != 0b11 || two.active_links() != 0b110 || two.primary() != one.primary() {
        return TestResult::Fail("iwl_mld_fw_sta_id_mask/active links not widened");
    }
    if two.with_secondary(further(3, 2, 2)).is_ok() {
        return TestResult::Fail("third active link exceeded IWL_FW_MAX_ACTIVE_LINKS_NUM");
    }
    let Ok(back) = two.without(2) else {
        return TestResult::Fail("active further link could not be removed");
    };
    if back.sta_mask() != 1 || back.secondary().is_some() || !back.association_only() {
        return TestResult::Fail("removed further link still owns resources");
    }
    if back.without(back.association().spec_link).is_ok() {
        return TestResult::Fail("the only active link was removed");
    }
    // Primary-link switch (mac80211 _ieee80211_set_active_links removing
    // the association link): the further link becomes the serving owner.
    let association = *two.association();
    let Ok(switched) = two.without(association.spec_link) else {
        return TestResult::Fail("association link could not be deactivated");
    };
    if switched.primary().spec_link != 2
        || switched.association_active()
        || switched.sta_mask() != 0b10
        || switched.active_links() != 0b100
        || *switched.association() != association
    {
        return TestResult::Fail("primary-link switch kept the association owner");
    }
    let moved = LinkOwner {
        fw_link: 3,
        ..association
    };
    if switched.with_secondary(moved).is_ok() {
        return TestResult::Fail("association link restored with another identity");
    }
    let Ok(restored) = switched.with_secondary(association) else {
        return TestResult::Fail("association link identity could not be restored");
    };
    if !restored.association_active() || restored.sta_mask() != 0b11 {
        return TestResult::Fail("restored association link lost its STA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_mld_further_link_owner_and_sta_mask
);

fn smoke_iwl_mld_further_link_key_queue_baid_bodies() -> TestResult {
    // Pairwise MODIFY: old/new mask, key 0, CCMP|MFP for an MFP station.
    let key = pairwise_key_modify(1, 3, true);
    if get32(&key, 0) != 2
        || get32(&key, 4) != 1
        || get32(&key, 8) != 3
        || get32(&key, 12) != 0
        || get32(&key, 16) != 0x22
    {
        return TestResult::Fail("SEC_KEY MODIFY body differs from Linux");
    }
    let baid = baid_modify(1, 3, 5);
    if get32(&baid, 0) != 1 || get32(&baid, 4) != 1 || get32(&baid, 8) != 3 || get32(&baid, 12) != 5
    {
        return TestResult::Fail("RX_BAID MODIFY body differs from Linux");
    }
    // Per-link group keys name only that link STA: GTK MCAST|NO_TX,
    // IGTK adds MFP, BIGTK does not.
    let material = [7; 16];
    for (id, flags) in [(1u8, 0x4a), (4, 0x6a), (6, 0x4a)] {
        let Ok(body) =
            super::super::sc_security::key_command_for(1 << 1, id, true, false, Some(&material), 9)
        else {
            return TestResult::Fail("per-link group key refused");
        };
        if get32(&body[..], 4) != 2
            || get32(&body[..], 8) != u32::from(id)
            || get32(&body[..], 12) != flags
        {
            return TestResult::Fail("per-link group key mask/flags differ from Linux");
        }
    }
    if super::super::sc_security::key_command(6, true, false, Some(&material), 0).is_ok() {
        return TestResult::Fail("association-link key path widened to BIGTK");
    }
    let mut ids = PhyIds::station();
    if ids.allocate() != Ok(1) || ids.allocate() != Ok(2) || ids.allocate().is_ok() {
        return TestResult::Fail("PHY ids exceed NUM_PHY_CTX or reuse PHY0");
    }
    ids.release(1);
    if ids.allocate() != Ok(1) {
        return TestResult::Fail("released PHY id not reusable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_mld_further_link_key_queue_baid_bodies
);

fn smoke_iwl_mld_shared_id_pool_and_per_link_group_replay() -> TestResult {
    // Linux shares link/STA/PHY id pools across vifs: with a P2P DEVICE
    // holding FW link1, its last-station aux id and PHY1, a further MLD
    // link takes link2/STA1/PHY2, never an alias.
    let Ok(mut ids) = FwIds::new(Some(3), Some(4)) else {
        return TestResult::Fail("FwIds refused actual counts");
    };
    if ids.claim(1, 3).is_err() || ids.claim(0, 0).is_err() || ids.allocate() != Ok((2, 1)) {
        return TestResult::Fail("further link aliased a reserved P2P link/station id");
    }
    let mut full = FwIds::new(Some(2), Some(4)).unwrap();
    if full.claim(1, 3).is_err() || full.claim(0, 0).is_err() || full.allocate().is_ok() {
        return TestResult::Fail("exhausted FW link pool still allocated");
    }
    let mut phys = PhyIds::station();
    phys.claim(1);
    if phys.allocate() != Ok(2) || phys.allocate().is_ok() {
        return TestResult::Fail("further link PHY aliased P2P PHY1");
    }
    // A further link's group frames use only that link's floors.
    use super::super::frame_api::{GroupReplay, Replay};
    let mut replay = Replay::default();
    replay.group[1].fill(100);
    replay.group_valid[1] = true;
    let mut link = GroupReplay::default();
    link.install(1, 5);
    replay.swap_group(&mut link);
    if replay.group[1][0] != 5 || !replay.group_valid[1] || replay.group_valid[2] {
        return TestResult::Fail("further link group floor not selected");
    }
    replay.group[1][0] = 6;
    replay.swap_group(&mut link);
    if replay.group[1][0] != 100 || link.group[1][0] != 6 || link.group[1][1] != 5 {
        return TestResult::Fail("per-link group PN leaked across links");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_mld_shared_id_pool_and_per_link_group_replay
);

use super::super::connection::Beacon;

fn mld_beacon(bssid: [u8; 6], channel: u8, mld: [u8; 6], link: Option<u8>, eml: u16) -> Beacon {
    let mut ies = alloc::vec![0, 3, b'm', b'l', b'o'];
    if let Some(link) = link {
        // Basic MLE: link id + EML capabilities present. Common-info
        // length: 1 (this length byte) + 6 (MLD address) + 1 (link id) +
        // 2 (EML capabilities) = 10, as required by
        // BasicMultiLink::parse (wireless/src/association/mlo.rs).
        let mut body = alloc::vec![0x90, 0, 10];
        body.extend_from_slice(&mld);
        body.push(link);
        body.extend_from_slice(&eml.to_le_bytes());
        ies.extend_from_slice(&[255, body.len() as u8 + 1, 107]);
        ies.extend_from_slice(&body);
    }
    Beacon {
        bssid,
        ssid: b"mlo".to_vec(),
        channel,
        band: if channel <= 14 { Band::Two } else { Band::Five },
        interval: 100,
        dtim: 1,
        rsn: None,
        privacy: true,
        capabilities: 0x11,
        information_elements: ies,
    }
}

/// cfg80211_mlme_check_mlo/_compat and iwl mld last-MLO-scan freshness
/// select the further links a station association requests.
fn smoke_iwl_mld_scan_candidates_same_ap_mld_fresh_links() -> TestResult {
    use super::super::sc_mlo_assoc::scan_candidates;
    let assoc = mld_beacon(AP_A, 36, AP_MLD, Some(1), 1);
    let other_mld = [0x02, 0, 0, 0, 0, 0x30];
    let stale = [0x02, 0, 0, 0, 0, 0x23];
    let table = alloc::vec![
        assoc.clone(),
        mld_beacon(AP_B, 6, AP_MLD, Some(0), 1),
        // Same link id as the association link.
        mld_beacon([0x02, 0, 0, 0, 0, 0x24], 149, AP_MLD, Some(1), 1),
        // Another AP MLD, an EML mismatch, no MLE, and a stale entry.
        mld_beacon([0x02, 0, 0, 0, 0, 0x25], 1, other_mld, Some(3), 1),
        mld_beacon([0x02, 0, 0, 0, 0, 0x26], 11, AP_MLD, Some(4), 0),
        mld_beacon([0x02, 0, 0, 0, 0, 0x27], 44, AP_MLD, None, 1),
        mld_beacon(stale, 52, AP_MLD, Some(5), 1),
        // Link 2 then a duplicate link 2: only the first is requested.
        mld_beacon([0x02, 0, 0, 0, 0, 0x28], 100, AP_MLD, Some(2), 1),
        mld_beacon([0x02, 0, 0, 0, 0, 0x29], 104, AP_MLD, Some(2), 1),
    ];
    let mut draws = [OWN_MLD, OWN_B, OWN_B, [0x03, 0, 0, 0, 0, 0x13]].into_iter();
    let fresh = |b: &Beacon| b.bssid != stale;
    let Ok(found) = scan_candidates(&assoc, &table, fresh, OWN_MLD, || {
        draws.next().ok_or("exhausted")
    }) else {
        return TestResult::Fail("candidate selection failed");
    };
    let links: alloc::vec::Vec<_> = found.iter().map(|c| c.beacon.bssid).collect();
    if links != [AP_B, [0x02, 0, 0, 0, 0, 0x28]] {
        return TestResult::Fail("wrong further links requested");
    }
    // The MLD address and a reused address are redrawn; the multicast bit
    // is cleared and the locally administered bit set.
    if found[0].own_link != OWN_B || found[1].own_link != [0x02, 0, 0, 0, 0, 0x13] {
        return TestResult::Fail("link address not a fresh distinct random address");
    }
    // A non-MLD association BSS requests nothing.
    let plain = mld_beacon(AP_A, 36, AP_MLD, None, 1);
    if !scan_candidates(&plain, &table, |_| true, OWN_MLD, || Ok(OWN_B)).is_ok_and(|v| v.is_empty())
    {
        return TestResult::Fail("non-MLD BSS requested further links");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_mld_scan_candidates_same_ap_mld_fresh_links
);

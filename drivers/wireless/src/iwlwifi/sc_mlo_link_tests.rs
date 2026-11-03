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
    let back = two.without_secondary();
    if back.sta_mask() != 1 || back.secondary().is_some() {
        return TestResult::Fail("removed further link still owns resources");
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

//! Tag5 `TX_LDPC` / `TX_STBC` programs: TLC coding flags only toward a peer
//! that advertises the matching receive capability, Linux
//! `rs_fw_get_config_flags` (`mvm/rs-fw.c`).
use super::super::super::mvm_boot::feature_bits;
use super::*;

/// HT Capabilities/Operation/WMM of `ht_ies` with `info` bits set in the
/// Capability Information field (bit0 LDPC, bits8..9 Rx STBC).
fn coded_ies(info: u16) -> Vec<u8> {
    let mut ies = ht_ies();
    let cap = u16::from_le_bytes([ies[2], ies[3]]) | info;
    ies[2..4].copy_from_slice(&cap.to_le_bytes());
    ies
}

fn tlc_flags(h: &Harness) -> Result<(u16, u8), &'static str> {
    let actor = h.actor.lock();
    let (_, _, b) = actor
        .commands
        .iter()
        .rev()
        .find(|(g, c, _)| *g == 5 && *c == 15)
        .ok_or("TLC configuration absent")?;
    Ok((u16::from_le_bytes([b[8], b[9]]), b[6]))
}

fn smoke_mvm_tx_ldpc_program_sets_tlc_ldpc_only_for_ldpc_peer() -> TestResult {
    check(|| {
        let h = Harness::build_features(false, true, 5, 3, false, false, feature_bits::TX_LDPC)?;
        {
            let mut ap = h.actor.lock();
            ap.beacon_ies = Some(coded_ies(1));
            ap.response_ies = Some(coded_ies(1));
        }
        h.join()?;
        if tlc_flags(&h)? != (2, 1) {
            return Err("tag5 TX_LDPC did not set TLC_MNG_CFG_FLAGS_LDPC with one chain");
        }
        let start = {
            let mut actor = h.actor.lock();
            actor.closing = true;
            actor.commands.len()
        };
        run(h.device.disassociate())?.map_err(|_| "TX LDPC ordered close")?;
        leaving_deauthentication_preceded_teardown(&h, start)?;
        if h.retained() != (0, 0, 0) {
            return Err("TX LDPC close left native resources");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/coding",
    smoke_mvm_tx_ldpc_program_sets_tlc_ldpc_only_for_ldpc_peer
);

fn smoke_mvm_tx_stbc_program_uses_both_chains_toward_rx_stbc_peer() -> TestResult {
    check(|| {
        for (bits, info, expected) in [
            (feature_bits::TX_STBC, 0x100, (1, 3)),
            (feature_bits::TX_STBC | feature_bits::TX_LDPC, 0x101, (3, 3)),
        ] {
            let h = Harness::build_features(false, true, 5, 3, false, false, bits)?;
            {
                let mut ap = h.actor.lock();
                ap.beacon_ies = Some(coded_ies(info));
                ap.response_ies = Some(coded_ies(info));
            }
            h.join()?;
            if tlc_flags(&h)? != expected {
                return Err("tag5 TX_STBC TLC flag/two-chain mask");
            }
            run(h.device.disassociate())?.map_err(|_| "TX STBC ordered close")?;
            if h.retained() != (0, 0, 0) {
                return Err("TX STBC close left native resources");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/coding",
    smoke_mvm_tx_stbc_program_uses_both_chains_toward_rx_stbc_peer
);

fn smoke_mvm_tx_coding_not_granted_keeps_tlc_flags_clear() -> TestResult {
    check(|| {
        // An LDPC peer without a TX_LDPC program: the tag2 program and no
        // TLC coding flag.
        let h = Harness::profile(false, true)?;
        {
            let mut ap = h.actor.lock();
            ap.beacon_ies = Some(coded_ies(1 | 0x100));
            ap.response_ies = Some(coded_ies(1 | 0x100));
        }
        h.join()?;
        if tlc_flags(&h)? != (0, 1) {
            return Err("TLC coding flags without a tag5 program");
        }
        drop(h);
        // A TX_LDPC program toward a peer without RX LDPC is not offered and
        // its selection fails before any native publication.
        for bits in [feature_bits::TX_LDPC, feature_bits::TX_STBC] {
            if Harness::build_features(false, true, 5, 3, false, false, bits)
                .and_then(|h| h.join())
                .is_ok()
            {
                return Err("TX coding program accepted for a peer without RX support");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/coding",
    smoke_mvm_tx_coding_not_granted_keeps_tlc_flags_clear
);

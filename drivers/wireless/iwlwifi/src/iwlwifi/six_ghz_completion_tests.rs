//! Whole6GHz source continuations over literal native wire contracts.
use super::super::super::super::{runtime::model as native_model, six_ghz_scan};
use super::*;

fn smoke_iwl_six_ghz_active_rnr_psc_native_tables_and_capability_namespaces() -> TestResult {
    check(|| {
        let six = model();
        let guard = setup(Native::Sc, six, Fault::None)?;
        let phy = guard.device().phy;
        let channels = [
            Channel::six(1).unwrap(),
            Channel::six(5).unwrap(),
            Channel::six(9).unwrap(),
        ];
        // Independent crc32 vector for "narf", not the production encoder.
        let targets = vec![
            narf_wireless::scan::Scan6GhzTarget {
                channel: 1,
                frequency_mhz: 5955,
                bssid: AP,
                short_ssid: Some(0x0a70_2122),
                unsolicited_probe: false,
                psc_no_listen: false,
                psd_20: -128,
            },
            narf_wireless::scan::Scan6GhzTarget {
                channel: 5,
                frequency_mhz: 5975,
                bssid: [2, 9, 8, 7, 6, 5],
                short_ssid: Some(0x0a70_2122),
                unsolicited_probe: true,
                psc_no_listen: true,
                psd_20: 8,
            },
        ];
        let ssids = vec![b"narf".to_vec()];
        let mut request = six_ghz_scan::Active {
            permitted: &[true, true, false],
            ssids: &ssids,
            targets: &targets,
            phy,
            hidden: true,
            tpc: true,
            fixed: true,
            extra_ies: &[221, 3, 1, 2, 3],
        };
        for version in 14..=18 {
            let bytes = six_ghz_scan::request(version, 0, &channels, OWN, &request)?;
            let probe = if version == 18 { 604 } else { 596 };
            let band = if version >= 17 { 2 << 30 } else { 0 };
            require(
                half(&bytes, 8) == 0x42
                    && bytes[17] == 4
                    && bytes[45] == 3
                    && word(&bytes, 48) == (band | 0x10000)
                    && word(&bytes, 56) == (band | 0x0300_0002)
                    && word(&bytes, 64) == (band | 0x0400_0000)
                    && bytes[probe + 532..probe + 534] == [1, 2]
                    && word(&bytes, probe + 1216) == 0x0a70_2122
                    && bytes[probe + 538..probe + 542] == *b"narf"
                    && bytes[probe + 1248..probe + 1254] == AP,
                "6GHz UMAC literal target bitmaps/shortSSID/BSSID/hidden source bytes",
            )?;
            require(
                if version < 17 {
                    bytes[53] == 2 && bytes[61] == 2
                } else {
                    bytes[53] == 128 && bytes[61] == 8
                },
                "6GHz versioned band/unknown PSD aliased",
            )?;
            let six_at = usize::from(half(&bytes, probe + 12));
            let six_len = usize::from(half(&bytes, probe + 14));
            let elements = &bytes[probe + 20 + six_at..probe + 20 + six_at + six_len];
            require(
                elements.starts_with(&[1, 8, 0x8c, 18, 0x98, 36, 0xb0, 72, 96, 108])
                    && elements.windows(3).any(|x| x == [255, 22, 35])
                    && elements.ends_with(&[255, 3, 59, 0x1c, 6])
                    && half(&bytes, probe + 4) == 0
                    && half(&bytes, probe + 8) == 0,
                "6GHz native probe omitted HE6-band or emitted legacy-band template",
            )?;
            let common = probe + 20 + usize::from(half(&bytes, probe + 16));
            require(
                bytes[common..common + 14] == [221, 3, 1, 2, 3, 221, 7, 0, 0x50, 0xf2, 8, 0, 0, 0],
                "6GHz source-qualified TPC/common IE template",
            )?;
        }
        request.phy.he = false;
        require(
            six_ghz_scan::request(18, 0, &channels, OWN, &request).is_err(),
            "active6GHz invented HE source",
        )?;
        request.phy = phy;
        request.extra_ies = &[45, 0];
        require(
            six_ghz_scan::request(18, 0, &channels, OWN, &request).is_err(),
            "6GHz extraIE overrode PHY source",
        )?;
        drop(guard);
        // Same numeric59 in two different TLV namespaces is not authority.
        for api in [false, true] {
            for capability in [false, true] {
                let (mut hw, _, _) = native_model::station_model_for_format(
                    super::super::super::super::rx_rfh::CompletionFormat::Ax210,
                );
                let mut image = vec![0; 88];
                image[4..8].copy_from_slice(
                    &super::super::super::super::IWL_TLV_UCODE_MAGIC.to_le_bytes(),
                );
                for (tag, set) in [(29u32, api), (30, capability)] {
                    if set {
                        image.extend_from_slice(&tag.to_le_bytes());
                        image.extend_from_slice(&8u32.to_le_bytes());
                        image.extend_from_slice(&1u32.to_le_bytes());
                        image.extend_from_slice(&(1u32 << 27).to_le_bytes());
                    }
                }
                let parsed = super::super::super::super::parse_ucode(&image)
                    .map_err(|_| "6GHz actual namespace TLVs")?;
                native_model::firmware_profile(&mut hw, &parsed)?;
                require(
                    hw.band_in_rx_supported() == api
                        && hw.scan_hidden_six_supported() == capability
                        && !hw.scan_tpc_supported(),
                    "6GHz cap59 inherited distinct API59 or fabricated TPC cap10",
                )?;
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/six_ghz",
    smoke_iwl_six_ghz_active_rnr_psc_native_tables_and_capability_namespaces
);

fn smoke_iwl_six_ghz_native_active_discovery_uses_copied_legacy_rnr_and_current_power() -> TestResult
{
    check(|| {
        for rnr in [false, true] {
            let mut six = model();
            if rnr {
                six.channel = 1;
            }
            let guard = setup(
                Native::Sc,
                six,
                if rnr {
                    Fault::SixRnrReport
                } else {
                    Fault::None
                },
            )?;
            guard.policy_db.install(policy());
            let mut req = scan(six);
            req.active = true;
            req.ssids = vec![SSID.to_vec()];
            req.colocated_6ghz = rnr;
            if rnr {
                req.channels.clear();
                req.frequencies_mhz = vec![2432, 5955];
            }
            let found = run(guard.device().scan(req), service)?
                .map_err(|_| "native6GHz active PSC/RNR discovery")?;
            require(
                found
                    .iter()
                    .any(|b| b.frequency_mhz == 5950 + 5 * u32::from(six.channel)),
                "native6GHz active target did not produce a band-qualified candidate",
            )?;
            let slot = HARNESS.lock();
            let wire = &slot.as_ref().unwrap().1;
            let at = wire
                .commands
                .iter()
                .rposition(|(g, c, _)| (*g, *c) == (1, 0xd))
                .ok_or("active6GHz command absent")?;
            let body = &wire.commands[at].2;
            require(
                body[45] == 1
                    && body[52] == six.channel
                    && word(body, 48) >> 30 == 2
                    && word(body, 48) & (1 << 26) == 0
                    && half(body, 8) == 0x42
                    && wire.commands[..at]
                        .iter()
                        .any(|(g, c, b)| (*g, *c) == (1, 0x9f) && b[0] == 1),
                "active6GHz probe lacked exact channel or preceding native global power receipt",
            )?;
            if rnr {
                require(
                    body[604 + 532..604 + 534] == [1, 1] && word(body, 48) & 0x00ff_ffff != 0,
                    "native RNR did not populate actual per-channel target tables",
                )?;
            }
            drop(slot);
        }
        for denial in 0..3 {
            let mut six = model();
            if denial == 1 {
                six.mcc_flags = 0x6005;
            } // ALLOW20 is not ACTIVE.
            if denial == 2 {
                six.nvm_flags = 0;
            }
            let guard = setup(Native::Sc, six, Fault::None)?;
            let mut domain = policy();
            if denial == 0 {
                domain.rules[0].flags = RegFlags::NO_IR;
            }
            guard.policy_db.install(domain);
            let mut req = scan(six);
            req.active = true;
            req.ssids = vec![SSID.to_vec()];
            let result = run(guard.device().scan(req), service)?;
            let slot = HARNESS.lock();
            let wire = &slot.as_ref().unwrap().1;
            let scans: Vec<_> = wire
                .commands
                .iter()
                .filter(|(g, c, _)| (*g, *c) == (1, 0xd))
                .collect();
            require(!wire.commands.iter().any(|(g,c,b)|(*g,*c)==(1,0x9f)&&b[0]==1)
                && if denial==2 {result.is_err()&&scans.is_empty()}
                    else {result.is_ok()&&scans.iter().all(|(_,_,b)|half(b,8)&0x800!=0)},
                "active6GHz inferred emission from geometry, ALLOW20, or absent NVM/host permission")?;
            drop(slot);
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/six_ghz",
    smoke_iwl_six_ghz_native_active_discovery_uses_copied_legacy_rnr_and_current_power
);

fn smoke_iwl_six_ghz_live_tpe_replacement_omission_and_response_without_tpe() -> TestResult {
    check(|| {
        for native in [Native::Sc, Native::Mvm, Native::Bz] {
            let six = model();
            let guard = setup(native, six, Fault::SixResponseWithoutTpe)?;
            join(&guard, six)?;
            close(&guard)?;
        }
        for regulatory in 0..=2 {
            let mut six = model();
            six.regulatory = regulatory;
            let guard = setup(Native::Sc, six, Fault::None)?;
            join(&guard, six)?;
            for (tpe, absent) in [(10, false), (30, false), (127, true)] {
                {
                    let mut slot = HARNESS.lock();
                    let wire = &mut slot.as_mut().unwrap().1;
                    six.tpe = tpe;
                    wire.six = Some(six);
                    let mut beacon = wire.ap.beacon();
                    complete_ap_frame(&mut beacon, six)?;
                    if absent {
                        let ies = without(&beacon[36..], 195, None);
                        beacon.truncate(36);
                        beacon.extend_from_slice(&ies);
                    }
                    wire.mpdu(&beacon, false);
                }
                let packet = tx_amsdu_tests::packet(tpe as u8, 100, false);
                let mut state = guard
                    .device()
                    .state
                    .try_lock()
                    .ok_or("live TPE native owner")?;
                let State {
                    hardware,
                    connection,
                    ..
                } = &mut *state;
                run(
                    connection
                        .as_mut()
                        .ok_or("live TPE station absent")?
                        .send(hardware, &packet),
                    service,
                )??;
                drop(state);
                let current = {
                    let slot = HARNESS.lock();
                    let wire = &slot.as_ref().unwrap().1;
                    wire.commands
                        .iter()
                        .rev()
                        .find(|(g, c, _)| (*g, *c) == (4, 0xc))
                        .is_some_and(|(_, _, b)| b[4] == tpe as u8)
                        && wire.data.iter().any(|(f, p)| *p && *f == packet)
                };
                require(current,"live TPE tightened/relaxed/absent replacement lacked current AP receipt or protected DATA")?;
            }
            // AP type is an association fact, not live TPE authority.
            {
                let mut slot = HARNESS.lock();
                let wire = &mut slot.as_mut().unwrap().1;
                let mut changed = six;
                changed.regulatory = (regulatory + 1) % 3;
                let mut beacon = wire.ap.beacon();
                complete_ap_frame(&mut beacon, changed)?;
                wire.mpdu(&beacon, false);
            }
            drain();
            carrier(guard.device(), false)?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/six_ghz",
    smoke_iwl_six_ghz_live_tpe_replacement_omission_and_response_without_tpe
);

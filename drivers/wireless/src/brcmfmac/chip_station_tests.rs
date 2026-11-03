// SPDX-License-Identifier: GPL-2.0-or-later
//! Covered non-BCM43602 chip profiles over the shared CR4/msgbuf station
//! path. The model's identity word names a BCM4356 (Linux 0x180000 CR4 RAM
//! base, so the retained model layout is unchanged); its firmware replies
//! are synthetic and qualify no physical board.
use super::*;
use crate::cyw43439::phy_fixture::{Vht80, VhtFault};

/// ChipCommon identity (AI, revision 2, chip 0x4356), chip id, PCI id.
const BCM4356: (u32, u16, u16) = (0x1002_4356, 0x4356, 0x43ec);

fn width(h: &Harness) -> Option<u32> {
    h.device
        .state
        .try_lock()
        .unwrap()
        .station
        .channel_width_mhz()
}
fn native(caps: [u32; 2], with160: bool, request160: bool) -> Vht80 {
    let mut inventory = vec![
        0xd826, 0xd926, 0xd82e, 0xd92e, 0xe02a, 0xe12a, 0xe22a, 0xe32a,
    ];
    if with160 {
        // Independent brcmu_d11.c D11AC 5 GHz 160 MHz, center 50, primary 36.
        inventory.push(0xe832);
    }
    Vht80 {
        caps,
        mode: Some(1),
        txstreams: Some(2),
        txbf: [None, None],
        // Firmware's own request carries SUPP_CHAN_WIDTH_160 | SHORT_GI_160.
        txbf_request: if request160 { 4 | 64 } else { 0 },
        inventory,
        center: 42,
        fault: VhtFault::None,
    }
}

fn station_160_capability() -> Result<(), &'static str> {
    for version in [5, 6] {
        // bw_cap 160 bit plus a reported 160 MHz chanspec: Linux
        // brcmf_update_vht_cap's 160 bits; operation stays 80 MHz.
        let h = Harness::new_vht_chip(version, 36, 3, native([3, 15], true, true), BCM4356)?;
        let vht = h
            .device
            .phy_capabilities(5000)
            .and_then(|c| c.vht)
            .ok_or("covered-chip VHT capability missing")?;
        if vht[..4] != [32 | 4 | 64, 0, 0, 0] {
            return Err("160 MHz capability not taken from the firmware bw_cap/chanspec");
        }
        h.associate(false)?;
        let commands = h.bus.commands();
        let join = commands
            .iter()
            .position(|(id, _, _)| *id == 26)
            .ok_or("covered-chip join missing")?;
        if commands[join].1[48..50] != 0xe02au16.to_le_bytes()
            || width(&h) != Some(80)
            || !h.device.state.try_lock().unwrap().station.vht_connection()
        {
            return Err("covered chip did not join VHT80 through the shared path");
        }
        ready(h.device.disassociate())?.map_err(|_| "covered-chip teardown")?;
        if h.device.link_up() || h.bus.stats().5 != 0 {
            return Err("covered-chip teardown retained authority or freed live DMA");
        }
        // Missing either firmware fact keeps the 80 MHz capability.
        for (caps, with160) in [([3, 7], true), ([3, 15], false)] {
            let h = Harness::new_vht_chip(version, 36, 3, native(caps, with160, false), BCM4356)?;
            let vht = h
                .device
                .phy_capabilities(5000)
                .and_then(|c| c.vht)
                .ok_or("covered-chip VHT80 capability missing")?;
            if vht[..4] != [32, 0, 0, 0] {
                return Err("160 MHz capability assumed without both firmware facts");
            }
            h.associate(false)?;
            if width(&h) != Some(80) {
                return Err("covered chip without 160 did not join VHT80");
            }
        }
        // The retained BCM43602 ignores the 160 bit exactly as before.
        let h = Harness::new_vht(
            version,
            false,
            36,
            None,
            false,
            7,
            native([3, 15], true, false),
        )?;
        if h.device
            .phy_capabilities(5000)
            .and_then(|c| c.vht)
            .map(|v| v[0])
            != Some(32)
        {
            return Err("BCM43602 VHT capability changed");
        }
    }
    Ok(())
}
fn smoke_brcmf_chip_profile_station_vht160_capability_from_firmware() -> TestResult {
    station_160_capability().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/chips",
    smoke_brcmf_chip_profile_station_vht160_capability_from_firmware
);

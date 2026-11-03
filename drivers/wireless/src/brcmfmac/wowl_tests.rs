// SPDX-License-Identifier: GPL-2.0-or-later
//! BCM43602 Wake-on-WLAN and GTK rekey offload over the msgbuf model:
//! Linux 7.3-rc4 `feature.c` probe, `brcmf_configure_wowl` +
//! `brcmf_keepalive_start` before D3_INFORM, `brcmf_cfg80211_resume`
//! wake report and clear after D0_INFORM, `brcmf_cfg80211_set_rekey_data`.
use super::*;
use crate::cyw43439::station::wowl::{self, Wakeup};
use narf_wireless::{GtkRekeyData, WowlanConfig, WowlanPattern};

fn harness(cap: Option<u32>) -> Result<Harness, &'static str> {
    let (adapter, bus) = firmware::create(6, true).map_err(|_| "CR4/common-ring ownership")?;
    bus.keys_first(true);
    bus.channel(6);
    if let Some(cap) = cap {
        bus.wowl_profile(cap);
    }
    let station = ready(Station::initialize(adapter, &[], firmware::domain()))?
        .map_err(|_| "PCIe station firmware initialization")?;
    let name = narf_net::iface::register("wlan%d", OWN, send);
    let device = shell(name.clone(), station);
    narf_net::iface::set_link_state(&name, true);
    narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
    narf_net::iface::install_rx_drain(drain);
    Ok(Harness {
        device,
        bus,
        name,
        channel: 6,
        association_ies: Vec::new(),
    })
}
fn iovar(name: &str, value: &[u8]) -> (u32, Vec<u8>) {
    let mut body = name.as_bytes().to_vec();
    body.push(0);
    body.extend_from_slice(value);
    (263, body)
}
fn since(harness: &Harness, mark: usize) -> Vec<(u32, Vec<u8>)> {
    harness.bus.commands()[mark..]
        .iter()
        .map(|(command, body, _)| (*command, body.clone()))
        .collect()
}
fn config() -> WowlanConfig {
    WowlanConfig {
        disconnect: true,
        magic_packet: true,
        gtk_rekey_failure: true,
        // IPv4 EtherType at Ethernet offset 12.
        patterns: vec![WowlanPattern {
            mask: vec![0x03],
            pattern: vec![0x08, 0x00],
            offset: 12,
        }],
        net_detect: None,
    }
}
fn suspend_program() -> Vec<(u32, Vec<u8>)> {
    let mut clear = [0u8; 8];
    clear[..6].copy_from_slice(b"clear\0");
    vec![
        (85, vec![0; 4]),
        (86, 1u32.to_le_bytes().to_vec()),
        iovar(
            "wowl_pattern",
            &wowl::pattern(b"add\0", &[0x08, 0x00], &[0x03], 12),
        ),
        iovar("wowl_wakeind", &clear),
        iovar("wowl", &0x41fu32.to_le_bytes()),
        iovar("wowl_activate", &1u32.to_le_bytes()),
        iovar("mkeep_alive", &wowl::keep_alive()),
    ]
}
fn resume_clear() -> Vec<(u32, Vec<u8>)> {
    vec![
        (262, b"wowl_wakeind\0".to_vec()),
        iovar("wowl_clear", &0u32.to_le_bytes()),
        iovar("wowl_pattern", &wowl::pattern(b"clr\0", &[], &[], 0)),
        (86, 0u32.to_le_bytes().to_vec()),
    ]
}

/// Fixed `fwil_types.h` layouts and the `brcmf_report_wowl_wakeind` map.
fn wire() -> Result<(), &'static str> {
    let add = wowl::pattern(b"add\0", &[0xaa; 10], &[0xff, 0x03], 14);
    let word = |bytes: &[u8], at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    if add.len() != 32 + 2 + 10
        || &add[..4] != b"add\0"
        || word(&add, 4) != 2
        || word(&add, 8) != 14
        || word(&add, 12) != 30
        || word(&add, 16) != 10
        || add[20..32] != [0; 12]
        || add[32..34] != [0xff, 0x03]
        || add[34..] != [0xaa; 10]
    {
        return Err("brcmf_fil_wowl_pattern_le add layout");
    }
    let clr = wowl::pattern(b"clr\0", &[], &[], 0);
    if clr.len() != 32 || &clr[..4] != b"clr\0" || word(&clr, 12) != 28 || word(&clr, 16) != 0 {
        return Err("brcmf_fil_wowl_pattern_le clr layout");
    }
    if wowl::keep_alive() != [1, 0, 0, 0, 0x30, 0x75, 0, 0, 0, 0, 0] {
        return Err("brcmf_mkeep_alive_pkt_le layout");
    }
    let data = GtkRekeyData {
        kek: [0x22; 16],
        kck: [0x11; 16],
        replay_counter: [0, 0, 0, 0, 0, 0, 0, 7],
        akm: Some(0x000f_ac02),
    };
    let info = wowl::gtk_keyinfo(&data);
    if info[..16] != [0x11; 16] || info[16..32] != [0x22; 16] || info[32..] != data.replay_counter {
        return Err("brcmf_gtk_keyinfo_le order kck/kek/replay");
    }
    let ind = |value: u32| {
        let mut reply = [0u8; 8];
        reply[4..].copy_from_slice(&value.to_le_bytes());
        wowl::decode_wakeind(&reply)
    };
    let disconnect = Wakeup {
        disconnect: true,
        wakeind: wowl::WOWL_BCN,
        ..Default::default()
    };
    if ind(wowl::WOWL_MAGIC)
        .ok()
        .flatten()
        .is_none_or(|w| !w.magic_packet || w.disconnect)
        || ind(wowl::WOWL_BCN) != Ok(Some(disconnect))
        || ind(wowl::WOWL_NET)
            .ok()
            .flatten()
            .is_none_or(|w| w.pattern != Some(0))
        || ind(wowl::WOWL_GTK_FAILURE) != Ok(None)
        || ind(wowl::WOWL_GTK_FAILURE | wowl::WOWL_RETR)
            .ok()
            .flatten()
            .is_none_or(|w| !w.gtk_rekey_failure || !w.disconnect)
        || ind(0) != Ok(None)
        || wowl::decode_wakeind(&[0; 4]).is_ok()
    {
        return Err("brcmf_report_wowl_wakeind mapping");
    }
    let features = wowl::Features {
        gtk: true,
        net_detect: true,
    };
    let support = features.support();
    if support.max_patterns != 16
        || support.max_pattern_len != 128
        || support.min_pattern_len != 1
        || support.max_packet_offset != 1500
        || support.net_detect_max_match_sets != 0
        || !support.gtk_rekey
        || wowl::Features::default().support().gtk_rekey_failure
    {
        return Err("brcmf_wowlan_support limits or feature gating");
    }
    let mut bad = config();
    bad.patterns[0].mask = vec![0x03, 0];
    let mut many = config();
    many.patterns = vec![many.patterns[0].clone(); 17];
    if features.validate(&config()).is_err()
        || features.validate(&bad).is_ok()
        || features.validate(&many).is_ok()
        || wowl::Features::default().validate(&config()).is_ok()
        || wowl::trigger_bits(&config(), true) != 0x41f
        || wowl::trigger_bits(&WowlanConfig::default(), false) != wowl::WOWL_UNASSOC
    {
        return Err("SET_WOWLAN bounds or brcmf_configure_wowl trigger word");
    }
    Ok(())
}
fn smoke_brcmf_wowl_wire_layouts_and_wake_decode() -> TestResult {
    wire().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/wow",
    smoke_brcmf_wowl_wire_layouts_and_wake_decode
);

/// Without `pci_pme_capable(D3hot)` no `wowl` probe is issued and nothing
/// is advertised; with it, only the firmware-reported features are.
fn advertisement() -> Result<(), &'static str> {
    let plain = harness(None)?;
    if plain.device.wowlan_support().is_some()
        || plain.device.supports_gtk_rekey_offload()
        || plain.device.set_wowlan(Some(config())) != Err(95)
        || plain
            .bus
            .commands()
            .iter()
            .any(|(_, body, _)| body.starts_with(b"wowl"))
    {
        return Err("WoWL advertised or probed without a PME-capable bus");
    }
    drop(plain);
    let basic = harness(Some(0))?;
    let support = basic.device.wowlan_support().ok_or("WOWL not advertised")?;
    if support.gtk_rekey
        || basic.device.supports_gtk_rekey_offload()
        || basic.device.set_wowlan(Some(config())) != Err(22)
        || basic.device.set_wowlan(Some(WowlanConfig {
            magic_packet: true,
            ..Default::default()
        })) != Ok(())
        || basic.device.wowlan_config().is_none_or(|c| !c.magic_packet)
        || basic.device.set_wowlan(None) != Ok(())
        || basic.device.wowlan_config().is_some()
    {
        return Err("WOWL without WOWL_GTK advertised GTK or retained bad triggers");
    }
    Ok(())
}
fn smoke_brcmf_wowl_advertised_only_with_pme_and_firmware() -> TestResult {
    advertisement().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/wow",
    smoke_brcmf_wowl_advertised_only_with_pme_and_firmware
);

/// Composed WPA2 station: SET_REKEY_OFFLOAD → `gtk_key_info`, SET_WOWLAN,
/// system suspend (WoWL program, keep-alive, D3_INFORM) keeping the
/// association, a magic-packet wake, D0_INFORM resume with the wake report
/// and the awake configuration restored, then uplink on the same peer.
fn conversation() -> Result<(), &'static str> {
    let harness = harness(Some(wowl::WOWL_GTK_FAILURE))?;
    if !harness.device.supports_gtk_rekey_offload()
        || harness
            .device
            .wowlan_support()
            .is_none_or(|s| !s.gtk_rekey_failure)
    {
        return Err("WOWL_GTK not advertised");
    }
    let rekey = GtkRekeyData {
        kek: [0x22; 16],
        kck: [0x11; 16],
        replay_counter: [0, 0, 0, 0, 0, 0, 0, 3],
        akm: None,
    };
    if harness.device.set_gtk_rekey_data(rekey) != Err(107) {
        return Err("rekey data accepted without an association");
    }
    harness.associate(true)?;
    let mark = harness.bus.commands().len();
    harness
        .device
        .set_gtk_rekey_data(rekey)
        .map_err(|_| "SET_REKEY_OFFLOAD refused")?;
    ready(harness.device.apply_external())?;
    if since(&harness, mark) != [iovar("gtk_key_info", &wowl::gtk_keyinfo(&rekey)[..])] {
        return Err("gtk_key_info bytes");
    }
    harness
        .device
        .set_wowlan(Some(config()))
        .map_err(|_| "SET_WOWLAN refused")?;
    harness.bus.d3_ack(true);
    let mark = harness.bus.commands().len();
    narf_scheduler::block_on(Endpoint::suspend(&*harness.device))
        .map_err(|_| "WoWL suspend failed")?;
    if since(&harness, mark) != suspend_program()
        || harness.bus.pm() != 1
        || harness.device.connected_bssid() != Some(AP)
        || !harness.device.link_up()
    {
        return Err("WoWL program/keep-alive order or association dropped");
    }
    // The firmware wakes the host for a magic packet.
    harness.bus.wowl_wake(wowl::WOWL_MAGIC);
    harness.bus.d0_alive();
    let mark = harness.bus.commands().len();
    narf_scheduler::block_on(Endpoint::resume(&*harness.device))
        .map_err(|_| "D0_INFORM resume failed")?;
    let expected = Wakeup {
        magic_packet: true,
        wakeind: wowl::WOWL_MAGIC,
        ..Default::default()
    };
    if since(&harness, mark) != resume_clear()
        || harness.bus.pm() != 0
        || harness.device.last_wowlan_wakeup() != Some(expected)
    {
        return Err("wake report, wowl_clear, pattern clr or PM restore");
    }
    let (uplink, _) = packets();
    harness
        .device
        .enqueue(&uplink)
        .map_err(|_| "post-resume TX refused")?;
    harness.pump();
    if !harness.bus.uplink(&uplink) || harness.device.connected_bssid() != Some(AP) {
        return Err("post-resume uplink did not reach the retained peer");
    }
    Ok(())
}
fn smoke_brcmf_wowl_suspend_magic_wake_resume_conversation() -> TestResult {
    conversation().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/wow",
    smoke_brcmf_wowl_suspend_magic_wake_resume_conversation
);

/// A refused D3 handshake after WoWL programming leaves the transport UP:
/// the awake configuration is restored before the coordinator unwinds.
fn unwind() -> Result<(), &'static str> {
    let harness = harness(Some(0))?;
    harness.associate(true)?;
    let mut config = config();
    config.gtk_rekey_failure = false;
    harness
        .device
        .set_wowlan(Some(config))
        .map_err(|_| "SET_WOWLAN refused")?;
    harness.bus.d3_ack(false);
    let mark = harness.bus.commands().len();
    if narf_scheduler::block_on(Endpoint::suspend(&*harness.device)).is_ok() {
        return Err("unacknowledged D3 suspend succeeded");
    }
    let commands = since(&harness, mark);
    if commands.len() != 11
        || commands[7..] != resume_clear()[..]
        || harness.bus.pm() != 0
        || harness.device.connected_bssid() != Some(AP)
        || harness.device.last_wowlan_wakeup().is_some()
    {
        return Err("refused suspend did not clear WoWL and restore PM");
    }
    Ok(())
}
fn smoke_brcmf_wowl_refused_d3_restores_awake_config() -> TestResult {
    unwind().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/wow",
    smoke_brcmf_wowl_refused_d3_restores_awake_config
);

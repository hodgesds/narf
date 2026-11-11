//! Composed station WoWLAN conversation (Linux `wow.c`
//! `ath10k_wow_op_suspend` -> `ath10k_wow_op_resume`) over the retained
//! Device, holder task, native HTC/WMI/CE and a WPA2 association. The model
//! firmware answers WOW_ENABLE on HTC endpoint 0 and HOSTWAKEUP with
//! WOW_WAKEUP_HOST; the FakeAp keeps checking PN/replay after resume.
use super::*;
use core::future::Future;
use narf_wireless::{WowlanConfig, WowlanPattern};

fn harness(wow: bool) -> Harness {
    Harness::new_on_firmware(
        4,
        Dialect::Tlv,
        true,
        false,
        2412,
        0x64,
        NativeFirmware {
            ht: None,
            radio: RadioSource {
                hardware: HwRev::Qca6174,
                rf_chains: 2,
                vht: None,
            },
            all_inventory: false,
            // RAW, WMI management TX/by-reference and (optionally) WOWLAN.
            features: (1 << 10) | (1 << 2) | (1 << 18) | if wow { 1 << 6 } else { 0 },
            htt: (3, 1),
            hardware_keys: true,
            nlo: false,
        },
    )
}
/// Poll the holder task and the caller's future with one noop waker, as the
/// executor would interleave them.
pub(super) type Holder = Option<core::pin::Pin<Box<dyn Future<Output = ()>>>>;
pub(super) fn interleave<F: Future>(holder: &mut Holder, future: F) -> Poll<F::Output> {
    let mut future = core::pin::pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..8192 {
        if let Some(task) = holder.as_mut() {
            if task.as_mut().poll(&mut cx).is_ready() {
                *holder = None;
            }
        }
        if let Poll::Ready(result) = future.as_mut().poll(&mut cx) {
            return Poll::Ready(result);
        }
    }
    Poll::Pending
}
pub(super) fn word(v: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(v[at..at + 4].try_into().unwrap())
}

fn conversation(reason: u32) -> Result<(), &'static str> {
    let h = harness(true);
    h.model(|m| {
        m.wow = Some(super::super::wow_native::Fixture {
            reason,
            commands: Vec::new(),
        })
    });
    let support = h
        .device
        .wowlan_support()
        .ok_or("WOWLAN feature+service not advertised")?;
    if !support.disconnect || !support.magic_packet || support.max_patterns != 0 {
        return Err("RAW decap advertisement");
    }
    let pattern = WowlanConfig {
        patterns: vec![WowlanPattern {
            mask: vec![1],
            pattern: vec![0xaa],
            offset: 0,
        }],
        ..WowlanConfig::default()
    };
    if h.device.set_wowlan(Some(pattern)).is_ok() {
        return Err("zero-length RAW pattern path accepted");
    }
    let config = WowlanConfig {
        disconnect: true,
        magic_packet: true,
        ..WowlanConfig::default()
    };
    h.device
        .set_wowlan(Some(config.clone()))
        .map_err(|_| "SET_WOWLAN refused")?;
    if !matches!(h.device.wow_suspend(), Ok(None)) {
        return Err("unassociated station entered WoW");
    }
    h.join()?;
    let (uplink, _) = packets();
    let (arming, holder) = h
        .device
        .wow_suspend()
        .map_err(|_| "WoW program refused")?
        .ok_or("associated station not eligible")?;
    let mut holder: Holder = Some(Box::pin(holder));
    let Poll::Ready(Ok(suspended)) = interleave(&mut holder, arming.armed()) else {
        return Err("WOW_ENABLE suspend-complete not observed");
    };
    // The holder owns the Radio across WoW: no worker/control can reach it.
    if h.device.radio.try_lock().is_some() || h.device.drain() {
        return Err("WoW-armed radio reachable by the worker");
    }
    let Poll::Ready(result) = interleave(&mut holder, suspended.resume()) else {
        return Err("WOW_WAKEUP_HOST not observed");
    };
    let report = h.device.wowlan_wakeup().ok_or("no wake report")?;
    if report.reason != reason || report.packet != [0xde, 0xad, 0xbe, 0xef] {
        return Err("wake report contents");
    }
    let commands = h.model(|m| m.wow.as_ref().unwrap().commands.clone());
    // cleanup 24 + 22, five STA disconnect/magic events, ENABLE, HOSTWAKEUP.
    let events = [0u32, 2, 3, 8, 10];
    if commands.len() != 24 + 22 + events.len() + 2
        || commands[..24]
            .iter()
            .enumerate()
            .any(|(i, c)| word(c, 0) != 0x13003 || word(c, 12) != 0 || word(c, 16) != 1 << i)
        || commands[24..46]
            .iter()
            .enumerate()
            .any(|(i, c)| word(c, 0) != 0x13002 || word(c, 12) != i as u32)
        || commands[46..51]
            .iter()
            .zip(events)
            .any(|(c, e)| word(c, 0) != 0x13003 || word(c, 12) != 1 || word(c, 16) != 1 << e)
        || word(&commands[51], 0) != 0x13004
        || word(&commands[52], 0) != 0x13005
    {
        return Err("Linux wow.c command order");
    }
    if reason == 10 {
        // Magic packet: association, keys and PN/replay state are kept.
        result.map_err(|_| "magic-packet resume dropped the association")?;
        if !h.device.link_up() || h.device.wowlan_config() != Some(config) {
            return Err("carrier or SET_WOWLAN state lost across WoW");
        }
        let before = h.model(|m| m.data.as_ref().unwrap().uplink.len());
        narf_net::iface::send_on(&h.name, &uplink).map_err(|_| "post-resume uplink")?;
        h.pump();
        if !h.model(|m| {
            let data = m.data.as_ref().unwrap();
            data.uplink.len() > before && data.uplink.contains(&uplink)
        }) {
            return Err("post-resume CCMP uplink rejected by the AP's PN/replay check");
        }
    } else if result.is_ok() || !report.connection_lost() {
        return Err("disconnect-class wake kept a stale association");
    }
    Ok(())
}

fn smoke_ath10k_wow_magic_suspend_wake_resume_keeps_wpa2_link() -> TestResult {
    match conversation(10) {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/ath10k/wow",
    smoke_ath10k_wow_magic_suspend_wake_resume_keeps_wpa2_link
);

fn smoke_ath10k_wow_deauth_wake_requests_restart() -> TestResult {
    match conversation(3) {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/ath10k/wow",
    smoke_ath10k_wow_deauth_wake_requests_restart
);

/// Without `ATH10K_FW_FEATURE_WOWLAN_SUPPORT` nothing is advertised and
/// SET_WOWLAN is -EOPNOTSUPP (`ath10k_wow_init` returns early).
fn smoke_ath10k_wow_unadvertised_without_firmware_feature() -> TestResult {
    let h = harness(false);
    if h.device.wowlan_support().is_some()
        || h.device.set_wowlan(Some(WowlanConfig::default())) != Err(narf_wireless::EOPNOTSUPP)
        || !matches!(h.device.wow_suspend(), Ok(None))
    {
        return TestResult::Fail("WoW advertised without the firmware feature");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wow",
    smoke_ath10k_wow_unadvertised_without_firmware_feature
);

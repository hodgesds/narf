// SPDX-License-Identifier: GPL-2.0-or-later
//! Power-save commands consumed through actual retained PCIe msgbuf DMA.
use super::*;

fn policy() -> Result<(), &'static str> {
    for version in [5, 6] {
        let harness = Harness::new(version, true, false)?;
        harness.associate(true)?;
        for enabled in [true, true, false] {
            harness
                .device
                .set_power_save(enabled)
                .map_err(|_| "PCIe PS request")?;
            ready(harness.device.apply_power_save())?;
            if harness
                .device
                .state
                .try_lock()
                .unwrap()
                .station
                .power_save()
                != enabled
                || !harness.device.link_up()
                || harness.device.connected_bssid() != Some(AP)
            {
                return Err("PCIe power-save receipt changed authorized peer or applied policy");
            }
        }
        let mut timeout = b"pm2_sleep_ret\0".to_vec();
        timeout.extend_from_slice(&[0xd0, 0x07, 0, 0]);
        if harness.bus.power_commands()
            != [
                (86, vec![0; 4]),
                (86, vec![2, 0, 0, 0]),
                (263, timeout.clone()),
                (86, vec![0; 4]),
                (263, timeout),
            ]
            || harness.bus.stats().5 != 0
        {
            return Err("PCIe native command bytes, duplicate policy or DMA retention");
        }
    }
    Ok(())
}
fn smoke_brcmf_power_save_native_receipts_preserve_peer_and_dma() -> TestResult {
    policy().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/power",
    smoke_brcmf_power_save_native_receipts_preserve_peer_and_dma
);

fn rejected() -> Result<(), &'static str> {
    for version in [5, 6] {
        for command in [86, 263] {
            let harness = Harness::new(version, true, true)?;
            harness.associate(true)?;
            let (uplink, _) = packets();
            harness
                .device
                .enqueue(&uplink)
                .map_err(|_| "PCIe pre-failure TX")?;
            harness.bus.reject_power_save(command);
            harness
                .device
                .set_power_save(true)
                .map_err(|_| "PCIe PS request")?;
            ready(harness.device.apply_power_save())?;
            if !harness.closed(&uplink)
                || harness.bus.sent() != 0
                || harness.device.set_power_save(false) != Err(19)
                || harness.bus.stats().5 != 0
            {
                return Err(
                    "PCIe rejected power policy retained carrier/TX or freed uncertain DMA",
                );
            }
            let mut state = harness.device.state.try_lock().unwrap();
            if state.pending.is_some()
                || !matches!(state.tx.try_recv(), Ok(None))
                || state.station.power_save()
                || state.station.poll() != Err(Error::Failed)
            {
                return Err("PCIe rejected power policy kept queued data or reusable station");
            }
        }
    }
    Ok(())
}
fn smoke_brcmf_power_save_partial_or_rejected_transition_is_terminal() -> TestResult {
    rejected().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/power",
    smoke_brcmf_power_save_partial_or_rejected_transition_is_terminal
);

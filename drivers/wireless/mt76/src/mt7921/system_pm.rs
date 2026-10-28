//! System suspend/resume of the retained CONNAC2 PCIe owner.
//!
//! Linux references (7.3-rc7, `drivers/net/wireless/mediatek/mt76`):
//! - `mt7921/pci.c::mt7921_pci_suspend` / `mt7921_pci_resume` — driver own,
//!   forced deep sleep, HIF suspend, WFDMA busy poll then TX/RX DMA_EN clear,
//!   host interrupt masking and the final firmware-own handoff; resume takes
//!   driver own, reinitializes WPDMA only when the device lost it, re-enables
//!   DMA, restores the deep-sleep policy and reports HIF resume. Any resume
//!   failure falls back to `mt792x_reset` (here: the verified WFSYS reset of
//!   `recovery.rs`).
//! - `mt792x_core.c::__mt792x_mcu_{drv,fw}_pmctrl` — ten LPCTL attempts, each
//!   polling `PCIE_LPCR_HOST_OWN_SYNC` for 50 ms.
//! - `mt792x_dma.c::mt792x_wpdma_reinit_cond` / `mt792x_dma_need_reinit` —
//!   `MT_WFDMA_DUMMY_CR.MT_WFDMA_NEED_REINIT` is set by every DMA enable and
//!   lost when the WFDMA block was powered down.
//! - `mt76_connac_mcu.c::mt76_connac_mcu_set_hif_suspend` (UNI `HIF_CTRL`,
//!   `UNI_HIF_CTRL_BASIC`, `hif_type = 2` for PCIe) and
//!   `mt76_connac_mcu_set_deep_sleep` (CE `CHIP_CONFIG`, `"KeepFullPwr %d"`).
//! - Without WoWLAN, `net/wireless/sysfs.c::wiphy_suspend` calls
//!   `cfg80211_leave_all` before `__ieee80211_suspend` removes the interface
//!   (`mt76_connac_mcu_uni_add_dev(.., false)`: BSS inactive, then DEV
//!   inactive) and stops the MAC (`mt76_connac_mcu_set_mac_enable(.., false)`).
//!   A suspended station is therefore never resumed associated: resume
//!   returns the radio idle, and a fresh scan/association is required.
use super::station::Command;
use super::{Backend, Error, RadioInfo, Session, Stage, State};

/// `MCU_CE_CMD_CHIP_CONFIG`.
const CE_CHIP_CONFIG: u8 = 0xca;
/// `MCU_UNI_CMD_HIF_CTRL`.
const UNI_HIF_CTRL: u16 = 0x07;
/// `MT792x_DRV_OWN_RETRY_COUNT`.
const OWN_RETRIES: usize = 10;
/// `mt76_poll_msec_tick(.., 50, 1)` per LPCTL attempt.
const OWN_POLL_MS: u64 = 50;
/// WFDMA busy poll around the DMA_EN clear. Linux polls 1 ms; the bound is
/// widened to a few scheduler ticks so one late poll is not a failure.
const IDLE_POLL_MS: u64 = 10;
/// `MCU_EXT_CMD_ID_RADIO_ON_OFF_CTRL` and its `EXT_CMD_RADIO_{ON,OFF}_LED`.
const EXT_RADIO_ON_OFF_CTRL: u8 = 0x05;
const RADIO_ON_LED: u8 = 0x2;
const RADIO_OFF_LED: u8 = 0x3;

/// `struct mt76_connac_config` carrying `"KeepFullPwr %d"` (`!enable`).
pub(super) fn deep_sleep_config(enable: bool) -> [u8; 328] {
    let mut body = [0u8; 328];
    let text: &[u8] = if enable {
        b"KeepFullPwr 0"
    } else {
        b"KeepFullPwr 1"
    };
    body[8..8 + text.len()].copy_from_slice(text);
    body
}

/// `mt76_connac_mcu_set_hif_suspend`: `{hif_type, pad[3]}` then the
/// `UNI_HIF_CTRL_BASIC` TLV `{tag = 0, len = 12, suspend, pad[7]}`.
pub(super) fn hif_suspend_request(suspend: bool) -> [u8; 16] {
    let mut body = [0u8; 16];
    body[0] = 2; // HIF_PCIE
    body[4..6].copy_from_slice(&0u16.to_le_bytes());
    body[6..8].copy_from_slice(&12u16.to_le_bytes());
    body[8] = u8::from(suspend);
    body
}

impl<B: Backend> Session<B> {
    /// Quiesce the radio for a platform suspend. An association is left
    /// first (cfg80211 without WoWLAN); the firmware VIF and MAC are then
    /// stopped before the PCIe low-power handoff.
    pub(super) async fn suspend(&mut self) -> Result<(), Error> {
        let (info, vif) = match self.state {
            State::Suspended(_) => return Ok(()),
            State::Associated { info, .. } => {
                self.disassociate_station().await?;
                (info, true)
            }
            State::ScanReady(info) => (info, true),
            State::RadioReady(info) => (info, false),
            _ => return Err(Error::Busy),
        };
        self.boot_started = Some(self.backend.now_ns());
        let result = self.suspend_inner(info, vif).await;
        self.boot_started = None;
        match result {
            Ok(()) => {
                self.events.clear();
                self.state = State::Suspended(info);
                Ok(())
            }
            Err(error) => {
                // Linux restore_napi/restore_suspend: undo what was started,
                // and only a failed undo requires the reset path.
                self.boot_started = Some(self.backend.now_ns());
                let restored = self.resume_inner(info).await;
                self.boot_started = None;
                self.state = match restored {
                    Ok(()) => State::RadioReady(info),
                    Err(_) => State::Failed {
                        stage: Stage::Suspend,
                        error,
                    },
                };
                Err(error)
            }
        }
    }

    async fn suspend_inner(&mut self, info: RadioInfo, vif: bool) -> Result<(), Error> {
        self.stage(Stage::Suspend);
        if vif {
            let bss = super::scan::station_bss_record(false);
            self.exchange(Command::Unified { id: 2 }, &bss).await?;
            let mut dev = [0u8; 16];
            super::super::cmd::encode_uni_dev_info_update(
                0,
                0,
                false,
                info.capabilities.mac,
                &mut dev,
            )
            .ok_or(Error::Bounds)?;
            self.exchange(Command::Unified { id: 1 }, &dev).await?;
            self.exchange(
                Command::Extended {
                    id: 0x46,
                    query: false,
                },
                &[0, 0, 0, 0],
            )
            .await?;
        }
        if !self.data_pending.is_empty() {
            return Err(Error::Busy);
        }
        self.take_driver_own().await?;
        self.radio_led(RADIO_OFF_LED).await?;
        // set_hif_suspend(mdev, true, true): the firmware acknowledgement is
        // awaited before deep sleep is forced.
        self.exchange(
            Command::Unified { id: UNI_HIF_CTRL },
            &hif_suspend_request(true),
        )
        .await?;
        self.notify(
            Command::Ce {
                id: CE_CHIP_CONFIG,
                query: false,
            },
            &deep_sleep_config(true),
        )
        .await?;
        self.wait(IDLE_POLL_MS, |backend| {
            backend.idle().map(|idle| idle.then_some(()))
        })
        .await?;
        self.backend.suspend_dma()?;
        // Clearing DMA_EN after the busy poll must leave the engine idle
        // before ownership leaves the host.
        self.wait(IDLE_POLL_MS, |backend| {
            backend.idle().map(|idle| idle.then_some(()))
        })
        .await?;
        for _ in 0..OWN_RETRIES {
            self.backend.request_firmware_own()?;
            match self
                .wait(OWN_POLL_MS, |backend| {
                    backend.firmware_owned().map(|owned| owned.then_some(()))
                })
                .await
            {
                Ok(()) => return Ok(()),
                Err(Error::Timeout) => {}
                Err(error) => return Err(error),
            }
        }
        Err(Error::Timeout)
    }

    async fn take_driver_own(&mut self) -> Result<(), Error> {
        for _ in 0..OWN_RETRIES {
            self.backend.request_driver_own()?;
            match self
                .wait(OWN_POLL_MS, |backend| {
                    backend.driver_owned().map(|owned| owned.then_some(()))
                })
                .await
            {
                Ok(()) => return Ok(()),
                Err(Error::Timeout) => {}
                Err(error) => return Err(error),
            }
        }
        Err(Error::Timeout)
    }

    async fn resume_inner(&mut self, info: RadioInfo) -> Result<(), Error> {
        self.stage(Stage::Resume);
        self.backend.restore_bus()?;
        self.take_driver_own().await?;
        if self.backend.dma_needs_reinit()? {
            // mt792x_wpdma_reset(dev, false): the old rings are retired only
            // after DMA is disabled and proven idle.
            self.backend.quiesce()?;
            self.wait(100, |backend| backend.idle().map(|idle| idle.then_some(())))
                .await?;
            self.backend.reinit_dma()?;
            self.rx_ba.reset_after_quiescence();
            self.tx_ba.reset_after_quiescence();
            self.data_pending.clear();
            self.received_msdu.clear();
            self.rx_fragments.clear();
        } else {
            self.backend.resume_dma()?;
        }
        // Firmware that did not survive the platform transition cannot
        // accept the deep-sleep/HIF commands; the caller resets instead.
        if self.backend.fw_state()? & 3 != 3 {
            return Err(Error::InvalidFirmware);
        }
        self.events.clear();
        // The native radio never enables runtime deep sleep (pm->ds_enable
        // off), so resume restores "KeepFullPwr 1".
        self.notify(
            Command::Ce {
                id: CE_CHIP_CONFIG,
                query: false,
            },
            &deep_sleep_config(false),
        )
        .await?;
        self.exchange(
            Command::Unified { id: UNI_HIF_CTRL },
            &hif_suspend_request(false),
        )
        .await?;
        // mt7921_mcu_regd_update: the firmware's country/CLC limits are
        // reloaded from the same package-selected world tables used at
        // initialization, then the radio LED returns on.
        let responses = info.capabilities.chip_capabilities & 1 != 0;
        for body in self.firmware.world_limits(info.hardware_type, responses)? {
            let command = Command::Ce {
                id: 0x5c,
                query: false,
            };
            if responses {
                self.exchange(command, &body).await?;
            } else {
                self.notify(command, &body).await?;
            }
        }
        self.radio_led(RADIO_ON_LED).await
    }

    /// `mt7921_mcu_radio_led_ctrl`: EXT `ID_RADIO_ON_OFF_CTRL` `{ctrlid, rsv}`.
    /// Extended commands carry `ext_cid_ack`, so the reply is consumed.
    async fn radio_led(&mut self, value: u8) -> Result<(), Error> {
        self.exchange(
            Command::Extended {
                id: EXT_RADIO_ON_OFF_CTRL,
                query: false,
            },
            &[value, 0, 0, 0],
        )
        .await
        .map(|_| ())
    }

    /// Synchronous removal teardown (Linux `mt7921e_unregister_device`:
    /// token put, `mt792x_dma_cleanup`). It cannot await, so the idle proof
    /// is a bounded 100 ms poll; without it the published rings are kept.
    pub(super) fn retire_removed(&mut self) -> bool {
        self.boot_started = None;
        self.backend.close_receive_capture(self.receive_epoch);
        self.rx_ba.fence();
        self.tx_ba.fence();
        self.security = None;
        self.station_permission = None;
        self.station_bss = None;
        self.wmm = None;
        self.wmm_pending = None;
        self.ht20_rx = None;
        self.ht20_profile = None;
        self.vht_profile = None;
        self.he_profile = None;
        self.ap_phy = None;
        self.control_pending.clear();
        self.tx_fragments.clear();
        self.received_msdu.clear();
        self.rx_fragments.clear();
        self.data_pending.clear();
        self.events.clear();
        if matches!(self.state, State::Prepared | State::Stopped) {
            self.state = State::Stopped;
            return true;
        }
        let result = (|| {
            self.backend.check()?;
            self.backend.quiesce()?;
            let start = self.backend.now_ns();
            while !self.backend.idle()? {
                if self.backend.now_ns().saturating_sub(start) >= 100_000_000 {
                    return Err(Error::Timeout);
                }
                core::hint::spin_loop();
            }
            self.backend.release()
        })();
        match result {
            Ok(()) => {
                self.state = State::Stopped;
                true
            }
            Err(error) => {
                self.state = State::Failed {
                    stage: Stage::Shutdown,
                    error,
                };
                false
            }
        }
    }

    /// Resume a suspended radio. A failed low-power exit falls back to the
    /// verified WFSYS reset and fresh firmware boot, requiring the same
    /// radio identity. The station is always idle afterwards.
    pub(super) async fn resume(&mut self, expected_mac: [u8; 6]) -> Result<RadioInfo, Error> {
        if expected_mac == [0; 6] || expected_mac[0] & 1 != 0 {
            return Err(Error::Bounds);
        }
        let State::Suspended(info) = self.state else {
            return Err(Error::Busy);
        };
        if info.capabilities.mac != expected_mac {
            return Err(Error::InvalidIdentity);
        }
        self.boot_started = Some(self.backend.now_ns());
        let result = self.resume_inner(info).await;
        self.boot_started = None;
        match result {
            Ok(()) => {
                self.state = State::RadioReady(info);
                Ok(info)
            }
            Err(Error::Authority | Error::DeviceGone) => {
                let error = result.unwrap_err();
                self.state = State::Failed {
                    stage: Stage::Resume,
                    error,
                };
                Err(error)
            }
            Err(_) => self.recover(expected_mac).await,
        }
    }
}

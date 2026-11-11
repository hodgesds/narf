// SPDX-License-Identifier: GPL-2.0-or-later
//! Fresh firmware and packet rings after verified physical retirement.
use super::*;
impl
    recovery::Rebuild<
        super::super::firmware_transport::PacketIo<super::super::firmware_native::PciIo>,
        super::super::prepare_native::Coherent,
    > for NativeEnvironment
{
    async fn power_down(&self) -> Result<(), Error> {
        use super::super::{firmware_transport::Stage, prepare};
        match self.power_state.load(Ordering::Acquire) {
            1 => return Ok(()),
            0 => {}
            3 => self.wow_resume_prologue().await?,
            _ => return Err(Error::State),
        }
        let firmware = self.firmware();
        let io = firmware
            .native()
            .parked_control()
            .map_err(prepare::Error::Access)?;
        io.disable_aspm().map_err(prepare::Error::Access)?;
        self.power_state.store(2, Ordering::Release);
        let ready = firmware.status().stage == Stage::Ready;
        let device = firmware.device_id();
        let rtl8821ae = device == super::super::regs::RTL_DEV_8821AE;
        let rtl8192ee = device == super::super::regs::RTL_DEV_8192EE;
        let rtl8192ce = super::super::rtl8192ce::is_8192ce(device);
        let rtl8723be = device == super::super::regs::RTL_DEV_8723BE;
        let rtl8192de = device == super::super::regs::RTL_DEV_8192DE;
        let disabled = if rtl8821ae {
            super::super::power_runtime::disable_rtl8821ae(&io, ready).await
        } else if rtl8192ee {
            // `rtl92ee_card_disable` → `_rtl92ee_poweroff_adapter`, after the
            // owner's `ee92_quiesce` retirement proof.
            super::super::power_runtime::disable_rtl8192ee(&io, ready).await
        } else if rtl8192ce {
            // `rtl92ce_card_disable`, normally already run by the owner's
            // `ce92_quiesce` (accepted by its `SYS_FUNC_EN + 1` receipt).
            super::super::power_runtime::disable_rtl8192ce(&io).await
        } else if rtl8723be {
            // `rtl8723be_card_disable` → `_rtl8723be_poweroff_adapter`,
            // after the owner's `be8723_quiesce` retirement proof.
            super::super::power_runtime::disable_rtl8723be(&io, ready).await
        } else if rtl8192de {
            // `rtl92de_card_disable`, normally already run by the owner's
            // `de92_quiesce` (accepted by its receipt).
            super::super::power_runtime::disable_rtl8192de(&io).await
        } else {
            super::super::power_runtime::disable(&io, ready).await
        };
        disabled.map_err(prepare::Error::Access)?;
        self.power_state.store(1, Ordering::Release);
        if rtl8821ae || rtl8192ee || rtl8192ce || rtl8723be || rtl8192de {
            // ASPM is not composed for 8821AE/8192EE/8192CE/8723BE/8192DE
            // (`prepare_bus_power`; 8192EE / 8192CE `enable_aspm` is not
            // issued): the probe's ASPM-disabled link state is kept.
            return Ok(());
        }
        // Card-disable proof is complete. Optional idle-link optimization
        // cannot revoke that receipt or grant any packet/DMA ownership.
        let _ = firmware
            .native()
            .idle_aspm(PCIE_ASPM.load(Ordering::Acquire))
            .await;
        Ok(())
    }
    fn wowlan_image(&self) -> Result<Vec<u8>, Error> {
        if self.firmware().device_id() != super::super::regs::RTL_DEV_8821AE {
            return Err(Error::State);
        }
        super::super::firmware_transport::registered_wowlan_image()
            .map_err(|e| Error::Radio(super::super::prepare::Error::Access(e)))
    }
    fn wow_parked(&self, mailbox: super::super::rtl8821ae::h2c::Mailbox) -> Result<(), Error> {
        if self.firmware().device_id() != super::super::regs::RTL_DEV_8821AE
            || self
                .power_state
                .compare_exchange(0, 3, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err(Error::State);
        }
        *self.wow_mailbox.lock() = Some(mailbox);
        Ok(())
    }
    async fn rebuild(
        &self,
        retained: Arc<super::super::prepare_native::Retained>,
        factory: Arc<Factory>,
        channel: u8,
    ) -> Result<(), Error> {
        use super::super::{
            firmware_transport::Owner,
            prepare,
            regs::{
                RTL_DEV_8188EE, RTL_DEV_8192DE, RTL_DEV_8192EE, RTL_DEV_8723BE, RTL_DEV_8821AE,
            },
        };
        // The fresh-generation rebuild is the card-disable/enable flow:
        // 88EE `_rtl88ee_poweroff_adapter` + NIC enable, 8821AE
        // `_rtl8821ae_poweroff_adapter` + `_rtl8821ae_init_mac`'s enable,
        // 8192EE `_rtl92ee_poweroff_adapter` + `_rtl92ee_init_mac`'s enable,
        // 8192CE `rtl92ce_card_disable` + a fresh `rtl92ce_hw_init`,
        // 8723BE `_rtl8723be_poweroff_adapter` + `_rtl8723be_init_mac`'s
        // enable, 8192DE `rtl92de_card_disable` + the `_rtl92de_init_mac`
        // power prefix.
        let device = self.firmware().device_id();
        if !matches!(
            device,
            RTL_DEV_8188EE | RTL_DEV_8821AE | RTL_DEV_8192EE | RTL_DEV_8723BE | RTL_DEV_8192DE
        ) && !super::super::rtl8192ce::is_8192ce(device)
        {
            return Err(Error::State);
        }
        self.power_down().await?;
        let old = self.firmware();
        let io = old
            .native()
            .parked_control()
            .map_err(prepare::Error::Access)?;
        io.disable_aspm().map_err(prepare::Error::Access)?;
        self.power_state.store(2, Ordering::Release);
        let enabled = if device == RTL_DEV_8821AE {
            super::super::power_runtime::enable_rtl8821ae(&io).await
        } else if device == RTL_DEV_8192EE {
            super::super::power_runtime::enable_rtl8192ee(&io).await
        } else if device == RTL_DEV_8723BE {
            super::super::power_runtime::enable_rtl8723be(&io).await
        } else if device == RTL_DEV_8192DE {
            let mode = super::super::rtl8192de::mode_from_prom(
                super::super::rtl8192de::Interface::Pci,
                &factory.logical,
            )
            .ok_or(prepare::Error::State)?;
            let function = old.native().function().ok_or(prepare::Error::State)?;
            super::super::power_runtime::enable_rtl8192de(&io, mode, function).await
        } else if super::super::rtl8192ce::is_8192ce(device) {
            // No separate enable: the fresh owner's firmware run issues the
            // `_rtl92ce_init_mac` power prefix (`power_runtime::
            // disable_rtl8192ce` note); EFUSE identity is read through the
            // EFUSE power switch, as Linux's probe does.
            Ok(())
        } else {
            super::super::power_runtime::enable(&io).await
        };
        enabled.map_err(prepare::Error::Access)?;
        self.power_state.store(0, Ordering::Release);
        io.verify_factory(&factory)
            .map_err(prepare::Error::Access)?;
        let firmware = Arc::new(Owner::new(io, device));
        *self.firmware.lock() = firmware.clone();
        super::super::prepare_native::initialize_registered_on_channel(
            firmware.clone(),
            retained,
            factory,
            channel,
        )
        .await?;
        firmware.native().arm_msi();
        Ok(())
    }
}
impl NativeEnvironment {
    /// `_rtl8821ae_wowlan_initialize_adapter` up to its disable commands,
    /// over the parked (bus-mastering-off) control window: record
    /// `_rtl8821ae_get_wakeup_reason`, then `set_fw_wowlan_mode(false)` and
    /// `set_fw_remote_wake_ctrl_cmd(0)` continuing the armed firmware's H2C
    /// boxes. The PCIe DMA-hang patch, TRX descriptor addresses and RX DMA
    /// release that follow in Linux serve its warm `simple_initialize`
    /// path; here the caller continues with the cold card-disable/enable
    /// rebuild (fresh rings), so they are not issued. `REG_FTISR` is read
    /// by Linux for a debug print only. The armed state is consumed even on
    /// error (the cold disable then resets the 8051 regardless).
    async fn wow_resume_prologue(&self) -> Result<(), Error> {
        use super::super::{firmware_transport::Io as _, prepare, rtl8821ae::wow};
        let mut mailbox = self.wow_mailbox.lock().take().unwrap_or_default();
        self.power_state.store(0, Ordering::Release);
        let io = self
            .firmware()
            .native()
            .parked_control()
            .map_err(prepare::Error::Access)?;
        let reason = wow::wake_reason(
            io.read8(wow::REG_MCUTST_WOWLAN)
                .map_err(prepare::Error::Access)?,
        );
        if let Some(device) = self.device.lock().upgrade() {
            *device.lifecycle.wakeup.lock() = Some(reason);
        }
        let disabled = async {
            mailbox
                .fill(&io, wow::H2C_WO_WLAN, &wow::wowlan_mode(false))
                .await?;
            mailbox
                .fill(
                    &io,
                    wow::H2C_REMOTE_WAKE_CTRL,
                    &wow::remote_wake_ctrl(false),
                )
                .await
        }
        .await;
        // A firmware that never takes the disable commands is still reset
        // by the cold card-disable that follows.
        let _ = disabled;
        Ok(())
    }
}
impl Native {
    pub(in crate::rtlwifi) fn native_firmware(
        &self,
    ) -> Arc<super::super::firmware_transport::Owner<super::super::firmware_native::PciIo>> {
        self.environment.firmware()
    }
    pub(in crate::rtlwifi) async fn provision(&self) -> Result<(), super::super::prepare::Error> {
        let _control = self.lifecycle.control.lock().await;
        if self.removed.load(Ordering::Acquire)
            || self.lifecycle.rebuilding.load(Ordering::Acquire)
            || self.lifecycle.suspended.load(Ordering::Acquire)
            || self.admission.closed.load(Ordering::Acquire)
        {
            return Err(super::super::prepare::Error::State);
        }
        super::super::prepare_native::initialize_registered_on_channel(
            self.environment.firmware(),
            self.prepared.clone(),
            self.factory.clone(),
            self.lifecycle.channel.load(Ordering::Acquire),
        )
        .await
    }
}

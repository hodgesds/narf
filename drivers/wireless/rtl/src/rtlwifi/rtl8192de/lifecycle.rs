// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE software-variable lifecycle (`rtl92d_init_sw_vars`,
//! `rtl92d_deinit_sw_vars`, `rtl92d_init_aspm_vars`).
//!
//! Exact Linux `rtl8192de/sw.c` values (driver state, no register
//! writes — the register effects live in [`super::mac`],
//! [`super::station`] and [`super::txpower`]):
//!
//! - DM: initial-gain enabled, `dm_flag` 0, frame bursting on,
//!   thermal 0, `useramask` true.
//! - The default channel is 36 on 5 GHz, 1 otherwise; non-single
//!   modes disable 8K A-MSDU and cap the RX buffer at 4096
//!   ([`super::sw_consequences`]).
//! - `transmit_config` / `receive_config` / `irq_mask` are
//!   [`super::mac::TCR`] / [`super::mac::RCR`] /
//!   [`super::mac::IRQ_MASK`].
//! - Power save: `reg_fwctrl_lps` 3, `reg_max_lps_awakeintvl` 5,
//!   `fwctrl_psmode` DTIM (from `reg_fwctrl_lps` 3; 1 ⇒ MIN, 2 ⇒ MAX).
//! - Early mode off; 8 `skb_waitq` queues; the firmware buffer is
//!   `0x8000` bytes (`max_fw_size`).
//! - ASPM: `const_pci_aspm` 3, device setting `0x03`, host setting
//!   `0x02`, `const_hwsw_rfoff_d3` 0, `const_support_pciaspm` from the
//!   module parameter.
//! - `rtl92d_deinit_sw_vars` frees the firmware buffer and purges the
//!   8 wait queues.
//!
//! The firmware request itself (`request_firmware_nowait`) belongs to
//! the firmware lane ([`super::fw`]); the module parameters are
//! [`ModParams`].

use super::mac::{IRQ_MASK, RCR, TCR};
use super::{Band, MacPhyMode};

/// `rtl92de_mod_params` (`rtl8192de/sw.c`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModParams {
    pub sw_crypto: bool,
    pub inactiveps: bool,
    pub swctrl_lps: bool,
    pub fwctrl_lps: bool,
    pub aspm_support: u8,
}

impl Default for ModParams {
    fn default() -> Self {
        Self {
            sw_crypto: false,
            inactiveps: true,
            swctrl_lps: true,
            fwctrl_lps: false,
            aspm_support: 1,
        }
    }
}

/// `FW_PS_*_MODE` (`wifi.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FwPsMode {
    Min,
    Max,
    Dtim,
}

/// `fwctrl_psmode` from `reg_fwctrl_lps` (1 ⇒ MIN, 2 ⇒ MAX, 3 ⇒ DTIM;
/// anything else leaves the mode unset).
pub fn fw_ps_mode(reg_fwctrl_lps: u8) -> Option<FwPsMode> {
    match reg_fwctrl_lps {
        1 => Some(FwPsMode::Min),
        2 => Some(FwPsMode::Max),
        3 => Some(FwPsMode::Dtim),
        _ => None,
    }
}

/// `rtl92d_init_aspm_vars` (`rtl8192de/sw.c`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AspmVars {
    pub const_pci_aspm: u8,
    pub const_devicepci_aspm_setting: u8,
    pub const_hostpci_aspm_setting: u8,
    pub const_hwsw_rfoff_d3: u8,
    pub const_support_pciaspm: u8,
}

impl AspmVars {
    pub fn new(aspm_support: u8) -> Self {
        Self {
            const_pci_aspm: 3,
            const_devicepci_aspm_setting: 0x03,
            const_hostpci_aspm_setting: 0x02,
            const_hwsw_rfoff_d3: 0,
            const_support_pciaspm: aspm_support,
        }
    }

    /// `support_backdoor` from `const_support_pciaspm` (`pci.c`):
    /// only the explicit ASPM-support setting (1) enables the
    /// back door (and ASPM); 0 refuses ASPM outright and 2 leaves
    /// it to the chipset setting (Intel bridges only).
    pub fn support_backdoor(&self) -> bool {
        self.const_support_pciaspm == 1
    }
}

/// The `rtl92d_init_sw_vars` state for one function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwVars {
    pub dm_initialgain_enable: bool,
    pub dm_flag: u8,
    pub disable_framebursting: bool,
    pub thermalvalue: u8,
    pub useramask: bool,
    pub current_channel: u8,
    pub disable_amsdu_8k: bool,
    pub rxbuffersize: Option<u32>,
    pub transmit_config: u32,
    pub receive_config: u32,
    pub irq_mask: (u32, u32),
    pub inactiveps: bool,
    pub swctrl_lps: bool,
    pub fwctrl_lps: bool,
    pub reg_fwctrl_lps: u8,
    pub reg_max_lps_awakeintvl: u8,
    pub fwctrl_psmode: Option<FwPsMode>,
    pub earlymode_enable: bool,
    /// `max_fw_size` / the allocated firmware buffer size (`0x8000`).
    pub max_fw_size: u32,
    pub firmware_allocated: bool,
    /// The 8 `skb_waitq` depths.
    pub waitq_depths: [u8; 8],
    pub aspm: AspmVars,
}

impl SwVars {
    /// `rtl92d_init_sw_vars` for `band` / `mode` / `params` (the
    /// firmware request itself is the firmware lane's).
    pub fn new(band: Band, mode: MacPhyMode, params: ModParams) -> Self {
        let cons = super::sw_consequences(mode, band);
        Self {
            dm_initialgain_enable: true,
            dm_flag: 0,
            disable_framebursting: false,
            thermalvalue: 0,
            useramask: true,
            current_channel: cons.default_channel,
            disable_amsdu_8k: cons.disable_amsdu_8k,
            rxbuffersize: cons.rxbuffersize,
            transmit_config: TCR,
            receive_config: RCR,
            irq_mask: IRQ_MASK,
            inactiveps: params.inactiveps,
            swctrl_lps: params.swctrl_lps,
            fwctrl_lps: params.fwctrl_lps,
            reg_fwctrl_lps: 3,
            reg_max_lps_awakeintvl: 5,
            fwctrl_psmode: fw_ps_mode(3),
            earlymode_enable: false,
            max_fw_size: 0x8000,
            firmware_allocated: true,
            waitq_depths: [0; 8],
            aspm: AspmVars::new(params.aspm_support),
        }
    }

    /// `rtl92d_deinit_sw_vars`: free the firmware buffer and purge the
    /// 8 wait queues.
    pub fn deinit(&mut self) {
        self.firmware_allocated = false;
        self.waitq_depths = [0; 8];
    }
}

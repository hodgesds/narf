// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained RTL8852C (MAC_0/PHY_0, non-DBCC) radio composition after the C
//! BB/RF tables: the C part of phy.c `rtw89_phy_dm_init` and the first
//! channel, mirroring the B `radio_full` owner.
//!
//! Order (Linux core.c `rtw89_core_start` -> phy.c `rtw89_phy_dm_init`,
//! then core.c `__rtw89_set_channel` and `rtw89_chip_rfk_channel`):
//! `rtw8852c_bb_sethw` (`radio_init::controls_c`), `rtw89_phy_init_rf_nctl`
//! (`radio_init::nctl_c`; `rfk_hw_init` and `rfe_gpio` are NULL for C),
//! `rtw8852c_rfk_init` (`rfk::c::Init`), `rtw8852c_set_txpwr_ctrl`
//! (`rtw8852c_set_txpwr_ref(0)`), `rtw8852c_power_trim` (thermal + PA bias
//! trim), `rtw8852c_bb_cfg_txrx_path`, then `rfk::c_channel::Channel::
//! set_channel` (incl. `rtw8852c_set_txpwr` from `radio_power_c::Plan`) and
//! `rtw8852c_rfk_channel`, which yields the `RF_GET_MCCCH` V0 body the
//! native caller sends. The phy.c DM sub-inits between `bb_sethw` and NCTL
//! (PHYSTS/DIG/CFO/EDCCA) run inside [`Radio::prepare_controls`] through
//! `phy_operating::Operating::prepare_c`.
use super::{
    channel_c, factory_c,
    operating_channel_c::{Band, Profile},
    power,
    radio_gain::Gain,
    radio_init,
    radio_power::initial_reference,
    radio_power_c,
    radio_table::Pair,
    rfk::{
        self,
        c::Init,
        c_channel::{Channel, State as ChannelState},
        c_tssi::Tracking,
        Error, Interface,
    },
};
use alloc::vec::Vec;

const PHY: u32 = 0x10000;
/// RR_TM2 / RR_TM2_OFF, RR_BIASA / RR_BIASA_TXG / RR_BIASA_TXA (reg.h).
const RR_TM2: (u32, u32) = (0x43, 0xf_0000);
const RR_BIASA: u32 = 0x60;
const RR_BIASA_TXG: u32 = 0xf000;
const RR_BIASA_TXA: u32 = 0xf_0000;

type Field = (u32, u32, u32);

/// `rtw8852c_bb_cfg_txrx_path` for non-DBCC PHY_0 with no user
/// `antenna_rx` (`RF_PATH_AB`): `rtw8852c_bb_cfg_rx_path(RF_PATH_AB)` —
/// R_CHBW_MOD ANT_RX_SEG0, R_FC0_BW 1RCCA SEG0/SEG1, HT/VHT/HE/HE-TB NSS
/// limits, `rtw8852c_ctrl_btg_bt_rx(band == 2G)`, TXPW RSTB 1 then 3 per
/// path, `B_RXHE_USER_MAX` 8 — then the `rx_nss` NSS limits (`hal.rx_nss`
/// from the firmware PHY capability, mac.c `rtw89_mac_setup_phycap_part0`).
/// `band` is the CHANCTX_0 band at dm_init (chan.c
/// `rtw89_config_default_chandef`: 2.4GHz channel 1 on first start).
pub(super) fn txrx_path_fields(band: Band, rx_nss: u8) -> Option<Vec<Field>> {
    if !matches!(rx_nss, 1 | 2) {
        return None;
    }
    let mut out = alloc::vec![
        (PHY + 0x4978, 0xf, 3),
        (PHY + 0x4974, 0x3_c000, 3),
        (PHY + 0x4974, 0x3c_0000, 3),
        (PHY + 0x0d18, 0x300, 1),
        (PHY + 0x0d18, 0x60_0000, 1),
        (PHY + 0x0d80, 0x1_c000, 1),
        (PHY + 0x0d80, 0x380_0000, 1),
    ];
    channel_c::btg_bt_rx(band == Band::Ghz2, &mut out);
    for reg in [0x58dc, 0x78dc] {
        out.push((PHY + reg, 0xc000_0000, 1));
        out.push((PHY + reg, 0xc000_0000, 3));
    }
    out.push((PHY + 0x0d80, 0x3fc0, 8));
    let nss = u32::from(rx_nss == 2);
    out.push((PHY + 0x0d18, 0x300, nss));
    out.push((PHY + 0x0d18, 0x60_0000, nss));
    out.push((PHY + 0x0d80, 0x1_c000, nss));
    out.push((PHY + 0x0d80, 0x380_0000, nss));
    Some(out)
}

/// `rtw8852c_power_trim`: `rtw8852c_thermal_trim` (RR_TM2 OFF per path,
/// only with programmed PHY-cap thermal trim) then `rtw8852c_pa_bias_trim`
/// (RR_BIASA TXG/TXA per path, only with programmed PA bias trim), as
/// (path, RF address, mask, value).
pub(super) fn power_trim_writes(calibration: &factory_c::Calibration) -> Vec<(u8, u32, u32, u32)> {
    let mut out = Vec::new();
    for path in 0..2u8 {
        if let Some(value) = calibration.thermal_setting(usize::from(path)) {
            out.push((path, RR_TM2.0, RR_TM2.1, u32::from(value)));
        }
    }
    for path in 0..2u8 {
        if let Some((g, a)) = calibration.pa_bias_setting(usize::from(path)) {
            out.push((path, RR_BIASA, RR_BIASA_TXG, u32::from(g)));
            out.push((path, RR_BIASA, RR_BIASA_TXA, u32::from(a)));
        }
    }
    out
}

fn apply(io: &mut impl Interface, address: u32, mask: u32, value: u32) -> Result<(), Error> {
    io.admit()?;
    let old = io.read32(address)?;
    if old == u32::MAX {
        return Err(power::Error::Gone.into());
    }
    let new = (old & !mask) | ((value << mask.trailing_zeros()) & mask);
    io.admit()?;
    io.write32(address, new)?;
    Ok(())
}

fn verify(io: &mut impl Interface, fields: &[Field]) -> Result<(), Error> {
    // Fold overlapping writes: the last write of each bit is the final value.
    let mut expected: Vec<(u32, u32, u32)> = Vec::new();
    for &(address, mask, value) in fields {
        let bits = (value << mask.trailing_zeros()) & mask;
        match expected.iter_mut().find(|e| e.0 == address) {
            Some(e) => {
                e.1 |= mask;
                e.2 = (e.2 & !mask) | bits;
            }
            None => expected.push((address, mask, bits)),
        }
    }
    for (address, mask, bits) in expected {
        io.admit()?;
        let actual = io.read32(address)?;
        if actual == u32::MAX || actual & mask != bits {
            return Err(power::Error::Access.into());
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Preparing,
    Ready,
}

/// Inputs bound by the native caller to the actual C factory, firmware and
/// container. `power` must be built for the initial channel.
pub(super) struct Inputs<'a> {
    pub gain: &'a Gain,
    pub calibration: &'a factory_c::Calibration,
    pub power: &'a radio_power_c::Plan,
    pub tracking: &'a Tracking,
    /// `hal.cv` (CHIP_CAV = 0).
    pub cut: u8,
    /// `hal.rx_nss` (1 or 2).
    pub rx_nss: u8,
}

#[derive(Default)]
pub(super) struct Radio {
    state: State,
    offset_base: Option<[i8; 2]>,
    init: Init,
    channel: Channel,
    epoch: u32,
}

fn radio_error(e: radio_init::Error) -> Error {
    match e {
        radio_init::Error::Register(e) => Error::Register(e),
        radio_init::Error::Terminal => Error::Terminal,
        _ => Error::Table,
    }
}

impl Radio {
    pub fn state(&self) -> State {
        self.state
    }
    /// The calibrated channel, only while Ready.
    pub fn channel(&self) -> Option<Profile> {
        (self.state == State::Ready)
            .then(|| self.channel.calibrated())
            .flatten()
    }
    pub fn epoch(&self) -> u32 {
        self.epoch
    }
    /// `efuse_gain.offset_base[PHY_0/PHY_1]` read by `controls_c`.
    pub fn offset_base(&self) -> Option<[i8; 2]> {
        self.offset_base
    }
    pub fn init(&self) -> &Init {
        &self.init
    }
    pub fn rfk(&self) -> &Channel {
        &self.channel
    }

    /// `rtw8852c_bb_sethw` (`radio_init::controls_c`), the phy.c DM
    /// sub-inits (`phy_operating::Operating::prepare_c`) and
    /// `rtw89_phy_init_rf_nctl` (`radio_init::nctl_c` with the selected
    /// firmware NCTL table), before any RFK admission (as B's
    /// `prepare_basic_rfk` runs `controls` and `nctl` before the RFK owner).
    ///
    /// # Safety
    /// Actual RTL8852C PHY_0 after completed C `radio_init::Init` tables on
    /// the same retained owner, CMAC TX and ordinary DMA closed, exclusive
    /// radio/reset/PM ownership. Failure leaves the radio non-Ready and the
    /// enclosing native owner terminalizes it.
    pub async unsafe fn prepare_controls(
        &mut self,
        io: &mut impl super::phy_operating::Interface,
        operating: &mut super::phy_operating::Operating,
        identity: super::factory::Identity,
        nctl: &[Pair],
    ) -> Result<(), Error> {
        if self.state != State::New || self.offset_base.is_some() {
            return Err(Error::Terminal);
        }
        self.state = State::Preparing;
        let bases = radio_init::controls_c(io).map_err(radio_error)?;
        self.offset_base = Some(bases);
        // SAFETY: caller contract; directly after the C bb_sethw above.
        unsafe { operating.prepare_c(io, identity) }.await?;
        radio_init::nctl_c(io, nctl).await.map_err(radio_error)?;
        self.state = State::New;
        Ok(())
    }

    /// The rest of dm_init and the first channel (module docs), after
    /// [`Self::prepare_controls`]. Returns the `rtw89_fw_h2c_rf_ntfy_mcc` V0
    /// body for the caller to send as H2C category 2 / class 0x0a /
    /// function 2 (`RF_GET_MCCCH`).
    ///
    /// # Safety
    /// Same owner directly after [`Self::prepare_controls`]; Interface
    /// admission is checked before every access. Failure or cancellation
    /// leaves the radio non-Ready and the enclosing native owner
    /// terminalizes it.
    pub async unsafe fn prepare(
        &mut self,
        io: &mut impl Interface,
        input: Inputs<'_>,
    ) -> Result<[u8; 24], Error> {
        let bases = self.offset_base.ok_or(Error::Terminal)?;
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        let txrx = txrx_path_fields(Band::Ghz2, input.rx_nss).ok_or(Error::Policy)?;
        let profile = input.power.channel();
        self.state = State::Preparing;
        io.admit()?;
        // SAFETY: caller contract; C tables, bb_sethw and NCTL completed.
        unsafe { self.init.prepare(io) }.await?;
        // `rtw8852c_set_txpwr_ctrl` = `rtw8852c_set_txpwr_ref(PHY_0, 0)`:
        // the same R_AX_PWR_RATE_CTRL / 0x5804.. words as B.
        // SAFETY: same owner; reference control only.
        unsafe { initial_reference(io) }?;
        for (path, address, mask, value) in power_trim_writes(input.calibration) {
            io.admit()?;
            io.rf_write(path, address, mask, value).await?;
        }
        for &(address, mask, value) in &txrx {
            apply(io, address, mask, value)?;
        }
        verify(io, &txrx)?;
        let inputs = channel_c::Inputs {
            gain: input.gain,
            calibration: input.calibration,
            offset_base: bases[0],
        };
        // SAFETY: caller contract; dm_init completed on this owner.
        unsafe {
            self.channel
                .set_channel(io, profile, &inputs, input.power, input.tracking, input.cut)
        }
        .await?;
        // SAFETY: directly after set_channel on the same owner.
        let mcc = unsafe {
            self.channel
                .rfk_channel(io, input.calibration, input.tracking, input.cut)
        }
        .await?;
        if self.channel.state() != ChannelState::Calibrated {
            return Err(Error::Terminal);
        }
        self.epoch = self.epoch.wrapping_add(1);
        self.state = State::Ready;
        Ok(mcc)
    }

    /// core.c `rtw89_set_channel` + `rtw89_chip_rfk_channel` on a Ready
    /// radio: `set_channel` (band change runs coex switch-band and the
    /// TSSI scan) then `rtw8852c_rfk_channel`. Returns the MCC V0 body.
    ///
    /// # Safety
    /// Same owner as [`Self::prepare`] on a Ready radio; the caller has
    /// drained and closed ordinary TX and every autonomous response.
    pub async unsafe fn retune(
        &mut self,
        io: &mut impl Interface,
        input: Inputs<'_>,
    ) -> Result<[u8; 24], Error> {
        if self.state != State::Ready {
            return Err(Error::Terminal);
        }
        let profile = input.power.channel();
        let bases = self.offset_base.ok_or(Error::Terminal)?;
        self.state = State::Preparing;
        let inputs = channel_c::Inputs {
            gain: input.gain,
            calibration: input.calibration,
            offset_base: bases[0],
        };
        // SAFETY: caller contract.
        unsafe {
            self.channel
                .set_channel(io, profile, &inputs, input.power, input.tracking, input.cut)
        }
        .await?;
        // SAFETY: directly after set_channel.
        let mcc = unsafe {
            self.channel
                .rfk_channel(io, input.calibration, input.tracking, input.cut)
        }
        .await?;
        self.epoch = self.epoch.wrapping_add(1);
        self.state = State::Ready;
        Ok(mcc)
    }
}

/// Map an RFK error to the native register error.
pub(super) fn error(e: Error) -> power::Error {
    match e {
        rfk::Error::Register(e) => e,
        rfk::Error::Terminal => power::Error::Terminal,
        rfk::Error::Policy => power::Error::Access,
        rfk::Error::Table => power::Error::Unsupported,
        // The firmware reported a failed RFK step; the radio is in an
        // unknown calibration state, so the error is terminal.
        rfk::Error::Report => power::Error::Terminal,
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "radio_c/tests.rs"]
mod tests;

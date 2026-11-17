// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 2009-2012 Realtek Corporation.
//! Retained RTL8723AE cold MAC/BB/RF setup, before IQK and TX-power admission.
//!
//! The caller runs `prepare_mac` after ePHY setup and before firmware
//! download, then `download_and_configure` downloads before its post-table
//! steps. LLT/RQPN/MAC writes are never replayed after the 8051 starts.
//! No ring base or CR gate is written here.
//! This is a cold preparation result, never a station/TX permission:
//! coexistence, IQK, calibrated TX power and shared packet/station
//! composition are still required before the driver can transmit.
use super::{mac, phy, version::Version};
use crate::rtlwifi::{firmware_transport::Io, prepare::Error};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    New,
    MacPrepared,
    TablesReady,
    Failed,
}

#[derive(Debug)]
pub struct Tables {
    pub bb: phy::Report,
    pub chnlval: [u32; 2],
    pub receive_config: u32,
}

/// Records terminal ownership before the first register operation.
/// Failure or cancellation cannot retry a partially programmed device.
#[derive(Debug)]
pub struct Owner {
    phase: Phase,
    tables: Option<Tables>,
}

impl Default for Owner {
    fn default() -> Self {
        Self::new()
    }
}

impl Owner {
    pub const fn new() -> Self {
        Self {
            phase: Phase::New,
            tables: None,
        }
    }
    pub const fn phase(&self) -> Phase {
        self.phase
    }
    pub fn tables(&self) -> Option<&Tables> {
        self.tables.as_ref()
    }

    /// `ephy_retries` is the successful `power::post_flow` loop count
    /// (1..99), retained by the caller across firmware download so the
    /// source's shared APSD retry counter is preserved.
    pub async fn prepare_mac(
        &mut self,
        io: &impl Io,
        ephy_retries: u16,
        mac_func_enabled: bool,
    ) -> Result<(), Error> {
        if self.phase != Phase::New {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        if !(1..100).contains(&ephy_retries) {
            return Err(Error::State);
        }
        if !mac_func_enabled {
            super::llt::init(io)?;
        }
        mac::init_mac(io, ephy_retries).await?;
        self.phase = Phase::MacPrepared;
        Ok(())
    }

    /// `rtl8723_download_fw`, then the MAC/BB/RF table/default portion of
    /// `rtl8723e_hw_init`. The state is terminal before the firmware await,
    /// including when firmware starts but a later table write fails.
    pub async fn download_and_configure(
        &mut self,
        io: &impl Io,
        version: Version,
        payload: &[u8],
    ) -> Result<(), Error> {
        if self.phase != Phase::MacPrepared {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        super::fw::download(io, payload).await?;
        phy::mac_config(io)?;
        let receive_config = mac::trim_receive_config(io)?;
        let bb = phy::bb_config(io).await?;
        phy::rf_config(io).await?;
        phy::umc_fixups(io, version).await?;
        let chnlval = phy::read_chnlval(io).await?;
        phy::enable_modulation(io)?;
        mac::hw_configure(io)?;
        io.write32(0x0670, (1 << 31) | (1 << 30))?; // CAM clear
                                                    // The firmware-only owner does not retain the factory adapter.
                                                    // Factory MAC, coexistence, IQK and calibrated power are deferred
                                                    // to the future retained radio/station owner; MAC/DMA stays closed.
        io.write8(mac::REG_SECCFG, 0)?;
        self.tables = Some(Tables {
            bb,
            chnlval,
            receive_config,
        });
        self.phase = Phase::TablesReady;
        Ok(())
    }
}

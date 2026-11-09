// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE host-to-firmware commands (`rtl92d_fill_h2c_cmd`).
//!
//! - [`Mailbox::fill`] — `rtl92d_fill_h2c_cmd`
//!   (`rtl8192d/fw_common.c`): refused while the radio is off
//!   (`rfpwr_state == ERFOFF` or `inactive_pwrstate == ERFOFF`);
//!   one write attempt with `_rtl92d_check_fw_read_last_h2c`
//!   (`REG_HMETFR` bit `boxnum` clear) with up to 99 re-checks 10 us
//!   apart, each followed by Linux's `0x1BF` read; byte-wise box
//!   writes (1–3 bytes: BIT(7) of the id clear; 4–5 bytes: BIT(7)
//!   set, the first two bytes into `REG_HMEBOX_EXT_n` first);
//!   `last_hmeboxnum` rotation. Unlike Linux (which logs and returns),
//!   a box the firmware never drained or a length outside 1..=5
//!   poisons the mailbox with [`Error::CommandTimeout`] /
//!   [`Error::Descriptor`]. The `h2c_setinprogress` spinlock is not
//!   modelled: the mailbox is owned by one caller, which serializes
//!   fills.
//! - [`joinbss`] — `rtl92d_set_fw_joinbss_report_cmd`
//!   (`H2C_JOINBSSRPT`, one byte: `RT_MEDIA_CONNECT` /
//!   `RT_MEDIA_DISCONNECT`).
//!
//! Not this step: the H2C rate-mask send
//! (`rtl92d_update_hal_rate_mask`, multi-station rate-id / MAC-id) and
//! the power-mode command (`rtl92d_set_fw_pwrmode_cmd`, LPS) — later
//! steps. The reserved-page packet (`rtl92d_set_fw_rsvdpagepkt`) lives
//! in [`super::rsvd_page`].

use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

pub const REG_HMEBOX_EXT_0: u16 = 0x0088;
pub const REG_MCUTST_1: u16 = 0x01c0;
pub const REG_HMETFR: u16 = 0x01cc;
pub const REG_HMEBOX_0: u16 = 0x01d0;

/// `enum rtl_h2c_cmd` (`wifi.h`).
pub const H2C_JOINBSSRPT: u8 = 2;

/// `H2C_RSVDPAGE` (`wifi.h` `enum rtl8192c_h2c_cmd`).
pub const H2C_RSVDPAGE: u8 = 3;

/// `RT_MEDIA_CONNECT` / `RT_MEDIA_DISCONNECT`.
pub const MEDIA_CONNECT: u8 = 1;
pub const MEDIA_DISCONNECT: u8 = 0;

/// The H2C mailbox state (`rtlhal->last_hmeboxnum`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mailbox {
    pub last_hmeboxnum: u8,
}

impl Mailbox {
    pub fn new() -> Self {
        Self { last_hmeboxnum: 0 }
    }

    fn fw_read_last(&self, io: &impl Io) -> Result<bool, Error> {
        let v = io.read8(REG_HMETFR)?;
        Ok((v >> self.last_hmeboxnum) & 1 == 0)
    }

    /// `rtl92d_fill_h2c_cmd`. `rf_on` is false when `rfpwr_state` or
    /// `inactive_pwrstate` is `ERFOFF`: the command is dropped without
    /// a write, as in Linux.
    pub async fn fill(
        &mut self,
        io: &impl Io,
        element_id: u8,
        cmd: &[u8],
        rf_on: bool,
    ) -> Result<(), Error> {
        if !rf_on {
            return Ok(());
        }
        if !(1..=5).contains(&cmd.len()) || self.last_hmeboxnum > 3 {
            return Err(Error::Descriptor);
        }
        let boxnum = self.last_hmeboxnum;
        let box_reg = REG_HMEBOX_0 + u16::from(boxnum) * 4;
        let box_extreg = REG_HMEBOX_EXT_0 + u16::from(boxnum) * 2;
        let mut wait_h2c_limit = 100u8;
        let mut isfw_read = self.fw_read_last(io)?;
        while !isfw_read {
            wait_h2c_limit = wait_h2c_limit.saturating_sub(1);
            if wait_h2c_limit == 0 {
                return Err(Error::CommandTimeout);
            }
            io.delay_us(10).await;
            isfw_read = self.fw_read_last(io)?;
            let _ = io.read8(0x1bf)?;
        }
        let mut boxcontent = [0u8; 4];
        let mut boxextcontent = [0u8; 2];
        boxcontent[0] = element_id;
        if cmd.len() <= 3 {
            boxcontent[0] &= !(1 << 7);
            boxcontent[1..1 + cmd.len()].copy_from_slice(cmd);
            for (idx, value) in boxcontent.into_iter().enumerate() {
                io.write8(box_reg + idx as u16, value)?;
            }
        } else {
            boxcontent[0] |= 1 << 7;
            boxextcontent.copy_from_slice(&cmd[..2]);
            boxcontent[1..1 + (cmd.len() - 2)].copy_from_slice(&cmd[2..]);
            for (idx, value) in boxextcontent.into_iter().enumerate() {
                io.write8(box_extreg + idx as u16, value)?;
            }
            for (idx, value) in boxcontent.into_iter().enumerate() {
                io.write8(box_reg + idx as u16, value)?;
            }
        }
        self.last_hmeboxnum = boxnum + 1;
        if self.last_hmeboxnum == 4 {
            self.last_hmeboxnum = 0;
        }
        Ok(())
    }
}

impl Default for Mailbox {
    fn default() -> Self {
        Self::new()
    }
}

/// `rtl92d_set_fw_joinbss_report_cmd` (`mstatus` =
/// [`MEDIA_CONNECT`] / [`MEDIA_DISCONNECT`]).
pub async fn joinbss(
    mailbox: &mut Mailbox,
    io: &impl Io,
    mstatus: u8,
    rf_on: bool,
) -> Result<(), Error> {
    mailbox.fill(io, H2C_JOINBSSRPT, &[mstatus], rf_on).await
}

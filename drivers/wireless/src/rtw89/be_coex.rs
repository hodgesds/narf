// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Explicit RTL8922A SCC WLAN-only arbitration for closed calibration.
//! Source rtw8922a_btc_{set_rfe,init_cfg}, BTC_MODE_WL/_action_wl_only,
//! cfg_gnt_v2/cfg_plt_be and NORMAL-selected init/CTRL/slot/TDMA layouts.
//! No BT-disabled/BT-version observation or generic BT-profile engine exists
//! here. Ordinary packets, BT telemetry policy and dual-BT/MLO stay closed.
use super::{power, rfk};
use alloc::{vec, vec::Vec};
#[derive(Clone, Copy, Debug)]
pub(super) struct Protocol {
    init: u8,
    ctrl: u8,
    tdma: u8,
}
impl Protocol {
    pub(super) fn from_version(v: [u8; 4]) -> Option<Self> {
        let code = u32::from_be_bytes(v);
        if v[0..2] != [0, 35] || code < u32::from_be_bytes([0, 35, 8, 0]) {
            return None;
        }
        Some(if code >= u32::from_be_bytes([0, 35, 111, 0]) {
            Self {
                init: 11,
                ctrl: 9,
                tdma: 8,
            }
        } else {
            Self {
                init: 7,
                ctrl: 7,
                tdma: 7,
            }
        })
    }
    fn init(self, rfe: u8, cv: u8, acv: u8, nss: (u8, u8)) -> Result<Vec<u8>, rfk::Error> {
        if rfe == 0 || rfe == 255 {
            return Err(rfk::Error::Policy);
        }
        let dedicated = rfe % 2 == 0 && cv != 0;
        let num = if dedicated { 3 } else { 2 };
        let mut body = vec![0; if self.init == 7 { 27 } else { 43 }];
        let length = (body.len() - 3) as u8;
        body[0..3].copy_from_slice(&[0, self.init, length]);
        if self.init == 7 {
            body[3..11].copy_from_slice(&[6, 1, 1, 0, 0, 0, 0, 0]);
            body[11..19].copy_from_slice(&[
                rfe,
                cv,
                0,
                u8::from(!dedicated),
                u8::from(!dedicated),
                if cv <= 1 { 4 } else { 0 },
                acv,
                0,
            ]);
            body[19..27].copy_from_slice(&[u8::from(dedicated), num, 10, 0, 0, 1, 2, 0]);
        } else {
            body[3..11].copy_from_slice(&[0, 1, 1, 1, 0, 0, 0, 0]);
            body[11..19].copy_from_slice(&[
                rfe,
                if cv <= 1 { 4 } else { 0 },
                cv,
                acv,
                u8::from(!dedicated),
                u8::from(!dedicated),
                0,
                0,
            ]);
            let (tx, rx) = nss;
            if !(1..=2).contains(&tx) || !(1..=2).contains(&rx) {
                return Err(rfk::Error::Policy);
            }
            // Source _btc_get_rf_path_from_ant_num: one NSS selects the
            // actual RFE single_pos RF_PATH_A(0), two selects the source
            // RF_PATH_AB enum value4 (not the unrelated path bitmask3).
            let tx = if tx == 1 { 0 } else { 4 };
            let rx = if rx == 1 { 0 } else { 4 };
            body[19..27].copy_from_slice(&[
                u8::from(dedicated),
                num,
                10,
                0,
                2,
                (tx << 4) | rx,
                1,
                0,
            ]);
            body[27 + if dedicated { 2 } else { 1 }] = 1; // actual source RFE antenna function map
            if !dedicated {
                body[32 + 4] = 1;
            } // ant_xmap[RF_S1][BT_1ST]
        }
        Ok(body)
    }
    fn ctrl(self) -> Vec<u8> {
        let mut body = vec![0; if self.ctrl == 7 { 7 } else { 23 }];
        let length = (body.len() - 3) as u8;
        body[..3].copy_from_slice(&[6, self.ctrl, length]);
        if self.ctrl == 9 {
            body[5] = 1;
        } // explicit WLAN-only control
        body
    }
    fn policy(self) -> Vec<u8> {
        let mut bytes = if self.tdma == 7 {
            vec![0, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0]
        } else {
            vec![0, 12, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        };
        // _append_slot_v7: type, version, stride9, slot0 then LE slot body.
        bytes.extend_from_slice(&[1, 7, 9, 0, 100, 0, 0, 0, 0x55, 0x55, 0x55, 0xe5]);
        bytes
    }
    fn slots(self) -> Vec<u8> {
        let defaults: [(u16, u32, u16); 18] = [
            (100, 0x55555555, 0),
            (5, 0xea5a5a5a, 1),
            (70, 0xea5a5a5a, 1),
            (15, 0xea5a5a5a, 1),
            (15, 0xea5a5a5a, 1),
            (250, 0xe5555555, 0),
            (7, 0xea5a5a5a, 0),
            (5, 0xe5555555, 0),
            (50, 0xe5555555, 0),
            (20, 0xea5a5a5a, 1),
            (500, 0x55555555, 0),
            (5, 0xea5a5a5a, 0),
            (5, 0xffffffff, 1),
            (5, 0xe5555555, 0),
            (5, 0x55555555, 0),
            (250, 0xea5a5a5a, 0),
            (50, 0xffffffff, 1),
            (50, 0xffffdfff, 1),
        ];
        let mut body = vec![1, 7, 18];
        for (duration, table, kind) in defaults {
            body.extend_from_slice(&duration.to_le_bytes());
            body.extend_from_slice(&kind.to_le_bytes());
            body.extend_from_slice(&table.to_le_bytes());
        }
        body
    }
}
pub(super) trait Interface: rfk::Interface {
    async fn coex_command(
        &mut self,
        function: u8,
        body: &[u8],
        done: bool,
    ) -> Result<(), rfk::Error>;
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Busy,
    WlanOnly,
}
#[derive(Default)]
pub(super) struct Owner {
    state: State,
    rfk: bool,
    scoreboard: u32,
}
fn field(io: &mut impl Interface, at: u32, mask: u32, value: u32) -> Result<(), rfk::Error> {
    io.admit()?;
    let old = io.read32(at)?;
    if old == u32::MAX {
        return Err(power::Error::Gone.into());
    }
    io.write32(at, (old & !mask) | (value & mask))?;
    if io.read32(at)? & mask != value & mask {
        return Err(power::Error::Access.into());
    }
    io.admit()
}
// mac_be cfg_gnt_v2 for both source bands: WL SW-HI, BT SW-LO,
// separate WLAN_ACT0 SW-HI; no second BT exists in the 8922A para_ver.
const GNT: u32 = (1 << 4)
    | (1 << 16)
    | (1 << 14)
    | (1 << 8)
    | (1 << 20)
    | (1 << 18)
    | (1 << 2)
    | (1 << 3)
    | (1 << 6)
    | (1 << 7)
    | (1 << 10)
    | (1 << 11)
    | (1 << 12)
    | (1 << 13)
    | (1 << 0)
    | (1 << 1)
    | (1 << 22)
    | (1 << 23);
pub(super) fn enforce(io: &mut impl Interface) -> Result<(), rfk::Error> {
    field(io, 0xe348, u32::MAX, GNT)?;
    // Source cfg_ctrl_path_v2(wl=true) has no I/O. SCC PLT uses MAC0 only.
    io.admit()?;
    io.write16(0x1087c, 0x111)?;
    if io.read16(0x1087c)? != 0x111 {
        return Err(power::Error::Access.into());
    }
    io.admit()
}
async fn scoreboard(io: &mut impl Interface, value: u32) -> Result<(), rfk::Error> {
    io.admit()?;
    let old = io.read32(0xac)?;
    if old == u32::MAX {
        return Err(power::Error::Gone.into());
    }
    // Only the retained source host producer supplies low24 bits. Firmware
    // bits survive, BTGS1_NOTIFY is cleared and TP_MAJOR/toggle are asserted.
    io.write32(0xac, (old & 0x7e000000) | 0x81000000 | value)?;
    io.delay_us(1000).await;
    io.admit()?;
    if io.read32(0xac)? & 0xffffff != value {
        return Err(power::Error::Access.into());
    }
    io.admit()
}
impl Owner {
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn fixture_packet_refusal_metadata() -> Self {
        Self {
            state: State::WlanOnly,
            rfk: false,
            scoreboard: 0x4003,
        }
    }
    pub(super) fn state(&self) -> State {
        self.state
    }
    /// # Safety
    /// Original closed SCC owner and fresh N22W scope for the complete
    /// explicit static WLAN-only program; no independent BT/PTA producer.
    /// No BT profile/version/disabled facts are inferred. Caller retains this
    /// owner and terminalizes error/drop; every operation checks its grant.
    #[allow(clippy::too_many_arguments)]
    pub(super) async unsafe fn prepare(
        &mut self,
        io: &mut impl Interface,
        protocol: Protocol,
        rfe: u8,
        cv: u8,
        acv: u8,
        nss: (u8, u8),
    ) -> Result<(), rfk::Error> {
        if self.state != State::New {
            return Err(rfk::Error::Terminal);
        }
        let init = protocol.init(rfe, cv, acv, nss)?;
        self.state = State::Busy;
        let shared = !(rfe % 2 == 0 && cv != 0);
        for path in 0..2 {
            io.rf_write(path, 0xef, 0xfffff, 1 << 17).await?;
            for (group, value) in [
                (0, 0x5ff),
                (3, 0x5df),
                (2, if shared && path == 1 { 0x55f } else { 0x5ff }),
            ] {
                io.rf_write(path, 0x33, 0xfffff, group).await?;
                io.rf_write(path, 0x3f, 0xfffff, value).await?;
            }
            io.rf_write(path, 0xef, 0xfffff, 0).await?;
        }
        for (at, value) in [
            (0xe324, (1 << 23) | (1 << 22) | (1 << 17) | (1 << 10)),
            (0xe344, 0xf0ffffff),
            (0xe328, 0xda5a5a5a),
            (0xe32c, 0xda5a5a5a),
            (0xe350, 0xf0ffffff),
        ] {
            field(io, at, u32::MAX, value)?;
        }
        self.scoreboard = 0x4003;
        scoreboard(io, self.scoreboard).await?;
        io.coex_command(5, &init, false).await?;
        io.coex_command(5, &protocol.ctrl(), false).await?;
        io.coex_command(1, &protocol.slots(), true).await?;
        field(io, 0x11a2c, (1 << 19) | (0x1ff << 20), 0)?;
        field(io, 0x11a50, 1 << 23, 0)?;
        field(io, 0x11a54, 0x1ff, 0)?;
        enforce(io)?;
        io.coex_command(3, &protocol.policy(), true).await?;
        self.state = State::WlanOnly;
        Ok(())
    }
    pub(super) async fn notify(
        &mut self,
        io: &mut impl Interface,
        rfk: Option<bool>,
    ) -> Result<(), rfk::Error> {
        if self.state != State::WlanOnly {
            return Err(rfk::Error::Terminal);
        }
        self.state = State::Busy;
        if rfk.is_some_and(|start| start == self.rfk) {
            return Err(rfk::Error::Terminal);
        }
        if let Some(start) = rfk {
            self.rfk = start;
            if start {
                self.scoreboard |= 1 << 11;
            } else {
                self.scoreboard &= !(1 << 11);
            }
            scoreboard(io, self.scoreboard).await?;
        }
        enforce(io)?;
        self.state = State::WlanOnly;
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "be_coex_tests.rs"]
mod tests;

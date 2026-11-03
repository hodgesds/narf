// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Exact B initial WLAN-only PTA owner. BT is arbitrated low, not assumed
//! absent. Adaptive simultaneous BT, TDMA scheduling and power saving are out
//! of this one-shot profile. Every transition requires current qualification.
use super::power::{self, Io};
include!("coex_native/recipe.rs");
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Register(power::Error),
    Policy,
    Firmware,
    Profile,
    Terminal,
}
impl From<power::Error> for Error {
    fn from(e: power::Error) -> Self {
        Self::Register(e)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Protocol;
impl Protocol {
    pub fn for_version(v: [u8; 4]) -> Option<Self> {
        // coex.c rtw89_btc_ver_defs: B >=0.29.29, <0.29.122 uses
        // fcxtdma3/fcxslots1/fcxinit0/fcxctrl1. No newer ABI guessing.
        let code = u32::from_be_bytes(v);
        (u32::from_be_bytes([0, 29, 29, 0])..u32::from_be_bytes([0, 29, 122, 0]))
            .contains(&code)
            .then_some(Self)
    }
    pub fn off_policy(self) -> [u8; 26] {
        // Original _append_tdma(v3) and _append_slot_v1, OFF_BT slot0.
        [
            0, 12, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 10, 1, 0, 100, 0, 0x55, 0x55, 0x55, 0xe5,
            0, 0,
        ]
    }
    pub fn init(self, rfe: u8, cut: u8) -> [u8; 14] {
        let dedicated = rfe != 0 && rfe % 2 == 0;
        [
            0,
            12,
            u8::from(dedicated),
            if dedicated { 3 } else { 2 },
            10,
            0,
            rfe,
            cut,
            if dedicated { 0 } else { 2 },
            0,
            6,
            3,
            0,
            0,
        ]
    }
}
/// RTL8851B coex.c `rtw89_btc_ver_defs` rows: 0.29.29 (up to the 0.29.133
/// row) is field-for-field the RTL8852B 0.29.29 row (`fcxtdma` 3,
/// `fcxslots` 1, `fcxinit` 0, `fcxctrl` 1, `drvinfo_ver` 0), so B's
/// [`Protocol`] encodings apply; the shipped `rtw8851b_fw-1.bin` (0.29.41.5)
/// selects it. The 0.29.133 v7 row and anything below 0.29.29 (Linux's
/// default row belongs to another chip) have no NARF ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Protocol51;
impl Protocol51 {
    pub fn for_version(v: [u8; 4]) -> Option<Self> {
        let code = u32::from_be_bytes(v);
        (u32::from_be_bytes([0, 29, 29, 0])..u32::from_be_bytes([0, 29, 133, 0]))
            .contains(&code)
            .then_some(Self)
    }
}
/// RTL8852C coex.c `rtw89_btc_ver_defs` rows: every C row has `fcxinit` 0
/// and `fcxctrl` 1 (B's init/ctrl encodings); 0.27.0..0.27.97 use
/// `fcxtdma` 3 / `fcxslots` 1 (B's policy encoding) and 0.27.97 onward
/// `fcxtdma` 4 / `fcxslots` 2 (`btf_tlv_v7`, `_append_slot_v7`). Linux takes
/// the first row at or below the firmware; NARF stops at the 0.27 series.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ProtocolC {
    Tdma3,
    Tdma4,
}
impl ProtocolC {
    pub fn for_version(v: [u8; 4]) -> Option<Self> {
        let code = u32::from_be_bytes(v);
        let at = |sub| u32::from_be_bytes([0, 27, sub, 0]);
        if (at(0)..at(97)).contains(&code) {
            Some(Self::Tdma3)
        } else if (at(97)..u32::from_be_bytes([0, 28, 0, 0])).contains(&code) {
            Some(Self::Tdma4)
        } else {
            None
        }
    }
    /// Identity byte bound into the C calibration recipe.
    pub fn tag(self) -> u8 {
        match self {
            Self::Tdma3 => 3,
            Self::Tdma4 => 4,
        }
    }
    /// `_fw_set_policy(BTC_CXP_OFF_BT)`: `_append_tdma` + `_append_slot`
    /// with the same OFF TDMA and OFF_BT slot0 (100 TU, 0xe5555555, MIX)
    /// as B. Tdma4 is `btf_tlv_v7{CXPOLICY_TDMA, 4, 8}` + 8 TDMA bytes and
    /// one `btf_tlv_v7{CXPOLICY_SLOT, 2, 9}` with slot id 0 and
    /// `fbtc_slot_v7 {dur, cxtype, cxtbl}`.
    pub fn off_policy(self) -> alloc::vec::Vec<u8> {
        match self {
            Self::Tdma3 => Protocol.off_policy().to_vec(),
            Self::Tdma4 => alloc::vec![
                0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 9, 0, 100, 0, 0, 0, 0x55, 0x55, 0x55, 0xe5,
            ],
        }
    }
    /// `rtw89_fw_h2c_cxdrv_init` (`fcxinit` 0) from `rtw8852c_btc_set_rfe`:
    /// the same field values as B (ant num 2/3 by RFE parity, isolation
    /// 10, `afh_guard_ch` 6, BT0 at BTG when shared, WL-only + init ok).
    pub fn init(self, rfe: u8, cut: u8) -> [u8; 14] {
        Protocol.init(rfe, cut)
    }
}
/// rtw8852c `rtw89_mac_cfg_gnt_v1` value for `_set_ant(BTC_ANT_WONLY)`:
/// both bands GNT_WL SW high, GNT_BT SW low (para_ver 0x1: no WLAN_ACT mux,
/// so `wlan_act_en`/`wlan_act` stay 0), written to `R_AX_GNT_SW_CTRL`.
pub(super) const C_GNT_WONLY: u32 = (1 << 0)
    | (1 << 1)
    | (1 << 2)
    | (1 << 3)
    | (1 << 4)
    | (1 << 6)
    | (1 << 7)
    | (1 << 8)
    | (1 << 10)
    | (1 << 11)
    | (1 << 12)
    | (1 << 13)
    | (1 << 14)
    | (1 << 16)
    | (1 << 18);
pub(super) trait Interface: Io {
    fn admit(&mut self) -> Result<(), Error>;
    async fn rf_write(
        &mut self,
        path: u8,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), Error>;
    /// Exact BTFC_SET function; completion is a matching successful actual
    /// firmware DONE_ACK when requested, not hardware RP consumption.
    async fn command(&mut self, function: u8, bytes: &[u8], done: bool) -> Result<(), Error>;
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Preparing,
    WlanOnly,
}
#[derive(Default)]
pub(super) struct Coex {
    state: State,
}
impl Coex {
    pub fn state(&self) -> State {
        self.state
    }
    /// # Safety
    /// Same retained exact B radio owner, current measured board/channel
    /// envelope, no independent BT/PTA producer, PHY0/SCC and CMAC TX closed.
    pub async unsafe fn prepare(
        &mut self,
        io: &mut impl Interface,
        rfe: u8,
        cut: u8,
        protocol: Protocol,
    ) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        self.state = State::Preparing;
        let mut a = Access(io);
        // rtw89_mac_coex_init: Realtek internal PTA, with source byte widths.
        a.m8(0x40, 0, 0x20)?;
        a.m8(0xda20, 0, 2)?;
        a.m8(0xda35, 0, 1)?;
        a.m8(0xda40, 0, 12)?;
        a.m8(0xda42, 0, 1)?;
        a.m8(0xcc07, 2, 0)?;
        a.m16(0xc340, 0x200, 0x20)?;
        let value = a.lte_read(0x3c).await? & 0x100;
        a.lte_write(0x3c, value).await?;
        a.m8(0x40, 0xc0, 0)?;
        a.m8(0xda4c, 0, 1)?;
        a.m8(0xda6c, 0x3f, 5)?;
        a.m8(0x41, 4, 2)?;
        // __rtw8852bx_btc_init_cfg; real RFE-parity antenna layout.
        a.m32(0xda30, 0, 8)?;
        a.m32(0xda10, 0, 0x100)?;
        a.rf(0, 2, 0).await?;
        a.rf(1, 2, 0).await?;
        let dedicated = rfe != 0 && rfe % 2 == 0;
        for (path, group, value) in [
            (0, 0, if dedicated { 0x5df } else { 0x5ff }),
            (1, 0, if dedicated { 0x5df } else { 0x5ff }),
            (0, 2, 0x5ff),
            (1, 2, if dedicated { 0x5ff } else { 0x55f }),
        ] {
            a.rf(path, 0xef, 0x20000).await?;
            a.rf(path, 0x33, group).await?;
            a.rf(path, 0x3f, value).await?;
            a.rf(path, 0xef, 0).await?;
        }
        a.w32(0xda2c, 0xf0ffffff)?;
        a.m32(0xda40, 0, 0x10004)?;
        scoreboard(a.0, 0x4003).await?;
        a.cmd(5, &protocol.init(rfe, cut), false).await?;
        // Driver control v1: no manual testing, no ignore-BT/freerun flag.
        a.cmd(5, &[6, 4, 0, 0, 0, 0], false).await?;
        // Source default coex power control is 0xffffffff: disable both
        // inherited force-by-rate and BT-grant adjustments. No dBm inferred.
        a.m32(0xd200, 0x3ff, 0)?;
        a.m32(0xd220, 0xffa, 0)?;
        if a.r32(0xd200)? & 0x3ff != 0 || a.r32(0xd220)? & 0xffa != 0 {
            return Err(power::Error::Access.into());
        }
        // Actual _set_ant(WONLY), not an inferred BT-disabled state.
        a.lte_write(0x38, 0x77007700).await?;
        if a.lte_read(0x38).await? != 0x77007700 {
            return Err(power::Error::Access.into());
        }
        a.m8(0x73, 0, 4)?;
        a.w16(0xc67c, 0x111)?;
        if a.r8(0x73)? & 4 == 0 || a.r16(0xc67c)? != 0x111 {
            return Err(power::Error::Access.into());
        }
        // Explicit source OFF policy prevents relying on unknown firmware
        // TDMA defaults. Wait for actual matching successful DONE_ACK.
        a.cmd(3, &protocol.off_policy(), true).await?;
        self.state = State::WlanOnly;
        Ok(())
    }
}
impl Coex {
    /// RTL8852C coex.c `rtw89_btc_ntfy_init` for the same WLAN-only owner:
    /// `rtw8852c_btc_set_rfe`, `rtw8852c_btc_init_cfg`
    /// (`rtw89_mac_coex_init_v1` RTK/inner PTA, `rtw8852c_btc_set_wl_pri`
    /// TX_RESP/BEACON, RR_WLSEL off, `rtw8852c_set_trx_mask` by antenna
    /// type, PTA break table, BT counter enable/reset), `_write_scbd`
    /// (ACTIVE|ON|BTLOG), `_set_init_info` (INIT, CTRL), the default WL TX
    /// power control, then `_action_wl_only`: `_set_ant(WONLY)`
    /// (`rtw89_mac_cfg_gnt_v1`, `rtw89_mac_cfg_ctrl_path_v1(wl)` = no I/O,
    /// `_set_bt_plut` GNT_WL) and `_set_policy(BTC_CXP_OFF_BT)`.
    ///
    /// # Safety
    /// Same retained exact C radio owner, current signed C records, no
    /// independent BT/PTA producer, PHY0/SCC and CMAC TX closed.
    pub async unsafe fn prepare_c(
        &mut self,
        io: &mut impl Interface,
        rfe: u8,
        cut: u8,
        protocol: ProtocolC,
    ) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        self.state = State::Preparing;
        let mut a = Access(io);
        // rtw89_mac_coex_init_v1 (RTW89_MAC_AX_COEX_RTK_MODE, INNER).
        a.m32(0xda00, 0, (1 << 31) | (1 << 16))?;
        a.m32(0xda10, 0, 1)?;
        a.m16(0xc340, 0, 0x20)?;
        a.m16(0xc340, 0x200, 0)?;
        a.m32(0xda00, 3 << 24, 0)?;
        a.m32(0xda04, 0xff, 5)?;
        // rtw8852c_btc_set_wl_pri(TX_RESP), (BEACON): R_BTC_COEX_WL_REQ.
        a.m32(0xda24, 0, 1 << 10)?;
        a.m32(0xda24, 0, 1 << 22)?;
        // RF gnt debug off (RR_WLSEL).
        a.rf(0, 2, 0).await?;
        a.rf(1, 2, 0).await?;
        let dedicated = rfe != 0 && rfe % 2 == 0;
        let masks: &[(u8, u32, u32)] = if dedicated {
            &[(0, 0, 0x5df), (1, 0, 0x5df)]
        } else {
            &[(0, 0, 0x5ff), (1, 0, 0x5ff), (0, 2, 0x5ff)]
        };
        for &(path, group, value) in masks {
            a.rf(path, 0xef, 0x20000).await?;
            a.rf(path, 0x33, group).await?;
            a.rf(path, 0x3f, value).await?;
            a.rf(path, 0xef, 0).await?;
        }
        a.w32(0xda44, 0xf0ffffff)?;
        a.m32(0xda10, 0, 3)?;
        scoreboard(a.0, 0x4003).await?;
        a.cmd(5, &protocol.init(rfe, cut), false).await?;
        a.cmd(5, &[6, 4, 0, 0, 0, 0], false).await?;
        // rtw8852c_btc_set_wl_txpwr_ctrl(0xffffffff) on PHY_0.
        a.m32(0xd200, 0x3ff, 0)?;
        a.m32(0xd220, 0xffa, 0)?;
        if a.r32(0xd200)? & 0x3ff != 0 || a.r32(0xd220)? & 0xffa != 0 {
            return Err(power::Error::Access.into());
        }
        enforce_c(a.0).await?;
        a.cmd(3, &protocol.off_policy(), true).await?;
        self.state = State::WlanOnly;
        Ok(())
    }
}
/// RTL8852C `_set_ant(FC_EXEC, BTC_ANT_WONLY)` with readback (the C
/// counterpart of [`enforce`]).
pub(super) async fn enforce_c(io: &mut impl Interface) -> Result<(), Error> {
    let mut a = Access(io);
    a.w32(0xda48, C_GNT_WONLY)?;
    a.w16(0xc67c, 0x111)?;
    if a.r32(0xda48)? != C_GNT_WONLY || a.r16(0xc67c)? != 0x111 {
        return Err(power::Error::Access.into());
    }
    Ok(())
}
struct Access<'a, I>(&'a mut I);
impl<I: Interface> Access<'_, I> {
    fn r8(&mut self, a: u32) -> Result<u8, Error> {
        self.0.admit()?;
        Ok(self.0.read8(a)?)
    }
    fn r16(&mut self, a: u32) -> Result<u16, Error> {
        self.0.admit()?;
        Ok(self.0.read16(a)?)
    }
    fn r32(&mut self, a: u32) -> Result<u32, Error> {
        self.0.admit()?;
        let v = self.0.read32(a)?;
        if v == u32::MAX {
            return Err(power::Error::Gone.into());
        }
        Ok(v)
    }
    fn w8(&mut self, a: u32, v: u8) -> Result<(), Error> {
        self.0.admit()?;
        Ok(self.0.write8(a, v)?)
    }
    fn w16(&mut self, a: u32, v: u16) -> Result<(), Error> {
        self.0.admit()?;
        Ok(self.0.write16(a, v)?)
    }
    fn w32(&mut self, a: u32, v: u32) -> Result<(), Error> {
        self.0.admit()?;
        Ok(self.0.write32(a, v)?)
    }
    fn m8(&mut self, a: u32, c: u8, s: u8) -> Result<(), Error> {
        let v = self.r8(a)?;
        self.w8(a, (v & !c) | s)
    }
    fn m16(&mut self, a: u32, c: u16, s: u16) -> Result<(), Error> {
        let v = self.r16(a)?;
        self.w16(a, (v & !c) | s)
    }
    fn m32(&mut self, a: u32, c: u32, s: u32) -> Result<(), Error> {
        let v = self.r32(a)?;
        self.w32(a, (v & !c) | s)
    }
    async fn ready(&mut self) -> Result<(), Error> {
        let start = self.0.now_us();
        loop {
            if self.r8(0xdaf3)? & 32 != 0 {
                return Ok(());
            }
            if self.0.now_us().saturating_sub(start) >= 50_000 {
                return Err(power::Error::Timeout.into());
            }
            self.0.admit()?;
            self.0.delay_us(50).await;
            self.0.admit()?;
        }
    }
    async fn lte_read(&mut self, a: u32) -> Result<u32, Error> {
        self.ready().await?;
        self.w32(0xdaf0, 0x800f0000 | a)?;
        self.r32(0xdaf8)
    }
    async fn lte_write(&mut self, a: u32, v: u32) -> Result<(), Error> {
        self.ready().await?;
        self.w32(0xdaf4, v)?;
        self.w32(0xdaf0, 0xc00f0000 | a)
    }
    async fn rf(&mut self, p: u8, a: u32, v: u32) -> Result<(), Error> {
        self.0.admit()?;
        self.0.rf_write(p, a, 0xfffff, v).await
    }
    async fn cmd(&mut self, f: u8, b: &[u8], d: bool) -> Result<(), Error> {
        self.0.admit()?;
        self.0.command(f, b, d).await?;
        self.0.admit()
    }
}
pub(super) async fn scoreboard(io: &mut impl Interface, lower: u32) -> Result<(), Error> {
    let mut a = Access(io);
    let old = a.r32(0xac)?;
    // mac.c::rtw89_mac_cfg_sb: preserve FW-owned high bits and TP notify.
    a.w32(0xac, (old & 0x7e000000) | 0x81000000 | (lower & 0xffffff))?;
    a.0.admit()?;
    a.0.delay_us(1000).await;
    a.0.admit()
}
/// The WL-only source action precedes normal RFK selection in _run_coex.
/// Keep its real fixed grant at every RFK boundary, with actual readback;
/// the already completed OFF TDMA/slot policy has not changed.
pub(super) async fn enforce(io: &mut impl Interface) -> Result<(), Error> {
    let mut a = Access(io);
    a.lte_write(0x38, 0x77007700).await?;
    if a.lte_read(0x38).await? != 0x77007700 {
        return Err(power::Error::Access.into());
    }
    a.m8(0x73, 0, 4)?;
    a.w16(0xc67c, 0x111)?;
    if a.r8(0x73)? & 4 == 0 || a.r16(0xc67c)? != 0x111 {
        return Err(power::Error::Access.into());
    }
    Ok(())
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "coex_native/tests.rs"]
mod tests;

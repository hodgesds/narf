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

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! One retained actual-DDV factory snapshot for cold power and firmware setup.
use super::{
    efuse,
    mac::ChipId,
    power::{self, Io},
    secure::{self, Fuses},
};
use alloc::{vec, vec::Vec};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Register(power::Error),
    Map(efuse::EfuseError),
    Secure(secure::Error),
    Unsupported,
    Terminal,
}
impl From<power::Error> for Error {
    fn from(value: power::Error) -> Self {
        Self::Register(value)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    New,
    Reading,
    Ready,
}
pub trait Source: Io {
    fn profile(&self) -> (ChipId, u8);
    async fn physical(&mut self, start: u16, output: &mut [u8]) -> Result<(), power::Error>;
}
#[derive(Clone, Copy, Debug)]
pub struct Identity {
    chip: ChipId,
    cut: u8,
    mac: [u8; 6],
    calibration: power::Calibration,
    xtal: u8,
    country: [u8; 2],
    fuses: Fuses,
}
impl Identity {
    pub fn chip(self) -> ChipId {
        self.chip
    }
    pub fn cut(self) -> u8 {
        self.cut
    }
    pub fn mac(self) -> [u8; 6] {
        self.mac
    }
    pub fn calibration(self) -> power::Calibration {
        self.calibration
    }
    pub fn xtal(self) -> u8 {
        self.xtal
    }
    pub fn country(self) -> [u8; 2] {
        self.country
    }
    pub fn fuses(self) -> Fuses {
        self.fuses
    }
}
#[derive(Debug)]
pub struct Factory {
    state: State,
    identity: Option<Identity>,
    logical: Vec<u8>,
}
impl Default for Factory {
    fn default() -> Self {
        Self {
            state: State::New,
            identity: None,
            logical: Vec::new(),
        }
    }
}
impl Factory {
    pub fn state(&self) -> State {
        self.state
    }
    pub fn identity(&self) -> Option<Identity> {
        self.identity
    }
    pub fn logical(&self) -> Option<&[u8]> {
        (self.state == State::Ready).then_some(self.logical.as_slice())
    }
    /// A single completed native DDV lifecycle supplies every input. No erased
    /// data is synthesized after an I/O error and no caller can construct an
    /// Identity. Cancellation leaves Reading and prohibits replacement/retry.
    pub async fn read(&mut self, io: &mut impl Source) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        let (chip, cut) = io.profile();
        let size = match chip {
            ChipId::Rtl8852A => 1536,
            ChipId::Rtl8852B | ChipId::Rtl8852C | ChipId::Rtl8851B => 2048,
            ChipId::Rtl8922A => return Err(Error::Unsupported),
        };
        if cut > 15 {
            return Err(Error::Unsupported);
        }
        self.state = State::Reading;
        let autoload = io.read16(0xa)?;
        if autoload == u16::MAX {
            return Err(power::Error::Gone.into());
        }
        let mut physical = [0; 1216];
        io.physical(0, &mut physical).await?;
        let mut logical = vec![0; size];
        efuse::decode_map(&physical, &mut logical).map_err(Error::Map)?;
        let mac: [u8; 6] = logical[0x400..0x406].try_into().unwrap();
        if !efuse::mac_is_valid(mac) {
            return Err(Error::Map(efuse::EfuseError::MacUninitialized));
        }
        // Linux physical power-k marker0x5e9, ECV0x5ea, secure0x5ec/5ed.
        let mut extra = [0; 5];
        io.physical(0x5e9, &mut extra).await?;
        if chip == ChipId::Rtl8851B && extra[1] >> 4 != 15 && extra[1] >> 4 != cut {
            return Err(Error::Unsupported);
        }
        let fuses = Fuses::decode(chip, extra[3], extra[4]).map_err(Error::Secure)?;
        // Original Linux packed types independently establish these common AX
        // offsets: RFE0x2ca, XTAL0x2b9, country0x2cb; no BE layout is admitted.
        let identity = Identity {
            chip,
            cut,
            mac,
            calibration: power::Calibration {
                rfe_type: logical[0x2ca],
                valid: autoload & (1 << 5) != 0,
                power_k_valid: matches!(chip, ChipId::Rtl8852B) && extra[0] == 0xaa,
            },
            xtal: logical[0x2b9],
            country: logical[0x2cb..0x2cd].try_into().unwrap(),
            fuses,
        };
        self.logical = logical;
        self.identity = Some(identity);
        self.state = State::Ready;
        Ok(())
    }
}
impl Source for super::power_native::NativeIo {
    fn profile(&self) -> (ChipId, u8) {
        self.profile()
    }
    async fn physical(&mut self, start: u16, output: &mut [u8]) -> Result<(), power::Error> {
        self.read_physical(start, output).await
    }
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "factory/tests.rs"]
mod tests;

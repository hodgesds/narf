// SPDX-License-Identifier: GPL-2.0-or-later
//! Calibration-only C21 measured emission authorization. No operating grant.
use super::{efuse::Factory8821c, hardware::Features, mac, phy8821c};
#[cfg(any(test, feature = "kernel-test"))]
use alloc::vec::Vec;
use alloc::{format, string::String};
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::{FirmwareBlob, FirmwareError};
use narf_wireless::reg::{RegFlags, RegulatoryDomain};

pub(super) const LENGTH: usize = 128;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Firmware(FirmwareError),
    Authority,
    Unsigned,
    Format,
    Identity,
    Factory,
    Policy,
    Thermal,
}
/// Metadata to measure/sign for this exact retained calibration program.
/// This request grants no device, RF, firmware or station authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub identity: [u8; 32],
    pub mac: [u8; 6],
    pub filename: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Board {
    identity: [u8; 32],
    mac: [u8; 6],
    thermal: u8,
    hardware: Features,
}
impl Board {
    pub(super) fn new(
        factory: &Factory8821c,
        phy: phy8821c::Info,
        mac: mac::Info,
        hardware: Features,
        firmware: [u8; 32],
    ) -> Result<Self, Error> {
        let expected = phy8821c::Info::from_factory(factory, phy.cut, hardware)
            .map_err(|_| Error::Identity)?;
        if (phy.cut, phy.package, phy.rfe, phy.crystal)
            != (
                expected.cut,
                expected.package,
                expected.rfe,
                expected.crystal,
            )
            || mac.cut != phy.cut
            || (mac.reserved_boundary, mac.h2c_page, mac.firmware_tx_page) != (460, 500, 508)
        {
            return Err(Error::Identity);
        }
        // Do not manufacture an erased thermal/swing value. The chosen
        // initial calibration program has explicit factory values only.
        if factory.thermal() > 63 || factory.swing_2g() > 9 {
            return Err(Error::Factory);
        }
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(b"NARF RTL8821CE calibration-only ch1/20 RF-A v1");
        hash.update(
            b"minimum coded TXAGC; source swing/channel; general/phydm; IQK clear0 segment0",
        );
        hash.update(b"fresh RF08 abcde; failmask0 reload0; no packet/response/power-track grant");
        hash.update(factory.logical());
        hash.update(&firmware);
        hash.update(&hardware.raw);
        hash.update(&[phy.cut, phy.package, phy.rfe, phy.crystal]);
        for value in phy.channel_filters {
            hash.update(&value.to_le_bytes());
        }
        phy8821c::bind_tables(&mut hash, phy).map_err(|_| Error::Identity)?;
        super::radio8821c::bind_recipe(&mut hash);
        Ok(Self {
            identity: hash.finalize(),
            mac: factory.mac(),
            thermal: factory.thermal(),
            hardware,
        })
    }
    pub(super) fn request(self) -> Request {
        let m = self.mac;
        Request {
            identity: self.identity,
            mac: m,
            filename: format!(
                "rtw88/rtw8821ce-iqk-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
                m[0], m[1], m[2], m[3], m[4], m[5]
            ),
        }
    }
}
pub(super) enum Source {
    Registered,
    #[cfg(any(test, feature = "kernel-test"))]
    Verified {
        bytes: Vec<u8>,
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    },
}
pub(super) struct Envelope {
    board: Board,
    cap: Cap<FirmwareBlob, Read>,
    antenna: i16,
    qualified: i16,
    peak: i16,
    thermal: [u8; 2],
}
impl core::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("C21CalibrationEnvelope")
            .field("board", &self.board)
            .finish_non_exhaustive()
    }
}
struct ReadEnvelope(Board);
impl CapOp<FirmwareBlob, Read> for ReadEnvelope {
    type Output = Result<Envelope, Error>;
    fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
        Ok((|| {
            let view = narf_firmware::view_of(cap).map_err(Error::Firmware)?;
            Envelope::decode(view.bytes, view.signer, self.0, *cap)
        })())
    }
}
impl Source {
    pub(super) fn load(self, board: Board) -> Result<Envelope, Error> {
        match self {
            Self::Registered => {
                let authority = narf_firmware::trusted_loader_authority()
                    .and_then(|cap| cap.derive::<Read>().ok())
                    .ok_or(Error::Authority)?;
                let cap = narf_firmware::open(&board.request().filename, &authority)
                    .map_err(Error::Firmware)?;
                cap.invoke(ReadEnvelope(board))
                    .map_err(|_| Error::Authority)?
            }
            #[cfg(any(test, feature = "kernel-test"))]
            Self::Verified { bytes, signer, cap } => Envelope::decode(&bytes, signer, board, cap),
        }
    }
}
struct Current;
impl CapOp<FirmwareBlob, Read> for Current {
    type Output = ();
    fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<(), CapError> {
        Ok(())
    }
}
fn half(raw: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([raw[at], raw[at + 1]])
}
fn signed(raw: &[u8], at: usize) -> i16 {
    i16::from_le_bytes([raw[at], raw[at + 1]])
}
impl Envelope {
    pub(super) fn hardware(&self) -> Features {
        self.board.hardware
    }
    fn decode(
        raw: &[u8],
        signer: Option<[u8; 32]>,
        board: Board,
        cap: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        cap.invoke(Current).map_err(|_| Error::Authority)?;
        signer.ok_or(Error::Unsigned)?;
        if raw.len() != LENGTH
            || &raw[..4] != b"N21Q"
            || half(raw, 4) != 1
            || half(raw, 6) != 128
            || u32::from_le_bytes(raw[8..12].try_into().unwrap()) != 128
            || half(raw, 12) != 0x10ec
            || half(raw, 14) != 0xc821
            || raw[54] != 1
            || raw[55] != 20
            || &raw[64..66] != b"US"
            || raw[66..] != [0; 62]
        {
            return Err(Error::Format);
        }
        if raw[16..48] != board.identity || raw[48..54] != board.mac {
            return Err(Error::Identity);
        }
        let (antenna, qualified, peak) = (signed(raw, 56), signed(raw, 58), signed(raw, 60));
        let thermal = [raw[62], raw[63]];
        if !(0..=128).contains(&antenna)
            || !(-512..=256).contains(&qualified)
            || !(-512..=256).contains(&peak)
            || thermal[0] > thermal[1]
            || thermal[1] > 63
            || !(thermal[0]..=thermal[1]).contains(&board.thermal)
        {
            return Err(Error::Format);
        }
        Ok(Self {
            board,
            cap,
            antenna,
            qualified,
            peak,
            thermal,
        })
    }
    fn policy(&self, domain: &RegulatoryDomain) -> Result<i16, Error> {
        if domain.country_code != *b"US" {
            return Err(Error::Policy);
        }
        let mut covering = false;
        let mut limit = self.qualified.min(80);
        for rule in &domain.rules {
            if rule.freq_start_mhz >= 2422 || rule.freq_end_mhz <= 2402 {
                continue;
            }
            if rule.freq_start_mhz >= rule.freq_end_mhz
                || rule.max_bandwidth_mhz < 20
                || rule.flags.bits() & !RegFlags::NO_P2P.bits() != 0
            {
                return Err(Error::Policy);
            }
            covering |= rule.freq_start_mhz <= 2402 && rule.freq_end_mhz >= 2422;
            limit = limit.min(i16::from(rule.max_power_dbm) * 4);
        }
        if !covering || i32::from(self.peak) + i32::from(self.antenna) > i32::from(limit) {
            return Err(Error::Policy);
        }
        Ok(limit)
    }
    pub(super) fn matches(&self, board: Board) -> bool {
        self.board == board
    }
    pub(super) fn validate(&self, domain: &RegulatoryDomain) -> Result<i16, Error> {
        self.cap.invoke(Current).map_err(|_| Error::Authority)?;
        self.policy(domain)
    }
    pub(super) fn temperature(&self, value: u8) -> Result<(), Error> {
        if (self.thermal[0]..=self.thermal[1]).contains(&value) {
            Ok(())
        } else {
            Err(Error::Thermal)
        }
    }
    /// Qualification and current policy enclose the actual native operation,
    /// including descriptor bytes and doorbell, rather than a prior sample.
    pub(super) fn invoke<T, F, Op>(
        &self,
        policy: &F,
        operation: Op,
    ) -> Result<T, super::firmware_transport::Error>
    where
        F: Fn() -> Result<RegulatoryDomain, super::firmware_transport::Error>,
        Op: FnOnce() -> Result<T, super::firmware_transport::Error>,
    {
        struct Invoke<'a, F, Op> {
            envelope: &'a Envelope,
            policy: &'a F,
            operation: Op,
        }
        impl<T, F, Op> CapOp<FirmwareBlob, Read> for Invoke<'_, F, Op>
        where
            F: Fn() -> Result<RegulatoryDomain, super::firmware_transport::Error>,
            Op: FnOnce() -> Result<T, super::firmware_transport::Error>,
        {
            type Output = Result<T, super::firmware_transport::Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    self.envelope
                        .policy(&(self.policy)()?)
                        .map_err(super::firmware_transport::Error::Calibration8821c)?;
                    (self.operation)()
                })())
            }
        }
        self.cap
            .invoke(Invoke {
                envelope: self,
                policy,
                operation,
            })
            .map_err(|_| super::firmware_transport::Error::Calibration8821c(Error::Authority))?
    }
}

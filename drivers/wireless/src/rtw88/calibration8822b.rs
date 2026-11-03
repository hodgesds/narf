// SPDX-License-Identifier: GPL-2.0-or-later
//! Calibration-only RTL8822BE ("B22") measured emission authorization for the
//! firmware-offloaded `rtw8822b_do_iqk` program on channel 1 / 20 MHz, 2T2R.
//!
//! The signed `N2BQ` record mirrors the C21 `N21Q` format (same 128-byte
//! layout, B22 magic and PCI `10ec:b822` header) and is bound to a distinct
//! B22 board identity: the 768-byte `Factory8822b` map, the authenticated
//! `rtw8822b_fw.bin` digest, the firmware hardware report, the selected
//! `rtw8822b_table.c` rows and this recipe. It carries only measured facts a
//! provisioner supplies (antenna gain, qualified and measured peak power in
//! quarter-dBm, thermal window); nothing here invents a board value, and an
//! unprovisioned board stays unadmitted (`Error::Firmware`). No operating,
//! packet or station authority follows from this record.
pub use super::calibration8821c::Error;
use super::{efuse8822b::Factory8822b, hardware::Features, mac, phy8822b};
#[cfg(any(test, feature = "kernel-test"))]
use alloc::vec::Vec;
use alloc::{format, string::String};
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::FirmwareBlob;
use narf_wireless::reg::RegulatoryDomain;

pub(super) const LENGTH: usize = 128;
/// Record bytes 12..16: PCI vendor/device little-endian.
pub(super) const HEADER: [u8; 4] = [0xec, 0x10, 0x22, 0xb8];
/// Metadata to measure/sign for this exact retained calibration program.
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
/// Recipe text bound into the identity; changing the program changes it.
pub(super) fn bind_recipe(hash: &mut narf_crypto::sha256::Sha256) {
    hash.update(b"rtw8822b_set_channel ch1/20 BB_PATH_AB; TXAGC 0x1d00/0x1d80 all-zero index");
    hash.update(b"general/phydm(2T2R, AB/AB); IQK clear0 segment0; fresh RF08 abcde");
    hash.update(b"1bf0 failmask0 reload0; RF42 thermal window; no packet/power-track grant");
}
impl Board {
    pub(super) fn new(
        factory: &Factory8822b,
        phy: phy8822b::Info,
        mac: mac::Info,
        hardware: Features,
        firmware: [u8; 32],
    ) -> Result<Self, Error> {
        let expected = phy8822b::Info::from_factory(factory, phy.cut, hardware)
            .map_err(|_| Error::Identity)?;
        if (phy.cut, phy.rfe, phy.crystal) != (expected.cut, expected.rfe, expected.crystal)
            || mac.cut != phy.cut
            || (mac.reserved_boundary, mac.h2c_page, mac.firmware_tx_page) != (1996, 2036, 2044)
        {
            return Err(Error::Identity);
        }
        // An erased thermal meter (0xff) is never replaced by a default.
        if factory.thermal() > 63 {
            return Err(Error::Factory);
        }
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(b"NARF RTL8822BE calibration-only ch1/20 RF-AB v1");
        hash.update(factory.logical());
        hash.update(&firmware);
        hash.update(&hardware.raw);
        hash.update(&[phy.cut, phy.rfe, phy.crystal]);
        for kind in 0..5 {
            let rows = phy8822b::rows(phy, kind).ok_or(Error::Identity)?;
            hash.update(&[kind as u8]);
            hash.update(&(rows.len() as u32).to_le_bytes());
            for (address, value) in rows {
                hash.update(&address.to_le_bytes());
                hash.update(&value.to_le_bytes());
            }
        }
        bind_recipe(&mut hash);
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
                "rtw88/rtw8822be-iqk-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
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
        f.debug_struct("B22CalibrationEnvelope")
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
            || &raw[..4] != b"N2BQ"
            || half(raw, 4) != 1
            || half(raw, 6) != 128
            || u32::from_le_bytes(raw[8..12].try_into().unwrap()) != 128
            || raw[12..16] != HEADER
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
    /// Current US policy must plainly cover 2402..2422 MHz at 20 MHz and
    /// bound the measured peak plus antenna gain (both paths transmit).
    fn policy(&self, domain: &RegulatoryDomain) -> Result<i16, Error> {
        if domain.country_code != *b"US" {
            return Err(Error::Policy);
        }
        let mut covering = false;
        let mut limit = self.qualified.min(80);
        for (i, rule) in domain.rules.iter().enumerate() {
            if rule.freq_start_mhz >= 2422 || rule.freq_end_mhz <= 2402 {
                continue;
            }
            if !super::channel_policy::plain_rule(domain, i, 20) {
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
}
impl super::calibration8821c::Enclosure for Envelope {
    /// Qualification and current policy enclose the actual native operation,
    /// including descriptor bytes and doorbell, rather than a prior sample.
    fn invoke<T, F, Op>(
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
                        .map_err(super::firmware_transport::Error::Calibration8822b)?;
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
            .map_err(|_| super::firmware_transport::Error::Calibration8822b(Error::Authority))?
    }
}

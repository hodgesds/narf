// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Fresh measured A MAC authority, distinct from historical cold N5AB-v1.
use super::{factory::Factory, mac::ChipId, power, radio_assets::Assets, radio_policy::Lifecycle};
use alloc::format;
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::{FirmwareBlob, FirmwareError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Identity,
    Format,
    Unsigned,
    Authority,
    Firmware(FirmwareError),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Board {
    identity: [u8; 32],
    mac: [u8; 6],
    device: u16,
}
impl Board {
    pub(super) fn identity(self) -> [u8; 32] {
        self.identity
    }
    pub fn new(
        lifecycle: Lifecycle,
        factory: &Factory,
        device: narf_bus::DeviceId,
        assets: &Assets,
    ) -> Result<Self, Error> {
        let id = factory.identity().ok_or(Error::Identity)?;
        if device.vendor != 0x10ec
            || !matches!(device.device, 0x8852 | 0xa85a)
            || id.chip() != ChipId::Rtl8852A
            || assets.chip() != ChipId::Rtl8852A
            || !id.calibration().valid
            || id.calibration().rfe_type == 255
        {
            return Err(Error::Identity);
        }
        let mut h = narf_crypto::sha256::Sha256::new();
        h.update(b"NARF RTL8852A measured closed MAC authority v1; no historical N5ABv1 extension");
        h.update(super::mac_runtime::a::RECIPE);
        h.update(&[match lifecycle {
            Lifecycle::Initial => 0,
            Lifecycle::Repeat => 1,
        }]);
        for value in [
            device.vendor,
            device.device,
            device.subsystem_vendor,
            device.subsystem_id,
        ] {
            h.update(&value.to_le_bytes());
        }
        h.update(factory.logical().ok_or(Error::Identity)?);
        h.update(factory.a_phycap().ok_or(Error::Identity)?);
        h.update(&[id.cut(), id.calibration().rfe_type, id.xtal()]);
        id.fuses().bind(&mut h);
        assets
            .bind(&mut h, id.calibration().rfe_type, id.cut())
            .map_err(|_| Error::Identity)?;
        Ok(Self {
            identity: h.finalize(),
            mac: id.mac(),
            device: device.device,
        })
    }
}
pub(super) struct Qualification {
    board: Board,
    authority: Cap<FirmwareBlob, Read>,
}
struct Current;
impl CapOp<FirmwareBlob, Read> for Current {
    type Output = ();
    fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<(), CapError> {
        Ok(())
    }
}
struct Decode(Board);
impl CapOp<FirmwareBlob, Read> for Decode {
    type Output = Result<Qualification, Error>;
    fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
        Ok((|| {
            let view = narf_firmware::view_of(cap).map_err(Error::Firmware)?;
            Qualification::decode(view.bytes, view.signer, self.0, *cap)
        })())
    }
}
impl Qualification {
    pub fn load(board: Board) -> Result<Self, Error> {
        let m = board.mac;
        let name = format!(
            "rtw89/rtw8852a-mac-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            m[0], m[1], m[2], m[3], m[4], m[5]
        );
        let loader = narf_firmware::trusted_loader_authority()
            .and_then(|cap| cap.derive::<Read>().ok())
            .ok_or(Error::Authority)?;
        let cap = narf_firmware::open(&name, &loader).map_err(Error::Firmware)?;
        cap.invoke(Decode(board)).map_err(|_| Error::Authority)?
    }
    fn decode(
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        board: Board,
        authority: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        authority.invoke(Current).map_err(|_| Error::Authority)?;
        signer.ok_or(Error::Unsigned)?;
        if bytes.len() != 96
            || &bytes[..4] != b"N5AM"
            || bytes[4..8] != [1, 0, 96, 0]
            || bytes[8..12] != 96u32.to_le_bytes()
            || bytes[12..14] != 0x10ecu16.to_le_bytes()
            || bytes[14..16] != board.device.to_le_bytes()
            || bytes[54..] != [0; 42]
        {
            return Err(Error::Format);
        }
        if bytes[16..48] != board.identity || bytes[48..54] != board.mac {
            return Err(Error::Identity);
        }
        Ok(Self { board, authority })
    }
    pub fn matches(&self, board: Board) -> bool {
        self.board == board
    }
    pub fn current(&self) -> Result<(), power::Error> {
        self.authority
            .invoke(Current)
            .map_err(|_| power::Error::Access)
    }
    pub fn with_current<T>(
        &self,
        operation: impl FnOnce() -> Result<T, power::Error>,
    ) -> Result<T, power::Error> {
        struct Invoke<F>(F);
        impl<T, F: FnOnce() -> Result<T, power::Error>> CapOp<FirmwareBlob, Read> for Invoke<F> {
            type Output = Result<T, power::Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok(self.0())
            }
        }
        self.authority
            .invoke(Invoke(operation))
            .map_err(|_| power::Error::Access)?
    }
}

pub(super) struct SecurePolicy {
    board: Board,
    authority: Cap<FirmwareBlob, Read>,
    blacklist: super::secure::Blacklist,
}
struct DecodeSecure(Board);
impl CapOp<FirmwareBlob, Read> for DecodeSecure {
    type Output = Result<SecurePolicy, Error>;
    fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
        Ok((|| {
            let view = narf_firmware::view_of(cap).map_err(Error::Firmware)?;
            SecurePolicy::decode(view.bytes, view.signer, self.0, *cap)
        })())
    }
}
impl SecurePolicy {
    pub fn load(board: Board) -> Result<Self, Error> {
        let m = board.mac;
        let name = format!(
            "rtw89/rtw8852a-secure-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            m[0], m[1], m[2], m[3], m[4], m[5]
        );
        let loader = narf_firmware::trusted_loader_authority()
            .and_then(|cap| cap.derive::<Read>().ok())
            .ok_or(Error::Authority)?;
        let cap = narf_firmware::open(&name, &loader).map_err(Error::Firmware)?;
        cap.invoke(DecodeSecure(board))
            .map_err(|_| Error::Authority)?
    }
    fn decode(
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        board: Board,
        authority: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        authority.invoke(Current).map_err(|_| Error::Authority)?;
        signer.ok_or(Error::Unsigned)?;
        if bytes.len() != 96
            || &bytes[..4] != b"N5AS"
            || bytes[4..8] != [1, 0, 96, 0]
            || bytes[8..12] != 96u32.to_le_bytes()
            || bytes[12..14] != 0x10ecu16.to_le_bytes()
            || bytes[14..16] != board.device.to_le_bytes()
            || bytes[55] != 0
            || bytes[88..] != [0; 8]
        {
            return Err(Error::Format);
        }
        if bytes[16..48] != board.identity || bytes[48..54] != board.mac {
            return Err(Error::Identity);
        }
        Ok(Self {
            board,
            authority,
            blacklist: super::secure::Blacklist::board_8852a(
                bytes[54],
                bytes[56..88].try_into().map_err(|_| Error::Format)?,
            ),
        })
    }
    pub fn matches(&self, board: Board) -> bool {
        self.board == board
    }
    pub fn current(&self) -> Result<(), power::Error> {
        self.authority
            .invoke(Current)
            .map_err(|_| power::Error::Access)
    }
    pub fn plan(
        &self,
        image: super::prepared::PreparedFirmware,
        fuses: super::secure::Fuses,
    ) -> Result<Result<super::download_plan::DownloadPlan, super::download_plan::Error>, power::Error>
    {
        struct Plan<'a> {
            policy: &'a SecurePolicy,
            image: super::prepared::PreparedFirmware,
            fuses: super::secure::Fuses,
        }
        impl CapOp<FirmwareBlob, Read> for Plan<'_> {
            type Output = Result<super::download_plan::DownloadPlan, super::download_plan::Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok(super::download_plan::DownloadPlan::new(
                    self.image,
                    self.fuses,
                    Some(self.policy.blacklist),
                ))
            }
        }
        self.authority
            .invoke(Plan {
                policy: self,
                image,
                fuses,
            })
            .map_err(|_| power::Error::Access)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "mac_a_policy_tests.rs"]
pub(super) mod tests;

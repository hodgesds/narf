// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Signed measured envelope for the exact B cold/calibration recipe. This
//! grants calibration only: neither packet TX nor autonomous ACK/CTS emission.
use super::{factory::Factory, mac::ChipId, radio_assets::Assets};
use alloc::format;
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::{FirmwareBlob, FirmwareError};
const LENGTH: usize = 96;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Firmware(FirmwareError),
    Authority,
    Unsigned,
    Format,
    Identity,
    Policy,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Board {
    identity: [u8; 32],
    mac: [u8; 6],
    device: u16,
}
impl Board {
    pub fn new(
        factory: &Factory,
        device: narf_bus::DeviceId,
        assets: &Assets,
    ) -> Result<Self, Error> {
        let identity = factory.identity().ok_or(Error::Identity)?;
        let calibration = identity.calibration();
        if device.vendor != 0x10ec
            || !matches!(device.device, 0xb852 | 0xb85b)
            || identity.chip() != ChipId::Rtl8852B
            || !calibration.valid
            || calibration.rfe_type == 255
        {
            return Err(Error::Identity);
        }
        // This exact source-selected firmware ABI supports TDMA3 and slot1.
        super::coex_native::Protocol::for_version(assets.firmware_version())
            .ok_or(Error::Identity)?;
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(b"NARF RTL8852B cold ch1 legacy20 awake WLAN-only calibration v1");
        hash.update(b"CMAC TXEN=0; NCTL RCK DACK RXDCK; no ordinary packet/response grant");
        hash.update(&super::rfk_tables::RECIPE);
        hash.update(&super::coex_native::RECIPE);
        hash.update(&device.vendor.to_le_bytes());
        hash.update(&device.device.to_le_bytes());
        hash.update(&device.subsystem_vendor.to_le_bytes());
        hash.update(&device.subsystem_id.to_le_bytes());
        hash.update(factory.logical().ok_or(Error::Identity)?);
        hash.update(factory.b_phycap().ok_or(Error::Identity)?);
        hash.update(&[identity.cut(), calibration.rfe_type, identity.xtal()]);
        assets
            .bind(&mut hash, calibration.rfe_type, identity.cut())
            .map_err(|_| Error::Identity)?;
        Ok(Self {
            identity: hash.finalize(),
            mac: identity.mac(),
            device: device.device,
        })
    }
    pub fn identity(self) -> [u8; 32] {
        self.identity
    }
}
struct Current;
impl CapOp<FirmwareBlob, Read> for Current {
    type Output = ();
    fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<(), CapError> {
        Ok(())
    }
}
pub(super) struct Calibration {
    board: Board,
    authority: Cap<FirmwareBlob, Read>,
    antenna_qdb: i16,
    qualified_qdbm: i16,
    calibration_peak_qdbm: i16,
    // An explicit inert fixture can carry its own fixed host policy. The
    // registered loader always leaves this None and uses the real database.
    #[cfg(any(test, feature = "kernel-test"))]
    model_domain: Option<narf_wireless::reg::RegulatoryDomain>,
}
struct Decode(Board);
impl CapOp<FirmwareBlob, Read> for Decode {
    type Output = Result<Calibration, Error>;
    fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
        Ok((|| {
            let view = narf_firmware::view_of(cap).map_err(Error::Firmware)?;
            Calibration::from_verified(view.bytes, view.signer, self.0, *cap)
        })())
    }
}
impl Calibration {
    pub fn load(board: Board) -> Result<Self, Error> {
        let m = board.mac;
        let name = format!(
            "rtw89/rtw8852b-cal-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            m[0], m[1], m[2], m[3], m[4], m[5]
        );
        let loader = narf_firmware::trusted_loader_authority()
            .and_then(|cap| cap.derive::<Read>().ok())
            .ok_or(Error::Authority)?;
        let cap = narf_firmware::open(&name, &loader).map_err(Error::Firmware)?;
        cap.invoke(Decode(board)).map_err(|_| Error::Authority)?
    }
    fn from_verified(
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        board: Board,
        authority: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        authority.invoke(Current).map_err(|_| Error::Authority)?;
        signer.ok_or(Error::Unsigned)?;
        if bytes.len() != LENGTH
            || &bytes[..4] != b"N52B"
            || bytes[4..8] != [1, 0, 96, 0]
            || bytes[8..12] != (LENGTH as u32).to_le_bytes()
            || bytes[12..14] != 0x10ecu16.to_le_bytes()
            || bytes[14..16] != board.device.to_le_bytes()
            || bytes[54..58] != [1, 20, 1, 0]
            || bytes[64..] != [0; 32]
        {
            return Err(Error::Format);
        }
        if bytes[16..48] != board.identity || bytes[48..54] != board.mac {
            return Err(Error::Identity);
        }
        let signed = |at| i16::from_le_bytes(bytes[at..at + 2].try_into().unwrap());
        let antenna_qdb = signed(58);
        let qualified_qdbm = signed(60);
        let calibration_peak_qdbm = signed(62);
        if !(0..=256).contains(&antenna_qdb)
            || !(-512..=256).contains(&qualified_qdbm)
            || !(-512..=256).contains(&calibration_peak_qdbm)
        {
            return Err(Error::Format);
        }
        Ok(Self {
            board,
            authority,
            antenna_qdb,
            qualified_qdbm,
            calibration_peak_qdbm,
            #[cfg(any(test, feature = "kernel-test"))]
            model_domain: None,
        })
    }
    pub fn current(&self) -> Result<(), Error> {
        self.authority
            .invoke(Current)
            .map_err(|_| Error::Authority)?;
        #[cfg(any(test, feature = "kernel-test"))]
        if let Some(domain) = self.model_domain.as_ref() {
            return self.check(domain);
        }
        let domain = narf_wireless::reg::db::ensure_domain().map_err(|_| Error::Policy)?;
        self.check(&domain)
    }
    fn check(&self, domain: &narf_wireless::reg::RegulatoryDomain) -> Result<(), Error> {
        if !domain.country_code.iter().all(u8::is_ascii_uppercase) {
            return Err(Error::Policy);
        }
        let mut ceiling = None;
        for rule in &domain.rules {
            if rule.freq_start_mhz >= 2422 || rule.freq_end_mhz <= 2402 {
                continue;
            }
            if rule.freq_start_mhz > 2402
                || rule.freq_end_mhz < 2422
                || rule.max_bandwidth_mhz < 20
                || rule.flags.bits() & !narf_wireless::reg::RegFlags::NO_P2P.bits() != 0
            {
                return Err(Error::Policy);
            }
            let power = i16::from(rule.max_power_dbm) * 4;
            ceiling = Some(ceiling.map_or(power, |old: i16| old.min(power)));
        }
        let ceiling = ceiling.ok_or(Error::Policy)?.min(self.qualified_qdbm);
        if i32::from(self.calibration_peak_qdbm) + i32::from(self.antenna_qdb) > i32::from(ceiling)
        {
            return Err(Error::Policy);
        }
        Ok(())
    }
    pub fn matches(&self, board: Board) -> bool {
        self.board == board
    }
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "calibration_policy/tests.rs"]
pub(super) mod tests;

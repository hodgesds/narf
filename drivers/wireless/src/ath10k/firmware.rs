// SPDX-License-Identifier: GPL-2.0-or-later
//! Firmware/board ownership and boot preparation, based on Linux
//! ath10k/core.c. BMI_DONE remains the runtime HIF owner's responsibility.

use super::{
    bmi::{Bmi, BmiError, Transport},
    profile::Profile,
};
use alloc::{format, string::String, vec::Vec};
use core::ops::Range;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Bmi(BmiError),
    Missing,
    InvalidContainer,
    Unsupported,
    BoardNotFound,
    Calibration,
    Address,
    Authority,
    NoMemory,
}
impl From<BmiError> for Error {
    fn from(value: BmiError) -> Self {
        Self::Bmi(value)
    }
}

/// Production implementation opens capability-authorized immutable firmware
/// registry blobs and copies their verified bytes into owned storage.
#[allow(async_fn_in_trait)]
pub trait Files {
    fn load(&mut self, name: &str) -> Result<Vec<u8>, Error>;
    /// Wait only at an asset lookup checkpoint. The caller retains the same
    /// completed ROM state; this must never retry a BMI transaction. Stores
    /// without a staging service preserve their ordinary terminal Missing.
    async fn wait_missing(&mut self) -> Result<(), Error> {
        Err(Error::Missing)
    }
}

pub(super) async fn staging_pause() {
    narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(500_000_000)).await;
}

pub(super) struct RegistryFiles {
    authority: narf_capabilities::Cap<narf_firmware::FirmwareRegistry, narf_capabilities::Read>,
}
impl RegistryFiles {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            authority: narf_firmware::trusted_loader_authority()
                .and_then(|authority| authority.derive().ok())
                .ok_or(Error::Authority)?,
        })
    }
    /// Probe may precede installation of the trusted loader. No registry cap
    /// has been acquired yet, so waiting here cannot replace a revoked cap.
    pub async fn wait_authority() -> Result<Self, Error> {
        loop {
            match Self::new() {
                Ok(files) => return Ok(files),
                Err(Error::Authority) if narf_firmware::trusted_loader_authority().is_none() => {
                    staging_pause().await;
                }
                Err(error) => return Err(error),
            }
        }
    }
}
impl Files for RegistryFiles {
    fn load(&mut self, name: &str) -> Result<Vec<u8>, Error> {
        let board = matches!(name.rsplit('/').next(), Some("board.bin" | "board-2.bin"));
        crate::firmware_asset::load(&self.authority, name, 16 * 1024 * 1024, board)
            .map(|asset| asset.bytes)
            .map_err(|error| match error {
                narf_firmware::FirmwareError::NotFound => Error::Missing,
                narf_firmware::FirmwareError::OutOfMemory => Error::NoMemory,
                _ => Error::Authority,
            })
    }
    async fn wait_missing(&mut self) -> Result<(), Error> {
        staging_pause().await;
        Ok(())
    }
}

#[derive(Debug)]
pub struct Image {
    bytes: Vec<u8>,
    pub api: u8,
    image: Range<usize>,
    otp: Option<Range<usize>>,
    pub codeswap: Option<Range<usize>>,
    pub features: u64,
    pub wmi: u32,
    pub htt: u32,
}
fn word(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(Error::InvalidContainer)?
            .try_into()
            .unwrap(),
    ))
}
fn entries(bytes: &[u8], start: usize) -> Result<Vec<(u32, Range<usize>)>, Error> {
    let mut out = Vec::new();
    let mut at = start;
    while at < bytes.len() {
        let id = word(bytes, at)?;
        let length = word(bytes, at + 4)? as usize;
        let data = at.checked_add(8).ok_or(Error::InvalidContainer)?;
        let end = data.checked_add(length).ok_or(Error::InvalidContainer)?;
        let next = end.checked_add(3).ok_or(Error::InvalidContainer)? & !3;
        if next > bytes.len() {
            return Err(Error::InvalidContainer);
        }
        out.push((id, data..end));
        at = next;
    }
    Ok(out)
}
fn magic(bytes: &[u8], expected: &[u8]) -> Result<usize, Error> {
    if !bytes.starts_with(expected) {
        return Err(Error::InvalidContainer);
    }
    let offset = (expected.len() + 3) & !3;
    if offset > bytes.len() {
        return Err(Error::InvalidContainer);
    }
    Ok(offset)
}
impl Image {
    pub fn parse(bytes: Vec<u8>, api: u8) -> Result<Self, Error> {
        if !(2..=6).contains(&api) {
            return Err(Error::Unsupported);
        }
        let mut image = None;
        let mut otp = None;
        let mut codeswap = None;
        let (mut features, mut wmi, mut htt) = (0, 0, 0);
        let mut seen = 0u32;
        for (id, region) in entries(&bytes, magic(&bytes, b"QCA-ATH10K\0")?)? {
            if matches!(id, 2..=7) {
                if seen & (1 << id) != 0 {
                    return Err(Error::InvalidContainer);
                }
                seen |= 1 << id;
            }
            match id {
                2 => {
                    for (i, &value) in bytes[region].iter().take(8).enumerate() {
                        features |= u64::from(value) << (i * 8);
                    }
                }
                3 if !region.is_empty() => image = Some(region),
                4 if !region.is_empty() => otp = Some(region),
                5 | 6 => {
                    if region.len() != 4 {
                        return Err(Error::InvalidContainer);
                    }
                    if id == 5 {
                        wmi = word(&bytes, region.start)?;
                    } else {
                        htt = word(&bytes, region.start)?;
                    }
                }
                7 if !region.is_empty() => codeswap = Some(region),
                _ => {}
            }
        }
        if features & (1 << 19) != 0 {
            return Err(Error::Unsupported);
        } // NON_BMI.
        if wmi == 0 {
            wmi = if features & (1 << 1) == 0 {
                1
            } else if features & (1 << 4) != 0 {
                3
            } else {
                2
            };
        }
        if !(1..=6).contains(&wmi) {
            return Err(Error::Unsupported);
        }
        if htt == 0 {
            htt = match wmi {
                1 => 1,
                2 | 3 | 5 => 2,
                4 => 3,
                _ => return Err(Error::Unsupported),
            };
        }
        if !(1..=4).contains(&htt) {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            bytes,
            api,
            image: image.ok_or(Error::InvalidContainer)?,
            otp,
            codeswap,
            features,
            wmi,
            htt,
        })
    }
    pub fn image(&self) -> &[u8] {
        &self.bytes[self.image.clone()]
    }
    pub fn otp(&self) -> Option<&[u8]> {
        self.otp.as_ref().map(|range| &self.bytes[range.clone()])
    }
    pub fn codeswap(&self) -> Option<&[u8]> {
        self.codeswap
            .as_ref()
            .map(|range| &self.bytes[range.clone()])
    }
    pub fn load(files: &mut impl Files, profile: Profile) -> Result<Self, Error> {
        for api in (2..=6).rev() {
            match files.load(&format!("{}/firmware-{api}.bin", profile.directory)) {
                Ok(bytes) => return Self::parse(bytes, api),
                Err(Error::Missing) => {}
                Err(error) => return Err(error),
            }
        }
        Err(Error::Missing)
    }
    pub(super) async fn wait_load(files: &mut impl Files, profile: Profile) -> Result<Self, Error> {
        loop {
            match Self::load(files, profile) {
                Err(Error::Missing) => files.wait_missing().await?,
                result => return result,
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub vendor: u16,
    pub device: u16,
    pub subsystem_vendor: u16,
    pub subsystem_device: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OtpIdentity {
    pub board: u8,
    pub chip: u8,
    pub extended: bool,
}
impl OtpIdentity {
    fn from_result(result: u32) -> Option<Self> {
        let board = ((result & 0x7c00) >> 10) as u8;
        (result & 255 == 0 && board != 0).then_some(Self {
            board,
            chip: ((result >> 15) & 3) as u8,
            extended: result & 0x40000 != 0,
        })
    }
}
pub fn board_names(
    identity: Identity,
    otp: Option<OtpIdentity>,
    variant: &str,
) -> Result<Vec<String>, Error> {
    if variant.len() > 32
        || !variant
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b',')
    {
        return Err(Error::Unsupported);
    }
    let base = if let Some(otp) = otp {
        format!(
            "bus=pci,bmi-chip-id={},bmi-board-id={}",
            otp.chip, otp.board
        )
    } else {
        format!(
            "bus=pci,vendor={:04x},device={:04x},subsystem-vendor={:04x},subsystem-device={:04x}",
            identity.vendor, identity.device, identity.subsystem_vendor, identity.subsystem_device
        )
    };
    let mut names = Vec::new();
    if !variant.is_empty() {
        names.push(format!("{base},variant={variant}"));
    }
    names.push(base);
    Ok(names)
}
pub fn select_board<'a>(
    bytes: &'a [u8],
    names: &[String],
    extended: bool,
) -> Result<&'a [u8], Error> {
    let top = entries(bytes, magic(bytes, b"QCA-ATH10K-BOARD\0")?)?;
    for name in names {
        for (kind, region) in &top {
            if *kind != u32::from(extended) {
                continue;
            }
            let body = &bytes[region.clone()];
            let mut matches = false;
            for (kind, region) in entries(body, 0)? {
                if kind == 0 && body[region.clone()] == *name.as_bytes() {
                    matches = true;
                }
                if kind == 1 && matches && !region.is_empty() {
                    return Ok(&body[region]);
                }
            }
        }
    }
    Err(Error::BoardNotFound)
}

const HI: u32 = 0x400800;

fn load_board(
    files: &mut impl Files,
    profile: Profile,
    names: &[String],
) -> Result<Vec<u8>, Error> {
    match files.load(&format!("{}/board-2.bin", profile.directory)) {
        Ok(bytes) => match select_board(&bytes, names, false) {
            Ok(board) => Ok(board.to_vec()),
            Err(Error::BoardNotFound) => files.load(&format!("{}/board.bin", profile.directory)),
            Err(error) => Err(error),
        },
        Err(Error::Missing) => files.load(&format!("{}/board.bin", profile.directory)),
        Err(error) => Err(error),
    }
}

async fn wait_board(
    files: &mut impl Files,
    profile: Profile,
    names: &[String],
) -> Result<Vec<u8>, Error> {
    loop {
        match load_board(files, profile, names) {
            Err(Error::Missing) => files.wait_missing().await?,
            result => return result,
        }
    }
}

async fn wait_extended_board(
    files: &mut impl Files,
    profile: Profile,
    name: String,
) -> Result<Vec<u8>, Error> {
    loop {
        match files.load(&format!("{}/board-2.bin", profile.directory)) {
            Ok(bytes) => {
                // A complete signed container for other boards is not a
                // calibration receipt for the discovered extended identity.
                match select_board(&bytes, core::slice::from_ref(&name), true) {
                    Ok(board) => return Ok(board.to_vec()),
                    Err(Error::BoardNotFound) => {
                        files.wait_missing().await.map_err(|error| match error {
                            Error::Missing => Error::BoardNotFound,
                            error => error,
                        })?;
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(Error::Missing) => files.wait_missing().await?,
            Err(error) => return Err(error),
        }
    }
}

/// Execute ROM-side boot preparation using the existing DMA-backed BMI.
/// No DONE occurs here: the next owned HIF stage must publish all live CE
/// buffers and arrange reset/IRQ teardown before firmware is permitted to run.
pub(super) async fn prepare<T: Transport>(
    bmi: &mut Bmi<T>,
    files: &mut impl Files,
    profile: Profile,
    identity: Identity,
    variant: &str,
    image: &Image,
) -> Result<Option<OtpIdentity>, Error> {
    if profile.pll {
        super::clock::enable(bmi).await?;
    }
    let otp_bytes = image.otp().ok_or(Error::Calibration)?;
    bmi.fast_download(profile.patch, otp_bytes).await?;
    let otp = OtpIdentity::from_result(bmi.execute(profile.patch, 0x10).await?);
    let names = board_names(identity, otp, variant)?;
    // Keep this exact completed OTP identity while a signed board arrives.
    // Restarting prepare would repeat PLL/OTP execution on the live target.
    let board = wait_board(files, profile, &names).await?;
    if board.len() != profile.board + profile.board_tail {
        return Err(Error::Calibration);
    }
    bmi.write_u32(HI, 0x0002).await?; // HTC_PROTOCOL_VERSION 2.0.
    let options = bmi.read_u32(HI + 0x10).await?;
    bmi.write_u32(HI + 0x10, options | (1 << 9) | (2 << 12) | (1 << 3))
        .await?;
    bmi.write_u32(HI + 0x44, 0).await?;
    bmi.write_u32(HI + 0x104, 0).await?;
    bmi.write_u32(HI + 0xbc, u32::from(identity.device)).await?;
    let extra = bmi.read_u32(HI + 0xac).await?;
    if extra != 0 {
        if extra & 3 != 0 {
            return Err(Error::Calibration);
        }
        bmi.write_memory(extra, &board[profile.board..]).await?;
        bmi.write_u32(HI + 0xb0, ((profile.board_tail as u32) << 16) | 1)
            .await?;
    }
    let base = bmi.read_u32(HI + 0x54).await?;
    if base == 0 || base & 3 != 0 {
        return Err(Error::Address);
    }
    bmi.write_memory(base, &board[..profile.board]).await?;
    bmi.write_u32(HI + 0x58, 1).await?;
    if otp.is_some_and(|identity| identity.extended) {
        bmi.fast_download(profile.patch, otp_bytes).await?;
        let result = bmi.execute(profile.patch, 0x40000).await?;
        let extended_id = result & 255;
        if extended_id != 0 {
            let chip = otp.unwrap().chip;
            let name = format!("bus=pci,bmi-chip-id={chip},bmi-eboard-id={extended_id}");
            let data = wait_extended_board(files, profile, name).await?;
            if data.len() != profile.extended_board {
                return Err(Error::Calibration);
            }
            let address = base.checked_add(0x3000).ok_or(Error::Address)?;
            bmi.write_memory(address, &data).await?;
        }
    }
    bmi.fast_download(profile.patch, otp_bytes).await?;
    let result = bmi.execute(profile.patch, profile.otp_parameter).await?;
    if result != 0 && image.features & (1 << 7) == 0 {
        return Err(Error::Calibration);
    }
    if image.features & (1 << 9) != 0 {
        bmi.write_u32(HI + 0x20, 1).await?;
    }
    if let Some(bytes) = image.codeswap() {
        bmi.configure_codeswap(bytes).await?;
    }
    bmi.fast_download(profile.patch, image.image()).await?;
    bmi.write_u32(HI + 0x14, 0).await?;
    Ok(otp)
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;

#[cfg(any(test, feature = "kernel-test"))]
#[path = "firmware_parser_tests.rs"]
mod parser_tests;

#[cfg(feature = "kernel-test")]
mod asset_authority_tests {
    use super::*;
    use crate::firmware_asset::tests::install;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_ath10k_board_data_requires_signer_and_current_registry_invocation() -> TestResult {
        let (write, read) = narf_firmware::bootstrap_authority();
        let mut files = RegistryFiles { authority: read };
        for name in ["ath10k/narf-test/board-2.bin", "ath10k/narf-test/board.bin"] {
            match install(&write, name, b"inert-board", false) {
                Ok(()) => {
                    if files.load(name).is_ok() {
                        return TestResult::Fail("unsigned developer ath10k calibration admitted");
                    }
                }
                Err(narf_firmware::FirmwareError::UnsignedRejected) => {}
                Err(_) => return TestResult::Fail("unexpected board fixture installation failure"),
            }
            install(&write, name, b"inert-board", true).unwrap();
            if files.load(name).as_deref() != Ok(b"inert-board".as_slice()) {
                return TestResult::Fail("signed exact ath10k board copy changed");
            }
        }
        let executable = "ath10k/narf-test/firmware-6.bin";
        match install(&write, executable, b"inert-code", false) {
            Ok(()) => {
                if files.load(executable).as_deref() != Ok(b"inert-code".as_slice()) {
                    return TestResult::Fail("ath10k developer executable policy changed");
                }
            }
            Err(narf_firmware::FirmwareError::UnsignedRejected) => {}
            Err(_) => {
                return TestResult::Fail("unexpected executable fixture installation failure")
            }
        }
        read.revoke();
        if files.load("ath10k/narf-test/board-2.bin").is_ok() {
            return TestResult::Fail("ath10k firmware read ignored current registry epoch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/ath10k/firmware",
        smoke_ath10k_board_data_requires_signer_and_current_registry_invocation
    );
}

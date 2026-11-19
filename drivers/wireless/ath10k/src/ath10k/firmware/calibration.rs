// SPDX-License-Identifier: GPL-2.0-or-later
//! Exact PCI-function calibration files, following Linux core.c
//! ath10k_fetch_cal_file/download_cal_file/core_pre_cal_config.
//! Signed registry inputs retain the same source owner as executable/BDF data.
use super::platform::{Platform, Source};
use super::*;
use narf_bus::PcieAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Mode {
    Pre,
    Final,
}

/// Where Linux's `ar->cal_mode` came from (`ATH10K_{PRE_,}CAL_MODE_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Origin {
    Nvmem,
    File,
    Dt,
}

#[derive(Debug)]
pub(super) struct Calibration {
    pub mode: Mode,
    pub origin: Origin,
    pub bytes: Vec<u8>,
}

/// Linux `ath10k_fetch_cal_file` for one exact PCI function.
fn file(
    files: &mut impl Files,
    address: Option<PcieAddr>,
    prefix: &str,
) -> Result<Option<Vec<u8>>, Error> {
    let Some(address) = address else {
        return Ok(None);
    };
    let name = format!(
        "ath10k/{prefix}-pci-{:04x}:{:02x}:{:02x}.{}.bin",
        address.segment, address.bus, address.device, address.function
    );
    match files.load(&name) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(Error::Missing) => Ok(None),
        Err(error) => Err(error),
    }
}

fn platform(source: &Source) -> Result<Option<Vec<u8>>, Error> {
    match source {
        Source::Absent => Ok(None),
        Source::Present(bytes) => Ok(Some(bytes.clone())),
        Source::Refused(error) => Err(error.clone()),
    }
}

/// Optional lookup at the current loader checkpoint without DT/NVMEM
/// sources. Missing is not a receipt for a different function; malformed or
/// revoked signed input is terminal.
#[cfg(any(test, feature = "kernel-test"))]
pub(super) fn load(
    files: &mut impl Files,
    address: Option<PcieAddr>,
    profile: Profile,
) -> Result<Option<Calibration>, Error> {
    select(files, address, profile, &Platform::default())
}

/// Linux `ath10k_core_pre_cal_download` then `ath10k_download_cal_data`
/// source precedence: pre-cal NVMEM cell, pre-cal file, pre-cal DT property,
/// then cal NVMEM cell, cal file, cal DT property (EEPROM and OTP follow in
/// [`prepare_for_address`]). Linux falls through on any source error except
/// `-EPROBE_DEFER`; here a present source that is refused or malformed is
/// terminal, so a broken factory input never silently selects another one.
pub(super) fn select(
    files: &mut impl Files,
    address: Option<PcieAddr>,
    profile: Profile,
    sources: &Platform,
) -> Result<Option<Calibration>, Error> {
    if address.is_some_and(|address| address.device > 31 || address.function > 7) {
        return Err(Error::Unsupported);
    }
    for (mode, prefix, nvmem, dt) in [
        (Mode::Pre, "pre-cal", &sources.pre_nvmem, &sources.pre_dt),
        (Mode::Final, "cal", &sources.nvmem, &sources.dt),
    ] {
        for origin in [Origin::Nvmem, Origin::File, Origin::Dt] {
            let bytes = match origin {
                Origin::Nvmem => platform(nvmem)?,
                Origin::File => file(files, address, prefix)?,
                Origin::Dt => platform(dt)?,
            };
            if let Some(bytes) = bytes {
                // Keep the per-silicon calibration geometry from Linux's
                // hw_params (`cal_data_len`), rather than accepting arbitrary
                // partial input.
                if bytes.len() != profile.calibration || bytes.len() & 3 != 0 {
                    return Err(Error::Calibration);
                }
                return Ok(Some(Calibration {
                    mode,
                    origin,
                    bytes,
                }));
            }
        }
    }
    Ok(None)
}

impl Calibration {
    /// Native host-interest board download. An advertised extension needs its
    /// complete source extent; a short cal file cannot invent extension bytes.
    pub async fn download<T: Transport>(
        &self,
        bmi: &mut Bmi<T>,
        profile: Profile,
    ) -> Result<u32, Error> {
        let extension = bmi.read_u32(HI + 0xac).await?;
        if extension != 0 {
            if extension & 3 != 0 || self.bytes.len() != profile.board + profile.board_tail {
                return Err(Error::Calibration);
            }
            bmi.write_memory(extension, &self.bytes[profile.board..])
                .await?;
            bmi.write_u32(HI + 0xb0, ((profile.board_tail as u32) << 16) | 1)
                .await?;
        }
        let base = bmi.read_u32(HI + 0x54).await?;
        if base == 0 || base & 3 != 0 {
            return Err(Error::Address);
        }
        bmi.write_memory(base, &self.bytes[..self.bytes.len().min(profile.board)])
            .await?;
        bmi.write_u32(HI + 0x58, 1).await?;
        Ok(base)
    }

    /// BMI_PARAM_GET_FLASH_BOARD_ID / GET_EEPROM_BOARD_ID and
    /// BMI_PARAM_FLASH_SECTION_ALL from the native BMI contract. A final
    /// calibration file is already the complete calibration mode, without
    /// another OTP calibration execution.
    pub fn board_id_parameter(&self) -> u32 {
        if self.mode == Mode::Pre {
            0x8000
        } else {
            0x10
        }
    }
    pub fn otp_parameter(&self) -> Option<u32> {
        (self.mode == Mode::Pre).then_some(0x10000)
    }
}

/// Registry classification is intentionally independent of executable
/// developer policy. A per-function calibration file is a board input even
/// though its basename is not board.bin or board-2.bin.
pub(super) fn signed_input(name: &str) -> bool {
    name.rsplit('/').next().is_some_and(|base| {
        matches!(base, "board.bin" | "board-2.bin")
            || (base.ends_with(".bin")
                && (base.starts_with("pre-cal-pci-") || base.starts_with("cal-pci-")))
    })
}

/// Native BMI preparation for an exact enumerated PCI function. The caller
/// supplies the address from its existing exclusive PCI-device binding.
#[allow(clippy::too_many_arguments)]
pub(in crate::ath10k) async fn prepare_for_address<T: Transport>(
    bmi: &mut Bmi<T>,
    files: &mut impl Files,
    profile: Profile,
    identity: Identity,
    variant: &str,
    image: &Image,
    address: Option<PcieAddr>,
    sources: &Platform,
) -> Result<Option<OtpIdentity>, Error> {
    let calibration = select(files, address, profile, sources)?;
    if profile.pll {
        super::super::clock::enable(bmi).await?;
    }
    // A pre-cal file must reach native host-interest memory before the
    // FLASH board-ID OTP execution. Its name binds the physical function;
    // the later signed board selection still follows the reported identity.
    if let Some(calibration) = calibration.as_ref().filter(|cal| cal.mode == Mode::Pre) {
        calibration.download(bmi, profile).await?;
    }
    let otp_bytes = image.otp().ok_or(Error::Calibration)?;
    bmi.fast_download(profile.patch, otp_bytes).await?;
    let otp = OtpIdentity::from_result(
        bmi.execute(
            profile.patch,
            calibration
                .as_ref()
                .map_or(0x10, Calibration::board_id_parameter),
        )
        .await?,
    );
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
    // Linux `core.c::ath10k_download_cal_data` tries the QCA9887 SI EEPROM
    // before OTP. Its 2116-byte image replaces board data only when
    // `ath10k_push_board_ext_data` accepts that length (no extension region);
    // otherwise, or on any EEPROM failure, the board file plus OTP is used.
    let eeprom = if calibration.is_none()
        && profile.device == super::super::hw::QCA9887_DEVICE_ID
        && extra == 0
    {
        bmi.calibration_eeprom(profile.calibration).await?
    } else {
        None
    };
    let base = if let Some(calibration) = calibration.as_ref().filter(|cal| cal.mode == Mode::Final)
    {
        calibration.download(bmi, profile).await?
    } else {
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
        match &eeprom {
            Some(calibration) => {
                let length = calibration.len().min(profile.board);
                bmi.write_memory(base, &calibration[..length]).await?
            }
            None => bmi.write_memory(base, &board[..profile.board]).await?,
        }
        bmi.write_u32(HI + 0x58, 1).await?;
        base
    };
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
    // A successful EEPROM download is Linux's `done` calibration mode: the
    // OTP calibration execution is skipped.
    if eeprom.is_none()
        && !calibration
            .as_ref()
            .is_some_and(|cal| cal.mode == Mode::Final)
    {
        bmi.fast_download(profile.patch, otp_bytes).await?;
        let result = bmi
            .execute(
                profile.patch,
                calibration
                    .as_ref()
                    .and_then(Calibration::otp_parameter)
                    .unwrap_or(profile.otp_parameter),
            )
            .await?;
        if result != 0 && image.features & (1 << 7) == 0 {
            return Err(Error::Calibration);
        }
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
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use narf_kernel_test::{kernel_test_in, TestResult};

    #[derive(Default)]
    struct Inputs {
        blobs: BTreeMap<String, Vec<u8>>,
        lookups: Vec<String>,
        refused: Option<String>,
    }
    impl Files for Inputs {
        fn load(&mut self, name: &str) -> Result<Vec<u8>, Error> {
            self.lookups.push(name.into());
            if self.refused.as_deref() == Some(name) {
                return Err(Error::Authority);
            }
            self.blobs.get(name).cloned().ok_or(Error::Missing)
        }
    }
    fn address() -> PcieAddr {
        PcieAddr {
            segment: 0x12,
            bus: 0x34,
            device: 0x1a,
            function: 5,
        }
    }
    fn profile() -> Profile {
        Profile::select(0x50, 0x4100016d).unwrap()
    }
    const PRE: &str = "ath10k/pre-cal-pci-0012:34:1a.5.bin";
    const FINAL: &str = "ath10k/cal-pci-0012:34:1a.5.bin";

    fn smoke_ath10k_cal_file_uses_exact_pci_function_and_precedence() -> TestResult {
        (|| {
            let p = profile();
            let mut files = Inputs::default();
            // Another function on the same card must not supply this radio's
            // factory data. These are inert authored bytes, never RF assets.
            files.blobs.insert(
                "ath10k/pre-cal-pci-0012:34:1a.4.bin".into(),
                alloc::vec![0x44; p.calibration],
            );
            if load(&mut files, Some(address()), p)?.is_some() || files.lookups != [PRE, FINAL] {
                return Err(Error::Unsupported);
            }
            files
                .blobs
                .insert(FINAL.into(), alloc::vec![0x55; p.calibration]);
            let final_cal = load(&mut files, Some(address()), p)?.ok_or(Error::Missing)?;
            if final_cal.mode != Mode::Final
                || final_cal.bytes != alloc::vec![0x55; p.calibration]
                || final_cal.otp_parameter().is_some()
            {
                return Err(Error::Calibration);
            }
            files
                .blobs
                .insert(PRE.into(), alloc::vec![0x66; p.calibration]);
            files.lookups.clear();
            let pre = load(&mut files, Some(address()), p)?.ok_or(Error::Missing)?;
            if pre.mode != Mode::Pre
                || pre.bytes != alloc::vec![0x66; p.calibration]
                || files.lookups != [PRE]
                || pre.board_id_parameter() != 0x8000
                || pre.otp_parameter() != Some(0x10000)
            {
                return Err(Error::Calibration);
            }
            files.lookups.clear();
            if load(&mut files, None, p)?.is_some() || !files.lookups.is_empty() {
                return Err(Error::Address);
            }
            Ok(())
        })()
        .map_or_else(
            |_| TestResult::Fail("calibration file identity/precedence"),
            |()| TestResult::Pass,
        )
    }
    kernel_test_in!(
        "drivers/wireless/ath10k/firmware",
        smoke_ath10k_cal_file_uses_exact_pci_function_and_precedence
    );

    fn smoke_ath10k_present_invalid_calibration_never_falls_back() -> TestResult {
        let p = profile();
        let mut files = Inputs::default();
        files
            .blobs
            .insert(FINAL.into(), alloc::vec![0x55; p.calibration]);
        for length in [0, 4, p.calibration - 1, p.calibration + 4] {
            files.blobs.insert(PRE.into(), alloc::vec![0; length]);
            files.lookups.clear();
            if !matches!(
                load(&mut files, Some(address()), p),
                Err(Error::Calibration)
            ) || files.lookups != [PRE]
            {
                return TestResult::Fail("malformed present pre-cal selected fallback");
            }
        }
        files.refused = Some(PRE.into());
        files.lookups.clear();
        if !matches!(load(&mut files, Some(address()), p), Err(Error::Authority))
            || files.lookups != [PRE]
        {
            return TestResult::Fail("refused pre-cal authority selected another source");
        }
        if !signed_input(PRE)
            || !signed_input(FINAL)
            || signed_input("ath10k/QCA988X/hw2.0/firmware-6.bin")
        {
            return TestResult::Fail("per-function calibration inherited executable policy");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/ath10k/firmware",
        smoke_ath10k_present_invalid_calibration_never_falls_back
    );
}

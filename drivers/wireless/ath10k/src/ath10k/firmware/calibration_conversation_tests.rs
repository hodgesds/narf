// SPDX-License-Identifier: GPL-2.0-or-later
//! Native BMI conversations over the ordinary boot-test target model.
use super::*;
use crate::ath10k::firmware::calibration::prepare_for_address;
use crate::ath10k::firmware::platform::{Platform, Source};
use narf_bus::PcieAddr;

const PRE: &str = "ath10k/pre-cal-pci-0002:03:04.1.bin";
const FINAL: &str = "ath10k/cal-pci-0002:03:04.1.bin";
fn address() -> Option<PcieAddr> {
    Some(PcieAddr::new(2, 3, 4, 1))
}
fn setup() -> (Profile, Identity, Store, Image) {
    let p = Profile::select(0x50, 0x4100016d).unwrap();
    let id = Identity {
        device: 0x50,
        ..identity()
    };
    let mut files = Store::default();
    files
        .0
        .insert(format!("{}/board.bin", p.directory), vec![0x55; p.board]);
    (p, id, files, Image::parse(image(0, 1, 1), 6).unwrap())
}

fn smoke_ath10k_pre_cal_download_precedes_flash_identity_and_native_otp() -> TestResult {
    let (p, id, mut files, image) = setup();
    files.0.insert(PRE.into(), vec![0x66; p.calibration]);
    files.0.insert(FINAL.into(), vec![0x77; p.calibration]);
    let mut bmi = Bmi::new(Target::default());
    if !matches!(
        ready(prepare_for_address(
            &mut bmi,
            &mut files,
            p,
            id,
            "",
            &image,
            address(),
            &Platform::default()
        )),
        Some(Ok(Some(_)))
    ) {
        return TestResult::Fail("pre-cal native boot failed");
    }
    let target = &bmi.transport;
    let mut board_bytes = Vec::new();
    for (at, bytes) in &target.writes {
        if (0x430000..0x430000 + p.board as u32).contains(at) {
            board_bytes.extend_from_slice(bytes);
        }
    }
    let first_board = target
        .sequence
        .iter()
        .position(|&(cmd, at, _)| cmd == 3 && at == 0x430000);
    let flash_id = target
        .sequence
        .iter()
        .position(|&(cmd, _, value)| cmd == 4 && value == 0x8000);
    if target.executions != [(p.patch, 0x8000), (p.patch, 0x10000)]
        || target.downloads != [vec![0x44; 4], vec![0x44; 4], vec![0x99; 4]]
        || board_bytes != [vec![0x66; p.calibration], vec![0x55; p.board]].concat()
        || !matches!((first_board, flash_id), (Some(board), Some(id)) if board < id)
        || !target.eeprom_queries.is_empty()
        || target.commands.contains(&1)
    {
        return TestResult::Fail("pre-cal file/identity/OTP/native board ordering");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/firmware",
    smoke_ath10k_pre_cal_download_precedes_flash_identity_and_native_otp
);

fn smoke_ath10k_final_cal_file_is_done_mode_without_eeprom_or_otp_calibration() -> TestResult {
    let (p, id, mut files, image) = setup();
    files.0.insert(FINAL.into(), vec![0x77; p.calibration]);
    let mut bmi = Bmi::new(Target::default());
    if !matches!(
        ready(prepare_for_address(
            &mut bmi,
            &mut files,
            p,
            id,
            "",
            &image,
            address(),
            &Platform::default()
        )),
        Some(Ok(Some(_)))
    ) {
        return TestResult::Fail("final cal native boot failed");
    }
    let target = &bmi.transport;
    let mut board_bytes = Vec::new();
    for (at, bytes) in &target.writes {
        if (0x430000..0x430000 + p.board as u32).contains(at) {
            board_bytes.extend_from_slice(bytes);
        }
    }
    if target.executions != [(p.patch, 0x10)]
        || target.downloads != [vec![0x44; 4], vec![0x99; 4]]
        || board_bytes != vec![0x77; p.calibration]
        || !target.eeprom_queries.is_empty()
        || !target
            .writes
            .iter()
            .any(|(at, bytes)| *at == HI + 0x58 && bytes == &1u32.to_le_bytes())
        || target.commands.contains(&1)
    {
        return TestResult::Fail("final cal did not retain Linux done-mode semantics");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/firmware",
    smoke_ath10k_final_cal_file_is_done_mode_without_eeprom_or_otp_calibration
);

fn smoke_ath10k_short_cal_geometry_and_otp_failure_never_activate_firmware() -> TestResult {
    for name in [PRE, FINAL] {
        let (p, id, mut files, image) = setup();
        files.0.insert(name.into(), vec![0x66; p.calibration]);
        let mut bmi = Bmi::new(Target {
            board_ext: 0x440000,
            ..Target::default()
        });
        if ready(prepare_for_address(
            &mut bmi,
            &mut files,
            p,
            id,
            "",
            &image,
            address(),
            &Platform::default(),
        )) != Some(Err(Error::Calibration))
            || bmi
                .transport
                .downloads
                .iter()
                .any(|bytes| *bytes == vec![0x99; 4])
            || bmi.transport.writes.iter().any(|(at, _)| *at == 0x440000)
        {
            return TestResult::Fail("short cal invented extension bytes or activated firmware");
        }
    }
    let (p, id, mut files, image) = setup();
    files.0.insert(PRE.into(), vec![0x66; p.calibration]);
    let mut bmi = Bmi::new(Target {
        failed_otp: true,
        ..Target::default()
    });
    if ready(prepare_for_address(
        &mut bmi,
        &mut files,
        p,
        id,
        "",
        &image,
        address(),
        &Platform::default(),
    )) != Some(Err(Error::Calibration))
        || bmi.transport.executions != [(p.patch, 0x8000), (p.patch, 0x10000)]
        || bmi
            .transport
            .downloads
            .iter()
            .any(|bytes| *bytes == vec![0x99; 4])
    {
        return TestResult::Fail("failed flash OTP calibration activated firmware");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/firmware",
    smoke_ath10k_short_cal_geometry_and_otp_failure_never_activate_firmware
);

/// Linux `ath10k_core_pre_cal_download`: a `pre-calibration` NVMEM cell
/// beats the pre-cal file and reaches host-interest memory before the FLASH
/// board-ID OTP; `ath10k_download_cal_data`: with no file, the
/// `qcom,calibration-data` property is done mode without EEPROM or OTP
/// calibration. A refused NVMEM provider never falls back to the file.
fn smoke_ath10k_platform_nvmem_pre_cal_and_dt_cal_drive_native_bmi() -> TestResult {
    let (p, id, mut files, image) = setup();
    files.0.insert(PRE.into(), vec![0x66; p.calibration]);
    let sources = Platform {
        pre_nvmem: Source::Present(vec![0x5a; p.calibration]),
        dt: Source::Present(vec![0x77; p.calibration]),
        ..Platform::default()
    };
    let mut bmi = Bmi::new(Target::default());
    if !matches!(
        ready(prepare_for_address(
            &mut bmi,
            &mut files,
            p,
            id,
            "",
            &image,
            address(),
            &sources
        )),
        Some(Ok(Some(_)))
    ) {
        return TestResult::Fail("NVMEM pre-cal native boot failed");
    }
    let target = &bmi.transport;
    let mut board_bytes = Vec::new();
    for (at, bytes) in &target.writes {
        if (0x430000..0x430000 + p.board as u32).contains(at) {
            board_bytes.extend_from_slice(bytes);
        }
    }
    if target.executions != [(p.patch, 0x8000), (p.patch, 0x10000)]
        || board_bytes != [vec![0x5a; p.calibration], vec![0x55; p.board]].concat()
        || !target.eeprom_queries.is_empty()
    {
        return TestResult::Fail("NVMEM pre-cal precedence/ordering");
    }

    let (p, id, mut files, image) = setup();
    let sources = Platform {
        dt: Source::Present(vec![0x77; p.calibration]),
        ..Platform::default()
    };
    let mut bmi = Bmi::new(Target::default());
    if !matches!(
        ready(prepare_for_address(
            &mut bmi,
            &mut files,
            p,
            id,
            "",
            &image,
            address(),
            &sources
        )),
        Some(Ok(Some(_)))
    ) {
        return TestResult::Fail("DT cal native boot failed");
    }
    let target = &bmi.transport;
    let mut board_bytes = Vec::new();
    for (at, bytes) in &target.writes {
        if (0x430000..0x430000 + p.board as u32).contains(at) {
            board_bytes.extend_from_slice(bytes);
        }
    }
    if target.executions != [(p.patch, 0x10)]
        || board_bytes != vec![0x77; p.calibration]
        || !target.eeprom_queries.is_empty()
    {
        return TestResult::Fail("DT cal did not retain Linux done-mode semantics");
    }

    let (p, id, mut files, image) = setup();
    files.0.insert(PRE.into(), vec![0x66; p.calibration]);
    let sources = Platform {
        pre_nvmem: Source::Refused(Error::Unsupported),
        ..Platform::default()
    };
    let mut bmi = Bmi::new(Target::default());
    if ready(prepare_for_address(
        &mut bmi,
        &mut files,
        p,
        id,
        "",
        &image,
        address(),
        &sources,
    )) != Some(Err(Error::Unsupported))
        || !bmi.transport.executions.is_empty()
    {
        return TestResult::Fail("unavailable NVMEM provider fell back to the file");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/firmware",
    smoke_ath10k_platform_nvmem_pre_cal_and_dt_cal_drive_native_bmi
);

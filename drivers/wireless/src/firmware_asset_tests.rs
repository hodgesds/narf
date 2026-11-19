// SPDX-License-Identifier: GPL-2.0-or-later
//! Facade-level smoke test for the shared `firmware_asset` helper.
//!
//! The helper itself lives in `narf-drivers-wireless-core`, but this test
//! drives it through a real firmware registry minted by the brcmfmac driver's
//! provisioning fixture — so it stays in the facade, which can reach
//! `crate::brcmfmac`, rather than in the core crate, which cannot depend on a
//! driver.
use crate::firmware_asset::{copy, load};
use narf_firmware::FirmwareError;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_wireless_asset_real_registry_epochs_owned_copy_and_bounds() -> TestResult {
    let (_, read) = crate::brcmfmac::provision::tests::registry().unwrap();
    let name = "narf-test/brcm/fw";
    let asset = load(&read, name, 8, true).unwrap();
    if asset.bytes != [0x44, 0x33, 0x22, 0x11, 9, 8, 7, 6]
        || !asset.current()
        || asset.signer.is_none()
        || !matches!(load(&read, name, 7, true), Err(FirmwareError::BadFormat))
        || !matches!(
            copy(&asset.cap, "narf-test/brcm/nv", 8, true),
            Err(FirmwareError::BadFormat)
        )
    {
        return TestResult::Fail(
            "current owned asset copy ignored exact identity, signer or extent",
        );
    }
    asset.cap.revoke();
    if asset.current()
        || !matches!(
            copy(&asset.cap, name, 8, true),
            Err(FirmwareError::AuthorityRevoked)
        )
        || asset.bytes != [0x44, 0x33, 0x22, 0x11, 9, 8, 7, 6]
    {
        return TestResult::Fail("revoked source cap remained usable or invalidated owned copy");
    }
    read.revoke();
    if !matches!(
        load(&read, name, 8, true),
        Err(FirmwareError::AuthorityRevoked)
    ) {
        return TestResult::Fail("revoked registry authority opened firmware asset");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/firmware_asset",
    smoke_wireless_asset_real_registry_epochs_owned_copy_and_bounds
);

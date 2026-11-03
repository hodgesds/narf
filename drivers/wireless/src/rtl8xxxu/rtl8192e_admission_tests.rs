//! Admission regressions. Records are synthetic dimensional fixtures only.
use super::*;
use crate::rtl8xxxu::firmware_transport::Owner;
use crate::rtl8xxxu::regs::ChipFamily;
use crate::rtl8xxxu::rtl8192e_policy::tests as policy;
use crate::rtl8xxxu::rtl8192e_tests::{image, Fake};
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_rtl8192eu_admission_requires_record_policy_and_radio() -> TestResult {
    let nf = || Err(PolicyError::Firmware(FirmwareError::NotFound));
    let domain = Ok(policy::domain(30, 40));
    let missing = Err(narf_wireless::reg::policy::Error::Firmware(
        FirmwareError::NotFound,
    ));
    if classify(true, true, &domain, &nf()) != Ok(Admission::PendingAssets)
        || classify(true, true, &missing, &nf()) != Ok(Admission::PendingAssets)
        || classify(true, true, &domain, &Err(PolicyError::Unsigned)) != Err(Error::Profile)
        || classify(true, true, &domain, &Err(PolicyError::Identity)) != Err(Error::Profile)
    {
        return TestResult::Fail("8192eu unprovisioned/invalid record classification");
    }
    let owner = Owner::new(Fake::new(), ChipFamily::Rtl8192eu);
    // Not RadioReady: nothing is admitted.
    let f = policy::factory(true);
    let early = policy::parse(&policy::record(&f, 0x0fff_ffff, &[(1, 0, 40)]), &f).unwrap();
    if admit(&owner, policy::domain(30, 40), early).err() != Some(Error::State) {
        return TestResult::Fail("8192eu admitted before RadioReady");
    }
    if narf_scheduler::block_on(owner.initialize_device(&image(300))).is_err() {
        return TestResult::Fail("8192eu fixture lifecycle");
    }
    let factory = owner.factory_8192e().unwrap();
    let ok = policy::parse(
        &policy::record(&factory, 0x0fff_ffff, &[(1, 0, 40)]),
        &factory,
    )
    .unwrap();
    if classify(true, true, &domain, &Ok(ok)) != Ok(Admission::Ready) {
        return TestResult::Fail("8192eu provisioned record not ready");
    }
    let ok = policy::parse(
        &policy::record(&factory, 0x0fff_ffff, &[(1, 0, 40)]),
        &factory,
    )
    .unwrap();
    if classify(false, true, &domain, &Ok(ok)) != Ok(Admission::PendingAssets) {
        return TestResult::Fail("8192eu admitted without net authority");
    }
    let ok = policy::parse(
        &policy::record(&factory, 0x0fff_ffff, &[(1, 0, 40)]),
        &factory,
    )
    .unwrap();
    let admitted = match admit(&owner, policy::domain(30, 40), ok) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("8192eu provisioned admission refused"),
    };
    if admitted.permission.primary() != INITIAL_PRIMARY
        || admitted.permission.width() != INITIAL_WIDTH
        || admitted.permission.admitted() != 0x0fff_ffff
    {
        return TestResult::Fail("8192eu initial permission");
    }
    // A record without the initial channel row is refused, not defaulted.
    let other = policy::parse(
        &policy::record(&factory, 0x0fff_ffff, &[(6, 0, 40)]),
        &factory,
    )
    .unwrap();
    if admit(&owner, policy::domain(30, 40), other).err() != Some(Error::Profile) {
        return TestResult::Fail("8192eu admitted without the initial channel row");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8192eu",
    smoke_rtl8192eu_admission_requires_record_policy_and_radio
);

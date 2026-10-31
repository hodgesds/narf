//! API89 ALIVE/unified initialization over actual Ax210 RFH/TFH queues.
//! The test supplies firmware execution; no physical PCI or RF is claimed.
use super::super::gen3_fixture::Case;
use super::*;
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
struct Fixture {
    hardware: Option<Hardware>,
    firmware: model::Firmware,
    trace: model::TxTrace,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(hardware) = self.hardware.take() {
            // SAFETY: no future or physical DMA remains. This fixture owns
            // every RAM queue, and destroys the hardware before its views.
            unsafe { model::destroy(hardware) };
        }
    }
}
#[inline(never)]
fn fixture(
    case: Case,
    parsed: &ParsedUcode<'_>,
) -> Result<alloc::boxed::Box<Fixture>, &'static str> {
    let (mut hardware, mut firmware, trace) =
        model::station_model_for_format(rx_rfh::CompletionFormat::Ax210);
    model::api89_identity(&mut hardware, case.did(), case.revision(), case.radio())?;
    model::firmware_profile(&mut hardware, parsed)?;
    hardware.prepare_station_profile(parsed)?;
    firmware.register(0x388, 0x02020202);
    firmware.register(0x38c, 0x0202);
    Ok(alloc::boxed::Box::new(Fixture {
        hardware: Some(hardware),
        firmware,
        trace,
    }))
}
fn smoke_api89_alive6_selects_native_mvm_unified_receipts_independent_of_rfh_format() -> TestResult
{
    (|| {
        for case in [Case::Ty, Case::SoCdb, Case::Ma] {
            let image = case.image();
            let parsed =
                super::super::parse_ucode(&image).map_err(|_| "API89 cold fixture metadata")?;
            let mut fixture = fixture(case, &parsed)?;
            let mut alive = alloc::vec![0;144];
            alive[..2].copy_from_slice(&0xcafeu16.to_le_bytes());
            fixture.firmware.inject(1, 0, 0x8000, &alive);
            let Fixture {
                hardware,
                firmware,
                trace,
            } = &mut *fixture;
            let mut boot = alloc::boxed::Box::pin(hardware.as_mut().unwrap().finish_boot(&parsed));
            let mut cx = Context::from_waker(Waker::noop());
            let deadline = narf_time::Deadline::after_ms(1000);
            let mut count = 0;
            loop {
                if let Poll::Ready(result) = boot.as_mut().poll(&mut cx) {
                    if result != Ok([2; 6]) || count != 2 {
                        return Err("API89 ALIVE6 used Sc init or returned wrong native MAC");
                    }
                    break;
                }
                while let Some(command) = trace.take() {
                    let expected = match count {
                        0 => [3, 2, 0, 0, 4, 0, 0, 0, 2, 0, 0, 0],
                        1 => [0, 12, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0],
                        _ => {
                            return Err("API89 unified init published unexpected PHY/PNVM command")
                        }
                    };
                    if command.queue != 0 || command.bytes.as_slice() != expected {
                        return Err("API89 independent native unified command/header literal");
                    }
                    firmware.inject(
                        expected[0],
                        expected[1],
                        u16::from_le_bytes([expected[2], expected[3]]),
                        &[],
                    );
                    count += 1;
                    if count == 2 {
                        firmware.inject(4, 0, 0x8000, &[]);
                    }
                }
                if deadline.expired() {
                    return Err("API89 actual ALIVE/unified completion bound");
                }
                narf_scheduler::sleep_pumps::run();
                core::hint::spin_loop();
            }
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/api89",
    smoke_api89_alive6_selects_native_mvm_unified_receipts_independent_of_rfh_format
);

fn smoke_api89_actual_alive_sku_requires_owned_pnvm_before_initialization() -> TestResult {
    (|| {
        let image = Case::Ty.image();
        let parsed = super::super::parse_ucode(&image).map_err(|_| "API89 SKU fixture metadata")?;
        let mut fixture = fixture(Case::Ty, &parsed)?;
        let mut alive = alloc::vec![0;144];
        alive[..2].copy_from_slice(&0xcafeu16.to_le_bytes());
        alive[116..128].fill(0x51);
        fixture.firmware.inject(1, 0, 0x8000, &alive);
        let mut boot =
            alloc::boxed::Box::pin(fixture.hardware.as_mut().unwrap().finish_boot(&parsed));
        let result = boot.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        drop(boot);
        if !matches!(result, Poll::Ready(Err("firmware needs external PNVM")))
            || fixture.trace.take().is_some()
        {
            return Err("API89 SKU borrowed absent calibration or initialized firmware early");
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/api89",
    smoke_api89_actual_alive_sku_requires_owned_pnvm_before_initialization
);

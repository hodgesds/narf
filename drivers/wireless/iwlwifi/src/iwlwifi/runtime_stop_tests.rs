//! Native stop ordering and uncertain-DMA retention. The explicit RAM
//! transport owns no PCI function or real DMA engine; CSR writes use the
//! same capability-checked MMIO path as production.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn check(test: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    test().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
fn smoke_iwl_native_stop_timeout_still_resets_and_disables_bme_but_pins_dma() -> TestResult {
    check(|| {
        for format in [
            rx_rfh::CompletionFormat::Qu,
            rx_rfh::CompletionFormat::Ax210,
            rx_rfh::CompletionFormat::Bz,
        ] {
            let (mut hardware, _firmware) = model::create_for_format(true, format);
            let retained = model::retained(&hardware);
            // Model only: simulate ownership without programming any physical
            // device. Its uncompleted native queue allocations remain real.
            hardware.armed = true;
            let mut disabled = false;
            let result = hardware.finish_stop(Err("test missing DMA stop ACK"), || {
                disabled = true;
                Ok(())
            });
            let (register, reset) = if format == rx_rfh::CompletionFormat::Bz {
                (super::super::regs::CSR_GP_CNTRL, 1 << 31)
            } else {
                (super::super::regs::CSR_RESET, 1 << 7)
            };
            let valid = result == Err("test missing DMA stop ACK")
                && disabled
                && hardware.mmio.read(register) & reset != 0
                && hardware.armed
                && model::retained(&hardware) == retained
                && retained.2 == 1;
            let bme_failure = hardware.finish_stop(Ok(()), || Err("test BME disable denied"));
            let valid = valid
                && bme_failure == Err("test BME disable denied")
                && hardware.armed
                && model::retained(&hardware) == retained;
            hardware.armed = false;
            // SAFETY: the private RAM constructor never programmed a device;
            // the simulated armed flag does not represent physical DMA.
            unsafe {
                model::destroy(hardware);
            }
            if !valid {
                return Err("missing DMA ACK skipped reset/BME or released native ownership");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/policy",
    smoke_iwl_native_stop_timeout_still_resets_and_disables_bme_but_pins_dma
);

fn smoke_iwl_native_stop_async_missing_ack_is_bounded_and_keeps_owned_queues() -> TestResult {
    check(|| {
        for format in [
            rx_rfh::CompletionFormat::Ax210,
            rx_rfh::CompletionFormat::Bz,
        ] {
            let (mut hardware, mut firmware) = model::create_for_format(true, format);
            let retained = model::retained(&hardware);
            let (register, request, reset) = if format == rx_rfh::CompletionFormat::Bz {
                (super::super::regs::CSR_GP_CNTRL, 1 << 29, 1 << 31)
            } else {
                (super::super::regs::CSR_RESET, 1 << 9, 1 << 7)
            };
            firmware.register(register, 0); // no device-side DMA-stop ACK
            hardware.armed = true;
            let result = narf_scheduler::block_on_spin(hardware.stop_for_suspend());
            let valid = result == Err("Wi-Fi register timeout")
                && hardware.is_failed()
                && hardware.mmio.read(register) & (request | reset) == request | reset
                && hardware.armed
                && model::retained(&hardware) == retained;
            hardware.armed = false;
            // SAFETY: no physical DMA exists in this explicit RAM fixture.
            unsafe {
                model::destroy(hardware);
            }
            if !valid {
                return Err("async DMA timeout skipped attempted RF reset or unpinned queues");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/policy",
    smoke_iwl_native_stop_async_missing_ack_is_bounded_and_keeps_owned_queues
);

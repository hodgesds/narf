//! Real object-table firmware/PNVM revocation around private native DMA.
use super::*;
use crate::iwlwifi::{
    runtime::{model, Hardware},
    rx_rfh::CompletionFormat,
};
use core::{
    future::Future,
    pin::{pin, Pin},
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
pub(in crate::iwlwifi) fn inputs() -> Result<(Asset, Asset), &'static str> {
    let (write, read) = narf_firmware::bootstrap_authority();
    let bytes = crate::iwlwifi::firmware_parser_tests::mld_image();
    for (name, bytes) in [
        ("narf-test/iwl-native-source/executable", bytes.as_slice()),
        ("narf-test/iwl-native-source/pnvm", &[9u8; 32][..]),
    ] {
        crate::firmware_asset::tests::install(&write, name, bytes, true)
            .map_err(|_| "native source test install")?;
    }
    Ok((
        crate::firmware_asset::load(
            &read,
            "narf-test/iwl-native-source/executable",
            16 * 1024 * 1024,
            true,
        )
        .map_err(|_| "native executable source load")?,
        crate::firmware_asset::load(&read, "narf-test/iwl-native-source/pnvm", 64, true)
            .map_err(|_| "native PNVM source load")?,
    ))
}
struct Transport {
    hardware: Option<Hardware>,
    firmware: model::Firmware,
    trace: model::TxTrace,
}
impl Drop for Transport {
    fn drop(&mut self) {
        if let Some(hw) = self.hardware.take() {
            // SAFETY: no native future/actor remains; this is exclusively the private
            // RAM transport. No physical PCI function ever received its addresses.
            unsafe { model::destroy(hw) };
        }
    }
}
fn poll<T>(f: Pin<&mut impl Future<Output = T>>) -> Poll<T> {
    let result = f.poll(&mut Context::from_waker(Waker::noop()));
    if result.is_pending() {
        narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
            2_000_000,
        )));
    }
    result
}
fn check(f: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    f().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
fn smoke_iwl_native_source_binding_rejects_changed_copy_and_rebind() -> TestResult {
    check(|| {
        let (mut executable, pnvm) = inputs()?;
        let (hw, firmware, trace) = model::station_model_for_format(CompletionFormat::Bz);
        let mut t = Transport {
            hardware: Some(hw),
            firmware,
            trace,
        };
        executable.bytes[0] ^= 1;
        if t.hardware
            .as_mut()
            .unwrap()
            .bind_sources(&executable, Some(&pnvm))
            .is_ok()
        {
            return Err("altered executable copy bound a genuine firmware capability");
        }
        executable.bytes[0] ^= 1;
        t.hardware
            .as_mut()
            .unwrap()
            .bind_sources(&executable, Some(&pnvm))?;
        let (replacement, other) = inputs()?;
        if t.hardware
            .as_mut()
            .unwrap()
            .bind_sources(&replacement, Some(&other))
            .is_ok()
        {
            return Err("native source owner rebound without full lifecycle proof");
        }
        if t.trace.take().is_some() {
            return Err("source validation emitted native I/O");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/runtime",
    smoke_iwl_native_source_binding_rejects_changed_copy_and_rebind
);
fn smoke_iwl_native_executable_or_pnvm_revocation_pins_real_packet_dma_and_never_reinstalls(
) -> TestResult {
    check(|| {
        for format in [
            CompletionFormat::Qu,
            CompletionFormat::Ax210,
            CompletionFormat::Bz,
        ] {
            for which in 0..2 {
                let (executable, pnvm) = inputs()?;
                let (mut hw, firmware, trace) = model::station_model_for_format(format);
                model::versions(&mut hw, &[0x17, 5, 3, 0]);
                hw.bind_sources(&executable, Some(&pnvm))?;
                let mut t = Transport {
                    hardware: Some(hw),
                    firmware,
                    trace,
                };
                {
                    let mut f = pin!(t.hardware.as_mut().unwrap().allocate_tx(0, 0));
                    if !poll(f.as_mut()).is_pending() {
                        return Err("source allocation did not publish native DMA");
                    }
                    t.trace.take().ok_or("source queue ADD trace missing")?;
                    t.firmware.inject(0x17, 5, 0, &[17, 0, 0, 0, 0, 0, 0, 0]);
                    if !matches!(poll(f.as_mut()), Poll::Ready(Ok(17))) {
                        return Err("source native queue receipt");
                    }
                }
                t.hardware
                    .as_mut()
                    .unwrap()
                    .enqueue_transmit(17, &[0; 26], 26, None)?;
                let packet = t.trace.take().ok_or("source packet DMA absent")?;
                if which == 0 {
                    executable.cap.revoke();
                } else {
                    pnvm.cap.revoke();
                }
                t.firmware.tx_complete(17, packet.pointer);
                if t.hardware.as_mut().unwrap().poll().is_ok()
                    || model::retained(t.hardware.as_ref().unwrap()) != (0, 1, 1)
                {
                    return Err("revoked native source reclaimed unvalidated packet DMA");
                }
                let _replacement = inputs()?;
                if t.hardware
                    .as_mut()
                    .unwrap()
                    .enqueue_transmit(17, &[0; 26], 26, None)
                    .is_ok()
                    || t.hardware
                        .as_ref()
                        .unwrap()
                        .source_fence()?
                        .invoke(|| Ok(()))
                        .is_ok()
                    || t.trace.take().is_some()
                {
                    return Err("source reinstall revived native I/O/publication");
                }
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/runtime",
    smoke_iwl_native_executable_or_pnvm_revocation_pins_real_packet_dma_and_never_reinstalls
);

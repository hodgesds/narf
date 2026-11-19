//! Bz ALIVE7 / MLD INIT_PHY and exact ABI admission over real RAM queues.
use super::super::bz_fixture::Case;
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
            // SAFETY: the fixture owns all RAM endpoints. No borrowed future
            // or physical DMA survives destruction of this unarmed model.
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
        model::station_model_for_format(rx_rfh::CompletionFormat::Bz);
    model::native_station_identity(&mut hardware, case.did(), case.revision(), case.radio())?;
    model::firmware_profile(&mut hardware, parsed)?;
    for offset in [0x30, 0x34, 0x38, 0x3c] {
        firmware.register(offset, 0x02020202);
    }
    Ok(alloc::boxed::Box::new(Fixture {
        hardware: Some(hardware),
        firmware,
        trace,
    }))
}
fn smoke_bz_core103_alive7_uses_native_mld_phy_init_and_csr_mac() -> TestResult {
    (|| {
        for case in [Case::FmDiscrete, Case::WhIntegrated] {
            let image = case.image();
            let parsed =
                super::super::parse_ucode(&image).map_err(|_| "Bz ALIVE fixture metadata")?;
            let mut fixture = fixture(case, &parsed)?;
            fixture
                .hardware
                .as_mut()
                .unwrap()
                .prepare_station_profile(&parsed)?;
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
                        return Err("Bz ALIVE7 selected wrong init/native MAC");
                    }
                    break;
                }
                while let Some(command) = trace.take() {
                    let expected = match count {
                        0 => alloc::vec![3, 2, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0],
                        1 => {
                            let mut bytes =
                                alloc::vec![0x6a, 1, 1, 0, 28, 0, 0, 0, 0x18, 0, 0x33, 0];
                            bytes.resize(36, 0);
                            bytes
                        }
                        _ => return Err("Bz MLD init published unexpected NVM/extra command"),
                    };
                    if command.queue != 0 || command.bytes != expected {
                        return Err("Bz independent native INIT_PHY/header literal");
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
                    return Err("Bz ALIVE7/INIT_PHY native completion bound");
                }
                narf_scheduler::sleep_pumps::run();
            }
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/bz103",
    smoke_bz_core103_alive7_uses_native_mld_phy_init_and_csr_mac
);
fn smoke_bz_core103_actual_metadata_refuses_old_or_incompatible_abi_before_commands() -> TestResult
{
    (|| {
        for which in 0..5 {
            let mut image = Case::FmDiscrete.image();
            if which == 0 {
                image[72..76].copy_from_slice(&100u32.to_le_bytes());
            } else {
                // Authored command table is the first TLV; change one real
                // producer/consumer fact while retaining all other metadata.
                let length = u32::from_le_bytes(image[92..96].try_into().unwrap()) as usize;
                let (group, opcode, field, value) = match which {
                    1 => (1, 0x1c, 2, 10),
                    2 => (0, 1, 3, 8),
                    3 => (5, 0xd, 2, 1),
                    _ => (3, 9, 2, 7),
                };
                let row = image[96..96 + length]
                    .chunks_exact_mut(4)
                    .find(|v| v[0] == opcode && v[1] == group)
                    .ok_or("Bz factual fixture row absent")?;
                row[field] = value;
            }
            let parsed =
                super::super::parse_ucode(&image).map_err(|_| "Bz incompatible metadata parse")?;
            let mut fixture = fixture(Case::FmDiscrete, &parsed)?;
            if fixture
                .hardware
                .as_mut()
                .unwrap()
                .prepare_station_profile(&parsed)
                .is_ok()
                || fixture.trace.take().is_some()
                || !fixture.hardware.as_ref().unwrap().resources.data.is_empty()
            {
                return Err("Bz incompatible profile reached commands or station DMA");
            }
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/bz103",
    smoke_bz_core103_actual_metadata_refuses_old_or_incompatible_abi_before_commands
);

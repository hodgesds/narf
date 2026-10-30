use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn fixed_gpe_gas_never_reinterprets_memory_or_wrapping_ports() -> TestResult {
    let valid = GpeBlockInfo {
        address: 0x700,
        byte_count: 4,
        base_gsi: 64,
        address_space: 1,
        bit_offset: 0,
        access_size: 1,
    };
    if !super::super::gpe_byte_ports_valid(valid) {
        return TestResult::Fail("literal fixed GPE byte-port GAS rejected");
    }
    for malformed in [
        GpeBlockInfo {
            address_space: 0,
            ..valid
        },
        GpeBlockInfo {
            address_space: 2,
            ..valid
        },
        GpeBlockInfo {
            address: 0x1_0700,
            ..valid
        },
        GpeBlockInfo {
            address: 0xfffe,
            ..valid
        },
        GpeBlockInfo {
            bit_offset: 1,
            ..valid
        },
        GpeBlockInfo {
            access_size: 2,
            ..valid
        },
        GpeBlockInfo {
            byte_count: 3,
            ..valid
        },
        GpeBlockInfo {
            byte_count: 0,
            ..valid
        },
    ] {
        if super::super::gpe_byte_ports_valid(malformed) {
            return TestResult::Fail("unsupported GAS geometry became byte-port authority");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "acpi/gpe_wake",
    fixed_gpe_gas_never_reinterprets_memory_or_wrapping_ports
);

#[cfg(target_arch = "x86_64")]
fn native_wake_gpe_retains_shared_runtime_enables_and_failed_readback_owner() -> TestResult {
    let block = GpeBlockInfo {
        address: 0x700,
        byte_count: 4,
        base_gsi: 64,
        address_space: 1,
        bit_offset: 0,
        access_size: 1,
    };
    // EC69 pending+enabled, stale70 pending.
    let mut bytes = [0x60, 0, 0x20, 0];
    // SAFETY: this serialized kernel smoke owns the complete scoped model;
    // every live lease is released before the model guard restores FADT.
    let mut registers = match unsafe { __test_registers(block, &mut bytes) } {
        Ok(model) => model,
        Err(_) => return TestResult::Fail("GPE byte model registration failed"),
    };
    let claim_model = |number| {
        // SAFETY: the scoped fixture above owns the exact RAM/W1C registers,
        // and all claims below retire before that fixture is restored.
        unsafe { claim(number) }
    };
    let release_model = |lease: &mut WakeGpe| {
        // SAFETY: this token belongs to the same live scoped register model;
        // the test retains its exact ownership until release returns.
        unsafe { release(lease) }
    };
    let mut lease = match claim_model(70) {
        Ok(lease) => lease,
        Err(_) => return TestResult::Fail("disabled actual bit could not be claimed"),
    };
    if !lease.enabled() || !armed(70) || registers.byte(0) != 0x20 || registers.byte(2) != 0x60 {
        return TestResult::Fail(
            "wake arm erased shared runtime status or failed to clear disabled stale status",
        );
    }
    if !matches!(claim_model(70), Err(WakeGpeError::Busy)) || registers.byte(2) != 0x60 {
        return TestResult::Fail("duplicate wake owner changed the shared enable register");
    }
    // A runtime consumer enabled while a lease exists must survive terminal
    // wake cleanup, even when it shares the same physical enable byte.
    super::super::enable_gpe(71);
    if release_model(&mut lease).is_err() || armed(70) || registers.byte(2) != 0xa0 {
        return TestResult::Fail(
            "wake cleanup lost another runtime enable or retained its own bit",
        );
    }
    registers.set_byte(0, 0xa0);
    let mut existing = claim_model(71).unwrap();
    if registers.byte(0) != 0xa0 {
        return TestResult::Fail("claim erased an already-enabled runtime GPE event");
    }
    if release_model(&mut existing).is_err() || registers.byte(2) != 0xa0 {
        return TestResult::Fail("already-enabled runtime GPE was disabled after wake");
    }
    registers.set_stuck_enable(0x40);
    let mut failed = claim_model(70).unwrap();
    if failed.enabled() || armed(70) || !matches!(claim_model(70), Err(WakeGpeError::Busy)) {
        return TestResult::Fail(
            "failed enable readback released ambiguous ownership or armed wake",
        );
    }
    if release_model(&mut failed).is_err() {
        return TestResult::Fail("failed enable claim could not be explicitly retired");
    }
    registers.set_stuck_enable(0);
    let mut again = claim_model(70).unwrap();
    if !again.enabled() || release_model(&mut again).is_err() {
        return TestResult::Fail("terminal cleanup prevented a new exact GPE claim");
    }
    let (status, count) = super::super::gpe_block_status_irq(block);
    if count != 2 || status[..2] != [0xa0, 0] {
        return TestResult::Fail("real SCI register reader did not use the scoped W1C result");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "acpi/gpe_wake",
    native_wake_gpe_retains_shared_runtime_enables_and_failed_readback_owner
);

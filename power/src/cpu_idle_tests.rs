use crate::cpu_idle::decode_cst;
use alloc::vec;
use narf_aml::Value;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_power_core::IdleEntry;

fn state(space: u8, width: u8, offset: u8, address: u64, kind: u64, latency: u64) -> Value {
    let mut gas = vec![0x82, 12, 0, space, width, offset, 0];
    gas.extend_from_slice(&address.to_le_bytes());
    gas.extend_from_slice(&[0x79, 0]);
    Value::Package(vec![
        Value::Buffer(gas),
        Value::Integer(kind),
        Value::Integer(latency),
        Value::Integer(0),
    ])
}
fn package(states: alloc::vec::Vec<Value>) -> Value {
    let mut all = vec![Value::Integer(states.len() as u64)];
    all.extend(states);
    Value::Package(all)
}

fn cst_preserves_firmware_encodings() -> TestResult {
    let value = package(vec![
        state(0x7f, 1, 2, 0x31, 3, 200),
        state(1, 8, 0, 0x414, 2, 18),
        state(1, 8, 0, 0x415, 3, 350),
    ]);
    let Some(states) = decode_cst(&value) else {
        return TestResult::Fail("valid _CST refused");
    };
    if states.len() != 3
        || !matches!(states[0].entry, IdleEntry::Mwait { hint: 0x31 })
        || !matches!(
            states[1].entry,
            IdleEntry::SystemIo {
                port: 0x414,
                acpi_type: 2
            }
        )
        || !matches!(
            states[2].entry,
            IdleEntry::SystemIo {
                port: 0x415,
                acpi_type: 3
            }
        )
        || states[2].target_residency_us != 700
        || states[0].id == states[2].id
    {
        return TestResult::Fail("firmware entry or latency changed");
    }
    TestResult::Pass
}
kernel_test_in!("power/idle", cst_preserves_firmware_encodings);

fn cst_rejects_malformed_tables() -> TestResult {
    let malformed = [
        Value::Integer(0),
        Value::Package(vec![]),
        Value::Package(vec![Value::Integer(2), state(1, 8, 0, 0x414, 2, 18)]),
        package(vec![Value::Package(vec![Value::Integer(0)])]),
        package(vec![state(1, 8, 0, 0x414, 2, u64::MAX)]),
    ];
    if malformed.iter().any(|value| decode_cst(value).is_some()) {
        return TestResult::Fail("malformed _CST accepted");
    }
    for bad in [
        state(0, 8, 0, 0x414, 2, 18),
        state(1, 32, 0, 0x414, 2, 18),
        state(1, 8, 0, 0x1_0414, 2, 18),
        state(1, 8, 0, 0, 2, 18),
        state(0x7f, 1, 3, 0x20, 3, 50),
        state(1, 8, 0, 0x414, 0, 18),
    ] {
        if decode_cst(&package(vec![bad])).is_some_and(|states| !states.is_empty()) {
            return TestResult::Fail("unsupported resource admitted");
        }
    }
    let good = state(1, 8, 0, 0x414, 2, 18);
    let Value::Package(fields) = &good else {
        unreachable!()
    };
    let Value::Buffer(gas) = &fields[0] else {
        unreachable!()
    };
    for len in 0..gas.len() {
        let mut truncated = fields.clone();
        truncated[0] = Value::Buffer(gas[..len].to_vec());
        if decode_cst(&package(vec![Value::Package(truncated)]))
            .is_some_and(|states| !states.is_empty())
        {
            return TestResult::Fail("truncated register admitted");
        }
    }
    TestResult::Pass
}
kernel_test_in!("power/idle", cst_rejects_malformed_tables);

use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

#[path = "strict_review_tests.rs"]
mod review;

pub(crate) fn package(opcode: &[u8], payload: &[u8]) -> Vec<u8> {
    let length = payload.len() + 2;
    assert!(length < 4096);
    let mut bytes = opcode.to_vec();
    bytes.extend_from_slice(&[0x40 | (length as u8 & 15), (length >> 4) as u8]);
    bytes.extend_from_slice(payload);
    bytes
}

fn method(name: &[u8; 4], flags: u8, body: &[u8]) -> Vec<u8> {
    let mut payload = name.to_vec();
    payload.push(flags);
    payload.extend_from_slice(body);
    package(&[0x14], &payload)
}

fn device(name: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut payload = name.to_vec();
    payload.extend_from_slice(body);
    package(&[0x5b, 0x82], &payload)
}

fn parse(body: &[u8]) -> Result<(), &'static str> {
    crate::__parse_body_for_test(body, "\\")
        .map(|_| ())
        .map_err(|_| "strict fixture AML parse failed")
}

fn native_scoped_names_and_nested_method_failures_are_real_receipts() -> Result<(), &'static str> {
    // SAFETY: this serialized smoke owns namespace/OpRegion evaluation and
    // restores both tables before the runner invokes another subsystem.
    let _namespace = unsafe { crate::__test_namespace_scope() };
    let mut body = alloc::vec![0x08, b'V', b'A', b'L', b'U', 0];
    body.extend_from_slice(&method(
        b"HELP",
        1,
        &[
            0x70, 0x68, b'V', b'A', b'L', b'U', 0xa4, b'V', b'A', b'L', b'U',
        ],
    ));
    body.extend_from_slice(&method(b"GOOD", 1, b"HELP\x68\xa4VALU"));
    // A truncated helper must fail callers that discard its value and
    // callers that use the value; the compatibility evaluator drops both.
    body.extend_from_slice(&method(b"BADH", 0, &[0xa4, 0x0a]));
    body.extend_from_slice(&method(b"CALL", 0, b"BADH"));
    body.extend_from_slice(&method(b"CAL2", 0, b"\xa4BADH"));
    body.extend_from_slice(&method(b"MISS", 0, b"\xa4DECO"));
    body.extend_from_slice(&method(b"UNKN", 0, &[0x5b, 0x34]));
    body.extend_from_slice(&method(b"ARGS", 1, &[0xa4, 0x69]));
    body.extend_from_slice(&method(b"SERL", 0x08, &[0xa4, 1]));
    body.extend_from_slice(&method(b"LOOP", 0, b"LOOP"));
    let mut while_body = alloc::vec![1, 0xa3];
    let while_term = package(&[0xa2], &while_body);
    body.extend_from_slice(&method(b"BUSY", 0, &while_term));
    while_body.clear();
    let mut root = device(b"ZST0", &body);
    root.extend_from_slice(&device(b"ZST1", b"\x08DECO\x0a\x55"));
    parse(&root)?;
    if evaluate_method("\\ZST0.GOOD", &[Value::Integer(0x6d)])
        != Ok(Completion::Value(Value::Integer(0x6d)))
        || evaluate_object("\\ZST0.VALU", &[]) != Ok(Value::Integer(0x6d))
    {
        return Err("strict Store/call/Return did not retain the exact scoped value");
    }
    for path in ["\\ZST0.CALL", "\\ZST0.CAL2"] {
        if evaluate_method(path, &[]) != Err(Error::Bounds) {
            return Err("strict method call discarded a nested helper failure");
        }
        if crate::eval::evaluate_method(path, &[]).is_err() {
            return Err("opt-in strict mode changed the compatibility evaluator");
        }
    }
    if evaluate_method("\\ZST0.MISS", &[]) != Err(Error::Missing)
        || evaluate_method("\\ZST0.UNKN", &[]) != Err(Error::Unsupported)
        || evaluate_method("\\ZST0.ARGS", &[Value::Integer(1)]) != Err(Error::Arguments)
        || evaluate_method("\\ZST0.SERL", &[]) != Err(Error::Arguments)
    {
        return Err(
            "unknown opcode/name, missing argument or unsupported method lock became success",
        );
    }
    for path in ["\\ZST0.LOOP", "\\ZST0.BUSY"] {
        if evaluate_method(path, &[]) != Err(Error::Budget) {
            return Err("strict recursion/loop escaped its shared bounded budget");
        }
    }
    Ok(())
}

fn unsupported_or_failed_opregion_operations_never_become_success() -> Result<(), &'static str> {
    // SAFETY: serialized namespace/register-table scope, no hardware fields
    // in the fixture can be admitted by the checked accessor.
    let _namespace = unsafe { crate::__test_namespace_scope() };
    let mut body = alloc::vec![0x5b, 0x80, b'R', b'E', b'G', b'N', 8, 0, 1]; // GPIO region: legacy stub
    let field = package(&[0x5b, 0x81], b"REGN\x01BITS\x08");
    body.extend_from_slice(&field);
    body.extend_from_slice(&method(b"READ", 0, b"\xa4BITS"));
    body.extend_from_slice(&method(b"WRIT", 0, b"\x70\x01BITS\xa4\x01"));
    parse(&device(b"ZRG0", &body))?;
    if crate::oregion::write_field("\\ZRG0.BITS", 1).is_err() {
        return Err("fixture did not exercise the existing unsupported-space success stub");
    }
    let expected = Error::Field(crate::oregion::FieldAccessError::Unsupported);
    if evaluate_method("\\ZRG0.READ", &[]) != Err(expected)
        || evaluate_method("\\ZRG0.WRIT", &[]) != Err(expected)
    {
        return Err("strict Field read/write accepted an unsupported hardware-space stub");
    }
    // A recognized Field whose region was never registered is a hardware
    // access error, not a namespace read of Integer(0).
    crate::push_field_node(String::from("\\ZRG0.LOST"));
    crate::oregion::register_field(crate::oregion::FieldInfo {
        path: String::from("\\ZRG0.LOST"),
        region_path: String::from("\\ZRG0.NONE"),
        bit_offset: 0,
        bit_length: 8,
        access_kind: 1,
        update_rule: 0,
        lock_rule: false,
        index_field: None,
        bank_field: None,
    });
    if evaluate_object("\\ZRG0.LOST", &[])
        != Err(Error::Field(crate::oregion::FieldAccessError::NoRegion))
    {
        return Err("strict Field read discarded the native missing-region error");
    }
    Ok(())
}

fn scoped_receipts() -> TestResult {
    native_scoped_names_and_nested_method_failures_are_real_receipts()
        .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!("aml/strict", scoped_receipts);

fn field_receipts() -> TestResult {
    unsupported_or_failed_opregion_operations_never_become_success()
        .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!("aml/strict", field_receipts);

#[cfg(target_arch = "x86_64")]
fn checked_ec_contention_fails_without_unbounded_gate_wait() -> TestResult {
    // SAFETY: serialized namespace/register-table scope. The live EC ports
    // are never accessed because the explicitly held transaction gate must
    // make checked admission fail first.
    let _namespace = unsafe { crate::__test_namespace_scope() };
    let mut body = alloc::vec![0x5b, 0x80, b'R', b'E', b'G', b'N', 3, 0, 1];
    body.extend_from_slice(&package(&[0x5b, 0x81], b"REGN\x01BITS\x08"));
    if parse(&device(b"ZEC0", &body)).is_err() {
        return TestResult::Fail("checked EC Field fixture parse failed");
    }
    let Some(_gate) = crate::oregion::try_acquire_ec_txn_gate() else {
        return TestResult::Fail("serialized checked-EC fixture found an existing transaction");
    };
    if crate::oregion::read_field_checked("\\ZEC0.BITS")
        != Err(crate::oregion::FieldAccessError::Unsupported)
        || crate::oregion::write_field_checked("\\ZEC0.BITS", 1)
            != Err(crate::oregion::FieldAccessError::Unsupported)
    {
        return TestResult::Fail("checked EC admission ignored a retained transaction owner");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "aml/strict",
    checked_ec_contention_fails_without_unbounded_gate_wait
);

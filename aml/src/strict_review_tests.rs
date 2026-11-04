use super::*;
use alloc::vec;

fn method_completion_and_uninitialized_locals_are_not_integer_zero() -> TestResult {
    // SAFETY: serialized test owns the scoped namespace and register tables.
    let _namespace = unsafe { crate::__test_namespace_scope() };
    let mut body = b"\x08NUMB\x0a\x07".to_vec();
    body.extend_from_slice(&method(b"UNIN", 0, &[0xa4, 0x60]));
    body.extend_from_slice(&method(b"INIT", 0, &[0x70, 0, 0x60, 0xa4, 0x60]));
    body.extend_from_slice(&method(b"VOID", 0, &[0xa3]));
    body.extend_from_slice(&method(b"VSTM", 0, b"VOID"));
    body.extend_from_slice(&method(b"VEXP", 0, b"\xa4VOID"));
    body.extend_from_slice(&method(b"VSTR", 0, b"\x70VOIDNUMB"));
    let conditional = package(&[0xa0], b"VOID\x70\x01NUMB");
    body.extend_from_slice(&method(b"VPRD", 0, &conditional));
    if parse(&device(b"ZRV0", &body)).is_err() {
        return TestResult::Fail("strict completion fixture parse failed");
    }
    if evaluate_method("\\ZRV0.UNIN", &[]) != Err(Error::Uninitialized)
        || evaluate_method("\\ZRV0.INIT", &[]) != Ok(Completion::Value(Value::Integer(0)))
        || evaluate_method("\\ZRV0.VOID", &[]) != Ok(Completion::Void)
        || evaluate_method("\\ZRV0.VSTM", &[]) != Ok(Completion::Void)
    {
        return TestResult::Fail("uninitialized Local or void completion became explicit Integer0");
    }
    for path in ["\\ZRV0.VEXP", "\\ZRV0.VSTR", "\\ZRV0.VPRD"] {
        if evaluate_method(path, &[]) != Err(Error::NoReturnValue) {
            return TestResult::Fail("void helper supplied a Store, predicate or Return operand");
        }
    }
    if evaluate_object("\\ZRV0.VOID", &[]) != Err(Error::NoReturnValue)
        || evaluate_object("\\ZRV0.NUMB", &[]) != Ok(Value::Integer(7))
    {
        return TestResult::Fail("void data object or rejected void Store changed target value");
    }
    TestResult::Pass
}
kernel_test_in!(
    "aml/strict",
    method_completion_and_uninitialized_locals_are_not_integer_zero
);

fn logical_true_and_fixed_name_stores_preserve_supported_aml_semantics() -> TestResult {
    // SAFETY: serialized scope owns all Name/method/Field references here.
    let _namespace = unsafe { crate::__test_namespace_scope() };
    let mut body = b"\x08NUMB\x0a\x07\x08TEXT\x0dkeep\x00\x08BUFF".to_vec();
    body.extend_from_slice(&package(&[0x11], &[0x0a, 2, 0xa5, 0x5a]));
    body.extend_from_slice(&method(b"MIXD", 0, b"\xa4\x93\x01\x0d1\x00"));
    let mut package_equal = vec![0xa4, 0x93];
    package_equal.extend_from_slice(&package(&[0x12], &[1, 1]));
    package_equal.extend_from_slice(&package(&[0x12], &[1, 1]));
    body.extend_from_slice(&method(b"PKGE", 0, &package_equal));
    body.extend_from_slice(&method(b"EQST", 0, b"\xa4\x93\x0dsame\x00\x0dsame\x00"));
    let mut buffer_equal = vec![0xa4, 0x93];
    buffer_equal.extend_from_slice(&package(&[0x11], &[0x0a, 2, 0xa5, 0x5a]));
    buffer_equal.extend_from_slice(&package(&[0x11], &[0x0a, 2, 0xa5, 0x5a]));
    body.extend_from_slice(&method(b"EQBF", 0, &buffer_equal));
    body.extend_from_slice(&method(b"EQIN", 0, &[0xa4, 0x93, 1, 1]));
    // And(LEqual(1,1),0x80,NullTarget) is0x80 only when AML TRUE
    // is all ones. Boolean1 would silently clear the required bit.
    body.extend_from_slice(&method(
        b"ANDT",
        0,
        &[0xa4, 0x7b, 0x93, 1, 1, 0x0a, 0x80, 0],
    ));
    body.extend_from_slice(&method(b"NOTT", 0, &[0xa4, 0x92, 0]));
    body.extend_from_slice(&method(b"LORT", 0, &[0xa4, 0x91, 0, 1]));
    body.extend_from_slice(&method(b"SNAM", 0, b"\x70\x01TEXT"));
    body.extend_from_slice(&method(b"INAM", 0, b"\x70\x0d7\x00NUMB"));
    let mut buffer_store = vec![0x70];
    buffer_store.extend_from_slice(&package(&[0x11], &[1, 0]));
    buffer_store.extend_from_slice(b"BUFF");
    body.extend_from_slice(&method(b"BNAM", 0, &buffer_store));
    if parse(&device(b"ZRV1", &body)).is_err() {
        return TestResult::Fail("strict logical/store fixture parse failed");
    }
    for path in [
        "\\ZRV1.EQST",
        "\\ZRV1.EQBF",
        "\\ZRV1.EQIN",
        "\\ZRV1.NOTT",
        "\\ZRV1.LORT",
    ] {
        if evaluate_method(path, &[]) != Ok(Completion::Value(Value::Integer(u64::MAX))) {
            return TestResult::Fail(
                "supported logical TRUE was not the actual AML all-ones value",
            );
        }
    }
    if evaluate_method("\\ZRV1.ANDT", &[]) != Ok(Completion::Value(Value::Integer(0x80))) {
        return TestResult::Fail("logical TRUE lost a bitwise control mask");
    }
    for path in [
        "\\ZRV1.MIXD",
        "\\ZRV1.PKGE",
        "\\ZRV1.SNAM",
        "\\ZRV1.INAM",
        "\\ZRV1.BNAM",
    ] {
        if evaluate_method(path, &[]) != Err(Error::Unsupported) {
            return TestResult::Fail("unsupported comparison/converting Store fabricated a result");
        }
    }
    if evaluate_object("\\ZRV1.NUMB", &[]) != Ok(Value::Integer(7))
        || evaluate_object("\\ZRV1.TEXT", &[]) != Ok(Value::String(String::from("keep")))
        || evaluate_object("\\ZRV1.BUFF", &[]) != Ok(Value::Buffer(vec![0xa5, 0x5a]))
    {
        return TestResult::Fail(
            "refused fixed-target Store changed type, content or buffer length",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "aml/strict",
    logical_true_and_fixed_name_stores_preserve_supported_aml_semantics
);

fn dsdt_revision_establishes_the_strict_integer_profile() -> TestResult {
    // SAFETY: this scope owns namespace/OpRegion parsing and restores the
    // previous real DSDT profile before returning to the test runner.
    let _namespace = unsafe { crate::__test_namespace_scope() };
    for revision in [1u8, 2] {
        crate::__reset_for_test();
        let aml = device(b"ZREV", b"\x08VALU\x01");
        let mut table = vec![0u8; 36];
        table[..4].copy_from_slice(b"DSDT");
        table[4..8].copy_from_slice(&((36 + aml.len()) as u32).to_le_bytes());
        table[8] = revision;
        table.extend_from_slice(&aml);
        let physical = narf_memory::PhysAddr::from_kernel_ptr(table.as_ptr()).raw();
        // SAFETY: complete owned SDT/header/body covered by the kernel direct
        // map; walk_aml_table copies all referenced code before it returns.
        if unsafe { crate::walk_aml_table(physical, "\\") }.is_err() {
            return TestResult::Fail("actual DSDT revision fixture could not be parsed");
        }
        let value = evaluate_object("\\ZREV.VALU", &[]);
        if (revision == 1 && value != Err(Error::Unsupported))
            || (revision == 2 && value != Ok(Value::Integer(1)))
        {
            return TestResult::Fail(
                "strict integer width was guessed instead of using actual DSDT revision",
            );
        }
    }
    crate::__reset_for_test();
    if parse(&device(b"ZREV", b"\x08VALU\x01")).is_err()
        || evaluate_object("\\ZREV.VALU", &[]) != Err(Error::Unsupported)
    {
        return TestResult::Fail("unknown DSDT width silently enabled64-bit strict evaluation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "aml/strict",
    dsdt_revision_establishes_the_strict_integer_profile
);

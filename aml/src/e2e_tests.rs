//! End-to-end AML interpreter smokes.
//!
//! Each test builds a realistic DSDT-style AML byte sequence
//! (OpRegion → Field → Method) and exercises the complete
//! evaluate_method → Field-read/write → OpRegion backing path,
//! rather than calling oregion::read_field / write_field directly.
//!
//! Region space coverage:
//!   - SystemMemory: heap-allocated backing buffer, identity-mapped.
//!   - SystemIO / PciConfig / EmbeddedCtl: namespace+field
//!     registration verified; access result accepted as Ok(_) or
//!     Unsupported (no real hardware in QEMU test builds for IO/EC).
//!
//! References:
//!   Linux drivers/acpi/acpica/exfield.c — field I/O dispatch
//!   Linux drivers/acpi/acpica/exconfig.c — region registration
//!   ACPI 6.5 §19.6.31 (Field), §20.2.5.2 (FieldOp encoding)

extern crate alloc;

use narf_kernel_test::{kernel_test_in, TestResult};

// ── helpers ──────────────────────────────────────────────────────────────────

/// Encode a single-byte PkgLength for small bodies (fits in 6 bits).
#[inline]
fn pkg1(content_len: usize) -> u8 {
    // PkgLength includes the PkgLength byte itself.
    (1 + content_len) as u8
}

/// Build `Method(\NAME, flags) { <body> }` blob.
/// name4 must be exactly 4 bytes (padded with b'_').
fn method_blob(name4: &[u8; 4], flags: u8, body: &[u8]) -> alloc::vec::Vec<u8> {
    // Content inside PkgLength: root(1) + NameSeg(4) + flags(1) + body
    let content = 1 + 4 + 1 + body.len();
    let mut v = alloc::vec::Vec::new();
    v.push(0x14); // MethodOp
    v.push(pkg1(content)); // single-byte PkgLength
    v.push(b'\\');
    v.extend_from_slice(name4);
    v.push(flags);
    v.extend_from_slice(body);
    v
}

/// Encode `OpRegion(\NAME, space, BytePrefix(offset8), BytePrefix(len8))`.
fn op_region_byte(name4: &[u8; 4], space: u8, offset8: u8, len8: u8) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec::Vec::new();
    v.push(0x5B); // EXT_OP_PREFIX
    v.push(0x80); // EXT_OP_REGION_OP
    v.push(b'\\');
    v.extend_from_slice(name4);
    v.push(space);
    v.push(0x0A); // BytePrefix
    v.push(offset8);
    v.push(0x0A); // BytePrefix
    v.push(len8);
    v
}

/// Encode `OpRegion(\NAME, space, QWordPrefix(offset64), BytePrefix(len8))`.
fn op_region_qword(name4: &[u8; 4], space: u8, offset: u64, len8: u8) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec::Vec::new();
    v.push(0x5B);
    v.push(0x80);
    v.push(b'\\');
    v.extend_from_slice(name4);
    v.push(space);
    v.push(0x0E); // QWordPrefix
    v.extend_from_slice(&offset.to_le_bytes());
    v.push(0x0A); // BytePrefix
    v.push(len8);
    v
}

/// Encode `Field(\RGNM, ByteAcc, NoLock, Preserve) { \FLDN, bit_len }`.
/// Assumes both region and field names are single-segment relative names
/// (4-byte, no prefix needed in the field list).
///
/// Single-byte PkgLength form: content = NameSeg(4) + flags(1) + NameSeg(4) + pkglen(1).
fn field_byte_acc(rgn4: &[u8; 4], fld4: &[u8; 4], bit_len: u8) -> alloc::vec::Vec<u8> {
    // Content = rgn_nameseg(4) + flags(1) + fld_nameseg(4) + pkglen(1) = 10
    let content = 4 + 1 + 4 + 1;
    let mut v = alloc::vec::Vec::new();
    v.push(0x5B); // EXT_OP_PREFIX
    v.push(0x81); // EXT_FIELD_OP
    v.push(pkg1(content)); // PkgLength
    v.extend_from_slice(rgn4); // region NameSeg (relative — no root char in field body)
    v.push(0x01); // ByteAcc, NoLock, Preserve
    v.extend_from_slice(fld4); // field NameSeg
    v.push(bit_len); // PkgLength = bit count (single-byte, must be < 64)
    v
}

// ── Smoke E01: Method returning literal Integer (baseline) ───────────────────
//
// Method(\E01_, 0, NotSerialized) { Return (0x42) }
// Invoke → expect Integer(0x42).
// Validates the simplest round-trip: method body fetch + Return opcode.

fn e2e_aml_method_returns_integer() -> TestResult {
    let body: &[u8] = &[
        0xA4, // ReturnOp
        0x0A, 0x42, // BytePrefix 0x42
    ];
    let blob = method_blob(b"E01_", 0, body);
    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("E01: parse failed");
    }
    match crate::eval::evaluate_method("\\E01", &[]) {
        Ok(crate::Value::Integer(0x42)) => TestResult::Pass,
        Ok(_) => TestResult::Fail("E01: expected Integer(0x42)"),
        Err(_) => TestResult::Fail("E01: evaluate_method failed"),
    }
}
kernel_test_in!("aml/e2e", e2e_aml_method_returns_integer);

// ── Smoke E02: Method with Add arithmetic ────────────────────────────────────
//
// Method(\E02_, 0) { Return (Add(5, 7, Local0)) } → 12

fn e2e_aml_method_add_arithmetic() -> TestResult {
    let body: &[u8] = &[
        0xA4, // ReturnOp
        0x72, // AddOp
        0x0A, 0x05, // BytePrefix 5
        0x0A, 0x07, // BytePrefix 7
        0x60, // Local0 (result target)
    ];
    let blob = method_blob(b"E02_", 0, body);
    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("E02: parse failed");
    }
    match crate::eval::evaluate_method("\\E02", &[]) {
        Ok(crate::Value::Integer(12)) => TestResult::Pass,
        Ok(_) => TestResult::Fail("E02: expected Integer(12)"),
        Err(_) => TestResult::Fail("E02: evaluate_method failed"),
    }
}
kernel_test_in!("aml/e2e", e2e_aml_method_add_arithmetic);

// ── Smoke E03: Method with Local variable ────────────────────────────────────
//
// Method(\E03_, 0) { Store(100, Local0); Return(Local0) } → 100

fn e2e_aml_method_local_variable() -> TestResult {
    let body: &[u8] = &[
        0x70, // StoreOp
        0x0A, 0x64, // BytePrefix 100
        0x60, // Local0 (destination)
        0xA4, // ReturnOp
        0x60, // Local0
    ];
    let blob = method_blob(b"E03_", 0, body);
    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("E03: parse failed");
    }
    match crate::eval::evaluate_method("\\E03", &[]) {
        Ok(crate::Value::Integer(100)) => TestResult::Pass,
        Ok(_) => TestResult::Fail("E03: expected Integer(100)"),
        Err(_) => TestResult::Fail("E03: evaluate_method failed"),
    }
}
kernel_test_in!("aml/e2e", e2e_aml_method_local_variable);

// ── Smoke E04: Method with Argument ─────────────────────────────────────────
//
// Method(\E04_, 1) { Return(Multiply(Arg0, 2, Local0)) }
// Invoked with arg=21 → returns 42.

fn e2e_aml_method_with_argument() -> TestResult {
    let body: &[u8] = &[
        0xA4, // ReturnOp
        0x77, // MultiplyOp
        0x68, // Arg0
        0x0A, 0x02, // BytePrefix 2
        0x60, // Local0 (target)
    ];
    let blob = method_blob(b"E04_", 1, body);
    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("E04: parse failed");
    }
    let args = [crate::Value::Integer(21)];
    match crate::eval::evaluate_method("\\E04", &args) {
        Ok(crate::Value::Integer(42)) => TestResult::Pass,
        Ok(_) => TestResult::Fail("E04: expected Integer(42)"),
        Err(_) => TestResult::Fail("E04: evaluate_method failed"),
    }
}
kernel_test_in!("aml/e2e", e2e_aml_method_with_argument);

// ── Smoke E05: If/Else control flow ─────────────────────────────────────────
//
// Method(\E05_, 1) {
//   If (LGreater(Arg0, 50)) { Return(1) }
//   Return(0)
// }
// Called with 100 → 1; with 10 → 0.

fn e2e_aml_if_else_control_flow() -> TestResult {
    // If body: Return(1) = [0xA4, 0x01]
    // Predicate: LGreater(Arg0, 50) = [0x94, 0x68, 0x0A, 0x32]
    let if_body: &[u8] = &[0xA4, 0x01]; // Return(One)
    let pred: &[u8] = &[0x94, 0x68, 0x0A, 0x32]; // LGreater(Arg0, 50)
    // PkgLength for If: includes the PkgLen byte + pred + if_body
    let if_content = pred.len() + if_body.len();

    let mut body = alloc::vec::Vec::new();
    body.push(0xA0); // IfOp
    body.push(pkg1(if_content)); // PkgLength
    body.extend_from_slice(pred);
    body.extend_from_slice(if_body);
    body.push(0xA4); // ReturnOp
    body.push(0x00); // ZeroOp

    let blob = method_blob(b"E05_", 1, &body);
    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("E05: parse failed");
    }

    let args_hi = [crate::Value::Integer(100)];
    match crate::eval::evaluate_method("\\E05", &args_hi) {
        Ok(crate::Value::Integer(1)) => {}
        Ok(_) => return TestResult::Fail("E05: arg=100 expected 1"),
        Err(_) => return TestResult::Fail("E05: arg=100 evaluate failed"),
    }
    let args_lo = [crate::Value::Integer(10)];
    match crate::eval::evaluate_method("\\E05", &args_lo) {
        Ok(crate::Value::Integer(0)) => TestResult::Pass,
        Ok(_) => TestResult::Fail("E05: arg=10 expected 0"),
        Err(_) => TestResult::Fail("E05: arg=10 evaluate failed"),
    }
}
kernel_test_in!("aml/e2e", e2e_aml_if_else_control_flow);

// ── Smoke E06: While loop summing 1..=10 ─────────────────────────────────────
//
// Method(\E06_, 0) {
//   Store(0, Local0); Store(1, Local1)
//   While(LLessEqual(Local1, 10)) { Local0 += Local1; Increment(Local1) }
//   Return(Local0)
// } → 55
//
// LLessEqual(a,b) = LNot(LGreater(a,b)):
//   0x92 0x94 <a> <b>

fn e2e_aml_while_loop_sum() -> TestResult {
    // While body:
    //   Add(Local0, Local1, Local0)
    //   Increment(Local1)
    let while_body: &[u8] = &[
        0x72, 0x60, 0x61, 0x60, // Add(Local0, Local1, Local0)
        0x75, 0x61, // Increment(Local1)
    ];
    // Predicate: LLessEqual(Local1, 10) = LNot(LGreater(Local1, 10))
    //   = 0x92 0x94 0x61 0x0A 0x0A
    let pred: &[u8] = &[
        0x92, // LNotOp
        0x94, // LGreaterOp
        0x61, // Local1
        0x0A, 0x0A, // BytePrefix 10
    ];
    let while_content = pred.len() + while_body.len();

    let mut body = alloc::vec::Vec::new();
    // Store(0, Local0)
    body.extend_from_slice(&[0x70, 0x00, 0x60]);
    // Store(1, Local1)
    body.extend_from_slice(&[0x70, 0x01, 0x61]);
    // While(...)
    body.push(0xA2); // WhileOp
    body.push(pkg1(while_content));
    body.extend_from_slice(pred);
    body.extend_from_slice(while_body);
    // Return(Local0)
    body.push(0xA4);
    body.push(0x60);

    let blob = method_blob(b"E06_", 0, &body);
    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("E06: parse failed");
    }
    match crate::eval::evaluate_method("\\E06", &[]) {
        Ok(crate::Value::Integer(55)) => TestResult::Pass,
        Ok(crate::Value::Integer(n)) => {
            let _ = n;
            TestResult::Fail("E06: wrong sum (expected 55)")
        }
        Ok(_) => TestResult::Fail("E06: not an integer"),
        Err(_) => TestResult::Fail("E06: evaluate_method failed"),
    }
}
kernel_test_in!("aml/e2e", e2e_aml_while_loop_sum);

// ── Smoke E07: SystemMemory OpRegion — read via Method ───────────────────────
//
// AML:
//   OperationRegion(\E7RG, SystemMemory, <buf_phys>, 8)
//   Field(\E7RG, ByteAcc, NoLock, Preserve) { \E7F0, 8 }
//   Method(\E07_, 0) { Return(\E7F0) }
//
// Backing buffer byte[0] = 0xAB → Method returns 0xAB.
// Then use write_field to set byte[0] = 0xCD → buf[0] == 0xCD.
//
// This exercises the full evaluate_method → Field-node read →
// oregion::read_field → mmio_read path without touching hardware.

fn e2e_aml_sysmem_opregion_via_method() -> TestResult {
    use alloc::boxed::Box;

    crate::__reset_for_test();
    crate::oregion::__reset_for_test();

    // Backing: 8-byte buffer, byte 0 = 0xAB.
    let mut backing: Box<[u8; 8]> = Box::new([0u8; 8]);
    backing[0] = 0xAB;
    let phys = backing.as_ptr() as u64;

    // OpRegion(\E7RG, SystemMemory, phys, 8)
    let rgn = op_region_qword(b"E7RG", 0x00, phys, 8);

    // Field(\E7RG, ByteAcc, Preserve) { E7F0, 8 }
    // region NameSeg in field body is relative (no root prefix).
    let fld = field_byte_acc(b"E7RG", b"E7F0", 8);

    // Method(\E07_, 0) { Return(E7F0) }
    // NameString for E7F0 field ref inside the method body.
    // `read_name_string` in the evaluator resolves against method scope "\\"
    // so a bare NameSeg b"E7F0" resolves to "\\E7F0".
    let method_body: &[u8] = &[
        0xA4,                    // ReturnOp
        b'E', b'7', b'F', b'0', // NameSeg (4-char, relative)
    ];
    let meth = method_blob(b"E07_", 0, method_body);

    let mut blob = alloc::vec::Vec::new();
    blob.extend_from_slice(&rgn);
    blob.extend_from_slice(&fld);
    blob.extend_from_slice(&meth);

    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("E07: parse failed");
    }

    // Evaluate the method — should read byte 0 = 0xAB via mmio_read.
    let rd = crate::eval::evaluate_method("\\E07", &[]);
    match rd {
        Ok(crate::Value::Integer(0xAB)) => {}
        Ok(crate::Value::Integer(v)) => {
            let _ = v;
            drop(backing);
            return TestResult::Fail("E07: RD returned wrong value (expected 0xAB)");
        }
        Ok(_) => {
            drop(backing);
            return TestResult::Fail("E07: RD returned non-integer");
        }
        Err(_) => {
            drop(backing);
            return TestResult::Fail("E07: evaluate_method RD failed");
        }
    }

    // Write 0xCD via write_field (the direct accessor — tests the WR path).
    if crate::oregion::write_field("\\E7F0", 0xCD).is_err() {
        drop(backing);
        return TestResult::Fail("E07: write_field failed");
    }
    let got = backing[0];
    drop(backing);
    if got != 0xCD {
        return TestResult::Fail("E07: backing byte 0 not 0xCD after write");
    }
    TestResult::Pass
}
kernel_test_in!("aml/e2e", e2e_aml_sysmem_opregion_via_method);

// ── Smoke E08: SystemMemory — DSDT-style RD + WR methods ─────────────────────
//
// Extends E07 with a Method for writing (instead of calling write_field
// directly), verifying the Store(Arg0, field) path through the evaluator.
//
// AML:
//   OperationRegion(\E8RG, SystemMemory, <buf_phys>, 8)
//   Field(\E8RG, ByteAcc, NoLock, Preserve) { \E8F0, 8 }
//   Method(\E8R, 0) { Return(\E8F0) }
//   Method(\E8W, 1) { Store(Arg0, \E8F0) }

fn e2e_aml_sysmem_read_write_methods() -> TestResult {
    use alloc::boxed::Box;

    crate::__reset_for_test();
    crate::oregion::__reset_for_test();

    let mut backing: Box<[u8; 8]> = Box::new([0u8; 8]);
    backing[0] = 0x11;
    let phys = backing.as_ptr() as u64;

    let rgn = op_region_qword(b"E8RG", 0x00, phys, 8);
    let fld = field_byte_acc(b"E8RG", b"E8F0", 8);

    // Method(\E8R_, 0) { Return(E8F0) }
    let rd_body: &[u8] = &[0xA4, b'E', b'8', b'F', b'0'];
    let rd_meth = method_blob(b"E8R_", 0, rd_body);

    // Method(\E8W_, 1) { Store(Arg0, E8F0) }
    // StoreOp: 0x70 <src-TermArg> <dst-SuperName>
    // src = Arg0 (0x68), dst = NameSeg "E8F0"
    let wr_body: &[u8] = &[0x70, 0x68, b'E', b'8', b'F', b'0'];
    let wr_meth = method_blob(b"E8W_", 1, wr_body);

    let mut blob = alloc::vec::Vec::new();
    blob.extend_from_slice(&rgn);
    blob.extend_from_slice(&fld);
    blob.extend_from_slice(&rd_meth);
    blob.extend_from_slice(&wr_meth);

    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        drop(backing);
        return TestResult::Fail("E08: parse failed");
    }

    // Read — should return initial value 0x11.
    match crate::eval::evaluate_method("\\E8R", &[]) {
        Ok(crate::Value::Integer(0x11)) => {}
        _ => {
            drop(backing);
            return TestResult::Fail("E08: RD expected 0x11");
        }
    }

    // Write 0xBE via the method.
    if crate::eval::evaluate_method("\\E8W", &[crate::Value::Integer(0xBE)]).is_err() {
        drop(backing);
        return TestResult::Fail("E08: WR method failed");
    }

    // Verify backing was updated.
    let got = backing[0];
    drop(backing);
    if got != 0xBE {
        return TestResult::Fail("E08: backing byte != 0xBE after WR method");
    }
    TestResult::Pass
}
kernel_test_in!("aml/e2e", e2e_aml_sysmem_read_write_methods);

// ── Smoke E09: SystemIO OpRegion — region+field registration verified ─────────
//
// AML:
//   OperationRegion(\E9IO, SystemIO, 0x70, 2)
//   Field(\E9IO, ByteAcc, NoLock, Preserve) { \E9PT, 8 }
//
// We verify:
//   1. Region is registered with the right space/offset/length.
//   2. Field is registered and maps to the region.
//   3. write_field / read_field return Ok or Unsupported, never
//      NoField / NoRegion (the namespace plumbing is correct).
//
// We do NOT assert on the returned value since 0x70 is the real CMOS
// index port — touching it on bare metal in a QEMU test is unexpected
// but not dangerous because the region handler short-circuits through
// cmos_read / cmos_write rather than raw io_in / io_out.

fn e2e_aml_sysio_opregion_registration() -> TestResult {
    crate::__reset_for_test();
    crate::oregion::__reset_for_test();

    // OpRegion(\E9IO, SystemIO=1, offset=0x70, length=2)
    let rgn = op_region_byte(b"E9IO", 0x01, 0x70, 2);
    // Field(\E9IO, ByteAcc) { E9PT, 8 }
    let fld = field_byte_acc(b"E9IO", b"E9PT", 8);

    let mut blob = alloc::vec::Vec::new();
    blob.extend_from_slice(&rgn);
    blob.extend_from_slice(&fld);

    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("E09: parse failed");
    }

    // 1. Region metadata correct.
    let region = match crate::oregion::region_for("\\E9IO") {
        Some(r) => r,
        None => return TestResult::Fail("E09: \\E9IO region not registered"),
    };
    if region.space != crate::oregion::RegionSpace::SystemIO {
        return TestResult::Fail("E09: region space is not SystemIO");
    }
    if region.offset != 0x70 {
        return TestResult::Fail("E09: region offset mismatch");
    }
    if region.length != 2 {
        return TestResult::Fail("E09: region length mismatch");
    }

    // 2. Field metadata correct.
    let field = match crate::oregion::field_for("\\E9PT") {
        Some(f) => f,
        None => return TestResult::Fail("E09: \\E9PT field not registered"),
    };
    if field.bit_offset != 0 {
        return TestResult::Fail("E09: field bit_offset mismatch");
    }
    if field.bit_length != 8 {
        return TestResult::Fail("E09: field bit_length mismatch");
    }

    // 3. write_field must not return NoField or NoRegion.
    match crate::oregion::write_field("\\E9PT", 0x99) {
        Ok(()) => {}
        Err(crate::oregion::FieldAccessError::Unsupported) => {}
        Err(crate::oregion::FieldAccessError::NoField) => {
            return TestResult::Fail("E09: write_field returned NoField");
        }
        Err(crate::oregion::FieldAccessError::NoRegion) => {
            return TestResult::Fail("E09: write_field returned NoRegion");
        }
        Err(crate::oregion::FieldAccessError::TooWide) => {
            return TestResult::Fail("E09: write_field returned TooWide");
        }
    }

    TestResult::Pass
}
kernel_test_in!("aml/e2e", e2e_aml_sysio_opregion_registration);

// ── Smoke E10: PCI_Config OpRegion — DSDT-style VEND+DEV fields ───────────────
//
// AML (mimics a real DSDT's VID/DID field block):
//   Device(\EAPC) {
//     Name(_BBN, 0)
//     Name(_ADR, 0x00000000)   // bus 0, device 0, func 0
//     OperationRegion(\EACF, PciConfig, 0, 256)
//     Field(\EACF, WordAcc, NoLock, Preserve) { \EAVD, 16, \EADV, 16 }
//   }
//
// Verify: region registered as PciConfig; VEND field at bit 0 width 16;
// DEV field at bit 16 width 16. read_field returns Ok or Unsupported (no ECAM).

fn e2e_aml_pci_config_opregion_fields() -> TestResult {
    crate::__reset_for_test();
    crate::oregion::__reset_for_test();

    let mut blob = alloc::vec::Vec::new();

    // Device(\EAPC) {
    //   Name(_BBN, 0); Name(_ADR, 0)
    //   OpRegion + 2-field
    // }
    // We declare everything at root scope to keep the blob simple —
    // the Field names are absolute so the device wrapper is not needed.

    // OpRegion(\EACF, PciConfig=2, offset=0, length=DWordPrefix(256))
    blob.push(0x5B); // EXT_OP_PREFIX
    blob.push(0x80); // EXT_OP_REGION_OP
    blob.push(b'\\');
    blob.extend_from_slice(b"EACF");
    blob.push(0x02); // PciConfig
    blob.push(0x00); // ZeroOp (offset=0)
    blob.push(0x0C); // DWordPrefix
    blob.extend_from_slice(&256u32.to_le_bytes()); // length=256

    // Field(\EACF, WordAcc=2, NoLock, Preserve) { EAVD, 16, EADV, 16 }
    // Content = NameSeg(4) + flags(1) + field1(4+1) + field2(4+1) = 15
    let field_content = 4 + 1 + (4 + 1) + (4 + 1);
    blob.push(0x5B);
    blob.push(0x81);
    blob.push(pkg1(field_content));
    blob.extend_from_slice(b"EACF"); // region NameSeg
    blob.push(0x02); // WordAcc, NoLock, Preserve
    blob.extend_from_slice(b"EAVD"); // field 0: VENDOR ID
    blob.push(0x10); // 16 bits
    blob.extend_from_slice(b"EADV"); // field 1: DEVICE ID
    blob.push(0x10); // 16 bits

    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("E10: parse failed");
    }

    // Region check.
    let region = match crate::oregion::region_for("\\EACF") {
        Some(r) => r,
        None => return TestResult::Fail("E10: \\EACF not registered"),
    };
    if region.space != crate::oregion::RegionSpace::PciConfig {
        return TestResult::Fail("E10: region space not PciConfig");
    }
    if region.offset != 0 {
        return TestResult::Fail("E10: region offset mismatch");
    }
    if region.length != 256 {
        return TestResult::Fail("E10: region length mismatch");
    }

    // VEND field at bit 0, 16 bits.
    let vend = match crate::oregion::field_for("\\EAVD") {
        Some(f) => f,
        None => return TestResult::Fail("E10: \\EAVD field not registered"),
    };
    if vend.bit_offset != 0 || vend.bit_length != 16 {
        return TestResult::Fail("E10: EAVD bit_offset/length mismatch");
    }

    // DEV field at bit 16, 16 bits.
    let dev = match crate::oregion::field_for("\\EADV") {
        Some(f) => f,
        None => return TestResult::Fail("E10: \\EADV field not registered"),
    };
    if dev.bit_offset != 16 || dev.bit_length != 16 {
        return TestResult::Fail("E10: EADV bit_offset/length mismatch");
    }

    // read_field must not return NoField / NoRegion.
    match crate::oregion::read_field("\\EAVD") {
        Ok(_) | Err(crate::oregion::FieldAccessError::Unsupported) => {}
        Err(e) => {
            let _ = e;
            return TestResult::Fail("E10: read_field EAVD returned unexpected error");
        }
    }

    TestResult::Pass
}
kernel_test_in!("aml/e2e", e2e_aml_pci_config_opregion_fields);

// ── Smoke E11: EmbeddedControl OpRegion — region+field registration ───────────
//
// AML:
//   OperationRegion(\EBEC, EmbeddedCtl=3, 0, 256)
//   Field(\EBEC, ByteAcc, NoLock, Preserve) { \EBR0, 8 }
//
// EmbeddedCtl reads route through ec_read_byte which calls ec_wait_ibf_clear.
// Without real EC ports configured the call returns Unsupported —
// identical to the SystemIO case. We only verify registration here.

fn e2e_aml_ec_opregion_registration() -> TestResult {
    crate::__reset_for_test();
    crate::oregion::__reset_for_test();

    // OpRegion(\EBEC, EmbeddedCtl=3, 0, 256)
    let rgn = op_region_byte(b"EBEC", 0x03, 0, 0xFF);
    // Field(\EBEC, ByteAcc) { EBR0, 8 }
    let fld = field_byte_acc(b"EBEC", b"EBR0", 8);

    let mut blob = alloc::vec::Vec::new();
    blob.extend_from_slice(&rgn);
    blob.extend_from_slice(&fld);

    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("E11: parse failed");
    }

    // Region: EmbeddedCtl, offset 0.
    let region = match crate::oregion::region_for("\\EBEC") {
        Some(r) => r,
        None => return TestResult::Fail("E11: \\EBEC region not registered"),
    };
    if region.space != crate::oregion::RegionSpace::EmbeddedCtl {
        return TestResult::Fail("E11: region space not EmbeddedCtl");
    }

    // Field registered.
    if crate::oregion::field_for("\\EBR0").is_none() {
        return TestResult::Fail("E11: \\EBR0 field not registered");
    }

    // read_field must not return NoField / NoRegion.
    match crate::oregion::read_field("\\EBR0") {
        Ok(_) | Err(crate::oregion::FieldAccessError::Unsupported) => {}
        Err(crate::oregion::FieldAccessError::NoField) => {
            return TestResult::Fail("E11: read_field returned NoField");
        }
        Err(crate::oregion::FieldAccessError::NoRegion) => {
            return TestResult::Fail("E11: read_field returned NoRegion");
        }
        Err(_) => return TestResult::Fail("E11: read_field unexpected error"),
    }

    TestResult::Pass
}
kernel_test_in!("aml/e2e", e2e_aml_ec_opregion_registration);

// ── Smoke E12: Sub-byte and cross-byte Field bit packing ─────────────────────
//
// Field layout: { F4, 4, F12, 12 } in a SystemMemory region backed by [u8; 2].
// Write F4 = 0xA and F12 = 0x123.
// Expected backing bytes: byte0 = 0x3A (low nibble F4=0xA, high nibble low4
// of 0x123=0x3), byte1 = 0x12 (high 8 bits of 0x123).
// i.e. little-endian bit layout: bits[3:0]=F4=0xA, bits[15:4]=F12=0x123.
//
// ACPI 6.5 §19.6.31: fields are laid out LSB-first within each
// access unit. ByteAcc means the field engine issues byte reads/writes.
// F4  occupies bits[3:0]  of byte 0  → write 0xA   → byte0 |= 0x0A
// F12 occupies bits[7:4]  of byte 0 (low 4 bits) and bits[7:0] of byte 1.
//     low nibble of 0x123 = 0x3, shifted to bits[7:4] → byte0 |= 0x30
//     high byte of 0x123  = 0x12                       → byte1 = 0x12
// byte0 = 0x0A | 0x30 = 0x3A, byte1 = 0x12.
//
// Ref: Linux exfield.c AcpiExExtractFromField bit-packing.

fn e2e_aml_field_sub_byte_cross_byte_packing() -> TestResult {
    use alloc::boxed::Box;

    crate::__reset_for_test();
    crate::oregion::__reset_for_test();

    let backing: Box<[u8; 8]> = Box::new([0u8; 8]);
    let phys = backing.as_ptr() as u64;

    let rgn = op_region_qword(b"ECRG", 0x00, phys, 8);

    // Field(\ECRG, ByteAcc, NoLock, Preserve) { ECF4, 4, ECF2, 12 }
    // Content = NameSeg(4) + flags(1) + field1(4+1) + field2(4+1) = 15
    let field_content = 4 + 1 + (4 + 1) + (4 + 1);
    let mut fld = alloc::vec::Vec::new();
    fld.push(0x5B);
    fld.push(0x81);
    fld.push(pkg1(field_content));
    fld.extend_from_slice(b"ECRG");
    fld.push(0x01); // ByteAcc, NoLock, Preserve
    fld.extend_from_slice(b"ECF4"); // 4-bit field
    fld.push(0x04);
    fld.extend_from_slice(b"ECF2"); // 12-bit field
    fld.push(0x0C); // 12 bits

    let mut blob = alloc::vec::Vec::new();
    blob.extend_from_slice(&rgn);
    blob.extend_from_slice(&fld);

    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        drop(backing);
        return TestResult::Fail("E12: parse failed");
    }

    // Verify field registration.
    let f4 = match crate::oregion::field_for("\\ECF4") {
        Some(f) => f,
        None => {
            drop(backing);
            return TestResult::Fail("E12: ECF4 not registered");
        }
    };
    if f4.bit_offset != 0 || f4.bit_length != 4 {
        drop(backing);
        return TestResult::Fail("E12: ECF4 bit_offset/length mismatch");
    }

    let f12 = match crate::oregion::field_for("\\ECF2") {
        Some(f) => f,
        None => {
            drop(backing);
            return TestResult::Fail("E12: ECF2 not registered");
        }
    };
    if f12.bit_offset != 4 || f12.bit_length != 12 {
        drop(backing);
        return TestResult::Fail("E12: ECF2 bit_offset/length mismatch");
    }

    // Write F4 = 0xA.
    if crate::oregion::write_field("\\ECF4", 0xA).is_err() {
        drop(backing);
        return TestResult::Fail("E12: write_field ECF4 failed");
    }

    // Write F12 = 0x123.
    if crate::oregion::write_field("\\ECF2", 0x123).is_err() {
        drop(backing);
        return TestResult::Fail("E12: write_field ECF2 failed");
    }

    // Verify read-back.
    let rb4 = crate::oregion::read_field("\\ECF4");
    let rb12 = crate::oregion::read_field("\\ECF2");

    let b0 = backing[0];
    let b1 = backing[1];
    drop(backing);

    match rb4 {
        Ok(0xA) => {}
        Ok(v) => {
            let _ = v;
            return TestResult::Fail("E12: ECF4 read-back != 0xA");
        }
        Err(_) => return TestResult::Fail("E12: ECF4 read failed"),
    }
    match rb12 {
        Ok(0x123) => {}
        Ok(v) => {
            let _ = v;
            return TestResult::Fail("E12: ECF2 read-back != 0x123");
        }
        Err(_) => return TestResult::Fail("E12: ECF2 read failed"),
    }

    // byte0 bits[3:0]=0xA, bits[7:4]=low4(0x123)=0x3 → 0x3A
    if b0 != 0x3A {
        return TestResult::Fail("E12: backing byte0 wrong (expected 0x3A)");
    }
    // byte1 = high 8 bits of 0x123 = 0x12
    if b1 != 0x12 {
        return TestResult::Fail("E12: backing byte1 wrong (expected 0x12)");
    }

    TestResult::Pass
}
kernel_test_in!("aml/e2e", e2e_aml_field_sub_byte_cross_byte_packing);

// ── Smoke E13: Notify dispatches to registered handler ───────────────────────
//
// AML:
//   Method(\E13_, 0) { Notify(\E13T, 0x80) }
//   Name(\E13T, 0)
//
// Register a handler on "\\E13T", invoke the method, verify handler
// received value 0x80.  Tests the Notify opcode path through
// crate::sync::dispatch_notify (Wave 15 event-bus migration).

fn e2e_aml_notify_dispatches_to_handler() -> TestResult {
    use core::sync::atomic::{AtomicU64, Ordering};
    static RECV: AtomicU64 = AtomicU64::new(u64::MAX);

    fn handler(_target: &str, value: u64) {
        RECV.store(value, Ordering::Relaxed);
    }

    crate::sync::register_notify_handler("\\E13T", handler);

    // Declare Name(\E13T, 0) so the path exists.
    let name_blob: &[u8] = &[
        0x08, // NameOp
        b'\\', b'E', b'1', b'3', b'T', // \E13T
        0x00, // ZeroOp
    ];

    // Method(\E13_, 0) { NotifyOp \E13T BytePrefix(0x80) }
    let method_body: &[u8] = &[
        0x86,                            // NotifyOp
        b'\\', b'E', b'1', b'3', b'T',  // \E13T
        0x0A, 0x80,                      // BytePrefix 0x80
    ];
    let meth = method_blob(b"E13_", 0, method_body);

    let mut blob = alloc::vec::Vec::new();
    blob.extend_from_slice(name_blob);
    blob.extend_from_slice(&meth);

    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("E13: parse failed");
    }

    RECV.store(u64::MAX, Ordering::Relaxed);
    if crate::eval::evaluate_method("\\E13", &[]).is_err() {
        return TestResult::Fail("E13: evaluate_method failed");
    }
    if RECV.load(Ordering::Relaxed) == 0x80 {
        TestResult::Pass
    } else {
        TestResult::Fail("E13: handler not called with 0x80")
    }
}
kernel_test_in!("aml/e2e", e2e_aml_notify_dispatches_to_handler);

// ── Smoke E14: CreateByteField + round-trip read/write ───────────────────────
//
// AML:
//   Name(\E14B, Buffer(4){0xAA, 0xBB, 0xCC, 0xDD})
//   CreateByteField(\E14B, 1, \E14F)   // byte-field at offset 1
//   Method(\E14R, 0) { Return(\E14F) }
//   Method(\E14W, 1) { Store(Arg0, \E14F) }
//
// Verify: E14R returns 0xBB; E14W(0xEE) → E14B[1] == 0xEE.
//
// CreateByteField encoding: 0x8C <BufferName> <BytePrefix(offset)> <FieldName>
// (ACPI 6.5 §20.2.5.2 CreateByteFieldOp).

fn e2e_aml_create_byte_field_round_trip() -> TestResult {
    crate::__reset_for_test();
    crate::oregion::__reset_for_test();

    // Name(\E14B, Buffer(4){ 0xAA, 0xBB, 0xCC, 0xDD })
    // Buffer encoding: BufferOp PkgLen SizeTermArg ByteData...
    // PkgLength counts itself + payload: 1 + 2(BytePrefix 4) + 4(data) = 7.
    let buffer_body: &[u8] = &[
        0x11, // BufferOp
        0x07, // PkgLength (self + 6 payload bytes)
        0x0A, 0x04, // BytePrefix 4 (size)
        0xAA, 0xBB, 0xCC, 0xDD,
    ];
    let mut blob = alloc::vec::Vec::new();
    blob.push(0x08); // NameOp
    blob.push(b'\\');
    blob.extend_from_slice(b"E14B");
    blob.extend_from_slice(buffer_body);

    // CreateByteField(\E14B, 1, \E14F)
    // 0x8C <SuperName/NameString> <ByteTermArg(index)> <NameSeg(fieldname)>
    blob.push(0x8C); // CreateByteFieldOp
    blob.push(b'\\');
    blob.extend_from_slice(b"E14B"); // source buffer name
    blob.push(0x0A); // BytePrefix
    blob.push(0x01); // byte index = 1
    blob.push(b'\\');
    blob.extend_from_slice(b"E14F"); // new field name

    // Method(\E14R, 0) { Return(\E14F) }
    let rd_body: &[u8] = &[0xA4, b'\\', b'E', b'1', b'4', b'F'];
    let rd_meth = method_blob(b"E14R", 0, rd_body);

    // Method(\E14W, 1) { Store(Arg0, \E14F) }
    let wr_body: &[u8] = &[0x70, 0x68, b'\\', b'E', b'1', b'4', b'F'];
    let wr_meth = method_blob(b"E14W", 1, wr_body);

    blob.extend_from_slice(&rd_meth);
    blob.extend_from_slice(&wr_meth);

    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("E14: parse failed");
    }

    // Read — expect byte 1 = 0xBB.
    match crate::eval::evaluate_method("\\E14R", &[]) {
        Ok(crate::Value::Integer(0xBB)) => {}
        Ok(crate::Value::Integer(v)) => {
            let _ = v;
            return TestResult::Fail("E14: RD expected 0xBB");
        }
        Ok(_) => return TestResult::Fail("E14: RD returned non-integer"),
        Err(_) => return TestResult::Fail("E14: RD evaluate_method failed"),
    }

    // Write 0xEE to the byte-field.
    if crate::eval::evaluate_method("\\E14W", &[crate::Value::Integer(0xEE)]).is_err() {
        return TestResult::Fail("E14: WR method failed");
    }

    // Verify the buffer was updated.
    let buf = match crate::read_name_as_buffer("\\E14B") {
        Some(b) => b,
        None => return TestResult::Fail("E14: could not read \\E14B as buffer"),
    };
    if buf.len() < 2 {
        return TestResult::Fail("E14: buffer too short after write");
    }
    if buf[1] != 0xEE {
        return TestResult::Fail("E14: buffer[1] != 0xEE after WR");
    }
    TestResult::Pass
}
kernel_test_in!("aml/e2e", e2e_aml_create_byte_field_round_trip);

// ── Smoke E15: Concatenate two Buffers ───────────────────────────────────────
//
// Method(\E15_, 0) {
//   Return(Concatenate(Buffer(){0xAA}, Buffer(){0xBB}))
// }
// → Value::Buffer([0xAA, 0xBB])
//
// ACPI 6.5 §19.6.10: Concatenate on two Buffers returns a new Buffer
// that is the two source buffers appended together.

fn e2e_aml_concatenate_buffers() -> TestResult {
    // Buffer(1){0xAA}: BufferOp PkgLen(1+1+1=3→stored as 4) SizeTermArg ByteData
    // PkgLength total = 1(PkgLen byte) + 1(BytePrefix) + 1(size) + 1(data) = 4
    let buf_aa: &[u8] = &[
        0x11, // BufferOp
        0x04, // PkgLength = 4 (1 PkgLen + 2 size + 1 data)
        0x0A, 0x01, // BytePrefix 1 (size)
        0xAA,
    ];
    let buf_bb: &[u8] = &[
        0x11, // BufferOp
        0x04,
        0x0A, 0x01,
        0xBB,
    ];

    // Method body: ReturnOp ConcatOp buf_aa buf_bb ZeroOp(target)
    // ConcatenateOp = 0x73: Concat(Source1, Source2, Target)
    let mut body = alloc::vec::Vec::new();
    body.push(0xA4); // ReturnOp
    body.push(0x73); // ConcatenateOp
    body.extend_from_slice(buf_aa);
    body.extend_from_slice(buf_bb);
    body.push(0x00); // ZeroOp (discard target)

    let blob = method_blob(b"E15_", 0, &body);
    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("E15: parse failed");
    }
    match crate::eval::evaluate_method("\\E15", &[]) {
        Ok(crate::Value::Buffer(b)) => {
            if b.len() == 2 && b[0] == 0xAA && b[1] == 0xBB {
                TestResult::Pass
            } else {
                TestResult::Fail("E15: buffer contents wrong (expected [0xAA, 0xBB])")
            }
        }
        Ok(_) => TestResult::Fail("E15: expected Buffer value"),
        Err(_) => TestResult::Fail("E15: evaluate_method failed"),
    }
}
kernel_test_in!("aml/e2e", e2e_aml_concatenate_buffers);

// ── Smoke E16: SystemMemory — method reads field, does arithmetic, writes back
//
// This is the canonical DSDT-style pattern (e.g. thermal setpoint update):
//   OpRegion + Field + Method that reads a value, doubles it, writes back.
//
// AML:
//   OperationRegion(\EFRG, SystemMemory, <buf_phys>, 8)
//   Field(\EFRG, ByteAcc, NoLock, Preserve) { \EFFV, 8 }
//   Method(\E16_, 0) {
//     Store(Multiply(\EFFV, 2, Local0), \EFFV)
//   }
//
// Backing byte 0 = 0x10 → after method → byte 0 = 0x20.

fn e2e_aml_method_reads_field_arithmetic_writes_back() -> TestResult {
    use alloc::boxed::Box;

    crate::__reset_for_test();
    crate::oregion::__reset_for_test();

    let mut backing: Box<[u8; 8]> = Box::new([0u8; 8]);
    backing[0] = 0x10;
    let phys = backing.as_ptr() as u64;

    let rgn = op_region_qword(b"EFRG", 0x00, phys, 8);
    let fld = field_byte_acc(b"EFRG", b"EFFV", 8);

    // Method body:
    //   Store(Multiply(EFFV, 2, Local0), EFFV)
    //   = StoreOp MultiplyOp EFFV BytePrefix(2) Local0  EFFV
    let method_body: &[u8] = &[
        0x70, // StoreOp
        0x77, // MultiplyOp
        b'E', b'F', b'F', b'V', // NameSeg source field (relative → \\EFFV)
        0x0A, 0x02, // BytePrefix 2
        0x60, // Local0 (result target)
        b'E', b'F', b'F', b'V', // Store destination NameSeg
    ];
    let meth = method_blob(b"E16_", 0, method_body);

    let mut blob = alloc::vec::Vec::new();
    blob.extend_from_slice(&rgn);
    blob.extend_from_slice(&fld);
    blob.extend_from_slice(&meth);

    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        drop(backing);
        return TestResult::Fail("E16: parse failed");
    }

    if crate::eval::evaluate_method("\\E16", &[]).is_err() {
        drop(backing);
        return TestResult::Fail("E16: evaluate_method failed");
    }

    let got = backing[0];
    drop(backing);

    if got == 0x20 {
        TestResult::Pass
    } else {
        TestResult::Fail("E16: backing byte != 0x20 (expected 0x10 * 2)")
    }
}
kernel_test_in!("aml/e2e", e2e_aml_method_reads_field_arithmetic_writes_back);

// ── Smoke E17: Multi-byte DWordAcc field across 4-byte boundary ───────────────
//
// DWord-width field (32 bits) in a SystemMemory region backed by [u64].
// Write 0xDEADBEEF, read back, verify.
//
// Tests the 4-byte access-unit path (ByteAcc smokes already done).

fn e2e_aml_dword_acc_field_round_trip() -> TestResult {
    use alloc::boxed::Box;

    crate::__reset_for_test();
    crate::oregion::__reset_for_test();

    let backing: Box<[u64; 1]> = Box::new([0u64]);
    let phys = backing.as_ptr() as u64;

    let rgn = op_region_qword(b"EDRG", 0x00, phys, 8);

    // Field(\EDRG, DWordAcc=3, NoLock, Preserve) { EDFD, 32 }
    let field_content = 4 + 1 + 4 + 1; // NameSeg(4) + flags(1) + fldNameSeg(4) + pkglen(1)
    let mut fld = alloc::vec::Vec::new();
    fld.push(0x5B);
    fld.push(0x81);
    fld.push(pkg1(field_content));
    fld.extend_from_slice(b"EDRG");
    fld.push(0x03); // DWordAcc, NoLock, Preserve
    fld.extend_from_slice(b"EDFD");
    fld.push(0x20); // 32 bits

    let mut blob = alloc::vec::Vec::new();
    blob.extend_from_slice(&rgn);
    blob.extend_from_slice(&fld);

    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        drop(backing);
        return TestResult::Fail("E17: parse failed");
    }

    if crate::oregion::write_field("\\EDFD", 0xDEAD_BEEF).is_err() {
        drop(backing);
        return TestResult::Fail("E17: write_field failed");
    }

    let rb = crate::oregion::read_field("\\EDFD");
    let raw = backing[0];
    drop(backing);

    match rb {
        Ok(0xDEAD_BEEF) => {}
        Ok(v) => {
            let _ = v;
            return TestResult::Fail("E17: read-back != 0xDEADBEEF");
        }
        Err(_) => return TestResult::Fail("E17: read_field failed"),
    }
    if (raw & 0xFFFF_FFFF) != 0xDEAD_BEEF {
        return TestResult::Fail("E17: backing low 32 bits wrong");
    }
    TestResult::Pass
}
kernel_test_in!("aml/e2e", e2e_aml_dword_acc_field_round_trip);

// ── Smoke E18: Mutex acquire → critical section → release ────────────────────
//
// Declare Mutex(\E18M, 0), then a Method that acquires it with timeout
// 0xFFFF (wait forever), returns One, then releases. Tests the
// acquire/release symmetry through the evaluator — any deadlock or
// double-release would panic the test harness.

fn e2e_aml_mutex_critical_section() -> TestResult {
    // Mutex(\E18M, 0)
    let mut blob = alloc::vec::Vec::new();
    blob.push(0x5B); // EXT_OP_PREFIX
    blob.push(0x01); // EXT_MUTEX_OP
    blob.push(b'\\');
    blob.extend_from_slice(b"E18M"); // \E18M
    blob.push(0x00); // SyncFlags

    // Method(\E18_, 0) {
    //   Acquire(\E18M, 0xFFFF)
    //   // critical section
    //   Release(\E18M)
    //   Return(One)
    // }
    let method_body: &[u8] = &[
        0x5B, 0x23,              // AcquireOp
        b'\\', b'E', b'1', b'8', b'M', // \E18M
        0xFF, 0xFF,              // timeout 0xFFFF
        0x5B, 0x27,              // ReleaseOp
        b'\\', b'E', b'1', b'8', b'M',
        0xA4, 0x01,              // Return(One)
    ];
    let meth = method_blob(b"E18_", 0, method_body);
    blob.extend_from_slice(&meth);

    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("E18: parse failed");
    }
    crate::sync::__reset_for_test();

    match crate::eval::evaluate_method("\\E18", &[]) {
        Ok(crate::Value::Integer(1)) => TestResult::Pass,
        Ok(_) => TestResult::Fail("E18: expected Integer(1)"),
        Err(_) => TestResult::Fail("E18: evaluate_method failed"),
    }
}
kernel_test_in!("aml/e2e", e2e_aml_mutex_critical_section);

// ── Smoke E19: DSDT-style nested method calls with field I/O ─────────────────
//
// Exercises the evaluate_method → method-as-TermArg → recursive call path
// chained with an OpRegion read.
//
// AML:
//   OperationRegion(\E9RG, SystemMemory, <buf_phys>, 8)
//   Field(\E9RG, ByteAcc, NoLock, Preserve) { \E9BV, 8 }
//   Method(\E9GV, 0) { Return(\E9BV) }          // inner: reads field
//   Method(\E9DV, 0) { Return(Add(\E9GV(), 1)) } // outer: calls inner + 1
//
// backing[0] = 0x0F → E9GV returns 0x0F → E9DV returns 0x10.

fn e2e_aml_nested_method_calls_with_field_read() -> TestResult {
    use alloc::boxed::Box;

    crate::__reset_for_test();
    crate::oregion::__reset_for_test();

    let mut backing: Box<[u8; 8]> = Box::new([0u8; 8]);
    backing[0] = 0x0F;
    let phys = backing.as_ptr() as u64;

    let rgn = op_region_qword(b"E9RG", 0x00, phys, 8);
    let fld = field_byte_acc(b"E9RG", b"E9BV", 8);

    // Method(\E9GV, 0) { Return(E9BV) }
    let getter_body: &[u8] = &[0xA4, b'E', b'9', b'B', b'V'];
    let getter = method_blob(b"E9GV", 0, getter_body);

    // Method(\E9DV, 0) { Return(Add(E9GV(), 1, Local0)) }
    // E9GV() as TermArg: evaluator resolves E9GV as a 0-arg Method and
    // calls it inline. AddOp then adds 1.
    let doubler_body: &[u8] = &[
        0xA4, // ReturnOp
        0x72, // AddOp
        b'E', b'9', b'G', b'V', // MethodInvocation (0 args, resolved by evaluator)
        0x01, // OneOp
        0x60, // Local0 (result)
    ];
    let doubler = method_blob(b"E9DV", 0, doubler_body);

    let mut blob = alloc::vec::Vec::new();
    blob.extend_from_slice(&rgn);
    blob.extend_from_slice(&fld);
    blob.extend_from_slice(&getter);
    blob.extend_from_slice(&doubler);

    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        drop(backing);
        return TestResult::Fail("E19: parse failed");
    }

    let result = crate::eval::evaluate_method("\\E9DV", &[]);
    drop(backing);

    match result {
        Ok(crate::Value::Integer(0x10)) => TestResult::Pass,
        Ok(crate::Value::Integer(v)) => {
            let _ = v;
            TestResult::Fail("E19: expected Integer(0x10)")
        }
        Ok(_) => TestResult::Fail("E19: non-integer result"),
        Err(_) => TestResult::Fail("E19: evaluate_method failed"),
    }
}
kernel_test_in!("aml/e2e", e2e_aml_nested_method_calls_with_field_read);

// ── Smoke E20: CreateField (variable-width) + round-trip ─────────────────────
//
// CreateField(\E20B, 8, 16, \E20F)  — 16-bit field starting at bit 8
// (byte 1 of the buffer). Write 0xBEEF, read back.
//
// CreateField encoding: 0x5B 0x13 <SourceBuf> <BitIndex> <NumBits> <FieldName>
// (ACPI 6.5 §20.2.5.2 CreateFieldOp)

fn e2e_aml_create_field_variable_width() -> TestResult {
    crate::__reset_for_test();
    crate::oregion::__reset_for_test();

    // Name(\E20B, Buffer(4){0,0,0,0})
    let buf_body: &[u8] = &[
        0x11, // BufferOp
        0x07, // PkgLength = 7 (1+2+4)
        0x0A, 0x04, // BytePrefix 4 (size)
        0x00, 0x00, 0x00, 0x00,
    ];
    let mut blob = alloc::vec::Vec::new();
    blob.push(0x08); // NameOp
    blob.push(b'\\');
    blob.extend_from_slice(b"E20B");
    blob.extend_from_slice(buf_body);

    // CreateField(\E20B, 8, 16, \E20F)
    // 0x5B 0x13  <SourceBuf-NameSeg>  <BitIndex-BytePrefix(8)>
    //            <NumBits-BytePrefix(16)>  <FieldName-NameSeg>
    blob.push(0x5B); // EXT_OP_PREFIX
    blob.push(0x13); // CreateFieldOp
    blob.push(b'\\');
    blob.extend_from_slice(b"E20B"); // source buffer
    blob.push(0x0A); // BytePrefix
    blob.push(8); // BitIndex = 8 (bit 8 = byte 1)
    blob.push(0x0A); // BytePrefix
    blob.push(16); // NumBits = 16
    blob.push(b'\\');
    blob.extend_from_slice(b"E20F"); // field name

    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("E20: parse failed");
    }

    // Verify BufferField node registered.
    let node = match crate::find_node("\\E20F") {
        Some(n) => n,
        None => return TestResult::Fail("E20: \\E20F not registered"),
    };
    if node.kind != crate::NodeKind::BufferField {
        return TestResult::Fail("E20: \\E20F not a BufferField");
    }

    // Write 0xBEEF to the 16-bit field (bit offset 8).
    crate::write_buffer_field("\\E20B", 8, 16, 0xBEEF);

    // Read back via read_buffer_field.
    let rb = crate::read_buffer_field("\\E20F");
    if rb != 0xBEEF {
        return TestResult::Fail("E20: read_buffer_field returned wrong value");
    }

    // Verify backing buffer bytes.
    let buf = match crate::read_name_as_buffer("\\E20B") {
        Some(b) => b,
        None => return TestResult::Fail("E20: could not read \\E20B"),
    };
    if buf.len() < 3 {
        return TestResult::Fail("E20: buffer too short");
    }
    // Little-endian: byte[1] = 0xEF, byte[2] = 0xBE
    if buf[1] != 0xEF || buf[2] != 0xBE {
        return TestResult::Fail("E20: buffer bytes wrong after write");
    }

    TestResult::Pass
}
kernel_test_in!("aml/e2e", e2e_aml_create_field_variable_width);

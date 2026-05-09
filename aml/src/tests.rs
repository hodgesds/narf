//! Per-crate smoke tests for `narf-aml`.
//!
//! Migrated from `narf-verification`'s mega-lib. Tests register
//! under the `aml` subsystem so the runner groups output
//! appropriately.

extern crate alloc;

use narf_kernel_test::{kernel_test_in, TestResult};

#[cfg(target_arch = "x86_64")]
fn smoke_aml_namespace_built_at_boot() -> TestResult {
    // Boot built the namespace from DSDT + SSDTs. QEMU q35 ships a
    // substantial table set. Other tests in the harness mutate the
    // live namespace (synthetic-body parsing, __reset_for_test calls),
    // so we consult the boot-time snapshot captured by frame/main.rs
    // immediately after the first parse_namespace.
    let (n, d) = crate::boot_snapshot();
    if n == 0 {
        return TestResult::Fail("boot snapshot wasn't captured");
    }
    if d < 4 {
        return TestResult::Fail("expected >=4 devices at boot");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("aml", smoke_aml_namespace_built_at_boot);

fn smoke_aml_synthetic_scope_and_name() -> TestResult {
    // Synthetic AML body: Scope(\X) { Name(_HID, 0x12345678) }.
    // ScopeOp(0x10), PkgLength, NameString(\X), TermList:
    //   NameOp(0x08), NameString(_HID), DWordPrefix, 0x78 0x56 0x34 0x12.
    crate::__reset_for_test();

    let mut body: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    body.push(0x10); // ScopeOp
                     // We'll patch PkgLength after building the body.
    let pkg_len_pos = body.len();
    body.push(0); // placeholder
                  // NameString: \X___ (root + 1 seg, name "X" padded to 4 chars).
    body.push(b'\\');
    body.extend_from_slice(b"X___");
    // Body inside scope: Name(_HID, DWord 0x12345678)
    body.push(0x08); // NameOp
    body.extend_from_slice(b"_HID");
    body.push(0x0C); // DWord prefix
    body.extend_from_slice(&0x12345678u32.to_le_bytes());

    // Pkg length covers from pkg_len_pos to end of body (NOT
    // including ScopeOp byte). Single-byte form supports up to
    // 0x3F bytes — easily fits.
    let pkg_total = body.len() - pkg_len_pos;
    body[pkg_len_pos] = pkg_total as u8;

    let n = match crate::__parse_body_for_test(&body, "\\") {
        Ok(n) => n,
        Err(e) => {
            return TestResult::Fail(match e {
                crate::AmlError::Truncated => "truncated",
                crate::AmlError::BadPkgLength => "bad pkglen",
                crate::AmlError::OutOfPkg => "out of pkg",
                crate::AmlError::Acpi(_) => "acpi err",
                crate::AmlError::BadNameSegment => "bad nameseg",
                crate::AmlError::NoDsdt => "no dsdt",
                crate::AmlError::MethodNotFound => "method not found",
            })
        }
    };
    if n != 2 {
        return TestResult::Fail("expected 2 nodes (Scope + Name)");
    }

    let scope = match crate::find_node("\\X") {
        Some(s) => s,
        None => return TestResult::Fail("Scope \\X missing"),
    };
    if scope.kind != crate::NodeKind::Scope {
        return TestResult::Fail("Scope kind wrong");
    }

    let hid = match crate::find_node("\\X._HID") {
        Some(n) => n,
        None => return TestResult::Fail("\\X._HID missing"),
    };
    match hid.value {
        Some(crate::NameValue::Integer(v)) if v == 0x12345678 => {}
        _ => return TestResult::Fail("_HID value didn't decode"),
    }
    TestResult::Pass
}
kernel_test_in!("aml", smoke_aml_synthetic_scope_and_name);

fn smoke_aml_synthetic_method_skipped() -> TestResult {
    // Method(\Y, 0) { Return(One) }. Verify Method is registered as
    // a node, body offset/length recorded, and the sentinel Return
    // op (0xA4 0x01) inside the body isn't treated as a top-level
    // declaration.
    crate::__reset_for_test();

    let mut body: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    body.push(0x14); // MethodOp
    let pkg_len_pos = body.len();
    body.push(0);
    body.push(b'\\');
    body.extend_from_slice(b"Y___");
    body.push(0); // method flags: 0 args
    body.push(0xA4); // ReturnOp
    body.push(0x01); // OneOp
    let pkg_total = body.len() - pkg_len_pos;
    body[pkg_len_pos] = pkg_total as u8;

    let n = match crate::__parse_body_for_test(&body, "\\") {
        Ok(n) => n,
        Err(_) => return TestResult::Fail("parse failed"),
    };
    if n != 1 {
        return TestResult::Fail("expected exactly 1 Method node");
    }
    let m = match crate::find_node("\\Y") {
        Some(m) => m,
        None => return TestResult::Fail("Method \\Y missing"),
    };
    if m.kind != crate::NodeKind::Method {
        return TestResult::Fail("kind wasn't Method");
    }
    if m.method_body.1 == 0 {
        return TestResult::Fail("method body length not recorded");
    }
    TestResult::Pass
}
kernel_test_in!("aml", smoke_aml_synthetic_method_skipped);

// ── AML method evaluator tests ────────────────────────────────────────────────
//
// These tests append synthetic Method nodes into the global namespace *without*
// calling __reset_for_test(), so they do not disturb the boot-time namespace
// that smoke_aml_namespace_built_at_boot relies on.  Each uses a distinct
// 4-char NameSeg so find_node() always matches the freshly-added node.

/// Build a `Method(\NAME, flags, body)` AML blob where `name4` is the exact
/// 4-byte NameSeg (e.g. `b"EV1_"`; trailing underscores are stripped by the
/// namespace builder, yielding path `\EV1`).
fn build_eval_method_blob(name4: &[u8; 4], flags: u8, body: &[u8]) -> alloc::vec::Vec<u8> {
    // NameString = root char (\) + 4-byte NameSeg.
    // PkgLength value = 1 (PkgLength byte) + 1 (root char) + 4 (NameSeg)
    //                 + 1 (flags) + body.len().
    let pkg_total = 1 + 1 + 4 + 1 + body.len();
    let mut blob = alloc::vec::Vec::new();
    blob.push(0x14); // MethodOp
    blob.push(pkg_total as u8); // single-byte PkgLength (must fit in 6 bits)
    blob.push(b'\\'); // root char
    blob.extend_from_slice(name4); // 4-byte NameSeg
    blob.push(flags); // MethodFlags
    blob.extend_from_slice(body);
    blob
}

fn smoke_aml_eval_add() -> TestResult {
    // Method(\EV1_, 0) { Return(Add(2, 3, Local0)) } → 5
    let body: &[u8] = &[
        0xA4, // ReturnOp
        0x72, // AddOp
        0x0A, 0x02, // BytePrefix 2
        0x0A, 0x03, // BytePrefix 3
        0x60, // Local0 (target)
    ];
    let blob = build_eval_method_blob(b"EV1_", 0, body);
    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("parse failed");
    }
    match crate::eval::evaluate_method("\\EV1", &[]) {
        Ok(crate::Value::Integer(5)) => TestResult::Pass,
        Ok(_) => TestResult::Fail("expected Integer(5)"),
        Err(_) => TestResult::Fail("evaluate_method failed"),
    }
}
kernel_test_in!("aml", smoke_aml_eval_add);

fn smoke_aml_eval_if_lequal() -> TestResult {
    // Method(\EV2_, 0) { Store(0x10, Local0); If(LEqual(Local0, 0x10)) { Return(One) } Return(Zero) } → 1
    let if_body: &[u8] = &[0xA4, 0x01]; // ReturnOp OneOp
    let pred: &[u8] = &[0x93, 0x60, 0x0A, 0x10]; // LEqual(Local0, 0x10)
                                                 // PkgLength for If: 1 (PkgLength byte) + pred.len() + if_body.len()
    let if_pkg_total = 1 + pred.len() + if_body.len();

    let mut body: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    body.push(0x70);
    body.push(0x0A);
    body.push(0x10);
    body.push(0x60); // Store(0x10, Local0)
    body.push(0xA0);
    body.push(if_pkg_total as u8); // IfOp PkgLength
    body.extend_from_slice(pred); // predicate
    body.extend_from_slice(if_body); // then-body
    body.push(0xA4);
    body.push(0x00); // Return(Zero)

    let blob = build_eval_method_blob(b"EV2_", 0, &body);
    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("parse failed");
    }
    match crate::eval::evaluate_method("\\EV2", &[]) {
        Ok(crate::Value::Integer(1)) => TestResult::Pass,
        Ok(_) => TestResult::Fail("expected Integer(1)"),
        Err(_) => TestResult::Fail("evaluate_method failed"),
    }
}
kernel_test_in!("aml", smoke_aml_eval_if_lequal);

fn smoke_aml_eval_while_increment() -> TestResult {
    // Method(\EV3_, 0) { Store(0, Local0); While(LLess(Local0, 5)) { Increment(Local0) } Return(Local0) } → 5
    let while_body: &[u8] = &[0x75, 0x60]; // IncrementOp Local0
    let pred: &[u8] = &[0x95, 0x60, 0x0A, 0x05]; // LLess(Local0, 5)
                                                 // PkgLength for While: 1 (PkgLength byte) + pred.len() + while_body.len()
    let while_pkg_total = 1 + pred.len() + while_body.len();

    let mut body: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    body.push(0x70);
    body.push(0x00);
    body.push(0x60); // Store(0, Local0)
    body.push(0xA2);
    body.push(while_pkg_total as u8); // WhileOp PkgLength
    body.extend_from_slice(pred);
    body.extend_from_slice(while_body);
    body.push(0xA4);
    body.push(0x60); // Return(Local0)

    let blob = build_eval_method_blob(b"EV3_", 0, &body);
    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("parse failed");
    }
    match crate::eval::evaluate_method("\\EV3", &[]) {
        Ok(crate::Value::Integer(5)) => TestResult::Pass,
        Ok(_) => TestResult::Fail("expected Integer(5)"),
        Err(_) => TestResult::Fail("evaluate_method failed"),
    }
}
kernel_test_in!("aml", smoke_aml_eval_while_increment);

fn smoke_aml_eval_multiply_arg() -> TestResult {
    // Method(\EV4_, 1) { Return(Multiply(Arg0, 7, Local0)) } called with [6] → 42
    let body: &[u8] = &[
        0xA4, // ReturnOp
        0x77, // MultiplyOp
        0x68, // Arg0
        0x0A, 0x07, // BytePrefix 7
        0x60, // Local0 (target)
    ];
    let blob = build_eval_method_blob(b"EV4_", 1, body);
    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("parse failed");
    }
    let args = [crate::Value::Integer(6)];
    match crate::eval::evaluate_method("\\EV4", &args) {
        Ok(crate::Value::Integer(42)) => TestResult::Pass,
        Ok(_) => TestResult::Fail("expected Integer(42)"),
        Err(_) => TestResult::Fail("evaluate_method failed"),
    }
}
kernel_test_in!("aml", smoke_aml_eval_multiply_arg);

// ── Resource template tests ──────────────────────────────────────────────────

fn smoke_aml_resource_irq_io_endtag() -> TestResult {
    // IRQ descriptor (mask 0x0010 = IRQ4) + IO Port + EndTag
    let buf: &[u8] = &[
        0x22, 0x10, 0x00, // small IRQ: type=4, len=2; mask=0x0010
        0x47, 0x01, 0x00, 0x03, 0x00, 0x03, 0x01, 0x08, // IO port: type=8, len=7
        0x79, 0x00, // EndTag
    ];
    let items = match crate::resource::decode_resource_template(buf) {
        Ok(v) => v,
        Err(e) => {
            let _ = match e {
                crate::resource::ResourceError::Truncated => "truncated",
                crate::resource::ResourceError::BadTag => "bad tag",
                crate::resource::ResourceError::NoEndTag => "no end tag",
            };
            return TestResult::Fail("decode_resource_template failed");
        }
    };
    if items.len() != 3 {
        return TestResult::Fail("expected 3 items");
    }
    match &items[0] {
        crate::resource::ResourceItem::Irq { mask, flags } => {
            if *mask != 0x0010 {
                return TestResult::Fail("IRQ mask wrong");
            }
            if *flags != None {
                return TestResult::Fail("IRQ flags should be None");
            }
        }
        _ => return TestResult::Fail("item[0] not Irq"),
    }
    match &items[1] {
        crate::resource::ResourceItem::Io {
            info,
            min,
            max,
            alignment,
            length,
        } => {
            if *info != 0x01 {
                return TestResult::Fail("IO info wrong");
            }
            if *min != 0x0300 {
                return TestResult::Fail("IO min wrong");
            }
            if *max != 0x0300 {
                return TestResult::Fail("IO max wrong");
            }
            if *alignment != 1 {
                return TestResult::Fail("IO alignment wrong");
            }
            if *length != 8 {
                return TestResult::Fail("IO length wrong");
            }
        }
        _ => return TestResult::Fail("item[1] not Io"),
    }
    match &items[2] {
        crate::resource::ResourceItem::EndTag => {}
        _ => return TestResult::Fail("item[2] not EndTag"),
    }
    TestResult::Pass
}
kernel_test_in!("aml", smoke_aml_resource_irq_io_endtag);

fn smoke_aml_resource_memory32fixed_large_tag() -> TestResult {
    // Large tag 0x86 (Memory32Fixed), length=9, then EndTag
    let buf: &[u8] = &[
        0x86, 0x09, 0x00, // large tag 0x86, payload length = 9
        0x00, // info = 0
        0x00, 0x00, 0x00, 0xFE, // base = 0xFE000000
        0x00, 0x00, 0x10, 0x00, // length = 0x00100000
        0x79, 0x00, // EndTag
    ];
    let items = match crate::resource::decode_resource_template(buf) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("decode_resource_template failed"),
    };
    if items.len() != 2 {
        return TestResult::Fail("expected 2 items");
    }
    match &items[0] {
        crate::resource::ResourceItem::Memory32Fixed { info, base, length } => {
            if *info != 0 {
                return TestResult::Fail("Memory32Fixed info wrong");
            }
            if *base != 0xFE00_0000 {
                return TestResult::Fail("Memory32Fixed base wrong");
            }
            if *length != 0x0010_0000 {
                return TestResult::Fail("Memory32Fixed length wrong");
            }
        }
        _ => return TestResult::Fail("item[0] not Memory32Fixed"),
    }
    match &items[1] {
        crate::resource::ResourceItem::EndTag => {}
        _ => return TestResult::Fail("item[1] not EndTag"),
    }
    TestResult::Pass
}
kernel_test_in!("aml", smoke_aml_resource_memory32fixed_large_tag);

fn smoke_aml_prt_decode() -> TestResult {
    use crate::Value;
    let entries_raw = alloc::vec![
        Value::Package(alloc::vec![
            Value::Integer(0x0001_FFFF),
            Value::Integer(0),  // INTA
            Value::Integer(0),  // no source name
            Value::Integer(16), // GSI 16
        ]),
        Value::Package(alloc::vec![
            Value::Integer(0x0002_FFFF),
            Value::Integer(1), // INTB
            Value::String(alloc::string::String::from("\\_SB.LNKB")),
            Value::Integer(0),
        ]),
    ];
    let prt = match crate::resource::decode_prt(&entries_raw) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("decode_prt failed"),
    };
    if prt.len() != 2 {
        return TestResult::Fail("expected 2 PrtEntry");
    }

    let e0 = &prt[0];
    if e0.address != 0x0001_FFFF {
        return TestResult::Fail("e0 address wrong");
    }
    if e0.pin != 0 {
        return TestResult::Fail("e0 pin wrong");
    }
    if e0.source != None {
        return TestResult::Fail("e0 source should be None");
    }
    if e0.source_index != 16 {
        return TestResult::Fail("e0 source_index wrong");
    }

    let e1 = &prt[1];
    if e1.address != 0x0002_FFFF {
        return TestResult::Fail("e1 address wrong");
    }
    if e1.pin != 1 {
        return TestResult::Fail("e1 pin wrong");
    }
    match &e1.source {
        Some(s) if s == "\\_SB.LNKB" => {}
        _ => return TestResult::Fail("e1 source wrong"),
    }
    if e1.source_index != 0 {
        return TestResult::Fail("e1 source_index wrong");
    }

    TestResult::Pass
}
kernel_test_in!("aml", smoke_aml_prt_decode);

// ── AML OpRegion / Field accessor smokes ─────────────────────────────────────

fn smoke_aml_oregion_sysmem_dword_field() -> TestResult {
    // Synthetic SystemMemory region pointing at an in-process buffer.
    //
    // AML declares:
    //   OpRegion(RGN0, SystemMemory, <buf_addr>, 8)
    //   Field(RGN0, DWordAcc, NoLock, Preserve) { F0, 32 }
    //
    // The buffer holds 0xCAFEBABE_DEADBEEF (little-endian u64).
    // F0 covers bits [0..32), so read_field("\\F0") should return the
    // low 32 bits = 0xDEADBEEF.
    use alloc::boxed::Box;

    crate::__reset_for_test();
    crate::oregion::__reset_for_test();

    // Allocate buffer and fill.
    let buf: Box<[u64; 1]> = Box::new([0xCAFEBABE_DEADBEEF_u64]);
    let addr = &buf[0] as *const u64 as u64;

    // Build the AML body.
    let mut body: alloc::vec::Vec<u8> = alloc::vec::Vec::new();

    // OpRegion(RGN0, SystemMemory, addr, 8)
    body.push(0x5B); // EXT_OP_PREFIX
    body.push(0x80); // EXT_OP_REGION_OP
                     // NameSeg RGN0 (4 bytes, no prefix — relative to parent \)
    body.extend_from_slice(b"RGN0");
    body.push(0x00); // RegionSpace = SystemMemory
                     // RegionOffset: QWordPrefix + 8-byte address
    body.push(0x0E);
    body.extend_from_slice(&addr.to_le_bytes());
    // RegionLen: BytePrefix + 8
    body.push(0x0A);
    body.push(0x08);

    // Field(RGN0, DWordAcc, NoLock, Preserve) { F0, 32 }
    // EXT_FIELD_OP, PkgLength, NameSeg(RGN0), FieldFlags(0x03=DWordAcc),
    //   NamedField: F0__ + PkgLength(32)
    body.push(0x5B);
    body.push(0x81);
    // PkgLength: content = 4(NameSeg) + 1(flags) + 4(NameSeg F0__) + 1(pkglen 32)
    //          = 10 bytes; total including PkgLen byte = 11 = 0x0B
    body.push(0x0B);
    body.extend_from_slice(b"RGN0");
    body.push(0x03); // DWordAcc
    body.extend_from_slice(b"F0__");
    body.push(0x20); // PkgLength for 32 bits (single-byte: 32 = 0x20)

    let _ = crate::__parse_body_for_test(&body, "\\");

    let result = crate::oregion::read_field("\\F0");
    drop(buf);

    match result {
        Ok(v) => {
            if v == 0xDEADBEEF {
                TestResult::Pass
            } else {
                TestResult::Fail("\\F0 value mismatch (expected 0xDEADBEEF)")
            }
        }
        Err(crate::oregion::FieldAccessError::NoField) => {
            TestResult::Fail("\\F0 not registered")
        }
        Err(crate::oregion::FieldAccessError::NoRegion) => {
            TestResult::Fail("\\RGN0 not registered")
        }
        Err(crate::oregion::FieldAccessError::TooWide) => {
            TestResult::Fail("read_field reported TooWide")
        }
        Err(crate::oregion::FieldAccessError::Unsupported) => {
            TestResult::Fail("read_field returned Unsupported for SystemMemory")
        }
    }
}
kernel_test_in!("aml", smoke_aml_oregion_sysmem_dword_field);

fn smoke_aml_oregion_bit_fields() -> TestResult {
    // Bit-level field test: SystemMemory region over a u64 = 0xFF.
    // Declare three 1-bit fields F0/F1/F2 at bit offsets 0/1/2.
    // Each should read back as 1 (all bits in 0xFF are set).
    use alloc::boxed::Box;

    crate::__reset_for_test();
    crate::oregion::__reset_for_test();

    let buf: Box<[u64; 1]> = Box::new([0xFF_u64]);
    let addr = &buf[0] as *const u64 as u64;

    let mut body: alloc::vec::Vec<u8> = alloc::vec::Vec::new();

    // OpRegion(BRG0, SystemMemory, addr, 8)
    body.push(0x5B);
    body.push(0x80);
    body.extend_from_slice(b"BRG0");
    body.push(0x00); // SystemMemory
    body.push(0x0E);
    body.extend_from_slice(&addr.to_le_bytes());
    body.push(0x0A);
    body.push(0x08); // length = 8 bytes

    // Field(BRG0, ByteAcc, NoLock, Preserve) { F0, 1, F1, 1, F2, 1 }
    // NameSeg BRG0 = 4, FieldFlags = 1, F0__(4) pkglen(1), F1__(4) pkglen(1), F2__(4) pkglen(1)
    // content = 4 + 1 + 5 + 5 + 5 = 20; total PkgLen = 21 = 0x15
    body.push(0x5B);
    body.push(0x81);
    body.push(0x15); // PkgLength = 21
    body.extend_from_slice(b"BRG0");
    body.push(0x01); // ByteAcc
    body.extend_from_slice(b"F0__");
    body.push(0x01); // bit_length = 1
    body.extend_from_slice(b"F1__");
    body.push(0x01); // bit_length = 1
    body.extend_from_slice(b"F2__");
    body.push(0x01); // bit_length = 1

    let _ = crate::__parse_body_for_test(&body, "\\");

    let r0 = crate::oregion::read_field("\\F0");
    let r1 = crate::oregion::read_field("\\F1");
    let r2 = crate::oregion::read_field("\\F2");
    drop(buf);

    match (r0, r1, r2) {
        (Ok(0), _, _) => TestResult::Fail("\\F0 bit=0 from 0xFF buffer"),
        (_, Ok(0), _) => TestResult::Fail("\\F1 bit=0 from 0xFF buffer"),
        (_, _, Ok(0)) => TestResult::Fail("\\F2 bit=0 from 0xFF buffer"),
        (Ok(1), Ok(1), Ok(1)) => TestResult::Pass,
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => match e {
            crate::oregion::FieldAccessError::NoField => {
                TestResult::Fail("field not registered")
            }
            crate::oregion::FieldAccessError::NoRegion => {
                TestResult::Fail("region not registered")
            }
            crate::oregion::FieldAccessError::TooWide => TestResult::Fail("field TooWide"),
            crate::oregion::FieldAccessError::Unsupported => TestResult::Fail("Unsupported"),
        },
        _ => TestResult::Fail("unexpected field value (not 0 or 1)"),
    }
}
kernel_test_in!("aml", smoke_aml_oregion_bit_fields);

#[cfg(target_arch = "x86_64")]
fn smoke_aml_oregion_boot_regions_present() -> TestResult {
    // After parse_namespace at boot, QEMU's DSDT declares several
    // PNP0C02 / EC OpRegions. Verify that at least one was captured.
    let mut count = 0usize;
    crate::oregion::for_each_region(|_| {
        count += 1;
    });
    if count > 0 {
        TestResult::Pass
    } else {
        TestResult::Fail("no OpRegion entries registered after boot namespace parse")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("aml", smoke_aml_oregion_boot_regions_present);

fn smoke_aml_oregion_pci_config_resolves() -> TestResult {
    // Synthetic AML that declares a rooted PCI device with an
    // ECAM-backed OpRegion.  Uses unique names (PCIT / RGNT / B0RT)
    // that do not collide with either the boot DSDT or other tests.
    // Does NOT call crate::__reset_for_test() so the boot-time
    // namespace is preserved intact.
    //
    //   Device(\PCIT) {
    //     Name(_BBN, 0x00)
    //     Name(_ADR, 0x00010000)   // slot 1, function 0
    //     OpRegion(RGNT, PciConfig, 0x10, 0x10)
    //     Field(RGNT, DWordAcc, NoLock, Preserve) { B0RT, 32 }
    //   }
    //
    // Verify:
    //   1. region_for("\\PCIT.RGNT") is registered with the right
    //      space / offset / length.
    //   2. read_field("\\PCIT.B0RT") does not return Unsupported when
    //      the ECAM base is known; Unsupported is accepted when the
    //      ECAM base is absent (e.g. aarch64 QEMU without MCFG).

    // Only reset the oregion tables (not the namespace) so we do not
    // disturb the boot-time node count relied on by other tests.
    crate::oregion::__reset_for_test();

    // ── Build AML ────────────────────────────────────────────────────
    let mut body: alloc::vec::Vec<u8> = alloc::vec::Vec::new();

    // Device(\PCIT): 0x5B 0x82
    body.push(0x5B);
    body.push(0x82);
    // PkgLength = 46
    body.push(46);
    // Rooted NameString: root char + "PCIT"
    body.push(b'\\');
    body.extend_from_slice(b"PCIT");

    // Name(_BBN, 0x00)
    body.push(0x08); // NameOp
    body.extend_from_slice(b"_BBN");
    body.push(0x00); // ZeroOp

    // Name(_ADR, DWord 0x00010000)
    body.push(0x08); // NameOp
    body.extend_from_slice(b"_ADR");
    body.push(0x0C); // DWordPrefix
    body.extend_from_slice(&0x0001_0000u32.to_le_bytes());

    // OpRegion(RGNT, PciConfig, 0x10, 0x10)
    body.push(0x5B);
    body.push(0x80);
    body.extend_from_slice(b"RGNT");
    body.push(0x02); // RegionSpace = PciConfig
    body.push(0x0A); // BytePrefix
    body.push(0x10); // offset = 16
    body.push(0x0A); // BytePrefix
    body.push(0x10); // length = 16

    // Field(RGNT, DWordAcc, NoLock, Preserve) { B0RT, 32 }
    body.push(0x5B);
    body.push(0x81);
    body.push(0x0B); // PkgLength = 11
    body.extend_from_slice(b"RGNT");
    body.push(0x03); // DWordAcc
    body.extend_from_slice(b"B0RT");
    body.push(0x20); // PkgLength for 32 bits

    let n = match crate::__parse_body_for_test(&body, "\\") {
        Ok(n) => n,
        Err(_) => return TestResult::Fail("parse failed"),
    };
    // Device(\PCIT) + Name(_BBN) + Name(_ADR) + OpRegion(RGNT) = 4 nodes.
    if n < 4 {
        return TestResult::Fail("expected at least 4 namespace nodes from Device blob");
    }

    // ── Verify region registration ────────────────────────────────────
    let rgn = match crate::oregion::region_for("\\PCIT.RGNT") {
        Some(r) => r,
        None => return TestResult::Fail("RGNT not registered"),
    };
    if rgn.space != crate::oregion::RegionSpace::PciConfig {
        return TestResult::Fail("RGNT space is not PciConfig");
    }
    if rgn.offset != 0x10 {
        return TestResult::Fail("RGNT offset mismatch");
    }
    if rgn.length != 0x10 {
        return TestResult::Fail("RGNT length mismatch");
    }

    // ── Verify read_field does not return Unsupported when ECAM is known ──
    let result = crate::oregion::read_field("\\PCIT.B0RT");
    let ecam_present = narf_acpi::mcfg_ecam_base().is_some();

    match result {
        Ok(_) => TestResult::Pass,
        Err(crate::oregion::FieldAccessError::Unsupported) if ecam_present => {
            TestResult::Fail("read_field returned Unsupported despite ECAM base being known")
        }
        Err(crate::oregion::FieldAccessError::Unsupported) => TestResult::Pass,
        Err(crate::oregion::FieldAccessError::NoField) => {
            TestResult::Fail("B0RT field not registered")
        }
        Err(crate::oregion::FieldAccessError::NoRegion) => {
            TestResult::Fail("RGNT region missing")
        }
        Err(crate::oregion::FieldAccessError::TooWide) => TestResult::Fail("B0RT TooWide"),
    }
}
kernel_test_in!("aml", smoke_aml_oregion_pci_config_resolves);

// ── AML sync smoke tests ──────────────────────────────────────────────────────
//
// These tests add synthetic Mutex/Event/Method nodes to the global namespace
// (no __reset_for_test call on the namespace) using unique 4-char NameSegs
// SM1..SM6 / TGT to avoid collisions with any other test nodes.

/// Build a 7-byte NameString encoding `\XXXX` (root char + 4-byte NameSeg).
fn name_seg_root(seg: &[u8; 4]) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec::Vec::new();
    v.push(b'\\');
    v.extend_from_slice(seg);
    v
}

fn smoke_aml_sync_mutex_acquire_release() -> TestResult {
    // Declare Mutex(\SM1_, 0) then Method(\SM2_, 0) {
    //   Acquire(\SM1, 0xFFFF); Release(\SM1); Return(One)
    // }
    use alloc::vec::Vec;

    let mut blob: Vec<u8> = Vec::new();
    blob.push(0x5B); // EXT_OP_PREFIX
    blob.push(0x01); // EXT_MUTEX_OP
    blob.extend_from_slice(&name_seg_root(b"SM1_")); // \SM1_
    blob.push(0x00); // SyncFlags

    // -- Method(\SM2_, 0) body --
    let mut body: Vec<u8> = Vec::new();
    body.push(0x5B);
    body.push(0x23); // AcquireOp
    body.extend_from_slice(&name_seg_root(b"SM1_")); // \SM1_
    body.push(0xFF);
    body.push(0xFF); // timeout = 0xFFFF
    body.push(0x5B);
    body.push(0x27); // ReleaseOp
    body.extend_from_slice(&name_seg_root(b"SM1_")); // \SM1_
    body.push(0xA4);
    body.push(0x01); // ReturnOp OneOp

    let pkg_total = 1 + 1 + 4 + 1 + body.len();
    blob.push(0x14); // MethodOp
    blob.push(pkg_total as u8); // single-byte PkgLength
    blob.extend_from_slice(&name_seg_root(b"SM2_")); // \SM2_
    blob.push(0x00); // MethodFlags
    blob.extend_from_slice(&body);

    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("SM2 parse failed");
    }
    crate::sync::__reset_for_test();

    match crate::eval::evaluate_method("\\SM2", &[]) {
        Ok(crate::Value::Integer(1)) => TestResult::Pass,
        Ok(v) => {
            let _ = v;
            TestResult::Fail("expected Integer(1) from SM2")
        }
        Err(_) => TestResult::Fail("evaluate_method \\SM2 failed"),
    }
}
kernel_test_in!("aml", smoke_aml_sync_mutex_acquire_release);

fn smoke_aml_sync_stall_sleep_no_trap() -> TestResult {
    // Method(\SM3_, 0) { Stall(10); Sleep(1); Return(0x42) }
    use alloc::vec::Vec;

    let mut body: Vec<u8> = Vec::new();
    body.push(0x5B);
    body.push(0x21); // StallOp
    body.push(0x0A);
    body.push(10); // BytePrefix 10
    body.push(0x5B);
    body.push(0x22); // SleepOp
    body.push(0x0A);
    body.push(1); // BytePrefix 1
    body.push(0xA4); // ReturnOp
    body.push(0x0A);
    body.push(0x42); // BytePrefix 0x42

    let pkg_total = 1 + 1 + 4 + 1 + body.len();
    let mut blob: Vec<u8> = Vec::new();
    blob.push(0x14);
    blob.push(pkg_total as u8);
    blob.extend_from_slice(&name_seg_root(b"SM3_"));
    blob.push(0x00);
    blob.extend_from_slice(&body);

    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("SM3 parse failed");
    }
    match crate::eval::evaluate_method("\\SM3", &[]) {
        Ok(crate::Value::Integer(0x42)) => TestResult::Pass,
        Ok(_) => TestResult::Fail("expected Integer(0x42) from SM3"),
        Err(_) => TestResult::Fail("evaluate_method \\SM3 failed"),
    }
}
kernel_test_in!("aml", smoke_aml_sync_stall_sleep_no_trap);

fn smoke_aml_sync_notify_dispatch() -> TestResult {
    // Register a handler that stores the notified value into a static.
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU64, Ordering};

    static NOTIFY_VAL: AtomicU64 = AtomicU64::new(0);

    fn handler(_target: &str, value: u64) {
        NOTIFY_VAL.store(value, Ordering::Relaxed);
    }

    crate::sync::register_notify_handler("\\TGT", handler);

    // Declare Name(\TGT_, 0) so \TGT exists in the namespace.
    let mut blob: Vec<u8> = Vec::new();
    blob.push(0x08); // NameOp
    blob.extend_from_slice(&name_seg_root(b"TGT_")); // \TGT_
    blob.push(0x00); // ZeroOp (value = 0)

    // Method(\SM4_, 0) { Notify(\TGT_, 5); Return(One) }
    let mut body: Vec<u8> = Vec::new();
    body.push(0x86); // NotifyOp
    body.extend_from_slice(&name_seg_root(b"TGT_")); // \TGT_
    body.push(0x0A);
    body.push(5); // BytePrefix 5
    body.push(0xA4);
    body.push(0x01); // Return(One)

    let pkg_total = 1 + 1 + 4 + 1 + body.len();
    blob.push(0x14);
    blob.push(pkg_total as u8);
    blob.extend_from_slice(&name_seg_root(b"SM4_"));
    blob.push(0x00);
    blob.extend_from_slice(&body);

    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("SM4 parse failed");
    }

    NOTIFY_VAL.store(0, Ordering::Relaxed);
    match crate::eval::evaluate_method("\\SM4", &[]) {
        Err(_) => return TestResult::Fail("evaluate_method \\SM4 failed"),
        Ok(_) => {}
    }
    if NOTIFY_VAL.load(Ordering::Relaxed) == 5 {
        TestResult::Pass
    } else {
        TestResult::Fail("notify handler not called with value 5")
    }
}
kernel_test_in!("aml", smoke_aml_sync_notify_dispatch);

fn smoke_aml_sync_event_signal_wait() -> TestResult {
    // Event(\SM5_) + Method(\SM6_, 0) {
    //   Reset(\SM5); Signal(\SM5); Wait(\SM5, 0xFFFF); Return(One)
    // }
    use alloc::vec::Vec;

    let mut blob: Vec<u8> = Vec::new();
    blob.push(0x5B); // EXT_OP_PREFIX
    blob.push(0x02); // EXT_EVENT_OP
    blob.extend_from_slice(&name_seg_root(b"SM5_")); // \SM5_

    // -- Method(\SM6_, 0) body --
    let mut body: Vec<u8> = Vec::new();
    body.push(0x5B);
    body.push(0x26); // ResetOp
    body.extend_from_slice(&name_seg_root(b"SM5_"));
    body.push(0x5B);
    body.push(0x24); // SignalOp
    body.extend_from_slice(&name_seg_root(b"SM5_"));
    body.push(0x5B);
    body.push(0x25); // WaitOp
    body.extend_from_slice(&name_seg_root(b"SM5_"));
    body.push(0x0B);
    body.push(0xFF);
    body.push(0xFF); // WordPrefix 0xFFFF
    body.push(0xA4);
    body.push(0x01);

    let pkg_total = 1 + 1 + 4 + 1 + body.len();
    blob.push(0x14);
    blob.push(pkg_total as u8);
    blob.extend_from_slice(&name_seg_root(b"SM6_"));
    blob.push(0x00);
    blob.extend_from_slice(&body);

    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("SM6 parse failed");
    }
    crate::sync::__reset_for_test();

    match crate::eval::evaluate_method("\\SM6", &[]) {
        Ok(crate::Value::Integer(1)) => TestResult::Pass,
        Ok(_) => TestResult::Fail("expected Integer(1) from SM6"),
        Err(_) => TestResult::Fail("evaluate_method \\SM6 failed"),
    }
}
kernel_test_in!("aml", smoke_aml_sync_event_signal_wait);

// ── GPE smoke tests ─────────────────────────────────────────────────

fn smoke_aml_gpe_install_aml_handlers() -> TestResult {
    // Synthetic AML: Scope(\\_GPE) { Method(_L01, 0) { Return(One) }
    //                                Method(_E0F, 0) { Return(Zero) } }
    use alloc::vec::Vec;

    crate::__reset_for_test();
    crate::gpe::__reset_for_test();

    // ── build blob ────────────────────────────────────────────────
    let mut blob: Vec<u8> = Vec::new();

    let method_l01: Vec<u8> = {
        let mut v = Vec::new();
        v.push(0x14); // MethodOp
        v.push(8u8); // PkgLength (single-byte: covers rest of method)
        v.extend_from_slice(b"_L01"); // relative NameSeg
        v.push(0x00); // MethodFlags: 0 args
        v.push(0xA4);
        v.push(0x01); // Return(One)
        v
    };

    let method_e0f: Vec<u8> = {
        let mut v = Vec::new();
        v.push(0x14); // MethodOp
        v.push(8u8); // PkgLength
        v.extend_from_slice(b"_E0F"); // relative NameSeg
        v.push(0x00); // MethodFlags
        v.push(0xA4);
        v.push(0x00); // Return(Zero)
        v
    };

    blob.push(0x10); // ScopeOp
    let pkg_len_pos = blob.len();
    blob.push(0u8); // PkgLength placeholder
    blob.push(b'\\'); // ROOT_CHAR
    blob.extend_from_slice(b"_GPE"); // NameSeg
    blob.extend_from_slice(&method_l01);
    blob.extend_from_slice(&method_e0f);
    let pkg_total = blob.len() - pkg_len_pos;
    blob[pkg_len_pos] = pkg_total as u8;

    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("GPE scope parse failed");
    }

    let installed = crate::gpe::install_aml_handlers();
    if installed != 2 {
        return TestResult::Fail("install_aml_handlers should return 2");
    }
    if crate::gpe::handler_count() != 2 {
        return TestResult::Fail("handler_count() should be 2");
    }
    TestResult::Pass
}
kernel_test_in!("aml", smoke_aml_gpe_install_aml_handlers);

fn smoke_aml_gpe_dispatch_native() -> TestResult {
    // Register a native handler for GPE 99, dispatch it, verify the counter.
    use core::sync::atomic::{AtomicU32, Ordering};
    static HITS: AtomicU32 = AtomicU32::new(0);

    crate::gpe::__reset_for_test();
    HITS.store(0, Ordering::Relaxed);

    fn handler(gpe: u32) {
        if gpe == 99 {
            HITS.fetch_add(1, Ordering::Relaxed);
        }
    }

    crate::gpe::register_native_handler(99, handler);
    crate::gpe::dispatch(99);

    if HITS.load(Ordering::Relaxed) == 1 {
        TestResult::Pass
    } else {
        TestResult::Fail("native GPE handler not called exactly once")
    }
}
kernel_test_in!("aml", smoke_aml_gpe_dispatch_native);

fn smoke_aml_gpe_dispatch_aml() -> TestResult {
    // Synthetic AML: Scope(\\_GPE) { Method(_L05, 0) { Notify(\TGN_, 0xAB) } }
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU64, Ordering};

    static NOTIFY_VAL: AtomicU64 = AtomicU64::new(0);

    fn notify_handler(_target: &str, value: u64) {
        NOTIFY_VAL.store(value, Ordering::Relaxed);
    }

    crate::__reset_for_test();
    crate::sync::__reset_for_test();
    crate::gpe::__reset_for_test();
    NOTIFY_VAL.store(0, Ordering::Relaxed);

    crate::sync::register_notify_handler("\\TGN", notify_handler);

    // Declare Name(\TGN_, 0) so \TGN exists in the namespace.
    let mut blob: Vec<u8> = Vec::new();
    blob.push(0x08); // NameOp
    blob.push(b'\\');
    blob.extend_from_slice(b"TGN_"); // \TGN_
    blob.push(0x00); // ZeroOp

    let method_body: Vec<u8> = {
        let mut v = Vec::new();
        v.push(0x86); // NotifyOp
        v.push(b'\\');
        v.extend_from_slice(b"TGN_"); // \TGN_
        v.push(0x0A);
        v.push(0xABu8); // BytePrefix 0xAB
        v.push(0xA4);
        v.push(0x01); // Return(One)
        v
    };
    let method_l05: Vec<u8> = {
        let mut v = Vec::new();
        v.push(0x14); // MethodOp
        let pkg_total: u8 = (1 + 4 + 1 + method_body.len()) as u8;
        v.push(pkg_total);
        v.extend_from_slice(b"_L05"); // relative NameSeg
        v.push(0x00); // MethodFlags
        v.extend_from_slice(&method_body);
        v
    };

    blob.push(0x10); // ScopeOp
    let pkg_len_pos = blob.len();
    blob.push(0u8); // PkgLength placeholder
    blob.push(b'\\');
    blob.extend_from_slice(b"_GPE");
    blob.extend_from_slice(&method_l05);
    let pkg_total = blob.len() - pkg_len_pos;
    blob[pkg_len_pos] = pkg_total as u8;

    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("_L05 scope parse failed");
    }

    let installed = crate::gpe::install_aml_handlers();
    if installed == 0 {
        return TestResult::Fail("install_aml_handlers found no GPE methods");
    }

    crate::gpe::dispatch(0x05);

    if NOTIFY_VAL.load(Ordering::Relaxed) == 0xAB {
        TestResult::Pass
    } else {
        TestResult::Fail("Notify value via GPE dispatch not received as 0xAB")
    }
}
kernel_test_in!("aml", smoke_aml_gpe_dispatch_aml);

// ── _PRT / _CRS bridge smoke tests ───────────────────────────────────────────

fn smoke_aml_prt_evaluation_round_trip() -> TestResult {
    // Build AML for:
    //   Scope(\_T1) { Device(PT01) { Method(_PRT, 0) {
    //     Return(Package(2) {
    //       Package(4) { 0x0001FFFF, 0, 0, 16 },
    //       Package(4) { 0x0002FFFF, 1, 0, 17 }
    //     })
    //   }}}

    crate::__reset_for_test();

    // inner Package(4) { 0x0001FFFF, 0, 0, 16 }
    let inner1: alloc::vec::Vec<u8> = {
        let mut v = alloc::vec::Vec::new();
        v.push(0x12); // PackageOp
        v.push(0x0B); // PkgLen = 11
        v.push(0x04); // NumElements = 4
        v.push(0x0C);
        v.push(0xFF);
        v.push(0xFF);
        v.push(0x01);
        v.push(0x00);
        v.push(0x00); // ZeroOp
        v.push(0x00); // ZeroOp
        v.push(0x0A);
        v.push(0x10); // BytePrefix 16
        v
    };

    // inner Package(4) { 0x0002FFFF, 1, 0, 17 }
    let inner2: alloc::vec::Vec<u8> = {
        let mut v = alloc::vec::Vec::new();
        v.push(0x12); // PackageOp
        v.push(0x0B); // PkgLen = 11
        v.push(0x04); // NumElements = 4
        v.push(0x0C);
        v.push(0xFF);
        v.push(0xFF);
        v.push(0x02);
        v.push(0x00);
        v.push(0x01); // OneOp (1)
        v.push(0x00); // ZeroOp (0)
        v.push(0x0A);
        v.push(0x11); // BytePrefix 17
        v
    };

    // outer Package(2) { inner1, inner2 }
    let outer_pkg: alloc::vec::Vec<u8> = {
        let mut v = alloc::vec::Vec::new();
        v.push(0x12); // PackageOp
        v.push(0x1A); // PkgLen = 26
        v.push(0x02); // NumElements = 2
        v.extend_from_slice(&inner1);
        v.extend_from_slice(&inner2);
        v
    };

    let return_stmt: alloc::vec::Vec<u8> = {
        let mut v = alloc::vec::Vec::new();
        v.push(0xA4); // ReturnOp
        v.extend_from_slice(&outer_pkg);
        v
    };

    let method: alloc::vec::Vec<u8> = {
        let mut v = alloc::vec::Vec::new();
        v.push(0x14); // MethodOp
        v.push(0x22); // PkgLen = 34
        v.extend_from_slice(b"_PRT"); // NameSeg (relative)
        v.push(0x00); // MethodFlags
        v.extend_from_slice(&return_stmt);
        v
    };

    let device: alloc::vec::Vec<u8> = {
        let mut v = alloc::vec::Vec::new();
        v.push(0x5B);
        v.push(0x82); // DeviceOp
        v.push(0x28); // PkgLen = 40
        v.extend_from_slice(b"PT01"); // NameSeg
        v.extend_from_slice(&method);
        v
    };

    let blob: alloc::vec::Vec<u8> = {
        let mut v = alloc::vec::Vec::new();
        v.push(0x10); // ScopeOp
        v.push(0x30); // PkgLen = 48
        v.push(b'\\'); // root char
        v.extend_from_slice(b"_T1_"); // NameSeg (strips to _T1)
        v.extend_from_slice(&device);
        v
    };

    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("prt: parse failed");
    }

    match crate::prt_crs::evaluate_prt_for("\\_T1.PT01") {
        Ok(entries) if entries.len() == 2 => {
            let e0 = &entries[0];
            let e1 = &entries[1];
            if e0.address != 0x0001FFFF {
                return TestResult::Fail("prt: entry[0].address mismatch");
            }
            if e0.pin != 0 {
                return TestResult::Fail("prt: entry[0].pin mismatch");
            }
            if e0.source_index != 16 {
                return TestResult::Fail("prt: entry[0].source_index mismatch");
            }
            if e1.address != 0x0002FFFF {
                return TestResult::Fail("prt: entry[1].address mismatch");
            }
            if e1.pin != 1 {
                return TestResult::Fail("prt: entry[1].pin mismatch");
            }
            if e1.source_index != 17 {
                return TestResult::Fail("prt: entry[1].source_index mismatch");
            }
            TestResult::Pass
        }
        Ok(entries) => {
            let _ = entries;
            TestResult::Fail("prt: expected 2 entries")
        }
        Err(_) => TestResult::Fail("prt: evaluate_prt_for failed"),
    }
}
kernel_test_in!("aml", smoke_aml_prt_evaluation_round_trip);

fn smoke_aml_crs_evaluation_round_trip() -> TestResult {
    // Build AML for:
    //   Scope(\_T2) { Device(CS01) { Method(_CRS, 0) {
    //     Return(Buffer(13) { ... })
    //   }}}

    crate::__reset_for_test();

    let res_bytes: [u8; 13] = [
        0x22, 0x10, 0x00, // small IRQ descriptor, mask=0x0010
        0x47, 0x01, 0x00, 0x03, 0x00, 0x03, 0x01, 0x08, // IO Port descriptor
        0x79, 0x00, // EndTag
    ];

    let buffer: alloc::vec::Vec<u8> = {
        let mut v = alloc::vec::Vec::new();
        v.push(0x11); // BufferOp
        v.push(0x10); // PkgLen = 16
        v.push(0x0A);
        v.push(0x0D); // BytePrefix 13 (size TermArg)
        v.extend_from_slice(&res_bytes);
        v
    };

    let return_stmt: alloc::vec::Vec<u8> = {
        let mut v = alloc::vec::Vec::new();
        v.push(0xA4); // ReturnOp
        v.extend_from_slice(&buffer);
        v
    };

    let method: alloc::vec::Vec<u8> = {
        let mut v = alloc::vec::Vec::new();
        v.push(0x14); // MethodOp
        v.push(0x18); // PkgLen = 24
        v.extend_from_slice(b"_CRS"); // NameSeg
        v.push(0x00); // MethodFlags
        v.extend_from_slice(&return_stmt);
        v
    };

    let device: alloc::vec::Vec<u8> = {
        let mut v = alloc::vec::Vec::new();
        v.push(0x5B);
        v.push(0x82); // DeviceOp
        v.push(0x1E); // PkgLen = 30
        v.extend_from_slice(b"CS01"); // NameSeg
        v.extend_from_slice(&method);
        v
    };

    let blob: alloc::vec::Vec<u8> = {
        let mut v = alloc::vec::Vec::new();
        v.push(0x10); // ScopeOp
        v.push(0x26); // PkgLen = 38
        v.push(b'\\'); // root char
        v.extend_from_slice(b"_T2_"); // NameSeg (strips to _T2)
        v.extend_from_slice(&device);
        v
    };

    if crate::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("crs: parse failed");
    }

    match crate::prt_crs::evaluate_crs_for("\\_T2.CS01") {
        Ok(items) if items.len() == 3 => {
            match &items[0] {
                crate::resource::ResourceItem::Irq { .. } => {}
                _ => return TestResult::Fail("crs: items[0] not Irq"),
            }
            match &items[1] {
                crate::resource::ResourceItem::Io { .. } => {}
                _ => return TestResult::Fail("crs: items[1] not Io"),
            }
            match &items[2] {
                crate::resource::ResourceItem::EndTag => {}
                _ => return TestResult::Fail("crs: items[2] not EndTag"),
            }
            TestResult::Pass
        }
        Ok(items) => {
            let _ = items;
            TestResult::Fail("crs: expected 3 resource items")
        }
        Err(_) => TestResult::Fail("crs: evaluate_crs_for failed"),
    }
}
kernel_test_in!("aml", smoke_aml_crs_evaluation_round_trip);

fn smoke_aml_prt_method_not_found() -> TestResult {
    // Reset namespace so \\NOPE definitely doesn't exist.
    crate::__reset_for_test();

    match crate::prt_crs::evaluate_prt_for("\\NOPE") {
        Err(crate::prt_crs::BridgeError::MethodNotFound) => TestResult::Pass,
        Ok(_) => TestResult::Fail("prt_not_found: expected MethodNotFound, got Ok"),
        Err(_) => TestResult::Fail("prt_not_found: expected MethodNotFound, got different Err"),
    }
}
kernel_test_in!("aml", smoke_aml_prt_method_not_found);

fn smoke_aml_eisa_id_decode() -> TestResult {
    // ACPI 6.5 §5.6.7 EISA-ID encoding round-trip. PNP0A03 (PCI
    // host bridge) packs as 0x030AD041; PNP0A08 (PCIe host
    // bridge) as 0x080AD041. Verifies `device_hid` decodes
    // integer-encoded `_HID` values consumers see in practice.
    let cases: &[(u32, &str)] = &[
        (0x030A_D041, "PNP0A03"),
        (0x080A_D041, "PNP0A08"),
        (0x0103_D041, "PNP0301"),
    ];
    for (raw, expected) in cases {
        let got = crate::eisa_id_from_u32(*raw);
        if got != *expected {
            return TestResult::Fail("eisa-id decode mismatch");
        }
    }
    TestResult::Pass
}
kernel_test_in!("aml", smoke_aml_eisa_id_decode);

fn smoke_aml_irq_routing_register_and_query() -> TestResult {
    // Register two synthetic PRT entries against a fake bridge,
    // verify they round-trip through the global registry.
    use crate::resource::PrtEntry;
    crate::irq_routing::clear();
    let entries = [
        PrtEntry { address: 0x0001_FFFF, pin: 0, source: None, source_index: 11 },
        PrtEntry { address: 0x0002_FFFF, pin: 1, source: None, source_index: 10 },
    ];
    crate::irq_routing::register_bridge("\\_SB.PCITEST", &entries);
    if crate::irq_routing::len() != 2 {
        return TestResult::Fail("registry length != 2 after register_bridge");
    }
    let r = crate::irq_routing::route_for("\\_SB.PCITEST", 1, 0);
    let r = match r {
        Some(r) => r,
        None => return TestResult::Fail("route_for missed (slot 1, pin 0)"),
    };
    if r.entry.source_index != 11 {
        return TestResult::Fail("route_for returned wrong GSI");
    }
    if crate::irq_routing::route_for("\\_SB.PCITEST", 0, 0).is_some() {
        return TestResult::Fail("route_for matched a non-existent slot");
    }
    crate::irq_routing::clear();
    if crate::irq_routing::len() != 0 {
        return TestResult::Fail("clear didn't drain");
    }
    TestResult::Pass
}
kernel_test_in!("aml", smoke_aml_irq_routing_register_and_query);

fn smoke_aml_skip_predicate_term_arg_decodes_lequal_osi() -> TestResult {
    // Synthetic predicate: LEqual(_OSI("Linux"), Ones).
    // Wire bytes (ACPI 6.5 §20.2.5):
    //   0x93                 = LEqualOp
    //   0x5F 0x4F 0x53 0x49  = NameSeg "_OSI"
    //   0x0D "Linux" 0x00    = StringPrefix + 5 chars + NUL
    //   0xFF                 = OnesOp
    // Total: 1 + 4 + 7 + 1 = 13 bytes.
    let buf: &[u8] = &[
        0x93, // LEqual
        b'_', b'O', b'S', b'I',
        0x0D, b'L', b'i', b'n', b'u', b'x', 0x00,
        0xFF,
    ];
    let mut cur = 0usize;
    if crate::skip_predicate_term_arg(buf, &mut cur, buf.len()).is_err() {
        return TestResult::Fail("skip_predicate_term_arg returned Err on LEqual(_OSI, Ones)");
    }
    if cur != buf.len() {
        return TestResult::Fail("cursor didn't advance to end of predicate");
    }
    TestResult::Pass
}
kernel_test_in!("aml", smoke_aml_skip_predicate_term_arg_decodes_lequal_osi);

fn smoke_aml_namespace_walks_past_if_blocks() -> TestResult {
    // Sentinel for the If-skip behaviour added so the
    // namespace builder doesn't bail on the first
    // If/Else (0xA0/0xA1) opcode it sees. After the change
    // QEMU q35's DSDT yields ~358 nodes (vs ~289 before);
    // any kernel whose firmware uses conditionals will see
    // a similar bump. Test asserts a soft floor that catches
    // a regression to the bail-on-unknown-op behaviour.
    let (n_nodes, n_devs) = crate::boot_snapshot();
    if n_nodes < 50 {
        return TestResult::Skip("namespace not parsed at boot");
    }
    if n_devs == 0 {
        return TestResult::Fail("no devices found — namespace walk degraded");
    }
    TestResult::Pass
}
kernel_test_in!("aml", smoke_aml_namespace_walks_past_if_blocks);

fn smoke_aml_evaluate_s5_against_qemu_dsdt() -> TestResult {
    // After boot-time `parse_namespace`, `evaluate_s5()`
    // returns Some with the platform's SLP_TYPa/b values. The
    // namespace exposes `\_S5_` at the root scope on every
    // ACPI 2.0+ firmware; QEMU q35 ships a degenerate
    // `Package(0,0,0,0)` (which the production power-off
    // path rewrites to QEMU defaults — see frame/bare_main).
    //
    // SLP_TYP is a 3-bit field per ACPI 6.5 §16.1.6.
    let (typa, typb) = match crate::evaluate_s5() {
        Some(p) => p,
        None => return TestResult::Skip("\\_S5_ not in namespace"),
    };
    if typa > 7 || typb > 7 {
        return TestResult::Fail("SLP_TYP out of 3-bit range");
    }
    TestResult::Pass
}
kernel_test_in!("aml", smoke_aml_evaluate_s5_against_qemu_dsdt);

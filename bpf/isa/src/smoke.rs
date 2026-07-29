//! In-kernel smokes, registered through `narf-kernel-test`.
//!
//! The exhaustive coverage lives in `tests.rs` and runs on the host, which is
//! far faster and needs no QEMU. These smokes exist only to prove the crate
//! behaves identically when built for the kernel target — the `no_std` build,
//! the kernel's codegen flags, and the target endianness. Keep them cheap;
//! `cargo xtask test` runs thousands of these.

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::encode::encode;
use crate::insn::{decode, Decoded, Insn};
use crate::opcode::{AluOp, Reg, Source};

fn smoke_isa_round_trip_on_target() -> TestResult {
    let want = Decoded::Alu {
        wide: true,
        op: AluOp::Add,
        dst: match Reg::new(1) {
            Some(r) => r,
            None => return TestResult::Fail("r1 must be a valid register"),
        },
        src: Source::Imm(-1),
    };
    let e = encode(want);
    match decode(e.slots(), 0) {
        Ok((got, 1)) if got == want => TestResult::Pass,
        Ok(_) => TestResult::Fail("round-trip changed the instruction"),
        Err(_) => TestResult::Fail("failed to decode a freshly encoded instruction"),
    }
}

fn smoke_isa_little_endian_slot_layout() -> TestResult {
    // The kernel target must agree with the host on byte order, or every
    // program image would decode as garbage.
    let i = Insn {
        code: 0x18,
        regs: 0x21,
        off: 0x0304,
        imm: 0x0506_0708,
    };
    let b = i.to_bytes();
    if b != [0x18, 0x21, 0x04, 0x03, 0x08, 0x07, 0x06, 0x05] {
        return TestResult::Fail("instruction slot is not little-endian");
    }
    if Insn::from_bytes(b) != i {
        return TestResult::Fail("byte round-trip lost information");
    }
    TestResult::Pass
}

fn smoke_isa_rejects_helper_call() -> TestResult {
    // NARF has one call ABI; a helper call must never decode.
    let prog = [Insn {
        code: 0x85,
        regs: 0x00,
        off: 0,
        imm: 12,
    }];
    match decode(&prog, 0) {
        Err(crate::insn::DecodeError::HelperCall(12)) => TestResult::Pass,
        _ => TestResult::Fail("helper call should not decode"),
    }
}

kernel_test_in!("bpf", smoke_isa_round_trip_on_target);
kernel_test_in!("bpf", smoke_isa_little_endian_slot_layout);
kernel_test_in!("bpf", smoke_isa_rejects_helper_call);

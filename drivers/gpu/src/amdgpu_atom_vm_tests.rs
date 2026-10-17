//! Opcode-level tests against `atom.c` semantics for the paths ASIC_Init
//! needs: IIO programs, sub-dword destinations, SHL/SHR, MUL32/DIV32,
//! absent CALLTABLE targets, the Linux "log and continue" cases, and the
//! stepped machine (DELAY, stuck guard).
use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Default)]
struct TestHooks {
    regs: BTreeMap<u32, u32>,
    writes: Vec<(u32, u32)>,
    tables: Vec<(u8, ResolvedTable<'static>)>,
    absent: Vec<u8>,
    /// Advanced by `step` on every `now_ms`; `None` is clockless.
    clock: Option<u64>,
    step: u64,
}
impl<'a> Hooks<'a> for TestHooks {
    fn reg_read(&mut self, index: u32) -> u32 {
        *self.regs.get(&index).unwrap_or(&0)
    }
    fn reg_write(&mut self, index: u32, value: u32) {
        self.writes.push((index, value));
        self.regs.insert(index, value);
    }
    fn resolve(&mut self, id: u8) -> Option<ResolvedTable<'a>> {
        self.tables.iter().find(|(i, _)| *i == id).map(|(_, t)| *t)
    }
    fn table_absent(&mut self, id: u8) -> bool {
        self.absent.contains(&id)
    }
    fn now_ms(&mut self) -> Option<u64> {
        let now = self.clock?;
        self.clock = Some(now + self.step);
        Some(now)
    }
}
fn table(body: &'static [u8], ws: Option<usize>) -> ResolvedTable<'static> {
    ResolvedTable {
        body,
        ps_dwords: 0,
        start: 0,
        ws_dwords: ws,
    }
}

const DATA_DIR: usize = 0x100;
const IIO_TABLE: usize = 0x200;

/// A data directory whose `indirectioaccess` entry (23) holds two IIO
/// programs: a read for port 2 and a write for port 2 (`0x80 | 2`).
fn iio_image() -> Vec<u8> {
    let mut image = vec![0u8; 0x400];
    image[DATA_DIR..DATA_DIR + 2].copy_from_slice(&((4 + 2 * 34) as u16).to_le_bytes());
    image[DATA_DIR + 4 + 2 * 23..DATA_DIR + 6 + 2 * 23]
        .copy_from_slice(&(IIO_TABLE as u16).to_le_bytes());
    #[rustfmt::skip]
    let programs = [
        ATOM_IIO_START, 0x02,
        ATOM_IIO_NOP,
        ATOM_IIO_CLEAR, 32, 0,          // temp = 0
        ATOM_IIO_SET, 1, 31,            // bit 31
        ATOM_IIO_MOVE_ATTR, 4, 0, 24,   // [27:24] = io_attr[3:0]
        ATOM_IIO_MOVE_INDEX, 8, 0, 8,   // [15:8] = index[7:0]
        ATOM_IIO_WRITE, 0x10, 0x00,     // REG[0x10] = temp
        ATOM_IIO_READ, 0x11, 0x00,      // temp = REG[0x11]
        ATOM_IIO_END, 0, 0,
        ATOM_IIO_START, 0x82,
        ATOM_IIO_CLEAR, 32, 0,
        ATOM_IIO_MOVE_DATA, 16, 0, 0,   // [15:0] = data[15:0]
        ATOM_IIO_MOVE_INDEX, 16, 0, 16, // [31:16] = index[15:0]
        ATOM_IIO_WRITE, 0x12, 0x00,
        ATOM_IIO_END, 0, 0,
    ];
    image[IIO_TABLE + 4..IIO_TABLE + 4 + programs.len()].copy_from_slice(&programs);
    image
}

fn atom_vm_iio_programs_follow_atom_iio_execute() -> TestResult {
    let image = iio_image();
    let mut state = AtomState::with_hooks(4, 4, TestHooks::default());
    state.bios = &image;
    state.data_table = DATA_DIR;
    state.hooks.regs.insert(0x11, 0x1122_3344);
    #[rustfmt::skip]
    let code: &[u8] = &[
        3, 0x05, 0x47, 5, 0, 0, 0,          // MOVE WS_ATTRIBUTES <- 5
        55, 2, 0,                           // SET_ATI_PORT 2
        3, 0x00, 0, 0x42, 0x00,             // MOVE WS[0] <- REG[0x42] (IIO read)
        1, 0x05, 0x42, 0x00, 0xef, 0xbe, 0, 0, // MOVE REG[0x42] <- 0xbeef (IIO write)
        55, 3, 0,                           // SET_ATI_PORT 3 (no program)
        3, 0x00, 1, 0x01, 0x00,             // MOVE WS[1] <- REG[1]
        55, 0, 0,                           // back to MM
        1, 0x05, 0x13, 0x00, 1, 0, 0, 0,    // MOVE REG[0x13] <- 1
        91,
    ];
    let mut ps = [0u32; 1];
    if execute_bytes(&mut state, code, &mut ps, 0).is_err() {
        return TestResult::Fail("IIO table errored");
    }
    let iio = state.iio.as_ref().map(|t| (t[2], t[0x82]));
    if iio != Some((IIO_TABLE as u16 + 6, IIO_TABLE as u16 + 32)) {
        return TestResult::Fail("atom_index_iio offsets");
    }
    if state.scratch[0] != 0x1122_3344 {
        return TestResult::Fail("IIO read did not return the program's READ");
    }
    if state.hooks.writes != [(0x10, 0x8500_4200), (0x12, 0x0042_beef), (0x13, 1)] {
        return TestResult::Fail("IIO CLEAR/SET/MOVE_* composition");
    }
    if state.scratch[1] != 0
        || state.anomalies != 1
        || state.first_anomaly != Some(Anomaly::UndefinedIio(3))
    {
        return TestResult::Fail("undefined IIO port must read 0 and be counted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/atom-vm",
    atom_vm_iio_programs_follow_atom_iio_execute
);

fn atom_vm_sub_dword_destinations_keep_saved_bits() -> TestResult {
    let mut state = AtomState::with_hooks(4, 4, TestHooks::default());
    for (reg, value) in [
        (0x20, 0xaabb_ccdd),
        (0x21, 0x5555_6666),
        (0x22, 0xffff_ffff),
        (0x23, 0x0000_0f10),
        (0x24, 0x0000_f000),
        (0x25, 0x0000_00f0),
    ] {
        state.hooks.regs.insert(reg, value);
    }
    #[rustfmt::skip]
    let code: &[u8] = &[
        13, 0x65, 0x20, 0x00, 0x01,       // OR REG[0x20].[15:8] |= 1
        1, 0x8d, 0x21, 0x00, 0x34, 0x12,  // MOVE REG[0x21].[31:16] <- 0x1234
        84, 0x30, 0x22, 0x00,             // CLEAR REG[0x22].[23:16]
        109, 0x65, 0x23, 0x00, 4,         // SHL REG[0x23].[15:8] by 4
        115, 0x65, 0x24, 0x00, 4,         // SHR REG[0x24].[15:8] by 4
        19, 0x20, 0x25, 0x00, 4,          // SHIFT_LEFT REG[0x25].[7:0] by 4
        91,
    ];
    if execute_bytes(&mut state, code, &mut [], 0).is_err() {
        return TestResult::Fail("sub-dword table errored");
    }
    let r = |reg| state.hooks.regs.get(&reg).copied();
    if r(0x20) != Some(0xaabb_cddd) {
        return TestResult::Fail("OR byte8 lost the surrounding bytes");
    }
    if r(0x21) != Some(0x1234_6666) {
        return TestResult::Fail("MOVE word16 lost the low word");
    }
    if r(0x22) != Some(0xff00_ffff) {
        return TestResult::Fail("CLEAR byte16");
    }
    // atom_op_shl/shr shift the raw destination, then realign.
    if r(0x23) != Some(0x0000_f110) || r(0x24) != Some(0x0000_0f00) {
        return TestResult::Fail("SHL/SHR must shift the full saved value");
    }
    // atom_op_shift_left shifts the aligned byte, which then truncates.
    if r(0x25) != Some(0) {
        return TestResult::Fail("SHIFT_LEFT byte0");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/atom-vm",
    atom_vm_sub_dword_destinations_keep_saved_bits
);

fn atom_vm_mul32_div32_use_64_bit_divmul() -> TestResult {
    let mut state = AtomState::with_hooks(4, 4, TestHooks::default());
    #[rustfmt::skip]
    let code: &[u8] = &[
        3, 0x05, 0, 0, 0, 0, 0x80,  // WS[0] = 0x8000_0000
        124, 0x05, 0, 4, 0, 0, 0,   // MUL32 WS[0] * 4
        91,
    ];
    if execute_bytes(&mut state, code, &mut [], 0).is_err() || state.divmul != [0, 2] {
        return TestResult::Fail("MUL32 64-bit product");
    }
    #[rustfmt::skip]
    let code: &[u8] = &[
        3, 0x05, 1, 6, 0, 0, 0,     // WS[1] = 6
        126, 0x05, 1, 2, 0, 0, 0,   // DIV32 (divmul[1]:WS[1]) / 2
        91,
    ];
    if execute_bytes(&mut state, code, &mut [], 0).is_err() || state.divmul != [3, 1] {
        return TestResult::Fail("DIV32 64-bit quotient");
    }
    #[rustfmt::skip]
    let code: &[u8] = &[
        3, 0x05, 1, 7, 0, 0, 0,
        39, 0x05, 1, 2, 0, 0, 0,    // DIV WS[1] / 2
        33, 0x05, 1, 3, 0, 0, 0,    // MUL WS[1] * 3 (low dword only)
        91,
    ];
    if execute_bytes(&mut state, code, &mut [], 0).is_err() || state.divmul != [21, 1] {
        return TestResult::Fail("DIV keeps the remainder; MUL writes only the quotient");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/atom-vm",
    atom_vm_mul32_div32_use_64_bit_divmul
);

fn atom_vm_linux_log_and_continue_cases() -> TestResult {
    let mut state = AtomState::with_hooks(4, 4, TestHooks::default());
    state.hooks.regs.insert(0x10, 0x77);
    #[rustfmt::skip]
    let code: &[u8] = &[
        56, 0,                              // SET_PCI_PORT
        3, 0x00, 2, 0x10, 0x00,             // WS[2] <- REG[0x10]: 0
        1, 0x05, 0x30, 0x00, 1, 0, 0, 0,    // REG[0x30] <- 1: dropped
        57, 0,                              // SET_SYSIO_PORT
        3, 0x01, 3, 9,                      // WS[3] <- PS[9]: out of range
        2, 0x05, 9, 1, 0, 0, 0,             // PS[9] <- 1: dropped
        91,
    ];
    let mut ps = [0u32; 1];
    if execute_bytes(&mut state, code, &mut ps, 0).is_err() {
        return TestResult::Fail("Linux continues past PCI/SYSIO and PS range");
    }
    if state.scratch[2] != 0
        || state.scratch[3] != 0xcdcd_cdcd
        || !state.hooks.writes.is_empty()
        || state.anomalies != 4
        || state.first_anomaly != Some(Anomaly::PortIo(0x10))
    {
        return TestResult::Fail("PCI/SYSIO/PS anomalies");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/atom-vm",
    atom_vm_linux_log_and_continue_cases
);

fn atom_vm_calltable_skips_absent_entries() -> TestResult {
    static CALLER: [u8; 5] = [82, 5, 82, 6, 91];
    static CALLEE: [u8; 8] = [3, 0x05, 0, 9, 0, 0, 0, 91];
    let hooks = TestHooks {
        tables: vec![(1, table(&CALLER, Some(2))), (6, table(&CALLEE, Some(1)))],
        absent: vec![5],
        ..TestHooks::default()
    };
    let mut state = AtomState::with_hooks(4, 4, hooks);
    state.scratch[0] = 0x55;
    if execute_table(&mut state, 1, &mut [0; 4]).is_err() {
        return TestResult::Fail("absent CALLTABLE target must be a no-op");
    }
    // Each execution has its own WS and the caller's is restored.
    if state.scratch.len() != 4 || state.scratch[0] != 0x55 {
        return TestResult::Fail("caller WS not restored");
    }
    state.hooks.tables.retain(|(id, _)| *id != 6);
    if execute_table(&mut state, 1, &mut [0; 4]) != Err(AtomError::UnknownTable(6))
        || state.scratch[0] != 0x55
    {
        return TestResult::Fail("present but unresolvable target");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/atom-vm",
    atom_vm_calltable_skips_absent_entries
);

fn atom_vm_machine_steps_delays_and_bounds_loops() -> TestResult {
    let code: &[u8] = &[80, 3, 81, 7, 91];
    let mut state = AtomState::with_hooks(1, 1, TestHooks::default());
    let mut ps = [0u32; 1];
    let mut machine = Machine::from_bytes(code, &mut ps, 0);
    let steps: Vec<_> = (0..3).map(|_| machine.step(&mut state)).collect();
    if steps != [Ok(Step::Delay(3000)), Ok(Step::Delay(7)), Ok(Step::Done)] {
        return TestResult::Fail("DELAY must surface as Step::Delay");
    }
    if machine.last().map(|s| (s.opcode, s.offset)) != Some((91, 4)) {
        return TestResult::Fail("op site");
    }
    // atom_op_jump: one target taken for over 20 s aborts.
    static LOOP: [u8; 3] = [67, 6, 0];
    let hooks = TestHooks {
        clock: Some(0),
        step: 1000,
        tables: vec![(0, table(&LOOP, None))],
        ..TestHooks::default()
    };
    let mut state = AtomState::with_hooks(1, 1, hooks);
    let mut ps = [0u32; 1];
    let Ok(mut machine) = Machine::start(&mut state, 0, &mut ps) else {
        return TestResult::Fail("start");
    };
    let result = loop {
        match machine.step(&mut state) {
            Ok(Step::Continue) if machine.steps() < 100 => {}
            other => break other,
        }
    };
    if result != Err(AtomError::Stuck) || machine.steps() < 20 {
        return TestResult::Fail("20 s same-jump guard");
    }
    // Without a clock, the repeat bound.
    let mut state = AtomState::new(1, 1);
    if execute_bytes(&mut state, &LOOP, &mut [], 0) != Err(AtomError::Stuck) {
        return TestResult::Fail("clockless stuck guard");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/atom-vm",
    atom_vm_machine_steps_delays_and_bounds_loops
);

/// amdgpu_atom_execute_table_locked: an opcode 0 / `>= ATOM_OP_CNT` breaks
/// out of that table with success (the CALLTABLE caller continues);
/// atom_op_switch "Bad case" returns and resumes at the offending byte. A
/// jump outside the table ends it. All three are logged anomalies.
fn atom_vm_bad_opcode_case_and_jump_end_or_resume_like_linux() -> TestResult {
    static CALLER: [u8; 10] = [82, 6, 3, 0x05, 0, 7, 0, 0, 0, 91];
    static CALLEE: [u8; 9] = [127, 3, 0x05, 0, 9, 0, 0, 0, 91];
    let hooks = TestHooks {
        tables: vec![(1, table(&CALLER, Some(1))), (6, table(&CALLEE, Some(1)))],
        ..TestHooks::default()
    };
    let mut state = AtomState::with_hooks(4, 4, hooks);
    if execute_table(&mut state, 1, &mut [0; 4]).is_err()
        || state.anomalies != 1
        || state.first_anomaly != Some(Anomaly::BadOpcode(127))
        || state.scratch.len() != 4
    {
        return TestResult::Fail("bad opcode did not end only the callee");
    }
    // SWITCH (imm 1) whose first entry is neither CASE_MAGIC nor CASE_END:
    // the byte there (MOVE WS[0] <- 9) runs next.
    let code: &[u8] = &[66, 0x05, 1, 0, 0, 0, 3, 0x05, 0, 9, 0, 0, 0, 91];
    let mut state = AtomState::new(4, 4);
    if execute_bytes(&mut state, code, &mut [], 0).is_err()
        || state.scratch[0] != 9
        || state.first_anomaly != Some(Anomaly::BadCase)
    {
        return TestResult::Fail("bad case did not resume at the offending byte");
    }
    // JUMP past the table end: the table stops, nothing after it runs.
    let code: &[u8] = &[67, 0xff, 0x00, 3, 0x05, 0, 9, 0, 0, 0, 91];
    let mut state = AtomState::new(4, 4);
    if execute_bytes(&mut state, code, &mut [], 0).is_err()
        || state.scratch[0] != 0
        || state.first_anomaly != Some(Anomaly::JumpTarget)
    {
        return TestResult::Fail("out-of-table jump not ended as an anomaly");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/atom-vm",
    atom_vm_bad_opcode_case_and_jump_end_or_resume_like_linux
);

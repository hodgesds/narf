use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

const ROM: usize = 0x100;
const CMD_DIR: usize = 0x200;
const DATA_DIR: usize = 0x400;
const DATA: usize = 0x600;
const TABLE_A: usize = 0x800;
const TABLE_B: usize = 0x900;
const TABLE_C: usize = 0xa00;

#[derive(Default)]
struct Fake {
    regs: BTreeMap<u32, u32>,
    writes: Vec<(u32, u32)>,
    delays: Vec<u64>,
    limit: u32,
}
impl Bus for Fake {
    fn read(&mut self, dword: u32) -> Option<u32> {
        (dword < self.limit).then(|| *self.regs.get(&dword).unwrap_or(&0))
    }
    fn write(&mut self, dword: u32, value: u32) -> bool {
        if dword >= self.limit {
            return false;
        }
        self.writes.push((dword, value));
        self.regs.insert(dword, value);
        true
    }
    fn delay_us(&mut self, us: u64) {
        self.delays.push(us);
    }
}
fn bus() -> Rc<RefCell<Fake>> {
    Rc::new(RefCell::new(Fake {
        limit: 0x40000,
        ..Fake::default()
    }))
}

fn table(image: &mut [u8], at: usize, revision: u8, ws: u8, ps_bytes: u8, code: &[u8]) {
    let size = 6 + code.len();
    image[at..at + 2].copy_from_slice(&(size as u16).to_le_bytes());
    image[at + 2] = 1;
    image[at + 3] = revision;
    image[at + 4] = ws;
    image[at + 5] = ps_bytes;
    image[at + 6..at + size].copy_from_slice(code);
}
/// A VBIOS whose SetPixelClock (12, rev 7) selects vram_info's data block,
/// loads a dword from it, writes it and PS[0]/PS[1] to registers, delays,
/// calls EnableDispPowerGating (13) and checks its own WS survived. Table 76
/// (rev 6) reaches outside the register window.
fn image(set_pixel_revision: u8) -> Vec<u8> {
    let mut image = vec![0u8; 0x1000];
    image[..2].copy_from_slice(&[0x55, 0xaa]);
    image[0x48..0x4a].copy_from_slice(&(ROM as u16).to_le_bytes());
    image[ROM..ROM + 4].copy_from_slice(&[36, 0, 1, 1]);
    image[ROM + 4..ROM + 8].copy_from_slice(b"ATOM");
    image[ROM + 0x1e..ROM + 0x20].copy_from_slice(&(CMD_DIR as u16).to_le_bytes());
    image[ROM + 0x20..ROM + 0x22].copy_from_slice(&(DATA_DIR as u16).to_le_bytes());
    let entries = 81usize;
    image[CMD_DIR..CMD_DIR + 2].copy_from_slice(&((4 + 2 * entries) as u16).to_le_bytes());
    image[CMD_DIR + 2] = 2;
    image[CMD_DIR + 3] = 1;
    for (id, at) in [(12usize, TABLE_A), (13, TABLE_B), (76, TABLE_C)] {
        image[CMD_DIR + 4 + 2 * id..CMD_DIR + 6 + 2 * id]
            .copy_from_slice(&(at as u16).to_le_bytes());
    }
    image[DATA_DIR..DATA_DIR + 2].copy_from_slice(&((4 + 2 * 34) as u16).to_le_bytes());
    image[DATA_DIR + 2] = 2;
    image[DATA_DIR + 3] = 1;
    image[DATA_DIR + 4 + 2 * 28..DATA_DIR + 6 + 2 * 28]
        .copy_from_slice(&(DATA as u16).to_le_bytes());
    image[DATA + 4..DATA + 8].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    #[rustfmt::skip]
    let a = [
        102, 28,                    // SET_DATA_BLOCK vram_info
        3, 0x04, 0, 4, 0,           // MOVE WS[0] <- ID[4]
        1, 0x02, 0x00, 0x30, 0,     // MOVE REG[0x3000] <- WS[0]
        1, 0x01, 0x01, 0x30, 0,     // MOVE REG[0x3001] <- PS[0]
        1, 0x01, 0x02, 0x30, 1,     // MOVE REG[0x3002] <- PS[1]
        81, 7,                      // DELAY_MICROSEC 7
        82, 13,                     // CALL_TABLE 13
        1, 0x02, 0x03, 0x30, 0,     // MOVE REG[0x3003] <- WS[0]
        91,
    ];
    table(&mut image, TABLE_A, set_pixel_revision, 1, 16, &a);
    #[rustfmt::skip]
    let b = [
        3, 0x05, 0, 0xad, 0xde, 0, 0, // MOVE WS[0] <- 0xdead
        1, 0x02, 0x04, 0x30, 0,       // MOVE REG[0x3004] <- WS[0]
        80, 2,                        // DELAY_MILLISEC 2
        91,
    ];
    table(&mut image, TABLE_B, 1, 1, 0, &b);
    #[rustfmt::skip]
    let c = [
        1, 0x01, 0xff, 0xff, 0,     // MOVE REG[0xffff] <- PS[0]
        91,
    ];
    table(&mut image, TABLE_C, 6, 0, 32, &c);
    image
}

fn navi22_bios_parameter_blocks_match_command_table2() -> TestResult {
    // set_pixel_clock_v7: 148.5 MHz on OTG 2 through combo PHY PLL0 for the
    // HDMI connector on transmitter 3 (UNIPHY1).
    let clock = PixelClock {
        otg: 2,
        pll: 0,
        transmitter: 3,
        pixel_100hz: 1_485_000,
        deep_color: 0,
    };
    let p = clock.params().unwrap();
    if p[..4] != 1_485_000u32.to_le_bytes()
        || p[4..10] != [20, 0x20, 3, 0, 2, 0]
        || p[10..] != [0; 6]
    {
        return TestResult::Fail("set_pixel_clock_parameter_v1_7");
    }
    // 10 bpc HDMI at 25.175 MHz: actual_pix_clk_100hz = 251750 * 5 >> 2 =
    // 314687, sent verbatim (a kHz path would round to 314680), ratio 5:4.
    let deep = PixelClock {
        pixel_100hz: 314_687,
        deep_color: 1,
        ..clock
    };
    let p = deep.params().unwrap();
    if p[..4] != 314_687u32.to_le_bytes() || p[9] != 1 {
        return TestResult::Fail("deep-colour pixclk_100hz / deep_color_ratio");
    }
    if (PixelClock {
        deep_color: 4,
        ..clock
    })
    .params()
    .is_ok()
    {
        return TestResult::Fail("undefined deep colour ratio accepted");
    }
    // encoder_control_digx_v1_5 STREAM_SETUP: DIG 1, HDMI, four lanes.
    let e = hdmi_stream_setup_params(1, 148_500).unwrap();
    if e != [1, 0x0f, 3, 4, 0x02, 0x3a, 0, 0, 0, 0, 0, 0] {
        return TestResult::Fail("dig_encoder_stream_setup_parameters_v1_5");
    }
    // transmitter_control_v1_6 ENABLE as dcn10_link_encoder_enable_tmds_output.
    let t = Transmitter {
        action: TransmitterAction::Enable,
        transmitter: 3,
        mode: TransmitterMode::Hdmi,
        lanes: 4,
        hpd: Some(3),
        connector: 0,
        symbol_khz: 148_500,
    };
    let p = t.params(6, 0).unwrap();
    if p[..12] != [3, 1, 3, 4, 0x02, 0x3a, 0, 0, 4, 0, 0, 0] || p[12..] != [0; 48] {
        return TestResult::Fail("dig_transmitter_control_parameters_v1_6");
    }
    // DP lane settings as dcn10_link_encoder_dp_set_lane_settings: HBR2
    // (symclk 54000 x 10 kHz), two lanes, DP_LANE_SET 0x09 in mode_laneset,
    // the connector object id (CONNECTOR_ID_DISPLAY_PORT 19), HPO 0 on v1.7.
    let lane = Transmitter {
        action: TransmitterAction::SetupVsemph,
        mode: TransmitterMode::DisplayPort,
        lanes: 2,
        connector: 19,
        symbol_khz: 20 * 27_000,
        ..t
    };
    let p = lane.params(7, 0x09).unwrap();
    if p[..12] != [3, 11, 0x09, 2, 0xf0, 0xd2, 0, 0, 4, 0, 19, 0] {
        return TestResult::Fail("dmub_dig_transmitter_control_data_v1_7 lane set");
    }
    if (Transmitter { lanes: 3, ..t }).params(6, 0).is_ok() {
        return TestResult::Fail("three lanes admitted");
    }
    // enable_disp_power_gating_v2_1 for dcn10_bios_golden_init.
    if pipe_power_gating_params(0, PipeAction::Init).unwrap()[..2] != [0, 7]
        || pipe_power_gating_params(5, PipeAction::Disable).unwrap()[..2] != [5, 0]
        || pipe_power_gating_params(6, PipeAction::Disable).is_ok()
    {
        return TestResult::Fail("enable_disp_power_gating_parameters_v2_1");
    }
    if (PixelClock { otg: 6, ..clock }).params().is_ok() || hdmi_stream_setup_params(0, 0).is_ok() {
        return TestResult::Fail("bounds");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-bios",
    navi22_bios_parameter_blocks_match_command_table2
);

fn navi22_bios_interpreter_follows_atom_c_data_blocks_ws_and_delays() -> TestResult {
    let image = image(7);
    let Ok(tables) = Tables::new(&image) else {
        return TestResult::Fail("synthetic VBIOS");
    };
    let bus = bus();
    let clock = PixelClock {
        otg: 0,
        pll: 1,
        transmitter: 0,
        pixel_100hz: 251_750,
        deep_color: 0,
    };
    if let Err(error) = tables.set_pixel_clock(bus.clone(), &clock) {
        let _ = error;
        return TestResult::Fail("SetPixelClock execution");
    }
    let fake = bus.borrow();
    // ID reads the image at data_block (vram_info) + 4; PS carries the block;
    // the callee's WS is its own, so the caller's WS[0] still holds the ID.
    if fake.regs.get(&0x3000) != Some(&0x1234_5678)
        || fake.regs.get(&0x3001) != Some(&251_750)
        || fake.regs.get(&0x3002) != Some(&u32::from_le_bytes([21, 0x1e, 3, 0]))
        || fake.regs.get(&0x3004) != Some(&0xdead)
        || fake.regs.get(&0x3003) != Some(&0x1234_5678)
        || fake.delays != [7, 2000]
    {
        return TestResult::Fail("atom.c semantics");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-bios",
    navi22_bios_interpreter_follows_atom_c_data_blocks_ws_and_delays
);

fn navi22_bios_refuses_revisions_and_out_of_window_access() -> TestResult {
    let image = image(6);
    let tables = Tables::new(&image).unwrap();
    let clock = PixelClock {
        otg: 0,
        pll: 0,
        transmitter: 0,
        pixel_100hz: 251_750,
        deep_color: 0,
    };
    if tables.set_pixel_clock(bus(), &clock)
        != Err(Error::Revision {
            table: 12,
            revision: 6,
        })
    {
        return TestResult::Fail("SetPixelClock v1.6 accepted");
    }
    let bus = bus();
    bus.borrow_mut().limit = 0x8000;
    let control = Transmitter {
        action: TransmitterAction::Disable,
        transmitter: 0,
        mode: TransmitterMode::Hdmi,
        lanes: 0,
        hpd: None,
        connector: 12,
        symbol_khz: 0,
    };
    if tables.transmitter(bus.clone(), &control) != Err(Error::Bus)
        || !bus.borrow().writes.is_empty()
    {
        return TestResult::Fail("out-of-window register write");
    }
    if tables.hdmi_stream_setup(bus, 0, 148_500) != Err(Error::Missing(4)) {
        return TestResult::Fail("absent DIGxEncoderControl");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-bios",
    navi22_bios_refuses_revisions_and_out_of_window_access
);

/// Records the `DMUB_CMD__VBIOS` commands a table call sends.
struct Dmcub(narf_lib::sync::IrqSafeSpinLock<Vec<(VbiosCommand, Vec<u8>)>>);
impl VbiosDmub for Dmcub {
    fn execute_vbios(
        &self,
        command: VbiosCommand,
        payload: &[u8],
    ) -> Result<(), crate::amdgpu_dmub_navi22::Error> {
        if payload.len() != command.payload_bytes() {
            return Err(crate::amdgpu_dmub_navi22::Error::Invalid);
        }
        self.0.lock().push((command, payload.to_vec()));
        Ok(())
    }
}

/// command_table2.c on DCN3.0 (`dmub_command_table`): every display table
/// becomes a DMUB_CMD__VBIOS command carrying the same parameter struct, the
/// ATOM interpreter never runs (no register traffic), and table revisions
/// the interpreter would refuse still go to DMCUB (the `*_fallback` paths).
fn navi22_bios_tables_go_to_dmub_when_running() -> TestResult {
    // Rev 6 SetPixelClock, no DIGxEncoderControl, an out-of-window table 76:
    // all refused by the ATOM path, all fine for DMCUB.
    let image = image(6);
    let dmcub = Dmcub(narf_lib::sync::IrqSafeSpinLock::new(Vec::new()));
    let tables = Tables::new(&image).unwrap().with_dmub(Some(&dmcub));
    let bus = bus();
    let clock = PixelClock {
        otg: 2,
        pll: 0,
        transmitter: 3,
        pixel_100hz: 1_485_000,
        deep_color: 0,
    };
    let t = Transmitter {
        action: TransmitterAction::Enable,
        transmitter: 3,
        mode: TransmitterMode::Hdmi,
        lanes: 4,
        hpd: Some(3),
        connector: 0,
        symbol_khz: 148_500,
    };
    if !tables.uses_dmub()
        || tables
            .pipe_power_gating(bus.clone(), 1, PipeAction::Disable)
            .is_err()
        || tables.set_pixel_clock(bus.clone(), &clock).is_err()
        || tables.hdmi_stream_setup(bus.clone(), 1, 148_500).is_err()
        || tables.transmitter(bus.clone(), &t).is_err()
    {
        return TestResult::Fail("DMUB VBIOS command refused");
    }
    if !bus.borrow().writes.is_empty() || !bus.borrow().delays.is_empty() {
        return TestResult::Fail("ATOM interpreter ran with DMUB present");
    }
    let sent = dmcub.0.lock();
    let expect: [(VbiosCommand, Vec<u8>); 4] = [
        (VbiosCommand::EnableDispPowerGating, vec![1, 0, 0, 0]),
        (
            VbiosCommand::SetPixelClock,
            clock.params().unwrap().to_vec(),
        ),
        (
            VbiosCommand::DigxEncoderControl,
            hdmi_stream_setup_params(1, 148_500).unwrap().to_vec(),
        ),
        // Table 76 is revision 6 here: the v1.6 struct in the 60-byte union.
        (
            VbiosCommand::Dig1TransmitterControl,
            t.params(6, 0).unwrap().to_vec(),
        ),
    ];
    if *sent != expect {
        return TestResult::Fail("DMUB VBIOS payloads differ from command_table2.c");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-bios",
    navi22_bios_tables_go_to_dmub_when_running
);

/// dmub_cmd.h: header type DMUB_CMD__VBIOS (128), sub_type 0..3,
/// payload_bytes = sizeof(cmd) - sizeof(header) under pack(1).
fn navi22_bios_dmub_vbios_command_layout_matches_dmub_cmd_h() -> TestResult {
    use crate::amdgpu_dmub_navi22::vbios_request;
    for (command, sub, size) in [
        (VbiosCommand::DigxEncoderControl, 0, 12),
        (VbiosCommand::Dig1TransmitterControl, 1, 60),
        (VbiosCommand::SetPixelClock, 2, 16),
        (VbiosCommand::EnableDispPowerGating, 3, 4),
    ] {
        let payload: Vec<u8> = (0..size as u8).map(|i| i + 1).collect();
        let Ok(r) = vbios_request(command, &payload) else {
            return TestResult::Fail("VBIOS request refused");
        };
        if r[..4] != [128, sub, 0, size as u8]
            || r[4..4 + size] != payload[..]
            || r[4 + size..].iter().any(|&b| b != 0)
        {
            return TestResult::Fail("DMUB_CMD__VBIOS header or payload");
        }
        if vbios_request(command, &payload[..size - 1]).is_ok() {
            return TestResult::Fail("short VBIOS payload accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-bios",
    navi22_bios_dmub_vbios_command_layout_matches_dmub_cmd_h
);

/// amdgpu_atomfirmware_allocate_fb_scratch sizes the FB scratch (20 KiB
/// default, not 16 KiB), and a clocked bus arms atom_op_jump's 20 s guard.
fn navi22_bios_atom_fallback_uses_fb_scratch_size_and_clock() -> TestResult {
    let base = image(7);
    let tables = Tables::new(&base).unwrap();
    if tables.fb_words != 20 * 1024 / 4 {
        return TestResult::Fail("ATOM FB scratch is not allocate_fb_scratch's size");
    }
    struct Clocked {
        now: u64,
        calls: u32,
    }
    impl Bus for Clocked {
        fn read(&mut self, _: u32) -> Option<u32> {
            Some(0)
        }
        fn write(&mut self, _: u32, _: u32) -> bool {
            true
        }
        fn delay_us(&mut self, _: u64) {}
        fn now_ms(&mut self) -> Option<u64> {
            self.calls += 1;
            self.now += 1000;
            Some(self.now)
        }
    }
    // SetPixelClock replaced by `JUMP_ALWAYS 6` (a self-loop at its start).
    let mut looped = image(7);
    table(&mut looped, TABLE_A, 7, 0, 16, &[67, 6, 0, 91]);
    let tables = Tables::new(&looped).unwrap();
    let bus = Rc::new(RefCell::new(Clocked { now: 0, calls: 0 }));
    let clock = PixelClock {
        otg: 0,
        pll: 0,
        transmitter: 0,
        pixel_100hz: 251_750,
        deep_color: 0,
    };
    if tables.set_pixel_clock(bus.clone(), &clock) != Err(Error::Atom(AtomError::Stuck))
        || !(20..1000).contains(&bus.borrow().calls)
    {
        return TestResult::Fail("20 s ATOM guard not driven by the clock");
    }
    // Two jumps that alternate targets reset the per-loop guard on every
    // jump, so only the whole-table TABLE_MS cap ends them.
    let mut pingpong = image(7);
    table(&mut pingpong, TABLE_A, 7, 0, 16, &[67, 9, 0, 67, 6, 0, 91]);
    let tables = Tables::new(&pingpong).unwrap();
    let bus = Rc::new(RefCell::new(Clocked { now: 0, calls: 0 }));
    if tables.set_pixel_clock(bus.clone(), &clock) != Err(Error::Timeout)
        || bus.borrow().now > TABLE_MS + 10_000
    {
        return TestResult::Fail("interpreted table not bounded by TABLE_MS");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-bios",
    navi22_bios_atom_fallback_uses_fb_scratch_size_and_clock
);

/// The DMUB table route serialises its `&self` callers without masking
/// interrupts: a VBIOS command can wait 100 ms for the DMCUB, and Linux
/// waits under a mutex (`dc_lock`) with IRQs on. A second caller is told
/// `Busy` instead of spinning.
fn navi22_dmub_route_keeps_interrupts_enabled() -> TestResult {
    if !narf_arch::interrupts_enabled() {
        return TestResult::Skip("test context runs with interrupts masked");
    }
    let lock = MailboxLock::new(0u32);
    let during = lock.with(|v| {
        *v += 1;
        (narf_arch::interrupts_enabled(), lock.with(|_| ()).is_none())
    });
    if during != Some((true, true)) {
        return TestResult::Fail("DMUB route masked interrupts or allowed a nested caller");
    }
    if lock.with(|v| *v) != Some(1) {
        return TestResult::Fail("DMUB route lock not released");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-bios",
    navi22_dmub_route_keeps_interrupts_enabled
);

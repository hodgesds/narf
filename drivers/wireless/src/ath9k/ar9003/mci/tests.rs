//! Fixture tests for the MCI engine (`ar9003_mci.c` port).
//!
//! The fixture is a register-map mock: writes are logged, the two MCI
//! interrupt registers have write-1-to-clear semantics, and a write to
//! `AR_MCI_COMMAND0` models the hardware setting `SW_MSG_DONE` so
//! `send_message(wait_done=true)` completes. BT is simulated by
//! writing GPM slots into `mci.gpm_buf` and raising the GPM bit.

use super::super::btcoex;
use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use narf_io::alloc_coherent_masked;
use narf_kernel_test::{kernel_test_in, TestResult};

/// Register-map mock with an op log and W1C MCI interrupt registers.
struct MciFixture {
    regs: BTreeMap<u64, u32>,
    ops: Vec<(u64, u32)>,
    delays_us: u64,
}

impl MciFixture {
    fn new() -> Self {
        Self {
            regs: BTreeMap::new(),
            ops: Vec::new(),
            delays_us: 0,
        }
    }

    fn reg(&self, addr: u64) -> u32 {
        self.regs.get(&addr).copied().unwrap_or(0)
    }

    fn last_write(&self, addr: u64) -> Option<u32> {
        self.ops
            .iter()
            .rev()
            .find(|(a, _)| *a == addr)
            .map(|(_, v)| *v)
    }

    fn writes(&self, addr: u64) -> Vec<u32> {
        self.ops
            .iter()
            .filter(|(a, _)| *a == addr)
            .map(|(_, v)| *v)
            .collect()
    }
}

impl RegisterIo for MciFixture {
    fn read32(&mut self, offset: u64) -> u32 {
        self.reg(offset)
    }

    fn write32(&mut self, offset: u64, value: u32) {
        self.ops.push((offset, value));
        match offset {
            AR_MCI_INTERRUPT_RAW | AR_MCI_INTERRUPT_RX_MSG_RAW => {
                let cur = self.reg(offset);
                self.regs.insert(offset, cur & !value);
            }
            AR_MCI_COMMAND0 => {
                self.regs.insert(offset, value);
                // Hardware accepts the message and raises SW_MSG_DONE.
                let raw = self.reg(AR_MCI_INTERRUPT_RAW);
                self.regs
                    .insert(AR_MCI_INTERRUPT_RAW, raw | AR_MCI_INTERRUPT_SW_MSG_DONE);
            }
            _ => {
                self.regs.insert(offset, value);
            }
        }
    }

    fn delay_us(&mut self, us: u64) {
        self.delays_us += us;
    }
}

/// A live MCI link: `chip`, MCI mode on, BT awake, ring empty.
fn live_chip(chip: Chip) -> (MciFixture, btcoex::Btcoex) {
    let mut io = MciFixture::new();
    io.regs.insert(AR_BTCOEX_CTRL, AR_BTCOEX_CTRL_MCI_MODE_EN);
    let mut btcoex = btcoex::Btcoex::new(chip);
    btcoex::init_mci(&mut btcoex);
    btcoex.mci.ready = true;
    btcoex.mci.bt_state = BtState::Awake;
    btcoex.mci.gpm_len = MCI_GPM_MAX_ENTRY as u32;
    (io, btcoex)
}

/// A live MCI link: AR9462, MCI mode on, BT awake, ring empty.
fn live() -> (MciFixture, btcoex::Btcoex) {
    live_chip(Chip::Ar9462)
}

fn command_header(cmd: u32) -> u8 {
    ((cmd & AR_MCI_COMMAND0_HEADER) >> AR_MCI_COMMAND0_HEADER_S) as u8
}

fn command_len(cmd: u32) -> u8 {
    ((cmd & AR_MCI_COMMAND0_LEN) >> AR_MCI_COMMAND0_LEN_S) as u8
}

/// Write a GPM slot into the ring buffer.
fn put_gpm(mci: &mut Mci, slot: usize, subtype: u8, opcode: u8, extra: &[(usize, u8)]) {
    let off = slot * 16;
    mci.gpm_buf[off + MCI_GPM_COEX_B_GPM_TYPE] = subtype;
    mci.gpm_buf[off + MCI_GPM_COEX_B_GPM_OPCODE] = opcode;
    for (i, b) in extra {
        mci.gpm_buf[off + i] = *b;
    }
}

/// Raise a GPM in the fixture: slot `count` written, GPM bit set.
fn raise_gpm(io: &mut MciFixture, count: u32) {
    io.regs
        .insert(AR_MCI_GPM_1, count << AR_MCI_GPM_WRITE_PTR_S);
    io.regs
        .insert(AR_MCI_INTERRUPT_RX_MSG_RAW, AR_MCI_INTERRUPT_RX_MSG_GPM);
}

/// Stage a BT profile-info GPM in `slot` (Linux byte layout:
/// type/linkid/state/role/rate/votype at bytes 6..12, `T` LE u16 at
/// bytes 12..13, `W`/`A` at bytes 14/15). One parameter per wire
/// field, mirroring the 10-byte image.
#[allow(clippy::too_many_arguments)]
fn put_profile(
    mci: &mut Mci,
    slot: usize,
    profile: u8,
    handle: u8,
    start: u8,
    master: u8,
    edr: u8,
    voice_type: u8,
    t: u16,
    w: u8,
    a: u8,
) {
    put_gpm(
        mci,
        slot,
        GpmSubtype::CoexAgent as u8,
        GpmCoexOpcode::BtProfileInfo as u8,
        &[
            (MCI_GPM_COEX_B_PROFILE_TYPE, profile),
            (MCI_GPM_COEX_B_PROFILE_LINKID, handle),
            (MCI_GPM_COEX_B_PROFILE_STATE, start),
            (MCI_GPM_COEX_B_PROFILE_ROLE, master),
            (MCI_GPM_COEX_B_PROFILE_RATE, edr),
            (MCI_GPM_COEX_B_PROFILE_VOTYPE, voice_type),
            (MCI_GPM_COEX_H_PROFILE_T, (t & 0xff) as u8),
            (MCI_GPM_COEX_H_PROFILE_T + 1, (t >> 8) as u8),
            (MCI_GPM_COEX_B_PROFILE_W, w),
            (MCI_GPM_COEX_B_PROFILE_A, a),
        ],
    );
}

/// Stage a BT status-update GPM in `slot`.
fn put_status(mci: &mut Mci, slot: usize, is_link: u8, handle: u8, is_critical: u8) {
    put_gpm(
        mci,
        slot,
        GpmSubtype::CoexAgent as u8,
        GpmCoexOpcode::BtStatusUpdate as u8,
        &[
            (MCI_GPM_COEX_B_STATUS_TYPE, is_link),
            (MCI_GPM_COEX_B_STATUS_LINKID, handle),
            (MCI_GPM_COEX_B_STATUS_STATE, is_critical),
        ],
    );
}

/// Raise `count` staged GPM slots and run them through `get_isr` +
/// `handle_interrupt`; `None` when no interrupt latched or the
/// interrupt errored.
fn pump_gpm(
    io: &mut MciFixture,
    btcoex: &mut btcoex::Btcoex,
    count: u32,
) -> Option<InterruptOutcome> {
    raise_gpm(io, count);
    if !get_isr(io, &mut btcoex.mci) {
        return None;
    }
    handle_interrupt(io, &mut btcoex.mci).ok()
}

fn mci_message_exchange() -> TestResult {
    let (mut io, mut btcoex) = live();
    send_coex_version_query(&mut io, &mut btcoex.mci, true);
    let Some(cmd) = io.last_write(AR_MCI_COMMAND0) else {
        return TestResult::Fail("version query wrote no COMMAND0");
    };
    if command_header(cmd) != Msg::Gpm as u8 || command_len(cmd) != 16 {
        return TestResult::Fail("version query COMMAND0 is not a 16-byte GPM");
    }
    // Payload word 1 carries the type/opcode bytes (4/5): type
    // COEX_AGENT (0x0c) in byte 4, opcode VERSION_QUERY (0x00) in
    // byte 5, so word 1 is 0x0000_000c.
    if io.last_write(AR_MCI_TX_PAYLOAD0 + 4) != Some(0x0000_000c) {
        return TestResult::Fail("version query payload is not COEX_AGENT/VERSION_QUERY");
    }
    // BT answers with a version-response GPM in slot 0.
    put_gpm(
        &mut btcoex.mci,
        0,
        GpmSubtype::CoexAgent as u8,
        GpmCoexOpcode::VersionResponse as u8,
        &[
            (MCI_GPM_COEX_B_MAJOR_VERSION, 3),
            (MCI_GPM_COEX_B_MINOR_VERSION, 1),
        ],
    );
    raise_gpm(&mut io, 1);
    if !get_isr(&mut io, &mut btcoex.mci) {
        return TestResult::Fail("get_isr refused a live interrupt");
    }
    let Ok(outcome) = handle_interrupt(&mut io, &mut btcoex.mci) else {
        return TestResult::Fail("handle_interrupt errored on a version response");
    };
    if outcome.gpm_seen != 1 {
        return TestResult::Fail("handle_interrupt did not see the GPM");
    }
    if btcoex.mci.bt_ver_major != 3 || btcoex.mci.bt_ver_minor != 1 {
        return TestResult::Fail("BT version was not learned from the GPM");
    }
    if !btcoex.mci.bt_version_known {
        return TestResult::Fail("bt_version_known was not set");
    }
    // `set_bt_version` records a controller version directly.
    set_bt_version(&mut btcoex.mci, 4, 2);
    if btcoex.mci.bt_ver_major != 4 || btcoex.mci.bt_ver_minor != 2 || !btcoex.mci.bt_version_known
    {
        return TestResult::Fail("set_bt_version did not record 4.2");
    }
    // The slot was recycled with the reserved pattern.
    if btcoex.mci.gpm_buf[4..8] != [0xfe; 4] {
        return TestResult::Fail("consumed GPM slot was not recycled");
    }
    TestResult::Pass
}

fn mci_send_gating() -> TestResult {
    // MCI mode off: the send fails and a channels GPM is queued.
    let (mut io, mut btcoex) = live();
    io.regs.insert(AR_BTCOEX_CTRL, 0);
    let mut payload = [0u32; 4];
    gpm_set_type_opcode(
        &mut payload,
        GpmSubtype::CoexAgent as u8,
        GpmCoexOpcode::WlanChannels as u8,
    );
    if send_message(
        &mut io,
        &mut btcoex.mci,
        SendMessageParams {
            header: Msg::Gpm,
            flag: 0,
            payload: &payload,
            len: 16,
            wait_done: true,
            check_bt: true,
        },
    ) {
        return TestResult::Fail("send_message succeeded with MCI mode off");
    }
    if !btcoex.mci.wlan_channels_update {
        return TestResult::Fail("unsent channels GPM was not queued");
    }
    if io.last_write(AR_MCI_COMMAND0).is_some() {
        return TestResult::Fail("gated send still wrote COMMAND0");
    }
    // BT asleep with check_bt: the send fails.
    let (mut io, mut btcoex) = live();
    btcoex.mci.bt_state = BtState::Sleep;
    if send_message(
        &mut io,
        &mut btcoex.mci,
        SendMessageParams {
            header: Msg::Gpm,
            flag: 0,
            payload: &payload,
            len: 16,
            wait_done: true,
            check_bt: true,
        },
    ) {
        return TestResult::Fail("send_message succeeded while BT sleeps");
    }
    // BT asleep without check_bt: the send goes out anyway.
    if !send_message(
        &mut io,
        &mut btcoex.mci,
        SendMessageParams {
            header: Msg::Gpm,
            flag: 0,
            payload: &payload,
            len: 16,
            wait_done: true,
            check_bt: false,
        },
    ) {
        return TestResult::Fail("unchecked send failed while BT sleeps");
    }
    if io.last_write(AR_MCI_COMMAND0).is_none() {
        return TestResult::Fail("unchecked send wrote no COMMAND0");
    }
    TestResult::Pass
}

fn mci_gpio_observation() -> TestResult {
    // MCI observation routes the four MCI signals to GPIO 0..3.
    let (mut io, mut btcoex) = live();
    btcoex.mci.config = ATH_MCI_CONFIG_MCI_OBS_MCI;
    if observation_set_up(&mut io, &btcoex.mci).is_err() {
        return TestResult::Fail("observation_set_up errored on OBS_MCI");
    }
    // MUX1: gpio3=0x16@15, gpio2=0x17@10, gpio1=0x18@5, gpio0=0x19@0.
    if io.last_write(AR_GPIO_OUTPUT_MUX1) != Some(0x000b_5f19) {
        return TestResult::Fail("OBS_MCI did not program MUX1 as expected");
    }
    if io.last_write(AR_OBS) != Some(0x4b) {
        return TestResult::Fail("OBS_MCI did not select the observation bus");
    }
    // TX/RX observation routes the in/out signals plus GPIO 5.
    let (mut io, mut btcoex) = live();
    btcoex.mci.config = ATH_MCI_CONFIG_MCI_OBS_TXRX;
    if observation_set_up(&mut io, &btcoex.mci).is_err() {
        return TestResult::Fail("observation_set_up errored on OBS_TXRX");
    }
    // MUX1: gpio3=0x14@15, gpio2=0x13@10, gpio1=9@5, gpio0=8@0.
    if io.last_write(AR_GPIO_OUTPUT_MUX1) != Some(0x000a_4d28) {
        return TestResult::Fail("OBS_TXRX did not program MUX1 as expected");
    }
    // No observation bit: nothing is written.
    let (mut io, mut btcoex) = live();
    btcoex.mci.config = 0;
    if observation_set_up(&mut io, &btcoex.mci).is_err() {
        return TestResult::Fail("observation_set_up errored with no OBS bit");
    }
    if !io.ops.is_empty() {
        return TestResult::Fail("observation_set_up wrote with no OBS bit");
    }
    TestResult::Pass
}

fn mci_gpm_walk() -> TestResult {
    // Empty ring: no GPM.
    let (mut io, mut btcoex) = live();
    let (offset, more) = get_next_gpm_offset(&mut io, &mut btcoex.mci);
    if offset != MCI_GPM_INVALID || more != MCI_GPM_NOMORE {
        return TestResult::Fail("empty ring returned a GPM offset");
    }
    // Slot 0 reserved, slot 1 valid: the walk skips slot 0.
    let (mut io, mut btcoex) = live();
    btcoex.mci.gpm_buf[0..16].fill(MCI_GPM_RSVD_PATTERN);
    put_gpm(
        &mut btcoex.mci,
        1,
        GpmSubtype::CoexAgent as u8,
        GpmCoexOpcode::StatusQuery as u8,
        &[],
    );
    io.regs.insert(AR_MCI_GPM_1, 2 << AR_MCI_GPM_WRITE_PTR_S);
    let (offset, more) = get_next_gpm_offset(&mut io, &mut btcoex.mci);
    if offset != 16 || more != MCI_GPM_NOMORE {
        return TestResult::Fail("walk did not skip the reserved slot");
    }
    // Wraparound: read index at the last slot, valid GPM at slot 0.
    let (mut io, mut btcoex) = live();
    btcoex.mci.gpm_buf[15 * 16..16 * 16].fill(MCI_GPM_RSVD_PATTERN);
    put_gpm(
        &mut btcoex.mci,
        0,
        GpmSubtype::CoexAgent as u8,
        GpmCoexOpcode::StatusQuery as u8,
        &[],
    );
    btcoex.mci.gpm_idx = 15;
    io.regs.insert(AR_MCI_GPM_1, 1 << AR_MCI_GPM_WRITE_PTR_S);
    let (offset, more) = get_next_gpm_offset(&mut io, &mut btcoex.mci);
    if offset != 0 || more != MCI_GPM_NOMORE {
        return TestResult::Fail("walk did not wrap around the ring");
    }
    // Offset mismatch marks the BT info stale.
    let (mut io, mut btcoex) = live();
    io.regs.insert(AR_MCI_GPM_1, 3 << AR_MCI_GPM_WRITE_PTR_S);
    check_gpm_offset(&mut io, &mut btcoex.mci);
    if !btcoex.mci.query_bt || !btcoex.mci.need_flush_btinfo {
        return TestResult::Fail("offset mismatch did not flag stale BT info");
    }
    if btcoex.mci.gpm_idx != 0 {
        return TestResult::Fail("offset mismatch did not restart the walk");
    }
    TestResult::Pass
}

fn mci_cal_handshake() -> TestResult {
    // Calibration request: WLAN_CAL_REQ goes out, seq advances, and no
    // grant means the previous calibration must not be reused.
    let (mut io, mut btcoex) = live();
    let mut reusable = true;
    init_cal_req(&mut io, &mut btcoex.mci, &mut reusable);
    if io.last_write(AR_MCI_TX_PAYLOAD0 + 4) != Some(GpmSubtype::WlanCalReq as u32) {
        return TestResult::Fail("init_cal_req did not send WLAN_CAL_REQ");
    }
    if btcoex.mci.wlan_cal_seq != 1 {
        return TestResult::Fail("init_cal_req did not advance the cal seq");
    }
    if reusable {
        return TestResult::Fail("missing BT grant still left cal reusable");
    }
    // Calibration done: WLAN_CAL_DONE goes out with its own seq.
    init_cal_done(&mut io, &mut btcoex.mci);
    if io.last_write(AR_MCI_TX_PAYLOAD0 + 4) != Some(GpmSubtype::WlanCalDone as u32) {
        return TestResult::Fail("init_cal_done did not send WLAN_CAL_DONE");
    }
    if btcoex.mci.wlan_cal_done != 1 {
        return TestResult::Fail("init_cal_done did not advance the done seq");
    }
    // A request while BT sleeps sends nothing.
    let (mut io, mut btcoex) = live();
    btcoex.mci.bt_state = BtState::Sleep;
    let mut reusable = true;
    init_cal_req(&mut io, &mut btcoex.mci, &mut reusable);
    if io.last_write(AR_MCI_COMMAND0).is_some() {
        return TestResult::Fail("init_cal_req sent while BT sleeps");
    }
    // Start reset only runs from CAL_START.
    let (mut io, mut btcoex) = live();
    if start_reset(&mut io, &mut btcoex.mci, true) {
        return TestResult::Fail("start_reset ran outside CAL_START");
    }
    btcoex.mci.bt_state = BtState::CalStart;
    if !start_reset(&mut io, &mut btcoex.mci, true) {
        return TestResult::Fail("start_reset did not run from CAL_START");
    }
    if btcoex.mci.bt_state != BtState::Awake {
        return TestResult::Fail("start_reset did not return BT to awake");
    }
    if io.last_write(AR_MCI_TX_PAYLOAD0 + 4) != Some(GpmSubtype::WlanCalGrant as u32) {
        return TestResult::Fail("start_reset did not grant the cal window");
    }
    // End reset: BT woke during calibration, recalibration is needed.
    let (mut io, mut btcoex) = live();
    btcoex.mci.bt_state = BtState::Sleep;
    io.regs.insert(
        AR_MCI_INTERRUPT_RX_MSG_RAW,
        AR_MCI_INTERRUPT_RX_MSG_REMOTE_RESET,
    );
    io.regs.insert(
        AR_PHY_TIMING4,
        1 << AR_PHY_TIMING_CONTROL4_DO_GAIN_DC_IQ_CAL_SHIFT,
    );
    let Ok(end) = end_reset(&mut io, &mut btcoex.mci, true) else {
        return TestResult::Fail("end_reset errored");
    };
    if end != EndReset::RecalibrationNeeded {
        return TestResult::Fail("end_reset missed the BT wakeup");
    }
    if btcoex.mci.bt_state != BtState::Awake {
        return TestResult::Fail("end_reset did not wake BT");
    }
    if io.last_write(AR_PHY_TIMING4) != Some(0) {
        return TestResult::Fail("end_reset did not clear the cal bit");
    }
    // No wakeup bits: idle, and the bit stays set. Linux's idle path
    // (`ar9003_mci_end_reset` going to `exit`) does not touch
    // TIMING4 at all, so the register must still read set and no
    // write to it may have happened.
    let (mut io, mut btcoex) = live();
    btcoex.mci.bt_state = BtState::Sleep;
    io.regs.insert(
        AR_PHY_TIMING4,
        1 << AR_PHY_TIMING_CONTROL4_DO_GAIN_DC_IQ_CAL_SHIFT,
    );
    let Ok(end) = end_reset(&mut io, &mut btcoex.mci, true) else {
        return TestResult::Fail("end_reset errored without wakeup bits");
    };
    if end != EndReset::Idle {
        return TestResult::Fail("end_reset recalibrated without a BT wakeup");
    }
    if io.reg(AR_PHY_TIMING4) != 1 << AR_PHY_TIMING_CONTROL4_DO_GAIN_DC_IQ_CAL_SHIFT
        || io.last_write(AR_PHY_TIMING4).is_some()
    {
        return TestResult::Fail("end_reset cleared the cal bit while idle");
    }
    TestResult::Pass
}

fn mci_sleep_and_power() -> TestResult {
    // Full sleep halts BT GPMs and drops readiness.
    let (mut io, mut btcoex) = live();
    if set_full_sleep(&mut io, &mut btcoex.mci).is_err() {
        return TestResult::Fail("set_full_sleep errored");
    }
    if io.last_write(AR_MCI_TX_PAYLOAD0 + 4) != Some(0x0001_030c) {
        return TestResult::Fail("set_full_sleep did not send HALT_BT_GPM");
    }
    if btcoex.mci.ready {
        return TestResult::Fail("set_full_sleep left MCI ready");
    }
    // Stop BT mutes and turns BTCOEX_CTRL off, unless saving full sleep.
    let (mut io, mut btcoex) = live();
    if stop_bt(&mut io, &mut btcoex.mci, false).is_err() {
        return TestResult::Fail("stop_bt errored");
    }
    if io.last_write(AR_BTCOEX_CTRL) != Some(0) {
        return TestResult::Fail("stop_bt did not turn BTCOEX_CTRL off");
    }
    if btcoex.mci.ready || btcoex.mci.bt_state != BtState::Sleep {
        return TestResult::Fail("stop_bt did not sleep the link");
    }
    let (mut io, mut btcoex) = live();
    if stop_bt(&mut io, &mut btcoex.mci, true).is_err() {
        return TestResult::Fail("stop_bt (save) errored");
    }
    if io.last_write(AR_BTCOEX_CTRL).is_some() {
        return TestResult::Fail("stop_bt (save) turned BTCOEX_CTRL off");
    }
    // Power-awake toggles BTCOEX_RC bit 0 when BT sleeps and the LNA
    // control value is 2.
    let (mut io, _) = live();
    io.regs.insert(AR_OBS_BUS_CTRL, 2);
    io.regs.insert(AR_MCI_RX_STATUS, AR_MCI_RX_REMOTE_SLEEP);
    if set_power_awake(&mut io).is_err() {
        return TestResult::Fail("set_power_awake errored");
    }
    if io.writes(AR_BTCOEX_RC) != vec![1, 0] {
        return TestResult::Fail("set_power_awake did not toggle BTCOEX_RC");
    }
    let (mut io, _) = live();
    io.regs.insert(AR_OBS_BUS_CTRL, 1);
    io.regs.insert(AR_MCI_RX_STATUS, AR_MCI_RX_REMOTE_SLEEP);
    if set_power_awake(&mut io).is_err() {
        return TestResult::Fail("set_power_awake (lna 1) errored");
    }
    if !io.writes(AR_BTCOEX_RC).is_empty() {
        return TestResult::Fail("set_power_awake toggled BTCOEX_RC with lna != 2");
    }
    TestResult::Pass
}

fn mci_state_sweep() -> TestResult {
    // Enable reads the mode bit, and only when ready.
    let (mut io, mut btcoex) = live();
    let Ok(v) = state(&mut io, &mut btcoex.mci, MciState::Enable) else {
        return TestResult::Fail("state(Enable) errored");
    };
    if v != AR_BTCOEX_CTRL_MCI_MODE_EN {
        return TestResult::Fail("state(Enable) did not read the mode bit");
    }
    io.regs.insert(AR_BTCOEX_CTRL, 0);
    let Ok(v) = state(&mut io, &mut btcoex.mci, MciState::Enable) else {
        return TestResult::Fail("state(Enable, off) errored");
    };
    if v != 0 {
        return TestResult::Fail("state(Enable) read set with mode off");
    }
    btcoex.mci.ready = false;
    io.regs.insert(AR_BTCOEX_CTRL, AR_BTCOEX_CTRL_MCI_MODE_EN);
    let Ok(v) = state(&mut io, &mut btcoex.mci, MciState::Enable) else {
        return TestResult::Fail("state(Enable, !ready) errored");
    };
    if v != 0 {
        return TestResult::Fail("state(Enable) read set while not ready");
    }
    // GPM offset init clamps out-of-range pointers to slot 0.
    let (mut io, mut btcoex) = live();
    io.regs.insert(AR_MCI_GPM_1, 5 << AR_MCI_GPM_WRITE_PTR_S);
    let Ok(_) = state(&mut io, &mut btcoex.mci, MciState::InitGpmOffset) else {
        return TestResult::Fail("state(InitGpmOffset) errored");
    };
    if btcoex.mci.gpm_idx != 5 {
        return TestResult::Fail("state(InitGpmOffset) did not take the pointer");
    }
    io.regs.insert(AR_MCI_GPM_1, 20 << AR_MCI_GPM_WRITE_PTR_S);
    let Ok(_) = state(&mut io, &mut btcoex.mci, MciState::InitGpmOffset) else {
        return TestResult::Fail("state(InitGpmOffset, oob) errored");
    };
    if btcoex.mci.gpm_idx != 0 {
        return TestResult::Fail("state(InitGpmOffset) did not clamp the pointer");
    }
    // Schedule offset and remote sleep read their registers.
    let (mut io, mut btcoex) = live();
    io.regs
        .insert(AR_MCI_RX_STATUS, 3 << AR_MCI_RX_LAST_SCHD_MSG_INDEX_S);
    let Ok(v) = state(&mut io, &mut btcoex.mci, MciState::LastSchdMsgOffset) else {
        return TestResult::Fail("state(LastSchdMsgOffset) errored");
    };
    if v != 48 {
        return TestResult::Fail("state(LastSchdMsgOffset) did not shift the index");
    }
    io.regs.insert(AR_MCI_RX_STATUS, AR_MCI_RX_REMOTE_SLEEP);
    let Ok(v) = state(&mut io, &mut btcoex.mci, MciState::RemoteSleep) else {
        return TestResult::Fail("state(RemoteSleep) errored");
    };
    if v != BtState::Sleep as u32 {
        return TestResult::Fail("state(RemoteSleep) missed the sleep bit");
    }
    io.regs.insert(AR_MCI_RX_STATUS, 0);
    let Ok(v) = state(&mut io, &mut btcoex.mci, MciState::RemoteSleep) else {
        return TestResult::Fail("state(RemoteSleep, awake) errored");
    };
    if v != BtState::Awake as u32 {
        return TestResult::Fail("state(RemoteSleep) missed the awake state");
    }
    // FTP stomp and BT-info flush are pure flag reads.
    let (mut io, mut btcoex) = live();
    let Ok(v) = state(&mut io, &mut btcoex.mci, MciState::NeedFtpStomp) else {
        return TestResult::Fail("state(NeedFtpStomp) errored");
    };
    if v != 1 {
        return TestResult::Fail("state(NeedFtpStomp) was 0 with stomping on");
    }
    btcoex.mci.config |= ATH_MCI_CONFIG_DISABLE_FTP_STOMP;
    let Ok(v) = state(&mut io, &mut btcoex.mci, MciState::NeedFtpStomp) else {
        return TestResult::Fail("state(NeedFtpStomp, off) errored");
    };
    if v != 0 {
        return TestResult::Fail("state(NeedFtpStomp) was 1 with stomping off");
    }
    btcoex.mci.unhalt_bt_gpm = false;
    btcoex.mci.need_flush_btinfo = true;
    let Ok(v) = state(&mut io, &mut btcoex.mci, MciState::NeedFlushBtInfo) else {
        return TestResult::Fail("state(NeedFlushBtInfo) errored");
    };
    if v != 1 || btcoex.mci.need_flush_btinfo {
        return TestResult::Fail("state(NeedFlushBtInfo) did not report and clear");
    }
    let Ok(v) = state(&mut io, &mut btcoex.mci, MciState::NeedFlushBtInfo) else {
        return TestResult::Fail("state(NeedFlushBtInfo, 2nd) errored");
    };
    if v != 0 {
        return TestResult::Fail("state(NeedFlushBtInfo) stayed set");
    }
    // AIC states read 0: Linux hard-disables AIC.
    for st in [
        MciState::AicCal,
        MciState::AicStart,
        MciState::AicCalReset,
        MciState::AicCalSingle,
    ] {
        let Ok(v) = state(&mut io, &mut btcoex.mci, st) else {
            return TestResult::Fail("state(AIC) errored");
        };
        if v != 0 {
            return TestResult::Fail("state(AIC) did not read 0");
        }
    }
    // SetBtAwake wakes the link; ResetReqWake arms the 2G/5G update.
    let (mut io, mut btcoex) = live();
    btcoex.mci.bt_state = BtState::Sleep;
    let Ok(_) = state(&mut io, &mut btcoex.mci, MciState::SetBtAwake) else {
        return TestResult::Fail("state(SetBtAwake) errored");
    };
    if btcoex.mci.bt_state != BtState::Awake {
        return TestResult::Fail("state(SetBtAwake) did not wake BT");
    }
    if io.last_write(AR_MCI_COMMAND0).is_none() {
        return TestResult::Fail("state(SetBtAwake) sent nothing");
    }
    let (mut io, mut btcoex) = live();
    btcoex.mci.update_2g5g = false;
    let Ok(_) = state(&mut io, &mut btcoex.mci, MciState::ResetReqWake) else {
        return TestResult::Fail("state(ResetReqWake) errored");
    };
    if !btcoex.mci.update_2g5g {
        return TestResult::Fail("state(ResetReqWake) did not arm the 2G/5G update");
    }
    // RX recovery is rate-limited by the TSF. `init_mci` leaves
    // `query_bt` set, so clear it first: the "soon" call must be the
    // thing that leaves it clear, not the fixture default.
    let (mut io, mut btcoex) = live();
    btcoex.mci.last_recovery = 100_000;
    btcoex.mci.query_bt = false;
    btcoex.mci.need_flush_btinfo = false;
    io.regs.insert(AR_TSF_L32, 150_000);
    let Ok(_) = state(&mut io, &mut btcoex.mci, MciState::RecoverRx) else {
        return TestResult::Fail("state(RecoverRx, soon) errored");
    };
    if btcoex.mci.query_bt {
        return TestResult::Fail("state(RecoverRx) recovered inside the rate limit");
    }
    io.regs.insert(AR_TSF_L32, 250_000);
    let Ok(_) = state(&mut io, &mut btcoex.mci, MciState::RecoverRx) else {
        return TestResult::Fail("state(RecoverRx, late) errored");
    };
    if !btcoex.mci.query_bt || !btcoex.mci.need_flush_btinfo {
        return TestResult::Fail("state(RecoverRx) did not recover past the rate limit");
    }
    // Version response answers 0.0: Linux never assigns wlan_ver.
    let (mut io, mut btcoex) = live();
    let Ok(_) = state(&mut io, &mut btcoex.mci, MciState::SendWlanCoexVersion) else {
        return TestResult::Fail("state(SendWlanCoexVersion) errored");
    };
    if io.last_write(AR_MCI_TX_PAYLOAD0 + 4) != Some(0x0000_010c) {
        return TestResult::Fail("version response did not answer 0.0");
    }
    TestResult::Pass
}

fn mci_update_wlan_channels() -> TestResult {
    // Channel 1 (2412 MHz, HT20) clears the WLAN channel ±10 plus the
    // 7-channel guard from the map. Linux clears BT channels 0..26
    // (`wlan_chan` 10, `chan_start` -7 clamped to 0, `chan_end` 27),
    // and BT channel `i` is payload bit `48 + i`
    // (`MCI_GPM_CLR_CHANNEL_BIT`), so bits 48..74 go: word 1 loses
    // its whole top half (0xffff_0000 -> 0) and word 2 its low 11
    // bits (0xffff_ffff -> 0xffff_f800). The stored map is NOT the
    // pristine channelmap, though: `update_wlan_channels` sends it,
    // and Linux's `ar9003_mci_send_coex_wlan_channels` stamps the
    // type/opcode into `mci->wlan_channels` in place and overwrites
    // them with 0xff/0xff after the send — so bytes 4-5 (word 1's
    // low half) read 0xffff at assertion time, not 0x0000.
    let (mut io, mut btcoex) = live();
    if update_wlan_channels(&mut io, &mut btcoex.mci, 2412, Ht40::None, false).is_err() {
        return TestResult::Fail("update_wlan_channels errored on 2412");
    }
    if btcoex.mci.wlan_channels != [0, 0x0000_ffff, 0xffff_f800, 0x7fff_ffff] {
        return TestResult::Fail("2412 HT20 channel map is wrong");
    }
    // The map goes out as a channels GPM (type/opcode in word 1):
    // word 1 is 0x0000_040c (type 0x0c, opcode 4, map word 1 is 0).
    // It is not the last payload write — the trailing version query
    // overwrites TX_PAYLOAD0+4 afterwards — so look at all the writes.
    if !io.writes(AR_MCI_TX_PAYLOAD0 + 4).contains(&0x0000_040c) {
        return TestResult::Fail("channels GPM payload is wrong");
    }
    // 5 GHz channels are skipped entirely.
    let (mut io, mut btcoex) = live();
    let before = btcoex.mci.wlan_channels;
    if update_wlan_channels(&mut io, &mut btcoex.mci, 5180, Ht40::None, false).is_err() {
        return TestResult::Fail("update_wlan_channels errored on 5180");
    }
    if btcoex.mci.wlan_channels != before || io.last_write(AR_MCI_COMMAND0).is_some() {
        return TestResult::Fail("5 GHz channel was not skipped");
    }
    // allow_all leaves the map fully open: the local initial map
    // (`mci.c`: [0, 0xffff_0000, 0xffff_ffff, 0x7fff_ffff]), not the
    // `init_mci` default (whose word 1 is 0xffff_ffff) — and with
    // the same in-place 0xff/0xff type-opcode stamp the send leaves
    // behind, word 1 reads 0xffff_ffff, not 0xffff_0000.
    let (mut io, mut btcoex) = live();
    if update_wlan_channels(&mut io, &mut btcoex.mci, 2412, Ht40::None, true).is_err() {
        return TestResult::Fail("update_wlan_channels (allow_all) errored");
    }
    if btcoex.mci.wlan_channels != [0, 0xffff_ffff, 0xffff_ffff, 0x7fff_ffff] {
        return TestResult::Fail("allow_all channel map is wrong");
    }
    // Concurrent-TX power caps: HT20 0x14, HT40 0x10, else none.
    btcoex.mci.concur_tx = false;
    if get_max_txpower(&btcoex.mci, CTL_2GHT20).is_some() {
        return TestResult::Fail("txpower cap applied with concur_tx off");
    }
    btcoex.mci.concur_tx = true;
    if get_max_txpower(&btcoex.mci, CTL_2GHT20) != Some(ATH_BTCOEX_HT20_MAX_TXPOWER) {
        return TestResult::Fail("HT20 txpower cap is wrong");
    }
    if get_max_txpower(&btcoex.mci, CTL_2GHT40) != Some(ATH_BTCOEX_HT40_MAX_TXPOWER) {
        return TestResult::Fail("HT40 txpower cap is wrong");
    }
    if get_max_txpower(&btcoex.mci, 0).is_some() {
        return TestResult::Fail("txpower cap applied to an unknown mode");
    }
    TestResult::Pass
}

fn mci_setup_cleanup() -> TestResult {
    // AR9462 setup: buffers programmed, BTCOEX_CTRL 0x71b | OSLA fields
    // (aggr thresh 2, thresh-en, look-ahead-en) | MCI_MODE_EN = 0x277f,
    // ring filled with the reserved pattern, interrupt enabled.
    let (mut io, mut btcoex) = live();
    if setup(&mut io, &mut btcoex.mci, 0x1000, 0x2000).is_err() {
        return TestResult::Fail("setup errored on AR9462");
    }
    if io.last_write(AR_MCI_GPM_0) != Some(0x1000)
        || io.last_write(AR_MCI_GPM_1) != Some(MCI_GPM_MAX_ENTRY as u32)
        || io.last_write(AR_MCI_SCHD_TABLE_0) != Some(0x2000)
    {
        return TestResult::Fail("setup did not program the GPM/schedule buffers");
    }
    if io.last_write(AR_BTCOEX_CTRL) != Some(0x277f) {
        return TestResult::Fail("setup did not program BTCOEX_CTRL 0x277f");
    }
    if !btcoex.mci.ready || btcoex.mci.gpm_len != MCI_GPM_MAX_ENTRY as u32 {
        return TestResult::Fail("setup did not mark the link ready");
    }
    if btcoex
        .mci
        .gpm_buf
        .iter()
        .any(|b| *b != MCI_GPM_RSVD_PATTERN)
    {
        return TestResult::Fail("setup did not fill the ring with the reserved pattern");
    }
    if io.last_write(AR_MCI_INTERRUPT_EN) != Some(AR_MCI_INTERRUPT_DEFAULT) {
        return TestResult::Fail("setup did not enable the MCI interrupt");
    }
    // Cleanup turns MCI off and disables the interrupt.
    cleanup(&mut io);
    if io.last_write(AR_BTCOEX_CTRL) != Some(0)
        || io.last_write(AR_MCI_INTERRUPT_EN) != Some(0)
        || io.last_write(AR_MCI_INTERRUPT_RX_MSG_EN) != Some(0)
    {
        return TestResult::Fail("cleanup did not turn MCI off");
    }
    // AR9565 setup programs the two-antenna control word instead.
    let (mut io, mut btcoex) = live_chip(Chip::Ar9565);
    if setup(&mut io, &mut btcoex.mci, 0x1000, 0x2000).is_err() {
        return TestResult::Fail("setup errored on AR9565");
    }
    if io.last_write(AR_BTCOEX_CTRL) != Some(0x307) {
        return TestResult::Fail("setup did not program BTCOEX_CTRL 0x303|MCI_MODE_EN");
    }
    if !btcoex.mci.ready {
        return TestResult::Fail("setup did not mark the AR9565 link ready");
    }
    TestResult::Pass
}

fn mci_bt_gain_ctrl_and_timing4() -> TestResult {
    // Gain control hands the LNA to BT and forces a 2G/5G refresh.
    let (mut io, mut btcoex) = live();
    if bt_gain_ctrl(&mut io, &mut btcoex.mci).is_err() {
        return TestResult::Fail("bt_gain_ctrl errored");
    }
    if btcoex.mci.is_2g || !btcoex.mci.update_2g5g {
        return TestResult::Fail("bt_gain_ctrl did not move off 2G");
    }
    if io.last_write(AR_PHY_GLB_CONTROL) != Some(AR_BTCOEX_CTRL_BT_OWN_SPDT_CTRL) {
        return TestResult::Fail("bt_gain_ctrl did not take SPDT control");
    }
    // The TIMING4 gain/DC/IQ-cal bit re-arms and clears.
    let (mut io, _) = live();
    if set_timing4_gain_dc_iq_cal(&mut io, true).is_err() {
        return TestResult::Fail("set_timing4_gain_dc_iq_cal(true) errored");
    }
    if io.last_write(AR_PHY_TIMING4) != Some(1 << AR_PHY_TIMING_CONTROL4_DO_GAIN_DC_IQ_CAL_SHIFT) {
        return TestResult::Fail("cal bit was not set");
    }
    if set_timing4_gain_dc_iq_cal(&mut io, false).is_err() {
        return TestResult::Fail("set_timing4_gain_dc_iq_cal(false) errored");
    }
    if io.last_write(AR_PHY_TIMING4) != Some(0) {
        return TestResult::Fail("cal bit was not cleared");
    }
    TestResult::Pass
}

fn mci_get_isr() -> TestResult {
    // Dead-card reads refuse the interrupt.
    let (mut io, mut btcoex) = live();
    io.regs.insert(AR_MCI_INTERRUPT_RAW, 0xdeadbeef);
    if get_isr(&mut io, &mut btcoex.mci) {
        return TestResult::Fail("get_isr accepted a deadbeef interrupt");
    }
    if btcoex.mci.raw_intr != 0 || btcoex.mci.rx_msg_intr != 0 {
        return TestResult::Fail("get_isr latched a dead-card interrupt");
    }
    // A live interrupt latches and clears in hardware.
    let (mut io, mut btcoex) = live();
    io.regs.insert(
        AR_MCI_INTERRUPT_RX_MSG_RAW,
        AR_MCI_INTERRUPT_RX_MSG_CONT_INFO,
    );
    io.regs.insert(AR_MCI_CONT_STATUS, 0x1234);
    if !get_isr(&mut io, &mut btcoex.mci) {
        return TestResult::Fail("get_isr refused a live interrupt");
    }
    if btcoex.mci.rx_msg_intr != AR_MCI_INTERRUPT_RX_MSG_CONT_INFO {
        return TestResult::Fail("get_isr did not latch the RX message cause");
    }
    if btcoex.mci.cont_status != 0x1234 {
        return TestResult::Fail("get_isr did not latch CONT_STATUS");
    }
    if io.reg(AR_MCI_INTERRUPT_RX_MSG_RAW) != 0 {
        return TestResult::Fail("get_isr did not clear the RX message cause");
    }
    // get_interrupt returns the latched causes and clears them.
    let (raw, rx_msg) = get_interrupt(&mut btcoex.mci);
    if raw != 0 || rx_msg != AR_MCI_INTERRUPT_RX_MSG_CONT_INFO {
        return TestResult::Fail("get_interrupt returned the wrong causes");
    }
    let (raw, rx_msg) = get_interrupt(&mut btcoex.mci);
    if raw != 0 || rx_msg != 0 {
        return TestResult::Fail("get_interrupt did not clear on read");
    }
    TestResult::Pass
}

fn mci_check_bt() -> TestResult {
    // Awake + query pending: the periodic check flushes BT info.
    let (mut io, mut btcoex) = live();
    if check_bt(&mut io, &mut btcoex.mci).is_err() {
        return TestResult::Fail("check_bt errored while awake");
    }
    if !btcoex.mci.need_flush_btinfo {
        return TestResult::Fail("check_bt did not flag BT info for flush");
    }
    // BT asleep: the state syncs to Sleep and nothing is flushed.
    let (mut io, mut btcoex) = live();
    io.regs.insert(AR_MCI_RX_STATUS, AR_MCI_RX_REMOTE_SLEEP);
    if check_bt(&mut io, &mut btcoex.mci).is_err() {
        return TestResult::Fail("check_bt errored while BT asleep");
    }
    if btcoex.mci.bt_state != BtState::Sleep || btcoex.mci.need_flush_btinfo {
        return TestResult::Fail("check_bt did not sync the Sleep state");
    }
    // Not ready: the check is a no-op.
    let (mut io, mut btcoex) = live();
    btcoex.mci.ready = false;
    if check_bt(&mut io, &mut btcoex.mci).is_err() {
        return TestResult::Fail("check_bt errored while not ready");
    }
    if btcoex.mci.need_flush_btinfo {
        return TestResult::Fail("check_bt flushed BT info while not ready");
    }
    TestResult::Pass
}

fn mci_header_values() -> TestResult {
    // Message headers (`ar9003_mci.h::enum mci_message`): the raw
    // header byte written to COMMAND0.
    let headers = [
        (Msg::LnaCtrl, 0x10u8),
        (Msg::ContNack, 0x20),
        (Msg::ContInfo, 0x30),
        (Msg::ContRst, 0x40),
        (Msg::SchdInfo, 0x50),
        (Msg::CpuInt, 0x60),
        (Msg::SysWaking, 0x70),
        (Msg::Gpm, 0x80),
        (Msg::LnaInfo, 0x90),
        (Msg::LnaState, 0x94),
        (Msg::LnaTake, 0x98),
        (Msg::LnaTrans, 0x9c),
        (Msg::SysSleeping, 0xa0),
        (Msg::ReqWake, 0xc0),
        (Msg::Debug16, 0xfe),
        (Msg::RemoteReset, 0xff),
    ];
    for (msg, want) in headers {
        if msg as u8 != want {
            return TestResult::Fail("MCI message header value is wrong");
        }
    }
    // GPM subtypes (`ar9003_mci.h::enum mci_gpm_subtype`).
    let subtypes = [
        (GpmSubtype::BtCalReq, 0u8),
        (GpmSubtype::BtCalGrant, 1),
        (GpmSubtype::BtCalDone, 2),
        (GpmSubtype::WlanCalReq, 3),
        (GpmSubtype::WlanCalGrant, 4),
        (GpmSubtype::WlanCalDone, 5),
        (GpmSubtype::CoexAgent, 0x0c),
        (GpmSubtype::RsvdPattern, 0xfe),
        (GpmSubtype::BtDebug, 0xff),
    ];
    for (subtype, want) in subtypes {
        if subtype as u8 != want {
            return TestResult::Fail("MCI GPM subtype value is wrong");
        }
    }
    // Coex opcodes (`ar9003_mci.h::enum mci_gpm_coex_opcode`).
    let opcodes = [
        (GpmCoexOpcode::VersionQuery, 0u8),
        (GpmCoexOpcode::VersionResponse, 1),
        (GpmCoexOpcode::StatusQuery, 2),
        (GpmCoexOpcode::HaltBtGpm, 3),
        (GpmCoexOpcode::WlanChannels, 4),
        (GpmCoexOpcode::BtProfileInfo, 5),
        (GpmCoexOpcode::BtStatusUpdate, 6),
        (GpmCoexOpcode::BtUpdateFlags, 7),
        (GpmCoexOpcode::Noop, 8),
    ];
    for (opcode, want) in opcodes {
        if opcode as u8 != want {
            return TestResult::Fail("MCI coex opcode value is wrong");
        }
    }
    if HaltBtGpm::Unhalt as u8 != 0 || HaltBtGpm::Halt as u8 != 1 {
        return TestResult::Fail("HALT_BT_GPM state value is wrong");
    }
    if BtFlagsOp::Read as u8 != 0 || BtFlagsOp::Set as u8 != 1 || BtFlagsOp::Clear as u8 != 2 {
        return TestResult::Fail("BT flags op value is wrong");
    }
    if BtState::Sleep as u8 != 0
        || BtState::Awake as u8 != 1
        || BtState::CalStart as u8 != 2
        || BtState::Cal as u8 != 3
    {
        return TestResult::Fail("BT state value is wrong");
    }
    // Every MCI state variant constructs (header coverage); spot-check
    // the Linux order.
    let states = [
        MciState::Enable,
        MciState::InitGpmOffset,
        MciState::CheckGpmOffset,
        MciState::NextGpmOffset,
        MciState::LastGpmOffset,
        MciState::Bt,
        MciState::SetBtSleep,
        MciState::SetBtAwake,
        MciState::SetBtCalStart,
        MciState::SetBtCal,
        MciState::LastSchdMsgOffset,
        MciState::RemoteSleep,
        MciState::ContStatus,
        MciState::ResetReqWake,
        MciState::SendWlanCoexVersion,
        MciState::SetBtCoexVersion,
        MciState::SendWlanChannels,
        MciState::SendVersionQuery,
        MciState::SendStatusQuery,
        MciState::NeedFlushBtInfo,
        MciState::SetConcurTxPri,
        MciState::RecoverRx,
        MciState::NeedFtpStomp,
        MciState::NeedTuning,
        MciState::NeedStatDebug,
        MciState::SharedChainConcurTx,
        MciState::AicCal,
        MciState::AicStart,
        MciState::AicCalReset,
        MciState::AicCalSingle,
        MciState::IsAr9462,
        MciState::IsAr9565_1Ant,
        MciState::IsAr9565_2Ant,
        MciState::WlanWeakSignal,
        MciState::SetWlanPsState,
        MciState::GetWlanPsState,
        MciState::Debug,
        MciState::StatDebug,
        MciState::AllowFcs,
        MciState::Set2gContention,
    ];
    if states.len() != 40 {
        return TestResult::Fail("MCI state list is incomplete");
    }
    if MciState::Enable as u8 != 0
        || MciState::RecoverRx as u8 != 21
        || MciState::AicCal as u8 != 26
        || MciState::Set2gContention as u8 != 39
    {
        return TestResult::Fail("MCI state value is wrong");
    }
    // HT40 variants construct.
    let _ = [Ht40::None, Ht40::Plus, Ht40::Minus];
    let _ = [EndReset::Idle, EndReset::RecalibrationNeeded];
    TestResult::Pass
}

fn mci_bt_profile_list() -> TestResult {
    // Profile-type decoding (`ar9003_mci.h` enum order).
    if GpmCoexProfile::from_u8(5) != Some(GpmCoexProfile::Voice)
        || GpmCoexProfile::from_u8(7).is_some()
        || GpmCoexProfile::from_u8(8).is_some()
        || GpmCoexProfile::Voice as u8 != 5
        || GpmCoexProfile::Max as u8 != 7
    {
        return TestResult::Fail("GpmCoexProfile decoding is wrong");
    }
    // Single SCO, T=12: the 10-byte payload image parses field for
    // field and the scheme picks duty 50 / aggr 8 / period 20.
    let (mut io, mut btcoex) = live();
    put_profile(&mut btcoex.mci, 0, 5, 0, 1, 1, 0, 6, 12, 3, 2);
    // The staged slot is pinned byte-for-byte against the Linux
    // layout (`ar9003_mci.h` offsets 6..16).
    if btcoex.mci.gpm_buf[6..16] != [5, 0, 1, 1, 0, 6, 12, 0, 3, 2] {
        return TestResult::Fail("profile GPM slot bytes do not match the Linux layout");
    }
    let Some(outcome) = pump_gpm(&mut io, &mut btcoex, 1) else {
        return TestResult::Fail("profile GPM did not pump");
    };
    if outcome.gpm_seen != 1 {
        return TestResult::Fail("profile GPM was not seen");
    }
    let profiles = &btcoex.mci.profiles;
    if profiles.num_sco != 1 || profiles.num_profiles() != 1 {
        return TestResult::Fail("SCO profile was not counted");
    }
    let Some(entry) = profiles.entries[0] else {
        return TestResult::Fail("SCO profile entry is missing");
    };
    if entry.profile != GpmCoexProfile::Voice
        || entry.conn_handle != 0
        || !entry.start
        || !entry.master
        || entry.edr
        || entry.voice_type != 6
        || entry.t != 12
        || entry.w != 3
        || entry.a != 2
    {
        return TestResult::Fail("profile payload did not parse field for field");
    }
    if profiles.voice_priority != 114 {
        return TestResult::Fail("voice priority is not table[6] = 114");
    }
    if profiles.duty_cycle != 50
        || profiles.btcoex_period != 20
        || profiles.bt_stomp_type != btcoex::StompType::Low
        || profiles.aggr_limit != 8
        || profiles.btcoex_no_stomp != 10
        || profiles.concur_txprio != [114, 114, 114, 0, 0]
    {
        return TestResult::Fail("single-SCO scheme is wrong");
    }
    // Voice type out of range falls back to priority 110.
    let (mut io, mut btcoex) = live();
    put_profile(&mut btcoex.mci, 0, 5, 0, 1, 0, 0, 9, 6, 0, 0);
    if pump_gpm(&mut io, &mut btcoex, 1).is_none() {
        return TestResult::Fail("voice-type-9 GPM did not pump");
    }
    if btcoex.mci.profiles.voice_priority != 110 {
        return TestResult::Fail("voice type >= 9 did not fall back to 110");
    }
    // T=6 SCO: duty 30, aggr 6.
    let (mut io, mut btcoex) = live();
    put_profile(&mut btcoex.mci, 0, 5, 0, 1, 0, 0, 0, 6, 0, 0);
    if pump_gpm(&mut io, &mut btcoex, 1).is_none() {
        return TestResult::Fail("T=6 SCO GPM did not pump");
    }
    if btcoex.mci.profiles.duty_cycle != 30 || btcoex.mci.profiles.aggr_limit != 6 {
        return TestResult::Fail("T=6 SCO scheme is wrong");
    }
    // Type change on a known handle (A2DP -> HID in one interrupt),
    // then the stop: the entry is dropped and the scheme returns to
    // the empty-list duty 55.
    let (mut io, mut btcoex) = live();
    put_profile(&mut btcoex.mci, 0, 2, 3, 1, 0, 1, 0, 0, 0, 0);
    put_profile(&mut btcoex.mci, 1, 3, 3, 1, 0, 0, 0, 0, 0, 0);
    if pump_gpm(&mut io, &mut btcoex, 2).is_none() {
        return TestResult::Fail("type-change GPMs did not pump");
    }
    if btcoex.mci.profiles.num_a2dp != 0 || btcoex.mci.profiles.num_hid != 1 {
        return TestResult::Fail("type change did not move the count");
    }
    if btcoex.mci.profiles.duty_cycle != 30 || btcoex.mci.profiles.aggr_limit != 6 {
        return TestResult::Fail("single-HID scheme after type change is wrong");
    }
    put_profile(&mut btcoex.mci, 2, 3, 3, 0, 0, 0, 0, 0, 0, 0);
    if pump_gpm(&mut io, &mut btcoex, 3).is_none() {
        return TestResult::Fail("profile-stop GPM did not pump");
    }
    if btcoex.mci.profiles.num_profiles() != 0 || btcoex.mci.profiles.duty_cycle != 55 {
        return TestResult::Fail("profile stop did not empty the list");
    }
    // Illegal types are ignored and never run the scheme.
    for bad_type in [0u8, 7u8] {
        let (mut io, mut btcoex) = live();
        put_profile(&mut btcoex.mci, 0, bad_type, 0, 1, 0, 0, 0, 0, 0, 0);
        if pump_gpm(&mut io, &mut btcoex, 1).is_none() {
            return TestResult::Fail("illegal-type GPM did not pump");
        }
        if btcoex.mci.profiles.num_profiles() != 0 || btcoex.mci.profiles.duty_cycle != 0 {
            return TestResult::Fail("illegal profile type reached the list");
        }
    }
    // SCO cap: a second voice profile is refused.
    let (mut io, mut btcoex) = live();
    put_profile(&mut btcoex.mci, 0, 5, 0, 1, 0, 0, 0, 12, 0, 0);
    put_profile(&mut btcoex.mci, 1, 5, 1, 1, 0, 0, 0, 12, 0, 0);
    if pump_gpm(&mut io, &mut btcoex, 2).is_none() {
        return TestResult::Fail("SCO-cap GPMs did not pump");
    }
    if btcoex.mci.profiles.num_sco != 1 || btcoex.mci.profiles.num_profiles() != 1 {
        return TestResult::Fail("second SCO profile was admitted");
    }
    // ACL cap: 7 RFCOMM fill the list; an 8th RFCOMM and an A2DPVO
    // (SCO-counted but not VOICE-exempt from the ACL cap) are refused.
    let (mut io, mut btcoex) = live();
    for handle in 0..7u8 {
        put_profile(
            &mut btcoex.mci,
            handle as usize,
            1,
            handle,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
        );
    }
    put_profile(&mut btcoex.mci, 7, 1, 7, 1, 0, 0, 0, 0, 0, 0);
    put_profile(&mut btcoex.mci, 8, 6, 7, 1, 0, 0, 0, 0, 0, 0);
    if pump_gpm(&mut io, &mut btcoex, 9).is_none() {
        return TestResult::Fail("ACL-cap GPMs did not pump");
    }
    let profiles = &btcoex.mci.profiles;
    if profiles.num_other_acl != 7 || profiles.num_sco != 0 || profiles.num_profiles() != 7 {
        return TestResult::Fail("ACL cap admitted too many profiles");
    }
    if profiles.duty_cycle != 95 || profiles.aggr_limit != 4 || profiles.btcoex_period != 20 {
        return TestResult::Fail("seven-profile scheme is wrong");
    }
    TestResult::Pass
}

fn mci_bt_profile_scheme() -> TestResult {
    // Single PAN, AR9462: duty 35, period 53 halved to 26.
    let (mut io, mut btcoex) = live();
    put_profile(&mut btcoex.mci, 0, 4, 1, 1, 0, 0, 0, 0, 0, 0);
    if pump_gpm(&mut io, &mut btcoex, 1).is_none() {
        return TestResult::Fail("PAN GPM did not pump");
    }
    let profiles = &btcoex.mci.profiles;
    if profiles.num_pan != 1
        || profiles.duty_cycle != 35
        || profiles.btcoex_period != 26
        || profiles.btcoex_no_stomp != 16
        || profiles.aggr_limit != 0
    {
        return TestResult::Fail("single-PAN AR9462 scheme is wrong");
    }
    // Single PAN, AR9565: duty 40.
    let (mut io, mut btcoex) = live_chip(Chip::Ar9565);
    put_profile(&mut btcoex.mci, 0, 4, 1, 1, 0, 0, 0, 0, 0, 0);
    if pump_gpm(&mut io, &mut btcoex, 1).is_none() {
        return TestResult::Fail("AR9565 PAN GPM did not pump");
    }
    if btcoex.mci.profiles.duty_cycle != 40 || btcoex.mci.profiles.btcoex_no_stomp != 15 {
        return TestResult::Fail("single-PAN AR9565 scheme is wrong");
    }
    // Single HID: duty 30, aggr 6.
    let (mut io, mut btcoex) = live();
    put_profile(&mut btcoex.mci, 0, 3, 0, 1, 0, 0, 0, 0, 0, 0);
    if pump_gpm(&mut io, &mut btcoex, 1).is_none() {
        return TestResult::Fail("HID GPM did not pump");
    }
    if btcoex.mci.profiles.duty_cycle != 30 || btcoex.mci.profiles.aggr_limit != 6 {
        return TestResult::Fail("single-HID scheme is wrong");
    }
    // Single EDR A2DP: no special case; duty 50, aggr 0, and the
    // concurrent-TX priorities fold in the A2DP priority 90.
    let (mut io, mut btcoex) = live();
    put_profile(&mut btcoex.mci, 0, 2, 0, 1, 0, 1, 0, 0, 0, 0);
    if pump_gpm(&mut io, &mut btcoex, 1).is_none() {
        return TestResult::Fail("A2DP GPM did not pump");
    }
    let profiles = &btcoex.mci.profiles;
    if profiles.duty_cycle != 50
        || profiles.aggr_limit != 0
        || profiles.num_bdr != 0
        || profiles.concur_txprio != [90, 90, 90, 0, 0]
    {
        return TestResult::Fail("single-EDR-A2DP scheme is wrong");
    }
    // Single basic-rate A2DP: the +20 BDR bonus applies (50 + 20).
    let (mut io, mut btcoex) = live();
    put_profile(&mut btcoex.mci, 0, 2, 0, 1, 0, 0, 0, 0, 0, 0);
    if pump_gpm(&mut io, &mut btcoex, 1).is_none() {
        return TestResult::Fail("BDR A2DP GPM did not pump");
    }
    if btcoex.mci.profiles.num_bdr != 1
        || btcoex.mci.profiles.duty_cycle != 70
        || btcoex.mci.profiles.btcoex_no_stomp != 6
    {
        return TestResult::Fail("BDR duty bonus is wrong");
    }
    // Two profiles (A2DP + HID): duty 60, aggr 6.
    let (mut io, mut btcoex) = live();
    put_profile(&mut btcoex.mci, 0, 2, 0, 1, 0, 1, 0, 0, 0, 0);
    put_profile(&mut btcoex.mci, 1, 3, 1, 1, 0, 0, 0, 0, 0, 0);
    if pump_gpm(&mut io, &mut btcoex, 2).is_none() {
        return TestResult::Fail("two-profile GPMs did not pump");
    }
    if btcoex.mci.profiles.duty_cycle != 60 || btcoex.mci.profiles.aggr_limit != 6 {
        return TestResult::Fail("two-profile scheme is wrong");
    }
    // Two HIDs: duty 30.
    let (mut io, mut btcoex) = live();
    put_profile(&mut btcoex.mci, 0, 3, 0, 1, 0, 0, 0, 0, 0, 0);
    put_profile(&mut btcoex.mci, 1, 3, 1, 1, 0, 0, 0, 0, 0, 0);
    if pump_gpm(&mut io, &mut btcoex, 2).is_none() {
        return TestResult::Fail("two-HID GPMs did not pump");
    }
    if btcoex.mci.profiles.duty_cycle != 30 {
        return TestResult::Fail("two-HID scheme is wrong");
    }
    // Three profiles: duty 70, aggr 4.
    let (mut io, mut btcoex) = live();
    put_profile(&mut btcoex.mci, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0);
    put_profile(&mut btcoex.mci, 1, 2, 1, 1, 0, 1, 0, 0, 0, 0);
    put_profile(&mut btcoex.mci, 2, 3, 2, 1, 0, 0, 0, 0, 0, 0);
    if pump_gpm(&mut io, &mut btcoex, 3).is_none() {
        return TestResult::Fail("three-profile GPMs did not pump");
    }
    if btcoex.mci.profiles.duty_cycle != 70 || btcoex.mci.profiles.aggr_limit != 4 {
        return TestResult::Fail("three-profile scheme is wrong");
    }
    // Eight profiles, HT: duty 98, period unhalved at 40, and the
    // aggregation limit is adjusted down to half the (zero) airtime.
    let (mut io, mut btcoex) = live();
    btcoex.mci.is_ht = true;
    for handle in 0..7u8 {
        put_profile(
            &mut btcoex.mci,
            handle as usize,
            1,
            handle,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
        );
    }
    put_profile(&mut btcoex.mci, 7, 5, 7, 1, 0, 0, 0, 12, 0, 0);
    if pump_gpm(&mut io, &mut btcoex, 8).is_none() {
        return TestResult::Fail("eight-profile HT GPMs did not pump");
    }
    let profiles = &btcoex.mci.profiles;
    if profiles.num_profiles() != 8
        || profiles.duty_cycle != 98
        || profiles.btcoex_period != 40
        || profiles.aggr_limit != 0
        || profiles.btcoex_no_stomp != 0
    {
        return TestResult::Fail("eight-profile HT scheme is wrong");
    }
    // Eight profiles, non-HT: period halved to 20, aggr stays 4.
    let (mut io, mut btcoex) = live();
    for handle in 0..7u8 {
        put_profile(
            &mut btcoex.mci,
            handle as usize,
            1,
            handle,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
        );
    }
    put_profile(&mut btcoex.mci, 7, 5, 7, 1, 0, 0, 0, 12, 0, 0);
    if pump_gpm(&mut io, &mut btcoex, 8).is_none() {
        return TestResult::Fail("eight-profile GPMs did not pump");
    }
    if btcoex.mci.profiles.btcoex_period != 20 || btcoex.mci.profiles.aggr_limit != 4 {
        return TestResult::Fail("eight-profile non-HT scheme is wrong");
    }
    // 5 GHz: the BDR bonus and no-stomp computation are skipped.
    let (mut io, mut btcoex) = live();
    btcoex.mci.is_2g = false;
    put_profile(&mut btcoex.mci, 0, 2, 0, 1, 0, 0, 0, 0, 0, 0);
    if pump_gpm(&mut io, &mut btcoex, 1).is_none() {
        return TestResult::Fail("5 GHz GPM did not pump");
    }
    let profiles = &btcoex.mci.profiles;
    if profiles.num_bdr != 1
        || profiles.duty_cycle != 50
        || profiles.btcoex_period != 40
        || profiles.btcoex_no_stomp != 0
    {
        return TestResult::Fail("5 GHz scheme is wrong");
    }
    // DISABLE_TUNING after a scheme: the duty cycle and stomp type
    // stand, only the 2 GHz period halving still applies.
    let (mut io, mut btcoex) = live();
    put_profile(&mut btcoex.mci, 0, 4, 1, 1, 0, 0, 0, 0, 0, 0);
    if pump_gpm(&mut io, &mut btcoex, 1).is_none() {
        return TestResult::Fail("PAN GPM did not pump");
    }
    btcoex.mci.config |= ATH_MCI_CONFIG_DISABLE_TUNING;
    put_profile(&mut btcoex.mci, 1, 3, 5, 1, 0, 0, 0, 0, 0, 0);
    if pump_gpm(&mut io, &mut btcoex, 2).is_none() {
        return TestResult::Fail("tuning-disabled GPM did not pump");
    }
    let profiles = &btcoex.mci.profiles;
    if profiles.num_hid != 1
        || profiles.duty_cycle != 35
        || profiles.btcoex_period != 13
        || profiles.aggr_limit != 0
        || profiles.btcoex_no_stomp != 8
    {
        return TestResult::Fail("DISABLE_TUNING did not hold the scheme");
    }
    // DISABLE_TUNING from the start: nothing is ever tuned.
    let (mut io, mut btcoex) = live();
    btcoex.mci.config |= ATH_MCI_CONFIG_DISABLE_TUNING;
    put_profile(&mut btcoex.mci, 0, 3, 0, 1, 0, 0, 0, 0, 0, 0);
    if pump_gpm(&mut io, &mut btcoex, 1).is_none() {
        return TestResult::Fail("tuning-disabled HID GPM did not pump");
    }
    let profiles = &btcoex.mci.profiles;
    if profiles.num_hid != 1
        || profiles.duty_cycle != 0
        || profiles.btcoex_period != 0
        || profiles.bt_stomp_type != btcoex::StompType::All
    {
        return TestResult::Fail("DISABLE_TUNING from the start tuned anyway");
    }
    TestResult::Pass
}

fn mci_bt_profile_status() -> TestResult {
    // A critical status update for an unknown handle counts as a
    // management link and stomps everything.
    let (mut io, mut btcoex) = live();
    put_status(&mut btcoex.mci, 0, 0, 2, 1);
    if pump_gpm(&mut io, &mut btcoex, 1).is_none() {
        return TestResult::Fail("status GPM did not pump");
    }
    let profiles = &btcoex.mci.profiles;
    if profiles.num_mgmt != 1
        || profiles.duty_cycle != 55
        || profiles.bt_stomp_type != btcoex::StompType::All
        || profiles.concur_txprio != [62, 0, 62, 0, 0]
    {
        return TestResult::Fail("critical status update was not counted");
    }
    // Repeating the same update, and clearing a bit that was never
    // set, leave the management count alone (no scheme re-run).
    put_status(&mut btcoex.mci, 1, 0, 2, 1);
    if pump_gpm(&mut io, &mut btcoex, 2).is_none() {
        return TestResult::Fail("repeat status GPM did not pump");
    }
    if btcoex.mci.profiles.num_mgmt != 1 {
        return TestResult::Fail("repeat status update changed the count");
    }
    put_status(&mut btcoex.mci, 2, 0, 3, 0);
    if pump_gpm(&mut io, &mut btcoex, 3).is_none() {
        return TestResult::Fail("clear status GPM did not pump");
    }
    if btcoex.mci.profiles.num_mgmt != 1 {
        return TestResult::Fail("clearing an unset bit changed the count");
    }
    // Clearing the critical bit drops the management count and the
    // stomp type returns to LOW with empty priorities.
    put_status(&mut btcoex.mci, 3, 0, 2, 0);
    if pump_gpm(&mut io, &mut btcoex, 4).is_none() {
        return TestResult::Fail("un-critical status GPM did not pump");
    }
    let profiles = &btcoex.mci.profiles;
    if profiles.num_mgmt != 0
        || profiles.bt_stomp_type != btcoex::StompType::Low
        || profiles.concur_txprio != [0, 0, 0, 0, 0]
    {
        return TestResult::Fail("clearing the critical bit did not release the stomp");
    }
    // Link-status updates are ignored.
    put_status(&mut btcoex.mci, 4, 1, 5, 1);
    if pump_gpm(&mut io, &mut btcoex, 5).is_none() {
        return TestResult::Fail("link status GPM did not pump");
    }
    if btcoex.mci.profiles.num_mgmt != 0 {
        return TestResult::Fail("link status update was counted");
    }
    // A status update for a handle that already has a profile is
    // ignored (its critical bit stays clear).
    put_profile(&mut btcoex.mci, 5, 1, 4, 1, 0, 0, 0, 0, 0, 0);
    if pump_gpm(&mut io, &mut btcoex, 6).is_none() {
        return TestResult::Fail("RFCOMM GPM did not pump");
    }
    put_status(&mut btcoex.mci, 6, 0, 4, 1);
    if pump_gpm(&mut io, &mut btcoex, 7).is_none() {
        return TestResult::Fail("known-handle status GPM did not pump");
    }
    if btcoex.mci.profiles.num_mgmt != 0 || btcoex.mci.profiles.status[4] {
        return TestResult::Fail("known-handle status update was counted");
    }
    // Handles at or above the profile maximum are ignored.
    put_status(&mut btcoex.mci, 7, 0, 8, 1);
    if pump_gpm(&mut io, &mut btcoex, 8).is_none() {
        return TestResult::Fail("handle-8 status GPM did not pump");
    }
    if btcoex.mci.profiles.num_mgmt != 0 {
        return TestResult::Fail("out-of-range handle was counted");
    }
    TestResult::Pass
}

fn mci_bt_profile_flush() -> TestResult {
    // Two live profiles, then stale BT info: the next coex GPM
    // flushes the list and re-arms the status query. The flush does
    // not re-run the scheme (duty 60 stands, aggr resets to 0).
    let (mut io, mut btcoex) = live();
    put_profile(&mut btcoex.mci, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0);
    put_profile(&mut btcoex.mci, 1, 3, 1, 1, 0, 0, 0, 0, 0, 0);
    if pump_gpm(&mut io, &mut btcoex, 2).is_none() {
        return TestResult::Fail("profile GPMs did not pump");
    }
    if btcoex.mci.profiles.num_profiles() != 2 || btcoex.mci.profiles.duty_cycle != 60 {
        return TestResult::Fail("profile setup did not reach two profiles");
    }
    btcoex.mci.need_flush_btinfo = true;
    btcoex.mci.unhalt_bt_gpm = false;
    put_gpm(
        &mut btcoex.mci,
        2,
        GpmSubtype::CoexAgent as u8,
        GpmCoexOpcode::VersionQuery as u8,
        &[],
    );
    if pump_gpm(&mut io, &mut btcoex, 3).is_none() {
        return TestResult::Fail("flush-trigger GPM did not pump");
    }
    let profiles = &btcoex.mci.profiles;
    if profiles.num_profiles() != 0
        || profiles.num_other_acl != 0
        || profiles.num_hid != 0
        || profiles.aggr_limit != 0
        || profiles.duty_cycle != 60
    {
        return TestResult::Fail("stale BT info did not flush the profile list");
    }
    if btcoex.mci.need_flush_btinfo || btcoex.mci.query_bt {
        return TestResult::Fail("flush did not clear the re-fetch flags");
    }
    // The re-arm is a topology status query: type COEX_AGENT (0x0c)
    // and opcode STATUS_QUERY (0x02) in payload word 1, bitmap byte
    // 0x02 (QUERY_BT_TOPOLOGY) at byte 6.
    if io.last_write(AR_MCI_TX_PAYLOAD0 + 4) != Some(0x0002_020c) {
        return TestResult::Fail("flush did not send the topology status query");
    }
    // While an UNHALT is still owed, the flush does not fire.
    let (mut io, mut btcoex) = live();
    put_profile(&mut btcoex.mci, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0);
    if pump_gpm(&mut io, &mut btcoex, 1).is_none() {
        return TestResult::Fail("unhalt-case profile GPM did not pump");
    }
    btcoex.mci.need_flush_btinfo = true;
    // `unhalt_bt_gpm` stays true from `init_mci`.
    put_gpm(
        &mut btcoex.mci,
        1,
        GpmSubtype::CoexAgent as u8,
        GpmCoexOpcode::VersionQuery as u8,
        &[],
    );
    if pump_gpm(&mut io, &mut btcoex, 2).is_none() {
        return TestResult::Fail("unhalt-case GPM did not pump");
    }
    if btcoex.mci.profiles.num_profiles() != 1 {
        return TestResult::Fail("flush fired while an UNHALT was owed");
    }
    TestResult::Pass
}

fn mci_sync_gpm_ring() -> TestResult {
    // A real 512-byte coherent DMA buffer (schedule table + GPM ring),
    // filled with the reserved pattern as the owner does at probe.
    let mut dma = match alloc_coherent_masked(
        MCI_DMA_BUF_BYTES,
        narf_lib::id::DomainId::DRIVER_0,
        u64::from(u32::MAX),
    ) {
        Ok(dma) => dma,
        Err(_) => return TestResult::Fail("MCI DMA allocation failed in the fixture"),
    };
    {
        let bytes = dma.as_mut_slice();
        bytes.fill(MCI_GPM_RSVD_PATTERN);
        // Slot 0: coex-agent version query; slot 1: BT calibration request.
        bytes[MCI_GPM_DMA_OFFSET + MCI_GPM_COEX_B_GPM_TYPE] = GpmSubtype::CoexAgent as u8;
        bytes[MCI_GPM_DMA_OFFSET + MCI_GPM_COEX_B_GPM_OPCODE] = GpmCoexOpcode::VersionQuery as u8;
        bytes[MCI_GPM_DMA_OFFSET + 16 + MCI_GPM_COEX_B_GPM_TYPE] = GpmSubtype::BtCalReq as u8;
        bytes[MCI_GPM_DMA_OFFSET + 16 + MCI_GPM_COEX_B_GPM_OPCODE] = 0;
    }
    // The engine as `setup` leaves it: ring filled, ready, 2G, awake.
    let (mut io, mut btcoex) = live();
    btcoex.mci.gpm_buf.fill(MCI_GPM_RSVD_PATTERN);
    io.regs.insert(AR_MCI_GPM_1, 2 << AR_MCI_GPM_WRITE_PTR_S);
    sync_gpm_ring(&mut io, &dma, &mut btcoex.mci);
    // Both pending slots copied in.
    if btcoex.mci.gpm_buf[MCI_GPM_COEX_B_GPM_TYPE] != GpmSubtype::CoexAgent as u8
        || btcoex.mci.gpm_buf[MCI_GPM_COEX_B_GPM_OPCODE] != GpmCoexOpcode::VersionQuery as u8
        || btcoex.mci.gpm_buf[16 + MCI_GPM_COEX_B_GPM_TYPE] != GpmSubtype::BtCalReq as u8
    {
        return TestResult::Fail("sync did not copy the pending DMA slots in");
    }
    // The walk consumes slot 0 (recycled) and advances past it; BT
    // posts a different GPM into DMA slot 1 meanwhile.
    recycle_gpm(&mut btcoex.mci, 0);
    btcoex.mci.gpm_idx = 1;
    {
        let bytes = dma.as_mut_slice();
        bytes[MCI_GPM_DMA_OFFSET + 16 + MCI_GPM_COEX_B_GPM_TYPE] = GpmSubtype::CoexAgent as u8;
        bytes[MCI_GPM_DMA_OFFSET + 16 + MCI_GPM_COEX_B_GPM_OPCODE] =
            GpmCoexOpcode::VersionResponse as u8;
    }
    sync_gpm_ring(&mut io, &dma, &mut btcoex.mci);
    // The stale DMA slot 0 was cleared, so it cannot be re-processed;
    // the CPU copy stays recycled.
    if dma.as_slice()[MCI_GPM_DMA_OFFSET + MCI_GPM_COEX_B_GPM_TYPE] != MCI_GPM_RSVD_PATTERN
        || btcoex.mci.gpm_buf[MCI_GPM_COEX_B_GPM_TYPE] != MCI_GPM_RSVD_PATTERN
    {
        return TestResult::Fail("sync did not clear the consumed DMA slot");
    }
    // The pending slot 1 keeps its unconsumed content: the DMA
    // overwrite is not copied over it, and the DMA slot is not cleared.
    if btcoex.mci.gpm_buf[16 + MCI_GPM_COEX_B_GPM_TYPE] != GpmSubtype::BtCalReq as u8
        || dma.as_slice()[MCI_GPM_DMA_OFFSET + 16 + MCI_GPM_COEX_B_GPM_TYPE]
            != GpmSubtype::CoexAgent as u8
    {
        return TestResult::Fail("sync clobbered or cleared a pending slot");
    }
    // A `check_gpm_offset` walk from slot 0 does not resurrect the
    // consumed slot 0.
    btcoex.mci.gpm_idx = 0;
    sync_gpm_ring(&mut io, &dma, &mut btcoex.mci);
    if btcoex.mci.gpm_buf[MCI_GPM_COEX_B_GPM_TYPE] != MCI_GPM_RSVD_PATTERN {
        return TestResult::Fail("sync re-copied a consumed GPM after the index reset");
    }
    // A bogus write pointer syncs nothing.
    {
        let bytes = dma.as_mut_slice();
        bytes[MCI_GPM_DMA_OFFSET + MCI_GPM_COEX_B_GPM_TYPE] = GpmSubtype::CoexAgent as u8;
    }
    io.regs
        .insert(AR_MCI_GPM_1, 0xffff << AR_MCI_GPM_WRITE_PTR_S);
    sync_gpm_ring(&mut io, &dma, &mut btcoex.mci);
    if btcoex.mci.gpm_buf[MCI_GPM_COEX_B_GPM_TYPE] != MCI_GPM_RSVD_PATTERN {
        return TestResult::Fail("sync copied from the DMA ring on a bogus write pointer");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/wireless/ath9k/ar9003", mci_message_exchange);
kernel_test_in!("drivers/wireless/ath9k/ar9003", mci_send_gating);
kernel_test_in!("drivers/wireless/ath9k/ar9003", mci_gpio_observation);
kernel_test_in!("drivers/wireless/ath9k/ar9003", mci_gpm_walk);
kernel_test_in!("drivers/wireless/ath9k/ar9003", mci_cal_handshake);
kernel_test_in!("drivers/wireless/ath9k/ar9003", mci_sleep_and_power);
kernel_test_in!("drivers/wireless/ath9k/ar9003", mci_state_sweep);
kernel_test_in!("drivers/wireless/ath9k/ar9003", mci_update_wlan_channels);
kernel_test_in!("drivers/wireless/ath9k/ar9003", mci_get_isr);
kernel_test_in!("drivers/wireless/ath9k/ar9003", mci_setup_cleanup);
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    mci_bt_gain_ctrl_and_timing4
);
kernel_test_in!("drivers/wireless/ath9k/ar9003", mci_check_bt);
kernel_test_in!("drivers/wireless/ath9k/ar9003", mci_bt_profile_list);
kernel_test_in!("drivers/wireless/ath9k/ar9003", mci_bt_profile_scheme);
kernel_test_in!("drivers/wireless/ath9k/ar9003", mci_bt_profile_status);
kernel_test_in!("drivers/wireless/ath9k/ar9003", mci_bt_profile_flush);
kernel_test_in!("drivers/wireless/ath9k/ar9003", mci_sync_gpm_ring);
kernel_test_in!("drivers/wireless/ath9k/ar9003", mci_header_values);

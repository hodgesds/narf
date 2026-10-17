//! Register-model tests for the DCN3.0 native DDC owner. The model implements
//! the documented engine behaviour Linux relies on: AUX_SW_DATA index loads and
//! auto-increment, the AUX_SW_GO request/reply frame, DC_I2C_DATA's circular
//! buffer and the TRANSACTIONn queue, and both arbitration handshakes.
use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

const BASE: u64 = 0x34c0;
const BASE1: u64 = 0xc0;

/// A DisplayPort sink on an AUX line: DPCD plus an EDID at 0x50.
#[derive(Clone)]
pub(crate) struct Sink {
    pub dpcd: Vec<u8>,
    pub edid: Vec<u8>,
    pub offset: usize,
    pub segment: usize,
    /// Replies to answer with AUX DEFER before acknowledging.
    pub defers: u32,
    pub nack_native: bool,
    /// Engine never completes (no DONE), for cancellation and timeouts.
    pub stuck: bool,
    pub hpd_low: bool,
}
impl Sink {
    pub(crate) fn new(edid: Vec<u8>) -> Self {
        let mut dpcd = vec![0; 0x300];
        for (i, byte) in dpcd.iter_mut().enumerate() {
            *byte = i as u8 ^ 0x5a;
        }
        dpcd[0] = 0x12;
        Self {
            dpcd,
            edid,
            offset: 0,
            segment: 0,
            defers: 0,
            nack_native: false,
            stuck: false,
            hpd_low: false,
        }
    }
    fn i2c_write(&mut self, address: u32, data: &[u8]) -> bool {
        match address {
            0x50 => {
                if let Some(&offset) = data.first() {
                    self.offset = usize::from(offset);
                }
                true
            }
            0x30 => {
                if let Some(&segment) = data.first() {
                    self.segment = usize::from(segment);
                }
                true
            }
            _ => false,
        }
    }
    fn i2c_read(&mut self, address: u32, out: &mut [u8]) -> bool {
        if address != 0x50 {
            return false;
        }
        for byte in out.iter_mut() {
            *byte = *self
                .edid
                .get(self.segment * 256 + self.offset)
                .unwrap_or(&0xff);
            self.offset += 1;
        }
        true
    }
}

pub(crate) struct Fake {
    pub regs: BTreeMap<u64, u32>,
    pub writes: Vec<(u64, u32)>,
    pub gone: bool,
    pub aux: [Option<Sink>; 6],
    /// I2C devices on the hardware engine, by DDC line.
    pub ddc: [Option<Sink>; 6],
    pub i2c_stuck: bool,
    /// Every AUX request frame header seen: (line, command byte, length).
    pub requests: Vec<(u8, u8, usize)>,
    request: [[u8; 32]; 6],
    wptr: [usize; 6],
    reply: [Vec<u8>; 6],
    rptr: [usize; 6],
    reading: [bool; 6],
    i2c_buffer: Vec<u8>,
    i2c_index: usize,
    i2c_reading: bool,
}
impl Fake {
    pub(crate) fn new() -> Self {
        let mut regs = BTreeMap::new();
        regs.insert(BASE1 + MICROSECOND_TIME_BASE_DIV, 0x0012_0264);
        for line in 0..6u64 {
            // GOP left both pins masked as GPIO, so restore is observable.
            regs.insert(BASE + DC_GPIO_DDC1_MASK + 4 * line, PIN_CLK | PIN_DATA);
        }
        Self {
            regs,
            writes: Vec::new(),
            gone: false,
            aux: Default::default(),
            ddc: Default::default(),
            i2c_stuck: false,
            requests: Vec::new(),
            request: [[0; 32]; 6],
            wptr: [0; 6],
            reply: Default::default(),
            rptr: [0; 6],
            reading: [false; 6],
            i2c_buffer: vec![0; 1024],
            i2c_index: 0,
            i2c_reading: false,
        }
    }
    pub(crate) fn get(&self, reg: u64) -> u32 {
        *self.regs.get(&(BASE + reg)).unwrap_or(&0)
    }
    pub(crate) fn set(&mut self, reg: u64, value: u32) {
        self.regs.insert(BASE + reg, value);
    }
    fn aux_line(reg: u64) -> Option<(u8, u64)> {
        if (AUX_CONTROL..AUX_CONTROL + 6 * AUX_STRIDE).contains(&reg) {
            let line = (reg - AUX_CONTROL) / AUX_STRIDE;
            Some((line as u8, reg - line * AUX_STRIDE))
        } else {
            None
        }
    }
    fn run_aux(&mut self, line: usize) {
        let control = self.get(AUX_SW_CONTROL + line as u64 * AUX_STRIDE);
        let bytes = field(control, AUX_SW_WR_BYTES) as usize;
        let frame = self.request[line];
        let command = frame[0];
        let address =
            u32::from(command & 0xf) << 16 | u32::from(frame[1]) << 8 | u32::from(frame[2]);
        let length = if bytes > 3 {
            usize::from(frame[3]) + 1
        } else {
            0
        };
        self.requests.push((line as u8, command & 0xf0, length));
        let status_reg = AUX_SW_STATUS + line as u64 * AUX_STRIDE;
        let Some(sink) = self.aux[line].as_mut() else {
            self.set(status_reg, AUX_SW_DONE | AUX_SW_RX_TIMEOUT);
            return;
        };
        if sink.stuck {
            self.set(status_reg, 0);
            return;
        }
        if sink.hpd_low {
            self.set(status_reg, AUX_SW_DONE | AUX_SW_HPD_DISCON);
            return;
        }
        let mut reply = Vec::new();
        if sink.defers > 0 {
            sink.defers -= 1;
            reply.push(0x20);
        } else {
            let payload = &frame[4..4 + bytes.saturating_sub(4)];
            match command >> 4 {
                0x9 => {
                    if sink.nack_native {
                        reply.push(0x10);
                    } else {
                        reply.push(0);
                        let start = address as usize;
                        reply.extend_from_slice(&sink.dpcd[start..start + length]);
                    }
                }
                0x8 => {
                    if sink.nack_native {
                        reply.push(0x10);
                    } else {
                        let start = address as usize;
                        sink.dpcd[start..start + length].copy_from_slice(payload);
                        reply.push(0);
                    }
                }
                0x0 | 0x4 => reply.push(if sink.i2c_write(address, payload) {
                    0
                } else {
                    0x40
                }),
                0x1 | 0x5 => {
                    let mut data = vec![0; length];
                    if sink.i2c_read(address, &mut data) {
                        reply.push(0);
                        reply.extend_from_slice(&data);
                    } else {
                        reply.push(0x40);
                    }
                }
                _ => reply.push(0x40),
            }
        }
        self.set(status_reg, AUX_SW_DONE | (reply.len() as u32) << 24);
        self.reply[line] = reply;
    }
    fn run_i2c(&mut self) {
        let control = self.get(DC_I2C_CONTROL);
        let line = field(control, I2C_DDC_SELECT) as usize;
        let count = field(control, I2C_TRANSACTION_COUNT) as usize + 1;
        if self.i2c_stuck {
            self.set(DC_I2C_SW_STATUS, I2C_STATUS_USED_BY_SW);
            return;
        }
        let mut position = 0;
        let mut status = 0x4; // DC_I2C_SW_DONE
        for transaction in 0..count {
            let reg = self.get(DC_I2C_TRANSACTION0 + transaction as u64);
            let length = field(reg, I2C_COUNT0) as usize;
            let address = u32::from(self.i2c_buffer[position] >> 1);
            position += 1;
            let Some(device) = self.ddc[line].as_mut() else {
                status |= I2C_SW_STOPPED_ON_NACK;
                break;
            };
            if reg & I2C_RW0 == 0 {
                let data = self.i2c_buffer[position..position + length].to_vec();
                if !device.i2c_write(address, &data) {
                    status |= I2C_SW_STOPPED_ON_NACK;
                    break;
                }
            } else if !device.i2c_read(address, &mut self.i2c_buffer[position..position + length]) {
                status |= I2C_SW_STOPPED_ON_NACK;
                break;
            }
            position += length;
        }
        self.set(DC_I2C_SW_STATUS, status);
    }
}
impl Io for Fake {
    fn read(&mut self, dword: u64) -> u32 {
        if self.gone {
            return u32::MAX;
        }
        let reg = dword.wrapping_sub(BASE);
        if let Some((line, AUX_SW_DATA)) = Self::aux_line(reg) {
            let line = usize::from(line);
            if self.reading[line] {
                let byte = *self.reply[line].get(self.rptr[line]).unwrap_or(&0);
                self.rptr[line] += 1;
                return u32::from(byte) << 8 | AUX_SW_DATA_RW;
            }
        }
        if reg == DC_I2C_DATA && self.i2c_reading {
            let byte = self.i2c_buffer[self.i2c_index];
            self.i2c_index += 1;
            return u32::from(byte) << 8;
        }
        *self.regs.get(&dword).unwrap_or(&0)
    }
    fn write(&mut self, dword: u64, value: u32) {
        self.writes.push((dword, value));
        self.regs.insert(dword, value);
        let reg = dword.wrapping_sub(BASE);
        if let Some((line, kind)) = Self::aux_line(reg) {
            let l = usize::from(line);
            match kind {
                AUX_CONTROL => {
                    let done = if value & AUX_RESET != 0 {
                        AUX_RESET_DONE
                    } else {
                        0
                    };
                    self.regs.insert(dword, value & !AUX_RESET_DONE | done);
                }
                AUX_ARB_CONTROL => {
                    let current = self.regs[&dword];
                    let mut status = field(current, AUX_REG_RW_CNTL_STATUS);
                    if value & AUX_SW_DONE_USING_AUX_REG != 0 {
                        status = 0;
                    } else if value & AUX_SW_USE_AUX_REG_REQ != 0 && status != DMCU_CAN_ACCESS_AUX {
                        status = SW_CAN_ACCESS_AUX;
                    }
                    self.regs.insert(
                        dword,
                        put(
                            value & !AUX_SW_DONE_USING_AUX_REG,
                            AUX_REG_RW_CNTL_STATUS,
                            status,
                        ),
                    );
                }
                AUX_INTERRUPT_CONTROL if value & AUX_SW_DONE_ACK != 0 => {
                    let status = AUX_SW_STATUS + u64::from(line) * AUX_STRIDE;
                    let old = self.get(status);
                    self.set(status, old & !AUX_SW_DONE);
                }
                AUX_SW_DATA => {
                    if value & AUX_SW_DATA_RW != 0 {
                        if value & AUX_SW_AUTOINCREMENT_DISABLE != 0 {
                            self.rptr[l] = field(value, AUX_SW_INDEX) as usize;
                        }
                        self.reading[l] = true;
                    } else {
                        self.reading[l] = false;
                        if value & AUX_SW_AUTOINCREMENT_DISABLE != 0 {
                            self.wptr[l] = field(value, AUX_SW_INDEX) as usize;
                        }
                        let at = self.wptr[l].min(31);
                        self.request[l][at] = field(value, AUX_SW_DATA_FIELD) as u8;
                        self.wptr[l] += 1;
                    }
                }
                AUX_SW_CONTROL if value & AUX_SW_GO != 0 => {
                    self.regs.insert(dword, value & !AUX_SW_GO);
                    self.run_aux(l);
                }
                _ => {}
            }
            return;
        }
        match reg {
            DC_I2C_ARBITRATION => {
                let mut status = 0;
                if value & I2C_SW_DONE_USING_I2C_REG == 0 && value & I2C_SW_USE_I2C_REG_REQ != 0 {
                    status = I2C_STATUS_USED_BY_SW;
                }
                let value = value & !(I2C_SW_DONE_USING_I2C_REG | I2C_SW_USE_I2C_REG_REQ);
                self.regs.insert(
                    dword,
                    put(value, I2C_REG_RW_CNTL_STATUS, status)
                        | if status != 0 {
                            I2C_SW_USE_I2C_REG_REQ
                        } else {
                            0
                        },
                );
            }
            DC_I2C_DATA => {
                if value & I2C_INDEX_WRITE != 0 {
                    self.i2c_index = field(value, I2C_INDEX) as usize;
                }
                if value & I2C_DATA_RW != 0 {
                    self.i2c_reading = true;
                } else {
                    self.i2c_reading = false;
                    self.i2c_buffer[self.i2c_index] = field(value, I2C_DATA_FIELD) as u8;
                    self.i2c_index += 1;
                }
            }
            DC_I2C_CONTROL => {
                if value & I2C_SW_STATUS_RESET != 0 && !self.i2c_stuck {
                    self.set(DC_I2C_SW_STATUS, 0);
                }
                if value & I2C_GO != 0 {
                    self.regs.insert(dword, value & !I2C_GO);
                    self.run_i2c();
                }
            }
            _ => {}
        }
    }
}

pub(crate) fn engine(fake: Fake) -> Engine<Fake> {
    Engine::new_with(fake, Cap::bootstrap(), BASE, BASE1)
}
fn run<T>(future: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}
/// A valid 256-byte EDID: base block with one CTA extension.
pub(crate) fn edid() -> Vec<u8> {
    let mut bytes = vec![0u8; 256];
    bytes[..8].copy_from_slice(&[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]);
    for (i, b) in bytes.iter_mut().enumerate().take(126).skip(8) {
        *b = i as u8;
    }
    bytes[126] = 1;
    bytes[128] = 0x02;
    bytes[129] = 3;
    for block in [0usize, 128] {
        let sum = bytes[block..block + 127]
            .iter()
            .fold(0u8, |a, &b| a.wrapping_add(b));
        bytes[block + 127] = 0u8.wrapping_sub(sum);
    }
    bytes
}

fn dcn30_aux_bind_mirrors_enc3_hw_init_and_timeout() -> TestResult {
    let mut e = engine(Fake::new());
    if e.bind_aux(2, 1).is_err() || e.bind_hpd(1, Signal::DisplayPort).is_err() {
        return TestResult::Fail("bind refused");
    }
    let rx0 = e.io.get(Engine::<Fake>::aux(2, AUX_DPHY_RX_CONTROL0));
    let rx1 = e.io.get(Engine::<Fake>::aux(2, AUX_DPHY_RX_CONTROL1));
    // 0x103d1110 with AUX_RX_RECEIVE_WINDOW cleared; 552us is 69 x 8us.
    if rx0 != 0x103d_1010
        || e.io.get(Engine::<Fake>::aux(2, AUX_DPHY_TX_CONTROL)) != 0x21c7a
        || field(e.io.get(Engine::<Fake>::aux(2, AUX_CONTROL)), AUX_HPD_SEL) != 1
        || field(rx1, AUX_RX_TIMEOUT_LEN) != 69
        || field(rx1, AUX_RX_TIMEOUT_LEN_MUL) != 0
        || e.poll_us[2] != 3312
    {
        return TestResult::Fail("DCN3.0 AUX init values");
    }
    // Literal DP_AUX2 ids: 0x1f50 + 2 * 0x1c.
    if !e.io.writes.iter().any(|&(d, _)| d == BASE + 0x1f92) {
        return TestResult::Fail("AUX2 RX_CONTROL0 id");
    }
    // DP filter 80/0ms, HPD2 GPIO mask bit 8 cleared, HPD block enabled.
    let filt = e.io.get(DC_HPD_TOGGLE_FILT_CNTL + HPD_STRIDE);
    if field(filt, DC_HPD_CONNECT_INT_DELAY) != 8
        || field(filt, DC_HPD_DISCONNECT_INT_DELAY) != 0
        || e.io.get(DC_HPD_CONTROL + HPD_STRIDE) & DC_HPD_EN == 0
        || e.io.get(DC_GPIO_HPD_MASK) & (1 << 8) != 0
    {
        return TestResult::Fail("DP HPD filter/enable");
    }
    // Longer periods use the 16/32/64us multipliers, capped at 127 units.
    e.configure_timeout(2, 3200).unwrap();
    let rx1 = e.io.get(Engine::<Fake>::aux(2, AUX_DPHY_RX_CONTROL1));
    if field(rx1, AUX_RX_TIMEOUT_LEN) != 100 || field(rx1, AUX_RX_TIMEOUT_LEN_MUL) != 2 {
        return TestResult::Fail("LTTPR timeout encoding");
    }
    e.configure_timeout(2, 20000).unwrap();
    let rx1 = e.io.get(Engine::<Fake>::aux(2, AUX_DPHY_RX_CONTROL1));
    if field(rx1, AUX_RX_TIMEOUT_LEN) != 127 || field(rx1, AUX_RX_TIMEOUT_LEN_MUL) != 3 {
        return TestResult::Fail("timeout cap");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-ddc",
    dcn30_aux_bind_mirrors_enc3_hw_init_and_timeout
);

fn dcn30_aux_native_dpcd_frames_and_release() -> TestResult {
    let mut fake = Fake::new();
    fake.aux[3] = Some(Sink::new(edid()));
    let mut e = engine(fake);
    e.bind_aux(3, 0).unwrap();
    let mut caps = [0; 16];
    if run(dpcd(&mut e, 3, 0, &mut caps, false)).is_err() {
        return TestResult::Fail("DPCD read failed");
    }
    if caps[0] != 0x12 || caps[5] != 5 ^ 0x5a {
        return TestResult::Fail("DPCD bytes");
    }
    // The header: action|addr[19:16] loaded at index zero, then autoincrement.
    let data = BASE + Engine::<Fake>::aux(3, AUX_SW_DATA);
    let frame: Vec<u32> =
        e.io.writes
            .iter()
            .filter(|w| w.0 == data)
            .map(|w| w.1)
            .collect();
    if frame.len() < 4
        || frame[0] != AUX_SW_AUTOINCREMENT_DISABLE | 0x90 << 8
        || frame[1] & AUX_SW_AUTOINCREMENT_DISABLE != 0
        || field(frame[3], AUX_SW_DATA_FIELD) != 15
        || field(
            e.io.get(Engine::<Fake>::aux(3, AUX_SW_CONTROL)),
            AUX_SW_WR_BYTES,
        ) != 4
    {
        return TestResult::Fail("AUX request frame");
    }
    // Pads are back in their GPIO state, the AUX pad mode is kept, the
    // engine is released and DDC4 left I2C mode.
    let mask = e.io.get(DC_GPIO_DDC1_MASK + 12);
    if mask & (PIN_CLK | PIN_DATA) != PIN_CLK | PIN_DATA
        || mask & AUX_PAD_MODE == 0
        || field(
            e.io.get(Engine::<Fake>::aux(3, AUX_ARB_CONTROL)),
            AUX_REG_RW_CNTL_STATUS,
        ) != 0
        || e.io.get(DC_GPIO_AUX_CTRL_5) & 1 << 15 != 0
    {
        return TestResult::Fail("AUX release");
    }
    // A first acquire enabled the engine through a reset.
    let control = e.io.get(Engine::<Fake>::aux(3, AUX_CONTROL));
    if control & AUX_EN == 0 || control & AUX_RESET != 0 {
        return TestResult::Fail("AUX enable/reset");
    }
    // Writes carry the payload; WR_BYTES is the header, length and data.
    if run(dpcd(&mut e, 3, 0x100, &mut [0x0a, 0x84], true)).is_err()
        || e.io.aux[3].as_ref().unwrap().dpcd[0x101] != 0x84
        || field(
            e.io.get(Engine::<Fake>::aux(3, AUX_SW_CONTROL)),
            AUX_SW_WR_BYTES,
        ) != 6
    {
        return TestResult::Fail("DPCD write");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-ddc",
    dcn30_aux_native_dpcd_frames_and_release
);

fn dcn30_aux_retry_policy_matches_dce_aux() -> TestResult {
    // Two DEFERs then ACK succeed inside the seven-attempt budget.
    let mut fake = Fake::new();
    let mut sink = Sink::new(edid());
    sink.defers = 2;
    fake.aux[0] = Some(sink);
    let mut e = engine(fake);
    e.bind_aux(0, 0).unwrap();
    let mut buf = [0; 1];
    if run(dpcd(&mut e, 0, 0, &mut buf, false)).is_err() || e.io.requests.len() != 3 {
        return TestResult::Fail("DEFER then ACK");
    }
    // A sink that only defers is abandoned after AUX_MAX_RETRIES.
    e.io.aux[0].as_mut().unwrap().defers = 100;
    e.io.requests.clear();
    if run(dpcd(&mut e, 0, 0, &mut buf, false)) != Err(Error::Defer) || e.io.requests.len() != 7 {
        return TestResult::Fail("endless DEFER bounded");
    }
    // No sink: three timeouts, the hardware having waited between them.
    e.io.aux[0] = None;
    e.io.requests.clear();
    if run(dpcd(&mut e, 0, 0, &mut buf, false)) != Err(Error::Timeout) || e.io.requests.len() != 3 {
        return TestResult::Fail("timeout retries");
    }
    // NACK and HPD loss are terminal at once.
    let mut sink = Sink::new(edid());
    sink.nack_native = true;
    e.io.aux[0] = Some(sink.clone());
    e.io.requests.clear();
    if run(dpcd(&mut e, 0, 0, &mut buf, false)) != Err(Error::Nack) || e.io.requests.len() != 1 {
        return TestResult::Fail("NACK terminal");
    }
    sink.nack_native = false;
    sink.hpd_low = true;
    e.io.aux[0] = Some(sink);
    if run(dpcd(&mut e, 0, 0, &mut buf, false)) != Err(Error::HpdDisconnected) {
        return TestResult::Fail("HPD discon terminal");
    }
    // A DMCU-owned engine is refused before the pads are touched.
    e.io.set(AUX_ARB_CONTROL, DMCU_CAN_ACCESS_AUX << 2);
    let writes = e.io.writes.len();
    if run(dpcd(&mut e, 0, 0, &mut buf, false)) != Err(Error::Engine) || e.io.writes.len() != writes
    {
        return TestResult::Fail("DMCU arbitration");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-ddc",
    dcn30_aux_retry_policy_matches_dce_aux
);

fn dcn30_i2c_over_aux_reads_edid_in_mot_chunks() -> TestResult {
    let mut fake = Fake::new();
    fake.aux[1] = Some(Sink::new(edid()));
    let mut e = engine(fake);
    e.bind_aux(1, 1).unwrap();
    let mut offset = [0u8];
    let mut block = [0u8; 128];
    let mut messages = [
        Message {
            address: 0x50,
            write: true,
            data: &mut offset,
        },
        Message {
            address: 0x50,
            write: false,
            data: &mut block,
        },
    ];
    if run(i2c(&mut e, 1, Mode::Aux, &mut messages)).is_err() || block[..] != edid()[..128] {
        return TestResult::Fail("EDID over AUX");
    }
    // One MOT write, seven MOT reads, and a final read that releases MOT.
    let commands: Vec<u8> = e.io.requests.iter().map(|r| r.1).collect();
    if commands.len() != 9
        || commands[0] != 0x40
        || commands[1..8].iter().any(|&c| c != 0x50)
        || commands[8] != 0x10
        || e.io.requests[1].2 != 16
    {
        return TestResult::Fail("I2C-over-AUX framing");
    }
    // An absent I2C device is an I2C NACK, not a retry.
    let mut nothing = [0u8; 1];
    let mut messages = [Message {
        address: 0x37,
        write: false,
        data: &mut nothing,
    }];
    if run(i2c(&mut e, 1, Mode::Aux, &mut messages)) != Err(Error::I2cNack) {
        return TestResult::Fail("I2C-over-AUX NACK");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-ddc",
    dcn30_i2c_over_aux_reads_edid_in_mot_chunks
);

fn dcn30_hw_i2c_reads_hdmi_edid() -> TestResult {
    let mut fake = Fake::new();
    fake.ddc[4] = Some(Sink::new(edid()));
    // The GOP left the pad in AUX mode with the pull-downs off.
    fake.set(DC_GPIO_DDC1_MASK + 16, PIN_CLK | PIN_DATA | AUX_PAD_MODE);
    let mut e = engine(fake);
    let mut offset = [128u8];
    let mut block = [0u8; 128];
    let mut messages = [
        Message {
            address: 0x50,
            write: true,
            data: &mut offset,
        },
        Message {
            address: 0x50,
            write: false,
            data: &mut block,
        },
    ];
    if run(i2c(&mut e, 4, Mode::I2c, &mut messages)).is_err() {
        return TestResult::Fail("HW I2C EDID read");
    }
    if block[..] != edid()[128..] {
        return TestResult::Fail("HW I2C EDID bytes");
    }
    // 100 kHz from the 0x00120264 time base: 100 MHz / 2 / 100 kHz.
    let speed = e.io.get(Engine::<Fake>::i2c_speed(4));
    let setup = e.io.get(Engine::<Fake>::i2c_setup(4));
    let t0 = e.io.get(DC_I2C_TRANSACTION0);
    let t1 = e.io.get(DC_I2C_TRANSACTION0 + 1);
    if field(speed, I2C_PRESCALE) != 500
        || field(speed, I2C_THRESHOLD) != 2
        || field(speed, I2C_START_STOP_TIMING_CNTL) != 2
        || field(setup, I2C_TIME_LIMIT) != 3
        || setup & I2C_DDC_ENABLE == 0
        || setup & I2C_SEND_RESET_LENGTH == 0
        || field(e.io.get(DC_I2C_CONTROL), I2C_DDC_SELECT) != 4
    {
        return TestResult::Fail("I2C engine setup");
    }
    // The offset write is queued without STOP; the read runs with STOP.
    if t0 & (I2C_STOP0 | I2C_RW0) != 0
        || field(t0, I2C_COUNT0) != 1
        || t1 & (I2C_STOP0 | I2C_RW0) != I2C_STOP0 | I2C_RW0
        || field(t1, I2C_COUNT0) != 128
    {
        return TestResult::Fail("I2C transaction queue");
    }
    // Pad in I2C mode with pull-downs and RXSEL, then GPIO bits restored.
    let mask = e.io.get(DC_GPIO_DDC1_MASK + 16);
    if mask & AUX_PAD_MODE != 0
        || mask & (DDC_DATA_PD_EN | DDC_CLK_PD_EN) != DDC_DATA_PD_EN | DDC_CLK_PD_EN
        || mask & (PIN_CLK | PIN_DATA) != PIN_CLK | PIN_DATA
        || e.io.get(DC_GPIO_AUX_CTRL_5) & 1 << 16 == 0
        || (e.io.get(PHY_AUX_CNTL) >> 18) & 3 != 1
        || field(e.io.get(DC_I2C_ARBITRATION), I2C_REG_RW_CNTL_STATUS) != 0
    {
        return TestResult::Fail("I2C pad/arbitration lifecycle");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dcn30-ddc", dcn30_hw_i2c_reads_hdmi_edid);

fn dcn30_hw_i2c_nack_timeout_and_busy_fail_closed() -> TestResult {
    let mut e = engine(Fake::new());
    let mut byte = [0u8];
    let mut messages = [Message {
        address: 0x50,
        write: false,
        data: &mut byte,
    }];
    if run(i2c(&mut e, 0, Mode::I2c, &mut messages)) != Err(Error::I2cNack)
        || field(e.io.get(DC_I2C_ARBITRATION), I2C_REG_RW_CNTL_STATUS) != 0
    {
        return TestResult::Fail("no device is a released NACK");
    }
    // An engine that never completes times out within the computed bound and
    // is soft-reset on release.
    e.io.ddc[0] = Some(Sink::new(edid()));
    e.io.i2c_stuck = true;
    let mut messages = [Message {
        address: 0x50,
        write: false,
        data: &mut byte,
    }];
    if run(i2c(&mut e, 0, Mode::I2c, &mut messages)) != Err(Error::Timeout)
        || !e
            .io
            .writes
            .iter()
            .any(|&(d, v)| d == BASE + DC_I2C_CONTROL && v & I2C_SOFT_RESET != 0)
    {
        return TestResult::Fail("stuck I2C engine");
    }
    // A DDC line the hardware requester holds is refused before any pad write.
    e.io.i2c_stuck = false;
    e.io.set(DC_I2C_DDC1_HW_STATUS, I2C_STATUS_USED_BY_HW);
    let writes = e.io.writes.len();
    let mut messages = [Message {
        address: 0x50,
        write: false,
        data: &mut byte,
    }];
    if run(i2c(&mut e, 0, Mode::I2c, &mut messages)) != Err(Error::Engine)
        || e.io.writes.len() != writes
    {
        return TestResult::Fail("HW-owned DDC");
    }
    // Oversized payloads and a missing time base are refused.
    e.io.set(DC_I2C_DDC1_HW_STATUS, 0);
    let mut big = [0u8; 300];
    let mut messages = [Message {
        address: 0x50,
        write: false,
        data: &mut big,
    }];
    if run(i2c(&mut e, 0, Mode::I2c, &mut messages)) != Err(Error::Invalid) {
        return TestResult::Fail("oversized payload");
    }
    e.io.regs.insert(BASE1 + MICROSECOND_TIME_BASE_DIV, 0);
    let mut messages = [Message {
        address: 0x50,
        write: false,
        data: &mut byte,
    }];
    if run(i2c(&mut e, 0, Mode::I2c, &mut messages)) != Err(Error::Unsupported) {
        return TestResult::Fail("zero time base without crystal");
    }
    // After reset-on-init the divider is zero; the VBIOS crystal paces it.
    e.crystal_khz = 100_000;
    e.io.ddc[0] = Some(Sink::new(edid()));
    let mut messages = [Message {
        address: 0x50,
        write: false,
        data: &mut byte,
    }];
    if run(i2c(&mut e, 0, Mode::I2c, &mut messages)).is_err()
        || field(e.io.get(Engine::<Fake>::i2c_speed(0)), I2C_PRESCALE) != 500
    {
        return TestResult::Fail("crystal fallback");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-ddc",
    dcn30_hw_i2c_nack_timeout_and_busy_fail_closed
);

fn dcn30_hpd_sense_filter_and_ack() -> TestResult {
    let mut e = engine(Fake::new());
    e.bind_hpd(3, Signal::Hdmi).unwrap();
    // HDMI 500/100ms; HPD4's GPIO mask is bit 20 (not the A-register 24).
    let filt = e.io.get(DC_HPD_TOGGLE_FILT_CNTL + 3 * HPD_STRIDE);
    if field(filt, DC_HPD_CONNECT_INT_DELAY) != 50
        || field(filt, DC_HPD_DISCONNECT_INT_DELAY) != 10
        || !e
            .io
            .writes
            .iter()
            .any(|&(d, v)| d == BASE + DC_GPIO_HPD_MASK && v & (1 << 20) == 0)
    {
        return TestResult::Fail("HDMI HPD filter");
    }
    // An already-enabled block is left as found.
    let writes = e.io.writes.len();
    e.bind_hpd(3, Signal::Hdmi).unwrap();
    if e.io.writes[writes..]
        .iter()
        .any(|&(d, _)| d == BASE + DC_HPD_CONTROL + 3 * HPD_STRIDE)
    {
        return TestResult::Fail("HPD_EN rewritten");
    }
    // The debounced bit decides, not the raw pin.
    e.io.set(DC_HPD_INT_STATUS + 3 * HPD_STRIDE, DC_HPD_SENSE);
    if e.hpd_sense(3) != Ok(false) || e.hpd_raw(3) != Ok(true) {
        return TestResult::Fail("raw pin used as connect");
    }
    e.io.set(
        DC_HPD_INT_STATUS + 3 * HPD_STRIDE,
        DC_HPD_SENSE | DC_HPD_SENSE_DELAYED,
    );
    if e.hpd_ack(3) != Ok(true) {
        return TestResult::Fail("ack sense");
    }
    let control = e.io.get(DC_HPD_INT_CONTROL + 3 * HPD_STRIDE);
    if control & DC_HPD_INT_ACK == 0 || control & DC_HPD_INT_POLARITY != 0 {
        return TestResult::Fail("connected arms the disconnect edge");
    }
    e.io.set(DC_HPD_INT_STATUS + 3 * HPD_STRIDE, 0);
    e.hpd_ack(3).unwrap();
    e.hpd_interrupt(3, true).unwrap();
    let control = e.io.get(DC_HPD_INT_CONTROL + 3 * HPD_STRIDE);
    if control & DC_HPD_INT_POLARITY == 0 || control & DC_HPD_INT_EN == 0 {
        return TestResult::Fail("disconnected arms the connect edge");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dcn30-ddc", dcn30_hpd_sense_filter_and_ack);

fn dcn30_ddc_cancel_releases_and_device_loss_retains() -> TestResult {
    let mut fake = Fake::new();
    let mut sink = Sink::new(edid());
    sink.stuck = true;
    fake.aux[5] = Some(sink);
    let mut e = engine(fake);
    e.bind_aux(5, 5).unwrap();
    {
        let mut buf = [0u8; 4];
        let mut future = pin!(dpcd(&mut e, 5, 0, &mut buf, false));
        let mut cx = Context::from_waker(Waker::noop());
        let mut pending = false;
        for _ in 0..64 {
            if future.as_mut().poll(&mut cx).is_pending() {
                pending = true;
                break;
            }
        }
        if !pending {
            return TestResult::Fail("stuck AUX completed");
        }
        // Dropped mid-transaction.
    }
    let arb = e.io.get(Engine::<Fake>::aux(5, AUX_ARB_CONTROL));
    if field(arb, AUX_REG_RW_CNTL_STATUS) != 0
        || e.io.get(DC_GPIO_DDC1_MASK + 20) & (PIN_CLK | PIN_DATA) != PIN_CLK | PIN_DATA
    {
        return TestResult::Fail("cancellation left the engine owned");
    }
    e.io.gone = true;
    if e.hpd_sense(0) != Err(Error::DeviceGone) {
        return TestResult::Fail("device loss");
    }
    e.io.gone = false;
    let mut buf = [0u8; 1];
    if run(dpcd(&mut e, 5, 0, &mut buf, false)) != Err(Error::Busy)
        || e.check(0) != Err(Error::Busy)
    {
        return TestResult::Fail("failed owner reused");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-ddc",
    dcn30_ddc_cancel_releases_and_device_loss_retains
);

fn dcn30_ddc_constructor_binds_navi22_banks() -> TestResult {
    let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
    let mut dcn = gpu.ip_blocks[0];
    dcn.hw_id = crate::amdgpu_discovery::HW_ID_DCN;
    dcn.major = 3;
    dcn.minor = 0;
    dcn.revision = 0;
    dcn.num_bases = 4;
    dcn.base_addrs[..4].copy_from_slice(&[0x12, 0xc0, 0x34c0, 0x9000]);
    gpu.ip_blocks.push(dcn);
    gpu.regs.len = 0x100000;
    // SAFETY: the constructor only validates the inert map.
    let ddc = unsafe { Ddc::new(&gpu, Cap::bootstrap(), 100_000) };
    let Ok(mut ddc) = ddc else {
        return TestResult::Fail("Navi22 DDC refused");
    };
    if ddc.0.base != BASE || ddc.0.base1 != BASE1 {
        return TestResult::Fail("bank bases");
    }
    if ddc.bind(6, Some(0), Signal::Hdmi) != Err(Error::Invalid)
        || ddc.bind(0, Some(6), Signal::Hdmi) != Err(Error::Invalid)
        || ddc.bind(0, None, Signal::DisplayPort) != Err(Error::Unsupported)
    {
        return TestResult::Fail("bind bounds");
    }
    gpu.regs.len = (BASE + u64::from(LAST_REG)) * 4 + 3;
    // SAFETY: as above.
    if unsafe { Ddc::new(&gpu, Cap::bootstrap(), 100_000) }.is_ok() {
        return TestResult::Fail("truncated bank admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-ddc",
    dcn30_ddc_constructor_binds_navi22_banks
);

/// Drive a debounced HPD level in the model.
pub(crate) fn set_hpd(fake: &mut Fake, index: u8, connected: bool) {
    let reg = DC_HPD_INT_STATUS + u64::from(index) * HPD_STRIDE;
    fake.set(
        reg,
        if connected {
            DC_HPD_SENSE | DC_HPD_SENSE_DELAYED
        } else {
            0
        },
    );
}

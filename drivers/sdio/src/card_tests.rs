use super::*;
use alloc::{sync::Arc, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

struct State {
    registers: [u8; 256],
    common: Vec<u8>,
    commands: Vec<(u8, u32, u16)>,
    words: Vec<u32>,
    left: usize,
    reject_data: bool,
    refuse_commands: bool,
}
impl State {
    fn set32(&mut self, a: u32, v: u32) {
        self.registers[a as usize..a as usize + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn get32(&self, a: u32) -> u32 {
        u32::from_le_bytes(
            self.registers[a as usize..a as usize + 4]
                .try_into()
                .unwrap(),
        )
    }
    fn get16(&self, a: u32) -> u16 {
        u16::from_le_bytes(
            self.registers[a as usize..a as usize + 2]
                .try_into()
                .unwrap(),
        )
    }
    fn moved(&mut self) {
        self.left -= 1;
        if self.left == 0 {
            self.set32(PRESENT_STATE, PS_CARD_PRESENT);
            self.set32(INT_STATUS, self.get32(INT_STATUS) | INT_DATA_END);
        }
    }
}
#[derive(Clone)]
pub struct Model(
    Arc<IrqSafeSpinLock<State>>,
    Option<crate::pio::HostIdentity>,
);
impl core::fmt::Debug for Model {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SdioCardModel")
            .field("host", &self.1)
            .finish_non_exhaustive()
    }
}
impl Model {
    fn new() -> Self {
        let mut s = State {
            registers: [0; 256],
            common: vec![0; 0x20000],
            commands: Vec::new(),
            words: Vec::new(),
            left: 0,
            reject_data: false,
            refuse_commands: false,
        };
        s.set32(CAPABILITIES, (50 << 8) | CAPS_CAN_VDD_330);
        s.registers[HOST_VERSION as usize] = SPEC_300 as u8;
        s.set32(PRESENT_STATE, PS_CARD_PRESENT);
        s.common[CCCR_SDIO_REVISION as usize] = 0x32;
        s.common[CCCR_IO_ENABLE as usize] = 6;
        s.common[CCCR_IO_READY as usize] = 6;
        s.common[9..12].copy_from_slice(&[0, 0x10, 0]);
        s.common[0x1000..0x100d]
            .copy_from_slice(&[0x20, 4, 0xd0, 2, 0xaf, 0xa9, 0x22, 4, 0, 0, 2, 0x32, 0xff]);
        for f in 1..=2 {
            let a = 0x100 * f + 9;
            let cis = 0x1000 + f * 0x100;
            s.common[a..a + 3].copy_from_slice(&[0, (cis >> 8) as u8, 0]);
            s.common[cis] = 0x22;
            s.common[cis + 1] = 42;
            s.common[cis + 2] = 1;
            if f == 1 {
                s.common[cis + 2 + 12] = 64;
            } else {
                s.common[cis + 2 + 13] = 2;
            }
            s.common[cis + 44] = 0xff;
        }
        Self(Arc::new(IrqSafeSpinLock::new(s)), None)
    }
}
impl Registers for Model {
    fn enable_intx(&mut self) -> bool {
        true
    }
    fn host_identity(&self) -> Option<crate::pio::HostIdentity> {
        self.1
    }
    fn read8(&mut self, a: u32) -> u8 {
        self.0.lock().registers[a as usize]
    }
    fn read16(&mut self, a: u32) -> u16 {
        self.0.lock().get16(a)
    }
    fn read32(&mut self, a: u32) -> u32 {
        let mut s = self.0.lock();
        if a == BUFFER {
            s.words.push(0x44332211);
            s.moved();
            0x44332211
        } else {
            s.get32(a)
        }
    }
    fn write8(&mut self, a: u32, value: u8) {
        self.0.lock().registers[a as usize] = if a == SOFTWARE_RESET { 0 } else { value };
    }
    fn write16(&mut self, a: u32, value: u16) {
        let mut s = self.0.lock();
        let stored = if a == CLOCK_CONTROL && value & CLK_INT_EN != 0 {
            value | CLK_INT_STABLE
        } else {
            value
        };
        s.registers[a as usize..a as usize + 2].copy_from_slice(&stored.to_le_bytes());
        if a != COMMAND {
            return;
        }
        let cmd = (value >> 8) as u8;
        let arg = s.get32(ARGUMENT);
        let mode = s.get16(TRANSFER_MODE);
        s.commands.push((cmd, arg, mode));
        if s.refuse_commands {
            s.set32(INT_STATUS, INT_ERROR | INT_TIMEOUT);
            return;
        }
        let status = s.get32(INT_STATUS) | INT_RESPONSE;
        s.set32(INT_STATUS, status);
        let response = match cmd {
            5 => 0xa0300000,
            3 => 0x12340000,
            52 => {
                let addr = ((arg >> 9) & 0x1ffff) as usize;
                if arg >> 31 != 0 {
                    s.common[addr] = arg as u8;
                    if addr == CCCR_IO_ENABLE as usize {
                        s.common[CCCR_IO_READY as usize] = arg as u8;
                    }
                }
                u32::from(s.common[addr])
            }
            53 if s.reject_data => 0x0200,
            _ => 0,
        };
        s.set32(RESPONSE, response);
        if value & CMD_DATA != 0 {
            s.left =
                usize::from(s.get16(BLOCK_SIZE)).div_ceil(4) * usize::from(s.get16(BLOCK_COUNT));
            s.set32(
                PRESENT_STATE,
                PS_CARD_PRESENT
                    | if mode & TRNS_READ != 0 {
                        PS_DATA_AVAIL
                    } else {
                        PS_SPACE_AVAIL
                    },
            );
        } else if value & CMD_RESP_MASK == CMD_RESP_SHORT_BUSY {
            let status = s.get32(INT_STATUS) | INT_DATA_END;
            s.set32(INT_STATUS, status);
        }
    }
    fn write32(&mut self, a: u32, value: u32) {
        let mut s = self.0.lock();
        if a == INT_STATUS {
            let new = s.get32(a) & !value;
            s.set32(a, new);
        } else if a == BUFFER {
            s.words.push(value);
            s.moved();
        } else {
            s.set32(a, value);
        }
    }
}
fn smoke_sdio_owned_card_enumeration_and_fifo() -> TestResult {
    let model = Model::new();
    let shared = model.0.clone();
    let mut card = match Card::initialize(model, Config::default()) {
        Ok(card) => card,
        Err(_) => return TestResult::Fail("card initialization failed"),
    };
    if card.host().rca != 0x1234
        || card.host().func_count != 2
        || card.host().current_clock_hz != 25_000_000
        || card
            .function(2)
            .map(|f| (f.vendor, f.device, f.max_block_size))
            != Some((0x02d0, 0xa9af, 512))
    {
        return TestResult::Fail("actual card response/CIS not retained");
    }
    if shared.lock().commands[..5]
        .iter()
        .map(|v| v.0)
        .collect::<Vec<_>>()
        != [0, 5, 5, 3, 7]
    {
        return TestResult::Fail("SDIO card command order differs");
    }
    if shared.lock().common[CCCR_IO_ENABLE as usize] != 0 {
        return TestResult::Fail("inherited functions remained enabled across host reset");
    }
    if card.cmd53_write(2, 0, &[1; 8]) != Err(SdioError::NotEnabled)
        || card.enable_func(2).is_err()
        || card.set_block_size(2, 512).is_err()
        || card.cmd53_block_write(2, 0, 512, 2, &[0x55; 1024]).is_err()
    {
        return TestResult::Fail("function enable/block PIO failed");
    }
    let mut data = [0; 8];
    if card.cmd53_read_fixed(2, 0, &mut data).is_err()
        || data != [0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44]
    {
        return TestResult::Fail("fixed FIFO read failed");
    }
    let s = shared.lock();
    let last = s.commands.last().unwrap();
    if last.0 != 53
        || last.1 & (1 << 26) != 0
        || last.1 & 511 != 8
        || s.common[0x210..0x212] != [0, 2]
        || last.2 & TRNS_DMA != 0
    {
        return TestResult::Fail("fixed CMD53/FBR or PIO flags differ");
    }
    drop(s);
    drop(card);
    let s = shared.lock();
    if s.get16(CLOCK_CONTROL) != 0 || s.registers[POWER_CONTROL as usize] != 0 {
        return TestResult::Fail("owned card drop did not power down");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/sdio/card",
    smoke_sdio_owned_card_enumeration_and_fifo
);

fn smoke_sdio_card_invalid_extent_and_r5_no_fifo() -> TestResult {
    let model = Model::new();
    let shared = model.0.clone();
    let mut card = match Card::initialize(model, Config::default()) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("init"),
    };
    if card.enable_func(1).is_err() {
        return TestResult::Fail("enable");
    }
    let before = shared.lock().commands.len();
    if card.cmd52_read(1, 0x20000) != Err(SdioError::AddressOverflow)
        || card.cmd53_write(1, 0x1ffff, &[1; 2]) != Err(SdioError::AddressOverflow)
        || card.cmd53_write(1, 0, &[1; 65]) != Err(SdioError::LengthOverflow)
        || shared.lock().commands.len() != before
    {
        return TestResult::Fail("invalid address reached command register");
    }
    shared.lock().reject_data = true;
    if card.cmd53_write(1, 0, &[1; 4]) != Err(SdioError::ResponseError(2))
        || !shared.lock().words.is_empty()
        || !card.is_failed()
    {
        return TestResult::Fail("R5 rejection touched FIFO or allowed reuse");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/sdio/card",
    smoke_sdio_card_invalid_extent_and_r5_no_fifo
);

fn smoke_sdio_card_cis_bounds_and_clock_limits() -> TestResult {
    let host = SdhciHost::new(0, SPEC_300 as u8, 50 << 8, 0);
    if host.clock_divisor(400_000) != 126
        || host.clock_divisor(12_000_000) != 6
        || host.calc_clk_div(12_000_000) != 0x300
    {
        return TestResult::Fail("v3 even clock divisor wrong");
    }
    let host = SdhciHost::new(0, SPEC_200 as u8, 50 << 8, 0);
    if host.clock_divisor(400_000) != 128 || host.clock_divisor(12_000_000) != 8 {
        return TestResult::Fail("v2 power-of-two divisor wrong");
    }
    let model = Model::new();
    let shared = model.0.clone();
    shared.lock().common[0x1000..0x1400].fill(0);
    if !matches!(Card::initialize(model, Config::default()), Err(Error::Cis)) {
        return TestResult::Fail("unterminated CIS accepted");
    }
    let s = shared.lock();
    if s.commands.len() > 1050 || s.registers[POWER_CONTROL as usize] != 0 {
        return TestResult::Fail("CIS work unbounded or failed init not powered down");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/sdio/card",
    smoke_sdio_card_cis_bounds_and_clock_limits
);

/// Isolated standard-register/CIS model for composed consumer denial tests.
/// No fixture identity is installed as a production platform profile.
pub fn initialized_fixture(identity: Option<crate::pio::HostIdentity>) -> (Card<Model>, Model) {
    let mut model = Model::new();
    model.1 = identity;
    let card =
        Card::initialize(model.clone(), Config::default()).expect("SDIO model initialization");
    (card, model)
}
impl Model {
    /// Fail every later published command at the controller completion.
    pub fn refuse_commands(&self) {
        self.0.lock().refuse_commands = true;
    }
    pub fn command_count(&self) -> usize {
        self.0.lock().commands.len()
    }
}

fn smoke_sdio_card_negotiates_four_bit_and_high_speed_like_linux() -> TestResult {
    // mmc_sdio_init_card on an sdhci-pci host: SHS card + CAN_DO_HISPD host
    // -> EHS + CTRL_HISPD + 50 MHz; then sdio_enable_wide -> CCCR_IF 4-bit +
    // CTRL_4BITBUS. Reserved CCCR_IF bits are preserved.
    let model = Model::new();
    let shared = model.0.clone();
    {
        let mut s = shared.lock();
        s.set32(
            CAPABILITIES,
            (50 << 8) | CAPS_CAN_VDD_330 | CAPS_CAN_DO_HISPD,
        );
        s.common[CCCR_HIGH_SPEED as usize] = HIGH_SPEED_SHS;
        s.common[CCCR_BUS_IFACE as usize] = BUS_IFACE_CD_DISABLE;
    }
    let config = Config {
        max_clock_hz: 50_000_000,
        ..Config::default()
    };
    let card = match Card::initialize(model, config) {
        Ok(card) => card,
        Err(_) => return TestResult::Fail("high-speed card initialization failed"),
    };
    {
        let s = shared.lock();
        if s.common[CCCR_HIGH_SPEED as usize] != HIGH_SPEED_SHS | HIGH_SPEED_EHS
            || s.common[CCCR_BUS_IFACE as usize] != BUS_IFACE_CD_DISABLE | BUS_IFACE_BW_4BIT
            || s.registers[HOST_CONTROL as usize] & (CTRL_HISPD | CTRL_4BITBUS)
                != CTRL_HISPD | CTRL_4BITBUS
        {
            return TestResult::Fail("card/host high-speed or 4-bit state differs from Linux");
        }
    }
    if card.host().current_clock_hz != 50_000_000
        || card.host().bus_width != 4
        || !card.host().high_speed
    {
        return TestResult::Fail("negotiated clock/width not retained");
    }
    // A low-speed card without 4BLS stays 1-bit; no HISPD host stays legacy.
    let model = Model::new();
    let shared = model.0.clone();
    {
        let mut s = shared.lock();
        s.common[CCCR_CARD_CAPABILITY as usize] = CARD_CAP_LSC;
        s.common[CCCR_HIGH_SPEED as usize] = HIGH_SPEED_SHS;
    }
    let card = match Card::initialize(model, Config::default()) {
        Ok(card) => card,
        Err(_) => return TestResult::Fail("legacy card initialization failed"),
    };
    let s = shared.lock();
    if s.common[CCCR_BUS_IFACE as usize] & BUS_IFACE_BW_MASK != BUS_IFACE_BW_1BIT
        || s.common[CCCR_HIGH_SPEED as usize] & HIGH_SPEED_EHS != 0
        || s.registers[HOST_CONTROL as usize] & (CTRL_HISPD | CTRL_4BITBUS) != 0
        || card.host().bus_width != 1
        || card.host().current_clock_hz != 25_000_000
    {
        return TestResult::Fail("low-speed/no-HISPD card was widened or sped up");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/sdio/card",
    smoke_sdio_card_negotiates_four_bit_and_high_speed_like_linux
);

#[derive(Clone, Default)]
struct FakeLine(alloc::sync::Arc<core::sync::atomic::AtomicU32>);
impl crate::card::InterruptLine for FakeLine {
    fn unmask(&self) {
        self.0.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    }
}
fn smoke_sdio_card_interrupt_claim_enables_cccr_and_sdhci_like_linux() -> TestResult {
    use core::sync::atomic::{AtomicU32, Ordering};
    let model = Model::new();
    let shared = model.0.clone();
    let mut card = match Card::initialize(model, Config::default()) {
        Ok(card) => card,
        Err(_) => return TestResult::Fail("card initialization failed"),
    };
    // No platform line: claim reports polling and touches nothing.
    if card.enable_card_interrupt(0b110, alloc::sync::Arc::new(|| {})) != Ok(false)
        || shared.lock().common[CCCR_INT_ENABLE as usize] != 0
    {
        return TestResult::Fail("claim without a line changed the card");
    }
    let line = FakeLine::default();
    let subscriber = alloc::sync::Arc::new(crate::card::Subscriber::default());
    if !card.attach_interrupt(alloc::boxed::Box::new(line.clone()), subscriber.clone()) {
        return TestResult::Fail("model registers refused INTx");
    }
    // Bit 0 is the master enable; function 3 does not exist on this card.
    if card.enable_card_interrupt(0b1, alloc::sync::Arc::new(|| {})) != Err(SdioError::BadFunction)
        || card.enable_card_interrupt(0b1000, alloc::sync::Arc::new(|| {}))
            != Err(SdioError::BadFunction)
    {
        return TestResult::Fail("invalid function interrupt claim accepted");
    }
    static WAKES: AtomicU32 = AtomicU32::new(0);
    let notify = alloc::sync::Arc::new(|| {
        WAKES.fetch_add(1, Ordering::AcqRel);
    });
    if card.enable_card_interrupt(0b110, notify) != Ok(true) {
        return TestResult::Fail("card interrupt claim failed");
    }
    {
        let s = shared.lock();
        // sdio_claim_irq: IENM | IEN1 | IEN2; sdhci_enable_sdio_irq.
        if s.common[CCCR_INT_ENABLE as usize] != 0b111
            || s.get32(INT_ENABLE) & INT_CARD_INT == 0
            || s.get32(SIGNAL_ENABLE) != INT_CARD_INT
        {
            return TestResult::Fail("CCCR/SDHCI card-interrupt enables differ from Linux");
        }
    }
    if line.0.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("claim did not unmask the line");
    }
    subscriber.notify();
    if WAKES.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("line delivery did not reach the function driver");
    }
    card.rearm_card_interrupt();
    if line.0.load(Ordering::Acquire) != 2 {
        return TestResult::Fail("rearm did not unmask the line");
    }
    drop(card);
    let s = shared.lock();
    if s.get32(SIGNAL_ENABLE) != 0 || s.get32(INT_ENABLE) != 0 {
        return TestResult::Fail("dropped card left interrupt signalling enabled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/sdio/card",
    smoke_sdio_card_interrupt_claim_enables_cccr_and_sdhci_like_linux
);

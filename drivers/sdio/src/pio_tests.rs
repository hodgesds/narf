use super::*;
use alloc::{collections::VecDeque, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Model {
    bytes: [u8; 256],
    reads: VecDeque<u32>,
    writes: Vec<(u32, usize, u32)>,
    fifo: Vec<u32>,
    left: usize,
    early_end: bool,
    crc: bool,
    stall: bool,
}
impl Model {
    fn new() -> Self {
        let mut bytes = [0; 256];
        bytes[INT_STATUS as usize..INT_STATUS as usize + 4]
            .copy_from_slice(&INT_CARD_INT.to_le_bytes());
        Self {
            bytes,
            reads: VecDeque::new(),
            writes: Vec::new(),
            fifo: Vec::new(),
            left: 0,
            early_end: false,
            crc: false,
            stall: false,
        }
    }
    fn set32(&mut self, a: u32, v: u32) {
        self.bytes[a as usize..a as usize + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn get32(&self, a: u32) -> u32 {
        u32::from_le_bytes(self.bytes[a as usize..a as usize + 4].try_into().unwrap())
    }
    fn moved(&mut self) {
        self.left -= 1;
        if self.left == 0 {
            self.set32(PRESENT_STATE, 0);
            self.set32(INT_STATUS, self.get32(INT_STATUS) | INT_DATA_END);
        }
    }
}
impl Registers for Model {
    fn read8(&mut self, a: u32) -> u8 {
        self.bytes[a as usize]
    }
    fn read16(&mut self, a: u32) -> u16 {
        u16::from_le_bytes(self.bytes[a as usize..a as usize + 2].try_into().unwrap())
    }
    fn read32(&mut self, a: u32) -> u32 {
        if a == BUFFER {
            let word = self.reads.pop_front().unwrap();
            self.moved();
            word
        } else {
            self.get32(a)
        }
    }
    fn write8(&mut self, a: u32, v: u8) {
        self.writes.push((a, 1, u32::from(v)));
        self.bytes[a as usize] = v;
    }
    fn write16(&mut self, a: u32, v: u16) {
        self.writes.push((a, 2, u32::from(v)));
        self.bytes[a as usize..a as usize + 2].copy_from_slice(&v.to_le_bytes());
        if a != COMMAND || self.stall {
            return;
        }
        self.set32(INT_STATUS, self.get32(INT_STATUS) | INT_RESPONSE);
        if self.crc {
            self.set32(INT_STATUS, self.get32(INT_STATUS) | INT_ERROR | INT_CRC);
            return;
        }
        if v & CMD_DATA != 0 {
            let block = self.read16(BLOCK_SIZE) as usize;
            let count = self.read16(BLOCK_COUNT) as usize;
            self.left = block.div_ceil(4) * count;
            let read = self.read16(TRANSFER_MODE) & TRNS_READ != 0;
            if self.early_end {
                self.set32(INT_STATUS, self.get32(INT_STATUS) | INT_DATA_END);
            } else {
                self.set32(
                    PRESENT_STATE,
                    if read { PS_DATA_AVAIL } else { PS_SPACE_AVAIL },
                );
            }
        } else if v & CMD_RESP_MASK == CMD_RESP_SHORT_BUSY {
            self.set32(INT_STATUS, self.get32(INT_STATUS) | INT_DATA_END);
        }
    }
    fn write32(&mut self, a: u32, v: u32) {
        self.writes.push((a, 4, v));
        if a == INT_STATUS {
            self.set32(a, self.get32(a) & !v);
        } else if a == BUFFER {
            self.fifo.push(v);
            self.moved();
        } else {
            self.set32(a, v);
        }
    }
}

fn smoke_sdhci_pio_exact_command_width_flags_and_tails() -> TestResult {
    let mut io = Model::new();
    io.reads
        .extend([0x44332211, 0xaa776655, 0x88776655, 0xbbccbbaa]);
    let mut controller = Controller::new(io);
    let mut bytes = [0; 14];
    assert_eq!(
        controller.execute(
            53,
            0x12345678,
            Response::Short,
            Some(Data::Read {
                bytes: &mut bytes,
                block_size: 7
            })
        ),
        Ok(0)
    );
    assert_eq!(
        bytes,
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x55, 0x66, 0x77, 0x88, 0xaa, 0xbb, 0xcc]
    );
    assert_eq!(controller.io.get32(INT_STATUS), INT_CARD_INT);
    assert!(controller.io.writes.contains(&(
        TRANSFER_MODE,
        2,
        u32::from(TRNS_BLK_CNT_EN | TRNS_READ | TRNS_MULTI)
    )));
    assert!(controller.io.writes.contains(&(
        COMMAND,
        2,
        u32::from(make_cmd(
            53,
            CMD_RESP_SHORT | CMD_CRC | CMD_INDEX | CMD_DATA
        ))
    )));
    assert_eq!(
        controller.execute(
            53,
            0,
            Response::Short,
            Some(Data::Write {
                bytes: &bytes[..7],
                block_size: 7
            })
        ),
        Ok(0)
    );
    assert_eq!(controller.io.fifo, vec![0x44332211, 0x00776655]);
    assert_eq!(controller.execute(5, 0, Response::R4, None), Ok(0));
    assert_eq!(controller.io.read16(COMMAND), make_cmd(5, CMD_RESP_SHORT));
    assert_eq!(
        controller.execute(7, 0x12340000, Response::Busy, None),
        Ok(0)
    );
    assert_eq!(controller.io.get32(INT_STATUS), INT_CARD_INT);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/sdio/pio",
    smoke_sdhci_pio_exact_command_width_flags_and_tails
);

fn smoke_sdhci_pio_failure_is_terminal() -> TestResult {
    for kind in 0..3 {
        let mut io = Model::new();
        io.crc = kind == 0;
        io.early_end = kind == 1;
        io.stall = kind == 2;
        let mut controller = Controller::new(io);
        let bytes = [1; 7];
        assert!(controller
            .execute(
                53,
                0,
                Response::Short,
                Some(Data::Write {
                    bytes: &bytes,
                    block_size: 7
                })
            )
            .is_err());
        assert!(controller.is_failed());
        assert!(controller.io.fifo.is_empty());
        let before = controller.io.writes.len();
        assert_eq!(
            controller.execute(52, 0, Response::Short, None),
            Err(Error::Failed)
        );
        assert_eq!(controller.io.writes.len(), before);
    }
    let mut controller = Controller::new(Model::new());
    for block in [0, 3, 513] {
        assert_eq!(
            controller.execute(
                53,
                0,
                Response::Short,
                Some(Data::Write {
                    bytes: &[1; 8],
                    block_size: block
                })
            ),
            Err(Error::Invalid)
        );
    }
    assert!(controller.io.writes.is_empty());
    assert!(!controller.is_failed());
    TestResult::Pass
}
kernel_test_in!("drivers/sdio/pio", smoke_sdhci_pio_failure_is_terminal);

//! SDHCI DMA model: a register file whose COMMAND write runs the selected
//! DMA engine against real `narf_io` buffers (identity bus addresses),
//! walking the ADMA2 table the controller built.

use super::*;
use crate::pio::{Controller, Error, Response};
use crate::sdhci::adma::{ATTR_NOP_END_VALID, ATTR_TRAN_VALID};
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Model {
    bytes: [u8; 256],
    writes: Vec<(u32, usize, u32)>,
    /// Bytes the card returns for a read / received for a write.
    card_rx: Vec<u8>,
    card_tx: Vec<u8>,
    grant: bool,
    granted: u32,
    bus_master: bool,
    adma_fail: bool,
    r5_error: bool,
    /// SDMA: raise one boundary interrupt before completing.
    boundary_once: bool,
    /// TRAN descriptors the engine walked: (len, addr).
    walked: Vec<(usize, u64)>,
}
impl Model {
    fn new() -> Self {
        Self {
            bytes: [0; 256],
            writes: Vec::new(),
            card_rx: Vec::new(),
            card_tx: Vec::new(),
            grant: true,
            granted: 0,
            bus_master: false,
            adma_fail: false,
            r5_error: false,
            boundary_once: false,
            walked: Vec::new(),
        }
    }
    fn set32(&mut self, a: u32, v: u32) {
        self.bytes[a as usize..a as usize + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn get32(&self, a: u32) -> u32 {
        u32::from_le_bytes(self.bytes[a as usize..a as usize + 4].try_into().unwrap())
    }
    fn get16(&self, a: u32) -> u16 {
        u16::from_le_bytes(self.bytes[a as usize..a as usize + 2].try_into().unwrap())
    }
    fn raise(&mut self, bits: u32) {
        self.set32(INT_STATUS, self.get32(INT_STATUS) | bits);
    }
    fn memory(addr: u64, len: usize) -> &'static mut [u8] {
        // SAFETY: identity bus addresses of live narf_io buffers owned by
        // the controller under test; the model runs synchronously inside
        // its COMMAND write, as the device would between doorbell and
        // completion.
        unsafe {
            core::slice::from_raw_parts_mut(
                narf_memory::PhysAddr::new(addr).kernel_mut_ptr::<u8>(),
                len,
            )
        }
    }
    fn move_bytes(&mut self, addr: u64, len: usize, read: bool) {
        let memory = Self::memory(addr, len);
        if read {
            let source: Vec<u8> = self.card_rx.drain(..len).collect();
            memory.copy_from_slice(&source);
        } else {
            self.card_tx.extend_from_slice(memory);
        }
    }
    fn run_dma(&mut self, read: bool, total: usize) {
        let select = self.bytes[HOST_CONTROL as usize] & CTRL_DMA_MASK;
        if select == CTRL_SDMA {
            let addr = u64::from(self.get32(DMA_ADDRESS));
            if self.boundary_once {
                self.boundary_once = false;
                self.raise(INT_DMA_END);
            }
            self.walked.push((total, addr));
            self.move_bytes(addr, total, read);
            self.raise(INT_DATA_END);
            return;
        }
        let desc_size = if select == CTRL_ADMA64 { 12 } else { 8 };
        let mut at = u64::from(self.get32(ADMA_ADDRESS));
        if select == CTRL_ADMA64 {
            at |= u64::from(self.get32(ADMA_ADDRESS_HI)) << 32;
        }
        for _ in 0..crate::sdhci::adma::TABLE_COUNT {
            let raw = Self::memory(at, desc_size).to_vec();
            let (attr, len, addr) = crate::sdhci::adma::read_desc(&raw, 0, desc_size).unwrap();
            if self.adma_fail {
                self.set32(ADMA_ERROR, 0x5);
                self.raise(INT_ERROR | INT_ADMA_ERROR);
                return;
            }
            if attr & 0x1 == 0 {
                break;
            }
            if attr & 0x30 == 0x20 {
                let len = if len == 0 { 65536 } else { usize::from(len) };
                self.walked.push((len, addr));
                self.move_bytes(addr, len, read);
            }
            if attr & 0x2 != 0 {
                break;
            }
            at += desc_size as u64;
        }
        self.raise(INT_DATA_END);
    }
}
impl crate::pio::Registers for Model {
    fn read8(&mut self, a: u32) -> u8 {
        self.bytes[a as usize]
    }
    fn read16(&mut self, a: u32) -> u16 {
        self.get16(a)
    }
    fn read32(&mut self, a: u32) -> u32 {
        self.get32(a)
    }
    fn write8(&mut self, a: u32, v: u8) {
        self.writes.push((a, 1, u32::from(v)));
        // Resets complete immediately.
        self.bytes[a as usize] = if a == SOFTWARE_RESET { 0 } else { v };
    }
    fn write16(&mut self, a: u32, v: u16) {
        self.writes.push((a, 2, u32::from(v)));
        self.bytes[a as usize..a as usize + 2].copy_from_slice(&v.to_le_bytes());
        if a != COMMAND {
            return;
        }
        self.set32(RESPONSE, if self.r5_error { 0x0000_4000 } else { 0x1000 });
        self.raise(INT_RESPONSE);
        let mode = self.get16(TRANSFER_MODE);
        if v & CMD_DATA != 0 && mode & TRNS_DMA != 0 && !self.r5_error {
            let total =
                usize::from(self.get16(BLOCK_SIZE) & 0xfff) * usize::from(self.get16(BLOCK_COUNT));
            self.run_dma(mode & TRNS_READ != 0, total);
        }
    }
    fn write32(&mut self, a: u32, v: u32) {
        self.writes.push((a, 4, v));
        if a == INT_STATUS {
            self.set32(a, self.get32(a) & !v);
        } else {
            self.set32(a, v);
        }
    }
    fn enable_dma(&mut self) -> Option<narf_io::DmaDevice> {
        self.granted += 1;
        if !self.grant {
            return None;
        }
        self.bus_master = true;
        Some(narf_io::DmaDevice::coherent())
    }
    fn disable_dma(&mut self) -> bool {
        self.bus_master = false;
        true
    }
}

const ADMA_CAPS: u32 = CAPS_CAN_DO_ADMA2 | CAPS_CAN_DO_SDMA;

fn wrote(model: &Model, offset: u32, value: u32) -> bool {
    model
        .writes
        .iter()
        .any(|&(a, _, v)| a == offset && v == value)
}

fn smoke_sdhci_adma2_bounce_write_and_read() -> TestResult {
    let mut controller = Controller::new(Model::new());
    if controller.setup_dma(SPEC_300 as u8, ADMA_CAPS) != Some(Mode::Adma32)
        || !controller.registers().bus_master
    {
        return TestResult::Fail("ADMA2 not admitted with a bus-master grant");
    }
    let engine = controller.dma_engine().unwrap();
    let (bounce, table) = (engine.bounce_addr(), engine.table_addr().unwrap());
    let payload: Vec<u8> = (0..1536u32).map(|i| (i * 7) as u8).collect();
    let argument = crate::sdhci::cmd::cmd53_arg(true, 2, true, true, 0x8000, 3);
    if controller.execute(
        53,
        argument,
        Response::R5,
        Some(Data::Write {
            bytes: &payload,
            block_size: 512,
        }),
    ) != Ok(0x1000)
    {
        return TestResult::Fail("ADMA2 block write failed");
    }
    let io = controller.registers();
    if io.card_tx != payload || io.walked != vec![(1536, bounce)] {
        return TestResult::Fail("device did not receive the bounced payload");
    }
    if !wrote(io, ADMA_ADDRESS, table as u32)
        || io.bytes[HOST_CONTROL as usize] & CTRL_DMA_MASK != CTRL_ADMA32
        || !wrote(io, BLOCK_SIZE, u32::from(make_blksz(7, 512)))
        || !wrote(
            io,
            TRANSFER_MODE,
            u32::from(TRNS_BLK_CNT_EN | TRNS_MULTI | TRNS_DMA),
        )
    {
        return TestResult::Fail("ADMA address/select/boundary/transfer mode not programmed");
    }
    let engine = controller.dma_engine().unwrap();
    if engine.descriptor(0) != Some((ATTR_TRAN_VALID, 1536, bounce))
        || engine.descriptor(1) != Some((ATTR_NOP_END_VALID, 0, 0))
        || engine.armed().is_some()
    {
        return TestResult::Fail("descriptor table or completion state wrong");
    }
    let reply: Vec<u8> = (0..1024u32).map(|i| (i ^ 0x5a) as u8).collect();
    controller.registers().card_rx = reply.clone();
    let mut bytes = vec![0u8; 1024];
    let argument = crate::sdhci::cmd::cmd53_arg(false, 2, true, false, 0x8000, 2);
    if controller.execute(
        53,
        argument,
        Response::R5,
        Some(Data::Read {
            bytes: &mut bytes,
            block_size: 512,
        }),
    ) != Ok(0x1000)
        || bytes != reply
    {
        return TestResult::Fail("ADMA2 read not copied out of the bounce buffer");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/sdio/dma", smoke_sdhci_adma2_bounce_write_and_read);

fn smoke_sdhci_dma_sync_direction_follows_request() -> TestResult {
    let mut model = Model::new();
    let Ok(mut engine) = Engine::new(&narf_io::DmaDevice::coherent(), Mode::Adma32) else {
        return TestResult::Fail("engine allocation");
    };
    let mut buffer = [0u8; 64];
    if engine
        .prepare(
            &mut model,
            &Data::Read {
                bytes: &mut buffer,
                block_size: 64,
            },
        )
        .is_err()
        || engine.armed() != Some((64, DmaDirection::FromDevice))
    {
        return TestResult::Fail("read not handed to the device FROM_DEVICE");
    }
    engine.disarm();
    if engine
        .prepare(
            &mut model,
            &Data::Write {
                bytes: &[1; 32],
                block_size: 32,
            },
        )
        .is_err()
        || engine.armed() != Some((32, DmaDirection::ToDevice))
    {
        return TestResult::Fail("write not handed to the device TO_DEVICE");
    }
    let mut data = Data::Write {
        bytes: &[1; 32],
        block_size: 32,
    };
    engine.complete(&mut data);
    if engine.armed().is_some() {
        return TestResult::Fail("completion did not return the buffer to the CPU");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/sdio/dma",
    smoke_sdhci_dma_sync_direction_follows_request
);

fn smoke_sdhci_adma_error_resets_and_falls_back_to_pio() -> TestResult {
    let mut controller = Controller::new(Model::new());
    if controller.setup_dma(SPEC_300 as u8, ADMA_CAPS).is_none() {
        return TestResult::Fail("ADMA2 not admitted");
    }
    controller.registers().adma_fail = true;
    let argument = crate::sdhci::cmd::cmd53_arg(true, 2, true, true, 0x8000, 1);
    if controller.execute(
        53,
        argument,
        Response::R5,
        Some(Data::Write {
            bytes: &[0xa5; 512],
            block_size: 512,
        }),
    ) != Err(Error::Dma(0x5))
    {
        return TestResult::Fail("ADMA error not reported with its status");
    }
    let io = controller.registers();
    if !wrote(io, SOFTWARE_RESET, u32::from(RESET_CMD | RESET_DATA)) || io.bus_master {
        return TestResult::Fail("ADMA error did not reset CMD/DATA and revoke bus mastering");
    }
    if controller.dma_mode().is_some()
        || !controller.is_failed()
        || controller.setup_dma(SPEC_300 as u8, ADMA_CAPS).is_some()
        || controller.registers().granted != 1
    {
        return TestResult::Fail("faulted owner did not latch PIO-only");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/sdio/dma",
    smoke_sdhci_adma_error_resets_and_falls_back_to_pio
);

fn smoke_sdhci_dma_r5_rejection_resets_without_copy() -> TestResult {
    let mut controller = Controller::new(Model::new());
    if controller.setup_dma(SPEC_300 as u8, ADMA_CAPS).is_none() {
        return TestResult::Fail("ADMA2 not admitted");
    }
    controller.registers().r5_error = true;
    let mut bytes = [0x11u8; 512];
    let argument = crate::sdhci::cmd::cmd53_arg(false, 2, true, false, 0x8000, 1);
    let result = controller.execute(
        53,
        argument,
        Response::R5,
        Some(Data::Read {
            bytes: &mut bytes,
            block_size: 512,
        }),
    );
    if !matches!(result, Err(Error::Card(_)))
        || bytes != [0x11; 512]
        || !wrote(
            controller.registers(),
            SOFTWARE_RESET,
            u32::from(RESET_CMD | RESET_DATA),
        )
        || controller.dma_mode().is_some()
    {
        return TestResult::Fail("R5 rejection under DMA copied data or skipped the reset");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/sdio/dma",
    smoke_sdhci_dma_r5_rejection_resets_without_copy
);

fn smoke_sdhci_dma_admission_keeps_pio_without_caps_or_grant() -> TestResult {
    let mut controller = Controller::new(Model::new());
    if controller.setup_dma(SPEC_300 as u8, 0).is_some() || controller.registers().granted != 0 {
        return TestResult::Fail("host without DMA capability asked for a grant");
    }
    if controller
        .setup_dma(SPEC_300 as u8, CAPS_CAN_DO_SDMA | CAPS_CAN_64BIT)
        .is_some()
        || controller.registers().granted != 0
    {
        return TestResult::Fail("64-bit SDMA without v4 mode admitted");
    }
    let mut model = Model::new();
    model.grant = false;
    let mut controller = Controller::new(model);
    if controller.setup_dma(SPEC_300 as u8, ADMA_CAPS).is_some()
        || controller.registers().granted != 1
        || controller.registers().bus_master
    {
        return TestResult::Fail("refused platform grant did not keep PIO");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/sdio/dma",
    smoke_sdhci_dma_admission_keeps_pio_without_caps_or_grant
);

fn smoke_sdhci_sdma_boundary_restart_and_64bit_adma() -> TestResult {
    let mut model = Model::new();
    model.boundary_once = true;
    let mut controller = Controller::new(model);
    if controller.setup_dma(SPEC_100 as u8, ADMA_CAPS) != Some(Mode::Sdma) {
        return TestResult::Fail("spec 1.00 host did not select SDMA");
    }
    let bounce = controller.dma_engine().unwrap().bounce_addr();
    let payload = [0x3cu8; 256];
    let argument = crate::sdhci::cmd::cmd53_arg(true, 1, false, true, 0x100, 256);
    if controller.execute(
        53,
        argument,
        Response::R5,
        Some(Data::Write {
            bytes: &payload,
            block_size: 256,
        }),
    ) != Ok(0x1000)
    {
        return TestResult::Fail("SDMA write failed");
    }
    let next = (bounce & !(DEFAULT_BOUNDARY_SIZE - 1)) + DEFAULT_BOUNDARY_SIZE;
    let io = controller.registers();
    if !wrote(io, DMA_ADDRESS, bounce as u32)
        || !wrote(io, DMA_ADDRESS, next as u32)
        || io.card_tx[..] != payload[..]
        || io.bytes[HOST_CONTROL as usize] & CTRL_DMA_MASK != CTRL_SDMA
    {
        return TestResult::Fail("SDMA address or boundary restart wrong");
    }
    let mut controller = Controller::new(Model::new());
    if controller.setup_dma(SPEC_300 as u8, ADMA_CAPS | CAPS_CAN_64BIT) != Some(Mode::Adma64) {
        return TestResult::Fail("64-bit host did not select ADMA64");
    }
    let mut bytes = [0u8; 64];
    controller.registers().card_rx = vec![0x77; 64];
    let argument = crate::sdhci::cmd::cmd53_arg(false, 1, false, true, 0x100, 64);
    if controller.execute(
        53,
        argument,
        Response::R5,
        Some(Data::Read {
            bytes: &mut bytes,
            block_size: 64,
        }),
    ) != Ok(0x1000)
        || bytes != [0x77; 64]
        || controller.registers().bytes[HOST_CONTROL as usize] & CTRL_DMA_MASK != CTRL_ADMA64
    {
        return TestResult::Fail("ADMA64 byte-mode read failed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/sdio/dma",
    smoke_sdhci_sdma_boundary_restart_and_64bit_adma
);

use super::*;
use alloc::{
    collections::{BTreeMap, VecDeque},
    vec,
    vec::Vec,
};
use narf_kernel_test::{kernel_test_in, TestResult};
const CORE: u32 = 0x18011000;
#[derive(Default)]
struct Host {
    window: u32,
    words: BTreeMap<u32, u32>,
    ops: Vec<(u8, u8, u32, usize)>,
    rx: VecDeque<u8>,
    enabled: u8,
    fail_write: bool,
    reassert_change: bool,
}
impl SdioFunction for Host {
    fn cmd52_read(&mut self, f: u8, a: u32) -> Result<u8, SdioError> {
        self.ops.push((52, f, a, 0));
        Ok(0)
    }
    fn cmd52_write(&mut self, f: u8, a: u32, v: u8) -> Result<(), SdioError> {
        self.ops.push((52, f, a, 1));
        let shift = match a {
            0x1000a => Some(8),
            0x1000b => Some(16),
            0x1000c => Some(24),
            _ => None,
        };
        if let Some(shift) = shift {
            self.window = (self.window & !(255 << shift)) | (u32::from(v) << shift);
        }
        Ok(())
    }
    fn cmd53_read(&mut self, f: u8, a: u32, b: &mut [u8]) -> Result<(), SdioError> {
        self.ops.push((53, f, a, b.len()));
        if f != 1 || a & 0x8000 == 0 || b.len() != 4 {
            return Err(SdioError::HostError);
        }
        b.copy_from_slice(
            &self
                .words
                .get(&(self.window | (a & 0x7fff)))
                .copied()
                .unwrap_or(0)
                .to_le_bytes(),
        );
        Ok(())
    }
    fn cmd53_write(&mut self, f: u8, a: u32, b: &[u8]) -> Result<(), SdioError> {
        self.ops.push((53, f, a, b.len()));
        if self.fail_write {
            return Err(SdioError::HostError);
        }
        if f == 1 && b.len() == 4 && a & 0x8000 != 0 {
            let address = self.window | (a & 0x7fff);
            let value = u32::from_le_bytes(b.try_into().unwrap());
            if address == CORE + 0x20 {
                let old = self.words.get(&address).copied().unwrap_or(0);
                let raced = if value == 0x20 && self.reassert_change {
                    0x20
                } else {
                    0
                };
                self.words.insert(address, (old & !value) | raced);
            } else {
                self.words.insert(address, value);
            }
        }
        Ok(())
    }
    fn cmd53_read_fixed(&mut self, f: u8, a: u32, b: &mut [u8]) -> Result<(), SdioError> {
        self.ops.push((54, f, a, b.len()));
        if f != 2 || a != 0x8000 {
            return Err(SdioError::HostError);
        }
        for byte in b {
            *byte = self.rx.pop_front().unwrap_or(0);
        }
        Ok(())
    }
    fn cmd53_block_read(
        &mut self,
        _: u8,
        _: u32,
        _: u16,
        _: u16,
        _: &mut [u8],
    ) -> Result<(), SdioError> {
        Err(SdioError::Unsupported)
    }
    fn cmd53_block_write(
        &mut self,
        _: u8,
        _: u32,
        _: u16,
        _: u16,
        _: &[u8],
    ) -> Result<(), SdioError> {
        Err(SdioError::Unsupported)
    }
    fn enable_func(&mut self, f: u8) -> Result<(), SdioError> {
        self.enabled |= 1 << f;
        Ok(())
    }
    fn set_block_size(&mut self, f: u8, size: u16) -> Result<(), SdioError> {
        self.ops.push((55, f, 0, usize::from(size)));
        Ok(())
    }
}
fn smoke_cyw_sdio_bridge_real_backplane_and_burst() -> TestResult {
    let mut transport = SdioTransport::new(Host::default());
    if transport.prepare().is_err()
        || transport.write_backplane(CORE + 0x48, 0x12345678).is_err()
        || transport.read_backplane(CORE + 0x48) != Ok(0x12345678)
    {
        return TestResult::Fail("backplane CMD53 register access failed");
    }
    if transport.func.words.get(&(CORE + 0x48)) != Some(&0x12345678)
        || !transport.func.ops.contains(&(53, 1, 0x9048, 4))
    {
        return TestResult::Fail("backplane word flag/window missing");
    }
    transport.func.ops.clear();
    if transport
        .write_burst(Function::Backplane, 0, &[1; 1025])
        .is_err()
        || transport.func.ops.len() != 17
        || transport.func.ops[0] != (53, 1, 0, 64)
        || transport.func.ops[15] != (53, 1, 960, 64)
        || transport.func.ops[16] != (53, 1, 1024, 1)
        || transport.func.ops.iter().any(|op| op.3 > 64)
    {
        return TestResult::Fail("RAM burst not split within host byte count");
    }
    if transport.func.enabled != 2 {
        return TestResult::Fail("F1 preparation enabled wrong function");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/sdio_bridge",
    smoke_cyw_sdio_bridge_real_backplane_and_burst
);

fn smoke_cyw_sdio_fifo_readiness_padding_and_flow() -> TestResult {
    let mut transport = SdioTransport::new(Host::default());
    if transport.prepare().is_err() || transport.initialize_packets(CORE).is_err() {
        return TestResult::Fail("packet init");
    }
    let mut bytes = vec![0; super::super::runtime::MAX_PACKET];
    if transport.receive_packet(&mut bytes) != Ok(0) || transport.func.ops.iter().any(|v| v.0 == 54)
    {
        return TestResult::Fail("empty RX performed a FIFO command");
    }
    let mut frame = vec![0x55; 600];
    frame[..4].copy_from_slice(&[0x58, 2, 0xa7, 0xfd]);
    transport.func.rx.extend(frame.iter().copied());
    transport.func.words.insert(CORE + 0x20, 1 << 6);
    if transport.receive_packet(&mut bytes) != Ok(600) || bytes[..600] != frame {
        return TestResult::Fail("F2 header/remainder copied wrong extent");
    }
    if transport
        .func
        .ops
        .iter()
        .filter(|v| v.0 == 54)
        .copied()
        .collect::<Vec<_>>()
        != vec![
            (54, 2, 0x8000, 64),
            (54, 2, 0x8000, 512),
            (54, 2, 0x8000, 24),
        ]
    {
        return TestResult::Fail("RX did not use bounded fixed-address commands");
    }
    if transport.receive_packet(&mut bytes) != Ok(0) || transport.rx_pending {
        return TestResult::Fail("zero header did not drain indication");
    }
    transport.func.words.insert(CORE + 0x20, 0x30);
    let before = transport.func.ops.iter().filter(|v| v.1 == 2).count();
    if transport.transmit_packet(&frame) != Err(TransportError::Busy)
        || transport.failed
        || transport.func.ops.iter().filter(|v| v.1 == 2).count() != before
    {
        return TestResult::Fail("global flow control submitted data or poisoned retry");
    }
    transport.func.words.insert(CORE + 0x20, 0x20);
    transport.func.reassert_change = true;
    if transport.transmit_packet(&frame) != Err(TransportError::Busy)
        || transport.failed
        || transport.func.ops.iter().filter(|v| v.1 == 2).count() != before
    {
        return TestResult::Fail("raced flow-change ACK allowed FIFO TX before debounce");
    }
    transport.func.reassert_change = false;
    if transport.transmit_packet(&frame).is_err() {
        return TestResult::Fail("unblocked packet not sent");
    }
    let tx = transport
        .func
        .ops
        .iter()
        .filter(|v| v.0 == 53 && v.1 == 2)
        .copied()
        .collect::<Vec<_>>();
    if tx != vec![(53, 2, 0x8000, 512), (53, 2, 0x8200, 88)] {
        return TestResult::Fail("TX incremental CMD53 extent differs from Linux");
    }
    transport.func.fail_write = true;
    if transport.transmit_packet(&frame).is_ok() || !transport.failed {
        return TestResult::Fail("ambiguous TX failure permitted replay");
    }
    let count = transport.func.ops.len();
    if transport.transmit_packet(&frame) != Err(TransportError::NotReady)
        || transport.func.ops.len() != count
    {
        return TestResult::Fail("failed FIFO owner reused");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/sdio_bridge",
    smoke_cyw_sdio_fifo_readiness_padding_and_flow
);

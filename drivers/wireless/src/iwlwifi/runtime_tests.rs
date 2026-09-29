use super::*;
use crate::iwlwifi::{regs, transport};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Default)]
struct Mmio {
    writes: Vec<(u32, u32)>,
}
impl IwlMmio for Mmio {
    fn read(&mut self, _: u32) -> u32 {
        0
    }
    fn write(&mut self, register: u32, value: u32) {
        self.writes.push((register, value));
    }
}

fn smoke_ax210_peripheral_write_width() -> TestResult {
    let mut mmio = Mmio::default();
    transport::prph_write_ax210(&mut mmio, 0xd05c04, 1 << 20);
    if mmio.writes.as_slice()
        != [
            (regs::HBUS_TARG_PRPH_WADDR, 0x03d05c04),
            (regs::HBUS_TARG_PRPH_WDAT, 1 << 20),
        ]
    {
        return TestResult::Fail("PNVM doorbell requires a 32-bit peripheral write");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/runtime",
    smoke_ax210_peripheral_write_width
);

fn smoke_command_dma_lifecycle() -> TestResult {
    let mut q = CommandQueue::new().unwrap();
    let mut mmio = Mmio::default();
    let sequence = q.send(&mut mmio, 1, 0x0d, 18, &[7; 64]).unwrap();
    let mut header = rx::RxPacketHeader {
        len_n_flags: 4,
        cmd: 0x0d,
        group_id: 1,
        sequence: sequence | 0x8000,
    };
    if q.complete(header) != Ok(false) || q.pending[0].is_none() {
        return TestResult::Fail("notification freed command DMA");
    }
    header.sequence = sequence;
    header.cmd = 0x0e;
    if q.complete(header).is_ok() || q.pending[0].is_none() {
        return TestResult::Fail("wrong command reclaimed DMA");
    }
    header.cmd = 0x0d;
    if q.complete(header) != Ok(true) || q.pending[0].is_some() || q.complete(header).is_ok() {
        return TestResult::Fail("command reclaim lifecycle");
    }
    // Hardware pointer wraps at 65536, DMA slot at 128, response at 256.
    q.write = u16::MAX;
    let sequence = q.send(&mut mmio, 1, 0x0d, 18, &[]).unwrap();
    if sequence != 255 || q.pending[127].is_none() || q.write != 0 {
        return TestResult::Fail("command index wrap");
    }
    header.sequence = 255;
    if q.complete(header) != Ok(true) {
        return TestResult::Fail("wrapped response");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/runtime",
    smoke_command_dma_lifecycle
);

fn smoke_command_queue_backpressure() -> TestResult {
    let mut q = CommandQueue::new().unwrap();
    let mut mmio = Mmio::default();
    for _ in 0..COMMAND_DEPTH - 1 {
        q.send(&mut mmio, 1, 8, 1, &[]).unwrap();
    }
    let before = mmio.writes.len();
    if q.send(&mut mmio, 1, 8, 1, &[]).is_ok() || mmio.writes.len() != before {
        return TestResult::Fail("full queue published another command");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/runtime",
    smoke_command_queue_backpressure
);

fn smoke_rx_packet_length_and_alignment() -> TestResult {
    let mut bytes = [0; 128];
    // Firmware length includes the 4-byte command header, not len_n_flags.
    boot_context::put32(&mut bytes, 0, 7);
    bytes[4] = 1;
    bytes[8..11].copy_from_slice(&[0xaa, 0xbb, 0xcc]);
    boot_context::put32(&mut bytes, 64, 4);
    bytes[68] = 4;
    let parsed = packets(&bytes).unwrap();
    if parsed.len() != 2 || parsed[0].payload != [0xaa, 0xbb, 0xcc] || !parsed[1].payload.is_empty()
    {
        return TestResult::Fail("RX length/alignment convention");
    }
    boot_context::put32(&mut bytes, 0, 3);
    if packets(&bytes).is_ok() {
        return TestResult::Fail("short command header accepted");
    }
    boot_context::put32(&mut bytes, 0, 128);
    if packets(&bytes).is_ok() {
        return TestResult::Fail("overlong packet accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/runtime",
    smoke_rx_packet_length_and_alignment
);

fn smoke_rfh_dma_out_of_order_and_repost() -> TestResult {
    for format in [
        rx_rfh::CompletionFormat::Ax210,
        rx_rfh::CompletionFormat::Bz,
    ] {
        let mut q = ReceiveQueue::new(format).unwrap();
        let mut mmio = Mmio::default();
        q.publish(&mut mmio).unwrap();
        if q.advertised != 504 {
            return TestResult::Fail("initial RX publication granularity");
        }
        for (slot, tag) in [7u16, 2].into_iter().enumerate() {
            let mut completion = [0; 32];
            boot_context::put16(
                &mut completion,
                if format == rx_rfh::CompletionFormat::Bz {
                    0
                } else {
                    4
                },
                tag,
            );
            write_dma(&q.used, slot * format.size(), &completion[..format.size()]);
            let mut packet = [0; 9];
            boot_context::put32(&mut packet, 0, 5);
            packet[4] = 1;
            packet[8] = tag as u8;
            write_dma(&q.buffers[tag as usize - 1], 0, &packet);
        }
        // Hardware write-back includes wrap bits, masked to ring depth.
        write_dma(&q.status, 0, &514u16.to_le_bytes());
        let packets = q.drain(&mut mmio).unwrap();
        if packets.len() != 2 || packets[0].payload != [7] || packets[1].payload != [2] {
            return TestResult::Fail("RFH assumed descriptor order instead of tags");
        }
        if q.read != 2 || q.write != 1 || q.advertised != 0 {
            return TestResult::Fail("RX refill wrap");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/runtime",
    smoke_rfh_dma_out_of_order_and_repost
);

fn smoke_tx_completion_bounds_and_wrap() -> TestResult {
    use super::super::data_queue::DataQueue;
    let mut q = DataQueue::new().unwrap();
    let mut allocation = [0; 8];
    boot_context::put16(&mut allocation, 0, 17);
    boot_context::put16(&mut allocation, 4, u16::MAX);
    q.activate(&allocation).unwrap();
    let mut mmio = Mmio::default();
    if q.send(&mut mmio, &[0; 36], 24, 0x4100).unwrap() != 0 {
        return TestResult::Fail("TX pointer failed to wrap");
    }
    let mut reply = [0; 48];
    reply[0] = 1;
    reply[40] = 1;
    boot_context::put16(&mut reply, 36, 18);
    if q.complete(&reply).is_ok() {
        return TestResult::Fail("wrong TX queue accepted");
    }
    boot_context::put16(&mut reply, 36, 17);
    boot_context::put32(&mut reply, 44, 1);
    if q.complete(&reply).is_ok() {
        return TestResult::Fail("TX completion skipped unowned descriptor");
    }
    boot_context::put32(&mut reply, 44, 0);
    if q.complete(&reply) != Ok((0, true)) || q.complete(&reply).is_ok() {
        return TestResult::Fail("TX completion reclaimed twice");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/runtime",
    smoke_tx_completion_bounds_and_wrap
);

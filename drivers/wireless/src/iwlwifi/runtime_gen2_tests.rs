use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Default)]
struct Mmio(Vec<(u32, u32)>);
impl IwlMmio for Mmio {
    fn read(&mut self, _: u32) -> u32 {
        0
    }
    fn write(&mut self, r: u32, v: u32) {
        self.0.push((r, v));
    }
}
fn smoke_iwl_gen2_owned_rfh_uses_tagged_pages_and_low12_completions() -> TestResult {
    let mut queue = ReceiveQueue::new(rx_rfh::CompletionFormat::Qu).unwrap();
    let first = u64::from_le_bytes(queue.free.as_slice()[..8].try_into().unwrap());
    let second = u64::from_le_bytes(queue.free.as_slice()[8..16].try_into().unwrap());
    if first != queue.buffers[0].dma_addr().raw() | 1
        || second != queue.buffers[1].dma_addr().raw() | 2
    {
        return TestResult::Fail("Gen2 owner wrote AX210 free descriptors or wrong stride");
    }
    let mut mmio = Mmio::default();
    queue.publish(&mut mmio).unwrap();
    if mmio.0.last() != Some(&(0x1c80, 504)) {
        return TestResult::Fail("Gen2 RFH publication used PRPH or Bz shared doorbell");
    }
    write_dma(&queue.buffers[0], 0, &[4, 0, 0, 0, 4, 0, 0, 0x80]);
    write_dma(&queue.used, 0, &[1, 0xf0, 0xff, 0xff]);
    write_dma(&queue.status, 0, &1u16.to_le_bytes());
    let packets = queue.drain(&mut mmio).unwrap();
    if packets.len() != 1
        || packets[0].header.cmd != 4
        || packets[0].header.sequence != 0x8000
        || !packets[0].payload.is_empty()
        || queue.read != 1
    {
        return TestResult::Fail("Gen2 completion mask/stride did not reach actual packet parser");
    }
    write_dma(&queue.used, 4, &[2, 0, 0, 0]);
    write_dma(&queue.used, 8, &[2, 0, 0, 0]);
    write_dma(&queue.status, 0, &3u16.to_le_bytes());
    if queue.drain(&mut mmio).is_ok() {
        return TestResult::Fail("duplicate Gen2 used descriptor reclaimed one buffer twice");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_gen2_owned_rfh_uses_tagged_pages_and_low12_completions
);

fn smoke_iwl_gen2_owned_boot_keeps_context_sections_without_iml() -> TestResult {
    use super::super::{FwSection, UcodeHeader};
    let rx = ReceiveQueue::new(rx_rfh::CompletionFormat::Qu).unwrap();
    let commands = CommandQueue::new().unwrap();
    let mut parsed = ParsedUcode {
        api: super::super::firmware_api::FirmwareApi::default(),
        header: UcodeHeader {
            version: 77,
            build: 0,
            human_readable: alloc::string::String::new(),
        },
        num_of_cpu: 2,
        init_sections: Vec::new(),
        rt_sections: vec![
            FwSection {
                dest_offset: 0,
                payload: &[1, 2, 3],
            },
            FwSection {
                dest_offset: super::super::CPU1_CPU2_SEPARATOR,
                payload: &[],
            },
            FwSection {
                dest_offset: 4,
                payload: &[4, 5],
            },
            FwSection {
                dest_offset: super::super::PAGING_SEPARATOR,
                payload: &[],
            },
            FwSection {
                dest_offset: 8,
                payload: &[6],
            },
        ],
        fw_version: Some((77, 0, 0)),
        pnvm_version: None,
        unknown_tlv_count: 0,
    };
    parsed.api.api_changes[0] |= 1 << 20; // API_NEW_VERSION: raw header77.
    let boot = BootImage::new(&parsed, 0x351, &rx, &commands).unwrap();
    if boot.scratch.is_some()
        || boot.iml.is_some()
        || boot._info.is_some()
        || boot.iml_len != 0
        || boot._sections.len() != 3
        || boot.context.as_slice()[..16]
            != [0x51, 3, 0, 0, 0xc0, 1, 0, 0, 0x90, 9, 0, 0, 0, 0, 0, 0]
    {
        return TestResult::Fail("Gen2 boot borrowed IML/scratch or wrong owned context");
    }
    for (index, offset) in [(0, 704), (1, 192), (2, 1216)] {
        if boot.context.as_slice()[offset..offset + 8]
            != boot._sections[index].dma_addr().raw().to_le_bytes()
        {
            return TestResult::Fail("context DRAM role differs from retained section owner");
        }
    }
    parsed.header.version = 76;
    if BootImage::new(&parsed, 0x351, &rx, &commands).is_ok() {
        return TestResult::Fail("Gen2 accepted firmware outside exact API77 profile");
    }
    parsed.api.api_changes[0] = 0;
    parsed.header.version = 0x0102_4d04; // legacy API bits8..15, not major/display.
    parsed.fw_version = Some((123, 0x4567, 8));
    if BootImage::new(&parsed, 0x351, &rx, &commands).is_err() {
        return TestResult::Fail("Gen2 did not use source legacy header API field");
    }
    parsed.header.version = 77;
    parsed.fw_version = Some((77, 0, 0));
    if BootImage::new(&parsed, 0x351, &rx, &commands).is_ok() {
        return TestResult::Fail("Gen2 treated legacy serial/display77 as protocol API77");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_gen2_owned_boot_keeps_context_sections_without_iml
);

fn smoke_iwl_gen2_actual_alive6_unified_nvm_receipts_before_mac() -> TestResult {
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    struct Fixture {
        hardware: Option<Hardware>,
        firmware: model::Firmware,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Some(hardware) = self.hardware.take() {
                // SAFETY: every published descriptor addresses this fixture's private
                // RAM; no native PCI command, IRQ enable or physical device was used.
                unsafe { model::destroy(hardware) };
            }
        }
    }
    let (mut hardware, mut firmware) =
        model::create_for_format(false, rx_rfh::CompletionFormat::Qu);
    model::versions(&mut hardware, &[1, 0, 99, 6, 0, 12, 1, 0]);
    firmware.register(0x388, 0x02020202);
    firmware.register(0x38c, 0x0202);
    let mut fixture = Fixture {
        hardware: Some(hardware),
        firmware,
    };
    let mut alive = vec![0; 144];
    alive[..2].copy_from_slice(&[0xfe, 0xca]);
    // Nonzero SKU must not trigger the modern external PNVM path on Qu.
    alive[116..128].fill(0xaa);
    fixture.firmware.inject(1, 0, 0x8000, &alive);
    let parsed = ParsedUcode {
        api: super::super::firmware_api::FirmwareApi::default(),
        header: super::super::UcodeHeader {
            version: 0x0102_4d04,
            build: 0,
            human_readable: alloc::string::String::new(),
        },
        num_of_cpu: 2,
        init_sections: Vec::new(),
        rt_sections: Vec::new(),
        fw_version: Some((77, 0, 0)),
        pnvm_version: None,
        unknown_tlv_count: 0,
    };
    let mut boot = pin!(fixture.hardware.as_mut().unwrap().finish_boot(&parsed));
    let mut cx = Context::from_waker(Waker::noop());
    if !boot.as_mut().poll(&mut cx).is_pending() || fixture.firmware.tx_write() != 1 {
        return TestResult::Fail("ALIVE6 failed to reach actual INIT_EXTENDED_CFG command");
    }
    fixture.firmware.inject(3, 2, 0, &[]);
    // This RAM fixture has no IRQ; drive the real no-IRQ Activity timer.
    narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
        2_000_000,
    )));
    for _ in 0..4 {
        if !boot.as_mut().poll(&mut cx).is_pending() {
            return TestResult::Fail("Gen2 boot finished before NVM completion");
        };
        if fixture.firmware.tx_write() == 2 {
            break;
        }
    }
    if fixture.firmware.tx_write() != 2 {
        return TestResult::Fail("Gen2 boot did not submit NVM_ACCESS_COMPLETE via retained TFH");
    }
    fixture.firmware.inject(0, 12, 1, &[]);
    // Completion may race its command response; both must be retained.
    fixture.firmware.inject(4, 0, 0x8000, &[]);
    narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
        2_000_000,
    )));
    for _ in 0..4 {
        match boot.as_mut().poll(&mut cx) {
            Poll::Ready(Ok(mac)) if mac == [2; 6] && fixture.firmware.tx_write() == 2 => {
                return TestResult::Pass
            }
            Poll::Ready(_) => {
                return TestResult::Fail("Gen2 unified init used PHY/PNVM or returned wrong MAC")
            }
            Poll::Pending => {}
        }
    }
    TestResult::Fail("actual RFH INIT_COMPLETE did not finish Gen2 boot")
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_gen2_actual_alive6_unified_nvm_receipts_before_mac
);

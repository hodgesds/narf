use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};
fn smoke_iwl_gen2_context_literal_geometry_and_tagged_rfh() -> TestResult {
    let q = BootQueues {
        free: 0x100001000,
        used: 0x100002000,
        status: 0x100003000,
        command: 0x100004000,
        rx_depth: 512,
        command_depth: 128,
    };
    let bytes = header(0x351, q).unwrap();
    if bytes[..16] != [0x51, 3, 0, 0, 0xc0, 1, 0, 0, 0x90, 9, 0, 0, 0, 0, 0, 0]
        || bytes[24..32] != q.free.to_le_bytes()
        || bytes[32..40] != q.used.to_le_bytes()
        || bytes[40..48] != q.status.to_le_bytes()
        || bytes[48..56] != q.command.to_le_bytes()
        || bytes[56..64] != [4, 0, 0, 0, 0, 0, 0, 0]
        || bytes[64..].iter().any(|&b| b != 0)
        || free_descriptor(0x12345678000, 0xabc) != Ok([0xbc, 0x8a, 0x67, 0x45, 0x23, 1, 0, 0])
        || used_descriptor(&[0xbc, 0x8a, 0xff, 0xff]) != Ok(0xabc)
    {
        return TestResult::Fail("Gen2 context/DWflags/queue units or RFH wire format");
    }
    let mut bad = q;
    bad.free = 0xfffff800;
    if header(0, bad).is_ok()
        || dma_extent(0xfffff000, 8192)
        || dma_extent(u64::MAX, 2)
        || free_descriptor(0x1234, 1).is_ok()
        || used_descriptor(&[0; 4]).is_ok()
    {
        return TestResult::Fail("Gen2 context/RFH address or boundary admission");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_gen2_context_literal_geometry_and_tagged_rfh
);
fn smoke_iwl_gen2_context_cpu_release_uses_interleaved_actual_prph() -> TestResult {
    struct Mmio {
        live: bool,
        trace: alloc::vec::Vec<(u32, u32)>,
    }
    impl super::super::transport::IwlMmio for Mmio {
        fn authorized(&self) -> bool {
            self.live
        }
        fn read(&mut self, _: u32) -> u32 {
            0
        }
        fn write(&mut self, a: u32, v: u32) {
            self.trace.push((a, v));
        }
    }
    let mut io = Mmio {
        live: true,
        trace: vec![],
    };
    if start(&mut io, 0x12345678000) != Ok(())
        || io.trace
            != vec![
                (0x40, 0x45678000),
                (0x44, 0x123),
                (0x444, 0x03005c44),
                (0x44c, 1),
            ]
    {
        return TestResult::Fail("Gen2 ROM release did not use context and actual PRPH WDAT");
    }
    io.live = false;
    io.trace.clear();
    if start(&mut io, 0x12345678000) != Err(Error::Authority) || !io.trace.is_empty() {
        return TestResult::Fail("revoked Gen2 context publication performed MMIO");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_gen2_context_cpu_release_uses_interleaved_actual_prph
);
fn smoke_iwl_gen2_profile_exact_mac_rf_and_pci_latency() -> TestResult {
    use super::super::gen2_profile as p;
    if p::API != 77 || p::select(0x2723, 0x340, 0xdeadbeef).unwrap().prefix != "iwlwifi-cc-a0" {
        return TestResult::Fail("AX200 firmware selection used integrated RF suffix");
    }
    for (hw, rf, name) in [
        (0x331, 0x10a000, "iwlwifi-Qu-b0-hr-b0"),
        (0x332, 0x108000, "iwlwifi-Qu-c0-jf-b0"),
        (0x35f, 0x10c000, "iwlwifi-QuZ-a0-hr-b0"),
    ] {
        if p::select(0xa0f0, hw, rf).unwrap().prefix != name {
            return TestResult::Fail("MVM firmware stepping/RF selector");
        }
    }
    // Linux pcie/drv.c Qu PCI IDs and their cfg/22000.c latency classes.
    for (did, latency) in [
        (0x02f0, (500, 200)),
        (0x06f0, (500, 200)),
        (0x34f0, (1820, 1820)),
        (0x3df0, (1820, 1820)),
        (0x4df0, (1820, 1820)),
        (0x43f0, (12000, 2500)),
        (0xa0f0, (12000, 2500)),
    ] {
        let Ok(profile) = p::select(did, 0x351, 0x10c000) else {
            return TestResult::Fail("Linux Qu PCI ID not admitted");
        };
        if profile.prefix != "iwlwifi-QuZ-a0-hr-b0"
            || !profile.integrated
            || (profile.xtal_latency_us, profile.ltr_delay_us) != latency
            || super::super::chip_config_for_pci_id(0x8086, did)
                .is_none_or(|c| c.generation != super::super::Generation::Gen2)
        {
            return TestResult::Fail("Qu PCI latency class/match table");
        }
    }
    for (did, hw, rf) in [
        (0x2723, 0x351, 0x10c000),
        (0x02f0, 0x330, 0x10c000),
        (0x02f0, 0x331, 0x999000),
        (0x7df0, 0x351, 0x10c000),
        (0x2723, u32::MAX, 0x10c000),
    ] {
        if p::select(did, hw, rf).is_ok() {
            return TestResult::Fail("unknown/gone Gen2 identity admitted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_gen2_profile_exact_mac_rf_and_pci_latency
);

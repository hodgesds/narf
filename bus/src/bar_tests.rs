use super::*;
use narf_capabilities::{Cap, Write};
use narf_kernel_test::{kernel_test_in, TestResult};

/// QEMU pci-testdev's optional RAM-backed 64-bit BAR2 exercises the same
/// KVM memory-slot registration that aborts for an enabled VFIO BAR probe.
/// Run with -device pci-testdev,membar=256M,membar-backed=on.
fn live_decoded_ram_bar_survives_sizing() -> TestResult {
    let Some(device) = crate::devices()
        .into_iter()
        .find(|d| d.id.vendor == 0x1b36 && d.id.device == 0x0005)
    else {
        return TestResult::Skip("QEMU pci-testdev RAM-backed BAR fixture absent");
    };
    // This fixture has no driver, queues, DMA or IRQ handlers. The smoke
    // exclusively owns its configuration and enables decoding deliberately.
    let cap = Cap::<crate::BusDeviceCap, Write>::bootstrap();
    let Ok(before) = crate::pci::read_command(&cap, &device) else {
        return TestResult::Fail("fixture Command read failed");
    };
    let (Ok(low), Ok(high)) = (
        crate::pci::read_config32(&cap, &device, 0x18),
        crate::pci::read_config32(&cap, &device, 0x1c),
    ) else {
        return TestResult::Fail("fixture BAR2 read failed");
    };
    let flags =
        crate::pci::cmd::IO_SPACE | crate::pci::cmd::MEM_SPACE | crate::pci::cmd::BUS_MASTER;
    if crate::pci::set_command(&cap, &device, flags).is_err() {
        return TestResult::Fail("fixture Command enable failed");
    }
    // SAFETY: this unbound, non-DMA test fixture is owned exclusively here.
    let result = unsafe { read_bar(&device, 2) };
    let command_after = crate::pci::read_command(&cap, &device);
    let low_after = crate::pci::read_config32(&cap, &device, 0x18);
    let high_after = crate::pci::read_config32(&cap, &device, 0x1c);
    let restored = crate::pci::clear_command(&cap, &device, u16::MAX).is_ok()
        && crate::pci::set_command(&cap, &device, before).is_ok();
    if !restored
        || command_after != Ok(before | flags)
        || low_after != Ok(low)
        || high_after != Ok(high)
    {
        return TestResult::Fail("live BAR or Command value was not restored");
    }
    match result {
        Ok(bar)
            if matches!(bar.kind, BarKind::Mmio64 { prefetchable: true })
                && bar.size == 0x1000_0000
                && bar.phys.raw() == (u64::from(high) << 32 | u64::from(low & !15)) =>
        {
            TestResult::Pass
        }
        _ => TestResult::Fail("live 256 MiB BAR2 decode mismatch"),
    }
}
kernel_test_in!("bus/bar/vfio", live_decoded_ram_bar_survives_sizing);

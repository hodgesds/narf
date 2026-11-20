// SPDX-License-Identifier: GPL-2.0-or-later
//! Candidate discovery must not bless a legacy bus as a gSPI host.
use super::host_ports::*;
use alloc::sync::Arc;
use narf_drivers_spi::{SpiBus, SpiError, SpiMode};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Debug)]
struct Legacy;
impl SpiBus for Legacy {
    fn transfer(&self, _: &[u8], _: &mut [u8]) -> Result<(), SpiError> {
        panic!("unsupported open touched legacy hardware")
    }
    fn transfer_full_duplex(&self, _: &mut [u8], _: &mut [u8]) -> Result<(), SpiError> {
        panic!("unsupported open touched legacy hardware")
    }
    fn set_mode(&self, _: SpiMode) -> Result<(), SpiError> {
        panic!("unsupported open changed mode")
    }
    fn set_freq(&self, _: u32) -> Result<(), SpiError> {
        panic!("unsupported open changed frequency")
    }
    fn set_cs(&self, _: u8) -> Result<(), SpiError> {
        panic!("unsupported open changed CS")
    }
    fn name(&self) -> &str {
        "cyw-legacy-no-session"
    }
}
fn smoke_legacy_spi_refuses_whole_transaction_without_effects() -> TestResult {
    let port = HostPort::SpiGspi {
        bus: Arc::new(Legacy),
        cs: 0,
    };
    if port.is_available()
        || !matches!(
            port.open_gspi(SpiMode::Mode0, 1_000_000),
            Err(PortError::TransactionUnavailable)
        )
    {
        return TestResult::Fail("legacy transfer was promoted to whole-CS/native authority");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/host_ports",
    smoke_legacy_spi_refuses_whole_transaction_without_effects
);
fn smoke_host_port_kinds_and_availability() -> TestResult {
    let pci = HostPort::PciSdhci;
    let platform = HostPort::PlatformSdhci {
        mmio_base: 0xfedc0000,
    };
    if pci.kind() != HostPortKind::PciSdhci
        || !pci.is_available()
        || platform.kind() != HostPortKind::PlatformSdhci
        || platform.is_available()
        || !matches!(
            platform.open_gspi(SpiMode::Mode0, 1_000_000),
            Err(PortError::NotGspi)
        )
    {
        return TestResult::Fail("candidate availability implies unsupported native host");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/host_ports",
    smoke_host_port_kinds_and_availability
);

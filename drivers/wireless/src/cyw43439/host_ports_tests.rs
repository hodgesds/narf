// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixture smokes for the CYW43439 additional host ports.
//!
//! Every expected byte below is written out literally from the
//! datasheet §6.4 command-word layout (Figure 6-2 / Table 6-3) and the
//! landed codec's field positions — never computed from the module
//! under test. Command word, MSB → LSB: RW bit 31, AI bit 30,
//! FN bits 29-28, ADDR bits 27-11, LENGTH bits 10-0.

use super::host_ports::*;
use ::core::fmt;
use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_drivers_spi::{registry, SpiBus, SpiError, SpiMode};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

/// Scripted SPI bus: records every transfer and serves queued
/// response bytes (zero-filled when the queue is empty).
struct FakeSpiBus {
    name: &'static str,
    responses: IrqSafeSpinLock<Vec<Vec<u8>>>,
    log: IrqSafeSpinLock<Vec<Vec<u8>>>,
    css: IrqSafeSpinLock<Vec<u8>>,
    mode: IrqSafeSpinLock<Option<SpiMode>>,
    freq: IrqSafeSpinLock<Option<u32>>,
}

impl fmt::Debug for FakeSpiBus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeSpiBus")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl FakeSpiBus {
    fn new(name: &'static str, responses: Vec<Vec<u8>>) -> Self {
        Self {
            name,
            responses: IrqSafeSpinLock::new(responses),
            log: IrqSafeSpinLock::new(Vec::new()),
            css: IrqSafeSpinLock::new(Vec::new()),
            mode: IrqSafeSpinLock::new(None),
            freq: IrqSafeSpinLock::new(None),
        }
    }

    fn transfers(&self) -> Vec<Vec<u8>> {
        self.log.lock().clone()
    }

    fn chip_selects(&self) -> Vec<u8> {
        self.css.lock().clone()
    }
}

impl SpiBus for FakeSpiBus {
    fn transfer(&self, tx: &[u8], rx: &mut [u8]) -> Result<(), SpiError> {
        self.log.lock().push(tx.to_vec());
        let response = if self.responses.lock().is_empty() {
            Vec::new()
        } else {
            self.responses.lock().remove(0)
        };
        for slot in rx.iter_mut() {
            *slot = 0;
        }
        let take = rx.len().min(response.len());
        rx[..take].copy_from_slice(&response[..take]);
        Ok(())
    }

    fn transfer_full_duplex(&self, tx: &mut [u8], rx: &mut [u8]) -> Result<(), SpiError> {
        self.log.lock().push(tx.to_vec());
        let response = if self.responses.lock().is_empty() {
            Vec::new()
        } else {
            self.responses.lock().remove(0)
        };
        for slot in tx.iter_mut() {
            *slot = 0;
        }
        let take = tx.len().min(response.len());
        tx[..take].copy_from_slice(&response[..take]);
        for slot in rx.iter_mut() {
            *slot = 0;
        }
        let take = rx.len().min(response.len());
        rx[..take].copy_from_slice(&response[..take]);
        Ok(())
    }

    fn set_mode(&self, mode: SpiMode) -> Result<(), SpiError> {
        *self.mode.lock() = Some(mode);
        Ok(())
    }

    fn set_freq(&self, hz: u32) -> Result<(), SpiError> {
        *self.freq.lock() = Some(hz);
        Ok(())
    }

    fn set_cs(&self, cs: u8) -> Result<(), SpiError> {
        self.css.lock().push(cs);
        Ok(())
    }

    fn name(&self) -> &str {
        self.name
    }
}

fn make_transport(
    name: &'static str,
    cs: u8,
    responses: Vec<Vec<u8>>,
) -> (GspiTransport, Arc<FakeSpiBus>) {
    let fake = Arc::new(FakeSpiBus::new(name, responses));
    let bus: Arc<dyn SpiBus> = fake.clone();
    let transport =
        GspiTransport::new(bus, cs, SpiMode::Mode0, 1_000_000).expect("fake bus accepts config");
    (transport, fake)
}

fn smoke_gspi_read32_frames_command_word() -> TestResult {
    // Scripted reply: 4 junk bytes (command phase) then 0x12345678.
    let (mut transport, fake) = make_transport(
        "read32-test-bus",
        2,
        alloc::vec![alloc::vec![0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78]],
    );
    let value = match transport.read32(Function::Bus, 0x0014) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("read32 should succeed on fake bus"),
    };
    if value != 0x1234_5678 {
        return TestResult::Fail("read32 should return the scripted big-endian value");
    }
    let log = fake.transfers();
    if log.len() != 1 {
        return TestResult::Fail("read32 should be exactly one transfer");
    }
    // Read / increment / FN 0 / addr 0x14 / len 4:
    // 0x4000_0000 | (0x14 << 11) | 4 = 0x4000_A004.
    if log[0] != alloc::vec![0x40, 0x00, 0xA0, 0x04, 0, 0, 0, 0] {
        return TestResult::Fail("read32 command bytes mismatch");
    }
    if fake.chip_selects() != alloc::vec![2] {
        return TestResult::Fail("read32 should assert CS 2 once");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/host_ports",
    smoke_gspi_read32_frames_command_word
);

fn smoke_gspi_write32_frames_payload() -> TestResult {
    let (mut transport, fake) = make_transport("write32-test-bus", 0, Vec::new());
    if transport
        .write32(Function::Backplane, 0x1_8000, 0xAABB_CCDD)
        .is_err()
    {
        return TestResult::Fail("write32 should succeed on fake bus");
    }
    let log = fake.transfers();
    if log.len() != 1 {
        return TestResult::Fail("write32 should be exactly one transfer");
    }
    // Write / increment / FN 1 / addr 0x18000 / len 4:
    // 0xD000_0000 | (0x18000 << 11) | 4 = 0xDC00_0004.
    if log[0] != alloc::vec![0xDC, 0x00, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD] {
        return TestResult::Fail("write32 command + payload bytes mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/host_ports",
    smoke_gspi_write32_frames_payload
);

fn smoke_gspi_burst_chunks_at_2047() -> TestResult {
    let mut pattern = alloc::vec![0u8; 5000];
    for (i, slot) in pattern.iter_mut().enumerate() {
        *slot = (i % 251) as u8;
    }
    let (mut transport, fake) = make_transport("burst-test-bus", 0, Vec::new());
    if transport.write_burst(Function::Wlan, 0, &pattern).is_err() {
        return TestResult::Fail("write_burst should succeed on fake bus");
    }
    let log = fake.transfers();
    if log.len() != 3 {
        return TestResult::Fail("5000-byte burst should chunk into 3 transfers");
    }
    if log[0].len() != 2051 || log[1].len() != 2051 || log[2].len() != 910 {
        return TestResult::Fail("burst chunk lengths should be 2047/2047/906");
    }
    // Chunk 0: write / increment / FN 2 / addr 0 / len 2047 = 0xE000_07FF.
    if log[0][0..4] != [0xE0, 0x00, 0x07, 0xFF] {
        return TestResult::Fail("burst chunk 0 command word mismatch");
    }
    // Chunk 1: addr 2047 / len 2047 = 0xE03F_FFFF.
    if log[1][0..4] != [0xE0, 0x3F, 0xFF, 0xFF] {
        return TestResult::Fail("burst chunk 1 command word mismatch");
    }
    // Chunk 2: addr 4094 / len 906 = 0xE07F_F38A.
    if log[2][0..4] != [0xE0, 0x7F, 0xF3, 0x8A] {
        return TestResult::Fail("burst chunk 2 command word mismatch");
    }
    if log[0][4..] != pattern[0..2047] {
        return TestResult::Fail("burst chunk 0 payload mismatch");
    }
    if log[1][4..] != pattern[2047..4094] {
        return TestResult::Fail("burst chunk 1 payload mismatch");
    }
    if log[2][4..] != pattern[4094..] {
        return TestResult::Fail("burst chunk 2 payload mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/host_ports",
    smoke_gspi_burst_chunks_at_2047
);

fn smoke_gspi_read_burst_chunks() -> TestResult {
    let mut pattern = alloc::vec![0u8; 3000];
    for (i, slot) in pattern.iter_mut().enumerate() {
        *slot = (i % 251) as u8;
    }
    let mut first = alloc::vec![0u8; 4 + 2047];
    first[4..].copy_from_slice(&pattern[0..2047]);
    let mut second = alloc::vec![0u8; 4 + 953];
    second[4..].copy_from_slice(&pattern[2047..]);
    let (mut transport, fake) =
        make_transport("read-burst-test-bus", 0, alloc::vec![first, second]);
    let mut out = alloc::vec![0u8; 3000];
    if transport
        .read_burst(Function::Wlan, 0x40, &mut out)
        .is_err()
    {
        return TestResult::Fail("read_burst should succeed on fake bus");
    }
    if out != pattern {
        return TestResult::Fail("read_burst payload should match scripted bytes");
    }
    let log = fake.transfers();
    if log.len() != 2 || log[0].len() != 2051 || log[1].len() != 957 {
        return TestResult::Fail("3000-byte read should chunk into 2047/953");
    }
    // Chunk 0: read / increment / FN 2 / addr 0x40 / len 2047 = 0x6002_07FF.
    if log[0][0..4] != [0x60, 0x02, 0x07, 0xFF] {
        return TestResult::Fail("read chunk 0 command word mismatch");
    }
    // Chunk 1: addr 0x40 + 2047 = 0x83F / len 953:
    // 0x4000_0000 (increment) | 0x2000_0000 (FN 2) | (0x83F << 11) | 953.
    // 0x83F << 11 = 0x41F800; 953 = 0x3B9; word = 0x6041_FBB9.
    if log[1][0..4] != [0x60, 0x41, 0xFB, 0xB9] {
        return TestResult::Fail("read chunk 1 command word mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/host_ports",
    smoke_gspi_read_burst_chunks
);

fn smoke_gspi_probe_link_pattern() -> TestResult {
    let (mut good, _) = make_transport(
        "probe-good-bus",
        0,
        alloc::vec![alloc::vec![0, 0, 0, 0, 0xFE, 0xED, 0xBE, 0xAD]],
    );
    match good.probe_link() {
        Ok(true) => {}
        _ => return TestResult::Fail("probe should pass on TEST_RO pattern"),
    }
    let (mut swapped, _) = make_transport(
        "probe-swapped-bus",
        0,
        alloc::vec![alloc::vec![0, 0, 0, 0, 0xAD, 0xBE, 0xED, 0xFE]],
    );
    match swapped.probe_link() {
        Ok(false) => {}
        _ => return TestResult::Fail("probe should fail on byte-swapped pattern"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/host_ports",
    smoke_gspi_probe_link_pattern
);

fn smoke_gspi_address_overflow_rejected() -> TestResult {
    let (mut transport, fake) = make_transport("overflow-test-bus", 0, Vec::new());
    match transport.read32(Function::Bus, 0x2_0000) {
        Err(TransportError::AddressOverflow) => {}
        _ => return TestResult::Fail("17-bit overflow address should be rejected"),
    }
    let buf = alloc::vec![0u8; 512];
    match transport.write_burst(Function::Backplane, 0x1_FF00, &buf) {
        Err(TransportError::AddressOverflow) => {}
        _ => return TestResult::Fail("window crossing the 17-bit field should be rejected"),
    }
    if !fake.transfers().is_empty() {
        return TestResult::Fail("rejected bursts must not touch the bus");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/host_ports",
    smoke_gspi_address_overflow_rejected
);

fn smoke_host_port_kinds_and_availability() -> TestResult {
    let pci = HostPort::PciSdhci;
    if pci.kind() != HostPortKind::PciSdhci || !pci.is_available() {
        return TestResult::Fail("PCI SDHCI port should be available");
    }
    if !matches!(
        pci.open_gspi(SpiMode::Mode0, 1_000_000),
        Err(PortError::NotGspi)
    ) {
        return TestResult::Fail("PCI port should refuse open_gspi");
    }
    let platform = HostPort::PlatformSdhci {
        mmio_base: 0xFEDC_0000,
    };
    if platform.kind() != HostPortKind::PlatformSdhci || platform.is_available() {
        return TestResult::Fail("platform SDHCI port should be unavailable");
    }
    if !matches!(
        platform.open_gspi(SpiMode::Mode0, 1_000_000),
        Err(PortError::NotGspi)
    ) {
        return TestResult::Fail("platform port should refuse open_gspi");
    }
    let fake = Arc::new(FakeSpiBus::new("kind-test-bus", Vec::new()));
    let bus: Arc<dyn SpiBus> = fake.clone();
    let gspi = HostPort::SpiGspi { bus, cs: 3 };
    if gspi.kind() != HostPortKind::SpiGspi || !gspi.is_available() {
        return TestResult::Fail("gSPI port should be available");
    }
    let transport = match gspi.open_gspi(SpiMode::Mode0, 1_000_000) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("gSPI port should open"),
    };
    if transport.bus_name() != "kind-test-bus" || transport.cs() != 3 {
        return TestResult::Fail("opened transport should keep bus name and CS");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/host_ports",
    smoke_host_port_kinds_and_availability
);

fn smoke_spi_port_discovery_lists_registered_bus() -> TestResult {
    let fake = Arc::new(FakeSpiBus::new("cyw43439-host-ports-test-bus", Vec::new()));
    let bus: Arc<dyn SpiBus> = fake.clone();
    let _ = registry::register_unique(bus);
    let found = discover_spi_ports()
        .iter()
        .any(|b| b.name() == "cyw43439-host-ports-test-bus");
    if !found {
        return TestResult::Fail("discovery should list the registered bus");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/host_ports",
    smoke_spi_port_discovery_lists_registered_bus
);

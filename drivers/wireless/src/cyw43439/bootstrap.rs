// SPDX-License-Identifier: GPL-2.0-or-later
//! SDIO function match → verified firmware → actual loader → FIFO station.
//! The SDHCI host hands over whole-card ownership, never a second F1 window.

use super::{
    firmware::{build_nvram_blob, FirmwareLoader},
    interface,
    sdio_bridge::SdioTransport,
};
use alloc::{string::String, vec::Vec};
use core::fmt::Write;
use narf_drivers_sdio::native::{FunctionDriver, NativeCard};

pub fn register() {
    for (name, vendor, device) in [
        ("cyw43439-sdio", 0x02d0, 0xa9af),
        ("cyw43439-cypress-sdio", 0x04b4, 0xbd3d),
    ] {
        let _ = narf_drivers_sdio::native::register_function_driver(FunctionDriver {
            name,
            vendor,
            device,
            function: 1,
            probe,
        });
    }
    narf_drivers_sdio::native::register_pci_driver();
}

fn read_blob(names: &[&str]) -> Result<Vec<u8>, &'static str> {
    let authority = narf_firmware::trusted_loader_authority()
        .and_then(|cap| cap.derive().ok())
        .ok_or("firmware authority unavailable")?;
    for &name in names {
        if let Ok(cap) = narf_firmware::open(name, &authority) {
            let view = narf_firmware::view_of(&cap).map_err(|_| "firmware authority revoked")?;
            return Ok(view.bytes.to_vec());
        }
    }
    Err("required CYW43439 firmware or board NVRAM missing")
}

/// Callback runs after the host has reset/selected/enumerated the card.
/// Firmware lookup happens when the executor polls the retained owner;
/// the boot initcall has already completed firmware registry population.
fn probe(card: NativeCard) {
    narf_scheduler::spawn(async move {
        match boot(card).await {
            Ok(()) => {}
            Err(reason) => {
                let _ = writeln!(narf_console::Writer, "cyw43439: {}", reason);
            }
        }
    });
}

/// Explicit platform boot path for an already enumerated card. Platform
/// code supplies its exclusive standard Registers implementation through
/// Card::initialize; the same loader and station path is used as PCI.
pub async fn boot<R: narf_drivers_sdio::pio::Registers + Send + 'static>(
    card: narf_drivers_sdio::card::Card<R>,
) -> Result<(), &'static str> {
    // NVRAM is board calibration supplied by the verified firmware registry.
    // There is no synthesized MAC, country override, or generic calibration.
    let firmware = read_blob(&["brcm/brcmfmac43439-sdio.bin", "43439A0.bin"])?;
    let nvram = read_blob(&["brcm/brcmfmac43439-sdio.txt", "43439A0.txt"])?;
    let clm = read_blob(&["brcm/brcmfmac43439-sdio.clm_blob", "43439A0_clm.bin"])?;
    let nvram = core::str::from_utf8(&nvram).map_err(|_| "NVRAM is not text")?;
    let nvram = build_nvram_blob(nvram).map_err(|_| "invalid NVRAM")?;
    let mut transport = SdioTransport::new(card);
    transport
        .prepare()
        .map_err(|_| "SDIO F1 preparation failed")?;
    let mut loader = FirmwareLoader::new(transport, &firmware, &nvram, 0, false);
    loader.run().map_err(|_| "firmware bootstrap failed")?;
    let core = loader.packet_core().ok_or("firmware did not release CM3")?;
    let mut transport = loader
        .into_transport()
        .map_err(|_| "firmware owner not ready")?;
    transport
        .initialize_packets(core)
        .map_err(|_| "F2/mailbox setup failed")?;
    let name = available_name().ok_or("no free wireless interface name")?;
    interface::attach(&name, transport, &clm)
        .await
        .map_err(|_| "station initialization failed")?;
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: "cyw43439".into(),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: None,
        pci_did: None,
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });
    Ok(())
}
fn available_name() -> Option<String> {
    (0..16).map(|n| alloc::format!("wlan{}", n)).find(|name| {
        narf_net::iface::lookup(name).is_none()
            && !narf_wireless::registry::list()
                .iter()
                .any(|i| i.name() == name)
    })
}

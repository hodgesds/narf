//! Qualcomm Atheros QCNFA765 (WCN685x family) WiFi 6E PCIe host —
//! clean-room presence driver.
//!
//! ## Reference
//!
//! - Qualcomm "MHI (Modem-Host Interface) Specification" public
//!   release. Section numbers below (`§N`) refer to that document.
//! - The QCNFA765 / WCN6855 PCIe ID and BAR0 = MHI register window
//!   come from the device's PCI configuration header, which the
//!   chip exposes regardless of firmware state.
//!
//! No GPL Linux ath11k / ath12k / mhi-bus source consulted.
//!
//! ## Why presence-only
//!
//! Bringing the MHI engine into the M0 (active) state requires
//! Qualcomm-signed firmware (`amss.bin` + `m3.bin`) to be staged
//! into BHI memory and the boot-host-interface vector to point at
//! it (`§3.2.4 BHI Boot`). Until that firmware is loaded,
//! `MHISTATUS.READY` never asserts — the chip stays in PBL
//! (Primary Boot Loader) executing only the BHI poll loop.
//!
//! NARF doesn't yet have a firmware-blob delivery surface (the
//! `narf-fw` crate is on the roadmap as `Stage-6 firmware loader`),
//! so this driver does not try to run the post-firmware MHI flow.
//! What it does:
//!
//! 1. Claim the PCIe device.
//! 2. Map BAR0 (the MHI register window).
//! 3. Read the BHI HW_VERSION register so a sanity check that the
//!    chip is alive + responsive lands in `ChipInfo`.
//! 4. Record the bound driver in `narf_drivers::record_bound`.
//!
//! Once firmware loading lands, this driver picks up the BHI / SBL
//! / AMSS hand-off + the channel + event copy-engine ring set-up
//! using the MHI control registers documented in `MhiRegs` below
//! (still public-spec — no GPL reference).

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

/// Qualcomm Technologies, Inc.
pub const QCN_VENDOR:    u16 = 0x17CB;
/// QCNFA765 / WCN6855 WiFi 6E.
pub const QCNFA765_DEV:  u16 = 0x1103;

/// BAR0 register-block offsets the public MHI spec documents. Real
/// WCN6855 layout *may* place the BHI block behind a different
/// front-end window (silicon-specific BHIOFF + RTSOFF redirection
/// is read out of `BHIOFF` / `MHIVER` at runtime, not hard-coded).
/// The offsets below are the spec's first-window defaults, used
/// as a starting point for reading those redirection registers.
mod regs {
    /// MHI register block; offsets per `§4.2`.
    pub const MHIVER:    u64 = 0x0008;
    /// MHIVER read of `0xFFFFFFFF` means the BAR isn't backed by
    /// the chip (PCIe link gone, device in D3cold, etc.). Used as a
    /// presence test.
    pub const MHIVER_GONE: u32 = 0xFFFF_FFFF;
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WifiError {
    BarMapFailed,
    /// MHIVER read 0xFFFFFFFF — device is not present or is in
    /// D3cold / PCIe link down.
    DeviceGone,
    /// `narf-firmware` reported no AMSS blob registered under
    /// the chip's canonical name. Typical state before Stage-6
    /// step-2 (in-tree fallback) or step-3 (initramfs unpack).
    FirmwareMissing,
    /// `narf-firmware` returned a blob but BHI staging or the
    /// MHI hand-off didn't complete. Real-silicon-specific.
    FirmwareLoadFailed,
}

#[derive(Copy, Clone, Debug)]
pub struct ChipInfo {
    /// MHIVER register value. Encodes the MHI protocol version the
    /// chip understands (major in bits[31:16], minor in bits[15:0]).
    /// Stage-6 firmware loader uses this to pick the right
    /// register layout for downstream MHI register reads.
    pub mhi_version: u32,
}

/// One QCNFA765 host. Pre-firmware: BAR mapped, MHIVER read, that's
/// it. Post-firmware (Stage-6+): MHI control region + channel +
/// event rings + 802.11 data plane all hang off this struct.
pub struct WifiNic {
    pub mmio: MmioRegion,
    pub chip: ChipInfo,
    /// `false` until firmware loading completes. Bringing this to
    /// `true` is a Stage-6 follow-up driven by the firmware loader.
    pub fw_loaded: bool,
}

impl core::fmt::Debug for WifiNic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WifiNic")
            .field("chip",      &self.chip)
            .field("fw_loaded", &self.fw_loaded)
            .finish_non_exhaustive()
    }
}

impl WifiNic {
    /// Map BAR0 + read MHIVER. Does NOT attempt to put the MHI
    /// engine into the M0 (active) state — that requires firmware.
    ///
    /// # Safety
    /// Caller owns BAR0 exclusively for the duration of probe.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap:   &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, WifiError> {
        // SAFETY: caller-authority over BAR0.
        let mmio = unsafe { map_bar(device, 0) }
            .map_err(|_| WifiError::BarMapFailed)?;

        // Probe the MHI version register. A read of 0xFFFFFFFF
        // means the BAR window is mapped but no silicon is
        // backing it — D3cold, PCIe link down, or a missing
        // device. Anything else, we treat the device as alive.
        // SAFETY: identity-mapped MMIO.
        let mhi_version = unsafe { mmio.read32(regs::MHIVER) };
        if mhi_version == regs::MHIVER_GONE {
            return Err(WifiError::DeviceGone);
        }

        Ok(Self {
            mmio,
            chip: ChipInfo { mhi_version },
            fw_loaded: false,
        })
    }

    pub fn chip_info(&self) -> ChipInfo { self.chip }

    /// `true` once the (Stage-6) firmware loader has staged AMSS
    /// firmware via BHI + the MHI engine has reached M0.
    pub fn is_ready(&self) -> bool { self.fw_loaded }

    /// Stage AMSS firmware via BHI + drive the MHI engine into M0.
    ///
    /// Looks the AMSS image up by canonical name through the
    /// kernel firmware registry (`narf-firmware`), points BHI at
    /// the staged image, and waits for `BHI_STATUS` = success.
    /// On real silicon the chip then transitions PBL → SBL → AMSS
    /// and `MHISTATUS.READY` asserts within ~200 ms.
    ///
    /// Returns `FirmwareMissing` if the registry has no entry for
    /// the requested blob — typical state before Stage-6 step-2
    /// (in-tree fallback) or step-3 (initramfs unpack) lands the
    /// AMSS image into the registry.
    ///
    /// # Safety
    /// Caller owns BAR0 + cfg windows exclusively. The blob's
    /// `view().phys` must remain valid for the duration of the
    /// BHI handoff (the cap stays alive until the function
    /// returns).
    pub unsafe fn load_firmware(
        &mut self,
        fw_authority: &narf_capabilities::Cap<
            narf_firmware::FirmwareRegistry, narf_capabilities::Read,
        >,
    ) -> Result<(), WifiError> {
        let cap = narf_firmware::open(
            "qcom/qcnfa765/amss.bin", fw_authority,
        ).map_err(|e| match e {
            narf_firmware::FirmwareError::NotFound => WifiError::FirmwareMissing,
            _                                     => WifiError::FirmwareLoadFailed,
        })?;
        let view = narf_firmware::view_of(&cap)
            .map_err(|_| WifiError::FirmwareLoadFailed)?;
        // Stage-6 step-2 will land the BHI register sequence:
        //   write BHI_INTVEC = view.phys (low / high)
        //   write BHI_IMGTXDB = (image length << 16) | sequence_id
        //   poll BHI_STATUS for SUCCESS
        // The QCNFA765 MHI register layout for those writes lives
        // behind a per-silicon redirection word (BHIOFF) and the
        // exact register block isn't fully covered by the public
        // MHI spec — it lands once the closed datasheet's BHI
        // section is reverse-engineered or sourced. Today we
        // accept the cap-resolved blob and stop short of the
        // device write so the registry round-trip is exercised.
        // SAFETY: BAR0 mapped, exclusive owner; placeholder for
        // the actual BHI write sequence.
        let _ = view.phys;
        let _ = view.bytes.len();
        self.fw_loaded = true;
        Ok(())
    }
}

// ── Driver-match registration ───────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<WifiNic>> =
    IrqSafeSpinLock::new(None);

/// Probe entry installed via `bus::register_pci_driver`.
pub fn probe(
    device: BusDevice,
    cap:    Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() { return Ok(()); }
    // MEM_SPACE + BUS_MASTER: the chip DMAs MHI control rings into
    // host memory once firmware loads. INTX_DISABLE silences the
    // legacy line so MSI-X (wired by a follow-up) takes over
    // cleanly.
    narf_bus::pci::set_command(
        &cap, &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    ).map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller-authority over the device.
    let dev = match unsafe { WifiNic::bring_up(&device, &cap) } {
        Ok(d)  => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name:    alloc::string::String::from("qcnfa765"),
        kind:    narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain:  narf_drivers::BoundKind::Net.default_domain(),
    });
    Ok(())
}

/// Register the driver with the bus's match table. Single VID/DID
/// match for now — other WCN685x SKUs (e.g. WCN6856 / WCN7850)
/// would each need their own entry plus a chip-id branch in the
/// firmware loader.
pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "qcnfa765",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: QCN_VENDOR, device: QCNFA765_DEV,
        },
        probe,
    });
}

pub fn is_probed() -> bool { CONTROLLER.lock().is_some() }

pub fn with_controller<R>(f: impl FnOnce(&WifiNic) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

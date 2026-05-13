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
//! ## 2026 audit notes
//!
//! Qualcomm hosts the WCN685x firmware tree at
//! `git.codelinaro.org/clo/ath-firmware/ath11k-firmware` — signed
//! firmware blobs only, no register / WMI documentation. The WMI
//! command-set TLV definitions live in the Linux GPL-2.0 `ath11k`
//! / `ath12k` source trees and are off-limits for clean-room
//! consumption. Until Qualcomm publishes a programming guide,
//! this driver must stop at the BHI (primary-boot-loader) presence
//! check described below.
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

use core::sync::atomic::{compiler_fence, Ordering};

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

/// Qualcomm Technologies, Inc.
pub const QCN_VENDOR: u16 = 0x17CB;
/// QCNFA765 / WCN6855 WiFi 6E.
pub const QCNFA765_DEV: u16 = 0x1103;

/// BAR0 register-block offsets per the public MHI host spec. Real
/// WCN6855 silicon places the BHI block behind a runtime-readable
/// `BHIOFF` redirection word; bring-up reads `BHIOFF` from the
/// front-of-BAR window and uses that to locate BHI registers.
///
/// References:
///   - MHI Host Interface §4.2 (register layout)
///   - MHI Host Interface §3.2.4 (BHI boot sequence)
mod regs {
    // ── front-of-BAR (always at fixed offset) ─────────────────────
    /// MHI version register. `0xFFFFFFFF` ↔ device-gone presence test.
    pub const MHIVER: u64 = 0x0008;
    /// BHIOFF: BHI block offset within BAR0 (read once, cached).
    pub const BHIOFF: u64 = 0x0028;
    /// Sentinel — front-of-BAR reads for absent silicon.
    pub const MHIVER_GONE: u32 = 0xFFFF_FFFF;

    // ── BHI block (offsets RELATIVE to BHIOFF) ────────────────────
    /// BHI Boot Image transmit doorbell — write image length +
    /// sequence id here to kick off staging (§3.2.4).
    pub const BHI_IMGTXDB: u64 = 0x18;
    /// BHI Image Address — phys address of the staged image. Two
    /// 32-bit halves: low at +0x108, high at +0x10C.
    pub const BHI_IMGADDR_LO: u64 = 0x108;
    pub const BHI_IMGADDR_HI: u64 = 0x10C;
    /// BHI Image Size in bytes (§3.2.4 Table 3-3).
    pub const BHI_IMGSIZE: u64 = 0x110;
    /// BHI EXECENV — current execution environment (0=PBL, 1=SBL,
    /// 2=AMSS). Driver polls this to confirm firmware loaded.
    pub const BHI_EXECENV: u64 = 0x28;
    /// BHI STATUS — boot-loader writes 1 (success) / 2 (error)
    /// once it consumes the staged image.
    pub const BHI_STATUS: u64 = 0x2C;

    /// BHI_STATUS values (§3.2.4 Table 3-4).
    pub const BHI_STATUS_RESET: u32 = 0;
    pub const BHI_STATUS_SUCCESS: u32 = 1;
    pub const BHI_STATUS_ERROR: u32 = 2;

    /// EXECENV after AMSS firmware is running.
    pub const EXECENV_AMSS: u32 = 2;
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

/// One QCNFA765 host. Pre-firmware: BAR mapped, MHIVER read, BHI
/// offset cached. Post-firmware: AMSS staged + MHI engine in M0,
/// per-channel rings + 802.11 data plane attach.
pub struct WifiNic {
    pub mmio: MmioRegion,
    pub chip: ChipInfo,
    /// BHI register-block offset within BAR0, read from `BHIOFF`
    /// at bring-up. Cached so `load_firmware` doesn't re-read it.
    bhi_off: u64,
    /// `false` until firmware loading completes (BHI_STATUS reads
    /// SUCCESS + EXECENV reads AMSS).
    pub fw_loaded: bool,
}

impl core::fmt::Debug for WifiNic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WifiNic")
            .field("chip", &self.chip)
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
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, WifiError> {
        // SAFETY: caller-authority over BAR0.
        let mmio = unsafe { map_bar(device, 0) }.map_err(|_| WifiError::BarMapFailed)?;

        // Probe the MHI version register. A read of 0xFFFFFFFF
        // means the BAR window is mapped but no silicon is
        // backing it — D3cold, PCIe link down, or a missing
        // device. Anything else, we treat the device as alive.
        // SAFETY: identity-mapped MMIO.
        let mhi_version = unsafe { mmio.read32(regs::MHIVER) };
        if mhi_version == regs::MHIVER_GONE {
            return Err(WifiError::DeviceGone);
        }
        // Cache BHIOFF so `load_firmware` can address the BHI
        // register block without re-reading the redirection word.
        // SAFETY: identity-mapped MMIO; readable in PBL state.
        let bhi_off = unsafe { mmio.read32(regs::BHIOFF) } as u64;

        Ok(Self {
            mmio,
            chip: ChipInfo { mhi_version },
            bhi_off,
            fw_loaded: false,
        })
    }

    pub fn chip_info(&self) -> ChipInfo {
        self.chip
    }

    /// `true` once the (Stage-6) firmware loader has staged AMSS
    /// firmware via BHI + the MHI engine has reached M0.
    pub fn is_ready(&self) -> bool {
        self.fw_loaded
    }

    /// Stage AMSS firmware via BHI + drive the MHI engine into M0.
    ///
    /// Looks the AMSS image up by canonical name through the
    /// kernel firmware registry (`narf-firmware`), runs the BHI
    /// staging sequence per MHI spec §3.2.4, and waits for
    /// `BHI_STATUS = SUCCESS` plus `EXECENV = AMSS`. On real
    /// silicon the chip transitions PBL → SBL → AMSS and
    /// `MHISTATUS.READY` asserts within ~200 ms after that.
    ///
    /// BHI sequence:
    ///   1. Write image phys address (low / high) to
    ///      `BHI_IMGADDR_LO` / `BHI_IMGADDR_HI`.
    ///   2. Write image length to `BHI_IMGSIZE`.
    ///   3. Write `(0u32 << 16) | sequence_id` to `BHI_IMGTXDB`
    ///      to ring the boot-host doorbell.
    ///   4. Poll `BHI_STATUS` until non-zero. Success = 1, Error = 2.
    ///   5. Confirm `EXECENV` reads `AMSS` (= 2).
    ///
    /// Returns `FirmwareMissing` if the registry has no entry for
    /// the requested blob — typical before in-tree fallback or
    /// initramfs unpack stages the AMSS image. Returns
    /// `FirmwareLoadFailed` on any device-side failure or timeout.
    ///
    /// # Safety
    /// Caller owns BAR0 + cfg windows exclusively. The blob's
    /// `view().phys` must remain valid for the duration of the
    /// BHI handoff (the cap stays alive until the function
    /// returns).
    pub unsafe fn load_firmware(
        &mut self,
        fw_authority: &narf_capabilities::Cap<
            narf_firmware::FirmwareRegistry,
            narf_capabilities::Read,
        >,
    ) -> Result<(), WifiError> {
        let cap =
            narf_firmware::open("qcom/qcnfa765/amss.bin", fw_authority).map_err(|e| match e {
                narf_firmware::FirmwareError::NotFound => WifiError::FirmwareMissing,
                _ => WifiError::FirmwareLoadFailed,
            })?;
        let view = narf_firmware::view_of(&cap).map_err(|_| WifiError::FirmwareLoadFailed)?;

        let bhi = self.bhi_off;
        let phys = view.phys;
        let len = view.bytes.len() as u32;
        // Step 1+2: program image base + size.
        // SAFETY: BAR0 mapped, exclusive owner; bhi_off in-range.
        unsafe {
            self.mmio.write32(bhi + regs::BHI_IMGADDR_LO, phys as u32);
            self.mmio
                .write32(bhi + regs::BHI_IMGADDR_HI, (phys >> 32) as u32);
            self.mmio.write32(bhi + regs::BHI_IMGSIZE, len);
        }
        // Memory barrier so the device sees the staging writes
        // before the doorbell ring.
        compiler_fence(Ordering::SeqCst);

        // Step 3: ring the doorbell. Sequence id = 1; sufficient
        // for the first (and only) AMSS load this driver ever
        // does. Multi-stage loaders (PBL → SBL → AMSS) reuse the
        // same doorbell with monotonically-incrementing seq ids.
        // SAFETY: same.
        unsafe {
            self.mmio.write32(bhi + regs::BHI_IMGTXDB, 1);
        }

        // Step 4: poll BHI_STATUS. Spec says ~200 ms typical;
        // bound the wait so a wedged controller surfaces as
        // FirmwareLoadFailed rather than livelock. 1 s wall-clock
        // budget gives ample headroom over the typical ~200 ms.
        let mut status = regs::BHI_STATUS_RESET;
        narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: identity-mapped MMIO.
                status = unsafe { self.mmio.read32(bhi + regs::BHI_STATUS) };
                status != regs::BHI_STATUS_RESET
            },
            narf_time::Deadline::after_ms(1_000),
        );
        if status != regs::BHI_STATUS_SUCCESS {
            return Err(WifiError::FirmwareLoadFailed);
        }

        // Step 5: confirm EXECENV reads AMSS.
        // SAFETY: same.
        let env = unsafe { self.mmio.read32(bhi + regs::BHI_EXECENV) };
        if env != regs::EXECENV_AMSS {
            return Err(WifiError::FirmwareLoadFailed);
        }

        // Record the firmware-version coupling so the bound-driver
        // inventory + kernel crash bundles know which AMSS image
        // is running.
        let _ = view.bytes; // hold the borrow alive through the record
        narf_drivers::set_bound_firmware(
            "qcnfa765",
            narf_drivers::BoundFirmware {
                blob_name: alloc::string::String::from("qcom/qcnfa765/amss.bin"),
                sha256: view.sha256,
                signer: view.signer,
                version: None, // step-1 BlobView always emits None
            },
        );
        self.fw_loaded = true;
        Ok(())
    }
}

// ── Driver-match registration ───────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<WifiNic>> = IrqSafeSpinLock::new(None);

/// Probe entry installed via `bus::register_pci_driver`.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    // MEM_SPACE + BUS_MASTER: the chip DMAs MHI control rings into
    // host memory once firmware loads. INTX_DISABLE silences the
    // legacy line so MSI-X (wired by a follow-up) takes over
    // cleanly.
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller-authority over the device.
    let dev = match unsafe { WifiNic::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("qcnfa765"),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
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
            vendor: QCN_VENDOR,
            device: QCNFA765_DEV,
        },
        probe,
    });
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

pub fn with_controller<R>(f: impl FnOnce(&WifiNic) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

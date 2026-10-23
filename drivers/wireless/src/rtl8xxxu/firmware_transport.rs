//! Live RTL8188EU power and firmware transport over vendor USB control.
//!
//! Linux references: `rtl8xxxu/8188e.c::{rtl8188eu_power_on,
//! rtl8188e_emu_to_active,rtl8188eu_reset_8051}` and
//! `rtl8xxxu/core.c::{rtl8xxxu_load_firmware,rtl8xxxu_writeN,
//! rtl8xxxu_download_firmware,rtl8xxxu_start_firmware}`.
//!
//! Firmware-ready is a diagnostic stage. It does not enable the RF, install
//! PHY/calibration tables, publish a station interface, or authorize TX.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_drivers_usb::device::{USBDevice, UsbError};
use narf_firmware::FirmwareError;
use narf_lib::sync::IrqSafeSpinLock;

use super::regs::*;

const HEADER_LEN: usize = 32;
const MAX_PAYLOAD: usize = 8 * RTL_FW_PAGE_SIZE;
const CONTROL_CHUNK: usize = 196; // rtl8188eu_fops.writeN_block_size
const REG_LPLDO_CTRL: u16 = 0x23;
const REG_AFE_XTAL_CTRL: u16 = 0x24;
const MCU_RAM_SELECT: u8 = 1 << 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    UnsupportedChip,
    AlreadyStarted,
    InvalidImage,
    Firmware(FirmwareError),
    Usb(UsbError),
    ShortTransfer,
    PowerTimeout,
    ChecksumTimeout,
    StartTimeout,
    Deadline,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Detected,
    Validated,
    Powered,
    Downloading,
    FirmwareReady,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub stage: Stage,
    pub error: Option<Error>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirmwareInfo {
    pub signature: u16,
    pub major: u16,
    pub minor: u8,
    pub payload_bytes: usize,
}

/// Validate the chip-bound header and exact RAM-code extent before any USB
/// access. Other families have different power/reset/download requirements.
pub fn parse_image(chip: ChipFamily, blob: &[u8]) -> Result<(FirmwareInfo, &[u8]), Error> {
    if chip != ChipFamily::Rtl8188eu {
        return Err(Error::UnsupportedChip);
    }
    if blob.len() <= HEADER_LEN {
        return Err(Error::InvalidImage);
    }
    let signature = u16::from_le_bytes([blob[0], blob[1]]);
    let payload = &blob[HEADER_LEN..];
    let declared = u16::from_le_bytes([blob[12], blob[13]]) as usize;
    if signature & 0xfff0 != 0x88e0 || payload.len() != declared || payload.len() > MAX_PAYLOAD {
        return Err(Error::InvalidImage);
    }
    Ok((
        FirmwareInfo {
            signature,
            major: u16::from_le_bytes([blob[4], blob[5]]),
            minor: blob[6],
            payload_bytes: payload.len(),
        },
        payload,
    ))
}

/// All register and firmware writes use EP0 with request 0x05, value=address,
/// index=0. The trait requires exact-count checking at the owner boundary.
#[async_trait::async_trait]
pub trait ControlIo: Send + Sync {
    async fn read(&self, addr: u16, out: &mut [u8]) -> Result<usize, UsbError>;
    async fn write(&self, addr: u16, data: &[u8]) -> Result<usize, UsbError>;
    async fn delay_us(&self, us: u64) {
        narf_time::sleep_cycles(narf_time::ns_to_cycles(us.saturating_mul(1000))).await;
    }
}

/// Production transport retains the enumerated USB handle for the entire
/// attempt. The owner serializes its sequence; it never nests block_on in an
/// executor poll or holds an IRQ-disabling lock across USB awaits.
#[derive(Debug)]
pub struct UsbControl {
    device: Arc<USBDevice>,
}

impl UsbControl {
    pub fn new(device: Arc<USBDevice>) -> Self {
        Self { device }
    }
}

#[async_trait::async_trait]
impl ControlIo for UsbControl {
    async fn read(&self, addr: u16, out: &mut [u8]) -> Result<usize, UsbError> {
        self.device
            .control_in(REALTEK_USB_READ, REALTEK_USB_CMD_REQ, addr, 0, out)
            .await
    }

    async fn write(&self, addr: u16, data: &[u8]) -> Result<usize, UsbError> {
        self.device
            .control_out(REALTEK_USB_WRITE, REALTEK_USB_CMD_REQ, addr, 0, data)
            .await
    }
}

/// A retained, one-shot initialization attempt. A failed or cancelled owner
/// cannot replay register writes; recovery requires a fresh device lifecycle.
pub struct Owner<I: ControlIo> {
    io: I,
    chip: ChipFamily,
    started: AtomicBool,
    status: IrqSafeSpinLock<Status>,
}

impl<I: ControlIo> core::fmt::Debug for Owner<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8xxxuFirmwareOwner")
            .field("chip", &self.chip)
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}

struct Attempt<'a, I: ControlIo>(&'a Owner<I>);

impl<I: ControlIo> Drop for Attempt<'_, I> {
    fn drop(&mut self) {
        let mut state = self.0.status.lock();
        if !matches!(state.stage, Stage::FirmwareReady | Stage::Failed) {
            state.stage = Stage::Failed;
            state.error = Some(Error::Cancelled);
        }
    }
}

impl<I: ControlIo> Owner<I> {
    pub fn new(io: I, chip: ChipFamily) -> Self {
        Self {
            io,
            chip,
            started: AtomicBool::new(false),
            status: IrqSafeSpinLock::new(Status {
                stage: Stage::Detected,
                error: None,
            }),
        }
    }

    pub fn status(&self) -> Status {
        *self.status.lock()
    }

    fn stage(&self, stage: Stage) {
        *self.status.lock() = Status { stage, error: None };
    }

    fn begin(&self) -> Result<Attempt<'_, I>, Error> {
        self.started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::AlreadyStarted)?;
        Ok(Attempt(self))
    }

    fn finish(&self, result: Result<FirmwareInfo, Error>) -> Result<FirmwareInfo, Error> {
        match result {
            Ok(_) => self.stage(Stage::FirmwareReady),
            Err(error) => {
                *self.status.lock() = Status {
                    stage: Stage::Failed,
                    error: Some(error),
                }
            }
        }
        result
    }

    /// The production probe path obtains the blob from the capability-gated
    /// firmware registry. Keep its cap alive through every USB transfer.
    pub async fn initialize_registered(&self) -> Result<FirmwareInfo, Error> {
        let _attempt = self.begin()?;
        let result = async {
            if self.chip != ChipFamily::Rtl8188eu {
                return Err(Error::UnsupportedChip);
            }
            let loader = narf_firmware::trusted_loader_authority()
                .ok_or(Error::Firmware(FirmwareError::AuthorityRevoked))?;
            let auth = loader
                .derive()
                .map_err(|_| Error::Firmware(FirmwareError::AuthorityRevoked))?;
            let cap =
                narf_firmware::open("rtlwifi/rtl8188eufw.bin", &auth).map_err(Error::Firmware)?;
            let view = narf_firmware::view_of(&cap).map_err(Error::Firmware)?;
            // Own the validated bytes before awaiting USB so registry
            // revocation cannot invalidate an outstanding borrowed view.
            let _ = parse_image(self.chip, view.bytes)?;
            let bytes = view.bytes.to_vec();
            self.run_before(&bytes, narf_time::Deadline::after_ms(30_000))
                .await
        }
        .await;
        self.finish(result)
    }

    /// Exercise the same production sequence against a supplied blob. The
    /// USB probe uses initialize_registered; this entry point supports tests
    /// and a caller that already owns authenticated firmware bytes.
    pub async fn initialize(&self, blob: &[u8]) -> Result<FirmwareInfo, Error> {
        self.initialize_before(blob, narf_time::Deadline::after_ms(30_000))
            .await
    }

    // Same one-shot ownership path, with an injected deadline for service
    // policy and active-TD timeout regressions.
    pub(super) async fn initialize_before(
        &self,
        blob: &[u8],
        deadline: narf_time::Deadline,
    ) -> Result<FirmwareInfo, Error> {
        let _attempt = self.begin()?;
        let result = self.run_before(blob, deadline).await;
        self.finish(result)
    }

    async fn run_before(
        &self,
        blob: &[u8],
        deadline: narf_time::Deadline,
    ) -> Result<FirmwareInfo, Error> {
        let (info, payload) = parse_image(self.chip, blob)?;
        self.stage(Stage::Validated);
        narf_time::timeout(deadline, async {
            self.power_on().await?;
            self.stage(Stage::Powered);
            self.download(payload).await?;
            Ok(info)
        })
        .await
        .unwrap_or(Err(Error::Deadline))
        // Never issue cleanup transfers here. xHCI's EP0 error/deadline and
        // Future::drop do not establish Stop Endpoint + TD drain. Its
        // persistent per-slot control-data buffer may still belong to the
        // prior TD even after UsbError, so another read/write would reuse it.
        // The one-shot owner remains terminal; controller-level quiescence
        // and a fresh USB lifecycle are required before any recovery I/O.
    }

    async fn read<const N: usize>(&self, addr: u16) -> Result<[u8; N], Error> {
        let mut bytes = [0; N];
        let count = self.io.read(addr, &mut bytes).await.map_err(Error::Usb)?;
        if count != N {
            return Err(Error::ShortTransfer);
        }
        Ok(bytes)
    }
    async fn read8(&self, addr: u16) -> Result<u8, Error> {
        Ok(self.read::<1>(addr).await?[0])
    }
    async fn read16(&self, addr: u16) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.read(addr).await?))
    }
    async fn read32(&self, addr: u16) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.read(addr).await?))
    }
    async fn write(&self, addr: u16, bytes: &[u8]) -> Result<(), Error> {
        if self.io.write(addr, bytes).await.map_err(Error::Usb)? != bytes.len() {
            return Err(Error::ShortTransfer);
        }
        Ok(())
    }
    async fn write8(&self, addr: u16, value: u8) -> Result<(), Error> {
        self.write(addr, &[value]).await
    }
    async fn write16(&self, addr: u16, value: u16) -> Result<(), Error> {
        self.write(addr, &value.to_le_bytes()).await
    }
    async fn write32(&self, addr: u16, value: u32) -> Result<(), Error> {
        self.write(addr, &value.to_le_bytes()).await
    }

    async fn poll(
        &self,
        addr: u16,
        mask: u32,
        expected: u32,
        count: usize,
        delay: u64,
        error: Error,
    ) -> Result<(), Error> {
        for _ in 0..count {
            if self.read32(addr).await? & mask == expected {
                return Ok(());
            }
            self.io.delay_us(delay).await;
        }
        Err(error)
    }

    async fn power_on(&self) -> Result<(), Error> {
        let value = self.read16(REG_APS_FSMCO).await?;
        self.write16(REG_APS_FSMCO, value & !((1 << 11) | (1 << 12)))
            .await?;
        self.poll(
            REG_APS_FSMCO,
            1 << 17,
            1 << 17,
            MAX_REG_POLL,
            10,
            Error::PowerTimeout,
        )
        .await?;
        let value = self.read8(REG_SYS_FUNC).await?;
        self.write8(REG_SYS_FUNC, value & !3).await?;
        let value = self.read32(REG_AFE_XTAL_CTRL).await?;
        self.write32(REG_AFE_XTAL_CTRL, value | (1 << 23)).await?;
        let value = self.read16(REG_APS_FSMCO).await?;
        self.write16(REG_APS_FSMCO, value & !(1 << 15)).await?;
        let value = self.read16(REG_APS_FSMCO).await?;
        self.write16(REG_APS_FSMCO, value & !((1 << 11) | (1 << 12)))
            .await?;
        let value = self.read32(REG_APS_FSMCO).await?;
        self.write32(REG_APS_FSMCO, value | APS_FSMCO_MAC_ENABLE)
            .await?;
        self.poll(
            REG_APS_FSMCO,
            APS_FSMCO_MAC_ENABLE,
            0,
            MAX_REG_POLL,
            10,
            Error::PowerTimeout,
        )
        .await?;
        let value = self.read8(REG_LPLDO_CTRL).await?;
        self.write8(REG_LPLDO_CTRL, value & !(1 << 4)).await?;
        // Linux deliberately leaves MAC TX/RX disabled until TRXFF_BNDY is
        // configured, due to the 8188E RX FIFO boundary hardware erratum.
        self.write16(REG_CR, 0x063f).await
    }

    async fn reset_8051(&self) -> Result<(), Error> {
        let value = self.read16(REG_SYS_FUNC).await?;
        self.write16(REG_SYS_FUNC, value & !SYS_FUNC_CPU_ENABLE)
            .await?;
        self.write16(REG_SYS_FUNC, value | SYS_FUNC_CPU_ENABLE)
            .await
    }

    async fn download(&self, payload: &[u8]) -> Result<(), Error> {
        self.stage(Stage::Downloading);
        let value = self.read8(REG_SYS_FUNC + 1).await?;
        self.write8(REG_SYS_FUNC + 1, value | 4).await?;
        let value = self.read16(REG_SYS_FUNC).await?;
        self.write16(REG_SYS_FUNC, value | SYS_FUNC_CPU_ENABLE)
            .await?;
        if self.read8(REG_MCU_FW_DL).await? & MCU_RAM_SELECT != 0 {
            self.write8(REG_MCU_FW_DL, 0).await?;
            self.reset_8051().await?;
        }
        let value = self.read8(REG_MCU_FW_DL).await?;
        self.write8(REG_MCU_FW_DL, value | MCU_FW_DL_ENABLE).await?;
        let value = self.read32(REG_MCU_FW_DL).await?;
        self.write32(REG_MCU_FW_DL, value & !(1 << 19)).await?;
        let value = self.read8(REG_MCU_FW_DL).await?;
        self.write8(REG_MCU_FW_DL, value | MCU_FW_DL_CSUM_REPORT)
            .await?;
        for (page, bytes) in payload.chunks(RTL_FW_PAGE_SIZE).enumerate() {
            let value = self.read8(REG_MCU_FW_DL + 2).await?;
            self.write8(REG_MCU_FW_DL + 2, (value & 0xf8) | page as u8)
                .await?;
            for (chunk, bytes) in bytes.chunks(CONTROL_CHUNK).enumerate() {
                let addr = REG_FW_START_ADDRESS + (chunk * CONTROL_CHUNK) as u16;
                self.write(addr, bytes).await?;
            }
        }
        let value = self.read16(REG_MCU_FW_DL).await?;
        self.write16(REG_MCU_FW_DL, value & !(MCU_FW_DL_ENABLE as u16))
            .await?;
        self.poll(
            REG_MCU_FW_DL,
            MCU_FW_DL_CSUM_REPORT as u32,
            MCU_FW_DL_CSUM_REPORT as u32,
            FW_POLL_MAX,
            0,
            Error::ChecksumTimeout,
        )
        .await?;
        let value = self.read32(REG_MCU_FW_DL).await?;
        self.write32(
            REG_MCU_FW_DL,
            (value | MCU_FW_DL_READY as u32) & !MCU_WINT_INIT_READY,
        )
        .await?;
        self.reset_8051().await?;
        self.poll(
            REG_MCU_FW_DL,
            MCU_WINT_INIT_READY,
            MCU_WINT_INIT_READY,
            FW_POLL_MAX,
            100,
            Error::StartTimeout,
        )
        .await
    }
}

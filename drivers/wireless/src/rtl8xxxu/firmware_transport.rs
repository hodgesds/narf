//! Live RTL8188EU/RTL8192EU power and firmware transport over vendor USB
//! control. RTL8192EU chip steps live in `rtl8192e_init`.
//!
//! Linux references: `rtl8xxxu/8188e.c::{rtl8188eu_power_on,
//! rtl8188e_emu_to_active,rtl8188eu_reset_8051}` and
//! `rtl8xxxu/core.c::{rtl8xxxu_load_firmware,rtl8xxxu_writeN,
//! rtl8xxxu_download_firmware,rtl8xxxu_start_firmware}`.
//!
//! Production initialization continues through checked RTL8188EU tables,
//! post-table MAC state and full LC/IQK. MAC TX/RX remain closed; neither
//! firmware-ready nor radio-ready publishes a station or authorizes packets.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use narf_drivers_usb::device::{USBDevice, UsbError};
use narf_firmware::FirmwareError;
use narf_lib::sync::IrqSafeSpinLock;

use super::regs::*;

const HEADER_LEN: usize = 32;
const MAX_PAYLOAD: usize = 8 * RTL_FW_PAGE_SIZE;
const CONTROL_CHUNK: usize = 196; // rtl8188eu_fops.writeN_block_size

/// `rtl8xxxu_fileops.writeN_block_size` of the families with a native owner.
fn control_chunk(chip: ChipFamily) -> usize {
    match chip {
        ChipFamily::Rtl8192eu => super::rtl8192e::WRITEN_BLOCK_SIZE,
        ChipFamily::Rtl8723bu => super::rtl8723b_init::WRITEN_BLOCK_SIZE,
        _ => CONTROL_CHUNK,
    }
}

/// `rtl8xxxu_load_firmware` signature family accepted per chip.
fn firmware_signature(chip: ChipFamily) -> Option<u16> {
    match chip {
        ChipFamily::Rtl8188eu => Some(0x88e0),
        ChipFamily::Rtl8192eu => Some(0x92e0),
        ChipFamily::Rtl8723bu => Some(super::rtl8723b_init::FIRMWARE_SIGNATURE),
        _ => None,
    }
}
const REG_LPLDO_CTRL: u16 = 0x23;
const REG_AFE_XTAL_CTRL: u16 = 0x24;
const MCU_RAM_SELECT: u8 = 1 << 7;

#[path = "runtime_restart.rs"]
mod runtime_restart;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    UnsupportedChip,
    UnsupportedSilicon,
    BadEndpoints,
    BadEfuse,
    EfuseTimeout,
    LltTimeout,
    RadioRead,
    Calibration,
    RuntimeBusy,
    RuntimeState,
    CamTimeout,
    AlreadyStarted,
    InvalidImage,
    Firmware(FirmwareError),
    Usb(UsbError),
    ShortTransfer,
    PowerTimeout,
    ChecksumTimeout,
    StartTimeout,
    MailboxBusy,
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
    FactoryReady,
    TablesReady,
    InitializingTables,
    Calibrating,
    RadioReady,
    StartingReceive,
    Receiving,
    ReceiveStopped,
    Parking,
    Parked,
    Restarting,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub stage: Stage,
    pub error: Option<Error>,
}

/// RTL8192EU radio state retained at RadioReady.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Radio8192e {
    pub iqk: super::rtl8192e_iqk::Iqk,
    pub post: super::rtl8192e_radio::PostCalibration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CalibrationInfo {
    pub tx_x: u16,
    pub tx_y: u16,
    pub rx_x: u16,
    pub rx_y: u16,
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
    let family = firmware_signature(chip).ok_or(Error::UnsupportedChip)?;
    if blob.len() <= HEADER_LEN {
        return Err(Error::InvalidImage);
    }
    let signature = u16::from_le_bytes([blob[0], blob[1]]);
    let payload = &blob[HEADER_LEN..];
    let declared = u16::from_le_bytes([blob[12], blob[13]]) as usize;
    if signature & 0xfff0 != family || payload.len() != declared || payload.len() > MAX_PAYLOAD {
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
    #[cfg(any(test, feature = "kernel-test"))]
    fn inert_source_fixture(&self) -> bool {
        false
    }
    fn identity(&self) -> Option<(u16, u16)> {
        None
    }
    async fn read(&self, addr: u16, out: &mut [u8]) -> Result<usize, UsbError>;
    async fn write(&self, addr: u16, data: &[u8]) -> Result<usize, UsbError>;
    async fn configuration(&self, _out: &mut [u8]) -> Result<usize, UsbError> {
        Err(UsbError::NotConfigured)
    }
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
    fn identity(&self) -> Option<(u16, u16)> {
        Some((self.device.vendor_id(), self.device.product_id()))
    }
    async fn configuration(&self, out: &mut [u8]) -> Result<usize, UsbError> {
        self.device.get_config_descriptor(0, out).await
    }
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
    identity: Option<(u16, u16)>,
    started: AtomicBool,
    status: IrqSafeSpinLock<Status>,
    factory: IrqSafeSpinLock<Option<super::device_init::Factory>>,
    calibration: IrqSafeSpinLock<Option<CalibrationInfo>>,
    endpoints: IrqSafeSpinLock<Option<super::device_init::Endpoints>>,
    runtime_taken: AtomicBool,
    executable: IrqSafeSpinLock<Option<Executable>>,
    // Exact uploaded image; a restart invokes its original executable cap.
    runtime_image: IrqSafeSpinLock<Option<Arc<[u8]>>>,
    // RTL8192EU factory/queue facts and gen2 H2C mailbox state.
    factory_8192e: IrqSafeSpinLock<Option<super::rtl8192e_init::Factory>>,
    queues_8192e: IrqSafeSpinLock<Option<super::rtl8192e_init::QueueMap>>,
    radio_8192e: IrqSafeSpinLock<Option<Radio8192e>>,
    // RTL8723BU factory/queue facts (`rtl8723b_init`).
    factory_8723b: IrqSafeSpinLock<Option<super::rtl8723b_init::Factory>>,
    queues_8723b: IrqSafeSpinLock<Option<super::rtl8192e_init::QueueMap>>,
    h2c_next: AtomicU8,
    h2c_busy: AtomicBool,
}

/// Identity of the exact immutable image uploaded by this retained owner.
/// The cap is retained after loading; a filename or digest alone is not current authority.
#[derive(Clone, Copy)]
pub(super) struct Executable {
    pub(super) digest: [u8; 32],
    source: Option<narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>>,
    inert_fixture: bool,
}
impl Executable {
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn source_cap(
        &self,
    ) -> Option<narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>> {
        self.source
    }
    fn new(
        bytes: &[u8],
        source: Option<
            narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>,
        >,
        inert_fixture: bool,
    ) -> Self {
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(bytes);
        Self {
            digest: hash.finalize(),
            source,
            inert_fixture,
        }
    }
    pub(super) fn invoke<T>(&self, operation: impl FnOnce() -> T) -> Result<T, Error> {
        use narf_capabilities::{Cap, CapError, CapOp, Read};
        struct Current<F>(F);
        impl<T, F: FnOnce() -> T> CapOp<narf_firmware::FirmwareBlob, Read> for Current<F> {
            type Output = T;
            fn execute(self, _: &Cap<narf_firmware::FirmwareBlob, Read>) -> Result<T, CapError> {
                Ok((self.0)())
            }
        }
        if let Some(cap) = self.source {
            return cap
                .invoke(Current(operation))
                .map_err(|_| Error::Firmware(FirmwareError::AuthorityRevoked));
        }
        #[cfg(any(test, feature = "kernel-test"))]
        if self.inert_fixture {
            return Ok(operation());
        }
        Err(Error::Firmware(FirmwareError::AuthorityRevoked))
    }
    pub(super) async fn fence<T>(
        &self,
        future: impl core::future::Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        let mut future = core::pin::pin!(future);
        core::future::poll_fn(|cx| {
            self.invoke(|| future.as_mut().poll(cx))
                .unwrap_or_else(|e| core::task::Poll::Ready(Err(e)))
        })
        .await
    }
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
        if !matches!(
            state.stage,
            Stage::FirmwareReady | Stage::TablesReady | Stage::RadioReady | Stage::Failed
        ) {
            state.stage = Stage::Failed;
            state.error = Some(Error::Cancelled);
        }
    }
}

impl<I: ControlIo> Owner<I> {
    pub fn new(io: I, chip: ChipFamily) -> Self {
        let identity = io.identity();
        Self {
            identity,
            io,
            chip,
            started: AtomicBool::new(false),
            factory: IrqSafeSpinLock::new(None),
            calibration: IrqSafeSpinLock::new(None),
            endpoints: IrqSafeSpinLock::new(None),
            runtime_taken: AtomicBool::new(false),
            executable: IrqSafeSpinLock::new(None),
            runtime_image: IrqSafeSpinLock::new(None),
            factory_8192e: IrqSafeSpinLock::new(None),
            queues_8192e: IrqSafeSpinLock::new(None),
            radio_8192e: IrqSafeSpinLock::new(None),
            factory_8723b: IrqSafeSpinLock::new(None),
            queues_8723b: IrqSafeSpinLock::new(None),
            h2c_next: AtomicU8::new(0),
            h2c_busy: AtomicBool::new(false),
            status: IrqSafeSpinLock::new(Status {
                stage: Stage::Detected,
                error: None,
            }),
        }
    }

    pub fn usb_identity(&self) -> Option<(u16, u16)> {
        self.identity
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
            Ok(_) => {
                if !matches!(self.status().stage, Stage::TablesReady | Stage::RadioReady) {
                    self.stage(Stage::FirmwareReady);
                }
            }
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
        if self.started.load(Ordering::Acquire) {
            return Err(Error::AlreadyStarted);
        }
        let loader = narf_firmware::trusted_loader_authority()
            .ok_or(Error::Firmware(FirmwareError::AuthorityRevoked))?;
        let authority = loader
            .derive()
            .map_err(|_| Error::Firmware(FirmwareError::AuthorityRevoked))?;
        let name = self.chip.firmware_name().ok_or(Error::UnsupportedChip)?;
        self.initialize_registered_from(&authority, name).await
    }
    pub async fn wait_initialize_registered(&self) -> Result<FirmwareInfo, Error> {
        loop {
            match self.initialize_registered().await {
                Err(error)
                    if !self.started.load(Ordering::Acquire)
                        && firmware_missing(
                            error,
                            narf_firmware::trusted_loader_authority().is_some(),
                        ) =>
                {
                    self.io.delay_us(500_000).await;
                }
                result => return result,
            }
        }
    }
    pub(super) async fn initialize_registered_from(
        &self,
        authority: &narf_capabilities::Cap<
            narf_firmware::FirmwareRegistry,
            narf_capabilities::Read,
        >,
        name: &str,
    ) -> Result<FirmwareInfo, Error> {
        if self.started.load(Ordering::Acquire) {
            return Err(Error::AlreadyStarted);
        }
        if firmware_signature(self.chip).is_none() {
            return Err(Error::UnsupportedChip);
        }
        let asset = crate::firmware_asset::load(authority, name, HEADER_LEN + MAX_PAYLOAD, false)
            .map_err(Error::Firmware)?;
        let _ = parse_image(self.chip, &asset.bytes)?;
        let _attempt = self.begin()?;
        let executable = Executable::new(&asset.bytes, Some(asset.cap), false);
        *self.executable.lock() = Some(executable);
        let result = executable
            .fence(self.run_device_before(&asset.bytes, narf_time::Deadline::after_ms(30_000)))
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

    /// Initialize the source-matched RTL8188EU factory/FIFO and register
    /// tables and checked LC/IQ calibration. This is not packet readiness;
    /// MAC TX/RX gates remain closed. Production initialize_registered follows this path.
    pub async fn initialize_device(&self, blob: &[u8]) -> Result<FirmwareInfo, Error> {
        let _attempt = self.begin()?;
        let result = self
            .run_device_before(blob, narf_time::Deadline::after_ms(30_000))
            .await;
        self.finish(result)
    }

    pub fn factory(&self) -> Option<super::device_init::Factory> {
        *self.factory.lock()
    }

    /// RTL8192EU identity/EFUSE facts once `FactoryReady` was reached.
    pub fn factory_8192e(&self) -> Option<super::rtl8192e_init::Factory> {
        *self.factory_8192e.lock()
    }

    /// RTL8192EU IQK outcome and post-calibration state once RadioReady.
    pub fn radio_8192e(&self) -> Option<Radio8192e> {
        *self.radio_8192e.lock()
    }

    /// RTL8192EU TX queue to bulk-OUT endpoint map installed before firmware.
    pub fn queues_8192e(&self) -> Option<super::rtl8192e_init::QueueMap> {
        *self.queues_8192e.lock()
    }

    /// RTL8723BU identity/EFUSE facts once `FactoryReady` was reached.
    pub fn factory_8723b(&self) -> Option<super::rtl8723b_init::Factory> {
        *self.factory_8723b.lock()
    }

    /// RTL8723BU TX queue to bulk-OUT endpoint map installed before firmware.
    pub fn queues_8723b(&self) -> Option<super::rtl8192e_init::QueueMap> {
        *self.queues_8723b.lock()
    }

    pub fn chip(&self) -> ChipFamily {
        self.chip
    }

    /// Exclusive gen2 H2C mailbox claim; a concurrent command is refused.
    pub(super) fn h2c_claim(&self) -> Result<super::rtl8192e_init::H2cClaim<'_>, Error> {
        if !matches!(self.chip, ChipFamily::Rtl8192eu | ChipFamily::Rtl8723bu) {
            return Err(Error::UnsupportedChip);
        }
        self.h2c_busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::RuntimeBusy)?;
        Ok(super::rtl8192e_init::H2cClaim {
            next: &self.h2c_next,
            busy: &self.h2c_busy,
        })
    }

    pub(super) fn executable(&self) -> Option<Executable> {
        *self.executable.lock()
    }
    /// Resolve the exact optional measurement request without modifying the
    /// parked radio or inventing an envelope. This is not an HT grant.
    pub fn ht20_request(&self) -> Result<super::Ht20Request, Error> {
        let executable = self.executable().ok_or(Error::RuntimeState)?;
        executable.invoke(|| ())?;
        let factory = self.factory().ok_or(Error::RuntimeState)?;
        let (vid, pid) = self.usb_identity().ok_or(Error::RuntimeState)?;
        let calibration = super::power_policy::Calibration::load_registered(factory, vid, pid)
            .map_err(|_| Error::RuntimeState)?;
        let domain = narf_wireless::reg::db::ensure_domain().map_err(|_| Error::RuntimeState)?;
        let permission = calibration
            .permission(&domain, 1)
            .map_err(|_| Error::RuntimeState)?;
        let base = super::wmm_runtime::Proof::registered(factory, vid, pid, permission)
            .map_err(|_| Error::RuntimeState)?;
        Ok(super::ht_runtime::request(&base, executable))
    }

    /// Resolve the signed v2 full20/40 program request for this primary and
    /// secondary. This performs no radio I/O and grants no native HT mode.
    pub fn ht40_request(&self, primary: u8, secondary: u8) -> Result<super::Ht40Request, Error> {
        let geometry = super::ht_runtime::Geometry::new(primary, secondary)
            .map_err(|_| Error::RuntimeState)?;
        let executable = self.executable().ok_or(Error::RuntimeState)?;
        executable.invoke(|| ())?;
        let factory = self.factory().ok_or(Error::RuntimeState)?;
        let (vid, pid) = self.usb_identity().ok_or(Error::RuntimeState)?;
        let calibration = super::power_policy::Calibration::load_registered(factory, vid, pid)
            .map_err(|_| Error::RuntimeState)?;
        let domain = narf_wireless::reg::db::ensure_domain().map_err(|_| Error::RuntimeState)?;
        geometry.ceiling(&domain).map_err(|_| Error::RuntimeState)?;
        let permission = calibration
            .permission(&domain, primary)
            .map_err(|_| Error::RuntimeState)?;
        let base = super::wmm_runtime::Proof::registered(factory, vid, pid, permission)
            .map_err(|_| Error::RuntimeState)?;
        base.invoke(|| ()).map_err(|_| Error::RuntimeState)?;
        Ok(super::ht_runtime::wide_request(&base, executable, geometry))
    }

    pub fn calibration(&self) -> Option<CalibrationInfo> {
        *self.calibration.lock()
    }

    pub fn endpoints(&self) -> Option<super::device_init::Endpoints> {
        *self.endpoints.lock()
    }

    pub(super) fn claim_receive(&self) -> Result<(), Error> {
        if self.status().stage != Stage::RadioReady {
            return Err(Error::RuntimeState);
        }
        self.runtime_taken
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::RuntimeBusy)?;
        self.stage(Stage::StartingReceive);
        Ok(())
    }
    pub(super) fn receiving(&self) {
        self.stage(Stage::Receiving);
    }
    pub(super) fn receive_stopped(&self) {
        self.stage(Stage::ReceiveStopped);
    }
    pub(super) fn runtime_failed(&self, error: Error) {
        *self.status.lock() = Status {
            stage: Stage::Failed,
            error: Some(error),
        };
    }

    async fn run_device_before(
        &self,
        blob: &[u8],
        deadline: narf_time::Deadline,
    ) -> Result<FirmwareInfo, Error> {
        self.run_device_expected(blob, deadline, None).await
    }

    async fn run_device_expected(
        &self,
        blob: &[u8],
        deadline: narf_time::Deadline,
        expected: Option<(super::device_init::Factory, super::device_init::Endpoints)>,
    ) -> Result<FirmwareInfo, Error> {
        let (info, payload) = parse_image(self.chip, blob)?;
        if self.executable.lock().is_none() {
            #[cfg(any(test, feature = "kernel-test"))]
            let inert = self.io.inert_source_fixture();
            #[cfg(not(any(test, feature = "kernel-test")))]
            let inert = false;
            *self.executable.lock() = Some(Executable::new(blob, None, inert));
        }
        if self.runtime_image.lock().is_none() {
            *self.runtime_image.lock() = Some(Arc::from(blob));
        }
        self.stage(Stage::Validated);
        narf_time::timeout(deadline, async {
            let mut config = alloc::vec![0; 4096];
            let count = self
                .io
                .configuration(&mut config)
                .await
                .map_err(Error::Usb)?;
            if count > config.len() {
                return Err(Error::BadEndpoints);
            }
            let endpoints = super::device_init::endpoints(&config[..count])?;
            if self.chip == ChipFamily::Rtl8192eu {
                return self.run_device_8192e(payload, endpoints, info).await;
            }
            if self.chip == ChipFamily::Rtl8723bu {
                return self.run_device_8723b(payload, endpoints, info).await;
            }
            let factory = super::device_init::factory(self).await?;
            if expected.is_some_and(|old| old != (factory, endpoints)) {
                return Err(Error::BadEfuse);
            }
            *self.endpoints.lock() = Some(endpoints);
            *self.factory.lock() = Some(factory);
            self.stage(Stage::FactoryReady);
            self.power_on().await?;
            super::device_init::pre_firmware(self, endpoints).await?;
            self.stage(Stage::Powered);
            self.download(payload).await?;
            self.stage(Stage::InitializingTables);
            super::device_init::mac_bb_rf(self, factory).await?;
            self.stage(Stage::TablesReady);
            self.stage(Stage::Calibrating);
            let iq = super::radio_init::configure(self, factory).await?;
            *self.calibration.lock() = Some(CalibrationInfo {
                tx_x: iq.tx_x,
                tx_y: iq.tx_y,
                rx_x: iq.rx_x,
                rx_y: iq.rx_y,
            });
            self.stage(Stage::RadioReady);
            Ok(info)
        })
        .await
        .unwrap_or(Err(Error::Deadline))
    }

    /// RTL8192EU `rtl8xxxu_probe` identify/EFUSE then `rtl8xxxu_init_device`
    /// through firmware start, the MAC/BB/RF tables, the post-table MAC
    /// stage, LC + two-path IQ calibration and the post-calibration tail, in
    /// Linux order. Channel and packet stages belong to the station owner.
    /// RadioReady is not packet readiness.
    async fn run_device_8192e(
        &self,
        payload: &[u8],
        endpoints: super::device_init::Endpoints,
        info: FirmwareInfo,
    ) -> Result<FirmwareInfo, Error> {
        let factory = super::rtl8192e_init::factory(self, endpoints).await?;
        *self.endpoints.lock() = Some(endpoints);
        *self.factory_8192e.lock() = Some(factory);
        self.stage(Stage::FactoryReady);
        self.power_on().await?;
        let queues = super::rtl8192e_init::pre_firmware(self, factory).await?;
        *self.queues_8192e.lock() = Some(queues);
        self.stage(Stage::Powered);
        self.download(payload).await?;
        self.stage(Stage::InitializingTables);
        super::rtl8192e_phy::mac_bb_rf(self, &factory).await?;
        super::rtl8192e_radio::post_tables(self, &factory).await?;
        self.stage(Stage::TablesReady);
        self.stage(Stage::Calibrating);
        let tx_paths = factory.identity.tx_paths;
        super::rtl8192e_iqk::lc_calibrate(self, tx_paths).await?;
        let iqk = super::rtl8192e_iqk::iq_calibrate(self, tx_paths).await?;
        let post = super::rtl8192e_radio::post_calibration(self).await?;
        *self.radio_8192e.lock() = Some(Radio8192e { iqk, post });
        self.stage(Stage::RadioReady);
        Ok(info)
    }

    /// RTL8723BU `rtl8xxxu_probe` identify/EFUSE then `rtl8xxxu_init_device`
    /// through power-on, reserved pages/queue priority/RX boundary, firmware
    /// download/start, the `init_reg_hmtfr` H2C init, antenna selection and
    /// the MAC/BB/RF tables through HIMR. The owner stops at TablesReady:
    /// post-table MAC, calibration and the radio tail are not implemented.
    async fn run_device_8723b(
        &self,
        payload: &[u8],
        endpoints: super::device_init::Endpoints,
        info: FirmwareInfo,
    ) -> Result<FirmwareInfo, Error> {
        let factory = super::rtl8723b_init::factory(self, endpoints).await?;
        *self.endpoints.lock() = Some(endpoints);
        *self.factory_8723b.lock() = Some(factory);
        self.stage(Stage::FactoryReady);
        self.power_on().await?;
        let queues = super::rtl8723b_init::pre_firmware(self, factory).await?;
        *self.queues_8723b.lock() = Some(queues);
        self.stage(Stage::Powered);
        self.download(payload).await?;
        self.stage(Stage::InitializingTables);
        super::rtl8723b_phy::mac_bb_rf(self, &factory).await?;
        self.stage(Stage::TablesReady);
        Ok(info)
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

    pub(super) async fn delay_us(&self, us: u64) {
        self.io.delay_us(us).await;
    }

    async fn read<const N: usize>(&self, addr: u16) -> Result<[u8; N], Error> {
        let mut bytes = [0; N];
        let executable = self.executable();
        let read = async { self.io.read(addr, &mut bytes).await.map_err(Error::Usb) };
        let count = if let Some(executable) = executable {
            executable.fence(read).await?
        } else {
            read.await?
        };
        if count != N {
            return Err(Error::ShortTransfer);
        }
        Ok(bytes)
    }
    pub(super) async fn read8(&self, addr: u16) -> Result<u8, Error> {
        Ok(self.read::<1>(addr).await?[0])
    }
    pub(super) async fn read16(&self, addr: u16) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.read(addr).await?))
    }
    pub(super) async fn read32(&self, addr: u16) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.read(addr).await?))
    }
    async fn write(&self, addr: u16, bytes: &[u8]) -> Result<(), Error> {
        let executable = self.executable();
        let write = async { self.io.write(addr, bytes).await.map_err(Error::Usb) };
        let count = if let Some(executable) = executable {
            executable.fence(write).await?
        } else {
            write.await?
        };
        if count != bytes.len() {
            return Err(Error::ShortTransfer);
        }
        Ok(())
    }
    pub(super) async fn write8(&self, addr: u16, value: u8) -> Result<(), Error> {
        self.write(addr, &[value]).await
    }
    pub(super) async fn write16(&self, addr: u16, value: u16) -> Result<(), Error> {
        self.write(addr, &value.to_le_bytes()).await
    }
    pub(super) async fn write32(&self, addr: u16, value: u32) -> Result<(), Error> {
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
        if self.chip == ChipFamily::Rtl8192eu {
            return super::rtl8192e_init::power_on(self).await;
        }
        if self.chip == ChipFamily::Rtl8723bu {
            return super::rtl8723b_init::power_on(self).await;
        }
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
        if self.chip == ChipFamily::Rtl8192eu {
            return super::rtl8192e_init::reset_8051(self).await;
        }
        if self.chip == ChipFamily::Rtl8723bu {
            return super::rtl8723b_init::reset_8051(self).await;
        }
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
        let block = control_chunk(self.chip);
        for (page, bytes) in payload.chunks(RTL_FW_PAGE_SIZE).enumerate() {
            let value = self.read8(REG_MCU_FW_DL + 2).await?;
            self.write8(REG_MCU_FW_DL + 2, (value & 0xf8) | page as u8)
                .await?;
            for (chunk, bytes) in bytes.chunks(block).enumerate() {
                let addr = REG_FW_START_ADDRESS + (chunk * block) as u16;
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
        .await?;
        // `rtl8xxxu_start_firmware`: `init_reg_hmtfr` (RTL8723BU only here).
        if self.chip == ChipFamily::Rtl8723bu {
            self.write8(REG_HMTFR, 0x0f).await?;
        }
        Ok(())
    }
}

impl Owner<UsbControl> {
    /// The packet adapter must use the identical retained USB generation and
    /// controller as EP0. Taking another caller-provided handle is forbidden.
    pub(super) fn usb_device(&self) -> Arc<USBDevice> {
        self.io.device.clone()
    }
}

pub(super) fn firmware_missing(error: Error, has_loader_authority: bool) -> bool {
    matches!(error, Error::Firmware(FirmwareError::NotFound))
        || (matches!(error, Error::Firmware(FirmwareError::AuthorityRevoked))
            && !has_loader_authority)
}

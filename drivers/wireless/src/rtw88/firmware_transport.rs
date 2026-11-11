// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821CE/RTL8822CE section firmware lifecycle, Linux rtw88/mac.c/fw.c.
//! Requires an exclusively retained, pristine PCIe reserved-page DMA backend.
//! It does not itself enable PCI bus mastering or supply a packet runtime.
use alloc::boxed::Box;
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::FirmwareError;
#[path = "runtime_lps.rs"]
pub(super) mod runtime_lps;
#[path = "wow_owner.rs"]
mod wow_owner;
/// Outcome of one power-save H2C publication attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PsSubmit {
    /// The HMEBOX low word was written under the original source.
    Issued,
    /// Native RX/TX/command prefix advanced after extended-word staging; no
    /// command was published. The caller retires that prefix and may retry.
    Unissued,
}
/// Encloses the final native publication check/write in the caller's
/// original PS source; it must invoke the operation at most once.
pub(super) type PsScope<'a> =
    dyn FnMut(&mut dyn FnMut() -> Result<bool, Error>) -> Result<bool, Error> + Send + 'a;
const HEADER: usize = 64;
const CHECKSUM: usize = 8;
const MAX_IMAGE: usize = 1024 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Image,
    State,
    Prerequisite,
    Access,
    Gone,
    Timeout,
    Checksum,
    Ready,
    Deadline,
    Cancelled,
    Memory,
    Firmware(FirmwareError),
    Power(super::power_policy::Error),
    Calibration8821c(super::calibration8821c::Error),
    /// RTL8822BE `N2BQ` calibration envelope (`calibration8822b`).
    Calibration8822b(super::calibration8822b::Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    New,
    Ready,
    MacPrepared,
    PhyTablesPrepared,
    Calibration8821cPrepared,
    Operating8821cPrepared,
    Radio8821cPrepared,
    Calibrated,
    Station,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Dmem,
    Imem,
    Emem,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub version: u16,
    pub subversion: u8,
    pub subindex: u8,
    /// Linux FW_FEATURE_SIG must be present before feature bits have meaning.
    /// This is image metadata, not evidence that any power transition ran.
    pub features: u32,
    pub h2c: u16,
    pub sections: usize,
}
#[derive(Debug)]
struct Section<'a> {
    kind: Kind,
    address: u32,
    bytes: &'a [u8],
}
#[derive(Debug)]
struct Image<'a> {
    info: Info,
    sections: [Option<Section<'a>>; 3],
}
fn filename(did: u16) -> Result<&'static str, Error> {
    match did {
        0xc821 => Ok("rtw88/rtw8821c_fw.bin"),
        0xc822 => Ok("rtw88/rtw8822c_fw.bin"),
        // rtw8822b.c::rtw8822b_hw_spec.fw_name.
        0xb822 => Ok("rtw88/rtw8822b_fw.bin"),
        _ => Err(Error::Unsupported),
    }
}
struct Snapshot(u16);
impl CapOp<narf_firmware::FirmwareBlob, Read> for Snapshot {
    type Output = Result<alloc::vec::Vec<u8>, Error>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareBlob, Read>,
    ) -> Result<Self::Output, CapError> {
        Ok((|| {
            let view = narf_firmware::view_of(cap).map_err(Error::Firmware)?;
            parse(self.0, view.bytes)?;
            let mut bytes = alloc::vec::Vec::new();
            bytes
                .try_reserve_exact(view.bytes.len())
                .map_err(|_| Error::Memory)?;
            bytes.extend_from_slice(view.bytes);
            Ok(bytes)
        })())
    }
}
/// Owned authenticated/validated image staging. Construction publishes no DMA
/// or readiness; only the real retained Owner may begin a hardware attempt.
pub(super) struct PreparedImage {
    did: u16,
    bytes: alloc::vec::Vec<u8>,
}
impl PreparedImage {
    pub(super) fn size(&self) -> usize {
        self.bytes.len()
    }
}
pub(super) fn preflight_image(
    did: u16,
    bytes: alloc::vec::Vec<u8>,
) -> Result<PreparedImage, Error> {
    parse(did, &bytes)?;
    Ok(PreparedImage { did, bytes })
}
struct Open(&'static str);
impl CapOp<narf_firmware::FirmwareRegistry, Read> for Open {
    type Output = Result<Cap<narf_firmware::FirmwareBlob, Read>, FirmwareError>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self::Output, CapError> {
        Ok(narf_firmware::open(self.0, cap))
    }
}
pub(super) fn registered_image(did: u16) -> Result<PreparedImage, Error> {
    registered_named(did, filename(did)?)
}
/// `rtw8822c_hw_spec.wow_fw_name`, opened, authenticated and parsed through
/// the same firmware registry/signature path as the NIC image (Linux
/// `main.c::rtw_load_firmware(RTW_WOWLAN_FW)`). RTL8822CE only.
pub(super) fn registered_wow_image(did: u16) -> Result<PreparedImage, Error> {
    if did != 0xc822 {
        return Err(Error::Unsupported);
    }
    registered_named(did, super::wow::WOW_FIRMWARE)
}
fn registered_named(did: u16, name: &'static str) -> Result<PreparedImage, Error> {
    let loader = narf_firmware::trusted_loader_authority()
        .ok_or(Error::Firmware(FirmwareError::AuthorityRevoked))?;
    let authority = loader
        .derive()
        .map_err(|_| Error::Firmware(FirmwareError::AuthorityRevoked))?;
    let cap = authority
        .invoke(Open(name))
        .map_err(|_| Error::Firmware(FirmwareError::AuthorityRevoked))?
        .map_err(Error::Firmware)?;
    let bytes = cap
        .invoke(Snapshot(did))
        .map_err(|_| Error::Firmware(FirmwareError::AuthorityRevoked))??;
    preflight_image(did, bytes)
}
fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn parse(did: u16, bytes: &[u8]) -> Result<Image<'_>, Error> {
    let signature = match did {
        0xc821 => [0x21, 0x88],
        // RTL8822B and RTL8822C images share the 0x8822 header signature;
        // the PCI identity (and the registered filename) selects the chip.
        0xc822 | 0xb822 => [0x22, 0x88],
        _ => return Err(Error::Unsupported),
    };
    // Installed rtw8822b_fw.bin places IMEM at OCP 0x0 (header imem_addr
    // 0x80000000 masked by mac.c::start_download_firmware), below the
    // OCPBASE_IMEM_88XX 0x30000 used by the C21/C22 images; both stay below
    // OCPBASE_EMEM_88XX and download_firmware_to_mem selects the IMEM
    // checksum bits for any address under OCPBASE_DMEM_88XX.
    let imem_base = if did == 0xb822 { 0 } else { 0x30000 };
    if !(HEADER..=MAX_IMAGE).contains(&bytes.len()) || bytes[..2] != signature {
        return Err(Error::Image);
    }
    let has_emem = bytes[0x18] & 0x10 != 0 && word(bytes, 0x34) != 0;
    let mut sections = [None, None, None];
    let mut offset = HEADER;
    for (index, (kind, base, limit, address, size, enabled)) in [
        (Kind::Dmem, 0x200000u32, 0x300000u32, 0x20, 0x24, true),
        (Kind::Imem, imem_base, 0x100000, 0x3c, 0x30, true),
        (Kind::Emem, 0x100000, 0x200000, 0x38, 0x34, has_emem),
    ]
    .into_iter()
    .enumerate()
    {
        if !enabled {
            continue;
        }
        let size = word(bytes, size);
        let address = word(bytes, address) & 0x7fff_ffff;
        let length = size.checked_add(CHECKSUM as u32).ok_or(Error::Image)?;
        // Initial profile admits the fixed OCP memory bases defined by Linux
        // mac.h only. Unsupported relocated layouts never reach IDDMA/MMIO.
        if size == 0 || address != base || address.checked_add(length).is_none_or(|end| end > limit)
        {
            return Err(Error::Image);
        }
        let end = offset.checked_add(length as usize).ok_or(Error::Image)?;
        let data = bytes.get(offset..end).ok_or(Error::Image)?;
        sections[index] = Some(Section {
            kind,
            address,
            bytes: data,
        });
        offset = end;
    }
    if offset != bytes.len() {
        return Err(Error::Image);
    }
    Ok(Image {
        info: Info {
            version: u16::from_le_bytes([bytes[4], bytes[5]]),
            subversion: bytes[6],
            subindex: bytes[7],
            features: match word(bytes, 0x0c) {
                features if features & 1 != 0 => features,
                _ => 0,
            },
            h2c: u16::from_le_bytes([bytes[0x1c], bytes[0x1d]]),
            sections: if has_emem { 3 } else { 2 },
        },
        sections,
    })
}
/// Asynchronous register work enclosed by a synchronous authority invoke.
///
/// `Io` register access is asynchronous so a USB backend can issue real EP0
/// vendor requests (`rtw88/usb.c::rtw_usb_read`/`rtw_usb_write`) while the
/// PCI backend completes in its first poll. `wrap` is the existing
/// synchronous enclosure (a capability `invoke`, `Admission::run`, ...).
/// The operation's first poll runs inside it: an immediately-ready PCI
/// operation therefore executes wholly inside the enclosure, exactly as the
/// synchronous form did. An operation still in flight after that poll (a USB
/// transfer) continues outside, and completion re-enters the enclosure, so a
/// revocation or close while a transfer is in flight voids the result.
pub(super) async fn enclosed<T, E, W>(
    wrap: W,
    operation: impl core::future::Future<Output = Result<T, E>>,
) -> Result<T, E>
where
    W: Fn(&mut dyn FnMut() -> Result<Option<T>, E>) -> Result<Option<T>, E>,
{
    let mut operation = core::pin::pin!(operation);
    let first = wrap(&mut || {
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        match core::future::Future::poll(operation.as_mut(), &mut cx) {
            core::task::Poll::Ready(result) => result.map(Some),
            core::task::Poll::Pending => Ok(None),
        }
    })?;
    if let Some(value) = first {
        return Ok(value);
    }
    let value = operation.await?;
    wrap(&mut || Ok(None))?;
    Ok(value)
}

/// Complete an operation whose every register access is a synchronous PCI
/// MMIO access, from a synchronous PCI backend method. Such an operation is
/// ready in its first poll; one that is not (it would need a real transfer)
/// is refused rather than spun on.
pub(super) fn ready_now<T, E: From<Error>>(
    operation: impl core::future::Future<Output = Result<T, E>>,
) -> Result<T, E> {
    let operation = core::pin::pin!(operation);
    let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
    match core::future::Future::poll(operation, &mut cx) {
        core::task::Poll::Ready(result) => result,
        core::task::Poll::Pending => Err(Error::State.into()),
    }
}

/// Test bridge: drive a register-model future (whose `Io` completes in its
/// first poll) from a synchronous kernel test body.
#[cfg(any(test, feature = "kernel-test"))]
pub(super) fn now<F: core::future::Future>(future: F) -> F::Output {
    narf_scheduler::block_on(future)
}

/// One 32-bit register sample for a programmed-state readback. Readbacks
/// run over the native asynchronous `Io` (PCI or USB) or over a synchronous
/// sampler of the retained PCI backend, without a borrowing async closure.
pub(super) trait Read32: Send {
    fn read32(&mut self, reg: u16)
        -> impl core::future::Future<Output = Result<u32, Error>> + Send;
}
impl<R: Read32> Read32 for &mut R {
    fn read32(
        &mut self,
        reg: u16,
    ) -> impl core::future::Future<Output = Result<u32, Error>> + Send {
        (**self).read32(reg)
    }
}
/// Readback through the owner's own 32-bit register read.
pub(super) struct IoRead32<'a, I>(pub &'a mut I);
impl<I: Io> Read32 for IoRead32<'_, I> {
    fn read32(
        &mut self,
        reg: u16,
    ) -> impl core::future::Future<Output = Result<u32, Error>> + Send {
        self.0.read32(reg)
    }
}
/// Readback through `radio::read`, which also maps an all-ones sample to
/// `Gone`.
pub(super) struct RadioRead32<'a, I>(pub &'a mut I);
impl<I: Io> Read32 for RadioRead32<'_, I> {
    fn read32(
        &mut self,
        reg: u16,
    ) -> impl core::future::Future<Output = Result<u32, Error>> + Send {
        super::radio::read(self.0, reg)
    }
}
/// Readback through an immediately-completing sampler (PCI MMIO, models).
#[derive(Clone, Copy)]
pub(super) struct Sampled<F>(pub F);
impl<F: FnMut(u16) -> Result<u32, Error> + Send> Read32 for Sampled<F> {
    fn read32(
        &mut self,
        reg: u16,
    ) -> impl core::future::Future<Output = Result<u32, Error>> + Send {
        core::future::ready((self.0)(reg))
    }
}

/// # Safety
/// Claim proves this backend owns every published host DMA mapping and the
/// exact powered PCI device exclusively. Reserved-page submissions retain
/// their buffers across cancellation/ambiguous errors and cannot overwrite
/// them until terminal completion. Dropping this backend must retain any
/// mapping that hardware can still access. Firmware claim keeps MAC TX/RX
/// and IRQs closed. A station-page continuation requires the original
/// current qualified PS scope and exact native queue/prefix quiet proof;
/// no unrelated command/reset/ring client may race either path.
#[async_trait::async_trait]
pub(super) unsafe trait Io: Send {
    /// Every register future completes in its first poll (PCI MMIO). A
    /// backend whose accesses are real transfers (USB EP0/bulk) is `false`:
    /// synchronous `ready_now` shells (`interface::Device::drain`) are then
    /// no-ops and its station is driven by the asynchronous worker.
    const SYNCHRONOUS: bool = true;
    /// Host interface whose MAC queue/FIFO rows `prepare_mac` programs.
    fn hci(&self) -> super::mac::Hci {
        super::mac::Hci::Pcie
    }
    fn claim_pristine(&mut self) -> Result<(), Error>;
    fn read8(&mut self, reg: u16) -> impl core::future::Future<Output = Result<u8, Error>> + Send;
    fn read16(&mut self, reg: u16)
        -> impl core::future::Future<Output = Result<u16, Error>> + Send;
    fn read32(&mut self, reg: u16)
        -> impl core::future::Future<Output = Result<u32, Error>> + Send;
    fn write8(
        &mut self,
        reg: u16,
        value: u8,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send;
    fn write16(
        &mut self,
        reg: u16,
        value: u16,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send;
    fn write32(
        &mut self,
        reg: u16,
        value: u32,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send;
    async fn reserved_page(&mut self, data: &[u8]) -> Result<(), Error>;
    /// Native station continuation only; a separate exact original PS source
    /// must enclose CPU mapping writes and each actual DMA publication.
    async fn station_reserved_page(
        &mut self,
        _: &[u8],
        _: u16,
        _: &super::runtime_ps_scope::Bound,
        _: &super::station_control::Admission,
    ) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    async fn lte_backup(&mut self) -> Result<u32, Error>;
    async fn lte_restore(&mut self, value: u32) -> Result<(), Error>;
    async fn finish_dma(&mut self) -> Result<(), Error>;
    /// Continue only the exact successfully parked firmware owner, with BME,
    /// host packet queues and interrupts closed. No reconstruction is allowed.
    fn begin_mac(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn finish_mac(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn begin_phy(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn finish_phy(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn begin_calibration8821c(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn finish_calibration8821c(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn begin_operating8821c(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn finish_operating8821c(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn begin_station8821c(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn finish_station8821c(&mut self, _: super::power_policy::Gate) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn begin_commands(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn submit_h2c(
        &mut self,
        _: &[u8; 32],
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move { Err(Error::Unsupported) }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn poll_h2c(&mut self) -> impl core::future::Future<Output = Result<bool, Error>> + Send {
        async move { Err(Error::Unsupported) }
    }
    /// Drain the command producer and park bus mastering without granting
    /// ordinary packets or reclaiming the retained firmware bounce buffers.
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn park_radio(&mut self) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move { Err(Error::Unsupported) }
    }
    fn finish_radio(&mut self, _: super::power_policy::Gate) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn station_allowed(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn station_publication(&mut self) -> Result<super::publication::Publication, Error> {
        Err(Error::Unsupported)
    }
    fn station_own(&mut self) -> Result<[u8; 6], Error> {
        Err(Error::Unsupported)
    }
    fn station_extension(
        &mut self,
    ) -> Result<Option<alloc::sync::Arc<super::station_profile::Grant>>, Error> {
        Ok(None)
    }
    fn station_bind_extension(
        &mut self,
        _: alloc::sync::Arc<super::station_profile::Grant>,
    ) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn packet_profile(&mut self, _: super::packet_format::DataProfile) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_profile_readback(
        &mut self,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move { Err(Error::Unsupported) }
    }
    fn station_ht_facts(&self) -> Option<super::ht::Facts> {
        None
    }
    fn station_ht_extension(
        &mut self,
        _: alloc::sync::Arc<super::station_profile::Grant>,
    ) -> Result<Option<alloc::sync::Arc<super::ht::Grant>>, Error> {
        Ok(None)
    }
    fn station_bind_ht(&mut self, _: alloc::sync::Arc<super::ht::Grant>) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    /// Actual retained packet/command owner is idle before changing TX paths.
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_ht_program_quiet(
        &mut self,
    ) -> impl core::future::Future<Output = Result<bool, Error>> + Send {
        async move { Err(Error::Unsupported) }
    }
    fn station_ht_request(&mut self) -> Result<super::ht::Request, Error> {
        Err(Error::Unsupported)
    }
    fn station_rx_ba_extension(
        &mut self,
        _: alloc::sync::Arc<super::ht::Grant>,
    ) -> Result<Option<alloc::sync::Arc<super::rx_ba_power::Grant>>, Error> {
        Ok(None)
    }
    fn station_bind_rx_ba(
        &mut self,
        _: alloc::sync::Arc<super::rx_ba_power::Grant>,
    ) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn station_rx_ba_request(&mut self) -> Result<super::RxBaRequest, Error> {
        Err(Error::Unsupported)
    }
    fn station_tx_ba_extension(
        &mut self,
    ) -> Result<Option<alloc::sync::Arc<super::tx_ba_power::Grant>>, Error> {
        Ok(None)
    }
    fn station_protection_extension(
        &mut self,
    ) -> Result<Option<alloc::sync::Arc<super::protection::Grant>>, Error> {
        Ok(None)
    }
    fn station_bind_protection(
        &mut self,
        _: alloc::sync::Arc<super::protection::Grant>,
    ) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    /// N21W measurement metadata for the bound C21 HT/T/Q program.
    /// Power-tracking hooks return `impl Future + Send`: the PCI
    /// `reserved_page::Backend` runs its unchanged synchronous `Registers`
    /// call in the first poll; the USB backend runs them over EP0.
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_power_tracking_request(
        &mut self,
        _: u8,
        _: Option<alloc::sync::Arc<super::qualification::Grant>>,
    ) -> impl core::future::Future<Output = Result<super::PowerTrackingRequest, Error>> + Send {
        async move { Err(Error::Unsupported) }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_power_tracking_extension(
        &mut self,
        _: u8,
        _: Option<alloc::sync::Arc<super::qualification::Grant>>,
    ) -> impl core::future::Future<
        Output = Result<Option<alloc::sync::Arc<super::tracking8821c::Grant>>, Error>,
    > + Send {
        async move { Ok(None) }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_bind_power_tracking(
        &mut self,
        _: alloc::sync::Arc<super::tracking8821c::Grant>,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move { Err(Error::Unsupported) }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_power_tracking_begin(
        &mut self,
        _: &alloc::sync::Arc<super::tracking8821c::Grant>,
        _: bool,
    ) -> impl core::future::Future<Output = Result<bool, Error>> + Send {
        async move { Err(Error::Unsupported) }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_power_tracking_quiet(
        &mut self,
    ) -> impl core::future::Future<Output = Result<bool, Error>> + Send {
        async move { Err(Error::Unsupported) }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_power_tracking_iqk(
        &mut self,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move { Err(Error::Unsupported) }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_power_tracking_finish(
        &mut self,
        _: Option<super::tracking8821c::Program>,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move { Err(Error::Unsupported) }
    }
    fn station_bind_continuation(
        &mut self,
        _: alloc::sync::Arc<super::qualification::Grant>,
    ) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn station_rts_request(&mut self) -> Result<super::RtsRequest, Error> {
        Err(Error::Unsupported)
    }
    /// Load the exact separately signed continuation `kind` over the
    /// current station gate (Registered source on real hardware).
    fn station_continuation(
        &mut self,
        _: &'static super::qualification::Kind,
    ) -> Result<Option<alloc::sync::Arc<super::qualification::Grant>>, Error> {
        Ok(None)
    }
    fn station_continuation_request(
        &mut self,
        _: &'static super::qualification::Kind,
    ) -> Result<super::ContinuationRequest, Error> {
        Err(Error::Unsupported)
    }
    /// A clone of the current retained station gate.
    fn station_gate(&mut self) -> Result<super::power_policy::Gate, Error> {
        Err(Error::Unsupported)
    }
    /// Committed operating primary and its retune epoch (initial = 1).
    fn station_channel(&self) -> (u8, u64) {
        (1, 1)
    }
    /// Wiphy 5GHz capability bodies the station offers on admitted 5GHz
    /// primary `channel`: `(HT, Some(VHT))` when a loadable N2xV record
    /// over that channel's scope (and its admitted 80MHz block) lets the
    /// join offer VHT80, `(HT20, None)` when only the band-5 N2xL/N2xH
    /// HT program loads, `None` when the join there stays legacy.
    fn station_band5_capability(
        &mut self,
        _: u8,
    ) -> Result<Option<super::vht::Band5Capability>, Error> {
        Ok(None)
    }
    /// Optional signed N2xO record admitting noninitial `channel` over the
    /// exact current base. None if unprovisioned or not admitted.
    fn station_channel_grant(
        &mut self,
        _: u8,
    ) -> Result<Option<alloc::sync::Arc<super::qualification::Grant>>, Error> {
        Ok(None)
    }
    /// The installed host regulatory snapshot classifying passive-only
    /// (DFS / NO_IR) primaries and scoping the station's beacon witnesses
    /// (`narf_wireless::reg::witness`). `None`: no passive-only primary.
    fn station_regulatory(
        &self,
    ) -> Result<Option<alloc::sync::Arc<narf_wireless::reg::RegulatoryDomain>>, Error> {
        Ok(None)
    }
    /// Grant (or with `None` withdraw) station frame TX on the committed
    /// passive-only primary `grant.0`, admitted by the station's witness
    /// taken under exactly the policy snapshot `grant.1`.
    fn station_passive_tx(
        &mut self,
        grant: Option<(u8, alloc::sync::Arc<narf_wireless::reg::RegulatoryDomain>)>,
    ) -> Result<(), Error> {
        match grant {
            None => Ok(()),
            Some(_) => Err(Error::Unsupported),
        }
    }
    /// Install the target channel gate (base for channel 1), stop new TX
    /// publication and pause hardware TX. Re-entrant for the same target;
    /// returns whether every TX queue has drained.
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_retune_begin(
        &mut self,
        _: u8,
        _: Option<alloc::sync::Arc<super::qualification::Grant>>,
    ) -> impl core::future::Future<Output = Result<bool, Error>> + Send {
        async move { Err(Error::Unsupported) }
    }
    /// Begin widening the committed primary to the bound N2xB 40MHz pair or
    /// N2xV 80MHz block: same TX refusal/TXPAUSE/drain as a retune, gate
    /// unchanged, packet-core RX admission set to 40MHz / 80MHz. Re-entrant; returns whether TX drained.
    /// Completed by [`Io::station_retune_finish`] on the same primary.
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_width_begin(
        &mut self,
    ) -> impl core::future::Future<Output = Result<bool, Error>> + Send {
        async move { Err(Error::Unsupported) }
    }
    /// Submit the chip's pre-association IQK H2C during a retune.
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_retune_iqk(
        &mut self,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move { Err(Error::Unsupported) }
    }
    /// RTL8822BE associated-station IQK maintenance step
    /// (`tracking8822b::Step`, PCI `Native`): Begin/Quiet report quiet.
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_b22_iqk(
        &mut self,
        _: super::tracking8822b::Step,
    ) -> impl core::future::Future<Output = Result<bool, Error>> + Send {
        async move { Err(Error::Unsupported) }
    }
    /// Commit the programmed target, reopen TX and return the new epoch.
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn station_retune_finish(
        &mut self,
        _: u8,
    ) -> impl core::future::Future<Output = Result<u64, Error>> + Send {
        async move { Err(Error::Unsupported) }
    }
    fn station_bind_host(&mut self, _: narf_net::native_emission::Lifetime) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn station_bind_tx_ba(
        &mut self,
        _: alloc::sync::Arc<super::tx_ba_power::Grant>,
    ) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn station_tx_ba_request(&mut self) -> Result<super::TxBaRequest, Error> {
        Err(Error::Unsupported)
    }
    fn packet_aggregation(
        &mut self,
        _: Option<super::packet_format::Aggregation>,
    ) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn packet_submit_batch(
        &mut self,
        _: &[alloc::vec::Vec<u8>],
    ) -> Result<alloc::vec::Vec<u64>, super::packet_core::Error> {
        Err(super::packet_core::Error::State)
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn mailbox_ready(&mut self) -> impl core::future::Future<Output = Result<bool, Error>> + Send {
        async move { Err(Error::Unsupported) }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn mailbox_submit(
        &mut self,
        _: [u8; 8],
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move { Err(Error::Unsupported) }
    }
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn mailbox_consumed(
        &mut self,
    ) -> impl core::future::Future<Output = Result<bool, Error>> + Send {
        async move { Err(Error::Unsupported) }
    }
    fn mailbox_pending(&self) -> bool {
        false
    }
    /// Power-save H2C only, Linux fw.c `rtw_fw_send_h2c_command`: stage
    /// HMEBOX_EXT, then run `scope` around the final current native checks
    /// and the HMEBOX low-word write that actually publishes the command.
    /// `Unissued` (and any error before that write) means firmware never saw
    /// a command; the extended-only staging is overwritten by a retry.
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn ps_mailbox_submit(
        &mut self,
        _: [u8; 8],
        _: &mut PsScope<'_>,
    ) -> impl core::future::Future<Output = Result<PsSubmit, Error>> + Send {
        async move { Err(Error::Unsupported) }
    }
    fn packet_prepare(&mut self, _: [u8; 6], _: u8) -> Result<(), super::packet_core::Error> {
        Err(super::packet_core::Error::State)
    }
    fn packet_start(&mut self) -> Result<(), super::packet_core::Error> {
        Err(super::packet_core::Error::State)
    }
    /// Asynchronous MAC open after [`Io::packet_start`], before any packet
    /// is submitted. PCI opens CR/TXPAUSE inside its synchronous
    /// `packet_start` (default: nothing left to do); USB writes CR = 0xff and
    /// TXPAUSE = 0 over asynchronous EP0 here.
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn packet_open(
        &mut self,
    ) -> impl core::future::Future<Output = Result<(), super::packet_core::Error>> + Send {
        async move { Ok(()) }
    }
    /// Asynchronous MAC close before the synchronous [`Io::packet_stop`].
    /// PCI closes inside `packet_stop` (default: nothing to do here); USB
    /// pauses TX, closes CR's MAC/DMA gates over EP0 and retires every
    /// retained bulk receipt, so its `packet_stop` need not fail closed.
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn packet_close(
        &mut self,
    ) -> impl core::future::Future<Output = Result<(), super::packet_core::Error>> + Send {
        async move { Ok(()) }
    }
    /// Linux `rtw_hci_dynamic_rx_agg` from `rtw_watch_dog_work`: PCI's
    /// `rtw_pci_ops.dynamic_rx_agg` is NULL (no-op); USB overrides it.
    #[allow(clippy::manual_async_fn)] // `#[async_trait]` impl: an `async fn` here would be boxed
    fn dynamic_rx_agg(
        &mut self,
        _enable: bool,
    ) -> impl core::future::Future<Output = Result<(), Error>> + Send {
        async move { Ok(()) }
    }
    fn packet_ready(&self) -> bool {
        false
    }
    fn packet_submit(&mut self, _: &[u8], _: bool) -> Result<u64, super::packet_core::Error> {
        Err(super::packet_core::Error::State)
    }
    /// Admit Probe Requests from `address` (a random scan SA) until cleared.
    fn packet_scan_address(&mut self, _: Option<[u8; 6]>) -> Result<(), super::packet_core::Error> {
        Err(super::packet_core::Error::State)
    }
    fn packet_poll(&mut self) -> Result<super::packet_core::Step, super::packet_core::Error> {
        Err(super::packet_core::Error::State)
    }
    fn packet_stop(&mut self) -> Result<(), super::packet_core::Error> {
        Err(super::packet_core::Error::State)
    }
    /// `rtw_pci_stop` plus the DMA idle proof (`dma_stop::prove`). Only
    /// success lets Drop release the published rings and buffers.
    async fn quiesce_dma(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    /// True once `quiesce_dma` proved every published mapping idle.
    fn dma_reclaimable(&self) -> bool {
        false
    }

    async fn delay_us(&mut self, us: u64) {
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(us.saturating_mul(1000))).await;
    }
    /// `wow.c::rtw_wow_swap_fw` precondition: the original station's TRX is
    /// stopped (`rtw_wow_stop_trx`) and the firmware reserved-page channel
    /// may be reused for a section download at page 0, restoring the
    /// station reserved-page `boundary` afterwards. The window stays open
    /// (`finish_dma` does not park) until [`Io::end_swap`].
    fn claim_swap(&mut self, _boundary: u16) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    /// `rtw_fw_download_rsvd_page` inside the swap window: one reserved-page
    /// image at the station boundary.
    async fn swap_page(&mut self, _: &[u8]) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    /// Close the swap window (`rtw_wow_resume_trx` done).
    fn end_swap(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    /// `rtw_hci_stop` (PCI `rtw_pci_stop`): reversible host ring reset.
    fn hci_stop(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    /// `rtw_hci_setup` + `rtw_hci_start` after [`Io::hci_stop`].
    fn hci_restart(&mut self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
}
#[derive(Debug)]
struct Backup {
    map: u8,
    cr: u8,
    pages: u16,
    rqpn: u32,
    beacon: u8,
}
pub(super) struct RadioPreflight {
    board: super::power_policy::Board,
    calibration: alloc::sync::Arc<super::power_policy::Calibration>,
    permission: super::power_policy::Permission,
    gain: [u8; 2],
    gate: super::power_policy::Gate,
    mac: super::mac::Info,
    phy: super::phy::Info,
}
pub(super) struct Owner<I: Io> {
    io: I,
    did: u16,
    phase: Phase,
    info: Option<Info>,
    mac: Option<super::mac::Info>,
    hardware: Option<super::hardware::Features>,
    phy: Option<super::phy::Info>,
    phy8821c: Option<super::phy8821c::Info>,
    phy8822b: Option<super::phy8822b::Info>,
    calibration8822b: Option<super::radio8822b::Calibration>,
    envelope8822b: Option<alloc::sync::Arc<super::calibration8822b::Envelope>>,
    operating8822b: Option<super::operating8822b::Info>,
    operating_envelope8822b: Option<alloc::sync::Arc<super::operating8822b::Envelope>>,
    /// C21/B22 host interface; keys the PHY rows and every signed C21/B22
    /// record (`Interface::host_of`).
    interface: super::phy8821c::Interface,
    calibration8821c: Option<super::radio8821c::Info>,
    envelope8821c: Option<alloc::sync::Arc<super::calibration8821c::Envelope>>,
    operating8821c: Option<super::operating8821c::Info>,
    operating_envelope8821c: Option<alloc::sync::Arc<super::operating8821c::Envelope>>,
    station_grant8821c: Option<alloc::sync::Arc<super::station_power8821c::Grant>>,
    /// C21 or B22 (`radio8822b::prepare_station`) awake-station receipt.
    station_radio8821c: Option<super::radio8821c::StationInfo>,
    station_grant8822b: Option<alloc::sync::Arc<super::operating8822b::Grant>>,
    image_digest: Option<[u8; 32]>,
    power: Option<alloc::sync::Arc<super::power_policy::Calibration>>,
    radio: Option<super::radio::Info>,
    radio_gate: Option<super::power_policy::Gate>,
    /// Boxed: the station owner carries the shared join plan, PHY and
    /// security state, and `Owner` is moved by value through lifecycle
    /// construction; inline it would land on small (aarch64) stacks.
    station: Option<alloc::boxed::Box<super::station::State>>,
    tracking_facts: Option<super::dm::Facts>,
    /// Retained efuse antenna facts for the `coex` (N2xK) owner.
    coex_facts: Option<super::coex::Facts>,
}
impl<I: Io> core::fmt::Debug for Owner<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw8822ceFirmware")
            .field("phase", &self.phase)
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}
impl<I: Io> Owner<I> {
    pub fn new(io: I, did: u16) -> Self {
        Self {
            io,
            did,
            phase: Phase::New,
            info: None,
            mac: None,
            hardware: None,
            phy: None,
            phy8821c: None,
            phy8822b: None,
            calibration8822b: None,
            envelope8822b: None,
            operating8822b: None,
            operating_envelope8822b: None,
            interface: super::phy8821c::Interface::Pcie,
            calibration8821c: None,
            envelope8821c: None,
            operating8821c: None,
            operating_envelope8821c: None,
            station_grant8821c: None,
            station_radio8821c: None,
            station_grant8822b: None,
            image_digest: None,
            power: None,
            radio: None,
            radio_gate: None,
            station: None,
            tracking_facts: None,
            coex_facts: None,
        }
    }
    /// The same owner behind another C21/B22 host interface (before any
    /// stage).
    pub(super) fn on(self, interface: super::phy8821c::Interface) -> Self {
        Self { interface, ..self }
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub(super) async fn start_station(
        &mut self,
        environment: alloc::sync::Arc<dyn super::station::Environment>,
        admission: super::station_control::Admission,
    ) -> Result<super::station_control::Admission, super::station::Error> {
        if !matches!(self.phase, Phase::Calibrated | Phase::Radio8821cPrepared)
            || self.station.is_some()
        {
            return Err(super::station::Error::State);
        }
        let own = self.io.station_own()?;
        self.phase = Phase::Failed; // poison before the first awaited prerequisite
        self.station = Some(alloc::boxed::Box::new(super::station::State::new(
            own,
            environment,
            admission,
        )));
        let station = self
            .station
            .as_deref_mut()
            .ok_or(super::station::Error::State)?;
        station.set_tracking_facts(self.tracking_facts);
        station.set_coex_facts(self.coex_facts);
        station.start(&mut self.io).await?;
        self.phase = Phase::Station;
        Ok(station.admission())
    }
    pub(super) fn station_local(&self) -> Option<[u8; 6]> {
        self.station.as_deref().map(super::station::State::local)
    }
    pub(super) fn station_ht_capability(&self) -> Option<[u8; 26]> {
        self.io
            .station_ht_facts()
            .and_then(super::ht::Facts::capability)
    }
    pub(super) fn station_peer(&self) -> Option<[u8; 6]> {
        self.station
            .as_deref()
            .and_then(super::station::State::peer)
    }
    pub(super) fn station_ready(&self) -> bool {
        self.station
            .as_deref()
            .is_some_and(super::station::State::ready)
    }
    pub(super) fn station_receive_open(&self) -> bool {
        self.station
            .as_deref()
            .is_some_and(super::station::State::receive_open)
    }
    pub(super) fn station_check(&mut self) -> Result<(), super::station::Error> {
        let station = self
            .station
            .as_deref()
            .ok_or(super::station::Error::State)?;
        if self.phase != Phase::Station
            || matches!(
                station.phase(),
                super::station::Phase::Prepared
                    | super::station::Phase::Failed
                    | super::station::Phase::Stopped
            )
        {
            return Err(super::station::Error::State);
        }
        self.io
            .station_allowed()
            .map_err(super::station::Error::Native)
    }
    pub(super) fn station_publication(
        &mut self,
    ) -> Result<super::publication::Publication, super::station::Error> {
        self.station_check()?;
        let epoch = self
            .station
            .as_deref()
            .ok_or(super::station::Error::State)?
            .admission()
            .epoch();
        self.io
            .station_publication()
            .map(|p| p.with_epoch(epoch))
            .map_err(super::station::Error::Native)
    }
    pub(super) fn station_phase(&self) -> Option<super::station::Phase> {
        self.station.as_deref().map(super::station::State::phase)
    }
    pub(super) fn station_candidates(
        &self,
    ) -> alloc::vec::Vec<narf_wireless::association::ObservedBss> {
        self.station
            .as_deref()
            .map_or_else(alloc::vec::Vec::new, super::station::State::candidates)
    }
    pub(super) fn station_information_elements(
        &self,
        peer: [u8; 6],
    ) -> Option<alloc::vec::Vec<u8>> {
        self.station.as_deref()?.information_elements(peer)
    }
    pub(super) async fn station_poll(
        &mut self,
    ) -> Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, super::station::Error> {
        self.station
            .as_deref_mut()
            .ok_or(super::station::Error::State)?
            .poll(&mut self.io)
            .await
    }
    pub(super) async fn station_send(&mut self, frame: &[u8]) -> Result<(), super::station::Error> {
        self.station
            .as_deref_mut()
            .ok_or(super::station::Error::State)?
            .send(&mut self.io, frame)
            .await
    }
    pub(super) fn station_batch_capacity(&self) -> usize {
        self.station
            .as_deref()
            .map_or(0, super::station::State::batch_capacity)
    }
    pub(super) fn station_batch_active(&self) -> bool {
        self.station
            .as_deref()
            .is_some_and(super::station::State::batch_active)
    }
    pub(super) async fn station_send_batch(
        &mut self,
        frames: &[&[u8]],
    ) -> Result<usize, super::station::Error> {
        self.station
            .as_deref_mut()
            .ok_or(super::station::Error::State)?
            .send_batch(&mut self.io, frames)
            .await
    }
    pub(super) fn station_stop(&mut self) -> Result<(), super::station::Error> {
        self.station
            .as_deref_mut()
            .ok_or(super::station::Error::State)?
            .stop(&mut self.io)
    }
    pub(super) async fn station_disconnect(&mut self) -> Result<(), super::station::Error> {
        let result = self
            .station
            .as_deref_mut()
            .ok_or(super::station::Error::State)?
            .disconnect(&mut self.io)
            .await;
        // The stopped one-shot owner proves DMA idle so its mappings can be
        // released. A missing proof keeps them retained and never turns a
        // completed disconnect into a failure.
        let _ = self.io.quiesce_dma().await;
        result
    }
    /// `rtw_pci_stop` and DMA idle proof for any phase (removal, failure).
    /// Closes the station first; success lets Drop free every mapping.
    pub(super) async fn quiesce_dma(&mut self) -> Result<(), Error> {
        if let Some(station) = self.station.as_deref_mut() {
            let _ = station.close_packets(&mut self.io).await;
            let _ = station.stop(&mut self.io);
        }
        self.phase = Phase::Failed;
        self.io.quiesce_dma().await
    }
    pub(super) fn dma_reclaimable(&self) -> bool {
        self.io.dma_reclaimable()
    }
    pub(super) fn bind_host(
        &mut self,
        host: narf_net::native_emission::Lifetime,
    ) -> Result<(), Error> {
        self.io.station_allowed()?;
        self.io.station_bind_host(host)
    }
    pub(super) async fn station_scan(
        &mut self,
        dwell_ms: u64,
        probes: &[alloc::vec::Vec<u8>],
        address: Option<[u8; 6]>,
        channels: &[u8],
    ) -> Result<alloc::vec::Vec<narf_wireless::association::ObservedBss>, super::station::Error>
    {
        self.station
            .as_deref_mut()
            .ok_or(super::station::Error::State)?
            .scan_for(&mut self.io, dwell_ms, probes, address, channels)
            .await
    }
    /// Noninitial primaries admitted by a provisioned signed N2xO record
    /// over the current base: bit N = 2.4GHz channel N (bit 1 always set),
    /// bit 16 + i = 5GHz primary `channel_policy::PRIMARIES5[i]`.
    pub(super) fn station_admitted_channels(&mut self) -> u64 {
        let mut mask = 1 << 1;
        if self.station.is_some() {
            for channel in 2..=super::channel_policy::LAST {
                if matches!(self.io.station_channel_grant(channel), Ok(Some(_))) {
                    mask |= 1 << channel;
                }
            }
            for (i, channel) in super::channel_policy::PRIMARIES5.into_iter().enumerate() {
                if matches!(self.io.station_channel_grant(channel), Ok(Some(_))) {
                    mask |= 1 << (16 + i);
                }
            }
        }
        mask
    }
    /// Wiphy 5GHz (HT, VHT) capability bodies over the admitted 5GHz
    /// primaries (`Io::station_band5_capability`): the VHT80 offer of the
    /// first primary whose join can offer VHT80, else the first HT20 offer.
    /// `None` when every admitted 5GHz join stays legacy.
    pub(super) fn station_band5_capability(&mut self) -> Option<super::vht::Band5Capability> {
        self.station.as_ref()?;
        let mut ht20 = None;
        for channel in super::channel_policy::PRIMARIES5 {
            match self.io.station_band5_capability(channel) {
                Ok(Some((ht, Some(vht)))) => return Some((ht, Some(vht))),
                Ok(Some(ht)) if ht20.is_none() => ht20 = Some(ht),
                _ => {}
            }
        }
        ht20
    }
    pub(super) fn station_channel(&self) -> u8 {
        self.station.as_deref().map_or(1, |s| s.channel())
    }
    pub(super) async fn station_associate(
        &mut self,
        bssid: [u8; 6],
        ssid: &[u8],
        pmk: Option<zeroize::Zeroizing<[u8; 32]>>,
        ies: &[u8],
    ) -> Result<(), super::station::Error> {
        self.station
            .as_deref_mut()
            .ok_or(super::station::Error::State)?
            .associate(&mut self.io, bssid, ssid, pmk, ies)
            .await
    }
    pub fn mac_info(&self) -> Option<super::mac::Info> {
        matches!(
            self.phase,
            Phase::MacPrepared
                | Phase::PhyTablesPrepared
                | Phase::Calibration8821cPrepared
                | Phase::Operating8821cPrepared
                | Phase::Radio8821cPrepared
                | Phase::Calibrated
                | Phase::Station
        )
        .then_some(self.mac)
        .flatten()
    }
    pub(super) fn hardware_info(&self) -> Option<super::hardware::Features> {
        if matches!(
            self.phase,
            Phase::MacPrepared
                | Phase::PhyTablesPrepared
                | Phase::Calibration8821cPrepared
                | Phase::Operating8821cPrepared
                | Phase::Radio8821cPrepared
                | Phase::Calibrated
                | Phase::Station
        ) {
            self.hardware
        } else {
            None
        }
    }
    pub async fn prepare_mac(&mut self) -> Result<super::mac::Info, Error> {
        if self.phase != Phase::Ready {
            return Err(Error::State);
        }
        // Fail before the first MMIO/await. Cancellation cannot replay LLT
        // or queue setup over an ambiguous current hardware state.
        self.phase = Phase::Failed;
        self.io.begin_mac()?;
        let hardware = super::hardware::Features::read(&mut self.io).await?;
        let hci = self.io.hci();
        let info = super::mac::prepare_on(&mut self.io, self.did, hci).await?;
        self.io.finish_mac()?;
        self.mac = Some(info);
        self.hardware = Some(hardware);
        self.phase = Phase::MacPrepared;
        Ok(info)
    }
    pub fn phy_info(&self) -> Option<super::phy::Info> {
        if matches!(
            self.phase,
            Phase::PhyTablesPrepared | Phase::Calibrated | Phase::Station
        ) {
            self.phy
        } else {
            None
        }
    }
    pub(super) fn image_digest(&self) -> Option<[u8; 32]> {
        match self.phase {
            Phase::Ready
            | Phase::MacPrepared
            | Phase::PhyTablesPrepared
            | Phase::Calibration8821cPrepared
            | Phase::Operating8821cPrepared
            | Phase::Radio8821cPrepared
            | Phase::Calibrated
            | Phase::Station => self.image_digest,
            _ => None,
        }
    }
    pub(super) fn qualify_board(
        &mut self,
        factory: &super::efuse::Factory,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<super::power_policy::Permission, Error> {
        self.qualify_with(factory, domain, super::power_policy::Source::Registered)
    }
    pub(super) fn qualify_with(
        &mut self,
        factory: &super::efuse::Factory,
        domain: &narf_wireless::reg::RegulatoryDomain,
        source: super::power_policy::Source,
    ) -> Result<super::power_policy::Permission, Error> {
        if !matches!(self.phase, Phase::PhyTablesPrepared | Phase::Calibrated) {
            return Err(Error::State);
        }
        let board = super::power_policy::Board::new(
            factory,
            self.phy.ok_or(Error::State)?,
            self.hardware.ok_or(Error::State)?,
            self.image_digest.ok_or(Error::State)?,
        )
        .map_err(Error::Power)?;
        if let Some(calibration) = &self.power {
            if !calibration.matches(board) {
                return Err(Error::Power(super::power_policy::Error::Identity));
            }
            return calibration.permission(domain).map_err(Error::Power);
        }
        let calibration = source.load(board).map_err(Error::Power)?;
        let permission = calibration.permission(domain).map_err(Error::Power)?;
        self.power = Some(alloc::sync::Arc::new(calibration));
        Ok(permission)
    }
    pub(super) fn current_power(
        &self,
        permission: super::power_policy::Permission,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<[u8; 2], Error> {
        if !matches!(self.phase, Phase::PhyTablesPrepared | Phase::Calibrated) {
            return Err(Error::State);
        }
        self.power
            .as_ref()
            .ok_or(Error::State)?
            .gains(permission, domain)
            .map_err(Error::Power)
    }
    pub fn radio_info(&self) -> Option<super::radio::Info> {
        matches!(self.phase, Phase::Calibrated | Phase::Station)
            .then_some(self.radio)
            .flatten()
    }
    pub(super) async fn prepare_radio(
        &mut self,
        factory: &super::efuse::Factory,
        permission: super::power_policy::Permission,
    ) -> Result<super::radio::Info, Error> {
        self.prepare_radio_with_policy(factory, permission, || {
            narf_wireless::reg::db::ensure_domain()
                .map_err(|_| Error::Power(super::power_policy::Error::Policy))
        })
        .await
    }
    pub(super) async fn prepare_radio_with_policy<F>(
        &mut self,
        factory: &super::efuse::Factory,
        permission: super::power_policy::Permission,
        policy: F,
    ) -> Result<super::radio::Info, Error>
    where
        F: Fn() -> Result<narf_wireless::reg::RegulatoryDomain, Error> + Send + Sync,
    {
        let plan = self.preflight_radio(factory, permission, &policy()?)?;
        self.prepare_radio_prepared(factory, plan, policy).await
    }
    pub(super) fn preflight_radio(
        &self,
        factory: &super::efuse::Factory,
        permission: super::power_policy::Permission,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<RadioPreflight, Error> {
        if self.phase != Phase::PhyTablesPrepared {
            return Err(Error::State);
        }
        let gain = self.current_power(permission, domain)?;
        let calibration = self.power.clone().ok_or(Error::State)?;
        let board = super::power_policy::Board::new(
            factory,
            self.phy.ok_or(Error::State)?,
            self.hardware.ok_or(Error::State)?,
            self.image_digest.ok_or(Error::State)?,
        )
        .map_err(Error::Power)?;
        if !calibration.matches(board) {
            return Err(Error::Power(super::power_policy::Error::Identity));
        }
        let gate = super::power_policy::Gate::new(calibration.clone(), permission, factory.mac());
        let mac = self.mac.ok_or(Error::State)?;
        let phy = self.phy.ok_or(Error::State)?;
        Ok(RadioPreflight {
            board,
            calibration,
            permission,
            gain,
            gate,
            mac,
            phy,
        })
    }
    pub(super) async fn prepare_radio_prepared<F>(
        &mut self,
        factory: &super::efuse::Factory,
        plan: RadioPreflight,
        policy: F,
    ) -> Result<super::radio::Info, Error>
    where
        F: Fn() -> Result<narf_wireless::reg::RegulatoryDomain, Error> + Send + Sync,
    {
        if self.phase != Phase::PhyTablesPrepared {
            return Err(Error::State);
        }
        let actual = super::power_policy::Board::new(
            factory,
            self.phy.ok_or(Error::State)?,
            self.hardware.ok_or(Error::State)?,
            self.image_digest.ok_or(Error::State)?,
        )
        .map_err(Error::Power)?;
        if actual != plan.board {
            return Err(Error::Power(super::power_policy::Error::Identity));
        }
        let RadioPreflight {
            calibration,
            permission,
            gain,
            gate,
            mac,
            phy,
            ..
        } = plan;
        // Poison before any radio/calibration register or await. A partial
        // calibration never grants replay, ordinary packet or carrier access.
        self.phase = Phase::Failed;
        let mut io = super::radio::Checked {
            io: &mut self.io,
            calibration: &calibration,
            permission,
            policy,
        };
        self.radio_gate = Some(gate.clone());
        let info = super::radio::prepare(&mut io, factory, mac, phy, gain, gate).await?;
        self.radio = Some(info);
        let p = self.phy.ok_or(Error::State)?;
        self.tracking_facts = Some(super::dm::Facts {
            did: 0xc822,
            rfe: p.rfe,
            crystal: p.crystal,
            thermal: factory.thermal(),
            power_track_type: (factory.logical()[0xc8] >> 4) & 15,
            cck_gi: info.cck_gi,
        });
        self.coex_facts = Some(super::coex::Facts {
            did: 0xc822,
            rfe: factory.rfe(),
            board_option: factory.board_option(),
            bt_setting: factory.bt_setting(),
        });
        self.phase = Phase::Calibrated;
        Ok(info)
    }
    pub(super) fn calibration_info8821c(&self) -> Option<super::radio8821c::Info> {
        matches!(
            self.phase,
            Phase::Calibration8821cPrepared
                | Phase::Operating8821cPrepared
                | Phase::Radio8821cPrepared
                | Phase::Station
        )
        .then_some(self.calibration8821c)
        .flatten()
    }
    pub(super) fn legacy_wmm_request(&self) -> Result<super::station_profile::Request, Error> {
        if !matches!(
            self.phase,
            Phase::Calibrated | Phase::Radio8821cPrepared | Phase::Station
        ) {
            return Err(Error::State);
        }
        if self.did == 0xc821 {
            return super::power_policy::Gate::c21(
                self.station_grant8821c
                    .as_ref()
                    .ok_or(Error::State)?
                    .clone(),
            )
            .extension_request()
            .ok_or(Error::Unsupported);
        }
        self.radio_gate
            .as_ref()
            .and_then(super::power_policy::Gate::extension_request)
            .ok_or(Error::Unsupported)
    }
    pub(super) fn ht20_request(&mut self) -> Result<super::ht::Request, Error> {
        self.io.station_ht_request()
    }
    pub(super) fn rx_ba_request(&mut self) -> Result<super::RxBaRequest, Error> {
        self.io.station_rx_ba_request()
    }
    pub(super) fn tx_ba_request(&mut self) -> Result<super::TxBaRequest, Error> {
        self.io.station_tx_ba_request()
    }
    pub(super) fn rts_request(&mut self) -> Result<super::RtsRequest, Error> {
        self.io.station_rts_request()
    }
    /// N2xD dynamic-mechanism measurement metadata. No grant.
    pub(super) async fn power_tracking_request(
        &mut self,
    ) -> Result<super::PowerTrackingRequest, Error> {
        let facts = self
            .tracking_facts
            .filter(|f| f.did == 0xc821 && f.power_track_type == 0 && f.thermal[0] <= 63)
            .ok_or(Error::Unsupported)?;
        let dm = self
            .station
            .as_deref()
            .and_then(super::station::State::dm_grant);
        self.io
            .station_power_tracking_request(facts.thermal[0], dm)
            .await
    }
    pub(super) fn tracking_request(&mut self) -> Result<super::ContinuationRequest, Error> {
        self.io.station_continuation_request(&super::dm::KIND)
    }
    /// One periodic dynamic-mechanism watchdog step (Linux
    /// `rtw_watch_dog_work`, run with the retained owner held).
    pub(super) async fn station_watchdog(&mut self) -> Result<bool, super::station::Error> {
        match self.station.as_deref_mut() {
            Some(s) if self.phase == Phase::Station => s.watchdog(&mut self.io).await,
            _ => Ok(false),
        }
    }
    pub(super) fn station_tracking(&self) -> Option<&super::station::State> {
        self.station.as_deref().filter(|s| s.tracking_active())
    }
    pub(super) fn station_rts_threshold(&self) -> Option<u32> {
        self.station
            .as_deref()
            .and_then(super::station::State::rts_threshold)
    }
    pub(super) async fn station_set_rts_threshold(
        &mut self,
        value: u32,
    ) -> Result<(), super::station::Error> {
        self.station
            .as_deref_mut()
            .ok_or(super::station::Error::State)?
            .set_rts_threshold(&mut self.io, value)
            .await
    }
    pub(super) fn operating_info8821c(&self) -> Option<super::operating8821c::Info> {
        matches!(
            self.phase,
            Phase::Operating8821cPrepared | Phase::Radio8821cPrepared | Phase::Station
        )
        .then_some(self.operating8821c)
        .flatten()
    }
    pub(super) fn operating_request8821c(
        &self,
        factory: &super::efuse::Factory8821c,
    ) -> Result<super::operating8821c::Request, Error> {
        if self.did != 0xc821
            || !matches!(
                self.phase,
                Phase::Calibration8821cPrepared
                    | Phase::Operating8821cPrepared
                    | Phase::Radio8821cPrepared
                    | Phase::Station
            )
        {
            return Err(Error::State);
        }
        Ok(super::operating8821c::request(
            self.calibration_board8821c(factory)?.request(),
            self.calibration8821c.ok_or(Error::State)?,
        ))
    }
    pub(super) fn preflight_operating8821c(
        &self,
        factory: &super::efuse::Factory8821c,
        source: super::operating8821c::Source,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<alloc::sync::Arc<super::operating8821c::Envelope>, Error> {
        if self.phase != Phase::Calibration8821cPrepared {
            return Err(Error::State);
        }
        let envelope = source.load(
            self.operating_request8821c(factory)?,
            factory,
            self.envelope8821c.as_ref().ok_or(Error::State)?.clone(),
        )?;
        envelope.invoke(&|| Ok(domain.clone()), || Ok(()))?;
        Ok(alloc::sync::Arc::new(envelope))
    }
    pub(super) async fn prepare_operating8821c<F>(
        &mut self,
        factory: &super::efuse::Factory8821c,
        envelope: alloc::sync::Arc<super::operating8821c::Envelope>,
        policy: F,
    ) -> Result<super::operating8821c::Info, Error>
    where
        F: Fn() -> Result<narf_wireless::reg::RegulatoryDomain, Error> + Send + Sync,
    {
        if self.phase != Phase::Calibration8821cPrepared
            || !envelope.matches(&self.operating_request8821c(factory)?)
        {
            return Err(Error::State);
        }
        envelope.invoke(&policy, || Ok(()))?;
        self.phase = Phase::Failed;
        self.operating_envelope8821c = Some(envelope.clone());
        let info = narf_time::timeout(
            narf_time::Deadline::after_ms(3000),
            envelope.prepare(&mut self.io, policy),
        )
        .await
        .map_err(|_| Error::Deadline)??;
        self.operating8821c = Some(info);
        self.phase = Phase::Operating8821cPrepared;
        Ok(info)
    }
    pub(super) fn station_request8821c(
        &self,
        factory: &super::efuse::Factory8821c,
    ) -> Result<super::station_power8821c::Request, Error> {
        if self.did != 0xc821
            || !matches!(
                self.phase,
                Phase::Operating8821cPrepared | Phase::Radio8821cPrepared | Phase::Station
            )
        {
            return Err(Error::State);
        }
        // Retained power identity already binds the immutable factory/cut/RFE,
        // original firmware, IQK recipe and all exact operating gain indices.
        if !self
            .envelope8821c
            .as_ref()
            .ok_or(Error::State)?
            .matches(self.calibration_board8821c(factory)?)
        {
            return Err(Error::State);
        }
        Ok(super::station_power8821c::request(
            self.operating8821c.ok_or(Error::State)?,
            factory.mac(),
        ))
    }
    pub(super) fn station_radio_info8821c(&self) -> Option<super::radio8821c::StationInfo> {
        matches!(self.phase, Phase::Radio8821cPrepared | Phase::Station)
            .then_some(self.station_radio8821c)
            .flatten()
    }
    pub(super) fn preflight_station8821c(
        &self,
        factory: &super::efuse::Factory8821c,
        source: super::station_power8821c::Source,
    ) -> Result<alloc::sync::Arc<super::station_power8821c::Grant>, Error> {
        if self.phase != Phase::Operating8821cPrepared {
            return Err(Error::State);
        }
        source.load(
            self.station_request8821c(factory)?,
            self.operating_envelope8821c
                .as_ref()
                .ok_or(Error::State)?
                .clone(),
        )
    }
    pub(super) async fn prepare_station8821c(
        &mut self,
        factory: &super::efuse::Factory8821c,
        grant: alloc::sync::Arc<super::station_power8821c::Grant>,
    ) -> Result<super::radio8821c::StationInfo, Error> {
        if self.phase != Phase::Operating8821cPrepared
            || !grant.matches(&self.station_request8821c(factory)?)
        {
            return Err(Error::State);
        }
        grant.check()?;
        self.phase = Phase::Failed;
        self.station_grant8821c = Some(grant.clone());
        let result = narf_time::timeout(
            narf_time::Deadline::after_ms(4000),
            super::radio8821c::prepare_station(
                &mut self.io,
                factory,
                self.phy8821c.ok_or(Error::State)?,
                self.calibration8821c.ok_or(Error::State)?,
                self.operating8821c.ok_or(Error::State)?,
                grant,
            ),
        )
        .await
        .map_err(|_| Error::Deadline)??;
        self.station_radio8821c = Some(result);
        let p = self.phy8821c.ok_or(Error::State)?;
        self.tracking_facts = Some(super::dm::Facts {
            did: 0xc821,
            rfe: p.rfe,
            crystal: p.crystal,
            thermal: [factory.thermal(), 0xff],
            power_track_type: 0,
            cck_gi: [0, 0],
        });
        self.coex_facts = Some(super::coex::Facts {
            did: 0xc821,
            rfe: factory.rfe(),
            board_option: factory.board_option(),
            bt_setting: factory.bt_setting(),
        });
        self.phase = Phase::Radio8821cPrepared;
        Ok(result)
    }
    pub(super) fn calibration_request8821c(
        &self,
        factory: &super::efuse::Factory8821c,
    ) -> Result<super::calibration8821c::Request, Error> {
        if self.did != 0xc821 {
            return Err(Error::Unsupported);
        }
        if !matches!(
            self.phase,
            Phase::PhyTablesPrepared
                | Phase::Calibration8821cPrepared
                | Phase::Operating8821cPrepared
                | Phase::Radio8821cPrepared
                | Phase::Station
        ) {
            return Err(Error::State);
        }
        Ok(self.calibration_board8821c(factory)?.request())
    }
    fn calibration_board8821c(
        &self,
        factory: &super::efuse::Factory8821c,
    ) -> Result<super::calibration8821c::Board, Error> {
        super::calibration8821c::Board::new(
            factory,
            self.phy8821c.ok_or(Error::State)?,
            self.mac.ok_or(Error::State)?,
            self.hardware.ok_or(Error::State)?,
            self.image_digest.ok_or(Error::State)?,
        )
        .map_err(Error::Calibration8821c)
    }
    pub(super) fn preflight_calibration8821c(
        &self,
        factory: &super::efuse::Factory8821c,
        source: super::calibration8821c::Source,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<alloc::sync::Arc<super::calibration8821c::Envelope>, Error> {
        if self.did != 0xc821 {
            return Err(Error::Unsupported);
        }
        if self.phase != Phase::PhyTablesPrepared {
            return Err(Error::State);
        }
        let envelope = source
            .load(self.calibration_board8821c(factory)?)
            .map_err(Error::Calibration8821c)?;
        envelope.validate(domain).map_err(Error::Calibration8821c)?;
        Ok(alloc::sync::Arc::new(envelope))
    }
    pub(super) async fn prepare_calibration8821c<F>(
        &mut self,
        factory: &super::efuse::Factory8821c,
        envelope: alloc::sync::Arc<super::calibration8821c::Envelope>,
        policy: F,
    ) -> Result<super::radio8821c::Info, Error>
    where
        F: Fn() -> Result<narf_wireless::reg::RegulatoryDomain, Error> + Send + Sync,
    {
        if self.did != 0xc821 || self.phase != Phase::PhyTablesPrepared {
            return Err(Error::State);
        }
        // Consume only a preflight for the same immutable board/firmware owner.
        if !envelope.matches(self.calibration_board8821c(factory)?) {
            return Err(Error::Calibration8821c(
                super::calibration8821c::Error::Identity,
            ));
        }
        envelope
            .validate(&policy()?)
            .map_err(Error::Calibration8821c)?;
        self.phase = Phase::Failed;
        self.envelope8821c = Some(envelope.clone()); // before the first device access/await
        let mac = self.mac.ok_or(Error::State)?;
        let phy = self.phy8821c.ok_or(Error::State)?;
        let mut checked = super::radio8821c::Checked {
            io: &mut self.io,
            envelope: &*envelope,
            policy,
        };
        let result = narf_time::timeout(
            narf_time::Deadline::after_ms(12000),
            super::radio8821c::prepare(&mut checked, factory, mac, phy, &envelope),
        )
        .await
        .map_err(|_| Error::Deadline)??;
        self.calibration8821c = Some(result);
        self.phase = Phase::Calibration8821cPrepared;
        Ok(result)
    }
    /// RTL8822BE `rtw8822b_phy_set_param` table stage over the same retained
    /// MAC-prepared owner (`phy8822b`). Opens no RF/MAC TX path.
    pub(super) async fn prepare_phy8822b(
        &mut self,
        factory: &super::efuse8822b::Factory8822b,
    ) -> Result<super::phy8822b::Info, Error> {
        if self.did != 0xb822 {
            return Err(Error::Unsupported);
        }
        if self.phase != Phase::MacPrepared {
            return Err(Error::State);
        }
        // The factory map layout (MAC at 0xd0 or USB 0x107) must belong to
        // the same host interface that keys the B22 records. The
        // `rtw8822b_table.c` rows are interface-independent: no branch
        // header in the MAC/BB/AGC/RF-A/RF-B tables carries an `intf`
        // condition that differs between INTF_PCIE and INTF_USB, so
        // `phy/gen_rtl8822b_tables.py` with `intf = INTF_USB` emits the same
        // 17 frozen tables (`phy8822b::rows`).
        if factory.usb() != matches!(self.interface, super::phy8821c::Interface::Usb { .. }) {
            return Err(Error::Unsupported);
        }
        self.phase = Phase::Failed;
        let info = super::phy8822b::Info::from_factory(
            factory,
            self.mac.ok_or(Error::State)?.cut,
            self.hardware.ok_or(Error::State)?,
        )?;
        self.io.begin_phy()?;
        let info = super::phy8822b::prepare(&mut self.io, info).await?;
        self.io.finish_phy()?;
        self.phy8822b = Some(info);
        self.phase = Phase::PhyTablesPrepared;
        Ok(info)
    }
    fn calibration_board8822b(
        &self,
        factory: &super::efuse8822b::Factory8822b,
    ) -> Result<super::calibration8822b::Board, Error> {
        if self.did != 0xb822 {
            return Err(Error::Unsupported);
        }
        super::calibration8822b::Board::new(
            factory,
            self.phy8822b.ok_or(Error::State)?,
            self.mac.ok_or(Error::State)?,
            self.hardware.ok_or(Error::State)?,
            self.image_digest.ok_or(Error::State)?,
            self.interface.host_of(0xb822),
        )
        .map_err(Error::Calibration8822b)
    }
    /// Metadata a provisioner measures and signs as `N2BQ`; grants nothing.
    pub(super) fn calibration_request8822b(
        &self,
        factory: &super::efuse8822b::Factory8822b,
    ) -> Result<super::calibration8822b::Request, Error> {
        if !matches!(
            self.phase,
            Phase::PhyTablesPrepared | Phase::Calibration8821cPrepared
        ) {
            return Err(Error::State);
        }
        Ok(self.calibration_board8822b(factory)?.request())
    }
    pub(super) fn calibration_info8822b(&self) -> Option<super::radio8822b::Calibration> {
        self.calibration8822b
    }
    pub(super) fn preflight_calibration8822b(
        &self,
        factory: &super::efuse8822b::Factory8822b,
        source: super::calibration8822b::Source,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<alloc::sync::Arc<super::calibration8822b::Envelope>, Error> {
        if self.phase != Phase::PhyTablesPrepared {
            return Err(Error::State);
        }
        let envelope = source
            .load(self.calibration_board8822b(factory)?)
            .map_err(Error::Calibration8822b)?;
        envelope.validate(domain).map_err(Error::Calibration8822b)?;
        Ok(alloc::sync::Arc::new(envelope))
    }
    /// RTL8822BE `rtw8822b_phy_calibration` on ch1/20 inside the `N2BQ`
    /// envelope (`radio8822b::calibrate`). The owner records its internal
    /// phase as `Calibration8821cPrepared`; every later C21 continuation
    /// checks `0xc821` and so never accepts this owner.
    pub(super) async fn prepare_calibration8822b<F>(
        &mut self,
        factory: &super::efuse8822b::Factory8822b,
        envelope: alloc::sync::Arc<super::calibration8822b::Envelope>,
        policy: F,
    ) -> Result<super::radio8822b::Calibration, Error>
    where
        F: Fn() -> Result<narf_wireless::reg::RegulatoryDomain, Error> + Send + Sync,
    {
        if self.did != 0xb822 || self.phase != Phase::PhyTablesPrepared {
            return Err(Error::State);
        }
        if !envelope.matches(self.calibration_board8822b(factory)?) {
            return Err(Error::Calibration8822b(
                super::calibration8822b::Error::Identity,
            ));
        }
        envelope
            .validate(&policy()?)
            .map_err(Error::Calibration8822b)?;
        self.phase = Phase::Failed;
        self.envelope8822b = Some(envelope.clone()); // before the first device access/await
        let mac = self.mac.ok_or(Error::State)?;
        let phy = self.phy8822b.ok_or(Error::State)?;
        let mut checked = super::radio8821c::Checked {
            io: &mut self.io,
            envelope: &*envelope,
            policy,
        };
        let result = narf_time::timeout(
            narf_time::Deadline::after_ms(12000),
            super::radio8822b::calibrate(&mut checked, mac, phy, &envelope),
        )
        .await
        .map_err(|_| Error::Deadline)??;
        self.calibration8822b = Some(result);
        self.phase = Phase::Calibration8821cPrepared;
        Ok(result)
    }

    /// Metadata a provisioner measures and signs as `N2BP`; grants nothing.
    pub(super) fn operating_request8822b(
        &self,
        factory: &super::efuse8822b::Factory8822b,
    ) -> Result<super::operating8822b::Request, Error> {
        if self.did != 0xb822
            || !matches!(
                self.phase,
                Phase::Calibration8821cPrepared | Phase::Operating8821cPrepared
            )
        {
            return Err(Error::State);
        }
        let board = self.calibration_board8822b(factory)?;
        if !self
            .envelope8822b
            .as_ref()
            .ok_or(Error::State)?
            .matches(board)
        {
            return Err(Error::State);
        }
        Ok(super::operating8822b::request(
            board.request(),
            self.calibration8822b.ok_or(Error::State)?,
        ))
    }
    pub(super) fn operating_info8822b(&self) -> Option<super::operating8822b::Info> {
        (self.did == 0xb822 && self.phase == Phase::Operating8821cPrepared)
            .then_some(self.operating8822b)
            .flatten()
    }
    pub(super) fn preflight_operating8822b(
        &self,
        factory: &super::efuse8822b::Factory8822b,
        source: super::operating8822b::Source,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<alloc::sync::Arc<super::operating8822b::Envelope>, Error> {
        if self.did != 0xb822 || self.phase != Phase::Calibration8821cPrepared {
            return Err(Error::State);
        }
        let envelope = source.load(
            self.operating_request8822b(factory)?,
            factory,
            self.envelope8822b.as_ref().ok_or(Error::State)?.clone(),
        )?;
        envelope.invoke(&|| Ok(domain.clone()), || Ok(()))?;
        Ok(alloc::sync::Arc::new(envelope))
    }
    /// RTL8822BE parked `N2BP` operating power after the `N2BQ` IQK
    /// (`operating8822b::Envelope::prepare`), bounded to three seconds.
    pub(super) async fn prepare_operating8822b<F>(
        &mut self,
        factory: &super::efuse8822b::Factory8822b,
        envelope: alloc::sync::Arc<super::operating8822b::Envelope>,
        policy: F,
    ) -> Result<super::operating8822b::Info, Error>
    where
        F: Fn() -> Result<narf_wireless::reg::RegulatoryDomain, Error> + Send + Sync,
    {
        if self.did != 0xb822
            || self.phase != Phase::Calibration8821cPrepared
            || !envelope.matches(&self.operating_request8822b(factory)?)
        {
            return Err(Error::State);
        }
        envelope.invoke(&policy, || Ok(()))?;
        self.phase = Phase::Failed;
        self.operating_envelope8822b = Some(envelope.clone());
        let info = narf_time::timeout(
            narf_time::Deadline::after_ms(3000),
            envelope.prepare(&mut self.io, policy),
        )
        .await
        .map_err(|_| Error::Deadline)??;
        self.operating8822b = Some(info);
        self.phase = Phase::Operating8821cPrepared;
        Ok(info)
    }
    /// Metadata a provisioner measures and signs as `N2BS`; grants nothing.
    pub(super) fn station_request8822b(
        &self,
        factory: &super::efuse8822b::Factory8822b,
    ) -> Result<super::operating8822b::StationRequest, Error> {
        if self.did != 0xb822 || self.phase != Phase::Operating8821cPrepared {
            return Err(Error::State);
        }
        Ok(super::operating8822b::station_request(
            self.operating8822b.ok_or(Error::State)?,
            factory.mac(),
        ))
    }
    /// Decode and currently authorize `N2BS` over the retained `N2BP`.
    pub(super) fn preflight_station8822b(
        &self,
        factory: &super::efuse8822b::Factory8822b,
        source: super::operating8822b::StationSource,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<alloc::sync::Arc<super::operating8822b::Grant>, Error> {
        let grant = source.load(
            self.station_request8822b(factory)?,
            self.operating_envelope8822b
                .as_ref()
                .ok_or(Error::State)?
                .clone(),
        )?;
        grant.invoke(&|| Ok(domain.clone()), || Ok(()))?;
        Ok(grant)
    }
    /// RTL8822BE awake-station radio program (`radio8822b::prepare_station`)
    /// inside `N2BQ` + `N2BP` + `N2BS` and current policy, bounded to four
    /// seconds like C21's. Success earns `Radio8821cPrepared` with the B22
    /// packet gate retained by the PCI transport.
    pub(super) async fn prepare_station8822b<F>(
        &mut self,
        factory: &super::efuse8822b::Factory8822b,
        grant: alloc::sync::Arc<super::operating8822b::Grant>,
        policy: F,
    ) -> Result<super::radio8821c::StationInfo, Error>
    where
        F: Fn() -> Result<narf_wireless::reg::RegulatoryDomain, Error> + Send + Sync,
    {
        if self.did != 0xb822
            || self.phase != Phase::Operating8821cPrepared
            || !grant.matches(&self.station_request8822b(factory)?)
        {
            return Err(Error::State);
        }
        grant.invoke(&policy, || Ok(()))?;
        self.phase = Phase::Failed;
        self.station_grant8822b = Some(grant.clone());
        let result = narf_time::timeout(
            narf_time::Deadline::after_ms(4000),
            super::radio8822b::prepare_station(
                &mut self.io,
                factory,
                self.phy8822b.ok_or(Error::State)?,
                grant,
                policy,
            ),
        )
        .await
        .map_err(|_| Error::Deadline)??;
        self.station_radio8821c = Some(result);
        // dm watchdog facts (`dm::B22_MECHANISMS`: DIG/RA only; no
        // `rtw8822b_pwr_track` under N2BD, so the power-track type is unused).
        let p = self.phy8822b.ok_or(Error::State)?;
        self.tracking_facts = Some(super::dm::Facts {
            did: 0xb822,
            rfe: p.rfe,
            crystal: p.crystal,
            thermal: [factory.thermal(), 0xff],
            power_track_type: 0,
            cck_gi: [0, 0],
        });
        self.phase = Phase::Radio8821cPrepared;
        Ok(result)
    }
    pub(super) async fn prepare_phy8821c(
        &mut self,
        factory: &super::efuse::Factory8821c,
    ) -> Result<super::phy8821c::Info, Error> {
        if self.did != 0xc821 {
            return Err(Error::Unsupported);
        }
        if self.phase != Phase::MacPrepared {
            return Err(Error::State);
        }
        // The factory map layout (MAC at 0xd0 or USB 0x107) must belong to
        // the same host interface that keys the rows and records.
        if factory.usb() != matches!(self.interface, super::phy8821c::Interface::Usb { .. }) {
            return Err(Error::Unsupported);
        }
        self.phase = Phase::Failed;
        let info = super::phy8821c::Info::from_factory(
            factory,
            self.mac.ok_or(Error::State)?.cut,
            self.hardware.ok_or(Error::State)?,
        )?
        .on(self.interface);
        self.io.begin_phy()?;
        // The firmware antenna report can narrow a physical two-path chip in
        // Linux. This continuation admits only genuine one-path C21 silicon,
        // with the same current cut used by the original conditional parser.
        let cfg = self.io.read32(0xf0).await?;
        if cfg == u32::MAX {
            return Err(Error::Gone);
        }
        if cfg & (1 << 27) != 0 || (cfg >> 12) & 15 != u32::from(info.cut) {
            return Err(Error::Unsupported);
        }
        let info = narf_time::timeout(
            narf_time::Deadline::after_ms(2000),
            super::phy8821c::prepare(&mut self.io, info),
        )
        .await
        .map_err(|_| Error::Deadline)??;
        self.io.finish_phy()?;
        self.phy8821c = Some(info);
        self.phase = Phase::PhyTablesPrepared;
        Ok(info)
    }
    pub async fn prepare_phy_tables(
        &mut self,
        factory: &super::efuse::Factory,
    ) -> Result<super::phy::Info, Error> {
        if self.did != 0xc822 {
            return Err(Error::Unsupported);
        }
        if self.phase != Phase::MacPrepared {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let info = super::phy::Info::from_factory(
            factory,
            self.mac.ok_or(Error::State)?.cut,
            self.hardware.ok_or(Error::State)?,
        )?;
        self.io.begin_phy()?;
        let info = super::phy::prepare(&mut self.io, info).await?;
        self.io.finish_phy()?;
        self.phy = Some(info);
        self.phase = Phase::PhyTablesPrepared;
        Ok(info)
    }
    /// Production always opens exactly the NIC image through current firmware
    /// authority; the same signature/header can occur in WoW or sibling files.
    pub async fn initialize_registered(&mut self) -> Result<Info, Error> {
        let did = self.did;
        self.initialize_registered_with(|| registered_image(did))
            .await
    }
    async fn initialize_registered_with(
        &mut self,
        load: impl FnOnce() -> Result<PreparedImage, Error>,
    ) -> Result<Info, Error> {
        if self.phase != Phase::New {
            return Err(Error::State);
        }
        let image = load()?;
        self.initialize_prepared(image).await
    }
    pub(super) async fn initialize_prepared(
        &mut self,
        image: PreparedImage,
    ) -> Result<Info, Error> {
        if self.phase != Phase::New || self.did != image.did {
            return Err(Error::State);
        }
        // The staged bytes are immutable and parsed before this single-use
        // boundary. Every attempted claim, I/O failure or drop stays terminal.
        self.phase = Phase::Failed;
        self.download_inner(&image.bytes).await
    }
    /// In-family authenticated owner/model entry; production uses registry.
    pub(super) async fn download(&mut self, bytes: &[u8]) -> Result<Info, Error> {
        if self.phase != Phase::New {
            return Err(Error::State);
        }
        // Fail before the first await; cancellation cannot reconstruct/reset
        // firmware over a backend with outstanding reserved-page ownership.
        self.phase = Phase::Failed;
        self.download_inner(bytes).await
    }
    async fn download_inner(&mut self, bytes: &[u8]) -> Result<Info, Error> {
        let image = parse(self.did, bytes)?;
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(bytes);
        self.image_digest = Some(hash.finalize());
        self.io.claim_pristine()?;
        narf_time::timeout(narf_time::Deadline::after_ms(2000), self.run(&image))
            .await
            .map_err(|_| Error::Deadline)??;
        self.info = Some(image.info);
        self.phase = Phase::Ready;
        Ok(image.info)
    }
    /// `wow.c::rtw_wow_swap_fw`: download another authenticated image (WoW
    /// or the normal restore) into the running station's CPU through the
    /// same section sequence as bring-up. A failure poisons the owner.
    pub(super) async fn swap_firmware(&mut self, image: &PreparedImage) -> Result<Info, Error> {
        if self.phase != Phase::Station || self.did != image.did {
            return Err(Error::State);
        }
        let boundary =
            super::reserved_page::station_boundary(self.did).ok_or(Error::Unsupported)?;
        self.io.claim_swap(boundary)?;
        self.phase = Phase::Failed;
        let parsed = parse(self.did, &image.bytes)?;
        narf_time::timeout(narf_time::Deadline::after_ms(2000), self.run(&parsed))
            .await
            .map_err(|_| Error::Deadline)??;
        self.phase = Phase::Station;
        Ok(parsed.info)
    }
    async fn update8(&mut self, reg: u16, clear: u8, set: u8) -> Result<(), Error> {
        let value = self.io.read8(reg).await?;
        self.io.write8(reg, value & !clear | set).await
    }
    async fn poll(&mut self, reg: u16, mask: u32, target: u32) -> Result<(), Error> {
        for _ in 0..1000 {
            let value = self.io.read32(reg).await?;
            if value == u32::MAX {
                return Err(Error::Gone);
            }
            if value & mask == target {
                return Ok(());
            }
            self.io.delay_us(10).await;
        }
        Err(Error::Timeout)
    }
    async fn cpu(&mut self, enable: bool) -> Result<(), Error> {
        if enable {
            self.update8(0x1d, 0, 1).await?;
            self.update8(3, 0, 4).await
        } else {
            self.update8(3, 4, 0).await?;
            self.update8(0x1d, 1, 0).await
        }
    }
    async fn backup(&mut self) -> Result<Backup, Error> {
        let map = self.io.read8(0x10d).await?;
        self.io.write8(0x10d, 0xc0).await?;
        let cr = self.io.read8(0x100).await?;
        self.io.write8(0x100, 5).await?;
        self.io.write32(0x1330, 1 << 31).await?;
        let pages = self.io.read16(0x230).await?;
        let rqpn = self.io.read32(0x22c).await? | 1 << 31;
        self.io.write16(0x230, 0x200).await?;
        self.io.write32(0x22c, rqpn).await?;
        let beacon = self.io.read8(0x550).await?;
        self.io.write8(0x550, beacon & !8 | 16).await?;
        Ok(Backup {
            map,
            cr,
            pages,
            rqpn,
            beacon,
        })
    }
    async fn restore(&mut self, b: &Backup) -> Result<(), Error> {
        self.io.write8(0x10d, b.map).await?;
        self.io.write8(0x100, b.cr).await?;
        self.io.write32(0x1330, 1 << 31).await?;
        self.io.write16(0x230, b.pages).await?;
        self.io.write32(0x22c, b.rqpn).await?;
        self.io.write8(0x550, b.beacon).await
    }
    async fn section(&mut self, section: &Section<'_>) -> Result<(), Error> {
        let control = self.io.read32(0x1208).await?;
        if control == u32::MAX {
            return Err(Error::Gone);
        }
        self.io.write32(0x1208, control | 1 << 25).await?;
        for (part, bytes) in section.bytes.chunks(4096).enumerate() {
            // Native transport mirrors fw.c's beacon-page validity and exact
            // TD completion; only then may IDDMA consume the device TXBUF.
            self.io.reserved_page(bytes).await?;
            self.poll(0x1208, 1 << 31, 0).await?;
            let control =
                1 << 31 | 1 << 29 | if part != 0 { 1 << 24 } else { 0 } | bytes.len() as u32;
            self.io.write32(0x1200, 0x18780000 + 48).await?;
            self.io
                .write32(0x1204, section.address + part as u32 * 4096)
                .await?;
            self.io.write32(0x1208, control).await?;
            self.poll(0x1208, 1 << 31, 0).await?;
        }
        let control = self.io.read8(0x80).await?;
        if self.io.read32(0x1208).await? & 1 << 27 != 0 {
            return Err(Error::Checksum);
        }
        self.io
            .write8(
                0x80,
                control
                    | if section.address < 0x200000 {
                        0x18
                    } else {
                        0x60
                    },
            )
            .await
    }
    async fn run(&mut self, image: &Image<'_>) -> Result<(), Error> {
        let lte = self.io.lte_backup().await?;
        self.cpu(false).await?;
        let backup = self.backup().await?;
        self.update8(0x1082, 1, 0).await?;
        self.update8(9, 0x40, 0).await?;
        self.update8(0x1082, 0, 1).await?;
        self.update8(9, 0, 0x40).await?;
        let control = self.io.read16(0x80).await? & 0x3800 | 1;
        self.io.write16(0x80, control).await?;
        for section in image.sections.iter().flatten() {
            self.section(section).await?;
        }
        self.restore(&backup).await?;
        self.io.write32(0x210, 4).await?;
        let control = self.io.read16(0x80).await?;
        if control & 0x50 != 0x50 {
            return Err(Error::Checksum);
        }
        self.io.write16(0x80, (control | 1 << 14) & !1).await?;
        self.cpu(true).await?;
        self.io.lte_restore(lte).await?;
        self.poll(0x80, 0xffff & !0x3000, 0xc078)
            .await
            .map_err(|error| {
                if error == Error::Timeout {
                    Error::Ready
                } else {
                    error
                }
            })?;
        self.io.finish_dma().await
    }
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "channel_policy_tests.rs"]
mod channel_policy_tests;
#[cfg(any(test, feature = "kernel-test"))]
#[path = "ht40_tests.rs"]
mod ht40_tests;
#[cfg(any(test, feature = "kernel-test"))]
#[path = "mac/tests.rs"]
mod mac_tests;
#[cfg(any(test, feature = "kernel-test"))]
#[path = "phy/tests.rs"]
mod phy_tests;
#[cfg(any(test, feature = "kernel-test"))]
#[path = "power_policy_tests.rs"]
mod power_policy_tests;
#[cfg(any(test, feature = "kernel-test"))]
#[path = "radio/tests.rs"]
mod radio_tests;
#[cfg(any(test, feature = "kernel-test"))]
#[path = "station_composition_tests.rs"]
pub(super) mod station_composition_tests;
#[cfg(any(test, feature = "kernel-test"))]
#[path = "firmware_transport_tests.rs"]
mod tests;

#[cfg(any(test, feature = "kernel-test"))]
#[path = "phy/rtl8821c_tests.rs"]
mod phy8821c_tests;

#[cfg(any(test, feature = "kernel-test"))]
#[path = "b22_tests.rs"]
mod b22_tests;

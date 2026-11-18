// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained rtlwifi paged MMIO firmware owner; Linux rtlwifi/rtl8188ee/fw.c
//! rtl8821ae/fw.c, rtl8192ee/fw.c, rtl8192c/fw_common.c and
//! rtl8723com/fw_common.c. Profiles: RTL8188EE, RTL8821AE, RTL8192EE,
//! RTL8192CE/8188CE (normal images), RTL8723BE and RTL8723AE.
//! PCI bus mastering remains parked. This does not install native packet rings.
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use narf_firmware::FirmwareError;
use narf_lib::{
    mutex::Mutex,
    sync::{IrqSafeSpinLock, OnceLock},
};

const HEADER: usize = 32;
const PAGE: usize = 4096;
const MAX_PAYLOAD: usize = PAGE * 8;
const MCU: u16 = 0x80;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Image,
    NoMemory,
    Access,
    Gone,
    Gate,
    AlreadyStarted,
    Checksum,
    Start,
    Deadline,
    Cancelled,
    Firmware(FirmwareError),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Detected,
    Validated,
    Preparing,
    Downloading,
    Ready,
    Failed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status {
    pub stage: Stage,
    pub error: Option<Error>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Info {
    pub version: u16,
    pub subversion: u8,
    pub payload: usize,
}
/// Exact PCI firmware header, authenticated by the profile-selected filename.
/// 88E1 alone cannot distinguish an EE image from an EU image.
/// `rtl8821ae/sw.c` `wowlan_firmware`: `rtl8821aefw_wowlan.bin` opened
/// through the trusted registry authority (as the normal image) and its
/// header validated; the bytes are downloaded later by the WoWLAN
/// card-disable branch (`rtl8821ae_set_fw_related_for_wowlan(true)`).
pub(crate) fn registered_wowlan_image() -> Result<Vec<u8>, Error> {
    let loader = narf_firmware::trusted_loader_authority()
        .ok_or(Error::Firmware(FirmwareError::AuthorityRevoked))?;
    let authority = loader
        .derive()
        .map_err(|_| Error::Firmware(FirmwareError::AuthorityRevoked))?;
    let asset = crate::firmware_asset::load(
        &authority,
        super::rtl8821ae::fw::FW_WOWLAN,
        HEADER + MAX_PAYLOAD,
        false,
    )
    .map_err(Error::Firmware)?;
    parse(super::regs::RTL_DEV_8821AE, &asset.bytes)?;
    Ok(asset.bytes.to_vec())
}
pub fn parse(did: u16, bytes: &[u8]) -> Result<(Info, &[u8]), Error> {
    if did == super::regs::RTL_DEV_8821AE {
        // IS_FW_HEADER_EXIST_8821 plus exact RAM-code length (rtl8821ae/fw.rs).
        return super::rtl8821ae::fw::parse(bytes);
    }
    if did == super::regs::RTL_DEV_8192EE {
        // IS_FW_HEADER_EXIST (0x92e0) plus exact RAM-code length.
        return super::rtl8192ee::fw::parse(bytes);
    }
    if super::rtl8192ce::is_8192ce(did) {
        // IS_FW_HEADER_EXIST (0x92c0 / 0x88c0), exact length, max_fw_size.
        return super::rtl8192ce::fw::parse(bytes);
    }
    if did == super::regs::RTL_DEV_8723BE {
        // rtl8723be is_fw_header (0x5300), exact length, max_fw_size.
        return super::rtl8723be::fw::parse(bytes);
    }
    if did == super::regs::RTL_DEV_8723AE {
        // rtl8723ae is_fw_header (0x2300), exact length, max_fw_size.
        return super::rtl8723ae::fw::parse(bytes);
    }
    if did == super::regs::RTL_DEV_8192DE {
        // IS_FW_HEADER_EXIST (0x92c0 / 0x88c0 masked, 0x92d0-0x92d3
        // exact), exact length, max_fw_size.
        return super::rtl8192de::fw::parse(bytes);
    }
    if did != super::regs::RTL_DEV_8188EE {
        return Err(Error::Unsupported);
    }
    if bytes.len() <= HEADER || bytes[..2] != [0xe1, 0x88] {
        return Err(Error::Image);
    }
    let body = &bytes[HEADER..];
    if usize::from(u16::from_le_bytes([bytes[12], bytes[13]])) != body.len()
        || body.len() > MAX_PAYLOAD
    {
        return Err(Error::Image);
    }
    Ok((
        Info {
            version: u16::from_le_bytes([bytes[4], bytes[5]]),
            subversion: bytes[6],
            payload: body.len(),
        },
        body,
    ))
}
#[async_trait::async_trait]
pub trait Io: Send + Sync {
    /// Restrict only this original8821 PCI function. Defaults are NOT a
    /// park/stop receipt; unsupported backends retain all resources.
    fn restrict_8821_packets(&self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }

    fn read8(&self, reg: u16) -> Result<u8, Error>;
    fn read32(&self, reg: u16) -> Result<u32, Error>;
    /// Exact-width source EFUSE/SYS word access. Unsupported adapters
    /// refuse instead of widening to an unaligned dword or splitting bytes.
    fn read16(&self, _reg: u16) -> Result<u16, Error> {
        Err(Error::Access)
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), Error>;
    fn write32(&self, reg: u16, value: u32) -> Result<(), Error>;
    fn write_bytes(&self, reg: u16, bytes: &[u8]) -> Result<(), Error>;
    /// Exact-width 16-bit MMIO write. Profiles whose Linux sequence uses
    /// `rtl_write_word` (RTL8821AE LLT/MAC init) require it; adapters that
    /// cannot issue one refuse rather than splitting it into bytes.
    fn write16(&self, _reg: u16, _value: u16) -> Result<(), Error> {
        Err(Error::Access)
    }
    async fn delay_us(&self, micros: u64) {
        if micros == 0 {
            narf_scheduler::yield_now().await;
        } else {
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(micros.saturating_mul(1000)))
                .await;
        }
    }
}
pub struct Owner<I: Io> {
    io: I,
    did: u16,
    started: AtomicBool,
    native_claimed: AtomicBool,
    status: IrqSafeSpinLock<Status>,
    identity: IrqSafeSpinLock<Option<Identity>>,
    // Allocated only for AE and retained across all firmware/table awaits.
    ae_cold: Mutex<Option<Box<super::rtl8723ae::init::Owner>>>,
    ae_access: OnceLock<Arc<dyn AeAccess>>,
    ae_retired: AtomicBool,
}
/// The AE continuation stays closed until the original registered capsule
/// installs its separately signed station program. The closure is the actual
/// access, not an unguarded future or a caller-provided admission boolean.
pub(in crate::rtlwifi) trait AeAccess: Send + Sync {
    /// Immutable selected profile metadata. This is no current effect
    /// grant; invoke_effect still encloses each actual ASPM operation.
    fn aspm_profile(&self) -> bool {
        false
    }
    fn invoke(&self, operation: &mut dyn FnMut() -> Result<(), Error>) -> Result<(), Error>;
    /// Actual synchronous scalar/control effect. AE serializes this narrow
    /// boundary with terminal park; outer poll/descriptor scopes stay reentrant.
    fn invoke_effect(&self, operation: &mut dyn FnMut() -> Result<(), Error>) -> Result<(), Error>;
}
/// Earlier AE cold work must also stop on detach/source loss. The original
/// cold Box remains in Owner; this facade encloses the ACTUAL access/poll.
struct AeColdIo<'a, I: Io> {
    owner: &'a Owner<I>,
    image: Option<Identity>,
}
impl<I: Io> AeColdIo<'_, I> {
    fn access<T>(&self, operation: impl FnOnce(&I) -> Result<T, Error>) -> Result<T, Error> {
        let current = || {
            if self.owner.ae_retired.load(Ordering::Acquire) {
                return Err(Error::Gate);
            }
            operation(&self.owner.io)
        };
        if self.owner.ae_retired.load(Ordering::Acquire) {
            return Err(Error::Gate);
        }
        match self.image {
            Some(image) => image
                .invoke(|| current().map_err(super::prepare::Error::Access))
                .map_err(|error| match error {
                    super::prepare::Error::Access(error) => error,
                    _ => Error::Gate,
                }),
            None => current(), // Read-only version selection before an image exists.
        }
    }
    fn poll<F: core::future::Future + ?Sized>(
        &self,
        future: core::pin::Pin<&mut F>,
        cx: &mut core::task::Context<'_>,
    ) -> Result<core::task::Poll<F::Output>, Error> {
        self.access(|_| Ok(future.poll(cx)))
    }
}
#[async_trait::async_trait]
impl<I: Io> Io for AeColdIo<'_, I> {
    fn read8(&self, r: u16) -> Result<u8, Error> {
        self.access(|io| io.read8(r))
    }
    fn read16(&self, r: u16) -> Result<u16, Error> {
        self.access(|io| io.read16(r))
    }
    fn read32(&self, r: u16) -> Result<u32, Error> {
        self.access(|io| io.read32(r))
    }
    fn write8(&self, r: u16, v: u8) -> Result<(), Error> {
        self.access(|io| io.write8(r, v))
    }
    fn write16(&self, r: u16, v: u16) -> Result<(), Error> {
        self.access(|io| io.write16(r, v))
    }
    fn write32(&self, r: u16, v: u32) -> Result<(), Error> {
        self.access(|io| io.write32(r, v))
    }
    fn write_bytes(&self, r: u16, v: &[u8]) -> Result<(), Error> {
        self.access(|io| io.write_bytes(r, v))
    }
    async fn delay_us(&self, us: u64) {
        self.owner.io.delay_us(us).await;
    }
}
/// Exact image of the successful retained CPU owner; not an upload receipt.
#[derive(Clone, Copy)]
pub(crate) struct Identity {
    pub(super) digest: [u8; 32],
    /// Actual selected/validated header bytes, not a filename or caller's
    /// guessed chip version. Short inert fixtures carry no header facts.
    pub(super) version: Option<(u16, u8)>,
    source: Option<narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>>,
}
impl Identity {
    fn from_bytes(
        bytes: &[u8],
        source: Option<
            narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>,
        >,
    ) -> Self {
        let mut h = narf_crypto::sha256::Sha256::new();
        h.update(bytes);
        Self {
            digest: h.finalize(),
            version: bytes
                .get(4..7)
                .map(|v| (u16::from_le_bytes([v[0], v[1]]), v[2])),
            source,
        }
    }
    /// An unsourced identity over `bytes` for qualification fixtures.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn fixture(bytes: &[u8]) -> Self {
        Self::from_bytes(bytes, None)
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn fixture_with_source(
        bytes: &[u8],
        source: narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>,
    ) -> Self {
        Self::from_bytes(bytes, Some(source))
    }
    pub(super) fn invoke<T>(
        &self,
        operation: impl FnOnce() -> Result<T, super::prepare::Error>,
    ) -> Result<T, super::prepare::Error> {
        use narf_capabilities::{Cap, CapError, CapOp, Read};
        struct Current<F>(F);
        impl<T, F: FnOnce() -> Result<T, super::prepare::Error>>
            CapOp<narf_firmware::FirmwareBlob, Read> for Current<F>
        {
            type Output = Result<T, super::prepare::Error>;
            fn execute(
                self,
                _: &Cap<narf_firmware::FirmwareBlob, Read>,
            ) -> Result<Self::Output, CapError> {
                Ok((self.0)())
            }
        }
        if let Some(cap) = &self.source {
            return cap.invoke(Current(operation)).map_err(|_| {
                super::prepare::Error::Access(Error::Firmware(FirmwareError::AuthorityRevoked))
            })?;
        }
        #[cfg(any(test, feature = "kernel-test"))]
        return operation(); // Supplied-image fixture owners cannot construct real PCI I/O.
        #[cfg(not(any(test, feature = "kernel-test")))]
        Err(super::prepare::Error::Access(Error::Firmware(
            FirmwareError::AuthorityRevoked,
        )))
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn model() -> Self {
        Self::from_bytes(b"inert EE unit identity", None)
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn revoke_source(self) -> bool {
        self.source.is_some_and(|cap| {
            cap.revoke();
            true
        })
    }
}
impl<I: Io> core::fmt::Debug for Owner<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RtlwifiFirmwareOwner")
            .field("device_id", &self.did)
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}
/// Exclusive native continuation of the exact successful firmware owner.
/// No Clone and no public constructor: a second owner cannot overwrite the
/// ring bases or LLT while the first retains published device DMA.
pub(super) struct PacketIo<I: Io>(Arc<Owner<I>>, Arc<PacketState>);
impl<I: Io> PacketIo<I> {
    pub(super) fn require_ae_aspm_profile(&self) -> Result<(), Error> {
        if self.0.did != super::regs::RTL_DEV_8723AE
            || !self
                .0
                .ae_access
                .get()
                .is_some_and(|access| access.aspm_profile())
        {
            return Err(Error::Gate);
        }
        self.with_effect_io(|_| Ok(()))
    }
}
impl PacketIo<super::firmware_native::PciIo> {
    /// Shared receipt metadata only; configuration effects still use the
    /// current original source/PCI invocation through with_effect_io.
    pub(super) fn original_aspm_receipt(&self) -> &AtomicBool {
        super::aspm::PolicyPort::prepared(self.0.native())
    }
}
struct PacketState {
    program: OnceLock<Arc<super::rtl8821ae::coex_program::Program>>,
    // Historical metadata from the original owner's single actual inquiry.
    // Its presence consumes qualification even when no signed asset exists.
    request: OnceLock<super::rtl8821ae::coex_program::Request>,
    scalar: narf_lib::sync::IrqSafeSpinLock<()>,
    retired: AtomicBool,
}
impl PacketState {
    fn new() -> Self {
        Self {
            program: OnceLock::new(),
            request: OnceLock::new(),
            scalar: narf_lib::sync::IrqSafeSpinLock::new(()),
            retired: AtomicBool::new(false),
        }
    }
    // No scalar lock here: outer polls, descriptor scopes and their scalar
    // children must remain reentrant. Only with_effect_io takes that gate.
    fn current<I: Io, T>(
        &self,
        owner: &Owner<I>,
        operation: impl FnOnce(&I) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if self.retired.load(Ordering::Acquire) || owner.status().stage != Stage::Ready {
            return Err(Error::Gate);
        }
        let image = owner.identity().ok_or(Error::Gate)?;
        let effect = || operation(&owner.io).map_err(super::prepare::Error::Access);
        image
            .invoke(|| {
                if let Some(program) = self.program.get() {
                    program.invoke(effect)
                } else {
                    effect()
                }
            })
            .map_err(|e| match e {
                super::prepare::Error::Access(e) => e,
                _ => Error::Gate,
            })
    }
}

impl<I: Io> core::fmt::Debug for PacketIo<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8188eePacketIo")
            .field("firmware", &self.0)
            .finish_non_exhaustive()
    }
}
impl<I: Io> PacketIo<I> {
    pub(super) fn bind_8821_program(
        &self,
        base: Arc<super::rtl8821ae::envelope::Calibration>,
        factory: &super::efuse::Factory,
        permission: super::rtl8821ae::envelope::Permission,
        bt: super::rtl8821ae::coex_program::BtIdentity,
    ) -> Result<Option<Arc<super::rtl8821ae::coex_program::Program>>, super::prepare::Error> {
        self.bind_8821_program_using(&base, factory, permission, bt, |image| {
            super::rtl8821ae::coex_program::Program::registered(
                base.clone(),
                image,
                factory,
                permission,
                bt,
            )
        })
    }
    fn bind_8821_program_using(
        &self,
        base: &super::rtl8821ae::envelope::Calibration,
        factory: &super::efuse::Factory,
        permission: super::rtl8821ae::envelope::Permission,
        bt: super::rtl8821ae::coex_program::BtIdentity,
        load: impl FnOnce(
            Identity,
        ) -> Result<
            Option<Arc<super::rtl8821ae::coex_program::Program>>,
            super::prepare::Error,
        >,
    ) -> Result<Option<Arc<super::rtl8821ae::coex_program::Program>>, super::prepare::Error> {
        if self.0.did != super::regs::RTL_DEV_8821AE
            || self.0.status().stage != Stage::Ready
            || self.1.program.get().is_some()
            || self.1.request.get().is_some()
            || self.1.retired.load(Ordering::Acquire)
        {
            return Err(super::prepare::Error::State);
        }
        let image = self.0.identity().ok_or(super::prepare::Error::State)?;
        base.with_current(|| {
            image.invoke(|| {
                if self.1.retired.load(Ordering::Acquire) {
                    return Err(super::prepare::Error::State);
                }
                let request =
                    super::rtl8821ae::coex_program::request(base, image, factory, permission, bt)?;
                // Latch before the lookup, including NotFound and load errors.
                // A second binding must rebuild the original native owner.
                self.1
                    .request
                    .set(request)
                    .map_err(|_| super::prepare::Error::State)
            })
        })?;
        let program = load(image)?;
        if self.1.retired.load(Ordering::Acquire) {
            return Err(super::prepare::Error::State);
        }
        if let Some(program) = &program {
            self.1
                .program
                .set(program.clone())
                .map_err(|_| super::prepare::Error::State)?;
        }
        Ok(program)
    }
    /// Prior observed provisioning metadata only. Cloning it performs no
    /// I/O, current-source validation, asset lookup or grant installation.
    pub(super) fn request_8821_program(&self) -> Option<super::rtl8821ae::coex_program::Request> {
        self.1.request.get().cloned()
    }
    pub(super) fn with_effect_io<T>(
        &self,
        operation: impl FnOnce(&I) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if self.0.did != super::regs::RTL_DEV_8723AE {
            if self.0.did == super::regs::RTL_DEV_8821AE {
                let _scalar = self.1.scalar.lock();
                return self.1.current(&self.0, operation);
            }
            return self.1.current(&self.0, operation);
        }
        if self.0.status().stage != Stage::Ready {
            return Err(Error::Gate);
        }
        let access = self.0.ae_access.get().ok_or(Error::Gate)?;
        let mut operation = Some(operation);
        let mut result = None;
        access.invoke_effect(&mut || {
            result = Some(operation.take().ok_or(Error::Gate)?(&self.0.io)?);
            Ok(())
        })?;
        result.ok_or(Error::Gate)
    }
    pub(super) fn with_io<T>(
        &self,
        operation: impl FnOnce(&I) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if self.0.status().stage != Stage::Ready {
            return Err(Error::Gate);
        }
        if self.0.did == super::regs::RTL_DEV_8723AE {
            let access = self.0.ae_access.get().ok_or(Error::Gate)?;
            let mut operation = Some(operation);
            let mut result = None;
            access.invoke(&mut || {
                result = Some(operation.take().ok_or(Error::Gate)?(&self.0.io)?);
                Ok(())
            })?;
            return result.ok_or(Error::Gate);
        }
        self.1.current(&self.0, operation)
    }
    pub(super) fn terminal_8821(&self) -> Option<super::prepare::packet::TerminalPark>
    where
        I: 'static,
    {
        if self.0.did != super::regs::RTL_DEV_8821AE {
            return None;
        }
        let owner = self.0.clone();
        let state = self.1.clone();
        Some(super::prepare::packet::TerminalPark::new(Arc::new(
            move || {
                // The store precedes the SAME scalar gate. A scalar admitted
                // earlier completes before restrictive park; later scalars refuse.
                state.retired.store(true, Ordering::Release);
                let _scalar = state.scalar.lock();
                owner
                    .io
                    .restrict_8821_packets()
                    .map_err(super::prepare::Error::Access)
            },
        )))
    }
    pub(super) fn guard_8821_publication(
        &self,
        original: super::prepare::packet::Publication,
    ) -> super::prepare::packet::Publication
    where
        I: 'static,
    {
        if self.0.did != super::regs::RTL_DEV_8821AE {
            return original;
        }
        let owner = self.0.clone();
        let state = self.1.clone();
        super::prepare::packet::Publication::guarded(Arc::new(move |operation| {
            let mut result = None;
            state
                .current(&owner, |_| {
                    result = Some(original.invoke(operation));
                    Ok(())
                })
                .map_err(super::prepare::Error::Access)?;
            result.ok_or(super::prepare::Error::State)?
        }))
    }
}
#[async_trait::async_trait]
impl<I: Io> Io for PacketIo<I> {
    fn read8(&self, reg: u16) -> Result<u8, Error> {
        self.with_effect_io(|io| io.read8(reg))
    }
    fn read32(&self, reg: u16) -> Result<u32, Error> {
        self.with_effect_io(|io| io.read32(reg))
    }
    fn read16(&self, reg: u16) -> Result<u16, Error> {
        self.with_effect_io(|io| io.read16(reg))
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), Error> {
        self.with_effect_io(|io| io.write8(reg, value))
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), Error> {
        self.with_effect_io(|io| io.write32(reg, value))
    }
    fn write_bytes(&self, reg: u16, bytes: &[u8]) -> Result<(), Error> {
        self.with_effect_io(|io| io.write_bytes(reg, bytes))
    }
    fn write16(&self, reg: u16, value: u16) -> Result<(), Error> {
        self.with_effect_io(|io| io.write16(reg, value))
    }
    async fn delay_us(&self, micros: u64) {
        self.0.io.delay_us(micros).await;
    }
}
struct Attempt<'a, I: Io>(&'a Owner<I>);
impl<I: Io> Drop for Attempt<'_, I> {
    fn drop(&mut self) {
        let mut s = self.0.status.lock();
        if !matches!(s.stage, Stage::Ready | Stage::Failed) {
            *s = Status {
                stage: Stage::Failed,
                error: Some(Error::Cancelled),
            };
        }
    }
}
impl<I: Io> Owner<I> {
    pub fn new(io: I, did: u16) -> Self {
        Self {
            io,
            did,
            started: AtomicBool::new(false),
            native_claimed: AtomicBool::new(false),
            status: IrqSafeSpinLock::new(Status {
                stage: Stage::Detected,
                error: None,
            }),
            identity: IrqSafeSpinLock::new(None),
            ae_cold: Mutex::new(None),
            ae_access: OnceLock::new(),
            ae_retired: AtomicBool::new(false),
        }
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) async fn rtl8723ae_cold_phase(&self) -> Option<super::rtl8723ae::init::Phase> {
        self.ae_cold
            .lock()
            .await
            .as_ref()
            .map(|owner| owner.phase())
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) async fn ae_fixture_lock(
        &self,
    ) -> narf_lib::mutex::MutexGuard<'_, Option<Box<super::rtl8723ae::init::Owner>>> {
        self.ae_cold.lock().await
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn ae_fixture_fail(&self) {
        self.set(Stage::Failed, Some(Error::Cancelled));
    }
    pub fn status(&self) -> Status {
        *self.status.lock()
    }
    /// PCI device id selecting the firmware/ring profile.
    pub fn device_id(&self) -> u16 {
        self.did
    }
    /// The retained native adapter, for vector binding only. Register
    /// access still flows through the gated `PacketIo` continuation.
    pub(super) fn native(&self) -> &I {
        &self.io
    }
    pub(in crate::rtlwifi) fn retire_ae(&self) {
        if self.did == super::regs::RTL_DEV_8723AE {
            self.ae_retired.store(true, Ordering::Release);
        }
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::rtlwifi) fn ae_fixture_source(&self) -> Option<Identity> {
        *self.identity.lock()
    }
    pub(in crate::rtlwifi) fn install_ae_access(
        &self,
        access: Arc<dyn AeAccess>,
    ) -> Result<(), Error> {
        if self.did != super::regs::RTL_DEV_8723AE
            || self.status().stage != Stage::Ready
            || !self.native_claimed.load(Ordering::Acquire)
        {
            return Err(Error::Gate);
        }
        self.ae_access
            .set(access)
            .map_err(|_| Error::AlreadyStarted)
    }
    pub(crate) fn identity(&self) -> Option<Identity> {
        if self.status().stage != Stage::Ready {
            return None;
        }
        *self.identity.lock()
    }
    /// Claim at most one LLT/descriptor continuation after successful boot.
    /// Failed allocation, cancellation, or Drop never reopens this claim.
    pub(super) fn claim_packet_io(self: &Arc<Self>) -> Result<PacketIo<I>, Error> {
        // AE already retains source LLT/MAC/table state. A generic ring
        // continuation cannot discard/replay that original cold Box.
        if self.did == super::regs::RTL_DEV_8723AE {
            return Err(Error::Unsupported);
        }
        if self.status().stage != Stage::Ready {
            return Err(Error::Gate);
        }
        self.native_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::AlreadyStarted)?;
        Ok(PacketIo(self.clone(), Arc::new(PacketState::new())))
    }
    pub(in crate::rtlwifi) async fn claim_ae_cold(
        self: &Arc<Self>,
        target: &Arc<super::rtl8723ae::retained::Retained<I>>,
    ) -> Result<super::rtl8723ae::cold_storage::Bound, Error>
    where
        I: super::rtl8723ae::retained::Backend,
    {
        use super::rtl8723ae::{cold_storage::Storage, retained::Phase};
        if self.did != super::regs::RTL_DEV_8723AE
            || self.status().stage != Stage::Ready
            || !target.registered_for(self)
        {
            return Err(Error::Gate);
        }
        self.identity()
            .ok_or(Error::Gate)?
            .invoke(|| Ok(()))
            .map_err(|_| Error::Gate)?;
        self.native_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::AlreadyStarted)?;
        target.claim_intent();
        // Fixed order: registered destination regular Mutex, then cold Mutex.
        let mut state = target.state.lock().await;
        let mut cold = self.ae_cold.lock().await;
        if self.status().stage != Stage::Ready
            || !target.registered_for(self)
            || state.phase != Phase::Allocated
            || !target.cold.empty()
        {
            state.phase = Phase::ResetOnly;
            return Err(Error::Gate);
        }
        let identity = self.identity().ok_or(Error::Gate)?;
        let pci = self.io.identity()?;
        if pci.address() != self.io.address() {
            state.phase = Phase::ResetOnly;
            return Err(Error::Gate);
        }
        identity
            .invoke(|| {
                if self.status().stage != Stage::Ready
                    || !target.registered_for(self)
                    || self
                        .identity()
                        .is_none_or(|now| now.digest != identity.digest)
                    || !cold.as_deref().is_some_and(Storage::accepts)
                {
                    state.phase = Phase::ResetOnly;
                    return Err(super::prepare::Error::State);
                }
                let original = cold.take().unwrap();
                match target.cold.install(original, pci) {
                    Ok(()) => {
                        state.port = Some(PacketIo(self.clone(), Arc::new(PacketState::new())));
                        state.identity = Some(identity);
                        state.phase = Phase::ColdOwned;
                        Ok(())
                    }
                    Err(original) => {
                        *cold = Some(original);
                        state.phase = Phase::ResetOnly;
                        Err(super::prepare::Error::State)
                    }
                }
            })
            .map_err(|_| Error::Gate)?;
        // Original Box + PacketIo were stored before either mutex can drop.
        target.cold.bound().map_err(|_| Error::Gate)
    }
    fn set(&self, stage: Stage, error: Option<Error>) {
        *self.status.lock() = Status { stage, error };
    }
    fn begin(&self) -> Result<Attempt<'_, I>, Error> {
        if self.did == super::regs::RTL_DEV_8723AE && self.ae_retired.load(Ordering::Acquire) {
            return Err(Error::Gate);
        }
        self.started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::AlreadyStarted)?;
        Ok(Attempt(self))
    }
    fn finish(&self, result: Result<Info, Error>) -> Result<Info, Error> {
        match result {
            Ok(_) => self.set(Stage::Ready, None),
            Err(e) => self.set(Stage::Failed, Some(e)),
        };
        result
    }
    pub async fn initialize_registered(&self) -> Result<Info, Error> {
        if self.started.load(Ordering::Acquire) {
            return Err(Error::AlreadyStarted);
        }
        let loader = narf_firmware::trusted_loader_authority()
            .ok_or(Error::Firmware(FirmwareError::AuthorityRevoked))?;
        let authority = loader
            .derive()
            .map_err(|_| Error::Firmware(FirmwareError::AuthorityRevoked))?;
        if self.did == super::regs::RTL_DEV_8821AE {
            // rtl8821ae/sw.c fw_name, then core.c rtl_fw_do_work's
            // alt_fw_name retry only when the primary image is absent.
            let mut result = Err(Error::Firmware(FirmwareError::NotFound));
            for name in super::rtl8821ae::fw::Image::Normal.names() {
                result = self.initialize_registered_from(&authority, name).await;
                if result != Err(Error::Firmware(FirmwareError::NotFound)) {
                    break;
                }
            }
            return result;
        }
        if self.did == super::regs::RTL_DEV_8192EE {
            // rtl8192ee/sw.c fw_name; no alt_fw_name.
            return self
                .initialize_registered_from(&authority, super::rtl8192ee::fw::FW_NORMAL)
                .await;
        }
        if super::rtl8192ce::is_8192ce(self.did) {
            // rtl8192ce/sw.c rtl92c_init_sw_vars: the image follows the
            // measured chip version; unqualified versions load nothing.
            let name = self.rtl8192ce_version()?.firmware();
            return self.initialize_registered_from(&authority, name).await;
        }
        if self.did == super::regs::RTL_DEV_8723BE {
            // rtl8723be/sw.c fw_name, then rtl_fw_do_work's alt_fw_name
            // retry only when the primary image is absent.
            let mut result = Err(Error::Firmware(FirmwareError::NotFound));
            for name in super::rtl8723be::version::Version::firmware_names() {
                result = self.initialize_registered_from(&authority, name).await;
                if result != Err(Error::Firmware(FirmwareError::NotFound)) {
                    break;
                }
            }
            return result;
        }
        if self.did == super::regs::RTL_DEV_8723AE {
            // rtl8723ae/sw.c rtl8723e_init_sw_vars: the image follows the
            // measured chip version (UMC B-cut ⇒ rtl8723fw_B.bin); no
            // alt_fw_name. Unqualified versions load nothing.
            let name = self.rtl8723ae_version()?.firmware();
            return self.initialize_registered_from(&authority, name).await;
        }
        if self.did == super::regs::RTL_DEV_8192DE {
            // rtl8192de/sw.c fw_name; no alt_fw_name, no version
            // selection.
            return self
                .initialize_registered_from(&authority, super::rtl8192de::fw::FW_NAME)
                .await;
        }
        self.initialize_registered_from(&authority, super::fw::FW_8188EE)
            .await
    }
    /// `_rtl8723e_read_chip_version` over this owner's registers.
    pub(super) fn rtl8723ae_version(&self) -> Result<super::rtl8723ae::version::Version, Error> {
        use super::rtl8723ae::version::{
            Version, BT_FUNC, REG_GPIO_OUTSTS, REG_MULTI_FUNC_CTRL, REG_SYS_CFG, TRP_VAUX_EN,
        };
        let io = AeColdIo {
            owner: self,
            image: None,
        };
        let sys_cfg = io.read32(REG_SYS_CFG)?;
        if sys_cfg == u32::MAX {
            return Err(Error::Gone);
        }
        // Preserve the source's conditional dependent reads: test chips
        // and non-8723 parts never reach GPIO or multifunction controls.
        if sys_cfg & TRP_VAUX_EN != 0 || sys_cfg & BT_FUNC == 0 {
            return Err(Error::Unsupported);
        }
        let gpio = io.read32(REG_GPIO_OUTSTS)?;
        if gpio == u32::MAX {
            return Err(Error::Gone);
        }
        let multi = io.read32(REG_MULTI_FUNC_CTRL)?;
        if multi == u32::MAX {
            return Err(Error::Gone);
        }
        Version::from_registers(sys_cfg, || gpio, || multi).map_err(|_| Error::Unsupported)
    }
    /// `_rtl92ce_read_chip_version` over this owner's registers.
    pub(super) fn rtl8192ce_version(&self) -> Result<super::rtl8192ce::version::Version, Error> {
        use super::rtl8192ce::version::{Version, REG_HPON_FSM, REG_SYS_CFG};
        let sys_cfg = self.io.read32(REG_SYS_CFG)?;
        if sys_cfg == u32::MAX {
            return Err(Error::Gone);
        }
        let mut hpon = Ok(0);
        let version = Version::from_registers(sys_cfg, || {
            hpon = self.io.read32(REG_HPON_FSM);
            *hpon.as_ref().unwrap_or(&0)
        });
        hpon?;
        version.map_err(|_| Error::Unsupported)
    }
    pub(super) async fn initialize_registered_from(
        &self,
        authority: &narf_capabilities::Cap<
            narf_firmware::FirmwareRegistry,
            narf_capabilities::Read,
        >,
        name: &str,
    ) -> Result<Info, Error> {
        if self.started.load(Ordering::Acquire) {
            return Err(Error::AlreadyStarted);
        }
        // rtl8192ce: only the image rtl92c_init_sw_vars selects for the
        // measured chip version.
        let ce_bound =
            super::rtl8192ce::is_8192ce(self.did) && self.rtl8192ce_version()?.firmware() == name;
        // rtl8723ae: only the image rtl8723e_init_sw_vars selects.
        let ae_bound =
            self.did == super::regs::RTL_DEV_8723AE && self.rtl8723ae_version()?.firmware() == name;
        if !ce_bound
            && !ae_bound
            && !matches!(
                (self.did, name),
                (super::regs::RTL_DEV_8188EE, super::fw::FW_8188EE)
                    | (
                        super::regs::RTL_DEV_8821AE,
                        super::rtl8821ae::fw::FW_NORMAL | super::rtl8821ae::fw::FW_NORMAL_ALT
                    )
                    | (super::regs::RTL_DEV_8192EE, super::rtl8192ee::fw::FW_NORMAL)
                    | (
                        super::regs::RTL_DEV_8723BE,
                        super::rtl8723be::version::FW_NORMAL
                            | super::rtl8723be::version::FW_NORMAL_ALT
                    )
                    | (super::regs::RTL_DEV_8192DE, super::rtl8192de::fw::FW_NAME)
            )
        {
            return Err(Error::Unsupported);
        }
        self.load_registered(authority, name).await
    }
    /// Registry-mechanics fixtures (deferral, revocation, retry) stage a
    /// unique image name so their absence/presence is independent of every
    /// other fixture in the shared kernel registry. Everything after the
    /// production per-chip name gate is the same path.
    #[cfg(feature = "kernel-test")]
    pub(super) async fn initialize_registered_fixture(
        &self,
        authority: &narf_capabilities::Cap<
            narf_firmware::FirmwareRegistry,
            narf_capabilities::Read,
        >,
        name: &str,
    ) -> Result<Info, Error> {
        if self.started.load(Ordering::Acquire) {
            return Err(Error::AlreadyStarted);
        }
        self.load_registered(authority, name).await
    }
    async fn load_registered(
        &self,
        authority: &narf_capabilities::Cap<
            narf_firmware::FirmwareRegistry,
            narf_capabilities::Read,
        >,
        name: &str,
    ) -> Result<Info, Error> {
        let asset = crate::firmware_asset::load(authority, name, HEADER + MAX_PAYLOAD, false)
            .map_err(Error::Firmware)?;
        parse(self.did, &asset.bytes)?;
        let _attempt = self.begin()?;
        *self.identity.lock() = Some(Identity::from_bytes(&asset.bytes, Some(asset.cap)));
        let result = self.run(&asset.bytes).await;
        self.finish(result)
    }

    /// Caller already owns authenticated image bytes; probe uses registry.
    pub async fn initialize(&self, bytes: &[u8]) -> Result<Info, Error> {
        let _attempt = self.begin()?;
        let result = async {
            parse(self.did, bytes)?;
            *self.identity.lock() = Some(Identity::from_bytes(bytes, None));
            self.run(bytes).await
        }
        .await;
        self.finish(result)
    }
    async fn read8(&self, reg: u16) -> Result<u8, Error> {
        self.io.read8(reg)
    }
    async fn reset(&self) -> Result<(), Error> {
        let value = self.read8(3).await?;
        self.io.write8(3, value & !4)?;
        self.io.write8(3, value | 4)
    }
    async fn poll(&self, mask: u32, error: Error) -> Result<(), Error> {
        for _ in 0..3000 {
            let value = self.io.read32(MCU)?;
            if value == u32::MAX {
                return Err(Error::Gone);
            }
            if value & mask != 0 {
                return Ok(());
            }
            self.io.delay_us(5).await;
        }
        Err(error)
    }
    async fn run(&self, bytes: &[u8]) -> Result<Info, Error> {
        let (info, payload) = parse(self.did, bytes)?;
        self.set(Stage::Validated, None);
        if self.did == super::regs::RTL_DEV_8821AE {
            return self.run_8821ae(info, payload).await;
        }
        if self.did == super::regs::RTL_DEV_8192EE {
            return self.run_8192ee(info, payload).await;
        }
        if super::rtl8192ce::is_8192ce(self.did) {
            return self.run_8192ce(info, payload).await;
        }
        if self.did == super::regs::RTL_DEV_8723BE {
            return self.run_8723be(info, payload).await;
        }
        if self.did == super::regs::RTL_DEV_8723AE {
            return self.run_8723ae(info, payload).await;
        }
        if self.did == super::regs::RTL_DEV_8192DE {
            return self.run_8192de(info, payload).await;
        }
        narf_time::timeout(narf_time::Deadline::after_ms(1000), async {
            self.set(Stage::Preparing, None);
            // Linux _rtl88ee_init_mac sets the CPU clock before firmware.
            // Packet engines stay closed until a later retained ring owner:
            // clear HCI/TX/RX DMA and MAC TX/RX in CR, preserve protocol bits.
            // Each native access additionally invokes the live PCI authority
            // and verifies BUS_MASTER remains disabled.
            let control = self.read8(0x100).await?;
            self.io.write8(0x100, control & !0xcf)?;
            if self.read8(0x100).await? & 0xcf != 0 {
                return Err(Error::Gate);
            }
            let clock = self.read8(8).await?;
            self.io.write8(8, clock | 8)?;
            if self.read8(8).await? & 8 == 0 {
                return Err(Error::Gate);
            }
            if self.io.read32(MCU)? == u32::MAX {
                return Err(Error::Gone);
            }
            let control = self.read8(MCU).await?;
            if control & 0x80 != 0 {
                self.io.write8(MCU, 0)?;
                self.reset().await?;
            }
            let value = self.read8(3).await?;
            self.io.write8(3, value | 4)?;
            let value = self.read8(MCU).await?;
            self.io.write8(MCU, value | 1)?;
            let value = self.read8(MCU + 2).await?;
            self.io.write8(MCU + 2, value & !8)?;
            // Fresh checksum, shared RTL8188E W1C bit. Never accept the
            // preceding image's checksum report after a partial write.
            let value = self.read8(MCU).await?;
            self.io.write8(MCU, value | 4)?;
            self.set(Stage::Downloading, None);
            for (page, data) in payload.chunks(PAGE).enumerate() {
                let value = self.read8(MCU + 2).await?;
                self.io.write8(MCU + 2, value & 0xf8 | page as u8)?;
                for (offset, chunk) in data.chunks(256).enumerate() {
                    self.io.write_bytes(0x1000 + (offset * 256) as u16, chunk)?;
                    self.io.delay_us(0).await;
                }
                // Linux rtl_fill_dummy pads final image to a dword boundary.
                let pad = data.len().next_multiple_of(4) - data.len();
                if pad != 0 {
                    self.io
                        .write_bytes(0x1000 + data.len() as u16, &[0; 3][..pad])?;
                }
            }
            let value = self.read8(MCU).await?;
            self.io.write8(MCU, value & !1)?;
            self.io.write8(MCU + 1, 0)?;
            self.poll(4, Error::Checksum).await?;
            let value = self.io.read32(MCU)?;
            if value == u32::MAX {
                return Err(Error::Gone);
            }
            self.io.write32(MCU, (value | 2) & !0x40)?;
            self.reset().await?;
            self.poll(0x40, Error::Start).await?;
            Ok(info)
        })
        .await
        .unwrap_or(Err(Error::Deadline))
    }
    /// `rtl8821ae_hw_init` firmware step with packet engines still closed.
    /// Linux runs `_rtl8821ae_init_mac` first; here the probe has already run
    /// the exact enable flow and the retained ring owner later performs the
    /// LLT/ring-base part, so CR DMA/MAC TX/RX gates are cleared exactly as
    /// for RTL8188EE (preserving PROTOCOL/SCHEDULE). Then `REG_SYS_CFG &= 0x7f`
    /// and `rtl8821ae_download_fw`. Probe does not run
    /// `_rtl8821ae_poweroff_adapter`, so a still-running RAM image is handled
    /// as Linux's `mac_func_enable` case (stop + 8051 self-reset).
    async fn run_8821ae(&self, info: Info, payload: &[u8]) -> Result<Info, Error> {
        // FW_8821AE_POLLING_TIMEOUT_COUNT x 5 us twice plus 1000 page chunks
        // fits well inside the EE one-second bound.
        narf_time::timeout(narf_time::Deadline::after_ms(1000), async {
            self.set(Stage::Preparing, None);
            let control = self.read8(0x100).await?;
            self.io.write8(0x100, control & !0xcf)?;
            if self.read8(0x100).await? & 0xcf != 0 {
                return Err(Error::Gate);
            }
            if self.io.read32(MCU)? == u32::MAX {
                return Err(Error::Gone);
            }
            let sys_cfg = self.read8(0xf0).await?;
            self.io.write8(0xf0, sys_cfg & 0x7f)?;
            self.set(Stage::Downloading, None);
            super::rtl8821ae::fw::download(&self.io, payload, true).await?;
            Ok(info)
        })
        .await
        .unwrap_or(Err(Error::Deadline))
    }
    /// `rtl92ee_hw_init` firmware step with packet engines still closed.
    /// Linux runs `_rtl92ee_init_mac` first; here the probe has already run
    /// its enable prefix and `RTL8192E_NIC_ENABLE_FLOW`, and the retained ring
    /// owner later performs the ring-base/LLT remainder, so CR DMA/MAC TX/RX
    /// gates are cleared as for the other profiles. Then, in Linux order, the
    /// `0x577 = 0x03` and 40 MHz crystal AFE writes and `rtl92ee_download_fw`.
    /// The `REG_PCIE_CTRL_REG = 0x8000` write that precedes the download in
    /// Linux releases the TX DMA queue stops; it belongs to the ring owner
    /// (bus mastering stays parked here) and is not issued. The BT-coexist
    /// antenna writes (`0x64`/`0x65`) are not issued: BT-coexist boards are
    /// never admitted. A still-running RAM image is handled as Linux's
    /// `mac_func_enable` case, since probe does not power the adapter off.
    async fn run_8192ee(&self, info: Info, payload: &[u8]) -> Result<Info, Error> {
        // 2999 checksum reads plus 3001 x 50 us WINTINI polls fit well inside
        // the one-second bound.
        narf_time::timeout(narf_time::Deadline::after_ms(1000), async {
            self.set(Stage::Preparing, None);
            let control = self.read8(0x100).await?;
            self.io.write8(0x100, control & !0xcf)?;
            if self.read8(0x100).await? & 0xcf != 0 {
                return Err(Error::Gate);
            }
            if self.io.read32(MCU)? == u32::MAX {
                return Err(Error::Gone);
            }
            self.io.write8(0x577, 0x03)?;
            self.io.write8(0x78, 0x2a)?;
            self.io.write8(0x79, 0x00)?;
            self.io.write8(0x28, 0x83)?;
            self.set(Stage::Downloading, None);
            super::rtl8192ee::fw::download(&self.io, payload, true).await?;
            Ok(info)
        })
        .await
        .unwrap_or(Err(Error::Deadline))
    }
    /// `rtl92ce_hw_init` firmware step with packet engines still closed.
    /// The chip version is measured and qualified first (test chips, unknown
    /// cuts and the 1T2R bonding are refused). Linux order follows:
    /// `_rtl92ce_init_mac` power-on prefix (this family has no pwrseq table),
    /// then — instead of `REG_CR = 0x2ff`, the LLT and the ring bases, which
    /// belong to the retained ring owner — the CR DMA/MAC gates are cleared
    /// as for the other profiles. A still-running RAM image is stopped as in
    /// `_rtl92ce_poweroff_adapter` (probe does not power the adapter off),
    /// then `rtl92c_download_fw`.
    async fn run_8192ce(&self, info: Info, payload: &[u8]) -> Result<Info, Error> {
        // 1000 x 100 us APFM poll, 99 checksum reads and 101 x 5 ms WINTINI
        // polls fit inside the one-second bound.
        narf_time::timeout(narf_time::Deadline::after_ms(1000), async {
            self.set(Stage::Preparing, None);
            if self.io.read32(MCU)? == u32::MAX {
                return Err(Error::Gone);
            }
            self.rtl8192ce_version()?;
            super::rtl8192ce::power::power_on(&self.io).await?;
            let control = self.read8(0x100).await?;
            self.io.write8(0x100, control & !0xcf)?;
            if self.read8(0x100).await? & 0xcf != 0 {
                return Err(Error::Gate);
            }
            super::rtl8192ce::fw::stop_running(&self.io).await?;
            self.set(Stage::Downloading, None);
            super::rtl8192ce::fw::download(&self.io, payload).await?;
            Ok(info)
        })
        .await
        .unwrap_or(Err(Error::Deadline))
    }
    /// `_rtl8723be_read_chip_version` over this owner's registers.
    pub(super) fn rtl8723be_version(&self) -> Result<super::rtl8723be::version::Version, Error> {
        use super::rtl8723be::version::{Version, REG_SYS_CFG, REG_SYS_CFG1};
        let sys_cfg1 = self.io.read32(REG_SYS_CFG1)?;
        let sys_cfg = self.io.read32(REG_SYS_CFG)?;
        if sys_cfg1 == u32::MAX || sys_cfg == u32::MAX {
            return Err(Error::Gone);
        }
        Version::from_registers(sys_cfg1, sys_cfg).map_err(|_| Error::Unsupported)
    }
    /// `rtl8723be_hw_init` firmware step with packet engines still closed.
    /// The chip version is measured first (a part without `CHIP_8723B` is
    /// refused before any write). Probe has already run the
    /// `_rtl8723be_init_mac` power prefix and `RTL8723_NIC_ENABLE_FLOW`; the
    /// `_rtl8723be_init_mac` remainder (`REG_CR = 0x2ff`, LLT, ring bases)
    /// belongs to the retained ring owner, so the CR DMA/MAC gates are
    /// cleared as for the other profiles. Then, in Linux order,
    /// `REG_SYS_CFG &= 0x7f` and `rtl8723_download_fw`, which itself stops a
    /// still-running RAM image (probe does not power the adapter off).
    async fn run_8723be(&self, info: Info, payload: &[u8]) -> Result<Info, Error> {
        // 5999 undelayed checksum reads plus 6001 x 5 ms WINTINI polls
        // (FW_8723B_POLLING_TIMEOUT_COUNT) bound the Linux wait at ~30 s.
        narf_time::timeout(narf_time::Deadline::after_ms(31_000), async {
            self.set(Stage::Preparing, None);
            if self.io.read32(MCU)? == u32::MAX {
                return Err(Error::Gone);
            }
            self.rtl8723be_version()?;
            let control = self.read8(0x100).await?;
            self.io.write8(0x100, control & !0xcf)?;
            if self.read8(0x100).await? & 0xcf != 0 {
                return Err(Error::Gate);
            }
            let sys_cfg = self.read8(0xf0).await?;
            self.io.write8(0xf0, sys_cfg & 0x7f)?;
            self.set(Stage::Downloading, None);
            super::rtl8723be::fw::download(&self.io, payload).await?;
            Ok(info)
        })
        .await
        .unwrap_or(Err(Error::Deadline))
    }
    /// `rtl92d_download_fw` with packet engines still closed. No chip
    /// version is measured (the 8192DE loads one image name with no
    /// version selection) and no pre-download register writes run:
    /// Linux's download starts directly with the dual-MAC coordination
    /// check, and the MAC-init / power-on prefix (`_rtl92de_init_mac`,
    /// card enable) belongs to the follow-up power-on lane, as do the
    /// CR DMA/MAC gates, LLT and ring bases (retained ring owner).
    /// The 5000 x 500 us dual-MAC wait plus the checksum and ready
    /// polls bound the Linux wait near 2.5 s.
    async fn run_8192de(&self, info: Info, payload: &[u8]) -> Result<Info, Error> {
        narf_time::timeout(narf_time::Deadline::after_ms(6_000), async {
            self.set(Stage::Preparing, None);
            if self.io.read32(MCU)? == u32::MAX {
                return Err(Error::Gone);
            }
            self.set(Stage::Downloading, None);
            super::rtl8192de::fw::download(&self.io, payload).await?;
            Ok(info)
        })
        .await
        .unwrap_or(Err(Error::Deadline))
    }
    /// RTL8723AE cold MAC/firmware/BB/RF continuation, with packet engines
    /// closed. Probe already qualified the factory map and ran card-enable.
    /// The measured version and EFUSE/autoload mode are checked before new
    /// writes. Source order: ePHY -> parked LLT/MAC -> firmware download ->
    /// MAC/BB/RF tables, UMC fixups and defaults. CR gate enables and ring
    /// bases are excluded; factory identity/coexistence/IQK/calibrated power
    /// remain with the future radio owner. No station admission follows.
    async fn run_8723ae(&self, info: Info, payload: &[u8]) -> Result<Info, Error> {
        // Worst source firmware poll is about 5.1 s; the additional RF
        // table's four 50 ms delays and BB/LSSI settles fit the 6 s bound.
        let image = (*self.identity.lock()).ok_or(Error::Gate)?;
        let io = AeColdIo {
            owner: self,
            image: Some(image),
        };
        let work = async {
            use super::rtl8723ae::{adapter, init, power};
            let cold_error = |error| match error {
                super::prepare::Error::Access(error) => error,
                _ => Error::Gate,
            };
            self.set(Stage::Preparing, None);
            if io.read32(MCU)? == u32::MAX {
                return Err(Error::Gone);
            }
            let version = self.rtl8723ae_version()?;
            let mode = io.read8(adapter::REG_9346CR)?;
            if mode & (adapter::CR9346_AUTOLOAD_OK | adapter::CR9346_EEPROM)
                != adapter::CR9346_AUTOLOAD_OK
            {
                return Err(Error::Unsupported);
            }
            // A regular async Mutex keeps the same chip owner retained;
            // no IRQ-disabling guard crosses any await.
            let mut retained = self.ae_cold.lock().await;
            let cold = retained.get_or_insert_with(|| Box::new(init::Owner::new()));
            // Card-enable and ePHY setup do not write CR. Preserve the
            // source's pre-power `CR == 0xff` LLT-skip observation before
            // parking the gates below.
            let control = io.read8(0x100)?;
            let retries = power::post_flow_with_retries(&io).await?;
            io.write8(0x100, control & !0xcf)?;
            if io.read8(0x100)? & 0xcf != 0 {
                return Err(Error::Gate);
            }
            cold.prepare_mac(&io, retries, control == 0xff)
                .await
                .map_err(cold_error)?;
            self.set(Stage::Downloading, None);
            cold.download_and_configure(&io, version, payload)
                .await
                .map_err(cold_error)?;
            Ok(info)
        };
        let mut work = core::pin::pin!(work);
        narf_time::timeout(
            narf_time::Deadline::after_ms(6_000),
            core::future::poll_fn(|cx| match io.poll(work.as_mut(), cx) {
                Ok(poll) => poll,
                Err(error) => core::task::Poll::Ready(Err(error)),
            }),
        )
        .await
        .unwrap_or(Err(Error::Deadline))
    }
}
#[cfg(feature = "kernel-test")]
#[path = "firmware_transport_tests.rs"]
mod tests;

#[cfg(any(test, feature = "kernel-test"))]
#[path = "firmware_transport_terminal_tests.rs"]
mod terminal_tests;

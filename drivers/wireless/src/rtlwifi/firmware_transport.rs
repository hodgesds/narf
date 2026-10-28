// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8188EE paged MMIO firmware owner; Linux rtlwifi/rtl8188ee/fw.c and efuse.c.
//! PCI bus mastering remains parked. This does not install native packet rings.
use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::{AtomicBool, Ordering};
use narf_firmware::FirmwareError;
use narf_lib::sync::IrqSafeSpinLock;

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
pub fn parse(did: u16, bytes: &[u8]) -> Result<(Info, &[u8]), Error> {
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
    fn read8(&self, reg: u16) -> Result<u8, Error>;
    fn read32(&self, reg: u16) -> Result<u32, Error>;
    fn write8(&self, reg: u16, value: u8) -> Result<(), Error>;
    fn write32(&self, reg: u16, value: u32) -> Result<(), Error>;
    fn write_bytes(&self, reg: u16, bytes: &[u8]) -> Result<(), Error>;
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
}
/// Exact image of the successful retained CPU owner; not an upload receipt.
#[derive(Clone, Copy)]
pub(crate) struct Identity {
    pub(super) digest: [u8; 32],
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
            source,
        }
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
pub(super) struct PacketIo<I: Io>(Arc<Owner<I>>);
impl<I: Io> core::fmt::Debug for PacketIo<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8188eePacketIo")
            .field("firmware", &self.0)
            .finish_non_exhaustive()
    }
}
impl<I: Io> PacketIo<I> {
    pub(super) fn with_io<T>(
        &self,
        operation: impl FnOnce(&I) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if self.0.status().stage != Stage::Ready {
            return Err(Error::Gate);
        }
        operation(&self.0.io)
    }
}
#[async_trait::async_trait]
impl<I: Io> Io for PacketIo<I> {
    fn read8(&self, reg: u16) -> Result<u8, Error> {
        self.with_io(|io| io.read8(reg))
    }
    fn read32(&self, reg: u16) -> Result<u32, Error> {
        self.with_io(|io| io.read32(reg))
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), Error> {
        self.with_io(|io| io.write8(reg, value))
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), Error> {
        self.with_io(|io| io.write32(reg, value))
    }
    fn write_bytes(&self, reg: u16, bytes: &[u8]) -> Result<(), Error> {
        self.with_io(|io| io.write_bytes(reg, bytes))
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
        }
    }
    pub fn status(&self) -> Status {
        *self.status.lock()
    }
    /// The retained native adapter, for vector binding only. Register
    /// access still flows through the gated `PacketIo` continuation.
    pub(super) fn native(&self) -> &I {
        &self.io
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
        if self.status().stage != Stage::Ready {
            return Err(Error::Gate);
        }
        self.native_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::AlreadyStarted)?;
        Ok(PacketIo(self.clone()))
    }
    fn set(&self, stage: Stage, error: Option<Error>) {
        *self.status.lock() = Status { stage, error };
    }
    fn begin(&self) -> Result<Attempt<'_, I>, Error> {
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
        self.initialize_registered_from(&authority, super::fw::FW_8188EE)
            .await
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
        if self.did != super::regs::RTL_DEV_8188EE {
            return Err(Error::Unsupported);
        }
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
}
#[cfg(feature = "kernel-test")]
#[path = "firmware_transport_tests.rs"]
mod tests;

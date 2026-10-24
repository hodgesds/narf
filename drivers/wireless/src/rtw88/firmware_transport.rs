// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8822CE section firmware lifecycle, Linux rtw88/mac.c/fw.c.
//! Requires an exclusively retained, pristine PCIe reserved-page DMA backend.
//! It does not itself enable PCI bus mastering or supply a packet runtime.
use alloc::boxed::Box;
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::FirmwareError;
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
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    New,
    Ready,
    MacPrepared,
    PhyTablesPrepared,
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
    if did == 0xc822 {
        Ok("rtw88/rtw8822c_fw.bin")
    } else {
        Err(Error::Unsupported)
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
fn registered_image(did: u16) -> Result<alloc::vec::Vec<u8>, Error> {
    let name = filename(did)?;
    let loader = narf_firmware::trusted_loader_authority()
        .ok_or(Error::Firmware(FirmwareError::AuthorityRevoked))?;
    let authority = loader
        .derive()
        .map_err(|_| Error::Firmware(FirmwareError::AuthorityRevoked))?;
    let cap = narf_firmware::open(name, &authority).map_err(Error::Firmware)?;
    cap.invoke(Snapshot(did))
        .map_err(|_| Error::Firmware(FirmwareError::AuthorityRevoked))?
}
fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn parse(did: u16, bytes: &[u8]) -> Result<Image<'_>, Error> {
    if did != 0xc822 {
        return Err(Error::Unsupported);
    }
    if !(HEADER..=MAX_IMAGE).contains(&bytes.len()) || bytes[..2] != [0x22, 0x88] {
        return Err(Error::Image);
    }
    let has_emem = bytes[0x18] & 0x10 != 0 && word(bytes, 0x34) != 0;
    let mut sections = [None, None, None];
    let mut offset = HEADER;
    for (index, (kind, base, limit, address, size, enabled)) in [
        (Kind::Dmem, 0x200000u32, 0x300000u32, 0x20, 0x24, true),
        (Kind::Imem, 0x30000, 0x100000, 0x3c, 0x30, true),
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
            h2c: u16::from_le_bytes([bytes[0x1c], bytes[0x1d]]),
            sections: if has_emem { 3 } else { 2 },
        },
        sections,
    })
}
/// # Safety
/// Claim proves this backend owns every published host DMA mapping and the
/// exact powered PCI device exclusively. Reserved-page submissions retain
/// their buffers across cancellation/ambiguous errors and cannot overwrite
/// them until terminal completion. Dropping this backend must retain any
/// mapping that hardware can still access. Ordinary MAC TX/RX and IRQs stay
/// closed throughout; no unrelated command/reset/ring client may race it.
#[async_trait::async_trait]
pub unsafe trait Io: Send {
    fn claim_pristine(&mut self) -> Result<(), Error>;
    fn read8(&mut self, reg: u16) -> Result<u8, Error>;
    fn read16(&mut self, reg: u16) -> Result<u16, Error>;
    fn read32(&mut self, reg: u16) -> Result<u32, Error>;
    fn write8(&mut self, reg: u16, value: u8) -> Result<(), Error>;
    fn write16(&mut self, reg: u16, value: u16) -> Result<(), Error>;
    fn write32(&mut self, reg: u16, value: u32) -> Result<(), Error>;
    async fn reserved_page(&mut self, data: &[u8]) -> Result<(), Error>;
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
    async fn delay_us(&mut self, us: u64) {
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(us.saturating_mul(1000))).await;
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
pub struct Owner<I: Io> {
    io: I,
    did: u16,
    phase: Phase,
    info: Option<Info>,
    mac: Option<super::mac::Info>,
    hardware: Option<super::hardware::Features>,
    phy: Option<super::phy::Info>,
    image_digest: Option<[u8; 32]>,
    power: Option<super::power_policy::Calibration>,
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
            image_digest: None,
            power: None,
        }
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn mac_info(&self) -> Option<super::mac::Info> {
        matches!(self.phase, Phase::MacPrepared | Phase::PhyTablesPrepared)
            .then_some(self.mac)
            .flatten()
    }
    pub(super) fn hardware_info(&self) -> Option<super::hardware::Features> {
        if matches!(self.phase, Phase::MacPrepared | Phase::PhyTablesPrepared) {
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
        let hardware = super::hardware::Features::read(&mut self.io)?;
        let info = super::mac::prepare(&mut self.io).await?;
        self.io.finish_mac()?;
        self.mac = Some(info);
        self.hardware = Some(hardware);
        self.phase = Phase::MacPrepared;
        Ok(info)
    }
    pub fn phy_info(&self) -> Option<super::phy::Info> {
        if self.phase == Phase::PhyTablesPrepared {
            self.phy
        } else {
            None
        }
    }
    pub(super) fn image_digest(&self) -> Option<[u8; 32]> {
        match self.phase {
            Phase::Ready | Phase::MacPrepared | Phase::PhyTablesPrepared => self.image_digest,
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
        if self.phase != Phase::PhyTablesPrepared {
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
        self.power = Some(calibration);
        Ok(permission)
    }
    pub(super) fn current_power(
        &self,
        permission: super::power_policy::Permission,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<[u8; 2], Error> {
        if self.phase != Phase::PhyTablesPrepared {
            return Err(Error::State);
        }
        self.power
            .as_ref()
            .ok_or(Error::State)?
            .gains(permission, domain)
            .map_err(Error::Power)
    }
    pub async fn prepare_phy_tables(
        &mut self,
        factory: &super::efuse::Factory,
    ) -> Result<super::phy::Info, Error> {
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
        if self.phase != Phase::New {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let bytes = registered_image(self.did)?;
        self.download_inner(&bytes).await
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
    fn update8(&mut self, reg: u16, clear: u8, set: u8) -> Result<(), Error> {
        let value = self.io.read8(reg)?;
        self.io.write8(reg, value & !clear | set)
    }
    async fn poll(&mut self, reg: u16, mask: u32, target: u32) -> Result<(), Error> {
        for _ in 0..1000 {
            let value = self.io.read32(reg)?;
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
    fn cpu(&mut self, enable: bool) -> Result<(), Error> {
        if enable {
            self.update8(0x1d, 0, 1)?;
            self.update8(3, 0, 4)
        } else {
            self.update8(3, 4, 0)?;
            self.update8(0x1d, 1, 0)
        }
    }
    fn backup(&mut self) -> Result<Backup, Error> {
        let map = self.io.read8(0x10d)?;
        self.io.write8(0x10d, 0xc0)?;
        let cr = self.io.read8(0x100)?;
        self.io.write8(0x100, 5)?;
        self.io.write32(0x1330, 1 << 31)?;
        let pages = self.io.read16(0x230)?;
        let rqpn = self.io.read32(0x22c)? | 1 << 31;
        self.io.write16(0x230, 0x200)?;
        self.io.write32(0x22c, rqpn)?;
        let beacon = self.io.read8(0x550)?;
        self.io.write8(0x550, beacon & !8 | 16)?;
        Ok(Backup {
            map,
            cr,
            pages,
            rqpn,
            beacon,
        })
    }
    fn restore(&mut self, b: &Backup) -> Result<(), Error> {
        self.io.write8(0x10d, b.map)?;
        self.io.write8(0x100, b.cr)?;
        self.io.write32(0x1330, 1 << 31)?;
        self.io.write16(0x230, b.pages)?;
        self.io.write32(0x22c, b.rqpn)?;
        self.io.write8(0x550, b.beacon)
    }
    async fn section(&mut self, section: &Section<'_>) -> Result<(), Error> {
        let control = self.io.read32(0x1208)?;
        if control == u32::MAX {
            return Err(Error::Gone);
        }
        self.io.write32(0x1208, control | 1 << 25)?;
        for (part, bytes) in section.bytes.chunks(4096).enumerate() {
            // Native transport mirrors fw.c's beacon-page validity and exact
            // TD completion; only then may IDDMA consume the device TXBUF.
            self.io.reserved_page(bytes).await?;
            self.poll(0x1208, 1 << 31, 0).await?;
            let control =
                1 << 31 | 1 << 29 | if part != 0 { 1 << 24 } else { 0 } | bytes.len() as u32;
            self.io.write32(0x1200, 0x18780000 + 48)?;
            self.io
                .write32(0x1204, section.address + part as u32 * 4096)?;
            self.io.write32(0x1208, control)?;
            self.poll(0x1208, 1 << 31, 0).await?;
        }
        let control = self.io.read8(0x80)?;
        if self.io.read32(0x1208)? & 1 << 27 != 0 {
            return Err(Error::Checksum);
        }
        self.io.write8(
            0x80,
            control
                | if section.address < 0x200000 {
                    0x18
                } else {
                    0x60
                },
        )
    }
    async fn run(&mut self, image: &Image<'_>) -> Result<(), Error> {
        let lte = self.io.lte_backup().await?;
        self.cpu(false)?;
        let backup = self.backup()?;
        self.update8(0x1082, 1, 0)?;
        self.update8(9, 0x40, 0)?;
        self.update8(0x1082, 0, 1)?;
        self.update8(9, 0, 0x40)?;
        let control = self.io.read16(0x80)? & 0x3800 | 1;
        self.io.write16(0x80, control)?;
        for section in image.sections.iter().flatten() {
            self.section(section).await?;
        }
        self.restore(&backup)?;
        self.io.write32(0x210, 4)?;
        let control = self.io.read16(0x80)?;
        if control & 0x50 != 0x50 {
            return Err(Error::Checksum);
        }
        self.io.write16(0x80, (control | 1 << 14) & !1)?;
        self.cpu(true)?;
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
#[path = "mac/tests.rs"]
mod mac_tests;
#[cfg(any(test, feature = "kernel-test"))]
#[path = "phy/tests.rs"]
mod phy_tests;
#[cfg(any(test, feature = "kernel-test"))]
#[path = "power_policy_tests.rs"]
mod power_policy_tests;
#[cfg(any(test, feature = "kernel-test"))]
#[path = "firmware_transport_tests.rs"]
mod tests;

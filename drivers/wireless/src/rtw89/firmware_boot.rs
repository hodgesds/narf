// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained AX WCPU reset/download progression, Linux fw.c/mac.c.
//! Requires completed, exclusive PCIe/BDRAM/DLE/HFC+CH12 preparation. This
//! private prerequisite neither enables ordinary packet DMA nor admits a NIC.
use super::{
    command_queue::{self, Kind},
    download_plan::{self, DownloadPlan},
    mac::ChipId,
    power::{self, Io},
};
use core::future::Future;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Register(power::Error),
    Transfer(command_queue::Error),
    Plan(download_plan::Error),
    NotPrepared,
    ChipMismatch,
    Terminal,
    FirmwareStatus(u8),
}
impl From<power::Error> for Error {
    fn from(value: power::Error) -> Self {
        Self::Register(value)
    }
}
impl From<command_queue::Error> for Error {
    fn from(value: command_queue::Error) -> Self {
        Self::Transfer(value)
    }
}
impl From<download_plan::Error> for Error {
    fn from(value: download_plan::Error) -> Self {
        Self::Plan(value)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Prepared,
    Starting,
    Header,
    Sections,
    ReadyWait,
    Running,
    Terminal,
}

pub trait Transport {
    type Registers: Io;
    fn chip(&self) -> ChipId;
    fn prepared(&self) -> bool;
    fn registers(&mut self) -> &mut Self::Registers;
    fn send(
        &mut self,
        kind: Kind,
        bytes: &[u8],
    ) -> impl Future<Output = Result<(), command_queue::Error>>;
}
#[derive(Debug)]
pub struct Firmware<T> {
    transport: T,
    plan: DownloadPlan,
    phase: Phase,
}
impl<T: Transport> Firmware<T> {
    pub fn new(transport: T, plan: DownloadPlan) -> Result<Self, Error> {
        if !transport.prepared() {
            return Err(Error::NotPrepared);
        }
        if transport.chip() != plan.chip() {
            return Err(Error::ChipMismatch);
        }
        Ok(Self {
            transport,
            plan,
            phase: Phase::Prepared,
        })
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub(super) fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
    /// One-shot: errors and cancellation preserve the owner but prohibit retry.
    /// Recovery requires a separate, complete fenced PCIe/chip reset owner.
    pub async fn start(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Prepared {
            return Err(Error::Terminal);
        }
        // Allocate the immutable header before any register side effect.
        self.phase = Phase::Starting;
        let result = async {
            let header = self.plan.header_command(0)?;
            self.start_inner(&header).await
        }
        .await;
        if result.is_err() {
            self.phase = Phase::Terminal;
        }
        result
    }
    async fn start_inner(&mut self, header: &[u8]) -> Result<(), Error> {
        if !self.transport.prepared() {
            return Err(Error::NotPrepared);
        }
        let chip = self.plan.chip();
        disable_cpu(self.transport.registers(), chip)?;
        enable_cpu(self.transport.registers(), chip)?;
        if self.plan.secure_enabled() {
            modify32(
                self.transport.registers(),
                0x1e0,
                0x0f00_0000,
                u32::from(self.plan.idmem_share_mode()) << 24,
            )?;
            modify32(self.transport.registers(), 0x1e0, 1 << 23, 1 << 23)?;
        }
        path_ready(self.transport.registers(), 1 << 1).await?;
        self.phase = Phase::Header;
        self.transport.send(Kind::Header, header).await?;
        path_ready(self.transport.registers(), 1 << 2).await?;
        self.transport.registers().write32(0x160, 0)?;
        self.transport.registers().write32(0x164, 0)?;
        self.phase = Phase::Sections;
        for section in 0..self.plan.section_count() {
            let len = self.plan.section_len(section).ok_or(Error::NotPrepared)?;
            for offset in (0..len).step_by(super::fwdl::FWDL_SECTION_PER_PKT_LEN) {
                let chunk = self.plan.chunk(section, offset)?;
                self.transport.send(Kind::Section, &chunk).await?;
            }
        }
        self.phase = Phase::ReadyWait;
        self.transport.registers().delay_us(5000).await;
        initialized(self.transport.registers()).await?;
        self.phase = Phase::Running;
        Ok(())
    }
}
fn modify32(io: &mut impl Io, address: u32, mask: u32, value: u32) -> Result<(), power::Error> {
    let old = io.read32(address)?;
    if old == u32::MAX {
        return Err(power::Error::Gone);
    }
    io.write32(address, (old & !mask) | (value & mask))
}
fn disable_cpu(io: &mut impl Io, chip: ChipId) -> Result<(), power::Error> {
    modify32(io, 0x88, 1 << 1, 0)?;
    modify32(io, 0x1e0, 7, 0)?;
    modify32(io, 0x8, 1 << 14, 0)?;
    if matches!(chip, ChipId::Rtl8852B | ChipId::Rtl8851B) {
        modify32(io, 0x88, 1 << 2, 0)?;
        modify32(io, 0x88, 1 << 2, 1 << 2)?;
    } else {
        // Full AX indirect CPU-local aperture; 64-KiB BARs cannot cover it.
        io.write32(0xc04, 0x18003040)?;
        io.write32(0x40000, 0)?;
        io.write32(0xc04, 0x18003044)?;
        let old = io.read32(0x40000)?;
        if old == u32::MAX {
            return Err(power::Error::Gone);
        }
        io.write32(0xc04, 0x18003044)?;
        io.write32(0x40000, (old | (1 << 8)) & !1)?;
    }
    modify32(io, 0x88, 1, 0)?;
    modify32(io, 0x88, 1, 1)
}
fn enable_cpu(io: &mut impl Io, chip: ChipId) -> Result<(), power::Error> {
    let platform = io.read32(0x88)?;
    if platform == u32::MAX {
        return Err(power::Error::Gone);
    }
    if platform & (1 << 1) != 0 {
        return Err(power::Error::AlreadyOn);
    }
    for address in [0x1f4, 0x1f8, 0x160, 0x164, 0x168, 0x16c] {
        io.write32(address, 0)?;
    }
    modify32(io, 0x8, 1 << 14, 1 << 14)?;
    modify32(io, 0x1e0, 0xe7, 1)?;
    if matches!(chip, ChipId::Rtl8852B | ChipId::Rtl8851B) {
        modify32(io, 0xc00, 3 << 16, 2 << 16)?;
    }
    let reason = io.read16(0x1e6)?;
    if reason == u16::MAX {
        return Err(power::Error::Gone);
    }
    io.write16(0x1e6, reason & !7)?;
    modify32(io, 0x88, 1 << 1, 1 << 1)
}
async fn path_ready(io: &mut impl Io, bit: u8) -> Result<(), Error> {
    let began = io.now_us();
    loop {
        let value = io.read8(0x1e0)?;
        if value == u8::MAX {
            return Err(power::Error::Gone.into());
        }
        if value & bit != 0 {
            return Ok(());
        }
        if io.now_us().saturating_sub(began) >= 400_000 {
            return Err(power::Error::Timeout.into());
        }
        io.delay_us(1).await;
    }
}
async fn initialized(io: &mut impl Io) -> Result<(), Error> {
    let began = io.now_us();
    loop {
        let value = io.read8(0x1e0)?;
        if value == u8::MAX {
            return Err(power::Error::Gone.into());
        }
        let status = (value >> 5) & 7;
        match status {
            7 => return Ok(()),
            2..=5 => return Err(Error::FirmwareStatus(status)),
            _ => (),
        }
        if io.now_us().saturating_sub(began) >= 400_000 {
            return Err(power::Error::Timeout.into());
        }
        io.delay_us(1).await;
    }
}

impl Transport for super::command_native::Native {
    type Registers = super::power_native::NativeIo;
    fn chip(&self) -> ChipId {
        self.chip()
    }
    fn prepared(&self) -> bool {
        self.firmware_prepared()
    }
    fn registers(&mut self) -> &mut Self::Registers {
        self.io()
    }
    async fn send(&mut self, kind: Kind, bytes: &[u8]) -> Result<(), command_queue::Error> {
        super::command_native::Native::send(self, kind, bytes).await
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "firmware_boot_tests.rs"]
mod tests;

//! Navi48 SMU14 cold boot: version handshake, firmware-owned board table and
//! bounded GFX DPM/protection policy. Linux smu_v14_0{,_2_ppt}.c,
//! smu14_driver_if_v14_0.h and smu_v14_0_2_pptable.h define this wire format.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as ip,
    amdgpu_vram::{Pool, Reservation},
};
use alloc::vec::Vec;
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

const MESSAGE: u32 = 0x82;
const ARGUMENT: u32 = 0x92;
const RESPONSE: u32 = 0x9a;
pub const DRIVER_INTERFACE: u32 = 0x2e;
const TRANSFER_BYTES: usize = 0x4000;
const COMBO_BYTES: usize = 5812;
const DRIVER_BYTES: usize = 1344;
const POWER_BYTES: usize = 4468;
const REQUIRED: u64 = (1 << 1) | (1 << 23) | (1 << 28) | (1 << 36);
const DISPLAY: u64 = (1 << 3) | (1 << 4) | (1 << 5) | (1 << 7);
// Keep boot display/memory/link clocks fixed until DCN owns their constraints.
// SMU throttlers, fan/thermal shutdown and electrical protections stay enabled.
const ALLOWED: u64 = REQUIRED
    | (1 << 0)
    | (1 << 25)
    | (1 << 26)
    | (1 << 27)
    | (1 << 29)
    | (1 << 37)
    | (1 << 38)
    | (1 << 41)
    | (1 << 46)
    | (1 << 48)
    | (1 << 49)
    | (1 << 50)
    | (1 << 51)
    | (1 << 55)
    | (1 << 56)
    | (1 << 57)
    | (1 << 58);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Allocation,
    Revoked,
    Busy,
    DeviceGone,
    Timeout,
    Rejected(u32),
    InterfaceMismatch(u32),
    PowerPolicy(u32),
    Features(u64),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Querying,
    Ready,
    ReadingBoard,
    BoardReady,
    UploadingBoard,
    BoardApplied,
    ConfiguringPower,
    PowerReady,
    EnablingDisplayPower,
    DisplayPowerReady,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Versions {
    pub firmware: u32,
    pub interface: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowerStatus {
    pub allowed: u64,
    pub enabled: u64,
    pub gfx_min_mhz: u16,
    pub gfx_max_mhz: u16,
}
fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn board_features(b: &[u8]) -> Result<u64, Error> {
    // sizeof/offsetof checked against the Linux C headers, not Rust layout.
    // All offsets are absolute within the combo, including CustomSkuTable.
    if b.len() != COMBO_BYTES
        || u16_at(b, 0) as usize != COMBO_BYTES
        || b[2..4] != [23, 0]
        || b[5] > 2
        || b[DRIVER_BYTES] != 0
    {
        return Err(Error::Unsupported);
    }
    for (field, value) in [
        (6, 1344),
        (8, 4468),
        (10, 1372),
        (12, 3552),
        (14, 5284),
        (16, 528),
        (18, 4924),
        (20, 360),
    ] {
        if u16_at(b, field) != value {
            return Err(Error::Invalid);
        }
    }
    let features =
        u32_at(b, DRIVER_BYTES + 4) as u64 | ((u32_at(b, DRIVER_BYTES + 8) as u64) << 32);
    if features & REQUIRED != REQUIRED {
        return Err(Error::Features(features));
    }
    Ok(features)
}
trait Io {
    fn read(&mut self, reg: u32) -> u32;
    fn write(&mut self, reg: u32, value: u32);
    fn check_policy(&mut self) -> Result<(), Error>;
    fn write_buffer(&mut self, offset: usize, bytes: &[u8]);
    fn read_buffer(&mut self, offset: usize, bytes: &mut [u8]);
    fn flush(&mut self) -> Result<(), Error>;
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
#[derive(Debug)]
struct Mmio {
    regs: MmioRegion,
    base: u64,
    nbio: u64,
    vram: MmioRegion,
    vram_size: u64,
    buffer: MmioRegion,
}
impl Io for Mmio {
    fn read(&mut self, reg: u32) -> u32 {
        // SAFETY: constructor bounds MP1 bank one through RESPONSE.
        unsafe { self.regs.read32(self.base + reg as u64 * 4) }
    }
    fn write(&mut self, reg: u32, value: u32) {
        // SAFETY: same bounded bank, exclusive mailbox owner with live authority.
        unsafe { self.regs.write32(self.base + reg as u64 * 4, value) };
    }
    fn check_policy(&mut self) -> Result<(), Error> {
        let base = self.vram_size.checked_sub(1 << 20).ok_or(Error::Invalid)?;
        // SAFETY: exclusive index latch and permanent mappings; in Cap::invoke.
        let mut reader =
            unsafe { crate::amdgpu_vram_access::MmioReader::new(&self.vram, &self.regs) };
        let scpm = crate::amdgpu_gddr6::runtime_entry::<4>(
            |offset, out| {
                crate::amdgpu_vram_access::read(
                    &mut reader,
                    self.vram_size,
                    base + offset as u64,
                    out,
                )
                .map_err(|_| crate::amdgpu_gddr6::Error::Invalid)
            },
            6,
        )
        .map_err(|_| Error::Invalid)?
        .map_or(0, u32::from_le_bytes);
        if scpm != 0 {
            return Err(Error::PowerPolicy(scpm));
        }
        Ok(())
    }
    fn write_buffer(&mut self, offset: usize, bytes: &[u8]) {
        for (i, word) in bytes.chunks_exact(4).enumerate() {
            // SAFETY: internal chunk ranges fit the retained 16 KiB reservation.
            unsafe {
                self.buffer.write32(
                    (offset + i * 4) as u64,
                    u32::from_le_bytes(word.try_into().unwrap()),
                )
            };
        }
    }
    fn read_buffer(&mut self, offset: usize, bytes: &mut [u8]) {
        for (i, word) in bytes.chunks_exact_mut(4).enumerate() {
            // SAFETY: completed transfer and bounded retained reservation.
            word.copy_from_slice(
                &unsafe { self.buffer.read32((offset + i * 4) as u64) }.to_le_bytes(),
            );
        }
    }
    fn flush(&mut self) -> Result<(), Error> {
        // SAFETY: exact NBIO bank and remap hole bounded at construction.
        unsafe {
            if self.regs.read32(self.nbio + 0x12d * 4) != 0x7f000 {
                return Err(Error::Invalid);
            }
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            self.regs.write32(0x7f000, 0);
            self.regs.read32(self.nbio + 0xc3 * 4);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    memory: Reservation,
    state: State,
    versions: Option<Versions>,
    board: Vec<u8>,
    features: u64,
    power: Option<PowerStatus>,
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)
    }
    async fn command(&mut self, message: u32, parameter: u32) -> Result<u32, Error> {
        self.access(|io| {
            if io.read(RESPONSE) == u32::MAX {
                return Err(Error::DeviceGone);
            }
            // First cold-boot query may start with response=0. All subsequent
            // commands follow an acknowledged reply; cancellation prevents reuse.
            io.write(RESPONSE, 0);
            io.write(ARGUMENT, parameter);
            io.write(MESSAGE, message);
            Ok(())
        })??;
        let deadline = narf_time::Deadline::after_ms(1000);
        loop {
            match self.access(|io| io.read(RESPONSE))? {
                u32::MAX => return Err(Error::DeviceGone),
                1 => return self.access(|io| io.read(ARGUMENT)),
                0 => {}
                value => return Err(Error::Rejected(value)),
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
        }
    }
    async fn verify(&mut self) -> Result<Versions, Error> {
        if self.state != State::Prepared {
            return Err(Error::Busy);
        }
        self.state = State::Querying;
        let result = async {
            let interface = self.command(3, 0).await?;
            if interface != DRIVER_INTERFACE {
                return Err(Error::InterfaceMismatch(interface));
            }
            let firmware = self.command(2, 0).await?;
            if firmware == 0 || firmware == u32::MAX {
                return Err(Error::Invalid);
            }
            Ok(Versions {
                firmware,
                interface,
            })
        }
        .await;
        self.state = if result.is_ok() {
            State::Ready
        } else {
            State::Failed
        };
        if let Ok(v) = result {
            self.versions = Some(v);
        }
        result
    }
    async fn transfer(&mut self, message: u32, table: u32) -> Result<(), Error> {
        let address = self.memory.address();
        self.memory.publish();
        self.command(0xe, (address >> 32) as u32).await?;
        self.command(0xf, address as u32).await?;
        self.command(message, table).await?;
        // SAFETY: transfer acknowledgement retires the only DMA using this
        // reservation. We still own it; next transfer publishes it again.
        unsafe { self.memory.stopped() };
        Ok(())
    }
    async fn read_board(&mut self) -> Result<(), Error> {
        if self.state != State::Ready {
            return Err(Error::Busy);
        }
        self.state = State::ReadingBoard;
        let result = async {
            self.access(|io| io.check_policy())??;
            for offset in (0..TRANSFER_BYTES).step_by(4096) {
                self.access(|io| io.write_buffer(offset, &[0; 4096]))?;
                narf_scheduler::yield_now().await;
            }
            self.access(|io| io.flush())??;
            self.transfer(0x12, 1).await?; // TABLE_COMBO_PPTABLE, SMU -> VRAM.
            let io = &mut self.io;
            for (i, bytes) in self.board.chunks_mut(4096).enumerate() {
                self.authority
                    .invoke(Op(|| io.read_buffer(i * 4096, bytes)))
                    .map_err(|_| Error::Revoked)?;
                narf_scheduler::yield_now().await;
            }
            self.features = board_features(&self.board)?;
            Ok(())
        }
        .await;
        self.state = if result.is_ok() {
            State::BoardReady
        } else {
            State::Failed
        };
        result
    }
    async fn upload_board(&mut self) -> Result<(), Error> {
        if self.state != State::BoardReady {
            return Err(Error::Busy);
        }
        self.state = State::UploadingBoard;
        let result = async {
            self.access(|io| io.check_policy())??;
            let io = &mut self.io;
            for (i, bytes) in self.board[DRIVER_BYTES..DRIVER_BYTES + POWER_BYTES]
                .chunks(4096)
                .enumerate()
            {
                self.authority
                    .invoke(Op(|| io.write_buffer(i * 4096, bytes)))
                    .map_err(|_| Error::Revoked)?;
                narf_scheduler::yield_now().await;
            }
            self.access(|io| io.flush())??;
            self.transfer(0x13, 0).await // TABLE_PPTABLE, VRAM -> SMU.
        }
        .await;
        self.state = if result.is_ok() {
            State::BoardApplied
        } else {
            State::Failed
        };
        result
    }
    async fn configure_power(&mut self) -> Result<PowerStatus, Error> {
        if self.state != State::BoardApplied {
            return Err(Error::Busy);
        }
        self.state = State::ConfiguringPower;
        let result = async {
            let allowed = self.features & ALLOWED;
            self.command(0x36, 0).await?; // DC BTC on the firmware's board table.
            self.command(5, (allowed >> 32) as u32).await?;
            self.command(4, allowed as u32).await?;
            self.command(6, 0).await?;
            let low = self.command(0xc, 0).await? as u64;
            let enabled = low | ((self.command(0xd, 0).await? as u64) << 32);
            if enabled & REQUIRED != REQUIRED || enabled & !allowed != 0 {
                return Err(Error::Features(enabled));
            }
            let min = self.command(0x1d, 0).await?;
            let max = self.command(0x1e, 0).await?;
            if min == 0 || min > max || max > u16::MAX as u32 {
                return Err(Error::Invalid);
            }
            Ok(PowerStatus {
                allowed,
                enabled,
                gfx_min_mhz: min as u16,
                gfx_max_mhz: max as u16,
            })
        }
        .await;
        self.state = if result.is_ok() {
            State::PowerReady
        } else {
            State::Failed
        };
        if let Ok(p) = result {
            self.power = Some(p);
        }
        result
    }
    async fn enable_display_power(&mut self) -> Result<PowerStatus, Error> {
        if self.state == State::DisplayPowerReady {
            self.access(|_| ())?;
            return self.power.ok_or(Error::Invalid);
        }
        if self.state != State::PowerReady {
            return Err(Error::Busy);
        }
        let previous = self.power.ok_or(Error::Invalid)?;
        if self.features & DISPLAY != DISPLAY {
            return Err(Error::Features(self.features));
        }
        self.state = State::EnablingDisplayPower;
        let result = async {
            self.access(|io| io.check_policy())??;
            let allowed = previous.allowed | DISPLAY;
            self.command(5, (allowed >> 32) as u32).await?;
            self.command(4, allowed as u32).await?;
            self.command(6, 0).await?;
            let low = u64::from(self.command(0xc, 0).await?);
            let enabled = low | (u64::from(self.command(0xd, 0).await?) << 32);
            if enabled & (REQUIRED | DISPLAY) != REQUIRED | DISPLAY || enabled & !allowed != 0 {
                return Err(Error::Features(enabled));
            }
            Ok(PowerStatus {
                allowed,
                enabled,
                ..previous
            })
        }
        .await;
        self.state = if result.is_ok() {
            State::DisplayPowerReady
        } else {
            State::Failed
        };
        if let Ok(power) = result {
            self.power = Some(power);
        }
        result
    }
}
#[derive(Debug)]
pub struct Smu {
    engine: Engine<Mmio>,
}
impl Smu {
    /// # Safety
    /// Every display pipe/stream is retired and all kernel engines are idle.
    /// The exclusive DCN owner must install clock floors before enabling a
    /// stream. Keep deep sleep, voltage scaling, link DPM and GFXOFF disabled.
    /// Failure/cancellation retains this owner and forbids replay.
    pub(crate) async unsafe fn enable_display_power(&mut self) -> Result<PowerStatus, Error> {
        self.engine.enable_display_power().await
    }
    /// # Safety
    /// Caller owns this physical Navi48's MP1/index/HDP/reset/PM controls and
    /// trained, exclusively free VRAM pool. PSP has loaded SMU14 with no command
    /// outstanding. Keep PSP/TMR and mappings alive, exclude all legacy SMU
    /// helpers, and retain this owner after any failure or cancelled operation.
    pub unsafe fn after_upload(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
    ) -> Result<Self, Error> {
        let layout = crate::amdgpu_psp_ring::navi48_layout(gpu).map_err(|_| Error::Unsupported)?;
        let base = crate::amdgpu_psp_ring::bank(
            gpu,
            ip::HW_ID_MP1,
            &[(14, 0, 2), (14, 0, 3)],
            1,
            RESPONSE,
        )
        .map_err(|_| Error::Unsupported)?;
        layout.validate_pool(gpu, &authority, pool).map_err(|e| {
            if e == crate::amdgpu_psp_ring::Error::Revoked {
                Error::Revoked
            } else {
                Error::Invalid
            }
        })?;
        let mut board = Vec::new();
        board
            .try_reserve_exact(COMBO_BYTES)
            .map_err(|_| Error::Allocation)?;
        board.resize(COMBO_BYTES, 0);
        let memory = pool
            .reserve(TRANSFER_BYTES as u64)
            .map_err(|_| Error::Allocation)?;
        let buffer = memory.mapping();
        Ok(Self {
            engine: Engine {
                io: Mmio {
                    regs: gpu.regs,
                    base,
                    nbio: layout.nbio,
                    vram: gpu.fb_bar,
                    vram_size: gpu.vram.size,
                    buffer,
                },
                authority,
                memory,
                state: State::Prepared,
                versions: None,
                board,
                features: 0,
                power: None,
            },
        })
    }
    pub fn state(&self) -> State {
        self.engine.state
    }
    pub fn versions(&self) -> Option<Versions> {
        self.engine.versions
    }
    pub fn power_status(&self) -> Option<PowerStatus> {
        self.engine.power
    }
    pub async fn verify(&mut self) -> Result<Versions, Error> {
        self.engine.verify().await
    }
    pub async fn read_board(&mut self) -> Result<(), Error> {
        self.engine.read_board().await
    }
    pub async fn upload_board(&mut self) -> Result<(), Error> {
        self.engine.upload_board().await
    }
    pub async fn configure_power(&mut self) -> Result<PowerStatus, Error> {
        self.engine.configure_power().await
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_smu_navi48_tests.rs"]
mod tests;

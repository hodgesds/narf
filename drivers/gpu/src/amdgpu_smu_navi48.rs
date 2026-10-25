//! Navi48 SMU14 cold boot: version handshake, firmware-owned board table and
//! bounded GFX DPM/protection policy. Linux smu_v14_0{,_2_ppt}.c,
//! smu14_driver_if_v14_0.h and smu_v14_0_2_pptable.h define this wire format.
pub use crate::amdgpu_smu_navi48_telemetry::{Limits, Metrics, Telemetry};
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as ip,
    amdgpu_smu_navi48_telemetry::{METRICS_BYTES, METRICS_TABLE},
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
// FEATURE_BACO_BIT (19): runtime PM's BACO/BAMACO needs PMFW's BACO feature
// running (smu_v14_0_get_bamaco_support); Linux allows every feature.
const ALLOWED: u64 = REQUIRED
    | (1 << 0)
    | FEATURE_BACO
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
// Autonomous protection PMFW must keep running once boot enabled it:
// THROTTLERS (PPT/TDC/thermal), GTHR, ACDC, VR0HOT, FW_CTF, FAN_CONTROL and
// FAN_ABNORMAL. Linux never disables these at runtime; neither does narf.
const PROTECTION: u64 =
    (1 << 23) | (1 << 25) | (1 << 26) | (1 << 27) | (1 << 28) | (1 << 29) | (1 << 57);
// smu_v14_0_deep_sleep_control's walk as smu_v14_0_2_ppt.c maps it, in its
// order: DS_GFXCLK, DS_UCLK, DS_FCLK, DS_SOCCLK, DS_LCLK (then DS_VCN, left
// out: the static media policy requires it off; DS_MP0CLK and DS_MP1CLK have
// no SMU 14.0.2 bit).
const DEEP_SLEEP_WALK: [(u64, &str); 5] = [
    (1 << 10, "GFXCLK"),
    (1 << 15, "UCLK"),
    (1 << 12, "FCLK"),
    (1 << 11, "SOCCLK"),
    (1 << 13, "LCLK"),
];
const PPCLK_GFXCLK: u32 = 0;
const PPCLK_UCLK: u32 = 2;
const FEATURE_DPM_UCLK: u64 = 1 << 3;
const MSG_ENTER_BACO: u32 = 0x15;
const MSG_EXIT_BACO: u32 = 0x16;
const MSG_ARM_D3: u32 = 0x17;
// smu14_driver_if_v14_0.h FEATURE_BACO_BIT.
const FEATURE_BACO: u64 = 1 << 19;
// offsetof(struct smu_14_0_2_powerplay_table, platform_caps) and
// SMU_14_0_2_PP_PLATFORM_CAP_BACO / _MACO (smu_v14_0_2_pptable.h).
const PLATFORM_CAPS: usize = 32;
const PLATFORM_CAP_BACO: u32 = 0x8;
const PLATFORM_CAP_MACO: u32 = 0x10;
/// amdgpu_smu.h `BACO_SUPPORT` / `MACO_SUPPORT`, as
/// `amdgpu_device_supports_baco` returns them.
pub const BACO_SUPPORT: u8 = 1;
pub const MACO_SUPPORT: u8 = 2;
/// amdgpu_smu.h `enum smu_baco_seq`, the EnterBaco / ArmD3 argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BacoSeq {
    Baco = 0,
    Msr = 1,
    Bamaco = 2,
    Ulps = 3,
}
/// `enum smu_baco_state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BacoState {
    Exit,
    Enter,
}
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
    /// A runtime telemetry/DPM command is in flight; cancellation leaves it.
    Runtime,
    /// PMFW accepted EnterBaco or ArmD3(BACO/BAMACO): only the matching
    /// exit may follow.
    Baco,
    /// A BACO entry or exit message is in flight; cancellation leaves it.
    BacoTransition,
    /// BACO was exited: this owner retired; the next bring-up makes a new one.
    BacoExited,
    Failed,
}
/// GFXCLK soft limits, Linux `smu_v14_0_set_performance_level` restricted to
/// the graphics clock: display never depends on it, so no admission reruns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GfxLevel {
    /// PMFW chooses within its whole DPM range (0xffff/0 automatic bounds).
    Auto,
    /// Pinned to the minimum or maximum DPM frequency.
    Low,
    High,
}
/// The deep-sleep feature PMFW refused, where the walk stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeepSleepRefused {
    /// Linux's name for it ("GFXCLK", "UCLK", ...).
    pub feature: &'static str,
    pub error: Error,
}
/// What `deep_sleep_control` left running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeepSleep {
    pub power: PowerStatus,
    /// The first refusal, which ended the walk (Linux logs and returns it;
    /// its caller ignores it).
    pub refused: Option<DeepSleepRefused>,
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
    /// The UCLK DPM range, read once display power enables UCLK DPM; until
    /// then memory runs at its boot clock.
    pub uclk_mhz: Option<(u16, u16)>,
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
    limits: Option<Limits>,
    /// PROTECTION bits running when boot power configuration completed.
    protection: u64,
    gfx_level: GfxLevel,
    /// `smu_baco->state`.
    baco: BacoState,
    /// The features running after boot configuration (Linux's SUPPORTED
    /// feature list, smu_smc_hw_setup).
    boot_enabled: u64,
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
            if interface == u32::MAX {
                return Err(Error::DeviceGone);
            }
            let firmware = self.command(2, 0).await?;
            if firmware == 0 || firmware == u32::MAX {
                return Err(Error::Invalid);
            }
            // smu_cmn_check_fw_version (smu_v14_0_2 .check_fw_version) only
            // logs an interface mismatch; PMFW updates move it independently.
            if interface != DRIVER_INTERFACE {
                use core::fmt::Write;
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: navi48 smu driver if version = {DRIVER_INTERFACE:#010x}, smu fw if version = {interface:#010x}, smu fw version = {firmware:#010x}"
                );
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
            // Telemetry limits are optional diagnostics; boot does not need them.
            self.limits = Limits::from_board(&self.board, self.features);
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
                uclk_mhz: None,
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
            self.protection = p.enabled & PROTECTION;
            self.boot_enabled = p.enabled;
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
            // smu_v14_0_get_dpm_ultimate_freq: GetMin/MaxDpmFreq of PPCLK_UCLK
            // now that its DPM runs.
            let uclk = if enabled & FEATURE_DPM_UCLK != 0 {
                let min = self.command(0x1d, PPCLK_UCLK << 16).await?;
                let max = self.command(0x1e, PPCLK_UCLK << 16).await?;
                if min == 0 || min > max || max > u32::from(u16::MAX) {
                    return Err(Error::Invalid);
                }
                Some((min as u16, max as u16))
            } else {
                None
            };
            Ok(PowerStatus {
                allowed,
                enabled,
                uclk_mhz: uclk,
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
    /// Runtime commands start from a powered state and leave `Runtime` set
    /// while in flight, so cancellation forbids reuse.
    fn begin_runtime(&mut self) -> Result<State, Error> {
        let resume = self.state;
        if !matches!(resume, State::PowerReady | State::DisplayPowerReady) {
            return Err(Error::Busy);
        }
        self.state = State::Runtime;
        Ok(resume)
    }
    /// A clean PMFW rejection leaves the mailbox idle and the owner reusable,
    /// as in Linux; timeout, revocation and device loss are terminal.
    fn end_runtime<T>(&mut self, resume: State, result: &Result<T, Error>) {
        self.state = match result {
            Ok(_) | Err(Error::Rejected(_)) => resume,
            Err(_) => State::Failed,
        };
    }
    fn protected(&self, enabled: u64) -> bool {
        self.power.is_some() && enabled & self.protection == self.protection
    }
    /// The board table's `platform_caps` (read with the combo table).
    fn platform_caps(&self) -> u32 {
        if self.board.len() < PLATFORM_CAPS + 4 || self.features == 0 {
            return 0;
        }
        u32_at(&self.board, PLATFORM_CAPS)
    }
    /// smu_v14_0_get_bamaco_support (smu_v14_0_2_check_powerplay_table
    /// sets `platform_support` / `maco_support` from the platform caps).
    /// "Supported" features are those running after boot configuration
    /// (smu_feature_list SUPPORTED); "enabled" is the last observed mask.
    fn bamaco_support(&self) -> u8 {
        let caps = self.platform_caps();
        if caps & PLATFORM_CAP_BACO == 0 {
            return 0;
        }
        let support = if caps & PLATFORM_CAP_MACO != 0 {
            MACO_SUPPORT
        } else {
            0
        };
        if self.baco == BacoState::Enter {
            return support | BACO_SUPPORT;
        }
        let Some(power) = self.power else {
            return 0;
        };
        if self.boot_enabled & FEATURE_BACO != 0 && power.enabled & FEATURE_BACO == 0 {
            return 0;
        }
        support | BACO_SUPPORT
    }
    /// One BACO message from a powered owner (entry) or a BACO owner
    /// (exit). A clean rejection restores the previous state; anything else
    /// is terminal, and cancellation leaves `BacoTransition`.
    async fn baco_message(
        &mut self,
        message: u32,
        parameter: u32,
        enter: bool,
    ) -> Result<(), Error> {
        let resume = self.state;
        let allowed = if enter {
            matches!(resume, State::PowerReady | State::DisplayPowerReady)
        } else {
            resume == State::Baco
        };
        if !allowed {
            return Err(Error::Busy);
        }
        self.state = State::BacoTransition;
        let result = self.command(message, parameter).await.map(|_| ());
        self.state = match (&result, enter) {
            (Ok(()), true) => State::Baco,
            (Ok(()), false) => State::BacoExited,
            (Err(Error::Rejected(_)), _) => resume,
            (Err(_), _) => State::Failed,
        };
        result
    }
    /// smu_v14_0_baco_set_state: EnterBaco(BAMACO or BACO sequence) or
    /// ExitBaco, nothing when already in that state.
    async fn baco_set_state(&mut self, state: BacoState, bamaco: bool) -> Result<(), Error> {
        if self.baco == state {
            self.access(|_| ())?;
            return Ok(());
        }
        match state {
            BacoState::Enter => {
                let seq = if bamaco {
                    BacoSeq::Bamaco
                } else {
                    BacoSeq::Baco
                };
                self.baco_message(MSG_ENTER_BACO, seq as u32, true).await?
            }
            BacoState::Exit => self.baco_message(MSG_EXIT_BACO, 0, false).await?,
        }
        self.baco = state;
        Ok(())
    }
    /// smu_v14_0_2_baco_enter (see `Smu::baco_enter`).
    async fn baco_enter(&mut self, bamaco: bool, armd3: bool) -> Result<(), Error> {
        if armd3 {
            // smu_baco->maco_support, not the runtime mode, picks the sequence.
            let seq = if self.platform_caps() & PLATFORM_CAP_MACO != 0 {
                BacoSeq::Bamaco
            } else {
                BacoSeq::Baco
            };
            return self.baco_arm_d3(seq).await;
        }
        self.baco_set_state(BacoState::Enter, bamaco).await?;
        // smu_v14_0_baco_enter: msleep(10).
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(10).as_instant()).await;
        Ok(())
    }
    /// smu_v14_0_2_baco_exit (see `Smu::baco_exit`).
    async fn baco_exit(&mut self, armd3: bool) -> Result<bool, Error> {
        if armd3 {
            // "Wait for PMFW handling for the Dstate change".
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(10).as_instant()).await;
            self.baco_arm_d3(BacoSeq::Ulps).await?;
            return Ok(false);
        }
        self.baco_set_state(BacoState::Exit, false).await?;
        Ok(true)
    }
    /// smu_v14_0_baco_set_armd3_sequence: ArmD3(seq); BACO/BAMACO arm the
    /// entry PMFW performs on the next D3 transition, anything else exits.
    async fn baco_arm_d3(&mut self, seq: BacoSeq) -> Result<(), Error> {
        let enter = matches!(seq, BacoSeq::Baco | BacoSeq::Bamaco);
        self.baco_message(MSG_ARM_D3, seq as u32, enter).await?;
        self.baco = if enter {
            BacoState::Enter
        } else {
            BacoState::Exit
        };
        Ok(())
    }
    async fn running(&mut self) -> Result<u64, Error> {
        let low = u64::from(self.command(0xc, 0).await?);
        Ok(low | (u64::from(self.command(0xd, 0).await?) << 32))
    }
    /// Linux `smu_cmn_get_metrics_table` (TABLE_SMU_METRICS, SMU -> VRAM),
    /// the running feature mask and `smu_v14_0_get_ppt_limit` (AC source).
    async fn read_telemetry(&mut self) -> Result<Telemetry, Error> {
        let resume = self.begin_runtime()?;
        let result = async {
            // Zeroed staging: an acknowledged but unwritten table reads as
            // zeros, never as the stale board table that shared this buffer.
            self.access(|io| io.write_buffer(0, &[0; METRICS_BYTES]))?;
            self.access(|io| io.flush())??;
            self.transfer(0x12, METRICS_TABLE).await?;
            let mut bytes = [0; METRICS_BYTES];
            self.access(|io| io.read_buffer(0, &mut bytes))?;
            let enabled = self.running().await?;
            let ppt_limit_w = self.command(0x33, 0).await?;
            Ok(Telemetry {
                metrics: Metrics::decode(&bytes),
                enabled,
                ppt_limit_w,
            })
        }
        .await;
        self.end_runtime(resume, &result);
        result
    }
    /// Linux smu_v14_0_set_ppt_limit: PPT0 SetPptLimit in watts, which needs
    /// the PPT feature (FEATURE_THROTTLERS_BIT on SMU14.0.2) running.
    async fn set_ppt_limit(&mut self, watts: u32) -> Result<(), Error> {
        let power = self.power.ok_or(Error::Invalid)?;
        if power.enabled & (1 << 23) == 0 {
            return Err(Error::Unsupported);
        }
        if watts == 0 || watts > 0xffff {
            return Err(Error::Invalid);
        }
        let resume = self.begin_runtime()?;
        let result = self.command(0x32, watts).await.map(|_| ());
        self.end_runtime(resume, &result);
        result
    }
    /// Linux smu_v14_0_set_vcn_enable, dGPU instance 0. Static media keeps
    /// MM_DPM/DS_VCN disabled and every autonomous protection running.
    async fn set_vcn_power(&mut self, enabled: bool) -> Result<PowerStatus, Error> {
        self.set_media_power(enabled, false).await
    }
    async fn set_jpeg_power(&mut self, enabled: bool) -> Result<PowerStatus, Error> {
        self.set_media_power(enabled, true).await
    }
    async fn set_media_power(&mut self, enabled: bool, jpeg: bool) -> Result<PowerStatus, Error> {
        let power = self.power.ok_or(Error::Invalid)?;
        let resume = self.begin_runtime()?;
        let result = async {
            let running = self.running().await?;
            if !self.protected(running) || running & ((1 << 20) | (1 << 44)) != 0 {
                return Err(Error::Features(running));
            }
            let command = match (jpeg, enabled) {
                (false, true) => 0x2a,
                (false, false) => 0x2b,
                (true, true) => 0x2c,
                (true, false) => 0x2d,
            };
            self.command(command, 0).await?;
            self.access(|_| ())?;
            Ok(PowerStatus {
                enabled: running,
                ..power
            })
        }
        .await;
        self.end_runtime(resume, &result);
        if let Ok(power) = result {
            self.power = Some(power);
        }
        result
    }
    /// smu_v14_0_enable_thermal_alert, after a retained IH/THM owner
    /// armed its source registers. Cancellation keeps Runtime quarantined.
    async fn allow_ih_interrupt(&mut self) -> Result<(), Error> {
        let resume = self.begin_runtime()?;
        let result = self.command(0x4d, 0).await.map(|_| ());
        self.end_runtime(resume, &result);
        result
    }
    /// SetSoftMaxByFreq then SetSoftMinByFreq on GFXCLK, with Linux's
    /// `SMU_V14_SOFT_FREQ_ROUND` on manual maxima.
    async fn set_gfx_level(&mut self, level: GfxLevel) -> Result<(), Error> {
        let power = self.power.ok_or(Error::Invalid)?;
        let (min, max) = (u32::from(power.gfx_min_mhz), u32::from(power.gfx_max_mhz));
        let (soft_max, soft_min) = match level {
            GfxLevel::Auto => (0xffff, 0),
            GfxLevel::Low => (min + 1, min),
            GfxLevel::High => ((max + 1).min(0xffff), max),
        };
        let resume = self.begin_runtime()?;
        let result = async {
            self.command(0x1a, PPCLK_GFXCLK << 16 | soft_max).await?;
            self.command(0x19, PPCLK_GFXCLK << 16 | soft_min).await?;
            Ok(())
        }
        .await;
        if result.is_ok() {
            self.gfx_level = level;
        }
        self.end_runtime(resume, &result);
        result
    }
    /// Linux `smu_v14_0_deep_sleep_control(true)`: for every DS feature of
    /// the walk the board supports (its FeaturesToRun), in Linux's order,
    /// EnableSmuFeaturesLow/High of that bit, stopping at the first PMFW
    /// refusal, which is reported in `DeepSleep::refused` and leaves the
    /// owner reusable. PMFW was allowed only the restricted boot mask, so the
    /// walk's bits are added to the allowed mask first. Afterwards every
    /// protection and display DPM feature must still run. Transport failures
    /// (timeout, revocation, device loss, cancellation) are terminal, as for
    /// every runtime command.
    async fn deep_sleep_control(&mut self) -> Result<DeepSleep, Error> {
        let previous = self.power.ok_or(Error::Invalid)?;
        // UCLK/FCLK/SOCCLK deep sleep only once display DPM runs.
        if self.state != State::DisplayPowerReady {
            return Err(Error::Busy);
        }
        let walk: alloc::vec::Vec<(u64, &'static str)> = DEEP_SLEEP_WALK
            .iter()
            .copied()
            .filter(|(bit, _)| bit & self.features != 0)
            .collect();
        let bits = walk.iter().fold(0, |m, (bit, _)| m | bit);
        if bits == 0 {
            self.access(|_| ())?;
            return Ok(DeepSleep {
                power: previous,
                refused: None,
            });
        }
        let required = REQUIRED | self.protection | (previous.enabled & DISPLAY);
        let resume = self.begin_runtime()?;
        let result = async {
            self.access(|io| io.check_policy())??;
            let mut allowed = previous.allowed;
            let mut refused = None;
            if bits & !allowed != 0 {
                let wanted = allowed | bits;
                let set = async {
                    self.command(5, (wanted >> 32) as u32).await?;
                    self.command(4, wanted as u32).await
                }
                .await;
                match set {
                    Ok(_) => allowed = wanted,
                    Err(error @ Error::Rejected(_)) => {
                        refused = Some(DeepSleepRefused {
                            feature: "allowed mask",
                            error,
                        })
                    }
                    Err(e) => return Err(e),
                }
            }
            if refused.is_none() {
                for (bit, feature) in walk {
                    let sent = async {
                        self.command(8, bit as u32).await?;
                        self.command(9, (bit >> 32) as u32).await
                    }
                    .await;
                    match sent {
                        Ok(_) => {}
                        Err(error @ Error::Rejected(_)) => {
                            refused = Some(DeepSleepRefused { feature, error });
                            break;
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
            let enabled = self.running().await?;
            // Nothing outside the allowed mask and the walk may run.
            if enabled & required != required || enabled & !(allowed | bits) != 0 {
                return Err(Error::Features(enabled));
            }
            Ok(DeepSleep {
                power: PowerStatus {
                    allowed,
                    enabled,
                    ..previous
                },
                refused,
            })
        }
        .await;
        self.end_runtime(resume, &result);
        if let Ok(d) = result {
            self.power = Some(d.power);
        }
        result
    }
}
#[derive(Debug)]
pub struct Smu {
    engine: Engine<Mmio>,
    /// The VBIOS boot UCLK (firmware_info), in MHz.
    boot_uclk_mhz: Option<u32>,
}

/// `AMDGPU_INFO_DEV_INFO`'s clocks under DPM (amdgpu_dpm_get_sclk/mclk,
/// in kHz): the GFXCLK DPM range, and the UCLK DPM range or, while UCLK
/// DPM is off, the boot UCLK for both ends (0 when the VBIOS gives none).
pub(crate) fn dev_info_clocks(power: &PowerStatus, boot_uclk_mhz: Option<u32>) -> [u32; 4] {
    let (memory_min, memory_max) = power
        .uclk_mhz
        .map(|(min, max)| (u32::from(min), u32::from(max)))
        .or(boot_uclk_mhz.map(|m| (m, m)))
        .unwrap_or((0, 0));
    [
        u32::from(power.gfx_min_mhz) * 1000,
        u32::from(power.gfx_max_mhz) * 1000,
        memory_min.saturating_mul(1000),
        memory_max.saturating_mul(1000),
    ]
}
impl Smu {
    /// # Safety
    /// Every display pipe/stream is retired and all kernel engines are idle.
    /// The exclusive DCN owner must install clock floors before enabling a
    /// stream. Keep deep sleep, voltage scaling, link DPM and GFXOFF disabled.
    /// Failure/cancellation retains this owner and forbids replay.
    pub(crate) async unsafe fn enable_display_power(&mut self) -> Result<PowerStatus, Error> {
        let power = self.engine.enable_display_power().await?;
        self.publish(&power);
        Ok(power)
    }
    /// Tell `AMDGPU_INFO` the clocks `power` runs at.
    fn publish(&self, power: &PowerStatus) {
        crate::amdgpu_info::publish_navi48_clocks(dev_info_clocks(power, self.boot_uclk_mhz));
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
            crate::amdgpu_rdna4::MP_VERSIONS,
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
                limits: None,
                protection: 0,
                gfx_level: GfxLevel::Auto,
                baco: BacoState::Exit,
                boot_enabled: 0,
            },
            // smu_v14_0_get_vbios_bootup_values: 10 kHz, used in MHz.
            boot_uclk_mhz: gpu
                .vbios
                .as_ref()
                .and_then(|v| crate::amdgpu_info::boot_mclk_10khz(v.bytes()))
                .map(|clock| clock / 100),
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
        let power = self.engine.configure_power().await?;
        self.publish(&power);
        Ok(power)
    }
    /// Board thermal/fan/power limits, when the firmware table provides them.
    pub fn limits(&self) -> Option<Limits> {
        self.engine.limits
    }
    /// Whether every autonomous protection running after boot configuration
    /// (throttlers, firmware CTF, fan control, ...) is still enabled.
    pub fn protected(&self, enabled: u64) -> bool {
        self.engine.protected(enabled)
    }
    pub fn gfx_level(&self) -> GfxLevel {
        self.engine.gfx_level
    }
    /// One PMFW metrics/feature/PPT refresh. Requires configured power.
    pub async fn read_telemetry(&mut self) -> Result<Telemetry, Error> {
        self.engine.read_telemetry().await
    }
    /// Permit SMU-to-host interrupts only after the retained thermal/IH
    /// owner is ready to acknowledge them.
    pub(crate) async fn allow_ih_interrupt(&mut self) -> Result<(), Error> {
        self.engine.allow_ih_interrupt().await
    }
    /// Apply GFXCLK soft limits. Display clocks, UCLK/FCLK pinning and every
    /// protection are untouched; a clean rejection leaves the owner usable.
    pub async fn set_gfx_level(&mut self, level: GfxLevel) -> Result<(), Error> {
        self.engine.set_gfx_level(level).await
    }
    /// Set the AC PPT0 socket power limit (watts). The caller validates it
    /// against `Limits::{ppt_min_w, ppt_max_w}`; every protection keeps
    /// running and a clean PMFW rejection leaves the owner usable.
    pub async fn set_ppt_limit(&mut self, watts: u32) -> Result<(), Error> {
        self.engine.set_ppt_limit(watts).await
    }
    /// SMU14 dGPU PowerUpVcn/PowerDownVcn for instance 0, with a fresh
    /// protection/static-clock policy check. No display or GFX clocks move.
    /// # Safety
    /// Own VCN and its power lifecycle exclusively. Before power-down, its
    /// retained owner has proved VCPU/LMI retirement and excluded submissions.
    pub async unsafe fn set_vcn_power(&mut self, enabled: bool) -> Result<PowerStatus, Error> {
        self.engine.set_vcn_power(enabled).await
    }
    /// SMU14 PowerUpJpeg/PowerDownJpeg with a fresh static-media policy check.
    /// # Safety
    /// Own JPEG's power lifecycle exclusively. Before power-down, its retained
    /// owner has proved JRBC/JMI retirement and excluded every submission.
    pub async unsafe fn set_jpeg_power(&mut self, enabled: bool) -> Result<PowerStatus, Error> {
        self.engine.set_jpeg_power(enabled).await
    }
    /// `amdgpu_device_supports_baco` (smu_v14_0_get_bamaco_support):
    /// `BACO_SUPPORT` and/or `MACO_SUPPORT`, 0 without board BACO circuitry.
    pub fn bamaco_support(&self) -> u8 {
        self.engine.bamaco_support()
    }
    pub fn baco_state(&self) -> BacoState {
        self.engine.baco
    }
    /// smu_v14_0_2_baco_enter. For runtime PM with the audio function
    /// enabled (`armd3`), arm PMFW with ArmD3 (BAMACO when the board has
    /// MACO circuitry, else BACO); PMFW enters on the next D3 of both
    /// functions. Otherwise EnterBaco with the runtime mode's sequence
    /// (`bamaco`), then the 10 ms of smu_v14_0_baco_enter.
    ///
    /// # Safety
    /// Every engine, display, IH and CPU accessor of this GPU is quiesced,
    /// client VRAM is evicted and PCI state was saved; until the matching
    /// [`Self::baco_exit`] only the PCI layer touches the function.
    pub async unsafe fn baco_enter(&mut self, bamaco: bool, armd3: bool) -> Result<(), Error> {
        self.engine.baco_enter(bamaco, armd3).await
    }
    /// smu_v14_0_2_baco_exit: after the PCI layer restored D0, wait 10 ms
    /// for PMFW's D-state handling and ArmD3(ULPS) (`armd3`), else
    /// ExitBaco. Returns whether the caller must clear BIOS_SCRATCH_6/7
    /// for the coming ASIC re-init (the ExitBaco path).
    ///
    /// # Safety
    /// As [`Self::baco_enter`]; the PCI function is back in D0.
    pub async unsafe fn baco_exit(&mut self, armd3: bool) -> Result<bool, Error> {
        self.engine.baco_exit(armd3).await
    }
    /// `smu_v14_0_deep_sleep_control(true)` as the default (non-compute)
    /// power profile runs it; see `Engine::deep_sleep_control`. A refusal is
    /// reported, not an error.
    ///
    /// # Safety
    /// The kernel engines' owners tolerate GFXCLK deep sleep, and the
    /// exclusive display owner has installed PMFW's watermark ranges and
    /// plans with DML's self-refresh exit latencies.
    pub(crate) async unsafe fn deep_sleep_control(&mut self) -> Result<DeepSleep, Error> {
        self.engine.deep_sleep_control().await
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_smu_navi48_tests.rs"]
mod tests;

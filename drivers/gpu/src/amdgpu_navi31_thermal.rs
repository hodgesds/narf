//! Owned SMU 13.0.0 THM/MP1 interrupt registers and the THM fan sequences.
//! Linux smu_v13_0_set_irq_state and smu_v13_0_irq_process, using
//! thm_13_0_2 and mp_13_0_0 headers, and smu_v13_0_set_fan_speed_pwm/rpm.
//!
//! The register indices match Navi48's THM file, but the MP1 file differs:
//! `MP1_SMN_IH_SW_INT` is 0x2c2 and `MP1_SMN_IH_SW_INT_CTRL` 0x2c3 here
//! (Navi48's 0x141/0x142 are SMU14-only). The version pins differ per bank
//! too — THM (13,0,2) against MP1 (13,0,0) — so `bank` is never called with
//! one version list for both. The discovery pins are the identity gate
//! until lane 1's skeleton (#2459) lands; that skeleton is the authoritative
//! Navi31 gate when it does.
//!
//! Sources: THM source 0 is the digital-thermometer low-to-high crossing
//! (software CTF, confirmed after the 50 ms delay in the power module),
//! source 1 the high-to-low crossing; ROM_SMUIO source 83 is the GPIO19
//! hardware CTF, which orders an immediate power-off; MP1 source 0xFE is
//! the SMU-to-driver interrupt, whose first data word is the context
//! (AC, DC, THERMAL_THROTTLING, FAN_ABNORMAL, FAN_RECOVERY).
use super::Limits;
use crate::{amdgpu::AmdGpu, amdgpu_discovery as ip, amdgpu_ih7 as ih, amdgpu_psp_ring::bank};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

const THERM_ENA: u32 = 0xa;
const THERM_CTRL: u32 = 0xb;
const MP_INT: u32 = 0x2c2;
const MP_CTRL: u32 = 0x2c3;
const INTH_MASK: u32 = 1 << 24;
const INTL_MASK: u32 = 1 << 25;
const TRIGGER_MASK: u32 = 1 << 26;
const IH_ENABLE: u32 = 1 << 28;
const CREDIT: u32 = 7 << 29;
const CLEAR: u32 = 0x38;
const MP_MASK: u32 = 1;
const MP_ACK: u32 = 1 << 8;
const MP_VALID: u32 = 1 << 8;
const SMU_TO_DRIVER: u8 = 0xfe;
/// MP1 contexts, smu13_driver_if_v13_0_0.h (`IH_INTERRUPT_CONTEXT_ID_*`).
/// AC is 0x3, DC 0x4, THERMAL_THROTTLING 0x7; only FAN_ABNORMAL and
/// FAN_RECOVERY change the high threshold, the rest only count.
const FAN_ABNORMAL: u32 = 8;
const FAN_RECOVERY: u32 = 9;
/// IH client ids, soc15_ih_clientid.h.
const CLIENT_THM: u8 = 0x0f;
const CLIENT_ROM_SMUIO: u8 = 0x16;
const CLIENT_MP1: u8 = 0x1f;
/// THM sources, smu_v13_0.c (`THM_11_0__SRCID__THM_DIG_THERM_*`).
const SRC_THERM_L2H: u8 = 0;
const SRC_THERM_H2L: u8 = 1;
/// ROM_SMUIO source, smu_v13_0.c (`SMUIO_11_0__SRCID__SMUIO_GPIO19`).
const SRC_SMUIO_GPIO19: u8 = 83;
/// Fan registers, thm_13_0_2_offset.h, and their field shifts.
const FDO_CTRL0: u32 = 0x8b;
const FDO_CTRL1: u32 = 0x8c;
const FDO_CTRL2: u32 = 0x8d;
const TACH_CTRL: u32 = 0x8e;
const FDO_STATIC_DUTY_MASK: u32 = 0xff;
const FMAX_DUTY100_MASK: u32 = 0xff;
const TMIN_MASK: u32 = 0xff;
const FDO_PWM_MODE_SHIFT: u32 = 11;
const FDO_PWM_MODE_MASK: u32 = 0x7 << FDO_PWM_MODE_SHIFT;
const TARGET_PERIOD_SHIFT: u32 = 3;
const TARGET_PERIOD_MASK: u32 = 0xffff_fff8;
/// `FDO_PWM_MODE_*`, smu_cmn.h.
const FDO_PWM_MODE_STATIC: u8 = 1;
const FDO_PWM_MODE_STATIC_RPM: u8 = 5;
/// Crystal clock for the tachometer, smu_v13_0_set_fan_speed_rpm.
const CRYSTAL_CLOCK_FREQ: u64 = 2500;

/// `speed * duty100 / 255`, as smu_v13_0_set_fan_speed_pwm. `speed` is a
/// u8, so Linux's clamp to 255 is the type itself.
fn fan_duty(speed: u8, duty100: u8) -> u8 {
    (u32::from(speed) * u32::from(duty100) / 255) as u8
}
/// `60 * crystal * 10000 / (8 * rpm)`, as smu_v13_0_set_fan_speed_rpm.
/// `None` for the speeds Linux refuses (zero, or so large `8 * rpm`
/// overflows a u32).
fn tach_period(rpm: u32) -> Option<u32> {
    if rpm == 0 || rpm > u32::MAX / 8 {
        return None;
    }
    Some((60 * CRYSTAL_CLOCK_FREQ * 10_000 / (8 * u64::from(rpm))) as u32)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Revoked,
    DeviceGone,
    Readback,
    Busy,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Armed,
    Stopped,
    Failed(Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub state: State,
    pub high_c: u8,
    pub high: u64,
    pub low: u64,
    pub smu: u64,
    pub hw_ctf: u64,
    pub fan_abnormal: bool,
}
/// What one handled interrupt vector asks the platform to do. The monitor
/// never powers anything off itself: power-off never runs from an IH or SMU
/// call frame, so the platform defers both outcomes to its own tasks (the
/// software CTF through the 50 ms confirmation in the power module, the
/// hardware CTF through an immediate orderly shutdown).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Ignored,
    /// THM low-to-high crossing: a software CTF candidate.
    SwCtf,
    /// ROM_SMUIO GPIO19: a hardware CTF already happened.
    HwCtf,
}
#[derive(Clone, Copy, Debug)]
struct Layout {
    thm: u64,
    mp: u64,
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        Ok(Self {
            thm: bank(gpu, ip::HW_ID_THM, &[(13, 0, 2)], 0, THERM_CTRL)
                .map_err(|_| Error::Unsupported)?,
            mp: bank(gpu, ip::HW_ID_MP1, &[(13, 0, 0)], 0, MP_CTRL)
                .map_err(|_| Error::Unsupported)?,
        })
    }
}
trait Io {
    fn read(&mut self, at: u64) -> u32;
    fn write(&mut self, at: u64, value: u32);
}
struct Mmio(MmioRegion);
impl Io for Mmio {
    fn read(&mut self, at: u64) -> u32 {
        // SAFETY: Layout bounded these discovery-based registers to this permanent BAR.
        unsafe { core::ptr::read_volatile((self.0.virt + at) as *const u32) }
    }
    fn write(&mut self, at: u64, value: u32) {
        // SAFETY: the service exclusively owns these thermal interrupt controls.
        unsafe { core::ptr::write_volatile((self.0.virt + at) as *mut u32, value) }
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
fn checked(v: u32) -> Result<u32, Error> {
    if v == u32::MAX {
        Err(Error::DeviceGone)
    } else {
        Ok(v)
    }
}
struct Engine<I> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    limits: Limits,
    status: Status,
}
impl<I: Io> Engine<I> {
    fn new(io: I, authority: Cap<BusDeviceCap, Write>, layout: Layout, limits: Limits) -> Self {
        Self {
            io,
            authority,
            layout,
            limits,
            status: Status {
                state: State::Prepared,
                high_c: limits.software_shutdown_c.min(255) as u8,
                high: 0,
                low: 0,
                smu: 0,
                hw_ctf: 0,
                fan_abnormal: false,
            },
        }
    }
    fn access<T>(
        &mut self,
        f: impl FnOnce(&mut I, Layout) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let result = self
            .authority
            .invoke(Op(|| f(&mut self.io, self.layout)))
            .map_err(|_| Error::Revoked)?;
        self.authority
            .invoke(Op(|| ()))
            .map_err(|_| Error::Revoked)?;
        result
    }
    fn arm(&mut self) -> Result<(), Error> {
        if self.status.state != State::Prepared {
            return Err(Error::Busy);
        }
        let high = u32::from(self.status.high_c);
        let result = self.access(|io, l| {
            let old = checked(io.read(l.thm + u64::from(THERM_CTRL) * 4))?;
            let control = (old & !(0xffff | INTH_MASK | INTL_MASK | TRIGGER_MASK | CREDIT))
                | high
                | IH_ENABLE
                | 5 << 29;
            io.write(l.thm + u64::from(THERM_CTRL) * 4, control);
            if checked(io.read(l.thm + u64::from(THERM_CTRL) * 4))? != control {
                return Err(Error::Readback);
            }
            io.write(l.thm + u64::from(THERM_ENA) * 4, CLEAR);
            let sw = checked(io.read(l.mp + u64::from(MP_INT) * 4))?;
            io.write(
                l.mp + u64::from(MP_INT) * 4,
                (sw & !(0xff | MP_VALID)) | u32::from(SMU_TO_DRIVER),
            );
            let control = checked(io.read(l.mp + u64::from(MP_CTRL) * 4))? & !MP_MASK;
            io.write(l.mp + u64::from(MP_CTRL) * 4, control);
            if checked(io.read(l.mp + u64::from(MP_CTRL) * 4))? & MP_MASK != 0 {
                return Err(Error::Readback);
            }
            Ok(())
        });
        self.status.state = result.map_or_else(State::Failed, |()| State::Armed);
        result
    }
    fn stop(&mut self) -> Result<(), Error> {
        if matches!(self.status.state, State::Prepared | State::Stopped) {
            self.status.state = State::Stopped;
            return Ok(());
        }
        let result = self.access(|io, l| {
            let control =
                checked(io.read(l.thm + u64::from(THERM_CTRL) * 4))? | INTH_MASK | INTL_MASK;
            io.write(l.thm + u64::from(THERM_CTRL) * 4, control);
            io.write(l.thm + u64::from(THERM_ENA) * 4, 0);
            let control = checked(io.read(l.mp + u64::from(MP_CTRL) * 4))? | MP_MASK;
            io.write(l.mp + u64::from(MP_CTRL) * 4, control);
            Ok(())
        });
        self.status.state = result.map_or_else(State::Failed, |()| State::Stopped);
        result
    }
    /// Capture exact known sources. Only MP1 source 0xfe is acknowledged;
    /// THM has no per-vector ACK in smu_v13_0_irq_process.
    fn handle(&mut self, event: ih::Event) -> Result<Outcome, Error> {
        if self.status.state != State::Armed {
            return Ok(Outcome::Ignored);
        }
        let v = event.vector;
        if v.client == CLIENT_THM {
            match v.source {
                SRC_THERM_L2H => {
                    self.status.high = self.status.high.saturating_add(1);
                    return Ok(Outcome::SwCtf);
                }
                SRC_THERM_H2L => self.status.low = self.status.low.saturating_add(1),
                _ => {}
            }
            return Ok(Outcome::Ignored);
        }
        if v.client == CLIENT_ROM_SMUIO {
            if v.source == SRC_SMUIO_GPIO19 {
                self.status.hw_ctf = self.status.hw_ctf.saturating_add(1);
                return Ok(Outcome::HwCtf);
            }
            return Ok(Outcome::Ignored);
        }
        if v.client != CLIENT_MP1 || v.source != SMU_TO_DRIVER {
            return Ok(Outcome::Ignored);
        }
        self.status.smu = self.status.smu.saturating_add(1);
        let context = v.data[0];
        let high = match context {
            FAN_ABNORMAL => Some(
                (i32::from(self.limits.software_shutdown_c)
                    + i32::from(self.limits.software_shutdown_offset_c))
                .clamp(0, 255) as u8,
            ),
            FAN_RECOVERY => Some(self.limits.software_shutdown_c.min(255) as u8),
            _ => None,
        };
        let result = self.access(|io, l| {
            let ctrl = checked(io.read(l.mp + u64::from(MP_CTRL) * 4))?;
            io.write(l.mp + u64::from(MP_CTRL) * 4, ctrl | MP_ACK);
            if let Some(high) = high {
                let ctrl = checked(io.read(l.thm + u64::from(THERM_CTRL) * 4))?;
                io.write(
                    l.thm + u64::from(THERM_CTRL) * 4,
                    (ctrl & !(0xff | TRIGGER_MASK)) | u32::from(high),
                );
            }
            Ok(())
        });
        if let Err(e) = result {
            self.status.state = State::Failed(e);
            return Err(e);
        }
        if let Some(high) = high {
            self.status.high_c = high;
            self.status.fan_abnormal = context == FAN_ABNORMAL;
        }
        Ok(Outcome::Ignored)
    }
    /// Set a static PWM mode (`FDO_PWM_MODE_STATIC` or
    /// `FDO_PWM_MODE_STATIC_RPM`), as smu_v13_0_set_fan_static_mode: TMIN
    /// to zero first, then the mode. The caller disables the FAN_CONTROL
    /// feature through the SMU owner first (Linux `auto_fan_control(0)`).
    fn set_static_mode(&mut self, mode: u8) -> Result<(), Error> {
        if mode != FDO_PWM_MODE_STATIC && mode != FDO_PWM_MODE_STATIC_RPM {
            return Err(Error::Invalid);
        }
        self.access(|io, l| {
            let old = checked(io.read(l.thm + u64::from(FDO_CTRL2) * 4))?;
            io.write(l.thm + u64::from(FDO_CTRL2) * 4, old & !TMIN_MASK);
            let old = checked(io.read(l.thm + u64::from(FDO_CTRL2) * 4))?;
            io.write(
                l.thm + u64::from(FDO_CTRL2) * 4,
                (old & !FDO_PWM_MODE_MASK) | (u32::from(mode) << FDO_PWM_MODE_SHIFT),
            );
            Ok(())
        })
    }
    /// Set a static fan duty, as smu_v13_0_set_fan_speed_pwm: the duty is
    /// scaled by the board's `FMAX_DUTY100`, then the static PWM mode is
    /// entered. Returns the written duty. A zero `FMAX_DUTY100` means the
    /// board has no fan table to scale against.
    fn set_fan_pwm(&mut self, speed: u8) -> Result<u8, Error> {
        let duty = self.access(|io, l| {
            let duty100 = checked(io.read(l.thm + u64::from(FDO_CTRL1) * 4))? & FMAX_DUTY100_MASK;
            if duty100 == 0 {
                return Err(Error::Unsupported);
            }
            let duty = fan_duty(speed, duty100 as u8);
            let old = checked(io.read(l.thm + u64::from(FDO_CTRL0) * 4))?;
            io.write(
                l.thm + u64::from(FDO_CTRL0) * 4,
                (old & !FDO_STATIC_DUTY_MASK) | u32::from(duty),
            );
            Ok(duty)
        })?;
        self.set_static_mode(FDO_PWM_MODE_STATIC)?;
        Ok(duty)
    }
    /// Set a static fan speed in RPM, as smu_v13_0_set_fan_speed_rpm: the
    /// tachometer period is programmed, then the static-RPM mode is entered.
    /// Returns the written tachometer period.
    fn set_fan_rpm(&mut self, rpm: u32) -> Result<u32, Error> {
        let period = tach_period(rpm).ok_or(Error::Invalid)?;
        self.access(|io, l| {
            let old = checked(io.read(l.thm + u64::from(TACH_CTRL) * 4))?;
            io.write(
                l.thm + u64::from(TACH_CTRL) * 4,
                (old & !TARGET_PERIOD_MASK)
                    | ((period << TARGET_PERIOD_SHIFT) & TARGET_PERIOD_MASK),
            );
            Ok(())
        })?;
        self.set_static_mode(FDO_PWM_MODE_STATIC_RPM)?;
        Ok(period)
    }
}
pub struct Monitor(Engine<Mmio>);
impl core::fmt::Debug for Monitor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Thermal").field(&self.0.status).finish()
    }
}
impl Monitor {
    /// Construction does no I/O. The retained IH service must own the
    /// monitor before arming, and stop it before dropping its GPU epoch.
    pub fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        limits: Option<Limits>,
    ) -> Option<Self> {
        let limits = limits.filter(|l| l.software_shutdown_c != 0)?;
        let layout = Layout::resolve(gpu).ok()?;
        Some(Self(Engine::new(Mmio(gpu.regs), authority, layout, limits)))
    }
    pub fn arm(&mut self) -> Result<(), Error> {
        self.0.arm()
    }
    pub fn stop(&mut self) -> Result<(), Error> {
        self.0.stop()
    }
    pub fn handle(&mut self, event: ih::Event) -> Result<Outcome, Error> {
        self.0.handle(event)
    }
    /// Set a static fan duty (0-255). The caller disables the FAN_CONTROL
    /// feature through the SMU owner first.
    pub fn set_fan_pwm(&mut self, speed: u8) -> Result<u8, Error> {
        self.0.set_fan_pwm(speed)
    }
    /// Set a static fan speed in RPM. The caller disables the FAN_CONTROL
    /// feature through the SMU owner first.
    pub fn set_fan_rpm(&mut self, rpm: u32) -> Result<u32, Error> {
        self.0.set_fan_rpm(rpm)
    }
    pub fn threshold(&self) -> u16 {
        self.0.limits.software_shutdown_c
    }
    pub fn status(&self) -> Status {
        self.0.status
    }
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi31_thermal_tests.rs"]
mod tests;

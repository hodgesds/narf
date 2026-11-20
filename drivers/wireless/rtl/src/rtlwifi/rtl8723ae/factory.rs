// SPDX-License-Identifier: GPL-2.0-or-later
//! Checked native AE logical-map and physical PA-byte observations.
//!
//! Linux rtlwifi/efuse.c:70..109,1099..1170 and rtl8723ae/hw.c:1004.
//! The switched preflight and timeout/lost-register refusals are explicit
//! native restrictions. This owns no radio/packet admission or DMA fence.
//! The registered native capsule retains this owner and exact cold backend,
//! including a failed cleanup receipt; registration supplies the one-shot handoff.
use super::{adapter, txpower, version};
use crate::rtlwifi::{efuse::Factory, firmware_transport::Error as AccessError};
use alloc::{boxed::Box, sync::Arc};

const ACCESS: u16 = 0xcf;
const CTRL: u16 = 0x30;
const SYS_FUNC: u16 = 2;
const SYS_CLK: u16 = 8;
const PHYSICAL_MAP: usize = 512 - 15;
pub(super) const PA_ADDRESS: u16 = 0x1fa;
const READY_REPEATS: usize = 1000;

/// Each operation must execute under CURRENT native PCI authority.
/// Exact-width reads are part of the contract, not an unaligned read32.
pub(super) trait Regs {
    fn read8(&self, reg: u16) -> Result<u8, AccessError>;
    fn read16(&self, reg: u16) -> Result<u16, AccessError>;
    fn read32(&self, reg: u16) -> Result<u32, AccessError>;
    fn write8(&self, reg: u16, value: u8) -> Result<(), AccessError>;
    fn write16(&self, reg: u16, value: u16) -> Result<(), AccessError>;
    fn write32(&self, reg: u16, value: u32) -> Result<(), AccessError>;
    fn settle_map_data(&self) {
        narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_us(50));
    }
}

// Requires the narrowly reviewed Io::read16/native implementation patch.
impl<I: crate::rtlwifi::firmware_transport::Io> Regs for I {
    fn read8(&self, reg: u16) -> Result<u8, AccessError> {
        <I as crate::rtlwifi::firmware_transport::Io>::read8(self, reg)
    }
    fn read16(&self, reg: u16) -> Result<u16, AccessError> {
        <I as crate::rtlwifi::firmware_transport::Io>::read16(self, reg)
    }
    fn read32(&self, reg: u16) -> Result<u32, AccessError> {
        <I as crate::rtlwifi::firmware_transport::Io>::read32(self, reg)
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), AccessError> {
        <I as crate::rtlwifi::firmware_transport::Io>::write8(self, reg, value)
    }
    fn write16(&self, reg: u16, value: u16) -> Result<(), AccessError> {
        <I as crate::rtlwifi::firmware_transport::Io>::write16(self, reg, value)
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), AccessError> {
        <I as crate::rtlwifi::firmware_transport::Io>::write32(self, reg, value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Access(AccessError),
    Gone,
    Timeout,
    Bank,
    Unprovisioned,
    Map,
    Identity,
    RawPower,
    Cleanup,
    Terminal,
}
impl From<AccessError> for Error {
    fn from(e: AccessError) -> Self {
        Self::Access(e)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Failure {
    /// Preserves the operation error independently from lost cleanup authority.
    pub operation: Option<Error>,
    pub cleanup: Option<Error>,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Gate {
    #[default]
    Untouched,
    MayBeOn,
    Closed,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Reading,
    Ready,
    Failed(Failure),
    Quarantined(Failure),
}

/// Private historical receipt of an actually acknowledged ACCESS0 readback.
/// It is retained by Owner even when the operation itself returned Err;
/// it grants neither current access, RF recovery nor DMA reclamation.
#[derive(Debug)]
pub(super) struct ReadPowerClosed {
    _private: (),
}

/// Sealed observation, never constructible from arbitrary logical bytes.
/// The byte is valid even when DATA=0xff; failed ready/cleanup is no Inputs.
#[derive(Debug)]
pub(super) struct Inputs {
    factory: Arc<Factory>,
    adapter: adapter::Adapter,
    pa: u8,
    sys_cfg: u32,
    gpio: u32,
    multi: u32,
    cr9346: u8,
}
impl Inputs {
    pub(super) fn factory(&self) -> &Factory {
        &self.factory
    }
    pub(super) fn adapter(&self) -> &adapter::Adapter {
        &self.adapter
    }
    pub(super) fn pa(&self) -> u8 {
        self.pa
    }
    pub(super) fn observed(&self) -> [u32; 4] {
        [self.sys_cfg, self.gpio, self.multi, u32::from(self.cr9346)]
    }
    pub(super) fn efuse(&self) -> txpower::Efuse {
        txpower::Efuse::from_adapter(&self.adapter)
    }
}

/// Retain this alongside the exact backend/function even when quarantined.
/// Closed means EFUSE read-power cleanup only, never RF or DMA quiescence.
#[derive(Debug, Default)]
pub(super) struct Owner {
    state: State,
    gate: Gate,
    inputs: Option<Arc<Inputs>>,
    closed: Option<ReadPowerClosed>,
}
impl Owner {
    pub(super) fn state(&self) -> State {
        self.state
    }
    pub(super) fn gate(&self) -> Gate {
        self.gate
    }
    pub(super) fn cleanup_receipt(&self) -> Option<&ReadPowerClosed> {
        self.closed.as_ref()
    }
    pub(super) fn inputs(&self) -> Option<Arc<Inputs>> {
        (self.state == State::Ready)
            .then(|| self.inputs.clone())
            .flatten()
    }

    /// # Safety
    /// Same exclusive powered AE function and original cold owner remain
    /// retained; no other EFUSE/reset/PHY writer, no native packet claim or
    /// station producer. Io validates every actual access under current PCI
    /// authority. Caller pins all state/reservation on Quarantined; no
    /// reset/retry/reclaim receipt is supplied here. No waits use an IRQ lock.
    pub(super) unsafe fn acquire(
        &mut self,
        io: &impl Regs,
        expected: Arc<Factory>,
    ) -> Result<Arc<Inputs>, Failure> {
        if self.state != State::New {
            return Err(Failure {
                operation: Some(Error::Terminal),
                cleanup: None,
            });
        }
        self.state = State::Reading;
        let result = self.read(io, expected);
        // Even a synchronous scheduler poll can pump/revoke. Cleanup invokes
        // current PCI authority independently; no raw-MMIO Drop escape hatch.
        let cleanup = if self.gate == Gate::MayBeOn {
            close(io).map(|receipt| {
                self.gate = Gate::Closed;
                self.closed = Some(receipt);
            })
        } else {
            Ok(())
        };
        if let Err(cleanup) = cleanup {
            let failure = Failure {
                operation: result.err(),
                cleanup: Some(cleanup),
            };
            self.state = State::Quarantined(failure);
            return Err(failure);
        }
        match result {
            Ok(inputs) => {
                let inputs = Arc::new(inputs);
                self.inputs = Some(inputs.clone());
                self.state = State::Ready;
                Ok(inputs)
            }
            Err(error) => {
                let failure = Failure {
                    operation: Some(error),
                    cleanup: None,
                };
                self.state = State::Failed(failure);
                Err(failure)
            }
        }
    }

    fn read(&mut self, io: &impl Regs, factory: Arc<Factory>) -> Result<Inputs, Error> {
        let sys_cfg = live32(io, version::REG_SYS_CFG)?;
        if sys_cfg & version::TRP_VAUX_EN != 0 || sys_cfg & version::BT_FUNC == 0 {
            return Err(Error::Unprovisioned);
        }
        let gpio = live32(io, version::REG_GPIO_OUTSTS)?;
        let multi = live32(io, version::REG_MULTI_FUNC_CTRL)?;
        let version = version::Version::from_registers(sys_cfg, || gpio, || multi)
            .map_err(|_| Error::Unprovisioned)?;
        let cr9346 = io.read8(adapter::REG_9346CR)?;
        if cr9346 == u8::MAX {
            return Err(Error::Gone);
        }
        if cr9346 & (adapter::CR9346_EEPROM | adapter::CR9346_AUTOLOAD_OK)
            != adapter::CR9346_AUTOLOAD_OK
        {
            return Err(Error::Unprovisioned);
        }
        bank(io)?;
        // Intent precedes a possibly accepted access-gate write.
        self.gate = Gate::MayBeOn;
        io.write8(ACCESS, 0x69)?;
        let func = io.read16(SYS_FUNC)?;
        if func == u16::MAX {
            return Err(Error::Gone);
        }
        if func & (1 << 12) == 0 {
            io.write16(SYS_FUNC, func | (1 << 12))?;
        }
        let clock = io.read16(SYS_CLK)?;
        if clock == u16::MAX {
            return Err(Error::Gone);
        }
        if clock & 0x22 != 0x22 {
            io.write16(SYS_CLK, clock | 0x22)?;
        }

        let mut raw = Box::new([0xff; PHYSICAL_MAP]);
        for (address, byte) in raw.iter_mut().enumerate() {
            *byte = map_byte(io, address as u16)?;
        }
        let mut logical = Box::new([0xff; 512]);
        narf_drivers_wireless_rtw::rtw88::efuse::decode_map(&raw[..], &mut logical[..256])
            .map_err(|_| Error::Map)?;
        if logical[..] != factory.logical {
            return Err(Error::Identity);
        }
        let adapter = adapter::Adapter::from_hardware(version, cr9346, multi, &logical[..])
            .map_err(|_| Error::Unprovisioned)?;
        if adapter.mac != factory.mac || !crate::rtlwifi::efuse::mac_is_valid(adapter.mac) {
            return Err(Error::Identity);
        }
        validate_power(&adapter)?;
        // Reassert/verify the bank immediately before the independent OOB
        // observation. Logical-map bytes cannot attest physical0x1fa.
        bank(io)?;
        let pa = physical(io, PA_ADDRESS)?;
        Ok(Inputs {
            factory,
            adapter,
            pa,
            sys_cfg,
            gpio,
            multi,
            cr9346,
        })
    }
}

fn live32(io: &impl Regs, reg: u16) -> Result<u32, Error> {
    let value = io.read32(reg)?;
    if value == u32::MAX {
        Err(Error::Gone)
    } else {
        Ok(value)
    }
}
fn bank(io: &impl Regs) -> Result<(), Error> {
    let value = live32(io, adapter::REG_EFUSE_TEST)?;
    io.write32(adapter::REG_EFUSE_TEST, adapter::efuse_test_wifi_sel(value))?;
    if live32(io, adapter::REG_EFUSE_TEST)? & adapter::EFUSE_SEL_MASK != 0 {
        return Err(Error::Bank);
    }
    Ok(())
}
fn close(io: &impl Regs) -> Result<ReadPowerClosed, Error> {
    io.write8(ACCESS, 0)?;
    let value = io.read8(ACCESS)?;
    if value == u8::MAX {
        return Err(Error::Gone);
    }
    if value != 0 {
        return Err(Error::Cleanup);
    }
    Ok(ReadPowerClosed { _private: () })
}

fn begin_read(io: &impl Regs, address: u16) -> Result<(), Error> {
    if address >= 512 {
        return Err(Error::Map);
    }
    io.write8(CTRL + 1, address as u8)?;
    let high = io.read8(CTRL + 2)?;
    if high == u8::MAX {
        return Err(Error::Gone);
    }
    io.write8(CTRL + 2, (high & 0xfc) | ((address >> 8) as u8 & 3))?;
    let trigger = io.read8(CTRL + 3)?;
    if trigger == u8::MAX {
        return Err(Error::Gone);
    }
    io.write8(CTRL + 3, trigger & 0x7f)?;
    Ok(())
}

/// Logical-map source read_efuse_byte (efuse.c:162..207): DWORD ready
/// reads, at most10000 repeats on PCIe, then50us DATA settling. Distinct
/// from the physical PA reader's BYTE ready polling and1000-repeat limit.
fn map_byte(io: &impl Regs, address: u16) -> Result<u8, Error> {
    begin_read(io, address)?;
    let mut reads = 0;
    let mut status = Ok(false);
    narf_scheduler::responsive_spin_until(
        || {
            if reads > 10_000 {
                return true;
            }
            reads += 1;
            status = live32(io, CTRL).map(|v| v & (1 << 31) != 0);
            !matches!(status, Ok(false)) || reads > 10_000
        },
        narf_time::Deadline::after_ms(100),
    );
    if !status? {
        return Err(Error::Timeout);
    }
    io.settle_map_data();
    let value = live32(io, CTRL)?;
    if value & (1 << 31) == 0 {
        return Err(Error::Timeout);
    }
    Ok(value as u8)
}

/// Source initial ready read plus at most1000 repeated ready reads. DATA
/// is read only after ready; DATA0xff is valid, status0xff is lost/unknown.
/// Linux timeout reads stale DATA; native qualification explicitly refuses.
fn physical(io: &impl Regs, address: u16) -> Result<u8, Error> {
    begin_read(io, address)?;
    let mut reads = 0;
    let mut status = Ok(false);
    // The attempt guard remains authoritative if the scheduler invokes done
    // once more at the time ceiling. Never issue a1002nd ready read.
    narf_scheduler::responsive_spin_until(
        || {
            if reads > READY_REPEATS {
                return true;
            }
            reads += 1;
            status = io.read8(CTRL + 3).map_err(Error::from).and_then(|v| {
                if v == u8::MAX {
                    Err(Error::Gone)
                } else {
                    Ok(v & 0x80 != 0)
                }
            });
            !matches!(status, Ok(false)) || reads > READY_REPEATS
        },
        narf_time::Deadline::after_ms(100),
    );
    if !status? {
        return Err(Error::Timeout);
    }
    Ok(io.read8(CTRL)?)
}

/// Independent source-tail re-observation of physical0x1fa. Its gate and
/// cleanup receipt remain in the retained calibration Context on EVERY Err.
/// This is not a logical-map fallback and does not mint factory Inputs.
#[derive(Debug, Default)]
pub(super) struct PaOwner {
    state: State,
    gate: Gate,
    closed: Option<ReadPowerClosed>,
    observed: Option<u8>,
}
impl PaOwner {
    pub(super) fn state(&self) -> State {
        self.state
    }
    pub(super) fn observed(&self) -> Option<u8> {
        self.observed
    }
    pub(super) fn cleanup_receipt(&self) -> Option<&ReadPowerClosed> {
        self.closed.as_ref()
    }
    /// # Safety
    /// The registered operation retains this owner and the exclusive original
    /// backend on success, failure, cancellation and removal. Every access,
    /// including ACCESS0 cleanup, must invoke current original PCI authority.
    pub(super) unsafe fn acquire(&mut self, io: &impl Regs) -> Result<u8, Failure> {
        if self.state != State::New {
            return Err(Failure {
                operation: Some(Error::Terminal),
                cleanup: None,
            });
        }
        self.state = State::Reading;
        let result = (|| {
            bank(io)?;
            self.gate = Gate::MayBeOn;
            io.write8(ACCESS, 0x69)?;
            let func = io.read16(SYS_FUNC)?;
            if func == u16::MAX {
                return Err(Error::Gone);
            }
            if func & (1 << 12) == 0 {
                io.write16(SYS_FUNC, func | (1 << 12))?;
            }
            let clock = io.read16(SYS_CLK)?;
            if clock == u16::MAX {
                return Err(Error::Gone);
            }
            if clock & 0x22 != 0x22 {
                io.write16(SYS_CLK, clock | 0x22)?;
            }
            physical(io, PA_ADDRESS)
        })();
        if self.gate == Gate::MayBeOn {
            match close(io) {
                Ok(receipt) => {
                    self.gate = Gate::Closed;
                    self.closed = Some(receipt);
                }
                Err(error) => {
                    let failure = Failure {
                        operation: result.err(),
                        cleanup: Some(error),
                    };
                    self.state = State::Quarantined(failure);
                    return Err(failure);
                }
            }
        }
        match result {
            Ok(value) => {
                self.observed = Some(value);
                self.state = State::Ready;
                Ok(value)
            }
            Err(error) => {
                let failure = Failure {
                    operation: Some(error),
                    cleanup: None,
                };
                self.state = State::Failed(failure);
                Err(failure)
            }
        }
    }
}

/// Conservative native admission restriction, not Linux defaulting. The
/// source preparation decoder still preserves all observed0xff arithmetic.
fn validate_power(adapter: &adapter::Adapter) -> Result<(), Error> {
    let h = &adapter.hwinfo;
    if h[0x10..=0x12]
        .iter()
        .chain(&h[0x16..=0x18])
        .any(|b| *b > 63)
        || h[0x1c..=0x27].contains(&0xff)
        || h[0x2b] == 0xff
    {
        return Err(Error::RawPower);
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "factory_policy_tests.rs"]
pub(super) mod tests;

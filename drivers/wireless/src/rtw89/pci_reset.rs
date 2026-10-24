// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! One retained identity-DMA PCIe FLR attempt, not a BME-off reset claim.
//! Linux pci.c::pci_wait_for_pending_transaction/pcie_flr/pci_restore_config_space.
use narf_bus::{BusAddr, BusDevice, BusDeviceCap, BusKind, DeviceId};
use narf_capabilities::{Cap, CapSlot, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Access,
    Unsupported,
    Identity,
    Capability,
    Pending,
    Timeout,
    Readback,
    Clock,
    Terminal,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    New,
    Starting,
    Quarantined,
    Ready,
    Terminal,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Binding {
    address: BusAddr,
    id: DeviceId,
    config: u64,
    slot: CapSlot,
}
impl Binding {
    fn new(device: &BusDevice, authority: &Cap<BusDeviceCap, Write>) -> Result<Self, Error> {
        let (address, config) = match device.kind {
            BusKind::Pcie { addr, cfg_phys }
                if device.addr == BusAddr::Pcie(addr)
                    && addr.device < 32
                    && addr.function < 8
                    && cfg_phys.raw() != 0
                    && cfg_phys.raw() & 4095 == 0
                    && cfg_phys.raw().checked_add(4095).is_some() =>
            {
                (addr, cfg_phys.raw())
            }
            _ => return Err(Error::Unsupported),
        };
        if device.id.vendor != 0x10ec || !matches!(device.id.device, 0xb852 | 0xb85b) {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            address: BusAddr::Pcie(address),
            id: device.id,
            config,
            slot: authority.slot(),
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Caps {
    express: u16,
    msi: Option<u16>,
    msix: Option<u16>,
}
/// The sole consumer is Startup::claim_reset below. No Clone, caller-created
/// field, generic consume operation or BME/power-only constructor is exposed.
pub(super) struct Fence {
    binding: Binding,
    caps: Caps,
    bars: [u32; 6],
    rom: u32,
}
/// # Safety
/// The function is exclusively reserved throughout this retained owner. Each
/// config read/write invokes the exact current BusDevice capability around the
/// actual access; `binding` never retargets. Only identity DMA is supported.
/// The monotonic clock and awaited delay are real platform time, not an
/// iteration counter. Drop performs NO config/MMIO/IRQ/DMA access. In particular
/// no path may access config during the100ms FLR quarantine, even on cancel.
pub(super) unsafe trait Io {
    fn binding(&self) -> Binding;
    fn read16(&mut self, offset: u16) -> Result<u16, Error>;
    fn read32(&mut self, offset: u16) -> Result<u32, Error>;
    fn write16(&mut self, offset: u16, value: u16) -> Result<(), Error>;
    fn write32(&mut self, offset: u16, value: u32) -> Result<(), Error>;
    fn now_ms(&self) -> u64;
    fn delay_ms(&mut self, ms: u64) -> impl core::future::Future<Output = ()>;
}
pub(super) struct Native {
    device: BusDevice,
    authority: Cap<BusDeviceCap, Write>,
    binding: Binding,
}
impl Native {
    fn new(device: BusDevice, authority: Cap<BusDeviceCap, Write>) -> Result<Self, Error> {
        if narf_io::iommu::mode() == narf_io::iommu::IommuMode::PerDomain {
            return Err(Error::Unsupported);
        }
        let binding = Binding::new(&device, &authority)?;
        crate::rtw88::pci_park::invoke(&authority, || ()).map_err(|_| Error::Access)?;
        Ok(Self {
            device,
            authority,
            binding,
        })
    }
    fn access<T>(
        &mut self,
        offset: u16,
        width: u16,
        operation: impl FnOnce(u64) -> T,
    ) -> Result<T, Error> {
        if narf_io::iommu::mode() == narf_io::iommu::IommuMode::PerDomain {
            return Err(Error::Unsupported);
        }
        if offset % width != 0 || u32::from(offset) + u32::from(width) > 4096 {
            return Err(Error::Capability);
        }
        if Binding::new(&self.device, &self.authority)? != self.binding {
            return Err(Error::Identity);
        }
        crate::rtw88::pci_park::invoke(&self.authority, || {
            operation(self.binding.config + u64::from(offset))
        })
        .map_err(|_| Error::Access)
    }
}
// SAFETY: retained exact function/cap/ECAM binding; every bounded aligned
// volatile config access is inside its actual current capability invocation.
// Native has no Drop cleanup, no DMA/IOMMU mutation and real monotonic timers.
unsafe impl Io for Native {
    fn binding(&self) -> Binding {
        self.binding
    }
    fn read16(&mut self, offset: u16) -> Result<u16, Error> {
        self.access(offset, 2, |address| {
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            // SAFETY: complete aligned exclusively reserved ECAM extent, inside
            // current invocation; physical address resolves through kernel map.
            let value = unsafe {
                narf_memory::PhysAddr::new(address)
                    .kernel_ptr::<u16>()
                    .read_volatile()
            };
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            value
        })
    }
    fn read32(&mut self, offset: u16) -> Result<u32, Error> {
        self.access(offset, 4, |address| {
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            // SAFETY: aligned full owned ECAM dword under current invocation.
            let value = unsafe {
                narf_memory::PhysAddr::new(address)
                    .kernel_ptr::<u32>()
                    .read_volatile()
            };
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            value
        })
    }
    fn write16(&mut self, offset: u16, value: u16) -> Result<(), Error> {
        self.access(offset, 2, |address| {
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            // SAFETY: exact owned current ECAM word. Word writes preserve the
            // adjacent RW1C status half rather than echoing it through a dword.
            unsafe {
                narf_memory::PhysAddr::new(address)
                    .kernel_mut_ptr::<u16>()
                    .write_volatile(value);
            }
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        })
    }
    fn write32(&mut self, offset: u16, value: u32) -> Result<(), Error> {
        self.access(offset, 4, |address| {
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            // SAFETY: exact bounded owned BAR/ROM config dword under invocation.
            unsafe {
                narf_memory::PhysAddr::new(address)
                    .kernel_mut_ptr::<u32>()
                    .write_volatile(value);
            }
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        })
    }
    fn now_ms(&self) -> u64 {
        narf_time::wall::monotonic_ns() / 1_000_000
    }
    async fn delay_ms(&mut self, ms: u64) {
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(ms.saturating_mul(1_000_000))).await;
    }
}
pub(super) struct Reset<I = Native> {
    io: I,
    binding: Binding,
    phase: Phase,
}
impl<I> core::fmt::Debug for Reset<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw89PciReset")
            .field("phase", &self.phase)
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}
struct Attempt<'a, I> {
    reset: &'a mut Reset<I>,
    committed: bool,
}
impl<I> Drop for Attempt<'_, I> {
    fn drop(&mut self) {
        if !self.committed {
            self.reset.phase = Phase::Terminal;
        }
        // Intentionally no config access, including during quarantine.
    }
}
impl Reset<Native> {
    /// # Safety
    /// The caller already retains the singleton reservation for this exact
    /// function. No other config/MMIO/IRQ/reset or driver producer may run.
    /// Inherited DMA need not be assumed stopped: only successful FLR below
    /// can produce the temporal fence. Retain this owner before awaiting run.
    pub(super) unsafe fn claim(
        device: BusDevice,
        authority: Cap<BusDeviceCap, Write>,
    ) -> Result<Self, Error> {
        let io = Native::new(device, authority)?;
        let binding = io.binding;
        Ok(Self {
            io,
            binding,
            phase: Phase::New,
        })
    }
}
const PARK_MASK: u16 = 7;
const INTX_OFF: u16 = 1 << 10;
impl<I: Io> Reset<I> {
    pub(super) fn phase(&self) -> Phase {
        self.phase
    }
    pub(super) async fn run(&mut self) -> Result<Fence, Error> {
        if self.phase != Phase::New {
            return Err(Error::Terminal);
        }
        self.phase = Phase::Starting;
        let mut attempt = Attempt {
            reset: self,
            committed: false,
        };
        let reset = &mut attempt.reset;
        if reset.io.binding() != reset.binding {
            return Err(Error::Identity);
        }
        validate_identity(&mut reset.io, reset.binding)?;
        let caps = capabilities(&mut reset.io)?;
        if reset.io.read32(caps.express + 4)? & (1 << 28) == 0 {
            return Err(Error::Unsupported);
        }
        let control = reset.io.read16(caps.express + 8)?;
        if control == u16::MAX || control & (1 << 15) != 0 {
            return Err(Error::Readback);
        }
        let mut bars = [0; 6];
        for (index, bar) in bars.iter_mut().enumerate() {
            *bar = reset.io.read32(0x10 + index as u16 * 4)?;
        }
        let rom = reset.io.read32(0x30)?;
        interrupts_off(&mut reset.io, caps)?;
        park(&mut reset.io)?;
        // Linux pci_wait_for_pending: sample at0,100,300,700ms. This profile
        // refuses pending timeout instead of resetting with ambiguous traffic.
        for index in 0..4 {
            if index != 0 {
                reset.io.delay_ms(100 << (index - 1)).await;
            }
            let status = reset.io.read16(caps.express + 10)?;
            if status == u16::MAX {
                return Err(Error::Access);
            }
            if status & (1 << 5) == 0 {
                break;
            }
            if index == 3 {
                return Err(Error::Pending);
            }
        }
        validate_identity(&mut reset.io, reset.binding)?;
        // From BEFORE the possibly accepted trigger onward, cancellation/error
        // performs no cleanup access. No readback may precede100 real ms.
        reset.phase = Phase::Quarantined;
        reset.io.write16(caps.express + 8, control | 1 << 15)?;
        let start = reset.io.now_ms();
        // Native milliseconds are truncated. An extra millisecond prevents a
        // fractional start tick from shortening the real100ms quiet period.
        let deadline = start.checked_add(101).ok_or(Error::Clock)?;
        let mut previous = start;
        loop {
            let now = reset.io.now_ms();
            if now < previous {
                return Err(Error::Clock);
            }
            if now >= deadline {
                break;
            }
            previous = now;
            reset.io.delay_ms(deadline - now).await;
        }
        wait_ready(&mut reset.io, reset.binding).await?;
        if capabilities(&mut reset.io)? != caps
            || reset.io.read16(caps.express + 8)? & (1 << 15) != 0
        {
            return Err(Error::Readback);
        }
        // Restoring a BAR with decode active is never allowed. An unexpected
        // post-FLR BME is a failed reset, not a substitute parking receipt.
        let command = reset.io.read16(4)?;
        if command == u16::MAX || command & PARK_MASK != 0 {
            return Err(Error::Readback);
        }
        interrupts_off(&mut reset.io, caps)?;
        park(&mut reset.io)?;
        // Linux restores type0 BAR dwords before the command register; high
        // dwords first also preserve paired64-bit BARs while decode stays off.
        for index in (0..6).rev() {
            let offset = 0x10 + index as u16 * 4;
            reset.io.write32(offset, bars[index])?;
            if reset.io.read32(offset)? != bars[index] {
                return Err(Error::Readback);
            }
        }
        reset.io.write32(0x30, rom)?;
        if reset.io.read32(0x30)? != rom {
            return Err(Error::Readback);
        }
        park(&mut reset.io)?;
        validate_identity(&mut reset.io, reset.binding)?;
        reset.phase = Phase::Ready;
        let fence = Fence {
            binding: reset.binding,
            caps,
            bars,
            rom,
        };
        attempt.committed = true;
        Ok(fence)
    }
}
fn validate_identity(io: &mut impl Io, binding: Binding) -> Result<(), Error> {
    if io.binding() != binding
        || io.read32(0)? != u32::from(binding.id.vendor) | u32::from(binding.id.device) << 16
        || io.read32(8)? >> 8 != binding.id.class
        || io.read32(0x2c)?
            != u32::from(binding.id.subsystem_vendor) | u32::from(binding.id.subsystem_id) << 16
        || io.read16(0xe)? & 0x7f != 0
    {
        return Err(Error::Identity);
    }
    Ok(())
}
fn capabilities(io: &mut impl Io) -> Result<Caps, Error> {
    if io.read16(6)? & 16 == 0 {
        return Err(Error::Unsupported);
    }
    let mut offset = (io.read32(0x34)? & 255) as u16;
    let mut seen = [false; 64];
    let (mut express, mut msi, mut msix) = (None, None, None);
    for _ in 0..48 {
        if offset == 0 {
            break;
        }
        if !(0x40..=0xfc).contains(&offset) || offset & 3 != 0 || seen[(offset / 4) as usize] {
            return Err(Error::Capability);
        }
        seen[(offset / 4) as usize] = true;
        let header = io.read16(offset)?;
        if header == u16::MAX {
            return Err(Error::Access);
        }
        let target = match header & 255 {
            0x10 => &mut express,
            5 => &mut msi,
            0x11 => &mut msix,
            _ => {
                offset = header >> 8;
                continue;
            }
        };
        if target.replace(offset).is_some() {
            return Err(Error::Capability);
        }
        offset = header >> 8;
    }
    if offset != 0 {
        return Err(Error::Capability);
    }
    let express = express.ok_or(Error::Unsupported)?;
    if express > 0xf4 || msi.is_some_and(|off| off > 0xfc) || msix.is_some_and(|off| off > 0xfc) {
        return Err(Error::Capability);
    }
    let flags = io.read16(express + 2)?;
    if flags & 15 == 0 || flags & 0xf0 != 0 {
        return Err(Error::Unsupported);
    }
    Ok(Caps { express, msi, msix })
}
fn interrupts_off(io: &mut impl Io, caps: Caps) -> Result<(), Error> {
    if let Some(msi) = caps.msi {
        let control = io.read16(msi + 2)?;
        if control == u16::MAX {
            return Err(Error::Access);
        }
        io.write16(msi + 2, control & !1)?;
        if io.read16(msi + 2)? & 1 != 0 {
            return Err(Error::Readback);
        }
    }
    if let Some(msix) = caps.msix {
        let control = io.read16(msix + 2)?;
        if control == u16::MAX {
            return Err(Error::Access);
        }
        io.write16(msix + 2, control & !(1 << 15) | 1 << 14)?;
        if io.read16(msix + 2)? & (3 << 14) != 1 << 14 {
            return Err(Error::Readback);
        }
    }
    Ok(())
}
fn park(io: &mut impl Io) -> Result<(), Error> {
    let command = io.read16(4)?;
    if command == u16::MAX {
        return Err(Error::Access);
    }
    io.write16(4, command & !PARK_MASK | INTX_OFF)?;
    if io.read16(4)? & (PARK_MASK | INTX_OFF) != INTX_OFF {
        return Err(Error::Readback);
    }
    Ok(())
}
async fn wait_ready(io: &mut impl Io, binding: Binding) -> Result<(), Error> {
    let start = io.now_ms();
    let deadline = start.checked_add(60_000).ok_or(Error::Clock)?;
    let mut delay = 1;
    let mut previous = start;
    loop {
        let command = io.read32(4)?;
        if command != u32::MAX && command as u16 != u16::MAX {
            let id = io.read32(0)?;
            // PCIe RRS software visibility: Vendor1/Deviceffff asks retry.
            if id != u32::MAX && id != 0xffff_0001 {
                return validate_identity(io, binding);
            }
        }
        let now = io.now_ms();
        if now < previous {
            return Err(Error::Clock);
        }
        if now >= deadline {
            return Err(Error::Timeout);
        }
        previous = now;
        io.delay_ms(delay.min(deadline - now)).await;
        delay = (delay * 2).min(1000);
    }
}

impl super::startup::Startup {
    /// Consume the only successful reset fence while retaining its exact
    /// singleton reservation. This does not accept BME-off or a board assertion.
    pub(super) fn claim_reset(
        device: BusDevice,
        authority: Cap<BusDeviceCap, Write>,
        fence: Fence,
    ) -> Result<Self, super::startup::Error> {
        let validate = || -> Result<(), Error> {
            if Binding::new(&device, &authority)? != fence.binding {
                return Err(Error::Identity);
            }
            let mut io = Native::new(device, authority)?;
            validate_identity(&mut io, fence.binding)?;
            if capabilities(&mut io)? != fence.caps
                || io.read16(fence.caps.express + 8)? & (1 << 15) != 0
                || io.read16(4)? & (PARK_MASK | INTX_OFF) != INTX_OFF
            {
                return Err(Error::Readback);
            }
            for (index, expected) in fence.bars.iter().copied().enumerate() {
                if io.read32(0x10 + index as u16 * 4)? != expected {
                    return Err(Error::Readback);
                }
            }
            if io.read32(0x30)? != fence.rom {
                return Err(Error::Readback);
            }
            Ok(())
        };
        validate().map_err(|error| {
            super::startup::Error::Register(if error == Error::Unsupported {
                super::power::Error::Unsupported
            } else {
                super::power::Error::Access
            })
        })?;
        // SAFETY: exact current successful temporal FLR fence consumed above;
        // caller retains its original singleton reservation throughout handoff.
        unsafe { Self::claim(device, authority) }
    }
}

#[cfg(feature = "kernel-test")]
#[path = "pci_reset/tests.rs"]
mod tests;

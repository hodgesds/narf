// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Original-owner BE closed radio access. Every real register, RF/XTAL
//! transaction and control/DMA publication is inside both current signed
//! N22P/N22W and original Bus capability invocation. No source-lock recursion.
use super::{
    be_qualification::{self, Grant},
    power::{self, Io},
    prepared_8922a::checked::CheckedPrepared,
    rf_access_be,
    rfk::{self, be_rfk::ReportKind},
};
use core::sync::atomic::{AtomicBool, Ordering};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};

pub(super) struct Registers<'a> {
    region: &'a MmioRegion,
    authority: &'a Cap<BusDeviceCap, Write>,
    qualification: Grant<'a>,
    cancelled: &'a AtomicBool,
    fault: Option<power::Error>,
}
impl<'a> Registers<'a> {
    /// # Safety
    /// These are the exact original checked Cold/FW/System/TRX owner and
    /// complete live Device BAR, with no competing radio/reset/IRQ producer.
    /// N22P was loaded over this owner's actual factory/assets/feature facts.
    /// The enclosing one-shot owner remains Busy on error/cancellation/drop
    /// and retains all DMA; this constructor grants no ordinary packet API.
    pub(super) unsafe fn new(
        region: &'a MmioRegion,
        authority: &'a Cap<BusDeviceCap, Write>,
        qualification: &'a be_qualification::Partial,
        cancelled: &'a AtomicBool,
    ) -> Self {
        // SAFETY: new's caller supplies the same original live BAR/PCI owner
        // and retained exact N22P source facts required by new_scope; wrapping
        // that borrowed grant changes neither ownership nor its authority.
        unsafe { Self::new_scope(region, authority, Grant::Partial(qualification), cancelled) }
    }
    /// # Safety
    /// Same original-owner contract as new; scope is the actual retained
    /// separately signed N22P or N22W permission, never a caller boolean.
    pub(super) unsafe fn new_scope(
        region: &'a MmioRegion,
        authority: &'a Cap<BusDeviceCap, Write>,
        qualification: Grant<'a>,
        cancelled: &'a AtomicBool,
    ) -> Self {
        Self {
            region,
            authority,
            qualification,
            cancelled,
            fault: None,
        }
    }
    fn latch<T>(&mut self, result: Result<T, power::Error>) -> Result<T, power::Error> {
        if let Some(error) = self.fault {
            return Err(error);
        }
        if let Err(error) = result {
            self.fault = Some(error);
        }
        result
    }
    /// Outer scope also encloses descriptor-memory writes/sync/publication
    /// in Prepared's checked CH12 port. Its per-register invocations remain.
    pub(super) fn semantic<T>(
        &mut self,
        operation: impl FnOnce() -> Result<T, power::Error>,
    ) -> Result<T, power::Error> {
        if self.cancelled.load(Ordering::Acquire) {
            return self.latch(Err(power::Error::Access));
        }
        if let Some(error) = self.fault {
            return Err(error);
        }
        let result = self.qualification.with_current(|| {
            crate::rtw88::pci_park::invoke(self.authority, || {
                guard(self.region)?;
                let result = operation()?;
                if self.cancelled.load(Ordering::Acquire) {
                    return Err(power::Error::Access);
                }
                guard(self.region)?;
                Ok(result)
            })
            .map_err(|_| power::Error::Access)?
        });
        self.latch(result)
    }
    pub(super) fn current(&mut self) -> Result<(), power::Error> {
        self.semantic(|| Ok(()))
    }
    fn checked<T>(
        &mut self,
        address: u32,
        operation: impl FnOnce(&MmioRegion, u64) -> Result<T, power::Error>,
    ) -> Result<T, power::Error> {
        let region = self.region;
        if !(permitted(address) || self.qualification.wlan() && permitted_wlan(address))
            || address & 3 != 0
            || u64::from(address)
                .checked_add(4)
                .is_none_or(|end| end > region.len)
        {
            return self.latch(Err(power::Error::Access));
        }
        self.semantic(|| operation(region, u64::from(address)))
    }
    async fn xtal(
        &mut self,
        address: u8,
        value: u8,
        mask: u8,
        read: bool,
    ) -> Result<u8, rfk::Error> {
        // mac_be.c::read/write_xtal_si_be; allowed original BE analog port.
        let command = u32::from(address)
            | if read {
                0x8100_0000
            } else {
                0x8000_0000 | (u32::from(value) << 8) | (u32::from(mask) << 16)
            };
        self.write32(0x88, command)?;
        let start = self.now_us();
        loop {
            let word = self.read32(0x88)?;
            if word & 0x8000_0000 == 0 {
                return Ok((word >> 8) as u8);
            }
            if self.now_us().saturating_sub(start) >= 50_000 {
                return self
                    .latch::<u8>(Err(power::Error::Timeout))
                    .map_err(Into::into);
            }
            self.delay_us(50).await;
        }
    }
}
fn permitted_wlan(address: u32) -> bool {
    [0xac, 0xe324, 0xe328, 0xe32c, 0xe344, 0xe348, 0xe350].contains(&address)
}
/// BB0/RF-v2 aperture plus the actual MAC0 SCC channel/power/PPDU fields.
/// No MAC1 bank, packet function, DMA enable, IRQ or reset-power API exists.
fn permitted(address: u32) -> bool {
    (0x20000..0x30000).contains(&address)
        || (0xe500..=0xe57c).contains(&address)
        || (0xed00..=0xed7c).contains(&address)
        || (0x11a00..=0x120e4).contains(&address)
        || [
            0x84, 0x88, 0x9c30, 0x10010, 0x10088, 0x1033c, 0x10370, 0x10828, 0x11440,
        ]
        .contains(&address)
}
fn guard(region: &MmioRegion) -> Result<(), power::Error> {
    guard_power(region, super::be_mac1::Power::Off)
}
fn guard_power(region: &MmioRegion, domain: super::be_mac1::Power) -> Result<(), power::Error> {
    let (afe1, fen1) = domain.tuple();
    // Complete always-accessible common tuples BEFORE the powered MAC0 bank.
    // BB0 platform can be toggled by source postinit; BB1 stays fully held.
    for (address, mask, expected) in [
        (0x24, 0x1f00_001f, 0x1f00_0000 | afe1),
        (0x84, 0x0303_0300, 0x0001_0000 | fen1),
        (0x10000, 0x3000_0000, 0),
        (0xb010, 0x8000_7fff, 0x8000_6fff),
        (0xb000, 0xb0, 0x30),
    ] {
        if region.len < address + 4 {
            return Err(power::Error::Access);
        }
        // SAFETY: only called within original current Bus invoke; aligned
        // complete control word extent checked, preceding power tuple proves
        // MAC0-bank accessibility. MAC1 is never read as a zero receipt.
        let value = unsafe { region.read32(address) };
        if value == u32::MAX {
            return Err(power::Error::Gone);
        }
        if value & mask != expected {
            return Err(power::Error::Access);
        }
    }
    Ok(())
}
impl Io for Registers<'_> {
    fn read8(&mut self, _: u32) -> Result<u8, power::Error> {
        self.latch(Err(power::Error::Unsupported))
    }
    fn read16(&mut self, at: u32) -> Result<u16, power::Error> {
        if at != 0x1087c || !self.qualification.wlan() || self.region.len < 0x1087e {
            return self.latch(Err(power::Error::Unsupported));
        }
        let region = self.region;
        // SAFETY: semantic invokes both original current authorities and
        // proves powered MAC0 before this exact aligned halfword extent.
        self.semantic(|| Ok(unsafe { region.read16(u64::from(at)) }))
    }
    fn read32(&mut self, address: u32) -> Result<u32, power::Error> {
        self.checked(address, |region, offset| {
            // SAFETY: checked exact current signed+Bus authority, aligned
            // permitted live aperture and complete word extent.
            let value = unsafe { region.read32(offset) };
            if value == u32::MAX {
                Err(power::Error::Gone)
            } else {
                Ok(value)
            }
        })
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), power::Error> {
        self.latch(Err(power::Error::Unsupported))
    }
    fn write16(&mut self, at: u32, value: u16) -> Result<(), power::Error> {
        if at != 0x1087c
            || value != 0x111
            || !self.qualification.wlan()
            || self.region.len < 0x1087e
        {
            return self.latch(Err(power::Error::Unsupported));
        }
        let region = self.region;
        self.semantic(|| {
            // SAFETY: semantic invokes the current original N22W/PCI caps
            // and verifies powered MAC0. The checks above restrict this to
            // aligned PLT halfword 0x1087c..0x1087e and source value 0x111.
            unsafe {
                region.write16(u64::from(at), value);
            }
            Ok(())
        })
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), power::Error> {
        self.checked(address, |region, offset| {
            // FEN is a narrow BB0 postinit surface. Inherited common/BB1
            // state cannot be replaced through a whole-word write.
            if address == 0x84 {
                // SAFETY: same checked original current control word.
                let old = unsafe { region.read32(offset) };
                if old == u32::MAX {
                    return Err(power::Error::Gone);
                }
                if (old ^ value) & !5 != 0 {
                    return Err(power::Error::Access);
                }
            }
            // SAFETY: checked exact signed+Bus authority, permitted aligned
            // source aperture; guard verifies packet/MAC1 closure afterward.
            unsafe {
                region.write32(offset, value);
            }
            Ok(())
        })
    }
    fn now_us(&self) -> u64 {
        narf_time::wall::monotonic_ns() / 1000
    }
    async fn delay_us(&mut self, us: u64) {
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(us.saturating_mul(1000))).await;
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported) // original completed factory owns ECV
    }
}

impl Registers<'_> {
    fn domain_effect(
        &mut self,
        before: super::be_mac1::Power,
        after: super::be_mac1::Power,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), power::Error> {
        if !self.qualification.wlan() || self.cancelled.load(Ordering::Acquire) {
            return self.latch(Err(power::Error::Access));
        }
        if let Some(error) = self.fault {
            return Err(error);
        }
        if u64::from(address) + 4 > self.region.len || address & 3 != 0 {
            return self.latch(Err(power::Error::Access));
        }
        let result = self.qualification.with_current(|| {
            crate::rtw88::pci_park::invoke(self.authority, || {
                guard_power(self.region, before)?;
                // SAFETY: original current PCI + N22W invocation, complete
                // powered tuple BEFORE a permitted C1/common register read.
                let old = unsafe { self.region.read32(u64::from(address)) };
                if old == u32::MAX {
                    return Err(power::Error::Gone);
                }
                let expected = (old & !mask) | (value & mask);
                // SAFETY: the original N22W/PCI scopes are still active;
                // alignment/word extent and the complete before-power tuple
                // were checked. Callers admit only exact source common-power
                // transitions or the three powered C1 fields, preserving all
                // bits outside that admitted field.
                unsafe {
                    self.region.write32(u64::from(address), expected);
                }
                // SAFETY: same current scopes and checked word extent. A
                // transition touches always-accessible common control only;
                // a C1 field leaves its verified Powered tuple unchanged.
                let observed = unsafe { self.region.read32(u64::from(address)) };
                if observed == u32::MAX || observed & mask != expected & mask {
                    return Err(power::Error::Access);
                }
                guard_power(self.region, after)?;
                if self.cancelled.load(Ordering::Acquire) {
                    return Err(power::Error::Access);
                }
                Ok(())
            })
            .map_err(|_| power::Error::Access)?
        });
        self.latch(result)
    }
}
impl super::be_mac1::Interface for Registers<'_> {
    fn transition(
        &mut self,
        before: super::be_mac1::Power,
        after: super::be_mac1::Power,
        at: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), power::Error> {
        use super::be_mac1::Power::*;
        let allowed = matches!(
            (before, after, at, mask, value),
            (Off, Afe, 0x24, 0x1f, 0x1f)
                | (Afe, Unisolated, 0x84, 0x2000000, 0)
                | (Unisolated, Powered, 0x84, 0x20000, 0x20000)
                | (Powered, Unisolated, 0x84, 0x20000, 0)
                | (Unisolated, Afe, 0x84, 0x2000000, 0x2000000)
                | (Afe, Off, 0x24, 0x1f, 0)
        );
        if !allowed {
            return self.latch(Err(power::Error::Access));
        }
        self.domain_effect(before, after, at, mask, value)
    }
    fn powered_field(&mut self, at: u32, mask: u32, value: u32) -> Result<(), power::Error> {
        if !matches!(
            (at, mask, value),
            (0x14000, 0x30000000, 0)
                | (0x15a84, u32::MAX, 0x0201fe00)
                | (0x15a78, u32::MAX, 0x00ffec7e)
        ) {
            return self.latch(Err(power::Error::Access));
        }
        self.domain_effect(
            super::be_mac1::Power::Powered,
            super::be_mac1::Power::Powered,
            at,
            mask,
            value,
        )
    }
    fn restrict(&mut self) -> Result<(), power::Error> {
        // Intentional restrictive exception: only CURRENT ORIGINAL PCI can
        // close this owned power window after N22W/cancellation failure.
        // No MAC1 bank is read and no normal source/grant is restored.
        let mut failed = false;
        for (at, mask, value) in [
            (0x84u64, 1 << 17, 0),
            (0x84, 1 << 25, 1 << 25),
            (0x24, 0x1f, 0),
        ] {
            let result = crate::rtw88::pci_park::invoke(self.authority, || {
                if at + 4 > self.region.len {
                    return Err(power::Error::Access);
                }
                // SAFETY: current original PCI invocation and complete word
                // extent above; the fixed list contains aligned, always-live
                // common FEN/isolation/AFE words, never a powered C1 bank.
                let old = unsafe { self.region.read32(at) };
                if old == u32::MAX {
                    return Err(power::Error::Gone);
                }
                // SAFETY: same current PCI/extent. These exact source masks
                // only disable FEN, assert isolation and remove AFE power for
                // the retained window; all unrelated bits are preserved. No
                // revoked N22W grant is used to resume normal radio effects.
                unsafe {
                    self.region.write32(at, (old & !mask) | value);
                }
                // SAFETY: the restrictive write leaves this common word
                // accessible; the original PCI scope and checked aligned
                // extent still cover its readback, without reading MAC1.
                let seen = unsafe { self.region.read32(at) };
                if seen == u32::MAX || seen & mask != value {
                    return Err(power::Error::Access);
                }
                Ok(())
            });
            if !matches!(result, Ok(Ok(()))) {
                failed = true;
            }
        }
        let verified = crate::rtw88::pci_park::invoke(self.authority, || guard(self.region));
        if failed || !matches!(verified, Ok(Ok(()))) {
            Err(power::Error::Access)
        } else {
            Ok(())
        }
    }
}

pub(super) struct Port<'a> {
    pub(super) io: Registers<'a>,
    pub(super) rf: &'a mut rf_access_be::Rf,
    pub(super) prepared: &'a mut CheckedPrepared,
    pub(super) device: narf_bus::DeviceId,
    pub(super) thermal_trim: [i8; 2],
    pub(super) mac1: &'a mut super::be_mac1::Window,
    pub(super) coex: Option<&'a mut super::be_coex::Owner>,
}
impl Port<'_> {
    pub(super) async fn prepare_wlan_coex(
        &mut self,
        protocol: super::be_coex::Protocol,
        rfe: u8,
        cv: u8,
        acv: u8,
        nss: (u8, u8),
    ) -> Result<(), rfk::Error> {
        self.active()?;
        if !self.io.qualification.wlan() {
            return Err(rfk::Error::Policy);
        }
        let owner = self.coex.take().ok_or(rfk::Error::Policy)?;
        // SAFETY: actual original retained WLAN-only producer and separately
        // selected N22W grant. It stays Busy in the original Radio if this
        // future is dropped while lending the concrete port for effects.
        let result = unsafe { owner.prepare(self, protocol, rfe, cv, acv, nss).await };
        self.coex = Some(owner);
        if result.is_err() {
            self.prepared.poison_radio();
        }
        result
    }
    fn finish<T>(&mut self, result: Result<T, power::Error>) -> Result<T, rfk::Error> {
        if result.is_err() {
            self.prepared.poison_radio();
        }
        result.map_err(Into::into)
    }
    fn active(&mut self) -> Result<(), rfk::Error> {
        let result = self
            .prepared
            .partial_radio_ready()
            .and_then(|()| self.io.current());
        self.finish(result)
    }
    fn control(
        &mut self,
        cat: u8,
        class: u8,
        func: u8,
        payload: &[u8],
        expected: Option<ReportKind>,
    ) -> Result<(), rfk::Error> {
        self.control_flags(cat, class, func, payload, expected, false)
    }
    #[allow(clippy::too_many_arguments)]
    fn control_flags(
        &mut self,
        cat: u8,
        class: u8,
        func: u8,
        payload: &[u8],
        expected: Option<ReportKind>,
        done: bool,
    ) -> Result<(), rfk::Error> {
        self.active()?;
        let region = self.io.region;
        let cancelled = self.io.cancelled;
        let prepared = &mut self.prepared;
        let qualification = self.io.qualification;
        let result = self.io.semantic(|| {
            // SAFETY: enclosing current measured N22P scope authorizes this
            // exact bounded RF table/init-late command; original transport
            // retains all command/descriptor/RX maps and its report identity.
            unsafe {
                prepared.send_h2c_scoped(
                    region,
                    cancelled,
                    super::fwcmd_8922a::H2cCmd { cat, class, func },
                    payload,
                    expected,
                    qualification,
                    done,
                )
            }
            .map(|_| ())
            .map_err(|_| power::Error::Access)
        });
        self.finish(result)
    }
}
impl Io for Port<'_> {
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        self.io.read8(a)
    }
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        self.io.read16(a)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.io.read32(a)
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        self.io.write8(a, v)
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), power::Error> {
        self.io.write16(a, v)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.io.write32(a, v)
    }
    fn now_us(&self) -> u64 {
        self.io.now_us()
    }
    async fn delay_us(&mut self, us: u64) {
        self.io.delay_us(us).await;
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        self.io.read_ecv().await
    }
}
impl super::phy_operating::Interface for Port<'_> {
    fn admit(&mut self) -> Result<(), rfk::Error> {
        self.active()
    }
    async fn xtal_read(&mut self, address: u8) -> Result<u8, rfk::Error> {
        self.active()?;
        self.io.xtal(address, 0, 0, true).await
    }
    async fn xtal_write(&mut self, address: u8, value: u8, mask: u8) -> Result<(), rfk::Error> {
        self.active()?;
        self.io.xtal(address, value, mask, false).await.map(|_| ())
    }
}
impl super::phy_operating_be::Interface for Port<'_> {
    fn mac1_ul_power(&mut self) -> Result<(), rfk::Error> {
        self.active()?;
        // SAFETY: retained original synchronous power-window owner. Its
        // concrete interface requires the separate current N22W permission
        // and restricts common power on any uncertainty before returning.
        let result = unsafe { self.mac1.program(&mut self.io) };
        self.finish(result)
    }
    async fn thermal(&mut self, path: u8) -> Result<super::phy_operating_be::Thermal, rfk::Error> {
        let threshold = be_qualification::thermal_threshold(self.device);
        let trim = self.thermal_trim;
        super::phy_operating_be::source_thermal(self, path, threshold, trim).await
    }
}
impl super::radio_init::Interface for Port<'_> {
    async fn radio_write(
        &mut self,
        path: u8,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), super::radio_init::Error> {
        self.active()
            .map_err(|_| super::radio_init::Error::Profile)?;
        // SAFETY: exact current N22P measured RF-v2 program, original owner
        // and complete BAR. Every actual RF suboperation uses Registers.
        unsafe {
            self.rf
                .write(&mut self.io, path, address, mask, value)
                .await
        }
        .map_err(Into::into)
    }
    async fn radio_page(
        &mut self,
        path: u8,
        page: u8,
        bytes: &[u8],
    ) -> Result<(), super::radio_init::Error> {
        if path > 1 || page >= 3 || bytes.is_empty() || bytes.len() > 2000 || bytes.len() % 4 != 0 {
            return Err(super::radio_init::Error::Profile);
        }
        self.control(2, 8 + path, page, bytes, None)
            .map_err(|_| super::radio_init::Error::Profile)
    }
}
impl rfk::Interface for Port<'_> {
    fn admit(&mut self) -> Result<(), rfk::Error> {
        self.active()
    }
    async fn rf_read(&mut self, path: u8, address: u32, mask: u32) -> Result<u32, rfk::Error> {
        self.active()?;
        // SAFETY: exact original qualified partial RF-v2 owner, current
        // signed+Bus authority independently surrounds every Io operation.
        let result = unsafe { self.rf.read(&mut self.io, path, address, mask).await };
        self.finish(result)
    }
    async fn rf_write(
        &mut self,
        path: u8,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), rfk::Error> {
        self.active()?;
        // SAFETY: same original qualified RF-v2/retained DMA contract as read.
        let result = unsafe {
            self.rf
                .write(&mut self.io, path, address, mask, value)
                .await
        };
        self.finish(result)
    }
    async fn begin(&mut self, _: rfk::Kind) -> Result<(), rfk::Error> {
        Err(rfk::Error::Policy)
    }
    async fn end(&mut self, _: rfk::Kind) -> Result<(), rfk::Error> {
        Err(rfk::Error::Policy)
    }
    async fn pause(&mut self) -> Result<u32, rfk::Error> {
        self.active()?;
        let region = self.io.region;
        let cancel = self.io.cancelled;
        let prepared = &mut self.prepared;
        let qualification = self.io.qualification;
        let result = self.io.semantic(|| {
            prepared
                .scheduler_scoped(region, cancel, None, qualification)
                .map_err(|_| power::Error::Access)
        });
        self.finish(result)
    }
    async fn resume(&mut self, saved: u32) -> Result<(), rfk::Error> {
        self.active()?;
        let region = self.io.region;
        let cancel = self.io.cancelled;
        let prepared = &mut self.prepared;
        let qualification = self.io.qualification;
        let result = self.io.semantic(|| {
            prepared
                .scheduler_scoped(region, cancel, Some(saved), qualification)
                .map(|_| ())
                .map_err(|_| power::Error::Access)
        });
        self.finish(result)
    }
    async fn coex_switch_band(&mut self) -> Result<(), rfk::Error> {
        self.active()?;
        let owner = self.coex.take().ok_or(rfk::Error::Policy)?;
        let result = owner.notify(self, None).await;
        self.coex = Some(owner);
        if result.is_err() {
            self.prepared.poison_radio();
        }
        result
    }
    async fn coex_rfk(&mut self, start: bool) -> Result<(), rfk::Error> {
        self.active()?;
        let owner = self.coex.take().ok_or(rfk::Error::Policy)?;
        let result = owner.notify(self, Some(start)).await;
        self.coex = Some(owner);
        if result.is_err() {
            self.prepared.poison_radio();
        }
        result
    }
    async fn h2c(
        &mut self,
        cat: u8,
        class: u8,
        func: u8,
        payload: &[u8],
    ) -> Result<(), rfk::Error> {
        let wlan = self.io.qualification.wlan()
            && self
                .coex
                .as_ref()
                .is_some_and(|owner| owner.state() == super::be_coex::State::WlanOnly);
        // N22P's command set stays sealed. Channel RFK requires both the
        // separate N22W grant and completed retained WLAN-only producer.
        let expected = match (cat, class, func) {
            (2, 11, 8) => Some(ReportKind::PreNtfy),
            (2, 11, 5) => Some(ReportKind::Dack),
            (2, 11, 6) => Some(ReportKind::RxDck),
            (2, 10, 15) => None,
            (2, 11, 4) if wlan => Some(ReportKind::Txgapk),
            (2, 11, 1) if wlan => Some(ReportKind::Iqk),
            (2, 11, 0) if wlan => Some(ReportKind::Tssi),
            (2, 11, 3) if wlan => Some(ReportKind::Dpk),
            _ => return Err(rfk::Error::Policy),
        };
        self.control(cat, class, func, payload, expected)
    }
    async fn await_rfk_report(
        &mut self,
        timeout_ms: u64,
    ) -> Result<rfk::be_rfk::Report, rfk::Error> {
        self.active()?;
        let kind = self.prepared.pending_rfk().ok_or(rfk::Error::Terminal)?;
        let region = self.io.region;
        let cancelled = self.io.cancelled;
        let prepared = &mut self.prepared;
        let qualification = self.io.qualification;
        let result = self.io.semantic(|| {
            prepared
                .await_rfk_report_scoped(region, cancelled, kind, timeout_ms, qualification)
                .map_err(|_| power::Error::Access)
        });
        self.finish(result)
    }
}
impl super::be_coex::Interface for Port<'_> {
    async fn coex_command(
        &mut self,
        function: u8,
        body: &[u8],
        done: bool,
    ) -> Result<(), rfk::Error> {
        if !self.io.qualification.wlan() || !matches!((function, done), (5, false) | (1 | 3, true))
        {
            return Err(rfk::Error::Policy);
        }
        self.control_flags(2, 0x10, function, body, None, done)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "native_radio_be_io_tests.rs"]
mod tests;

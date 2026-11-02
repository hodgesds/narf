// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! One actual retained Native's independent PS publication/receipt adapter.
use super::*;
use crate::rtw89::{
    lps::{self, Binding},
    lps_wire, power, rx_packet,
};
use alloc::{collections::VecDeque, vec::Vec};
impl Native {
    pub(in crate::rtw89) fn sleep_profile(
        &self,
    ) -> Result<Option<lps_wire::Profile>, power::Error> {
        self.ordinary_current()?;
        self.ordinary
            .as_ref()
            .ok_or(power::Error::Access)?
            .qualification
            .sleep_profile()
            .map_err(|_| power::Error::Access)
    }
    pub(in crate::rtw89) fn sleep_peer(
        &self,
    ) -> Result<crate::rtw89::station_control::Peer, power::Error> {
        self.ordinary_current()?;
        self.station_runtime
            .peer
            .clone()
            .ok_or(power::Error::Terminal)
    }
    pub(in crate::rtw89) fn sleep_block(&mut self, blocked: bool) {
        self.sleep_blocked = blocked;
    }
    pub(in crate::rtw89) fn sleeping(&self) -> bool {
        self.sleep_blocked
    }
    pub(super) fn sleep_current(&self, binding: &Binding) -> Result<(), power::Error> {
        binding.current()?;
        crate::rtw88::pci_park::invoke(&self.authority, || ()).map_err(|_| power::Error::Access)?;
        if self.sleep_reset.is_some()
            || self.sleep_profile()?.is_none()
            || self
                .station_runtime
                .peer
                .as_ref()
                .is_none_or(|peer| !binding.matches_peer(peer))
        {
            return Err(power::Error::Access);
        }
        Ok(())
    }
    fn sleep_with<T>(
        &mut self,
        binding: &Binding,
        operation: impl FnOnce(&mut Self) -> Result<T, power::Error>,
    ) -> Result<T, power::Error> {
        self.sleep_current(binding)?;
        binding.run(|| {
            self.with_ordinary_current(|native| {
                native.sleep_current(binding)?;
                operation(native)
            })
        })
    }
    pub(in crate::rtw89) fn sleep_port(&mut self) -> Port<'_> {
        Port(self)
    }
    /// Full actual RX prefix, including dropped/partial descriptors, before a
    /// fresh offload request. Never relabel an already queued response as new.
    pub(super) fn sleep_prefix(&mut self, binding: &Binding) -> Result<Option<bool>, power::Error> {
        let mut saw = false;
        for _ in 0..=usize::from(self.depth) * 2 {
            self.sleep_current(binding)?;
            let batch = self
                .rx_hardware_step(32)
                .map_err(|_| power::Error::Access)?;
            for event in batch.events {
                saw = true;
                self.retain_event(event)?;
            }
            if !batch.consumed {
                return Ok((!self.receive.assembling()).then_some(!saw));
            }
        }
        Ok(None)
    }
    /// RF grants can die while firmware owns autonomous NULL/PS-Poll. A
    /// current device grant may reset quietly; it cannot borrow a dead RF
    /// grant to issue a NULL-emitting wake/leave. All mappings remain pinned.
    pub(in crate::rtw89) async fn sleep_reset_terminal(&mut self) -> Result<(), power::Error> {
        self.state = State::Terminal;
        self.sleep_blocked = true;
        self.dma_idle = None;
        if self.sleep_reset.is_none() {
            // Release the retained IRQ binding BEFORE the reset quarantine.
            self.irq_release();
            // SAFETY: same retained exclusively reserved PCI function; State
            // is terminal, IRQ released, and all published DMA remains owned.
            let reset =
                unsafe { crate::rtw89::pci_reset::Reset::claim(self.device, self.authority) }
                    .map_err(|_| power::Error::Access)?
                    .repeat();
            self.sleep_reset = Some(reset); // retained BEFORE first await
        }
        let reset = self.sleep_reset.as_mut().ok_or(power::Error::Terminal)?;
        if reset.phase() != crate::rtw89::pci_reset::Phase::New {
            return Err(power::Error::Terminal);
        }
        let fence = reset.run().await.map_err(|_| power::Error::Terminal)?;
        // Consume only the actual same-function temporal FLR receipt for old
        // DMA retirement; this never reopens ordinary RF or an old namespace.
        self.release_reset_fenced(fence)?;
        Ok(())
    }
}
pub(in crate::rtw89) struct Port<'a>(&'a mut Native);
// SAFETY: borrows the same Native, sealed live profile and physical peer;
// each actual MMIO/H2C transaction encloses original fixed Binding plus exact
// full current device/base/optional joint programs, including after waits.
unsafe impl lps::Io for Port<'_> {
    fn block(&mut self, blocked: bool) {
        self.0.sleep_block(blocked);
    }
    async fn coex(&mut self, binding: &Binding, enter: bool) -> Result<(), power::Error> {
        self.current(binding)?;
        self.0.sleep_with(binding, |native| {
            let old = native.io.read32(0xac)?;
            if old == u32::MAX {
                return Err(power::Error::Gone);
            }
            let lower = if enter {
                old & 0xffffff & !2
            } else {
                old & 0xffffff | 0x4003
            };
            native
                .io
                .write32(0xac, (old & 0x7e000000) | 0x81000000 | lower)
        })?;
        self.0.io.delay_us(1000).await;
        self.current(binding)?;
        // This admitted program keeps WONLY/OFF_BT throughout LPS; no BT/PTA
        // producer may retarget it. Clock-gated restore must retain the exact
        // original fixed grant and CMAC selection. Verify, never invent RF.
        let start = self.0.io.now_us();
        loop {
            let ready = self
                .0
                .sleep_with(binding, |native| native.io.read8(0xdaf3))?;
            if ready & 32 != 0 {
                break;
            }
            if self.0.io.now_us().saturating_sub(start) >= 50_000 {
                return Err(power::Error::Timeout);
            }
            self.0.io.delay_us(50).await;
        }
        self.0.sleep_with(binding, |native| {
            native.io.write32(0xdaf0, 0x800f0038)?;
            if native.io.read32(0xdaf8)? != 0x77007700
                || native.io.read8(0x73)? & 4 == 0
                || native.io.read16(0xc67c)? != 0x111
            {
                return Err(power::Error::Access);
            }
            Ok(())
        })?;
        let version = self.0.sleep_profile()?.ok_or(power::Error::Access)?.version;
        let protocol = crate::rtw89::coex_native::Protocol::for_version(version)
            .ok_or(power::Error::Unsupported)?;
        self.0
            .runtime_command(
                2,
                0x10,
                3,
                &protocol.off_policy(),
                true,
                station::Permit::Sleep(binding),
            )
            .await
    }
    async fn reset(&mut self) -> Result<(), power::Error> {
        self.0.sleep_reset_terminal().await
    }
    fn current(&mut self, binding: &Binding) -> Result<(), power::Error> {
        self.0.sleep_current(binding)
    }
    fn pending(&mut self, binding: &Binding) -> Result<bool, power::Error> {
        self.0.sleep_with(binding, |native| {
            // Actual HCI IRQ receipts are consumed without an RF wake. B
            // keeps this register/ring geometry accessible while gated.
            let events = native.irq_service()?;
            if events.fatal() || events.stuck || events.rx_unavailable {
                return Err(power::Error::Terminal);
            }
            let pending = !native.station_runtime.backlog.is_empty()
                || native.queue.pending() != 0
                || native
                    .receive
                    .pending(&mut native.io)
                    .map_err(|_| power::Error::Access)?;
            native.irq_rearm()?;
            native.sleep_current(binding)?;
            Ok(pending)
        })
    }
    fn idle(&mut self, binding: &Binding) -> Result<bool, power::Error> {
        self.current(binding)?;
        self.0.poll().map_err(|_| power::Error::Access)?;
        if self.0.queue.pending() != 0
            || self
                .0
                .station_runtime
                .core
                .as_ref()
                .is_none_or(|core| !core.ready())
            || !self.0.station_runtime.backlog.is_empty()
        {
            return Ok(false);
        }
        Ok(self.0.sleep_prefix(binding)?.unwrap_or(false))
    }
    async fn packet(
        &mut self,
        binding: &Binding,
        body: &[u8],
        id: u8,
        operation: u8,
    ) -> Result<Vec<u8>, power::Error> {
        self.current(binding)?;
        if self.0.sleep_prefix(binding)?.is_none() {
            return Err(power::Error::Timeout);
        }
        // Drop only obsolete offload responses, before actual new publication.
        self.0.station_runtime.backlog.retain(|event| !matches!(event,rx_packet::Event::Firmware(m) if (m.category,m.class,m.function)==(1,1,2)));
        self.0
            .runtime_command(1, 9, 1, body, true, station::Permit::Sleep(binding))
            .await?;
        let start = self.0.io.now_us();
        loop {
            self.current(binding)?;
            let mut response = None;
            let mut remaining = VecDeque::new();
            while let Some(event) = self.0.station_runtime.backlog.pop_front() {
                match event {
                    rx_packet::Event::Firmware(message)
                        if (message.category, message.class, message.function) == (1, 1, 2)
                            && lps_wire::packet_response(&message.bytes, id, operation) =>
                    {
                        if response.replace(message.bytes).is_some() {
                            return Err(power::Error::Access);
                        }
                    }
                    other => remaining.push_back(other),
                }
            }
            self.0.station_runtime.backlog = remaining;
            if let Some(response) = response {
                self.current(binding)?;
                return Ok(response);
            }
            if self.0.io.now_us().saturating_sub(start) >= 400_000 {
                return Err(power::Error::Timeout);
            }
            self.0.io.delay_us(50).await;
            self.current(binding)?;
            self.0.poll().map_err(|_| power::Error::Access)?;
            let batch = self
                .0
                .rx_hardware_step(32)
                .map_err(|_| power::Error::Access)?;
            for event in batch.events {
                self.0.retain_event(event)?;
            }
        }
    }
    async fn command(
        &mut self,
        binding: &Binding,
        class: u8,
        function: u8,
        body: &[u8],
        done: bool,
    ) -> Result<(), power::Error> {
        let permit = if (class, function) == (2, 0) && body == lps_wire::parameters(true) {
            station::Permit::SleepEnter(binding)
        } else {
            station::Permit::Sleep(binding)
        };
        self.0
            .runtime_command(1, class, function, body, done, permit)
            .await
    }
    fn read16(&mut self, binding: &Binding, address: u32) -> Result<u16, power::Error> {
        if !matches!(address, 0x1e4 | 0x8170) {
            return Err(power::Error::Access);
        }
        self.0
            .sleep_with(binding, |native| native.io.read16(address))
    }
    fn read32(&mut self, binding: &Binding, address: u32) -> Result<u32, power::Error> {
        if !matches!(address, 0x1e8 | 0xca0c) {
            return Err(power::Error::Access);
        }
        self.0
            .sleep_with(binding, |native| native.io.read32(address))
    }
    fn write16(&mut self, binding: &Binding, address: u32, value: u16) -> Result<(), power::Error> {
        if address != 0x10c0 {
            return Err(power::Error::Access);
        }
        self.0
            .sleep_with(binding, |native| native.io.write16(address, value))
    }
    fn now_us(&self) -> u64 {
        self.0.io.now_us()
    }
    async fn delay_us(&mut self, us: u64) {
        self.0.io.delay_us(us).await;
    }
    fn restore(&mut self, binding: &Binding) -> Result<(), power::Error> {
        self.0.sleep_with(binding, |native| {
            if native.io.read32(0x1e8)? & 0x80000000 != 0 {
                return Err(power::Error::Terminal);
            }
            crate::rtw89::phy_operating::restore_physts(&mut native.io)?;
            crate::rtw89::track::restore_environment(&mut RestorePort(&mut native.io))
        })
    }
}
struct RestorePort<'a>(&'a mut NativeIo);
impl crate::rtw89::track::Hw for RestorePort<'_> {
    fn read(&mut self, address: u32) -> Result<u32, power::Error> {
        if !crate::rtw89::track::REGISTERS.contains(&address) {
            return Err(power::Error::Access);
        }
        self.0.read32(address)
    }
    fn write(&mut self, address: u32, value: u32) -> Result<(), power::Error> {
        if !crate::rtw89::track::REGISTERS.contains(&address) {
            return Err(power::Error::Access);
        }
        self.0.write32(address, value)
    }
    fn profile(&mut self) -> Result<crate::rtw89::track::Profile, power::Error> {
        Err(power::Error::Unsupported)
    }
    async fn crystal(&mut self, _: u8) -> Result<u8, power::Error> {
        Err(power::Error::Unsupported)
    }
}

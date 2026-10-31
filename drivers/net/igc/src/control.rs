//! IGC control plane. Linux reference: igc_ethtool.c/igc_main.c at ecd997b0189a.
use super::*;
use narf_net::nic::{Diagnostic, NicControl, Settings, Statistic};

impl Igc {
    fn publish_pools(&self) {
        let mut pools = Vec::new();
        for _ in 0..self.num_queues() {
            let pool = Arc::new(narf_io::pool::DmaPool::new(MAX_TSO, DomainId::DRIVER_0, 8));
            let _ = pool.prefill(8);
            pools.push(pool);
        }
        narf_net::iface::enable_zero_copy_tx_context(
            self.name(),
            self.cookie,
            send_owned,
            pools,
            0,
            true,
        );
    }
    pub fn change_settings(&self, settings: Settings) -> Result<(), i32> {
        settings.validate(4, matches!(self.device.id.device, IGC_I220_V | IGC_I221_V))?;
        let _control = self.control().map_err(|_| 16)?;
        crate::traffic::validate_flows(
            &self.flows.lock(),
            usize::from(settings.channels),
            self.config.lock().unicast.len(),
        )?;
        crate::traffic::Schedule::validate(
            self.schedule.lock().config.clone(),
            usize::from(settings.channels),
            0,
        )?;
        if self.queues().iter().any(|q| q.busy_umem()) {
            return Err(16);
        }
        let old = self.settings.lock().clone();
        let old_queues = self.queues();
        let resize = old.channels != settings.channels
            || old.rx_entries != settings.rx_entries
            || old.tx_entries != settings.tx_entries;
        let replacement = if resize {
            let mut queues = Vec::new();
            for _ in 0..settings.channels {
                let q =
                    Queue::new_sized(settings.tx_entries as usize, settings.rx_entries as usize)
                        .map_err(|_| 12)?;
                q.set_owner(self.name());
                queues.push(Arc::new(q));
            }
            Some(Arc::new(queues))
        } else {
            None
        };
        let running = self.ready();
        if running {
            self.stop().map_err(|_| 5)?;
        } else if self.state.load(Ordering::Acquire) != ADMIN_DOWN {
            return Err(16);
        }
        self.quarantine.lock().push(old_queues.clone());
        if let Some(q) = replacement {
            *self.queues.lock() = q;
        }
        *self.settings.lock() = settings;
        let result = self.reset_and_start();
        if result.is_err() {
            self.quarantine.lock().push(self.queues());
            *self.queues.lock() = old_queues;
            *self.settings.lock() = old;
            return Err(5);
        }
        // The reset fence makes every prior queue set safe to release.
        self.quarantine.lock().clear();
        if resize {
            {
                let mut history = self.queue_history.lock();
                for (q, queue) in old_queues.iter().enumerate() {
                    let values = queue.statistics();
                    for (i, v) in values.into_iter().enumerate() {
                        if i != 4 {
                            history[q][i] += v;
                        }
                    }
                }
            }
            self.publish_pools();
        }
        if !running {
            self.stop().map_err(|_| 5)?;
            self.state.store(ADMIN_DOWN, Ordering::Release);
        }
        Ok(())
    }
    pub fn request_admin(&self, up: bool) {
        self.admin_up.store(up, Ordering::Release);
    }
    pub(super) fn maintain_admin(&self) {
        let desired = self.admin_up.load(Ordering::Acquire);
        if !desired && self.ready() {
            if let Ok(_control) = self.control() {
                if self.stop().is_ok() {
                    self.state.store(ADMIN_DOWN, Ordering::Release);
                }
            }
        } else if desired && self.state.load(Ordering::Acquire) == ADMIN_DOWN {
            if let Ok(_control) = self.control() {
                let _ = self.reset_and_start();
            }
        }
    }
    pub fn remove(&self) {
        if self.removed.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut fenced = false;
        if let Ok(_control) = self.control() {
            self.state.store(CHANGING, Ordering::SeqCst);
            if self
                .hw
                .wait(100_000, || self.active.load(Ordering::SeqCst) == 0)
            {
                fenced = hardware::quiesce(&self.hw, self.num_queues()).is_ok();
                if fenced {
                    if let Some(table) = self.msix.lock().as_mut() {
                        // SAFETY: DMA and interrupt sources are stopped.
                        unsafe {
                            table.disable();
                        }
                    }
                }
            }
        }
        self.state.store(REMOVED, Ordering::Release);
        self.cancel_timestamps(19);
        for r in &self.irq_routes {
            *ISR_HW[r.vector as usize].lock() = None;
            narf_interrupts::dispatch::remove_handler(r.vector, "igc", u64::from(r.vector));
            narf_interrupts::synchronize_irq(r.vector);
            if fenced {
                let _ = narf_interrupts::vector::free(r.vector);
            }
        }
        self.tx_ipc_ring.lock().take();
        self.rx_ipc_ring.lock().take();
        for q in 0..self.num_queues() {
            narf_net::bypass::classifier::release_native(self.name(), q as u32);
        }
        if fenced {
            // SAFETY: acknowledged master drain above; these leases may now end.
            for queue in self.queues().iter() {
                // SAFETY: the device-wide drain above completed before lease release.
                unsafe {
                    queue.bind_xsk(None);
                    queue.reset_after_quiesce();
                }
            }
            self.quarantine.lock().clear();
            RETAINED.lock().retain(|c| c.cookie != self.cookie);
        }
        crate::publish::clear_rx_mirror_attached(self.name());
        let index = self.phc_index.swap(-1, Ordering::AcqRel);
        if index >= 0 {
            narf_time::phc::unregister(index as u32);
        }
        narf_net::registry().unregister(self.name());
        narf_net::iface::unregister(self.name());
        narf_power::device_pm::unregister_device_pm(self.name());
        narf_bus::pcie_recovery::unregister_error_callback(self.device.addr);
    }
}

impl NicControl for Igc {
    fn settings(&self) -> Result<Settings, i32> {
        Ok(self.settings.lock().clone())
    }
    fn set_settings(&self, s: Settings) -> Result<(), i32> {
        self.change_settings(s)
    }
    fn eee_status(&self) -> Result<narf_net::nic::EeeStatus, i32> {
        let _control = self.control().map_err(|_| 16)?;
        let _op = self.clock_operation()?;
        hardware::eee_status(&self.hw).map_err(|_| 5)
    }
    fn statistics(&self) -> Result<Vec<Statistic>, i32> {
        let _control = self.control().map_err(|_| 16)?;
        let s = self.stats();
        let mut out = self.counters.lock().snapshot();
        for (name, value) in [
            ("rx_packets", s.rx_packets),
            ("tx_packets", s.tx_packets),
            ("rx_bytes", s.rx_bytes),
            ("tx_bytes", s.tx_bytes),
            ("rx_crc_errors", s.crc_errors),
            ("rx_missed_errors", s.missed_packets),
            ("rx_dropped", s.rx_drops),
            ("tx_rejected", s.tx_rejected),
            ("resets", s.resets),
            ("tx_hwtstamp_timeouts", self.ptp.lock().timeouts),
        ] {
            out.push(Statistic {
                name: alloc::string::String::from(name),
                value,
            });
        }
        let history = *self.queue_history.lock();
        let queues = self.queues();
        for (q, retired) in history.iter().enumerate() {
            let mut values = queues.get(q).map_or([0; 8], |q| q.statistics());
            for (i, value) in values.iter_mut().enumerate() {
                if i != 4 {
                    *value += retired[i];
                }
            }
            for (name, value) in [
                "tx_submitted",
                "tx_completed",
                "tx_bytes",
                "tx_rejected",
                "tx_pending",
                "rx_packets",
                "rx_bytes",
                "rx_dropped",
            ]
            .into_iter()
            .zip(values)
            {
                out.push(Statistic {
                    name: alloc::format!("queue_{q}_{name}"),
                    value,
                });
            }
        }
        Ok(out)
    }
    fn registers(&self) -> Result<Vec<u32>, i32> {
        let _operation = self.clock_operation()?;
        // Interrupt and statistics registers are intentionally excluded:
        // reading a diagnostic snapshot must not acknowledge/clear them.
        let mut out = Vec::new();
        for reg in [
            0, 8, 0x10, 0x18, 0x100, 0x400, 0xe14, 0xe30, 0xe38, 0x5000, 0x5004, 0x5818,
        ] {
            out.push(self.hw.read(reg));
        }
        for q in 0..self.num_queues() {
            for base in [0xc000, 0xe000] {
                for off in [0, 4, 8, 0x10, 0x18, 0x28] {
                    out.push(self.hw.read(base + q as u64 * 0x40 + off));
                }
            }
        }
        Ok(out)
    }
    fn nvm_info(&self) -> Result<(u32, u32), i32> {
        let _op = self.clock_operation()?;
        let size = 2u32 << (((self.hw.read(0x10) & 0x7800) >> 11) + 6).min(15);
        Ok((0x8086 | (u32::from(self.device.id.device) << 16), size))
    }
    fn supported_link_modes(&self) -> u32 {
        if matches!(self.device.id.device, IGC_I220_V | IGC_I221_V) {
            0x1f
        } else {
            0x3f
        }
    }
    fn nvm(&self, offset: u32, len: u32) -> Result<Vec<u8>, i32> {
        let _control = self.control().map_err(|_| 16)?;
        let _operation = self.clock_operation()?;
        hardware::read_nvm(&self.hw, offset, len).map_err(|e| {
            if e == IgcError::Other("NVM range") {
                22
            } else {
                5
            }
        })
    }
    fn diagnostics(&self, offline: bool) -> Result<Vec<Diagnostic>, i32> {
        if offline {
            self.recover().map_err(|_| 5)?;
        }
        let _control = self.control().map_err(|_| 16)?;
        let _op = self.operation().map_err(|_| 19)?;
        let mac = hardware::read_mac(&self.hw).map_err(|_| 5)?;
        let checksum = hardware::read_nvm(&self.hw, 0, 128)
            .map(|bytes| {
                bytes.chunks_exact(2).fold(0u16, |sum, b| {
                    sum.wrapping_add(u16::from_le_bytes([b[0], b[1]]))
                }) == 0xbaba
            })
            .unwrap_or(false);
        Ok(alloc::vec![
            Diagnostic {
                name: "register_access",
                passed: self.hw.read(8) != u32::MAX
            },
            Diagnostic {
                name: "nvm_checksum",
                passed: checksum
            },
            Diagnostic {
                name: "unicast_address",
                passed: hardware::valid_mac(mac)
            },
            Diagnostic {
                name: "queue_configuration",
                passed: self.queues().iter().enumerate().all(|(q, _)| self
                    .hw
                    .read(0xc028 + q as u64 * 0x40)
                    & (1 << 25)
                    != 0
                    && self.hw.read(0xe028 + q as u64 * 0x40) & (1 << 25) != 0)
            }
        ])
    }
    fn restart_link(&self) -> Result<(), i32> {
        self.recover().map_err(|_| 5)
    }
    fn clock_index(&self) -> i32 {
        self.phc_index.load(Ordering::Acquire)
    }
    fn clock_get(&self) -> Result<u64, i32> {
        let _op = self.clock_operation()?;
        let _p = self.ptp.lock();
        crate::ptp::read(&self.hw).map_err(|_| 19)
    }
    fn clock_set(&self, ns: u64) -> Result<(), i32> {
        if self.schedule.lock().active() {
            return Err(16);
        }
        let _control = self.control().map_err(|_| 16)?;
        let _op = self.clock_operation()?;
        let mut p = self.ptp.lock();
        crate::ptp::write(&self.hw, ns).map_err(|_| 22)?;
        p.saved = Some((ns, narf_time::monotonic_ns()));
        Ok(())
    }
    fn clock_adjust(&self, delta: i64, ppb: i32) -> Result<(), i32> {
        if delta != 0 && self.schedule.lock().active() {
            return Err(16);
        }
        let _control = self.control().map_err(|_| 16)?;
        let _op = self.clock_operation()?;
        let mut p = self.ptp.lock();
        if ppb.unsigned_abs() > 62_499_999 {
            return Err(34);
        }
        if delta == 0 {
            crate::ptp::frequency(&self.hw, ppb).map_err(|_| 34)?;
            p.ppb = ppb;
            return Ok(());
        }
        let old = crate::ptp::read(&self.hw).map_err(|_| 19)?;
        let next = (i128::from(old) + i128::from(delta))
            .try_into()
            .map_err(|_| 22)?;
        crate::ptp::write(&self.hw, next).map_err(|_| 22)?;
        crate::ptp::frequency(&self.hw, ppb).map_err(|_| 34)?;
        p.ppb = ppb;
        p.saved = Some((next, narf_time::monotonic_ns()));
        Ok(())
    }
    fn timestamp_config(&self) -> Result<narf_net::nic::TimestampConfig, i32> {
        Ok(self.ptp.lock().config)
    }
    fn timestamps(&self, config: narf_net::nic::TimestampConfig) -> Result<(), i32> {
        let _control = self.control().map_err(|_| 16)?;
        let _op = self.clock_operation()?;
        let mut p = self.ptp.lock();
        if (config.rx && self.queues().iter().any(|q| q.xsk().is_some()))
            || p.quarantined != 0
            || p.pending.iter().any(Option::is_some)
        {
            return Err(16);
        }
        crate::ptp::configure(&self.hw, self.num_queues(), config);
        p.config = config;
        Ok(())
    }
    fn take_timestamp(&self) -> Result<Option<narf_net::nic::Timestamp>, i32> {
        Ok(self.ptp.lock().events.pop_front())
    }
    fn schedule(&self, config: narf_net::nic::TrafficSchedule) -> Result<(), i32> {
        let _control = self.control().map_err(|_| 16)?;
        if self.mtu() > 1500 {
            return Err(22);
        }
        let schedule =
            crate::traffic::Schedule::validate(config, self.num_queues(), self.clock_get()?)?;
        self.stop().map_err(|_| 16)?;
        *self.schedule.lock() = schedule;
        self.reset_and_start().map_err(|_| 5)
    }
    fn traffic_schedule(&self) -> Result<narf_net::nic::TrafficSchedule, i32> {
        Ok(self.schedule.lock().config.clone())
    }
    fn preemption(
        &self,
    ) -> Result<(narf_net::nic::Preemption, narf_net::nic::PreemptionStatus), i32> {
        let m = self.merge.lock();
        Ok((m.config, m.status))
    }
    fn set_preemption(&self, c: narf_net::nic::Preemption) -> Result<(), i32> {
        if c.verify_ms == 0
            || c.verify_ms > 128
            || !(64..=256).contains(&c.minimum_fragment)
            || c.minimum_fragment % 64 != 0
        {
            return Err(22);
        }
        let _control = self.control().map_err(|_| 16)?;
        if self.mtu() > 1500
            || self.queues().iter().any(|q| q.xsk().is_some())
            || self.config.lock().unicast.len()
                + self
                    .flows
                    .lock()
                    .iter()
                    .filter(|f| f.destination_mac.is_some())
                    .count()
                > 14
        {
            return Err(16);
        }
        self.stop().map_err(|_| 16)?;
        self.merge.lock().config = c;
        self.reset_and_start().map_err(|_| 5)
    }
    fn flow_rules(&self) -> Result<Vec<narf_net::nic::FlowRule>, i32> {
        Ok(self.flows.lock().clone())
    }
    fn set_flow_rules(&self, rules: Vec<narf_net::nic::FlowRule>) -> Result<(), i32> {
        let _control = self.control().map_err(|_| 16)?;
        let _op = self.operation().map_err(|_| 19)?;
        crate::traffic::validate_flows(
            &rules,
            self.num_queues(),
            self.config.lock().unicast.len(),
        )?;
        *self.flows.lock() = rules;
        self.apply_filters();
        Ok(())
    }
    fn bind_xsk(
        &self,
        q: u16,
        socket: Option<Arc<narf_net::bypass::xdp::XdpSocket>>,
    ) -> Result<(), i32> {
        let _control = self.control().map_err(|_| 16)?;
        let queues = self.queues();
        let queue = queues.get(usize::from(q)).ok_or(22)?;
        if socket.is_some()
            && (self.mtu() > 1500 || self.ptp.lock().config.rx || self.merge.lock().config.enabled)
        {
            return Err(22);
        }
        self.stop().map_err(|_| 16)?;
        // SAFETY: stop acknowledged PCIe master drain; no live DMA targets.
        unsafe {
            queue.bind_xsk(socket.clone());
        }
        if self.reset_and_start().is_err() {
            // A failed restart is not a DMA fence. Retain the queue claim and
            // close the socket so recovery detaches it before restarting DMA.
            if let Some(socket) = socket {
                socket.close();
            }
            return Err(5);
        }
        Ok(())
    }
    fn runtime_suspend(&self) -> Result<(), i32> {
        narf_power::device_pm::DevicePmOps::suspend(self).map_err(|_| 16)?;
        narf_bus::pci::set_power_state(
            &self.hw.cap,
            &self.device,
            narf_bus::pci::PciPowerState::D3Hot,
        )
        .map_err(|_| 5)
    }
    fn runtime_resume(&self) -> Result<(), i32> {
        narf_power::device_pm::DevicePmOps::resume(self).map_err(|_| 5)
    }
}

impl narf_bus::pcie_recovery::ErrorCallback for Igc {
    fn error_detected(
        &self,
        _: narf_bus::pcie_recovery::PciErrSeverity,
        state: narf_bus::pcie_recovery::PciChannelState,
    ) -> narf_bus::pcie_recovery::PciErsResult {
        use narf_bus::pcie_recovery::{PciChannelState as S, PciErsResult as R};
        self.state.store(FAILED, Ordering::SeqCst);
        for r in &self.irq_routes {
            *ISR_HW[r.vector as usize].lock() = None;
        }
        match state {
            S::Normal => R::CanRecover,
            S::Frozen => R::NeedReset,
            S::PermFailure => R::Disconnect,
        }
    }
    fn slot_reset(&self) -> narf_bus::pcie_recovery::PciErsResult {
        self.recovery_requested.store(true, Ordering::Release);
        narf_bus::pcie_recovery::PciErsResult::Recovered
    }
    fn resume(&self) {
        self.recovery_requested.store(true, Ordering::Release);
    }
}

#[derive(Debug)]
pub(super) struct PhcDevice(pub alloc::sync::Weak<Igc>);
impl narf_time::phc::HardwareClock for PhcDevice {
    fn read_ns(&self) -> Result<u64, i32> {
        self.0.upgrade().ok_or(19)?.clock_get()
    }
    fn set_ns(&self, ns: u64) -> Result<(), i32> {
        self.0.upgrade().ok_or(19)?.clock_set(ns)
    }
    fn adjust(&self, delta: i64, ppb: i32) -> Result<(), i32> {
        self.0.upgrade().ok_or(19)?.clock_adjust(delta, ppb)
    }
    fn max_adjust_ppb(&self) -> u32 {
        62_499_999
    }
    fn frequency_ppb(&self) -> i32 {
        self.0.upgrade().map_or(0, |c| c.ptp.lock().ppb)
    }
}

impl Igc {
    pub(super) fn clock_operation(&self) -> Result<Operation<'_>, i32> {
        self.active.fetch_add(1, Ordering::SeqCst);
        let guard = Operation(&self.active);
        if self.removed.load(Ordering::Acquire)
            || !matches!(self.state.load(Ordering::SeqCst), RUNNING | ADMIN_DOWN)
            || self.hw.cap.invoke(Check).is_err()
        {
            return Err(19);
        }
        Ok(guard)
    }
    pub(super) fn save_clock(&self) {
        if let Ok(ns) = crate::ptp::read(&self.hw) {
            self.ptp.lock().saved = Some((ns, narf_time::monotonic_ns()));
        }
        self.cancel_timestamps(125);
    }
    pub(super) fn cancel_timestamps(&self, error: i32) {
        self.ptp.lock().cancel(error);
        self.deliver_timestamps();
    }
    pub(super) fn deliver_timestamps(&self) {
        let events = core::mem::take(&mut self.ptp.lock().events);
        for event in events {
            if !narf_net::raw_sock::complete_tx_timestamp(self.name(), event) {
                let mut clock = self.ptp.lock();
                if clock.events.len() < 256 {
                    clock.events.push_back(event);
                }
            }
        }
    }
    pub(super) fn restore_clock(&self) -> Result<(), IgcError> {
        let mut p = self.ptp.lock();
        p.quarantined = 0;
        let ns = p.saved.map_or_else(
            || {
                let wall = narf_time::now_wall();
                (wall.secs.max(0) as u64) * 1_000_000_000 + u64::from(wall.nanos)
            },
            |(clock, then)| {
                crate::ptp::advance(clock, narf_time::monotonic_ns().saturating_sub(then), p.ppb)
            },
        );
        crate::ptp::configure(&self.hw, self.num_queues(), p.config);
        crate::ptp::write(&self.hw, ns)?;
        crate::ptp::frequency(&self.hw, p.ppb)
    }
}

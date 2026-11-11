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
        // igc_ethtool_set_link_ksettings: link characteristics cannot change
        // while firmware blocks PHY reset (reset_and_start skips PHY setup).
        if (old.link != settings.link || old.pause != settings.pause || old.eee != settings.eee)
            && hardware::phy_reset_blocked(&self.hw)
        {
            return Err(22);
        }
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
        // Linux igc_ethtool_get_stats updates the hardware counters first.
        self.sample_counters();
        let s = self.stats();
        let counters = self.counters.lock();
        let mut out = counters.snapshot();
        let (timeouts, skipped) = {
            let p = self.ptp.lock();
            (p.timeouts, p.skipped)
        };
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
            ("tx_hwtstamp_timeouts", timeouts),
        ] {
            out.push(Statistic {
                name: alloc::string::String::from(name),
                value,
            });
        }
        let hw_drops = counters.drops;
        let history = *self.queue_history.lock();
        let queues = self.queues();
        let mut linux_queues = Vec::new();
        for (q, retired) in history.iter().enumerate() {
            let mut values = queues.get(q).map_or([0; 10], |q| q.statistics());
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
                "rx_csum_err",
                "rx_alloc_failed",
            ]
            .into_iter()
            .zip(values)
            {
                out.push(Statistic {
                    name: alloc::format!("queue_{q}_{name}"),
                    value,
                });
            }
            // Linux per-queue values: tx packets/bytes/restart, rx
            // packets/bytes/drops/csum_err/alloc_failed. The drops are the
            // hardware RQDPC drops, not the receive-path drops above.
            linux_queues.push([
                values[1],
                values[2],
                // Linux `tx_stats.restart_queue`: wakes of a stopped queue.
                queues.get(q).map_or(0, |q| q.txq().restarts()),
                values[5],
                values[6],
                hw_drops[q],
                values[8],
                values[9],
            ]);
        }
        out.extend(linux_stats(&counters, &s, skipped, &linux_queues));
        Ok(out)
    }
    fn registers(&self) -> Result<Vec<u32>, i32> {
        let _operation = self.clock_operation()?;
        // Linux igc_ethtool_get_stats updates the hardware counters first;
        // the dump reports the same accumulated values.
        self.sample_counters();
        let counters = self.counters.lock();
        Ok(regs_dump(&self.hw, &counters).to_vec())
    }
    fn msglevel(&self) -> Result<u32, i32> {
        Ok(*self.msglevel.lock())
    }
    fn set_msglevel(&self, level: u32) -> Result<(), i32> {
        *self.msglevel.lock() = level;
        Ok(())
    }
    fn priv_flags(&self) -> Result<u32, i32> {
        Ok(*self.priv_flags.lock())
    }
    fn set_priv_flags(&self, flags: u32) -> Result<(), i32> {
        // Linux igc_ethtool_set_priv_flags silently masks unknown bits and
        // reinitializes only when a known flag changed and the device runs.
        let _control = self.control().map_err(|_| 16)?;
        let mut current = self.priv_flags.lock();
        let next = flags & 0x3;
        if next == *current {
            return Ok(());
        }
        *current = next;
        drop(current);
        if self.ready() {
            self.stop().map_err(|_| 16)?;
            self.reset_and_start().map_err(|_| 5)?;
        }
        Ok(())
    }
    fn priv_flag_names(&self) -> &'static [&'static str] {
        &["legacy-rx", "reverse-tsn-txq-prio"]
    }
    fn rxfh_fields(&self, flow_type: u8) -> Result<u32, i32> {
        let (udp4, udp6) = *self.rss_udp.lock();
        rxfh_field_data(flow_type, udp4, udp6)
    }
    fn set_rxfh_fields(&self, flow_type: u8, data: u32) -> Result<(), i32> {
        let _control = self.control().map_err(|_| 16)?;
        let mut flags = self.rss_udp.lock();
        let (udp4, udp6) = rxfh_field_flags(flow_type, data, flags.0, flags.1)?;
        if (udp4, udp6) != *flags {
            *flags = (udp4, udp6);
            // Live MRQC rewrite (no restart), as in Linux.
            hardware::set_rss_fields(&self.hw, udp4, udp6);
        }
        Ok(())
    }
    fn mm_stats(&self) -> Result<narf_net::nic::MmStats, i32> {
        let _control = self.control().map_err(|_| 16)?;
        Ok(self.counters.lock().mm_stats())
    }
    fn registers_version(&self) -> u32 {
        // Linux igc_ethtool_get_regs: (2 << 24) | (revision << 16) | device_id.
        (2 << 24) | (u32::from(self.pci_revision) << 16) | u32::from(self.device.id.device)
    }
    fn check_coalesce(&self, rx_usecs: u32, tx_usecs: u32) -> Result<(), i32> {
        check_coalesce_usecs(rx_usecs)?;
        check_coalesce_usecs(tx_usecs)
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
    fn set_nvm(&self, magic: u32, offset: u32, data: &[u8]) -> Result<(), i32> {
        let _control = self.control().map_err(|_| 16)?;
        let _operation = self.clock_operation()?;
        // Linux igc_ethtool_set_eeprom (igc_ethtool.c:507-575): len == 0 and
        // flash-absent i225 both refuse with -EOPNOTSUPP (95); a magic other
        // than vendor | (device << 16) fails with -EFAULT (14); an
        // out-of-range write fails with -EINVAL (22).
        hardware::write_eeprom(&self.hw, magic, self.device.id.device, offset, data).map_err(|e| {
            match e {
                IgcError::Other("EEPROM empty" | "no flash") => 95,
                IgcError::Other("bad EEPROM magic") => 14,
                IgcError::Other("NVM range") => 22,
                _ => 5,
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
    fn timestamp_info(&self) -> (u32, u32, u32) {
        (0x47, 3, 3)
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
    fn permanent_mac(&self) -> Result<[u8; 6], i32> {
        Ok(self.config.lock().permanent_mac)
    }
    fn set_preemption(&self, c: narf_net::nic::Preemption) -> Result<(), i32> {
        if c.verify_ms == 0 || c.verify_ms > 128 {
            return Err(22);
        }
        // Linux `igc_ethtool_set_mm` (igc_ethtool.c:1860-1882) rounds
        // tx_min_frag_size up to a supported size instead of rejecting
        // it; the stored (rounded) value is what MM_GET reports back.
        // The genl layer already enforces the 60..=252 netlink policy
        // range, so anything reaching here rounds into 64..=256.
        let c = narf_net::nic::Preemption {
            minimum_fragment: round_min_fragment(c.minimum_fragment),
            ..c
        };
        let _control = self.control().map_err(|_| 16)?;
        if self.mtu() > 1500
            || self.queues().iter().any(|q| q.xsk().is_some())
            || self.config.lock().unicast.len()
                + self
                    .flows
                    .lock()
                    .iter()
                    .filter(|f| {
                        !crate::traffic::is_flex(f)
                            && (f.destination_mac.is_some() || f.source_mac.is_some())
                    })
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
    fn kick_xsk(&self, q: u16) -> Result<(), i32> {
        let _op = self.operation().map_err(|_| 16)?;
        let queues = self.queues();
        let queue = queues.get(usize::from(q)).ok_or(22)?;
        queue.poll_xsk(&self.hw, usize::from(q), self.mtu());
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

/// Linux `igc_fpe_get_supported_frag_size` (igc_tsn.c:441-453): the
/// smallest supported size in {64, 128, 192, 256} at or above the
/// request; anything above the largest rounds to `TX_MAX_FRAG_SIZE`
/// (256). `merge.rs` programs `minimum_fragment / 64 - 1`, so the
/// rounded value always lands on a legal fragment field.
pub(crate) fn round_min_fragment(v: u16) -> u16 {
    for size in [64u16, 128, 192, 256] {
        if v <= size {
            return size;
        }
    }
    256
}

/// Linux `igc_ethtool_set_coalesce` validation for one usecs value:
/// IGC_MIN_ITR_USECS=10, IGC_MAX_ITR_USECS=10000; 2 and 4..9 are invalid.
/// 0 disables ITR. (The shared `Settings` cap of 8388us — the EITR
/// register max — still bounds the committed value at set_settings time.)
pub(crate) fn check_coalesce_usecs(usecs: u32) -> Result<(), i32> {
    if usecs > 10_000 || usecs == 2 || (3 < usecs && usecs < 10) {
        return Err(22);
    }
    Ok(())
}

/// Linux `igc_ethtool_get_rxfh_fields`: the RSS hash fields for one flow
/// type, as RXH bits (uapi ethtool.h: IP_SRC 0x10, IP_DST 0x20, L4_B_0_1
/// 0x40, L4_B_2_3 0x80). TCP always hashes L4; UDP hashes L4 only when its
/// UDP flag is set; AH/ESP/SCTP/IP hash IP only.
pub(crate) fn rxfh_field_data(flow_type: u8, udp4: bool, udp6: bool) -> Result<u32, i32> {
    Ok(match flow_type {
        0x01 | 0x05 => 0xf0,
        0x02 => 0x30 | if udp4 { 0xc0 } else { 0 },
        0x06 => 0x30 | if udp6 { 0xc0 } else { 0 },
        0x03 | 0x04 | 0x07 | 0x08 | 0x09 | 0x0a | 0x0b | 0x0c | 0x10 | 0x11 => 0x30,
        _ => return Err(22),
    })
}

/// Linux `igc_ethtool_set_rxfh_fields` validation: returns the new UDP
/// flags. TCP requires all four bits; UDP requires the IP bits with the L4
/// bits both or neither; AH/ESP/SCTP require the IP bits and no L4 bits.
/// IP and Ethernet flows are not settable.
pub(crate) fn rxfh_field_flags(
    flow_type: u8,
    data: u32,
    udp4: bool,
    udp6: bool,
) -> Result<(bool, bool), i32> {
    if data & !0xf0 != 0 {
        return Err(22);
    }
    match flow_type {
        0x01 | 0x05 => {
            if data != 0xf0 {
                return Err(22);
            }
        }
        0x02 => {
            if data & 0x30 != 0x30 {
                return Err(22);
            }
            return Ok((
                match data & 0xc0 {
                    0 => false,
                    0xc0 => true,
                    _ => return Err(22),
                },
                udp6,
            ));
        }
        0x06 => {
            if data & 0x30 != 0x30 {
                return Err(22);
            }
            return Ok((
                udp4,
                match data & 0xc0 {
                    0 => false,
                    0xc0 => true,
                    _ => return Err(22),
                },
            ));
        }
        0x03 | 0x04 | 0x07 | 0x08 | 0x09 | 0x0a | 0x0b | 0x0c => {
            if data & 0x30 != 0x30 || data & 0xc0 != 0 {
                return Err(22);
            }
        }
        _ => return Err(22),
    }
    Ok((udp4, udp6))
}

/// Linux `igc_gstrings_stats` + `igc_gstrings_net_stats` + per-queue stats,
/// in `igc_ethtool_get_strings` order, skipping the names the caller
/// already reports. Pure over the sampled counters so tests can drive it
/// with a fake register model. Per-queue values are `[tx packets, tx bytes,
/// tx restart, rx packets, rx bytes, rx drops, rx csum_err, rx
/// alloc_failed]`; tx restart is always 0 — NARF never stops a TX ring
/// and restarts it; a full ring rejects instead.
pub(crate) fn linux_stats(
    counters: &crate::counters::Counters,
    s: &IgcStats,
    tx_hwtstamp_skipped: u64,
    per_queue: &[[u64; 8]],
) -> Vec<Statistic> {
    let mut out = Vec::new();
    for (name, value) in [
        ("rx_broadcast", counters.value(0x4078)),
        ("tx_broadcast", counters.value(0x40f4)),
        ("rx_multicast", counters.value(0x407c)),
        ("tx_multicast", counters.value(0x40f0)),
        ("multicast", counters.value(0x407c)),
        (
            "collisions",
            counters.value(0x4028) + counters.value(0x402c),
        ),
        ("rx_no_buffer_count", counters.value(0x40a0)),
        ("tx_aborted_errors", counters.value(0x4018)),
        ("tx_carrier_errors", counters.value(0x4034)),
        ("tx_window_errors", counters.value(0x4020)),
        ("tx_abort_late_coll", counters.value(0x4020)),
        ("tx_deferred_ok", counters.value(0x4030)),
        ("tx_single_coll_ok", counters.value(0x4014)),
        ("tx_multi_coll_ok", counters.value(0x401c)),
        ("tx_timeout_count", s.tx_timeouts),
        ("rx_long_length_errors", counters.value(0x40ac)),
        ("rx_short_length_errors", counters.value(0x40a4)),
        ("rx_align_errors", counters.value(0x4004)),
        ("tx_tcp_seg_good", counters.value(0x40f8)),
        // tsctfc is never assigned in Linux igc.
        ("tx_tcp_seg_failed", 0),
        ("rx_flow_control_xon", counters.value(0x4048)),
        ("rx_flow_control_xoff", counters.value(0x4050)),
        ("tx_flow_control_xon", counters.value(0x404c)),
        ("tx_flow_control_xoff", counters.value(0x4054)),
        ("rx_long_byte_count", counters.value(0x4088)),
        // doosync is only incremented on driver-detected TX DMA
        // out-of-sync events; NARF has no such detection.
        ("tx_dma_out_of_sync", 0),
        ("tx_smbus", counters.value(0x40bc)),
        ("rx_smbus", counters.value(0x40b4)),
        ("dropped_smbus", counters.value(0x40b8)),
        // os2bmc_* are never assigned in Linux igc.
        ("os2bmc_rx_by_bmc", 0),
        ("os2bmc_tx_by_bmc", 0),
        ("os2bmc_tx_by_host", 0),
        ("os2bmc_rx_by_host", 0),
        ("tx_hwtstamp_skipped", tx_hwtstamp_skipped),
        // rx_hwtstamp_cleared is never incremented in Linux igc.
        ("rx_hwtstamp_cleared", 0),
        ("tx_lpi_counter", counters.value(0x4148)),
        ("rx_lpi_counter", counters.value(0x414c)),
        // NARF advances a past Qbv base_time to the next cycle instead of
        // erroring (Schedule::validate), so this stays 0.
        ("qbv_config_change_errors", 0),
    ] {
        out.push(Statistic {
            name: alloc::string::String::from(name),
            value,
        });
    }
    // Net stats (Linux igc_update_stats formulas; cexterr, rx_over_errors,
    // tx_fifo_errors and tx_heartbeat_errors are never assigned in Linux
    // igc, so they are 0).
    let fifo = counters.drops.iter().sum::<u64>() + counters.value(0x4010);
    for (name, value) in [
        (
            "rx_errors",
            counters.value(0x400c)
                + counters.value(0x4000)
                + counters.value(0x4004)
                + counters.value(0x40a4)
                + counters.value(0x40ac),
        ),
        ("tx_errors", counters.value(0x4018) + counters.value(0x4020)),
        // Linux tx_dropped counts max-SDU drops; the closest NARF quantity
        // is rejected TX submissions.
        ("tx_dropped", s.tx_rejected),
        (
            "rx_length_errors",
            counters.value(0x40a4) + counters.value(0x40ac),
        ),
        ("rx_over_errors", 0),
        ("rx_frame_errors", counters.value(0x4004)),
        ("rx_fifo_errors", fifo),
        ("tx_fifo_errors", 0),
        ("tx_heartbeat_errors", 0),
    ] {
        out.push(Statistic {
            name: alloc::string::String::from(name),
            value,
        });
    }
    for (q, v) in per_queue.iter().enumerate() {
        for (name, value) in [
            (alloc::format!("tx_queue_{q}_packets"), v[0]),
            (alloc::format!("tx_queue_{q}_bytes"), v[1]),
            (alloc::format!("tx_queue_{q}_restart"), v[2]),
            (alloc::format!("rx_queue_{q}_packets"), v[3]),
            (alloc::format!("rx_queue_{q}_bytes"), v[4]),
            (alloc::format!("rx_queue_{q}_drops"), v[5]),
            (alloc::format!("rx_queue_{q}_csum_err"), v[6]),
            (alloc::format!("rx_queue_{q}_alloc_failed"), v[7]),
        ] {
            out.push(Statistic { name, value });
        }
    }
    out
}

/// Linux `igc_ethtool_get_regs` (IGC_REGS_LEN=740) as a pure function over
/// the register accessor and the accumulated counters, so tests can drive it
/// with a fake register model. The dump is built by sequential writes in
/// Linux's order, reproducing the RAL/RAH overlap quirk (the second RAL/RAH
/// copies preserve the ABI). Statistics words 30..90 and 213..214 come from
/// the accumulated counters, never from a live read: the registers are
/// clear-on-read and a live read would corrupt the accumulation. The
/// interrupt-cause words use the set/shadow copies (EICS/ICS) so the
/// snapshot never acknowledges an interrupt. IAC (word 16) is the one
/// exception to a live read: it is clear-on-read and already accumulated,
/// so the dump reports the accumulated value instead of stealing it.
pub(crate) fn regs_dump(
    r: &impl crate::hardware::Registers,
    counters: &crate::counters::Counters,
) -> [u32; 740] {
    let mut out = [0u32; 740];
    // General registers.
    out[0] = r.read(0);
    out[1] = r.read(8);
    out[2] = r.read(0x18);
    out[3] = r.read(0x20);
    out[4] = r.read(0x34);
    // NVM register.
    out[5] = r.read(0x10);
    // Interrupt (EICS/ICS shadows, never clear-on-read).
    out[6] = r.read(0x1520);
    out[7] = r.read(0x1520);
    out[8] = r.read(0x1524);
    out[9] = r.read(0x1528);
    out[10] = r.read(0x152c);
    out[11] = r.read(0x1530);
    out[12] = r.read(0x1504);
    out[13] = r.read(0x1504);
    out[14] = r.read(0x1508);
    out[15] = r.read(0x150c);
    out[16] = counters.value(0x4100) as u32;
    out[17] = r.read(0x1510);
    // Flow control.
    out[18] = r.read(0x28);
    out[19] = r.read(0x2c);
    out[20] = r.read(0x170);
    out[21] = r.read(0x2160);
    out[22] = r.read(0x2168);
    out[23] = r.read(0x2460);
    // Receive / transmit.
    out[24] = r.read(0x100);
    out[25] = r.read(0x5000);
    out[26] = r.read(0x5004);
    out[27] = r.read(0x5008);
    out[28] = r.read(0x400);
    out[29] = r.read(0x410);
    // Statistics 30..90 from the accumulated counters. The 0 entries are
    // symerrs (32), sec (42), scvpc (89) and hrmpc (90): Linux
    // igc_update_stats never accumulates them, so they are always 0.
    const STAT_REGS: [u64; 61] = [
        0x4000, 0x4004, 0, 0x400c, 0x4010, 0x4014, 0x4018, 0x401c, 0x4020, 0x4028, 0x4030, 0x4034,
        0, 0x403c, 0x4040, 0x4048, 0x404c, 0x4050, 0x4054, 0x4058, 0x405c, 0x4060, 0x4064, 0x4068,
        0x406c, 0x4070, 0x4074, 0x4078, 0x407c, 0x4080, 0x4088, 0x4090, 0x40a0, 0x40a4, 0x40a8,
        0x40ac, 0x40b0, 0x40b4, 0x40b8, 0x40bc, 0x40c0, 0x40c8, 0x40d0, 0x40d4, 0x40d8, 0x40dc,
        0x40e0, 0x40e4, 0x40e8, 0x40ec, 0x40f0, 0x40f4, 0x40f8, 0x4100, 0x4104, 0x4118, 0x4128,
        0x4130, 0x4138, 0, 0,
    ];
    for (i, reg) in STAT_REGS.iter().enumerate() {
        out[30 + i] = if *reg == 0 {
            0
        } else {
            counters.value(*reg) as u32
        };
    }
    // Per-queue registers, always 4 queues in the Linux dump.
    for q in 0..4 {
        out[91 + q] = r.read(0xc00c + q as u64 * 0x40);
        out[95 + q] = r.read(0x5480 + q as u64 * 4);
        out[99 + q] = r.read(0xc000 + q as u64 * 0x40);
        out[103 + q] = r.read(0xc004 + q as u64 * 0x40);
        out[107 + q] = r.read(0xc008 + q as u64 * 0x40);
        out[111 + q] = r.read(0xc010 + q as u64 * 0x40);
        out[115 + q] = r.read(0xc018 + q as u64 * 0x40);
        out[119 + q] = r.read(0xc028 + q as u64 * 0x40);
    }
    for i in 0..10 {
        out[123 + i] = r.read(0x1680 + i as u64 * 4);
    }
    // 133..138 stay zero, as in Linux.
    for i in 0..16 {
        out[139 + i] = r.read(0x5400 + i as u64 * 8);
    }
    for i in 0..16 {
        out[145 + i] = r.read(0x5404 + i as u64 * 8);
    }
    for q in 0..4 {
        out[149 + q] = r.read(0xe000 + q as u64 * 0x40);
        out[156 + q] = r.read(0xe008 + q as u64 * 0x40);
        out[160 + q] = r.read(0xe010 + q as u64 * 0x40);
        out[164 + q] = r.read(0xe018 + q as u64 * 0x40);
        out[168 + q] = r.read(0xe028 + q as u64 * 0x40);
    }
    // Linux writes all TDBAL words before TDBAH: their legacy dump
    // slots overlap at 152 (queue 3 low / queue 0 high).
    for q in 0..4 {
        out[152 + q] = r.read(0xe004 + q as u64 * 0x40);
    }
    // Second RAL/RAH copies preserve the ABI after the overlap above.
    for i in 0..16 {
        out[172 + i] = r.read(0x5400 + i as u64 * 8);
    }
    for i in 0..16 {
        out[188 + i] = r.read(0x5404 + i as u64 * 8);
    }
    out[204] = r.read(0x55b0);
    for i in 0..8 {
        out[205 + i] = r.read(0x5cb0 + i as u64 * 4);
    }
    out[213] = counters.value(0x4148) as u32;
    out[214] = counters.value(0x414c) as u32;
    // 215..739 stay zero.
    out
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

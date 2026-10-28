use super::firmware_transport::Io;
use super::*;
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
#[derive(Clone, Debug)]
struct BlockState {
    address: u64,
    bytes: Vec<u8>,
    writes: usize,
    syncs: usize,
    acquires: usize,
    published_at: Option<usize>,
}
struct Block {
    state: Arc<IrqSafeSpinLock<BlockState>>,
    drops: Arc<AtomicUsize>,
}
impl Drop for Block {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}
// SAFETY: the sole Block is the model's CPU writer; register simulator reads
// the device-side snapshot only on doorbells. All storage is inert host bytes.
unsafe impl Memory for Block {
    fn address(&self) -> u64 {
        self.state.lock().address
    }
    fn len(&self) -> usize {
        self.state.lock().bytes.len()
    }
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        let mut state = self.state.lock();
        if state.published_at == Some(state.acquires) {
            return Err(Error::Memory);
        }
        state
            .bytes
            .get_mut(offset..offset + bytes.len())
            .ok_or(Error::Memory)?
            .copy_from_slice(bytes);
        state.writes += 1;
        Ok(())
    }
    fn sync(&self) {
        self.state.lock().syncs += 1;
    }
    fn acquire(&self) {
        self.state.lock().acquires += 1;
    }
}
struct Model {
    bytes: Vec<u8>,
    calls: usize,
    fail: Option<usize>,
    pending: bool,
    stale_valid: bool,
    stall: bool,
    ready: bool,
    doorbells: usize,
    packets: Vec<Vec<u8>>,
    continuation: u8,
    pending_rf: bool,
    revoke_on_rf: bool,
    rf_written: bool,
    commands: Vec<[u8; 32]>,
    command_ring: crate::rtw88::command::Ring,
    command_index: u32,
    command_stall: bool,
    iqk_armed: bool,
    iqk_complete: bool,
    iqk_reads: usize,
    hold_delay: Option<u64>,
    ignore_rf: bool,
    ignore_write: Option<u16>,
    thermal_values: Option<[u8; 2]>,
    thermal_conversions: usize,
    thermal_triggered: bool,
    cam_stuck: bool,
    awake_stuck: bool,
    station_gate: Option<crate::rtw88::power_policy::Gate>,
    extension: Option<Arc<crate::rtw88::station_profile::Grant>>,
    ht: Option<Arc<crate::rtw88::ht::Grant>>,
    rx_ba: Option<Arc<crate::rtw88::rx_ba_power::Grant>>,
    tx_ba: Option<Arc<crate::rtw88::tx_ba_power::Grant>>,
    protection: Option<Arc<crate::rtw88::protection::Grant>>,
    dm: Vec<Arc<crate::rtw88::qualification::Grant>>,
    before_publication: Option<Arc<dyn Fn() + Send + Sync>>,
    edca_writes: usize,
    packet_model: crate::rtw88::packet_core::tests::Model,
    packet_core: Option<crate::rtw88::packet_core::Core>,
    clock: Arc<AtomicU64>,
    mailboxes: Vec<[u8; 8]>,
    mailbox_pending: bool,
    mailbox_hold: bool,
    ring: Arc<IrqSafeSpinLock<BlockState>>,
    frame: Arc<IrqSafeSpinLock<BlockState>>,
}
#[derive(Clone)]
struct Port(Arc<IrqSafeSpinLock<Model>>);
impl Port {
    fn tx_base(&self) -> Result<crate::rtw88::tx_ba_power::Base, Error> {
        let m = self.0.lock();
        Ok(match &m.rx_ba {
            Some(r) => crate::rtw88::tx_ba_power::Base::R(r.clone()),
            None => crate::rtw88::tx_ba_power::Base::H(m.ht.as_ref().ok_or(Error::State)?.clone()),
        })
    }
    fn tx_ba_request(&self) -> Result<crate::rtw88::TxBaRequest, Error> {
        crate::rtw88::tx_ba_power::request(&self.tx_base()?)
    }
    fn protection_base(&self) -> Result<crate::rtw88::protection::Base, Error> {
        let m = self.0.lock();
        Ok(if let Some(t) = &m.tx_ba {
            crate::rtw88::protection::Base::T(t.clone())
        } else if let Some(r) = &m.rx_ba {
            crate::rtw88::protection::Base::R(r.clone())
        } else {
            crate::rtw88::protection::Base::H(m.ht.as_ref().ok_or(Error::State)?.clone())
        })
    }
    fn rts_request(&self) -> Result<crate::rtw88::RtsRequest, Error> {
        crate::rtw88::protection::request(&self.protection_base()?)
    }
    fn dm_request(&self) -> Result<crate::rtw88::ContinuationRequest, Error> {
        let m = self.0.lock();
        crate::rtw88::qualification::request(
            &crate::rtw88::dm::KIND,
            m.station_gate.as_ref().ok_or(Error::State)?,
        )
    }
    fn qualify_dm(&self, s: crate::rtw88::qualification::Source) -> Result<(), Error> {
        self.qualify(&crate::rtw88::dm::KIND, s)
    }
    pub(super) fn kind_request(
        &self,
        kind: &'static crate::rtw88::qualification::Kind,
    ) -> Result<crate::rtw88::ContinuationRequest, Error> {
        let m = self.0.lock();
        crate::rtw88::qualification::request(kind, m.station_gate.as_ref().ok_or(Error::State)?)
    }
    /// Stage one continuation of `kind`, replacing an earlier one of it.
    pub(super) fn qualify(
        &self,
        kind: &'static crate::rtw88::qualification::Kind,
        s: crate::rtw88::qualification::Source,
    ) -> Result<(), Error> {
        let gate = self.0.lock().station_gate.clone().ok_or(Error::State)?;
        let g = s.load(kind, &gate)?;
        let mut m = self.0.lock();
        m.dm.retain(|old| !old.is(kind));
        m.dm.push(g);
        Ok(())
    }
    fn qualify_protection(&self, s: crate::rtw88::protection::Source) -> Result<(), Error> {
        let g = s.load(self.protection_base()?)?;
        self.0.lock().protection = Some(g);
        Ok(())
    }
    fn qualify_tx_ba(&self, s: crate::rtw88::tx_ba_power::Source) -> Result<(), Error> {
        let g = s.load(self.tx_base()?)?;
        self.0.lock().tx_ba = Some(g);
        Ok(())
    }
    fn rx_ba_request(&self) -> Result<crate::rtw88::RxBaRequest, Error> {
        crate::rtw88::rx_ba_power::request(self.0.lock().ht.as_ref().ok_or(Error::State)?)
    }
    fn qualify_rx_ba(&self, s: crate::rtw88::rx_ba_power::Source) -> Result<(), Error> {
        let h = self.0.lock().ht.as_ref().ok_or(Error::State)?.clone();
        let grant = s.load(h)?;
        self.0.lock().rx_ba = Some(grant);
        Ok(())
    }
    fn qualify_ht(&self, s: crate::rtw88::ht::Source) -> Result<(), Error> {
        let b = self
            .0
            .lock()
            .extension
            .as_ref()
            .ok_or(Error::State)?
            .clone();
        let g = s.load(b)?;
        self.0.lock().ht = Some(g);
        Ok(())
    }
    fn ht_request(&self) -> Result<crate::rtw88::ht::Request, Error> {
        crate::rtw88::ht::request(self.0.lock().extension.as_ref().ok_or(Error::State)?)
    }
    fn qualify_extension(
        &self,
        source: crate::rtw88::station_profile::Source,
    ) -> Result<(), Error> {
        let gate = self
            .0
            .lock()
            .station_gate
            .as_ref()
            .ok_or(Error::State)?
            .clone();
        let grant = source.load(gate)?;
        self.0.lock().extension = Some(grant);
        Ok(())
    }
    fn access(&self) -> Result<(), Error> {
        let mut model = self.0.lock();
        let at = model.calls;
        model.calls += 1;
        if model.fail == Some(at) {
            Err(Error::Access)
        } else {
            Ok(())
        }
    }
    fn packet_with<T>(
        &mut self,
        operation: impl FnOnce(
            &mut crate::rtw88::packet_core::Core,
            &mut crate::rtw88::packet_core::tests::Model,
        ) -> Result<T, crate::rtw88::packet_core::Error>,
    ) -> Result<T, crate::rtw88::packet_core::Error> {
        let mut m = self.0.lock();
        m.packet_model.now = m.clock.load(Ordering::Acquire).saturating_mul(1000);
        let mut core = m
            .packet_core
            .take()
            .ok_or(crate::rtw88::packet_core::Error::State)?;
        let result = operation(&mut core, &mut m.packet_model);
        m.packet_core = Some(core);
        result
    }
}
#[async_trait::async_trait]
// SAFETY: no physical PCI/DMA. The simulator holds all synthetic device
// mappings, observes OWN before claiming, and only reads published storage.
unsafe impl Registers for Port {
    fn station_continuation(
        &mut self,
        kind: &'static crate::rtw88::qualification::Kind,
    ) -> Result<Option<Arc<crate::rtw88::qualification::Grant>>, Error> {
        self.station_allowed()?;
        Ok(self.0.lock().dm.iter().find(|g| g.is(kind)).cloned())
    }
    fn station_continuation_request(
        &mut self,
        kind: &'static crate::rtw88::qualification::Kind,
    ) -> Result<crate::rtw88::ContinuationRequest, Error> {
        self.station_allowed()?;
        let m = self.0.lock();
        crate::rtw88::qualification::request(kind, m.station_gate.as_ref().ok_or(Error::State)?)
    }
    fn station_gate(&mut self) -> Result<crate::rtw88::power_policy::Gate, Error> {
        self.station_allowed()?;
        self.0.lock().station_gate.clone().ok_or(Error::State)
    }
    fn station_rts_request(&mut self) -> Result<crate::rtw88::RtsRequest, Error> {
        self.station_allowed()?;
        self.rts_request()
    }
    fn station_protection_extension(
        &mut self,
    ) -> Result<Option<Arc<crate::rtw88::protection::Grant>>, Error> {
        self.station_allowed()?;
        Ok(self.0.lock().protection.clone())
    }
    fn station_bind_coding(
        &mut self,
        g: Arc<crate::rtw88::qualification::Grant>,
    ) -> Result<(), Error> {
        self.station_allowed()?;
        let mut m = self.0.lock();
        let gate = m
            .station_gate
            .as_ref()
            .ok_or(Error::State)?
            .with_coding(g)?;
        m.station_gate = Some(gate);
        Ok(())
    }
    fn station_bind_protection(
        &mut self,
        g: Arc<crate::rtw88::protection::Grant>,
    ) -> Result<(), Error> {
        self.station_allowed()?;
        let gate = self
            .0
            .lock()
            .station_gate
            .as_ref()
            .ok_or(Error::State)?
            .with_protection(g.clone())?;
        let current = gate.clone();
        let mut m = self.0.lock();
        m.packet_model.authority = Some(Arc::new(move || current.current().is_ok()));
        m.packet_model.protection = Some(g);
        m.station_gate = Some(gate);
        Ok(())
    }
    fn station_tx_ba_extension(
        &mut self,
    ) -> Result<Option<Arc<crate::rtw88::tx_ba_power::Grant>>, Error> {
        self.station_allowed()?;
        Ok(self.0.lock().tx_ba.clone())
    }
    fn station_bind_tx_ba(
        &mut self,
        g: Arc<crate::rtw88::tx_ba_power::Grant>,
    ) -> Result<(), Error> {
        self.station_allowed()?;
        let gate = self
            .0
            .lock()
            .station_gate
            .as_ref()
            .ok_or(Error::State)?
            .with_tx_ba(g)?;
        let current = gate.clone();
        let mut m = self.0.lock();
        m.packet_model.authority = Some(Arc::new(move || current.current().is_ok()));
        m.packet_model.originator_ba = true;
        m.station_gate = Some(gate);
        Ok(())
    }
    fn packet_aggregation(
        &mut self,
        cfg: Option<crate::rtw88::packet_format::Aggregation>,
    ) -> Result<(), Error> {
        self.station_allowed()?;
        let mut m = self.0.lock();
        if cfg.is_some_and(|c| {
            m.station_gate
                .as_ref()
                .and_then(crate::rtw88::power_policy::Gate::tx_grant)
                .is_none_or(|g| !g.allows(c))
        }) {
            return Err(Error::Prerequisite);
        }
        m.packet_core
            .as_mut()
            .ok_or(Error::State)?
            .aggregation(cfg)
            .map_err(|_| Error::State)
    }
    fn packet_submit_batch(
        &mut self,
        b: &[Vec<u8>],
    ) -> Result<Vec<u64>, crate::rtw88::packet_core::Error> {
        self.station_allowed()
            .map_err(|_| crate::rtw88::packet_core::Error::Access)?;
        self.packet_with(|core, port| core.submit_batch(port, b))
    }
    fn station_rx_ba_extension(
        &mut self,
        _: Arc<crate::rtw88::ht::Grant>,
    ) -> Result<Option<Arc<crate::rtw88::rx_ba_power::Grant>>, Error> {
        self.station_allowed()?;
        Ok(self.0.lock().rx_ba.clone())
    }
    fn station_bind_rx_ba(
        &mut self,
        g: Arc<crate::rtw88::rx_ba_power::Grant>,
    ) -> Result<(), Error> {
        self.station_allowed()?;
        let gate = self
            .0
            .lock()
            .station_gate
            .as_ref()
            .ok_or(Error::State)?
            .with_rx_ba(g)?;
        let current = gate.clone();
        let mut m = self.0.lock();
        m.packet_model.authority = Some(Arc::new(move || current.current().is_ok()));
        m.packet_model.recipient_ba = true;
        m.station_gate = Some(gate);
        Ok(())
    }
    fn station_ht_facts(&self) -> Option<crate::rtw88::ht::Facts> {
        self.0.lock().station_gate.as_ref()?.ht_facts()
    }
    fn station_ht_extension(
        &mut self,
        _: Arc<crate::rtw88::station_profile::Grant>,
    ) -> Result<Option<Arc<crate::rtw88::ht::Grant>>, Error> {
        self.station_allowed()?;
        Ok(self.0.lock().ht.clone())
    }
    fn station_bind_ht(&mut self, g: Arc<crate::rtw88::ht::Grant>) -> Result<(), Error> {
        self.station_allowed()?;
        let gate = self
            .0
            .lock()
            .station_gate
            .as_ref()
            .ok_or(Error::State)?
            .with_ht(g)?;
        let current = gate.clone();
        let mut m = self.0.lock();
        m.packet_model.authority = Some(Arc::new(move || current.current().is_ok()));
        m.station_gate = Some(gate);
        Ok(())
    }
    fn claim_firmware_dma(&mut self, base: u32) -> Result<(), Error> {
        self.access()?;
        let model = self.0.lock();
        let ring = model.ring.lock();
        if u64::from(base) != ring.address || ring.bytes[..16] != [0; 16] || ring.syncs == 0 {
            return Err(Error::Prerequisite);
        }
        Ok(())
    }
    fn read8(&mut self, reg: u16) -> Result<u8, Error> {
        self.access()?;
        Ok(self.0.lock().bytes[usize::from(reg)])
    }
    fn read16(&mut self, reg: u16) -> Result<u16, Error> {
        self.access()?;
        let model = self.0.lock();
        let at = usize::from(reg);
        let mut value = u16::from_le_bytes(model.bytes[at..at + 2].try_into().unwrap());
        if reg == 0x204 && model.stale_valid {
            value |= 1 << 15;
        }
        if matches!(reg, 0x232 | 0x236 | 0x23a | 0x23e)
            && model
                .station_gate
                .as_ref()
                .is_some_and(|g| g.allows_tx_ba() || g.protection_grant().is_some())
        {
            if model
                .packet_model
                .controls
                .fifo_invalid
                .load(Ordering::Acquire)
            {
                return Ok(u16::MAX);
            }
            if model
                .packet_model
                .controls
                .fifo_stuck
                .load(Ordering::Acquire)
            {
                return Ok(0);
            }
            return Ok(if reg == 0x23e { 14 } else { 16 });
        }
        Ok(value)
    }
    fn read32(&mut self, reg: u16) -> Result<u32, Error> {
        self.access()?;
        let mut model = self.0.lock();
        let at = usize::from(reg);
        if reg == 0x2820 && model.iqk_armed {
            model.iqk_reads += 1;
            if model.iqk_complete && model.iqk_reads >= 2 {
                model.bytes[at..at + 4].copy_from_slice(&0xabcdeu32.to_le_bytes());
            }
        }
        let mut value = u32::from_le_bytes(model.bytes[at..at + 4].try_into().unwrap());
        if reg == 0x1208 {
            value &= !(1 << 31);
        }
        if reg == 0x208 {
            value &= !1;
        }
        if reg == 0x670 && !model.cam_stuck {
            value &= !(1 << 31);
        }
        if reg == 0x80 && model.ready && value & 1 << 14 != 0 {
            value |= 1 << 15;
        }
        Ok(value)
    }
    fn write8(&mut self, reg: u16, value: u8) -> Result<(), Error> {
        self.access()?;
        let mut model = self.0.lock();
        model.bytes[usize::from(reg)] = value;
        if reg == 0x3d9 && model.continuation == 11 && !model.awake_stuck {
            model.bytes[0x3da] ^= 0x80;
        }
        // H2C initialization is an 8-bit REG_H2C_INFO write in mac.c.
        // Its bit2 receipt exposes both empty pointers at the configured head.
        if reg == 0x254 && value & 4 != 0 {
            let head = word(&model.bytes, 0x244) & 0x3ffff;
            model.bytes[0x10d0..0x10d4].copy_from_slice(&head.to_le_bytes());
            model.bytes[0x10d4..0x10d8].copy_from_slice(&head.to_le_bytes());
        }
        if reg == 0x383 && value & 16 != 0 {
            {
                let mut ring = model.ring.lock();
                ring.published_at = Some(ring.acquires);
            }
            {
                let mut frame = model.frame.lock();
                frame.published_at = Some(frame.acquires);
            }
            let frame = model.frame.lock().bytes.clone();
            let length = usize::from(u16::from_le_bytes([frame[0], frame[1]]));
            model.packets.push(frame[..DESC + length].to_vec());
            model.doorbells += 1;
            if !model.stall {
                model.bytes[0x205] |= 0x80;
            }
        }
        Ok(())
    }
    fn write16(&mut self, reg: u16, mut value: u16) -> Result<(), Error> {
        self.access()?;
        let mut model = self.0.lock();
        let at = usize::from(reg);
        if reg == 0x204 {
            value &= !(1 << 15);
        }
        model.bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
    fn write32(&mut self, reg: u16, value: u32) -> Result<(), Error> {
        self.access()?;
        let mut model = self.0.lock();
        if model.continuation == 12 && matches!(reg, 0x500 | 0x504 | 0x508 | 0x50c) {
            model.edca_writes += 1;
        }
        if model.ignore_write == Some(reg) {
            return Ok(());
        }
        let at = usize::from(reg);
        model.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        if reg == 0xc90 {
            model.rf_written = true;
            if !model.ignore_rf {
                let address = ((value >> 20) & 255) as usize;
                let offset = 0x2800 + address * 4;
                model.bytes[offset..offset + 4].copy_from_slice(&(value & 0xfffff).to_le_bytes());
                if address == 8 && value & 0xfffff == 0 {
                    model.iqk_armed = false;
                }
                if address == 0x42 && value & 0x30000 == 0x30000 {
                    model.thermal_triggered = true;
                }
            }
            if model.revoke_on_rf {
                model.fail = Some(model.calls);
            }
        }
        Ok(())
    }
    async fn delay_us(&mut self, us: u64) {
        core::future::poll_fn(|_| {
            let model = self.0.lock();
            if model.pending || model.pending_rf && model.rf_written || model.hold_delay == Some(us)
            {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
        self.0
            .lock()
            .clock
            .fetch_add(us.div_ceil(1000), Ordering::AcqRel);
        if us == 2_000_000 {
            let mut model = self.0.lock();
            if model.thermal_triggered {
                if let Some(samples) = model.thermal_values {
                    let temperature = samples[model.thermal_conversions.min(1)];
                    let previous = word(&model.bytes, 0x2908);
                    model.bytes[0x2908..0x290c].copy_from_slice(
                        &((previous & !0xfc00) | u32::from(temperature) << 10).to_le_bytes(),
                    );
                }
                model.thermal_conversions += 1;
                model.thermal_triggered = false;
            }
        }
    }
    async fn lte_backup(&mut self) -> Result<u32, Error> {
        self.access()?;
        Ok(0x12345678)
    }
    async fn lte_restore(&mut self, value: u32) -> Result<(), Error> {
        self.access()?;
        if value != 0x12345678 {
            return Err(Error::State);
        }
        Ok(())
    }
    async fn finish_dma(&mut self) -> Result<(), Error> {
        self.access()
    }
    fn begin_mac(&mut self) -> Result<(), Error> {
        self.access()?;
        let mut model = self.0.lock();
        if model.continuation != 0 {
            return Err(Error::State);
        }
        model.continuation = 1;
        Ok(())
    }
    fn finish_mac(&mut self) -> Result<(), Error> {
        self.access()?;
        let mut model = self.0.lock();
        if model.continuation != 1 || model.bytes[0x100] & 0xcf != 0 || model.bytes[0x522] != 255 {
            return Err(Error::Prerequisite);
        }
        model.continuation = 2;
        Ok(())
    }
    fn begin_phy(&mut self) -> Result<(), Error> {
        self.access()?;
        let mut model = self.0.lock();
        if model.continuation != 2 {
            return Err(Error::State);
        }
        model.continuation = 3;
        Ok(())
    }
    fn finish_phy(&mut self) -> Result<(), Error> {
        self.access()?;
        let mut model = self.0.lock();
        if model.continuation != 3 || model.bytes[0x100] & 0xcf != 0 || model.bytes[0x522] != 255 {
            return Err(Error::Prerequisite);
        }
        model.continuation = 4;
        Ok(())
    }
    fn begin_calibration8821c(&mut self) -> Result<(), Error> {
        self.access()?;
        let mut model = self.0.lock();
        if model.continuation != 4 || model.bytes[0x100] & 0xcf != 0 || model.bytes[0x522] != 255 {
            return Err(Error::Prerequisite);
        }
        model.continuation = 5;
        Ok(())
    }
    fn begin_commands(&mut self) -> Result<(), Error> {
        self.access()?;
        let mut model = self.0.lock();
        if model.continuation != 5 {
            return Err(Error::State);
        }
        model.continuation = 6;
        model.bytes[0x100] = 0x33;
        Ok(())
    }
    fn submit_h2c(&mut self, packet: &[u8; 32]) -> Result<(), Error> {
        self.access()?;
        let mut model = self.0.lock();
        if model.continuation != 6 {
            return Err(Error::State);
        }
        let index = model.command_index;
        let (_, next) = model.command_ring.reserve(index)?;
        model.commands.push(*packet);
        model.command_index = (index & 0xffff0000) | u32::from(next);
        Ok(())
    }
    fn poll_h2c(&mut self) -> Result<bool, Error> {
        self.access()?;
        let mut model = self.0.lock();
        if !model.command_stall {
            model.command_index = (model.command_index & 0xffff) * 0x10001;
        }
        let index = model.command_index;
        let done = model.command_ring.poll(index)?;
        if done && model.commands.len() == 3 {
            model.iqk_armed = true;
        }
        Ok(done)
    }
    fn park_radio(&mut self) -> Result<(), Error> {
        self.access()?;
        let mut model = self.0.lock();
        if model.continuation != 6 || model.command_ring.pending() {
            return Err(Error::State);
        }
        // Native::park first closes the source DMA configuration bits before
        // CR/BME parking. Preserve that real prerequisite in the retained
        // register model; a later readback must not have to fabricate it.
        model.bytes[0x303] |= 0xf7;
        model.bytes[0x100] = 0;
        model.continuation = 7;
        Ok(())
    }
    fn finish_calibration8821c(&mut self) -> Result<(), Error> {
        self.access()?;
        let mut model = self.0.lock();
        if model.continuation != 7 || model.bytes[0x100] & 0xcf != 0 || model.bytes[0x522] != 255 {
            return Err(Error::Prerequisite);
        }
        model.continuation = 8;
        Ok(())
    }
    fn begin_operating8821c(&mut self) -> Result<(), Error> {
        self.access()?;
        let mut m = self.0.lock();
        if m.continuation != 8 || m.bytes[0x100] & 0xcf != 0 || m.bytes[0x522] != 255 {
            return Err(Error::Prerequisite);
        }
        m.continuation = 9;
        Ok(())
    }
    fn finish_operating8821c(&mut self) -> Result<(), Error> {
        self.access()?;
        let mut m = self.0.lock();
        if m.continuation != 9 || m.bytes[0x100] & 0xcf != 0 || m.bytes[0x522] != 255 {
            return Err(Error::Prerequisite);
        }
        m.continuation = 10;
        Ok(())
    }
    fn begin_station8821c(&mut self) -> Result<(), Error> {
        self.access()?;
        let mut m = self.0.lock();
        if m.continuation != 10 || m.bytes[0x100] & 0xcf != 0 || m.bytes[0x522] != 255 {
            return Err(Error::Prerequisite);
        }
        m.continuation = 11;
        Ok(())
    }
    fn finish_station8821c(&mut self, gate: crate::rtw88::power_policy::Gate) -> Result<(), Error> {
        self.access()?;
        gate.current().map_err(Error::Power)?;
        let mut m = self.0.lock();
        if m.continuation != 11
            || gate.did() != 0xc821
            || m.bytes[0x100] & 0xcf != 0
            || m.bytes[0x522] != 255
            || m.ring.lock().bytes[..16] != [0; 16]
            || m.frame.lock().bytes[..DESC] != [0; DESC]
        {
            return Err(Error::Prerequisite);
        }
        m.station_gate = Some(gate);
        m.continuation = 12;
        Ok(())
    }
    fn parked_cpu<T>(&mut self, operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        self.access()?;
        if self.0.lock().continuation != 11 {
            return Err(Error::State);
        }
        operation()
    }
    fn station_allowed(&mut self) -> Result<(), Error> {
        self.access()?;
        let m = self.0.lock();
        if m.continuation != 12 || !m.packet_model.live || !m.packet_model.allowed {
            return Err(Error::Access);
        }
        m.station_gate
            .as_ref()
            .ok_or(Error::State)?
            .current()
            .map_err(Error::Power)
    }
    fn station_publication(&mut self) -> Result<crate::rtw88::publication::Publication, Error> {
        self.station_allowed()?;
        let m = self.0.lock();
        Ok(crate::rtw88::publication::Publication::model(
            m.station_gate.as_ref().ok_or(Error::State)?.clone(),
            None,
        )
        .before_invoke(m.before_publication.clone()))
    }
    fn station_extension(
        &mut self,
    ) -> Result<Option<Arc<crate::rtw88::station_profile::Grant>>, Error> {
        self.station_allowed()?;
        Ok(self.0.lock().extension.clone())
    }
    fn station_bind_extension(
        &mut self,
        grant: Arc<crate::rtw88::station_profile::Grant>,
    ) -> Result<(), Error> {
        self.station_allowed()?;
        let gate = self
            .0
            .lock()
            .station_gate
            .as_ref()
            .ok_or(Error::State)?
            .with_extension(grant)?;
        let current = gate.clone();
        let mut m = self.0.lock();
        m.packet_model.authority = Some(Arc::new(move || current.current().is_ok()));
        m.station_gate = Some(gate);
        Ok(())
    }
    fn packet_profile(&mut self, p: crate::rtw88::packet_format::DataProfile) -> Result<(), Error> {
        self.station_allowed()?;
        let mut m = self.0.lock();
        if m.station_gate.as_ref().is_none_or(|g| !g.allows_profile(p)) {
            return Err(Error::Unsupported);
        }
        m.packet_core
            .as_mut()
            .ok_or(Error::State)?
            .configure_data(p)
            .map_err(|_| Error::State)
    }
    fn station_profile_readback(&mut self) -> Result<(), Error> {
        self.station_allowed()?;
        let ht = self
            .0
            .lock()
            .station_gate
            .as_ref()
            .and_then(crate::rtw88::power_policy::Gate::ht_grant);
        if let Some(g) = ht {
            return g.readback(|r| self.read32(r));
        }
        let indices = self
            .0
            .lock()
            .station_gate
            .as_ref()
            .and_then(crate::rtw88::power_policy::Gate::c21_indices)
            .ok_or(Error::Unsupported)?;
        crate::rtw88::radio8821c::operating_readback(|r| self.read32(r), indices)
    }
    fn station_own(&mut self) -> Result<[u8; 6], Error> {
        self.station_allowed()?;
        Ok(self
            .0
            .lock()
            .station_gate
            .as_ref()
            .ok_or(Error::State)?
            .own())
    }
    fn mailbox_ready(&mut self) -> Result<bool, Error> {
        self.access()?;
        let m = self.0.lock();
        Ok(!m.mailbox_pending)
    }
    fn mailbox_submit(&mut self, words: [u8; 8]) -> Result<(), Error> {
        self.access()?;
        let mut m = self.0.lock();
        if m.mailbox_pending {
            return Err(Error::State);
        }
        m.mailboxes.push(words);
        m.mailbox_pending = true;
        Ok(())
    }
    fn mailbox_consumed(&mut self) -> Result<bool, Error> {
        self.access()?;
        let mut m = self.0.lock();
        if !m.mailbox_pending {
            return Err(Error::State);
        }
        if m.mailbox_hold {
            return Ok(false);
        }
        m.mailbox_pending = false;
        Ok(true)
    }
    fn mailbox_pending(&self) -> bool {
        self.0.lock().mailbox_pending
    }
    fn packet_prepare(
        &mut self,
        own: [u8; 6],
        id: u8,
    ) -> Result<(), crate::rtw88::packet_core::Error> {
        use crate::rtw88::packet_core::{Core, Error as PacketError};
        self.station_allowed().map_err(|_| PacketError::Access)?;
        let mut m = self.0.lock();
        let gate = m.station_gate.as_ref().ok_or(PacketError::State)?.clone();
        if gate.own() != own || m.packet_core.is_some() {
            return Err(PacketError::State);
        }
        m.packet_model.authority = Some(Arc::new(move || gate.current().is_ok()));
        m.packet_model.receive_chip = crate::rtw88::packet_phy::Chip::C21;
        m.packet_core = Some(Core::prepare(&mut m.packet_model, own, id)?);
        Ok(())
    }
    fn packet_start(&mut self) -> Result<(), crate::rtw88::packet_core::Error> {
        self.packet_with(|core, port| core.start(port))?;
        let mut m = self.0.lock();
        m.bytes[0x100] = 255;
        m.bytes[0x522] = 0;
        Ok(())
    }
    fn packet_ready(&self) -> bool {
        let m = self.0.lock();
        m.packet_model.active
            && m.packet_core
                .as_ref()
                .is_some_and(crate::rtw88::packet_core::Core::ready)
    }
    fn packet_submit(
        &mut self,
        frame: &[u8],
        report: bool,
    ) -> Result<u64, crate::rtw88::packet_core::Error> {
        self.station_allowed()
            .map_err(|_| crate::rtw88::packet_core::Error::Access)?;
        self.packet_with(|core, port| core.submit(port, frame, report))
    }
    fn packet_poll(
        &mut self,
    ) -> Result<crate::rtw88::packet_core::Step, crate::rtw88::packet_core::Error> {
        self.station_allowed()
            .map_err(|_| crate::rtw88::packet_core::Error::Access)?;
        self.packet_with(|core, port| core.poll(port))
    }
    fn packet_stop(&mut self) -> Result<(), crate::rtw88::packet_core::Error> {
        // Native stop encloses only PCI authority: closing RF/DMA must remain
        // possible after a measured-source or regulatory revocation.
        let result = self.packet_with(|core, port| {
            let authority = port.authority.take();
            let allowed = port.allowed;
            port.allowed = true;
            let result = core.stop(port);
            port.authority = authority;
            port.allowed = allowed;
            result
        });
        let mut m = self.0.lock();
        m.bytes[0x100] &= !0xcf;
        m.bytes[0x522] = 255;
        result
    }
}
fn allocated() -> (Backend<Port, Block>, Port, Arc<AtomicUsize>) {
    let drops = Arc::new(AtomicUsize::new(0));
    let ring = Arc::new(IrqSafeSpinLock::new(BlockState {
        address: 0x10000,
        bytes: vec![0xa5; 16],
        writes: 0,
        syncs: 0,
        acquires: 0,
        published_at: None,
    }));
    let frame = Arc::new(IrqSafeSpinLock::new(BlockState {
        address: 0x20000,
        bytes: vec![0xa5; DESC + PAYLOAD],
        writes: 0,
        syncs: 0,
        acquires: 0,
        published_at: None,
    }));
    let port = Port(Arc::new(IrqSafeSpinLock::new(Model {
        bytes: vec![0; 0x2c00],
        calls: 0,
        fail: None,
        pending: false,
        stale_valid: false,
        stall: false,
        ready: true,
        doorbells: 0,
        packets: Vec::new(),
        continuation: 0,
        pending_rf: false,
        revoke_on_rf: false,
        rf_written: false,
        commands: Vec::new(),
        command_ring: crate::rtw88::command::Ring::default(),
        command_index: 0,
        command_stall: false,
        iqk_armed: false,
        iqk_complete: true,
        iqk_reads: 0,
        hold_delay: None,
        ignore_rf: false,
        ignore_write: None,
        thermal_values: None,
        thermal_conversions: 0,
        thermal_triggered: false,
        cam_stuck: false,
        awake_stuck: false,
        station_gate: None,
        extension: None,
        ht: None,
        rx_ba: None,
        tx_ba: None,
        protection: None,
        dm: Vec::new(),
        before_publication: None,
        edca_writes: 0,
        packet_model: crate::rtw88::packet_core::tests::Model::new(),
        packet_core: None,
        clock: Arc::new(AtomicU64::new(0)),
        mailboxes: Vec::new(),
        mailbox_pending: false,
        mailbox_hold: false,
        ring: ring.clone(),
        frame: frame.clone(),
    })));
    let backend = Backend::new(
        port.clone(),
        Block {
            state: ring,
            drops: drops.clone(),
        },
        Block {
            state: frame,
            drops: drops.clone(),
        },
        0x123,
    )
    .unwrap();
    (backend, port, drops)
}
fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn smoke_rtw88_persistent_reserved_page_native_descriptor_and_reuse() -> TestResult {
    let (mut backend, port, drops) = allocated();
    backend.claim_pristine().unwrap();
    for length in [1, 80, 81, 4096, 7] {
        let bytes = vec![0x12; length];
        narf_scheduler::block_on(backend.reserved_page(&bytes)).unwrap();
        let model = port.0.lock();
        let frame = model.frame.lock();
        let ring = model.ring.lock();
        if frame.bytes[DESC..DESC + length] != bytes
            || word(&frame.bytes, 0) != length as u32 | 48 << 16 | 1 << 26 | 1 << 31
            || word(&frame.bytes, 4) != 0x81000
            || word(&frame.bytes, 12) != 0x500
            || word(&frame.bytes, 32) != 0x8000
        {
            return TestResult::Fail(
                "native firmware packet descriptor/offset/legacy profile mismatch",
            );
        }
        if word(&ring.bytes, 0) != 48 | (((DESC + length).div_ceil(128) as u32 | 0x8000) << 16)
            || word(&ring.bytes, 4) != 0x20000
            || word(&ring.bytes, 8) != length as u32
            || word(&ring.bytes, 12) != 0x20030
        {
            return TestResult::Fail(
                "native reserved-page PCI two-segment BD/pagecount/OWN mismatch",
            );
        }
        if ring.acquires != model.doorbells || frame.acquires != model.doorbells {
            return TestResult::Fail("fresh valid lacked device completion acquire before reuse");
        }
        if backend.state != PageState::Idle
            || u16::from_le_bytes(model.bytes[0x204..0x206].try_into().unwrap()) != 0x123
        {
            return TestResult::Fail(
                "completed page did not restore reserved boundary/reopen serial owner",
            );
        }
    }
    if port.0.lock().doorbells != 5 {
        return TestResult::Fail("native descriptor path did not publish every exact transfer");
    }
    drop(backend);
    if drops.load(Ordering::SeqCst) != 0 {
        return TestResult::Fail("published native mappings were reclaimed without reset proof");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_persistent_reserved_page_native_descriptor_and_reuse
);
fn smoke_rtw88_reserved_page_every_access_fault_and_post_publication_cancel() -> TestResult {
    let (mut reference, reference_port, _) = allocated();
    reference.claim_pristine().unwrap();
    let start = reference_port.0.lock().calls;
    narf_scheduler::block_on(reference.reserved_page(&[0x12; 80])).unwrap();
    let end = reference_port.0.lock().calls;
    for fail in start..end {
        let (mut backend, port, _) = allocated();
        backend.claim_pristine().unwrap();
        port.0.lock().fail = Some(fail);
        if narf_scheduler::block_on(backend.reserved_page(&[0x12; 80])) != Err(Error::Access)
            || backend.state != PageState::Terminal
        {
            return TestResult::Fail("failed page I/O reopened or claimed completion");
        }
        let model = port.0.lock();
        let calls = model.calls;
        let frame = model.frame.lock().bytes.clone();
        let ring = model.ring.lock().bytes.clone();
        drop(model);
        if calls != fail + 1
            || narf_scheduler::block_on(backend.reserved_page(&[0x34; 80])) != Err(Error::State)
        {
            return TestResult::Fail("ambiguous native transfer performed cleanup or retry");
        }
        let model = port.0.lock();
        if model.calls != calls
            || model.frame.lock().bytes != frame
            || model.ring.lock().bytes != ring
        {
            return TestResult::Fail("failed native buffer overwritten before quiescence");
        }
    }
    let (mut backend, port, _) = allocated();
    backend.claim_pristine().unwrap();
    {
        let mut model = port.0.lock();
        model.pending = true;
        model.stall = true;
    }
    let mut future = Box::pin(backend.reserved_page(&[0x12; 80]));
    if future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        != Poll::Pending
    {
        return TestResult::Fail("cancel fixture did not reach actual TD publication");
    }
    drop(future);
    let model = port.0.lock();
    let calls = model.calls;
    let frame = model.frame.lock().bytes.clone();
    let ring = model.ring.lock().bytes.clone();
    let doorbells = model.doorbells;
    drop(model);
    if doorbells != 1
        || backend.state != PageState::Terminal
        || narf_scheduler::block_on(backend.reserved_page(&[0x34; 80])) != Err(Error::State)
    {
        return TestResult::Fail("cancelled actual TD was not terminally retained");
    }
    let model = port.0.lock();
    if model.calls != calls || model.frame.lock().bytes != frame || model.ring.lock().bytes != ring
    {
        return TestResult::Fail("cancelled native TD scratch was overwritten");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_reserved_page_every_access_fault_and_post_publication_cancel
);
fn smoke_rtw88_reserved_page_stale_valid_and_timeout_never_reuse() -> TestResult {
    for stale in [false, true] {
        let (mut backend, port, _) = allocated();
        backend.claim_pristine().unwrap();
        {
            let mut model = port.0.lock();
            model.stall = true;
            model.stale_valid = stale;
        }
        let wanted = if stale {
            Error::Prerequisite
        } else {
            Error::Timeout
        };
        if narf_scheduler::block_on(backend.reserved_page(&[0; 80])) != Err(wanted)
            || backend.state != PageState::Terminal
            || port.0.lock().doorbells != usize::from(!stale)
        {
            return TestResult::Fail("stale page-valid or timeout passed completion gate");
        }
        let calls = port.0.lock().calls;
        if narf_scheduler::block_on(backend.reserved_page(&[0; 80])) != Err(Error::State)
            || port.0.lock().calls != calls
        {
            return TestResult::Fail("unproven beacon-page completion was retried");
        }
    }
    let (backend, _, drops) = allocated();
    drop(backend);
    if drops.load(Ordering::SeqCst) != 2 {
        return TestResult::Fail("unpublished page allocations leaked");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_reserved_page_stale_valid_and_timeout_never_reuse
);
fn image() -> Vec<u8> {
    let mut bytes = vec![0; 64 + 4093 + 8 + 9 + 8 + 5 + 8];
    bytes[..2].copy_from_slice(&[0x22, 0x88]);
    bytes[0x18] = 0x10;
    for (offset, value) in [
        (0x20, 0x80200000u32),
        (0x24, 4093),
        (0x30, 9),
        (0x34, 5),
        (0x38, 0x80100000),
        (0x3c, 0x80030000),
    ] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (index, byte) in bytes[64..].iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }
    bytes
}
fn smoke_rtw88_actual_reserved_page_backend_composes_whole_firmware() -> TestResult {
    for did in [0xc821, 0xc822] {
        if let TestResult::Fail(error) = composed_firmware(did) {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
fn composed_firmware(did: u16) -> TestResult {
    let (backend, port, _) = allocated();
    let mut bytes = image();
    bytes[0] = if did == 0xc821 { 0x21 } else { 0x22 };
    let mut owner = firmware_transport::Owner::new(backend, did);
    if narf_scheduler::block_on(owner.download(&bytes)).is_err()
        || owner.phase() != firmware_transport::Phase::Ready
    {
        return TestResult::Fail("real section owner/native page backend did not compose");
    }
    let model = port.0.lock();
    let payloads: Vec<_> = model.packets.iter().map(|packet| &packet[48..]).collect();
    if payloads
        != vec![
            &bytes[64..4160],
            &bytes[4160..4165],
            &bytes[4165..4182],
            &bytes[4182..4195],
        ]
    {
        return TestResult::Fail(
            "composed page DMA did not carry exact firmware sections/trailers",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_actual_reserved_page_backend_composes_whole_firmware
);

fn smoke_rtw8821ce_real_reserved_dma_owner_survives_phy_success_cancel_and_revocation() -> TestResult
{
    for outcome in 0..5 {
        let (backend, port, drops) = allocated();
        let mut bytes = image();
        bytes[0] = 0x21;
        let lifecycle = crate::rtw88::firmware_lifecycle::Lifecycle::new(0xc821);
        if narf_scheduler::block_on(lifecycle.initialize_bytes(|| Ok(backend), bytes)).is_err() {
            return TestResult::Fail("composed C21 fixture failed retained firmware setup");
        }
        {
            let mut model = port.0.lock();
            model.bytes[0xf0..0xf4].copy_from_slice(&(3u32 << 12).to_le_bytes());
            model.bytes[0x1a0] = 0x19;
            model.bytes[0x1a6..0x1aa]
                .copy_from_slice(&((7u32 << 16) | (1 << 19) | (1 << 21) | (3 << 26)).to_le_bytes());
        }
        if narf_scheduler::block_on(lifecycle.prepare_mac()).is_err() {
            return TestResult::Fail("composed C21 fixture failed inactive MAC/H2C setup");
        }
        {
            let model = port.0.lock();
            if word(&model.bytes, 0x10d0) & 0x3ffff != 500 << 7
                || word(&model.bytes, 0x10d4) & 0x3ffff != 500 << 7
            {
                return TestResult::Fail(
                    "C21 byte H2C initialization missed configured empty pointers",
                );
            }
        }
        let (frame, ring, doorbells) = {
            let model = port.0.lock();
            let frame = model.frame.lock().bytes.clone();
            let ring = model.ring.lock().bytes.clone();
            (frame, ring, model.doorbells)
        };
        let mut raw = [255; 512];
        raw[0xd0..0xd6].copy_from_slice(&[2, 4, 6, 8, 10, 12]);
        raw[0xb9] = 0x33;
        raw[0xca] = 4;
        let factory = match crate::rtw88::efuse::Factory8821c::for_test(raw) {
            Ok(factory) => factory,
            Err(_) => return TestResult::Fail("composed C21 fixture has invalid factory identity"),
        };
        {
            let mut model = port.0.lock();
            model.pending = outcome == 1;
            model.pending_rf = outcome == 2;
            model.revoke_on_rf = outcome == 4;
            if outcome == 3 {
                model.fail = Some(model.calls);
            }
        }
        if matches!(outcome, 1 | 2) {
            let mut future = Box::pin(lifecycle.prepare_phy8821c(&factory));
            if future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                != Poll::Pending
            {
                return TestResult::Fail(
                    "composed C21 PHY cancellation missed real retained DMA owner",
                );
            }
            drop(future);
        } else {
            let expected = if outcome == 0 {
                None
            } else {
                Some(Error::Access)
            };
            if narf_scheduler::block_on(lifecycle.prepare_phy8821c(&factory)).err() != expected {
                return TestResult::Fail(
                    "composed C21 PHY success/current-authority failure differed",
                );
            }
        }
        let status = lifecycle.status();
        if (outcome == 0
            && status.stage != crate::rtw88::firmware_lifecycle::Stage::PhyTablesPrepared)
            || (outcome != 0 && status.stage != crate::rtw88::firmware_lifecycle::Stage::Failed)
            || drops.load(Ordering::SeqCst) != 0
        {
            return TestResult::Fail(
                "C21 PHY result freed retained native DMA or claimed readiness",
            );
        }
        let calls = {
            let model = port.0.lock();
            if model.frame.lock().bytes != frame
                || model.ring.lock().bytes != ring
                || model.doorbells != doorbells
                || model.bytes[0x100] & 0xcf != 0
                || model.bytes[0x522] != 255
            {
                return TestResult::Fail("C21 PHY rewrote retained page buffers or opened MAC");
            }
            model.calls
        };
        if narf_scheduler::block_on(lifecycle.prepare_phy8821c(&factory)) != Err(Error::State)
            || narf_scheduler::block_on(lifecycle.initialize_bytes(|| Err(Error::Memory), vec![]))
                != Err(Error::State)
            || port.0.lock().calls != calls
        {
            return TestResult::Fail(
                "C21 PHY replayed native DMA owner after terminal/completed result",
            );
        }
        // Keep the actual Backend's published buffers pinned on destruction.
        drop(lifecycle);
        if drops.load(Ordering::SeqCst) != 0 {
            return TestResult::Fail("C21 PHY terminal/completed owner reclaimed published DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c",
    smoke_rtw8821ce_real_reserved_dma_owner_survives_phy_success_cancel_and_revocation
);

#[path = "reserved_calibration8821c_tests.rs"]
mod calibration8821c_tests;

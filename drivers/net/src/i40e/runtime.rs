//! Stable interface ownership and replaceable, exclusively rebuilt hardware.
//! Workers lease an Arc for a bounded operation; recovery withdraws publication
//! and waits for every lease before touching DMA or queue configuration.

use super::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecoveryStatus {
    pub recovering: bool,
    /// Successful rebuilds, also the current hardware generation.
    pub generation: u64,
    pub failed_attempts: u64,
    pub last_error: Option<I40eError>,
}

struct Runtime {
    hardware: Option<Arc<Hardware>>,
    status: RecoveryStatus,
}

/// A stable registered interface. MAC, frame-ring endpoints and queue count
/// survive every reset; runtime hardware is never exposed as a borrowed field.
pub struct I40eNic {
    pub device_id: u16,
    pub port_num: u8,
    pub mac: [u8; 6],
    queues: usize,
    rss: rss::RssConfig,
    runtime: IrqSafeSpinLock<Runtime>,
    tx_rejected: AtomicU64,
    rx_dropped: AtomicU64,
    pub(super) rx_ipc_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    pub(super) tx_ipc_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}
impl core::fmt::Debug for I40eNic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("I40eNic")
            .field("device_id", &self.device_id)
            .field("mac", &self.mac)
            .field("queues", &self.queues)
            .field("recovery", &self.recovery_status())
            .finish_non_exhaustive()
    }
}
impl I40eNic {
    pub(super) fn new(
        hardware: Hardware,
        rx: Consumer<Frame, RX_RING_N>,
        tx: Producer<Frame, TX_RING_N>,
    ) -> Self {
        Self {
            device_id: hardware.device_id,
            port_num: hardware.port_num,
            mac: hardware.mac,
            queues: hardware.queues.len(),
            rss: hardware.rss.clone(),
            runtime: IrqSafeSpinLock::new(Runtime {
                hardware: Some(Arc::new(hardware)),
                status: RecoveryStatus::default(),
            }),
            tx_rejected: AtomicU64::new(0),
            rx_dropped: AtomicU64::new(0),
            rx_ipc_ring: IrqSafeSpinLock::new(Some(rx)),
            tx_ipc_ring: IrqSafeSpinLock::new(Some(tx)),
        }
    }
    fn lease(&self) -> Option<(Arc<Hardware>, u64)> {
        let runtime = self.runtime.lock();
        runtime
            .hardware
            .as_ref()
            .map(|hw| (hw.clone(), runtime.status.generation))
    }
    pub fn queue_count(&self) -> usize {
        self.queues
    }
    pub fn recovery_status(&self) -> RecoveryStatus {
        self.runtime.lock().status
    }
    pub fn dropped_frames(&self) -> (u64, u64) {
        (
            self.tx_rejected.load(Ordering::Relaxed),
            self.rx_dropped.load(Ordering::Relaxed),
        )
    }
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }
    pub fn link_status(&self) -> LinkStatus {
        self.lease()
            .filter(|(hw, _)| !hw.irq().failed())
            .map(|(hw, _)| hw.link_status())
            .unwrap_or_default()
    }
    pub fn link_up(&self) -> bool {
        self.link_status().link_up
    }
    /// Submit using a stable Toeplitz flow hash. Recovery returns DeviceFailed
    /// until every queue and interrupt route has been restored.
    pub fn transmit_with_meta(
        &self,
        frame: &[u8],
        meta: narf_net::TxMeta,
    ) -> Result<(), I40eError> {
        let (hw, _) = self.lease().ok_or(I40eError::DeviceFailed)?;
        hw.transmit_with_meta(frame, meta, self.rss.tx_queue(frame, self.queues))
    }
    pub fn transmit(&self, frame: &[u8]) -> Result<(), I40eError> {
        self.transmit_with_meta(frame, narf_net::TxMeta::plain())
    }
    /// Compatibility polling across all hardware queues.
    pub fn receive(&self) -> Option<alloc::vec::Vec<u8>> {
        let (hw, _) = self.lease()?;
        if hw.irq().failed() {
            return None;
        }
        for queue in hw.queues.iter() {
            // SAFETY: lease prevents reset; queue lock serializes its consumers.
            if let Some(bytes) = unsafe { queue.lock().receive(&hw.csr) } {
                return Some(bytes);
            }
        }
        None
    }
}

async fn delay(ms: u64) {
    narf_time::sleep_cycles(narf_time::Deadline::after_ms(ms).remaining_cycles()).await;
}

pub(super) fn spawn_pumps(
    device: Arc<I40eNic>,
    rx: Producer<Frame, RX_RING_N>,
    tx: Consumer<Frame, TX_RING_N>,
) {
    // The external ABI remains one SPSC endpoint. Queue workers serialize just
    // try_send; packet copying, completion reclaim and IRQ handling stay per-queue.
    let delivery = Arc::new(IrqSafeSpinLock::new(rx));
    for queue in 0..device.queues {
        let d = device.clone();
        let rx = delivery.clone();
        let mut spec = narf_scheduler::TaskSpec::kernel_any();
        spec.affinity.preferred = Some(narf_scheduler::CpuId(rss::queue_cpu(queue)));
        narf_scheduler::spawn_with_spec(
            async move {
                queue_pump(d, queue, rx).await;
            },
            spec,
        );
    }
    let d = device.clone();
    narf_scheduler::spawn(async move {
        tx_pump(d, tx).await;
    });
    let d = device.clone();
    narf_scheduler::spawn(async move {
        admin_pump(d).await;
    });
    narf_scheduler::spawn(async move {
        recovery_pump(device).await;
    });
}

async fn recovery_pump(device: Arc<I40eNic>) {
    loop {
        let retired = {
            let mut runtime = device.runtime.lock();
            if runtime
                .hardware
                .as_ref()
                .is_some_and(|hw| hw.irq().failed())
            {
                runtime.status.recovering = true;
                runtime.hardware.take()
            } else {
                None
            }
        };
        let Some(mut retired) = retired else {
            delay(100).await;
            continue;
        };
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  i40e: port {} recovering",
            device.port_num
        );
        // No new leases can be acquired. Existing IRQ waits and AQ commands
        // are bounded; cancellation drops their guards and leases as well.
        while Arc::get_mut(&mut retired).is_none() {
            delay(1).await;
        }
        let mut backoff = 100;
        loop {
            let hardware = Arc::get_mut(&mut retired).unwrap();
            let before = hardware.reset_discarded;
            let result = hardware.recover().await;
            device
                .tx_rejected
                .fetch_add(hardware.reset_discarded - before, Ordering::Relaxed);
            match result {
                Ok(()) => {
                    let generation = {
                        let mut runtime = device.runtime.lock();
                        runtime.status.generation = runtime.status.generation.wrapping_add(1);
                        runtime.status.recovering = false;
                        runtime.status.last_error = None;
                        runtime.hardware = Some(retired);
                        runtime.status.generation
                    };
                    let _ = writeln!(
                        narf_console::Writer,
                        "  i40e: port {} recovered (generation {})",
                        device.port_num,
                        generation
                    );
                    break;
                }
                Err(error) => {
                    hardware.irq().fail();
                    {
                        let mut runtime = device.runtime.lock();
                        runtime.status.failed_attempts += 1;
                        runtime.status.last_error = Some(error);
                    }
                    // Retain all DMA, even when reset cannot prove quiescence.
                    // Retry in place; repeated failure cannot leak new buffers.
                    let _ = writeln!(
                        narf_console::Writer,
                        "  i40e: port {} recovery {:?}; retry in {} ms",
                        device.port_num,
                        error,
                        backoff
                    );
                    delay(backoff).await;
                    backoff = (backoff * 2).min(30_000);
                }
            }
        }
    }
}

async fn admin_pump(device: Arc<I40eNic>) {
    let mut refresh = false;
    let mut generation = 0;
    loop {
        let Some((hw, current)) = device.lease() else {
            delay(10).await;
            continue;
        };
        if hw.irq().failed() {
            drop(hw);
            delay(10).await;
            continue;
        }
        if current != generation {
            refresh = false;
            generation = current;
        }
        let activity = narf_interrupts::wait::wait_for_irq_until(
            hw.irq().admin_vector(),
            narf_time::Deadline::after_ms(100),
        );
        let mut drained = 0;
        while drained < AQ_WORK_LIMIT {
            let Some(event) = hw.poll_arq_event() else {
                break;
            };
            drained += 1;
            refresh |= event.opcode == AqOpcode::GetLinkStatus as u16;
        }
        if refresh {
            if let Ok(link) = hw.refresh_link_async().await {
                refresh = false;
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "  i40e: port {} link {} ({})",
                    device.port_num,
                    if link.link_up { "up" } else { "down" },
                    link.speed().label()
                );
            }
        }
        if drained == AQ_WORK_LIMIT {
            narf_scheduler::yield_now().await;
        } else {
            hw.irq().rearm_admin();
            let _ = activity.await;
        }
    }
}

async fn queue_pump(
    device: Arc<I40eNic>,
    index: usize,
    rx: Arc<IrqSafeSpinLock<Producer<Frame, RX_RING_N>>>,
) {
    let mut generation = 0;
    let mut last_clean = 0;
    let mut was_pending = false;
    let mut deadline = narf_time::Deadline::after_ms(250);
    loop {
        let Some((hw, current)) = device.lease() else {
            delay(10).await;
            continue;
        };
        if hw.irq().failed() {
            drop(hw);
            delay(10).await;
            continue;
        }
        if current != generation {
            was_pending = false;
            generation = current;
        }
        let activity = narf_interrupts::wait::wait_for_irq_until(
            hw.irq().queue_vector(index),
            narf_time::Deadline::after_ms(10),
        );
        let progress = {
            let mut queue = hw.queues[index].lock();
            queue
                .reclaim()
                .map(|()| (queue.tx_progress(), queue.tx_pending()))
        };
        let Ok((clean, pending)) = progress else {
            hw.irq().fail();
            continue;
        };
        if !pending || !was_pending || clean != last_clean {
            deadline = narf_time::Deadline::after_ms(250);
        } else if deadline.expired() {
            hw.irq().fail();
            continue;
        }
        last_clean = clean;
        was_pending = pending;
        let mut drained = 0;
        while drained < ring::RING_LEN {
            if hw.irq().failed() {
                break;
            }
            // SAFETY: hardware lease prevents reset and DMA reclamation.
            let packet = unsafe { hw.queues[index].lock().receive_with_meta(&hw.csr) };
            let Some(packet) = packet else {
                break;
            };
            drained += 1;
            let delivered = if let Some((bytes, meta)) = packet {
                if let Ok(buffer) = alloc_coherent(bytes.len(), DomainId::DRIVER_0) {
                    let mut frame = Frame::new(buffer, bytes.len() as u32);
                    frame.payload_mut().copy_from_slice(&bytes);
                    frame.set_rx_meta(meta);
                    rx.lock().try_send(frame).is_ok()
                } else {
                    false
                }
            } else {
                false
            };
            if !delivered {
                device.rx_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        if drained == ring::RING_LEN {
            narf_scheduler::yield_now().await;
        } else {
            hw.irq().rearm_queue(index);
            let _ = activity.await;
        }
    }
}

async fn tx_pump(device: Arc<I40eNic>, mut tx: Consumer<Frame, TX_RING_N>) {
    while let Ok(frame) = tx.recv().await {
        let queue = device.rss.tx_queue(frame.payload(), device.queues);
        let mut deadline = narf_time::Deadline::after_ms(250);
        let mut generation = 0;
        loop {
            let Some((hw, current)) = device.lease() else {
                delay(10).await;
                continue;
            };
            if hw.irq().failed() {
                drop(hw);
                delay(10).await;
                continue;
            }
            if current != generation {
                deadline = narf_time::Deadline::after_ms(250);
                generation = current;
            }
            let activity = narf_interrupts::wait::wait_for_irq_until(
                hw.irq().queue_vector(queue),
                narf_time::Deadline::after_ms(10),
            );
            match hw.transmit_with_meta(frame.payload(), frame.tx_meta(), queue) {
                Ok(()) => break,
                Err(I40eError::TxRingFull) => {
                    if deadline.expired() {
                        hw.irq().fail();
                    } else {
                        let _ = activity.await;
                    }
                }
                Err(I40eError::DeviceFailed | I40eError::InvalidTxHead) => {}
                Err(_) => {
                    device.tx_rejected.fetch_add(1, Ordering::Relaxed);
                    break;
                }
            }
        }
        narf_scheduler::yield_now().await;
    }
}

impl Hardware {
    /// Called only on an unpublished, exclusively owned hardware generation.
    async fn recover(&mut self) -> Result<(), I40eError> {
        self.interrupts.as_mut().unwrap().quiesce();
        self.link_state.store(0, Ordering::Release);
        self.reset_async().await?;
        // This successful reset is the only authorization to recycle DMA.
        for queue in self.queues.iter() {
            // SAFETY: all leases drained and the reset completed above.
            self.reset_discarded += unsafe { queue.lock().reset_after_quiesce() };
        }
        // SAFETY: owned BAR mapping, reset has completed.
        let allocation = unsafe { self.csr.read32(REG_PFLAN_QALLOC) };
        let (base, last) = ring::decode_qalloc(allocation);
        if allocation & (1 << 31) == 0 || last < base || last - base + 1 < self.queues.len() as u16
        {
            return Err(I40eError::NoQueuesAllocated);
        }
        self.base_queue = base;
        // Re-read HMC geometry after a possible global reset. Old backing is
        // freed only now, when hardware is known quiescent.
        // SAFETY: owned CSR mapping; this allocates unpublished backing.
        let hmc = unsafe {
            hmc::LanHmc::alloc(
                &self.csr,
                self.pf_id,
                self.queues.len() as u32,
                self.queues.len() as u32,
            )?
        };
        // SAFETY: confirmed reset stopped access to old HMC; replace exactly once.
        unsafe {
            ManuallyDrop::drop(&mut self.hmc);
        }
        self.hmc = ManuallyDrop::new(hmc);
        for i in 0..AQ_RING_LEN as usize {
            let mut descriptor = AqDesc {
                flags: AQ_FLAG_BUF | AQ_FLAG_LB,
                datalen: AQ_BUF_BYTES as u16,
                ..AqDesc::default()
            };
            set_desc_buf_addr(&mut descriptor, self.arq_bufs[i].dma_addr().raw());
            // SAFETY: quiescent DMA rings; old completion bits must not survive.
            unsafe {
                write_desc(&self.atq, i, AqDesc::default());
                write_desc(&self.arq, i, descriptor);
            }
        }
        *self.atq_next.lock() = 0;
        *self.arq_ntc.lock() = 0;
        self.atq_busy.store(false, Ordering::Release);
        self.interrupts.as_mut().unwrap().reset_complete();
        self.initialize(true)
    }
    async fn reset_async(&self) -> Result<(), I40eError> {
        // SAFETY: BAR0 owned; all register offsets checked at probe.
        let grstdel = unsafe { self.csr.read32(REG_GLGEN_RSTCTL) } & GLGEN_RSTCTL_GRSTDEL_MASK;
        let budget = (grstdel as u64 * 200).clamp(100, GLOBAL_RESET_MAX_MS);
        let interval = narf_time::Deadline::after_ms(1).remaining_cycles();
        narf_time::poll_bit_async(
            // SAFETY: owned BAR0; status is read-only.
            || unsafe { self.csr.read32(REG_GLGEN_RSTAT) } & GLGEN_RSTAT_DEVSTATE_MASK == 0,
            interval,
            narf_time::Deadline::after_ms(budget),
        )
        .await
        .map_err(|_| I40eError::GlobalResetTimeout)?;
        narf_time::poll_bit_async(
            // SAFETY: owned BAR0; status is read-only.
            || unsafe { self.csr.read32(REG_GLNVM_ULD) } & GLNVM_ULD_READY == GLNVM_ULD_READY,
            interval,
            narf_time::Deadline::after_ms(NVM_READY_MAX_MS),
        )
        .await
        .map_err(|_| I40eError::NvmNotReady)?;
        // SAFETY: exclusive unpublished PF; request only its own reset.
        unsafe {
            self.csr.write32(
                REG_PFGEN_CTRL,
                self.csr.read32(REG_PFGEN_CTRL) | PFGEN_CTRL_PFSWR,
            );
        }
        dma_barrier();
        narf_time::poll_bit_async(
            // SAFETY: same live mapping throughout the bounded reset wait.
            || unsafe {
                self.csr.read32(REG_PFGEN_CTRL) & PFGEN_CTRL_PFSWR == 0
                    && self.csr.read32(REG_GLGEN_RSTAT) & GLGEN_RSTAT_DEVSTATE_MASK == 0
                    && self.csr.read32(REG_GLNVM_ULD) & GLNVM_ULD_READY == GLNVM_ULD_READY
            },
            interval,
            narf_time::Deadline::after_ms(PF_RESET_MAX_MS),
        )
        .await
        .map_err(|_| I40eError::PfResetTimeout)
    }
}

#[path = "runtime_tests.rs"]
mod tests;

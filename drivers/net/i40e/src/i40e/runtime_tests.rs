//! Memory-backed PF/firmware model. Exercises real AQ, HMC, RSS, queue and
//! recovery code without accessing PCI configuration or a host NIC.
use super::*;
use alloc::{boxed::Box, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

static MODEL: IrqSafeSpinLock<usize> = IrqSafeSpinLock::new(0);
static PUMP_REGISTERED: AtomicBool = AtomicBool::new(false);

fn pump() {
    let ptr = MODEL.lock();
    if *ptr != 0 {
        // SAFETY: Fixture publishes stable boxed storage and unpublishes under
        // this lock after hardware teardown. No real device addresses enter it.
        unsafe {
            let firmware = &mut *(*ptr as *mut Firmware);
            if firmware.cpu == narf_lib::percpu::current_cpu() {
                firmware.step();
            }
        }
    }
}

struct Firmware {
    csr: MmioRegion,
    cpu: usize,
    atq: *mut AqDesc,
    buffers: Vec<*mut u8>,
    properties: [u8; 128],
    queues: u16,
    resets: usize,
    stall_reset: bool,
    reject_vsi: bool,
    key_commands: usize,
    lut_commands: usize,
    mapping_commands: usize,
}
impl Firmware {
    fn step(&mut self) {
        // SAFETY: all pointers refer exclusively to fixture-owned DMA memory.
        // SAFETY: fixture-owned MMIO; offset is bounded by the four queues.
        unsafe {
            if self.csr.read32(REG_PFGEN_CTRL) & PFGEN_CTRL_PFSWR != 0 {
                if self.stall_reset {
                    return;
                }
                self.resets += 1;
                self.csr.write32(REG_PFGEN_CTRL, 0);
                self.csr.write32(REG_PF_ATQLEN, 0);
                self.csr.write32(REG_PF_ATQH, 0);
                self.csr.write32(REG_PF_ATQT, 0);
                self.csr.write32(irq::REG_PFINT_ICR0, 0);
                self.csr.write32(0x00245900, 0);
                self.csr.write32(0x00245980, 0);
                for q in 0..self.queues {
                    self.csr.write32(ring::reg_qtx_ena(q), 0);
                    self.csr.write32(ring::reg_qrx_ena(q), 0);
                    self.csr.write32(irq::reg_pfint_lnklstn(q), 0);
                }
                self.properties.fill(0);
                return;
            }
            for q in 0..self.queues {
                for register in [ring::reg_qtx_ena(q), ring::reg_qrx_ena(q)] {
                    let req = self.csr.read32(register) & 1;
                    self.csr.write32(register, req | (req << 2));
                }
            }
            if self.csr.read32(REG_PF_ATQLEN) & AQLEN_ENABLE == 0 {
                return;
            }
            let slot = self.csr.read32(REG_PF_ATQH) as usize;
            if slot == self.csr.read32(REG_PF_ATQT) as usize {
                return;
            }
            let mut d = core::ptr::read_volatile(self.atq.add(slot));
            let buf = core::slice::from_raw_parts_mut(self.buffers[slot], AQ_BUF_BYTES);
            match d.opcode {
                0x0001 => {
                    d.params[9] = 6;
                    d.params[13] = 1;
                    d.params[14] = 15;
                }
                0x0107 => {
                    d.params[0] = MAC_ADDR_LAN_VALID as u8;
                    buf[..24].fill(0);
                    buf[..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
                }
                0x0200 => {
                    buf[..32].fill(0);
                    buf[0] = 1;
                    buf[2] = 1;
                    buf[16] = vsi::ELEMENT_TYPE_VSI;
                    buf[18] = 7;
                }
                0x0212 => {
                    if self.reject_vsi {
                        d.retval = 5;
                    }
                    d.params[0] = 7;
                    d.params[2] = 3;
                    self.properties[96..98].copy_from_slice(&19u16.to_le_bytes());
                    buf[..128].copy_from_slice(&self.properties);
                }
                0x0211 => {
                    if buf[0] & 4 != 0 {
                        self.properties[8..16].copy_from_slice(&buf[8..16]);
                    }
                    if buf[0] & 0x40 != 0 {
                        self.mapping_commands += 1;
                        self.properties[28..78].copy_from_slice(&buf[28..78]);
                    }
                }
                0x000a => {
                    buf[..128].fill(0);
                    for (i, (id, number, width)) in [
                        (0x40u16, 512u32, 3u32),
                        (0x41, 8, 0),
                        (0x42, 8, 0),
                        (0x43, 9, 0),
                    ]
                    .iter()
                    .enumerate()
                    {
                        let off = i * 32;
                        buf[off..off + 2].copy_from_slice(&id.to_le_bytes());
                        buf[off + 4..off + 8].copy_from_slice(&number.to_le_bytes());
                        buf[off + 8..off + 12].copy_from_slice(&width.to_le_bytes());
                    }
                    d.params[4..8].copy_from_slice(&4u32.to_le_bytes());
                    d.datalen = 128;
                }
                0x0250 => buf[12] = 0,
                0x0607 => {
                    d.params[0] = AQ_LSE_IS_ENABLED as u8;
                    d.params[4] = LINK_INFO_LINK_UP | LINK_INFO_MEDIA_AVAILABLE;
                }
                0x0b02 => {
                    self.key_commands += 1;
                    if d.params[0..2] != 0x8003u16.to_le_bytes()
                        || d.datalen != 52
                        || d.flags & AQ_FLAG_RD == 0
                    {
                        d.retval = 14;
                    }
                }
                0x0b03 => {
                    self.lut_commands += 1;
                    if d.params[0..4] != [3, 128, 1, 0]
                        || d.datalen != 512
                        || buf[..512]
                            .iter()
                            .enumerate()
                            .any(|(i, &q)| q != (i % self.queues as usize) as u8)
                    {
                        d.retval = 14;
                    }
                }
                _ => {}
            }
            d.flags |= AQ_FLAG_DD | AQ_FLAG_CMP;
            core::ptr::write_volatile(self.atq.add(slot), d);
            self.csr
                .write32(REG_PF_ATQH, ((slot + 1) % AQ_RING_LEN as usize) as u32);
        }
    }
}

struct Fixture {
    hardware: Option<Hardware>,
    firmware: Box<Firmware>,
    _memory: DmaBuffer,
}
impl Fixture {
    fn new(queues: u16, device_id: u16) -> Self {
        let mut memory = alloc_coherent(rss::CSR_END as usize, DomainId::DRIVER_0).unwrap();
        memory.as_mut_slice().fill(0);
        let csr = MmioRegion {
            phys: memory.phys_addr(),
            virt: memory.as_mut_ptr() as u64,
            len: memory.len() as u64,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        // SAFETY: fixture-owned MMIO backing, no physical NIC operations.
        unsafe {
            csr.write32(REG_GLNVM_ULD, GLNVM_ULD_READY);
            csr.write32(REG_PFLAN_QALLOC, (1 << 31) | (7 << 16));
            csr.write32(hmc::REG_GLHMC_LANQMAX, 8);
            csr.write32(hmc::REG_GLHMC_LANTXOBJSZ, 7);
            csr.write32(hmc::REG_GLHMC_LANRXOBJSZ, 5);
        }
        let buffer = || alloc_coherent(AQ_BUF_BYTES, DomainId::DRIVER_0).unwrap();
        let atq = buffer();
        let arq = buffer();
        let atq_bufs: Vec<_> = (0..AQ_RING_LEN).map(|_| buffer()).collect();
        let arq_bufs: Vec<_> = (0..AQ_RING_LEN).map(|_| buffer()).collect();
        for (i, buffer) in arq_bufs.iter().enumerate() {
            let mut d = AqDesc {
                flags: AQ_FLAG_BUF | AQ_FLAG_LB,
                datalen: AQ_BUF_BYTES as u16,
                ..AqDesc::default()
            };
            set_desc_buf_addr(&mut d, buffer.dma_addr().raw());
            // SAFETY: unpublished, fixture-owned descriptor rings, bounded slot.
            unsafe {
                write_desc(&atq, i, AqDesc::default());
                write_desc(&arq, i, d);
            }
        }
        let mut firmware = Box::new(Firmware {
            csr,
            cpu: narf_lib::percpu::current_cpu(),
            atq: atq.cpu_mut_ptr_at::<AqDesc>(0),
            buffers: atq_bufs
                .iter()
                .map(|buf| buf.cpu_mut_ptr_at::<u8>(0))
                .collect(),
            properties: [0; 128],
            queues,
            resets: 0,
            stall_reset: false,
            reject_vsi: false,
            key_commands: 0,
            lut_commands: 0,
            mapping_commands: 0,
        });
        let hardware = Hardware {
            csr,
            atq: ManuallyDrop::new(atq),
            arq: ManuallyDrop::new(arq),
            atq_bufs: ManuallyDrop::new(atq_bufs),
            arq_bufs: ManuallyDrop::new(arq_bufs),
            atq_next: IrqSafeSpinLock::new(0),
            arq_ntc: IrqSafeSpinLock::new(0),
            atq_busy: AtomicBool::new(false),
            device_id,
            port_num: 0,
            fw: FirmwareVersion::default(),
            mac: [0; 6],
            link_state: AtomicU64::new(0),
            pf_id: 0,
            base_queue: 0,
            vsi_seid: 0,
            vsi: vsi::VsiParams::default(),
            // SAFETY: fixture MMIO reports bounded, supported HMC geometry.
            hmc: ManuallyDrop::new(unsafe {
                hmc::LanHmc::alloc(&csr, 0, queues as u32, queues as u32).unwrap()
            }),
            queues: ManuallyDrop::new(
                (0..queues)
                    .map(|q| IrqSafeSpinLock::new(ring::QueuePair::alloc(q).unwrap()))
                    .collect(),
            ),
            rss: rss::RssConfig::default(),
            reset_discarded: 0,
            interrupts: Some(interrupts::Interrupts::simulated(csr, queues)),
        };
        *MODEL.lock() = &mut *firmware as *mut Firmware as usize;
        if !PUMP_REGISTERED.swap(true, Ordering::AcqRel) {
            narf_scheduler::sleep_pumps::register_nested_only(pump);
        }
        Self {
            hardware: Some(hardware),
            firmware,
            _memory: memory,
        }
    }
    fn edit<R>(&mut self, f: impl FnOnce(&mut Firmware) -> R) -> R {
        let _guard = MODEL.lock();
        f(&mut self.firmware)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.edit(|fw| {
            fw.stall_reset = false;
            fw.reject_vsi = false;
        });
        self.hardware.take();
        *MODEL.lock() = 0;
    }
}

fn smoke_i40e_multiqueue_firmware_rebuild() -> TestResult {
    let mut fixture = Fixture::new(4, I40E_DEV_SFP_XL710);
    let hw = fixture.hardware.as_mut().unwrap();
    if hw.initialize(false).is_err() {
        return TestResult::Fail("model PF initialization failed");
    }
    let csr = hw.csr;
    for q in 0..4 {
        // SAFETY: fixture-owned MMIO; offset is bounded by the four queues.
        unsafe {
            if csr.read32(ring::reg_qrx_ena(q)) != 5
                || csr.read32(ring::reg_qtx_ena(q)) != 5
                || csr.read32(irq::reg_pfint_lnklstn(q)) != q as u32
            {
                return TestResult::Fail("queue mapping/enable chain missing");
            }
        }
    }
    // SAFETY: fixture-owned CSR bank covers the PF RSS registers.
    unsafe {
        if csr.read32(0x00240000) != 0x03020100
            || csr.read32(0x00243f80) != 0x03020100
            || csr.read32(0x00245900) != 1 << 31
            || csr.read32(0x00245980) != (1 << 1) | (1 << 9) | (1 << 11)
        {
            return TestResult::Fail("PF RSS key/table/hash programming wrong");
        }
    }
    let (rx_prod, rx_cons) = channel();
    let (tx_prod, tx_cons) = channel();
    let device = Arc::new(I40eNic::new(
        fixture.hardware.take().unwrap(),
        rx_cons,
        tx_prod,
    ));
    let (lease, _) = device.lease().unwrap();
    let packet = crate::i40e::tests::tcp_packet(false, 10);
    device.transmit(&packet).unwrap();
    let selected = device.rss.tx_queue(&packet, 4);
    if !lease.queues[selected].lock().tx_pending() {
        return TestResult::Fail("flow TX did not select hardware queue");
    }
    lease.irq().fail();
    let mut cx = Context::from_waker(Waker::noop());
    // This unsubmitted IPC frame must survive recovery in the same TX task.
    let mut tx_prod = device.tx_ipc_ring.lock().take().unwrap();
    let buffer = alloc_coherent(packet.len(), DomainId::DRIVER_0).unwrap();
    let mut frame = Frame::new(buffer, packet.len() as u32);
    frame.payload_mut().copy_from_slice(&packet);
    tx_prod.try_send(frame).unwrap();
    let mut tx = pin!(tx_pump(device.clone(), tx_cons));
    assert!(tx.as_mut().poll(&mut cx).is_pending());
    let mut recovery = pin!(recovery_pump(device.clone()));
    assert!(recovery.as_mut().poll(&mut cx).is_pending());
    if device.lease().is_some() || device.link_up() || fixture.edit(|fw| fw.resets) != 0 {
        return TestResult::Fail("recovery did not withdraw publication before waiting for leases");
    }
    drop(lease);
    // Fail one rebuild after successful reset. It must remain unpublished and
    // retry without replacing the registered interface or its IPC endpoints.
    fixture.edit(|fw| fw.reject_vsi = true);
    let failed = narf_scheduler::responsive_spin_until(
        || {
            pump();
            let _ = recovery.as_mut().poll(&mut cx);
            device.recovery_status().failed_attempts == 1
        },
        narf_time::Deadline::after_ms(1000),
    );
    if !failed || device.lease().is_some() || device.dropped_frames().0 != 1 {
        return TestResult::Fail(
            "failed rebuild published hardware or lost abandoned TX accounting",
        );
    }
    fixture.edit(|fw| fw.reject_vsi = false);
    let restored = narf_scheduler::responsive_spin_until(
        || {
            pump();
            let _ = recovery.as_mut().poll(&mut cx);
            device.recovery_status().generation == 1
        },
        narf_time::Deadline::after_ms(1000),
    );
    if !restored
        || !device.link_up()
        || device.queue_count() != 4
        || device.rx_ipc_ring.lock().is_none()
    {
        return TestResult::Fail("retry failed to restore stable interface");
    }
    let (hw, _) = device.lease().unwrap();
    if hw.queues.iter().any(|q| q.lock().tx_pending())
        || hw.vsi.tc0_queue_count() != 4
        || hw.vsi.qs_handle_0 != 19
        || fixture.edit(|fw| fw.mapping_commands) != 2
    {
        return TestResult::Fail("rebuild retained stale ring state or lost VSI queue handles");
    }
    let _ = tx.as_mut().poll(&mut cx);
    if !hw.queues[selected].lock().tx_pending() {
        return TestResult::Fail("IPC TX did not resume after recovery");
    }
    // Keep the compatibility RX producer alive for the duration of the test.
    drop(rx_prod);
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_multiqueue_firmware_rebuild);

fn smoke_i40e_x722_rss_and_reset_timeout() -> TestResult {
    let mut fixture = Fixture::new(2, I40E_DEV_SFP_X722);
    if fixture
        .hardware
        .as_mut()
        .unwrap()
        .initialize(false)
        .is_err()
    {
        return TestResult::Fail("X722 AQ RSS setup failed");
    }
    if fixture.edit(|fw| (fw.key_commands, fw.lut_commands)) != (1, 1) {
        return TestResult::Fail("X722 omitted key/LUT AQ commands");
    }
    fixture
        .hardware
        .as_ref()
        .unwrap()
        .transmit(&crate::i40e::tests::tcp_packet(false, 8))
        .unwrap();
    // Cancel an in-flight AQ command: its DMA must stay owned until reset.
    {
        let hw = fixture.hardware.as_ref().unwrap();
        let mut command = pin!(hw.refresh_link_async());
        assert!(command
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        if !hw.atq_busy.load(Ordering::Acquire) {
            return TestResult::Fail("AQ future failed to retain transaction ownership");
        }
    }
    if !fixture.hardware.as_ref().unwrap().irq().failed()
        || fixture
            .hardware
            .as_ref()
            .unwrap()
            .atq_busy
            .load(Ordering::Acquire)
    {
        return TestResult::Fail(
            "AQ cancellation failed to poison PF and release transaction gate",
        );
    }
    let ring_phys = fixture.hardware.as_ref().unwrap().queues[0]
        .lock()
        .tx_ring_phys();
    fixture.edit(|fw| fw.stall_reset = true);
    {
        let hw = fixture.hardware.as_mut().unwrap();
        let mut reset = pin!(hw.recover());
        let mut cx = Context::from_waker(Waker::noop());
        let mut result = None;
        let completed = narf_scheduler::responsive_spin_until(
            || {
                pump();
                if let Poll::Ready(value) = reset.as_mut().poll(&mut cx) {
                    result = Some(value);
                    true
                } else {
                    false
                }
            },
            narf_time::Deadline::after_ms(1500),
        );
        if !completed || result != Some(Err(I40eError::PfResetTimeout)) {
            return TestResult::Fail("stuck reset did not time out");
        }
    }
    let hw = fixture.hardware.as_ref().unwrap();
    if hw.reset_discarded != 0
        || hw.queues[0].lock().tx_ring_phys() != ring_phys
        || !hw.queues.iter().any(|q| q.lock().tx_pending())
    {
        return TestResult::Fail("failed reset reclaimed in-flight DMA");
    }
    fixture.edit(|fw| fw.stall_reset = false);
    if narf_scheduler::block_on_spin(fixture.hardware.as_mut().unwrap().recover()).is_err() {
        return TestResult::Fail("reset retry failed");
    }
    if fixture.edit(|fw| (fw.key_commands, fw.lut_commands)) != (2, 2) {
        return TestResult::Fail("recovery lost X722 RSS configuration");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_x722_rss_and_reset_timeout);

fn smoke_i40e_all_queues_deliver_and_rearm() -> TestResult {
    let mut fixture = Fixture::new(4, I40E_DEV_SFP_XL710);
    fixture
        .hardware
        .as_mut()
        .unwrap()
        .initialize(false)
        .unwrap();
    let (rx_prod, rx_cons) = channel();
    let (tx_prod, _tx_cons) = channel();
    let device = Arc::new(I40eNic::new(
        fixture.hardware.take().unwrap(),
        rx_cons,
        tx_prod,
    ));
    let delivery = Arc::new(IrqSafeSpinLock::new(rx_prod));
    let mut consumer = device.rx_ipc_ring.lock().take().unwrap();
    let (hw, _) = device.lease().unwrap();
    let mut workers = Vec::new();
    let mut cx = Context::from_waker(Waker::noop());
    for q in 0..4 {
        let mut bytes = crate::i40e::tests::tcp_packet(false, 16);
        bytes[54] = q as u8;
        ring::runtime_tests::inject_rx(&hw.queues[q].lock(), &bytes);
        // Exercise the real handler cookie: only this queue's dynamic control
        // may be masked, then its own drain must rearm it.
        narf_interrupts::dispatch::on_irq(hw.irq().queue_vector(q));
        // SAFETY: fixture-owned MMIO; offset is bounded by the four queues.
        unsafe {
            if hw.csr.read32(irq::reg_pfint_dyn_ctln(q as u16)) & 1 != 0 {
                return TestResult::Fail("queue interrupt did not mask its own route");
            }
        }
        let mut worker = Box::pin(queue_pump(device.clone(), q, delivery.clone()));
        assert!(worker.as_mut().poll(&mut cx).is_pending());
        workers.push(worker);
        let frame = consumer.try_recv().unwrap().unwrap();
        if frame.payload() != bytes || !frame.rx_meta().csum_l4 {
            return TestResult::Fail("nonzero hardware queue lost payload or checksum metadata");
        }
        // SAFETY: fixture-owned MMIO; offset is bounded by the four queues.
        unsafe {
            if hw.csr.read32(irq::reg_pfint_dyn_ctln(q as u16)) & 1 == 0 {
                return TestResult::Fail("queue drain failed to rearm interrupt");
            }
        }
    }
    hw.irq().fail();
    for q in 0..4 {
        // SAFETY: fixture-owned MMIO; offset is bounded by the four queues.
        unsafe {
            if hw.csr.read32(irq::reg_pfint_dyn_ctln(q)) & 1 != 0 {
                return TestResult::Fail("fatal PF left another queue armed");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_all_queues_deliver_and_rearm);

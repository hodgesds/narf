use super::*;
use alloc::boxed::Box;
use core::{future::Future, pin::Pin, sync::atomic::AtomicU32};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Card(u16);
impl crate::drm_registry::DrmCard for Card {
    fn name(&self) -> &str {
        "client-shader-model"
    }
    fn driver(&self) -> &str {
        "amdgpu"
    }
    fn vendor_id(&self) -> u16 {
        0x1002
    }
    fn device_id(&self) -> u16 {
        self.0
    }
    fn subsystem_vendor(&self) -> u16 {
        0
    }
    fn subsystem_device(&self) -> u16 {
        0
    }
    fn vbios_version(&self) -> Option<&str> {
        None
    }
    fn gpu_busy_percent(&self) -> Option<u32> {
        None
    }
    fn power_state(&self) -> &str {
        "D0"
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    NoShader,
    Corrupt,
    Overrun,
    WrongRoot,
    Fence,
    Terminal,
    Interrupt,
    Pending,
}
struct Model {
    fault: Fault,
    issued: AtomicU32,
    interrupts: Arc<AtomicU32>,
    first: IrqSafeSpinLock<Option<Arc<gem::GemObject>>>,
}
impl Submitter for Model {
    fn ring_for(&self, ip: u32, instance: u32, ring: u32) -> Option<u32> {
        if instance != 0 || ring != 0 {
            return None;
        }
        match ip {
            uapi::AMDGPU_HW_IP_GFX => Some(0),
            uapi::AMDGPU_HW_IP_COMPUTE => Some(1),
            _ => None,
        }
    }
    fn submit<'a>(
        &'a self,
        space: &'a vm::VmState,
        submission: &'a Submission,
        _health: &'a Arc<amdgpu_ctx::Health>,
    ) -> Pin<Box<dyn Future<Output = Result<u64, FsError>> + Send + 'a>> {
        Box::pin(async move {
            let ib = submission.ibs[0];
            let ring = self.ring_for(ib.ip_type, ib.ip_instance, ib.ring).unwrap();
            assert_eq!(submission.ibs.len(), 1);
            assert_eq!(ib.flags, uapi::AMDGPU_IB_FLAG_EMIT_MEM_SYNC);
            assert!(space.pasid().unwrap() != 0 && space.root_pde().is_some());
            let own = space.mapped_object(VA).unwrap();
            // Follow the actual mapped object and leaf rather than a fixed
            // fake VMID0 aperture. Both peers use identical virtual addresses.
            let leaf = space.leaf_entry(VA).unwrap();
            assert_eq!(
                leaf & 0x0000_ffff_ffff_f000,
                own.placement().gpu & 0x0000_ffff_ffff_f000
            );
            assert_eq!(
                leaf & (vm::PTE_VALID
                    | vm::PTE_SYSTEM
                    | vm::PTE_READABLE
                    | vm::PTE_WRITEABLE
                    | vm::PTE_EXECUTABLE),
                vm::PTE_VALID
                    | vm::PTE_SYSTEM
                    | vm::PTE_READABLE
                    | vm::PTE_WRITEABLE
                    | vm::PTE_EXECUTABLE
            );
            let object = {
                let mut first = self.first.lock();
                if first.is_none() {
                    *first = Some(own.clone());
                }
                if self.fault == Fault::WrongRoot {
                    first.as_ref().unwrap().clone()
                } else {
                    own
                }
            };
            let placement = object.placement();
            let word = |at: u64| {
                let pair = placement.load_u64(at & !7).unwrap();
                (pair >> ((at & 7) * 8)) as u32
            };
            let mut registers = alloc::collections::BTreeMap::new();
            let mut at = ib.va_start - VA;
            let end = at + u64::from(ib.length_dw) * 4;
            let mut dispatch = false;
            while at < end {
                let header = word(at);
                let length = ((header >> 16) & 0x3fff) + 2;
                match (header >> 8) & 255 {
                    0x76 => {
                        for i in 2..length {
                            registers.insert(word(at + 4) + i - 2, word(at + u64::from(i) * 4));
                        }
                    }
                    0x15 => {
                        assert_eq!(
                            [word(at + 4), word(at + 8), word(at + 12), word(at + 16)],
                            [1, 1, 1, 0x8045]
                        );
                        dispatch = true;
                    }
                    0x10 => {}
                    _ => return Err(FsError::InvalidData),
                }
                at += u64::from(length) * 4;
            }
            assert!(dispatch);
            assert_eq!(
                u64::from(registers[&0x20c]) << 8 | u64::from(registers[&0x20d]) << 40,
                VA
            );
            let output = u64::from(registers[&0x240]) | u64::from(registers[&0x241]) << 32;
            if self.fault != Fault::NoShader {
                for lane in 0..32u32 {
                    let mut v = [lane, 0];
                    let mut pc = 0;
                    while pc < 8 {
                        match word(pc * 4) {
                            0x3000_0082 => v[0] <<= 2,
                            0xbf87_0001 => {}
                            0x3a02_0002 => v[1] = registers[&0x242] ^ v[0],
                            0xee06_8000 => {
                                assert_eq!(
                                    [word((pc + 1) * 4), word((pc + 2) * 4)],
                                    [0x008c_0000, 0]
                                );
                                let dst = output - VA + u64::from(v[0]);
                                let aligned = dst & !7;
                                let shift = (dst & 7) * 8;
                                let old = placement.load_u64(aligned).unwrap();
                                let value = v[1] ^ u32::from(self.fault == Fault::Corrupt);
                                placement
                                    .store_u64(
                                        aligned,
                                        (old & !(u64::from(u32::MAX) << shift))
                                            | u64::from(value) << shift,
                                    )
                                    .unwrap();
                                pc += 2;
                            }
                            0xbfc1_0000 => {}
                            0xbfb0_0000 => break,
                            _ => return Err(FsError::InvalidData),
                        }
                        pc += 1;
                    }
                }
                if self.fault == Fault::Overrun {
                    placement.store_u64(shader::OUTPUT_OFFSET + 128, 0).unwrap();
                }
            }
            if self.fault == Fault::Pending {
                // Published shader writes with no returned completion receipt.
                core::future::pending::<()>().await;
            }
            self.interrupts.fetch_add(1, Ordering::SeqCst);
            let sequence = self.issued.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(u64::from(ring) << 32 | u64::from(sequence))
        })
    }
    fn signalled(&self, _: u64) -> bool {
        self.fault != Fault::Fence
    }
    fn error(&self, _: u64) -> Option<FsError> {
        (self.fault == Fault::Terminal).then_some(FsError::Canceled)
    }
    fn wait(
        &self,
        _: u64,
        _: u64,
    ) -> Pin<Box<dyn Future<Output = Result<bool, FsError>> + Send + '_>> {
        Box::pin(async { Ok(self.fault != Fault::Fence) })
    }
}
struct Events {
    count: Arc<AtomicU32>,
    fault: Fault,
}
impl Observer for Events {
    async fn sample(
        &mut self,
        source: Source,
    ) -> Result<crate::amdgpu_navi48_interrupts::Sample, crate::amdgpu_ih7::Error> {
        Ok(crate::amdgpu_navi48_interrupts::Sample {
            source,
            count: u64::from(self.count.load(Ordering::SeqCst)),
            cpu: 0,
            vector: Some(0x70),
        })
    }
    async fn observed(
        &mut self,
        sample: crate::amdgpu_navi48_interrupts::Sample,
    ) -> Result<bool, crate::amdgpu_ih7::Error> {
        if self.fault == Fault::Interrupt {
            return Err(crate::amdgpu_ih7::Error::Protocol);
        }
        Ok(u64::from(self.count.load(Ordering::SeqCst)) == sample.count + 1)
    }
}
fn run(did: u16, engines: u8, fault: Fault) -> Result<Proof, FsError> {
    let card = crate::drm_registry::register_drm_card(Arc::new(Card(did)));
    let gate = narf_scheduler::block_on_spin(gem::lock_placement_live(card))?;
    let owned = prepare(card, &gate)?;
    let count = Arc::new(AtomicU32::new(0));
    let model = Model {
        fault,
        issued: AtomicU32::new(0),
        interrupts: count.clone(),
        first: IrqSafeSpinLock::new(None),
    };
    let mut events = Events { count, fault };
    narf_scheduler::block_on_spin(execute(&owned, &model, &mut events, engines))
}
fn client_shader_uses_two_owned_roots_on_both_rdna4_dies() -> TestResult {
    for (did, engines) in [(0x7550, 4), (0x7590, 2)] {
        let Ok(proof) = run(did, engines, Fault::None) else {
            return TestResult::Fail("client shader model failed");
        };
        if proof.pasids[0] == proof.pasids[1]
            || proof.roots[0] == proof.roots[1]
            || !proof.msi_verified
            || proof.lanes != 32
            || proof.tickets[0].contains(&0)
            || proof.tickets[1].iter().any(|t| t >> 32 != 1)
        {
            return TestResult::Fail("not independent clients and queues");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48",
    client_shader_uses_two_owned_roots_on_both_rdna4_dies
);
fn client_shader_fence_cannot_replace_output_or_peer_guards() -> TestResult {
    for fault in [
        Fault::NoShader,
        Fault::Corrupt,
        Fault::Overrun,
        Fault::WrongRoot,
    ] {
        if run(0x7590, 2, fault) != Err(FsError::InvalidData) {
            return TestResult::Fail("incorrect output passed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48",
    client_shader_fence_cannot_replace_output_or_peer_guards
);
fn client_shader_requires_real_fence_interrupt_and_healthy_context() -> TestResult {
    for (fault, error) in [
        (Fault::Fence, FsError::TimedOut),
        (Fault::Terminal, FsError::Canceled),
        (Fault::Interrupt, FsError::InvalidData),
    ] {
        if run(0x7550, 4, fault) != Err(error) {
            return TestResult::Fail("incomplete client job passed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48",
    client_shader_requires_real_fence_interrupt_and_healthy_context
);
fn client_shader_owned_helpers_reject_foreign_card_admission() -> TestResult {
    let card = crate::drm_registry::register_drm_card(Arc::new(Card(0x7590)));
    let other = crate::drm_registry::register_drm_card(Arc::new(Card(0x7550)));
    let gate = narf_scheduler::block_on_spin(gem::lock_placement_live(card)).unwrap();
    if gem::GemState::for_card(other)
        .create_kernel_system(BYTES, &gate)
        .err()
        != Some(FsError::InvalidData)
    {
        return TestResult::Fail("foreign gate allocated client memory");
    }
    let owned = prepare(card, &gate).unwrap();
    if vm::VmState::for_card(other).map_kernel_object(
        &gate,
        1,
        owned.clients[0].object.clone(),
        VA,
        0xe,
    ) != Err(FsError::InvalidData)
    {
        return TestResult::Fail("foreign gate mapped client memory");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48",
    client_shader_owned_helpers_reject_foreign_card_admission
);

fn client_shader_cancelled_publication_keeps_owned_bo_and_tables() -> TestResult {
    use core::task::{Context, Waker};
    let card = crate::drm_registry::register_drm_card(Arc::new(Card(0x7590)));
    let gate = narf_scheduler::block_on_spin(gem::lock_placement_live(card)).unwrap();
    let storage = Mutex::new(Some(prepare(card, &gate).unwrap()));
    let mut retained = narf_scheduler::block_on_spin(storage.lock());
    let clients = &retained.as_ref().unwrap().clients;
    let roots = [clients[0].vm.root_phys(), clients[1].vm.root_phys()];
    let weak = Arc::downgrade(&clients[0].placement);
    let count = Arc::new(AtomicU32::new(0));
    let model = Model {
        fault: Fault::Pending,
        issued: AtomicU32::new(0),
        interrupts: count.clone(),
        first: IrqSafeSpinLock::new(None),
    };
    let mut events = Events {
        count,
        fault: Fault::None,
    };
    let mut future = Box::pin(execute(retained.as_ref().unwrap(), &model, &mut events, 2));
    if !future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending()
    {
        return TestResult::Fail("model did not stop after uncertain publication");
    }
    drop(future);
    // Cancellation releases the future's borrows, not the retained owner.
    drop(retained);
    retained = narf_scheduler::block_on_spin(storage.lock());
    let owned = retained.as_ref().unwrap();
    if weak.upgrade().is_none()
        || roots
            != [
                owned.clients[0].vm.root_phys(),
                owned.clients[1].vm.root_phys(),
            ]
        || owned
            .clients
            .iter()
            .any(|c| c.vm.pasid().is_none() || c.vm.mapping_count() != 1)
    {
        return TestResult::Fail("cancelled shader released client backing");
    }
    // The independent model is now stopped; only tests may drop this owner
    // without a real hardware completion/full-reset receipt.
    *retained = None;
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48",
    client_shader_cancelled_publication_keeps_owned_bo_and_tables
);

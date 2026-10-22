use super::*;
use alloc::{boxed::Box, collections::BTreeMap};
use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicU32, AtomicU8},
    task::{Context, Poll},
};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Card(u16);
impl crate::drm_registry::DrmCard for Card {
    fn name(&self) -> &str {
        "native-draw-model"
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
#[repr(u8)]
enum Fault {
    None,
    NoPixels,
    Guard,
    WrongRoot,
    Fence,
    Terminal,
    Interrupt,
    Pending,
}
struct Model {
    fixture: Fixture,
    ready: AtomicBool,
    fault: AtomicU8,
    issued: AtomicU32,
    stopped: AtomicBool,
    interrupts: Arc<AtomicU32>,
    first: IrqSafeSpinLock<Option<Arc<gem::GemPlacement>>>,
}
impl Model {
    fn fault(&self) -> Fault {
        match self.fault.load(Ordering::Acquire) {
            1 => Fault::NoPixels,
            2 => Fault::Guard,
            3 => Fault::WrongRoot,
            4 => Fault::Fence,
            5 => Fault::Terminal,
            6 => Fault::Interrupt,
            7 => Fault::Pending,
            _ => Fault::None,
        }
    }
    fn stop(&self) {
        // Independent model stop receipt: only now can uncertain GPU accesses
        // cease and VM/CS retirement release the actual backing allocations.
        self.ready.store(false, Ordering::Release);
        self.stopped.store(true, Ordering::Release);
        self.first.lock().take();
    }
}
impl Submitter for Model {
    fn ring_for(&self, ip: u32, instance: u32, ring: u32) -> Option<u32> {
        (ip == uapi::AMDGPU_HW_IP_GFX && instance == 0 && ring == 0).then_some(0)
    }
    fn submit<'a>(
        &'a self,
        space: &'a vm::VmState,
        submission: &'a Submission,
        _: &'a Arc<amdgpu_ctx::Health>,
    ) -> Pin<Box<dyn Future<Output = Result<u64, FsError>> + Send + 'a>> {
        Box::pin(async move {
            if !self.ready.load(Ordering::Acquire) {
                return Err(FsError::Busy);
            }
            let ib = submission.ibs[0];
            assert_eq!(submission.ibs.len(), 1);
            assert_eq!(ib.va_start, draw::VA + draw::IB);
            assert_eq!(ib.length_dw, self.fixture.ib_dwords());
            assert_eq!(ib.flags, uapi::AMDGPU_IB_FLAG_EMIT_MEM_SYNC);
            assert_eq!(self.ring_for(ib.ip_type, ib.ip_instance, ib.ring), Some(0));
            let code = space.mapped_object(draw::VA).unwrap().placement();
            let data = space
                .mapped_object(draw::VA + draw::CODE_BYTES)
                .unwrap()
                .placement();
            let code_leaf = space.leaf_entry(draw::VA).unwrap();
            let data_leaf = space.leaf_entry(draw::VA + draw::CODE_BYTES).unwrap();
            assert_eq!(
                code_leaf & (vm::PTE_READABLE | vm::PTE_WRITEABLE | vm::PTE_EXECUTABLE),
                vm::PTE_READABLE | vm::PTE_EXECUTABLE
            );
            assert_eq!(
                data_leaf & (vm::PTE_READABLE | vm::PTE_WRITEABLE | vm::PTE_EXECUTABLE),
                vm::PTE_READABLE | vm::PTE_WRITEABLE
            );
            assert_ne!(
                code_leaf & 0x0000_ffff_ffff_f000,
                data_leaf & 0x0000_ffff_ffff_f000
            );
            let word = |offset: u64| {
                let (p, at) = if offset < draw::CODE_BYTES {
                    (&code, offset)
                } else {
                    (&data, offset - draw::CODE_BYTES)
                };
                (p.load_u64(at & !7).unwrap() >> ((at & 7) * 8)) as u32
            };
            // Fetch actual IB and shader bytes through this VM's retained
            // code BO. A native fence never substitutes for graphics state.
            for (i, v) in self.fixture.pm4.iter().enumerate() {
                assert_eq!(word(draw::IB + i as u64 * 4), *v);
            }
            for at in (0..140).step_by(4) {
                assert_eq!(word(at), self.fixture.word(at, 0, false));
            }
            for at in (0x1000..0x1034).step_by(4) {
                assert_eq!(word(at), self.fixture.word(at, 0, false));
            }
            let mut registers = BTreeMap::new();
            let mut pos = 0usize;
            let mut draw_at = None;
            let mut bottom_before = false;
            let mut bottom_after = false;
            while pos < self.fixture.pm4.len() {
                let h = word(draw::IB + pos as u64 * 4);
                let n = ((h >> 16) & 0x3fff) as usize + 2;
                let op = (h >> 8) & 255;
                let payload = &self.fixture.pm4[pos + 1..pos + n];
                match op {
                    0x69 | 0x76 | 0x79 | 0x7a => {
                        let base = match op {
                            0x69 => 0x28000,
                            0x76 => 0xb000,
                            _ => 0x30000,
                        };
                        for (i, v) in payload[1..].iter().enumerate() {
                            registers.insert(base + ((payload[0] & 0xffff) + i as u32) * 4, *v);
                        }
                    }
                    0xb8 | 0xba | 0xbe => {
                        let base = match op {
                            0xb8 => 0x28000,
                            0xba => 0xb000,
                            _ => 0x30000,
                        };
                        for pair in payload.chunks_exact(2) {
                            registers.insert(base + pair[0] * 4, pair[1]);
                        }
                    }
                    0x49 if payload[0] & 0x3f == 0x28 => {
                        if draw_at.is_some() {
                            bottom_after = true;
                        } else {
                            bottom_before = true;
                        }
                    }
                    0x2d => {
                        assert_eq!(payload, &[3, 2]);
                        assert!(draw_at.replace(pos).is_none());
                    }
                    0x15 => panic!("compute dispatch cannot prove a draw"),
                    _ => {}
                }
                pos += n;
            }
            assert!(draw_at.is_some() && bottom_before && bottom_after);
            assert_eq!(registers[&0xb224], (draw::VA >> 8) as u32);
            assert_eq!(registers[&0xb020], ((draw::VA + 0x1000) >> 8) as u32);
            assert_eq!(registers[&0x28c60], ((draw::VA + draw::TARGET) >> 8) as u32);
            assert_eq!(registers[&0x28c78], 63 | (63 << 16));
            assert_eq!(registers[&0x28250], 7 | (11 << 16));
            assert_eq!(registers[&0x28254], 35 | (33 << 16));
            assert_eq!(
                [
                    registers[&0xb038],
                    registers[&0xb03c],
                    registers[&0xb040],
                    registers[&0xb044]
                ],
                [1.0f32.to_bits(), 0, 0, 1.0f32.to_bits()]
            );
            assert_eq!(
                registers[&0x309a0],
                ((draw::VA
                    + draw::GE
                    + if self.fixture.target == 1200 {
                        0x2c0000
                    } else {
                        0x580000
                    })
                    >> 16) as u32
            );
            let destination = {
                let mut first = self.first.lock();
                if first.is_none() {
                    *first = Some(data.clone());
                }
                if self.fault() == Fault::WrongRoot {
                    first.as_ref().unwrap().clone()
                } else {
                    data.clone()
                }
            };
            if self.fault() != Fault::NoPixels {
                // Model only the fixed primary NGG position and PS color
                // exports after actual state/ISA fetch. Pixel bounds come
                // from DCN-independent GFX12 inclusive raster scissors.
                let tl = registers[&0x28250];
                let br = registers[&0x28254];
                for y in (tl >> 16)..=(br >> 16) {
                    for x in (tl & 0xffff)..=(br & 0xffff) {
                        let at = draw::TARGET - draw::CODE_BYTES
                            + u64::from(y) * draw::PITCH
                            + u64::from(x) * 4;
                        let shift = (at & 7) * 8;
                        let prev = destination.load_u64(at & !7).unwrap();
                        destination
                            .store_u64(
                                at & !7,
                                (prev & !(u64::from(u32::MAX) << shift))
                                    | u64::from(draw::COLOR) << shift,
                            )
                            .unwrap();
                    }
                }
                if self.fault() == Fault::Guard {
                    destination
                        .store_u64(draw::TARGET - draw::CODE_BYTES + 0x4000, 0)
                        .unwrap();
                }
            }
            let seq = self.issued.fetch_add(1, Ordering::AcqRel) + 1;
            if self.fault() == Fault::Pending {
                core::future::pending::<()>().await;
            }
            self.interrupts.fetch_add(1, Ordering::AcqRel);
            Ok(u64::from(seq))
        })
    }
    fn signalled(&self, ticket: u64) -> bool {
        self.stopped.load(Ordering::Acquire)
            || (self.fault() != Fault::Fence
                && u64::from(self.issued.load(Ordering::Acquire)) >= ticket)
    }
    fn retired(&self, ticket: u64) -> bool {
        self.stopped.load(Ordering::Acquire)
            || (self.fault() == Fault::None && self.signalled(ticket))
    }
    fn error(&self, _: u64) -> Option<FsError> {
        (self.fault() == Fault::Terminal).then_some(FsError::Canceled)
    }
    fn wait(
        &self,
        _: u64,
        _: u64,
    ) -> Pin<Box<dyn Future<Output = Result<bool, FsError>> + Send + '_>> {
        Box::pin(async { Ok(self.fault() != Fault::Fence) })
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
            count: u64::from(self.count.load(Ordering::Acquire)),
            cpu: 0,
            vector: Some(0x70),
        })
    }
    async fn observed(
        &mut self,
        s: crate::amdgpu_navi48_interrupts::Sample,
    ) -> Result<bool, crate::amdgpu_ih7::Error> {
        if self.fault == Fault::Interrupt {
            return Err(crate::amdgpu_ih7::Error::Protocol);
        }
        Ok(u64::from(self.count.load(Ordering::Acquire)) == s.count + 1)
    }
}
fn input(chip: crate::amdgpu_rdna4::Rdna4Chip, pfp_version: u32) -> Inputs {
    Inputs {
        chip,
        max_se: if chip == crate::amdgpu_rdna4::Rdna4Chip::Navi44 {
            2
        } else {
            4
        },
        pfp_version,
    }
}
fn model(owned: &Owned) -> Arc<Model> {
    Arc::new(Model {
        fixture: owned.fixture,
        ready: AtomicBool::new(true),
        fault: AtomicU8::new(0),
        issued: AtomicU32::new(0),
        stopped: AtomicBool::new(false),
        interrupts: Arc::new(AtomicU32::new(0)),
        first: IrqSafeSpinLock::new(None),
    })
}
fn run(owned: &Owned, m: &Model, fault: Fault) -> Result<Proof, FsError> {
    m.fault.store(fault as u8, Ordering::Release);
    m.first.lock().take();
    narf_scheduler::block_on_spin(execute(
        owned,
        m,
        &mut Events {
            count: m.interrupts.clone(),
            fault,
        },
    ))
}
fn native_draw_covers_both_targets_and_full_pixel_guards() -> TestResult {
    for chip in crate::amdgpu_rdna4::Rdna4Chip::ALL {
        let card = crate::drm_registry::register_drm_card(Arc::new(Card(
            if chip == crate::amdgpu_rdna4::Rdna4Chip::Navi44 {
                0x7590
            } else {
                0x7550
            },
        )));
        let gate = narf_scheduler::block_on_spin(gem::lock_placement_live(card)).unwrap();
        let owned = prepare(card, &gate, input(chip, 2680)).unwrap();
        let m = model(&owned);
        crate::amdgpu_cs::register_submitter(card, m.clone());
        let p = run(&owned, m.as_ref(), Fault::None).unwrap();
        assert_eq!(p.drawn_pixels, 667);
        assert_eq!(p.untouched_pixels, 3429);
        assert!(p.msi_verified);
        assert_ne!(p.roots[0], p.roots[1]);
        assert_ne!(p.pasids[0], p.pasids[1]);
        assert!(p.tickets[1] > p.tickets[0]);
        m.stop();
        drop(owned);
        crate::amdgpu_cs::retire(card, &|ticket| m.retired(ticket));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48",
    native_draw_covers_both_targets_and_full_pixel_guards
);
fn native_draw_refuses_fence_only_output_uncertainty_and_unready_queue() -> TestResult {
    let card = crate::drm_registry::register_drm_card(Arc::new(Card(0x7590)));
    let gate = narf_scheduler::block_on_spin(gem::lock_placement_live(card)).unwrap();
    let owned = prepare(
        card,
        &gate,
        input(crate::amdgpu_rdna4::Rdna4Chip::Navi44, 2630),
    )
    .unwrap();
    let m = model(&owned);
    crate::amdgpu_cs::register_submitter(card, m.clone());
    m.ready.store(false, Ordering::Release);
    assert_eq!(run(&owned, m.as_ref(), Fault::None), Err(FsError::Busy));
    assert_eq!(m.issued.load(Ordering::Acquire), 0);
    m.ready.store(true, Ordering::Release);
    for (f, error) in [
        (Fault::NoPixels, FsError::InvalidData),
        (Fault::Guard, FsError::InvalidData),
        (Fault::WrongRoot, FsError::InvalidData),
        (Fault::Fence, FsError::TimedOut),
        (Fault::Terminal, FsError::Canceled),
        (Fault::Interrupt, FsError::InvalidData),
    ] {
        assert_eq!(run(&owned, m.as_ref(), f), Err(error));
    }
    m.fault.store(Fault::Pending as u8, Ordering::Release);
    m.first.lock().take();
    let before = Arc::strong_count(&owned.clients[0].objects[1]);
    let mut events = Events {
        count: m.interrupts.clone(),
        fault: Fault::Pending,
    };
    let mut future = Box::pin(execute(&owned, m.as_ref(), &mut events));
    let mut cx = Context::from_waker(core::task::Waker::noop());
    assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
    drop(future);
    assert!(Arc::strong_count(&owned.clients[0].objects[1]) >= before);
    assert!(!m.retired(u64::from(m.issued.load(Ordering::Acquire))));
    // An API error/cancel never pretends to free memory. The independent
    // modeled hardware stop is required before actual VM/CS retirement.
    m.stop();
    drop(owned);
    crate::amdgpu_cs::retire(card, &|ticket| m.retired(ticket));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48",
    native_draw_refuses_fence_only_output_uncertainty_and_unready_queue
);
fn native_draw_fixture_refuses_missing_topology_and_tracks_pfp_boundary() -> TestResult {
    for chip in crate::amdgpu_rdna4::Rdna4Chip::ALL {
        let old = Fixture::new(input(chip, 2679)).unwrap();
        let new = Fixture::new(input(chip, 2680)).unwrap();
        assert!(!old.pm4.contains(&0xc000_ef00));
        assert!(new.pm4.contains(&0xc000_ef00));
        let mut bad = input(chip, 2680);
        bad.max_se = 0;
        assert!(Fixture::new(bad).is_err());
        assert!(Fixture::new(input(chip, 0)).is_ok());
        assert_eq!(
            old.word(draw::TARGET + 11 * draw::PITCH + 7 * 4, 0, true),
            draw::COLOR
        );
        assert_ne!(
            old.word(draw::TARGET + 11 * draw::PITCH + 6 * 4, 0, true),
            draw::COLOR
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48",
    native_draw_fixture_refuses_missing_topology_and_tracks_pfp_boundary
);

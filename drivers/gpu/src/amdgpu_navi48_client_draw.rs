//! Actual GFX12 NGG/PS rectangle through native client jobs and distinct roots.
//! Uncertain jobs keep every code, data, geometry-ring and page-table owner.
use super::{Arc, OWNER, READ_GENERATION, SHADER_PROOF, SUBMITTER};
use crate::amdgpu_cs::{Ib, Submission, Submitter};
use crate::amdgpu_gfx12_draw::{self as draw, Fixture, Inputs};
use crate::amdgpu_navi48_interrupts::{NativeObserver, Observer, Source};
use crate::{amdgpu_ctx, amdgpu_gem as gem, amdgpu_uapi as uapi, amdgpu_vm as vm};
use alloc::{vec, vec::Vec};
use core::sync::atomic::Ordering;
use narf_filesystem::FsError;
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof {
    pub target: u16,
    pub width: u32,
    pub height: u32,
    pub drawn_pixels: u32,
    pub untouched_pixels: u32,
    pub geometry_bytes: u64,
    pub pasids: [u16; 2],
    pub roots: [u64; 2],
    pub tickets: [u64; 2],
    pub msi_verified: bool,
}
struct Client {
    _gem: gem::GemState,
    _contexts: amdgpu_ctx::CtxState,
    vm: vm::VmState,
    objects: [Arc<gem::GemObject>; 2],
    placements: [Arc<gem::GemPlacement>; 2],
    context: u32,
    health: Arc<amdgpu_ctx::Health>,
}
impl Client {
    fn load(&self, offset: u64) -> Option<u64> {
        if offset < draw::CODE_BYTES {
            self.placements[0].load_u64(offset)
        } else {
            self.placements[1].load_u64(offset - draw::CODE_BYTES)
        }
    }
    fn store(&self, offset: u64, value: u64) -> Option<()> {
        if offset < draw::CODE_BYTES {
            self.placements[0].store_u64(offset, value)
        } else {
            self.placements[1].store_u64(offset - draw::CODE_BYTES, value)
        }
    }
}
struct Owned {
    fixture: Fixture,
    clients: [Client; 2],
}
static RETAINED: Mutex<Option<Owned>> = Mutex::new(None);
static RESULT: IrqSafeSpinLock<Option<(u64, Result<Proof, FsError>)>> = IrqSafeSpinLock::new(None);
pub(super) fn result(generation: u64) -> Option<Result<Proof, FsError>> {
    RESULT
        .lock()
        .filter(|(g, _)| *g == generation)
        .map(|(_, r)| r)
}
fn prepare(card: u32, gate: &gem::PlacementGuard, inputs: Inputs) -> Result<Owned, FsError> {
    let fixture = Fixture::new(inputs)?;
    let client = || {
        let objects = gem::GemState::for_card(card);
        let (code_handle, code) = objects.create_kernel_system(draw::CODE_BYTES, gate)?;
        let (data_handle, data) =
            objects.create_kernel_system(fixture.bytes() - draw::CODE_BYTES, gate)?;
        let space = vm::VmState::for_card(card);
        if space.geometry() != vm::Geometry::GMC12 {
            return Err(FsError::InvalidData);
        }
        space.map_kernel_object(
            gate,
            code_handle,
            code.clone(),
            draw::VA,
            uapi::AMDGPU_VM_PAGE_READABLE | uapi::AMDGPU_VM_PAGE_EXECUTABLE,
        )?;
        space.map_kernel_object(
            gate,
            data_handle,
            data.clone(),
            draw::VA + draw::CODE_BYTES,
            uapi::AMDGPU_VM_PAGE_READABLE | uapi::AMDGPU_VM_PAGE_WRITEABLE,
        )?;
        let contexts = amdgpu_ctx::CtxState::new();
        let context = contexts.alloc(0)?;
        let health = contexts.health(context).ok_or(FsError::NotFound)?;
        Ok(Client {
            _gem: objects,
            _contexts: contexts,
            vm: space,
            placements: [code.placement(), data.placement()],
            objects: [code, data],
            context,
            health,
        })
    };
    let clients = [client()?, client()?];
    let [a, b] = &clients;
    if a.vm.root_pde() == b.vm.root_pde()
        || a.vm.pasid().is_none()
        || b.vm.pasid().is_none()
        || a.vm.pasid() == b.vm.pasid()
        || Arc::ptr_eq(&a.objects[0], &b.objects[0])
        || Arc::ptr_eq(&a.objects[1], &b.objects[1])
    {
        return Err(FsError::InvalidData);
    }
    Ok(Owned { fixture, clients })
}
fn write(owned: &Owned, index: usize) -> Result<(), FsError> {
    let f = owned.fixture;
    for at in (0..f.bytes()).step_by(8) {
        let value =
            u64::from(f.word(at, index, false)) | u64::from(f.word(at + 4, index, false)) << 32;
        owned.clients[index]
            .store(at, value)
            .ok_or(FsError::BadAddress)?;
    }
    core::sync::atomic::fence(Ordering::SeqCst);
    Ok(())
}
fn check(owned: &Owned, index: usize, drawn: bool) -> Result<(), FsError> {
    let f = owned.fixture;
    core::sync::atomic::fence(Ordering::SeqCst);
    for at in (0..f.bytes()).step_by(8) {
        if f.geometry(at) {
            continue;
        }
        let value =
            u64::from(f.word(at, index, drawn)) | u64::from(f.word(at + 4, index, drawn)) << 32;
        if owned.clients[index].load(at) != Some(value) {
            return Err(FsError::InvalidData);
        }
    }
    Ok(())
}
async fn execute(
    owned: &Owned,
    engine: &dyn Submitter,
    observer: &mut impl Observer,
) -> Result<Proof, FsError> {
    let f = owned.fixture;
    let pixels = draw::RECT[2] * draw::RECT[3];
    let mut proof = Proof {
        target: f.target,
        width: draw::WIDTH,
        height: draw::HEIGHT,
        drawn_pixels: pixels,
        untouched_pixels: draw::WIDTH * draw::HEIGHT - pixels,
        geometry_bytes: f.ge_bytes,
        pasids: core::array::from_fn(|i| owned.clients[i].vm.pasid().unwrap()),
        roots: core::array::from_fn(|i| owned.clients[i].vm.root_pde().unwrap()),
        tickets: [0; 2],
        msi_verified: true,
    };
    for i in 0..2 {
        write(owned, i)?;
    }
    for i in 0..2 {
        let client = &owned.clients[i];
        let before = observer
            .sample(Source::Graphics)
            .await
            .map_err(|_| FsError::InvalidData)?;
        if before.vector.is_none() {
            return Err(FsError::InvalidData);
        }
        let submission = Submission {
            ctx_id: client.context,
            ibs: vec![Ib {
                va_start: draw::VA + draw::IB,
                length_dw: f.ib_dwords(),
                ip_type: uapi::AMDGPU_HW_IP_GFX,
                ip_instance: 0,
                ring: 0,
                flags: uapi::AMDGPU_IB_FLAG_EMIT_MEM_SYNC,
            }],
            in_syncobjs: Vec::new(),
            out_syncobjs: Vec::new(),
            bo_handles: None,
            dependencies: Vec::new(),
            user_fence: None,
        };
        let ticket = engine
            .submit(&client.vm, &submission, &client.health)
            .await?;
        // Publication never precedes retained BO/root ownership. No await
        // separates its returned ticket from this VM lifetime receipt.
        client.vm.note_job(ticket);
        proof.tickets[i] = ticket;
        let deadline =
            narf_time::monotonic_ns().saturating_add(crate::amdgpu_ring_watch::JOB_TIMEOUT_NS);
        if ticket == 0
            || ticket >> 32 != 0
            || (i == 1 && ticket <= proof.tickets[0])
            || !engine.wait(ticket, deadline).await?
        {
            return Err(FsError::TimedOut);
        }
        if let Some(e) = engine.error(ticket).or_else(|| client.health.error()) {
            return Err(e);
        }
        loop {
            if observer
                .observed(before)
                .await
                .map_err(|_| FsError::InvalidData)?
            {
                break;
            }
            if narf_time::monotonic_ns() >= deadline {
                return Err(FsError::TimedOut);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(100).as_instant()).await;
        }
        // The IB includes the actual CB/GL2-to-host cache barrier and a
        // BOTTOM_OF_PIPE PWS wait before its outer native fence/RPTR/EOP.
        // A fence without pixels, an old root, or a write into the peer fails.
        for peer in 0..2 {
            check(owned, peer, peer <= i)?;
        }
    }
    Ok(proof)
}

pub(super) async fn prove() {
    if !SHADER_PROOF.load(Ordering::Acquire) {
        return;
    }
    let inputs = {
        let owner = OWNER.lock().await;
        owner
            .as_ref()
            .filter(|boot| matches!(boot.shader_result(), Some(Ok(_))))
            .and_then(|boot| boot.draw_inputs())
            .map(|inputs| (*READ_GENERATION.lock(), inputs))
    };
    let Some((input_generation, inputs)) = inputs else {
        return;
    };
    let Some(engine) = SUBMITTER.lock().clone() else {
        return;
    };
    let generation = engine.generation;
    if generation != input_generation {
        return;
    }
    let mut retained = RETAINED.lock().await;
    if result(generation).is_some() {
        return;
    }
    let outcome = async {
        let _runtime = crate::amdgpu_navi48_runtime_pm::access()
            .await
            .map_err(|_| FsError::NoDevice)?;
        let gate = gem::lock_placement_live(engine.card).await?;
        if *READ_GENERATION.lock() != generation {
            return Err(FsError::NoDevice);
        }
        // quiesce withdraws the old SUBMITTER before advancing generation;
        // restart publishes a matching successor only after whole-device
        // reset and fresh queue/IH proofs. Thus the matching generation above
        // proves old DMA stopped, even if its prior proof was canceled before
        // submit returned a ticket. Every other path retains this owner.
        *retained = Some(prepare(engine.card, &gate, inputs)?);
        *RESULT.lock() = Some((generation, Err(FsError::Busy)));
        narf_time::timeout(
            narf_time::Deadline::after_us(10_000_000),
            execute(
                retained.as_ref().unwrap(),
                engine.as_ref(),
                &mut NativeObserver,
            ),
        )
        .await
        .map_err(|_| FsError::TimedOut)?
    }
    .await;
    *RESULT.lock() = Some((generation, outcome));
    use core::fmt::Write;
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: RDNA4 native rectangle proof {outcome:?}"
    );
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_client_draw_tests.rs"]
mod tests;

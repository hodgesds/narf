//! Opt-in client-address-space compute proof. Hardware completion alone is
//! insufficient: two independent roots map the same VA to different BOs.
//! Retained storage survives cancellation, timeout and reset uncertainty.
use super::{Arc, OWNER, READ_GENERATION, SHADER_PROOF, SUBMITTER};
use crate::amdgpu_cs::{Ib, Submission, Submitter};
use crate::amdgpu_gfx12_shader as shader;
use crate::amdgpu_navi48_interrupts::{NativeObserver, Observer, Source};
use crate::{amdgpu_ctx, amdgpu_gem as gem, amdgpu_uapi as uapi, amdgpu_vm as vm};
use alloc::{vec, vec::Vec};
use core::sync::atomic::Ordering;
use narf_filesystem::FsError;
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};

const VA: u64 = 0x20_0000;
const BYTES: u64 = 8192;
const WORDS: usize = BYTES as usize / 4;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof {
    pub pasids: [u16; 2],
    pub roots: [u64; 2],
    /// [graphics, compute][first address space, second address space].
    pub tickets: [[u64; 2]; 2],
    pub lanes: u32,
    pub msi_verified: bool,
}
struct Client {
    // Keep the actual per-open handle/context tables, VM root, PASID and BO
    // address lease alive even if submission is canceled after publication.
    _gem: gem::GemState,
    _contexts: amdgpu_ctx::CtxState,
    vm: vm::VmState,
    object: Arc<gem::GemObject>,
    placement: Arc<gem::GemPlacement>,
    context: u32,
    health: Arc<amdgpu_ctx::Health>,
}
struct Owned {
    clients: [Client; 2],
}
// Never hold an IRQ-safe lock across an await. This async mutex retains
// uncertain storage; a successor generation may replace it only after the
// native full-reset/restart path has registered the replacement submitter.
static RETAINED: Mutex<Option<Owned>> = Mutex::new(None);
static RESULT: IrqSafeSpinLock<Option<(u64, Result<Proof, FsError>)>> = IrqSafeSpinLock::new(None);
pub(super) fn result(generation: u64) -> Option<Result<Proof, FsError>> {
    RESULT
        .lock()
        .filter(|(g, _)| *g == generation)
        .map(|(_, r)| r)
}
fn prepare(card: u32, gate: &gem::PlacementGuard) -> Result<Owned, FsError> {
    let client = || {
        let objects = gem::GemState::for_card(card);
        let (handle, object) = objects.create_kernel_system(BYTES, gate)?;
        let space = vm::VmState::for_card(card);
        if space.geometry() != vm::Geometry::GMC12 {
            return Err(FsError::InvalidData);
        }
        space.map_kernel_object(
            gate,
            handle,
            object.clone(),
            VA,
            uapi::AMDGPU_VM_PAGE_READABLE
                | uapi::AMDGPU_VM_PAGE_WRITEABLE
                | uapi::AMDGPU_VM_PAGE_EXECUTABLE,
        )?;
        let contexts = amdgpu_ctx::CtxState::new();
        let context = contexts.alloc(0)?;
        let health = contexts.health(context).ok_or(FsError::NotFound)?;
        Ok(Client {
            _gem: objects,
            _contexts: contexts,
            vm: space,
            placement: object.placement(),
            object,
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
        || Arc::ptr_eq(&a.object, &b.object)
    {
        return Err(FsError::InvalidData);
    }
    Ok(Owned { clients })
}
fn image(engines: u8, queue: usize, client: usize) -> Result<Vec<u32>, FsError> {
    let mut words = vec![shader::POISON; WORDS];
    words[..shader::PROGRAM.len()].copy_from_slice(&shader::PROGRAM);
    let ib = shader::ib(
        VA,
        VA + shader::OUTPUT_OFFSET,
        engines,
        shader::SALTS[queue] ^ ((client as u32 + 1) << 24),
    )
    .map_err(|_| FsError::InvalidData)?;
    let at = shader::IB_OFFSET as usize / 4;
    words[at..at + ib.len()].copy_from_slice(&ib);
    Ok(words)
}
fn write(client: &Client, words: &[u32]) -> Result<(), FsError> {
    for (i, pair) in words.chunks_exact(2).enumerate() {
        client
            .placement
            .store_u64(i as u64 * 8, u64::from(pair[0]) | u64::from(pair[1]) << 32)
            .ok_or(FsError::BadAddress)?;
    }
    // Ordinary Job publication performs HDP request/ack and the requested
    // GC12 system-scope cache synchronization before dispatch.
    core::sync::atomic::fence(Ordering::SeqCst);
    Ok(())
}
fn check(client: &Client, expected: &[u32]) -> Result<(), FsError> {
    core::sync::atomic::fence(Ordering::SeqCst);
    for (i, pair) in expected.chunks_exact(2).enumerate() {
        let want = u64::from(pair[0]) | u64::from(pair[1]) << 32;
        if client.placement.load_u64(i as u64 * 8) != Some(want) {
            return Err(FsError::InvalidData);
        }
    }
    Ok(())
}
async fn execute(
    owned: &Owned,
    engine: &dyn Submitter,
    observer: &mut impl Observer,
    engines: u8,
) -> Result<Proof, FsError> {
    let mut proof = Proof {
        pasids: core::array::from_fn(|i| owned.clients[i].vm.pasid().unwrap()),
        roots: core::array::from_fn(|i| owned.clients[i].vm.root_pde().unwrap()),
        tickets: [[0; 2]; 2],
        lanes: shader::LANES,
        msi_verified: true,
    };
    for (queue, source) in [Source::Graphics, Source::Compute].into_iter().enumerate() {
        let mut expected = [image(engines, queue, 0)?, image(engines, queue, 1)?];
        for (client, words) in owned.clients.iter().zip(&expected) {
            write(client, words)?;
        }
        for client_index in 0..2 {
            let client = &owned.clients[client_index];
            let before = observer
                .sample(source)
                .await
                .map_err(|_| FsError::InvalidData)?;
            proof.msi_verified &= before.vector.is_some();
            let submission = Submission {
                ctx_id: client.context,
                ibs: vec![Ib {
                    va_start: VA + shader::IB_OFFSET,
                    length_dw: 256,
                    ip_type: if queue == 0 {
                        uapi::AMDGPU_HW_IP_GFX
                    } else {
                        uapi::AMDGPU_HW_IP_COMPUTE
                    },
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
            // No await separates returned publication from its VM lifetime
            // receipt. RETAINED already holds all BOs and roots before submit.
            client.vm.note_job(ticket);
            proof.tickets[queue][client_index] = ticket;
            let deadline =
                narf_time::monotonic_ns().saturating_add(crate::amdgpu_ring_watch::JOB_TIMEOUT_NS);
            if ticket == 0 || ticket >> 32 != queue as u64 || !engine.wait(ticket, deadline).await?
            {
                return Err(FsError::TimedOut);
            }
            if let Some(error) = engine.error(ticket).or_else(|| client.health.error()) {
                return Err(error);
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
            let start = shader::OUTPUT_OFFSET as usize / 4;
            for lane in 0..shader::LANES as usize {
                expected[client_index][start + lane] =
                    shader::SALTS[queue] ^ ((client_index as u32 + 1) << 24) ^ (lane as u32 * 4);
            }
            // Check both spaces, including untouched peer output and every
            // code/IB/guard word. A stale root or cross-client write fails.
            for (client, words) in owned.clients.iter().zip(&expected) {
                check(client, words)?;
            }
        }
    }
    Ok(proof)
}

pub(super) async fn prove() {
    if !SHADER_PROOF.load(Ordering::Acquire) {
        return;
    }
    // The initial VMID0 proof worker holds OWNER until both queue proofs
    // drain. Do not retain OWNER while acquiring client placement admission.
    let ready = {
        let owner = OWNER.lock().await;
        owner
            .as_ref()
            .is_some_and(|boot| matches!(boot.shader_result(), Some(Ok(_))))
    };
    if !ready {
        return;
    }
    let engine = { SUBMITTER.lock().clone() };
    let Some(engine) = engine else {
        return;
    };
    let generation = engine.generation;
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
        // A different registered generation follows a completed full reset.
        // Its proof may finally replace the previous uncertain owned storage.
        *retained = Some(prepare(engine.card, &gate)?);
        *RESULT.lock() = Some((generation, Err(FsError::Busy)));
        let engines = crate::amdgpu::with_controller(|gpu| gpu.gc_info.map(|gc| gc.num_se))
            .flatten()
            .and_then(|n| u8::try_from(n).ok())
            .ok_or(FsError::InvalidData)?;
        narf_time::timeout(
            narf_time::Deadline::after_us(10_000_000),
            execute(
                retained.as_ref().unwrap(),
                engine.as_ref(),
                &mut NativeObserver,
                engines,
            ),
        )
        .await
        .map_err(|_| FsError::TimedOut)?
    }
    .await;
    *RESULT.lock() = Some((generation, outcome));
    // Retain even successful objects until the next proved reset. This keeps
    // diagnostics simple and costs exactly two 8 KiB BOs plus their page tables.
    use core::fmt::Write;
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: RDNA4 client shader proof {outcome:?}"
    );
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_client_shader_tests.rs"]
mod tests;

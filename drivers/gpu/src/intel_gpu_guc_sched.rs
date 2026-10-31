//! Owned GuC scheduling for kernel GGTT/PPGTT and nonsecure userspace work.
//!
//! Linux reference: ~/git/linux b90c984d615e8ce2af96f5b1411a962d83fed2ad,
//! MIT xe_guc_submit.c, xe_lrc.c, xe_guc_ads.c and their ABI headers.
//! Scheduling acknowledgments are not job completion. Retirement additionally
//! requires the GPU breadcrumb and exact saved ring head after deregistration.

use crate::{
    intel_gpu_aux::MmioWindow,
    intel_gpu_context::{ContextError, ContextSeed},
    intel_gpu_exec::ResidentBatch,
    intel_gpu_fence::{CompletionFence, JobError},
    intel_gpu_gt::GtPlatform,
    intel_gpu_guc::GuCMessage,
    intel_gpu_guc_boot::BootAllocator,
    intel_gpu_guc_transport::{TransportError, XeLpgTransport},
    intel_gpu_rcs::{GpuBacking, SubmitError},
};
use alloc::{sync::Arc, vec::Vec};
use core::{
    mem::ManuallyDrop,
    sync::atomic::{fence, Ordering},
};

const REGS: u64 = 4096;
const BREADCRUMB: u64 = 0x800;
const TIMEOUT: u64 = 5_000_000_000;
const MAX_CONTEXTS: usize = 64;

/// Firmware context identities are reusable after deregistration. Request
/// stamps are independent, so a prior TLB ACK/breadcrumb cannot complete a
/// new incarnation. The final TLB ACK is our reclamation/reuse barrier.
struct Identities {
    used: u64,
    next_id: u16,
    next_stamp: u32,
}
impl Identities {
    const fn new() -> Self {
        Self {
            used: 0,
            next_id: 1,
            next_stamp: 1,
        }
    }
    fn candidate(&self, live: impl Fn(u32) -> bool) -> Result<(u16, u32), SchedulingError> {
        let id = (0..64)
            .map(|n| (self.next_id - 1 + n) % 64 + 1)
            .find(|id| self.used & (1u64 << (id - 1)) == 0)
            .ok_or(SchedulingError::Full)?;
        let mut stamp = self.next_stamp;
        while live(stamp) {
            stamp = ((stamp + 1) & 0x7fffffff).max(1);
        }
        Ok((id, stamp))
    }
    fn claim(&mut self, id: u16, stamp: u32) {
        self.used |= 1u64 << (id - 1);
        self.next_id = id % 64 + 1;
        self.next_stamp = ((stamp + 1) & 0x7fffffff).max(1);
    }
    fn retire(&mut self, id: u16) {
        self.used &= !(1u64 << (id - 1));
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SchedulingError {
    State,
    Busy,
    Full,
    Allocation(SubmitError),
    Address,
    Cache,
    Residency(narf_filesystem::FsError),
    Output(narf_filesystem::InstallFdError),
    Defaults(ContextError),
    Protocol,
    Timeout,
    Transport(TransportError),
}

#[derive(Copy, Clone, Debug)]
pub(crate) struct SchedulingAds {
    pub golden: u32,
    pub bytes: u32,
    pub hwsp: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Phase {
    Invalidate,
    Invalidating,
    Register,
    Policy,
    Enable,
    Enabling,
    Running,
    Disable,
    Disabling,
    Deregister,
    Deregistering,
    RetireInvalidate,
    RetireInvalidating,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Defaults {
    Empty,
    Seed(u16),
    Switch(u16),
    Ready,
}

struct Context<B: GpuBacking> {
    id: u16,
    stamp: u32,
    image: B,
    ring: B,
    phase: Phase,
    deadline: u64,
    fence: Arc<CompletionFence>,
    resident: Option<ResidentBatch>,
    user: Option<crate::intel_gpu_user::UserJob>,
    tail: u32,
}

struct Resources<A: BootAllocator> {
    allocator: A,
    hwsp: A::Backing,
    golden: A::Backing,
    contexts: Vec<Context<A::Backing>>,
    seed_image: Option<A::Backing>,
    seed_id: Option<u16>,
    defaults_completion: Option<Arc<CompletionFence>>,
}

pub(crate) struct GuCScheduler<A: BootAllocator> {
    resources: ManuallyDrop<Resources<A>>,
    platform: GtPlatform,
    identities: Identities,
    published: bool,
    lost: bool,
    released: bool,
    defaults: Defaults,
    pristine: bool,
    epoch: u64,
}

impl<A: BootAllocator> GuCScheduler<A> {
    pub(crate) fn allocate(
        mut allocator: A,
        platform: GtPlatform,
    ) -> Result<Self, SchedulingError> {
        let hwsp = allocator.alloc(1).map_err(SchedulingError::Allocation)?;
        if !valid(&hwsp) || !hwsp.coherent_for_device() {
            allocator.free(hwsp);
            return Err(SchedulingError::Cache);
        }
        let pages = if platform == GtPlatform::Battlemage {
            4
        } else {
            14
        };
        let golden = match allocator.alloc(pages) {
            Ok(b) => b,
            Err(e) => {
                allocator.free(hwsp);
                return Err(SchedulingError::Allocation(e));
            }
        };
        if !valid(&golden)
            || golden.size_pages() != pages
            || !golden.coherent_for_device()
            || overlap(&hwsp, &golden)
        {
            allocator.free(golden);
            allocator.free(hwsp);
            return Err(SchedulingError::Address);
        }
        hwsp.zero_fill();
        golden.zero_fill();
        if allocator.sync_for_device(&hwsp).is_err() || allocator.sync_for_device(&golden).is_err()
        {
            allocator.free(golden);
            allocator.free(hwsp);
            return Err(SchedulingError::Cache);
        }
        Ok(Self {
            epoch: crate::intel_gpu_user::next_epoch(),
            resources: ManuallyDrop::new(Resources {
                allocator,
                hwsp,
                golden,
                contexts: Vec::new(),
                seed_image: None,
                seed_id: None,
                defaults_completion: None,
            }),
            platform,
            identities: Identities::new(),
            published: false,
            lost: false,
            released: false,
            defaults: Defaults::Empty,
            pristine: true,
        })
    }

    pub(crate) fn ads(&self) -> SchedulingAds {
        SchedulingAds {
            golden: self.resources.golden.ggtt_offset(),
            bytes: self.resources.golden.size_pages() * 4096,
            hwsp: self.resources.hwsp.ggtt_offset(),
        }
    }

    pub(crate) fn enable_engine(&mut self, mmio: &impl MmioWindow) -> Result<(), SchedulingError> {
        if self.published || self.lost {
            return Err(SchedulingError::State);
        }
        if mmio.read32(0x208c) == u32::MAX {
            return Err(SchedulingError::Protocol);
        }
        // xe_hw_engine_enable_ring: render-well and GT wake are held by GuCGt.
        self.published = true;
        let uc = match self.platform {
            GtPlatform::Integrated(_) => 9,
            GtPlatform::Alchemist => 1,
            GtPlatform::Battlemage => 3,
        };
        mmio.write32(0x20c4, 0x3f7e0000 | uc << 8 | uc << 1);
        mmio.write32(0x20a8, u32::MAX); // runtime owner enables IRQs after startup probes
        mmio.write32(0x2098, u32::MAX);
        mmio.write32(0x2080, self.resources.hwsp.ggtt_offset());
        mmio.write32(0x229c, 0x00080008);
        mmio.write32(0x209c, 0x01000000);
        let _ = mmio.read32(0x209c);
        Ok(())
    }

    /// Execute only an owned kernel probe. No user commands, PPGTT, external
    /// addresses or arbitrary instructions enter this bring-up API.
    pub(crate) fn submit_probe(
        &mut self,
        now: u64,
    ) -> Result<(u16, Arc<CompletionFence>), SchedulingError> {
        self.admit()?;
        self.submit(now, None, None)
    }

    fn admit(&self) -> Result<(), SchedulingError> {
        if matches!(self.defaults, Defaults::Seed(_) | Defaults::Switch(_)) {
            return Err(SchedulingError::Busy);
        }
        Ok(())
    }

    pub(crate) fn defaults_ready(&self) -> bool {
        self.defaults == Defaults::Ready && !self.lost
    }

    pub(crate) fn user_epoch(&self) -> Option<u64> {
        (self.published && self.defaults_ready()).then_some(self.epoch)
    }

    pub(crate) fn submit_user(
        &mut self,
        now: u64,
        context: Arc<crate::intel_gpu_user::UserContext>,
        batch: crate::intel_gpu_user::UserBatch,
        output: Option<&crate::intel_gpu_user::UserOutput<'_>>,
    ) -> Result<(u16, Arc<CompletionFence>), SchedulingError> {
        if self.user_epoch().is_none() || batch.0.platform() != Some(self.platform) {
            return Err(SchedulingError::State);
        }
        let pages = if self.platform == GtPlatform::Battlemage {
            4
        } else {
            14
        };
        let claim = context
            .claim(self.epoch, pages)
            .map_err(SchedulingError::Residency)?;
        self.submit_inner(now, Some(batch.0), None, Some(claim), output)
    }

    pub(crate) fn can_prime(&self) -> bool {
        self.published
            && !self.lost
            && self.pristine
            && self.defaults == Defaults::Empty
            && self.resources.contexts.is_empty()
    }

    pub(crate) fn begin_defaults(
        &mut self,
        seed: ContextSeed,
        now: u64,
    ) -> Result<Arc<CompletionFence>, SchedulingError> {
        if !self.can_prime() {
            return Err(SchedulingError::Busy);
        }
        let (id, _) = self.submit(now, None, Some(seed.commands()))?;
        let completion = Arc::new(CompletionFence::new());
        self.resources.defaults_completion = Some(completion.clone());
        self.defaults = Defaults::Seed(id);
        Ok(completion)
    }

    /// # Safety
    /// The batch and every nested command stream must be trusted kernel code.
    /// It must access only resident mappings, return with BB_END and leave
    /// global/transport/context/ring state and completion evidence untouched.
    /// No CPU, userspace mapping or peer may modify any leaf until the fence
    /// completes or full-engine reset is proven. This does not grant isolated
    /// user 3D execution; isolated user state and coordinated recovery remain gated.
    pub(crate) unsafe fn submit_resident(
        &mut self,
        now: u64,
        batch: ResidentBatch,
    ) -> Result<(u16, Arc<CompletionFence>), SchedulingError> {
        self.admit()?;
        if batch.platform() != Some(self.platform) {
            return Err(SchedulingError::Address);
        }
        self.submit(now, Some(batch), None)
    }

    fn submit(
        &mut self,
        now: u64,
        resident: Option<ResidentBatch>,
        prefix: Option<Vec<u32>>,
    ) -> Result<(u16, Arc<CompletionFence>), SchedulingError> {
        self.submit_inner(now, resident, prefix, None, None)
    }

    fn submit_inner(
        &mut self,
        now: u64,
        resident: Option<ResidentBatch>,
        prefix: Option<Vec<u32>>,
        user: Option<crate::intel_gpu_user::ContextClaim>,
        output: Option<&crate::intel_gpu_user::UserOutput<'_>>,
    ) -> Result<(u16, Arc<CompletionFence>), SchedulingError> {
        if !self.published || self.lost {
            return Err(SchedulingError::State);
        }
        if self.resources.contexts.len() == MAX_CONTEXTS {
            return Err(SchedulingError::Full);
        }
        let (id, stamp) = self
            .identities
            .candidate(|stamp| self.resources.contexts.iter().any(|c| c.stamp == stamp))?;
        let deadline = now.checked_add(TIMEOUT).ok_or(SchedulingError::Timeout)?;
        let r = &mut *self.resources;
        r.contexts
            .try_reserve(1)
            .map_err(|_| SchedulingError::Full)?;
        let pages = if self.platform == GtPlatform::Battlemage {
            4
        } else {
            14
        };
        let image = r
            .allocator
            .alloc(pages)
            .map_err(SchedulingError::Allocation)?;
        let ring = match r.allocator.alloc(2) {
            Ok(b) => b,
            Err(e) => {
                r.allocator.free(image);
                return Err(SchedulingError::Allocation(e));
            }
        };
        let invalid = !valid(&image)
            || !valid(&ring)
            || image.size_pages() != pages
            || ring.size_pages() != 2
            || !image.coherent_for_device()
            || !ring.coherent_for_device()
            || overlap(&image, &ring)
            || r.seed_image
                .as_ref()
                .is_some_and(|old| overlap(old, &image) || overlap(old, &ring))
            || [&r.hwsp, &r.golden]
                .into_iter()
                .any(|old| overlap(old, &image) || overlap(old, &ring))
            || r.contexts.iter().any(|c| {
                [&c.image, &c.ring]
                    .into_iter()
                    .any(|old| overlap(old, &image) || overlap(old, &ring))
            });
        if invalid {
            r.allocator.free(ring);
            r.allocator.free(image);
            return Err(SchedulingError::Address);
        }
        image.zero_fill();
        ring.zero_fill();
        if self.defaults == Defaults::Ready {
            for off in (REGS..u64::from(pages) * 4096).step_by(4) {
                image.write32(off, r.golden.read32(off));
            }
            if let Some(user) = &user {
                user.restore(&image);
            }
            image.write32(REGS + 3 * 4, 0x00090008);
            image.write32(REGS + 5 * 4, 0);
            image.write32(REGS + 9 * 4, ring.ggtt_offset());
            image.write32(REGS + 11 * 4, 0x1001);
            image.write32(REGS + 0x23 * 4, 0);
            for slot in (0x25..=0x33).step_by(2) {
                image.write32(REGS + slot * 4, 0);
            }
        } else {
            context_image(&image, self.platform, ring.ggtt_offset());
        }
        let mutating = resident.is_some() || prefix.is_some();
        let mut words: Vec<u32> = if let Some(prefix) = prefix {
            let mut words = alloc::vec![0x04000001];
            words.extend_from_slice(&prefix);
            render_completion(self.platform, image.ggtt_offset(), stamp, &mut words);
            words
        } else if let Some(batch) = &resident {
            let root = batch.space().root_descriptor();
            // xe_lrc.c::xe_lrc_set_ppgtt: PDP0 on DG2/MTL, PTBP on Xe2.
            image.write32(REGS + 0x31 * 4, (root >> 32) as u32);
            image.write32(REGS + 0x33 * 4, root as u32);
            let mut words = resident_ring(
                self.platform,
                (!batch.skip_batch()).then_some(batch.address()),
                image.ggtt_offset(),
                stamp,
            );
            if let Some((address, value)) = batch.user_fence() {
                // MIT xe_ring_ops.c::emit_store_imm_ppgtt_posted: qword
                // PPGTT store after the render-cache flush, before the owned
                // GGTT breadcrumb. ResidentBatch validated writable residency.
                let before_breadcrumb = words
                    .windows(2)
                    .position(|v| v == [0x7a000004, 0x01104080])
                    .expect("owned completion stream");
                words.splice(
                    before_breadcrumb..before_breadcrumb,
                    [
                        0x10200003,
                        address as u32,
                        (address >> 32) as u32,
                        value as u32,
                        (value >> 32) as u32,
                        0,
                    ],
                );
            }
            words
        } else {
            alloc::vec![
                0x04000001,
                0,
                0x10400002,
                image.ggtt_offset() + BREADCRUMB as u32,
                0,
                stamp,
                0x01000000,
                0,
            ]
        };
        if words.len() % 2 != 0 {
            words.push(0);
        }
        if words.len() > ring.size_pages() as usize * 1024 {
            r.allocator.free(ring);
            r.allocator.free(image);
            return Err(SchedulingError::Full);
        }
        let tail = words.len() as u32 * 4;
        for (i, word) in words.into_iter().enumerate() {
            ring.write32(i as u64 * 4, word);
        }
        image.write32(REGS + 7 * 4, tail);
        let completion = Arc::new(CompletionFence::new());
        if let Some(batch) = &resident {
            if let Err(error) = batch.reserve(&completion) {
                r.allocator.free(ring);
                r.allocator.free(image);
                return Err(SchedulingError::Residency(error));
            }
        }
        if r.allocator.sync_for_device(&image).is_err()
            || r.allocator.sync_for_device(&ring).is_err()
            || resident
                .as_ref()
                .is_some_and(|batch| !batch.publish_for_device())
        {
            r.allocator.free(ring);
            r.allocator.free(image);
            drop(resident);
            completion.signal(Err(JobError::Reset));
            return Err(SchedulingError::Cache);
        }
        if let Some(output) = output {
            if let Err(error) = output.install(completion.clone()) {
                r.allocator.free(ring);
                r.allocator.free(image);
                drop(resident);
                completion.signal(Err(JobError::Reset));
                return Err(SchedulingError::Output(error));
            }
        }
        r.contexts.push(Context {
            user: user.map(|claim| claim.publish(completion.clone())),
            id,
            stamp,
            image,
            ring,
            phase: Phase::Invalidate,
            deadline,
            fence: completion.clone(),
            resident,
            tail,
        });
        if mutating {
            self.pristine = false;
        }
        self.identities.claim(id, stamp);
        Ok((id, completion))
    }

    pub(crate) fn poll<M: MmioWindow>(
        &mut self,
        ct: &mut XeLpgTransport<M, A>,
        now: u64,
    ) -> Result<(), SchedulingError> {
        if self.lost {
            return Err(SchedulingError::State);
        }
        let result = self.progress(ct, now);
        if result.is_err() {
            self.lost = true;
        }
        result
    }

    fn progress<M: MmioWindow>(
        &mut self,
        ct: &mut XeLpgTransport<M, A>,
        now: u64,
    ) -> Result<(), SchedulingError> {
        // Bound one poll even if firmware continuously emits events.
        for _ in 0..64 {
            let Some(message) = ct.receive().map_err(SchedulingError::Transport)? else {
                break;
            };
            self.event(message)?;
        }
        if matches!(self.defaults, Defaults::Seed(_)) && self.resources.seed_image.is_some() {
            let (id, _) = self.submit(now, None, None)?;
            self.defaults = Defaults::Switch(id);
        }
        for context in &mut self.resources.contexts {
            if now >= context.deadline {
                return Err(SchedulingError::Timeout);
            }
            if context.phase == Phase::Running {
                fence(Ordering::Acquire);
                let seq = context.image.read32(BREADCRUMB);
                if seq != 0 && seq != context.stamp {
                    return Err(SchedulingError::Protocol);
                }
                if seq != 0 {
                    context.phase = Phase::Disable;
                }
            }
            let id = u32::from(context.id);
            let (action, payload, next): (u16, Vec<u32>, Phase) = match context.phase {
                Phase::Invalidate => (
                    0x7000,
                    alloc::vec![context.stamp, 0x80000003],
                    Phase::Invalidating,
                ),
                Phase::RetireInvalidate => (
                    0x7000,
                    alloc::vec![context.stamp | 0x80000000, 0x80000003],
                    Phase::RetireInvalidating,
                ),
                Phase::Register => (
                    0x4502,
                    alloc::vec![
                        1,
                        id,
                        0,
                        1,
                        0,
                        0,
                        0,
                        0,
                        0,
                        context.image.ggtt_offset()
                            | if context.resident.is_some() {
                                0x119
                            } else {
                                0x19
                            },
                        0
                    ],
                    Phase::Policy,
                ),
                Phase::Policy => (
                    0x100b,
                    {
                        let (priority, timeslice) = context
                            .user
                            .as_ref()
                            .map_or((3, 1000), |user| user.policy());
                        alloc::vec![
                            id, 0x20030001, priority, 0x20010001, timeslice, 0x20020001, 500000
                        ]
                    },
                    Phase::Enable,
                ),
                Phase::Enable => (0x1001, alloc::vec![id, 1], Phase::Enabling),
                Phase::Disable => (0x1001, alloc::vec![id, 0], Phase::Disabling),
                Phase::Deregister => (0x4503, alloc::vec![id], Phase::Deregistering),
                _ => continue,
            };
            match ct.send(context.id, action, 0, &payload, true) {
                Ok(()) => context.phase = next,
                Err(TransportError::Ct(crate::intel_gpu_guc::GuCError::Full)) => {}
                Err(error) => return Err(SchedulingError::Transport(error)),
            }
        }
        Ok(())
    }

    fn event(&mut self, message: GuCMessage) -> Result<(), SchedulingError> {
        if message.kind != 1 || message.auxiliary >> 16 != 0 {
            return Err(SchedulingError::Protocol);
        }
        let action = message.auxiliary as u16;
        if !matches!(action, 0x1002 | 0x4600 | 0x7001) {
            return Err(SchedulingError::Protocol);
        }
        let len = if action == 0x1002 { 2 } else { 1 };
        if message.payload.len() != len {
            return Err(SchedulingError::Protocol);
        }
        let cookie = message.payload[0];
        let index = self
            .resources
            .contexts
            .iter()
            .position(|c| {
                if action == 0x7001 {
                    c.stamp == cookie & 0x7fffffff
                } else {
                    u32::from(c.id) == cookie
                }
            })
            .ok_or(SchedulingError::Protocol)?;
        let resources = &mut *self.resources;
        let c = &mut resources.contexts[index];
        match (action, c.phase, message.payload.get(1).copied()) {
            (0x7001, Phase::Invalidating, None) if cookie == c.stamp => c.phase = Phase::Register,
            (0x7001, Phase::RetireInvalidating, None) if cookie == (c.stamp | 0x80000000) => {
                fence(Ordering::Acquire);
                if c.image.read32(BREADCRUMB) != c.stamp
                    || c.image.read32(REGS + 5 * 4) & 0x1ffffc != c.tail
                {
                    return Err(SchedulingError::Protocol);
                }
                if let Some(user) = &c.user {
                    resources
                        .allocator
                        .sync_for_cpu(&c.image)
                        .map_err(|_| SchedulingError::Cache)?;
                    user.capture(&c.image).map_err(SchedulingError::Residency)?;
                }
                let c = resources.contexts.remove(index);
                let r = resources;
                r.allocator.free(c.ring);
                if self.defaults == Defaults::Seed(c.id) {
                    r.seed_image = Some(c.image);
                    r.seed_id = Some(c.id);
                } else {
                    r.allocator.free(c.image);
                    self.identities.retire(c.id);
                }
                // Drop all PPGTT tables and BO references before terminal
                // publication. Deregistration and the final TLB ACK are proven.
                drop(c.resident);
                if let Some(user) = c.user {
                    user.finish(false);
                }
                c.fence.signal(Ok(()));
                if self.defaults == Defaults::Switch(c.id) {
                    self.capture_defaults()?;
                }
            }
            (0x1002, Phase::Enabling, Some(1)) => {
                c.phase = Phase::Running;
                c.fence.mark_submitted();
            }
            (0x1002, Phase::Disabling, Some(0)) => c.phase = Phase::Deregister,
            (0x4600, Phase::Deregistering, None) => {
                fence(Ordering::Acquire);
                if c.image.read32(BREADCRUMB) != c.stamp
                    || c.image.read32(REGS + 5 * 4) & 0x1ffffc != c.tail
                {
                    return Err(SchedulingError::Protocol);
                }
                c.phase = Phase::RetireInvalidate;
            }
            _ => return Err(SchedulingError::Protocol),
        }
        Ok(())
    }

    fn capture_defaults(&mut self) -> Result<(), SchedulingError> {
        let r = &mut *self.resources;
        let image = r.seed_image.as_ref().ok_or(SchedulingError::State)?;
        r.allocator
            .sync_for_cpu(image)
            .map_err(|_| SchedulingError::Cache)?;
        // The seed was fully retired, then a different context executed and
        // retired. The image cannot still be resident in the engine.
        if image.read32(REGS + 4) != 0x1108101d
            || image.read32(REGS + 0x33 * 4) != 0
            || image.read32(REGS + 0x31 * 4) != 0
        {
            return Err(SchedulingError::Protocol);
        }
        r.golden.zero_fill();
        for off in (REGS..u64::from(image.size_pages()) * 4096).step_by(4) {
            r.golden.write32(off, image.read32(off));
        }
        r.golden.write32(REGS + 3 * 4, 0x00090008);
        for slot in [5, 7, 9, 0x23] {
            r.golden.write32(REGS + slot * 4, 0);
        }
        r.allocator
            .sync_for_device(&r.golden)
            .map_err(|_| SchedulingError::Cache)?;
        self.defaults = Defaults::Ready;
        self.identities
            .retire(r.seed_id.take().expect("retired seed identity"));
        r.allocator
            .free(r.seed_image.take().expect("owned retired seed"));
        r.defaults_completion
            .as_ref()
            .expect("owned priming fence")
            .signal(Ok(()));
        Ok(())
    }

    /// # Safety
    /// GuC is in reset with firmware DMA idle AND GRDOM_FULL has completed.
    /// No other host owner can re-arm the retired HWS/LRC/GGTT addresses.
    pub(crate) unsafe fn release_after_reset(mut self) {
        self.published = false;
        self.free();
    }

    fn free(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        // SAFETY: called once by Drop before publication, or proven reset.
        let mut r = unsafe { ManuallyDrop::take(&mut self.resources) };
        for c in r.contexts.drain(..) {
            r.allocator.free(c.ring);
            r.allocator.free(c.image);
            drop(c.resident);
            if let Some(user) = c.user {
                user.finish(true);
            }
            c.fence.signal(Err(JobError::Reset));
        }
        if let Some(image) = r.seed_image.take() {
            r.allocator.free(image);
        }
        r.allocator.free(r.golden);
        r.allocator.free(r.hwsp);
        if let Some(completion) = r.defaults_completion {
            completion.signal(Err(JobError::Reset));
        }
    }
}

impl<A: BootAllocator> Drop for GuCScheduler<A> {
    fn drop(&mut self) {
        if !self.published {
            self.free();
        }
    }
}

fn valid(b: &impl GpuBacking) -> bool {
    b.ggtt_offset() >= 0x800000
        && b.ggtt_offset() % 4096 == 0
        && b.size_pages() != 0
        && (b.ggtt_offset() as u64 + b.size_pages() as u64 * 4096) <= 0xfee00000
}
fn overlap(a: &impl GpuBacking, b: &impl GpuBacking) -> bool {
    (a.ggtt_offset() as u64) < b.ggtt_offset() as u64 + b.size_pages() as u64 * 4096
        && (b.ggtt_offset() as u64) < a.ggtt_offset() as u64 + a.size_pages() as u64 * 4096
}

/// Single nonsecure PPGTT render job, following xe_ring_ops.c. Preparser/TLB
/// invalidation precedes the PPGTT batch; HDC/render/depth/data cache drain
/// precedes the separate GGTT post-sync completion write. MTL needs AuxCCS
/// invalidation; DG2 and Xe-LPG need the extra
/// depth flush (Wa_14016712196). All tails are qword aligned.
fn resident_ring(platform: GtPlatform, batch: Option<u64>, image: u32, seq: u32) -> Vec<u32> {
    let mut words = alloc::vec![0x04000001, 0x02800101, 0x7a000404, 0x20344c1c, 0xd0, 0, 0, 0,];
    if matches!(platform, GtPlatform::Integrated(_)) {
        words.extend_from_slice(&[0x11020001, 0x4208, 1, 0]);
    }
    if let Some(batch) = batch {
        words.extend_from_slice(&[
            0x02800100,
            0x18800101,
            batch as u32,
            (batch >> 32) as u32,
            0x04000000,
        ]);
    }
    render_completion(platform, image, seq, &mut words);
    words
}

fn render_completion(platform: GtPlatform, image: u32, seq: u32, words: &mut Vec<u32>) {
    if platform != GtPlatform::Battlemage {
        words.extend_from_slice(&[0x7a000004, 1, 0xd0, 0, 0, 0]);
    }
    words.extend_from_slice(&[
        0x7a000204,
        0x101010a1,
        0,
        0,
        0,
        0,
        0x7a000004,
        0x01104080,
        image + BREADCRUMB as u32,
        0,
        seq,
        0,
        0x01000000,
        0x04000001,
        0x02800000,
    ]);
    if words.len() % 2 != 0 {
        words.push(0);
    }
}

fn context_image(image: &impl GpuBacking, platform: GtPlatform, ring: u32) {
    // Literal register groups from xe_lrc.c's DG2/MTL/Xe2 RCS tables;
    // lengths and command placement differ from the Gen12 execlists codec.
    let groups: &[&[u32]] = &[
        &[
            0x244, 0x034, 0x030, 0x038, 0x03c, 0x168, 0x140, 0x110, 0x1c0, 0x1c4, 0x1c8, 0x180,
            0x2b4, 0x120, 0x124,
        ],
        if platform == GtPlatform::Battlemage {
            &[
                0x3a8, 0x3ac, 0x108, 0x284, 0x280, 0x27c, 0x278, 0x274, 0x270,
            ]
        } else {
            &[
                0x3a8, 0x28c, 0x288, 0x284, 0x280, 0x27c, 0x278, 0x274, 0x270,
            ]
        },
    ];
    let mut cursor = 0u64;
    for group in groups {
        cursor += 1;
        image.write32(REGS + cursor * 4, 0x11081000 | (group.len() as u32 * 2 - 1));
        cursor += 1;
        for offset in *group {
            image.write32(REGS + cursor * 4, 0x2000 + offset);
            cursor += 2;
        }
    }
    let extra: &[u32] = if platform == GtPlatform::Alchemist {
        &[0x1b0, 0x5a8, 0x5ac]
    } else {
        cursor += 2;
        &[0x5a8, 0x5ac]
    };
    image.write32(REGS + cursor * 4, 0x11081000 | (extra.len() as u32 * 2 - 1));
    cursor += 1;
    for offset in extra {
        image.write32(REGS + cursor * 4, 0x2000 + offset);
        cursor += 2;
    }
    cursor += 6;
    image.write32(REGS + cursor * 4, 0x11080001);
    image.write32(REGS + (cursor + 1) * 4, 0x20c8);
    image.write32(REGS + (cursor + 3) * 4, 0x05000001);
    image.write32(REGS + 3 * 4, 0x00090009); // inhibit restore and synchronous switch
    image.write32(REGS + 9 * 4, ring);
    image.write32(REGS + 11 * 4, 0x1001); // 8 KiB ring
                                          // reset_stop_ring() sets the masked STOP_RING disable in value slot
                                          // 0x71 of the later register block; the initial inhibited restore skips it.
    image.write32(REGS + 0x71 * 4, 0x01000000);
}

#[cfg(feature = "kernel-test")]
mod identity_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_identity_pool_full_wrap_and_failed_preview() -> TestResult {
        let mut ids = Identities::new();
        assert_eq!(ids.candidate(|_| false), Ok((1, 1)));
        assert_eq!(
            ids.candidate(|_| false),
            Ok((1, 1)),
            "a failed preparation must not consume an identity"
        );
        for expected in 1..=64 {
            let (id, stamp) = ids.candidate(|_| false).unwrap();
            assert_eq!(id, expected);
            ids.claim(id, stamp);
        }
        assert_eq!(ids.candidate(|_| false), Err(SchedulingError::Full));
        ids.retire(7);
        ids.next_stamp = 0x7fffffff;
        assert_eq!(
            ids.candidate(|s| s == 0x7fffffff || s == 1 || s == 2),
            Ok((7, 3))
        );
        ids.claim(7, 0x7fffffff);
        assert_eq!(ids.next_stamp, 1);
        assert_eq!(ids.candidate(|_| false), Err(SchedulingError::Full));
        ids.retire(7);
        assert_eq!(ids.candidate(|s| s == 1), Ok((7, 2)));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc_gt",
        smoke_identity_pool_full_wrap_and_failed_preview
    );
}

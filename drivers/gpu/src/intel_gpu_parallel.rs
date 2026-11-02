//! Width-two, single-placement GuC groups. MIT Linux b90c984d
//! xe_guc_submit.c::{__register_mlrc_exec_queue,wq_item_append,submit_exec_queue}
//! and xe_guc_submit_types.h. Scratch is a separate owned coherent page,
//! leaving our private PPHWSP breadcrumbs/restore batch undisturbed.
use super::*;

pub(super) struct Lane<B: GpuBacking> {
    pub engine: Engine,
    pub image: B,
    pub ring: B,
    pub tail: u32,
    pub runtime: job_timeout::Runtime,
    pub finished: bool,
}
pub(super) struct Group<B: GpuBacking> {
    pub child: Lane<B>,
    pub scratch: B,
    /// Physical-lane observations remain separate: both lanes can exceed
    /// runtime, and later reset messages must not rewrite timeout attribution.
    pub timeout_lanes: u8,
    pub reset_lanes: u8,
}
impl<B: GpuBacking> Group<B> {
    pub fn backings(&self) -> [&B; 3] {
        [&self.child.image, &self.child.ring, &self.scratch]
    }
    pub fn free<A: BootAllocator<Backing = B>>(self, allocator: &mut A) {
        allocator.free(self.scratch);
        allocator.free(self.child.ring);
        allocator.free(self.child.image);
    }
    pub fn valid_wq(&self) -> bool {
        self.scratch.read32(4) == 20
            && self.scratch.read32(8) == 0
            // SUSPENDED is a named non-error ABI state, not evidence of a
            // guilty context. Lane/runtime and global liveness remain bounded.
            && matches!(self.scratch.read32(12), 1 | 2)
            // Single-use WQ head is diagnostic: firmware publication may lag
            // the lane stores. Deregistration + final TLB ACK revoke all WQ
            // references; both lane saved-head/breadcrumbs prove completion.
            && matches!(self.scratch.read32(0), 0 | 20)
    }
}

pub(super) struct Spec<'a, B: GpuBacking> {
    pub platform: GtPlatform,
    pub engine: Engine,
    pub parent: [&'a B; 2],
    pub parent_tail: u32,
    pub id: u16,
    pub stamp: u32,
    pub resident: &'a ResidentBatch,
    pub user: &'a crate::intel_gpu_user::ContextClaim,
}
pub(super) fn prepare<A: BootAllocator>(
    r: &mut Resources<A>,
    spec: Spec<'_, A::Backing>,
) -> Result<Group<A::Backing>, SchedulingError> {
    let pages = spec.engine.lrc_pages(spec.platform);
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
    let scratch = match r.allocator.alloc(1) {
        Ok(b) => b,
        Err(e) => {
            r.allocator.free(ring);
            r.allocator.free(image);
            return Err(SchedulingError::Allocation(e));
        }
    };
    let mut group = Group {
        child: Lane {
            engine: spec.engine,
            image,
            ring,
            tail: 0,
            runtime: Default::default(),
            finished: false,
        },
        scratch,
        timeout_lanes: 0,
        reset_lanes: 0,
    };
    let result = (|| {
        for (index, b) in group.backings().into_iter().enumerate() {
            if !valid(b)
                || !b.coherent_for_device()
                || b.size_pages() != [pages, 2, 1][index]
                || spec.parent.iter().any(|old| overlap(*old, b))
                || group.backings()[..index].iter().any(|old| overlap(*old, b))
                || r.contexts
                    .iter()
                    .flat_map(Context::backings)
                    .any(|old| overlap(old, b))
                || r.engines
                    .iter()
                    .flat_map(|e| [&e.hwsp, &e.golden])
                    .any(|old| overlap(old, b))
                || r.seed_image.as_ref().is_some_and(|old| overlap(old, b))
                || r.slpc.as_ref().is_some_and(|old| overlap(old, b))
            {
                return Err(SchedulingError::Address);
            }
        }
        let image = &group.child.image;
        let ring = &group.child.ring;
        image.zero_fill();
        ring.zero_fill();
        group.scratch.zero_fill();
        let golden = &state_of(&r.engines, spec.engine).golden;
        for offset in (REGS..u64::from(pages) * 4096).step_by(4) {
            image.write32(offset, golden.read32(offset));
        }
        spec.user.restore_lane(image, 1);
        image.write32(REGS + 3 * 4, 0x00090008);
        image.write32(REGS + 5 * 4, 0);
        image.write32(REGS + 9 * 4, ring.ggtt_offset());
        image.write32(REGS + 11 * 4, 0x1001);
        image.write32(REGS + 0x23 * 4, 0);
        for slot in (0x25..=0x33).step_by(2) {
            image.write32(REGS + slot * 4, 0);
        }
        let root = spec.resident.space().root_descriptor();
        image.write32(REGS + 0x31 * 4, (root >> 32) as u32);
        image.write32(REGS + 0x33 * 4, root as u32);
        let address = (!spec.resident.skip_batch())
            .then_some(spec.resident.parallel().ok_or(SchedulingError::State)?);
        let mut words = if spec.engine.is_copy() {
            crate::intel_gpu_engine::copy_ring(address, None, image.ggtt_offset(), spec.stamp)
        } else {
            resident_ring(
                spec.platform,
                true,
                address,
                image.ggtt_offset(),
                spec.stamp,
            )
        };
        job_timeout::setup(image, spec.platform);
        job_timeout::prefix(image.ggtt_offset(), spec.stamp, spec.engine, &mut words);
        if words.len() % 2 != 0 {
            words.push(0);
        }
        let tail = words.len() as u32 * 4;
        if tail > ring.size_pages() * 4096 {
            return Err(SchedulingError::Address);
        }
        for (i, word) in words.into_iter().enumerate() {
            ring.write32(i as u64 * 4, word);
        }
        image.write32(REGS + 7 * 4, tail);
        group.child.tail = tail;
        // guc_sched_wq_desc is128B; go/join reserved cachelines are zero.
        // WQ_OFFSET=1024,WQ_SIZE=1024; five DW single-use type5 item.
        group.scratch.write32(12, 1);
        let item = [
            0x00040005,
            spec.parent[0].ggtt_offset() | 0x119,
            u32::from(spec.id) | (spec.parent_tail / 8) << 18,
            0,
            tail / 8,
        ];
        for (i, word) in item.into_iter().enumerate() {
            group.scratch.write32(1024 + i as u64 * 4, word);
        }
        if r.allocator.sync_for_device(image).is_err()
            || r.allocator.sync_for_device(ring).is_err()
            || r.allocator.sync_for_device(&group.scratch).is_err()
        {
            return Err(SchedulingError::Cache);
        }
        fence(Ordering::Release);
        group.scratch.write32(4, 20);
        r.allocator
            .sync_for_device(&group.scratch)
            .map_err(|_| SchedulingError::Cache)?;
        Ok(())
    })();
    match result {
        Ok(()) => Ok(group),
        Err(e) => {
            group.free(&mut r.allocator);
            Err(e)
        }
    }
}

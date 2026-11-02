//! Width-two through four, single-placement GuC groups. MIT Linux b90c984d
//! xe_guc_submit.c::{__register_mlrc_exec_queue,wq_item_append,submit_exec_queue}
//! and xe_guc_submit_types.h. Scratch is a separate owned coherent page,
//! leaving private PPHWSP breadcrumbs/restore batches undisturbed.
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
    pub children: Vec<Lane<B>>,
    pub scratch: B,
    /// Bit0 is the parent. Keep independent observations for every lane:
    /// later reset messages must not rewrite earlier timeout attribution.
    pub timeout_lanes: u8,
    pub reset_lanes: u8,
}
impl<B: GpuBacking> Group<B> {
    pub fn width(&self) -> usize {
        self.children.len() + 1
    }
    pub fn backings(&self) -> impl Iterator<Item = &B> {
        core::iter::once(&self.scratch).chain(
            self.children
                .iter()
                .flat_map(|lane| [&lane.image, &lane.ring]),
        )
    }
    pub fn free<A: BootAllocator<Backing = B>>(self, allocator: &mut A) {
        for lane in self.children.into_iter().rev() {
            allocator.free(lane.ring);
            allocator.free(lane.image);
        }
        allocator.free(self.scratch);
    }
    pub fn valid_wq(&self) -> bool {
        let tail = (self.width() as u32 + 3) * 4;
        self.scratch.read32(4) == tail
            && self.scratch.read32(8) == 0
            && matches!(self.scratch.read32(12), 1 | 2)
            // Single-use WQ head is diagnostic; firmware publication may lag
            // lane stores. Deregistration+final TLB ACK revoke all references;
            // every lane's saved head/breadcrumb proves actual completion.
            && (self.scratch.read32(0) == 0 || self.scratch.read32(0) == tail)
    }
}

pub(super) struct Spec<'a, B: GpuBacking> {
    pub platform: GtPlatform,
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
    let engines = spec.user.parallel().ok_or(SchedulingError::State)?;
    let addresses = spec.resident.parallel().ok_or(SchedulingError::State)?;
    if !(2..=crate::intel_gpu_user::MAX_PARALLEL_WIDTH).contains(&engines.len())
        || addresses.len() + 1 != engines.len()
    {
        return Err(SchedulingError::State);
    }
    let mut children = Vec::new();
    children
        .try_reserve_exact(engines.len() - 1)
        .map_err(|_| SchedulingError::Full)?;
    let scratch = r.allocator.alloc(1).map_err(SchedulingError::Allocation)?;
    // Install the owner before fallible lane allocation. Every partial group
    // rolls back together; no identity, WQ or firmware reference exists yet.
    let mut group = Group {
        children,
        scratch,
        timeout_lanes: 0,
        reset_lanes: 0,
    };
    let result = (|| {
        for &engine in &engines[1..] {
            let image = r
                .allocator
                .alloc(engine.lrc_pages(spec.platform))
                .map_err(SchedulingError::Allocation)?;
            let ring = match r.allocator.alloc(2) {
                Ok(ring) => ring,
                Err(e) => {
                    r.allocator.free(image);
                    return Err(SchedulingError::Allocation(e));
                }
            };
            group.children.push(Lane {
                engine,
                image,
                ring,
                tail: 0,
                runtime: Default::default(),
                finished: false,
            });
        }
        if group.scratch.size_pages() != 1
            || group.children.iter().any(|lane| {
                lane.image.size_pages() != lane.engine.lrc_pages(spec.platform)
                    || lane.ring.size_pages() != 2
            })
        {
            return Err(SchedulingError::Address);
        }
        for (index, backing) in group.backings().enumerate() {
            if !valid(backing)
                || !backing.coherent_for_device()
                || spec.parent.iter().any(|old| overlap(*old, backing))
                || group
                    .backings()
                    .take(index)
                    .any(|old| overlap(old, backing))
                || r.contexts
                    .iter()
                    .flat_map(Context::backings)
                    .any(|old| overlap(old, backing))
                || r.engines
                    .iter()
                    .flat_map(|e| [&e.hwsp, &e.golden])
                    .any(|old| overlap(old, backing))
                || r.seed_image
                    .as_ref()
                    .is_some_and(|old| overlap(old, backing))
                || r.slpc.as_ref().is_some_and(|old| overlap(old, backing))
            {
                return Err(SchedulingError::Address);
            }
        }
        group.scratch.zero_fill();
        for (index, lane) in group.children.iter_mut().enumerate() {
            let image = &lane.image;
            let ring = &lane.ring;
            image.zero_fill();
            ring.zero_fill();
            let golden = &state_of(&r.engines, lane.engine).golden;
            for offset in (REGS..u64::from(image.size_pages()) * 4096).step_by(4) {
                image.write32(offset, golden.read32(offset));
            }
            spec.user.restore_lane(image, index + 1);
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
            let address = (!spec.resident.skip_batch()).then_some(addresses[index]);
            let mut words = if lane.engine.is_copy() {
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
            job_timeout::prefix(image.ggtt_offset(), spec.stamp, lane.engine, &mut words);
            if words.len() % 2 != 0 {
                words.push(0);
            }
            lane.tail = words.len() as u32 * 4;
            if lane.tail > ring.size_pages() * 4096 {
                return Err(SchedulingError::Address);
            }
            for (i, word) in words.into_iter().enumerate() {
                ring.write32(i as u64 * 4, word);
            }
            image.write32(REGS + 7 * 4, lane.tail);
            if r.allocator.sync_for_device(image).is_err()
                || r.allocator.sync_for_device(ring).is_err()
            {
                return Err(SchedulingError::Cache);
            }
        }
        //128B descriptor; go/join cachelines remain zero. WQ_OFFSET1024,
        // WQ_SIZE1024. Source WQI has width+3 DW, length excludes its header.
        group.scratch.write32(12, 1);
        let header = ((group.width() as u32 + 2) << 16) | 5;
        let item = [
            header,
            spec.parent[0].ggtt_offset() | 0x119,
            u32::from(spec.id) | (spec.parent_tail / 8) << 18,
            0,
        ];
        for (i, word) in item.into_iter().enumerate() {
            group.scratch.write32(1024 + i as u64 * 4, word);
        }
        for (index, lane) in group.children.iter().enumerate() {
            group
                .scratch
                .write32(1040 + index as u64 * 4, lane.tail / 8);
        }
        r.allocator
            .sync_for_device(&group.scratch)
            .map_err(|_| SchedulingError::Cache)?;
        fence(Ordering::Release);
        group.scratch.write32(4, (group.width() as u32 + 3) * 4);
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

use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn queue() -> KernelQueue {
    KernelQueue {
        kind: QueueType::Compute,
        pipe: 1,
        queue: 3,
        doorbell: 0x174,
        mqd: 0x123400001000,
        write_pointer: 0x123400004008,
    }
}
fn matches(packet: &Packet, fields: &[(usize, u32)]) -> bool {
    packet
        .words()
        .iter()
        .enumerate()
        .all(|(i, word)| *word == fields.iter().find(|f| f.0 == i).map_or(0, |f| f.1))
}
fn mes12_kernel_packets_obey_eight_byte_c_layout() -> TestResult {
    // Golden dword offsets independently checked by compiling Linux's packed
    // unions; every unlisted word must be zero, including alignment padding.
    let mut p = map_kernel_queue(queue()).unwrap();
    p.bind_completion(0x432100002008, 1).unwrap();
    if !matches(
        &p,
        &[
            (0, 0x40021),
            (18, 0x174),
            (20, 0x1000),
            (21, 0x1234),
            (22, 0x4008),
            (23, 0x1234),
            (28, 1),
            (37, 0x2000),
            (38, 0x2008),
            (39, 0x4321),
            (40, 1),
            (50, 1),
            (51, 3),
        ],
    ) {
        return TestResult::Fail("MES12 ADD_QUEUE uses wrong alignment or padding");
    }
    let mut p = unmap_kernel_queue(queue()).unwrap();
    p.bind_completion(0x432100002008, 1).unwrap();
    if !matches(
        &p,
        &[
            (0, 0x40031),
            (1, 0x174),
            (4, 8),
            (6, 0x2008),
            (7, 0x4321),
            (8, 1),
            (10, 1),
            (11, 3),
            (15, 1),
        ],
    ) {
        return TestResult::Fail("MES12 REMOVE_QUEUE uses wrong status/tail alignment");
    }
    let mut p = resources_1(0x123400005000).unwrap();
    p.bind_completion(0x432100002008, 1).unwrap();
    if !matches(
        &p,
        &[
            (0, 0x40131),
            (2, 0x2008),
            (3, 0x4321),
            (4, 1),
            (13, 10),
            (16, 0x5000),
            (17, 0x1234),
        ],
    ) {
        return TestResult::Fail("MES12 resource extension layout");
    }
    let mut p = query_status();
    p.bind_completion(0x432100002010, 0x123456789).unwrap();
    if !matches(
        &p,
        &[
            (0, 0x400b1),
            (2, 0x2010),
            (3, 0x4321),
            (4, 0x23456789),
            (5, 1),
        ],
    ) {
        return TestResult::Fail("MES12 drain-query fence truncated or misplaced");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/mes12",
    mes12_kernel_packets_obey_eight_byte_c_layout
);

fn mes12_resources_and_completion_require_current_protocol() -> TestResult {
    let mut res = Resources {
        bases: Bases {
            gc: [1, 2, 3, 4, 5],
            mmhub: [6, 7, 8, 9, 10],
            osssys: [11, 12, 13, 14, 15],
        },
        queues: QueueMasks::default(),
        scheduler_context: 0x123400001000,
        query_fence: 0x123400001008,
        revision: 0x8a,
    };
    let p = resources(&res).unwrap();
    if !matches(
        &p,
        &[
            (0, 0x40001),
            (22, 0x1000),
            (23, 0x1234),
            (24, 0x1008),
            (25, 0x1234),
            (26, 1),
            (27, 2),
            (28, 3),
            (29, 4),
            (30, 5),
            (34, 6),
            (35, 7),
            (36, 8),
            (37, 9),
            (38, 10),
            (42, 11),
            (43, 12),
            (44, 13),
            (45, 14),
            (46, 15),
            (54, 0x100447),
        ],
    ) {
        return TestResult::Fail("MES12 resources, flags or base-bank padding");
    }
    res.revision = 0x8b;
    if resources(&res).unwrap().words()[55] != 50 {
        return TestResult::Fail("MES12 revision-specific oversubscription timer");
    }
    res.queues.vmids_gfxhub = 1;
    if resources(&res) != Err(Error::Invalid) {
        return TestResult::Fail("privileged VMID0 delegated to scheduler");
    }
    let rejected = 0x820e0209_00000000;
    if completion(1, 9, 10) != Ok(Completion::Pending)
        || completion(rejected, 9, 10) != Ok(Completion::Pending)
        || completion(1, 10, 10) != Ok(Completion::Success)
        || completion(rejected, 10, 10)
            != Ok(Completion::Rejected(Rejection {
                code: 9,
                opcode: 2,
                misc: 14,
                category: 2,
            }))
        || completion(0, 10, 10) != Err(Error::MalformedCompletion)
        || completion(2, 10, 10) != Err(Error::MalformedCompletion)
        || completion(1, 11, 10) != Err(Error::MalformedCompletion)
    {
        return TestResult::Fail("MES12 completion accepted undrained/stale API or lost rejection");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/mes12",
    mes12_resources_and_completion_require_current_protocol
);

fn memory() -> QueueMemory {
    QueueMemory {
        descriptor: 0x123400001000,
        ring: 0x123400002000,
        ring_bytes: 4096,
        eop: 0x123400003000,
        read_pointer: 0x123400004000,
        write_pointer: 0x123400004008,
        doorbell: 0x174,
    }
}
fn mes12_mqd_carries_native_fields_and_rejects_aliasing() -> TestResult {
    let words = mqd(memory()).unwrap();
    let expected = [
        (0, 0xc0310800),
        (11, 1),
        (23, u32::MAX),
        (24, u32::MAX),
        (26, u32::MAX),
        (27, u32::MAX),
        (32, 7),
        (128, 0x1000),
        (129, 0x1234),
        (130, 1),
        (132, 0xbe05501),
        (136, 0x34000020),
        (137, 0x12),
        (139, 0x4000),
        (140, 0x1234),
        (141, 0x4008),
        (142, 0x1234),
        (143, 0x400005d0),
        (145, 0xd8308009),
        (149, 0x300000),
        (162, 0x100),
        (165, 0x34000030),
        (166, 0x12),
        (167, 8),
        (184, 0x8000),
    ];
    if words
        .iter()
        .enumerate()
        .any(|(i, w)| *w != expected.iter().find(|f| f.0 == i).map_or(0, |f| f.1))
    {
        return TestResult::Fail("MES12 MQD differs from Linux field/shift defaults");
    }
    for case in 0..8 {
        let mut m = memory();
        match case {
            0 => m.ring_bytes = 512,
            1 => m.ring_bytes = 4095,
            2 => m.ring = m.descriptor,
            3 => m.eop = m.ring + 256,
            4 => m.read_pointer = m.write_pointer,
            5 => m.ring = ADDRESS_LIMIT - 256,
            6 => m.doorbell = 1 << 26,
            _ => m.doorbell = 3,
        }
        if mqd(m).is_ok() {
            return TestResult::Fail("invalid/overlapping MES queue backing accepted");
        }
    }
    for case in 0..6 {
        let mut q = queue();
        match case {
            0 => q.mqd += 4,
            1 => q.write_pointer = ADDRESS_LIMIT,
            2 => q.pipe = 2,
            3 => q.queue = 4,
            4 => q.kind = QueueType::Scheduler,
            _ => q.doorbell = 1,
        }
        if map_kernel_queue(q).is_ok() || unmap_kernel_queue(q).is_ok() {
            return TestResult::Fail("invalid GC12 queue admitted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/mes12",
    mes12_mqd_carries_native_fields_and_rejects_aliasing
);

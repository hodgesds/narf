use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

const SDMA: u64 = 0x10034;
const GCTX: u64 = 0x15890;
const MCTX: u64 = 0x21590;
const GCP: u64 = 0x17828;
const CCP: u64 = 0x17894;
const GST: u64 = 0x15740;
const MST: u64 = 0x213c0;
const GCTL: u64 = 0x15730;
const MCTL: u64 = 0x213b0;
struct Fake {
    regs: BTreeMap<u64, u32>,
    reads: Vec<u64>,
    writes: Vec<(u64, u32)>,
    stale_gfx: bool,
    ignored: Option<u64>,
    revoke: Option<(u64, Cap<BusDeviceCap, Write>)>,
}
impl Io for Fake {
    fn read(&mut self, at: u64) -> u32 {
        self.reads.push(at);
        if at == GST && self.stale_gfx {
            self.stale_gfx = false;
            return 0;
        }
        *self.regs.get(&at).unwrap_or(&0)
    }
    fn write(&mut self, at: u64, v: u32) {
        self.writes.push((at, v));
        if self.ignored != Some(at) {
            self.regs
                .insert(at, if at == GCTL || at == MCTL { v & !1 } else { v });
        }
        if let Some((when, cap)) = self.revoke {
            if at == when {
                cap.revoke();
            }
        }
    }
}
fn fixture() -> Engine<Fake> {
    let mut regs = BTreeMap::new();
    for (at, v) in [
        (GCTX, 0xaaa801),
        (MCTX, 0xaaa801),
        (GCP, 0x84000000),
        (CCP, 0x84000000),
        (SDMA, 0x40),
        (GCTL, 0x1ffc),
        (MCTL, 0x1ffc),
        (GST, 0x785753),
        (MST, 0x342026),
    ] {
        regs.insert(at, v);
    }
    Engine {
        io: Fake {
            regs,
            reads: Vec::new(),
            writes: Vec::new(),
            stale_gfx: false,
            ignored: None,
            revoke: None,
        },
        authority: Cap::bootstrap(),
        layout: Layout {
            gfx: 0x10000,
            mm: 0x20000,
        },
        status: Status {
            state: State::Prepared,
            count: 0,
            last: None,
            mask_error: None,
        },
        published: 0,
        owned_clients: false,
    }
}
fn event(client: u8, source: u8, ring: u8) -> ih::Event {
    ih::Event {
        ih_ring: 1,
        vector: ih::Vector::decode([
            u32::from(client) | (u32::from(source) << 8) | (u32::from(ring) << 16) | (7 << 24),
            0x1234,
            0,
            0x425678,
            0xdeadbeef,
            0xab,
            0,
            0,
        ]),
    }
}
fn navi48_fault_arming_preserves_defaults_eops_and_inactive_user_contexts() -> TestResult {
    let mut e = fixture();
    e.io.regs.insert(GCP, 0);
    e.io.regs.insert(CCP, 0);
    e.enable(None).unwrap();
    assert_eq!(e.status.state, State::Armed);
    assert_eq!(
        e.io.writes,
        [
            (GCTX, 0xfffc01),
            (MCTX, 0xfffc01),
            (GCP, 0x85c00000),
            (CCP, 0x85800000),
            (SDMA, 0x41)
        ]
    );
    assert_eq!(e.io.regs[&GCTL], 0x1ffc);
    assert_eq!(e.io.regs[&MCTL], 0x1ffc);
    assert_eq!(e.enable(None), Err(Error::Busy));
    e.stop();
    assert_eq!(e.status.state, State::Contained);
    for (at, value) in [
        (GCTX, 0xaaa801),
        (MCTX, 0xaaa801),
        (GCP, 0x84000000),
        (CCP, 0x84000000),
        (SDMA, 0x40),
    ] {
        assert_eq!(e.io.regs[&at], value);
    }
    assert_eq!(e.enable(None), Err(Error::Busy));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-faults",
    navi48_fault_arming_preserves_defaults_eops_and_inactive_user_contexts
);

fn navi48_vm_faults_decode_48bit_addresses_capture_then_ack_and_contain() -> TestResult {
    for client in [0x0a, 0x12] {
        let mut e = fixture();
        e.enable(None).unwrap();
        e.io.reads.clear();
        e.io.writes.clear();
        e.io.stale_gfx = true;
        let mut v = event(client, 0, 0xff);
        v.vector.vmid_source = client == 0x12;
        let (hub, status, control) = if client == 0x0a {
            (Hub::Gfx, GST, GCTL)
        } else {
            (Hub::Mm, MST, MCTL)
        };
        e.handle(v).unwrap();
        assert_eq!(e.status.count, 1);
        assert_eq!(e.status.state, State::Contained);
        let record = e.status.last.unwrap();
        assert_eq!(record.event, Some(v));
        assert_eq!(
            record.kind,
            Kind::Vm {
                hub,
                page: 0xbdeadbeef000,
                write: true,
                retry: true
            }
        );
        assert!(record.acknowledged);
        assert_eq!(record.protection.unwrap().raw, e.io.regs[&status]);
        assert_eq!(
            e.io.reads.iter().filter(|&&at| at == status).count(),
            if client == 0x0a { 2 } else { 1 }
        );
        assert_eq!(e.io.writes[0], (control, 0x1ffd));
        assert_eq!(e.io.regs[&control], 0x1ffc);
        assert_eq!(e.io.writes.len(), 6);
        // Already queued faults still get captured/acknowledged after masking.
        e.handle(v).unwrap();
        assert_eq!(e.status.count, 2);
        assert_eq!(e.io.writes.len(), 7);
        assert_eq!(e.enable(None), Err(Error::Busy));
    }
    let p = Protection::decode(0x785753);
    assert_eq!(
        (
            p.more_faults,
            p.walker_error,
            p.permission_faults,
            p.mapping_error
        ),
        (true, 1, 5, true)
    );
    assert_eq!((p.client, p.write, p.vmid), (43, false, 7));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-faults",
    navi48_vm_faults_decode_48bit_addresses_capture_then_ack_and_contain
);

fn navi48_command_faults_use_exact_client_source_and_preserve_queue_identity() -> TestResult {
    for (source, fault) in [
        (183, CommandFault::BadOpcode),
        (184, CommandFault::PrivilegedRegister),
        (185, CommandFault::PrivilegedInstruction),
    ] {
        let mut e = fixture();
        e.enable(None).unwrap();
        e.io.writes.clear();
        e.io.reads.clear();
        let v = event(0x0a, source, 0xda);
        e.handle(v).unwrap();
        assert_eq!(e.status.state, State::Contained);
        let record = e.status.last.unwrap();
        assert_eq!(
            record.kind,
            Kind::Command {
                fault,
                me: 2,
                pipe: 2,
                queue: 5
            }
        );
        assert_eq!(record.protection, None);
        assert!(!record.acknowledged);
        assert_eq!(e.io.writes.len(), 5);
        assert!(!e.io.reads.contains(&GST) && !e.io.reads.contains(&MST));
    }
    let mut e = fixture();
    e.enable(None).unwrap();
    e.io.writes.clear();
    e.io.reads.clear();
    for (client, source) in [(0x0a, 181), (0x0a, 49), (0x04, 0), (0x12, 183), (0x12, 185)] {
        e.handle(event(client, source, 0)).unwrap();
    }
    assert_eq!(e.status.state, State::Armed);
    assert_eq!(e.status.count, 0);
    assert!(e.io.writes.is_empty() && e.io.reads.is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-faults",
    navi48_command_faults_use_exact_client_source_and_preserve_queue_identity
);

fn navi48_sdma_shader_and_poison_faults_keep_iv_evidence_without_latch_io() -> TestResult {
    let sq = |kind: u32| {
        let mut v = event(0x0a, 239, 0);
        v.vector.data = [(kind << 21) | 0x55, 2 << 6, 0, 0];
        v
    };
    for (v, kind) in [
        (
            event(0x0a, 55, 0x10),
            Kind::Sdma {
                fault: SdmaFault::QueueHang,
                instance: 1,
                queue: 0,
            },
        ),
        (
            event(0x0a, 60, 0x01),
            Kind::Sdma {
                fault: SdmaFault::PageFault,
                instance: 0,
                queue: 1,
            },
        ),
        (
            event(0x0a, 195, 0x04),
            Kind::Command {
                fault: CommandFault::ProtectionFault,
                me: 1,
                pipe: 0,
                queue: 0,
            },
        ),
        (
            sq(2),
            Kind::Shader {
                error: ShaderError::MemoryViolation,
                detail: 0x55,
            },
        ),
        (sq(0), Kind::Poison(Poison::Shader { fatal: true })),
        (event(0x0a, 201, 0), Kind::Poison(Poison::CpFue)),
        (event(0x17, 0, 0), Kind::Poison(Poison::Umc)),
        (
            event(0x10, 160, 0),
            Kind::Poison(Poison::Media {
                instance: 0,
                source: 160,
            }),
        ),
    ] {
        let mut e = fixture();
        e.enable(None).unwrap();
        e.io.writes.clear();
        e.io.reads.clear();
        e.handle(v).unwrap();
        assert_eq!(e.status.state, State::Contained);
        let record = e.status.last.unwrap();
        assert_eq!((record.event, record.kind), (Some(v), kind));
        assert_eq!((record.protection, record.acknowledged), (None, false));
        assert!(!e.io.reads.contains(&GST) && !e.io.reads.contains(&MST));
        assert_eq!(e.io.writes.len(), 5);
    }
    // Shader wave messages and media traps are not faults.
    let mut e = fixture();
    e.enable(None).unwrap();
    let mut wave = event(0x0a, 239, 0);
    wave.vector.data = [1 << 21, 1 << 6, 0, 0];
    e.handle(wave).unwrap();
    e.handle(event(0x10, 119, 0)).unwrap();
    assert_eq!((e.status.state, e.status.count), (State::Armed, 0));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-faults",
    navi48_sdma_shader_and_poison_faults_keep_iv_evidence_without_latch_io
);

fn navi48_fault_sweep_after_lost_vectors_captures_then_acks_set_latches() -> TestResult {
    let mut e = fixture();
    assert_eq!(e.sweep(), Err(Error::Busy));
    e.enable(None).unwrap();
    e.io.writes.clear();
    e.io.reads.clear();
    // Nothing latched: reads only, no acknowledgement or containment.
    e.io.regs.insert(GST, 0);
    e.io.regs.insert(MST, 0);
    assert_eq!(e.sweep(), Ok([None, None]));
    assert_eq!(e.io.reads, [GST, GST, MST]);
    assert!(e.io.writes.is_empty());
    assert_eq!((e.status.state, e.status.count), (State::Armed, 0));
    // An MMHUB latch whose IV was overwritten.
    e.io.regs.insert(MST, 0x342026);
    assert_eq!(e.sweep(), Ok([None, Some(3)]));
    assert_eq!(e.status.state, State::Contained);
    let record = e.status.last.unwrap();
    assert_eq!(record.event, None);
    assert_eq!(record.kind, Kind::Latched { hub: Hub::Mm });
    assert_eq!(record.protection.unwrap().raw, 0x342026);
    assert!(record.acknowledged);
    assert_eq!(e.io.writes[0], (MCTL, 0x1ffd));
    // A device that vanished fails the sweep and attempts the masks.
    e.io.regs.insert(GST, u32::MAX);
    assert_eq!(e.sweep(), Err(Error::DeviceGone));
    assert_eq!(e.status.state, State::Failed(Error::DeviceGone));
    assert_eq!(e.sweep(), Err(Error::DeviceGone));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-faults",
    navi48_fault_sweep_after_lost_vectors_captures_then_acks_set_latches
);

fn navi48_fault_preflight_and_partial_programming_fail_without_reuse() -> TestResult {
    for case in 0..8 {
        let mut e = fixture();
        let expected = match case {
            0 => {
                e.io.regs.insert(GCTX, 0);
                Error::Busy
            }
            1 => {
                e.io.regs.insert(MCTX, 0xaaa901);
                Error::Busy
            }
            2 => {
                e.io.regs.insert(GCTX + 15 * 4, 1);
                Error::Busy
            }
            3 => {
                e.io.regs.insert(CCP, u32::MAX);
                Error::DeviceGone
            }
            4 => {
                e.io.regs.insert(GCP, 0x01800000);
                Error::Busy
            }
            5 => {
                e.authority.revoke();
                Error::Revoked
            }
            6 => {
                e.io.regs.insert(SDMA, 0x41);
                Error::Busy
            }
            _ => {
                e.io.regs.insert(MCTX + 4, 1);
                Error::Busy
            }
        };
        assert_eq!(e.enable(None), Err(expected));
        assert_eq!(e.status.state, State::Failed(expected));
        assert!(e.io.writes.is_empty());
        assert_eq!(e.enable(None), Err(Error::Busy));
    }
    let mut e = fixture();
    e.io.ignored = Some(MCTX);
    assert_eq!(e.enable(None), Err(Error::Readback));
    assert_eq!(e.status.mask_error, None);
    assert_eq!(
        e.io.writes,
        [
            (GCTX, 0xfffc01),
            (MCTX, 0xfffc01),
            (GCTX, 0xaaa801),
            (MCTX, 0xaaa801)
        ]
    );
    let mut e = fixture();
    e.io.revoke = Some((GCTX, e.authority));
    assert_eq!(e.enable(None), Err(Error::Revoked));
    assert_eq!(e.status.mask_error, Some(Error::Revoked));
    assert_eq!(e.io.writes, [(GCTX, 0xfffc01)]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-faults",
    navi48_fault_preflight_and_partial_programming_fail_without_reuse
);

fn navi48_fault_mmio_failures_preserve_raw_evidence_and_uncertain_masks() -> TestResult {
    for case in 0..3 {
        let mut e = fixture();
        e.enable(None).unwrap();
        e.io.writes.clear();
        let v = event(0x0a, 0, 4);
        let expected = match case {
            0 => {
                e.authority.revoke();
                Error::Revoked
            }
            1 => {
                e.io.regs.insert(GST, u32::MAX);
                Error::DeviceGone
            }
            _ => {
                e.io.revoke = Some((GCTL, e.authority));
                Error::Revoked
            }
        };
        assert_eq!(e.handle(v), Err(expected));
        assert_eq!(e.status.state, State::Failed(expected));
        let record = e.status.last.unwrap();
        assert_eq!(record.event, Some(v));
        assert_eq!(record.protection.is_some(), case == 2);
        assert_eq!(record.acknowledged, case == 2);
        assert_eq!(
            e.status.mask_error,
            if case == 1 {
                None
            } else {
                Some(Error::Revoked)
            }
        );
        assert_eq!(e.io.writes.len(), [0, 5, 1][case]);
        assert_eq!(e.enable(None), Err(Error::Busy));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-faults",
    navi48_fault_mmio_failures_preserve_raw_evidence_and_uncertain_masks
);

fn navi48_fault_monitor_constructor_checks_discovery_and_live_authority() -> TestResult {
    let mut words = vec![0; 0x80000 / 4];
    let gpu = crate::amdgpu_gmc_navi48::tests::descriptor(&mut words);
    let cap = Cap::bootstrap();
    // SAFETY: owned register fixture; construction does not access hardware.
    let monitor = unsafe { Monitor::new(&gpu, cap) }.unwrap();
    assert_eq!(monitor.status().state, State::Prepared);
    for case in 0..6 {
        let mut bad = crate::amdgpu_gmc_navi48::tests::descriptor(&mut words);
        match case {
            0 => bad.chip.did = crate::amdgpu::NAVI22,
            1 => bad.ip_blocks[0].revision = 0,
            2 => bad.ip_blocks[1].minor = 0,
            3 => bad.ip_blocks[0].base_addrs[0] = 0x20000 - 0x1e25,
            4 => bad.ip_blocks.push(bad.ip_blocks[1]),
            _ => bad.ip_blocks[1].num_bases = 0,
        }
        // SAFETY: only discovery validation on owned descriptors.
        let result = unsafe { Monitor::new(&bad, cap) };
        assert!(matches!(result, Err(Error::Unsupported)));
    }
    cap.revoke();
    // SAFETY: revoked authority must fail before any register use.
    let result = unsafe { Monitor::new(&gpu, cap) };
    assert!(matches!(result, Err(Error::Revoked)));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-faults",
    navi48_fault_monitor_constructor_checks_discovery_and_live_authority
);

fn client_fixture() -> Engine<Fake> {
    let mut e = fixture();
    for base in [GCTX, MCTX] {
        for vmid in 1..16 {
            e.io.regs.insert(base + vmid * 4, 0xaaa807);
        }
    }
    e
}
fn navi48_owned_client_faults_arm_and_contain_without_changing_translation() -> TestResult {
    let mut e = client_fixture();
    let before = e.io.regs.clone();
    e.enable(Some([0xaaa807; 2])).unwrap();
    assert_eq!(e.status.state, State::Armed);
    assert_eq!(e.io.writes.len(), 35);
    assert_eq!(e.published, (1 << 35) - 1);
    for base in [GCTX, MCTX] {
        for vmid in 0..16 {
            let at = base + vmid * 4;
            assert_eq!(e.io.regs[&at], before[&at] | 0x555400);
        }
    }
    e.io.writes.clear();
    e.handle(event(0x0a, 183, 0x14)).unwrap();
    assert_eq!(e.status.state, State::Contained);
    assert_eq!(e.io.writes.len(), 35);
    assert_eq!(e.status.mask_error, None);
    for base in [GCTX, MCTX] {
        for vmid in 0..16 {
            let at = base + vmid * 4;
            assert_eq!(e.io.regs[&at], before[&at]);
        }
    }
    for at in [GCP, CCP, SDMA, GCTL, MCTL] {
        assert_eq!(e.io.regs[&at], before[&at]);
    }
    assert_eq!(e.enable(Some([0xaaa807; 2])), Err(Error::Busy));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-faults",
    navi48_owned_client_faults_arm_and_contain_without_changing_translation
);

fn navi48_client_fault_arming_rejects_changed_controls_before_publication() -> TestResult {
    for base in [GCTX, MCTX] {
        for vmid in 1..16 {
            for change in [1, 2, 0x100, 0x400, 0x800000] {
                let mut e = client_fixture();
                e.io.regs.insert(base + vmid * 4, 0xaaa807 ^ change);
                assert_eq!(e.enable(Some([0xaaa807; 2])), Err(Error::Busy));
                assert_eq!(e.status.state, State::Failed(Error::Busy));
                assert_eq!(e.published, 0);
                assert!(e.io.writes.is_empty());
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-faults",
    navi48_client_fault_arming_rejects_changed_controls_before_publication
);

fn navi48_client_fault_partial_writes_mask_every_published_source() -> TestResult {
    for base in [GCTX, MCTX] {
        for vmid in 1..16 {
            let mut e = client_fixture();
            e.io.ignored = Some(base + vmid * 4);
            assert_eq!(e.enable(Some([0xaaa807; 2])), Err(Error::Readback));
            assert_eq!(e.status.state, State::Failed(Error::Readback));
            assert_eq!(e.status.mask_error, None);
            for base in [GCTX, MCTX] {
                for id in 0..16 {
                    let want = if id == 0 { 0xaaa801 } else { 0xaaa807 };
                    assert_eq!(e.io.regs[&(base + id * 4)], want);
                }
            }
            assert_eq!(e.io.regs[&GCP], 0x84000000);
            assert_eq!(e.io.regs[&CCP], 0x84000000);
            assert_eq!(e.io.regs[&SDMA], 0x40);
        }
    }
    let mut e = client_fixture();
    let last = MCTX + 15 * 4;
    e.io.revoke = Some((last, e.authority));
    assert_eq!(e.enable(Some([0xaaa807; 2])), Err(Error::Revoked));
    assert_eq!(e.status.mask_error, Some(Error::Revoked));
    assert_eq!(e.io.writes.last(), Some(&(last, 0xfffc07)));
    let writes = e.io.writes.len();
    e.stop();
    assert_eq!(e.io.writes.len(), writes);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-faults",
    navi48_client_fault_partial_writes_mask_every_published_source
);

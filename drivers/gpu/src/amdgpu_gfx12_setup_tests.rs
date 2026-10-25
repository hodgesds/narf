use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
const GC: u64 = 0x10000;
const HYP: u64 = 0x40000;
const NBIO: u64 = 0x60000;
const INDEX: u64 = 0x42400;
const BROADCAST: u64 = 0x48800;
struct Fake {
    regs: BTreeMap<u64, u32>,
    index: u32,
    broadcast: u32,
    memory: Vec<u32>,
    writes: Vec<(u32, u64, u32)>,
    /// SH_MEM_CONFIG / SH_MEM_BASES by the GRBM selection they were written
    /// under.
    sh_mem: BTreeMap<(u32, u64), u32>,
    busy: Option<(u32, u64)>,
    dirty: bool,
    refuse: Option<u64>,
    stuck: bool,
    gone: bool,
    revoke: Option<Cap<BusDeviceCap, Write>>,
}
impl Io for Fake {
    fn read(&mut self, at: u64) -> u32 {
        if self.busy == Some((self.index, at)) {
            return 1;
        }
        match at {
            INDEX => self.index,
            BROADCAST => self.broadcast,
            0x13d00 if self.regs[&0x4200c] & 0x14000000 == 0 => {
                if self.gone {
                    u32::MAX
                } else {
                    u32::from(self.stuck)
                }
            }
            _ => *self.regs.get(&at).unwrap_or(&0),
        }
    }
    fn write(&mut self, at: u64, v: u32) {
        self.writes.push((self.index, at, v));
        if self.refuse == Some(at) {
            return;
        }
        match at {
            INDEX => {
                self.index = v;
                return;
            }
            BROADCAST => {
                self.broadcast = v;
                return;
            }
            0x7f000 => {
                self.dirty = false;
                return;
            }
            0x14f48 | 0x15094 | 0x4b864 => assert_eq!(self.broadcast, 0xe0000000),
            0x42790 | 0x4278c => {
                // Only a VMID is selected: ME, pipe and queue 0.
                assert_eq!(self.index & !0xf0, 0);
                assert!(at == 0x42790 || self.index != 0, "VMID0 keeps its bases");
                self.sh_mem.insert((self.index >> 4, at), v);
            }
            0x17828 | 0x17938 | 0x177ac => assert_eq!(self.index, 0),
            0x4261c | 0x42620 | 0x42624 | 0x53200 | 0x4a410 | 0x4200c => {
                assert!(!self.dirty, "RLC pointer published before flush");
                assert_eq!(self.memory[0], 6);
            }
            0x13680 | 0x14eec => {}
            _ => panic!("wrong GC12 setup register {at:x}"),
        }
        self.regs.insert(at, v);
        if at == 0x4200c {
            if let Some(cap) = self.revoke {
                cap.revoke();
            }
        }
    }
    fn memory(&mut self, _: MmioRegion, at: u64, v: u32) {
        self.dirty = true;
        self.memory[(at / 4) as usize] = v;
    }
    async fn delay(&mut self) {
        assert_eq!(self.index, 0x32);
        assert_eq!(self.broadcast, 0x12345678);
        narf_scheduler::yield_now().await;
    }
}
fn fixture(revision: u8) -> (Pool, Engine<Fake>) {
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(0x90004000),
        virt: 0,
        len: 4096,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: the model intercepts every access; this is allocator bookkeeping.
    let pool = unsafe { Pool::from_owned_range(map, 0x8_0000_4000) }.unwrap();
    let e = Engine {
        io: Fake {
            regs: BTreeMap::from([
                (0x15850, 0x800),
                (0x15854, 0xbff),
                (0x604b4, 0x7f000),
                (0x60054, u32::from(revision) << 24),
                (0x14f48, 0x10204060),
                (0x15094, 0x80000000),
                (0x4b864, 0xdeadbeef),
                (0x13680, 0x12345fff),
                (0x14eec, 0xa5a5a5a5),
                (0x17828, 0x403c0001),
                (0x53200, 0xa0000010),
                (0x4a410, 0x800f0013),
                (0x4200c, 0x14000002),
            ]),
            index: 0x32,
            broadcast: 0x12345678,
            memory: vec![u32::MAX; 1024],
            writes: Vec::new(),
            sh_mem: BTreeMap::new(),
            busy: None,
            dirty: false,
            refuse: None,
            stuck: false,
            gone: false,
            revoke: None,
        },
        authority: Cap::bootstrap(),
        layout: Layout {
            gc: GC,
            hyp: HYP,
            nbio: NBIO,
            strap: 0x60054,
        },
        clear: pool.reserve(4096).unwrap(),
        state: State::Prepared,
        report: None,
    };
    (pool, e)
}
fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}
fn gfx12_setup_builds_linux_clearstate_and_preserves_controls() -> TestResult {
    for revision in [0, 1, 15] {
        let (pool, mut e) = fixture(revision);
        let want = Report {
            revision,
            clear_state_address: 0x8_0000_4000,
            clear_state_dwords: 75,
        };
        assert_eq!(run(e.initialize()), Ok(want));
        assert_eq!(e.report, Some(want));
        assert_eq!(e.state, State::Ready);
        // VMIDs 0-7: DEFAULT_SH_MEM_CONFIG; 1-7 also the apertures.
        let mut sh_mem = BTreeMap::new();
        for vmid in 0..8 {
            sh_mem.insert((vmid, 0x42790), 0xc00c);
            if vmid != 0 {
                sh_mem.insert((vmid, 0x4278c), 0x2000_1000);
            }
        }
        assert_eq!(e.io.sh_mem, sh_mem);
        let r = &e.io.regs;
        assert_eq!(
            r[&0x14f48],
            if revision == 0 {
                0x1020c06f
            } else {
                0x1020c060
            }
        );
        assert_eq!(
            r[&0x15094],
            if revision == 0 {
                0x83000000
            } else {
                0x80000000
            }
        );
        assert_eq!(
            r[&0x4b864],
            if revision == 0 {
                0xdeadbeaf
            } else {
                0xdeadbeef
            }
        );
        assert_eq!(r[&0x13680], 0x123450ff);
        assert_eq!(r[&0x14eec], 0xa5a5a5a5);
        assert_eq!(r[&0x17828], 0x40000001);
        assert_eq!(r[&0x17938], 7);
        assert_eq!(r[&0x177ac], 1);
        assert_eq!(r[&0x53200], 0xa0000013);
        assert_eq!(r[&0x4a410], 0xbc000003);
        assert_eq!(r[&0x4200c], 2);
        assert_eq!(r[&0x42620], 8);
        assert_eq!(r[&0x4261c], 0x4000);
        assert_eq!(r[&0x42624], 75);
        assert_eq!(e.io.index, 0x32);
        assert_eq!(e.io.broadcast, 0x12345678);
        let hash = e.io.memory[..75]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .fold(0xcbf29ce484222325u64, |h, b| {
                (h ^ u64::from(b)).wrapping_mul(0x100000001b3)
            });
        assert_eq!(hash, 0xb0f45c3e7f714838);
        assert!(e.io.memory[75..].iter().all(|v| *v == 0));
        assert_eq!(run(e.initialize()), Err(Error::Busy));
        drop(e);
        assert_eq!(pool.available(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_setup_builds_linux_clearstate_and_preserves_controls
);

fn gfx12_setup_refuses_busy_queues_and_restores_both_selectors() -> TestResult {
    for busy in [
        (0, 0x17d00),
        (0x700, 0x17a00),
        (0x305, 0x17eac),
        (13, 0x17eac),
    ] {
        let (pool, mut e) = fixture(0);
        e.io.busy = Some(busy);
        assert_eq!(run(e.initialize()), Err(Error::Busy));
        assert_eq!(e.io.index, 0x32);
        assert!(e.io.writes.iter().all(|w| w.1 == INDEX));
        drop(e);
        assert_eq!(pool.available(), 4096);
    }
    let (pool, mut e) = fixture(0);
    e.io.refuse = Some(0x15094);
    assert_eq!(run(e.initialize()), Err(Error::Readback));
    assert_eq!(e.io.index, 0x32);
    assert_eq!(e.io.broadcast, 0x12345678);
    drop(e);
    assert_eq!(pool.available(), 4096);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_setup_refuses_busy_queues_and_restores_both_selectors
);

fn gfx12_setup_quarantines_after_publication_and_cancellation() -> TestResult {
    for case in 0..5 {
        let (pool, mut e) = fixture(1);
        if case == 0 {
            {
                let mut f = core::pin::pin!(e.initialize());
                assert!(f
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending());
            }
            assert_eq!(e.state, State::Settling);
        } else {
            let expected = match case {
                1 => {
                    e.io.stuck = true;
                    Error::Timeout
                }
                2 => {
                    e.io.gone = true;
                    Error::DeviceGone
                }
                3 => {
                    e.io.revoke = Some(e.authority);
                    Error::Revoked
                }
                _ => {
                    e.io.refuse = Some(0x42624);
                    Error::Readback
                }
            };
            assert_eq!(run(e.initialize()), Err(expected));
            assert_eq!(e.state, State::Failed(expected));
        }
        assert_eq!(e.report, None);
        assert_eq!(run(e.initialize()), Err(Error::Busy));
        drop(e);
        assert_eq!(pool.available(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_setup_quarantines_after_publication_and_cancellation
);

fn gfx12_setup_selects_revision_strap_by_nbio_generation() -> TestResult {
    let mut regs = vec![0; 0x80000 / 4];
    let mut gpu = crate::amdgpu_gmc_navi48::tests::descriptor(&mut regs);
    gpu.ip_blocks[0].base_addrs[1] = 0x10000;
    assert_eq!(Layout::resolve(&gpu).unwrap().strap, 0x30054);
    (
        gpu.ip_blocks[2].major,
        gpu.ip_blocks[2].minor,
        gpu.ip_blocks[2].revision,
    ) = (6, 3, 1);
    assert_eq!(Layout::resolve(&gpu).unwrap().strap, 0x30070);
    gpu.ip_blocks[0].base_addrs[1] = 0x20000 - 0x4c80;
    assert!(Layout::resolve(&gpu).is_err());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_setup_selects_revision_strap_by_nbio_generation
);

/// GC 12.0.0 and 12.0.1 share the bank layout and the golden sequence
/// (gfx_v12_0_init_golden_registers has one case for both): every profile
/// resolves the same banks, and the rev0 entries follow the NBIO strap, not
/// the die.
fn gfx12_setup_layout_and_golden_are_shared_by_both_dies() -> TestResult {
    use crate::amdgpu_rdna4::tests::Profile;
    let mut regs = vec![0; 0x80000 / 4];
    for profile in Profile::ALL {
        let mut gpu = crate::amdgpu_gmc_navi48::tests::descriptor(&mut regs);
        gpu.ip_blocks[0].base_addrs[1] = 0x10000;
        profile.apply(&mut gpu);
        let Ok(layout) = Layout::resolve(&gpu) else {
            return TestResult::Fail("GFX12 setup refused an RDNA4 profile");
        };
        if layout.gc != 0x4000 * 4 || layout.hyp != 0x10000 * 4 || layout.strap != 0x30054 {
            return TestResult::Fail("GFX12 setup profile banks");
        }
    }
    if GOLDEN != [(0, 0x13d2, 0x8000, 0x8000)] || GOLDEN_REV0.len() != 3 {
        return TestResult::Fail("GC12 golden tables");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_setup_layout_and_golden_are_shared_by_both_dies
);

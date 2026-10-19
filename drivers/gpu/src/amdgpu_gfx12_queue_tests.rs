use super::*;
use crate::amdgpu_navi48_interrupts as interrupts;
use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    sync::atomic::AtomicU32,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
const GPU: u64 = 0x8_0000_4000;
const VA: u64 = 0xc_0000_0000;
struct Fake {
    index: u32,
    memory: Vec<u32>,
    target: Vec<u32>,
    dirty: bool,
    mapped: Arc<AtomicU32>,
    progress: Arc<AtomicU32>,
    eop: Arc<[AtomicU32; 3]>,
    emit_eop: bool,
    emit_cpu: bool,
    bells: Vec<u32>,
    complete: bool,
    corrupt: bool,
    rptr_stuck: bool,
    busy: bool,
    revoked: Option<Cap<BusDeviceCap, Write>>,
    fence_revoke: Option<Cap<BusDeviceCap, Write>>,
    fence_gone: bool,
    fence_reads: u32,
    regs: BTreeMap<u64, u32>,
    /// Client-job packets the CP ran: register writes, waits (reg0, reg1,
    /// reference, mask, info), PFP syncs and IBs (address, control).
    job_writes: Vec<(u32, u32)>,
    job_waits: Vec<(u32, u32, u32, u32, u32)>,
    job_hdp: Vec<u32>,
    hdp_complete: bool,
    job_syncs: u32,
    /// Pipeline syncs: (fence address, sequence waited for).
    job_pipeline_syncs: Vec<(u64, u32)>,
    /// CONTEXT_CONTROL load words, graphics jobs only.
    job_context_controls: Vec<u32>,
    /// ACQUIRE_MEM cache flushes.
    job_mem_syncs: u32,
    job_ibs: Vec<(u64, u32)>,
    /// MMIO queue-reset writes: (GRBM selection, register, value).
    hqd_resets: Vec<(u32, u64, u32)>,
    /// The compute HQD ignores its dequeue.
    hqd_stuck: bool,
    /// Pipe reset / RLC writes, including the selected HQD.
    reset_trace: Vec<(u32, u64, u32)>,
    active: [bool; 4],
    dequeue: [u32; 4],
    drop_reset_write: Option<(u64, u32)>,
    rlc_stuck: bool,
    rlc_pending: u8,
    /// A ring restored after a reset runs client slots from 0.
    restored: bool,
    shader_execute: bool,
    shader_corrupt: bool,
    shader_overrun: bool,
    shader_skip_fence: bool,
}
impl Fake {
    /// Independent PM4/ISA model for the small proof kernel. Only the
    /// shader interpreter stores output: an IB/fence alone cannot pass.
    fn execute_shader(&mut self) {
        let mut regs = BTreeMap::new();
        let mut dispatch = false;
        let ib = self.target[64..320].to_vec();
        let mut pos = 0;
        while pos < ib.len() {
            let w = &ib[pos..];
            let length = ((w[0] >> 16) & 0x3fff) as usize + 2;
            match (w[0] >> 8) & 255 {
                0x76 => {
                    assert_eq!(w[0] & 3, 2);
                    for (i, v) in w[2..length].iter().enumerate() {
                        regs.insert(w[1] + i as u32, *v);
                    }
                }
                0x15 => {
                    assert_eq!(&w[..5], &[0xc0031502, 1, 1, 1, 0x8045]);
                    dispatch = true;
                }
                0x10 => {}
                op => panic!("unexpected shader IB opcode {op:#x}"),
            }
            pos += length;
        }
        assert!(dispatch);
        assert_eq!((regs[&0x207], regs[&0x208], regs[&0x209]), (32, 1, 1));
        assert_eq!(
            (regs[&0x212], regs[&0x213], regs[&0x228]),
            (0x60000000, 6, 0)
        );
        assert_eq!(
            u64::from(regs[&0x20c]) << 8 | u64::from(regs[&0x20d]) << 40,
            VA
        );
        let pointer = u64::from(regs[&0x240]) | u64::from(regs[&0x241]) << 32;
        assert_eq!(pointer, VA + 4160);
        let salt = regs[&0x242];
        if !self.shader_execute {
            return;
        }
        for lane in 0..32u32 {
            let mut v = [lane, 0];
            let mut pc = 0;
            let mut stored = false;
            while pc < 8 {
                match self.target[pc] {
                    0x30000082 => v[0] <<= 2,
                    0xbf870001 => {} // explicit VALU dependency wait
                    0x3a020002 => v[1] = salt ^ v[0],
                    0xee068000 => {
                        assert_eq!(&self.target[pc + 1..pc + 3], &[0x008c0000, 0]);
                        let at = ((pointer - VA + u64::from(v[0])) / 4) as usize;
                        self.target[at] = v[1] ^ u32::from(self.shader_corrupt);
                        stored = true;
                        pc += 2;
                    }
                    0xbfc10000 => assert!(stored),
                    0xbfb00000 => break,
                    word => panic!("unexpected gfx1201 proof instruction {word:#x}"),
                }
                pc += 1;
            }
        }
        if self.shader_overrun {
            self.target[1072] = 0;
        } // just past output
    }
    /// A CP running client-job slots of `pipe` from its RPTR to `tail`.
    fn execute_jobs(&mut self, pipe: usize, tail: u64) {
        let off = pipe * 3072;
        // Compute rings write registers without the PFP engine select.
        let write_cmd = if pipe == 0 { 0x4010_0000 } else { 0x0010_0000 };
        let mut rptr = u64::from(self.memory[off + 2560]);
        while rptr < tail {
            let slot = off + (rptr % 1024) as usize;
            let mut cursor = 0;
            let mut shader_job = false;
            let mut hdp = false;
            let mut context = false;
            while cursor < 256 {
                let words = &self.memory[slot + cursor..slot + 256];
                let header = words[0];
                assert_eq!(header >> 30, 3);
                let length = ((header >> 16) & 0x3fff) as usize + 2;
                assert!(cursor + length <= 256, "a packet crosses its job slot");
                match (header >> 8) & 255 {
                    0x37 => {
                        assert_eq!(length, 5);
                        assert_eq!(words[1], write_cmd, "confirmed register write");
                        assert_eq!(words[3], 0);
                        self.job_writes.push((words[2], words[4]));
                    }
                    0x3c if words[1] & 0x10 != 0 => {
                        // A pipeline sync: on the ring's own engine, equal,
                        // the whole fence word, poll interval 4.
                        let pfp = if pipe == 0 { 0x100 } else { 0 };
                        assert_eq!(
                            (length, words[1], words[5], words[6]),
                            (7, 0x13 | pfp, !0, 4)
                        );
                        let address = u64::from(words[2]) | u64::from(words[3]) << 32;
                        // Jobs run to completion here, so the wait is met.
                        assert_eq!(self.memory[((address - GPU) / 4) as usize], words[4]);
                        self.job_pipeline_syncs.push((address, words[4]));
                    }
                    0x3c if words[2] == 0x60000 / 4 + 0x106 => {
                        assert!(!context, "HDP before context control");
                        let (mask, engine) = if pipe == 0 { (1, 0x100) } else { (4, 0) };
                        assert_eq!(
                            words[..length],
                            [
                                0xc0053c00,
                                0x43 | engine,
                                0x18106,
                                0x18107,
                                mask,
                                mask,
                                0x20
                            ]
                        );
                        self.job_hdp.push(mask);
                        if !self.hdp_complete {
                            return; // no IB or completion can pass the handshake
                        }
                        hdp = true;
                    }
                    0x3c => {
                        assert_eq!((length, words[6]), (7, 0x20));
                        self.job_waits
                            .push((words[2], words[3], words[4], words[5], words[1]));
                    }
                    0x42 => {
                        assert_eq!((length, words[1]), (2, 0));
                        self.job_syncs += 1;
                    }
                    0x28 => {
                        assert_eq!((pipe, length, words[2]), (0, 3, 0), "graphics only");
                        context = true;
                        self.job_context_controls.push(words[1]);
                    }
                    0x58 => {
                        assert_eq!(words[1..length], [0, !0, 0xff_ffff, 0, 0, 10, 0xc3b1]);
                        self.job_mem_syncs += 1;
                    }
                    0x3f => {
                        assert_eq!(length, 4);
                        if words[3] & 0x0f00_0000 != 0 {
                            assert!(hdp, "HDP acknowledgement before client IB");
                        }
                        let address = u64::from(words[1]) | u64::from(words[2]) << 32;
                        self.job_ibs.push((address, words[3]));
                        if address == VA + crate::amdgpu_gfx12_shader::IB_OFFSET {
                            shader_job = true;
                            self.execute_shader();
                        }
                    }
                    0x49 => {
                        assert_eq!((length, words[1], words[2]), (8, 0x06600514, 0x22000000));
                        let address = u64::from(words[3]) | (u64::from(words[4]) << 32);
                        if !shader_job || !self.shader_skip_fence {
                            self.memory[((address - GPU) / 4) as usize] = words[5];
                        }
                        if shader_job {
                            if self.emit_eop {
                                self.eop[pipe].fetch_add(1, Ordering::SeqCst);
                            }
                            if self.emit_cpu {
                                self.eop[2].fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }
                    0x10 => {}
                    op => panic!("unexpected job opcode {op:#x}"),
                }
                cursor += length;
            }
            assert_eq!(cursor, 256, "the job fills its slot exactly");
            rptr += 256;
            // GC12 writes back only the low 32 bits.
            if !self.rptr_stuck {
                self.memory[off + 2560] = rptr as u32;
            }
        }
    }
    fn execute(&mut self, pipe: usize, tail: u32) {
        assert!(!self.dirty);
        assert_eq!(self.mapped.load(Ordering::SeqCst) & (1 << pipe), 1 << pipe);
        let off = pipe * 3072;
        let m = &self.memory[off + 1024..];
        assert_eq!(
            u64::from(m[128]) | (u64::from(m[129]) << 32),
            GPU + pipe as u64 * 12288 + 4096
        );
        assert_eq!(m[130], 1);
        assert_eq!(m[131], 0);
        assert_eq!(m[135], if pipe == 0 { 0xa01 } else { 0x111 });
        assert_eq!(m[143], if pipe == 0 { 0x40000458 } else { 0x40000018 });
        assert_eq!(m[145], if pipe == 0 { 0x00a00709 } else { 0xd0308909 });
        assert_eq!(m[162], 0x100);
        assert_eq!(m[184], 0);
        assert_eq!(self.memory[off + 2562], tail);
        let mut cursor = self.memory[off + 2560] as usize;
        let mut writes = 0;
        while cursor < tail as usize {
            let words = &self.memory[off + cursor..];
            let header = words[0];
            assert_eq!(header >> 30, 3);
            let length = ((header >> 16) & 0x3fff) as usize + 2;
            assert!(cursor + length <= tail as usize);
            match (header >> 8) & 255 {
                0x37 => {
                    assert_eq!(words[1], 0x100500);
                    let address = u64::from(words[2]) | (u64::from(words[3]) << 32);
                    assert!(address >= VA + pipe as u64 * 4096);
                    assert!(address + (length as u64 - 4) * 4 <= VA + (pipe as u64 + 1) * 4096);
                    assert_eq!(address % 4, 0);
                    let index = ((address - VA) / 4) as usize;
                    self.target[index..index + length - 4].copy_from_slice(&words[4..length]);
                    writes += length - 4;
                }
                0x10 => {}
                0x49 => {
                    assert_eq!(length, 8);
                    assert_eq!(words[1], 0x06600514);
                    assert_eq!(words[2], 0x22000000);
                    let address = u64::from(words[3]) | (u64::from(words[4]) << 32);
                    assert_eq!(address, VA + pipe as u64 * 4096 + 4088);
                    assert_eq!(words[5], if pipe == 0 { 0x90701234 } else { 0x90705678 });
                    assert_eq!(&words[6..8], &[0, 0]);
                    assert_eq!(
                        self.regs[&if pipe == 0 { 0x17828 } else { 0x17894 }] & 0x84000000,
                        0x84000000
                    );
                    self.target[((address - VA) / 4) as usize] = words[5] ^ u32::from(self.corrupt);
                    if self.emit_eop {
                        self.eop[pipe].fetch_add(1, Ordering::SeqCst);
                    }
                    if self.emit_cpu {
                        self.eop[2].fetch_add(1, Ordering::SeqCst);
                    }
                    writes += 1;
                }
                _ => panic!("unexpected bootstrap PM4 opcode"),
            }
            cursor += length;
        }
        assert_eq!(writes, if tail == 256 { 17 } else { 1 });
        if self.corrupt {
            self.target[pipe * 1024 + 7] ^= 1;
        }
        if !self.rptr_stuck {
            self.memory[off + 2560] = tail;
        }
        // GC12 updates only the low 32 bits of its RPTR writeback.
        self.memory[off + 2561] = u32::MAX;
    }
}
impl Io for Fake {
    fn read(&mut self, at: u64) -> u32 {
        match at {
            0x42400 => self.index,
            0x15850 => 0x800,
            0x15854 => 0xbff,
            0x604b4 => 0x7f000,
            0x42600 => {
                let v = *self.regs.get(&at).unwrap_or(&0);
                if v & 1 != 0 && !self.rlc_stuck && self.rlc_pending == 0 {
                    self.regs.insert(at, v & !1);
                    v & !1
                } else {
                    self.rlc_pending = self.rlc_pending.saturating_sub(1);
                    v
                }
            }
            0x17eac if self.index & 0xff == 4 && !self.hqd_resets.is_empty() => {
                let q = (self.index >> 8) as usize;
                u32::from(self.active[q] || (q == 0 && self.hqd_stuck))
            }
            0x17f04 if self.index & 0xff == 4 => self.dequeue[(self.index >> 8) as usize],
            0x17a00 | 0x17eac => u32::from(self.busy),
            _ => *self.regs.get(&at).unwrap_or(&0),
        }
    }
    fn write(&mut self, at: u64, v: u32) {
        match at {
            0x42400 => self.index = v,
            0x7f000 => self.dirty = false,
            0x42600 | 0x4a410 => {
                self.reset_trace.push((self.index, at, v));
                if self.drop_reset_write != Some((at, v)) {
                    self.regs.insert(at, v);
                }
            }
            // CP_HQD_ACTIVE / DEQUEUE_REQUEST and SPI_COMPUTE_QUEUE_RESET.
            0x17eac | 0x17f04 | 0x17dcc => {
                if self.regs[&0x53000] & 1 != 0 {
                    assert_eq!(self.regs[&0x42600] & 3, 2, "RLC safe before reset");
                }
                self.hqd_resets.push((self.index, at, v));
                self.reset_trace.push((self.index, at, v));
                if self.drop_reset_write == Some((at, v)) {
                    return;
                }
                let q = (self.index >> 8) as usize;
                match at {
                    0x17eac => {
                        assert_ne!(self.regs[&0x4a410] & (1 << 16), 0, "reset held");
                        self.active[q] = v & 1 != 0;
                        if q == 0 {
                            self.hqd_stuck = v & 1 != 0;
                        }
                    }
                    0x17f04 => self.dequeue[q] = v,
                    _ => {}
                }
            }
            _ => panic!("unexpected CP register write"),
        }
    }
    fn memory_read(&mut self, map: MmioRegion, at: u64) -> u32 {
        assert!(!self.dirty);
        if map.phys.raw() == 0x90004000 {
            if at == JOB_FENCE || at == PIPE_BYTES + JOB_FENCE {
                self.fence_reads += 1;
                if self.fence_gone {
                    self.regs.insert(0x60000 + 0xc3 * 4, u32::MAX);
                }
                if let Some(cap) = self.fence_revoke {
                    cap.revoke();
                }
            }
            self.memory[(at / 4) as usize]
        } else {
            self.target[(at / 4) as usize]
        }
    }
    fn memory_write(&mut self, map: MmioRegion, at: u64, v: u32) {
        self.dirty = true;
        if map.phys.raw() == 0x90004000 {
            self.memory[(at / 4) as usize] = v;
        } else {
            self.target[(at / 4) as usize] = v;
        }
    }
    fn doorbell(&mut self, _: MmioRegion, offset: u32, v: u64) {
        if v > 512 || self.restored {
            let pipe = match offset {
                0x116 => 0,
                6 => 1,
                _ => panic!("wrong CP doorbell"),
            };
            self.bells.push(offset);
            if self.complete {
                self.execute_jobs(pipe, v);
            }
            return;
        }
        assert!(v == 256 || v == 512);
        let pipe = match offset {
            0x116 => 0,
            6 => 1,
            _ => panic!("wrong CP doorbell"),
        };
        self.bells.push(offset);
        self.progress.store(1, Ordering::SeqCst);
        if self.complete {
            self.execute(pipe, v as u32);
        }
        if let Some(cap) = self.revoked {
            cap.revoke();
        }
    }
    async fn delay(&mut self) {
        assert_eq!(self.index, 0x32);
        narf_scheduler::yield_now().await;
    }
}
struct FakeMes {
    mapped: Arc<AtomicU32>,
    fail: Option<api::QueueType>,
    stall: Option<api::QueueType>,
}
impl Mapper for FakeMes {
    async fn map(&mut self, q: api::KernelQueue) -> Result<(), mes::Error> {
        let pipe = match q.kind {
            api::QueueType::Graphics => 0,
            api::QueueType::Compute => 1,
            _ => panic!("wrong MES queue type"),
        };
        assert_eq!((q.pipe, q.queue), (0, 0));
        assert_eq!(q.mqd, GPU + pipe * 12288 + 4096);
        assert_eq!(q.write_pointer, GPU + pipe * 12288 + 10248);
        assert_eq!(q.doorbell, if pipe == 0 { 0x116 } else { 6 });
        if self.fail == Some(q.kind) {
            return Err(mes::Error::Timeout);
        }
        if self.stall == Some(q.kind) {
            core::future::pending::<()>().await;
        }
        self.mapped.fetch_or(1 << pipe, Ordering::SeqCst);
        Ok(())
    }
}
fn fixture() -> (Pool, Engine<Fake>, FakeMes, gmc::Aperture, MmioRegion) {
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(0x90004000),
        virt: 0,
        len: 24576,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: model intercepts all memory accesses, bookkeeping-only mapping.
    let pool = unsafe { Pool::from_owned_range(map, GPU) }.unwrap();
    let mapped = Arc::new(AtomicU32::new(0));
    let e = Engine {
        io: Fake {
            index: 0x32,
            memory: vec![u32::MAX; 6144],
            target: vec![u32::MAX; 2048],
            dirty: false,
            mapped: mapped.clone(),
            progress: Arc::new(AtomicU32::new(0)),
            eop: Arc::new(core::array::from_fn(|_| AtomicU32::new(0))),
            emit_eop: true,
            emit_cpu: true,
            bells: Vec::new(),
            complete: true,
            corrupt: false,
            rptr_stuck: false,
            busy: false,
            revoked: None,
            fence_revoke: None,
            fence_gone: false,
            fence_reads: 0,
            regs: BTreeMap::from([
                (0x17828, 0x84000000),
                (0x17894, 0x84000000),
                (0x53000, 1),
                (0x42600, 0),
                (0x4a410, 0xbc00000a),
            ]),
            job_writes: Vec::new(),
            job_waits: Vec::new(),
            job_hdp: Vec::new(),
            hdp_complete: true,
            job_syncs: 0,
            job_pipeline_syncs: Vec::new(),
            job_context_controls: Vec::new(),
            job_mem_syncs: 0,
            job_ibs: Vec::new(),
            hqd_resets: Vec::new(),
            hqd_stuck: false,
            reset_trace: Vec::new(),
            active: [false; 4],
            dequeue: [0; 4],
            drop_reset_write: None,
            rlc_stuck: false,
            rlc_pending: 0,
            restored: false,
            shader_execute: true,
            shader_corrupt: false,
            shader_overrun: false,
            shader_skip_fence: false,
        },
        authority: Cap::bootstrap(),
        layout: Layout {
            gc: 0x10000,
            hyp: 0x40000,
            oss: 0x70000,
            nbio: 0x60000,
        },
        doorbells: map,
        memory: pool.reserve(24576).unwrap(),
        state: State::Prepared,
        proof: None,
        interrupt_result: None,
        job_wptr: [512; 2],
        job_seq: [0; 2],
        shader_engines: 4,
        shader_result: None,
    };
    let mes = FakeMes {
        mapped,
        fail: None,
        stall: None,
    };
    let aperture = gmc::Aperture {
        start: VA,
        size: 2 << 20,
        source: VA,
        destination: VA + 4096,
    };
    let target = MmioRegion {
        phys: narf_memory::PhysAddr::new(0x90100000),
        len: 8192,
        ..map
    };
    (pool, e, mes, aperture, target)
}
fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}
fn gfx12_kernel_queues_execute_confirmed_writes_through_owned_translation() -> TestResult {
    let (pool, mut e, mut mes, aperture, target) = fixture();
    assert_eq!(
        run(e.initialize(&mut mes, aperture, target)),
        Ok(Proof {
            graphics_fence: 0x9070cafe,
            compute_fence: 0x9070beef,
            written_bytes: 128
        })
    );
    assert_eq!(e.state, State::Verified);
    assert_eq!(e.io.index, 0x32);
    assert_eq!(e.io.bells, [0x116, 6]);
    assert_eq!(
        run(e.initialize(&mut mes, aperture, target)),
        Err(Error::Busy)
    );
    drop(e);
    assert_eq!(pool.available(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_kernel_queues_execute_confirmed_writes_through_owned_translation
);

fn gfx12_kernel_queues_refuse_inherited_hqds_and_bad_apertures() -> TestResult {
    for case in 0..3 {
        let (pool, mut e, mut mes, mut aperture, target) = fixture();
        let expected = match case {
            0 => {
                e.io.busy = true;
                Error::Busy
            }
            1 => {
                aperture.destination += 4096;
                Error::Invalid
            }
            _ => {
                e.authority.revoke();
                Error::Revoked
            }
        };
        assert_eq!(run(e.initialize(&mut mes, aperture, target)), Err(expected));
        assert_eq!(e.io.index, 0x32);
        assert!(e.io.bells.is_empty());
        assert_eq!(mes.mapped.load(Ordering::SeqCst), 0);
        drop(e);
        assert_eq!(pool.available(), 24576);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_kernel_queues_refuse_inherited_hqds_and_bad_apertures
);

fn gfx12_kernel_queue_failures_keep_mapped_storage_and_no_success_report() -> TestResult {
    for case in 0..5 {
        let (pool, mut e, mut mes, aperture, target) = fixture();
        let expected = match case {
            0 => {
                e.io.corrupt = true;
                Error::DataMismatch
            }
            1 => {
                e.io.rptr_stuck = true;
                Error::Timeout
            }
            2 => {
                e.io.complete = false;
                Error::Timeout
            }
            3 => {
                mes.fail = Some(api::QueueType::Compute);
                Error::Mes(mes::Error::Timeout)
            }
            _ => {
                e.io.revoked = Some(e.authority);
                Error::Revoked
            }
        };
        assert_eq!(run(e.initialize(&mut mes, aperture, target)), Err(expected));
        assert_eq!(e.state, State::Failed(expected));
        assert_eq!(e.proof, None);
        assert_eq!(e.io.bells, [0x116]);
        assert_eq!(
            run(e.initialize(&mut mes, aperture, target)),
            Err(Error::Busy)
        );
        drop(e);
        assert_eq!(pool.available(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_kernel_queue_failures_keep_mapped_storage_and_no_success_report
);

fn gfx12_kernel_queue_cancellation_retains_pending_maps_and_submissions() -> TestResult {
    for case in 0..3 {
        let (pool, mut e, mut mes, aperture, target) = fixture();
        match case {
            0 => mes.stall = Some(api::QueueType::Graphics),
            1 => mes.stall = Some(api::QueueType::Compute),
            _ => e.io.complete = false,
        };
        {
            let mut f = core::pin::pin!(e.initialize(&mut mes, aperture, target));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(
            e.state,
            match case {
                0 => State::Mapping(0),
                1 => State::Mapping(1),
                _ => State::Submitted(0),
            }
        );
        assert_eq!(
            run(e.initialize(&mut mes, aperture, target)),
            Err(Error::Busy)
        );
        drop(e);
        assert_eq!(pool.available(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_kernel_queue_cancellation_retains_pending_maps_and_submissions
);

struct FakeObserver {
    counters: Arc<[AtomicU32; 3]>,
    msi: bool,
    stall: bool,
    reject: bool,
}
impl FakeObserver {
    fn new(e: &Engine<Fake>) -> Self {
        Self {
            counters: e.io.eop.clone(),
            msi: true,
            stall: false,
            reject: false,
        }
    }
}
impl Observer for FakeObserver {
    async fn sample(
        &mut self,
        source: Source,
    ) -> Result<interrupts::Sample, crate::amdgpu_ih7::Error> {
        if self.stall {
            core::future::pending::<()>().await;
        }
        if self.reject {
            return Err(crate::amdgpu_ih7::Error::Protocol);
        }
        let pipe = match source {
            Source::Graphics => 0,
            Source::Compute => 1,
            Source::Sdma0 | Source::Vcn0 | Source::Jpeg0 => panic!("unexpected non-CP sample"),
        };
        Ok(interrupts::Sample {
            source,
            count: self.counters[pipe].load(Ordering::SeqCst).into(),
            cpu: self.counters[2].load(Ordering::SeqCst).into(),
            vector: self.msi.then_some(0x60),
        })
    }
    async fn observed(
        &mut self,
        sample: interrupts::Sample,
    ) -> Result<bool, crate::amdgpu_ih7::Error> {
        Ok(u64::from(
            self.counters[match sample.source {
                Source::Graphics => 0,
                Source::Compute => 1,
                Source::Sdma0 | Source::Vcn0 | Source::Jpeg0 => panic!("unexpected non-CP sample"),
            }]
            .load(Ordering::SeqCst),
        ) == sample.count + 1
            && (!self.msi || u64::from(self.counters[2].load(Ordering::SeqCst)) != sample.cpu))
    }
}
fn gfx12_eop_proof_requires_each_engine_fence_vector_and_cpu_delivery() -> TestResult {
    for msi in [true, false] {
        let (pool, mut e, mut mes, aperture, target) = fixture();
        run(e.initialize(&mut mes, aperture, target)).unwrap();
        let mut observer = FakeObserver::new(&e);
        observer.msi = msi;
        e.io.emit_cpu = msi;
        e.io.regs.insert(0x17828, 0x84100000);
        e.io.regs.insert(0x17894, 0x84200000);
        let expected = Ok(InterruptProof {
            fences: [0x90701234, 0x90705678],
            msi_verified: msi,
        });
        assert_eq!(
            run(e.prove_interrupts(&mut observer, aperture, target)),
            expected
        );
        assert_eq!(e.interrupt_result, Some(expected));
        assert_eq!(e.state, State::InterruptVerified);
        assert_eq!(e.io.bells, [0x116, 6, 0x116, 6]);
        assert_eq!(e.io.regs[&0x17828], 0x84100000);
        assert_eq!(e.io.regs[&0x17894], 0x84200000);
        assert_eq!(
            run(e.prove_interrupts(&mut observer, aperture, target)),
            Err(Error::Busy)
        );
        drop(e);
        assert_eq!(pool.available(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_eop_proof_requires_each_engine_fence_vector_and_cpu_delivery
);

fn gfx12_eop_missing_evidence_faults_and_revocation_never_report_success() -> TestResult {
    for case in 0..8 {
        let (pool, mut e, mut mes, mut aperture, target) = fixture();
        run(e.initialize(&mut mes, aperture, target)).unwrap();
        let mut observer = FakeObserver::new(&e);
        let expected = match case {
            0 => {
                e.io.emit_eop = false;
                Error::Timeout
            }
            1 => {
                e.io.emit_cpu = false;
                Error::Timeout
            }
            2 => {
                e.io.corrupt = true;
                Error::Timeout
            }
            3 => {
                e.io.rptr_stuck = true;
                Error::Timeout
            }
            4 => {
                e.io.revoked = Some(e.authority);
                Error::Revoked
            }
            5 => {
                observer.reject = true;
                Error::Interrupts(crate::amdgpu_ih7::Error::Protocol)
            }
            6 => {
                aperture.start = u64::MAX;
                aperture.source = u64::MAX;
                Error::Invalid
            }
            _ => {
                e.io.regs.insert(0x17828, 0);
                Error::Busy
            }
        };
        assert_eq!(
            run(e.prove_interrupts(&mut observer, aperture, target)),
            Err(expected)
        );
        assert_eq!(e.interrupt_result, Some(Err(expected)));
        assert_eq!(e.state, State::Failed(expected));
        assert_eq!(e.io.bells.len(), if case >= 5 { 2 } else { 3 });
        assert_eq!(
            run(e.prove_interrupts(&mut observer, aperture, target)),
            Err(Error::Busy)
        );
        drop(e);
        assert_eq!(pool.available(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_eop_missing_evidence_faults_and_revocation_never_report_success
);

fn gfx12_eop_cancellation_retains_sources_queues_and_prevents_replay() -> TestResult {
    for before_submit in [true, false] {
        let (pool, mut e, mut mes, aperture, target) = fixture();
        run(e.initialize(&mut mes, aperture, target)).unwrap();
        let mut observer = FakeObserver::new(&e);
        observer.stall = before_submit;
        e.io.complete = false;
        {
            let mut f = core::pin::pin!(e.prove_interrupts(&mut observer, aperture, target));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(e.state, State::InterruptSubmitted(0));
        assert_eq!(e.interrupt_result, None);
        assert_eq!(e.io.bells.len(), if before_submit { 2 } else { 3 });
        assert_eq!(
            run(e.prove_interrupts(&mut observer, aperture, target)),
            Err(Error::Busy)
        );
        drop(e);
        assert_eq!(pool.available(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_eop_cancellation_retains_sources_queues_and_prevents_replay
);

/// Client jobs on the graphics ring, as gfx_v12_0 frames them: each job's
/// 256-dword slot carries the VM flush for its VMID on the GFX hub through
/// the ring's engine 0 (PT base written through the PFP, then REQ written
/// and ACK waited for, then PFP_SYNC_ME), its IB under that VMID, and an
/// interrupting fence of its sequence. Slots wrap around the 1024-dword
/// ring; a ring the CP has not drained refuses a fifth job; bad jobs and
/// jobs before both proofs are refused without a write.
fn gfx12_graphics_queue_runs_client_jobs_with_vm_flushes() -> TestResult {
    let (_pool, mut e, mut mes, aperture, target) = fixture();
    run(e.initialize(&mut mes, aperture, target)).unwrap();
    let job = Job::new(3, 0x1234, 0x1_0000_8001, &[(0x2_0000_1000, 64)]).unwrap();
    if e.submit(Pipe::Graphics, job) != Err(Error::Busy) {
        return TestResult::Fail("job before the interrupt proof");
    }
    // As the interrupt proof leaves the graphics ring.
    e.state = State::InterruptVerified;
    e.io.memory[2560] = 512;
    let writes = e.io.bells.len();
    for bad in [
        Job { vmid: 0, ..job },
        Job { vmid: 16, ..job },
        Job::new(3, 1, 0x1_0000_8001, &[(0x2_0000_1000, 0)]).unwrap(),
        Job::new(3, 1, 0x1_0000_8001, &[(0x2_0000_1002, 64)]).unwrap(),
        Job { ib_count: 0, ..job },
    ] {
        if e.submit(Pipe::Graphics, bad) != Err(Error::Invalid) || e.io.bells.len() != writes {
            return TestResult::Fail("bad job");
        }
    }
    if e.submit(Pipe::Graphics, job) != Ok(1) || e.completed_job(Pipe::Graphics) != Ok(1) {
        return TestResult::Fail("first job");
    }
    let gc = 0x10000 / 4;
    let lut = 0x70000 / 4;
    if e.io.job_writes
        != [
            (gc + 0x168f + 6, 0x8001),
            (gc + 0x1690 + 6, 1),
            (lut + 3, 0x1234),
        ]
        || e.io.job_waits != [(gc + 0x1647, gc + 0x1659, 0x00f8_0008, 8, 0x143)]
        || e.io.job_syncs != 1
        || e.io.job_pipeline_syncs != [(GPU + 10496, 0)]
        || e.io.job_context_controls != [0x8101_8003]
        || e.io.job_mem_syncs != 0
        || e.io.job_hdp != [1]
        || e.io.job_ibs != [(0x2_0000_1000, 64 | 3 << 24)]
        || e.io.memory[2562] != 768
    {
        return TestResult::Fail("first job's packets");
    }
    // Four more wrap the ring (slots at 768, 0, 256, 512).
    // Job 3 follows the same context: CONTEXT_CONTROL only enables loads.
    for seq in 2..=5 {
        let next = Job {
            vmid: 5,
            ctx_switch: seq != 3,
            ..job
        };
        if e.submit(Pipe::Graphics, next) != Ok(seq) || e.completed_job(Pipe::Graphics) != Ok(seq) {
            return TestResult::Fail("wrapped jobs");
        }
    }
    if e.io.job_context_controls[2] != 0x8000_0000 || e.io.job_context_controls[3] != 0x8101_8003 {
        return TestResult::Fail("CONTEXT_CONTROL without a context switch");
    }
    if Job::new(3, 1, 0, &[(0, 1); 9]).is_some() {
        return TestResult::Fail("more IBs than a slot holds");
    }
    if e.io.job_ibs.len() != 5 || e.io.job_ibs[4].1 != 64 | 5 << 24 || e.io.memory[2562] != 1792 {
        return TestResult::Fail("wrapped job slots");
    }
    // Several IBs run in order under the job's VMID, in one slot.
    let three = [
        (0x3_0000_0000, 16),
        (0x3_0000_1000, 32),
        (0x3_0000_2000, 48),
    ];
    let multi = Job::new(4, 0x99, 0x1_0000_8001, &three).unwrap();
    if e.submit(Pipe::Graphics, multi) != Ok(6)
        || e.completed_job(Pipe::Graphics) != Ok(6)
        || e.io.job_ibs[5..]
            != [
                (0x3_0000_0000, 16 | 4 << 24),
                (0x3_0000_1000, 32 | 4 << 24),
                (0x3_0000_2000, 48 | 4 << 24),
            ]
    {
        return TestResult::Fail("multi-IB job");
    }
    // The compute queue: its own ring, fence and engine (1), no PFP.
    e.io.memory[3072 + 2560] = 512;
    let syncs = e.io.job_syncs;
    let writes = e.io.job_writes.len();
    let compute = Job::new(2, 0x55, 0x1_0000_8001, &[(0x2_0000_4000, 8)]).unwrap();
    if e.submit(Pipe::Compute, compute) != Ok(1)
        || e.completed_job(Pipe::Compute) != Ok(1)
        || e.completed_job(Pipe::Graphics) != Ok(6)
        || e.io.job_syncs != syncs
        || e.io.job_writes[writes..]
            != [
                (gc + 0x168f + 4, 0x8001),
                (gc + 0x1690 + 4, 1),
                (lut + 2, 0x55),
            ]
        || e.io.job_waits.last() != Some(&(gc + 0x1648, gc + 0x165a, 0x00f8_0004, 4, 0x43))
        || e.io.job_ibs.last() != Some(&(0x2_0000_4000, 8 | 1 << 23 | 2 << 24))
        || e.io.memory[3072 + 2562] != 768
        || e.io.job_pipeline_syncs.last() != Some(&(GPU + 12288 + 10496, 0))
        || e.io.job_hdp.last() != Some(&4)
    {
        return TestResult::Fail("compute job");
    }
    // A reused VMID: no flush and no LUT write, only the IB and fence.
    let (writes, waits) = (e.io.job_writes.len(), e.io.job_waits.len());
    let pipeline_syncs = e.io.job_pipeline_syncs.len();
    let hdp = e.io.job_hdp.len();
    let reused = Job {
        flush: false,
        map_pasid: false,
        ..compute
    };
    if e.submit(Pipe::Compute, reused) != Ok(2)
        || e.completed_job(Pipe::Compute) != Ok(2)
        || e.io.job_writes.len() != writes
        || e.io.job_waits.len() != waits
        || e.io.job_pipeline_syncs.len() != pipeline_syncs
        || e.io.job_hdp.len() != hdp + 1
        || e.io.job_hdp.last() != Some(&4)
        || e.io.job_ibs.last() != Some(&(0x2_0000_4000, 8 | 1 << 23 | 2 << 24))
    {
        return TestResult::Fail("job on a reused VMID");
    }
    // A memory sync: ACQUIRE_MEM before the IB; compute has no
    // CONTEXT_CONTROL.
    let controls = e.io.job_context_controls.len();
    let synced = Job {
        mem_sync: true,
        ..reused
    };
    if e.submit(Pipe::Compute, synced) != Ok(3)
        || e.io.job_mem_syncs != 1
        || e.io.job_context_controls.len() != controls
    {
        return TestResult::Fail("memory sync");
    }
    // With the CP stalled, four slots fill and a fifth is refused.
    e.io.complete = false;
    for seq in 7..=10 {
        if e.submit(Pipe::Graphics, job) != Ok(seq) {
            return TestResult::Fail("filling the ring");
        }
    }
    let bells = e.io.bells.len();
    if e.submit(Pipe::Graphics, job) != Err(Error::Busy)
        || e.io.bells.len() != bells
        || e.completed_job(Pipe::Graphics) != Ok(6)
    {
        return TestResult::Fail("full ring");
    }
    // The ring test after a reset needs a free slot too: the CP must have
    // let go of the stalled jobs first.
    if e.submit_fence(Pipe::Graphics) != Err(Error::Busy) {
        return TestResult::Fail("ring test on a ring the CP never drained");
    }
    // A reset that dropped the stalled slots (RPTR caught up): the test is
    // a fence of the next sequence and nothing else.
    e.io.memory[2560] = e.job_wptr[0] as u32;
    e.io.complete = true;
    let (ibs, writes, waits) = (
        e.io.job_ibs.len(),
        e.io.job_writes.len(),
        e.io.job_waits.len(),
    );
    if e.submit_fence(Pipe::Graphics) != Ok(11)
        || e.completed_job(Pipe::Graphics) != Ok(11)
        || (
            e.io.job_ibs.len(),
            e.io.job_writes.len(),
            e.io.job_waits.len(),
        ) != (ibs, writes, waits)
    {
        return TestResult::Fail("ring test slot");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_graphics_queue_runs_client_jobs_with_vm_flushes
);

/// A missing NBIO acknowledgement must prevent both the IB and its fence,
/// even when the VMID itself needs no flush and the CP has ring space.
fn gfx12_hdp_acknowledgement_precedes_execution_on_both_queues() -> TestResult {
    for pipe in [Pipe::Graphics, Pipe::Compute] {
        let (_pool, mut e, mut mes, aperture, target) = fixture();
        run(e.initialize(&mut mes, aperture, target)).unwrap();
        e.state = State::InterruptVerified;
        let p = pipe.index();
        e.io.memory[p * 3072 + 2560] = 512;
        e.io.hdp_complete = false;
        let job = Job {
            flush: false,
            map_pasid: false,
            ..Job::new(3, 0x42, 0, &[(0x2_0000_1000, 64)]).unwrap()
        };
        assert_eq!(e.submit(pipe, job), Ok(1));
        assert_eq!(e.completed_job(pipe), Ok(0));
        assert_eq!(e.io.memory[p * 3072 + 2560], 512);
        assert!(e.io.job_ibs.is_empty());
        assert_eq!(e.io.job_hdp, [if p == 0 { 1 } else { 4 }]);
        e.io.hdp_complete = true;
        e.io.execute_jobs(p, 768);
        assert_eq!(e.io.job_ibs.len(), 1);
        assert_eq!(e.completed_job(pipe), Ok(1));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_hdp_acknowledgement_precedes_execution_on_both_queues
);

/// gfx_v12_0_reset_kcq's queue half: a reset dequeue and SPI queue reset
/// under the compute selection (the prior one restored), waiting for the
/// HQD to go idle; then the descriptor as first built, a NOP ring and
/// pointers at 0, so the ring test runs from the ring's start.
fn gfx12_compute_queue_resets_by_mmio_and_restores_for_remap() -> TestResult {
    let (_pool, mut e, mut mes, aperture, target) = fixture();
    run(e.initialize(&mut mes, aperture, target)).unwrap();
    if run(e.reset_compute_hqd()) != Err(Error::Busy)
        || e.restore(Pipe::Compute) != Err(Error::Busy)
    {
        return TestResult::Fail("reset before the interrupt proof");
    }
    e.state = State::InterruptVerified;
    e.io.memory[3072 + 2560] = 512;
    // A compute job the CP never finishes.
    e.io.complete = false;
    let job = Job::new(3, 1, 0x1_0000_8001, &[(0x2_0000_1000, 64)]).unwrap();
    if e.submit(Pipe::Compute, job) != Ok(1) {
        return TestResult::Fail("hung job");
    }
    let graphics = e.io.memory[..3072].to_vec();
    let reset = [(4, 0x17f04, 2), (4, 0x17dcc, 1)];
    e.io.rlc_pending = 2;
    if run(e.reset_compute_hqd()) != Ok(())
        || e.io.hqd_resets != reset
        || e.io.index != 0x32
        || e.io.reset_trace != [(0x32, 0x42600, 3), reset[0], reset[1], (0x32, 0x42600, 1)]
    {
        return TestResult::Fail("MMIO compute queue reset");
    }
    assert_eq!(e.state, State::ComputeReset);
    assert_eq!(run(e.reset_compute_hqd()), Err(Error::Busy));
    assert_eq!(e.submit_fence(Pipe::Compute), Err(Error::Busy));
    if e.restore(Pipe::Compute) != Ok(()) {
        return TestResult::Fail("restore");
    }
    let m = &e.io.memory[3072..6144];
    if m[1024..1536] != descriptor(GPU, 1).unwrap()
        || m[..1024].iter().any(|&w| w != RING_NOP)
        || m[2560..2562] != [0, 0]
        || m[2562..2564] != [0, 0]
        || e.io.memory[..3072] != graphics[..]
    {
        return TestResult::Fail("restored compute queue");
    }
    // Mapped again from that descriptor, the ring test is the first slot.
    e.io.restored = true;
    e.io.complete = true;
    if e.submit_fence(Pipe::Compute) != Ok(2)
        || e.completed_job(Pipe::Compute) != Ok(2)
        || e.io.memory[3072 + 2562] != 256
    {
        return TestResult::Fail("ring test after the restore");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_compute_queue_resets_by_mmio_and_restores_for_remap
);

/// Exercise the timeout-to-pipe-reset path, then remap and run a fence.
/// Every HQD must be cleared between reset assertion/deassertion, while
/// unrelated MEC control bits and the graphics ring remain unchanged.
fn gfx12_compute_timeout_resets_the_pipe_before_restoring() -> TestResult {
    let (_pool, mut e, mut mes, aperture, target) = fixture();
    run(e.initialize(&mut mes, aperture, target)).unwrap();
    e.state = State::InterruptVerified;
    e.io.memory[3072 + 2560] = 512;
    e.io.complete = false;
    let job = Job::new(3, 1, 0x1_0000_8001, &[(0x2_0000_1000, 64)]).unwrap();
    assert_eq!(e.submit(Pipe::Compute, job), Ok(1));
    let graphics = e.io.memory[..3072].to_vec();
    e.io.hqd_stuck = true;
    assert_eq!(run(e.reset_compute_hqd()), Ok(()));
    let mut expected = vec![
        (0x32, 0x42600, 3),
        (4, 0x17f04, 2),
        (4, 0x17dcc, 1),
        (4, 0x4a410, 0xbc01000a),
    ];
    for q in 0..4 {
        expected.extend([(4 | q << 8, 0x17eac, 0), (4 | q << 8, 0x17f04, 0)]);
    }
    expected.extend([(4, 0x4a410, 0xbc00000a), (0x32, 0x42600, 1)]);
    assert_eq!(e.io.reset_trace, expected);
    assert_eq!(e.io.index, 0x32);
    assert_eq!(e.state, State::ComputeReset);
    assert_eq!(
        e.completed_job(Pipe::Compute),
        Ok(0),
        "reset is not completion"
    );
    assert_eq!(e.restore(Pipe::Compute), Ok(()));
    assert_eq!(e.io.memory[..3072], graphics);
    e.io.restored = true;
    e.io.complete = true;
    assert_eq!(e.submit_fence(Pipe::Compute), Ok(2));
    assert_eq!(e.completed_job(Pipe::Compute), Ok(2));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_compute_timeout_resets_the_pipe_before_restoring
);

/// Test the synchronous fallback's failure boundaries without spending a
/// dequeue timeout on every injected fault.
fn gfx12_compute_pipe_reset_refuses_foreign_hqds_and_lost_writes() -> TestResult {
    for case in 0..7 {
        let (_pool, mut e, _mes, _aperture, _target) = fixture();
        e.io.regs.insert(0x42600, 2);
        e.io.hqd_resets.push((4, 0x17f04, 2));
        e.io.hqd_stuck = true;
        let expected = match case {
            0 => {
                e.io.active[2] = true;
                Error::Busy
            }
            1 => {
                e.io.regs.insert(0x4a410, 0xbc01000a);
                Error::Busy
            }
            2 => {
                e.io.drop_reset_write = Some((0x4a410, 0xbc01000a));
                Error::Readback
            }
            3 => {
                e.io.drop_reset_write = Some((0x17eac, 0));
                Error::Readback
            }
            4 => {
                e.io.drop_reset_write = Some((0x4a410, 0xbc00000a));
                Error::Readback
            }
            5 => {
                e.io.regs.insert(0x4a410, !0);
                Error::DeviceGone
            }
            _ => {
                e.authority.revoke();
                Error::Revoked
            }
        };
        assert_eq!(e.reset_compute_pipe(), Err(expected));
        assert_eq!(e.io.index, 0x32);
        if matches!(case, 0 | 1 | 5 | 6) {
            assert!(e.io.reset_trace.is_empty(), "must refuse before writes");
        }
        if matches!(case, 3 | 4) {
            assert_ne!(
                e.io.regs[&0x4a410] & (1 << 16),
                0,
                "uncertain pipe stays reset"
            );
        }
        assert!(e.io.bells.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_compute_pipe_reset_refuses_foreign_hqds_and_lost_writes
);

fn gfx12_compute_reset_quarantines_cancellation_and_revocation() -> TestResult {
    for (safe_wait, revoke) in [(true, false), (false, false), (true, true), (false, true)] {
        let (pool, mut e, mut mes, aperture, target) = fixture();
        run(e.initialize(&mut mes, aperture, target)).unwrap();
        e.state = State::InterruptVerified;
        e.io.rlc_stuck = safe_wait;
        e.io.hqd_stuck = true;
        let cap = e.authority;
        {
            let mut future = core::pin::pin!(e.reset_compute_hqd());
            let mut cx = Context::from_waker(Waker::noop());
            assert!(future.as_mut().poll(&mut cx).is_pending());
            if revoke {
                cap.revoke();
                assert_eq!(run(future), Err(Error::Revoked));
            }
        }
        assert_eq!(
            e.state,
            if revoke {
                State::Failed(Error::Revoked)
            } else {
                State::ResettingCompute
            }
        );
        assert_eq!(e.io.index, 0x32);
        let before = e.io.reset_trace.clone();
        assert_eq!(run(e.reset_compute_hqd()), Err(Error::Busy));
        assert_eq!(e.restore(Pipe::Compute), Err(Error::Busy));
        assert_eq!(e.submit_fence(Pipe::Compute), Err(Error::Busy));
        assert_eq!(e.submit_fence(Pipe::Graphics), Err(Error::Busy));
        assert_eq!(e.io.reset_trace, before);
        if safe_wait {
            assert!(e.io.hqd_resets.is_empty());
        }
        assert!(!before.iter().any(|&(_, at, _)| at == 0x4a410));
        drop(e);
        assert_eq!(pool.available(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_compute_reset_quarantines_cancellation_and_revocation
);

fn gfx12_compute_reset_requires_rlc_acknowledgement() -> TestResult {
    let (_pool, mut e, _mes, _aperture, _target) = fixture();
    e.state = State::InterruptVerified;
    e.io.rlc_stuck = true;
    assert_eq!(run(e.reset_compute_hqd()), Err(Error::Timeout));
    assert_eq!(e.state, State::Failed(Error::Timeout));
    assert!(e.io.hqd_resets.is_empty());
    assert_eq!(e.io.reset_trace, [(0x32, 0x42600, 3), (0x32, 0x42600, 1)]);
    assert_eq!(run(e.reset_compute_hqd()), Err(Error::Busy));

    let (_pool, mut e, _mes, _aperture, _target) = fixture();
    e.state = State::InterruptVerified;
    e.io.regs.insert(0x53000, 0); // Disabled RLC cannot acknowledge commands.
    assert_eq!(run(e.reset_compute_hqd()), Ok(()));
    assert_eq!(e.io.reset_trace, [(4, 0x17f04, 2), (4, 0x17dcc, 1)]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_compute_reset_requires_rlc_acknowledgement
);

fn shader_ready() -> (Pool, Engine<Fake>, gmc::Aperture, MmioRegion, FakeObserver) {
    let (pool, mut e, mut mes, aperture, target) = fixture();
    run(e.initialize(&mut mes, aperture, target)).unwrap();
    let mut observer = FakeObserver::new(&e);
    e.io.regs.insert(0x17828, 0x84100000);
    e.io.regs.insert(0x17894, 0x84200000);
    run(e.prove_interrupts(&mut observer, aperture, target)).unwrap();
    (pool, e, aperture, target, observer)
}
fn gfx12_shader_proof_requires_isa_output_and_fresh_completion() -> TestResult {
    for msi in [true, false] {
        let (pool, mut e, aperture, target, mut observer) = shader_ready();
        observer.msi = msi;
        e.io.emit_cpu = msi;
        let proof = run(e.prove_shaders(&mut observer, async { Ok((aperture, target)) })).unwrap();
        assert_eq!(
            proof,
            crate::amdgpu_gfx12_shader::Proof {
                lanes: 32,
                fences: [1, 1],
                msi_verified: msi
            }
        );
        assert_eq!(e.shader_result, Some(Ok(proof)));
        assert_eq!(e.state, State::InterruptVerified);
        assert_eq!(e.job_wptr, [768, 768]);
        assert_eq!(e.io.job_ibs.len(), 2);
        assert_eq!(
            run(e.prove_shaders(&mut observer, async { Ok((aperture, target)) })),
            Err(Error::Busy)
        );
        // Client fences continue after the diagnostic's physical sequence.
        // The completed proof must not retire a subsequently stalled IB.
        let job = Job::new(3, 0x1234, 0x1_0000_8001, &[(0x2_0000_1000, 64)]).unwrap();
        e.io.complete = false;
        for pipe in [Pipe::Graphics, Pipe::Compute] {
            assert_eq!(e.submit(pipe, job), Ok(2));
            assert_eq!(e.completed_job(pipe), Ok(1));
            e.io.execute_jobs(pipe.index(), 1024);
            assert_eq!(e.completed_job(pipe), Ok(2));
        }
        drop(e);
        assert_eq!(pool.available(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_shader_proof_requires_isa_output_and_fresh_completion
);
fn gfx12_shader_failures_never_enable_clients_or_release_memory() -> TestResult {
    for case in 0..8 {
        let (pool, mut e, aperture, target, mut observer) = shader_ready();
        let expected = match case {
            0 => {
                e.io.shader_execute = false;
                Error::DataMismatch
            }
            1 => {
                e.io.shader_corrupt = true;
                Error::DataMismatch
            }
            2 => {
                e.io.shader_overrun = true;
                Error::DataMismatch
            }
            3 => {
                e.io.shader_skip_fence = true;
                Error::Timeout
            }
            4 => {
                e.io.emit_eop = false;
                Error::Timeout
            }
            5 => {
                e.io.emit_cpu = false;
                Error::Timeout
            }
            6 => {
                e.io.rptr_stuck = true;
                Error::Timeout
            }
            _ => {
                observer.reject = true;
                Error::Interrupts(crate::amdgpu_ih7::Error::Protocol)
            }
        };
        let result = run(e.prove_shaders(&mut observer, async { Ok((aperture, target)) }));
        assert_eq!(result, Err(expected));
        assert_eq!(e.state, State::Failed(expected));
        assert_eq!(e.submit_fence(Pipe::Compute), Err(Error::Busy));
        drop(e);
        assert_eq!(pool.available(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_shader_failures_never_enable_clients_or_release_memory
);
fn gfx12_shader_cancellation_and_late_clients_refuse_replay() -> TestResult {
    for before_publish in [true, false] {
        let (pool, mut e, aperture, target, mut observer) = shader_ready();
        if !before_publish {
            e.io.complete = false;
        }
        {
            let prepare = async {
                if before_publish {
                    core::future::pending::<()>().await;
                }
                Ok((aperture, target))
            };
            let mut future = core::pin::pin!(e.prove_shaders(&mut observer, prepare));
            assert!(future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert!(matches!(e.state, State::ShaderSubmitted(_)));
        let bells = e.io.bells.len();
        assert_eq!(
            run(e.prove_shaders(&mut observer, async { Ok((aperture, target)) })),
            Err(Error::Busy)
        );
        assert_eq!(e.submit_fence(Pipe::Graphics), Err(Error::Busy));
        assert_eq!(e.io.bells.len(), bells);
        drop(e);
        assert_eq!(pool.available(), 0);
    }
    let (_, mut e, aperture, target, mut observer) = shader_ready();
    e.submit_fence(Pipe::Compute).unwrap();
    let bells = e.io.bells.len();
    let called = core::sync::atomic::AtomicBool::new(false);
    assert_eq!(
        run(e.prove_shaders(&mut observer, async {
            called.store(true, Ordering::SeqCst);
            Ok((aperture, target))
        })),
        Err(Error::Busy)
    );
    assert!(!called.load(Ordering::SeqCst));
    assert_eq!(e.io.bells.len(), bells);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_shader_cancellation_and_late_clients_refuse_replay
);

fn gfx12_shader_rejects_unowned_addresses_and_failed_preparation() -> TestResult {
    use crate::amdgpu_gfx12_shader as shader;
    for (code, output, engines) in [
        (VA + 4, VA + 4160, 4),
        (1 << 48, VA + 4160, 4),
        (VA, VA + 4161, 4),
        (VA, (1 << 48) - 124, 4),
        (VA, u64::MAX - 3, 4),
        (VA, VA + 4160, 0),
        (VA, VA + 4160, 9),
    ] {
        assert_eq!(shader::ib(code, output, engines, 0), Err(Error::Invalid));
    }
    for case in 0..4 {
        let (pool, mut e, mut aperture, mut target, mut observer) = shader_ready();
        let bells = e.io.bells.len();
        let prep = match case {
            0 => Err(gmc::Error::Revoked),
            1 => {
                aperture.destination += 4096;
                Ok((aperture, target))
            }
            2 => {
                target.len -= 4;
                Ok((aperture, target))
            }
            _ => {
                e.authority.revoke();
                Ok((aperture, target))
            }
        };
        let expected = match case {
            0 => Error::Gmc(gmc::Error::Revoked),
            3 => Error::Revoked,
            _ => Error::Invalid,
        };
        assert_eq!(
            run(e.prove_shaders(&mut observer, async { prep })),
            Err(expected)
        );
        assert_eq!(e.io.bells.len(), bells);
        if case != 3 {
            assert_eq!(e.state, State::Failed(expected));
        }
        drop(e);
        assert_eq!(pool.available(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_shader_rejects_unowned_addresses_and_failed_preparation
);

fn gfx12_client_fences_reject_device_loss_and_revocation() -> TestResult {
    for pipe in [Pipe::Graphics, Pipe::Compute] {
        for case in 0..5 {
            let (pool, mut e, mut mes, aperture, target) = fixture();
            run(e.initialize(&mut mes, aperture, target)).unwrap();
            let available = pool.available();
            e.io.memory[((pipe.base() + JOB_FENCE) / 4) as usize] = u32::MAX;
            e.io.fence_reads = 0;
            match case {
                1 => {
                    e.io.regs.insert(0x60000 + 0xc3 * 4, u32::MAX);
                }
                2 => e.io.fence_gone = true,
                3 => {
                    e.authority.revoke();
                }
                4 => e.io.fence_revoke = Some(e.authority),
                _ => {}
            }
            let expected = match case {
                0 => Ok(u32::MAX), // valid sequence at physical wrap
                1 | 2 => Err(Error::DeviceGone),
                _ => Err(Error::Revoked),
            };
            assert_eq!(e.completed_job(pipe), expected);
            assert_eq!(e.io.fence_reads, u32::from(!matches!(case, 1 | 3)));
            assert!(!e.memory.reusable_for_test());
            drop(e);
            assert_eq!(pool.available(), available);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_client_fences_reject_device_loss_and_revocation
);

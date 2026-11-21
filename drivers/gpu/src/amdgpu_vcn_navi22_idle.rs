//! VCN3 begin-use / delayed idle work, serialized by the platform owner.
//! Keep the PSP image, VCPU context, writebacks and logical sequences across
//! idle; reset only ring pointers when restoring the hardware.
use super::*;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const IDLE_NS: u64 = 1_000_000_000; // Linux VCN_IDLE_TIMEOUT
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Awake,
    Quiescing,
    Asleep,
    Waking,
    Failed,
}
#[derive(Debug)]
pub(crate) struct Runtime {
    pub phase: Phase,
    last_use: Option<u64>,
    images: [Option<u64>; 2],
    gb: u32,
    gated: bool,
}
impl Runtime {
    pub(super) fn gated(&self) -> bool {
        self.phase == Phase::Asleep && self.gated
    }
    pub const fn new() -> Self {
        Self {
            phase: Phase::Awake,
            last_use: None,
            images: [None; 2],
            gb: 0,
            gated: false,
        }
    }
    pub(super) fn initialized(&mut self, images: [Option<u64>; 2], gb: u32) {
        self.images = images;
        self.gb = gb;
    }
}
pub(crate) trait Control: SramLoader {
    /// False means MM_DPM_PG is disabled; no SMU power message was sent.
    async fn power(&mut self, instances: [bool; 2], on: bool) -> Result<bool, Error>;
}
pub(crate) struct Owned<'a> {
    pub smu: Option<&'a mut crate::amdgpu_smu_navi22::Smu>,
    pub psp: &'a mut crate::amdgpu_psp_ring::Psp,
}
impl SramLoader for Owned<'_> {
    async fn load_sram(&mut self, instance: usize, words: &[u32]) -> Result<(), Error> {
        self.psp.load_sram(instance, words).await
    }
}
impl Control for Owned<'_> {
    async fn power(&mut self, instances: [bool; 2], on: bool) -> Result<bool, Error> {
        match self.smu.as_mut() {
            Some(smu) => smu.set_vcn_power(instances, on).await.map_err(Error::Power),
            None => Ok(false),
        }
    }
}
impl<I: Io> Engine<I> {
    fn unpause_idle(&mut self, i: usize) -> Result<(), Error> {
        if self.mode == StartMode::Dpg && self.paused[i] {
            self.hw.access(|io, l| {
                let at = l.reg(i, DPG_PAUSE);
                let value = checked(io.read(at))? & !DPG_PAUSE_ACK;
                io.write(at, value & !DPG_PAUSE_REQ);
                Ok(())
            })?;
            self.paused[i] = false;
        }
        Ok(())
    }
    pub(crate) async fn idle(&mut self, pm: &mut impl Control, now: u64) -> Result<bool, Error> {
        let result = self.idle_inner(pm, now).await;
        if result.is_err() {
            self.runtime.phase = Phase::Failed;
            self.state = State::Failed;
        }
        result
    }
    async fn idle_inner(&mut self, pm: &mut impl Control, now: u64) -> Result<bool, Error> {
        match self.runtime.phase {
            Phase::Asleep => return Ok(false),
            Phase::Awake => {}
            _ => return Err(Error::DeviceGone),
        }
        if !matches!(self.state, State::Running | State::Verified) {
            return Ok(false);
        }
        let last = *self.runtime.last_use.get_or_insert(now);
        if now.saturating_sub(last) < IDLE_NS {
            return Ok(false);
        }
        // `amdgpu_fence_count_emitted` over the rings that are ready.
        let counted: [[bool; 3]; 2] =
            core::array::from_fn(|i| core::array::from_fn(|slot| self.ring_counted(i, slot)));
        let instances = &self.vcn;
        let enc_count = self.enc_count;
        let (all_done, enc_done) = self.hw.access(|io, l| {
            invalidate(io, l);
            checked(io.read(l.hdp + 0xd1 * 4))?;
            let mut all = true;
            let mut enc = [true; 2];
            for (i, inst) in instances.iter().enumerate() {
                let Some(inst) = inst else {
                    continue;
                };
                let map = inst.memory.mapping();
                if counted[i][0] {
                    all &= fence::signaled(io.read_memory(map, FENCE[0]), inst.dec.seq);
                }
                for j in 0..enc_count {
                    if counted[i][j + 1] {
                        enc[i] &=
                            fence::signaled(io.read_memory(map, FENCE[j + 1]), inst.enc[j].seq);
                    }
                }
                all &= enc[i];
            }
            checked(io.read(l.hdp + 0xd1 * 4))?;
            Ok((all, enc))
        })?;
        self.runtime.phase = Phase::Quiescing;
        for (i, done) in enc_done.into_iter().enumerate() {
            if done {
                self.unpause_idle(i)?;
            }
        }
        if !all_done {
            self.runtime.phase = Phase::Awake;
            return Ok(false);
        }
        let started = narf_time::monotonic_ns();
        {
            use core::fmt::Write;
            let _ = writeln!(
                narf_console::PriorityWriter::<7>,
                "amdgpu: navi22 VCN idle gate: stopping the engines and powering them off"
            );
        }
        let result = match self.stop_instances().await {
            Ok(()) => {
                pm.power([self.vcn[0].is_some(), self.vcn[1].is_some()], false)
                    .await
            }
            Err(error) => Err(error),
        };
        note_gate(GateTrace {
            elapsed_ns: narf_time::monotonic_ns().saturating_sub(started),
            result,
        });
        self.runtime.gated = result?;
        self.runtime.phase = Phase::Asleep;
        MEDIA_ASLEEP.store(true, Ordering::Release);
        Ok(true)
    }
    /// When the idle work should look again. Linux queues `idle_work`
    /// VCN_IDLE_TIMEOUT after a ring's last use and re-queues it one timeout
    /// later while fences remain emitted: the rest of the timeout after a
    /// recent use, a full timeout while busy, and `None` once gated or
    /// unusable, until the next `begin_use`.
    pub(crate) fn idle_recheck(&self, now: u64) -> Option<u64> {
        if self.runtime.phase != Phase::Awake
            || !matches!(self.state, State::Running | State::Verified)
        {
            return None;
        }
        let since = self
            .runtime
            .last_use
            .map_or(0, |last| now.saturating_sub(last));
        Some(if since < IDLE_NS {
            IDLE_NS - since
        } else {
            IDLE_NS
        })
    }
    pub(crate) async fn begin_use(
        &mut self,
        pm: &mut impl Control,
        ring: MediaRing,
        now: u64,
    ) -> Result<(), Error> {
        if !self.client_ready(ring) {
            return Err(Error::Invalid);
        }
        if ring == MediaRing::Jpeg {
            return Ok(());
        }
        let result = self.begin_inner(pm, ring, now).await;
        if result.is_err() {
            self.runtime.phase = Phase::Failed;
            self.state = State::Failed;
        }
        result
    }
    async fn begin_inner(
        &mut self,
        pm: &mut impl Control,
        ring: MediaRing,
        now: u64,
    ) -> Result<(), Error> {
        if !matches!(self.state, State::Running | State::Verified) {
            return Err(Error::Busy);
        }
        let asleep = match self.runtime.phase {
            Phase::Asleep => true,
            Phase::Awake => false,
            _ => return Err(Error::DeviceGone),
        };
        self.runtime.last_use = Some(now);
        self.runtime.phase = Phase::Waking;
        // The idle work runs again from the next use on (Linux
        // `amdgpu_vcn_ring_begin_use` cancels it, `end_use` re-queues it).
        wake_idle_work();
        if asleep {
            if self.runtime.gated
                && !pm
                    .power([self.vcn[0].is_some(), self.vcn[1].is_some()], true)
                    .await?
            {
                return Err(Error::PowerGated);
            }
            let images = self.runtime.images;
            for (i, image) in images.into_iter().enumerate() {
                if self.vcn[i].is_none() {
                    continue;
                }
                match self.mode {
                    StartMode::Dpg => self.start_instance_dpg(i, self.runtime.gb, pm).await?,
                    StartMode::Static => {
                        self.start_instance(i, image.ok_or(Error::Invalid)?, self.runtime.gb)
                            .await?
                    }
                }
            }
            self.runtime.gated = false;
        }
        if matches!(ring, MediaRing::Enc(_)) && self.mode == StartMode::Dpg {
            self.pause_dpg(0).await?;
        }
        self.runtime.phase = Phase::Awake;
        Ok(())
    }
}

/// One idle gate attempt that reached the engine stop and PMFW power-off
/// (`vcn_v3_0_stop` + `amdgpu_dpm_enable_vcn(false)`): how long it took and
/// how it ended (`Ok(gated)`: whether PMFW gated the engines).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GateTrace {
    pub elapsed_ns: u64,
    pub result: Result<bool, Error>,
}

/// A gate attempt slower than this is reported above debug level.
const GATE_SLOW_NS: u64 = 100_000_000;

static LAST_GATE: narf_lib::sync::IrqSafeSpinLock<Option<GateTrace>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// The most recent gate attempt (read by the kernel tests).
#[cfg(feature = "kernel-test")]
pub(crate) fn last_gate() -> Option<GateTrace> {
    *LAST_GATE.lock()
}

/// Console level of a gate attempt's report: debug, unless it failed (err)
/// or took longer than [`GATE_SLOW_NS`] (warning).
pub(crate) fn gate_level(trace: &GateTrace) -> u32 {
    if trace.result.is_err() {
        3
    } else if trace.elapsed_ns > GATE_SLOW_NS {
        4
    } else {
        7
    }
}

/// Record and report the end of a gate attempt.
fn note_gate(trace: GateTrace) {
    use core::fmt::Write;
    *LAST_GATE.lock() = Some(trace);
    let (ms, us) = (
        trace.elapsed_ns / 1_000_000,
        trace.elapsed_ns / 1_000 % 1_000,
    );
    let _ = match (gate_level(&trace), trace.result) {
        (_, Err(error)) => writeln!(
            narf_console::PriorityWriter::<3>,
            "amdgpu: navi22 VCN idle gate failed after {ms}.{us:03} ms: {error:?}"
        ),
        (4, Ok(gated)) => writeln!(
            narf_console::PriorityWriter::<4>,
            "amdgpu: navi22 VCN idle gate took {ms}.{us:03} ms (power gated: {gated})"
        ),
        (_, Ok(gated)) => writeln!(
            narf_console::PriorityWriter::<7>,
            "amdgpu: navi22 VCN idle gate done in {ms}.{us:03} ms (power gated: {gated})"
        ),
    };
}

static EPOCH: AtomicU64 = AtomicU64::new(0);
/// The media engines are gated: the idle work has nothing to do until the
/// next `begin_use`, so its task parks instead of polling.
static MEDIA_ASLEEP: AtomicBool = AtomicBool::new(false);
static IDLE_WAKER: narf_lib::sync::IrqSafeSpinLock<Option<core::task::Waker>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

fn wake_idle_work() {
    MEDIA_ASLEEP.store(false, Ordering::Release);
    let waker = IDLE_WAKER.lock().take();
    if let Some(w) = waker {
        w.wake();
    }
}

/// Resolves when the media is in use again or the idle work stopped.
fn media_in_use(epoch: u64) -> impl core::future::Future<Output = ()> {
    core::future::poll_fn(move |cx| {
        let done =
            || !MEDIA_ASLEEP.load(Ordering::Acquire) || EPOCH.load(Ordering::Acquire) != epoch;
        if done() {
            return core::task::Poll::Ready(());
        }
        *IDLE_WAKER.lock() = Some(cx.waker().clone());
        if done() {
            return core::task::Poll::Ready(());
        }
        core::task::Poll::Pending
    })
}

pub(crate) fn stop() {
    EPOCH.fetch_add(1, Ordering::AcqRel);
    let waker = IDLE_WAKER.lock().take();
    if let Some(w) = waker {
        w.wake();
    }
}
/// The idle work failed (the engine is already `Failed`); its task ends.
/// Linux's `amdgpu_vcn_idle_work_handler` ignores `set_pg_state`'s result:
/// a VCN that cannot gate is a video failure, never the GPU's. Video is
/// withdrawn from clients (`AMDGPU_INFO` stops offering the rings) and
/// graphics keeps running. A GPU that really stopped answering is found by
/// the paths that own graphics: the hang detector's HDP read-back and the
/// submitter's fence sampling.
pub(crate) fn gate_failed(error: &crate::amdgpu_navi22_boot::Error) {
    crate::amdgpu_vcn_navi22_cs::unregister();
    use core::fmt::Write;
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: navi22 VCN idle failed: {error:?}; video closed, graphics continue"
    );
}
pub(crate) fn start() {
    let epoch = EPOCH.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
    MEDIA_ASLEEP.store(false, Ordering::Release);
    narf_scheduler::spawn(async move {
        // Linux queues `idle_work` VCN_IDLE_TIMEOUT after a ring's last use.
        let mut delay = IDLE_NS;
        loop {
            // Gated or unusable media: no idle work until the next use
            // (Linux queues `idle_work` from `ring_end_use` only).
            if MEDIA_ASLEEP.load(Ordering::Acquire) {
                media_in_use(epoch).await;
                delay = IDLE_NS;
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_ns(delay).as_instant()).await;
            if EPOCH.load(Ordering::Acquire) != epoch {
                return;
            }
            let mut owner = crate::amdgpu_navi22_platform::owner().await;
            if EPOCH.load(Ordering::Acquire) != epoch {
                return;
            }
            let Some(boot) = owner.as_mut() else {
                return;
            };
            if let Err(error) = boot.idle_media(narf_time::monotonic_ns()).await {
                gate_failed(&error);
                return;
            }
            match boot.media_idle_recheck(narf_time::monotonic_ns()) {
                Some(ns) => delay = ns,
                // Parked under the owner, which `begin_use` also holds, so its
                // `wake_idle_work` cannot fall between this and the park.
                None => MEDIA_ASLEEP.store(true, Ordering::Release),
            }
        }
    });
}

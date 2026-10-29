//! VCN3 begin-use / delayed idle work, serialized by the platform owner.
//! Keep the PSP image, VCPU context, writebacks and logical sequences across
//! idle; reset only ring pointers when restoring the hardware.
use super::*;
use core::sync::atomic::{AtomicU64, Ordering};

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
                all &= fence::signaled(io.read_memory(map, FENCE[0]), inst.dec.seq);
                for j in 0..enc_count {
                    enc[i] &= fence::signaled(io.read_memory(map, FENCE[j + 1]), inst.enc[j].seq);
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
        self.stop_instances().await?;
        self.runtime.gated = pm
            .power([self.vcn[0].is_some(), self.vcn[1].is_some()], false)
            .await?;
        self.runtime.phase = Phase::Asleep;
        Ok(true)
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

static EPOCH: AtomicU64 = AtomicU64::new(0);
pub(crate) fn stop() {
    EPOCH.fetch_add(1, Ordering::AcqRel);
}
pub(crate) fn start() {
    let epoch = EPOCH.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
    narf_scheduler::spawn(async move {
        loop {
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(100).as_instant()).await;
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
                crate::amdgpu_navi22_cs::abandon(narf_filesystem::FsError::NoDevice);
                use core::fmt::Write;
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: navi22 VCN idle failed: {error:?}"
                );
                return;
            }
        }
    });
}

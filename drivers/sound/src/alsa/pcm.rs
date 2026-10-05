use super::*;
use crate::{
    format::HwParams,
    pcm::{PcmSubstream, SubstreamState},
};
use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
};
use core::sync::atomic::{AtomicBool, Ordering};
use narf_filesystem::{FsFuture, MmapLifetime, POLL_ERR, POLL_IN, POLL_OUT};
use narf_lib::{mutex::Mutex, readiness::Readiness, sync::IrqSafeSpinLock};

const OPEN: u32 = 0;
const SETUP: u32 = 1;
const PREPARED: u32 = 2;
const RUNNING: u32 = 3;
const XRUN: u32 = 4;
const DRAINING: u32 = 5;
const PAUSED: u32 = 6;
const SUSPENDED: u32 = 7;
const DISCONNECTED: u32 = 8;
mod groups;
pub(crate) use groups::suspend_card;
const PAGE: usize = 4096;
const STATUS: u64 = 0x8000_0000;
const CONTROL: u64 = 0x8100_0000;
const STATUS64: u64 = 0x8200_0000;
const CONTROL64: u64 = 0x8300_0000;
const MAX_TRANSFER: usize = 256 * 1024;

/// Page-aligned, zeroed, separately owned memory. User mappings outlive both
/// HW_FREE and close through FileOps::mmap_lifetime. No Rust references are
/// ever formed to bytes concurrently writable by userspace.
#[derive(Debug)]
struct Pages(narf_io::DmaBuffer);
impl Pages {
    fn new(len: usize) -> Result<Arc<Self>, FsError> {
        narf_io::alloc_coherent(len, narf_lib::id::DomainId::DRIVER_0)
            .map(|b| Arc::new(Self(b)))
            .map_err(|_| FsError::OutOfMemory)
    }
    fn read(&self, offset: usize, out: &mut [u8]) {
        assert!(offset + out.len() <= self.0.len());
        for (i, b) in out.iter_mut().enumerate() {
            // SAFETY: checked live dedicated backing; volatile access does not
            // create references to memory userspace may concurrently modify.
            *b = unsafe { self.0.cpu_ptr::<u8>().add(offset + i).read_volatile() };
        }
    }
    fn write(&self, offset: usize, input: &[u8]) {
        assert!(offset + input.len() <= self.0.len());
        for (i, b) in input.iter().enumerate() {
            // SAFETY: same bounds/lifetime contract as read, no borrowed slice.
            unsafe {
                self.0
                    .cpu_mut_ptr::<u8>()
                    .add(offset + i)
                    .write_volatile(*b)
            };
        }
    }
    fn load64(&self, at: usize) -> u64 {
        assert!(at % 8 == 0 && at + 8 <= self.0.len());
        // SAFETY: aligned, retained page storage; only atomic operations on
        // these words in the kernel, interoperating with user machine stores.
        unsafe {
            (&*self
                .0
                .cpu_ptr::<core::sync::atomic::AtomicU64>()
                .add(at / 8))
                .load(Ordering::Acquire)
        }
    }
    fn store64(&self, at: usize, value: u64) {
        assert!(at % 8 == 0 && at + 8 <= self.0.len());
        // SAFETY: aligned live backing as in load64.
        unsafe {
            (&*self
                .0
                .cpu_ptr::<core::sync::atomic::AtomicU64>()
                .add(at / 8))
                .store(value, Ordering::Release)
        };
    }
    fn store32(&self, at: usize, value: u32) {
        assert!(at % 4 == 0 && at + 4 <= self.0.len());
        // SAFETY: aligned live backing; status state is an independent word.
        unsafe {
            (&*self
                .0
                .cpu_ptr::<core::sync::atomic::AtomicU32>()
                .add(at / 4))
                .store(value, Ordering::Release)
        };
    }
    fn frames(&self, offset: usize, len: usize) -> Result<Vec<u64>, FsError> {
        if offset.checked_add(len).is_none_or(|end| end > self.0.len()) {
            return Err(FsError::InvalidData);
        }
        Ok((offset / PAGE..(offset + len) / PAGE)
            .map(|p| self.0.dma_addr_at((p * PAGE) as u64).raw())
            .collect())
    }
}

#[derive(Debug)]
struct Runtime {
    stream: Option<PcmSubstream>,
    legacy: bool,
    state: u32,
    suspended_state: u32,
    pause_supported: bool,
    params: Option<HwParams>,
    access: u32,
    data: Option<Arc<Pages>>,
    status: Option<Arc<Pages>>,
    control: Option<Arc<Pages>>,
    appl: u64,
    submitted: u64,
    hw: u64,
    boundary: u64,
    avail_min: u64,
    start_threshold: u64,
    stop_threshold: u64,
    silence_threshold: u64,
    silence_size: u64,
    silence_start: u64,
    silence_filled: u64,
    trigger_ns: u64,
    tstamp_type: u32,
    user_pversion: u32,
}
impl Runtime {
    fn new() -> Self {
        Self {
            stream: None,
            legacy: true,
            state: OPEN,
            suspended_state: OPEN,
            pause_supported: false,
            params: None,
            access: 3,
            data: None,
            status: None,
            control: None,
            appl: 0,
            submitted: 0,
            hw: 0,
            boundary: 1 << 60,
            avail_min: 1,
            start_threshold: 1,
            stop_threshold: 0,
            silence_threshold: 0,
            silence_size: 0,
            silence_start: 0,
            silence_filled: 0,
            trigger_ns: 0,
            tstamp_type: 0,
            user_pversion: 0,
        }
    }
    fn frames(&self) -> u64 {
        self.params
            .map_or(0, |p| p.period_size as u64 * p.periods as u64)
    }
    fn frame_bytes(&self) -> usize {
        self.params.map_or(0, |p| {
            p.channels.count() as usize * p.format.bytes_per_sample()
        })
    }
    fn avail(&self, capture: bool) -> u64 {
        if capture {
            self.hw.saturating_sub(self.appl).min(self.frames())
        } else {
            self.frames()
                .saturating_add(self.hw)
                .saturating_sub(self.appl)
        }
    }
    fn stop(&mut self) -> Result<(), FsError> {
        if let Some(s) = self.stream.as_mut() {
            if matches!(s.state, SubstreamState::Running | SubstreamState::Paused) {
                s.trigger_stop().map_err(sound_error)?;
            }
        }
        Ok(())
    }
    fn prepare(&mut self) -> Result<(), FsError> {
        self.stop()?;
        let s = self.stream.as_mut().ok_or(FsError::BadFd)?;
        s.prepare().map_err(sound_error)?;
        self.state = PREPARED;
        self.appl = 0;
        self.submitted = 0;
        self.hw = 0;
        self.silence_start = 0;
        self.silence_filled = 0;
        if let Some(control) = &self.control {
            control.store64(0, 0);
            control.store64(8, self.avail_min);
        }
        self.publish();
        Ok(())
    }
    fn publish(&self) {
        if let Some(p) = &self.status {
            let now = self.timestamp();
            p.store64(8, self.hw % self.boundary);
            p.store64(16, now / 1_000_000_000);
            p.store64(24, now % 1_000_000_000);
            p.store32(0, self.state);
        }
    }
    fn timestamp(&self) -> u64 {
        if self.tstamp_type == 0 {
            narf_time::wall::now_wall().as_nanos().max(0) as u64
        } else {
            narf_time::wall::monotonic_ns()
        }
    }
    fn xrun(&mut self) {
        let _ = self.stop();
        self.state = XRUN;
        self.publish();
    }
    fn mapping(&self, offset: u64, len: usize) -> Result<(Arc<Pages>, usize), FsError> {
        if len == 0 || len % PAGE != 0 || offset % PAGE as u64 != 0 {
            return Err(FsError::InvalidData);
        }
        if matches!(offset, STATUS | STATUS64 | CONTROL | CONTROL64) {
            // pcm_native.c: SYNC_APPLPTR requires explicit commits. Older
            // alsa-lib needs both records coupled; non-coherent architectures
            // use SYNC_PTR for both records.
            if cfg!(target_arch = "aarch64")
                || matches!(offset, CONTROL | CONTROL64)
                || self.user_pversion < 0x2000e
            {
                return Err(FsError::NoDeviceAddress);
            }
            if len != PAGE {
                return Err(FsError::InvalidData);
            }
            let p = if matches!(offset, STATUS | STATUS64) {
                &self.status
            } else {
                &self.control
            };
            return p.clone().map(|p| (p, 0)).ok_or(FsError::InvalidData);
        }
        let bytes = self
            .params
            .ok_or(FsError::BadFileState)?
            .buffer_bytes()
            .div_ceil(PAGE)
            * PAGE;
        if self.access != 0
            || offset
                .checked_add(len as u64)
                .is_none_or(|end| end > bytes as u64)
        {
            return Err(FsError::InvalidData);
        }
        self.data
            .clone()
            .map(|p| (p, offset as usize))
            .ok_or(FsError::InvalidData)
    }
}

pub(crate) struct Pcm {
    card: u32,
    device: u32,
    capture: bool,
    runtime: Mutex<Runtime>,
    ready: Readiness,
    linked: AtomicBool,
    closed: AtomicBool,
    peer_closed: AtomicBool,
    peer_xrun: AtomicBool,
}
impl core::fmt::Debug for Pcm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AlsaPcm")
            .field("card", &self.card)
            .field("device", &self.device)
            .field("capture", &self.capture)
            .finish()
    }
}
static STREAMS: IrqSafeSpinLock<Vec<Weak<Pcm>>> = IrqSafeSpinLock::new(Vec::new());
static PUMP_INSTALLED: AtomicBool = AtomicBool::new(false);
fn pump() {
    let streams = {
        let mut list = STREAMS.lock();
        list.retain(|s| s.strong_count() != 0);
        list.clone()
    };
    for weak in streams {
        if let Some(pcm) = weak.upgrade() {
            pcm.refresh();
        }
    }
}
impl Pcm {
    pub(crate) fn new(card: u32, device: u32, capture: bool) -> Arc<Self> {
        let pcm = Arc::new(Self {
            card,
            device,
            capture,
            runtime: Mutex::new(Runtime::new()),
            ready: Readiness::new(0),
            linked: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            peer_closed: AtomicBool::new(false),
            peer_xrun: AtomicBool::new(false),
        });
        STREAMS.lock().push(Arc::downgrade(&pcm));
        pcm
    }
    pub(crate) fn opened(card: u32, device: u32, capture: bool) -> Result<Arc<Self>, FsError> {
        let pcm = Self::new(card, device, capture);
        {
            let mut r = pcm.runtime.try_lock().unwrap();
            pcm.ensure_open(&mut r)?;
        }
        if !PUMP_INSTALLED.swap(true, Ordering::AcqRel) {
            narf_scheduler::sleep_pumps::register(pump);
        }
        Ok(pcm)
    }
    fn ensure_open(&self, r: &mut Runtime) -> Result<(), FsError> {
        if r.stream.is_some() {
            return Ok(());
        }
        let mut s = if self.capture {
            crate::open_capture(self.card, self.device)
                .map_err(sound_error)?
                .substream
        } else {
            crate::open_playback(self.card, self.device)
                .map_err(sound_error)?
                .substream
        };
        let p = crate::default_hw_params(self.card, self.capture).map_err(sound_error)?;
        s.hw_params(p).map_err(sound_error)?;
        s.prepare().map_err(sound_error)?;
        r.stream = Some(s);
        r.params = Some(p);
        r.state = PREPARED;
        Ok(())
    }
    fn activate(&self, r: &mut Runtime) -> Result<(), FsError> {
        self.ensure_open(r)?;
        if r.legacy {
            r.stop()?;
            r.status = Some(Pages::new(PAGE)?);
            r.control = Some(Pages::new(PAGE)?);
            r.legacy = false;
            r.state = OPEN;
            r.params = None;
            r.publish();
        }
        Ok(())
    }
    fn update_ready(&self, r: &Runtime) {
        let ok = if self.capture {
            POLL_IN | 0x40
        } else {
            POLL_OUT | 0x100
        };
        let mask = if matches!(r.state, OPEN | SETUP | XRUN | SUSPENDED | DISCONNECTED) {
            ok | POLL_ERR
        } else if r.state == DRAINING && self.capture {
            ok | if r.avail(true) == 0 { POLL_ERR } else { 0 }
        } else if r.state != DRAINING && r.avail(self.capture) >= r.avail_min {
            ok
        } else {
            0
        };
        self.ready
            .set(mask, (POLL_IN | POLL_OUT | POLL_ERR | 0x40 | 0x100) & !mask);
    }
    pub(crate) fn close(&self) {
        // A group operation can retain the runtime after the last file closes.
        // Notify peers now, rather than waiting for the runtime's final Arc.
        self.closed.store(true, Ordering::Release);
        self.peer_closed.store(true, Ordering::Release);
        self.refresh();
    }
    pub(crate) fn refresh(&self) {
        if self.linked.load(Ordering::Acquire) {
            groups::refresh(self);
        }
        if let Some(mut r) = self.runtime.try_lock() {
            if !r.legacy {
                self.service(&mut r);
                self.update_ready(&r);
            }
        }
    }
    pub(crate) fn readiness(&self) -> &Readiness {
        self.refresh();
        &self.ready
    }
    pub(crate) fn poll(&self) -> u32 {
        self.refresh();
        if self.runtime.try_lock().is_some_and(|r| r.legacy) {
            return if self.capture { POLL_IN } else { POLL_OUT };
        }
        self.ready.mask()
    }
    fn service(&self, r: &mut Runtime) {
        if self.peer_xrun.swap(false, Ordering::AcqRel) && !matches!(r.state, OPEN | SETUP | XRUN) {
            r.xrun();
        }
        if self.peer_closed.swap(false, Ordering::AcqRel) {
            let _ = r.stop();
            r.state = SETUP;
        }
        if r.legacy || !matches!(r.state, PREPARED | RUNNING | PAUSED | DRAINING) {
            r.publish();
            return;
        }
        let frame = r.frame_bytes();
        let capacity = r.frames();
        if frame == 0 || capacity == 0 {
            return;
        }
        if r.access == 0 {
            let control = r.control.as_ref().unwrap();
            let appl = control.load64(0);
            let avail_min = control.load64(8);
            if appl >= r.boundary {
                r.xrun();
                return;
            }
            let delta = (appl + r.boundary - r.appl % r.boundary) % r.boundary;
            if delta > r.avail(self.capture) {
                r.xrun();
                return;
            }
            r.appl += delta;
            r.avail_min = avail_min;
        }
        if !self.capture {
            let running = matches!(r.state, RUNNING | DRAINING);
            if running {
                r.hw = r.stream.as_ref().unwrap().pointer();
            }
            let free = r.stop_threshold >= r.boundary && r.state != DRAINING;
            if running && r.state != DRAINING && r.avail(false) >= r.stop_threshold {
                r.xrun();
                return;
            }
            if r.state == DRAINING && r.hw >= r.appl {
                if r.stop().is_err() {
                    r.xrun();
                    return;
                }
                r.state = SETUP;
                r.publish();
                return;
            }
            self.silence(r);
            // Cyclic DMA can move beyond the application pointer in boundary
            // mode. Catch the submission cursor up without replaying old laps.
            r.submitted = r.submitted.max(r.hw);
            let target = if free {
                r.hw.saturating_add(capacity).max(r.appl)
            } else {
                r.appl.max(r.silence_start.saturating_add(r.silence_filled))
            };
            let mut scratch = [0u8; 4096];
            if free || r.silence_size != 0 {
                let mut at = r.hw;
                let end = r.submitted.min(r.hw.saturating_add(capacity));
                while at < end {
                    let count = (end - at)
                        .min(capacity - at % capacity)
                        .min((scratch.len() / frame) as u64)
                        as usize;
                    r.data.as_ref().unwrap().read(
                        (at % capacity) as usize * frame,
                        &mut scratch[..count * frame],
                    );
                    if r.stream
                        .as_mut()
                        .unwrap()
                        .overwrite(at, &scratch[..count * frame])
                        .is_err()
                    {
                        r.xrun();
                        return;
                    }
                    at += count as u64;
                }
            }
            let mut remaining = capacity;
            while r.submitted < target && remaining != 0 {
                let offset = (r.submitted % capacity) as usize * frame;
                let count = (target - r.submitted)
                    .min(remaining)
                    .min(capacity - r.submitted % capacity)
                    .min((scratch.len() / frame) as u64) as usize;
                r.data
                    .as_ref()
                    .unwrap()
                    .read(offset, &mut scratch[..count * frame]);
                match r.stream.as_mut().unwrap().write(&scratch[..count * frame]) {
                    Ok(0) => break,
                    Ok(n) if n <= count * frame && n % frame == 0 => {
                        r.submitted += (n / frame) as u64;
                        remaining -= (n / frame) as u64;
                    }
                    _ => {
                        r.xrun();
                        return;
                    }
                }
            }
            // mmap_commit and START are separate in alsa-lib. RW transfers
            // start here only for unlinked files; group starts happen unlocked.
            if !self.linked.load(Ordering::Acquire)
                && r.access != 0
                && r.state == PREPARED
                && r.appl >= r.start_threshold
                && r.appl != 0
            {
                if r.stream.as_mut().unwrap().trigger_start().is_err() {
                    r.xrun();
                    return;
                }
                r.state = RUNNING;
                r.trigger_ns = r.timestamp();
            }
        } else if r.state == RUNNING {
            let hardware = r.stream.as_ref().unwrap().pointer();
            if hardware.saturating_sub(r.appl) > capacity {
                r.xrun();
                return;
            }
            let mut scratch = [0u8; 4096];
            let mut remaining = capacity;
            while r.hw - r.appl < capacity && remaining != 0 {
                let offset = (r.hw % capacity) as usize * frame;
                let count = (capacity - (r.hw - r.appl))
                    .min(capacity - r.hw % capacity)
                    .min(remaining)
                    .min((scratch.len() / frame) as u64) as usize;
                match r
                    .stream
                    .as_mut()
                    .unwrap()
                    .read(&mut scratch[..count * frame])
                {
                    Ok(0) => break,
                    Ok(n) if n <= count * frame && n % frame == 0 => {
                        r.data.as_ref().unwrap().write(offset, &scratch[..n]);
                        r.hw += (n / frame) as u64;
                        remaining -= (n / frame) as u64;
                    }
                    _ => {
                        r.xrun();
                        return;
                    }
                }
            }
        }
        r.publish();
    }
    fn silence(&self, r: &mut Runtime) {
        if self.capture || r.silence_size == 0 {
            return;
        }
        let boundary_mode = r.silence_size >= r.boundary;
        let start = if boundary_mode { r.hw } else { r.appl };
        r.silence_filled = r
            .silence_filled
            .saturating_sub(start.saturating_sub(r.silence_start));
        r.silence_start = start;
        let count = if boundary_mode {
            r.frames().saturating_sub(r.silence_filled)
        } else {
            r.silence_threshold
                .saturating_sub(r.appl.saturating_sub(r.hw).saturating_add(r.silence_filled))
                .min(r.silence_size)
        };
        let mut at = start + r.silence_filled;
        let mut left = count.min(r.frames());
        let width = r.frame_bytes();
        let zero = [0u8; 4096]; // Supported formats are signed little-endian PCM.
        while left != 0 {
            let n = left
                .min(r.frames() - at % r.frames())
                .min((zero.len() / width) as u64);
            r.data.as_ref().unwrap().write(
                (at % r.frames()) as usize * width,
                &zero[..n as usize * width],
            );
            left -= n;
            at += n;
        }
        r.silence_filled += count;
    }
    pub(crate) fn mmap(&self, offset: u64, len: usize) -> Result<Vec<u64>, FsError> {
        let r = self.runtime.try_lock().ok_or(FsError::Busy)?;
        let (p, offset) = r.mapping(offset, len)?;
        p.frames(offset, len)
    }
    pub(crate) fn mmap_owner(&self, offset: u64, len: usize) -> Option<Arc<dyn MmapLifetime>> {
        let r = self.runtime.try_lock()?;
        let (p, _) = r.mapping(offset, len).ok()?;
        Some(p)
    }
    pub(crate) fn mmap_backing(
        &self,
        offset: u64,
        len: usize,
    ) -> Result<narf_filesystem::MmapBacking, FsError> {
        let r = self.runtime.try_lock().ok_or(FsError::Busy)?;
        let (owner, at) = r.mapping(offset, len)?;
        Ok(narf_filesystem::MmapBacking {
            frames: owner.frames(at, len)?,
            lifetime: Some(owner),
        })
    }
    pub(crate) fn validate_mmap(
        &self,
        offset: u64,
        len: usize,
        prot: u32,
        flags: u32,
    ) -> Result<u32, FsError> {
        if flags & 1 == 0
            || prot & 4 != 0
            || (matches!(offset, STATUS | STATUS64 | CONTROL | CONTROL64) && prot & 1 == 0)
            || (!matches!(offset, STATUS | STATUS64 | CONTROL | CONTROL64)
                && ((self.capture && prot & 1 == 0) || (!self.capture && prot & 3 == 0)))
        {
            return Err(FsError::InvalidData);
        }
        self.runtime
            .try_lock()
            .ok_or(FsError::Busy)?
            .mapping(offset, len)
            .map(|_| {
                if matches!(offset, STATUS | STATUS64) {
                    prot & !2
                } else {
                    prot
                }
            })
    }
    pub(crate) fn read<'a>(&'a self, out: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            if !self.capture {
                // A playback file has no read operation. VFS already checks
                // descriptor access mode; Linux then returns EINVAL here.
                return Err(FsError::InvalidData);
            }
            self.maybe_start_group(out.len() as u64).await?;
            let mut r = self.runtime.lock().await;
            self.ensure_open(&mut r)?;
            if out.is_empty() {
                return Ok(0);
            }
            if r.legacy {
                let deadline = narf_time::Deadline::after_ms(500);
                loop {
                    let s = r.stream.as_mut().unwrap();
                    if s.state != SubstreamState::Running {
                        s.trigger_start().map_err(sound_error)?;
                    }
                    let n = s.read(out).map_err(sound_error)?;
                    if n != 0 {
                        return Ok(n);
                    }
                    if deadline.expired() {
                        return Err(FsError::WouldBlock);
                    }
                    drop(r);
                    narf_time::SleepUntil::new(narf_time::Deadline::after_ms(2).as_instant()).await;
                    r = self.runtime.lock().await;
                    if !r.legacy {
                        return Err(FsError::BadFileState);
                    }
                }
            }
            if r.access != 3 {
                return Err(FsError::InvalidData);
            }
            self.transfer_read(&mut r, out)
        })
    }
    pub(crate) fn write<'a>(&'a self, offset: u64, data: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let mut r = self.runtime.lock().await;
            self.ensure_open(&mut r)?;
            if offset == crate::devfs_bridge::HW_PARAMS_MAGIC_OFFSET {
                let p = crate::devfs_bridge::decode_hw_params(data).ok_or(FsError::InvalidData)?;
                r.stop()?;
                let s = r.stream.as_mut().unwrap();
                s.state = SubstreamState::Open;
                s.hw_params(p).map_err(sound_error)?;
                s.prepare().map_err(sound_error)?;
                r.params = Some(p);
                r.legacy = true;
                r.state = PREPARED;
                return Ok(data.len());
            }
            if self.capture {
                return Err(FsError::InvalidData);
            }
            if data.is_empty() {
                return Ok(0);
            }
            if r.legacy {
                let s = r.stream.as_mut().unwrap();
                let n = match s.write(data) {
                    Err(crate::SoundError::BadState) if s.state == SubstreamState::Running => {
                        s.trigger_stop().map_err(sound_error)?;
                        s.prepare().map_err(sound_error)?;
                        s.write(data).map_err(sound_error)?
                    }
                    other => other.map_err(sound_error)?,
                };
                if n == 0 {
                    return Err(FsError::WouldBlock);
                }
                if s.state != SubstreamState::Running {
                    s.trigger_start().map_err(sound_error)?;
                }
                return Ok(n);
            }
            if r.access != 3 {
                return Err(FsError::InvalidData);
            }
            let result = self.transfer_write(&mut r, data);
            drop(r);
            // Linux returns already-copied bytes even if automatic START
            // fails; the next transfer observes the group's XRUN state.
            if result.is_ok() {
                let _ = self.maybe_start_group(0).await;
            }
            result
        })
    }
    fn transfer_write(&self, r: &mut Runtime, data: &[u8]) -> Result<usize, FsError> {
        self.service(r);
        if r.state == SUSPENDED {
            return Err(FsError::StreamSuspended);
        }
        if r.state == XRUN {
            return Err(FsError::StreamXrun);
        }
        if !matches!(r.state, PREPARED | RUNNING | PAUSED) {
            return Err(FsError::BadFileState);
        }
        let frame = r.frame_bytes();
        if data.len() % frame != 0 {
            return Err(FsError::InvalidData);
        }
        let n = data
            .len()
            .min(r.avail(false).min(r.frames()) as usize * frame);
        if n == 0 {
            return Err(FsError::WouldBlock);
        }
        let bytes = r.params.unwrap().buffer_bytes();
        let at = (r.appl % r.frames()) as usize * frame;
        let first = n.min(bytes - at);
        let p = r.data.as_ref().unwrap();
        p.write(at, &data[..first]);
        p.write(0, &data[first..n]);
        r.appl += (n / frame) as u64;
        r.control.as_ref().unwrap().store64(0, r.appl % r.boundary);
        self.service(r);
        self.update_ready(r);
        Ok(n)
    }
    fn transfer_read(&self, r: &mut Runtime, out: &mut [u8]) -> Result<usize, FsError> {
        if !self.linked.load(Ordering::Acquire)
            && r.state == PREPARED
            && (out.len() / r.frame_bytes()) as u64 >= r.start_threshold
        {
            r.stream
                .as_mut()
                .unwrap()
                .trigger_start()
                .map_err(sound_error)?;
            r.state = RUNNING;
            r.trigger_ns = r.timestamp();
        }
        self.service(r);
        if r.state == SUSPENDED {
            return Err(FsError::StreamSuspended);
        }
        if r.state == XRUN {
            return Err(FsError::StreamXrun);
        }
        if !matches!(r.state, PREPARED | RUNNING | PAUSED | DRAINING) {
            return Err(FsError::BadFileState);
        }
        let frame = r.frame_bytes();
        if out.len() % frame != 0 {
            return Err(FsError::InvalidData);
        }
        let n = out.len().min(r.avail(true) as usize * frame);
        if n == 0 {
            if r.state == DRAINING {
                r.state = SETUP;
                self.update_ready(r);
                return Ok(0);
            }
            return Err(FsError::WouldBlock);
        }
        let bytes = r.params.unwrap().buffer_bytes();
        let at = (r.appl % r.frames()) as usize * frame;
        let first = n.min(bytes - at);
        let p = r.data.as_ref().unwrap();
        p.read(at, &mut out[..first]);
        p.read(0, &mut out[first..n]);
        r.appl += (n / frame) as u64;
        r.control.as_ref().unwrap().store64(0, r.appl % r.boundary);
        self.update_ready(r);
        Ok(n)
    }
    pub(crate) fn flush<'a>(&'a self) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let mut r = self.runtime.lock().await;
            if self.capture || !r.legacy {
                return Ok(());
            }
            if let Some(s) = r.stream.as_mut() {
                if s.state == SubstreamState::Running {
                    s.drain().map_err(sound_error)?;
                    s.prepare().map_err(sound_error)?;
                }
            }
            Ok(())
        })
    }
    pub(crate) fn ioctl<'a>(
        &'a self,
        cmd: u32,
        arg: u64,
        ctx: &'a dyn IoctlContext,
    ) -> FsFuture<'a, u64> {
        Box::pin(async move {
            if (cmd >> 8) & 255 != u32::from(b'A') {
                return Ok((-25i64) as u64);
            }
            let nr = (cmd & 255) as u8;
            // Validate the entire request word, not just its low command byte.
            let (dir, size) = match nr {
                0x00 | 0x02 | 0x03 | 0x04 => (if nr == 0 { 2 } else { 1 }, 4),
                0x01 => (2, 288),
                0x10 | 0x11 => (3, 608),
                0x13 => (3, 136),
                0x20 => (2, 152),
                0x21 => (2, 8),
                0x23 => (3, 136),
                0x24 => (3, 152),
                0x32 => (2, 24),
                0x45 | 0x60 => (1, 4),
                0x46 | 0x49 => (1, 8),
                0x50 | 0x52 => (1, 24),
                0x51 | 0x53 => (2, 24),
                0x12 | 0x22 | 0x40..=0x44 | 0x47 | 0x48 | 0x61 => (0, 0),
                _ => return Ok((-25i64) as u64),
            };
            if cmd != command(b'A', nr, dir, size) {
                return Ok((-25i64) as u64);
            }
            if nr == 0x60 || nr == 0x61 {
                return self.link_ioctl(nr, arg, ctx).await;
            }
            if matches!(nr, 0x40..=0x45 | 0x47 | 0x48) {
                return self.group_action(nr, arg, ctx.nonblocking()).await;
            }
            if self.linked.load(Ordering::Acquire) {
                groups::refresh(self);
            }
            let mut r = self.runtime.lock().await;
            self.activate(&mut r)?;
            if matches!(nr, 0x50..=0x53) {
                drop(r);
                return self.xfer(nr, arg, ctx).await;
            }
            match nr {
                0x00 => ctx.write(arg, &0x0002_0012u32.to_ne_bytes())?,
                0x01 => ctx.write(arg, &info(self.card, self.device, self.capture)?)?,
                0x02 => {} // snd_pcm_common_ioctl: historical TSTAMP ignores arg.
                0x03 | 0x04 => {
                    let b = input(ctx, arg, 4)?;
                    let value = get32(&b, 0);
                    if (nr == 2 && value > 1) || (nr == 3 && value > 2) {
                        return Err(FsError::InvalidData);
                    }
                    if nr == 3 {
                        r.tstamp_type = value;
                    } else {
                        r.user_pversion = value;
                    }
                }
                0x10 | 0x11 => {
                    let mut b = input(ctx, arg, 608)?;
                    if nr == 0x11 && !matches!(r.state, OPEN | SETUP | PREPARED) {
                        return Err(FsError::BadFileState);
                    }
                    if nr == 0x11 && r.data.as_ref().is_some_and(|p| Arc::strong_count(p) > 1) {
                        return Err(FsError::BadFileState);
                    }
                    let caps =
                        crate::pcm_capabilities(self.card, self.capture).map_err(sound_error)?;
                    let refined = params::refine(&mut b, &caps, nr == 0x11);
                    if nr == 0x11 {
                        r.stop()?;
                        r.state = OPEN;
                        r.params = None;
                        r.data = None;
                        r.publish();
                        self.update_ready(&r);
                    }
                    if let Some((p, access)) = refined? {
                        let data = Pages::new(p.buffer_bytes())?;
                        r.stop()?;
                        let s = r.stream.as_mut().unwrap();
                        s.state = SubstreamState::Open;
                        s.hw_params(p).map_err(sound_error)?;
                        if !self.capture {
                            s.free_running(true).map_err(sound_error)?;
                        }
                        r.pause_supported = true;
                        r.params = Some(p);
                        r.data = Some(data);
                        r.access = access;
                        r.state = SETUP;
                        r.boundary = r.frames();
                        while r.boundary <= (i64::MAX as u64 - r.frames()) / 2 {
                            r.boundary *= 2;
                        }
                        r.avail_min = p.period_size as u64;
                        r.silence_threshold = 0;
                        r.silence_size = 0;
                        r.silence_start = 0;
                        r.silence_filled = 0;
                        r.start_threshold = 1;
                        r.stop_threshold = r.frames();
                        r.appl = 0;
                        r.hw = 0;
                        r.submitted = 0;
                        r.control.as_ref().unwrap().store64(0, 0);
                        r.control.as_ref().unwrap().store64(8, r.avail_min);
                    }
                    ctx.write(arg, &b)?;
                }
                0x12 => {
                    if !matches!(r.state, SETUP | PREPARED) {
                        return Err(FsError::BadFileState);
                    }
                    if r.data.as_ref().is_some_and(|p| Arc::strong_count(p) > 1) {
                        return Err(FsError::BadFileState);
                    }
                    r.stop()?;
                    r.data = None;
                    r.params = None;
                    r.state = OPEN;
                    if let Some(s) = r.stream.as_mut() {
                        s.state = SubstreamState::Open;
                    }
                }
                0x13 => {
                    let mut b = input(ctx, arg, 136)?;
                    // snd_pcm_sw_params_user copies the record back even on
                    // validation failure; an unwritable output wins EFAULT.
                    ctx.write(arg, &b)?;
                    if r.params.is_none() {
                        return Err(FsError::BadFileState);
                    }
                    let avail = get64(&b, 16);
                    let silence_threshold = get64(&b, 48);
                    let silence_size = get64(&b, 56);
                    if get32(&b, 0) > 1
                        || avail == 0
                        || (get32(&b, 72) >= 0x2000c && get32(&b, 76) > 2)
                        || (silence_size >= r.boundary && silence_threshold != 0)
                        || (silence_size < r.boundary
                            && (silence_size > silence_threshold || silence_threshold > r.frames()))
                    {
                        return Err(FsError::InvalidData);
                    }
                    r.silence_threshold = silence_threshold;
                    r.silence_size = silence_size;
                    r.silence_start = if silence_size >= r.boundary {
                        r.hw
                    } else {
                        r.appl
                    };
                    r.silence_filled = if silence_size >= r.boundary {
                        r.appl.saturating_sub(r.hw).min(r.frames())
                    } else {
                        0
                    };
                    r.avail_min = avail;
                    r.start_threshold = get64(&b, 32);
                    r.stop_threshold = get64(&b, 40);
                    if get32(&b, 72) >= 0x2000c {
                        r.tstamp_type = get32(&b, 76);
                    }
                    r.control.as_ref().unwrap().store64(8, avail);
                    put64(&mut b, 64, r.boundary);
                    ctx.write(arg, &b)?;
                }
                0x20 | 0x24 => {
                    self.service(&mut r);
                    ctx.write(arg, &self.status(&r))?;
                }
                0x21 => {
                    if !matches!(
                        r.state,
                        PREPARED | RUNNING | PAUSED | DRAINING | XRUN | SUSPENDED
                    ) || (self.capture && r.state == DRAINING)
                    {
                        return Err(FsError::BadFileState);
                    }
                    self.service(&mut r);
                    if r.state == SUSPENDED {
                        return Err(FsError::StreamSuspended);
                    }
                    if r.state == XRUN {
                        return Err(FsError::StreamXrun);
                    }
                    let delay = if self.capture {
                        r.hw.saturating_sub(r.appl)
                    } else {
                        r.appl.wrapping_sub(r.hw)
                    };
                    ctx.write(arg, &delay.to_ne_bytes())?;
                }
                0x22 => {
                    if !matches!(
                        r.state,
                        PREPARED | RUNNING | PAUSED | DRAINING | XRUN | SUSPENDED
                    ) || (self.capture && r.state == DRAINING)
                    {
                        return Err(FsError::BadFileState);
                    }
                    self.service(&mut r);
                    if r.state == SUSPENDED {
                        return Err(FsError::StreamSuspended);
                    }
                    if r.state == XRUN {
                        return Err(FsError::StreamXrun);
                    }
                }
                0x23 => {
                    let mut b = input(ctx, arg, 136)?;
                    let flags = get32(&b, 0);
                    if flags & 1 != 0 {
                        if r.state == SUSPENDED {
                            return Err(FsError::StreamSuspended);
                        }
                        if r.state == XRUN {
                            return Err(FsError::StreamXrun);
                        }
                        if !matches!(r.state, PREPARED | RUNNING | PAUSED | DRAINING)
                            || (self.capture && r.state == DRAINING)
                        {
                            return Err(FsError::BadFileState);
                        }
                    }
                    self.service(&mut r);
                    if flags & 2 == 0 {
                        let appl = get64(&b, 72);
                        if appl >= r.boundary {
                            return Err(FsError::InvalidData);
                        }
                        let delta = (appl + r.boundary - r.appl % r.boundary) % r.boundary;
                        if delta > r.avail(self.capture) {
                            return Err(FsError::InvalidData);
                        }
                        r.appl += delta;
                        r.control.as_ref().unwrap().store64(0, appl);
                    }
                    if flags & 4 == 0 {
                        let avail = get64(&b, 80);
                        r.avail_min = avail;
                        r.control.as_ref().unwrap().store64(8, avail);
                    }
                    self.service(&mut r);
                    b[8..].fill(0);
                    put32(&mut b, 8, r.state);
                    put64(&mut b, 16, r.hw % r.boundary);
                    let now = r.timestamp();
                    put64(&mut b, 24, now / 1_000_000_000);
                    put64(&mut b, 32, now % 1_000_000_000);
                    put64(&mut b, 72, r.appl % r.boundary);
                    put64(&mut b, 80, r.avail_min);
                    ctx.write(arg, &b)?;
                }
                0x32 => {
                    let mut b = input(ctx, arg, 24)?;
                    let p = r.params.ok_or(FsError::InvalidData)?;
                    let ch = get32(&b, 0);
                    if ch >= p.channels.count() as u32 {
                        return Err(FsError::InvalidData);
                    }
                    b[4..].fill(0);
                    put64(&mut b, 8, 0);
                    put32(&mut b, 16, ch * p.format.bytes_per_sample() as u32 * 8);
                    put32(&mut b, 20, r.frame_bytes() as u32 * 8);
                    ctx.write(arg, &b)?;
                }
                0x46 | 0x49 => {
                    let b = input(ctx, arg, 8)?;
                    let wanted = get64(&b, 0);
                    ctx.write(arg, &0u64.to_ne_bytes())?;
                    if wanted == 0 {
                        return Ok(0);
                    }
                    self.service(&mut r);
                    let error = if r.state == SUSPENDED {
                        Some(FsError::StreamSuspended)
                    } else if r.state == XRUN {
                        Some(FsError::StreamXrun)
                    } else if !matches!(r.state, PREPARED | RUNNING | PAUSED | DRAINING)
                        || (self.capture && r.state == DRAINING)
                    {
                        Some(FsError::BadFileState)
                    } else {
                        None
                    };
                    if let Some(error) = error {
                        ctx.write(arg, &(-super::errno(error)).to_ne_bytes())?;
                        return Err(error);
                    }
                    let n = if nr == 0x46 {
                        // NO_REWINDS: Linux suppresses apply_appl_ptr's error
                        // and reports zero frames rewound (PulseAudio relies
                        // on this). Never move the pointer behind submitted DMA.
                        0
                    } else {
                        wanted.min(r.avail(self.capture))
                    };
                    if nr == 0x46 {
                        r.appl -= n;
                    } else {
                        r.appl += n;
                    }
                    r.control.as_ref().unwrap().store64(0, r.appl % r.boundary);
                    ctx.write(arg, &n.to_ne_bytes())?;
                }
                _ => unreachable!(),
            }
            if nr == 0x13 {
                self.service(&mut r);
            }
            r.publish();
            self.update_ready(&r);
            Ok(0)
        })
    }
    fn status(&self, r: &Runtime) -> Vec<u8> {
        let mut b = alloc::vec![0;152];
        let now = r.timestamp();
        put32(&mut b, 0, r.state);
        put64(&mut b, 8, r.trigger_ns / 1_000_000_000);
        put64(&mut b, 16, r.trigger_ns % 1_000_000_000);
        put64(&mut b, 24, now / 1_000_000_000);
        put64(&mut b, 32, now % 1_000_000_000);
        put64(&mut b, 40, r.appl % r.boundary);
        put64(&mut b, 48, r.hw % r.boundary);
        put64(
            &mut b,
            56,
            if self.capture {
                r.hw.saturating_sub(r.appl)
            } else {
                r.appl.wrapping_sub(r.hw)
            },
        );
        put64(&mut b, 64, r.avail(self.capture));
        put64(&mut b, 72, r.avail(self.capture));
        b
    }
    async fn wait_drain(&self, nonblock: bool) -> Result<u64, FsError> {
        if nonblock {
            return Err(FsError::WouldBlock);
        }
        let deadline = narf_time::Deadline::after_ms(10000);
        loop {
            self.refresh();
            {
                let mut r = self.runtime.lock().await;
                self.service(&mut r);
                self.update_ready(&r);
                if r.state == XRUN {
                    return Err(FsError::StreamXrun);
                }
                if r.state != DRAINING {
                    return Ok(0);
                }
            }
            if deadline.expired() {
                return Err(FsError::Busy);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
        }
    }
    async fn xfer(&self, nr: u8, arg: u64, ctx: &dyn IoctlContext) -> Result<u64, FsError> {
        // pcm_native.c::snd_pcm_xfer{ i,n }_frames_ioctl checks OPEN before
        // touching user memory, then validates the writable result field.
        if self.runtime.lock().await.state == OPEN {
            return Err(FsError::BadFileState);
        }
        ctx.write(arg, &0u64.to_ne_bytes())?;
        let result = self.xfer_inner(nr, arg, ctx).await;
        if let Err(error) = result {
            ctx.write(arg, &(-super::errno(error)).to_ne_bytes())?;
        }
        result
    }

    async fn xfer_inner(&self, nr: u8, arg: u64, ctx: &dyn IoctlContext) -> Result<u64, FsError> {
        let b = input(ctx, arg, 24)?;
        let address = get64(&b, 8);
        let frames = get64(&b, 16);
        // Both request numbers dispatch by the opened substream direction
        // in Linux, rather than rejecting the opposite spelling.
        let capture = self.capture;
        let planar = nr >= 0x52;
        let (frame, channels, sample) = {
            let r = self.runtime.lock().await;
            let params = r.params.ok_or(FsError::BadFileState)?;
            // pcm_lib checks access and a null capture buffer before size or
            // state. Mono interleaved transfers also accept planar access.
            if (planar && r.access != 4)
                || (!planar && r.access != 3 && params.channels.count() > 1)
            {
                return Err(FsError::InvalidData);
            }
            (
                r.frame_bytes(),
                params.channels.count() as usize,
                params.format.bytes_per_sample(),
            )
        };
        let pointers = if planar {
            Some(input(ctx, address, channels * 8)?)
        } else {
            None
        };
        if capture && !planar && address == 0 {
            return Err(FsError::InvalidData);
        }
        if frames == 0 {
            return Ok(0);
        }
        let bytes = usize::try_from(frames)
            .ok()
            .and_then(|n| n.checked_mul(frame))
            .ok_or(FsError::InvalidData)?;
        // Bound staging memory, not the application's transfer length.
        let chunk = bytes.min(MAX_TRANSFER / frame * frame);
        let mut data = alloc::vec![0; chunk];
        let mut plane = alloc::vec![0; if planar { chunk / channels } else { 0 }];
        let mut done = 0usize;
        loop {
            self.maybe_start_group(if capture { bytes as u64 } else { 0 })
                .await?;
            let result = {
                let mut r = self.runtime.lock().await;
                self.service(&mut r);
                if r.state == XRUN {
                    Err(FsError::StreamXrun)
                } else if r.state == SUSPENDED {
                    Err(FsError::StreamSuspended)
                } else if !matches!(r.state, PREPARED | RUNNING | PAUSED) {
                    Err(FsError::BadFileState)
                } else {
                    // Capture starts based on the complete requested transfer,
                    // not the size of our bounded temporary buffer.
                    if capture
                        && !self.linked.load(Ordering::Acquire)
                        && r.state == PREPARED
                        && frames >= r.start_threshold
                    {
                        r.stream
                            .as_mut()
                            .unwrap()
                            .trigger_start()
                            .map_err(sound_error)?;
                        r.state = RUNNING;
                        r.trigger_ns = r.timestamp();
                        self.service(&mut r);
                    }
                    let n = (bytes - done)
                        .min(chunk)
                        .min(r.avail(capture).min(r.frames()) as usize * frame);
                    if n == 0 {
                        Err(FsError::WouldBlock)
                    } else {
                        let copy_result = (|| {
                            if !capture {
                                data[..n].fill(0);
                                if let Some(pointers) = &pointers {
                                    for ch in 0..channels {
                                        let ptr = get64(pointers, ch * 8);
                                        // ALSA null playback planes mean silence.
                                        if ptr == 0 {
                                            continue;
                                        }
                                        ctx.read(
                                            ptr.checked_add((done / channels) as u64)
                                                .ok_or(FsError::BadAddress)?,
                                            &mut plane[..n / channels],
                                        )?;
                                        for f in 0..n / frame {
                                            data[f * frame + ch * sample
                                                ..f * frame + (ch + 1) * sample]
                                                .copy_from_slice(
                                                    &plane[f * sample..(f + 1) * sample],
                                                );
                                        }
                                    }
                                } else if address != 0 {
                                    ctx.read(
                                        address
                                            .checked_add(done as u64)
                                            .ok_or(FsError::BadAddress)?,
                                        &mut data[..n],
                                    )?;
                                }
                                self.transfer_write(&mut r, &data[..n])
                            } else {
                                let old_appl = r.appl;
                                let n = self.transfer_read(&mut r, &mut data[..n])?;
                                let copied = (|| {
                                    if let Some(pointers) = &pointers {
                                        for ch in 0..channels {
                                            let ptr = get64(pointers, ch * 8);
                                            // A null capture plane discards that channel.
                                            if ptr == 0 {
                                                continue;
                                            }
                                            for f in 0..n / frame {
                                                plane[f * sample..(f + 1) * sample]
                                                    .copy_from_slice(
                                                        &data[f * frame + ch * sample
                                                            ..f * frame + (ch + 1) * sample],
                                                    );
                                            }
                                            ctx.write(
                                                ptr.checked_add((done / channels) as u64)
                                                    .ok_or(FsError::BadAddress)?,
                                                &plane[..n / channels],
                                            )?;
                                        }
                                    } else {
                                        ctx.write(
                                            address
                                                .checked_add(done as u64)
                                                .ok_or(FsError::BadAddress)?,
                                            &data[..n],
                                        )?;
                                    }
                                    Ok::<(), FsError>(())
                                })();
                                if let Err(error) = copied {
                                    r.appl = old_appl;
                                    r.control.as_ref().unwrap().store64(0, r.appl % r.boundary);
                                    self.update_ready(&r);
                                    return Err(error);
                                }
                                Ok(n)
                            }
                        })();
                        copy_result
                    }
                }
            };
            let start_failed = result.is_ok() && self.maybe_start_group(0).await.is_err();
            match result {
                Ok(n) => done += n,
                Err(FsError::WouldBlock) if !ctx.nonblocking() => {
                    narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
                    continue;
                }
                Err(error) if done == 0 => return Err(error),
                Err(_) => break,
            }
            if start_failed || done == bytes {
                break;
            }
        }
        ctx.write(arg, &((done / frame) as u64).to_ne_bytes())?;
        Ok(0)
    }
}

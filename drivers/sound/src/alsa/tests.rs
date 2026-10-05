//! Regression oracles: /usr/src/linux/sound/core/{pcm_native,pcm_lib,control}.c
//! and include/uapi/asm-generic/{errno-base,errno}.h. Exercise actual FileOps
//! dispatch and dedicated mmap pages, not just structure serialization.
use super::*;
use crate::{format::*, hardware::*, mixer::*, SoundError};
use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use narf_filesystem::{FileOps, FsFuture, POLL_ERR, POLL_IN, POLL_OUT};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

struct Memory {
    bytes: IrqSafeSpinLock<Vec<u8>>,
    files: IrqSafeSpinLock<Vec<Arc<dyn FileOps>>>,
    read_only: AtomicU64,
}
impl Memory {
    fn new() -> Self {
        Self {
            bytes: IrqSafeSpinLock::new(alloc::vec![0;65536]),
            files: IrqSafeSpinLock::new(Vec::new()),
            read_only: AtomicU64::new(0),
        }
    }
    fn put(&self, at: usize, b: &[u8]) {
        self.bytes.lock()[at..at + b.len()].copy_from_slice(b);
    }
    fn word(&self, at: usize) -> u64 {
        get64(&self.bytes.lock(), at)
    }
}
impl IoctlContext for Memory {
    fn file(&self, fd: i32) -> Result<Arc<dyn FileOps>, FsError> {
        self.files
            .lock()
            .get(fd as usize)
            .cloned()
            .ok_or(FsError::BadFd)
    }
    fn process_id(&self) -> u32 {
        42
    }
    fn read(&self, a: u64, b: &mut [u8]) -> Result<(), FsError> {
        let data = self.bytes.lock();
        let a = usize::try_from(a).map_err(|_| FsError::BadAddress)?;
        if a == 0 {
            return Err(FsError::BadAddress);
        }
        let end = a.checked_add(b.len()).ok_or(FsError::BadAddress)?;
        b.copy_from_slice(data.get(a..end).ok_or(FsError::BadAddress)?);
        Ok(())
    }
    fn write(&self, a: u64, b: &[u8]) -> Result<(), FsError> {
        if self.read_only.load(Ordering::Acquire) == a {
            return Err(FsError::BadAddress);
        }
        let mut data = self.bytes.lock();
        let a = usize::try_from(a).map_err(|_| FsError::BadAddress)?;
        if a == 0 {
            return Err(FsError::BadAddress);
        }
        let end = a.checked_add(b.len()).ok_or(FsError::BadAddress)?;
        data.get_mut(a..end)
            .ok_or(FsError::BadAddress)?
            .copy_from_slice(b);
        Ok(())
    }
    fn nonblocking(&self) -> bool {
        true
    }
}
#[derive(Debug)]
struct Backend {
    claimed: [AtomicBool; 2],
    position: [AtomicU64; 2],
    written: AtomicU64,
    volume: AtomicI32,
    paused: [AtomicBool; 2],
    fail_start: AtomicBool,
    samples: IrqSafeSpinLock<Vec<u8>>,
}
impl Default for Backend {
    fn default() -> Self {
        Self {
            claimed: core::array::from_fn(|_| AtomicBool::new(false)),
            position: core::array::from_fn(|_| AtomicU64::new(0)),
            written: AtomicU64::new(0),
            volume: AtomicI32::new(0),
            paused: core::array::from_fn(|_| AtomicBool::new(false)),
            fail_start: AtomicBool::new(false),
            samples: IrqSafeSpinLock::new(Vec::new()),
        }
    }
}
#[derive(Debug)]
struct Device(Arc<Backend>);
#[derive(Debug)]
struct Stream {
    backend: Arc<Backend>,
    capture: bool,
    params: HwParams,
    application: u64,
}
fn defaults() -> HwParams {
    HwParams {
        format: SampleFormat::S16LE,
        rate: SampleRate::R48000,
        channels: ChannelCount::Stereo,
        period_size: 64,
        periods: 4,
    }
}
impl PcmDevice for Device {
    fn default_params(&self, _: bool) -> HwParams {
        defaults()
    }
    fn open(&self, capture: bool, _: u32) -> Result<Box<dyn PcmHardware>, SoundError> {
        if self.0.claimed[usize::from(capture)].swap(true, Ordering::AcqRel) {
            return Err(SoundError::DeviceBusy);
        }
        Ok(Box::new(Stream {
            backend: self.0.clone(),
            capture,
            params: defaults(),
            application: 0,
        }))
    }
    fn controls(&self) -> Vec<ControlId> {
        alloc::vec![ControlId {
            index: 0,
            kind: ControlKind::MasterVolume
        }]
    }
    fn get_control(&self, _: ControlId) -> Result<ControlValue, SoundError> {
        let v = self.0.volume.load(Ordering::Acquire);
        Ok(ControlValue::Integer { left: v, right: v })
    }
    fn set_control(&self, _: ControlId, v: ControlValue) -> Result<(), SoundError> {
        match v {
            ControlValue::Integer { left, right } if left == right && (0..=87).contains(&left) => {
                self.0.volume.store(left, Ordering::Release);
                Ok(())
            }
            _ => Err(SoundError::OutOfRange),
        }
    }
}
impl PcmHardware for Stream {
    fn configure(&mut self, p: HwParams) -> Result<(), SoundError> {
        if p != defaults() {
            return Err(SoundError::InvalidParams);
        }
        self.params = p;
        Ok(())
    }
    fn prepare(&mut self) -> Result<(), SoundError> {
        self.application = 0;
        self.backend.position[usize::from(self.capture)].store(0, Ordering::Release);
        Ok(())
    }
    fn start(&mut self) -> Result<(), SoundError> {
        if self.backend.fail_start.load(Ordering::Acquire) {
            return Err(SoundError::BadState);
        }
        Ok(())
    }
    fn stop(&mut self) -> Result<(), SoundError> {
        Ok(())
    }
    fn reset(&mut self) -> Result<(), SoundError> {
        self.application = self.pointer();
        Ok(())
    }
    fn pause(&mut self, paused: bool) -> Result<(), SoundError> {
        self.backend.paused[usize::from(self.capture)].store(paused, Ordering::Release);
        Ok(())
    }
    fn overwrite(&mut self, frame: u64, b: &[u8]) -> Result<(), SoundError> {
        let mut samples = self.backend.samples.lock();
        samples.resize(1024, 0);
        for (i, byte) in b.iter().enumerate() {
            samples[(frame as usize * 4 + i) % 1024] = *byte;
        }
        Ok(())
    }
    fn pointer(&self) -> u64 {
        self.backend.position[usize::from(self.capture)].load(Ordering::Acquire)
    }
    fn write(&mut self, b: &[u8]) -> Result<usize, SoundError> {
        self.application = self.application.max(self.pointer());
        let n = b
            .len()
            .min((256 - (self.application - self.pointer()).min(256)) as usize * 4);
        self.overwrite(self.application, &b[..n])?;
        self.application += (n / 4) as u64;
        self.backend.written.fetch_add(n as u64, Ordering::AcqRel);
        Ok(n)
    }
    fn read(&mut self, b: &mut [u8]) -> Result<usize, SoundError> {
        let n = b
            .len()
            .min(self.pointer().saturating_sub(self.application) as usize * 4);
        b[..n].fill(0x5a);
        self.application += (n / 4) as u64;
        Ok(n)
    }
    fn drain(&mut self) -> Result<(), SoundError> {
        Ok(())
    }
}
impl Drop for Stream {
    fn drop(&mut self) {
        self.backend.claimed[usize::from(self.capture)].store(false, Ordering::Release);
    }
}
struct Fixture {
    card: u32,
    backend: Arc<Backend>,
}
impl Fixture {
    fn new() -> Self {
        let backend = Arc::new(Backend::default());
        let card = crate::register_hardware_card(
            crate::CardInfo {
                index: 0,
                driver: "alsa-test",
                id: "ALSA",
                name: "ALSA ABI test",
                playback_count: 1,
                capture_count: 1,
            },
            Arc::new(Device(backend.clone())),
        );
        Self { card, backend }
    }
    fn pcm(&self, capture: bool) -> Arc<dyn FileOps> {
        let node: Arc<dyn FileOps> = if capture {
            Arc::new(crate::devfs_bridge::SoundPcmCaptureFile::new(self.card, 0))
        } else {
            Arc::new(crate::devfs_bridge::SoundPcmPlaybackFile::new(self.card, 0))
        };
        node.open_instance_checked(!capture).unwrap().unwrap()
    }
    fn control(&self) -> Arc<dyn FileOps> {
        crate::devfs_bridge::SoundControlFile::new(self.card)
            .open_instance_checked(true)
            .unwrap()
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        crate::unregister_hardware_card(self.card);
    }
}
fn run<T>(f: FsFuture<'_, T>) -> Result<T, FsError> {
    crate::tests_support::poll_once(f)
}
fn ioctl(
    f: &dyn FileOps,
    m: &Memory,
    nr: u8,
    dir: u32,
    size: u32,
    arg: u64,
) -> Result<u64, FsError> {
    run(f.ioctl_user(command(b'A', nr, dir, size), arg, m))
}
fn any_params(access: u32) -> Vec<u8> {
    let mut b = alloc::vec![0;608];
    put32(&mut b, 4, 1 << access);
    b[36..100].fill(255);
    for i in 0..12 {
        put32(&mut b, 264 + i * 12, u32::MAX);
    }
    put32(&mut b, 512, u32::MAX);
    b
}
fn configure(f: &dyn FileOps, m: &Memory, access: u32) -> Result<(), FsError> {
    m.put(128, &any_params(access));
    ioctl(f, m, 0x11, 3, 608, 128)?;
    ioctl(f, m, 0x40, 0, 0, 0)?;
    Ok(())
}
macro_rules! test {
    ($name:ident,$body:block) => {
        fn $name() -> TestResult {
            $body;
            TestResult::Pass
        }
        kernel_test_in!("drivers/sound/alsa", $name);
    };
}

test!(alsa_pcm_refine_and_linux_errno_precedence, {
    let fixture = Fixture::new();
    let f = fixture.pcm(false);
    let m = Memory::new();
    assert_eq!(ioctl(f.as_ref(), &m, 0, 2, 4, 64), Ok(0));
    assert_eq!(get32(&m.bytes.lock(), 64), 0x20012);
    assert_eq!(run(f.read(0, &mut [0; 4])), Err(FsError::InvalidData));
    // pcm_native: unknown word never accesses the argument; TSTAMP ignores it.
    assert_eq!(ioctl(f.as_ref(), &m, 0xfe, 3, 4096, 0), Ok((-25i64) as u64));
    assert_eq!(ioctl(f.as_ref(), &m, 2, 1, 4, 0), Ok(0));
    assert_eq!(ioctl(f.as_ref(), &m, 0, 2, 4, 0), Err(FsError::BadAddress));
    assert_eq!(
        ioctl(f.as_ref(), &m, 0x12, 0, 0, 0),
        Err(FsError::BadFileState)
    );
    assert_eq!(
        ioctl(f.as_ref(), &m, 0x40, 0, 0, 0),
        Err(FsError::BadFileState)
    );
    assert_eq!(
        ioctl(f.as_ref(), &m, 0x21, 2, 8, 0),
        Err(FsError::BadFileState)
    );
    assert_eq!(
        f.poll_readiness() & (POLL_OUT | POLL_ERR),
        POLL_OUT | POLL_ERR
    );
    m.put(128, &any_params(3));
    assert_eq!(ioctl(f.as_ref(), &m, 0x10, 3, 608, 128), Ok(0));
    assert_eq!(get32(&m.bytes.lock(), 128 + 36), 1 << 2);
    assert_eq!(get32(&m.bytes.lock(), 128 + 260 + 3 * 12), 48000);
    let mut impossible = any_params(3);
    put32(&mut impossible, 36, 1 << 10);
    m.put(128, &impossible);
    assert_eq!(
        ioctl(f.as_ref(), &m, 0x10, 3, 608, 128),
        Err(FsError::InvalidData)
    );
    configure(f.as_ref(), &m, 3).unwrap();
    // SW_PARAMS.boundary is output, not an input requirement.
    let mut sw = [0; 136];
    put32(&mut sw, 4, 1);
    put64(&mut sw, 16, 64);
    put64(&mut sw, 32, 256);
    put64(&mut sw, 40, 256);
    m.put(1024, &sw);
    assert_eq!(ioctl(f.as_ref(), &m, 0x13, 3, 136, 1024), Ok(0));
    assert!(m.word(1024 + 64) > 256);
    assert_eq!(ioctl(f.as_ref(), &m, 0x61, 0, 0, 0), Ok((-114i64) as u64));
    assert_eq!(
        ioctl(f.as_ref(), &m, 0x45, 1, 4, 0),
        Err(FsError::BadFileState)
    );
});

test!(alsa_pcm_rw_backpressure_xrun_and_recovery, {
    let fixture = Fixture::new();
    let f = fixture.pcm(false);
    let m = Memory::new();
    configure(f.as_ref(), &m, 3).unwrap();
    m.put(4096, &[0x33; 1024]);
    let mut transfer = [0; 24];
    put64(&mut transfer, 8, 4096);
    put64(&mut transfer, 16, 256);
    m.put(2048, &transfer);
    assert_eq!(ioctl(f.as_ref(), &m, 0x50, 1, 24, 2048), Ok(0));
    assert_eq!(m.word(2048), 256);
    assert_eq!(fixture.backend.written.load(Ordering::Acquire), 1024);
    assert_eq!(f.poll_readiness() & POLL_OUT, 0);
    assert_eq!(
        ioctl(f.as_ref(), &m, 0x50, 1, 24, 2048),
        Err(FsError::WouldBlock)
    );
    fixture.backend.position[0].store(64, Ordering::Release);
    assert_ne!(f.poll_readiness() & POLL_OUT, 0);
    fixture.backend.position[0].store(257, Ordering::Release);
    assert_ne!(f.poll_readiness() & POLL_ERR, 0);
    assert_eq!(
        ioctl(f.as_ref(), &m, 0x21, 2, 8, 64),
        Err(FsError::StreamXrun)
    );
    assert_eq!(ioctl(f.as_ref(), &m, 0x40, 0, 0, 0), Ok(0));
    assert_eq!(f.poll_readiness() & POLL_ERR, 0);
});

test!(alsa_pcm_mmap_commit_and_backing_lifetime, {
    let fixture = Fixture::new();
    let f = fixture.pcm(false);
    let m = Memory::new();
    configure(f.as_ref(), &m, 0).unwrap();
    assert!(f.validate_mmap(0, 8192, 3, 1).is_err());
    assert!(f.validate_mmap(0, 4096, 3, 2).is_err());
    let data = f.mmap_backing(0, 4096).unwrap();
    // SYNC_APPLPTR requires the ioctl commit path, including on x86.
    assert_eq!(
        f.mmap_backing(0x81000000, 4096).unwrap_err(),
        FsError::NoDeviceAddress
    );
    m.put(64, &0x20010u32.to_ne_bytes());
    ioctl(f.as_ref(), &m, 4, 1, 4, 64).unwrap();
    let status = f.mmap_backing(0x80000000, 4096);
    if cfg!(target_arch = "aarch64") {
        assert_eq!(status.as_ref().unwrap_err(), &FsError::NoDeviceAddress);
    }
    // SAFETY: these are freshly retained device-owned pages, accessible via
    // the physical direct map; atomic words match the mmap protocol offsets.
    unsafe {
        let ptr = narf_memory::PhysAddr::new(data.frames[0]).kernel_mut_ptr::<u8>();
        core::ptr::write_bytes(ptr, 0x44, 1024);
    }
    let mut sync = [0; 136];
    put32(&mut sync, 0, 4);
    put64(&mut sync, 72, 256);
    m.put(1024, &sync);
    ioctl(f.as_ref(), &m, 0x23, 3, 136, 1024).unwrap();
    ioctl(f.as_ref(), &m, 0x42, 0, 0, 0).unwrap();
    f.poll_readiness();
    assert_eq!(fixture.backend.written.load(Ordering::Acquire), 1024);
    fixture.backend.position[0].store(128, Ordering::Release);
    f.poll_readiness();
    // SAFETY: retained status page, aligned atomic hardware pointer word.
    if let Ok(status) = &status {
        // SAFETY: retained status page, aligned atomic hardware pointer word.
        let hw = unsafe {
            (&*narf_memory::PhysAddr::new(status.frames[0] + 8).kernel_ptr::<AtomicU64>())
                .load(Ordering::Acquire)
        };
        assert_eq!(hw, 128);
    }
    ioctl(f.as_ref(), &m, 0x43, 0, 0, 0).unwrap();
    assert_eq!(
        ioctl(f.as_ref(), &m, 0x12, 0, 0, 0),
        Err(FsError::BadFileState)
    );
    drop(data);
    ioctl(f.as_ref(), &m, 0x12, 0, 0, 0).unwrap();
    drop(f);
    if let Ok(status) = status {
        assert!(status.lifetime.is_some());
    }
});

test!(
    alsa_large_transfers_null_silence_and_zero_size_precedence,
    {
        let fixture = Fixture::new();
        let f = fixture.pcm(false);
        let m = Memory::new();
        configure(f.as_ref(), &m, 3).unwrap();
        let mut transfer = [0; 24];
        // A request larger than the staging limit copies only what fits. Null
        // playback data has Linux's explicit silence meaning, not EFAULT.
        put64(&mut transfer, 16, 100_000);
        m.put(2048, &transfer);
        assert_eq!(ioctl(f.as_ref(), &m, 0x50, 1, 24, 2048), Ok(0));
        assert_eq!(m.word(2048), 256);
        fixture.backend.position[0].store(257, Ordering::Release);
        f.poll_readiness();
        put64(&mut transfer, 16, 0);
        m.put(2048, &transfer);
        assert_eq!(ioctl(f.as_ref(), &m, 0x50, 1, 24, 2048), Ok(0));
        assert_eq!(m.word(2048), 0);
        m.put(64, &1u64.to_ne_bytes());
        assert_eq!(
            ioctl(f.as_ref(), &m, 0x46, 1, 8, 64),
            Err(FsError::StreamXrun)
        );
        assert_eq!(m.word(64) as i64, -32);
        m.put(64, &0u64.to_ne_bytes());
        assert_eq!(ioctl(f.as_ref(), &m, 0x46, 1, 8, 64), Ok(0));
    }
);

test!(
    alsa_capture_rejects_pointer_commit_beyond_available_frames,
    {
        let fixture = Fixture::new();
        let f = fixture.pcm(true);
        let m = Memory::new();
        configure(f.as_ref(), &m, 0).unwrap();
        ioctl(f.as_ref(), &m, 0x42, 0, 0, 0).unwrap();
        fixture.backend.position[1].store(64, Ordering::Release);
        let mut sync = [0; 136];
        put32(&mut sync, 0, 4);
        put64(&mut sync, 72, 65);
        m.put(1024, &sync);
        assert_eq!(
            ioctl(f.as_ref(), &m, 0x23, 3, 136, 1024),
            Err(FsError::InvalidData)
        );
        put64(&mut sync, 72, 64);
        m.put(1024, &sync);
        assert_eq!(ioctl(f.as_ref(), &m, 0x23, 3, 136, 1024), Ok(0));
        assert_eq!(m.word(1024 + 72), 64);
        assert_eq!(f.poll_readiness() & POLL_ERR, 0);
    }
);

test!(alsa_capture_sync_ptr_and_planar_transfer, {
    let fixture = Fixture::new();
    let f = fixture.pcm(true);
    let m = Memory::new();
    configure(f.as_ref(), &m, 4).unwrap();
    assert_eq!(run(f.write(0, &[0; 4])), Err(FsError::InvalidData));
    let mut x = [0; 24];
    put64(&mut x, 8, 4096);
    put64(&mut x, 16, 16);
    m.put(2048, &x);
    m.put(4096, &8192u64.to_ne_bytes());
    m.put(4104, &12288u64.to_ne_bytes());
    assert_eq!(
        ioctl(f.as_ref(), &m, 0x53, 2, 24, 2048),
        Err(FsError::WouldBlock)
    );
    fixture.backend.position[1].store(64, Ordering::Release);
    assert_ne!(f.poll_readiness() & POLL_IN, 0);
    assert_eq!(ioctl(f.as_ref(), &m, 0x53, 2, 24, 2048), Ok(0));
    assert_eq!(m.word(2048), 16);
    assert_eq!(&m.bytes.lock()[8192..8224], &[0x5a; 32]);
    assert_eq!(&m.bytes.lock()[12288..12320], &[0x5a; 32]);
    let mut sync = [0; 136];
    put32(&mut sync, 0, 7);
    m.put(1024, &sync);
    assert_eq!(ioctl(f.as_ref(), &m, 0x23, 3, 136, 1024), Ok(0));
    assert_eq!(m.word(1024 + 72), 16);
    assert_eq!(m.word(1024 + 16), 64);
});

test!(alsa_mixer_nested_pointers_events_and_locks, {
    let fixture = Fixture::new();
    let first = fixture.control();
    let second = fixture.control();
    let m = Memory::new();
    let ctl = |f: &dyn FileOps, nr, dir, size, arg| {
        run(f.ioctl_user(command(b'U', nr, dir, size), arg, &m))
    };
    let mut list = [0; 80];
    put32(&mut list, 4, 1);
    put64(&mut list, 16, 4096);
    m.put(128, &list);
    assert_eq!(ctl(first.as_ref(), 0x10, 3, 80, 128), Ok(0));
    assert_eq!(get32(&m.bytes.lock(), 128 + 12), 1);
    assert_eq!(get32(&m.bytes.lock(), 4096), 1);
    assert_eq!(run(first.write(0, b"0 50\n")), Err(FsError::InvalidData));
    put64(&mut list, 16, u64::MAX);
    m.put(128, &list);
    assert_eq!(
        ctl(first.as_ref(), 0x10, 3, 80, 128),
        Err(FsError::BadAddress)
    );
    let mut id = [0; 64];
    put32(&mut id, 0, 1);
    m.put(128, &id);
    assert_eq!(
        ctl(first.as_ref(), 0x15, 1, 64, 128),
        Err(FsError::InvalidData)
    );
    assert_eq!(ctl(first.as_ref(), 0x14, 1, 64, 128), Ok(0));
    assert_eq!(ctl(second.as_ref(), 0x14, 1, 64, 128), Err(FsError::Busy));
    assert_eq!(
        ctl(second.as_ref(), 0x15, 1, 64, 128),
        Err(FsError::OperationNotPermitted)
    );
    m.put(64, &1u32.to_ne_bytes());
    ctl(second.as_ref(), 0x16, 3, 4, 64).unwrap();
    let mut value = alloc::vec![0;1224];
    put32(&mut value, 0, 1);
    put64(&mut value, 72, 35);
    put64(&mut value, 80, 35);
    m.put(128, &value);
    assert_eq!(ctl(first.as_ref(), 0x13, 3, 1224, 128), Ok(0));
    assert_ne!(second.poll_readiness() & POLL_IN, 0);
    let mut event = [0; 72];
    assert_eq!(run(second.read(0, &mut event)), Ok(72));
    assert_eq!(get32(&event, 4), 1);
    assert_eq!(get32(&event, 8), 1);
    assert_eq!(second.poll_readiness() & POLL_IN, 0);
    let mut tlv = [0; 8];
    put32(&mut tlv, 0, 1);
    put32(&mut tlv, 4, 8);
    m.put(128, &tlv);
    assert_eq!(
        ctl(first.as_ref(), 0x1a, 3, 8, 128),
        Err(FsError::NoDeviceAddress)
    );
    assert_eq!(ctl(first.as_ref(), 0xd0, 3, 4, 0), Ok((-92i64) as u64));
});

fn state(f: &dyn FileOps, m: &Memory) -> u32 {
    ioctl(f, m, 0x20, 2, 152, 2048).unwrap();
    get32(&m.bytes.lock(), 2048)
}
fn policy(f: &dyn FileOps, m: &Memory, start: u64, stop: u64, threshold: u64, silence: u64) {
    let mut b = alloc::vec![0;136];
    put64(&mut b, 16, 1);
    put64(&mut b, 32, start);
    put64(&mut b, 40, stop);
    put64(&mut b, 48, threshold);
    put64(&mut b, 56, silence);
    m.put(1024, &b);
    ioctl(f, m, 0x13, 3, 136, 1024).unwrap();
}
fn ctl(f: &dyn FileOps, m: &Memory, nr: u8, size: u32, at: u64) -> Result<u64, FsError> {
    run(f.ioctl_user(
        command(
            b'U',
            nr,
            if matches!(nr, 0x14 | 0x15) { 1 } else { 3 },
            size,
        ),
        at,
        m,
    ))
}
fn user_info(name: &str, kind: u32, count: u32, elements: u32) -> Vec<u8> {
    let mut b = alloc::vec![0;272];
    put32(&mut b, 4, 2);
    string(&mut b, 16, 44, name);
    put32(&mut b, 64, kind);
    put32(&mut b, 68, 3 | 32);
    put32(&mut b, 72, count);
    put32(&mut b, 76, elements);
    put64(&mut b, 88, 100);
    b
}
test!(alsa_linked_pause_resume_and_suspend, {
    let fixture = Fixture::new();
    let m = Memory::new();
    let p = fixture.pcm(false);
    let c = fixture.pcm(true);
    m.files.lock().extend([p.clone(), c.clone()]);
    configure(p.as_ref(), &m, 3).unwrap();
    configure(c.as_ref(), &m, 3).unwrap();
    policy(p.as_ref(), &m, 1024, 256, 0, 0);
    assert_eq!(
        ioctl(p.as_ref(), &m, 0x60, 1, 4, 99),
        Err(FsError::BadFileState)
    );
    assert_eq!(
        ioctl(p.as_ref(), &m, 0x60, 1, 4, 0),
        Err(FsError::InvalidData)
    );
    assert_eq!(ioctl(p.as_ref(), &m, 0x60, 1, 4, 1), Ok(0));
    assert_eq!(ioctl(p.as_ref(), &m, 0x60, 1, 4, 1), Ok((-114i64) as u64));
    run(p.write(0, &[7; 256])).unwrap();
    ioctl(p.as_ref(), &m, 0x42, 0, 0, 0).unwrap();
    assert_eq!(state(c.as_ref(), &m), 3);
    ioctl(c.as_ref(), &m, 0x45, 1, 4, 1).unwrap();
    assert_eq!(state(p.as_ref(), &m), 6);
    assert_eq!(state(c.as_ref(), &m), 6);
    assert!(fixture.backend.paused[0].load(Ordering::Acquire));
    assert!(fixture.backend.paused[1].load(Ordering::Acquire));
    run(p.write(0, &[9; 64])).unwrap();
    ioctl(p.as_ref(), &m, 0x45, 1, 4, 0).unwrap();
    assert_eq!(state(c.as_ref(), &m), 3);
    run(Box::pin(crate::suspend_hardware_card(fixture.card))).unwrap();
    assert_eq!(state(p.as_ref(), &m), 7);
    assert_ne!(p.poll_readiness() & POLL_ERR, 0);
    assert_eq!(run(p.write(0, &[0; 4])), Err(FsError::StreamSuspended));
    assert_eq!(
        ioctl(p.as_ref(), &m, 0x22, 0, 0, 0),
        Err(FsError::StreamSuspended)
    );
    ioctl(c.as_ref(), &m, 0x47, 0, 0, 0).unwrap();
    assert_eq!(state(p.as_ref(), &m), 3);
    ioctl(c.as_ref(), &m, 0x43, 0, 0, 0).unwrap();
    assert_eq!(state(p.as_ref(), &m), 1);
    ioctl(p.as_ref(), &m, 0x61, 0, 0, 0).unwrap();
    assert_eq!(ioctl(c.as_ref(), &m, 0x61, 0, 0, 0), Ok((-114i64) as u64));
});
test!(alsa_group_autostart_failure_and_close, {
    let a = Fixture::new();
    let b = Fixture::new();
    let m = Memory::new();
    let p = a.pcm(false);
    let c = b.pcm(true);
    configure(p.as_ref(), &m, 3).unwrap();
    configure(c.as_ref(), &m, 3).unwrap();
    m.files.lock().push(c.clone());
    ioctl(p.as_ref(), &m, 0x60, 1, 4, 0).unwrap();
    b.backend.fail_start.store(true, Ordering::Release);
    // pcm_lib.c returns copied bytes even when the automatic group start fails.
    assert_eq!(run(p.write(0, &[0; 128])), Ok(128));
    assert_eq!(run(p.write(0, &[0; 4])), Err(FsError::StreamXrun));
    assert_eq!(state(p.as_ref(), &m), 4);
    assert_eq!(state(c.as_ref(), &m), 4);
    ioctl(p.as_ref(), &m, 0x40, 0, 0, 0).unwrap();
    let mut xfer = [0; 24];
    put64(&mut xfer, 16, 32);
    m.put(4096, &xfer);
    assert_eq!(ioctl(p.as_ref(), &m, 0x50, 1, 24, 4096), Ok(0));
    assert_eq!(m.word(4096), 32);
    assert_eq!(state(c.as_ref(), &m), 4);
    b.backend.fail_start.store(false, Ordering::Release);
    ioctl(p.as_ref(), &m, 0x40, 0, 0, 0).unwrap();
    run(p.write(0, &[0; 128])).unwrap();
    assert_eq!(state(c.as_ref(), &m), 3);
    m.files.lock().clear();
    // An in-flight group operation owns a runtime Arc, not the file. Closing
    // the file must still stop its peers while that runtime remains retained.
    let retained = crate::devfs_bridge::pcm_from_file(c.as_ref()).unwrap();
    drop(c);
    assert_eq!(state(p.as_ref(), &m), 1);
    drop(retained);
});
test!(alsa_silence_and_boundary_playback, {
    let fixture = Fixture::new();
    let m = Memory::new();
    let p = fixture.pcm(false);
    configure(p.as_ref(), &m, 0).unwrap();
    policy(p.as_ref(), &m, 1024, 256, 128, 64);
    // PREPARED silence occupies real backend slots, but is not application data.
    ioctl(p.as_ref(), &m, 0x20, 2, 152, 2048).unwrap();
    assert!(fixture.backend.written.load(Ordering::Acquire) >= 256);
    let backing = p.mmap_backing(0, 4096).unwrap();
    let address = narf_memory::PhysAddr::new(backing.frames[0]).kernel_mut_ptr::<u8>();
    // SAFETY: retained owned PCM mapping; the first 64 frames fit this page.
    unsafe {
        core::ptr::write_bytes(address, 0x6d, 256);
    }
    let mut sync = alloc::vec![0;136];
    put32(&mut sync, 0, 4);
    put64(&mut sync, 72, 64);
    m.put(3000, &sync);
    ioctl(p.as_ref(), &m, 0x23, 3, 136, 3000).unwrap();
    assert!(fixture.backend.samples.lock()[..256]
        .iter()
        .all(|b| *b == 0x6d));
    ioctl(p.as_ref(), &m, 0x42, 0, 0, 0).unwrap();
    fixture.backend.position[0].store(65, Ordering::Release);
    assert_eq!(state(p.as_ref(), &m), 4); // silence never masks normal XRUN policy
    ioctl(p.as_ref(), &m, 0x40, 0, 0, 0).unwrap();
    policy(p.as_ref(), &m, 1024, u64::MAX, 0, 0);
    let boundary = m.word(1088);
    policy(p.as_ref(), &m, boundary, boundary, 0, boundary);
    ioctl(p.as_ref(), &m, 0x40, 0, 0, 0).unwrap();
    // PREPARE initializes silence before mmap writers populate their samples.
    // SAFETY: the retained PCM backing still owns this complete sample range.
    unsafe {
        core::ptr::write_bytes(address, 0x3c, 256);
    }
    ioctl(p.as_ref(), &m, 0x42, 0, 0, 0).unwrap(); // empty boundary-mode start is valid
    assert!(fixture.backend.samples.lock()[..256]
        .iter()
        .all(|b| *b == 0x3c));
    fixture.backend.position[0].store(1024, Ordering::Release);
    assert_eq!(state(p.as_ref(), &m), 3);
    assert_eq!(m.word(2048 + 64), 1280); // Linux avail may exceed buffer_size
    assert!(fixture.backend.samples.lock().iter().all(|b| *b == 0));
    ioctl(p.as_ref(), &m, 0x43, 0, 0, 0).unwrap();
});
test!(alsa_user_controls_tlv_events_and_ownership, {
    let fixture = Fixture::new();
    let m = Memory::new();
    let a = fixture.control();
    let b = fixture.control();
    m.put(64, &1u32.to_ne_bytes());
    ctl(b.as_ref(), &m, 0x16, 4, 64).unwrap();
    m.put(128, &user_info("User Volume", 2, 2, 2));
    ctl(a.as_ref(), &m, 0x17, 272, 128).unwrap();
    let mut id = m.bytes.lock()[128..192].to_vec();
    let num = get32(&id, 0);
    m.put(1024, &id);
    ctl(a.as_ref(), &m, 0x11, 272, 1024).unwrap();
    assert_eq!(get32(&m.bytes.lock(), 1024 + 76), 42);
    assert_eq!(get32(&m.bytes.lock(), 1024 + 68) & (512 | 1024), 512 | 1024);
    let mut value = alloc::vec![0;1224];
    value[..64].copy_from_slice(&id);
    put64(&mut value, 72, 21);
    put64(&mut value, 80, 22);
    m.put(2048, &value);
    assert_eq!(
        ctl(b.as_ref(), &m, 0x13, 1224, 2048),
        Err(FsError::OperationNotPermitted)
    );
    ctl(a.as_ref(), &m, 0x13, 1224, 2048).unwrap();
    ctl(b.as_ref(), &m, 0x12, 1224, 2048).unwrap();
    assert_eq!(m.word(2048 + 80), 22);
    let mut tlv = alloc::vec![0;24];
    put32(&mut tlv, 0, num);
    put32(&mut tlv, 4, 16);
    put32(&mut tlv, 8, 1);
    put32(&mut tlv, 12, 8);
    put32(&mut tlv, 16, 100);
    m.put(4096, &tlv);
    assert_eq!(ctl(a.as_ref(), &m, 0x1b, 8, 4096), Ok(1));
    assert_eq!(ctl(a.as_ref(), &m, 0x1b, 8, 4096), Ok(0));
    assert_eq!(
        ctl(b.as_ref(), &m, 0x1b, 8, 4096),
        Err(FsError::OperationNotPermitted)
    );
    m.put(4100, &8u32.to_ne_bytes());
    assert_eq!(ctl(b.as_ref(), &m, 0x1a, 8, 4096), Err(FsError::NoSpace));
    m.put(4100, &16u32.to_ne_bytes());
    ctl(b.as_ref(), &m, 0x1a, 8, 4096).unwrap();
    assert_eq!(get32(&m.bytes.lock(), 4112), 100);
    let mut events = [0; 144];
    assert_eq!(run(b.read(0, &mut events)), Ok(144));
    assert_eq!(get32(&events, 4), 1 | 2 | 4 | 8);
    assert_eq!(get32(&events, 76), 2 | 4 | 8);
    m.put(128, &id);
    assert_eq!(ctl(b.as_ref(), &m, 0x19, 64, 128), Err(FsError::Busy));
    drop(a);
    ctl(b.as_ref(), &m, 0x14, 64, 128).unwrap();
    ctl(b.as_ref(), &m, 0x19, 64, 128).unwrap();
    assert_eq!(ctl(b.as_ref(), &m, 0x11, 272, 128), Err(FsError::NotFound));
    assert_eq!(run(b.read(0, &mut events)), Ok(144));
    assert_eq!(get32(&events, 4), u32::MAX);
    put32(&mut id, 0, num + 1);
    m.put(128, &id);
    assert_eq!(ctl(b.as_ref(), &m, 0x11, 272, 128), Err(FsError::NotFound));
});
test!(alsa_user_enum_replace_and_validation, {
    let fixture = Fixture::new();
    let m = Memory::new();
    let c = fixture.control();
    let mut b = user_info("Input Route", 3, 1, 1);
    put32(&mut b, 80, 2);
    put64(&mut b, 152, 1024);
    put32(&mut b, 160, 8);
    m.put(1024, b"Mic\0Aux\0");
    m.put(128, &b);
    ctl(c.as_ref(), &m, 0x17, 272, 128).unwrap();
    let num = get32(&m.bytes.lock(), 128);
    m.put(128 + 84, &99u32.to_ne_bytes());
    ctl(c.as_ref(), &m, 0x11, 272, 128).unwrap();
    assert_eq!(&m.bytes.lock()[128 + 88..128 + 92], b"Aux\0");
    assert_eq!(m.word(128 + 152), 0);
    let mut v = alloc::vec![0;1224];
    put32(&mut v, 0, num);
    put32(&mut v, 72, 2);
    m.put(2048, &v);
    assert_eq!(
        ctl(c.as_ref(), &m, 0x13, 1224, 2048),
        Err(FsError::InvalidData)
    );
    // REPLACE removes the old group before validating the replacement count.
    put32(&mut b, 72, 0);
    m.put(128, &b);
    assert_eq!(
        ctl(c.as_ref(), &m, 0x18, 272, 128),
        Err(FsError::InvalidData)
    );
    m.put(128, &num.to_ne_bytes());
    assert_eq!(ctl(c.as_ref(), &m, 0x11, 272, 128), Err(FsError::NotFound));
    put32(&mut b, 72, 1);
    put64(&mut b, 152, 0);
    m.put(128, &b);
    assert_eq!(
        ctl(c.as_ref(), &m, 0x17, 272, 128),
        Err(FsError::BadAddress)
    );
});

test!(alsa_user_control_types_and_copy_fault_rollback, {
    let fixture = Fixture::new();
    let m = Memory::new();
    let c = fixture.control();
    // SUBSCRIBE only copies out when querying with a negative argument.
    m.put(64, &1u32.to_ne_bytes());
    m.read_only.store(64, Ordering::Release);
    assert_eq!(ctl(c.as_ref(), &m, 0x16, 4, 64), Ok(0));
    m.put(64, &(-1i32).to_ne_bytes());
    assert_eq!(ctl(c.as_ref(), &m, 0x16, 4, 64), Err(FsError::BadAddress));
    m.read_only.store(0, Ordering::Release);
    for (kind, count, bytes) in [
        (1, 128, 1024),
        (2, 128, 1024),
        (3, 128, 512),
        (4, 512, 512),
        (5, 1, 176),
        (6, 64, 512),
    ] {
        let mut b = user_info("Typed Control", kind, count, 1);
        if kind == 3 {
            put32(&mut b, 80, 2);
            put64(&mut b, 152, 4096);
            put32(&mut b, 160, 4);
            m.put(4096, b"A\0B\0");
        }
        m.put(128, &b);
        ctl(c.as_ref(), &m, 0x17, 272, 128).unwrap();
        let id = m.bytes.lock()[128..192].to_vec();
        let mut v = alloc::vec![0;1224];
        v[..64].copy_from_slice(&id);
        if matches!(kind, 4 | 5) {
            v[72..72 + bytes].fill(0xa5);
        } else if kind == 3 {
            for i in 0..count as usize {
                put32(&mut v, 72 + i * 4, 1);
            }
        } else {
            for i in 0..count as usize {
                put64(&mut v, 72 + i * 8, 1);
            }
        }
        m.put(2048, &v);
        ctl(c.as_ref(), &m, 0x13, 1224, 2048).unwrap();
        m.put(2120, &alloc::vec![0xcc;1152]);
        ctl(c.as_ref(), &m, 0x12, 1224, 2048).unwrap();
        assert_eq!(&m.bytes.lock()[2120..2120 + bytes], &v[72..72 + bytes]);
        assert!(m.bytes.lock()[2120 + bytes..3272].iter().all(|b| *b == 0));
        m.put(128, &id);
        ctl(c.as_ref(), &m, 0x19, 64, 128).unwrap();
    }
    let b = user_info("Copy Fault", 1, 1, 1);
    m.put(128, &b);
    m.read_only.store(128, Ordering::Release);
    assert_eq!(
        ctl(c.as_ref(), &m, 0x17, 272, 128),
        Err(FsError::BadAddress)
    );
    m.read_only.store(0, Ordering::Release);
    assert_eq!(ctl(c.as_ref(), &m, 0x11, 272, 128), Err(FsError::NotFound));
});
test!(alsa_cross_card_suspend_reset_and_xrun_group, {
    let a = Fixture::new();
    let b = Fixture::new();
    let m = Memory::new();
    let p = a.pcm(false);
    let c = b.pcm(true);
    configure(p.as_ref(), &m, 3).unwrap();
    configure(c.as_ref(), &m, 3).unwrap();
    m.files.lock().push(c.clone());
    ioctl(p.as_ref(), &m, 0x60, 1, 4, 0).unwrap();
    run(p.write(0, &[0; 256])).unwrap();
    run(Box::pin(crate::suspend_hardware_card(a.card))).unwrap();
    assert_eq!(state(c.as_ref(), &m), 7);
    ioctl(p.as_ref(), &m, 0x47, 0, 0, 0).unwrap();
    assert_eq!(state(c.as_ref(), &m), 3);
    // A nonzero PAUSE argument is a boolean even above the low 32 bits.
    ioctl(c.as_ref(), &m, 0x45, 1, 4, 1 << 32).unwrap();
    ioctl(p.as_ref(), &m, 0x41, 0, 0, 0).unwrap();
    assert_eq!(state(c.as_ref(), &m), 6);
    run(p.write(0, &[0; 128])).unwrap();
    ioctl(p.as_ref(), &m, 0x45, 1, 4, 0).unwrap();
    a.backend.position[0].store(64, Ordering::Release);
    assert_eq!(state(p.as_ref(), &m), 4);
    assert_ne!(c.poll_readiness() & POLL_ERR, 0);
    assert_eq!(state(c.as_ref(), &m), 4);
    ioctl(p.as_ref(), &m, 0x40, 0, 0, 0).unwrap();
    // No member may start when a peer has freed its hardware parameters.
    ioctl(c.as_ref(), &m, 0x12, 0, 0, 0).unwrap();
    policy(p.as_ref(), &m, 1024, 256, 0, 0);
    run(p.write(0, &[0; 64])).unwrap();
    assert_eq!(
        ioctl(p.as_ref(), &m, 0x42, 0, 0, 0),
        Err(FsError::BadFileState)
    );
    assert_eq!(state(p.as_ref(), &m), 2);
});

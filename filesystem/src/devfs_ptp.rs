//! Linux /dev/ptpN character devices backed by the precision-clock registry.
use crate::{FileOps, FileType, FsError, FsFuture, IoctlContext, Mode, Stat};
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};

#[derive(Debug)]
pub struct PtpFile {
    pub index: u32,
    clock: Arc<dyn narf_time::phc::HardwareClock>,
}
fn lookup(name: &str) -> Option<Arc<dyn FileOps>> {
    let index = name.strip_prefix("ptp")?.parse().ok()?;
    PtpFile::open(index).map(|f| f as Arc<dyn FileOps>)
}
impl PtpFile {
    pub fn open(index: u32) -> Option<Arc<Self>> {
        Some(Arc::new(Self {
            index,
            clock: narf_time::phc::get(index)?,
        }))
    }
}

fn enumerate() -> Vec<(alloc::string::String, FileType)> {
    narf_time::phc::indices()
        .into_iter()
        .map(|i| (alloc::format!("ptp{i}"), FileType::Special))
        .collect()
}
pub fn register() {
    crate::devfs::register_provider(crate::devfs::DeviceProvider {
        name: "ptp",
        lookup,
        lookup_dir: |_| None,
        enumerate,
    });
}
fn error(e: i32) -> FsError {
    match e {
        19 => FsError::NoDevice,
        22 => FsError::InvalidPath,
        16 => FsError::Busy,
        _ => FsError::Io(narf_block::BlockError::IOError),
    }
}
fn timestamp(out: &mut [u8], offset: usize, ns: u64) {
    out[offset..offset + 8].copy_from_slice(&((ns / 1_000_000_000) as i64).to_ne_bytes());
    out[offset + 8..offset + 12].copy_from_slice(&((ns % 1_000_000_000) as u32).to_ne_bytes());
}
fn wall_ns() -> u64 {
    let w = narf_time::now_wall();
    (w.secs.max(0) as u64).saturating_mul(1_000_000_000) + u64::from(w.nanos)
}
impl FileOps for PtpFile {
    fn read<'a>(&'a self, _: u64, _: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
    fn write<'a>(&'a self, _: u64, _: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }
    fn rdev(&self) -> u64 {
        crate::devfs::linux_makedev(247, self.index)
    }
    fn hardware_clock(&self) -> Option<Arc<dyn narf_time::phc::HardwareClock>> {
        Some(self.clock.clone())
    }
    fn ioctl_user<'a>(
        &'a self,
        cmd: u32,
        arg: u64,
        user: &'a dyn IoctlContext,
    ) -> FsFuture<'a, u64> {
        Box::pin(async move {
            if (cmd >> 8) & 255 != b'=' as u32 {
                return Err(FsError::Unsupported);
            }
            match cmd {
                0x80503d01 | 0x80503d0a => {
                    let mut out = [0u8; 80];
                    out[..4].copy_from_slice(&self.clock.max_adjust_ppb().to_ne_bytes());
                    user.write(arg, &out)?;
                    Ok(0)
                }
                0x43403d05 | 0xc4c03d09 | 0x43403d0e | 0xc4c03d12 => {
                    let mut header = [0u8; 16];
                    user.read(arg, &mut header)?;
                    let n = u32::from_ne_bytes(header[..4].try_into().unwrap()) as usize;
                    if n > 25 {
                        return Err(FsError::InvalidPath);
                    }
                    let extended = matches!(cmd & 255, 9 | 18);
                    let mut out = vec![0u8; if extended { 1216 } else { 832 }];
                    out[..16].copy_from_slice(&header);
                    for i in 0..n {
                        let before = wall_ns();
                        let device = self.clock.read_ns().map_err(error)?;
                        let after = wall_ns();
                        if extended {
                            timestamp(&mut out, 16 + i * 48, before);
                            timestamp(&mut out, 32 + i * 48, device);
                            timestamp(&mut out, 48 + i * 48, after);
                        } else {
                            timestamp(&mut out, 16 + i * 32, before);
                            timestamp(&mut out, 32 + i * 32, device);
                            timestamp(&mut out, 48 + i * 32, after);
                        }
                    }
                    user.write(arg, &out)?;
                    Ok(0)
                }
                _ => Err(FsError::Unsupported),
            }
        })
    }
}

mod tests {
    use super::*;
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;
    #[derive(Debug)]
    struct Clock;
    impl narf_time::phc::HardwareClock for Clock {
        fn read_ns(&self) -> Result<u64, i32> {
            Ok(7_000_000_123)
        }
        fn set_ns(&self, _: u64) -> Result<(), i32> {
            Ok(())
        }
        fn adjust(&self, _: i64, _: i32) -> Result<(), i32> {
            Ok(())
        }
        fn max_adjust_ppb(&self) -> u32 {
            62_499_999
        }
    }
    struct User {
        input: [u8; 16],
        output: IrqSafeSpinLock<Vec<u8>>,
    }
    impl IoctlContext for User {
        fn read(&self, _: u64, b: &mut [u8]) -> Result<(), FsError> {
            b.copy_from_slice(&self.input[..b.len()]);
            Ok(())
        }
        fn write(&self, _: u64, b: &[u8]) -> Result<(), FsError> {
            *self.output.lock() = b.to_vec();
            Ok(())
        }
        fn nonblocking(&self) -> bool {
            false
        }
    }
    fn poll<F: Future>(f: F) -> Option<F::Output> {
        let mut f = pin!(f);
        let mut c = Context::from_waker(Waker::noop());
        match f.as_mut().poll(&mut c) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }
    fn smoke_ptp_ioctl_sizes_and_samples() -> TestResult {
        let file = PtpFile {
            index: 0,
            clock: Arc::new(Clock),
        };
        let mut user = User {
            input: [0; 16],
            output: IrqSafeSpinLock::new(Vec::new()),
        };
        if !matches!(poll(file.ioctl_user(0x80503d01, 1, &user)), Some(Ok(0)))
            || user.output.lock().len() != 80
        {
            return TestResult::Fail("PTP caps size mismatch");
        }
        user.input[..4].copy_from_slice(&2u32.to_ne_bytes());
        if !matches!(poll(file.ioctl_user(0xc4c03d12, 1, &user)), Some(Ok(0))) {
            return TestResult::Fail("PTP extended offset failed");
        }
        {
            let out = user.output.lock();
            if out.len() != 1216
                || i64::from_ne_bytes(out[32..40].try_into().unwrap()) != 7
                || u32::from_ne_bytes(out[40..44].try_into().unwrap()) != 123
            {
                return TestResult::Fail("PTP clock sample layout wrong");
            }
        }
        user.input[..4].copy_from_slice(&26u32.to_ne_bytes());
        if !matches!(
            poll(file.ioctl_user(0xc4c03d12, 1, &user)),
            Some(Err(FsError::InvalidPath))
        ) {
            return TestResult::Fail("PTP sample count not bounded");
        }
        if !matches!(
            poll(file.ioctl_user(0x80043d01, 1, &user)),
            Some(Err(FsError::Unsupported))
        ) {
            return TestResult::Fail("wrong PTP ioctl size accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("filesystem", smoke_ptp_ioctl_sizes_and_samples);
}

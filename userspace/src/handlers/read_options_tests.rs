//! Actual syscall dispatch of per-invocation read status. Linux read(2),
//! readv(2), pread64/preadv and dup/F_SETFL share an open file description;
//! stream threshold policy must never be copied into a numeric fd or FileOps.
use super::CurrentTtyFile;
use crate::abi_test_support::*;
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use narf_filesystem::{DirOps, FileOps, FileType, FsError, FsFuture, Mode, ReadOptions, Stat};
use narf_lib::sync::IrqSafeSpinLock;

struct OptionsFile {
    seen: IrqSafeSpinLock<Vec<ReadOptions>>,
    blocked: AtomicBool,
    // Deterministically model F_SETFL on a CLONE_FILES peer after fdget but
    // before FileOps::read_with_options. No fd-table lock crosses this callback.
    change: IrqSafeSpinLock<Option<(u32, u32)>>,
}
impl OptionsFile {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            seen: IrqSafeSpinLock::new(Vec::new()),
            blocked: AtomicBool::new(false),
            change: IrqSafeSpinLock::new(None),
        })
    }
}
impl FileOps for OptionsFile {
    fn read<'a>(&'a self, _: u64, _: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::InvalidData) }) // lost adapter/forwarding
    }
    fn read_with_options<'a>(
        &'a self,
        _: u64,
        bytes: &'a mut [u8],
        options: ReadOptions,
    ) -> FsFuture<'a, usize> {
        Box::pin(async move {
            self.seen.lock().push(options);
            if self.blocked.load(Ordering::Acquire) {
                return Err(FsError::WouldBlock);
            }
            bytes.fill(if options.nonblocking { b'N' } else { b'B' });
            Ok(bytes.len())
        })
    }
    fn write<'a>(&'a self, _: u64, _: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::ReadOnly) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o400,
            },
            mtime_cycles: 0,
        }
    }
    fn as_dir(&self) -> Option<Arc<dyn DirOps>> {
        let change = self.change.lock().take();
        if let Some((fd, flags)) = change {
            assert_eq!(set_flags(fd, flags), Some(0));
        }
        None
    }
    fn is_stream(&self) -> bool {
        true
    }
    fn nonblock_read_eagain(&self) -> bool {
        true
    }
}
fn install(file: Arc<dyn FileOps>) -> u32 {
    fd::install(
        FAKE_TASK,
        fd::FdEntry {
            ops: file,
            offset: 0,
            flags: 0,
            status_flags: fd::O_RDONLY,
        },
    )
    .unwrap()
}
fn set_flags(fd: u32, flags: u32) -> Option<i64> {
    call(Syscall::Fcntl.raw(), a2(fd as u64, 4, flags as u64))
}
fn read_variant(kind: u8, fd: u32, bytes: &mut [u8; 64]) -> Option<i64> {
    let iov = [
        (bytes.as_mut_ptr() as u64, 32u64),
        (bytes.as_mut_ptr() as u64 + 32, 32),
    ];
    match kind {
        0 => call(
            Syscall::Read.raw(),
            a2(fd as u64, bytes.as_mut_ptr() as u64, 64),
        ),
        1 => call(Syscall::Readv.raw(), a2(fd as u64, iov.as_ptr() as u64, 2)),
        2 => call(
            Syscall::Pread64.raw(),
            a3(fd as u64, bytes.as_mut_ptr() as u64, 64, 0),
        ),
        3 => call(
            Syscall::Preadv.raw(),
            a3(fd as u64, iov.as_ptr() as u64, 2, 0),
        ),
        4 => call(
            Syscall::Preadv2.raw(),
            a3(fd as u64, iov.as_ptr() as u64, 2, u64::MAX),
        ),
        _ => unreachable!(),
    }
}

fn smoke_abi_read_options_scalar_vector_dup_and_current_tty_forwarding() -> TestResult {
    with_setup(|| {
        for wrapped in [false, true] {
            let source = OptionsFile::new();
            let file: Arc<dyn FileOps> = if wrapped {
                Arc::new(CurrentTtyFile {
                    inner: source.clone(),
                    inode: 0x9123,
                })
            } else {
                source.clone()
            };
            let original = install(file);
            let duplicate = call(Syscall::Dup.raw(), a0(original as u64)).unwrap() as u32;
            for kind in 0..5 {
                for nonblocking in [true, false] {
                    // Set through one descriptor, read through the other.
                    let (setter, reader) = if nonblocking {
                        (duplicate, original)
                    } else {
                        (original, duplicate)
                    };
                    assert_eq!(
                        set_flags(setter, if nonblocking { fd::O_NONBLOCK } else { 0 }),
                        Some(0)
                    );
                    let mut bytes = [0; 64];
                    assert_eq!(read_variant(kind, reader, &mut bytes), Some(64));
                    assert_eq!(bytes, [if nonblocking { b'N' } else { b'B' }; 64]);
                    assert_eq!(
                        source.seen.lock().last(),
                        Some(&ReadOptions { nonblocking })
                    );
                }
            }
            assert_eq!(call(Syscall::Close.raw(), a0(original as u64)), Some(0));
            assert_eq!(set_flags(duplicate, fd::O_NONBLOCK), Some(0));
            assert_eq!(read_variant(1, duplicate, &mut [0; 64]), Some(64));
            assert_eq!(call(Syscall::Close.raw(), a0(duplicate as u64)), Some(0));
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/read_options",
    smoke_abi_read_options_scalar_vector_dup_and_current_tty_forwarding
);

fn smoke_abi_read_options_current_status_after_fd_lookup_and_signal_order() -> TestResult {
    with_setup(|| {
        for kind in [0, 1, 4] {
            let source = OptionsFile::new();
            source.blocked.store(true, Ordering::Release);
            let original = install(source.clone());
            let duplicate = call(Syscall::Dup.raw(), a0(original as u64)).unwrap() as u32;
            let mut bytes = [0x31; 64];
            *source.change.lock() = Some((duplicate, fd::O_NONBLOCK));
            assert_eq!(read_variant(kind, original, &mut bytes), Some(EAGAIN));
            assert_eq!(
                source.seen.lock().last(),
                Some(&ReadOptions { nonblocking: true })
            );
            *source.change.lock() = Some((duplicate, 0));
            super::raise_signal_pending(FAKE_TASK, 10);
            let result = read_variant(kind, original, &mut bytes);
            super::clear_signal_pending(FAKE_TASK, 10);
            assert_eq!(
                result,
                Some(EINTR),
                "blocking retry must observe its pending signal"
            );
            assert_eq!(
                source.seen.lock().last(),
                Some(&ReadOptions { nonblocking: false })
            );
            assert_eq!(bytes, [0x31; 64]);
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/read_options",
    smoke_abi_read_options_current_status_after_fd_lookup_and_signal_order
);

fn smoke_abi_read_options_nonblocking_eagain_and_blocking_interruption() -> TestResult {
    with_setup(|| {
        for kind in [0, 1, 4] {
            let source = OptionsFile::new();
            source.blocked.store(true, Ordering::Release);
            let fd = install(source);
            super::raise_signal_pending(FAKE_TASK, 10);
            let mut bytes = [0x63; 64];
            let blocked = read_variant(kind, fd, &mut bytes);
            assert_eq!(set_flags(fd, fd::O_NONBLOCK), Some(0));
            let nonblocked = read_variant(kind, fd, &mut bytes);
            super::clear_signal_pending(FAKE_TASK, 10);
            assert_eq!(
                blocked,
                Some(EINTR),
                "poll-drive hint must not turn blocking readv into EAGAIN"
            );
            assert_eq!(nonblocked, Some(EAGAIN));
            assert_eq!(bytes, [0x63; 64]);
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/read_options",
    smoke_abi_read_options_nonblocking_eagain_and_blocking_interruption
);

fn smoke_abi_read_options_ordinary_file_default_adapter_unchanged() -> TestResult {
    with_memfs(
        "/read-options",
        "read-options",
        &[("f", &[b'x'; 64])],
        || {
            let file = call_open(c"/read-options/f".as_ptr() as u64, 0).unwrap() as u32;
            for kind in 0..5 {
                for flags in [0, fd::O_NONBLOCK] {
                    assert_eq!(set_flags(file, flags), Some(0));
                    assert_eq!(call(Syscall::Lseek.raw(), a2(file as u64, 0, 0)), Some(0));
                    let mut bytes = [0; 64];
                    assert_eq!(read_variant(kind, file, &mut bytes), Some(64));
                    assert_eq!(bytes, [b'x'; 64]);
                }
            }
            Ok(())
        },
    )
}
kernel_test_in!(
    "syscall_abi/read_options",
    smoke_abi_read_options_ordinary_file_default_adapter_unchanged
);

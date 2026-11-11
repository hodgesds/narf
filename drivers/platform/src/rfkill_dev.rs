// SPDX-License-Identifier: GPL-2.0-or-later
//! `/dev/rfkill` (misc 10:242): the rfkill event and control channel.
//!
//! NetworkManager, wpa_supplicant, `systemd-rfkill` (which saves and
//! restores soft blocks across boots), the `rfkill` tool and desktop
//! airplane-mode toggles all use this node, not sysfs. Semantics follow
//! Linux `net/rfkill/core.c`:
//!
//! - Every open gets its own event queue. It starts with one `ADD` event per
//!   registered radio (`rfkill_fop_open`). Every later register,
//!   unregister and state change appends `ADD`, `DEL` or `CHANGE` to every
//!   open queue.
//! - `read` returns one `struct rfkill_event_ext` (`idx`, `type`, `op`,
//!   `soft`, `hard`, `hard_block_reasons`, 9 bytes), truncated to the
//!   caller's count and to `RFKILL_IOCTL_MAX_SIZE`. It blocks on an empty
//!   queue; `O_NONBLOCK` gets `EAGAIN`.
//! - `write` takes an event of at least 7 bytes. `RFKILL_OP_CHANGE` sets the
//!   soft block of radio `idx` when its type matches (or the type is
//!   `RFKILL_TYPE_ALL`). `RFKILL_OP_CHANGE_ALL` sets it on every radio of
//!   that type. Other ops are `EINVAL`. A hard block is reported but never
//!   cleared from here.
//! - `poll` is always writable and readable while the queue holds events.
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::Poll;

use narf_filesystem::{FileOps, FileType, FsError, FsFuture, Mode, Stat, POLL_IN, POLL_OUT};
use narf_lib::readiness::Readiness;
use narf_lib::sync::IrqSafeSpinLock;

/// `enum rfkill_operation`.
pub const OP_ADD: u8 = 0;
pub const OP_DEL: u8 = 1;
pub const OP_CHANGE: u8 = 2;
pub const OP_CHANGE_ALL: u8 = 3;
/// `RFKILL_TYPE_ALL`.
pub const TYPE_ALL: u8 = 0;
/// `NUM_RFKILL_TYPES`.
const NUM_TYPES: u8 = 9;
/// `sizeof(struct rfkill_event_ext)`.
pub const EVENT_SIZE: usize = 9;
/// `RFKILL_EVENT_SIZE_V1`.
const EVENT_SIZE_V1: usize = 8;
/// `RFKILL_HARD_BLOCK_SIGNAL`.
pub const HARD_BLOCK_SIGNAL: u8 = 1;
/// `RFKILL_IOCTL_NOINPUT` = `_IO('R', 1)`.
const IOCTL_NOINPUT: u32 = 0x5201;
/// `RFKILL_IOCTL_MAX_SIZE` = `_IOW('R', 2, __u32)`.
const IOCTL_MAX_SIZE: u32 = 0x4004_5202;
/// Events a reader may have outstanding; the oldest is dropped beyond it.
const QUEUE_LIMIT: usize = 1024;

/// `struct rfkill_event_ext`, host byte order as Linux copies it.
pub fn encode(idx: u32, rtype: u8, op: u8, soft: bool, hard: bool) -> [u8; EVENT_SIZE] {
    let mut event = [0; EVENT_SIZE];
    event[..4].copy_from_slice(&idx.to_ne_bytes());
    event[4] = rtype;
    event[5] = op;
    event[6] = u8::from(soft);
    event[7] = u8::from(hard);
    event[8] = if hard { HARD_BLOCK_SIGNAL } else { 0 };
    event
}

/// One open of `/dev/rfkill`.
#[derive(Debug)]
pub struct RfkillFile {
    queue: IrqSafeSpinLock<VecDeque<[u8; EVENT_SIZE]>>,
    readiness: Readiness,
    max_size: AtomicUsize,
}

static READERS: IrqSafeSpinLock<Vec<Weak<RfkillFile>>> = IrqSafeSpinLock::new(Vec::new());

impl RfkillFile {
    /// A new reader whose queue starts with `initial` (the `ADD` events of
    /// the radios registered now), subscribed to every later event.
    /// The caller holds the radio registry lock, so no event is lost or
    /// doubled between the snapshot and the subscription.
    pub(crate) fn open_with(initial: Vec<[u8; EVENT_SIZE]>) -> Arc<Self> {
        let file = Arc::new(Self {
            readiness: Readiness::new(if initial.is_empty() {
                POLL_OUT
            } else {
                POLL_IN | POLL_OUT
            }),
            queue: IrqSafeSpinLock::new(initial.into_iter().collect()),
            max_size: AtomicUsize::new(EVENT_SIZE),
        });
        let mut readers = READERS.lock();
        readers.retain(|reader| reader.strong_count() > 0);
        readers.push(Arc::downgrade(&file));
        file
    }

    fn push(&self, event: [u8; EVENT_SIZE]) {
        {
            let mut queue = self.queue.lock();
            if queue.len() >= QUEUE_LIMIT {
                queue.pop_front();
            }
            queue.push_back(event);
        }
        self.readiness.set(POLL_IN, 0);
    }

    fn pop(&self, buf: &mut [u8]) -> Option<usize> {
        let mut queue = self.queue.lock();
        let event = queue.pop_front()?;
        if queue.is_empty() {
            self.readiness.set(0, POLL_IN);
        }
        let size = buf
            .len()
            .min(EVENT_SIZE)
            .min(self.max_size.load(Ordering::Relaxed));
        buf[..size].copy_from_slice(&event[..size]);
        Some(size)
    }
}

/// Append `event` to every open reader (`rfkill_send_events`).
/// Called with the radio registry lock held, after the state changed.
pub(crate) fn broadcast(event: [u8; EVENT_SIZE]) {
    let readers: Vec<Arc<RfkillFile>> = {
        let mut readers = READERS.lock();
        readers.retain(|reader| reader.strong_count() > 0);
        readers.iter().filter_map(Weak::upgrade).collect()
    };
    for reader in readers {
        reader.push(event);
    }
}

/// A parsed write: `(idx, type, op, soft)`.
pub(crate) fn parse_write(buf: &[u8], max_size: usize) -> Result<(u32, u8, u8, bool), FsError> {
    if buf.len() < EVENT_SIZE_V1 - 1 {
        return Err(FsError::InvalidData);
    }
    let size = buf.len().min(EVENT_SIZE).min(max_size);
    let mut event = [0u8; EVENT_SIZE];
    event[..size].copy_from_slice(&buf[..size]);
    let idx = u32::from_ne_bytes(event[..4].try_into().unwrap());
    let (rtype, op, soft) = (event[4], event[5], event[6] != 0);
    if rtype >= NUM_TYPES || !matches!(op, OP_CHANGE | OP_CHANGE_ALL) {
        return Err(FsError::InvalidData);
    }
    Ok((idx, rtype, op, soft))
}

impl FileOps for RfkillFile {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(core::future::poll_fn(move |cx| {
            if let Some(size) = self.pop(buf) {
                return Poll::Ready(Ok(size));
            }
            // Register, then re-check under the cell: an event pushed in
            // between either is seen here or wakes this waker.
            let id = self as *const Self as u64;
            match self.readiness.arm(id, POLL_IN, cx.waker()) {
                Poll::Ready(_) => match self.pop(buf) {
                    Some(size) => Poll::Ready(Ok(size)),
                    None => Poll::Pending,
                },
                Poll::Pending => Poll::Pending,
            }
        }))
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let (idx, rtype, op, soft) = parse_write(buf, self.max_size.load(Ordering::Relaxed))?;
            crate::rfkill::apply_user_change(idx, rtype, op == OP_CHANGE_ALL, soft);
            Ok(buf.len())
        })
    }

    fn nonblock_read_eagain(&self) -> bool {
        true
    }

    fn readiness(&self) -> Option<&Readiness> {
        Some(&self.readiness)
    }

    fn poll_readiness(&self) -> u32 {
        self.readiness.mask()
    }

    fn stat(&self) -> Stat {
        stat()
    }

    fn rdev(&self) -> u64 {
        narf_filesystem::devfs::linux_makedev(10, 242)
    }

    fn ino(&self) -> u64 {
        0xd001_0000_0000_0000 | self.rdev().wrapping_add(1)
    }

    fn ioctl_user<'a>(
        &'a self,
        cmd: u32,
        arg: u64,
        context: &'a dyn narf_filesystem::IoctlContext,
    ) -> FsFuture<'a, u64> {
        Box::pin(async move {
            match cmd {
                // rfkill-input key handling is not in this kernel; the
                // request to disable it needs nothing.
                IOCTL_NOINPUT => Ok(0),
                IOCTL_MAX_SIZE => {
                    let mut size = [0u8; 4];
                    context.read(arg, &mut size)?;
                    let size = u32::from_ne_bytes(size) as usize;
                    if size < EVENT_SIZE_V1 - 1 {
                        return Err(FsError::InvalidData);
                    }
                    self.max_size.store(size, Ordering::Relaxed);
                    Ok(0)
                }
                _ => Err(FsError::Unsupported),
            }
        })
    }
}

fn stat() -> Stat {
    Stat {
        size: 0,
        blocks: 0,
        mode: Mode {
            file_type: FileType::Special,
            perms: 0o644,
        },
        mtime_cycles: 0,
    }
}

/// The stable `/dev/rfkill` inode; each `open(2)` gets its own reader.
#[derive(Debug)]
struct RfkillNode;

impl FileOps for RfkillNode {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::BadFd) })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::BadFd) })
    }
    fn stat(&self) -> Stat {
        stat()
    }
    fn rdev(&self) -> u64 {
        narf_filesystem::devfs::linux_makedev(10, 242)
    }
    fn ino(&self) -> u64 {
        0xd001_0000_0000_0000 | self.rdev().wrapping_add(1)
    }
    fn open_instance(&self) -> Option<Arc<dyn FileOps>> {
        Some(crate::rfkill::open_reader() as Arc<dyn FileOps>)
    }
}

/// Register the `/dev/rfkill` node.
pub fn register() {
    narf_filesystem::devfs::register_provider(narf_filesystem::devfs::DeviceProvider {
        name: "rfkill",
        lookup: |name| (name == "rfkill").then(|| Arc::new(RfkillNode) as Arc<dyn FileOps>),
        lookup_dir: |_| None,
        enumerate: || alloc::vec![(alloc::string::String::from("rfkill"), FileType::Special)],
    });
}

//! Opt-in, capability-gated passive GuC log snapshots. The raw file uses
//! NARFGLOG framing; a separate descriptor exports source-qualified LFD1.0.
//! Neither is a Xe DRM ioctl. Payloads are opaque firmware diagnostics and
//! can disclose GPU addresses and instruction state.
//!
//! MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad:
//! xe_guc_log.{c,h}::{xe_guc_log_snapshot_capture,GUC_LOG_SIZE},
//! abi/guc_log_abi.h and xe_guc_fwif.h. Passive copying does not consume logs,
//! enable verbosity/notifications, flush firmware, or claim an atomic image.

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::sync::atomic::{fence, AtomicU64, AtomicU8, Ordering};
use narf_filesystem::{FileOps, FileType, FsError, FsFuture, Mode, Stat};
use narf_lib::mutex::Mutex;

#[path = "intel_gpu_guc_lfd.rs"]
mod lfd;

#[path = "intel_gpu_guc_stream.rs"]
pub(crate) mod stream;
pub use stream::StreamSession;

use crate::{intel_gpu_gt::GtPlatform, intel_gpu_rcs::GpuBacking, intel_gpu_user::UserBackend};

/// Fixed allocation advertised to the admitted GuC firmware: state page,
/// event data, crash dump, state capture. Never derive copy sizes from DMA.
pub const LOG_BYTES: usize = 0x115000;
pub const HEADER_BYTES: usize = 112;
pub const SNAPSHOT_BYTES: usize = HEADER_BYTES + LOG_BYTES;
const MAX_CARDS: usize = 64;
const CAP_SYSLOG: u32 = 34;
const OPT_IN: &str = "narf.intel.guc_log";
static RETAINED: [AtomicU8; MAX_CARDS] = [const { AtomicU8::new(0) }; MAX_CARDS];
static NEXT_INCARNATION: AtomicU64 = AtomicU64::new(1);

pub(crate) fn next_incarnation() -> u64 {
    NEXT_INCARNATION
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            value.checked_add(1)
        })
        .expect("GuC firmware incarnation exhausted")
}

fn opted_in(command_line: narf_boot::args::KernelCmdline<'_>) -> bool {
    // Only a single unambiguous explicit value enables opaque diagnostics.
    let mut values = command_line
        .tokens()
        .filter_map(|token| token.strip_prefix("narf.intel.guc_log="));
    values.next() == Some("1") && values.next().is_none() && !command_line.has_flag(OPT_IN)
}
fn enabled() -> bool {
    opted_in(narf_boot::args())
}
fn capable() -> bool {
    narf_filesystem::caller_capable(CAP_SYSLOG)
}

#[derive(Copy, Clone)]
struct Gate {
    enabled: fn() -> bool,
    capable: fn() -> bool,
}
impl Gate {
    const PHYSICAL: Self = Self { enabled, capable };
    fn check(self) -> Result<(), FsError> {
        if !(self.enabled)() || !(self.capable)() {
            Err(FsError::OperationNotPermitted)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
struct Permit {
    index: u32,
}
impl Permit {
    fn take(index: u32) -> Result<Self, FsError> {
        let slot = RETAINED.get(index as usize).ok_or(FsError::NoDevice)?;
        slot.fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            (count < 2).then_some(count + 1)
        })
        .map_err(|_| FsError::Busy)?;
        Ok(Self { index })
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        RETAINED[self.index as usize].fetch_sub(1, Ordering::AcqRel);
    }
}

/// Preallocated copy destination with one of two retained-snapshot permits.
/// Only the descriptor boundary creates these; the GT owner receives it by
/// value and cannot accidentally return live BO references to the caller.
pub struct CaptureBuffer {
    bytes: Vec<u8>,
    permit: Permit,
}
impl core::fmt::Debug for CaptureBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GuCLogCaptureBuffer")
            .field("card", &self.index())
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

/// Identity of the actual firmware upload, separate from a user epoch which
/// may continue through an idle runtime suspend/resume.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub epoch: u64,
    pub incarnation: u64,
    pub now_ns: u64,
    pub platform: GtPlatform,
    pub firmware_version: (u8, u8, u8),
    pub firmware_digest: [u8; 32],
}

impl CaptureBuffer {
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn reserve_for_test(index: u32) -> Result<Self, FsError> {
        Self::reserve(index)
    }
    fn reserve(index: u32) -> Result<Self, FsError> {
        let permit = Permit::take(index)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(LOG_BYTES)
            .map_err(|_| FsError::OutOfMemory)?;
        bytes.resize(LOG_BYTES, 0);
        Ok(Self { bytes, permit })
    }
    pub fn index(&self) -> u32 {
        self.permit.index
    }

    /// The retained GT/reset owner supplies its exact log backing and checks
    /// current PCI authority, D0 and wake in `current_access_ok` before any
    /// backing read and each 4KiB chunk. A failed proof discards the partial
    /// destination. No host/BO pointers are added to the framing, and no
    /// firmware-provided length controls a read or output extent. The raw
    /// firmware payload itself can contain GPU addresses and instruction state.
    /// Live incoherent backing is always refused; a one-shot
    /// cache clean is not a proof for concurrent firmware writes.
    pub(crate) fn capture(
        mut self,
        backing: &impl GpuBacking,
        identity: Identity,
        mut current_access_ok: impl FnMut() -> bool,
    ) -> Result<Snapshot, FsError> {
        let profile = identity.platform.guc().ok_or(FsError::Unsupported)?;
        if identity.epoch == 0
            || identity.incarnation == 0
            || identity.firmware_version < profile.minimum_version
        {
            return Err(FsError::NoDevice);
        }
        if !backing.coherent_for_device() {
            return Err(FsError::Unsupported);
        }
        if u64::from(backing.size_pages()) * 4096 != LOG_BYTES as u64 {
            return Err(FsError::InvalidData);
        }
        if !current_access_ok() {
            return Err(FsError::NoDevice);
        }
        fence(Ordering::Acquire);
        let before = read_states(backing);
        for (page, destination) in self.bytes.chunks_exact_mut(4096).enumerate() {
            if !current_access_ok() {
                return Err(FsError::NoDevice);
            }
            fence(Ordering::Acquire);
            for (word, output) in destination.chunks_exact_mut(4).enumerate() {
                output.copy_from_slice(
                    &backing
                        .read32((page * 4096 + word * 4) as u64)
                        .to_le_bytes(),
                );
            }
        }
        if !current_access_ok() {
            return Err(FsError::NoDevice);
        }
        fence(Ordering::Acquire);
        let after = read_states(backing);
        let mut valid = 0;
        let mut changed = 0;
        for index in 0..3 {
            let copied = core::array::from_fn(|word| {
                let offset = index * 36 + word * 4;
                u32::from_le_bytes(
                    self.bytes[offset..offset + 4]
                        .try_into()
                        .expect("bounded log header"),
                )
            });
            if valid_state(index, &copied) {
                valid |= 1 << index;
            }
            if before[index] != after[index] || copied != before[index] || copied != after[index] {
                changed |= 1 << index;
            }
        }
        let mut header = [0; HEADER_BYTES];
        header[..8].copy_from_slice(b"NARFGLOG");
        for (offset, value) in [
            (8, 1),
            (12, HEADER_BYTES as u32),
            (16, LOG_BYTES as u32),
            (20, self.index()),
            (24, platform_tag(identity.platform)),
            (28, 3),
            (56, u32::from(identity.firmware_version.0)),
            (60, u32::from(identity.firmware_version.1)),
            (64, u32::from(identity.firmware_version.2)),
            (68, valid),
            (72, changed),
            (76, 1 << 6),
        ] {
            header[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [
            (32, identity.epoch),
            (40, identity.incarnation),
            (48, identity.now_ns),
        ] {
            header[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        header[80..112].copy_from_slice(&identity.firmware_digest);
        Ok(Snapshot {
            header,
            buffer: self,
        })
    }
}

// The real packed ABI has nine dwords (36 bytes), not the stale diagram's
// 32-byte labels. Marker/version fields are opaque; validation is informational
// and never drives a memory access. Unknown/corrupt logs remain useful raw data.
fn read_states(backing: &impl GpuBacking) -> [[u32; 9]; 3] {
    core::array::from_fn(|index| {
        core::array::from_fn(|word| backing.read32((index * 36 + word * 4) as u64))
    })
}
fn valid_state(index: usize, words: &[u32; 9]) -> bool {
    let (markers, size) = match index {
        0 => ([0xcabba9e6, 0xdeadfeed], 0x10000),
        1 => ([0xcabba9e6, 0x8086dead], 0x4000),
        _ => ([0xcabba9f7, 0xbeeffeed], 0x100000),
    };
    words[..2] == markers
        && words[4] == size
        && [words[2], words[3], words[5], words[6]]
            .into_iter()
            .all(|offset| offset <= size)
}
pub(crate) fn platform_tag(platform: GtPlatform) -> u32 {
    match platform {
        GtPlatform::Alchemist => 1,
        GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake) => 2,
        GtPlatform::Battlemage => 3,
        _ => 0,
    }
}

/// Immutable complete owned copy. Its permit is retained through descriptor
/// duplication, partial reads, reset and runtime suspend until the last owner
/// drops. Raw payload bytes are never interpreted as addresses by the kernel.
pub struct Snapshot {
    header: [u8; HEADER_BYTES],
    buffer: CaptureBuffer,
}
impl core::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GuCLogSnapshot")
            .field("card", &self.buffer.index())
            .field("bytes", &SNAPSHOT_BYTES)
            .finish()
    }
}
impl Snapshot {
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn read_for_test(&self, offset: u64, output: &mut [u8]) -> usize {
        self.read(offset, output)
    }
    fn read(&self, offset: u64, output: &mut [u8]) -> usize {
        let Ok(start) = usize::try_from(offset) else {
            return 0;
        };
        if start >= SNAPSHOT_BYTES {
            return 0;
        }
        let length = output.len().min(SNAPSHOT_BYTES - start);
        let header_length = HEADER_BYTES.saturating_sub(start).min(length);
        output[..header_length].copy_from_slice(
            &self.header[start.min(HEADER_BYTES)..start.min(HEADER_BYTES) + header_length],
        );
        if header_length < length {
            let payload_start = start.saturating_sub(HEADER_BYTES);
            output[header_length..length].copy_from_slice(
                &self.buffer.bytes[payload_start..payload_start + length - header_length],
            );
        }
        length
    }
}

#[derive(Copy, Clone, Debug)]
enum Format {
    Raw,
    Lfd,
}
impl Format {
    fn limit(self) -> usize {
        match self {
            Self::Raw => SNAPSHOT_BYTES,
            Self::Lfd => lfd::MAX_BYTES,
        }
    }
    fn initial_size(self) -> u64 {
        match self {
            Self::Raw => SNAPSHOT_BYTES as u64,
            Self::Lfd => 0, // seq-file style: exact size is known after capture.
        }
    }
}
enum Captured {
    Raw(Snapshot),
    Lfd(lfd::Export),
}
impl Captured {
    fn len(&self) -> usize {
        match self {
            Self::Raw(_) => SNAPSHOT_BYTES,
            Self::Lfd(export) => export.len(),
        }
    }
    fn read(&self, offset: u64, output: &mut [u8]) -> usize {
        match self {
            Self::Raw(snapshot) => snapshot.read(offset, output),
            Self::Lfd(export) => export.read(offset, output),
        }
    }
}
struct Node {
    index: u32,
    backend: Arc<dyn UserBackend>,
    gate: Gate,
    format: Format,
}
impl core::fmt::Debug for Node {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GuCLogNode")
            .field("card", &self.index)
            .finish()
    }
}
struct File {
    index: u32,
    backend: Arc<dyn UserBackend>,
    gate: Gate,
    format: Format,
    size: AtomicU64,
    snapshot: Mutex<Option<Captured>>,
}
impl core::fmt::Debug for File {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GuCLogFile")
            .field("card", &self.index)
            .finish()
    }
}
fn stat(size: u64) -> Stat {
    Stat {
        size,
        blocks: 0,
        mode: Mode {
            file_type: FileType::File,
            perms: 0o444,
        },
        mtime_cycles: 0,
    }
}
impl FileOps for Node {
    fn open_instance_checked(&self, write: bool) -> Result<Option<Arc<dyn FileOps>>, FsError> {
        self.gate.check()?;
        if write {
            return Err(FsError::ReadOnly);
        }
        Ok(Some(Arc::new(File {
            index: self.index,
            backend: self.backend.clone(),
            gate: self.gate,
            format: self.format,
            size: AtomicU64::new(self.format.initial_size()),
            snapshot: Mutex::new(None),
        })))
    }
    fn read<'a>(&'a self, _offset: u64, _output: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::OperationNotPermitted) })
    }
    fn write<'a>(&'a self, _offset: u64, _input: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::ReadOnly) })
    }
    fn stat(&self) -> Stat {
        stat(self.format.initial_size())
    }
}
impl FileOps for File {
    fn read<'a>(&'a self, offset: u64, output: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            self.gate.check()?;
            if output.is_empty() || offset >= self.format.limit() as u64 {
                return Ok(0);
            }
            let mut snapshot = self.snapshot.lock().await;
            self.gate.check()?;
            if snapshot.is_none() {
                let buffer = CaptureBuffer::reserve(self.index)?;
                let captured = self.backend.guc_log_snapshot(buffer).await?;
                if captured.buffer.index() != self.index {
                    return Err(FsError::NoDevice);
                }
                // Revocation while awaiting the GT never releases raw bytes.
                self.gate.check()?;
                let captured = match self.format {
                    Format::Raw => Captured::Raw(captured),
                    Format::Lfd => Captured::Lfd(lfd::Export::new(captured)?),
                };
                self.size.store(captured.len() as u64, Ordering::Release);
                *snapshot = Some(captured);
            }
            self.gate.check()?;
            Ok(snapshot
                .as_ref()
                .expect("retained snapshot")
                .read(offset, output))
        })
    }
    fn write<'a>(&'a self, _offset: u64, _input: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::ReadOnly) })
    }
    fn stat(&self) -> Stat {
        // Variable LFD size reveals event/crash presence; a revoked
        // descriptor must not retain that metadata disclosure either.
        let size = if matches!(self.format, Format::Lfd) && self.gate.check().is_err() {
            0
        } else {
            self.size.load(Ordering::Acquire)
        };
        stat(size)
    }
}

pub(crate) fn visible(index: u32) -> bool {
    enabled()
        && index < MAX_CARDS as u32
        && crate::drm_registry::card(index)
            .is_some_and(|card| card.vendor_id() == 0x8086 && card.intel_user_backend().is_some())
}
pub(crate) fn lookup(name: &str) -> Option<Arc<dyn FileOps>> {
    let (prefix, format) = if name.starts_with("guc-log-lfd") {
        ("guc-log-lfd", Format::Lfd)
    } else {
        ("guc-log", Format::Raw)
    };
    let index = name.strip_prefix(prefix)?.parse::<u32>().ok()?;
    if name != alloc::format!("{prefix}{index}") || !visible(index) {
        return None;
    }
    let backend = crate::drm_registry::card(index)?.intel_user_backend()?;
    Some(Arc::new(Node {
        index,
        backend,
        gate: Gate::PHYSICAL,
        format,
    }))
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_guc_log_tests.rs"]
mod tests;

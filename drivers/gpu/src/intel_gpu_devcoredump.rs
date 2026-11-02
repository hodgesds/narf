//! Protected first-failure GuC diagnostic bundles, captured before GT teardown.
//!
//! MIT Linux b90c984d xe_devcoredump.c::{devcoredump_snapshot,
//! xe_devcoredump_snapshot_free}, xe_guc_ct.c::xe_guc_ct_snapshot_capture and
//! xe_guc_log.c::xe_guc_log_snapshot_capture. This bounded NARF format is a
//! partial device coredump: no user BO, VM or LRC image is captured. Opaque
//! firmware/CT bytes can contain addresses and commands and require CAP_SYSLOG.

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::sync::atomic::{fence, AtomicU64, AtomicU8, Ordering};
use narf_filesystem::{FileOps, FileType, FsError, FsFuture, Mode, Stat};
use narf_lib::sync::IrqSafeSpinLock;

use super::{Report, Snapshot, MAX_CARDS, MAX_REPORT_BYTES};
use crate::{intel_gpu_guc_log::Identity, intel_gpu_rcs::GpuBacking};

pub(crate) const HEADER_BYTES: usize = 256;
pub(crate) const LOG_BYTES: usize = crate::intel_gpu_guc_log::LOG_BYTES;
pub(crate) const CT_BYTES: usize = 6 * 4096;
const REPORT_OFFSET: usize = HEADER_BYTES;
const LOG_OFFSET: usize = REPORT_OFFSET + MAX_REPORT_BYTES;
const CT_OFFSET: usize = LOG_OFFSET + LOG_BYTES;
pub(crate) const DUMP_BYTES: usize = CT_OFFSET + CT_BYTES;
const CAP_SYSLOG: u32 = 34;
const CAP_SYS_ADMIN: u32 = 21;
static RETAINED: [AtomicU8; MAX_CARDS] = [const { AtomicU8::new(0) }; MAX_CARDS];
static GENERATIONS: [AtomicU64; MAX_CARDS] = [const { AtomicU64::new(0) }; MAX_CARDS];

fn opted_in(args: narf_boot::args::KernelCmdline<'_>) -> bool {
    let mut values = args
        .tokens()
        .filter_map(|token| token.strip_prefix("narf.intel.devcoredump="));
    values.next() == Some("1")
        && values.next().is_none()
        && !args.has_flag("narf.intel.devcoredump")
}
pub(crate) fn enabled() -> bool {
    opted_in(narf_boot::args())
}
fn capable() -> bool {
    narf_filesystem::caller_capable(CAP_SYSLOG)
}
fn admin() -> bool {
    narf_filesystem::caller_capable(CAP_SYS_ADMIN)
}
#[derive(Copy, Clone)]
struct Gate {
    enabled: fn() -> bool,
    capable: fn() -> bool,
    admin: fn() -> bool,
}
impl Gate {
    const PHYSICAL: Self = Self {
        enabled,
        capable,
        admin,
    };
    fn check(self) -> Result<(), FsError> {
        if !(self.enabled)() || !(self.capable)() {
            Err(FsError::OperationNotPermitted)
        } else {
            Ok(())
        }
    }
    fn check_admin(self) -> Result<(), FsError> {
        self.check()?;
        if !(self.admin)() {
            Err(FsError::OperationNotPermitted)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
struct Permit(u32);
impl Permit {
    fn take(index: u32) -> Result<Self, FsError> {
        RETAINED
            .get(index as usize)
            .ok_or(FsError::NoDevice)?
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < 2).then_some(count + 1)
            })
            .map_err(|_| FsError::Busy)?;
        Ok(Self(index))
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        RETAINED[self.0 as usize].fetch_sub(1, Ordering::AcqRel);
    }
}

struct Dump {
    bytes: Vec<u8>,
    generation: u64,
    permit: Permit,
}
impl core::fmt::Debug for Dump {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IntelCoredump")
            .field("card", &self.permit.0)
            .field("generation", &self.generation)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}
/// Allocated in normal task context, before polling hardware for failures.
/// Capture/publish only mutate this unique preallocated Arc and fixed bytes.
#[derive(Debug)]
pub(crate) struct Armed(Arc<Dump>);
impl Armed {
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn reserve_for_test(index: u32) -> Result<Self, FsError> {
        Self::reserve(index)
    }
    fn reserve(index: u32) -> Result<Self, FsError> {
        let permit = Permit::take(index)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(DUMP_BYTES)
            .map_err(|_| FsError::OutOfMemory)?;
        bytes.resize(DUMP_BYTES, 0);
        // Reserve identity in normal context too. Cancelled preparation may
        // leave gaps; no identity can wrap or name a later replacement.
        let generation = GENERATIONS[index as usize]
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| FsError::Busy)?
            + 1;
        Ok(Self(Arc::new(Dump {
            bytes,
            generation,
            permit,
        })))
    }

    pub(crate) fn capture(
        mut self,
        mut report: Report,
        identity: Option<Identity>,
        log: Option<&impl GpuBacking>,
        ct: Option<&impl GpuBacking>,
        mut access: impl FnMut() -> bool,
    ) {
        let dump = Arc::get_mut(&mut self.0).expect("unpublished crash destination");
        report.generation = dump.generation;
        let bytes = &mut dump.bytes;
        let mut sections = 1u32;
        let report_len = Snapshot {
            report,
            suppressed: 0,
        }
        .text_into(&mut bytes[REPORT_OFFSET..LOG_OFFSET]);
        let mut denied = false;
        let mut checked_access = || {
            if denied {
                return false;
            }
            denied = !access();
            !denied
        };
        if let Some(identity) = identity.filter(|identity| {
            identity.incarnation != 0
                && identity.platform == report.capture.platform
                && identity
                    .platform
                    .guc()
                    .is_some_and(|profile| identity.firmware_version >= profile.minimum_version)
        }) {
            put64(bytes, 48, identity.now_ns);
            put64(bytes, 56, identity.incarnation);
            put32(
                bytes,
                68,
                u32::from(identity.firmware_version.0)
                    | u32::from(identity.firmware_version.1) << 8
                    | u32::from(identity.firmware_version.2) << 16,
            );
            bytes[80..112].copy_from_slice(&identity.firmware_digest);
            if log.is_some_and(|backing| {
                copy_backing(
                    backing,
                    &mut bytes[LOG_OFFSET..CT_OFFSET],
                    &mut checked_access,
                )
            }) {
                sections |= 2;
            }
            if ct.is_some_and(|backing| {
                copy_backing(backing, &mut bytes[CT_OFFSET..], &mut checked_access)
            }) {
                sections |= 4;
            }
        }
        bytes[..8].copy_from_slice(b"NARFCDMP");
        for (offset, value) in [
            (8, 1),
            (12, HEADER_BYTES as u32),
            (16, DUMP_BYTES as u32),
            (20, dump.permit.0),
            (
                64,
                crate::intel_gpu_guc_log::platform_tag(report.capture.platform),
            ),
            (72, sections),
            (112, REPORT_OFFSET as u32),
            (116, report_len as u32),
            (120, LOG_OFFSET as u32),
            (124, LOG_BYTES as u32),
            (128, CT_OFFSET as u32),
            (132, CT_BYTES as u32),
            // Sequential passive copy, preallocated, no device-freeze proof.
            (136, 7),
        ] {
            put32(bytes, offset, value);
        }
        put64(bytes, 32, report.capture.epoch);
        put64(bytes, 40, report.capture.now_ns);
        put64(bytes, 24, dump.generation);
        publish(self.0);
    }
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
/// A live sequential copy requires coherent backing, exact host-owned extent,
/// and renewed D0/capability/wake proof for every fixed 4KiB chunk. Descriptor
/// pointers, lengths and cursor values are opaque bytes, never copy bounds.
fn copy_backing(
    backing: &impl GpuBacking,
    output: &mut [u8],
    access: &mut impl FnMut() -> bool,
) -> bool {
    if !backing.coherent_for_device()
        || u64::from(backing.size_pages()) * 4096 != output.len() as u64
        || !access()
    {
        return false;
    }
    for (page, destination) in output.chunks_exact_mut(4096).enumerate() {
        if !access() {
            output.fill(0);
            return false;
        }
        fence(Ordering::Acquire);
        for (word, bytes) in destination.chunks_exact_mut(4).enumerate() {
            bytes.copy_from_slice(
                &backing
                    .read32((page * 4096 + word * 4) as u64)
                    .to_le_bytes(),
            );
        }
    }
    if !access() {
        output.fill(0);
        return false;
    }
    fence(Ordering::Acquire);
    true
}

struct Slot {
    generation: u64,
    dump: Option<Arc<Dump>>,
}
static DUMPS: IrqSafeSpinLock<[Slot; MAX_CARDS]> = IrqSafeSpinLock::new(
    [const {
        Slot {
            generation: 0,
            dump: None,
        }
    }; MAX_CARDS],
);

fn publish(dump: Arc<Dump>) {
    let index = dump.permit.0 as usize;
    let mut slots = DUMPS.lock();
    let slot = &mut slots[index];
    if slot.dump.is_some() || dump.generation <= slot.generation {
        return;
    }
    slot.generation = dump.generation;
    slot.dump = Some(dump);
}
fn snapshot(index: u32) -> Option<Arc<Dump>> {
    DUMPS.lock().get(index as usize)?.dump.clone()
}
fn clear(index: u32, generation: u64) -> bool {
    let removed = {
        let mut slots = DUMPS.lock();
        let Some(slot) = slots.get_mut(index as usize) else {
            return false;
        };
        if slot.generation != generation || slot.dump.is_none() {
            return false;
        }
        slot.dump.take()
    };
    // Large buffer destruction and final permit release happen outside IRQ lock.
    drop(removed);
    true
}

#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn take_for_test(index: u32) -> Vec<u8> {
    let dump = snapshot(index).expect("captured crash bundle");
    assert!(clear(index, dump.generation));
    dump.bytes.clone()
}

/// Replenish only in normal context. Allocation failure/retained old readers
/// affect optional diagnostics alone and never change recovery behavior.
pub(crate) fn arm(index: u32) -> Option<Armed> {
    if !enabled() || snapshot(index).is_some() {
        return None;
    }
    Armed::reserve(index).ok()
}

struct Node {
    index: u32,
    gate: Gate,
}
impl core::fmt::Debug for Node {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("IntelCoredumpNode")
            .field(&self.index)
            .finish()
    }
}
struct File {
    dump: Arc<Dump>,
    gate: Gate,
    writable: bool,
}
impl core::fmt::Debug for File {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IntelCoredumpFile")
            .field("card", &self.dump.permit.0)
            .field("generation", &self.dump.generation)
            .finish()
    }
}
fn stat(size: u64) -> Stat {
    Stat {
        size,
        blocks: 0,
        mode: Mode {
            file_type: FileType::File,
            perms: 0o600,
        },
        mtime_cycles: 0,
    }
}
impl FileOps for Node {
    fn open_instance_checked(&self, write: bool) -> Result<Option<Arc<dyn FileOps>>, FsError> {
        self.gate.check()?;
        if write {
            self.gate.check_admin()?;
        }
        let dump = snapshot(self.index).ok_or(FsError::WouldBlock)?;
        Ok(Some(Arc::new(File {
            dump,
            gate: self.gate,
            writable: write,
        })))
    }
    fn read<'a>(&'a self, _offset: u64, _output: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::OperationNotPermitted) })
    }
    fn write<'a>(&'a self, _offset: u64, _input: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::OperationNotPermitted) })
    }
    fn stat(&self) -> Stat {
        stat(0)
    }
}
impl FileOps for File {
    fn read<'a>(&'a self, offset: u64, output: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            self.gate.check()?;
            let Some(bytes) = usize::try_from(offset)
                .ok()
                .and_then(|offset| self.dump.bytes.get(offset..))
            else {
                return Ok(0);
            };
            let count = bytes.len().min(output.len());
            output[..count].copy_from_slice(&bytes[..count]);
            Ok(count)
        })
    }
    fn write<'a>(&'a self, offset: u64, input: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            self.gate.check_admin()?;
            if !self.writable {
                return Err(FsError::ReadOnly);
            }
            if offset != 0 || input != b"clear\n" {
                return Err(FsError::InvalidData);
            }
            if !clear(self.dump.permit.0, self.dump.generation) {
                return Err(FsError::Busy);
            }
            Ok(input.len())
        })
    }
    fn stat(&self) -> Stat {
        stat(if self.gate.check().is_ok() {
            DUMP_BYTES as u64
        } else {
            0
        })
    }
}
pub(crate) fn visible(index: u32) -> bool {
    enabled()
        && index < MAX_CARDS as u32
        && crate::drm_registry::card(index)
            .is_some_and(|card| card.vendor_id() == 0x8086 && card.intel_user_backend().is_some())
}
pub(crate) fn lookup(name: &str) -> Option<Arc<dyn FileOps>> {
    let index = name.strip_prefix("devcoredump")?.parse::<u32>().ok()?;
    if name != alloc::format!("devcoredump{index}") || !visible(index) {
        return None;
    }
    Some(Arc::new(Node {
        index,
        gate: Gate::PHYSICAL,
    }))
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_devcoredump_tests.rs"]
mod tests;

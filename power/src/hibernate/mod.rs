//! Hibernation (S4): Linux's `kernel/power/hibernate.c`. The plan of work
//! is `power/research/s4-hibernation-plan.md`. The key custody, the sealed
//! image format and the resume pipeline live in [`crate::suspend_service`].
//!
//! [`hibernate`] is Linux's `hibernate()`:
//! 1. Prepare the image file.
//! 2. Freeze the tasks; prepare the async system PM bracket for S4; freeze
//!    the kernel work.
//! 3. Preallocate the snapshot; run the devices' freeze callbacks.
//! 4. With interrupts off, capture the CPU state and take the snapshot.
//! 5. Thaw the devices to write the image, sealed under a TPM-enrolled
//!    slot.
//! 6. Run the devices' poweroff callbacks and power down.
//! The restored image comes back through step 4. It runs the restore
//! callbacks and thaws everything, and its caller sees `Ok(())`.
//!
//! [`software_resume`] is Linux's `software_resume`, a late initcall here
//! too, through the normal block and TPM drivers. It follows
//! `narf.resume=<device> narf.resume_offset=<block>` to the image and
//! verifies it whole. It then refuses a changed memory map, stages the
//! pages in frames the image does not use, quiesces the devices and jumps.
//! A refused or failed image boots on normally.
//!
//! Until secondary CPUs can be taken down and brought back (lane 4), both
//! refuse to run while more than one CPU is online.

pub mod arch;
pub mod image_file;
pub mod payload;
pub mod restore;
pub mod snapshot;

use alloc::string::String;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_capabilities::{Cap, Invoke, NoopOp};

use crate::device_pm;
use crate::freezer::{self, FreezeError};
use crate::suspend::{self, SuspendPhase};
use crate::suspend_service::{
    attempt_resume, BlockStore, ConsolePrompt, HwKeyEntropy, ImageStore, KeyCustodyAnchor,
    PolicyLevel, RecordedPolicy, ResumeRefusal, ServiceError, SuspendService, TpmAnchor,
};
use crate::system_pm::{self, SystemSleepState};
use crate::Power;

use self::arch::{ArchError, ArchRecord, Captured};
use self::image_file::{ExtentStore, ImageFileError, Locator, BLOCK};
use self::payload::{PayloadHeader, PayloadSource};
use self::restore::RestoreError;
use self::snapshot::SnapshotError;

/// The image file when `narf.hibernate_file=` names none.
pub const DEFAULT_IMAGE_PATH: &str = "/hibernate.img";

/// Room in the image file beyond the payload: the sealed header and
/// manifest, the hook region, and what the system allocates before the
/// snapshot.
const IMAGE_SLACK: u64 = 64 << 20;

/// The image file's path: `narf.hibernate_file=`, else [`DEFAULT_IMAGE_PATH`].
pub fn image_path() -> String {
    String::from(
        narf_boot::args()
            .value("narf.hibernate_file")
            .unwrap_or(DEFAULT_IMAGE_PATH),
    )
}

/// Set while a hibernation holds the CPU context, so the S3 wake
/// continuation, which the restore reuses, skips S3's device resume: the
/// restored [`hibernate`] runs the restore callbacks itself.
static RESTORING: AtomicBool = AtomicBool::new(false);

/// `hibernation_available`: whether `disk` is offered. This arch can
/// restore an image and a TPM can wrap its key slot.
pub fn available() -> bool {
    arch::SUPPORTED && TpmAnchor::production().is_some()
}

/// Whether the S3 wake path is resuming a hibernation image.
pub fn restoring_image() -> bool {
    RESTORING.load(Ordering::Acquire)
}

/// Why a hibernation did not happen. The system is running again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HibernateError {
    AuthorityRevoked,
    /// Another sleep transition is in progress.
    Busy,
    /// More than one CPU is online (lane 4).
    SecondaryCpus(u32),
    /// No TPM for the image's key slot.
    NoTpm,
    ImageFile(ImageFileError),
    Freeze(FreezeError),
    /// A device's prepare, freeze or poweroff callback failed.
    Devices,
    Snapshot(SnapshotError),
    Arch(ArchError),
    Seal(ServiceError),
}

/// A sleep claim released on every path out.
struct Claim;
impl Drop for Claim {
    fn drop(&mut self) {
        suspend::set_phase(SuspendPhase::Idle);
    }
}

/// `hibernate()`: snapshot the system into the image file and power down.
/// Returns `Ok(())` in the image, restored, and `Err` when the
/// hibernation stopped short with the system running.
pub async fn hibernate(cap: &Cap<Power, Invoke>) -> Result<(), HibernateError> {
    cap.invoke(NoopOp)
        .map_err(|_| HibernateError::AuthorityRevoked)?;
    if !arch::SUPPORTED {
        return Err(HibernateError::Arch(ArchError::NotImplemented));
    }
    let online = narf_lib::smp::online_count();
    if online > 1 {
        return Err(HibernateError::SecondaryCpus(online));
    }
    let tpm = TpmAnchor::production().ok_or(HibernateError::NoTpm)?;
    suspend::claim_suspend_transition().map_err(|_| HibernateError::Busy)?;
    let _claim = Claim;

    // Size the file for what is in use now, with room to grow.
    let ranges = narf_memory::frame::saveable_ram_ranges();
    let mut in_use = 0u64;
    for &(start, end) in &ranges {
        narf_memory::frame::for_each_saveable_frame(start, end, |_| in_use += 1);
    }
    let image_len = payload::payload_len(in_use + in_use / 4 + 4096) + IMAGE_SLACK;
    let file = image_file::prepare(&image_path(), image_len)
        .await
        .map_err(HibernateError::ImageFile)?;

    freezer::freeze_processes()
        .await
        .map_err(HibernateError::Freeze)?;
    let transition = system_pm::prepare_async_system_pm_for(SystemSleepState::S4).await;
    let result = if transition.succeeded() {
        match freezer::freeze_kernel_threads().await {
            Ok(()) => {
                let result = snapshot_and_write(&file, &tpm);
                freezer::thaw_kernel_threads();
                result
            }
            Err(e) => Err(HibernateError::Freeze(e)),
        }
    } else {
        Err(HibernateError::Devices)
    };
    let _ = transition.resume().await;
    freezer::thaw_processes();
    if result.is_ok() {
        // The image has done its job; a later boot must not restore it
        // again (`swsusp_unmark`).
        let _ = file.store().write_all(0, &[0u8; BLOCK as usize]);
        let _ = file.store().flush();
    }
    result
}

/// `hibernation_snapshot` + `swsusp_write` + `power_down`. Returns only in
/// the restored image (`Ok`) or when the hibernation failed (`Err`), with
/// the devices running again either way.
fn snapshot_and_write(file: &image_file::ImageFile, tpm: &TpmAnchor) -> Result<(), HibernateError> {
    let mut prealloc = snapshot::preallocate().map_err(HibernateError::Snapshot)?;
    if !device_pm::freeze_all_devices().ok() {
        device_pm::set_hibernate_recovering(true);
        let _ = device_pm::thaw_all_devices();
        device_pm::set_hibernate_recovering(false);
        return Err(HibernateError::Devices);
    }
    // `ioapic_suspend`: the restored image must route as it did, not as the
    // boot kernel programmed. Reserved now; filled with interrupts off.
    #[cfg(target_arch = "x86_64")]
    let mut ioapic = alloc::vec::Vec::with_capacity(8 * 256);
    let irqs = narf_arch::interrupts_enabled();
    RESTORING.store(true, Ordering::Release);
    // SAFETY: interrupts go off on the only CPU, the devices are frozen,
    // and this frame stays live until the capture returns.
    let (captured, rtc_before) = unsafe {
        narf_arch::disable_interrupts();
        // `timekeeping_suspend`, with the RTC for the sleep length: a
        // restored image's counter starts again from power-on.
        narf_time::timekeeping_suspend();
        let rtc_before = rtc_seconds();
        #[cfg(target_arch = "x86_64")]
        narf_acpi::ioapic::save_all(&mut ioapic);
        (arch::capture(|record| (prealloc.take(), record)), rtc_before)
    };
    RESTORING.store(false, Ordering::Release);
    if matches!(captured, Ok(Captured::Restored)) {
        // `ioapic_resume`, interrupts still off.
        #[cfg(target_arch = "x86_64")]
        // SAFETY: the IOAPICs this kernel saved, interrupts off.
        unsafe {
            narf_acpi::ioapic::restore_all(&ioapic);
        }
        let slept = match (rtc_before, rtc_seconds()) {
            (Some(before), Some(after)) if after > before => (after - before) as u64 * 1_000_000_000,
            _ => 0,
        };
        narf_time::timekeeping_resume_after_reset(slept);
    } else {
        let _ = narf_time::timekeeping_resume();
    }
    if irqs {
        // SAFETY: restores the state masked above.
        unsafe { narf_arch::enable_interrupts() };
    }
    let (taken, record) = match captured {
        Ok(Captured::Restored) => {
            // The image, back. `prealloc` still names the copy frames this
            // kernel allocated before the snapshot; dropping it frees them.
            drop(prealloc);
            let _ = device_pm::restore_all_devices();
            return Ok(());
        }
        Ok(Captured::Snapshot(snapshot)) => snapshot,
        Err(e) => {
            recover();
            return Err(HibernateError::Arch(e));
        }
    };
    if let Err(e) = taken {
        recover();
        return Err(HibernateError::Snapshot(e));
    }
    prealloc.release_spare();
    // Thaw for the write. amdgpu and the like stay frozen while not
    // recovering, as Linux's thaw leaves them.
    let _ = device_pm::thaw_all_devices();
    if let Err(e) = write_image(file, tpm, &prealloc, &record) {
        drop(prealloc);
        recover_after_thaw();
        return Err(e);
    }
    drop(prealloc);
    if !device_pm::poweroff_all_devices().ok() {
        recover_after_thaw();
        return Err(HibernateError::Devices);
    }
    crate::system::hibernation_power_down(crate::system::default_hibernation_mode())
}

/// The RTC as seconds since the epoch, Linux's persistent clock.
fn rtc_seconds() -> Option<i64> {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: the CMOS RTC's ports, with interrupts off.
        unsafe { narf_arch::x86_64::rtc::read_now() }
            .ok()
            .map(|t| t.to_unix_seconds())
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

/// Thaw after a failed snapshot: every device resumes (`pm_hibernate_is_recovering`).
fn recover() {
    device_pm::set_hibernate_recovering(true);
    let _ = device_pm::thaw_all_devices();
    device_pm::set_hibernate_recovering(false);
}

/// Bring back the devices a normal thaw left frozen, after a failed write
/// or poweroff: they suspend once more and resume.
fn recover_after_thaw() {
    let _ = device_pm::freeze_all_devices();
    recover();
}

/// `swsusp_write`: seal the payload into the image file under a fresh slot
/// the TPM wraps.
fn write_image(
    file: &image_file::ImageFile,
    tpm: &TpmAnchor,
    prealloc: &snapshot::Prealloc,
    record: &ArchRecord,
) -> Result<(), HibernateError> {
    let snapshot = prealloc.snapshot();
    let mut header = PayloadHeader::for_running_kernel(snapshot.len() as u64);
    header.arch = record.encode();
    let source = PayloadSource::new(&header, snapshot);
    let mut service = SuspendService::new(HwKeyEntropy);
    service.create_epoch().map_err(HibernateError::Seal)?;
    service.enroll(tpm).map_err(HibernateError::Seal)?;
    let policy = RecordedPolicy {
        level: PolicyLevel::Tpm,
        policy_epoch: 0,
    };
    let mut store = file.store();
    service
        .seal_source_registered(&mut store, policy, &source)
        .map_err(HibernateError::Seal)?;
    store.flush().map_err(HibernateError::Seal)?;
    let _ = narf_console::write_str(&alloc::format!(
        "  hibernate: image of {} pages written; resume with narf.resume={} narf.resume_offset={}\n",
        snapshot.len(),
        file.device,
        file.resume_offset()
    ));
    Ok(())
}

/// Why [`software_resume`] booted on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResumeSkip {
    /// No `narf.resume=`.
    NotConfigured,
    SecondaryCpus(u32),
    NoDevice(String),
    /// The locator block holds no image file.
    NoImage,
    Refused(ResumeRefusal),
    Payload(RestoreError),
    /// The RAM layout differs from the image's.
    MemoryMapChanged,
    Arch(ArchError),
    Devices,
    Store,
}

/// `software_resume`: restore the image `narf.resume=` names, if any. It
/// returns only when the boot goes on without one.
pub fn software_resume() -> ResumeSkip {
    let args = narf_boot::args();
    let Some(device) = args.value("narf.resume") else {
        return ResumeSkip::NotConfigured;
    };
    let offset: u64 = args.parse_value("narf.resume_offset").unwrap_or(0);
    let skip = resume_from(device, offset);
    let _ = narf_console::write_str(&alloc::format!("  hibernate: no resume: {skip:?}\n"));
    skip
}

fn resume_from(device: &str, offset: u64) -> ResumeSkip {
    if !arch::SUPPORTED {
        return ResumeSkip::Arch(ArchError::NotImplemented);
    }
    let online = narf_lib::smp::online_count();
    if online > 1 {
        return ResumeSkip::SecondaryCpus(online);
    }
    let name = device.strip_prefix("/dev/").unwrap_or(device);
    let Some(dev) = narf_block::registry::find_block_device(name) else {
        return ResumeSkip::NoDevice(String::from(device));
    };
    let whole = BlockStore::new(dev);
    let mut block = alloc::vec![0u8; BLOCK as usize];
    if whole.read_exact(offset * BLOCK, &mut block).is_err() {
        return ResumeSkip::Store;
    }
    let Ok(locator) = Locator::decode(&block) else {
        return ResumeSkip::NoImage;
    };
    let store = ExtentStore::new(whole, locator);
    let tpm = TpmAnchor::production();
    let anchors: alloc::vec::Vec<&dyn KeyCustodyAnchor> =
        tpm.iter().map(|t| t as &dyn KeyCustodyAnchor).collect();
    let verified = match attempt_resume(&store, &anchors, &mut ConsolePrompt) {
        Ok(v) => v,
        Err(ResumeRefusal::NoImage) => return ResumeSkip::NoImage,
        Err(e) => return ResumeSkip::Refused(e),
    };
    let (header, mut loader) = match restore::load_payload(&verified, &store) {
        Ok(loaded) => loaded,
        Err(e) => return ResumeSkip::Payload(e),
    };
    let ranges = narf_memory::frame::saveable_ram_ranges();
    if header.ram_hash != payload::ram_layout_hash(&ranges) {
        loader.abandon();
        return ResumeSkip::MemoryMapChanged;
    }
    let record = match ArchRecord::decode(&header.arch) {
        Ok(r) => r,
        Err(e) => {
            loader.abandon();
            return ResumeSkip::Arch(e);
        }
    };
    // Consume the image before jumping: a restore that dies in the copy
    // must cold-boot next time, not loop.
    if store.write_all(0, &[0u8; BLOCK as usize]).is_err() || store.flush().is_err() {
        loader.abandon();
        return ResumeSkip::Store;
    }
    // `resume_target_kernel`: quiesce, interrupts off, jump.
    if !device_pm::freeze_all_devices().ok() {
        recover();
        loader.abandon();
        return ResumeSkip::Devices;
    }
    let irqs = narf_arch::interrupts_enabled();
    let first_pb = loader.first_pb();
    // SAFETY: the only CPU, devices quiesced, interrupts going off; the
    // loader names every image page with a copy in a frame no pair writes,
    // and hands out only such frames.
    let jumped = unsafe {
        narf_arch::disable_interrupts();
        arch::restore(&record, &ranges, first_pb, &mut loader)
    };
    let Err(e) = jumped;
    if irqs {
        // SAFETY: restores the state masked above.
        unsafe { narf_arch::enable_interrupts() };
    }
    recover();
    loader.abandon();
    ResumeSkip::Arch(e)
}

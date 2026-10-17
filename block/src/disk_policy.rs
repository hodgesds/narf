//! Boot-medium-only disk write policy (`narf.disks=`).
//!
//! A bare-metal NARF boot from a USB stick must never write to the
//! machine's internal disks: they hold the user's real operating system.
//! `narf.disks=boot-only` turns that into a block-layer guarantee instead
//! of a property every mount path has to get right:
//!
//! - Every device entering the registry is wrapped in a [`PolicyGuard`].
//!   Under [`DiskPolicy::BootOnly`] the guard rejects every
//!   [`BlockDeviceSync::write`] with [`BlockIoError::ReadOnly`] (logged once
//!   per device) unless the device's *disk* has been positively identified
//!   as the medium NARF booted from via [`trust_boot_medium`]. Reads are
//!   always passed through, so internal disks can still be enumerated,
//!   partition-scanned and identified for diagnostics.
//! - A partition shares its parent disk's [`DiskId`], so identifying one
//!   partition of the stick trusts the stick and nothing else.
//! - [`DiskId`]s are never reused. A device that is unplugged and replaced
//!   by another one under the same name (`usb-msc0`) starts untrusted.
//! - [`automount_allowed`] is the matching gate for boot-time automatic
//!   mounts: under `boot-only` only the identified boot medium qualifies.
//!
//! Absent the argument (or `narf.disks=all`) the policy is
//! [`DiskPolicy::All`] and the guard is a pass-through, which is what every
//! QEMU test boot relies on. Every xtask generator of media meant for a real
//! machine (`usb-image`, `grub-image`, `disk-write-partitioned`) therefore
//! writes `narf.disks=boot-only` itself unless `--allow-all-disks` is given.
//! An unrecognised value fails closed to `boot-only`. The resolved policy is
//! printed as a framed console banner either way.
//!
//! Limits: the guard covers every write that goes through the registry
//! (filesystems, devfs block nodes, the bootlog). A driver writing through a
//! private controller handle it never registered is outside this layer;
//! see the boot-time audit in `docs/BOOTING_ON_CACHYOS.md`.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::registry::{BlockDeviceSync, BlockIoError};

/// Kernel argument selecting the policy.
pub const ARG: &str = "narf.disks";

/// Which block devices may be written.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DiskPolicy {
    /// Every registered device is writable (default).
    All,
    /// Only the positively identified boot medium is writable; every other
    /// device is read-only at the block layer and never auto-mounted.
    BootOnly,
}

/// Parse a `narf.disks=` value. `None` (argument absent) is
/// [`DiskPolicy::All`]; an unknown value is an error the caller turns into
/// [`DiskPolicy::BootOnly`] (fail closed).
pub fn parse(value: Option<&str>) -> Result<DiskPolicy, &'static str> {
    match value {
        None => Ok(DiskPolicy::All),
        Some(v) if v.eq_ignore_ascii_case("all") => Ok(DiskPolicy::All),
        Some(v) if v.eq_ignore_ascii_case("boot-only") || v.eq_ignore_ascii_case("boot") => {
            Ok(DiskPolicy::BootOnly)
        }
        Some(_) => Err("expected `all` or `boot-only`"),
    }
}

const UNSET: u8 = 0;
const ALL: u8 = 1;
const BOOT_ONLY: u8 = 2;

static POLICY: AtomicU8 = AtomicU8::new(UNSET);

fn encode(policy: DiskPolicy) -> u8 {
    match policy {
        DiskPolicy::All => ALL,
        DiskPolicy::BootOnly => BOOT_ONLY,
    }
}

fn from_cmdline() -> DiskPolicy {
    parse(narf_boot::args().value(ARG)).unwrap_or(DiskPolicy::BootOnly)
}

/// The active policy. Resolved from the command line on first use; the
/// result is cached once a command line is present.
pub fn policy() -> DiskPolicy {
    match POLICY.load(Ordering::Acquire) {
        ALL => DiskPolicy::All,
        BOOT_ONLY => DiskPolicy::BootOnly,
        _ => {
            let policy = from_cmdline();
            if !narf_boot::cmdline().is_empty() {
                let _ = POLICY.compare_exchange(
                    UNSET,
                    encode(policy),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
            }
            policy
        }
    }
}

/// Resolve the policy from the command line and log it. Called once early
/// in boot, before any storage driver probes, so the console states the
/// policy before any device appears.
pub fn init_from_cmdline() -> DiskPolicy {
    let value = narf_boot::args().value(ARG);
    let policy = match parse(value) {
        Ok(policy) => policy,
        Err(why) => {
            let _ = writeln!(
                narf_console::Writer,
                "disks: {ARG}={} not understood ({why}); failing closed to boot-only",
                value.unwrap_or("")
            );
            DiskPolicy::BootOnly
        }
    };
    POLICY.store(encode(policy), Ordering::Release);
    // Both outcomes are announced, framed so the line stands out of the
    // probe noise: on a bare-metal boot the operator must be able to see at
    // a glance whether the internal disks are protected.
    let _ = writeln!(
        narf_console::Writer,
        "disks: ================================"
    );
    let _ = writeln!(narf_console::Writer, "{}", banner(policy, value.is_some()));
    let _ = writeln!(
        narf_console::Writer,
        "disks: ================================"
    );
    policy
}

/// The console line [`init_from_cmdline`] prints for the active policy.
/// `explicit` is whether `narf.disks=` was on the command line.
pub fn banner(policy: DiskPolicy, explicit: bool) -> &'static str {
    match (policy, explicit) {
        (DiskPolicy::BootOnly, _) => {
            "disks: POLICY narf.disks=boot-only: every disk is read-only until identified as the boot medium"
        }
        (DiskPolicy::All, true) => {
            "disks: POLICY narf.disks=all: EVERY disk is writable (internal disks NOT protected)"
        }
        (DiskPolicy::All, false) => {
            "disks: POLICY all (no narf.disks= argument): EVERY disk is writable (internal disks NOT protected)"
        }
    }
}

/// Test-only: force the policy (and with `None`, return to the unresolved
/// state).
#[doc(hidden)]
pub fn __set_policy_for_test(policy: Option<DiskPolicy>) {
    POLICY.store(policy.map_or(UNSET, encode), Ordering::Release);
}

// ── Disk identity and trust ─────────────────────────────────────────

/// Identity of one physical disk registration. Partitions inherit their
/// parent's id. Never reused.
pub type DiskId = u64;

static NEXT_DISK: AtomicU64 = AtomicU64::new(1);

pub(crate) fn new_disk_id() -> DiskId {
    NEXT_DISK.fetch_add(1, Ordering::Relaxed)
}

/// Disks identified as the boot medium.
static TRUSTED: IrqSafeSpinLock<Vec<DiskId>> = IrqSafeSpinLock::new(Vec::new());

fn disk_trusted(disk: DiskId) -> bool {
    TRUSTED.lock().contains(&disk)
}

/// Record that the disk `disk` — the [`crate::RegisteredBlockDevice::disk`]
/// of the registry entry `device_name` whose contents were just verified —
/// was positively identified as the medium NARF booted from. The whole disk
/// becomes writable and eligible for automatic mounts.
///
/// Callers pass the id from the *same* registry snapshot as the device they
/// read the proof from, so a device swapped in under the same name (a
/// different stick on `usb-msc0`) can never inherit the trust. Callers must
/// only do this after matching a boot-specific secret on the medium (the
/// `/NARFLOG.ID` token) — never from a name, size or label alone.
pub fn trust_boot_medium(device_name: &str, disk: DiskId) {
    let newly = {
        let mut trusted = TRUSTED.lock();
        if trusted.contains(&disk) {
            false
        } else {
            trusted.push(disk);
            true
        }
    };
    if newly && policy() == DiskPolicy::BootOnly {
        let _ = writeln!(
            narf_console::Writer,
            "disks: {device_name}: identified as the boot medium; its disk is writable"
        );
    }
}

/// True when `device_name`'s disk was identified as the boot medium.
pub fn is_boot_medium(device_name: &str) -> bool {
    crate::registry::disk_of(device_name).is_some_and(disk_trusted)
}

/// Whether boot-time code may automatically mount (or otherwise open for
/// writing) `device_name`. Always true under [`DiskPolicy::All`].
pub fn automount_allowed(device_name: &str) -> bool {
    match policy() {
        DiskPolicy::All => true,
        DiskPolicy::BootOnly => is_boot_medium(device_name),
    }
}

/// Whether a write to `device_name` would currently pass its guard.
pub fn write_allowed(device_name: &str) -> bool {
    automount_allowed(device_name)
}

/// Test-only: forget every identified boot medium.
#[doc(hidden)]
pub fn __reset_trust_for_test() {
    TRUSTED.lock().clear();
}

// ── The guard ───────────────────────────────────────────────────────

/// Number of writes refused by the policy since boot (all devices).
static REFUSED: AtomicU64 = AtomicU64::new(0);

/// Writes refused by the policy since boot.
pub fn refused_writes() -> u64 {
    REFUSED.load(Ordering::Relaxed)
}

/// Registry-side wrapper enforcing [`policy`] on one device.
pub struct PolicyGuard {
    name: &'static str,
    disk: DiskId,
    inner: Arc<dyn BlockDeviceSync>,
    warned: AtomicBool,
}

impl core::fmt::Debug for PolicyGuard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PolicyGuard")
            .field("name", &self.name)
            .field("disk", &self.disk)
            .finish_non_exhaustive()
    }
}

impl PolicyGuard {
    pub fn new(name: &'static str, disk: DiskId, inner: Arc<dyn BlockDeviceSync>) -> Self {
        Self {
            name,
            disk,
            inner,
            warned: AtomicBool::new(false),
        }
    }

    /// The disk this guard belongs to.
    pub fn disk(&self) -> DiskId {
        self.disk
    }

    fn permits_write(&self) -> bool {
        match policy() {
            DiskPolicy::All => true,
            DiskPolicy::BootOnly => disk_trusted(self.disk),
        }
    }
}

impl BlockDeviceSync for PolicyGuard {
    fn lba_size(&self) -> u32 {
        self.inner.lba_size()
    }
    fn capacity(&self) -> u64 {
        self.inner.capacity()
    }
    fn read(&self, lba: u64, n_blocks: u16, out: &mut [u8]) -> Result<(), BlockIoError> {
        self.inner.read(lba, n_blocks, out)
    }
    fn is_read_only(&self) -> bool {
        !self.permits_write() || self.inner.is_read_only()
    }
    fn write(&self, lba: u64, n_blocks: u16, data: &[u8]) -> Result<(), BlockIoError> {
        if self.permits_write() {
            return self.inner.write(lba, n_blocks, data);
        }
        REFUSED.fetch_add(1, Ordering::Relaxed);
        if !self.warned.swap(true, Ordering::Relaxed) {
            let _ = writeln!(
                narf_console::Writer,
                "disks: refused write to {} (lba {lba}, {n_blocks} blocks): \
                 {ARG}=boot-only and it is not the boot medium; further refusals are silent",
                self.name
            );
        }
        Err(BlockIoError::ReadOnly)
    }
}

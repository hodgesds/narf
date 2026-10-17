//! Block-layer disk write policy (`narf.disks=`).
//!
//! A bare-metal NARF boot must never write to a disk except as the operator
//! explicitly allowed: the machine's disks hold the user's real operating
//! system. `narf.disks=` turns that into a block-layer guarantee instead of a
//! property every mount path has to get right. Every device entering the
//! registry is wrapped in a [`PolicyGuard`]; reads always pass through, so
//! every disk can still be enumerated, partition-scanned and identified.
//!
//! | value       | writable                                                    |
//! | ----------- | ----------------------------------------------------------- |
//! | `all`       | every device (the default; what QEMU test boots rely on)    |
//! | `boot-only` | only the disk positively identified as the boot medium      |
//! | `root-ro`   | nothing; the designated root may be mounted read-only       |
//! | `root-rw`   | only the designated root *partition* (one btrfs filesystem) |
//!
//! `boot-only`:
//! - The guard rejects every [`BlockDeviceSync::write`] with
//!   [`BlockIoError::ReadOnly`] (logged once per device) unless the device's
//!   *disk* has been positively identified as the medium NARF booted from via
//!   [`trust_boot_medium`].
//! - A partition shares its parent disk's [`DiskId`], so identifying one
//!   partition of the stick trusts the stick and nothing else.
//! - [`DiskId`]s are never reused. A device that is unplugged and replaced
//!   by another one under the same name (`usb-msc0`) starts untrusted.
//!
//! `root-ro` / `root-rw` (booting an installed distro, e.g. CachyOS):
//! - Nothing is writable until root mounting calls [`designate_root`] for the
//!   partition whose filesystem UUID matched `root=UUID=`. The designation
//!   re-reads the UUID from the device itself, requires it to equal the
//!   command line's, requires it to be unique among every registered device
//!   (a cloned disk or a multi-device btrfs carries the same UUID: refused),
//!   refuses an ESP / vfat partition, and under `root-rw` requires btrfs (the
//!   one writer with a mount-time write-safety gate). It can succeed once.
//! - Under `root-rw` exactly the designated partition's guard — identified by
//!   its never-reused [`DevId`], never by name — passes writes. The whole
//!   disk device, its ESP, and every other disk stay read-only.
//! - Under `root-ro` no guard ever passes a write; the distro path's tmpfs
//!   overlay provides the writable view.
//! - The designation is revoked for the rest of the boot (every write refused
//!   again, banner printed) if the designated device is unregistered or
//!   replaced, or another device carrying the same filesystem UUID appears.
//! - [`automount_allowed`] admits only the root candidate (before
//!   designation), the designated root, and vfat partitions on the root's
//!   physical disk (its ESP, which the guard keeps read-only).
//!
//! An unrecognised (or repeated) value fails closed to `boot-only`. The
//! resolved policy is printed as a framed console banner either way, and a
//! designation prints a second banner naming exactly which device and UUID
//! is writable.
//!
//! Limits: the guard covers every write that goes through the registry
//! (filesystems, devfs block nodes, the bootlog). A driver writing through a
//! private controller handle it never registered is outside this layer;
//! see the boot-time audit in `docs/BOOTING_ON_CACHYOS.md`.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::partition::{format_uuid_bytes, parse_uuid};
use crate::registry::{BlockDeviceSync, BlockIoError, RegisteredBlockDevice};

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
    /// Nothing is writable. The partition named by `root=UUID=` may be
    /// mounted read-only once designated ([`designate_root`]).
    RootRo,
    /// Only the designated root partition (`root=UUID=`, btrfs) is writable.
    RootRw,
}

impl DiskPolicy {
    /// The `narf.disks=` spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            DiskPolicy::All => "all",
            DiskPolicy::BootOnly => "boot-only",
            DiskPolicy::RootRo => "root-ro",
            DiskPolicy::RootRw => "root-rw",
        }
    }

    /// `root-ro` or `root-rw`.
    pub fn is_root_policy(self) -> bool {
        matches!(self, DiskPolicy::RootRo | DiskPolicy::RootRw)
    }
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
        Some(v) if v.eq_ignore_ascii_case("root-ro") => Ok(DiskPolicy::RootRo),
        Some(v) if v.eq_ignore_ascii_case("root-rw") => Ok(DiskPolicy::RootRw),
        Some(_) => Err("expected `all`, `boot-only`, `root-ro` or `root-rw`"),
    }
}

const UNSET: u8 = 0;
const ALL: u8 = 1;
const BOOT_ONLY: u8 = 2;
const ROOT_RO: u8 = 3;
const ROOT_RW: u8 = 4;

static POLICY: AtomicU8 = AtomicU8::new(UNSET);

fn encode(policy: DiskPolicy) -> u8 {
    match policy {
        DiskPolicy::All => ALL,
        DiskPolicy::BootOnly => BOOT_ONLY,
        DiskPolicy::RootRo => ROOT_RO,
        DiskPolicy::RootRw => ROOT_RW,
    }
}

/// The `narf.disks=` value on the command line. More than one is ambiguous
/// and fails closed like an unknown value.
fn cmdline_value() -> Result<Option<&'static str>, &'static str> {
    let mut values = narf_boot::args().values(ARG);
    let first = values.next();
    if values.next().is_some() {
        return Err("given more than once");
    }
    Ok(first)
}

fn from_cmdline() -> DiskPolicy {
    cmdline_value()
        .and_then(parse)
        .unwrap_or(DiskPolicy::BootOnly)
}

/// The active policy. Resolved from the command line on first use; the
/// result is cached once a command line is present.
pub fn policy() -> DiskPolicy {
    match POLICY.load(Ordering::Acquire) {
        ALL => DiskPolicy::All,
        BOOT_ONLY => DiskPolicy::BootOnly,
        ROOT_RO => DiskPolicy::RootRo,
        ROOT_RW => DiskPolicy::RootRw,
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

const RULE: &str = "disks: ==================================================================";

fn framed(line: &str) {
    let _ = writeln!(narf_console::Writer, "{RULE}");
    let _ = writeln!(narf_console::Writer, "{line}");
    let _ = writeln!(narf_console::Writer, "{RULE}");
}

/// Resolve the policy from the command line and log it. Called once early
/// in boot, before any storage driver probes, so the console states the
/// policy before any device appears.
pub fn init_from_cmdline() -> DiskPolicy {
    let value = cmdline_value();
    let policy = match value.and_then(parse) {
        Ok(policy) => policy,
        Err(why) => {
            let _ = writeln!(
                narf_console::Writer,
                "disks: {ARG}={} not understood ({why}); failing closed to boot-only",
                value.ok().flatten().unwrap_or("")
            );
            DiskPolicy::BootOnly
        }
    };
    POLICY.store(encode(policy), Ordering::Release);
    // Every outcome is announced, framed so the line stands out of the
    // probe noise: on a bare-metal boot the operator must be able to see at
    // a glance whether the internal disks are protected.
    let root = root_arg_text();
    let explicit = !matches!(value, Ok(None));
    framed(&banner_with_root(policy, explicit, root.as_deref()));
    policy
}

/// The console line [`init_from_cmdline`] prints for the active policy.
/// `explicit` is whether `narf.disks=` was on the command line.
pub fn banner(policy: DiskPolicy, explicit: bool) -> String {
    banner_with_root(policy, explicit, None)
}

/// [`banner`] naming the `root=` value a root policy will designate.
pub fn banner_with_root(policy: DiskPolicy, explicit: bool, root: Option<&str>) -> String {
    let root = root.unwrap_or("<missing: nothing will be writable>");
    match (policy, explicit) {
        (DiskPolicy::BootOnly, _) => String::from(
            "disks: POLICY narf.disks=boot-only: every disk is read-only until identified as the boot medium",
        ),
        (DiskPolicy::All, true) => String::from(
            "disks: POLICY narf.disks=all: EVERY disk is writable (internal disks NOT protected)",
        ),
        (DiskPolicy::All, false) => String::from(
            "disks: POLICY all (no narf.disks= argument): EVERY disk is writable (internal disks NOT protected)",
        ),
        (DiskPolicy::RootRo, _) => alloc::format!(
            "disks: POLICY narf.disks=root-ro: NOTHING is writable; root={root} may be mounted read-only"
        ),
        (DiskPolicy::RootRw, _) => alloc::format!(
            "disks: POLICY narf.disks=root-rw: ONLY the partition whose filesystem UUID matches root={root} \
             will be WRITABLE; every other disk and partition (its ESP included) is read-only"
        ),
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

/// Identity of one registry entry (one [`PolicyGuard`]). Never reused, never
/// zero: a device re-registered under the same name gets a fresh id.
pub type DevId = u64;

static NEXT_DISK: AtomicU64 = AtomicU64::new(1);
static NEXT_DEV: AtomicU64 = AtomicU64::new(1);

pub(crate) fn new_disk_id() -> DiskId {
    NEXT_DISK.fetch_add(1, Ordering::Relaxed)
}

fn new_dev_id() -> DevId {
    NEXT_DEV.fetch_add(1, Ordering::Relaxed)
}

/// Disks identified as the boot medium.
static TRUSTED: IrqSafeSpinLock<Vec<DiskId>> = IrqSafeSpinLock::new(Vec::new());

fn disk_trusted(disk: DiskId) -> bool {
    TRUSTED.lock().contains(&disk)
}

/// Record that the disk `disk` — the [`crate::RegisteredBlockDevice::disk`]
/// of the registry entry `device_name` whose contents were just verified —
/// was positively identified as the medium NARF booted from. Under
/// `boot-only` the whole disk becomes writable and eligible for automatic
/// mounts; under every other policy this grants nothing.
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

/// Test-only: forget every identified boot medium.
#[doc(hidden)]
pub fn __reset_trust_for_test() {
    TRUSTED.lock().clear();
}

// ── Root designation (root-ro / root-rw) ────────────────────────────

/// Why [`designate_root`] refused.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    /// The active policy is `all` or `boot-only`: there is no root to
    /// designate.
    NotRootPolicy,
    /// The command line has no `root=UUID=<uuid>`, more than one `root=`, or
    /// a malformed UUID.
    NoRootUuidArg,
    /// The UUID passed does not equal the command line's `root=UUID=`.
    UuidMismatch,
    /// No registered device has that name.
    NoSuchDevice,
    /// The device is a whole disk (or a LUKS view), not a scanned partition.
    NotAPartition,
    /// The UUID read back from the device itself does not match.
    IdentityMismatch,
    /// More than one registered device carries the UUID (cloned disk,
    /// multi-device btrfs).
    Ambiguous,
    /// The device is an EFI System Partition or a vfat filesystem, which stay
    /// read-only in every root policy.
    EfiOrVfat,
    /// `root-rw` requires btrfs, the writer with a write-safety gate.
    NotBtrfs,
    /// A root was already designated this boot.
    AlreadyDesignated,
    /// An earlier designation was revoked; nothing is designated again.
    Revoked,
}

#[derive(Clone, Debug)]
struct Designation {
    name: &'static str,
    dev: DevId,
    disk: DiskId,
    /// Hardware identity of the root's disk (PCI path, serial, namespace),
    /// when its transport reports one.
    identity: Option<Arc<crate::registry::DiskIdentity>>,
    uuid: [u8; 16],
}

static DESIGNATED: IrqSafeSpinLock<Option<Designation>> = IrqSafeSpinLock::new(None);
/// [`Designation::dev`] for the lock-free guard check; 0 = none.
static DESIGNATED_DEV: AtomicU64 = AtomicU64::new(0);
/// Set once a designation is revoked; never cleared outside tests.
static REVOKED: AtomicBool = AtomicBool::new(false);
/// Test-only override of the command line's `root=` value.
static ROOT_ARG_OVERRIDE: IrqSafeSpinLock<Option<Option<String>>> = IrqSafeSpinLock::new(None);

/// The single `root=` value on the command line (`None` when absent or
/// repeated).
fn root_arg_text() -> Option<String> {
    if let Some(over) = ROOT_ARG_OVERRIDE.lock().clone() {
        return over;
    }
    let mut values = narf_boot::args().values("root");
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }
    Some(String::from(first))
}

/// The filesystem UUID `root=UUID=` names, if the command line has exactly
/// one `root=` and it is a well-formed `UUID=`.
pub fn root_uuid_arg() -> Option<[u8; 16]> {
    let text = root_arg_text()?;
    let uuid = text
        .strip_prefix("UUID=")
        .or_else(|| text.strip_prefix("uuid="))?;
    parse_uuid(uuid)
}

/// Test-only: replace the command line's `root=` value (`Some(None)` = no
/// `root=`; `None` = use the real command line).
#[doc(hidden)]
pub fn __set_root_arg_for_test(value: Option<Option<&str>>) {
    *ROOT_ARG_OVERRIDE.lock() = value.map(|v| v.map(String::from));
}

/// Test-only: forget the designation and any revocation.
#[doc(hidden)]
pub fn __reset_root_for_test() {
    *DESIGNATED.lock() = None;
    DESIGNATED_DEV.store(0, Ordering::Release);
    REVOKED.store(false, Ordering::Release);
}

/// The filesystem UUID of a registry entry, from its partition metadata (the
/// scanner read it from the device) or, for an entry without metadata, read
/// from the device now.
fn entry_uuid(entry: &RegisteredBlockDevice) -> Option<[u8; 16]> {
    match &entry.partition {
        Some(meta) if !meta.fs_uuid.is_empty() => parse_uuid(&meta.fs_uuid),
        _ => crate::partition::discover_volume_uuid(entry.dev.as_ref())
            .and_then(|text| parse_uuid(&text)),
    }
}

fn entry_is_vfat(entry: &RegisteredBlockDevice) -> bool {
    matches!(
        crate::fs_detect::detect_filesystem(&entry.dev),
        Ok(Some(crate::fs_detect::FsType::Fat))
    )
}

fn revoke(reason: &str) {
    if REVOKED.swap(true, Ordering::AcqRel) {
        return;
    }
    DESIGNATED_DEV.store(0, Ordering::Release);
    framed(&alloc::format!(
        "disks: ROOT DESIGNATION REVOKED ({reason}): every disk is read-only for the rest of this boot"
    ));
}

/// Designate the partition `device_name`, whose filesystem UUID matched the
/// command line's `root=UUID=`, as the root under `root-ro` / `root-rw`.
///
/// Called by root mounting after its `root=UUID=` match and *before* the
/// filesystem is constructed, so a `root-rw` mount sees a writable device.
/// The UUID is re-verified against the command line, the registry's
/// identity metadata, and the device itself; see [`PolicyError`] for every
/// refusal. Succeeds at most once per boot.
pub fn designate_root(device_name: &str, fs_uuid: [u8; 16]) -> Result<(), PolicyError> {
    let policy = policy();
    if !policy.is_root_policy() {
        return Err(PolicyError::NotRootPolicy);
    }
    if REVOKED.load(Ordering::Acquire) {
        return Err(PolicyError::Revoked);
    }
    if DESIGNATED.lock().is_some() {
        return Err(PolicyError::AlreadyDesignated);
    }
    let arg = root_uuid_arg().ok_or(PolicyError::NoRootUuidArg)?;
    if arg != fs_uuid {
        return Err(PolicyError::UuidMismatch);
    }
    let devices = crate::registry::block_devices();
    let entry = devices
        .iter()
        .find(|e| e.name == device_name)
        .ok_or(PolicyError::NoSuchDevice)?;
    let meta = entry.partition.as_ref().ok_or(PolicyError::NotAPartition)?;
    if parse_uuid(&meta.fs_uuid) != Some(fs_uuid) {
        return Err(PolicyError::IdentityMismatch);
    }
    // Re-read the identity from the medium itself, not only the scanner's
    // record of it.
    let on_disk = crate::partition::discover_volume_uuid(entry.dev.as_ref())
        .and_then(|text| parse_uuid(&text));
    if on_disk != Some(fs_uuid) {
        return Err(PolicyError::IdentityMismatch);
    }
    if meta.is_efi_system_partition() || entry_is_vfat(entry) {
        return Err(PolicyError::EfiOrVfat);
    }
    if policy == DiskPolicy::RootRw
        && !matches!(
            crate::fs_detect::detect_filesystem(&entry.dev),
            Ok(Some(crate::fs_detect::FsType::Btrfs))
        )
    {
        return Err(PolicyError::NotBtrfs);
    }
    // Unique by the registry's identity index (a duplicated partition UUID
    // yields no match) and by every whole-disk entry's own superblock.
    let unique = crate::registry::find_by_fs_uuid(&format_uuid_bytes(&fs_uuid))
        .is_some_and(|found| found.dev_id == entry.dev_id);
    if !unique
        || devices
            .iter()
            .any(|other| other.dev_id != entry.dev_id && entry_uuid(other) == Some(fs_uuid))
    {
        return Err(PolicyError::Ambiguous);
    }
    {
        let mut slot = DESIGNATED.lock();
        if slot.is_some() {
            return Err(PolicyError::AlreadyDesignated);
        }
        *slot = Some(Designation {
            name: entry.name,
            dev: entry.dev_id,
            disk: entry.disk,
            identity: entry.identity.clone(),
            uuid: fs_uuid,
        });
    }
    DESIGNATED_DEV.store(entry.dev_id, Ordering::Release);
    // A device registered between the snapshot above and the store was not
    // checked by `note_registered` against this designation: check again.
    let after = crate::registry::block_devices();
    let still_there = after.iter().any(|e| e.dev_id == entry.dev_id);
    let duplicate = after
        .iter()
        .any(|other| other.dev_id != entry.dev_id && entry_uuid(other) == Some(fs_uuid));
    if !still_there || duplicate {
        revoke("the registry changed while the root was being designated");
        return Err(PolicyError::Ambiguous);
    }
    let uuid = format_uuid_bytes(&fs_uuid);
    framed(&match policy {
        DiskPolicy::RootRw => alloc::format!(
            "disks: WRITABLE: {} (btrfs UUID {uuid}) is the ONLY writable device \
             (narf.disks=root-rw); every other disk and partition is read-only",
            entry.name
        ),
        _ => alloc::format!(
            "disks: root {} (UUID {uuid}) designated READ-ONLY (narf.disks=root-ro); \
             NOTHING is writable",
            entry.name
        ),
    });
    Ok(())
}

/// Registry hook: `entry` was just registered (`replaced`: the id of the
/// entry it replaced under the same name). Revokes the designation when the
/// designated device was replaced or another device carries its UUID.
pub(crate) fn note_registered(entry: &RegisteredBlockDevice, replaced: Option<DevId>) {
    let Some(designated) = DESIGNATED.lock().clone() else {
        return;
    };
    if REVOKED.load(Ordering::Acquire) {
        return;
    }
    if replaced == Some(designated.dev) {
        revoke("the designated root device was re-registered");
    } else if entry.dev_id != designated.dev && entry_uuid(entry) == Some(designated.uuid) {
        revoke("a second device carries the root filesystem UUID");
    }
}

/// Registry hook: the device `dev` was unregistered.
pub(crate) fn note_unregistered(dev: DevId) {
    if dev != 0 && DESIGNATED_DEV.load(Ordering::Acquire) == dev {
        revoke("the designated root device was removed");
    }
}

/// True when `root-rw` is active and a root is designated (and not
/// revoked): exactly one partition is writable.
pub fn root_writable() -> bool {
    policy() == DiskPolicy::RootRw
        && !REVOKED.load(Ordering::Acquire)
        && DESIGNATED_DEV.load(Ordering::Acquire) != 0
}

/// The designated root's registry name, if any (and not revoked).
pub fn designated_root() -> Option<&'static str> {
    if REVOKED.load(Ordering::Acquire) {
        return None;
    }
    DESIGNATED.lock().as_ref().map(|d| d.name)
}

fn entry_named(name: &str) -> Option<RegisteredBlockDevice> {
    crate::registry::block_devices()
        .into_iter()
        .find(|e| e.name == name)
}

/// Whether boot-time code may automatically mount (or otherwise open)
/// `device_name`. Always true under [`DiskPolicy::All`].
///
/// Under the root policies: before designation only a partition whose
/// filesystem UUID equals `root=UUID=` (the candidate root mounting will
/// designate); afterwards the designated root, plus vfat partitions on the
/// same physical disk (its ESP), which the guard keeps read-only.
pub fn automount_allowed(device_name: &str) -> bool {
    match policy() {
        DiskPolicy::All => true,
        DiskPolicy::BootOnly => is_boot_medium(device_name),
        DiskPolicy::RootRo | DiskPolicy::RootRw => {
            let Some(entry) = entry_named(device_name) else {
                return false;
            };
            let designated = DESIGNATED.lock().clone();
            match designated {
                None => {
                    let want = root_uuid_arg();
                    !REVOKED.load(Ordering::Acquire)
                        && want.is_some()
                        && entry
                            .partition
                            .as_ref()
                            .is_some_and(|meta| parse_uuid(&meta.fs_uuid) == want)
                }
                Some(d) if d.dev == entry.dev_id => true,
                // Same physical disk: the registry's disk id (a partition
                // inherits its parent's) and, when the transport reports one,
                // the same hardware identity (PCI path, serial, namespace).
                Some(d) => {
                    entry.disk == d.disk
                        && entry.identity.as_deref() == d.identity.as_deref()
                        && entry.partition.is_some()
                        && entry_is_vfat(&entry)
                }
            }
        }
    }
}

/// Whether a write to `device_name` would currently pass its guard.
pub fn write_allowed(device_name: &str) -> bool {
    match policy() {
        DiskPolicy::All => true,
        DiskPolicy::BootOnly => is_boot_medium(device_name),
        DiskPolicy::RootRo => false,
        DiskPolicy::RootRw => entry_named(device_name).is_some_and(|e| dev_writable(e.dev_id)),
    }
}

fn dev_writable(dev: DevId) -> bool {
    dev != 0 && !REVOKED.load(Ordering::Acquire) && DESIGNATED_DEV.load(Ordering::Acquire) == dev
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
    dev: DevId,
    inner: Arc<dyn BlockDeviceSync>,
    warned: AtomicBool,
}

impl core::fmt::Debug for PolicyGuard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PolicyGuard")
            .field("name", &self.name)
            .field("disk", &self.disk)
            .field("dev", &self.dev)
            .finish_non_exhaustive()
    }
}

impl PolicyGuard {
    /// Wrap `inner`; the guard gets a fresh, never-reused [`DevId`].
    pub fn new(name: &'static str, disk: DiskId, inner: Arc<dyn BlockDeviceSync>) -> Self {
        Self {
            name,
            disk,
            dev: new_dev_id(),
            inner,
            warned: AtomicBool::new(false),
        }
    }

    /// The disk this guard belongs to.
    pub fn disk(&self) -> DiskId {
        self.disk
    }

    /// This guard's registry-entry identity.
    pub fn dev_id(&self) -> DevId {
        self.dev
    }

    fn permits_write(&self) -> bool {
        match policy() {
            DiskPolicy::All => true,
            DiskPolicy::BootOnly => disk_trusted(self.disk),
            DiskPolicy::RootRo => false,
            DiskPolicy::RootRw => dev_writable(self.dev),
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
            let policy = policy();
            let why = match policy {
                DiskPolicy::BootOnly => "it is not the boot medium",
                DiskPolicy::RootRo => "nothing is writable",
                _ => "it is not the designated root partition",
            };
            let _ = writeln!(
                narf_console::Writer,
                "disks: refused write to {} (lba {lba}, {n_blocks} blocks): \
                 {ARG}={} and {why}; further refusals are silent",
                self.name,
                policy.as_str(),
            );
        }
        Err(BlockIoError::ReadOnly)
    }
}

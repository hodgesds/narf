//! Which btrfs filesystems the in-kernel test workloads may write.
//!
//! The boot-time read/write smokes (`narf.btrfs_smoke`), the crash smoke
//! (`narf.btrfs_crash=`) and the root-rw interop workload
//! (`narf.rootrw_interop=`) all mutate a btrfs filesystem. Their command-line
//! flags are not enough of a guard on their own: a mistyped or copied command
//! line on a bare-metal host whose root is btrfs would point them at real
//! data. So each workload also requires that the filesystem it is about to
//! touch carries a harness marker — an fsid only xtask's own fixture builders
//! produce — and the smokes, which never run on the root, refuse the
//! filesystem the command line names as `root=UUID=` outright.

use alloc::string::String;
use alloc::sync::Arc;

use narf_block::BlockDeviceSync;

/// fsid prefix of every whole-system harness image xtask builds
/// (`btrfs-rootrw-interop`, `cachyos-root-smoke`, `cachyos-gate`, the
/// snapshot fixture): `c4c405ee-0000-4a11-9e57-…`.
pub const HARNESS_FSID_PREFIX: &str = "c4c405ee-0000-4a11-9e57-";

/// fsids of the committed `testdata/` fixtures xtask serves on nvme0 to the
/// boot-time smokes (`fixture-bitmap`, `fixture-bgt`, `fixture-tall`).
pub const FIXTURE_FSIDS: &[&str] = &[
    "78fa8eab-8bfc-4252-b88b-aa552ffa3e01",
    "5f8d956b-6df0-4b2a-b9f5-553fd9adc10f",
    "4f3892c4-269c-4188-90c1-4a459a979daf",
];

/// Whether `fsid` (canonical lowercase) is one of xtask's disposable images.
pub fn is_harness_fsid(fsid: &str) -> bool {
    fsid.starts_with(HARNESS_FSID_PREFIX) || FIXTURE_FSIDS.contains(&fsid)
}

/// The `root=UUID=` the kernel command line names, lowercased.
pub fn cmdline_root_uuid() -> Option<String> {
    let root = narf_boot::args().value("root")?;
    let uuid = root.strip_prefix("UUID=")?;
    Some(uuid.to_ascii_lowercase())
}

/// The btrfs fsid on `dev` (canonical lowercase), or `None` if it holds no
/// btrfs superblock.
pub fn btrfs_fsid(dev: &dyn BlockDeviceSync) -> Option<String> {
    const SB: u64 = 0x1_0000;
    let lba = dev.lba_size() as u64;
    if lba == 0 || SB % lba != 0 || lba > 4096 {
        return None;
    }
    let mut sb = alloc::vec![0u8; lba as usize];
    dev.read(SB / lba, 1, &mut sb).ok()?;
    if sb.get(0x40..0x48) != Some(b"_BHRfS_M".as_slice()) {
        return None;
    }
    let fsid: [u8; 16] = sb.get(0x20..0x30)?.try_into().ok()?;
    Some(narf_block::partition::format_uuid_bytes(&fsid).to_ascii_lowercase())
}

/// The verdict for a test workload that is about to write `fsid`. `on_root`
/// is true for the interop workload, whose whole point is to write the
/// harness image mounted as `/`; the smokes must never touch the root.
/// Pure: the unit of the refusal tests.
pub fn check_disposable(
    fsid: &str,
    root_uuid: Option<&str>,
    on_root: bool,
) -> Result<(), &'static str> {
    if !is_harness_fsid(fsid) {
        return Err("filesystem carries no xtask harness marker (fsid)");
    }
    if !on_root && root_uuid.is_some_and(|root| root.eq_ignore_ascii_case(fsid)) {
        return Err("filesystem is the root=UUID= named on the command line");
    }
    Ok(())
}

/// [`check_disposable`] for the btrfs on `dev`, logging a refusal.
pub fn device_is_disposable(dev: &Arc<dyn BlockDeviceSync>, what: &str, on_root: bool) -> bool {
    use core::fmt::Write as _;
    let Some(fsid) = btrfs_fsid(&**dev) else {
        return false;
    };
    match check_disposable(&fsid, cmdline_root_uuid().as_deref(), on_root) {
        Ok(()) => true,
        Err(why) => {
            let _ = writeln!(
                narf_console::Writer,
                "  {what}: REFUSING to write btrfs {fsid}: {why}"
            );
            false
        }
    }
}

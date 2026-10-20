//! Mounting and reading a btrfs image through NARF the way a
//! `narf.disks=root-rw` boot does.
//!
//! The kernel's root path (`narf_filesystem::root_mount`) registers the
//! partition in the block registry (where every device is wrapped in the
//! `narf.disks` guard), designates it as the root after re-verifying its
//! `root=UUID=`, plans the mount from the command line (`plan_root`), and
//! builds the root through the named `btrfs` constructor with `rootflags=`.
//! systemd then mounts the other fstab subvolumes (`@home`) through the same
//! constructor, which hands back views over one shared core. This module
//! does exactly those calls, minus attaching the result to a VFS mount tree.

use std::collections::BTreeMap;
use std::sync::Arc;

use narf_block::disk_policy::{self, DiskPolicy};
use narf_block::BlockDeviceSync;
use narf_filesystem::{DirOps, FileOps, FileType, FsError, FsInstance};

use crate::host::block_on;
use crate::model::{Flat, FlatTree};

/// Registry name of the partition (the shape of the user's NVMe root).
pub const PART: &str = "nvme0n1p2";
/// CachyOS's fstab options for `/` and `/home` (minus `subvol=`).
pub const FSTAB_OPTS: &str = "noatime,compress=zstd:1,space_cache=v2,discard=async";

pub fn uuid_string(fsid: &[u8; 16]) -> String {
    narf_block::partition::format_uuid_bytes(fsid).to_ascii_lowercase()
}

/// Forget every registration, designation and mounted core from a previous
/// mount, so each mount starts from a fresh boot's state.
pub fn reset() {
    narf_block::registry::__reset_for_test();
    disk_policy::__reset_root_for_test();
    disk_policy::__set_policy_for_test(Some(DiskPolicy::RootRw));
}

/// Register `dev` as the root partition and designate it (`root=UUID=`).
pub fn register_root(dev: Arc<dyn BlockDeviceSync>, fsid: &[u8; 16]) -> Result<(), String> {
    use std::sync::Once;
    static FSTYPES: Once = Once::new();
    FSTYPES.call_once(narf_drivers_fs_btrfs::register_fstypes);
    reset();
    let uuid = uuid_string(fsid);
    disk_policy::__set_root_arg_for_test(Some(Some(&format!("UUID={uuid}"))));
    narf_block::register_partition_device(
        PART,
        "nvme0n1",
        dev,
        Some(narf_block::registry::PartitionMetadata {
            fs_uuid: uuid.clone(),
            partlabel: "root".into(),
            ..Default::default()
        }),
    );
    disk_policy::designate_root(PART, *fsid).map_err(|e| format!("designate_root: {e:?}"))
}

/// The root mount `try_mount_root` performs for
/// `root=UUID=<fsid> rootflags=subvol=/<subvol>,<opts> rw` under
/// `narf.disks=root-rw` with systemd as PID 1, followed by fstab mounts of
/// `others`. Returns one filesystem instance per subvolume, root first.
pub fn mount_root_rw(
    fsid: &[u8; 16],
    root_subvol: &str,
    others: &[&str],
) -> Result<Vec<Arc<dyn FsInstance>>, String> {
    let uuid = uuid_string(fsid);
    let cmdline = format!("root=UUID={uuid} rootflags=subvol=/{root_subvol},{FSTAB_OPTS} rw");
    let spec = narf_filesystem::root_selector::RootSpec::from_cmdline(&cmdline);
    let plan = narf_filesystem::root_mount::plan_root(DiskPolicy::RootRw, true, &spec);
    if plan.read_only || plan.tmpfs_overlay || !plan.designate {
        return Err(format!("unexpected root-rw plan {plan:?}"));
    }
    let fstype = narf_filesystem::lookup_fstype("btrfs").ok_or("btrfs fstype not registered")?;
    let source = format!("/dev/{PART}");
    let mount = |options: &str, read_only: bool| {
        fstype.init(&narf_filesystem::MountRequest {
            fs_type: "btrfs",
            source: &source,
            options,
            uid: 0,
            gid: 0,
            umask: 0o022,
            initial_namespace: true,
            read_only,
        })
    };
    let mut out = Vec::new();
    let root = mount(plan.flags.as_deref().unwrap_or(""), plan.read_only).map_err(|e| {
        format!(
            "root mount: {e:?}; refusal: {:?}; klog:\n{}",
            narf_drivers_fs_btrfs::rw_gate::last_refusal(),
            crate::host::klog_take()
        )
    })?;
    if root.always_read_only() {
        return Err("root mounted read-only".into());
    }
    out.push(root);
    for sv in others {
        let fs = mount(&format!("subvol=/{sv},{FSTAB_OPTS}"), false)
            .map_err(|e| format!("fstab mount of {sv}: {e:?}"))?;
        out.push(fs);
    }
    Ok(out)
}

/// Resolve the directory at `path` (relative to `root`).
pub async fn dir_at(root: &Arc<dyn DirOps>, path: &str) -> Result<Arc<dyn DirOps>, FsError> {
    let mut d = root.clone();
    for c in path.split('/').filter(|c| !c.is_empty()) {
        d = d.lookup_dir_async(c).await?;
    }
    Ok(d)
}

/// Split `path` into (parent dir path, name).
pub fn split(path: &str) -> (&str, &str) {
    match path.rsplit_once('/') {
        Some((p, n)) => (p, n),
        None => ("", path),
    }
}

pub async fn file_at(root: &Arc<dyn DirOps>, path: &str) -> Result<Arc<dyn FileOps>, FsError> {
    let (p, n) = split(path);
    dir_at(root, p).await?.lookup_async(n).await
}

pub async fn read_all(f: &Arc<dyn FileOps>) -> Result<Vec<u8>, FsError> {
    let size = f.stat_async().await?.size as usize;
    let mut buf = vec![0u8; size + 4096];
    let mut done = 0;
    while done < buf.len() {
        let n = f.read(done as u64, &mut buf[done..]).await?;
        if n == 0 {
            break;
        }
        done += n;
    }
    buf.truncate(done);
    Ok(buf)
}

pub async fn xattrs_of(f: &Arc<dyn FileOps>) -> Result<BTreeMap<String, Vec<u8>>, FsError> {
    let mut out = BTreeMap::new();
    let names = f.list_xattr().await?;
    for name in names.split(|&b| b == 0).filter(|n| !n.is_empty()) {
        let name = String::from_utf8_lossy(name).into_owned();
        // Only the namespace the workload owns: `security.*`/`system.*`
        // entries (SELinux labels, POSIX ACLs) are not modelled.
        if !name.starts_with("user.") {
            continue;
        }
        let v = f.get_xattr(&name).await?;
        out.insert(name, v);
    }
    Ok(out)
}

/// The root directory inode number every subvolume tree uses
/// (`BTRFS_FIRST_FREE_OBJECTID`); a directory entry resolving to it is a
/// nested subvolume, not part of this tree.
const SUBVOL_ROOT_INO: u64 = 256;

/// Read the whole tree under `root` (nested subvolumes excluded: their names
/// are returned separately).
pub fn walk(root: &Arc<dyn DirOps>) -> Result<(FlatTree, Vec<String>), String> {
    block_on(async {
        let mut tree = FlatTree::new();
        let mut nested = Vec::new();
        let mut stack: Vec<(String, Arc<dyn DirOps>)> = vec![(String::new(), root.clone())];
        while let Some((path, dir)) = stack.pop() {
            let entries = dir
                .enumerate_async(0, usize::MAX)
                .await
                .map_err(|e| format!("readdir {path:?}: {e:?}"))?;
            for (name, ft) in entries {
                let p = if path.is_empty() {
                    name.clone()
                } else {
                    format!("{path}/{name}")
                };
                match ft {
                    FileType::Dir => {
                        let d = dir
                            .lookup_dir_async(&name)
                            .await
                            .map_err(|e| format!("lookup dir {p}: {e:?}"))?;
                        if d.ino() == SUBVOL_ROOT_INO {
                            nested.push(p);
                            continue;
                        }
                        tree.insert(
                            p.clone(),
                            Flat::Dir {
                                perms: d.dir_mode() & 0o7777,
                                xattrs: BTreeMap::new(),
                            },
                        );
                        stack.push((p, d));
                    }
                    FileType::File | FileType::Symlink => {
                        let f = dir
                            .lookup_async(&name)
                            .await
                            .map_err(|e| format!("lookup {p}: {e:?}"))?;
                        let data = read_all(&f).await.map_err(|e| format!("read {p}: {e:?}"))?;
                        if ft == FileType::Symlink {
                            tree.insert(
                                p,
                                Flat::Symlink(String::from_utf8_lossy(&data).into_owned()),
                            );
                        } else {
                            let xattrs = xattrs_of(&f)
                                .await
                                .map_err(|e| format!("xattrs {p}: {e:?}"))?;
                            tree.insert(
                                p,
                                Flat::File {
                                    data: Arc::new(data),
                                    perms: f.stat().mode.perms & 0o7777,
                                    xattrs,
                                },
                            );
                        }
                    }
                    other => return Err(format!("{p}: unexpected type {other:?}")),
                }
            }
        }
        Ok((tree, nested))
    })
}

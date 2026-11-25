//! Mounting and reading an ext4 image through NARF.
//!
//! The image is registered in the block registry as a partition (so every
//! write goes through the `narf.disks` guard, as on a boot) and mounted with
//! the named `ext4` constructor the root path and fstab mounts use.

use std::sync::Arc;

use narf_block::disk_policy::{self, DiskPolicy};
use narf_block::BlockDeviceSync;
use narf_filesystem::{DirOps, FileOps, FileType, FsError, FsInstance};

use crate::host::block_on;
use crate::model::{join, Model, Node};

/// Registry name of the partition (the shape of the user's NVMe root).
pub const PART: &str = "nvme0n1p2";

fn register_fstypes() {
    use std::sync::Once;
    static FSTYPES: Once = Once::new();
    FSTYPES.call_once(narf_drivers_fs_ext2::register_fstypes);
}

/// Mount `dev` read-write under `narf.disks=all` (every disk writable): a
/// fresh boot's registry, then the named `ext4` constructor.
pub fn mount(dev: Arc<dyn BlockDeviceSync>) -> Result<Arc<dyn FsInstance>, String> {
    register_fstypes();
    narf_block::registry::__reset_for_test();
    narf_drivers_fs_ext2::registry::__reset_for_test();
    disk_policy::__reset_root_for_test();
    disk_policy::__set_policy_for_test(Some(DiskPolicy::All));
    narf_block::register_partition_device(
        PART,
        "nvme0n1",
        dev,
        Some(narf_block::registry::PartitionMetadata {
            partlabel: "root".into(),
            ..Default::default()
        }),
    );
    let fstype = narf_filesystem::lookup_fstype("ext4").ok_or("ext4 fstype not registered")?;
    let source = format!("/dev/{PART}");
    let fs = fstype
        .init(&narf_filesystem::MountRequest {
            fs_type: "ext4",
            source: &source,
            options: "",
            uid: 0,
            gid: 0,
            umask: 0o022,
            initial_namespace: false,
            read_only: false,
        })
        .map_err(|e| format!("mount: {e:?}"))?;
    Ok(fs)
}

/// The directory at absolute `path`.
pub async fn dir_at(root: &Arc<dyn DirOps>, path: &str) -> Result<Arc<dyn DirOps>, FsError> {
    let mut dir = root.clone();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        dir = dir.lookup_dir_async(part).await?;
    }
    Ok(dir)
}

pub async fn read_all(f: &Arc<dyn FileOps>) -> Result<Vec<u8>, FsError> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(out.len() as u64, &mut buf).await?;
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(&buf[..n]);
    }
}

/// Everything NARF sees under the root, `lost+found` aside.
pub fn walk(root: &Arc<dyn DirOps>) -> Result<Model, String> {
    block_on(async {
        let mut m = Model::default();
        let mut stack: Vec<(String, Arc<dyn DirOps>)> = vec![("/".into(), root.clone())];
        while let Some((path, dir)) = stack.pop() {
            let entries = dir
                .enumerate_async(0, usize::MAX)
                .await
                .map_err(|e| format!("readdir {path}: {e:?}"))?;
            for (name, ft) in entries {
                if name == "." || name == ".." || (path == "/" && name == "lost+found") {
                    continue;
                }
                let p = join(&path, &name);
                match ft {
                    FileType::Dir => {
                        let d = dir
                            .lookup_dir_async(&name)
                            .await
                            .map_err(|e| format!("lookup dir {p}: {e:?}"))?;
                        m.nodes.insert(p.clone(), Node::Dir);
                        stack.push((p, d));
                    }
                    FileType::File | FileType::Symlink => {
                        let f = dir
                            .lookup_async(&name)
                            .await
                            .map_err(|e| format!("lookup {p}: {e:?}"))?;
                        let data = read_all(&f).await.map_err(|e| format!("read {p}: {e:?}"))?;
                        let node = if ft == FileType::Symlink {
                            Node::Symlink(String::from_utf8_lossy(&data).into_owned())
                        } else {
                            Node::File(data)
                        };
                        m.nodes.insert(p, node);
                    }
                    other => return Err(format!("{p}: unexpected type {other:?}")),
                }
            }
        }
        Ok(m)
    })
}

/// The image's filesystem UUID (`s_uuid`).
pub fn image_uuid(image: &std::path::Path) -> [u8; 16] {
    use std::os::unix::fs::FileExt;
    let f = std::fs::File::open(image).expect("open image");
    let mut uuid = [0u8; 16];
    f.read_exact_at(&mut uuid, 1024 + 0x68)
        .expect("read s_uuid");
    uuid
}

/// What a `narf.disks=root-rw root=UUID=<uuid> rw` boot does: register the
/// partition with its filesystem UUID, designate it as the root, then mount
/// it through the named `ext4` constructor with a read-write request.
pub fn mount_root_rw(
    dev: Arc<dyn BlockDeviceSync>,
    uuid: &[u8; 16],
) -> Result<Arc<dyn FsInstance>, FsError> {
    register_fstypes();
    narf_block::registry::__reset_for_test();
    narf_drivers_fs_ext2::registry::__reset_for_test();
    disk_policy::__reset_root_for_test();
    disk_policy::__set_policy_for_test(Some(DiskPolicy::RootRw));
    let text = narf_block::partition::format_uuid_bytes(uuid).to_ascii_lowercase();
    disk_policy::__set_root_arg_for_test(Some(Some(&format!("UUID={text}"))));
    narf_block::register_partition_device(
        PART,
        "nvme0n1",
        dev,
        Some(narf_block::registry::PartitionMetadata {
            fs_uuid: text,
            partlabel: "root".into(),
            ..Default::default()
        }),
    );
    disk_policy::designate_root(PART, *uuid).map_err(|_| FsError::PermissionDenied)?;
    let fstype = narf_filesystem::lookup_fstype("ext4").ok_or(FsError::NotFound)?;
    let source = format!("/dev/{PART}");
    fstype.init(&narf_filesystem::MountRequest {
        fs_type: "ext4",
        source: &source,
        options: "",
        uid: 0,
        gid: 0,
        umask: 0o022,
        initial_namespace: true,
        read_only: false,
    })
}

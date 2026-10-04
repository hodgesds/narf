//! Core filesystem constructors. Namespace-dependent backends register from
//! userspace; storage backends register from their driver crates.

use super::{FileSystemType, MountRequest};
use crate::{FsError, FsInstance};
use alloc::{sync::Arc, vec::Vec};

type Built = Result<Arc<dyn FsInstance>, FsError>;

fn tmpfs(r: &MountRequest<'_>) -> Built {
    Ok(Arc::new(crate::TmpFs::from_options(
        r.options, r.uid, r.gid,
    )?))
}
fn ramfs(r: &MountRequest<'_>) -> Built {
    Ok(Arc::new(crate::RamFs::from_options(
        r.options, r.uid, r.gid,
    )?))
}
fn devpts(r: &MountRequest<'_>) -> Built {
    Ok(Arc::new(crate::devfs_pty::DevPtsFs::from_options(
        r.options,
        r.uid,
        r.gid,
        r.initial_namespace,
    )?))
}
fn efivarfs(r: &MountRequest<'_>) -> Built {
    Ok(Arc::new(crate::EfivarFs::from_options(
        r.options, r.uid, r.gid,
    )?))
}
fn cgroup(_r: &MountRequest<'_>) -> Built {
    #[cfg(feature = "cgroup")]
    {
        Ok(Arc::new(crate::CgroupFs::new()))
    }
    #[cfg(not(feature = "cgroup"))]
    {
        Ok(Arc::new(crate::MemFs::new("cgroup2")))
    }
}

pub(super) fn types() -> Vec<FileSystemType> {
    let mut types = alloc::vec![
        FileSystemType::new("tmpfs", tmpfs),
        FileSystemType::new("shmfs", tmpfs),
        FileSystemType::new("shm", tmpfs),
        FileSystemType::new("ramfs", ramfs),
        FileSystemType::new("proc", |_| Ok(Arc::new(crate::procfs::ProcFs))),
        FileSystemType::new("procfs", |_| Ok(Arc::new(crate::procfs::ProcFs))),
        FileSystemType::new("sysfs", |_| Ok(Arc::new(crate::SysFs::new()))),
        FileSystemType::new("devtmpfs", |_| Ok(Arc::new(crate::DevFs::new()))),
        FileSystemType::new("devfs", |_| Ok(Arc::new(crate::DevFs::new()))),
        FileSystemType::new("cgroup2", cgroup),
        FileSystemType::new("cgroup", cgroup),
        FileSystemType::new("bpf", |_| Ok(Arc::new(crate::bpffs::BpfFs::new()))),
        FileSystemType::new("bpffs", |_| Ok(Arc::new(crate::bpffs::BpfFs::new()))),
        FileSystemType::new("devpts", devpts),
        FileSystemType::new("debugfs", |_| Ok(Arc::new(crate::debugfs::DebugFs::new()))),
        FileSystemType::new("efivarfs", efivarfs),
    ];
    // Existing compatibility placeholders remain explicitly registered. They
    // provide directories only, not the semantics of their Linux namesakes.
    types.push(FileSystemType::new("memfs", |_| {
        Ok(Arc::new(crate::MemFs::new("memfs")))
    }));
    types.push(FileSystemType::new("securityfs", |_| {
        Ok(Arc::new(crate::MemFs::new("securityfs")))
    }));
    types.push(FileSystemType::new("tracefs", |_| {
        Ok(Arc::new(crate::MemFs::new("tracefs")))
    }));
    types.push(FileSystemType::new("configfs", |_| {
        Ok(Arc::new(crate::MemFs::new("configfs")))
    }));
    types.push(FileSystemType::new("fusectl", |_| {
        Ok(Arc::new(crate::MemFs::new("fusectl")))
    }));
    types.push(FileSystemType::new("pstore", |_| {
        Ok(Arc::new(crate::MemFs::new("pstore")))
    }));
    types.push(FileSystemType::new("hugetlbfs", |_| {
        Ok(Arc::new(crate::MemFs::new("hugetlbfs")))
    }));
    types.push(FileSystemType::new("binfmt_misc", |_| {
        Ok(Arc::new(crate::MemFs::new("binfmt_misc")))
    }));
    types.push(FileSystemType::new("autofs", |_| {
        Ok(Arc::new(crate::MemFs::new("autofs")))
    }));
    types
}

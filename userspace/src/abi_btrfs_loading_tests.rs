//! The loader's writable-Btrfs cache sequence, through mmap/close/munmap and
//! the actual file-demand fault hook. No host disk is attached to this test.

use alloc::{sync::Arc, vec, vec::Vec};
use narf_block::ram::RamBlockDevice;
use narf_filesystem::{FileOps, FsInstance};
use narf_lib::{id::DomainId, sync::IrqSafeSpinLock};
use narf_memory::{AddressSpace, VirtAddr};

use crate::abi_test_support::*;

static LOADER_AS: IrqSafeSpinLock<Option<Arc<AddressSpace>>> = IrqSafeSpinLock::new(None);

fn address_space() -> Option<Arc<AddressSpace>> {
    LOADER_AS.lock().clone()
}

fn complete<T>(
    future: impl core::future::Future<Output = Result<T, narf_filesystem::FsError>>,
) -> Result<T, &'static str> {
    crate::handlers::poll_io_to_completion(future)
        .and_then(Result::ok)
        .ok_or("Btrfs fixture operation failed")
}

fn image() -> Result<Vec<u8>, &'static str> {
    // The syscall scenario needs a writable Btrfs inode, not a large contiguous
    // host-root image. The host tests separately cover the CachyOS BGT layout.
    let sparse = include_bytes!("../../drivers/fs/btrfs/testdata/fixture-fst.img.sparse");
    let size = u64::from_le_bytes(sparse[8..16].try_into().unwrap()) as usize;
    let mut image = Vec::new();
    image
        .try_reserve_exact(size)
        .map_err(|_| "fixture allocation failed")?;
    image.resize(size, 0);
    let mut cursor = 20;
    for _ in 0..u32::from_le_bytes(sparse[16..20].try_into().unwrap()) {
        let offset = u64::from_le_bytes(sparse[cursor..cursor + 8].try_into().unwrap()) as usize;
        let len = u64::from_le_bytes(sparse[cursor + 8..cursor + 16].try_into().unwrap()) as usize;
        cursor += 16;
        image[offset..offset + len].copy_from_slice(&sparse[cursor..cursor + len]);
        cursor += len;
    }
    Ok(image)
}

fn map_then_close(file: Arc<dyn FileOps>, len: u64) -> Result<u64, &'static str> {
    let fd = crate::fd::install(
        FAKE_TASK,
        crate::fd::FdEntry {
            ops: file,
            offset: 0,
            flags: 0,
            status_flags: crate::fd::O_RDONLY,
        },
    )
    .ok_or("fd install failed")?;
    let base = call(
        Syscall::Mmap.raw(),
        SyscallArgs {
            arg1: len,
            arg2: 1,
            arg3: 2,
            arg4: u64::from(fd),
            ..SyscallArgs::default()
        },
    )
    .filter(|&value| value > 0)
    .ok_or("private file mmap failed")? as u64;
    if call(
        Syscall::Close.raw(),
        SyscallArgs {
            arg0: u64::from(fd),
            ..SyscallArgs::default()
        },
    ) != Some(0)
    {
        return Err("fd close failed");
    }
    Ok(base)
}

fn fault_byte(space: &AddressSpace, va: u64) -> Result<u8, &'static str> {
    // SAFETY: the test owns this live user root and va is inside its mapping.
    unsafe { space.demand_alloc_page(VirtAddr::new(va)) }
        .map_err(|_| "loader's mapped file page was refused")?;
    let region = space
        .lookup(VirtAddr::new(va))
        .ok_or("fault lost the VMA")?;
    let page = ((va - region.base.as_u64()) >> 12) as usize;
    let phys = region
        .phys
        .get(page)
        .ok_or("fault did not install backing")?;
    // SAFETY: the VMA owns this resident frame, reached through the direct map.
    Ok(unsafe { phys.kernel_ptr::<u8>().add((va & 4095) as usize).read() })
}

fn smoke_btrfs_loader_private_map_survives_replacement() -> TestResult {
    with_setup(|| {
        // SAFETY: tests run after paging initialization; this test owns the root.
        let space = Arc::new(
            unsafe { AddressSpace::new_for_user() }.map_err(|_| "user root allocation failed")?,
        );
        *LOADER_AS.lock() = Some(space.clone());
        crate::handlers::install_address_space_lookup(address_space);
        let result = (|| {
            let vol = complete(narf_drivers_fs_btrfs::volume::BtrfsVolume::mount(
                RamBlockDevice::from_image(512, image()?),
                DomainId::DRIVER_0,
            ))?;
            let root = vol.root();
            let old = complete(root.create("loader-cache"))?;
            if complete(old.write(0, &vec![0x37; 8192]))? != 8192 {
                return Err("old cache seed was short");
            }
            let old_ino = old.ino();
            let old_base = map_then_close(old, 8192)?;
            let next = complete(root.create("loader-cache~"))?;
            if complete(next.write(0, &vec![0x59; 8192]))? != 8192 {
                return Err("new cache seed was short");
            }
            drop(next);
            complete(root.rename("loader-cache~", "loader-cache"))?;
            complete(root.syncfs())?;
            // First touch happens after replacement and after closing the fd.
            // The VMA alone must pin the old inode and its still-unfaulted data.
            if fault_byte(&space, old_base + 4096)? != 0x37 {
                return Err("old mapping read replacement bytes");
            }
            let fresh = complete(root.lookup_async("loader-cache"))?;
            if fresh.ino() == old_ino {
                return Err("replacement reused a still-mapped inode");
            }
            let fresh_base = map_then_close(fresh, 8192)?;
            if fault_byte(&space, fresh_base)? != 0x59 {
                return Err("new mapping read old cache bytes");
            }
            for base in [old_base, fresh_base] {
                if call(
                    Syscall::Munmap.raw(),
                    SyscallArgs {
                        arg0: base,
                        arg1: 8192,
                        ..SyscallArgs::default()
                    },
                ) != Some(0)
                {
                    return Err("private map teardown failed");
                }
            }
            complete(root.syncfs())?;
            let (fs_root, _) = vol.fs_tree_root();
            if complete(narf_drivers_fs_btrfs::btree::find_item(
                &vol,
                fs_root,
                &narf_drivers_fs_btrfs::format::BtrfsKey::new(
                    old_ino,
                    narf_drivers_fs_btrfs::format::INODE_ITEM_KEY,
                    0,
                ),
            ))?
            .is_some()
            {
                return Err("last unmap did not permit old inode reclamation");
            }
            Ok(())
        })();
        crate::handlers::restore_address_space_lookup(None);
        *LOADER_AS.lock() = None;
        result
    })
}
kernel_test_in!(
    "syscall_abi/btrfs_loading",
    smoke_btrfs_loader_private_map_survives_replacement
);

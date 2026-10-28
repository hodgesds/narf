//! File-loading contracts shared with ext4: replacement keeps the old open
//! inode alive, and independent opens observe one inode's current metadata.

use super::*;
use crate::host::block_on;
use narf_filesystem::{FileOps, FsInstance};

// The harness models one boot's block registry and scheduler.
static BOOT: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn fixture(name: &str) -> (PathBuf, Vec<Arc<dyn FsInstance>>) {
    host::init();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/btrfs-host-file-loading")
        .join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let image = dir.join("root.img");
    fixture::unsparse(&fixture::testdata().join("fixture-bgt.img.sparse"), &image);
    let (fsid, nodesize, _) = dev::image_identity(&image);
    let dev = Arc::new(RecDev::open(&image, 512, fsid, nodesize));
    narf::register_root(dev, &fsid).unwrap();
    (image, narf::mount_root_rw(&fsid, "@", &[]).unwrap())
}

async fn read_exact(file: &Arc<dyn FileOps>, expected: &[u8]) {
    let mut actual = vec![0; expected.len()];
    assert_eq!(file.read(0, &mut actual).await.unwrap(), actual.len());
    assert_eq!(actual, expected);
}

#[test]
fn replacement_preserves_open_cache_inode() {
    let _boot = BOOT.lock().unwrap_or_else(|e| e.into_inner());
    let (image, views) = fixture("replacement");
    let root = views[0].root();
    block_on(async {
        let old = root.create("ld.so.cache").await.unwrap();
        let old_data = vec![0x37; 187287];
        assert_eq!(old.write(0, &old_data).await.unwrap(), old_data.len());
        let reader = root.lookup_async("ld.so.cache").await.unwrap();
        let replacement = root.create("ld.so.cache~").await.unwrap();
        let new_data = vec![0x59; 187287];
        assert_eq!(
            replacement.write(0, &new_data).await.unwrap(),
            new_data.len()
        );
        root.rename("ld.so.cache~", "ld.so.cache").await.unwrap();
        let fresh = root.lookup_async("ld.so.cache").await.unwrap();
        assert_ne!(fresh.ino(), reader.ino());
        read_exact(&fresh, &new_data).await;
        read_exact(&reader, &old_data).await;
        assert_eq!(reader.statx_async(0, 0x7ff).await.unwrap().nlink, 0);
        root.syncfs().await.unwrap();
        read_exact(&reader, &old_data).await;
        // An unlinked open file remains writable, without touching its replacement.
        assert_eq!(old.write(8192, b"OLD!").await.unwrap(), 4);
        let mut page = [0; 4];
        assert_eq!(reader.read(8192, &mut page).await.unwrap(), 4);
        assert_eq!(&page, b"OLD!");
        read_exact(&fresh, &new_data).await;
        drop(old);
        drop(reader);
        root.syncfs().await.unwrap();
    });
    drop(root);
    drop(views);
    narf::reset();
    linux::check(&image, true).unwrap();
}

#[test]
fn independent_opens_share_size_changes() {
    let _boot = BOOT.lock().unwrap_or_else(|e| e.into_inner());
    let (image, views) = fixture("metadata");
    let root = views[0].root();
    block_on(async {
        let writer = root.create("library.so").await.unwrap();
        let reader = root.lookup_async("library.so").await.unwrap();
        let data = vec![0x7b; 12288];
        assert_eq!(writer.write(0, &data).await.unwrap(), data.len());
        assert_eq!(
            reader.stat().size,
            data.len() as u64,
            "first page must not fault against stale zero EOF"
        );
        assert_eq!(reader.stat_async().await.unwrap().size, data.len() as u64);
        writer.truncate(4096).await.unwrap();
        assert_eq!(
            reader.stat().size,
            4096,
            "a second open must observe a shrink"
        );
        assert_eq!(reader.statx_async(0, 0x7ff).await.unwrap().size, 4096);
        root.syncfs().await.unwrap();
    });
    drop(root);
    drop(views);
    narf::reset();
    linux::check(&image, true).unwrap();
}

#[test]
fn loader_style_symlinks_resolve_through_shared_vfs() {
    let _boot = BOOT.lock().unwrap_or_else(|e| e.into_inner());
    let (image, views) = fixture("symlinks");
    let root = views[0].root();
    block_on(async {
        let usr = root.mkdir("loader-usr").await.unwrap();
        let lib = usr.mkdir("lib").await.unwrap();
        let library = lib.create("libtest.so.1").await.unwrap();
        library.write(0, b"ELF-library").await.unwrap();
        lib.symlink("libtest.so", "libtest.so.1").await.unwrap();
        root.symlink("loader-lib", "loader-usr/lib").await.unwrap();
        root.symlink("loader-absolute", "/loader-usr/lib/libtest.so.1")
            .await
            .unwrap();
        for path in [
            "loader-lib/libtest.so",
            "loader-absolute",
            "loader-usr/lib/../lib/libtest.so",
        ] {
            let file = narf_filesystem::resolve_async(root.clone(), path)
                .await
                .unwrap();
            assert_eq!(file.ino(), library.ino());
            read_exact(&file, b"ELF-library").await;
        }
        root.syncfs().await.unwrap();
    });
    drop(root);
    drop(views);
    narf::reset();
    linux::check(&image, true).unwrap();
}

#[test]
fn unlinked_inode_is_recovered_after_a_crash() {
    let _boot = BOOT.lock().unwrap_or_else(|e| e.into_inner());
    let (image, views) = fixture("orphan-recovery");
    let crash = image.with_file_name("crash.img");
    let root = views[0].root();
    let ino = block_on(async {
        let file = root.create("open-at-crash").await.unwrap();
        file.write(0, &vec![0x41; 16384]).await.unwrap();
        let ino = file.ino();
        root.unlink("open-at-crash").await.unwrap();
        root.syncfs().await.unwrap();
        read_exact(&file, &vec![0x41; 16384]).await;
        // The durable copy contains nlink=0 plus ORPHAN_ITEM, as at power loss
        // with this process still holding the file. Later cleanup of `image`
        // cannot change this independent crash image.
        std::fs::copy(&image, &crash).unwrap();
        ino
    });
    drop(root);
    drop(views);
    narf::reset();
    linux::check(&crash, true).unwrap();
    let (fsid, nodesize, _) = dev::image_identity(&crash);
    let dev = Arc::new(RecDev::open(&crash, 512, fsid, nodesize));
    narf::register_root(dev, &fsid).unwrap();
    let views = narf::mount_root_rw(&fsid, "@", &[]).unwrap();
    let core = narf_drivers_fs_btrfs::registry::instance_for(&fsid).unwrap();
    let subvols = linux::subvolumes(&crash).unwrap();
    let tree = linux::subvol_id(&subvols, "@").unwrap();
    let vol = block_on(narf_drivers_fs_btrfs::volume::BtrfsVolume::mount_view(
        &core,
        Some(narf_drivers_fs_btrfs::volume::Subvol::Id(tree)),
        false,
    ))
    .unwrap();
    assert!(matches!(
        block_on(vol.load_inode(ino)),
        Err(narf_filesystem::FsError::NotFound)
    ));
    let (fs_root, _) = vol.fs_tree_root();
    assert!(block_on(narf_drivers_fs_btrfs::btree::find_item(
        &vol,
        fs_root,
        &narf_drivers_fs_btrfs::format::BtrfsKey::new((-5i64) as u64, 48, ino),
    ))
    .unwrap()
    .is_none());
    block_on(views[0].root().syncfs()).unwrap();
    drop(views);
    drop(vol);
    drop(core);
    narf::reset();
    linux::check(&crash, true).unwrap();
}

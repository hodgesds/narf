//! Writable overlay for driver-provided `/dev` subdirectories.
//!
//! `/dev/dri` and `/dev/snd` are served by delegates the GPU and sound
//! drivers install; those only resolve and list their own device nodes.
//! systemd-udevd also expects to manage the directory itself, as it does on
//! Linux devtmpfs: it creates `by-path`, stages each alias as a temporary
//! symlink and renames it into place (`udev-node.c`, `node_symlink`). A
//! delegate that cannot `mkdir` fails the first step, which reached udev as
//! `EPERM` and left `/dev/dri/by-path` and `/dev/snd/by-path` empty.
//!
//! [`DelegateDir`] keeps the driver's nodes authoritative and layers a
//! [`DynamicMap`] of runtime-created entries beside them. A runtime entry
//! may never take, shadow or replace a name the driver publishes.

use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};

use narf_lib::sync::IrqSafeSpinLock;

use super::{
    dynamic_enumerate, dynamic_lookup_dir, dynamic_lookup_file, dynamic_mkdir, dynamic_rename,
    dynamic_rmdir, dynamic_symlink, dynamic_unlink, DynamicMap,
};
use crate::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture};

/// Runtime-created entries of `/dev/dri`. Outlives delegate replacement.
pub(super) static DRI_DYNAMIC: IrqSafeSpinLock<DynamicMap> =
    IrqSafeSpinLock::new(alloc::collections::BTreeMap::new());

/// Runtime-created entries of `/dev/snd`. Outlives delegate replacement.
pub(super) static SND_DYNAMIC: IrqSafeSpinLock<DynamicMap> =
    IrqSafeSpinLock::new(alloc::collections::BTreeMap::new());

/// A driver's directory delegate plus the runtime entries beside it.
pub(super) struct DelegateDir {
    pub(super) inner: Arc<dyn DirOps>,
    pub(super) overlay: &'static IrqSafeSpinLock<DynamicMap>,
}

impl DelegateDir {
    /// `true` when the driver publishes `name`; such names are read-only.
    fn driver_owns(&self, name: &str) -> bool {
        self.inner.lookup(name).is_some() || self.inner.lookup_dir(name).is_some()
    }

    fn merged(&self, mut entries: Vec<(String, FileType)>) -> Vec<(String, FileType)> {
        for (name, file_type) in dynamic_enumerate(self.overlay) {
            if !entries.iter().any(|(existing, _)| *existing == name) {
                entries.push((name, file_type));
            }
        }
        entries
    }
}

impl DirOps for DelegateDir {
    fn ino(&self) -> u64 {
        self.inner.ino()
    }

    fn dir_mode(&self) -> u16 {
        self.inner.dir_mode()
    }

    fn dir_owners(&self) -> (u32, u32) {
        self.inner.dir_owners()
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        self.inner.as_any()
    }

    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        self.inner
            .lookup(name)
            .or_else(|| dynamic_lookup_file(self.overlay, name))
    }

    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        self.inner
            .lookup_dir(name)
            .or_else(|| dynamic_lookup_dir(self.overlay, name))
    }

    fn try_lookup(&self, name: &str) -> Result<Arc<dyn FileOps>, FsError> {
        match self.inner.try_lookup(name) {
            Err(FsError::NotFound) => {
                dynamic_lookup_file(self.overlay, name).ok_or(FsError::NotFound)
            }
            other => other,
        }
    }

    fn try_lookup_dir(&self, name: &str) -> Result<Arc<dyn DirOps>, FsError> {
        match self.inner.try_lookup_dir(name) {
            Err(FsError::NotFound) => {
                dynamic_lookup_dir(self.overlay, name).ok_or(FsError::NotFound)
            }
            other => other,
        }
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            match self.inner.lookup_async(name).await {
                Err(FsError::NotFound) => {
                    dynamic_lookup_file(self.overlay, name).ok_or(FsError::NotFound)
                }
                other => other,
            }
        })
    }

    fn lookup_dir_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            match self.inner.lookup_dir_async(name).await {
                Err(FsError::NotFound) => {
                    dynamic_lookup_dir(self.overlay, name).ok_or(FsError::NotFound)
                }
                other => other,
            }
        })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        Box::new(
            self.enumerate(0, usize::MAX)
                .into_iter()
                .map(|(name, file_type)| DirEntry {
                    name: alloc::borrow::Cow::Owned(name),
                    file_type,
                }),
        )
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        // Page after merging: the two sources have independent cursors.
        self.merged(self.inner.enumerate(0, usize::MAX))
            .into_iter()
            .skip(cursor)
            .take(max)
            .collect()
    }

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> FsFuture<'a, Vec<(String, FileType)>> {
        Box::pin(async move {
            let driver = match self.inner.enumerate_async(0, usize::MAX).await {
                Ok(entries) => entries,
                // A delegate without an async listing still has a sync one.
                Err(FsError::Unsupported) => self.inner.enumerate(0, usize::MAX),
                Err(error) => return Err(error),
            };
            Ok(self
                .merged(driver)
                .into_iter()
                .skip(cursor)
                .take(max)
                .collect())
        })
    }

    fn mkdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        let result = if self.driver_owns(name) {
            Err(FsError::Busy)
        } else {
            dynamic_mkdir(self.overlay, name, 0o755)
        };
        Box::pin(async move { result })
    }

    fn rmdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        let result = dynamic_rmdir(self.overlay, name);
        Box::pin(async move { result })
    }

    fn symlink<'a>(&'a self, name: &'a str, target: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        let result = if self.driver_owns(name) {
            Err(FsError::Busy)
        } else {
            dynamic_symlink(self.overlay, name, target)
        };
        Box::pin(async move { result })
    }

    fn unlink<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        let result = if self.driver_owns(name) {
            Err(FsError::Unsupported)
        } else {
            dynamic_unlink(self.overlay, name)
        };
        Box::pin(async move { result })
    }

    fn rename<'a>(&'a self, old_name: &'a str, new_name: &'a str) -> FsFuture<'a, ()> {
        let result = if self.driver_owns(old_name) {
            Err(FsError::Unsupported)
        } else if self.driver_owns(new_name) {
            Err(FsError::Busy)
        } else {
            dynamic_rename(self.overlay, old_name, new_name)
        };
        Box::pin(async move { result })
    }
}

/// Fixture and assertions shared by the `/dev/dri` and `/dev/snd` checks.
fn alias_publication_through(
    slot: &IrqSafeSpinLock<Option<Arc<dyn DirOps>>>,
    register: fn(Arc<dyn DirOps>),
    directory: &str,
    node: &'static str,
) -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;

    /// A driver delegate in its real shape: lookup and listing only.
    struct Driver(&'static str);
    impl DirOps for Driver {
        fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
            // Any node will do; only its presence under this name matters.
            (name == self.0).then(|| {
                Arc::new(super::DevSymlink {
                    target: String::from("driver-node"),
                    inode: 1,
                }) as Arc<dyn FileOps>
            })
        }
        fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
            Box::new(core::iter::once(DirEntry {
                name: alloc::borrow::Cow::Borrowed(self.0),
                file_type: FileType::Special,
            }))
        }
    }

    // Stand in for the real driver only for this test.
    let previous = slot.lock().clone();
    register(Arc::new(Driver(node)));
    let Some(dir) = super::DevDir.lookup_dir(directory) else {
        *slot.lock() = previous;
        return TestResult::Fail("delegate directory missing from /dev");
    };
    let result = (|| {
        // udev's first step, and the one that failed on hardware.
        let by_path = match narf_scheduler::block_on(dir.mkdir("by-path")) {
            Ok(by_path) => by_path,
            Err(_) => return TestResult::Fail("mkdir by-path refused"),
        };
        if !matches!(
            narf_scheduler::block_on(dir.mkdir("by-path")),
            Err(FsError::Busy)
        ) {
            return TestResult::Fail("second mkdir by-path did not report it exists");
        }
        if narf_scheduler::block_on(by_path.symlink("pci-0000:03:00.0-node", "../old")).is_err() {
            return TestResult::Fail("initial alias create failed");
        }
        let stage = match narf_scheduler::block_on(by_path.symlink(".#stage", "../new")) {
            Ok(stage) => stage,
            Err(_) => return TestResult::Fail("staged alias create failed"),
        };
        if narf_scheduler::block_on(by_path.rename(".#stage", "pci-0000:03:00.0-node")).is_err()
            || by_path.lookup(".#stage").is_some()
        {
            return TestResult::Fail("alias publication by rename failed");
        }
        // Resolve afresh from /dev, as a later open does.
        let Some(alias) = super::DevDir
            .lookup_dir(directory)
            .and_then(|fresh| fresh.lookup_dir("by-path"))
            .and_then(|fresh| fresh.lookup("pci-0000:03:00.0-node"))
        else {
            return TestResult::Fail("published alias missing after a fresh lookup");
        };
        let mut target = [0; 16];
        if alias.ino() != stage.ino()
            || !matches!(narf_scheduler::block_on(alias.read(0, &mut target)), Ok(n)
                if &target[..n] == b"../new")
        {
            return TestResult::Fail("alias lost its target or inode during rename");
        }
        // The driver's node stays visible, authoritative and unshadowed.
        let listed = dir.enumerate(0, usize::MAX);
        if listed.iter().filter(|(name, _)| name == node).count() != 1
            || listed.iter().filter(|(name, _)| name == "by-path").count() != 1
            || dir.lookup(node).is_none()
        {
            return TestResult::Fail("listing does not show the driver node and by-path once each");
        }
        if narf_scheduler::block_on(dir.mkdir(node)).is_ok()
            || narf_scheduler::block_on(dir.symlink(node, "elsewhere")).is_ok()
            || narf_scheduler::block_on(dir.unlink(node)).is_ok()
        {
            return TestResult::Fail("a driver-owned name could be replaced or removed");
        }
        if narf_scheduler::block_on(dir.symlink(".#shadow", "elsewhere")).is_err()
            || narf_scheduler::block_on(dir.rename(".#shadow", node)).is_ok()
        {
            return TestResult::Fail("rename could shadow a driver-owned name");
        }
        TestResult::Pass
    })();
    if let Some(by_path) = dir.lookup_dir("by-path") {
        let _ = narf_scheduler::block_on(by_path.unlink("pci-0000:03:00.0-node"));
        let _ = narf_scheduler::block_on(by_path.unlink(".#stage"));
    }
    let _ = narf_scheduler::block_on(dir.unlink(".#shadow"));
    let _ = narf_scheduler::block_on(dir.rmdir("by-path"));
    *slot.lock() = previous;
    result
}

fn smoke_dri_alias_atomic_udev_publication() -> narf_kernel_test::TestResult {
    alias_publication_through(&super::DRI_DIR, super::register_dri_dir, "dri", "card0")
}
narf_kernel_test::kernel_test_in!(
    "filesystem/devfs_alias",
    smoke_dri_alias_atomic_udev_publication
);

fn smoke_snd_alias_atomic_udev_publication() -> narf_kernel_test::TestResult {
    alias_publication_through(&super::SND_DIR, super::register_snd_dir, "snd", "controlC0")
}
narf_kernel_test::kernel_test_in!(
    "filesystem/devfs_alias",
    smoke_snd_alias_atomic_udev_publication
);

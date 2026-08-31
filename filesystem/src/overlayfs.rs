//! Linux-compatible union filesystem core.
//!
//! NARF uses regular `.wh.<name>` marker files because not every writable
//! backend can create Linux overlayfs's character-device/xattr whiteouts.
//! The markers are an internal representation and are never exposed through
//! the merged view. `.wh..wh..opq` provides opaque-directory semantics.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::fmt;

use narf_lib::sync::IrqSafeSpinLock;

use crate::{
    DirEntry, DirOps, FileLock, FileOps, FileType, FsError, FsFuture, FsInstance, FsIoctlReply,
    FsMappingRange, FsStatx, Stat,
};

/// Prefix used by NARF's backing-store whiteout representation.
pub const WHITEOUT_PREFIX: &str = ".wh.";
/// Marker stored inside an opaque directory.
pub const OPAQUE_MARKER: &str = ".wh..wh..opq";

const COPY_CHUNK_SIZE: usize = 64 * 1024;

fn whiteout_name(name: &str) -> String {
    let mut value = String::with_capacity(WHITEOUT_PREFIX.len() + name.len());
    value.push_str(WHITEOUT_PREFIX);
    value.push_str(name);
    value
}

fn valid_visible_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.starts_with(WHITEOUT_PREFIX)
}

fn has_whiteout(dir: &dyn DirOps, name: &str) -> bool {
    dir.lookup(&whiteout_name(name)).is_some()
}

fn is_opaque(dir: &dyn DirOps) -> bool {
    dir.lookup(OPAQUE_MARKER).is_some()
}

/// Lazily materialized upper-directory path. Each lower-only descendant has
/// one slot pointing at its parent slot; a mutation walks to the nearest
/// existing upper ancestor and creates the missing directory chain.
struct UpperDir {
    dir: IrqSafeSpinLock<Option<Arc<dyn DirOps>>>,
    parent: Option<Arc<UpperDir>>,
    name: Option<String>,
    lower_metadata: Option<Arc<dyn DirOps>>,
}

impl UpperDir {
    fn root(dir: Option<Arc<dyn DirOps>>) -> Arc<Self> {
        Arc::new(Self {
            dir: IrqSafeSpinLock::new(dir),
            parent: None,
            name: None,
            lower_metadata: None,
        })
    }

    fn child(
        parent: Arc<Self>,
        name: &str,
        dir: Option<Arc<dyn DirOps>>,
        lower_metadata: Option<Arc<dyn DirOps>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            dir: IrqSafeSpinLock::new(dir),
            parent: Some(parent),
            name: Some(name.to_string()),
            lower_metadata,
        })
    }

    fn get(&self) -> Option<Arc<dyn DirOps>> {
        self.dir.lock().clone()
    }

    fn publish(&self, candidate: Arc<dyn DirOps>) -> Arc<dyn DirOps> {
        let mut slot = self.dir.lock();
        if let Some(existing) = slot.as_ref() {
            return Arc::clone(existing);
        }
        *slot = Some(Arc::clone(&candidate));
        candidate
    }

    fn ensure<'a>(self: &'a Arc<Self>) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            if let Some(dir) = self.get() {
                return Ok(dir);
            }

            let mut missing: Vec<(Arc<UpperDir>, String)> = Vec::new();
            let mut cursor = Arc::clone(self);
            let mut parent_dir = loop {
                if let Some(dir) = cursor.get() {
                    break dir;
                }
                let parent = cursor.parent.as_ref().ok_or(FsError::ReadOnly)?;
                let name = cursor.name.as_ref().ok_or(FsError::ReadOnly)?.clone();
                missing.push((Arc::clone(&cursor), name));
                cursor = Arc::clone(parent);
            };

            for (slot, name) in missing.into_iter().rev() {
                if let Some(existing) = slot.get() {
                    parent_dir = existing;
                    continue;
                }
                let created = match parent_dir.mkdir(&name).await {
                    Ok(dir) => dir,
                    Err(FsError::Busy) => parent_dir
                        .lookup_dir_async(&name)
                        .await
                        .map_err(|_| FsError::Busy)?,
                    Err(error) => return Err(error),
                };
                if let Some(lower) = slot.lower_metadata.as_ref() {
                    created.set_dir_mode_async(lower.dir_mode()).await?;
                    let (uid, gid) = lower.dir_owners();
                    created.set_dir_owners_async(uid, gid).await?;
                }
                parent_dir = slot.publish(created);
            }
            Ok(parent_dir)
        })
    }
}

/// A mounted overlay. A missing upper creates Linux's read-only lower-only
/// form; attempts to mutate it return `ReadOnly`.
pub struct OverlayFs {
    name: &'static str,
    upper: Option<Arc<dyn DirOps>>,
    lowers: Vec<Arc<dyn DirOps>>,
    mount_id: Arc<()>,
}

impl fmt::Debug for OverlayFs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OverlayFs")
            .field("name", &self.name)
            .field("writable", &self.upper.is_some())
            .field("lowers", &self.lowers.len())
            .finish()
    }
}

impl OverlayFs {
    /// Construct a writable overlay. `lowers[0]` has the highest priority.
    pub fn new(name: &'static str, upper: Arc<dyn DirOps>, lowers: Vec<Arc<dyn DirOps>>) -> Self {
        Self::from_layers(name, Some(upper), lowers)
    }

    /// Construct a read-only overlay from lower layers.
    pub fn new_read_only(name: &'static str, lowers: Vec<Arc<dyn DirOps>>) -> Self {
        Self::from_layers(name, None, lowers)
    }

    fn from_layers(
        name: &'static str,
        upper: Option<Arc<dyn DirOps>>,
        mut lowers: Vec<Arc<dyn DirOps>>,
    ) -> Self {
        if let Some(opaque) = lowers.iter().position(|lower| is_opaque(lower.as_ref())) {
            lowers.truncate(opaque + 1);
        }
        Self {
            name,
            upper,
            lowers,
            mount_id: Arc::new(()),
        }
    }
}

impl FsInstance for OverlayFs {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::new(OverlayDir {
            upper: UpperDir::root(self.upper.clone()),
            lowers: self.lowers.clone(),
            mount_id: Arc::clone(&self.mount_id),
            writable: self.upper.is_some(),
        })
    }

    fn name(&self) -> &str {
        self.name
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum LayerKind {
    File,
    Dir,
}

struct OverlayDir {
    upper: Arc<UpperDir>,
    lowers: Vec<Arc<dyn DirOps>>,
    mount_id: Arc<()>,
    writable: bool,
}

struct ChildLayers {
    upper: Option<Arc<dyn DirOps>>,
    lowers: Vec<Arc<dyn DirOps>>,
}

impl fmt::Debug for OverlayDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OverlayDir")
            .field("upper_present", &self.upper.get().is_some())
            .field("lowers", &self.lowers.len())
            .finish()
    }
}

impl OverlayDir {
    fn upper_dir(&self) -> Option<Arc<dyn DirOps>> {
        self.upper.get()
    }

    fn lower_kind(&self, name: &str) -> Option<LayerKind> {
        for lower in &self.lowers {
            if has_whiteout(lower.as_ref(), name) {
                return None;
            }
            if lower.lookup(name).is_some() {
                return Some(LayerKind::File);
            }
            if lower.lookup_dir(name).is_some() {
                return Some(LayerKind::Dir);
            }
        }
        None
    }

    fn lower_file(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        for lower in &self.lowers {
            if has_whiteout(lower.as_ref(), name) || lower.lookup_dir(name).is_some() {
                return None;
            }
            if let Some(file) = lower.lookup(name) {
                return Some(file);
            }
        }
        None
    }

    async fn remove_whiteout(&self, upper: &dyn DirOps, name: &str) -> Result<(), FsError> {
        if has_whiteout(upper, name) {
            match upper.unlink(&whiteout_name(name)).await {
                Ok(()) | Err(FsError::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    async fn create_whiteout(&self, upper: &dyn DirOps, name: &str) -> Result<(), FsError> {
        match upper.create(&whiteout_name(name)).await {
            Ok(_) | Err(FsError::Busy) => Ok(()),
            Err(error) => Err(error),
        }
    }

    async fn copy_up_file(&self, name: &str) -> Result<Arc<dyn FileOps>, FsError> {
        if let Some(upper) = self.upper_dir() {
            if let Some(file) = upper.lookup(name) {
                return Ok(file);
            }
        }
        let lower = self.lower_file(name).ok_or(FsError::NotFound)?;
        OverlayFile::new(Arc::clone(&self.upper), name.to_string(), lower)
            .ensure_copied_up()
            .await
    }

    fn child_layers(&self, name: &str) -> Option<ChildLayers> {
        let upper = self.upper_dir();
        if upper.as_ref().and_then(|dir| dir.lookup(name)).is_some() {
            return None;
        }
        let upper_child = upper.as_ref().and_then(|dir| dir.lookup_dir(name));
        if upper_child.is_none()
            && upper
                .as_ref()
                .is_some_and(|dir| has_whiteout(dir.as_ref(), name))
        {
            return None;
        }

        let mut children = Vec::new();
        let upper_opaque = upper_child
            .as_ref()
            .is_some_and(|dir| is_opaque(dir.as_ref()));
        if !upper_opaque {
            for lower in &self.lowers {
                if has_whiteout(lower.as_ref(), name) || lower.lookup(name).is_some() {
                    break;
                }
                if let Some(dir) = lower.lookup_dir(name) {
                    let opaque = is_opaque(dir.as_ref());
                    children.push(dir);
                    if opaque {
                        break;
                    }
                }
            }
        }
        if upper_child.is_none() && children.is_empty() {
            None
        } else {
            Some(ChildLayers {
                upper: upper_child,
                lowers: children,
            })
        }
    }

    async fn prepare_create(&self, name: &str) -> Result<Arc<dyn DirOps>, FsError> {
        if !valid_visible_name(name) {
            return Err(FsError::InvalidPath);
        }
        if self.lookup(name).is_some() || self.lookup_dir(name).is_some() {
            return Err(FsError::Busy);
        }
        let upper = self.upper.ensure().await?;
        self.remove_whiteout(upper.as_ref(), name).await?;
        Ok(upper)
    }

    async fn prepare_destination(&self, name: &str) -> Result<Arc<dyn DirOps>, FsError> {
        if !valid_visible_name(name) {
            return Err(FsError::InvalidPath);
        }
        let upper = self.upper.ensure().await?;
        self.remove_whiteout(upper.as_ref(), name).await?;
        Ok(upper)
    }

    async fn remove_entry(&self, name: &str, directory: bool) -> Result<(), FsError> {
        if !valid_visible_name(name) {
            return Err(FsError::InvalidPath);
        }
        let visible_dir = self.lookup_dir(name);
        let visible_file = self.lookup(name);
        if directory {
            let child = visible_dir.ok_or_else(|| {
                if visible_file.is_some() {
                    FsError::InvalidPath
                } else {
                    FsError::NotFound
                }
            })?;
            if !child.enumerate(0, 1).is_empty() {
                return Err(FsError::Busy);
            }
        } else if visible_file.is_none() {
            return Err(if visible_dir.is_some() {
                FsError::InvalidPath
            } else {
                FsError::NotFound
            });
        }

        let lower_positive = self.lower_kind(name).is_some();
        let upper = self.upper.ensure().await?;
        if directory {
            if let Some(raw_child) = upper.lookup_dir(name) {
                // An empty merged directory may contain only internal markers.
                for (marker, _) in raw_child.enumerate(0, usize::MAX) {
                    if marker.starts_with(WHITEOUT_PREFIX) {
                        raw_child.unlink(&marker).await?;
                    }
                }
                upper.rmdir(name).await?;
            }
        } else if upper.lookup(name).is_some() {
            upper.unlink(name).await?;
        }
        if lower_positive {
            self.create_whiteout(upper.as_ref(), name).await?;
        }
        Ok(())
    }
}

impl DirOps for OverlayDir {
    fn ino(&self) -> u64 {
        self.upper_dir().map_or_else(
            || self.lowers.first().map_or(0, |dir| dir.ino()),
            |dir| dir.ino(),
        )
    }

    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        if !valid_visible_name(name) {
            return None;
        }
        if let Some(upper) = self.upper_dir() {
            if let Some(file) = upper.lookup(name) {
                return Some(file);
            }
            if upper.lookup_dir(name).is_some() || has_whiteout(upper.as_ref(), name) {
                return None;
            }
        }
        self.lower_file(name).map(|file| {
            Arc::new(OverlayFile::new(
                Arc::clone(&self.upper),
                name.to_string(),
                file,
            )) as Arc<dyn FileOps>
        })
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { self.lookup(name).ok_or(FsError::NotFound) })
    }

    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        if !valid_visible_name(name) {
            return None;
        }
        let child = self.child_layers(name)?;
        let metadata = child.lowers.first().cloned();
        Some(Arc::new(OverlayDir {
            upper: UpperDir::child(Arc::clone(&self.upper), name, child.upper, metadata),
            lowers: child.lowers,
            mount_id: Arc::clone(&self.mount_id),
            writable: self.writable,
        }))
    }

    fn lookup_dir_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move { self.lookup_dir(name).ok_or(FsError::NotFound) })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        let mut merged = BTreeMap::new();
        let mut hidden = BTreeSet::new();
        let mut layers = Vec::new();
        if let Some(upper) = self.upper_dir() {
            layers.push(upper);
        }
        layers.extend(self.lowers.iter().cloned());

        for layer in layers {
            let entries = layer.enumerate(0, usize::MAX);
            let mut opaque = false;
            for (name, _) in &entries {
                if name == OPAQUE_MARKER {
                    opaque = true;
                } else if let Some(target) = name.strip_prefix(WHITEOUT_PREFIX) {
                    hidden.insert(target.to_string());
                }
            }
            for (name, file_type) in entries {
                if name.starts_with(WHITEOUT_PREFIX)
                    || hidden.contains(&name)
                    || merged.contains_key(&name)
                {
                    continue;
                }
                merged.insert(name, file_type);
            }
            if opaque {
                break;
            }
        }
        merged.into_iter().skip(cursor).take(max).collect()
    }

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> FsFuture<'a, Vec<(String, FileType)>> {
        Box::pin(async move { Ok(self.enumerate(cursor, max)) })
    }

    fn dir_mode(&self) -> u16 {
        self.upper_dir().map_or_else(
            || self.lowers.first().map_or(0o755, |dir| dir.dir_mode()),
            |dir| dir.dir_mode(),
        )
    }

    fn set_dir_mode(&self, perms: u16) {
        if let Some(upper) = self.upper_dir() {
            upper.set_dir_mode(perms);
        }
    }

    fn set_dir_mode_async<'a>(&'a self, perms: u16) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let upper = self.upper.ensure().await?;
            upper.set_dir_mode_async(perms).await
        })
    }

    fn dir_owners(&self) -> (u32, u32) {
        self.upper_dir().map_or_else(
            || self.lowers.first().map_or((0, 0), |dir| dir.dir_owners()),
            |dir| dir.dir_owners(),
        )
    }

    fn set_dir_owners(&self, uid: u32, gid: u32) {
        if let Some(upper) = self.upper_dir() {
            upper.set_dir_owners(uid, gid);
        }
    }

    fn set_dir_owners_async<'a>(&'a self, uid: u32, gid: u32) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let upper = self.upper.ensure().await?;
            upper.set_dir_owners_async(uid, gid).await
        })
    }

    fn fsync<'a>(&'a self, data_only: bool) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if let Some(upper) = self.upper_dir() {
                upper.fsync(data_only).await
            } else if let Some(lower) = self.lowers.first() {
                lower.fsync(data_only).await
            } else {
                Ok(())
            }
        })
    }

    fn syncfs<'a>(&'a self) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if let Some(upper) = self.upper_dir() {
                upper.syncfs().await
            } else if let Some(lower) = self.lowers.first() {
                lower.syncfs().await
            } else {
                Ok(())
            }
        })
    }

    fn unlink<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move { self.remove_entry(name, false).await })
    }

    fn create<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let upper = self.prepare_create(name).await?;
            upper.create(name).await
        })
    }

    fn create_socket<'a>(&'a self, name: &'a str, perms: u16) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let upper = self.prepare_create(name).await?;
            upper.create_socket(name, perms).await
        })
    }

    fn mknod<'a>(
        &'a self,
        name: &'a str,
        file_type: FileType,
        rdev: u64,
    ) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let upper = self.prepare_create(name).await?;
            upper.mknod(name, file_type, rdev).await
        })
    }

    fn mkdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            let upper = self.prepare_create(name).await?;
            upper.mkdir(name).await
        })
    }

    fn rmdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move { self.remove_entry(name, true).await })
    }

    fn symlink<'a>(&'a self, name: &'a str, target: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let upper = self.prepare_create(name).await?;
            upper.symlink(name, target).await
        })
    }

    fn rename<'a>(&'a self, old_name: &'a str, new_name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if !self.writable {
                return Err(FsError::ReadOnly);
            }
            if !valid_visible_name(old_name) || !valid_visible_name(new_name) {
                return Err(FsError::InvalidPath);
            }
            if old_name == new_name {
                return (self.lookup(old_name).is_some() || self.lookup_dir(old_name).is_some())
                    .then_some(())
                    .ok_or(FsError::NotFound);
            }
            let lower_positive = self.lower_kind(old_name).is_some();
            let source_is_dir = self.lookup_dir(old_name).is_some();
            if source_is_dir && lower_positive {
                // Linux's default redirect_dir=off behavior is EXDEV for a
                // lower or merged directory.
                return Err(FsError::CrossDevice);
            }
            if !source_is_dir && self.lookup(old_name).is_none() {
                return Err(FsError::NotFound);
            }
            if !source_is_dir && self.upper_dir().and_then(|d| d.lookup(old_name)).is_none() {
                self.copy_up_file(old_name).await?;
            }
            let upper = self.prepare_destination(new_name).await?;
            upper.rename(old_name, new_name).await?;
            if lower_positive {
                self.create_whiteout(upper.as_ref(), old_name).await?;
            }
            Ok(())
        })
    }

    fn rename_to<'a>(
        &'a self,
        old_name: &'a str,
        new_dir: &'a dyn DirOps,
        new_name: &'a str,
        flags: u32,
    ) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let destination = new_dir
                .as_any()
                .and_then(|any| any.downcast_ref::<OverlayDir>())
                .filter(|dir| Arc::ptr_eq(&self.mount_id, &dir.mount_id))
                .ok_or(FsError::CrossDevice)?;
            if !self.writable {
                return Err(FsError::ReadOnly);
            }
            if flags & !0x3 != 0 || flags == 0x3 {
                return Err(FsError::Unsupported);
            }
            let lower_positive = self.lower_kind(old_name).is_some();
            let source_is_dir = self.lookup_dir(old_name).is_some();
            if source_is_dir && lower_positive {
                return Err(FsError::CrossDevice);
            }
            if !source_is_dir && self.lookup(old_name).is_none() {
                return Err(FsError::NotFound);
            }
            if flags == 0x2 && (lower_positive || destination.lower_kind(new_name).is_some()) {
                return Err(FsError::Unsupported);
            }
            if flags == 0x1
                && (destination.lookup(new_name).is_some()
                    || destination.lookup_dir(new_name).is_some())
            {
                return Err(FsError::Busy);
            }
            if !source_is_dir && self.upper_dir().and_then(|d| d.lookup(old_name)).is_none() {
                self.copy_up_file(old_name).await?;
            }
            let source_upper = self.upper.ensure().await?;
            let destination_upper = destination.prepare_destination(new_name).await?;
            source_upper
                .rename_to(old_name, destination_upper.as_ref(), new_name, flags)
                .await?;
            if lower_positive {
                self.create_whiteout(source_upper.as_ref(), old_name)
                    .await?;
            }
            Ok(())
        })
    }

    fn link<'a>(&'a self, old_name: &'a str, new_name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if self.lookup_dir(old_name).is_some() {
                return Err(FsError::InvalidPath);
            }
            if self
                .upper_dir()
                .and_then(|dir| dir.lookup(old_name))
                .is_none()
            {
                self.copy_up_file(old_name).await?;
            }
            let upper = self.prepare_create(new_name).await?;
            upper.link(old_name, new_name).await
        })
    }

    fn link_to<'a>(
        &'a self,
        old_name: &'a str,
        new_dir: &'a dyn DirOps,
        new_name: &'a str,
    ) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let destination = new_dir
                .as_any()
                .and_then(|any| any.downcast_ref::<OverlayDir>())
                .filter(|dir| Arc::ptr_eq(&self.mount_id, &dir.mount_id))
                .ok_or(FsError::CrossDevice)?;
            if self.lookup_dir(old_name).is_some() {
                return Err(FsError::InvalidPath);
            }
            if self
                .upper_dir()
                .and_then(|dir| dir.lookup(old_name))
                .is_none()
            {
                self.copy_up_file(old_name).await?;
            }
            let source_upper = self.upper.ensure().await?;
            let destination_upper = destination.prepare_create(new_name).await?;
            source_upper
                .link_to(old_name, destination_upper.as_ref(), new_name)
                .await
        })
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }

    fn link_node<'a>(&'a self, name: &'a str, node: Arc<dyn FileOps>) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let upper = self.prepare_create(name).await?;
            upper.link_node(name, node).await
        })
    }

    fn tmpfile<'a>(&'a self, mode: u32) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { self.upper.ensure().await?.tmpfile(mode).await })
    }

    fn supports_tmpfile(&self) -> bool {
        self.upper_dir().is_some_and(|dir| dir.supports_tmpfile())
    }
}

struct OverlayFile {
    upper: Arc<UpperDir>,
    name: String,
    lower: Arc<dyn FileOps>,
    upper_file: IrqSafeSpinLock<Option<Arc<dyn FileOps>>>,
}

impl fmt::Debug for OverlayFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OverlayFile")
            .field("name", &self.name)
            .field("copied_up", &self.upper_file.lock().is_some())
            .finish()
    }
}

impl OverlayFile {
    fn new(upper: Arc<UpperDir>, name: String, lower: Arc<dyn FileOps>) -> Self {
        Self {
            upper,
            name,
            lower,
            upper_file: IrqSafeSpinLock::new(None),
        }
    }

    fn copied_up(&self) -> Option<Arc<dyn FileOps>> {
        self.upper_file.lock().clone()
    }

    fn active(&self) -> Arc<dyn FileOps> {
        self.copied_up().unwrap_or_else(|| Arc::clone(&self.lower))
    }

    async fn copy_regular_data(
        lower: &dyn FileOps,
        upper: &dyn FileOps,
        size: u64,
    ) -> Result<(), FsError> {
        let mut offset = 0u64;
        let mut buffer = alloc::vec![0u8; COPY_CHUNK_SIZE];
        while offset < size {
            let wanted = core::cmp::min(buffer.len() as u64, size - offset) as usize;
            let read = lower.read(offset, &mut buffer[..wanted]).await?;
            if read == 0 {
                break;
            }
            let mut written = 0usize;
            while written < read {
                let count = upper
                    .write(offset + written as u64, &buffer[written..read])
                    .await?;
                if count == 0 {
                    return Err(FsError::Io(crate::BlockError::IOError));
                }
                written += count;
            }
            offset += read as u64;
        }
        Ok(())
    }

    async fn copy_xattrs(lower: &dyn FileOps, upper: &dyn FileOps) -> Result<(), FsError> {
        let names = match lower.list_xattr().await {
            Ok(names) => names,
            Err(FsError::Unsupported) => return Ok(()),
            Err(error) => return Err(error),
        };
        for raw_name in names
            .split(|byte| *byte == 0)
            .filter(|name| !name.is_empty())
        {
            let name = core::str::from_utf8(raw_name).map_err(|_| FsError::InvalidData)?;
            let value = lower.get_xattr(name).await?;
            upper.set_xattr(name, &value, 0).await?;
        }
        Ok(())
    }

    async fn ensure_copied_up(&self) -> Result<Arc<dyn FileOps>, FsError> {
        if let Some(file) = self.copied_up() {
            return Ok(file);
        }
        let upper_dir = self.upper.ensure().await?;
        if let Some(existing) = upper_dir.lookup(&self.name) {
            let mut slot = self.upper_file.lock();
            *slot = Some(Arc::clone(&existing));
            return Ok(existing);
        }

        let stat = self.lower.stat();
        let create_result = match stat.mode.file_type {
            FileType::File => upper_dir.create(&self.name).await,
            FileType::Symlink => {
                let mut target = alloc::vec![0u8; stat.size as usize];
                let read = self.lower.read(0, &mut target).await?;
                target.truncate(read);
                let target = core::str::from_utf8(&target).map_err(|_| FsError::InvalidData)?;
                upper_dir.symlink(&self.name, target).await
            }
            FileType::Socket => upper_dir.create_socket(&self.name, stat.mode.perms).await,
            file_type => {
                upper_dir
                    .mknod(&self.name, file_type, self.lower.rdev())
                    .await
            }
        };
        let upper_file = match create_result {
            Ok(file) => file,
            Err(FsError::Busy) => {
                let existing = upper_dir.lookup(&self.name).ok_or(FsError::Busy)?;
                let mut slot = self.upper_file.lock();
                *slot = Some(Arc::clone(&existing));
                return Ok(existing);
            }
            Err(error) => return Err(error),
        };

        let copy_result = async {
            if stat.mode.file_type == FileType::File {
                Self::copy_regular_data(self.lower.as_ref(), upper_file.as_ref(), stat.size)
                    .await?;
            }
            let (uid, gid) = self.lower.owners();
            upper_file.set_owners(uid, gid).await?;
            upper_file.set_perms(stat.mode.perms).await?;
            if stat.mtime_cycles != 0 {
                let mtime_ns = narf_time::cycles_to_ns(stat.mtime_cycles);
                upper_file.set_times(None, Some(mtime_ns))?;
            }
            Self::copy_xattrs(self.lower.as_ref(), upper_file.as_ref()).await?;
            Ok(())
        }
        .await;
        if let Err(error) = copy_result {
            let _ = upper_dir.unlink(&self.name).await;
            return Err(error);
        }

        let mut slot = self.upper_file.lock();
        if let Some(existing) = slot.as_ref() {
            return Ok(Arc::clone(existing));
        }
        *slot = Some(Arc::clone(&upper_file));
        Ok(upper_file)
    }
}

impl FileOps for OverlayFile {
    /// `ovl_file_operations` sets no `.poll`, so an overlaid regular file is
    /// not pollable — the overlay does not change what the inode is. Decided
    /// per inode, so a special file showing through stays pollable.
    fn can_poll(&self) -> bool {
        crate::fs_inode_can_poll(self.stat().mode.file_type)
    }

    fn read<'a>(&'a self, offset: u64, buffer: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { self.active().read(offset, buffer).await })
    }

    fn write<'a>(&'a self, offset: u64, buffer: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { self.ensure_copied_up().await?.write(offset, buffer).await })
    }

    fn stat(&self) -> Stat {
        self.active().stat()
    }

    fn ino(&self) -> u64 {
        self.active().ino()
    }

    fn stat_async<'a>(&'a self) -> FsFuture<'a, Stat> {
        Box::pin(async move { self.active().stat_async().await })
    }

    fn statx_async<'a>(&'a self, flags: u32, mask: u32) -> FsFuture<'a, FsStatx> {
        Box::pin(async move { self.active().statx_async(flags, mask).await })
    }

    fn owners(&self) -> (u32, u32) {
        self.active().owners()
    }

    fn truncate<'a>(&'a self, len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move { self.ensure_copied_up().await?.truncate(len).await })
    }

    fn set_owners<'a>(&'a self, uid: u32, gid: u32) -> FsFuture<'a, ()> {
        Box::pin(async move { self.ensure_copied_up().await?.set_owners(uid, gid).await })
    }

    fn set_perms<'a>(&'a self, perms: u16) -> FsFuture<'a, ()> {
        Box::pin(async move { self.ensure_copied_up().await?.set_perms(perms).await })
    }

    fn flush<'a>(&'a self) -> FsFuture<'a, ()> {
        Box::pin(async move { self.active().flush().await })
    }

    fn fsync<'a>(&'a self, data_only: bool) -> FsFuture<'a, ()> {
        Box::pin(async move { self.active().fsync(data_only).await })
    }

    fn syncfs<'a>(&'a self) -> FsFuture<'a, ()> {
        Box::pin(async move { self.active().syncfs().await })
    }

    fn set_xattr<'a>(&'a self, name: &'a str, value: &'a [u8], flags: u32) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.ensure_copied_up()
                .await?
                .set_xattr(name, value, flags)
                .await
        })
    }

    fn get_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, Vec<u8>> {
        Box::pin(async move { self.active().get_xattr(name).await })
    }

    fn list_xattr<'a>(&'a self) -> FsFuture<'a, Vec<u8>> {
        Box::pin(async move { self.active().list_xattr().await })
    }

    fn remove_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move { self.ensure_copied_up().await?.remove_xattr(name).await })
    }

    fn access<'a>(&'a self, mask: u32) -> FsFuture<'a, ()> {
        Box::pin(async move { self.active().access(mask).await })
    }

    fn get_lock<'a>(&'a self, owner: u64, lock: FileLock) -> FsFuture<'a, FileLock> {
        Box::pin(async move { self.active().get_lock(owner, lock).await })
    }

    fn set_lock<'a>(&'a self, owner: u64, lock: FileLock, wait: bool) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.ensure_copied_up()
                .await?
                .set_lock(owner, lock, wait)
                .await
        })
    }

    fn fallocate<'a>(&'a self, mode: u32, offset: u64, len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.ensure_copied_up()
                .await?
                .fallocate(mode, offset, len)
                .await
        })
    }

    fn seek<'a>(&'a self, offset: u64, whence: u32) -> FsFuture<'a, u64> {
        Box::pin(async move { self.active().seek(offset, whence).await })
    }

    fn bmap<'a>(&'a self, block: u64, block_size: u32) -> FsFuture<'a, u64> {
        Box::pin(async move { self.active().bmap(block, block_size).await })
    }

    fn setup_mapping<'a>(
        &'a self,
        file_offset: u64,
        len: u64,
        flags: u64,
        memory_offset: u64,
    ) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.ensure_copied_up()
                .await?
                .setup_mapping(file_offset, len, flags, memory_offset)
                .await
        })
    }

    fn remove_mappings<'a>(&'a self, ranges: &'a [FsMappingRange]) -> FsFuture<'a, ()> {
        Box::pin(async move { self.active().remove_mappings(ranges).await })
    }

    fn poll_readiness(&self) -> u32 {
        self.active().poll_readiness()
    }

    fn poll_readiness_at(&self, offset: u64) -> u32 {
        self.active().poll_readiness_at(offset)
    }

    fn acknowledge_poll_readiness(&self, readiness: u32) {
        self.active().acknowledge_poll_readiness(readiness);
    }

    fn poll_deadline(&self) -> Option<u64> {
        self.active().poll_deadline()
    }

    fn readiness_notifies(&self) -> bool {
        self.active().readiness_notifies()
    }

    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, FsError> {
        self.active().ioctl(cmd, arg)
    }

    fn ioctl_async<'a>(
        &'a self,
        cmd: u32,
        arg: u64,
        input: &'a [u8],
        out_size: usize,
    ) -> FsFuture<'a, FsIoctlReply> {
        Box::pin(async move { self.active().ioctl_async(cmd, arg, input, out_size).await })
    }

    fn mmap_frames(&self, offset: u64, len: usize) -> Result<Vec<u64>, FsError> {
        self.active().mmap_frames(offset, len)
    }

    fn mmap_fault(&self, offset: u64) -> Result<u64, FsError> {
        self.active().mmap_fault(offset)
    }

    fn rdev(&self) -> u64 {
        self.active().rdev()
    }

    fn write_should_block(&self) -> bool {
        self.active().write_should_block()
    }

    fn pipe_capacity(&self) -> Option<usize> {
        self.active().pipe_capacity()
    }

    fn is_stream(&self) -> bool {
        self.active().is_stream()
    }

    fn block_on_input(&self) -> bool {
        self.active().block_on_input()
    }

    fn nonblock_read_eagain(&self) -> bool {
        self.active().nonblock_read_eagain()
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

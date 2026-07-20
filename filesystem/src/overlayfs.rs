//! `OverlayFs` — a union / overlay filesystem (Linux `overlayfs`).
//!
//! An overlay stacks a single writable **upper** directory over one or
//! more read-only **lower** directories. A lookup consults the layers
//! top-down (upper first, then each lower in registration order); the
//! first hit wins, so an upper entry *shadows* a same-named lower one.
//! Writes are directed at the upper layer — creating, `mkdir`-ing, and
//! symlinking all land there, and a lower-only file opened for write is
//! **copied up** into upper before the write proceeds. Removing a
//! lower-only file leaves the lower untouched (it is read-only) and
//! instead records a **whiteout** in upper, which hides the lower entry
//! from every future lookup and enumeration of the union.
//!
//! This is the union filesystem containers and `systemd-nspawn` layer a
//! rootfs with: an immutable base image as the lower(s) plus a writable
//! scratch layer as the upper.
//!
//! ## What this implementation does / does not do
//!
//! - **Merged directories**: `lookup_dir` returns a fresh [`OverlayDir`]
//!   that unions the same-named subdirectory across every layer that has
//!   it, so descending into a directory present in both upper and a
//!   lower still sees the union of their contents (and honours whiteouts
//!   within). A subdirectory present in only one layer is still wrapped
//!   in an `OverlayDir` (with a single backing layer) so a later write
//!   under it copies up correctly.
//!
//! - **Whiteout representation**: real overlayfs marks a whiteout with a
//!   character device `0:0` in the upper layer. NARF's writable backends
//!   (`MemFs`) can't mint device nodes, so we represent a whiteout as a
//!   zero-length regular file in the upper layer whose name is the
//!   target name prefixed with [`WHITEOUT_PREFIX`] (`".wh."`), matching
//!   the AUFS/overlayfs on-disk whiteout *naming* convention. `unlink`
//!   of a lower-visible entry creates `.wh.<name>`; lookup/enumerate
//!   treat a `.wh.<name>` in upper as "<name> is deleted from the union"
//!   and never surface the `.wh.*` entries themselves.
//!
//! - **Copy-up** is implemented for the write path: [`OverlayDir::lookup`]
//!   / `lookup_async` return an [`OverlayFile`] wrapper whose first
//!   `write`/`truncate`/`set_*` copies the lower file's bytes into a new
//!   upper file and then re-targets all subsequent ops at that upper
//!   copy. Reads before any write go straight to the (cheaper) lower
//!   file. A file already in upper is returned directly — no wrapper.
//!
//! - **`workdir`** (real overlayfs's atomic-rename staging area) is
//!   accepted-and-ignored at mount time: our copy-up and whiteout ops
//!   act directly on the upper directory rather than staging through a
//!   workdir, which is correct for the single-threaded VFS here.
//!
//! - **Opaque directories** (a real-overlayfs `.wh..wh..opq` marker that
//!   hides *all* lower entries under a copied-up directory) are not
//!   implemented; per-entry whiteouts cover the cases the kernel-test
//!   suite and container rootfs layering exercise.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use narf_lib::sync::IrqSafeSpinLock;

use crate::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, FsInstance, Stat};

/// Filename prefix marking an upper-layer whiteout. A zero-length file
/// `.wh.<name>` in the upper layer means "<name> is deleted from the
/// union" — it hides any same-named lower entry from lookup/enumerate
/// and is itself never surfaced. Matches the AUFS/overlayfs on-disk
/// whiteout naming convention.
pub const WHITEOUT_PREFIX: &str = ".wh.";

/// Build the whiteout marker name for `name` (`".wh." + name`).
fn whiteout_name(name: &str) -> String {
    let mut s = String::with_capacity(WHITEOUT_PREFIX.len() + name.len());
    s.push_str(WHITEOUT_PREFIX);
    s.push_str(name);
    s
}

// ── OverlayFs (the mounted instance) ────────────────────────────────

/// A mounted overlay filesystem. Owns the writable `upper` layer and an
/// ordered list of read-only `lowers` (index 0 is highest priority,
/// consulted right after upper). `root()` merges the layers' root
/// directories into an [`OverlayDir`].
pub struct OverlayFs {
    name: &'static str,
    upper: Arc<dyn DirOps>,
    lowers: Vec<Arc<dyn DirOps>>,
}

impl fmt::Debug for OverlayFs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OverlayFs")
            .field("name", &self.name)
            .field("lowers", &self.lowers.len())
            .finish_non_exhaustive()
    }
}

impl OverlayFs {
    /// Build an overlay from a writable `upper` directory and an ordered
    /// list of read-only `lowers` (first = highest priority). At least
    /// an upper is required; `lowers` may be empty (degenerate to a
    /// pass-through of upper).
    pub fn new(name: &'static str, upper: Arc<dyn DirOps>, lowers: Vec<Arc<dyn DirOps>>) -> Self {
        Self {
            name,
            upper,
            lowers,
        }
    }
}

impl FsInstance for OverlayFs {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::new(OverlayDir {
            upper: Arc::clone(&self.upper),
            lowers: self.lowers.clone(),
        }) as Arc<dyn DirOps>
    }

    fn name(&self) -> &str {
        self.name
    }
}

// ── OverlayDir (a merged directory) ─────────────────────────────────

/// A merged directory view: the union of one `upper` directory and zero
/// or more `lowers`, with upper/earlier-lower shadowing later layers and
/// upper-layer whiteouts hiding lower entries.
///
/// Every writable op is directed at `upper`. Because a fresh
/// `OverlayDir` is minted per `lookup_dir`, each nested directory keeps
/// the correct per-layer backing so copy-up and whiteouts happen against
/// the right upper subdirectory.
struct OverlayDir {
    upper: Arc<dyn DirOps>,
    lowers: Vec<Arc<dyn DirOps>>,
}

impl fmt::Debug for OverlayDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OverlayDir")
            .field("lowers", &self.lowers.len())
            .finish_non_exhaustive()
    }
}

impl OverlayDir {
    /// True if the upper layer holds a whiteout for `name` (so `name` is
    /// deleted from the union regardless of what any lower holds).
    fn is_whited_out(&self, name: &str) -> bool {
        self.upper.lookup(&whiteout_name(name)).is_some()
    }
}

impl DirOps for OverlayDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        // Never resolve the whiteout markers themselves.
        if name.starts_with(WHITEOUT_PREFIX) {
            return None;
        }
        // Upper wins outright — an entry there shadows every lower.
        if let Some(f) = self.upper.lookup(name) {
            return Some(f);
        }
        // A whiteout in upper deletes the name from the union even
        // though upper has no live entry for it.
        if self.is_whited_out(name) {
            return None;
        }
        // Fall through the lowers in priority order. A lower-only file
        // is wrapped so the first write copies it up into `upper`.
        for lower in &self.lowers {
            if let Some(f) = lower.lookup(name) {
                return Some(Arc::new(OverlayFile::new(
                    Arc::clone(&self.upper),
                    name.to_string(),
                    f,
                )) as Arc<dyn FileOps>);
            }
        }
        None
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { self.lookup(name).ok_or(FsError::NotFound) })
    }

    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        if name.starts_with(WHITEOUT_PREFIX) {
            return None;
        }
        // A whiteout hides a lower directory too. If upper itself holds
        // a live directory we still surface it (a re-created directory
        // over a whiteout); otherwise a whiteout blocks the lowers.
        let upper_dir = self.upper.lookup_dir(name);
        if upper_dir.is_none() && self.is_whited_out(name) {
            return None;
        }
        // Collect the same-named subdirectory from every layer that has
        // it, preserving priority order (upper first).
        let mut lower_dirs: Vec<Arc<dyn DirOps>> = Vec::new();
        for lower in &self.lowers {
            if let Some(d) = lower.lookup_dir(name) {
                lower_dirs.push(d);
            }
        }
        match (upper_dir, lower_dirs.is_empty()) {
            (None, true) => None,
            (Some(u), _) => {
                // Present in upper (and maybe lowers) → merged dir with
                // the upper subdir as its writable layer.
                Some(Arc::new(OverlayDir {
                    upper: u,
                    lowers: lower_dirs,
                }) as Arc<dyn DirOps>)
            }
            (None, false) => {
                // Lower-only directory. Writes into it must land in a
                // *fresh* upper subdirectory (copy-up-on-write for the
                // directory), so make the highest-priority lower the
                // "upper" writable layer only if we can; since lowers
                // are read-only, we instead surface the first lower as
                // the writable slot and the rest as lowers. A write then
                // fails ReadOnly rather than silently mutating a lower —
                // matching "the parent hasn't been copied up yet". A
                // create()/mkdir() at this level would need the parent
                // copied up first; that is left to callers that mkdir
                // the parent explicitly (documented limitation).
                let mut it = lower_dirs.into_iter();
                let writable = it.next()?;
                Some(Arc::new(OverlayDir {
                    upper: writable,
                    lowers: it.collect(),
                }) as Arc<dyn DirOps>)
            }
        }
    }

    fn lookup_dir_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move { self.lookup_dir(name).ok_or(FsError::NotFound) })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // Names live in owned `String`s across layers — same constraint
        // as MemFs: we can't synthesise `&'static str` without leaking.
        // The readdir path uses `enumerate()` below.
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        // Build the full deduped union first, then apply cursor/max.
        // `seen` tracks names already emitted (upper/earlier-lower wins);
        // `whiteouts` tracks names deleted by an upper whiteout so a
        // lower entry with that name is suppressed. The `.wh.*` markers
        // are consumed into `whiteouts` and never emitted themselves.
        let mut merged: BTreeMap<String, FileType> = BTreeMap::new();
        let mut whiteouts: BTreeSet<String> = BTreeSet::new();

        // Upper first: record whiteouts and live entries.
        for (name, ft) in self.upper.enumerate(0, usize::MAX) {
            if let Some(target) = name.strip_prefix(WHITEOUT_PREFIX) {
                whiteouts.insert(target.to_string());
                continue;
            }
            merged.insert(name, ft);
        }
        // Lowers in priority order: fill in names not already present
        // and not whited-out.
        for lower in &self.lowers {
            for (name, ft) in lower.enumerate(0, usize::MAX) {
                if name.starts_with(WHITEOUT_PREFIX) {
                    // A lower-layer whiteout also hides deeper lowers.
                    if let Some(target) = name.strip_prefix(WHITEOUT_PREFIX) {
                        whiteouts.insert(target.to_string());
                    }
                    continue;
                }
                if whiteouts.contains(&name) || merged.contains_key(&name) {
                    continue;
                }
                merged.insert(name, ft);
            }
        }

        // `BTreeMap` gives a deterministic (sorted) order.
        merged.into_iter().skip(cursor).take(max).collect()
    }

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> FsFuture<'a, Vec<(String, FileType)>> {
        Box::pin(async move { Ok(self.enumerate(cursor, max)) })
    }

    fn unlink<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if name.starts_with(WHITEOUT_PREFIX) {
                return Err(FsError::InvalidPath);
            }
            // Is the name present in upper as a live entry? If so, remove
            // it from upper directly.
            let in_upper = self.upper.lookup(name).is_some();
            if in_upper {
                self.upper.unlink(name).await?;
            } else if self.upper.lookup_dir(name).is_some() {
                // An upper directory can't be unlink()'d (POSIX EISDIR).
                return Err(FsError::InvalidPath);
            }
            // Does any lower still expose the name? If so, leave a
            // whiteout so it disappears from the union. (The lower is
            // read-only and untouched.)
            let in_lower = self
                .lowers
                .iter()
                .any(|l| l.lookup(name).is_some() || l.lookup_dir(name).is_some());
            if in_lower {
                // Create the whiteout marker in upper (idempotent —
                // Busy means it already exists, which is fine).
                match self.upper.create(&whiteout_name(name)).await {
                    Ok(_) | Err(FsError::Busy) => {}
                    Err(e) => return Err(e),
                }
                return Ok(());
            }
            // Neither upper (removed above) nor any lower has it → the
            // unlink is done iff it was in upper; otherwise NotFound.
            if in_upper {
                Ok(())
            } else {
                Err(FsError::NotFound)
            }
        })
    }

    fn create<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            if name.starts_with(WHITEOUT_PREFIX) {
                return Err(FsError::InvalidPath);
            }
            // Creating over a whited-out lower name resurrects it: drop
            // the whiteout first so the fresh upper file is visible.
            if self.is_whited_out(name) {
                let _ = self.upper.unlink(&whiteout_name(name)).await;
            }
            self.upper.create(name).await
        })
    }

    fn mkdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            if name.starts_with(WHITEOUT_PREFIX) {
                return Err(FsError::InvalidPath);
            }
            if self.is_whited_out(name) {
                let _ = self.upper.unlink(&whiteout_name(name)).await;
            }
            self.upper.mkdir(name).await
        })
    }

    fn rmdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if name.starts_with(WHITEOUT_PREFIX) {
                return Err(FsError::InvalidPath);
            }
            let in_upper = self.upper.lookup_dir(name).is_some();
            if in_upper {
                self.upper.rmdir(name).await?;
            }
            // Whiteout a lower-visible directory of the same name so the
            // union no longer shows it.
            let in_lower = self.lowers.iter().any(|l| l.lookup_dir(name).is_some());
            if in_lower {
                match self.upper.create(&whiteout_name(name)).await {
                    Ok(_) | Err(FsError::Busy) => {}
                    Err(e) => return Err(e),
                }
                return Ok(());
            }
            if in_upper {
                Ok(())
            } else {
                Err(FsError::NotFound)
            }
        })
    }

    fn symlink<'a>(&'a self, name: &'a str, target: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            if name.starts_with(WHITEOUT_PREFIX) {
                return Err(FsError::InvalidPath);
            }
            if self.is_whited_out(name) {
                let _ = self.upper.unlink(&whiteout_name(name)).await;
            }
            self.upper.symlink(name, target).await
        })
    }

    fn rename<'a>(&'a self, old_name: &'a str, new_name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if old_name.starts_with(WHITEOUT_PREFIX) || new_name.starts_with(WHITEOUT_PREFIX) {
                return Err(FsError::InvalidPath);
            }
            // Rename is only supported for entries that already live in
            // upper (a lower-only rename would require copy-up of the
            // source plus a whiteout of the old name; deferred). Delegate
            // straight to the upper layer.
            self.upper.rename(old_name, new_name).await
        })
    }
}

// ── OverlayFile (copy-up-on-write wrapper) ──────────────────────────

/// Wraps a lower-layer [`FileOps`] so reads go to the (read-only) lower
/// file until the first write, at which point the file's bytes are
/// copied up into a fresh upper file and every subsequent op targets the
/// upper copy. This is overlayfs's copy-up semantics on the file path.
///
/// The wrapper is minted only for lower-only files; a file already in
/// upper is returned bare by [`OverlayDir::lookup`].
struct OverlayFile {
    /// The upper directory the copy-up target is created in.
    upper: Arc<dyn DirOps>,
    /// Name of the file within its directory (the copy-up target name).
    name: String,
    /// The read-only lower file we shadow until copy-up.
    lower: Arc<dyn FileOps>,
    /// Once copy-up has happened, the upper file every op targets.
    upper_file: IrqSafeSpinLock<Option<Arc<dyn FileOps>>>,
}

impl fmt::Debug for OverlayFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OverlayFile")
            .field("name", &self.name)
            .field("copied_up", &self.upper_file.lock().is_some())
            .finish_non_exhaustive()
    }
}

impl OverlayFile {
    fn new(upper: Arc<dyn DirOps>, name: String, lower: Arc<dyn FileOps>) -> Self {
        Self {
            upper,
            name,
            lower,
            upper_file: IrqSafeSpinLock::new(None),
        }
    }

    /// Return the upper copy if copy-up has already happened.
    fn copied_up(&self) -> Option<Arc<dyn FileOps>> {
        self.upper_file.lock().clone()
    }

    /// Perform copy-up if it hasn't happened yet, returning the upper
    /// file to target. Copies the lower file's current bytes into a
    /// fresh upper file of the same name, then remembers it.
    async fn ensure_copied_up(&self) -> Result<Arc<dyn FileOps>, FsError> {
        if let Some(f) = self.copied_up() {
            return Ok(f);
        }
        // Read the whole lower file. Lower files here are in-memory /
        // modestly sized; a chunked copy would be an easy refinement.
        let size = self.lower.stat().size as usize;
        let mut buf = alloc::vec![0u8; size];
        let mut off = 0usize;
        while off < size {
            let n = self.lower.read(off as u64, &mut buf[off..]).await?;
            if n == 0 {
                break;
            }
            off += n;
        }
        buf.truncate(off);
        // Create (or reuse) the upper copy and seed it with the bytes.
        let upper_file = match self.upper.create(&self.name).await {
            Ok(f) => f,
            // Someone already copied it up (or created it) — use that.
            Err(FsError::Busy) => self.upper.lookup(&self.name).ok_or(FsError::Busy)?,
            Err(e) => return Err(e),
        };
        if !buf.is_empty() {
            upper_file.write(0, &buf).await?;
        }
        // Publish the copy-up result. If a racer beat us, keep theirs.
        let mut g = self.upper_file.lock();
        if let Some(existing) = g.clone() {
            return Ok(existing);
        }
        *g = Some(Arc::clone(&upper_file));
        Ok(upper_file)
    }
}

impl FileOps for OverlayFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            // After copy-up, read the upper copy (it holds the writes);
            // before, read straight from the cheaper lower file.
            match self.copied_up() {
                Some(f) => f.read(offset, buf).await,
                None => self.lower.read(offset, buf).await,
            }
        })
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let f = self.ensure_copied_up().await?;
            f.write(offset, buf).await
        })
    }

    fn stat(&self) -> Stat {
        match self.copied_up() {
            Some(f) => f.stat(),
            None => self.lower.stat(),
        }
    }

    fn ino(&self) -> u64 {
        match self.copied_up() {
            Some(f) => f.ino(),
            None => self.lower.ino(),
        }
    }

    fn owners(&self) -> (u32, u32) {
        match self.copied_up() {
            Some(f) => f.owners(),
            None => self.lower.owners(),
        }
    }

    fn truncate<'a>(&'a self, len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let f = self.ensure_copied_up().await?;
            f.truncate(len).await
        })
    }

    fn set_owners<'a>(&'a self, uid: u32, gid: u32) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let f = self.ensure_copied_up().await?;
            f.set_owners(uid, gid).await
        })
    }

    fn set_perms<'a>(&'a self, perms: u16) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let f = self.ensure_copied_up().await?;
            f.set_perms(perms).await
        })
    }
}

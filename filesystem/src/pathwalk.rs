//! Linux-shaped dentry cache and RCU pathname walk.
//!
//! A [`Dentry`] is the VFS name object: it has stable parent/name identity,
//! is either positive or negative, and is distinct from the filesystem's
//! [`DirOps`] / [`FileOps`] inode-operation objects. Hash buckets publish
//! immutable dentry lists through QSBR. RCU walk follows those lists without
//! taking a lock and validates each parent/child step with the dentry sequence
//! before converting the result to owned `Arc` references. A cache miss,
//! symlink, revalidation requirement, or sequence mismatch asks the caller to
//! restart in reference-walk mode.
//!
//! This is the same division used by Linux's `__d_lookup_rcu`, `lookup_fast`,
//! and `try_to_unlazy`: the dcache supplies name objects; filesystem lookup is
//! authoritative only on the slow path; mutation unhashes a dentry before the
//! backing namespace changes; retired hash snapshots survive an RCU grace
//! period.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;
use narf_rcu::{Atomic as RcuAtomic, Owned as RcuOwned, ReadGuard};

use crate::{DirOps, FileOps, FileType, FsError};

const DENTRY_BUCKET_COUNT: usize = 64;
const DENTRY_BUCKET_WAYS: usize = 8;

/// The inode-facing state attached to a VFS name.
#[derive(Clone)]
enum DentryTarget {
    Positive {
        file: Option<Arc<dyn FileOps>>,
        directory: Option<Arc<dyn DirOps>>,
        file_type: FileType,
    },
    Negative,
}

/// A cached VFS name, separate from the filesystem inode-operation object.
///
/// Parent and name never change while this object is hashed. Rename/unlink
/// unhash it and advance `sequence`; a later lookup publishes another dentry.
/// This makes an RCU reader's sampled fields immutable while retaining the
/// Linux rule that the sampled sequence must be validated before use.
pub struct Dentry {
    name: String,
    parent: Option<Arc<Dentry>>,
    target: DentryTarget,
    sequence: AtomicU64,
    hashed: AtomicBool,
}

impl core::fmt::Debug for Dentry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Dentry")
            .field("name", &self.name)
            .field(
                "positive",
                &matches!(self.target, DentryTarget::Positive { .. }),
            )
            .field("hashed", &self.hashed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Dentry {
    pub(crate) fn root(directory: Arc<dyn DirOps>) -> Arc<Self> {
        Self::new_root(directory, true)
    }

    pub(crate) fn detached_root(directory: Arc<dyn DirOps>) -> Arc<Self> {
        Self::new_root(directory, false)
    }

    fn new_root(directory: Arc<dyn DirOps>, hashed: bool) -> Arc<Self> {
        Arc::new(Self {
            name: "/".to_string(),
            parent: None,
            target: DentryTarget::Positive {
                file: None,
                directory: Some(directory),
                file_type: FileType::Dir,
            },
            sequence: AtomicU64::new(1),
            hashed: AtomicBool::new(hashed),
        })
    }

    /// Referenced directory inode attached to this positive dentry.
    pub fn directory(&self) -> Option<Arc<dyn DirOps>> {
        match &self.target {
            DentryTarget::Positive { directory, .. } => directory.clone(),
            DentryTarget::Negative => None,
        }
    }

    fn directory_ref(&self) -> Option<&dyn DirOps> {
        match &self.target {
            DentryTarget::Positive { directory, .. } => directory.as_deref(),
            DentryTarget::Negative => None,
        }
    }

    fn file(&self) -> Option<Arc<dyn FileOps>> {
        match &self.target {
            DentryTarget::Positive { file, .. } => file.clone(),
            DentryTarget::Negative => None,
        }
    }

    fn file_type(&self) -> Option<FileType> {
        match self.target {
            DentryTarget::Positive { file_type, .. } => Some(file_type),
            DentryTarget::Negative => None,
        }
    }

    fn is_negative(&self) -> bool {
        matches!(self.target, DentryTarget::Negative)
    }

    fn read_sequence(&self) -> Option<u64> {
        let before = self.sequence.load(Ordering::Acquire);
        if !self.hashed.load(Ordering::Acquire) {
            return None;
        }
        let after = self.sequence.load(Ordering::Acquire);
        (before == after && self.hashed.load(Ordering::Acquire)).then_some(after)
    }

    fn sequence_valid(&self, sequence: u64) -> bool {
        self.hashed.load(Ordering::Acquire) && self.sequence.load(Ordering::Acquire) == sequence
    }

    /// Equivalent to `d_drop`: stop new hash lookups and make readers that
    /// found this object through an older RCU bucket retry.
    fn unhash(&self) {
        self.sequence.fetch_add(1, Ordering::AcqRel);
        self.hashed.store(false, Ordering::Release);
    }
}

struct DentryBucket {
    entries: Vec<Arc<Dentry>>,
    replace: usize,
    generation: u64,
}

static DENTRY_BUCKETS: [RcuAtomic<DentryBucket>; DENTRY_BUCKET_COUNT] =
    [const { RcuAtomic::null() }; DENTRY_BUCKET_COUNT];
static DENTRY_WRITERS: [IrqSafeSpinLock<()>; DENTRY_BUCKET_COUNT] =
    [const { IrqSafeSpinLock::new(()) }; DENTRY_BUCKET_COUNT];

// The bucket sequence closes the lookup-vs-create race when no dentry existed
// at mutation start. Existing objects also carry their own sequence, as Linux
// dentries do. A count is used instead of odd/even parity because two writers
// may overlap after leaving the short bucket critical section.
static ACTIVE_MUTATIONS: [AtomicUsize; DENTRY_BUCKET_COUNT] =
    [const { AtomicUsize::new(0) }; DENTRY_BUCKET_COUNT];
static MUTATION_GENERATIONS: [AtomicU64; DENTRY_BUCKET_COUNT] =
    [const { AtomicU64::new(1) }; DENTRY_BUCKET_COUNT];

/// Marks a namespace mutation in a filesystem that participates in RCU walk.
///
/// Construct this before the first directory-entry change and retain it until
/// the change is fully visible. It holds no lock and may cross `.await`.
#[must_use = "an RCU path mutation must stay guarded until publication completes"]
pub struct PathMutationGuard {
    buckets: u64,
}

impl core::fmt::Debug for PathMutationGuard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PathMutationGuard")
            .field("buckets", &self.buckets)
            .finish()
    }
}

fn directory_key(directory: &dyn DirOps) -> (usize, u64, u64) {
    directory.dcache_identity()
}

fn hash(directory: (usize, u64, u64), name: &str) -> usize {
    let mut value = (directory.0 as u64) ^ 0xcbf2_9ce4_8422_2325;
    value ^= directory.1;
    value = value.wrapping_mul(0x100_0000_01b3);
    value ^= directory.2;
    value = value.wrapping_mul(0x100_0000_01b3);
    for byte in name.bytes() {
        value ^= u64::from(byte);
        value = value.wrapping_mul(0x100_0000_01b3);
    }
    value as usize % DENTRY_BUCKET_COUNT
}

fn for_each_bucket(mut buckets: u64, mut f: impl FnMut(usize)) {
    while buckets != 0 {
        let bucket = buckets.trailing_zeros() as usize;
        buckets &= buckets - 1;
        f(bucket);
    }
}

/// Begin changing `names` in an RCU-walkable directory.
///
/// Every alias of each affected dentry is unhashed before the backing
/// namespace can change. An empty name list invalidates every child of the
/// directory. Unrelated hash chains remain available to RCU readers.
pub fn begin_path_mutation(parent: &dyn DirOps, names: &[&str]) -> PathMutationGuard {
    let parent_key = directory_key(parent);
    let mut buckets = 0u64;
    if names.is_empty() {
        buckets = u64::MAX;
    } else {
        for name in names {
            buckets |= 1u64 << hash(parent_key, name);
        }
    }

    for_each_bucket(buckets, |bucket| {
        ACTIVE_MUTATIONS[bucket].fetch_add(1, Ordering::AcqRel);
    });
    if names.is_empty() {
        for_each_bucket(buckets, |bucket| invalidate_bucket(parent, None, bucket));
    } else {
        for name in names {
            invalidate_bucket(parent, Some(name), hash(parent_key, name));
        }
    }
    PathMutationGuard { buckets }
}

impl Drop for PathMutationGuard {
    fn drop(&mut self) {
        if self.buckets == 0 {
            return;
        }
        for_each_bucket(self.buckets, |bucket| {
            MUTATION_GENERATIONS[bucket].fetch_add(1, Ordering::Release);
            ACTIVE_MUTATIONS[bucket].fetch_sub(1, Ordering::Release);
        });
        self.buckets = 0;
    }
}

#[derive(Copy, Clone)]
pub(crate) struct LookupToken {
    bucket: usize,
    generation: u64,
    parent_sequence: u64,
}

/// Sample the hash-chain generation before a blocking filesystem lookup.
pub(crate) fn lookup_token(parent: &Dentry, name: &str) -> Option<LookupToken> {
    let parent_sequence = parent.read_sequence()?;
    let directory = parent.directory_ref()?;
    let bucket = hash(directory_key(directory), name);
    let before = MUTATION_GENERATIONS[bucket].load(Ordering::Acquire);
    if ACTIVE_MUTATIONS[bucket].load(Ordering::Acquire) != 0 {
        return None;
    }
    let after = MUTATION_GENERATIONS[bucket].load(Ordering::Acquire);
    (before == after && ACTIVE_MUTATIONS[bucket].load(Ordering::Acquire) == 0).then_some(
        LookupToken {
            bucket,
            generation: after,
            parent_sequence,
        },
    )
}

fn token_valid(parent: &Dentry, token: LookupToken) -> bool {
    parent.sequence_valid(token.parent_sequence)
        && ACTIVE_MUTATIONS[token.bucket].load(Ordering::Acquire) == 0
        && MUTATION_GENERATIONS[token.bucket].load(Ordering::Acquire) == token.generation
}

fn dentry_parent_directory_is(dentry: &Dentry, directory: &dyn DirOps) -> bool {
    let Some(parent) = dentry.parent.as_ref() else {
        return false;
    };
    let Some(parent_directory) = parent.directory_ref() else {
        return false;
    };
    directory_key(parent_directory) == directory_key(directory)
}

fn invalidate_bucket(parent: &dyn DirOps, name: Option<&str>, bucket_index: usize) {
    loop {
        // Build the replacement snapshot before taking the IRQ-safe writer
        // lock. Linux likewise allocates dentries outside d_lock and keeps the
        // hash critical section to validation, unlink, and publication.
        let guard = narf_rcu::pin();
        let current = DENTRY_BUCKETS[bucket_index].load(&guard);
        let Some(bucket) = current.as_ref() else {
            return;
        };
        let generation = bucket.generation;
        let replace = bucket.replace;
        let mut changed = false;
        let mut next = Vec::with_capacity(bucket.entries.len());
        for dentry in &bucket.entries {
            let matches = name.is_none_or(|name| dentry.name == name)
                && dentry_parent_directory_is(dentry, parent);
            if matches {
                changed = true;
            } else {
                next.push(dentry.clone());
            }
        }
        drop(guard);
        if !changed {
            return;
        }
        let next = RcuOwned::new(DentryBucket {
            entries: next,
            replace,
            generation: generation.wrapping_add(1),
        });

        let writer = DENTRY_WRITERS[bucket_index].lock();
        let guard = narf_rcu::pin();
        let current = DENTRY_BUCKETS[bucket_index].load(&guard);
        let Some(bucket) = current.as_ref() else {
            continue;
        };
        if bucket.generation != generation {
            continue;
        }
        for dentry in &bucket.entries {
            let matches = name.is_none_or(|name| dentry.name == name)
                && dentry_parent_directory_is(dentry, parent);
            if matches {
                dentry.unhash();
            }
        }
        DENTRY_BUCKETS[bucket_index].store(next, &guard);
        drop(guard);
        drop(writer);
        return;
    }
}

fn dentry_matches(dentry: &Dentry, parent: &Dentry, name: &str) -> bool {
    dentry.name == name
        && dentry
            .parent
            .as_ref()
            .is_some_and(|candidate| core::ptr::eq(candidate.as_ref(), parent))
}

fn lookup_rcu<'guard>(
    guard: &'guard ReadGuard<'static>,
    parent: &Dentry,
    name: &str,
) -> Option<(&'guard Arc<Dentry>, u64, LookupToken)> {
    let directory = parent.directory_ref()?;
    if !directory.rcu_walkable() {
        return None;
    }
    let token = lookup_token(parent, name)?;
    let bucket = DENTRY_BUCKETS[token.bucket].load(guard);
    let child = bucket
        .as_ref()?
        .entries
        .iter()
        .rev()
        .find(|dentry| dentry_matches(dentry, parent, name))?;
    let sequence = child.read_sequence()?;
    token_valid(parent, token).then_some((child, sequence, token))
}

fn merged_target(old: &DentryTarget, new: DentryTarget) -> DentryTarget {
    match (old, new) {
        (
            DentryTarget::Positive {
                file: old_file,
                directory: old_directory,
                file_type: old_type,
            },
            DentryTarget::Positive {
                file,
                directory,
                file_type,
            },
        ) => DentryTarget::Positive {
            file: file.or_else(|| old_file.clone()),
            directory: directory.or_else(|| old_directory.clone()),
            file_type: if file_type == FileType::Dir {
                *old_type
            } else {
                file_type
            },
        },
        (_, new) => new,
    }
}

fn reusable_target(old: &DentryTarget, new: &DentryTarget) -> bool {
    match (old, new) {
        // Once a directory dentry is reachable, descendants may already name
        // it as their parent. Keep that identity stable even if a later
        // file-shaped lookup could add another inode-ops view.
        (
            DentryTarget::Positive {
                directory: Some(_), ..
            },
            DentryTarget::Positive { .. },
        ) => true,
        (
            DentryTarget::Positive { file: Some(_), .. },
            DentryTarget::Positive { file: Some(_), .. },
        ) => true,
        (DentryTarget::Negative, DentryTarget::Negative) => true,
        _ => false,
    }
}

fn cache(
    parent: &Arc<Dentry>,
    name: &str,
    token: LookupToken,
    target: DentryTarget,
) -> Option<Arc<Dentry>> {
    parent.read_sequence()?;
    let directory = parent.directory_ref()?;
    if !directory.rcu_walkable() || !token_valid(parent, token) {
        return None;
    }
    let bucket_index = hash(directory_key(directory), name);
    if token.bucket != bucket_index {
        return None;
    }

    loop {
        let guard = narf_rcu::pin();
        let current = DENTRY_BUCKETS[bucket_index].load(&guard);
        let (mut entries, replace, generation) = current.as_ref().map_or_else(
            || (Vec::with_capacity(DENTRY_BUCKET_WAYS), 0, 0),
            |bucket| (bucket.entries.clone(), bucket.replace, bucket.generation),
        );
        drop(guard);

        let existing = entries
            .iter()
            .position(|dentry| dentry_matches(dentry, parent.as_ref(), name));
        let reusable = existing.filter(|index| reusable_target(&entries[*index].target, &target));
        let merged = existing
            .map(|index| merged_target(&entries[index].target, target.clone()))
            .unwrap_or_else(|| target.clone());
        let dentry = Arc::new(Dentry {
            name: name.to_string(),
            parent: Some(parent.clone()),
            target: merged,
            sequence: AtomicU64::new(1),
            hashed: AtomicBool::new(true),
        });

        let evicting = existing.is_none() && entries.len() == DENTRY_BUCKET_WAYS;
        let evicted = if let Some(index) = existing {
            let old = entries[index].clone();
            entries[index] = dentry.clone();
            Some(old)
        } else if entries.len() < DENTRY_BUCKET_WAYS {
            entries.push(dentry.clone());
            None
        } else {
            let index = replace % DENTRY_BUCKET_WAYS;
            let old = entries[index].clone();
            entries[index] = dentry.clone();
            Some(old)
        };
        let next_replace = if evicting {
            replace.wrapping_add(1)
        } else {
            replace
        };
        let next = RcuOwned::new(DentryBucket {
            entries,
            replace: next_replace,
            generation: generation.wrapping_add(1),
        });

        let writer = DENTRY_WRITERS[bucket_index].lock();
        if !token_valid(parent, token) {
            return None;
        }
        let guard = narf_rcu::pin();
        let current = DENTRY_BUCKETS[bucket_index].load(&guard);
        let current_generation = current.as_ref().map_or(0, |bucket| bucket.generation);
        if current_generation != generation {
            continue;
        }
        if let Some(index) = reusable {
            let existing = current.as_ref()?.entries[index].clone();
            if existing.read_sequence().is_some() {
                return Some(existing);
            }
            continue;
        }
        if let Some(evicted) = evicted {
            evicted.unhash();
        }
        DENTRY_BUCKETS[bucket_index].store(next, &guard);
        drop(guard);
        drop(writer);
        return Some(dentry);
    }
}

pub(crate) enum FastFile {
    Hit(Arc<dyn FileOps>),
    Negative,
    Retry,
}

pub(crate) enum FastDirectory {
    Hit(Arc<Dentry>),
    Negative,
    Retry,
}

/// Try a complete file lookup using only RCU dentry operations.
pub(crate) fn resolve_file(root: Arc<Dentry>, path: &str) -> FastFile {
    if path.is_empty() || path.starts_with('/') {
        return FastFile::Retry;
    }
    let guard = narf_rcu::pin();
    let mut current = root.as_ref();
    let Some(mut current_sequence) = current.read_sequence() else {
        return FastFile::Retry;
    };
    let mut components = path
        .split('/')
        .filter(|component| !component.is_empty() && *component != ".")
        .peekable();
    let Some(mut component) = components.next() else {
        return FastFile::Retry;
    };

    loop {
        if component == ".." {
            return FastFile::Retry;
        }
        let Some((child, child_sequence, token)) = lookup_rcu(&guard, current, component) else {
            return FastFile::Retry;
        };
        // Interlocking validation: after finding the child, prove the parent
        // was stable while the hash lookup ran. The child sequence protects
        // the next step and eventual conversion to a referenced result.
        if !current.sequence_valid(current_sequence) || !token_valid(current, token) {
            return FastFile::Retry;
        }
        let final_component = components.peek().is_none();
        if final_component {
            if child.file_type() == Some(FileType::Symlink) {
                return FastFile::Retry;
            }
            if !child.sequence_valid(child_sequence) || !token_valid(current, token) {
                return FastFile::Retry;
            }
            if child.is_negative() {
                return FastFile::Negative;
            }
            return child.file().map_or(FastFile::Retry, FastFile::Hit);
        }
        if child.file_type() == Some(FileType::Symlink) || child.directory().is_none() {
            return FastFile::Retry;
        }
        current = child.as_ref();
        current_sequence = child_sequence;
        component = components.next().expect("peek reported a component");
    }
}

/// Try a complete directory lookup using only RCU dentry operations.
pub(crate) fn resolve_directory(root: Arc<Dentry>, path: &str) -> FastDirectory {
    if path.starts_with('/') {
        return FastDirectory::Retry;
    }
    if path.is_empty() {
        return FastDirectory::Hit(root);
    }
    let guard = narf_rcu::pin();
    let mut current = root.as_ref();
    let mut current_arc = None;
    let Some(mut current_sequence) = current.read_sequence() else {
        return FastDirectory::Retry;
    };
    for component in path
        .split('/')
        .filter(|component| !component.is_empty() && *component != ".")
    {
        if component == ".." {
            return FastDirectory::Retry;
        }
        let Some((child, child_sequence, token)) = lookup_rcu(&guard, current, component) else {
            return FastDirectory::Retry;
        };
        if !current.sequence_valid(current_sequence) || !token_valid(current, token) {
            return FastDirectory::Retry;
        }
        if child.is_negative() {
            return FastDirectory::Negative;
        }
        if child.file_type() == Some(FileType::Symlink) || child.directory().is_none() {
            return FastDirectory::Retry;
        }
        current = child.as_ref();
        current_arc = Some(child);
        current_sequence = child_sequence;
    }
    if current.sequence_valid(current_sequence) {
        FastDirectory::Hit(current_arc.map_or(root, Arc::clone))
    } else {
        FastDirectory::Retry
    }
}

pub(crate) fn cache_directory(
    parent: &Arc<Dentry>,
    name: &str,
    token: LookupToken,
    directory: Arc<dyn DirOps>,
) -> Option<Arc<Dentry>> {
    cache(
        parent,
        name,
        token,
        DentryTarget::Positive {
            file: None,
            directory: Some(directory),
            file_type: FileType::Dir,
        },
    )
}

pub(crate) fn reference_directory(
    parent: &Arc<Dentry>,
    name: &str,
    directory: Arc<dyn DirOps>,
) -> Arc<Dentry> {
    Arc::new(Dentry {
        name: name.to_string(),
        parent: Some(parent.clone()),
        target: DentryTarget::Positive {
            file: None,
            directory: Some(directory),
            file_type: FileType::Dir,
        },
        sequence: AtomicU64::new(1),
        hashed: AtomicBool::new(false),
    })
}

pub(crate) fn cache_file(
    parent: &Arc<Dentry>,
    name: &str,
    token: LookupToken,
    file: Arc<dyn FileOps>,
    file_type: FileType,
) -> Option<Arc<Dentry>> {
    cache(
        parent,
        name,
        token,
        DentryTarget::Positive {
            file: Some(file),
            directory: None,
            file_type,
        },
    )
}

pub(crate) fn cache_negative(parent: &Arc<Dentry>, name: &str, token: LookupToken) {
    let _ = cache(parent, name, token, DentryTarget::Negative);
}

pub(crate) fn map_fast_file(result: FastFile) -> Option<Result<Arc<dyn FileOps>, FsError>> {
    match result {
        FastFile::Hit(file) => Some(Ok(file)),
        FastFile::Negative => Some(Err(FsError::NotFound)),
        FastFile::Retry => None,
    }
}

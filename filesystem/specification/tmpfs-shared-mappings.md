# Coherent shared mappings for tmpfs

Status: design, 2026-09-15. Implements the first of the tmpfs audit's
remaining gaps (`TMPFS_RAMFS_LINUX_COMPAT_AUDIT.md`, item 1).

## The gap

On Linux a tmpfs file's pages ARE its mapped pages. `shmem_get_folio`
returns a folio from the inode's `address_space`, `filemap_map_pages`
installs that same folio's page into the PTE, and `read`/`write` reach it
through the same `address_space`. There is exactly one copy of the data,
so every path sees every write immediately.

NARF's tmpfs stores file bytes as slab allocations (`Box<[u8]>` per 4-KiB
page) and advertises `FileOps::mmap_cache_generation`, which routes
`mmap(MAP_SHARED)` onto the generic fallback in
`userspace/src/mapped_file.rs`. That path allocates a *separate* physical
frame per `(file, offset)`, copies the file's bytes in on first fault, and
copies them back on `msync`/`fsync`. Two consequences, both observable:

  * a store through the mapping is invisible to `read(2)` until an
    explicit `msync`/`fsync`; and
  * a `write(2)` is invisible to an already-faulted mapping, forever —
    the mapped frame is never refreshed.

That is not what `mmap(MAP_SHARED)` means, and it is the whole mechanism
behind `memfd_create` + `mmap` (Wayland buffers, dbus, PulseAudio) and
`/dev/shm`. `new_anon_file` — what `memfd_create` returns — is a
`MemFile`, so this affects exactly the objects built for sharing.

## What already exists

The extension point is present and documented; tmpfs simply does not use
it. `FileOps` offers three mmap strategies:

| method | shape | used by |
| --- | --- | --- |
| `mmap_frames` | answered once at `mmap` time; a snapshot | device BARs, perf rings |
| `mmap_fault` | answered per page from the fault handler; **tracks the file** | BPF arenas |
| `mmap_cache_generation` | generic copy + writeback | tmpfs today |

`mmap_fault`'s contract is exactly the one wanted here: the frame is
mapped **borrowed** (`RegionPerms::SHARED`, so `munmap` and teardown clear
PTEs and free nothing), "the file owns it, and must keep owning it for as
long as any mapping of the file can exist", and the mapping-held
`Arc<dyn FileOps>` in `mapped_file` is what guarantees that.

`sys_mmap` reaches that path only for `MAP_SHARED` (`if fd >= 0 && flags &
MAP_SHARED != 0`), so `MAP_PRIVATE` file mappings keep the copy semantics
they must have, with no extra work.

## Design

**1. tmpfs pages become owned physical frames.** `FileData.pages` changes
from `BTreeMap<u64, Box<[u8]>>` to a map of an RAII frame wrapper that
allocates with `narf_memory::frame::alloc_frame` and frees on drop. File
data is read and written through `PhysAddr::kernel_ptr`, which is the
direct map, so the change is confined to how a page is allocated and
addressed — not to the sparse-map structure, the block accounting, or the
quota charge.

**2. `MemFile` implements `mmap_fault`.** It materialises the page at
`offset` — charging blocks and quota exactly as a write does, so a mapping
cannot outflank `size=` — and returns its frame. Idempotent per offset, as
the contract requires: a second call finds the page already present.

**3. `MemFile` stops advertising `mmap_cache_generation`.** That is the
flag `sys_mmap` tests to decide between the generic copy path and the
device/demand path, so removing it is what flips tmpfs onto the coherent
one. The generation counter itself disappears with it.

Coherence then falls out of there being one copy: a store through the
mapping IS the file's byte, and a `write(2)` lands in the page the mapping
already has.

## The hard case: truncate under a live mapping

Freeing a frame that userspace still has a PTE for would hand the buddy
allocator a page a process can still write — the precise hazard
`mapped_file`'s module header exists to describe.

Linux's answer is `unmap_mapping_range`: walk the inode's `i_mmap`
interval tree, clear the PTEs in every address space, and let subsequent
accesses take SIGBUS. NARF has no reverse map from a file range to the
mappings of it, and no cross-address-space PTE invalidation with the TLB
shootdown that implies.

**Decision: retain, do not free.** A page that has ever been handed out by
`mmap_fault` is not returned to the buddy while the file lives. `truncate`
and hole-punch remove it from the file's logical contents — reads see a
hole, `stat` reports the smaller size — and move the frame to a retired
list freed when the inode is.

Two properties make this the right trade:

  * It is **memory-safe by construction**, with no window and no
    cross-address-space surgery.
  * The retained frame **keeps its block charge** against the mount and
    the owner's quota. Without that, `mmap` a page, punch it, repeat
    would be an unbounded allocation the mount's own accounting reports
    as empty.

The divergence is that a mapping of truncated-away data keeps reading
stale bytes where Linux delivers SIGBUS. It is recorded in the audit's
gap list rather than presented as compatibility. Retention only triggers
for a page that was actually mapped and then truncated away, which is not
a shape the sharing workloads this exists for produce: they `ftruncate`
once, then map.

## Verification

  * the coherence both ways: a `write(2)` visible through an existing
    mapping, and a store through the mapping visible to `read(2)` with no
    `msync`;
  * two independent mappings of one memfd observing each other's stores —
    the `memfd_create` + `mmap` shape directly;
  * a page faulted in after the mapping was created (the mapping tracks
    the file, which `mmap_frames` could not do);
  * block accounting and `ENOSPC` reached through `mmap_fault`, not only
    through `write`;
  * a punched page's frame retained, still charged, and the mount usable
    afterwards.

Each new smoke is run against a deliberately stubbed mechanism first and
required to fail with the expected message.

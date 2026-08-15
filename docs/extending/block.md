# Extending NARF: Block Devices & Filesystem Drivers

Prereq: read [drivers.md](drivers.md) first — this doc assumes you have a bound
driver (a PCI probe, virtio bring-up, …) and now need to **publish a block
device** and/or **mount a filesystem** on one.

Two seams:

1. `narf-block` — register a block device the rest of the kernel can address.
2. `narf-filesystem`'s `root_mount` factory registry — register a filesystem
   driver so it auto-mounts (or is mounted directly) on a block device.

Both are cleanly out-of-tree: you implement a trait and call a `pub` register
fn.

---

## 1. Registering a block device (`narf-block`)

Source: `block/src/registry.rs`, `block/src/lib.rs`.

There are **two** block-device traits, and understanding why is the key to this
subsystem:

- `BlockDevice` (`block/src/lib.rs:69`) — the *rich async* interface (methods
  return `impl Future`). Great for the fast path, but its `impl Future` return
  types mean it **cannot be type-erased behind a `dyn`** for a uniform registry.
- `BlockDeviceSync` (`block/src/registry.rs:37`) — the *synchronous,
  `dyn`-safe* interface. **This is what you register.** Drivers provide blocking
  read/write ops that the registry (and the FS layer, via a bridge) consume.

### 1.1 The `BlockDeviceSync` trait — implement this

```rust
pub trait BlockDeviceSync: Send + Sync {                    // block/src/registry.rs:37
    fn lba_size(&self) -> u32;                              // 512 or 4096
    fn capacity(&self) -> u64;                              // total LBAs
    fn read(&self, lba: u64, n_blocks: u16, out: &mut [u8]) -> Result<(), BlockIoError>;
    fn write(&self, lba: u64, n_blocks: u16, data: &[u8]) -> Result<(), BlockIoError>;
}
```

All four methods are required. `BlockIoError` (`block/src/registry.rs:24`) has
`OutOfRange`, `BufferTooSmall`, `DriverError`, `DeviceRemoved`. Your `read`/
`write` do the transfer synchronously (poll the controller to completion) —
every in-tree device does exactly this, and the async bridge (§1.3) depends on
it.

### 1.2 The registration entry point

Re-exported from the crate root (`block/src/lib.rs:57`):

```rust
pub fn register_block_device(name: &'static str, dev: Arc<dyn BlockDeviceSync>);
    // block/src/registry.rs:87
pub fn register_block_device_with_meta(                     // block/src/registry.rs:95
    name: &'static str,
    dev: Arc<dyn BlockDeviceSync>,
    partition: Option<PartitionMetadata>,
);
```

- `name` is a `'static str` set at registration (`"nvme0"`, `"vblk0"`,
  `"sata0"` by convention; partitions get `"vblk0p1"` etc.).
- Registration is **idempotent on `name`** (`block/src/registry.rs:107`) — a
  re-bring-up replaces the entry rather than doubling it. It also reserves a
  default `IoScheduler` slot (a boxed `DeadlineScheduler`) for the device
  (`block/src/registry.rs:120`); if you installed a non-default I/O scheduler
  you must re-`install_io_scheduler` after re-registering.
- `register_block_device_with_meta` attaches GPT `partlabel`/`partuuid`
  (`PartitionMetadata`, `block/src/registry.rs:53`) so boot-time
  `root=PARTLABEL=` / `root=PARTUUID=` selectors match. The partition scanner
  uses this; a whole-disk driver passes `None` (which `register_block_device`
  does for you).

Companion lookups (`block/src/registry.rs`): `find_block_device(name)` `:134`,
`block_devices()` `:124`, `block_device_count()` `:129`,
`unregister_block_device(name)` `:144` (hot-unplug / test teardown).

### 1.3 The sync → async bridge (`SyncBlock`)

Filesystems want the *async* `BlockDevice`; the registry stores
`BlockDeviceSync`. `SyncBlock` (`block/src/registry.rs:202`) adapts one to the
other by running the sync read/write inside the future body:

```rust
pub struct SyncBlock(pub Arc<dyn BlockDeviceSync>);      // block/src/registry.rs:202
impl SyncBlock { pub fn new(dev: Arc<dyn BlockDeviceSync>) -> Arc<Self>; }  // :214
impl BlockDevice for SyncBlock { /* … */ }               // :219
```

So the flow is: your driver implements `BlockDeviceSync` → you
`register_block_device` it → an FS factory wraps it in `SyncBlock::new` to get
an `Arc<dyn BlockDevice>` → the FS mounts on that.

### 1.4 Worked reference: virtio-blk

From the probe (`drivers/virtio/src/blk_pci.rs:1209`):

```rust
narf_block::register_block_device(
    "vblk0",
    alloc::sync::Arc::new(VirtioBlkBlockSync)
        as alloc::sync::Arc<dyn narf_block::BlockDeviceSync>,
);
```

with `impl narf_block::BlockDeviceSync for VirtioBlkBlockSync` at
`drivers/virtio/src/blk_pci.rs:1111`. That's the whole publish step — call it
from your PCI probe after bring-up.

### 1.5 Notes

- The rich `BlockDevice` async trait (`block/src/lib.rs:69`) is the surface for
  drivers that want native async submission (`submit`/`flush`/`discard`/`cancel`
  returning futures, `BlockRequest`/`BlockCompletion` types,
  `block/src/lib.rs:153`/`:189`). You only need it if you're writing a
  high-throughput native-async driver; for everything else, `BlockDeviceSync` +
  the `SyncBlock` bridge is the path.
- I/O-scheduler policy is pluggable via `install_io_scheduler` /
  `IoScheduler` (`block/src/lib.rs:48`) but that's an I/O-path extension, not a
  device-driver seam.
- Block devices automatically appear as `/dev/<name>` nodes — no separate devfs
  registration (see [chardev.md](chardev.md) §"auto-block").

---

## 2. Registering a filesystem driver (`root_mount` factory)

Source: `filesystem/src/root_mount.rs`, `filesystem/src/lib.rs`. Reference
drivers: `drivers/fs/fat`, `drivers/fs/ext2`, `drivers/fs/btrfs`.

**There is no per-superblock `register_filesystem` à la Linux with a
`mount()`-callback vtable of many methods.** Instead a filesystem driver
registers a single **factory function** keyed by detected FS type, and the
boot-time root-mount walker (or explicit mount code) calls it.

### 2.1 The factory seam

```rust
pub type FsFactory =                                        // filesystem/src/root_mount.rs:43
    fn(Arc<dyn BlockDeviceSync>) -> Result<Arc<dyn FsInstance>, FsError>;

pub fn register_fs_factory(fs_type: FsType, factory: FsFactory);  // filesystem/src/root_mount.rs:51
```

- `FsType` comes from `narf_block::fs_detect::FsType` (the BPB/superblock
  detector). You register a factory for `FsType::Fat`, `FsType::Ext`, etc.
- Registration is idempotent on `fs_type` (`filesystem/src/root_mount.rs:53`).
- **Call it from a `Stage::Subsys` initcall** so the root-mount walker (which
  runs at **`Stage::Late`**, `filesystem/src/root_mount.rs:50`) finds you.
- Your factory receives a `BlockDeviceSync`, wraps it in `SyncBlock`, and
  returns an `Arc<dyn FsInstance>` (or an `FsError`, in which case the walker
  skips this candidate device and tries the next).

### 2.2 What a mounted FS returns: `FsInstance` → `DirOps` → `FileOps`

`FsInstance` (`filesystem/src/lib.rs:782`) — the mounted-volume handle:

```rust
pub trait FsInstance: Send + Sync + 'static {   // filesystem/src/lib.rs:782
    fn root(&self) -> Arc<dyn DirOps>;           // :785
    fn name(&self) -> &str;
}
```

`DirOps` (`filesystem/src/lib.rs:678`) — a directory node. **Required
(Stage-3):** `lookup` and `iter`; everything else has defaults:

```rust
pub trait DirOps: Send + Sync {                  // filesystem/src/lib.rs:678
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>>;              // :680 (required)
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a>;      // :694 (required)
    fn lookup_dir(&self, _name: &str) -> Option<Arc<dyn DirOps>> { None }  // default
    // async fallbacks (default to the sync method), and Stage-4 mutations
    // (create/mkdir/unlink/rmdir/symlink/rename) that default to Unsupported.
}
```

`FileOps` (`filesystem/src/lib.rs:346`) — a file node. **Required:** `read`,
`write`, `stat`; the ~30 other methods are optional with sane defaults (this
same trait is what char devices implement — see [chardev.md](chardev.md)):

```rust
pub trait FileOps: Send + Sync {                 // filesystem/src/lib.rs:346
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize>;  // :351 (required)
    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize>;     // :355 (required)
    fn stat(&self) -> Stat;                                                        // :359 (required)
    // ino / truncate / owners / set_perms / poll_readiness / ioctl / mmap_frames
    // / as_dir / rdev / … all have defaults.
}
```

Supporting types: `Stat`, `Mode`, `FileType`, `DirEntry`
(`filesystem/src/lib.rs:177`–`339`). `FsFuture<'a, T>` is the crate's boxed
future alias.

### 2.3 Worked reference: FAT

Factory + registration (`drivers/fs/fat/src/lib.rs:107`):

```rust
pub fn register_initcalls() {
    narf_init::register(Stage::Subsys, "fat-fs-factory", || {
        narf_filesystem::root_mount::register_fs_factory(
            narf_block::fs_detect::FsType::Fat,
            fat_factory,
        );
        InitResult::Ok
    });
}

fn fat_factory(dev: Arc<dyn narf_block::BlockDeviceSync>)   // drivers/fs/fat/src/lib.rs:123
    -> Result<Arc<dyn FsInstance>, FsError>
{
    let async_dev = narf_block::SyncBlock::new(dev);        // sync → async bridge
    let vol = narf_scheduler::block_on(
        volume::FatVolume::mount(async_dev, DomainId::DRIVER_0))?;  // the real mount
    Ok(vol as Arc<dyn FsInstance>)
}
```

The layered structure worth copying:

- `FatVolume::<B>::mount(device, domain) -> Result<Arc<Self>, FsError>`
  (`drivers/fs/fat/src/volume.rs:252`) — the actual superblock parse + volume
  bring-up, generic over `B: BlockDevice`.
- `FatMount<B>(Arc<FatVolume<B>>)` (`drivers/fs/fat/src/lib.rs:73`) — a thin
  `FsInstance` adapter forwarding `root`/`name` to the volume
  (`drivers/fs/fat/src/lib.rs:75`).
- `mount(authority, path, device, domain)` (`drivers/fs/fat/src/lib.rs:59`) — a
  convenience that mounts directly at a VFS path via
  `registry().mount(authority, path, FatMount(vol))`, for when you're mounting
  explicitly rather than via the auto-mount walker.

ext2 mirrors this pattern in `drivers/fs/ext2/src/lib.rs` and
`drivers/fs/ext2/src/volume.rs`. Btrfs registers both root auto-detection and
the string-keyed `mount -t btrfs` builder so subvolume mount options can be
parsed before constructing the volume.

### 2.4 Mounting explicitly (not via the root walker)

If you're not going through `register_fs_factory`, you mount into the VFS
directly with the mount authority (cap-gated):

```rust
let auth = narf_filesystem::bootstrap_mount_authority();   // filesystem/src/lib.rs:1165
narf_filesystem::registry().mount(&auth, "/mnt", my_fs_instance)?;  // filesystem/src/lib.rs (VfsRegistry::mount)
```

`registry()` is `filesystem/src/lib.rs:1038`; `mount<F: FsInstance>` and
`mount_arc` take a `Cap<MountPoint, Grant>` authority. This is exactly what
`devfs::mount_default` and the FAT `mount()` helper do.

### 2.5 Gotchas

- **`block_on` in the factory.** `FsFactory` is synchronous but the volume mount
  is async, so the factories `narf_scheduler::block_on(...)`. That's fine at
  boot; don't do it from an async context (you'd nest executors).
- **Domain.** Mounts run in a driver domain (`DomainId::DRIVER_0` in the
  references). Match your driver's domain.
- **Stage ordering.** Register the factory at `Stage::Subsys`; the walker is
  `Stage::Late`. If you register too late (at `Late`) the walker won't see you.
- **Return `Err`, don't panic**, from a factory whose superblock validation
  fails — the walker logs and tries the next candidate device.

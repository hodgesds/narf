# Extending NARF: Character Devices (`/dev/*` nodes)

Prereq: [drivers.md](drivers.md). This covers publishing a `/dev/*` node backed
by your driver. The core VFS trait (`FileOps`) is shared with filesystem files —
see [block.md](block.md) §2.2 for its full shape.

Source: `filesystem/src/devfs.rs`, `filesystem/src/devfs_block.rs`. A char
device implements `FileOps` (`filesystem/src/lib.rs:346`) and is published into
devfs via one of four patterns.

---

## 1. What you implement: `FileOps`

Your char device is an `Arc<dyn FileOps>` (`filesystem/src/lib.rs:346`). Only
three methods are required; the ~30 others have defaults tuned for a plain file,
which you override to give your node character-device behaviour:

```rust
pub trait FileOps: Send + Sync {                 // filesystem/src/lib.rs:346
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize>;  // :351 required
    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize>;     // :355 required
    fn stat(&self) -> Stat;                                                        // :359 required
    // Character-device-relevant defaults you often override:
    //   fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, FsError>
    //   fn poll_readiness(&self) -> u32                    // POLL_IN|POLL_OUT
    //   fn is_stream(&self) -> bool
    //   fn mmap_frames(&self, offset: u64, len: usize) -> Result<Vec<u64>, FsError>
    //   fn rdev(&self) -> u64                              // MAJ:MIN
    //   fn owners(&self) -> (u32, u32)                     // uid, gid
}
```

> **Reentrancy footgun.** A `FileOps::read`/`write` must **not** call
> `fd::with_table` (the FS-table lock is held across the call → deadlock). If
> your device needs fd-table state, intercept it a layer up in `sys_read`
> instead. This is a documented NARF pitfall.

---

## 2. The four publication patterns

devfs is a synthetic `DirOps` (`DevDir`) whose `lookup`/`lookup_dir` matches
node names. You hook into it one of four ways; all `register_*`/`install_*`
functions are `pub` on the `narf_filesystem::devfs` module, so all four are
usable from an out-of-tree crate.

### Pattern A — static singleton node

For a single fixed node. Register your `Arc<dyn FileOps>` once:

```rust
pub fn register_fp(node: Arc<dyn FileOps>);                          // filesystem/src/devfs.rs:197  → /dev/fp0
pub fn register_fb0(node: Arc<dyn FileOps>);                        // :215  → /dev/fb0
pub fn register_tpm(tpm0: Arc<dyn FileOps>, tpmrm0: Arc<dyn FileOps>); // :491  → /dev/tpm0, /dev/tpmrm0
```

`DevDir::lookup` returns a proxy that delegates to the registered node. Simple,
idempotent, no dynamic naming.

### Pattern B — dynamic hook (numbered nodes)

For a family of nodes with a numeric suffix (`ttyUSB0`, `video1`, …). Install a
`lookup` + `enumerate` pair of fn pointers:

```rust
pub fn install_tty_usb_hooks(                                        // filesystem/src/devfs.rs:269
    lookup: fn(&str) -> Option<Arc<dyn FileOps>>,
    enumerate: fn() -> Vec<(String, FileType)>,
);
pub fn install_video_hooks(/* same shape */);                       // :313  → /dev/video<N>
pub fn install_rfcomm_hooks(/* same shape */);                      // (rfcomm<N>)
```

`DevDir::lookup` calls your `lookup` when a name matches the prefix pattern;
`enumerate` lists your nodes for `getdents`. Supports an unbounded, dynamic set
of same-class devices.

### Pattern C — directory delegate

For an entire `/dev/<subdir>/`. Register a `DirOps` that owns the subtree:

```rust
pub fn register_dri_dir(dir: Arc<dyn DirOps>);   // filesystem/src/devfs.rs:368  → /dev/dri/
pub fn register_snd_dir(dir: Arc<dyn DirOps>);   // :384                          → /dev/snd/
```

`DevDir::lookup_dir` returns your directory; you control everything under it.
This is how DRM (`/dev/dri/card0`) and sound (`/dev/snd/*`) work — see
[graphics.md](graphics.md) and [sound.md](sound.md).

### Pattern D — auto-enumerated block devices (no registration)

Block devices need **no** devfs call. Anything registered with
`narf_block::register_block_device` (see [block.md](block.md) §1) appears in
`/dev/` automatically: `DevDir::lookup` falls back to
`devfs_block::lookup_block_file(name)` (`filesystem/src/devfs_block.rs:259`),
which wraps the `BlockDeviceSync` in a `BlockFile`
(`filesystem/src/devfs_block.rs:52`, `from_dev` `:77`) implementing `FileOps`.
`enumerate_block_devices` (`filesystem/src/devfs_block.rs:267`) lists them. So
publishing a block device *is* publishing its `/dev` node.

---

## 3. Reference: how devfs itself mounts

`DevFs` (`filesystem/src/devfs.rs:1048`) is an `FsInstance` whose `root()` is the
`DevDir`. It is mounted at `/dev` by `mount_default()`
(`filesystem/src/devfs.rs:1079`) using the bootstrap mount authority — the same
`registry().mount(&auth, "/dev", DevFs::new())` VFS path any filesystem uses
(see [block.md](block.md) §2.4).

---

## 4. Gotchas and the one gap

- **Adding a *new node-name category* needs a core edit.** Patterns A/B/C/D
  cover almost everything, but the actual name-matching lives in
  `DevDir::lookup` / `lookup_dir` inside `filesystem/src/devfs.rs`. If your
  device's `/dev/<name>` doesn't fit an existing registered node, prefix hook,
  or directory delegate, you must add a match arm there — that one line is not
  out-of-tree. The four patterns are extensible *within* their categories
  without editing devfs; a genuinely new category is the gap.
- **No FS-table locks in `FileOps`** (see §1 footgun).
- **`stat`/`rdev`/`owners` matter.** Userspace `stat()`/`ls -l` reads them;
  return a `FileType::Special` mode and the right MAJ:MIN `rdev` so tools see a
  character (or block) special file, not a regular file.
- **Blocking reads.** For a stream device (tty, input), return
  `Err(FsError::WouldBlock)` when it is empty but still live, and implement
  `is_stream`/`poll_readiness` so `read`/`poll` block instead of treating an
  ambiguous 0-byte result as EOF — the console read path depends on this.
- **`ioctl` is your control channel.** Override `FileOps::ioctl` for device
  control (termios, DRM ioctls, evdev `EVIOC*`); it surfaces to userspace via the
  syscall layer (see the core syscalls extending doc).

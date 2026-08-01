# Devfs Linux compatibility audit

Audit scope: NARF's `/dev` implementation, its VFS/syscall translations, the
mount dispatch for `devtmpfs` and `devpts`, and device-registration call paths.
The baseline is Linux devtmpfs/devpts behavior, not the obsolete Linux `devfs`
filesystem.

Upstream references:

- [Linux allocated device numbers and Unix98 PTYs](https://docs.kernel.org/admin-guide/devices.html)
- [The devpts filesystem](https://docs.kernel.org/filesystems/devpts.html)
- [FUSE overview and `/dev/fuse` mount contract](https://docs.kernel.org/filesystems/fuse/fuse.html)
- [uinput userspace interface](https://docs.kernel.org/input/uinput.html)
- [Linux VFS `mknod` API](https://docs.kernel.org/filesystems/api-summary.html)

## Method

The audit followed both directions of the interface:

1. `DevFs::root` / `DevDir::{lookup,lookup_dir,enumerate,mknod}` into each
   device implementation.
2. Linux `open`, `mknod`, `stat`, `statx`, `getdents`, and mount handlers back
   into the VFS traits.
3. Registration hooks for block, input, framebuffer, sound, DRM, TPM, USB
   serial, video, Bluetooth, RTC, and FUSE.
4. Semcode call-chain analysis at base commit
   `46b33e588ebe579ca0566b1466fd450703477650` for `mount_default`,
   `mknod_register`, `ptmx_open`, `open_ptmx`, `sys_mknodat`, and `sys_mount`.
   This confirmed that the compatibility seams are the shared VFS file-type
   translation, clone-on-open handling in the Linux open path, devfs dynamic
   mutation, and mount backend dispatch.

## Implemented compatibility

| Surface | Linux contract | NARF result |
|---|---|---|
| Filesystem identity | Mounted root is `devtmpfs` | `DevFs::name()` is `devtmpfs`; procfs mount listings use that name. |
| Char vs block type | `S_IFCHR`/`DT_CHR` and `S_IFBLK`/`DT_BLK` are distinct | `FileType::Special` and `FileType::Block` remain distinct through stat, statx, getdents, FUSE attrs, and FUSE mknod. |
| Device number | `st_rdev` carries Linux `dev_t` | Static devices carry documented Linux identities; dynamic mknod preserves the caller's encoded value. Extended minor bits use Linux `new_encode_dev` layout. |
| Stable inode | Repeated lookup identifies the same node | Static path nodes, PTYs, block nodes, input nodes, dynamic devices, directories, and symlinks return stable non-zero inode values. |
| Writable devtmpfs | udev may create and maintain runtime hierarchy | Root and nested dynamic directories support mkdir, char/block mknod, symlink, rename, unlink, and rmdir. Device nodes retain chmod/chown metadata; directories retain chmod mode. Duplicate creation fails and non-empty directories cannot be removed. |
| Readdir consistency | Entries have the correct `d_type` and resolve | Dynamic and static entries use matching types. Optional hardware nodes are hidden until their driver registers a backing object. `/dev/kmsg` and mountpoint directories are enumerated. |
| Standard memory devices | Conventional IDs and modes | `null` 1:3, `zero` 1:5, `full` 1:7, `random` 1:8, `urandom` 1:9, and `kmsg` 1:11 have Linux-shaped metadata. |
| TTY identities | `/dev/tty` 5:0, console 5:1, ptmx 5:2, VTs major 4, Unix98 slaves major 136 | Metadata matches those assignments. PTY `st_size` is zero rather than a private index channel. |
| Current controlling TTY | Opening `/dev/tty` targets the caller's controlling terminal and fails with `ENXIO` when none exists | The Linux open path selects the recorded console or PTY slave after `O_PATH` handling, forwards I/O/ioctl/readiness/job control, and retains the `/dev/tty` 5:0 identity. |
| Unix98 PTY path | `/dev/ptmx` may link to `pts/ptmx`; opening the clone node creates a pair | Root `ptmx` is the relative `pts/ptmx` symlink. `DevPtsFs` exposes `ptmx` and live numeric slaves; each successful open clones a new master. |
| FUSE clone device | Mount `fd=N` comes from an opened `/dev/fuse`; each open is a connection | Lookup/stat is side-effect free. `FileOps::open_instance` creates one connection only after open permissions pass, and separate opens are independent. Device ID is misc 10:229. |
| Block aliases | `/dev/disk/by-*` entries are symlinks to device nodes | by-label and by-partuuid return `../../<device>` symlinks and enumerate as links. Registered devices enumerate as block nodes. |
| Input | evdev nodes and `/dev/uinput` use char-device metadata | uinput is misc 10:223; event nodes expose stable per-device identities and stream size zero. |
| Static aliases | Conventional fd and RTC links | `fd`, `stdin`, `stdout`, `stderr`, `rtc`, and `ptmx` stat as symlinks with target-sized `st_size`. |

Clone-on-open is a VFS contract rather than a path-name special case.
`FileOps::open_instance` is invoked after the Linux permission check and is
skipped by `O_PATH`, preventing stat-only scanners from allocating PTYs or
FUSE connections.

## Remaining differences

These are real differences, not hidden behind a blanket “compatible” claim.

### High priority

1. **devpts instances and mount options.** Linux gives each devpts mount an
   independent PTY index space and supports `newinstance`, `gid=`, `mode=`,
   `ptmxmode=`, and `max=`. NARF mounts a real `DevPtsFs`, but all mounts share
   one global registry and currently expose `pts/ptmx` as mode 0666. This is
   functionally compatible for the initial mount, not container-isolation
   compatible.
2. **`/dev/kmsg` record ABI.** Reads expose a byte snapshot of NARF's console
   log. Linux exposes structured, sequence-numbered records with seek and
   overrun behavior. Writes are accepted and logged, but priority/facility and
   per-reader record cursors are not fully modeled.

### Medium priority

1. **Block device allocation authority.** Registered block devices currently
   receive extended major 259 and an enumeration-order minor. Drivers do not
   publish an authoritative Linux major/minor pair, so identities may change
   if registration order changes.
2. **Filesystem UUID aliases.** Partition labels and GPT PARTUUIDs are known;
   filesystem UUIDs are not scanned, leaving `/dev/disk/by-uuid` empty.
3. **Dynamic node backing.** A userspace-created mknod without a registered
   NARF driver has correct namespace/metadata behavior but an inert placeholder
   data path. Linux would route an unclaimed device number through cdev/bdev
   lookup and generally fail open with `ENXIO`/`ENODEV`; NARF currently allows
   no-op read/write behavior.
4. **Random pool controls.** Random and urandom produce the same initialized
   CSPRNG stream behavior, as modern Linux does after initialization, but
   entropy-accounting ioctls are compatibility no-ops and `/dev/random` never
   has a pre-initialization blocking state.

### Adjacent pseudo-filesystems

`/dev/shm`, `/dev/mqueue`, and `/dev/hugepages` are valid mountpoints. tmpfs is
real, while the `mqueue` and `hugetlbfs` mount backends are still generic empty
in-memory filesystems. Those are mount-backend gaps rather than devtmpfs node
gaps and should be implemented on separate focused branches.

## Regression coverage

Kernel smokes cover:

- char/block type and `st_rdev` preservation;
- mode/uid/gid/inode persistence across lookup;
- duplicate creation, rename, unlink, nested mkdir/symlink/rmdir;
- standard device identities and modes;
- readdir/lookup agreement for optional nodes;
- block-node and by-label symlink shape;
- `/dev/ptmx` target, live devpts slaves, and clone-on-open;
- side-effect-free `/dev/fuse` lookup and independent opens.

The complete repository merge gates remain authoritative; this audit does not
turn a focused smoke into a claim of exhaustive Linux conformance.

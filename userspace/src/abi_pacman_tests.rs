//! Linux syscall ABI conformance — what `pacman -Syu` and its hooks do.
//!
//! Each case replays, syscall for syscall, a sequence captured with `strace`
//! from the program on Linux, on the filesystems the CachyOS root uses (btrfs
//! for `/etc`, tmpfs for `/tmp`), and checks Linux's answer at every step:
//!
//! * glibc `ldconfig` (`elf/cache.c::save_cache`) rewriting
//!   `/etc/ld.so.cache` through `/etc/ld.so.cache~` — under `chroot("/")`
//!   too, which is how pacman runs a hook (`_alpm_run_chroot`).
//! * Bun's atomic file write (Claude Code's Write tool): every name is
//!   reached through `/proc/self/fd/<dirfd>/<name>`, on worker threads.
//! * mkinitcpio's install hook: `install -Dm644 /dev/stdin /boot/vmlinuz-*`
//!   with standard input a pipe.
//! * `grub-probe`: the source and root fields of `/proc/self/mounts` and
//!   `/proc/self/mountinfo` for a block-device mount.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_block::ram::RamBlockDevice;
use narf_filesystem::FsInstance;

use crate::abi_test_support::*;

const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_NOCTTY: u64 = 0o400;
const O_TRUNC: u64 = 0o1000;
const O_NONBLOCK: u64 = 0o4000;
const O_DIRECTORY: u64 = 0o200_000;
const O_NOFOLLOW: u64 = 0o400_000;
const O_CLOEXEC: u64 = 0o2_000_000;
const O_PATH: u64 = 0o10_000_000;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const STATX_ALL: u64 = 0xfff;
const S_IFMT: u32 = 0o170_000;
const S_IFREG: u32 = 0o100_000;
const S_IFIFO: u32 = 0o010_000;
const S_IFLNK: u32 = 0o120_000;

/// A `CLONE_FILES` worker thread of the fixture process, like the thread
/// pool Bun runs its filesystem calls on.
const THREAD: u64 = FAKE_TASK + 23;

fn cstr(s: &str) -> String {
    alloc::format!("{s}\0")
}

fn openat(path: &str, flags: u64, mode: u64) -> i64 {
    let path = cstr(path);
    call(
        Syscall::Openat.raw(),
        a3(AT_FDCWD, path.as_ptr() as u64, flags, mode),
    )
    .unwrap_or(i64::MIN)
}

fn write_all(fd: i64, bytes: &[u8]) -> i64 {
    call(
        Syscall::Write.raw(),
        a2(fd as u64, bytes.as_ptr() as u64, bytes.len() as u64),
    )
    .unwrap_or(i64::MIN)
}

fn read_some(fd: i64, buf: &mut [u8]) -> i64 {
    call(
        Syscall::Read.raw(),
        a2(fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64),
    )
    .unwrap_or(i64::MIN)
}

fn close(fd: i64) -> i64 {
    call(Syscall::Close.raw(), a0(fd as u64)).unwrap_or(i64::MIN)
}

fn chmod(path: &str, mode: u64) -> i64 {
    let path = cstr(path);
    call_chmod(path.as_ptr() as u64, mode).unwrap_or(i64::MIN)
}

fn rename(old: &str, new: &str) -> i64 {
    let (old, new) = (cstr(old), cstr(new));
    call_rename(old.as_ptr() as u64, new.as_ptr() as u64).unwrap_or(i64::MIN)
}

fn mkdir(path: &str) -> i64 {
    let path = cstr(path);
    call_mkdir(path.as_ptr() as u64, 0o755).unwrap_or(i64::MIN)
}

fn readlink(path: &str) -> Result<String, &'static str> {
    let path = cstr(path);
    let mut buf = [0u8; 512];
    match call_readlink(path.as_ptr() as u64, buf.as_mut_ptr() as u64, 511) {
        Some(n) if n > 0 => core::str::from_utf8(&buf[..n as usize])
            .map(String::from)
            .map_err(|_| "readlink returned non-UTF-8"),
        _ => Err("readlink failed"),
    }
}

/// `stat(2)` (`newfstatat(AT_FDCWD, path, buf, flags)`): `(st_mode, st_ino,
/// st_size)` or the negative errno.
fn fstatat(path: &str, flags: u64) -> Result<(u32, u64, u64), i64> {
    let path = cstr(path);
    let mut sb = [0u8; STAT_SIZE];
    match call(
        Syscall::Newfstatat.raw(),
        a3(
            AT_FDCWD,
            path.as_ptr() as u64,
            sb.as_mut_ptr() as u64,
            flags,
        ),
    ) {
        Some(0) => Ok((stat_mode(&sb), stat_ino(&sb), stat_size(&sb))),
        Some(errno) => Err(errno),
        None => Err(i64::MIN),
    }
}

fn fstat(fd: i64) -> Result<(u32, u64, u64), i64> {
    let mut sb = [0u8; STAT_SIZE];
    match call(Syscall::Fstat.raw(), a1(fd as u64, sb.as_mut_ptr() as u64)) {
        Some(0) => Ok((stat_mode(&sb), stat_ino(&sb), stat_size(&sb))),
        Some(errno) => Err(errno),
        None => Err(i64::MIN),
    }
}

fn stat_ino(sb: &[u8]) -> u64 {
    u64::from_ne_bytes(sb[8..16].try_into().unwrap())
}

/// `st_size`: offset 48 in both the x86_64 and the asm-generic layout.
fn stat_size(sb: &[u8]) -> u64 {
    u64::from_ne_bytes(sb[48..56].try_into().unwrap())
}

/// `statx(AT_FDCWD, path, flags, STATX_ALL)`: `(stx_mode, stx_ino,
/// stx_size)` or the negative errno.
fn statx(path: &str, flags: u64) -> Result<(u32, u64, u64), i64> {
    let path = cstr(path);
    let mut buf = [0u8; 256];
    match call(
        Syscall::Statx.raw(),
        a4(
            AT_FDCWD,
            path.as_ptr() as u64,
            flags,
            STATX_ALL,
            buf.as_mut_ptr() as u64,
        ),
    ) {
        Some(0) => Ok((
            u32::from(u16::from_ne_bytes(buf[28..30].try_into().unwrap())),
            u64::from_ne_bytes(buf[32..40].try_into().unwrap()),
            u64::from_ne_bytes(buf[40..48].try_into().unwrap()),
        )),
        Some(errno) => Err(errno),
        None => Err(i64::MIN),
    }
}

fn read_file(path: &str) -> Result<Vec<u8>, &'static str> {
    let fd = openat(path, O_RDONLY | O_CLOEXEC, 0);
    if fd < 0 {
        return Err("open for reading failed");
    }
    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let n = read_some(fd, &mut buf);
        if n < 0 {
            close(fd);
            return Err("read failed");
        }
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
    close(fd);
    Ok(out)
}

fn chroot_slash() -> Result<(), &'static str> {
    let root = b"/\0";
    if call(Syscall::Chroot.raw(), a0(root.as_ptr() as u64)) != Some(0) {
        return Err("chroot(\"/\") failed");
    }
    Ok(())
}

fn chroot_to(path: &str) -> Result<(), &'static str> {
    let path = cstr(path);
    if call(Syscall::Chroot.raw(), a0(path.as_ptr() as u64)) != Some(0) {
        return Err("chroot failed");
    }
    Ok(())
}

fn chdir(path: &str) -> Result<(), &'static str> {
    let path = cstr(path);
    if call(Syscall::Chdir.raw(), a0(path.as_ptr() as u64)) != Some(0) {
        return Err("chdir failed");
    }
    Ok(())
}

/// A hook's root on a native boot. PID 1 runs rooted at the installed root
/// (`spawn_rooted_pid1(.., "/mnt")`), so every process inherits a chroot.
/// pacman runs a hook with `_alpm_run_chroot`: `chroot("/")`, `chdir("/")`,
/// and `ldconfig -r .` adds its own `chroot(".")`, `chdir("/")`. Each of
/// those names the root it is already in, which leaves the root as it was.
fn enter_hook_root(session_root: &str) -> Result<(), &'static str> {
    chroot_to(session_root)?;
    chdir("/")?;
    chroot_slash()?;
    chdir("/")?;
    chroot_to(".")?;
    chdir("/")
}

// ─────────────────────────── btrfs fixture ───────────────────────────

/// Mount the btrfs free-space-tree fixture read-write at `at` (the allocator
/// a `root-rw` root uses) and run `body` with the mount in the VFS.
fn with_btrfs_at(at: &str, body: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    with_setup(|| {
        let image = crate::abi_fault_write_tests::btrfs_decode_sparse(
            crate::abi_fault_write_tests::BTRFS_FST_FIXTURE_SPARSE,
        );
        let volume = crate::handlers::poll_io_to_completion(
            narf_drivers_fs_btrfs::volume::BtrfsVolume::mount(
                RamBlockDevice::from_image(512, image),
                narf_lib::id::DomainId::DRIVER_0,
            ),
        )
        .and_then(|r| r.ok())
        .ok_or("mounting the btrfs fixture failed")?;
        let handle = registry()
            .mount_arc(
                &bootstrap_mount_authority(),
                at,
                Arc::clone(&volume) as Arc<dyn FsInstance>,
            )
            .map_err(|_| "attaching the btrfs fixture failed")?;
        let outcome = body();
        let _ = registry().unmount(&handle, at);
        drop(volume);
        outcome
    })
}

// ───────────────────────────── ldconfig ──────────────────────────────

/// `save_cache` exactly as `strace ldconfig` shows it:
///
/// ```text
/// openat(AT_FDCWD, "/etc/ld.so.cache~", O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW, 0600) = 3
/// write(3, ..., 89376) / write(3, ..., 104716)
/// lseek(3, 194092, SEEK_SET); write(3, ..., 24); write(3, "", 0); write(3, ..., 47)
/// chmod("/etc/ld.so.cache~", 0644) = 0
/// fsync(3) = 0
/// close(3) = 0
/// rename("/etc/ld.so.cache~", "/etc/ld.so.cache") = 0
/// ```
///
/// Run twice; before the second run the `~` file is left behind, as the
/// failed first transaction on NARF left it, so the open truncates an
/// existing file rather than creating one.
fn ldconfig_save_cache(dir: &str) -> Result<(), &'static str> {
    ldconfig_save_cache_with(dir, &mut || {})
}

/// [`ldconfig_save_cache`], running `between` after the cache is written and
/// before its `chmod`.
fn ldconfig_save_cache_with(dir: &str, between: &mut dyn FnMut()) -> Result<(), &'static str> {
    let tmp = alloc::format!("{dir}/ld.so.cache~");
    let cache = alloc::format!("{dir}/ld.so.cache");
    for round in 0..2u8 {
        if round == 1 {
            let stale = openat(&tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0o600);
            if stale < 0 || write_all(stale, &[0x55; 4096]) != 4096 || close(stale) != 0 {
                return Err("fixture: leaving a stale ld.so.cache~ failed");
            }
        }
        let fd = openat(&tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0o600);
        if fd < 0 {
            return Err("open(ld.so.cache~, O_CREAT|O_TRUNC|O_NOFOLLOW) failed");
        }
        let body = alloc::vec![0x40 + round; 89376 + 104716];
        if write_all(fd, &body[..89376]) != 89376 || write_all(fd, &body[89376..]) != 104716 {
            return Err("writing the new cache failed");
        }
        if call(Syscall::Lseek.raw(), a2(fd as u64, 194092, 0)) != Some(194092) {
            return Err("lseek(194092, SEEK_SET) failed");
        }
        if write_all(fd, &[0x74; 24]) != 24
            || write_all(fd, &[]) != 0
            || write_all(fd, b"ldconfig (GNU libc) stable release version 2.42") != 47
        {
            return Err("writing the cache trailer failed");
        }
        between();
        if chmod(&tmp, 0o644) != 0 {
            return Err("chmod(ld.so.cache~, 0644) of the file just written failed");
        }
        if call(Syscall::Fsync.raw(), a0(fd as u64)) != Some(0) {
            return Err("fsync of the new cache failed");
        }
        if close(fd) != 0 {
            return Err("close of the new cache failed");
        }
        match fstatat(&tmp, 0) {
            Ok((mode, _, size)) if mode == S_IFREG | 0o644 && size == 194092 + 24 + 47 => {}
            Ok(_) => return Err("ld.so.cache~ does not have mode 0644 and the written size"),
            Err(_) => return Err("ld.so.cache~ does not stat after close"),
        }
        if rename(&tmp, &cache) != 0 {
            return Err("rename(ld.so.cache~, ld.so.cache) failed");
        }
        match fstatat(&cache, 0) {
            Ok((mode, _, _)) if mode == S_IFREG | 0o644 => {}
            _ => return Err("ld.so.cache is not a 0644 regular file after the rename"),
        }
        if fstatat(&tmp, 0) != Err(ENOENT) {
            return Err("ld.so.cache~ still resolves after the rename");
        }
        let written = read_file(&cache)?;
        if written.len() != 194092 + 24 + 47 || written[..4] != [0x40 + round; 4] {
            return Err("ld.so.cache does not hold what ldconfig wrote");
        }
    }
    Ok(())
}

fn smoke_pacman_ldconfig_tmpfs() -> TestResult {
    with_tmpfs("/pacman-ldc", "size=4M", || {
        if mkdir("/pacman-ldc/etc") != 0 {
            return Err("fixture: mkdir etc failed");
        }
        ldconfig_save_cache("/pacman-ldc/etc")
    })
}
kernel_test_in!("syscall_abi/pacman/ldconfig", smoke_pacman_ldconfig_tmpfs);

fn smoke_pacman_ldconfig_btrfs() -> TestResult {
    with_btrfs_at("/pacman-ldc-btrfs", || {
        if mkdir("/pacman-ldc-btrfs/etc") != 0 {
            return Err("fixture: mkdir etc on btrfs failed");
        }
        ldconfig_save_cache("/pacman-ldc-btrfs/etc")
    })
}
kernel_test_in!("syscall_abi/pacman/ldconfig", smoke_pacman_ldconfig_btrfs);

/// A RAM disk holding only the sectors a sparse btrfs fixture (or a write)
/// gave it: the 128 MiB laptop fixture costs its ~400 KiB of data.
struct SparseDevice {
    sectors: narf_lib::sync::IrqSafeSpinLock<alloc::collections::BTreeMap<u64, Box<[u8; 512]>>>,
    capacity: u64,
}

impl SparseDevice {
    /// Decode the `NARFBTR1` encoding (see `btrfs_decode_sparse`) sector by
    /// sector.
    fn from_sparse(sparse: &[u8]) -> Self {
        let total = u64::from_le_bytes(sparse[8..16].try_into().unwrap());
        let runs = u32::from_le_bytes(sparse[16..20].try_into().unwrap()) as usize;
        let mut sectors = alloc::collections::BTreeMap::new();
        let mut p = 20usize;
        for _ in 0..runs {
            let off = u64::from_le_bytes(sparse[p..p + 8].try_into().unwrap());
            let len = u64::from_le_bytes(sparse[p + 8..p + 16].try_into().unwrap()) as usize;
            p += 16;
            for (i, byte) in sparse[p..p + len].iter().enumerate() {
                let at = off + i as u64;
                let sector: &mut Box<[u8; 512]> = sectors
                    .entry(at / 512)
                    .or_insert_with(|| Box::new([0u8; 512]));
                sector[(at % 512) as usize] = *byte;
            }
            p += len;
        }
        Self {
            sectors: narf_lib::sync::IrqSafeSpinLock::new(sectors),
            capacity: total / 512,
        }
    }
}

impl narf_block::BlockDeviceSync for SparseDevice {
    fn lba_size(&self) -> u32 {
        512
    }

    fn capacity(&self) -> u64 {
        self.capacity
    }

    fn read(
        &self,
        lba: u64,
        n_blocks: u16,
        out: &mut [u8],
    ) -> Result<(), narf_block::BlockIoError> {
        if lba + u64::from(n_blocks) > self.capacity {
            return Err(narf_block::BlockIoError::OutOfRange);
        }
        if out.len() < usize::from(n_blocks) * 512 {
            return Err(narf_block::BlockIoError::BufferTooSmall);
        }
        let sectors = self.sectors.lock();
        for i in 0..usize::from(n_blocks) {
            let dst = &mut out[i * 512..(i + 1) * 512];
            match sectors.get(&(lba + i as u64)) {
                Some(sector) => dst.copy_from_slice(&sector[..]),
                None => dst.fill(0),
            }
        }
        Ok(())
    }

    fn write(&self, lba: u64, n_blocks: u16, src: &[u8]) -> Result<(), narf_block::BlockIoError> {
        if lba + u64::from(n_blocks) > self.capacity {
            return Err(narf_block::BlockIoError::OutOfRange);
        }
        if src.len() < usize::from(n_blocks) * 512 {
            return Err(narf_block::BlockIoError::BufferTooSmall);
        }
        let mut sectors = self.sectors.lock();
        for i in 0..usize::from(n_blocks) {
            let mut sector = Box::new([0u8; 512]);
            sector.copy_from_slice(&src[i * 512..(i + 1) * 512]);
            sectors.insert(lba + i as u64, sector);
        }
        Ok(())
    }
}

const LAPTOP_DISK: &str = "pacmanvd1p2";
const LAPTOP_FIXTURE: &[u8] =
    include_bytes!("../../drivers/fs/btrfs/testdata/fixture-laptop.img.sparse");

/// ldconfig on a root mounted as the CachyOS one is: a distro-layout btrfs
/// (free-space tree, no-holes, zstd, 16 KiB nodes) mounted from its block
/// device by `mount -t btrfs -o subvol=/root,compress=zstd:1,noatime`, with
/// a second subvolume of the same filesystem mounted beside it (CachyOS has
/// seven), and an `/etc` large enough to spread its tree over many leaves.
fn smoke_pacman_ldconfig_btrfs_subvolume_root() -> TestResult {
    with_setup(|| {
        narf_block::register_block_device(
            LAPTOP_DISK,
            Arc::new(SparseDevice::from_sparse(LAPTOP_FIXTURE)),
        );
        let device = alloc::format!("/dev/{LAPTOP_DISK}");
        let outcome = (|| {
            if mount(
                Some(&device),
                "/pacman-ldc-root",
                "btrfs",
                0,
                "subvol=/root,compress=zstd:1,noatime",
            ) != 0
            {
                return Err("fixture: mount -t btrfs -o subvol=/root,compress=zstd:1 failed");
            }
            let home = mount(
                Some(&device),
                "/pacman-ldc-home",
                "btrfs",
                0,
                "subvol=/home,compress=zstd:1,noatime",
            );
            let result = (|| {
                if home != 0 {
                    return Err("fixture: mounting a second subvolume failed");
                }
                for i in 0..200 {
                    let fd = openat(
                        &alloc::format!("/pacman-ldc-root/etc/conf-{i:03}"),
                        O_WRONLY | O_CREAT | O_TRUNC,
                        0o644,
                    );
                    if fd < 0 || write_all(fd, &[b'c'; 300]) != 300 || close(fd) != 0 {
                        return Err("fixture: populating /etc failed");
                    }
                }
                chroot_slash()?;
                ldconfig_save_cache("/pacman-ldc-root/etc")?;
                // What a transaction leaves for the hook: the newest inode
                // freed again (pacman's extraction temporaries), so the next
                // create is issued its number, and a replaced file still
                // open, whose last close — its final iput — lands while
                // ldconfig is writing.
                let etc = "/pacman-ldc-root/etc";
                for round in 0..2 {
                    let freed = alloc::format!("{etc}/.replaced-{round}");
                    let fd = openat(&freed, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
                    if fd < 0 || write_all(fd, &[b'r'; 8192]) != 8192 || close(fd) != 0 {
                        return Err("fixture: writing a replaced file failed");
                    }
                    if call_unlink(cstr(&freed).as_ptr() as u64) != Some(0) {
                        return Err("fixture: removing a replaced file failed");
                    }
                }
                let held_path = alloc::format!("{etc}/.held");
                let held = openat(&held_path, O_RDWR | O_CREAT | O_TRUNC, 0o644);
                if held < 0
                    || write_all(held, &[b'h'; 65536]) != 65536
                    || call_unlink(cstr(&held_path).as_ptr() as u64) != Some(0)
                {
                    return Err("fixture: leaving an open unlinked file failed");
                }
                let mut held = Some(held);
                ldconfig_save_cache_with(etc, &mut || {
                    if let Some(fd) = held.take() {
                        close(fd);
                    }
                })
            })();
            umount("/pacman-ldc-home");
            umount("/pacman-ldc-root");
            result
        })();
        narf_block::unregister_block_device(LAPTOP_DISK);
        outcome
    })
}
kernel_test_in!(
    "syscall_abi/pacman/ldconfig",
    smoke_pacman_ldconfig_btrfs_subvolume_root
);

/// ldconfig with the btrfs subvolume mounted at `/` itself, as on a CachyOS
/// boot, so `/etc/ld.so.cache~` is a name on the root mount: a private mount
/// namespace (the test image keeps its own root) whose `/` is the laptop
/// fixture's `root` subvolume, mounted from its device with
/// `subvol=/root,compress=zstd:1,noatime`, under `chroot("/")`.
fn smoke_pacman_ldconfig_btrfs_mounted_at_root() -> TestResult {
    with_setup(|| {
        crate::handlers::install_mount_namespace(
            FAKE_TASK,
            narf_filesystem::MountNamespace::snapshot_global(),
        );
        narf_block::register_block_device(
            LAPTOP_DISK,
            Arc::new(SparseDevice::from_sparse(LAPTOP_FIXTURE)),
        );
        let device = alloc::format!("/dev/{LAPTOP_DISK}");
        let outcome = (|| {
            if mount(
                Some(&device),
                "/",
                "btrfs",
                0,
                "subvol=/root,compress=zstd:1,noatime",
            ) != 0
            {
                return Err("fixture: mounting the btrfs subvolume at / failed");
            }
            let result = (|| {
                chroot_slash()?;
                ldconfig_save_cache("/etc")
            })();
            const MNT_DETACH: u64 = 2;
            let root = cstr("/");
            let _ = call(Syscall::Umount2.raw(), a1(root.as_ptr() as u64, MNT_DETACH));
            result
        })();
        narf_block::unregister_block_device(LAPTOP_DISK);
        outcome
    })
}
kernel_test_in!(
    "syscall_abi/pacman/ldconfig",
    smoke_pacman_ldconfig_btrfs_mounted_at_root
);

/// The hook as pacman runs it: `chroot("/")`, `chdir("/")`, then ldconfig.
fn smoke_pacman_ldconfig_btrfs_in_chroot() -> TestResult {
    with_btrfs_at("/pacman-ldc-chroot", || {
        if mkdir("/pacman-ldc-chroot/etc") != 0 {
            return Err("fixture: mkdir etc on btrfs failed");
        }
        chroot_slash()?;
        ldconfig_save_cache("/pacman-ldc-chroot/etc")
    })
}
kernel_test_in!(
    "syscall_abi/pacman/ldconfig",
    smoke_pacman_ldconfig_btrfs_in_chroot
);

/// The 11-glibc-ldconfig hook as it runs on a NARF-booted CachyOS root:
/// inside PID 1's root (the installed root's directory), then pacman's and
/// ldconfig's own `chroot`s of that root (see [`enter_hook_root`]), then
/// `save_cache` on `/etc`. On the root mount this failed every
/// transaction: "Changing access rights of /etc/ld.so.cache~ to 0644
/// failed: No such file or directory".
fn smoke_pacman_ldconfig_hook_in_session_root() -> TestResult {
    with_btrfs_at("/pacman-session", || {
        if mkdir("/pacman-session/etc") != 0 {
            return Err("fixture: mkdir etc on btrfs failed");
        }
        enter_hook_root("/pacman-session")?;
        ldconfig_save_cache("/etc")?;
        // The root is where it was: `/` is the session root, not a name
        // with an extra slash below it.
        match fstatat("/etc/ld.so.cache", 0) {
            Ok((mode, _, _)) if mode == S_IFREG | 0o644 => Ok(()),
            _ => Err("the cache is not at /etc/ld.so.cache in the hook's root"),
        }
    })
}
kernel_test_in!(
    "syscall_abi/pacman/ldconfig",
    smoke_pacman_ldconfig_hook_in_session_root
);

/// The same on tmpfs, so the root's spelling is checked apart from btrfs.
fn smoke_pacman_ldconfig_hook_in_session_root_tmpfs() -> TestResult {
    with_tmpfs("/pacman-session-tmp", "size=4M", || {
        if mkdir("/pacman-session-tmp/etc") != 0 {
            return Err("fixture: mkdir etc failed");
        }
        enter_hook_root("/pacman-session-tmp")?;
        ldconfig_save_cache("/etc")
    })
}
kernel_test_in!(
    "syscall_abi/pacman/ldconfig",
    smoke_pacman_ldconfig_hook_in_session_root_tmpfs
);

// ──────────────────────────── Bun write ─────────────────────────────

/// Claude Code's Write tool on Bun, as `strace -f` shows it on Linux, with
/// each call on the thread that made it there:
///
/// ```text
/// [A] openat(AT_FDCWD, "<dir>", O_RDONLY|O_CLOEXEC|O_PATH|O_DIRECTORY) = 25
/// [B] readlink("/proc/self/fd/25") = "<dir>"
/// [C] openat(AT_FDCWD, "/proc/self/fd/25/hello.txt", O_RDONLY|O_NOCTTY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC) = -ENOENT
/// [D] statx(AT_FDCWD, "/proc/self/fd/25/hello.txt", AT_SYMLINK_NOFOLLOW, STATX_ALL) = -ENOENT
/// [E] openat(AT_FDCWD, "/proc/self/fd/25/hello.txt.tmp.<pid>.<hex>", O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0666) = 26
/// [F] write(26, "hello", 5) = 5; fsync(26) = 0; close(26) = 0
/// [G] rename("/proc/self/fd/25/hello.txt.tmp.<pid>.<hex>", "/proc/self/fd/25/hello.txt") = 0
/// [H] statx(AT_FDCWD, "/proc/self/fd/25/hello.txt", AT_STATX_SYNC_AS_STAT, STATX_ALL) = {S_IFREG|0644, size 5}
/// ```
///
/// Then the same file is written again (an Edit): the existing file opens
/// and reads through the link and the replacement renames over it.
fn bun_atomic_write(dir: &str) -> Result<(), &'static str> {
    let thread = |on: bool| set_task(if on { THREAD } else { FAKE_TASK });
    let dirfd = openat(dir, O_RDONLY | O_CLOEXEC | O_PATH | O_DIRECTORY, 0);
    if dirfd < 0 {
        return Err("open(dir, O_PATH|O_DIRECTORY) failed");
    }
    // A thread: CLONE_FILES and CLONE_FS, so it shares the table and root.
    crate::fd::share(FAKE_TASK, THREAD);
    crate::handlers::fs_fork(FAKE_TASK, THREAD, true);
    crate::handlers::register_task_to_pid(THREAD, FAKE_TASK);
    let outcome = (|| {
        thread(true);
        if readlink(&alloc::format!("/proc/self/fd/{dirfd}"))? != dir {
            return Err("/proc/self/fd/<dirfd> does not name the directory");
        }
        let via = |name: &str| alloc::format!("/proc/self/fd/{dirfd}/{name}");
        let target = via("hello.txt");
        let tmp = via("hello.txt.tmp.4242.798cbcf78e74");
        for (round, content) in [&b"hello"[..], &b"hello, world"[..]].iter().enumerate() {
            // [C], [D]: is the target there already?
            let existing = openat(
                &target,
                O_RDONLY | O_NOCTTY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC,
                0,
            );
            thread(false);
            let probed = statx(&target, AT_SYMLINK_NOFOLLOW);
            if round == 0 {
                if existing != ENOENT {
                    return Err("open of a missing name through /proc/self/fd/N/ is not ENOENT");
                }
                if probed != Err(ENOENT) {
                    return Err("statx of a missing name through /proc/self/fd/N/ is not ENOENT");
                }
            } else {
                if existing < 0 {
                    return Err("open of an existing file through /proc/self/fd/N/ failed");
                }
                let mut old = [0u8; 16];
                if read_some(existing, &mut old) != 5 || &old[..5] != b"hello" {
                    close(existing);
                    return Err("an existing file read through /proc/self/fd/N/ is wrong");
                }
                close(existing);
                match probed {
                    Ok((mode, _, 5)) if mode & S_IFMT == S_IFREG => {}
                    _ => return Err("statx of an existing file through /proc/self/fd/N/ failed"),
                }
            }
            // [E], [F]
            thread(true);
            let fd = openat(
                &tmp,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                0o666,
            );
            if fd < 0 {
                return Err("O_CREAT|O_EXCL of a new name through /proc/self/fd/N/ failed");
            }
            thread(false);
            if write_all(fd, content) != content.len() as i64
                || call(Syscall::Fsync.raw(), a0(fd as u64)) != Some(0)
                || close(fd) != 0
            {
                return Err("writing the temporary file failed");
            }
            // [G]
            thread(true);
            if rename(&tmp, &target) != 0 {
                return Err("rename through /proc/self/fd/N/ failed");
            }
            // [H]
            thread(false);
            match statx(&target, 0) {
                Ok((mode, _, size)) if mode == S_IFREG | 0o644 && size == content.len() as u64 => {}
                Ok(_) => return Err("the written file is not a 0644 regular file of its size"),
                Err(_) => return Err("statx of the written file through /proc/self/fd/N/ failed"),
            }
            // The file is where the directory is, under its ordinary name.
            if read_file(&alloc::format!("{dir}/hello.txt"))? != *content {
                return Err("the file written through /proc/self/fd/N/ does not hold the bytes");
            }
            if fstatat(&alloc::format!("{dir}/hello.txt.tmp.4242.798cbcf78e74"), 0) != Err(ENOENT) {
                return Err("the temporary name survived the rename");
            }
        }
        Ok(())
    })();
    set_task(FAKE_TASK);
    crate::fd::detach(THREAD);
    crate::handlers::__test_fs_release(THREAD);
    crate::handlers::__test_forget_task_pid(THREAD);
    close(dirfd);
    outcome
}

/// `fd_path_of` backs `/proc/<pid>/fd/<n>`; the boot path installs it.
fn with_fd_links<T>(body: impl FnOnce() -> T) -> T {
    let prev = narf_filesystem::procfs::__test_fd_path_hook_snapshot();
    narf_filesystem::procfs::__test_fd_path_hook_restore(crate::handlers::fd_path_of as usize);
    let outcome = body();
    narf_filesystem::procfs::__test_fd_path_hook_restore(prev);
    outcome
}

fn smoke_pacman_bun_write_tmpfs() -> TestResult {
    with_tmpfs("/pacman-bun", "size=1M", || {
        with_fd_links(|| {
            if mkdir("/pacman-bun/project") != 0 {
                return Err("fixture: mkdir failed");
            }
            bun_atomic_write("/pacman-bun/project")
        })
    })
}
kernel_test_in!("syscall_abi/pacman/bun_write", smoke_pacman_bun_write_tmpfs);

fn smoke_pacman_bun_write_btrfs() -> TestResult {
    with_btrfs_at("/pacman-bun-btrfs", || {
        with_fd_links(|| {
            if mkdir("/pacman-bun-btrfs/project") != 0 {
                return Err("fixture: mkdir on btrfs failed");
            }
            bun_atomic_write("/pacman-bun-btrfs/project")
        })
    })
}
kernel_test_in!("syscall_abi/pacman/bun_write", smoke_pacman_bun_write_btrfs);

/// Claude Code as it runs on a native boot: inside PID 1's root (see
/// [`enter_hook_root`]), with procfs mounted in it.
fn smoke_pacman_bun_write_in_session_root() -> TestResult {
    with_tmpfs("/pacman-bun-session", "size=1M", || {
        with_fd_links(|| {
            if mkdir("/pacman-bun-session/project") != 0 || mkdir("/pacman-bun-session/proc") != 0 {
                return Err("fixture: mkdir failed");
            }
            let handle = registry()
                .mount(
                    &bootstrap_mount_authority(),
                    "/pacman-bun-session/proc",
                    narf_filesystem::procfs::ProcFs,
                )
                .map_err(|_| "fixture: mounting procfs in the session root failed")?;
            let outcome = (|| {
                chroot_to("/pacman-bun-session")?;
                chdir("/")?;
                bun_atomic_write("/project")
            })();
            let _ = registry().unmount(&handle, "/pacman-bun-session/proc");
            outcome
        })
    })
}
kernel_test_in!(
    "syscall_abi/pacman/bun_write",
    smoke_pacman_bun_write_in_session_root
);

/// The walk continues from the directory the link jumps to: `..` climbs
/// out of it, a name that is not there is ENOENT, and a descriptor that is
/// not a directory cannot have names under it (ENOTDIR), as from
/// `link_path_walk` after `nd_jump_link`.
fn smoke_pacman_proc_fd_prefix_walks_on_from_the_file() -> TestResult {
    with_tmpfs("/pacman-walk", "size=1M", || {
        with_fd_links(|| {
            if mkdir("/pacman-walk/a") != 0 || mkdir("/pacman-walk/a/b") != 0 {
                return Err("fixture: mkdir failed");
            }
            let file = openat("/pacman-walk/a/f", O_RDWR | O_CREAT, 0o644);
            let dirfd = openat("/pacman-walk/a/b", O_RDONLY | O_DIRECTORY, 0);
            if file < 0 || dirfd < 0 {
                return Err("fixture: open failed");
            }
            let mut pipe = [0i32; 2];
            if call(Syscall::Pipe2.raw(), a1(pipe.as_mut_ptr() as u64, 0)) != Some(0) {
                return Err("fixture: pipe2 failed");
            }
            let outcome = (|| {
                if fstatat(&alloc::format!("/proc/self/fd/{dirfd}/../f"), 0).map(|s| s.0)
                    != Ok(S_IFREG | 0o644)
                {
                    return Err("`..` after /proc/self/fd/N did not climb out of the directory");
                }
                if fstatat(&alloc::format!("/proc/self/fd/{dirfd}/missing"), 0) != Err(ENOENT) {
                    return Err("a missing name under /proc/self/fd/N is not ENOENT");
                }
                if fstatat(&alloc::format!("/proc/self/fd/{file}/x"), 0) != Err(ENOTDIR) {
                    return Err("a name under a regular file's /proc/self/fd/N is not ENOTDIR");
                }
                if fstatat(&alloc::format!("/proc/self/fd/{}/x", pipe[0]), 0) != Err(ENOTDIR) {
                    return Err("a name under a pipe's /proc/self/fd/N is not ENOTDIR");
                }
                if mkdir(&alloc::format!("/proc/self/fd/{dirfd}/c")) != 0
                    || fstatat("/pacman-walk/a/b/c", 0).map(|s| s.0 & S_IFMT) != Ok(0o040_000)
                {
                    return Err("mkdir through /proc/self/fd/N/ did not make the directory there");
                }
                Ok(())
            })();
            for fd in [file, dirfd, i64::from(pipe[0]), i64::from(pipe[1])] {
                close(fd);
            }
            outcome
        })
    })
}
kernel_test_in!(
    "syscall_abi/pacman/bun_write",
    smoke_pacman_proc_fd_prefix_walks_on_from_the_file
);

// ──────────────────────────── /dev/stdin ─────────────────────────────

/// mkinitcpio's `90-mkinitcpio-install.hook` feeds the kernel image to
/// `install -Dm644 /dev/stdin /boot/vmlinuz-<pkgbase>` on a pipe. coreutils
/// `install` stats the source first (`stat("/dev/stdin")`), then opens and
/// copies it. `/dev/stdin` is the devtmpfs symlink to `/proc/self/fd/0`, whose
/// magic link lands on the pipe: stat describes the pipe, and the open reads
/// it.
fn dev_stdin_is_the_pipe(chrooted: bool) -> Result<(), &'static str> {
    let mut pipe = [0i32; 2];
    if call(Syscall::Pipe2.raw(), a1(pipe.as_mut_ptr() as u64, 0)) != Some(0) {
        return Err("pipe2 failed");
    }
    let (r, w) = (i64::from(pipe[0]), i64::from(pipe[1]));
    if call_dup2(r as u64, 0) != Some(0) || close(r) != 0 {
        return Err("making the pipe standard input failed");
    }
    if write_all(w, b"MZ kernel image") != 15 {
        return Err("writing the pipe failed");
    }
    if chrooted {
        chroot_slash()?;
    }
    let (_, pipe_ino, _) = fstat(0).map_err(|_| "fstat(0) failed")?;
    for path in ["/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"] {
        match fstatat(path, 0) {
            Ok((mode, ino, _)) if mode & S_IFMT == S_IFIFO && ino == pipe_ino => {}
            Ok(_) => return Err("stat of the stdin link does not describe the pipe"),
            Err(_) => return Err("stat of the stdin link failed (install: cannot stat)"),
        }
        match statx(path, 0) {
            Ok((mode, ino, _)) if mode & S_IFMT == S_IFIFO && ino == pipe_ino => {}
            _ => return Err("statx of the stdin link does not describe the pipe"),
        }
    }
    if fstatat("/dev/stdin", AT_SYMLINK_NOFOLLOW).map(|s| s.0 & S_IFMT) != Ok(S_IFLNK) {
        return Err("lstat(/dev/stdin) is not the devtmpfs symlink");
    }
    let path = cstr("/dev/stdin");
    if call_access(path.as_ptr() as u64, 4) != Some(0) {
        return Err("access(/dev/stdin, R_OK) failed");
    }
    let fd = openat("/dev/stdin", O_RDONLY, 0);
    if fd < 0 {
        return Err("open(/dev/stdin) failed");
    }
    let mut got = [0u8; 32];
    let n = read_some(fd, &mut got);
    close(fd);
    close(w);
    if n != 15 || &got[..15] != b"MZ kernel image" {
        return Err("reading /dev/stdin did not read the pipe");
    }
    Ok(())
}

fn smoke_pacman_dev_stdin_pipe() -> TestResult {
    with_setup(|| with_fd_links(|| dev_stdin_is_the_pipe(false)))
}
kernel_test_in!("syscall_abi/pacman/dev_stdin", smoke_pacman_dev_stdin_pipe);

fn smoke_pacman_dev_stdin_pipe_in_chroot() -> TestResult {
    with_setup(|| with_fd_links(|| dev_stdin_is_the_pipe(true)))
}
kernel_test_in!(
    "syscall_abi/pacman/dev_stdin",
    smoke_pacman_dev_stdin_pipe_in_chroot
);

// ──────────────────────────── mount table ────────────────────────────

/// A RAM disk the block registry can hand to `mount -t btrfs /dev/<name>`.
struct ImageDevice {
    data: narf_lib::sync::IrqSafeSpinLock<Vec<u8>>,
}

impl narf_block::BlockDeviceSync for ImageDevice {
    fn lba_size(&self) -> u32 {
        512
    }

    fn capacity(&self) -> u64 {
        (self.data.lock().len() / 512) as u64
    }

    fn read(
        &self,
        lba: u64,
        n_blocks: u16,
        out: &mut [u8],
    ) -> Result<(), narf_block::BlockIoError> {
        let data = self.data.lock();
        let start = lba as usize * 512;
        let end = start + usize::from(n_blocks) * 512;
        if end > data.len() {
            return Err(narf_block::BlockIoError::OutOfRange);
        }
        if out.len() < end - start {
            return Err(narf_block::BlockIoError::BufferTooSmall);
        }
        out[..end - start].copy_from_slice(&data[start..end]);
        Ok(())
    }

    fn write(&self, lba: u64, n_blocks: u16, src: &[u8]) -> Result<(), narf_block::BlockIoError> {
        let mut data = self.data.lock();
        let start = lba as usize * 512;
        let end = start + usize::from(n_blocks) * 512;
        if end > data.len() {
            return Err(narf_block::BlockIoError::OutOfRange);
        }
        if src.len() < end - start {
            return Err(narf_block::BlockIoError::BufferTooSmall);
        }
        data[start..end].copy_from_slice(&src[..end - start]);
        Ok(())
    }
}

const MOUNT_DISK: &str = "pacmanvd0p2";
const DEFAULT_SUBVOL_FIXTURE: &[u8] =
    include_bytes!("../../drivers/fs/btrfs/testdata/fixture-defaultsubvol.img.sparse");

fn mount(source: Option<&str>, target: &str, fstype: &str, flags: u64, data: &str) -> i64 {
    let source = source.map(cstr);
    let (target, fstype, data) = (cstr(target), cstr(fstype), cstr(data));
    call(
        Syscall::Mount.raw(),
        a4(
            source.as_ref().map_or(0, |s| s.as_ptr() as u64),
            target.as_ptr() as u64,
            fstype.as_ptr() as u64,
            flags,
            data.as_ptr() as u64,
        ),
    )
    .unwrap_or(i64::MIN)
}

fn umount(target: &str) {
    let target = cstr(target);
    let _ = call(Syscall::Umount2.raw(), a1(target.as_ptr() as u64, 0));
}

/// The `/proc/self/mounts` and `/proc/self/mountinfo` rows for `target`.
fn mount_rows(target: &str) -> Result<(String, String), &'static str> {
    let mounts = read_file("/proc/self/mounts")?;
    let mountinfo = read_file("/proc/self/mountinfo")?;
    let mounts = String::from_utf8(mounts).map_err(|_| "/proc/self/mounts is not UTF-8")?;
    let mountinfo =
        String::from_utf8(mountinfo).map_err(|_| "/proc/self/mountinfo is not UTF-8")?;
    let row = mounts
        .lines()
        .rfind(|line| line.split(' ').nth(1) == Some(target))
        .ok_or("no /proc/self/mounts row for the mount")?;
    let info = mountinfo
        .lines()
        .rfind(|line| line.split(' ').nth(4) == Some(target))
        .ok_or("no /proc/self/mountinfo row for the mount")?;
    Ok((String::from(row), String::from(info)))
}

/// `show_vfsmnt` / `show_mountinfo`: the source of a btrfs mount is the
/// device (`btrfs_show_devname`), and mountinfo's root is the mounted
/// subvolume's path from the top level (`/@` for CachyOS's root). For a
/// filesystem with no `show_devname` the source is the string the mount was
/// made with (`mnt_devname`), `none` when there was none.
fn smoke_pacman_mount_sources() -> TestResult {
    with_setup(|| {
        let image = crate::abi_fault_write_tests::btrfs_decode_sparse(DEFAULT_SUBVOL_FIXTURE);
        narf_block::register_block_device(
            MOUNT_DISK,
            Arc::new(ImageDevice {
                data: narf_lib::sync::IrqSafeSpinLock::new(image),
            }),
        );
        let outcome = (|| {
            const MS_RDONLY: u64 = 1;
            let device = alloc::format!("/dev/{MOUNT_DISK}");
            // The default subvolume (`def`), then the top level by id.
            for (target, data, root) in [
                ("/pacman-mnt-default", "", "/def"),
                ("/pacman-mnt-top", "subvolid=5", "/"),
                ("/pacman-mnt-named", "subvol=/def", "/def"),
            ] {
                if mount(Some(&device), target, "btrfs", MS_RDONLY, data) != 0 {
                    return Err("mount -t btrfs /dev/<disk> failed");
                }
                let rows = mount_rows(target);
                umount(target);
                let (row, info) = rows?;
                if row.split(' ').next() != Some(device.as_str()) {
                    return Err("/proc/self/mounts does not name the btrfs device as the source");
                }
                let fields: Vec<&str> = info.split(' ').collect();
                let dash = fields
                    .iter()
                    .position(|f| *f == "-")
                    .ok_or("mountinfo row has no separator")?;
                if fields.get(dash + 1) != Some(&"btrfs")
                    || fields.get(dash + 2) != Some(&device.as_str())
                {
                    return Err(
                        "/proc/self/mountinfo does not name the btrfs device as the source",
                    );
                }
                if fields.get(3) != Some(&root) {
                    return Err("mountinfo's root is not the mounted subvolume's path");
                }
            }
            // mnt_devname: what the mount was made with.
            if mount(
                Some("pacmantmp"),
                "/pacman-mnt-tmpfs",
                "tmpfs",
                0,
                "size=64k",
            ) != 0
            {
                return Err("mount -t tmpfs pacmantmp failed");
            }
            let rows = mount_rows("/pacman-mnt-tmpfs");
            umount("/pacman-mnt-tmpfs");
            let (row, info) = rows?;
            if !row.starts_with("pacmantmp /pacman-mnt-tmpfs tmpfs ")
                || !info.contains(" - tmpfs pacmantmp ")
            {
                return Err("a tmpfs mount does not show the source it was mounted with");
            }
            if mount(None, "/pacman-mnt-none", "tmpfs", 0, "size=64k") != 0 {
                return Err("mount -t tmpfs with no source failed");
            }
            let rows = mount_rows("/pacman-mnt-none");
            umount("/pacman-mnt-none");
            let (row, info) = rows?;
            if !row.starts_with("none /pacman-mnt-none tmpfs ") || !info.contains(" - tmpfs none ")
            {
                return Err("a mount with no source does not show `none`");
            }
            Ok(())
        })();
        narf_block::unregister_block_device(MOUNT_DISK);
        outcome
    })
}
kernel_test_in!("syscall_abi/pacman/mounts", smoke_pacman_mount_sources);

//! Linux superblock magics, the `f_type` `statfs(2)` reports.
//!
//! Every Linux filesystem's `->statfs` copies `sb->s_magic` into
//! `buf->f_type`, and userspace detects filesystems by it: systemd and
//! elogind look for `CGROUP2_SUPER_MAGIC` at `/sys/fs/cgroup`, sd-device for
//! `SYSFS_MAGIC` behind a `/sys` descriptor, `df`, `stat -f` and `findmnt`
//! name the type from it. The values are `include/uapi/linux/magic.h`'s,
//! plus the few a filesystem defines privately (`CONFIGFS_MAGIC` in
//! `fs/configfs/mount.c`, `FUSE_CTL_SUPER_MAGIC` in `fs/fuse/control.c`,
//! `MQUEUE_MAGIC` in `ipc/mqueue.c`).
//!
//! [`for_fs_type`] maps a filesystem type name — what [`crate::FsInstance::name`]
//! returns and `/proc/mounts` prints — to its magic, and is the default of
//! [`crate::FsInstance::magic`].

pub const TMPFS_MAGIC: u64 = 0x0102_1994;
pub const RAMFS_MAGIC: u64 = 0x8584_58f6;
pub const HUGETLBFS_MAGIC: u64 = 0x9584_58f6;
pub const PROC_SUPER_MAGIC: u64 = 0x9fa0;
pub const SYSFS_MAGIC: u64 = 0x6265_6572;
pub const CGROUP_SUPER_MAGIC: u64 = 0x0027_e0eb;
pub const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
pub const DEVPTS_SUPER_MAGIC: u64 = 0x1cd1;
pub const MQUEUE_MAGIC: u64 = 0x1980_0202;
pub const DEBUGFS_MAGIC: u64 = 0x6462_6720;
pub const TRACEFS_MAGIC: u64 = 0x7472_6163;
pub const SECURITYFS_MAGIC: u64 = 0x7363_6673;
pub const PSTOREFS_MAGIC: u64 = 0x6165_676c;
pub const CONFIGFS_MAGIC: u64 = 0x6265_6570;
pub const EFIVARFS_MAGIC: u64 = 0xde5e_81e4;
pub const BPF_FS_MAGIC: u64 = 0xcafe_4a11;
pub const BINFMTFS_MAGIC: u64 = 0x4249_4e4d;
pub const AUTOFS_SUPER_MAGIC: u64 = 0x0187;
pub const BTRFS_SUPER_MAGIC: u64 = 0x9123_683e;
/// ext2, ext3 and ext4 share it.
pub const EXT4_SUPER_MAGIC: u64 = 0xef53;
/// vfat and msdos share it.
pub const MSDOS_SUPER_MAGIC: u64 = 0x4d44;
pub const EXFAT_SUPER_MAGIC: u64 = 0x2011_bab0;
pub const ISOFS_SUPER_MAGIC: u64 = 0x9660;
pub const UDF_SUPER_MAGIC: u64 = 0x1501_3346;
pub const SQUASHFS_MAGIC: u64 = 0x7371_7368;
/// minix v1, 14-character names.
pub const MINIX_SUPER_MAGIC: u64 = 0x137f;
/// minix v1, 30-character names.
pub const MINIX_SUPER_MAGIC2: u64 = 0x138f;
/// minix v2, 14-character names.
pub const MINIX2_SUPER_MAGIC: u64 = 0x2468;
/// minix v2, 30-character names.
pub const MINIX2_SUPER_MAGIC2: u64 = 0x2478;
pub const MINIX3_SUPER_MAGIC: u64 = 0x4d5a;
pub const V9FS_MAGIC: u64 = 0x0102_1997;
pub const OVERLAYFS_SUPER_MAGIC: u64 = 0x794c_7630;
/// fuse, fuseblk and virtiofs (a FUSE transport) share it.
pub const FUSE_SUPER_MAGIC: u64 = 0x6573_5546;
pub const FUSE_CTL_SUPER_MAGIC: u64 = 0x6573_5543;

/// The magic of the filesystem type named `name`.
///
/// NARF names a FAT volume by its FAT width and a minix volume by its
/// version; Linux mounts every FAT volume as vfat or msdos and reports
/// `MSDOS_SUPER_MAGIC` for both. A name this table does not know is one of
/// NARF's in-memory trees — tmpfs and devtmpfs themselves, and the MemFs
/// instances behind `/dev/shm`, `/tmp` and the like — which Linux serves
/// from shmem, so it is `TMPFS_MAGIC`.
pub fn for_fs_type(name: &str) -> u64 {
    match name {
        "btrfs" => BTRFS_SUPER_MAGIC,
        "ext2" | "ext3" | "ext4" => EXT4_SUPER_MAGIC,
        "vfat" | "msdos" | "fat" | "fat12" | "fat16" | "fat32" => MSDOS_SUPER_MAGIC,
        "exfat" => EXFAT_SUPER_MAGIC,
        "iso9660" => ISOFS_SUPER_MAGIC,
        "udf" => UDF_SUPER_MAGIC,
        "squashfs" => SQUASHFS_MAGIC,
        "minix" | "minix1" => MINIX_SUPER_MAGIC,
        "minix2" => MINIX2_SUPER_MAGIC,
        "minix3" => MINIX3_SUPER_MAGIC,
        "9p" => V9FS_MAGIC,
        "overlay" | "overlayfs" => OVERLAYFS_SUPER_MAGIC,
        "fuse" | "fuseblk" | "virtiofs" => FUSE_SUPER_MAGIC,
        n if n.starts_with("fuse.") || n.starts_with("fuseblk.") => FUSE_SUPER_MAGIC,
        "fusectl" => FUSE_CTL_SUPER_MAGIC,
        "proc" | "procfs" => PROC_SUPER_MAGIC,
        "sysfs" => SYSFS_MAGIC,
        "cgroup2" => CGROUP2_SUPER_MAGIC,
        "cgroup" => CGROUP_SUPER_MAGIC,
        "devpts" => DEVPTS_SUPER_MAGIC,
        "mqueue" => MQUEUE_MAGIC,
        "ramfs" => RAMFS_MAGIC,
        "hugetlbfs" => HUGETLBFS_MAGIC,
        "debugfs" => DEBUGFS_MAGIC,
        "tracefs" => TRACEFS_MAGIC,
        "securityfs" => SECURITYFS_MAGIC,
        "pstore" => PSTOREFS_MAGIC,
        "configfs" => CONFIGFS_MAGIC,
        "efivarfs" => EFIVARFS_MAGIC,
        "bpf" | "bpffs" => BPF_FS_MAGIC,
        "binfmt_misc" => BINFMTFS_MAGIC,
        "autofs" => AUTOFS_SUPER_MAGIC,
        _ => TMPFS_MAGIC,
    }
}

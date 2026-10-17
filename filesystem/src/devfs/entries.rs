//! Builtin device nodes, including mountpoints and optional driver delegates.
use super::*;

pub(super) struct Entry {
    pub name: &'static str,
    pub file_type: FileType,
    pub file: fn() -> Option<Arc<dyn FileOps>>,
    pub directory: fn() -> Option<Arc<dyn DirOps>>,
    pub visible: fn() -> bool,
}

pub(super) const ENTRIES: &[Entry] = &[
    Entry {
        name: "fd",
        file_type: FileType::Symlink,
        file: || {
            Some(Arc::new(DevSymlink {
                target: "/proc/self/fd".into(),
                inode: named_inode("fd", 2),
            }))
        },
        directory: || None,
        visible: || true,
    },
    Entry {
        name: "stdin",
        file_type: FileType::Symlink,
        file: || {
            Some(Arc::new(DevSymlink {
                target: "/proc/self/fd/0".into(),
                inode: named_inode("stdin", 2),
            }))
        },
        directory: || None,
        visible: || true,
    },
    Entry {
        name: "stdout",
        file_type: FileType::Symlink,
        file: || {
            Some(Arc::new(DevSymlink {
                target: "/proc/self/fd/1".into(),
                inode: named_inode("stdout", 2),
            }))
        },
        directory: || None,
        visible: || true,
    },
    Entry {
        name: "stderr",
        file_type: FileType::Symlink,
        file: || {
            Some(Arc::new(DevSymlink {
                target: "/proc/self/fd/2".into(),
                inode: named_inode("stderr", 2),
            }))
        },
        directory: || None,
        visible: || true,
    },
    Entry {
        name: "rtc",
        file_type: FileType::Symlink,
        file: || {
            Some(Arc::new(DevSymlink {
                target: "/dev/rtc0".into(),
                inode: named_inode("rtc", 2),
            }))
        },
        directory: || None,
        visible: || true,
    },
    Entry {
        name: "null",
        file_type: FileType::Special,
        file: || Some(Arc::new(DevNull)),
        directory: || None,
        visible: || true,
    },
    Entry {
        name: "zero",
        file_type: FileType::Special,
        file: || Some(Arc::new(DevZero)),
        directory: || None,
        visible: || true,
    },
    Entry {
        name: "full",
        file_type: FileType::Special,
        file: || Some(Arc::new(crate::devfs_misc::DevFull)),
        directory: || None,
        visible: || true,
    },
    Entry {
        name: "random",
        file_type: FileType::Special,
        file: || Some(Arc::new(DevBlockingRandom)),
        directory: || None,
        visible: || true,
    },
    Entry {
        name: "urandom",
        file_type: FileType::Special,
        file: || Some(Arc::new(DevRandom)),
        directory: || None,
        visible: || true,
    },
    Entry {
        name: "kmsg",
        file_type: FileType::Special,
        file: || Some(Arc::new(DevKmsg::new())),
        directory: || None,
        visible: || true,
    },
    Entry {
        name: "console",
        file_type: FileType::Special,
        file: || {
            Some(Arc::new(DevConsole {
                kind: ConsoleNodeKind::Console,
            }))
        },
        directory: || None,
        visible: || true,
    },
    Entry {
        name: "tty",
        file_type: FileType::Special,
        file: || {
            Some(Arc::new(DevConsole {
                kind: ConsoleNodeKind::CurrentTty,
            }))
        },
        directory: || None,
        visible: || true,
    },
    Entry {
        name: "tty0",
        file_type: FileType::Special,
        file: || {
            Some(Arc::new(DevConsole {
                kind: ConsoleNodeKind::Virtual(0),
            }))
        },
        directory: || None,
        visible: || true,
    },
    Entry {
        name: "tty1",
        file_type: FileType::Special,
        file: || {
            Some(Arc::new(DevConsole {
                kind: ConsoleNodeKind::Virtual(1),
            }))
        },
        directory: || None,
        visible: || true,
    },
    Entry {
        name: "ptmx",
        file_type: FileType::Special,
        file: || Some(Arc::new(crate::devfs_pty::DevTmpfsPtmx)),
        directory: || None,
        visible: || true,
    },
    Entry {
        name: "uinput",
        file_type: FileType::Special,
        file: || Some(Arc::new(crate::devfs_input::UinputControlFile::new())),
        directory: || None,
        visible: || true,
    },
    Entry {
        name: "fuse",
        file_type: FileType::Special,
        file: || Some(Arc::new(DevFuseNode)),
        directory: || None,
        visible: || true,
    },
    Entry {
        name: "rtc0",
        file_type: FileType::Special,
        file: || Some(Arc::new(crate::devfs_rtc::DevRtc)),
        directory: || None,
        visible: || true,
    },
    Entry {
        name: "fp0",
        file_type: FileType::Special,
        file: || {
            if FP_NODE.lock().is_some() {
                Some(Arc::new(DevFp))
            } else {
                None
            }
        },
        directory: || None,
        visible: || FP_NODE.lock().is_some(),
    },
    Entry {
        name: "fb0",
        file_type: FileType::Special,
        file: || {
            if FB0_NODE.lock().is_some() {
                Some(Arc::new(DevFb0Proxy))
            } else {
                None
            }
        },
        directory: || None,
        visible: || FB0_NODE.lock().is_some(),
    },
    Entry {
        name: "tpm0",
        file_type: FileType::Special,
        file: || {
            if TPM0_NODE.lock().is_some() {
                Some(Arc::new(DevTpm0Proxy))
            } else {
                None
            }
        },
        directory: || None,
        visible: || TPM0_NODE.lock().is_some(),
    },
    Entry {
        name: "tpmrm0",
        file_type: FileType::Special,
        file: || {
            if TPMRM0_NODE.lock().is_some() {
                Some(Arc::new(DevTpmRm0Proxy))
            } else {
                None
            }
        },
        directory: || None,
        visible: || TPMRM0_NODE.lock().is_some(),
    },
    Entry {
        name: "pts",
        file_type: FileType::Dir,
        file: || None,
        directory: || Some(Arc::new(DevEmptyDir { inode: 3 })),
        visible: || true,
    },
    Entry {
        name: "shm",
        file_type: FileType::Dir,
        file: || None,
        directory: || Some(Arc::new(DevEmptyDir { inode: 4 })),
        visible: || true,
    },
    Entry {
        name: "mqueue",
        file_type: FileType::Dir,
        file: || None,
        directory: || Some(Arc::new(DevEmptyDir { inode: 5 })),
        visible: || true,
    },
    Entry {
        name: "hugepages",
        file_type: FileType::Dir,
        file: || None,
        directory: || Some(Arc::new(DevEmptyDir { inode: 6 })),
        visible: || true,
    },
    Entry {
        name: "disk",
        file_type: FileType::Dir,
        file: || None,
        directory: || Some(Arc::new(crate::devfs_block::DevDiskDir)),
        visible: || true,
    },
    Entry {
        name: "input",
        file_type: FileType::Dir,
        file: || None,
        directory: || Some(Arc::new(crate::devfs_input::DevInputDir)),
        visible: || true,
    },
    Entry {
        name: "snd",
        file_type: FileType::Dir,
        file: || None,
        directory: || SND_DIR.lock().clone(),
        visible: || SND_DIR.lock().is_some(),
    },
    Entry {
        name: "dri",
        file_type: FileType::Dir,
        file: || None,
        directory: || DRI_DIR.lock().clone(),
        visible: || DRI_DIR.lock().is_some(),
    },
];

pub(super) fn find(name: &str) -> Option<&'static Entry> {
    ENTRIES.iter().find(|entry| entry.name == name)
}

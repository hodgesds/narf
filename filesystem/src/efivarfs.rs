//! Linux-compatible EFI variable filesystem.
//!
//! The file ABI follows Linux `fs/efivarfs`: each filename is
//! `VariableName-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, reads prepend the
//! variable's four-byte attribute word, and writes replace the complete
//! value using the same prefix. Firmware calls are serialized by an async
//! mutex; the directory cache never invents values when EFI Runtime Services
//! are unavailable.

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use narf_block::BlockError;
use narf_efi::runtime::{self, EfiStatus, EfiVariableId, EfiVariableInfo, EfiVariableValue};
use narf_efi::variable::{attr, Guid, EFI_GLOBAL_VARIABLE};
use narf_lib::mutex::Mutex;
use narf_lib::sync::IrqSafeSpinLock;

use crate::{
    DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, FsInstance, FsIoctlReply, FsStat, Mode,
    Stat,
};

const EFIVARFS_MAGIC: u64 = 0xde5e_81e4;
const MAX_VARIABLES: usize = 4096;
const EFI_VARIABLE_MASK: u32 = attr::NON_VOLATILE
    | attr::BOOTSERVICE_ACCESS
    | attr::RUNTIME_ACCESS
    | attr::HARDWARE_ERROR_RECORD
    | attr::AUTHENTICATED_WRITE_ACCESS
    | attr::TIME_BASED_AUTHENTICATED_WRITE_ACCESS
    | attr::APPEND_WRITE;
const QUERY_ATTRS: u32 = attr::NON_VOLATILE | attr::BOOTSERVICE_ACCESS | attr::RUNTIME_ACCESS;
const FS_IMMUTABLE_FL: u32 = 0x10;
const FS_IOC_GETFLAGS_NR: u32 = 0x6601;
const FS_IOC_SETFLAGS_NR: u32 = 0x6602;

const LINUX_EFI_RANDOM_SEED_TABLE_GUID: Guid = Guid::new(
    0x1ce1_e5bc,
    0x7ceb,
    0x42f2,
    [0x81, 0xe5, 0x8a, 0xad, 0xf1, 0x80, 0xf5, 0x7b],
);
const LINUX_EFI_CRASH_GUID: Guid = Guid::new(
    0xcfc8_fc79,
    0xbe2e,
    0x4ddc,
    [0x97, 0xf0, 0x9f, 0x98, 0xbf, 0xe2, 0x98, 0xa0],
);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct VariableKey {
    name: String,
    guid: [u8; 16],
}

impl VariableKey {
    fn new(name: String, guid: Guid) -> Self {
        Self { name, guid: guid.0 }
    }

    fn guid(&self) -> Guid {
        Guid(self.guid)
    }

    fn display_key(&self) -> Self {
        Self {
            name: self.name.replace('/', "!"),
            guid: self.guid,
        }
    }

    fn filename(&self) -> String {
        format!("{}-{}", self.display_key().name, format_guid(self.guid()))
    }
}

#[derive(Debug)]
struct VariableEntry {
    key: VariableKey,
    ino: u64,
    size: AtomicU64,
    committed: AtomicBool,
    removed: AtomicBool,
    immutable: AtomicBool,
    op_lock: Mutex<()>,
}

impl VariableEntry {
    fn new(key: VariableKey, data_size: usize, committed: bool) -> Self {
        let immutable = !variable_is_removable(&key);
        Self {
            ino: inode_for(&key),
            key,
            size: AtomicU64::new(data_size as u64),
            committed: AtomicBool::new(committed),
            removed: AtomicBool::new(false),
            immutable: AtomicBool::new(immutable),
            op_lock: Mutex::new(()),
        }
    }
}

trait VariableBackend: Send {
    fn list(&mut self) -> Result<Vec<EfiVariableId>, EfiStatus>;
    fn get(&mut self, key: &VariableKey) -> Result<EfiVariableValue, EfiStatus>;
    fn set(&mut self, key: &VariableKey, attributes: u32, data: &[u8]) -> Result<(), EfiStatus>;
    fn query(&mut self, attributes: u32) -> Result<EfiVariableInfo, EfiStatus>;
}

#[derive(Debug)]
struct RuntimeBackend;

impl VariableBackend for RuntimeBackend {
    fn list(&mut self) -> Result<Vec<EfiVariableId>, EfiStatus> {
        // SAFETY: efivarfs is only constructed after the validated runtime
        // table and its persistent mappings have been installed.
        unsafe { runtime::list_variables(MAX_VARIABLES) }
    }

    fn get(&mut self, key: &VariableKey) -> Result<EfiVariableValue, EfiStatus> {
        // SAFETY: calls are serialized by `EfivarInner::backend`.
        unsafe { runtime::get_variable_with_attributes(&key.name, &key.guid()) }
    }

    fn set(&mut self, key: &VariableKey, attributes: u32, data: &[u8]) -> Result<(), EfiStatus> {
        // SAFETY: calls are serialized by `EfivarInner::backend`.
        unsafe { runtime::set_variable(&key.name, &key.guid(), attributes, data) }
    }

    fn query(&mut self, attributes: u32) -> Result<EfiVariableInfo, EfiStatus> {
        // SAFETY: calls are serialized by `EfivarInner::backend`.
        unsafe { runtime::query_variable_info(attributes) }
    }
}

struct EfivarInner {
    backend: Mutex<Box<dyn VariableBackend>>,
    entries: IrqSafeSpinLock<BTreeMap<VariableKey, Arc<VariableEntry>>>,
    uid: u32,
    gid: u32,
}

impl fmt::Debug for EfivarInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EfivarInner")
            .field("entries", &self.entries.lock().len())
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .finish_non_exhaustive()
    }
}

/// One Linux efivarfs instance backed by installed EFI Runtime Services.
#[derive(Debug)]
pub struct EfivarFs {
    inner: Arc<EfivarInner>,
}

impl EfivarFs {
    /// Construct a mount from Linux `uid=`/`gid=` options.
    ///
    /// Returns `Unsupported` when the boot path did not preserve and install
    /// EFI Runtime Services; callers must not substitute an in-memory store.
    pub fn from_options(
        options: &str,
        default_uid: u32,
        default_gid: u32,
    ) -> Result<Self, FsError> {
        if !runtime::is_available() {
            return Err(FsError::Unsupported);
        }
        let (uid, gid) = parse_options(options, default_uid, default_gid)?;
        Self::with_backend(Box::new(RuntimeBackend), uid, gid)
    }

    fn with_backend(
        mut backend: Box<dyn VariableBackend>,
        uid: u32,
        gid: u32,
    ) -> Result<Self, FsError> {
        let variables = backend.list().map_err(status_to_fs_error)?;
        let mut entries = BTreeMap::new();
        for id in variables {
            if id.vendor == LINUX_EFI_RANDOM_SEED_TABLE_GUID {
                continue;
            }
            let key = VariableKey::new(id.name, id.vendor);
            let display_key = key.display_key();
            if entries.contains_key(&display_key) {
                return Err(FsError::Io(BlockError::IOError));
            }
            let data_size = match backend.get(&key) {
                Ok(value) => value.data.len(),
                Err(runtime::EFI_NOT_FOUND) => 0,
                Err(status) => return Err(status_to_fs_error(status)),
            };
            entries.insert(
                display_key,
                Arc::new(VariableEntry::new(key, data_size, true)),
            );
        }
        Ok(Self {
            inner: Arc::new(EfivarInner {
                backend: Mutex::new(backend),
                entries: IrqSafeSpinLock::new(entries),
                uid,
                gid,
            }),
        })
    }
}

impl FsInstance for EfivarFs {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::new(EfivarRoot {
            inner: self.inner.clone(),
        })
    }

    fn name(&self) -> &str {
        "efivarfs"
    }

    fn statfs<'a>(&'a self) -> FsFuture<'a, FsStat> {
        Box::pin(async move {
            let mut backend = self.inner.backend.lock().await;
            let info = backend.query(QUERY_ATTRS).ok();
            Ok(FsStat {
                blocks: info.map(|v| v.storage_bytes).unwrap_or(0),
                blocks_free: info.map(|v| v.remaining_bytes).unwrap_or(0),
                blocks_available: info.map(|v| v.remaining_bytes).unwrap_or(0),
                files: self.inner.entries.lock().len() as u64,
                files_free: 0,
                block_size: 1,
                name_len: 255,
                fragment_size: 1,
            })
        })
    }
}

#[derive(Debug)]
struct EfivarRoot {
    inner: Arc<EfivarInner>,
}

impl EfivarRoot {
    fn entry(&self, name: &str) -> Option<Arc<VariableEntry>> {
        let key = parse_filename(name).ok()?;
        self.inner.entries.lock().get(&key).cloned()
    }
}

impl DirOps for EfivarRoot {
    fn ino(&self) -> u64 {
        EFIVARFS_MAGIC
    }

    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        self.entry(name).map(|entry| {
            Arc::new(EfivarFile {
                inner: self.inner.clone(),
                entry,
            }) as Arc<dyn FileOps>
        })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        self.inner
            .entries
            .lock()
            .values()
            .skip(cursor)
            .take(max)
            .map(|entry| (entry.key.filename(), FileType::File))
            .collect()
    }

    fn dir_owners(&self) -> (u32, u32) {
        (self.inner.uid, self.inner.gid)
    }

    fn create<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let key = parse_filename(name)?;
            if key.guid() == LINUX_EFI_RANDOM_SEED_TABLE_GUID {
                return Err(FsError::PermissionDenied);
            }
            let entry = {
                let mut entries = self.inner.entries.lock();
                if entries.contains_key(&key) {
                    return Err(FsError::Busy);
                }
                let entry = Arc::new(VariableEntry::new(key.clone(), 0, false));
                entries.insert(key, entry.clone());
                entry
            };
            Ok(Arc::new(EfivarFile {
                inner: self.inner.clone(),
                entry,
            }) as Arc<dyn FileOps>)
        })
    }

    fn unlink<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let key = parse_filename(name)?;
            let entry = self
                .inner
                .entries
                .lock()
                .get(&key)
                .cloned()
                .ok_or(FsError::NotFound)?;
            let _operation = entry.op_lock.lock().await;
            if entry.removed.load(Ordering::Acquire) {
                return Err(FsError::NotFound);
            }
            if entry.immutable.load(Ordering::Acquire) {
                return Err(FsError::PermissionDenied);
            }
            if entry.committed.load(Ordering::Acquire) {
                let mut backend = self.inner.backend.lock().await;
                match backend.set(&entry.key, 0, &[]) {
                    Ok(()) | Err(runtime::EFI_NOT_FOUND) => {}
                    Err(status) => return Err(status_to_fs_error(status)),
                }
            }
            entry.removed.store(true, Ordering::Release);
            self.inner.entries.lock().remove(&key);
            Ok(())
        })
    }
}

#[derive(Debug)]
struct EfivarFile {
    inner: Arc<EfivarInner>,
    entry: Arc<VariableEntry>,
}

impl FileOps for EfivarFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            if !self.entry.committed.load(Ordering::Acquire) {
                return Ok(0);
            }
            let value = {
                let mut backend = self.inner.backend.lock().await;
                match backend.get(&self.entry.key) {
                    Ok(value) => value,
                    Err(runtime::EFI_NOT_FOUND) => return Ok(0),
                    Err(status) => return Err(status_to_fs_error(status)),
                }
            };
            self.entry
                .size
                .store(value.data.len() as u64, Ordering::Release);
            let total = value.data.len().saturating_add(4);
            let start = usize::try_from(offset).unwrap_or(usize::MAX);
            if start >= total {
                return Ok(0);
            }
            let mut bytes = Vec::with_capacity(total);
            bytes.extend_from_slice(&value.attributes.to_le_bytes());
            bytes.extend_from_slice(&value.data);
            let count = (total - start).min(buf.len());
            buf[..count].copy_from_slice(&bytes[start..start + count]);
            Ok(count)
        })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let _operation = self.entry.op_lock.lock().await;
            if self.entry.removed.load(Ordering::Acquire) {
                return Err(FsError::Io(BlockError::IOError));
            }
            if self.entry.immutable.load(Ordering::Acquire) {
                return Err(FsError::PermissionDenied);
            }
            let attributes = u32::from_le_bytes(
                buf.get(..4)
                    .ok_or(FsError::InvalidData)?
                    .try_into()
                    .map_err(|_| FsError::InvalidData)?,
            );
            if attributes & !EFI_VARIABLE_MASK != 0 {
                return Err(FsError::InvalidData);
            }
            let data = &buf[4..];
            if !validate_variable(&self.entry.key, data) {
                return Err(FsError::InvalidData);
            }
            let actual = {
                let mut backend = self.inner.backend.lock().await;
                backend
                    .set(&self.entry.key, attributes, data)
                    .map_err(status_to_fs_error)?;
                match backend.get(&self.entry.key) {
                    Ok(value) => Some(value.data.len()),
                    Err(runtime::EFI_NOT_FOUND) => None,
                    Err(status) => return Err(status_to_fs_error(status)),
                }
            };
            match actual {
                Some(size) => {
                    self.entry.size.store(size as u64, Ordering::Release);
                    self.entry.committed.store(true, Ordering::Release);
                }
                None => {
                    self.entry.size.store(0, Ordering::Release);
                    self.entry.committed.store(false, Ordering::Release);
                    self.entry.removed.store(true, Ordering::Release);
                    self.inner
                        .entries
                        .lock()
                        .remove(&self.entry.key.display_key());
                }
            }
            Ok(buf.len())
        })
    }

    fn stat(&self) -> Stat {
        let size = if self.entry.committed.load(Ordering::Acquire) {
            self.entry.size.load(Ordering::Acquire).saturating_add(4)
        } else {
            0
        };
        Stat {
            size,
            blocks: 0,
            mode: Mode {
                file_type: FileType::File,
                perms: 0o644,
            },
            mtime_cycles: 0,
        }
    }

    fn ino(&self) -> u64 {
        self.entry.ino
    }

    fn owners(&self) -> (u32, u32) {
        (self.inner.uid, self.inner.gid)
    }

    fn ioctl_async<'a>(
        &'a self,
        cmd: u32,
        _arg: u64,
        input: &'a [u8],
        out_size: usize,
    ) -> FsFuture<'a, FsIoctlReply> {
        Box::pin(async move {
            match cmd & 0xffff {
                FS_IOC_GETFLAGS_NR => {
                    if out_size != 4 && out_size != 8 {
                        return Err(FsError::InvalidData);
                    }
                    let flags = if self.entry.immutable.load(Ordering::Acquire) {
                        FS_IMMUTABLE_FL
                    } else {
                        0
                    };
                    let mut output = Vec::with_capacity(out_size);
                    output.extend_from_slice(&flags.to_ne_bytes());
                    output.resize(out_size, 0);
                    Ok(FsIoctlReply { result: 0, output })
                }
                FS_IOC_SETFLAGS_NR => {
                    let raw = input.get(..4).ok_or(FsError::InvalidData)?;
                    let flags =
                        u32::from_ne_bytes(raw.try_into().map_err(|_| FsError::InvalidData)?);
                    if flags & !FS_IMMUTABLE_FL != 0 {
                        return Err(FsError::Unsupported);
                    }
                    self.entry
                        .immutable
                        .store(flags & FS_IMMUTABLE_FL != 0, Ordering::Release);
                    Ok(FsIoctlReply {
                        result: 0,
                        output: Vec::new(),
                    })
                }
                _ => Err(FsError::Unsupported),
            }
        })
    }
}

fn parse_options(options: &str, mut uid: u32, mut gid: u32) -> Result<(u32, u32), FsError> {
    for option in options.split(',').filter(|option| !option.is_empty()) {
        let (key, value) = option.split_once('=').ok_or(FsError::InvalidData)?;
        match key {
            "uid" => uid = value.parse().map_err(|_| FsError::InvalidData)?,
            "gid" => gid = value.parse().map_err(|_| FsError::InvalidData)?,
            _ => return Err(FsError::InvalidData),
        }
    }
    Ok((uid, gid))
}

fn parse_filename(filename: &str) -> Result<VariableKey, FsError> {
    if filename.len() < 38 {
        return Err(FsError::InvalidPath);
    }
    let separator = filename.len() - 37;
    if filename.as_bytes().get(separator) != Some(&b'-') || separator == 0 {
        return Err(FsError::InvalidPath);
    }
    let name = filename.get(..separator).ok_or(FsError::InvalidPath)?;
    let guid = filename
        .get(separator + 1..)
        .and_then(parse_guid)
        .ok_or(FsError::InvalidPath)?;
    Ok(VariableKey::new(name.to_string(), guid))
}

fn format_guid(guid: Guid) -> String {
    let b = guid.0;
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}

fn parse_guid(text: &str) -> Option<Guid> {
    let bytes = text.as_bytes();
    if bytes.len() != 36 || [8, 13, 18, 23].iter().any(|&i| bytes[i] != b'-') {
        return None;
    }
    let d1 = u32::from_str_radix(text.get(0..8)?, 16).ok()?;
    let d2 = u16::from_str_radix(text.get(9..13)?, 16).ok()?;
    let d3 = u16::from_str_radix(text.get(14..18)?, 16).ok()?;
    let mut d4 = [0u8; 8];
    let tail = [
        text.get(19..21)?,
        text.get(21..23)?,
        text.get(24..26)?,
        text.get(26..28)?,
        text.get(28..30)?,
        text.get(30..32)?,
        text.get(32..34)?,
        text.get(34..36)?,
    ];
    for (dst, src) in d4.iter_mut().zip(tail) {
        *dst = u8::from_str_radix(src, 16).ok()?;
    }
    Some(Guid::new(d1, d2, d3, d4))
}

fn inode_for(key: &VariableKey) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in key.name.as_bytes().iter().chain(key.guid.iter()) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash.max(2)
}

fn variable_is_removable(key: &VariableKey) -> bool {
    if key.guid() == LINUX_EFI_CRASH_GUID {
        return true;
    }
    key.guid() == EFI_GLOBAL_VARIABLE && matches_safe_global_name(&key.name)
}

fn matches_safe_global_name(name: &str) -> bool {
    matches!(
        name,
        "BootNext"
            | "BootOrder"
            | "DriverOrder"
            | "ConIn"
            | "ConInDev"
            | "ConOut"
            | "ConOutDev"
            | "ErrOut"
            | "ErrOutDev"
            | "Lang"
            | "OsIndications"
            | "PlatformLang"
            | "Timeout"
    ) || exact_hex_suffix(name, "Boot")
        || exact_hex_suffix(name, "Driver")
}

fn exact_hex_suffix(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == 4 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn validate_variable(key: &VariableKey, data: &[u8]) -> bool {
    if key.guid() != EFI_GLOBAL_VARIABLE {
        return true;
    }
    match key.name.as_str() {
        "BootNext" | "Timeout" => data.len() == 2,
        "BootOrder" | "DriverOrder" => data.len() % 2 == 0,
        "Lang" | "PlatformLang" => validate_ascii_string(data),
        "ConIn" | "ConInDev" | "ConOut" | "ConOutDev" | "ErrOut" | "ErrOutDev" => {
            validate_device_path(data)
        }
        name if exact_hex_suffix(name, "Boot") || exact_hex_suffix(name, "Driver") => {
            validate_load_option(data)
        }
        _ => true,
    }
}

fn validate_ascii_string(data: &[u8]) -> bool {
    for &byte in data {
        if !byte.is_ascii() {
            return false;
        }
        if byte == 0 {
            return true;
        }
    }
    false
}

fn validate_load_option(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    let path_len = usize::from(u16::from_le_bytes([data[4], data[5]]));
    let Some(description_units) = data[6..].chunks_exact(2).position(|unit| unit == [0, 0]) else {
        return false;
    };
    let description_bytes = (description_units + 1) * 2;
    let path_start = 6usize.saturating_add(description_bytes);
    path_start
        .checked_add(path_len)
        .filter(|end| *end <= data.len())
        .is_some_and(|end| validate_device_path(&data[path_start..end]))
}

fn validate_device_path(data: &[u8]) -> bool {
    let mut offset = 0usize;
    while offset.checked_add(4).is_some_and(|end| end <= data.len()) {
        let node = &data[offset..];
        let len = usize::from(u16::from_le_bytes([node[2], node[3]]));
        if len < 4 || offset.checked_add(len).is_none_or(|end| end > data.len()) {
            return false;
        }
        if matches!(node[0], 0x7f | 0xff) && node[1] == 0xff {
            return true;
        }
        offset += len;
    }
    false
}

fn status_to_fs_error(status: EfiStatus) -> FsError {
    match status {
        runtime::EFI_NOT_FOUND => FsError::NotFound,
        runtime::EFI_OUT_OF_RESOURCES | runtime::EFI_VOLUME_FULL => FsError::NoSpace,
        runtime::EFI_WRITE_PROTECTED => FsError::ReadOnly,
        runtime::EFI_ACCESS_DENIED | runtime::EFI_SECURITY_VIOLATION => FsError::PermissionDenied,
        runtime::EFI_DEVICE_ERROR => FsError::Io(BlockError::IOError),
        runtime::EFI_UNSUPPORTED => FsError::Unsupported,
        _ => FsError::InvalidData,
    }
}

mod tests {
    use alloc::collections::BTreeMap;
    use alloc::vec;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    use narf_kernel_test::{kernel_test_in, TestResult};

    use super::*;

    #[derive(Debug)]
    struct FakeBackend {
        values: BTreeMap<VariableKey, EfiVariableValue>,
    }

    impl VariableBackend for FakeBackend {
        fn list(&mut self) -> Result<Vec<EfiVariableId>, EfiStatus> {
            Ok(self
                .values
                .keys()
                .map(|key| EfiVariableId {
                    name: key.name.clone(),
                    vendor: key.guid(),
                })
                .collect())
        }

        fn get(&mut self, key: &VariableKey) -> Result<EfiVariableValue, EfiStatus> {
            self.values.get(key).cloned().ok_or(runtime::EFI_NOT_FOUND)
        }

        fn set(
            &mut self,
            key: &VariableKey,
            attributes: u32,
            data: &[u8],
        ) -> Result<(), EfiStatus> {
            if attributes == 0 && data.is_empty() {
                self.values.remove(key);
                return Ok(());
            }
            if attributes & attr::APPEND_WRITE != 0 {
                if let Some(value) = self.values.get_mut(key) {
                    value.attributes = attributes;
                    value.data.extend_from_slice(data);
                    return Ok(());
                }
            }
            self.values.insert(
                key.clone(),
                EfiVariableValue {
                    attributes,
                    data: data.to_vec(),
                },
            );
            Ok(())
        }

        fn query(&mut self, _attributes: u32) -> Result<EfiVariableInfo, EfiStatus> {
            Ok(EfiVariableInfo {
                storage_bytes: 65_536,
                remaining_bytes: 32_768,
                max_variable_bytes: 8_192,
            })
        }
    }

    fn fake_fs() -> EfivarFs {
        let boot_order = VariableKey::new("BootOrder".to_string(), EFI_GLOBAL_VARIABLE);
        let protected = VariableKey::new(
            "VendorSecret".to_string(),
            Guid::new(0x1234_5678, 0xabcd, 0xef01, [1, 2, 3, 4, 5, 6, 7, 8]),
        );
        let random_seed = VariableKey::new(
            "NARFRandomSeed".to_string(),
            LINUX_EFI_RANDOM_SEED_TABLE_GUID,
        );
        let slash_name = VariableKey::new("Slash/Name".to_string(), EFI_GLOBAL_VARIABLE);
        let mut values = BTreeMap::new();
        values.insert(
            boot_order,
            EfiVariableValue {
                attributes: QUERY_ATTRS,
                data: vec![1, 0, 2, 0],
            },
        );
        values.insert(
            protected,
            EfiVariableValue {
                attributes: QUERY_ATTRS,
                data: vec![0xaa],
            },
        );
        values.insert(
            random_seed,
            EfiVariableValue {
                attributes: QUERY_ATTRS,
                data: vec![0xbb],
            },
        );
        values.insert(
            slash_name,
            EfiVariableValue {
                attributes: QUERY_ATTRS,
                data: vec![0xcc],
            },
        );
        EfivarFs::with_backend(Box::new(FakeBackend { values }), 12, 34).unwrap()
    }

    fn poll_once<F: Future>(future: F) -> Option<F::Output> {
        fn clone(_: *const ()) -> RawWaker {
            raw_waker()
        }
        fn wake(_: *const ()) {}
        fn raw_waker() -> RawWaker {
            RawWaker::new(
                core::ptr::null(),
                &RawWakerVTable::new(clone, wake, wake, wake),
            )
        }
        // SAFETY: the no-op vtable never dereferences its null data pointer.
        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut context = Context::from_waker(&waker);
        let mut future = core::pin::pin!(future);
        match Pin::new(&mut future).poll(&mut context) {
            Poll::Ready(value) => Some(value),
            Poll::Pending => None,
        }
    }

    fn smoke_efivarfs_filename_and_file_abi() -> TestResult {
        let fs = fake_fs();
        let root = fs.root();
        let boot_name = format!("BootOrder-{}", format_guid(EFI_GLOBAL_VARIABLE));
        let entries = root.enumerate(0, 32);
        if entries.len() != 3 || !entries.iter().any(|(name, _)| name == &boot_name) {
            return TestResult::Fail("efivarfs enumeration or random-seed filtering mismatch");
        }
        let slash_name = format!("Slash!Name-{}", format_guid(EFI_GLOBAL_VARIABLE));
        let slash_file = match root.lookup(&slash_name) {
            Some(file) => file,
            None => return TestResult::Fail("slash-to-bang firmware name was not resolvable"),
        };
        let mut slash_value = [0u8; 5];
        if poll_once(slash_file.read(0, &mut slash_value)).and_then(Result::ok) != Some(5)
            || slash_value[4] != 0xcc
        {
            return TestResult::Fail("slash-to-bang lookup lost the firmware variable name");
        }
        if !matches!(
            poll_once(root.create(&slash_name)),
            Some(Err(FsError::Busy))
        ) {
            return TestResult::Fail("slash-to-bang dentry collision was not rejected");
        }
        let uppercase = format!(
            "BootOrder-{}",
            format_guid(EFI_GLOBAL_VARIABLE).to_ascii_uppercase()
        );
        let file = match root.lookup(&uppercase) {
            Some(file) => file,
            None => return TestResult::Fail("GUID lookup was not case insensitive"),
        };
        if file.stat().size != 8 || file.owners() != (12, 34) || file.ino() == 0 {
            return TestResult::Fail("efivarfs stat metadata mismatch");
        }
        let mut bytes = [0u8; 8];
        match poll_once(file.read(0, &mut bytes)) {
            Some(Ok(8))
                if bytes[..4] == QUERY_ATTRS.to_le_bytes() && bytes[4..] == [1, 0, 2, 0] => {}
            _ => return TestResult::Fail("efivarfs four-byte attribute prefix mismatch"),
        }
        let mut append = Vec::new();
        append.extend_from_slice(&(QUERY_ATTRS | attr::APPEND_WRITE).to_le_bytes());
        append.extend_from_slice(&[3, 0]);
        if poll_once(file.write(999, &append)).and_then(Result::ok) != Some(append.len()) {
            return TestResult::Fail("efivarfs append write failed");
        }
        let mut updated = [0u8; 10];
        if poll_once(file.read(0, &mut updated)).and_then(Result::ok) != Some(10)
            || updated[4..] != [1, 0, 2, 0, 3, 0]
        {
            return TestResult::Fail("efivarfs append did not report firmware result size");
        }
        TestResult::Pass
    }
    kernel_test_in!("filesystem/efivarfs", smoke_efivarfs_filename_and_file_abi);

    fn smoke_efivarfs_immutable_create_delete_and_statfs() -> TestResult {
        let fs = fake_fs();
        let root = fs.root();
        let protected = format!(
            "VendorSecret-{}",
            format_guid(Guid::new(
                0x1234_5678,
                0xabcd,
                0xef01,
                [1, 2, 3, 4, 5, 6, 7, 8]
            ))
        );
        let protected_file = root.lookup(&protected).unwrap();
        let write = [0u8; 4];
        if poll_once(protected_file.write(0, &write)) != Some(Err(FsError::PermissionDenied)) {
            return TestResult::Fail("unknown firmware variable was not immutable by default");
        }
        let flags = match poll_once(protected_file.ioctl_async(0x8008_6601, 0, &[], 8)) {
            Some(Ok(reply)) => reply.output,
            _ => return TestResult::Fail("FS_IOC_GETFLAGS failed"),
        };
        if u32::from_ne_bytes(flags[..4].try_into().unwrap()) != FS_IMMUTABLE_FL {
            return TestResult::Fail("FS_IMMUTABLE_FL missing");
        }
        if poll_once(protected_file.ioctl_async(0x4008_6602, 0, &0u64.to_ne_bytes(), 0))
            .and_then(Result::ok)
            .is_none()
        {
            return TestResult::Fail("FS_IOC_SETFLAGS could not clear immutable");
        }
        if poll_once(root.unlink(&protected)) != Some(Ok(())) || root.lookup(&protected).is_some() {
            return TestResult::Fail("cleared variable could not be deleted");
        }
        if !matches!(
            poll_once(protected_file.write(0, &write)),
            Some(Err(FsError::Io(BlockError::IOError)))
        ) {
            return TestResult::Fail("unlinked file handle could recreate a firmware variable");
        }

        let new_name = format!("Boot0001-{}", format_guid(EFI_GLOBAL_VARIABLE));
        let new_file = match poll_once(root.create(&new_name)) {
            Some(Ok(file)) => file,
            _ => return TestResult::Fail("valid efivarfs create failed"),
        };
        if new_file.stat().size != 0 {
            return TestResult::Fail("uncommitted variable was not zero length");
        }
        let mut load_option = Vec::new();
        load_option.extend_from_slice(&QUERY_ATTRS.to_le_bytes());
        load_option.extend_from_slice(&0u32.to_le_bytes());
        load_option.extend_from_slice(&4u16.to_le_bytes());
        load_option.extend_from_slice(&[b'x', 0, 0, 0]);
        load_option.extend_from_slice(&[0x7f, 0xff, 4, 0]);
        if poll_once(new_file.write(0, &load_option))
            .and_then(Result::ok)
            .is_none()
        {
            return TestResult::Fail("valid Boot#### load option rejected");
        }
        let statfs = match poll_once(fs.statfs()) {
            Some(Ok(statfs)) => statfs,
            _ => return TestResult::Fail("efivarfs statfs failed"),
        };
        if statfs.block_size != 1 || statfs.blocks != 65_536 || statfs.blocks_free != 32_768 {
            return TestResult::Fail("efivarfs QueryVariableInfo projection mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "filesystem/efivarfs",
        smoke_efivarfs_immutable_create_delete_and_statfs
    );
}

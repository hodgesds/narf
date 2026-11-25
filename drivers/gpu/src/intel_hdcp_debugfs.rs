//! The per-connector HDCP debugfs files of an Intel card, behind
//! `narf.intel.hdcp=1` (MIT Linux 7.4-rc4
//! `drivers/gpu/drm/i915/display/intel_hdcp.c`):
//!
//! - `intel_hdcp_connector_debugfs_add`: every DisplayPort, HDMI-A and
//!   HDMI-B connector gets `i915_hdcp_sink_capability` (0444) and
//!   `i915_force_hdcp14` (0644) in its `connector->debugfs_entry`, which
//!   DRM names `/sys/kernel/debug/dri/<minor>/<connector name>`
//!   (`drm_debugfs_connector_add`; the name is `drm_connector_init`'s
//!   "%s-%d" of the type and its 1-based index).
//! - `intel_hdcp_sink_capability_show`: "<name>:<id> HDCP version: "
//!   then `__intel_hdcp_info` ("HDCP1.4 ", "HDCP2.2 ", or "None", and a
//!   newline), -ENODEV without an encoder on a connected connector.
//! - `intel_hdcp_force_14_show` / `_write`: "yes" or "no"
//!   (`str_yes_no`), -ENODEV without an encoder on a connected connector
//!   with a CRTC; the write takes `kstrtobool_from_user` and sets
//!   `hdcp->force_hdcp14`.
//!
//! NARF has no DRM debugfs core, so this module owns `dri/` for the Intel
//! cards whose connectors HDCP attached (only with the option). The sink
//! is read on the GT runtime actor's HDCP pass, which owns the route's
//! AUX or DDC ([`crate::intel_hdcp_live::ask_capability`]); a read waits
//! for it, bounded. Nothing here logs; the files carry versions only,
//! never a KSV or key.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use narf_filesystem::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, Mode, Stat};
use narf_lib::sync::IrqSafeSpinLock;

use crate::drm::card::ConnectorType;
use crate::intel_hdcp::HdcpError;
use crate::intel_hdcp_live as live;

/// The file names `intel_hdcp_connector_debugfs_add` creates.
pub const SINK_CAPABILITY: &str = "i915_hdcp_sink_capability";
pub const FORCE_HDCP14: &str = "i915_force_hdcp14";

/// How long a read waits for the HDCP pass to read the sink.
const ANSWER_NS: u64 = 2_000_000_000;
const ANSWER_POLL_US: u64 = 5_000;

static REGISTERED: AtomicBool = AtomicBool::new(false);
/// The first of this tree's debugfs inode numbers.
static INO_BASE: AtomicU64 = AtomicU64::new(0);
/// The inode numbers this tree may use past [`INO_BASE`].
const INO_SPAN: u64 = 1 << 24;

/// Create `/sys/kernel/debug/dri` once, when HDCP first attaches to a card.
/// Another owner of `dri` leaves the files absent.
pub(crate) fn register() {
    if REGISTERED.swap(true, Ordering::AcqRel) {
        return;
    }
    INO_BASE.store(narf_filesystem::debugfs::alloc_ino_range(INO_SPAN), Ordering::Release);
    let _ = narf_filesystem::debugfs::register_dir("dri", Arc::new(DriDir));
}

fn ino(offset: u64) -> u64 {
    INO_BASE.load(Ordering::Acquire) + offset % INO_SPAN
}

/// `drm_connector_enum_list`'s names of the types that carry the files.
pub(crate) fn type_name(ty: ConnectorType) -> Option<&'static str> {
    match ty {
        ConnectorType::DisplayPort => Some("DP"),
        ConnectorType::HdmiA => Some("HDMI-A"),
        ConnectorType::HdmiB => Some("HDMI-B"),
        _ => None,
    }
}

/// The connector's DRM name: the type, then `connector_type_id` counted
/// from 1 (`drm_connector_init`'s `ida_alloc_min(.., 1, ..)`).
pub(crate) fn connector_name(ty: ConnectorType, type_index: u32) -> Option<String> {
    let mut name = String::from(type_name(ty)?);
    let _ = write!(name, "-{}", type_index + 1);
    Some(name)
}

/// `intel_hdcp_sink_capability_show`'s text for the (HDCP 1.4, HDCP 2.2)
/// answer of connector `name` with object id `id`.
pub(crate) fn sink_capability_text(name: &str, id: u32, hdcp1: bool, hdcp2: bool) -> String {
    let mut text = String::new();
    let _ = write!(text, "{name}:{id} HDCP version: ");
    if hdcp1 {
        text.push_str("HDCP1.4 ");
    }
    if hdcp2 {
        text.push_str("HDCP2.2 ");
    }
    if !hdcp1 && !hdcp2 {
        text.push_str("None");
    }
    text.push('\n');
    text
}

/// `kstrtobool`: y/Y/t/T/1 and "on" are true, n/N/f/F/0 and "off" false;
/// anything else is -EINVAL (`None`).
pub(crate) fn kstrtobool(buf: &[u8]) -> Option<bool> {
    match buf.first()? {
        b'y' | b'Y' | b't' | b'T' | b'1' => Some(true),
        b'n' | b'N' | b'f' | b'F' | b'0' => Some(false),
        b'o' | b'O' => match buf.get(1)? {
            b'n' | b'N' => Some(true),
            b'f' | b'F' => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// The errno a show or write returns for an HDCP refusal.
fn fs_error(error: HdcpError) -> FsError {
    match error {
        HdcpError::NoRoute => FsError::NoDevice,
        HdcpError::Timeout | HdcpError::MsgTimeout => FsError::TimedOut,
        HdcpError::Disabled | HdcpError::Unsupported => FsError::Unsupported,
        _ => crate::intel_gpu_user::io_error(),
    }
}

fn cards() -> Vec<u32> {
    (0..crate::drm_registry::count() as u32)
        .filter(|&card| !live::debugfs_connectors(card).is_empty())
        .collect()
}

/// `/sys/kernel/debug/dri`: one directory per card minor.
#[derive(Debug)]
struct DriDir;

impl DirOps for DriDir {
    fn ino(&self) -> u64 {
        ino(0)
    }
    fn dcache_identity(&self) -> (usize, u64, u64) {
        (narf_filesystem::debugfs::attrs().dev as usize, 0, self.ino())
    }
    fn inode_attrs(&self) -> narf_filesystem::InodeAttrs {
        narf_filesystem::debugfs::attrs()
    }
    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        None
    }
    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        let card: u32 = name.parse().ok()?;
        if alloc::format!("{card}") != name || live::debugfs_connectors(card).is_empty() {
            return None;
        }
        Some(Arc::new(MinorDir { card }))
    }
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        Box::new(cards().into_iter().map(|card| DirEntry {
            name: alloc::format!("{card}").into(),
            file_type: FileType::Dir,
        }))
    }
}

/// `dri/<minor>`: the card's DP and HDMI connectors.
#[derive(Debug)]
struct MinorDir {
    card: u32,
}

impl MinorDir {
    fn connectors(&self) -> Vec<(u32, String)> {
        live::debugfs_connectors(self.card)
            .into_iter()
            .filter_map(|(id, ty, index)| Some((id, connector_name(ty, index)?)))
            .collect()
    }
}

impl DirOps for MinorDir {
    fn ino(&self) -> u64 {
        ino(1 + u64::from(self.card))
    }
    fn dcache_identity(&self) -> (usize, u64, u64) {
        (narf_filesystem::debugfs::attrs().dev as usize, 0, self.ino())
    }
    fn inode_attrs(&self) -> narf_filesystem::InodeAttrs {
        narf_filesystem::debugfs::attrs()
    }
    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        None
    }
    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        let (connector, name) = self.connectors().into_iter().find(|(_, n)| n == name)?;
        Some(Arc::new(ConnectorDir {
            card: self.card,
            connector,
            name,
        }))
    }
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        Box::new(self.connectors().into_iter().map(|(_, name)| DirEntry {
            name: name.into(),
            file_type: FileType::Dir,
        }))
    }
}

/// `dri/<minor>/<connector>`: the two HDCP files.
#[derive(Debug)]
struct ConnectorDir {
    card: u32,
    connector: u32,
    name: String,
}

fn entry_ino(card: u32, connector: u32, k: u64) -> u64 {
    ino(0x1_0000 + ((u64::from(card) << 12 | u64::from(connector & 0xfff)) << 2 | k))
}

impl DirOps for ConnectorDir {
    fn ino(&self) -> u64 {
        entry_ino(self.card, self.connector, 0)
    }
    fn dcache_identity(&self) -> (usize, u64, u64) {
        (narf_filesystem::debugfs::attrs().dev as usize, 0, self.ino())
    }
    fn inode_attrs(&self) -> narf_filesystem::InodeAttrs {
        narf_filesystem::debugfs::attrs()
    }
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        let (card, connector) = (self.card, self.connector);
        match name {
            SINK_CAPABILITY => Some(Arc::new(SinkCapabilityFile {
                card,
                connector,
                name: self.name.clone(),
                text: IrqSafeSpinLock::new(None),
            })),
            FORCE_HDCP14 => Some(Arc::new(ForceHdcp14File { card, connector })),
            _ => None,
        }
    }
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        Box::new([SINK_CAPABILITY, FORCE_HDCP14].into_iter().map(|name| DirEntry {
            name: name.into(),
            file_type: FileType::File,
        }))
    }
}

/// Copy `text` from `offset` into `buf`.
fn copy_at(text: &[u8], offset: u64, buf: &mut [u8]) -> usize {
    let start = usize::try_from(offset).unwrap_or(usize::MAX).min(text.len());
    let n = buf.len().min(text.len() - start);
    buf[..n].copy_from_slice(&text[start..start + n]);
    n
}

/// `i915_hdcp_sink_capability`. A read at offset 0 asks the sink again
/// (`single_open` shows afresh); later offsets continue that text.
#[derive(Debug)]
struct SinkCapabilityFile {
    card: u32,
    connector: u32,
    name: String,
    text: IrqSafeSpinLock<Option<String>>,
}

impl SinkCapabilityFile {
    async fn show(&self) -> Result<String, FsError> {
        let ticket = live::ask_capability(self.card, self.connector).map_err(fs_error)?;
        let deadline = narf_time::monotonic_ns().saturating_add(ANSWER_NS);
        loop {
            if let Some(answer) = live::capability_answer(self.card, self.connector, ticket) {
                let (hdcp1, hdcp2) = answer.map_err(fs_error)?;
                return Ok(sink_capability_text(
                    &self.name,
                    self.connector,
                    hdcp1,
                    hdcp2,
                ));
            }
            if narf_time::monotonic_ns() >= deadline {
                return Err(FsError::TimedOut);
            }
            narf_time::SleepUntil::new(
                narf_time::Deadline::after_us(ANSWER_POLL_US).as_instant(),
            )
            .await;
        }
    }
}

impl FileOps for SinkCapabilityFile {
    fn ino(&self) -> u64 {
        entry_ino(self.card, self.connector, 1)
    }
    fn inode_attrs(&self) -> narf_filesystem::InodeAttrs {
        narf_filesystem::debugfs::attrs()
    }
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let cached = if offset == 0 {
                None
            } else {
                self.text.lock().clone()
            };
            let text = match cached {
                Some(text) => text,
                None => {
                    let text = self.show().await?;
                    *self.text.lock() = Some(text.clone());
                    text
                }
            };
            Ok(copy_at(text.as_bytes(), offset, buf))
        })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::PermissionDenied) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::File,
                perms: 0o444,
            },
            mtime_cycles: 0,
        }
    }
}

/// `i915_force_hdcp14`.
#[derive(Debug)]
struct ForceHdcp14File {
    card: u32,
    connector: u32,
}

impl FileOps for ForceHdcp14File {
    fn ino(&self) -> u64 {
        entry_ino(self.card, self.connector, 2)
    }
    fn inode_attrs(&self) -> narf_filesystem::InodeAttrs {
        narf_filesystem::debugfs::attrs()
    }
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let shown = live::force_hdcp14(self.card, self.connector);
        Box::pin(async move {
            let force = shown.map_err(fs_error)?;
            let text: &[u8] = if force { b"yes\n" } else { b"no\n" };
            Ok(copy_at(text, offset, buf))
        })
    }
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let result = if buf.is_empty() {
            Ok(0)
        } else {
            match kstrtobool(buf) {
                Some(force) => live::set_force_hdcp14(self.card, self.connector, force)
                    .map(|()| buf.len())
                    .map_err(fs_error),
                None => Err(FsError::InvalidData),
            }
        };
        Box::pin(async move { result })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::File,
                perms: 0o644,
            },
            mtime_cycles: 0,
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_hdcp_debugfs_tests.rs"]
mod tests;

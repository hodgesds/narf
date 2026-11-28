//! `/proc/kallsyms` — the kernel symbol table, as `perf`, `bpftrace` and
//! `crash` read it.
//!
//! Linux refs: `kernel/kallsyms.c` (`kallsyms_open`, `s_show`, the seq_file
//! iterator) and `kernel/ksyms_common.c` (`kallsyms_show_value`).
//!
//! Format, one symbol per line in address order: `%px %c %s\n` — a 16-digit
//! zero-padded hex address, the `nm(1)` type letter, the name. The table
//! itself comes from the image (`narf_observability::kallsyms`); this file
//! only decides whether its reader may see the addresses.
//!
//! ## Who sees addresses
//!
//! Every reader sees every name and type. The ADDRESSES defeat KASLR, so
//! they are printed only when [`kallsyms_show_value`] allows it, and
//! otherwise every one of them reads as zero — never a mix, which would let a
//! reader recover the slide from the one value that slipped through.
//!
//! The decision is made ONCE, at `open(2)`, against the opener's
//! credentials, exactly as `kallsyms_open` caches
//! `kallsyms_show_value(file->f_cred)` in the iterator: a descriptor opened
//! by a privileged process keeps showing addresses after the process drops
//! its capabilities (it chose to hold the descriptor), and a descriptor
//! opened unprivileged stays zeroed even if its holder later gains
//! `CAP_SYSLOG` — so a privileged reader cannot be tricked into reading
//! through a descriptor an unprivileged process prepared and passed it, and
//! a setuid binary cannot be used to read one its unprivileged caller
//! opened. Checking at `read(2)` instead would allow both.
//!
//! ## Reading
//!
//! The rendered file is ~20 MB for a release image and ~40 MB for the test
//! image (every kernel test linked in), so it is streamed rather
//! than built per `read(2)`: each open file carries a cursor (seq_file's
//! `m->index` plus its partly-copied line), and a read continuing where the
//! last one stopped resumes from it. Any other offset re-renders from the
//! start up to that offset, which is seq_file's `traverse` behaviour.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;
use narf_observability::kallsyms::{self, NameBuf, Table, MAX_NAME};

use super::sys_kernel::{kptr_restrict, perf_event_paranoid};
use super::{proc_attrs, register_proc, ProcFile};
use crate::{FileOps, FileType, FsError, FsFuture, Mode, Stat};

/// `CAP_SYSLOG` (`include/uapi/linux/capability.h`).
pub const CAP_SYSLOG: u32 = 34;

/// `kernel/ksyms_common.c::kallsyms_show_value`.
///
/// ```text
/// switch (kptr_restrict) {
/// case 0:  if (kallsyms_for_perf()) return true;   // paranoid <= 1
///          fallthrough;
/// case 1:  if (security_capable(cred, &init_user_ns, CAP_SYSLOG, ...) == 0)
///                  return true;
///          fallthrough;
/// default: return false;
/// }
/// ```
///
/// `cap_syslog` answers the credential question for whoever the caller is
/// deciding for — at `/proc/kallsyms` open, the opener. It is asked only
/// when the policy depends on it, as Linux asks `security_capable` only on
/// the fallthrough.
pub fn kallsyms_show_value(cap_syslog: impl FnOnce() -> bool) -> bool {
    match kptr_restrict() {
        0 if perf_event_paranoid() <= 1 => true,
        0 | 1 => cap_syslog(),
        _ => false,
    }
}

/// Register `/proc/kallsyms`.
pub fn register_all() {
    register_proc("kallsyms", Arc::new(KallsymsNode));
}

/// The registry entry. Every open mints a [`KallsymsFile`] bound to the
/// opener's answer; the shared adapter's `read` is never the reader's path.
#[derive(Debug)]
struct KallsymsNode;

impl ProcFile for KallsymsNode {
    fn read(&self) -> Vec<u8> {
        // Only reachable by an in-kernel caller reading the registry entry
        // without opening it; open(2) always goes through `open` below.
        // Such a caller has no opener whose credentials could be asked, and
        // the whole body (~40 MB for a test image) is more than it should
        // ever materialise in one allocation, so it reads an empty file.
        Vec::new()
    }

    fn perms(&self) -> u16 {
        // `proc_create("kallsyms", 0444, NULL, &kallsyms_proc_ops)`.
        0o444
    }

    fn open(&self, ino: u64, _write: bool) -> Result<Option<Arc<dyn FileOps>>, FsError> {
        // `kallsyms_open`: `iter->show_value = kallsyms_show_value(file->f_cred)`.
        // This runs in the opener's context, so `caller_capable` is the
        // opener's credential.
        let show_value = kallsyms_show_value(|| crate::caller_capable(CAP_SYSLOG));
        Ok(Some(Arc::new(KallsymsFile {
            ino,
            show_value,
            cursor: IrqSafeSpinLock::new(Some(Cursor::default())),
        })))
    }
}

/// Longest rendered line: 16 hex digits, space, type, space, name, newline.
const LINE_MAX: usize = 16 + 1 + 1 + 1 + MAX_NAME + 1;

/// Where a sequential reader is: seq_file's index plus the unread tail of
/// the line that did not fit the previous buffer.
#[derive(Clone, Default)]
struct Cursor {
    /// File offset of the next byte this cursor produces.
    pos: u64,
    /// Next symbol to render.
    index: usize,
    /// Rendered bytes not yet handed out.
    pending: Vec<u8>,
}

fn hex16(v: u64, out: &mut [u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for (i, slot) in out[..16].iter_mut().enumerate() {
        *slot = DIGITS[((v >> ((15 - i) * 4)) & 0xF) as usize];
    }
}

/// `s_show`: render symbol `index` into `line`, returning its length, or
/// `None` past the end (or on a table that cannot be decoded, which ends
/// the file rather than printing garbage).
fn render(
    table: &Table<'_>,
    index: usize,
    show_value: bool,
    name: &mut NameBuf,
    line: &mut [u8; LINE_MAX],
) -> Option<usize> {
    let e = table.entry(index)?;
    table.name(e.name_index, name).ok()?;
    let value = if show_value { kallsyms::address(&e) } else { 0 };
    hex16(value, &mut line[..16]);
    line[16] = b' ';
    line[17] = e.kind;
    line[18] = b' ';
    let n = name.as_bytes();
    line[19..19 + n.len()].copy_from_slice(n);
    line[19 + n.len()] = b'\n';
    Some(20 + n.len())
}

impl Cursor {
    /// Produce the next bytes of the file into `buf`.
    fn fill(&mut self, show_value: bool, buf: &mut [u8]) -> usize {
        let mut n = 0;
        // Drain the tail of a line a previous read split.
        if !self.pending.is_empty() {
            let take = self.pending.len().min(buf.len());
            buf[..take].copy_from_slice(&self.pending[..take]);
            self.pending.drain(..take);
            n = take;
        }
        let Ok(table) = kallsyms::table() else {
            // No table in this image (linked without `cargo narf`'s patch step):
            // the file exists and is empty.
            self.pos += n as u64;
            return n;
        };
        let mut name = NameBuf::new();
        let mut line = [0u8; LINE_MAX];
        while n < buf.len() {
            let Some(len) = render(&table, self.index, show_value, &mut name, &mut line) else {
                break;
            };
            self.index += 1;
            let room = buf.len() - n;
            if len <= room {
                buf[n..n + len].copy_from_slice(&line[..len]);
                n += len;
            } else {
                buf[n..].copy_from_slice(&line[..room]);
                self.pending.extend_from_slice(&line[room..len]);
                n = buf.len();
            }
        }
        self.pos += n as u64;
        n
    }

    /// Advance to file offset `to` (>= `pos`) without handing bytes out.
    fn skip_to(&mut self, show_value: bool, to: u64) {
        let mut scratch = [0u8; 4096];
        while self.pos < to {
            let want = ((to - self.pos) as usize).min(scratch.len());
            if self.fill(show_value, &mut scratch[..want]) == 0 {
                return;
            }
        }
    }
}

/// One open `/proc/kallsyms`: the opener's answer and the read cursor.
struct KallsymsFile {
    ino: u64,
    /// `kallsyms_show_value(file->f_cred)`, fixed at open.
    show_value: bool,
    /// `None` while a read has it checked out (see `read`).
    cursor: IrqSafeSpinLock<Option<Cursor>>,
}

impl core::fmt::Debug for KallsymsFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KallsymsFile")
            .field("show_value", &self.show_value)
            .finish_non_exhaustive()
    }
}

impl FileOps for KallsymsFile {
    fn ino(&self) -> u64 {
        self.ino
    }
    fn inode_attrs(&self) -> crate::InodeAttrs {
        proc_attrs()
    }
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            if buf.is_empty() {
                return Ok(0);
            }
            // Check the cursor out rather than render under the lock: the
            // lock masks IRQs, and decoding a large read takes a while. A
            // second reader of the same description racing this one finds
            // it checked out and renders from a fresh cursor instead — the
            // same bytes, just without the shortcut.
            let saved = self.cursor.lock().take();
            let mut cursor = match saved {
                Some(c) if c.pos <= offset => c,
                _ => Cursor::default(),
            };
            cursor.skip_to(self.show_value, offset);
            let n = if cursor.pos == offset {
                cursor.fill(self.show_value, buf)
            } else {
                // Past the end of the file.
                0
            };
            *self.cursor.lock() = Some(cursor);
            Ok(n)
        })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::ReadOnly) })
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

#[path = "kallsyms_tests.rs"]
mod tests;

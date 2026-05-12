//! `DevFs` — minimal `/dev/null` + `/dev/zero` virtual filesystem.
//!
//! Real C programs reach for these almost universally — discarding
//! debug output via `> /dev/null`, zero-filling buffers via `dd
//! if=/dev/zero`, etc. Without them user programs that mention the
//! paths in a never-taken branch still need them to *exist* (or
//! the open call surfaces a NotFound that the caller doesn't
//! distinguish from a real failure).
//!
//! Layout: a single `DevFs::new()` returns an `FsInstance` whose
//! root holds two read-only special files.
//!
//! Semantics:
//!   - `/dev/null`: read returns 0 (immediate EOF); write returns
//!     the requested length (bytes silently discarded).
//!   - `/dev/zero`: read fills the user buffer with zeros and
//!     returns the requested length; write discards.
//!
//! Stat reports `FileType::Special` so `S_ISCHR(...)` consumers see
//! the right shape.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, FsInstance, Mode, Stat};

/// `/dev/null` — read = EOF, write = discard.
struct DevNull;

impl FileOps for DevNull {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Ok(0) })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let len = buf.len();
        Box::pin(async move { Ok(len) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o666,
            },
            mtime_cycles: 0,
        }
    }
}

/// `/dev/random` and `/dev/urandom` — read = fill with PRNG bytes,
/// write = discard. NARF doesn't distinguish blocking-vs-non-
/// blocking RNG today (no entropy pool), so both entries map to
/// the same backing.
///
/// Backing: a Park-Miller minimal-standard LCG seeded lazily on
/// first read from `narf_time::now_cycles()`. Matches the same
/// non-cryptographic guarantee `crypto::per_task_rng()` documents.
struct DevRandom;

use core::sync::atomic::{AtomicU64, Ordering};
static RANDOM_STATE: AtomicU64 = AtomicU64::new(0);

fn next_random_u32() -> u32 {
    let mut s = RANDOM_STATE.load(Ordering::Relaxed);
    if s == 0 {
        let cy = narf_time::now_cycles();
        s = (cy ^ 0x9E37_79B9_7F4A_7C15).wrapping_mul(0xC2B2_AE3D_27D4_EB4F) & 0x7FFF_FFFF;
        if s == 0 {
            s = 1;
        }
    }
    s = (s.wrapping_mul(48271)) % 0x7FFF_FFFF;
    RANDOM_STATE.store(s, Ordering::Relaxed);
    s as u32
}

impl FileOps for DevRandom {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let len = buf.len();
        // Fill the user buffer in 4-byte chunks, plus tail bytes.
        let mut i = 0usize;
        while i + 4 <= len {
            let v = next_random_u32();
            buf[i] = (v & 0xFF) as u8;
            buf[i + 1] = ((v >> 8) & 0xFF) as u8;
            buf[i + 2] = ((v >> 16) & 0xFF) as u8;
            buf[i + 3] = ((v >> 24) & 0xFF) as u8;
            i += 4;
        }
        if i < len {
            let v = next_random_u32();
            let mut shift = 0u32;
            while i < len {
                buf[i] = ((v >> shift) & 0xFF) as u8;
                i += 1;
                shift += 8;
            }
        }
        Box::pin(async move { Ok(len) })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let len = buf.len();
        Box::pin(async move { Ok(len) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o666,
            },
            mtime_cycles: 0,
        }
    }
}

/// `/dev/zero` — read = zero-fill the buffer, write = discard.
struct DevZero;

impl FileOps for DevZero {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let len = buf.len();
        // Zero-fill happens here so the future body owns the slice
        // mutation; the async-block move keeps `buf` borrowed for
        // the future's lifetime.
        for slot in buf.iter_mut() {
            *slot = 0;
        }
        Box::pin(async move { Ok(len) })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let len = buf.len();
        Box::pin(async move { Ok(len) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o666,
            },
            mtime_cycles: 0,
        }
    }
}

/// `/dev/console` — typed-byte stream backed by `narf_input`.
///
/// Reads pull pending key-press events off `narf_input`'s global
/// ring, translate them into ASCII bytes (printable keys, Enter
/// → `\n`, Backspace → `0x7F`), and copy into the user buffer.
/// Releases / modifier keys / non-translatable codes are
/// dropped silently. Returns 0 immediately when nothing is queued
/// (non-blocking semantics — callers that want blocking reads
/// poll-and-yield in user space until the next key arrives).
///
/// Writes go to the kernel console (UART + framebuffer if
/// installed) so user code can `write(open("/dev/console"))` for
/// stdout-equivalent output without an explicit fd-table lookup
/// against fd 1/2.
struct DevConsole;

/// Translate one `KeyCode` (with live modifier state) into one
/// printable ASCII byte. Returns `None` for non-translatable keys
/// (modifiers, function keys, navigation cluster). The shift map
/// matches a US-QWERTY layout — internationalisation is a follow-up
/// (real systems consult `/etc/keymaps`).
fn key_to_ascii(code: narf_input::KeyCode, mods: narf_input::Modifiers) -> Option<u8> {
    use narf_input::{KeyCode as K, Modifiers as M};
    let shift = mods.contains(M::SHIFT) ^ mods.contains(M::CAPS_LOCK);
    let base = match code {
        K::A => b'a', K::B => b'b', K::C => b'c', K::D => b'd', K::E => b'e',
        K::F => b'f', K::G => b'g', K::H => b'h', K::I => b'i', K::J => b'j',
        K::K => b'k', K::L => b'l', K::M => b'm', K::N => b'n', K::O => b'o',
        K::P => b'p', K::Q => b'q', K::R => b'r', K::S => b's', K::T => b't',
        K::U => b'u', K::V => b'v', K::W => b'w', K::X => b'x', K::Y => b'y',
        K::Z => b'z',
        K::Key0 => return Some(if shift { b')' } else { b'0' }),
        K::Key1 => return Some(if shift { b'!' } else { b'1' }),
        K::Key2 => return Some(if shift { b'@' } else { b'2' }),
        K::Key3 => return Some(if shift { b'#' } else { b'3' }),
        K::Key4 => return Some(if shift { b'$' } else { b'4' }),
        K::Key5 => return Some(if shift { b'%' } else { b'5' }),
        K::Key6 => return Some(if shift { b'^' } else { b'6' }),
        K::Key7 => return Some(if shift { b'&' } else { b'7' }),
        K::Key8 => return Some(if shift { b'*' } else { b'8' }),
        K::Key9 => return Some(if shift { b'(' } else { b'9' }),
        K::Space => return Some(b' '),
        K::Enter | K::KpEnter => return Some(b'\n'),
        K::Tab => return Some(b'\t'),
        K::Backspace => return Some(0x7F),
        K::Escape => return Some(0x1B),
        K::Minus => return Some(if shift { b'_' } else { b'-' }),
        K::Equal => return Some(if shift { b'+' } else { b'=' }),
        K::LeftBrace => return Some(if shift { b'{' } else { b'[' }),
        K::RightBrace => return Some(if shift { b'}' } else { b']' }),
        K::Backslash => return Some(if shift { b'|' } else { b'\\' }),
        K::Semicolon => return Some(if shift { b':' } else { b';' }),
        K::Apostrophe => return Some(if shift { b'"' } else { b'\'' }),
        K::Grave => return Some(if shift { b'~' } else { b'`' }),
        K::Comma => return Some(if shift { b'<' } else { b',' }),
        K::Dot => return Some(if shift { b'>' } else { b'.' }),
        K::Slash => return Some(if shift { b'?' } else { b'/' }),
        _ => return None,
    };
    Some(if shift { base.to_ascii_uppercase() } else { base })
}

impl FileOps for DevConsole {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        // Pull events off the global input ring, translating each
        // key-press to a byte. Stop when the user buffer is full
        // or the ring runs dry. Non-blocking — callers wanting
        // blocking behaviour loop in user space until n>0.
        //
        // Bounded by ring capacity (256) so a ring full of
        // re-pushed Pointer events (consumed by the cursor pump,
        // not by us) can't loop forever inside one call.
        let mut written = 0usize;
        let mut iters = 0usize;
        while written < buf.len() && iters < 256 {
            iters += 1;
            let ev = match narf_input::pop_global() {
                Some(e) => e,
                None => break,
            };
            match ev {
                narf_input::InputEvent::Key(k) => {
                    if !k.pressed {
                        continue;
                    }
                    if let Some(b) = key_to_ascii(k.code, k.modifiers) {
                        buf[written] = b;
                        written += 1;
                    }
                }
                narf_input::InputEvent::AsciiByte(b) => {
                    buf[written] = b;
                    written += 1;
                }
                // Pointer/Scroll events aren't readable through
                // /dev/console, but they ARE consumed by another
                // subscriber (the cursor pump). Re-push so we
                // don't silently steal them — without this, a
                // shell looping on read() drains every Pointer
                // event before the cursor pump can render it.
                other => {
                    let _ = narf_input::push_global(other);
                }
            }
        }
        Box::pin(async move { Ok(written) })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        // Same path as `sys_write` to fd 1/2: forward to the kernel
        // console (UART + framebuffer hook if installed). Treat
        // non-UTF-8 input as best-effort lossy by way of
        // `from_utf8_lossy` — `write_str` is the only public sink.
        let n = buf.len();
        if let Ok(s) = core::str::from_utf8(buf) {
            narf_console::write_str(s);
        } else {
            // Slow path: emit bytes one-by-one as `?` substitutes
            // for invalid UTF-8 — matches the standard library's
            // handling and keeps the byte count truthful.
            for &b in buf {
                if b.is_ascii() {
                    narf_console::write_str(unsafe {
                        core::str::from_utf8_unchecked(core::slice::from_ref(&b))
                    });
                } else {
                    narf_console::write_str("?");
                }
            }
        }
        Box::pin(async move { Ok(n) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o666,
            },
            mtime_cycles: 0,
        }
    }
}

/// `DevFs` root directory — exposes `null` and `zero` as fixed
/// children. No mutation surface (the trait defaults return
/// `Unsupported` on every override-able method).
struct DevDir;

impl DirOps for DevDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        match name {
            "null" => Some(Arc::new(DevNull) as Arc<dyn FileOps>),
            "zero" => Some(Arc::new(DevZero) as Arc<dyn FileOps>),
            "random" => Some(Arc::new(DevRandom) as Arc<dyn FileOps>),
            "urandom" => Some(Arc::new(DevRandom) as Arc<dyn FileOps>),
            "console" | "tty" | "tty0" => {
                Some(Arc::new(DevConsole) as Arc<dyn FileOps>)
            }
            _ => None,
        }
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            self.lookup(name).ok_or(FsError::NotFound)
        })
    }

    fn lookup_dir_async<'a>(&'a self, _name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            // DevFs root has no subdirectories.
            Err(FsError::NotFound)
        })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // Names are `&'static str` literals — fine for DirEntry.
        const ENTRIES: &[DirEntry] = &[
            DirEntry { name: "null", file_type: FileType::Special },
            DirEntry { name: "zero", file_type: FileType::Special },
            DirEntry { name: "random", file_type: FileType::Special },
            DirEntry { name: "urandom", file_type: FileType::Special },
            DirEntry { name: "console", file_type: FileType::Special },
            DirEntry { name: "tty", file_type: FileType::Special },
            DirEntry { name: "tty0", file_type: FileType::Special },
        ];
        Box::new(ENTRIES.iter().copied())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        let entries = [
            ("null", FileType::Special),
            ("zero", FileType::Special),
            ("random", FileType::Special),
            ("urandom", FileType::Special),
            ("console", FileType::Special),
            ("tty", FileType::Special),
            ("tty0", FileType::Special),
        ];
        entries
            .iter()
            .skip(cursor)
            .take(max)
            .map(|(n, t)| ((*n).into(), *t))
            .collect()
    }

    fn enumerate_async<'a>(&'a self, cursor: usize, max: usize) -> FsFuture<'a, Vec<(String, FileType)>> {
        Box::pin(async move {
            Ok(self.enumerate(cursor, max))
        })
    }
}

/// Mountable handle. `DevFs::new()` returns one suitable for
/// `registry().mount("/dev", DevFs::new())`.
#[derive(Debug)]
pub struct DevFs {
    name: String,
}

impl DevFs {
    pub fn new() -> Self {
        Self {
            name: "devfs".into(),
        }
    }
}

impl Default for DevFs {
    fn default() -> Self {
        Self::new()
    }
}

impl FsInstance for DevFs {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::new(DevDir)
    }
    fn name(&self) -> &str {
        &self.name
    }
}

/// Boot helper: mount DevFs at `/dev` if no FS is already mounted
/// there. Idempotent — re-running silently no-ops on `Busy`.
/// Use during kernel init to give every user task /dev/null,
/// /dev/zero, /dev/random, /dev/urandom out of the box.
pub fn mount_default() {
    let auth = crate::bootstrap_mount_authority();
    let _ = crate::registry().mount(&auth, "/dev", DevFs::new());
}

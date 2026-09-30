//! Virtual-console keyboard/font ioctls and the `/dev/vcs*` nodes.
//!
//! `systemd-vconsole-setup` (and `loadkeys`, `setfont`, `kbd_mode`) walk a
//! VT like this on Linux (`src/vconsole/vconsole-setup.c`):
//!
//! 1. `access("/dev/vcsN")` — is VT N allocated? NARF had no `/dev/vcs*`
//!    at all, so every VT looked unallocated and vconsole-setup exited 1
//!    with "No virtual console that can be configured found: No such file
//!    or directory".
//! 2. `KDGKBMODE` must be `K_XLATE` or `K_UNICODE` (else the VT belongs to
//!    an X server). NARF answered 0 (`K_RAW`).
//! 3. `KDSKBMODE`, then `loadkeys -C /dev/ttyN`: `KDGKBTYPE` (`KB_101`,
//!    else "Couldn't get a file descriptor referring to the console"),
//!    `KDSKBENT` for every key, `KDSKBSENT`, `KDSKBDIACRUC`.
//! 4. `KDFONTOP(KD_FONT_OP_GET)` decides whether the console driver has a
//!    font at all; `ENOSYS` (a console driver without `con_font_get`, e.g.
//!    dummycon) makes vconsole-setup skip the font instead of failing.
//!
//! References: `drivers/tty/vt/vt_ioctl.c::vt_k_ioctl`,
//! `drivers/tty/vt/keyboard.c` (`vt_do_*`), `drivers/tty/vt/vt.c::
//! con_font_op`, `drivers/tty/vt/vc_screen.c`.
//!
//! LINUX-GAP: `perm` in `vt_k_ioctl` is "this tty is the caller's
//! controlling terminal, or CAP_SYS_TTY_CONFIG"; NARF has no per-caller
//! ctty test at this layer, so only the capability grants it (the
//! restrictive direction). NARF's console driver has no loadable font, so
//! every font operation ends where dummycon's does (-ENOSYS); `/dev/vcs*`
//! exist for allocated VTs but NARF keeps no VT screen buffer, so they
//! read as empty.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::{FileOps, FileType, FsError, FsFuture, Mode, Stat};

pub(crate) const KDGKBTYPE: u32 = 0x4B33;
pub(crate) const KDGKBENT: u32 = 0x4B46;
pub(crate) const KDSKBENT: u32 = 0x4B47;
pub(crate) const KDGKBSENT: u32 = 0x4B48;
pub(crate) const KDSKBSENT: u32 = 0x4B49;
pub(crate) const KDGKBDIACR: u32 = 0x4B4A;
pub(crate) const KDSKBDIACR: u32 = 0x4B4B;
pub(crate) const KDGKBMETA: u32 = 0x4B62;
pub(crate) const KDSKBMETA: u32 = 0x4B63;
pub(crate) const KDFONTOP: u32 = 0x4B72;
pub(crate) const KDGKBDIACRUC: u32 = 0x4BFA;
pub(crate) const KDSKBDIACRUC: u32 = 0x4BFB;

/// `KB_101`.
const KB_101: u8 = 0x02;
/// `CAP_SYS_TTY_CONFIG`, `CAP_SYS_ADMIN`.
const CAP_SYS_TTY_CONFIG: u32 = 26;
const CAP_SYS_ADMIN: u32 = 21;
/// `KD_FONT_OP_*`.
const KD_FONT_OP_SET: u32 = 0;
const KD_FONT_OP_GET: u32 = 1;
const KD_FONT_OP_SET_DEFAULT: u32 = 2;
const KD_FONT_OP_COPY: u32 = 3;
const KD_FONT_OP_SET_TALL: u32 = 4;
const KD_FONT_OP_GET_TALL: u32 = 5;
/// `vt.c`: `max_font_width` / `_height` / `_glyphs`.
const MAX_FONT_WIDTH: u32 = 64;
const MAX_FONT_HEIGHT: u32 = 128;
const MAX_FONT_GLYPHS: u32 = 512;

/// `vt_k_ioctl`'s `perm` — see the module LINUX-GAP.
pub(crate) fn vt_perm() -> bool {
    crate::caller_capable(CAP_SYS_TTY_CONFIG)
}

unsafe fn copy_in(uptr: usize, out: &mut [u8]) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::BadAddress);
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: the ioctl syscall path validated `uptr` as a user address; the
    // SMAP window makes the CPL=0 load legal and the copy is bounded by
    // `out.len()`.
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::copy_nonoverlapping(uptr as *const u8, out.as_mut_ptr(), out.len());
        });
    }
    #[cfg(not(target_arch = "x86_64"))]
    // SAFETY: as above, without SMAP.
    unsafe {
        core::ptr::copy_nonoverlapping(uptr as *const u8, out.as_mut_ptr(), out.len());
    }
    Ok(())
}

unsafe fn copy_out(uptr: usize, src: &[u8]) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::BadAddress);
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: see `copy_in`.
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::copy_nonoverlapping(src.as_ptr(), uptr as *mut u8, src.len());
        });
    }
    #[cfg(not(target_arch = "x86_64"))]
    // SAFETY: see `copy_in`.
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), uptr as *mut u8, src.len());
    }
    Ok(())
}

/// `conv_8bit_to_uni` / `conv_uni_to_8bit` over the default (identity)
/// user map. LINUX-GAP: `PIO_UNISCRNMAP` is not modelled, so the user map
/// never changes.
fn conv_uni_to_8bit(uni: u32) -> u8 {
    if uni < 0x100 {
        uni as u8
    } else {
        0xFF // (unsigned char)-1
    }
}

/// The KD* ioctls `vt_k_ioctl` routes to `keyboard.c` and `con_font_op`.
pub(crate) fn vt_keyboard_ioctl(vt: u32, cmd: u32, arg: usize) -> Result<u64, FsError> {
    match cmd {
        // "this is naïve." — `put_user(KB_101, (char __user *)arg)`.
        KDGKBTYPE => {
            // SAFETY: `arg` is the caller's `char *`.
            unsafe { copy_out(arg, &[KB_101])? };
            Ok(0)
        }
        KDGKBMETA => {
            let v = (crate::vt::kbd_meta(vt) as i32).to_ne_bytes();
            // SAFETY: `arg` is the caller's `int *`.
            unsafe { copy_out(arg, &v)? };
            Ok(0)
        }
        // `vt_do_kdskbmeta` — no `perm` check in Linux either.
        KDSKBMETA => crate::vt::set_kbd_meta(vt, arg as u32)
            .map(|()| 0)
            .map_err(|()| FsError::InvalidData),
        // `vt_do_kdsk_ioctl`: `struct kbentry { u8 kb_table, kb_index; u16
        // kb_value; }`.
        KDGKBENT | KDSKBENT => {
            let mut kbe = [0u8; 4];
            // SAFETY: `arg` is the caller's `struct kbentry *` (4 bytes).
            unsafe { copy_in(arg, &mut kbe)? };
            let (table, index) = (kbe[0], kbe[1]);
            if cmd == KDGKBENT {
                let v = crate::vt::get_kbent(vt, index, table).to_ne_bytes();
                // SAFETY: `kb_value` is the u16 at offset 2.
                unsafe { copy_out(arg + 2, &v)? };
                return Ok(0);
            }
            // `if (!perm || !capable(CAP_SYS_TTY_CONFIG)) return -EPERM;`
            if !vt_perm() {
                return Err(FsError::OperationNotPermitted);
            }
            let value = u16::from_ne_bytes([kbe[2], kbe[3]]);
            match crate::vt::set_kbent(
                vt,
                index,
                table,
                value,
                crate::caller_capable(CAP_SYS_ADMIN),
            ) {
                Ok(()) => Ok(0),
                Err(crate::vt::KbentError::Inval) => Err(FsError::InvalidData),
                Err(crate::vt::KbentError::Perm) => Err(FsError::OperationNotPermitted),
            }
        }
        // `vt_do_kdgkb_ioctl`: `struct kbsentry { u8 kb_func; u8
        // kb_string[512]; }`.
        KDGKBSENT | KDSKBSENT => {
            let mut func = [0u8; 1];
            // SAFETY: `kb_func` is the first byte of `struct kbsentry`.
            unsafe { copy_in(arg, &mut func)? };
            if cmd == KDGKBSENT {
                let mut s = crate::vt::get_func(func[0]);
                s.truncate(511);
                s.push(0);
                // SAFETY: `kb_string[512]` follows `kb_func`; `s` is at
                // most 512 bytes including the NUL.
                unsafe { copy_out(arg + 1, &s)? };
                return Ok(0);
            }
            if !vt_perm() {
                return Err(FsError::OperationNotPermitted);
            }
            // `strndup_user(kb_string, 512)`: longer than 511 is -EINVAL.
            let mut raw = vec![0u8; 512];
            // SAFETY: `kb_string` is the 512 bytes after `kb_func`.
            unsafe { copy_in(arg + 1, &mut raw)? };
            let len = raw
                .iter()
                .position(|&b| b == 0)
                .ok_or(FsError::InvalidData)?;
            raw.truncate(len);
            crate::vt::set_func(func[0], raw);
            Ok(0)
        }
        // `vt_do_diacrit`.
        KDGKBDIACR => {
            // `struct kbdiacrs { unsigned int kb_cnt; struct kbdiacr
            // kbdiacr[256]; }`, `struct kbdiacr { u8 diacr, base, result; }`.
            let table = crate::vt::accents();
            let mut out = Vec::with_capacity(4 + table.len() * 3);
            out.extend_from_slice(&(table.len() as u32).to_ne_bytes());
            for d in &table {
                out.push(conv_uni_to_8bit(d.diacr));
                out.push(conv_uni_to_8bit(d.base));
                out.push(conv_uni_to_8bit(d.result));
            }
            // SAFETY: `arg` is the caller's `struct kbdiacrs *`.
            unsafe { copy_out(arg, &out)? };
            Ok(0)
        }
        KDGKBDIACRUC => {
            let table = crate::vt::accents();
            let mut out = Vec::with_capacity(4 + table.len() * 12);
            out.extend_from_slice(&(table.len() as u32).to_ne_bytes());
            for d in &table {
                out.extend_from_slice(&d.diacr.to_ne_bytes());
                out.extend_from_slice(&d.base.to_ne_bytes());
                out.extend_from_slice(&d.result.to_ne_bytes());
            }
            // SAFETY: `arg` is the caller's `struct kbdiacrsuc *`.
            unsafe { copy_out(arg, &out)? };
            Ok(0)
        }
        KDSKBDIACR | KDSKBDIACRUC => {
            if !vt_perm() {
                return Err(FsError::OperationNotPermitted);
            }
            let mut cnt = [0u8; 4];
            // SAFETY: `kb_cnt` is the leading `unsigned int`.
            unsafe { copy_in(arg, &mut cnt)? };
            let ct = u32::from_ne_bytes(cnt) as usize;
            // `if (ct >= MAX_DIACR) return -EINVAL;`
            if ct >= crate::vt::MAX_DIACR {
                return Err(FsError::InvalidData);
            }
            let size = if cmd == KDSKBDIACR { 3 } else { 12 };
            let mut raw = vec![0u8; ct * size];
            if ct != 0 {
                // SAFETY: `ct` entries follow `kb_cnt`.
                unsafe { copy_in(arg + 4, &mut raw)? };
            }
            let table = raw
                .chunks_exact(size)
                .map(|c| {
                    if size == 3 {
                        // `conv_8bit_to_uni` over the identity user map.
                        crate::vt::DiacrUc {
                            diacr: u32::from(c[0]),
                            base: u32::from(c[1]),
                            result: u32::from(c[2]),
                        }
                    } else {
                        let w = |o: usize| u32::from_ne_bytes([c[o], c[o + 1], c[o + 2], c[o + 3]]);
                        crate::vt::DiacrUc {
                            diacr: w(0),
                            base: w(4),
                            result: w(8),
                        }
                    }
                })
                .collect();
            crate::vt::set_accents(table);
            Ok(0)
        }
        KDFONTOP => font_op(arg),
        _ => Err(FsError::Unsupported),
    }
}

/// `KDFONTOP` -> `con_font_op` for a console driver that has no font
/// operations (`vc_sw->con_font_get/set/default == NULL`), the VT always in
/// `KD_TEXT`. `struct console_font_op { u32 op, flags, width, height,
/// charcount; u8 *data; }` — 32 bytes on LP64, `data` at offset 24.
fn font_op(arg: usize) -> Result<u64, FsError> {
    let mut raw = [0u8; 32];
    // SAFETY: `arg` is the caller's `struct console_font_op *`.
    unsafe { copy_in(arg, &mut raw)? };
    let w = |o: usize| u32::from_ne_bytes([raw[o], raw[o + 1], raw[o + 2], raw[o + 3]]);
    let (op, width, height, charcount) = (w(0), w(8), w(12), w(16));
    let data = u64::from_ne_bytes(raw[24..32].try_into().unwrap_or([0; 8]));
    // `if (!perm && op.op != KD_FONT_OP_GET) return -EPERM;`
    if !vt_perm() && op != KD_FONT_OP_GET {
        return Err(FsError::OperationNotPermitted);
    }
    match op {
        KD_FONT_OP_SET | KD_FONT_OP_SET_TALL => {
            // `con_font_set`'s argument checks come first.
            let vpitch = if op == KD_FONT_OP_SET_TALL {
                height
            } else {
                32
            };
            if data == 0
                || charcount > MAX_FONT_GLYPHS
                || width == 0
                || width > MAX_FONT_WIDTH
                || height == 0
                || height > MAX_FONT_HEIGHT
                || vpitch < height
            {
                return Err(FsError::InvalidData);
            }
            Err(FsError::NotImplemented)
        }
        KD_FONT_OP_GET | KD_FONT_OP_GET_TALL => {
            // `if (vpitch > max_font_height) return -EINVAL;`
            let vpitch = if op == KD_FONT_OP_GET_TALL {
                height
            } else {
                32
            };
            if vpitch > MAX_FONT_HEIGHT {
                return Err(FsError::InvalidData);
            }
            Err(FsError::NotImplemented)
        }
        KD_FONT_OP_SET_DEFAULT => Err(FsError::NotImplemented),
        // "was buggy and never really used"
        KD_FONT_OP_COPY => Err(FsError::InvalidData),
        _ => Err(FsError::NotImplemented),
    }
}

/// Which `/dev/vcs*` flavour a node is (`vc_screen.c`): text (`vcs`, minor
/// N), attributes (`vcsa`, minor 128+N), Unicode (`vcsu`, minor 64+N). N = 0
/// is the foreground console.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VcsKind {
    Text,
    Unicode,
    Attr,
}

/// Parse a `/dev` leaf into a `/dev/vcs*` node that exists: `vcs`, `vcsa`,
/// `vcsu` always, `vcsN`/`vcsaN`/`vcsuN` for an allocated VT N.
pub(crate) fn parse_vcs(name: &str) -> Option<(VcsKind, u32)> {
    let (kind, rest) = if let Some(r) = name.strip_prefix("vcsa") {
        (VcsKind::Attr, r)
    } else if let Some(r) = name.strip_prefix("vcsu") {
        (VcsKind::Unicode, r)
    } else if let Some(r) = name.strip_prefix("vcs") {
        (VcsKind::Text, r)
    } else {
        return None;
    };
    if rest.is_empty() {
        return Some((kind, 0));
    }
    if rest.starts_with('0') || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u32 = rest.parse().ok()?;
    crate::vt::is_allocated(n).then_some((kind, n))
}

/// The `/dev/vcs*` names that exist right now, for `/dev` enumeration.
pub(crate) fn vcs_names() -> Vec<alloc::string::String> {
    let mut out = Vec::new();
    for n in 0..=crate::vt::MAX_VT {
        if n != 0 && !crate::vt::is_allocated(n) {
            continue;
        }
        for prefix in ["vcs", "vcsu", "vcsa"] {
            out.push(if n == 0 {
                alloc::string::String::from(prefix)
            } else {
                alloc::format!("{prefix}{n}")
            });
        }
    }
    out
}

/// A `/dev/vcs*` node.
#[derive(Debug)]
pub(crate) struct DevVcs {
    pub(crate) kind: VcsKind,
    pub(crate) vt: u32,
}

impl FileOps for DevVcs {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        // No VT screen buffer to copy out (module LINUX-GAP).
        Box::pin(async { Ok(0) })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        // `vcs_write` stops at the end of the screen, which is 0 bytes here.
        Box::pin(async { Ok(0) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                // `vc_screen.c`: `vcs_init` registers the class with no
                // devnode callback, so devtmpfs creates them 0600.
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }

    fn rdev(&self) -> u64 {
        // VCS_MAJOR 7; vcsu at +64, vcsa at +128.
        let base = match self.kind {
            VcsKind::Text => 0,
            VcsKind::Unicode => 64,
            VcsKind::Attr => 128,
        };
        crate::devfs::linux_makedev(7, base + self.vt)
    }

    fn ino(&self) -> u64 {
        crate::devfs::device_inode(self.rdev(), 1)
    }
}

//! Linux syscall ABI conformance — the VT keyboard/font surface
//! systemd-vconsole-setup and `loadkeys` use.
//!
//! systemd-vconsole-setup exited 1 on NARF with "No virtual console that
//! can be configured found: No such file or directory": it tests VT N's
//! allocation with `access("/dev/vcsN")`, and NARF had no `/dev/vcs*`. Past
//! that it needs `KDGKBMODE` to say `K_XLATE`/`K_UNICODE` (NARF said 0,
//! `K_RAW`), and `loadkeys -C /dev/ttyN` needs `KDGKBTYPE`, `KDSKBENT`,
//! `KDSKBSENT` and `KDSKBDIACRUC` (all -ENOTTY). `KDFONTOP` answers
//! -ENOSYS, as Linux does for a console driver without font support, which
//! vconsole-setup treats as "no font support, skipping".

use crate::abi_test_support::*;

const KDGKBTYPE: u64 = 0x4B33;
const KDGKBMODE: u64 = 0x4B44;
const KDSKBMODE: u64 = 0x4B45;
const KDGKBENT: u64 = 0x4B46;
const KDSKBENT: u64 = 0x4B47;
const KDGKBSENT: u64 = 0x4B48;
const KDSKBSENT: u64 = 0x4B49;
const KDFONTOP: u64 = 0x4B72;
const KDGKBDIACRUC: u64 = 0x4BFA;
const KDSKBDIACRUC: u64 = 0x4BFB;
const K_XLATE: i32 = 1;
const K_UNICODE: i32 = 3;

fn open_tty1() -> Option<u64> {
    let fd = call_open(c"/dev/tty1".as_ptr() as u64, 0o2)?;
    u64::try_from(fd).ok()
}

fn ioctl(fd: u64, cmd: u64, arg: u64) -> Option<i64> {
    call(Syscall::Ioctl.raw(), a2(fd, cmd, arg))
}

/// vconsole-setup's `find_source_vc` + `loadkeys` path succeeds.
fn smoke_abi_vconsole_keyboard_pos() -> TestResult {
    with_setup(|| {
        // `verify_vc_allocation(1)`: VT 1 is the boot console.
        if call_access(c"/dev/vcs1".as_ptr() as u64, 0) != Some(0)
            || call_access(c"/dev/vcs".as_ptr() as u64, 0) != Some(0)
            || call_access(c"/dev/vcsa1".as_ptr() as u64, 0) != Some(0)
        {
            return Err("/dev/vcs, /dev/vcs1 and /dev/vcsa1 must exist for VT 1");
        }
        let fd = open_tty1().ok_or("open /dev/tty1 failed")?;
        let finish = |r: Result<(), &'static str>| {
            let _ = ioctl(fd, KDSKBMODE, K_UNICODE as u64);
            let _ = call(Syscall::Close.raw(), a0(fd));
            r
        };
        let mut mode = -1i32;
        if ioctl(fd, KDGKBMODE, &mut mode as *mut i32 as u64) != Some(0) || mode != K_UNICODE {
            return finish(Err("KDGKBMODE must report K_UNICODE (vt.default_utf8=1)"));
        }
        if ioctl(fd, KDSKBMODE, K_XLATE as u64) != Some(0) {
            return finish(Err("KDSKBMODE K_XLATE failed"));
        }
        if ioctl(fd, KDGKBMODE, &mut mode as *mut i32 as u64) != Some(0) || mode != K_XLATE {
            return finish(Err("KDSKBMODE did not stick"));
        }
        let mut kbtype = 0u8;
        if ioctl(fd, KDGKBTYPE, &mut kbtype as *mut u8 as u64) != Some(0) || kbtype != 0x02 {
            return finish(Err("KDGKBTYPE must report KB_101 (loadkeys' is_a_console)"));
        }
        // kbentry { kb_table, kb_index, kb_value }: key 30 = K(KT_LETTER,'a').
        let mut kbe = [0u8, 30, 0x61, 0x0b];
        if ioctl(fd, KDSKBENT, kbe.as_mut_ptr() as u64) != Some(0) {
            return finish(Err("KDSKBENT of a Linux-valid entry failed"));
        }
        let mut back = [0u8, 30, 0, 0];
        if ioctl(fd, KDGKBENT, back.as_mut_ptr() as u64) != Some(0) || back[2..] != [0x61, 0x0b] {
            return finish(Err("KDGKBENT did not read back the stored entry"));
        }
        // A never-allocated map reads K_NOSUCHMAP at index 0.
        let mut none = [3u8, 0, 0, 0];
        if ioctl(fd, KDGKBENT, none.as_mut_ptr() as u64) != Some(0)
            || u16::from_ne_bytes([none[2], none[3]]) != 0x027f
        {
            return finish(Err("KDGKBENT of an absent map must be K_NOSUCHMAP"));
        }
        // kbsentry { kb_func; kb_string[512] }.
        let mut kbs = [0u8; 513];
        kbs[0] = 5;
        kbs[1..6].copy_from_slice(b"\x1b[15~");
        if ioctl(fd, KDSKBSENT, kbs.as_mut_ptr() as u64) != Some(0) {
            return finish(Err("KDSKBSENT failed"));
        }
        let mut got = [0u8; 513];
        got[0] = 5;
        if ioctl(fd, KDGKBSENT, got.as_mut_ptr() as u64) != Some(0) || &got[1..7] != b"\x1b[15~\0" {
            return finish(Err("KDGKBSENT did not read back the function string"));
        }
        // kbdiacrsuc { kb_cnt; kbdiacruc[256] { diacr, base, result } }.
        let mut dia = [0u32; 1 + 3 * 2];
        dia[0] = 2;
        dia[1..4].copy_from_slice(&[0x60, 0x61, 0xe0]);
        dia[4..7].copy_from_slice(&[0x27, 0x65, 0xe9]);
        if ioctl(fd, KDSKBDIACRUC, dia.as_mut_ptr() as u64) != Some(0) {
            return finish(Err("KDSKBDIACRUC failed"));
        }
        let mut out = [0u32; 1 + 3 * 256];
        if ioctl(fd, KDGKBDIACRUC, out.as_mut_ptr() as u64) != Some(0) || out[..7] != dia[..] {
            return finish(Err("KDGKBDIACRUC did not read back the accent table"));
        }
        // vconsole-setup's `verify_vc_support_font`: GET is -ENOSYS on a
        // console without font operations, which it reads as "skip".
        let mut op = [0u8; 32];
        op[0..4].copy_from_slice(&1u32.to_ne_bytes()); // KD_FONT_OP_GET
        op[8..12].copy_from_slice(&u32::MAX.to_ne_bytes());
        op[12..16].copy_from_slice(&u32::MAX.to_ne_bytes());
        op[16..20].copy_from_slice(&u32::MAX.to_ne_bytes());
        if ioctl(fd, KDFONTOP, op.as_mut_ptr() as u64) != Some(ENOSYS) {
            return finish(Err(
                "KDFONTOP GET must be ENOSYS without console font support",
            ));
        }
        finish(Ok(()))
    })
}
kernel_test_in!("syscall_abi", smoke_abi_vconsole_keyboard_pos);

/// The -EINVAL / -ENOENT answers `vt_do_kdskbmode`, `vt_kdskbent`,
/// `vt_do_kdskbdiacruc`, `con_font_op` and `vc_screen.c` give.
fn smoke_abi_vconsole_keyboard_neg() -> TestResult {
    with_setup(|| {
        // VT 42 was never allocated: no /dev/vcs42.
        if call_access(c"/dev/vcs42".as_ptr() as u64, 0) != Some(ENOENT) {
            return Err("/dev/vcsN of an unallocated VT must not exist");
        }
        let fd = open_tty1().ok_or("open /dev/tty1 failed")?;
        let finish = |r: Result<(), &'static str>| {
            let _ = ioctl(fd, KDSKBMODE, K_UNICODE as u64);
            let _ = call(Syscall::Close.raw(), a0(fd));
            r
        };
        if ioctl(fd, KDSKBMODE, 7) != Some(EINVAL) {
            return finish(Err("KDSKBMODE of an unknown mode must be EINVAL"));
        }
        // K(KT_CUR, 4): KT_CUR's max value is 3.
        let mut kbe = [0u8, 31, 4, 6];
        if ioctl(fd, KDSKBENT, kbe.as_mut_ptr() as u64) != Some(EINVAL) {
            return finish(Err("KDSKBENT beyond max_vals must be EINVAL"));
        }
        // A Unicode keysym (KTYP >= NR_TYPES) is only valid in K_UNICODE.
        let _ = ioctl(fd, KDSKBMODE, K_XLATE as u64);
        let mut uni = [0u8, 31, 0x41, 0xf0];
        if ioctl(fd, KDSKBENT, uni.as_mut_ptr() as u64) != Some(EINVAL) {
            return finish(Err("a Unicode keysym outside K_UNICODE must be EINVAL"));
        }
        let _ = ioctl(fd, KDSKBMODE, K_UNICODE as u64);
        if ioctl(fd, KDSKBENT, uni.as_mut_ptr() as u64) != Some(0) {
            return finish(Err("a Unicode keysym in K_UNICODE must be accepted"));
        }
        // `if (ct >= MAX_DIACR) return -EINVAL;`
        let mut dia = [0u32; 1];
        dia[0] = 256;
        if ioctl(fd, KDSKBDIACRUC, dia.as_mut_ptr() as u64) != Some(EINVAL) {
            return finish(Err("KDSKBDIACRUC with 256 entries must be EINVAL"));
        }
        // KD_FONT_OP_COPY: "was buggy and never really used" -> -EINVAL;
        // KD_FONT_OP_SET with no data -> -EINVAL before the ENOSYS.
        let mut op = [0u8; 32];
        op[0..4].copy_from_slice(&3u32.to_ne_bytes());
        if ioctl(fd, KDFONTOP, op.as_mut_ptr() as u64) != Some(EINVAL) {
            return finish(Err("KD_FONT_OP_COPY must be EINVAL"));
        }
        op[0..4].copy_from_slice(&0u32.to_ne_bytes());
        op[8..12].copy_from_slice(&8u32.to_ne_bytes());
        op[12..16].copy_from_slice(&16u32.to_ne_bytes());
        op[16..20].copy_from_slice(&256u32.to_ne_bytes());
        if ioctl(fd, KDFONTOP, op.as_mut_ptr() as u64) != Some(EINVAL) {
            return finish(Err("KD_FONT_OP_SET without data must be EINVAL"));
        }
        finish(Ok(()))
    })
}
kernel_test_in!("syscall_abi", smoke_abi_vconsole_keyboard_neg);

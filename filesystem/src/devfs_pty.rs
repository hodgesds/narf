//! Unix98 pseudoterminal support for `/dev/ptmx` and `/dev/pts/<N>`.
//!
//! Linux refs:
//!   - `drivers/tty/pty.c` — `ptm_unix98_ops`, `pts_unix98_ops`
//!   - `fs/devpts/inode.c` — pts directory, index allocation
//!
//! ## Design
//!
//! Each `open("/dev/ptmx")` allocates a `Pty` and returns a `PtyMaster`
//! `FileOps` handle.  A `PtySlave` `FileOps` handle is then reachable
//! via `/dev/pts/<N>` where N is available internally through
//! `PtyMaster::index()` and to Linux callers through PTY ioctls. As on Linux,
//! `stat().size` remains zero and does not encode private state.
//!
//! Both handles share one `Arc<Pty>`.  The pair is registered in
//! `PTY_TABLE` on allocation and removed when **both** handles have been
//! dropped (the `Arc` refcount hits one in each of the master/slave
//! wrappers, tracked via separate `Arc`s keyed by index).
//!
//! ## Data-flow
//!
//! ```text
//!   userspace writer                  userspace reader
//!        |                                   ^
//!        v   PtyMaster::write               |
//!   ntty line discipline ───────────>  PtySlave::read
//!   (ICANON, ECHO, ISIG → pty.input)
//!        |
//!        '— ECHO ─┐
//!   PtySlave::write  ──────────────>  slave_tx_to_master
//!                                         |
//!                                         v   PtyMaster::read
//! ```
//!
//! ## Remaining differences
//!
//! NARF currently has one global PTY registry. Separate devpts mounts expose
//! that registry rather than allocating Linux-style independent instances,
//! and devpts mount options (`newinstance`, `gid`, `mode`, `ptmxmode`, `max`)
//! are not yet applied.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, FsInstance, Mode, Stat};

// ── Terminal ioctl numbers (Linux ABI) ────────────────────────────────────────
//
// Mirrors `userspace::fd` constants — duplicated here so the FS layer doesn't
// need to import the kernel-userspace crate. The wire values are stable Linux
// ABI; if these ever drift, sys_ioctl will route the wrong cmd word.

/// `ioctl(fd, TIOCGPGRP, &pid_t)` — foreground process group.
pub const TIOCGPGRP: u32 = 0x540F;
/// `ioctl(fd, TIOCSPGRP, &pid_t)` — set foreground process group.
pub const TIOCSPGRP: u32 = 0x5410;
/// `ioctl(fd, TIOCSCTTY, 0)` — set this tty as the caller's controlling tty.
pub const TIOCSCTTY: u32 = 0x540E;
/// `ioctl(master_fd, TIOCGPTN, &u32)` — query the slave index N.
pub const TIOCGPTN: u32 = 0x80045430;
/// `ioctl(master_fd, TIOCSPTLCK, &i32)` — set (1) / clear (0) slave-lock.
pub const TIOCSPTLCK: u32 = 0x40045431;
/// `ioctl(master_fd, TIOCGPTPEER, flags)` — open a fresh slave fd. Handled
/// by the syscall layer because fd allocation lives in userspace::fd.
pub const TIOCGPTPEER: u32 = 0x40045441;
/// `ioctl(fd, TIOCGWINSZ, &winsize)` — query window dimensions.
pub const TIOCGWINSZ: u32 = 0x5413;
/// `ioctl(fd, TIOCSWINSZ, &winsize)` — set window dimensions.
pub const TIOCSWINSZ: u32 = 0x5414;
/// `ioctl(fd, TCGETS, &termios)` — get terminal attributes.
pub const TCGETS: u32 = 0x5401;
/// `ioctl(fd, TCSETS, &termios)` — set terminal attributes (immediate).
pub const TCSETS: u32 = 0x5402;
/// `ioctl(fd, TCSETSW, &termios)` — set terminal attributes (drain output).
pub const TCSETSW: u32 = 0x5403;
/// `ioctl(fd, TCSETSF, &termios)` — set terminal attributes (drain + flush).
pub const TCSETSF: u32 = 0x5404;
/// `ioctl(fd, TCGETS2, &termios2)` — get terminal attributes (termios2 form,
/// 44 bytes: kernel `termios` + `c_ispeed`/`c_ospeed`). Modern glibc's
/// `tcgetattr()` issues TCGETS2, NOT TCGETS — so a device that only answers
/// TCGETS makes glibc's `tcgetattr()` (and therefore `isatty()`-adjacent
/// terminal probes) fail with ENOTTY. systemd concludes `/dev/console` is not
/// a terminal and silently disables console logging; getty/login also break.
pub const TCGETS2: u32 = 0x802c542a;
/// `ioctl(fd, TCSETS2, &termios2)` — set terminal attributes (immediate).
pub const TCSETS2: u32 = 0x402c542b;
/// `ioctl(fd, TCSETSW2, &termios2)` — set terminal attributes (drain output).
pub const TCSETSW2: u32 = 0x402c542c;
/// `ioctl(fd, TCSETSF2, &termios2)` — set terminal attributes (drain + flush).
pub const TCSETSF2: u32 = 0x402c542d;
/// `ioctl(fd, FIONREAD, &i32)` — bytes immediately readable.
pub const FIONREAD: u32 = 0x541B;
/// `ioctl(fd, TIOCOUTQ, int*)` — bytes still queued for output.
///
/// Note there is deliberately no `TIOCINQ` constant: `ioctls.h:47` defines
/// it as `#define TIOCINQ FIONREAD`, the very same command, so a separate
/// match arm for it would be dead code.
pub const TIOCOUTQ: u32 = 0x5411;
/// `ioctl(fd, TIOCEXCL)` / `TIOCNXCL` / `TIOCGEXCL` — exclusive-open mode.
pub const TIOCEXCL: u32 = 0x540C;
pub const TIOCNXCL: u32 = 0x540D;
pub const TIOCGEXCL: u32 = 0x8004_5440;
/// `ioctl(fd, TIOCSTI, char*)` — push one byte back into the input queue.
pub const TIOCSTI: u32 = 0x5412;
/// `ioctl(fd, TIOCSETD/TIOCGETD, int*)` — line-discipline number.
pub const TIOCSETD: u32 = 0x5423;
pub const TIOCGETD: u32 = 0x5424;
/// `ioctl(fd, TIOCVHANGUP)` — force a hangup.
pub const TIOCVHANGUP: u32 = 0x5437;
/// `ioctl(fd, TIOCGLCKTRMIOS/TIOCSLCKTRMIOS, termios*)` — the mask of
/// termios bits that `TCSETS` may not change.
pub const TIOCGLCKTRMIOS: u32 = 0x5456;
pub const TIOCSLCKTRMIOS: u32 = 0x5457;
/// `N_TTY` — the only line discipline NARF implements, and the one every
/// PTY uses (`include/uapi/linux/tty.h`).
pub const N_TTY: i32 = 0;
/// `CAP_SYS_ADMIN`, the capability the privileged tty ioctls test.
pub const CAP_SYS_ADMIN: u32 = 21;
/// `ioctl(fd, TIOCNOTTY, 0)` — give up the controlling terminal.
pub const TIOCNOTTY: u32 = 0x5422;
/// `ioctl(fd, TIOCGSID, &pid_t)` — session id of the tty's session leader.
pub const TIOCGSID: u32 = 0x5429;
/// `ioctl(fd, TCSBRK, int)` — drain output, optionally send BREAK.
pub const TCSBRK: u32 = 0x5409;
/// `ioctl(fd, TCXONC, int)` — suspend/resume output (tcflow).
pub const TCXONC: u32 = 0x540A;
/// `ioctl(fd, TCFLSH, int)` — flush pending input/output (tcflush).
pub const TCFLSH: u32 = 0x540B;
/// `ioctl(master_fd, TIOCPKT, &int)` — enable/disable packet mode. In packet
/// mode every master read is prefixed with a status byte; KDE's KPtyDevice
/// (konsole) enables it and desyncs without the framing. `0x5420` (raw, like
/// TIOCPKT in `include/uapi/asm-generic/ioctls.h`).
pub const TIOCPKT: u32 = 0x5420;
/// `ioctl(master_fd, TIOCGPKT, &int)` — read the packet-mode flag.
/// `_IOR('T', 0x38, int)`.
pub const TIOCGPKT: u32 = 0x8004_5438;
/// `ioctl(master_fd, TIOCGPTLCK, &int)` — read the slave-lock flag set by
/// TIOCSPTLCK. `_IOR('T', 0x39, int)`.
pub const TIOCGPTLCK: u32 = 0x8004_5439;
/// `ioctl(master_fd, TIOCSIG, sig)` — send signal `sig` (the arg VALUE, not a
/// pointer) to the slave's foreground process group. `_IOW('T', 0x36, int)`.
pub const TIOCSIG: u32 = 0x4004_5436;
/// TIOCPKT_DATA — the status byte prefixed to an ordinary data packet.
pub const TIOCPKT_DATA: u8 = 0;
/// `ioctl(fd, KDGKBMODE, &int)` — query the VT keyboard translation mode.
pub const KDGKBMODE: u32 = 0x4B44;
/// `ioctl(fd, KDSKBMODE, int)` — set the VT keyboard translation mode.
pub const KDSKBMODE: u32 = 0x4B45;
/// `ioctl(fd, KDGETMODE, &int)` — query the VT graphics/text mode.
pub const KDGETMODE: u32 = 0x4B3B;
/// `ioctl(fd, KDSIGACCEPT, int)` — nominate the SysRq kbrequest signal.
pub const KDSIGACCEPT: u32 = 0x4B4E;
/// `ioctl(fd, VT_OPENQRY, &int)` — first free VT index.
pub const VT_OPENQRY: u32 = 0x5600;
/// `ioctl(fd, VT_GETMODE, &vt_mode)` — current VT switching mode.
pub const VT_GETMODE: u32 = 0x5601;
/// `ioctl(fd, VT_GETSTATE, &vt_stat)` — active-VT state.
pub const VT_GETSTATE: u32 = 0x5603;
/// `ioctl(fd, VT_ACTIVATE, vtnum)` — switch to VT `vtnum`.
pub const VT_ACTIVATE: u32 = 0x5606;
/// `ioctl(fd, VT_WAITACTIVE, vtnum)` — block until VT `vtnum` is active.
pub const VT_WAITACTIVE: u32 = 0x5607;
/// `ioctl(fd, VT_SETMODE, &vt_mode)` — install the VT switching mode (logind
/// sets `VT_PROCESS` on a session's VT so it is signalled on switch requests).
pub const VT_SETMODE: u32 = 0x5602;
/// `ioctl(fd, VT_RELDISP, arg)` — acknowledge/allow a VT switch. NARF never
/// forces one, so this is a no-op that returns success.
pub const VT_RELDISP: u32 = 0x5605;
/// `ioctl(fd, KDSETMODE, KD_TEXT|KD_GRAPHICS)` — set text vs graphics console
/// mode. A compositor sets `KD_GRAPHICS` on its VT to take over the display.
pub const KDSETMODE: u32 = 0x4B3A;

// ── Ring buffer ───────────────────────────────────────────────────────────────

/// Fixed-capacity lock-protected byte ring.  Capacity is specified as a
/// const-generic `N` so each PTY gets its own appropriately-sized ring.
pub(crate) struct ByteRing<const N: usize> {
    inner: IrqSafeSpinLock<ByteRingInner<N>>,
}

struct ByteRingInner<const N: usize> {
    buf: [u8; N],
    head: usize, // read pointer
    len: usize,  // bytes currently stored
}

impl<const N: usize> ByteRing<N> {
    const fn new() -> Self {
        Self {
            inner: IrqSafeSpinLock::new(ByteRingInner {
                buf: [0u8; N],
                head: 0,
                len: 0,
            }),
        }
    }

    /// Push bytes; silently discards those that don't fit.
    fn push(&self, data: &[u8]) {
        let mut g = self.inner.lock();
        for &b in data {
            if g.len < N {
                let tail = (g.head + g.len) % N;
                g.buf[tail] = b;
                g.len += 1;
            }
        }
    }

    /// Pop up to `buf.len()` bytes; returns number actually copied.
    fn pop(&self, buf: &mut [u8]) -> usize {
        let mut g = self.inner.lock();
        let n = buf.len().min(g.len);
        for slot in buf.iter_mut().take(n) {
            *slot = g.buf[g.head];
            g.head = (g.head + 1) % N;
        }
        g.len -= n;
        n
    }

    /// Returns the number of bytes currently in the ring.
    /// Used by tests to verify buffer state without popping.
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().len
    }

    /// Discard everything queued — `TCFLSH`'s output half.
    pub(crate) fn clear(&self) {
        let mut g = self.inner.lock();
        g.head = 0;
        g.len = 0;
    }
}

impl<const N: usize> core::fmt::Debug for ByteRing<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let g = self.inner.lock();
        f.debug_struct("ByteRing")
            .field("capacity", &N)
            .field("len", &g.len)
            .finish()
    }
}

// ── Termios ───────────────────────────────────────────────────────────────────

/// Wire length of libc's userspace `struct termios` on x86_64 (glibc/musl:
/// 4 flag words + c_line + c_cc[32] + 2 speeds, padded to 60). This is the
/// size of NARF's INTERNAL termios image, NOT the ioctl wire size.
pub const TERMIOS_WIRE_LEN: usize = 60;

/// The KERNEL-ABI `struct termios` is 36 bytes (`NCCS = 19`): 4 flag words
/// (16) + c_line (1) + c_cc[19] (19). TCGETS/TCSETS exchange exactly this
/// with userspace — glibc's tcgetattr/tcsetattr pass a 36-byte
/// `__kernel_termios` and convert. Writing the full 60-byte image overruns
/// that buffer by 24 bytes (clobbering the caller's stack canary → SIGABRT
/// in glibc's isatty during systemd's open_terminal). The first 36 bytes of
/// the 60-byte image are exactly the kernel struct (speeds live at 52+).
pub const KERNEL_TERMIOS_LEN: usize = 36;

/// The KERNEL-ABI `struct termios2` is 44 bytes: the 36-byte kernel `termios`
/// followed by `c_ispeed` (u32) and `c_ospeed` (u32). TCGETS2/TCSETS2 exchange
/// exactly this. glibc's `tcgetattr`/`tcsetattr` use termios2 on Linux.
pub const KERNEL_TERMIOS2_LEN: usize = 44;

/// A plausible fixed baud (38400) reported in the `c_ispeed`/`c_ospeed`
/// fields of a TCGETS2 reply for a virtual console/PTY (which has no real
/// line rate). tcgetattr only needs a self-consistent value.
const TERMIOS2_BAUD: u32 = 38400;

// `c_lflag` bits we honour (asm-generic termbits).
const L_ISIG: u32 = 0x0000_0001;
const L_ICANON: u32 = 0x0000_0002;
const L_ECHO: u32 = 0x0000_0008;
const L_TOSTOP: u32 = 0x0000_0100;
// Remaining c_lflag bits (`include/uapi/asm-generic/termbits.h`).
const L_ECHOE: u32 = 0x0000_0010;
const L_ECHOK: u32 = 0x0000_0020;
const L_ECHONL: u32 = 0x0000_0040;
const L_NOFLSH: u32 = 0x0000_0080;
const L_ECHOCTL: u32 = 0x0000_0200;
const L_ECHOPRT: u32 = 0x0000_0400;
const L_ECHOKE: u32 = 0x0000_0800;
const L_IEXTEN: u32 = 0x0000_8000;
const L_EXTPROC: u32 = 0x0001_0000;
// c_iflag bits (`termbits-common.h` + `termbits.h`).
const I_ISTRIP: u32 = 0x0000_0020;
const I_INLCR: u32 = 0x0000_0040;
const I_IGNCR: u32 = 0x0000_0080;
const I_ICRNL: u32 = 0x0000_0100;
const I_IUCLC: u32 = 0x0000_0200;
const I_IXON: u32 = 0x0000_0400;
const I_IXANY: u32 = 0x0000_0800;
const I_IMAXBEL: u32 = 0x0000_2000;
const I_IUTF8: u32 = 0x0000_4000;
// c_oflag bits.
const O_OPOST: u32 = 0x0000_0001;
const O_OLCUC: u32 = 0x0000_0002;
const O_ONLCR: u32 = 0x0000_0004;
const O_OCRNL: u32 = 0x0000_0008;
const O_ONOCR: u32 = 0x0000_0010;
const O_ONLRET: u32 = 0x0000_0020;
const O_TABDLY: u32 = 0x0000_1800;
const O_XTABS: u32 = 0x0000_1800;

/// `c_cc[]` indices (`include/uapi/asm-generic/termbits.h:42`).
pub const VINTR: usize = 0;
pub const VQUIT: usize = 1;
pub const VERASE: usize = 2;
pub const VKILL: usize = 3;
pub const VEOF: usize = 4;
pub const VTIME: usize = 5;
pub const VMIN: usize = 6;
pub const VSTART: usize = 8;
pub const VSTOP: usize = 9;
pub const VSUSP: usize = 10;
pub const VEOL: usize = 11;
pub const VREPRINT: usize = 12;
pub const VDISCARD: usize = 13;
pub const VWERASE: usize = 14;
pub const VLNEXT: usize = 15;
pub const VEOL2: usize = 16;

/// Full termios state. We keep the userspace `struct termios` wire image
/// verbatim so TCGETS/TCSETS round-trip every field a program sets, and
/// derive the line-discipline knobs (ICANON / ECHO / ISIG) from `c_lflag`.
#[derive(Copy, Clone, Debug)]
pub struct Termios {
    /// Raw `struct termios` wire image (c_iflag@0, c_oflag@4, c_cflag@8,
    /// c_lflag@12, c_line@16, c_cc[]@17, speeds@52..60).
    pub raw: [u8; TERMIOS_WIRE_LEN],
}

impl Termios {
    fn lflag(&self) -> u32 {
        u32::from_ne_bytes(self.raw[12..16].try_into().unwrap())
    }
    /// Canonical mode (line-buffered): slave reads wait for `\n` or `^D`.
    pub fn icanon(&self) -> bool {
        self.lflag() & L_ICANON != 0
    }
    /// Echo: bytes the slave reads are echoed back to the master.
    pub fn echo(&self) -> bool {
        self.lflag() & L_ECHO != 0
    }
    /// Signal generation: ^C/^\/^Z (the `c_cc[VINTR/VQUIT/VSUSP]` chars)
    /// raise SIGINT/SIGQUIT/SIGTSTP to the foreground pgrp instead of
    /// being returned through `read`. Raw-mode programs (vi, readline)
    /// clear ISIG to receive those bytes literally.
    pub fn isig(&self) -> bool {
        self.lflag() & L_ISIG != 0
    }
    /// TOSTOP: a background process writing this tty raises SIGTTOU.
    pub fn tostop(&self) -> bool {
        self.lflag() & L_TOSTOP != 0
    }
    /// A `c_cc[]` control character by index (VINTR=0, VQUIT=1, VERASE=2,
    /// VKILL=3, VEOF=4, …). `c_cc[]` starts at wire offset 17 (after
    /// c_line@16). Returns 0 for out-of-range indices.
    pub fn cc(&self, idx: usize) -> u8 {
        self.raw.get(17 + idx).copied().unwrap_or(0)
    }

    fn iflag(&self) -> u32 {
        u32::from_ne_bytes(self.raw[0..4].try_into().unwrap())
    }
    fn oflag(&self) -> u32 {
        u32::from_ne_bytes(self.raw[4..8].try_into().unwrap())
    }

    // ── c_iflag ───────────────────────────────────────────────────────
    /// ISTRIP: clear the 8th bit of every input byte.
    pub fn istrip(&self) -> bool {
        self.iflag() & I_ISTRIP != 0
    }
    /// INLCR: translate NL to CR on input.
    pub fn inlcr(&self) -> bool {
        self.iflag() & I_INLCR != 0
    }
    /// IGNCR: discard CR on input. Checked BEFORE ICRNL, as Linux does.
    pub fn igncr(&self) -> bool {
        self.iflag() & I_IGNCR != 0
    }
    /// ICRNL: translate CR to NL on input.
    pub fn icrnl(&self) -> bool {
        self.iflag() & I_ICRNL != 0
    }
    /// IUCLC: map upper case to lower case on input.
    pub fn iuclc(&self) -> bool {
        self.iflag() & I_IUCLC != 0
    }
    /// IXON: ^S/^Q (VSTOP/VSTART) suspend and resume output.
    pub fn ixon(&self) -> bool {
        self.iflag() & I_IXON != 0
    }
    /// IXANY: any input byte restarts suspended output, not just VSTART.
    pub fn ixany(&self) -> bool {
        self.iflag() & I_IXANY != 0
    }
    /// IMAXBEL: ring the bell instead of dropping input when the edit
    /// buffer is full.
    pub fn imaxbel(&self) -> bool {
        self.iflag() & I_IMAXBEL != 0
    }
    /// IUTF8: input is UTF-8, so continuation bytes do not advance a
    /// column and erase removes a whole character.
    pub fn iutf8(&self) -> bool {
        self.iflag() & I_IUTF8 != 0
    }

    // ── c_oflag ───────────────────────────────────────────────────────
    /// OPOST: perform output processing at all. With it clear every other
    /// output flag is inert, exactly as in `do_output_char`.
    pub fn opost(&self) -> bool {
        self.oflag() & O_OPOST != 0
    }
    /// OLCUC: map lower case to upper case on output.
    pub fn olcuc(&self) -> bool {
        self.oflag() & O_OLCUC != 0
    }
    /// ONLCR: translate NL to CR-NL on output. Its absence is why a
    /// terminal emulator shows staircased text.
    pub fn onlcr(&self) -> bool {
        self.oflag() & O_ONLCR != 0
    }
    /// OCRNL: translate CR to NL on output.
    pub fn ocrnl(&self) -> bool {
        self.oflag() & O_OCRNL != 0
    }
    /// ONOCR: suppress CR when already at column 0.
    pub fn onocr(&self) -> bool {
        self.oflag() & O_ONOCR != 0
    }
    /// ONLRET: NL also performs the carriage-return function.
    pub fn onlret(&self) -> bool {
        self.oflag() & O_ONLRET != 0
    }
    /// XTABS (TABDLY == XTABS): expand tabs to spaces on output.
    pub fn xtabs(&self) -> bool {
        self.oflag() & O_TABDLY == O_XTABS
    }

    // ── c_lflag ───────────────────────────────────────────────────────
    /// ECHOE: erase the character with BS-SP-BS rather than echoing the
    /// erase char itself.
    pub fn echoe(&self) -> bool {
        self.lflag() & L_ECHOE != 0
    }
    /// ECHOK: echo a newline after the KILL character.
    pub fn echok(&self) -> bool {
        self.lflag() & L_ECHOK != 0
    }
    /// ECHOKE: erase the whole line on KILL instead of echoing a newline.
    pub fn echoke(&self) -> bool {
        self.lflag() & L_ECHOKE != 0
    }
    /// ECHONL: echo NL even when ECHO is off.
    pub fn echonl(&self) -> bool {
        self.lflag() & L_ECHONL != 0
    }
    /// ECHOPRT: echo erased characters between `\` and `/`, the
    /// hardcopy-terminal erase style.
    pub fn echoprt(&self) -> bool {
        self.lflag() & L_ECHOPRT != 0
    }
    /// ECHOCTL: render control characters as `^X`.
    pub fn echoctl(&self) -> bool {
        self.lflag() & L_ECHOCTL != 0
    }
    /// NOFLSH: do NOT flush the input queue when ISIG generates a signal.
    pub fn noflsh(&self) -> bool {
        self.lflag() & L_NOFLSH != 0
    }
    /// IEXTEN: enable the extended chars — VLNEXT, VWERASE, VREPRINT,
    /// VDISCARD. With it clear they are ordinary input.
    pub fn iexten(&self) -> bool {
        self.lflag() & L_IEXTEN != 0
    }
    /// EXTPROC: the line discipline is done externally; the kernel passes
    /// input through untouched.
    pub fn extproc(&self) -> bool {
        self.lflag() & L_EXTPROC != 0
    }
    /// VMIN / VTIME, the non-canonical read thresholds.
    pub fn vmin_vtime(&self) -> (u8, u8) {
        (self.cc(VMIN), self.cc(VTIME))
    }
}

impl Default for Termios {
    fn default() -> Self {
        // Cooked-mode default matching Linux's `n_tty_set_termios` initial
        // state: ICRNL|IXON in, OPOST|ONLCR out, CS8|CREAD control,
        // ISIG|ICANON|ECHO|ECHOE|ECHOK|IEXTEN local, sane control chars.
        let mut raw = [0u8; TERMIOS_WIRE_LEN];
        raw[0..4].copy_from_slice(&0x0000_0500u32.to_ne_bytes()); // c_iflag: ICRNL|IXON
        raw[4..8].copy_from_slice(&0x0000_0005u32.to_ne_bytes()); // c_oflag: OPOST|ONLCR
        raw[8..12].copy_from_slice(&0x0000_00bfu32.to_ne_bytes()); // c_cflag: B38400|CS8|CREAD
        raw[12..16].copy_from_slice(&0x0000_803bu32.to_ne_bytes()); // c_lflag
                                                                    // c_cc[] begins at offset 17 (after c_line@16). Indices:
                                                                    // VINTR=0 VQUIT=1 VERASE=2 VKILL=3 VEOF=4 VTIME=5 VMIN=6.
                                                                    // Exactly Linux's `INIT_C_CC` (`include/linux/termios_internal.h:21`).
                                                                    // The six that used to be missing are not decoration: with VSTART
                                                                    // and VSTOP zero, ^Q/^S can never match and IXON flow control is
                                                                    // dead on arrival; with VWERASE/VLNEXT/VREPRINT zero, ^W/^V/^R are
                                                                    // ordinary input no matter what IEXTEN says.
        let cc = 17;
        raw[cc] = 0x03; // VINTR    = ^C
        raw[cc + 1] = 0x1c; // VQUIT    = ^\
        raw[cc + 2] = 0x7f; // VERASE   = DEL
        raw[cc + 3] = 0x15; // VKILL    = ^U
        raw[cc + 4] = 0x04; // VEOF     = ^D
        raw[cc + 6] = 0x01; // VMIN     = 1
        raw[cc + 8] = 0x11; // VSTART   = ^Q
        raw[cc + 9] = 0x13; // VSTOP    = ^S
        raw[cc + 10] = 0x1a; // VSUSP    = ^Z
        raw[cc + 12] = 0x12; // VREPRINT = ^R
        raw[cc + 13] = 0x0f; // VDISCARD = ^O
        raw[cc + 14] = 0x17; // VWERASE  = ^W
        raw[cc + 15] = 0x16; // VLNEXT   = ^V
        Self { raw }
    }
}

/// Window size — the whole `struct winsize`, pixels included.
///
/// The pixel fields are not decoration: terminal emulators set them, and
/// `tty_do_resize` compares the ENTIRE struct (`memcmp`) to decide whether
/// a resize happened. Dropping them loses information programs read back
/// (sixel and the kitty graphics protocol size images from it) and makes a
/// pixels-only resize look like no resize at all.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WinSize {
    pub rows: u16,
    pub cols: u16,
    pub xpixel: u16,
    pub ypixel: u16,
}

impl Default for WinSize {
    fn default() -> Self {
        Self {
            rows: 24,
            cols: 80,
            xpixel: 0,
            ypixel: 0,
        }
    }
}

/// SIGWINCH — raised on the foreground pgrp when the window size changes.
const SIGWINCH: u32 = 28;

// ── Pty ───────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Default)]
struct PtyControl {
    /// Linux `tty->ctrl.session`; zero means no session owns the tty.
    sid: u64,
    /// Linux `tty->ctrl.pgrp`; zero means no foreground process group.
    fg_pgrp: u64,
}

/// Shared state for one pseudoterminal pair.
///
/// Linux ref: `drivers/tty/pty.c` `struct tty_struct` (paired)
pub struct Pty {
    /// The slave's input queue, produced by running master writes through
    /// the shared n_tty line discipline (cooked line-buffering + echo +
    /// ISIG). The slave reads completed input from here.
    /// (Linux: `master->link->read_buf` after `n_tty_receive_buf`)
    pub(crate) input: IrqSafeSpinLock<crate::ntty::LineState>,

    /// Bytes written by the slave, readable by the master. The line
    /// discipline's echo of master writes also lands here so the master
    /// "sees" what was typed.
    /// (Linux: `tty->link->read_buf` from the slave's perspective)
    pub(crate) slave_tx_to_master: ByteRing<4096>,

    /// Non-canonical read timing (VMIN/VTIME). Linux keeps the equivalent
    /// on the stack of `n_tty_read`, which blocks; NARF's reads are
    /// poll-and-retry, so the deadline has to outlive one attempt.
    pub(crate) read_timer: IrqSafeSpinLock<ReadTimer>,

    /// Output-side line-discipline state (OPOST column tracking) for the
    /// slave-to-master direction.
    pub(crate) output: IrqSafeSpinLock<crate::ntty::OutputState>,

    /// `TTY_EXCLUSIVE` — set by TIOCEXCL. A further open by a caller
    /// without CAP_SYS_ADMIN is EBUSY.
    pub(crate) exclusive: AtomicBool,

    /// The mask of termios bits `TCSETS` may not change, set by
    /// TIOCSLCKTRMIOS. A set bit keeps the OLD value.
    pub(crate) locked_termios: IrqSafeSpinLock<Termios>,

    /// Line discipline state.
    pub(crate) termios: IrqSafeSpinLock<Termios>,

    /// Window dimensions.  ioctl(TIOCSWINSZ) / ioctl(TIOCGWINSZ) deferred
    /// to Stage 4 when ioctl() is added to NARF's syscall surface.
    #[allow(dead_code)]
    pub(crate) window: IrqSafeSpinLock<WinSize>,

    /// Linux's `tty->ctrl.lock` protects the session and foreground process
    /// group as one state. Keeping both fields under one lock prevents a
    /// concurrent reader from observing half of a `TIOCSCTTY` publication.
    ctrl: IrqSafeSpinLock<PtyControl>,

    /// Allocation index; becomes the `/dev/pts/<N>` name.
    pub(crate) index: u32,

    /// Owner of the `/dev/pts/<N>` slave node, captured from the task that
    /// opened `/dev/ptmx`.
    ///
    /// Linux `fs/devpts/inode.c::devpts_pty_new`:
    /// ```c
    /// inode->i_uid = opts->setuid ? opts->uid : current_fsuid();
    /// inode->i_gid = opts->setgid ? opts->gid : current_fsgid();
    /// ```
    /// Ownership MUST follow the opener: the slave is mode 0620, so a
    /// hardcoded root owner makes every `open("/dev/pts/N")` by an ordinary
    /// desktop user fail with EACCES — which is exactly how a terminal
    /// emulator dies inside a normal (uid != 0) graphical session.
    // LINUX-GAP: devpts `uid=`/`gid=` mount options are still not parsed
    // (see the module header), so the `opts->setuid`/`setgid` branches above
    // have no equivalent here and the caller's credentials always win.
    pub(crate) uid: AtomicU32,
    /// Group of the slave node — `current_fsgid()` at ptmx-open time.
    pub(crate) gid: AtomicU32,

    /// How many `PtySlave` handles are currently open, and whether one ever
    /// was. Together these are the HANGUP condition: a master read may only
    /// report end-of-stream once a slave has been opened and every one of
    /// them has since closed.
    ///
    /// Both halves are needed. Without the counter an empty ring looks like
    /// a hangup and the terminal gets a phantom EOF (the blank `foot`
    /// window). Without `ever_opened` a master read BEFORE the child opens
    /// its slave would report EIO instead of waiting, which is the same bug
    /// with the sign flipped.
    pub(crate) slave_opens: AtomicU32,
    pub(crate) slave_ever_opened: AtomicBool,
    /// The master has closed. Linux `pty_close` sets `TTY_OTHER_CLOSED` on
    /// the peer either way, but the MASTER's close additionally
    /// `tty_vhangup(tty->link)`s the slave — so the two sides end
    /// DIFFERENTLY, and that difference is load-bearing:
    ///
    ///   slave closes  -> master read  = EIO   (`n_tty_wait_for_input`)
    ///   master closes -> slave  read  = 0/EOF (`tty_read`/`tty_hung_up_p`)
    ///
    /// EOF is what makes a shell on a vanished terminal exit; EIO is what
    /// tells a terminal its child is gone. Swapping them wedges one side or
    /// the other.
    pub(crate) master_closed: AtomicBool,

    /// Wave-76: slave-lock flag (TIOCSPTLCK). After ptmx_open the slave
    /// is locked; userspace calls unlockpt() / TIOCSPTLCK(0) before
    /// `open("/dev/pts/N")`. While locked, `DevPts::lookup` returns
    /// `FsError::Io(...)` so the syscall layer surfaces -EIO.
    // Only read by the `linux-compat` lock/unlock paths; always constructed so
    // the field is dead only when that feature is off.
    pub(crate) locked: AtomicBool,

    /// Packet mode (TIOCPKT). When set, every master read is framed with a
    /// leading status byte (`TIOCPKT_DATA` for ordinary output). Linux
    /// `pty.c`: `tty->link->packet`. KDE's KPtyDevice (konsole) enables this
    /// and relies on the framing; without it its read loop desyncs.
    // LINUX-GAP: only the TIOCPKT_DATA framing is produced. The flush/stop/
    // start control packets (TIOCPKT_FLUSHREAD/FLUSHWRITE/STOP/START) are not
    // emitted yet — they would be raised from tcflush/^S/^Q, which NARF's pty
    // does not implement. Consumers that only need output framing (konsole)
    // work; ones that depend on flush notifications lose that signal only.
    pub(crate) packet: AtomicBool,
}

impl core::fmt::Debug for Pty {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pty").field("index", &self.index).finish()
    }
}

/// Pending-read timing for non-canonical mode.
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct ReadTimer {
    /// Absolute monotonic deadline, when a timer is running.
    deadline: Option<u64>,
    /// Readable byte count when the timer was last armed, so the arrival
    /// of a new byte can restart an inter-byte timer.
    seen: usize,
}

impl ReadTimer {
    pub(crate) const fn new() -> Self {
        Self {
            deadline: None,
            seen: 0,
        }
    }
    fn disarm(&mut self) {
        self.deadline = None;
        self.seen = 0;
    }
}

/// What a non-canonical read should do with the bytes currently queued.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum ReadGate {
    /// Hand over what is queued (possibly nothing, which is a legitimate
    /// 0-byte return for a timed-out or polling read).
    Deliver,
    /// Not satisfied yet and no timer has expired — would-block.
    Block,
}

/// VTIME is counted in tenths of a second (`TIME_CHAR` * `HZ / 10`).
const DECISECOND_NS: u64 = 100_000_000;

impl Pty {
    /// A slave was opened at some point and none is open now — the master's
    /// end-of-stream condition. Linux `pty_read`: EIO once the last slave
    /// closes; before any slave opens, the master simply waits.
    pub(crate) fn hung_up(&self) -> bool {
        self.slave_ever_opened.load(Ordering::Acquire)
            && self.slave_opens.load(Ordering::Acquire) == 0
    }

    /// Decide whether a non-canonical read may return, per the VMIN/VTIME
    /// matrix in `n_tty_read` (`drivers/tty/n_tty.c:2216-2281`):
    ///
    /// ```c
    /// minimum = time = 0;
    /// timeout = MAX_SCHEDULE_TIMEOUT;
    /// if (!ldata->icanon) {
    ///         minimum = MIN_CHAR(tty);
    ///         if (minimum)
    ///                 time = (HZ / 10) * TIME_CHAR(tty);
    ///         else {
    ///                 timeout = (HZ / 10) * TIME_CHAR(tty);
    ///                 minimum = 1;
    ///         }
    /// }
    /// ...
    /// if (kb - kbuf >= minimum) break;
    /// if (time) timeout = time;      /* after the first byte */
    /// ```
    ///
    /// which yields the four POSIX cases:
    ///
    /// * **MIN>0, TIME==0** — block until MIN bytes. `time` is 0, so the
    ///   timeout stays infinite.
    /// * **MIN>0, TIME>0** — TIME is an INTER-BYTE timer. The first wait is
    ///   still infinite (`timeout` only becomes `time` after a byte has
    ///   been copied), and each further byte restarts it.
    /// * **MIN==0, TIME>0** — TIME is an overall read timer started when
    ///   the read begins; return as soon as any byte arrives, or empty when
    ///   it expires.
    /// * **MIN==0, TIME==0** — poll: return immediately with whatever is
    ///   queued, including nothing.
    ///
    /// Canonical mode never reaches here: `minimum` and `time` are left at
    /// zero for it, so `c_cc[VMIN]`/`c_cc[VTIME]` are simply not consulted.
    pub(crate) fn noncanon_read_gate(&self, t: &Termios, avail: usize) -> ReadGate {
        let (vmin, vtime) = t.vmin_vtime();
        // `if (minimum) ... else { timeout = ...; minimum = 1; }`
        let minimum = if vmin == 0 { 1usize } else { vmin as usize };
        let mut timer = self.read_timer.lock();

        if avail >= minimum {
            timer.disarm();
            return ReadGate::Deliver;
        }
        // MIN==0, TIME==0: a pure polling read never waits.
        if vmin == 0 && vtime == 0 {
            timer.disarm();
            return ReadGate::Deliver;
        }
        // MIN>0, TIME==0: no timer at all, wait for the full count.
        if vmin > 0 && vtime == 0 {
            timer.disarm();
            return ReadGate::Block;
        }

        let now = narf_time::monotonic_ns();
        let span = u64::from(vtime) * DECISECOND_NS;

        if vmin == 0 {
            // Overall read timer, armed on the first attempt of this read.
            let deadline = *timer.deadline.get_or_insert(now.saturating_add(span));
            if now >= deadline {
                timer.disarm();
                return ReadGate::Deliver; // expired: hand over what there is
            }
            return ReadGate::Block;
        }

        // MIN>0, TIME>0: the inter-byte timer does not run until at least
        // one byte has arrived — Linux's first wait is still infinite.
        if avail == 0 {
            timer.disarm();
            return ReadGate::Block;
        }
        if timer.deadline.is_none() || avail > timer.seen {
            // First byte, or another one arrived: (re)start the gap timer.
            timer.deadline = Some(now.saturating_add(span));
            timer.seen = avail;
            return ReadGate::Block;
        }
        if now >= timer.deadline.unwrap_or(now) {
            timer.disarm();
            return ReadGate::Deliver;
        }
        ReadGate::Block
    }

    /// `TIOCGPGRP`: report the foreground process group.
    ///
    /// `drivers/tty/tty_jobctrl.c:474` — "Return the pgrp of the current
    /// tty" but only for the caller's OWN controlling terminal:
    ///
    /// ```c
    /// if (tty == real_tty && current->signal->tty != real_tty)
    ///         return -ENOTTY;
    /// ```
    ///
    /// Reporting it unconditionally leaks another session's job-control
    /// state to any process that can open the device.
    fn get_fg_pgrp(&self) -> Result<u64, FsError> {
        let ctrl = *self.ctrl.lock();
        if let Some((caller_sid, _)) = jobctl_query(0) {
            if ctrl.sid != 0 && ctrl.sid != caller_sid {
                // ENOTTY — `Unsupported` is the ioctl path's ENOTTY.
                return Err(FsError::Unsupported);
            }
        }
        Ok(ctrl.fg_pgrp)
    }

    /// `TIOCSPGRP`: set the foreground process group.
    ///
    /// `tty_jobctrl.c:497-521` rejects in this order, and the order is the
    /// ABI: EINVAL for a negative pgrp, ENOTTY when this is not the
    /// caller's controlling tty or the sessions differ, ESRCH when no such
    /// process group exists, EPERM when it exists in another session.
    /// Storing whatever arrives lets any process hand the terminal to a
    /// group in a different session.
    fn set_fg_pgrp(&self, pgrp: i32) -> Result<u64, FsError> {
        if pgrp < 0 {
            return Err(FsError::InvalidData);
        }
        let pgrp = pgrp as u64;
        let ctrl_sid = self.ctrl.lock().sid;
        if let Some((caller_sid, pgrp_sid)) = jobctl_query(pgrp) {
            if ctrl_sid != 0 && ctrl_sid != caller_sid {
                // ENOTTY — `Unsupported` is the ioctl path's ENOTTY.
                return Err(FsError::Unsupported);
            }
            if pgrp_sid == 0 {
                return Err(FsError::NoSuchProcess); // ESRCH
            }
            if pgrp_sid != caller_sid {
                return Err(FsError::OperationNotPermitted); // EPERM
            }
        }
        self.ctrl.lock().fg_pgrp = pgrp;
        Ok(0)
    }

    /// Apply a `TCSETS`-family termios, honouring the locked mask.
    ///
    /// `tty_ioctl.c`:
    ///
    /// ```c
    /// #define NOSET_MASK(x, y, z) (x = ((x) & ~(z)) | ((y) & (z)))
    ///     NOSET_MASK(termios->c_iflag, old->c_iflag, locked->c_iflag);
    ///     ...
    ///     termios->c_cc[i] = locked->c_cc[i] ? old->c_cc[i] : termios->c_cc[i];
    /// ```
    ///
    /// A bit set in the lock keeps the OLD value, so TIOCSLCKTRMIOS can pin
    /// individual flags — which is the point: a privileged process can stop
    /// a setuid program from, say, clearing ECHO on a shared terminal.
    pub(crate) fn set_termios_locked(&self, mut raw: [u8; TERMIOS_WIRE_LEN]) {
        let locked = *self.locked_termios.lock();
        let mut cur = self.termios.lock();
        // c_iflag/c_oflag/c_cflag/c_lflag: four u32s at offsets 0, 4, 8, 12.
        for off in [0usize, 4, 8, 12] {
            let l = u32::from_ne_bytes(locked.raw[off..off + 4].try_into().unwrap());
            if l == 0 {
                continue;
            }
            let old = u32::from_ne_bytes(cur.raw[off..off + 4].try_into().unwrap());
            let new = u32::from_ne_bytes(raw[off..off + 4].try_into().unwrap());
            let merged = (new & !l) | (old & l);
            raw[off..off + 4].copy_from_slice(&merged.to_ne_bytes());
        }
        // c_line at 16: a non-zero lock keeps the old value.
        if locked.raw[16] != 0 {
            raw[16] = cur.raw[16];
        }
        // c_cc[] from 17: per-entry, a non-zero lock keeps the old value.
        // NCCS is 19 on the asm-generic layout.
        let cc = 17..TERMIOS_WIRE_LEN.min(17 + 19);
        for ((slot, &lock), &old) in raw[cc.clone()]
            .iter_mut()
            .zip(locked.raw[cc.clone()].iter())
            .zip(cur.raw[cc].iter())
        {
            if lock != 0 {
                *slot = old;
            }
        }
        cur.raw = raw;
    }

    /// `TIOCSTI`: push one byte back into this tty's input queue.
    ///
    /// `tty_io.c::tiocsti` (2274-2291):
    ///
    /// ```c
    /// if (!tty_legacy_tiocsti && !capable(CAP_SYS_ADMIN))
    ///         return -EIO;
    /// if ((current->signal->tty != tty) && !capable(CAP_SYS_ADMIN))
    ///         return -EPERM;
    /// ```
    ///
    /// `CONFIG_LEGACY_TIOCSTI` defaults to y (`drivers/tty/Kconfig:149`), so
    /// the first test passes and injecting into YOUR OWN controlling
    /// terminal is unprivileged; injecting into somebody else's is what
    /// needs CAP_SYS_ADMIN, because that is the terminal-hijacking case.
    pub(crate) fn insert_input_byte(&self, b: u8) -> Result<u64, FsError> {
        let own_tty = match jobctl_query(0) {
            Some((caller_sid, _)) => {
                let sid = self.ctrl.lock().sid;
                sid != 0 && sid == caller_sid
            }
            // No session tables (early boot, in-kernel tests): treat it as
            // the caller's own terminal rather than inventing a denial.
            None => true,
        };
        if !own_tty && !caller_capable(CAP_SYS_ADMIN) {
            return Err(FsError::OperationNotPermitted); // EPERM
        }
        let t = *self.termios.lock();
        let mut sigs: alloc::vec::Vec<u32> = alloc::vec::Vec::new();
        {
            let mut state = self.input.lock();
            crate::ntty::feed_byte(
                &mut state,
                &t,
                b,
                &mut |c| self.slave_tx_to_master.push(&[c]),
                &mut |bb| match signal_for_cc(&t, bb) {
                    Some(sig) => {
                        sigs.push(sig);
                        true
                    }
                    None => false,
                },
            );
        }
        if !sigs.is_empty() {
            let pgrp = self.ctrl.lock().fg_pgrp;
            for sig in sigs {
                pty_deliver_signal(pgrp, sig);
            }
        }
        Ok(0)
    }

    /// `TIOCVHANGUP`: force a hangup on this terminal.
    ///
    /// `tty_io.c:2729` gates it on CAP_SYS_ADMIN. The effect is what the
    /// master closing already produces — readers see EOF and pollers HUP —
    /// so it reuses that path rather than inventing a second one.
    fn vhangup(&self) -> Result<u64, FsError> {
        if !caller_capable(CAP_SYS_ADMIN) {
            return Err(FsError::OperationNotPermitted); // EPERM
        }
        self.master_closed.store(true, Ordering::Release);
        self.slave_opens.store(0, Ordering::Release);
        self.slave_ever_opened.store(true, Ordering::Release);
        Ok(0)
    }

    /// `TCFLSH` (`tcflush`): discard queued input and/or output.
    ///
    /// `drivers/tty/tty_ioctl.c::__tty_perform_flush` — TCIFLUSH(0) drops
    /// the input queue, TCOFLUSH(1) the output queue, TCIOFLUSH(2) both;
    /// anything else is -EINVAL.
    fn flush_queues(&self, arg: usize) -> Result<u64, FsError> {
        const TCIFLUSH: usize = 0;
        const TCOFLUSH: usize = 1;
        const TCIOFLUSH: usize = 2;
        match arg {
            TCIFLUSH | TCIOFLUSH => {
                let mut st = self.input.lock();
                st.ready.clear();
                st.line.clear();
                st.eof = false;
                if arg == TCIOFLUSH {
                    self.slave_tx_to_master.clear();
                }
                Ok(0)
            }
            TCOFLUSH => {
                self.slave_tx_to_master.clear();
                Ok(0)
            }
            _ => Err(FsError::InvalidData),
        }
    }

    /// `TCXONC` (`tcflow`): suspend or resume the flow the IXON control
    /// characters drive.
    ///
    /// `tty_ioctl.c` TCXONC: TCOOFF(0) stops output, TCOON(1) restarts it,
    /// TCIOFF(2) transmits a STOP char and TCION(3) a START char; anything
    /// else is -EINVAL.
    fn flow_control(&self, arg: usize) -> Result<u64, FsError> {
        const TCOOFF: usize = 0;
        const TCOON: usize = 1;
        const TCIOFF: usize = 2;
        const TCION: usize = 3;
        match arg {
            TCOOFF => {
                self.input.lock().stopped = true;
                Ok(0)
            }
            TCOON => {
                self.input.lock().stopped = false;
                Ok(0)
            }
            // TCIOFF/TCION transmit the flow characters toward the peer.
            // With no physical line the observable effect is the same flag
            // the received character would have set.
            TCIOFF => {
                self.input.lock().stopped = true;
                Ok(0)
            }
            TCION => {
                self.input.lock().stopped = false;
                Ok(0)
            }
            _ => Err(FsError::InvalidData),
        }
    }

    /// Apply a new window size, signalling the foreground process group
    /// when it actually changed.
    ///
    /// `tty_do_resize` (`drivers/tty/tty_io.c:2324`):
    ///
    /// ```c
    /// if (!memcmp(ws, &tty->winsize, sizeof(*ws)))
    ///         return 0;
    /// ...
    /// kill_pgrp(pgrp, SIGWINCH, 1);
    /// tty->winsize = *ws;
    /// ```
    ///
    /// Both halves matter. Without the signal a running program never
    /// learns its geometry changed, so a resized window leaves vi, less and
    /// every other full-screen program drawing at the old size. And the
    /// no-change early return is what stops a terminal that re-sends its
    /// size on every repaint from storming SIGWINCH at the foreground job.
    pub(crate) fn resize(&self, ws: WinSize) {
        {
            let mut w = self.window.lock();
            if *w == ws {
                return;
            }
            *w = ws;
        }
        let pgrp = self.ctrl.lock().fg_pgrp;
        if pgrp != 0 {
            pty_deliver_signal(pgrp, SIGWINCH);
        }
    }

    fn acquire_controlling_tty(&self, arg: usize, readable: bool) -> Result<(), FsError> {
        // Linux maps a PTY master to its slave-side `real_tty` before job
        // control ioctls, so both endpoints share this transaction.
        let _txn = TIOCSCTTY_TXN.lock();
        let hook = (*CTTY_HOOK.lock()).ok_or(FsError::Unsupported)?;
        let tty_sid = self.ctrl.lock().sid;
        let (sid, pgid) = hook(self.index, tty_sid, arg, readable)?;
        *self.ctrl.lock() = PtyControl { sid, fg_pgrp: pgid };
        Ok(())
    }

    fn new(index: u32, uid: u32, gid: u32) -> Self {
        Self {
            input: IrqSafeSpinLock::new(crate::ntty::LineState::new()),
            output: IrqSafeSpinLock::new(crate::ntty::OutputState::new()),
            read_timer: IrqSafeSpinLock::new(ReadTimer::new()),
            exclusive: AtomicBool::new(false),
            // All-zero: nothing is locked until TIOCSLCKTRMIOS says so.
            locked_termios: IrqSafeSpinLock::new(Termios {
                raw: [0u8; TERMIOS_WIRE_LEN],
            }),
            slave_tx_to_master: ByteRing::new(),
            termios: IrqSafeSpinLock::new(Termios::default()),
            window: IrqSafeSpinLock::new(WinSize::default()),
            ctrl: IrqSafeSpinLock::new(PtyControl::default()),
            index,
            uid: AtomicU32::new(uid),
            gid: AtomicU32::new(gid),
            // Linux: ptmx_open() starts with the slave locked. unlockpt()
            // clears via TIOCSPTLCK(0) before the slave can be opened.
            locked: AtomicBool::new(true),
            slave_opens: AtomicU32::new(0),
            slave_ever_opened: AtomicBool::new(false),
            master_closed: AtomicBool::new(false),
            packet: AtomicBool::new(false),
        }
    }
}

// ── PTY table ─────────────────────────────────────────────────────────────────

/// Global table mapping PTY index → shared `Arc<Pty>`.
///
/// Inserted on `ptmx_open()`; removed when the master drops (which happens
/// after the slave has also been dropped, since the slave holds its own
/// `Arc<Pty>`).  We use a `Vec` because the table is expected to hold O(10)
/// entries at most; a `BTreeMap` would require `narf-alloc` features not yet
/// pulled in here.
static PTY_TABLE: IrqSafeSpinLock<Vec<(u32, Arc<Pty>)>> = IrqSafeSpinLock::new(Vec::new());

static NEXT_PTY_INDEX: AtomicU32 = AtomicU32::new(0);

/// `fn() -> (fsuid, fsgid)` for the calling task, installed by userspace.
///
/// Stored as a raw `usize` so this crate needs no dependency on the
/// userspace credential table (mirrors `PTY_SIGNAL_HOOK` above). Until it
/// is installed — in-kernel tests and very early boot — PTYs are opened on
/// behalf of root, matching the credentials those callers actually run with.
static PTY_CREDS_HOOK: AtomicUsize = AtomicUsize::new(0);

/// `fn(pgrp) -> (caller's session, that pgrp's session or 0 if no such
/// pgrp)`, installed by userspace.
///
/// Job-control ioctls need both answers to reproduce Linux's errno
/// ordering, and neither is knowable from this crate — process groups and
/// sessions live in the userspace tables.
type JobctlHook = fn(u64) -> (u64, u64);

static JOBCTL_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install the session / process-group accessor used by the job-control
/// ioctls.
pub fn install_pty_jobctl_hook(hook: JobctlHook) {
    JOBCTL_HOOK.store(hook as usize, Ordering::Release);
}

/// `(caller session, pgrp's session)`; `None` when no hook is installed,
/// in which case the job-control checks are skipped rather than guessed at
/// (early boot and in-kernel tests have no session tables).
fn jobctl_query(pgrp: u64) -> Option<(u64, u64)> {
    let raw = JOBCTL_HOOK.load(Ordering::Acquire);
    if raw == 0 {
        return None;
    }
    // SAFETY: `raw` was stored by `install_pty_jobctl_hook` from a
    // `JobctlHook`, the only writer of this slot, and function pointers are
    // never unmapped.
    let hook: JobctlHook = unsafe { core::mem::transmute(raw) };
    Some(hook(pgrp))
}

/// `fn(capability) -> bool` for the calling task, installed by userspace.
type CapHook = fn(u32) -> bool;

static CAP_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install the capability check used by the privileged tty ioctls.
pub fn install_pty_cap_hook(hook: CapHook) {
    CAP_HOOK.store(hook as usize, Ordering::Release);
}

/// Whether the caller holds `cap`. With no hook installed — early boot and
/// in-kernel tests — the answer is "yes", matching the fact that those
/// callers really do run as root.
fn caller_capable(cap: u32) -> bool {
    let raw = CAP_HOOK.load(Ordering::Acquire);
    if raw == 0 {
        return true;
    }
    // SAFETY: `raw` was stored by `install_pty_cap_hook` from a `CapHook`,
    // the only writer of this slot, and function pointers are never
    // unmapped.
    let hook: CapHook = unsafe { core::mem::transmute(raw) };
    hook(cap)
}

/// Install the current-credentials accessor used to own new PTY slaves.
pub fn install_pty_creds_hook(hook: fn() -> (u32, u32)) {
    PTY_CREDS_HOOK.store(hook as usize, Ordering::Release);
}

/// Credentials to stamp on a new slave node; `(0, 0)` when no hook is set.
fn current_pty_creds() -> (u32, u32) {
    let raw = PTY_CREDS_HOOK.load(Ordering::Acquire);
    if raw == 0 {
        return (0, 0);
    }
    // SAFETY: `raw` was stored by `install_pty_creds_hook` from a
    // `fn() -> (u32, u32)`, the only writer of this slot, and function
    // pointers are never unmapped.
    let hook: fn() -> (u32, u32) = unsafe { core::mem::transmute(raw) };
    hook()
}

/// Allocate a fresh PTY index, create the shared `Pty`, and register it.
/// Returns `(index, Arc<Pty>)`.
///
/// Called in the syscall context of `open("/dev/ptmx")`, so the credentials
/// sampled here are the opener's — which is precisely what Linux stamps on
/// the slave inode.
pub fn ptmx_open() -> (u32, Arc<Pty>) {
    let index = NEXT_PTY_INDEX.fetch_add(1, Ordering::Relaxed);
    let (uid, gid) = current_pty_creds();
    let pty = Arc::new(Pty::new(index, uid, gid));
    PTY_TABLE.lock().push((index, Arc::clone(&pty)));
    (index, pty)
}

/// Remove the PTY from the table (called when the master is dropped).
pub fn ptmx_close(index: u32) {
    let mut tbl = PTY_TABLE.lock();
    tbl.retain(|(i, _)| *i != index);
}

/// `fn(pgrp: u64, signum: u32) -> bool` installed by userspace to deliver
/// a terminal-generated signal (^C/^\/^Z) to a PTY's foreground process
/// group. Stored as a raw `usize` so this crate needs no dep on
/// userspace's signal table (mirrors the console's signal hook). Returns
/// true if at least one task was signalled.
static PTY_SIGNAL_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install the PTY foreground-pgrp signal hook. See `PTY_SIGNAL_HOOK`.
pub fn install_pty_signal_hook(hook: fn(u64, u32) -> bool) {
    PTY_SIGNAL_HOOK.store(hook as usize, Ordering::Release);
}

/// Map an input byte to the signal its `c_cc` entry generates under ISIG:
/// VINTR→SIGINT, VQUIT→SIGQUIT, VSUSP→SIGTSTP. `None` for non-signal bytes
/// (and for an unset `c_cc[]` slot, which is 0).
fn signal_for_cc(t: &Termios, b: u8) -> Option<u32> {
    if b == 0 {
        None
    } else if b == t.cc(0) {
        Some(2) // SIGINT
    } else if b == t.cc(1) {
        Some(3) // SIGQUIT
    } else if b == t.cc(10) {
        Some(20) // SIGTSTP
    } else {
        None
    }
}

/// Deliver `signum` to PTY foreground process group `pgrp` via the
/// installed hook. No-op (false) when no hook is installed or `pgrp` is 0.
fn pty_deliver_signal(pgrp: u64, signum: u32) -> bool {
    if pgrp == 0 {
        return false;
    }
    let raw = PTY_SIGNAL_HOOK.load(Ordering::Acquire);
    if raw == 0 {
        return false;
    }
    // SAFETY: `raw` was stored by `install_pty_signal_hook` from a
    // `fn(u64, u32) -> bool`; transmuting the identical signature back is
    // sound (fn pointers and usize share size/alignment).
    let hook: fn(u64, u32) -> bool = unsafe { core::mem::transmute(raw) };
    hook(pgrp, signum)
}

/// Look up a PTY by its pts index.  Returns `None` if not found.
pub fn pts_lookup(index: u32) -> Option<Arc<Pty>> {
    PTY_TABLE
        .lock()
        .iter()
        .find(|(i, _)| *i == index)
        .map(|(_, p)| Arc::clone(p))
}

/// Snapshot the current list of active PTY indices.
pub fn pts_indices() -> Vec<u32> {
    PTY_TABLE.lock().iter().map(|(i, _)| *i).collect()
}

/// Foreground process group (TASK-space) of PTY `index`, or 0 if the index is
/// unknown or no fg pgrp has been installed. Backs `/proc/<pid>/stat`'s tpgid
/// for a process whose controlling terminal is `/dev/pts/<index>`.
pub fn pty_fg_pgrp(index: u32) -> u64 {
    pts_lookup(index)
        .map(|p| p.ctrl.lock().fg_pgrp)
        .unwrap_or(0)
}

/// Wave-76: open a fresh slave by master index. Used by the syscall
/// layer to satisfy `TIOCGPTPEER` (musl/glibc prefer this over
/// `ptsname()+open()`). Returns `None` if the master is gone, or
/// `Some(Err(()))` if the slave is still locked.
pub fn pts_open_peer(index: u32) -> Option<Result<Arc<PtySlave>, ()>> {
    let pty = pts_lookup(index)?;
    if pty.locked.load(Ordering::Acquire) {
        return Some(Err(()));
    }
    // Exclusive mode refuses a second opener without CAP_SYS_ADMIN, the
    // TIOCGPTPEER equivalent of `tty_open`'s EBUSY.
    if pty.exclusive.load(Ordering::Acquire) && !caller_capable(CAP_SYS_ADMIN) {
        return Some(Err(()));
    }
    Some(Ok(Arc::new(PtySlave::new(pty))))
}

// ── User-pointer helpers ──────────────────────────────────────────────────────
//
// Raw memcpy across user/kernel — mirrors `drivers/gpu/src/drm_ioctl_bridge`
// `copy_in`/`copy_out`. The SMAP/STAC bracket lives in the syscall trap
// layer; this layer just sees an opaque usize and does a pointer load/store.

// SMAP gotcha — every load/store to user memory below has to sit
// inside a `with_user_access` window. A bare `mov` from a user-only
// PTE at CPL=0 faults with #PF (CR2 = user vaddr) once CR4.SMAP=1,
// which is the case on every CPU NARF boots. See
// `[[project_user_cstr_page_safety]]` for the broader pattern.

#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn read_user_i32(uptr: usize) -> Result<i32, FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: caller guarantees uptr is a valid user-space pointer; with_user_access
    // temporarily enables SMAP access and read_unaligned handles any alignment.
    // SAFETY: Valid memory or trusted environment
    let v = unsafe {
        narf_arch::x86_64::smap::with_user_access(|| core::ptr::read_unaligned(uptr as *const i32))
    };
    Ok(v)
}

/// Read the single `char` a `TIOCSTI` argument points at.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn read_user_u8(uptr: usize) -> Result<u8, FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: caller guarantees uptr is a valid user-space pointer; the
    // SMAP window is what makes a CPL=0 load from a user-only PTE legal.
    // SAFETY: Valid memory or trusted environment
    let v = unsafe {
        narf_arch::x86_64::smap::with_user_access(|| core::ptr::read_unaligned(uptr as *const u8))
    };
    Ok(v)
}

/// Read the single `char` a `TIOCSTI` argument points at.
#[cfg(not(target_arch = "x86_64"))]
pub(crate) unsafe fn read_user_u8(uptr: usize) -> Result<u8, FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: the caller guarantees `uptr` is a valid user-space pointer
    // and it is non-null per the check above.
    // SAFETY: Valid memory or trusted environment
    Ok(unsafe { core::ptr::read_unaligned(uptr as *const u8) })
}

// Not linux-compat-gated: /dev/random's RND* ioctls (always present) write an
// int back to userspace through this helper.
#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
pub(crate) unsafe fn write_user_i32(uptr: usize, v: i32) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: caller guarantees uptr is a valid user-space pointer; with_user_access
    // enables SMAP and write_unaligned handles any alignment.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::write_unaligned(uptr as *mut i32, v);
        });
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
unsafe fn write_user_u32(uptr: usize, v: u32) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: caller guarantees uptr is a valid user-space pointer; with_user_access
    // enables SMAP and write_unaligned handles any alignment.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::write_unaligned(uptr as *mut u32, v);
        });
    }
    Ok(())
}

// ── VT ioctl structs: vt_stat (6 bytes) / vt_mode (8 bytes) ──────────
// `struct vt_stat { unsigned short v_active, v_signal, v_state; }` and
// `struct vt_mode { char mode, waitv; short relsig, acqsig, frsig; }`
// (`include/uapi/linux/vt.h`). Copied byte-for-byte through the SMAP window so
// the on-wire layout is exact regardless of pointer alignment.

#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn write_user_vt_stat(
    uptr: usize,
    active: u16,
    signal: u16,
    state: u16,
) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    let mut b = [0u8; 6];
    b[0..2].copy_from_slice(&active.to_le_bytes());
    b[2..4].copy_from_slice(&signal.to_le_bytes());
    b[4..6].copy_from_slice(&state.to_le_bytes());
    // SAFETY: `uptr` is the validated user `struct vt_stat *`; with_user_access
    // opens the SMAP window for the 6-byte copy.
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::copy_nonoverlapping(b.as_ptr(), uptr as *mut u8, 6);
        });
    }
    Ok(())
}

/// Read a `struct vt_mode` → `(mode, waitv, relsig, acqsig, frsig)`.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn read_user_vt_mode(uptr: usize) -> Result<(u8, u8, i16, i16, i16), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    let mut b = [0u8; 8];
    // SAFETY: `uptr` is the validated user `struct vt_mode *`.
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::copy_nonoverlapping(uptr as *const u8, b.as_mut_ptr(), 8);
        });
    }
    Ok((
        b[0],
        b[1],
        i16::from_le_bytes([b[2], b[3]]),
        i16::from_le_bytes([b[4], b[5]]),
        i16::from_le_bytes([b[6], b[7]]),
    ))
}

#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn write_user_vt_mode(
    uptr: usize,
    mode: u8,
    waitv: u8,
    relsig: i16,
    acqsig: i16,
    frsig: i16,
) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    let mut b = [0u8; 8];
    b[0] = mode;
    b[1] = waitv;
    b[2..4].copy_from_slice(&relsig.to_le_bytes());
    b[4..6].copy_from_slice(&acqsig.to_le_bytes());
    b[6..8].copy_from_slice(&frsig.to_le_bytes());
    // SAFETY: `uptr` is the validated user `struct vt_mode *`.
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::copy_nonoverlapping(b.as_ptr(), uptr as *mut u8, 8);
        });
    }
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) unsafe fn write_user_vt_stat(
    uptr: usize,
    active: u16,
    signal: u16,
    state: u16,
) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    let mut b = [0u8; 6];
    b[0..2].copy_from_slice(&active.to_le_bytes());
    b[2..4].copy_from_slice(&signal.to_le_bytes());
    b[4..6].copy_from_slice(&state.to_le_bytes());
    // SAFETY: caller guarantees `uptr` is a valid 6-byte user buffer.
    unsafe {
        core::ptr::copy_nonoverlapping(b.as_ptr(), uptr as *mut u8, 6);
    }
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) unsafe fn read_user_vt_mode(uptr: usize) -> Result<(u8, u8, i16, i16, i16), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    let mut b = [0u8; 8];
    // SAFETY: caller guarantees `uptr` is a valid 8-byte user buffer.
    unsafe {
        core::ptr::copy_nonoverlapping(uptr as *const u8, b.as_mut_ptr(), 8);
    }
    Ok((
        b[0],
        b[1],
        i16::from_le_bytes([b[2], b[3]]),
        i16::from_le_bytes([b[4], b[5]]),
        i16::from_le_bytes([b[6], b[7]]),
    ))
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) unsafe fn write_user_vt_mode(
    uptr: usize,
    mode: u8,
    waitv: u8,
    relsig: i16,
    acqsig: i16,
    frsig: i16,
) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    let mut b = [0u8; 8];
    b[0] = mode;
    b[1] = waitv;
    b[2..4].copy_from_slice(&relsig.to_le_bytes());
    b[4..6].copy_from_slice(&acqsig.to_le_bytes());
    b[6..8].copy_from_slice(&frsig.to_le_bytes());
    // SAFETY: caller guarantees `uptr` is a valid 8-byte user buffer.
    unsafe {
        core::ptr::copy_nonoverlapping(b.as_ptr(), uptr as *mut u8, 8);
    }
    Ok(())
}

// Non-x86_64 fallback — no SMAP, just raw pointer ops (aarch64 has
// its own MTE/PAN dance but the FS layer here is still x86_64-only
// in practice).
#[cfg(not(target_arch = "x86_64"))]
pub(crate) unsafe fn read_user_i32(uptr: usize) -> Result<i32, FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: the caller guarantees `uptr` is a valid user-space pointer
    // (its fn contract); it is non-null per the check above, and
    // `read_unaligned` reads exactly 4 bytes regardless of alignment.
    // SAFETY: Valid memory or trusted environment
    Ok(unsafe { core::ptr::read_unaligned(uptr as *const i32) })
}

#[cfg(not(target_arch = "x86_64"))]
#[allow(dead_code)]
pub(crate) unsafe fn write_user_i32(uptr: usize, v: i32) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: the caller guarantees `uptr` is a valid user-space pointer
    // (its fn contract); it is non-null per the check above, and
    // `write_unaligned` writes exactly 4 bytes regardless of alignment.
    // SAFETY: Valid memory or trusted environment
    unsafe { core::ptr::write_unaligned(uptr as *mut i32, v) };
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn write_user_u32(uptr: usize, v: u32) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: the caller guarantees `uptr` is a valid user-space pointer
    // (its fn contract); it is non-null per the check above, and
    // `write_unaligned` writes exactly 4 bytes regardless of alignment.
    // SAFETY: Valid memory or trusted environment
    unsafe { core::ptr::write_unaligned(uptr as *mut u32, v) };
    Ok(())
}

/// POSIX `struct winsize` — mirrors `userspace::fd::Winsize` so the FS
/// crate can satisfy `TIOCGWINSZ`/`TIOCSWINSZ` without depending on it.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct WireWinsize {
    pub(crate) ws_row: u16,
    pub(crate) ws_col: u16,
    pub(crate) ws_xpixel: u16,
    pub(crate) ws_ypixel: u16,
}

#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn read_user_winsize(uptr: usize) -> Result<WireWinsize, FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: caller guarantees uptr is a valid user-space pointer; with_user_access
    // enables SMAP and read_unaligned handles any alignment.
    // SAFETY: Valid memory or trusted environment
    let v = unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::read_unaligned(uptr as *const WireWinsize)
        })
    };
    Ok(v)
}

#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn write_user_winsize(uptr: usize, v: WireWinsize) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: caller guarantees uptr is a valid user-space pointer; with_user_access
    // enables SMAP and write_unaligned handles any alignment.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::write_unaligned(uptr as *mut WireWinsize, v);
        });
    }
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) unsafe fn read_user_winsize(uptr: usize) -> Result<WireWinsize, FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: the caller guarantees `uptr` is a valid user-space pointer
    // (its fn contract); it is non-null per the check above, and
    // `read_unaligned` reads exactly one `WireWinsize` regardless of
    // alignment.
    // SAFETY: Valid memory or trusted environment
    Ok(unsafe { core::ptr::read_unaligned(uptr as *const WireWinsize) })
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) unsafe fn write_user_winsize(uptr: usize, v: WireWinsize) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: the caller guarantees `uptr` is a valid user-space pointer
    // (its fn contract); it is non-null per the check above, and
    // `write_unaligned` writes exactly one `WireWinsize` regardless of
    // alignment.
    // SAFETY: Valid memory or trusted environment
    unsafe { core::ptr::write_unaligned(uptr as *mut WireWinsize, v) };
    Ok(())
}

/// Copy a pty's `struct termios` wire image (60 bytes) out to user memory
/// for TCGETS. Mirrors what the program last set via TCSETS, so
/// tcgetattr(tcsetattr(x)) round-trips.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn write_user_termios(
    uptr: usize,
    src: &[u8; TERMIOS_WIRE_LEN],
) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // Kernel ABI: write only the first 36 bytes (kernel struct termios).
    let mut k = [0u8; KERNEL_TERMIOS_LEN];
    k.copy_from_slice(&src[..KERNEL_TERMIOS_LEN]);
    // SAFETY: caller guarantees uptr is a valid user pointer; with_user_access
    // brackets the access with SMAP and write_unaligned emits inline stores
    // (a copy_nonoverlapping memcpy libcall escapes the STAC/CLAC window).
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::write_unaligned(uptr as *mut [u8; KERNEL_TERMIOS_LEN], k);
        });
    }
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) unsafe fn write_user_termios(
    uptr: usize,
    src: &[u8; TERMIOS_WIRE_LEN],
) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // Kernel ABI: write only the first 36 bytes (kernel struct termios).
    // SAFETY: caller guarantees uptr is a valid user pointer; src and uptr
    // are non-overlapping and 36 <= 60.
    unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), uptr as *mut u8, KERNEL_TERMIOS_LEN) };
    Ok(())
}

/// Read a `struct termios` wire image (60 bytes) in from user memory for
/// TCSETS.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn read_user_termios(uptr: usize) -> Result<[u8; TERMIOS_WIRE_LEN], FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // Kernel ABI: read only the first 36 bytes (kernel struct termios),
    // zero-extended into the 60-byte internal image.
    // SAFETY: caller guarantees uptr is a valid user pointer; with_user_access
    // brackets the access with SMAP and read_unaligned emits inline loads (a
    // copy_nonoverlapping memcpy libcall escapes the STAC/CLAC window and
    // faults supervisor-reading the user page).
    let k = unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::read_unaligned(uptr as *const [u8; KERNEL_TERMIOS_LEN])
        })
    };
    let mut out = [0u8; TERMIOS_WIRE_LEN];
    out[..KERNEL_TERMIOS_LEN].copy_from_slice(&k);
    Ok(out)
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) unsafe fn read_user_termios(uptr: usize) -> Result<[u8; TERMIOS_WIRE_LEN], FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // Kernel ABI: read only the first 36 bytes (kernel struct termios).
    let mut out = [0u8; TERMIOS_WIRE_LEN];
    // SAFETY: caller guarantees uptr is a valid user pointer; out and uptr
    // are non-overlapping and 36 <= 60.
    unsafe {
        core::ptr::copy_nonoverlapping(uptr as *const u8, out.as_mut_ptr(), KERNEL_TERMIOS_LEN)
    };
    Ok(out)
}

/// TCGETS2: write a 44-byte `struct termios2` — the 36-byte kernel `termios`
/// (first 36 bytes of our internal image) plus `c_ispeed`/`c_ospeed`.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn write_user_termios2(
    uptr: usize,
    src: &[u8; TERMIOS_WIRE_LEN],
) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    let mut k = [0u8; KERNEL_TERMIOS2_LEN];
    k[..KERNEL_TERMIOS_LEN].copy_from_slice(&src[..KERNEL_TERMIOS_LEN]);
    k[36..40].copy_from_slice(&TERMIOS2_BAUD.to_ne_bytes());
    k[40..44].copy_from_slice(&TERMIOS2_BAUD.to_ne_bytes());
    // SAFETY: caller guarantees uptr is a valid user pointer; with_user_access
    // brackets SMAP and write_unaligned emits inline stores.
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::write_unaligned(uptr as *mut [u8; KERNEL_TERMIOS2_LEN], k);
        });
    }
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) unsafe fn write_user_termios2(
    uptr: usize,
    src: &[u8; TERMIOS_WIRE_LEN],
) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    let mut k = [0u8; KERNEL_TERMIOS2_LEN];
    k[..KERNEL_TERMIOS_LEN].copy_from_slice(&src[..KERNEL_TERMIOS_LEN]);
    k[36..40].copy_from_slice(&TERMIOS2_BAUD.to_ne_bytes());
    k[40..44].copy_from_slice(&TERMIOS2_BAUD.to_ne_bytes());
    // SAFETY: caller guarantees uptr is a valid user pointer; non-overlapping.
    unsafe { core::ptr::copy_nonoverlapping(k.as_ptr(), uptr as *mut u8, KERNEL_TERMIOS2_LEN) };
    Ok(())
}

/// TCSETS2: read a 44-byte `struct termios2`; keep the 36-byte `termios` part
/// (the `c_ispeed`/`c_ospeed` speeds are meaningless for a virtual console).
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn read_user_termios2(uptr: usize) -> Result<[u8; TERMIOS_WIRE_LEN], FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: caller guarantees uptr is a valid user pointer; with_user_access
    // brackets SMAP and read_unaligned emits inline loads.
    let k = unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::read_unaligned(uptr as *const [u8; KERNEL_TERMIOS_LEN])
        })
    };
    let mut out = [0u8; TERMIOS_WIRE_LEN];
    out[..KERNEL_TERMIOS_LEN].copy_from_slice(&k);
    Ok(out)
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) unsafe fn read_user_termios2(uptr: usize) -> Result<[u8; TERMIOS_WIRE_LEN], FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    let mut out = [0u8; TERMIOS_WIRE_LEN];
    // SAFETY: caller guarantees uptr is a valid user pointer; non-overlapping.
    unsafe {
        core::ptr::copy_nonoverlapping(uptr as *const u8, out.as_mut_ptr(), KERNEL_TERMIOS_LEN)
    };
    Ok(out)
}

// ── PtyMaster FileOps ─────────────────────────────────────────────────────────

/// `/dev/ptmx` open result — the master half of a PTY pair.
///
/// Linux ref: `drivers/tty/pty.c` `ptm_unix98_ops`
pub struct PtyMaster {
    pty: Arc<Pty>,
}

impl core::fmt::Debug for PtyMaster {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PtyMaster")
            .field("index", &self.pty.index)
            .finish()
    }
}

impl PtyMaster {
    pub fn new(pty: Arc<Pty>) -> Self {
        Self { pty }
    }

    /// Return the PTY index.  Userspace can use this to construct the
    /// `/dev/pts/<N>` path (substitute for `ioctl(TIOCGPTN)` which is
    /// not yet available in NARF).
    pub fn index(&self) -> u32 {
        self.pty.index
    }
}

impl Drop for PtyMaster {
    fn drop(&mut self) {
        // Linux `pty_close`: the master's close sets TTY_OTHER_CLOSED on the
        // peer AND `tty_vhangup`s it, so a slave still reading must now see
        // end-of-file rather than wait for a writer that can never return.
        self.pty.master_closed.store(true, Ordering::Release);
        ptmx_close(self.pty.index);
    }
}

impl FileOps for PtyMaster {
    /// Read bytes that the slave has sent.
    /// Linux ref: `pty.c pty_read` → `tty_buffer_request_room` →
    ///   drains `tty->link->read_buf`.
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        // Packet mode (TIOCPKT): every read is framed as [status][data...].
        // Linux `pty_read` prefixes the control byte to the drained bytes;
        // with no pending control event the byte is TIOCPKT_DATA and ordinary
        // output follows. (The flush/stop/start control packets are a
        // documented gap — see `Pty::packet`.)
        // IXON/TCXONC flow control: while output is stopped the master sees
        // nothing, which is the whole point of ^S. Linux gates the transmit
        // path on `tty->flow.stopped`; a flag that stopped nothing would be
        // an accepted-and-discarded control.
        if self.pty.input.lock().stopped && !self.pty.hung_up() {
            return Box::pin(async move { Err(FsError::WouldBlock) });
        }
        if self.pty.packet.load(Ordering::Acquire) {
            if buf.is_empty() {
                return Box::pin(async move { Ok(0) });
            }
            let n = self.pty.slave_tx_to_master.pop(&mut buf[1..]);
            if n > 0 {
                buf[0] = TIOCPKT_DATA;
                return Box::pin(async move { Ok(n + 1) });
            }
            // No data copied. If output is nonetheless pending, the caller's
            // buffer had room only for the status byte (buf.len() == 1); emit
            // a bare TIOCPKT_DATA header and leave the data for the next read.
            if self.pty.slave_tx_to_master.len() > 0 {
                buf[0] = TIOCPKT_DATA;
                return Box::pin(async move { Ok(1) });
            }
            if self.pty.hung_up() {
                return Box::pin(async move { Err(FsError::Io(narf_block::BlockError::IOError)) });
            }
            return Box::pin(async move { Err(FsError::WouldBlock) });
        }
        let n = self.pty.slave_tx_to_master.pop(buf);
        // Drain first: bytes the slave wrote before it closed are still the
        // child's output and must be delivered, exactly as Linux drains
        // `read_buf` before reporting the hangup.
        if n == 0 && self.pty.hung_up() {
            // EIO, the errno Linux's `pty_read` returns on hangup — not
            // ENOTSUP, and emphatically not Ok(0), which is the phantom EOF
            // this whole predicate exists to avoid.
            return Box::pin(async move { Err(FsError::Io(narf_block::BlockError::IOError)) });
        }
        // Empty and NOT hung up: would-block. The ring state that produced
        // n == 0 also classifies it, without a second syscall query.
        if n == 0 {
            return Box::pin(async move { Err(FsError::WouldBlock) });
        }
        Box::pin(async move { Ok(n) })
    }

    /// Write bytes to the slave's input — through the shared n_tty line
    /// discipline. Cooked mode (ICANON) buffers into lines, ECHO mirrors
    /// the bytes back to the master read side, and ISIG control chars
    /// (^C/^\/^Z) raise a signal to this PTY's foreground process group.
    /// Linux ref: `pty.c pty_write` → `n_tty_receive_buf` on `tty->link`.
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let t = *self.pty.termios.lock();
        // Collect ISIG signals to deliver AFTER releasing the discipline
        // lock (signal delivery allocates + takes the pgid/signal locks).
        let mut sigs: Vec<u32> = Vec::new();
        {
            let pty = &*self.pty;
            let mut state = pty.input.lock();
            for &b in buf {
                crate::ntty::feed_byte(
                    &mut state,
                    &t,
                    b,
                    &mut |c| pty.slave_tx_to_master.push(&[c]),
                    &mut |bb| match signal_for_cc(&t, bb) {
                        Some(sig) => {
                            sigs.push(sig);
                            true
                        }
                        None => false,
                    },
                );
            }
        }
        if !sigs.is_empty() {
            let pgrp = self.pty.ctrl.lock().fg_pgrp;
            for sig in sigs {
                pty_deliver_signal(pgrp, sig);
            }
        }
        let n = buf.len();
        Box::pin(async move { Ok(n) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o620,
            },
            mtime_cycles: 0,
        }
    }

    fn rdev(&self) -> u64 {
        crate::devfs::linux_makedev(5, 2)
    }

    fn ino(&self) -> u64 {
        0xd001_0000_0000_0000 | self.rdev().wrapping_add(1)
    }

    fn owners(&self) -> (u32, u32) {
        (0, 5)
    }

    /// Wave-76: PtyMaster identifies itself via the FileOps hook so
    /// `sys_ioctl(TIOCGPTPEER)` can allocate a fresh slave fd without
    /// a `Any`-based downcast on `Arc<dyn FileOps>`.
    fn as_pty_master_index(&self) -> Option<u32> {
        Some(self.pty.index)
    }

    fn tty_fg_pgrp(&self) -> Option<u64> {
        Some(self.pty.ctrl.lock().fg_pgrp)
    }

    fn tty_session(&self) -> Option<u64> {
        Some(self.pty.ctrl.lock().sid)
    }

    fn set_tty_fg_pgrp(&self, pgrp: u64) -> bool {
        self.pty.ctrl.lock().fg_pgrp = pgrp;
        true
    }

    // The controlling-tty transaction and its CTTY hook are `linux-compat`
    // machinery; without the feature this override drops to the trait default
    // (`Ok(false)` — TIOCSCTTY is a no-op on non-Linux-ABI builds).
    fn tty_acquire_controlling(&self, arg: usize, readable: bool) -> Result<bool, FsError> {
        self.pty.acquire_controlling_tty(arg, readable)?;
        Ok(true)
    }

    /// Wave-76: master-side ioctls.
    ///
    /// - `TIOCGPTN`     — write the slave number into *(u32*)arg
    /// - `TIOCSPTLCK`   — set/clear the slave-lock flag from *(i32*)arg
    /// - `TIOCSPGRP`    — set fg_pgrp from *(i32*)arg (per-tty slot)
    /// - `TIOCGPGRP`    — read fg_pgrp into *(i32*)arg
    /// - `TIOCGPTPEER`  — NOT handled here; the syscall layer special-cases
    ///   it to allocate a fresh fd in the caller's table.
    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, FsError> {
        match cmd {
            TIOCGPTN => {
                // SAFETY: arg is a validated user pointer passed from the ioctl syscall path.
                unsafe { write_user_u32(arg, self.pty.index)? };
                Ok(0)
            }
            TIOCSPTLCK => {
                // SAFETY: arg is a validated user pointer passed from the ioctl syscall path.
                let v = unsafe { read_user_i32(arg)? };
                self.pty.locked.store(v != 0, Ordering::Release);
                Ok(0)
            }
            TIOCGPGRP => {
                let pgrp = self.pty.get_fg_pgrp()? as i32;
                // SAFETY: arg is a validated user pointer passed from the ioctl syscall path.
                unsafe { write_user_i32(arg, pgrp)? };
                Ok(0)
            }
            TIOCSPGRP => {
                // SAFETY: arg is a validated user pointer passed from the ioctl syscall path.
                let pgrp = unsafe { read_user_i32(arg)? };
                self.pty.set_fg_pgrp(pgrp)
            }
            TIOCSCTTY => {
                self.pty.acquire_controlling_tty(arg, true)?;
                Ok(0)
            }
            TIOCGWINSZ => {
                let w = *self.pty.window.lock();
                let ws = WireWinsize {
                    ws_row: w.rows,
                    ws_col: w.cols,
                    ws_xpixel: w.xpixel,
                    ws_ypixel: w.ypixel,
                };
                // SAFETY: arg is a validated user pointer passed from the ioctl syscall path.
                unsafe { write_user_winsize(arg, ws)? };
                Ok(0)
            }
            TIOCSWINSZ => {
                // SAFETY: arg is a validated user pointer passed from the ioctl syscall path.
                let ws = unsafe { read_user_winsize(arg)? };
                self.pty.resize(WinSize {
                    rows: ws.ws_row,
                    cols: ws.ws_col,
                    xpixel: ws.ws_xpixel,
                    ypixel: ws.ws_ypixel,
                });
                Ok(0)
            }
            TCGETS => {
                let t = *self.pty.termios.lock();
                // SAFETY: arg is a validated user pointer passed from the ioctl syscall path.
                unsafe { write_user_termios(arg, &t.raw)? };
                Ok(0)
            }
            TCSETS | TCSETSW | TCSETSF => {
                // Store the caller's termios so it round-trips and the
                // line-discipline knobs take effect.
                // SAFETY: arg is a validated user pointer passed from the ioctl syscall path.
                let raw = unsafe { read_user_termios(arg)? };
                self.pty.set_termios_locked(raw);
                // TCSETSF additionally DISCARDS queued input
                // (`tty_ioctl.c::set_termios` -> `tty_ldisc_flush`), which
                // is the whole reason `tcsetattr(TCSAFLUSH)` exists: a
                // program switching to raw mode must not then read the
                // keystrokes typed while it was still cooked.
                if cmd == TCSETSF {
                    let mut st = self.pty.input.lock();
                    st.ready.clear();
                    st.line.clear();
                    st.eof = false;
                }
                Ok(0)
            }
            TCGETS2 => {
                let t = *self.pty.termios.lock();
                // SAFETY: arg is a validated user `struct termios2 *`.
                unsafe { write_user_termios2(arg, &t.raw)? };
                Ok(0)
            }
            TCSETS2 | TCSETSW2 | TCSETSF2 => {
                // SAFETY: arg is a validated user `struct termios2 *`.
                let raw = unsafe { read_user_termios2(arg)? };
                self.pty.set_termios_locked(raw);
                Ok(0)
            }
            TIOCEXCL => {
                // `set_bit(TTY_EXCLUSIVE, &tty->flags)` (`tty_io.c:2713`).
                self.pty.exclusive.store(true, Ordering::Release);
                Ok(0)
            }
            TIOCNXCL => {
                self.pty.exclusive.store(false, Ordering::Release);
                Ok(0)
            }
            TIOCGEXCL => {
                let v = self.pty.exclusive.load(Ordering::Acquire) as i32;
                // SAFETY: arg is a validated user `int *`.
                unsafe { write_user_i32(arg, v)? };
                Ok(0)
            }
            TIOCGETD => {
                // `put_user(ld->ops->num, p)` — always N_TTY here.
                // SAFETY: arg is a validated user `int *`.
                unsafe { write_user_i32(arg, N_TTY)? };
                Ok(0)
            }
            TIOCSETD => {
                // Only N_TTY exists; `tty_set_ldisc` answers EINVAL for a
                // discipline that is not registered.
                // SAFETY: arg is a validated user `int *`.
                let want = unsafe { read_user_i32(arg)? };
                if want != N_TTY {
                    return Err(FsError::InvalidData); // EINVAL
                }
                Ok(0)
            }
            TIOCSTI => {
                // `arg` is a `char __user *`, read BEFORE the byte is fed.
                // SAFETY: arg is a validated user `char *`.
                let b = unsafe { read_user_u8(arg)? };
                self.pty.insert_input_byte(b)
            }
            TIOCVHANGUP => self.pty.vhangup(),
            TIOCGLCKTRMIOS => {
                let l = *self.pty.locked_termios.lock();
                // SAFETY: arg is a validated user `struct termios *`.
                unsafe { write_user_termios(arg, &l.raw)? };
                Ok(0)
            }
            TIOCSLCKTRMIOS => {
                // `checkpoint_restore_ns_capable` (`tty_ioctl.c:843`);
                // CAP_SYS_ADMIN implies it.
                if !caller_capable(CAP_SYS_ADMIN) {
                    return Err(FsError::OperationNotPermitted); // EPERM
                }
                // SAFETY: arg is a validated user `struct termios *`.
                let raw = unsafe { read_user_termios(arg)? };
                self.pty.locked_termios.lock().raw = raw;
                Ok(0)
            }
            TCFLSH => self.pty.flush_queues(arg),
            TCXONC => self.pty.flow_control(arg),
            // TCSBRK / tcdrain: a PTY has no transmitter to drain and no
            // BREAK to send, so Linux's pty (which supplies no `break_ctl`)
            // waits for output to drain and returns success.
            TCSBRK => Ok(0),
            TIOCOUTQ => {
                // The MASTER's output queue is what it has written toward
                // the slave, i.e. the slave's pending input — not the
                // slave's output, which is what the master READS.
                let n = self.pty.input.lock().readable() as i32;
                // SAFETY: arg is a validated user `int *`.
                unsafe { write_user_i32(arg, n)? };
                Ok(0)
            }
            FIONREAD => {
                // Bytes the master can read = bytes slave has written.
                let n = self.pty.slave_tx_to_master.len() as i32;
                // SAFETY: arg is a validated user pointer passed from the ioctl syscall path.
                unsafe { write_user_i32(arg, n)? };
                Ok(0)
            }
            TIOCPKT => {
                // Linux `pty_set_pktmode`: a non-zero int enables packet mode
                // on the master, zero disables it.
                // SAFETY: arg is a validated user `int *`.
                let on = unsafe { read_user_i32(arg)? } != 0;
                self.pty.packet.store(on, Ordering::Release);
                Ok(0)
            }
            TIOCGPKT => {
                // Linux `pty_get_pktmode`: report the packet-mode flag.
                let v = self.pty.packet.load(Ordering::Acquire) as i32;
                // SAFETY: arg is a validated user `int *`.
                unsafe { write_user_i32(arg, v)? };
                Ok(0)
            }
            TIOCGPTLCK => {
                // Linux `pty_get_lock`: report the slave-lock flag (the value
                // last set by TIOCSPTLCK / unlockpt).
                let v = self.pty.locked.load(Ordering::Acquire) as i32;
                // SAFETY: arg is a validated user `int *`.
                unsafe { write_user_i32(arg, v)? };
                Ok(0)
            }
            TIOCSIG => {
                // Linux `pty_signal`: `arg` is the signal number VALUE (not a
                // pointer — see the compat path that skips `compat_ptr` for
                // TIOCSIG). Validate it, then raise it on the slave's
                // foreground process group; an out-of-range signal is EINVAL.
                let sig = arg as u32;
                if sig == 0 || sig > 64 {
                    return Err(FsError::InvalidData);
                }
                let pgrp = self.pty.ctrl.lock().fg_pgrp;
                pty_deliver_signal(pgrp, sig);
                Ok(0)
            }
            // TIOCGPTPEER is dispatched by sys_ioctl directly; if it
            // reaches here, fall through to Unsupported (→ -ENOTTY).
            _ => Err(FsError::Unsupported),
        }
    }

    /// POLLIN when the master's input queue (slave_tx_to_master) has at
    /// least one byte; POLLOUT always; POLLHUP once every slave has closed.
    ///
    /// The HUP half matters as much as the EIO on `read`: an event loop
    /// (foot, and every other terminal) sits in poll/epoll rather than a
    /// bare blocking read, so without it the loop simply never wakes and
    /// never learns its child is gone.
    ///
    /// Linux ref: `n_tty_poll` —
    ///   `if (test_bit(TTY_OTHER_CLOSED, &tty->flags)) mask |= EPOLLHUP;`
    /// set by `pty_close` on the peer and cleared when a slave re-opens
    /// (`pty.c` `set_bit`/`clear_bit` on `tty->link->flags`), which the
    /// open counter reproduces.
    fn poll_readiness(&self) -> u32 {
        let mut mask = crate::POLL_OUT;
        // Stopped output is not readable output — the poll mask has to agree
        // with `read`, or an event loop spins on a POLLIN that never yields
        // a byte.
        let stopped = self.pty.input.lock().stopped;
        if !stopped && self.pty.slave_tx_to_master.len() > 0 {
            mask |= crate::POLL_IN;
        }
        if self.pty.hung_up() {
            mask |= crate::POLL_HUP;
        }
        mask
    }
}

// ── PtySlave FileOps ──────────────────────────────────────────────────────────

/// `/dev/pts/<N>` — the slave half of a PTY pair.
///
/// Linux ref: `drivers/tty/pty.c` `pts_unix98_ops`
pub struct PtySlave {
    pty: Arc<Pty>,
}

/// Closing the last slave is the HANGUP the master read waits for.
/// Linux: `pty_close` on the slave wakes the master's readers, and a
/// subsequent master read returns `EIO` rather than blocking forever.
impl Drop for PtySlave {
    fn drop(&mut self) {
        let prev = self.pty.slave_opens.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(prev > 0, "PtySlave dropped without a matching open");
    }
}

impl core::fmt::Debug for PtySlave {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PtySlave")
            .field("index", &self.pty.index)
            .finish()
    }
}

impl PtySlave {
    pub fn new(pty: Arc<Pty>) -> Self {
        pty.slave_opens.fetch_add(1, Ordering::AcqRel);
        pty.slave_ever_opened.store(true, Ordering::Release);
        Self { pty }
    }
}

impl FileOps for PtySlave {
    /// Read the slave's input. The shared n_tty line discipline already
    /// processed the master's writes into `pty.input` — whole lines when
    /// ICANON is set, raw bytes otherwise — so this just drains the ready
    /// queue. A pending `^D` EOF on an empty queue surfaces as a 0-byte
    /// read (end-of-file); an empty queue with no EOF returns 0 too
    /// (NARF's synchronous "would block").
    ///
    /// Linux ref: `n_tty.c n_tty_read` → canonical buffer drain.
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        // Non-canonical reads answer to VMIN/VTIME, which decide whether
        // enough has arrived (or waited long enough) to return at all.
        // Canonical mode does not consult them — Linux leaves `minimum` and
        // `time` at zero for it — so it keeps the line-at-a-time path below.
        let t = *self.pty.termios.lock();
        if !t.icanon() {
            let avail = self.pty.input.lock().readable();
            let gate = self.pty.noncanon_read_gate(&t, avail);
            let hung_up = self.pty.master_closed.load(Ordering::Acquire);
            if gate == ReadGate::Block && !hung_up {
                // Not satisfied and no timer has expired. A hung-up master
                // is still a real EOF, so it overrides the wait.
                return Box::pin(async move { Err(FsError::WouldBlock) });
            }
            if avail == 0 {
                // Deliver with an empty queue. With VMIN == 0 this is a
                // legitimate 0-byte read, NOT end-of-file: a polling read
                // (VTIME == 0) never waits, and a timed read reports what it
                // has when VTIME expires — `n_tty_read` returns `kb - kbuf`,
                // which is simply zero. This is the second place a 0 is
                // correct on a PTY, alongside canonical mode's latched ^D.
                return Box::pin(async move { Ok(0) });
            }
            let n = self.pty.input.lock().drain_into(buf);
            return Box::pin(async move {
                if n == 0 {
                    // The caller passed a zero-length buffer.
                    Ok(0)
                } else {
                    Ok(n)
                }
            });
        }
        let mut state = self.pty.input.lock();
        if state.readable() == 0 {
            // The ONE PTY case where 0 is correct: canonical mode latches ^D
            // as a genuine EOF a shell must see exactly once. `take_eof()`
            // consumes that latch and reports it; anything else is "no
            // completed line yet", which is would-block, not end-of-file.
            // A hung-up master is also a real EOF (Linux `tty_read` /
            // `tty_hung_up_p`).
            let latched_eof = state.take_eof();
            let hung_up = self.pty.master_closed.load(Ordering::Acquire);
            drop(state);
            return Box::pin(async move {
                if latched_eof || hung_up {
                    Ok(0)
                } else {
                    Err(FsError::WouldBlock)
                }
            });
        }
        let n = state.drain_into(buf);
        drop(state);
        // `readable() != 0` counts buffered bytes, but ICANON only RELEASES a
        // completed line — an incomplete line, or input consumed as a signal
        // character (^C), drains 0. That is would-block, not end-of-file; the
        // readable()==0 branch above is the only place a real EOF originates.
        if n == 0 {
            return Box::pin(async move { Err(FsError::WouldBlock) });
        }
        Box::pin(async move { Ok(n) })
    }

    /// libc readers of a slave opened O_NONBLOCK expect EAGAIN on an empty
    /// queue, not a phantom EOF. Gated the same way, so `^D` still lands.
    fn nonblock_read_eagain(&self) -> bool {
        // Same hangup exception: after the master closes, an O_NONBLOCK
        // slave read reports EOF (0), not EAGAIN — there is nothing left
        // that could ever arrive.
        self.pty.input.lock().would_block() && !self.pty.master_closed.load(Ordering::Acquire)
    }

    /// Write bytes; with ECHO on, also copies them to `slave_tx_to_master`
    /// so the master "sees" what the slave wrote.
    ///
    /// Linux ref: `pty.c pty_write` for the echo side via
    ///   `n_tty_receive_buf_common → n_tty_echo`.
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        // Slave output runs through OPOST on its way to the master, which
        // is what turns a bare `\n` into CR-NL. Skipping it is invisible on
        // a serial console (the UART driver adds its own CR) and ruins
        // every terminal emulator, which correctly expects the line
        // discipline to have done it.
        //
        // This is the `tty->ops->write` side of `do_output_char`; ECHO is
        // NOT involved here. Echo reflects INPUT — bytes the master wrote —
        // and is applied on the master write path by `ntty::feed_byte`.
        let mut processed = alloc::vec::Vec::with_capacity(buf.len() + 8);
        {
            let t = *self.pty.termios.lock();
            let mut out = self.pty.output.lock();
            crate::ntty::process_output(&mut out, &t, buf, &mut |c| processed.push(c));
        }
        self.pty.slave_tx_to_master.push(&processed);
        // Linux reports the bytes the CALLER supplied, not the expanded
        // count: a `\n` that became CR-NL still consumed one byte of the
        // caller's buffer.
        let n = buf.len();
        Box::pin(async move { Ok(n) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o620,
            },
            mtime_cycles: 0,
        }
    }

    fn rdev(&self) -> u64 {
        crate::devfs::linux_makedev(136, self.pty.index)
    }

    fn ino(&self) -> u64 {
        0xd001_0000_0000_0000 | self.rdev().wrapping_add(1)
    }

    /// The opener of `/dev/ptmx` owns the slave — see [`Pty::uid`]. With the
    /// 0620 mode above, reporting root here instead denies the slave to every
    /// non-root session.
    fn owners(&self) -> (u32, u32) {
        (
            self.pty.uid.load(Ordering::Acquire),
            self.pty.gid.load(Ordering::Acquire),
        )
    }

    /// Wave-76: slave-side ioctls.
    ///
    /// - `TIOCGPTN`   — returns this slave's index (Linux extension; harmless)
    /// - `TIOCSPGRP`  — set the per-tty fg_pgrp (same slot as the master)
    /// - `TIOCGPGRP`  — read the per-tty fg_pgrp
    /// - `TIOCSCTTY`  — install this PTY as the caller's controlling tty
    ///   via the userspace registry (see `set_controlling_tty_hook`).
    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, FsError> {
        match cmd {
            TIOCGPTN => {
                // SAFETY: arg is a validated user pointer passed from the ioctl syscall path.
                unsafe { write_user_u32(arg, self.pty.index)? };
                Ok(0)
            }
            TIOCGPGRP => {
                let pgrp = self.pty.get_fg_pgrp()? as i32;
                // SAFETY: arg is a validated user pointer passed from the ioctl syscall path.
                unsafe { write_user_i32(arg, pgrp)? };
                Ok(0)
            }
            TIOCSPGRP => {
                // SAFETY: arg is a validated user pointer passed from the ioctl syscall path.
                let pgrp = unsafe { read_user_i32(arg)? };
                self.pty.set_fg_pgrp(pgrp)
            }
            TIOCSCTTY => {
                self.pty.acquire_controlling_tty(arg, true)?;
                Ok(0)
            }
            TIOCGSID => {
                // Linux `tiocgsid`: the session of the tty's session leader.
                // ENOTTY while the tty has no session, matching Linux's
                // `if (!real_tty->ctrl.session) return -ENOTTY;`.
                let sid = self.pty.ctrl.lock().sid;
                if sid == 0 {
                    return Err(FsError::Unsupported);
                }
                // SAFETY: arg is a validated user pointer passed from the ioctl syscall path.
                unsafe { write_user_i32(arg, sid as i32)? };
                Ok(0)
            }
            TIOCGWINSZ => {
                let w = *self.pty.window.lock();
                let ws = WireWinsize {
                    ws_row: w.rows,
                    ws_col: w.cols,
                    ws_xpixel: w.xpixel,
                    ws_ypixel: w.ypixel,
                };
                // SAFETY: arg is a validated user pointer passed from the ioctl syscall path.
                unsafe { write_user_winsize(arg, ws)? };
                Ok(0)
            }
            TIOCSWINSZ => {
                // SAFETY: arg is a validated user pointer passed from the ioctl syscall path.
                let ws = unsafe { read_user_winsize(arg)? };
                self.pty.resize(WinSize {
                    rows: ws.ws_row,
                    cols: ws.ws_col,
                    xpixel: ws.ws_xpixel,
                    ypixel: ws.ws_ypixel,
                });
                Ok(0)
            }
            TCGETS => {
                let t = *self.pty.termios.lock();
                // SAFETY: arg is a validated user pointer passed from the ioctl syscall path.
                unsafe { write_user_termios(arg, &t.raw)? };
                Ok(0)
            }
            TCSETS | TCSETSW | TCSETSF => {
                // SAFETY: arg is a validated user pointer passed from the ioctl syscall path.
                let raw = unsafe { read_user_termios(arg)? };
                self.pty.set_termios_locked(raw);
                // TCSETSF discards queued input; TCSETS and TCSETSW do not.
                if cmd == TCSETSF {
                    let mut st = self.pty.input.lock();
                    st.ready.clear();
                    st.line.clear();
                    st.eof = false;
                }
                Ok(0)
            }
            TCGETS2 => {
                let t = *self.pty.termios.lock();
                // SAFETY: arg is a validated user `struct termios2 *`.
                unsafe { write_user_termios2(arg, &t.raw)? };
                Ok(0)
            }
            TCSETS2 | TCSETSW2 | TCSETSF2 => {
                // SAFETY: arg is a validated user `struct termios2 *`.
                let raw = unsafe { read_user_termios2(arg)? };
                self.pty.set_termios_locked(raw);
                Ok(0)
            }
            TIOCEXCL => {
                // `set_bit(TTY_EXCLUSIVE, &tty->flags)` (`tty_io.c:2713`).
                self.pty.exclusive.store(true, Ordering::Release);
                Ok(0)
            }
            TIOCNXCL => {
                self.pty.exclusive.store(false, Ordering::Release);
                Ok(0)
            }
            TIOCGEXCL => {
                let v = self.pty.exclusive.load(Ordering::Acquire) as i32;
                // SAFETY: arg is a validated user `int *`.
                unsafe { write_user_i32(arg, v)? };
                Ok(0)
            }
            TIOCGETD => {
                // `put_user(ld->ops->num, p)` — always N_TTY here.
                // SAFETY: arg is a validated user `int *`.
                unsafe { write_user_i32(arg, N_TTY)? };
                Ok(0)
            }
            TIOCSETD => {
                // Only N_TTY exists; `tty_set_ldisc` answers EINVAL for a
                // discipline that is not registered.
                // SAFETY: arg is a validated user `int *`.
                let want = unsafe { read_user_i32(arg)? };
                if want != N_TTY {
                    return Err(FsError::InvalidData); // EINVAL
                }
                Ok(0)
            }
            TIOCSTI => {
                // `arg` is a `char __user *`, read BEFORE the byte is fed.
                // SAFETY: arg is a validated user `char *`.
                let b = unsafe { read_user_u8(arg)? };
                self.pty.insert_input_byte(b)
            }
            TIOCVHANGUP => self.pty.vhangup(),
            TIOCGLCKTRMIOS => {
                let l = *self.pty.locked_termios.lock();
                // SAFETY: arg is a validated user `struct termios *`.
                unsafe { write_user_termios(arg, &l.raw)? };
                Ok(0)
            }
            TIOCSLCKTRMIOS => {
                // `checkpoint_restore_ns_capable` (`tty_ioctl.c:843`);
                // CAP_SYS_ADMIN implies it.
                if !caller_capable(CAP_SYS_ADMIN) {
                    return Err(FsError::OperationNotPermitted); // EPERM
                }
                // SAFETY: arg is a validated user `struct termios *`.
                let raw = unsafe { read_user_termios(arg)? };
                self.pty.locked_termios.lock().raw = raw;
                Ok(0)
            }
            TCFLSH => self.pty.flush_queues(arg),
            TCXONC => self.pty.flow_control(arg),
            // TCSBRK / tcdrain: a PTY has no transmitter to drain and no
            // BREAK to send, so Linux's pty (which supplies no `break_ctl`)
            // waits for output to drain and returns success.
            TCSBRK => Ok(0),
            TIOCOUTQ => {
                // Bytes written but not yet consumed by the other end.
                let n = self.pty.slave_tx_to_master.len() as i32;
                // SAFETY: arg is a validated user `int *`.
                unsafe { write_user_i32(arg, n)? };
                Ok(0)
            }
            FIONREAD => {
                // Bytes the slave can read now = completed line-discipline
                // output queued in `pty.input`.
                let n = self.pty.input.lock().readable() as i32;
                // SAFETY: arg is a validated user pointer passed from the ioctl syscall path.
                unsafe { write_user_i32(arg, n)? };
                Ok(0)
            }
            _ => Err(FsError::Unsupported),
        }
    }

    /// POLLIN when the slave's input queue (`pty.input`) has at least one
    /// readable byte; POLLOUT always. Mirrors the ConsoleFile pattern but
    /// reads from the per-PTY discipline instead of the global input ring.
    fn poll_readiness(&self) -> u32 {
        let mut mask = crate::POLL_OUT;
        if self.pty.input.lock().readable() > 0 {
            mask |= crate::POLL_IN;
        }
        // Linux `n_tty_poll`: EPOLLHUP once the peer closed. Without it a
        // shell sitting in poll/epoll on its tty never learns the terminal
        // went away and never exits.
        if self.pty.master_closed.load(Ordering::Acquire) {
            mask |= crate::POLL_HUP;
        }
        mask
    }

    /// Job control: the slave's tty id is its `/dev/pts/<N>` index.
    fn tty_id(&self) -> Option<u32> {
        Some(self.pty.index)
    }

    /// Job control: this PTY's foreground process group (0 = unset).
    fn tty_fg_pgrp(&self) -> Option<u64> {
        Some(self.pty.ctrl.lock().fg_pgrp)
    }

    fn tty_session(&self) -> Option<u64> {
        Some(self.pty.ctrl.lock().sid)
    }

    fn set_tty_fg_pgrp(&self, pgrp: u64) -> bool {
        self.pty.ctrl.lock().fg_pgrp = pgrp;
        true
    }

    // See the master-side override above: gated to match the `linux-compat`
    // CTTY machinery, falling back to the trait default when the feature is off.
    fn tty_acquire_controlling(&self, arg: usize, readable: bool) -> Result<bool, FsError> {
        self.pty.acquire_controlling_tty(arg, readable)?;
        Ok(true)
    }

    /// Job control: TOSTOP from this PTY's termios.
    fn tty_tostop(&self) -> bool {
        self.pty.termios.lock().tostop()
    }
}

// ── Controlling-tty hook ──────────────────────────────────────────────────────
//
// `TIOCSCTTY` and master-close-SIGHUP both need to reach the per-task
// session table that lives in `userspace::handlers`. Rather than make
// the filesystem crate depend on userspace, we expose a function-pointer
// hook the userspace crate installs at boot.

/// Validates and records the caller's controlling tty, then reports the
/// caller's `(session id, process group id)` in visible-pid space. `tty_sid`
/// is the tty's current owner and `arg` is the Linux TIOCSCTTY argument.
///
/// The return value is what lets `TIOCSCTTY` implement Linux's
/// `__proc_set_tty` (drivers/tty/tty_jobctrl.c), which installs the tty's
/// session AND its foreground process group as one operation. Without the
/// pgrp half, `tcgetpgrp()` answers 0 forever and a job-control shell's
/// `initialize_job_control` loop never converges — see the TIOCSCTTY arm.
type CttyHook =
    fn(pty_index: u32, tty_sid: u64, arg: usize, readable: bool) -> Result<(u64, u64), FsError>;

static CTTY_HOOK: IrqSafeSpinLock<Option<CttyHook>> = IrqSafeSpinLock::new(None);

static TIOCSCTTY_TXN: IrqSafeSpinLock<()> = IrqSafeSpinLock::new(());

/// Install the hook called from `PtySlave::ioctl(TIOCSCTTY)`. Userspace
/// uses this to record the caller's controlling tty.
pub fn set_controlling_tty_hook(hook: CttyHook) {
    *CTTY_HOOK.lock() = Some(hook);
}

// ── DevPtmx FileOps ───────────────────────────────────────────────────────────

/// The devpts `ptmx` clone node. Path lookup and stat are side-effect free;
/// `FileOps::open_instance` allocates a fresh master/slave pair only after a
/// successful open has passed permission checks.
pub struct DevPtmx;

impl core::fmt::Debug for DevPtmx {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DevPtmx").finish()
    }
}

impl FileOps for DevPtmx {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Ok(0) })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                // cdev 5:2 in Linux (major 5, minor 2)
                perms: 0o666,
            },
            mtime_cycles: 0,
        }
    }

    /// Mark this FileOps as the ptmx clone-on-open node. `sys_open`
    /// allocates a fresh `Pty` pair via [`open_ptmx`] and installs
    /// the master FileOps in the caller's fd table instead of this
    /// singleton. Linux: `drivers/tty/pty.c::ptmx_open`.
    fn is_ptmx_clone(&self) -> bool {
        true
    }

    fn open_instance(&self) -> Option<Arc<dyn FileOps>> {
        Some(open_ptmx() as Arc<dyn FileOps>)
    }

    fn rdev(&self) -> u64 {
        crate::devfs::linux_makedev(5, 2)
    }

    fn ino(&self) -> u64 {
        0xd001_0000_0000_0000 | self.rdev().wrapping_add(1)
    }
}

/// Open a new PTY master.  This is the programmatic equivalent of
/// `open("/dev/ptmx", O_RDWR)` on Linux.
pub fn open_ptmx() -> Arc<PtyMaster> {
    let (_index, pty) = ptmx_open();
    Arc::new(PtyMaster::new(pty))
}

// ── DevPts DirOps ─────────────────────────────────────────────────────────────

/// `/dev/pts/` directory.
///
/// `lookup("N")` returns a `PtySlave` for the PTY with that index if it
/// exists.  `iter()` / `enumerate()` report the currently-open PTY
/// indices.
///
/// Linux ref: `fs/devpts/inode.c devpts_get_inode` (slave inode lookup).
pub struct DevPts;

impl core::fmt::Debug for DevPts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DevPts").finish()
    }
}

impl DirOps for DevPts {
    fn ino(&self) -> u64 {
        3
    }

    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        if name == "ptmx" {
            return Some(Arc::new(DevPtmx) as Arc<dyn FileOps>);
        }
        let idx: u32 = name.parse().ok()?;
        let pty = pts_lookup(idx)?;
        // Wave-76: a locked slave is invisible to `lookup()` — the
        // async path surfaces this as EIO. We can't return Err from
        // a sync `lookup`, so a locked PTY reports NotFound here.
        // The async path below distinguishes locked vs absent.
        if pty.locked.load(Ordering::Acquire) {
            return None;
        }
        Some(Arc::new(PtySlave::new(pty)) as Arc<dyn FileOps>)
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            if name == "ptmx" {
                return Ok(Arc::new(DevPtmx) as Arc<dyn FileOps>);
            }
            let idx: u32 = name.parse().map_err(|_| FsError::NotFound)?;
            let pty = pts_lookup(idx).ok_or(FsError::NotFound)?;
            // `tty_open`: `if (test_bit(TTY_EXCLUSIVE, &tty->flags) &&
            // !capable(CAP_SYS_ADMIN)) return -EBUSY;` — exclusive mode is
            // what stops a second program attaching to a terminal another
            // already owns.
            if pty.exclusive.load(Ordering::Acquire) && !caller_capable(CAP_SYS_ADMIN) {
                return Err(FsError::Busy);
            }
            if pty.locked.load(Ordering::Acquire) {
                return Err(FsError::Busy);
            }
            Ok(Arc::new(PtySlave::new(pty)) as Arc<dyn FileOps>)
        })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // We can't return references to a locally-allocated Vec here —
        // `DirEntry.name` is `&'static str`.  The pts enumeration uses
        // `enumerate()` which returns owned Strings.
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        core::iter::once((String::from("ptmx"), FileType::Special))
            .chain(pts_indices().into_iter().map(|idx| {
                let mut s = String::new();
                let mut tmp = [0u8; 10];
                let digits = u32_to_str(idx, &mut tmp);
                s.push_str(digits);
                (s, FileType::Special)
            }))
            .skip(cursor)
            .take(max)
            .collect()
    }

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> FsFuture<'a, Vec<(String, FileType)>> {
        Box::pin(async move { Ok(self.enumerate(cursor, max)) })
    }
}

/// Mountable Linux `devpts` filesystem. It shares NARF's PTY registry with
/// the built-in `/dev/pts` view, so mounting `devpts` over that path preserves
/// live Unix98 slave nodes instead of replacing them with an empty tmpfs.
#[derive(Debug, Default)]
pub struct DevPtsFs;

impl FsInstance for DevPtsFs {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::new(DevPts)
    }

    fn name(&self) -> &str {
        "devpts"
    }
}

/// Format a `u32` into `buf` (right-justified).  Returns the decimal string.
fn u32_to_str(mut n: u32, buf: &mut [u8; 10]) -> &str {
    if n == 0 {
        buf[9] = b'0';
        // SAFETY: the only byte in `buf[9..]` was just set to b'0' (0x30), an
        // ASCII digit, which is valid UTF-8.
        // SAFETY: Valid memory or trusted environment
        return unsafe { core::str::from_utf8_unchecked(&buf[9..]) };
    }
    let mut pos = 10;
    while n > 0 {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    // SAFETY: every byte written into `buf[pos..]` above is `b'0' + digit`
    // where `digit` is `n % 10` in 0..=9, so each byte is an ASCII digit
    // (0x30..=0x39) and the whole slice is valid UTF-8.
    // SAFETY: Valid memory or trusted environment
    unsafe { core::str::from_utf8_unchecked(&buf[pos..]) }
}

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Reset the PTY table and index counter.  ONLY for use in kernel tests.
#[doc(hidden)]
pub fn __reset_for_test() {
    PTY_TABLE.lock().clear();
    NEXT_PTY_INDEX.store(0, Ordering::Relaxed);
}

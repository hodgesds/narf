//! Standard Linux errno definitions.
//!
//! Values match Linux `<asm-generic/errno-base.h>`, `<asm-generic/errno.h>`,
//! and `<linux/errno.h>`.
//!
//! Syscall handlers return negated error values (`-errno` as `u64` with status Ok).
//! Helper function [`to_wire`] converts positive errno constants into their
//! negative wire representations.

#![allow(dead_code)]

// ── Linux errno base (1..34) — <asm-generic/errno-base.h> ─────────────────

pub const EPERM: i64 = 1;
pub const ENOENT: i64 = 2;
pub const ESRCH: i64 = 3;
pub const EINTR: i64 = 4;
pub const EIO: i64 = 5;
pub const ENXIO: i64 = 6;
pub const E2BIG: i64 = 7;
pub const ENOEXEC: i64 = 8;
pub const EBADF: i64 = 9;
pub const ECHILD: i64 = 10;
pub const EAGAIN: i64 = 11;
pub const ENOMEM: i64 = 12;
pub const EACCES: i64 = 13;
pub const EFAULT: i64 = 14;
pub const ENOTBLK: i64 = 15;
pub const EBUSY: i64 = 16;
pub const EEXIST: i64 = 17;
pub const EXDEV: i64 = 18;
pub const ENODEV: i64 = 19;
pub const ENOTDIR: i64 = 20;
pub const EISDIR: i64 = 21;
pub const EINVAL: i64 = 22;
pub const ENFILE: i64 = 23;
pub const EMFILE: i64 = 24;
pub const ENOTTY: i64 = 25;
pub const ETXTBSY: i64 = 26;
pub const EFBIG: i64 = 27;
pub const ENOSPC: i64 = 28;
pub const ESPIPE: i64 = 29;
pub const EROFS: i64 = 30;
pub const EMLINK: i64 = 31;
pub const EPIPE: i64 = 32;
pub const EDOM: i64 = 33;
pub const ERANGE: i64 = 34;

// ── Linux errno extensions (35..134) — <asm-generic/errno.h> ──────────────

pub const EDEADLK: i64 = 35;
pub const ENAMETOOLONG: i64 = 36;
pub const ENOLCK: i64 = 37;
pub const ENOSYS: i64 = 38;
pub const ENOTEMPTY: i64 = 39;
pub const ELOOP: i64 = 40;
pub const EWOULDBLOCK: i64 = EAGAIN;
pub const ENOMSG: i64 = 42;
pub const EIDRM: i64 = 43;
pub const ECHRNG: i64 = 44;
pub const EL2NSYNC: i64 = 45;
pub const EL3HLT: i64 = 46;
pub const EL3RST: i64 = 47;
pub const ELNRNG: i64 = 48;
pub const EUNATCH: i64 = 49;
pub const ENOCSI: i64 = 50;
pub const EL2HLT: i64 = 51;
pub const EBADE: i64 = 52;
pub const EBADR: i64 = 53;
pub const EXFULL: i64 = 54;
pub const ENOANO: i64 = 55;
pub const EBADRQC: i64 = 56;
pub const EBADSLT: i64 = 57;
pub const EDEADLOCK: i64 = EDEADLK;
pub const EBFONT: i64 = 59;
pub const ENOSTR: i64 = 60;
pub const ENODATA: i64 = 61;
pub const ETIME: i64 = 62;
pub const ENOSR: i64 = 63;
pub const ENONET: i64 = 64;
pub const ENOPKG: i64 = 65;
pub const EREMOTE: i64 = 66;
pub const ENOLINK: i64 = 67;
pub const EADV: i64 = 68;
pub const ESRMNT: i64 = 69;
pub const ECOMM: i64 = 70;
pub const EPROTO: i64 = 71;
pub const EMULTIHOP: i64 = 72;
pub const EDOTDOT: i64 = 73;
pub const EBADMSG: i64 = 74;
pub const EFSBADCRC: i64 = EBADMSG;
pub const EOVERFLOW: i64 = 75;
pub const ENOTUNIQ: i64 = 76;
pub const EBADFD: i64 = 77;
pub const EREMCHG: i64 = 78;
pub const ELIBACC: i64 = 79;
pub const ELIBBAD: i64 = 80;
pub const ELIBSCN: i64 = 81;
pub const ELIBMAX: i64 = 82;
pub const ELIBEXEC: i64 = 83;
pub const EILSEQ: i64 = 84;
pub const ERESTART: i64 = 85;
pub const ESTRPIPE: i64 = 86;
pub const EUSERS: i64 = 87;
pub const ENOTSOCK: i64 = 88;
pub const EDESTADDRREQ: i64 = 89;
pub const EMSGSIZE: i64 = 90;
pub const EPROTOTYPE: i64 = 91;
pub const ENOPROTOOPT: i64 = 92;
pub const EPROTONOSUPPORT: i64 = 93;
pub const ESOCKTNOSUPPORT: i64 = 94;
pub const EOPNOTSUPP: i64 = 95;
pub const ENOTSUP: i64 = EOPNOTSUPP;
pub const EPFNOSUPPORT: i64 = 96;
pub const EAFNOSUPPORT: i64 = 97;
pub const EADDRINUSE: i64 = 98;
pub const EADDRNOTAVAIL: i64 = 99;
pub const ENETDOWN: i64 = 100;
pub const ENETUNREACH: i64 = 101;
pub const ENETRESET: i64 = 102;
pub const ECONNABORTED: i64 = 103;
pub const ECONNRESET: i64 = 104;
pub const ENOBUFS: i64 = 105;
pub const EISCONN: i64 = 106;
pub const ENOTCONN: i64 = 107;
pub const ESHUTDOWN: i64 = 108;
pub const ETOOMANYREFS: i64 = 109;
pub const ETIMEDOUT: i64 = 110;
pub const ECONNREFUSED: i64 = 111;
pub const EHOSTDOWN: i64 = 112;
pub const EHOSTUNREACH: i64 = 113;
pub const EALREADY: i64 = 114;
pub const EINPROGRESS: i64 = 115;
pub const ESTALE: i64 = 116;
pub const EUCLEAN: i64 = 117;
pub const EFSCORRUPTED: i64 = EUCLEAN;
pub const ENOTNAM: i64 = 118;
pub const ENAVAIL: i64 = 119;
pub const EISNAM: i64 = 120;
pub const EREMOTEIO: i64 = 121;
pub const EDQUOT: i64 = 122;
pub const ENOMEDIUM: i64 = 123;
pub const EMEDIUMTYPE: i64 = 124;
pub const ECANCELED: i64 = 125;
pub const ENOKEY: i64 = 126;
pub const EKEYEXPIRED: i64 = 127;
pub const EKEYREVOKED: i64 = 128;
pub const EKEYREJECTED: i64 = 129;
pub const EOWNERDEAD: i64 = 130;
pub const ENOTRECOVERABLE: i64 = 131;
pub const ERFKILL: i64 = 132;
pub const EHWPOISON: i64 = 133;
/// Wrong file type for the intended operation (`asm-generic/errno.h`, 134).
pub const EFTYPE: i64 = 134;

// ── Linux kernel-internal error codes (512..531) — <linux/errno.h> ────────

pub const ERESTARTSYS: i64 = 512;
pub const ERESTARTNOINTR: i64 = 513;
pub const ERESTARTNOHAND: i64 = 514;
pub const ENOIOCTLCMD: i64 = 515;
pub const ERESTART_RESTARTBLOCK: i64 = 516;
pub const EPROBE_DEFER: i64 = 517;
pub const EOPENSTALE: i64 = 518;
pub const ENOPARAM: i64 = 519;
pub const EBADHANDLE: i64 = 521;
pub const ENOTSYNC: i64 = 522;
pub const EBADCOOKIE: i64 = 523;
pub const ENOTSUPP: i64 = 524;
pub const ETOOSMALL: i64 = 525;
pub const ESERVERFAULT: i64 = 526;
pub const EBADTYPE: i64 = 527;
pub const EJUKEBOX: i64 = 528;
pub const EIOCBQUEUED: i64 = 529;
pub const ERECALLCONFLICT: i64 = 530;
pub const ENOGRACE: i64 = 531;

/// Convert a positive errno into the negative wire integer returned in syscall registers.
#[inline]
pub const fn to_wire(errno: i64) -> i64 {
    -errno
}

/// Negative wire return values for Linux errnos.
///
/// In syscall ABI conformance tests and wire comparisons, syscall return values
/// appear as negative integers.
pub mod wire {
    pub const EPERM: i64 = -super::EPERM;
    pub const ENOENT: i64 = -super::ENOENT;
    pub const ESRCH: i64 = -super::ESRCH;
    pub const EINTR: i64 = -super::EINTR;
    pub const EIO: i64 = -super::EIO;
    pub const ENXIO: i64 = -super::ENXIO;
    pub const E2BIG: i64 = -super::E2BIG;
    pub const ENOEXEC: i64 = -super::ENOEXEC;
    pub const EBADF: i64 = -super::EBADF;
    pub const ECHILD: i64 = -super::ECHILD;
    pub const EAGAIN: i64 = -super::EAGAIN;
    pub const ENOMEM: i64 = -super::ENOMEM;
    pub const EACCES: i64 = -super::EACCES;
    pub const EFAULT: i64 = -super::EFAULT;
    pub const ENOTBLK: i64 = -super::ENOTBLK;
    pub const EBUSY: i64 = -super::EBUSY;
    pub const EEXIST: i64 = -super::EEXIST;
    pub const EXDEV: i64 = -super::EXDEV;
    pub const ENODEV: i64 = -super::ENODEV;
    pub const ENOTDIR: i64 = -super::ENOTDIR;
    pub const EISDIR: i64 = -super::EISDIR;
    pub const EINVAL: i64 = -super::EINVAL;
    pub const ENFILE: i64 = -super::ENFILE;
    pub const EMFILE: i64 = -super::EMFILE;
    pub const ENOTTY: i64 = -super::ENOTTY;
    pub const ETXTBSY: i64 = -super::ETXTBSY;
    pub const EFBIG: i64 = -super::EFBIG;
    pub const ENOSPC: i64 = -super::ENOSPC;
    pub const ESPIPE: i64 = -super::ESPIPE;
    pub const EROFS: i64 = -super::EROFS;
    pub const EMLINK: i64 = -super::EMLINK;
    pub const EPIPE: i64 = -super::EPIPE;
    pub const EDOM: i64 = -super::EDOM;
    pub const ERANGE: i64 = -super::ERANGE;
    pub const EDEADLK: i64 = -super::EDEADLK;
    pub const ENAMETOOLONG: i64 = -super::ENAMETOOLONG;
    pub const ENOLCK: i64 = -super::ENOLCK;
    pub const ENOSYS: i64 = -super::ENOSYS;
    pub const ENOTEMPTY: i64 = -super::ENOTEMPTY;
    pub const ELOOP: i64 = -super::ELOOP;
    pub const EWOULDBLOCK: i64 = -super::EWOULDBLOCK;
    pub const ENOMSG: i64 = -super::ENOMSG;
    pub const EIDRM: i64 = -super::EIDRM;
    pub const ECHRNG: i64 = -super::ECHRNG;
    pub const EL2NSYNC: i64 = -super::EL2NSYNC;
    pub const EL3HLT: i64 = -super::EL3HLT;
    pub const EL3RST: i64 = -super::EL3RST;
    pub const ELNRNG: i64 = -super::ELNRNG;
    pub const EUNATCH: i64 = -super::EUNATCH;
    pub const ENOCSI: i64 = -super::ENOCSI;
    pub const EL2HLT: i64 = -super::EL2HLT;
    pub const EBADE: i64 = -super::EBADE;
    pub const EBADR: i64 = -super::EBADR;
    pub const EXFULL: i64 = -super::EXFULL;
    pub const ENOANO: i64 = -super::ENOANO;
    pub const EBADRQC: i64 = -super::EBADRQC;
    pub const EBADSLT: i64 = -super::EBADSLT;
    pub const EDEADLOCK: i64 = -super::EDEADLOCK;
    pub const EBFONT: i64 = -super::EBFONT;
    pub const ENOSTR: i64 = -super::ENOSTR;
    pub const ENODATA: i64 = -super::ENODATA;
    pub const ETIME: i64 = -super::ETIME;
    pub const ENOSR: i64 = -super::ENOSR;
    pub const ENONET: i64 = -super::ENONET;
    pub const ENOPKG: i64 = -super::ENOPKG;
    pub const EREMOTE: i64 = -super::EREMOTE;
    pub const ENOLINK: i64 = -super::ENOLINK;
    pub const EADV: i64 = -super::EADV;
    pub const ESRMNT: i64 = -super::ESRMNT;
    pub const ECOMM: i64 = -super::ECOMM;
    pub const EPROTO: i64 = -super::EPROTO;
    pub const EMULTIHOP: i64 = -super::EMULTIHOP;
    pub const EDOTDOT: i64 = -super::EDOTDOT;
    pub const EBADMSG: i64 = -super::EBADMSG;
    pub const EFSBADCRC: i64 = -super::EFSBADCRC;
    pub const EOVERFLOW: i64 = -super::EOVERFLOW;
    pub const ENOTUNIQ: i64 = -super::ENOTUNIQ;
    pub const EBADFD: i64 = -super::EBADFD;
    pub const EREMCHG: i64 = -super::EREMCHG;
    pub const ELIBACC: i64 = -super::ELIBACC;
    pub const ELIBBAD: i64 = -super::ELIBBAD;
    pub const ELIBSCN: i64 = -super::ELIBSCN;
    pub const ELIBMAX: i64 = -super::ELIBMAX;
    pub const ELIBEXEC: i64 = -super::ELIBEXEC;
    pub const EILSEQ: i64 = -super::EILSEQ;
    pub const ERESTART: i64 = -super::ERESTART;
    pub const ESTRPIPE: i64 = -super::ESTRPIPE;
    pub const EUSERS: i64 = -super::EUSERS;
    pub const ENOTSOCK: i64 = -super::ENOTSOCK;
    pub const EDESTADDRREQ: i64 = -super::EDESTADDRREQ;
    pub const EMSGSIZE: i64 = -super::EMSGSIZE;
    pub const EPROTOTYPE: i64 = -super::EPROTOTYPE;
    pub const ENOPROTOOPT: i64 = -super::ENOPROTOOPT;
    pub const EPROTONOSUPPORT: i64 = -super::EPROTONOSUPPORT;
    pub const ESOCKTNOSUPPORT: i64 = -super::ESOCKTNOSUPPORT;
    pub const EOPNOTSUPP: i64 = -super::EOPNOTSUPP;
    pub const ENOTSUP: i64 = -super::ENOTSUP;
    pub const EPFNOSUPPORT: i64 = -super::EPFNOSUPPORT;
    pub const EAFNOSUPPORT: i64 = -super::EAFNOSUPPORT;
    pub const EADDRINUSE: i64 = -super::EADDRINUSE;
    pub const EADDRNOTAVAIL: i64 = -super::EADDRNOTAVAIL;
    pub const ENETDOWN: i64 = -super::ENETDOWN;
    pub const ENETUNREACH: i64 = -super::ENETUNREACH;
    pub const ENETRESET: i64 = -super::ENETRESET;
    pub const ECONNABORTED: i64 = -super::ECONNABORTED;
    pub const ECONNRESET: i64 = -super::ECONNRESET;
    pub const ENOBUFS: i64 = -super::ENOBUFS;
    pub const EISCONN: i64 = -super::EISCONN;
    pub const ENOTCONN: i64 = -super::ENOTCONN;
    pub const ESHUTDOWN: i64 = -super::ESHUTDOWN;
    pub const ETOOMANYREFS: i64 = -super::ETOOMANYREFS;
    pub const ETIMEDOUT: i64 = -super::ETIMEDOUT;
    pub const ECONNREFUSED: i64 = -super::ECONNREFUSED;
    pub const EHOSTDOWN: i64 = -super::EHOSTDOWN;
    pub const EHOSTUNREACH: i64 = -super::EHOSTUNREACH;
    pub const EALREADY: i64 = -super::EALREADY;
    pub const EINPROGRESS: i64 = -super::EINPROGRESS;
    pub const ESTALE: i64 = -super::ESTALE;
    pub const EUCLEAN: i64 = -super::EUCLEAN;
    pub const EFSCORRUPTED: i64 = -super::EFSCORRUPTED;
    pub const ENOTNAM: i64 = -super::ENOTNAM;
    pub const ENAVAIL: i64 = -super::ENAVAIL;
    pub const EISNAM: i64 = -super::EISNAM;
    pub const EREMOTEIO: i64 = -super::EREMOTEIO;
    pub const EDQUOT: i64 = -super::EDQUOT;
    pub const ENOMEDIUM: i64 = -super::ENOMEDIUM;
    pub const EMEDIUMTYPE: i64 = -super::EMEDIUMTYPE;
    pub const ECANCELED: i64 = -super::ECANCELED;
    pub const ENOKEY: i64 = -super::ENOKEY;
    pub const EKEYEXPIRED: i64 = -super::EKEYEXPIRED;
    pub const EKEYREVOKED: i64 = -super::EKEYREVOKED;
    pub const EKEYREJECTED: i64 = -super::EKEYREJECTED;
    pub const EOWNERDEAD: i64 = -super::EOWNERDEAD;
    pub const ENOTRECOVERABLE: i64 = -super::ENOTRECOVERABLE;
    pub const ERFKILL: i64 = -super::ERFKILL;
    pub const EHWPOISON: i64 = -super::EHWPOISON;
    pub const EFTYPE: i64 = -super::EFTYPE;
}

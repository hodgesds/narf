//! `<sys/un.h>` + `<sys/socket.h>` extra struct surface.
//!
//! Real C programs reach for `struct sockaddr_un`, `struct msghdr`,
//! `struct cmsghdr`, and the matching `sendmsg` / `recvmsg` /
//! `socketpair` entries. None of these are wired to a working
//! kernel transport on NARF; the surface exists so a link succeeds,
//! and every functional entry refuses with `errno = ENOSYS`.
//!
//! The struct shapes match the SUSv4 `<sys/un.h>` / `<sys/socket.h>`
//! definitions on x86_64 and aarch64 so a binary compiled against
//! system headers observes the expected field offsets and array sizes.

#![allow(non_camel_case_types)]

use crate::net::{sa_family_t, socklen_t};
use crate::posix::{c_char, c_int, c_void, ssize_t};
use crate::random::iovec;

pub const ENOSYS: c_int = 38;

// ── struct sockaddr_un ──────────────────────────────────────────────

/// `<sys/un.h>` `struct sockaddr_un` — Unix-domain socket address.
/// `sun_path` is the conventional 108 bytes; the abstract-socket
/// trick (leading NUL) sits inside that array.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct sockaddr_un {
    pub sun_family: sa_family_t,
    pub sun_path:   [c_char; 108],
}

impl Default for sockaddr_un {
    fn default() -> Self {
        Self { sun_family: 0, sun_path: [0; 108] }
    }
}

// ── struct msghdr / cmsghdr ─────────────────────────────────────────

/// `<sys/socket.h>` `struct msghdr` — recvmsg / sendmsg packet
/// descriptor. Field layout per SUSv4.
#[repr(C)]
pub struct msghdr {
    pub msg_name:        *mut c_void,
    pub msg_namelen:     socklen_t,
    pub msg_iov:         *mut iovec,
    pub msg_iovlen:      usize,
    pub msg_control:     *mut c_void,
    pub msg_controllen:  usize,
    pub msg_flags:       c_int,
}

/// `<sys/socket.h>` `struct cmsghdr` — control-message header.
/// Real ancillary data lives in a packed buffer immediately after
/// this header; the macro family `CMSG_FIRSTHDR` / `CMSG_NXTHDR`
/// walks them. We expose the struct shape; the macros are
/// header-side and don't compile to a symbol here.
#[repr(C)]
pub struct cmsghdr {
    pub cmsg_len:    usize,
    pub cmsg_level:  c_int,
    pub cmsg_type:   c_int,
}

// MSG_* flag constants — values match Linux.
pub const MSG_OOB:       c_int = 0x0001;
pub const MSG_PEEK:      c_int = 0x0002;
pub const MSG_DONTROUTE: c_int = 0x0004;
pub const MSG_CTRUNC:    c_int = 0x0008;
pub const MSG_TRUNC:     c_int = 0x0020;
pub const MSG_DONTWAIT:  c_int = 0x0040;
pub const MSG_EOR:       c_int = 0x0080;
pub const MSG_WAITALL:   c_int = 0x0100;
pub const MSG_NOSIGNAL:  c_int = 0x4000;
pub const MSG_CMSG_CLOEXEC: c_int = 0x4000_0000_u32 as c_int;

// SCM_* / SOL_* level constants.
pub const SCM_RIGHTS:      c_int = 0x01;
pub const SCM_CREDENTIALS: c_int = 0x02;

// ── sendmsg / recvmsg / socketpair / sockatmark ─────────────────────
//
// All ENOSYS today. The entries exist purely so a C program that
// references them at link time gets a real symbol. When the kernel
// grows a transport these become real.

#[inline]
fn enosys_minus_one() -> ssize_t {
    crate::errno::set_errno(ENOSYS);
    -1
}

/// `sendmsg(sockfd, msg, flags)` — stub.
///
/// # Safety
/// Caller-supplied `msg`, when non-null, must point at a valid
/// `msghdr`. We don't read it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sendmsg(
    _sockfd: c_int,
    _msg:    *const msghdr,
    _flags:  c_int,
) -> ssize_t {
    enosys_minus_one()
}

/// `recvmsg(sockfd, msg, flags)` — stub.
///
/// # Safety
/// `msg`, when non-null, must point at a writable `msghdr`. We don't
/// touch it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn recvmsg(
    _sockfd: c_int,
    _msg:    *mut msghdr,
    _flags:  c_int,
) -> ssize_t {
    enosys_minus_one()
}

/// `socketpair(domain, type, protocol, sv[2])` — stub. `sv` is left
/// untouched.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn socketpair(
    _domain:   c_int,
    _type:     c_int,
    _protocol: c_int,
    _sv:       *mut c_int,
) -> c_int {
    crate::errno::set_errno(ENOSYS);
    -1
}

/// `sockatmark(sockfd)` — stub. Always returns -1 / ENOSYS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sockatmark(_sockfd: c_int) -> c_int {
    crate::errno::set_errno(ENOSYS);
    -1
}

/// `getpeername(sockfd, addr, addrlen)` — stub.
///
/// # Safety
/// `addr` and `addrlen`, when non-null, must point to writable storage
/// matching the C signature. We don't touch them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpeername(
    _sockfd:  c_int,
    _addr:    *mut crate::net::sockaddr,
    _addrlen: *mut socklen_t,
) -> c_int {
    crate::errno::set_errno(ENOSYS);
    -1
}

/// `getsockname(sockfd, addr, addrlen)` — stub. Mirrors `getpeername`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getsockname(
    _sockfd:  c_int,
    _addr:    *mut crate::net::sockaddr,
    _addrlen: *mut socklen_t,
) -> c_int {
    crate::errno::set_errno(ENOSYS);
    -1
}

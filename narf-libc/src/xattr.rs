//! Extended attribute surface: `getxattr` / `setxattr` /
//! `listxattr` / `removexattr` + path / fd / lname variants.
//!
//! NARF's FS layer doesn't yet store per-file extended attributes;
//! these surfaces all return -1 with errno = ENOTSUP. Real programs
//! either check for the error and skip the metadata they would
//! have stored (rsync, tar) or proceed without complaint. The
//! symbols exist so binaries link.

#![allow(non_camel_case_types)]

use crate::posix::c_int;
use core::ffi::c_void;

const ENOTSUP: c_int = 95;

#[inline]
fn enotsup() -> isize {
    crate::errno::set_errno(ENOTSUP);
    -1
}

/// `getxattr(path, name, value, size)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getxattr(
    _path: *const i8,
    _name: *const i8,
    _value: *mut c_void,
    _size: usize,
) -> isize {
    enotsup()
}

/// `lgetxattr(path, name, value, size)` — don't follow symlinks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lgetxattr(
    _path: *const i8,
    _name: *const i8,
    _value: *mut c_void,
    _size: usize,
) -> isize {
    enotsup()
}

/// `fgetxattr(fd, name, value, size)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fgetxattr(
    _fd:    c_int,
    _name:  *const i8,
    _value: *mut c_void,
    _size:  usize,
) -> isize {
    enotsup()
}

/// `setxattr(path, name, value, size, flags)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setxattr(
    _path:  *const i8,
    _name:  *const i8,
    _value: *const c_void,
    _size:  usize,
    _flags: c_int,
) -> c_int {
    enotsup() as c_int
}

/// `lsetxattr(path, name, value, size, flags)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lsetxattr(
    _path:  *const i8,
    _name:  *const i8,
    _value: *const c_void,
    _size:  usize,
    _flags: c_int,
) -> c_int {
    enotsup() as c_int
}

/// `fsetxattr(fd, name, value, size, flags)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsetxattr(
    _fd:    c_int,
    _name:  *const i8,
    _value: *const c_void,
    _size:  usize,
    _flags: c_int,
) -> c_int {
    enotsup() as c_int
}

/// `listxattr(path, list, size)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn listxattr(
    _path: *const i8,
    _list: *mut i8,
    _size: usize,
) -> isize {
    enotsup()
}

/// `llistxattr(path, list, size)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn llistxattr(
    _path: *const i8,
    _list: *mut i8,
    _size: usize,
) -> isize {
    enotsup()
}

/// `flistxattr(fd, list, size)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flistxattr(
    _fd:   c_int,
    _list: *mut i8,
    _size: usize,
) -> isize {
    enotsup()
}

/// `removexattr(path, name)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn removexattr(
    _path: *const i8,
    _name: *const i8,
) -> c_int {
    enotsup() as c_int
}

/// `lremovexattr(path, name)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lremovexattr(
    _path: *const i8,
    _name: *const i8,
) -> c_int {
    enotsup() as c_int
}

/// `fremovexattr(fd, name)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fremovexattr(
    _fd:   c_int,
    _name: *const i8,
) -> c_int {
    enotsup() as c_int
}

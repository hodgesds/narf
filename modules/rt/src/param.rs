//! The module's load parameters.
//!
//! A module declares parameters with defaults in a `.narf_kparams` section
//! (`name=value` lines). At load the kernel applies `<module>.<name>=value`
//! from the kernel command line, then the load's own `name=value` arguments,
//! and serves the result through `narf_module_param`. [`get`] reads one.

use alloc::string::String;
use alloc::vec;

use crate::abi;

/// Error reading a parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamError {
    /// The module declares no parameter of that name.
    Undeclared,
    /// The kernel returned this negative errno.
    Errno(i32),
    /// The value is not UTF-8.
    NotUtf8,
}

/// The current value of parameter `name`.
pub fn get(name: &str) -> Result<String, ParamError> {
    let mut len = 0usize;
    let mut buf = vec![0u8; 64];
    loop {
        // SAFETY: `name` is a live `&str`; `buf` names `buf.len()` writable
        // bytes; `len` is a live `usize`.
        let rc = unsafe {
            abi::narf_module_param(
                name.as_ptr(),
                name.len(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut len,
            )
        };
        match rc {
            0 => {
                buf.truncate(len);
                return String::from_utf8(buf).map_err(|_| ParamError::NotUtf8);
            }
            -2 => return Err(ParamError::Undeclared),
            // -ENOBUFS reports the needed length; retry once at that size.
            -105 if len > buf.len() => buf.resize(len, 0),
            errno => return Err(ParamError::Errno(errno)),
        }
    }
}

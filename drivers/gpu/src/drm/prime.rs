//! DRM PRIME — stub, expanded in a follow-up commit.

use alloc::vec::Vec;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PrimeError { NotFound, BadHandle, Full }

#[derive(Clone, Debug)]
pub struct PrimeBinding { pub handle: u32, pub fd: i32 }

#[derive(Debug, Default)]
pub struct PrimeTable { bindings: Vec<PrimeBinding>, next_fd: i32 }
impl PrimeTable { pub fn new() -> Self { PrimeTable { bindings: Vec::new(), next_fd: 4096 } } }

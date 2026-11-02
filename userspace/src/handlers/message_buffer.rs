//! Bounded socket-message scratch storage. Small native iovec/control arrays
//! and payloads stay on the syscall stack; larger messages retain a fallible
//! heap fallback. Every byte exposed to a copy or protocol handler is initialized.

use alloc::collections::TryReserveError;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

#[derive(Debug)]
pub(super) enum MessageBuffer<const INLINE: usize> {
    Inline { data: [u8; INLINE], len: usize },
    Heap(Vec<u8>),
}

impl<const INLINE: usize> MessageBuffer<INLINE> {
    pub(super) fn try_new(len: usize) -> Result<Self, TryReserveError> {
        if len <= INLINE {
            Ok(Self::Inline {
                data: [0; INLINE],
                len,
            })
        } else {
            let mut data = Vec::new();
            data.try_reserve_exact(len)?;
            data.resize(len, 0);
            Ok(Self::Heap(data))
        }
    }
}

impl<const INLINE: usize> Deref for MessageBuffer<INLINE> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Self::Inline { data, len } => &data[..*len],
            Self::Heap(data) => data,
        }
    }
}

impl<const INLINE: usize> DerefMut for MessageBuffer<INLINE> {
    fn deref_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Inline { data, len } => &mut data[..*len],
            Self::Heap(data) => data,
        }
    }
}

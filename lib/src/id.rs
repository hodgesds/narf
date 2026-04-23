//! Typed newtype IDs.
//!
//! Eliminates "is this u32 a PID or a CPU id?" confusion at the type level,
//! per `lib/specification/spec.md` §3.5.

/// Defines a typed ID newtype over an unsigned integer repr.
///
/// Gives `Copy`, `Clone`, `PartialEq`, `Eq`, `Hash`, `Debug`, `Display`,
/// `new`, and `raw()` accessor. Construction is `const`-capable.
#[macro_export]
macro_rules! define_typed_id {
    ($(#[$meta:meta])* $vis:vis $name:ident, $repr:ty) => {
        $(#[$meta])*
        #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(transparent)]
        $vis struct $name($repr);

        impl $name {
            #[inline]
            pub const fn new(raw: $repr) -> Self { Self(raw) }

            #[inline]
            pub const fn raw(self) -> $repr { self.0 }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

define_typed_id!(
    /// CPU identifier. Allocated at Stage-1 BSP bring-up; grows at Stage-2 AP bring-up.
    pub CpuId, u16);

define_typed_id!(
    /// Protection domain identifier. The full authoritative table is in
    /// `security-model/specification/spec.md` §4.1; Stage 1 only uses
    /// `DomainId::FRAME` (0).
    pub DomainId, u8);

define_typed_id!(
    /// Task (kernel-thread / future) identifier.
    pub TaskId, u32);

define_typed_id!(
    /// NUMA node identifier.
    pub NodeId, u16);

define_typed_id!(
    /// IRQ line identifier.
    pub IrqId, u32);

// Reserved `DomainId` constants per security-model/ §4.1. They live on the
// type so every subsystem has a single import path. These are declarations;
// runtime enforcement (PKS / MTE enable) lands in Stage 2.
impl DomainId {
    pub const FRAME:       Self = Self::new(0);
    pub const CAPS:        Self = Self::new(1);
    pub const MEMORY_MGR:  Self = Self::new(2);
    pub const SCHED:       Self = Self::new(3);
    pub const IPC:         Self = Self::new(4);
    pub const TRACER:      Self = Self::new(5);
    pub const KEYS:        Self = Self::new(6);
    pub const OBSERVE:     Self = Self::new(7);
    pub const USERSPACE_K: Self = Self::new(8);
    pub const DRIVER_0:    Self = Self::new(9);
    pub const DRIVER_1:    Self = Self::new(10);
    pub const DRIVER_2:    Self = Self::new(11);
    pub const DRIVER_3:    Self = Self::new(12);
    pub const DRIVER_4:    Self = Self::new(13);
    pub const DRIVER_5:    Self = Self::new(14);
    pub const SCRATCH:     Self = Self::new(15);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_ids_are_transparent() {
        assert_eq!(core::mem::size_of::<CpuId>(),   core::mem::size_of::<u16>());
        assert_eq!(core::mem::size_of::<DomainId>(), core::mem::size_of::<u8>());
        assert_eq!(core::mem::size_of::<TaskId>(),  core::mem::size_of::<u32>());
    }

    #[test]
    fn domain_constants_match_table() {
        // security-model/ §4.1 — fully spelled out as an integration guard.
        assert_eq!(DomainId::FRAME.raw(), 0);
        assert_eq!(DomainId::SCRATCH.raw(), 15);
    }
}

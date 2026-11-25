//! `narf_lib` for the module: the async mutex and the spin lock from
//! `narf-module-rt`, and the allocation-domain name.
//!
//! Module text never runs in hard-IRQ context, so the module-rt spin lock
//! (whose guard is `!Send`, like the kernel's IRQ-safe guard) needs no
//! interrupt masking to stand in for `IrqSafeSpinLock`.

pub mod mutex {
    pub use narf_module_rt::sync::Mutex;
}

pub mod sync {
    pub use narf_module_rt::sync::SpinLock as IrqSafeSpinLock;
}

pub mod id {
    /// Allocation domain. The module allocates in its own effective domain
    /// whatever the driver asks for; the type keeps the built-in signature.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct DomainId;
    impl DomainId {
        pub const DRIVER_0: DomainId = DomainId;
    }
}

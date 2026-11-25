//! `narf_capabilities` for the module: the `Cap<T, R>` / `CapOp` shapes the
//! driver's firmware paths are written against.
//!
//! Built in, the driver holds a capability for the trusted firmware loader
//! and for each blob it opens, and re-proves each before use. A module's
//! authority is its manifest's `Firmware:Read` grant, which the kernel
//! checks at every `narf_firmware_*` call; nothing the module holds can be
//! revoked independently of the module itself. So a `Cap` here is a plain
//! token naming what it was opened for, and `invoke` always runs the
//! operation — the kernel side is where the check is.

use core::marker::PhantomData;

/// A right a capability carries.
pub trait Rights: Copy + 'static {}

/// Read right.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Read;
impl Rights for Read {}

/// Write right.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Write;
impl Rights for Write {}

/// Why a capability operation was refused (never, in the module).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapError {
    Revoked,
}

/// A token for object `T` with right `R`. `id` names the object (a cached
/// firmware file's slot for a blob; 0 for the loader).
pub struct Cap<T, R> {
    id: u64,
    _marker: PhantomData<fn() -> (T, R)>,
}

impl<T, R> Clone for Cap<T, R> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T, R> Copy for Cap<T, R> {}
impl<T, R> PartialEq for Cap<T, R> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl<T, R> Eq for Cap<T, R> {}
impl<T, R> core::fmt::Debug for Cap<T, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Cap").field("id", &self.id).finish()
    }
}

impl<T, R: Rights> Cap<T, R> {
    /// The token for object `id`.
    pub(crate) const fn token(id: u64) -> Self {
        Self {
            id,
            _marker: PhantomData,
        }
    }
    /// The object this token names.
    pub(crate) const fn id(&self) -> u64 {
        self.id
    }
    /// A token for the same object with right `R2`.
    pub fn derive<R2: Rights>(&self) -> Result<Cap<T, R2>, CapError> {
        Ok(Cap::token(self.id))
    }
    /// Run `op` against this capability.
    pub fn invoke<O: CapOp<T, R>>(&self, op: O) -> Result<O::Output, CapError> {
        op.execute(self)
    }
    /// The capability is current (always, in the module).
    pub fn check_live(&self) -> Result<(), CapError> {
        Ok(())
    }
}

/// An operation run under a capability.
pub trait CapOp<T, R: Rights>: Sized {
    type Output;
    fn execute(self, cap: &Cap<T, R>) -> Result<Self::Output, CapError>;
}

/// The operation that only proves the capability current.
#[derive(Copy, Clone, Debug, Default)]
pub struct NoopOp;

impl<T, R: Rights> CapOp<T, R> for NoopOp {
    type Output = ();
    fn execute(self, _cap: &Cap<T, R>) -> Result<(), CapError> {
        Ok(())
    }
}

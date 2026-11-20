// SPDX-License-Identifier: GPL-2.0-or-later
//! Current-per-access AE factory IO and qualified native poll/access adapter.
use super::{
    radio_policy::{PowerGrant, QualifiedProgram},
    retained::{Backend, Retained},
};
use crate::rtlwifi::{
    firmware_transport::{Error as AccessError, Identity, Io},
    prepare::Error,
};
use alloc::{boxed::Box, sync::Arc};
use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
};

pub(super) struct FactoryIo<I: Backend> {
    root: Arc<Retained<I>>,
    identity: Identity,
    may_be_on: AtomicBool,
    closing: AtomicBool,
    qualified: Option<Arc<QualifiedIo<I>>>,
}
impl<I: Backend> FactoryIo<I> {
    pub(super) fn new(root: Arc<Retained<I>>, identity: Identity) -> Self {
        Self {
            root,
            identity,
            may_be_on: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            qualified: None,
        }
    }
    fn current<T>(&self, f: impl FnOnce(&I) -> Result<T, AccessError>) -> Result<T, AccessError> {
        match &self.qualified {
            Some(qualified) => qualified.access(f),
            None => self.root.current(self.identity, f),
        }
    }
    fn cleanup<T>(&self, f: impl FnOnce(&I) -> Result<T, AccessError>) -> Result<T, AccessError> {
        // Restrictive EFUSE ACCESS0/readback only: current original PCI remains
        // mandatory even if registration or executable source was retired.
        self.root.firmware_backend().current(f)
    }
}
#[async_trait::async_trait]
impl<I: Backend> Io for FactoryIo<I> {
    fn read8(&self, reg: u16) -> Result<u8, AccessError> {
        if reg == 0xcf && self.closing.load(Ordering::Acquire) {
            self.cleanup(|io| io.read8(reg))
        } else {
            self.current(|io| io.read8(reg))
        }
    }
    fn read16(&self, reg: u16) -> Result<u16, AccessError> {
        self.current(|io| io.read16(reg))
    }
    fn read32(&self, reg: u16) -> Result<u32, AccessError> {
        self.current(|io| io.read32(reg))
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), AccessError> {
        if reg == 0xcf && value == 0 {
            if !self.may_be_on.load(Ordering::Acquire) {
                return Err(AccessError::Gate);
            }
            self.closing.store(true, Ordering::Release);
            return self.cleanup(|io| io.write8(reg, value));
        }
        if reg == 0xcf && value == 0x69 {
            self.may_be_on.store(true, Ordering::Release);
        }
        self.current(|io| io.write8(reg, value))
    }
    fn write16(&self, reg: u16, value: u16) -> Result<(), AccessError> {
        self.current(|io| io.write16(reg, value))
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), AccessError> {
        self.current(|io| io.write32(reg, value))
    }
    fn write_bytes(&self, _: u16, _: &[u8]) -> Result<(), AccessError> {
        Err(AccessError::Gate)
    }
}

/// Prepared policy evidence, not station admission. Constructor is private
/// and used only by the retained native preparation supervisor.
/// Policy binding derives it from THIS original cold Bound and
/// live Inputs; no borrowed/caller replacement grants or arbitrary policy fn.
pub(super) struct QualifiedIo<I: Backend> {
    root: Arc<Retained<I>>,
    identity: Identity,
    program: Arc<QualifiedProgram>,
    grant: PowerGrant,
    domain: Arc<narf_wireless::reg::RegulatoryDomain>,
    source: Policy,
}
enum Policy {
    Native,
    #[cfg(any(test, feature = "kernel-test"))]
    Fixture(Arc<narf_wireless::reg::db::Database>),
}
impl Policy {
    fn snapshot(&self) -> Option<Arc<narf_wireless::reg::RegulatoryDomain>> {
        match self {
            Self::Native => narf_wireless::reg::db::snapshot(),
            #[cfg(any(test, feature = "kernel-test"))]
            Self::Fixture(database) => database.snapshot(),
        }
    }
}
impl<I: Backend> QualifiedIo<I> {
    /// Native-only constructor: the Program has already bound the original
    /// cold Box, actual acquired Inputs and all three signed source identities.
    pub(super) fn bind(
        root: Arc<Retained<I>>,
        identity: Identity,
        program: Arc<QualifiedProgram>,
        domain: Arc<narf_wireless::reg::RegulatoryDomain>,
    ) -> Result<Arc<Self>, Error> {
        let grant = program.grant_for(&domain)?;
        let io = Arc::new(Self {
            root,
            identity,
            program,
            grant,
            domain,
            source: Policy::Native,
        });
        io.invoke(|_| Ok(()))?;
        Ok(io)
    }
    pub(super) fn grant(&self) -> &PowerGrant {
        &self.grant
    }
    pub(super) fn factory(self: &Arc<Self>) -> FactoryIo<I> {
        FactoryIo {
            root: self.root.clone(),
            identity: self.identity,
            may_be_on: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            qualified: Some(self.clone()),
        }
    }
    pub(super) fn invoke<T>(
        &self,
        f: impl FnOnce(&I) -> Result<T, AccessError>,
    ) -> Result<T, Error> {
        self.program.invoke(|| {
            if !self.root.radio_allowed() {
                return Err(Error::RadioOff);
            }
            let now = self.source.snapshot().ok_or(Error::State)?;
            if !Arc::ptr_eq(&now, &self.domain) || self.program.grant_for(&now)? != self.grant {
                return Err(Error::State);
            }
            self.root.current(self.identity, f).map_err(Error::Access)
        })
    }
    pub(super) fn program(&self) -> &Arc<QualifiedProgram> {
        &self.program
    }
    pub(super) fn current_domain(
        &self,
    ) -> Result<Arc<narf_wireless::reg::RegulatoryDomain>, Error> {
        self.invoke(|_| Ok(self.domain.clone()))
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn bind_fixture(
        root: Arc<Retained<I>>,
        identity: Identity,
        program: Arc<QualifiedProgram>,
        database: Arc<narf_wireless::reg::db::Database>,
    ) -> Result<Arc<Self>, Error> {
        // A selected fixture DB never falls back to global policy.
        let domain = database.snapshot().ok_or(Error::State)?;
        let grant = program.grant_for(&domain)?;
        let io = Arc::new(Self {
            root,
            identity,
            program,
            grant,
            domain,
            source: Policy::Fixture(database),
        });
        io.invoke(|_| Ok(()))?;
        Ok(io)
    }
    /// The ACTUAL child poll executes inside firmware/NAPC/NAQR + current
    /// PCI invocation; this never checks Noop then polls outside the guard.
    /// Native reads/writes below independently invoke again per actual access.
    #[inline(never)]
    pub(super) fn poll<F: Future + ?Sized>(
        &self,
        future: Pin<&mut F>,
        cx: &mut Context<'_>,
    ) -> Result<Poll<F::Output>, Error> {
        self.invoke(|io| {
            Ok(
                super::radio_switch::on(io, self.program.inputs().adapter().version)
                    .map(|()| future.poll(cx)),
            )
        })?
    }
    fn access<T>(&self, f: impl FnOnce(&I) -> Result<T, AccessError>) -> Result<T, AccessError> {
        self.invoke(f).map_err(|e| match e {
            Error::Access(e) => e,
            _ => AccessError::Gate,
        })
    }
}
#[async_trait::async_trait]
impl<I: Backend> Io for QualifiedIo<I> {
    fn read8(&self, reg: u16) -> Result<u8, AccessError> {
        self.access(|io| io.read8(reg))
    }
    fn read16(&self, reg: u16) -> Result<u16, AccessError> {
        self.access(|io| io.read16(reg))
    }
    fn read32(&self, reg: u16) -> Result<u32, AccessError> {
        self.access(|io| io.read32(reg))
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), AccessError> {
        self.access(|io| io.write8(reg, value))
    }
    fn write16(&self, reg: u16, value: u16) -> Result<(), AccessError> {
        self.access(|io| io.write16(reg, value))
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), AccessError> {
        self.access(|io| io.write32(reg, value))
    }
    fn write_bytes(&self, _: u16, _: &[u8]) -> Result<(), AccessError> {
        Err(AccessError::Gate)
    }
    async fn delay_us(&self, us: u64) {
        // Native PciIo uses the regular timer/pump bridge; a Rust register
        // actor may expose its own actual pending source wait. This does not
        // move the resumed poll outside QualifiedIo::poll's current guards.
        self.root.firmware_backend().delay_us(us).await;
    }
}

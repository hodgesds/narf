//! Terminal-only identity after actual native control-child retirement.
use super::*;
use core::sync::atomic::{AtomicU8, Ordering};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Debug)]
pub(super) struct TerminalSlot {
    phase: AtomicU8,
    receipt: IrqSafeSpinLock<Option<Weak<Retired>>>,
}
impl Default for TerminalSlot {
    fn default() -> Self {
        Self {
            phase: AtomicU8::new(LIVE),
            receipt: IrqSafeSpinLock::new(None),
        }
    }
}
const LIVE: u8 = 0;
const WITHDRAWING: u8 = 1;
const RETIRED: u8 = 2;
struct Withdrawing<'a>(&'a AtomicU8);
impl Drop for Withdrawing<'_> {
    fn drop(&mut self) {
        let _ = self
            .0
            .compare_exchange(WITHDRAWING, LIVE, Ordering::AcqRel, Ordering::Acquire);
    }
}

/// This receipt can only keep the original request's final ACK current. It
/// contains no new administrative operation and cannot select a successor.
#[derive(Clone, Debug)]
pub struct RadioControlRetirement {
    inner: Arc<Retired>,
}
struct Retired {
    authority: RadioControlAuthority,
    iface: Arc<dyn WirelessNetIface>,
    control: crate::registry::ControlWdev,
    net: narf_net::ControlRetirement,
}
impl fmt::Debug for Retired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Retired")
            .field("authority", &self.authority)
            .field("control", &self.control)
            .finish_non_exhaustive()
    }
}
impl RadioControlAuthority {
    /// Only the frontend's outstanding DEL waiter may use this terminal
    /// observation. Normal current()/native-command checks remain denied
    /// after withdrawal. A transition can keep a waiter pending, never ACK
    /// success: its callback must still return the actual typed receipt.
    pub(crate) fn retirement_wait_current(&self) -> bool {
        if self.terminal.phase.load(Ordering::Acquire) == LIVE && self.current().is_ok() {
            return true;
        }
        // Re-read after a failed live check: removal may have raced that
        // check. RETIRED is published only after its Weak receipt, so an
        // observer cannot miss the handoff or revive normal administration.
        match self.terminal.phase.load(Ordering::Acquire) {
            WITHDRAWING => {
                self.guard.reply.current()
                    && self
                        .guard
                        .reservation
                        .as_ref()
                        .is_some_and(|lease| lease.current())
            }
            RETIRED => {
                let receipt = {
                    self.terminal
                        .receipt
                        .lock()
                        .as_ref()
                        .and_then(Weak::upgrade)
                };
                receipt.is_some_and(|inner| RadioControlRetirement { inner }.current())
            }
            _ => false,
        }
    }
    /// Call only after this exact child's native firmware/RF/packet owner has
    /// actually retired. All real administrative grants are invoked again at
    /// withdrawal. A closed source may still complete cleanup, but can never
    /// publish a successful terminal result. No driver callback runs under a
    /// registry lock, and no further command is authorized by the receipt.
    pub fn retire_control(
        &self,
        cap: &Cap<narf_net::NetIface, Write>,
    ) -> Result<RadioControlRetirement, WirelessError> {
        let guard = &self.guard;
        let iface = guard.iface.upgrade().ok_or(WirelessError::Denied)?;
        let target::Target::Control(control) = guard.target else {
            return Err(WirelessError::Denied);
        };
        if guard.mode != 10
            || iface.current_iftype() != 10
            || iface.radio_control_generation() != Some(guard.generation)
            || !guard.target.current(iface.as_ref(), guard.namespace, false)
            || !crate::registry::list()
                .iter()
                .any(|actual| Arc::ptr_eq(actual, &iface))
            || !guard.has_reservation()
            || guard
                .reservation
                .as_ref()
                .is_none_or(|lease| !lease.current())
        {
            return Err(WirelessError::Denied);
        }
        self.terminal
            .phase
            .compare_exchange(LIVE, WITHDRAWING, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| WirelessError::Busy)?;
        let _transition = Withdrawing(&self.terminal.phase);
        let net = guard
            .admin
            .retire_control_child(cap, guard.namespace)
            .map_err(|_| WirelessError::Denied)?;
        if !crate::registry::retire_control(control, &iface) {
            // Native retirement and net withdrawal are already complete.
            // Release only this old metadata object, outside registry locks.
            iface.release_control_metadata();
            return Err(WirelessError::Denied);
        }
        let retired = RadioControlRetirement {
            inner: Arc::new(Retired {
                authority: self.clone(),
                iface,
                control,
                net,
            }),
        };
        let previous = {
            self.terminal
                .receipt
                .lock()
                .replace(Arc::downgrade(&retired.inner))
        };
        drop(previous);
        self.terminal.phase.store(RETIRED, Ordering::Release);
        Ok(retired)
    }
}
impl RadioControlRetirement {
    pub fn current(&self) -> bool {
        let retained = &self.inner;
        let guard = &retained.authority.guard;
        guard.reply.current()
            && guard
                .reservation
                .as_ref()
                .is_some_and(|lease| lease.current())
            && retained.net.current()
            && retained.iface.control_namespace() == Some(guard.namespace)
            && retained.iface.current_iftype() == guard.mode
            && retained.iface.radio_control_generation() == Some(guard.generation)
            && crate::registry::retired_control_current(retained.control, &retained.iface)
    }
}
impl narf_net::netlink_generic::DeferredAuthority for RadioControlRetirement {
    fn current(&self) -> bool {
        RadioControlRetirement::current(self)
    }
}
impl Drop for Retired {
    fn drop(&mut self) {
        crate::registry::unregister_control(self.control, self.iface.as_ref());
        self.iface.release_control_metadata();
    }
}

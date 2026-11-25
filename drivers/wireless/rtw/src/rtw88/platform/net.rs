//! `narf_net` for the module: the frame and netdev shapes the station shell
//! (`interface.rs`) is written against, with its stack hooks routed to the
//! module's netdev (`iface_module.rs`).
//!
//! Built in, the shell registers itself with the kernel network stack and
//! reports carrier and received frames by interface name. In the module the
//! one netdev is the netif-bridge interface `iface_module` registered, so
//! the same calls — `iface::set_link_metadata`, `iface::on_rx_frame_from`,
//! `iface::lookup` / `OpenStopEvent::observe` — land there.

use super::narf_io::DmaBuffer;
use super::narf_ipc::{Consumer, Producer};
use super::narf_lib::sync::IrqSafeSpinLock;

/// Shell RX ring depth (the built-in value).
pub const RX_RING_N: usize = 1024;
/// Shell TX ring depth (the built-in value).
pub const TX_RING_N: usize = 1024;

/// L4 checksum offload kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L4CsumKind {
    Tcp,
    Udp,
    Sctp,
}

/// Per-frame TX offload requests. The module's netdev never offers an
/// offload, so the stack always sends [`TxMeta::plain`].
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TxMeta {
    pub csum_l4: Option<L4CsumKind>,
    pub tso_mss: Option<u16>,
    pub vlan_tag: Option<u16>,
    pub more: bool,
}

impl TxMeta {
    /// A plain data frame with no offloads.
    pub const fn plain() -> Self {
        Self {
            csum_l4: None,
            tso_mss: None,
            vlan_tag: None,
            more: false,
        }
    }
}

/// Offloads a netdev supports (none, in the module).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct OffloadCapabilities {
    pub tx_checksum: bool,
    pub rx_checksum: bool,
    pub max_tso_bytes: u32,
    pub vlan_insert: bool,
}

/// One Ethernet frame in a shell ring.
#[derive(Debug)]
pub struct Frame {
    buf: DmaBuffer,
    len: u32,
    tx_meta: TxMeta,
}

impl Frame {
    /// A frame of `len` bytes over `buf`.
    pub fn new(buf: DmaBuffer, len: u32) -> Self {
        let len = len.min(buf.len() as u32);
        Self {
            buf,
            len,
            tx_meta: TxMeta::plain(),
        }
    }
    pub fn len(&self) -> u32 {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn payload(&self) -> &[u8] {
        &self.buf.as_slice()[..self.len as usize]
    }
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let len = self.len as usize;
        &mut self.buf.as_mut_slice()[..len]
    }
    pub fn tx_meta(&self) -> TxMeta {
        self.tx_meta
    }
    pub fn set_tx_meta(&mut self, meta: TxMeta) {
        self.tx_meta = meta;
    }
}

/// A network interface (the station shell implements it).
pub trait Interface: Send + Sync {
    fn name(&self) -> &str;
    fn mac(&self) -> [u8; 6];
    fn mtu(&self) -> u32;
    fn link_up(&self) -> bool;
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>;
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>;
}

/// Provider lifetimes for native emission fences (the kernel's
/// `native_emission`, which is plain data plus wakers).
pub mod native_emission {
    use alloc::sync::{Arc, Weak};
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, Ordering};
    use core::task::Waker;

    use super::IrqSafeSpinLock;

    struct State {
        live: AtomicBool,
        waiters: IrqSafeSpinLock<Vec<Waker>>,
    }

    impl core::fmt::Debug for State {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("State")
                .field("live", &self.live)
                .finish_non_exhaustive()
        }
    }

    /// Owned by the registration (the module netdev).
    #[derive(Clone, Debug)]
    pub struct ProviderLifetime(Arc<State>);
    /// A weak, non-revivable observation.
    #[derive(Clone, Debug)]
    pub struct Lifetime(Weak<State>);

    impl Default for ProviderLifetime {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ProviderLifetime {
        pub fn new() -> Self {
            Self(Arc::new(State {
                live: AtomicBool::new(true),
                waiters: IrqSafeSpinLock::new(Vec::new()),
            }))
        }
        pub fn observe(&self) -> Lifetime {
            Lifetime(Arc::downgrade(&self.0))
        }
        /// Close the fence and wake every watcher.
        pub fn retire(&self) {
            self.0.live.store(false, Ordering::Release);
            let waiters = core::mem::take(&mut *self.0.waiters.lock());
            for waker in waiters {
                waker.wake();
            }
        }
    }

    impl Lifetime {
        pub fn current(&self) -> bool {
            self.0
                .upgrade()
                .is_some_and(|state| state.live.load(Ordering::Acquire))
        }
        pub fn watch(&self, waker: Waker) -> bool {
            let Some(state) = self.0.upgrade() else {
                return false;
            };
            {
                let mut waiters = state.waiters.lock();
                if !state.live.load(Ordering::Acquire) {
                    return false;
                }
                if !waiters.iter().any(|old| old.will_wake(&waker)) {
                    if waiters.len() == 64 {
                        return false;
                    }
                    waiters.push(waker);
                }
            }
            state.live.load(Ordering::Acquire)
        }
    }
}

/// Netdev administration by name, answered by the module netdev.
pub mod iface {
    use super::native_emission::Lifetime;
    use crate::rtw88::iface_module;

    /// What `lookup` reports of a registered netdev.
    #[derive(Clone, Debug)]
    pub struct NetIfaceSnapshot {
        pub name: &'static str,
        pub mac: [u8; 6],
        pub link_up: bool,
    }

    /// The netdev registered under `name`.
    pub fn lookup(name: &str) -> Option<NetIfaceSnapshot> {
        iface_module::lookup(name)
    }

    /// An administrative open/stop observation of one registration.
    #[derive(Clone, Debug)]
    pub struct OpenStopEvent {
        snapshot: NetIfaceSnapshot,
        identity: Option<Lifetime>,
    }

    impl OpenStopEvent {
        /// The current administrative state of `expected`'s registration.
        pub fn observe(expected: &NetIfaceSnapshot) -> Option<Self> {
            let identity = iface_module::identity(expected.name)?;
            Some(Self {
                snapshot: expected.clone(),
                identity: Some(identity),
            })
        }
        /// IFF_UP. The module netdev is opened at registration (it has no
        /// IFF_UP event), as `ath11k.ko`'s is.
        pub fn up(&self) -> bool {
            self.snapshot.link_up || self.identity.is_some()
        }
        /// The registration's native emission identity while it is up.
        pub fn native_identity(&self) -> Option<Lifetime> {
            self.identity.clone()
        }
        /// The observation still names the live registration.
        pub fn current(&self) -> bool {
            self.identity.as_ref().is_some_and(Lifetime::current)
        }
    }

    /// Link duplex (unused; the module reports carrier only).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum LinkDuplex {
        Half,
        Full,
    }

    /// Carrier for `name`.
    pub fn set_link_metadata(
        name: &str,
        carrier: bool,
        _speed_mbps: Option<u32>,
        _duplex: Option<LinkDuplex>,
    ) -> bool {
        iface_module::set_carrier(name, carrier)
    }

    /// Deliver one received Ethernet frame from `name` to the stack.
    pub fn on_rx_frame_from(name: &str, frame: &mut [u8]) {
        iface_module::deliver(name, frame);
    }

    /// The module keeps no name across a rebind (no reset is carried).
    pub fn rebind_name(_name: &str) -> Option<&'static str> {
        None
    }

    /// Retire `name` for a rebind: the module withdraws it instead.
    pub fn retire_for_rebind(name: &str) -> bool {
        iface_module::withdraw(name);
        false
    }

    /// Withdraw `name`.
    pub fn unregister(name: &str) {
        iface_module::withdraw(name);
    }
}

/// The network registry (the shell unregisters itself on withdrawal).
pub fn registry() -> Registry {
    Registry
}

/// The module's view of the network registry.
#[derive(Clone, Copy, Debug)]
pub struct Registry;

impl Registry {
    pub fn unregister(&self, name: &str) {
        iface_module::withdraw(name);
    }
}

use crate::rtw88::iface_module;

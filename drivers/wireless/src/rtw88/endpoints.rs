// SPDX-License-Identifier: GPL-2.0-or-later
//! Per-generation netdev dispatch. Cookies are never reused during a boot;
//! a copied send hook from a retired shell cannot target its replacement.
use alloc::{string::String, sync::Arc, vec::Vec};
use narf_lib::sync::IrqSafeSpinLock;

pub(super) const MAX_FUNCTIONS: usize = 4;
pub(super) trait Endpoint: Send + Sync {
    fn send(&self, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()>;
    fn drain(&self) -> bool;
}
struct Entry {
    cookie: u64,
    name: String,
    endpoint: Arc<dyn Endpoint>,
}
struct Pool {
    next: u64,
    entries: Vec<Entry>,
}
impl Pool {
    const fn new() -> Self {
        Self {
            next: 1,
            entries: Vec::new(),
        }
    }
    fn insert(&mut self, name: &str, endpoint: Arc<dyn Endpoint>) -> Result<u64, ()> {
        if self.entries.len() == MAX_FUNCTIONS
            || self.entries.iter().any(|entry| entry.name == name)
        {
            return Err(());
        }
        let cookie = self.next;
        self.next = self.next.checked_add(1).ok_or(())?;
        self.entries.push(Entry {
            cookie,
            name: name.into(),
            endpoint,
        });
        Ok(cookie)
    }
    fn get(&self, cookie: u64) -> Option<Arc<dyn Endpoint>> {
        self.entries
            .iter()
            .find(|entry| entry.cookie == cookie)
            .map(|entry| entry.endpoint.clone())
    }
    fn remove(&mut self, endpoint: *const ()) {
        self.entries
            .retain(|entry| Arc::as_ptr(&entry.endpoint) as *const () != endpoint);
    }
}
static ENDPOINTS: IrqSafeSpinLock<Pool> = IrqSafeSpinLock::new(Pool::new());

pub(super) fn insert(name: &str, endpoint: Arc<dyn Endpoint>) -> Result<u64, ()> {
    ENDPOINTS.lock().insert(name, endpoint)
}
pub(super) fn remove(endpoint: *const ()) {
    ENDPOINTS.lock().remove(endpoint);
}
pub(super) fn send(cookie: u64, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let endpoint = ENDPOINTS.lock().get(cookie).ok_or(())?;
    endpoint.send(bytes, meta)
}
pub(super) fn drain() -> bool {
    let endpoints: Vec<_> = ENDPOINTS
        .lock()
        .entries
        .iter()
        .map(|entry| entry.endpoint.clone())
        .collect();
    // Do not short-circuit: every independently owned ring gets a turn.
    let mut any = false;
    for endpoint in endpoints {
        any |= endpoint.drain();
    }
    any
}
#[cfg(feature = "kernel-test")]
pub(super) fn cookie(name: &str) -> Option<u64> {
    ENDPOINTS
        .lock()
        .entries
        .iter()
        .find(|entry| entry.name == name)
        .map(|entry| entry.cookie)
}

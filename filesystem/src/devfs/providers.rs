//! Typed registration for device families projected into devtmpfs.
//!
//! Lookup and directory enumeration consult the same provider snapshots.
//! Driver callbacks always run after releasing the registry lock.
use super::*;

pub type DeviceLookup = fn(&str) -> Option<Arc<dyn FileOps>>;
pub type DeviceEnumeration = fn() -> Vec<(String, FileType)>;

#[derive(Clone, Copy, Debug)]
pub struct DeviceProvider {
    pub name: &'static str,
    pub lookup: DeviceLookup,
    pub lookup_dir: fn(&str) -> Option<Arc<dyn DirOps>>,
    pub enumerate: DeviceEnumeration,
}

static PROVIDERS: IrqSafeSpinLock<Vec<DeviceProvider>> = IrqSafeSpinLock::new(Vec::new());

pub fn register_provider(provider: DeviceProvider) {
    let mut providers = PROVIDERS.lock();
    if let Some(old) = providers.iter_mut().find(|old| old.name == provider.name) {
        *old = provider;
    } else {
        providers.push(provider);
    }
}

pub fn unregister_provider(name: &str) {
    PROVIDERS.lock().retain(|provider| provider.name != name);
}

pub(super) fn lookup(name: &str) -> Option<Arc<dyn FileOps>> {
    let providers = PROVIDERS.lock().clone();
    providers
        .iter()
        .find_map(|provider| (provider.lookup)(name))
}

pub(super) fn enumerate() -> Vec<(String, FileType)> {
    let providers = PROVIDERS.lock().clone();
    providers
        .iter()
        .flat_map(|provider| (provider.enumerate)())
        .collect()
}

pub(super) fn lookup_dir(name: &str) -> Option<Arc<dyn DirOps>> {
    let providers = PROVIDERS.lock().clone();
    providers
        .iter()
        .find_map(|provider| (provider.lookup_dir)(name))
}

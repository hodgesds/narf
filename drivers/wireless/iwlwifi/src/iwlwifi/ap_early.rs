//! Linux early AP group keys: accepted zeroizing metadata is not an installed
//! native key/default/port. Original source proofs are captured before State.
use super::*;
use narf_wireless::ap_control::ApEmissionAuthority;

struct Key {
    event: ApEventAuthority,
    role: narf_net::native_emission::Lifetime,
    key: narf_wireless::OwnedKey,
}
struct DefaultChoice {
    event: ApEventAuthority,
    role: narf_net::native_emission::Lifetime,
    id: u8,
}
#[derive(Default)]
pub(in crate::iwlwifi) struct Staging {
    keys: Vec<Arc<Key>>,
    defaults: [Option<Arc<DefaultChoice>>; 2],
}
impl Staging {
    pub(in crate::iwlwifi) fn clear(&mut self) {
        self.keys.clear();
        self.defaults = [None, None];
    }
}
pub(in crate::iwlwifi) struct Prepared {
    keys: Vec<Arc<Key>>,
    defaults: [Option<Arc<DefaultChoice>>; 2],
    guards: Arc<[ApEmissionAuthority]>,
}
impl Prepared {
    pub(in crate::iwlwifi) fn guards(&self) -> Arc<[ApEmissionAuthority]> {
        self.guards.clone()
    }
    pub(in crate::iwlwifi) fn validate(
        &self,
        plan: &super::super::ap_wire::Plan,
    ) -> Result<(), &'static str> {
        if self.keys.is_empty() {
            return Ok(());
        }
        if !plan.secure() {
            return Err("early AP group key has no secure START plan");
        }
        if self.keys.iter().any(|key| {
            key.key.params().idx >= 4
                && plan
                    .rsn
                    .as_ref()
                    .is_none_or(|rsn| rsn.rsn_capabilities & 0x80 == 0)
        }) {
            return Err("early AP IGTK has no actual PMF START offer");
        }
        Ok(())
    }
    pub(in crate::iwlwifi) async fn install(
        &self,
        ap: &mut super::super::ap_session::Session,
        hw: &mut Hardware,
    ) -> Result<(), &'static str> {
        // Before any TX, install each selected native default last in its
        // cipher class. Latest ADD is the actual firmware TX-key selector;
        // no remove/re-add or inferred old PN changes that fact.
        let selected = |id: u8| self.defaults.iter().flatten().any(|choice| choice.id == id);
        for last in [false, true] {
            for key in self
                .keys
                .iter()
                .filter(|key| selected(key.key.params().idx) == last)
            {
                let mut params = key.key.params().clone();
                params.default_mgmt = false;
                let secret = narf_wireless::OwnedKey::new(params);
                ap.key(hw, secret.params()).await?;
            }
        }
        for (kind, choice) in self.defaults.iter().enumerate() {
            if let Some(choice) = choice {
                ap.default_key(choice.id, false, kind == 0, kind == 1, false)?;
            }
        }
        Ok(())
    }
}
impl Host {
    /// Full arbitrary authority callbacks execute outside State and staging
    /// locks. Drop stale owned secrets without consulting a successor.
    pub(in crate::iwlwifi) fn prune_early(&self) {
        let (keys, defaults) = {
            let staging = self.early.lock();
            (staging.keys.clone(), staging.defaults.clone())
        };
        let dead: Vec<_> = keys
            .iter()
            .filter(|key| !key.role.current() || key.event.registration_current().is_err())
            .cloned()
            .collect();
        let dead_defaults: Vec<_> = defaults
            .iter()
            .flatten()
            .filter(|choice| !choice.role.current() || choice.event.registration_current().is_err())
            .cloned()
            .collect();
        let mut staging = self.early.lock();
        staging
            .keys
            .retain(|key| !dead.iter().any(|old| Arc::ptr_eq(old, key)));
        let present: Vec<_> = staging
            .keys
            .iter()
            .map(|key| key.key.params().idx)
            .collect();
        for choice in &mut staging.defaults {
            if choice.as_ref().is_some_and(|choice| {
                !present.contains(&choice.id)
                    || dead_defaults.iter().any(|old| Arc::ptr_eq(old, choice))
            }) {
                *choice = None;
            }
        }
    }
    pub(in crate::iwlwifi) fn stage_early(
        &self,
        iface: &dyn narf_wireless::WirelessNetIface,
        authority: &ApControlAuthority,
        operation: &mut Option<Operation>,
    ) -> Result<Option<Result<bool, i32>>, i32> {
        let eligible = matches!(
            operation,
            Some(Operation::Key(_) | Operation::DeleteKey(..) | Operation::DefaultKey(..))
        );
        if !eligible {
            return Ok(None);
        }
        authority.check_for(iface).map_err(|_| 1)?;
        self.prune_early();
        let event = authority.event_authority().map_err(|_| 1)?;
        let role = self.role.lock().observe();
        let mut staging = self.early.lock();
        let result = match operation.take().unwrap() {
            Operation::Key(key) => {
                let p = key.params();
                if p.pairwise
                    || p.peer.is_some()
                    || p.idx > 5
                    || p.key.len() != 16
                    || !p.seq.is_empty() && p.seq.len() != 6
                    || p.cipher
                        != if p.idx >= 4 {
                            narf_wireless::CIPHER_SUITE_AES_CMAC
                        } else {
                            narf_wireless::CIPHER_SUITE_CCMP
                        }
                    || p.default_mgmt && p.idx < 4
                {
                    return Err(22);
                }
                let id = p.idx;
                let select = p.default_mgmt;
                staging.keys.retain(|old| old.key.params().idx != id);
                staging.keys.push(Arc::new(Key {
                    event: event.clone(),
                    role: role.clone(),
                    key,
                }));
                if select {
                    staging.defaults[1] = Some(Arc::new(DefaultChoice { event, role, id }));
                }
                Ok(true)
            }
            Operation::DeleteKey(id, pairwise, peer) => {
                if pairwise || peer.is_some() {
                    return Err(22);
                }
                let before = staging.keys.len();
                staging.keys.retain(|key| key.key.params().idx != id);
                if staging.keys.len() == before {
                    return Err(2);
                }
                for choice in &mut staging.defaults {
                    if choice.as_ref().is_some_and(|choice| choice.id == id) {
                        *choice = None;
                    }
                }
                Ok(true)
            }
            Operation::DefaultKey(id, unicast, multicast, management, beacon) => {
                if unicast
                    || beacon
                    || multicast == management
                    || management != (id >= 4)
                    || !staging.keys.iter().any(|key| key.key.params().idx == id)
                {
                    return Err(22);
                }
                staging.defaults[usize::from(management)] =
                    Some(Arc::new(DefaultChoice { event, role, id }));
                Ok(true)
            }
            _ => return Err(22),
        };
        drop(staging);
        authority.check_for(iface).map_err(|_| 1)?;
        Ok(Some(result))
    }
    pub(in crate::iwlwifi) fn capture_early(
        &self,
        iface: &dyn narf_wireless::WirelessNetIface,
    ) -> Result<Prepared, i32> {
        self.prune_early();
        let (keys, defaults) = {
            let staging = self.early.lock();
            (staging.keys.clone(), staging.defaults.clone())
        };
        let mut guards = Vec::new();
        for key in &keys {
            if !key.role.current() {
                return Err(1);
            }
            guards.push(key.event.native_emission_for(iface).map_err(|_| 1)?);
        }
        for choice in defaults.iter().flatten() {
            if !choice.role.current() {
                return Err(1);
            }
            guards.push(choice.event.native_emission_for(iface).map_err(|_| 1)?);
        }
        Ok(Prepared {
            keys,
            defaults,
            guards: guards.into(),
        })
    }
}

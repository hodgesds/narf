//! Physical P2P client7 planning and current role-owned beacon NoA.
//! Protocol device addresses never replace the actual local/BSSID key owner.
use super::{
    connection::Beacon,
    native_band::{Band, Channel},
    p2p_go,
};
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use narf_lib::sync::IrqSafeSpinLock;

pub(super) const UPDATE_REQUIRED: &str = "P2P client native CTWindow receipt required";
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Noa {
    pub index: u8,
    pub ctwindow: u8,
    pub descriptors: Vec<u8>,
}
impl Noa {
    pub fn parse(ies: &[u8]) -> Result<Option<Self>, &'static str> {
        let attrs = p2p_go::attributes(ies)?;
        let Some(raw) = p2p_go::unique(&attrs, 12)? else {
            return Ok(None);
        };
        if raw.len() < 2 || (raw.len() - 2) % 13 != 0 || raw.len() > 54 {
            return Err("P2P client peer NoA extent");
        }
        Ok(Some(Self {
            index: raw[0],
            ctwindow: raw[1] & 127,
            descriptors: raw[2..].to_vec(),
        }))
    }
}
#[derive(Clone)]
pub(super) struct Plan {
    pub own: [u8; 6],
    pub peer: [u8; 6],
    pub local_device: [u8; 6],
    pub peer_device: p2p_go::Identity,
    pub channel: Channel,
    pub elements: Vec<u8>,
    pub noa: Option<Noa>,
}
impl Plan {
    pub fn new(own: [u8; 6], beacon: &Beacon, elements: &[u8]) -> Result<Self, &'static str> {
        if own == [0; 6]
            || own[0] & 1 != 0
            || beacon.bssid == [0; 6]
            || beacon.bssid[0] & 1 != 0
            || beacon.band == Band::Six
            || !beacon.privacy
            || elements.len() > 1536
        {
            return Err("P2P client physical/protected legacy identity invalid");
        }
        // Native security/SSID/rates/PHY remain owned by the real station
        // plan. Only actual P2P/WPS vendor IEs may supplement that request.
        for (id, body) in super::ap_wire::elements_iter(elements)? {
            if id != 221
                || !(body.starts_with(&[0x50, 0x6f, 0x9a, 9])
                    || body.starts_with(&[0, 0x50, 0xf2, 4]))
            {
                return Err("P2P client extra IEs replace station-owned fields");
            }
        }
        let attrs = p2p_go::attributes(elements)?;
        let cap = p2p_go::unique(&attrs, 2)?.ok_or("P2P client request capability absent")?;
        if cap.len() != 2 || cap[1] & 1 != 0 {
            return Err("P2P client request claims GO identity");
        }
        let info = p2p_go::unique(&attrs, 13)?.ok_or("P2P client request DeviceInfo absent")?;
        if info.len() < 17 || 17 + usize::from(info[16]) * 8 > info.len() {
            return Err("P2P client DeviceInfo extent");
        }
        let local_device: [u8; 6] = info[..6].try_into().unwrap();
        if local_device == [0; 6] || local_device[0] & 1 != 0 {
            return Err("P2P client protocol device address invalid");
        }
        let peer_device = p2p_go::Identity::beacon(&beacon.information_elements)?;
        let rates = super::rates::Rates::parse(&beacon.information_elements, beacon.channel)?;
        if rates.supported & 15 != 0 || rates.basic & 15 != 0 {
            return Err("P2P client GO advertised CCK rates");
        }
        Ok(Self {
            own,
            peer: beacon.bssid,
            local_device,
            peer_device,
            channel: Channel {
                band: beacon.band,
                number: beacon.channel,
            },
            elements: elements.to_vec(),
            noa: Noa::parse(&beacon.information_elements)?,
        })
    }
    pub fn binding(&self) -> [u8; 32] {
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(b"NARF physical P2P CLIENT8 nativeSTA7 legacy20 peer-NoA CTWindow original-role program v1");
        hash.update(&self.own);
        hash.update(&self.peer);
        hash.update(&self.local_device);
        hash.update(&self.peer_device.device);
        hash.update(&self.channel.frequency().to_le_bytes());
        hash.update(&self.elements);
        hash.finalize()
    }
    pub fn response(&self, ies: &[u8]) -> Result<(), &'static str> {
        let attrs = p2p_go::attributes(ies)?;
        if p2p_go::unique(&attrs, 0)? != Some(&[0]) {
            return Err("P2P client association omitted successful P2P Status");
        }
        Ok(())
    }
    pub fn confirm(&self, ies: &[u8]) -> Result<Option<Noa>, &'static str> {
        // Peer NoA may disappear and therefore clear CTWindow, but the
        // negotiated GO's device identity may never silently change.
        if p2p_go::Identity::beacon(ies)? != self.peer_device {
            return Err("P2P client GO device changed; reassociation required");
        }
        Noa::parse(ies)
    }
}

pub(super) struct Native {
    pub plan: Plan,
    role: narf_net::native_emission::Lifetime,
    gen2: bool,
    copy_open: AtomicBool,
    prepared: AtomicBool,
    retired: AtomicBool,
    aid: AtomicU16,
    desired: AtomicU32,
    applied: AtomicU32,
    noa: IrqSafeSpinLock<Option<Noa>>,
}
impl Native {
    pub fn new(
        plan: Plan,
        role: narf_net::native_emission::Lifetime,
        gen2: bool,
    ) -> Result<Arc<Self>, &'static str> {
        if !role.current() {
            return Err("P2P client original role retired");
        }
        let window = u32::from(plan.noa.as_ref().map_or(0, |noa| noa.ctwindow));
        Ok(Arc::new(Self {
            noa: IrqSafeSpinLock::new(plan.noa.clone()),
            plan,
            role,
            gen2,
            copy_open: AtomicBool::new(false),
            prepared: AtomicBool::new(false),
            retired: AtomicBool::new(false),
            aid: AtomicU16::new(0),
            desired: AtomicU32::new(window),
            applied: AtomicU32::new(window),
        }))
    }
    pub fn current(&self) -> Result<(), &'static str> {
        (!self.retired.load(Ordering::Acquire) && self.role.current())
            .then_some(())
            .ok_or("P2P client original role retired")
    }
    pub fn retire(&self) {
        self.retired.store(true, Ordering::Release);
    }
    pub fn begin_copy(&self) -> Result<(), &'static str> {
        self.current()?;
        self.copy_open.store(true, Ordering::Release);
        Ok(())
    }
    pub fn mark_prepared(&self) -> Result<(), &'static str> {
        self.current()?;
        self.prepared.store(true, Ordering::Release);
        Ok(())
    }
    pub fn pending(&self) -> bool {
        self.desired.load(Ordering::Acquire) != self.applied.load(Ordering::Acquire)
    }
    pub fn transmission(&self) -> Result<(), &'static str> {
        self.current()?;
        if !self.prepared.load(Ordering::Acquire) {
            return Err("P2P client lacks actual MAC/link receipts");
        }
        if self.pending() {
            return Err(UPDATE_REQUIRED);
        }
        Ok(())
    }
    pub fn receive(
        &self,
        mpdu: &super::scan_api::Mpdu<'_>,
        band_in_rx: bool,
    ) -> Result<(), &'static str> {
        if !self.copy_open.load(Ordering::Acquire) {
            return Ok(());
        }
        let f = mpdu.frame;
        if f.len() < 36
            || f[0] != 0x80
            || f[1] & 0xc7 != 0
            || f[22] & 15 != 0
            || f[4..10] != [255; 6]
            || f[10..16] != self.plan.peer
            || f[16..22] != self.plan.peer
            || mpdu.status & 3 != 3
            || mpdu.raw_fw_link != 0
            || mpdu.channel != self.plan.channel.number
            || band_in_rx && mpdu.raw_band != self.plan.channel.band as u8
        {
            return Ok(());
        }
        self.current()?;
        let ies = mpdu
            .body(24, 0)
            .and_then(|body| body.get(12..))
            .ok_or("P2P client beacon body invalid")?;
        let noa = self.plan.confirm(ies)?;
        {
            let cached = self.noa.lock();
            if let (Some(old), Some(new)) = (cached.as_ref(), noa.as_ref()) {
                if old.index == new.index
                    && old.ctwindow == new.ctwindow
                    && old.descriptors == new.descriptors
                {
                    return Ok(());
                }
            }
        }
        self.desired.store(
            u32::from(noa.as_ref().map_or(0, |noa| noa.ctwindow)),
            Ordering::Release,
        );
        *self.noa.lock() = noa;
        Ok(())
    }
    pub fn desired(&self) -> u32 {
        self.desired.load(Ordering::Acquire)
    }
    pub fn commit_window(&self, value: u32) -> Result<(), &'static str> {
        self.current()?;
        self.applied.store(value, Ordering::Release);
        Ok(())
    }
    pub fn associated(&self, aid: u16) -> Result<(), &'static str> {
        self.current()?;
        if aid > 2007 {
            return Err("P2P client actual association ID invalid");
        }
        self.aid.store(aid, Ordering::Release);
        Ok(())
    }
    pub fn mac(
        &self,
        action: u32,
        aid: Option<u16>,
        window: u32,
    ) -> Result<[u8; 52], &'static str> {
        self.current()?;
        if !matches!(action, 1..=3) || window > 127 {
            return Err("P2P client native MAC extent invalid");
        }
        let mut body = super::station_api::mac(action, self.plan.own, aid);
        super::boot_context::put32(&mut body, 8, 7);
        if self.gen2 {
            super::boot_context::put32(&mut body, 20, if aid.is_some() { 4 } else { 12 });
        }
        super::boot_context::put32(&mut body, 48, window);
        Ok(body)
    }
    pub fn update_mac(&self) -> Result<[u8; 52], &'static str> {
        let aid = self.aid.load(Ordering::Acquire);
        self.mac(2, (aid != 0).then_some(aid), self.desired())
    }
}

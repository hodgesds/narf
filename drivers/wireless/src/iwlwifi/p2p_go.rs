//! P2P GO wire identity and source-owned native NoA projection.
//! Actual role/receive/publication owners precede native NoA authority.
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use narf_lib::sync::IrqSafeSpinLock;

const OUI: [u8; 4] = [0x50, 0x6f, 0x9a, 9];
const NOA: u8 = 12;
const MAX_ATTRIBUTES: usize = 1536;

/// P2P Device Address is protocol identity, never physical MAC ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Identity {
    pub device: [u8; 6],
}
impl Identity {
    pub fn beacon(ies: &[u8]) -> Result<Self, &'static str> {
        let attrs = attributes(ies)?;
        let capability = unique(&attrs, 2)?.ok_or("GO beacon omitted P2P capability")?;
        if capability.len() != 2 || capability[1] & 1 == 0 {
            return Err("GO beacon lacks actual group-owner capability");
        }
        let device = unique(&attrs, 3)?.ok_or("GO beacon omitted P2P device ID")?;
        let device: [u8; 6] = device.try_into().map_err(|_| "GO device ID extent")?;
        if !unicast(device) {
            return Err("GO device ID is not a unicast protocol identity");
        }
        Ok(Self { device })
    }
    pub fn discovery_request(&self, ies: &[u8]) -> bool {
        let Ok(attrs) = attributes(ies) else {
            return false;
        };
        let Ok(Some(capability)) = unique(&attrs, 2) else {
            return false;
        };
        if capability.len() != 2 {
            return false;
        }
        matches!(unique(&attrs, 3), Ok(None))
            || matches!(unique(&attrs,3),Ok(Some(device)) if device==self.device)
    }
    /// Fixed software emission-program identity. Dynamic NoA comes only
    /// from this native owner; its values do not change the measured scope.
    pub fn binding(&self, own: [u8; 6], channel: super::native_band::Channel) -> [u8; 32] {
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(b"NARF Intel physical GO9 OFDM20 native-MAC0 NoA1 host-GTK-CCMP IGTK-CMAC exact-PN program v9");
        hash.update(&own);
        hash.update(&self.device);
        hash.update(&channel.frequency().to_le_bytes());
        hash.finalize()
    }
    pub fn probe(&self, ies: &[u8]) -> Result<(), &'static str> {
        let attrs = attributes(ies)?;
        let capability = unique(&attrs, 2)?.ok_or("GO probe omitted P2P capability")?;
        if capability.len() != 2 || capability[1] & 1 == 0 {
            return Err("GO probe lacks actual group-owner capability");
        }
        let info = unique(&attrs, 13)?.ok_or("GO probe omitted P2P device information")?;
        // Address6/config-methods2/primary-type8/secondary-count1, then
        // secondary types and WPS Device Name. Preserve those opaque fields.
        if info.len() < 17 || info[..6] != self.device {
            return Err("GO probe changed its P2P device identity");
        }
        let secondary_end = 17 + usize::from(info[16]) * 8;
        if secondary_end > info.len() {
            return Err("GO probe secondary device types truncated");
        }
        Ok(())
    }
}
fn unicast(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}

/// Concatenate fragmented P2P vendor payloads before decoding LE16 attrs,
/// matching the actual hostap group producer's251-byte fragmentation.
pub(super) fn attributes(ies: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    for (id, body) in super::ap_wire::elements_iter(ies)? {
        if id == 221 && body.starts_with(&OUI) {
            if out.len() + body.len() - OUI.len() > MAX_ATTRIBUTES {
                return Err("GO P2P attributes exceed bounded template");
            }
            out.extend_from_slice(&body[4..]);
        }
    }
    validate_attributes(&out)?;
    Ok(out)
}
fn validate_attributes(mut raw: &[u8]) -> Result<(), &'static str> {
    while !raw.is_empty() {
        if raw.len() < 3 {
            return Err("truncated GO P2P attribute header");
        }
        let len = usize::from(u16::from_le_bytes([raw[1], raw[2]]));
        raw = raw
            .get(3 + len..)
            .ok_or("truncated GO P2P attribute extent")?;
    }
    Ok(())
}
pub(super) fn unique(raw: &[u8], id: u8) -> Result<Option<&[u8]>, &'static str> {
    let mut raw = raw;
    let mut found = None;
    while !raw.is_empty() {
        let len = usize::from(u16::from_le_bytes([raw[1], raw[2]]));
        if raw[0] == id && found.replace(&raw[3..3 + len]).is_some() {
            return Err("duplicate GO P2P identity attribute");
        }
        raw = &raw[3 + len..];
    }
    Ok(found)
}

/// One current non-MLD physical GO owner; no request metadata or MAC type
/// alone constructs it. The actual native role captures it after old MAC
/// removal and an all-RFH prefix, before new MAC publication. Pending NoA
/// is observational until complete native preparation marks it ready.
pub(super) struct Native {
    identity: Identity,
    own: [u8; 6],
    owner: Arc<super::ap_owner::Owner>,
    prefix_epoch: u64,
    ready: AtomicBool,
    noa: IrqSafeSpinLock<Option<Vec<u8>>>,
}
impl Native {
    pub fn new(
        identity: Identity,
        own: [u8; 6],
        owner: Arc<super::ap_owner::Owner>,
        actual_epoch: u64,
    ) -> Result<Arc<Self>, &'static str> {
        owner.check()?;
        if !unicast(own) || actual_epoch == u64::MAX {
            return Err("GO native physical identity/capture invalid");
        }
        Ok(Arc::new(Self {
            identity,
            own,
            owner,
            prefix_epoch: actual_epoch,
            ready: AtomicBool::new(false),
            noa: IrqSafeSpinLock::new(None),
        }))
    }
    pub fn mark_ready(&self, epoch: u64) -> Result<(), &'static str> {
        self.current()?;
        if epoch != self.prefix_epoch {
            return Err("GO prepared capture differs from actual open prefix");
        }
        self.ready.store(true, Ordering::Release);
        Ok(())
    }
    pub fn current(&self) -> Result<(), &'static str> {
        self.owner.check()
    }
    /// Firmware PROBE_RESPONSE_DATA v1 names MAC0, independently of the
    /// RFH FW-link/station identities used for ordinary AP DATA.
    pub fn receive(&self, packet: &super::runtime::Packet) -> Result<bool, &'static str> {
        if (packet.header.group_id, packet.header.cmd) != (3, 0xfc) {
            return Ok(false);
        }
        // Hardware captured this exact retained GO object before copying
        // the physical fallback prefix. NoA is role control, independent of
        // the DATA/key receive epoch, which can close during a key update.
        if packet.receive_queue != 0 {
            return Ok(true);
        }
        self.current()?;
        let b = &packet.payload;
        if b.len() != 44 {
            return Err("GO native NoA notification extent");
        }
        if u32::from_le_bytes(b[..4].try_into().unwrap()) != 0 {
            return Ok(false);
        }
        if !matches!(b[40], 0 | 0xff) {
            return Err("GO native CSA needs unsupported channel-switch owner");
        }
        let noa = if u32::from_le_bytes(b[4..8].try_into().unwrap()) == 0 {
            None
        } else {
            let len = usize::from(u16::from_le_bytes([b[9], b[10]]));
            if b[8] != NOA || !matches!(len, 15 | 28) {
                return Err("GO native NoA attribute extent/identity");
            }
            // Copy attribute header + real1/2 descriptors, excluding the
            // native alignment byte and unused second descriptor.
            Some(b[8..11 + len].to_vec())
        };
        *self.noa.lock() = noa;
        Ok(true)
    }
    /// Called only at the final native publication boundary, after bounded
    /// already-completed fallback-RFH drain and after any TX-credit wait.
    /// Source/capture checks precede replacing host-supplied NoA bytes.
    pub fn project_probe(&self, frame: &mut Vec<u8>) -> Result<(), &'static str> {
        self.current()?;
        if !self.ready.load(Ordering::Acquire) {
            return Err("GO native preparation has no ready receipt");
        }
        if frame.first() != Some(&0x50) {
            return Ok(());
        }
        if frame.len() < 36 || frame[10..16] != self.own || frame[16..22] != self.own {
            return Err("GO probe lost current physical native identity");
        }
        self.identity.probe(&frame[36..])?;
        let attrs = attributes(&frame[36..])?;
        let mut retained = Vec::new();
        let mut raw = attrs.as_slice();
        while !raw.is_empty() {
            let len = usize::from(u16::from_le_bytes([raw[1], raw[2]]));
            if raw[0] != NOA {
                retained.extend_from_slice(&raw[..3 + len]);
            }
            raw = &raw[3 + len..];
        }
        // A userspace NoA is metadata only. Append solely the current
        // owner-bound native receipt; None also clears a previous NoA.
        if let Some(noa) = self.noa.lock().as_ref() {
            retained.extend_from_slice(noa);
        }
        let mut projected = frame[..36].to_vec();
        for (id, body) in super::ap_wire::elements_iter(&frame[36..])? {
            if id != 221 || !body.starts_with(&OUI) {
                projected.extend_from_slice(&[id, body.len() as u8]);
                projected.extend_from_slice(body);
            }
        }
        for part in retained.chunks(251) {
            projected.extend_from_slice(&[221, (4 + part.len()) as u8]);
            projected.extend_from_slice(&OUI);
            projected.extend_from_slice(part);
        }
        if projected.len() > 2048 {
            return Err("GO native NoA exceeds bounded probe template");
        }
        *frame = projected;
        Ok(())
    }
}

/// P2P initiation must honor the host's explicit NO_P2P flag over every
/// overlapping20MHz rule, independently of ACTIVE/NO_IR/DFS power checks.
pub(super) fn host_allows(
    domain: &narf_wireless::reg::RegulatoryDomain,
    channel: super::native_band::Channel,
) -> bool {
    let center = channel.frequency();
    domain.rules.iter().all(|rule| {
        rule.freq_end_mhz <= center.saturating_sub(10)
            || rule.freq_start_mhz >= center + 10
            || !rule.flags.contains(narf_wireless::reg::RegFlags::NO_P2P)
    })
}

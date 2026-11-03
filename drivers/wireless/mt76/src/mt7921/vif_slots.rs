//! Native CONNAC2 per-interface geometry, not device/admin/RF authority.
//! Linux mt7921_add_interface: first free idx<4, OMAC=idx, WMM=idx%4,
//! assigned BMC WCID=19-idx. Actual start/retirement remains the caller's job.
use super::firmware_transport::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Vif {
    index: u8,
}
impl Vif {
    /// The retained physical interface's logical BSS0/OMAC0/WMM0.
    pub(crate) const HOME: Self = Self { index: 0 };
    pub(crate) fn new(index: u8) -> Result<Self, Error> {
        if index >= 4 {
            return Err(Error::Bounds);
        }
        Ok(Self { index })
    }
    pub(crate) fn index(self) -> u8 {
        self.index
    }
    pub(crate) fn bmc(self) -> u8 {
        19 - self.index
    }
    /// Linux mt7921_add_interface: `omac_idx = idx` (band 0, HW BSS).
    pub(crate) fn omac(self) -> u8 {
        self.index
    }
    /// Linux mt7921_add_interface: `wmm_idx = idx % MT76_CONNAC_MAX_WMM_SETS`.
    pub(crate) fn wmm(self) -> u8 {
        self.index % 4
    }
    pub(crate) fn device_payloads(
        self,
        own: [u8; 6],
        enable: bool,
        assigned: bool,
    ) -> Result<([u8; 16], [u8; 36]), Error> {
        if own == [0; 6] || own[0] & 1 != 0 {
            return Err(Error::Bounds);
        }
        let mut device = [0; 16];
        device[0] = self.index;
        device[6..8].copy_from_slice(&12u16.to_le_bytes());
        device[8] = u8::from(enable);
        device[10..16].copy_from_slice(&own);
        let mut bss = [0; 36];
        bss[0] = self.index;
        bss[6..8].copy_from_slice(&32u16.to_le_bytes());
        bss[8] = u8::from(enable);
        bss[9] = self.index; // OMAC
        bss[10] = self.index; // hardware BSS (<EXT_BSSID_START)
        bss[12..16].copy_from_slice(&super::p2p_wire::CONNECTION_P2P_GO.to_le_bytes());
        bss[16] = 1;
        bss[17] = self.index % 4; // MT76_CONNAC_MAX_WMM_SETS
        if assigned {
            bss[24..26].copy_from_slice(&u16::from(self.bmc()).to_le_bytes());
            bss[30..32].copy_from_slice(&u16::from(self.bmc()).to_le_bytes());
        }
        Ok((device, bss))
    }
}

/// One vif's native station-record identity: its BSS/OMAC/WMM indices, the
/// peer WCID it owns (the AP of a STATION/P2P_CLIENT vif) and its BMC WCID
/// (19 - idx). Linux `mt76_connac_mcu_alloc_sta_req` stamps `bss_idx`,
/// `muar_idx = omac_idx` for a peer and 0xe for the vif's own BMC WCID;
/// `mt76_wcid_alloc` hands out the peer index from the shared WTBL map.
/// `HOME` is BSS0 with peer WCID 1 and BMC WCID 19, the retained physical
/// interface's identity, so every `HOME` record is byte-identical to the
/// historical single-vif builders.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Link {
    vif: Vif,
    peer: u8,
}
impl Link {
    pub(crate) const HOME: Self = Self {
        vif: Vif::HOME,
        peer: 1,
    };
    /// A peer WCID from Linux `mt76_wcid_alloc(.., MT792x_WTBL_STA)`:
    /// below `MT792x_WTBL_STA` = 19 - 4 = 15 (the per-vif BMC WCIDs 16..=19
    /// are reserved); WCID 0 is the global WCID.
    pub(crate) fn new(vif: Vif, peer: u8) -> Result<Self, Error> {
        if !(1..=LAST_PEER_WCID).contains(&peer) {
            return Err(Error::Bounds);
        }
        Ok(Self { vif, peer })
    }
    pub(crate) fn vif(self) -> Vif {
        self.vif
    }
    pub(crate) fn bss(self) -> u8 {
        self.vif.index
    }
    pub(crate) fn omac(self) -> u8 {
        self.vif.omac()
    }
    pub(crate) fn wmm(self) -> u8 {
        self.vif.wmm()
    }
    pub(crate) fn peer(self) -> u8 {
        self.peer
    }
    pub(crate) fn bmc(self) -> u8 {
        self.vif.bmc()
    }
}
/// Stamp `vif`'s BSS index into a unified BSS_INFO / CE BSS request built
/// for BSS0. Every such Linux request opens with
/// `struct { u8 bss_idx; u8 pad[3]; } hdr` = `mvif->idx`
/// (mt76_connac_mcu_uni_set_chctx, mt76_connac_mcu_uni_add_bss,
/// mt7921_mcu_uni_add_beacon_offload, mt7921_mcu_set_bss_pm), so a
/// `Vif::HOME` body is unchanged.
pub(crate) fn on_bss<T: AsMut<[u8]>>(vif: Vif, mut body: T) -> T {
    body.as_mut()[0] = vif.index();
    body
}
/// Highest peer WCID (`MT792x_WTBL_STA` - 1, mt792x.h).
pub(crate) const LAST_PEER_WCID: u8 = 14;

/// Metadata allocation identity; no start, packet, RF or current grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Allocation {
    vif: Vif,
    generation: u64,
}
impl Allocation {
    pub(crate) fn vif(self) -> Vif {
        self.vif
    }
}
#[derive(Debug)]
pub(crate) struct Slots {
    generations: [Option<u64>; 4],
    next: u64,
}
impl Default for Slots {
    fn default() -> Self {
        // The actual retained physical interface owns logical BSS0. Child
        // publication still requires its actual typed registration/source.
        Self {
            generations: [Some(1), None, None, None],
            next: 2,
        }
    }
}
impl Slots {
    pub(crate) fn reserve(&mut self) -> Result<Allocation, Error> {
        let index = self
            .generations
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Busy)?;
        let generation = self.next;
        self.next = self.next.checked_add(1).ok_or(Error::Authority)?;
        self.generations[index] = Some(generation);
        Ok(Allocation {
            vif: Vif::new(index as u8)?,
            generation,
        })
    }
    pub(crate) fn current(&self, allocation: Allocation) -> bool {
        self.generations[usize::from(allocation.vif.index)] == Some(allocation.generation)
    }
    /// Call only after actual native BSS/WTBL/ROC ownership was retired, or
    /// before any native publication. A stale destructor cannot free reuse.
    pub(crate) fn release_retired(&mut self, allocation: Allocation) -> bool {
        if allocation.vif.index == 0 || !self.current(allocation) {
            return false;
        }
        self.generations[usize::from(allocation.vif.index)] = None;
        true
    }
}

/// Match Linux mt792x_config_mac_addr_list for a default virtual address.
/// Explicit unicast addresses are separately admitted by the create owner.
pub(crate) fn mac_candidates(physical: [u8; 6]) -> [[u8; 6]; 4] {
    let mut addresses = [physical; 4];
    for (index, address) in addresses.iter_mut().enumerate().skip(1) {
        address[0] |= 2;
        address[0] ^= ((index - 1) as u8) << 2;
    }
    addresses
}

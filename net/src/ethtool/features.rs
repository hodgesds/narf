//! Interface offload policy shared by ioctl and Generic Netlink.
use super::{get, nic, put};
use crate::iface::NetIfaceEntry;

pub(super) const NAMES: &[&str] = &[
    "tx-scatter-gather",
    "tx-checksum-ipv4",
    "",
    "tx-checksum-ip-generic",
    "tx-checksum-ipv6",
    "highdma",
    "tx-scatter-gather-fraglist",
    "tx-vlan-hw-insert",
    "rx-vlan-hw-parse",
    "rx-vlan-filter",
    "vlan-challenged",
    "tx-generic-segmentation",
    "",
    "",
    "rx-gro",
    "rx-lro",
    "tx-tcp-segmentation",
    "tx-gso-robust",
    "tx-tcp-ecn-segmentation",
    "tx-tcp-mangleid-segmentation",
    "tx-tcp6-segmentation",
    "tx-fcoe-segmentation",
    "tx-gre-segmentation",
    "tx-gre-csum-segmentation",
    "tx-ipxip4-segmentation",
    "tx-ipxip6-segmentation",
    "tx-udp_tnl-segmentation",
    "tx-udp_tnl-csum-segmentation",
    "tx-gso-partial",
    "tx-tunnel-remcsum-segmentation",
    "tx-sctp-segmentation",
    "tx-esp-segmentation",
    "",
    "tx-udp-segmentation",
    "tx-gso-list",
    "tx-tcp-accecn-segmentation",
    "tx-checksum-fcoe-crc",
    "tx-checksum-sctp",
    "rx-ntuple-filter",
    "rx-hashing",
    "rx-checksum",
    "tx-nocache-copy",
    "loopback",
    "rx-fcs",
    "rx-all",
    "tx-vlan-stag-hw-insert",
    "rx-vlan-stag-hw-parse",
    "rx-vlan-stag-filter",
    "l2-fwd-offload",
    "hw-tc-offload",
    "esp-hw-offload",
    "esp-tx-csum-hw-offload",
    "rx-udp_tunnel-port-offload",
    "tls-hw-tx-offload",
    "tls-hw-rx-offload",
    "rx-gro-hw",
    "tls-hw-record",
    "rx-gro-list",
    "macsec-hw-offload",
    "rx-udp-gro-forwarding",
    "hsr-tag-ins-offload",
    "hsr-tag-rm-offload",
    "hsr-fwd-offload",
    "hsr-dup-offload",
];
const TX: u64 = 1 << 3;
const RX: u64 = 1 << 40;
const VLAN: u64 = 1 << 7;
const GRO: u64 = 1 << 14;
const TSO: u64 = (1 << 16) | (1 << 20);

pub(super) fn hardware(e: &NetIfaceEntry) -> u64 {
    let c = e.offload_hardware;
    (u64::from(c.tx_checksum) * TX)
        | (u64::from(c.rx_checksum) * RX)
        | (u64::from(c.vlan_insert) * VLAN)
        | (u64::from(c.max_tso_bytes > 0) * TSO)
        | (u64::from(e.gro_supported) * GRO)
}
fn active(e: &NetIfaceEntry) -> u64 {
    let c = e.offloads;
    (u64::from(c.tx_checksum) * TX)
        | (u64::from(c.rx_checksum) * RX)
        | (u64::from(c.vlan_insert) * VLAN)
        | (u64::from(c.max_tso_bytes > 0) * TSO)
        | (u64::from(e.software_gro) * GRO)
}
pub(crate) fn apply(e: &mut NetIfaceEntry) {
    let hw = hardware(e);
    let wanted = e
        .feature_wanted
        .unwrap_or((hw & !GRO) | (u64::from(e.software_gro) * GRO));
    let bits = wanted & hw;
    e.offloads = e.offload_hardware;
    e.offloads.tx_checksum &= bits & TX != 0;
    e.offloads.rx_checksum &= bits & RX != 0;
    e.offloads.vlan_insert &= bits & VLAN != 0;
    // The frame contract has a single IPv4/IPv6 TSO capability, and TSO
    // requires checksum generation. Never claim a partially applied setting.
    if bits & TSO != TSO || bits & TX == 0 {
        e.offloads.max_tso_bytes = 0;
    }
    e.software_gro = bits & GRO != 0;
}
pub(super) fn snapshot(name: &str) -> nic::Result<(u64, u64, u64)> {
    crate::iface::with_features(name, |e| {
        (
            hardware(e),
            e.feature_wanted.unwrap_or_else(|| active(e)),
            active(e),
        )
    })
}
pub(super) fn update(name: &str, valid: u64, requested: u64) -> nic::Result<u32> {
    crate::iface::with_features(name, |e| {
        let hw = hardware(e);
        let old = e.feature_wanted.unwrap_or_else(|| active(e));
        let mask = valid & hw;
        let wanted = (old & !mask) | (requested & mask);
        e.feature_wanted = Some(wanted);
        apply(e);
        u32::from(valid & !hw != 0) | (u32::from(wanted != active(e)) << 1)
    })
}
pub(super) fn legacy(name: &str, b: &mut [u8]) -> nic::Result<Option<u32>> {
    let cmd = get(b, 0);
    match cmd {
        0x3a => {
            let blocks = get(b, 4) as usize;
            let (hw, wanted, active) = snapshot(name)?;
            put(b, 4, 2);
            for i in 0..blocks.min(2) {
                put(b, 8 + i * 16, (hw >> (i * 32)) as u32);
                put(b, 12 + i * 16, (wanted >> (i * 32)) as u32);
                put(b, 16 + i * 16, (active >> (i * 32)) as u32);
                put(b, 20 + i * 16, 0);
            }
        }
        0x3b => {
            let mut valid = 0u64;
            let mut wanted = 0u64;
            for i in 0..get(b, 4) as usize {
                let v = get(b, 8 + i * 8);
                let w = get(b, 12 + i * 8);
                if i < 2 {
                    valid |= u64::from(v) << (i * 32);
                    wanted |= u64::from(w) << (i * 32);
                } else if v != 0 {
                    return Err(22);
                }
            }
            return update(name, valid, wanted).map(Some);
        }
        0x25 => {
            put(
                b,
                4,
                if snapshot(name)?.2 & VLAN != 0 {
                    1 << 7
                } else {
                    0
                },
            );
        }
        0x26 => {
            let flags = get(b, 4);
            if flags & !(1 << 7) != 0 {
                return Err(95);
            }
            let (hw, _, a) = snapshot(name)?;
            if (flags ^ if a & VLAN != 0 { 1 << 7 } else { 0 }) != 0 && hw & VLAN == 0 {
                return Err(95);
            }
            update(name, VLAN, u64::from(flags & (1 << 7) != 0) * VLAN)?;
        }
        0x14 | 0x16 | 0x18 | 0x1e | 0x21 | 0x23 | 0x2b => {
            let a = snapshot(name)?.2;
            let bit = match cmd {
                0x14 => RX,
                0x16 => TX,
                0x1e => TSO,
                0x2b => GRO,
                _ => 0,
            };
            put(b, 4, u32::from(a & bit != 0));
        }
        0x15 | 0x17 | 0x19 | 0x1f | 0x22 | 0x24 | 0x2c => {
            let value = get(b, 4);
            if value > 1 {
                return Err(22);
            }
            let bit = match cmd {
                0x15 => RX,
                0x17 => TX,
                0x1f => TSO,
                0x2c => GRO,
                _ => return Err(95),
            };
            let (hw, _, _) = snapshot(name)?;
            if hw & bit == 0 {
                return Err(95);
            }
            update(name, bit, if value != 0 { bit } else { 0 })?;
        }
        _ => return Ok(None),
    }
    Ok(Some(0))
}

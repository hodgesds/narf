//! Checked advanced-descriptor packet preparation; no packet bytes are
//! published before validation and checksum seed construction succeeds.

use super::igc::{AdvTxCtxtDesc, IgcError};
use narf_net::{L4CsumKind, RxMeta, TxMeta};

pub(crate) const MAX_TSO: usize = 65535;
pub(crate) const MAX_MTU: u32 = 9216;

#[derive(Debug)]
pub(crate) struct TxPlan {
    pub context: Option<AdvTxCtxtDesc>,
    pub command: u32,
    pub info: u32,
}

fn invalid() -> IgcError {
    IgcError::Other("invalid packet/offload request")
}
fn word(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

impl TxPlan {
    pub(crate) fn prepare(
        b: &mut [u8],
        meta: TxMeta,
        _queue: usize,
        mtu: u32,
    ) -> Result<Self, IgcError> {
        if b.len() < 14 || b.len() > MAX_TSO {
            return Err(invalid());
        }
        let mut mac = 14;
        let mut ethertype = word(b, 12);
        if ethertype == 0x8100 || ethertype == 0x88a8 {
            if b.len() < 18 || meta.vlan_tag.is_some() {
                return Err(invalid());
            }
            ethertype = word(b, 16);
            mac = 18;
        }
        if meta.tso_mss.is_none() && b.len() > mtu as usize + mac {
            return Err(invalid());
        }
        let mut context = meta.vlan_tag.map(|v| AdvTxCtxtDesc {
            vlan_macip_lens: (u32::from(v) << 16) | ((mac as u32) << 9),
            type_tucmd_mlhl: 0x20200000,
            // Linux igc never enables IGC_RING_FLAG_TX_CTX_IDX (the
            // corresponding igb flag is for 82575). Use context index 0
            // in both context and data descriptors on I225/I226.
            mss_l4len_idx: 0,
            ..Default::default()
        });
        let mut command = 0x22300000; // DEXT + DATA + IFCS
        if meta.vlan_tag.is_some() {
            command |= 1 << 30;
        }
        let mut info = (b.len() as u32) << 14;
        if meta.csum_l4.is_some() || meta.tso_mss.is_some() {
            let (ip, protocol, addresses) = match ethertype {
                0x0800 => {
                    if b.len() < mac + 20 || b[mac] >> 4 != 4 {
                        return Err(invalid());
                    }
                    let ihl = usize::from(b[mac] & 15) * 4;
                    if !(20..=60).contains(&ihl)
                        || b.len() < mac + ihl
                        || word(b, mac + 6) & 0x3fff != 0
                        || usize::from(word(b, mac + 2)) != b.len() - mac
                    {
                        return Err(invalid());
                    }
                    (ihl, b[mac + 9], &b[mac + 12..mac + 20])
                }
                0x86dd => {
                    if b.len() < mac + 40
                        || b[mac] >> 4 != 6
                        || usize::from(word(b, mac + 4)) != b.len() - mac - 40
                    {
                        return Err(invalid());
                    }
                    // Extension headers need software checksum/segmentation.
                    (40, b[mac + 6], &b[mac + 8..mac + 40])
                }
                _ => return Err(invalid()),
            };
            let tcp = protocol == 6;
            let sctp = protocol == 132;
            if (protocol != 6 && protocol != 17 && !sctp)
                || meta.csum_l4.is_some_and(|k| {
                    k != if tcp {
                        L4CsumKind::Tcp
                    } else if sctp {
                        L4CsumKind::Sctp
                    } else {
                        L4CsumKind::Udp
                    }
                })
                || (meta.tso_mss.is_some() && !tcp)
            {
                return Err(invalid());
            }
            let transport = mac + ip;
            let l4 = if tcp {
                if b.len() < transport + 20 {
                    return Err(invalid());
                }
                usize::from(b[transport + 12] >> 4) * 4
            } else if sctp {
                12
            } else {
                8
            };
            if l4 < if tcp { 20 } else { 8 }
                || b.len() < transport + l4
                || (!tcp && !sctp && usize::from(word(b, transport + 4)) != b.len() - transport)
            {
                return Err(invalid());
            }
            let header = transport + l4;
            if let Some(mss) = meta.tso_mss {
                if mss == 0
                    || usize::from(mss) + ip + l4 > mtu as usize
                    || header > 255
                    || header == b.len()
                {
                    return Err(invalid());
                }
            }
            let mut sum = u32::from(protocol);
            for pair in addresses.chunks_exact(2) {
                sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
            }
            if meta.tso_mss.is_none() {
                sum += (b.len() - transport) as u32;
            }
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            let csum = transport + if tcp { 16 } else { 6 };
            if sctp {
                b[transport + 8..transport + 12].fill(0);
            } else {
                b[csum..csum + 2].copy_from_slice(&(sum as u16).to_be_bytes());
            }
            let ipv4 = ethertype == 0x0800;
            if ipv4 {
                b[mac + 10..mac + 12].fill(0);
            }
            if meta.tso_mss.is_some() {
                b[mac + if ipv4 { 2 } else { 4 }..mac + if ipv4 { 4 } else { 6 }].fill(0);
                command |= 1 << 31;
                info = ((b.len() - header) as u32) << 14;
            }
            info |= 0x200 | if ipv4 { 0x100 } else { 0 };
            context = Some(AdvTxCtxtDesc {
                vlan_macip_lens: (u32::from(meta.vlan_tag.unwrap_or(0)) << 16)
                    | ((mac as u32) << 9)
                    | ip as u32,
                launch_time: 0,
                type_tucmd_mlhl: 0x20200000
                    | if ipv4 { 0x400 } else { 0 }
                    | if tcp {
                        0x800
                    } else if sctp {
                        0x1000
                    } else {
                        0
                    },
                mss_l4len_idx: (u32::from(meta.tso_mss.unwrap_or(0)) << 16) | ((l4 as u32) << 8),
            });
        }
        Ok(Self {
            context,
            command,
            info,
        })
    }
}

pub(crate) fn rx_metadata(status: u32, hash: u32) -> RxMeta {
    let checksum = status & 4 == 0; // IXSM overrides computed flags.
    RxMeta {
        timestamp_ns: None,
        csum_l3: checksum && status & 0x40 != 0 && status & 0x40000000 == 0,
        csum_l4: checksum && status & 0x30 != 0 && status & 0x20000000 == 0,
        gro_segs: 1,
        rx_hash: hash,
    }
}

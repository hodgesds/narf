use alloc::{vec, vec::Vec};
use narf_net::{
    pkt::{self, ETHERTYPE_IPV4, ETH_HDR_LEN, IPV4_HDR_LEN, IP_PROTO_UDP},
    pkt_dhcp::{self as dhcp, DhcpHeader},
    pkt_udp,
};

/// One deterministic network shared by a station and its test access point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkPlan {
    pub station: [u8; 6],
    pub bssid: [u8; 6],
    pub server_ip: [u8; 4],
    pub lease_ip: [u8; 4],
    pub netmask: [u8; 4],
    pub lease_seconds: u32,
}

impl NetworkPlan {
    /// Compare every lease term, including the gateway and DNS side channel.
    pub fn matches_lease(&self, lease: &narf_net::dhcp::Lease) -> bool {
        lease.addr.0 == self.lease_ip
            && lease.netmask.0 == self.netmask
            && lease.gateway.map(|ip| ip.0) == Some(self.server_ip)
            && lease.dns.len() == 1
            && lease.dns[0].0 == self.server_ip
            && lease.lease_seconds == self.lease_seconds
    }
}

/// Accepted wire requests; malformed or foreign requests do not count.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DhcpObservations {
    pub discovers: u32,
    pub requests: u32,
}

/// A single-station initial-lease DHCP peer, correlated by MAC and transaction.
/// It does not implement renewal, relaying, allocation pools or persistence.
#[derive(Debug)]
pub struct DhcpServer {
    plan: NetworkPlan,
    offered_xid: Option<u32>,
    seen: DhcpObservations,
}

impl DhcpServer {
    pub fn new(plan: NetworkPlan) -> Self {
        Self {
            plan,
            offered_xid: None,
            seen: DhcpObservations::default(),
        }
    }

    pub fn observations(&self) -> DhcpObservations {
        self.seen
    }

    /// Accept a checked DISCOVER/REQUEST and return the complete Ethernet reply.
    /// Retransmission of the current exchange is idempotent. A REQUEST naming
    /// another server/address or an unoffered transaction cannot earn an ACK.
    pub fn receive(&mut self, eth: &[u8]) -> Option<Vec<u8>> {
        if eth.get(..6)? != [0xff; 6] || eth.get(6..12)? != self.plan.station {
            return None;
        }
        let payload = client_payload(eth)?;
        let request = DhcpHeader::decode(payload).ok()?;
        if request.op != dhcp::OP_BOOT_REQUEST
            || request.htype != dhcp::HTYPE_ETHERNET
            || request.hlen != 6
            || request.hops != 0
            || request.chaddr[..6] != self.plan.station
            || request.ciaddr != [0; 4]
            || request.giaddr != [0; 4]
        {
            return None;
        }
        let options = Options::parse(payload.get(dhcp::DHCP_HDR_LEN..)?)?;
        let reply_type = match options.kind? {
            dhcp::DHCPDISCOVER => {
                self.offered_xid = Some(request.xid);
                self.seen.discovers = self.seen.discovers.saturating_add(1);
                dhcp::DHCPOFFER
            }
            dhcp::DHCPREQUEST => {
                if self.offered_xid != Some(request.xid)
                    || options.requested_ip != Some(self.plan.lease_ip)
                    || options.server != Some(self.plan.server_ip)
                {
                    return None;
                }
                self.seen.requests = self.seen.requests.saturating_add(1);
                dhcp::DHCPACK
            }
            _ => return None,
        };
        let mut reply = Vec::with_capacity(300);
        DhcpHeader {
            op: dhcp::OP_BOOT_REPLY,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid: request.xid,
            secs: 0,
            flags: request.flags,
            ciaddr: [0; 4],
            yiaddr: self.plan.lease_ip,
            siaddr: self.plan.server_ip,
            giaddr: [0; 4],
            chaddr: request.chaddr,
        }
        .encode_into(&mut reply);
        dhcp::append_message_type(&mut reply, reply_type);
        dhcp::append_server_identifier(&mut reply, self.plan.server_ip);
        dhcp::append_option(&mut reply, dhcp::OPT_SUBNET_MASK, &self.plan.netmask);
        dhcp::append_option(&mut reply, dhcp::OPT_ROUTER, &self.plan.server_ip);
        dhcp::append_option(&mut reply, dhcp::OPT_DNS_SERVER, &self.plan.server_ip);
        dhcp::append_option(
            &mut reply,
            dhcp::OPT_LEASE_TIME,
            &self.plan.lease_seconds.to_be_bytes(),
        );
        dhcp::append_end(&mut reply);
        Some(udp_ipv4(
            self.plan.station,
            self.plan.bssid,
            self.plan.server_ip,
            [255; 4],
            67,
            68,
            &reply,
        ))
    }
}

#[derive(Default)]
struct Options {
    kind: Option<u8>,
    requested_ip: Option<[u8; 4]>,
    server: Option<[u8; 4]>,
}

impl Options {
    fn parse(mut bytes: &[u8]) -> Option<Self> {
        let mut out = Self::default();
        while let Some((&tag, rest)) = bytes.split_first() {
            bytes = rest;
            match tag {
                dhcp::OPT_END => return Some(out),
                dhcp::OPT_PAD => continue,
                _ => {}
            }
            let (&len, rest) = bytes.split_first()?;
            let data = rest.get(..usize::from(len))?;
            bytes = rest.get(usize::from(len)..)?;
            match tag {
                dhcp::OPT_DHCP_MESSAGE_TYPE if data.len() == 1 && out.kind.is_none() => {
                    out.kind = Some(data[0])
                }
                dhcp::OPT_REQUESTED_IP if data.len() == 4 && out.requested_ip.is_none() => {
                    out.requested_ip = Some(data.try_into().ok()?)
                }
                dhcp::OPT_SERVER_IDENTIFIER if data.len() == 4 && out.server.is_none() => {
                    out.server = Some(data.try_into().ok()?)
                }
                dhcp::OPT_DHCP_MESSAGE_TYPE
                | dhcp::OPT_REQUESTED_IP
                | dhcp::OPT_SERVER_IDENTIFIER => return None,
                _ => {}
            }
        }
        None // Missing END or a truncated TLV is not a valid conversation.
    }
}

fn client_payload(eth: &[u8]) -> Option<&[u8]> {
    if eth.get(12..14)? != ETHERTYPE_IPV4.to_be_bytes() {
        return None;
    }
    let ip = eth.get(ETH_HDR_LEN..)?;
    if ip.len() < IPV4_HDR_LEN || ip[0] >> 4 != 4 || ip[9] != IP_PROTO_UDP {
        return None;
    }
    if ip[12..16] != [0; 4] || ip[16..20] != [255; 4] {
        return None;
    }
    let ihl = usize::from(ip[0] & 15) * 4;
    let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    if ihl < IPV4_HDR_LEN
        || total < ihl + pkt_udp::UDP_HDR_LEN
        || u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0
        || pkt::ip_checksum(ip.get(..ihl)?) != 0
    {
        return None;
    }
    let udp = ip.get(ihl..total)?;
    if udp[..4] != [0, 68, 0, 67]
        || usize::from(u16::from_be_bytes([udp[4], udp[5]])) != udp.len()
        || pkt_udp::verify_ipv4(
            ip[12..16].try_into().ok()?,
            ip[16..20].try_into().ok()?,
            udp,
        )
        .is_err()
    {
        return None;
    }
    udp.get(pkt_udp::UDP_HDR_LEN..)
}

/// Decode a client DHCP message without accepting malformed packet lengths,
/// fragmentation, checksums, duplicate control options or truncated TLVs.
pub fn dhcp_message_type(eth: &[u8]) -> Option<u8> {
    let payload = client_payload(eth)?;
    DhcpHeader::decode(payload).ok()?;
    Options::parse(payload.get(dhcp::DHCP_HDR_LEN..)?)?.kind
}

/// Build fixture Ethernet/IPv4/UDP bytes, including both checksums.
/// Panics if a caller asks for an IPv4 datagram larger than its wire length.
pub fn udp_ipv4(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total = IPV4_HDR_LEN + pkt_udp::UDP_HDR_LEN + payload.len();
    let ip_total = u16::try_from(total).expect("fixture IPv4 length");
    let mut frame = vec![0; ETH_HDR_LEN + total];
    pkt::write_eth_header(&mut frame, dst_mac, src_mac, ETHERTYPE_IPV4);
    let ip = &mut frame[ETH_HDR_LEN..];
    pkt::write_ipv4_header(ip, ip_total, IP_PROTO_UDP, src_ip, dst_ip).expect("fixture IP header");
    pkt::set_ipv4_checksum(ip);
    pkt_udp::build_ipv4(
        &mut ip[IPV4_HDR_LEN..],
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        payload,
    )
    .expect("fixture UDP header");
    frame
}

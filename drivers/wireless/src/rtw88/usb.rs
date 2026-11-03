// SPDX-License-Identifier: GPL-2.0-or-later
//! RTW88 USB host-interface transport for the RTL8821C die (RTL8821CU).
//!
//! Port of Linux 7.3-rc4 `rtw88/usb.c`, `usb.h` and `rtw8821cu.c` plus the
//! USB branches of `mac.c` (`rtw_mac_pre_system_cfg`, `rtw_mac_power_switch`,
//! `txdma_queue_mapping`, `__priority_queue_cfg`, `send_firmware_pkt`),
//! `fw.c::rtw_fw_write_data_rsvd_page`, `tx.c::rtw_tx_fill_tx_desc`,
//! `tx.h::fill_txdesc_checksum_common` and `rtw8821c.c` (USB power rows,
//! `rqpn_table_8821c`, `page_table_8821c`, `rtw8821cu_efuse_parsing`).
//!
//! The PCI backend (`pci*.rs`, `reserved_page.rs`, `power.rs`, `mac.rs`) is
//! not touched: every USB difference lives here, so PCI stays byte-identical.
//! Register access is the asynchronous EP0 vendor request owned by the
//! existing NARF USB stack (`rtl8xxxu::firmware_transport::ControlIo`, bound
//! to `narf_drivers_usb::device::USBDevice`); bulk data uses
//! `narf_drivers_usb::bulk`. Nothing here publishes a station, a band or a
//! TX grant: see `drivers/wireless/specification/rtw88.md` "RTL8821CU USB
//! transport" for the remaining admission blockers.

use super::power::Command;
use crate::rtl8xxxu::firmware_transport::ControlIo;
use alloc::vec::Vec;
use narf_drivers_usb::device::UsbError;

/// `usb.h`: `RTW_USB_CMD_READ` / `RTW_USB_CMD_WRITE` / `RTW_USB_CMD_REQ`.
pub(super) const CMD_READ: u8 = 0xc0;
pub(super) const CMD_WRITE: u8 = 0x40;
pub(super) const CMD_REQ: u8 = 0x05;
/// `usb.h`: `RTW_USB_MAX_XMITBUF_SZ`, `RTW_USB_MAX_RECVBUF_SZ`.
pub(super) const MAX_XMITBUF: usize = 1024 * 20;
pub(super) const MAX_RECVBUF: usize = 32768;
/// `usb.h`: `RTW_USB_EP_MAX`, `TX_DESC_QSEL_MAX`.
pub(super) const EP_MAX: usize = 4;
pub(super) const QSEL_MAX: usize = 20;
/// `rtw8821c_hw_spec`: `tx_pkt_desc_sz`, `rx_pkt_desc_sz`,
/// `usb_tx_agg_desc_num`, `page_size` (`TX_PAGE_SIZE`).
pub(super) const TX_DESC: usize = 48;
pub(super) const RX_DESC: usize = 24;
pub(super) const TX_AGG_DESC_NUM: u8 = 3;
/// `rtw_usb_write_firmware_page` block size for every chip but 8723D.
pub(super) const FW_PAGE_BLOCK: usize = 196;
/// `fw.h`: `FW_START_ADDR_LEGACY`.
pub(super) const FW_START_ADDR_LEGACY: u16 = 0x1000;
/// `main.c::rtw_chip_parameter_setup` USB `rpwm_addr` / `cpwm_addr`.
pub(super) const RPWM: u16 = 0xfe58;
pub(super) const CPWM: u16 = 0xfe57;
/// Linux `IEEE80211_MAX_MPDU_LEN_VHT_11454` + `PHY_STATUS_SIZE * 8`.
const MAX_RX_SKB: usize = RX_DESC + 4 * 8 + 11454;

/// `tx.h` TX descriptor queue selectors.
pub(super) const QSEL_BEACON: u8 = 0x10;
pub(super) const QSEL_HIGH: u8 = 0x11;
pub(super) const QSEL_MGMT: u8 = 0x12;
pub(super) const QSEL_H2C: u8 = 0x13;

// reg.h offsets used only by the USB branches below.
const REG_SYS_FUNC_EN: u16 = 0x02;
const REG_RF_CTRL: u16 = 0x1f;
const REG_GPIO_MUXCFG: u16 = 0x40;
const REG_LED_CFG: u16 = 0x4c;
const REG_PAD_CTRL1: u16 = 0x64;
const REG_MCUFW_CTRL: u16 = 0x80;
const REG_WLRF1: u16 = 0xec;
const REG_SYS_CFG1: u16 = 0xf0;
const REG_SYS_STATUS1: u16 = 0xf4;
const REG_CR: u16 = 0x100;
const REG_TXDMA_PQ_MAP: u16 = 0x10c;
const REG_AUTO_LLT_V1: u16 = 0x208;
const REG_TXDMA_OFFSET_CHK: u16 = 0x20c;
const REG_RXDMA_AGG_PG_TH: u16 = 0x280;
const REG_RXDMA_MODE: u16 = 0x290;
const REG_CPU_DMEM_CON: u16 = 0x1080;
const REG_CR_EXT: u16 = 0x1100;
const BIT_RXDMA_ARBBW_EN: u8 = 1 << 0;
const BIT_RXDMA_AGG_EN: u8 = 1 << 2;
const BIT_DROP_DATA_EN: u16 = 1 << 9;
/// `rtw8821c_hw_spec.sys_func_en`.
const SYS_FUNC_EN_8821C: u8 = 0xd8;
/// `main.h`: `RTW_PWR_POLLING_CNT`; `do_pwr_poll_cmd` polls every 50us.
const POLLING_CNT: u32 = 20000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Usb(UsbError),
    /// The control or bulk transfer moved fewer bytes than requested.
    Short,
    /// The configuration descriptor does not describe a usable rtw88
    /// vendor interface (`rtw_usb_parse` -EINVAL).
    Endpoints,
    /// `txdma_queue_mapping` / `priority_queue_cfg` -EINVAL bulk-out count.
    BulkOut,
    /// Power-sequence poll, LLT or beacon-valid receipt never arrived.
    Timeout,
    /// `rtw_mac_power_switch` -EALREADY.
    Already,
    /// A power command used an opcode the parser does not model.
    Command,
    /// The device read back all-ones or an unsupported cut.
    Gone,
    /// A packet would not fit the descriptor/aggregate limits.
    Packet,
}
impl From<UsbError> for Error {
    fn from(error: UsbError) -> Self {
        Self::Usb(error)
    }
}

/// `rtw8821cu.c::rtw_8821cu_id_table` (all entries bind
/// `rtw8821c_hw_spec`, vendor-specific interface 0xff/0xff/0xff).
pub(super) const RTL8821CU_IDS: &[(u16, u16)] = &[
    (0x0bda, 0x2006),
    (0x0bda, 0x8731),
    (0x0bda, 0x8811),
    (0x0bda, 0xb820),
    (0x0bda, 0xb82b),
    (0x0bda, 0xc80c),
    (0x0bda, 0xc811),
    (0x0bda, 0xc820),
    (0x0bda, 0xc821),
    (0x0bda, 0xc82a),
    (0x0bda, 0xc82b),
    (0x2001, 0x331d),
    (0x7392, 0xc811),
    (0x7392, 0xd811),
    (0x2c4e, 0x0105),
];
pub(super) fn is_rtl8821cu(vid: u16, pid: u16) -> bool {
    RTL8821CU_IDS.contains(&(vid, pid))
}

/// Bus speed as `rtw_usb_init_burst_pkt_len` / `rtw_usb_dynamic_rx_agg`
/// observe it (`usb_device_speed`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Speed {
    Full,
    High,
    Super,
}
impl Speed {
    pub(super) fn from_port(speed: narf_drivers_usb::xhci::PortSpeed) -> Self {
        use narf_drivers_usb::xhci::PortSpeed;
        match speed {
            PortSpeed::Super | PortSpeed::SuperPlus => Self::Super,
            PortSpeed::High => Self::High,
            PortSpeed::Full | PortSpeed::Low => Self::Full,
        }
    }
}

/// `enum rtw_dma_mapping`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum Dma {
    Extra = 0,
    Low = 1,
    Normal = 2,
    High = 3,
}
impl Dma {
    /// `usb.c::dma_mapping_to_ep`.
    fn endpoint(self) -> usize {
        match self {
            Self::High => 0,
            Self::Normal => 1,
            Self::Low => 2,
            Self::Extra => 3,
        }
    }
}
/// `struct rtw_rqpn` field order: vo, vi, be, bk, mg, hi.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Rqpn {
    pub vo: Dma,
    pub vi: Dma,
    pub be: Dma,
    pub bk: Dma,
    pub mg: Dma,
    pub hi: Dma,
}
/// `struct rtw_page_table` field order: hq, nq, lq, exq, gapq.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Pages {
    pub hq: u16,
    pub nq: u16,
    pub lq: u16,
    pub exq: u16,
    pub gapq: u16,
}
const fn rqpn(vo: Dma, vi: Dma, be: Dma, bk: Dma, mg: Dma, hi: Dma) -> Rqpn {
    Rqpn {
        vo,
        vi,
        be,
        bk,
        mg,
        hi,
    }
}
const fn pages(hq: u16, nq: u16, lq: u16, exq: u16, gapq: u16) -> Pages {
    Pages {
        hq,
        nq,
        lq,
        exq,
        gapq,
    }
}
/// `rtw8821c.c::rqpn_table_8821c`; index is the bulk-out endpoint count.
pub(super) const RQPN_8821C: [Rqpn; 5] = {
    use Dma::*;
    [
        rqpn(Normal, Normal, Low, Low, Extra, High),
        rqpn(Normal, Normal, Low, Low, Extra, High),
        rqpn(Normal, Normal, Normal, High, High, High),
        rqpn(Normal, Normal, Low, Low, High, High),
        rqpn(Normal, Normal, Low, Low, Extra, High),
    ]
};
/// `rtw8821c.c::page_table_8821c`; index is the bulk-out endpoint count.
pub(super) const PAGES_8821C: [Pages; 5] = [
    pages(16, 16, 16, 14, 1),
    pages(16, 16, 16, 14, 1),
    pages(16, 16, 0, 0, 1),
    pages(16, 16, 16, 0, 1),
    pages(16, 16, 16, 14, 1),
];
/// USB rows only exist for two, three or four bulk-out pipes
/// (`txdma_queue_mapping` / `priority_queue_cfg` return -EINVAL otherwise).
pub(super) fn usb_tables(bulkout: usize) -> Result<(Rqpn, Pages), Error> {
    match bulkout {
        2..=4 => Ok((RQPN_8821C[bulkout], PAGES_8821C[bulkout])),
        _ => Err(Error::BulkOut),
    }
}
/// `mac.c::txdma_queue_mapping` REG_TXDMA_PQ_MAP value.
pub(super) fn txdma_pq_map(r: Rqpn) -> u16 {
    (r.hi as u16) << 14
        | (r.mg as u16) << 12
        | (r.bk as u16) << 10
        | (r.be as u16) << 8
        | (r.vi as u16) << 6
        | (r.vo as u16) << 4
}
/// `priority_queue_cfg` public-queue size over `rtw_set_trx_fifo_info`'s
/// acquired pages (`txff_pg_num - rsvd_pg_num`).
pub(super) fn public_pages(acq: u16, p: Pages) -> Option<u16> {
    acq.checked_sub(p.hq)?
        .checked_sub(p.lq)?
        .checked_sub(p.nq)?
        .checked_sub(p.exq)?
        .checked_sub(p.gapq)
}

/// Endpoint geometry from `rtw_usb_parse`: the bulk-IN pipe, the optional
/// interrupt-IN pipe and up to four bulk-OUT pipes in descriptor order,
/// with the derived `qsel_to_ep` table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Endpoints {
    pub bulk_in: u8,
    pub bulk_in_packet: u16,
    pub interrupt_in: Option<u8>,
    pub out: [u8; EP_MAX],
    pub out_packets: [u16; EP_MAX],
    pub out_count: u8,
    /// Index into `out`, None where Linux stores -EINVAL (TID8..15).
    pub qsel_to_ep: [Option<u8>; QSEL_MAX],
}
impl Endpoints {
    /// Parse a full configuration descriptor. The rtw88 USB id table binds
    /// only the vendor-specific (0xff/0xff/0xff) interface, altsetting 0.
    pub(super) fn parse(config: &[u8]) -> Result<Self, Error> {
        if config.len() < 9 || config[0] != 9 || config[1] != 2 {
            return Err(Error::Endpoints);
        }
        let total = usize::from(u16::from_le_bytes([config[2], config[3]]));
        if total != config.len() {
            return Err(Error::Endpoints);
        }
        let mut plan = Self {
            bulk_in: 0,
            bulk_in_packet: 0,
            interrupt_in: None,
            out: [0; EP_MAX],
            out_packets: [0; EP_MAX],
            out_count: 0,
            qsel_to_ep: [None; QSEL_MAX],
        };
        let (mut offset, mut claimed, mut selected) = (9, false, false);
        let (mut advertised, mut seen) = (0u8, 0u8);
        while offset < total {
            let length = usize::from(config[offset]);
            if length < 2 || offset + length > total {
                return Err(Error::Endpoints);
            }
            let d = &config[offset..offset + length];
            match d[1] {
                4 => {
                    if d.len() < 9 || selected && seen != advertised {
                        return Err(Error::Endpoints);
                    }
                    selected = !claimed && d[3] == 0 && d[5..8] == [0xff; 3];
                    if selected {
                        claimed = true;
                        advertised = d[4];
                        seen = 0;
                    }
                }
                5 if selected => {
                    if d.len() < 7 {
                        return Err(Error::Endpoints);
                    }
                    seen += 1;
                    let (address, kind) = (d[2], d[3] & 3);
                    let packet = u16::from_le_bytes([d[4], d[5]]) & 0x7ff;
                    if address & 0x70 != 0 || address & 15 == 0 || packet == 0 {
                        return Err(Error::Endpoints);
                    }
                    let input = address & 0x80 != 0;
                    match (input, kind) {
                        // "IN pipes overflow" / "INT pipes overflow".
                        (true, 2) if plan.bulk_in != 0 => return Err(Error::Endpoints),
                        (true, 2) => {
                            plan.bulk_in = address;
                            plan.bulk_in_packet = packet;
                        }
                        (true, 3) if plan.interrupt_in.is_some() => return Err(Error::Endpoints),
                        (true, 3) => plan.interrupt_in = Some(address),
                        (false, 2) => {
                            let slot = usize::from(plan.out_count);
                            if slot == EP_MAX || plan.out[..slot].contains(&address) {
                                return Err(Error::Endpoints);
                            }
                            plan.out[slot] = address;
                            plan.out_packets[slot] = packet;
                            plan.out_count += 1;
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
            offset += length;
        }
        if !claimed || seen != advertised || plan.bulk_in == 0 || plan.out_count == 0 {
            return Err(Error::Endpoints);
        }
        let r = RQPN_8821C[usize::from(plan.out_count)];
        let mut map = [None; QSEL_MAX];
        for (qsel, dma) in [
            (0, r.be),
            (1, r.bk),
            (2, r.bk),
            (3, r.be),
            (4, r.vi),
            (5, r.vi),
            (6, r.vo),
            (7, r.vo),
            (usize::from(QSEL_BEACON), r.hi),
            (usize::from(QSEL_HIGH), r.hi),
            (usize::from(QSEL_MGMT), r.mg),
            (usize::from(QSEL_H2C), r.hi),
        ] {
            let ep = dma.endpoint();
            // Linux indexes out_ep[] unchecked; a mapping past the
            // discovered pipes would submit on endpoint 0. Refuse it.
            if ep >= usize::from(plan.out_count) {
                return Err(Error::Endpoints);
            }
            map[qsel] = Some(ep as u8);
        }
        plan.qsel_to_ep = map;
        Ok(plan)
    }
    /// `usb.c::qsel_to_ep` then `out_ep[ep]`: the bulk-OUT address.
    pub(super) fn out_for(&self, qsel: u8) -> Option<u8> {
        let ep = (*self.qsel_to_ep.get(usize::from(qsel))?)?;
        Some(self.out[usize::from(ep)])
    }
}

/// `usb.c::rtw_usb_tx_queue_mapping_to_qsel`: management/control frames to
/// MGMT, group-addressed to HIGH, other frames to `skb->priority` (the
/// TID). Linux's BEACON fallback needs a queue mapping above
/// `IEEE80211_AC_BK` (3), the largest AC index, so only a priority outside
/// the TID range reaches it here.
pub(super) fn tx_qsel(frame: &[u8], tid: u8) -> Option<u8> {
    let fc = *frame.first()?;
    let addr1 = frame.get(4..10)?;
    Some(if matches!(fc & 0x0c, 0x00 | 0x04) {
        QSEL_MGMT
    } else if addr1[0] & 1 != 0 {
        QSEL_HIGH
    } else if tid < 8 {
        tid
    } else {
        QSEL_BEACON
    })
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn put(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// `tx.h::fill_txdesc_checksum_common(txdesc, 16)` as used by
/// `rtw8821c_fill_txdesc_checksum`: clear W7[15:0], XOR the first sixteen
/// little-endian 16-bit words, store the result in W7[15:0].
pub(super) fn fill_checksum(desc: &mut [u8; TX_DESC]) {
    let w7 = word(desc, 28) & !0xffff;
    put(desc, 28, w7);
    let mut sum = 0u16;
    for pair in desc[..32].chunks_exact(2) {
        sum ^= u16::from_le_bytes([pair[0], pair[1]]);
    }
    put(desc, 28, w7 | u32::from(sum));
}

/// The subset of `struct rtw_tx_pkt_info` that the USB firmware/H2C paths
/// populate (everything else is zero in `rtw_usb_write_data_rsvd_page` /
/// `rtw_usb_write_data_h2c`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct PacketInfo {
    pub size: u16,
    pub offset: u8,
    pub ls: bool,
    pub qsel: u8,
}
/// `tx.c::rtw_tx_fill_tx_desc` for [`PacketInfo`] (MORE_DATA follows
/// `qsel == TX_DESC_QSEL_HIGH`), followed by the USB checksum.
pub(super) fn descriptor(info: PacketInfo) -> [u8; TX_DESC] {
    let mut desc = [0; TX_DESC];
    put(
        &mut desc,
        0,
        u32::from(info.size) | u32::from(info.offset) << 16 | u32::from(info.ls) << 26,
    );
    put(
        &mut desc,
        4,
        u32::from(info.qsel & 0x1f) << 8 | u32::from(info.qsel == QSEL_HIGH) << 29,
    );
    fill_checksum(&mut desc);
    desc
}
/// `rtw_usb_write_data_rsvd_page` behind `mac.c::send_firmware_pkt`: the
/// payload grows by one byte when descriptor + payload is a multiple of
/// the 512-byte high-speed bulk packet (no zero-length terminator needed).
/// The extra byte comes from the caller's buffer in Linux; it is zero here.
pub(super) fn reserved_page_packet(data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut size = data.len();
    if (size + TX_DESC) & 511 == 0 {
        size += 1;
    }
    let length = u16::try_from(size).map_err(|_| Error::Packet)?;
    let mut packet = Vec::with_capacity(TX_DESC + size);
    packet.extend_from_slice(&descriptor(PacketInfo {
        size: length,
        offset: TX_DESC as u8,
        ls: true,
        qsel: QSEL_BEACON,
    }));
    packet.extend_from_slice(data);
    packet.resize(TX_DESC + size, 0);
    Ok(packet)
}
/// `rtw_usb_write_data_h2c`: only size and qsel are set (offset 0, no LS).
pub(super) fn h2c_packet(h2c: &[u8]) -> Result<Vec<u8>, Error> {
    let size = u16::try_from(h2c.len()).map_err(|_| Error::Packet)?;
    let mut packet = Vec::with_capacity(TX_DESC + h2c.len());
    packet.extend_from_slice(&descriptor(PacketInfo {
        size,
        qsel: QSEL_H2C,
        ..PacketInfo::default()
    }));
    packet.extend_from_slice(h2c);
    Ok(packet)
}

/// `rtw_usb_tx_agg_skb`: pack descriptor-prefixed packets of one bulk-OUT
/// queue, each start 8-byte aligned, up to `usb_tx_agg_desc_num` packets
/// and [`MAX_XMITBUF`] bytes. With more than one packet the head
/// descriptor carries DMA_TXAGG_NUM (W7[31:24]) and a refreshed checksum.
/// Returns the URB payload and the number of packets consumed.
pub(super) fn aggregate(packets: &[Vec<u8>]) -> Result<(Vec<u8>, usize), Error> {
    let first = packets.first().ok_or(Error::Packet)?;
    if first.len() < TX_DESC || first.len() > MAX_XMITBUF {
        return Err(Error::Packet);
    }
    if packets.len() == 1 {
        return Ok((first.clone(), 1));
    }
    let mut head = Vec::with_capacity(MAX_XMITBUF);
    let mut count = 0usize;
    let mut align = 0;
    for packet in packets {
        if packet.len() < TX_DESC {
            return Err(Error::Packet);
        }
        if count != 0
            && (count == usize::from(TX_AGG_DESC_NUM) || packet.len() + head.len() > MAX_XMITBUF)
        {
            break;
        }
        head.resize(head.len() + align, 0);
        head.extend_from_slice(packet);
        align = packet.len().next_multiple_of(8) - packet.len();
        count += 1;
    }
    if count > 1 {
        let desc: &mut [u8; TX_DESC] = (&mut head[..TX_DESC]).try_into().unwrap();
        let w7 = word(desc, 28) & 0x00ff_ffff | (count as u32) << 24;
        put(desc, 28, w7);
        fill_checksum(desc);
    }
    Ok((head, count))
}

/// One packet of a bulk-IN aggregate: the whole descriptor-prefixed record
/// (`rx_desc .. rx_desc + skb_len`) and its `pkt_offset`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RxRecord<'a> {
    pub bytes: &'a [u8],
    pub payload_offset: usize,
    pub c2h: bool,
}
/// `usb.c::rtw_usb_rx_handler` framing loop over one completed URB: each
/// record is RXDESC + drv_info (8-byte units) + shift + pkt_len; the next
/// record starts at `round_up(skb_len, 8)`. Records above Linux's
/// `max_skb_len` are skipped, a record past the URB ends the walk.
/// Callers still admit each record through `packet_format::receive*`.
pub(super) fn split_rx(urb: &[u8]) -> Vec<RxRecord<'_>> {
    let mut records = Vec::new();
    // rtw_usb_read_port_complete drops URBs shorter than 24 bytes or
    // filling the whole receive buffer.
    if urb.len() < 24 || urb.len() >= MAX_RECVBUF {
        return records;
    }
    // do { ... } while (rx_desc + pkt_desc_sz < end): the first record is
    // parsed unconditionally (the URB already holds >= 24 bytes).
    let mut at = 0usize;
    loop {
        let w0 = word(urb, at);
        let length = (w0 & 0x3fff) as usize;
        let drv_info = ((w0 >> 16) & 15) as usize * 8;
        let shift = ((w0 >> 24) & 3) as usize;
        let c2h = word(urb, at + 8) & (1 << 28) != 0;
        let offset = RX_DESC + drv_info + shift;
        let total = length + offset;
        if total <= MAX_RX_SKB {
            match urb.get(at..at + total) {
                Some(bytes) => records.push(RxRecord {
                    bytes,
                    payload_offset: offset,
                    c2h,
                }),
                None => break,
            }
        }
        at += total.next_multiple_of(8);
        if at + RX_DESC >= urb.len() {
            break;
        }
    }
    records
}

/// `rtw8821cu_efuse_parsing`: the USB logical map keeps the MAC at 0x107
/// (`struct rtw8821cu_efuse`), not the PCI 0xd0 used by `Factory8821c`.
pub(super) fn efuse_mac(logical: &[u8; 512]) -> [u8; 6] {
    logical[0x107..0x10d].try_into().unwrap()
}

/// `rtw8821c.c` power sequences filtered to `RTW_PWR_INTF_USB_MSK`
/// (all rows are `RTW_PWR_ADDR_MAC`/`_USB`, so offsets are used as-is).
pub(super) const CARDDIS_TO_CARDEMU_8821C_USB: &[Command] = &[
    cmd(0x004a, 1, 0x01, 0x00),
    cmd(0x0005, 1, 0x98, 0x00),
    cmd(0xffff, 4, 0x00, 0x00),
];
pub(super) const CARDEMU_TO_ACT_8821C_USB: &[Command] = &[
    cmd(0x0020, 1, 0x01, 0x01),
    cmd(0x0001, 3, 0x01, 0x01),
    cmd(0x0000, 1, 0x20, 0x00),
    cmd(0x0005, 1, 0x1c, 0x00),
    cmd(0x0006, 2, 0x02, 0x02),
    cmd(0x0006, 1, 0x01, 0x01),
    cmd(0x0005, 1, 0x80, 0x00),
    cmd(0x0005, 1, 0x18, 0x00),
    cmd(0x10c3, 1, 0x01, 0x01),
    cmd(0x0005, 1, 0x01, 0x01),
    cmd(0x0005, 2, 0x01, 0x00),
    cmd(0x0020, 1, 0x08, 0x08),
    cmd(0x007c, 1, 0x02, 0x00),
    cmd(0xffff, 4, 0x00, 0x00),
];
pub(super) const ACT_TO_CARDEMU_8821C_USB: &[Command] = &[
    cmd(0x0093, 1, 0x08, 0x00),
    cmd(0x001f, 1, 0xff, 0x00),
    cmd(0x0049, 1, 0x02, 0x00),
    cmd(0x0006, 1, 0x01, 0x01),
    cmd(0x0002, 1, 0x02, 0x00),
    cmd(0x10c3, 1, 0x01, 0x00),
    cmd(0x0005, 1, 0x02, 0x02),
    cmd(0x0005, 2, 0x02, 0x00),
    cmd(0x0020, 1, 0x08, 0x00),
    cmd(0x0000, 1, 0x20, 0x20),
    cmd(0xffff, 4, 0x00, 0x00),
];
pub(super) const CARDEMU_TO_CARDDIS_8821C_USB: &[Command] = &[
    cmd(0x0007, 1, 0xff, 0x20),
    cmd(0x0067, 1, 0x20, 0x00),
    cmd(0x004a, 1, 0x01, 0x00),
    cmd(0x0081, 1, 0xc0, 0x00),
    cmd(0x0005, 1, 0x18, 0x08),
    cmd(0x0090, 1, 0x02, 0x00),
    cmd(0xffff, 4, 0x00, 0x00),
];
const fn cmd(offset: u16, op: u8, mask: u8, value: u8) -> Command {
    Command {
        offset,
        cut: 0xff,
        op,
        mask,
        value,
    }
}

/// Register owner over EP0 vendor requests (`rtw_usb_read` /
/// `rtw_usb_write`). Every access to the always-on section
/// (0x00..=0xff, 0x1000..=0x10ff) is followed, as `rtw_usb_reg_sec` does
/// for 8822C/8822B/8821C, by a one-byte write of the same data buffer's
/// first byte to 0x4e0.
pub(super) struct Registers<C: ControlIo> {
    io: C,
}
impl<C: ControlIo> Registers<C> {
    pub(super) fn new(io: C) -> Self {
        Self { io }
    }
    pub(super) fn control(&self) -> &C {
        &self.io
    }
    async fn section(&self, addr: u16, data: &[u8]) -> Result<(), Error> {
        let on = addr <= 0xff || (0x1000..=0x10ff).contains(&addr);
        if on && self.io.write(0x4e0, &data[..1]).await? != 1 {
            return Err(Error::Short);
        }
        Ok(())
    }
    async fn read(&self, addr: u16, len: usize) -> Result<u32, Error> {
        let mut data = [0u8; 4];
        let n = self.io.read(addr, &mut data[..len]).await?;
        if n != len {
            return Err(Error::Short);
        }
        self.section(addr, &data).await?;
        Ok(u32::from_le_bytes(data))
    }
    async fn write(&self, addr: u16, value: u32, len: usize) -> Result<(), Error> {
        let data = value.to_le_bytes();
        if self.io.write(addr, &data[..len]).await? != len {
            return Err(Error::Short);
        }
        self.section(addr, &data).await
    }
    pub(super) async fn read8(&self, addr: u16) -> Result<u8, Error> {
        Ok(self.read(addr, 1).await? as u8)
    }
    pub(super) async fn read16(&self, addr: u16) -> Result<u16, Error> {
        Ok(self.read(addr, 2).await? as u16)
    }
    pub(super) async fn read32(&self, addr: u16) -> Result<u32, Error> {
        self.read(addr, 4).await
    }
    pub(super) async fn write8(&self, addr: u16, value: u8) -> Result<(), Error> {
        self.write(addr, value.into(), 1).await
    }
    pub(super) async fn write16(&self, addr: u16, value: u16) -> Result<(), Error> {
        self.write(addr, value.into(), 2).await
    }
    pub(super) async fn write32(&self, addr: u16, value: u32) -> Result<(), Error> {
        self.write(addr, value, 4).await
    }
    async fn update8(&self, addr: u16, clear: u8, set: u8) -> Result<(), Error> {
        let value = self.read8(addr).await?;
        self.write8(addr, value & !clear | set).await
    }
    async fn update32(&self, addr: u16, clear: u32, set: u32) -> Result<(), Error> {
        let value = self.read32(addr).await?;
        if value == u32::MAX {
            return Err(Error::Gone);
        }
        self.write32(addr, value & !clear | set).await
    }

    /// `rtw_usb_write_firmware_page` (legacy 8051 download; the C21 3081
    /// MCU downloads through the reserved page instead): select ROM page
    /// in REG_MCUFW_CTRL[18:16], then write 196/8/1-byte blocks at 0x1000.
    pub(super) async fn write_firmware_page(&self, page: u32, data: &[u8]) -> Result<(), Error> {
        self.update32(REG_MCUFW_CTRL, 7 << 16, (page & 7) << 16)
            .await?;
        let mut addr = FW_START_ADDR_LEGACY;
        let mut rest = data;
        while !rest.is_empty() {
            let n = if rest.len() >= FW_PAGE_BLOCK {
                FW_PAGE_BLOCK
            } else if rest.len() >= 8 {
                8
            } else {
                1
            };
            if self.io.write(addr, &rest[..n]).await? != n {
                return Err(Error::Short);
            }
            addr = addr.wrapping_add(n as u16);
            rest = &rest[n..];
        }
        Ok(())
    }

    async fn commands(&self, cut_mask: u8, rows: &[Command]) -> Result<(), Error> {
        for row in rows {
            if row.op == 4 {
                return Ok(());
            }
            if row.cut & cut_mask == 0 {
                continue;
            }
            match row.op {
                0 => {}
                1 => {
                    self.update8(row.offset, row.mask, row.value & row.mask)
                        .await?
                }
                2 => {
                    // do_pwr_poll_cmd; USB has no PFM_WOWL retry (PCIe only).
                    let target = row.value & row.mask;
                    let mut done = false;
                    for _ in 0..POLLING_CNT {
                        if self.read8(row.offset).await? & row.mask == target {
                            done = true;
                            break;
                        }
                        self.io.delay_us(50).await;
                    }
                    if !done {
                        return Err(Error::Timeout);
                    }
                }
                3 => {
                    let unit = if row.value == 0 { 1 } else { 1000 };
                    self.io.delay_us(u64::from(row.offset) * unit).await;
                }
                _ => return Err(Error::Command),
            }
        }
        Err(Error::Command)
    }

    /// `mac.c::rtw_mac_pre_system_cfg` for a 3081-MCU chip on USB: the HCI
    /// switch has no USB write; pin-mux, BB/RF disable follow.
    pub(super) async fn pre_system(&self) -> Result<(), Error> {
        self.write8(0x1c, 0).await?; // REG_RSV_CTRL
        self.update32(REG_PAD_CTRL1, 0, 1 << 29 | 1 << 28).await?;
        self.update32(REG_LED_CFG, 1 << 25 | 1 << 26, 0).await?;
        self.update32(REG_GPIO_MUXCFG, 0, 1 << 2).await?;
        self.update8(REG_SYS_FUNC_EN, 3, 0).await?;
        self.update8(REG_RF_CTRL, 7, 0).await?;
        self.update32(REG_WLRF1, 7 << 24, 0).await
    }

    /// `mac.c::rtw_mac_power_switch` on USB for RTL8821C.
    pub(super) async fn power_switch(&self, on: bool) -> Result<(), Error> {
        let config = self.read32(REG_SYS_CFG1).await?;
        if config == u32::MAX {
            return Err(Error::Gone);
        }
        let cut = (config >> 12) & 15;
        if cut > 6 {
            return Err(Error::Gone);
        }
        // rtw_chip_wcpu_3081: toggle RPWM when firmware is still resident.
        let rpwm = self.read8(RPWM).await?;
        if self.read16(REG_MCUFW_CTRL).await? == 0xc078 {
            self.write8(RPWM, (rpwm ^ 0x80) & 0x80).await?;
        }
        let current =
            !(self.read8(REG_CR).await? == 0xea || self.read8(REG_SYS_STATUS1 + 1).await? & 1 != 0);
        if on == current {
            return Err(Error::Already);
        }
        let mask = 1u8 << (cut + 1);
        let (first, second) = if on {
            (CARDDIS_TO_CARDEMU_8821C_USB, CARDEMU_TO_ACT_8821C_USB)
        } else {
            (ACT_TO_CARDEMU_8821C_USB, CARDEMU_TO_CARDDIS_8821C_USB)
        };
        self.commands(mask, first).await?;
        self.commands(mask, second).await?;
        if on {
            self.update8(REG_SYS_STATUS1 + 1, 1, 0).await?;
        }
        Ok(())
    }

    /// `mac.c::rtw_mac_power_on` (pre-system, switch with the -EALREADY
    /// off/on cycle, `__rtw_mac_init_system_cfg`).
    pub(super) async fn power_on(&self) -> Result<(), Error> {
        self.pre_system().await?;
        match self.power_switch(true).await {
            Err(Error::Already) => {
                // Linux ignores the result of this off transition.
                let _ = self.power_switch(false).await;
                self.pre_system().await?;
                self.power_switch(true).await?;
            }
            result => result?,
        }
        self.update32(REG_CPU_DMEM_CON, 0, 1 << 16 | 1 << 8).await?;
        self.update8(REG_SYS_FUNC_EN + 1, 0, SYS_FUNC_EN_8821C)
            .await?;
        self.update8(REG_CR_EXT + 3, 0x0f, 0x0c).await?;
        let mcu = self.read32(REG_MCUFW_CTRL).await?;
        if mcu & (1 << 20) != 0 {
            self.write32(REG_MCUFW_CTRL, mcu & !(1 << 20)).await?;
            self.update32(REG_GPIO_MUXCFG, 1 << 19, 0).await?;
        }
        Ok(())
    }

    /// `usb.c::rtw_usb_interface_cfg` -> `rtw_usb_init_burst_pkt_len`.
    pub(super) async fn interface_cfg(&self, speed: Speed) -> Result<(), Error> {
        let burst: u8 = match speed {
            Speed::Super => 0,
            Speed::High => 1,
            Speed::Full => 2,
        };
        // BIT_DMA_BURST_CNT | BIT_DMA_MODE, BIT_DMA_BURST_SIZE = burst.
        self.write8(REG_RXDMA_MODE, 0x0c | 0x02 | burst << 4)
            .await?;
        let value = self.read16(REG_TXDMA_OFFSET_CHK).await?;
        self.write16(REG_TXDMA_OFFSET_CHK, value | BIT_DROP_DATA_EN)
            .await
    }

    /// `usb.c::rtw_usb_dynamic_rx_agg_v1` (8821C/8822B/8822C/8814A).
    pub(super) async fn dynamic_rx_agg(&self, enable: bool) -> Result<(), Error> {
        self.update8(REG_TXDMA_PQ_MAP, 0, BIT_RXDMA_AGG_EN).await?;
        self.update8(REG_RXDMA_AGG_PG_TH + 3, 1 << 7, 0).await?;
        let (size, timeout) = if enable { (0x5, 0x20) } else { (0x0, 0x1) };
        self.write16(REG_RXDMA_AGG_PG_TH, size | timeout << 8).await
    }

    /// The USB-only tails of `txdma_queue_mapping` (REG_TXDMA_PQ_MAP from the
    /// endpoint-count row, then BIT_RXDMA_ARBBW_EN after CR enable) and
    /// `__priority_queue_cfg` (AUTO_LLT_V1 block-descriptor count and
    /// TXDMA_OFFSET_CHK+1 bit1). Order is the Linux order within each.
    pub(super) async fn queue_mapping(&self, bulkout: usize) -> Result<Rqpn, Error> {
        let (r, _) = usb_tables(bulkout)?;
        self.write16(REG_TXDMA_PQ_MAP, txdma_pq_map(r)).await?;
        Ok(r)
    }
    pub(super) async fn queue_mapping_tail(&self) -> Result<(), Error> {
        self.update8(REG_TXDMA_PQ_MAP, 0, BIT_RXDMA_ARBBW_EN).await
    }
    pub(super) async fn priority_queue_tail(&self) -> Result<(), Error> {
        self.update8(REG_AUTO_LLT_V1, 0xf0, TX_AGG_DESC_NUM << 4)
            .await?;
        self.write8(REG_AUTO_LLT_V1 + 3, TX_AGG_DESC_NUM).await?;
        self.update8(REG_TXDMA_OFFSET_CHK + 1, 0, 1 << 1).await
    }
}

/// `usb.c::rtw_usb_init_burst_pkt_len` over the firmware owner's
/// asynchronous register `Io` (the same writes as
/// [`Registers::interface_cfg`]), used by `mac::prepare_on` for USB.
pub(super) async fn interface_cfg(
    io: &mut impl super::firmware_transport::Io,
    speed: Speed,
) -> Result<(), super::firmware_transport::Error> {
    let burst: u8 = match speed {
        Speed::Super => 0,
        Speed::High => 1,
        Speed::Full => 2,
    };
    io.write8(REG_RXDMA_MODE, 0x0c | 0x02 | burst << 4).await?;
    let value = io.read16(REG_TXDMA_OFFSET_CHK).await?;
    io.write16(REG_TXDMA_OFFSET_CHK, value | BIT_DROP_DATA_EN)
        .await
}

/// Bulk transport over the enumerated device (`rtw_usb_write_port` /
/// `rtw_usb_rx_resubmit`). `URB_ZERO_PACKET` is the controller's job; the
/// reserved-page path avoids the case altogether (see
/// [`reserved_page_packet`]).
pub(super) struct Bulk<'a> {
    pub device: &'a narf_drivers_usb::device::USBDevice,
    pub endpoints: Endpoints,
}
impl Bulk<'_> {
    pub(super) async fn write_port(&self, qsel: u8, packet: &[u8]) -> Result<(), Error> {
        let ep = self.endpoints.out_for(qsel).ok_or(Error::Endpoints)?;
        let n = narf_drivers_usb::bulk::bulk_out(self.device, ep, packet).await?;
        if n != packet.len() {
            return Err(Error::Short);
        }
        Ok(())
    }
    pub(super) async fn read_port(&self, out: &mut [u8]) -> Result<usize, Error> {
        Ok(narf_drivers_usb::bulk::bulk_in(self.device, self.endpoints.bulk_in, out).await?)
    }
}

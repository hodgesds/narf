// SPDX-License-Identifier: GPL-2.0-or-later
//! Current peer TIM facts and Linux common-beacon/hw.c timer program.
use crate::ath9k::packet::Error;
#[derive(Clone, Copy)]
pub(in crate::ath9k) struct Tim {
    pub timestamp: u64,
    pub interval: u16,
    pub dtim_period: u8,
    pub unicast: bool,
    pub cab: bool,
}
impl Tim {
    pub(in crate::ath9k) fn parse(
        bytes: &[u8],
        own: [u8; 6],
        ap: [u8; 6],
        aid: u16,
    ) -> Result<Option<Self>, Error> {
        if bytes.len() < 36
            || bytes[..2] != [0x80, 0]
            || bytes[10..16] != ap
            || bytes[16..22] != ap
            || bytes[4..10] != own && bytes[4..10] != [255; 6]
        {
            return Ok(None);
        }
        if !(1..=2007).contains(&aid) || bytes[22] & 15 != 0 {
            return Err(Error::Packet);
        }
        let interval = u16::from_le_bytes([bytes[32], bytes[33]]);
        if !(1..=1024).contains(&interval) {
            return Err(Error::Packet);
        }
        let mut at = 36;
        let mut tim = None;
        while at < bytes.len() {
            let head = bytes.get(at..at + 2).ok_or(Error::Packet)?;
            let end = at
                .checked_add(2 + usize::from(head[1]))
                .ok_or(Error::Packet)?;
            let data = bytes.get(at + 2..end).ok_or(Error::Packet)?;
            if head[0] == 5 {
                if tim.is_some() || data.len() < 4 || data[1] == 0 || data[0] >= data[1] {
                    return Err(Error::Packet);
                }
                let offset = usize::from(data[2] & 0xfe);
                let octet = usize::from(aid / 8);
                let unicast = octet
                    .checked_sub(offset)
                    .and_then(|index| data.get(3 + index))
                    .is_some_and(|bitmap| bitmap & (1 << (aid & 7)) != 0);
                tim = Some(Self {
                    timestamp: u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
                    interval,
                    dtim_period: data[1],
                    unicast,
                    cab: data[0] == 0 && data[2] & 1 != 0,
                });
            }
            at = end;
        }
        // A source-qualified station cannot silently infer an absent TIM.
        tim.map(Some).ok_or(Error::Packet)
    }
    pub(in crate::ath9k) fn plan(self, tsf: u64) -> Plan {
        // common-beacon.c: FUDGE2 + default sw_response_time6 TU.
        let adjusted = tsf.wrapping_add(8 * 1024);
        let interval = u32::from(self.interval) * 1024;
        let dtim = interval * u32::from(self.dtim_period);
        let next = |period: u32| {
            (adjusted.wrapping_add(u64::from(period) - adjusted % u64::from(period))) as u32
        };
        let next_tbtt = next(interval);
        let next_dtim = next(dtim);
        // IEEE80211_MS_TO_TU(100)=97; source rounds to a beacon multiple.
        let sleep = (97u32.div_ceil(u32::from(self.interval)) * interval).min(dtim);
        let beacon = interval.max(sleep);
        let next_tim = if beacon == dtim { next_dtim } else { next_tbtt };
        Plan {
            registers: [
                (0x8200, next_tbtt),
                (0x8220, interval),
                (0x8224, interval),
                (0x8214, next_dtim.wrapping_sub(3 * 1024)),
                (0x8210, next_tim.wrapping_sub(3 * 1024)),
                (0x80d4, 0x0a080000),
                (0x80d8, 0x00200000),
                (0x8230, beacon),
                (0x8234, dtim),
                (0x813c, 0x4240),
            ],
        }
    }
}
#[derive(Clone, Copy)]
pub(in crate::ath9k) struct Plan {
    pub registers: [(u64, u32); 10],
}

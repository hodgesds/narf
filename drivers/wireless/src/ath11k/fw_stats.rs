//! Native pdev statistics used by ath11k_mac_handle_get_txpower. Firmware
//! reports half-dBm, after target/CTL/regulatory/PSD minima. This is telemetry,
//! never a transmit-power grant. Linux ath11k/{wmi.h,wmi.c,mac.c}.
use super::wmi::{self, WmiCmd, WmiError};
use super::wmi_ids::*;
use alloc::vec::Vec;

pub(super) fn request(pdev_id: u32) -> WmiCmd {
    let mut payload = Vec::with_capacity(24);
    // request_stats_cmd: stats_id=PDEV, vdev_id=0, peer_macaddr=0, pdev_id.
    for word in [
        (u32::from(WMI_TAG_REQUEST_STATS_CMD) << 16) | 20,
        4,
        0,
        0,
        0,
        pdev_id,
    ] {
        payload.extend_from_slice(&word.to_le_bytes());
    }
    WmiCmd {
        cmd_id: WMI_REQUEST_STATS_CMDID,
        buf: payload,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PdevPower {
    pub pdev_id: u32,
    pub half_dbm: u32,
}

/// Parse only the requested single-pdev response profile. The ARRAY_BYTE
/// contains packed base(7), TX(35) and RX(15) dwords, not nested TLVs.
/// Validate the complete inventory and all extents before reading the base.
pub(super) fn decode(payload: &[u8]) -> Result<PdevPower, WmiError> {
    let (mut header, mut data) = (None, None);
    wmi::tlv_iter(payload, |tlv| {
        match tlv.tag {
            WMI_TAG_STATS_EVENT => {
                if header.replace(tlv.value).is_some() {
                    return Err(WmiError::Invalid("duplicate pdev stats header"));
                }
            }
            WMI_TAG_ARRAY_BYTE => {
                if header.is_none() || data.replace(tlv.value).is_some() {
                    return Err(WmiError::Invalid("unordered/duplicate pdev stats data"));
                }
            }
            _ => return Err(WmiError::UnexpectedTag(tlv.tag)),
        }
        Ok(())
    })?;
    let h = header.ok_or(WmiError::Missing(WMI_TAG_STATS_EVENT))?;
    let d = data.ok_or(WmiError::Missing(WMI_TAG_ARRAY_BYTE))?;
    if h.len() != 44
        || wmi::rd32(h, 0) != 4
        || wmi::rd32(h, 4) != 1
        || h[8..28].iter().any(|b| *b != 0)
        || h[32..44].iter().any(|b| *b != 0)
        || d.len() != 228
    {
        return Err(WmiError::Invalid("unsupported pdev stats inventory/extent"));
    }
    Ok(PdevPower {
        pdev_id: wmi::rd32(h, 28),
        half_dbm: wmi::rd32(d, 24),
    })
}

#[derive(Clone, Copy, Debug)]
struct Pending {
    token: u64,
    pdev: u32,
    epoch: u64,
    at: u64,
    published: bool,
}
#[derive(Clone, Copy, Debug)]
struct Sample {
    epoch: u64,
    at: u64,
    dbm: i32,
}

/// One physical transaction, shared by every virtual interface. The firmware
/// response has no nonce: a cancelled/expired request cannot be replaced and
/// allow its late receipt to satisfy a successor. No DMA is reclaimed here.
#[derive(Default, Debug)]
pub(super) struct State {
    epoch: u64,
    serial: u64,
    pending: Option<Pending>,
    sample: Option<Sample>,
}
impl State {
    pub fn begin(&mut self, pdev: u32, now: u64) -> Option<u64> {
        if self.pending.is_some() {
            return None;
        }
        let token = self.serial.checked_add(1)?;
        self.serial = token;
        self.sample = None;
        self.pending = Some(Pending {
            token,
            pdev,
            epoch: self.epoch,
            at: now,
            published: false,
        });
        Some(token)
    }
    pub fn owns(&self, token: u64) -> bool {
        self.pending.is_some_and(|p| p.token == token)
    }
    pub fn published(&mut self, token: u64, now: u64) {
        if let Some(p) = self.pending.as_mut().filter(|p| p.token == token) {
            p.published = true;
            p.at = now;
        }
    }
    /// A known native send error published no command. This is the only
    /// pre-receipt rollback, and is not called from a Future's Drop.
    pub fn send_failed(&mut self, token: u64) {
        if self
            .pending
            .is_some_and(|p| p.token == token && !p.published)
        {
            self.pending = None;
        }
    }
    pub fn receive(&mut self, receipt: PdevPower, now: u64) {
        let Some(p) = self.pending else {
            return;
        };
        if !p.published || p.pdev != receipt.pdev_id {
            return;
        }
        self.pending = None;
        // Unsigned firmware power is reported like Linux; reject values
        // which cannot even fit its signed user-visible dBm representation.
        if p.epoch == self.epoch
            && now.saturating_sub(p.at) <= 1000
            && receipt.half_dbm / 2 <= i32::MAX as u32
        {
            self.sample = Some(Sample {
                epoch: self.epoch,
                at: now,
                dbm: (receipt.half_dbm / 2) as i32,
            });
        }
    }
    pub fn cached(&self, now: u64) -> Option<i32> {
        self.sample
            .filter(|s| s.epoch == self.epoch && now.saturating_sub(s.at) <= 1000)
            .map(|s| s.dbm)
    }
    pub fn invalidate(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        self.sample = None;
        // Deliberately retain the old request until its actual response.
    }
    pub fn reset(&mut self) {
        self.invalidate();
        self.pending = None;
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::vec;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn packet() -> Vec<u8> {
        let mut p = vec![0; 280];
        p[..4].copy_from_slice(&[44, 0, 0x46, 0]);
        p[4] = 4;
        p[8] = 1;
        p[32] = 7;
        p[48..52].copy_from_slice(&[228, 0, 17, 0]);
        p[76] = 23;
        p
    }
    fn smoke_ath11k_pdev_stats_native_wire_bounds() -> TestResult {
        let result = (|| {
            let q = request(7);
            if q.cmd_id != 0x16001
                || q.buf
                    != [
                        20, 0, 0x8f, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0,
                    ]
            {
                return Err("PDEV request differs from literal Linux native wire");
            }
            let p = packet();
            if decode(&p)
                != Ok(PdevPower {
                    pdev_id: 7,
                    half_dbm: 23,
                })
            {
                return Err("native pdev power/base offset failed");
            }
            for len in 0..p.len() {
                if decode(&p[..len]).is_ok() {
                    return Err("truncated pdev statistics accepted");
                }
            }
            for offset in [4, 8, 12, 16, 20, 24, 28, 36, 40, 44, 48] {
                let mut malformed = p.clone();
                malformed[offset] ^= 1;
                if decode(&malformed).is_ok() {
                    return Err("wrong pdev inventory/ARRAY_BYTE extent accepted");
                }
            }
            let mut duplicate = p.clone();
            duplicate.extend_from_slice(&p[..48]);
            if decode(&duplicate).is_ok() {
                return Err("duplicate pdev header accepted");
            }
            let mut wrong_order = p[48..].to_vec();
            wrong_order.extend_from_slice(&p[..48]);
            if decode(&wrong_order).is_ok() {
                return Err("stats payload before header accepted");
            }
            Ok(())
        })();
        match result {
            Ok(()) => TestResult::Pass,
            Err(e) => TestResult::Fail(e),
        }
    }
    fn smoke_ath11k_pdev_stats_untagged_owner_and_expiry() -> TestResult {
        let result = (|| {
            let mut s = State::default();
            let receipt = PdevPower {
                pdev_id: 7,
                half_dbm: 23,
            };
            s.receive(receipt, 0);
            if s.cached(0).is_some() {
                return Err("unsolicited stats created a sample/owner");
            }
            let token = s.begin(7, 10).ok_or("missing first pdev request")?;
            s.receive(receipt, 10); // cannot ACK an unposted request
            if s.cached(10).is_some() || s.begin(7, 11).is_some() {
                return Err("unpublished/cancelled request was reused");
            }
            s.published(token, 20);
            s.receive(
                PdevPower {
                    pdev_id: 8,
                    half_dbm: 50,
                },
                21,
            );
            if s.begin(7, 21).is_some() {
                return Err("foreign pdev receipt retired owner");
            }
            s.receive(receipt, 22);
            if s.cached(22) != Some(11) || s.cached(1023).is_some() {
                return Err("half-dBm snapshot/expiry incorrect");
            }
            let token = s
                .begin(7, 30)
                .ok_or("terminal native receipt did not release request")?;
            s.published(token, 30);
            s.invalidate();
            if s.begin(7, 31).is_some() {
                return Err("channel invalidation recycled untagged request");
            }
            s.receive(receipt, 32);
            if s.cached(32).is_some() {
                return Err("late previous-channel receipt entered successor cache");
            }
            let token = s
                .begin(7, 33)
                .ok_or("late receipt did not retire previous-channel request")?;
            s.published(token, 33);
            s.receive(receipt, 1034);
            if s.cached(1034).is_some() {
                return Err("expired response became current telemetry");
            }
            let old = s
                .begin(7, 1035)
                .ok_or("expired response did not retire old request")?;
            s.reset();
            let new = s
                .begin(7, 1036)
                .ok_or("completed transport reset retained old request")?;
            s.published(old, 1036);
            s.send_failed(old);
            s.receive(receipt, 1036);
            if s.owns(old) || !s.owns(new) || s.cached(1036).is_some() {
                return Err("old reset waiter changed successor publication/rollback");
            }
            s.send_failed(new);
            if s.begin(7, 1037).is_none() {
                return Err("known unpublished send failure blocked retry");
            }
            Ok(())
        })();
        match result {
            Ok(()) => TestResult::Pass,
            Err(e) => TestResult::Fail(e),
        }
    }
    kernel_test_in!(
        "drivers/wireless/ath11k",
        smoke_ath11k_pdev_stats_native_wire_bounds
    );
    kernel_test_in!(
        "drivers/wireless/ath11k",
        smoke_ath11k_pdev_stats_untagged_owner_and_expiry
    );
}

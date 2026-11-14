//! One actual user MPDU's native sequence observation for BA restart.
//! Linux mt76_connac2_mac.h TXS0/1/2/3, mt7921/mac.c TXS records,
//! mt76_connac_mac.c:579..587 (HOST TXS disables hardware A-MSDU).
//! Linux retires a requested MPDU HOST TXS once (tx.c idr_remove). Reuse
//! follows that terminal-report contract only after DMA+TX_FREE also retire;
//! cancellation/timeouts quarantine the PID until verified firmware reset.
use super::{firmware_transport::Error, packet_tx};
use alloc::vec::Vec;

const FIRST_PID: u16 = 3;
#[derive(Clone, Copy, Debug)]
struct Sample {
    tid: u8,
    wcid: u16,
    management: bool,
    pid: u8,
    token: Option<u16>,
    terminal: Option<u8>,
    report: Option<Result<u16, Error>>,
}
/// Linux `mt7921e_tx_prepare_skb`: a station's data frame requests a TX
/// status at most every HZ/4, and `mt76_connac2_mac_fill_txs` takes the
/// station's TX rate from it.
const RATE_INTERVAL_NS: u64 = 250_000_000;
/// A rate sample whose frame retired without a status is given up after
/// this long (its PID is then reused).
const RATE_ABANDON_NS: u64 = 1_000_000_000;

/// One outstanding rate-only TX status request.
#[derive(Clone, Copy, Debug)]
struct RateSample {
    pid: u8,
    wcid: u16,
    token: Option<u16>,
    requested_ns: u64,
    reported: bool,
    terminal: bool,
}

/// The latest TX status of a station: the rate word and bandwidth the
/// frame went out at (`MT_TXS0_TX_RATE`, `MT_TXS0_BW`) and how many of the
/// sampled frames failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RateReport {
    pub wcid: u16,
    pub tx_rate: u16,
    pub bw: u8,
    pub failures: u32,
    /// Increments with every report, so a consumer takes each one once.
    pub sequence: u32,
}

#[derive(Debug)]
pub(super) struct Owner {
    next: u16,
    occupied: [u64; 2],
    sample: Option<Sample>,
    rate: Option<RateSample>,
    last_rate_ns: Option<u64>,
    rate_report: Option<RateReport>,
    rate_sampling: bool,
}
impl Owner {
    pub fn new() -> Self {
        Self {
            next: FIRST_PID,
            occupied: [0; 2],
            sample: None,
            rate: None,
            last_rate_ns: None,
            rate_report: None,
            rate_sampling: true,
        }
    }
    /// For descriptor fixtures that pin exact TXD words and PIDs: no
    /// periodic rate sample is requested, so only their own BA sample
    /// changes a frame's status fields.
    pub fn without_rate_sampling() -> Self {
        Self {
            rate_sampling: false,
            ..Self::new()
        }
    }
    /// A PID for a rate-only TX status on `wcid`'s next data frame, when the
    /// last sample is at least HZ/4 old. An unpublished request is reused;
    /// a retired frame whose status never came is given up after a second.
    pub fn rate_pid(&mut self, wcid: u16, now_ns: u64) -> Option<u8> {
        if !self.rate_sampling {
            return None;
        }
        if let Some(rate) = self.rate {
            if rate.token.is_none() && rate.wcid == wcid {
                return Some(rate.pid);
            }
            let abandoned =
                rate.terminal && now_ns.saturating_sub(rate.requested_ns) >= RATE_ABANDON_NS;
            if !abandoned {
                return None;
            }
            self.rate = None;
            self.release_pid(rate.pid);
        }
        if self
            .last_rate_ns
            .is_some_and(|last| now_ns.saturating_sub(last) < RATE_INTERVAL_NS)
        {
            return None;
        }
        let pid = self.reserve_pid()?;
        self.rate = Some(RateSample {
            pid,
            wcid,
            token: None,
            requested_ns: now_ns,
            reported: false,
            terminal: false,
        });
        self.last_rate_ns = Some(now_ns);
        Some(pid)
    }
    /// The rate-sampled frame was published as `token`.
    pub fn begin_rate(&mut self, token: u16) {
        if let Some(rate) = self.rate.as_mut() {
            rate.token = Some(token);
        }
    }
    /// The station's latest sampled TX status.
    pub fn rate_report(&self) -> Option<RateReport> {
        self.rate_report
    }
    fn finish_rate(&mut self) {
        if let Some(rate) = self.rate.filter(|rate| rate.reported && rate.terminal) {
            self.rate = None;
            self.release_pid(rate.pid);
        }
    }
    /// The lowest free PID after the rotating start (`idr_alloc_cyclic`).
    fn reserve_pid(&mut self) -> Option<u8> {
        let mut free = None;
        for _ in FIRST_PID..127 {
            let candidate = self.next as u8;
            self.next = if self.next == 126 {
                FIRST_PID
            } else {
                self.next + 1
            };
            if self.occupied[usize::from(candidate) / 64] & (1u64 << (candidate % 64)) == 0 {
                free = Some(candidate);
                break;
            }
        }
        let pid = free?;
        self.occupied[usize::from(pid) / 64] |= 1u64 << (pid % 64);
        Some(pid)
    }
    /// The caller proves every earlier native data token terminal before
    /// arming. Re-arm cannot overlap an old, unconsumed report owner.
    pub fn arm(&mut self, tid: u8) -> Result<(), Error> {
        self.arm_for(tid, 1, false)
    }
    /// Same native terminal-report owner for an AP management MPDU. This
    /// does not assert a sequence originator or create a transmit grant.
    pub fn arm_ap_management(&mut self, wcid: u8) -> Result<(), Error> {
        self.arm_ap_management_on(super::vif_slots::Vif::HOME, wcid)
    }
    /// `arm_ap_management` for the AP BSS on `vif`: a peer or its BMC WCID.
    pub fn arm_ap_management_on(
        &mut self,
        vif: super::vif_slots::Vif,
        wcid: u8,
    ) -> Result<(), Error> {
        if !(1..=13).contains(&wcid) && wcid != vif.bmc() {
            return Err(Error::Bounds);
        }
        self.arm_for(0, u16::from(wcid), true)
    }
    /// Reserve only a report identity on the actual independent VIF/BMC.
    /// This observation grants no role, channel or transmit authority.
    pub fn arm_p2p_management(&mut self, vif: super::vif_slots::Vif, tid: u8) -> Result<(), Error> {
        self.arm_for(tid, u16::from(vif.bmc()), true)
    }
    fn arm_for(&mut self, tid: u8, wcid: u16, management: bool) -> Result<(), Error> {
        if tid >= 8 {
            return Err(Error::Bounds);
        }
        if self.sample.is_some() {
            return Err(Error::Busy);
        }
        // mt76.h MASK=GENMASK(6,0); tx.c idr_alloc end127 is exclusive.
        let pid = self.reserve_pid().ok_or(Error::EventOverflow)?;
        self.sample = Some(Sample {
            tid,
            wcid,
            management,
            pid,
            token: None,
            terminal: None,
            report: None,
        });
        Ok(())
    }
    pub fn pid(&self, tid: u8) -> Result<Option<u8>, Error> {
        let Some(sample) = self.sample.filter(|sample| sample.tid == tid) else {
            return Ok(None);
        };
        if sample.token.is_some() {
            return Err(Error::Busy);
        }
        Ok(Some(sample.pid))
    }
    pub fn published(&self, tid: u8) -> bool {
        self.sample
            .is_some_and(|sample| sample.tid == tid && sample.token.is_some())
    }
    pub fn begin(&mut self, tid: u8, token: u16) -> Result<(), Error> {
        let sample = self
            .sample
            .as_mut()
            .filter(|sample| sample.tid == tid)
            .ok_or(Error::Busy)?;
        if sample.token.is_some() || token == 0 {
            return Err(Error::Busy);
        }
        sample.token = Some(token);
        Ok(())
    }
    pub fn terminal(&mut self, completion: packet_tx::Completion) {
        if let Some(rate) = self
            .rate
            .as_mut()
            .filter(|rate| rate.token == Some(completion.token))
        {
            rate.terminal = true;
        }
        self.finish_rate();
        if let Some(sample) = self
            .sample
            .as_mut()
            .filter(|sample| sample.token == Some(completion.token))
        {
            sample.terminal = Some(completion.status);
        }
    }
    /// Validate the entire event before mutating the single retained sample.
    /// Unrequested PIDs are diagnostics; a current PID with conflicting
    /// WCID/TID/format/sequence is never accepted as a new observation.
    pub fn receive(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let reports = reports(bytes)?;
        // `mt76_connac2_mac_fill_txs` for the rate sample's PID and WCID.
        if let Some(mut rate) = self.rate.filter(|rate| rate.token.is_some()) {
            for report in reports
                .iter()
                .filter(|report| report.pid == rate.pid && report.wcid == rate.wcid)
            {
                if report.format > 1 {
                    continue;
                }
                let failures = self
                    .rate_report
                    .filter(|last| last.wcid == rate.wcid)
                    .map_or(0, |last| last.failures);
                let sequence = self
                    .rate_report
                    .map_or(1, |last| last.sequence.wrapping_add(1));
                self.rate_report = Some(RateReport {
                    wcid: rate.wcid,
                    tx_rate: report.tx_rate,
                    bw: report.bw,
                    failures: failures.saturating_add(u32::from(report.failed)),
                    sequence,
                });
                rate.reported = true;
            }
            self.rate = Some(rate);
            self.finish_rate();
        }
        let Some(mut sample) = self.sample.filter(|sample| sample.token.is_some()) else {
            return Ok(());
        };
        for report in reports
            .into_iter()
            .filter(|report| report.pid == sample.pid)
        {
            if report.tid != sample.tid
                || report.wcid != sample.wcid
                || report.format > 1
                || report.ampdu
            {
                return Err(Error::MalformedEvent);
            }
            let result = if report.failed {
                Err(Error::Rejected(1))
            } else {
                Ok(report.sequence)
            };
            if sample.report.is_some_and(|old| old != result) {
                return Err(Error::MalformedEvent);
            }
            sample.report = Some(result);
        }
        self.sample = Some(sample);
        Ok(())
    }
    /// Both the true native TXS and DMA+TX_FREE terminal proof are required.
    /// No timer, host packet count or token release can synthesize an SN.
    pub fn take(&mut self, tid: u8) -> Result<Option<u16>, Error> {
        let Some(sample) = self.sample.filter(|sample| sample.tid == tid) else {
            return Err(Error::Busy);
        };
        let Some(status) = sample.terminal else {
            return Ok(None);
        };
        if status != 0 {
            return Err(Error::Rejected(status));
        }
        let Some(sequence) = sample.report else {
            return Ok(None);
        };
        let sequence = sequence?;
        self.sample = None;
        self.release_pid(sample.pid);
        Ok(Some(sequence))
    }
    /// Management ACK is a native TXS fact, joined with packet dual
    /// retirement. A failed terminal report yields false, never a guessed
    /// positive ACK from TX_FREE alone. Malformed/conflicting reports have
    /// already failed receive and remain quarantined by the caller.
    pub fn take_ap_ack(&mut self) -> Result<Option<bool>, Error> {
        let sample = self.sample.filter(|s| s.management).ok_or(Error::Busy)?;
        let (Some(status), Some(report)) = (sample.terminal, sample.report) else {
            return Ok(None);
        };
        self.sample = None;
        self.release_pid(sample.pid);
        Ok(Some(status == 0 && report.is_ok()))
    }
    fn release_pid(&mut self, pid: u8) {
        self.occupied[usize::from(pid) / 64] &= !(1u64 << (pid % 64));
    }
    /// Before publication there can be no matching new TXS. Once exposed,
    /// a missing or failed proof quarantines the PID; no age-based reuse.
    pub fn cancel(&mut self) {
        if let Some(sample) = self.sample.take() {
            if sample.token.is_none()
                || sample.terminal == Some(0) && sample.report.is_some_and(|report| report.is_ok())
            {
                self.release_pid(sample.pid);
            }
        }
    }
    /// DMA idle alone cannot retire a firmware-delayed status event.
    pub fn clear_after_quiescence(&mut self) {
        self.cancel();
    }
    /// Only after full WFSYS reset readiness, DMA idle/bus-master-off and
    /// clearing all RX rings. A DMA-only reinit must not call this method.
    pub fn firmware_reset(&mut self) {
        *self = Self::new();
    }
}

pub(super) fn request(header: &mut [u8; packet_tx::HEADER], pid: u8) -> Result<(), Error> {
    if pid < FIRST_PID as u8 {
        return Err(Error::Bounds);
    }
    let status = u32::from_le_bytes(header[20..24].try_into().unwrap());
    header[20..24].copy_from_slice(&((status & !0xff) | (1 << 10) | u32::from(pid)).to_le_bytes());
    let word = u32::from_le_bytes(header[28..32].try_into().unwrap()) & !(1 << 10);
    header[28..32].copy_from_slice(&word.to_le_bytes());
    let word = u32::from_le_bytes(header[12..16].try_into().unwrap()) | 1 << 28;
    header[12..16].copy_from_slice(&word.to_le_bytes());
    Ok(())
}
#[derive(Clone, Copy, Debug)]
struct Report {
    pid: u8,
    tid: u8,
    wcid: u16,
    format: u8,
    ampdu: bool,
    failed: bool,
    sequence: u16,
    /// `MT_TXS0_TX_RATE` and `MT_TXS0_BW`.
    tx_rate: u16,
    bw: u8,
}
fn reports(bytes: &[u8]) -> Result<Vec<Report>, Error> {
    if bytes.len() < 40 {
        return Err(Error::MalformedEvent);
    }
    let header = u32::from_le_bytes(bytes[..4].try_into().unwrap());
    let len = (header & 0xffff) as usize;
    if header >> 27 != 1 || len < 40 || len > bytes.len() || len > 4096 || (len - 8) % 32 != 0 {
        return Err(Error::MalformedEvent);
    }
    let mut reports = Vec::with_capacity((len - 8) / 32);
    for data in bytes[8..len].chunks_exact(32) {
        let word = |offset| u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        let r0 = word(0);
        reports.push(Report {
            pid: (word(12) >> 24) as u8,
            tid: ((r0 >> 26) & 7) as u8,
            wcid: ((word(8) >> 16) & 0x3ff) as u16,
            format: ((r0 >> 23) & 3) as u8,
            ampdu: r0 & (1 << 25) != 0,
            failed: r0 & (0x5f << 16) != 0,
            sequence: (word(4) >> 20) as u16,
            tx_rate: (r0 & 0x3fff) as u16,
            bw: ((r0 >> 29) & 3) as u8,
        });
    }
    Ok(reports)
}

#[path = "tx_sequence_tests.rs"]
mod tests;

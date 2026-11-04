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
#[derive(Debug)]
pub(super) struct Owner {
    next: u16,
    occupied: [u64; 2],
    sample: Option<Sample>,
}
impl Owner {
    pub fn new() -> Self {
        Self {
            next: FIRST_PID,
            occupied: [0; 2],
            sample: None,
        }
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
        let pid = free.ok_or(Error::EventOverflow)?;
        self.occupied[usize::from(pid) / 64] |= 1u64 << (pid % 64);
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
        });
    }
    Ok(reports)
}

#[path = "tx_sequence_tests.rs"]
mod tests;

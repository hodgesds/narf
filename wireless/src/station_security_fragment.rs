//! Additive fragment train/protected-reassembly interface. This is not native
//! fragmentation support and grants no RF, DMA, source or controlled port.
use super::*;
use crate::packet_key::fragment::{KeyIdentity, Reassembled, Reassembly};
pub(super) type Receive = Reassembly;

/// One complete immutable host-encrypted train, retained before native issue.
/// The caller must preserve these bytes across Busy, serialize actual terminal
/// MPDUs, and recheck original native/source/port plus this fixed key identity
/// at publication. This observation cannot keep a retired key installed.
pub struct FragmentTrain {
    frames: Vec<Vec<u8>>,
    key: KeyIdentity,
}
impl core::fmt::Debug for FragmentTrain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FragmentTrain")
            .field("len", &self.frames.len())
            .finish_non_exhaustive()
    }
}
impl FragmentTrain {
    pub fn frames(&self) -> &[Vec<u8>] {
        &self.frames
    }
    pub fn current_key(&self) -> bool {
        self.key.current()
    }
    /// Consume the not-yet-issued train to set only CCMP-muted Duration/NAV.
    /// The native owner supplies exact rate/next-fragment calculations. Count
    /// must match and bit15 (AID/CFP interpretation) stays clear. No callback,
    /// re-encryption, PN/SN change, new key/source or RF authority is involved.
    pub fn with_durations(mut self, durations: &[u16]) -> Result<Self, Error> {
        if !self.key.current() {
            return Err(Error::State);
        }
        if durations.len() != self.frames.len() || durations.iter().any(|value| value & 0x8000 != 0)
        {
            return Err(Error::Profile);
        }
        for (frame, value) in self.frames.iter_mut().zip(durations) {
            frame[2..4].copy_from_slice(&value.to_le_bytes());
        }
        Ok(self)
    }
}
type Piece = (Vec<u8>, Vec<u8>);
type Pieces = Vec<Piece>;
fn threshold(value: u32) -> Result<usize, Error> {
    if !(256..=2346).contains(&value) || value & 1 != 0 {
        return Err(Error::Profile);
    }
    Ok(value as usize)
}
fn prepare(header: &[u8], body: &[u8], threshold: usize) -> Result<Pieces, Error> {
    let per = threshold
        .checked_sub(header.len() + 4)
        .ok_or(Error::Profile)?;
    let count = body.len().div_ceil(per);
    if !(2..=16).contains(&count) {
        return Err(Error::Profile);
    }
    let mut pieces = Vec::new();
    pieces
        .try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    for (number, chunk) in body.chunks(per).enumerate() {
        let mut h = header.to_vec();
        h[1] |= 0x40;
        if number + 1 < count {
            h[1] |= 4;
        } else {
            h[1] &= !4;
        }
        h[22] = (h[22] & 0xf0) | number as u8;
        pieces.push((h, chunk.to_vec()));
    }
    Ok(pieces)
}
impl Security {
    fn seal_fragments(&mut self, pieces: Pieces) -> Result<FragmentTrain, Error> {
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(pieces.len())
            .map_err(|_| Error::Allocation)?;
        let key = self
            .pair
            .as_mut()
            .ok_or(Error::State)?
            .key
            .fragment_key_identity()
            .map_err(Error::Crypto)?;
        for (mut header, body) in pieces {
            let wire = match self
                .pair
                .as_mut()
                .ok_or(Error::State)?
                .key
                .protect_fragment(&header, &body)
            {
                Ok(wire) => wire,
                Err(error) => {
                    self.fail();
                    return Err(Error::Crypto(error));
                }
            };
            header.extend_from_slice(&wire);
            frames.push(header);
        }
        Ok(FragmentTrain { frames, key })
    }
    /// Protect an actually fragmented non-MLD Ethernet MSDU. The threshold is
    /// mac80211's plaintext MPDU+FCS threshold (CCMP overhead is added later).
    /// Native size/peer/queue/prefix/program checks must precede this call.
    /// One MSDU SN and consecutive per-fragment PN are consumed once. The
    /// existing unfragmented APIs remain unchanged; callers use them when the
    /// original MSDU fits. No A-MSDU/A-MPDU/+HTC/MLD opt-in is implied.
    pub fn transmit_ethernet_fragments(
        &mut self,
        ethernet: &[u8],
        tid: Option<u8>,
        fragment_threshold: u32,
    ) -> Result<FragmentTrain, Error> {
        if !self.port_open() {
            return Err(Error::State);
        }
        if self.mld.is_some()
            || tid.is_some_and(|tid| tid > 15)
            || !(14..=1514).contains(&ethernet.len())
            || ethernet[6..12] != self.own
            || ethernet[..6] == [0; 6]
        {
            return Err(Error::Profile);
        }
        let protocol = u16::from_be_bytes([ethernet[12], ethernet[13]]);
        if protocol < 0x600 || matches!(protocol, 0x888e | 0x80f3 | 0x8137) {
            return Err(Error::Profile);
        }
        let limit = threshold(fragment_threshold)?;
        let mut header = vec![if tid.is_some() { 0x88 } else { 8 }, 0x41, 0, 0];
        header.extend_from_slice(&self.peer);
        header.extend_from_slice(&self.own);
        header.extend_from_slice(&ethernet[..6]);
        let sequence = tid.map_or(self.sequence, |tid| self.qos_sequence[usize::from(tid)]);
        header.extend_from_slice(&(sequence << 4).to_le_bytes());
        if let Some(tid) = tid {
            header.extend_from_slice(&[tid, 0]);
        }
        let mut body = self.msdu_header(protocol);
        body.extend_from_slice(&ethernet[14..]);
        // Allocate/validate the whole train before consuming any SN/PN.
        let pieces = prepare(&header, &body, limit)?;
        if let Some(tid) = tid {
            self.qos_sequence[usize::from(tid)] = (sequence + 1) & 4095;
        } else {
            self.sequence = (sequence + 1) & 4095;
        }
        self.seal_fragments(pieces)
    }
    /// PMF robust management uses its caller's ONE assigned management SN,
    /// CCMP's management nonce flag and the same pairwise TX PN namespace.
    pub fn protect_management_fragments(
        &mut self,
        frame: &[u8],
        fragment_threshold: u32,
    ) -> Result<FragmentTrain, Error> {
        if !self.pmf || !self.port_open() {
            return Err(Error::State);
        }
        if self.mld.is_some()
            || !(25..=4096).contains(&frame.len())
            || frame[0] & 12 != 0
            || frame[1] & 0xc7 != 0
            || frame[22] & 15 != 0
            || !Self::robust(frame)
            || frame[4..10] != self.peer
            || frame[10..16] != self.own
            || frame[16..22] != self.peer
        {
            return Err(Error::Profile);
        }
        let pieces = prepare(&frame[..24], &frame[24..], threshold(fragment_threshold)?)?;
        self.seal_fragments(pieces)
    }
    fn fragment_input(
        &mut self,
        mpdu: &impl RawFrame,
        now_ms: u64,
        management: bool,
    ) -> Result<Option<Reassembled>, Error> {
        if self.failed || self.pending.is_some() && !management {
            return Err(Error::State);
        }
        if self.mld.is_some() || !self.admitted_link(mpdu) || !mpdu.unmodified() {
            return Ok(None);
        }
        let bytes = mpdu.bytes();
        let length = if bytes.first() == Some(&0x88) { 26 } else { 24 };
        if bytes.len() < length + 17
            || bytes[1] & 0x40 == 0
            || (bytes[0] & 12 == 0) != management
            || bytes[4..10] != self.own
            || bytes[10..16] != self.peer
            || management && (!self.pmf || bytes[16..22] != self.peer)
        {
            return Ok(None);
        }
        let Some(pair) = self.pair.as_mut() else {
            return Ok(None);
        };
        let mut wire = bytes[length..].to_vec();
        let part = match pair.key.unprotect_fragment(&bytes[..length], &mut wire) {
            Ok(part) => part,
            Err(_) => return Ok(None),
        };
        let cache = self
            .fragment_rx
            .get_or_insert_with(|| Box::new(Receive::default()));
        match cache.push(part, now_ms) {
            Ok(frame) => Ok(frame),
            Err(_) => Ok(None),
        }
    }
    /// Explicit native-fragment opt-in. Protected fragments authenticate each
    /// original MPDU; plaintext fragments can reach only the existing EAPOL
    /// verifier and can never open a data port by themselves. Native source,
    /// peer/profile/CRC and original copy epoch must be checked for every input.
    /// MLD, multicast, A-MSDU/BlockAck/+HTC fragments remain denied.
    pub fn receive_fragment_with_nonce(
        &mut self,
        mpdu: &impl RawFrame,
        now_ms: u64,
        fresh_snonce: impl FnMut() -> Option<[u8; 32]>,
    ) -> Result<Rx, Error> {
        let result = self.receive_fragment_inner(mpdu, now_ms, fresh_snonce);
        if result.is_err() {
            self.fail();
        }
        result
    }
    fn receive_fragment_inner(
        &mut self,
        mpdu: &impl RawFrame,
        now_ms: u64,
        fresh_snonce: impl FnMut() -> Option<[u8; 32]>,
    ) -> Result<Rx, Error> {
        if self.failed || self.pending.is_some() {
            return Err(Error::State);
        }
        if self.mld.is_some() || !self.admitted_link(mpdu) || !mpdu.unmodified() {
            return Ok(Rx::Ignored);
        }
        let bytes = mpdu.bytes();
        if bytes.len() < 24
            || !matches!(bytes[0], 8 | 0x88)
            || bytes[4..10] != self.own
            || bytes[10..16] != self.peer
            || !unicast(bytes[16..22].try_into().unwrap())
            || bytes[1] & 0x83 != 2
            || bytes[22] & 15 == 0 && bytes[1] & 4 == 0
        {
            return Ok(Rx::Ignored);
        }
        if bytes[1] & 0x40 != 0 {
            let Some(frame) = self.fragment_input(mpdu, now_ms, false)? else {
                return Ok(Rx::Ignored);
            };
            if frame.management() {
                return Ok(Rx::Ignored);
            }
            return self.receive_normalized(frame.into_bytes(), true, fresh_snonce);
        }
        if bytes[0] == 0x88 && (bytes.len() < 26 || bytes[24] & 0xf0 != 0 || bytes[25] != 0) {
            return Ok(Rx::Ignored);
        }
        let key = self
            .pair
            .as_mut()
            .map(|pair| pair.key.fragment_key_identity())
            .transpose()
            .map_err(Error::Crypto)?;
        let cache = self
            .fragment_rx
            .get_or_insert_with(|| Box::new(Receive::default()));
        let length = if bytes[0] == 0x88 { 26 } else { 24 };
        let Ok(Some(frame)) = cache.push_plain(&bytes[..length], &bytes[length..], key, now_ms)
        else {
            return Ok(Rx::Ignored);
        };
        // Same retained protocol owner sees protected=false and keeps all
        // initial/rekey MIC/replay/RSN/terminal-delivery requirements intact.
        self.receive_normalized(frame, false, fresh_snonce)
    }
    /// Authenticate/reassemble original protected DATA then run the SAME
    /// retained EAPOL/controlled-port owner. RawFrame's original native/source
    /// proof is mandatory for every fragment; this cache supplies none.
    pub fn receive_protected_fragment_with_nonce(
        &mut self,
        mpdu: &impl RawFrame,
        now_ms: u64,
        fresh_snonce: impl FnMut() -> Option<[u8; 32]>,
    ) -> Result<Rx, Error> {
        if mpdu.bytes().get(1).is_none_or(|flags| flags & 0x40 == 0) {
            return Ok(Rx::Ignored);
        }
        self.receive_fragment_with_nonce(mpdu, now_ms, fresh_snonce)
    }
    /// Original unicast management fragments under the SAME pre-key/nonrobust
    /// and PMF policy as receive_management. Protected robust fragments must
    /// authenticate with the original pair key; group/BIP fragments are denied.
    /// Plaintext reassembly never fabricates an original native RawFrame.
    pub fn receive_management_fragment(
        &mut self,
        mpdu: &impl RawFrame,
        now_ms: u64,
    ) -> Result<MgmtRx, Error> {
        if self.failed {
            return Err(Error::State);
        }
        let bytes = mpdu.bytes();
        if self.mld.is_some()
            || !self.admitted_link(mpdu)
            || !mpdu.unmodified()
            || !(25..=4096).contains(&bytes.len())
            || bytes[0] & 15 != 0
            || bytes[1] & 0x83 != 0
            || bytes[4..10] != self.own
            || bytes[10..16] != self.peer
            || bytes[16..22] != self.peer
            || bytes[22] & 15 == 0 && bytes[1] & 4 == 0
        {
            return Ok(MgmtRx::Ignored);
        }
        if bytes[1] & 0x40 == 0 {
            let key = self
                .pair
                .as_mut()
                .map(|pair| pair.key.fragment_key_identity())
                .transpose()
                .map_err(Error::Crypto)?;
            let cache = self
                .fragment_rx
                .get_or_insert_with(|| Box::new(Receive::default()));
            let Ok(Some(frame)) =
                cache.push_plain_management(&bytes[..24], &bytes[24..], key, now_ms)
            else {
                return Ok(MgmtRx::Ignored);
            };
            return Ok(if self.pmf && self.pair.is_some() && Self::robust(&frame) {
                MgmtRx::Ignored
            } else {
                MgmtRx::Frame(frame)
            });
        }
        let Some(frame) = self.fragment_input(mpdu, now_ms, true)? else {
            return Ok(MgmtRx::Ignored);
        };
        if !frame.management() || !Self::robust(frame.bytes()) {
            return Ok(MgmtRx::Ignored);
        }
        Ok(MgmtRx::Frame(frame.into_bytes()))
    }
    /// Fixed cache work observation for the retained native worker/LPS owner.
    pub fn fragment_pending(&mut self, now_ms: u64) -> bool {
        self.fragment_rx.as_mut().is_some_and(|cache| {
            cache.expire(now_ms);
            cache.pending()
        })
    }
}

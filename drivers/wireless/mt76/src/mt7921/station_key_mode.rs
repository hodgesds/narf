//! Unreferenced next-batch key state: crypto ownership, not native retirement.
//! A Hardware key has an unknown transmit PN. Only genuinely changed key
//! material can start a fresh software counter; identical retries retain it.
//! Actual disable ACK/current device/RF/copy ownership remain Session's job.
use alloc::vec::Vec;
use narf_wireless::ccmp::{self, AesCcm, CcmpError, ReplayWindow};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const MAX_PN: u64 = (1 << 48) - 1;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Header,
    Key,
    UnknownTransmitPn,
    Exhausted,
    Authentication,
    Replay,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tx {
    HardwareUnknown,
    Software(u64),
    ReceiveOnly,
}
/// No key bytes or plaintext are emitted by Debug.
pub(super) struct Key {
    tk: Zeroizing<[u8; 16]>,
    index: u8,
    tx: Tx,
}
impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StationCcmpKey")
            .field("index", &self.index)
            .field("tx", &self.tx)
            .finish_non_exhaustive()
    }
}
/// AES-verified bytes and PN only. This carries no hardware DECRYPTED flag,
/// native metadata, current-key epoch, channel grant or port authorization.
/// The native caller must bind all of those before reorder/defragmentation;
/// only its terminal parser commit may advance the real replay floor.
pub(super) struct Verified {
    body: Zeroizing<Vec<u8>>,
    pn: u64,
    queue: usize,
    management: bool,
}
impl Verified {
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn pn(&self) -> u64 {
        self.pn
    }
    pub fn queue(&self) -> usize {
        self.queue
    }
    pub fn management(&self) -> bool {
        self.management
    }
}
impl core::fmt::Debug for Verified {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SoftwareVerifiedCcmp")
            .field("pn", &self.pn)
            .field("queue", &self.queue)
            .field("management", &self.management)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Copy)]
pub(super) struct Peer {
    pub own: [u8; 6],
    pub ap: [u8; 6],
}
struct Header<'a> {
    bytes: &'a [u8],
    queue: usize,
    priority: u8,
    management: bool,
}
impl Key {
    /// Observation of a genuinely installed hardware PTK, not a fresh
    /// software counter and not an admission to use the native key.
    pub fn hardware_pairwise(tk: [u8; 16]) -> Self {
        Self {
            tk: Zeroizing::new(tk),
            index: 0,
            tx: Tx::HardwareUnknown,
        }
    }
    /// A reused software-only WCID has no newly programmed hardware key.
    /// The Session retains the one hardware TK from this physical MAC
    /// generation and must reject moving that unknown counter into zero.
    /// Genuine new PTKs still require their authenticated nonce/KDF owner.
    pub fn fresh_software_pairwise(
        tk: [u8; 16],
        last_hardware_tk: &[u8; 16],
    ) -> Result<Self, Error> {
        let staged = Zeroizing::new(tk);
        if bool::from(staged.as_slice().ct_eq(last_hardware_tk)) {
            return Err(Error::UnknownTransmitPn);
        }
        Ok(Self {
            tk: staged,
            index: 0,
            tx: Tx::Software(0),
        })
    }
    /// Authenticated installed GTK material. Station ToDS TX uses its PTK;
    /// a GTK cannot acquire a transmit counter through this constructor.
    pub fn group(tk: [u8; 16], index: u8) -> Result<Self, Error> {
        if index > 3 {
            return Err(Error::Key);
        }
        Ok(Self {
            tk: Zeroizing::new(tk),
            index,
            tx: Tx::ReceiveOnly,
        })
    }
    pub fn same(&self, tk: &[u8; 16]) -> bool {
        bool::from(self.tk.as_slice().ct_eq(tk))
    }
    /// Stage genuinely changed PTK material after the native caller proves
    /// its required key-disable/old-TX receipts. Same-key retry is a no-op;
    /// hardware's unknown PN can never be relabeled as software PN zero.
    pub fn replace_pairwise(&mut self, tk: [u8; 16]) -> Result<bool, Error> {
        if self.tx == Tx::ReceiveOnly {
            return Err(Error::Key);
        }
        let fresh = Zeroizing::new(tk);
        if self.same(&fresh) {
            return Ok(false);
        }
        self.tk.copy_from_slice(fresh.as_slice());
        self.tx = Tx::Software(0);
        Ok(true)
    }
    pub fn software_tx(&self) -> bool {
        matches!(self.tx, Tx::Software(_))
    }
    pub fn protect(&mut self, peer: Peer, header: &[u8], body: &[u8]) -> Result<Vec<u8>, Error> {
        let parsed = shape(header, peer, true, false)?;
        if parsed.bytes.len() != header.len() || body.is_empty() || body.len() > 4096 {
            return Err(Error::Header);
        }
        let pn = match self.tx {
            Tx::HardwareUnknown => return Err(Error::UnknownTransmitPn),
            Tx::ReceiveOnly => return Err(Error::Key),
            Tx::Software(pn) if pn == MAX_PN => return Err(Error::Exhausted),
            Tx::Software(pn) => pn + 1,
        };
        // A failed encryption/publication burns its PN as Linux does.
        self.tx = Tx::Software(pn);
        let mut plaintext = Zeroizing::new(body.to_vec());
        let wire = ccmp::protect(
            &Ccm,
            header,
            &self.tk,
            pn,
            0,
            parsed.priority,
            parsed.management,
            &mut plaintext,
        )
        .map_err(map_crypto)?;
        let mut frame = Vec::with_capacity(header.len() + wire.len());
        frame.extend_from_slice(header);
        frame.extend_from_slice(&wire);
        Ok(frame)
    }
    /// Check a complete raw encrypted MPDU. The replay tracker here is a
    /// copy: successful MIC verification cannot commit an out-of-order BA
    /// packet or a partial MSDU's PN ahead of the native parser owner.
    pub fn verify(&self, peer: Peer, frame: &[u8], floor: u64) -> Result<Verified, Error> {
        let group = self.tx == Tx::ReceiveOnly;
        let header = shape(frame, peer, false, group)?;
        let wire = frame.get(header.bytes.len()..).ok_or(Error::Header)?;
        if !(16..=4112).contains(&wire.len())
            || wire[2] != 0
            || wire[3] & 0x3f != 0x20
            || wire[3] >> 6 != self.index
        {
            return Err(Error::Header);
        }
        let mut replay = ReplayWindow {
            last_seen_pn: floor,
        };
        let mut scratch = Zeroizing::new(wire.to_vec());
        let plaintext = ccmp::unprotect(
            &Ccm,
            header.bytes,
            &self.tk,
            header.priority,
            header.management,
            &mut replay,
            &mut scratch,
        )
        .map_err(map_crypto)?;
        Ok(Verified {
            body: Zeroizing::new(plaintext),
            pn: replay.last_seen_pn,
            queue: header.queue,
            management: header.management,
        })
    }
}
fn shape(frame: &[u8], peer: Peer, transmit: bool, group: bool) -> Result<Header<'_>, Error> {
    let first = frame.get(..24).ok_or(Error::Header)?;
    if peer.own == [0; 6]
        || peer.ap == [0; 6]
        || peer.own[0] & 1 != 0
        || peer.ap[0] & 1 != 0
        || first[1] & 0xc0 != 0x40
        || first[0] & 3 != 0
    {
        return Err(Error::Header);
    }
    let management = matches!(first[0], 0xa0 | 0xc0 | 0xd0);
    let qos = first[0] == 0x88;
    let length = if qos { 26 } else { 24 };
    let header = frame.get(..length).ok_or(Error::Header)?;
    if management {
        if group || header[1] & 7 != 0 || header[22] & 15 != 0 || header[16..22] != peer.ap {
            return Err(Error::Header);
        }
    } else if !matches!(header[0], 0x08 | 0x88)
        || header[1] & 3 != if transmit { 1 } else { 2 }
        || header[16..22] == [0; 6]
        || !transmit && header[16] & 1 != 0
        || qos
            && (header[25] != 0
                || header[24] & 0x80 != 0 && (header[1] & 4 != 0 || header[22] & 15 != 0))
    {
        return Err(Error::Header);
    }
    if transmit {
        if group || header[4..10] != peer.ap || header[10..16] != peer.own {
            return Err(Error::Header);
        }
    } else if header[10..16] != peer.ap
        || if group {
            header[4] & 1 == 0
        } else {
            header[4..10] != peer.own
        }
    {
        return Err(Error::Header);
    }
    let priority = if qos { header[24] & 15 } else { 0 };
    Ok(Header {
        bytes: header,
        queue: if qos { usize::from(priority) } else { 16 },
        priority,
        management,
    })
}
fn map_crypto(error: CcmpError) -> Error {
    match error {
        CcmpError::Replay => Error::Replay,
        CcmpError::AuthFailed => Error::Authentication,
        _ => Error::Header,
    }
}
struct Ccm;
impl AesCcm for Ccm {
    fn encrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        body: &mut [u8],
    ) -> Result<[u8; 8], CcmpError> {
        narf_crypto::aes_ccm::seal(key, nonce, aad, body).map_err(|error| match error {
            narf_crypto::aes_ccm::Error::Length => CcmpError::TooLong,
            _ => CcmpError::AuthFailed,
        })
    }
    fn decrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        body: &mut [u8],
        tag: &[u8; 8],
    ) -> Result<(), CcmpError> {
        narf_crypto::aes_ccm::open(key, nonce, aad, body, tag).map_err(|error| match error {
            narf_crypto::aes_ccm::Error::Length => CcmpError::TooLong,
            _ => CcmpError::AuthFailed,
        })
    }
}

//! TPM 2.0 Command Builder and Response Parser.
//!
//! Based on TCG TPM 2.0 Library Specification, Part 3: Commands.
//! Clean-room implementation following the wire format (§5.6).
//!   <https://trustedcomputinggroup.org/resource/tpm-library-specification/>

use crate::types::{TpmError, TpmRc};
use alloc::vec::Vec;

pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
pub const TPM_ST_SESSIONS: u16 = 0x8002;

#[derive(Clone, Copy, Debug)]
pub enum CommandCode {
    GetRandom = 0x0000_017B,
    PcrRead = 0x0000_017E,
    PcrExtend = 0x0000_0182,
}

pub struct CommandBuilder {
    buf: Vec<u8>,
}

impl CommandBuilder {
    /// Start a command with the `TPM_ST_NO_SESSIONS` tag. Only valid
    /// for commands without authorization handles (e.g. GetRandom,
    /// PCR_Read): the TPM parses parameters immediately after the
    /// handle area under this tag.
    pub fn new(cc: CommandCode) -> Self {
        Self::with_tag(cc, TPM_ST_NO_SESSIONS)
    }

    /// Start a command with the `TPM_ST_SESSIONS` tag. Required for
    /// every command whose handles carry an authorization area
    /// (PCR_Extend, Create, …): the TPM reads the authorizationSize
    /// field after the handles *only* under this tag — under
    /// `TPM_ST_NO_SESSIONS` those bytes are parsed as the first
    /// parameter instead (TCG Part 1 §18.5). Emitting a session area
    /// under the no-sessions tag produces a malformed frame a real
    /// TPM rejects (#937).
    pub fn new_with_sessions(cc: CommandCode) -> Self {
        Self::with_tag(cc, TPM_ST_SESSIONS)
    }

    fn with_tag(cc: CommandCode, tag: u16) -> Self {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&tag.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes()); // placeholder for size
        buf.extend_from_slice(&(cc as u32).to_be_bytes());
        Self { buf }
    }

    pub fn push_u8(&mut self, val: u8) {
        self.buf.push(val);
    }

    pub fn push_u16(&mut self, val: u16) {
        self.buf.extend_from_slice(&val.to_be_bytes());
    }

    pub fn push_u32(&mut self, val: u32) {
        self.buf.extend_from_slice(&val.to_be_bytes());
    }

    pub fn push_slice(&mut self, val: &[u8]) {
        self.buf.extend_from_slice(val);
    }

    pub fn finish(mut self) -> Vec<u8> {
        let size = self.buf.len() as u32;
        self.buf[2..6].copy_from_slice(&size.to_be_bytes());
        self.buf
    }

    /// Build TPM2_PCR_Extend command (§22.2).
    ///
    /// The pcrHandle is an authorization handle, so the frame uses
    /// the `TPM_ST_SESSIONS` tag with the empty password session
    /// (`TPM_RS_PW`) — the same encoding as
    /// `drivers/tpm/src/tpm2/commands.rs::pcr_extend`. Under
    /// `TPM_ST_NO_SESSIONS` the TPM would parse the authorizationSize
    /// as the TPML_DIGEST_VALUES count and reject the command (#937).
    pub fn pcr_extend(pcr: u32, digest: &[u8]) -> Vec<u8> {
        let mut cb = Self::new_with_sessions(CommandCode::PcrExtend);
        cb.push_u32(pcr); // pcrHandle
                          // authorization area (empty password session)
        cb.push_u32(9); // size of authorizationArea
        cb.push_u32(0x40000009); // TPM_RS_PW
        cb.push_u16(0); // nonceSize
        cb.push_u8(0); // sessionAttributes
        cb.push_u16(0); // hmacSize

        // TPML_DIGEST_VALUES
        cb.push_u32(1); // count
        cb.push_u16(0x000B); // hashAlg = SHA256
        cb.push_slice(digest);
        cb.finish()
    }

    /// Build TPM2_PCR_Read command (§22.4).
    pub fn pcr_read(pcr: u32) -> Vec<u8> {
        let mut cb = Self::new(CommandCode::PcrRead);
        // pcrSelectionIn (TPML_PCR_SELECTION)
        cb.push_u32(1); // count
        cb.push_u16(0x000B); // hashAlg = SHA256
        cb.push_u8(3); // sizeofSelect
        let mut mask = [0u8; 3];
        if pcr < 24 {
            mask[(pcr / 8) as usize] |= 1 << (pcr % 8);
        }
        cb.push_slice(&mask);
        cb.finish()
    }

    /// Build TPM2_GetRandom command (§16.1).
    pub fn get_random(bytes: u16) -> Vec<u8> {
        let mut cb = Self::new(CommandCode::GetRandom);
        cb.push_u16(bytes);
        cb.finish()
    }
}

/// A parsed TPM2_PCR_Read response (Part 3 §22.6): the PCR update
/// counter, the echoed selection list, and the digest values in
/// selection order.
pub struct PcrReadResponse {
    /// `pcrUpdateCounter` — a UINT32 on the wire.
    pub update_counter: u32,
    /// `pcrSelectionOut` as `(TPM_ALG_ID, pcrSelect bytes)` pairs.
    pub selections: Vec<(u16, Vec<u8>)>,
    /// `pcrValues` — one entry per selected PCR, in selection order.
    pub digests: Vec<Vec<u8>>,
}

pub struct ResponseParser<'a> {
    buf: &'a [u8],
}

impl<'a> ResponseParser<'a> {
    pub fn new(buf: &'a [u8]) -> Result<Self, TpmError> {
        if buf.len() < 10 {
            return Err(TpmError::BadResponse);
        }
        let rc = u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]);
        if rc != 0 {
            // Map TPM2 response codes to a typed category per TCG
            // Part 2 §6.6 / Part 1 §39.4. Surfacing the decoded
            // `TpmRc` lets callers distinguish "retry me" (Retry /
            // NvRate) from "fatal" (Failure) without re-decoding
            // the wire bits.
            return Err(TpmError::Rc(TpmRc::from_rc(rc)));
        }
        Ok(Self { buf })
    }

    pub fn body(&self) -> &[u8] {
        &self.buf[10..]
    }

    /// Parse a TPM2_PCR_Read response (Part 3 §22.6), returning the
    /// first digest in the response's selection — the shape callers
    /// that read a single PCR consume.
    ///
    /// The walk is structural (see `parse_pcr_read_full`); this
    /// method once read the digest off the response tail instead,
    /// which coincides with the spec framing only for a single-PCR
    /// response and masked non-spec framing on the device side
    /// (#1065).
    pub fn parse_pcr_read(&self) -> Result<Vec<u8>, TpmError> {
        let full = self.parse_pcr_read_full()?;
        full.digests.into_iter().next().ok_or(TpmError::BadResponse)
    }

    /// Parse a TPM2_PCR_Read response structurally (Part 3 §22.6):
    /// `pcrUpdateCounter` (UINT32), `pcrSelectionOut`
    /// (TPML_PCR_SELECTION), `pcrValues` (TPML_DIGEST — a UINT32
    /// count followed by that many TPM2B_DIGEST entries, each with
    /// its own u16 size prefix). The walk must consume the body
    /// exactly; truncation, an overrun count, or trailing bytes are
    /// `BadResponse`, never a best-effort tail read.
    pub fn parse_pcr_read_full(&self) -> Result<PcrReadResponse, TpmError> {
        let body = self.body();
        let mut off = 0usize;
        let take = |off: &mut usize, n: usize| -> Result<&[u8], TpmError> {
            if body.len() < *off + n {
                return Err(TpmError::BadResponse);
            }
            let s = &body[*off..*off + n];
            *off += n;
            Ok(s)
        };
        let raw = take(&mut off, 4)?;
        let update_counter = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let raw = take(&mut off, 4)?;
        let sel_count = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
        // No with_capacity from wire counts: a corrupt count must
        // fail on the bounds-checked walk, not on a giant alloc.
        let mut selections = Vec::new();
        for _ in 0..sel_count {
            // TPMS_PCR_SELECTION: hashAlg(2) + sizeofSelect(1) + pcrSelect[]
            let raw = take(&mut off, 3)?;
            let alg = u16::from_be_bytes([raw[0], raw[1]]);
            let size = raw[2] as usize;
            let mask = take(&mut off, size)?.to_vec();
            selections.push((alg, mask));
        }
        let raw = take(&mut off, 4)?;
        let digest_count = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
        let mut digests = Vec::new();
        for _ in 0..digest_count {
            // TPM2B_DIGEST: size(2) + buffer[size]
            let raw = take(&mut off, 2)?;
            let size = u16::from_be_bytes([raw[0], raw[1]]) as usize;
            digests.push(take(&mut off, size)?.to_vec());
        }
        if off != body.len() {
            return Err(TpmError::BadResponse);
        }
        Ok(PcrReadResponse {
            update_counter,
            selections,
            digests,
        })
    }

    /// Parse a TPM2_GetCapability response for TPM_CAP_TPM_PROPERTIES.
    ///
    /// Returns `(more_data, entries)` — `more_data` set means the TPM
    /// holds further properties past the last returned tag and the
    /// caller may page by re-querying from tag+1. Each entry is a
    /// `(TPM_PT tag, value)` pair in ascending tag order. The echoed
    /// capability must be TPM_CAP_TPM_PROPERTIES; anything else is a
    /// `BadResponse` (use `parse_get_capability_pcr_selections` for
    /// TPM_CAP_PCRS instead).
    pub fn parse_get_capability_properties(&self) -> Result<(bool, Vec<(u32, u32)>), TpmError> {
        let body = self.body();
        // moreData(1) + capability(4) + count(4) + count × (tag(4) + value(4))
        if body.len() < 9 {
            return Err(TpmError::BadResponse);
        }
        let more_data = body[0] != 0;
        let capability = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
        if capability != crate::tpm2::TPM_CAP_TPM_PROPERTIES {
            return Err(TpmError::BadResponse);
        }
        let count = u32::from_be_bytes([body[5], body[6], body[7], body[8]]) as usize;
        if body.len() < 9 + count * 8 {
            return Err(TpmError::BadResponse);
        }
        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let off = 9 + i * 8;
            let tag = u32::from_be_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]]);
            let value =
                u32::from_be_bytes([body[off + 4], body[off + 5], body[off + 6], body[off + 7]]);
            entries.push((tag, value));
        }
        Ok((more_data, entries))
    }

    /// Parse a TPM2_GetCapability response for TPM_CAP_PCRS.
    ///
    /// Returns `(more_data, selections)` where each selection is a
    /// `(TPM_ALG_ID, pcrSelect bytes)` pair (TPML_PCR_SELECTION).
    pub fn parse_get_capability_pcr_selections(
        &self,
    ) -> Result<(bool, Vec<(u16, Vec<u8>)>), TpmError> {
        let body = self.body();
        // moreData(1) + capability(4) + count(4) + count × TPMS_PCR_SELECTION
        if body.len() < 9 {
            return Err(TpmError::BadResponse);
        }
        let more_data = body[0] != 0;
        let capability = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
        if capability != crate::tpm2::TPM_CAP_PCRS {
            return Err(TpmError::BadResponse);
        }
        let count = u32::from_be_bytes([body[5], body[6], body[7], body[8]]) as usize;
        let mut selections = Vec::with_capacity(count);
        let mut off = 9usize;
        for _ in 0..count {
            // algorithm(2) + sizeofSelect(1) + pcrSelect[sizeofSelect]
            if body.len() < off + 3 {
                return Err(TpmError::BadResponse);
            }
            let alg = u16::from_be_bytes([body[off], body[off + 1]]);
            let size = body[off + 2] as usize;
            if body.len() < off + 3 + size {
                return Err(TpmError::BadResponse);
            }
            selections.push((alg, body[off + 3..off + 3 + size].to_vec()));
            off += 3 + size;
        }
        Ok((more_data, selections))
    }

    /// Parse TPM2_GetRandom response.
    pub fn parse_get_random(&self) -> Result<Vec<u8>, TpmError> {
        let body = self.body();
        if body.len() < 2 {
            return Err(TpmError::BadResponse);
        }
        let size = u16::from_be_bytes([body[0], body[1]]) as usize;
        if 2 + size > body.len() {
            return Err(TpmError::BadResponse);
        }
        Ok(body[2..2 + size].to_vec())
    }
}

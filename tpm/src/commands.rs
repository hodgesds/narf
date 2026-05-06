//! TPM 2.0 Command Builder and Response Parser.
//!
//! Based on TCG TPM 2.0 Library Specification, Part 3: Commands.
//! Clean-room implementation following the wire format (§5.6).

use crate::types::TpmError;
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
    pub fn new(cc: CommandCode) -> Self {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
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
    pub fn pcr_extend(pcr: u32, digest: &[u8]) -> Vec<u8> {
        let mut cb = Self::new(CommandCode::PcrExtend);
        cb.push_u32(pcr); // pcrHandle
                          // authHandle (empty password session)
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
            // TODO: Map TPM2 error codes (RC) to TpmError
            return Err(TpmError::HardwareError);
        }
        Ok(Self { buf })
    }

    pub fn body(&self) -> &[u8] {
        &self.buf[10..]
    }

    /// Parse TPM2_PCR_Read response.
    pub fn parse_pcr_read(&self) -> Result<Vec<u8>, TpmError> {
        let body = self.body();
        if body.len() < 4 {
            return Err(TpmError::BadResponse);
        }
        // pcrUpdateCounter (u32)
        // pcrSelectionOut (TPML_PCR_SELECTION)
        // pcrValues (TPML_DIGEST)
        // For simplicity in Stage 4, we assume a single PCR was requested.
        let digest_count = u32::from_be_bytes([
            body[body.len() - 36],
            body[body.len() - 35],
            body[body.len() - 34],
            body[body.len() - 33],
        ]);
        if digest_count == 0 {
            return Err(TpmError::BadResponse);
        }
        Ok(body[body.len() - 32..].to_vec())
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

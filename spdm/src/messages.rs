//! SPDM 1.2 Message Definitions.
//!
//! Based on DSP0274: Security Protocol and Data Model (SPDM) Specification.
//! Clean-room implementation following the wire format.

use alloc::vec::Vec;

pub const SPDM_VERSION_12: u8 = 0x12;

pub enum RequestCode {
    GetVersion      = 0x84,
    GetCapabilities = 0xE1,
    NegotiateAlgs   = 0xE3,
    GetMeasurements = 0xE5,
}

pub enum ResponseCode {
    Version      = 0x04,
    Capabilities = 0x61,
    Algorithms   = 0x63,
    Measurements = 0x65,
    Error        = 0x7F,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidRequest     = 0x01,
    Busy               = 0x03,
    UnexpectedRequest  = 0x04,
    Unspecified        = 0x05,
    DecryptError       = 0x06,
    UnsupportedRequest = 0x07,
    RequestResend      = 0x08,
}

pub struct SpdmHeader {
    pub version: u8,
    pub code:    u8,
    pub param1:  u8,
    pub param2:  u8,
}

impl SpdmHeader {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.version);
        buf.push(self.code);
        buf.push(self.param1);
        buf.push(self.param2);
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 4 { return None; }
        Some(Self {
            version: buf[0],
            code:    buf[1],
            param1:  buf[2],
            param2:  buf[3],
        })
    }
}

pub struct GetVersionRequest;

impl GetVersionRequest {
    pub fn encode() -> Vec<u8> {
        let mut buf = Vec::with_capacity(4);
        SpdmHeader {
            version: 0x10, // Must be 0x10 for GET_VERSION
            code:    RequestCode::GetVersion as u8,
            param1:  0,
            param2:  0,
        }.encode(&mut buf);
        buf
    }
}

pub struct GetCapabilitiesRequest {
    pub ct_exponent: u8,
    pub flags:       u32,
}

impl GetCapabilitiesRequest {
    pub fn encode(version: u8) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12);
        SpdmHeader {
            version,
            code:    RequestCode::GetCapabilities as u8,
            param1:  0,
            param2:  0,
        }.encode(&mut buf);
        buf.push(0); // Reserved
        buf.push(0); // CTExponent (Host doesn't need to specify)
        buf.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        buf.extend_from_slice(&0x00000001u32.to_le_bytes()); // Flags (CERT_CAP=1 for now)
        buf
    }
}

pub struct GetMeasurementsRequest {
    pub measurement_attributes: u8,
    pub measurement_operation:  u8,
}

impl GetMeasurementsRequest {
    pub fn encode(version: u8, index: u8) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12);
        SpdmHeader {
            version,
            code:    RequestCode::GetMeasurements as u8,
            param1:  0, // MeasurementAttributes (0 = no signature)
            param2:  index,
        }.encode(&mut buf);
        // Nonce (32 bytes) - host-supplied
        buf.extend_from_slice(&[0u8; 32]); 
        buf
    }
}

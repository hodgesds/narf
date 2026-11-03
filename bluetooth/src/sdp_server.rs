//! SDP server — answers Service Discovery requests against a small
//! in-memory record database.
//!
//! Spec sources (public-only):
//! - Bluetooth Core Specification 5.3, Vol 3 Part B (SDP). §3
//!   (Service Records / Service Attributes), §4 (PDU formats and
//!   the response layouts used here), §5 (DataElement TLV encoding).
//!   <https://www.bluetooth.com/specifications/specs/core-specification/>
//! - Bluetooth Assigned Numbers — SDP Service-Class UUIDs and
//!   Universal Attribute IDs.
//!
//! No GPL Linux source consulted.
//!
//! ## Behaviour contract
//!
//! - One record is published: a Serial Port Profile record pointing
//!   at RFCOMM server channel 1 (see [`SPP_RECORD_HANDLE`]).
//! - The server never issues continuation state: requests carrying a
//!   non-empty continuation state are answered with Error Response
//!   0x0005 (Invalid Continuation State), and responses always end
//!   with a zero continuation byte. The database holds one record,
//!   so truncation never arises in practice; an attribute list that
//!   would exceed the request's max byte count is answered with
//!   Error Response 0x0006 (Insufficient Resources) instead of a
//!   silently truncated list.
//! - Error Response parameters are the 2-byte error code only: the
//!   error terminates the transaction, so no continuation state
//!   follows (§4.2.1 read as error-terminal).
//! - UUID matching normalises 16-bit and 32-bit UUIDs into the
//!   Bluetooth Base UUID (`00000000-0000-1000-8000-00805F9B34FB`
//!   with the short value in the top 32 bits) before comparison.
//!   A search for PublicBrowseRoot (0x1002) matches every browsable
//!   record.

use alloc::vec::Vec;

use crate::sdp::{
    decode_element, encode_sequence, encode_text, encode_uint, encode_uuid, PduHeader,
    DE_TYPE_SEQUENCE, DE_TYPE_UINT, DE_TYPE_UUID, PDU_ERROR_RESPONSE,
    PDU_SERVICE_ATTRIBUTE_REQUEST, PDU_SERVICE_ATTRIBUTE_RESPONSE,
    PDU_SERVICE_SEARCH_ATTRIBUTE_REQUEST, PDU_SERVICE_SEARCH_ATTRIBUTE_RESPONSE,
    PDU_SERVICE_SEARCH_REQUEST, PDU_SERVICE_SEARCH_RESPONSE,
};

/// Handle of the published Serial Port Profile record. Server-chosen
/// 32-bit handle space starts at 0x00010000 by convention.
pub const SPP_RECORD_HANDLE: u32 = 0x00010000;
/// RFCOMM server channel the SPP record advertises. The RFCOMM
/// session itself mirrors whatever DLCI the peer opens; this channel
/// number is only what SDP tells peers to use.
pub const SPP_SERVER_CHANNEL: u8 = 1;
/// ServiceClass UUID for Serial Port (Assigned Numbers).
pub const UUID_SERIAL_PORT: u16 = 0x1101;
/// ServiceClass UUID for the public browse root (Assigned Numbers).
pub const UUID_PUBLIC_BROWSE_ROOT: u16 = 0x1002;
/// Protocol UUID for L2CAP (Assigned Numbers).
pub const UUID_L2CAP: u16 = 0x0100;
/// Protocol UUID for RFCOMM (Assigned Numbers).
pub const UUID_RFCOMM: u16 = 0x0003;

/// SDP error codes (§4.2.1, table 4-2).
pub const SDP_ERR_INVALID_VERSION: u16 = 0x0001;
pub const SDP_ERR_INVALID_RECORD_HANDLE: u16 = 0x0002;
pub const SDP_ERR_INVALID_REQUEST_SYNTAX: u16 = 0x0003;
pub const SDP_ERR_INVALID_PDU_SIZE: u16 = 0x0004;
pub const SDP_ERR_INVALID_CONTINUATION_STATE: u16 = 0x0005;
pub const SDP_ERR_INSUFFICIENT_RESOURCES: u16 = 0x0006;

/// One published service record: a handle, its class UUIDs (16-bit
/// forms), whether it appears under the public browse root, and its
/// attributes as pre-encoded (attribute-ID, DataElement-value) pairs.
#[derive(Debug)]
struct Record {
    handle: u32,
    class_uuids: Vec<u16>,
    browsable: bool,
    /// (attribute ID, pre-encoded DataElement value).
    attrs: Vec<(u16, Vec<u8>)>,
}

/// The SDP server: a fixed record database plus the request handler.
/// Stateless per request — no per-connection state lives here; the
/// pump owns one server per controller.
#[derive(Debug)]
pub struct SdpServer {
    records: Vec<Record>,
}

impl Default for SdpServer {
    fn default() -> Self {
        Self::new()
    }
}

impl SdpServer {
    pub fn new() -> Self {
        Self {
            records: alloc::vec![spp_record()],
        }
    }

    /// Answer one SDP PDU. Always returns a complete response PDU
    /// (never empty): malformed input gets an Error Response.
    pub fn handle(&self, req: &[u8]) -> Vec<u8> {
        let Ok(hdr) = PduHeader::decode(req) else {
            return error_response(0, SDP_ERR_INVALID_PDU_SIZE);
        };
        let params = &req[5..];
        if params.len() < hdr.parameter_length as usize {
            return error_response(hdr.transaction_id, SDP_ERR_INVALID_PDU_SIZE);
        }
        let params = &params[..hdr.parameter_length as usize];
        match hdr.pdu_id {
            PDU_SERVICE_SEARCH_REQUEST => self.answer_search(hdr.transaction_id, params),
            PDU_SERVICE_ATTRIBUTE_REQUEST => self.answer_attribute(hdr.transaction_id, params),
            PDU_SERVICE_SEARCH_ATTRIBUTE_REQUEST => {
                self.answer_search_attribute(hdr.transaction_id, params)
            }
            _ => error_response(hdr.transaction_id, SDP_ERR_INVALID_REQUEST_SYNTAX),
        }
    }

    fn answer_search(&self, tid: u16, params: &[u8]) -> Vec<u8> {
        let Some((uuids, max_count, rest)) = parse_uuid_sequence(params) else {
            return error_response(tid, SDP_ERR_INVALID_REQUEST_SYNTAX);
        };
        let rest = match parse_continuation(rest) {
            Ok(rest) => rest,
            Err(err) => return error_response(tid, cont_error_code(err)),
        };
        if !rest.is_empty() {
            return error_response(tid, SDP_ERR_INVALID_REQUEST_SYNTAX);
        }
        let mut matches: Vec<u32> = Vec::new();
        for record in &self.records {
            if record_matches(record, &uuids) {
                matches.push(record.handle);
            }
        }
        let total = matches.len() as u16;
        let current = core::cmp::min(matches.len(), max_count as usize);
        let mut out_params: Vec<u8> = Vec::new();
        out_params.extend_from_slice(&total.to_be_bytes());
        out_params.extend_from_slice(&(current as u16).to_be_bytes());
        for handle in matches.iter().take(current) {
            out_params.extend_from_slice(&handle.to_be_bytes());
        }
        out_params.push(0); // continuation state: empty
        response_pdu(PDU_SERVICE_SEARCH_RESPONSE, tid, &out_params)
    }

    fn answer_attribute(&self, tid: u16, params: &[u8]) -> Vec<u8> {
        if params.len() < 6 {
            return error_response(tid, SDP_ERR_INVALID_REQUEST_SYNTAX);
        }
        let handle = u32::from_be_bytes([params[0], params[1], params[2], params[3]]);
        let max_bytes = u16::from_be_bytes([params[4], params[5]]) as usize;
        let Some((ids, rest)) = parse_attribute_id_sequence(&params[6..]) else {
            return error_response(tid, SDP_ERR_INVALID_REQUEST_SYNTAX);
        };
        let rest = match parse_continuation(rest) {
            Ok(rest) => rest,
            Err(err) => return error_response(tid, cont_error_code(err)),
        };
        if !rest.is_empty() {
            return error_response(tid, SDP_ERR_INVALID_REQUEST_SYNTAX);
        }
        let Some(record) = self.records.iter().find(|r| r.handle == handle) else {
            return error_response(tid, SDP_ERR_INVALID_RECORD_HANDLE);
        };
        let mut list: Vec<u8> = Vec::new();
        for (aid, value) in &record.attrs {
            if attribute_wanted(*aid, &ids) {
                encode_uint(&mut list, 2, *aid as u64);
                list.extend_from_slice(value);
            }
        }
        if list.len() > max_bytes {
            return error_response(tid, SDP_ERR_INSUFFICIENT_RESOURCES);
        }
        let mut out_params: Vec<u8> = Vec::new();
        out_params.extend_from_slice(&(list.len() as u16).to_be_bytes());
        out_params.extend_from_slice(&list);
        out_params.push(0); // continuation state: empty
        response_pdu(PDU_SERVICE_ATTRIBUTE_RESPONSE, tid, &out_params)
    }

    fn answer_search_attribute(&self, tid: u16, params: &[u8]) -> Vec<u8> {
        let Some((uuids, max_bytes, rest)) = parse_uuid_sequence(params) else {
            return error_response(tid, SDP_ERR_INVALID_REQUEST_SYNTAX);
        };
        let Some((ids, rest)) = parse_attribute_id_sequence(rest) else {
            return error_response(tid, SDP_ERR_INVALID_REQUEST_SYNTAX);
        };
        let rest = match parse_continuation(rest) {
            Ok(rest) => rest,
            Err(err) => return error_response(tid, cont_error_code(err)),
        };
        if !rest.is_empty() {
            return error_response(tid, SDP_ERR_INVALID_REQUEST_SYNTAX);
        }
        let wanted = &ids;
        let mut lists: Vec<u8> = Vec::new();
        for record in &self.records {
            if !record_matches(record, &uuids) {
                continue;
            }
            let mut pairs: Vec<u8> = Vec::new();
            for (aid, value) in &record.attrs {
                if attribute_wanted(*aid, wanted) {
                    encode_uint(&mut pairs, 2, *aid as u64);
                    pairs.extend_from_slice(value);
                }
            }
            encode_sequence(&mut lists, 5, &pairs);
        }
        if lists.len() > max_bytes as usize {
            return error_response(tid, SDP_ERR_INSUFFICIENT_RESOURCES);
        }
        let mut out_params: Vec<u8> = Vec::new();
        out_params.extend_from_slice(&(lists.len() as u16).to_be_bytes());
        out_params.extend_from_slice(&lists);
        out_params.push(0); // continuation state: empty
        response_pdu(PDU_SERVICE_SEARCH_ATTRIBUTE_RESPONSE, tid, &out_params)
    }
}

/// The published SPP record: Serial Port class, L2CAP + RFCOMM
/// (server channel 1) protocol stack, public browse root, name.
fn spp_record() -> Record {
    let mut protocol: Vec<u8> = Vec::new();
    let mut l2cap_layer: Vec<u8> = Vec::new();
    encode_uuid(&mut l2cap_layer, &UUID_L2CAP.to_be_bytes());
    encode_sequence(&mut protocol, 5, &l2cap_layer);
    let mut rfcomm_layer: Vec<u8> = Vec::new();
    encode_uuid(&mut rfcomm_layer, &UUID_RFCOMM.to_be_bytes());
    encode_uint(&mut rfcomm_layer, 1, SPP_SERVER_CHANNEL as u64);
    encode_sequence(&mut protocol, 5, &rfcomm_layer);

    let mut class_list: Vec<u8> = Vec::new();
    encode_uuid(&mut class_list, &UUID_SERIAL_PORT.to_be_bytes());

    let mut browse_list: Vec<u8> = Vec::new();
    encode_uuid(&mut browse_list, &UUID_PUBLIC_BROWSE_ROOT.to_be_bytes());

    let mut profile_list: Vec<u8> = Vec::new();
    let mut profile_entry: Vec<u8> = Vec::new();
    encode_uuid(&mut profile_entry, &UUID_SERIAL_PORT.to_be_bytes());
    encode_uint(&mut profile_entry, 2, 0x0102);
    encode_sequence(&mut profile_list, 5, &profile_entry);

    let mut name: Vec<u8> = Vec::new();
    encode_text(&mut name, "NARF SPP");

    let mut handle_value: Vec<u8> = Vec::new();
    encode_uint(&mut handle_value, 4, SPP_RECORD_HANDLE as u64);

    Record {
        handle: SPP_RECORD_HANDLE,
        class_uuids: alloc::vec![UUID_SERIAL_PORT],
        browsable: true,
        attrs: alloc::vec![
            (0x0000, handle_value),
            (0x0001, {
                let mut v = Vec::new();
                encode_sequence(&mut v, 5, &class_list);
                v
            }),
            (0x0004, {
                let mut v = Vec::new();
                encode_sequence(&mut v, 5, &protocol);
                v
            }),
            (0x0005, {
                let mut v = Vec::new();
                encode_sequence(&mut v, 5, &browse_list);
                v
            }),
            (0x0009, {
                let mut v = Vec::new();
                encode_sequence(&mut v, 5, &profile_list);
                v
            }),
            (0x0100, name),
        ],
    }
}

/// Expand a 16-bit or 32-bit UUID into the 128-bit Bluetooth Base
/// UUID form. 128-bit inputs pass through unchanged.
fn normalize_uuid(bytes: &[u8]) -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    // Base UUID tail: 0000-1000-8000-00805F9B34FB.
    out[4..16].copy_from_slice(&[
        0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB,
    ]);
    match bytes.len() {
        2 => {
            out[2] = bytes[0];
            out[3] = bytes[1];
            Some(out)
        }
        4 => {
            out[0..4].copy_from_slice(bytes);
            Some(out)
        }
        16 => {
            let mut full = [0u8; 16];
            full.copy_from_slice(bytes);
            Some(full)
        }
        _ => None,
    }
}

fn record_matches(record: &Record, uuids: &[[u8; 16]]) -> bool {
    if uuids.is_empty() {
        return false;
    }
    let browse_root = normalize_uuid(&UUID_PUBLIC_BROWSE_ROOT.to_be_bytes()).unwrap();
    for want in uuids {
        if *want == browse_root && record.browsable {
            return true;
        }
        for class in &record.class_uuids {
            if let Some(norm) = normalize_uuid(&class.to_be_bytes()) {
                if norm == *want {
                    return true;
                }
            }
        }
    }
    false
}

/// Parsed UUID-sequence request prefix: normalised UUIDs, the
/// trailing u16 field (max record count / max byte count), and the
/// unparsed remainder.
type UuidSeq<'a> = (Vec<[u8; 16]>, u16, &'a [u8]);

/// Parse a leading UUID Sequence DataElement, then a u16 BE field
/// (max record count for search, max byte count for
/// search-attribute). Returns (uuids, field, rest).
fn parse_uuid_sequence(params: &[u8]) -> Option<UuidSeq<'_>> {
    let (uuids, rest) = parse_uuid_list(params)?;
    if rest.len() < 2 {
        return None;
    }
    let count = u16::from_be_bytes([rest[0], rest[1]]);
    Some((uuids, count, &rest[2..]))
}

/// Parse a UUID Sequence DataElement into normalised 128-bit UUIDs.
/// Returns (uuids, rest-after-element).
fn parse_uuid_list(params: &[u8]) -> Option<(Vec<[u8; 16]>, &[u8])> {
    let (ty, payload, consumed) = decode_element(params).ok()?;
    if ty != DE_TYPE_SEQUENCE {
        return None;
    }
    let mut uuids: Vec<[u8; 16]> = Vec::new();
    let mut buf = payload;
    while !buf.is_empty() {
        let (ety, epayload, econsumed) = decode_element(buf).ok()?;
        if ety != DE_TYPE_UUID {
            return None;
        }
        let norm = normalize_uuid(epayload)?;
        uuids.push(norm);
        buf = &buf[econsumed..];
    }
    Some((uuids, &params[consumed..]))
}

/// Parse an attribute-ID Sequence DataElement into raw ID values
/// (u16 singles, u32 ranges). Returns (ids, rest-after-element).
fn parse_attribute_id_sequence(params: &[u8]) -> Option<(Vec<u32>, &[u8])> {
    let (ty, payload, consumed) = decode_element(params).ok()?;
    if ty != DE_TYPE_SEQUENCE {
        return None;
    }
    let mut ids: Vec<u32> = Vec::new();
    let mut buf = payload;
    while !buf.is_empty() {
        let (ety, epayload, econsumed) = decode_element(buf).ok()?;
        if ety != DE_TYPE_UINT {
            return None;
        }
        let id = match epayload.len() {
            2 => u16::from_be_bytes([epayload[0], epayload[1]]) as u32,
            4 => u32::from_be_bytes([epayload[0], epayload[1], epayload[2], epayload[3]]),
            _ => return None,
        };
        ids.push(id);
        buf = &buf[econsumed..];
    }
    Some((ids, &params[consumed..]))
}

/// Whether attribute `id` is requested: either listed singly or
/// inside a requested range (start in the high 16 bits, end in the
/// low 16 bits). Checking against the record's own attributes
/// instead of expanding ranges keeps a maximal range (0..0xFFFF)
/// from materialising a 64k-entry list.
fn attribute_wanted(id: u16, ids: &[u32]) -> bool {
    ids.iter().any(|raw| {
        if *raw <= 0xFFFF {
            *raw as u16 == id
        } else {
            let start = (*raw >> 16) as u16;
            let end = (*raw & 0xFFFF) as u16;
            start <= id && id <= end
        }
    })
}

/// Continuation-field parse failures: truncated (the size byte
/// overruns the parameters) vs non-empty (a state the server never
/// issued).
enum ContError {
    Truncated,
    NonEmpty,
}

/// Parse a continuation-state field: size byte + that many bytes.
/// `Ok(rest)` only for an empty state.
fn parse_continuation(params: &[u8]) -> Result<&[u8], ContError> {
    if params.is_empty() {
        return Err(ContError::Truncated);
    }
    let size = params[0] as usize;
    if params.len() < 1 + size {
        return Err(ContError::Truncated);
    }
    if size != 0 {
        return Err(ContError::NonEmpty);
    }
    Ok(&params[1..])
}

/// Map a continuation error to its SDP error code.
fn cont_error_code(err: ContError) -> u16 {
    match err {
        ContError::Truncated => SDP_ERR_INVALID_REQUEST_SYNTAX,
        ContError::NonEmpty => SDP_ERR_INVALID_CONTINUATION_STATE,
    }
}

/// Build a response PDU: header + parameters.
fn response_pdu(pdu_id: u8, tid: u16, params: &[u8]) -> Vec<u8> {
    let mut out = PduHeader {
        pdu_id,
        transaction_id: tid,
        parameter_length: params.len() as u16,
    }
    .encode()
    .to_vec();
    out.extend_from_slice(params);
    out
}

/// Build an Error Response PDU: header + 2-byte error code.
fn error_response(tid: u16, code: u16) -> Vec<u8> {
    response_pdu(PDU_ERROR_RESPONSE, tid, &code.to_be_bytes())
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn search_request(tid: u16, uuid: u16) -> Vec<u8> {
        crate::sdp::build_service_search_request(tid, &[&uuid.to_be_bytes()], 0xFFFF)
    }

    fn sdp_search_spp_found() -> TestResult {
        let server = SdpServer::new();
        let rsp = server.handle(&search_request(0x1234, UUID_SERIAL_PORT));
        // Exact bytes: PDU 0x03, TID 0x1234, len 9, total 1, current 1,
        // handle 0x00010000, continuation 0.
        let expected: Vec<u8> = alloc::vec![
            0x03, 0x12, 0x34, 0x00, 0x09, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
        ];
        if rsp != expected {
            return TestResult::Fail("SPP search response bytes mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/sdp-server", sdp_search_spp_found);

    fn sdp_search_no_match_empty() -> TestResult {
        let server = SdpServer::new();
        let rsp = server.handle(&search_request(0x0001, 0x1108)); // Headset, not published
        let expected: Vec<u8> =
            alloc::vec![0x03, 0x00, 0x01, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00];
        if rsp != expected {
            return TestResult::Fail("no-match search should list zero handles");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/sdp-server", sdp_search_no_match_empty);

    fn sdp_attribute_unknown_handle_errors() -> TestResult {
        let server = SdpServer::new();
        let req = crate::sdp::build_service_attribute_request(
            0x00AA,
            0x00020000,
            0xFFFF,
            &[0x0001],
            false,
        );
        let rsp = server.handle(&req);
        // PDU 0x01, TID 0x00AA, len 2, error 0x0002.
        let expected: Vec<u8> = alloc::vec![0x01, 0x00, 0xAA, 0x00, 0x02, 0x00, 0x02];
        if rsp != expected {
            return TestResult::Fail("unknown handle should error 0x0002");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/sdp-server", sdp_attribute_unknown_handle_errors);

    fn sdp_attribute_name_present() -> TestResult {
        let server = SdpServer::new();
        let req = crate::sdp::build_service_attribute_request(
            0x0007,
            SPP_RECORD_HANDLE,
            0xFFFF,
            &[0x0100],
            false,
        );
        let rsp = server.handle(&req);
        if rsp.len() < 6 || rsp[0] != PDU_SERVICE_ATTRIBUTE_RESPONSE {
            return TestResult::Fail("attribute response PDU id wrong");
        }
        if rsp[1..3] != [0x00, 0x07] {
            return TestResult::Fail("attribute response TID not echoed");
        }
        if !rsp.windows(8).any(|w| w == b"NARF SPP") {
            return TestResult::Fail("attribute response missing service name");
        }
        if rsp.last() != Some(&0) {
            return TestResult::Fail("attribute response must end with empty continuation");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/sdp-server", sdp_attribute_name_present);

    fn sdp_continuation_rejected() -> TestResult {
        let server = SdpServer::new();
        // Search request with a non-empty continuation state: build by
        // hand (UUID seq + max count + size 1 + one byte).
        let mut uuid_seq: Vec<u8> = Vec::new();
        encode_uuid(&mut uuid_seq, &UUID_SERIAL_PORT.to_be_bytes());
        let mut params: Vec<u8> = Vec::new();
        encode_sequence(&mut params, 5, &uuid_seq);
        params.extend_from_slice(&0xFFFFu16.to_be_bytes());
        params.push(1);
        params.push(0xAB);
        let mut req = PduHeader {
            pdu_id: PDU_SERVICE_SEARCH_REQUEST,
            transaction_id: 0x0009,
            parameter_length: params.len() as u16,
        }
        .encode()
        .to_vec();
        req.extend_from_slice(&params);
        let rsp = server.handle(&req);
        let expected: Vec<u8> = alloc::vec![0x01, 0x00, 0x09, 0x00, 0x02, 0x00, 0x05];
        if rsp != expected {
            return TestResult::Fail("non-empty continuation should error 0x0005");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/sdp-server", sdp_continuation_rejected);
}

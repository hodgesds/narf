//! GATT server-side attribute database (clean-room).
//!
//! Spec: Bluetooth Core Specification 5.3 Vol 3 Part F (ATT) +
//! Vol 3 Part G (GATT). Public Bluetooth SIG documents. No GPL
//! Linux source consulted.
//!
//! The server holds a flat ordered list of *attributes*. Each
//! attribute has a 16-bit handle (assigned in insertion order
//! starting at 0x0001), a UUID type, permissions, and a value.
//! Service / Characteristic / Descriptor structure is encoded by
//! the *type* of each attribute:
//!
//!   - 0x2800 Primary Service declaration — value is the service UUID.
//!   - 0x2801 Secondary Service declaration.
//!   - 0x2803 Characteristic declaration — value is `[props (1) || value_handle (2) || char UUID]`.
//!   - 0x2902 Client Characteristic Configuration descriptor.
//!   - any other UUID — Characteristic Value or vendor descriptor.
//!
//! The server's job is to consume incoming ATT requests (Read /
//! Write / Find Information / Read By Type / Read By Group Type)
//! and emit the right Response. We model that as a single
//! `handle_request(&Pdu) -> Pdu` entry point.

use alloc::vec::Vec;

use crate::att::{
    Pdu, ATT_ECODE_ATTRIBUTE_NOT_FOUND, ATT_ECODE_INVALID_HANDLE,
    ATT_ECODE_REQUEST_NOT_SUPPORTED, ATT_ECODE_WRITE_NOT_PERMITTED, ATT_ERROR_RSP,
    ATT_EXCHANGE_MTU_REQ, ATT_EXCHANGE_MTU_RSP, ATT_FIND_INFORMATION_REQ,
    ATT_FIND_INFORMATION_RSP, ATT_READ_BY_GROUP_TYPE_REQ, ATT_READ_BY_GROUP_TYPE_RSP,
    ATT_READ_BY_TYPE_REQ, ATT_READ_BY_TYPE_RSP, ATT_READ_REQ, ATT_READ_RSP, ATT_WRITE_REQ,
    ATT_WRITE_RSP,
};
use crate::gatt::{Uuid, UUID_PRIMARY_SERVICE};

/// Permission bitmap for an attribute (§3.3.1.1 + §3.3.3 of Vol 3
/// Part G; the spec encodes these implicitly through the attribute
/// type, but server-side we surface them as flags).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Permissions {
    pub readable: bool,
    pub writable: bool,
    pub requires_auth: bool,
    pub requires_encryption: bool,
}

impl Permissions {
    pub const fn read() -> Self {
        Self {
            readable: true,
            writable: false,
            requires_auth: false,
            requires_encryption: false,
        }
    }
    pub const fn read_write() -> Self {
        Self {
            readable: true,
            writable: true,
            requires_auth: false,
            requires_encryption: false,
        }
    }
}

/// One attribute slot in the database.
#[derive(Clone, Debug)]
pub struct Attribute {
    pub handle: u16,
    pub uuid: Uuid,
    pub perms: Permissions,
    pub value: Vec<u8>,
}

/// Flat attribute database. Handles assigned in insertion order
/// starting at 0x0001.
#[derive(Debug, Default)]
pub struct AttributeDatabase {
    attrs: Vec<Attribute>,
    next_handle: u16,
}

impl AttributeDatabase {
    pub fn new() -> Self {
        Self {
            attrs: Vec::new(),
            next_handle: 0x0001,
        }
    }

    /// Insert one attribute and return its assigned handle.
    pub fn insert(&mut self, uuid: Uuid, perms: Permissions, value: Vec<u8>) -> u16 {
        let handle = self.next_handle;
        self.attrs.push(Attribute {
            handle,
            uuid,
            perms,
            value,
        });
        self.next_handle = self.next_handle.saturating_add(1);
        handle
    }

    /// Convenience: declare a Primary Service. Returns the service
    /// declaration's handle. Subsequent characteristic / descriptor
    /// inserts go into this service until the next `add_primary_service`.
    pub fn add_primary_service(&mut self, service_uuid: Uuid) -> u16 {
        let mut value = Vec::new();
        service_uuid.write_le(&mut value);
        self.insert(Uuid::U16(UUID_PRIMARY_SERVICE), Permissions::read(), value)
    }

    /// Convenience: declare a Characteristic — emits the declaration
    /// attribute (UUID 0x2803) plus the value attribute. Returns
    /// `(declaration_handle, value_handle)`.
    pub fn add_characteristic(
        &mut self,
        char_uuid: Uuid,
        properties: u8,
        perms: Permissions,
        initial_value: Vec<u8>,
    ) -> (u16, u16) {
        // Declaration value layout: properties (1) || value_handle
        // (2) || characteristic UUID (2 or 16). The value handle is
        // always the next slot (decl_handle + 1) by GATT convention.
        let decl_handle = self.next_handle;
        let value_handle = decl_handle.wrapping_add(1);
        let mut decl_value = Vec::new();
        decl_value.push(properties);
        decl_value.extend_from_slice(&value_handle.to_le_bytes());
        char_uuid.write_le(&mut decl_value);
        self.insert(Uuid::U16(0x2803), Permissions::read(), decl_value);
        let _val_h = self.insert(char_uuid, perms, initial_value);
        debug_assert_eq!(_val_h, value_handle);
        (decl_handle, value_handle)
    }

    pub fn attrs(&self) -> &[Attribute] {
        &self.attrs
    }

    pub fn attr_by_handle(&self, handle: u16) -> Option<&Attribute> {
        self.attrs.iter().find(|a| a.handle == handle)
    }

    pub fn attr_by_handle_mut(&mut self, handle: u16) -> Option<&mut Attribute> {
        self.attrs.iter_mut().find(|a| a.handle == handle)
    }
}

// ── Request dispatch ───────────────────────────────────────────────

/// Server-side ATT MTU. Default 23, may grow on Exchange MTU.
#[derive(Debug)]
pub struct GattServer {
    pub db: AttributeDatabase,
    pub mtu: u16,
}

impl Default for GattServer {
    fn default() -> Self {
        Self {
            db: AttributeDatabase::new(),
            mtu: 23,
        }
    }
}

impl GattServer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Handle one ATT request and produce the response PDU.
    pub fn handle_request(&mut self, req: &Pdu) -> Pdu {
        match req.opcode {
            ATT_EXCHANGE_MTU_REQ => self.handle_mtu(req),
            ATT_READ_REQ => self.handle_read(req),
            ATT_WRITE_REQ => self.handle_write(req),
            ATT_READ_BY_GROUP_TYPE_REQ => self.handle_read_by_group_type(req),
            ATT_READ_BY_TYPE_REQ => self.handle_read_by_type(req),
            ATT_FIND_INFORMATION_REQ => self.handle_find_information(req),
            _ => self.error_rsp(req.opcode, 0, ATT_ECODE_REQUEST_NOT_SUPPORTED),
        }
    }

    fn error_rsp(&self, req_opcode: u8, handle: u16, code: u8) -> Pdu {
        Pdu {
            opcode: ATT_ERROR_RSP,
            params: alloc::vec![req_opcode, (handle & 0xFF) as u8, (handle >> 8) as u8, code],
        }
    }

    fn handle_mtu(&mut self, req: &Pdu) -> Pdu {
        let client_mtu = if req.params.len() >= 2 {
            u16::from_le_bytes([req.params[0], req.params[1]])
        } else {
            23
        };
        // Pick min(client, server) ≥ 23 (§3.4.2).
        self.mtu = self.mtu.min(client_mtu).max(23);
        Pdu {
            opcode: ATT_EXCHANGE_MTU_RSP,
            params: self.mtu.to_le_bytes().to_vec(),
        }
    }

    fn handle_read(&self, req: &Pdu) -> Pdu {
        if req.params.len() < 2 {
            return self.error_rsp(ATT_READ_REQ, 0, ATT_ECODE_INVALID_HANDLE);
        }
        let h = u16::from_le_bytes([req.params[0], req.params[1]]);
        let attr = match self.db.attr_by_handle(h) {
            Some(a) => a,
            None => return self.error_rsp(ATT_READ_REQ, h, ATT_ECODE_INVALID_HANDLE),
        };
        if !attr.perms.readable {
            return self.error_rsp(ATT_READ_REQ, h, ATT_ECODE_WRITE_NOT_PERMITTED);
        }
        let mut out = attr.value.clone();
        // Truncate to MTU - 1 (opcode byte).
        let cap = (self.mtu as usize).saturating_sub(1);
        out.truncate(cap);
        Pdu {
            opcode: ATT_READ_RSP,
            params: out,
        }
    }

    fn handle_write(&mut self, req: &Pdu) -> Pdu {
        if req.params.len() < 2 {
            return self.error_rsp(ATT_WRITE_REQ, 0, ATT_ECODE_INVALID_HANDLE);
        }
        let h = u16::from_le_bytes([req.params[0], req.params[1]]);
        let new_value = req.params[2..].to_vec();
        let attr = match self.db.attr_by_handle_mut(h) {
            Some(a) => a,
            None => return self.error_rsp(ATT_WRITE_REQ, h, ATT_ECODE_INVALID_HANDLE),
        };
        if !attr.perms.writable {
            return self.error_rsp(ATT_WRITE_REQ, h, ATT_ECODE_WRITE_NOT_PERMITTED);
        }
        attr.value = new_value;
        Pdu {
            opcode: ATT_WRITE_RSP,
            params: Vec::new(),
        }
    }

    fn handle_read_by_group_type(&self, req: &Pdu) -> Pdu {
        // params: start_handle (2) + end_handle (2) + group_type (2 or 16).
        if req.params.len() < 6 {
            return self.error_rsp(ATT_READ_BY_GROUP_TYPE_REQ, 0, ATT_ECODE_INVALID_HANDLE);
        }
        let start = u16::from_le_bytes([req.params[0], req.params[1]]);
        let end = u16::from_le_bytes([req.params[2], req.params[3]]);
        let group_uuid = match Uuid::from_le_bytes(&req.params[4..]) {
            Some(u) => u,
            None => {
                return self.error_rsp(ATT_READ_BY_GROUP_TYPE_REQ, 0, ATT_ECODE_INVALID_HANDLE)
            }
        };
        // We only support Primary Service group discovery in this
        // pass — Secondary Service follows the same shape with a
        // different UUID, easy to extend.
        if group_uuid != Uuid::U16(UUID_PRIMARY_SERVICE) {
            return self.error_rsp(
                ATT_READ_BY_GROUP_TYPE_REQ,
                start,
                ATT_ECODE_REQUEST_NOT_SUPPORTED,
            );
        }
        // Walk attrs in [start, end] picking 0x2800 declarations.
        let mut tuples = Vec::new();
        let mut unit_size: Option<usize> = None;
        for (i, attr) in self.db.attrs.iter().enumerate() {
            if attr.handle < start || attr.handle > end {
                continue;
            }
            if attr.uuid != Uuid::U16(UUID_PRIMARY_SERVICE) {
                continue;
            }
            // The end-group-handle is the next 0x2800 declaration's
            // handle - 1, or the database's last handle.
            let mut group_end = attr.handle;
            for next in self.db.attrs.iter().skip(i + 1) {
                if next.uuid == Uuid::U16(UUID_PRIMARY_SERVICE) {
                    break;
                }
                group_end = next.handle;
            }
            let value_len = attr.value.len();
            let unit = 4 + value_len;
            // §3.4.4.10: every tuple in a single response has the
            // same length. Once we've started a response, skip
            // tuples whose unit size differs.
            match unit_size {
                None => unit_size = Some(unit),
                Some(s) if s != unit => continue,
                _ => {}
            }
            let mut t = Vec::with_capacity(unit);
            t.extend_from_slice(&attr.handle.to_le_bytes());
            t.extend_from_slice(&group_end.to_le_bytes());
            t.extend_from_slice(&attr.value);
            tuples.extend_from_slice(&t);
        }
        if tuples.is_empty() {
            return self.error_rsp(ATT_READ_BY_GROUP_TYPE_REQ, start, ATT_ECODE_ATTRIBUTE_NOT_FOUND);
        }
        let mut out = Vec::with_capacity(1 + tuples.len());
        out.push(unit_size.unwrap_or(0) as u8);
        out.extend_from_slice(&tuples);
        Pdu {
            opcode: ATT_READ_BY_GROUP_TYPE_RSP,
            params: out,
        }
    }

    fn handle_read_by_type(&self, req: &Pdu) -> Pdu {
        if req.params.len() < 6 {
            return self.error_rsp(ATT_READ_BY_TYPE_REQ, 0, ATT_ECODE_INVALID_HANDLE);
        }
        let start = u16::from_le_bytes([req.params[0], req.params[1]]);
        let end = u16::from_le_bytes([req.params[2], req.params[3]]);
        let target_uuid = match Uuid::from_le_bytes(&req.params[4..]) {
            Some(u) => u,
            None => return self.error_rsp(ATT_READ_BY_TYPE_REQ, 0, ATT_ECODE_INVALID_HANDLE),
        };
        let mut tuples = Vec::new();
        let mut unit_size: Option<usize> = None;
        for attr in self.db.attrs.iter() {
            if attr.handle < start || attr.handle > end {
                continue;
            }
            if attr.uuid != target_uuid {
                continue;
            }
            let unit = 2 + attr.value.len();
            match unit_size {
                None => unit_size = Some(unit),
                Some(s) if s != unit => continue,
                _ => {}
            }
            tuples.extend_from_slice(&attr.handle.to_le_bytes());
            tuples.extend_from_slice(&attr.value);
        }
        if tuples.is_empty() {
            return self.error_rsp(ATT_READ_BY_TYPE_REQ, start, ATT_ECODE_ATTRIBUTE_NOT_FOUND);
        }
        let mut out = Vec::with_capacity(1 + tuples.len());
        out.push(unit_size.unwrap_or(0) as u8);
        out.extend_from_slice(&tuples);
        Pdu {
            opcode: ATT_READ_BY_TYPE_RSP,
            params: out,
        }
    }

    fn handle_find_information(&self, req: &Pdu) -> Pdu {
        if req.params.len() < 4 {
            return self.error_rsp(ATT_FIND_INFORMATION_REQ, 0, ATT_ECODE_INVALID_HANDLE);
        }
        let start = u16::from_le_bytes([req.params[0], req.params[1]]);
        let end = u16::from_le_bytes([req.params[2], req.params[3]]);
        // Spec says all entries in one response share the same UUID
        // size — choose 16-bit or 128-bit based on the first match.
        let mut format: Option<u8> = None;
        let mut tuples = Vec::new();
        for attr in self.db.attrs.iter() {
            if attr.handle < start || attr.handle > end {
                continue;
            }
            let (this_format, encoded_len) = match attr.uuid {
                Uuid::U16(_) => (0x01u8, 4),
                Uuid::U128(_) => (0x02u8, 18),
            };
            match format {
                None => format = Some(this_format),
                Some(f) if f != this_format => continue,
                _ => {}
            }
            let mut t = Vec::with_capacity(encoded_len);
            t.extend_from_slice(&attr.handle.to_le_bytes());
            attr.uuid.write_le(&mut t);
            tuples.extend_from_slice(&t);
        }
        if tuples.is_empty() {
            return self.error_rsp(
                ATT_FIND_INFORMATION_REQ,
                start,
                ATT_ECODE_ATTRIBUTE_NOT_FOUND,
            );
        }
        let mut out = Vec::with_capacity(1 + tuples.len());
        out.push(format.unwrap_or(0x01));
        out.extend_from_slice(&tuples);
        Pdu {
            opcode: ATT_FIND_INFORMATION_RSP,
            params: out,
        }
    }
}

//! ATOM display-object table walker — clean-room.
//!
//! Reference: AMD `AtomBios.h` (MIT-licensed structure). The
//! display-object data table (id `0x05` per AtomBios.h) carries
//! the per-board topology: which connectors are wired to which
//! encoders, which encoders drive which transmitters, and what
//! signal types each connector accepts (DP/HDMI/DVI/eDP/…).
//!
//! ## Layout
//!
//! ```text
//! ATOM_DISPLAY_OBJECT_TABLE
//! +0x00   ATOM_COMMON_TABLE_HEADER (4 B)
//! +0x04   usDeviceSupport                u16  (bitmap of display kinds)
//! +0x06   ucNumberOfPath                 u8
//! +0x07   ucReserved                     u8
//! +0x08   ATOM_DISPLAY_OBJECT_PATH[N]    8-byte entries
//! ```
//!
//! Each path:
//!
//! ```text
//! +0x00   usDeviceTag                    u16
//! +0x02   usSize                         u16  (path entry size)
//! +0x04   usConnObjectId                 u16
//! +0x06   usGPUObjectId                  u16
//! ```
//!
//! `usConnObjectId` decodes via `ATOM_OBJECT_ID_*` constants per
//! AtomBios.h: bits[15:8] = object enum-id (DP / HDMI / DVI /
//! eDP / VGA / LVDS / DSI), bits[7:0] = instance number.
//!
//! ## Scope
//!
//! Stage-6 ships path enumeration + connector-type decode.
//! Encoder / transmitter / per-path object chains (each path
//! continues past the GPU-object header with a list of
//! intermediate object ids, terminated by a sentinel) are a
//! mechanical follow-up once a board with an interesting
//! connector chain shows up.

use core::fmt;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DisplayObjError {
    Truncated,
    UnsupportedVersion(u8),
    PathOutOfBounds,
}

/// Connector types per the ATOM `ATOM_OBJECT_ID_*` enum subset
/// we care about. Stage-6 covers the modern-display set
/// (DP / eDP / HDMI / DVI / VGA / LVDS / DSI).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnectorKind {
    Dp,
    Edp,
    HdmiA,
    HdmiB,
    DviI,
    DviD,
    Vga,
    Lvds,
    /// `CONNECTOR_OBJECT_ID_USBC` — a DisplayPort tunnel over a USB-C port,
    /// which is how Phoenix's DPIA outputs present.
    Usbc,
    Unknown(u8),
}

impl ConnectorKind {
    /// `CONNECTOR_OBJECT_ID_*` from `ObjectID.h`.
    ///
    /// LINUX-GAP: `Vga` was 0x01, which is `SINGLE_LINK_DVI_I` — VGA is
    /// **0x05**. And `Dsi` was 0x15, which is `CONNECTOR_OBJECT_ID_MXM`; there
    /// is no DSI connector object id in the enum at all. 0x17 is
    /// `CONNECTOR_OBJECT_ID_USBC`, which is the one Phoenix actually has and
    /// which was missing.
    ///
    /// DVI comes in four ids — single and dual link of each of I and D — and
    /// only two were mapped, so a dual-link DVI-D panel read as unknown.
    fn from_object_enum(id: u8) -> Self {
        match id {
            0x01 | 0x02 => ConnectorKind::DviI,
            0x03 | 0x04 => ConnectorKind::DviD,
            0x05 => ConnectorKind::Vga,
            0x0C => ConnectorKind::HdmiA,
            0x0D => ConnectorKind::HdmiB,
            0x0E => ConnectorKind::Lvds,
            0x13 => ConnectorKind::Dp,
            0x14 | 0x16 => ConnectorKind::Edp,
            0x17 => ConnectorKind::Usbc,
            other => ConnectorKind::Unknown(other),
        }
    }
}

/// One connector path entry from the ATOM table.
#[derive(Copy, Clone)]
pub struct DisplayPath {
    pub device_tag: u16,
    pub connector_kind: ConnectorKind,
    pub connector_index: u8,
    pub gpu_object_id: u16,
}

impl fmt::Debug for DisplayPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DisplayPath")
            .field("device_tag", &self.device_tag)
            .field("connector", &self.connector_kind)
            .field("index", &self.connector_index)
            .field("gpu_obj", &self.gpu_object_id)
            .finish()
    }
}

/// One link in the per-path object chain. Each path entry's 8-byte header is
/// followed by a list of intermediate object ids, the chain terminating with a
/// sentinel object id of `0`.
///
/// An object id packs three fields (`displayobject.h`): the **object type** in
/// bits 15:12, an enum id in bits 11:8, and the object's own id in bits 7:0.
#[derive(Copy, Clone, Debug)]
pub struct ObjectLink {
    /// Object type, bits 15:12 — a `GRAPH_OBJECT_TYPE_*` value.
    pub kind: u8,
    /// Enum id, bits 11:8: which instance of this object type.
    pub enum_id: u8,
    /// The object's own id, bits 7:0 — e.g. an `ENCODER_OBJECT_ID_*` when the
    /// type is `GRAPH_OBJECT_TYPE_ENCODER`.
    pub instance: u8,
}

/// `GRAPH_OBJECT_TYPE_*` from `ObjectID.h`, the values that go in bits 15:12.
///
/// LINUX-GAP: the constants that stood here were `ATOM_OBJECT_TYPE_ENCODER =
/// 0x21`, `_TRANSMITTER = 0x22`, `_CLOCK_SRC = 0x23`, `_ROUTER = 0x12`,
/// described as "bits[15:8] of the object id". No `ATOM_OBJECT_TYPE_*` exists
/// anywhere in the AMD tree. The type field is four bits at 12, not a byte at
/// 8, and its value space is 0..7 — so a comparison against 0x21 can never
/// match. There are also no "transmitter" or "clock source" object types:
/// those are object *ids* within the encoder type. 0x21 and 0x22 happen to be
/// `ENCODER_OBJECT_ID_*` values from a different field entirely.
pub const GRAPH_OBJECT_TYPE_NONE: u8 = 0x0;
pub const GRAPH_OBJECT_TYPE_GPU: u8 = 0x1;
pub const GRAPH_OBJECT_TYPE_ENCODER: u8 = 0x2;
pub const GRAPH_OBJECT_TYPE_CONNECTOR: u8 = 0x3;
pub const GRAPH_OBJECT_TYPE_ROUTER: u8 = 0x4;
pub const GRAPH_OBJECT_TYPE_DISPLAY_PATH: u8 = 0x6;
pub const GRAPH_OBJECT_TYPE_GENERIC: u8 = 0x7;

/// `displayobject.h`'s `enum object_id_bit`.
pub const OBJECT_ID_MASK: u16 = 0x00FF;
pub const ENUM_ID_MASK: u16 = 0x0F00;
pub const ENUM_ID_SHIFT: u32 = 8;
pub const OBJECT_TYPE_MASK: u16 = 0xF000;
pub const OBJECT_TYPE_SHIFT: u32 = 12;

impl ObjectLink {
    /// Split a raw object id into its three fields.
    pub fn from_raw(objid: u16) -> Self {
        Self {
            kind: ((objid & OBJECT_TYPE_MASK) >> OBJECT_TYPE_SHIFT) as u8,
            enum_id: ((objid & ENUM_ID_MASK) >> ENUM_ID_SHIFT) as u8,
            instance: (objid & OBJECT_ID_MASK) as u8,
        }
    }
    pub fn is_encoder(self) -> bool {
        self.kind == GRAPH_OBJECT_TYPE_ENCODER
    }
    pub fn is_connector(self) -> bool {
        self.kind == GRAPH_OBJECT_TYPE_CONNECTOR
    }
    pub fn is_router(self) -> bool {
        self.kind == GRAPH_OBJECT_TYPE_ROUTER
    }
}

/// Iterator surface over the path table.
#[derive(Debug)]
pub struct DisplayObjectTable<'a> {
    raw: &'a [u8],
    n_paths: usize,
    /// Walking offset within `raw` for the next `next()` call.
    cursor: usize,
}

impl<'a> DisplayObjectTable<'a> {
    /// Parse the table directory. Caller obtains the slice via
    /// `Atombios::data_table(0x05)`.
    pub fn parse(raw: &'a [u8]) -> Result<Self, DisplayObjError> {
        if raw.len() < 8 {
            return Err(DisplayObjError::Truncated);
        }
        let format_revision = raw[2];
        if format_revision == 0 || format_revision > 2 {
            return Err(DisplayObjError::UnsupportedVersion(format_revision));
        }
        let n_paths = raw[6] as usize;
        // Minimum size = 8 byte header + n_paths * 8 byte path entries.
        if raw.len() < 8 + n_paths * 8 {
            return Err(DisplayObjError::Truncated);
        }
        Ok(Self {
            raw,
            n_paths,
            cursor: 8,
        })
    }

    /// Number of paths the table claims.
    pub fn path_count(&self) -> usize {
        self.n_paths
    }

    /// Bitmap of supported display kinds (`usDeviceSupport`).
    pub fn device_support_bitmap(&self) -> u16 {
        u16::from_le_bytes([self.raw[4], self.raw[5]])
    }

    /// Reset the iterator's cursor to the first path.
    pub fn rewind(&mut self) {
        self.cursor = 8;
    }

    /// Iterate the object-chain links following the 8-byte path
    /// header at `path_off`. Each path's chain is a sequence of
    /// 16-bit object ids terminated by a `0` sentinel. Returns
    /// an iterator borrowing from the underlying table.
    ///
    /// `path_off` is the offset of the path header (i.e. value
    /// of the iterator's `cursor` BEFORE the most recent `next`).
    /// The chain starts at `path_off + 8` and continues until
    /// either the sentinel or the path's `usSize` bound.
    pub fn chain_at<'b>(&'b self, path_off: usize, path_size: usize) -> ObjectLinkIter<'b> {
        let start = path_off + 8;
        let end = (path_off + path_size).min(self.raw.len());
        ObjectLinkIter {
            raw: self.raw,
            cursor: start,
            end,
        }
    }
}

/// Iterator over an object chain. Yields one `ObjectLink` per
/// 16-bit id, stopping at the first `0` id or at `end`.
#[derive(Debug)]
pub struct ObjectLinkIter<'a> {
    raw: &'a [u8],
    cursor: usize,
    end: usize,
}

impl<'a> Iterator for ObjectLinkIter<'a> {
    type Item = ObjectLink;
    fn next(&mut self) -> Option<ObjectLink> {
        if self.cursor + 2 > self.end {
            return None;
        }
        let id = u16::from_le_bytes([self.raw[self.cursor], self.raw[self.cursor + 1]]);
        self.cursor += 2;
        if id == 0 {
            return None;
        }
        Some(ObjectLink::from_raw(id))
    }
}

impl<'a> Iterator for DisplayObjectTable<'a> {
    type Item = DisplayPath;
    fn next(&mut self) -> Option<DisplayPath> {
        let paths_end = 8 + self.n_paths * 8;
        if self.cursor >= paths_end {
            return None;
        }
        if self.cursor + 8 > self.raw.len() {
            return None;
        }
        let off = self.cursor;
        let device_tag = u16::from_le_bytes([self.raw[off], self.raw[off + 1]]);
        let _size = u16::from_le_bytes([self.raw[off + 2], self.raw[off + 3]]);
        let conn_obj_id = u16::from_le_bytes([self.raw[off + 4], self.raw[off + 5]]);
        let gpu_obj_id = u16::from_le_bytes([self.raw[off + 6], self.raw[off + 7]]);
        self.cursor += 8;
        // LINUX-GAP: these two were the other way round — the connector kind
        // was decoded from the high byte and the index from the low. The
        // object's own id is bits **7:0** and the enum id (which instance of
        // that connector type) is bits 11:8, so a DisplayPort connector
        // (0x3113) read as kind 0x31 and index 0x13.
        let link = ObjectLink::from_raw(conn_obj_id);
        let connector_kind = ConnectorKind::from_object_enum(link.instance);
        let connector_index = link.enum_id;
        Some(DisplayPath {
            device_tag,
            connector_kind,
            connector_index,
            gpu_object_id: gpu_obj_id,
        })
    }
}

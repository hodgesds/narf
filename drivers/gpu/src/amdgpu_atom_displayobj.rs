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
    Dsi,
    Unknown(u8),
}

impl ConnectorKind {
    fn from_object_enum(id: u8) -> Self {
        match id {
            0x13 => ConnectorKind::Dp,
            0x14 => ConnectorKind::Edp,
            0x0C => ConnectorKind::HdmiA,
            0x0D => ConnectorKind::HdmiB,
            0x02 => ConnectorKind::DviI,
            0x03 => ConnectorKind::DviD,
            0x01 => ConnectorKind::Vga,
            0x0E => ConnectorKind::Lvds,
            0x15 => ConnectorKind::Dsi,
            other => ConnectorKind::Unknown(other),
        }
    }
}

/// One connector path entry from the ATOM table.
#[derive(Copy, Clone)]
pub struct DisplayPath {
    pub device_tag:       u16,
    pub connector_kind:   ConnectorKind,
    pub connector_index:  u8,
    pub gpu_object_id:    u16,
}

impl fmt::Debug for DisplayPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DisplayPath")
            .field("device_tag", &self.device_tag)
            .field("connector",  &self.connector_kind)
            .field("index",      &self.connector_index)
            .field("gpu_obj",    &self.gpu_object_id)
            .finish()
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
        if raw.len() < 8 { return Err(DisplayObjError::Truncated); }
        let format_revision = raw[2];
        if format_revision == 0 || format_revision > 2 {
            return Err(DisplayObjError::UnsupportedVersion(format_revision));
        }
        let n_paths = raw[6] as usize;
        // Minimum size = 8 byte header + n_paths * 8 byte path entries.
        if raw.len() < 8 + n_paths * 8 {
            return Err(DisplayObjError::Truncated);
        }
        Ok(Self { raw, n_paths, cursor: 8 })
    }

    /// Number of paths the table claims.
    pub fn path_count(&self) -> usize { self.n_paths }

    /// Bitmap of supported display kinds (`usDeviceSupport`).
    pub fn device_support_bitmap(&self) -> u16 {
        u16::from_le_bytes([self.raw[4], self.raw[5]])
    }

    /// Reset the iterator's cursor to the first path.
    pub fn rewind(&mut self) { self.cursor = 8; }
}

impl<'a> Iterator for DisplayObjectTable<'a> {
    type Item = DisplayPath;
    fn next(&mut self) -> Option<DisplayPath> {
        let paths_end = 8 + self.n_paths * 8;
        if self.cursor >= paths_end { return None; }
        if self.cursor + 8 > self.raw.len() { return None; }
        let off = self.cursor;
        let device_tag    = u16::from_le_bytes([self.raw[off],     self.raw[off + 1]]);
        let _size         = u16::from_le_bytes([self.raw[off + 2], self.raw[off + 3]]);
        let conn_obj_id   = u16::from_le_bytes([self.raw[off + 4], self.raw[off + 5]]);
        let gpu_obj_id    = u16::from_le_bytes([self.raw[off + 6], self.raw[off + 7]]);
        self.cursor += 8;
        let connector_kind = ConnectorKind::from_object_enum(
            ((conn_obj_id >> 8) & 0xFF) as u8,
        );
        let connector_index = (conn_obj_id & 0xFF) as u8;
        Some(DisplayPath {
            device_tag,
            connector_kind,
            connector_index,
            gpu_object_id: gpu_obj_id,
        })
    }
}

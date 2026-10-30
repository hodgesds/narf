//! Optional CONNAC2 WM release-feature receipt (next CNM batch).
//! Linux mt792x_core.c::mt792x_get_offload_capability. Offsets come from
//! validated region extents; arbitrary firmware bytes never grant authority.
use super::fwdl;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Header,
    Extent,
    Duplicate,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Features(u8);
impl Features {
    pub fn cnm(self) -> bool {
        self.0 & (1 << 7) != 0
    }
    pub fn nan(self) -> bool {
        self.0 & (1 << 5) != 0
    }
}
/// Absent optional release metadata differs from malformed metadata. A
/// caller may keep legacy boot operation, but neither case implies CNM.
pub(super) fn parse(ram: &[u8]) -> Result<Option<Features>, Error> {
    let tail = fwdl::parse_fw_trailer(ram).map_err(|_| Error::Header)?;
    if tail.n_region == 0 || tail.n_region > 64 {
        return Err(Error::Header);
    }
    let table = ram
        .len()
        .checked_sub(fwdl::FW_TRAILER_SIZE + usize::from(tail.n_region) * fwdl::FW_REGION_SIZE)
        .ok_or(Error::Extent)?;
    let mut payload = 0usize;
    for region in fwdl::iter_fw_regions(ram, &tail).map_err(|_| Error::Header)? {
        payload = payload
            .checked_add(region.map_err(|_| Error::Header)?.len as usize)
            .ok_or(Error::Extent)?;
        if payload > table {
            return Err(Error::Extent);
        }
    }
    if payload == table {
        return Ok(None);
    }
    let release = payload.checked_add(16).ok_or(Error::Extent)?;
    let header = ram
        .get(release..release.checked_add(4).ok_or(Error::Extent)?)
        .filter(|_| release + 4 <= table)
        .ok_or(Error::Extent)?;
    let start = release + 4;
    let end = start
        .checked_add(usize::from(u16::from_le_bytes([header[0], header[1]])))
        .filter(|end| *end <= table)
        .ok_or(Error::Extent)?;
    let mut cursor = start;
    let mut features = None;
    while cursor < end {
        let header = ram
            .get(cursor..cursor + 4)
            .filter(|_| cursor + 4 <= end)
            .ok_or(Error::Extent)?;
        cursor += 4;
        let length = usize::from(u16::from_le_bytes([header[0], header[1]]));
        let next = cursor
            .checked_add(length)
            .filter(|next| *next <= end)
            .ok_or(Error::Extent)?;
        if header[3] == 4 {
            if length != 16 {
                return Err(Error::Extent);
            }
            if features.is_some() {
                return Err(Error::Duplicate);
            }
            features = Some(Features(ram[cursor + 1]));
        }
        cursor = next
            .checked_add(usize::from(header[2]))
            .filter(|next| *next <= end)
            .ok_or(Error::Extent)?;
    }
    Ok(features)
}

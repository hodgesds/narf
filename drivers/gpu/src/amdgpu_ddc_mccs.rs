//! VESA DDC/CI1.1 §§4.1,4.3–4.6,6.3: framed capabilities/get/set.
//! AMD's vendor FreeSync VCP contract is dm_helpers_read_mccs_caps and
//! dm_helpers_mccs_vcp_set: current bit0 support; set0x0101 enables it.
//! The caller retains its DDC claim throughout every request and wait.
use super::Error;
use crate::amdgpu_freesync::{AmdVsdb, VrrRange};
use alloc::vec::Vec;
use core::future::Future;

const MAX_CAPS: usize = 1024;
const MAX_REPLY: usize = 38;
const ATTEMPTS: usize = 3;
pub(crate) trait Bus {
    fn write(&mut self, bytes: &mut [u8]) -> impl Future<Output = Result<(), Error>> + Send;
    fn read(&mut self, bytes: &mut [u8]) -> impl Future<Output = Result<(), Error>> + Send;
    fn delay(&mut self, us: u64) -> impl Future<Output = ()> + Send;
}
/// Immutable result of a complete exchange for one fresh sink discovery.
/// Neither an EDID VCP code nor a successful set write constructs this proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Negotiated {
    generation: u64,
    metadata: AmdVsdb,
}
impl Negotiated {
    pub fn range(self, generation: u64, metadata: AmdVsdb) -> Option<VrrRange> {
        (generation != 0 && generation == self.generation && metadata == self.metadata).then_some(
            VrrRange {
                min_hz: metadata.min_hz,
                max_hz: metadata.max_hz,
            },
        )
    }
}
fn request(payload: &[u8]) -> ([u8; 7], usize) {
    let mut b = [0; 7];
    b[0] = 0x51;
    b[1] = 0x80 | payload.len() as u8;
    b[2..2 + payload.len()].copy_from_slice(payload);
    let last = 2 + payload.len();
    b[last] = b[..last].iter().fold(0x6e, |sum, b| sum ^ b);
    (b, last + 1)
}
fn reply(bytes: &[u8]) -> Result<&[u8], Error> {
    if bytes.len() < 3 || bytes[0] != 0x6e || bytes[1] & 0x80 == 0 {
        return Err(Error::InvalidMccs);
    }
    let n = usize::from(bytes[1] & 0x7f);
    let end = n + 3;
    if n > 35 || end > bytes.len() || bytes[..end].iter().fold(0x50, |sum, b| sum ^ b) != 0 {
        return Err(Error::InvalidMccs);
    }
    Ok(&bytes[2..2 + n])
}
async fn exchange(
    bus: &mut impl Bus,
    payload: &[u8],
    length: usize,
    wait_us: u64,
) -> Result<Vec<u8>, Error> {
    for attempt in 0..ATTEMPTS {
        let (mut bytes, n) = request(payload);
        let result = async {
            bus.write(&mut bytes[..n]).await?;
            bus.delay(wait_us).await;
            let mut bytes = [0; MAX_REPLY];
            bus.read(&mut bytes[..length]).await?;
            let payload = reply(&bytes[..length])?;
            if payload.is_empty() {
                return Err(Error::MccsUnsupported);
            }
            let mut out = Vec::new();
            out.try_reserve_exact(payload.len())
                .map_err(|_| Error::Allocation)?;
            out.extend_from_slice(payload);
            Ok(out)
        }
        .await;
        // A completed bus command is terminal even if the message was bad.
        // An uncertain hardware completion is never retried or released.
        match result {
            Err(Error::Nack | Error::InvalidMccs | Error::MccsUnsupported)
                if attempt + 1 < ATTEMPTS =>
            {
                bus.delay(50_000).await
            }
            result => {
                if result.is_ok() {
                    bus.delay(50_000).await;
                }
                return result;
            }
        }
    }
    unreachable!()
}
fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
fn vcp_list(bytes: &[u8], wanted: u8) -> Result<bool, Error> {
    let mut i = 0;
    let mut found = false;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let code = hex(bytes[i])
            .zip(bytes.get(i + 1).copied().and_then(hex))
            .map(|(h, l)| h << 4 | l)
            .ok_or(Error::InvalidMccs)?;
        i += 2;
        found |= code == wanted;
        if bytes.get(i) == Some(&b'(') {
            i += 1;
            // Values may themselves be structured vendor data. Only the
            // outer feature code establishes support; no code found inside
            // a value list may authorize this operation.
            let mut depth = 1;
            while depth != 0 {
                match bytes.get(i) {
                    Some(b'(') => depth += 1,
                    Some(b')') => depth -= 1,
                    Some(_) => {}
                    None => return Err(Error::InvalidMccs),
                }
                i += 1;
            }
        }
    }
    Ok(found)
}
fn advertises_vcp(bytes: &[u8], wanted: u8) -> Result<bool, Error> {
    if bytes.is_empty()
        || bytes
            .iter()
            .any(|b| !b.is_ascii_graphic() && !b.is_ascii_whitespace())
    {
        return Err(Error::InvalidMccs);
    }
    let bytes = if bytes.first() == Some(&b'(') && bytes.last() == Some(&b')') {
        &bytes[1..bytes.len() - 1]
    } else {
        bytes
    };
    let mut i = 0;
    let mut found = false;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        while bytes
            .get(i)
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
        {
            i += 1;
        }
        if start == i || bytes.get(i) != Some(&b'(') {
            return Err(Error::InvalidMccs);
        }
        let key = &bytes[start..i];
        i += 1;
        let start = i;
        let mut depth = 1;
        while depth != 0 {
            match bytes.get(i) {
                Some(b'(') => depth += 1,
                Some(b')') => depth -= 1,
                Some(_) => {}
                None => return Err(Error::InvalidMccs),
            }
            i += 1;
        }
        if key.eq_ignore_ascii_case(b"vcp") {
            found |= vcp_list(&bytes[start..i - 1], wanted)?;
        }
    }
    Ok(found)
}
async fn capabilities(bus: &mut impl Bus, code: u8) -> Result<(), Error> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(MAX_CAPS)
        .map_err(|_| Error::Allocation)?;
    loop {
        let offset = u16::try_from(bytes.len()).map_err(|_| Error::InvalidMccs)?;
        let [hi, lo] = offset.to_be_bytes();
        let part = exchange(bus, &[0xf3, hi, lo], MAX_REPLY, 50_000).await?;
        if part.len() < 3 || part[0] != 0xe3 || part[1..3] != [hi, lo] {
            return Err(Error::InvalidMccs);
        }
        let data = &part[3..];
        if data.is_empty() {
            break;
        }
        if bytes.len() + data.len() > MAX_CAPS {
            return Err(Error::InvalidMccs);
        }
        bytes.extend_from_slice(data);
    }
    // DDC/CI ends the transfer with an empty fragment, not a C-string
    // marker. Keep every wire byte in offset accounting, then match
    // ddcutil get_capabilities_into_buffer's trailing blank/NUL trimming.
    // Interior NUL remains invalid; it cannot hide a second expression.
    while bytes.last().is_some_and(|b| *b == b' ' || *b == 0) {
        bytes.pop();
    }
    if advertises_vcp(&bytes, code)? {
        Ok(())
    } else {
        Err(Error::MccsUnsupported)
    }
}
async fn get(bus: &mut impl Bus, code: u8) -> Result<u16, Error> {
    let p = exchange(bus, &[1, code], 11, 40_000).await?;
    if p.len() != 8 || p[0] != 2 || p[2] != code || p[3] != 0 {
        return Err(Error::InvalidMccs);
    }
    match p[1] {
        0 => Ok(u16::from_be_bytes([p[6], p[7]])),
        1 => Err(Error::MccsUnsupported),
        _ => Err(Error::InvalidMccs),
    }
}
pub(crate) async fn negotiate(
    bus: &mut impl Bus,
    generation: u64,
    metadata: AmdVsdb,
) -> Result<Negotiated, Error> {
    if generation == 0
        || metadata.vcp_code == 0
        || metadata.min_hz == 0
        || metadata.max_hz.saturating_sub(metadata.min_hz)
            <= crate::amdgpu_freesync::MIN_REFRESH_RANGE_HZ as u16
    {
        return Err(Error::MccsUnsupported);
    }
    // A successor after GPU reset cannot infer remote display processing
    // from the local I2C reset. Honor the command interval before its first
    // packet, then establish support again through fresh replies.
    bus.delay(50_000).await;
    capabilities(bus, metadata.vcp_code).await?;
    if get(bus, metadata.vcp_code).await? & 1 == 0 {
        return Err(Error::MccsUnsupported);
    }
    let (mut b, n) = request(&[3, metadata.vcp_code, 1, 1]);
    for attempt in 0..ATTEMPTS {
        match bus.write(&mut b[..n]).await {
            Err(Error::Nack) if attempt + 1 < ATTEMPTS => bus.delay(50_000).await,
            result => {
                result?;
                break;
            }
        }
    }
    bus.delay(50_000).await;
    // Linux establishes support bit0 and Set0x0101, not a separate vendor
    // enable-readback bit. Require an exact whole-value echo conservatively;
    // a sink which does not echo the setting stays at fixed refresh.
    if get(bus, metadata.vcp_code).await? != 0x0101 {
        return Err(Error::MccsUnsupported);
    }
    Ok(Negotiated {
        generation,
        metadata,
    })
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_ddc_mccs_tests.rs"]
pub(crate) mod tests;

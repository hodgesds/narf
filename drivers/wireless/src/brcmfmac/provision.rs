// SPDX-License-Identifier: GPL-2.0-or-later
//! Signed deployment board selection. A chip filename is never board authority.
//! NBSP v1 binds immutable host/card facts to exact registry payloads. It grants
//! no clocks, GPIOs, regulators, PCI rights or firmware protocol extensions.
use alloc::{string::String, sync::Arc, vec::Vec};
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_drivers_sdio::pio::HostIdentity;
use narf_firmware::{FirmwareBlob, FirmwareRegistry};
pub const MANIFEST: &str = "brcm/wifi-board-selection-v1.bin";
const HEADER: usize = 16;
const RECORD: usize = 616;
const ASSET: usize = 168;
const MAX_RECORDS: usize = 16;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Pcie43602,
    Sdio43439,
    /// NBSP family 3: another `chip_profile` PCIe chip (CR4 or CA7).
    PcieFullmac,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Access,
    Missing,
    Unsigned,
    Invalid,
    Ambiguous,
    Mismatch,
    Stale,
    Memory,
}
#[derive(Clone, Debug)]
struct Asset {
    role: u8,
    signed: bool,
    key: String,
    length: usize,
    sha256: [u8; 32],
}
#[derive(Clone, Debug)]
struct Receipt {
    cap: Cap<FirmwareBlob, Read>,
    key: String,
    length: usize,
    signer: Option<[u8; 32]>,
    registry_digest: [u8; 32],
}
/// Current source instances remain tied to the immutable payloads selected
/// at bootstrap. Hot replacement preserves these pinned bytes under the
/// registry contract; actual cap revocation fails before later bus access.
#[derive(Debug)]
pub(crate) struct Proof {
    receipts: Vec<Receipt>,
}
impl Proof {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        for receipt in &self.receipts {
            receipt
                .cap
                .invoke(Check(receipt))
                .map_err(|_| Error::Stale)??;
        }
        Ok(())
    }
}
struct Check<'a>(&'a Receipt);
impl CapOp<FirmwareBlob, Read> for Check<'_> {
    type Output = Result<(), Error>;
    fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
        Ok(narf_firmware::view_of(cap)
            .map_err(|_| Error::Stale)
            .and_then(|view| {
                if view.name == self.0.key
                    && view.bytes.len() == self.0.length
                    && view.signer == self.0.signer
                    && view.sha256 == self.0.registry_digest
                {
                    Ok(())
                } else {
                    Err(Error::Stale)
                }
            }))
    }
}
#[derive(Debug)]
pub struct Selection {
    family: Family,
    host: HostIdentity,
    chip: u16,
    revisions: u16,
    function: u8,
    card_vendor: u16,
    card_device: u16,
    board: String,
    /// Family 3 OTP chips: Linux's `settings->antenna_sku` (bytes 96..112);
    /// `board` is then Linux's `settings->board_type`.
    antenna_sku: Option<String>,
    /// Family 3: the `brcmf_pcie_fwnames` base every revision selects.
    base: Option<&'static str>,
    assets: Vec<Asset>,
    source: Option<Receipt>,
}
impl Selection {
    pub fn board(&self) -> &str {
        &self.board
    }
    pub fn family(&self) -> Family {
        self.family
    }
    pub(crate) fn revisions(&self) -> u16 {
        self.revisions
    }
    pub(crate) fn host(&self) -> HostIdentity {
        self.host
    }
    pub(crate) fn admits_chip(&self, chip: u16, revision: u8) -> bool {
        chip == self.chip && revision < 16 && self.revisions & (1 << revision) != 0
    }
    /// The OTP read at claim (`brcmf_pcie_read_otp`) against the record.
    /// A chip Linux reads no OTP for needs none and a record without an
    /// antenna SKU. An OTP chip needs a valid OTP, and the record's keys
    /// must be Linux `board_types` (`brcmf_pcie_prepare_fw_request`'s Apple
    /// selection) for that OTP: NVRAM one of `board_types[0..=3]` (each
    /// carries the OTP module), the executable any of `[0..=5]` or plain.
    pub(crate) fn admits_otp(
        &self,
        chip: u16,
        otp: Option<&super::chip_profile::OtpParams>,
    ) -> bool {
        use super::chip_profile::{apple_board_types, asset_board, linux_reads_otp};
        match (&self.antenna_sku, self.base, otp) {
            (None, _, None) => !linux_reads_otp(chip),
            (Some(sku), Some(base), Some(otp)) if linux_reads_otp(chip) => {
                let types = apple_board_types(&self.board, otp, sku);
                asset_board(base, &self.assets[1].key, "txt")
                    .is_some_and(|b| types[..4].iter().any(|t| t == b))
                    && asset_board(base, &self.assets[0].key, "bin")
                        .is_none_or(|b| types.iter().any(|t| t == b))
            }
            _ => false,
        }
    }
    pub fn load(&self) -> Result<Assets, Error> {
        self.load_using(&authority()?)
    }
    pub(crate) fn load_using(
        &self,
        authority: &Cap<FirmwareRegistry, Read>,
    ) -> Result<Assets, Error> {
        let mut receipts = Vec::new();
        receipts.try_reserve_exact(4).map_err(|_| Error::Memory)?;
        if let Some(source) = &self.source {
            source
                .cap
                .invoke(Check(source))
                .map_err(|_| Error::Stale)??;
            receipts.push(source.clone());
        }
        let mut bodies = Vec::new();
        bodies
            .try_reserve_exact(self.assets.len())
            .map_err(|_| Error::Memory)?;
        for asset in &self.assets {
            let (body, receipt) = read_using(authority, &asset.key, Some(asset), asset.signed)?;
            bodies.push(body);
            receipts.push(receipt);
        }
        let mut bodies = bodies.into_iter();
        let result = Assets {
            firmware: bodies.next().ok_or(Error::Invalid)?,
            nvram: bodies.next().ok_or(Error::Invalid)?,
            clm: bodies.next().unwrap_or_default(),
            proof: Arc::new(Proof { receipts }),
        };
        executable_shape(self.family, result.firmware.len())?;
        result.proof.validate()?;
        Ok(result)
    }
}
#[derive(Debug)]
pub struct Assets {
    pub(crate) firmware: Vec<u8>,
    pub(crate) nvram: Vec<u8>,
    pub(crate) clm: Vec<u8>,
    pub(crate) proof: Arc<Proof>,
}
struct Open<'a>(&'a str);
impl CapOp<FirmwareRegistry, Read> for Open<'_> {
    type Output = Result<Cap<FirmwareBlob, Read>, narf_firmware::FirmwareError>;
    fn execute(self, cap: &Cap<FirmwareRegistry, Read>) -> Result<Self::Output, CapError> {
        Ok(narf_firmware::open(self.0, cap))
    }
}
struct CopyBlob<'a> {
    key: &'a str,
    asset: Option<&'a Asset>,
    signed: bool,
}
impl CapOp<FirmwareBlob, Read> for CopyBlob<'_> {
    type Output = Result<(Vec<u8>, Receipt), Error>;
    fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
        Ok((|| {
            let view = narf_firmware::view_of(cap).map_err(|_| Error::Access)?;
            if view.name != self.key || view.bytes.is_empty() || view.bytes.len() > 16 * 1024 * 1024
            {
                return Err(Error::Mismatch);
            }
            if self.signed && view.signer.is_none() {
                return Err(Error::Unsigned);
            }
            if self.asset.is_none()
                && self.signed
                && view.bytes.len() > super::firmware::NVRAM_MAX_SIZE
            {
                return Err(Error::Invalid);
            }
            if let Some(asset) = self.asset {
                let mut digest = narf_crypto::sha256::Sha256::new();
                digest.update(view.bytes);
                if view.bytes.len() != asset.length || digest.finalize() != asset.sha256 {
                    return Err(Error::Mismatch);
                }
            }
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(view.bytes.len())
                .map_err(|_| Error::Memory)?;
            bytes.extend_from_slice(view.bytes);
            Ok((
                bytes,
                Receipt {
                    cap: *cap,
                    key: self.key.into(),
                    length: view.bytes.len(),
                    signer: view.signer,
                    registry_digest: view.sha256,
                },
            ))
        })())
    }
}
pub(crate) fn authority() -> Result<Cap<FirmwareRegistry, Read>, Error> {
    narf_firmware::trusted_loader_authority()
        .and_then(|cap| cap.derive::<Read>().ok())
        .ok_or(Error::Access)
}
fn read(key: &str, asset: Option<&Asset>, signed: bool) -> Result<(Vec<u8>, Receipt), Error> {
    read_using(&authority()?, key, asset, signed)
}
fn read_using(
    authority: &Cap<FirmwareRegistry, Read>,
    key: &str,
    asset: Option<&Asset>,
    signed: bool,
) -> Result<(Vec<u8>, Receipt), Error> {
    let cap = authority
        .invoke(Open(key))
        .map_err(|_| Error::Access)?
        .map_err(|_| Error::Missing)?;
    cap.invoke(CopyBlob { key, asset, signed })
        .map_err(|_| Error::Access)?
}
/// Trusted compiled platform registration remains an explicit board policy.
/// Its NVRAM still requires a verified signer; executable unsigned policy is
/// solely the existing firmware registry/build decision.
pub(super) fn trusted_assets(firmware: &str, nvram: &str) -> Result<Assets, Error> {
    trusted_assets_using(&authority()?, firmware, nvram)
}
pub(super) fn trusted_assets_using(
    authority: &Cap<FirmwareRegistry, Read>,
    firmware: &str,
    nvram: &str,
) -> Result<Assets, Error> {
    let (firmware, fw) = read_using(authority, firmware, None, false)?;
    executable_shape(Family::Pcie43602, firmware.len())?;
    let (nvram, nv) = read_using(authority, nvram, None, true)?;
    let proof = Arc::new(Proof {
        receipts: alloc::vec![fw, nv],
    });
    proof.validate()?;
    Ok(Assets {
        firmware,
        nvram,
        clm: Vec::new(),
        proof,
    })
}
pub fn select(
    family: Family,
    host: HostIdentity,
    card: Option<(u8, u16, u16)>,
) -> Result<Selection, Error> {
    select_using(&authority()?, MANIFEST, family, host, card)
}
pub(crate) fn select_using(
    authority: &Cap<FirmwareRegistry, Read>,
    name: &str,
    family: Family,
    host: HostIdentity,
    card: Option<(u8, u16, u16)>,
) -> Result<Selection, Error> {
    let (bytes, source) = read_using(authority, name, None, true)?;
    let mut records = parse(&bytes)?;
    let matching = |record: &Selection| {
        record.family == family
            && record.host == host
            && match card {
                Some((function, vendor, device)) => {
                    record.function == function
                        && record.card_vendor == vendor
                        && record.card_device == device
                }
                None => record.function == 0,
            }
    };
    let mut found = None;
    for record in records.drain(..) {
        if matching(&record) {
            if found.is_some() {
                return Err(Error::Ambiguous);
            }
            found = Some(record);
        }
    }
    let mut result = found.ok_or(Error::Mismatch)?;
    result.source = Some(source);
    Ok(result)
}
fn half(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}
fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn string(bytes: &[u8], key: bool) -> Result<String, Error> {
    string_with(bytes, key, false)
}
/// `comma`: Linux board types (`apple,<board>`) for family 3 OTP chips.
fn string_with(bytes: &[u8], key: bool, comma: bool) -> Result<String, Error> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(Error::Invalid)?;
    if end == 0
        || bytes[end..].iter().any(|byte| *byte != 0)
        || !bytes[..end].iter().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'-' | b'.')
                || key && *byte == b'/'
                || comma && *byte == b','
        })
    {
        return Err(Error::Invalid);
    }
    let text = core::str::from_utf8(&bytes[..end]).map_err(|_| Error::Invalid)?;
    if key
        && (text.starts_with('/')
            || text
                .split('/')
                .any(|part| part.is_empty() || matches!(part, "." | "..")))
    {
        return Err(Error::Invalid);
    }
    Ok(text.into())
}
/// Only shape known without touching cores: actual RAM/firmware compatibility
/// still belongs to the discovered retained loader, never a guessed capacity.
fn executable_shape(family: Family, length: usize) -> Result<(), Error> {
    if length == 0
        || match family {
            Family::Pcie43602 | Family::PcieFullmac => length < 4,
            Family::Sdio43439 => length > crate::cyw43439::firmware::MAX_IMAGE_SIZE,
        }
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn parse_asset(bytes: &[u8], role: u8, comma: bool) -> Result<Asset, Error> {
    if bytes[0] != role || bytes[1] & !1 != 0 || half(bytes, 2) != 0 || role != 1 && bytes[1] != 1 {
        return Err(Error::Invalid);
    }
    let length = word(bytes, 4) as usize;
    if length == 0
        || length > 16 * 1024 * 1024
        || role == 2 && length > super::firmware::NVRAM_MAX_SIZE
        || bytes[8..40] == [0; 32]
    {
        return Err(Error::Invalid);
    }
    Ok(Asset {
        role,
        signed: bytes[1] != 0,
        key: string_with(&bytes[40..168], true, comma)?,
        length,
        sha256: bytes[8..40].try_into().unwrap(),
    })
}
/// Family 3 admission from the Linux tables: a covered chip, a PCI identity
/// `brcmf_pcie_devid_table` binds with an implemented vendor (WCC/BCA,
/// seeded or not), and one `brcmf_pcie_fwnames` row for every revision in the
/// record's mask. Returns that row's firmware base name.
fn fullmac_firmware(
    chip: u16,
    revisions: u16,
    host: &narf_bus::DeviceId,
) -> Result<&'static str, Error> {
    let mut base = None;
    for revision in (0..16u8).filter(|r| revisions & (1 << r) != 0) {
        let (profile, _) =
            super::chip_profile::admit(chip, revision, host).ok_or(Error::Invalid)?;
        if base.is_some_and(|b| b != profile.firmware.base) {
            return Err(Error::Invalid);
        }
        base = Some(profile.firmware.base);
    }
    base.ok_or(Error::Invalid)
}
fn parse(bytes: &[u8]) -> Result<Vec<Selection>, Error> {
    if bytes.len() < HEADER
        || &bytes[..4] != b"NBSP"
        || half(bytes, 4) != 1
        || usize::from(half(bytes, 6)) != HEADER
        || word(bytes, 8) as usize != bytes.len()
        || usize::from(half(bytes, 14)) != RECORD
    {
        return Err(Error::Invalid);
    }
    let count = usize::from(half(bytes, 12));
    if count == 0 || count > MAX_RECORDS || bytes.len() != HEADER + count * RECORD {
        return Err(Error::Invalid);
    }
    let mut records: Vec<Selection> = Vec::new();
    records
        .try_reserve_exact(count)
        .map_err(|_| Error::Memory)?;
    for raw in bytes[HEADER..].chunks_exact(RECORD) {
        let (family, chip) = match raw[0] {
            1 => (Family::Pcie43602, 43602),
            2 => (Family::Sdio43439, 43439),
            // BCM43602 keeps its own family; others name the actual chip.
            3 if half(raw, 2) != 43602 => (Family::PcieFullmac, half(raw, 2)),
            _ => return Err(Error::Invalid),
        };
        // Family 3 OTP chips carry the Linux antenna SKU in 96..112.
        let otp = family == Family::PcieFullmac && super::chip_profile::linux_reads_otp(chip);
        if half(raw, 2) != chip
            || half(raw, 4) == 0
            || raw[7] != 0
            || !otp && raw[96..112] != [0; 16]
        {
            return Err(Error::Invalid);
        }
        let address = u64::from_le_bytes(raw[8..16].try_into().unwrap());
        let address = match raw[6] {
            1 => {
                if address >> 40 != 0 || address & 255 > 7 || address >> 8 & 255 > 31 {
                    return Err(Error::Invalid);
                }
                narf_bus::BusAddr::Pcie(narf_bus::PcieAddr::new(
                    (address >> 24) as u16,
                    (address >> 16) as u8,
                    (address >> 8) as u8,
                    address as u8,
                ))
            }
            2 if family == Family::Sdio43439 && address != 0 && address & 3 == 0 => {
                narf_bus::BusAddr::Mmio(narf_memory::PhysAddr::new(address))
            }
            _ => return Err(Error::Invalid),
        };
        let host = HostIdentity {
            address,
            id: narf_bus::DeviceId {
                vendor: half(raw, 16),
                device: half(raw, 18),
                subsystem_vendor: half(raw, 20),
                subsystem_id: half(raw, 22),
                class: word(raw, 24),
            },
        };
        if family == Family::Pcie43602
            && (host.id.vendor != 0x14e4
                || !matches!(host.id.device, 0x43ba..=0x43bc)
                || raw[1] != 0
                || raw[28..32] != [0; 4])
        {
            return Err(Error::Invalid);
        }
        let firmware = if family == Family::PcieFullmac {
            Some(fullmac_firmware(chip, half(raw, 4), &host.id)?)
        } else {
            None
        };
        if family == Family::PcieFullmac && (raw[1] != 0 || raw[28..32] != [0; 4]) {
            return Err(Error::Invalid);
        }
        if family == Family::Sdio43439
            && (raw[1] != 1
                || !matches!(
                    (half(raw, 28), half(raw, 30)),
                    (0x02d0, 0xa9af) | (0x04b4, 0xbd3d)
                ))
        {
            return Err(Error::Invalid);
        }
        if family == Family::Sdio43439
            && matches!(address, narf_bus::BusAddr::Pcie(_))
            && !matches!(host.id.class, 0x080500 | 0x080501)
        {
            return Err(Error::Invalid);
        }
        let mut assets = Vec::new();
        assets.try_reserve_exact(3).map_err(|_| Error::Memory)?;
        assets.push(parse_asset(&raw[112..112 + ASSET], 1, otp)?);
        executable_shape(family, assets[0].length)?;
        assets.push(parse_asset(&raw[112 + ASSET..112 + 2 * ASSET], 2, otp)?);
        if let Some(base) = firmware {
            if !super::chip_profile::linux_asset_name(base, &assets[0].key, "bin")
                || !super::chip_profile::linux_asset_name(base, &assets[1].key, "txt")
            {
                return Err(Error::Invalid);
            }
        }
        let board = string_with(&raw[32..96], false, otp)?;
        let antenna_sku = if otp {
            // Shape only; the OTP identity itself is checked at claim.
            let base = firmware.ok_or(Error::Invalid)?;
            let prefix = alloc::format!("{board}-");
            let nvram = super::chip_profile::asset_board(base, &assets[1].key, "txt");
            let executable = super::chip_profile::asset_board(base, &assets[0].key, "bin");
            if !nvram.is_some_and(|b| b.starts_with(&prefix))
                || executable.is_some_and(|b| b != board && !b.starts_with(&prefix))
            {
                return Err(Error::Invalid);
            }
            Some(string(&raw[96..112], false)?)
        } else {
            None
        };
        if family == Family::Sdio43439 {
            assets.push(parse_asset(&raw[112 + 2 * ASSET..], 3, false)?);
        } else if raw[112 + 2 * ASSET..].iter().any(|byte| *byte != 0) {
            return Err(Error::Invalid);
        }
        if assets
            .iter()
            .enumerate()
            .any(|(index, asset)| assets[..index].iter().any(|other| other.key == asset.key))
        {
            return Err(Error::Invalid);
        }
        if records.iter().any(|record| {
            record.family == family
                && record.host == host
                && record.function == raw[1]
                && record.card_vendor == half(raw, 28)
                && record.card_device == half(raw, 30)
        }) {
            return Err(Error::Ambiguous);
        }
        records.push(Selection {
            family,
            host,
            chip,
            revisions: half(raw, 4),
            function: raw[1],
            card_vendor: half(raw, 28),
            card_device: half(raw, 30),
            board,
            antenna_sku,
            base: firmware,
            assets,
            source: None,
        });
    }
    Ok(records)
}

#[cfg(feature = "kernel-test")]
#[path = "provision_tests.rs"]
pub(crate) mod tests;

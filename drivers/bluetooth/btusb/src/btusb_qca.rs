//! Qualcomm WCN6855 USB firmware transport.
//!
//! WCN6855 USB parts expose a small DFU protocol before normal HCI use:
//! vendor control-IN requests return the target version and patch status,
//! a vendor control-OUT request accepts the image header, and endpoint 2
//! bulk-OUT accepts the remaining image body.  This is deliberately separate
//! from Qualcomm's UART `0xFC00` EDL protocol.
//!
//! Reference: Linux `drivers/bluetooth/btusb.c`, GPL-2.0-only, consulted
//! under NARF's GPL-2.0-or-later licensing.  Relevant routines are
//! `btusb_setup_qca`, `btusb_setup_qca_download_fw`, and the WCN6855 rows in
//! `qca_devices_table`.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use core::fmt::Write as _;

use narf_capabilities::{Cap, Read};
use narf_firmware::{FirmwareBlob, FirmwareRegistry};

use crate::xhci::Xhci;

const RT_VENDOR_IN_DEVICE: u8 = 0xC0;
const RT_VENDOR_OUT_DEVICE: u8 = 0x40;

const QCA_GET_TARGET_VERSION: u8 = 0x09;
const QCA_CHECK_STATUS: u8 = 0x05;
const QCA_DFU_DOWNLOAD: u8 = 0x01;

const QCA_SYSCFG_UPDATED: u8 = 0x40;
const QCA_PATCH_UPDATED: u8 = 0x80;
const QCA_FLAG_MULTI_NVM: u8 = 0x80;
const QCA_DFU_PACKET_LEN: usize = 4096;

const WCN6855_2_0_RAM_VERSION_GF: u32 = 0x400C_1200;
const WCN6855_2_1_RAM_VERSION_GF: u32 = 0x400C_1211;

/// Controller metadata returned by vendor request `0x09`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct QcaVersion {
    pub rom_version: u32,
    pub patch_version: u32,
    pub ram_version: u32,
    pub chip_id: u8,
    pub platform_id: u8,
    pub flag: u16,
}

impl QcaVersion {
    const WIRE_LEN: usize = 20;

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::WIRE_LEN {
            return None;
        }
        Some(Self {
            rom_version: u32::from_le_bytes(bytes[0..4].try_into().ok()?),
            patch_version: u32::from_le_bytes(bytes[4..8].try_into().ok()?),
            ram_version: u32::from_le_bytes(bytes[8..12].try_into().ok()?),
            chip_id: bytes[12],
            platform_id: bytes[13],
            flag: u16::from_le_bytes(bytes[14..16].try_into().ok()?),
        })
    }

    pub(crate) fn board_id(self) -> u16 {
        if ((self.flag >> 8) as u8) == QCA_FLAG_MULTI_NVM {
            ((self.chip_id as u16) << 8) | self.platform_id as u16
        } else {
            0
        }
    }

    fn is_global_foundries(self) -> bool {
        matches!(
            self.ram_version,
            WCN6855_2_0_RAM_VERSION_GF | WCN6855_2_1_RAM_VERSION_GF
        )
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct DeviceInfo {
    rom_version: u32,
    image_header_len: usize,
    nvm_header_len: usize,
    patch_version_offset: usize,
}

const WCN6855_DEVICES: &[DeviceInfo] = &[
    DeviceInfo {
        rom_version: 0x0013_0100,
        image_header_len: 40,
        nvm_header_len: 4,
        patch_version_offset: 16,
    },
    DeviceInfo {
        rom_version: 0x0013_0200,
        image_header_len: 40,
        nvm_header_len: 4,
        patch_version_offset: 16,
    },
    DeviceInfo {
        rom_version: 0x0013_0201,
        image_header_len: 40,
        nvm_header_len: 4,
        patch_version_offset: 16,
    },
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FirmwareNames {
    pub rampatch: String,
    pub nvm: String,
}

pub(crate) fn firmware_names(version: QcaVersion) -> FirmwareNames {
    let board_id = version.board_id();
    let subdir = if version.rom_version == 0x0013_0201 && matches!(board_id, 0x030A | 0x030B) {
        "QCA2066/"
    } else {
        ""
    };
    let variant = if version.is_global_foundries() {
        "_gf"
    } else {
        ""
    };
    let board = if board_id == 0 {
        String::new()
    } else {
        format!("_{board_id:04x}")
    };

    FirmwareNames {
        rampatch: format!("qca/{subdir}rampatch_usb_{:08x}.bin", version.rom_version),
        nvm: format!(
            "qca/{subdir}nvm_usb_{:08x}{variant}{board}.bin",
            version.rom_version
        ),
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum QcaError {
    ControlTransfer,
    MalformedVersion,
    UnsupportedVersion(u32),
    FirmwareAuthority,
    FirmwareUnavailable,
    FirmwareInvalid,
    FirmwareTransfer,
}

fn device_info(rom_version: u32) -> Option<DeviceInfo> {
    WCN6855_DEVICES
        .iter()
        .copied()
        .find(|info| info.rom_version == rom_version)
}

async fn read_version(xhci: &Xhci, slot_id: u8) -> Result<QcaVersion, QcaError> {
    let mut raw = [0u8; QcaVersion::WIRE_LEN];
    let count = xhci
        .control_in(
            slot_id,
            RT_VENDOR_IN_DEVICE,
            QCA_GET_TARGET_VERSION,
            0,
            0,
            &mut raw,
        )
        .await
        .map_err(|_| QcaError::ControlTransfer)?;
    if count != raw.len() {
        return Err(QcaError::MalformedVersion);
    }
    QcaVersion::decode(&raw).ok_or(QcaError::MalformedVersion)
}

async fn read_status(xhci: &Xhci, slot_id: u8) -> Result<u8, QcaError> {
    let mut status = [0u8; 1];
    let count = xhci
        .control_in(
            slot_id,
            RT_VENDOR_IN_DEVICE,
            QCA_CHECK_STATUS,
            0,
            0,
            &mut status,
        )
        .await
        .map_err(|_| QcaError::ControlTransfer)?;
    if count != 1 {
        return Err(QcaError::ControlTransfer);
    }
    Ok(status[0])
}

fn validate_rampatch(image: &[u8], version: QcaVersion, info: DeviceInfo) -> Result<(), QcaError> {
    if image.len() < info.image_header_len || image.len() < info.patch_version_offset + 6 {
        return Err(QcaError::FirmwareInvalid);
    }
    let off = info.patch_version_offset;
    let rom_high = u16::from_le_bytes([image[off], image[off + 1]]) as u32;
    let rom_low = u16::from_le_bytes([image[off + 2], image[off + 3]]) as u32;
    let patch = u16::from_le_bytes([image[off + 4], image[off + 5]]) as u32;
    let image_rom = if version.rom_version & !0xFFFF != 0 {
        (rom_high << 16) | rom_low
    } else {
        rom_low
    };
    if image_rom != version.rom_version || patch <= version.patch_version {
        return Err(QcaError::FirmwareInvalid);
    }
    Ok(())
}

pub(crate) fn validate_rampatch_image(image: &[u8], version: QcaVersion) -> Result<(), QcaError> {
    let info = device_info(version.rom_version)
        .ok_or(QcaError::UnsupportedVersion(version.rom_version))?;
    validate_rampatch(image, version, info)
}

async fn cooperative_delay_ms(ms: u64) {
    let deadline = narf_time::Deadline::after_ms(ms);
    while !deadline.expired() {
        narf_scheduler::yield_now().await;
    }
}

async fn download_image(
    xhci: &Xhci,
    slot_id: u8,
    bulk_out_dci: u8,
    image: &[u8],
    header_len: usize,
) -> Result<(), QcaError> {
    if image.len() < header_len {
        return Err(QcaError::FirmwareInvalid);
    }
    let sent = xhci
        .control_out(
            slot_id,
            RT_VENDOR_OUT_DEVICE,
            QCA_DFU_DOWNLOAD,
            0,
            0,
            &image[..header_len],
        )
        .await
        .map_err(|_| QcaError::FirmwareTransfer)?;
    if sent != header_len {
        return Err(QcaError::FirmwareTransfer);
    }

    // Endpoint 2 changes from ACL to DFU after the header request.
    cooperative_delay_ms(20).await;
    for chunk in image[header_len..].chunks(QCA_DFU_PACKET_LEN) {
        let sent = xhci
            .bulk_out(slot_id, bulk_out_dci, chunk)
            .await
            .map_err(|_| QcaError::FirmwareTransfer)?;
        if sent != chunk.len() {
            return Err(QcaError::FirmwareTransfer);
        }
    }
    Ok(())
}

fn firmware_cap(name: &str) -> Result<Cap<FirmwareBlob, Read>, QcaError> {
    let write = narf_firmware::trusted_loader_authority().ok_or(QcaError::FirmwareAuthority)?;
    let read: Cap<FirmwareRegistry, Read> =
        write.derive().map_err(|_| QcaError::FirmwareAuthority)?;
    narf_firmware::open(name, &read).map_err(|_| QcaError::FirmwareUnavailable)
}

async fn load_named_image(
    xhci: &Xhci,
    slot_id: u8,
    bulk_out_dci: u8,
    name: &str,
    header_len: usize,
    validate: impl FnOnce(&[u8]) -> Result<(), QcaError>,
) -> Result<(), QcaError> {
    let cap = firmware_cap(name)?;
    let view = narf_firmware::view_of(&cap).map_err(|_| QcaError::FirmwareUnavailable)?;
    validate(view.bytes)?;
    let _ = writeln!(
        narf_console::Writer,
        "  btusb-qca: loading {} ({} bytes)",
        name,
        view.bytes.len()
    );
    download_image(xhci, slot_id, bulk_out_dci, view.bytes, header_len).await
}

/// Bring a WCN6855 USB controller out of ROM/DFU state before normal HCI.
/// Already-patched controllers do not require firmware-registry authority.
pub(crate) async fn setup_wcn6855(
    xhci: &Xhci,
    slot_id: u8,
    bulk_out_dci: u8,
) -> Result<QcaVersion, QcaError> {
    let mut version = read_version(xhci, slot_id).await?;
    let Some(info) = device_info(version.rom_version) else {
        // Upstream treats a future controller with a non-zero high ROM
        // version as operational without host patching.
        if version.rom_version & !0xFFFF != 0 {
            return Ok(version);
        }
        return Err(QcaError::UnsupportedVersion(version.rom_version));
    };
    let status = read_status(xhci, slot_id).await?;

    if status & QCA_PATCH_UPDATED == 0 {
        let names = firmware_names(version);
        load_named_image(
            xhci,
            slot_id,
            bulk_out_dci,
            &names.rampatch,
            info.image_header_len,
            |image| validate_rampatch_image(image, version),
        )
        .await?;
    }

    // The running patch version affects board/NVM selection.
    version = read_version(xhci, slot_id).await?;
    if status & QCA_SYSCFG_UPDATED == 0 {
        let names = firmware_names(version);
        load_named_image(
            xhci,
            slot_id,
            bulk_out_dci,
            &names.nvm,
            info.nvm_header_len,
            |_| Ok(()),
        )
        .await?;

        // WCN6855 2.1 resets internally to apply NVM.
        if info.rom_version >= 0x0013_0201 {
            cooperative_delay_ms(100).await;
        }
    }

    Ok(version)
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn version_decode_and_board_id() {
        let mut raw = [0u8; QcaVersion::WIRE_LEN];
        raw[0..4].copy_from_slice(&0x0013_0201u32.to_le_bytes());
        raw[4..8].copy_from_slice(&0x0000_0007u32.to_le_bytes());
        raw[8..12].copy_from_slice(&WCN6855_2_1_RAM_VERSION_GF.to_le_bytes());
        raw[12] = 0x01;
        raw[13] = 0x0A;
        raw[14..16].copy_from_slice(&0x8000u16.to_le_bytes());
        let version = QcaVersion::decode(&raw).unwrap();
        assert_eq!(version.rom_version, 0x0013_0201);
        assert_eq!(version.board_id(), 0x010A);
    }

    #[test]
    fn firmware_names_include_variant_and_board() {
        let version = QcaVersion {
            rom_version: 0x0013_0201,
            ram_version: WCN6855_2_1_RAM_VERSION_GF,
            chip_id: 0x01,
            platform_id: 0x0A,
            flag: 0x8000,
            ..QcaVersion::default()
        };
        let names = firmware_names(version);
        assert_eq!(names.rampatch, "qca/rampatch_usb_00130201.bin");
        assert_eq!(names.nvm, "qca/nvm_usb_00130201_gf_010a.bin");
    }

    #[test]
    fn firmware_names_select_qca2066_subdirectory() {
        let version = QcaVersion {
            rom_version: 0x0013_0201,
            chip_id: 0x03,
            platform_id: 0x0A,
            flag: 0x8000,
            ..QcaVersion::default()
        };
        let names = firmware_names(version);
        assert_eq!(names.rampatch, "qca/QCA2066/rampatch_usb_00130201.bin");
        assert_eq!(names.nvm, "qca/QCA2066/nvm_usb_00130201_030a.bin");
    }

    #[test]
    fn rampatch_must_match_rom_and_advance_patch() {
        let version = QcaVersion {
            rom_version: 0x0013_0201,
            patch_version: 6,
            ..QcaVersion::default()
        };
        let info = device_info(version.rom_version).unwrap();
        let mut image = [0u8; 40];
        image[16..18].copy_from_slice(&0x0013u16.to_le_bytes());
        image[18..20].copy_from_slice(&0x0201u16.to_le_bytes());
        image[20..22].copy_from_slice(&7u16.to_le_bytes());
        assert_eq!(validate_rampatch(&image, version, info), Ok(()));
        image[20..22].copy_from_slice(&6u16.to_le_bytes());
        assert_eq!(
            validate_rampatch(&image, version, info),
            Err(QcaError::FirmwareInvalid)
        );
    }
}

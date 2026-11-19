// SPDX-License-Identifier: GPL-2.0-or-later
//! Devicetree and NVMEM calibration sources of the exact PCI function.
//!
//! Linux `core.c::ath10k_download_cal_dt` reads `qcom,pre-calibration-data`
//! (then the legacy `qcom,ath10k-pre-calibration-data`) or
//! `qcom,calibration-data` (then `qcom,ath10k-calibration-data`) from
//! `ar->dev->of_node`; `ath10k_download_cal_nvmem` reads the
//! `pre-calibration` / `calibration` nvmem cells of the same node and
//! `ath10k_core_check_dt` reads `qcom,calibration-variant` (then
//! `qcom,ath10k-calibration-variant`). For a PCI function that node is the
//! one `drivers/pci/of.c::pci_set_of_node` associates below the host bridge
//! (`narf_firmware_fdt::for_pci_function`). The only NVMEM provider read here
//! is `nvmem-rmem` (`drivers/nvmem/rmem.c`), the firmware-reserved region
//! read through a write-back mapping like `rmem_read`'s `memremap`.
//!
//! These bytes come from boot platform firmware (the DTB and the region it
//! reserves), not from the signed firmware registry: their authority is the
//! same as the Devicetree's own.
use super::Error;
use alloc::vec::Vec;
use narf_firmware_fdt::{NvmemError, PropIter, RmemCell};

/// One optional calibration source at probe time.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::ath10k) enum Source {
    /// Linux `-ENOENT`: try the next source.
    #[default]
    Absent,
    Present(Vec<u8>),
    /// A present source that cannot be read (Linux `-EPROBE_DEFER`, a read
    /// error or an invalid cell). Terminal, never a fallback receipt.
    Refused(Error),
}

/// The function's DT/NVMEM calibration facts, collected before BMI.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::ath10k) struct Platform {
    pub pre_nvmem: Source,
    pub pre_dt: Source,
    pub nvmem: Source,
    pub dt: Source,
    /// `ath10k_core_check_dt`: `strscpy` into the 32-byte `bdf_ext`.
    pub variant: Option<Vec<u8>>,
}

/// `ATH10K_SMBIOS_BDF_EXT_STR_LENGTH`.
const BDF_EXT_LENGTH: usize = 0x20;

fn property<'a>(props: PropIter<'a>, name: &str) -> Option<&'a [u8]> {
    props
        .into_iter()
        .find_map(|(key, value)| (key == name).then_some(value))
}

/// `of_get_property` of the primary name; the legacy name only on -ENOENT.
fn dt_source(props: PropIter<'_>, primary: &str, legacy: &str) -> Source {
    property(props, primary)
        .or_else(|| property(props, legacy))
        .map_or(Source::Absent, |value| Source::Present(value.to_vec()))
}

/// `of_property_read_string`: bytes before the first NUL; an unterminated
/// value is `-EILSEQ` and leaves the variant unset.
fn dt_string(value: &[u8]) -> Option<&[u8]> {
    value.iter().position(|b| *b == 0).map(|end| &value[..end])
}

impl Platform {
    /// Collect every source of one function node. `read` copies an
    /// `nvmem-rmem` cell's bytes; it is only called for a registered,
    /// in-bounds, byte-aligned cell.
    pub fn from_props(
        blob: &[u8],
        props: PropIter<'_>,
        mut read: impl FnMut(&RmemCell) -> Result<Vec<u8>, Error>,
    ) -> Self {
        let mut nvmem = |id: &str| match narf_firmware_fdt::rmem_cell(blob, props, id) {
            Err(NvmemError::NotFound) => Source::Absent,
            Err(NvmemError::ProviderUnavailable) => Source::Refused(Error::Unsupported),
            Err(NvmemError::Invalid) => Source::Refused(Error::Calibration),
            // `nvmem_cell_read` post-processing of bit-field cells is not
            // implemented; a factory blob is a whole-byte cell.
            Ok(cell) if cell.bits.is_some() => Source::Refused(Error::Unsupported),
            // `rmem_read`: `-EIO` past the reserved region.
            Ok(cell)
                if u64::from(cell.offset) + u64::from(cell.bytes) > cell.size
                    || cell.bytes == 0 =>
            {
                Source::Refused(Error::Calibration)
            }
            Ok(cell) => read(&cell).map_or_else(Source::Refused, Source::Present),
        };
        let pre_nvmem = nvmem("pre-calibration");
        let calibration = nvmem("calibration");
        let primary = property(props, "qcom,calibration-variant").and_then(dt_string);
        let legacy = property(props, "qcom,ath10k-calibration-variant").and_then(dt_string);
        Self {
            pre_nvmem,
            pre_dt: dt_source(
                props,
                "qcom,pre-calibration-data",
                "qcom,ath10k-pre-calibration-data",
            ),
            nvmem: calibration,
            dt: dt_source(
                props,
                "qcom,calibration-data",
                "qcom,ath10k-calibration-data",
            ),
            variant: primary
                .or(legacy)
                .map(|value| value[..value.len().min(BDF_EXT_LENGTH - 1)].to_vec()),
        }
    }

    /// The unique node of PCI function `devfns` (root-bus hop first) under
    /// `domain`; no node is Linux's absent `of_node` (every source -ENOENT).
    pub fn in_blob(
        blob: &[u8],
        domain: u16,
        devfns: &[u8],
        read: impl FnMut(&RmemCell) -> Result<Vec<u8>, Error>,
    ) -> Self {
        let mut read = Some(read);
        let mut out = Self::default();
        narf_firmware_fdt::for_pci_function(blob, domain, devfns, |_, props, _| {
            if let Some(read) = read.take() {
                out = Self::from_props(blob, props, read);
            }
        });
        out
    }

    /// Sources of a probed PCI function from the boot Devicetree; empty
    /// without a DTB (x86_64, or a QEMU boot without `-dtb`).
    pub fn for_device(device: &narf_bus::BusDevice) -> Self {
        const MAX_DTB_SIZE: usize = 2 * 1024 * 1024;
        let narf_bus::BusKind::Pcie { addr, .. } = device.kind else {
            return Self::default();
        };
        let Some(devfns) = narf_bus::pci::devfn_path(device) else {
            return Self::default();
        };
        let Some(phys) = narf_bus::boot_dtb() else {
            return Self::default();
        };
        // SAFETY: the boot path reserved the firmware DTB in RAM covered by
        // the kernel direct map; `discover` validates the header and bounds
        // every slice by the blob's own `totalsize` (capped here).
        let Some(blob) =
            (unsafe { narf_firmware_fdt::discover(phys.raw() as usize, MAX_DTB_SIZE) })
        else {
            return Self::default();
        };
        Self::in_blob(blob, addr.segment, &devfns, read_rmem)
    }
}

/// `rmem_read`: copy one cell through a write-back mapping of the
/// reserved region (Linux `memremap(..., MEMREMAP_WB)`).
fn read_rmem(cell: &RmemCell) -> Result<Vec<u8>, Error> {
    use narf_memory::ioremap::{ioremap, MmioAttrs};
    let phys = cell
        .base
        .checked_add(u64::from(cell.offset))
        .ok_or(Error::Address)?;
    let length = usize::try_from(cell.bytes).map_err(|_| Error::Calibration)?;
    // SAFETY: `rmem_cell` only returns an enabled static `/reserved-memory`
    // `nvmem-rmem` region, which boot removed from the RAM map and nothing
    // else owns; the caller checked the cell lies inside it. The mapping is
    // only read here, with the same write-back type as Linux's memremap.
    // Unlike `rmem_read` the mapping is retained: the ioremap cache hands an
    // identical range to every caller without a reference count, so another
    // function's concurrent probe of the same cell may still be copying.
    let mapping = unsafe { ioremap(phys, u64::from(cell.bytes), MmioAttrs::WriteBack) }
        .map_err(|_| Error::Address)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Error::NoMemory)?;
    // SAFETY: the mapping covers `length` bytes from `va()`.
    let source = unsafe { core::slice::from_raw_parts(mapping.va() as *const u8, length) };
    bytes.extend_from_slice(source);
    Ok(bytes)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "platform_tests.rs"]
mod tests;

//! Devicetree discovery of the Arm Generic Interrupt Controller.
//!
//! Arch-neutral and allocation-free: [`detect`] is a pure function of a
//! flattened devicetree blob, so it runs in the pre-MMU aarch64 boot path
//! (before the heap exists) and its smokes run on both architectures.
//! `aarch64::gic::probe` turns the result into the live backend.
//!
//! Bindings (Linux `Documentation/devicetree/bindings/interrupt-controller/`):
//!
//! | compatible            | version | `reg[0]`    | `reg[1]`                  |
//! |-----------------------|---------|-------------|---------------------------|
//! | `arm,gic-400`         | v2      | GICD        | GICC (CPU interface)      |
//! | `arm,cortex-a15-gic`  | v2      | GICD        | GICC (QEMU `virt`, v2)    |
//! | `qcom,msm-qgic2`      | v2      | GICD        | GICC (IPQ8074/6018/5018)  |
//! | `arm,gic-v3`          | v3      | GICD        | GICR (all redistributors) |
//!
//! Further `reg` entries (GICH / GICV, extra redistributor regions) are
//! ignored. Parent `ranges` are assumed to be identity — true for the
//! QEMU `virt` root and for the Qualcomm `soc@0` nodes, which translate
//! `<0 0 0 0xffffffff>`; a SoC that offsets its GIC through `ranges`
//! needs translation added here first.

use narf_firmware_fdt as fdt;

/// GIC architecture generation the devicetree describes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GicVersion {
    /// GICv2: memory-mapped CPU interface (`GICC_IAR` / `GICC_EOIR`),
    /// `GICD_ITARGETSR` SPI routing, `GICD_SGIR` for SGIs.
    V2,
    /// GICv3: `ICC_*_EL1` system-register CPU interface, per-CPU
    /// redistributors, `GICD_IROUTER` affinity routing.
    V3,
}

/// One MMIO register window from a `reg` entry.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MmioWindow {
    pub base: u64,
    pub len: u64,
}

/// What [`detect`] found.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GicDescription {
    pub version: GicVersion,
    /// Distributor (`GICD`) window — `reg[0]` for every binding.
    pub dist: MmioWindow,
    /// `reg[1]`: the GICv2 CPU interface (`GICC`) or the GICv3
    /// redistributor region (`GICR`).
    pub cpu: MmioWindow,
    /// GICv3 `redistributor-stride`, when the node overrides the
    /// architectural 128 KiB (GICv3) frame pair. Always `None` on v2.
    pub redist_stride: Option<u64>,
}

/// Why [`detect`] produced no usable description.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GicDetectError {
    /// The blob's FDT header did not validate.
    BadBlob,
    /// No enabled node carries a supported GIC `compatible` (includes
    /// unknown controllers such as GICv4.1-only or vendor AICs).
    NotFound,
    /// A supported GIC node exists but its `reg` property is absent or
    /// holds fewer than the two windows the binding requires, or a
    /// window is zero-sized.
    MissingReg(GicVersion),
}

/// Supported compatibles, most specific first. Matching is on any
/// string of the node's `compatible` list.
const COMPATIBLES: &[(&str, GicVersion)] = &[
    ("qcom,msm-qgic2", GicVersion::V2),
    ("arm,gic-400", GicVersion::V2),
    ("arm,cortex-a15-gic", GicVersion::V2),
    ("arm,gic-v3", GicVersion::V3),
];

/// Version for a `compatible` payload (NUL-separated list), if any
/// string names a supported GIC.
pub fn version_for_compatible(value: &[u8]) -> Option<GicVersion> {
    COMPATIBLES
        .iter()
        .find(|(c, _)| fdt::compatible_matches(value, c))
        .map(|(_, v)| *v)
}

/// Find the root interrupt controller in `blob`.
///
/// The first enabled node with a supported `compatible` wins (a secondary
/// cascaded GIC would follow the primary in DT order, as Linux assumes).
/// Disabled (`status = "disabled"`) nodes are skipped.
pub fn detect(blob: &[u8]) -> Result<GicDescription, GicDetectError> {
    if fdt::parse_header(blob).is_none() {
        return Err(GicDetectError::BadBlob);
    }
    let mut out: Option<Result<GicDescription, GicDetectError>> = None;
    fdt::walk_with_cells(blob, |_path, props, cells| {
        if out.is_some() {
            return;
        }
        let mut version = None;
        let mut reg: Option<&[u8]> = None;
        let mut stride = None;
        for (name, value) in props {
            match name {
                "compatible" => version = version_for_compatible(value),
                "reg" => reg = Some(value),
                "redistributor-stride" => {
                    stride = match value.len() {
                        4 => {
                            Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]) as u64)
                        }
                        8 => Some(u64::from_be_bytes([
                            value[0], value[1], value[2], value[3], value[4], value[5], value[6],
                            value[7],
                        ])),
                        _ => None,
                    }
                }
                _ => {}
            }
        }
        let Some(version) = version else { return };
        if fdt::node_status(props) == fdt::Status::Disabled {
            return;
        }
        out = Some(describe(version, reg, cells, stride));
    });
    out.unwrap_or(Err(GicDetectError::NotFound))
}

fn describe(
    version: GicVersion,
    reg: Option<&[u8]>,
    cells: fdt::Cells,
    stride: Option<u64>,
) -> Result<GicDescription, GicDetectError> {
    let missing = GicDetectError::MissingReg(version);
    let reg = reg.ok_or(missing)?;
    if cells.address == 0 || cells.address > 2 || cells.size == 0 || cells.size > 2 {
        return Err(missing);
    }
    let entry = cells.entry_bytes();
    let (d_base, d_len) = cells.read_one_reg(reg, 0).ok_or(missing)?;
    let (c_base, c_len) = cells.read_one_reg(reg, entry).ok_or(missing)?;
    if d_len == 0 || c_len == 0 {
        return Err(missing);
    }
    Ok(GicDescription {
        version,
        dist: MmioWindow {
            base: d_base,
            len: d_len,
        },
        cpu: MmioWindow {
            base: c_base,
            len: c_len,
        },
        redist_stride: match version {
            GicVersion::V3 => stride.filter(|s| *s != 0),
            GicVersion::V2 => None,
        },
    })
}

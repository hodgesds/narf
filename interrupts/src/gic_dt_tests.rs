//! Devicetree GIC detection smokes (`gic_dt::detect`). Pure blob
//! parsing, so they run on both architectures.

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::gic_dt::{detect, GicDescription, GicDetectError, GicVersion, MmioWindow};

extern crate alloc;
use alloc::vec::Vec;

const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_END: u32 = 9;

/// Minimal FDT writer: nodes are opened/closed explicitly so nested
/// `#address-cells` scopes (Qualcomm `soc@0`) can be expressed.
struct Blob {
    s: Vec<u8>,
    strings: Vec<u8>,
}

impl Blob {
    fn new() -> Self {
        let mut b = Self {
            s: Vec::new(),
            strings: Vec::new(),
        };
        b.begin("");
        b
    }

    fn pad(&mut self) {
        while self.s.len() % 4 != 0 {
            self.s.push(0);
        }
    }

    fn begin(&mut self, name: &str) -> &mut Self {
        self.s.extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
        self.s.extend_from_slice(name.as_bytes());
        self.s.push(0);
        self.pad();
        self
    }

    fn end(&mut self) -> &mut Self {
        self.s.extend_from_slice(&FDT_END_NODE.to_be_bytes());
        self
    }

    fn prop(&mut self, name: &str, value: &[u8]) -> &mut Self {
        let off = self.strings.len() as u32;
        self.strings.extend_from_slice(name.as_bytes());
        self.strings.push(0);
        self.s.extend_from_slice(&FDT_PROP.to_be_bytes());
        self.s
            .extend_from_slice(&(value.len() as u32).to_be_bytes());
        self.s.extend_from_slice(&off.to_be_bytes());
        self.s.extend_from_slice(value);
        self.pad();
        self
    }

    fn cells(&mut self, name: &str, cells: &[u32]) -> &mut Self {
        let v: Vec<u8> = cells.iter().flat_map(|c| c.to_be_bytes()).collect();
        self.prop(name, &v)
    }

    fn finish(&mut self) -> Vec<u8> {
        self.end(); // root
        self.s.extend_from_slice(&FDT_END.to_be_bytes());
        let off_rsv = 40u32;
        let off_struct = off_rsv + 16;
        let off_strings = off_struct + self.s.len() as u32;
        let total = off_strings + self.strings.len() as u32;
        let mut out = Vec::new();
        for w in [
            FDT_MAGIC,
            total,
            off_struct,
            off_strings,
            off_rsv,
            17,
            16,
            0,
            self.strings.len() as u32,
            self.s.len() as u32,
        ] {
            out.extend_from_slice(&w.to_be_bytes());
        }
        out.extend_from_slice(&[0u8; 16]); // empty reservation map
        out.extend_from_slice(&self.s);
        out.extend_from_slice(&self.strings);
        out
    }
}

fn win(base: u64, len: u64) -> MmioWindow {
    MmioWindow { base, len }
}

/// Root with QEMU `virt`'s `#address-cells = <2>`, `#size-cells = <2>`.
fn virt_root() -> Blob {
    let mut b = Blob::new();
    b.cells("#address-cells", &[2]).cells("#size-cells", &[2]);
    b
}

fn smoke_gic_dt_detects_v2_compatibles() -> TestResult {
    // IPQ8074: `qcom,msm-qgic2` under `soc@0` with 1/1 cells and a GICv2m
    // child; only the first two reg windows matter.
    let mut b = virt_root();
    b.begin("soc@0")
        .cells("#address-cells", &[1])
        .cells("#size-cells", &[1])
        .cells("ranges", &[0, 0, 0, 0xffff_ffff]);
    b.begin("interrupt-controller@b000000")
        .prop("compatible", b"qcom,msm-qgic2\0")
        .cells("#address-cells", &[1])
        .cells("#size-cells", &[1])
        .prop("interrupt-controller", &[])
        .cells("reg", &[0x0b00_0000, 0x1000, 0x0b00_2000, 0x1000]);
    b.begin("v2m@0")
        .prop("compatible", b"arm,gic-v2m-frame\0")
        .cells("reg", &[0, 0xffd])
        .end();
    b.end().end();
    let ipq8074 = detect(&b.finish());
    let want = Ok(GicDescription {
        version: GicVersion::V2,
        dist: win(0x0b00_0000, 0x1000),
        cpu: win(0x0b00_2000, 0x1000),
        redist_stride: None,
    });
    if ipq8074 != want {
        return TestResult::Fail("qcom,msm-qgic2 (IPQ8074 layout) not detected as v2");
    }

    // IPQ6018 layout: 2/2 cells, four windows (GICD, GICC, GICH, GICV),
    // with `arm,gic-400` as a second compatible string.
    let mut b = virt_root();
    b.begin("intc@b000000")
        .prop("compatible", b"vendor,unknown-gic\0arm,gic-400\0")
        .cells(
            "reg",
            &[
                0,
                0x0b00_0000,
                0,
                0x1000,
                0,
                0x0b00_2000,
                0,
                0x1000,
                0,
                0x0b00_1000,
                0,
                0x1000,
                0,
                0x0b00_4000,
                0,
                0x1000,
            ],
        )
        .end();
    if detect(&b.finish()) != want {
        return TestResult::Fail("arm,gic-400 (2/2 cells, 4 windows) not detected as v2");
    }

    // QEMU `virt,gic-version=2`.
    let mut b = virt_root();
    b.begin("intc@8000000")
        .prop("compatible", b"arm,cortex-a15-gic\0")
        .cells(
            "reg",
            &[0, 0x0800_0000, 0, 0x1_0000, 0, 0x0801_0000, 0, 0x1_0000],
        )
        .end();
    let virt = detect(&b.finish());
    if virt
        != Ok(GicDescription {
            version: GicVersion::V2,
            dist: win(0x0800_0000, 0x1_0000),
            cpu: win(0x0801_0000, 0x1_0000),
            redist_stride: None,
        })
    {
        return TestResult::Fail("arm,cortex-a15-gic (QEMU virt v2) not detected");
    }
    TestResult::Pass
}
kernel_test_in!("interrupts", smoke_gic_dt_detects_v2_compatibles);

fn smoke_gic_dt_detects_v3() -> TestResult {
    let mut b = virt_root();
    b.begin("intc@8000000")
        .prop("compatible", b"arm,gic-v3\0")
        .cells(
            "reg",
            &[0, 0x0800_0000, 0, 0x1_0000, 0, 0x080a_0000, 0, 0xf6_0000],
        )
        .end();
    let qemu = detect(&b.finish());
    if qemu
        != Ok(GicDescription {
            version: GicVersion::V3,
            dist: win(0x0800_0000, 0x1_0000),
            cpu: win(0x080a_0000, 0xf6_0000),
            redist_stride: None,
        })
    {
        return TestResult::Fail("arm,gic-v3 (QEMU virt) not detected");
    }
    // GICv4 parts publish a 256 KiB stride.
    let mut b = virt_root();
    b.begin("intc@17a00000")
        .prop("compatible", b"arm,gic-v3\0")
        .cells("redistributor-stride", &[0, 0x4_0000])
        .cells(
            "reg",
            &[0, 0x17a0_0000, 0, 0x1_0000, 0, 0x17a6_0000, 0, 0x10_0000],
        )
        .end();
    match detect(&b.finish()) {
        Ok(d) if d.version == GicVersion::V3 && d.redist_stride == Some(0x4_0000) => {}
        _ => return TestResult::Fail("redistributor-stride not honoured"),
    }
    TestResult::Pass
}
kernel_test_in!("interrupts", smoke_gic_dt_detects_v3);

fn smoke_gic_dt_rejects_unknown_and_disabled() -> TestResult {
    let mut b = virt_root();
    b.begin("intc@8000000")
        .prop("compatible", b"apple,aic\0")
        .cells(
            "reg",
            &[0, 0x0800_0000, 0, 0x1_0000, 0, 0x0801_0000, 0, 0x1000],
        )
        .end();
    b.begin("intc@9000000")
        .prop("compatible", b"arm,gic-v5\0")
        .cells(
            "reg",
            &[0, 0x0900_0000, 0, 0x1_0000, 0, 0x0901_0000, 0, 0x1000],
        )
        .end();
    if detect(&b.finish()) != Err(GicDetectError::NotFound) {
        return TestResult::Fail("unknown interrupt controllers must be NotFound");
    }
    if detect(&virt_root().finish()) != Err(GicDetectError::NotFound) {
        return TestResult::Fail("tree with no GIC must be NotFound");
    }
    // A disabled v3 node is skipped in favour of the enabled v2 one.
    let mut b = virt_root();
    b.begin("intc@1000")
        .prop("compatible", b"arm,gic-v3\0")
        .prop("status", b"disabled\0")
        .cells("reg", &[0, 0x1000, 0, 0x1000, 0, 0x2000, 0, 0x1000])
        .end();
    b.begin("intc@8000000")
        .prop("compatible", b"arm,gic-400\0")
        .cells(
            "reg",
            &[0, 0x0800_0000, 0, 0x1000, 0, 0x0801_0000, 0, 0x2000],
        )
        .end();
    match detect(&b.finish()) {
        Ok(d) if d.version == GicVersion::V2 && d.dist.base == 0x0800_0000 => {}
        _ => return TestResult::Fail("disabled GIC node was not skipped"),
    }
    if detect(&[0u8; 64]) != Err(GicDetectError::BadBlob) {
        return TestResult::Fail("garbage blob must be BadBlob");
    }
    TestResult::Pass
}
kernel_test_in!("interrupts", smoke_gic_dt_rejects_unknown_and_disabled);

fn smoke_gic_dt_missing_reg() -> TestResult {
    let mut b = virt_root();
    b.begin("intc@b000000")
        .prop("compatible", b"qcom,msm-qgic2\0")
        .prop("interrupt-controller", &[])
        .end();
    if detect(&b.finish()) != Err(GicDetectError::MissingReg(GicVersion::V2)) {
        return TestResult::Fail("v2 node without reg must be MissingReg");
    }
    // One window only: no CPU interface / redistributor.
    let mut b = virt_root();
    b.begin("intc@8000000")
        .prop("compatible", b"arm,gic-v3\0")
        .cells("reg", &[0, 0x0800_0000, 0, 0x1_0000])
        .end();
    if detect(&b.finish()) != Err(GicDetectError::MissingReg(GicVersion::V3)) {
        return TestResult::Fail("v3 node with one reg window must be MissingReg");
    }
    // Zero-sized CPU-interface window.
    let mut b = virt_root();
    b.begin("intc@8000000")
        .prop("compatible", b"arm,cortex-a15-gic\0")
        .cells("reg", &[0, 0x0800_0000, 0, 0x1_0000, 0, 0x0801_0000, 0, 0])
        .end();
    if detect(&b.finish()) != Err(GicDetectError::MissingReg(GicVersion::V2)) {
        return TestResult::Fail("zero-sized GICC window must be MissingReg");
    }
    TestResult::Pass
}
kernel_test_in!("interrupts", smoke_gic_dt_missing_reg);

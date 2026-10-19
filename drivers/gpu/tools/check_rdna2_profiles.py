#!/usr/bin/env python3
"""Check compiled RDNA2 inventories against an unmodified Linux source tree."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile
from functools import lru_cache


def check_dmub_layouts(amd):
    """The shared DMUB implementation requires identical offsets and masks."""
    definitions = {}
    for revision in [0, 2, 3]:
        values = {}
        for suffix in ["offset", "sh_mask"]:
            header = amd / f"include/asic_reg/dcn/dcn_3_0_{revision}_{suffix}.h"
            for name, value in re.findall(r"^#define\s+(\w+)\s+(0x[0-9a-fA-F]+|[0-9]+)\b", header.read_text(), re.MULTILINE):
                if "DMCUB" in name or "MMHUBBUB_SOFT_RESET" in name:
                    values[name] = int(value, 0)
        definitions[revision] = values
    common = set.intersection(*(set(values) for values in definitions.values()))
    if not common:
        raise SystemExit("No shared DMCUB definitions found")
    # RBBMIF timeout fields differ but are not used by the shared owner.
    used = {name for name in definitions[0] if "RBBMIF_TIMEOUT" not in name}
    for revision in [2, 3]:
        for name in used:
            if definitions[revision].get(name) != definitions[0][name]:
                raise SystemExit(f"DCN 3.0.{revision} DMUB definition differs: {name}")
    print(f"PASS: {len(used)} DMCUB offset/base/mask definitions agree across DCN 3.0/3.0.2/3.0.3")


@lru_cache(maxsize=1)
def power_layouts(linux):
    header = linux / "drivers/gpu/drm/amd/pm/swsmu/inc/pmfw_if/smu11_driver_if_sienna_cichlid.h"
    legacy = subprocess.check_output(["git", "-C", str(linux), "show", "fbe8115c6ab7:drivers/gpu/drm/amd/pm/inc/smu11_driver_if_sienna_cichlid.h"], text=True)
    result = {}
    with tempfile.TemporaryDirectory(prefix="narf-rdna2-power-") as temporary:
        work = Path(temporary)
        for name, text, kind in [("common", header.read_text(), "PPTable_t"), ("beige", header.read_text(), "PPTable_beige_goby_t"), ("legacy", legacy, "PPTable_beige_goby_t")]:
            (work / "interface.h").write_text(text)
            (work / "layout.c").write_text('#include <stdint.h>\n#include <stddef.h>\n#include <stdio.h>\n#include "interface.h"\nint main(void) { printf("%zu,%zu,%zu", sizeof(' + kind + '), offsetof(' + kind + ', I2cControllers), offsetof(' + kind + ', MmHubPadding)); }\n')
            subprocess.run(["cc", str(work / "layout.c"), "-o", str(work / "layout")], check=True)
            result[name] = tuple(map(int, subprocess.check_output([str(work / "layout")], text=True).split(",")))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux", type=Path, default=Path.home() / "git/linux")
    parser.add_argument(
        "--firmware-dir", type=Path,
        help="also parse complete raw or .zst firmware inventories for all four ASICs",
    )
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1] / "src/amdgpu_rdna2.rs"
    amd = args.linux / "drivers/gpu/drm/amd"
    check_dmub_layouts(amd)
    pci_table = (amd / "amdgpu/amdgpu_drv.c").read_text()
    ucode = (amd / "amdgpu/amdgpu_ucode.c").read_text()
    dm = (amd / "display/amdgpu_dm/amdgpu_dm.c").read_text().split("static int dm_init_microcode", 1)[1]
    legacy = ucode.split("static const char *amdgpu_ucode_legacy_naming", 1)[1]

    def firmware_branch(block):
        return legacy.split(f"(block_type == {block})", 1)[1].split("} else if", 1)[0]

    def case_body(text, version):
        tag = "case IP_VERSION(" + version.replace(".", ", ") + "):"
        if tag not in text:
            raise SystemExit(f"Linux has no case for {version}")
        body = text.split(tag, 1)[1].lstrip()
        # Consecutive C switch labels share the final label's body.
        while body.startswith("case IP_VERSION("):
            body = body.split(":", 1)[1].lstrip()
        return body.split("case IP_VERSION(", 1)[0]

    firmware_sources = "\n".join(
        (amd / path).read_text()
        for path in [
            "amdgpu/psp_v11_0.c", "amdgpu/gfx_v10_0.c",
            "amdgpu/sdma_v5_2.c", "amdgpu/amdgpu_vcn.c",
            "pm/swsmu/smu11/smu_v11_0.c", "display/amdgpu_dm/amdgpu_dm.c",
        ]
    )
    chips = {
        "navi21": "SIENNA_CICHLID", "navi22": "NAVY_FLOUNDER",
        "navi23": "DIMGREY_CAVEFISH", "navi24": "BEIGE_GOBY",
    }
    hub_source = source.with_name("amdgpu_gmc_navi22_regs.rs")
    hub_text = hub_source.read_text()
    hub_members = set(re.findall(r"pub (\w+): u32", hub_text.split("struct HubRegs {", 1)[1].split("\n}", 1)[0]))
    hub_fields = {}
    hub_output = ""
    for kind, symbol, header in [
        ("gfx", "GFX", "gc/gc_10_3_0_offset.h"),
        ("mm", "MM", "mmhub/mmhub_2_0_0_offset.h"),
    ]:
        table = hub_text.split(f"const {symbol}: HubRegs = HubRegs {{", 1)[1].split("};", 1)[0]
        fields = re.findall(r"^\s*(\w+):[^\n]*// linux: (\w+)", table, re.MULTILINE)
        if not hub_members or {field for field, _ in fields} != hub_members:
            raise SystemExit(f"{symbol} table must annotate every HubRegs field")
        for field, define in fields:
            hub_fields[(kind, field)] = (header, define)
            hub_output += f'println!("hub-{kind} {field} {{}}", gmc_regs::{symbol}.{field});\n'
    discovery = (amd / "amdgpu/amdgpu_discovery.c").read_text()
    sdma_backend = discovery.split("static int amdgpu_discovery_set_sdma_ip_blocks", 1)[1]
    gfx_source = (amd / "amdgpu/gfx_v10_0.c").read_text()
    golden_selector = gfx_source.split("static void gfx_v10_0_init_golden_registers", 1)[1]
    gc_macros = {}
    for text in [(amd / "include/asic_reg/gc/gc_10_1_0_offset.h").read_text(), gfx_source]:
        gc_macros.update({key: int(value, 0) for key, value in re.findall(
            r"^#define\s+(\w+)\s+(0x[0-9a-fA-F]+|[0-9]+)\b", text, re.MULTILINE)})
    golden_expected = {}
    for asic, revision in [("navi21", 0), ("navi22", 2), ("navi23", 4), ("navi24", 5)]:
        selected = case_body(golden_selector, f"10.3.{revision}")
        tables = re.findall(r"soc15_program_register_sequence\(adev,\s*(golden_settings_\w+)", selected)
        if not tables:
            raise SystemExit(f"Linux does not select golden tables for {asic}")
        rows = []
        for table in tables:
            body = gfx_source.split(table + "[] = {", 1)[1].split("};", 1)[0]
            values = re.findall(r"SOC15_REG_GOLDEN_VALUE\(GC,\s*0,\s*(\w+),\s*"
                                r"(0x[0-9a-fA-F]+|[0-9]+),\s*(0x[0-9a-fA-F]+|[0-9]+)\)", body)
            if len(values) != body.count("SOC15_REG_GOLDEN_VALUE"):
                raise SystemExit(f"unparsed Linux golden row in {table}")
            rows.extend((gc_macros[reg + "_BASE_IDX"], gc_macros[reg], int(a, 0), int(o, 0))
                        for reg, a, o in values)
        golden_expected[asic] = rows
    gmc = (amd / "amdgpu/gmc_v10_0.c").read_text()
    gfx_backend = gmc.split("static void gmc_v10_0_set_gfxhub_funcs", 1)[1]
    mm_backend = gmc.split("static void gmc_v10_0_set_mmhub_funcs", 1)[1].split("static void", 1)[0]
    mm_source = (amd / "amdgpu/mmhub_v2_0.c").read_text()
    mm_clients = mm_source.split("static void mmhub_v2_0_init_client_info", 1)[1]
    # Query compiled Rust values, rather than reimplementing its macros in Python.
    with tempfile.TemporaryDirectory(prefix="narf-rdna2-") as directory:
        work = Path(directory)
        subprocess.run([
            "rustc", "--edition=2021", "-A", "dead_code", "--test", str(source),
            "-o", str(work / "tests"),
        ], check=True)
        subprocess.run([str(work / "tests")], check=True)
        # JSON quoting produces a valid Rust string for ordinary filesystem paths.
        import json
        harness = work / "inventory.rs"
        harness.write_text(
            "#[path = " + json.dumps(str(source)) + "] mod rdna2;\n"
            "#[path = " + json.dumps(str(hub_source)) + "] mod gmc_regs;\n"
            "fn main() { for p in rdna2::PROFILES {\n"
            'for &id in p.pci_ids { println!("id {} {:04x}", p.asic, id); }\n'
            'for (kind, v) in [("gc", p.gc_version), ("psp", p.psp_version), '
            '("smu", p.psp_version), ("sdma", p.sdma_version), ("dcn", p.dcn_version)] {'
            'println!("{} {} {}.{}.{}", kind, p.asic, v.0, v.1, v.2); }\n'
            'for v in p.vcn_versions { println!("vcn {} {}.{}.{}", p.asic, v.0, v.1, v.2); }\n'
            'for row in rdna2::golden::for_gc(p.gc_version).unwrap() {'
            'println!("golden {} {},{},{},{}", p.asic, row.base_index, row.offset, row.and_mask, row.or_mask); }\n'
            'for size in [1668, 1700, 1888] { if let Some(l) = p.power_table_layout(size) {'
            'println!("power {} {},{},{}", p.asic, l.smc_bytes, l.board_start, l.board_end); }}\n'
            "let f = p.firmware;\n"
            "for name in [f.sos, f.smc, f.sdma, f.ce, f.pfp, f.me, f.mec, "
            "f.mec2, f.rlc, f.vcn, f.dmcub] {\n"
            'println!("fw {} {}", p.asic, name); } }\n'
            'let r = rdna2::PSP_GC_REGISTERS;\n'
            'for (name, offset) in [("GCMC_VM_FB_LOCATION_BASE", r.fb_base), '
            '("GCMC_VM_FB_LOCATION_TOP", r.fb_top), ("GCMC_VM_FB_OFFSET", r.fb_offset), '
            '("CP_STAT", r.cp_status), ("RLC_RLCS_BOOTLOAD_STATUS", r.rlc_status)] {'
            'let index = if name == "RLC_RLCS_BOOTLOAD_STATUS" {r.rlc_base_index} '
            'else {r.gc_base_index}; '
            'println!("reg {} {}", name, offset); println!("reg {}_BASE_IDX {}", name, index); }\n'
            'for v in rdna2::GMC_MMHUB_VERSIONS { println!("mmhub common {}.{}.{}", v.0, v.1, v.2); }\n'
            'for v in rdna2::IH_OSSSYS_VERSIONS { println!("ih common {}.{}.{}", v.0, v.1, v.2); }\n'
            + hub_output + "}\n"
        )
        subprocess.run([
            "rustc", "--edition=2021", "-A", "dead_code", str(harness),
            "-o", str(work / "inventory"),
        ], check=True)
        output = subprocess.check_output([str(work / "inventory")], text=True)
    actual = {name: set() for name in chips}
    golden_actual = {name: [] for name in chips}
    firmware_count = 0
    version_count = 0
    register_count = 0
    for line in output.splitlines():
        kind, asic, value = line.split()
        if kind == "power":
            layout = tuple(map(int, value.split(",")))
            expected = power_layouts(args.linux)["legacy" if layout[0] == 1700 else "beige" if asic == "navi24" else "common"]
            if layout != expected:
                raise SystemExit(f"{asic} PowerPlay layout {layout} disagrees with Linux {expected}")
        elif kind == "golden":
            golden_actual[asic].append(tuple(map(int, value.split(","))))
        elif kind.startswith("hub-"):
            header, define = hub_fields[(kind.removeprefix("hub-"), asic)]
            text = (amd / "include/asic_reg" / header).read_text()
            for key, wanted in [(define, int(value)), (define + "_BASE_IDX", 0)]:
                found = re.search(r"^#define " + key + r"\s+(0x[0-9a-fA-F]+|[0-9]+)\b",
                                  text, re.MULTILINE)
                if found is None or int(found.group(1), 0) != wanted:
                    raise SystemExit(f"{kind} {key} disagrees with Linux {header}")
                register_count += 1
        elif kind == "ih":
            backend = (amd / "amdgpu/amdgpu_discovery.c").read_text().split(
                "static int amdgpu_discovery_set_ih_ip_blocks", 1)[1]
            if "&navi10_ih_ip_block" not in case_body(backend, value):
                raise SystemExit(f"Linux OSSSYS {value} does not use navi10_ih")
            version_count += 1
        elif kind == "mmhub":
            body = case_body(mm_clients, value)
            if ("amdgpu_mmhub_init_client_info" not in body
                    or '#include "mmhub/mmhub_2_0_0_offset.h"' not in mm_source
                    or "default:" not in mm_backend
                    or "&mmhub_v2_0_funcs" not in mm_backend
                    or f'case IP_VERSION({value.replace(".", ", ")}):' in mm_backend):
                raise SystemExit(f"Linux MMHUB {value} does not use the selected common backend")
            version_count += 1
        elif kind == "reg":
            header = amd / "include/asic_reg/gc/gc_10_3_0_offset.h"
            found = re.search(r"^#define mm" + asic + r"\s+(0x[0-9a-fA-F]+|[0-9]+)\b",
                              header.read_text(), re.MULTILINE)
            if found is None or int(found.group(1), 0) != int(value):
                raise SystemExit(f"PSP GC register {asic}={value} disagrees with Linux")
            register_count += 1
        elif kind == "id":
            actual[asic].add(int(value, 16))
        elif kind in ("gc", "psp", "smu", "sdma", "vcn", "dcn"):
            chip = chips[asic]
            prefix = chip.lower()
            if kind == "dcn":
                body = case_body(dm, value)
                expected = f"FIRMWARE_{chip}_DMUB"
            else:
                block, suffix = {
                    "gc": ("GC_HWIP", ""), "psp": ("MP0_HWIP", ""),
                    "smu": ("MP1_HWIP", "_smc"), "sdma": ("SDMA0_HWIP", "_sdma"),
                    "vcn": ("UVD_HWIP", "_vcn"),
                }[kind]
                body = case_body(firmware_branch(block), value)
                expected = f'"{prefix}{suffix}"'
            if expected not in body:
                raise SystemExit(f"Linux {kind} {value} does not select {asic}: {expected}")
            if kind == "gc" and "&gfxhub_v2_1_funcs" not in case_body(gfx_backend, value):
                raise SystemExit(f"Linux GC {value} does not use gfxhub_v2_1")
            if kind == "sdma" and "&sdma_v5_2_ip_block" not in case_body(sdma_backend, value):
                raise SystemExit(f"Linux SDMA {value} does not use sdma_v5_2")
            version_count += 1
        else:
            if f'"{value}"' not in firmware_sources:
                raise SystemExit(f"Linux does not declare {value}")
            firmware_count += 1
    for asic, chip in chips.items():
        if golden_actual[asic] != golden_expected[asic]:
            raise SystemExit(f"{asic} golden sequence differs from Linux (order, bank, offset or masks)")
        expected = {
            int(value, 16) for value in re.findall(
                r"\{0x1002, (0x[0-9A-Fa-f]+),[^\n]*\bCHIP_" + chip + r"\}",
                pci_table,
            )
        }
        if not expected or actual[asic] != expected:
            raise SystemExit(
                f"{asic}: missing={sorted(expected - actual[asic])}, "
                f"extra={sorted(actual[asic] - expected)}"
            )
    print(f"PASS: {sum(map(len, actual.values()))} exact PCI IDs and "
          f"{firmware_count} firmware names, {version_count} IP selections and "
          f"{register_count} GPU register fields and {sum(map(len, golden_actual.values()))} "
          f"golden rows match {args.linux}")

    if args.firmware_dir is not None:
        check_firmware(source, args.firmware_dir, chips)


def check_firmware(source, directory, chips):
    """Exercise the existing parsers on real containers, without device I/O.

    The legacy runner expects Navy filenames; aliases in a temporary directory
    let each ASIC's bytes exercise exactly those parsers without modifying them.
    This validates structure only, not signatures or hardware compatibility.
    """
    runner = source.parents[1] / "tools/navi22_conformance/fw/narf_ucode.rs"
    with tempfile.TemporaryDirectory(prefix="narf-rdna2-firmware-") as temporary:
        work = Path(temporary)
        binary = work / "parser"
        subprocess.run([
            "rustc", "--edition=2021", "-O", str(runner), "-o", str(binary),
        ], check=True)
        for asic, chip in chips.items():
            prefix = chip.lower()
            for kind in ["sos", "smc", "sdma", "ce", "pfp", "me", "mec",
                         "mec2", "rlc", "vcn", "dmcub"]:
                raw = directory / f"{prefix}_{kind}.bin"
                if raw.is_file():
                    data = raw.read_bytes()
                else:
                    compressed = raw.with_suffix(".bin.zst").resolve(strict=True)
                    data = subprocess.check_output(["zstd", "-qdc", str(compressed)])
                (work / f"navy_flounder_{kind}.bin").write_bytes(data)
            result = subprocess.run([str(binary), str(work), asic], capture_output=True, text=True)
            if result.returncode or "parse error" in result.stdout:
                raise SystemExit(f"{asic} firmware parsing failed:\n{result.stdout}\n{result.stderr}")
            print(f"PASS: {asic} real SOS/SMC/graphics/VCN/DMCUB containers parsed")


if __name__ == "__main__":
    main()

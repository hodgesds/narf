#!/usr/bin/env python3
"""Extract/check factual MT7920/21/22 headers, section tables and trailers.

Inputs must match the complete pinned SHA256. No executable or CLC payload is
copied. Metadata slices exercise the production decoders, not image acceptance.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct


SOURCES = (
    ("mt7920_patch", "mediatek/WIFI_MT7961_patch_mcu_1a_2_hdr.bin", 100384,
     "a766c4e39815e554c80ce5b1596095ff283a60db93356679fecd6494f71cee23"),
    ("mt7921_patch", "mediatek/WIFI_MT7961_patch_mcu_1_2_hdr.bin", 92192,
     "a276c06c2b772adb50b86639d33c82824ff4c21d617feb78caea74c040b873f6"),
    ("mt7922_patch", "mediatek/WIFI_MT7922_patch_mcu_1_1_hdr.bin", 137632,
     "490f19974ac232b2f95d995091e2e0d578521354c07f41cf9f0c198fce83b46d"),
    ("mt7920_ram", "mediatek/WIFI_RAM_CODE_MT7961_1a.bin", 802808,
     "3edec74ffe341b917e7fa4ddb2b68851411f2416555f10619a5900fa4b141e6c"),
    ("mt7921_ram", "mediatek/WIFI_RAM_CODE_MT7961_1.bin", 792036,
     "b94217a951518a9c14095765f367bc5dd7698f2dc033941d6f18fc2ebd6a2ab9"),
    ("mt7922_ram", "mediatek/WIFI_RAM_CODE_MT7922_1.bin", 1122084,
     "d95cef824e8fd6a51324a04eca067c2a005239451f471a96a83d0190b022e7fe"),
)


def rust_array(values):
    return "[" + ", ".join(str(value) for value in values) + "]"


def patch_metadata(blob):
    assert len(blob) >= 96
    count, = struct.unpack_from(">I", blob, 44)
    end = 96 + count * 64
    assert 0 < count <= 64 and end <= len(blob)
    regions = []
    for index in range(count):
        sec_type, offset, size, address, length, key = struct.unpack_from(">IIIIII", blob, 96 + index * 64)
        assert sec_type & 0xffff == 2 and end <= offset <= offset + length <= len(blob)
        regions.append({"sec_type": sec_type, "offset": offset, "size": size,
                        "addr": address, "len": length, "sec_key_idx": key})
    hw_sw, version, checksum = struct.unpack_from(">IIH", blob, 20)
    return blob[:end], {
        "build_date": list(blob[:16]), "platform": list(blob[16:20]),
        "hw_sw_ver": hw_sw, "patch_ver": version, "checksum": checksum,
        "n_region": count, "regions": regions,
    }


def ram_metadata(blob):
    assert len(blob) >= 36
    tail = blob[-36:]
    count = tail[2]
    start = len(blob) - 36 - count * 40
    assert 0 < count <= 64 and start >= 0
    regions = []
    payload_end = 0
    for index in range(count):
        cursor = start + index * 40
        crc, length, block, _, address, size = struct.unpack_from("<IIIIII", blob, cursor)
        regions.append({"decomp_crc": crc, "decomp_len": length, "decomp_blk_sz": block,
                        "addr": address, "len": size, "feature_set": blob[cursor + 24],
                        "region_type": blob[cursor + 25]})
        payload_end += size
    assert payload_end <= start
    return blob[start:], {
        "chip_id": tail[0], "eco_code": tail[1], "n_region": count,
        "format_ver": tail[3], "format_flag": tail[4], "fw_ver": list(tail[7:17]),
        "build_date": list(tail[17:32]), "crc": struct.unpack_from("<I", tail, 32)[0],
        "regions": regions, "payload_end": payload_end, "table_start": start,
    }


def outputs(root):
    generated = {}
    manifests = []
    patch_lines = ["#[rustfmt::skip]", "const PATCH_GOLDENS: &[PatchGolden] = &["]
    ram_lines = ["#[rustfmt::skip]", "const RAM_GOLDENS: &[RamGolden] = &["]
    for key, name, size, digest in SOURCES:
        blob = (root / name).read_bytes()
        if len(blob) != size or hashlib.sha256(blob).hexdigest() != digest:
            raise ValueError(f"unpinned input: {name}")
        patch = key.endswith("patch")
        metadata, facts = patch_metadata(blob) if patch else ram_metadata(blob)
        generated[f"{key}.metadata.bin"] = metadata
        manifests.append({"source": name, "source_size": size, "source_sha256": digest,
                          "metadata_size": len(metadata),
                          "metadata_sha256": hashlib.sha256(metadata).hexdigest(), "facts": facts})
        lines = patch_lines if patch else ram_lines
        lines.extend([f"    {'PatchGolden' if patch else 'RamGolden'} {{", f"        source: {json.dumps(name)},",
                      f"        source_sha256: {json.dumps(digest)},", f"        image_len: {size},",
                      f'        metadata: include_bytes!("{key}.metadata.bin"),',
                      f"        {'header: Connac2PatchHdr' if patch else 'trailer: Connac2FwTrailer'} {{"])
        for field, value in facts.items():
            if field in ("regions", "payload_end", "table_start"):
                continue
            value = rust_array(value) if isinstance(value, list) else str(value)
            lines.append(f"            {field}: {value},")
        lines.extend(["        },", "        regions: &["])
        for region in facts["regions"]:
            values = ", ".join(f"{name}: {value}" for name, value in region.items())
            lines.append(f"            {'Connac2PatchSection' if patch else 'Connac2FwRegion'} {{ {values} }},")
        lines.extend(["        ],", "    },"])
    patch_lines.append("];\n")
    ram_lines.append("];\n")
    generated["goldens.rs"] = ("// Generated factual tables only; no executable or CLC payload.\n"
                                + "\n".join(patch_lines + ram_lines)).encode()
    generated["provenance.json"] = (json.dumps({
        "kind": "metadata-only parser fixtures; never load into hardware",
        "decoder": "independent Python struct decoder; Linux mt76/mt76_connac_mcu.h",
        "license_note": "No executable/CLC payload copied; original vendor firmware license not supplied by this fixture.",
        "images": manifests,
    }, indent=2, sort_keys=True) + "\n").encode()
    return generated


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firmware-root", type=Path, default=Path("/lib/firmware"))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="replace generated metadata")
    mode.add_argument("--check", action="store_true", help="check generated metadata (default)")
    args = parser.parse_args()
    destination = Path(__file__).resolve().parent
    for name, data in outputs(args.firmware_root).items():
        path = destination / name
        if args.write:
            path.write_bytes(data)
        else:
            assert path.read_bytes() == data, f"stale golden: {path}"
    print("MediaTek firmware metadata matches six SHA256-pinned local images")


if __name__ == "__main__":
    main()

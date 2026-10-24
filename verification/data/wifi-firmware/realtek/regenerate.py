#!/usr/bin/env python3
"""Extract non-executable Realtek firmware geometry from local, raw sources.

Usage: python3 regenerate.py --firmware-root /lib/firmware --check
       python3 regenerate.py --firmware-root /lib/firmware --write

The layouts come from Linux drivers/net/wireless/realtek/{rtl8xxxu,rtlwifi,
rtw88,rtw89}, particularly rtw89/fw.h's packed structures. This independent
producer does not import or invoke NARF's parsers. It records full-source SHA256
and retains container/header metadata only. Executable bodies, signatures and
key bitmaps are omitted. Zero-filled structural replays are parser inputs only;
they are neither original firmware nor suitable for provisioning or boot.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys


ROOT = Path(__file__).resolve().parent
NAMES = [
    "rtlwifi/rtl8188eufw.bin",
    "rtlwifi/rtl8188efw.bin",
    "rtw88/rtw8822c_fw.bin",
    "rtw89/rtw8851b_fw-1.bin",
    "rtw89/rtw8851b_fw.bin",
    "rtw89/rtw8852a_fw-1.bin",
    "rtw89/rtw8852a_fw.bin",
    "rtw89/rtw8852b_fw-2.bin",
    "rtw89/rtw8852b_fw-1.bin",
    "rtw89/rtw8852b_fw.bin",
    "rtw89/rtw8852c_fw-2.bin",
    "rtw89/rtw8852c_fw-1.bin",
    "rtw89/rtw8852c_fw.bin",
]


def u16(data, at):
    return struct.unpack_from("<H", data, at)[0]


def u32(data, at):
    return struct.unpack_from("<I", data, at)[0]


def fragment(fragments, data, offset, length):
    assert length > 0 and 0 <= offset <= len(data) - length
    fragments.append({"offset": offset, "hex": data[offset:offset + length].hex()})


def ax_image(data, entry, fragments):
    start, size = entry["offset"], entry["length"]
    body = data[start:start + size]
    version = body[15]  # FW_HDR_W3_HDR_VER
    assert version in (0, 1)
    base = (32, 48)[version]
    count = body[25]  # FW_HDR[_V1]_W6_SEC_NUM
    assert 0 < count <= 10
    fixed = base + count * 16
    dynamic = bool(u32(body, 28) & (1 << 16))
    header = ((u32(body, 12) >> 16) & 255 if version == 0
              else u32(body, 20) >> 16) if dynamic else fixed
    assert fixed <= header <= size
    if dynamic:
        assert header - fixed >= 8 and u32(body, fixed) == header - fixed
    # Keep descriptors and dynamic length/count only, never dynamic contents.
    fragment(fragments, data, start, fixed + (8 if dynamic else 0))
    sections, position = [], header
    for index in range(count):
        desc = base + index * 16
        flags = u32(body, desc + 4)
        checksum = bool(flags & (1 << 28))
        length = (flags & 0xffffff) + (8 if checksum else 0)
        kind = (flags >> 24) & 15
        section = {
            "kind": kind,
            "address": u32(body, desc) & (0x1fffffff if version == 0 else 0xffffffff),
            "length": length,
            "checksum": checksum,
            "redownload": bool(flags & (1 << 29)),
            "offset": position,
            "pool": None,
        }
        content = position
        position += length
        assert position <= size
        mssc = u32(body, desc + 8) & (0xffffffff if version == 0 else 255)
        if kind == 9 and mssc:
            pool_start = position
            bitmap = mssc & 255 == 255
            if bitmap:
                pool = body[pool_start:pool_start + 32]
                assert pool[:8] == b"MSSKPOOL" and pool[20] == 0
                # rtw89_fw_mss_pool_hdr_v0: device/customer/key bitmap shape.
                bits = pool[21] * u16(pool, 24) * u16(pool, 26)
                assert bits % 8 == 0
                prefix = 32 + bits // 8 + (8 if pool[16] else 0)
                assert u32(pool, 8) == 32 and u32(pool, 12) == prefix
                sig_count = u16(pool, 22)
                sig_length = (u16(body, content + 60) >> 2) or 512
                # Only this structural security-header length field is needed.
                fragment(fragments, data, start + content + 60, 2)
                fragment(fragments, data, start + pool_start, 32)
            else:
                prefix, sig_count, sig_length = 0, mssc, 512
            if version == 1 and u32(body, 24) & (1 << 24):
                sig_length += 8
            pool_length = prefix + sig_count * sig_length
            section["pool"] = {
                "offset": pool_start,
                "length": pool_length,
                "signatures_offset": pool_start + prefix,
                "signature_length": sig_length,
                "signature_count": sig_count,
                "bitmap": bitmap,
            }
            position += pool_length
            assert position <= size
        sections.append(section)
    assert position == size, (entry, position, size)
    return dict(entry, version=version, major=body[4], minor=body[5],
                header_length=header, dynamic=dynamic, sections=sections)


def extract(root, name):
    data = (root / name).read_bytes()
    fragments = []
    result = {"name": name, "sha256": hashlib.sha256(data).hexdigest(),
              "length": len(data), "fragments": fragments, "images": []}
    if name.startswith("rtlwifi/"):
        fragment(fragments, data, 0, 32)
        assert u16(data, 0) == 0x88e1 and u16(data, 12) == len(data) - 32
        result["legacy"] = {"signature": u16(data, 0), "version": u16(data, 4),
                            "subversion": data[6], "payload": len(data) - 32}
    elif name.startswith("rtw88/"):
        fragment(fragments, data, 0, 64)
        assert u16(data, 0) == 0x8822
        # rtw88/fw.h: FW_HDR_DMEM/IMEM/EMEM_ADDR and *_SIZE. Each has an
        # eight-byte checksum in the file, beyond the advertised payload.
        sections = []
        position = 64
        for addr, length in ((0x20, 0x24), (0x3c, 0x30), (0x38, 0x34)):
            if length == 0x34 and not (data[0x18] & 0x10 and u32(data, length)):
                continue
            size = u32(data, length) + 8
            sections.append({"address": u32(data, addr) & 0x7fffffff,
                             "length": size, "offset": position})
            position += size
        assert position == len(data)
        result["ce"] = {"version": u16(data, 4), "subversion": data[6],
                        "h2c": u16(data, 0x1c), "sections": sections}
    else:
        assert data[0] == 255  # rtw89_mfw_hdr.sig == RTW89_MFW_SIG
        entries = data[1]
        fragment(fragments, data, 0, 16 + entries * 16)
        for index in range(entries):
            at = 16 + index * 16
            entry = {"cut": data[at], "kind": data[at + 1],
                     "manufacturing": data[at + 2] != 0,
                     "offset": u32(data, at + 4), "length": u32(data, at + 8)}
            assert entry["offset"] >= 16 + entries * 16
            assert 0 < entry["length"] <= len(data) - entry["offset"]
            # Retained AX parser admits these executable suit types. Log-format
            # entries remain bounded by the original TOC, but are not firmware.
            if entry["kind"] in (1, 3, 5, 64, 65):
                result["images"].append(ax_image(data, entry, fragments))
    fragments.sort(key=lambda f: f["offset"])
    end = 0
    for part in fragments:
        assert end <= part["offset"]
        end = part["offset"] + len(part["hex"]) // 2
    return result


def rust_bytes(hexadecimal):
    values = ["0x" + hexadecimal[i:i + 2] for i in range(0, len(hexadecimal), 2)]
    return "&[" + ", ".join(values) + "]"


def render(manifest):
    lines = [
        "// Generated by regenerate.py from raw local Linux firmware sources.",
        "// Source SHA256 identifies ORIGINAL files, not zero-payload replays.",
        "// Metadata only: never register or boot these structural parser inputs.",
        "#[derive(Debug)]",
        "pub struct Source {",
        "    pub name: &'static str,",
        "    pub sha256: &'static str,",
        "    pub length: usize,",
        "    pub fragments: &'static [(usize, &'static [u8])],",
        "    pub images: &'static [Image],",
        "}",
        "#[derive(Debug)]",
        "pub struct Image {",
        "    pub cut: u8,",
        "    pub kind: u8,",
        "    pub manufacturing: bool,",
        "    pub offset: usize,",
        "    pub length: usize,",
        "    pub version: u8,",
        "    pub major: u8,",
        "    pub minor: u8,",
        "    pub header_length: usize,",
        "    pub dynamic: bool,",
        "    pub sections: &'static [Section],",
        "}",
        "#[derive(Debug)]",
        "pub struct Section {",
        "    pub kind: u8,",
        "    pub address: u32,",
        "    pub length: u32,",
        "    pub checksum: bool,",
        "    pub redownload: bool,",
        "    pub offset: usize,",
        "    pub pool: Option<Pool>,",
        "}",
        "#[derive(Debug)]",
        "pub struct Pool {",
        "    pub offset: usize,",
        "    pub length: usize,",
        "    pub signatures_offset: usize,",
        "    pub signature_length: usize,",
        "    pub signature_count: usize,",
        "    pub bitmap: bool,",
        "}",
    ]
    for i, source in enumerate(manifest["sources"]):
        lines += [f"pub const SOURCE_{i}: Source = Source {{",
                  f'    name: "{source["name"]}",',
                  f'    sha256: "{source["sha256"]}",',
                  f'    length: {source["length"]},', "    fragments: &["]
        for part in source["fragments"]:
            lines.append(f'        ({part["offset"]}, {rust_bytes(part["hex"])}),')
        lines += ["    ],", "    images: &["]
        for image in source["images"]:
            lines.append("        Image {")
            for key in ("cut", "kind", "manufacturing", "offset", "length",
                        "version", "major", "minor", "header_length", "dynamic"):
                lines.append(f"            {key}: {str(image[key]).lower()},")
            lines.append("            sections: &[")
            for section in image["sections"]:
                lines.append("                Section {")
                for key in ("kind", "address", "length", "checksum", "redownload", "offset"):
                    lines.append(f"                    {key}: {str(section[key]).lower()},")
                if section["pool"] is None:
                    lines.append("                    pool: None,")
                else:
                    lines.append("                    pool: Some(Pool {")
                    for key, value in section["pool"].items():
                        lines.append(f"                        {key}: {str(value).lower()},")
                    lines.append("                    }),")
                lines.append("                },")
            lines += ["            ],", "        },"]
        lines += ["    ],", "};"]
    lines.append("pub const AX: &[Source] = &[")
    lines += [f"    SOURCE_{i}," for i in range(3, len(manifest["sources"]))]
    lines.append("];")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firmware-root", type=Path, default=Path("/lib/firmware"))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args()
    try:
        manifest = {"format": 1, "provenance": "raw Linux firmware metadata; opaque bytes omitted",
                    "sources": [extract(args.firmware_root, name) for name in NAMES]}
        products = {"manifest.json": json.dumps(manifest, indent=2) + "\n",
                    "metadata.rs": render(manifest)}
        for name, content in products.items():
            path = ROOT / name
            if args.write:
                path.write_text(content)
            elif path.read_text() != content:
                raise ValueError(f"{name}: source hash or metadata differs; review before --write")
        print(f"Realtek metadata {'written' if args.write else 'verified'}: "
              f"{len(manifest['sources'])} raw sources, "
              f"{sum(len(s['images']) for s in manifest['sources'])} AX images")
    except (OSError, ValueError, AssertionError, struct.error) as error:
        print(f"Realtek metadata failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Extract metadata facts from pinned installed Qualcomm firmware (stdlib only).

Formats: Linux ath10k/{hw.h,core.c}, ath11k/{hw.h,core.c,fw.c}.
Retain container magic, IE headers and names/scalars; opaque image, OTP,
board-calibration and REGDB payloads are omitted. Raw AMSS/M3 retains only
the ELF32 header. Replays preserve source offsets and lengths with zero gaps.
These are parser inputs, never firmware-registry or hardware-boot inputs.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct


SOURCES = {
    "qca988x_api5": ("ath10k/QCA988X/hw2.0/firmware-5.bin", "15867031c87f1d7408c1b25fb6419077a1b97de208f2aa58c3266b60e1f8daa2"),
    "qca6174_api6": ("ath10k/QCA6174/hw3.0/firmware-6.bin", "04d3bad5efa3f9fbe3ba53fd3e25fa9b0585ed227eea8111303b4e08861f979d"),
    "qca6174_board2": ("ath10k/QCA6174/hw3.0/board-2.bin", "66e83dde1c9af535df1fcd17c72971a96a263357300e921b358d35a353227d60"),
    "qca6390_board2": ("ath11k/QCA6390/hw2.0/board-2.bin", "4aa9f0fe15e9e2b6f9bb13b7187ed8ce035d9d46fb65fac5d5eba2c4e7edc091"),
    "wcn6855_board2": ("ath11k/WCN6855/hw2.0/board-2.bin", "9287fa8d14d915892666b03e9403135875d08371fd1438d2c6d9fe96ae71cf68"),
    "qca6390_amss": ("ath11k/QCA6390/hw2.0/amss.bin", "8ab2a06422e3989012df423bb6a156fde2c3feb4cd5db4c5d3588f674dc872ff"),
    "qca6390_m3": ("ath11k/QCA6390/hw2.0/m3.bin", "1921d25edb52f90a7a0acc7275861e14399f904d579aae9f7ab1c4d28533fad6"),
    "wcn6855_amss": ("ath11k/WCN6855/hw2.0/amss.bin", "e12b23ddc4b8d2d2a10a651a5d6fdcd00f60fcae884d2cf5dad17627211fcdfd"),
    "wcn6855_m3": ("ath11k/WCN6855/hw2.0/m3.bin", "0c590881870d0e6e98fc7d393ce05690e09287933b1b535e935bf5d98b77713f"),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def ies(data, start, end):
    """Independent little-endian IE walk; no NARF encoder/parser involved."""
    at = start
    while at < end:
        if at + 8 > end:
            raise ValueError("truncated IE header")
        kind, size = struct.unpack_from("<II", data, at)
        stop = at + 8 + ((size + 3) & ~3)
        if stop > end:
            raise ValueError("truncated IE body/padding")
        yield at, kind, at + 8, size
        at = stop


def extract(key, data):
    ranges = []
    facts = {}
    if "_api" in key:
        assert data.startswith(b"QCA-ATH10K\0")
        ranges.append((0, 12))
        entries = []
        for header, kind, offset, size in ies(data, 12, len(data)):
            ranges.append((header, 8))
            if kind in (0, 1, 2, 5, 6):
                ranges.append((offset, size))
            entries.append({"id": kind, "offset": offset, "size": size})
            if kind in (2, 5, 6):
                facts[{2: "features", 5: "wmi", 6: "htt"}[kind]] = int.from_bytes(data[offset:offset + size], "little")
            if kind in (3, 4, 7):
                facts[{3: "image", 4: "otp", 7: "codeswap"}[kind]] = [offset, size]
        facts["entries"] = entries
        facts["api"] = int(key[-1])
    elif key.endswith("board2"):
        magic = b"QCA-ATH10K-BOARD\0" if key.startswith("qca6174") else b"QCA-ATH11K-BOARD\0"
        assert data[:len(magic)] == magic
        start = (len(magic) + 3) & ~3
        ranges.append((0, start))
        records = []
        count = 0
        for header, kind, offset, size in ies(data, start, len(data)):
            ranges.append((header, 8))
            names = []
            for subheader, subkind, suboffset, subsize in ies(data, offset, offset + size):
                ranges.append((subheader, 8))
                if subkind == 0:
                    ranges.append((suboffset, subsize))
                    names.append(data[suboffset:suboffset + subsize].decode("ascii"))
                elif subkind == 1:
                    records.extend({"kind": kind, "name": name, "offset": suboffset, "size": subsize} for name in names)
                    names = []
            count += 1
        samples = []
        for kind in sorted({record["kind"] for record in records}):
            same = [record for record in records if record["kind"] == kind]
            for index in sorted({0, len(same) // 2, len(same) - 1}):
                samples.append(same[index])
        facts = {"top_level_ie_count": count, "board_name_count": len(records), "samples": samples}
    else:
        assert data[:7] == b"\x7fELF\x01\x01\x01"
        ranges.append((0, 52))  # ELF32_Ehdr only, never program segments.
        facts = {"format": "ELF32 little-endian raw image; not firmware-2 IE container"}
    ranges.sort()
    merged = []
    for offset, size in ranges:
        if merged and merged[-1][0] + merged[-1][1] == offset:
            merged[-1] = (merged[-1][0], merged[-1][1] + size)
        else:
            assert not merged or merged[-1][0] + merged[-1][1] < offset
            merged.append((offset, size))
    metadata = b"".join(data[offset:offset + size] for offset, size in merged)
    fragments = []
    packed = 0
    for offset, size in merged:
        fragments.append((offset, packed, size))
        packed += size
    return metadata, fragments, facts


def rust_metadata(key, source, sha, data, fragments):
    return [
        "        metadata: MetadataGolden {",
        f"            source: {json.dumps(source)},",
        f"            source_sha256: {json.dumps(sha)},",
        f"            image_len: {len(data)},",
        f'            bytes: include_bytes!("{key}.metadata.bin"),',
        "            fragments: &[" + ", ".join(f"({a}, {b}, {c})" for a, b, c in fragments) + "],",
        "        },",
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firmware-root", type=Path, default=Path("/lib/firmware"))
    parser.add_argument("--check", action="store_true", help="compare without rewriting")
    args = parser.parse_args()
    output = Path(__file__).resolve().parent
    generated = {}
    tables = {"ath10k_firmware": [], "ath10k_board": [], "ath11k_board": [], "ath11k_raw": []}
    images = []
    for key, (source, sha) in SOURCES.items():
        data = (args.firmware_root / source).read_bytes()
        if digest(data) != sha:
            raise SystemExit(f"{source}: source SHA256 differs from pin")
        metadata, fragments, facts = extract(key, data)
        generated[f"{key}.metadata.bin"] = metadata
        images.append({"source": source, "source_sha256": sha, "source_size": len(data), "metadata_sha256": digest(metadata), "metadata_size": len(metadata), "facts": facts})
        base = rust_metadata(key, source, sha, data, fragments)
        if "_api" in key:
            table = tables["ath10k_firmware"]
            table.extend(["    ImageGolden {"] + base)
            for fact in ("api", "features", "wmi", "htt"):
                table.append(f"        {fact}: {facts[fact]},")
            for fact in ("image", "otp"):
                offset, size = facts[fact]
                table.append(f"        {fact}: ({offset}, {size}),")
            table.extend(["    },"])
        elif key.endswith("board2"):
            table = tables["ath10k_board" if key.startswith("qca6174") else "ath11k_board"]
            table.extend(["    BoardGolden {"] + base + ["        samples: &["])
            for sample in facts["samples"]:
                table.append("            BoardSample { kind: %d, name: %s, offset: %d, len: %d }," % (sample["kind"], json.dumps(sample["name"]), sample["offset"], sample["size"]))
            table.extend(["        ],", "    },"])
        else:
            tables["ath11k_raw"].extend(["    RawGolden {"] + base + ["    },"])
    for name, table in tables.items():
        kind = {"ath10k_firmware": "ImageGolden", "ath10k_board": "BoardGolden", "ath11k_board": "BoardGolden", "ath11k_raw": "RawGolden"}[name]
        const = {"ath10k_firmware": "IMAGE_GOLDENS", "ath10k_board": "BOARD_GOLDENS", "ath11k_board": "BOARD_GOLDENS", "ath11k_raw": "RAW_GOLDENS"}[name]
        generated[name + ".rs"] = ("// Generated by regen.py from pinned raw sources; opaque payloads omitted.\n#[rustfmt::skip]\nconst " + const + ": &[" + kind + "] = &[\n" + "\n".join(table) + "\n];\n").encode()
    manifest = {
        "schema": "narf-wifi-metadata-replay-v1",
        "decoder": "independent Python struct/unicode decoder; Linux ath10k/hw.h and ath11k/hw.h",
        "policy": "Preserve source geometry; retain magic/IE headers, scalar metadata, board identities and raw ELF headers. Zero all executable, OTP, calibration and REGDB payloads. Parser tests only, never registry/boot inputs or board qualification.",
        "images": images,
        "aliases": {"ath11k/WCN6855/hw2.1/" + name: "ath11k/WCN6855/hw2.0/" + name for name in ("amss.bin", "m3.bin", "board-2.bin")},
        "unavailable": ["ath11k/QCA6390/hw2.0/firmware-2.bin", "ath11k/WCN6855/hw2.0/firmware-2.bin", "ath11k/WCN6855/hw2.1/firmware-2.bin"],
        "raw_board_fallbacks_excluded": "ath10k board.bin is opaque calibration, not an IE parser input; no calibrated board or physical device is qualified here.",
    }
    # Check aliases and declared absences independently; never invent an API2 container.
    for alias, source in manifest["aliases"].items():
        if (args.firmware_root / alias).read_bytes() != (args.firmware_root / source).read_bytes():
            raise SystemExit(f"alias differs: {alias}")
    for absent in manifest["unavailable"]:
        if (args.firmware_root / absent).exists():
            raise SystemExit(f"new source available; review missing coverage: {absent}")
    generated["provenance.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    for name, content in generated.items():
        path = output / name
        if args.check:
            if not path.exists() or path.read_bytes() != content:
                raise SystemExit(f"stale fixture: {path}")
        else:
            path.write_bytes(content)
    print(f"Qualcomm: {len(images)} pinned sources, {len(generated)} fixture artifacts verified")


if __name__ == "__main__":
    main()

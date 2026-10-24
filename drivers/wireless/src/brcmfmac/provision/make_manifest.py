#!/usr/bin/env python3
"""Encode explicit deployment facts as raw NBSP v1; never infer a board.

Input: JSON array of records. Each record supplies family (pcie43602 or
sdio43439), board, revisions, host (kind, address, vendor, device,
subsystem_vendor, subsystem_device, class), and assets with key/path/signed.
PCI address is [segment,bus,device,function]; MMIO address is a number.
SDIO additionally supplies card=[function,vendor,device]. Asset paths are raw
payloads; set wrapped=true explicitly to strip an existing NRFW trailer.
Sign/package this output with the existing xtask pack-firmware workflow.
--fixtures generates only deliberately synthetic, nondeployment Rust literals.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

HEADER, RECORD, ASSET = 16, 616, 168


def number(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def text(value, size, key=False):
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
    if key:
        allowed += "/"
    if not value or len(value) >= size or any(c not in allowed for c in value):
        raise ValueError("invalid name")
    if key and any(part in ("", ".", "..") for part in value.split("/")):
        raise ValueError("invalid key components")
    return value.encode("ascii").ljust(size, b"\0")


def payload(asset):
    if "fixture" in asset:
        return bytes(asset["fixture"])
    data = Path(asset["path"]).read_bytes()
    if asset.get("wrapped", False):
        if len(data) < 104 or data[-4:] != b"NRFW":
            raise ValueError("not an NRFW envelope")
        end = len(data) - 104 - int.from_bytes(data[-8:-4], "little")
        if end <= 0:
            raise ValueError("invalid NRFW extent")
        data = data[:end]
    return data


def encode(records):
    if not 1 <= len(records) <= 16:
        raise ValueError("record count")
    result = bytearray(struct.pack("<4sHHIHH", b"NBSP", 1, HEADER,
                                   HEADER + RECORD * len(records), len(records), RECORD))
    selectors = set()
    for record in records:
        family = {"pcie43602": 1, "sdio43439": 2}[record["family"]]
        chip = 43602 if family == 1 else 43439
        card = tuple(map(number, record.get("card", [0, 0, 0])))
        revisions = number(record["revisions"])
        if not 0 < revisions <= 0xffff or len(card) != 3:
            raise ValueError("revision/card")
        host = record["host"]
        if host["kind"] == "pci":
            segment, bus, device, function = map(number, host["address"])
            if not (0 <= segment <= 65535 and 0 <= bus <= 255 and
                    0 <= device <= 31 and 0 <= function <= 7):
                raise ValueError("PCI address")
            address, kind = segment << 24 | bus << 16 | device << 8 | function, 1
        else:
            if host["kind"] != "mmio" or family != 2:
                raise ValueError("host kind")
            address, kind = number(host["address"]), 2
            if address <= 0 or address % 4:
                raise ValueError("MMIO address")
        ids = tuple(number(host[name]) for name in
                    ("vendor", "device", "subsystem_vendor", "subsystem_device"))
        class_id = number(host["class"])
        if family == 1 and (ids[0] != 0x14e4 or ids[1] not in (0x43ba, 0x43bb, 0x43bc) or card != (0, 0, 0)):
            raise ValueError("PCIe profile")
        if family == 2 and (card not in ((1, 0x2d0, 0xa9af), (1, 0x4b4, 0xbd3d)) or
                            kind == 1 and class_id not in (0x080500, 0x080501)):
            raise ValueError("SDIO profile")
        selector = family, kind, address, ids, class_id, card
        if selector in selectors:
            raise ValueError("ambiguous duplicate selector")
        selectors.add(selector)
        row = bytearray(RECORD)
        struct.pack_into("<BBHHBBQHHHHIHH", row, 0, family, card[0], chip, revisions,
                         kind, 0, address, *ids, class_id, card[1], card[2])
        row[32:96] = text(record["board"], 64)
        assets = record["assets"]
        if len(assets) != (2 if family == 1 else 3):
            raise ValueError("asset count")
        keys = set()
        for role, asset in enumerate(assets, 1):
            data = payload(asset)
            signed = asset.get("signed", role != 1)
            if role != 1 and not signed:
                raise ValueError("calibration/CLM always needs a verified signer")
            if not 0 < len(data) <= (64000 if role == 2 else 16 * 1024 * 1024):
                raise ValueError("asset extent")
            if role == 1 and (family == 1 and len(data) < 4 or family == 2 and len(data) > 4 * 1024 * 1024):
                raise ValueError("retained executable shape")
            if asset["key"] in keys:
                raise ValueError("duplicate asset key")
            keys.add(asset["key"])
            offset = 112 + (role - 1) * ASSET
            struct.pack_into("<BBHI", row, offset, role, int(signed), 0, len(data))
            row[offset + 8:offset + 40] = hashlib.sha256(data).digest()
            row[offset + 40:offset + ASSET] = text(asset["key"], 128, True)
        result.extend(row)
    return bytes(result)


def fixtures(path):
    # Unpopulated synthetic segment; keys are never production canonical names.
    assets = [dict(key="narf-test/brcm/fw", fixture=[0x44, 0x33, 0x22, 0x11, 9, 8, 7, 6]),
              dict(key="narf-test/brcm/nv", fixture=list(b"boardrev=1\n"))]
    records = [dict(family="pcie43602", board="synthetic-not-a-board", revisions=8,
                    host=dict(kind="pci", address=[65534, 250, 29, 3], vendor=0x14e4,
                              device=0x43ba, subsystem_vendor=0x106b, subsystem_device=0x133, **{"class": 0x028000}), assets=assets),
               dict(family="sdio43439", board="synthetic-not-a-board", revisions=1,
                    card=[1, 0x2d0, 0xa9af], host=dict(kind="pci", address=[65534, 250, 28, 2], vendor=0x1abc,
                    device=0x1234, subsystem_vendor=0x1234, subsystem_device=0x5678, **{"class": 0x080500}),
                    assets=assets + [dict(key="narf-test/brcm/clm", fixture=list(b"inert-clm"))])]
    data = encode(records)
    with Path(path).open("w") as output:
        output.write("// Independent Python struct/hashlib NBSP v1 encoder; synthetic test identities only.\n")
        output.write(f"const MANIFEST_BYTES: [u8; {len(data)}] = [\n")
        for offset in range(0, len(data), 16):
            output.write(",".join(f"0x{byte:02x}" for byte in data[offset:offset + 16]) + ",\n")
        output.write("];\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?")
    parser.add_argument("output", nargs="?")
    parser.add_argument("--fixtures")
    args = parser.parse_args()
    if args.fixtures:
        fixtures(args.fixtures)
    elif args.input and args.output:
        Path(args.output).write_bytes(encode(json.loads(Path(args.input).read_text())))
    else:
        parser.error("supply input.json output.bin or --fixtures output.rs")

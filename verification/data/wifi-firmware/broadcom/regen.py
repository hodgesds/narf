#!/usr/bin/env python3
"""Extract/check installed BCM43602 metadata without executable payloads.

Linux brcmfmac/pcie.c: BRCMF_RAMSIZE_OFFSET is 0x6c; optional magic
0x534d4152 precedes a little-endian RAM size. This pinned image has no
such magic. Retain the reset-vector word and eight metadata-window bytes
only, at their original offsets. No boot/registry/calibration input.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct


SOURCE = "brcm/brcmfmac43602-pcie.bin"
SHA256 = "bf4cfc23ee952a3d82ef33a0f5f87853201c98f1bed034876a910f354f37862d"
ABSENT = [
    "brcm/brcmfmac43439-sdio.bin", "43439A0.bin",
    "brcm/brcmfmac43439-sdio.txt", "43439A0.txt",
    "brcm/brcmfmac43439-sdio.clm_blob", "43439A0_clm.bin",
    "brcm/brcmfmac43602-pcie.txt",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firmware-root", type=Path, default=Path("/lib/firmware"))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    output = Path(__file__).resolve().parent
    data = (args.firmware_root / SOURCE).read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise SystemExit("BCM43602 source SHA256 differs from pin")
    for absent in ABSENT:
        if (args.firmware_root / absent).exists():
            raise SystemExit(f"new source available; review missing coverage: {absent}")
    metadata = data[:4] + data[0x6c:0x74]
    vector = struct.unpack_from("<I", data)[0]
    magic, candidate_size = struct.unpack_from("<II", data, 0x6c)
    ram = f"Some({candidate_size})" if magic == 0x534d4152 else "None"
    rust = f'''// Generated factual metadata; no executable image or board qualification.
const SOURCE: &str = {json.dumps(SOURCE)};
const SOURCE_SHA256: &str = {json.dumps(SHA256)};
const IMAGE_LEN: usize = {len(data)};
const RESET_VECTOR_WORD: u32 = {vector};
const RAMSIZE: Option<u32> = {ram};
const METADATA: &[u8] = include_bytes!("bcm43602.metadata.bin");
const FRAGMENTS: &[(usize, usize, usize)] = &[(0, 0, 4), (108, 4, 8)];
'''
    provenance = {
        "schema": "narf-wifi-metadata-replay-v1",
        "source": SOURCE, "source_sha256": SHA256, "source_size": len(data),
        "metadata_sha256": hashlib.sha256(metadata).hexdigest(), "metadata_size": len(metadata),
        "decoder": "independent Python struct decoder; Linux brcmfmac/pcie.c BRCMF_RAMSIZE_{MAGIC,OFFSET}",
        "facts": {"reset_vector_word": vector, "ram_metadata_offset": 108, "ram_metadata_magic": magic, "embedded_ramsize": candidate_size if magic == 0x534d4152 else None, "trx_wrapped": vector == 0x30524448},
        "policy": "Only reset-vector word and optional RAM metadata window retained; opaque executable payload zeroed. Parser tests only: never firmware registry, boot input, or BCM43602 board admission.",
        "unavailable": ABSENT,
        "open": "No exact CYW43439 firmware/NVRAM/CLM source and no qualified BCM43602 board NVRAM here. No other board NVRAM is substituted. Physical radio validation remains open.",
    }
    generated = {"bcm43602.metadata.bin": metadata, "goldens.rs": rust.encode(), "provenance.json": (json.dumps(provenance, indent=2, sort_keys=True) + "\n").encode()}
    for name, content in generated.items():
        path = output / name
        if args.check:
            if not path.exists() or path.read_bytes() != content:
                raise SystemExit(f"stale fixture: {path}")
        else:
            path.write_bytes(content)
    print("Broadcom: 1 pinned source, 3 fixture artifacts verified; exact CYW43439 assets absent")


if __name__ == "__main__":
    main()

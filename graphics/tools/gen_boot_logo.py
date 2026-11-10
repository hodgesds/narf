#!/usr/bin/env python3
"""Generate NARF boot-logo pixel blobs from the sloth grid artwork.

Source of truth: graphics/assets/narf-sloth-grid.png — the 2x2 grid of
sloth logo variants (1254x1254, supplied 2026-11-09). This script crops
the two quadrants used at boot, downscales them with Lanczos, and emits
raw RGB565 little-endian pixel data (no header) for the kernel to
`include_bytes!`.

Outputs (written next to the grid PNG):
  boot-tile.rgb565     — bottom-right quadrant ("lying" sloth), 64x64.
                         One tile per CPU, Tux-style, across the top of
                         the end-of-boot panel.
  splash-circle.rgb565 — bottom-left quadrant (orange circle), 256x256.
                         Single centered logo for the virtio-gpu early
                         splash.

Why RGB565: the framebuffer is XRGB8888, so RGB888 would blit with a
trivial pack — but RGB565 halves the embedded size (tile 16 KiB ->
8 KiB, circle 256 KiB -> 128 KiB, total ~136 KiB) for no visible loss
at these sizes: the art is flat colours and the blit expands 5/6-bit
channels back to 8-bit. No PNG decoder in the kernel (deliberate):
the decode happens here, at authoring time, and the checked-in blobs
are reproducible from the grid PNG.

Usage:
  python3 graphics/tools/gen_boot_logo.py [--check]
  --check verifies the checked-in blobs match a fresh regeneration
  (byte-identical) and exits non-zero on any drift.

Requires Pillow (pip install pillow).
"""

import hashlib
import struct
import sys
from pathlib import Path

from PIL import Image

HERE = Path(__file__).resolve().parent
ASSETS = HERE.parent / "assets"
GRID = ASSETS / "narf-sloth-grid.png"

# (quadrant origin, output size, output name)
TARGETS = (
    # bottom-right: lying sloth, the per-CPU tile.
    ("bottom-right", (1, 1), 64, ASSETS / "boot-tile.rgb565"),
    # bottom-left: orange circle, the centered early-splash logo.
    ("bottom-left", (0, 1), 256, ASSETS / "splash-circle.rgb565"),
)


def rgb565(pixel):
    r, g, b = pixel[:3]
    return struct.pack(
        "<H", ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
    )


def generate(grid):
    w, h = grid.size
    qw, qh = w // 2, h // 2
    blobs = {}
    for name, (qx, qy), size, _out in TARGETS:
        quad = grid.crop((qx * qw, qy * qh, (qx + 1) * qw, (qy + 1) * qh))
        small = quad.convert("RGB").resize((size, size), Image.LANCZOS)
        data = b"".join(rgb565(small.getpixel((x, y)))
                        for y in range(size) for x in range(size))
        blobs[name] = (size, data)
    return blobs


def main():
    check = "--check" in sys.argv
    grid = Image.open(GRID)
    assert grid.size == (1254, 1254), f"unexpected grid size {grid.size}"
    blobs = generate(grid)
    ok = True
    for name, _origin, size, out in TARGETS:
        _n, data = blobs[name]
        digest = hashlib.sha256(data).hexdigest()[:16]
        if check:
            current = out.read_bytes() if out.exists() else b""
            match = current == data
            ok = ok and match
            print(f"{out.name}: {len(data)} bytes sha256:{digest} "
                  f"{'OK' if match else 'DRIFT — regenerate'}")
        else:
            out.write_bytes(data)
            print(f"{out.name}: {len(data)} bytes ({size}x{size} RGB565) "
                  f"sha256:{digest}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

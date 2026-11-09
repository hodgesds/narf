#!/usr/bin/env python3
"""Inspect the authenticated .narf PE section; never execute a selected image."""
import argparse
import hashlib
import hmac
import json
import pathlib
import struct

MAGIC = b"NARF_EFI_BUNDLE\0"
PARTS = ("kernel", "initramfs", "cmdline")


def inspect(image):
    def integer(offset, fmt):
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(image):
            raise ValueError("truncated PE header")
        return struct.unpack_from(fmt, image, offset)[0]

    if image[:2] != b"MZ":
        raise ValueError("missing DOS signature")
    pe = integer(60, "<I")
    if image[pe:pe + 4] != b"PE\0\0" or integer(pe + 4, "<H") != 0x8664:
        raise ValueError("not an x86_64 PE image")
    count, optional_size = integer(pe + 6, "<H"), integer(pe + 20, "<H")
    optional = pe + 24
    if optional_size < 112 or integer(optional, "<H") != 0x20B or not 1 <= count <= 96:
        raise ValueError("unsupported PE headers")
    table = optional + optional_size
    headers = integer(optional + 60, "<I")
    if table + count * 40 > headers or headers > len(image):
        raise ValueError("invalid PE section table")
    cert = (0, 0)
    if integer(optional + 108, "<I") >= 5:
        if optional_size < 152:
            raise ValueError("truncated PE data directories")
        cert = (integer(optional + 144, "<I"), integer(optional + 148, "<I"))
    sections = []
    for i in range(count):
        row = table + i * 40
        if image[row:row + 8].rstrip(b"\0") != b".narf":
            continue
        virtual, raw_size, raw = integer(row + 8, "<I"), integer(row + 16, "<I"), integer(row + 20, "<I")
        if raw < headers or not 256 <= virtual <= raw_size or raw + raw_size > len(image):
            raise ValueError("invalid .narf section extent")
        if cert[1] and raw < cert[0] + cert[1] and cert[0] < raw + raw_size:
            raise ValueError("bundle overlaps Authenticode certificate storage")
        sections.append((raw, virtual))
    if len(sections) != 1:
        raise ValueError("expected exactly one .narf section")
    raw, virtual = sections[0]
    section = image[raw:raw + virtual]
    if section[:16] != MAGIC or struct.unpack_from("<II", section, 16) != (1, 256):
        raise ValueError("unsupported native bundle")
    total = struct.unpack_from("<Q", section, 24)[0]
    if not 256 <= total <= len(section) or any(section[176:256]):
        raise ValueError("invalid native bundle header")
    cursor, parts = 256, {}
    for i, name in enumerate(PARTS):
        offset, size = struct.unpack_from("<QQ", section, 32 + i * 16)
        if offset != cursor or offset + size > total:
            raise ValueError("invalid native bundle part extent")
        data = section[offset:offset + size]
        digest = hashlib.sha256(data).digest()
        if not hmac.compare_digest(digest, section[80 + i * 32:112 + i * 32]):
            raise ValueError(f"{name} SHA-256 mismatch")
        parts[name] = {"offset": raw + offset, "size": size, "sha256": digest.hex()}
        cursor = (offset + size + 7) & ~7
    if cursor != total or not parts["kernel"]["size"] or not parts["initramfs"]["size"]:
        raise ValueError("incomplete native bundle")
    kernel = image[parts["kernel"]["offset"]:][:parts["kernel"]["size"]]
    cpio = image[parts["initramfs"]["offset"]:][:parts["initramfs"]["size"]]
    command = image[parts["cmdline"]["offset"]:][:parts["cmdline"]["size"]]
    if len(kernel) < 64 or kernel[:7] != b"\x7fELF\2\1\1" or struct.unpack_from("<H", kernel, 18)[0] != 62:
        raise ValueError("bundle kernel is not x86_64 ELF64")
    if not cpio.startswith(b"070701") or len(command) >= 2048 or b"\0" in command:
        raise ValueError("invalid initramfs or command line")
    command.decode("utf-8")
    return {"format": "narf-efi-bundle-v1", "architecture": "x86_64", "parts": parts}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=pathlib.Path)
    parser.add_argument("--kernel", type=pathlib.Path)
    parser.add_argument("--extract", type=pathlib.Path)
    parser.add_argument("--manifest", type=pathlib.Path)
    parser.add_argument("--tamper", choices=PARTS)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    if args.image.stat().st_size > 2 * 1024**3:
        parser.error("EFI image exceeds 2 GiB")
    image = args.image.read_bytes()
    try:
        manifest = inspect(image)
        if args.kernel and hashlib.sha256(args.kernel.read_bytes()).hexdigest() != manifest["parts"]["kernel"]["sha256"]:
            raise ValueError("selected kernel differs from embedded kernel")
        if args.extract:
            args.extract.mkdir(parents=True, exist_ok=True)
            for name, filename in zip(PARTS, ("kernel.elf", "initramfs.cpio", "cmdline")):
                part = manifest["parts"][name]
                (args.extract / filename).write_bytes(image[part["offset"]:part["offset"] + part["size"]])
        if args.tamper:
            if not args.output or args.output.resolve() == args.image.resolve():
                raise ValueError("tampering requires a distinct --output file")
            part = manifest["parts"][args.tamper]
            if not part["size"]:
                raise ValueError("cannot tamper with an empty part")
            modified = bytearray(image)
            modified[part["offset"]] ^= 1
            args.output.write_bytes(modified)
        encoded = json.dumps(manifest, sort_keys=True, indent=2) + "\n"
        if args.manifest:
            args.manifest.write_text(encoded)
        elif not args.extract and not args.tamper:
            print(encoded, end="")
    except (ValueError, UnicodeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()

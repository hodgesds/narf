#!/usr/bin/env python3
"""Bind one Limine configuration digest into an x86_64 EFI executable."""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import struct
import tempfile


MARKER = b"++CONFIG_B2SUM_SIGNATURE++"
PLACEHOLDER = b"0" * 128
X86_64_PE_MACHINE = 0x8664


def pe_machine(image: bytes) -> int:
    if len(image) < 64 or image[:2] != b"MZ":
        raise ValueError("loader is not a PE/COFF executable")
    pe_offset = struct.unpack_from("<I", image, 60)[0]
    if pe_offset > 1024 * 1024 or pe_offset + 6 > len(image):
        raise ValueError("loader has an invalid PE header offset")
    if image[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("loader has no PE signature")
    return struct.unpack_from("<H", image, pe_offset + 4)[0]


def bind(loader: bytes, config: bytes) -> bytes:
    if pe_machine(loader) != X86_64_PE_MACHINE:
        raise ValueError("loader is not an x86_64 PE/COFF EFI executable")
    if loader.count(MARKER) != 1:
        raise ValueError("loader does not contain exactly one Limine config binding")
    offset = loader.index(MARKER) + len(MARKER)
    embedded = loader[offset : offset + len(PLACEHOLDER)]
    digest = hashlib.blake2b(config, digest_size=64).hexdigest().encode("ascii")
    if len(embedded) != len(digest):
        raise ValueError("loader has a truncated Limine config binding")
    if embedded == digest:
        return loader
    if embedded != PLACEHOLDER:
        raise ValueError("loader is already bound to a different Limine config")
    return loader[:offset] + digest + loader[offset + len(digest) :]


def write_atomic(path: pathlib.Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("loader", type=pathlib.Path)
    parser.add_argument("config", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    args = parser.parse_args()
    write_atomic(args.output, bind(args.loader.read_bytes(), args.config.read_bytes()))


if __name__ == "__main__":
    main()

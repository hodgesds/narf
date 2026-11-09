#!/usr/bin/env python3
"""Independent PE/bundle fixtures for packaging and malformed-image tests."""
import hashlib
import importlib.util
import pathlib
import struct
import sys
import unittest

spec = importlib.util.spec_from_file_location("native_efi", pathlib.Path(__file__).with_name("native-efi.py"))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def fixture():
    kernel = bytearray(64)
    kernel[:7] = b"\x7fELF\2\1\1"
    struct.pack_into("<H", kernel, 18, 62)
    bundle = bytearray(256)
    bundle[:16] = native.MAGIC
    struct.pack_into("<II", bundle, 16, 1, 256)
    for i, data in enumerate((kernel, b"070701fixture", b"narf.disks=boot-only")):
        struct.pack_into("<QQ", bundle, 32 + 16 * i, len(bundle), len(data))
        bundle[80 + i * 32:112 + i * 32] = hashlib.sha256(data).digest()
        bundle.extend(data)
        bundle.extend(bytes((-len(bundle)) % 8))
    struct.pack_into("<Q", bundle, 24, len(bundle))
    image = bytearray(512)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 60, 64)
    image[64:68] = b"PE\0\0"
    struct.pack_into("<HH", image, 68, 0x8664, 1)
    struct.pack_into("<H", image, 84, 240)
    struct.pack_into("<H", image, 88, 0x20B)
    struct.pack_into("<I", image, 148, 512)
    struct.pack_into("<I", image, 196, 16)
    image[328:336] = b".narf\0\0\0"
    struct.pack_into("<IIII", image, 336, len(bundle), 4096, len(bundle), 512)
    image.extend(bundle)
    return image


class NativeImageTests(unittest.TestCase):
    def test_manifest_and_part_tampering(self):
        image = fixture()
        manifest = native.inspect(image)
        for name, part in manifest["parts"].items():
            with self.subTest(name=name):
                corrupt = image.copy()
                corrupt[part["offset"]] ^= 1
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    native.inspect(corrupt)

    def test_all_truncations_are_rejected(self):
        image = fixture()
        for length in range(len(image)):
            with self.subTest(length=length), self.assertRaises(ValueError):
                native.inspect(image[:length])

    def test_untrusted_header_extents(self):
        for offset, fmt, value in ((60, "<I", 0xffffffff), (70, "<H", 97),
                                   (348, "<I", 0xffffffff), (544, "<Q", 0xffffffffffffffff),
                                   (536, "<Q", 255), (528, "<I", 2), (688, "<B", 1)):
            with self.subTest(offset=offset):
                image = fixture()
                struct.pack_into(fmt, image, offset, value)
                with self.assertRaises(ValueError):
                    native.inspect(image)

    def test_certificate_table_cannot_alias_bundle(self):
        image = fixture()
        struct.pack_into("<II", image, 232, 512, 16)
        with self.assertRaisesRegex(ValueError, "certificate"):
            native.inspect(image)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--fixture":
        pathlib.Path(sys.argv[2]).write_bytes(fixture())
    else:
        unittest.main()

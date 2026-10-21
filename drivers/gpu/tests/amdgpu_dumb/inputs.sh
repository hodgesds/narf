#!/usr/bin/env bash
# The vector inputs check.sh answers with Linux (see harness.c's grammar).
set -euo pipefail
# Zero dimensions.
echo "C 0 1 32"
echo "C 1 0 32"
echo "C 1 1 0"
# Every pixel size's padding over widths around its 256-byte unit.
for bpp in 1 7 8 9 15 16 17 24 25 32 33 48 64 128; do
	for w in 1 2 31 32 33 63 64 65 127 128 129 255 256 257 640 1023 1366 1920 2560 3840 5120 7680; do
		for h in 1 768 1080 2160; do
			echo "C $w $h $bpp"
		done
	done
done
# 32-bit overflow: bpp, cpp * width, height * stride, PAGE_ALIGN of the
# size, and amdgpu_gem_align_pitch's own add and multiply.
for bpp in 4294967287 4294967288 4294967295; do
	echo "C 1 1 $bpp"
done
for w in 1073741823 1073741824 1073741825 4294967231 4294967232 4294967233 4294967295; do
	for bpp in 8 16 32; do
		echo "C $w 1 $bpp"
	done
done
for h in 1048575 1048576 1048577 4194303 4194304 4194305; do
	echo "C 1024 $h 32"
	echo "C 1023 $h 32"
done
for h in 1048575 1048576 1048577; do
	echo "C 1 $h 32768"
	echo "C 4 $h 8192"
done

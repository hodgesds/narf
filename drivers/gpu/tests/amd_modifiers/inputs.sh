#!/usr/bin/env bash
# The vector inputs check.sh answers with Linux (see harness.c's grammar).
set -euo pipefail
echo M
echo P
amd=$((0x02 << 56))
# AMD_FMT_MOD | TILE_VERSION(GFX12) | TILE(sw) [| DCC | MAX_COMPRESSED_BLOCK].
mod() { printf '%x' $((amd | 5 | $1 << 8 | ${2:-0} << 13 | ${3:-0} << 18)); }
mods=0
for sw in 4 3 2 1; do
	for blk in 2 1 0; do
		mods="$mods $(mod $sw 1 $blk)"
	done
done
for sw in 4 3 2 1; do
	mods="$mods $(mod $sw)"
done
# Modifiers no plane lists: GFX11 64K_R_X / GFX9 64K_D, an unlisted DCC
# variant (max block 3), GFX12 3D swizzles, TILE 0 with DCC, another vendor.
others="ffffffffffffff $(printf %x $((amd | 4 | 27 << 8))) $(printf %x $((amd | 1 | 10 << 8))) $(mod 3 1 3) $(mod 5) $(mod 0 1 0) $(mod 6 1 2) 100000000000001"
# The native planes' list (amdgpu_navi48_kms::PLANE_FORMATS), Linux's
# whole DCN4 list, and others.
echo "B XR24 AR24 XR30 XB30 AR30 AB30 XB24 AB24 RG16 NV12 P010 XR4H AR4H XB4H AB4H"
echo "B XR24"
echo "B XR24 AR24 RA24 XR30 XB30 AR30 AB30 XR48 XB48 AR48 AB48 XB24 AB24 RG16 NV12 P010 XR4H AR4H XB4H AB4H"
echo "B NV12 P010"
# Every format against every listed modifier, INVALID and the others.
for f in XR24 AR24 XB24 AB24 XR30 AR30 XB30 AB30 RG16 XR4H AR4H XB4H AB4H NV12 P010 NV21 RA24 XR48; do
	for m in $mods $others; do
		echo "F $f $m"
	done
done
# Tiling flags: each swizzle field value with each max block, DCC on/off,
# and stray bits above them (number type, data format, write-compress
# disable).
for sw in 0 1 2 3 4 5 7; do
	for blk in 0 1 2 3; do
		for dcc in 0 1; do
			printf 'T %x %d\n' $((sw | blk << 3)) $dcc
			printf 'T %x %d\n' $((sw | blk << 3 | 0x45e0)) $dcc
		done
	done
done
echo "T ffffffffffffffff 1"
# ADDFB2: fourcc w h flags, then per plane handle pitch offset modifier,
# then the BO's GEM tiling flags, GFX12_DCC and size (hex but the fourcc).
z="0 0 0 0"
A() { echo "A $*"; }
h() { printf %x "$1"; }
for f in XR24 AR24 XB30 RG16 AB4H; do
	cpp=4
	[ $f = RG16 ] && cpp=2
	[ $f = AB4H ] && cpp=8
	for w in 780 77f 1; do
		for ht in 438 1; do
			p=$(((0x$w * cpp + 255) / 256 * 256))
			A $f $w $ht 0 1 $(h $p) 0 0 $z $z $z 0 0 $(h $((p * 0x$ht)))
			A $f $w $ht 2 1 $(h $p) 0 0 $z $z $z 0 0 $(h $((p * 0x$ht)))
			A $f $w $ht 0 1 $(h $((0x$w * cpp))) 0 0 $z $z $z 0 0 1000000
			A $f $w $ht 2 1 $(h $p) 0 0 $z $z $z 0 0 $(h $((p * 0x$ht - 1)))
			for m in $mods; do
				for pitch in $(h $p) 2000 20000; do
					A $f $w $ht 2 1 $pitch 0 $m $z $z $z 0 0 4000000
				done
			done
		done
	done
done
# Tiled sizes at the edge of the BO, offsets, and tiling flags without
# modifiers.
for m in $(mod 4) $(mod 3) $(mod 2) $(mod 1) $(mod 4 1 2); do
	for bo in 870000 880000 8a0000 900000 1000000 2000000; do
		A XR24 780 438 2 1 2000 0 $m $z $z $z 0 0 $bo
	done
	for off in 100 1000 10000 40000; do
		A XR24 780 438 2 1 2000 $off $m $z $z $z 0 0 4000000
	done
done
for t in 0 1 2 3 4 c 14 1c 23 9; do
	for dcc in 0 1; do
		A XR24 780 438 0 1 2000 0 0 $z $z $z $t $dcc 4000000
		A NV12 780 438 0 1 800 0 0 1 800 440000 0 $z $z $t $dcc 4000000
	done
done
# NV12 / P010: chroma plane checks, handles, per-plane modifiers.
for f in NV12 P010; do
	cpp=1
	[ $f = P010 ] && cpp=2
	p=$(h $((0x780 * cpp)))
	A $f 780 438 0 1 $p 0 0 1 $p 1fe000 0 $z $z 0 0 400000
	A $f 780 438 0 1 $p 0 0 1 $p 1fe000 0 $z $z 0 0 300000
	A $f 780 438 0 1 $p 0 0 1 $p 1fa400 0 $z $z 0 0 400000
	A $f 780 438 0 1 $p 0 0 2 $p 1fe000 0 $z $z 0 0 400000
	A $f 780 438 0 1 $p 0 0 0 $p 1fe000 0 $z $z 0 0 400000
	A $f 780 438 0 1 $p 0 0 1 100 1fe000 0 $z $z 0 0 400000
	A $f 780 438 2 1 $p 0 0 1 $p 1fe000 0 $z $z 0 0 400000
	A $f 780 438 2 1 $p 0 0 1 $p 1fe000 0 1 0 0 0 $z 0 0 400000
	A $f 781 439 2 1 $(h $((0x800 * cpp))) 0 0 1 $(h $((0x800 * cpp))) 200000 0 $z $z 0 0 800000
	A $f 2 2 2 1 100 0 0 1 100 100 0 $z $z 0 0 1000
	for m in $mods $(mod 3 1 3); do
		A $f 780 438 2 1 $p 0 $m 1 $p 400000 $m $z $z 0 0 1000000
		A $f 780 438 2 1 $p 0 $m 1 $p 400000 0 $z $z 0 0 1000000
		A $f 780 438 2 1 4000 0 $m 1 4000 800000 $m $z $z 0 0 2000000
	done
done
# Bad flags, sizes, handles, modifiers and formats.
A XR24 780 438 4 1 2000 0 0 $z $z $z 0 0 4000000
A XR24 780 438 3 1 2000 0 0 $z $z $z 0 0 4000000
A XR24 0 438 0 1 2000 0 0 $z $z $z 0 0 4000000
A XR24 780 0 0 1 2000 0 0 $z $z $z 0 0 4000000
A XR24 4000 1 2 1 10000 0 0 $z $z $z 0 0 4000000
A XR24 4001 1 2 1 10100 0 0 $z $z $z 0 0 4000000
A XR24 1 4001 2 1 100 0 0 $z $z $z 0 0 4000000
A XR24 780 438 0 0 2000 0 0 $z $z $z 0 0 4000000
A XR24 780 438 0 1 2000 0 1 $z $z $z 0 0 4000000
A XR24 780 438 2 1 2000 0 0 1 0 0 0 $z $z 0 0 4000000
A XR24 780 438 2 1 2000 0 0 0 0 0 0 0 2000 0 0 $z 0 0 4000000
A XR24 780 438 0 1 2000 0 0 1 0 0 0 $z $z 0 0 4000000
A XR24 780 438 0 1 2000 0 0 0 0 0 1 $z $z 0 0 4000000
A XR24 780 438 2 1 2000 ffffffff 0 $z $z $z 0 0 4000000
A XR24 780 438 2 1 ffffffff 0 0 $z $z $z 0 0 4000000
A XR24 780 438 2 1 2000 0 $(mod 3 1 3) $z $z $z 0 0 4000000
A NV21 780 438 0 1 800 0 0 1 800 440000 0 $z $z 0 0 4000000

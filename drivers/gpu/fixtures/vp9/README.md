# Original VP9 Profile0 keyframe

This repository's original 128×128, 8-bit 4:2:0 four-region picture is encoded
as a single lossless, error-resilient VP9 Profile0 keyframe. The source Y
quadrants are 32/80/144/208; U is 64 and V is 192. The exact raw VP9 payload
lives in `src/amdgpu_vcn_navi48_vp9_words.rs`; no third-party stream is copied.
The original picture and resulting stream are dedicated to the public domain
under CC0-1.0. Driver and regeneration code retain the repository MIT license.

Pinned primary tools:

- libvpx 1.15.2, official archive
  <https://chromium.googlesource.com/webm/libvpx/+archive/refs/tags/v1.15.2.tar.gz>,
  SHA-256 `b6c70df4026cd1c3cfa006bb7ec96c3ad4716c2530fd82c78c763cb97a4496c9`.
  Configure `--target=generic-gnu --disable-vp8 --enable-vp9-highbitdepth
  --disable-unit-tests --disable-docs --disable-webm-io --disable-shared
  --enable-static`, then `make -j2`. No encoder logic changes.
- FFmpeg 8.0, official archive <https://ffmpeg.org/releases/ffmpeg-8.0.tar.xz>,
  SHA-256 `b2751fccb6cc4c77708113cd78b561059b6fa904b24162fa0be2d60273d27b8e`.
  Include VP9 decoder/parser/IVF demuxer, rawvideo output and the
  `vp9_metadata,trace_headers` bitstream filters for the strict CBS trace.
- Mesa 26.2.4, archive/hash and MIT notices in `../../VCN-NOTICES`.
  The actual generic/codec builder, context formula, initialization table,
  tier3 reference-list package and IB constructors are extracted unchanged
  by `../../tests/vcn5/decode_primary.py` and executed by `vp9_check.py`.
  Both gfx1200/gfx1201 surface layouts come from actual GFX12 Addrlib.

Regenerate with `regenerate.py --vpxenc /path/to/vpxenc --ffmpeg /path/to/ffmpeg`.
Run the independent source/fixture oracle with
`../../tests/vcn5/vp9_check.py /path/to/mesa-26.2.4 --ffmpeg /path/to/ffmpeg`.
It compares every create/decode/destroy byte, 2072 initialized default
probability bytes, all three complete IBs and tier3 reference package,
actual surface geometry, and every independently decoded NV12 byte.

Raw payload: 64 bytes, SHA-256
`8720e79f246912d0d8001e0517b68f81be764b9d0102334ddf500f613ee6e453`.
Default probability bytes: SHA-256
`1e47124c4a2c369b8bcbd24bf681106e22ddb2929fc0260a1907bf7ae86af593`.
Decoded NV12: 24576 bytes, SHA-256
`af4b8817ee41af9585b6687e9969414a065e7f1a673e9204784daaab0820618b`.

The stream enables frame-parallel/error-resilient decoding, disables
segmentation, has no references, no tiles and quantizer/filter level zero.
The uncompressed header occupies 18 bytes; compressed header is 10 bytes.
Mesa tier3 binds the current linear target and an empty dynamic-reference
list, with no monolithic DPB. The full hardware context remains required.

This is a known keyframe proof prerequisite. A software decoder or model is
not native silicon acceptance, and Profile0 alone does not enable the VP9
capability row or prove Profile2, inter prediction, upper ranges or clients.


## Profile2 precision proof

`--profile2` selects the independent 10-bit fixture in
`amdgpu_vcn_navi48_vp9_10_words.rs`. Regeneration uses the same pinned high-bit
libvpx build with profile2, bit-depth 10 and input-bit-depth 10; other keyframe
options remain the same. The original Y quadrants are 129/321/577/833; U is 259
and V is 771, so every plane exercises precision discarded by an 8-bit path.
The 69-byte raw payload SHA-256 is
`43fa8123ae12129fa97147b98d948fa4c6c49dfd804f5430ad2d2077c7ce4576`.
Independent FFmpeg decode matches all original samples; packed MSB-aligned
P010 is 49152 bytes, SHA-256
`7c8a710cc653140480b728b7769d34d2f77c46cc30766530e9fc7b6742646c01`.

Run both scripts with `--profile2` to select this fixture. The same unchanged
Mesa builder executes its 10-bit P010 path and adds 65536 bytes to the actual
context, totaling 10923264 bytes; complete arena 11161600 bytes. Actual Addrlib
surfaces yield Y pitch 128/UV pitch 64 in samples and UV offset 32768 bytes.
Firmware header sizes remain compressed 10/uncompressed 18 bytes; strict CBS
trace independently checks syntax position, bit depth and header flags.
Defaults remain the same pinned Mesa probability table. Full P010 byte
comparison includes nonzero low 2 sample bits and zero 6 packing bits. Both fixed
keyframes remain prerequisites; inter-frame, upper profile/ranges and actual
application acceptance remain unproven and the codec row stays gated.

# Original HEVC Main8 fixture

The bytes in `src/amdgpu_vcn_navi48_hevc_words.rs::STREAM` encode an original
128×128 8-bit I420 picture: luma quadrants 32, 80, 144, 208, Cb=64, Cr=192.
The original picture and generated fixture are dedicated to CC0-1.0 by their
NARF contributors. No encoder/decoder source or third-party video is embedded.

`regenerate.py --x265 /path/to/x265 --ffmpeg /path/to/ffmpeg` reconstructs the
picture, encodes it from stdin (one frame known in advance makes x265 select
Main Still Picture), independently decodes I420 and interleaves its chroma to
NV12. It checks the exact fixture and decoded hashes. It does not need a GPU.

Pinned official tool sources used to establish these bytes:

- [x265 4.1](https://download.videolan.org/pub/videolan/x265/x265_4.1.tar.gz),
  SHA256 `a31699c6a89806b74b0151e5e6a7df65de4b49050482fe5ebf8a4379d7af8f29`.
  Release CLI, 8-bit, `ENABLE_SHARED=OFF`, `ENABLE_ASSEMBLY=OFF`,
  `ENABLE_LIBNUMA=OFF`, `HIGH_BIT_DEPTH=OFF`. For host CMake 4 compatibility,
  only CMP0025/CMP0054 were changed from OLD to NEW and the minimum was raised
  from 2.8.8 to 3.5; codec source was unchanged. Encoder version reports
  `4.1+1-1d117be`, GCC 15.3.0, no assembly.
- [FFmpeg 8.0](https://ffmpeg.org/releases/ffmpeg-8.0.tar.xz),
  SHA256 `b2751fccb6cc4c77708113cd78b561059b6fa904b24162fa0be2d60273d27b8e`.
  Independent software HEVC decoder/parser, HEVC demuxer, rawvideo encoder/muxer,
  file protocol, `hevc_metadata,trace_headers` bitstream filters, format filter;
  `--disable-everything --disable-x86asm --disable-autodetect --disable-network
  --disable-debug --enable-small --extra-cflags=-O2` plus those components.

The standard timing VUI remains enabled. x265 4.1's `--no-vui-timing-info`
combination emits a header rejected by FFmpeg CBS; that stream is not used.

Verified SHA256:

- Annex-B HEVC stream:
  `26a5c91dacb9c140fe7dc624a3f57d9005657bc2b51d7a12ed34269b73458256`.
- Input and independently decoded I420:
  `3aeeb7ddb1ba5911ca2c43dce7fe51c6e75973f23c83dffc71220024749f3aba`.
- Independently decoded NV12:
  `af4b8817ee41af9585b6687e9969414a065e7f1a673e9204784daaab0820618b`.

The primary ABI comparison is
`tests/vcn5/hevc_check.py /path/to/mesa-26.2.4 --igt /path/to/igt-gpu-tools-2.4
--ffmpeg /path/to/ffmpeg`. It extracts Mesa's HEVC types and `build_hevc_msg`
unchanged, checks complete create/decode/destroy message bytes and IGT's unified
IB descriptors, verifies fixture hashes, independently decodes every pixel,
and verifies SPS/PPS/IDR fields with FFmpeg `trace_headers`.
Mesa source provenance is in `research/rdna4-mesa-26.2.4.md`; upstream notices
are preserved in `VCN-NOTICES`.

This single Main8 IDR is a proof input. It does not establish Main10, inter
prediction, resolution/profile ranges, malformed-stream containment, concurrent
sessions, application API support or physical acceptance on either die.

## Main10 companion

`src/amdgpu_vcn_navi48_hevc10_words.rs::STREAM` is a separate original
128×128 Main10 IDR. Its I420 little-endian 10-bit luma values are 129, 321,
577, 833; Cb=259, Cr=771. Every sample deliberately has nonzero low precision
bits. Rebuild the same pinned x265 source with `HIGH_BIT_DEPTH=ON`,
`MAIN12=OFF`; all other options are unchanged. Run `regenerate.py --main10
--x265 /path/to/10bit/x265 --ffmpeg /path/to/ffmpeg`. It uses Main10 and QP0,
then independently decodes yuv420p10le and interleaves/MSB-aligns it to P010.
No lossless/RExt profile switch is used. `hevc_check.py` accepts the same
`--main10` option for full primary message/descriptor/pixel/header comparison.

Verified SHA256:

- Annex-B Main10:
  `11f4e8621dd28676980f61687c94a746cb68ce586e7bf9075a072bcbf729b85f`.
- Input and independently decoded I420p10le:
  `d2199a1de7852c3dc0833b19b5f90520f063b045bc51dfc6d6c3f87a546e0386`.
- Independently decoded MSB-aligned P010:
  `7c8a710cc653140480b728b7769d34d2f77c46cc30766530e9fc7b6742646c01`.

The native proof verifies all 49152 bytes, including the low precision bits.
Main10 reuses no Main8 output/context/DPB storage. This companion does not
establish inter prediction, full Main10/range/application or silicon acceptance;
HEVC capability rows remain gated.

## Independent surface allocation check

`tests/vcn5/hevc_surface_check.py /path/to/mesa-26.2.4 --gpu /path/to/drivers/gpu`
compiles unchanged Mesa Addrlib with two workers and never opens a GPU.
The normal `hevc_check.py` invokes it as well; `--surface-build-dir` optionally
reuses objects keyed by all Addrlib source/header bytes and compiler flags.
Mesa's unchanged format-helper generators and `si_get_plane_format` derive
the two actual plane formats/dimensions from `u_format.yaml`. Actual
`Addr3ComputeSurfaceInfo` and `Addr3ComputeSurfaceAddrFromCoord` then determine
sample pitches, byte addresses, slice sizes, UV offsets and total target sizes
for both GFX1200/GFX1201 revision ranges. The resulting surfaces are compared
to the live Rust message bytes, independently of the fixed-message C reference.

The proof deliberately uses Addrlib's valid compact 128-byte minimum linear
alignment. Main8 Y/UV sample pitches are 128/64; the UV byte offset is 16384
and target size is 24576. Main10 P010 sample pitches are also 128/64, with
256-byte row strides, UV offset 32768 and target size 49152. Pitch fields
count plane-format elements, so the interleaved UV width is 64, not 128.
The harness separately exercises Mesa's general 256-byte interoperability
pitch policy: that enlarges Main8 rows/offset/size to 256/128 samples,
32768/49152 bytes, while Main10 stays the same. Those padded surfaces must
not be silently substituted for the compact proof arena. The original
incorrect UV128 descriptors fail this surface-derived check.

The generic-message reference also executes unchanged `ac_vcn_dec.c` blocks:
create/decode headers and index offsets, full generic decode assignments,
codec branch, tier0 swizzle selection, feedback initialization and final
buffer/flag assignments. It calls unchanged `stream_type`,
`calc_ctx_size_hevc`, `ac_vcn_dec_dpb_size`, `ac_vcn_dec_dpb_alignment` and
`send_cmd`; VCN5 address mode comes from the actual decoder-init switch.
Host adapters supply only fixture parameters and real Addrlib surface results,
not expected generic-message fields. Surface heights/sizes/pitches/UV offsets
are passed as machine-readable output from the independent surface process.
This verifies tier0 DPB alignment/strides/sizes, hardware-context sizes,
`db_swizzle_mode`, array mode and all bound-buffer flags without restating
those expressions in the fixed-message C fixture. Header/source notices are
preserved in extracted temporary code. Negative mutation checks reject wrong
DPB swizzle, array mode, missing DPB binding flag, context size and DPB size.

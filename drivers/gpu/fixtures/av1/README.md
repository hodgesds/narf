# Original AV1 Main8 keyframe and primary decoder CDF

The original 256×128, 8-bit 4:2:0 source picture has Y quadrants 32/80/144/208,
U 64 and V 192. It is encoded as one lossless reduced-still keyframe with one
4×2-superblock tile, using 64×64 superblocks and disabled CDEF/restoration,
film grain, filter/intra-edge tools, screen content, segmentation and matrices.
The original picture and encoded stream are dedicated to the public domain
under CC0-1.0; driver/regeneration code retains the repository MIT license.

The 193-byte raw OBU payload in `amdgpu_vcn_navi48_av1_words.rs` has SHA-256
`5687498d2f4309175866e5ce58f8b21b97810e98eaa738a4cf7bd9d21aace1c2`.
Pinned libaom regenerates the stream; independent FFmpeg 8.0/libaom decode
matches every original source sample. Strict FFmpeg CBS checks all fixed
sequence/frame tools and derives the tile offset 16/size 177 from actual header
syntax and byte alignment. Compact encoder roundtrips use their own preserved
sequence prefix and parsed frame metadata, excluding CPU alignment padding.

`default_cdf.bin` is third-party AMD Mesa decoder data, not CC0 picture data.
It contains the four defaults initialized by actual unchanged
`ac_vcn_av1_init_probs(RDECODE_AV1_VER_2)` from pinned Mesa 26.2.4:
81920 bytes, SHA-256
`3e7d9954ccdda4207222de61f3661396e0c43d39fc59bdba0f79da5443ed5890`.
The relevant upstream 2020 AMD MIT notice is preserved in `../../VCN-NOTICES`.
This decoder table differs from the encoder's default CDF and must not be
substituted with encoder data. The primary context formula gives 20480-byte
frame contexts and 36688896-byte total context. The full retained arena is
37076992 bytes; it includes 128 KiB stream capacity and per-frame segment/film-
grain storage (20736 bytes, padded 24576), even though film grain is disabled.

Regenerate the original fixture with `regenerate.py --aomenc /path/to/aomenc
--ffmpeg /path/to/ffmpeg`. Regenerate the CDF with `cdf_regenerate.py /path/to/
mesa-26.2.4 --output /path/to/default_cdf.bin`. The primary comparison is
`../../tests/vcn5/av1_check.py /path/to/mesa-26.2.4 --ffmpeg /path/to/ffmpeg`.
It compares complete create/decode/destroy messages, all initialized CDF bytes,
real gfx1200/gfx1201 Addrlib surfaces and complete IBs/tier3 references. A
nonzero synthetic metadata case checks signed quant/filter/tx field mapping;
it does not claim that those metadata describe the fixed lossless stream.

Pinned tools:

- libaom 3.13.1, official release
  <https://storage.googleapis.com/aom-releases/libaom-3.13.1.tar.gz>, SHA-256
  `19e45a5a7192d690565229983dad900e76b513a02306c12053fb9a262cbeca7d`.
  Corresponding official release commit
  <https://aomedia.googlesource.com/aom/+/d772e334cc724105040382a977ebb10dfd393293>.
  CMake Release, `AOM_TARGET_CPU=generic`, `ENABLE_TESTS=OFF`,
  `ENABLE_DOCS=OFF`, `ENABLE_EXAMPLES=ON`, `ENABLE_TOOLS=ON`,
  `ENABLE_NASM=OFF`, `BUILD_SHARED_LIBS=OFF`; no encoder logic edits.
- FFmpeg 8.0 archive/hash in `../vp9/README.md`; compile libaom AV1 decoder,
  AV1 parser/IVF demuxer and `av1_metadata,trace_headers` CBS support.
- Mesa 26.2.4 archive/hash in `../../VCN-NOTICES`.

A completed software decoder or synthetic DMA model is not physical acceptance.
This fixed Main8 picture proves neither Main10, inter references, full ranges,
film grain nor applications. Codec capability rows remain gated. Dynamic
roundtrip admission accepts only parsed fixed-sequence keyframes and requires
an explicit pixel-error tolerance; it never trusts an arbitrary client stream.

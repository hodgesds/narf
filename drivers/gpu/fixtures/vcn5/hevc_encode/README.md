# VCN5 HEVC encoder and native decoder roundtrip

These original fixtures describe a fixed 384×128 Main8 intra picture: two diagonal luma 64 regions and two 192 regions, distinct U80/V176. `frame.bin` is tightly packed NV12; the native encoder uploads it to a zero-padded 512-byte pitch. Commands use no references, QP 20, SAO/AMP/transform-skip/rate-control disabled, CTB 64 and transform blocks 4..32. This is bounded bring-up coverage, not full profile/range or application acceptance.

`headers.bin` is reviewed static VPS/SPS/PPS data originating from Mesa26.2.4
`radeon_bitstream.c`. Firmware output begins after its 80-byte, 16-byte-aligned
prefix. Every prefix byte and padding byte must survive unchanged.

`reference.hevc` combines those exact headers/padding with one matching x265 4.1 IDR. FFmpeg 8.0 independently decodes it to every original source sample. This reference supplies the test model's synthetic device output; the model does not encode or decode video. On hardware, the native proof decodes the actual newly encoded output in another owned session and checks every NV12 component (absolute error<=4 and total error<=73728). Wrong/stale/missing completion, stream/guard/command/input corruption and failed/cancelled work cannot publish `EncodeRoundtripProof`.

Native Rust tests exercise the production encoder/decoder packet builders,
bounds, refusal and retained-session paths with these reviewed assets. The
former source extraction/compiler comparison pipeline is removed. Firmware
interfaces1.8..1.10 use the documented minimum-version selection; the owner
refuses older/unknown-major firmware before allocation/publication. Internal
models do not establish external Mesa/Addrlib conformance or physical encoding.

To regenerate the independent slice, convert `frame.bin` NV12 to I420, then run x265 4.1 with:

```
x265 --input frame.i420 --input-res 384x128 --fps 25 --frames 1 --qp 20 --keyint 1 --min-cu-size 8 --ctu 64 --max-tu-size 32 --tu-intra-depth 1 --tu-inter-depth 1 --no-sao --no-amp --no-wpp --no-signhide --no-deblock --no-info --repeat-headers --pools none --frame-threads 1 --output reference-x265.hevc
```

Keep its single IDR NAL(type 20), prepend the reviewed headers padded to 80 bytes and a four-byte AnnexB start code. The decoded reference is exact despite x265's IDR QP offset; native firmware output is accepted only by the explicit fidelity thresholds. No hardware or performance claim follows from host/model checks. Mesa packet/header adaptations retain AMD's MIT terms in `drivers/gpu/VCN-NOTICES`.

The384-pixel width respects Mesa26.2.4 VCN5 HEVC encode minimum384 (`ac_video.c`). Actual Addrlib source Y512/UV256 sample pitches and UV65536 back98304bytes, including zero source row padding; all73728logical source components are retained and checked. Compact decoder target Y384/UV192, UV49152 backs73728bytes without row padding. The encoder has two196608-byte reconstructions,798720-byte total arena; decoder context81952, DPB147456 and622592-byte arena are preserved as reviewed static sizing contracts.

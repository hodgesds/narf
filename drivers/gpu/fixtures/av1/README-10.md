# Original AV1 Main-profile 10-bit precision picture

The independent original 256×128 10-bit 4:2:0 picture uses luma quadrants
129/321/577/833, U 259 and V 771. All samples have nonzero low two bits;
8-bit truncation cannot pass the expected P010 comparison. Each decoded P010
sample is stored little-endian with all ten bits in bits 15:6 and zero low six
padding bits. The full target is 98,304 bytes: luma pitch 256 samples, chroma
pitch 128 two-component blocks, UV offset 65,536. Both actual gfx1200/gfx1201
Addrlib paths derive this geometry, independently of the message builder.

The source and encoded picture are original CC0-1.0 data. Code uses the repo
MIT license. The separate 196-byte lossless reduced-still stream embedded in
`amdgpu_vcn_navi48_av1_10_words.rs` has SHA-256
`f4e46774a0f69d2a624b10ed6896dcdbee53feee1a1a4676364b6079143e2a00`.
The pinned libaom 3.13.1 tool regenerates it exactly; independent FFmpeg 8.0
CBS checks the actual 10-bit syntax, tools, tile offset 16 and tile size 180.
Both aomdec and FFmpeg/libaom reproduce every original sample. Tool archive
hashes and build provenance are in `README.md`; regeneration is
`regenerate_10.py --aomenc /path/to/aomenc --ffmpeg /path/to/ffmpeg`.

Native Rust tests exercise production message/CDF construction, IB ownership,
P010 layout and nonzero quant/filter/transform metadata placement. Synthetic
metadata does not describe the lossless fixture. The former source extraction
and C-shim comparison pipeline is removed; internal agreement does not establish
external Mesa/Addrlib conformance or physical codec operation.

The Main8 fixture, parsed `Keyframe` API and encoder's dynamic 320 helper are
unchanged. The actual depth-independent hardware context remains 36,688,896
bytes with four 20,480-byte initialized default CDFs. The existing decoder
CDF is reused unchanged, not the distinct encoder CDF. A separately retained
37,126,144-byte arena includes all context, padded per-frame storage, 128 KiB
stream, target, messages, guards and IBs. Adding this optional proof to the
chain costs the whole arena; it does not alias or retire prior proof arenas.

Full P010 native completion remains a hardware gate. Model execution and
software decoding do not establish physical acceptance, general inter-frame
support, full range, film grain or applications, and do not raise codec bits.

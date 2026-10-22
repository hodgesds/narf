# Selected Mesa/libdrm INFO initialization replay

This host test executes the unchanged Mesa 26.2.4
`ac_drm_device_initialize` / `ac_query_gpu_info` and libdrm 2.4.134
`amdgpu_device_initialize` / query initialization. It links configured actual
Mesa common/util objects and the selected actual libdrm library. The build's
selected initializer/video sources must match the pinned official archives;
archive hashes match `verification/data/musl-demo/REGEN_mesa_amd.sh`.

`rust_answers.py` extracts unchanged production Rust INFO dispatch/query/
response builders, GET_CAP answers, VM geometry functions, UAPI mirrors and
native ring-selection helper. No DEV_INFO, memory, topology, firmware or cap
response is restated in C. Its adapter supplies explicit representative
GC12 discovery, harvesting, clock, retained firmware and heap inputs from
`inputs.rs`, substitutes host locks and process-local copy hooks, and supplies
a ready owner receipt for the actual ring helper. GTT limit/usage and card
heap are explicit host state inputs. These are model cards, not captured
physical board state. The encoded replies themselves execute production code.

The C adapter handles only process-local DRM metadata/ioctl transport and
version/acceleration controls. Render-node authentication, PCI identification,
query sequencing, VA managers, raw firmware decoding, chip identification,
heap/topology interpretation and feature setup run in actual selected sources.
It submits no GPU work, emulates no shader/codec execution and does not load
a Vulkan/GL application or establish rendering acceptance.

The production control keeps DRM 3.0.0 and the actual Rust ACCEL_WORKING=0.
Two separate controls change only the advertised host minor or the host
acceleration response; each still fails the corresponding real initializer.
Only the explicitly labelled `hypothetical-3.54` host envelope changes both.
No production version, acceleration, codec or feature bit is raised.

42 cases cover GFX1200/Navi44 and GFX1201/Navi48, complete fully published
initialization, DEV_INFO/MMR/HW_IP/MEMORY/ME/MEC/PFP/VCN omission, actual VCN
metadata withdrawal, unsupported VCN IP, graphics-only degraded readiness,
optional MAX_IBS fallback and exact raw VCN interface minors 8/9/10/11.
Every case logs the actual query IDs, payloads, lengths, results and derived
Mesa data. Missing mandatory answers fail at real consumer callsites; optional
MAX_IBS refusal uses the real Mesa fallback. Its success does not make that
fallback's larger IB limit safe for NARF clients; native MAX_IBS stays bounded.

Use a previously configured/built selected Mesa common/util tree and a built
selected libdrm tree/prefix; this test writes only its private work directory.
The render fixture tooling can supply those build products. Example:

```
python3 drivers/gpu/tests/mesa_info/check.py \
  --mesa-build /path/to/mesa-build \
  --libdrm-build /path/to/libdrm-build \
  --libdrm-prefix /path/to/libdrm-prefix \
  --mesa-archive /path/to/mesa-26.2.4.tar.xz \
  --libdrm-archive /path/to/libdrm-2.4.134.tar.xz \
  --work-dir /path/to/private-replay-build
```

The Rust and C adapters compile with warnings as errors. Related force-family,
CU-mask, parse-IB and dynamic-library override environment is cleared for each
child, so ambient developer settings cannot silently replace the tested chip
or selected library. No network or native hardware is required.

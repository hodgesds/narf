# Mesa/libdrm INFO compatibility requirements

The removed host replay extracted Rust response builders and linked them to a
C transport shim. GPU tests now exercise the production Rust INFO/GET_CAP/query
paths directly in their native test modules. They cover device identity,
geometry, firmware metadata, bounds, owner publication and refusal behavior.
No source slicing, temporary Rust program or C adapter is part of that gate.

Actual selected Mesa/libdrm must still run against the real NARF ioctl/device
boundary for application acceptance. An internal query model cannot establish
that conformance. The native card's DRM3.0.0 and ACCEL_WORKING=0 gates remain;
test inputs must not be mistaken for permission to raise those values.

Reference versions for the source audit were Mesa26.2.4 and libdrm2.4.134. The
archive hashes and real userspace build recipe remain in
`verification/data/musl-demo/REGEN_mesa_amd.sh`. That userspace compatibility
integration is separate from the removed extraction/shim pipeline.

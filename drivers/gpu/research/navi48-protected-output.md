# Navi48 protected-output requirements

Status: tracked separately from native display bring-up; unsupported and
unadvertised. This document records implementation prerequisites, not evidence
that an RX 9070 XT can authenticate or encrypt a protected stream under NARF.

The native KMS inventory in `amdgpu_navi48_kms.rs` and the shared DRM property
tables expose neither Content Protection nor HDCP Content Type. Native PSP
boot does not create DTM/HDCP trusted-application sessions. The helpers in
`crypto/src/hdcp.rs` are not an authenticated display transport, proof of
protocol conformance, or authority to provision transmitter keys. Native
retirement APIs' requirement to stop HDCP producers is a caller exclusion;
it does not implement protected output.

## Firmware and device ownership

- Identify the board's PSP firmware and supported DTM/HDCP trusted-application
  versions, their command ABIs and firmware distribution requirements. Record
  image versions/hashes and actual initialization responses. Do not infer TA
  availability from successful DMUB, SMU or ordinary PSP boot.
- Own session handles, command buffers and secure-memory lifetimes explicitly.
  Serialize topology updates, authentication, encryption control and reset
  against native modesetting. A failed/cancelled command must retain uncertain
  resources until completion or independently verified reset.
- Bind each protected session to the exact connector generation, route,
  encoder, link and stream. For MST, include downstream topology and payload
  mapping; an old connector ID alone must not authorize a replacement sink.
- Establish hardware evidence for encryption enable, encryption disable and
  loss of authentication on every supported DIO/HPO/FRL path. Authentication
  success alone must never publish protected scanout.

## Protocol and authorization

- Select supported HDCP versions and transports from board/firmware evidence.
  Implement their capability exchange, authentication, locality checks,
  repeater/topology validation, stream management and bounded retry rules.
  Validate against the applicable published specifications and conformance
  vectors; the existing crypto helpers need independent conformance review.
- Define authenticated revocation/SRM loading, update authority, persistence
  and rollback policy. Invalid, revoked or unsupported receivers must not
  become enabled through ordinary unprotected-link fallback.
- Establish who is authorized to provision/use transmitter credentials and
  approve protected playback, including applicable licensing and device
  provisioning requirements. This work does not grant that authorization.
  Never embed production keys in source, test fixtures, logs or crash dumps.
- Specify a capability-gated protected-buffer and presentation contract before
  accepting protected content. CPU-readable console/compositor buffers and
  today's ordinary DMA mappings do not acquire protection from link encryption.
  Changes to trusted key handling or isolation require the repository's TCB/
  security review process; this tracking document changes neither boundary.

## Publication and lifecycle gate

Only expose protection properties after the entire supported path exists.
Userspace may request protection; only authenticated, verified encrypted output
can report Enabled. Report loss promptly and enforce the protected-content
policy before presenting another protected frame. Reauthenticate after route,
mode, topology, firmware or connector-generation changes. Cancellation,
unplug, reset, suspend and teardown must retire firmware/protocol work before
releasing its resources. Preserve ordinary unprotected display operation when
protection is not requested.

Acceptance requires negative models for malformed/replayed protocol messages,
revocation, stale sessions, lost command completion and cancellation, followed
by physical tests with compatible direct sinks and repeaters. Record the board,
VBIOS/TA firmware, connector/cable, receiver firmware, link mode, protocol version,
authentication/encryption evidence and hotplug/modeset/disable/reset results.
All physical acceptance is currently outstanding. No protected-output support
claim or KMS property is authorized by completing this tracking task.

## Reference map

Implementation reconnaissance used the local Linux source at `/usr/src/linux`
(its Makefile identifies 7.3.0-rc4; the checkout has no Git revision metadata):

- `drivers/gpu/drm/amd/display/modules/hdcp/hdcp_psp.c`: separate DTM topology
  and HDCP session/authentication/encryption commands with TA result checks.
- `drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm_hdcp.c`: connector lifecycle,
  asynchronous authentication and PSP SRM interfaces.
- `drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm.c`: content-protection
  property transitions and integration with display changes.
- `drivers/gpu/drm/amd/amdgpu/amdgpu_psp.h` and
  `drivers/gpu/drm/amd/display/modules/hdcp/hdcp_psp.h`: PSP and TA interfaces
  to examine when selecting the board-supported implementation.

These are implementation references, not protocol specifications or a license
to use transmitter credentials. Exact source revisions and authoritative
protocol versions must be pinned when an implementation is proposed.

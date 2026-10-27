# ctap2 — Specification

Lane P3 of the power-suspend programme (issue #999). Protocol
sources: FIDO2 Client to Authenticator Protocol (CTAP2),
RFC 8949 (CBOR), RFC 8152 (COSE), RFC 2104 (HMAC),
NIST SP 800-38A (AES-CBC), RFC 5903 (P-256 ECDH), USB HID 1.11.

## 1. Purpose & scope

Provide the running system with a FIDO2/CTAP2 client over USB
HID sufficient for suspend-token enrollment and unwrap:
makeCredential with the `hmac-secret` extension, getAssertion
with hmac-secret derivation, and the CTAP2 PIN protocol
(protocol one) for the decided touch+PIN unlock default. The
client exposes the derivation result to the suspend service
(lane P1) through a narrow API; it does not own key custody,
suspend policy, or the resume environment (lane P5 has its own
minimal stack; it may reuse this protocol layer above its
transport, per design §4.6).

Out of scope: attestation verification (the token is physically
present and enrolled by its owner; `fmt`/attStmt are recorded,
not chained), CTAP2.1 pre-flight / credential management
beyond enrollment, PIN protocol two, platform (built-in)
authenticators, U2F/CTAPHID_MSG.

## 2. Assumptions

- One authenticator conversation at a time per channel; the
  caller serializes clients per token.
- The caller supplies `clientDataHash` — what an assertion is
  *about* is the suspend service's definition, not the client's.
- Randomness comes from the caller's `RandomSource`; production
  binds it to `narf-crypto`'s HW-entropy-gated fill (lane P0).
  The client never invents entropy.
- Authenticators speak CTAP2 over CTAPHID with 64-byte reports
  and advertise `pinUvAuthProtocol` 1 if PIN is used.

## 3. Public interface

Transport seam:

- `ctaphid::HidPipe` — `write_report`/`read_report` of exactly
  one 64-byte HID report. `read_report` must return
  `Error::Timeout` rather than block forever.
- `RandomSource` — `fill_random`.

Framing (`ctaphid`):

- `Channel::init(pipe, rng)` performs CTAPHID_INIT on the
  broadcast CID (8-byte nonce, echo validated, reserved CIDs
  rejected) and yields the channel + `InitResponse`.
- `Channel::exchange(cmd, payload)` — one message in flight;
  packetization (57-byte init packet, 59-byte continuations,
  sequence from 0), reassembly with BCNT bound (128 KiB),
  KEEPALIVE counting (`last_keepalive_up_needed`), ERROR frames
  surfaced as `Error::Hid(code)`, foreign CIDs skipped, all
  bounded by `MAX_PACKETS_PER_EXCHANGE` → `Error::Timeout`.
- `Channel::exchange_cbor(req)` — CTAPHID_CBOR; first response
  payload byte is the CTAP status, non-zero → `Error::Ctap`.

Client (`client`):

- `Client::connect(pipe, rng)` — INIT + capability check
  (protocol 2, CAP_CBOR) + getInfo (cached; `refresh_info`
  after PIN-state changes).
- `Client::get_info() -> AuthenticatorInfo` — versions,
  extensions, aaguid, options map (`client_pin_state()`),
  maxMsgSize, pinUvAuthProtocols; raw map retained.
- `Client::make_credential(MakeCredentialParams)` — ES256 only;
  always requests the `hmac-secret` extension; options rk/uv
  per params; with a PIN: one key-agreement session yields the
  pinUvAuthToken, `pinUvAuthParam =
  LEFT(HMAC(token, clientDataHash), 16)`, protocol 1.
  Validates the response authData's rpIdHash against the RP.
- `Client::get_assertion(GetAssertionParams)` — allow list or
  discoverable lookup; hmac-secret inputs built from the SAME
  key-agreement session as the PIN token (the authenticator's
  ephemeral persists per power cycle); extension output
  decrypted from the authData ED extensions (32 or 64 bytes).
- `Client::get_next_assertion(rp_id)` — drains the multi-
  credential queue signalled by `number_of_credentials`.
- `Client::pin_session()`, `Client::pin_retries()`.

PIN protocol one (`pin`):

- `PinSession::establish(channel, rng)` — getKeyAgreement,
  ECDH P-256, shared secret `SHA-256(x)`.
- `get_pin_token` (pinHashEnc = CBC(shared, LEFT(SHA-256(pin),
  16)); wrong PIN surfaces the authenticator's 0x31),
  `set_pin` (newPinEnc = CBC(shared, PIN zero-padded to 64)),
  `change_pin` (pinUvAuthParam = full HMAC(shared, newPinEnc)),
  `get_pin_retries` (standalone). PIN length 4..=63 enforced
  client-side.

Enrollment surface (`enroll`) — the P1 seam:

- `enroll_token(client, EnrollParams { pin_setup })` —
  `PinSetup::TouchAndPin` (default policy) sets the PIN first
  when the token has none (clientPin option false), then
  enrolls a discoverable credential with UV; `TouchOnly` only
  on explicit policy. Refuses tokens that do not advertise
  hmac-secret, and refuses enrollments whose authData does not
  grant it (ED extensions `hmac-secret == true`).
- `derive_slot_output(client, DeriveParams)` — one
  getAssertion for one enrolled credential id + caller salt(s);
  returns `HmacSecretOutput { first, second }`. The returned
  bytes are P1's wrapping input; this crate wraps nothing.
- `enrollment_complete(&[EnrolledToken])` — true only with
  ≥ 2 DISTINCT credential ids (mandatory backup token,
  decisions doc 2026-10-26). Each token wraps independently:
  one wrapped blob per token, either token unwraps its own.

Errors (`Error`): Transport, Timeout, Cbor, Hid(u8), Ctap(u8)
with `is_pin_invalid` / `is_pin_auth_invalid` helpers,
Protocol(&str), Crypto, Random, Unsupported(&str).

## 4. Invariants

- Wire constants come from the CTAP2 spec text only; the
  fixture token is an independent implementation (own CBOR,
  own AES-CBC, HMAC via narf-crypto HKDF) so agreement between
  client and fixture is evidence, not tautology.
- CBOR encoding is canonical (RFC 8949 §4.2.1: map keys sorted
  by encoded length then bytewise); decoding is strict
  (definite lengths, shortest form, no floats/tags/simple
  values beyond literals, depth ≤ 16, input ≤ 16 KiB, no
  trailing bytes, no duplicate map keys).
- One key-agreement session serves a call's PIN token AND its
  hmac-secret salts; re-keying mid-call would orphan one of
  them against authenticators with a persistent ephemeral.
- User presence is never fabricated: the client waits through
  KEEPALIVE UP_NEEDED until the authenticator answers or the
  exchange budget expires.
- PIN retry semantics belong to the authenticator; the client
  surfaces raw status bytes so the caller sees PIN_INVALID vs
  PIN_BLOCKED vs PIN_AUTH_INVALID distinctly.
- No key custody: pinUvAuthTokens, shared secrets, and
  hmac-secret outputs live only for the call that produced
  them; nothing is persisted by this crate.

## 5. Architecture notes (x86_64, aarch64)

- Architecture-neutral `no_std` + alloc. Crypto is
  `narf-crypto` (P-256, SHA-256) plus the RustCrypto `aes`
  block cipher narf-crypto itself uses; CBC is composed here
  per SP 800-38A with the protocol's zero IV.
- The production `HidPipe` lives in `drivers/usb` (`ctap`
  module) over an xHCI interrupt endpoint pair; this crate has
  no arch code and no initcalls (binding is via the USB attach
  chain, like CCID), so the configurable-drivers census is
  unaffected.

## 6. Dependencies

- `narf-crypto` (workspace): SHA-256, P-256 point/scalar
  arithmetic. (Its HKDF/HMAC is used by the fixture only; the
  client carries its own HMAC over the streaming SHA-256 so
  multi-part MACs — saltAuth over saltEnc — stay one-pass.)
- `aes` 0.8 (RustCrypto, default-features = false): raw
  AES-256 blocks for protocol-one CBC.
- Consumed by: `drivers/usb` (binding + registry), the suspend
  service (lane P1, future), kernel-test smokes.

## 7. Stage assignment

Stage 4/5-era driver-adjacent subsystem, landing with the
power-suspend programme (post-Stage-4). Not part of the TCB
(USB stack is outside the TCB per the tree map; no `frame/`,
`memory/`, `capabilities/`, `scheduler/`, or `security-model/`
paths are touched by the introducing change).

## 8. Open questions

- CTAP 2.1 `getPINToken` permissions (subCommand 9) would let
  the suspend token fetch be scoped to getAssertion only;
  worth adopting when targeting 2.1-only tokens — protocol-one
  full tokens are the current floor.
- PIN protocol two (HKDF-based KDF, AES-256-CBC with random
  IV in-band) for newer tokens that drop protocol one.
- Whether the resume environment (P5) reuses this crate's
  protocol modules directly or keeps a reduced fork — the
  `HidPipe` seam was designed for reuse; P5 decides.

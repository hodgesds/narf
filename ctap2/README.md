# ctap2 — FIDO2/CTAP2 client for suspend tokens

`ctap2` (package `narf-ctap2`) is the runtime-side FIDO2 client
NARF uses to talk to hardware suspend tokens (YubiKey-class
authenticators) over USB HID. It implements the CTAP2 subset the
power-suspend design needs: `authenticatorGetInfo`,
`authenticatorMakeCredential`, `authenticatorGetAssertion` with
the `hmac-secret` extension, `authenticatorGetNextAssertion`,
and `authenticatorClientPIN` under PIN/UV auth protocol one —
the decided touch+PIN default for token-only unlock.

The crate is a *protocol* crate, not a driver: it runs over a
64-byte HID report pipe (`ctaphid::HidPipe`). `drivers/usb`
binds that pipe to a real xHCI interrupt endpoint pair; the
suspend resume environment (lane P5) can bind the same protocol
layer to its polled stack, per design §4.6. A fixture
authenticator (`fixture_token`, test-only) implements the
spec's conversation independently so the client can be proven
end-to-end without silicon.

Layering (design §4): this crate owns the token conversation
only. Key custody — wrapping/unwrapping the suspend slot
secret with the hmac-secret output — belongs to the suspend
service (lane P1), which consumes the narrow enrollment /
derivation surface in `enroll`. The client never stores key
material; enrollment completeness (primary + mandatory backup
token, distinct credentials) is expressed as
`enroll::enrollment_complete` for the service to enforce.

Everything wire-shaped derives from the FIDO2 CTAP2
specification text and RFC 8949/8152 — CBOR here is canonical
(strictly sorted map keys, shortest-form integers) and the
decoder rejects indefinite lengths, floats, and non-shortest
forms rather than tolerating them.

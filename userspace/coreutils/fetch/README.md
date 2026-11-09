# userspace/coreutils/fetch — fetch

Downloads a file over HTTP/1.1.

```
fetch [-o output] <http://literal-ip[:port]/path>
```

With no `-o`, the response body goes to stdout; with `-o`, it goes
to the named file (a failed download removes the partial file).
Redirects are followed (up to 5 hops). `Content-Length` and
chunked (`Transfer-Encoding: chunked`) bodies are supported.

## Limits (deliberate — the kernel client covers them)

- **HTTP only.** `https://` is refused: there is no TLS in
  userspace. HTTPS downloads go through the kernel-side fetch
  client (`net::fetch`, TLS 1.3 via `net::tls_client`); the
  production root store is the open remainder #1802.
- **Literal IPv4 hosts only.** `getaddrinfo` has no resolver in
  tree, so a hostname cannot be resolved from this binary; use a
  literal address (the kernel `net::fetch` resolves hostnames via
  the in-tree DNS resolver).
- **No close-delimited bodies.** A response with neither
  `Content-Length` nor chunked framing is refused: `narf-libc`'s
  `recvfrom` loops on a kernel 0 return, so a userspace reader can
  never observe EOF (the kernel's `do_recv` returns Ok(0) for a
  peer FIN, but libc never surfaces it); waiting for EOF would
  hang. The kernel `net::fetch` client handles close-delimited
  bodies.

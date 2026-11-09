//! Fixture tests for the HTTP(S) fetch client (`fetch.rs`).
//!
//! The engine is driven over [`MemStream`] (a canned server) and —
//! for HTTPS — over a scripted TLS 1.3 server flight built from the
//! RFC 8448 §3 trace (see `tls_client_tests.rs`: the published
//! ServerHello + encrypted server flight + NewSessionTicket, then a
//! server application-data record carrying the HTTP response,
//! sealed under the trace's server application keys, seq 1). No
//! live network is involved; only silicon is untested.

use alloc::vec::Vec;

use crate::fetch::{
    fetch, fetch_once, FetchError, FetchOptions, FetchResponse, MemStream, TlsStream, Url,
};
use narf_kernel_test::{kernel_test_in, kt_assert_eq, TestResult};

/// Run one exchange over a canned server and return the response
/// plus the exact request bytes the client wrote.
fn run_once(input: &[u8], url: &str) -> Result<(FetchResponse, Vec<u8>), FetchError> {
    let mut stream = MemStream::new(input);
    let u = Url::parse(url)?;
    let (status, _location, body) = fetch_once(&mut stream, &u, &FetchOptions::default())?;
    Ok((
        FetchResponse {
            status,
            final_url: u,
            body,
        },
        stream.written().to_vec(),
    ))
}

fn url_parse_defaults_and_errors() -> TestResult {
    let Ok(u) = Url::parse("http://example.com") else {
        return TestResult::Fail("http URL parses");
    };
    kt_assert_eq!(u.scheme, crate::fetch::Scheme::Http);
    kt_assert_eq!(u.host.as_str(), "example.com");
    kt_assert_eq!(u.port, 80);
    kt_assert_eq!(u.path.as_str(), "/");
    kt_assert_eq!(u.host_header().as_str(), "example.com");

    let Ok(u) = Url::parse("https://example.com:8443/a/b?x=1#frag") else {
        return TestResult::Fail("https URL parses");
    };
    kt_assert_eq!(u.scheme, crate::fetch::Scheme::Https);
    kt_assert_eq!(u.port, 8443);
    kt_assert_eq!(u.path.as_str(), "/a/b?x=1");
    kt_assert_eq!(u.host_header().as_str(), "example.com:8443");

    // Literal IPv4 + default port.
    let Ok(u) = Url::parse("http://192.0.2.10/pkg.tar") else {
        return TestResult::Fail("literal IP parses");
    };
    kt_assert_eq!(u.host.as_str(), "192.0.2.10");
    kt_assert_eq!(u.port, 80);

    // Errors: no scheme, unknown scheme, empty host, bad port,
    // userinfo, IPv6 literal.
    kt_assert_eq!(
        Url::parse("example.com/x"),
        Err(FetchError::BadUrl),
        "bare host without scheme"
    );
    kt_assert_eq!(
        Url::parse("ftp://example.com/x"),
        Err(FetchError::UnsupportedScheme),
        "ftp is not a fetch scheme"
    );
    kt_assert_eq!(
        Url::parse("http:///x"),
        Err(FetchError::BadUrl),
        "empty host"
    );
    kt_assert_eq!(
        Url::parse("http://example.com:notaport/x"),
        Err(FetchError::BadUrl),
        "non-numeric port"
    );
    kt_assert_eq!(
        Url::parse("http://example.com:/x"),
        Err(FetchError::BadUrl),
        "empty port"
    );
    kt_assert_eq!(
        Url::parse("http://user@example.com/x"),
        Err(FetchError::BadUrl),
        "userinfo rejected"
    );
    kt_assert_eq!(
        Url::parse("http://[::1]/x"),
        Err(FetchError::BadUrl),
        "IPv6 literal rejected (remainder)"
    );
    TestResult::Pass
}

kernel_test_in!("net/fetch", url_parse_defaults_and_errors);

fn url_resolve_relative() -> TestResult {
    let Ok(base) = Url::parse("http://example.com/a/b/page?x=1") else {
        return TestResult::Fail("base parses");
    };
    // Absolute URI (may change scheme).
    let Ok(u) = base.resolve_relative("https://other.example/c/d") else {
        return TestResult::Fail("absolute Location resolves");
    };
    kt_assert_eq!(u.scheme, crate::fetch::Scheme::Https);
    kt_assert_eq!(u.host.as_str(), "other.example");
    kt_assert_eq!(u.path.as_str(), "/c/d");
    // Scheme-relative.
    let Ok(u) = base.resolve_relative("//cdn.example/pkg") else {
        return TestResult::Fail("scheme-relative Location resolves");
    };
    kt_assert_eq!(u.scheme, crate::fetch::Scheme::Http);
    kt_assert_eq!(u.host.as_str(), "cdn.example");
    kt_assert_eq!(u.path.as_str(), "/pkg");
    // Absolute path.
    let Ok(u) = base.resolve_relative("/v2/pkg?y=2") else {
        return TestResult::Fail("absolute-path Location resolves");
    };
    kt_assert_eq!(u.host.as_str(), "example.com");
    kt_assert_eq!(u.path.as_str(), "/v2/pkg?y=2");
    // Relative path, merged with the base directory, dot segments
    // removed (RFC 3986 §5.2.4).
    let Ok(u) = base.resolve_relative("c/../d") else {
        return TestResult::Fail("relative Location resolves");
    };
    kt_assert_eq!(u.path.as_str(), "/a/b/d");
    // Empty Location is not a redirect target.
    kt_assert_eq!(
        base.resolve_relative(""),
        Err(FetchError::BadLocation),
        "empty Location"
    );
    TestResult::Pass
}

kernel_test_in!("net/fetch", url_resolve_relative);

fn fetch_once_request_and_content_length() -> TestResult {
    let input = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello";
    let Ok((resp, written)) = run_once(input, "http://example.com/pkg.tar") else {
        return TestResult::Fail("fetch_once succeeds");
    };
    kt_assert_eq!(resp.status, 200);
    kt_assert_eq!(resp.body.as_slice(), b"hello".as_slice());
    // The exact request bytes (RFC 9112 §3): GET + Host + close.
    kt_assert_eq!(
        written.as_slice(),
        b"GET /pkg.tar HTTP/1.1\r\nHost: example.com\r\nUser-Agent: narf-fetch/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n".as_slice(),
        "request bytes"
    );
    TestResult::Pass
}

kernel_test_in!("net/fetch", fetch_once_request_and_content_length);

fn fetch_once_chunked() -> TestResult {
    // Chunk extensions and a trailer are tolerated; the terminating
    // zero chunk ends the body (RFC 9112 §7.1).
    let input = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=x\r\nhello\r\n5\r\n worl\r\n1\r\nd\r\n0\r\nX-Trailer: y\r\n\r\n";
    let Ok((resp, _)) = run_once(input, "http://example.com/pkg") else {
        return TestResult::Fail("chunked succeeds");
    };
    kt_assert_eq!(resp.status, 200);
    kt_assert_eq!(resp.body.as_slice(), b"hello world".as_slice());
    TestResult::Pass
}

kernel_test_in!("net/fetch", fetch_once_chunked);

fn fetch_once_close_delimited() -> TestResult {
    // No Content-Length, no chunked: the body runs to EOF.
    let input = b"HTTP/1.0 200 OK\r\n\r\nhello";
    let Ok((resp, _)) = run_once(input, "http://example.com/pkg") else {
        return TestResult::Fail("close-delimited succeeds");
    };
    kt_assert_eq!(resp.status, 200);
    kt_assert_eq!(resp.body.as_slice(), b"hello".as_slice());
    TestResult::Pass
}

kernel_test_in!("net/fetch", fetch_once_close_delimited);

fn fetch_once_bad_headers() -> TestResult {
    // Non-numeric Content-Length.
    let input = b"HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\nhello";
    kt_assert_eq!(
        run_once(input, "http://example.com/pkg").map(|_| ()),
        Err(FetchError::BadHeader),
        "non-numeric Content-Length"
    );
    // Conflicting duplicate Content-Length (RFC 9112 §6.3).
    let input = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!";
    kt_assert_eq!(
        run_once(input, "http://example.com/pkg").map(|_| ()),
        Err(FetchError::BadHeader),
        "conflicting Content-Length"
    );
    // Truncated Content-Length body fails closed (not a short body).
    let input = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello";
    kt_assert_eq!(
        run_once(input, "http://example.com/pkg").map(|_| ()),
        Err(FetchError::Transport),
        "truncated Content-Length body"
    );
    // EOF before the end of headers.
    let input = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n";
    kt_assert_eq!(
        run_once(input, "http://example.com/pkg").map(|_| ()),
        Err(FetchError::Transport),
        "EOF inside the head"
    );
    TestResult::Pass
}

kernel_test_in!("net/fetch", fetch_once_bad_headers);

/// A scripted two-hop redirect: `/start` → relative `b/../c`
/// (dot-segment removal) → 200. The connector mints a fresh canned
/// stream per URL, like the production connector mints a fresh TCP
/// connection per hop.
fn redirect_script(url: &Url) -> Result<MemStream<'static>, FetchError> {
    match (url.host.as_str(), url.path.as_str()) {
        ("example.com", "/start") => Ok(MemStream::new(
            b"HTTP/1.1 302 Found\r\nLocation: b/../c\r\nContent-Length: 0\r\n\r\n",
        )),
        ("example.com", "/a/c") => Ok(MemStream::new(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        )),
        _ => Err(FetchError::Transport),
    }
}

fn fetch_redirect_relative() -> TestResult {
    let Ok(url) = Url::parse("http://example.com/start") else {
        return TestResult::Fail("URL parses");
    };
    let Ok(resp) = fetch(url, &FetchOptions::default(), redirect_script) else {
        return TestResult::Fail("redirect chain succeeds");
    };
    kt_assert_eq!(resp.status, 200);
    kt_assert_eq!(resp.body.as_slice(), b"hello".as_slice());
    kt_assert_eq!(resp.final_url.path.as_str(), "/a/c");
    TestResult::Pass
}

kernel_test_in!("net/fetch", fetch_redirect_relative);

fn fetch_redirect_loop_too_many() -> TestResult {
    let Ok(url) = Url::parse("http://example.com/loop") else {
        return TestResult::Fail("URL parses");
    };
    let opts = FetchOptions {
        max_redirects: 1,
        ..FetchOptions::default()
    };
    let result = fetch(url, &opts, |_| {
        Ok(MemStream::new(
            b"HTTP/1.1 302 Found\r\nLocation: /loop\r\nContent-Length: 0\r\n\r\n",
        ))
    });
    kt_assert_eq!(
        result.map(|_| ()),
        Err(FetchError::TooManyRedirects),
        "redirect loop hits the hop cap"
    );
    TestResult::Pass
}

kernel_test_in!("net/fetch", fetch_redirect_loop_too_many);

fn fetch_status_error() -> TestResult {
    let Ok(url) = Url::parse("http://example.com/missing") else {
        return TestResult::Fail("URL parses");
    };
    let result = fetch(url, &FetchOptions::default(), |_| {
        Ok(MemStream::new(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found",
        ))
    });
    kt_assert_eq!(
        result.map(|_| ()),
        Err(FetchError::HttpStatus(404)),
        "404 surfaces as HttpStatus"
    );
    // A redirect without Location is not followed.
    let Ok(url) = Url::parse("http://example.com/bare") else {
        return TestResult::Fail("URL parses");
    };
    let result = fetch(url, &FetchOptions::default(), |_| {
        Ok(MemStream::new(
            b"HTTP/1.1 301 Moved Permanently\r\nContent-Length: 0\r\n\r\n",
        ))
    });
    kt_assert_eq!(
        result.map(|_| ()),
        Err(FetchError::BadLocation),
        "redirect without Location"
    );
    TestResult::Pass
}

kernel_test_in!("net/fetch", fetch_status_error);

/// HTTPS end to end over the scripted RFC 8448 §3 server flight:
/// the TLS handshake runs against the trace's published flight
/// (ServerHello + encrypted flight + NewSessionTicket), then the
/// server delivers an HTTP/1.1 response as application data sealed
/// under the trace's server application keys (seq 1). The fetch
/// engine reads the response through the established TLS stream.
fn fetch_https_over_rfc8448_flight() -> TestResult {
    use crate::tls_client::{SliceTransport, TlsClient};
    use crate::tls_client_tests::{
        flight_record, hex, nst_record, rfc_config, rfc_store, server_app_record_for,
        SERVER_HELLO_RECORD,
    };

    let store = rfc_store();
    let config = rfc_config(&store);
    let http = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\npackage-data!";
    let mut input = hex(SERVER_HELLO_RECORD);
    let flight = match flight_record() {
        Ok(r) => r,
        Err(e) => return TestResult::Fail(e),
    };
    input.extend_from_slice(&flight);
    let nst = match nst_record() {
        Ok(r) => r,
        Err(e) => return TestResult::Fail(e),
    };
    input.extend_from_slice(&nst);
    let app = match server_app_record_for(http) {
        Ok(r) => r,
        Err(e) => return TestResult::Fail(e),
    };
    input.extend_from_slice(&app);

    let transport = SliceTransport::new(&input);
    let client = match TlsClient::connect(transport, config) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("TLS handshake succeeds"),
    };
    let tls = TlsStream::from_client(client);
    let url = match Url::parse("https://server/pkg.bin") {
        Ok(u) => u,
        Err(_) => return TestResult::Fail("URL parses"),
    };
    let mut slot = Some(tls);
    let resp = match fetch(url, &FetchOptions::default(), |_| {
        slot.take().ok_or(FetchError::Transport)
    }) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("fetch over TLS succeeds"),
    };
    kt_assert_eq!(resp.status, 200);
    kt_assert_eq!(resp.body.as_slice(), b"package-data!".as_slice());
    kt_assert_eq!(resp.final_url.host.as_str(), "server");
    TestResult::Pass
}

kernel_test_in!("net/fetch", fetch_https_over_rfc8448_flight);

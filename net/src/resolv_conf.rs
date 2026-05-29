//! `/etc/resolv.conf` reader/writer and programmatic updater.
//!
//! ## Format reference
//!
//! The traditional resolv.conf format is described in POSIX and the
//! resolver(5) man page. We support the subset used by modern Linux:
//!
//! - `# comment` — line-level comments (pound sign or semicolon).
//! - `nameserver <ip>` — up to 3 nameserver addresses (RFC 1035 §6.1.3).
//! - `search <dom1> [dom2 ...]` — search list (RFC 1535; up to 6 domains).
//! - `domain <dom>` — single-domain alias; treated as `search <dom>`.
//! - `options <key>[:<value>] [...]` — resolver options. Parsed:
//!   `ndots:<n>`, `timeout:<n>`, `attempts:<n>`, `rotate`, `no-check-names`.
//!
//! ## References
//!
//! - RFC 1035 §6.1.3: name server list in resolv.conf.
//!   <https://datatracker.ietf.org/doc/html/rfc1035>
//! - RFC 1535: DNS Search List Security Issues.
//!   <https://datatracker.ietf.org/doc/html/rfc1535>
//! - systemd-resolved(8), resolvconf(8): current defacto config format.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Parsed `/etc/resolv.conf` contents.
///
/// All fields are optional: an empty `ResolvConfig` is valid (resolver
/// will default-construct nameservers from the DHCP lease, etc.).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResolvConfig {
    /// Up to 3 nameserver IP addresses (IPv4 or IPv6 string form).
    /// RFC 1035 §6.1.3 specifies at most 3.
    pub nameservers: Vec<String>,
    /// Search list for hostname lookups. RFC 1535: up to 6 entries.
    pub search: Vec<String>,
    /// `ndots` option: dots needed for absolute lookup before search.
    /// Default 1 (Linux glibc default).
    pub ndots: u8,
    /// `timeout` option: seconds per query attempt. Default 5.
    pub timeout: u8,
    /// `attempts` option: retry count per nameserver. Default 2.
    pub attempts: u8,
    /// `rotate` option: round-robin across nameservers.
    pub rotate: bool,
    /// `no-check-names` option: skip strict hostname validation.
    pub no_check_names: bool,
}

impl ResolvConfig {
    /// Construct an empty config with all-default option values.
    pub fn new() -> Self {
        Self {
            nameservers: Vec::new(),
            search: Vec::new(),
            ndots: 1,
            timeout: 5,
            attempts: 2,
            rotate: false,
            no_check_names: false,
        }
    }

    /// Parse `resolv.conf` content from a byte slice.
    ///
    /// Lines are split on `\n`. Fields are whitespace-separated.
    /// Unknown directives are silently ignored (permissive parser).
    pub fn parse(content: &str) -> Self {
        let mut cfg = Self::new();
        for raw_line in content.lines() {
            let line = raw_line.trim();
            // Skip blank lines and comments (# or ;).
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let directive = match parts.next() {
                Some(d) => d,
                None => continue,
            };
            match directive {
                "nameserver" => {
                    if let Some(ip) = parts.next() {
                        if cfg.nameservers.len() < 3 {
                            cfg.nameservers.push(ip.to_string());
                        }
                    }
                }
                "search" => {
                    cfg.search.clear();
                    for dom in parts.take(6) {
                        cfg.search.push(dom.to_string());
                    }
                }
                "domain" => {
                    // `domain` sets a single-entry search list.
                    if let Some(dom) = parts.next() {
                        cfg.search.clear();
                        cfg.search.push(dom.to_string());
                    }
                }
                "options" => {
                    for opt in parts {
                        if let Some(val) = opt.strip_prefix("ndots:") {
                            cfg.ndots = val.parse().unwrap_or(1);
                        } else if let Some(val) = opt.strip_prefix("timeout:") {
                            cfg.timeout = val.parse().unwrap_or(5);
                        } else if let Some(val) = opt.strip_prefix("attempts:") {
                            cfg.attempts = val.parse().unwrap_or(2);
                        } else if opt == "rotate" {
                            cfg.rotate = true;
                        } else if opt == "no-check-names" {
                            cfg.no_check_names = true;
                        }
                    }
                }
                _ => {} // Ignore unknown directives.
            }
        }
        cfg
    }

    /// Serialize to `resolv.conf` text format.
    ///
    /// Produces a canonical file that `parse()` round-trips cleanly.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("# Generated by narf resolv_conf\n");
        for ns in &self.nameservers {
            out.push_str("nameserver ");
            out.push_str(ns);
            out.push('\n');
        }
        if !self.search.is_empty() {
            out.push_str("search");
            for s in &self.search {
                out.push(' ');
                out.push_str(s);
            }
            out.push('\n');
        }
        // Emit options only when non-default.
        let mut opts: Vec<&str> = Vec::new();
        let ndots_str;
        let timeout_str;
        let attempts_str;
        if self.ndots != 1 {
            ndots_str = alloc::format!("ndots:{}", self.ndots);
            opts.push(ndots_str.as_str());
        } else {
            ndots_str = String::new();
        }
        if self.timeout != 5 {
            timeout_str = alloc::format!("timeout:{}", self.timeout);
            opts.push(timeout_str.as_str());
        } else {
            timeout_str = String::new();
        }
        if self.attempts != 2 {
            attempts_str = alloc::format!("attempts:{}", self.attempts);
            opts.push(attempts_str.as_str());
        } else {
            attempts_str = String::new();
        }
        if self.rotate {
            opts.push("rotate");
        }
        if self.no_check_names {
            opts.push("no-check-names");
        }
        if !opts.is_empty() {
            out.push_str("options");
            for o in &opts {
                out.push(' ');
                out.push_str(o);
            }
            out.push('\n');
        }
        // Suppress lint for unused String vars when opts is empty.
        let _ = (&ndots_str, &timeout_str, &attempts_str);
        out
    }

    /// Programmatic update from DHCP ACK data.
    ///
    /// Replaces the nameserver list with `servers` (IPv4 `[u8;4]`
    /// arrays) and sets the search domain to `search_domain` (if
    /// non-empty). Existing `options` fields are preserved.
    ///
    /// Called by the DHCP client after a successful ACK with options
    /// 6 (DNS servers) and 15 (domain name).
    pub fn update_from_dhcp(&mut self, servers: &[[u8; 4]], search_domain: &str) {
        self.nameservers.clear();
        for s in servers.iter().take(3) {
            self.nameservers.push(alloc::format!(
                "{}.{}.{}.{}",
                s[0], s[1], s[2], s[3]
            ));
        }
        if !search_domain.is_empty() {
            self.search.clear();
            self.search.push(search_domain.to_string());
        }
    }
}

// ── Global live config ────────────────────────────────────────────────

use narf_lib::sync::IrqSafeSpinLock;

static LIVE_CONFIG: IrqSafeSpinLock<ResolvConfig> =
    IrqSafeSpinLock::new(ResolvConfig {
        nameservers: Vec::new(),
        search: Vec::new(),
        ndots: 1,
        timeout: 5,
        attempts: 2,
        rotate: false,
        no_check_names: false,
    });

/// Install a new live config. Called on boot after reading
/// `/etc/resolv.conf` (or after a DHCP ACK populates it).
pub fn install(cfg: ResolvConfig) {
    *LIVE_CONFIG.lock() = cfg;
}

/// Run `f` against the live config. The lock is held across `f`; keep
/// the callback short (read fields, don't block).
pub fn with_config<R, F: FnOnce(&ResolvConfig) -> R>(f: F) -> R {
    f(&LIVE_CONFIG.lock())
}

/// Clone the current live nameserver list. Returns up to 3 addresses.
pub fn nameservers() -> Vec<String> {
    LIVE_CONFIG.lock().nameservers.clone()
}

/// Update the live config from a DHCP ACK. Merges servers + domain into
/// the existing config (options fields preserved).
pub fn update_from_dhcp(servers: &[[u8; 4]], search_domain: &str) {
    let mut g = LIVE_CONFIG.lock();
    g.update_from_dhcp(servers, search_domain);
}

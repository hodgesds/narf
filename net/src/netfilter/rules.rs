//! Rule-list types — match predicate + verdict, organised into tables
//! and chains, modeled (loosely) after nftables.
//!
//! Linux ref: `net/netfilter/nf_tables_api.c` for the table/chain
//! hierarchy, `nf_tables_core.c:nft_do_chain()` for the dispatch
//! loop. We don't implement the full expression language — just the
//! 5-tuple + iface + conntrack-state predicate matrix that covers
//! the common filter/NAT use cases.

use alloc::string::String;
use alloc::vec::Vec;

use super::{HookPoint, Tuple, Verdict};
use super::conntrack::CtState;

/// Direction relative to the interface a packet is leaving or
/// arriving on. Useful for the `iifname` / `oifname` distinction
/// in nftables.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Direction {
    /// `--in-interface` — packet is on the way in.
    In,
    /// `--out-interface` — packet is on the way out.
    Out,
}

/// A rule's match predicate. `None` on a field means "don't care".
/// All `Some` fields must match (AND semantics).
#[derive(Clone, Debug, Default)]
pub struct Match {
    pub src_ip:   Option<[u8; 4]>,
    pub dst_ip:   Option<[u8; 4]>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub proto:    Option<u8>,
    pub iface_in: Option<String>,
    pub iface_out: Option<String>,
    pub ct_state: Option<CtState>,
}

impl Match {
    pub const fn any() -> Self {
        Self {
            src_ip: None, dst_ip: None,
            src_port: None, dst_port: None,
            proto: None,
            iface_in: None, iface_out: None,
            ct_state: None,
        }
    }

    /// Convenience: match-source helper.
    pub fn from_src_ip(ip: [u8; 4]) -> Self {
        let mut m = Self::any();
        m.src_ip = Some(ip);
        m
    }

    /// Check the match against a (tuple, iface_in, iface_out, ct_state).
    pub fn matches(
        &self,
        t: &Tuple,
        iface_in: &str,
        iface_out: &str,
        ct_state: Option<CtState>,
    ) -> bool {
        if let Some(s) = self.src_ip { if s != t.src_ip { return false; } }
        if let Some(d) = self.dst_ip { if d != t.dst_ip { return false; } }
        if let Some(p) = self.src_port { if p != t.src_port { return false; } }
        if let Some(p) = self.dst_port { if p != t.dst_port { return false; } }
        if let Some(p) = self.proto { if p != t.proto { return false; } }
        if let Some(ref n) = self.iface_in {
            if n.as_str() != iface_in { return false; }
        }
        if let Some(ref n) = self.iface_out {
            if n.as_str() != iface_out { return false; }
        }
        if let Some(s) = self.ct_state {
            if ct_state != Some(s) { return false; }
        }
        true
    }
}

/// One rule: a match predicate paired with the verdict to apply on
/// match.
#[derive(Clone, Debug)]
pub struct Rule {
    pub m: Match,
    pub verdict: Verdict,
}

/// A chain — ordered list of rules + which hook point the chain is
/// bound to + a default policy (applied if no rule matches).
#[derive(Clone, Debug)]
pub struct Chain {
    pub name: String,
    pub hook: HookPoint,
    pub policy: Verdict,
    pub rules: Vec<Rule>,
}

impl Chain {
    pub fn new(name: String, hook: HookPoint) -> Self {
        Self {
            name,
            hook,
            policy: Verdict::Accept,
            rules: Vec::new(),
        }
    }

    /// Append a rule.
    pub fn append(&mut self, r: Rule) {
        self.rules.push(r);
    }

    /// Walk rules, return the first matching verdict or the policy.
    pub fn eval(
        &self,
        t: &Tuple,
        iface_in: &str,
        iface_out: &str,
        ct_state: Option<CtState>,
    ) -> Verdict {
        for r in &self.rules {
            if r.m.matches(t, iface_in, iface_out, ct_state) {
                return r.verdict;
            }
        }
        self.policy
    }
}

/// A table — collection of chains, in the spirit of nftables tables.
#[derive(Clone, Debug)]
pub struct Table {
    pub name: String,
    pub chains: Vec<Chain>,
}

impl Table {
    pub fn new(name: String) -> Self {
        Self { name, chains: Vec::new() }
    }

    pub fn chain(&mut self, name: &str) -> &mut Chain {
        let idx = self.chains.iter().position(|c| c.name == name);
        match idx {
            Some(i) => &mut self.chains[i],
            None => {
                // Auto-create with a default hook based on chain name.
                let hook = match name {
                    "prerouting"  => HookPoint::PreRouting,
                    "input"       => HookPoint::LocalIn,
                    "forward"     => HookPoint::Forward,
                    "output"      => HookPoint::LocalOut,
                    "postrouting" => HookPoint::PostRouting,
                    _ => HookPoint::LocalIn,
                };
                self.chains.push(Chain::new(name.into(), hook));
                self.chains.last_mut().unwrap()
            }
        }
    }
}

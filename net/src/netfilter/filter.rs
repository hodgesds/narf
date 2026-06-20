//! Packet filter — verdict-driven rule lists keyed by chain name,
//! evaluated at the chain's hook point.
//!
//! The public API mirrors nftables minus the expression language:
//!
//! - `nf_table_add(table, chain, rule)` to install a rule.
//! - Five builtin chains: `prerouting`, `input`, `forward`, `output`,
//!   `postrouting` — each registered at its corresponding hook point.
//! - Default policy: `ACCEPT` (open). A user can flip to `DROP` by
//!   calling `set_default_policy`.
//!
//! Filter hooks run at priority `0` so they sit *between* conntrack
//! (`-200`) and NAT (`+100`).

use alloc::string::ToString;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use super::rules::{Chain, Match, Rule, Table};
use super::{conntrack, parse_tuple_ipv4, HookPoint, PktCtx, Verdict};

/// Builtin filter table — the single global rule store. Stage-3 only
/// implements one table; nftables-style multi-table support is a
/// straightforward extension.
#[derive(Debug)]
pub struct Filter {
    inner: IrqSafeSpinLock<Vec<Table>>,
}

impl Default for Filter {
    fn default() -> Self {
        Self::new()
    }
}

impl Filter {
    pub const fn new() -> Self {
        Self {
            inner: IrqSafeSpinLock::new(Vec::new()),
        }
    }

    /// Get-or-create a table.
    fn table_mut<F, R>(&self, name: &str, f: F) -> R
    where
        F: FnOnce(&mut Table) -> R,
    {
        let mut tables = self.inner.lock();
        let idx = tables.iter().position(|t| t.name == name);
        let i = match idx {
            Some(i) => i,
            None => {
                tables.push(Table::new(name.to_string()));
                tables.len() - 1
            }
        };
        f(&mut tables[i])
    }

    /// Add a rule. Auto-creates the table and chain.
    pub fn add(&self, table: &str, chain: &str, rule: Rule) {
        self.table_mut(table, |t| {
            let c = t.chain(chain);
            c.append(rule);
        });
    }

    /// Set a chain's default policy.
    pub fn set_policy(&self, table: &str, chain: &str, v: Verdict) {
        self.table_mut(table, |t| {
            let c = t.chain(chain);
            c.policy = v;
        });
    }

    /// Snapshot every chain bound to `hook` across every table —
    /// returns clones to avoid lock-during-eval.
    fn chains_at(&self, hook: HookPoint) -> Vec<Chain> {
        let tables = self.inner.lock();
        let mut out = Vec::new();
        for t in tables.iter() {
            for c in t.chains.iter() {
                if c.hook == hook {
                    out.push(c.clone());
                }
            }
        }
        out
    }

    /// Reset to empty. Test-only.
    #[doc(hidden)]
    pub fn __reset_for_test(&self) {
        self.inner.lock().clear();
    }
}

static FILTER: Filter = Filter::new();

/// Reference the global filter.
#[inline]
pub fn filter() -> &'static Filter {
    &FILTER
}

#[doc(hidden)]
pub fn __reset_for_test() {
    FILTER.__reset_for_test();
}

/// Add a rule to `table`/`chain`. Auto-creates both if absent.
pub fn nf_table_add(table: &str, chain: &str, m: Match, verdict: Verdict) {
    FILTER.add(table, chain, Rule { m, verdict });
}

/// Set the default policy on `table`/`chain`.
pub fn nf_table_set_policy(table: &str, chain: &str, v: Verdict) {
    FILTER.set_policy(table, chain, v);
}

// ── Hooks ───────────────────────────────────────────────────────────

fn filter_for(hook: HookPoint, ctx: &mut PktCtx<'_>) -> Verdict {
    let tuple = match parse_tuple_ipv4(ctx.packet()) {
        Some(t) => t,
        None => return Verdict::Accept,
    };
    let ct_state = ctx.conntrack_id.and_then(|id| {
        let ct = conntrack::ct();
        let map = ct.lookup(&tuple);
        map.map(|e| e.lock().state).or_else(|| {
            let _ = id;
            None
        })
    });
    let chains = FILTER.chains_at(hook);
    if chains.is_empty() {
        return Verdict::Accept;
    }
    for c in &chains {
        let v = c.eval(&tuple, ctx.iface_in, ctx.iface_out, ct_state);
        match v {
            Verdict::Accept => continue,
            v => return v,
        }
    }
    Verdict::Accept
}

pub fn filter_prerouting(ctx: &mut PktCtx<'_>) -> Verdict {
    filter_for(HookPoint::PreRouting, ctx)
}
pub fn filter_input(ctx: &mut PktCtx<'_>) -> Verdict {
    filter_for(HookPoint::LocalIn, ctx)
}
pub fn filter_forward(ctx: &mut PktCtx<'_>) -> Verdict {
    filter_for(HookPoint::Forward, ctx)
}
pub fn filter_output(ctx: &mut PktCtx<'_>) -> Verdict {
    filter_for(HookPoint::LocalOut, ctx)
}
pub fn filter_postrouting(ctx: &mut PktCtx<'_>) -> Verdict {
    filter_for(HookPoint::PostRouting, ctx)
}

/// Register the filter hooks at priority `0` (sits between conntrack
/// `-200` and NAT `+100`).
pub fn register_default_hooks() {
    super::nf_register_hook(HookPoint::PreRouting, 0, filter_prerouting);
    super::nf_register_hook(HookPoint::LocalIn, 0, filter_input);
    super::nf_register_hook(HookPoint::Forward, 0, filter_forward);
    super::nf_register_hook(HookPoint::LocalOut, 0, filter_output);
    super::nf_register_hook(HookPoint::PostRouting, 0, filter_postrouting);
}

/// One-shot initializer — installs filter + conntrack + NAT hooks.
pub fn init_all_default_hooks() {
    conntrack::register_default_hooks();
    register_default_hooks();
    super::nat::register_default_hooks();
}

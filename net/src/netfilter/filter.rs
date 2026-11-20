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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RulesetError {
    AlreadyExists,
    NotFound,
    NotEmpty,
}

#[derive(Debug)]
struct Ruleset {
    tables: Vec<Table>,
    generation: u32,
}

impl Ruleset {
    fn changed(&mut self) {
        // Linux reserves zero for an unspecified generation.
        self.generation = self.generation.wrapping_add(1).max(1);
    }
}

/// Tables and their generation belong to the same network namespace.
#[derive(Debug)]
pub struct Filter {
    inner: IrqSafeSpinLock<Ruleset>,
}

impl Default for Filter {
    fn default() -> Self {
        Self::new()
    }
}

impl Filter {
    pub const fn new() -> Self {
        Self {
            inner: IrqSafeSpinLock::new(Ruleset {
                tables: Vec::new(),
                generation: 1,
            }),
        }
    }

    /// Get-or-create a table.
    fn table_mut<F, R>(&self, name: &str, f: F) -> R
    where
        F: FnOnce(&mut Table) -> R,
    {
        let mut ruleset = self.inner.lock();
        let tables = &mut ruleset.tables;
        let idx = tables.iter().position(|t| t.name == name);
        let i = match idx {
            Some(i) => i,
            None => {
                tables.push(Table::new(name.to_string()));
                tables.len() - 1
            }
        };
        let result = f(&mut tables[i]);
        ruleset.changed();
        result
    }

    /// Add a rule. Auto-creates the table and chain.
    pub fn add(&self, table: &str, chain: &str, rule: Rule) {
        self.table_mut(table, |t| {
            let c = t.chain(chain);
            c.append(rule);
        });
    }

    pub fn create_table(&self, name: &str) -> Result<(), RulesetError> {
        let mut ruleset = self.inner.lock();
        let tables = &mut ruleset.tables;
        if tables.iter().any(|table| table.name == name) {
            return Err(RulesetError::AlreadyExists);
        }
        tables.push(Table::new(name.to_string()));
        ruleset.changed();
        Ok(())
    }

    pub fn delete_table(&self, name: &str) -> Result<(), RulesetError> {
        let mut ruleset = self.inner.lock();
        let tables = &mut ruleset.tables;
        let index = tables
            .iter()
            .position(|table| table.name == name)
            .ok_or(RulesetError::NotFound)?;
        if !tables[index].chains.is_empty() {
            return Err(RulesetError::NotEmpty);
        }
        tables.remove(index);
        ruleset.changed();
        Ok(())
    }

    pub fn create_chain(&self, table: &str, chain: &str) -> Result<(), RulesetError> {
        let mut ruleset = self.inner.lock();
        let table = ruleset
            .tables
            .iter_mut()
            .find(|candidate| candidate.name == table)
            .ok_or(RulesetError::NotFound)?;
        if table.chains.iter().any(|candidate| candidate.name == chain) {
            return Err(RulesetError::AlreadyExists);
        }
        let hook = match chain {
            "prerouting" => HookPoint::PreRouting,
            "input" => HookPoint::LocalIn,
            "forward" => HookPoint::Forward,
            "output" => HookPoint::LocalOut,
            "postrouting" => HookPoint::PostRouting,
            _ => HookPoint::LocalIn,
        };
        table.chains.push(Chain::new(chain.to_string(), hook));
        ruleset.changed();
        Ok(())
    }

    pub fn delete_chain(&self, table: &str, chain: &str) -> Result<(), RulesetError> {
        let mut ruleset = self.inner.lock();
        let table = ruleset
            .tables
            .iter_mut()
            .find(|candidate| candidate.name == table)
            .ok_or(RulesetError::NotFound)?;
        let index = table
            .chains
            .iter()
            .position(|candidate| candidate.name == chain)
            .ok_or(RulesetError::NotFound)?;
        if !table.chains[index].rules.is_empty() {
            return Err(RulesetError::NotEmpty);
        }
        table.chains.remove(index);
        ruleset.changed();
        Ok(())
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
        let ruleset = self.inner.lock();
        let mut out = Vec::new();
        for t in &ruleset.tables {
            for c in t.chains.iter() {
                if c.hook == hook {
                    out.push(c.clone());
                }
            }
        }
        out
    }

    /// Consistent ruleset snapshot for read-only nfnetlink enumeration.
    /// Cloning under the one store lock prevents userspace from observing a
    /// table/chain/rule mixture from different updates.
    pub fn snapshot(&self) -> Vec<Table> {
        self.inner.lock().tables.clone()
    }

    pub(crate) fn snapshot_with_generation(&self) -> (u32, Vec<Table>) {
        let ruleset = self.inner.lock();
        (ruleset.generation, ruleset.tables.clone())
    }

    pub(crate) fn generation(&self) -> u32 {
        self.inner.lock().generation
    }

    /// Reset to empty. Test-only.
    #[doc(hidden)]
    pub fn __reset_for_test(&self) {
        let mut ruleset = self.inner.lock();
        ruleset.tables.clear();
        ruleset.generation = 1;
    }
}

static FILTER: Filter = Filter::new();

pub fn filter() -> &'static Filter {
    &FILTER
}

#[doc(hidden)]
pub fn __reset_for_test() {
    FILTER.__reset_for_test();
}

/// Add a rule to `table`/`chain`. Auto-creates both if absent.
pub fn nf_table_add(table: &str, chain: &str, m: Match, verdict: Verdict) {
    nf_table_add_in(0, table, chain, m, verdict);
}

pub fn nf_table_add_in(net_ns_id: u64, table: &str, chain: &str, m: Match, verdict: Verdict) {
    if net_ns_id == 0 {
        FILTER.add(table, chain, Rule { m, verdict });
    } else {
        super::namespace::get(net_ns_id)
            .filter
            .add(table, chain, Rule { m, verdict });
    }
}

/// Set the default policy on `table`/`chain`.
pub fn nf_table_set_policy(table: &str, chain: &str, v: Verdict) {
    nf_table_set_policy_in(0, table, chain, v);
}

pub fn nf_table_set_policy_in(net_ns_id: u64, table: &str, chain: &str, v: Verdict) {
    if net_ns_id == 0 {
        FILTER.set_policy(table, chain, v);
    } else {
        super::namespace::get(net_ns_id)
            .filter
            .set_policy(table, chain, v);
    }
}

// ── Hooks ───────────────────────────────────────────────────────────

fn filter_for(hook: HookPoint, ctx: &mut PktCtx<'_>) -> Verdict {
    let tuple = match parse_tuple_ipv4(ctx.packet()) {
        Some(t) => t,
        None => return Verdict::Accept,
    };
    let ct_state = ctx.conntrack_id.and_then(|id| {
        let map = if ctx.net_ns_id == 0 {
            conntrack::ct().lookup(&tuple)
        } else {
            super::namespace::get(ctx.net_ns_id)
                .conntrack
                .lookup(&tuple)
        };
        map.map(|e| e.lock().state).or_else(|| {
            let _ = id;
            None
        })
    });
    let chains = if ctx.net_ns_id == 0 {
        FILTER.chains_at(hook)
    } else {
        super::namespace::get(ctx.net_ns_id).filter.chains_at(hook)
    };
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

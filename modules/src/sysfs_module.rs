//! /sys/module/<name>/ adapter.
//!
//! Linux ref: `linux/kernel/module/sysfs.c::mod_sysfs_setup`
//! (`sysfs.c:401`).
//!
//! Per loaded module:
//!   * `name`     — module name
//!   * `version`  — manifest version
//!   * `refcnt`   — current refcount
//!   * `taint`    — placeholder
//!   * `holders/` — directory listing dependent modules
//!   * `parameters/<p>` — per-module parameter (rw)
//!   * `sections/<sect>` — section address (privileged read)
//!   * `notes/.note.<name>` — ELF notes (placeholder)

use alloc::format;
use alloc::string::ToString;
use alloc::sync::Arc;

use narf_filesystem::sysfs::{
    class_register, kobject_add_attr, kobject_add_writable_attr, Kobject,
};

use crate::loader::Module;

/// Install `/sys/module/<name>/` for the supplied module.
///
/// Idempotent — re-installing on the same name replaces the
/// previous kobject tree (which lets reloads work cleanly).
pub fn install_module(module: &Arc<Module>) -> Arc<Kobject> {
    // The "module" class lives at /sys/module/<name>/.
    // We reuse class_register's get-or-create semantics.
    let class_module = class_register("module");
    let kobj = narf_filesystem::sysfs::class_device_register(
        class_module,
        module.name(),
    );

    // ── Basic attributes ────────────────────────────────────────────
    let name = module.manifest.name.clone();
    kobject_add_attr(&kobj, "name", move || format!("{}\n", name));

    let version = module.manifest.version.clone();
    kobject_add_attr(&kobj, "version", move || format!("{}\n", version));

    let m_for_refcnt = module.clone();
    kobject_add_attr(&kobj, "refcnt", move || {
        format!("{}\n", m_for_refcnt.refcount.snapshot())
    });

    kobject_add_attr(&kobj, "taint", || "\n".to_string());

    let m_for_state = module.clone();
    kobject_add_attr(&kobj, "initstate", move || {
        format!("{}\n", m_for_state.state.lock().as_str())
    });

    let m_for_size = module.clone();
    kobject_add_attr(&kobj, "size", move || {
        format!("{}\n", m_for_size.total_size())
    });

    // ── Holders directory (placeholder; populated when dep graph wired) ──
    // Linux: `/sys/module/<name>/holders/` is a directory of symlinks.
    // We register an empty `holders` placeholder for now.
    kobject_add_attr(&kobj, "holders", || "\n".to_string());

    // ── Parameters ──────────────────────────────────────────────────
    let params_kobj = narf_filesystem::sysfs::class_device_register(
        kobj.clone(),
        "parameters",
    );
    // The cleanest writable-attr install needs a static lifetime for
    // the attr name. Since module-supplied parameter names are dynamic,
    // we currently leak the name into a static slot via Box::leak.
    // The number of modules + parameters in any sane system is small,
    // so the leak is bounded and equivalent to Linux's kobject_attr
    // strings (which are also typically static const).
    for p in &module.params {
        let name_static: &'static str = Box::leak(p.name.clone().into_boxed_str());
        // Both show + store closures need their own Arc<ParamSlot>
        // clone. The module owns the slot via its `params: Vec<ParamSlot>`
        // — we capture a raw pointer through an Arc<Module> clone so the
        // slot stays alive as long as the module does.
        let m_show = module.clone();
        let m_store = module.clone();
        let p_name_show = p.name.clone();
        let p_name_store = p.name.clone();
        kobject_add_writable_attr(
            &params_kobj,
            name_static,
            move || {
                if let Some(slot) = crate::params::find(&m_show.params, &p_name_show) {
                    format!("{}\n", slot.read())
                } else {
                    "\n".to_string()
                }
            },
            move |bytes: &[u8]| {
                let s = core::str::from_utf8(bytes)
                    .map_err(|_| narf_filesystem::FsError::InvalidData)?;
                if let Some(slot) = crate::params::find(&m_store.params, &p_name_store) {
                    slot.write(s.trim_end());
                    Ok(())
                } else {
                    Err(narf_filesystem::FsError::NotFound)
                }
            },
        );
    }

    // ── Sections directory (addresses) ──────────────────────────────
    let sections_kobj = narf_filesystem::sysfs::class_device_register(
        kobj.clone(),
        "sections",
    );
    for p in &module.placements {
        // Name based on section index, since the loader doesn't
        // currently track section names alongside placements.
        let nm: &'static str = Box::leak(format!(".sec{}", p.section_idx).into_boxed_str());
        let addr = p.target_addr;
        kobject_add_attr(&sections_kobj, nm, move || {
            format!("0x{:016x}\n", addr)
        });
    }

    kobj
}

// re-export Box so the macro-free path above compiles cleanly.
use alloc::boxed::Box;

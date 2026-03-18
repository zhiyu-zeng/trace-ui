// Cross-chunk merge and fixup logic

#![allow(dead_code)]

use bitvec::prelude::BitVec;
use rustc_hash::FxHashMap;

use crate::taint::parallel_types::{
    PartialUnresolvedLoad, PartialUnresolvedPairLoad, UnresolvedLoad, UnresolvedPairLoad,
    UnresolvedRegUse,
};
use crate::taint::scanner::{push_unique, CompactDeps, PairSplitDeps, RegLastDef, CONTROL_DEP_BIT};

/// Resolve a fully unresolved load using global state.
/// Determines pass-through exactly as single-threaded scan would.
pub fn resolve_unresolved_load(
    load: &UnresolvedLoad,
    global_mem_last_def: &FxHashMap<u64, (u32, u64)>,
    global_reg_last_def: &RegLastDef,
    patch_edges: &mut Vec<(u32, u32)>,
    init_corrections: &mut Vec<(u32, bool)>,
) {
    let mut all_same_store = true;
    let mut first_store_raw: Option<u32> = None;
    let mut store_val: Option<u64> = None;
    let mut has_init_mem = false;

    for offset in 0..load.width as u64 {
        if let Some(&(def_line, def_val)) = global_mem_last_def.get(&(load.addr + offset)) {
            patch_edges.push((load.line, def_line));
            match first_store_raw {
                None => {
                    first_store_raw = Some(def_line);
                    store_val = Some(def_val);
                }
                Some(first) if first != def_line => {
                    all_same_store = false;
                }
                _ => {}
            }
        } else {
            has_init_mem = true;
            all_same_store = false;
        }
    }

    // Pass-through check: exact same logic as scan_unified
    let is_pass_through = all_same_store
        && store_val.is_some()
        && load.load_value.is_some()
        && store_val.unwrap() == load.load_value.unwrap();

    if !is_pass_through {
        // Not pass-through → add register deps
        for r in &load.uses {
            if let Some(&def_line) = global_reg_last_def.get(r) {
                patch_edges.push((load.line, def_line));
            }
        }
    }

    // Correct init_mem_loads
    if !has_init_mem {
        init_corrections.push((load.line, false));
    }
}

/// Resolve partially unresolved loads — supplement missing mem deps.
/// Pass-through is already determined as false (mixed case). Reg deps already added.
pub fn resolve_partial_unresolved_loads(
    partials: &[PartialUnresolvedLoad],
    global_mem_last_def: &FxHashMap<u64, (u32, u64)>,
    patch_edges: &mut Vec<(u32, u32)>,
    init_corrections: &mut Vec<(u32, bool)>,
) {
    for partial in partials {
        let mut all_found = true;
        for &addr in &partial.missing_addrs {
            if let Some(&(def_line, _)) = global_mem_last_def.get(&addr) {
                patch_edges.push((partial.line, def_line));
            } else {
                all_found = false;
            }
        }
        if all_found {
            init_corrections.push((partial.line, false));
        }
    }
}

/// Resolve a fully unresolved pair load. Builds complete PairSplitDeps from global state.
pub fn resolve_unresolved_pair_load(
    pair: &UnresolvedPairLoad,
    global_mem_last_def: &FxHashMap<u64, (u32, u64)>,
    global_reg_last_def: &RegLastDef,
    global_last_cond_branch: Option<u32>,
    data_only: bool,
) -> (PairSplitDeps, Vec<(u32, u32)>) {
    let mut split = PairSplitDeps::default();
    let mut patch_edges = Vec::new();
    let ew = pair.elem_width;

    // half1 mem deps (first elem_width bytes)
    for offset in 0..ew as u64 {
        if let Some(&(raw, _)) = global_mem_last_def.get(&(pair.addr + offset)) {
            push_unique(&mut split.half1_deps, raw);
            patch_edges.push((pair.line, raw));
        }
    }
    // half2 mem deps (second elem_width bytes)
    for offset in ew as u64..2 * ew as u64 {
        if let Some(&(raw, _)) = global_mem_last_def.get(&(pair.addr + offset)) {
            push_unique(&mut split.half2_deps, raw);
            patch_edges.push((pair.line, raw));
        }
    }
    // shared: base reg dep
    if let Some(base) = pair.base_reg {
        if let Some(&raw) = global_reg_last_def.get(&base) {
            push_unique(&mut split.shared, raw);
            patch_edges.push((pair.line, raw));
        }
    }
    // shared: control dep
    if !data_only {
        if let Some(cb) = global_last_cond_branch {
            push_unique(&mut split.shared, cb | CONTROL_DEP_BIT);
            patch_edges.push((pair.line, cb | CONTROL_DEP_BIT));
        }
    }

    (split, patch_edges)
}

/// Resolve a partially unresolved pair load. Supplements missing half deps in existing PairSplitDeps.
pub fn resolve_partial_pair_load(
    partial: &PartialUnresolvedPairLoad,
    global_mem_last_def: &FxHashMap<u64, (u32, u64)>,
    global_reg_last_def: &RegLastDef,
    pair_split: &mut FxHashMap<u32, PairSplitDeps>,
    patch_edges: &mut Vec<(u32, u32)>,
) {
    let ew = partial.elem_width;
    let split = pair_split.entry(partial.line).or_default();

    if partial.half1_unresolved {
        for offset in 0..ew as u64 {
            if let Some(&(raw, _)) = global_mem_last_def.get(&(partial.addr + offset)) {
                push_unique(&mut split.half1_deps, raw);
                patch_edges.push((partial.line, raw));
            }
        }
    }
    if partial.half2_unresolved {
        for offset in ew as u64..2 * ew as u64 {
            if let Some(&(raw, _)) = global_mem_last_def.get(&(partial.addr + offset)) {
                push_unique(&mut split.half2_deps, raw);
                patch_edges.push((partial.line, raw));
            }
        }
    }
    if partial.base_reg_unresolved {
        if let Some(base) = partial.base_reg {
            if let Some(&raw) = global_reg_last_def.get(&base) {
                push_unique(&mut split.shared, raw);
                patch_edges.push((partial.line, raw));
            }
        }
    }
}

/// Resolve register uses that had no local definition.
pub fn resolve_unresolved_reg_uses(
    uses: &[UnresolvedRegUse],
    global_reg_last_def: &RegLastDef,
) -> Vec<(u32, u32)> {
    let mut patch_edges = Vec::new();
    for u in uses {
        if let Some(&def_line) = global_reg_last_def.get(&u.reg) {
            patch_edges.push((u.line, def_line));
        }
    }
    patch_edges
}

/// Add control deps for lines before the first local conditional branch.
/// Only adds for lines where needs_control_dep is true (non-pair, parsed, !data_only).
pub fn resolve_control_deps(
    chunk_start: u32,
    first_local_cond: Option<u32>,
    prev_last_cond: Option<u32>,
    chunk_end: u32,
    needs_control_dep: &BitVec,
    data_only: bool,
) -> Vec<(u32, u32)> {
    if data_only {
        return Vec::new();
    }
    let Some(prev_cond) = prev_last_cond else {
        return Vec::new();
    };
    let end = first_local_cond.unwrap_or(chunk_end);
    let mut patches = Vec::new();
    for line in chunk_start..end {
        let local_idx = (line - chunk_start) as usize;
        if local_idx < needs_control_dep.len() && needs_control_dep[local_idx] {
            patches.push((line, prev_cond | CONTROL_DEP_BIT));
        }
    }
    patches
}

/// Rebuild a single CompactDeps from multiple chunk deps + patch edges.
/// patch_edges are (source_line, dep_line) tuples from the fixup phase.
/// Uses push_unique for deduplication within each row.
pub fn rebuild_compact_deps(
    chunk_deps: &[CompactDeps],
    chunk_start_lines: &[u32],
    patch_edges: &[(u32, u32)],
) -> CompactDeps {
    // Group patch_edges by source line for efficient lookup
    let mut patches: FxHashMap<u32, Vec<u32>> = FxHashMap::default();
    for &(from, to) in patch_edges {
        patches.entry(from).or_default().push(to);
    }

    // Calculate total capacity
    let total_lines: usize = chunk_deps.iter().map(|c| c.offsets.len()).sum();
    let total_deps: usize =
        chunk_deps.iter().map(|c| c.data.len()).sum::<usize>() + patch_edges.len();

    let mut merged = CompactDeps::with_capacity(total_lines, total_deps);

    for (chunk_id, chunk) in chunk_deps.iter().enumerate() {
        let num_rows = chunk.offsets.len();
        for local_row in 0..num_rows {
            let global_line = chunk_start_lines[chunk_id] + local_row as u32;
            merged.start_row();

            // Add original deps from this chunk
            for &dep in chunk.row(local_row) {
                merged.push_unique(dep);
            }

            // Add patch deps from fixup
            if let Some(extras) = patches.get(&global_line) {
                for &dep in extras {
                    merged.push_unique(dep);
                }
            }
        }
    }

    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taint::types::RegId;
    use smallvec::smallvec;

    #[test]
    fn test_resolve_load_passthrough() {
        let mut global_mem = FxHashMap::default();
        for i in 0..8u64 {
            global_mem.insert(0x8000 + i, (10u32, 0x42u64));
        }
        let load = UnresolvedLoad {
            line: 20,
            addr: 0x8000,
            width: 8,
            load_value: Some(0x42),
            uses: smallvec![RegId(1), RegId(2)],
        };
        let mut global_reg = RegLastDef::new();
        global_reg.insert(RegId(1), 5);
        global_reg.insert(RegId(2), 8);

        let mut patch_edges = Vec::new();
        let mut init_corrections = Vec::new();
        resolve_unresolved_load(
            &load,
            &global_mem,
            &global_reg,
            &mut patch_edges,
            &mut init_corrections,
        );

        // Pass-through: only memory dep (one unique store line), no register deps
        assert!(patch_edges.iter().all(|&(from, _)| from == 20));
        assert!(patch_edges.iter().any(|&(_, to)| to == 10)); // mem dep
        assert!(!patch_edges.iter().any(|&(_, to)| to == 5)); // no reg dep x1
        assert!(!patch_edges.iter().any(|&(_, to)| to == 8)); // no reg dep x2
        assert_eq!(init_corrections, vec![(20, false)]);
    }

    #[test]
    fn test_resolve_load_not_passthrough_different_value() {
        let mut global_mem = FxHashMap::default();
        for i in 0..8u64 {
            global_mem.insert(0x8000 + i, (10u32, 0x99u64));
        }
        let load = UnresolvedLoad {
            line: 20,
            addr: 0x8000,
            width: 8,
            load_value: Some(0x42), // != 0x99
            uses: smallvec![RegId(1)],
        };
        let mut global_reg = RegLastDef::new();
        global_reg.insert(RegId(1), 5);

        let mut patch_edges = Vec::new();
        let mut init_corrections = Vec::new();
        resolve_unresolved_load(
            &load,
            &global_mem,
            &global_reg,
            &mut patch_edges,
            &mut init_corrections,
        );

        assert!(patch_edges.iter().any(|&(_, to)| to == 10)); // mem dep
        assert!(patch_edges.iter().any(|&(_, to)| to == 5)); // reg dep
    }

    #[test]
    fn test_resolve_load_init_mem() {
        // No global store exists → truly initial memory
        let global_mem = FxHashMap::default();
        let load = UnresolvedLoad {
            line: 20,
            addr: 0x8000,
            width: 4,
            load_value: None,
            uses: smallvec![RegId(1)],
        };
        let mut global_reg = RegLastDef::new();
        global_reg.insert(RegId(1), 5);

        let mut patch_edges = Vec::new();
        let mut init_corrections = Vec::new();
        resolve_unresolved_load(
            &load,
            &global_mem,
            &global_reg,
            &mut patch_edges,
            &mut init_corrections,
        );

        // No mem deps (no store found), but reg deps added (not pass-through)
        assert!(patch_edges.iter().any(|&(_, to)| to == 5));
        // init_mem_loads should NOT be corrected (it IS truly initial)
        assert!(init_corrections.is_empty());
    }

    #[test]
    fn test_resolve_partial_loads() {
        let mut global_mem = FxHashMap::default();
        global_mem.insert(0x8002u64, (15u32, 0u64));
        global_mem.insert(0x8003u64, (15u32, 0u64));

        let partials = vec![PartialUnresolvedLoad {
            line: 25,
            missing_addrs: smallvec![0x8002, 0x8003],
        }];

        let mut patch_edges = Vec::new();
        let mut init_corrections = Vec::new();
        resolve_partial_unresolved_loads(
            &partials,
            &global_mem,
            &mut patch_edges,
            &mut init_corrections,
        );

        assert!(patch_edges.iter().any(|&(from, to)| from == 25 && to == 15));
        assert_eq!(init_corrections, vec![(25, false)]);
    }

    #[test]
    fn test_resolve_pair_load() {
        let mut global_mem = FxHashMap::default();
        for i in 0..4u64 {
            global_mem.insert(0x8000 + i, (10, 0));
        }
        for i in 4..8u64 {
            global_mem.insert(0x8000 + i, (15, 0));
        }
        let mut global_reg = RegLastDef::new();
        global_reg.insert(RegId(3), 7);

        let pair = UnresolvedPairLoad {
            line: 25,
            addr: 0x8000,
            elem_width: 4,
            base_reg: Some(RegId(3)),
            defs: smallvec![RegId(0), RegId(1), RegId(3)],
        };
        let (split, _patches) = resolve_unresolved_pair_load(
            &pair,
            &global_mem,
            &global_reg,
            None,
            false,
        );
        assert!(split.half1_deps.contains(&10));
        assert!(split.half2_deps.contains(&15));
        assert!(split.shared.contains(&7));
    }

    #[test]
    fn test_resolve_reg_uses() {
        let mut global_reg = RegLastDef::new();
        global_reg.insert(RegId(5), 42);
        let uses = vec![
            UnresolvedRegUse { line: 100, reg: RegId(5) },
            UnresolvedRegUse { line: 101, reg: RegId(6) }, // not defined
        ];
        let patches = resolve_unresolved_reg_uses(&uses, &global_reg);
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0], (100, 42));
    }

    #[test]
    fn test_resolve_control_deps() {
        use bitvec::prelude::*;
        let mut needs = BitVec::new();
        // 10 lines: chunk starts at 100
        for i in 0..10 {
            needs.push(i != 3 && i != 7); // lines 103 and 107 don't need control dep
        }
        let patches = resolve_control_deps(100, Some(105), Some(95), 110, &needs, false);
        // Lines 100-104 (before first_local_cond=105), except 103
        assert!(patches.contains(&(100, 95 | CONTROL_DEP_BIT)));
        assert!(patches.contains(&(101, 95 | CONTROL_DEP_BIT)));
        assert!(patches.contains(&(102, 95 | CONTROL_DEP_BIT)));
        assert!(!patches.iter().any(|&(line, _)| line == 103)); // pair/unparsed
        assert!(patches.contains(&(104, 95 | CONTROL_DEP_BIT)));
        assert!(!patches.iter().any(|&(line, _)| line >= 105)); // after first local cond
    }

    #[test]
    fn test_rebuild_compact_deps() {
        // Chunk 0: 3 lines (lines 0,1,2)
        let mut c0 = CompactDeps::with_capacity(3, 6);
        c0.start_row(); // line 0: no deps
        c0.start_row();
        c0.push_unique(0); // line 1 → line 0
        c0.start_row();
        c0.push_unique(1); // line 2 → line 1

        // Chunk 1: 2 lines (lines 3,4)
        let mut c1 = CompactDeps::with_capacity(2, 4);
        c1.start_row(); // line 3: no local deps
        c1.start_row();
        c1.push_unique(3); // line 4 → line 3

        let patch_edges = vec![
            (3u32, 2u32), // line 3 depends on line 2 (cross-chunk)
        ];

        let merged = rebuild_compact_deps(&[c0, c1], &[0, 3], &patch_edges);

        // Verify
        assert_eq!(merged.row(0).len(), 0); // line 0: no deps
        assert_eq!(merged.row(1), &[0]); // line 1 → 0
        assert_eq!(merged.row(2), &[1]); // line 2 → 1

        let mut line3: Vec<u32> = merged.row(3).to_vec();
        line3.sort();
        assert_eq!(line3, vec![2]); // line 3 → 2 (from patch)

        assert_eq!(merged.row(4), &[3]); // line 4 → 3
    }

    #[test]
    fn test_rebuild_compact_deps_dedup() {
        let mut c0 = CompactDeps::with_capacity(2, 4);
        c0.start_row(); // line 0
        c0.start_row();
        c0.push_unique(0); // line 1 → 0

        // Patch also adds line 1 → 0 (duplicate)
        let patch_edges = vec![(1u32, 0u32)];

        let merged = rebuild_compact_deps(&[c0], &[0], &patch_edges);
        assert_eq!(merged.row(1).len(), 1); // deduped to single entry
        assert_eq!(merged.row(1), &[0]);
    }
}

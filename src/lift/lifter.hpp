#pragma once
// lift/lifter.hpp
// Layer 2 (lift): materialization of the trace into an ordered, program-shaped
// intermediate representation that layer 3 (reconstruct) can structure.
//
// The lifter walks the recovered CFG in linear (discovery) order and emits one
// lift item per control-flow node, with the loop and branch relationships
// already resolved:
//   - natural loops are recovered from the dominator back edges (computed on
//     the executed-edge subgraph, see Cfg::executed_graph) and recorded as
//     (header, back-sources) pairs;
//   - numeric-for header slots are tagged and paired with their increment
//     slot: mock backend pairs the for-head BRANCH with the ADVANCE that backs
//     into it; luau backend pairs FORNPREP with the FORNLOOP back edge;
//   - branch nodes carry their executed side and their declared other side.
//
// The lifter never invents statements: pcs that were never executed do not
// exist as lift items, and their existence is preserved only as the declared
// "other_target" annotation of a branch.

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "lift/cfg.hpp"
#include "lift/dominator.hpp"
#include "resilience/resolved.hpp"

namespace lure::lift {

struct LiftItem
{
    uint64_t pc = 0;
    std::string tag;
    std::string text;
    std::string cond_dsl;
    std::string cond_text;
    bool is_branch = false;
    bool is_numeric_for_head = false;  // mock: for-head BRANCH paired with an ADVANCE
    bool is_advance = false;           // mock: for-increment slot
    bool is_jump = false;              // unconditional jump (loop back-edge, if-else skip)
    bool is_numeric_for_advance = false; // TRUE when the advance backs a known head
    bool is_fornprep = false;          // luau: numeric-for preparation slot
    bool is_fornloop = false;          // luau: numeric-for increment+test slot
    bool is_loop_backedge = false;     // item whose executed target is a loop head
    bool unresolved = false;
    std::string notfound_reason;
    uint32_t line = 0;

    // branch payload
    bool branch_taken = false;
    uint64_t jump_target = 0;
    bool other_target_known = false;
    int64_t other_target = -1;

    // header pcs of the natural loops for which this item is a back-edge
    // source (empty for ordinary items)
    std::vector<uint64_t> backedge_headers;

    // natural-loop membership computed by the lifter
    std::set<uint64_t> loops; // headers of the natural loops this pc belongs to
};

struct LiftedProgram
{
    std::vector<LiftItem> items; // in executed (linear) order
    std::map<uint64_t, size_t> pc_to_item;
    std::vector<std::pair<uint64_t, uint64_t>> back_edges;  // (src, dst) natural back edges
    std::map<uint64_t, std::vector<uint64_t>> loop_backs;   // header -> back sources
    std::vector<std::pair<uint64_t, uint64_t>> numeric_for_pairs; // (head, increment-slot)
    uint64_t exit_pc = 0;        // last executed pc
    bool truncated = false;
    std::string vm_kind;
};

// Lifts a CFG (+ its dominator info over the executed-edge subgraph) into the
// program IR. Never throws.
Resolved<LiftedProgram> lift(const Cfg& cfg, const Cfg& exec, const DominatorInfo& doms);

} // namespace lure::lift
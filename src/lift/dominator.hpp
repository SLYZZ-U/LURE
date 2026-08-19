#pragma once
// lift/dominator.hpp
// Layer 2 (lift): dominator and post-dominator analysis over the recovered CFG.
//
// Used to (a) identify natural loops (a back edge (src -> dst) where dst
// dominates src) and (b) find structural join points for branch reconstruction.
// The analysis is the classic iterative dataflow algorithm (Aho, Lam, Sethi,
// Ullman, "Compilers: Principles, Techniques, and Tools", ch. 9), which is
// robust for the small graphs a single trace produces and simple to audit.

#include <cstdint>
#include <map>
#include <vector>

#include "lift/cfg.hpp"
#include "resilience/resolved.hpp"

namespace lure::lift {

struct DominatorInfo
{
    // pc -> set of dominators (the node itself listed last-ish; entry dominates
    // everything). Iteration order is dataflow-fixpoint order.
    std::map<uint64_t, std::vector<uint64_t>> dominators;
    // pc -> immediate dominator; entry maps to itself.
    std::map<uint64_t, uint64_t> idom;
    // linear discovery order (used to keep outputs deterministic).
    std::vector<uint64_t> order;
};

// Computes dominators of the CFG from the entry node.
Resolved<DominatorInfo> compute_dominators(const Cfg& cfg);

// Computes post-dominators (dominance in the reverse graph rooted at the exit
// nodes). Nodes that cannot reach an exit have no post-dominator and are
// omitted from the result.
Resolved<DominatorInfo> compute_postdominators(const Cfg& cfg);

bool dominates(const DominatorInfo& di, uint64_t a, uint64_t b);

} // namespace lure::lift
#pragma once
// concolic/concolic.hpp
// Layer 4 (concolic): path-prefix feasibility analysis over a layer-1 trace.
// For every branch with a modeled condition and a declared other target, the
// solver decides whether that other side is reachable under the branch
// outcomes observed before it. Results annotate reconstruction; they never
// change the reconstructed statements.

#include <cstdint>
#include <string>
#include <vector>

#include "concolic/solver.hpp"
#include "resilience/resolved.hpp"
#include "trace/trace_events.hpp"

namespace lure::concolic {

struct Feasibility
{
    uint64_t branch_pc = 0;
    int64_t other_target = -1;
    std::string condition;   // DSL of the probed branch
    bool other_side_is_taken_outcome = false; // TRUE if the observed outcome IS the other side
    CheckResult result;
};

// Probes every decidable branch with a declared other target. `solver` may be
// null, in which case all entries are reported as Unknown with a note.
Resolved<std::vector<Feasibility>> check_unexecuted_sides(const TraceData& trace, Solver* solver);

} // namespace lure::concolic
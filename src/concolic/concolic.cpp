// concolic/concolic.cpp
#include "concolic/concolic.hpp"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace lure::concolic {

Resolved<std::vector<Feasibility>> check_unexecuted_sides(const TraceData& trace, Solver* solver)
{
    std::vector<Feasibility> out;

    std::vector<std::string> prefix;
    std::vector<bool> prefix_pol;
    std::vector<uint64_t> probed; // pcs already probed (deduplication)

    for (const TraceEvent& e : trace.events)
    {
        if (!e.is_branch)
            continue;
        if (e.tag == "STEPLIMIT" || e.tag == "TRUNCATED")
            break;

        if (!e.cond_dsl.empty() && e.other_target >= 0 &&
            std::find(probed.begin(), probed.end(), e.pc) == probed.end())
        {
            Feasibility f;
            f.branch_pc = e.pc;
            f.other_target = e.other_target;
            f.condition = e.cond_dsl;
            f.other_side_is_taken_outcome = false;
            if (solver)
            {
                std::string err;
                f.result = solver->check(prefix, prefix_pol, e.cond_dsl, err);
                if (!err.empty() && f.result.verdict == Verdict::Unknown && f.result.note.empty())
                    f.result.note = err;
            }
            else
            {
                f.result.verdict = Verdict::Unknown;
                f.result.note = "no solver backend available";
            }
            probed.push_back(e.pc);
            out.push_back(std::move(f));
        }

        if (!e.cond_dsl.empty())
        {
            prefix.push_back(e.cond_dsl);
            prefix_pol.push_back(e.branch_taken);
        }
    }

    return Resolved<std::vector<Feasibility>>::success(std::move(out));
}

} // namespace lure::concolic
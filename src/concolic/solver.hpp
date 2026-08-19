#pragma once
// concolic/solver.hpp
// Layer 4 (concolic): feasibility checking of branch conditions against the
// path-prefix constraints collected from the trace.
//
// The recovery layers are built on the observed single path. The solver's job
// is to answer one narrow question without inventing semantics: "given the
// executed branch outcomes recorded up to instruction X, is the *other* side
// of X's condition satisfiable?" — i.e. would another input have been able to
// reach the unexecuted target, or is that side provably dead on this path.
// Verdicts are only annotations; they never gate reconstruction.

#include <memory>
#include <string>
#include <vector>

namespace lure::concolic {

enum class Verdict
{
    Sat,     // a model exists (feasible)
    Unsat,   // provably infeasible on this path prefix
    Unknown, // not modeled (parser limits) or solver error
};

struct CheckResult
{
    Verdict verdict = Verdict::Unknown;
    std::string model; // assignment text when Sat
    std::string note;  // reason when Unknown
};

// Ground DSL conditions to an SMT model. Implementations must be deterministic
// and side-effect free; a failure to model anything must yield Unknown, never
// a guess.
class Solver
{
public:
    virtual ~Solver() = default;

    // conds: DSL of each executed branch BEFORE the query point, with `pol`
    // the observed outcome (true = taken). query: DSL of the branch whose
    // OTHER side is being probed. err is set on hard failures.
    virtual CheckResult check(const std::vector<std::string>& conds,
        const std::vector<bool>& pol, const std::string& query, std::string& err) = 0;

    virtual std::string name() const = 0;
};

// Default solver: Z3 when LURE_USE_Z3, nullptr otherwise.
std::unique_ptr<Solver> create_solver();

} // namespace lure::concolic
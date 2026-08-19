#pragma once
// reconstruct/structural.hpp
// Layer 3 (reconstruct): structured decompilation of the lifted program into
// a syntax tree of Lua statements: sequence, if (single-sided when the other
// side was never executed), while, and numeric-for loops.
//
// Honesty contract: the trace only ever shows executed instructions. A branch
// whose other side was never executed is reconstructed as a single-sided if
// plus a Notfound annotation carrying the declared-but-unexecuted target; a
// numeric-for bound that was never materialized as a literal is a Notfound
// annotation as well. Nothing is invented.

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "resilience/resolved.hpp"

namespace lure::lift {
struct LiftedProgram;
}

namespace lure::lift {
struct DominatorInfo;
}

namespace lure::lift {
struct Cfg;
}

namespace lure::reconstruct {

struct StNode;
using StNodePtr = std::unique_ptr<StNode>;

struct StNode
{
    enum class K
    {
        Seq,        // sequential children
        If,         // conditional with cond; then/else branches
        While,      // pre-tested loop
        NumericFor, // numeric for loop
        Plain,      // a single executed statement (tag + textual sketch)
        Notfound    // annotation only: emitted as "-- not found: <reason>"
    } k = K::Seq;

    // Seq
    std::vector<StNodePtr> children;
    // If / While
    std::string cond;
    StNodePtr then_b;
    StNodePtr else_b;          // nullptr or a Notfound (unexecuted side) / a real body
    StNodePtr body;            // While / NumericFor loop body
    // NumericFor
    std::string loop_var;
    std::string lo_text;
    std::string hi_text;
    std::string step_text;
    std::string lo_note;       // Notfound explanation for the lower bound, if any
    std::string step_note;     // Notfound explanation for the step, if any
    // Plain
    uint64_t pc = 0;
    std::string tag;
    std::string text;
    uint32_t line = 0;
    bool unresolved = false;
    std::string reason;
    // Notfound
    std::string annotation;
};

// Structures the lifted program, using the executed-edge subgraph (for
// post-dominator join targets) and the post-dominator info computed over it.
// Returns an error only when the lifted program itself is unusable;
// structural weaknesses become Notfound nodes.
Resolved<StNodePtr> structure(const lift::LiftedProgram& lp, const lift::Cfg& exec,
    const lift::DominatorInfo& pdom);

} // namespace lure::reconstruct
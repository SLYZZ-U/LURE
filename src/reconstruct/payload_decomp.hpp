// reconstruct/payload_decomp.hpp
// Third, deepest pass (meant to run after the frame slice): register-level
// reconstruction of the printed payload inside its own call frame.
//
// The payload frame is executed under the real VM with its own real registers,
// so its events form a linear value path: every instruction's rendered
// right-hand side is an observed value. A backward slice starting from the
// printing call sites recovers the minimal set of definitions that produced
// the output. Accessor helper calls (pure frames that only read constants and
// return a value) fold away entirely -- their results appear as literals.
//
// Soundness contract: the emitted Lua is re-run against the instrumented VM
// and its stdout must match the recorded stdout byte-for-byte; only then is
// the result accepted (the caller owns that verification). Anything the pass
// cannot prove safe (loops in the live chain, tables written on the path,
// unresolved callees) aborts to the coarser observed-value slice.

#pragma once

#include "trace/trace_events.hpp"

#include <functional>
#include <string>
#include <vector>

namespace lure::reconstruct {

struct PayloadDecompResult
{
    bool ok = false;
    std::string lua; // executable Luau statements reproducing the stdout
    std::string why; // verdict / reason (set on both success and failure)
    // Statements recovered from a forced re-execution of the un-taken side of an
    // observed branch, i.e. observed under a probe rather than in the recorded
    // run. Reported so the sidecar can say exactly where they came from.
    unsigned probed_branches = 0;
    unsigned probes_run = 0;
    unsigned probes_dropped = 0; // candidates left unprobed because of the cap
    // How much of the run's observable behaviour this candidate puts into words.
    // Used to choose between candidates that both reproduce the output: the one
    // that leaves fewer effects unexpressed says more about the program.
    unsigned expressed_effects = 0;
    unsigned unexpressed_effects = 0;
};

// Runs on a frame-sliced trace; finds the unique frame that printed and tries
// a register-level reconstruction of its payload.
PayloadDecompResult decompile_payload(const TraceData& trace);

// Alternative, control-flow-flattening-aware reconstruction. The observed trace
// is already the *unrolled* linear execution of the printing frame, so a single
// forward symbolic pass over that frame recovers table literals, field-access
// expressions (t.field) and prints with propagated expressions, while the CFF
// dispatch machinery (state arithmetic that reaches no observable effect) is
// simply never emitted. Meant to run before decompile_payload; the caller
// verifies the emitted Lua byte-for-byte. ok=false with a reason when it cannot
// (e.g. output spans multiple frames).
PayloadDecompResult decompile_payload_symbolic(const TraceData& trace);

// The flat statement list that pass reconstructs, one Lua statement per entry
// and no branch structure. Exposed so a caller can build the same list for a
// probe run (see BranchProbe) and diff the two.
std::vector<std::string> symbolic_statements(const TraceData& trace);

// ---------------------------------------------------------------------------
// Branch recovery by forced re-execution
//
// A single trace contains *no* information about the side of a branch it did not
// take: the un-taken target never appears in it, and under control-flow
// flattening the guarded block is not even adjacent to the branch (both sides
// re-enter the dispatcher, which is what makes the static control dependence
// unrecoverable). Guessing the extent of the guarded block would invent
// structure, so instead the pass asks the caller to *re-run the script with that
// one branch decided the other way* and compares the two statement lists. What
// the two runs share is outside the conditional; where they differ is the
// then-body and the else-body -- both observed, neither invented.
// ---------------------------------------------------------------------------

// Names one dispatch of one observed conditional jump.
struct ProbeRequest
{
    uint32_t frame_id = 0;
    uint32_t pc = 0;
    uint32_t hit_index = 0; // 0 = first time this (frame, pc) was reached
};

struct ProbeReply
{
    // TRUE only when the inversion actually fired, the run completed without an
    // interpreter error and its trace was not truncated. Anything else proves
    // nothing about the un-taken side.
    bool usable = false;
    std::string why;                     // why it is not usable
    std::vector<std::string> statements; // symbolic_statements() of the probe run
};

using BranchProbe = std::function<ProbeReply(const ProbeRequest&)>;

// Same as decompile_payload_symbolic, additionally recovering `if/else` around
// the statements a probe proves are guarded. Falls back to the flat statement
// list for every branch the probe cannot settle, and annotates why.
PayloadDecompResult decompile_payload_symbolic(const TraceData& trace, const BranchProbe& probe);

// The general reconstruction (see symbolic.hpp): interprets the frame carrying
// the run's observable effects at opcode level and emits a statement for each
// one -- calls, writes to globals, table mutations, returns -- not only prints.
// Recovers called functions, folds numeric-for loops it can prove equivalent,
// and goes through the same probe/region machinery for `if/else`. Reports how
// many effects it could and could not express, so the caller can pick between
// candidates that both reproduce the output.
PayloadDecompResult decompile_general(const TraceData& trace, const BranchProbe& probe);

// The general pass's flat statement list, for probe comparison.
std::vector<std::string> general_statements(const TraceData& trace);

} // namespace lure::reconstruct
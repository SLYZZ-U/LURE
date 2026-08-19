#pragma once
// reconstruct/symbolic.hpp
// General symbolic reconstruction of one executed Lua frame (and, recursively,
// the frames it calls) into readable Lua statements.
//
// This is the generalisation of the payload pass: instead of recognising only
// printed output, it interprets the trace at the level of Luau's opcodes and
// emits a statement for every *externally observable effect* it can express --
// a call, a write to a global, a mutation of a table it reconstructed, a return
// -- with every operand rendered as a propagated expression rather than as the
// single value that happened to be observed.
//
// Honesty rules, unchanged from the rest of the pipeline:
//   * an operand it cannot express falls back to the value the trace observed;
//     if there is no such value, the whole statement is dropped and counted in
//     `unmodeled` with a reason, never emitted as a guess;
//   * pure computation that never reaches an observable effect is simply never
//     emitted (this is what elides an obfuscator's decoder and its flattened
//     dispatch arithmetic, with no knowledge of either);
//   * loops are folded only when the recovered loop provably reproduces every
//     observed iteration; otherwise the iterations stay unrolled and say so;
//   * nothing here decides that the result is correct -- the caller re-runs the
//     emitted Lua and compares the observable behaviour.

#include "trace/trace_events.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace lure::reconstruct {

struct SymStatement
{
    std::string text;        // one rendered Lua statement (no trailing newline)
    size_t event_index = 0;  // trace event that produced it
    unsigned depth = 0;      // nesting level, for indentation
    bool is_effect = false;  // externally observable (call / global / mutation)
    // Set when the statement binds a name (`local v3 = ...`). A binding nothing
    // ever reads is dead: the value was computed for the obfuscator's benefit,
    // not the program's, and dropping it is what removes a decoder's calls
    // without knowing anything about the decoder.
    std::string def_name;
    // TRUE when the bound value comes from a call, so dropping the *binding*
    // still has to keep the call itself if the call is observable.
    bool binds_call = false;
    bool observable_call = false;
    std::string text_call; // the call alone, without the binding
};

// A conditional inside the reconstructed frame whose executed side is
// expressible in reconstructed terms, and which is therefore worth probing by
// re-execution (see payload_decomp.hpp).
struct SymBranch
{
    uint32_t frame_id = 0;
    uint32_t pc = 0;
    uint32_t hit_index = 0;
    std::string cond;      // condition guarding the side the trace took
    size_t stmt_index = 0; // statements already emitted when it was reached
};

struct SymProgram
{
    bool ok = false;
    std::string why;
    std::vector<std::string> decls;    // hoisted table constructors / functions
    std::vector<SymStatement> stmts;
    std::vector<SymBranch> branches;
    unsigned unmodeled = 0;            // effects that could not be expressed
    std::vector<std::string> notes;    // one per distinct reason, deduplicated
};

// Reconstructs the frame that carries the trace's observable effects. Prefers a
// frame that produced output; when nothing was printed, falls back to the frame
// that wrote to the outside world (a global, or a table reached through one).
SymProgram reconstruct_symbolic(const TraceData& trace);

} // namespace lure::reconstruct

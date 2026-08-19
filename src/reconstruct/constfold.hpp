#pragma once
// reconstruct/constfold.hpp
// Layer 2.5 (reconstruct): constant folding over the recorded trace.
//
// The Luau backend renders every operand as the value observed at that very
// instruction (instrumentation.cpp: operand_text), so the decoder chains of
// obfuscated scripts already carry their constants: "t = 18 * 262144",
// "string.char(72, 101, 108)". This pass folds those expressions and rewrites
// the event texts in place before the CFG/lift stages, collapsing arithmetic
// chains into the literals the VM actually computed.
//
// Honesty contract: the fold only ever replaces an expression by the result
// of evaluating that same expression under Luau semantics with the observed
// operands. Nothing is invented: a register name that was never observed as
// a constant blocks the fold, and unparsable texts are left untouched.
// The environment is linear (per-event, first-execution semantics), matching
// the snapshot contract of the rest of the pipeline.

#include "trace/trace_events.hpp"

namespace lure::reconstruct {

// Rewrites ev.text in every event of the trace. Never throws, never fails:
// events that do not match the grammar are left as recorded.
void fold_constants(TraceData& trace);

} // namespace lure::reconstruct
// reconstruct/trace_slice.hpp
// Universal stdout-frame slicing: keeps exactly the events whose call frames
// can reach a print of the observed output, and drops everything else. The
// rule is structural (call depth relative to the deepest printing frame) and
// script-agnostic: an obfuscator's loader/decoder machinery runs in frames
// shallower than the code it finally executes, so it is elided wholesale.
//
// Soundness contract: every event that directly produced stdout is retained
// (its frame is by definition within the region); the region is a superset of
// all transitive producers, so a recorded output can be reproduced 1:1 from
// the retained events alone. When no print is observed the trace is left
// untouched (the pipeline falls back to the full reconstruction).

#pragma once

#include "trace/trace_events.hpp"

namespace lure::reconstruct {

struct SliceResult
{
    bool sliced = false;       // true: the region was narrower than the trace
    size_t retained = 0;       // events kept (after rebuild)
    size_t elided = 0;         // events dropped
    uint32_t floor_depth = 0;  // lowest retained call depth
    size_t terminals = 0;      // printing call sites found
};

// In-place shrink of trace.events; returns the slicing verdict.
SliceResult slice_to_printing_frames(TraceData& trace);

// Second, tighter pass (meant to run after the frame slice): keeps exactly the
// events whose defined value provably reached a printing call site, by
// literal-value identity. A def "x = <literal>" survives iff the literal is
// one of the observed stdout arguments (or was produced transitively by
// another surviving def). Everything else -- loads, helpers, metatable
// tampering -- is elided. Never keeps anything a frame slice would keep
// spuriously: literals equal to an output string that never reached it are
// still provably harmless to drop (they cannot change the output), and the
// report records the elision.
SliceResult slice_by_observed_values(TraceData& trace);

// True iff the event is a call site that wrote to stdout. Backed by the
// runtime's behavioral flag (TraceEvent::printed_output), never by callee name.
bool event_calls_print(const TraceEvent& ev);

} // namespace lure::reconstruct
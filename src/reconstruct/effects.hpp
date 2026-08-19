#pragma once
// reconstruct/effects.hpp
// What a run does that anything outside it can see.
//
// The pipeline's honesty gate used to be "the emitted Lua prints the same
// bytes". That is empty for the scripts this tool actually targets: a Roblox
// script builds interfaces, calls services and writes globals, and prints
// nothing at all, so *any* silent candidate passed. The signature below is the
// generalisation -- the ordered sequence of things the script did to the world
// outside itself:
//
//   * output written to the host's stream (marked behaviorally by the print
//     sink, never by callee name);
//   * a write to a global, which any other script can read;
//   * a call into a function the *host* provided rather than the language: those
//     are exactly the natives the stdlib whitelist did not claim, so they are
//     identified by what the trace already recorded about them and not by a list
//     of names.
//
// Two runs with the same signature are indistinguishable from outside the
// script, which is what "reproduces the recorded behaviour" has to mean.

#include "trace/trace_events.hpp"

#include <string>
#include <vector>

namespace lure::reconstruct {

// TRUE iff this event is one of the three kinds above. Used both to anchor the
// reconstruction on the frame that carries the behaviour and to compare runs.
bool event_is_observable_effect(const TraceEvent& ev);

// The ordered signature of a run. Values that have no stable identity across
// runs (tables, functions) render as a placeholder, so the comparison is over
// what the script did rather than over addresses it happened to get.
std::vector<std::string> effect_signature(const TraceData& trace);

} // namespace lure::reconstruct

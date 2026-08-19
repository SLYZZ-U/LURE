#pragma once
// lift/vm_detector.hpp
// Layer 2 (lift): backend identification. The trace's vm_kind field is the
// authoritative source; this detector additionally validates consistency with
// the observed event shape and reports a confidence verdict, so a mismatched
// or hand-edited trace is flagged instead of silently trusted.

#include <string>

#include "resilience/resolved.hpp"
#include "trace/trace_events.hpp"

namespace lure::lift {

struct BackendVerdict
{
    std::string kind;      // "mock" | "luau-instrumented" | "unknown"
    bool authoritative = false; // TRUE when vm_kind was self-declared
    std::string reason;    // human-readable justification
};

// Classifies the backend that produced a trace. Never throws.
Resolved<BackendVerdict> detect_backend(const TraceData& trace);

} // namespace lure::lift
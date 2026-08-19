// lift/vm_detector.cpp
#include "lift/vm_detector.hpp"

#include <cstddef>

namespace lure::lift {

Resolved<BackendVerdict> detect_backend(const TraceData& trace)
{
    BackendVerdict v;

    // 1. self-declaration
    if (trace.vm_kind == "mock" || trace.vm_kind == "luau-instrumented")
    {
        v.kind = trace.vm_kind;
        v.authoritative = true;
        v.reason = "trace self-declared vm_kind=\"" + trace.vm_kind + "\"";
    }
    else
    {
        v.kind = "unknown";
        v.reason = "trace has no recognizable vm_kind (\"" + trace.vm_kind + "\")";
    }

    // 2. consistency check against the event shape: the instrumented Luau VM
    // reports bytecode opcode mnemonics (opcode byte + tag), the mock reports
    // semantic tags. A mismatch is reported but never guessed around.
    if (v.kind == "mock")
    {
        if (!trace.events.empty() && trace.events[0].opcode != 0)
        {
            v.authoritative = false;
            v.reason += "; inconsistent: first event carries a nonzero opcode byte while declaring mock";
        }
    }
    else if (v.kind == "luau-instrumented")
    {
        size_t tagged = 0;
        for (const TraceEvent& e : trace.events)
            if (e.opcode != 0 || !e.tag.empty())
                ++tagged;
        if (tagged == 0)
        {
            v.authoritative = false;
            v.reason += "; inconsistent: no event carries an opcode or mnemonic while declaring luau-instrumented";
        }
    }

    return Resolved<BackendVerdict>::success(std::move(v));
}

} // namespace lure::lift
// reconstruct/trace_slice.cpp
// see trace_slice.hpp

#include "reconstruct/trace_slice.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <unordered_set>
#include <vector>

namespace lure::reconstruct {

bool event_calls_print(const TraceEvent& ev)
{
    // Behavioral detection: the runtime marked this call event when the
    // callee wrote to the observable output stream (print sink). Name-free by
    // design -- an alias, wrapper, or any function that emits output is
    // detected the same way as a direct `print(...)` call.
    return ev.printed_output;
}

SliceResult slice_by_observed_values(TraceData& trace)
{
    SliceResult out;
    std::vector<TraceEvent>& events = trace.events;
    if (events.empty())
        return out;

    // seed the live set with the exact arg values of every print call
    std::unordered_set<std::string> live;
    auto arg_text = [](const LuaValueSnapshot& a) -> std::string {
        switch (a.type)
        {
        case ValueType::String:
            return a.text;
        case ValueType::Number:
            return lua_number_text(a.nvalue);
        case ValueType::Bool:
            return a.text.empty() ? (a.nvalue != 0.0 ? "true" : "false") : a.text;
        default:
            return std::string();
        }
    };
    for (const TraceEvent& e : events)
    {
        if (!event_calls_print(e) || !e.call_info)
            continue;
        for (const LuaValueSnapshot& a : e.call_info->args)
        {
            std::string t = arg_text(a);
            if (!t.empty())
                live.insert(t);
        }
    }
    if (live.empty())
        return out;

    // backward: keep a literal def "x = <lit>" iff lit is live. Every kept
    // def re-presents the literal it contributed, so no new values are ever
    // pulled in -- the live set is closed under the slice.
    std::vector<std::pair<TraceEvent, bool>> kept;
    kept.reserve(events.size());
    for (auto it = events.rbegin(); it != events.rend(); ++it)
    {
        const TraceEvent& e = *it;
        bool keep = event_calls_print(e); // printing sites always survive
        if (!keep)
        {
            // "name = <single literal>" def form
            size_t eq = e.text.find('=');
            if (eq != std::string::npos && eq > 0)
            {
                std::string lhs = e.text.substr(0, eq);
                while (!lhs.empty() && std::isspace(static_cast<unsigned char>(lhs.back())))
                    lhs.pop_back();
                bool name = true;
                for (char c : lhs)
                    if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_'))
                    {
                        name = false;
                        break;
                    }
                std::string rhs;
                size_t p = eq + 1;
                while (p < e.text.size() && std::isspace(static_cast<unsigned char>(e.text[p])))
                    ++p;
                if (name && p < e.text.size())
                {
                    // string literal
                    if (e.text[p] == '"')
                    {
                        size_t q = e.text.find('"', p + 1);
                        if (q != std::string::npos)
                            rhs = e.text.substr(p + 1, q - p - 1);
                    }
                    else if (e.text[p] == '\'')
                    {
                        size_t q = e.text.find('\'', p + 1);
                        if (q != std::string::npos)
                            rhs = e.text.substr(p + 1, q - p - 1);
                    }
                    else
                    {
                        // number or bool token: consume until whitespace/comma
                        size_t q = p;
                        while (q < e.text.size() && !std::isspace(static_cast<unsigned char>(e.text[q])) &&
                               e.text[q] != ',')
                            ++q;
                        if (q > p)
                            rhs = e.text.substr(p, q - p);
                    }
                }
                keep = !rhs.empty() && live.count(rhs) > 0;
            }
        }
        kept.push_back({e, keep});
    }

    std::vector<TraceEvent> survivors;
    survivors.reserve(kept.size());
    for (auto it = kept.rbegin(); it != kept.rend(); ++it)
    {
        if (it->second)
            survivors.push_back(it->first);
        else
            ++out.elided;
    }
    out.retained = survivors.size();
    out.sliced = survivors.size() < events.size() && !survivors.empty();
    events.swap(survivors);
    return out;
}

SliceResult slice_to_printing_frames(TraceData& trace)
{
    SliceResult out;
    std::vector<TraceEvent>& events = trace.events;
    if (events.empty())
        return out;

    // locate printing call sites and their deepest inclusive frame
    uint32_t min_terminal_depth = ~0u;
    for (const TraceEvent& e : events)
    {
        if (!event_calls_print(e))
            continue;
        ++out.terminals;
        min_terminal_depth = std::min(min_terminal_depth, e.call_depth);
    }
    if (out.terminals == 0)
        return out; // nothing observable through stdout: keep everything

    // the regions of interest span from the frame directly below the
    // shallowest printer to the bottom of the trace
    uint32_t D = min_terminal_depth > 0 ? min_terminal_depth - 1 : 0;
    if (D == 0)
        return out; // a printer runs at or below depth 1: no machinery to cut

    out.floor_depth = D;
    std::vector<TraceEvent> kept;
    kept.reserve(events.size());
    for (const TraceEvent& e : events)
    {
        if (e.call_depth >= D)
            kept.push_back(e);
        else
            ++out.elided;
    }
    out.retained = kept.size();
    out.sliced = true;
    events.swap(kept);
    return out;
}

} // namespace lure::reconstruct
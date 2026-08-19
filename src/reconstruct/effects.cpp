// reconstruct/effects.cpp
// See effects.hpp.

#include "reconstruct/effects.hpp"

#include <cstdio>
#include <string>

namespace lure::reconstruct {
namespace {

// A value as it appears in a signature. Anything without a stable identity
// across two runs (a table, a closure, an unresolved value) collapses to its
// kind: the comparison is about what the script did, not about the addresses it
// was handed.
std::string signature_value(const lure::LuaValueSnapshot& s)
{
    switch (s.type)
    {
    case lure::ValueType::Nil:
        return "nil";
    case lure::ValueType::Bool:
        return s.text.empty() ? "bool" : s.text;
    case lure::ValueType::Number:
        return s.text.empty() ? lure::lua_number_text(s.nvalue) : s.text;
    case lure::ValueType::String:
    {
        // Bounded and escaped, so a long or binary payload cannot make the
        // signature unwieldy or ambiguous.
        std::string out = "\"";
        size_t n = 0;
        for (char ch : s.text)
        {
            if (n++ >= 96)
            {
                out += "...";
                break;
            }
            unsigned char u = static_cast<unsigned char>(ch);
            if (u < 0x20 || u >= 0x7f || ch == '"' || ch == '\\')
            {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\%03u", unsigned(u));
                out += buf;
            }
            else
                out.push_back(ch);
        }
        return out + "\"";
    }
    case lure::ValueType::Table:
        return "<table>";
    case lure::ValueType::Function:
        return "<function>";
    case lure::ValueType::Native:
        return "<native>";
    default:
        return "<unknown>";
    }
}

// TRUE iff the callee is a native the *host* supplied rather than one the
// standard library whitelist claimed. `register_natives` records every stdlib
// function it finds by name; a native left without one is, by construction,
// something the environment installed -- a service method, an exploit API, a
// stub. Calling it is observable behaviour; calling `string.rep` is not.
bool callee_is_host_boundary(const lure::CallInfo& ci)
{
    return ci.fn.type == lure::ValueType::Native && ci.native_name.empty();
}

bool is_call(const lure::TraceEvent& ev)
{
    return ev.tag == "CALL" || ev.tag == "CALLFB";
}

} // namespace

bool event_is_observable_effect(const TraceEvent& ev)
{
    if (ev.printed_output)
        return true;
    if (ev.tag == "SETGLOBAL")
        return true;
    if (is_call(ev) && ev.call_info && callee_is_host_boundary(*ev.call_info))
        return true;
    return false;
}

std::vector<std::string> effect_signature(const TraceData& trace)
{
    std::vector<std::string> out;
    for (const TraceEvent& ev : trace.events)
    {
        if (!event_is_observable_effect(ev))
            continue;
        std::string s;
        if (ev.printed_output)
            s = "out";
        else if (ev.tag == "SETGLOBAL")
        {
            out.push_back("global " + ev.k_text);
            continue;
        }
        else
            s = "host " + ev.call_info->fn.text;
        s += "(";
        if (ev.call_info)
            for (size_t i = 0; i < ev.call_info->args.size(); ++i)
            {
                // A print's trailing nils are the VM's padding, not arguments.
                if (ev.printed_output && ev.call_info->args[i].type == lure::ValueType::Nil)
                    break;
                if (i)
                    s += ", ";
                s += signature_value(ev.call_info->args[i]);
            }
        s += ")";
        out.push_back(std::move(s));
    }
    return out;
}

} // namespace lure::reconstruct

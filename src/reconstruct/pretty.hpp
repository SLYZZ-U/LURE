#pragma once
// reconstruct/pretty.hpp
// Layer 3 (reconstruct): rendering of the structured tree as text. The output
// is Luau-flavored Lua: every declaration of missing information surfaces as
// a "-- not found:" comment, and those comments are also recorded with their
// output line numbers so a report (see notfound_log.hpp) can be written.

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "reconstruct/structural.hpp"

namespace lure::reconstruct {

struct NotfoundEntry
{
    uint32_t lua_line = 0;   // 1-based line of the generated "-- not found:" comment
    std::string where;       // enclosing construct, e.g. "for-loop at line 3"
    std::string reason;
};

struct PrettyResult
{
    std::string lua;
    std::vector<NotfoundEntry> notfound;
};

// Renders the structured tree. Never throws.
Resolved<PrettyResult> pretty_print(const StNodePtr& root);

} // namespace lure::reconstruct
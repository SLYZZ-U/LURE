#pragma once
// resilience/notfound.hpp
// The standard unresolved-marker used at every pipeline layer. The emitted
// text must follow exactly the format of section 0 of the LURE spec:
//     -- not found: <reason>
#include <string>
#include <string_view>
#include <vector>

namespace lure::resilience {

struct Notfound
{
    std::string reason;
};

inline std::string format_notfound(const Notfound& nf)
{
    return "-- not found: " + nf.reason;
}

inline Notfound nf(std::string r)
{
    return Notfound{std::move(r)};
}

// Collector used by the CLI to enumerate every unresolved point at the end of
// a run, for the <script>.notfound.log report.
struct NotfoundLog
{
    struct Entry
    {
        int line = 0; // output line where the annotation was emitted
        std::string reason;
    };

    std::vector<Entry> entries;

    void add(int line, std::string reason) { entries.push_back({line, std::move(reason)}); }
    bool empty() const { return entries.empty(); }
};

} // namespace lure::resilience
#pragma once
// reconstruct/notfound_log.hpp
// Layer 3 (reconstruct): report of every not-found datum. Written as a sidecar
// file next to the reconstructed script so that consumers can audit which
// values in the output are inferred rather than observed. Layer 4's
// feasibility verdicts (concolic solver) are appended as a separate section.

#include <string>
#include <vector>

#include "concolic/concolic.hpp"
#include "reconstruct/pretty.hpp"

namespace lure::reconstruct {

// Writes the report to `path`; returns false (with `err` set) on failure.
bool write_notfound_log(const std::string& path, const std::vector<NotfoundEntry>& entries, std::string& err);

// Appends the layer-4 feasibility section (or replaces it when the entries
// list is empty, producing a positive note instead). Returns false on failure.
bool append_feasibility_log(const std::string& path, const std::vector<lure::concolic::Feasibility>& feas,
    std::string& err);

} // namespace lure::reconstruct
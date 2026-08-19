// vm/instrumentation.hpp (internal)
// C++ accessors used by the VM runners to control the trace hook and drain
// recorded events. Implementation lives in instrumentation.cpp (Layer 1).
#pragma once

#include "trace/trace_events.hpp"

#include <vector>

namespace lure::vm::instrumentation {

void clear_events();
std::vector<TraceEvent> drain_events();
bool truncated();
const char* opcode_name(unsigned op);

} // namespace lure::vm::instrumentation
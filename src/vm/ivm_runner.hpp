#pragma once
// vm/ivm_runner.hpp
// Interface of layer 1 VMs. Both the mock VM (tests/CI, always available) and
// the instrumented Luau VM (third_party/luau, optional) produce the same
// TraceData consumed by layers 2-4.

#include <map>
#include <memory>
#include <optional>
#include <string>

#include "trace/trace_events.hpp"

namespace lure::vm {

// Names one dispatch of one conditional jump: the (hit_index+1)-th time the
// instruction at code offset `pc` is reached inside the call frame whose serial
// is `frame_id`. Used to re-run a script with a single observed branch decided
// the other way, so the un-taken side becomes observable instead of guessed.
struct BranchFlip
{
    uint32_t frame_id = 0;
    uint32_t pc = 0;
    uint32_t hit_index = 0;
};

struct RunRequest
{
    std::string source;              // Lua script text
    std::string mode = "fast";       // "fast" | "full" (concolic)
    // concrete overrides applied to the initial environment (concolic seeds)
    std::map<std::string, double> initial_values;
    unsigned max_events = 200000;
    // install minimal Roblox environment stubs (game, workspace, script,
    // require, ...) so Roblox module init does not abort on missing globals
    bool roblox_env = false;
    // when set, invert exactly this branch decision during the run
    std::optional<BranchFlip> flip;
};

struct RunResult
{
    TraceData trace;
    std::string stdout_text; // captured stdout ("print" output)
    bool ok = true;          // false if the interpreter loop itself failed
    std::string error;       // interpreter-level error message when !ok
    std::string vm_kind;
    // TRUE iff RunRequest::flip was set and actually reached its target. A probe
    // that never fired proves nothing about the un-taken side.
    bool flip_fired = false;
};

class IVMRunner
{
public:
    virtual ~IVMRunner() = default;

    virtual RunResult run(const RunRequest& req) = 0;
    virtual std::string kind() const = 0;
    // TRUE iff the backend accepts concolic initial_value overrides.
    virtual bool accepts_overrides() const = 0;
};

std::unique_ptr<IVMRunner> make_mock_runner();
std::unique_ptr<IVMRunner> make_luau_runner(); // null when LURE_HAS_LUAU==0

} // namespace lure::vm
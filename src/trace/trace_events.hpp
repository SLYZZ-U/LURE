#pragma once
// trace/trace_events.hpp
// The TraceEvent structures captured by layer 1 (instrumented VM) and consumed
// by layers 2-4. This is the universal event record for the pipeline; it is
// mirrored by schemas/trace.fbs for the on-disk trace log.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace lure {

enum class ValueType : uint8_t
{
    Nil = 0,
    Bool,
    Number,
    String,
    Table,
    Function,
    Native,
    Unknown
};

enum class ResolutionStatus : uint8_t
{
    Resolved = 0,
    Unresolved = 1
};

struct LuaValueSnapshot
{
    ValueType type = ValueType::Unknown;
    std::string text;         // stringified observed value
    double nvalue = 0.0;      // numeric payload when type == Number
    std::string unres_reason; // precise reason when type == Unknown
};

struct CallInfo
{
    LuaValueSnapshot fn;
    std::vector<LuaValueSnapshot> args;
    uint32_t nresults = 0;
    std::string native_name; // whitelisted stdlib name when the callee is a known native
};

struct TableOpInfo
{
    LuaValueSnapshot table;
    LuaValueSnapshot key;
    LuaValueSnapshot value;
    bool is_set = false;
};

struct TraceEvent
{
    uint64_t pc = 0;        // offset of the executed instruction in its function
    // Stable per-run id of the function (Luau proto) the instruction belongs to,
    // numbered in first-execution order; 0 for backends with a single code body.
    // A pc is only unique *within* a proto, so anything that identifies an
    // instruction across a whole trace must key on the pair (see lift/cfg.hpp).
    uint32_t proto_id = 0;
    uint8_t opcode = 0;     // raw opcode byte
    uint32_t insn = 0;      // raw fused instruction word (A/B/C operand fields)
    uint32_t frame_id = 0;  // serial of the executing call frame (per call site)
    uint32_t line = 0;      // best-effort source line
    uint32_t call_depth = 0;
    std::string tag;        // mnemonic: "LOADK", "CALL", "BRANCH", "ARITH", ...
    std::string text;       // textual sketch of the statement/expression executed
    // Lua literal of the instruction's *constant* operand, when it has one that
    // is not already recoverable from the fields above: the K operand of the
    // arithmetic-with-constant opcodes, the name of a global read/write, the
    // method name of a NAMECALL, the dotted path of a GETIMPORT. Empty
    // otherwise. Reconstruction needs the operand itself, not its rendering.
    std::string k_text;
    std::vector<LuaValueSnapshot> stack;
    std::vector<LuaValueSnapshot> locals;
    std::optional<CallInfo> call_info;
    std::optional<TableOpInfo> table_op;
    bool is_branch = false;
    std::string cond_dsl;   // concolic DSL of the condition ("" if none)
    std::string cond_text;  // printable condition expression
    bool branch_taken = false;
    // Register holding the right-hand operand of a two-operand conditional
    // (JUMPIFEQ / JUMPIFNOTEQ / JUMPIFLE / ...), or -1. The left operand is
    // always the instruction's A field; the right one lives in the aux word,
    // which is not otherwise recoverable from `insn` alone. Needed to render a
    // condition in terms of reconstructed expressions rather than the two
    // observed values.
    int32_t cond_rhs_reg = -1;
    uint32_t jump_target = 0;  // pc offset the branch landed on (branch events only)
    int32_t other_target = -1; // pc offset of the unexplored side, or -1 if unknown
    ResolutionStatus status = ResolutionStatus::Resolved;
    std::string notfound_reason;
    // TRUE iff this call event wrote to the observable output stream (e.g. the
    // host's print sink) during execution. Marked behaviorally by the runtime,
    // never by callee name, so output sites survive slicing and drive the host
    // frame / fold-target detection regardless of which function prints.
    bool printed_output = false;
};

struct TraceData
{
    std::string source_script;
    std::string mode;    // "fast" | "full"
    std::string vm_kind; // "mock" | "luau-instrumented"
    std::vector<TraceEvent> events;
};

// Serialization helpers
LuaValueSnapshot value_from_number(double v);
LuaValueSnapshot value_from_string(std::string s);
std::string lua_number_text(double v); // Lua-style tostring for numbers

} // namespace lure
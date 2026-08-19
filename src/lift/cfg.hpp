#pragma once
// lift/cfg.hpp
// Layer 2 (lift): the control-flow graph recovered from a layer-1 trace.
//
// Every event carries a static pc (the plan index for the mock VM, the bytecode
// pc for the instrumented Luau VM), so the pipeline here is backend-agnostic:
// nodes are pcs, edges are the executed successor relation plus the declared
// jump targets of branch events. Nothing is guessed: an edge is only added when
// it was either executed or explicitly reported as a branch target.
//
// A pc is only unique inside its own function, so node identity is the pair
// (proto_id, pc) packed into one 64-bit key by node_key(). Every field named
// `pc` below, and every successor/target/entry/exit, is such a key; the raw
// bytecode offset and the function it belongs to are kept alongside for display.
// A backend with a single code body reports proto_id 0, which makes the key
// equal to the pc and the packing invisible.

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "resilience/resolved.hpp"
#include "trace/trace_events.hpp"

namespace lure::lift {

// Packs a function id and an in-function pc into one node identity.
inline uint64_t node_key(uint32_t proto_id, uint64_t pc)
{
    return (uint64_t(proto_id) << 32) | (pc & 0xffffffffull);
}
inline uint32_t key_proto(uint64_t key)
{
    return uint32_t(key >> 32);
}
inline uint64_t key_pc(uint64_t key)
{
    return key & 0xffffffffull;
}
// Human-readable form of a node key, for messages and not-found reasons.
std::string key_text(uint64_t key);

// One recovered control-flow node. The fields below are the *observed*
// attributes of the pc in the trace (first execution dominates).
struct Node
{
    uint64_t pc = 0;        // node identity: node_key(proto_id, raw_pc)
    uint64_t raw_pc = 0;    // bytecode offset inside its own function
    uint32_t proto_id = 0;  // function the instruction belongs to
    bool is_branch = false;
    std::string tag;
    std::string text;
    std::string cond_dsl;
    std::string cond_text;
    bool branch_taken = false;
    bool other_target_known = false; // the not-taken side was reported by the VM
    uint64_t jump_target = 0;        // executed side
    int64_t other_target = -1;       // unexplored side (may never be executed)
    bool is_advance = false;         // for-loop increment+test slot (mock backend)
    bool is_jump = false;            // unconditional jump (loop back-edge, if exit)
    bool declared = false;           // synthetic node: a branch target that was
                                     // declared but never executed (annotation only)
    bool unresolved = false;
    std::string notfound_reason;
    uint32_t line = 0;
    uint32_t call_depth = 0;

    std::vector<uint64_t> succs; // deduplicated successor keys, ascending by discovery
    size_t first_event = 0;      // index of the first event with this pc
};

struct Cfg
{
    std::vector<Node> nodes;                 // stable order: key discovery order
    std::map<uint64_t, size_t> pc_to_index;  // node key -> index into nodes
    uint64_t entry = 0;                      // pc of the first executed instruction
    std::vector<uint64_t> exits;             // pcs with no executed successor
    std::vector<std::pair<uint64_t, uint64_t>> back_edges; // (src, dst) natural-loop back edges
    std::vector<std::pair<uint64_t, uint64_t>> lifted_succs; // (pc, pc) executed transitions
    uint64_t max_pc = 0;
    bool truncated = false;                  // true when the trace hit the step limit
    std::string vm_kind;
    std::string source_script;
    std::string mode;
};

// Builds the CFG from a layer-1 trace. Never throws; failures are reported as
// Resolved::failure with an exact reason.
Resolved<Cfg> build_cfg(const TraceData& trace);

// Returns a copy of the CFG restricted to *executed* transitions: every
// successor edge that exists only as a declared branch target is dropped.
// Dominance/loop analysis must run on this subgraph, because declared-only
// edges can render an otherwise reducible flow graph irreducible and hide the
// natural loops a linear trace really executed.
Cfg executed_graph(const Cfg& cfg);

// Basic predicates on a CFG.
bool is_back_edge(const Cfg& cfg, uint64_t src, uint64_t dst);

} // namespace lure::lift
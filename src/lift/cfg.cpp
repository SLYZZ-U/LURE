// lift/cfg.cpp
#include "lift/cfg.hpp"

#include <algorithm>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace lure::lift {

std::string key_text(uint64_t key)
{
    std::string s = "pc " + std::to_string(key_pc(key));
    if (key_proto(key) != 0)
        s += " (fn " + std::to_string(key_proto(key)) + ")";
    return s;
}

bool is_back_edge(const Cfg& cfg, uint64_t src, uint64_t dst)
{
    return std::find(cfg.back_edges.begin(), cfg.back_edges.end(), std::make_pair(src, dst)) != cfg.back_edges.end();
}

// ---------------------------------------------------------------------------
// trace -> CFG
// ---------------------------------------------------------------------------

Resolved<Cfg> build_cfg(const TraceData& trace)
{
    Cfg cfg;
    cfg.vm_kind = trace.vm_kind;
    cfg.source_script = trace.source_script;
    cfg.mode = trace.mode;

    // Pass 1: shape the node table from the executed (proto, pc) pairs, in
    // discovery order. Keying on the pc alone would merge instructions of
    // different functions that happen to share an offset -- which every
    // multi-function trace contains.
    for (size_t i = 0; i < trace.events.size(); ++i)
    {
        const TraceEvent& e = trace.events[i];
        if (e.tag == "STEPLIMIT" || e.tag == "TRUNCATED")
        {
            cfg.truncated = true;
            continue;
        }
        const uint64_t key = node_key(e.proto_id, e.pc);
        auto it = cfg.pc_to_index.find(key);
        if (it == cfg.pc_to_index.end())
        {
            Node n;
            n.pc = key;
            n.raw_pc = e.pc;
            n.proto_id = e.proto_id;
            n.first_event = i;
            n.is_branch = e.is_branch;
            n.tag = e.tag;
            n.text = e.text;
            n.cond_dsl = e.cond_dsl;
            n.cond_text = e.cond_text;
            n.branch_taken = e.branch_taken;
            n.jump_target = node_key(e.proto_id, e.jump_target);
            n.other_target =
                e.other_target >= 0 ? int64_t(node_key(e.proto_id, uint64_t(e.other_target))) : -1;
            n.other_target_known = e.is_branch && e.other_target >= 0;
            n.is_advance = (e.tag == "ADVANCE");
            n.is_jump = (e.tag == "JUMP" || e.tag == "JUMPBACK" || e.tag == "JUMPX");
            n.unresolved = (e.status == ResolutionStatus::Unresolved);
            n.notfound_reason = e.notfound_reason;
            n.line = e.line;
            n.call_depth = e.call_depth;
            cfg.pc_to_index.emplace(key, cfg.nodes.size());
            cfg.nodes.push_back(std::move(n));
        }
        else
        {
            // Attribute merge: a pc executed more than once may gain the
            // attributes of later executions (e.g. the other side of a branch
            // inside a loop becomes known on a later iteration).
            Node& n = cfg.nodes[it->second];
            if (e.is_branch && !n.is_branch)
            {
                n.is_branch = true;
                n.jump_target = node_key(e.proto_id, e.jump_target);
                n.other_target =
                    e.other_target >= 0 ? int64_t(node_key(e.proto_id, uint64_t(e.other_target))) : -1;
                n.other_target_known = e.other_target >= 0;
                n.branch_taken = e.branch_taken;
            }
            if (e.status == ResolutionStatus::Unresolved && !n.unresolved)
            {
                n.unresolved = true;
                n.notfound_reason = e.notfound_reason;
            }
            if (!e.cond_dsl.empty() && n.cond_dsl.empty())
            {
                n.cond_dsl = e.cond_dsl;
                n.cond_text = e.cond_text;
            }
        }
        cfg.max_pc = std::max<uint64_t>(cfg.max_pc, e.pc);
    }

    if (cfg.nodes.empty())
    {
        if (trace.events.empty())
            return Resolved<Cfg>::failure("trace contains no events (empty run)");
        // only STEPLIMIT/TRUNCATED events present
        return Resolved<Cfg>::failure("trace contains only control events (step limit reached before any instruction)");
    }

    cfg.entry = cfg.nodes.front().pc;

    // Pass 2: edges. Every executed transition produces an edge; every branch
    // event additionally contributes its declared targets (both sides, so the
    // unexplored side is retained for annotation).
    for (size_t i = 0; i + 1 < trace.events.size(); ++i)
    {
        const TraceEvent& a = trace.events[i];
        const TraceEvent& b = trace.events[i + 1];
        if (a.tag == "STEPLIMIT" || a.tag == "TRUNCATED" || b.tag == "STEPLIMIT" || b.tag == "TRUNCATED")
            continue;
        const uint64_t akey = node_key(a.proto_id, a.pc);
        const uint64_t bkey = node_key(b.proto_id, b.pc);
        if (a.is_branch)
        {
            const int64_t other =
                a.other_target >= 0 ? int64_t(node_key(a.proto_id, uint64_t(a.other_target))) : -1;
            if (other >= 0 && !cfg.pc_to_index.count(uint64_t(other)))
            {
                // The unexplored side was declared but its pc never executed;
                // retain it as a synthetic annotation node so the branch keeps
                // both declared targets. executed_graph() drops the edge.
                Node dn;
                dn.pc = uint64_t(other);
                dn.raw_pc = key_pc(uint64_t(other));
                dn.proto_id = key_proto(uint64_t(other));
                dn.declared = true;
                dn.tag = "DECLARED";
                dn.notfound_reason = "declared branch target; never executed";
                cfg.pc_to_index.emplace(dn.pc, cfg.nodes.size());
                cfg.nodes.push_back(std::move(dn));
            }
            auto add_edge = [&](uint64_t from, uint64_t to)
            {
                auto it = cfg.pc_to_index.find(from);
                if (it == cfg.pc_to_index.end())
                    return;
                Node& n = cfg.nodes[it->second];
                if (std::find(n.succs.begin(), n.succs.end(), to) == n.succs.end())
                    n.succs.push_back(to);
            };
            add_edge(akey, bkey);
            if (other >= 0)
            {
                // unexplored side that was reported by the VM
                add_edge(akey, uint64_t(other));
            }
        }
        else
        {
            auto it = cfg.pc_to_index.find(akey);
            if (it == cfg.pc_to_index.end())
                continue;
            Node& n = cfg.nodes[it->second];
            if (std::find(n.succs.begin(), n.succs.end(), bkey) == n.succs.end())
                n.succs.push_back(bkey);
        }
        cfg.lifted_succs.emplace_back(akey, bkey);
    }

    // Exits: executed pcs with no executed successor; the last executed pc is
    // always an exit unless a branch reported a target beyond it.
    {
        std::unordered_set<uint64_t> has_succ;
        for (const Node& n : cfg.nodes)
            has_succ.insert(n.succs.begin(), n.succs.end());
        for (const Node& n : cfg.nodes)
            if (!has_succ.count(n.pc))
                cfg.exits.push_back(n.pc);
    }

    return Resolved<Cfg>::success(std::move(cfg));
}

Cfg executed_graph(const Cfg& cfg)
{
    Cfg exec = cfg;
    std::set<std::pair<uint64_t, uint64_t>> executed;
    for (const auto& [a, b] : cfg.lifted_succs)
        executed.emplace(a, b);
    for (Node& n : exec.nodes)
    {
        std::vector<uint64_t> kept;
        for (uint64_t s : n.succs)
            if (executed.count(std::make_pair(n.pc, s)))
                kept.push_back(s);
        n.succs = std::move(kept);
    }
    return exec;
}

} // namespace lure::lift
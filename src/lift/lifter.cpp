// lift/lifter.cpp
#include "lift/lifter.hpp"

#include <algorithm>
#include <set>

namespace lure::lift {

namespace {

// Natural-loop recovery: every back edge (src -> dst) with dst dominating src
// defines a loop; its body is the set of nodes that can reach src without
// passing through dst (standard algorithm, Aho et al. 9.6.6). Operates on the
// executed-edge subgraph so that declared-only edges cannot smuggle nodes
// into a body.
std::set<uint64_t> loop_body(const Cfg& exec, const DominatorInfo& doms, uint64_t dst, uint64_t src)
{
    std::set<uint64_t> body{dst};
    std::vector<uint64_t> work;
    auto touches = [&](uint64_t n)
    {
        for (const Node& nd : exec.nodes)
        {
            if (nd.pc == n)
                continue;
            for (uint64_t s : nd.succs)
                if (s == n)
                    work.push_back(nd.pc);
        }
    };
    touches(src);
    while (!work.empty())
    {
        uint64_t n = work.back();
        work.pop_back();
        if (n == dst)
            continue; // the header itself terminates the body
        if (!body.insert(n).second)
            continue; // already collected
        touches(n);
    }
    // A self-loop (src == dst, e.g. `while true do end`) has an empty body by
    // this definition; record the header alone.
    if (src == dst)
        body.insert(src);
    return body;
}

} // namespace

Resolved<LiftedProgram> lift(const Cfg& cfg, const Cfg& exec, const DominatorInfo& doms)
{
    if (cfg.nodes.empty())
        return Resolved<LiftedProgram>::failure("cannot lift an empty CFG");

    LiftedProgram lp;
    lp.vm_kind = cfg.vm_kind;
    lp.truncated = cfg.truncated;
    lp.exit_pc = cfg.nodes.back().pc;

    // 1. natural-loop membership from the executed-edge subgraph
    std::map<uint64_t, std::set<uint64_t>> loop_of; // header -> body pcs
    for (const Node& n : exec.nodes)
    {
        for (uint64_t s : n.succs)
        {
            if (!dominates(doms, s, n.pc))
                continue; // only genuine back edges (dst dominates src; self-loops qualify)
            lp.back_edges.emplace_back(n.pc, s);
            lp.loop_backs[s].push_back(n.pc);
            loop_of[s] = loop_body(exec, doms, s, n.pc);
        }
    }

    // 2. linear items
    for (const Node& n : cfg.nodes)
    {
        if (n.declared)
            continue; // declared-only target: represents nothing executed; the
                      // branch annotation carries it
        LiftItem it;
        it.pc = n.pc;
        it.tag = n.tag;
        it.text = n.text;
        it.cond_dsl = n.cond_dsl;
        it.cond_text = n.cond_text;
        it.is_branch = n.is_branch;
        it.branch_taken = n.branch_taken;
        it.jump_target = n.jump_target;
        it.other_target_known = n.other_target_known;
        it.other_target = n.other_target;
        it.is_advance = n.is_advance;
        it.is_jump = n.is_jump;
        it.unresolved = n.unresolved;
        it.notfound_reason = n.notfound_reason;
        it.line = n.line;
        it.is_fornprep = (n.tag == "FORNPREP");
        it.is_fornloop = (n.tag == "FORNLOOP");
        for (const auto& [hdr, body] : loop_of)
            if (body.count(n.pc))
                it.loops.insert(hdr);
        lp.pc_to_item[n.pc] = lp.items.size();
        lp.items.push_back(std::move(it));
    }

    // 3. back-edge item marking (is_loop_backedge)
    for (const auto& [hdr, srcs] : lp.loop_backs)
        for (uint64_t s : srcs)
        {
            auto it = lp.pc_to_item.find(s);
            if (it == lp.pc_to_item.end())
                continue;
            LiftItem& li = lp.items[it->second];
            li.is_loop_backedge = true;
            if (std::find(li.backedge_headers.begin(), li.backedge_headers.end(), hdr) ==
                li.backedge_headers.end())
                li.backedge_headers.push_back(hdr);
        }

    // 4. numeric-for pairing.
    //    mock backend: the for head and its synthetic ADVANCE slot declare the
    //    same pair of targets (taken -> body entry, not-taken -> loop exit), so
    //    an advance pairs with the nearest preceding branch declaring the same
    //    targets; nearest-first resolves nested loops correctly.
    //    luau backend: the FORNLOOP increment+test is the back edge into the
    //    FORNPREP slot; pair header (FORNPREP pc) with its loop-back source.
    for (size_t i = 0; i < lp.items.size(); ++i)
    {
        LiftItem& it = lp.items[i];
        if (it.is_advance && it.is_branch)
        {
            // find the nearest preceding branch that declares the same pair of
            // targets (taken/not-taken)
            for (size_t j = i; j-- > 0;)
            {
                LiftItem& h = lp.items[j];
                if (h.is_branch && h.jump_target == it.jump_target && h.other_target == it.other_target)
                {
                    it.is_numeric_for_advance = true;
                    h.is_numeric_for_head = true;
                    lp.numeric_for_pairs.emplace_back(h.pc, it.pc);
                    break;
                }
            }
        }
    }
    for (const auto& [hdr, srcs] : lp.loop_backs)
    {
        auto hit = lp.pc_to_item.find(hdr);
        if (hit == lp.pc_to_item.end())
            continue;
        const LiftItem& h = lp.items[hit->second];
        uint64_t back = 0;
        if (h.is_fornprep)
        {
            // the increment slot is the (single) back-edge source that is a
            // FORNLOOP; prefer the latest executed one
            size_t best = 0;
            for (uint64_t s : srcs)
            {
                auto sit = lp.pc_to_item.find(s);
                if (sit != lp.pc_to_item.end() && lp.items[sit->second].is_fornloop &&
                    sit->second > best)
                {
                    best = sit->second;
                    back = s;
                }
            }
            if (back != 0)
            {
                lp.items[hit->second].is_numeric_for_head = true;
                lp.items[best].is_numeric_for_advance = true;
                lp.numeric_for_pairs.emplace_back(hdr, back);
            }
        }
        else
        {
            // luau layout: the natural-loop header is the first instruction of
            // the body; the FORNPREP slot is the instruction immediately before
            // it (pc-1), with the FORNLOOP back-edge source jumping to the
            // header. Pair the FORNPREP with that FORNLOOP.
            size_t best = 0;
            for (uint64_t s : srcs)
            {
                auto sit = lp.pc_to_item.find(s);
                if (sit == lp.pc_to_item.end() || !lp.items[sit->second].is_fornloop ||
                    lp.items[sit->second].jump_target != hdr || sit->second <= best)
                    continue;
                best = sit->second;
                back = s;
            }
            if (back != 0 && hdr > 0)
            {
                auto fhit = lp.pc_to_item.find(hdr - 1);
                if (fhit != lp.pc_to_item.end() && lp.items[fhit->second].is_fornprep)
                {
                    lp.items[fhit->second].is_numeric_for_head = true;
                    lp.items[best].is_numeric_for_advance = true;
                    lp.numeric_for_pairs.emplace_back(hdr - 1, back);
                }
            }
        }
    }

    return Resolved<LiftedProgram>::success(std::move(lp));
}

} // namespace lure::lift
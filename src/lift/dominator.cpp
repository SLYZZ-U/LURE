// lift/dominator.cpp
#include "lift/dominator.hpp"

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <set>

namespace lure::lift {

bool dominates(const DominatorInfo& di, uint64_t a, uint64_t b)
{
    auto it = di.dominators.find(b);
    if (it == di.dominators.end())
        return false;
    return std::find(it->second.begin(), it->second.end(), a) != it->second.end();
}

namespace {

// Core fixpoint pass. dir = +1 for dominators (forward), -1 for
// post-dominators (reverse). For the reverse pass, "roots" are all exits,
// which act as a virtual single exit.
struct Adjacency
{
    std::vector<uint64_t> roots;          // entry (forward) or exits (reverse)
    std::vector<uint64_t> direct;         // nodes in discovery order
    std::map<uint64_t, std::vector<uint64_t>> preds;
    std::map<uint64_t, std::vector<uint64_t>> succs;
};

Adjacency make_adjacency(const Cfg& cfg, int dir)
{
    Adjacency a;
    a.direct.reserve(cfg.nodes.size());
    for (const Node& n : cfg.nodes)
        a.direct.push_back(n.pc);
    for (const Node& n : cfg.nodes)
        for (uint64_t s : n.succs)
        {
            if (dir > 0)
            {
                a.succs[n.pc].push_back(s);
                a.preds[s].push_back(n.pc);
            }
            else
            {
                a.preds[n.pc].push_back(s);
                a.succs[s].push_back(n.pc);
            }
        }
    a.roots = dir > 0 ? std::vector<uint64_t>{} : cfg.exits;
    if (dir > 0)
        a.roots.push_back(cfg.entry);
    else if (cfg.exits.empty())
    {
        // No executed exit (truncated or genuinely infinite trace): every node
        // post-dominates itself; the analysis degenerates but must not fail.
        a.roots = a.direct;
    }
    return a;
}

bool contains(const std::vector<uint64_t>& v, uint64_t x)
{
    return std::find(v.begin(), v.end(), x) != v.end();
}

Resolved<DominatorInfo> run_analysis(const Cfg& cfg, int dir)
{
    Adjacency adj = make_adjacency(cfg, dir);
    if ((dir > 0 && cfg.nodes.empty()) || (dir < 0 && adj.roots.empty()))
        return Resolved<DominatorInfo>::failure("empty graph: cannot compute dominators");

    // all-nodes universe as the initial approximation
    std::set<uint64_t> universe(adj.direct.begin(), adj.direct.end());

    auto full_set = [&](uint64_t self)
    {
        std::set<uint64_t> s = universe;
        s.insert(self);
        return s;
    };

    std::map<uint64_t, std::set<uint64_t>> dom_sets;
    for (uint64_t n : adj.direct)
        dom_sets[n] = full_set(n);
    for (uint64_t r : adj.roots)
        dom_sets[r] = {r};

    // dataflow fixpoint: Dom(n) = {n} U (intersect Dom(p) for p in preds(n))
    bool changed = true;
    while (changed)
    {
        changed = false;
        for (uint64_t n : adj.direct)
        {
            if (contains(adj.roots, n))
                continue;
            auto pit = adj.preds.find(n);
            std::set<uint64_t> cur;
            if (pit == adj.preds.end() || pit->second.empty())
                continue; // unreachable from the root: no dominator
            bool first = true;
            for (uint64_t p : pit->second)
            {
                auto dit = dom_sets.find(p);
                if (dit == dom_sets.end())
                    continue;
                if (first)
                {
                    cur = dit->second;
                    first = false;
                }
                else
                {
                    std::set<uint64_t> inter;
                    std::set_intersection(cur.begin(), cur.end(), dit->second.begin(), dit->second.end(),
                        std::inserter(inter, inter.begin()));
                    cur = std::move(inter);
                }
            }
            if (first)
                continue; // all predecessors unresolved (should not happen)
            cur.insert(n);
            if (cur != dom_sets[n])
            {
                dom_sets[n] = std::move(cur);
                changed = true;
            }
        }
    }

    DominatorInfo di;
    di.order = adj.direct;
    for (uint64_t n : adj.direct)
    {
        const std::set<uint64_t>& s = dom_sets[n];
        di.dominators[n].assign(s.begin(), s.end());
    }

    // immediate dominator: among the strict dominators of n, the one with the
    // largest dominator set. Dominator sets are nested along the domination
    // lattice (they form a tree), so the largest set belongs to the deepest —
    // i.e. closest — dominator.
    for (uint64_t n : adj.direct)
    {
        uint64_t idom = n;
        size_t best = 0;
        bool have = false;
        for (uint64_t d : di.dominators[n])
        {
            if (d == n)
                continue;
            size_t sz = di.dominators[d].size();
            if (!have || sz > best)
            {
                idom = d;
                best = sz;
                have = true;
            }
        }
        di.idom[n] = have ? idom : n;
    }

    return Resolved<DominatorInfo>::success(std::move(di));
}

} // namespace

Resolved<DominatorInfo> compute_dominators(const Cfg& cfg)
{
    return run_analysis(cfg, +1);
}

Resolved<DominatorInfo> compute_postdominators(const Cfg& cfg)
{
    return run_analysis(cfg, -1);
}

} // namespace lure::lift
// reconstruct/structural.cpp
#include "reconstruct/structural.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <set>
#include <sstream>
#include <string>

#include "lift/cfg.hpp"
#include "lift/dominator.hpp"
#include "lift/lifter.hpp"

namespace lure::reconstruct {

namespace {

constexpr size_t kNpos = static_cast<size_t>(-1);

struct Engine
{
    const lift::LiftedProgram& lp;
    const lift::Cfg& exec;           // executed-edge subgraph (used for postdom join targets)
    const lift::DominatorInfo& pdom; // post-dominators computed over the executed graph

    Engine(const lift::LiftedProgram& lp_, const lift::Cfg& exec_, const lift::DominatorInfo& pdom_)
        : lp(lp_), exec(exec_), pdom(pdom_)
    {
        for (const auto& [h, a] : lp.numeric_for_pairs)
            advance_head_of[a] = h;
    }

    size_t pos = 0;                  // current item index
    std::set<uint64_t> structured;   // pcs already emitted as a control construct

    // headers of the loop constructs whose bodies are currently being
    // structured; a back-edge item only terminates a region when it belongs to
    // one of these (an early back-edge occurrence that predates its own
    // construct must not truncate the enclosing region)
    std::vector<uint64_t> active;

    std::map<uint64_t, uint64_t> advance_head_of; // advance pc -> owning head pc

    const lift::LiftItem& cur() const { return lp.items[pos]; }

    bool loop_break(const lift::LiftItem& it) const
    {
        if (it.is_loop_backedge)
            for (uint64_t h : it.backedge_headers)
                if (std::find(active.begin(), active.end(), h) != active.end())
                    return true;
        if (it.is_numeric_for_advance)
        {
            auto f = advance_head_of.find(it.pc);
            if (f != advance_head_of.end() &&
                std::find(active.begin(), active.end(), f->second) != active.end())
                return true;
        }
        return false;
    }

    size_t idx_of(uint64_t pc) const
    {
        auto it = lp.pc_to_item.find(pc);
        return it == lp.pc_to_item.end() ? kNpos : it->second;
    }

    // Immediate post-dominator of a pc in the executed path, if it exists and
    // is a different node (i.e. there is a real join point).
    bool join_of(uint64_t pc, uint64_t& join) const
    {
        auto it = pdom.idom.find(pc);
        if (it == pdom.idom.end() || it->second == pc)
            return false;
        join = it->second;
        size_t j = idx_of(join);
        return j != kNpos && j > pos;
    }

    // ------------------------------------------------------------------
    // statement readers
    // ------------------------------------------------------------------

    StNodePtr plain(const lift::LiftItem& it)
    {
        auto n = std::make_unique<StNode>();
        n->k = StNode::K::Plain;
        n->pc = it.pc;
        n->tag = it.tag;
        n->text = it.text;
        n->line = it.line;
        n->unresolved = it.unresolved;
        n->reason = it.notfound_reason;
        return n;
    }

    StNodePtr notfound(std::string annotation)
    {
        auto n = std::make_unique<StNode>();
        n->k = StNode::K::Notfound;
        n->annotation = std::move(annotation);
        return n;
    }

    // Reads statements until an item whose pc is in `terms` or the stream
    // ends. Terminating items are left unconsumed (the caller consumes them).
    // With stop_at_jump, an unconditional jump (if-else skip glue) also ends
    // the region; used when the declared join of a single-sided if never
    // executed and therefore has no item of its own.
    StNodePtr region(const std::set<uint64_t>& terms, bool stop_at_jump = false)
    {
        auto seq = std::make_unique<StNode>();
        seq->k = StNode::K::Seq;

        while (pos < lp.items.size())
        {
            const lift::LiftItem& it = cur();

            if (it.unresolved)
            {
                seq->children.push_back(notfound(lift::key_text(it.pc) +
                    ": unresolved instruction" + (it.notfound_reason.empty() ? "" : " (" + it.notfound_reason + ")")));
                ++pos;
                continue;
            }
            if (terms.count(it.pc))
                break;
            if (loop_break(it))
                break; // terminator of an enclosing loop: its owning construct consumes it
            if (stop_at_jump && it.is_jump)
                break;
            if (it.is_jump)
            {
                // unconditional control glue (if-else skip, loop back edge);
                // it carries no statement to render
                ++pos;
                continue;
            }
            if (it.is_fornloop)
            {
                // re-executed increment slot outside its loop region (cannot
                // happen in a well-formed trace; keep it visible)
                seq->children.push_back(plain(it));
                ++pos;
                continue;
            }
            if (structured.count(it.pc))
            {
                // the construct owning this pc was already recovered; the
                // re-execution is an observation of the same site
                StNodePtr p = plain(it);
                seq->children.push_back(std::move(p));
                ++pos;
                continue;
            }

            // pair lookup for numeric-for heads
            uint64_t pair_adv = 0;
            for (const auto& [h, a] : lp.numeric_for_pairs)
                if (h == it.pc)
                    pair_adv = a;

            if (it.is_numeric_for_head || it.is_fornprep)
            {
                structured.insert(it.pc);
                ++pos; // the construct handles its own head slot
                size_t adv_idx = pair_adv ? idx_of(pair_adv) : kNpos;
                seq->children.push_back(numeric_for(it, pair_adv, adv_idx));
                continue;
            }
            if (it.is_branch && lp.loop_backs.count(it.pc))
            {
                structured.insert(it.pc);
                ++pos;
                seq->children.push_back(while_loop(it));
                continue;
            }
            if (it.is_branch)
            {
                structured.insert(it.pc);
                ++pos;
                seq->children.push_back(if_then(it));
                continue;
            }
            // ordinary executed statement
            seq->children.push_back(plain(it));
            ++pos;
        }
        return seq;
    }

    StNodePtr numeric_for(const lift::LiftItem& head, uint64_t adv_pc, size_t adv_idx)
    {
        auto n = std::make_unique<StNode>();
        n->k = StNode::K::NumericFor;

        // condition DSL: "<var><=<limit>" (mock: literal limit; luau: register
        // name). The lower bound is not recorded by either backend.
        std::string dsl = head.cond_dsl;
        size_t op = dsl.find("<=");
        bool descending = false;
        if (op == std::string::npos)
        {
            if ((op = dsl.find(">=")) != std::string::npos) // luau descending for
                descending = true;
        }
        std::string init_var, init_lo, init_hi, init_step;
        bool init_parsed = false;
        const std::string kInitPrefix = "-- for init ";
        if (head.text.rfind(kInitPrefix, 0) == 0)
        {
            // "-- for init t = 1, 7, 1" -> "t = 1" | " 7" | " 1"
            std::string rest = head.text.substr(kInitPrefix.size());
            std::string segs[3];
            size_t nseg = 0;
            size_t p = 0;
            while (nseg < 3)
            {
                size_t c = rest.find(',', p);
                segs[nseg++] = trim(c == std::string::npos ? rest.substr(p) : rest.substr(p, c - p));
                if (c == std::string::npos)
                    break;
                p = c + 1;
            }
            std::string first = segs[0];
            size_t eq = first.find('=');
            if (eq != std::string::npos)
            {
                init_var = trim(first.substr(0, eq));
                init_lo = trim(first.substr(eq + 1));
                init_hi = nseg > 1 ? segs[1] : "";
                init_step = nseg > 2 ? segs[2] : "";
                init_parsed = !init_var.empty() && !init_lo.empty();
            }
        }
        if (op != std::string::npos)
        {
            n->loop_var = trim(dsl.substr(0, op));
            std::string rhs = trim(dsl.substr(op + 2));
            n->hi_text = descending ? (rhs.empty() ? "?" : rhs) : (rhs.empty() ? "?" : rhs);
            n->lo_text = "?";
            if (descending)
                n->step_text = "-1"; // direction only; magnitude not recorded
        }
        else
        {
            n->loop_var = head.is_numeric_for_head ? head.cond_text : "?";
            n->hi_text = "?";
            n->lo_text = "?";
        }
        // the FORNPREP slot renders the observed initial and limit values
        // ("-- for init t = 1, 7"); prefer them over the DSL when present.
        if (init_parsed)
        {
            n->loop_var = init_var;
            if (n->lo_text == "?" && !init_lo.empty() && init_lo != "?")
                n->lo_text = init_lo;
            if (n->hi_text == "?" && !init_hi.empty() && init_hi != "?")
                n->hi_text = init_hi;
            if (!init_step.empty() && init_step != "?")
                n->step_text = init_step;
        }

        if (adv_idx == kNpos || adv_idx <= pos)
        {
            // no paired increment slot observed: the loop never iterated
            n->lo_note = "numeric-for head executed without a recorded increment slot; bounds unavailable";
            return n;
        }

        if (n->lo_text == "?")
            n->lo_note = "numeric-for lower bound (initial value of " + n->loop_var +
                         ") was not recorded by the backend; shown as ?";

        // body region ends at the increment slot
        std::set<uint64_t> terms{adv_pc};
        active.push_back(head.pc);
        n->body = region(terms);
        active.pop_back();
        // consume the increment slot
        if (pos < lp.items.size() && cur().pc == adv_pc)
            ++pos;

        if (!descending && head.is_numeric_for_head && n->step_text.empty())
            n->step_note = "step not recorded (implicit default 1 assumed)";
        return n;
    }

    StNodePtr while_loop(const lift::LiftItem& head)
    {
        auto n = std::make_unique<StNode>();
        n->k = StNode::K::While;
        n->cond = head.cond_text.empty() ? head.cond_dsl : head.cond_text;
        if (n->cond.empty())
            n->cond = "true"; // loop formed without a decidable condition

        // the back edge that closes this loop
        size_t back_idx = kNpos;
        for (uint64_t s : lp.loop_backs.at(head.pc))
        {
            size_t j = idx_of(s);
            if (j != kNpos && j > pos && (back_idx == kNpos || j > back_idx))
                back_idx = j;
        }
        if (back_idx == kNpos)
        {
            n->body = region(std::set<uint64_t>{});
            return n;
        }
        std::set<uint64_t> terms{lp.items[back_idx].pc};
        active.push_back(head.pc);
        n->body = region(terms);
        active.pop_back();
        if (pos < lp.items.size() && cur().pc == lp.items[back_idx].pc)
            ++pos;
        return n;
    }

    StNodePtr if_then(const lift::LiftItem& it)
    {
        auto n = std::make_unique<StNode>();
        n->k = StNode::K::If;
        n->cond = it.cond_text.empty() ? it.cond_dsl : it.cond_text;
        if (n->cond.empty())
            n->cond = "true";

        uint64_t join = 0;
        if (join_of(it.pc, join))
            n->then_b = region(std::set<uint64_t>{join});
        else if (it.other_target_known && it.other_target >= 0)
        {
            // single-sided execution: no true merge point in the executed
            // graph. The VM declared the other side's target. When that pc
            // executed (it is a real fall-through join), region to it;
            // otherwise it is the never-executed else side, whose entrance
            // sits behind the then-block's glue jump (stopped by the jump).
            join = uint64_t(it.other_target);
            size_t j = idx_of(join);
            if (j != kNpos && j > pos)
                n->then_b = region(std::set<uint64_t>{join});
            else
                n->then_b = region(std::set<uint64_t>{}, /*stop_at_jump=*/true);
        }
        else
            n->then_b = region(std::set<uint64_t>{});

        // unexecuted side: preserve the declared target as an annotation, but
        // only when that side truly never executed (a fall-through that was
        // taken does not get a not-found claim)
        bool other_executed = false;
        if (it.other_target >= 0)
            for (const lift::Node& n : exec.nodes)
                if (n.pc == it.pc)
                {
                    if (std::find(n.succs.begin(), n.succs.end(), uint64_t(it.other_target)) != n.succs.end())
                        other_executed = true;
                    break;
                }
        if (other_executed)
        {
            // both sides executed somewhere in the trace: the fall-through is a
            // real statement sequence, not an annotation; the then-region set
            // above remains correct (the join was resolved over the executed
            // graph, which contains the executed other-side edge)
            n->else_b = nullptr;
            return n;
        }
        std::string reason;
        if (it.other_target_known)
            reason = "branch's other side (declared " + lift::key_text(uint64_t(it.other_target)) +
                     ") was never executed in the recorded trace";
        else
            reason = "branch's other side was not executed; its target was never declared";
        n->else_b = notfound(reason);
        return n;
    }

    static std::string trim(std::string s)
    {
        size_t a = s.find_first_not_of(" \t");
        size_t b = s.find_last_not_of(" \t");
        if (a == std::string::npos)
            return "";
        return s.substr(a, b - a + 1);
    }
};

} // namespace

Resolved<StNodePtr> structure(const lift::LiftedProgram& lp, const lift::Cfg& exec, const lift::DominatorInfo& pdom)
{
    if (lp.items.empty())
        return Resolved<StNodePtr>::failure("cannot structure an empty program");

    Engine eng{lp, exec, pdom};
    return Resolved<StNodePtr>::success(eng.region(std::set<uint64_t>{}));
}

} // namespace lure::reconstruct
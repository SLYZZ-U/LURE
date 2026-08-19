// tests/catch2/test_pipeline.cpp
// End-to-end pipeline tests: mock VM -> CFG -> lift -> structure -> pretty,
// plus the concolic feasibility layer. These lock the honest-reconstruction
// contract: nothing in the output may claim more than the trace observed.

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>

#include "concolic/concolic.hpp"
#include "concolic/solver.hpp"
#include "lift/cfg.hpp"
#include "lift/dominator.hpp"
#include "lift/lifter.hpp"
#include "reconstruct/constfold.hpp"
#include "reconstruct/notfound_log.hpp"
#include "reconstruct/payload_decomp.hpp"
#include "reconstruct/pretty.hpp"
#include "reconstruct/structural.hpp"
#include "reconstruct/trace_slice.hpp"
#include "trace/trace_events.hpp"
#include "vm/ivm_runner.hpp"

namespace {

lure::TraceData run_mock(const std::string& src, unsigned max_events = 200000)
{
    auto runner = lure::vm::make_mock_runner();
    REQUIRE(runner);
    lure::vm::RunRequest req;
    req.source = src;
    req.max_events = max_events;
    lure::vm::RunResult rr = runner->run(req);
    REQUIRE(rr.ok);
    REQUIRE_FALSE(rr.trace.events.empty());
    return rr.trace;
}

// mock emission: <a><b> for binary conditions was observed in the meanwhile;
// compare without any whitespace so formatting differences do not break tests
std::string compact(const std::string& s)
{
    std::string out;
    for (char c : s)
        if (!std::isspace(static_cast<unsigned char>(c)))
            out += c;
    return out;
}

struct Reconstructed
{
    lure::lift::DominatorInfo doms;
    lure::lift::DominatorInfo pdom;
    lure::lift::LiftedProgram lp;
    lure::reconstruct::StNodePtr tree;
    lure::reconstruct::PrettyResult pretty;
};

Reconstructed reconstruct(const std::string& src)
{
    lure::TraceData trace = run_mock(src);
    lure::Resolved<lure::lift::Cfg> cr = lure::lift::build_cfg(trace);
    REQUIRE(cr.ok);
    lure::lift::Cfg exec = lure::lift::executed_graph(cr.value);
    lure::Resolved<lure::lift::DominatorInfo> dr = lure::lift::compute_dominators(exec);
    lure::Resolved<lure::lift::DominatorInfo> pr = lure::lift::compute_postdominators(exec);
    REQUIRE(dr.ok);
    REQUIRE(pr.ok);
    lure::Resolved<lure::lift::LiftedProgram> lr = lure::lift::lift(cr.value, exec, dr.value);
    REQUIRE(lr.ok);
    lure::Resolved<lure::reconstruct::StNodePtr> tr = lure::reconstruct::structure(lr.value, exec, pr.value);
    REQUIRE(tr.ok);
    lure::Resolved<lure::reconstruct::PrettyResult> pw = lure::reconstruct::pretty_print(tr.value);
    REQUIRE(pw.ok);
    return Reconstructed{dr.value, pr.value, std::move(lr.value), std::move(tr.value),
        std::move(pw.value)};
}

} // namespace

TEST_CASE("mock backend records a trace", "[pip][vm]")
{
    lure::TraceData tr = run_mock("print(1 + 2)");
    CHECK(tr.vm_kind == "mock");
    // statement-level granularity: the top-level call is at least one event
    CHECK(!tr.events.empty());
    bool saw_call = false;
    for (const auto& e : tr.events)
        if (e.tag == "CALL")
        {
            saw_call = true;
            CHECK(e.call_info.has_value());
        }
    CHECK(saw_call);
}

TEST_CASE("cfg preserves declared-but-unexecuted branch sides", "[pip][cfg]")
{
    // x=1 makes the if TAKEN; the then side executes, the other side (the pc
    // after the statement-less if) exists only as a declared target
    lure::TraceData tr = run_mock("local x = 1\nif x > 0 then x = 2 end");
    lure::Resolved<lure::lift::Cfg> cr = lure::lift::build_cfg(tr);
    REQUIRE(cr.ok);

    const lure::lift::Cfg& cfg = cr.value;
    const lure::lift::Node* branch = nullptr;
    for (const lure::lift::Node& n : cfg.nodes)
        if (n.is_branch)
            branch = &n;
    REQUIRE(branch != nullptr);
    CHECK(branch->succs.size() == 2); // executed (skip) + declared (then)

    lure::lift::Cfg exec = lure::lift::executed_graph(cfg);
    for (const lure::lift::Node& n : exec.nodes)
        if (n.is_branch)
            CHECK(n.succs.size() == 1); // declared-only edge dropped
}

TEST_CASE("numeric-for is paired across mock advance slots", "[pip][lift]")
{
    Reconstructed r = reconstruct("local s = 0\nfor i = 1, 3 do s = s + i end\nprint(s)");
    CHECK(r.lp.loop_backs.size() == 1);
    CHECK(r.lp.numeric_for_pairs.size() == 1);
    for (const auto& [h, a] : r.lp.numeric_for_pairs)
    {
        auto hit = r.lp.pc_to_item.find(h);
        auto ait = r.lp.pc_to_item.find(a);
        REQUIRE(hit != r.lp.pc_to_item.end());
        REQUIRE(ait != r.lp.pc_to_item.end());
        CHECK(r.lp.items[hit->second].is_numeric_for_head);
        CHECK(r.lp.items[ait->second].is_numeric_for_advance);
    }
}

TEST_CASE("structure emits a while loop from re-executed pcs", "[pip][struct]")
{
    Reconstructed r = reconstruct("local i = 0\nwhile i < 3 do i = i + 1 end\nprint(i)");
    std::string lua = r.pretty.lua;
    CHECK(compact(lua).find("whilei<3do") != std::string::npos);
    CHECK(compact(lua).find("i=i+1") != std::string::npos);
}

TEST_CASE("structure emits a numeric for with observed bounds and step", "[pip][struct]")
{
    Reconstructed r = reconstruct("local t = 0\nfor i = 1, 4 do t = t + i end\nprint(t)");
    std::string lua = r.pretty.lua;
    std::string c = compact(lua);
    // lo, hi and step were all observed by the backends
    CHECK(c.find("fori=1,4,1do") != std::string::npos);
    for (const auto& e : r.pretty.notfound)
        CHECK(e.reason.find("lower bound") == std::string::npos);
    for (const auto& e : r.pretty.notfound)
        CHECK(e.reason.find("step") == std::string::npos);
}

TEST_CASE("constant folding substitutes observed values into events", "[pip][fold]")
{
    lure::TraceData tr;
    auto ev = [](uint64_t pc, std::string tag, std::string text) {
        lure::TraceEvent e;
        e.pc = pc;
        e.tag = tag;
        e.text = std::move(text);
        return e;
    };
    tr.events.push_back(ev(0, "VARLOAD", "t = 1"));
    tr.events.push_back(ev(1, "ARITH", "reg_11 = 18 * 262144"));
    tr.events.push_back(ev(2, "SETTABLE", "K = \"HYqZX7q1XMispgA9mMf==\""));
    tr.events.push_back(ev(3, "VCPU", "reg_20 = \"HYqZX7q1XMispgA9mMf==\" .. reg_21 .. \"=\""));
    tr.events.push_back(ev(4, "ARITH", "n = t + 7")); // t is an env constant
    tr.events.push_back(ev(5, "ARITH", "m = reg_20 + t")); // string + number: not foldable
    lure::reconstruct::fold_constants(tr);
    CHECK(tr.events[0].text == "t = 1");
    CHECK(tr.events[1].text == "reg_11 = 4718592");
    CHECK(tr.events[2].text == "K = \"HYqZX7q1XMispgA9mMf==\"");
    CHECK(tr.events[3].text == "reg_20 = \"HYqZX7q1XMispgA9mMf==\" .. reg_21 .. \"=\"");
    CHECK(tr.events[4].text == "n = 8");
    CHECK(tr.events[5].text == "m = reg_20 + 1"); // t folds; the op type-errors
    // a folding failure must invalidate the target name so later events fall back
    tr.events.push_back(ev(6, "ARITH", "p = m + 1"));
    lure::reconstruct::fold_constants(tr);
    CHECK(tr.events[6].text == "p = m + 1");
}

TEST_CASE("frame slice keeps only stdout-reaching frames", "[pip][slice]")
{
    lure::TraceData tr;
    auto ev = [](uint64_t pc, uint32_t depth, std::string tag, std::string text) {
        lure::TraceEvent e;
        e.pc = pc;
        e.call_depth = depth;
        e.tag = std::move(tag);
        e.text = std::move(text);
        return e;
    };
    // deep decoder machinery at depth 1...
    tr.events.push_back(ev(0, 1, "ARITH", "x = 18 * 262144"));
    tr.events.push_back(ev(1, 1, "SETTABLE", "t[1] = \"noise\""));
    // loader at depth 2
    tr.events.push_back(ev(0, 2, "CALL", "reg_0 = reg_0(7)"));
    // payload frames at depth 3
    tr.events.push_back(ev(0, 3, "MOVE", "message = \"Hello!\""));
    lure::TraceEvent p;
    p.pc = 1;
    p.call_depth = 3;
    p.tag = "CALL";
    p.text = "print(\"Hello!\")";
    lure::CallInfo ci;
    lure::LuaValueSnapshot a;
    a.type = lure::ValueType::String;
    a.text = "Hello!";
    ci.args.push_back(a);
    p.call_info = ci;
    p.printed_output = true;
    tr.events.push_back(p);

    lure::reconstruct::SliceResult s = lure::reconstruct::slice_to_printing_frames(tr);
    REQUIRE(s.sliced);
    CHECK(s.floor_depth == 2);
    CHECK(s.retained == 3);
    CHECK(s.elided == 2);
    CHECK(tr.events.size() == 3);

    lure::reconstruct::SliceResult v = lure::reconstruct::slice_by_observed_values(tr);
    REQUIRE(v.sliced);
    CHECK(v.retained >= 2); // the literal def + the print site
    bool saw_def = false;
    bool saw_print = false;
    for (const auto& e : tr.events)
    {
        if (e.text.find("message = \"Hello!\"") != std::string::npos)
            saw_def = true;
        if (e.text.find("print(\"Hello!\")") != std::string::npos)
            saw_print = true;
    }
    CHECK(saw_def);
    CHECK(saw_print);
}

TEST_CASE("value slice drops dead literals and keeps printed ones", "[pip][slice]")
{
    lure::TraceData tr;
    auto ev = [](uint64_t pc, std::string tag, std::string text) {
        lure::TraceEvent e;
        e.pc = pc;
        e.tag = std::move(tag);
        e.text = std::move(text);
        return e;
    };
    tr.events.push_back(ev(0, "LOADK", "secret = \"never printed\""));
    tr.events.push_back(ev(1, "LOADK", "shown = \"printed value\""));
    lure::TraceEvent p;
    p.pc = 2;
    p.tag = "CALL";
    p.text = "print(\"printed value\")";
    lure::CallInfo ci;
    lure::LuaValueSnapshot a;
    a.type = lure::ValueType::String;
    a.text = "printed value";
    ci.args.push_back(a);
    p.call_info = ci;
    p.printed_output = true;
    tr.events.push_back(p);

    lure::reconstruct::SliceResult s = lure::reconstruct::slice_to_printing_frames(tr);
    CHECK_FALSE(s.sliced); // all events at the same depth: no frames to cut

    lure::reconstruct::SliceResult v = lure::reconstruct::slice_by_observed_values(tr);
    REQUIRE(v.sliced);
    CHECK(v.retained == 2);
    for (const auto& e : tr.events)
        CHECK(e.text.find("never printed") == std::string::npos);
}

TEST_CASE("unexecuted branch side becomes a not-found annotation", "[pip][struct]")
{
    // x=0: the then side of the if never executes and survives as an annotation
    Reconstructed r = reconstruct("local x = 0\nif x > 0 then x = 2 end\nprint(x)");
    CHECK(compact(r.pretty.lua).find("--notfound:") != std::string::npos);
    bool found = false;
    for (const auto& e : r.pretty.notfound)
        if (e.reason.find("other side") != std::string::npos)
            found = true;
    CHECK(found);
}

TEST_CASE("not-found report is written and readable", "[pip][report]")
{
    Reconstructed r = reconstruct("local t = 0\nfor i = 1, 4 do t = t + i end\nprint(t)");
    std::string path = "lure_test_report.notfound";
    std::string err;
    REQUIRE(lure::reconstruct::write_notfound_log(path, r.pretty.notfound, err));

    std::vector<lure::concolic::Feasibility> feas;
    auto solver = lure::concolic::create_solver();
    lure::TraceData tr = run_mock("local t = 0\nfor i = 1, 4 do t = t + i end\nprint(t)");
    lure::Resolved<std::vector<lure::concolic::Feasibility>> fr =
        lure::concolic::check_unexecuted_sides(tr, solver.get());
    REQUIRE(fr.ok);
    feas = std::move(fr.value);
    REQUIRE(lure::reconstruct::append_feasibility_log(path, feas, err));

    std::ifstream f(path);
    REQUIRE(f);
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    CHECK(content.find("not-found report") != std::string::npos);
    CHECK(content.find("feasibility") != std::string::npos);
    std::remove(path.c_str());
}

TEST_CASE("concolic feasibility: sat and unsat on the same prefix", "[pip][concolic]")
{
    auto solver = lure::concolic::create_solver();
    if (!solver)
    {
        WARN("no solver backend; skipping feasibility verdict assertions");
        return;
    }

    // observed: i(=1) < 3 was TRUE; the other side (i >= 3) is unsat under
    // the single prefix constraint asserted as observed
    lure::TraceData tr_sat = run_mock("local i = 5\nif i < 3 then i = 1 end");
    {
        lure::Resolved<std::vector<lure::concolic::Feasibility>> r =
            lure::concolic::check_unexecuted_sides(tr_sat, solver.get());
        REQUIRE(r.ok);
        REQUIRE_FALSE(r.value.empty());
        // i<3 observed false (i=5): probing the other side asserts i<3 — sat
        CHECK(r.value.front().result.verdict == lure::concolic::Verdict::Sat);
    }
    {
        lure::TraceData tr_unsat = run_mock("local i = 1\nif i < 3 then i = 2 end");
        lure::Resolved<std::vector<lure::concolic::Feasibility>> r =
            lure::concolic::check_unexecuted_sides(tr_unsat, solver.get());
        REQUIRE(r.ok);
        REQUIRE_FALSE(r.value.empty());
        // i<3 observed true: probing the other side asserts !(i<3) — unsat
        CHECK(r.value.front().result.verdict == lure::concolic::Verdict::Unsat);
    }
}

TEST_CASE("function calls carry call info", "[pip][honesty]")
{
    // the mock script runs two top-level statements; no user function executes
    lure::TraceData tr = run_mock("local a = 1\nlocal b = a + 1\nprint(b)");
    for (const auto& e : tr.events)
        if (e.tag == "CALL")
            CHECK(e.call_info.has_value());
}

TEST_CASE("printing calls are marked behaviorally", "[pip][g1]")
{
    // The runtime (mock) marks the call event that wrote to the output stream;
    // detection is name-free. A direct print is the simplest exercised case.
    lure::TraceData tr = run_mock("print(\"direct\")");
    size_t printing = 0;
    for (const auto& e : tr.events)
        if (e.tag == "CALL" && e.printed_output)
        {
            ++printing;
            CHECK(e.call_info.has_value());
        }
    CHECK(printing == 1);

    lure::reconstruct::SliceResult s = lure::reconstruct::slice_to_printing_frames(tr);
    CHECK(s.terminals == 1);
}

TEST_CASE("non-printing calls are not marked", "[pip][g1]")
{
    // tostring writes nothing to stdout -> not marked, even though it is a
    // whitelisted native the mock resolves by name
    lure::TraceData tr = run_mock("local s = tostring(7)\nprint(s)");
    size_t marked = 0;
    for (const auto& e : tr.events)
        if (e.tag == "CALL" && e.printed_output)
            ++marked;
    CHECK(marked == 1); // only the print call, not tostring
}

namespace {
// Fabricated host/payload frames for decompile_payload unit tests (no VM).
lure::TraceEvent mev(uint32_t frame, uint32_t depth, const std::string& tag,
    const std::string& text, uint32_t word)
{
    lure::TraceEvent e;
    e.frame_id = frame;
    e.call_depth = depth;
    e.tag = tag;
    e.text = text;
    e.insn = word;
    return e;
}

uint32_t word3(uint8_t a, uint8_t b, uint8_t c)
{
    return uint32_t(a) << 8 | uint32_t(b) << 16 | uint32_t(c) << 24;
}

void set_print_info(lure::TraceEvent& e, std::vector<std::string> args)
{
    lure::CallInfo ci;
    ci.native_name = "print";
    ci.fn.text = "print";
    for (auto& a : args)
    {
        lure::LuaValueSnapshot s;
        s.text = std::move(a);
        ci.args.push_back(std::move(s));
    }
    e.call_info = std::move(ci);
    e.printed_output = true;
}
} // namespace

TEST_CASE("payload decomp folds a pure accessor into a literal", "[pip][decomp]")
{
    // host payload frame (id 5, depth 4):
    //   GETUPVAL reg_0 = upval_[0] / LOADN reg_1 = 2  (dead: operands of a fold)
    //   CALL reg_0 = reg_0(2)  -> pure helper frame (id 6) returns consts[2]
    //   MOVE reg_3 = "Hello, World!"                  (reads the fold result)
    //   GETIMPORT reg_2 = print                       (dead: native callee)
    //   CALL print("Hello, World!")                   (terminal)
    lure::TraceData tr;
    tr.vm_kind = "luau-instrumented";
    tr.events.push_back(mev(5, 4, "GETUPVAL", "reg_0 = upval_[0]", word3(0, 0, 0)));
    tr.events.push_back(mev(5, 4, "LOADN", "reg_1 = 2", word3(1, 0, 0)));
    tr.events.push_back(mev(5, 4, "CALL", "reg_0 = reg_0(2)", word3(0, 2, 1)));
    tr.events.push_back(mev(6, 5, "GETUPVAL", "reg_2 = upval_[0]", word3(2, 0, 0)));
    tr.events.push_back(mev(6, 5, "SUBK", "reg_3 = 2", word3(0, 0, 0)));
    tr.events.push_back(mev(6, 5, "GETTABLE", "reg_1 = reg_2[2]", word3(1, 2, 0)));
    tr.events.push_back(mev(6, 5, "RETURN", "return reg_1", word3(0, 0, 0)));
    tr.events.push_back(mev(5, 4, "MOVE", "reg_3 = \"Hello, World!\"", word3(3, 0, 0)));
    tr.events.push_back(mev(5, 4, "GETIMPORT", "reg_2 = print", word3(2, 0, 0)));
    lure::TraceEvent term = mev(5, 4, "CALL", "print(\"Hello, World!\")", word3(2, 2, 1));
    set_print_info(term, {"\"Hello, World!\""});
    tr.events.push_back(std::move(term));

    lure::reconstruct::PayloadDecompResult r = lure::reconstruct::decompile_payload(tr);
    REQUIRE(r.ok);
    CHECK(r.lua == "local v0 = \"Hello, World!\"\nprint(v0)\n");
}

TEST_CASE("payload decomp keeps an impure call with observed args", "[pip][decomp]")
{
    // host: MOVE reg_1 = "x" / CALL reg_0 = string.upper(reg_1) (native, not
    // print: kept as an expression) / MOVE reg_3 = "X" / CALL print("X")
    lure::TraceData tr;
    tr.vm_kind = "luau-instrumented";
    tr.events.push_back(mev(5, 2, "MOVE", "reg_1 = \"x\"", word3(1, 4, 0)));
    lure::TraceEvent callu = mev(5, 2, "CALL", "reg_0 = reg_0(reg_1)", word3(0, 2, 1));
    {
        lure::CallInfo ci;
        ci.fn.text = "string.upper";
        lure::LuaValueSnapshot s;
        s.text = "\"x\"";
        ci.args.push_back(std::move(s));
        callu.call_info = std::move(ci);
    }
    tr.events.push_back(std::move(callu));
    tr.events.push_back(mev(5, 2, "MOVE", "reg_3 = \"X\"", word3(3, 0, 0)));
    lure::TraceEvent term = mev(5, 2, "CALL", "print(\"X\")", word3(2, 2, 1));
    set_print_info(term, {"\"X\""});
    tr.events.push_back(std::move(term));

    lure::reconstruct::PayloadDecompResult r = lure::reconstruct::decompile_payload(tr);
    REQUIRE(r.ok);
    CHECK(r.lua == "local v0 = string.upper(\"x\")\nlocal v1 = \"X\"\nprint(v1)\n");
}

TEST_CASE("payload decomp refuses a live loop counter", "[pip][decomp]")
{
    // the print argument aliases a loop counter register -> bail out
    lure::TraceData tr;
    tr.vm_kind = "luau-instrumented";
    tr.events.push_back(mev(5, 2, "FORNPREP", "-- for init", word3(2, 0, 0)));
    tr.events.push_back(mev(5, 2, "MOVE", "reg_2 = \"Hello\"", word3(2, 0, 0)));
    lure::TraceEvent term = mev(5, 2, "CALL", "print(\"Hello\")", word3(2, 2, 1));
    set_print_info(term, {"\"Hello\""});
    tr.events.push_back(std::move(term));

    lure::reconstruct::PayloadDecompResult r = lure::reconstruct::decompile_payload(tr);
    CHECK_FALSE(r.ok);
    CHECK(r.why.find("loop") != std::string::npos);
}

TEST_CASE("payload decomp refuses an unobserved reference", "[pip][decomp]")
{
    // the print argument is an upvalue read whose observed value was never
    // captured by a MOVE -> the reference cannot be reproduced
    lure::TraceData tr;
    tr.vm_kind = "luau-instrumented";
    tr.events.push_back(mev(5, 2, "GETUPVAL", "reg_2 = upval_[0]", word3(2, 0, 0)));
    lure::TraceEvent term = mev(5, 2, "CALL", "print(reg_2)", word3(1, 2, 1));
    set_print_info(term, {"reg_2"});
    tr.events.push_back(std::move(term));

    lure::reconstruct::PayloadDecompResult r = lure::reconstruct::decompile_payload(tr);
    CHECK_FALSE(r.ok);
    CHECK(r.why.find("reference") != std::string::npos);
}

TEST_CASE("payload decomp folds an observed concat argument", "[pip][decomp]")
{
    // mirror of a real VM event stream: the concat's rendered form contains
    // unobserved operand slots ("..."), but the terminal observed the full
    // literal, so the def folds to it and reproduces stdout 1:1
    lure::TraceData tr;
    tr.vm_kind = "luau-instrumented";
    tr.events.push_back(mev(9, 2, "GETIMPORT", "reg_2 = print", word3(2, 0, 0)));
    tr.events.push_back(mev(9, 2, "MOVE", "reg_4 = \"info\"", word3(4, 0, 0)));
    tr.events.push_back(mev(9, 2, "MOVE", "reg_6 = \"all systems nominal\"", word3(6, 0, 0)));
    tr.events.push_back(mev(9, 2, "CONCAT", "reg_3 = \"info\" .. ... .. \"all systems nominal\"",
        uint32_t(3) << 8 | uint32_t(0) << 16 | uint32_t(6) << 24));
    lure::TraceEvent term = mev(9, 2, "CALL", "print(\"info: all systems nominal\")",
        uint32_t(2) << 8 | uint32_t(2) << 16 | uint32_t(1) << 24);
    set_print_info(term, {"\"info: all systems nominal\""});
    tr.events.push_back(std::move(term));

    lure::reconstruct::PayloadDecompResult r = lure::reconstruct::decompile_payload(tr);
    REQUIRE(r.ok);
    CHECK(r.lua == "local v0 = \"info: all systems nominal\"\nprint(v0)\n");
}

TEST_CASE("payload decomp quotes raw string terminal observations", "[pip][decomp]")
{
    // the instrumented VM snapshots string args raw (no quotes); the folded
    // def must re-quote them into a valid Lua literal
    lure::TraceData tr;
    tr.vm_kind = "luau-instrumented";
    tr.events.push_back(mev(9, 2, "GETIMPORT", "reg_2 = print", word3(2, 0, 0)));
    tr.events.push_back(mev(9, 2, "LOADK", "reg_3 = 7", word3(3, 0, 0)));
    tr.events.push_back(mev(9, 2, "ARITH", "reg_4 = reg_3 + 5", word3(4, 3, 0)));
    lure::TraceEvent term = mev(9, 2, "CALL", "print(\"12\")", word3(2, 2, 1));
    lure::CallInfo ci;
    ci.native_name = "print";
    lure::LuaValueSnapshot s;
    s.type = lure::ValueType::String;
    s.text = "12";
    ci.args.push_back(std::move(s));
    term.call_info = std::move(ci);
    term.printed_output = true;
    tr.events.push_back(std::move(term));

    lure::reconstruct::PayloadDecompResult r = lure::reconstruct::decompile_payload(tr);
    REQUIRE(r.ok);
    CHECK(r.lua == "local v0 = \"12\"\nprint(v0)\n");
}

TEST_CASE("payload decomp requires a single printing frame", "[pip][decomp]")
{
    lure::TraceData tr;
    tr.vm_kind = "luau-instrumented";
    lure::TraceEvent t1 = mev(5, 2, "CALL", "print(\"a\")", word3(0, 2, 1));
    set_print_info(t1, {"\"a\""});
    lure::TraceEvent t2 = mev(7, 4, "CALL", "print(\"b\")", word3(0, 2, 1));
    set_print_info(t2, {"\"b\""});
    tr.events.push_back(std::move(t1));
    tr.events.push_back(std::move(t2));

    lure::reconstruct::PayloadDecompResult r = lure::reconstruct::decompile_payload(tr);
    CHECK_FALSE(r.ok);
    CHECK(r.why.find("multiple frames") != std::string::npos);
}

// ---------------------------------------------------------------------------
// symbolic reconstruction + branch recovery by forced re-execution
// ---------------------------------------------------------------------------

namespace {

lure::LuaValueSnapshot snap(lure::ValueType t, const std::string& text)
{
    lure::LuaValueSnapshot s;
    s.type = t;
    s.text = text;
    return s;
}

void set_table_op(lure::TraceEvent& e, const lure::LuaValueSnapshot& key,
    const lure::LuaValueSnapshot& value, bool is_set)
{
    lure::TableOpInfo t;
    t.table = snap(lure::ValueType::Table, "table: 0x1");
    t.key = key;
    t.value = value;
    t.is_set = is_set;
    e.table_op = std::move(t);
}

lure::TraceEvent at_pc(lure::TraceEvent e, uint64_t pc)
{
    e.pc = pc;
    return e;
}

// One printing frame holding the shape every sample reduces to: a table literal,
// a field read printed, then a field tested by a conditional whose taken side
// prints. Distinct pcs, so each is dispatched exactly once.
lure::TraceData one_frame_with_branch()
{
    lure::TraceData tr;
    tr.vm_kind = "luau-instrumented";

    lure::TraceEvent set1 = mev(5, 2, "SETTABLE", "reg_0[\"string\"] = \"hi\"", word3(2, 0, 1));
    set_table_op(set1, snap(lure::ValueType::String, "string"),
        snap(lure::ValueType::String, "hi"), true);
    lure::TraceEvent set2 = mev(5, 2, "SETTABLE", "reg_0[\"bool\"] = true", word3(2, 0, 1));
    set_table_op(set2, snap(lure::ValueType::String, "bool"),
        snap(lure::ValueType::Bool, "true"), true);
    lure::TraceEvent get1 = mev(5, 2, "GETTABLE", "reg_2 = reg_0[\"string\"]", word3(2, 0, 1));
    set_table_op(get1, snap(lure::ValueType::String, "string"), lure::LuaValueSnapshot{}, false);
    lure::TraceEvent p1 = mev(5, 2, "CALL", "print(\"hi\")", word3(1, 2, 1));
    set_print_info(p1, {"hi"});
    p1.call_info->args[0].type = lure::ValueType::String;
    lure::TraceEvent get2 = mev(5, 2, "GETTABLE", "reg_1 = reg_0[\"bool\"]", word3(1, 0, 1));
    set_table_op(get2, snap(lure::ValueType::String, "bool"), lure::LuaValueSnapshot{}, false);
    lure::TraceEvent br = mev(5, 2, "JUMPIFNOTEQ", "", word3(1, 0, 0));
    br.is_branch = true;
    br.branch_taken = false; // fell through, so the guarded side is the equal one
    br.cond_dsl = "true~=true";
    br.cond_rhs_reg = 2;
    br.other_target = 40;
    lure::TraceEvent p2 = mev(5, 2, "CALL", "print(\"bool is true\")", word3(1, 2, 1));
    set_print_info(p2, {"bool is true"});
    p2.call_info->args[0].type = lure::ValueType::String;

    tr.events.push_back(at_pc(mev(5, 2, "NEWTABLE", "reg_0 = {}", word3(0, 0, 0)), 0));
    tr.events.push_back(at_pc(std::move(set1), 1));
    tr.events.push_back(at_pc(std::move(set2), 2));
    tr.events.push_back(at_pc(std::move(get1), 3));
    tr.events.push_back(at_pc(std::move(p1), 4));
    tr.events.push_back(at_pc(std::move(get2), 5));
    tr.events.push_back(at_pc(mev(5, 2, "LOADB", "reg_2 = true", word3(2, 1, 0)), 6));
    tr.events.push_back(at_pc(std::move(br), 7));
    tr.events.push_back(at_pc(mev(5, 2, "LOADK", "reg_2 = \"bool is true\"", word3(2, 0, 0)), 8));
    tr.events.push_back(at_pc(std::move(p2), 9));
    return tr;
}

} // namespace

TEST_CASE("symbolic pass recovers a table literal and a field read", "[pip][decomp][sym]")
{
    lure::reconstruct::PayloadDecompResult r =
        lure::reconstruct::decompile_payload_symbolic(one_frame_with_branch());
    REQUIRE(r.ok);
    // No probe available: the conditional is left flat rather than guessed at.
    CHECK(r.lua ==
        "local t0 = {string = \"hi\", bool = true}\n"
        "print(t0.string)\n"
        "print(\"bool is true\")\n");
    CHECK(r.probed_branches == 0);
    CHECK(lure::reconstruct::symbolic_statements(one_frame_with_branch()).size() == 2);
}

TEST_CASE("a probe of the un-taken side recovers if/else", "[pip][decomp][sym]")
{
    lure::reconstruct::ProbeRequest seen;
    unsigned calls = 0;
    auto probe = [&](const lure::reconstruct::ProbeRequest& rq) {
        seen = rq;
        ++calls;
        lure::reconstruct::ProbeReply rp;
        rp.usable = true;
        // What the same run reconstructs with that one decision inverted.
        rp.statements = {"print(t0.string)", "print(\"bool is not true\")"};
        return rp;
    };

    lure::reconstruct::PayloadDecompResult r =
        lure::reconstruct::decompile_payload_symbolic(one_frame_with_branch(), probe);
    REQUIRE(r.ok);
    CHECK(calls == 1);
    // The probe names exactly one dispatch of one conditional.
    CHECK(seen.frame_id == 5);
    CHECK(seen.pc == 7);
    CHECK(seen.hit_index == 0);
    // The condition reads in reconstructed terms, in the sense of the side the
    // trace took (a JUMPIFNOTEQ that fell through guards `==`).
    CHECK(r.lua ==
        "local t0 = {string = \"hi\", bool = true}\n"
        "print(t0.string)\n"
        "if t0.bool == true then\n"
        "    print(\"bool is true\")\n"
        "else\n"
        "    print(\"bool is not true\")\n"
        "end\n");
    CHECK(r.probed_branches == 1);
    CHECK(r.probes_run == 1);
}

TEST_CASE("an unusable probe leaves the conditional unstructured", "[pip][decomp][sym]")
{
    auto probe = [](const lure::reconstruct::ProbeRequest&) {
        lure::reconstruct::ProbeReply rp;
        rp.usable = false;
        rp.why = "the run did not complete with that branch inverted";
        return rp;
    };
    lure::reconstruct::PayloadDecompResult r =
        lure::reconstruct::decompile_payload_symbolic(one_frame_with_branch(), probe);
    REQUIRE(r.ok);
    CHECK(r.lua.find("if ") == std::string::npos);
    CHECK(r.probed_branches == 0);
    CHECK(r.why.find("not observable") != std::string::npos);
}

TEST_CASE("a probe that diverges before the branch is rejected", "[pip][decomp][sym]")
{
    auto probe = [](const lure::reconstruct::ProbeRequest&) {
        lure::reconstruct::ProbeReply rp;
        rp.usable = true;
        // Differs from the recorded run *before* the inverted branch, so it says
        // nothing about the extent that branch guards.
        rp.statements = {"print(\"something else\")"};
        return rp;
    };
    lure::reconstruct::PayloadDecompResult r =
        lure::reconstruct::decompile_payload_symbolic(one_frame_with_branch(), probe);
    REQUIRE(r.ok);
    CHECK(r.lua.find("if ") == std::string::npos);
    CHECK(r.why.find("diverged before the branch") != std::string::npos);
}

TEST_CASE("a probe body referencing an undeclared table is refused", "[pip][decomp][sym]")
{
    auto probe = [](const lure::reconstruct::ProbeRequest&) {
        lure::reconstruct::ProbeReply rp;
        rp.usable = true;
        rp.statements = {"print(t0.string)", "print(t9.other)"};
        return rp;
    };
    lure::reconstruct::PayloadDecompResult r =
        lure::reconstruct::decompile_payload_symbolic(one_frame_with_branch(), probe);
    REQUIRE(r.ok);
    CHECK(r.lua.find("t9") == std::string::npos);
    CHECK(r.why.find("never did") != std::string::npos);
}

TEST_CASE("cfg keys nodes on the function, not the pc alone", "[pip][cfg]")
{
    // The same pc executed in two different functions: two nodes, not one.
    lure::TraceData tr;
    tr.vm_kind = "luau-instrumented";
    lure::TraceEvent a = mev(1, 1, "LOADN", "reg_0 = 1", word3(0, 0, 0));
    a.pc = 4;
    a.proto_id = 1;
    lure::TraceEvent b = mev(2, 2, "LOADN", "reg_0 = 2", word3(0, 0, 0));
    b.pc = 4;
    b.proto_id = 2;
    tr.events.push_back(std::move(a));
    tr.events.push_back(std::move(b));

    lure::Resolved<lure::lift::Cfg> cfg = lure::lift::build_cfg(tr);
    REQUIRE(cfg.ok);
    CHECK(cfg.value.nodes.size() == 2);
    CHECK(cfg.value.nodes[0].raw_pc == 4);
    CHECK(cfg.value.nodes[1].raw_pc == 4);
    CHECK(cfg.value.nodes[0].proto_id == 1);
    CHECK(cfg.value.nodes[1].proto_id == 2);
    CHECK(cfg.value.nodes[0].pc != cfg.value.nodes[1].pc);
    CHECK(lure::lift::key_text(cfg.value.nodes[1].pc) == "pc 4 (fn 2)");
    // A single-body backend reports proto 0, leaving the key equal to the pc.
    CHECK(lure::lift::node_key(0, 7) == 7);
}

// ---------------------------------------------------------------------------
// general reconstruction: a statement for every observable effect, not only
// prints; loops folded only when the fold reproduces every observed iteration
// ---------------------------------------------------------------------------

TEST_CASE("general pass emits a call with propagated arguments", "[pip][general]")
{
    lure::TraceData tr;
    tr.vm_kind = "luau-instrumented";
    tr.events.push_back(at_pc(mev(1, 1, "NEWTABLE", "reg_0 = {}", word3(0, 0, 0)), 0));
    tr.events.push_back(at_pc(mev(1, 1, "LOADK", "reg_2 = \"x\"", word3(2, 0, 0)), 1));
    // the call's receiver register holds the rebuilt table, the next the literal
    tr.events.push_back(at_pc(mev(1, 1, "MOVE", "reg_4 = reg_0", word3(4, 0, 0)), 2));
    tr.events.push_back(at_pc(mev(1, 1, "MOVE", "reg_5 = reg_2", word3(5, 2, 0)), 3));
    lure::TraceEvent call = mev(1, 1, "CALL", "table.insert(...)", word3(3, 3, 1));
    lure::CallInfo ci;
    ci.native_name = "table.insert";
    ci.args.push_back(snap(lure::ValueType::Table, "table: 0x1"));
    ci.args.push_back(snap(lure::ValueType::String, "x"));
    call.call_info = std::move(ci);
    tr.events.push_back(at_pc(std::move(call), 4));
    lure::TraceEvent p = mev(1, 1, "CALL", "print(\"done\")", word3(6, 2, 1));
    set_print_info(p, {"done"});
    p.call_info->args[0].type = lure::ValueType::String;
    tr.events.push_back(at_pc(std::move(p), 5));

    lure::reconstruct::PayloadDecompResult r =
        lure::reconstruct::decompile_general(tr, lure::reconstruct::BranchProbe());
    REQUIRE(r.ok);
    // The table is named and passed by name; the literal argument is propagated.
    CHECK(r.lua.find("table.insert(t0, \"x\")") != std::string::npos);
    CHECK(r.lua.find("print(\"done\")") != std::string::npos);
    CHECK(r.expressed_effects >= 2);
}

TEST_CASE("general pass emits a write to a global", "[pip][general]")
{
    lure::TraceData tr;
    tr.vm_kind = "luau-instrumented";
    tr.events.push_back(at_pc(mev(1, 1, "LOADK", "reg_0 = 42", word3(0, 0, 0)), 0));
    lure::TraceEvent sg = mev(1, 1, "SETGLOBAL", "\"RESULT\" = 42", word3(0, 0, 0));
    sg.k_text = "\"RESULT\"";
    tr.events.push_back(at_pc(std::move(sg), 1));

    lure::reconstruct::PayloadDecompResult r =
        lure::reconstruct::decompile_general(tr, lure::reconstruct::BranchProbe());
    REQUIRE(r.ok);
    CHECK(r.lua == "RESULT = 42\n");
}

TEST_CASE("general pass drops a call nothing reads", "[pip][general]")
{
    lure::TraceData tr;
    tr.vm_kind = "luau-instrumented";
    // A native call whose single result is never used and which produced no
    // output: the shape of an obfuscator's decoder helper.
    lure::TraceEvent dead = mev(1, 1, "CALL", "reg_0 = string.rep(...)", word3(0, 1, 2));
    lure::CallInfo ci;
    ci.native_name = "string.rep";
    dead.call_info = std::move(ci);
    tr.events.push_back(at_pc(std::move(dead), 0));
    lure::TraceEvent p = mev(1, 1, "CALL", "print(\"kept\")", word3(2, 2, 1));
    set_print_info(p, {"kept"});
    p.call_info->args[0].type = lure::ValueType::String;
    tr.events.push_back(at_pc(std::move(p), 1));

    lure::reconstruct::PayloadDecompResult r =
        lure::reconstruct::decompile_general(tr, lure::reconstruct::BranchProbe());
    REQUIRE(r.ok);
    CHECK(r.lua == "print(\"kept\")\n");
    CHECK(r.why.find("nothing read") != std::string::npos);
}

namespace {
// Two iterations of `for i = 1, 2 do print(...) end`, as the VM records them.
lure::TraceData numeric_for_trace(const char* first_arg, const char* second_arg)
{
    lure::TraceData tr;
    tr.vm_kind = "luau-instrumented";
    lure::TraceEvent prep = mev(1, 1, "FORNPREP", "-- for init reg_2 = 1, 2, 1", word3(0, 0, 0));
    prep.is_branch = true;
    prep.branch_taken = true;
    prep.jump_target = 3; // one past the FORNLOOP
    tr.events.push_back(at_pc(std::move(prep), 0));
    for (int k = 0; k < 2; ++k)
    {
        lure::TraceEvent p = mev(1, 1, "CALL", "print(...)", word3(4, 2, 1));
        set_print_info(p, {k == 0 ? first_arg : second_arg});
        p.call_info->args[0].type = lure::ValueType::String;
        tr.events.push_back(at_pc(std::move(p), 1));
        lure::TraceEvent loop = mev(1, 1, "FORNLOOP", "-- loop increment/check", word3(0, 0, 0));
        loop.is_branch = true;
        loop.branch_taken = (k == 0); // the second one exits
        loop.jump_target = 1;
        tr.events.push_back(at_pc(std::move(loop), 2));
    }
    return tr;
}
} // namespace

TEST_CASE("general pass folds a numeric for whose iterations match", "[pip][general]")
{
    lure::reconstruct::PayloadDecompResult r = lure::reconstruct::decompile_general(
        numeric_for_trace("x", "x"), lure::reconstruct::BranchProbe());
    REQUIRE(r.ok);
    CHECK(r.lua ==
        "for i0 = 1, 2, 1 do\n"
        "    print(\"x\")\n"
        "end\n");
}

TEST_CASE("general pass leaves a loop unrolled when the iterations differ", "[pip][general]")
{
    lure::reconstruct::PayloadDecompResult r = lure::reconstruct::decompile_general(
        numeric_for_trace("x", "y"), lure::reconstruct::BranchProbe());
    REQUIRE(r.ok);
    // Nothing is claimed about a loop that did not repeat itself: both observed
    // iterations are emitted, and the report says why.
    CHECK(r.lua == "print(\"x\")\nprint(\"y\")\n");
    CHECK(r.why.find("unrolled") != std::string::npos);
}
// cli/main.cpp
// lure: trace -> CFG -> structured Lua + not-found report.
//
//   lure run <script.lua> [--vm mock|luau] [--max-events N] [-o out.lua]
//
// Exit codes: 0 = reconstructed; 1 = usage or I/O error; 2 = interpreter-level
// failure with nothing recorded.

#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_set>

#include <CLI/CLI.hpp>
#include <spdlog/spdlog.h>

#include "concolic/concolic.hpp"
#include "concolic/solver.hpp"
#include "lift/cfg.hpp"
#include "lift/dominator.hpp"
#include "lift/lifter.hpp"
#include "lift/vm_detector.hpp"
#include "reconstruct/constfold.hpp"
#include "reconstruct/effects.hpp"
#include "reconstruct/notfound_log.hpp"
#include "reconstruct/payload_decomp.hpp"
#include "reconstruct/pretty.hpp"
#include "reconstruct/structural.hpp"
#include "reconstruct/trace_slice.hpp"
#include "resilience/notfound.hpp"
#include "resilience/resolved.hpp"
#include "trace/trace_events.hpp"
#include "vm/ivm_runner.hpp"

namespace {

struct Options
{
    std::string script;
    std::string out;
    std::string vm; // "" = auto
    std::string dump_trace; // optional: write the (folded) event list here
    unsigned max_events = 1000000;
    bool roblox_env = false;
};

bool read_file(const std::string& path, std::string& out, std::string& err)
{
    std::ifstream f(path, std::ios::binary);
    if (!f)
    {
        err = "cannot open script: " + path;
        return false;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}

bool write_file(const std::string& path, const std::string& content, std::string& err)
{
    std::ofstream f(path, std::ios::binary);
    if (!f)
    {
        err = "cannot write output: " + path;
        return false;
    }
    f << content;
    return static_cast<bool>(f);
}

int run(const Options& opt)
{
    // -------- input
    std::string src, err;
    if (!read_file(opt.script, src, err))
    {
        spdlog::error(err);
        return 1;
    }

    // -------- layer 1: VM backends
    std::unique_ptr<lure::vm::IVMRunner> runner;
    if (opt.vm == "mock")
    {
        runner = lure::vm::make_mock_runner();
    }
    else if (opt.vm == "luau")
    {
        runner = lure::vm::make_luau_runner();
        if (!runner)
        {
            spdlog::error("--vm luau requested but the instrumented Luau VM was not built");
            return 1;
        }
    }
    else
    {
        runner = lure::vm::make_luau_runner();
        if (!runner)
            runner = lure::vm::make_mock_runner();
    }

    lure::vm::RunRequest req;
    req.source = src;
    req.max_events = opt.max_events;
    req.roblox_env = opt.roblox_env;
    lure::vm::RunResult rr;
    try
    {
        rr = runner->run(req);
    }
    catch (const std::exception& ex)
    {
        spdlog::error("backend failed: {}", ex.what());
        return 2;
    }
    if (!rr.ok && rr.trace.events.empty())
    {
        spdlog::error("interpreter failed with no trace recorded: {}", rr.error);
        return 2;
    }
    if (!rr.ok)
        spdlog::warn("interpreter reported an error but recorded a prefix; reconstructing the prefix: {}",
            rr.error);
    spdlog::info("backend: {}  events: {}  stdout: {}", rr.vm_kind, rr.trace.events.size(),
        rr.stdout_text.empty() ? std::string("(empty)") : rr.stdout_text);

    // Honest framing when the traced run aborted. Everything reconstructed below
    // is the executed prefix of whatever ran before the error; for an obfuscated
    // script that is the loader/decoder machinery, not the payload it never got
    // to run. Without this the output reads like a successful decompilation.
    std::string abort_banner;
    if (!rr.ok)
    {
        abort_banner = "-- lure: THE TRACED RUN ABORTED: " + rr.error + "\n";
        if (rr.stdout_text.empty())
            abort_banner +=
                "-- lure: it produced no observable output, so nothing about the intended payload\n"
                "-- lure: was observed. What follows is only the executed prefix of the code that\n"
                "-- lure: ran before the error -- for an obfuscated script, its own machinery.\n";
    }

    // -------- layer 2.5: constant folding of the observed trace
    lure::reconstruct::fold_constants(rr.trace);

    if (!opt.dump_trace.empty())
    {
        std::ofstream tf(opt.dump_trace, std::ios::trunc);
        if (tf.is_open())
        {
            for (const auto& ev : rr.trace.events)
            {
                tf << "pc " << ev.pc << "  depth " << ev.call_depth << "  op " << static_cast<int>(ev.opcode)
                   << "  line " << ev.line << "  frame " << ev.frame_id
                   << (ev.printed_output ? "  printed" : "")
                   << "  tag " << ev.tag << "  insn " << std::hex << ev.insn << std::dec
                   << "  text: " << ev.text
                   << "  cond: " << ev.cond_dsl << "  taken: " << ev.branch_taken << "\n";
            }
            spdlog::info("trace dumped to {}", opt.dump_trace);
        }
        else
        {
            spdlog::error("cannot open {} for trace dump", opt.dump_trace);
        }
    }

    // -------- layer 2
    lure::Resolved<lure::lift::BackendVerdict> verdict = lure::lift::detect_backend(rr.trace);
    if (verdict.ok)
        spdlog::info("vm verdict: {} ({})", verdict.value.kind, verdict.value.reason);

    // -------- branch probing
    // One trace records nothing at all about the side of a branch it did not
    // take: the un-taken target never appears in it. Rather than guess at the
    // extent of a guarded block, the reconstruction may ask for the script to be
    // re-run with a single branch decision inverted and compare what the two
    // runs reconstruct. That keeps a recovered if/else *observed* on both sides.
    // A reply is used only when the inversion actually fired, the run completed
    // and its trace was not truncated.
    unsigned probe_runs = 0;
    lure::reconstruct::BranchProbe probe;         // for the payload pass
    lure::reconstruct::BranchProbe general_probe; // for the general pass
    std::unique_ptr<lure::vm::IVMRunner> prober;
    if (rr.vm_kind == "luau-instrumented")
        prober = lure::vm::make_luau_runner();
    if (prober)
    {
        // Probing compares two runs, so it is only sound if the script replays
        // identically. One unflipped re-run establishes that; a script that is
        // not reproducible (a decoder reading the clock, an address-dependent
        // value) gets no probing at all rather than a comparison against a
        // different execution.
        lure::vm::RunRequest creq;
        creq.source = src;
        creq.max_events = opt.max_events;
        creq.roblox_env = opt.roblox_env;
        lure::vm::RunResult crr = prober->run(creq);
        lure::reconstruct::fold_constants(crr.trace);
        bool reproducible = crr.ok == rr.ok && crr.stdout_text == rr.stdout_text &&
                            lure::reconstruct::symbolic_statements(crr.trace) ==
                                lure::reconstruct::symbolic_statements(rr.trace);
        if (!reproducible)
            spdlog::warn("branch probing disabled: the script does not replay identically, so a "
                         "probe run could not be compared against the recorded one");
        // A probe reply has to be built by the *same* reconstruction that will
        // consume it, or the two statement lists are not comparable.
        auto make_probe = [&](std::vector<std::string> (*statements)(const lure::TraceData&)) {
            return [&, statements](const lure::reconstruct::ProbeRequest& rq) {
                lure::reconstruct::ProbeReply reply;
                lure::vm::RunRequest preq;
                preq.source = src;
                preq.max_events = opt.max_events;
                preq.roblox_env = opt.roblox_env;
                lure::vm::BranchFlip f;
                f.frame_id = rq.frame_id;
                f.pc = rq.pc;
                f.hit_index = rq.hit_index;
                preq.flip = f;
                lure::vm::RunResult prr = prober->run(preq);
                ++probe_runs;
                if (!prr.flip_fired)
                {
                    reply.why = "the inversion never reached its target (not a two-way "
                                "conditional, or that dispatch was not replayed)";
                    return reply;
                }
                if (!prr.ok)
                {
                    reply.why = "the run did not complete with that branch inverted: " + prr.error;
                    return reply;
                }
                for (const lure::TraceEvent& e : prr.trace.events)
                    if (e.tag == "TRUNCATED")
                    {
                        reply.why = "the probe trace hit --max-events, so its statement list is "
                                    "incomplete";
                        return reply;
                    }
                // Same preprocessing as the recorded trace, so the two statement
                // lists are comparable.
                lure::reconstruct::fold_constants(prr.trace);
                reply.statements = statements(prr.trace);
                reply.usable = true;
                return reply;
            };
        };
        if (reproducible)
        {
            probe = make_probe(&lure::reconstruct::symbolic_statements);
            general_probe = make_probe(&lure::reconstruct::general_statements);
        }
    }

    // -------- layer 2.6: stdout-frame slicing
    // If the output was produced by frames deeper than the loader
    // machinery, retain only those frames: everything else is provably
    // irrelevant to the observed stdout and is elided wholesale.
    lure::reconstruct::SliceResult slice = lure::reconstruct::slice_to_printing_frames(rr.trace);
    if (slice.sliced)
    {
        spdlog::info("slice: retained {} event(s) from depth >= {}, elided {} loader event(s)",
            slice.retained, slice.floor_depth, slice.elided);
    }

    lure::Resolved<lure::lift::Cfg> cfg = lure::lift::build_cfg(rr.trace);
    if (!cfg.ok)
    {
        spdlog::error("CFG recovery failed: {}", cfg.reason);
        return 1;
    }
    lure::lift::Cfg exec = lure::lift::executed_graph(cfg.value);
    lure::Resolved<lure::lift::DominatorInfo> doms = lure::lift::compute_dominators(exec);
    lure::Resolved<lure::lift::DominatorInfo> pdom = lure::lift::compute_postdominators(exec);
    if (!doms.ok || !pdom.ok)
    {
        spdlog::error("dominance analysis failed: {} / {}", doms.reason, pdom.reason);
        return 1;
    }
    lure::Resolved<lure::lift::LiftedProgram> lp = lure::lift::lift(cfg.value, exec, doms.value);
    if (!lp.ok)
    {
        spdlog::error("lifting failed: {}", lp.reason);
        return 1;
    }
    spdlog::info("cfg: {} nodes, {} edges, {} natural loop(s){}", cfg.value.nodes.size(),
        cfg.value.lifted_succs.size(), lp.value.loop_backs.size(),
        lp.value.truncated ? " (trace truncated)" : "");

    // -------- payload reconstruction, shared by the sliced and unsliced paths
    // A candidate is accepted only when re-running it under the instrumented VM
    // reproduces the recorded *behaviour*: the same stdout, and the same ordered
    // sequence of things the script did to the outside world (see
    // reconstruct/effects.hpp). Comparing stdout alone was empty for a script
    // that prints nothing, which is most of the ones this tool targets -- any
    // silent candidate passed. That check is also what validates a recovered
    // conditional: emitting the wrong sense, or the wrong side as the body,
    // changes the behaviour and the candidate is rejected.
    //
    // Several candidates can pass. They are not equally informative: one may
    // reproduce the behaviour while saying nothing about the calls and writes
    // that produced it. So the winner is the one that expresses the most
    // observable effects, then the one that recovered more conditionals, then the
    // one leaving fewest effects unexpressed.
    const std::vector<std::string> recorded_effects = lure::reconstruct::effect_signature(rr.trace);
    spdlog::info("observable effects recorded: {}", recorded_effects.size());
    for (size_t i = 0; i < recorded_effects.size() && i < 12; ++i)
        spdlog::debug("  effect[{}] {}", i, recorded_effects[i]);
    lure::reconstruct::PayloadDecompResult decomp;
    bool payload_verified = false;
    std::unique_ptr<lure::vm::IVMRunner> verifier;
    if (rr.vm_kind == "luau-instrumented")
        verifier = lure::vm::make_luau_runner();
    auto consider = [&](lure::reconstruct::PayloadDecompResult cand, const char* label) {
        if (!cand.ok)
        {
            spdlog::info("candidate {}: nothing reconstructed -- {}", label, cand.why);
            return;
        }
        if (!verifier)
            return;
        lure::vm::RunRequest vreq;
        vreq.source = cand.lua;
        vreq.max_events = opt.max_events;
        vreq.roblox_env = opt.roblox_env;
        lure::vm::RunResult vrr = verifier->run(vreq);
        // LURE_DUMP_CANDIDATES=1 keeps every candidate on disk, verified or not:
        // a candidate that fails the re-run is the one worth reading.
        if (const char* dc = std::getenv("LURE_DUMP_CANDIDATES"))
            if (*dc == '1')
            {
                std::string p = (opt.out.empty() ? opt.script : opt.out) + ".cand." + label + ".lua";
                std::string e2;
                if (write_file(p, cand.lua, e2))
                    spdlog::info("candidate {} written to {}", label, p);
            }
        if (!vrr.ok)
        {
            spdlog::info("candidate {}: did not run ({})", label, vrr.error);
            return;
        }
        if (vrr.stdout_text != rr.stdout_text)
        {
            spdlog::info("candidate {}: different output", label);
            return;
        }
        const std::vector<std::string> got = lure::reconstruct::effect_signature(vrr.trace);
        if (got != recorded_effects)
        {
            spdlog::info("candidate {}: reproduced the output but not the effects ({} vs {})", label,
                got.size(), recorded_effects.size());
            return;
        }
        const bool better = !payload_verified ||
            cand.expressed_effects > decomp.expressed_effects ||
            (cand.expressed_effects == decomp.expressed_effects &&
                cand.probed_branches > decomp.probed_branches) ||
            (cand.expressed_effects == decomp.expressed_effects &&
                cand.probed_branches == decomp.probed_branches &&
                cand.unexpressed_effects < decomp.unexpressed_effects);
        spdlog::info("candidate {}: verified 1:1 ({} effect(s) expressed, {} not, {} conditional(s) "
                     "recovered){}",
            label, cand.expressed_effects, cand.unexpressed_effects, cand.probed_branches,
            better ? ", kept" : ", superseded");
        if (better)
        {
            decomp = std::move(cand);
            payload_verified = true;
        }
    };
    auto try_candidate = [&](lure::reconstruct::PayloadDecompResult cand) -> bool {
        consider(std::move(cand), "payload");
        return payload_verified;
    };

    // Writes a verified payload reconstruction plus its sidecar.
    auto emit_payload = [&](const std::string& banner, const std::string& provenance) -> int {
        std::string out_path = opt.out.empty() ? opt.script + ".dec.lua" : opt.out;
        std::string lua = abort_banner + banner + "\n" + decomp.lua;
        if (!write_file(out_path, lua, err))
        {
            spdlog::error(err);
            return 1;
        }
        spdlog::info("wrote {}", out_path);
        std::string report_path = out_path + ".notfound";
        std::string report_err;
        std::vector<lure::reconstruct::NotfoundEntry> notes;
        lure::reconstruct::NotfoundEntry e;
        e.lua_line = 1;
        e.where = "payload";
        e.reason = decomp.why + "; " + provenance +
                   "; the emitted payload was re-run under the instrumented VM and reproduced the "
                   "recorded stdout byte-for-byte.";
        notes.push_back(std::move(e));
        if (!lure::reconstruct::write_notfound_log(report_path, notes, report_err))
            spdlog::warn(report_err);
        return 0;
    };

    // -------- mode A: payload frames only (sliced)
    if (slice.sliced)
    {
        std::string out_path = opt.out.empty() ? opt.script + ".dec.lua" : opt.out;
        std::string lua;

        // Deepest pass first: register-level reconstruction of the printing
        // frame's payload. Accepted only when re-running the emitted Lua
        // against the instrumented VM reproduces the recorded stdout
        // byte-for-byte; otherwise the pass output is discarded and the
        // coarser observed-value slice below is used.
        if (verifier)
        {
            // The general reconstruction first: it expresses calls, writes and
            // loops, not only prints. The narrower passes follow as fallbacks,
            // and the comparison in `consider` keeps whichever says most.
            consider(lure::reconstruct::decompile_general(rr.trace, general_probe), "general");
            consider(lure::reconstruct::decompile_payload_symbolic(rr.trace, probe), "symbolic");
            consider(lure::reconstruct::decompile_payload(rr.trace), "register-slice");
            if (payload_verified)
                spdlog::info("payload decomp: verified 1:1 against the recorded stdout");
            else
                spdlog::warn("payload decomp did not verify; falling back to value slice");
        }

        if (payload_verified)
        {
            spdlog::info("payload decomp: {}", decomp.why);
            if (probe_runs)
                spdlog::info("branch probing: {} forced re-execution(s), {} conditional(s) recovered",
                    probe_runs, decomp.probed_branches);
            return emit_payload("-- lure: register-level payload reconstruction (verified 1:1)",
                "loader/decoder frames and dead events were elided");
        }

        // Coarse fallback: keep the printing sites and the defs whose literals
        // reached them. Runs after the payload decomp so it never strips the
        // defs that pass needs (the decomp operates on the frame-sliced trace).
        lure::reconstruct::SliceResult vslice = lure::reconstruct::slice_by_observed_values(rr.trace);
        if (vslice.sliced)
        {
            spdlog::info("value slice: retained {} value-def event(s), elided {} dead event(s)",
                vslice.retained, vslice.elided);
        }

        lua += abort_banner;
        lua += "-- lure: payload reconstruction (stdout-producing events)\n";
        if (vslice.sliced)
            lua += "-- " + std::to_string(vslice.retained) + " observed-value event(s); " +
                   std::to_string(slice.retained - vslice.retained + vslice.elided) +
                   " loader/dead event(s) elided\n";
        else
            lua += "-- " + std::to_string(slice.retained) + " event(s) retained; " +
                   std::to_string(slice.elided) + " loader/decoder event(s) elided\n";
        for (const auto& ev : rr.trace.events)
        {
            if (ev.tag == "STEPLIMIT" || ev.tag == "TRUNCATED")
                continue;
            std::string t = ev.text;
            if (t.empty())
                continue;
            if (t.size() >= 2 && t[0] == '-' && t[1] == '-')
                continue; // renderer comments ("-- prologue/varargs", ...)
            lua += t;
            lua += "\n";
        }
        if (!write_file(out_path, lua, err))
        {
            spdlog::error(err);
            return 1;
        }
        spdlog::info("wrote {}", out_path);
        std::string report_path = out_path + ".notfound";
        std::string report_err;
        std::vector<lure::reconstruct::NotfoundEntry> notes;
        lure::reconstruct::NotfoundEntry e;
        e.lua_line = 1;
        e.where = "slice";
        if (vslice.sliced)
            e.reason = std::to_string(vslice.elided) +
                       " dead event(s) were elided after the frame slice; " +
                       std::to_string(slice.elided) +
                       " loader/decoder event(s) in shallow frames were elided; the retained "
                       "events reproduce the observed stdout.";
        else
            e.reason = std::to_string(slice.elided) +
                       " loader/decoder event(s) in frames shallower than depth " +
                       std::to_string(slice.floor_depth) +
                       " were elided; the retained frames reproduce the observed stdout.";
        notes.push_back(std::move(e));
        if (!lure::reconstruct::write_notfound_log(report_path, notes, report_err))
            spdlog::warn(report_err);
        return 0;
    }

    // -------- mode B: no loader to slice away
    // The reconstruction applies just as well to a plain script, and renders far
    // better than the structural pass below (a table literal instead of a
    // NEWTABLE plus loose SETTABLEs, `t.field` instead of a register, a condition
    // in terms of those expressions instead of the two observed values). The
    // general pass folds the loops it can prove equivalent and says so when it
    // cannot; the older payload pass is purely linear, so it is only offered when
    // the printing frame executed every pc at most once and unrolling therefore
    // changes nothing. Same byte-for-byte gate either way.
    if (verifier)
    {
        consider(lure::reconstruct::decompile_general(rr.trace, general_probe), "general");

        uint32_t host = 0;
        bool have_host = false, one_frame = true;
        for (const lure::TraceEvent& ev : rr.trace.events)
        {
            if (!ev.printed_output)
                continue;
            if (!have_host)
            {
                host = ev.frame_id;
                have_host = true;
            }
            else if (ev.frame_id != host)
                one_frame = false;
        }
        bool linear = have_host && one_frame;
        if (linear)
        {
            std::unordered_set<uint64_t> seen;
            for (const lure::TraceEvent& ev : rr.trace.events)
                if (ev.frame_id == host && !seen.insert(ev.pc).second)
                {
                    linear = false; // the frame looped: only the general pass folds those
                    break;
                }
        }
        if (linear)
            consider(lure::reconstruct::decompile_payload_symbolic(rr.trace, probe), "symbolic");

        if (payload_verified)
        {
            spdlog::info("reconstruction: verified 1:1 against the recorded behaviour");
            spdlog::info("reconstruction: {}", decomp.why);
            if (probe_runs)
                spdlog::info("branch probing: {} forced re-execution(s), {} conditional(s) recovered",
                    probe_runs, decomp.probed_branches);
            return emit_payload("-- lure: symbolic reconstruction (verified 1:1)",
                "the frame carrying the run's observable effects, reconstructed statement by "
                "statement");
        }
    }

    // -------- layer 2.7
    lure::Resolved<lure::reconstruct::StNodePtr> tree = lure::reconstruct::structure(lp.value, exec, pdom.value);
    if (!tree.ok)
    {
        spdlog::error("structuring failed: {}", tree.reason);
        return 1;
    }
    lure::Resolved<lure::reconstruct::PrettyResult> pr = lure::reconstruct::pretty_print(tree.value);
    if (!pr.ok)
    {
        spdlog::error("rendering failed: {}", pr.reason);
        return 1;
    }

    std::string out_path = opt.out.empty() ? opt.script + ".dec.lua" : opt.out;
    if (!write_file(out_path, abort_banner + pr.value.lua, err))
    {
        spdlog::error(err);
        return 1;
    }
    spdlog::info("wrote {}", out_path);

    // -------- not-found report (+ layer 4 feasibility)
    std::string report_path = out_path + ".notfound";
    std::string report_err;
    std::vector<lure::reconstruct::NotfoundEntry> report = pr.value.notfound;
    if (!abort_banner.empty())
    {
        // First entry, so the aborted run is the first thing the report states.
        lure::reconstruct::NotfoundEntry e;
        e.lua_line = 1;
        e.where = "run";
        e.reason = "the traced run aborted (" + rr.error + ") after " +
                   std::to_string(rr.trace.events.size()) + " event(s)" +
                   (rr.stdout_text.empty()
                           ? "; it produced no observable output, so the payload it was going to "
                             "run was never observed and nothing here describes it"
                           : "; the output recorded before the error is reproduced by the "
                             "retained events") +
                   ".";
        report.insert(report.begin(), std::move(e));
    }
    if (!lure::reconstruct::write_notfound_log(report_path, report, report_err))
        spdlog::warn(report_err);

    std::unique_ptr<lure::concolic::Solver> solver = lure::concolic::create_solver();
    lure::Resolved<std::vector<lure::concolic::Feasibility>> feas =
        lure::concolic::check_unexecuted_sides(rr.trace, solver.get());
    if (!feas.ok)
    {
        spdlog::warn("feasibility analysis failed: {}", feas.reason);
    }
    else
    {
        if (!lure::reconstruct::append_feasibility_log(report_path, feas.value, report_err))
            spdlog::warn(report_err);
        size_t sat = 0, unsat = 0, unknown = 0;
        for (const auto& f : feas.value)
        {
            if (f.result.verdict == lure::concolic::Verdict::Sat)
                ++sat;
            else if (f.result.verdict == lure::concolic::Verdict::Unsat)
                ++unsat;
            else
                ++unknown;
        }
        spdlog::info("feasibility ({}): {} sat, {} unsat, {} unknown", solver ? solver->name() : "none", sat,
            unsat, unknown);
    }
    if (pr.value.notfound.empty())
        spdlog::info("no not-found values; reconstruction is fully observed");
    else
        spdlog::info("{} not-found value(s) reported in {}", pr.value.notfound.size(), report_path);

    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    // LURE_LOG=trace|debug|info|warn|error controls the default verbosity.
    const char* log_env = std::getenv("LURE_LOG");
    if (log_env && *log_env)
        spdlog::set_level(spdlog::level::from_str(log_env));

    CLI::App app{"lure: single-path decompilation of a Luau trace"};
    Options opt;
    app.add_option("script", opt.script, "Lua/Luau script to trace")->required()->check(CLI::ExistingFile);
    app.add_option("-o,--out", opt.out, "output .lua path (default: <script>.dec.lua)");
    app.add_option("--vm", opt.vm, "backend: mock | luau (default: auto)");
    app.add_option("--max-events", opt.max_events, "max recorded events before truncation");
    app.add_option("--dump-trace", opt.dump_trace,
        "write the folded event list (one per line) to this file for debugging");
    app.add_flag("--roblox", opt.roblox_env,
        "install minimal Roblox environment stubs (game, workspace, script, require, ...)");
    CLI11_PARSE(app, argc, argv);

    try
    {
        return run(opt);
    }
    catch (const std::exception& ex)
    {
        spdlog::error("unhandled exception: {}", ex.what());
        return 1;
    }
}
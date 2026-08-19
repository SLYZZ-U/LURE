// reconstruct/payload_decomp.cpp
// See payload_decomp.hpp for the contract.

#include "reconstruct/payload_decomp.hpp"
#include "reconstruct/symbolic.hpp"
#include "reconstruct/trace_slice.hpp"
#include "trace/trace_events.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace lure::reconstruct {
namespace {

using lure::TraceData;
using lure::TraceEvent;

struct Decoded
{
    uint8_t a = 0;
    uint8_t b = 0;
    uint8_t c = 0;
};

// Luau instruction layout: op 0-7, A 8-15, B 16-23, C 24-31.
Decoded decode(uint32_t w)
{
    Decoded d;
    d.a = uint8_t((w >> 8) & 0xff);
    d.b = uint8_t((w >> 16) & 0xff);
    d.c = uint8_t((w >> 24) & 0xff);
    return d;
}

std::string trim(const std::string& s)
{
    size_t b = 0;
    size_t e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b])))
        ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1])))
        --e;
    return s.substr(b, e - b);
}

bool split_lhs_rhs(const TraceEvent& ev, std::string& lhs, std::string& rhs)
{
    const std::string& text = ev.text;
    size_t eq = text.find('=');
    if (eq == std::string::npos)
        return false;
    lhs = trim(text.substr(0, eq));
    rhs = trim(text.substr(eq + 1));
    return !lhs.empty();
}

bool looks_like_reg(const std::string& s)
{
    if (s.size() <= 4 || s.rfind("reg_", 0) != 0)
        return false;
    for (size_t i = 4; i < s.size(); ++i)
        if (!std::isdigit(static_cast<unsigned char>(s[i])))
            return false;
    return true;
}

bool is_valid_ident(const std::string& s)
{
    if (s.empty())
        return false;
    if (!(std::isalpha(static_cast<unsigned char>(s[0])) || s[0] == '_'))
        return false;
    for (char ch : s)
        if (!(std::isalnum(static_cast<unsigned char>(ch)) || ch == '_'))
            return false;
    return true;
}

// Guards against emitting `local print = ...`-style shadowing or `local true`.
const std::unordered_set<std::string>& reserved_words()
{
    static const std::unordered_set<std::string> s = {
        "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "if", "in",
        "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while",
        "print", "type", "typeof", "tonumber", "tostring"};
    return s;
}

// Quote- and comma-aware CSV-ish split of the argument list of a rendered call.
std::vector<std::string> split_args(const std::string& s)
{
    std::vector<std::string> out;
    std::string cur;
    char quote = 0;
    for (char ch : s)
    {
        if (quote)
        {
            cur.push_back(ch);
            if (ch == quote)
                quote = 0;
            continue;
        }
        if (ch == '"' || ch == '\'')
        {
            quote = ch;
            cur.push_back(ch);
        }
        else if (ch == ',')
        {
            out.push_back(trim(cur));
            cur.clear();
        }
        else
            cur.push_back(ch);
    }
    if (!trim(cur).empty())
        out.push_back(trim(cur));
    return out;
}

bool begins_with(const std::string& s, const char* p)
{
    return s.rfind(p, 0) == 0;
}

// Renders a raw observed string as a Lua string literal (the VM snapshots
// strings raw; the rendered defs and fabricated tests already carry quotes).
std::string quote_lua_string(const std::string& s)
{
    std::string out = "\"";
    for (char ch : s)
    {
        switch (ch)
        {
        case '\\':
            out += "\\\\";
            break;
        case '"':
            out += "\\\"";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (static_cast<unsigned char>(ch) < 0x20 || static_cast<unsigned char>(ch) >= 0x7f)
            {
                // Zero-padded to three digits: `\1` followed by a digit reads as a
                // different character, which is how a decoded binary payload came
                // out as a malformed escape.
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\%03d", int(static_cast<unsigned char>(ch)));
                out += buf;
            }
            else
                out.push_back(ch);
            break;
        }
    }
    out += "\"";
    return out;
}

// ---------------------------------------------------------------------------
// per-frame register state (forward pass)
// ---------------------------------------------------------------------------

enum class RegKind
{
    KNone,
    KConst,  // value is the observed literal (rendered rhs)
    KRef,    // value is a reference text (upval_[0], reg_7[print], "{}")
    KMove,   // def is a MOVE; value was observed at the defining event
    KFold,   // def is a call to a pure accessor frame; results fold to a literal
    KCall    // def is a call that cannot fold; rendered call expression kept
};

struct RegState
{
    RegKind kind = RegKind::KNone;
    std::string value;
    uint8_t src = 0; // MOVE source register
};

// Tags a callee frame may contain and still be a pure accessor (it only reads
// constants/registers and returns a value; no calls, no table or global writes).
// Control-flow ops are pure too: the observed path already produced the
// result being folded, and the folded code never re-executes the frame.
bool frame_is_pure(const TraceData& trace, uint32_t serial)
{
    static const std::unordered_set<std::string> pure = {
        "MOVE", "LOADK", "LOADKX", "LOADN", "LOADB", "LOADNIL", "GETUPVAL", "GETGLOBAL",
        "GETIMPORT", "GETTABLE", "GETTABLEKS", "GETTABLEN", "GETUDATAKS", "GETVARARGS",
        "PREPVARARGS", "NAMECALL", "NAMECALLUDATA", "NEWCLASS",
        "ADD", "SUB", "MUL", "DIV", "MOD", "POW", "IDIV", "ADDK", "SUBK", "MULK", "DIVK",
        "MODK", "POWK", "IDIVK", "SUBRK", "DIVRK", "AND", "OR", "ANDK", "ORK", "CONCAT",
        "NOT", "MINUS", "LENGTH", "NEWTABLE", "DUPTABLE", "NEWCLOSURE", "DUPCLOSURE",
        "RETURN", "JUMP", "JUMPBACK", "JUMPIF", "JUMPIFNOT", "JUMPIFEQ", "JUMPIFLE",
        "JUMPIFLT", "JUMPIFNOTEQ", "JUMPIFNOTLE", "JUMPIFNOTLT", "JUMPX", "JUMPXEQKNIL",
        "JUMPXEQKB", "JUMPXEQKN", "JUMPXEQKS", "CMPPROTO", "NOP", "BREAK", "EXTRAARG"};
    for (const TraceEvent& ev : trace.events)
        if (ev.frame_id == serial && !pure.count(ev.tag))
            return false;
    return true;
}

// Writes a single destination register? Returns the reg, or -1.
int written_register(const std::string& tag, const Decoded& d)
{
    static const std::unordered_set<std::string> single_dst = {
        "MOVE", "LOADNIL", "LOADB", "LOADN", "LOADK", "LOADKX", "GETUPVAL", "GETGLOBAL",
        "GETIMPORT", "GETTABLE", "GETTABLEKS", "GETTABLEN", "GETUDATAKS", "NEWCLOSURE",
        "DUPCLOSURE", "NEWCLASS", "GETVARARGS", "ADD", "SUB", "MUL", "DIV", "MOD", "POW",
        "IDIV", "ADDK", "SUBK", "MULK", "DIVK", "MODK", "POWK", "IDIVK", "SUBRK", "DIVRK",
        "AND", "OR", "ANDK", "ORK", "CONCAT", "NOT", "MINUS", "LENGTH", "NEWTABLE",
        "DUPTABLE", "NAMECALL", "NAMECALLUDATA", "CALL", "CALLFB"};
    if (!single_dst.count(tag))
        return -1;
    return d.a;
}

bool is_arith_or_value(const std::string& tag)
{
    static const std::unordered_set<std::string> s = {
        "ADD", "SUB", "MUL", "DIV", "MOD", "POW", "IDIV", "ADDK", "SUBK", "MULK", "DIVK",
        "MODK", "POWK", "IDIVK", "SUBRK", "DIVRK", "AND", "OR", "ANDK", "ORK", "CONCAT",
        "NOT", "MINUS", "LENGTH", "LOADK", "LOADKX", "LOADN", "LOADB", "LOADNIL"};
    return s.count(tag);
}

struct Terminal
{
    size_t host_pos = 0;
    uint8_t a = 0; // callee register
    uint8_t b = 0; // nargs + 1
};

} // namespace

PayloadDecompResult decompile_payload(const TraceData& trace)
{
    PayloadDecompResult res;

    const std::vector<TraceEvent>& evs = trace.events;
    if (evs.empty())
    {
        res.why = "trace is empty";
        return res;
    }

    // Find the unique printing frame.
    uint32_t host = 0;
    bool have_host = false;
    for (const TraceEvent& ev : evs)
    {
        if (event_calls_print(ev))
        {
            if (!have_host)
            {
                host = ev.frame_id;
                have_host = true;
            }
            else if (ev.frame_id != host)
            {
                res.why = "stdout produced from multiple frames; not single-payload";
                return res;
            }
        }
    }
    if (!have_host)
    {
        res.why = "no printing call sites in the trace";
        return res;
    }

    // Host frame events, in trace order.
    std::vector<size_t> host_pos;
    for (size_t i = 0; i < evs.size(); ++i)
        if (evs[i].frame_id == host)
            host_pos.push_back(i);

    const size_t H = host_pos.size();

    auto fail = [&res](const char* why) {
        res.why = why;
    };

    // ---- forward pass: register defs over the host frame -------------------
    std::vector<RegState> regs(256);

    for (size_t k = 0; k < H; ++k)
    {
        const TraceEvent& ev = evs[host_pos[k]];
        const Decoded d = decode(ev.insn);
        const std::string& tag = ev.tag;

        int w = written_register(tag, d);
        if (w < 0)
            continue;

        uint8_t dst = uint8_t(w);
        RegState& st = regs[dst];

        if (ev.tag == "MOVE")
        {
            std::string lhs, rhs;
            if (!split_lhs_rhs(ev, lhs, rhs))
                continue;
            // The rhs of this move is the observed value of src; a fold-call
            // result or an unobserved reference gets its literal here. The
            // kind is left untouched: the backward pass needs it to know that
            // the fold/ref def is not to be kept as an assignment.
            RegState& sr = regs[d.b];
            if (sr.kind == RegKind::KFold || sr.kind == RegKind::KRef)
                sr.value = rhs;
            st = RegState{};
            st.kind = RegKind::KMove;
            st.src = d.b;
            st.value = rhs;
        }
        else if (ev.tag == "CALL" || ev.tag == "CALLFB")
        {
            st = RegState{};
            // The callee frame starts at the very next dispatch when the
            // callee is a Lua function; a native callee resumes in this frame.
            bool pure = false;
            if (host_pos[k] + 1 < evs.size() && evs[host_pos[k] + 1].frame_id != host)
                pure = frame_is_pure(trace, evs[host_pos[k] + 1].frame_id);
            st.kind = pure ? RegKind::KFold : RegKind::KCall;
            std::string lhs, rhs;
            if (split_lhs_rhs(ev, lhs, rhs))
                st.value = rhs; // rendered call expression
        }
        else if (is_arith_or_value(ev.tag))
        {
            st = RegState{};
            st.kind = RegKind::KConst;
            std::string lhs, rhs;
            if (split_lhs_rhs(ev, lhs, rhs))
                st.value = rhs;
        }
        else
        {
            // Accessor / closure / table creators: value is a reference text,
            // replaced by the observed literal if a later MOVE reads this reg.
            st = RegState{};
            st.kind = RegKind::KRef;
            std::string lhs, rhs;
            if (split_lhs_rhs(ev, lhs, rhs))
                st.value = rhs;
        }
    }

    // ---- backward pass: live slice from the printing sites ----------------
    // "Live" means: some later (already processed) read still needs the kill
    // point of this register. A def satisfies the pending read -- it is kept
    // and the register goes dead again (earlier defs of the same register are
    // not reached). Fold calls satisfy the read with an observed literal and
    // are never kept; impure kept calls re-live only their callee register
    // (arguments are rendered literals inside the call expression).
    std::vector<bool> kept(H, false);
    std::vector<Terminal> terminals;
    std::unordered_set<uint8_t> live;

    // Terminal-argument observations: reg -> the literal the printing call
    // read from that register. A kept pure def (arith/concat/table read) whose
    // register is an observed terminal argument folds to that literal instead
    // of a partially-rendered expression, exactly like a fold-call result.
    // The entry is consumed by the def that killed the liveness it raised, so
    // re-printed registers get per-printing-site observations.
    std::unordered_map<uint8_t, lure::LuaValueSnapshot> obs_override;

    // True iff a snapshot can be re-emitted as a self-contained Lua literal.
    auto fold_override = [](const lure::LuaValueSnapshot& s) -> std::string {
        switch (s.type)
        {
        case lure::ValueType::String:
            return quote_lua_string(s.text);
        case lure::ValueType::Number:
            return s.text.empty() ? lua_number_text(s.nvalue) : s.text;
        case lure::ValueType::Bool:
            return s.text.empty() ? (s.nvalue != 0.0 ? "true" : "false") : s.text;
        case lure::ValueType::Nil:
            return "nil";
        default:
            // untyped snapshots (tests): text may already be a literal
            if (!s.text.empty() && (s.text.front() == '"' || s.text.front() == '\''))
                return s.text;
            return std::string();
        }
    };

    for (int k = int(H) - 1; k >= 0; --k)
    {
        const TraceEvent& ev = evs[host_pos[size_t(k)]];
        const Decoded d = decode(ev.insn);
        const std::string& tag = ev.tag;

        if (event_calls_print(ev))
        {
            if (d.b == 0)
            {
                fail("printing call with unknown argument count (vararg spread)");
                return res;
            }
            kept[size_t(k)] = true;
            terminals.push_back(Terminal{size_t(k), d.a, d.b});
            for (int r = int(d.a) + 1; r < int(d.a) + int(d.b) && r < 256; ++r)
                live.insert(uint8_t(r));
            if (ev.call_info)
                for (size_t i = 0; i < ev.call_info->args.size() && int(i) < int(d.b) - 1; ++i)
                    obs_override[uint8_t(int(d.a) + 1 + int(i))] = ev.call_info->args[i];
            continue;
        }

        // Tables written on the live path and loops on the live path cannot be
        // reconstructed linearly; bail out to the observed-value slice.
        if (tag == "SETTABLE" || tag == "SETTABLEKS" || tag == "SETTABLEN")
        {
            if (live.count(d.a))
            {
                res.why = "table `" + (ev.text.empty() ? tag : ev.text) + "` is live (set on path)";
                return res;
            }
            continue;
        }
        if (tag == "FORNPREP" || tag == "FORNLOOP" || tag == "FORGLOOP" ||
            tag == "FORGPREP" || tag == "FORGPREP_INEXT" || tag == "FORGPREP_NEXT")
        {
            for (int r = int(d.a); r <= int(d.a) + 2 && r < 256; ++r)
                if (live.count(uint8_t(r)))
                {
                    fail("loop counter is live in the payload chain");
                    return res;
                }
            continue;
        }
        if (ev.is_branch || begins_with(tag, "JUMPIF") || begins_with(tag, "JUMPXEQ"))
        {
            if (live.count(d.a))
            {
                fail("conditional in the live chain is not supported");
                return res;
            }
            continue;
        }

        int w = written_register(tag, d);
        if (w < 0)
            continue;
        uint8_t dst = uint8_t(w);
        if (!live.count(dst))
            continue;

        const RegState& st = regs[dst];
        if (st.kind == RegKind::KFold)
        {
            // The accessor call's result is the observed literal: the pending
            // read is satisfied here, nothing is kept, no operand re-lives.
            live.erase(dst);
            continue;
        }

        kept[size_t(k)] = true;
        live.erase(dst);
        if (st.kind == RegKind::KMove)
        {
            live.insert(st.src);
        }
        else if (st.kind == RegKind::KCall)
        {
            // Reproduce the callee (the register coincides with the call's
            // result register, LOP_CALL A); its earlier def will keep.
            live.insert(dst);
        }
        else if (st.kind == RegKind::KConst || st.kind == RegKind::KRef)
        {
            // A pure def whose register is an observed terminal argument folds
            // to that literal; otherwise KConst/KRef keep their rendered value
            // (already a literal, or a reference resolved by a later MOVE).
            auto oit = obs_override.find(dst);
            if (oit != obs_override.end())
            {
                std::string lit = fold_override(oit->second);
                if (!lit.empty())
                    regs[dst].value = lit;
            }
        }
        obs_override.erase(dst);
    }

    // ---- emission ----------------------------------------------------------
    std::ostringstream out;
    std::unordered_map<uint8_t, std::string> last_name; // reg -> last emitted local
    unsigned fresh = 0;

    auto fresh_name = [&]() -> std::string {
        return "v" + std::to_string(fresh++);
    };

    auto emit_def = [&](size_t k) -> bool {
        const TraceEvent& ev = evs[host_pos[k]];
        const Decoded d = decode(ev.insn);
        uint8_t dst = uint8_t(written_register(ev.tag, d));
        const RegState& st = regs[dst];

        std::string lhs, rhs_text;
        if (!split_lhs_rhs(ev, lhs, rhs_text))
        {
            res.why = "kept def without rendered form: " + ev.tag;
            return false;
        }

        bool first = !last_name.count(dst);
        std::string name = last_name.count(dst)
            ? last_name[dst]
            : ((!looks_like_reg(lhs) && is_valid_ident(lhs) && !reserved_words().count(lhs))
                   ? lhs
                   : fresh_name());

        switch (st.kind)
        {
        case RegKind::KConst:
        case RegKind::KMove:
            if (st.value.empty())
            {
                res.why = "def without observed value: " + ev.tag;
                return false;
            }
            out << (first ? "local " : "") << name << " = " << st.value << "\n";
            break;
        case RegKind::KRef:
            if (st.value.empty() || looks_like_reg(st.value) || begins_with(st.value, "upval_") ||
                st.value.find('[') != std::string::npos)
            {
                res.why = "unresolved reference survives the fold: " + ev.tag + " (" + st.value + ")";
                return false;
            }
            out << (first ? "local " : "") << name << " = " << st.value << "\n";
            break;
        case RegKind::KFold:
            res.why = "internal: fold def kept";
            return false;
        case RegKind::KCall:
        {
            std::string callee;
            std::vector<std::string> arg_texts;
            if (ev.call_info)
            {
                callee = ev.call_info->native_name.empty() ? ev.call_info->fn.text
                                                           : ev.call_info->native_name;
                for (const auto& a : ev.call_info->args)
                    arg_texts.push_back(a.text);
            }
            if (callee.empty())
            {
                // "lhs = callee(args)" -> recover callee from the text
                std::string rest = rhs_text;
                size_t op = rest.find('(');
                if (op == std::string::npos)
                {
                    res.why = "kept call without callee name";
                    return false;
                }
                callee = trim(rest.substr(0, op));
                arg_texts = split_args(rest.substr(op + 1, rest.rfind(')') - op - 1));
            }
            // Prefer the reproduced callee local (the def that owned this
            // register before the call) over the textual name.
            std::string callee_name = last_name.count(dst) ? last_name[dst] : "";
            if (callee_name.empty())
            {
                if (looks_like_reg(callee))
                {
                    res.why = "kept call whose callee has no reproduced local (" + callee + ")";
                    return false;
                }
                callee_name = callee;
            }
            out << (first ? "local " : "") << name << " = " << callee_name << "(";
            for (size_t i = 0; i < arg_texts.size(); ++i)
            {
                if (i)
                    out << ", ";
                out << arg_texts[i];
            }
            out << ")\n";
            break;
        }
        default:
            res.why = "internal: unhandled def kind";
            return false;
        }
        last_name[dst] = name;
        return true;
    };

    auto emit_terminal = [&](const Terminal& t) -> bool {
        const TraceEvent& ev = evs[host_pos[t.host_pos]];
        std::vector<std::string> args;
        if (ev.call_info)
        {
            for (const auto& a : ev.call_info->args)
                args.push_back(a.text);
        }
        else
        {
            std::string body;
            size_t op = ev.text.find('(');
            size_t cl = ev.text.rfind(')');
            if (op != std::string::npos && cl > op)
                body = ev.text.substr(op + 1, cl - op - 1);
            args = split_args(body);
        }
        size_t expect = size_t(int(t.b) - 1);
        if (expect != args.size() && !(args.empty() && expect == 0))
        {
            res.why = "reported argument count does not match the trace";
            return false;
        }
        out << "print(";
        for (size_t i = 0; i < args.size(); ++i)
        {
            if (i)
                out << ", ";
            uint8_t r = uint8_t(int(t.a) + 1 + int(i));
            auto it = last_name.find(r);
            if (it != last_name.end() && !it->second.empty())
                out << it->second;
            else
                out << args[i];
        }
        out << ")\n";
        return true;
    };

    for (size_t k = 0; k < H; ++k)
    {
        if (!kept[k])
            continue;
        const TraceEvent& ev = evs[host_pos[k]];
        if (event_calls_print(ev))
        {
            for (const Terminal& t : terminals)
                if (t.host_pos == k && !emit_terminal(t))
                    return res;
            continue;
        }
        if (!emit_def(k))
            return res;
    }

    res.lua = out.str();
    res.ok = !res.lua.empty();
    if (res.ok)
    {
        size_t kept_cnt = size_t(std::count(kept.begin(), kept.end(), true));
        res.why = "register-level payload reconstructed from " + std::to_string(terminals.size()) +
                  " printing call site(s); " + std::to_string(kept_cnt) + " kept events";
    }
    else
        res.why = "nothing to reconstruct";
    return res;
}

// ---------------------------------------------------------------------------
// Symbolic, CFF-aware reconstruction (see header).
// ---------------------------------------------------------------------------
namespace {

// Snapshot -> self-contained Lua literal, or "" when it is not a literal
// (table/function/unknown). Mirrors the tolerance of the tests' untyped
// snapshots (text already carrying quotes).
std::string snapshot_literal(const lure::LuaValueSnapshot& s)
{
    switch (s.type)
    {
    case lure::ValueType::String:
        return quote_lua_string(s.text);
    case lure::ValueType::Number:
        return s.text.empty() ? lure::lua_number_text(s.nvalue) : s.text;
    case lure::ValueType::Bool:
        return s.text.empty() ? (s.nvalue != 0.0 ? "true" : "false") : s.text;
    case lure::ValueType::Nil:
        return "nil";
    default:
        if (!s.text.empty() && (s.text.front() == '"' || s.text.front() == '\''))
            return s.text;
        return std::string();
    }
}

// A string literal ("...") used as a table key renders as `.name` when it is a
// valid identifier, else `["..."]`. field_name yields the bare "name" form used
// inside a table constructor (`name = value`), else the `["..."]` bracketed key.
std::string key_suffix(const std::string& keylit)
{
    if (keylit.size() >= 2 && keylit.front() == '"' && keylit.back() == '"')
    {
        std::string inner = keylit.substr(1, keylit.size() - 2);
        if (is_valid_ident(inner) && !reserved_words().count(inner))
            return "." + inner;
    }
    return "[" + keylit + "]";
}

std::string key_ctor_name(const std::string& keylit)
{
    if (keylit.size() >= 2 && keylit.front() == '"' && keylit.back() == '"')
    {
        std::string inner = keylit.substr(1, keylit.size() - 2);
        if (is_valid_ident(inner) && !reserved_words().count(inner))
            return inner;
    }
    return "[" + keylit + "]";
}

// TRUE iff the text is a self-contained Lua literal (number, string, boolean,
// nil). Used to tell a branch that tests reconstructed program data from one
// that only compares opaque scalars: the latter is what a flattened dispatcher
// looks like, and probing every one of them would cost a VM run each for no
// recoverable structure. This is a data-flow property of our own
// reconstruction, not a signature of any obfuscator -- a branch it skips is
// simply left un-recovered, never guessed at.
bool is_literal_text(const std::string& s)
{
    if (s.empty())
        return false;
    if (s == "true" || s == "false" || s == "nil")
        return true;
    if (s.front() == '"' || s.front() == '\'')
        return true;
    size_t i = (s[0] == '-') ? 1 : 0;
    if (i >= s.size())
        return false;
    bool digit = false;
    for (; i < s.size(); ++i)
    {
        if (std::isdigit(static_cast<unsigned char>(s[i])))
            digit = true;
        else if (s[i] != '.' && s[i] != 'e' && s[i] != 'E' && s[i] != '+' && s[i] != '-' &&
                 s[i] != 'x' && s[i] != 'X' && !std::isxdigit(static_cast<unsigned char>(s[i])))
            return false;
    }
    return digit;
}

// The condition under which the *executed* side of a two-way conditional runs,
// as a Lua operator. `taken` selects between the opcode's predicate and its
// negation, so the returned operator always describes the path the trace
// recorded (a `JUMPIFNOTEQ` that fell through guards `==`, and so on).
// Returns "" for opcodes this pass does not model.
const char* executed_side_operator(const std::string& tag, bool taken)
{
    if (tag == "JUMPIFEQ")
        return taken ? "==" : "~=";
    if (tag == "JUMPIFNOTEQ")
        return taken ? "~=" : "==";
    if (tag == "JUMPIFLE")
        return taken ? "<=" : ">";
    if (tag == "JUMPIFNOTLE")
        return taken ? ">" : "<=";
    if (tag == "JUMPIFLT")
        return taken ? "<" : ">=";
    if (tag == "JUMPIFNOTLT")
        return taken ? ">=" : "<";
    return "";
}

// One reconstructed statement plus the trace event that produced it.
struct SymStmt
{
    std::string text;
    size_t event_index = 0;
};

// A conditional whose executed side is expressible in reconstructed terms, and
// therefore worth asking the caller to probe. Same shape as the general pass's
// SymBranch, so both passes feed the one probe/region assembly below.
using BranchCand = SymBranch;

// Result of the forward symbolic pass over the printing frame.
struct SymPass
{
    bool ok = false;
    std::string why;
    std::vector<std::string> decls; // hoisted table constructors, in creation order
    std::vector<SymStmt> stmts;
    std::vector<BranchCand> cands;
};

SymPass symbolic_pass(const TraceData& trace)
{
    SymPass res;
    const std::vector<TraceEvent>& evs = trace.events;
    if (evs.empty())
    {
        res.why = "trace is empty";
        return res;
    }

    // The output must come from a single frame (its events are that frame's
    // straight-line executed sequence, CFF loop already unrolled by the trace).
    uint32_t host = 0;
    bool have_host = false;
    for (const TraceEvent& ev : evs)
    {
        if (!ev.printed_output)
            continue;
        if (!have_host)
        {
            host = ev.frame_id;
            have_host = true;
        }
        else if (ev.frame_id != host)
        {
            res.why = "stdout produced from multiple frames; not single-payload";
            return res;
        }
    }
    if (!have_host)
    {
        res.why = "no printing call sites in the trace";
        return res;
    }

    // Per-register symbolic expression (empty = unknown), and a mapping from a
    // register to the table object it currently aliases.
    std::vector<std::string> expr(256);
    struct Tbl
    {
        std::string name;
        std::vector<std::pair<std::string, std::string>> fields;
        bool declared = false;
    };
    std::vector<Tbl> tables;
    std::unordered_map<int, int> reg_table; // register -> index into `tables`
    unsigned tcount = 0;

    // Names are handed out when a table is first *declared*, not when it is
    // created: an obfuscated loader creates a variable number of scratch tables
    // before the payload's, so numbering by creation makes the name depend on
    // work that recovers nothing (and differs between two runs of a decoder that
    // uses math.random, which would defeat the probe comparison).
    auto table_name = [&](int ti) -> const std::string& {
        Tbl& t = tables[size_t(ti)];
        if (t.name.empty())
            t.name = "t" + std::to_string(tcount++);
        return t.name;
    };

    // Table constructors are hoisted ahead of the statements: their field values
    // are observed literals (or earlier tables, always created first), so the
    // constructor has no side effect and cannot depend on anything a statement
    // does. Hoisting keeps a `local` out of a recovered `if` body, where its
    // scope would end at the `end` while later statements still use it.
    auto declare_table = [&](int ti) {
        if (ti < 0 || size_t(ti) >= tables.size())
            return;
        Tbl& t = tables[size_t(ti)];
        if (t.declared)
            return;
        t.declared = true;
        // Fieldless tables are almost always obfuscator scratch (register-VM
        // arrays, metatable holders); emitting `local tN = {}` is pure noise and
        // recovers nothing, so skip them. A genuinely empty original table is a
        // rare, acceptable loss (its emptiness is unobservable here anyway).
        if (t.fields.empty())
            return;
        std::string s = "local " + table_name(ti) + " = {";
        for (size_t i = 0; i < t.fields.size(); ++i)
        {
            if (i)
                s += ", ";
            s += t.fields[i].first + " = " + t.fields[i].second;
        }
        s += "}";
        res.decls.push_back(std::move(s));
    };

    auto clear_reg = [&](int r) {
        if (r >= 0 && r < 256)
        {
            expr[size_t(r)].clear();
            reg_table.erase(r);
        }
    };

    // Dispatch counts per pc inside the host frame: the probe names a branch by
    // (frame, pc, nth hit), so the pass must count hits exactly as the VM does.
    std::unordered_map<uint32_t, uint32_t> pc_hits;

    // LURE_DEBUG_SYM=1 dumps the decoded operands and table key this pass reads
    // per event, which is what --dump-trace cannot show.
    const bool debug_sym = [] {
        const char* v = std::getenv("LURE_DEBUG_SYM");
        return v && *v == '1';
    }();

    for (size_t ei = 0; ei < evs.size(); ++ei)
    {
        const TraceEvent& ev = evs[ei];
        if (ev.frame_id != host)
            continue;
        const Decoded d = decode(ev.insn);
        const std::string& tag = ev.tag;
        const uint32_t hit = pc_hits[uint32_t(ev.pc)]++;
        if (debug_sym)
            std::fprintf(stderr, "[sym] pc=%llu %s insn=%08x a=%u b=%u c=%u tblop=%d key=%s\n",
                (unsigned long long)ev.pc, tag.c_str(), unsigned(ev.insn), unsigned(d.a),
                unsigned(d.b), unsigned(d.c), ev.table_op ? 1 : 0,
                ev.table_op ? snapshot_literal(ev.table_op->key).c_str() : "-");

        // Printing call: emit `print(<expr-or-literal>, ...)`.
        if (ev.printed_output && ev.call_info)
        {
            std::string s = "print(";
            const auto& args = ev.call_info->args;
            bool first = true;
            for (size_t k = 0; k < args.size(); ++k)
            {
                if (args[k].type == lure::ValueType::Nil)
                    break; // trailing VM padding, not a real argument
                if (!first)
                    s += ", ";
                first = false;
                int argreg = int(d.a) + 1 + int(k);
                if (argreg >= 0 && argreg < 256 && !expr[size_t(argreg)].empty())
                    s += expr[size_t(argreg)];
                else
                {
                    std::string l = snapshot_literal(args[k]);
                    s += l.empty() ? "nil" : l;
                }
            }
            s += ")";
            res.stmts.push_back(SymStmt{std::move(s), ei});
            continue;
        }

        if (tag == "LOADK" || tag == "LOADKX" || tag == "LOADN" || tag == "LOADB" || tag == "LOADNIL")
        {
            std::string lhs, rhs;
            if (split_lhs_rhs(ev, lhs, rhs) && !rhs.empty())
                expr[d.a] = rhs;
            else
                clear_reg(d.a);
            reg_table.erase(d.a);
        }
        else if (tag == "MOVE")
        {
            if (!expr[d.b].empty())
                expr[d.a] = expr[d.b];
            else
            {
                // Fall back to the observed value carried in the rendered text
                // (this is how folded decoder results appear: `x = "string"`).
                std::string lhs, rhs;
                if (split_lhs_rhs(ev, lhs, rhs) && !rhs.empty() && !looks_like_reg(rhs) &&
                    rhs.find("upval_") == std::string::npos)
                    expr[d.a] = rhs;
                else
                    expr[d.a].clear();
            }
            auto it = reg_table.find(d.b);
            if (it != reg_table.end())
                reg_table[d.a] = it->second;
            else
                reg_table.erase(d.a);
        }
        else if (tag == "NEWTABLE" || tag == "DUPTABLE")
        {
            tables.push_back(Tbl{});
            reg_table[d.a] = int(tables.size()) - 1;
            expr[d.a].clear(); // named only once it is declared (see table_name)
        }
        else if (tag == "SETTABLE" || tag == "SETTABLEKS" || tag == "SETTABLEN")
        {
            auto it = reg_table.find(int(d.b));
            if (it != reg_table.end() && ev.table_op && !tables[size_t(it->second)].declared)
            {
                std::string keylit = snapshot_literal(ev.table_op->key);
                std::string vallit;
                auto vt = reg_table.find(int(d.a));
                if (vt != reg_table.end())
                {
                    // The value is another reconstructed table: declare it first
                    // so the one being built can refer to it by name. A fieldless
                    // scratch table has nothing truthful to write, so the field is
                    // dropped rather than invented.
                    if (!tables[size_t(vt->second)].fields.empty())
                    {
                        declare_table(vt->second);
                        vallit = tables[size_t(vt->second)].name;
                    }
                }
                else
                {
                    vallit = ev.table_op->is_set ? snapshot_literal(ev.table_op->value)
                                                 : std::string();
                    if (vallit.empty() && !expr[d.a].empty())
                        vallit = expr[d.a];
                }
                if (!keylit.empty() && !vallit.empty())
                    tables[size_t(it->second)].fields.push_back({key_ctor_name(keylit), vallit});
            }
        }
        else if (tag == "GETTABLE" || tag == "GETTABLEKS" || tag == "GETTABLEN")
        {
            auto it = reg_table.find(int(d.b));
            std::string keylit = ev.table_op ? snapshot_literal(ev.table_op->key) : std::string();
            if (it != reg_table.end() && !keylit.empty() && !tables[size_t(it->second)].fields.empty())
            {
                declare_table(it->second); // the table is used: materialize it first
                expr[d.a] = tables[size_t(it->second)].name + key_suffix(keylit);
            }
            else
                clear_reg(d.a); // fieldless/scratch table read: fall back to observed value
            reg_table.erase(d.a);
        }
        else if (ev.is_branch)
        {
            // A conditional worth probing: both of its operands must be
            // nameable in reconstructed terms (otherwise the recovered `if`
            // would not read as the source did), and at least one of them must
            // be more than an opaque literal.
            const char* cmp = executed_side_operator(tag, ev.branch_taken);
            const std::string& lhs = expr[d.a];
            if (cmp && *cmp && ev.cond_rhs_reg >= 0 && ev.cond_rhs_reg < 256)
            {
                const std::string& rhs = expr[size_t(ev.cond_rhs_reg)];
                if (!lhs.empty() && !rhs.empty() && (!is_literal_text(lhs) || !is_literal_text(rhs)))
                {
                    BranchCand c;
                    c.frame_id = host;
                    c.pc = uint32_t(ev.pc);
                    c.hit_index = hit;
                    c.cond = lhs + " " + cmp + " " + rhs;
                    c.stmt_index = res.stmts.size();

                    res.cands.push_back(std::move(c));
                }
            }
            else if ((tag == "JUMPIF" || tag == "JUMPIFNOT") && !lhs.empty() && !is_literal_text(lhs))
            {
                bool truthy = (tag == "JUMPIF") ? ev.branch_taken : !ev.branch_taken;
                BranchCand c;
                c.frame_id = host;
                c.pc = uint32_t(ev.pc);
                c.hit_index = hit;
                c.cond = truthy ? lhs : ("not " + lhs);
                c.stmt_index = res.stmts.size();

                res.cands.push_back(std::move(c));
            }
        }
        else
        {
            // Any other register-defining op invalidates the symbolic value: we
            // did not model it, so downstream uses fall back to observed values.
            int w = written_register(tag, d);
            if (w >= 0)
                clear_reg(w);
        }
    }

    res.ok = !res.stmts.empty() || !res.decls.empty();
    res.why = res.ok ? "symbolic single-frame payload reconstruction (CFF-aware linear pass)"
                     : "no statements reconstructed";
    return res;
}

// A statement range proven to run only on one side of a conditional. Indices
// are into the pass's statement list (table constructors are hoisted separately
// and are never part of a region).
struct Region
{
    size_t begin = 0; // first guarded statement index
    size_t end = 0;   // one past the last
    std::string cond;
    std::vector<std::string> else_body; // the other side, observed under a probe
};

// Properly nested regions are rendered straight out of the sorted list, so no
// intermediate tree is built.
std::string join_lines(const std::vector<std::string>& v, const std::string& indent)
{
    std::string out;
    for (const std::string& s : v)
    {
        out += indent;
        out += s;
        out += "\n";
    }
    return out;
}

// Names of hoisted tables (`t0`, `t1`, ...) referenced by a statement.
void collect_table_refs(const std::string& s, std::unordered_set<std::string>& out)
{
    for (size_t i = 0; i < s.size();)
    {
        if (s[i] != 't' || (i > 0 && (std::isalnum(static_cast<unsigned char>(s[i - 1])) || s[i - 1] == '_')))
        {
            ++i;
            continue;
        }
        size_t j = i + 1;
        while (j < s.size() && std::isdigit(static_cast<unsigned char>(s[j])))
            ++j;
        if (j > i + 1 && (j == s.size() || !(std::isalnum(static_cast<unsigned char>(s[j])) || s[j] == '_')))
            out.insert(s.substr(i, j - i));
        i = j > i ? j : i + 1;
    }
}

} // namespace

std::vector<std::string> symbolic_statements(const TraceData& trace)
{
    SymPass p = symbolic_pass(trace);
    std::vector<std::string> out;
    out.reserve(p.stmts.size());
    for (const SymStmt& s : p.stmts)
        out.push_back(s.text);
    return out;
}

std::vector<std::string> general_statements(const TraceData& trace)
{
    SymProgram p = reconstruct_symbolic(trace);
    std::vector<std::string> out;
    out.reserve(p.stmts.size());
    for (const SymStatement& s : p.stmts)
        out.push_back(s.text);
    return out;
}

namespace {

// Shared probe/region assembly: turns a flat statement list plus the branches
// worth probing into structured Lua. Both reconstruction passes feed this, so
// branch recovery, the honesty gates and the rendering exist once.
PayloadDecompResult assemble(const std::vector<std::string>& decls,
    const std::vector<std::pair<std::string, unsigned>>& stmts,
    const std::vector<SymBranch>& cands, const BranchProbe& probe,
    std::vector<std::string> notes, const std::string& base_why)
{
    PayloadDecompResult res;
    std::vector<std::string> flat;
    std::vector<unsigned> depths;
    flat.reserve(stmts.size());
    depths.reserve(stmts.size());
    for (const auto& s : stmts)
    {
        flat.push_back(s.first);
        depths.push_back(s.second);
    }

    // Table names this reconstruction actually declares. An `else` body observed
    // under a probe may mention a table the recorded run never built; that name
    // would be undefined in the emitted Lua and the byte-for-byte re-run cannot
    // catch it (the `else` side never runs there), so such a region is dropped.
    std::unordered_set<std::string> declared;
    for (const std::string& d : decls)
    {
        size_t sp = d.find(' ', 6); // "local tN = ..."
        if (d.rfind("local ", 0) == 0 && sp != std::string::npos)
            declared.insert(d.substr(6, sp - 6));
    }

    // ---- branch recovery ---------------------------------------------------
    // Each probe costs a full VM run, so the number of candidates actually
    // probed is capped; whatever the cap drops is reported, never silently
    // ignored.
    const size_t kProbeCap = 32;
    std::vector<Region> regions;

    if (probe && !cands.empty())
    {
        size_t used = 0;
        for (const SymBranch& c : cands)
        {
            if (used >= kProbeCap)
            {
                res.probes_dropped = unsigned(cands.size() - used);
                break;
            }
            ++used;
            ProbeRequest rq;
            rq.frame_id = c.frame_id;
            rq.pc = c.pc;
            rq.hit_index = c.hit_index;
            ProbeReply rp = probe(rq);
            if (!rp.usable)
            {
                notes.push_back("branch `" + c.cond + "` (pc " + std::to_string(c.pc) +
                                "): the un-taken side is not observable -- " + rp.why);
                continue;
            }

            // Longest common prefix / suffix of the two runs' statement lists.
            // Execution is identical up to the inverted branch, so the prefix
            // must reach it; what remains on each side is that side's body.
            const std::vector<std::string>& a = flat;
            const std::vector<std::string>& b = rp.statements;
            size_t pre = 0;
            while (pre < a.size() && pre < b.size() && a[pre] == b[pre])
                ++pre;
            if (pre < c.stmt_index)
            {
                notes.push_back("branch `" + c.cond + "` (pc " + std::to_string(c.pc) +
                                "): the probe run diverged before the branch, so the guarded "
                                "extent is not determined; left unstructured");
                continue;
            }
            size_t suf = 0;
            while (suf < a.size() - pre && suf < b.size() - pre &&
                   a[a.size() - 1 - suf] == b[b.size() - 1 - suf])
                ++suf;
            if (a.size() - suf <= pre)
            {
                notes.push_back("branch `" + c.cond + "` (pc " + std::to_string(c.pc) +
                                "): both sides produce the same statements, so it guards nothing "
                                "observable; left unstructured");
                continue;
            }

            // A region must not cut a recovered loop in half: its statements have
            // to sit at one nesting level, or the emitted `if`/`end` would
            // straddle a `do`/`end` and the result would not even parse.
            bool balanced = true;
            for (size_t j = pre; j < a.size() - suf; ++j)
                if (depths[j] != depths[pre])
                    balanced = false;
            if (!balanced)
            {
                notes.push_back("branch `" + c.cond + "` (pc " + std::to_string(c.pc) +
                                "): the statements it guards span more than one loop nesting "
                                "level; left unstructured");
                continue;
            }

            Region r;
            r.begin = pre;
            r.end = a.size() - suf;
            r.cond = c.cond;
            for (size_t i = pre; i < b.size() - suf; ++i)
                r.else_body.push_back(b[i]);

            std::unordered_set<std::string> refs;
            for (const std::string& s : r.else_body)
                collect_table_refs(s, refs);
            bool undefined_ref = false;
            for (const std::string& t : refs)
                if (!declared.count(t))
                    undefined_ref = true;
            if (undefined_ref)
            {
                notes.push_back("branch `" + c.cond + "` (pc " + std::to_string(c.pc) +
                                "): the other side builds a table the recorded run never did, so "
                                "its body cannot be emitted self-contained; left unstructured");
                continue;
            }
            regions.push_back(std::move(r));
        }
        res.probes_run = unsigned(used);
    }

    // Keep a set that nests properly: a partial overlap would mean two probes
    // disagree about the extent, and wrapping either way would invent structure.
    // Widest first, so an outer conditional wins over an inner one.
    std::stable_sort(regions.begin(), regions.end(), [](const Region& x, const Region& y) {
        if (x.begin != y.begin)
            return x.begin < y.begin;
        return (x.end - x.begin) > (y.end - y.begin);
    });
    std::vector<Region> kept;
    for (const Region& r : regions)
    {
        bool conflict = false;
        for (const Region& k : kept)
        {
            bool disjoint = r.end <= k.begin || k.end <= r.begin;
            bool nested = (r.begin >= k.begin && r.end <= k.end) || (k.begin >= r.begin && k.end <= r.end);
            bool same = r.begin == k.begin && r.end == k.end;
            if (same || (!disjoint && !nested))
            {
                conflict = true;
                break;
            }
        }
        if (conflict)
            notes.push_back("branch `" + r.cond +
                            "`: its guarded extent coincides with or partially overlaps another "
                            "recovered conditional; left unstructured");
        else
            kept.push_back(r);
    }
    res.probed_branches = unsigned(kept.size());

    // ---- emission ----------------------------------------------------------
    // `kept` is sorted (begin ascending, width descending) and properly nested,
    // so a single cursor walks it: a region's children are exactly the entries
    // that follow it and fall inside its range, consumed by the recursive call.
    std::ostringstream out;
    for (const std::string& d : decls)
        out << d << "\n";

    std::function<void(size_t, size_t, size_t&, const std::string&)> render =
        [&](size_t from, size_t to, size_t& ki, const std::string& indent) {
            size_t i = from;
            while (i < to)
            {
                while (ki < kept.size() && kept[ki].begin < i)
                    ++ki; // defensive: a region we already covered
                if (ki < kept.size() && kept[ki].begin == i && kept[ki].end <= to)
                {
                    const Region r = kept[ki];
                    ++ki;
                    out << indent << "if " << r.cond << " then\n";
                    render(r.begin, r.end, ki, indent + "    ");
                    if (!r.else_body.empty())
                    {
                        out << indent << "else\n";
                        out << join_lines(r.else_body, indent + "    ");
                    }
                    else
                    {
                        out << indent
                            << "-- not found: re-executing the other side of this branch produced "
                               "no observable statement\n";
                    }
                    out << indent << "end\n";
                    i = r.end;
                    continue;
                }
                out << indent << std::string(4 * depths[i], ' ') << flat[i] << "\n";
                ++i;
            }
        };
    size_t cursor = 0;
    render(0, flat.size(), cursor, "");

    res.lua = out.str();
    res.ok = !res.lua.empty();
    if (!res.ok)
    {
        res.why = "no statements reconstructed";
        return res;
    }
    res.why = base_why;
    if (res.probed_branches)
        res.why += "; " + std::to_string(res.probed_branches) +
                   " conditional(s) recovered by re-executing the branch the other way, so both "
                   "sides are observed and neither is inferred";
    for (const std::string& n : notes)
        res.why += "; " + n;
    return res;
}

} // namespace

PayloadDecompResult decompile_payload_symbolic(const TraceData& trace)
{
    return decompile_payload_symbolic(trace, BranchProbe());
}

PayloadDecompResult decompile_payload_symbolic(const TraceData& trace, const BranchProbe& probe)
{
    SymPass p = symbolic_pass(trace);
    if (!p.ok)
    {
        PayloadDecompResult res;
        res.why = p.why;
        return res;
    }
    std::vector<std::pair<std::string, unsigned>> stmts;
    stmts.reserve(p.stmts.size());
    for (const SymStmt& s : p.stmts)
        stmts.push_back({s.text, 0u});
    PayloadDecompResult res = assemble(p.decls, stmts, p.cands, probe, {},
        "symbolic single-frame payload reconstruction (CFF-aware linear pass)");
    // Every statement this pass emits is a print, i.e. an observable effect; it
    // models nothing else, so nothing is left unexpressed by its own measure.
    res.expressed_effects = unsigned(p.stmts.size());
    return res;
}

PayloadDecompResult decompile_general(const TraceData& trace, const BranchProbe& probe)
{
    SymProgram p = reconstruct_symbolic(trace);
    if (!p.ok)
    {
        PayloadDecompResult res;
        res.why = p.why;
        return res;
    }
    std::vector<std::pair<std::string, unsigned>> stmts;
    stmts.reserve(p.stmts.size());
    for (const SymStatement& s : p.stmts)
        stmts.push_back({s.text, s.depth});
    PayloadDecompResult res = assemble(p.decls, stmts, p.branches, probe, p.notes, p.why);
    res.unexpressed_effects = p.unmodeled;
    for (const SymStatement& s : p.stmts)
        if (s.is_effect)
            ++res.expressed_effects;
    return res;
}

} // namespace lure::reconstruct
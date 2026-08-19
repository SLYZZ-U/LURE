// reconstruct/symbolic.cpp
// See symbolic.hpp for the contract.
//
// Structure of the pass:
//   1. pick the frame that carries the trace's observable effects;
//   2. interpret that frame's opcodes forward, keeping a symbolic expression per
//      register instead of the single observed value;
//   3. emit a statement at every observable effect, with propagated operands;
//   4. fold numeric-for loops whose recovered form provably reproduces every
//      observed iteration;
//   5. recover a called Lua function as a `function` when its body has effects
//      of its own, and fold it away when it is pure computation.

#include "reconstruct/symbolic.hpp"

#include "reconstruct/effects.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace lure::reconstruct {
namespace {

using lure::TraceData;
using lure::TraceEvent;

// Bounds. These exist so a 300k-event obfuscated frame cannot make the pass
// build an unbounded expression or recurse forever; every one of them is
// reported when it bites, never silently applied.
constexpr size_t kMaxExprLen = 240;     // beyond this, fall back to the observed value
constexpr unsigned kMaxFunctions = 32;  // recovered `function` bodies
constexpr unsigned kMaxFrameDepth = 6;  // recursion into callee frames
constexpr size_t kMaxStatements = 4000; // emitted statements

// ---------------------------------------------------------------------------
// small text helpers
// ---------------------------------------------------------------------------

struct Decoded
{
    uint8_t a = 0, b = 0, c = 0;
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
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b])))
        ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1])))
        --e;
    return s.substr(b, e - b);
}

// The right-hand side of a rendered "lhs = rhs" event, or "".
std::string rendered_rhs(const TraceEvent& ev)
{
    size_t eq = ev.text.find(" = ");
    if (eq == std::string::npos)
        return std::string();
    return trim(ev.text.substr(eq + 3));
}

bool is_ident(const std::string& s)
{
    if (s.empty() || !(std::isalpha(static_cast<unsigned char>(s[0])) || s[0] == '_'))
        return false;
    for (char c : s)
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_'))
            return false;
    return true;
}

const std::unordered_set<std::string>& reserved_words()
{
    static const std::unordered_set<std::string> s = {"and", "break", "do", "else", "elseif", "end",
        "false", "for", "function", "if", "in", "local", "nil", "not", "or", "repeat", "return",
        "then", "true", "until", "while"};
    return s;
}

std::string quote_lua_string(const std::string& s)
{
    std::string out = "\"";
    for (char ch : s)
    {
        switch (ch)
        {
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (static_cast<unsigned char>(ch) < 0x20 || static_cast<unsigned char>(ch) >= 0x7f)
            {
                // Zero-padded to three digits on purpose: `\1` followed by a digit
                // reads as a different character entirely, which is how decoded
                // binary payloads came out as malformed escapes.
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\%03d", int(static_cast<unsigned char>(ch)));
                out += buf;
            }
            else
                out.push_back(ch);
        }
    }
    return out + "\"";
}

// Snapshot -> self-contained Lua literal, or "" when the value is not one
// (a table, a function, an unresolved value).
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
        // untyped snapshots (hand-built fixtures) may already carry a literal
        if (!s.text.empty() && (s.text.front() == '"' || s.text.front() == '\''))
            return s.text;
        return std::string();
    }
}

// A key literal renders as `.name` after a base, or `["..."]`.
std::string key_suffix(const std::string& keylit)
{
    if (keylit.size() >= 2 && keylit.front() == '"' && keylit.back() == '"')
    {
        std::string inner = keylit.substr(1, keylit.size() - 2);
        if (is_ident(inner) && !reserved_words().count(inner))
            return "." + inner;
    }
    return "[" + keylit + "]";
}

// ... and as `name = value` resp. `[key] = value` inside a constructor.
std::string key_ctor_name(const std::string& keylit)
{
    if (keylit.size() >= 2 && keylit.front() == '"' && keylit.back() == '"')
    {
        std::string inner = keylit.substr(1, keylit.size() - 2);
        if (is_ident(inner) && !reserved_words().count(inner))
            return inner;
    }
    return "[" + keylit + "]";
}

// A compound expression needs parentheses before an operator is applied to it.
// Over-parenthesising is harmless; under-parenthesising changes the meaning.
bool is_atom(const std::string& s)
{
    if (s.empty())
        return false;
    if (s.front() == '"' || s.front() == '\'')
        return s.find(' ') == std::string::npos;
    for (char c : s)
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '.' || c == '[' ||
                c == ']' || c == '"'))
            return false;
    return true;
}

std::string paren(const std::string& s)
{
    return is_atom(s) ? s : "(" + s + ")";
}

// Can this field value be evaluated before any statement runs? Literals and the
// names of hoisted tables can; a call result (`vN`) or a loop-carried local
// (`nN`) or a loop variable (`iN`) cannot -- those only exist once a statement
// has run, so a constructor mentioning one cannot be hoisted above it.
bool hoistable_value(const std::string& v)
{
    for (size_t i = 0; i < v.size(); ++i)
    {
        const bool boundary = (i == 0) ||
            !(std::isalnum(static_cast<unsigned char>(v[i - 1])) || v[i - 1] == '_');
        if (!boundary || (v[i] != 'v' && v[i] != 'n' && v[i] != 'i' && v[i] != 'p'))
            continue;
        size_t j = i + 1;
        while (j < v.size() && std::isdigit(static_cast<unsigned char>(v[j])))
            ++j;
        if (j > i + 1 && (j == v.size() ||
                             !(std::isalnum(static_cast<unsigned char>(v[j])) || v[j] == '_')))
            return false;
    }
    return true;
}

// A quoted string literal used as an identifier (global names arrive quoted).
std::string unquote(const std::string& s)
{
    if (s.size() >= 2 && (s.front() == '"' || s.front() == '\'') && s.back() == s.front())
        return s.substr(1, s.size() - 2);
    return s;
}

const char* binary_operator(const std::string& tag)
{
    if (tag == "ADD" || tag == "ADDK") return "+";
    if (tag == "SUB" || tag == "SUBK" || tag == "SUBRK") return "-";
    if (tag == "MUL" || tag == "MULK") return "*";
    if (tag == "DIV" || tag == "DIVK" || tag == "DIVRK") return "/";
    if (tag == "IDIV" || tag == "IDIVK") return "//";
    if (tag == "MOD" || tag == "MODK") return "%";
    if (tag == "POW" || tag == "POWK") return "^";
    if (tag == "AND" || tag == "ANDK") return "and";
    if (tag == "OR" || tag == "ORK") return "or";
    return nullptr;
}

bool uses_constant_operand(const std::string& tag)
{
    return tag == "ADDK" || tag == "SUBK" || tag == "MULK" || tag == "DIVK" || tag == "IDIVK" ||
           tag == "MODK" || tag == "POWK" || tag == "SUBRK" || tag == "DIVRK" || tag == "ANDK" ||
           tag == "ORK";
}

// The constant is the *left* operand for these two only.
bool constant_operand_is_left(const std::string& tag)
{
    return tag == "SUBRK" || tag == "DIVRK";
}

// The condition under which the *executed* side of a two-way conditional runs.
// `taken` selects the opcode's predicate or its negation, so the operator always
// describes the path the trace recorded.
const char* executed_side_operator(const std::string& tag, bool taken)
{
    if (tag == "JUMPIFEQ") return taken ? "==" : "~=";
    if (tag == "JUMPIFNOTEQ") return taken ? "~=" : "==";
    if (tag == "JUMPIFLE") return taken ? "<=" : ">";
    if (tag == "JUMPIFNOTLE") return taken ? ">" : "<=";
    if (tag == "JUMPIFLT") return taken ? "<" : ">=";
    if (tag == "JUMPIFNOTLT") return taken ? ">=" : "<";
    return "";
}

// TRUE iff the text is a self-contained literal. Used to tell a conditional that
// tests reconstructed program data from one that only compares opaque scalars --
// the shape a flattened dispatcher has. A data-flow property of our own
// reconstruction, not a signature: a conditional this skips is left un-recovered
// rather than guessed at.
bool is_literal_text(const std::string& s)
{
    if (s.empty())
        return false;
    if (s == "true" || s == "false" || s == "nil")
        return true;
    if (s.front() == '"' || s.front() == '\'')
        return true;
    bool digit = false;
    for (size_t i = (s[0] == '-' ? 1 : 0); i < s.size(); ++i)
    {
        if (std::isdigit(static_cast<unsigned char>(s[i])))
            digit = true;
        else if (!std::isxdigit(static_cast<unsigned char>(s[i])) && s[i] != '.' && s[i] != '+' &&
                 s[i] != '-')
            return false;
    }
    return digit;
}

// Opcodes that only read: a frame built entirely from these computes a value and
// nothing else, so its call folds to the value the trace observed instead of
// being emitted. Name-free (opcode tags, not callee names) and deliberately
// excludes CALL and every write.
bool frame_is_pure(const std::vector<const TraceEvent*>& frame_events)
{
    static const std::unordered_set<std::string> pure = {"MOVE", "LOADK", "LOADKX", "LOADN",
        "LOADB", "LOADNIL", "GETUPVAL", "GETGLOBAL", "GETIMPORT", "GETTABLE", "GETTABLEKS",
        "GETTABLEN", "GETUDATAKS", "GETVARARGS", "PREPVARARGS", "NEWCLASS", "ADD", "SUB", "MUL",
        "DIV", "MOD", "POW", "IDIV", "ADDK", "SUBK", "MULK", "DIVK", "MODK", "POWK", "IDIVK",
        "SUBRK", "DIVRK", "AND", "OR", "ANDK", "ORK", "CONCAT", "NOT", "MINUS", "LENGTH",
        "NEWTABLE", "DUPTABLE", "NEWCLOSURE", "DUPCLOSURE", "RETURN", "JUMP", "JUMPBACK", "JUMPIF",
        "JUMPIFNOT", "JUMPIFEQ", "JUMPIFLE", "JUMPIFLT", "JUMPIFNOTEQ", "JUMPIFNOTLE",
        "JUMPIFNOTLT", "JUMPX", "JUMPXEQKNIL", "JUMPXEQKB", "JUMPXEQKN", "JUMPXEQKS", "CMPPROTO",
        "NOP", "BREAK", "EXTRAARG", "CLOSEUPVALS", "FORNPREP", "FORNLOOP"};
    for (const TraceEvent* ev : frame_events)
        if (!pure.count(ev->tag))
            return false;
    return true;
}

// ---------------------------------------------------------------------------
// the pass
// ---------------------------------------------------------------------------

// What a register currently holds.
struct RegVal
{
    std::string expr;  // Lua expression text; empty = unknown
    int table = -1;    // index into Builder::tables when it holds a rebuilt table
    // Name of the local this register was bound to. A register a loop body writes
    // and the previous iteration read is carried between iterations: kept as an
    // expression it would grow without bound and would name a loop variable that
    // is out of scope afterwards, so it becomes a real variable and every write
    // to it becomes an assignment.
    std::string bound;
};

struct Tbl
{
    std::string name;
    std::vector<std::pair<std::string, std::string>> fields;
    // Per field: can its value be evaluated before any statement runs? A literal
    // or another hoisted table can; a call's result cannot.
    std::vector<bool> hoistable_fields;
    size_t positional = 0; // next array slot, for SETLIST
    bool declared = false;
};

// A pending `obj:method(...)`: NAMECALL loads the method and self, the following
// CALL performs it, and only the pair renders as method-call syntax.
struct PendingMethod
{
    bool active = false;
    std::string base;
    std::string name;
};

class Builder
{
public:
    explicit Builder(const TraceData& trace) : trace_(trace) {}

    SymProgram run();

private:
    // -- emission
    void emit(std::string text, size_t ev_index, bool is_effect);
    void note(const std::string& reason);
    void unexpressed(const std::string& reason);
    const std::string& table_name(int ti);
    void declare_table(int ti);

    // -- per-frame interpretation
    void walk_frame(uint32_t frame, size_t begin, size_t end, unsigned depth,
        const std::vector<std::string>& params);
    size_t frame_end(uint32_t frame, size_t begin) const;
    std::vector<const TraceEvent*> events_of(uint32_t frame, size_t begin, size_t end) const;

    // -- operand access
    std::string operand(uint8_t reg) const;
    std::string operand_or_observed(uint8_t reg, const lure::LuaValueSnapshot& observed) const;
    void set_reg(uint8_t reg, std::string expr, int table = -1);
    void clear_reg(int reg);

    // -- pieces
    bool emit_call(const TraceEvent& ev, size_t ev_index, size_t self_index, unsigned depth);
    void consider_branch(const TraceEvent& ev, size_t ev_index, uint32_t hit);
    std::string branch_condition(const TraceEvent& ev);
    void bind_loop_carried(uint32_t frame, size_t from, size_t end, uint64_t lo, uint64_t hi,
        int skip_lo, int skip_hi);
    bool fold_loop(size_t header_stmt, const std::string& header, std::vector<unsigned> candidates);
    void eliminate_dead_bindings();

    const TraceData& trace_;
    SymProgram out_;
    std::vector<RegVal> regs_{256};
    std::vector<Tbl> tables_;
    PendingMethod method_;
    unsigned tcount_ = 0;
    unsigned vcount_ = 0;
    unsigned fcount_ = 0;
    unsigned loopvars_ = 0;
    std::unordered_set<std::string> notes_seen_;
    std::unordered_map<uint32_t, std::string> function_of_proto_; // recovered bodies
    std::unordered_map<uint32_t, uint32_t> pc_hits_;
    bool truncated_ = false;
};

void Builder::note(const std::string& reason)
{
    if (notes_seen_.insert(reason).second)
        out_.notes.push_back(reason);
}

void Builder::unexpressed(const std::string& reason)
{
    ++out_.unmodeled;
    note(reason);
}

void Builder::emit(std::string text, size_t ev_index, bool is_effect)
{
    if (out_.stmts.size() >= kMaxStatements)
    {
        truncated_ = true;
        return;
    }
    SymStatement s;
    s.text = std::move(text);
    s.event_index = ev_index;
    s.is_effect = is_effect;
    out_.stmts.push_back(std::move(s));
}

const std::string& Builder::table_name(int ti)
{
    Tbl& t = tables_[size_t(ti)];
    if (t.name.empty())
        t.name = "t" + std::to_string(tcount_++);
    return t.name;
}

// Table constructors are hoisted ahead of the statements: a constructor whose
// every field is an observed literal or an earlier table has no side effect and
// cannot depend on a statement, and hoisting keeps the `local` out of a recovered
// `if` or loop body, where its scope would end at the `end`. A constructor that
// *does* depend on a statement (a field holding a call's result) cannot be
// hoisted above it, so that one is emitted in place.
void Builder::declare_table(int ti)
{
    if (ti < 0 || size_t(ti) >= tables_.size())
        return;
    Tbl& t = tables_[size_t(ti)];
    if (t.declared)
        return;
    t.declared = true;
    std::string s = "local " + table_name(ti) + " = {";
    bool hoistable = true;
    for (size_t i = 0; i < t.fields.size(); ++i)
    {
        if (i)
            s += ", ";
        if (t.fields[i].first.empty())
            s += t.fields[i].second; // positional entry
        else
            s += t.fields[i].first + " = " + t.fields[i].second;
        if (!t.hoistable_fields[i])
            hoistable = false;
    }
    s += "}";
    if (hoistable)
        out_.decls.push_back(std::move(s));
    else
    {
        emit(std::move(s), 0, false);
        out_.stmts.back().def_name = t.name;
    }
}

std::string Builder::operand(uint8_t reg) const
{
    return regs_[reg].expr;
}

std::string Builder::operand_or_observed(
    uint8_t reg, const lure::LuaValueSnapshot& observed) const
{
    const std::string& e = regs_[reg].expr;
    if (!e.empty())
        return e;
    return snapshot_literal(observed); // "" when the value is not a literal either
}

void Builder::set_reg(uint8_t reg, std::string expr, int table)
{
    // An expression that has grown past the cap is not worth propagating: it
    // would be unreadable and cost more than it recovers. Dropping it makes
    // later uses fall back to the value the trace observed.
    if (expr.size() > kMaxExprLen)
    {
        note("an expression grew past " + std::to_string(kMaxExprLen) +
             " characters and was replaced by the value observed at its use");
        expr.clear();
    }
    // A bound register is a real variable: write to it instead of rewriting what
    // it means, so its value cannot grow across loop iterations.
    if (!regs_[reg].bound.empty() && table < 0)
    {
        if (expr.empty())
        {
            regs_[reg].bound.clear();
            regs_[reg].expr.clear();
            regs_[reg].table = -1;
            return;
        }
        if (expr != regs_[reg].bound)
            emit(regs_[reg].bound + " = " + expr, 0, false);
        regs_[reg].expr = regs_[reg].bound;
        regs_[reg].table = -1;
        return;
    }
    if (!regs_[reg].bound.empty())
        regs_[reg].bound.clear();
    regs_[reg].expr = std::move(expr);
    regs_[reg].table = table;
}

void Builder::clear_reg(int reg)
{
    if (reg >= 0 && reg < 256)
    {
        regs_[size_t(reg)].expr.clear();
        regs_[size_t(reg)].table = -1;
        regs_[size_t(reg)].bound.clear();
    }
}

// Writes a single destination register? Returns the register, or -1. Used to
// invalidate a register whose defining opcode this pass does not model, so later
// uses fall back to the value the trace observed instead of a stale expression.
int written_register(const std::string& tag, const Decoded& d)
{
    static const std::unordered_set<std::string> single_dst = {"MOVE", "LOADNIL", "LOADB", "LOADN",
        "LOADK", "LOADKX", "GETUPVAL", "GETGLOBAL", "GETIMPORT", "GETTABLE", "GETTABLEKS",
        "GETTABLEN", "GETUDATAKS", "NEWCLOSURE", "DUPCLOSURE", "NEWCLASS", "GETVARARGS", "ADD",
        "SUB", "MUL", "DIV", "MOD", "POW", "IDIV", "ADDK", "SUBK", "MULK", "DIVK", "MODK", "POWK",
        "IDIVK", "SUBRK", "DIVRK", "AND", "OR", "ANDK", "ORK", "CONCAT", "NOT", "MINUS", "LENGTH",
        "NEWTABLE", "DUPTABLE", "NAMECALL", "NAMECALLUDATA", "CALL", "CALLFB"};
    if (!single_dst.count(tag))
        return -1;
    return d.a;
}

// The index one past the last event of the frame that starts at `begin`: the
// first event that has returned out of it.
size_t Builder::frame_end(uint32_t frame, size_t begin) const
{
    const std::vector<TraceEvent>& evs = trace_.events;
    const uint32_t depth0 = evs[begin].call_depth;
    size_t i = begin;
    while (i < evs.size() && (evs[i].call_depth >= depth0 || evs[i].frame_id == frame))
        ++i;
    return i;
}

std::vector<const TraceEvent*> Builder::events_of(uint32_t frame, size_t begin, size_t end) const
{
    std::vector<const TraceEvent*> v;
    for (size_t i = begin; i < end; ++i)
        if (trace_.events[i].frame_id == frame)
            v.push_back(&trace_.events[i]);
    return v;
}

// A conditional whose executed side is expressible in reconstructed terms, and
// which is therefore worth asking the caller to probe by re-execution.
void Builder::consider_branch(const TraceEvent& ev, size_t ev_index, uint32_t hit)
{
    const Decoded d = decode(ev.insn);
    const std::string lhs = operand(d.a);
    const char* cmp = executed_side_operator(ev.tag, ev.branch_taken);
    SymBranch c;
    c.frame_id = ev.frame_id;
    c.pc = uint32_t(ev.pc);
    c.hit_index = hit;
    c.stmt_index = out_.stmts.size();

    if (cmp && *cmp && ev.cond_rhs_reg >= 0 && ev.cond_rhs_reg < 256)
    {
        const std::string rhs = operand(uint8_t(ev.cond_rhs_reg));
        if (lhs.empty() || rhs.empty() || (is_literal_text(lhs) && is_literal_text(rhs)))
            return;
        c.cond = lhs + " " + cmp + " " + rhs;
    }
    else if ((ev.tag == "JUMPIF" || ev.tag == "JUMPIFNOT") && !lhs.empty() && !is_literal_text(lhs))
    {
        const bool truthy = (ev.tag == "JUMPIF") ? ev.branch_taken : !ev.branch_taken;
        c.cond = truthy ? lhs : ("not " + paren(lhs));
    }
    else
        return;
    (void)ev_index;
    out_.branches.push_back(std::move(c));
}

// Folds the iterations recorded for a loop into one. Accepted only when every
// observed iteration renders identically -- then the loop provably reproduces all
// of them, because the only things that differed between iterations (the loop
// variable, the values carried across) are already variables in the body.
// Otherwise the iterations are left unrolled and the caller is told why.
//
// `candidates` are the iteration counts the trace makes plausible: a loop tested
// at the top runs its body once per back edge, one tested at the bottom runs it
// once more, and rather than infer which shape the source had, both are tried and
// the one whose body divides the observed statements evenly wins.
bool Builder::fold_loop(
    size_t header_stmt, const std::string& header, std::vector<unsigned> candidates)
{
    if (header_stmt > out_.stmts.size())
        return false;
    const size_t body_begin = header_stmt;
    const size_t span = out_.stmts.size() - body_begin;
    if (span == 0)
        return false;

    size_t per = 0;
    for (unsigned iterations : candidates)
    {
        if (iterations == 0 || span % iterations != 0)
            continue;
        const size_t candidate_per = span / iterations;
        bool same = true;
        for (unsigned k = 1; k < iterations && same; ++k)
            for (size_t j = 0; j < candidate_per; ++j)
                if (out_.stmts[body_begin + j].text !=
                    out_.stmts[body_begin + k * candidate_per + j].text)
                {
                    same = false;
                    break;
                }
        if (same)
        {
            per = candidate_per;
            break;
        }
    }
    if (per == 0)
        return false;

    std::vector<SymStatement> body(
        out_.stmts.begin() + long(body_begin), out_.stmts.begin() + long(body_begin + per));
    for (SymStatement& s : body)
        ++s.depth;
    out_.stmts.erase(out_.stmts.begin() + long(body_begin), out_.stmts.end());

    SymStatement head;
    head.text = header;
    head.event_index = body.empty() ? 0 : body.front().event_index;
    out_.stmts.push_back(std::move(head));
    for (SymStatement& s : body)
        out_.stmts.push_back(std::move(s));
    SymStatement tail;
    tail.text = "end";
    out_.stmts.push_back(std::move(tail));
    return true;
}

// The condition under which the side of `ev` that executed runs, rendered from
// propagated expressions, or "" when it cannot be rendered truthfully.
std::string Builder::branch_condition(const TraceEvent& ev)
{
    const Decoded d = decode(ev.insn);
    const std::string lhs = operand(d.a);
    const char* cmp = executed_side_operator(ev.tag, ev.branch_taken);
    if (cmp && *cmp && ev.cond_rhs_reg >= 0 && ev.cond_rhs_reg < 256)
    {
        const std::string rhs = operand(uint8_t(ev.cond_rhs_reg));
        if (lhs.empty() || rhs.empty())
            return std::string();
        return lhs + " " + cmp + " " + rhs;
    }
    if ((ev.tag == "JUMPIF" || ev.tag == "JUMPIFNOT") && !lhs.empty())
    {
        const bool truthy = (ev.tag == "JUMPIF") ? ev.branch_taken : !ev.branch_taken;
        return truthy ? lhs : ("not " + paren(lhs));
    }
    return std::string();
}

// Binds every register the pc range [lo, hi) writes that already holds a value:
// those are the ones carried from one iteration to the next, and as expressions
// they would grow without bound and could name a variable that is out of scope
// once the loop ends.
void Builder::bind_loop_carried(
    uint32_t frame, size_t from, size_t end, uint64_t lo, uint64_t hi, int skip_lo, int skip_hi)
{
    const std::vector<TraceEvent>& evs = trace_.events;
    std::unordered_set<int> written;
    for (size_t j = from; j < end; ++j)
    {
        const TraceEvent& b = evs[j];
        if (b.frame_id != frame || b.pc < lo || b.pc >= hi)
            continue;
        const int w = written_register(b.tag, decode(b.insn));
        if (w >= 0 && !(w >= skip_lo && w <= skip_hi))
            written.insert(w);
    }
    std::vector<int> ordered(written.begin(), written.end());
    std::sort(ordered.begin(), ordered.end());
    for (int w : ordered)
    {
        if (regs_[size_t(w)].expr.empty() || regs_[size_t(w)].table >= 0 ||
            !regs_[size_t(w)].bound.empty())
            continue;
        // The binding is emitted *before* the loop, so its initializer has to be
        // evaluable there. An expression mentioning a loop variable or another
        // loop's local is not, and binding it would emit code that reads nil.
        if (!hoistable_value(regs_[size_t(w)].expr))
            continue;
        std::string name = "n" + std::to_string(vcount_++);
        emit("local " + name + " = " + regs_[size_t(w)].expr, from, false);
        out_.stmts.back().def_name = name;
        regs_[size_t(w)].bound = name;
        regs_[size_t(w)].expr = name;
    }
}

// Emits the call at `ev`, recovering a called Lua function as a `function` when
// its body has effects of its own and folding it away when it is pure
// computation. Returns false when the call could not be expressed truthfully.
bool Builder::emit_call(const TraceEvent& ev, size_t ev_index, size_t frame_last, unsigned depth)
{
    const std::vector<TraceEvent>& evs = trace_.events;
    const Decoded d = decode(ev.insn);
    const uint8_t base = d.a;

    // Does this call enter a Lua frame? The callee's first dispatch is the very
    // next event, one level deeper; a native callee resumes in this frame.
    uint32_t callee = 0;
    bool has_callee = false;
    if (ev_index + 1 < evs.size() && evs[ev_index + 1].call_depth == ev.call_depth + 1 &&
        evs[ev_index + 1].frame_id != ev.frame_id)
    {
        callee = evs[ev_index + 1].frame_id;
        has_callee = true;
    }

    std::string callee_text;
    bool callee_observable = false;
    if (has_callee)
    {
        const size_t cbegin = ev_index + 1;
        const size_t cend = std::min(frame_end(callee, cbegin), frame_last);
        std::vector<const TraceEvent*> body = events_of(callee, cbegin, cend);
        if (body.empty() || frame_is_pure(body))
        {
            // Pure computation: its result is the value the trace observed at the
            // point of use, so the call itself recovers nothing and is elided.
            // This is what makes an obfuscator's string decoder disappear.
            clear_reg(base);
            return true;
        }
        // Does anything under this call reach the outside world? A call that does
        // not, and whose result nothing reads, is the obfuscator working for
        // itself and is dropped later by dead-binding elimination.
        for (size_t j = cbegin; j < cend; ++j)
            if (evs[j].printed_output || evs[j].tag == "SETGLOBAL" || evs[j].tag == "SETUPVAL")
            {
                callee_observable = true;
                break;
            }
        const uint32_t proto = body.front()->proto_id;
        auto known = function_of_proto_.find(proto);
        if (known != function_of_proto_.end())
            callee_text = known->second;
        else if (depth + 1 > kMaxFrameDepth)
        {
            unexpressed("a called function nested deeper than " + std::to_string(kMaxFrameDepth) +
                        " levels was not reconstructed, so the calls into it are not emitted");
            return false;
        }
        else if (fcount_ >= kMaxFunctions)
        {
            unexpressed("more than " + std::to_string(kMaxFunctions) +
                        " distinct functions were called; the rest are not reconstructed");
            return false;
        }
        else
        {
            const unsigned nargs = d.b > 0 ? unsigned(d.b) - 1u : 0u;
            std::vector<std::string> params;
            for (unsigned k = 0; k < nargs; ++k)
                params.push_back("p" + std::to_string(k));

            // Claim the name *before* recursing, so a function recovered inside
            // this one cannot be given the same one.
            callee_text = "f" + std::to_string(fcount_++);
            function_of_proto_[proto] = callee_text;

            Builder inner(trace_);
            inner.tcount_ = tcount_;
            inner.vcount_ = vcount_;
            inner.fcount_ = fcount_;
            inner.loopvars_ = loopvars_;
            inner.function_of_proto_ = function_of_proto_;
            inner.walk_frame(callee, cbegin, cend, depth + 1, params);
            // Names allocated inside must not be reused outside.
            tcount_ = inner.tcount_;
            vcount_ = inner.vcount_;
            fcount_ = inner.fcount_;
            loopvars_ = inner.loopvars_;
            out_.unmodeled += inner.out_.unmodeled;
            for (const std::string& n : inner.out_.notes)
                note(n);
            if (!inner.out_.branches.empty())
                note("a conditional inside a reconstructed function was not probed; only the "
                     "top-level frame's branches are");
            // The nested reconstruction's own functions and tables have to be
            // visible to this one, since its body is emitted inside ours.
            for (const auto& kv : inner.function_of_proto_)
                function_of_proto_.insert(kv);

            std::string fn = "local " + callee_text + " = function(";
            for (size_t k = 0; k < params.size(); ++k)
                fn += (k ? ", " : "") + params[k];
            fn += ")\n";
            for (const std::string& dcl : inner.out_.decls)
                fn += "    " + dcl + "\n";
            // A bare `return` at the very end of a body is the compiler's, not
            // the program's.
            size_t nstmt = inner.out_.stmts.size();
            while (nstmt > 0 && inner.out_.stmts[nstmt - 1].text == "return")
                --nstmt;
            for (size_t k = 0; k < nstmt; ++k)
                fn += std::string(4 + 4 * inner.out_.stmts[k].depth, ' ') +
                      inner.out_.stmts[k].text + "\n";
            fn += "end";
            out_.decls.push_back(std::move(fn));
        }
    }
    else if (ev.call_info && !ev.call_info->native_name.empty())
    {
        callee_text = ev.call_info->native_name;
    }
    else if (!operand(base).empty())
    {
        callee_text = operand(base);
    }
    else if (ev.printed_output)
    {
        // The callee could not be named, but the run proved this call reached the
        // host's output stream, and `print` is how the emitted Lua reaches it.
        callee_text = "print";
        note("a call that produced output could not be named; it is emitted as `print`, which is "
             "the channel the run showed it used");
    }
    else
    {
        unexpressed("a call whose callee could not be named was not emitted");
        return false;
    }

    // Arguments: registers base+1 .. base+nargs.
    unsigned nargs;
    if (d.b > 0)
        nargs = unsigned(d.b) - 1u;
    else
    {
        nargs = ev.call_info ? unsigned(ev.call_info->args.size()) : 0u;
        note("a call passed a variable number of arguments; the ones the trace recorded are "
             "emitted");
    }
    std::vector<std::string> args;
    for (unsigned k = 0; k < nargs; ++k)
    {
        const int reg = int(base) + 1 + int(k);
        if (reg >= 256)
            break;
        std::string a;
        if (regs_[size_t(reg)].table >= 0)
        {
            declare_table(regs_[size_t(reg)].table);
            a = table_name(regs_[size_t(reg)].table);
        }
        else
        {
            lure::LuaValueSnapshot observed;
            if (ev.call_info && k < ev.call_info->args.size())
                observed = ev.call_info->args[k];
            a = operand_or_observed(uint8_t(reg), observed);
        }
        if (a.empty())
        {
            unexpressed("an argument of a call was neither reconstructed nor observed as a value, "
                        "so the call was not emitted");
            return false;
        }
        args.push_back(std::move(a));
    }

    // `obj:method(...)` when a NAMECALL set this call up: its first argument is
    // the receiver, which method-call syntax carries on the left instead.
    std::string call_text;
    if (method_.active && !args.empty())
    {
        call_text = paren(method_.base) + ":" + method_.name + "(";
        for (size_t k = 1; k < args.size(); ++k)
            call_text += (k > 1 ? ", " : "") + args[k];
        call_text += ")";
    }
    else
    {
        call_text = callee_text + "(";
        for (size_t k = 0; k < args.size(); ++k)
            call_text += (k ? ", " : "") + args[k];
        call_text += ")";
    }
    method_ = PendingMethod{};

    const unsigned nres = d.c > 0 ? unsigned(d.c) - 1u : 1u;
    if (d.c == 0)
        note("a call returned a variable number of values; one is bound");
    if (nres >= 1)
    {
        std::string name = "v" + std::to_string(vcount_++);
        emit("local " + name + " = " + call_text, ev_index, true);
        SymStatement& s = out_.stmts.back();
        s.def_name = name;
        s.binds_call = true;
        s.observable_call = ev.printed_output || callee_observable;
        s.text_call = call_text;
        set_reg(base, name);
    }
    else
    {
        emit(call_text, ev_index, true);
        clear_reg(base);
    }
    return true;
}

// Interprets one frame's events in order.
void Builder::walk_frame(uint32_t frame, size_t begin, size_t end, unsigned depth,
    const std::vector<std::string>& params)
{
    const std::vector<TraceEvent>& evs = trace_.events;
    for (size_t k = 0; k < params.size() && k < 256; ++k)
        regs_[k].expr = params[k];

    struct LoopState
    {
        size_t body_begin = 0;
        std::string var, init, limit, step;
        unsigned iterations = 0;
        uint64_t header_pc = 0;
    };
    std::vector<LoopState> loops;

    // Generic loops (`while`, `repeat`, `for ... in`): a branch or jump that goes
    // backwards closes a body, and the pcs between its target and itself are that
    // body. Found by shape, from the trace alone -- nothing here knows what kind
    // of loop the source wrote, only that control returned to a place it had been.
    struct GenLoop
    {
        uint64_t head = 0, back = 0;
        size_t body_begin = 0;
        unsigned back_edges = 0;
        std::string cond;
        bool cond_fixed = false;
    };
    std::vector<std::pair<uint64_t, uint64_t>> back_edges; // (head, back)
    {
        // A back edge is simply control returning to a pc it has already been
        // past: taken from the executed sequence itself rather than from any
        // opcode's meaning, so it catches every loop the language has (`while`,
        // `repeat`, `for`, `for ... in`) and every one an obfuscator builds,
        // including the ones whose loop opcode carries no decidable condition.
        bool have_prev = false;
        uint64_t prev = 0;
        std::unordered_set<uint64_t> numeric_for_backs;
        for (size_t j = begin; j < end; ++j)
            if (evs[j].frame_id == frame && evs[j].tag == "FORNLOOP")
                numeric_for_backs.insert(evs[j].pc);
        for (size_t j = begin; j < end; ++j)
        {
            const TraceEvent& b = evs[j];
            if (b.frame_id != frame || b.tag == "TRUNCATED" || b.tag == "STEPLIMIT")
                continue;
            // A numeric for is recovered from its own opcodes, which carry the
            // bounds; leave its back edge to that path.
            if (have_prev && b.pc < prev && !numeric_for_backs.count(prev))
            {
                std::pair<uint64_t, uint64_t> e{b.pc, prev};
                if (std::find(back_edges.begin(), back_edges.end(), e) == back_edges.end())
                    back_edges.push_back(e);
            }
            prev = b.pc;
            have_prev = true;
        }
    }
    // Only properly nested bodies can be reconstructed as nested loops; an
    // overlapping pair is irreducible control flow and is left alone.
    std::sort(back_edges.begin(), back_edges.end());
    std::vector<GenLoop> gloops;
    std::unordered_set<uint64_t> loop_pcs; // pcs that are part of a loop body
    for (const auto& e : back_edges)
        for (const auto& f : back_edges)
            if (&e != &f)
            {
                const bool overlap = e.first < f.first && f.first <= e.second && e.second < f.second;
                if (overlap)
                    note("two loop bodies in this frame overlap (irreducible control flow); "
                         "neither is folded");
            }
    for (const auto& e : back_edges)
        for (uint64_t p = e.first; p <= e.second; ++p)
            loop_pcs.insert(p);

    for (size_t i = begin; i < end; ++i)
    {
        const TraceEvent& ev = evs[i];
        if (ev.frame_id != frame)
            continue;
        if (ev.tag == "TRUNCATED" || ev.tag == "STEPLIMIT")
        {
            truncated_ = true;
            continue;
        }
        const Decoded d = decode(ev.insn);
        const std::string& tag = ev.tag;
        const uint32_t hit = pc_hits_[uint32_t(ev.pc)]++;

        // Close every generic loop this instruction has left, and open the one it
        // has entered.
        while (!gloops.empty() && (ev.pc < gloops.back().head || ev.pc > gloops.back().back))
        {
            GenLoop g = gloops.back();
            gloops.pop_back();
            bool folded = false;
            if (!g.cond.empty())
                folded = fold_loop(g.body_begin, "while " + g.cond + " do",
                    {g.back_edges, g.back_edges + 1u});
            if (!folded)
                note("a loop at pc " + std::to_string(g.head) + " ran " +
                     std::to_string(g.back_edges + 1u) +
                     " iteration(s) that do not render identically (or whose condition could not "
                     "be expressed), so they are emitted unrolled");
        }
        for (const auto& e : back_edges)
            if (e.first == ev.pc &&
                (gloops.empty() || gloops.back().head != e.first) &&
                (gloops.empty() || (e.first > gloops.back().head && e.second < gloops.back().back)))
            {
                GenLoop g;
                g.head = e.first;
                g.back = e.second;
                bind_loop_carried(frame, i, end, e.first, e.second + 1, -1, -1);
                g.body_begin = out_.stmts.size();
                gloops.push_back(std::move(g));
                break;
            }
        if (!gloops.empty() && ev.pc == gloops.back().back && ev.branch_taken)
            ++gloops.back().back_edges;

        if (tag == "CALL" || tag == "CALLFB")
        {
            emit_call(ev, i, end, depth);
            continue;
        }
        if (tag == "NAMECALL" || tag == "NAMECALLUDATA")
        {
            // Sets up `base:name(...)`: the method lands in A and the receiver in
            // A+1, and the following CALL performs it.
            std::string base = operand(d.b);
            if (regs_[d.b].table >= 0)
            {
                declare_table(regs_[d.b].table);
                base = table_name(regs_[d.b].table);
            }
            const std::string m = unquote(ev.k_text);
            if (!base.empty() && is_ident(m))
            {
                method_.active = true;
                method_.base = base;
                method_.name = m;
            }
            else
                method_ = PendingMethod{};
            clear_reg(d.a);
            continue;
        }
        if (tag == "LOADK" || tag == "LOADKX" || tag == "LOADN" || tag == "LOADB" ||
            tag == "LOADNIL")
        {
            set_reg(d.a, rendered_rhs(ev));
            continue;
        }
        if (tag == "MOVE")
        {
            if (!regs_[d.b].expr.empty() || regs_[d.b].table >= 0)
                set_reg(d.a, regs_[d.b].expr, regs_[d.b].table);
            else
            {
                // No expression for the source: the value the trace observed
                // there is still a fact, and this is how a folded pure call's
                // result reaches its use.
                const std::string rhs = rendered_rhs(ev);
                set_reg(d.a, is_literal_text(rhs) ? rhs : std::string());
            }
            continue;
        }
        if (tag == "GETGLOBAL")
        {
            const std::string name = unquote(ev.k_text);
            set_reg(d.a, is_ident(name) ? name : std::string());
            continue;
        }
        if (tag == "SETGLOBAL")
        {
            const std::string name = unquote(ev.k_text);
            const std::string val = operand(d.a);
            if (is_ident(name) && !val.empty())
                emit(name + " = " + val, i, true);
            else if (is_ident(name) && regs_[d.a].table >= 0)
            {
                declare_table(regs_[d.a].table);
                emit(name + " = " + table_name(regs_[d.a].table), i, true);
            }
            else
                unexpressed("a write to a global could not be expressed and was not emitted");
            continue;
        }
        if (tag == "GETIMPORT")
        {
            set_reg(d.a, ev.k_text);
            continue;
        }
        if (tag == "NEWTABLE" || tag == "DUPTABLE")
        {
            tables_.push_back(Tbl{});
            regs_[d.a].expr.clear();
            regs_[d.a].table = int(tables_.size()) - 1;
            continue;
        }
        if (tag == "SETTABLE" || tag == "SETTABLEKS" || tag == "SETTABLEN")
        {
            const std::string keylit = ev.table_op ? snapshot_literal(ev.table_op->key) : std::string();
            std::string val;
            const int bt = regs_[d.b].table;
            bool self_reference = false;
            if (regs_[d.a].table >= 0)
            {
                // A table storing itself (`Account.__index = Account`) cannot be a
                // field of its own constructor -- the name does not exist yet
                // inside it -- so it has to become an assignment after the fact.
                self_reference = (regs_[d.a].table == bt);
                declare_table(regs_[d.a].table);
                val = table_name(regs_[d.a].table);
            }
            else
            {
                val = operand(d.a);
                if (val.empty() && ev.table_op && ev.table_op->is_set)
                    val = snapshot_literal(ev.table_op->value);
            }
            if (keylit.empty() || val.empty())
            {
                unexpressed("a table write whose key or value was neither reconstructed nor "
                            "observed as a value was not emitted");
                continue;
            }
            if (bt >= 0 && !tables_[size_t(bt)].declared && !self_reference)
            {
                tables_[size_t(bt)].fields.push_back({key_ctor_name(keylit), val});
                tables_[size_t(bt)].hoistable_fields.push_back(hoistable_value(val));
            }
            else if (bt >= 0)
            {
                declare_table(bt); // no-op when it is already out
                emit(table_name(bt) + key_suffix(keylit) + " = " + val, i, true);
            }
            else if (!operand(d.b).empty())
            {
                emit(paren(operand(d.b)) + key_suffix(keylit) + " = " + val, i, true);
            }
            else
                unexpressed("a write into a table this pass never saw created was not emitted");
            continue;
        }
        if (tag == "SETLIST")
        {
            const int bt = regs_[d.a].table;
            const unsigned count = d.c > 0 ? unsigned(d.c) - 1u : 0u;
            if (bt < 0 || count == 0)
            {
                unexpressed("a table filled by SETLIST could not be expressed");
                continue;
            }
            Tbl& t = tables_[size_t(bt)];
            for (unsigned k = 0; k < count; ++k)
            {
                const int reg = int(d.b) + int(k);
                if (reg >= 256)
                    break;
                std::string v = operand(uint8_t(reg));
                if (regs_[size_t(reg)].table >= 0)
                {
                    declare_table(regs_[size_t(reg)].table);
                    v = table_name(regs_[size_t(reg)].table);
                }
                if (v.empty())
                {
                    unexpressed("an element of a table constructor was neither reconstructed nor "
                                "observed and was left out");
                    continue;
                }
                if (!t.declared)
                {
                    t.fields.push_back({std::string(), v});
                    t.hoistable_fields.push_back(hoistable_value(v));
                }
                else
                    emit(table_name(bt) + "[" + std::to_string(++t.positional) + "] = " + v, i, true);
            }
            continue;
        }
        if (tag == "GETTABLE" || tag == "GETTABLEKS" || tag == "GETTABLEN")
        {
            const std::string keylit = ev.table_op ? snapshot_literal(ev.table_op->key) : std::string();
            const int bt = regs_[d.b].table;
            if (bt >= 0 && !keylit.empty())
            {
                declare_table(bt);
                set_reg(d.a, table_name(bt) + key_suffix(keylit));
            }
            else if (!operand(d.b).empty() && !keylit.empty())
                set_reg(d.a, paren(operand(d.b)) + key_suffix(keylit));
            else
                clear_reg(d.a);
            continue;
        }
        if (const char* op = binary_operator(tag))
        {
            std::string l, r;
            if (uses_constant_operand(tag))
            {
                if (constant_operand_is_left(tag))
                {
                    l = ev.k_text;
                    r = operand(d.b);
                }
                else
                {
                    l = operand(d.b);
                    r = ev.k_text;
                }
            }
            else
            {
                l = operand(d.b);
                r = operand(d.c);
            }
            if (l.empty() || r.empty())
                clear_reg(d.a);
            else
                set_reg(d.a, paren(l) + " " + op + " " + paren(r));
            continue;
        }
        if (tag == "NOT" || tag == "MINUS" || tag == "LENGTH")
        {
            const std::string v = operand(d.b);
            if (v.empty())
                clear_reg(d.a);
            else
                set_reg(d.a, (tag == "NOT" ? "not " : tag == "MINUS" ? "-" : "#") + paren(v));
            continue;
        }
        if (tag == "CONCAT")
        {
            std::string s;
            bool ok = true;
            for (int r = int(d.b); r <= int(d.c) && r < 256; ++r)
            {
                const std::string v = operand(uint8_t(r));
                if (v.empty())
                {
                    ok = false;
                    break;
                }
                s += (s.empty() ? "" : " .. ") + paren(v);
            }
            if (ok)
                set_reg(d.a, s);
            else
                clear_reg(d.a);
            continue;
        }
        if (tag == "RETURN")
        {
            const unsigned n = d.b > 0 ? unsigned(d.b) - 1u : 0u;
            if (n == 0)
            {
                if (depth > 0)
                    emit("return", i, false);
                continue;
            }
            std::string s;
            bool ok = true;
            for (unsigned k = 0; k < n; ++k)
            {
                const int reg = int(d.a) + int(k);
                std::string v = operand(uint8_t(reg));
                if (regs_[size_t(reg)].table >= 0)
                {
                    declare_table(regs_[size_t(reg)].table);
                    v = table_name(regs_[size_t(reg)].table);
                }
                if (v.empty())
                {
                    ok = false;
                    break;
                }
                s += (k ? ", " : "") + v;
            }
            if (ok)
                emit("return " + s, i, false);
            else
                unexpressed("a returned value was neither reconstructed nor observed, so the "
                            "`return` was not emitted");
            continue;
        }
        if (tag == "FORNPREP")
        {
            // Render is "-- for init NAME = INIT, LIMIT, STEP" -- our own format,
            // and all three are observed numeric literals.
            LoopState st;
            st.header_pc = ev.pc;
            st.body_begin = out_.stmts.size();
            const std::string spec = rendered_rhs(ev);
            std::vector<std::string> parts;
            size_t from = 0;
            for (size_t p = spec.find(", "); ; p = spec.find(", ", from))
            {
                if (p == std::string::npos)
                {
                    parts.push_back(trim(spec.substr(from)));
                    break;
                }
                parts.push_back(trim(spec.substr(from, p - from)));
                from = p + 2;
            }
            if (parts.size() == 3 && is_literal_text(parts[0]) && is_literal_text(parts[1]) &&
                is_literal_text(parts[2]) && ev.branch_taken)
            {
                st.var = "i" + std::to_string(loopvars_++);
                st.init = parts[0];
                st.limit = parts[1];
                st.step = parts[2];
                set_reg(uint8_t(int(d.a) + 2), st.var);

                // Bind the registers the body writes that already hold a value:
                // those are the ones carried from one iteration to the next. The
                // body's pc range is known from the jump this instruction would
                // take over an empty loop.
                if (ev.jump_target > ev.pc + 1)
                    bind_loop_carried(frame, i, end, ev.pc + 1, ev.jump_target - 1, int(d.a),
                        int(d.a) + 2);
                st.body_begin = out_.stmts.size(); // after the bindings above
            }
            else if (!ev.branch_taken)
                note("a numeric for was reached with an empty range, so it has no observed body");
            else
                note("a numeric for whose bounds were not observed as numbers was left unrolled");
            loops.push_back(std::move(st));
            continue;
        }
        if (tag == "FORNLOOP")
        {
            if (loops.empty())
                continue;
            LoopState& st = loops.back();
            ++st.iterations;
            if (ev.branch_taken)
                continue; // another iteration follows
            bool folded = false;
            if (!st.var.empty())
                folded = fold_loop(st.body_begin,
                    "for " + st.var + " = " + st.init + ", " + st.limit + ", " + st.step + " do",
                    {st.iterations});
            if (!folded && !st.var.empty())
                note("a numeric for at pc " + std::to_string(st.header_pc) + " ran " +
                     std::to_string(st.iterations) +
                     " iterations that do not render identically, so they are emitted unrolled");
            clear_reg(int(d.a) + 2);
            loops.pop_back();
            continue;
        }
        if (tag == "FORGPREP" || tag == "FORGPREP_NEXT" || tag == "FORGPREP_INEXT" ||
            tag == "FORGLOOP")
        {
            note("a generic `for ... in` loop was left unrolled; only numeric for is folded");
            for (int r = int(d.a); r < int(d.a) + 6 && r < 256; ++r)
                clear_reg(r);
            continue;
        }
        if (ev.is_branch)
        {
            // Inside a loop, the branch that decides whether to run another
            // iteration is the loop's condition, not a conditional in the source.
            if (!gloops.empty() && !gloops.back().cond_fixed && ev.other_target >= 0 &&
                (uint64_t(ev.other_target) < gloops.back().head ||
                    uint64_t(ev.other_target) > gloops.back().back))
            {
                gloops.back().cond = branch_condition(ev);
                gloops.back().cond_fixed = true;
            }
            // A conditional is only offered for probing when it is not part of a
            // loop: a loop's own tests are not source-level `if`s, and wrapping
            // one in an if/else would claim a structure the program does not have.
            else if (loops.empty() && gloops.empty() && !loop_pcs.count(ev.pc) && hit == 0)
                consider_branch(ev, i, hit);
            continue;
        }
        if (tag == "SETUPVAL")
        {
            unexpressed("a write to an upvalue cannot be named from the trace and was not emitted");
            continue;
        }

        const int w = written_register(tag, d);
        if (w >= 0)
            clear_reg(w);
    }

    // A loop still open at the end of the frame never reported its exit (the
    // frame ended inside it, or the trace was cut). Fold what was observed.
    while (!loops.empty())
    {
        const LoopState& st = loops.back();
        if (!st.var.empty() && st.iterations > 0)
            fold_loop(st.body_begin,
                "for " + st.var + " = " + st.init + ", " + st.limit + ", " + st.step + " do",
                {st.iterations});
        loops.pop_back();
    }
    while (!gloops.empty())
    {
        const GenLoop& g = gloops.back();
        if (!g.cond.empty())
            fold_loop(g.body_begin, "while " + g.cond + " do", {g.back_edges, g.back_edges + 1u});
        gloops.pop_back();
    }
    (void)depth;
}

// The name a `local X = ...` line binds, or "".
std::string bound_name(const std::string& text)
{
    if (text.rfind("local ", 0) != 0)
        return std::string();
    size_t sp = text.find(' ', 6);
    if (sp == std::string::npos)
        return std::string();
    std::string n = text.substr(6, sp - 6);
    return is_ident(n) ? n : std::string();
}

// Occurrences of `name` as a standalone identifier.
unsigned count_uses(const std::string& hay, const std::string& name)
{
    unsigned n = 0;
    for (size_t p = hay.find(name); p != std::string::npos; p = hay.find(name, p + 1))
    {
        const bool left = (p == 0) ||
            !(std::isalnum(static_cast<unsigned char>(hay[p - 1])) || hay[p - 1] == '_');
        const size_t e = p + name.size();
        const bool right = (e >= hay.size()) ||
            !(std::isalnum(static_cast<unsigned char>(hay[e])) || hay[e] == '_');
        if (left && right)
            ++n;
    }
    return n;
}

// Drops every binding nothing reads, repeatedly, until nothing more is dead.
// This is what removes an obfuscator's decoder from the output without knowing
// anything about it: its calls exist only to produce values the payload already
// carries as literals, so once those literals are in place nothing reads the
// results and the whole chain falls away. A dropped call that reached the outside
// world would be a silent loss, so an observable one keeps its call and loses
// only the binding.
void Builder::eliminate_dead_bindings()
{
    unsigned dropped_calls = 0, dropped_values = 0;
    for (bool changed = true; changed;)
    {
        changed = false;
        // Everything that could reference a name, minus the definition itself.
        std::vector<std::string> pool;
        pool.reserve(out_.decls.size() + out_.stmts.size());
        for (const std::string& d : out_.decls)
            pool.push_back(d);
        for (const SymStatement& s : out_.stmts)
            pool.push_back(s.text);

        auto uses_elsewhere = [&](const std::string& name, size_t skip) {
            unsigned n = 0;
            for (size_t i = 0; i < pool.size(); ++i)
            {
                if (i == skip)
                    continue;
                n += count_uses(pool[i], name);
            }
            return n;
        };

        for (size_t i = 0; i < out_.stmts.size() && !changed; ++i)
        {
            SymStatement& s = out_.stmts[i];
            const std::string name = s.def_name.empty() ? bound_name(s.text) : s.def_name;
            if (name.empty())
                continue;
            if (uses_elsewhere(name, out_.decls.size() + i) != 0)
                continue;
            if (s.binds_call && s.observable_call)
            {
                // Keep the call, drop the binding.
                s.text = s.text_call.empty() ? s.text : s.text_call;
                s.def_name.clear();
                s.binds_call = false;
                changed = true;
            }
            else
            {
                if (s.binds_call)
                    ++dropped_calls;
                else
                    ++dropped_values;
                out_.stmts.erase(out_.stmts.begin() + long(i));
                changed = true;
            }
        }
        for (size_t i = 0; i < out_.decls.size() && !changed; ++i)
        {
            const std::string name = bound_name(out_.decls[i]);
            if (name.empty())
                continue;
            if (uses_elsewhere(name, i) != 0)
                continue;
            ++dropped_values;
            out_.decls.erase(out_.decls.begin() + long(i));
            changed = true;
        }
    }
    if (dropped_calls)
        note(std::to_string(dropped_calls) +
             " call(s) whose result nothing read and which produced no observable effect were "
             "dropped");
    if (dropped_values)
        note(std::to_string(dropped_values) +
             " value(s) or function(s) nothing read were dropped");
}

SymProgram Builder::run()
{
    const std::vector<TraceEvent>& evs = trace_.events;
    if (evs.empty())
    {
        out_.why = "trace is empty";
        return out_;
    }

    // Anchor: the frame that carries the observable effects. Output first (that
    // is the strongest evidence a frame is the payload), then any other effect
    // the outside world can see -- a write to a global, a call into a function
    // the host provided -- and finally, for a script that does none of those, the
    // frame execution started in, which for an un-obfuscated script is the whole
    // program. Anchoring on output alone left every silent script, which is most
    // real ones, with nothing to reconstruct.
    auto anchor_frame = [&](bool (*pred)(const TraceEvent&), uint32_t& frame) {
        bool found = false;
        for (const TraceEvent& ev : evs)
        {
            if (!pred(ev))
                continue;
            if (!found)
            {
                frame = ev.frame_id;
                found = true;
            }
            else if (ev.frame_id != frame)
            {
                out_.why = "the observable effects come from more than one frame; not a single "
                           "payload";
                return false;
            }
        }
        return found;
    };

    uint32_t host = 0;
    bool ok = anchor_frame([](const TraceEvent& e) { return e.printed_output; }, host);
    if (!ok && !out_.why.empty())
    {
        // Effects from several frames: they share a caller, and reconstructing
        // from there recovers those frames as functions instead of giving up.
        out_.why.clear();
        ok = false;
    }
    if (!ok)
    {
        ok = anchor_frame(
            [](const TraceEvent& e) { return event_is_observable_effect(e); }, host);
        if (!ok && !out_.why.empty())
            out_.why.clear();
    }
    if (!ok)
        host = evs.front().frame_id;

    size_t begin = 0;
    while (begin < evs.size() && evs[begin].frame_id != host)
        ++begin;
    if (begin >= evs.size())
    {
        out_.why = "the anchor frame has no events";
        return out_;
    }
    walk_frame(host, begin, frame_end(host, begin), 0, {});
    eliminate_dead_bindings();

    // Luau allows at most 200 locals per function, so a reconstruction with more
    // than that cannot even be compiled -- and one that needs thousands is not a
    // program anyone would read, it is an obfuscator's machinery that the pass
    // failed to elide. Say so instead of emitting Lua that cannot load. A
    // recovered function body is one decl holding many lines, so the count is per
    // decl as well as at the top level.
    {
        auto count_locals = [](const std::string& text) {
            unsigned n = 0;
            for (size_t p = text.find("local "); p != std::string::npos;
                 p = text.find("local ", p + 1))
            {
                const bool at_start = (p == 0) || text[p - 1] == '\n' || text[p - 1] == ' ';
                if (at_start)
                    ++n;
            }
            return n;
        };
        unsigned worst = 0;
        for (const std::string& d : out_.decls)
        {
            ++worst; // the decl itself is a local in the enclosing scope
            worst = std::max(worst, count_locals(d));
        }
        unsigned top = unsigned(out_.decls.size());
        for (const SymStatement& s : out_.stmts)
            top += count_locals(s.text);
        worst = std::max(worst, top);
        if (worst > 195)
        {
            out_.why = "the reconstruction needs " + std::to_string(worst) +
                       " locals in one scope, past the 200 Luau allows: the frame that was "
                       "reconstructed is machinery, not a payload";
            return out_;
        }
    }

    if (truncated_)
        note("the trace or the statement budget was exhausted, so the reconstruction is a prefix");
    out_.ok = !out_.stmts.empty() || !out_.decls.empty();
    out_.why = out_.ok ? "general symbolic reconstruction of the frame carrying the observable "
                         "effects"
                       : "nothing observable was reconstructed";
    return out_;
}

} // namespace

SymProgram reconstruct_symbolic(const TraceData& trace)
{
    Builder b(trace);
    return b.run();
}

} // namespace lure::reconstruct

// vm/instrumentation.cpp
// Layer 1: the trace hook invoked by the patched Luau VM (third_party/luau,
// see patches/luau/0001-instrument-vm-dispatch.patch) right before every
// opcode dispatch, plus the whitelisted-stdlib native registry.
//
// Resilience contract (spec section 0/5): this hook NEVER guesses and NEVER
// aborts execution. Values it cannot classify are recorded as Unknown with an
// exact reason; the pipeline continues. All accesses to the Lua state are
// read-only and bounds-checked -- with one explicit, opt-in exception: when a
// branch flip has been armed (lure_trace_arm_branch_flip) the hook rewrites a
// single conditional-jump instruction word to its complement and restores it on
// the next dispatch, so a probe run can execute the other declared side of an
// observed branch. Nothing is armed unless the caller asks for it.

#include "instrumentation.h"
#include "instrumentation.hpp"

#include "trace/trace_events.hpp"

#include "lbytecode.h"
#include "ldebug.h"
#include "lfunc.h"
#include "lobject.h"
#include "lstate.h"
#include "lstring.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace lure::vm::instrumentation {

static bool g_enabled = false;
static unsigned g_max_events = 200000;
static bool g_truncated = false;
static bool g_debug_nil = false; // LURE_DEBUG_NIL=1 enables nil-call forensics
static std::vector<TraceEvent> g_events;
static std::unordered_map<const void*, std::string> g_whitelist;

// Index (into g_events) of the most recently recorded call-family event. The
// host marks it via lure_trace_mark_output_written() when the call wrote to
// the output stream (print sink), giving a name-free "this call printed" flag.
static unsigned g_last_call_index = 0;

// Per-call-frame serials: each Lua call site gets a fresh serial while its
// frame is live (a depth transition pushes/pops one serial), so events of one
// function invocation share an id, distinct from re-invocations and from the
// caller/callees. Serial 0 is reserved for the C driver frame.
static std::vector<uint32_t> g_frame_stack{0};
static uint32_t g_next_serial = 1;

// Per-proto ids, numbered in first-execution order. The pointer itself is not
// stable across runs (nor meaningful downstream), but the numbering is: it is a
// function of the execution, so two runs of the same script agree. Needed
// because a pc only identifies an instruction within its own function.
static std::unordered_map<const void*, uint32_t> g_proto_ids;
static uint32_t g_next_proto_id = 1;

// ---------------------------------------------------------------------------
// One-shot branch inversion (see lure_trace_arm_branch_flip in the header).
//
// `armed` names a single dispatch of one instruction: the hit_index-th time
// pc_index is reached inside the frame whose serial is frame_id. On that
// dispatch the instruction word (and, for the JUMPXEQK* family, its aux word)
// is rewritten in place to the complementary conditional, and `pending`
// remembers the original words so the very next dispatch restores them. The
// hook runs before every instruction, so "the next dispatch" is always after
// the rewritten one has executed: exactly one branch decision is inverted and
// the bytecode is left byte-identical afterwards.
struct BranchFlip
{
    bool armed = false;
    uint32_t frame_id = 0;
    uint32_t pc_index = 0;
    uint32_t hit_index = 0;
    uint32_t hits = 0; // times the target (frame, pc) has been reached
    bool fired = false;
};
static BranchFlip g_flip;

struct PendingRestore
{
    uint32_t* addr = nullptr; // instruction word to restore
    uint32_t insn = 0;
    uint32_t* aux_addr = nullptr; // aux word, when the flip touched it
    uint32_t aux = 0;
};
static PendingRestore g_pending;

static void restore_pending_flip()
{
    if (g_pending.addr)
    {
        *g_pending.addr = g_pending.insn;
        g_pending.addr = nullptr;
    }
    if (g_pending.aux_addr)
    {
        *g_pending.aux_addr = g_pending.aux;
        g_pending.aux_addr = nullptr;
    }
}

// Forgets a pending restore *without* writing. The words live in a Proto owned
// by the lua_State, so once the host has closed that state the addresses are
// dangling and must never be written back; nothing will execute that bytecode
// again either, so dropping is the correct end-of-run action.
static void drop_pending_flip()
{
    g_pending = PendingRestore{};
}

// The complementary conditional of `op`, or -1 when the opcode has none.
// Complementary pairs share their jump target, so swapping the opcode inverts
// which of the two declared sides executes and nothing else.
static int complementary_branch_op(unsigned op)
{
    switch (static_cast<LuauOpcode>(op))
    {
    case LOP_JUMPIF:
        return LOP_JUMPIFNOT;
    case LOP_JUMPIFNOT:
        return LOP_JUMPIF;
    case LOP_JUMPIFEQ:
        return LOP_JUMPIFNOTEQ;
    case LOP_JUMPIFNOTEQ:
        return LOP_JUMPIFEQ;
    case LOP_JUMPIFLE:
        return LOP_JUMPIFNOTLE;
    case LOP_JUMPIFNOTLE:
        return LOP_JUMPIFLE;
    case LOP_JUMPIFLT:
        return LOP_JUMPIFNOTLT;
    case LOP_JUMPIFNOTLT:
        return LOP_JUMPIFLT;
    default:
        return -1;
    }
}

// The JUMPXEQK* family encodes its sense as bit 31 of the aux word.
static bool branch_sense_in_aux(unsigned op)
{
    switch (static_cast<LuauOpcode>(op))
    {
    case LOP_JUMPXEQKNIL:
    case LOP_JUMPXEQKB:
    case LOP_JUMPXEQKN:
    case LOP_JUMPXEQKS:
        return true;
    default:
        return false;
    }
}

static void reset_frame_tracking()
{
    g_frame_stack.assign({0});
    g_next_serial = 1;
    g_proto_ids.clear();
    g_next_proto_id = 1;
}

void clear_events()
{
    g_events.clear();
    g_truncated = false;
    g_last_call_index = 0;
    reset_frame_tracking();
    drop_pending_flip();
    g_flip = BranchFlip{};
}

std::vector<TraceEvent> drain_events()
{
    std::vector<TraceEvent> out;
    out.swap(g_events);
    g_truncated = false;
    return out;
}

bool truncated()
{
    return g_truncated;
}

} // namespace lure::vm::instrumentation

// ---------------------------------------------------------------------------
// C linkage interface consumed by the patched VM
// ---------------------------------------------------------------------------

extern "C" {

int lure_tracing_active(void)
{
    return int(lure::vm::instrumentation::g_enabled);
}

void lure_trace_set_enabled(int enabled)
{
    lure::vm::instrumentation::g_enabled = enabled != 0;
    if (!enabled)
    {
        lure::vm::instrumentation::g_truncated = false;
        // The run is over and its lua_State may already be closed, so a pending
        // instruction restore is dropped rather than written back.
        lure::vm::instrumentation::drop_pending_flip();
    }
}

void lure_trace_set_max_events(unsigned max_events)
{
    lure::vm::instrumentation::g_max_events = max_events > 0 ? max_events : 1;
}

void lure_trace_register_native(const char* name, const void* fn)
{
    if (fn && name)
        lure::vm::instrumentation::g_whitelist[fn] = name;
}

void lure_trace_reset(void)
{
    lure::vm::instrumentation::g_events.clear();
    lure::vm::instrumentation::g_whitelist.clear();
    lure::vm::instrumentation::g_truncated = false;
    lure::vm::instrumentation::g_last_call_index = 0;
    lure::vm::instrumentation::reset_frame_tracking();
    lure::vm::instrumentation::drop_pending_flip();
    lure::vm::instrumentation::g_flip = lure::vm::instrumentation::BranchFlip{};
}

int lure_trace_arm_branch_flip(unsigned frame_id, unsigned pc_index, unsigned hit_index)
{
    using namespace lure::vm::instrumentation;
    // Whether the target is flippable at all depends on its opcode, which is
    // only known once the dispatch is reached; arming always succeeds here and
    // a non-flippable target simply never fires (reported by
    // lure_trace_branch_flip_fired), so the caller learns it without guessing.
    g_flip = BranchFlip{};
    g_flip.armed = true;
    g_flip.frame_id = frame_id;
    g_flip.pc_index = pc_index;
    g_flip.hit_index = hit_index;
    return 1;
}

int lure_trace_branch_flip_fired(void)
{
    return int(lure::vm::instrumentation::g_flip.fired);
}

void lure_trace_mark_output_written(void)
{
    // Runs at most once per call, synchronously inside the callee that wrote
    // output (nothing else dispatches in between), so the recorded call event
    // is exactly the one that produced the output.
    if (lure::vm::instrumentation::g_last_call_index <
        lure::vm::instrumentation::g_events.size())
        lure::vm::instrumentation::g_events[lure::vm::instrumentation::g_last_call_index]
            .printed_output = true;
}

} // extern "C"

// ---------------------------------------------------------------------------
// dispatch hook implementation
// ---------------------------------------------------------------------------

namespace lure::vm::instrumentation {
namespace {

using lure::LuaValueSnapshot;
using lure::ValueType;
using lure::TraceEvent;

const char* base_opcode_name(unsigned op)
{
    switch (static_cast<LuauOpcode>(op))
    {
#define LURE_OP(x) \
    case x: \
        return #x;
        LURE_OP(LOP_NOP) LURE_OP(LOP_BREAK) LURE_OP(LOP_LOADNIL) LURE_OP(LOP_LOADB) LURE_OP(LOP_LOADN) LURE_OP(LOP_LOADK)
        LURE_OP(LOP_MOVE) LURE_OP(LOP_GETGLOBAL) LURE_OP(LOP_SETGLOBAL) LURE_OP(LOP_GETUPVAL) LURE_OP(LOP_SETUPVAL)
        LURE_OP(LOP_CLOSEUPVALS) LURE_OP(LOP_GETIMPORT) LURE_OP(LOP_GETTABLE) LURE_OP(LOP_SETTABLE)
        LURE_OP(LOP_GETTABLEKS) LURE_OP(LOP_SETTABLEKS) LURE_OP(LOP_GETTABLEN) LURE_OP(LOP_SETTABLEN)
        LURE_OP(LOP_NEWCLOSURE) LURE_OP(LOP_NAMECALL) LURE_OP(LOP_CALL) LURE_OP(LOP_RETURN) LURE_OP(LOP_JUMP)
        LURE_OP(LOP_JUMPBACK) LURE_OP(LOP_JUMPIF) LURE_OP(LOP_JUMPIFNOT) LURE_OP(LOP_JUMPIFEQ) LURE_OP(LOP_JUMPIFLE)
        LURE_OP(LOP_JUMPIFLT) LURE_OP(LOP_JUMPIFNOTEQ) LURE_OP(LOP_JUMPIFNOTLE) LURE_OP(LOP_JUMPIFNOTLT)
        LURE_OP(LOP_ADD) LURE_OP(LOP_SUB) LURE_OP(LOP_MUL) LURE_OP(LOP_DIV) LURE_OP(LOP_MOD) LURE_OP(LOP_POW)
        LURE_OP(LOP_ADDK) LURE_OP(LOP_SUBK) LURE_OP(LOP_MULK) LURE_OP(LOP_DIVK) LURE_OP(LOP_MODK) LURE_OP(LOP_POWK)
        LURE_OP(LOP_AND) LURE_OP(LOP_OR) LURE_OP(LOP_ANDK) LURE_OP(LOP_ORK) LURE_OP(LOP_CONCAT) LURE_OP(LOP_NOT)
        LURE_OP(LOP_MINUS) LURE_OP(LOP_LENGTH) LURE_OP(LOP_NEWTABLE) LURE_OP(LOP_DUPTABLE) LURE_OP(LOP_SETLIST)
        LURE_OP(LOP_FORNPREP) LURE_OP(LOP_FORNLOOP) LURE_OP(LOP_FORGLOOP) LURE_OP(LOP_FORGPREP_INEXT)
        LURE_OP(LOP_FASTCALL3) LURE_OP(LOP_FORGPREP_NEXT) LURE_OP(LOP_NATIVECALL) LURE_OP(LOP_GETVARARGS)
        LURE_OP(LOP_DUPCLOSURE) LURE_OP(LOP_PREPVARARGS) LURE_OP(LOP_LOADKX) LURE_OP(LOP_JUMPX)
        LURE_OP(LOP_FASTCALL) LURE_OP(LOP_COVERAGE) LURE_OP(LOP_CAPTURE) LURE_OP(LOP_SUBRK) LURE_OP(LOP_DIVRK)
        LURE_OP(LOP_FASTCALL1) LURE_OP(LOP_FASTCALL2) LURE_OP(LOP_FASTCALL2K) LURE_OP(LOP_FORGPREP)
        LURE_OP(LOP_JUMPXEQKNIL) LURE_OP(LOP_JUMPXEQKB) LURE_OP(LOP_JUMPXEQKN) LURE_OP(LOP_JUMPXEQKS)
        LURE_OP(LOP_IDIV) LURE_OP(LOP_IDIVK) LURE_OP(LOP_GETUDATAKS) LURE_OP(LOP_SETUDATAKS)
        LURE_OP(LOP_NAMECALLUDATA) LURE_OP(LOP_NEWCLASSMEMBER) LURE_OP(LOP_CALLFB)
#undef LURE_OP
    default:
        return "LOP_UNKNOWN";
    }
}

const char* opcode_name_impl(unsigned op)
{
    const char* n = base_opcode_name(op);
    return (std::strncmp(n, "LOP_", 4) == 0) ? n + 4 : n;
}

bool is_call_family(unsigned op)
{
    switch (static_cast<LuauOpcode>(op))
    {
    case LOP_CALL:
    case LOP_NATIVECALL:
    case LOP_FASTCALL:
    case LOP_FASTCALL1:
    case LOP_FASTCALL2:
    case LOP_FASTCALL2K:
    case LOP_FASTCALL3:
        return true;
    default:
        return false;
    }
}

bool is_table_family(unsigned op)
{
    switch (static_cast<LuauOpcode>(op))
    {
    case LOP_GETTABLE:
    case LOP_SETTABLE:
    case LOP_GETTABLEKS:
    case LOP_SETTABLEKS:
    case LOP_GETTABLEN:
    case LOP_SETTABLEN:
        return true;
    default:
        return false;
    }
}

std::string ptr_text(const void* p)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%p", p);
    return buf;
}

// Converts a runtime value to its snapshot. Split out of snapshot() so a value
// that legitimately lives outside the Lua stack (a proto constant) can be
// converted without tripping the untrusted-pointer guard.
LuaValueSnapshot snapshot_value(const TValue* v)
{
    LuaValueSnapshot s;
    switch (ttype(v))
    {
    case LUA_TNIL:
        s.type = ValueType::Nil;
        s.text = "nil";
        break;
    case LUA_TBOOLEAN:
        s.type = ValueType::Bool;
        s.text = bvalue(v) ? "true" : "false";
        break;
    case LUA_TNUMBER:
        s.type = ValueType::Number;
        s.nvalue = nvalue(v);
        s.text = lure::lua_number_text(s.nvalue);
        break;
    case LUA_TINTEGER:
        s.type = ValueType::Number;
        s.nvalue = double(lvalue(v));
        s.text = lure::lua_number_text(s.nvalue);
        break;
    case LUA_TSTRING:
    {
        s.type = ValueType::String;
        const TString* ts = tsvalue(v);
        size_t len = ts->len < 128 ? ts->len : 128;
        s.text.assign(getstr(ts), len);
        if (ts->len > 128)
            s.text += "...";
        break;
    }
    case LUA_TTABLE:
    {
        s.type = ValueType::Table;
        s.text = "table: " + ptr_text(hvalue(v));
        break;
    }
    case LUA_TFUNCTION:
    {
        Closure* c = clvalue(v);
        if (c->isC)
        {
            s.type = ValueType::Native;
            auto it = g_whitelist.find(reinterpret_cast<const void*>(c->c.f));
            if (it != g_whitelist.end() && !it->second.empty())
                s.text = it->second;
            else
            {
                s.unres_reason = "unresolved native call (fn ptr " + ptr_text(reinterpret_cast<const void*>(c->c.f)) +
                                 ", no stdlib match)";
                s.text = "native: " + ptr_text(reinterpret_cast<const void*>(c->c.f));
            }
        }
        else
        {
            s.type = ValueType::Function;
            s.text = "function: " + ptr_text(c->l.p);
        }
        break;
    }
    default:
    {
        s.type = ValueType::Unknown;
        s.unres_reason = "unsupported runtime value type (tt=" + std::to_string(int(ttype(v))) + ")";
        s.text = "other";
        break;
    }
    }
    return s;
}

LuaValueSnapshot snapshot(lua_State* L, const TValue* v)
{
    LuaValueSnapshot s;
    if (!v || v < L->stack || v >= L->ci->top)
    {
        s.type = ValueType::Unknown;
        s.unres_reason = "value slot beyond current frame (untrusted access skipped)";
        return s;
    }
    return snapshot_value(v);
}

// Same conversion for a value that does not live on the stack, so the
// stack-range guard above does not apply: a slot of the proto's constant table.
// Used by the opcodes whose key or operand is a constant index (the *KS family)
// rather than a register.
LuaValueSnapshot snapshot_constant(const Proto* p, int kidx)
{
    LuaValueSnapshot s;
    if (!p || kidx < 0 || size_t(kidx) >= size_t(p->sizek))
    {
        s.type = ValueType::Unknown;
        s.unres_reason = "constant index " + std::to_string(kidx) + " out of range";
        return s;
    }
    return snapshot_value(&p->k[kidx]);
}

// operand display name: locvar name when statically bound, else reg_<n>
std::string reg_name(lua_State* L, const Proto* p, int pc_index, uint32_t reg)
{
    for (int i = p->sizelocvars - 1; i >= 0; --i)
    {
        const LocVar& lv = p->locvars[i];
        if (lv.reg == reg && lv.startpc <= pc_index && pc_index < lv.endpc)
        {
            if (lv.varname && lv.varname->len > 0)
                return std::string(getstr(lv.varname), lv.varname->len);
        }
    }
    return "reg_" + std::to_string(reg);
}

// static register name: the locvar bound to the register anywhere in the
// function (ignores liveness at pc; used for display only, e.g. the loop
// variable of a FORNPREP whose locvar scope opens just after it)
std::string reg_static_name(const Proto* p, uint32_t reg)
{
    for (int i = p->sizelocvars - 1; i >= 0; --i)
    {
        const LocVar& lv = p->locvars[i];
        if (static_cast<uint32_t>(lv.reg) == reg)
        {
            if (lv.varname && lv.varname->len > 0)
                return std::string(getstr(lv.varname), lv.varname->len);
            break;
        }
    }
    return "reg_" + std::to_string(reg);
}

std::string string_literal(const std::string& s)
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
            if (static_cast<unsigned char>(ch) < 0x20)
            {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\%d", static_cast<int>(ch));
                out += buf;
            }
            else
                out += ch;
        }
    }
    out += "\"";
    return out;
}

bool is_lua_keyword(const std::string& s)
{
    static const char* kws[] = {"and",     "break", "do",   "else", "elseif", "end",   "false",
                                "for",     "function", "if", "in",  "local", "nil",   "not",
                                "or",      "repeat", "return", "then", "true", "until",
                                "while"};
    for (const char* kw : kws)
        if (s == kw)
            return true;
    return false;
}

// Lua literal of a constant-table slot
std::string k_literal(const Proto* p, int kidx)
{
    if (!p || kidx < 0 || static_cast<size_t>(kidx) >= p->sizek)
        return "?" + std::to_string(kidx) + "?";
    const TValue* v = &p->k[kidx];
    switch (ttype(v))
    {
    case LUA_TNIL:
        return "nil";
    case LUA_TBOOLEAN:
        return bvalue(v) ? "true" : "false";
    case LUA_TNUMBER:
        return lure::lua_number_text(nvalue(v));
    case LUA_TINTEGER:
        return lure::lua_number_text(double(lvalue(v)));
    case LUA_TSTRING:
    {
        const TString* ts = tsvalue(v);
        size_t len = ts->len;
        std::string s(getstr(ts), len > 256 ? 256 : len);
        if (len > 256)
            s += "...";
        return string_literal(s);
    }
    case LUA_TFUNCTION:
        return "function";
    case LUA_TTABLE:
        return "{}";
    default:
        return "?k" + std::to_string(kidx) + "?";
    }
}

// field access text: `.name` for identifier keys, else `[ "lit" ]`
std::string key_field_text(const Proto* p, int kidx)
{
    if (kidx < 0 || static_cast<size_t>(kidx) >= p->sizek)
        return "[?]";
    const TValue* v = &p->k[kidx];
    if (ttype(v) != LUA_TSTRING)
        return "[" + k_literal(p, kidx) + "]";
    const TString* ts = tsvalue(v);
    std::string s(getstr(ts), ts->len > 256 ? 256 : ts->len);
    if (ts->len > 256)
        s += "...";
    if (!s.empty() && (std::isalpha(static_cast<unsigned char>(s[0])) || s[0] == '_') &&
        std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isalnum(c) || c == '_'; }) &&
        !is_lua_keyword(s))
        return "." + s;
    return "[" + string_literal(s) + "]";
}

const TValue* reg_ptr(lua_State* L, uint32_t reg)
{
    StkId base = L->ci->base;
    if (base + reg < L->ci->top)
        return &base[reg];
    return nullptr;
}

// literal text of an observed value: nil/bool/number as-is, strings quoted
// (capped), whitelisted natives by name (e.g. "print", "string.char").
// Anything else (tables, closures, unknown natives) yields empty: the caller
// falls back to the register name.
std::string value_text(const LuaValueSnapshot& s, size_t cap = 40)
{
    switch (s.type)
    {
    case ValueType::Nil:
    case ValueType::Bool:
    case ValueType::Number:
        return s.text;
    case ValueType::String:
    {
        std::string t = s.text;
        if (t.size() > cap)
        {
            t = t.substr(0, cap - 3);
            t += "...";
        }
        return string_literal(t);
    }
    case ValueType::Native:
        if (!s.text.empty() && s.unres_reason.empty())
            return s.text;
        break;
    default:
        break;
    }
    return std::string();
}

// operand display text: the value the register holds right now (observed at
// this very instruction), else the static register name. Primitive values in
// string-decoder chains therefore render as literals without any decoder
// knowledge: the hook runs after the value was computed.
std::string operand_text(lua_State* L, const Proto* p, int pc_index, uint32_t reg)
{
    const TValue* v = reg_ptr(L, reg);
    if (v)
    {
        std::string lit = value_text(snapshot(L, v));
        if (!lit.empty())
            return lit;
    }
    return reg_name(L, p, pc_index, reg);
}

// upvalue display text: the captured value when readable (a captured global
// renders by its native name, e.g. "print"), else "upval_[n]".
std::string upval_text(lua_State* L, uint32_t idx)
{
    const TValue* f = &L->ci->func[0];
    if (ttisfunction(f) && !clvalue(f)->isC && idx < clvalue(f)->nupvalues)
    {
        std::string lit = value_text(snapshot(L, &clvalue(f)->l.uprefs[idx]));
        if (!lit.empty())
            return lit;
    }
    return "upval_[" + std::to_string(idx) + "]";
}

int32_t jump_offset(uint32_t insn, unsigned op)
{
    if (static_cast<LuauOpcode>(op) == LOP_JUMPX)
        return LUAU_INSN_E(insn);
    return LUAU_INSN_D(insn);
}

bool is_falsy(const TValue* v)
{
    return v == nullptr || ttisnil(v) || (ttisboolean(v) && !bvalue(v));
}

double num_of(const TValue* v)
{
    return ttisinteger(v) ? double(lvalue(v)) : nvalue(v);
}

bool is_num_tt(int ty)
{
    return ty == LUA_TNUMBER || ty == LUA_TINTEGER;
}

struct BranchInfo
{
    bool decidable = false;
    bool taken = false;
    std::string dsl;
    std::string cond_text;
};

// Returns a branch verdict only when it can be decided statically from
// primitive operand values (never invokes metamethods). Loops and
// metamethod-dependent conditions are not marked as branches at all: their
// loop structure is recovered from the repeated-pc pattern in the trace.
BranchInfo decode_branch(lua_State* L, uint32_t insn, unsigned op, const Proto* p, int pc_index, uint32_t aux)
{
    BranchInfo bi;
    uint32_t A = LUAU_INSN_A(insn);
    const TValue* ra = reg_ptr(L, A);
    if (!ra)
        return bi;
    std::string na = operand_text(L, p, pc_index, A);

    switch (static_cast<LuauOpcode>(op))
    {
    case LOP_JUMP:
    case LOP_JUMPBACK:
    case LOP_JUMPX:
        bi.decidable = true;
        bi.taken = true;
        bi.cond_text = "true";
        return bi;
    case LOP_JUMPIF:
    case LOP_JUMPIFNOT:
    {
        bool truthy = !is_falsy(ra);
        bi.decidable = true;
        bi.taken = (static_cast<LuauOpcode>(op) == LOP_JUMPIF) ? truthy : !truthy;
        if (truthy)
            bi.dsl = na;
        else
            bi.dsl = "not " + na;
        bi.cond_text = bi.dsl;
        return bi;
    }
    case LOP_JUMPIFEQ:
    case LOP_JUMPIFNOTEQ:
    case LOP_JUMPIFLE:
    case LOP_JUMPIFLT:
    case LOP_JUMPIFNOTLE:
    case LOP_JUMPIFNOTLT:
    {
        const TValue* rb = reg_ptr(L, LUAU_INSN_AUX_A(aux));
        if (!rb)
            return bi;
        auto ty = ttype(ra);
        if (ty != ttype(rb))
            return bi; // cross-type comparisons may hit metamethods
        std::string nb = operand_text(L, p, pc_index, LUAU_INSN_AUX_A(aux));

        bool eq = false;
        switch (ty)
        {
        case LUA_TNIL:
            eq = true;
            break;
        case LUA_TBOOLEAN:
            eq = bvalue(ra) == bvalue(rb);
            break;
        case LUA_TNUMBER:
            eq = nvalue(ra) == nvalue(rb);
            break;
        case LUA_TINTEGER:
            eq = lvalue(ra) == lvalue(rb);
            break;
        case LUA_TSTRING:
        {
            const TString* a = tsvalue(ra);
            const TString* b = tsvalue(rb);
            eq = a->len == b->len && std::memcmp(getstr(a), getstr(b), a->len) == 0;
            break;
        }
        default:
            return bi; // metamethod territory -> not decidable
        }

        bool is_num = is_num_tt(ty);
        double x = num_of(ra), y = num_of(rb);

        switch (static_cast<LuauOpcode>(op))
        {
        case LOP_JUMPIFEQ:
            bi.decidable = true;
            bi.taken = eq;
            bi.dsl = na + "==" + nb;
            break;
        case LOP_JUMPIFNOTEQ:
            bi.decidable = true;
            bi.taken = !eq;
            bi.dsl = na + "~=" + nb;
            break;
        case LOP_JUMPIFLE:
            if (!is_num)
                return bi;
            bi.decidable = true;
            bi.taken = x <= y;
            bi.dsl = na + "<=" + nb;
            break;
        case LOP_JUMPIFLT:
            if (!is_num)
                return bi;
            bi.decidable = true;
            bi.taken = x < y;
            bi.dsl = na + "<" + nb;
            break;
        case LOP_JUMPIFNOTLE:
            if (!is_num)
                return bi;
            bi.decidable = true;
            bi.taken = !(x <= y);
            bi.dsl = na + ">" + nb;
            break;
        case LOP_JUMPIFNOTLT:
            if (!is_num)
                return bi;
            bi.decidable = true;
            bi.taken = !(x < y);
            bi.dsl = na + ">=" + nb;
            break;
        default:
            return bi;
        }
        bi.cond_text = bi.dsl;
        return bi;
    }
    case LOP_JUMPXEQKNIL:
    case LOP_JUMPXEQKB:
    case LOP_JUMPXEQKN:
    {
        bool is_not = LUAU_INSN_AUX_NOT(aux) != 0;
        bool equal = false;
        switch (static_cast<LuauOpcode>(op))
        {
        case LOP_JUMPXEQKNIL:
            equal = ttisnil(ra);
            break;
        case LOP_JUMPXEQKB:
            equal = ttisboolean(ra);
            break;
        case LOP_JUMPXEQKN:
            equal = is_num_tt(ttype(ra));
            break;
        default:
            return bi;
        }
        bi.decidable = true;
        bi.taken = is_not ? !equal : equal;
        bi.dsl = is_not ? ("not " + na) : na;
        bi.cond_text = bi.dsl;
        return bi;
    }
    case LOP_JUMPXEQKS:
    {
        // aux: bits 0-23 constant index, bit 31 NOT flag (BytecodeBuilder)
        int ki = int(aux & 0xffffff);
        bool is_not = LUAU_INSN_AUX_NOT(aux) != 0;
        if (ki < 0 || static_cast<size_t>(ki) >= p->sizek)
            return bi;
        const TValue* kv = &p->k[ki];
        bool equal = false;
        if (ttisstring(ra) && ttype(kv) == LUA_TSTRING)
        {
            const TString* a = tsvalue(ra);
            const TString* b = tsvalue(kv);
            equal = a->len == b->len && std::memcmp(getstr(a), getstr(b), a->len) == 0;
        }
        else if (ttype(kv) == LUA_TNIL && ttisnil(ra))
            equal = true;
        bi.decidable = true;
        bi.taken = is_not ? !equal : equal;
        bi.dsl = na + (is_not ? " ~= " : " == ") + k_literal(p, ki);
        bi.cond_text = bi.dsl;
        return bi;
    }
    case LOP_FORNPREP:
    case LOP_FORNLOOP:
    {
        const TValue* lim = reg_ptr(L, A);
        const TValue* stp = reg_ptr(L, A + 1);
        const TValue* idx = reg_ptr(L, A + 2);
        if (!lim || !stp || !idx)
            return bi;
        if (!(is_num_tt(ttype(lim)) && is_num_tt(ttype(stp)) && is_num_tt(ttype(idx))))
            return bi;
        double limit = num_of(lim);
        double step = num_of(stp);
        double index = num_of(idx);
        bi.decidable = true;
        // FORNLOOP increments *then* tests, so the value that decides whether it
        // jumps back is index+step, not the index still in the register. Reporting
        // the pre-increment test made the last iteration look like a continue and
        // the loop's exit was never visible in the trace.
        double tested = (static_cast<LuauOpcode>(op) == LOP_FORNLOOP) ? index + step : index;
        bi.taken = (step > 0 ? tested <= limit : limit <= tested);
        std::string nlim = operand_text(L, p, pc_index, A);
        std::string nidx = reg_static_name(p, A + 2);
        bi.dsl = (step > 0 ? nidx + "<=" + nlim : nlim + "<=" + nidx);
        bi.cond_text = bi.dsl;
        return bi;
    }
    default:
        return bi;
    }
}

// --------------------------------------------------------------------------
// Lua-ish rendering of a single instruction, populated into ev.text. This is
// register-level: named registers (locvars) read as their source names,
// anonymous slots as reg_<n>, and literal immediates come straight from the
// bytecode (constants table) or from observed register values when relevant.
// Never fails: unrecognized opcodes fall back to the mnemonic.
// --------------------------------------------------------------------------
std::string render_text(lua_State* L, const Proto* p, int pc_index, uint32_t insn, unsigned op,
    uint32_t aux, const TraceEvent& ev)
{
    uint32_t A = LUAU_INSN_A(insn);
    uint32_t B = LUAU_INSN_B(insn);
    uint32_t C = LUAU_INSN_C(insn);
    int32_t D = LUAU_INSN_D(insn);

    auto R = [&](uint32_t reg) { return reg_static_name(p, reg); };
    auto RV = [&](uint32_t reg) { return operand_text(L, p, pc_index, reg); };

    switch (static_cast<LuauOpcode>(op))
    {
    case LOP_LOADN:
        return R(A) + " = " + std::to_string(D);
    case LOP_LOADK:
        return R(A) + " = " + k_literal(p, D);
    case LOP_LOADKX:
        return R(A) + " = " + k_literal(p, int(aux));
    case LOP_LOADB:
        return R(A) + " = " + (B != 0 ? "true" : "false");
    case LOP_LOADNIL:
        return R(A) + " = nil";
    case LOP_MOVE:
        return R(A) + " = " + RV(B);
    case LOP_GETUPVAL:
        return R(A) + " = " + upval_text(L, B);
    case LOP_SETUPVAL:
        return "upval_[" + std::to_string(B) + "] = " + RV(A);
    case LOP_GETGLOBAL:
        return R(A) + " = " + k_literal(p, int(aux));
    case LOP_SETGLOBAL:
        return k_literal(p, int(aux)) + " = " + RV(A);
    case LOP_GETTABLE:
        return R(A) + " = " + RV(B) + "[" + RV(C) + "]";
    case LOP_GETTABLEN:
        return R(A) + " = " + RV(B) + "[" + std::to_string(C + 1) + "]";
    case LOP_GETTABLEKS:
        return R(A) + " = " + RV(B) + key_field_text(p, int(aux));
    case LOP_SETTABLE:
        return RV(B) + "[" + RV(C) + "] = " + RV(A);
    case LOP_SETTABLEN:
        return RV(B) + "[" + std::to_string(C + 1) + "] = " + RV(A);
    case LOP_SETTABLEKS:
        return RV(B) + key_field_text(p, int(aux)) + " = " + RV(A);
    case LOP_NAMECALL:
        return "-- method call " + RV(B) + key_field_text(p, int(aux)) + " (self at " + R(A + 1) + ")";
    case LOP_GETIMPORT:
    {
        int len = int(aux >> 30);
        int i1 = int((aux >> 20) & 0x3ff);
        int i2 = int((aux >> 10) & 0x3ff);
        int i3 = int(aux & 0x3ff);
        std::string path;
        auto comp = [&](int ki)
        {
            if (ki >= 0 && static_cast<size_t>(ki) < p->sizek && ttype(&p->k[ki]) == LUA_TSTRING)
            {
                const TString* ts = tsvalue(&p->k[ki]);
                return std::string(getstr(ts), ts->len > 128 ? 128 : ts->len);
            }
            return std::string();
        };
        if (len >= 1)
            path = comp(i1);
        if (len >= 2)
            path += "." + comp(i2);
        if (len >= 3)
            path += "." + comp(i3);
        if (path.empty())
            path = "import";
        return R(A) + " = " + path;
    }
    case LOP_NEWTABLE:
    case LOP_DUPTABLE:
        return R(A) + " = {}";
    case LOP_SETLIST:
    {
        int count = int(C);
        if (count > 0)
            --count;
        return "-- fill table " + R(A) + " (batch " + std::to_string(count) + " from " + RV(B) + ")";
    }
    case LOP_DUPCLOSURE:
    case LOP_NEWCLOSURE:
        return R(A) + " = function";
    case LOP_GETVARARGS:
    {
        int n = int(B) - 1;
        std::string t;
        for (int i = 0; i < n && i < 4; ++i)
        {
            if (i)
                t += ", ";
            t += R(A + static_cast<uint32_t>(i));
        }
        if (n > 4)
            t += ", ...";
        if (t.empty())
            t = R(A);
        return "-- varargs -> " + t;
    }
    case LOP_PREPVARARGS:
    case LOP_BREAK:
        return "-- prologue/varargs";
    case LOP_ADD:
    case LOP_SUB:
    case LOP_MUL:
    case LOP_DIV:
    case LOP_MOD:
    case LOP_POW:
    case LOP_ADDK:
    case LOP_SUBK:
    case LOP_MULK:
    case LOP_DIVK:
    case LOP_MODK:
    case LOP_POWK:
    case LOP_SUBRK:
    case LOP_DIVRK:
    {
        const char* sc = "?";
        switch (static_cast<LuauOpcode>(op))
        {
        case LOP_ADD:
        case LOP_ADDK:
            sc = "+";
            break;
        case LOP_SUB:
        case LOP_SUBK:
        case LOP_SUBRK:
            sc = "-";
            break;
        case LOP_MUL:
        case LOP_MULK:
            sc = "*";
            break;
        case LOP_DIV:
        case LOP_DIVK:
        case LOP_DIVRK:
            sc = "/";
            break;
        case LOP_MOD:
        case LOP_MODK:
            sc = "%";
            break;
        case LOP_POW:
        case LOP_POWK:
            sc = "^";
            break;
        default:
            break;
        }
        bool usek = (op == LOP_ADDK || op == LOP_SUBK || op == LOP_MULK || op == LOP_DIVK || op == LOP_MODK ||
                     op == LOP_POWK);
        if (op == LOP_SUBRK || op == LOP_DIVRK)
            return R(A) + " = " + k_literal(p, int(C)) + " " + sc + " " + RV(B);
        std::string rhs = usek ? k_literal(p, int(C)) : RV(C);
        return R(A) + " = " + RV(B) + " " + sc + " " + rhs;
    }
    case LOP_AND:
    case LOP_ANDK:
    case LOP_OR:
    case LOP_ORK:
    {
        bool usek = (op == LOP_ANDK || op == LOP_ORK);
        return R(A) + " = " + RV(B) + (op == LOP_AND || op == LOP_ANDK ? " and " : " or ") +
               (usek ? k_literal(p, int(C)) : RV(C));
    }
    case LOP_CONCAT:
        return R(A) + " = " + RV(B) + " .. ... .. " + RV(C);
    case LOP_NOT:
        return R(A) + " = not " + RV(B);
    case LOP_MINUS:
        return R(A) + " = -" + RV(B);
    case LOP_LENGTH:
        return R(A) + " = #" + RV(B);
    case LOP_FORNPREP:
        return "-- for init " + R(A + 2) + " = " + RV(A + 2) + ", " + RV(A) + ", " + RV(A + 1);
    case LOP_FORNLOOP:
    case LOP_FORGLOOP:
        return "-- loop increment/check";
    case LOP_FORGPREP_NEXT:
    case LOP_FORGPREP_INEXT:
        return "-- generic-for init";
    case LOP_CALL:
    {
        if (ev.call_info)
        {
            std::string fn = ev.call_info->fn.type == ValueType::Native && !ev.call_info->fn.text.empty()
                                 ? ev.call_info->fn.text
                                 : R(A);
            std::string s = fn + "(";
            for (size_t i = 0; i < ev.call_info->args.size(); ++i)
            {
                const LuaValueSnapshot& a = ev.call_info->args[i];
                if (a.type == ValueType::Nil)
                    break; // trailing nils are VM padding, not real arguments
                if (i)
                    s += ", ";
                switch (a.type)
                {
                case ValueType::String:
                    s += string_literal(a.text);
                    break;
                case ValueType::Number:
                case ValueType::Bool:
                    s += a.text;
                    break;
                case ValueType::Table:
                    s += "{}"; // table identity is irrelevant for readability
                    break;
                case ValueType::Function:
                    s += "function";
                    break;
                case ValueType::Native:
                    s += a.text.empty() ? "?" : a.text;
                    break;
                default:
                    s += a.unres_reason.empty() ? a.text : "?";
                    break;
                }
            }
            s += ")";
            if (ev.call_info->nresults > 0)
                return R(A) + " = " + s;
            return s;
        }
        return R(A) + "(...)";
    }
    case LOP_RETURN:
    {
        int b = int(B) - 1;
        if (b < 0)
        {
            std::string t = "return ...";
            if (!ev.call_info)
                return t;
            return t;
        }
        if (b == 0)
            return "return";
        std::string s = "return " + R(A);
        for (int i = 1; i < b && i < 4; ++i)
            s += ", " + R(A + static_cast<uint32_t>(i));
        if (b > 4)
            s += ", ...";
        return s;
    }
    case LOP_JUMP:
    case LOP_JUMPBACK:
    case LOP_JUMPX:
    case LOP_JUMPIF:
    case LOP_JUMPIFNOT:
    case LOP_JUMPIFEQ:
    case LOP_JUMPIFNOTEQ:
    case LOP_JUMPIFLE:
    case LOP_JUMPIFLT:
    case LOP_JUMPIFNOTLE:
    case LOP_JUMPIFNOTLT:
    case LOP_JUMPXEQKNIL:
    case LOP_JUMPXEQKB:
    case LOP_JUMPXEQKN:

    case LOP_JUMPXEQKS:
    case LOP_COVERAGE:
    case LOP_FASTCALL:
    case LOP_FASTCALL1:
    case LOP_FASTCALL2:
        return "";
    default:
        return opcode_name_impl(op);
    }
}

} // namespace
} // namespace lure::vm::instrumentation

extern "C" void lure_trace_dispatch(lua_State* L, const lure_Instruction* pc)
{
    using namespace lure::vm::instrumentation;

    if (!g_enabled)
        return;

    // A branch inverted on the previous dispatch has now executed: put the
    // instruction word back before anything else can observe it. Unconditional
    // and runs even when recording is truncated, so the bytecode is never left
    // modified.
    if (g_pending.addr || g_pending.aux_addr)
        restore_pending_flip();

    try
    {
        if (g_events.size() >= g_max_events)
        {
            if (!g_truncated)
            {
                g_truncated = true;
                TraceEvent ev;
                ev.tag = "TRUNCATED";
                ev.status = lure::ResolutionStatus::Unresolved;
                ev.notfound_reason = "trace truncated at " + std::to_string(g_max_events) +
                                     " events (--max-events); remaining execution not recorded";
                g_events.push_back(std::move(ev));
            }
            return;
        }

        if (!isLua(L->ci))
            return;

        Closure* cl = clvalue(L->ci->func);
        Proto* p = cl->l.p;
        const Instruction* code = p->code;
        int idx = int(pc - code);
        if (idx < 0 || idx >= p->sizecode)
            return;

        uint32_t insn = *pc;
        unsigned op = LUAU_INSN_OP(insn);
        uint32_t A = LUAU_INSN_A(insn);
        uint32_t B = LUAU_INSN_B(insn);
        uint32_t C = LUAU_INSN_C(insn);

        // VM plumbing that carries no trace information: never branches and
        // renders as nothing. The real call shows up on the adjacent CALL
        // (call_info is captured there), so skipping these loses no semantics
        // and removes the bare-mnemonic noise lines from the output.
        switch (static_cast<LuauOpcode>(op))
        {
        case LOP_FASTCALL:
        case LOP_FASTCALL1:
        case LOP_FASTCALL2:
        case LOP_FASTCALL2K:
        case LOP_FASTCALL3:
        case LOP_COVERAGE:
            return;
        default:
            break;
        }

        TraceEvent ev;
        ev.pc = uint64_t(idx);
        {
            auto pit = g_proto_ids.find(static_cast<const void*>(p));
            if (pit == g_proto_ids.end())
                pit = g_proto_ids.emplace(static_cast<const void*>(p), g_next_proto_id++).first;
            ev.proto_id = pit->second;
        }
        ev.opcode = uint8_t(op);
        ev.insn = uint32_t(insn);
        ev.call_depth = uint32_t(L->ci - L->base_ci);
        ev.tag = opcode_name(op);

        ev.frame_id = g_frame_stack.back();
        while (g_frame_stack.size() <= ev.call_depth)
            g_frame_stack.push_back(g_next_serial++);
        while (g_frame_stack.size() > ev.call_depth + 1)
            g_frame_stack.pop_back();
        ev.frame_id = g_frame_stack.back();

        // Armed branch inversion: this is the dispatch the caller named, so
        // rewrite the conditional to its complement. The original words are
        // remembered and restored at the top of the next dispatch, i.e. as soon
        // as the inverted instruction has executed.
        if (g_flip.armed && !g_flip.fired && ev.frame_id == g_flip.frame_id &&
            uint32_t(idx) == g_flip.pc_index)
        {
            if (g_flip.hits++ == g_flip.hit_index)
            {
                uint32_t* word = const_cast<uint32_t*>(pc);
                int comp = complementary_branch_op(op);
                if (comp >= 0)
                {
                    g_pending.addr = word;
                    g_pending.insn = insn;
                    *word = (insn & ~0xffu) | uint32_t(comp);
                    g_flip.fired = true;
                    // Report what actually executes, not what was compiled: the
                    // rest of this hook (branch decoding, rendering) must see
                    // the inverted instruction.
                    insn = *word;
                    op = uint32_t(comp);
                    ev.insn = insn;
                    ev.opcode = uint8_t(op);
                    ev.tag = opcode_name(op);
                }
                else if (branch_sense_in_aux(op) && idx + 1 < p->sizecode)
                {
                    uint32_t* auxw = word + 1;
                    g_pending.aux_addr = auxw;
                    g_pending.aux = *auxw;
                    *auxw = *auxw ^ 0x80000000u;
                    g_flip.fired = true;
                    // aux is re-read below, so the inverted sense is picked up.
                }
                // No complement (unconditional jump, loop opcode): nothing is
                // rewritten and `fired` stays false, which the caller reads as
                // "this branch cannot be probed".
            }
        }

        // best-effort source line
        if (p->lineinfo && p->abslineinfo && idx < p->sizecode)
            ev.line = uint32_t(luaG_getline(p, idx));

        // locals snapshot: active locvars
        for (int i = 0; i < p->sizelocvars; ++i)
        {
            const LocVar& lv = p->locvars[i];
            if (lv.startpc <= idx && idx < lv.endpc)
            {
                LuaValueSnapshot s = snapshot(L, reg_ptr(L, lv.reg));
                ev.locals.push_back(std::move(s));
            }
        }

        // stack snapshot: small register window
        for (uint32_t r = 0; r < A + 4 && r < 12; ++r)
        {
            const TValue* v = reg_ptr(L, r);
            if (!v)
                break;
            ev.stack.push_back(snapshot(L, v));
        }

        if (is_call_family(op))
        {
            lure::CallInfo ci;
            const TValue* fn = reg_ptr(L, A);
            ci.fn = snapshot(L, fn);
            if (ci.fn.type == ValueType::Function || ci.fn.type == ValueType::Native)
            {
                // The real argument range is fixed by the opcode (LOP_CALL:
                // B-1 args at base+A+1 .. base+A+B-1). L->top may sit past it
                // (e.g. vararg frames), which used to drag live-but-unrelated
                // registers into the recorded argument list. B==0 means
                // "args extend to top" (multi-return adjustment) — fall back
                // to the top-bounded capture for that case only.
                const TValue* a0 = L->ci->base + A + 1;
                const TValue* argtop = L->top;
                if (op == static_cast<unsigned>(LOP_CALL) && B > 0)
                {
                    const TValue* op_end = a0 + (B - 1);
                    argtop = op_end <= L->ci->top ? op_end : L->ci->top;
                }
                unsigned maxargs = 8;
                for (const TValue* a = a0; a < argtop && a < L->ci->top && maxargs > 0; ++a, --maxargs)
                    ci.args.push_back(snapshot(L, a));
                ci.nresults = (op == static_cast<unsigned>(LOP_CALL)) ? (C != 0 ? C - 1 : 0) : 1;
                bool unres = (ci.fn.type == ValueType::Native && !ci.fn.unres_reason.empty());
                std::string unres_reason_kept = ci.fn.unres_reason;
                if (!unres && ci.fn.type == ValueType::Native && !ci.fn.text.empty())
                    ci.native_name = ci.fn.text;
                ev.call_info = std::move(ci);
                if (unres)
                {
                    ev.status = lure::ResolutionStatus::Unresolved;
                    ev.notfound_reason = unres_reason_kept;
                }
            }
            else
            {
                // diagnostic (LURE_DEBUG_NIL=1): a call whose callee is not a
                // function (usually nil) is the typical reason an obfuscated
                // module aborts on a missing global; dump the constant pools
                // in scope. Off by default: obfuscators probe nil inside
                // pcall so this fires on every iteration otherwise.
                if (!g_debug_nil)
                    g_debug_nil = (std::getenv("LURE_DEBUG_NIL") != nullptr);
                if (g_debug_nil)
                {
                std::fprintf(stderr,
                    "lure: nil/non-function call at pc=%u (fn=%s); protos in scope:\n", idx,
                    ci.fn.text.c_str());
                int frame = 0;
                for (const CallInfo* cif = L->base_ci; cif <= L->ci && frame < 8; ++cif, ++frame)
                {
                    if (!ttisfunction(&cif->func[0]) || !isLua(cif))
                        continue;
                    const Proto* fp = clvalue(&cif->func[0])->l.p;
                    std::fprintf(stderr, "  frame %d (pc=%u, %u consts):\n", frame,
                        unsigned(cif->savedpc - fp->code), fp->sizek);
                    for (uint32_t k = 0; k < fp->sizek; ++k)
                    {
                        const TValue* kv = &fp->k[k];
                        const char* t = "?";
                        std::string txt;
                        if (ttisnumber(kv))
                        {
                            t = "num";
                            char buf[64];
                            std::snprintf(buf, sizeof(buf), "%.17g", nvalue(kv));
                            txt = buf;
                        }
                        else if (ttisstring(kv))
                        {
                            t = "str";
                            const TString* ts = tsvalue(kv);
                            txt.assign(getstr(ts), ts->len > 64 ? 64 : ts->len);
                        }
                        else if (ttisboolean(kv))
                        {
                            t = "bool";
                            txt = bvalue(kv) ? "true" : "false";
                        }
                        std::fprintf(stderr, "    k[%u]=%s %s\n", k, t, txt.c_str());
                    }
                }
                }
            }
        }

        uint32_t aux = (idx + 1 < p->sizecode) ? uint32_t(*(pc + 1)) : 0u;

        if (is_table_family(op))
        {
            lure::TableOpInfo ti;
            bool is_set = (op == static_cast<unsigned>(LOP_SETTABLE) || op == static_cast<unsigned>(LOP_SETTABLEKS) ||
                           op == static_cast<unsigned>(LOP_SETTABLEN));
            ti.table = snapshot(L, reg_ptr(L, B));
            // Where the key lives depends on the opcode: a register for the
            // plain form, a string constant (AUX) for the KS form, and the
            // immediate C+1 for the N form. Reading register C unconditionally
            // reported the wrong key for KS/N (C is an inline-cache slot resp.
            // the index), which silently broke field recovery on any script the
            // compiler lowered to those forms.
            switch (static_cast<LuauOpcode>(op))
            {
            case LOP_GETTABLEKS:
            case LOP_SETTABLEKS:
                ti.key = snapshot_constant(p, int(aux));
                break;
            case LOP_GETTABLEN:
            case LOP_SETTABLEN:
                ti.key = lure::value_from_number(double(C) + 1.0);
                break;
            default:
                ti.key = snapshot(L, reg_ptr(L, C));
                break;
            }
            if (is_set)
            {
                ti.value = snapshot(L, reg_ptr(L, A));
                ti.is_set = true;
            }
            ev.table_op = std::move(ti);
        }

        {
            BranchInfo bi = decode_branch(L, insn, op, p, idx, aux);
            if (bi.decidable)
            {
                ev.is_branch = true;
                ev.branch_taken = bi.taken;
                ev.cond_dsl = std::move(bi.dsl);
                ev.cond_text = std::move(bi.cond_text);
                uint32_t jt = uint32_t(idx + 1 + jump_offset(insn, op));
                ev.jump_target = jt;
                ev.other_target =
                    int32_t(bi.taken ? idx + 1 : jt); // declared side that was not executed
                // Register of the rhs operand, for the family that compares two
                // registers (the rhs index lives in the aux word).
                switch (static_cast<LuauOpcode>(op))
                {
                case LOP_JUMPIFEQ:
                case LOP_JUMPIFNOTEQ:
                case LOP_JUMPIFLE:
                case LOP_JUMPIFNOTLE:
                case LOP_JUMPIFLT:
                case LOP_JUMPIFNOTLT:
                    ev.cond_rhs_reg = int32_t(LUAU_INSN_AUX_A(aux));
                    break;
                default:
                    break;
                }
            }
        }

        ev.text = render_text(L, p, idx, insn, op, aux, ev);

        // The instruction's constant operand, when reconstruction needs the
        // operand itself rather than its rendering (see TraceEvent::k_text).
        switch (static_cast<LuauOpcode>(op))
        {
        case LOP_ADDK:
        case LOP_SUBK:
        case LOP_MULK:
        case LOP_DIVK:
        case LOP_MODK:
        case LOP_POWK:
        case LOP_IDIVK:
        case LOP_SUBRK:
        case LOP_DIVRK:
        case LOP_ANDK:
        case LOP_ORK:
            ev.k_text = k_literal(p, int(C));
            break;
        case LOP_GETGLOBAL:
        case LOP_SETGLOBAL:
        case LOP_NAMECALL:
        case LOP_NAMECALLUDATA:
            ev.k_text = k_literal(p, int(aux));
            break;
        case LOP_GETIMPORT:
        {
            // The rendered form is already the dotted path, which *is* the
            // operand; reuse it rather than decoding aux twice.
            size_t eq = ev.text.find(" = ");
            if (eq != std::string::npos)
                ev.k_text = ev.text.substr(eq + 3);
            break;
        }
        default:
            break;
        }

        // collapse "load literal into store operand slot" pairs: compilers
        // paint the value/key slot registers right before the table write, and
        // the write itself renders the observed value, so the paint line is
        // pure noise (e.g. "o = 23\nreg_4.N = 23" becomes just the store).
        // Same for the callee slot of a call: the callee name is re-rendered
        // by the call itself (native name or register name), so the preceding
        // closure-load line is redundant.
        static uint32_t s_prev_op = ~0u, s_prev_a = 0;
        if (op == static_cast<unsigned>(LOP_SETTABLE) || op == static_cast<unsigned>(LOP_SETTABLEKS) ||
            op == static_cast<unsigned>(LOP_SETTABLEN))
        {
            bool prev_is_load = s_prev_op == static_cast<unsigned>(LOP_LOADK) ||
                                s_prev_op == static_cast<unsigned>(LOP_LOADKX) ||
                                s_prev_op == static_cast<unsigned>(LOP_LOADN) ||
                                s_prev_op == static_cast<unsigned>(LOP_LOADB) ||
                                s_prev_op == static_cast<unsigned>(LOP_LOADNIL);
            if (prev_is_load && s_prev_a == A)
                g_events.pop_back();
            else if (prev_is_load && op == static_cast<unsigned>(LOP_SETTABLE) && s_prev_a == C)
                g_events.pop_back();
        }
        else if (is_call_family(op))
        {
            bool prev_is_closure_load = s_prev_op == static_cast<unsigned>(LOP_MOVE) ||
                                        s_prev_op == static_cast<unsigned>(LOP_GETGLOBAL) ||
                                        s_prev_op == static_cast<unsigned>(LOP_GETUPVAL) ||
                                        s_prev_op == static_cast<unsigned>(LOP_GETTABLE) ||
                                        s_prev_op == static_cast<unsigned>(LOP_GETTABLEKS) ||
                                        s_prev_op == static_cast<unsigned>(LOP_GETTABLEN) ||
                                        s_prev_op == static_cast<unsigned>(LOP_NEWCLOSURE) ||
                                        s_prev_op == static_cast<unsigned>(LOP_DUPCLOSURE);
            if (prev_is_closure_load && s_prev_a == A)
                g_events.pop_back();
        }
        s_prev_op = op;
        s_prev_a = A;

        // Track call events so the host's output sink can mark the call that
        // produced observable output (see lure_trace_mark_output_written).
        // Recorded after the dedup pops above, so the index is final.
        if (is_call_family(op))
            g_last_call_index = unsigned(g_events.size());

        g_events.push_back(std::move(ev));
    }
    catch (...)
    {
        // the hook must never disturb execution: on internal failure it simply
        // stops recording events for the rest of the run (fail-open).
        g_enabled = false;
    }
}

// public accessor declared in instrumentation.hpp (the anonymous namespace
// above makes opcode_name_impl internally linked; wrapping it back into the
// enclosing namespace keeps the exported name unambiguous)
namespace lure::vm::instrumentation {
const char* opcode_name(unsigned op)
{
    return opcode_name_impl(op);
}
} // namespace lure::vm::instrumentation
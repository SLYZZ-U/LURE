// vm/mock_vm_runner.cpp
// A miniature Lua interpreter used as the always-available layer 1 backend.
// It executes a restricted subset of Lua and emits the same TraceData shape as
// the instrumented Luau VM: pc values are STATIC PLAN INDEXES (analogous to
// bytecode instruction offsets), so branch jump_target/other_target values are
// static and the CFG builder applies to both backends unchanged. The mock is a
// real pc-driven interpreter over a flat plan built from the parsed AST.
//
// Resilience: unknown natives (not in the whitelisted stdlib set) produce
// poisoned values; every downstream event that consumes a poisoned value is
// marked UNRESOLVED with the originating reason, and branches over poison are
// annotated. Nothing is guessed.

#include "vm/ivm_runner.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace lure::vm {
namespace {

using lure::CallInfo;
using lure::LuaValueSnapshot;
using lure::ResolutionStatus;
using lure::TraceData;
using lure::TraceEvent;
using lure::ValueType;

struct Value
{
    enum class T
    {
        Nil,
        Bool,
        Num,
        Str,
        Table,
        Native,
        Poison
    } t = T::Nil;

    bool b = false;
    double n = 0.0;
    std::string s;
    std::vector<std::pair<Value, Value>> tbl;
    std::string native_name;
    bool whitelisted = true;
    std::string poison_reason;

    bool is_poison() const { return t == T::Poison; }
};

// ---------------------------------------------------------------------------
// lexer
// ---------------------------------------------------------------------------

struct Lexer
{
    struct Tok
    {
        enum class K
        {
            End,
            Num,
            Str,
            Ident,
            Sym
        } k = K::End;
        std::string text;
        double num = 0.0;
        int line = 1;
    };

    std::string src;
    size_t pos = 0;
    int line = 1;
    std::vector<Tok> toks;

    explicit Lexer(std::string s)
        : src(std::move(s))
    {
        tokenize();
    }

    void error(const std::string& msg)
    {
        throw std::runtime_error("mock lexer error at line " + std::to_string(line) + ": " + msg);
    }

    static bool id_start(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'; }
    static bool id_cont(char c) { return id_start(c) || (c >= '0' && c <= '9'); }
    static bool digit(char c) { return c >= '0' && c <= '9'; }

    void push_tok(Tok::K k, std::string text = "", double num = 0.0)
    {
        toks.push_back({k, std::move(text), num, line});
    }

    void tokenize()
    {
        while (pos < src.size())
        {
            char c = src[pos];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
            {
                if (c == '\n')
                    ++line;
                ++pos;
                continue;
            }
            if (c == '-' && pos + 1 < src.size() && src[pos + 1] == '-')
            {
                while (pos < src.size() && src[pos] != '\n')
                    ++pos;
                continue;
            }
            if (c == '"' || c == '\'')
            {
                char q = c;
                ++pos;
                std::string acc;
                while (pos < src.size() && src[pos] != q)
                {
                    if (src[pos] == '\\' && pos + 1 < src.size())
                    {
                        char e = src[pos + 1];
                        switch (e)
                        {
                        case 'n':
                            acc += '\n';
                            break;
                        case 't':
                            acc += '\t';
                            break;
                        case 'r':
                            acc += '\r';
                            break;
                        case '\\':
                            acc += '\\';
                            break;
                        case '"':
                            acc += '"';
                            break;
                        case '\'':
                            acc += '\'';
                            break;
                        case '0':
                            acc += '\0';
                            break;
                        default:
                            acc += e;
                            break;
                        }
                        pos += 2;
                    }
                    else
                    {
                        acc += src[pos];
                        ++pos;
                    }
                }
                if (pos >= src.size())
                    error("unterminated string");
                ++pos;
                push_tok(Tok::K::Str, std::move(acc));
                continue;
            }
            if (digit(c) || (c == '.' && pos + 1 < src.size() && digit(src[pos + 1])))
            {
                size_t start = pos;
                bool dot = false, exp = false;
                while (pos < src.size())
                {
                    char d = src[pos];
                    if (digit(d))
                        ++pos;
                    else if (d == '.' && !dot && !exp)
                    {
                        dot = true;
                        ++pos;
                    }
                    else if ((d == 'e' || d == 'E') && !exp)
                    {
                        exp = true;
                        ++pos;
                        if (pos < src.size() && (src[pos] == '+' || src[pos] == '-'))
                            ++pos;
                    }
                    else
                        break;
                }
                push_tok(Tok::K::Num, "", std::strtod(src.substr(start, pos - start).c_str(), nullptr));
                continue;
            }
            if (id_start(c))
            {
                size_t start = pos;
                while (pos < src.size() && id_cont(src[pos]))
                    ++pos;
                push_tok(Tok::K::Ident, src.substr(start, pos - start));
                continue;
            }
            static const char* syms[] = {"==", "~=", "<=", ">=", "..", "..."};
            bool matched = false;
            for (const char* s : syms)
            {
                size_t n = std::strlen(s);
                if (src.compare(pos, n, s) == 0)
                {
                    push_tok(Tok::K::Sym, s);
                    pos += n;
                    matched = true;
                    break;
                }
            }
            if (matched)
                continue;
            if (std::string("+-*/%^#=<>(){}[],.;:").find(c) != std::string::npos)
            {
                push_tok(Tok::K::Sym, std::string(1, c));
                ++pos;
                continue;
            }
            error(std::string("unexpected character '") + c + "'");
        }
        push_tok(Tok::K::End);
    }
};

// ---------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------

struct Expr;
using ExprPtr = std::unique_ptr<Expr>;

struct Expr
{
    enum class K
    {
        Lit,
        Var,
        Index,
        Unary,
        Binary,
        Call
    } k;
    Value lit;
    std::string var;
    ExprPtr a, b;
    std::string op;
    std::string call_name;
    std::vector<ExprPtr> args;
};

struct Stmt;
using StmtPtr = std::unique_ptr<Stmt>;

struct Stmt
{
    enum class K
    {
        Local,
        Assign,
        If,
        While,
        For,
        Call,
        Return,
        Jump // synthetic unconditional jump (then-block exit, loop back-edge)
    } k;

    int plan_index = -1;
    int then_t = -1; // branch targets resolved during planning
    int else_t = -1;
    int advance_slot = -1;   // 'for' head: slot of the synthetic advance statement
    int loop_head_slot = -1; // synthetic advance: slot of the owning for-loop head
    bool is_advance = false; // TRUE for the synthetic for-loop advance statement

    // assign (local x = e | x = e | t[i] = e)
    struct AssignInfo
    {
        std::string name;
        ExprPtr rhs;
        ExprPtr index; // table index expr when set (t[i] = ...)
    };
    std::vector<AssignInfo> assigns;

    ExprPtr cond;
    std::vector<StmtPtr> then_block, else_block;
    std::string loop_var;
    ExprPtr lo, hi;
    std::vector<StmtPtr> body;
    std::string call_name;
    std::vector<ExprPtr> args;
    ExprPtr ret;
};

std::string lure_expr_text(Expr* e, int min_prec = 0);

// ---------------------------------------------------------------------------
// parser
// ---------------------------------------------------------------------------

struct Parser
{
    const std::vector<Lexer::Tok>& toks;
    size_t i = 0;

    explicit Parser(const std::vector<Lexer::Tok>& t)
        : toks(t)
    {
    }

    [[noreturn]] void error(const std::string& msg, int line = -1)
    {
        int l = line > 0 ? line : (i < toks.size() ? toks[i].line : -1);
        throw std::runtime_error("mock parse error at line " + std::to_string(l) + ": " + msg);
    }

    const Lexer::Tok& peek() const { return toks[std::min(i, toks.size() - 1)]; }
    bool kw(const char* w) const { return peek().k == Lexer::Tok::K::Ident && peek().text == w; }
    bool sym(const char* s) const { return peek().k == Lexer::Tok::K::Sym && peek().text == s; }
    void next() { ++i; }

    void expect_sym(const char* s)
    {
        if (!sym(s))
            error(std::string("expected '") + s + "'");
        next();
    }

    bool lit_start()
    {
        const auto& t = peek();
        return t.k == Lexer::Tok::K::Num || t.k == Lexer::Tok::K::Str ||
               (t.k == Lexer::Tok::K::Ident && (t.text == "true" || t.text == "false" || t.text == "nil"));
    }

    static Value numv(double n)
    {
        Value v;
        v.t = Value::T::Num;
        v.n = n;
        return v;
    }
    static Value strv(std::string s)
    {
        Value v;
        v.t = Value::T::Str;
        v.s = std::move(s);
        return v;
    }
    static Value boolv(bool b)
    {
        Value v;
        v.t = Value::T::Bool;
        v.b = b;
        return v;
    }

    Value literal_value()
    {
        const auto& t = peek();
        Value v;
        if (t.k == Lexer::Tok::K::Num)
        {
            v = numv(t.num);
            next();
        }
        else if (t.k == Lexer::Tok::K::Str)
        {
            v = strv(t.text);
            next();
        }
        else if (t.text == "true")
        {
            v = boolv(true);
            next();
        }
        else if (t.text == "false")
        {
            v = boolv(false);
            next();
        }
        else if (t.text == "nil")
        {
            next();
        }
        else
            error("expected literal");
        return v;
    }

    ExprPtr expr(int min_prec = 0)
    {
        static const std::vector<std::pair<std::string, int>> precs = {
            {"or", 1}, {"and", 2}, {"<", 3}, {">", 3}, {"<=", 3}, {">=", 3}, {"==", 3}, {"~=", 3},
            {"..", 4}, {"+", 5},   {"-", 5}, {"*", 6}, {"/", 6},  {"%", 6},  {"^", 7},
        };
        auto prec_of = [&](const std::string& op) -> int
        {
            for (const auto& [o, p] : precs)
                if (o == op)
                    return p;
            return -1;
        };

        ExprPtr left;
        const auto& t = peek();
        if (t.text == "not" || t.text == "-" || t.text == "#")
        {
            std::string op = t.text;
            next();
            auto e = std::make_unique<Expr>();
            e->k = Expr::K::Unary;
            e->op = op;
            e->a = expr(7);
            left = std::move(e);
        }
        else if (t.k == Lexer::Tok::K::Num || t.k == Lexer::Tok::K::Str || (t.k == Lexer::Tok::K::Ident && lit_start()))
        {
            auto e = std::make_unique<Expr>();
            e->k = Expr::K::Lit;
            e->lit = literal_value();
            left = std::move(e);
        }
        else if (t.k == Lexer::Tok::K::Ident)
        {
            std::string name = t.text;
            next();
            if (sym("("))
            {
                next();
                auto e = std::make_unique<Expr>();
                e->k = Expr::K::Call;
                e->call_name = std::move(name);
                while (!sym(")"))
                {
                    e->args.push_back(expr(0));
                    if (sym(","))
                        next();
                    else
                        break;
                }
                expect_sym(")");
                left = std::move(e);
            }
            else if (sym("["))
            {
                next();
                auto e = std::make_unique<Expr>();
                e->k = Expr::K::Index;
                auto base = std::make_unique<Expr>();
                base->k = Expr::K::Var;
                base->var = std::move(name);
                e->a = std::move(base);
                e->b = expr(0);
                expect_sym("]");
                left = std::move(e);
            }
            else
            {
                auto e = std::make_unique<Expr>();
                e->k = Expr::K::Var;
                e->var = std::move(name);
                left = std::move(e);
            }
        }
        else if (sym("("))
        {
            next();
            left = expr(0);
            expect_sym(")");
        }
        else
            error("expected expression");

        while (sym("["))
        {
            next();
            auto e = std::make_unique<Expr>();
            e->k = Expr::K::Index;
            e->a = std::move(left);
            e->b = expr(0);
            expect_sym("]");
            left = std::move(e);
        }

        while (prec_of(peek().text) >= min_prec)
        {
            std::string op = peek().text;
            int p = prec_of(op);
            next();
            auto e = std::make_unique<Expr>();
            e->k = Expr::K::Binary;
            e->op = op;
            e->a = std::move(left);
            e->b = expr(p + (op == "^" ? 1 : 0));
            left = std::move(e);
        }
        return left;
    }

    std::vector<StmtPtr> block()
    {
        std::vector<StmtPtr> stmts;
        while (true)
        {
            const auto& t = peek();
            if (t.k == Lexer::Tok::K::End)
                break;
            if (t.k == Lexer::Tok::K::Ident && (t.text == "end" || t.text == "elseif" || t.text == "else"))
                break;
            stmts.push_back(stmt());
        }
        return stmts;
    }

    StmtPtr stmt()
    {
        auto s = std::make_unique<Stmt>();
        const auto& t = peek();

        if (t.text == "local")
        {
            next();
            s->k = Stmt::K::Local;
            if (peek().k != Lexer::Tok::K::Ident)
                error("expected local name");
            std::string name = peek().text;
            next();
            ExprPtr init;
            if (sym("="))
            {
                next();
                init = expr(0);
            }
            s->assigns.push_back({std::move(name), std::move(init), nullptr});
            return s;
        }

        if (t.text == "if")
        {
            next();
            s->k = Stmt::K::If;
            s->cond = expr(0);
            if (!kw("then"))
                error("expected 'then'");
            next();
            s->then_block = block();
            if (kw("elseif"))
                error("elseif is not supported by the mock subset; use nested if/else");
            if (kw("else"))
            {
                next();
                s->else_block = std::move(block());
            }
            if (!kw("end"))
                error("expected 'end'");
            next();
            return s;
        }

        if (t.text == "while")
        {
            next();
            s->k = Stmt::K::While;
            s->cond = expr(0);
            if (!kw("do"))
                error("expected 'do'");
            next();
            s->body = block();
            if (!kw("end"))
                error("expected 'end'");
            next();
            return s;
        }

        if (t.text == "for")
        {
            next();
            s->k = Stmt::K::For;
            if (peek().k != Lexer::Tok::K::Ident)
                error("expected loop variable");
            s->loop_var = peek().text;
            next();
            expect_sym("=");
            s->lo = expr(0);
            expect_sym(",");
            s->hi = expr(0);
            if (!kw("do"))
                error("expected 'do'");
            next();
            s->body = block();
            if (!kw("end"))
                error("expected 'end'");
            next();
            return s;
        }

        if (t.text == "return")
        {
            next();
            s->k = Stmt::K::Return;
            const auto& n = peek();
            bool has_expr = n.k != Lexer::Tok::K::End && !(n.k == Lexer::Tok::K::Ident && n.text == "end");
            if (has_expr)
                s->ret = expr(0);
            return s;
        }

        if (peek().k == Lexer::Tok::K::Ident && i + 1 < toks.size() && toks[i + 1].k == Lexer::Tok::K::Sym &&
            toks[i + 1].text == "(")
        {
            s->k = Stmt::K::Call;
            s->call_name = t.text;
            next();
            next(); // (
            while (!sym(")"))
            {
                s->args.push_back(expr(0));
                if (sym(","))
                    next();
                else
                    break;
            }
            expect_sym(")");
            return s;
        }

        if (peek().k == Lexer::Tok::K::Ident)
        {
            std::string name = t.text;
            next();
            if (sym("["))
            {
                next();
                auto idx = std::make_unique<Expr>();
                idx->k = Expr::K::Index;
                auto base = std::make_unique<Expr>();
                base->k = Expr::K::Var;
                base->var = name;
                idx->a = std::move(base);
                idx->b = expr(0);
                expect_sym("]");
                expect_sym("=");
                s->k = Stmt::K::Assign;
                s->assigns.push_back({std::move(name), expr(0), std::move(idx)});
                return s;
            }
            if (sym("="))
            {
                next();
                s->k = Stmt::K::Assign;
                s->assigns.push_back({std::move(name), expr(0), nullptr});
                return s;
            }
            error("expected statement");
        }
        error("unexpected token", t.line);
    }
};

// ---------------------------------------------------------------------------
// planning pass: static pc slots + branch targets (depth-first over the AST)
// ---------------------------------------------------------------------------

std::string lure_expr_text(Expr* e, int min_prec)
{
    static const std::vector<std::pair<std::string, int>> precs = {
        {"or", 1}, {"and", 2}, {"<", 3}, {">", 3}, {"<=", 3}, {">=", 3}, {"==", 3}, {"~=", 3},
        {"..", 4}, {"+", 5},   {"-", 5}, {"*", 6}, {"/", 6},  {"%", 6},  {"^", 7},
    };
    auto prec_of = [&](const std::string& op) -> int
    {
        for (const auto& [o, p] : precs)
            if (o == op)
                return p;
        return 0;
    };
    std::string inner;
    switch (e->k)
    {
    case Expr::K::Lit:
        switch (e->lit.t)
        {
        case Value::T::Nil:
            inner = "nil";
            break;
        case Value::T::Bool:
            inner = e->lit.b ? "true" : "false";
            break;
        case Value::T::Num:
            inner = lure::lua_number_text(e->lit.n);
            break;
        case Value::T::Str:
            inner = "\"" + e->lit.s + "\"";
            break;
        default:
            inner = "nil";
            break;
        }
        break;
    case Expr::K::Var:
        inner = e->var;
        break;
    case Expr::K::Index:
        inner = lure_expr_text(e->a.get(), 8) + "[" + lure_expr_text(e->b.get(), 0) + "]";
        break;
    case Expr::K::Unary:
        inner = e->op + lure_expr_text(e->a.get(), 7);
        break;
    case Expr::K::Binary:
    {
        std::string op = e->op;
        int p = prec_of(op);
        std::string l = lure_expr_text(e->a.get(), p);
        std::string r = lure_expr_text(e->b.get(), p + 1);
        bool spaced = !(op == ".." || op == "+" || op == "-");
        inner = l + (spaced ? " " + op + " " : op) + r;
        if (min_prec > p)
            inner = "(" + inner + ")";
        break;
    }
    case Expr::K::Call:
    {
        inner = e->call_name + "(";
        for (size_t ai = 0; ai < e->args.size(); ++ai)
        {
            if (ai)
                inner += ", ";
            inner += lure_expr_text(e->args[ai].get(), 0);
        }
        inner += ")";
        break;
    }
    }
    return inner;
}

struct Planner
{
    std::vector<Stmt*> plan;      // slot -> statement, in slot order
    std::vector<StmtPtr> owned;   // owns synthetic statements appended to the plan

    int visit(Stmt* s)
    {
        s->plan_index = int(plan.size());
        plan.push_back(s);
        switch (s->k)
        {
        case Stmt::K::Local:
        case Stmt::K::Assign:
        case Stmt::K::Call:
        case Stmt::K::Return:
            return s->plan_index + 1;
        case Stmt::K::If:
        {
            int then_first = s->plan_index + 1;
            for (auto& b : s->then_block)
                visit(b.get());
            Stmt* jump = nullptr;
            if (!s->else_block.empty())
            {
                auto j = std::make_unique<Stmt>();
                j->k = Stmt::K::Jump;
                j->plan_index = int(plan.size());
                plan.push_back(j.get());
                jump = j.get();
                owned.push_back(std::move(j));
            }
            int else_first = int(plan.size());
            if (!s->else_block.empty())
            {
                for (auto& b : s->else_block)
                    visit(b.get());
            }
            int after = int(plan.size());
            s->then_t = then_first;
            s->else_t = s->else_block.empty() ? after : else_first;
            if (jump)
                jump->else_t = after;
            return after;
        }
        case Stmt::K::While:
        {
            int body_first = s->plan_index + 1;
            for (auto& b : s->body)
                visit(b.get());
            // synthetic back-edge: jump to the loop head after the body
            auto back = std::make_unique<Stmt>();
            back->k = Stmt::K::Jump;
            back->plan_index = int(plan.size());
            back->else_t = s->plan_index;
            plan.push_back(back.get());
            owned.push_back(std::move(back));
            s->then_t = body_first;
            s->else_t = int(plan.size());
            return s->else_t;
        }
        case Stmt::K::For:
        {
            int body_first = s->plan_index + 1;
            for (auto& b : s->body)
                visit(b.get());
            // synthetic ADVANCE statement: i = i + 1, then test and back-edge into the body
            auto adv = std::make_unique<Stmt>();
            adv->k = Stmt::K::For;
            adv->is_advance = true;
            adv->loop_var = s->loop_var;
            adv->plan_index = int(plan.size());
            adv->then_t = body_first; // test-taken: re-enter the body
            adv->else_t = adv->plan_index + 1; // test-not-taken: exit the loop
            adv->loop_head_slot = s->plan_index;
            plan.push_back(adv.get());
            owned.push_back(std::move(adv));
            s->advance_slot = int(plan.size()) - 1;
            s->then_t = body_first;
            s->else_t = s->advance_slot + 1; // slot after the advance statement
            return s->advance_slot + 1;
        }
        }
        return s->plan_index + 1;
    }
};

// ---------------------------------------------------------------------------
// interpreter (pc-driven over the plan)
// ---------------------------------------------------------------------------

struct MockInterp
{
    RunRequest req;
    TraceData trace;
    std::stringstream out;
    std::map<std::string, Value> env;
    uint64_t event_count = 0;
    unsigned step_limit = 100000;
    bool stepped_over = false;
    // Index of the most recently emitted CALL event (in trace.events), marked
    // when that call wrote observable output (see result_of_call "print").
    size_t last_call_index = SIZE_MAX;
    std::vector<Stmt*> plan;
    int pc = 0;

    explicit MockInterp(RunRequest r)
        : req(std::move(r))
    {
        trace.source_script = req.source;
        trace.mode = req.mode;
        trace.vm_kind = "mock";
    }

    static Value nilv() { return Value{}; }
    static Value boolv(bool b)
    {
        Value v;
        v.t = Value::T::Bool;
        v.b = b;
        return v;
    }
    static Value numv(double n)
    {
        Value v;
        v.t = Value::T::Num;
        v.n = n;
        return v;
    }
    static Value strv(std::string s)
    {
        Value v;
        v.t = Value::T::Str;
        v.s = std::move(s);
        return v;
    }
    static Value nativev(std::string name, bool whitelisted)
    {
        Value v;
        v.t = Value::T::Native;
        v.native_name = std::move(name);
        v.whitelisted = whitelisted;
        return v;
    }

    static std::string mock_fnptr(const std::string& name)
    {
        uint64_t h = 1469598103934665603ull;
        for (char c : name)
        {
            h ^= uint64_t(uint8_t(c));
            h *= 1099511628211ull;
        }
        char buf[40];
        std::snprintf(buf, sizeof(buf), "0x%016llx", static_cast<unsigned long long>(h));
        return buf;
    }

    static bool is_whitelisted_native(const std::string& name)
    {
        static const std::vector<std::string> whitelist = {"print", "tostring", "tonumber", "type", "select", "pcall",
            "math.floor", "math.ceil", "math.abs", "math.min", "math.max", "math.sqrt", "math.random", "string.len",
            "string.sub", "string.byte", "string.char", "string.rep", "string.lower", "string.upper", "table.insert",
            "table.concat", "bit32.bxor", "bit32.band", "bit32.bor", "bit32.lshift", "bit32.rshift"};
        return std::find(whitelist.begin(), whitelist.end(), name) != whitelist.end();
    }

    static bool truthy(const Value& v)
    {
        return !(v.t == Value::T::Nil || (v.t == Value::T::Bool && !v.b));
    }

    bool value_eq(const Value& a, const Value& b)
    {
        switch (a.t)
        {
        case Value::T::Nil:
            return b.t == Value::T::Nil;
        case Value::T::Bool:
            return b.t == Value::T::Bool && a.b == b.b;
        case Value::T::Num:
            return b.t == Value::T::Num && a.n == b.n;
        case Value::T::Str:
            return b.t == Value::T::Str && a.s == b.s;
        default:
            return a.t == b.t;
        }
    }

    std::string value_text(const Value& v)
    {
        switch (v.t)
        {
        case Value::T::Nil:
            return "nil";
        case Value::T::Bool:
            return v.b ? "true" : "false";
        case Value::T::Num:
            return lure::lua_number_text(v.n);
        case Value::T::Str:
            return v.s;
        case Value::T::Table:
            return "table: 0x0";
        case Value::T::Native:
            return v.native_name;
        case Value::T::Poison:
            return "<unresolved>";
        }
        return "nil";
    }

    LuaValueSnapshot snap(const Value& v)
    {
        LuaValueSnapshot s;
        switch (v.t)
        {
        case Value::T::Nil:
            s.type = ValueType::Nil;
            s.text = "nil";
            break;
        case Value::T::Bool:
            s.type = ValueType::Bool;
            s.text = v.b ? "true" : "false";
            break;
        case Value::T::Num:
            s.type = ValueType::Number;
            s.nvalue = v.n;
            s.text = lure::lua_number_text(v.n);
            break;
        case Value::T::Str:
            s.type = ValueType::String;
            s.text = v.s;
            break;
        case Value::T::Table:
            s.type = ValueType::Table;
            s.text = "table: 0x0";
            break;
        case Value::T::Native:
            s.type = v.whitelisted ? ValueType::Native : ValueType::Unknown;
            s.text = v.native_name;
            if (!v.whitelisted)
                s.unres_reason = v.poison_reason.empty() ? "unresolved native (no stdlib match)" : v.poison_reason;
            break;
        case Value::T::Poison:
            s.type = ValueType::Unknown;
            s.unres_reason = v.poison_reason;
            break;
        }
        return s;
    }

    Value poison(Value v, std::string reason)
    {
        v.t = Value::T::Poison;
        v.poison_reason = std::move(reason);
        v.native_name.clear();
        v.s.clear();
        v.n = 0.0;
        v.b = false;
        v.tbl.clear();
        return v;
    }

    void emit(TraceEvent ev)
    {
        ++event_count;
        if (stepped_over)
            return;
        if (event_count > step_limit)
        {
            stepped_over = true;
            TraceEvent t;
            t.tag = "STEPLIMIT";
            t.status = ResolutionStatus::Unresolved;
            t.notfound_reason = "mock execution step limit exceeded (" + std::to_string(step_limit) +
                                "); possible infinite loop, trace truncated";
            trace.events.push_back(std::move(t));
            return;
        }
        if (ev.tag == "CALL")
            last_call_index = trace.events.size();
        trace.events.push_back(std::move(ev));
    }

    // ------------------------------------------------------------------
    // expression evaluation
    // ------------------------------------------------------------------

    Value eval_inner(Expr* e, std::string& pr)
    {
        if (!e)
            return nilv();
        switch (e->k)
        {
        case Expr::K::Lit:
            return e->lit;
        case Expr::K::Var:
        {
            auto it = env.find(e->var);
            return it == env.end() ? nilv() : it->second;
        }
        case Expr::K::Index:
        {
            Value t = eval_inner(e->a.get(), pr);
            Value k = eval_inner(e->b.get(), pr);
            if (t.is_poison() || k.is_poison())
                return poison(nilv(), std::move(pr));
            if (t.t != Value::T::Table)
                return nilv();
            for (const auto& kv : t.tbl)
                if (value_eq(kv.first, k))
                    return kv.second;
            return nilv();
        }
        case Expr::K::Unary:
        {
            Value a = eval_inner(e->a.get(), pr);
            if (a.is_poison())
            {
                pr = a.poison_reason;
                return a;
            }
            if (e->op == "not")
                return boolv(!truthy(a));
            if (e->op == "#")
            {
                if (a.t == Value::T::Str)
                    return numv(double(a.s.size()));
                if (a.t == Value::T::Table)
                    return numv(double(a.tbl.size()));
                return numv(0.0);
            }
            if (e->op == "-")
                return numv(a.t == Value::T::Num ? -a.n : 0.0);
            return nilv();
        }
        case Expr::K::Binary:
        {
            if (e->op == "and" || e->op == "or")
            {
                Value a = eval_inner(e->a.get(), pr);
                if (a.is_poison())
                {
                    pr = a.poison_reason;
                    return a;
                }
                if (e->op == "and")
                    return truthy(a) ? eval_inner(e->b.get(), pr) : a;
                return truthy(a) ? a : eval_inner(e->b.get(), pr);
            }
            Value a = eval_inner(e->a.get(), pr);
            Value b = eval_inner(e->b.get(), pr);
            if (a.is_poison())
            {
                pr = a.poison_reason;
                return a;
            }
            if (b.is_poison())
            {
                pr = b.poison_reason;
                return b;
            }
            if (e->op == "..")
                return strv(value_text(a) + value_text(b));
            if (a.t == Value::T::Num && b.t == Value::T::Num)
            {
                double x = a.n, y = b.n;
                if (e->op == "+")
                    return numv(x + y);
                if (e->op == "-")
                    return numv(x - y);
                if (e->op == "*")
                    return numv(x * y);
                if (e->op == "/")
                    return numv(y != 0.0 ? x / y : 0.0);
                if (e->op == "%")
                    return numv(y != 0.0 ? std::fmod(x, y) : 0.0);
                if (e->op == "^")
                    return numv(std::pow(x, y));
                if (e->op == "<")
                    return boolv(x < y);
                if (e->op == "<=")
                    return boolv(x <= y);
                if (e->op == ">")
                    return boolv(x > y);
                if (e->op == ">=")
                    return boolv(x >= y);
                if (e->op == "==")
                    return boolv(x == y);
                if (e->op == "~=")
                    return boolv(x != y);
            }
            if (e->op == "==" || e->op == "~=")
            {
                bool eq = a.t == b.t && value_eq(a, b);
                return boolv(e->op == "==" ? eq : !eq);
            }
            return nilv();
        }
        case Expr::K::Call:
        {
            std::vector<Value> args;
            for (const auto& a : e->args)
                args.push_back(eval_inner(a.get(), pr));

            Value fn = nativev(e->call_name, is_whitelisted_native(e->call_name));
            std::string call_text = e->call_name + "(";
            for (size_t i = 0; i < args.size(); ++i)
            {
                if (i)
                    call_text += ", ";
                call_text += (args[i].is_poison() ? "<unresolved>" : value_text(args[i]));
            }
            call_text += ")";

            bool any_poison = false;
            std::string pr2;
            for (const auto& a : args)
                if (a.is_poison())
                {
                    any_poison = true;
                    pr2 = a.poison_reason;
                }

            if (!fn.whitelisted)
            {
                std::string reason = "unresolved native call (fn ptr " + mock_fnptr(e->call_name) + ", no stdlib match)";
                TraceEvent ev;
                ev.tag = "CALL";
                ev.status = ResolutionStatus::Unresolved;
                ev.notfound_reason = reason;
                ev.text = call_text;
                lure::CallInfo ci;
                ci.fn = snap(fn);
                for (const auto& a : args)
                    ci.args.push_back(snap(a));
                ev.call_info = std::move(ci);
                emit(std::move(ev));
                return poison(nilv(), reason);
            }
            if (any_poison)
            {
                TraceEvent ev;
                ev.tag = "CALL";
                ev.status = ResolutionStatus::Unresolved;
                ev.notfound_reason = "call argument derived from unresolved value (" + pr2 + ")";
                ev.text = call_text;
                lure::CallInfo ci;
                ci.fn = snap(fn);
                for (const auto& a : args)
                    ci.args.push_back(snap(a));
                ev.call_info = std::move(ci);
                emit(std::move(ev));
                return poison(nilv(), ev.notfound_reason);
            }

            TraceEvent ev;
            ev.tag = "CALL";
            ev.text = call_text;
            lure::CallInfo ci;
            ci.fn = snap(fn);
            if (fn.whitelisted)
                ci.native_name = fn.native_name;
            for (const auto& a : args)
                ci.args.push_back(snap(a));
            ev.call_info = std::move(ci);
            emit(std::move(ev));
            return result_of_call(e->call_name, args);
        }
        }
        return nilv();
    }

    Value eval(const ExprPtr& e)
    {
        std::string pr;
        return eval_inner(e.get(), pr);
    }

    Value result_of_call(const std::string& name, const std::vector<Value>& args)
    {
        if (name == "print")
        {
            if (last_call_index < trace.events.size())
                trace.events[last_call_index].printed_output = true;
            for (size_t i = 0; i < args.size(); ++i)
            {
                if (i)
                    out << "\t";
                out << value_text(args[i]);
            }
            out << "\n";
            return nilv();
        }
        if (name == "tostring")
            return strv(value_text(args.empty() ? nilv() : args[0]));
        if (name == "tonumber")
        {
            if (args.empty() || args[0].t != Value::T::Str)
                return nilv();
            const std::string& s = args[0].s;
            char* end = nullptr;
            double d = std::strtod(s.c_str(), &end);
            if (end && *end == '\0' && end != s.c_str())
                return numv(d);
            return nilv();
        }
        if (name == "type")
        {
            const char* tn = "nil";
            switch (args.empty() ? Value::T::Nil : args[0].t)
            {
            case Value::T::Nil:
                tn = "nil";
                break;
            case Value::T::Bool:
                tn = "boolean";
                break;
            case Value::T::Num:
                tn = "number";
                break;
            case Value::T::Str:
                tn = "string";
                break;
            case Value::T::Table:
                tn = "table";
                break;
            case Value::T::Native:
                tn = "function";
                break;
            case Value::T::Poison:
                tn = "unknown";
                break;
            }
            return strv(tn);
        }
        if (name.rfind("math.", 0) == 0)
        {
            const std::string f = name.substr(5);
            auto num = [&](size_t k) -> double { return k < args.size() && args[k].t == Value::T::Num ? args[k].n : 0.0; };
            if (f == "floor")
                return numv(std::floor(num(0)));
            if (f == "ceil")
                return numv(std::ceil(num(0)));
            if (f == "abs")
                return numv(std::abs(num(0)));
            if (f == "sqrt")
                return numv(std::sqrt(num(0)));
            if (f == "min" || f == "max")
                return numv(f == "min" ? std::min(num(0), num(1)) : std::max(num(0), num(1)));
            if (f == "random")
            {
                static uint64_t seed = 1;
                seed = seed * 6364136223846793005ull + 1442695040888963407ull;
                double span = 1.0;
                bool ranged = (!args.empty() && args[0].t == Value::T::Num);
                if (args.size() >= 2 && args[0].t == Value::T::Num && args[1].t == Value::T::Num)
                    span = std::max(1.0, args[1].n - args[0].n + 1.0);
                else if (ranged)
                    span = std::max(1.0, args[0].n);
                double r = double((seed >> 33) % 1000000) / 1e6;
                if (ranged)
                    return numv(args[0].n + std::floor(r * span));
                return numv(r);
            }
            return nativev(name, true);
        }
        if (name.rfind("string.", 0) == 0)
        {
            const std::string f = name.substr(7);
            auto str0 = [&]() -> std::string { return (!args.empty() && args[0].t == Value::T::Str) ? args[0].s : std::string(); };
            if (f == "len")
                return numv(double(str0().size()));
            if (f == "lower")
            {
                std::string s = str0();
                for (char& c : s)
                    if (c >= 'A' && c <= 'Z')
                        c = char(c + 32);
                return strv(s);
            }
            if (f == "upper")
            {
                std::string s = str0();
                for (char& c : s)
                    if (c >= 'a' && c <= 'z')
                        c = char(c - 32);
                return strv(s);
            }
            if (f == "rep")
            {
                std::string acc;
                int n = int(args.size() > 1 && args[1].t == Value::T::Num ? args[1].n : 0);
                for (int i = 0; i < n; ++i)
                    acc += str0();
                return strv(acc);
            }
            if (f == "sub")
            {
                const std::string s = str0();
                int b = int(args.size() > 1 && args[1].t == Value::T::Num ? args[1].n : 1);
                int e = int(args.size() > 2 && args[2].t == Value::T::Num ? args[2].n : double(s.size()));
                if (b < 0)
                    b = int(s.size()) + b + 1;
                if (e < 0)
                    e = int(s.size()) + e;
                b = std::max(b, 1);
                e = std::min(e, int(s.size()));
                if (b > e)
                    return strv("");
                return strv(s.substr(size_t(b - 1), size_t(e - b + 1)));
            }
            if (f == "byte")
            {
                const std::string s = str0();
                int i = int(args.size() > 1 && args[1].t == Value::T::Num ? args[1].n : 1);
                if (i >= 1 && i <= int(s.size()))
                    return numv(double(uint8_t(s[size_t(i) - 1])));
                return nilv();
            }
            if (f == "char")
            {
                std::string acc;
                for (const auto& a : args)
                    if (a.t == Value::T::Num)
                        acc += char(int(a.n) & 0xff);
                return strv(acc);
            }
            return nativev(name, true);
        }
        if (name.rfind("table.", 0) == 0)
        {
            const std::string f = name.substr(6);
            if (f == "insert")
            {
                // note: mock tables are value-semantic; the mutation applies to
                // the local copy, matching the snapshot emitted on the CALL event
                if (!args.empty() && args[0].t == Value::T::Table)
                {
                    Value v = args.size() > 1 ? args[1] : nilv();
                    Value t = args[0];
                    t.tbl.push_back({numv(double(t.tbl.size() + 1)), v});
                }
                return nilv();
            }
            if (f == "concat")
            {
                std::string acc;
                if (!args.empty() && args[0].t == Value::T::Table)
                    for (const auto& kv : args[0].tbl)
                        acc += value_text(kv.second);
                return strv(acc);
            }
            return nativev(name, true);
        }
        if (name.rfind("bit32.", 0) == 0)
        {
            if (args.size() < 2)
                return nilv();
            auto i32 = [&](const Value& v) -> int { return int(uint32_t(v.t == Value::T::Num ? v.n : 0.0)); };
            const std::string f = name.substr(6);
            int a = i32(args[0]), b = i32(args[1]);
            int r = 0;
            if (f == "bxor")
                r = a ^ b;
            else if (f == "band")
                r = a & b;
            else if (f == "bor")
                r = a | b;
            else if (f == "lshift")
                r = a << (b & 31);
            else if (f == "rshift")
                r = int(uint32_t(a) >> (b & 31));
            else
                return nativev(name, true);
            return numv(double(int32_t(r)));
        }
        return nativev(name, is_whitelisted_native(name));
    }

    // ------------------------------------------------------------------
    // conditions / DSL
    // ------------------------------------------------------------------

    std::string cond_dsl_of(Expr* e, bool& ok)
    {
        ok = false;
        if (!e)
            return "";
        if (e->k == Expr::K::Var)
        {
            ok = true;
            return e->var;
        }
        if (e->k == Expr::K::Unary && e->op == "not" && e->a && e->a->k == Expr::K::Var)
        {
            ok = true;
            return "not " + e->a->var;
        }
        if (e->k == Expr::K::Binary)
        {
            static const std::vector<std::string> cmps = {"==", "~=", "<", "<=", ">", ">="};
            if (std::find(cmps.begin(), cmps.end(), e->op) == cmps.end())
                return "";
            auto lit_text = [&](Expr* x) -> std::string
            {
                if (!x)
                    return "";
                if (x->k == Expr::K::Var)
                    return x->var;
                if (x->k == Expr::K::Lit)
                {
                    if (x->lit.t == Value::T::Num)
                        return lure::lua_number_text(x->lit.n);
                    if (x->lit.t == Value::T::Nil)
                        return "nil";
                    if (x->lit.t == Value::T::Bool)
                        return x->lit.b ? "true" : "false";
                    return ""; // string literals are not expressible in the numeric DSL
                }
                return "";
            };
            std::string l = lit_text(e->a.get()), r = lit_text(e->b.get());
            if (l.empty() || r.empty())
                return "";
            ok = true;
            return l + e->op + r;
        }
        return "";
    }

    // ------------------------------------------------------------------
    // statement execution via pc
    // ------------------------------------------------------------------

    void tbl_set(Value& t, const Value& k, const Value& v)
    {
        if (t.t != Value::T::Table)
            return;
        for (auto& kv : t.tbl)
            if (value_eq(kv.first, k))
            {
                kv.second = v;
                return;
            }
        t.tbl.push_back({k, v});
    }

    void run()
    {
        while (pc < int(plan.size()))
        {
            if (stepped_over)
                return;
            Stmt* s = plan[size_t(pc)];
            switch (s->k)
            {
            case Stmt::K::Local:
            {
                Value v = s->assigns.empty() ? nilv() : (s->assigns[0].rhs ? eval(s->assigns[0].rhs) : nilv());
                const std::string& name = s->assigns[0].name;
                env[name] = v;
                TraceEvent ev;
                ev.pc = uint64_t(s->plan_index);
                ev.tag = "LOCAL";
                ev.text = "local " + name +
                          (s->assigns[0].rhs ? " = " + lure_expr_text(s->assigns[0].rhs.get()) : "");
                if (v.is_poison())
                {
                    ev.status = ResolutionStatus::Unresolved;
                    ev.notfound_reason = v.poison_reason;
                }
                emit(std::move(ev));
                ++pc;
                break;
            }
            case Stmt::K::Assign:
            {
                const auto& a = s->assigns[0];
                if (a.index)
                {
                    Value t = eval(a.index->a);
                    Value k = eval(a.index->b);
                    Value v = eval(a.rhs);
                    std::string reason;
                    if (t.is_poison())
                        reason = t.poison_reason;
                    else if (k.is_poison())
                        reason = k.poison_reason;
                    else if (v.is_poison())
                        reason = v.poison_reason;
                    if (a.index->a->k == Expr::K::Var)
                        tbl_set(env[a.index->a->var], k, v);
                    else
                        tbl_set(t, k, v);
                    TraceEvent ev;
                    ev.pc = uint64_t(s->plan_index);
                    ev.tag = "TABLE_SET";
                    ev.text = lure_expr_text(a.index.get()) + " = " + (a.rhs ? lure_expr_text(a.rhs.get()) : "");
                    lure::TableOpInfo ti;
                    ti.table = snap(t);
                    ti.key = snap(k);
                    ti.value = snap(v);
                    ti.is_set = true;
                    ev.table_op = std::move(ti);
                    if (!reason.empty())
                    {
                        ev.status = ResolutionStatus::Unresolved;
                        ev.notfound_reason = "table write through unresolved value (" + reason + ")";
                    }
                    emit(std::move(ev));
                    ++pc;
                    break;
                }
                Value v = a.rhs ? eval(a.rhs) : nilv();
                env[a.name] = v;
                TraceEvent ev;
                ev.pc = uint64_t(s->plan_index);
                ev.tag = "ASSIGN";
                ev.text = a.name + " = " + (a.rhs ? lure_expr_text(a.rhs.get()) : "");
                if (v.is_poison())
                {
                    ev.status = ResolutionStatus::Unresolved;
                    ev.notfound_reason = v.poison_reason;
                }
                emit(std::move(ev));
                ++pc;
                break;
            }
            case Stmt::K::If:
            {
                Value c = eval(s->cond);
                TraceEvent ev;
                ev.pc = uint64_t(s->plan_index);
                ev.tag = "BRANCH";
                ev.is_branch = true;
                ev.cond_text = lure_expr_text(s->cond.get());
                bool ok_dsl = false;
                std::string dsl = cond_dsl_of(s->cond.get(), ok_dsl);
                if (c.is_poison())
                {
                    ev.status = ResolutionStatus::Unresolved;
                    ev.notfound_reason = "branch condition derived from unresolved value (" + c.poison_reason + ")";
                    ev.branch_taken = false;
                    ev.jump_target = uint32_t(s->else_t);
                    ev.other_target = int32_t(s->then_t);
                    ev.cond_dsl.clear();
                    emit(std::move(ev));
                    pc = s->else_t; // policy: execute the annotated side; annotation makes it explicit
                    break;
                }
                ev.cond_dsl = ok_dsl ? dsl : "";
                ev.branch_taken = truthy(c);
                ev.jump_target = uint32_t(truthy(c) ? s->then_t : s->else_t);
                ev.other_target = int32_t(truthy(c) ? s->else_t : s->then_t);
                emit(std::move(ev));
                pc = truthy(c) ? s->then_t : s->else_t;
                break;
            }
            case Stmt::K::While:
            {
                Value c = eval(s->cond);
                TraceEvent ev;
                ev.pc = uint64_t(s->plan_index);
                ev.tag = "BRANCH";
                ev.is_branch = true;
                ev.cond_text = lure_expr_text(s->cond.get());
                bool ok_dsl = false;
                std::string dsl = cond_dsl_of(s->cond.get(), ok_dsl);
                if (c.is_poison())
                {
                    ev.status = ResolutionStatus::Unresolved;
                    ev.notfound_reason = "branch condition derived from unresolved value (" + c.poison_reason + ")";
                    ev.branch_taken = false;
                    ev.jump_target = uint32_t(s->else_t);
                    ev.other_target = -1;
                    ev.cond_dsl.clear();
                    emit(std::move(ev));
                    pc = int(plan.size()); // cannot verify loop progression; stop, annotated
                    return;
                }
                ev.cond_dsl = ok_dsl ? dsl : "";
                ev.branch_taken = truthy(c);
                ev.jump_target = uint32_t(truthy(c) ? s->then_t : s->else_t);
                ev.other_target = int32_t(truthy(c) ? s->else_t : s->then_t);
                emit(std::move(ev));
                pc = truthy(c) ? s->then_t : s->else_t;
                break;
            }
            case Stmt::K::For:
            if (s->is_advance)
            {
                // synthetic advance: i = i + 1, then test; taken -> body, else -> exit.
                Stmt* head = s->loop_head_slot >= 0 ? plan[size_t(s->loop_head_slot)] : s;
                Value hi = eval(head->hi);
                double lim = hi.t == Value::T::Num ? hi.n : 0.0;
                Value cur = env.count(s->loop_var) ? env[s->loop_var] : numv(0.0);
                double i = cur.t == Value::T::Num ? cur.n : 0.0;
                i += 1.0;
                env[s->loop_var] = numv(i);
                bool taken = i <= lim;
                TraceEvent ev;
                ev.pc = uint64_t(s->plan_index);
                ev.tag = "ADVANCE";
                ev.text = s->loop_var + " = " + s->loop_var + " + 1";
                ev.is_branch = true;
                ev.branch_taken = taken;
                ev.cond_dsl = s->loop_var + "<=" + lure::lua_number_text(lim);
                ev.cond_text = ev.cond_dsl;
                ev.jump_target = uint32_t(taken ? s->then_t : s->else_t);
                ev.other_target = int32_t(taken ? s->else_t : s->then_t);
                emit(std::move(ev));
                pc = taken ? s->then_t : s->else_t;
                break;
            }
            {
                Value lo = eval(s->lo);
                Value hi = eval(s->hi);
                double lim = hi.t == Value::T::Num ? hi.n : 0.0;
                env[s->loop_var] = numv(lo.t == Value::T::Num ? lo.n : 0.0);
                double i = env[s->loop_var].n;
                bool taken = i <= lim;
                TraceEvent ev;
                ev.pc = uint64_t(s->plan_index);
                ev.tag = "BRANCH";
                ev.text = "-- for init " + s->loop_var + " = " +
                          lure::lua_number_text(lo.t == Value::T::Num ? lo.n : 0.0) + ", " +
                          lure::lua_number_text(lim) + ", 1";
                ev.is_branch = true;
                ev.cond_dsl = s->loop_var + "<=" + lure::lua_number_text(lim);
                ev.cond_text = ev.cond_dsl;
                ev.branch_taken = taken;
                ev.jump_target = uint32_t(taken ? s->then_t : s->else_t);
                ev.other_target = int32_t(taken ? s->else_t : s->then_t);
                emit(std::move(ev));
                pc = taken ? s->then_t : s->else_t;
                break;
            }
            case Stmt::K::Call:
            {
                std::vector<Value> args;
                for (const auto& a : s->args)
                    args.push_back(eval(a));
                std::string call_text = s->call_name + "(";
                for (size_t i = 0; i < args.size(); ++i)
                {
                    if (i)
                        call_text += ", ";
                    call_text += value_text(args[i]);
                }
                call_text += ")";

                Value fn = nativev(s->call_name, is_whitelisted_native(s->call_name));
                bool any_poison = false;
                std::string pr;
                for (const auto& a : args)
                    if (a.is_poison())
                    {
                        any_poison = true;
                        pr = a.poison_reason;
                    }

                TraceEvent ev;
                ev.pc = uint64_t(s->plan_index);
                ev.tag = "CALL";
                ev.text = call_text;
                lure::CallInfo ci;
                ci.fn = snap(fn);
                for (const auto& a : args)
                    ci.args.push_back(snap(a));
                ev.call_info = std::move(ci);

                if (!fn.whitelisted)
                {
                    ev.status = ResolutionStatus::Unresolved;
                    ev.notfound_reason = "unresolved native call (fn ptr " + mock_fnptr(s->call_name) + ", no stdlib match)";
                    emit(std::move(ev));
                    ++pc;
                    break;
                }
                if (any_poison)
                {
                    ev.status = ResolutionStatus::Unresolved;
                    ev.notfound_reason = "call argument derived from unresolved value (" + pr + ")";
                    emit(std::move(ev));
                    ++pc;
                    break;
                }
                emit(std::move(ev));
                result_of_call(s->call_name, args);
                ++pc;
                break;
            }
case Stmt::K::Jump:
            {
                TraceEvent ev;
                ev.pc = uint64_t(s->plan_index);
                ev.tag = "JUMP";
                emit(std::move(ev));
                pc = s->else_t;
                break;
            }
            case Stmt::K::Return:
            {
                Value v = s->ret ? eval(s->ret) : nilv();
                TraceEvent ev;
                ev.pc = uint64_t(s->plan_index);
                ev.tag = "RETURN";
                if (s->ret)
                {
                    ev.text = "return " + lure_expr_text(s->ret.get());
                    if (v.is_poison())
                    {
                        ev.status = ResolutionStatus::Unresolved;
                        ev.notfound_reason = v.poison_reason;
                    }
                }
                else
                    ev.text = "return";
                emit(std::move(ev));
                pc = int(plan.size());
                return;
            }
            }
        }
    }
};

} // namespace

class MockVMRunner : public IVMRunner
{
public:
    RunResult run(const RunRequest& req) override
    {
        MockInterp interp(req);
        for (auto& [k, v] : req.initial_values)
            interp.env[k] = MockInterp::numv(v);
        interp.env["print"] = MockInterp::nativev("print", true);
        interp.env["tostring"] = MockInterp::nativev("tostring", true);
        interp.env["tonumber"] = MockInterp::nativev("tonumber", true);
        interp.env["type"] = MockInterp::nativev("type", true);
        interp.step_limit = req.max_events > 0 ? req.max_events : 100000;

        try
        {
            Lexer lexer(req.source);
            Parser parser(lexer.toks);
            auto program = parser.block();
            Planner planner;
            for (auto& s : program)
                planner.visit(s.get());
            interp.plan = std::move(planner.plan);
            auto owned = std::move(planner.owned); // keep synthetic advance statements alive
            interp.run();
        }
        catch (const std::exception& e)
        {
            RunResult res;
            res.vm_kind = "mock";
            res.ok = false;
            res.error = e.what();
            res.trace = std::move(interp.trace);
            res.stdout_text = interp.out.str();
            return res;
        }

        RunResult res;
        res.trace = std::move(interp.trace);
        res.stdout_text = interp.out.str();
        res.vm_kind = "mock";
        res.ok = !interp.stepped_over;
        if (interp.stepped_over)
            res.error = "mock step limit exceeded";
        return res;
    }

    std::string kind() const override { return "mock"; }
    bool accepts_overrides() const override { return true; }
};

} // namespace

namespace lure::vm {

std::unique_ptr<IVMRunner> make_mock_runner()
{
    return std::make_unique<MockVMRunner>();
}

} // namespace lure::vm
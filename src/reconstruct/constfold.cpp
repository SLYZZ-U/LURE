// reconstruct/constfold.cpp
// See constfold.hpp. The evaluator mirrors Luau's own operator semantics
// (double arithmetic, Lua truthiness, 1-based string indexing with negative
// wraparound, and/or returning their operands).

#include "reconstruct/constfold.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace lure::reconstruct {

namespace {

using lure::TraceEvent;
using lure::TraceData;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

enum class CType : uint8_t
{
    Nil,
    Bool,
    Number,
    String
};

struct Const
{
    CType type = CType::Nil;
    double num = 0;
    double b = 0; // 0/1
    std::string str;
};

std::string escape_string(const std::string& s)
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

std::string const_text(const Const& c)
{
    switch (c.type)
    {
    case CType::Nil:
        return "nil";
    case CType::Bool:
        return c.b != 0 ? "true" : "false";
    case CType::Number:
        return lure::lua_number_text(c.num);
    case CType::String:
        return escape_string(c.str);
    }
    return "?";
}

// ---------------------------------------------------------------------------
// Expression AST
// ---------------------------------------------------------------------------

struct Expr
{
    virtual ~Expr() = default;
    virtual std::string render() const = 0;
};

struct NumE : Expr
{
    double v;
    explicit NumE(double x) : v(x) {}
    std::string render() const override { return lure::lua_number_text(v); }
};

struct StrE : Expr
{
    std::string v;
    explicit StrE(std::string s) : v(std::move(s)) {}
    std::string render() const override { return escape_string(v); }
};

struct BoolE : Expr
{
    bool v;
    explicit BoolE(bool b) : v(b) {}
    std::string render() const override { return v ? "true" : "false"; }
};

struct NilE : Expr
{
    std::string render() const override { return "nil"; }
};

struct NameE : Expr
{
    std::string v;
    explicit NameE(std::string s) : v(std::move(s)) {}
    std::string render() const override { return v; }
};

// Anything the fold cannot see through (table indexes, failed parses, "?").
struct OpaqueE : Expr
{
    std::string v;
    explicit OpaqueE(std::string s) : v(std::move(s)) {}
    std::string render() const override { return v; }
};

struct GroupE : Expr
{
    std::unique_ptr<Expr> e;
    explicit GroupE(std::unique_ptr<Expr> x) : e(std::move(x)) {}
    std::string render() const override { return "(" + e->render() + ")"; }
};

struct UnaryE : Expr
{
    std::string op;
    std::unique_ptr<Expr> e;
    UnaryE(std::string o, std::unique_ptr<Expr> x) : op(std::move(o)), e(std::move(x)) {}
    std::string render() const override
    {
        if (op == "not")
            return "not " + e->render();
        return op + e->render();
    }
};

struct BinaryE : Expr
{
    std::string op;
    std::unique_ptr<Expr> l, r;
    BinaryE(std::string o, std::unique_ptr<Expr> a, std::unique_ptr<Expr> b)
    : op(std::move(o)), l(std::move(a)), r(std::move(b))
    {
    }
    std::string render() const override { return l->render() + " " + op + " " + r->render(); }
};

struct CallE : Expr
{
    std::string fn;
    std::vector<std::unique_ptr<Expr>> args;
    std::string render() const override
    {
        std::string s = fn + "(";
        for (size_t i = 0; i < args.size(); ++i)
        {
            if (i)
                s += ", ";
            s += args[i]->render();
        }
        return s + ")";
    }
};

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

struct Tok
{
    enum class K
    {
        Num,
        Str,
        Name,
        Op,
        LParen,
        RParen,
        Comma,
        LBracket,
        RBracket,
        End
    };
    K k = K::End;
    std::string s;
    double num = 0;
};

class Lexer
{
public:
    explicit Lexer(const std::string& src) : s_(src) {}

    Tok next()
    {
        skip_ws();
        if (pos_ >= s_.size())
            return {Tok::K::End, {}, 0};
        char c = s_[pos_];
        if (c == '(')
        {
            ++pos_;
            return {Tok::K::LParen, "(", 0};
        }
        if (c == ')')
        {
            ++pos_;
            return {Tok::K::RParen, ")", 0};
        }
        if (c == ',')
        {
            ++pos_;
            return {Tok::K::Comma, ",", 0};
        }
        if (c == '[')
        {
            ++pos_;
            return {Tok::K::LBracket, "[", 0};
        }
        if (c == ']')
        {
            ++pos_;
            return {Tok::K::RBracket, "]", 0};
        }
        if (c == '"' || c == '\'')
        {
            return lex_string(c);
        }
        if (std::isdigit(static_cast<unsigned char>(c)) || (c == '.' && std::isdigit(static_cast<unsigned char>(s_[pos_ + 1]))))
        {
            return lex_number();
        }
        if (std::isalpha(static_cast<unsigned char>(c)) || c == '_')
        {
            return lex_name();
        }
        // operators (longest match first)
        static const char* kOps[] = {"..", "~=", "<=", ">=", "==", "and", "or", "not", "+", "-", "*", "/", "%", "^",
            "<", ">", "~"};
        for (const char* op : kOps)
        {
            size_t n = std::strlen(op);
            if (s_.compare(pos_, n, op) == 0)
            {
                pos_ += n;
                return {Tok::K::Op, op, 0};
            }
        }
        // unknown punctuation: mark as opaque tail
        return {Tok::K::Op, std::string(1, c), 0};
    }

    void skip_ws()
    {
        while (pos_ < s_.size() && std::isspace(static_cast<unsigned char>(s_[pos_])))
            ++pos_;
    }

    Tok lex_string(char quote)
    {
        size_t i = pos_ + 1;
        std::string out;
        while (i < s_.size() && s_[i] != quote)
        {
            char c = s_[i];
            if (c == '\\' && i + 1 < s_.size())
            {
                char e = s_[i + 1];
                i += 2;
                switch (e)
                {
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case '\\': out += '\\'; break;
                case '"': out += '"'; break;
                case '\'': out += '\''; break;
                default:
                    if (e >= '0' && e <= '9')
                    {
                        int v = 0;
                        int n = 0;
                        while (n < 3 && i - 1 + n < s_.size() && s_[i - 1 + n] >= '0' && s_[i - 1 + n] <= '9')
                        {
                            v = v * 10 + (s_[i - 1 + n] - '0');
                            ++n;
                        }
                        i += n - 1;
                        out += char(v);
                    }
                    else
                        out += e;
                    break;
                }
            }
            else
            {
                out += c;
                ++i;
            }
        }
        pos_ = (i < s_.size()) ? i + 1 : s_.size();
        return {Tok::K::Str, out, 0};
    }

    Tok lex_number()
    {
        size_t i = pos_;
        while (i < s_.size())
        {
            char c = s_[i];
            if (std::isdigit(static_cast<unsigned char>(c)) || c == '.')
            {
                ++i;
                continue;
            }
            if ((c == 'e' || c == 'E') && i + 1 < s_.size() &&
                (std::isdigit(static_cast<unsigned char>(s_[i + 1])) || s_[i + 1] == '+' || s_[i + 1] == '-'))
            {
                ++i;
                continue;
            }
            if ((c == '+' || c == '-') && i > pos_ && (s_[i - 1] == 'e' || s_[i - 1] == 'E'))
            {
                ++i;
                continue;
            }
            break;
        }
        std::string t = s_.substr(pos_, i - pos_);
        pos_ = i;
        return {Tok::K::Num, t, std::strtod(t.c_str(), nullptr)};
    }

    Tok lex_name()
    {
        size_t i = pos_;
        // dotted native names ("string.char", "_G.type")
        while (i < s_.size() && (std::isalnum(static_cast<unsigned char>(s_[i])) || s_[i] == '_' || s_[i] == '.'))
            ++i;
        std::string t = s_.substr(pos_, i - pos_);
        pos_ = i;
        return {Tok::K::Name, t, 0};
    }

private:
    const std::string& s_;
    size_t pos_ = 0;
};

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

class Parser
{
public:
    explicit Parser(const std::string& src)
    : s_(src), lx_(src)
    {
        cur_ = lx_.next();
    }

    bool ok() const { return ok_; }

    std::unique_ptr<Expr> parse()
    {
        std::unique_ptr<Expr> e = parse_expr(0);
        if (!ok_)
            return nullptr;
        if (cur_.k != Tok::K::End)
        {
            ok_ = false;
            return nullptr;
        }
        return e;
    }

private:
    bool is_op(const char* op) const
    {
        return cur_.k == Tok::K::Op && cur_.s == op;
    }

    int prec() const
    {
        if (cur_.k != Tok::K::Op)
            return -1;
        const std::string& s = cur_.s;
        if (s == "or")
            return 1;
        if (s == "and")
            return 2;
        if (s == "..")
            return 3;
        if (s == "+" || s == "-")
            return 4;
        if (s == "*" || s == "/" || s == "%")
            return 5;
        if (s == "^")
            return 6;
        if (s == "~=" || s == "==" || s == "<" || s == ">" || s == "<=" || s == ">=" || s == "~")
            return 3;
        return -1;
    }

    std::unique_ptr<Expr> parse_expr(int min_prec)
    {
        if (!ok_)
            return nullptr;
        std::unique_ptr<Expr> left = parse_unary();
        if (!left)
            return nullptr;
        for (;;)
        {
            int p = prec();
            if (p < min_prec || p < 0)
                break;
            std::string op = cur_.s;
            advance();
            std::unique_ptr<Expr> right = parse_expr((op == "^" || op == "..") ? p : p + 1);
            if (!right)
            {
                ok_ = false;
                return nullptr;
            }
            left = std::make_unique<BinaryE>(op, std::move(left), std::move(right));
        }
        return left;
    }

    std::unique_ptr<Expr> parse_unary()
    {
        if (!ok_)
            return nullptr;
        if (cur_.k == Tok::K::Op && (cur_.s == "-" || cur_.s == "not" || cur_.s == "#"))
        {
            std::string op = cur_.s;
            advance();
            std::unique_ptr<Expr> e = parse_unary();
            if (!e)
            {
                ok_ = false;
                return nullptr;
            }
            return std::make_unique<UnaryE>(op, std::move(e));
        }
        return parse_primary();
    }

    std::unique_ptr<Expr> parse_primary()
    {
        if (!ok_)
            return nullptr;
        switch (cur_.k)
        {
        case Tok::K::Num:
        {
            double v = cur_.num;
            advance();
            return std::make_unique<NumE>(v);
        }
        case Tok::K::Str:
        {
            std::string v = cur_.s;
            advance();
            return std::make_unique<StrE>(v);
        }
        case Tok::K::Name:
        {
            std::string name = cur_.s;
            advance();
            if (name == "true")
                return std::make_unique<BoolE>(true);
            if (name == "false")
                return std::make_unique<BoolE>(false);
            if (name == "nil")
                return std::make_unique<NilE>();
            if (cur_.k == Tok::K::LParen)
            {
                // call: fn(args...)
                advance();
                auto call = std::make_unique<CallE>();
                call->fn = std::move(name);
                if (cur_.k != Tok::K::RParen)
                {
                    for (;;)
                    {
                        std::unique_ptr<Expr> a = parse_expr(0);
                        if (!a)
                        {
                            ok_ = false;
                            return nullptr;
                        }
                        call->args.push_back(std::move(a));
                        if (cur_.k == Tok::K::Comma)
                            advance();
                        else
                            break;
                    }
                }
                if (cur_.k != Tok::K::RParen)
                {
                    ok_ = false;
                    return nullptr;
                }
                advance();
                return call;
            }
            if (cur_.k == Tok::K::LBracket)
            {
                // table index: keep opaque
                std::string text = name;
                advance();
                text += "[";
                while (ok_ && cur_.k != Tok::K::RBracket)
                {
                    text += cur_.s;
                    if (cur_.k == Tok::K::Str)
                        text = text; // s may contain escapes; acceptable
                    advance();
                }
                if (cur_.k != Tok::K::RBracket)
                {
                    ok_ = false;
                    return nullptr;
                }
                text += "]";
                advance();
                return std::make_unique<OpaqueE>(text);
            }
            return std::make_unique<NameE>(std::move(name));
        }
        case Tok::K::LParen:
        {
            advance();
            std::unique_ptr<Expr> e = parse_expr(0);
            if (!e || cur_.k != Tok::K::RParen)
            {
                ok_ = false;
                return nullptr;
            }
            advance();
            return std::make_unique<GroupE>(std::move(e));
        }
        default:
            ok_ = false;
            return nullptr;
        }
    }

    void advance()
    {
        cur_ = lx_.next();
        if (cur_.k == Tok::K::Op && cur_.s.size() == 1 &&
            !std::strchr("+-*/%^<>~=", cur_.s[0]) && cur_.s[0] != '?' && cur_.s != "and" && cur_.s != "or" &&
            cur_.s != "not")
        {
            ok_ = false; // unexpected punctuation
        }
    }

    const std::string& s_;
    Lexer lx_;
    Tok cur_;
    bool ok_ = true;
};

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

// Eval failure is signaled by this exception; the caller falls back to
// partial rendering (which still folds any constant subtree).
struct EvalFail
{
};

double to_atom(double v)
{
    return std::floor(v);
}

Const eval(const Expr& e, const std::map<std::string, Const>& env)
{
    if (const auto* n = dynamic_cast<const NumE*>(&e))
        return Const{CType::Number, n->v, 0, {}};
    if (const auto* s = dynamic_cast<const StrE*>(&e))
        return Const{CType::String, 0, 0, s->v};
    if (const auto* b = dynamic_cast<const BoolE*>(&e))
        return Const{CType::Bool, 0, b->v ? 1.0 : 0.0, {}};
    if (dynamic_cast<const NilE*>(&e))
        return Const{CType::Nil, 0, 0, {}};
    if (const auto* nm = dynamic_cast<const NameE*>(&e))
    {
        auto it = env.find(nm->v);
        if (it == env.end())
            throw EvalFail{};
        return it->second;
    }
    if (dynamic_cast<const OpaqueE*>(&e))
        throw EvalFail{};
    if (const auto* g = dynamic_cast<const GroupE*>(&e))
        return eval(*g->e, env);
    if (const auto* u = dynamic_cast<const UnaryE*>(&e))
    {
        Const c = eval(*u->e, env);
        if (u->op == "not")
            return Const{CType::Bool, 0, (c.type == CType::Nil || (c.type == CType::Bool && c.b == 0)) ? 1.0 : 0.0, {}};
        if (u->op == "-")
        {
            if (c.type != CType::Number)
                throw EvalFail{};
            return Const{CType::Number, -c.num, 0, {}};
        }
        if (u->op == "#")
        {
            if (c.type == CType::String)
                return Const{CType::Number, double(c.str.size()), 0, {}};
            throw EvalFail{};
        }
        throw EvalFail{};
    }
    if (const auto* b = dynamic_cast<const BinaryE*>(&e))
    {
        Const l = eval(*b->l, env);
        Const r = eval(*b->r, env);
        if (b->op == "and")
        {
            if (l.type == CType::Nil || (l.type == CType::Bool && l.b == 0))
                return l;
            return r;
        }
        if (b->op == "or")
        {
            if (l.type == CType::Nil || (l.type == CType::Bool && l.b == 0))
                return r;
            return l;
        }
        if (b->op == "..")
        {
            if (l.type != CType::String || r.type != CType::String)
                throw EvalFail{};
            return Const{CType::String, 0, 0, l.str + r.str};
        }
        if (l.type != CType::Number || r.type != CType::Number)
            throw EvalFail{};
        double a = l.num, c = r.num;
        if (b->op == "+")
            return Const{CType::Number, a + c, 0, {}};
        if (b->op == "-")
            return Const{CType::Number, a - c, 0, {}};
        if (b->op == "*")
            return Const{CType::Number, a * c, 0, {}};
        if (b->op == "/")
            return Const{CType::Number, a / c, 0, {}};
        if (b->op == "%")
            return Const{CType::Number, a - std::floor(a / c) * c, 0, {}};
        if (b->op == "^")
            return Const{CType::Number, std::pow(a, c), 0, {}};
        throw EvalFail{};
    }
    if (const auto* c = dynamic_cast<const CallE*>(&e))
    {
        std::vector<Const> args;
        for (const auto& a : c->args)
            args.push_back(eval(*a, env));
        const std::string& f = c->fn;
        auto need_num = [&](size_t i) -> double
        {
            if (i >= args.size() || args[i].type != CType::Number)
                throw EvalFail{};
            return args[i].num;
        };
        auto need_str = [&](size_t i) -> const std::string&
        {
            if (i >= args.size() || args[i].type != CType::String)
                throw EvalFail{};
            return args[i].str;
        };
        if (f == "math.floor")
            return Const{CType::Number, std::floor(need_num(0)), 0, {}};
        if (f == "math.ceil")
            return Const{CType::Number, std::ceil(need_num(0)), 0, {}};
        if (f == "math.abs")
            return Const{CType::Number, std::fabs(need_num(0)), 0, {}};
        if (f == "math.sqrt")
            return Const{CType::Number, std::sqrt(need_num(0)), 0, {}};
        if (f == "math.min")
        {
            double m = need_num(0);
            for (size_t i = 1; i < args.size(); ++i)
                m = std::min(m, need_num(i));
            return Const{CType::Number, m, 0, {}};
        }
        if (f == "math.max")
        {
            double m = need_num(0);
            for (size_t i = 1; i < args.size(); ++i)
                m = std::max(m, need_num(i));
            return Const{CType::Number, m, 0, {}};
        }
        if (f == "string.len")
            return Const{CType::Number, double(need_str(0).size()), 0, {}};
        if (f == "string.rep")
        {
            const std::string& s = need_str(0);
            double n = std::floor(need_num(1));
            if (n < 0 || n > 1e6)
                throw EvalFail{};
            std::string out;
            for (double i = 0; i < n; ++i)
                out += s;
            return Const{CType::String, 0, 0, out};
        }
        if (f == "string.lower")
        {
            std::string t = need_str(0);
            std::transform(t.begin(), t.end(), t.begin(), [](char ch) { return char(std::tolower(static_cast<unsigned char>(ch))); });
            return Const{CType::String, 0, 0, t};
        }
        if (f == "string.upper")
        {
            std::string t = need_str(0);
            std::transform(t.begin(), t.end(), t.begin(), [](char ch) { return char(std::toupper(static_cast<unsigned char>(ch))); });
            return Const{CType::String, 0, 0, t};
        }
        if (f == "tostring")
        {
            const Const& a = args[0];
            switch (a.type)
            {
            case CType::Nil: return Const{CType::String, 0, 0, "nil"};
            case CType::Bool: return Const{CType::String, 0, 0, a.b != 0 ? "true" : "false"};
            case CType::Number: return Const{CType::String, 0, 0, lure::lua_number_text(a.num)};
            case CType::String: return a;
            }
            throw EvalFail{};
        }
        if (f == "type")
        {
            switch (args[0].type)
            {
            case CType::Nil: return Const{CType::String, 0, 0, "nil"};
            case CType::Bool: return Const{CType::String, 0, 0, "boolean"};
            case CType::Number: return Const{CType::String, 0, 0, "number"};
            case CType::String: return Const{CType::String, 0, 0, "string"};
            }
            throw EvalFail{};
        }
        if (f == "tonumber")
        {
            const std::string& s = need_str(0);
            int base = args.size() > 1 ? int(std::floor(need_num(1))) : 10;
            if (base != 10 && base != 16 && base != 8 && base != 2)
                throw EvalFail{};
            char* end = nullptr;
            double v = std::strtod(s.c_str(), &end);
            if (base != 10)
                v = std::strtol(s.c_str(), &end, base);
            if (end == s.c_str() || (end && *end != 0))
                throw EvalFail{};
            return Const{CType::Number, v, 0, {}};
        }
        if (f == "string.byte")
        {
            const std::string& s = need_str(0);
            double i = args.size() > 1 ? to_atom(need_num(1)) : 1;
            double j = args.size() > 2 ? to_atom(need_num(2)) : i;
            if (i < 0)
                i = double(s.size()) + i + 1;
            if (j < 0)
                j = double(s.size()) + j + 1;
            i = std::max(1.0, i);
            j = std::min(double(s.size()), j);
            if (i != j || i < 1 || i > double(s.size()))
                throw EvalFail{}; // multi-byte results are not single-value calls
            return Const{CType::Number, double(static_cast<unsigned char>(s[size_t(i) - 1])), 0, {}};
        }
        if (f == "string.char")
        {
            std::string out;
            for (size_t i = 0; i < args.size(); ++i)
            {
                double v = need_num(i);
                if (v < 0 || v > 255)
                    throw EvalFail{};
                out += char(int(v));
            }
            return Const{CType::String, 0, 0, out};
        }
        if (f == "string.sub")
        {
            const std::string& s = need_str(0);
            double i = to_atom(need_num(1));
            double j = args.size() > 2 ? to_atom(need_num(2)) : double(s.size());
            if (i < 0)
                i = double(s.size()) + i + 1;
            if (j < 0)
                j = double(s.size()) + j + 1;
            i = std::max(1.0, std::min(i, double(s.size()) + 1));
            j = std::min(double(s.size()), std::max(j, 0.0));
            if (i > j)
                return Const{CType::String, 0, 0, ""};
            return Const{CType::String, 0, 0, s.substr(size_t(i) - 1, size_t(j - i + 1))};
        }
        throw EvalFail{};
    }
    throw EvalFail{};
}

// Renders an expression, folding every subtree that evaluates to a constant.
std::string fold_render(const Expr& e, const std::map<std::string, Const>& env)
{
    try
    {
        return const_text(eval(e, env));
    }
    catch (EvalFail&)
    {
        // fall through to structural rendering
    }
    if (const auto* g = dynamic_cast<const GroupE*>(&e))
        return "(" + fold_render(*g->e, env) + ")";
    if (const auto* u = dynamic_cast<const UnaryE*>(&e))
    {
        if (u->op == "not")
            return "not " + fold_render(*u->e, env);
        return u->op + fold_render(*u->e, env);
    }
    if (const auto* b = dynamic_cast<const BinaryE*>(&e))
        return fold_render(*b->l, env) + " " + b->op + " " + fold_render(*b->r, env);
    if (const auto* c = dynamic_cast<const CallE*>(&e))
    {
        std::string s = c->fn + "(";
        for (size_t i = 0; i < c->args.size(); ++i)
        {
            if (i)
                s += ", ";
            s += fold_render(*c->args[i], env);
        }
        return s + ")";
    }
    return e.render();
}

bool is_simple_name(const std::string& s)
{
    if (s.empty())
        return false;
    if (s.rfind("upval_[", 0) == 0)
        return false;
    for (char c : s)
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_')
            return false;
    return !std::isdigit(static_cast<unsigned char>(s[0]));
}

} // namespace

// ---------------------------------------------------------------------------

void fold_constants(TraceData& trace)
{
    std::map<std::string, Const> env;

    for (TraceEvent& ev : trace.events)
    {
        const std::string& t = ev.text;
        size_t eq = t.find(" = ");
        if (eq == std::string::npos || eq == 0)
            continue;
        std::string lhs = t.substr(0, eq);
        if (!is_simple_name(lhs))
            continue; // table stores, globals, upval stores: not folded
        std::string rhs = t.substr(eq + 3);
        if (rhs.find(".. ... ..") != std::string::npos)
            continue; // variadic concat sketch: skip
        if (rhs == "function" || rhs == "{}" || rhs == "nil" || rhs == "true" || rhs == "false")
            continue; // already minimal

        Parser p(rhs);
        std::unique_ptr<Expr> expr = p.parse();
        if (!expr)
            continue; // keep the text as recorded (incl. "?" operands)

        try
        {
            Const c = eval(*expr, env);
            ev.text = lhs + " = " + const_text(c);
            env[lhs] = c;
        }
        catch (EvalFail&)
        {
            std::string folded = fold_render(*expr, env);
            if (folded != rhs)
                ev.text = lhs + " = " + folded;
            env.erase(lhs); // not proven constant anymore; stop propagating it
        }
    }
}

} // namespace lure::reconstruct
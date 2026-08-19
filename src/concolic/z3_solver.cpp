// concolic/z3_solver.cpp
// Z3 backend for the Layer-4 feasibility checks. The DSL subset modeled here
// is deliberately small: unary polarity terms and two-operand comparisons
// over variables or numeric literals. Anything else yields Unknown (never a
// guess). All unknown names are independent uninterpreted constants, which is
// the honest semantics: the trace observed values, not relations.

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <z3++.h>

#include "concolic/solver.hpp"

namespace lure::concolic {

namespace {

struct Model
{
    bool supported = true;
    std::string unsupported_note;
    std::map<std::string, z3::expr> real_vars;
    std::map<std::string, z3::expr> bool_vars;
    std::vector<std::string> decl_order;
};

bool is_name(const std::string& s);
z3::expr operand(z3::context& ctx, Model& m, const std::string& name);

std::string trim(const std::string& s)
{
    size_t a = s.find_first_not_of(" \t");
    if (a == std::string::npos)
        return "";
    size_t b = s.find_last_not_of(" \t");
    return s.substr(a, b - a + 1);
}

bool is_number(const std::string& s)
{
    if (s.empty())
        return false;
    const char* p = s.c_str();
    char* end = nullptr;
    std::strtod(p, &end);
    return end && end != p && *end == '\0';
}

// Builds a z3 expression for the DSL condition `dsl` in `model`. On anything
// outside the modeled subset, marks the model unsupported and returns nullptr.
z3::expr parse_expr(z3::context& ctx, Model& m, const std::string& dsl_raw)
{
    std::string dsl = trim(dsl_raw);
    if (dsl.empty())
    {
        m.supported = false;
        m.unsupported_note = "empty condition";
        return ctx.bool_val(true);
    }

    bool negated = false;
    if (dsl.rfind("not ", 0) == 0)
    {
        negated = true;
        dsl = trim(dsl.substr(4));
    }

    // two-operand comparisons
    std::string ops[] = {"==", "~=", "<=", ">=", "<", ">"};
    size_t opos = std::string::npos;
    std::string op;
    for (const std::string& o : ops)
    {
        size_t p = dsl.find(o);
        if (p != std::string::npos)
        {
            opos = p;
            op = o;
            break;
        }
    }

    z3::expr e = ctx.bool_val(true);

    if (opos != std::string::npos)
    {
        std::string lhs = trim(dsl.substr(0, opos));
        std::string rhs = trim(dsl.substr(opos + op.size()));
        if (lhs.empty() || rhs.empty() || !is_name(lhs) || !is_name(rhs))
        {
            m.supported = false;
            m.unsupported_note = "malformed comparison: " + dsl_raw;
            return ctx.bool_val(true);
        }
        z3::expr a = operand(ctx, m, lhs);
        z3::expr b = operand(ctx, m, rhs);
        if (!m.supported)
            return ctx.bool_val(true);
        if (op == "==")
            e = a == b;
        else if (op == "~=")
            e = a != b;
        else if (op == "<=")
            e = a <= b;
        else if (op == ">=")
            e = a >= b;
        else if (op == "<")
            e = a < b;
        else
            e = a > b;
    }
    else
    {
        // bare term: boolean constant/variable or unmodeled type
        if (dsl == "true")
            e = ctx.bool_val(true);
        else if (dsl == "false")
            e = ctx.bool_val(false);
        else if (is_number(dsl))
        {
            m.supported = false;
            m.unsupported_note = "bare numeric literal is not a condition: " + dsl_raw;
            return ctx.bool_val(true);
        }
        else if (!is_name(dsl))
        {
            m.supported = false;
            m.unsupported_note = "unrecognized term: " + dsl_raw;
            return ctx.bool_val(true);
        }
        else
        {
            // a name used elsewhere numerically cannot be a bare truth test
            // without inventing truthiness semantics; do not guess
            if (m.real_vars.count(dsl))
            {
                m.supported = false;
                m.unsupported_note = "numeric variable used as bare truth test: " + dsl;
                return ctx.bool_val(true);
            }
            auto it = m.bool_vars.find(dsl);
            if (it == m.bool_vars.end())
            {
                z3::expr v = ctx.bool_const(dsl.c_str());
                m.bool_vars.emplace(dsl, v);
                m.decl_order.push_back(dsl);
            }
            e = m.bool_vars.at(dsl);
        }
    }

    return negated ? !e : e;
}

z3::expr operand(z3::context& ctx, Model& m, const std::string& name)
{
    if (is_number(name))
        return ctx.real_val(name.c_str());
    if (is_name(name))
    {
        if (m.bool_vars.count(name))
        {
            m.supported = false;
            m.unsupported_note = "boolean variable used numerically: " + name;
            return ctx.bool_val(true);
        }
        auto it = m.real_vars.find(name);
        if (it == m.real_vars.end())
        {
            z3::expr v = ctx.real_const(name.c_str());
            m.real_vars.emplace(name, v);
            m.decl_order.push_back(name);
        }
        return m.real_vars.at(name);
    }
    m.supported = false;
    m.unsupported_note = "invalid operand: " + name;
    return ctx.bool_val(true);
}

bool is_name(const std::string& s)
{
    if (s.empty())
        return false;
    for (char c : s)
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_'))
            return false;
    return true;
}

std::string model_text(z3::model& m, const Model& mm)
{
    std::string out;
    for (const std::string& n : mm.decl_order)
    {
        z3::expr v = m.eval(mm.real_vars.count(n) ? mm.real_vars.at(n) : mm.bool_vars.at(n), true);
        if (!out.empty())
            out += ", ";
        out += n + "=" + v.to_string();
    }
    return out;
}

class Z3Solver : public Solver
{
public:
    CheckResult check(const std::vector<std::string>& conds,
        const std::vector<bool>& pol, const std::string& query, std::string& err) override
    {
        CheckResult r;
        try
        {
            z3::context ctx;
            Model m;
            z3::expr_vector asserts(ctx);
            for (size_t i = 0; i < conds.size(); ++i)
            {
                z3::expr e = parse_expr(ctx, m, conds[i]);
                if (!m.supported)
                {
                    r.verdict = Verdict::Unknown;
                    r.note = "unsupported prefix clause: " + m.unsupported_note;
                    return r;
                }
                asserts.push_back(pol[i] ? e : !e);
            }
            z3::expr q = parse_expr(ctx, m, query);
            if (!m.supported)
            {
                r.verdict = Verdict::Unknown;
                r.note = "unsupported query clause: " + m.unsupported_note;
                return r;
            }

            z3::solver s(ctx);
            for (unsigned i = 0; i < asserts.size(); ++i)
                s.add(asserts[i]);
            s.add(!q);

            z3::check_result res = s.check();
            if (res == z3::sat)
            {
                r.verdict = Verdict::Sat;
                z3::model mdl = s.get_model();
                r.model = model_text(mdl, m);
            }
            else if (res == z3::unsat)
                r.verdict = Verdict::Unsat;
            else
            {
                r.verdict = Verdict::Unknown;
                r.note = "solver returned undef";
            }
        }
        catch (const z3::exception& ex)
        {
            r.verdict = Verdict::Unknown;
            r.note = std::string("z3 exception: ") + ex.msg();
        }
        catch (...)
        {
            r.verdict = Verdict::Unknown;
            r.note = "unknown solver failure";
        }
        return r;
    }

    std::string name() const override { return "z3"; }
};

} // namespace

std::unique_ptr<Solver> create_z3_solver()
{
    return std::make_unique<Z3Solver>();
}

} // namespace lure::concolic
// reconstruct/pretty.cpp
#include "reconstruct/pretty.hpp"

#include <sstream>
#include <string>
#include <vector>

namespace lure::reconstruct {

namespace {

class Emitter
{
public:
    PrettyResult run(const StNodePtr& root)
    {
        out_.str("");
        notfound_.clear();
        walk(*root, 0, "script");
        PrettyResult r;
        r.lua = out_.str();
        r.notfound = std::move(notfound_);
        return r;
    }

private:
    std::ostringstream out_;
    std::vector<NotfoundEntry> notfound_;
    uint32_t line_ = 0; // current output line (1-based)

    void emit_line(const std::string& s)
    {
        out_ << s << '\n';
        ++line_;
    }

    void note(const std::string& where, const std::string& reason)
    {
        NotfoundEntry e;
        e.lua_line = line_ + 1; // the comment is about to be emitted
        e.where = where;
        e.reason = reason;
        notfound_.push_back(std::move(e));
        emit_line("    -- not found: " + reason);
    }

    static std::string indent(int depth)
    {
        return std::string(static_cast<size_t>(depth) * 4, ' ');
    }

    void walk(const StNode& n, int depth, const std::string& where)
    {
        switch (n.k)
        {
        case StNode::K::Seq:
        {
            std::string w = where;
            if (w == "script" && !n.children.empty())
                w = "script";
            for (const StNodePtr& c : n.children)
                walk(*c, depth, w);
            break;
        }
        case StNode::K::Plain:
        {
            std::string body = n.text.empty() ? n.tag : n.text;
            emit_line(indent(depth) + body);
            break;
        }
        case StNode::K::Notfound:
        {
            note(where, n.annotation);
            break;
        }
        case StNode::K::If:
        {
            emit_line(indent(depth) + "if " + n.cond + " then");
            if (n.then_b)
                walk(*n.then_b, depth + 1, "if");
            if (n.else_b)
            {
                if (n.else_b->k == StNode::K::Notfound)
                    note("if at line ~" + std::to_string(line_), n.else_b->annotation);
                else
                {
                    emit_line(indent(depth) + "else");
                    walk(*n.else_b, depth + 1, "if-else");
                }
            }
            emit_line(indent(depth) + "end");
            break;
        }
        case StNode::K::While:
        {
            emit_line(indent(depth) + "while " + n.cond + " do");
            if (n.body && !n.body->children.empty())
                walk(*n.body, depth + 1, "while");
            else
                note("while at line ~" + std::to_string(line_),
                    "loop body executed no recorded statements (empty or unsampled)");
            emit_line(indent(depth) + "end");
            break;
        }
        case StNode::K::NumericFor:
        {
            std::string header = indent(depth) + "for " + n.loop_var + " = " + n.lo_text;
            if (!n.step_text.empty())
                header += ", " + n.hi_text + ", " + n.step_text;
            else if (!n.hi_text.empty())
                header += ", " + n.hi_text;
            emit_line(header + " do");
            if (!n.lo_note.empty())
                note("for " + n.loop_var, n.lo_note);
            if (!n.step_note.empty())
                note("for " + n.loop_var, n.step_note);
            if (n.body && !n.body->children.empty())
                walk(*n.body, depth + 1, "for " + n.loop_var);
            emit_line(indent(depth) + "end");
            break;
        }
        }
    }
};

} // namespace

Resolved<PrettyResult> pretty_print(const StNodePtr& root)
{
    Emitter e;
    PrettyResult r = e.run(root);
    if (r.lua.empty())
        return Resolved<PrettyResult>::failure("reconstruction produced no output");
    return Resolved<PrettyResult>::success(std::move(r));
}

} // namespace lure::reconstruct
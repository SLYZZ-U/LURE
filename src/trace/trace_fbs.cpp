// trace/trace_fbs.cpp
#include "trace/trace_fbs.hpp"

#include "trace_generated.h"

#include <flatbuffers/flatbuffers.h>

// The schema namespace is lure::trace; every generated type is referenced
// fully qualified because lure::TraceEvent etc. (trace_events.hpp) live in the
// parent namespace and would otherwise be ambiguous.

namespace lure::trace_fbs {

class TraceWriter::Impl
{
public:
    flatbuffers::FlatBufferBuilder builder;
};

TraceWriter::TraceWriter()
    : impl_(new Impl)
{
}

TraceWriter::~TraceWriter()
{
    delete impl_;
}

std::string TraceWriter::build(const TraceData& data)
{
    auto& fbb = impl_->builder;
    fbb.Clear();

    std::vector<flatbuffers::Offset<lure::trace::TraceEvent>> event_offsets;
    event_offsets.reserve(data.events.size());

    for (const TraceEvent& e : data.events)
    {
        auto mk_snapshot = [&](const LuaValueSnapshot& s)
        {
            return lure::trace::CreateLuaValueSnapshot(fbb, static_cast<lure::trace::ValueType>(s.type),
                fbb.CreateString(s.text), s.nvalue, fbb.CreateString(s.unres_reason));
        };

        std::vector<flatbuffers::Offset<lure::trace::LuaValueSnapshot>> stack_offsets;
        stack_offsets.reserve(e.stack.size());
        for (const auto& s : e.stack)
            stack_offsets.push_back(mk_snapshot(s));
        auto stack_vec = fbb.CreateVector(stack_offsets);

        std::vector<flatbuffers::Offset<lure::trace::LuaValueSnapshot>> locals_offsets;
        locals_offsets.reserve(e.locals.size());
        for (const auto& s : e.locals)
            locals_offsets.push_back(mk_snapshot(s));
        auto locals_vec = fbb.CreateVector(locals_offsets);

        flatbuffers::Offset<lure::trace::CallInfo> call_off = 0;
        if (e.call_info.has_value())
        {
            const CallInfo& ci = *e.call_info;
            std::vector<flatbuffers::Offset<lure::trace::LuaValueSnapshot>> args_offsets;
            args_offsets.reserve(ci.args.size());
            for (const auto& a : ci.args)
                args_offsets.push_back(mk_snapshot(a));
            call_off = lure::trace::CreateCallInfo(fbb, mk_snapshot(ci.fn), fbb.CreateVector(args_offsets),
                ci.nresults, fbb.CreateString(ci.native_name));
        }

        flatbuffers::Offset<lure::trace::TableOpInfo> table_off = 0;
        if (e.table_op.has_value())
        {
            const TableOpInfo& t = *e.table_op;
            table_off = lure::trace::CreateTableOpInfo(
                fbb, mk_snapshot(t.table), mk_snapshot(t.key), mk_snapshot(t.value), t.is_set);
        }

        auto ev = lure::trace::CreateTraceEvent(fbb, e.pc, e.opcode, e.line, e.call_depth, fbb.CreateString(e.tag),
            fbb.CreateString(e.text), stack_vec, locals_vec, call_off, table_off, e.is_branch, fbb.CreateString(e.cond_dsl),
            fbb.CreateString(e.cond_text), e.branch_taken, e.jump_target, e.other_target,
            static_cast<lure::trace::ResolutionStatus>(e.status), fbb.CreateString(e.notfound_reason),
            e.printed_output, e.insn, e.frame_id, e.cond_rhs_reg, e.proto_id,
            fbb.CreateString(e.k_text));
        event_offsets.push_back(ev);
    }

    auto events_vec = fbb.CreateVector(event_offsets);
    auto root = lure::trace::CreateTraceFile(fbb, fbb.CreateString(data.source_script), fbb.CreateString(data.mode),
        fbb.CreateString(data.vm_kind), events_vec);
    fbb.Finish(root);

    return std::string(reinterpret_cast<const char*>(fbb.GetBufferPointer()), fbb.GetSize());
}

static LuaValueSnapshot from_fbs(const lure::trace::LuaValueSnapshot* s)
{
    LuaValueSnapshot out;
    if (!s)
        return out;
    out.type = static_cast<lure::ValueType>(s->vtype());
    if (s->text())
        out.text = s->text()->str();
    out.nvalue = s->nvalue();
    if (s->unres_reason())
        out.unres_reason = s->unres_reason()->str();
    return out;
}

bool parse_trace(const std::string& bytes, TraceData& out, std::string& err)
{
    flatbuffers::Verifier verifier(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
    if (!lure::trace::VerifyTraceFileBuffer(verifier))
    {
        err = "trace buffer verification failed";
        return false;
    }

    const lure::trace::TraceFile* file = lure::trace::GetTraceFile(bytes.data());
    out.source_script = file->source_script() ? file->source_script()->str() : "";
    out.mode = file->mode() ? file->mode()->str() : "";
    out.vm_kind = file->vm_kind() ? file->vm_kind()->str() : "";

    if (const auto* events = file->events())
    {
        out.events.reserve(events->size());
        for (const auto* ev : *events)
        {
            if (!ev)
            {
                err = "trace contains a null event";
                return false;
            }
            TraceEvent e;
            e.pc = ev->pc();
            e.opcode = ev->opcode();
            e.line = ev->line();
            e.call_depth = ev->call_depth();
            e.tag = ev->tag() ? ev->tag()->str() : "";
            e.text = ev->text() ? ev->text()->str() : "";
            if (const auto* st = ev->stack())
                for (const auto* s : *st)
                    e.stack.push_back(from_fbs(s));
            if (const auto* lo = ev->locals())
                for (const auto* s : *lo)
                    e.locals.push_back(from_fbs(s));
            if (const auto* c = ev->call())
            {
                CallInfo ci;
                ci.fn = from_fbs(c->fn());
                if (const auto* args = c->args())
                    for (const auto* a : *args)
                        ci.args.push_back(from_fbs(a));
                ci.nresults = c->nresults();
                ci.native_name = c->native_name() ? c->native_name()->str() : "";
                e.call_info = std::move(ci);
            }
            if (const auto* t = ev->table_op())
            {
                TableOpInfo ti;
                ti.table = from_fbs(t->table());
                ti.key = from_fbs(t->key());
                ti.value = from_fbs(t->value());
                ti.is_set = t->is_set();
                e.table_op = std::move(ti);
            }
            e.is_branch = ev->is_branch();
            e.cond_dsl = ev->cond_dsl() ? ev->cond_dsl()->str() : "";
            e.cond_text = ev->cond_text() ? ev->cond_text()->str() : "";
            e.branch_taken = ev->branch_taken();
            e.jump_target = ev->jump_target();
            e.other_target = ev->other_target();
            e.status = static_cast<lure::ResolutionStatus>(ev->status());
            e.notfound_reason = ev->notfound_reason() ? ev->notfound_reason()->str() : "";
            e.printed_output = ev->printed_output();
            e.insn = ev->insn();
            e.frame_id = ev->frame_id();
            e.cond_rhs_reg = ev->cond_rhs_reg();
            e.proto_id = ev->proto_id();
            e.k_text = ev->k_text() ? ev->k_text()->str() : "";
            out.events.push_back(std::move(e));
        }
    }

    return true;
}

} // namespace lure::trace_fbs
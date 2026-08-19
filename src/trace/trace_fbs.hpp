#pragma once
// trace/trace_fbs.hpp
// FlatBuffers serialization of TraceData (trace.fbs -> generated trace_generated.h).

#include <cstdint>
#include <string>

#include "trace/trace_events.hpp"

namespace lure::trace_fbs {

// Serializes a full TraceData into a FlatBuffer; returns the buffer owned by
// the caller (FlatBufferBuilder is returned by value through a shared wrapper).
class TraceWriter
{
public:
    TraceWriter();  // owns the builder
    ~TraceWriter();
    TraceWriter(const TraceWriter&) = delete;
    TraceWriter& operator=(const TraceWriter&) = delete;

    std::string build(const TraceData& data);

private:
    class Impl;
    Impl* impl_;
};

// Deserializes a FlatBuffer previously written by TraceWriter.
bool parse_trace(const std::string& bytes, TraceData& out, std::string& err);

} // namespace lure::trace_fbs
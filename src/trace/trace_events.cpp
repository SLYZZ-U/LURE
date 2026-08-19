// trace/trace_events.cpp
#include "trace/trace_events.hpp"

#include <cmath>
#include <cstdio>

namespace lure {

LuaValueSnapshot value_from_number(double v)
{
    LuaValueSnapshot s;
    s.type = ValueType::Number;
    s.nvalue = v;
    s.text = lua_number_text(v);
    return s;
}

LuaValueSnapshot value_from_string(std::string sv)
{
    LuaValueSnapshot s;
    s.type = ValueType::String;
    s.text = std::move(sv);
    return s;
}

std::string lua_number_text(double v)
{
    if (std::isnan(v))
        return "-nan";
    if (std::isinf(v))
        return v > 0 ? "inf" : "-inf";
    double integral = 0.0;
    if (std::modf(v, &integral) == 0.0 && std::abs(v) < 1e15)
    {
        long long i = static_cast<long long>(v);
        return std::to_string(i);
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.14g", v);
    return buf;
}

} // namespace lure
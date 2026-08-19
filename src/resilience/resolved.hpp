#pragma once
// resilience/resolved.hpp
// The explicit resolution-result type mandated by section 7 of the LURE spec:
// every resolution function returns Resolved<T>; it never throws and never
// guesses. Call sites must handle both branches.

#include <string>
#include <utility>

namespace lure {

template <typename T>
struct Resolved
{
    bool ok = false;
    T value{};
    std::string reason;

    static Resolved success(T v)
    {
        return Resolved{true, std::move(v), {}};
    }

    static Resolved failure(std::string r)
    {
        return Resolved{false, T{}, std::move(r)};
    }

    explicit operator bool() const { return ok; }
    const T* operator->() const { return &value; }
    T& operator*() { return value; }
    const T& operator*() const { return value; }
};

// void specialization: no value payload, success() carries no argument.
template <>
struct Resolved<void>
{
    bool ok = false;
    std::string reason;

    static Resolved success()
    {
        return Resolved{true, {}};
    }

    static Resolved failure(std::string r)
    {
        return Resolved{false, std::move(r)};
    }

    explicit operator bool() const { return ok; }
};

} // namespace lure
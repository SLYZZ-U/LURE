#pragma once
// rbx_emulator/core/ostub/api_stub.hpp
// The standalone Windows-API emulation layer.
//
// Every imported function resolves to a slot inside the guest's stub arena;
// a UC_HOOK_CODE over that arena intercepts the call, looks up the import by
// its slot index and re-implements the API against emulated memory. The guest
// calling convention (Win64: RCX,RDX,R8,R9, stack) and the Win64 ABI rules
// (volatile RAX,RCX,RDX,R8..R11; non-volatile RBX,RBP,RSI,RDI,R12..R15, RSP)
// are respected: the stub implementations only touch volatile state.

#include <string>
#include <vector>

#include "core/guest/guest.hpp"

namespace lure::emu {

// Installs the code hook that intercepts the stub arena. Called by
// GuestSession::create after the arena exists.
Resolved<void> api_stub_install(GuestSession* g);

// The API log: one entry per intercepted call, in order.
struct ApiCallRecord
{
    uint64_t seq = 0;
    std::string dll;
    std::string name;
    std::vector<std::string> args; // positional, host-formatted
    std::string ret;
};

struct ApiLog
{
    std::vector<ApiCallRecord> calls;
    size_t cap = 1'000'000;
    void record(ApiCallRecord r) { if (calls.size() < cap) calls.push_back(std::move(r)); }
};

ApiLog& api_log();

} // namespace lure::emu
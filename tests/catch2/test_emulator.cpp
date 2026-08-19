// tests/catch2/test_emulator.cpp
// rbx_emulator end-to-end smoke tests: a hand-assembled x64 PE is parsed,
// mapped into the Unicorn guest, its single import is resolved to a stub slot
// and dispatched by the API hook when the guest calls it.

#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <vector>

#include <unicorn/unicorn.h>

#include "core/guest/guest.hpp"
#include "core/ostub/api_stub.hpp"

namespace {

using lure::emu::GuestSession;
using lure::emu::GuestOptions;

// A tiny PE32+ with one .text section (entry at RVA 0x1000) and a writable
// .idata section carrying a single import: kernel32.dll!GetCurrentProcessId.
// Layout (all offsets raw-file):
//   headers @0x000..0x188 (DOS + PE + optional + 2 section headers)
//   .text    raw @0x400, rva 0x1000, vsize 0x200, chars 0x60000020
//   .idata   raw @0x600, rva 0x2000, vsize 0x200, chars 0xC0000040
//     import descriptor @0x600, terminator @0x614
//     INT @0x628 -> 0x2038 (hint/name), IAT @0x630 -> 0x2038 (patched at run)
//     hint+name @0x638 "GetCurrentProcessId", dll name @0x64E "kernel32.dll"
std::vector<uint8_t> build_smoke_pe()
{
    std::vector<uint8_t> pe(0x800, 0);
    auto wr = [&](size_t off, const void* src, size_t n) { std::memcpy(pe.data() + off, src, n); };
    auto wr16 = [&](size_t off, uint16_t v) { wr(off, &v, 2); };
    auto wr32 = [&](size_t off, uint32_t v) { wr(off, &v, 4); };
    auto wr64 = [&](size_t off, uint64_t v) { wr(off, &v, 8); };
    auto str = [&](size_t off, const char* s) { wr(off, s, std::strlen(s) + 1); }; // incl. NUL

    // DOS header + e_lfanew
    str(0x00, "MZ");
    wr32(0x3C, 0x80);

    // PE signature + COFF file header
    str(0x80, "PE\0\0");
    wr16(0x84, 0x8664); // machine x64
    wr16(0x86, 2);      // number of sections
    wr16(0x94, 0xF0);   // size of optional header
    wr16(0x96, 0x0022); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // Optional header PE32+
    wr16(0x98, 0x20B);
    wr32(0x9C, 0x200);            // size of code
    wr32(0xA0, 0x200);            // size of initialized data
    wr32(0xA8, 0x1000);           // entry RVA
    wr32(0xAC, 0x1000);           // base of code
    wr64(0xB0, 0x140000000ull);   // image base
    wr32(0xB8, 0x1000);           // section alignment
    wr32(0xBC, 0x200);            // file alignment
    wr32(0xC8, 6);                // major subsystem version
    wr32(0xD0, 0x3000);           // size of image
    wr32(0xD4, 0x400);            // size of headers
    wr16(0xDC, 3);                // subsystem: console
    wr64(0xE0, 0x100000);         // stack reserve
    wr64(0xE8, 0x1000);           // stack commit
    wr64(0xF0, 0x100000);         // heap reserve
    wr64(0xF8, 0x1000);           // heap commit
    wr32(0x104, 16);              // number of data directories
    // data directory [1] import table
    wr32(0x108 + 8, 0x2000);
    wr32(0x108 + 12, 40);
    // data directory [12] IAT
    wr32(0x108 + 96, 0x2030);
    wr32(0x108 + 100, 8);

    // Section headers @0x188
    str(0x188, ".text");
    wr32(0x188 + 8, 0x200);       // virtual size
    wr32(0x188 + 12, 0x1000);     // virtual address
    wr32(0x188 + 16, 0x200);      // raw size
    wr32(0x188 + 20, 0x400);      // raw pointer
    wr32(0x188 + 36, 0x60000020); // CODE|EXECUTE|READ
    str(0x188 + 40, ".idata");
    wr32(0x188 + 48, 0x200);
    wr32(0x188 + 52, 0x2000);
    wr32(0x188 + 56, 0x200);
    wr32(0x188 + 60, 0x600);
    wr32(0x188 + 76, 0xC0000040); // INITIALIZED_DATA|READ|WRITE

    // Raw .text: placeholder NOPs; the test patches mov/jmp over them.
    for (size_t i = 0; i < 0x200; ++i)
        pe[0x400 + i] = 0x90;

    // Raw .idata
    wr32(0x600, 0x2028); // original first thunk (INT)
    wr32(0x600 + 12, 0x204E); // dll name RVA
    wr32(0x600 + 16, 0x2030); // first thunk (IAT)
    wr64(0x628, 0x2038); // INT entry -> hint/name
    wr64(0x630, 0x2038); // IAT entry (file view; loader patches this)
    wr16(0x638, 0);      // hint
    str(0x63A, "GetCurrentProcessId"); // 19 chars + NUL ends at 0x64E
    str(0x64E, "kernel32.dll");

    return pe;
}

} // namespace

TEST_CASE("smoke PE parses and maps into the guest")
{
    std::vector<uint8_t> pe = build_smoke_pe();
    auto g = GuestSession::create(pe.data(), pe.size(), GuestOptions{});
    if (!g.ok)
        FAIL(g.reason);
    REQUIRE(g.ok);
    REQUIRE(g.value->image().image_base == 0x140000000ull);
    REQUIRE(g.value->image().imports.size() == 1);
    REQUIRE(g.value->image().imports[0].name == "kernel32.dll");
    REQUIRE(g.value->image().imports[0].functions.size() == 1);
    REQUIRE(g.value->image().imports[0].functions[0].name == "GetCurrentProcessId");

    // The loader wrote a stub slot into the IAT inside guest memory.
    auto iat = g.value->read_u64(g.value->image_base() + 0x2030);
    REQUIRE(iat.ok);
    REQUIRE(iat.value != 0);
    REQUIRE(iat.value >= g.value->stub_arena());
}

TEST_CASE("guest calls an import and the API hook dispatches it")
{
    lure::emu::api_log().calls.clear();
    std::vector<uint8_t> pe = build_smoke_pe();
    auto g = GuestSession::create(pe.data(), pe.size(), GuestOptions{});
    REQUIRE(g.ok);

    auto iat = g.value->read_u64(g.value->image_base() + 0x2030);
    REQUIRE(iat.ok);
    REQUIRE(iat.value != 0);

    // Entry: mov rax, <stub slot>; jmp rax  (call through the resolved IAT).
    std::vector<uint8_t> code;
    code.push_back(0x48);
    code.push_back(0xB8);
    for (int i = 0; i < 8; ++i)
        code.push_back(uint8_t(iat.value >> (8 * i)));
    code.push_back(0xFF);
    code.push_back(0xE0);
    REQUIRE(g.value->write_mem(g.value->image_base() + 0x1000, code.data(), code.size()).ok);

    // Run 3 instructions: mov, jmp, ret-at-stub (the hook fires before it).
    // Give the RET a mapped return frame (the initial RSP points one byte
    // past the last mapped page).
    auto r = g.value->regs();
    REQUIRE(r.ok);
    std::vector<uint8_t> zero(32, 0);
    REQUIRE(g.value->write_mem(r.value.rsp - 32, zero.data(), zero.size()).ok);
    r.value.rsp -= 32;
    REQUIRE(g.value->set_regs(r.value).ok);
    uc_err e = uc_emu_start(g.value->uc(), r.value.rip, 0, 0, 3);
    REQUIRE(e == UC_ERR_OK);

    auto regs = g.value->regs();
    REQUIRE(regs.ok);
    REQUIRE(regs.value.rax == 1337); // GetCurrentProcessId returns the fake pid

    const auto& log = lure::emu::api_log();
    REQUIRE(log.calls.size() == 1);
    REQUIRE(log.calls[0].dll == "kernel32.dll");
    REQUIRE(log.calls[0].name == "GetCurrentProcessId");
    REQUIRE(log.calls[0].ret == "0x539");
}

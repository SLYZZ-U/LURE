// rbx_emulator/core/ostub/api_stub.cpp
// Standalone Windows-API emulation layer.
//
// Every imported function resolves to a guest stub slot; a UC_HOOK_CODE over
// the stub arena intercepts the call and re-implements the API against
// emulated memory. Win64 ABI: args in RCX,RDX,R8,R9 then stack; only volatile
// registers are touched by implementations (RAX plus explicit writes).

#include "core/ostub/api_stub.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>

#include <unicorn/unicorn.h>

namespace lure::emu {

namespace {

std::string hex64(uint64_t v)
{
    char b[24];
    std::snprintf(b, sizeof(b), "0x%llx", static_cast<unsigned long long>(v));
    return b;
}

// ---------------------------------------------------------------------------
// Call context: guest ABI reads + safe guest memory helpers
// ---------------------------------------------------------------------------

struct Ctx
{
    GuestSession* g = nullptr;
    uint64_t rcx = 0, rdx = 0, r8 = 0, r9 = 0, rsp = 0;

    static Ctx read(GuestSession* g)
    {
        Ctx c;
        c.g = g;
        uc_engine* uc = g->uc();
        uc_reg_read(uc, UC_X86_REG_RCX, &c.rcx);
        uc_reg_read(uc, UC_X86_REG_RDX, &c.rdx);
        uc_reg_read(uc, UC_X86_REG_R8, &c.r8);
        uc_reg_read(uc, UC_X86_REG_R9, &c.r9);
        uc_reg_read(uc, UC_X86_REG_RSP, &c.rsp);
        return c;
    }

    void set_rax(uint64_t v) const { uc_reg_write(g->uc(), UC_X86_REG_RAX, &v); }
    void set_rdx(uint64_t v) const { uc_reg_write(g->uc(), UC_X86_REG_RDX, &v); }
    void set_r8(uint64_t v) const { uc_reg_write(g->uc(), UC_X86_REG_R8, &v); }

    void write_ptr(uint64_t dst, uint64_t v) const { g->write_u64(dst, v); }
    void write_u32_at(uint64_t dst, uint32_t v) const { g->write_u32(dst, v); }

    // Reads a NUL-terminated guest string (bounded).
    std::string cstr(uint64_t addr, size_t cap = 4096) const
    {
        std::string s;
        if (addr == 0)
            return s;
        s.reserve(128);
        for (size_t i = 0; i < cap; ++i)
        {
            uint8_t b = 0;
            if (!g->read_mem(addr + i, &b, 1).ok)
                break;
            if (b == 0)
                break;
            s.push_back(char(b));
        }
        return s;
    }

    std::string wstr(uint64_t addr, size_t cap = 4096) const
    {
        std::string s;
        for (size_t i = 0; i < cap; ++i)
        {
            uint16_t c = 0;
            if (!g->read_mem(addr + 2 * i, &c, 2).ok)
                break;
            if (c == 0)
                break;
            s.push_back(c < 0x80 ? char(c) : '?');
        }
        return s;
    }

    uint64_t write_wstr_to(const std::string& s) const
    {
        uint64_t a = g->valloc((s.size() + 1) + 2, false);
        if (!a)
            return 0;
        std::vector<uint16_t> buf;
        for (char ch : s)
            buf.push_back(uint16_t(uint8_t(ch)));
        buf.push_back(0);
        g->write_mem(a, buf.data(), buf.size() * 2);
        return a;
    }

    uint64_t write_cstr_to(const std::string& s) const
    {
        uint64_t a = g->valloc(s.size() + 1, false);
        if (!a)
            return 0;
        g->write_mem(a, s.data(), s.size() + 1);
        return a;
    }

    void stop(uint32_t code) const
    {
        g->exited = true;
        g->exit_code = int32_t(code);
        uc_emu_stop(g->uc());
    }
};

using Impl = void (*)(const Ctx&);

// ---------------------------------------------------------------------------
// API implementations
// ---------------------------------------------------------------------------

// kernel32 ---------------------------------------------------------------

void k_WriteFile(const Ctx& c)
{
    uint64_t handle = c.rcx;
    uint64_t buf = c.rdx;
    uint64_t n = c.r8;
    uint64_t written_out = c.r9;
    const bool to_console = (handle == c.g->guest_stdout_handle || handle == c.g->guest_stderr_handle);
    if (to_console && n > 0)
    {
        std::vector<uint8_t> tmp(n);
        if (c.g->read_mem(buf, tmp.data(), n).ok)
        {
            std::string chunk(reinterpret_cast<const char*>(tmp.data()), n);
            bool is_err = (handle == c.g->guest_stderr_handle);
            std::string& sink = is_err ? c.g->console().stderr_text : c.g->console().stdout_text;
            if (sink.size() + chunk.size() <= c.g->console().stdout_limit)
                sink += chunk;
        }
    }
    if (written_out)
        c.write_ptr(written_out, n);
    c.set_rax(1);
}

void k_ReadFile(const Ctx& c)
{
    if (c.r9)
        c.write_ptr(c.r9, 0);
    c.set_rax(0); // instant EOF
}

void k_FlushFileBuffers(const Ctx& c) { c.set_rax(1); }

void k_GetStdHandle(const Ctx& c)
{
    switch (int32_t(c.rcx))
    {
    case -10:
        c.set_rax(c.g->guest_stdin_handle);
        break; // STD_INPUT_HANDLE
    case -11:
        c.set_rax(c.g->guest_stdout_handle);
        break;
    case -12:
        c.set_rax(c.g->guest_stderr_handle);
        break;
    default:
        c.set_rax(0);
        break;
    }
}

void k_ExitProcess(const Ctx& c) { c.stop(uint32_t(c.rcx)); }

void k_GetLastError(const Ctx& c) { c.set_rax(c.g->last_error); }

void k_SetLastError(const Ctx& c) { c.g->last_error = uint32_t(c.rcx); c.set_rax(0); }

void k_VirtualAlloc(const Ctx& c)
{
    uint64_t addr = c.rcx, size = c.rdx;
    uint32_t type = uint32_t(c.r8);
    uint32_t prot = uint32_t(c.r9);
    const bool exec = (prot & 0x10u) != 0; // PAGE_EXECUTE*
    if ((type & 0x1000u) == 0)             // MEM_COMMIT not set -> just reserve
    {
        c.set_rax(addr); // reserve is a no-op that returns the address
        return;
    }
    if (addr == 0)
        c.set_rax(c.g->valloc(size, exec));
    else
        c.set_rax(addr); // committed at a fixed address: already mapped
}

void k_VirtualFree(const Ctx& c)
{
    uint64_t addr = c.rcx;
    uint32_t type = uint32_t(c.rdx);
    if ((type & 0x8000u) != 0) // MEM_RELEASE
        c.g->heap_free(addr);
    c.set_rax(1);
}

void k_VirtualProtect(const Ctx& c)
{
    if (c.r9)
        c.write_u32_at(c.r9, 0x04); // PAGE_READWRITE as the old protection
    c.set_rax(1);
}

void k_GetModuleHandleA(const Ctx& c)
{
    std::string name = c.cstr(c.rcx);
    if (name.empty() || name == c.g->module_name())
        c.set_rax(c.g->image_base());
    else
        c.set_rax(0);
}

void k_GetModuleHandleW(const Ctx& c)
{
    std::string name = c.wstr(c.rcx);
    if (name.empty() || name == c.g->module_name())
        c.set_rax(c.g->image_base());
    else
        c.set_rax(0);
}

void k_GetModuleFileNameA(const Ctx& c)
{
    // GetModuleFileNameA(hModule=rcx, lpFilename=rdx, nSize=r8).
    std::string s = c.g->module_name();
    size_t n = s.size();
    if (c.r8 < n)
        n = size_t(c.r8);
    if (c.rdx && n)
        c.g->write_mem(c.rdx, s.data(), n);
    if (c.rdx && n < c.r8)
        c.g->write_mem(c.rdx + n, "\0", 1);
    c.set_rax(n);
}

void k_GetModuleFileNameW(const Ctx& c)
{
    // GetModuleFileNameW(hModule=rcx, lpFilename=rdx, nSize=r8 in WCHARs).
    std::string s = c.g->module_name();
    size_t n = s.size();
    if (c.r8 < n)
        n = size_t(c.r8);
    std::vector<uint8_t> buf;
    for (size_t i = 0; i < n; ++i)
    {
        uint16_t w = uint16_t(uint8_t(s[i]));
        buf.push_back(uint8_t(w & 0xff));
        buf.push_back(uint8_t(w >> 8));
    }
    if (c.rdx && !buf.empty())
        c.g->write_mem(c.rdx, buf.data(), buf.size());
    if (c.rdx && n < c.r8)
    {
        buf.clear();
        buf.push_back(0);
        buf.push_back(0);
        c.g->write_mem(c.rdx + 2 * n, buf.data(), 2);
    }
    c.set_rax(n);
}

void k_GetProcAddress(const Ctx& c)
{
    // GetProcAddress(HMODULE hModule=rcx, LPCSTR lpProcName=rdx).
    uint64_t hmod = c.rcx;
    std::string name = c.cstr(c.rdx, 512);
    std::string dll;
    if (hmod == c.g->image_base())
        dll = c.g->module_name();
    else
        dll = c.g->tracked_module(hmod);
    // 1. already-intercepted import of that dll
    uint64_t stub = c.g->resolve_import(dll, name);
    if (!stub)
        stub = c.g->resolve_import("kernel32.dll", name);
    if (!stub)
        stub = c.g->resolve_import("ntdll.dll", name);
    // 2. export of the image itself (real code)
    if (!stub)
    {
        auto r = c.g->resolve_export(name);
        if (r.ok)
            stub = r.value;
    }
    // 3. generic remote slot (opaque; interceptable later)
    if (!stub)
        stub = c.g->add_remote_function(dll.empty() ? "kernel32.dll" : dll, name);
    c.set_rax(stub);
}

void k_LoadLibraryA(const Ctx& c)
{
    std::string name = c.cstr(c.rcx);
    if (name.empty() || name == c.g->module_name())
        c.set_rax(c.g->image_base());
    else
        c.set_rax(c.g->loaded_module(name));
}

void k_LoadLibraryW(const Ctx& c)
{
    std::string name = c.wstr(c.rcx);
    if (name.empty() || name == c.g->module_name())
        c.set_rax(c.g->image_base());
    else
        c.set_rax(c.g->loaded_module(name));
}

void k_FreeLibrary(const Ctx& c) { c.set_rax(1); }

void k_GetSystemTimeAsFileTime(const Ctx& c)
{
    // virtual clock: 100ns units since Win32 epoch
    uint64_t ft = 116444736000000000ull + c.g->qpc_frequency * (c.g->tick_count / 1000);
    c.g->write_u64(c.rcx, ft);
    c.set_rax(0);
}

void k_GetSystemTime(const Ctx& c)
{
    // 16-byte SYSTEMTIME, zeroed = epoch 1601
    uint8_t zero[16] = {0};
    c.g->write_mem(c.rcx, zero, sizeof(zero));
}

void k_GetLocalTime(const Ctx& c) { k_GetSystemTime(c); }

void k_GetCurrentProcessId(const Ctx& c) { c.set_rax(1337); }

void k_GetCurrentThreadId(const Ctx& c) { c.set_rax(1); }

void k_GetCurrentProcess(const Ctx& c) { c.set_rax(uint64_t(-1)); }

void k_QueryPerformanceCounter(const Ctx& c)
{
    c.g->write_u64(c.rcx, c.g->qpc_frequency * (c.g->tick_count / 1000));
    c.set_rax(1);
}

void k_QueryPerformanceFrequency(const Ctx& c)
{
    c.g->write_u64(c.rcx, c.g->qpc_frequency);
    c.set_rax(1);
}

void k_GetTickCount(const Ctx& c) { c.set_rax(c.g->tick_count); }

void k_GetTickCount64(const Ctx& c) { c.set_rax(c.g->tick_count); }

void k_Sleep(const Ctx& c)
{
    c.g->tick_count += uint32_t(c.rcx);
    c.set_rax(0);
}

void k_IsProcessorFeaturePresent(const Ctx& c)
{
    // SSE2 + SSSE3 are present in every x64 CPU the emulator models; the
    // rest are reported absent so optimized paths fall back to portable code.
    uint32_t f = uint32_t(c.rcx);
    c.set_rax((f == 9 || f == 10 || f == 12) ? 1 : 0); // PF_SSE2/SSE3/SSSE3
}

void k_GetEnvironmentVariableA(const Ctx& c)
{
    (void)c.cstr(c.rcx);
    c.set_rax(0); // not found
}

void k_GetEnvironmentVariableW(const Ctx& c)
{
    (void)c.wstr(c.rcx);
    c.set_rax(0);
}

void k_SetEnvironmentVariableA(const Ctx& c) { c.set_rax(1); }

void k_SetEnvironmentVariableW(const Ctx& c) { c.set_rax(1); }

void k_GetCommandLineA(const Ctx& c) { c.set_rax(c.write_cstr_to("\"C:\\lure\\victim.exe\"")); }

void k_GetCommandLineW(const Ctx& c) { c.set_rax(c.write_wstr_to("\"C:\\lure\\victim.exe\"")); }

void k_GetStartupInfoA(const Ctx& c)
{
    uint8_t zero[104] = {0};
    c.g->write_mem(c.rcx, zero, sizeof(zero));
    c.set_rax(0);
}

void k_GetStartupInfoW(const Ctx& c)
{
    uint8_t zero[104] = {0};
    c.g->write_mem(c.rcx, zero, sizeof(zero));
    c.set_rax(0);
}

void k_GetFileType(const Ctx& c) { c.set_rax(2); } // FILE_TYPE_CHAR

void k_GetConsoleMode(const Ctx& c)
{
    if (c.rdx)
        c.write_u32_at(c.rdx, 0x87); // ENABLE_PROCESSED_OUTPUT | ...
    c.set_rax(1);
}

void k_SetConsoleMode(const Ctx& c) { c.set_rax(1); }

void k_GetConsoleScreenBufferInfo(const Ctx& c)
{
    if (c.rdx)
    {
        uint8_t zero[22] = {0};
        c.g->write_mem(c.rdx, zero, sizeof(zero));
    }
    c.set_rax(1);
}

void k_SetStdHandle(const Ctx& c) { c.set_rax(1); }

void k_GetProcessHeap(const Ctx& c) { c.set_rax(c.g->heap_base()); }

void k_HeapAlloc(const Ctx& c) { c.set_rax(c.g->valloc(c.rdx, false)); }

void k_HeapFree(const Ctx& c)
{
    c.g->heap_free(c.r8);
    c.set_rax(1);
}

void k_HeapReAlloc(const Ctx& c)
{
    uint64_t ptr = c.r8, size = c.r9;
    uint64_t old = c.g->heap_block_size(ptr);
    uint64_t n = c.g->valloc(size, false);
    if (n && old)
    {
        size_t copy = std::min<size_t>(size_t(old), size_t(size));
        std::vector<uint8_t> tmp(copy);
        if (c.g->read_mem(ptr, tmp.data(), copy).ok)
            c.g->write_mem(n, tmp.data(), copy);
    }
    c.g->heap_free(ptr);
    c.set_rax(n);
}

void k_IsDebuggerPresent(const Ctx& c) { c.set_rax(0); }

void k_TerminateProcess(const Ctx& c) { c.stop(uint32_t(c.rdx)); }

void k_GetErrorMode(const Ctx& c) { c.set_rax(0); }

void k_SetErrorMode(const Ctx& c) { c.set_rax(0); }

void k_GetSystemDirectoryA(const Ctx& c)
{
    c.set_rax(0);
}

void k_GetSystemDirectoryW(const Ctx& c)
{
    c.set_rax(0);
}

void k_GetWindowsDirectoryA(const Ctx& c)
{
    // GetWindowsDirectoryA(lpBuffer=rcx, nSize=rdx).
    static const char kDir[] = "C:\\Windows";
    const size_t len = sizeof(kDir) - 1; // 10 chars, no null
    size_t n = std::min<size_t>(len, size_t(c.rdx));
    if (c.rdx >= 1 && c.rcx)
    {
        c.g->write_mem(c.rcx, kDir, n);
        if (n < c.rdx)
            c.g->write_mem(c.rcx + n, "\0", 1);
    }
    c.set_rax(len); // required buffer size including null
}

void k_GetWindowsDirectoryW(const Ctx& c) { c.set_rax(0); }

void k_GetTempPathA(const Ctx& c)
{
    c.set_rax(0);
}

void k_GetTempPathW(const Ctx& c)
{
    c.set_rax(0);
}

// ntdll ------------------------------------------------------------------

void n_RtlGetCurrentPeb(const Ctx& c) { c.set_rax(c.g->fake_peb()); }

void n_RtlQueryPerformanceCounter(const Ctx& c)
{
    c.g->write_u64(c.rcx, c.g->qpc_frequency * (c.g->tick_count / 1000));
    c.g->write_u64(c.rdx, c.g->qpc_frequency);
    c.set_rax(0);
}

void n_RtlQueryPerformanceFrequency(const Ctx& c)
{
    c.g->write_u64(c.rcx, c.g->qpc_frequency);
    c.set_rax(0);
}

void n_RtlGetCurrentThread(const Ctx& c) { c.set_rax(1); }

void n_RtlGetCurrentProcess(const Ctx& c) { c.set_rax(uint64_t(-1)); }

void n_RtlZeroMemory(const Ctx& c)
{
    std::vector<uint8_t> zero(std::min<size_t>(size_t(c.rdx), 1 << 20));
    c.g->write_mem(c.rcx, zero.data(), zero.size());
    c.set_rax(c.rcx);
}

void n_RtlMoveMemory(const Ctx& c)
{
    size_t n = std::min<size_t>(size_t(c.r8), 1 << 20);
    std::vector<uint8_t> tmp(n);
    if (c.g->read_mem(c.rdx, tmp.data(), n).ok)
        c.g->write_mem(c.rcx, tmp.data(), n);
    c.set_rax(c.rcx);
}

void n_RtlCopyMemory(const Ctx& c)
{
    size_t n = std::min<size_t>(size_t(c.r8), 1 << 20);
    std::vector<uint8_t> tmp(n);
    if (c.g->read_mem(c.rdx, tmp.data(), n).ok)
        c.g->write_mem(c.rcx, tmp.data(), n);
    c.set_rax(c.rcx);
}

void n_RtlCompareMemory(const Ctx& c)
{
    size_t n = std::min<size_t>(size_t(c.r8), 1 << 20);
    std::vector<uint8_t> a(n), b(n);
    if (!c.g->read_mem(c.rcx, a.data(), n).ok || !c.g->read_mem(c.rdx, b.data(), n).ok)
    {
        c.set_rax(0);
        return;
    }
    size_t i = 0;
    while (i < n && a[i] == b[i])
        ++i;
    c.set_rax(i);
}

// CRTs as DLLs (dynamic-CRT targets; the fixture links /MT so CRT is static
// and never hits these) ------------------------------------------------

void crt_malloc(const Ctx& c) { c.set_rax(c.g->valloc(c.rcx, false)); }

void crt_free(const Ctx& c)
{
    c.g->heap_free(c.rcx);
    c.set_rax(0);
}

void crt_memset(const Ctx& c)
{
    size_t n = std::min<size_t>(size_t(c.r8), 1 << 20);
    std::vector<uint8_t> fill(n, uint8_t(c.rdx));
    if (!fill.empty())
        c.g->write_mem(c.rcx, fill.data(), n);
    c.set_rax(c.rcx);
}

void crt_memcpy(const Ctx& c)
{
    size_t n = std::min<size_t>(size_t(c.r8), 1 << 20);
    std::vector<uint8_t> tmp(n);
    if (c.g->read_mem(c.rdx, tmp.data(), n).ok)
        c.g->write_mem(c.rcx, tmp.data(), n);
    c.set_rax(c.rcx);
}

void crt_strlen(const Ctx& c)
{
    c.set_rax(c.cstr(c.rcx, 1 << 20).size());
}

// ---------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------

const std::vector<std::pair<std::string, Impl>>& stub_table()
{
    static const std::vector<std::pair<std::string, Impl>> t = {
        {"kernel32.dll!WriteFile", k_WriteFile},
        {"kernel32.dll!ReadFile", k_ReadFile},
        {"kernel32.dll!FlushFileBuffers", k_FlushFileBuffers},
        {"kernel32.dll!GetStdHandle", k_GetStdHandle},
        {"kernel32.dll!ExitProcess", k_ExitProcess},
        {"kernel32.dll!GetLastError", k_GetLastError},
        {"kernel32.dll!SetLastError", k_SetLastError},
        {"kernel32.dll!VirtualAlloc", k_VirtualAlloc},
        {"kernel32.dll!VirtualFree", k_VirtualFree},
        {"kernel32.dll!VirtualProtect", k_VirtualProtect},
        {"kernel32.dll!GetModuleHandleA", k_GetModuleHandleA},
        {"kernel32.dll!GetModuleHandleW", k_GetModuleHandleW},
        {"kernel32.dll!GetModuleFileNameA", k_GetModuleFileNameA},
        {"kernel32.dll!GetModuleFileNameW", k_GetModuleFileNameW},
        {"kernel32.dll!GetProcAddress", k_GetProcAddress},
        {"kernel32.dll!LoadLibraryA", k_LoadLibraryA},
        {"kernel32.dll!LoadLibraryW", k_LoadLibraryW},
        {"kernel32.dll!FreeLibrary", k_FreeLibrary},
        {"kernel32.dll!GetSystemTimeAsFileTime", k_GetSystemTimeAsFileTime},
        {"kernel32.dll!GetSystemTime", k_GetSystemTime},
        {"kernel32.dll!GetLocalTime", k_GetLocalTime},
        {"kernel32.dll!GetCurrentProcessId", k_GetCurrentProcessId},
        {"kernel32.dll!GetCurrentThreadId", k_GetCurrentThreadId},
        {"kernel32.dll!GetCurrentProcess", k_GetCurrentProcess},
        {"kernel32.dll!QueryPerformanceCounter", k_QueryPerformanceCounter},
        {"kernel32.dll!QueryPerformanceFrequency", k_QueryPerformanceFrequency},
        {"kernel32.dll!GetTickCount", k_GetTickCount},
        {"kernel32.dll!GetTickCount64", k_GetTickCount64},
        {"kernel32.dll!Sleep", k_Sleep},
        {"kernel32.dll!IsProcessorFeaturePresent", k_IsProcessorFeaturePresent},
        {"kernel32.dll!GetEnvironmentVariableA", k_GetEnvironmentVariableA},
        {"kernel32.dll!GetEnvironmentVariableW", k_GetEnvironmentVariableW},
        {"kernel32.dll!SetEnvironmentVariableA", k_SetEnvironmentVariableA},
        {"kernel32.dll!SetEnvironmentVariableW", k_SetEnvironmentVariableW},
        {"kernel32.dll!GetCommandLineA", k_GetCommandLineA},
        {"kernel32.dll!GetCommandLineW", k_GetCommandLineW},
        {"kernel32.dll!GetStartupInfoA", k_GetStartupInfoA},
        {"kernel32.dll!GetStartupInfoW", k_GetStartupInfoW},
        {"kernel32.dll!GetFileType", k_GetFileType},
        {"kernel32.dll!GetConsoleMode", k_GetConsoleMode},
        {"kernel32.dll!SetConsoleMode", k_SetConsoleMode},
        {"kernel32.dll!GetConsoleScreenBufferInfo", k_GetConsoleScreenBufferInfo},
        {"kernel32.dll!SetStdHandle", k_SetStdHandle},
        {"kernel32.dll!GetProcessHeap", k_GetProcessHeap},
        {"kernel32.dll!HeapAlloc", k_HeapAlloc},
        {"kernel32.dll!HeapFree", k_HeapFree},
        {"kernel32.dll!HeapReAlloc", k_HeapReAlloc},
        {"kernel32.dll!IsDebuggerPresent", k_IsDebuggerPresent},
        {"kernel32.dll!TerminateProcess", k_TerminateProcess},
        {"kernel32.dll!GetErrorMode", k_GetErrorMode},
        {"kernel32.dll!SetErrorMode", k_SetErrorMode},
        {"kernel32.dll!GetSystemDirectoryA", k_GetSystemDirectoryA},
        {"kernel32.dll!GetSystemDirectoryW", k_GetSystemDirectoryW},
        {"kernel32.dll!GetWindowsDirectoryA", k_GetWindowsDirectoryA},
        {"kernel32.dll!GetWindowsDirectoryW", k_GetWindowsDirectoryW},
        {"kernel32.dll!GetTempPathA", k_GetTempPathA},
        {"kernel32.dll!GetTempPathW", k_GetTempPathW},

        {"ntdll.dll!RtlGetCurrentPeb", n_RtlGetCurrentPeb},
        {"ntdll.dll!RtlQueryPerformanceCounter", n_RtlQueryPerformanceCounter},
        {"ntdll.dll!RtlQueryPerformanceFrequency", n_RtlQueryPerformanceFrequency},
        {"ntdll.dll!RtlGetCurrentThread", n_RtlGetCurrentThread},
        {"ntdll.dll!RtlGetCurrentProcess", n_RtlGetCurrentProcess},
        {"ntdll.dll!RtlZeroMemory", n_RtlZeroMemory},
        {"ntdll.dll!RtlMoveMemory", n_RtlMoveMemory},
        {"ntdll.dll!RtlCopyMemory", n_RtlCopyMemory},
        {"ntdll.dll!RtlCompareMemory", n_RtlCompareMemory},

        {"msvcrt.dll!malloc", crt_malloc},
        {"msvcrt.dll!free", crt_free},
        {"msvcrt.dll!calloc", [](const Ctx& c) { c.set_rax(c.g->valloc(c.rcx * c.rdx, false)); }},
        {"msvcrt.dll!realloc", [](const Ctx& c) {
             uint64_t ptr = c.rdx, size = c.r8;
             uint64_t old = c.g->heap_block_size(ptr);
             uint64_t n = c.g->valloc(size, false);
             if (n && old)
             {
                 size_t copy = std::min<size_t>(size_t(old), size_t(size));
                 std::vector<uint8_t> tmp(copy);
                 if (c.g->read_mem(ptr, tmp.data(), copy).ok)
                     c.g->write_mem(n, tmp.data(), copy);
             }
             c.g->heap_free(ptr);
             c.set_rax(n);
         }},
        {"msvcrt.dll!memset", crt_memset},
        {"msvcrt.dll!memcpy", crt_memcpy},
        {"msvcrt.dll!memmove", crt_memcpy},
        {"msvcrt.dll!strlen", crt_strlen},
        {"ucrtbase.dll!malloc", crt_malloc},
        {"ucrtbase.dll!free", crt_free},
        {"ucrtbase.dll!calloc", [](const Ctx& c) { c.set_rax(c.g->valloc(c.rcx * c.rdx, false)); }},
        {"ucrtbase.dll!realloc", [](const Ctx& c) {
             uint64_t ptr = c.rdx, size = c.r8;
             uint64_t old = c.g->heap_block_size(ptr);
             uint64_t n = c.g->valloc(size, false);
             if (n && old)
             {
                 size_t copy = std::min<size_t>(size_t(old), size_t(size));
                 std::vector<uint8_t> tmp(copy);
                 if (c.g->read_mem(ptr, tmp.data(), copy).ok)
                     c.g->write_mem(n, tmp.data(), copy);
             }
             c.g->heap_free(ptr);
             c.set_rax(n);
         }},
        {"ucrtbase.dll!memset", crt_memset},
        {"ucrtbase.dll!memcpy", crt_memcpy},
        {"ucrtbase.dll!memmove", crt_memcpy},
        {"ucrtbase.dll!strlen", crt_strlen},
    };
    return t;
}

} // namespace

// ---------------------------------------------------------------------------
// Public log
// ---------------------------------------------------------------------------

ApiLog& api_log()
{
    static ApiLog log;
    return log;
}

// ---------------------------------------------------------------------------
// Interception hook
// ---------------------------------------------------------------------------

namespace {

void stub_hook(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
    GuestSession* g = static_cast<GuestSession*>(user_data);
    (void)uc;
    (void)size;
    if (address < g->stub_arena() || address >= g->stub_arena() + g->stub_capacity() * 0x1000)
        return;

    const size_t slot = size_t((address - g->stub_arena()) / 0x1000);

    // The slot is either a real import (slot < imports count) or a remote
    // function allocated later by GetProcAddress/LoadLibrary.
    std::string dll, name;
    if (slot < g->import_names_size())
    {
        dll = g->import_dll(slot);
        name = g->import_name(slot);
    }

    const Impl* impl = nullptr;
    const auto& table = stub_table();
    if (!dll.empty() && !name.empty())
    {
        std::string key = dll + "!" + name;
        for (const auto& [k, fn] : table)
        {
            if (k == key)
            {
                impl = &fn;
                break;
            }
        }
    }

    Ctx ctx = Ctx::read(g);

    ApiCallRecord rec;
    rec.seq = api_log().calls.size();
    rec.dll = dll;
    rec.name = name;
    rec.args.push_back(hex64(ctx.rcx));

    if (impl)
    {
        (*impl)(ctx);
        char b[24];
        uint64_t rax = 0;
        uc_err e = uc_reg_read(g->uc(), UC_X86_REG_RAX, &rax);
        if (e == UC_ERR_OK)
        {
            std::snprintf(b, sizeof(b), "0x%llx", static_cast<unsigned long long>(rax));
            rec.ret = b;
        }
        else
        {
            rec.ret = "?";
        }
        api_log().record(std::move(rec));
        return;
    }

    // Unknown function: conservative no-op (returns NULL) so the guest keeps
    // running; the event is logged for post-run analysis.
    ctx.set_rax(0);
    rec.ret = "0x0 (unimplemented)";
    api_log().record(std::move(rec));
}

} // namespace

Resolved<void> api_stub_install(GuestSession* g)
{
    uc_hook h = 0;
    uc_err e = uc_hook_add(g->uc(), &h, UC_HOOK_CODE, reinterpret_cast<void*>(&stub_hook), g, g->stub_arena(),
        g->stub_arena() + g->stub_capacity() * 0x1000 - 1);
    if (e != UC_ERR_OK)
        return Resolved<void>::failure("api_stub_install: uc_hook_add failed");
    return Resolved<void>::success();
}

} // namespace lure::emu
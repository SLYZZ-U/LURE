#pragma once
// rbx_emulator/core/guest/guest.hpp
// The guest machine: a Unicorn x86-64 session with the image mapped, a guest
// stack, a virtual heap, and the import stub arena that turns every imported
// API call into a host-side emulated call.
//
// Design notes
//  - One guest session per GuestSession. Sessions are not thread-safe.
//  - Imported functions are resolved to 1-byte stub slots (0xC3 = RET) in a
//    dedicated executable arena; a UC_HOOK_CODE over the arena intercepts the
//    call before the RET and performs the API emulation in host code. The
//    guest calling convention (Win64: RCX/RDX/R8/R9 + stack) is preserved.
//  - No host OS calls are made on behalf of the guest: "standalone Windows
//    API" means every kernel32/ntdll/ucrt surface the guest touches is
//    re-implemented against the emulated memory.

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "core/pe/pe.hpp"
#include "resilience/resolved.hpp"

typedef struct uc_struct uc_engine;

namespace lure::emu {

// ---------------------------------------------------------------------------
// Guest ABI helpers (Win64)
// ---------------------------------------------------------------------------

struct GuestRegisters
{
    uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0, rsi = 0, rdi = 0, rbp = 0, rsp = 0;
    uint64_t r8 = 0, r9 = 0, r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0;
    uint64_t rip = 0;
};

// ---------------------------------------------------------------------------
// Virtual heap: guest allocations that live inside emulated memory.
// The arena is mapped once (sparse in the host, so no host memory is
// committed); allocation is a simple bump allocator with a free list.
// ---------------------------------------------------------------------------

class VirtualHeap
{
public:
    // Allocates `size` bytes (page-rounded) inside the arena. Returns 0 if
    // the arena is exhausted. `executable` is informational (the arena is
    // mapped RW; exec pages requested via VirtualAlloc stay non-exec so the
    // emulator is conservative about W^X).
    uint64_t alloc(uint64_t size, bool executable);
    bool free(uint64_t addr);
    uint64_t block_size(uint64_t addr) const; // size of a live block, or 0
    void set_base(uint64_t base) { arena_base_ = base; }
    uint64_t base() const { return arena_base_; }
    uint64_t committed() const { return committed_; }

private:
    uint64_t arena_base_ = 0; // set by the session when mapping the arena
    uint64_t committed_ = 0;  // contiguous committed prefix of the arena
    std::map<uint64_t, uint64_t> blocks_; // addr -> size of live allocations
    std::map<uint64_t, uint64_t> holes_;  // addr -> size of reusable spans
};

// ---------------------------------------------------------------------------
// Guest session
// ---------------------------------------------------------------------------

// Host-side sink for guest console output (fd 1/2 writes).
struct GuestConsole
{
    std::string stdout_text;
    std::string stderr_text;
    size_t stdout_limit = 1 << 20;
};

struct GuestOptions
{
    uint64_t stack_size = 8 << 20;      // guest stack reservation
    uint64_t heap_arena = 1ull << 34;   // 16 GiB heap arena start (below 0x7f..)
    size_t max_guest_allocations = 1 << 20;
    std::string module_name = "victim.exe"; // name GetModuleHandle/FileName report
    bool verbose_stubs = false;         // log every API call to stderr
};

// A remote function returned by GetProcAddress / LoadLibrary.
struct RemoteFunction
{
    uint64_t slot = 0; // address of the stub slot
    std::string dll;
    std::string name;
};

class GuestSession
{
public:
    // Parses + maps the image; resolves imports into the stub arena; sets up
    // the stack and returns the entry address to start at. No code runs.
    static Resolved<std::unique_ptr<GuestSession>> create(const uint8_t* image_data, size_t image_size,
        const GuestOptions& options);

    ~GuestSession();

    GuestSession(const GuestSession&) = delete;
    GuestSession& operator=(const GuestSession&) = delete;

    // --- raw machine access ------------------------------------------------
    uc_engine* uc() const { return uc_; }
    const pe::Image& image() const { return image_; }
    const GuestOptions& options() const { return options_; }
    GuestConsole& console() { return console_; }
    uint64_t entry() const { return entry_; }
    uint64_t image_base() const { return image_base_; }

    Resolved<void> read_mem(uint64_t addr, void* dst, size_t n) const;
    Resolved<void> write_mem(uint64_t addr, const void* src, size_t n);
    Resolved<uint64_t> read_u64(uint64_t addr) const;
    Resolved<uint32_t> read_u32(uint64_t addr) const;
    Resolved<void> write_u64(uint64_t addr, uint64_t v);
    Resolved<void> write_u32(uint64_t addr, uint32_t v);

    Resolved<GuestRegisters> regs() const;
    Resolved<void> set_regs(const GuestRegisters& r);

    // --- memory lifecycle --------------------------------------------------
    // Maps a fresh page-aligned region; registers it in the region table.
    Resolved<uint64_t> map_region(uint64_t size, bool executable, bool writable);
    Resolved<void> unmap_region(uint64_t addr);

    // Allocates from the virtual heap (VirtualAlloc semantics).
    uint64_t valloc(uint64_t size, bool executable);

    // --- stubs / API resolution -------------------------------------------
    // Resolves an import thunk by its DLL/name; returns the stub slot or 0.
    uint64_t resolve_import(const std::string& dll, const std::string& name);
    // GetProcAddress-style resolution against the loaded image's export table.
    Resolved<uint64_t> resolve_export(const std::string& name);
    // Allocates a new remote-function slot (GetProcAddress on "loaded" dlls).
    uint64_t add_remote_function(const std::string& dll, const std::string& name);
    // LoadLibrary result: the image base for the main module, a fake handle
    // otherwise (handles map back to the dll name for GetProcAddress).
    uint64_t loaded_module(const std::string& name);
    // Reverse map of a fake module handle; "" for unknown handles.
    std::string tracked_module(uint64_t handle) const;

    // The slot index for a stub address (imports are slots 0..N-1).
    int stub_index(uint64_t addr) const;
    const RemoteFunction* remote_at(uint64_t addr) const;

    // Import-descriptor access (stub dispatcher): slot i < import_names_size()
    // is the i-th imported function in IAT order.
    size_t import_names_size() const { return import_names_.size(); }
    const std::string& import_dll(size_t i) const;
    std::string import_name(size_t i) const;

    // A lazily-created fake PEB in guest memory (BeingDebugged=0), or 0 if
    // the allocation could not be made. Used by RtlGetCurrentPeb.
    uint64_t fake_peb();

    // Guest <-> host state used by the stub implementations.
    uint32_t last_error = 0;
    uint64_t guest_stdin_handle = 1;    // fake CONIN$
    uint64_t guest_stdout_handle = 2;   // fake CONOUT$
    uint64_t guest_stderr_handle = 3;   // fake CONERR$
    uint64_t qpc_frequency = 10'000'000;
    uint64_t tick_count = 0;            // virtual ms clock, advanced by stubs
    bool exited = false;                // set by ExitProcess/TerminateProcess
    int32_t exit_code = 0;
    const std::string& module_name() const { return options_.module_name; }

    // Virtual-heap access (HeapFree-style stubs).
    uint64_t heap_base() const { return heap_.base(); }
    void heap_free(uint64_t addr) { heap_.free(addr); }
    uint64_t heap_block_size(uint64_t addr) const { return heap_.block_size(addr); }

    // Stub arena geometry (consumed by the API dispatcher).
    uint64_t stub_arena() const { return stub_arena_; }
    size_t stub_capacity() const { return stub_capacity_; }

private:
    GuestSession() = default;

    Resolved<void> map_image(const uint8_t* data, size_t size);
    Resolved<void> resolve_all_imports();

    uc_engine* uc_ = nullptr;
    pe::Image image_;
    GuestOptions options_;
    GuestConsole console_;
    uint64_t entry_ = 0;
    uint64_t image_base_ = 0;
    uint64_t stack_base_ = 0;
    uint64_t stack_size_ = 0;
    VirtualHeap heap_;

    // stub arena
    uint64_t stub_arena_ = 0;
    size_t stub_capacity_ = 0;
    size_t stub_used_ = 0;
    std::vector<std::string> import_names_;    // slot index -> "dll!name"
    std::vector<std::string> import_dlls_;
    std::vector<RemoteFunction> remotes_;
    std::map<std::string, uint64_t> import_lookup_; // "dll!name" -> slot

    // fake module handles from LoadLibrary (handle -> dll name)
    std::map<uint64_t, std::string> module_handles_;
    uint64_t next_module_handle_ = 0x1000'0000'0000ull;
    uint64_t fake_peb_ = 0;

    // region table for mapped pages (addr -> {size, exec, writable})
    struct Region
    {
        uint64_t size = 0;
        bool executable = false;
        bool writable = false;
    };
    std::map<uint64_t, Region> regions_;
};

} // namespace lure::emu

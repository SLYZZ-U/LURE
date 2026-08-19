// rbx_emulator/core/guest/guest.cpp
#include "core/guest/guest.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <mutex>

#include <unicorn/unicorn.h>

#include "core/ostub/api_stub.hpp"

namespace lure::emu {

// ---------------------------------------------------------------------------
// Unicorn helpers
// ---------------------------------------------------------------------------

namespace {

const char* uc_err_str(uc_err e)
{
    switch (e)
    {
    case UC_ERR_OK:
        return "ok";
    case UC_ERR_ARG:
        return "invalid argument";
    case UC_ERR_READ_UNMAPPED:
        return "read from unmapped memory";
    case UC_ERR_WRITE_UNMAPPED:
        return "write to unmapped memory";
    case UC_ERR_FETCH_UNMAPPED:
        return "fetch from unmapped memory";
    case UC_ERR_MAP:
        return "mapping failed";
    case UC_ERR_NOMEM:
        return "out of host memory";
    default:
        return "unicorn error";
    }
}

uint64_t page_align_up(uint64_t v)
{
    return (v + 0xfff) & ~uint64_t(0xfff);
}

} // namespace

// ---------------------------------------------------------------------------
// VirtualHeap
// ---------------------------------------------------------------------------

uint64_t VirtualHeap::alloc(uint64_t size, bool /*executable*/)
{
    if (size == 0)
        return 0;
    uint64_t want = page_align_up(size);
    // reuse a hole when possible (first fit), splitting it
    for (auto it = holes_.begin(); it != holes_.end(); ++it)
    {
        if (it->second >= want)
        {
            uint64_t a = it->first;
            if (it->second > want)
                holes_[a + want] = it->second - want;
            holes_.erase(it);
            blocks_[a] = want;
            return a;
        }
    }
    uint64_t a = arena_base_ + committed_;
    if (a < arena_base_)
        return 0; // overflow
    committed_ += want;
    blocks_[a] = want;
    return a;
}

uint64_t VirtualHeap::block_size(uint64_t addr) const
{
    auto it = blocks_.find(addr);
    return it == blocks_.end() ? 0 : it->second;
}

bool VirtualHeap::free(uint64_t addr)
{
    auto it = blocks_.find(addr);
    if (it == blocks_.end())
        return false;
    uint64_t size = it->second;
    // tail shrink: the freed block ends the committed prefix
    if (addr + size == arena_base_ + committed_)
    {
        committed_ = addr - arena_base_;
        // absorb any hole that ended at the old committed edge
        for (auto h = holes_.begin(); h != holes_.end();)
        {
            if (h->first >= arena_base_ + committed_)
                h = holes_.erase(h);
            else
                ++h;
        }
    }
    else
    {
        holes_[addr] = size;
        // merge with a hole that directly preceded the freed block
        auto prev = holes_.lower_bound(addr);
        if (prev != holes_.begin())
        {
            --prev;
            if (prev->first + prev->second == addr)
            {
                prev->second += size;
                holes_.erase(addr);
            }
        }
    }
    blocks_.erase(it);
    return true;
}

// ---------------------------------------------------------------------------
// GuestSession
// ---------------------------------------------------------------------------

GuestSession::~GuestSession()
{
    if (uc_)
        uc_close(uc_);
}

Resolved<void> GuestSession::read_mem(uint64_t addr, void* dst, size_t n) const
{
    uc_err e = uc_mem_read(uc_, addr, dst, n);
    if (e != UC_ERR_OK)
        return Resolved<void>::failure(std::string("uc_mem_read(0x") + [&] {
            char b[32];
            std::snprintf(b, sizeof(b), "%llx", static_cast<unsigned long long>(addr));
            return std::string(b);
        }() + ", " + std::to_string(n) + "): " + uc_err_str(e));
    return Resolved<void>::success();
}

Resolved<void> GuestSession::write_mem(uint64_t addr, const void* src, size_t n)
{
    uc_err e = uc_mem_write(uc_, addr, src, n);
    if (e != UC_ERR_OK)
        return Resolved<void>::failure(std::string("uc_mem_write(0x") + [&] {
            char b[32];
            std::snprintf(b, sizeof(b), "%llx", static_cast<unsigned long long>(addr));
            return std::string(b);
        }() + ", " + std::to_string(n) + "): " + uc_err_str(e));
    return Resolved<void>::success();
}

Resolved<uint64_t> GuestSession::read_u64(uint64_t addr) const
{
    uint64_t v = 0;
    Resolved<void> r = read_mem(addr, &v, 8);
    if (!r.ok)
        return Resolved<uint64_t>::failure(r.reason);
    return Resolved<uint64_t>::success(v);
}

Resolved<uint32_t> GuestSession::read_u32(uint64_t addr) const
{
    uint32_t v = 0;
    Resolved<void> r = read_mem(addr, &v, 4);
    if (!r.ok)
        return Resolved<uint32_t>::failure(r.reason);
    return Resolved<uint32_t>::success(v);
}

Resolved<void> GuestSession::write_u64(uint64_t addr, uint64_t v)
{
    return write_mem(addr, &v, 8);
}

Resolved<void> GuestSession::write_u32(uint64_t addr, uint32_t v)
{
    return write_mem(addr, &v, 4);
}

Resolved<GuestRegisters> GuestSession::regs() const
{
    GuestRegisters r;
    struct
    {
        int id;
        uint64_t* dst;
    } map[] = {
        {UC_X86_REG_RAX, &r.rax}, {UC_X86_REG_RBX, &r.rbx}, {UC_X86_REG_RCX, &r.rcx}, {UC_X86_REG_RDX, &r.rdx},
        {UC_X86_REG_RSI, &r.rsi}, {UC_X86_REG_RDI, &r.rdi}, {UC_X86_REG_RBP, &r.rbp}, {UC_X86_REG_RSP, &r.rsp},
        {UC_X86_REG_R8, &r.r8},   {UC_X86_REG_R9, &r.r9},   {UC_X86_REG_R10, &r.r10}, {UC_X86_REG_R11, &r.r11},
        {UC_X86_REG_R12, &r.r12}, {UC_X86_REG_R13, &r.r13}, {UC_X86_REG_R14, &r.r14}, {UC_X86_REG_R15, &r.r15},
        {UC_X86_REG_RIP, &r.rip},
    };
    for (const auto& m : map)
    {
        if (uc_reg_read(uc_, m.id, m.dst) != UC_ERR_OK)
            return Resolved<GuestRegisters>::failure("uc_reg_read failed");
    }
    return Resolved<GuestRegisters>::success(r);
}

Resolved<void> GuestSession::set_regs(const GuestRegisters& r)
{
    struct
    {
        int id;
        uint64_t v;
    } map[] = {
        {UC_X86_REG_RAX, r.rax}, {UC_X86_REG_RBX, r.rbx}, {UC_X86_REG_RCX, r.rcx}, {UC_X86_REG_RDX, r.rdx},
        {UC_X86_REG_RSI, r.rsi}, {UC_X86_REG_RDI, r.rdi}, {UC_X86_REG_RBP, r.rbp}, {UC_X86_REG_RSP, r.rsp},
        {UC_X86_REG_R8, r.r8},   {UC_X86_REG_R9, r.r9},   {UC_X86_REG_R10, r.r10}, {UC_X86_REG_R11, r.r11},
        {UC_X86_REG_R12, r.r12}, {UC_X86_REG_R13, r.r13}, {UC_X86_REG_R14, r.r14}, {UC_X86_REG_R15, r.r15},
        {UC_X86_REG_RIP, r.rip},
    };
    for (const auto& m : map)
    {
        if (uc_reg_write(uc_, m.id, &m.v) != UC_ERR_OK)
            return Resolved<void>::failure("uc_reg_write failed");
    }
    return Resolved<void>::success();
}

Resolved<uint64_t> GuestSession::map_region(uint64_t size, bool executable, bool writable)
{
    if (size == 0)
        return Resolved<uint64_t>::failure("map_region: zero size");
    uint64_t want = page_align_up(size);
    // Find a gap below the stack region.
    uint64_t addr = 0;
    uint64_t cursor = 0x1'0000'0000ull;
    const uint64_t top = stack_base_ ? stack_base_ : 0x7f00'0000'0000ull;
    while (cursor + want <= top)
    {
        auto it = regions_.lower_bound(cursor);
        if (it != regions_.end() && it->first == cursor)
        {
            // an existing region starts exactly here; skip past it
            cursor = page_align_up(it->first + it->second.size);
            continue;
        }
        if (it == regions_.end() || it->first >= cursor + want)
        {
            addr = cursor;
            break;
        }
        cursor = page_align_up(it->first + it->second.size);
    }
    if (addr == 0)
        return Resolved<uint64_t>::failure("map_region: no gap");
    uc_prot prot = executable ? UC_PROT_ALL : (writable ? static_cast<uc_prot>(UC_PROT_READ | UC_PROT_WRITE) : UC_PROT_READ);
    uc_err e = uc_mem_map(uc_, addr, want, prot);
    if (e != UC_ERR_OK)
        return Resolved<uint64_t>::failure(std::string("uc_mem_map(") + std::to_string(addr) + ", " +
            std::to_string(want) + "): " + uc_err_str(e));
    regions_[addr] = Region{want, executable, writable};
    return Resolved<uint64_t>::success(addr);
}

Resolved<void> GuestSession::unmap_region(uint64_t addr)
{
    auto it = regions_.find(addr);
    if (it == regions_.end())
        return Resolved<void>::failure("unmap_region: unknown region");
    uc_err e = uc_mem_unmap(uc_, addr, it->second.size);
    if (e != UC_ERR_OK)
        return Resolved<void>::failure(std::string("uc_mem_unmap: ") + uc_err_str(e));
    regions_.erase(it);
    return Resolved<void>::success();
}

uint64_t GuestSession::valloc(uint64_t size, bool /*executable*/)
{
    uint64_t want = page_align_up(size ? size : 1);
    if (heap_.base() == 0)
    {
        const uint64_t arena_size = uint64_t(1) << 33; // 8 GiB sparse arena
        uc_err e = uc_mem_map(uc_, options_.heap_arena, arena_size, UC_PROT_READ | UC_PROT_WRITE);
        if (e != UC_ERR_OK)
            return 0;
        regions_[options_.heap_arena] = Region{arena_size, false, true};
        heap_.set_base(options_.heap_arena);
    }
    return heap_.alloc(want, /*executable=*/false);
}

int GuestSession::stub_index(uint64_t addr) const
{
    if (stub_arena_ && addr >= stub_arena_ && addr < stub_arena_ + stub_capacity_)
        return int((addr - stub_arena_) / 0x1000);
    return -1;
}

const RemoteFunction* GuestSession::remote_at(uint64_t addr) const
{
    for (const auto& r : remotes_)
        if (r.slot == addr)
            return &r;
    return nullptr;
}

uint64_t GuestSession::resolve_import(const std::string& dll, const std::string& name)
{
    auto it = import_lookup_.find(dll + "!" + name);
    if (it == import_lookup_.end())
        return 0;
    return it->second;
}

Resolved<uint64_t> GuestSession::resolve_export(const std::string& name)
{
    auto it = std::lower_bound(image_.exports.begin(), image_.exports.end(), name,
        [](const pe::ExportEntry& e, const std::string& n) { return e.name < n; });
    if (it == image_.exports.end() || it->name != name)
        return Resolved<uint64_t>::failure("export not found: " + name);
    return Resolved<uint64_t>::success(image_base_ + it->rva);
}

uint64_t GuestSession::add_remote_function(const std::string& dll, const std::string& name)
{
    if (stub_used_ >= stub_capacity_)
        return 0;
    uint64_t slot = stub_arena_ + stub_used_ * 0x1000;
    remotes_.push_back(RemoteFunction{slot, dll, name});
    ++stub_used_;
    return slot;
}

uint64_t GuestSession::loaded_module(const std::string& name)
{
    std::string n = name;
    std::transform(n.begin(), n.end(), n.begin(), [](unsigned char c) { return char(std::tolower(c)); });
    if (n.empty() || n == this->module_name())
        return image_base_;
    uint64_t h = next_module_handle_++;
    module_handles_[h] = n;
    return h;
}

std::string GuestSession::tracked_module(uint64_t handle) const
{
    auto it = module_handles_.find(handle);
    return it == module_handles_.end() ? std::string() : it->second;
}

const std::string& GuestSession::import_dll(size_t i) const
{
    static const std::string empty;
    return i < import_dlls_.size() ? import_dlls_[i] : empty;
}

std::string GuestSession::import_name(size_t i) const
{
    if (i >= import_names_.size())
        return {};
    std::string combined = import_names_[i];
    size_t bang = combined.find('!');
    return bang == std::string::npos ? combined : combined.substr(bang + 1);
}

uint64_t GuestSession::fake_peb()
{
    if (fake_peb_)
        return fake_peb_;
    Resolved<uint64_t> r = map_region(0x1000, /*exec=*/false, /*writable=*/true);
    if (!r.ok)
        return 0;
    fake_peb_ = r.value;
    // PEB layout: flags at +0 (BeingDebugged is bit 0 of the first DWORD,
    // which lives at offset 2 of the PEB), LDR at +0x18, ProcessParameters
    // at +0x20, and the trailing PROCESS_BASIC_INFORMATION-style echo.
    write_u32(fake_peb_, 0);                    // flags: BeingDebugged = 0
    write_u32(fake_peb_ + 0x04, 4);             // OS major version (Win8+)
    write_u32(fake_peb_ + 0x08, 0);             // OS minor version
    write_u32(fake_peb_ + 0x0c, 0xffffffffu);   // PROCESSOR_ARCHITECTURE hint zone
    write_u64(fake_peb_ + 0x18, 0);             // LDR (null is tolerated)
    write_u64(fake_peb_ + 0x20, 0);             // ProcessParameters (null tolerated)
    return fake_peb_;
}

Resolved<void> GuestSession::map_image(const uint8_t* data, size_t size)
{
    // headers region
    {
        uint64_t hsize = page_align_up(image_.size_of_headers);
        uc_err e = uc_mem_map(uc_, image_base_, hsize, UC_PROT_READ);
        if (e != UC_ERR_OK)
            return Resolved<void>::failure(std::string("map headers: ") + uc_err_str(e));
        regions_[image_base_] = Region{hsize, false, false};
        uint64_t copy_n = std::min<uint64_t>(image_.size_of_headers, size);
        if (uc_mem_write(uc_, image_base_, data, copy_n) != UC_ERR_OK)
            return Resolved<void>::failure("write headers into guest");
    }
    // sections
    for (const pe::Section& s : image_.sections)
    {
        uint64_t va = image_base_ + s.virtual_address;
        uint64_t vlen = page_align_up(std::max<uint32_t>(s.virtual_size, s.raw_size));
        if (vlen == 0)
            continue;
        // overlap with headers region
        bool exec = s.executable();
        bool writable = s.writable();
        uc_prot prot = exec ? UC_PROT_ALL : (writable ? static_cast<uc_prot>(UC_PROT_READ | UC_PROT_WRITE) : UC_PROT_READ);
        if (uc_mem_map(uc_, va, vlen, prot) != UC_ERR_OK)
            return Resolved<void>::failure("map section '" + s.name + "'");
        regions_[va] = Region{vlen, exec, writable};
        if (s.raw_size > 0)
        {
            if (uint64_t(s.raw_ptr) + s.raw_size > size)
                return Resolved<void>::failure("section '" + s.name + "' raw data out of bounds");
            if (uc_mem_write(uc_, va, data + s.raw_ptr, s.raw_size) != UC_ERR_OK)
                return Resolved<void>::failure("write section '" + s.name + "'");
        }
    }
    return Resolved<void>::success();
}

Resolved<void> GuestSession::resolve_all_imports()
{
    // Build the stub arena: one 0x1000 slot per imported function (and room
    // for remote functions). Each slot contains a single RET.
    size_t n_imports = 0;
    for (const auto& dll : image_.imports)
        n_imports += dll.functions.size();
    stub_capacity_ = std::max<size_t>(64, n_imports + 1024);
    Resolved<uint64_t> r = map_region(stub_capacity_ * 0x1000, /*exec=*/true, /*writable=*/true);
    if (!r.ok)
        return Resolved<void>::failure("stub arena: " + r.reason);
    stub_arena_ = r.value;
    stub_used_ = 0;
    std::vector<uint8_t> ret_slot(0x1000, 0xC3);
    if (!write_mem(stub_arena_, ret_slot.data(), ret_slot.size()).ok)
        return Resolved<void>::failure("write stub arena");

    uint64_t idx = 0;
    for (const auto& dll : image_.imports)
    {
        for (const auto& fn : dll.functions)
        {
            uint64_t slot = stub_arena_ + idx * 0x1000;
            import_names_.push_back(dll.name + "!" + fn.name);
            import_dlls_.push_back(dll.name);
            import_lookup_[dll.name + "!" + fn.name] = slot;
            // write the stub address into the IAT slot
            Resolved<void> w = write_u64(image_base_ + fn.iat_rva, slot);
            if (!w.ok)
                return w;
            ++idx;
            ++stub_used_;
        }
    }
    return Resolved<void>::success();
}

Resolved<std::unique_ptr<GuestSession>> GuestSession::create(const uint8_t* image_data, size_t image_size,
    const GuestOptions& options)
{
    pe::Image img;
    {
        Resolved<pe::Image> parsed = pe::parse_image(image_data, image_size);
        if (!parsed.ok)
            return Resolved<std::unique_ptr<GuestSession>>::failure("PE parse: " + parsed.reason);
        img = std::move(parsed.value);
    }

    std::unique_ptr<GuestSession> g(new GuestSession());
    g->image_ = std::move(img);
    g->options_ = options;
    g->image_base_ = g->image_.image_base;
    g->entry_ = g->image_base_ + g->image_.entry_rva;

    uc_engine* uc = nullptr;
    uc_err e = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (e != UC_ERR_OK)
        return Resolved<std::unique_ptr<GuestSession>>::failure(std::string("uc_open: ") + uc_err_str(e));
    g->uc_ = uc;

    Resolved<void> mapped = g->map_image(image_data, image_size);
    if (!mapped.ok)
        return Resolved<std::unique_ptr<GuestSession>>::failure(mapped.reason);

    Resolved<void> imports = g->resolve_all_imports();
    if (!imports.ok)
        return Resolved<std::unique_ptr<GuestSession>>::failure(imports.reason);

    // guest stack
    {
        Resolved<uint64_t> s = g->map_region(options.stack_size, /*exec=*/false, /*writable=*/true);
        if (!s.ok)
            return Resolved<std::unique_ptr<GuestSession>>::failure("stack: " + s.reason);
        g->stack_base_ = s.value;
        g->stack_size_ = options.stack_size;
        uint64_t rsp = s.value + options.stack_size;
        rsp -= 16; // inside the mapped region: ret pops a zeroed frame
        rsp &= ~uint64_t(15);
        GuestRegisters regs0;
        regs0.rsp = rsp;
        regs0.rip = g->entry_;
        Resolved<void> w = g->set_regs(regs0);
        if (!w.ok)
            return Resolved<std::unique_ptr<GuestSession>>::failure("initial registers: " + w.reason);
    }

    // install the API stub dispatcher over the arena
    Resolved<void> stub_hook = api_stub_install(g.get());
    if (!stub_hook.ok)
        return Resolved<std::unique_ptr<GuestSession>>::failure(stub_hook.reason);

    return Resolved<std::unique_ptr<GuestSession>>::success(std::move(g));
}

} // namespace lure::emu

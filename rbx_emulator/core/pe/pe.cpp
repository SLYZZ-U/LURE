// rbx_emulator/core/pe/pe.cpp
#include "core/pe/pe.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

namespace lure::emu::pe {

namespace {

// Minimal PE structure layouts (self-contained; no winnt.h).
struct DosHeader
{
    char magic[2];          // "MZ"
    uint16_t cblp;
    uint16_t cp;
    uint16_t crlc;
    uint16_t cparhdr;
    uint16_t minalloc;
    uint16_t maxalloc;
    uint16_t ss;
    uint16_t sp;
    uint16_t csum;
    uint16_t ip;
    uint16_t cs;
    uint16_t lfarlc;
    uint16_t ovno;
    uint16_t res[4];
    uint16_t oemid;
    uint16_t oeminfo;
    uint16_t res2[10];
    int32_t e_lfanew;
};

struct FileHeader
{
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
};

struct OptionalHeader64
{
    uint16_t magic; // 0x20b
    uint8_t major_linker_version;
    uint8_t minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_os_version;
    uint16_t minor_os_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t check_sum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint64_t size_of_stack_reserve;
    uint64_t size_of_stack_commit;
    uint64_t size_of_heap_reserve;
    uint64_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    // data directories follow
};

struct SectionHeader
{
    char name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t pointer_to_relocations;
    uint32_t pointer_to_linenumbers;
    uint16_t number_of_relocations;
    uint16_t number_of_linenumbers;
    uint32_t characteristics;
};

constexpr uint32_t kDataDirExport = 0;
constexpr uint32_t kDataDirImport = 1;
constexpr uint32_t kDataDirTls = 9;

bool read_at(const uint8_t* data, size_t size, size_t off, void* out, size_t n)
{
    if (off > size || n > size - off)
        return false;
    std::memcpy(out, data + off, n);
    return true;
}

template <typename T>
bool read_struct(const uint8_t* data, size_t size, size_t off, T& out)
{
    static_assert(std::is_trivially_copyable_v<T>);
    return read_at(data, size, off, &out, sizeof(T));
}

std::string read_cstr(const uint8_t* data, size_t size, size_t off, size_t max_len = 512)
{
    if (off >= size)
        return {};
    size_t n = 0;
    while (off + n < size && data[off + n] != 0 && n < max_len)
        ++n;
    return std::string(reinterpret_cast<const char*>(data + off), n);
}

std::string lower(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](char c) { return char(std::tolower(static_cast<unsigned char>(c))); });
    return s;
}

} // namespace

// ---------------------------------------------------------------------------

const Section* Image::section_at(uint32_t rva) const
{
    for (const Section& s : sections)
    {
        uint32_t lo = s.virtual_address;
        uint32_t hi = lo + std::max(s.virtual_size, s.raw_size);
        if (rva >= lo && rva < hi)
            return &s;
    }
    return nullptr;
}

int64_t Image::rva_to_offset(uint32_t rva) const
{
    if (rva < size_of_headers)
        return int64_t(rva);
    for (const Section& s : sections)
    {
        uint32_t lo = s.virtual_address;
        uint32_t hi = lo + std::max(s.virtual_size, s.raw_size);
        if (rva >= lo && rva < hi && rva - lo < s.raw_size)
            return int64_t(s.raw_ptr) + (rva - lo);
    }
    return -1;
}

// ---------------------------------------------------------------------------

Resolved<Image> parse_image(const uint8_t* data, size_t size)
{
    if (!data || size < sizeof(DosHeader) + 4)
        return Resolved<Image>::failure("file too small to be a PE image");

    DosHeader dos;
    if (!read_struct(data, size, 0, dos) || std::memcmp(dos.magic, "MZ", 2) != 0)
        return Resolved<Image>::failure("missing DOS 'MZ' signature");
    if (dos.e_lfanew <= 0 || size_t(dos.e_lfanew) + 24 > size)
        return Resolved<Image>::failure("invalid e_lfanew");

    uint32_t pe_sig = 0;
    if (!read_at(data, size, size_t(dos.e_lfanew), &pe_sig, 4) || pe_sig != 0x4550u)
        return Resolved<Image>::failure("missing PE signature");

    FileHeader fh;
    if (!read_struct(data, size, size_t(dos.e_lfanew) + 4, fh))
        return Resolved<Image>::failure("truncated file header");
    if (fh.machine != 0x8664)
        return Resolved<Image>::failure("not an x86-64 image (machine 0x" + [&] {
               char b[16];
               std::snprintf(b, sizeof(b), "%04x", fh.machine);
               return std::string(b);
           }() + ")");

    size_t opt_off = size_t(dos.e_lfanew) + 4 + sizeof(FileHeader);
    OptionalHeader64 oh;
    if (!read_struct(data, size, opt_off, oh))
        return Resolved<Image>::failure("truncated optional header");
    if (oh.magic != 0x20b)
        return Resolved<Image>::failure("not a PE32+ optional header (magic 0x" + [&] {
               char b[16];
               std::snprintf(b, sizeof(b), "%04x", oh.magic);
               return std::string(b);
           }() + ")");
    if (oh.number_of_rva_and_sizes < 10)
        return Resolved<Image>::failure("image has no data-directory support ("
                                        "number_of_rva_and_sizes=" + std::to_string(oh.number_of_rva_and_sizes) + ")");
    if (oh.section_alignment < 0x1000 || (oh.section_alignment % 0x1000) != 0)
        return Resolved<Image>::failure("unsupported section alignment 0x" + [&] {
               char b[16];
               std::snprintf(b, sizeof(b), "%x", oh.section_alignment);
               return std::string(b);
           }());

    Image img;
    img.image_base = oh.image_base;
    img.size_of_image = oh.size_of_image;
    img.size_of_headers = oh.size_of_headers;
    img.entry_rva = oh.address_of_entry_point;
    img.file_alignment = oh.file_alignment;

    // Data directories ------------------------------------------------------
    const size_t dir_off = opt_off + sizeof(OptionalHeader64);
    if (dir_off + 8ull * oh.number_of_rva_and_sizes > size)
        return Resolved<Image>::failure("data directory extends past end of file");
    struct Dir
    {
        uint32_t rva;
        uint32_t size;
    };
    auto dir = [&](uint32_t idx) -> Dir
    {
        if (idx >= oh.number_of_rva_and_sizes)
            return Dir{0, 0};
        Dir d;
        read_struct(data, size, dir_off + 8ull * idx, d);
        return d;
    };

    // Sections --------------------------------------------------------------
    size_t sec_off = opt_off + fh.size_of_optional_header;
    if (sec_off + size_t(fh.number_of_sections) * sizeof(SectionHeader) > size)
        return Resolved<Image>::failure("section table extends past end of file");
    img.sections.reserve(fh.number_of_sections);
    for (uint16_t i = 0; i < fh.number_of_sections; ++i)
    {
        SectionHeader sh;
        if (!read_struct(data, size, sec_off + size_t(i) * sizeof(SectionHeader), sh))
            return Resolved<Image>::failure("truncated section header");
        Section s;
        s.name.assign(sh.name, sh.name + (sh.name[0] ? strnlen(sh.name, 8) : 0));
        s.virtual_address = sh.virtual_address;
        s.virtual_size = sh.virtual_size;
        s.raw_ptr = sh.pointer_to_raw_data;
        s.raw_size = sh.size_of_raw_data;
        s.characteristics = sh.characteristics;
        img.sections.push_back(std::move(s));
    }

    // Imports ---------------------------------------------------------------
    const Dir imp_dir = dir(kDataDirImport);
    if (imp_dir.rva != 0)
    {
        if (img.rva_to_offset(imp_dir.rva) < 0)
            return Resolved<Image>::failure("import directory outside file");
        // descriptor table is raw-mapped in the headers region for typical
        // images; resolve offsets through rva_to_offset for correctness.
        uint32_t off = imp_dir.rva;
        for (size_t guard = 0; guard < 4096; ++guard)
        {
            // 20-byte descriptor
            struct ImpDesc
            {
                uint32_t original_first_thunk;
                uint32_t time_date_stamp;
                uint32_t forwarder_chain;
                uint32_t name_rva;
                uint32_t first_thunk;
            } id;
            int64_t foff = img.rva_to_offset(off);
            if (foff < 0 || !read_struct(data, size, size_t(foff), id))
                break;
            if (id.name_rva == 0 && id.first_thunk == 0)
                break;
            ImportDll dll;
            int64_t noff = img.rva_to_offset(id.name_rva);
            if (noff < 0)
                break;
            dll.name = lower(read_cstr(data, size, size_t(noff)));
            if (dll.name.empty())
                break;

            uint32_t thunk_rva = id.first_thunk ? id.first_thunk : id.original_first_thunk;
            for (size_t k = 0; k < 65536; ++k)
            {
                int64_t toff = img.rva_to_offset(thunk_rva);
                if (toff < 0)
                    break;
                uint64_t entry = 0;
                if (!read_at(data, size, size_t(toff), &entry, 8) || entry == 0)
                    break;
                ImportFunction fn;
                fn.iat_rva = thunk_rva;
                if (entry & 0x8000000000000000ull)
                {
                    fn.by_ordinal = true;
                    fn.ordinal = uint16_t(entry & 0xffff);
                }
                else
                {
                    int64_t noff2 = img.rva_to_offset(uint32_t(entry));
                    if (noff2 < 0)
                        break;
                    uint16_t hint = 0;
                    read_at(data, size, size_t(noff2), &hint, 2);
                    fn.ordinal = hint;
                    fn.name = read_cstr(data, size, size_t(noff2) + 2);
                }
                dll.functions.push_back(std::move(fn));
                thunk_rva += 8;
            }
            if (!dll.functions.empty())
                img.imports.push_back(std::move(dll));
            off += 20;
        }
    }

    // Exports ---------------------------------------------------------------
    const Dir exp_dir = dir(kDataDirExport);
    if (exp_dir.rva != 0)
    {
        int64_t eoff = img.rva_to_offset(exp_dir.rva);
        if (eoff >= 0)
        {
            struct ExpDir
            {
                uint32_t characteristics;
                uint32_t time_date_stamp;
                uint16_t major_version;
                uint16_t minor_version;
                uint32_t name_rva;
                uint32_t base;
                uint32_t number_of_functions;
                uint32_t number_of_names;
                uint32_t address_of_functions;
                uint32_t address_of_names;
                uint32_t address_of_name_ordinals;
            } ed;
            if (read_struct(data, size, size_t(eoff), ed))
            {
                for (uint32_t i = 0; i < ed.number_of_names; ++i)
                {
                    int64_t noff3 = img.rva_to_offset(ed.address_of_names + 4 * i);
                    int64_t ooff = img.rva_to_offset(ed.address_of_name_ordinals + 2 * i);
                    if (noff3 < 0 || ooff < 0)
                        break;
                    uint32_t name_rva = 0;
                    uint16_t ordinal_idx = 0;
                    if (!read_at(data, size, size_t(noff3), &name_rva, 4) ||
                        !read_at(data, size, size_t(ooff), &ordinal_idx, 2))
                        break;
                    int64_t noff4 = img.rva_to_offset(name_rva);
                    if (noff4 < 0)
                        break;
                    ExportEntry e;
                    e.name = read_cstr(data, size, size_t(noff4));
                    e.ordinal = uint16_t(ed.base + ordinal_idx);
                    int64_t foff = img.rva_to_offset(ed.address_of_functions + 4ull * ordinal_idx);
                    if (foff < 0)
                        break;
                    uint32_t fn_rva = 0;
                    if (!read_at(data, size, size_t(foff), &fn_rva, 4))
                        break;
                    e.rva = fn_rva;
                    img.exports.push_back(std::move(e));
                }
                std::sort(img.exports.begin(), img.exports.end(),
                    [](const ExportEntry& a, const ExportEntry& b) { return a.name < b.name; });
            }
        }
    }

    // TLS -------------------------------------------------------------------
    const Dir tls_dir = dir(kDataDirTls);
    if (tls_dir.rva != 0)
    {
        int64_t toff = img.rva_to_offset(tls_dir.rva);
        if (toff >= 0)
        {
            struct TlsDir64
            {
                uint64_t start_address_raw;
                uint64_t end_address_raw;
                uint64_t address_of_index;
                uint64_t address_of_callbacks;
                uint32_t size_of_zero_fill;
                uint32_t characteristics;
            } td;
            if (read_struct(data, size, size_t(toff), td))
            {
                if (td.end_address_raw > td.start_address_raw)
                {
                    img.tls_data_rva = uint32_t(td.start_address_raw - img.image_base);
                    img.tls_data_size = uint32_t(td.end_address_raw - td.start_address_raw);
                }
                if (td.address_of_index)
                    img.tls_index_rva = uint32_t(td.address_of_index - img.image_base);
                if (td.address_of_callbacks)
                {
                    int64_t coff = img.rva_to_offset(uint32_t(td.address_of_callbacks - img.image_base));
                    if (coff >= 0)
                    {
                        for (size_t k = 0; k < 64; ++k)
                        {
                            uint64_t cb = 0;
                            if (!read_at(data, size, size_t(coff) + 8 * k, &cb, 8) || cb == 0)
                                break;
                            img.tls_callbacks.push_back(uint32_t(cb - img.image_base));
                        }
                    }
                }
            }
        }
    }

    img.has_relocations = (oh.dll_characteristics & 0x0040u) != 0; // DYNAMIC_BASE
    return Resolved<Image>::success(std::move(img));
}

// ---------------------------------------------------------------------------

std::string describe_image(const Image& img)
{
    std::string s = "PE32+ image base=0x" + [&] {
        char b[24];
        std::snprintf(b, sizeof(b), "%llx", static_cast<unsigned long long>(img.image_base));
        return std::string(b);
    }() + " entry=0x" + [&] {
        char b[24];
        std::snprintf(b, sizeof(b), "%x", img.entry_rva);
        return std::string(b);
    }() + " size=0x" + [&] {
        char b[24];
        std::snprintf(b, sizeof(b), "%x", img.size_of_image);
        return std::string(b);
    }() + " sections=" + std::to_string(img.sections.size()) + " imports=" + std::to_string(img.imports.size()) +
        " exports=" + std::to_string(img.exports.size()) + " tls_callbacks=" + std::to_string(img.tls_callbacks.size());
    return s;
}

} // namespace lure::emu::pe

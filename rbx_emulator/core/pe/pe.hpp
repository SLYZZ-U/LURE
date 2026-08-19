#pragma once
// rbx_emulator/core/pe/pe.hpp
// Self-contained PE32+ (x64) image parser. No Windows SDK dependency: the
// loader that consumes this model drives the emulated machine directly.
//
// The parser is strict about bounds and format details (DOS/NT headers,
// section table, import descriptor table, export directory, TLS directory)
// and intentionally does NOT interpret semantics: mapping, import resolution
// and TLS callbacks are decisions taken by the guest layer.

#include <cstdint>
#include <string>
#include <vector>

#include "resilience/resolved.hpp"

namespace lure::emu::pe {

// ---------------------------------------------------------------------------
// Image model
// ---------------------------------------------------------------------------

struct Section
{
    std::string name;
    uint32_t virtual_address = 0; // RVA
    uint32_t virtual_size = 0;
    uint32_t raw_ptr = 0;
    uint32_t raw_size = 0;
    uint32_t characteristics = 0; // IMAGE_SCN_* flags (kept raw)

    bool executable() const { return (characteristics & 0x20000000u) != 0; } // MEM_EXECUTE
    bool readable() const { return (characteristics & 0x40000000u) != 0; }   // MEM_READ
    bool writable() const { return (characteristics & 0x80000000u) != 0; }   // MEM_WRITE
};

struct ImportFunction
{
    std::string name;
    uint16_t ordinal = 0;     // hint/ordinal (ordinal used when by_ordinal)
    bool by_ordinal = false;
    uint32_t iat_rva = 0;     // RVA of the IAT slot that must receive the stub address
};

struct ImportDll
{
    std::string name;                    // "kernel32.dll", lowercased
    std::vector<ImportFunction> functions;
};

struct ExportEntry
{
    std::string name;
    uint16_t ordinal = 0;
    uint32_t rva = 0;
};

struct Image
{
    uint64_t image_base = 0;
    uint32_t size_of_image = 0;
    uint32_t size_of_headers = 0;
    uint32_t entry_rva = 0;
    uint32_t file_alignment = 0;
    std::vector<Section> sections;
    std::vector<ImportDll> imports;     // in descriptor order
    std::vector<ExportEntry> exports;   // by name, sorted by name for bsearch
    uint32_t tls_data_rva = 0;          // raw TLS data (for mapping)
    uint32_t tls_data_size = 0;
    uint32_t tls_index_rva = 0;
    std::vector<uint32_t> tls_callbacks; // RVAs of TLS callback entry points
    bool has_relocations = false;

    // RVA helpers -----------------------------------------------------------
    bool rva_in_image(uint32_t rva) const { return rva < size_of_image; }

    // The section containing rva, or nullptr.
    const Section* section_at(uint32_t rva) const;
    // Translate an RVA to a file offset (for reading raw content) or -1.
    int64_t rva_to_offset(uint32_t rva) const;
};

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

// Parses `data` (size bytes) into `out`. Fails with a precise reason on any
// structural problem. The caller keeps `data` alive while using `out`.
Resolved<Image> parse_image(const uint8_t* data, size_t size);

// Human-readable summary (for logs / tests).
std::string describe_image(const Image& img);

} // namespace lure::emu::pe

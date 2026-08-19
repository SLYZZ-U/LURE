cmake_minimum_required(VERSION 3.20)
project(lure CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/utf-8 /permissive-)
endif()

option(LURE_BUILD_TESTS "Build the Catch2 test suite" ON)
option(LURE_USE_Z3 "Build the Z3-based concolic solver" ON)
option(LURE_USE_LUAU "Build the instrumented Luau VM runner (requires third_party/luau submodule)" ON)

include(FetchContent)

FetchContent_Declare(fmt
    GIT_REPOSITORY https://github.com/fmtlib/fmt.git
    GIT_TAG 11.0.2
)
FetchContent_Declare(spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.15.3
)
FetchContent_Declare(CLI11
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG v2.4.2
)
FetchContent_Declare(flatbuffers
    GIT_REPOSITORY https://github.com/google/flatbuffers.git
    GIT_TAG v24.3.25
)

set(CMAKE_CXX_VISIBILITY_PRESET hidden)

if(LURE_BUILD_TESTS)
    FetchContent_Declare(Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.7.1
    )
endif()

if(LURE_USE_Z3)
    FetchContent_Declare(z3
        GIT_REPOSITORY https://github.com/Z3Prover/z3.git
        GIT_TAG z3-4.13.4
    )
    set(Z3_BUILD_PYTHON_BINDINGS OFF CACHE BOOL "" FORCE)
    set(Z3_BUILD_DOTNET_BINDINGS OFF CACHE BOOL "" FORCE)
    set(Z3_BUILD_JAVA_BINDINGS OFF CACHE BOOL "" FORCE)
    set(Z3_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(Z3_BUILD_TEST_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(Z3_USE_LIB_GMP OFF CACHE BOOL "" FORCE)
    set(Z3_BUILD_LIBZ3_SHARED OFF CACHE BOOL "" FORCE)
endif()

FetchContent_MakeAvailable(fmt spdlog CLI11 flatbuffers)

if(LURE_BUILD_TESTS)
    FetchContent_MakeAvailable(Catch2)
endif()

if(LURE_USE_Z3)
    FetchContent_MakeAvailable(z3)
endif()

# Luau submodule: checked out + patched via patches/luau/*.patch.
# The instrumentation hook is compiled into lure_vm; the VM references it,
# so the final link must force-include lure_vm objects (see lure_cli below).
set(LURE_HAS_LUAU OFF)
if(LURE_USE_LUAU)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/luau/CMakeLists.txt")
        set(LUAU_BUILD_CLI OFF CACHE BOOL "" FORCE)
        set(LUAU_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        set(LUAU_BUILD_WEB OFF CACHE BOOL "" FORCE)
        add_subdirectory(third_party/luau)
        set(LURE_HAS_LUAU ON)
        # the patched VM (lvmexecute.cpp) includes src/vm/instrumentation.h for
        # the dispatch hook; the hook implementation itself lives in lure_vm
        target_include_directories(Luau.VM PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src/vm")
    else()
        message(WARNING "LURE_USE_LUAU=ON but third_party/luau is not checked out; building without the Luau VM runner. Run: git submodule update --init third_party/luau")
    endif()
endif()

# Workaround for the transitive issue where FlatBuffers' flatc needs python
# for some platforms; on Windows the CMake target provides the binary directly.
# NOTE: plain target names ("flatc", "flatbuffers") are used because the
# flatbuffers:: alias namespace is only exported by the install() path, while
# FetchContent consumes the targets in-tree.
add_custom_command(
    OUTPUT "${CMAKE_BINARY_DIR}/generated/trace_generated.h"
    COMMAND $<TARGET_FILE:flatc> --cpp -o "${CMAKE_BINARY_DIR}/generated" "${CMAKE_CURRENT_SOURCE_DIR}/schemas/trace.fbs"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/schemas/trace.fbs"
    VERBATIM
)
add_custom_target(lure_flatbuffers_gen ALL DEPENDS "${CMAKE_BINARY_DIR}/generated/trace_generated.h")

add_library(lure_common STATIC
    src/resilience/notfound.cpp
    src/trace/trace_events.cpp
    src/trace/trace_fbs.cpp
)
target_include_directories(lure_common PUBLIC src)
target_include_directories(lure_common PUBLIC "${CMAKE_BINARY_DIR}/generated")
target_link_libraries(lure_common PUBLIC fmt::fmt)
target_link_libraries(lure_common PUBLIC flatbuffers)
add_dependencies(lure_common lure_flatbuffers_gen)

add_library(lure_vm STATIC
    src/vm/ivm_runner.cpp
    src/vm/mock_vm_runner.cpp
)
target_link_libraries(lure_vm PUBLIC lure_common)
if(LURE_HAS_LUAU)
    target_sources(lure_vm PRIVATE
        src/vm/instrumentation.cpp
        src/vm/luau_vm_runner.cpp
    )
    target_include_directories(lure_vm PRIVATE third_party/luau/VM/src)
    target_link_libraries(lure_vm PUBLIC Luau.VM Luau.Compiler Luau.Ast)
    target_compile_definitions(lure_vm PUBLIC LURE_HAS_LUAU=1)
endif()

add_library(lure_concolic STATIC
    src/concolic/solver.cpp
    src/concolic/concolic.cpp
)
target_link_libraries(lure_concolic PUBLIC lure_common)
if(LURE_USE_Z3)
    target_sources(lure_concolic PRIVATE src/concolic/z3_solver.cpp)
    target_compile_definitions(lure_concolic PUBLIC LURE_USE_Z3=1)
    target_link_libraries(lure_concolic PUBLIC Z3::z3)
endif()

add_library(lure_lift STATIC
    src/lift/lifter.cpp
    src/lift/cfg.cpp
    src/lift/dominator.cpp
    src/lift/vm_detector.cpp
)
target_link_libraries(lure_lift PUBLIC lure_common)

add_library(lure_reconstruct STATIC
    src/reconstruct/structural.cpp
    src/reconstruct/pretty.cpp
    src/reconstruct/notfound_log.cpp
    src/reconstruct/constfold.cpp
    src/reconstruct/trace_slice.cpp
    src/reconstruct/payload_decomp.cpp
    src/reconstruct/symbolic.cpp
    src/reconstruct/effects.cpp
)
target_link_libraries(lure_reconstruct PUBLIC lure_lift lure_concolic lure_common)

add_executable(lure
    src/cli/main.cpp
)
target_link_libraries(lure PRIVATE
    lure_reconstruct
    lure_lift
    lure_concolic
    lure_vm
    lure_common
    CLI11::CLI11
    spdlog::spdlog
)
if(LURE_HAS_LUAU)
    # circular static linkage: lure_vm hooks are referenced from Luau.VM, and
    # lure_vm references Luau.* — force-include lure_vm objects into the exe.
    if(MSVC)
        target_link_options(lure PRIVATE "/WHOLEARCHIVE:lure_vm")
    else()
        target_link_options(lure PRIVATE "-Wl,--whole-archive" "$<TARGET_FILE:lure_vm>" "-Wl,--no-whole-archive")
    endif()
endif()

# rbx_emulator: x86-64 guest machine for Luau bytecode (QID front-end).
# Unicorn is vendored under third_party/unicorn and produced as its own
# imported static target.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/unicorn/CMakeLists.txt")
    set(UNICORN_ARCH "x86" CACHE STRING "Unicorn architectures (rbx_emulator only needs x86)")
    set(UNICORN_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(UNICORN_BUILD_SAMPLES OFF CACHE BOOL "" FORCE)
    set(UNICORN_INSTALL OFF CACHE BOOL "" FORCE)
    add_subdirectory(third_party/unicorn)
endif()

add_library(rbx_emulator STATIC
    rbx_emulator/core/pe/pe.cpp
    rbx_emulator/core/guest/guest.cpp
    rbx_emulator/core/ostub/api_stub.cpp
)
target_include_directories(rbx_emulator PUBLIC rbx_emulator)
target_include_directories(rbx_emulator PUBLIC src)      # resilience/resolved.hpp
target_link_libraries(rbx_emulator PUBLIC unicorn)       # imported target from third_party/unicorn
target_link_libraries(rbx_emulator PUBLIC lure_common)   # error strings/notfound helpers if needed

if(LURE_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests/catch2)
endif()
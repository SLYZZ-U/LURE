// vm/luau_vm_runner.cpp
// Layer 1 (luau backend): runs a script on the instrumented Luau VM and drains
// the recorded instruction trace. Only compiled when LURE_HAS_LUAU=1
// (CMakeLists.txt); make_luau_runner() returns nullptr otherwise.

#include "ivm_runner.hpp"

#include "instrumentation.h"
#include "instrumentation.hpp"

#include "trace/trace_events.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include <lua.h>
#include <lualib.h>

#include <Luau/Compiler.h>

#ifdef LURE_HAS_LUAU

#ifdef _WIN32
#include <windows.h>
#endif

namespace lure::vm {

namespace {

void* luau_alloc(void* /*ud*/, void* ptr, size_t /*osize*/, size_t nsize)
{
    if (nsize == 0)
    {
        std::free(ptr);
        return nullptr;
    }
    if (!ptr)
        return std::malloc(nsize);
    return std::realloc(ptr, nsize);
}

// Walks the globals table one level deep and registers every C function under
// its global or module name (name.lua_format, name.format, ...). This is the
// whitelist the instrumentation uses to name natives it cannot otherwise
// resolve; unresolvable entry points are still recorded, just not named.
void register_natives(lua_State* L)
{
    lua_getglobal(L, "_G");
    lua_pushnil(L);
    while (lua_next(L, -2) != 0)
    {
        // key at -2, value at -1
        const char* key = lua_tostring(L, -2);
        std::string name = key ? key : "";
        if (lua_iscfunction(L, -1))
        {
            lua_CFunction fn = lua_tocfunction(L, -1);
            if (fn)
                lure_trace_register_native(name.c_str(), reinterpret_cast<const void*>(fn));
        }
        else if (lua_istable(L, -1))
        {
            std::string mname = name;
            lua_pushnil(L);
            while (lua_next(L, -2) != 0)
            {
                const char* k = lua_tostring(L, -2);
                if (lua_iscfunction(L, -1) && k && !mname.empty())
                {
                    lua_CFunction fn = lua_tocfunction(L, -1);
                    if (fn)
                    {
                        std::string full = mname + "." + k;
                        lure_trace_register_native(full.c_str(), reinterpret_cast<const void*>(fn));
                    }
                }
                lua_pop(L, 1);
            }
        }
        lua_pop(L, 1);
    }
    lua_pop(L, 1);
}

// Captures the printing VM's "print" output for the duration of a run so it
// lands in RunResult.stdout_text.
//
// The capture redirects only the VM's own print sink (a hook installed into
// luaB_print, see third_party/luau/VM/src/lbaselib.cpp) into a process-local
// buffer. The process stdout stream and its descriptors are never touched,
// which keeps in-process loggers (spdlog) working across multiple runs.
extern "C" void (*lure_luau_print_sink)(const char* s, size_t l) = nullptr;

namespace {

std::string g_print_capture;
bool g_capturing = false;

void print_sink_impl(const char* s, size_t l)
{
    // Behaviorally mark the call event that produced this output (name-free
    // "this call printed" detection, see lure_trace_mark_output_written).
    lure_trace_mark_output_written();
    if (g_capturing)
        g_print_capture.append(s, l);
    else
        std::fwrite(s, 1, l, stdout);
}

} // namespace

class StdoutCapture
{
public:
    bool begin(std::string& /*err*/)
    {
        if (!g_sink_installed)
        {
            lure_luau_print_sink = print_sink_impl;
            g_sink_installed = true;
        }
        g_print_capture.clear();
        g_capturing = true;
        return true;
    }

    std::string end()
    {
        g_capturing = false;
        return std::move(g_print_capture);
    }

private:
    static bool g_sink_installed;
};

bool StdoutCapture::g_sink_installed = false;

// ---------------------------------------------------------------------------
// Roblox environment stubs (--roblox): a minimal DataModel so module
// initialization that touches game/workspace/script/require does not abort on
// a nil global. Stubs are deliberately permissive: unknown members read as a
// callable stub (so `x:Method()` chains keep running), unknown calls return
// nil. The stub C functions are discovered by register_natives() below and
// therefore get readable names in the recorded trace.
// ---------------------------------------------------------------------------

static int rbx_anyfn(lua_State* L);  // forward: generic callable stub
static void push_instance(lua_State* L, const char* name, const char* className, int parent);

// pushes { Connected = true, Disconnect = noop, Fire = noop, Wait = nilfn }
static int rbx_signal_connect(lua_State* L)
{
    (void)L;
    lua_newtable(L);
    lua_pushboolean(L, 1);
    lua_setfield(L, -2, "Connected");
    lua_pushcfunction(L, rbx_anyfn, "stub.any");
    lua_setfield(L, -2, "Disconnect");
    lua_pushcfunction(L, rbx_anyfn, "stub.any");
    lua_setfield(L, -2, "Fire");
    lua_pushcfunction(L, rbx_anyfn, "stub.any");
    lua_setfield(L, -2, "Wait");
    return 1;
}

static int rbx_signal_wait(lua_State* L)
{
    (void)L;
    return 0; // nil: never yields, never fires
}

static void push_signal(lua_State* L)
{
    lua_newtable(L);
    lua_pushcfunction(L, rbx_signal_connect, "stub.Connect");
    lua_setfield(L, -2, "Connect");
    lua_pushcfunction(L, rbx_signal_connect, "stub.Connect");
    lua_setfield(L, -2, "Once");
    lua_pushcfunction(L, rbx_signal_wait, "stub.Wait");
    lua_setfield(L, -2, "Wait");
    lua_pushcfunction(L, rbx_anyfn, "stub.any");
    lua_setfield(L, -2, "Fire");
}

static int rbx_anyfn(lua_State* L)
{
    (void)L;
    return 0; // unknown member/call -> nil
}

static int rbx_instance_call(lua_State* L)
{
    (void)L;
    lua_newtable(L);
    lua_pushcfunction(L, rbx_anyfn, "stub.any");
    lua_setfield(L, -2, "__call");
    lua_setmetatable(L, -2);
    return 1;
}

static int rbx_getfullname(lua_State* L)
{
    (void)L;
    lua_pushliteral(L, "prometheus");
    return 1;
}

static int rbx_findfirstchild(lua_State* L)
{
    (void)L;
    return 0; // nil: no children in the stub world
}

static int rbx_getchildren(lua_State* L)
{
    (void)L;
    lua_newtable(L);
    return 1;
}

static int rbx_isa(lua_State* L)
{
    (void)L;
    lua_pushboolean(L, 0);
    return 1;
}

static int rbx_clone(lua_State* L)
{
    (void)L;
    push_instance(L, "Clone", "Instance", LUA_NOREF);
    return 1;
}

static int rbx_instance_new(lua_State* L)
{
    const char* cls = luaL_optstring(L, 2, "Instance");
    push_instance(L, cls, cls, LUA_NOREF);
    return 1;
}

// pushes a fresh stub instance table on top of the stack.
// parent: absolute stack index of the Parent instance, or LUA_NOREF.
static void push_instance(lua_State* L, const char* name, const char* className, int parent)
{
    lua_newtable(L);
    int self = lua_gettop(L);
    lua_pushstring(L, name ? name : "");
    lua_setfield(L, self, "Name");
    lua_pushstring(L, className ? className : "Instance");
    lua_setfield(L, self, "ClassName");
    if (parent != LUA_NOREF)
    {
        lua_pushvalue(L, parent);
        lua_setfield(L, self, "Parent");
    }
    lua_pushcfunction(L, rbx_getfullname, "stub.GetFullName");
    lua_setfield(L, self, "GetFullName");
    lua_pushcfunction(L, rbx_findfirstchild, "stub.FindFirstChild");
    lua_setfield(L, self, "FindFirstChild");
    lua_pushcfunction(L, rbx_findfirstchild, "stub.FindFirstChild");
    lua_setfield(L, self, "WaitForChild");
    lua_pushcfunction(L, rbx_findfirstchild, "stub.FindFirstChild");
    lua_setfield(L, self, "FindFirstChildOfClass");
    lua_pushcfunction(L, rbx_getchildren, "stub.GetChildren");
    lua_setfield(L, self, "GetChildren");
    lua_pushcfunction(L, rbx_getchildren, "stub.GetChildren");
    lua_setfield(L, self, "GetDescendants");
    lua_pushcfunction(L, rbx_isa, "stub.IsA");
    lua_setfield(L, self, "IsA");
    lua_pushcfunction(L, rbx_anyfn, "stub.any");
    lua_setfield(L, self, "Destroy");
    lua_pushcfunction(L, rbx_anyfn, "stub.any");
    lua_setfield(L, self, "Remove");
    lua_pushcfunction(L, rbx_anyfn, "stub.any");
    lua_setfield(L, self, "ClearAllChildren");
    lua_pushcfunction(L, rbx_anyfn, "stub.any");
    lua_setfield(L, self, "GetAttribute");
    lua_pushcfunction(L, rbx_anyfn, "stub.any");
    lua_setfield(L, self, "SetAttribute");
    // signals commonly connected during init
    static const char* const kSignals[] = {"Changed", "ChildAdded", "ChildRemoved",
        "Heartbeat", "Stepped", "RenderStepped", "PlayerAdded", "PlayerRemoving"};
    for (const char* s : kSignals)
    {
        push_signal(L);
        lua_setfield(L, self, s);
    }
    // unknown members read as a callable stub; calling the instance returns a
    // fresh stub instance
    lua_newtable(L);
    lua_pushcfunction(L, rbx_anyfn, "stub.any");
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, rbx_instance_call, "stub.__call");
    lua_setfield(L, -2, "__call");
    lua_setmetatable(L, self);
}

static int rbx_getservice(lua_State* L)
{
    const char* name = luaL_optstring(L, 1, "DataModel");
    // parent: the DataModel is at a fixed upvalue-free spot; use the registry
    // slot set up by install_roblox_stubs
    lua_pushliteral(L, "lure_datamodel");
    lua_rawget(L, LUA_REGISTRYINDEX);
    push_instance(L, name, name, lua_gettop(L) - 1);
    return 1;
}

static int rbx_getobjects(lua_State* L)
{
    (void)L;
    lua_newtable(L);
    return 1;
}

static int rbx_require(lua_State* L)
{
    (void)L;
    // a module stub: callable and indexable without aborting init
    lua_newtable(L);
    lua_newtable(L);
    lua_pushcfunction(L, rbx_anyfn, "stub.any");
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, rbx_require, "require");
    lua_setfield(L, -2, "__call");
    lua_setmetatable(L, -2);
    return 1;
}

static int rbx_spawn(lua_State* L)
{
    lua_settop(L, 1);
    lua_pcall(L, 0, 0, 0);
    return 0;
}

static int rbx_getfenv(lua_State* L)
{
    (void)L;
    lua_getglobal(L, "_G");
    return 1;
}

static int rbx_setfenv(lua_State* L)
{
    (void)L;
    return 0;
}

static int rbx_zeronumber(lua_State* L)
{
    (void)L;
    lua_pushnumber(L, 0.0);
    return 1;
}

// installs the stubs into the global table; must run after luaL_openlibs so
// that register_natives() can pick the C functions up for naming.
static void install_roblox_stubs(lua_State* L)
{
    // DataModel ("game")
    push_instance(L, "Game", "DataModel", LUA_NOREF);
    lua_pushcfunction(L, rbx_getservice, "game.GetService");
    lua_setfield(L, -2, "GetService");
    lua_pushcfunction(L, rbx_getobjects, "game.GetObjects");
    lua_setfield(L, -2, "GetObjects");
    // stash the DataModel for rbx_getservice's parent chain
    lua_pushliteral(L, "lure_datamodel");
    lua_pushvalue(L, -2);
    lua_rawset(L, LUA_REGISTRYINDEX);
    lua_setglobal(L, "game");
    lua_getglobal(L, "game");
    lua_setglobal(L, "workspace"); // workspace: the DataModel itself is fine

    // script: the module we are tracing
    lua_getglobal(L, "game");
    push_instance(L, "prometheus", "ModuleScript", lua_gettop(L));
    lua_setglobal(L, "script");
    lua_pop(L, 1);

    lua_pushcfunction(L, rbx_require, "require");
    lua_setglobal(L, "require");
    lua_pushcfunction(L, rbx_spawn, "spawn");
    lua_setglobal(L, "spawn");
    lua_pushcfunction(L, rbx_spawn, "spawn");
    lua_setglobal(L, "delay");
    lua_pushcfunction(L, rbx_anyfn, "stub.any");
    lua_setglobal(L, "wait");
    lua_pushcfunction(L, rbx_zeronumber, "tick");
    lua_setglobal(L, "tick");
    lua_pushcfunction(L, rbx_zeronumber, "tick");
    lua_setglobal(L, "time");
    lua_pushcfunction(L, rbx_getfenv, "getfenv");
    lua_setglobal(L, "getfenv");
    lua_pushcfunction(L, rbx_setfenv, "setfenv");
    lua_setglobal(L, "setfenv");

    // task.*
    lua_newtable(L);
    lua_pushcfunction(L, rbx_spawn, "spawn");
    lua_setfield(L, -2, "wait");
    lua_pushcfunction(L, rbx_spawn, "spawn");
    lua_setfield(L, -2, "spawn");
    lua_pushcfunction(L, rbx_spawn, "spawn");
    lua_setfield(L, -2, "delay");
    lua_pushcfunction(L, rbx_spawn, "spawn");
    lua_setfield(L, -2, "defer");
    lua_pushcfunction(L, rbx_anyfn, "stub.any");
    lua_setfield(L, -2, "desynchronize");
    lua_pushcfunction(L, rbx_anyfn, "stub.any");
    lua_setfield(L, -2, "synchronize");
    lua_setglobal(L, "task");

    // Instance.new
    lua_newtable(L);
    lua_pushcfunction(L, rbx_instance_new, "Instance.new");
    lua_setfield(L, -2, "new");
    lua_setglobal(L, "Instance");

    // Enum: minimal, any member reads as a callable stub
    lua_newtable(L);
    lua_newtable(L);
    lua_pushcfunction(L, rbx_anyfn, "stub.any");
    lua_setfield(L, -2, "__index");
    lua_setmetatable(L, -2);
    lua_setglobal(L, "Enum");

    // shared
    lua_newtable(L);
    lua_setglobal(L, "shared");

    // exploit-library API commonly captured by module init; all read as
    // callable stubs so the capture does not end up with nil slots
    static const char* const kExploitApi[] = {
        "getgenv", "getrawmetatable", "hookfunction", "hookmetamethod", "clonefunction",
        "newcclosure", "iscclosure", "islclosure", "checkcaller", "setreadonly",
        "getreadonly", "make_writeable", "getreg", "getgc", "getinstances",
        "getnilinstances", "getsenv", "getscriptbytecode", "getrunningscripts",
        "decompile", "getinfo", "getstack", "getproto", "getupvalue", "setupvalue",
        "getupvalues", "setnamecallmethod", "getnamecallmethod", "getscriptclosure",
        "fireclickdetector", "firetouchinterest", "fireproximityprompt", "protect_gui",
        "unprotect_gui", "gethui", "getcustomasset", "queue_on_teleport",
        "setclipboard", "islibrarything", "loadstring", "setidentity",
    };
    for (const char* g : kExploitApi)
    {
        lua_pushcfunction(L, rbx_anyfn, g);
        lua_setglobal(L, g);
    }
}

// Probe safety net: inverting a branch can steer a control-flow-flattened
// dispatcher into a state it never reaches normally, and that can fail to
// terminate. Probe runs therefore get a step budget enforced at VM safepoints
// (loop back edges and calls); exhausting it raises a normal Lua error, which
// lua_pcall reports as a failed run so the probe is simply discarded.
static long long g_probe_budget = -1;

void probe_interrupt(lua_State* L, int gc)
{
    if (gc >= 0)
        return; // GC step, not a safepoint tick
    if (g_probe_budget < 0)
        return;
    if (--g_probe_budget <= 0)
    {
        g_probe_budget = -1;
        luaL_error(L, "lure: probe step budget exhausted");
    }
}

RunResult run_instrumented(const RunRequest& req)
{
    RunResult res;
    res.vm_kind = "luau-instrumented";

    lure_trace_reset();
    lure_trace_set_max_events(req.max_events);
    if (req.flip)
        lure_trace_arm_branch_flip(req.flip->frame_id, req.flip->pc, req.flip->hit_index);
    // LURE_NO_TRACE=1 runs the script with the dispatch hook disabled. Nothing is
    // recorded, so no reconstruction is possible -- it exists to answer one
    // question about a script that fails: does it fail *because* it is being
    // traced? Anything that behaves differently with this set is reacting to the
    // instrumentation, not to its own logic.
    const char* notrace = std::getenv("LURE_NO_TRACE");
    lure_trace_set_enabled(notrace && *notrace == '1' ? 0 : 1);

    lua_State* L = lua_newstate(luau_alloc, nullptr);
    if (!L)
    {
        res.ok = false;
        res.error = "lua_newstate failed";
        lure_trace_set_enabled(0);
        return res;
    }

    luaL_openlibs(L);
    if (req.roblox_env)
        install_roblox_stubs(L);
    register_natives(L);

    // Luau seeds math.random from the state address, time() and clock(), so two
    // runs of the same script diverge. A trace-based decompiler needs replay: the
    // reconstruction is checked by re-running the emitted Lua, and branch
    // recovery compares a run against the same run with one decision inverted --
    // both meaningless if the interpreter is not reproducible. Re-seeding to a
    // fixed value costs nothing (a randomized obfuscator decoder still decodes to
    // the same payload; only the arbitrary path it takes is pinned) and is the
    // only way the two runs can be compared at all. Done through the public API
    // and before any bytecode runs, so it records no trace events.
    lua_getglobal(L, "math");
    if (lua_istable(L, -1))
    {
        lua_getfield(L, -1, "randomseed");
        if (lua_isfunction(L, -1))
        {
            lua_pushnumber(L, 0);
            if (lua_pcall(L, 1, 0, 0) != LUA_OK)
                lua_pop(L, 1); // error object; seeding is best effort
        }
        else
            lua_pop(L, 1);
    }
    lua_pop(L, 1);

    if (req.flip)
    {
        g_probe_budget = long long(req.max_events);
        lua_callbacks(L)->interrupt = probe_interrupt;
    }

    StdoutCapture cap;
    std::string cap_err;
    if (!cap.begin(cap_err))
        res.error = cap_err; // capture is best effort; do not fail the run

    // source -> bytecode (Luau.Compiler), bytecode -> VM (luau_load). The
    // debug level must be >= 2 so protos carry source names (locvars the
    // instrumentation reads to name registers).
    int status = LUA_ERRRUN;
    std::string bcerr;
    try
    {
        Luau::CompileOptions copts;
        copts.debugLevel = 2;
        // A decompiler wants the *original* structure, so disable the optimizer:
        // at the default level Luau constant-folds table fields and eliminates
        // provably-constant branches (e.g. `if t.bool == true` when t is a local
        // literal), erasing the very tables/conditionals we aim to recover before
        // they are ever traced. Level 0 keeps NEWTABLE/SETTABLE, GETTABLE field
        // reads and JUMPIF branches intact. Generic; no per-script tuning.
        copts.optimizationLevel = 0;
        // Escape hatch for diagnosing a script that only fails at level 0:
        // LURE_OPT_LEVEL=1|2 restores the optimizer. Reconstruction quality
        // drops sharply (folded fields and eliminated branches never reach the
        // trace), so this is a debugging aid, not a supported mode.
        if (const char* lvl = std::getenv("LURE_OPT_LEVEL"))
            copts.optimizationLevel = std::atoi(lvl);
        std::string bytecode = Luau::compile(req.source, copts);
        std::string load_err;
        if (luau_load(L, "=lure", bytecode.data(), bytecode.size(), 0) == LUA_OK)
            status = lua_pcall(L, 0, 0, 0);
        else
            bcerr = "bytecode load failed";
    }
    catch (const std::exception& ex)
    {
        bcerr = std::string("compile/load failed: ") + ex.what();
    }

    res.stdout_text = cap.end();
    res.flip_fired = req.flip && lure_trace_branch_flip_fired() != 0;

    if (status != LUA_OK)
    {
        const char* msg = lua_tostring(L, -1);
        res.ok = false;
        res.error = msg ? msg : (bcerr.empty() ? "unknown error (load or runtime)" : bcerr);
    }

    // drain events even on failure: the executed prefix is still a trace
    res.trace.events = instrumentation::drain_events();
    res.trace.vm_kind = "luau-instrumented";
    res.trace.source_script = req.source;
    res.trace.mode = req.mode;
    if (!res.ok && !req.flip)
    {
        // diagnostic aid: the tail of the recorded prefix locates the failing
        // instruction (its pc) in the obfuscated bytecode. Suppressed for probe
        // runs: inverting a branch is expected to derail some paths, and the
        // caller already reports that as "the other side is not reproducible".
        std::fprintf(stderr, "lure: error tail (%zu events):\n", res.trace.events.size());
        size_t start = res.trace.events.size() > 25 ? res.trace.events.size() - 25 : 0;
        for (size_t i = start; i < res.trace.events.size(); ++i)
        {
            const TraceEvent& e = res.trace.events[i];
            std::fprintf(stderr, "  pc=%u %-12s %s", e.pc, e.tag.c_str(), e.text.c_str());
            if (e.table_op)
            {
                const auto& k = e.table_op->key;
                std::fprintf(stderr, "  [key=%s", k.text.c_str());
                if (!k.text.empty())
                {
                    bool printable = true;
                    for (unsigned char ch : k.text)
                        if (ch < 32 || ch > 126)
                        {
                            printable = false;
                            break;
                        }
                    if (!printable)
                    {
                        std::fprintf(stderr, " hex=");
                        for (unsigned char ch : k.text)
                            std::fprintf(stderr, "%02x", ch);
                    }
                }
                std::fprintf(stderr, "]");
            }
            if (e.call_info)
            {
                std::fprintf(stderr, "  [fn=%s", e.call_info->fn.text.c_str());
                for (const auto& a : e.call_info->args)
                    std::fprintf(stderr, ", %s", a.text.c_str());
                std::fprintf(stderr, "]");
            }
            std::fprintf(stderr, "\n");
        }
    }
    if (instrumentation::truncated())
    {
        TraceEvent ev;
        ev.tag = "TRUNCATED";
        ev.status = ResolutionStatus::Unresolved;
        ev.notfound_reason =
            "trace truncated at " + std::to_string(req.max_events) +
            " events (--max-events); remaining execution not recorded";
        res.trace.events.push_back(std::move(ev));
    }

    lua_close(L);
    lure_trace_set_enabled(0);
    g_probe_budget = -1;
    return res;
}

} // namespace

class LuauRunner : public IVMRunner
{
public:
    RunResult run(const RunRequest& req) override { return run_instrumented(req); }
    std::string kind() const override { return "luau-instrumented"; }
    bool accepts_overrides() const override { return false; }
};

} // namespace lure::vm

namespace lure::vm {

std::unique_ptr<IVMRunner> make_luau_runner()
{
    return std::make_unique<LuauRunner>();
}

} // namespace lure::vm

#else

namespace lure::vm {

std::unique_ptr<IVMRunner> make_luau_runner()
{
    return nullptr;
}

} // namespace lure::vm

#endif // LURE_HAS_LUAU
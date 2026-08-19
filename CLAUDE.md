# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

LURE is a **dynamic decompiler for Luau (Roblox Lua)**. It runs a script in an instrumented Luau VM, records a per-opcode execution trace, and reconstructs readable Lua from *only what execution proves*. The defining rule is the **honesty contract**: nothing is invented — anything not observed becomes a `-- not found: <reason>` annotation, and a reconstruction is accepted only if re-running it reproduces the recorded behaviour. Where one path is not enough (the un-taken side of an `if`), the answer comes from *another observation* — re-running with that one branch decision inverted — never from inference. The intended use is deobfuscating protected Roblox scripts, entirely by behavioral trace analysis (no obfuscator signatures / no pattern database).

What it reconstructs is the frame carrying the run's **observable effects** and, recursively, the functions it calls: calls, writes to globals, mutations of tables it rebuilt, returns — with operands rendered as propagated expressions. Computation that never reaches an observable effect is never emitted, which is exactly what makes an obfuscator's decoder and its flattened dispatch disappear without knowing anything about either.

`rbx_emulator/` is a **separate** subsystem: a Unicorn x86-64 PE emulator with a from-scratch Windows-API stub layer. It builds and is unit-tested but is **not** linked into the `lure` CLI nor referenced by `src/` — treat it as independent.

## Build

- The Luau submodule is required and must be patched: `git submodule update --init third_party/luau`, then apply `patches/luau/*.patch` to it. (`third_party/unicorn` and `third_party/capstone` are vendored in-tree, not submodules; capstone is currently unreferenced.)
- Configure (once): `cmake -B build` — on Windows this is a multi-config Visual Studio generator.
- Build everything: `cmake --build build --config Release`. Just the CLI: `cmake --build build --config Release --target lure`.
- Configure options (`-DLURE_...=ON/OFF`): `LURE_USE_LUAU` (instrumented VM; needs the submodule — without it only the mock backend exists), `LURE_USE_Z3` (concolic solver; Z3 is a large, slow first build), `LURE_BUILD_TESTS`.
- Deps are fetched via FetchContent (fmt, spdlog, CLI11, flatbuffers, Catch2, Z3). `schemas/trace.fbs` is codegen'd to `build/generated/trace_generated.h` by `flatc` at build time.

## Test

- All tests: `ctest --test-dir build -C Release`, or run the binary directly: `build/tests/catch2/Release/lure_tests.exe`.
- A single test (Catch2 name filter): `build/tests/catch2/Release/lure_tests.exe "constant folding substitutes observed values"`. Tag filters (e.g. `[reconstruct]`, `[sym]` for the symbolic pass and branch recovery) also work.
- Tests use inline literal assertions and hand-built fixtures (no golden files); most pipeline tests drive the mock backend, so they pass without the Luau submodule. Branch recovery is tested with a stub `BranchProbe`, so it needs no VM either.

## Run

- `build/Release/lure.exe <script.lua> [-o out.lua] [--vm mock|luau] [--roblox] [--dump-trace f] [--max-events N]`. There is **no `run` subcommand** despite some stale top-of-file comments. Output: `<out>.dec.lua` and `<out>.dec.lua.notfound`.
- `--roblox` installs minimal DataModel / exploit-env stubs so obfuscated module init doesn't abort on nil globals.
- `--dump-trace <file>` writes the folded per-event list (pc, depth, frame, tag, raw instruction word, rendered text, branch condition) — the primary tool for debugging reconstruction.
- `--max-events` defaults to 1,000,000. Obfuscated payloads are event-hungry (the randomized decoder in `prom.med` alone emits ~325k events); a truncated trace silently degrades reconstruction to the coarse fallback, so lower it only for quick experiments.
- Env vars: `LURE_LOG=trace|debug|info|warn|error` (verbosity), `LURE_DEBUG_NIL=1` (dump constant pools on nil-value calls), `LURE_DEBUG_SYM=1` (per-event decoded operands + table key as the symbolic pass sees them — what `--dump-trace` cannot show), `LURE_NO_TRACE=1` (run the script with the dispatch hook off and record nothing: answers "does this script fail *because* it is traced?"), `LURE_OPT_LEVEL=1|2` (restore the Luau optimizer; wrecks reconstruction, diagnostics only). Exit codes: `0` reconstructed, `1` usage/IO error, `2` interpreter failure with nothing recorded.

## Architecture

The whole pipeline lives in `src/` and is driven top-to-bottom by `cli/main.cpp::run()`. The universal data structure is `TraceEvent`/`TraceData` (`trace/trace_events.hpp`) — one event per executed opcode, carrying opcode, raw instruction word, `proto_id`, `frame_id`, `call_depth`, a rendered `text`, value snapshots, call/table info, and branch info (including `cond_rhs_reg`, the register holding a two-operand conditional's right-hand side, which is not recoverable from the instruction word alone). It is mirrored on disk by the FlatBuffers schema `schemas/trace.fbs` (the two must stay in sync; new fields go at the **end** of the table, as flatbuffers requires).

1. **VM backends** (`vm/`, lib `lure_vm`) implement `IVMRunner`: the real **instrumented Luau VM** (`luau_vm_runner.cpp` + `instrumentation.cpp`, `vm_kind="luau-instrumented"`) or an always-available `mock_vm_runner.cpp` (`"mock"`). The Luau VM is patched to call `lure_trace_dispatch(L, pc)` before every opcode. A run can additionally carry a `RunRequest::flip` — one conditional jump to execute with its decision inverted (see **branch probing** below).
2. **Lift** (`lift/`): `cfg.cpp` (trace → CFG), `dominator.cpp`, `lifter.cpp` (natural loops + numeric-for pairing) → `LiftedProgram`. Interspersed passes: `reconstruct/constfold.cpp` (evaluates observed constant expressions — this is what surfaces decrypted strings) and `reconstruct/trace_slice.cpp`.
3. **Reconstruct** (`reconstruct/`): two reconstructions plus a fallback, all gated by re-execution.
   - `symbolic.cpp` is the **general** one: it interprets the frame that carries the run's observable effects at opcode level, keeping a propagated expression per register, and emits a statement for **every effect it can express** — calls, writes to globals, mutations of tables it rebuilt, returns — not only prints. It recovers a called Lua function as a `function` when that function has effects of its own, folds a numeric `for` and a back-edge (`while`-shaped) loop when the fold provably reproduces every observed iteration, and drops every binding nothing reads.
   - `payload_decomp.cpp` holds the narrower, print-anchored passes (`decompile_payload_symbolic`, a forward pass over the printing frame, and `decompile_payload`, a backward register slice) plus the shared probe/region machinery both reconstructions use for `if/else`.
   - `structural.cpp` → `pretty.cpp` render the executed path as if/while/for/plain when nothing above verifies. This path has **no** verification gate and reuses register names loosely, so its output can read like wrong code; it is the last resort, not the goal.
   - `trace_slice.cpp` narrows the trace to the printing frames when the payload runs deeper than a loader; `constfold.cpp` evaluates observed constant expressions; `notfound_log.cpp` writes the sidecar.
4. **Concolic** (`concolic/`, lib `lure_concolic`): `concolic.cpp` + `z3_solver.cpp` (only when `LURE_USE_Z3`) report feasibility of the un-taken side of observed branches — annotate-only, never altering the reconstruction.

`main.cpp` offers every reconstruction as a **candidate** and accepts one only if re-running it reproduces the recorded stdout byte-for-byte. Several can pass, and they are not equally informative — one may reproduce the output while saying nothing about the calls and writes that produced it — so the winner is the candidate that expresses the most observable effects, then the one that recovered more conditionals, then the one leaving fewest effects unexpressed. `LURE_DUMP_CANDIDATES=1` writes every candidate to disk, including the ones that failed the re-run; that is the first thing to look at when the output is worse than expected.

### Branch probing (recovering `if/else`)

A single trace contains **no information whatsoever** about the side of a branch it did not take: the un-taken target pc never appears in it, and under control-flow flattening both sides re-enter the dispatcher, so the guarded block is not even adjacent to the branch and static control dependence is gone by construction. Guessing the extent of the guarded block would invent structure, so instead the pipeline **re-runs the script with that one decision inverted** and diffs the two reconstructions:

- `instrumentation.cpp` implements a one-shot inversion armed by `lure_trace_arm_branch_flip(frame_id, pc, hit_index)`: on that dispatch the instruction word is rewritten to the complementary conditional (`JUMPIF`↔`JUMPIFNOT`, `JUMPIFEQ`↔`JUMPIFNOTEQ`, `JUMPIFLE`↔`JUMPIFNOTLE`, `JUMPIFLT`↔`JUMPIFNOTLT`; the `JUMPXEQK*` family toggles the NOT bit of its aux word) and restored at the top of the next dispatch. Complementary pairs share their jump target, so this inverts *which* declared side runs and nothing else. Purely opcode-level: no obfuscator knowledge.
- `payload_decomp.cpp` nominates candidates and `main.cpp` supplies the `BranchProbe` callback that performs the run. Longest common prefix/suffix of the two statement lists gives the then-body (from the recorded run) and the else-body (from the probe) — **both observed, neither inferred**.
- Everything is gated: the inversion must actually fire, the probe run must complete, its trace must not be truncated, the divergence must start at or after the branch, and the else-body may not reference a table the recorded run never built (verification cannot catch that, since the `else` never runs during the re-run). Each failed gate becomes a `-- not found`-style note in `PayloadDecompResult::why`, never a guess. Probes are capped at 32 per run and the dropped count is reported.
- Candidates are bounded by a data-flow criterion, not a signature: a branch qualifies only when both operands are nameable from reconstructed data and at least one is more than an opaque literal. That skips a flattened dispatcher's `state >= 16267730` comparisons (both sides opaque scalars) without knowing anything about the obfuscator; a branch it skips is simply left un-recovered.
- Probing compares two executions, so `main.cpp` first re-runs the script **unflipped** and refuses to probe at all unless the statement list and stdout replay identically.

Cross-cutting foundation in `lure_common`: `resilience/resolved.hpp` (`Resolved<T>` — never throws, never guesses) and `resilience/notfound.hpp` (the not-found marker used at every layer).

## Non-obvious things to know

- **Patched Luau + whole-archive link.** `patches/luau/0001-*` injects the per-opcode trace hook into `VM/src/lvmexecute.cpp`; `0002-*` reroutes `print` through an overridable sink so the verification re-run captures stdout without corrupting CRT streams. The patched VM references symbols defined in `lure_vm`, so the final link force-includes `lure_vm` objects (see the `lure` target in `CMakeLists.txt`). Patches must be applied to the submodule before building.
- **Scripts are compiled at `optimizationLevel=0`** (`luau_vm_runner.cpp`) on purpose: at the default level Luau constant-folds table fields and eliminates provably-constant branches, erasing the very tables/conditionals a decompiler aims to recover before they are ever traced. Verified on `plain.lua`: at the default level its trace is 9 events with no table fields and no `if` at all; at level 0 it is 17 events carrying `SETTABLE`, `GETTABLEKS` and the `JUMPIFNOTEQ`.
- **The run is forced to be reproducible.** Luau seeds `math.random` from the state address, `time()` and `clock()`, so two runs of `prom.med` differed by ~100k events. Every layer here depends on replay — the reconstruction is checked by re-running it, and branch probing compares a run against the same run with one decision inverted — so `luau_vm_runner.cpp` re-seeds to a fixed value through the public API before any bytecode runs. Do not remove this: without it `prom.med` cannot be probed at all, and `main.cpp`'s reproducibility check disables probing.
- **The trace is already the unrolled linear execution**, which is why control-flow flattening is tractable here: a forward pass over the printing frame recovers real statements while dispatch arithmetic that reaches no observable effect is simply never emitted. No obfuscator-specific knowledge is involved.
- **An un-taken branch side is unobservable from one trace** — not merely hard, *absent*. This is why `if/else` recovery is a re-execution problem rather than an analysis problem; see **Branch probing** above. The corollary is that the recovered `else` body is observed under a forced condition, which the sidecar states explicitly.
- **Dead-binding elimination is what removes an obfuscator's decoder**, and it needs no knowledge of one. A decoder exists to produce values the payload then carries as literals; once those literals are in place nothing reads the decoder's results, so dropping every binding nothing reads collapses the whole chain. A dropped call that had reached the outside world would be a silent loss, so an observable one keeps its call and loses only the binding.
- **A loop-carried value must become a variable, not an expression.** Propagating an accumulator through iterations makes its expression grow without bound and makes it mention a loop variable that is out of scope afterwards (`total` came out as `(0 + (i0 * 10)) + (i0 * 10)`). `symbolic.cpp` pre-scans a loop body, binds every register it writes that already holds a value to a real local, and turns later writes into assignments.
- **`FORNLOOP` tests *after* incrementing.** Reporting the pre-increment comparison made the last iteration look like a continue, so a numeric for's exit was never visible in the trace and no loop was ever folded. `decode_branch` compensates; if loop recovery ever silently stops working, check that first.
- **A loop's own test is not an `if`.** A branch that is part of a loop body is never offered for probing: wrapping the back-edge test of a `while` in an `if/else` produced output that reproduced the stdout while claiming a structure the source did not have. Structure that merely verifies is not good enough.
- **`snapshot()` rejects any pointer outside the Lua stack** (`instrumentation.cpp`) as an untrusted access. A proto constant is *legitimately* outside it, so constant operands go through `snapshot_constant()`. Reading a constant with `snapshot()` silently yields an Unknown value — that bug is exactly what made `GETTABLEKS` field recovery fail on plain scripts.
- **Where a table op's key lives depends on the opcode**: register C for `GET/SETTABLE`, the AUX constant index for the `*KS` forms (C there is an inline-cache slot), and the immediate `C+1` for the `*N` forms. `instrumentation.cpp` switches on this; reading register C unconditionally reports a wrong key for four of the six opcodes.
- **The CFG keys nodes on `(proto_id, pc)`**, packed into one 64-bit key by `lift::node_key` (`cfg.hpp`), because a pc is only unique inside its own function. `Node::pc` *is* that key; `raw_pc`/`proto_id` are kept for display and `lift::key_text` renders it. A backend with a single code body reports proto 0, which makes the key equal to the pc — so the mock-backend tests are unaffected.
- **`printed_output` is set behaviorally** by the runtime print sink, never by callee name. Frame slicing and payload detection depend on this — keep any output detection name-free.
- **Reconstruction covers the observed path plus whatever a probe proved about the other side of a branch.** Anything neither observed nor probed is annotated, never synthesized.

## Status and remaining work

Goal: feed an obfuscated Roblox script and recover equivalent original Lua, fully generically — no obfuscator signatures, no hardcoded values, nothing invented. Validation samples live in `C:\Users\noelb\Desktop\test\`: `prom.weak/med/strong.lua` (Prometheus control-flow-flattening), `moonveil-cff/vm.lua` (a hand-rolled Lua bytecode VM), and `plain.lua` (the un-obfuscated oracle). All of them print `hi` then `bool is true`. The oracle source is a table `{string="hi", bool=true}`, a `print(t.string)`, and an `if t.bool == true then … else … end`; only the `then` executes in the recorded run, so the `else` is recovered by *re-executing that branch the other way* (see **Branch probing**) and is never inferred. Variable names and comments are destroyed by obfuscation and are not recoverable — "1:1" here means behavioral equivalence, checked by re-running the output.

### Where it stands

Validation is in two parts. The five obfuscated samples in `C:\Users\noelb\Desktop\test\` are all the *same* three-line program, which is what makes them a weak test of generality on their own; the shape probes in `C:\Users\noelb\Desktop\test\probe\` cover what they hid — a numeric `for`, a `while`, a generic `for ... in`, two functions, nested tables, method calls, and a script that **never prints at all**. Those probes exist because the sample set concealed a real limitation: everything used to be anchored on `print`.

The oracle for the samples is:

```lua
local table = { string = "hi", bool = true }
print(table.string)
if table.bool == true then print("bool is true") else print("bool is not true") end
```

| sample | reconstruction |
|---|---|
| `plain.lua`, `prom.weak`, `prom.med`, `moonveil-cff` | the whole program back: `local t0 = {string = "hi", bool = true}` / `print(t0.string)` / `if t0.bool == true then print("bool is true") else print("bool is not true") end` — verified 1:1, and the `else` came from a forced re-execution rather than a guess |
| `moonveil-vm` | the two prints, verified 1:1; its interpreter never materializes the table in a Luau frame, so no table is claimed and no branch is probed |
| `prom.strong` | **does not execute at all** in this environment (see 1) |

Probe results, each verified by re-execution:

| shape | reconstruction |
|---|---|
| two functions that print | both `function` bodies with their parameters, plus the two calls |
| nested tables | every table and the nested field reads, as written |
| numeric `for` | folded back into a loop, with its variable, body and observed bounds |
| accumulator across a loop | the carried value as a real local (`n0 = n0 + (i0 * 10)`), not an ever-growing expression |
| calls with computed arguments | `table.insert(t1, t0.name .. ":" .. i0)`, `table.concat(t1, ",")` |
| never prints (writes a global) | the tables and `_G.RESULT = t1`; the field holding a closure is reported unexpressed |
| generic `for ... in` | **not** folded: the iterations are emitted unrolled and the report says so |
| method calls / metatables | partial: `self` and the metatable chain are not modeled, so it falls back to the narrower pass |

Measured against three real-world obfuscated scripts in the same folder (2026-08-19) — this is what compatibility actually hinges on, and each failed differently:

| script | what happened |
|---|---|
| `luaobf.lua` (16 KB, WeAreDevs) | **runs and prints**, so the whole pipeline applies, but its printing call passes a *vararg spread* (`CALL B=0`): the register-slice pass refuses it outright and the other two get the argument list wrong. Its payload frame is also 117k events of decoder, which the general pass tries to reconstruct wholesale and hits a nil hole at every value it does not model. |
| `discord.lua` (256 KB) | aborts at `attempt to call a nil value` (a host API the stubs do not provide), prints nothing, and fills the 1,000,000-event budget. The general pass reconstructed the loader and asked for **34,759 locals** — past Luau's 200-per-function limit, so the emitted Lua could not even load. |
| `Oishihub.lua` (459 KB) | fills the event budget with no observable effect recorded at all, so there is nothing to anchor on. |

The pattern: on a real script the blocker is almost never the reconstruction algebra, it is (a) the script not running to completion in this sandbox, (b) its behaviour not being stdout so the verification gate is vacuous, and (c) scale.

### Remaining, ordered by leverage

1. **`prom.strong` never runs.** It aborts with `attempt to call a nil value` having printed nothing, so there is no observed behaviour to reconstruct. Established by measurement, **not** a LURE defect: it fails identically with `LURE_NO_TRACE=1` (dispatch hook off, nothing recorded), at `LURE_OPT_LEVEL=0/1/2`, with and without `--roblox`, and in an environment that provides every global it reads (`getfenv`, `setfenv`, `newproxy`, `unpack`, `select`, `getmetatable`, `setmetatable`, `rawset` — all verified present, `getfenv()` returns `_G` with a live `print`). The failing chain is in frame 2191: `W = upval2[339]` (a table), `L = S[22346566974792]` decodes to the 4-byte binary string `8b 4c 9c 09`, `b = W[L]` → nil, `R = b`, then `CALL R("hi")`. So a key its own pool produced is absent from its own table — some entries of that pool decode plausibly ("string", "hi", "bool is true" all appear correctly) and others do not. Most consistent explanation: an integrity/anti-tamper layer in the strong preset that does not pass here. Note the tension with the project rule: making it run is either (a) generic — a sandbox indistinguishable from a real Roblox host, i.e. `rbx_emulator`-scale work — or (b) obfuscator-specific, which is out of bounds. Do (a) or leave it reported.
2. **Loop *shapes* are not distinguished.** Every back-edge loop is emitted as `while <cond> do`, because that is what the trace proves: control returned to a pc it had been past, under a condition that held. A source-level `repeat ... until` and a `for ... in` therefore both come out as `while`, which is behaviourally right and structurally approximate. Folding a generic `for` properly means recovering the iterator triple from `FORGPREP`/`FORGLOOP` and emitting `for k, v in <iter> do`; its loop variables would then be real variables and its body would fold the way a numeric for's does.
3. **`self` and metatables are not modeled.** A method call renders as `obj:name(args)` when a `NAMECALL` set it up, but `setmetatable`'s effect on later field lookups is not tracked, and a field whose value is a closure is reported unexpressed — the closure's body is only recovered at its first *call*, and nothing links the two (`NEWCLOSURE` would have to carry the child proto's id, which `instrumentation.cpp` can now assign). This is what keeps an OO-style script (`Account.new` / `a:deposit`) on the narrower pass.
4. **Upvalues have no names.** Reading one yields an unknown value and writing one is reported unexpressed. Recovering them means tracking `CAPTURE` at closure creation and naming the captured local in the enclosing frame.
5. **The structural fallback has no verification gate.** `structural.cpp` writes whatever it rendered, and `render_text` names a register by *any* locvar bound to it anywhere in the function, so its output contains lines like `total = "name"` that read as wrong code. Everything above it is gated by re-execution; this one is not. Either gate it or mark its output as unverified in the file itself.
6. **The gate only compares stdout.** For a script whose behaviour is not output (the `_G.RESULT` probe), any candidate that prints nothing "reproduces" the empty stdout. The gate should compare an *effect signature* — the ordered outgoing calls to host functions and writes to globals — which the trace already records.
7. **MoonVeil VM devirtualization (hardest).** `moonveil-vm.lua` interprets its own bytecode, so recovering more than the observed prints requires lifting that bytecode's semantics out of the trace. Expect partial, executed-path results.
8. **Probe cost is linear in candidates.** Each probe is a full re-run (~0.3 s for `prom.weak`, ~5 s for `prom.med`), capped at 32. The obvious win is checkpointing before the branch instead of replaying from the start.

Done and not to be undone: `optimizationLevel = 0`, the fixed RNG seed, the 1,000,000 event default, `snapshot_constant` for constant operands, the per-opcode table-key selection, `(proto_id, pc)` CFG keys, the post-increment `FORNLOOP` test, dead-binding elimination, and loop-carried binding. Two earlier roadmap items are obsolete: making `decompile_payload` loop-aware (the general pass supersedes it) and a dedicated decoder-folding pass (dead-binding elimination does it).


claude --resume 0e0cdbff-5399-406a-8002-5afffc0a0d6e
// vm/instrumentation.h
// C linkage interface between the patched Luau VM (third_party/luau) and the
// LURE instrumentation layer. Included by lvmexecute.cpp via the patch
// patches/luau/0001-instrument-vm-dispatch.patch. Uses opaque types so it can
// be included from the VM without pulling LURE headers.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

struct lua_State;

typedef unsigned int lure_Instruction;

// TRUE iff tracing is enabled for the current run.
int lure_tracing_active(void);

// Called by the VM right before dispatching the instruction at pc.
void lure_trace_dispatch(struct lua_State* L, const lure_Instruction* pc);

void lure_trace_set_enabled(int enabled);
void lure_trace_set_max_events(unsigned max_events);
// Registers a whitelisted native (stdlib) by C function pointer.
void lure_trace_register_native(const char* name, const void* fn);
// Clears all per-run state (buffer + whitelist).
void lure_trace_reset(void);

// Called by the host right after a native function wrote to the observable
// output stream (print sink). Marks the most recent recorded call event as
// having produced output, so call sites are detected behaviorally rather than
// by callee name.
void lure_trace_mark_output_written(void);

// ---------------------------------------------------------------------------
// One-shot branch inversion (path probing).
//
// Arms the (hit_index+1)-th dispatch of the instruction at code offset
// pc_index inside the call frame whose serial is frame_id to execute with its
// condition inverted, so the *other* declared side of an observed branch can be
// executed and recorded. Nothing else about the run changes: the inversion is
// applied to the single instruction word right before it executes and undone
// immediately after, so every other dispatch of the same pc behaves normally.
//
// The inversion is purely opcode-level and obfuscator-agnostic: the conditional
// jump family comes in complementary pairs sharing one target
// (JUMPIF/JUMPIFNOT, JUMPIFEQ/JUMPIFNOTEQ, JUMPIFLE/JUMPIFNOTLE,
// JUMPIFLT/JUMPIFNOTLT) and the JUMPXEQK* family carries a NOT bit in its aux
// word. Unconditional jumps and loop opcodes have no complement and are
// refused.
//
// Returns 1 when an inversion was armed, 0 when the request is not a flippable
// conditional (nothing is armed and the run is unaffected). Only one flip can
// be armed at a time; it is cleared by lure_trace_reset.
int lure_trace_arm_branch_flip(unsigned frame_id, unsigned pc_index, unsigned hit_index);

// 1 iff the armed inversion actually reached its target and fired. A probe that
// did not fire proves nothing and its trace must be discarded.
int lure_trace_branch_flip_fired(void);

#ifdef __cplusplus
}
#endif
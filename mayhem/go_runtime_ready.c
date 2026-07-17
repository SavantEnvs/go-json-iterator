// go-json-iterator/mayhem/go_runtime_ready.c — libFuzzer init-ordering shim for the Go c-archive.
//
// Why this exists (QA #1123): go114-fuzz-build links the harness as -buildmode=c-archive and
// exports only LLVMFuzzerTestOneInput. In c-archive mode the Go runtime is started ASYNCHRONOUSLY
// on its own thread by a load-time constructor (_rt0_amd64_lib -> _rt0_amd64_lib_go). Go's
// runtime/libfuzzer.go init() registers the Go coverage counters with libFuzzer from THAT thread
// (__sanitizer_cov_8bit_counters_init / __sanitizer_cov_pcs_init), while libFuzzer's main thread
// concurrently builds the Fuzzer and calls TracePC::ClearInlineCounters(). When the two overlap,
// the main thread sees a module whose region table is not yet allocated and SEGVs at address 0x10
// inside libFuzzer itself, before any input is processed (~0.1% of starts under parallel load);
// more often the run merely starts before the counters are registered (no "Loaded 1 modules").
//
// libFuzzer calls LLVMFuzzerInitialize first thing in FuzzerDriver, before it touches any
// coverage module. Blocking here until the Go runtime has finished its runtime init tasks (which
// include the counter registration) makes the ordering deterministic. This is exactly the
// wait/release pair the cgo export wrapper of LLVMFuzzerTestOneInput performs on every call from
// C (cmd/cgo out.go); we only do it once, earlier. No input is executed, no target code runs, and
// no signal or crash is intercepted.
#include <stdint.h>

// Go runtime/cgo (gcc_libinit.c / gcc_context.c), exported by every cgo-enabled Go c-archive.
// _cgo_wait_runtime_init_done blocks until runtime.main has run the runtime init tasks and
// signalled runtime_init_done; it returns a traceback context (nonzero only if the program
// registered one via runtime.SetCgoTraceback), which the cgo export wrappers hand back to
// _cgo_release_context. We do the same.
extern uintptr_t _cgo_wait_runtime_init_done(void);
extern void _cgo_release_context(uintptr_t ctxt);

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  _cgo_release_context(_cgo_wait_runtime_init_done());
  return 0;
}

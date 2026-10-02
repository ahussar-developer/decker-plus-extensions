# Whole-Program Debloating (WPD)

DeckerPlus restricts which code pages are executable as a program runs. At each callsite, only the functions statically reachable from that call are mapped `PROT_READ|PROT_EXEC` — everything else stays `PROT_NONE`. An attacker exploiting a memory bug sees a much smaller ROP/JOP gadget surface as a result.

---

## Repository Layout

```
wpd-artifact/
├── pass/
│   ├── WholeProgramDebloat.cpp     # LLVM instrumentation pass
│   └── CMakeLists.txt
├── runtime/
│   ├── debloat_rt.cpp              # Runtime enforcement library
│   ├── debloat_rt.h
│   ├── libdebloatrt.version        # Exported symbol list
│   ├── CMakeLists.txt
│   └── ics/
│       └── ics.cpp                 # Indirect call sinking (ICS) cache
├── linker/
│   ├── linker.py                   # Generates per-program linker script
│   └── example-wpd-linker-script.lds  # Example output (lbm benchmark)
├── CMakeLists.txt
└── compile.sh                      # Example build pipeline
```

---

## Build

Requires LLVM (tested on LLVM 11):

```bash
mkdir build && cd build
cmake .. -DLLVM_DIR=/path/to/llvm/lib/cmake/llvm
make
```

Produces `pass/WholeProgramDebloat.so` and `runtime/debloat_rt.so`.

---

## Pipeline

1. **Compile** with the WPD pass — produces an instrumented binary plus static analysis output files (function IDs, reachability maps, disjoint sets).
2. **Generate** a linker script from those files using `linker.py`.
3. **Re-link** with the custom linker script and `debloat_rt.so`.

At runtime, `debloat_rt` reads the analysis files, finds the text segment, and uses `mprotect` to enforce permissions as execution proceeds.

---

## System Variants

Three configurations, each building on the last.

### Baseline

The LLVM pass does whole-program call graph analysis to compute, for each program point, the minimal set of functions that could execute. Instrumentation calls into `debloat_rt` are inserted at each relevant callsite and loop boundary; the runtime enforces those sets at page granularity. Functions that share a page get separated into their own page-aligned groups by the linker script, so enabling one doesn't inadvertently expose another.

**70.3% average gadget reduction** on SPEC CPU 2017, **88.5%** on GNU coreutils, **89.0%** on applications (nginx, Redis, lighttpd, xpdf — benchmarks I added). Average runtime overhead of 6.5% on SPEC.

### Function Cloning

Any function reachable from inside a loop is *encompassed* — its entire transitive reachable set gets lumped into the loop deck. That means a non-loop call to that function unnecessarily activates the whole loop deck.

Cloning fixes this: duplicate the encompassed function and its full reachable subgraph, point the non-loop callers at the clone. The clone gets a fine-grained deck; the original and loop deck are untouched. Internal call edges within the cloned subgraph are also updated to call other clones.

**75.5%** on SPEC, **89.6%** on coreutils, **94.2%** on applications.

### Inlining

Run LLVM's `InlinerAdvisor` before the DeckerPlus pass. Inlining removes call boundaries, which means fewer runtime deck activations — the binary can actually get larger while gadget reduction improves because the gain comes from shrinking available-page snapshots, not removing code. Thresholds from 100–1000 are swept per benchmark.

**77.6%** on SPEC, **94.7%** on coreutils, **97.8%** on applications.

---

## Component Descriptions

### `pass/WholeProgramDebloat.cpp` — LLVM Module Pass

Whole-program call graph analysis + instrumentation in a single module pass.

**Analysis.** Every application function gets a stable integer ID. The pass builds the direct call graph, then computes *static reachability* (full transitive closure per function via BFS). Functions are classified as *encompassed* (called inside a loop or reachable from one) or *toplevel* (everything else).

It also computes *disjoint sets* — a partition of all functions into groups that always appear together at runtime. Sets are split incrementally as instrumentation runs so the final partition is fully disjoint. Each group gets its own page-aligned `.text` section via the linker script.

**Instrumentation.** Four deck types, inserted at each callsite or loop:

- *Single*: toplevel callee — `debrt_protect_single` / `_end`, maps only that function's pages.
- *Reachable*: encompassed callee — `debrt_protect_reachable` / `_end`, maps the callee and its full reachable set.
- *Loop*: `debrt_protect_loop` at the preheader, `debrt_protect_loop_end` at every exit. Maps everything reachable from inside the loop.
- *Indirect*: function pointer call — `debrt_protect_indirect` / `_end` outside loops, ICS cache inside.

`main` is bookended with `debrt_init` / `debrt_destroy`. Analysis results are dumped to text files for the runtime and linker script generator.

---

### `runtime/debloat_rt.cpp` — Runtime Enforcement Library

Linked into the instrumented binary as a shared library. `debrt_init` reads `/proc/<pid>/maps` to find the text segment and parses the pass output to build a function-ID-to-pages map.

Each `debrt_protect_*` call computes the union of pages for the relevant set and calls `mprotect(PROT_READ|PROT_EXEC)`; everything else stays `PROT_NONE`. Page counts are reference-counted so nested decks work correctly. `_end` decrements counts and revokes pages that hit zero.

---

### `runtime/ics/ics.cpp` — Indirect Call Sinking Cache

Indirect calls inside loops can't be hoisted because the target isn't known until runtime. Calling `debrt_protect_indirect` on every iteration would mean a syscall every iteration.

The ICS cache is a flat 8MB hash table keyed by function pointer address. Hit → return immediately. Miss → call `debrt_protect_indirect`, cache the address. On loop exit, `ics_wrapper_debrt_protect_loop_end` revokes permissions and clears the table with `memset`. Cuts overhead by up to 80% vs. calling into the runtime on every iteration.

---

### `linker/linker.py` — Linker Script Generator

Takes the disjoint sets and function ID mapping from the pass and produces a GNU linker script with each function group placed at `ALIGN(0x1000)` in `.text`. This ensures each group is independently `mprotect`-able without exposing gadgets in adjacent functions. Fed to `ld` via `-T`; the linker itself is unmodified.

### `linker/example-wpd-linker-script.lds`

Generated linker script for the `lbm` SPEC CPU 2017 benchmark.

---

## My Contributions

This project was developed at Georgia Tech. The baseline system — pass, runtime, linker — was built by the team; I contributed the "Plus" part of DeckerPlus: the function cloning and inlining compiler extensions, and the evaluation on new application benchmarks beyond SPEC and coreutils.

**Function Cloning.** I designed and implemented this from scratch. The main work was identifying encompassed functions also called from non-loop sites, cloning each with its full transitive reachable subgraph, and wiring everything up correctly — non-loop callsites redirect to the clone, internal calls within the cloned subgraph call other clones. The data structures (reachability maps, adjacency lists, disjoint sets) all had to be extended to track clones as first-class entities. The edge case that made this hard: the same function can appear in multiple reachable subgraphs, each needing its own independent clone.

**Inlining Integration.** I integrated LLVM's inliner as a pre-pass and figured out how to evaluate it. The key result I worked out: inlining improves gadget reduction not because it removes gadgets — the binary gets larger — but because it shrinks the set of pages in runtime available-page snapshots. I swept cost thresholds (100–1000) per benchmark to find the setting that maximized gadget reduction rather than raw compile-time performance.

**Benchmark Evaluation.** I built out and ran all evaluation for the application benchmarks added beyond SPEC CPU 2017: nginx, Redis, lighttpd, and the xpdf suite (pdftops, pdfinfo, pdffonts, pdfdetach, pdfimages). This meant setting up builds with the WPD pass and custom linker scripts, writing test harnesses, and collecting gadget count and runtime overhead numbers. The point of these benchmarks was to get coverage on server and document-processing workloads rather than just CPU-bound compute.

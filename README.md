# Whole-Program Debloating (WPD)

DeckerPlus restricts which code pages are executable as a program runs. At each callsite, only the functions statically reachable from that call are mapped `PROT_READ|PROT_EXEC` and everything else stays `PROT_NONE`. An attacker exploiting a memory bug sees a much smaller ROP/JOP gadget surface as a result.

---

## My Contributions

I contributed across the compiler pass and build infrastructure throughout the project. My primary design contributions were the function cloning and inlining extensions built on top of the baseline pass. Beyond those, I made fixes and improvements to the existing pass code, adapted the linker script generator to support new benchmark targets, and ran all evaluation on the new application benchmarks.

**Function Cloning.** I designed and implemented a function cloning pre-pass in LLVM to improve gadget reduction at callsites that sit outside loops but call into encompassed functions. The core work involved whole-program analysis to identify these callsites, cloning each encompassed function and its full transitive reachable subgraph using LLVM's `CloneFunction` API, and updating all call targets and the module's function list to redirect non-loop callsites to their clones at the IR level. All internal call edges within a cloned subgraph are rewritten to reference other clones, preserving isolation. The main challenge was extending the pass's core data structures (static reachability maps, adjacency lists, disjoint sets) to treat cloned functions as first-class entities, since the same function can appear in multiple independent reachable subgraphs each requiring its own clone.

**Inlining Integration.** I integrated LLVM's `InlinerAdvisor` as a preprocessing step before the DeckerPlus instrumentation pass, and worked out how to evaluate it correctly. Because inlining runs on pre-instrumentation IR, the instrumentation pass sees a different call graph with fewer callsites, smaller reachable sets, and smaller available-page snapshots at runtime. The key insight is that inlining improves gadget reduction not by removing code from the binary (it often grows) but by reducing the number of pages that appear in runtime permission sets. I swept cost thresholds from 100 to 1000 per benchmark to find the configuration that maximized gadget reduction rather than compilation speed, which required careful evaluation methodology to separate the two effects.

**Linker Script and Build Infrastructure.** Extending coverage to new application benchmarks required adapting `linker.py` and the build pipeline for each target. The linker script generator reads disjoint set and function ID output from the pass and produces a custom GNU linker script placing each function group at its own `ALIGN(0x1000)` boundary. Getting this working correctly for server and document-processing applications meant handling per-benchmark build quirks and verifying that page-aligned placement held across different binary layouts.

**Benchmark Evaluation.** I ran all evaluation for the application benchmarks added beyond SPEC CPU 2017 and GNU coreutils: nginx, Redis, lighttpd, and the xpdf suite (pdftops, pdfinfo, pdffonts, pdfdetach, pdfimages). This included writing test harnesses and collecting gadget count and runtime overhead measurements across all three system variants. These benchmarks were chosen to evaluate the system on server and document-processing workloads, which are a better model of real-world attack targets than CPU-bound compute benchmarks.

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

1. **Compile** with the WPD pass, which produces an instrumented binary plus static analysis output files (function IDs, reachability maps, disjoint sets).
2. **Generate** a linker script from those files using `linker.py`.
3. **Re-link** with the custom linker script and `debloat_rt.so`.

At runtime, `debloat_rt` reads the analysis files, finds the text segment, and uses `mprotect` to enforce permissions as execution proceeds.

---

## System Variants

Three configurations, each building on the last.

### Baseline

The LLVM pass does whole-program call graph analysis to compute, for each program point, the minimal set of functions that could execute. Instrumentation calls into `debloat_rt` are inserted at each relevant callsite and loop boundary; the runtime enforces those sets at page granularity. Functions that share a page get separated into their own page-aligned groups by the linker script, so enabling one doesn't inadvertently expose another.

**70.3% average gadget reduction** on SPEC CPU 2017, **88.5%** on GNU coreutils, **89.0%** on applications (nginx, Redis, lighttpd, xpdf, benchmarks I added). Average runtime overhead of 6.5% on SPEC.

### Function Cloning

Any function reachable from inside a loop is *encompassed* and its entire transitive reachable set gets lumped into the loop deck. That means a non-loop call to that function unnecessarily activates the whole loop deck.

Cloning fixes this by duplicating the encompassed function and its full reachable subgraph and pointing the non-loop callers at the clone. The clone gets a fine-grained deck; the original and loop deck are untouched. Internal call edges within the cloned subgraph are also updated to call other clones.

**75.5%** on SPEC, **89.6%** on coreutils, **94.2%** on applications.

### Inlining

Run LLVM's `InlinerAdvisor` before the DeckerPlus pass. Inlining removes call boundaries, which means fewer runtime deck activations. The binary can actually get larger while gadget reduction improves because the gain comes from shrinking available-page snapshots, not removing code. Thresholds from 100 to 1000 are swept per benchmark.

**77.6%** on SPEC, **94.7%** on coreutils, **97.8%** on applications.

---

## Component Descriptions

### `pass/WholeProgramDebloat.cpp`

LLVM module pass. Whole-program call graph analysis and IR instrumentation.

**Analysis.** Every application function gets a stable integer ID. The pass builds the direct call graph by walking all call instructions in the module IR, then computes static reachability (full transitive closure per function via BFS). Functions are classified as *encompassed* (called inside a loop or transitively reachable from one) or *toplevel* (everything else). This classification drives all instrumentation decisions downstream.

The pass also computes disjoint sets, a partition of all functions into groups that always appear together at runtime. Sets are split incrementally as new callsite function sets are registered, ensuring the final partition is fully disjoint. Each group gets its own page-aligned `.text` section in the generated linker script.

**Instrumentation.** Using `IRBuilder`, the pass inserts one of four deck types at each callsite or loop. Single decks cover toplevel callees and map only that function's pages via `debrt_protect_single`. Reachable decks cover encompassed callees and map the full reachable set via `debrt_protect_reachable`. Loop decks are inserted at the preheader and every exit block (via `LoopInfo`) and map everything reachable from inside the loop. Indirect decks handle function pointer calls via `debrt_protect_indirect` outside loops and the ICS cache inside.

`main` is bookended with `debrt_init` and `debrt_destroy`. Analysis results are dumped to text files consumed by the runtime and linker script generator.

---

### `runtime/debloat_rt.cpp`

Runtime enforcement library, linked into the instrumented binary as a shared library. `debrt_init` reads `/proc/<pid>/maps` to locate the text segment and parses the pass output to build a function-ID-to-pages map.

Each `debrt_protect_*` call computes the union of pages for the relevant set and calls `mprotect(PROT_READ|PROT_EXEC)`; everything else stays `PROT_NONE`. Page counts are reference-counted so nested and overlapping decks are handled correctly. The `_end` variants decrement counts and revoke pages that hit zero.

---

### `runtime/ics/ics.cpp`

Indirect call sinking cache. Indirect calls inside loops can't be hoisted to the preheader because the target address isn't known until runtime, and calling `debrt_protect_indirect` on every iteration would mean a syscall per iteration.

The ICS cache is a flat 8MB hash table keyed by function pointer address. A hit returns immediately with no syscall. A miss calls `debrt_protect_indirect` and caches the address. On loop exit, `ics_wrapper_debrt_protect_loop_end` revokes permissions and clears the table with `memset`. Cuts overhead by up to 80% vs. calling into the runtime on every iteration.

---

### `linker/linker.py`

Takes the disjoint sets and function ID mapping from the pass and produces a GNU linker script with each function group placed at `ALIGN(0x1000)` in `.text`. This ensures each group is independently `mprotect`-able without exposing gadgets in adjacent functions. Fed to `ld` via `-T`; the linker itself is unmodified.

### `linker/example-wpd-linker-script.lds`

Generated linker script for the `lbm` SPEC CPU 2017 benchmark.

#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Value.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include <set>
#include <stack>
#include <queue>
#include <string>
#include <map>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <sstream>



#define BOTTOM_UP_DISJOINT_SET // comment out to use sharjeel's alg.

using namespace llvm;
using namespace std;

bool ENABLE_INSTRUMENTATION_SINKING = false; // can set via command line option below
cl::opt<bool> EnableInstrumentationSinking(
    "enable-instrumentation-sinking", cl::init(false), cl::Hidden,
    cl::desc("Attempts to sink instrumentation into loops."));
bool ENABLE_INDIRECT_CALL_SINKING = false; // can set via command line option below
cl::opt<bool> EnableIndirectCallSinking(
    "enable-indirect-call-sinking", cl::init(false), cl::Hidden,
    cl::desc("Attempts to sink indirect call instrumentation into loops."));
bool ENABLE_BASIC_INDIRECT_CALL_STATIC_ANALYSIS = false; // can set via command line option below
cl::opt<bool> EnableBasicIndirectCallStaticAnalysis(
    "enable-basic-indirect-call-static-analysis", cl::init(false), cl::Hidden,
    cl::desc("Attempts to apply basic static analysis to indirect calls for mapping them at loop headers."));


typedef struct{
    long id;
    set<Function *> *s;
}disjoint_set_t;


namespace {
    struct WholeProgramDebloat : public ModulePass {
        static char ID;

        WholeProgramDebloat() : ModulePass(ID) {}

        Function *debrt_init_func;
        Function *debrt_destroy_func;
        Function *debrt_protect_single_func;
        Function *debrt_protect_single_end_func;
        Function *debrt_protect_reachable_func;
        Function *debrt_protect_reachable_end_func;
        Function *debrt_protect_loop_func;
        //Function *debrt_protect_loop_end_func;
        Function *debrt_protect_indirect_func;
        Function *debrt_protect_indirect_end_func;
        Function *debrt_protect_sink_func;
        Function *debrt_protect_sink_end_func;
        Function *ics_map_indirect_call_func;
        Function *ics_wrapper_debrt_protect_loop_end_func;
        map<Function *, int> func_to_id;
        map<int, Function *> func_id_to_func;
        map<int, string> func_id_to_name;
        map<string, int> func_name_to_id;
        Type *int32Ty;
        Type *int64Ty;
        map<Function *, set<Function *> > adj_list;
        map<Function *, set<Function *> > rev_adj_list;
        map<Function *, set<Function *> > adj_list_fps;
        set<Function *> all_funcs;
        // "encompassed funcs" are functions that we aren't
        // allowed to instrument _inside of_, because they are either
        // called inside of a loop, or they are called by a function
        // that's called inside of a loop; they're encompassed by a loop.
        set<Function *> encompassed_funcs;
        set<Function *> toplevel_funcs;
        map<Function *, set<Function *> > static_reachability;
        map<int, set<Function *> > loop_static_reachability;
        vector<set<Function *>> instrumented_sets;
#ifdef BOTTOM_UP_DISJOINT_SET
        map<long, set<Function *> *> disjoint_sets;
#else
        map<size_t, set<Function *>> disjoint_sets;
#endif
        map<Function *, disjoint_set_t> func_to_disjoint_set;
        map<int, int> loop_id_to_func_id; // for debugging
        set<string> func_name_has_addr_taken;
        set<Function *> func_has_addr_taken;
        map<Function *, set<Function *> > func_to_fps;
        map<Function *, set<Function *> > func_to_parents;
        map<int, set<int> > sinks; // sink id to its function IDs
        map<int, int> sink_id_to_func_id; // the function ID that holds the sink, for debugging
        map<string, long> readelf_func_name_to_size;
        int loop_id_counter;
        int sink_id_counter;
        long long text_size;
        set<string> ics_func_names;
        set<string> libc_nonstatic_func_names;


        void getAnalysisUsage(AnalysisUsage &AU) const
        {
            AU.addRequired<LoopInfoWrapperPass>();
        }

        bool runOnModule(Module &M) override;
        bool runOnModule_real(Module &M);
        bool doInitialization(Module &) override;
        bool doFinalization(Module &) override;

        void wpd_init(Module &M);
        void build_basic_structs(Module &M);
        void extend_adj_list(void);
        void build_static_reachability(void);
        //void extend_static_reachability(void);
        void build_func_to_parents(void);
        void extend_encompassed_funcs(void);
        void build_toplevel_funcs(void);
        void create_disjoint_sets(void);
#ifdef BOTTOM_UP_DISJOINT_SET
        void finalize_disjoint_sets(void);
#endif

        bool instrument_main_start(Module &M);
        bool instrument_main_end(Module &M);
        void instrument_debrt_destroy(Instruction *I);
        void instrument(void);
        void instrument_loop(int func_id, Loop *loop);
        void instrument_loop_sink(int toplevel_func_id, Loop *toplevel_loop);

        int recurse_sink(Function *toplevel_func,
                         set<Function *> &toplevel_bridge_list,
                         set<Function *> &visited_funcs,
                         pair<Function *, CallBase *> parent_func);
        void instrument_after_invoke(InvokeInst *II,
                                     vector<Value *> &ArgsV,
                                     Function *debrt_func);
        void instrument_toplevel_func(Function *f, LoopInfo *LI);
        void instrument_indirect_and_external(Function *f, LoopInfo *LI);
        void instrument_external_call(Instruction &I,
                                      bool call_is_outside_loop);
        bool instrument_external_with_callback(Instruction &I,
                                               bool call_is_outside_loop);


        void get_callees(Loop *loop,
                         vector<pair<Function *, CallBase *> > &callees);
        void get_callees(pair<Function *, CallBase *> parent_func,
                         vector<pair<Function *, CallBase *> > &callees);
        bool sinking_condition_satisfied(vector<pair<Function *, CallBase *> > &callees,
                                                set<Function *> &visited_funcs);
        void instrument_sink_point(pair<Function *, CallBase *> parent_func,
                                   set<Function *> *toplevel_bridge_list);
        int iterative_sink(set<Function *> &toplevel_bridge_list,
                           set<Function *> &visited_funcs,
                           pair<Function *, CallBase *> parent_func);
        void get_callees_aux(vector<pair<Function *, CallBase *> > &callees,
                                     Instruction &I);
        void read_readelf_sections(void);
        void read_readelf(void);
        int get_set_byte_size(set<Function *> &functions);
        void get_address_taken_uses(Function &F, vector<User *> &offenders);
        void build_func_to_fps(Module &M);
#ifdef BOTTOM_UP_DISJOINT_SET
        void update_disjoint_sets(set<Function *> &new_set);
#endif


        string get_demangled_name(const Function &F);
        void dump_static_reachability(void);
        void dump_loop_static_reachability(void);
        void dump_encompassed_funcs(void);
        void dump_loop_id_to_func_id(void);
        void dump_sink_id_to_func_id(void);
        void dump_sinks(void);
        void dump_func_name_to_id(void);
        void dump_func_ptrs(void);
        void dump_disjoint_sets(void);
#ifdef BOTTOM_UP_DISJOINT_SET
        void print_disjoint_sets(void);
#endif
        void dump_stats(void);
    };
}

struct wpd_stats{
    int num_toplevel_loops;
    int num_instrumented_basic_loops;
    int num_instrumented_sunk_loops;
    int num_instrumented_sunk_multilevel_loops;
    int sink_fail_no_calles;
    int sink_fail_due_to_visited;
    int sink_fail_thresh_check;
}stats;


void WholeProgramDebloat::get_callees_aux(vector<pair<Function *, CallBase *> > &callees,
                                                  Instruction &I)
{
    pair<Function *, CallBase *> fcb;
    CallBase   *CB = dyn_cast<CallBase>(&I);
    CallInst   *CI = dyn_cast<CallInst>(&I);
    InvokeInst *II = dyn_cast<InvokeInst>(&I);
    if(CB){
        Function *callee = CB->getCalledFunction();
        if(func_to_id.count(callee) > 0){
            //callee_blocks_set.insert(&B); // FIXME dont want duplicates
            //callee_blocks.push_back(&B);
            //block_to_callee[&B] = callee;
            callees.push_back(make_pair(callee, CB));
        }
    }
}
void WholeProgramDebloat::get_callees(pair<Function *, CallBase *> parent_func,
                                      vector<pair<Function *, CallBase *> > &callees)
{
    for(auto &B : *(parent_func.first)){
        for(auto &I : B){
            get_callees_aux(callees, I);
        }
    }
}
void WholeProgramDebloat::get_callees(Loop *loop,
                                      vector<pair<Function *, CallBase *> > &callees)
{
    for(auto B : loop->getBlocks()){
        for(auto &I : (*B)){
            get_callees_aux(callees, I);
        }
    }
}

int WholeProgramDebloat::get_set_byte_size(set<Function *> &functions)
{
    int sum = 0;
    for(auto f : functions){
        sum += readelf_func_name_to_size[f->getName().str()];
    }
    return sum;
}


// Based on llvm 11 source tree's hasAddressTaken.
// For some function F, adds to offenders any "users" that take the address
// of F.
void WholeProgramDebloat::get_address_taken_uses(Function &F, vector<User *> &offenders)
{
  for (const Use &U : F.uses()) {
    User *FU = U.getUser();
    if (isa<BlockAddress>(FU))
      continue;

    const auto *Call = dyn_cast<CallBase>(FU);
    if (!Call) {
      offenders.push_back(FU);
    }
    if (!Call->isCallee(&U)) {
      offenders.push_back(FU);
    }
  }
}


bool WholeProgramDebloat::sinking_condition_satisfied(vector<pair<Function *, CallBase *> > &callees,
                                                      set<Function *> &visited_funcs)
{
    // Debug/dev attempt
    //#define UNION_THRESH 10
    //#define INTERSECT_THRESH 1
    // Thresh settings 1
    static const int UNION_THRESH = text_size * .1f;
    static const int INTERSECT_THRESH = text_size * .05f;
    // Thresh settings 2
    //static const int UNION_THRESH = text_size * .05f;
    //static const int INTERSECT_THRESH = text_size * .05f;
    // Thresh settings 3
    //static const int UNION_THRESH = text_size * .01f;
    //static const int INTERSECT_THRESH = text_size * 1.0f;

    int i;
    vector<set<Function *> > Ss;

    if(callees.size() == 0){
        stats.sink_fail_no_calles++;
        return false;
    }

    // Identify S sets
    for(auto callee : callees){
        // XXX Early termination for threshold calculation:
        // This is a conservative approach for now. Any repeat of a visited
        // func means the threshold condition is not satisfied.
        if(visited_funcs.find(callee.first) != visited_funcs.end()){
            stats.sink_fail_due_to_visited++;
            return false;
        }
        Ss.push_back(static_reachability[callee.first]);
    }

    // Find intersection across all S sets
    set<Function *> set_intersect_fin;
    set<Function *> tmp;
    set_intersect_fin.insert(Ss[0].begin(), Ss[0].end());
    for(i = 1; i < Ss.size(); i++){
        tmp.clear();
        tmp.insert(set_intersect_fin.begin(), set_intersect_fin.end());
        set_intersect_fin.clear();
        set_intersection(tmp.begin(),
                         tmp.end(),
                         Ss[i].begin(),
                         Ss[i].end(),
                         inserter(set_intersect_fin, set_intersect_fin.end()));
    }

    // Find union across all S sets
    set<Function *> set_union_fin;
    set_union_fin.insert(Ss[0].begin(), Ss[0].end());
    for(i = 1; i < Ss.size(); i++){
        tmp.clear();
        tmp.insert(set_union_fin.begin(), set_union_fin.end());
        set_union_fin.clear();
        set_union(tmp.begin(),
                  tmp.end(),
                  Ss[i].begin(),
                  Ss[i].end(),
                  inserter(set_union_fin, set_union_fin.end()));
    }

    int union_B     = get_set_byte_size(set_union_fin);
    int intersect_B = get_set_byte_size(set_intersect_fin);

    // FIXME: write a function like get_set_diff_size() which actually gets
    //        the total text size of its functions.  Don't just use the size of
    //        set_diff_fin. That's wrong.  And fix THRESH and THRESH_SMALL. not
    //        simple integers, but probably based on proportions of the total
    //        text size.
    //if(set_union_fin.size() > UNION_THRESH && set_intersect_fin.size() < INTERSECT_THRESH){
    //    errs() << "THRESH success: set_union_size("<<set_union_fin.size()<<") "
    //           << "set_intersect_size("<< set_intersect_fin.size()<<")\n";
    //    return true;
    //}
    //errs() << "THRESH fail: set_union_size("<<set_union_fin.size()<<") "
    //       << "set_intersect_size("<< set_intersect_fin.size()<<")\n";


    errs() << "UNION_THRESH(" << UNION_THRESH << ") "
           << "INTERSECT_THRESH(" << INTERSECT_THRESH << ")\n";
    if(union_B > UNION_THRESH && intersect_B < INTERSECT_THRESH){
        errs() << "THRESH success: "
               << "union_B(" << union_B << ") "
               << "intersect_B(" << intersect_B << ")\n";
        return true;
    }
    errs() << "THRESH fail: set_union_size("<<set_union_fin.size()<<") "
           << "set_intersect_size("<< set_intersect_fin.size()<<")\n";

    stats.sink_fail_thresh_check++;
    return false;
}

void WholeProgramDebloat::instrument_sink_point(pair<Function *, CallBase *> parent_func,
                                                set<Function *> *toplevel_bridge_list)
{
    CallBase *CB = parent_func.second;

    int sink_id = sink_id_counter;
    sink_id_counter++;

    // instrument before callee
    vector<Value *> ArgsV;
    ArgsV.push_back(ConstantInt::get(int32Ty, sink_id, false));
    IRBuilder<> builder(CB);
    builder.CreateCall(debrt_protect_sink_func, ArgsV);

    CallInst   *CI = dyn_cast<CallInst>(CB);
    InvokeInst *II = dyn_cast<InvokeInst>(CB);
    // instrument after callee
    if(CI){
        IRBuilder<> builder_end(CI);
        builder_end.SetInsertPoint(CI->getNextNode());
        builder_end.CreateCall(debrt_protect_sink_end_func, ArgsV);
    }else if(II){
        instrument_after_invoke(II, ArgsV, debrt_protect_sink_end_func);
    }else{
        assert(0);
    }

    // Store the sink ID -> func IDs
    // If this is a toplevel function call, then the sink ID corresponds
    // to the bridge list. Otherwise this is an instrumentation point deeper
    // than the toplevel call, and we need the function itself and its
    // statically reachable set.
    set<Function *> temp;
    if(toplevel_bridge_list){
        // this is a toplevel function call
        for(auto func : *toplevel_bridge_list){
            sinks[sink_id].insert(func_to_id[func]);
            temp.insert(func);
        }
    }else{
        // not a toplevel function call
        sinks[sink_id].insert(func_to_id[parent_func.first]);
        temp.insert(parent_func.first);
        for(auto func : static_reachability[parent_func.first]){
            sinks[sink_id].insert(func_to_id[func]);
            temp.insert(func);
        }
    }
#ifdef BOTTOM_UP_DISJOINT_SET
    update_disjoint_sets(temp);
#else
    instrumented_sets.push_back(temp);
#endif
    sink_id_to_func_id[sink_id] = func_to_id[parent_func.first]; // for debugging
}


int WholeProgramDebloat::iterative_sink(set<Function *> &toplevel_bridge_list,
                                        set<Function *> &visited_funcs,
                                        pair<Function *, CallBase *> toplevel_func)
{

    stack<pair<Function *, CallBase *> > s;

    s.push(toplevel_func);
    while(!s.empty()){
        vector<pair<Function *, CallBase *> > callees;
        pair<Function *, CallBase *> parent_func;

        parent_func = s.top();
        s.pop();

        visited_funcs.insert(parent_func.first);

        get_callees(parent_func, callees);

        if(sinking_condition_satisfied(callees, visited_funcs)){
            // add parent as a bridge
            toplevel_bridge_list.insert(parent_func.first);

            // descend to callees
            for(auto c : callees){
                s.push(c);
            }
        }else{

            // the callees don't satisfy the sink condition, so we need
            // to sink instrumentation to their parent function
            instrument_sink_point(parent_func, NULL);
        }
    }
}




void WholeProgramDebloat::instrument_loop_sink(int toplevel_func_id,
                                               Loop *toplevel_loop)
{
    bool multilevel_sink = false; // for stats

    vector<pair<Function *, CallBase *> > callees;
    set<Function *> visited_funcs;
    set<Function *> toplevel_bridge_list;

    // Grab the callees within this top-level loop
    get_callees(toplevel_loop, callees);

    // Check if the sinking condition is even satisfied within this top-level
    // loop
    if(sinking_condition_satisfied(callees, visited_funcs)){
        // The condition is met, so we'll sink instrumentation into the loop,
        // and possibly into interprocedural points
        for(auto toplevel_callee : callees){
            toplevel_bridge_list.clear();
            visited_funcs.clear();

            // never revisit a toplevel-func
            for(auto toplevel_callee : callees){
                visited_funcs.insert(toplevel_callee.first);
            }

            // for this toplevel-callee, try to sink deeper
            iterative_sink(toplevel_bridge_list, visited_funcs, toplevel_callee);

            // If the sink went deeper, then our bridge list is populated.
            // So we need to instrument the toplevel-callee with the bridges
            if(toplevel_bridge_list.size()){
                instrument_sink_point(toplevel_callee, &toplevel_bridge_list);
                multilevel_sink = true; // for stats
            }
        }
        stats.num_instrumented_sunk_loops++;
        if(multilevel_sink){
            stats.num_instrumented_sunk_multilevel_loops++;
        }
    }else{
        // Top-level callees did not satisfy threshold for sinking, so we
        // just do normal loop instrumentation in this case
        instrument_loop(toplevel_func_id, toplevel_loop);
    }

}


void WholeProgramDebloat::instrument_loop(int func_id, Loop *loop)
{
    //
    // XXX All this code is intentionally crammed in here. 'loop' is, I think,
    // an object address from getLoopInfo() that poofs. So we don't want to
    // rely on its address as a map key anywhere (like we might for a Fuction
    // or BasicBlock object).
    // 

    int loop_id = loop_id_counter;
    bool has_toplevel_indirect_call = false;

    // Find preheader
    BasicBlock *preheader = loop->getLoopPreheader();
    assert(preheader); // must run -loop-simplify for this to be OK.

    // Prime loop_static_reachability with any callees in our loops
    for(auto &B : loop->getBlocks()){
        for(auto &I : (*B)){
            CallBase *cb = dyn_cast<CallBase>(&I);
            if(cb){
                Function *callee = cb->getCalledFunction();
                // Normal callee: just prime this loop's static reachability
                // with it.
                if(func_to_id.count(callee) > 0){
                    loop_static_reachability[loop_id].insert(callee);
                }
                if(ENABLE_BASIC_INDIRECT_CALL_STATIC_ANALYSIS){
                    // Indirect call: We will prime the loop's static reachability
                    // with any function pointers that could have been invoked.
                    // This is based on the adj-list-fps for this function.
                    if(cb->getCalledFunction() == NULL){
                        loop_static_reachability[loop_id].insert(
                          adj_list_fps[func_id_to_func[func_id]].begin(),
                          adj_list_fps[func_id_to_func[func_id]].end());
                    }
                }
                if(ENABLE_INDIRECT_CALL_SINKING){
                    if(cb->getCalledFunction() == NULL){
                        has_toplevel_indirect_call = true;
                    }
                }
            }
        }
    }

    // If there was at least one function call inside the loop, then we
    // will instrument it.
    // Note: If the only call/calls was/were indirect, then we could end up
    // with a loop-id that has no reachable functions. That's ok. The runtime
    // library can handle it.
    if(loop_static_reachability.find(loop_id) != loop_static_reachability.end()
    || has_toplevel_indirect_call){
        stats.num_instrumented_basic_loops++;

        // Extend based on reachability of those callees
        for(auto loop_callee : loop_static_reachability[loop_id]){
            for(auto reachable_func : static_reachability[loop_callee]){
                loop_static_reachability[loop_id].insert(reachable_func);
            }
        }

        // Create arguments for the library function
        // errs() << "Make arguments\n";
        vector<Value *> ArgsV;
        ArgsV.push_back(ConstantInt::get(int32Ty, loop_id, false));

        // instrument the preheader of the loop
        Instruction *TI = preheader->getTerminator();
        assert(TI);
        assert(debrt_protect_loop_func);
        IRBuilder<> builder(TI);
        builder.CreateCall(debrt_protect_loop_func, ArgsV);

        //Set of functions debloated within loop (Sharjeel)
        // cporter update: added check in case 0-element case matters
        if(loop_static_reachability[loop_id].size() > 0){
#ifdef BOTTOM_UP_DISJOINT_SET
            update_disjoint_sets(loop_static_reachability[loop_id]);
#else
            instrumented_sets.push_back(loop_static_reachability[loop_id]);
#endif
        }
        // errs() << "Inserted library function within preheader(" << preheader->getName().str() << "\n";

        // instrument the exit(s) block(s) of the loop
        SmallVector<BasicBlock *, 8> exit_blocks;
        loop->getUniqueExitBlocks(exit_blocks);

        // dont assert. can refer to https://llvm.org/docs/LoopTerminology.html
        // statically infinite loop is possible. we just won't instrument exits in
        // that case
        //assert(exit_blocks.size() > 0);

        for(auto exit_block : exit_blocks){
            Instruction *ebt = exit_block->getTerminator();
            assert(ebt);
            IRBuilder<> builder_exit(ebt);
            //builder_exit.CreateCall(debrt_protect_loop_end_func, ArgsV);
            builder_exit.CreateCall(ics_wrapper_debrt_protect_loop_end_func, ArgsV);
        }

        // Note which function this loop is associated with
        loop_id_to_func_id[loop_id] = func_id;

        // Bump our ID counter
        loop_id_counter++;
    }

}


void WholeProgramDebloat::extend_encompassed_funcs(void)
{
    errs() << "Extending encompassed funcs\n";
    for(auto F : func_has_addr_taken){
        encompassed_funcs.insert(F);
    }
    for(auto F : encompassed_funcs){
        for(auto reachable_func : static_reachability[F]){
            encompassed_funcs.insert(reachable_func);
        }
    }
}


void WholeProgramDebloat::instrument_after_invoke(InvokeInst *II,
                                                  vector<Value *> &ArgsV,
                                                  Function *debrt_func)
{
    if(II->getCalledFunction()){
    }else{
    }
    // sanity check num-successors. should have
    // two: normal dest and unwind dest
    if(II->getNumSuccessors() != 2){
        errs()
        << "ERROR: unexpected number of successors. "
        << "expected 2, but got " << II->getNumSuccessors() << "\n";
        assert(0);
    }

    SplitEdge(II->getParent(), II->getNormalDest());
    Instruction *ndi = II->getNormalDest()->getFirstNonPHI();

    if(ndi == NULL){
        // unexpected, though the API allows getFirstNonPHI to be null.
        // assert 0 for now and handle only if we encounter it.
        errs() << "ndi is null\n";
        assert(0);
    }
    IRBuilder<> builder_end(ndi);
    if(dyn_cast<LandingPadInst>(ndi)){
        builder_end.SetInsertPoint(ndi->getNextNode());
    }
    builder_end.CreateCall(debrt_func, ArgsV);



void WholeProgramDebloat::instrument_indirect_and_external(Function *f, LoopInfo *LI)
{
    for(auto &b : *f){
        bool f_is_not_encompassed
          = encompassed_funcs.find(f) == encompassed_funcs.end();
        bool block_is_outside_loop = true;
        if(LI && LI->getLoopFor(&b)){
            block_is_outside_loop = false;
        }
        for(auto &I : b){
            CallBase   *CB = dyn_cast<CallBase>(&I);
            CallInst   *CI = dyn_cast<CallInst>(&I);
            InvokeInst *II = dyn_cast<InvokeInst>(&I);
            if(CB){
                Function *cf = CB->getCalledFunction();
                // ENABLE_INDIRECT_CALL_SINKING ensures that only when ICS is
                // active do we even instrument indirect calls now. This is
                // probably as it should have been from the start, because old
                // wpd approaches just turned on the transitive closure of all
                // func pointers.
                if(cf == NULL && ENABLE_INDIRECT_CALL_SINKING){
                    Value *v = CB->getCalledOperand();
                    if(dyn_cast<InlineAsm>(v)){
                        // ignore inline assembly... don't instrument
                        continue;
                    }
                    if(v->getType()->isPointerTy()){
                        // instrument before indirect func call
                        vector<Value *> ArgsV;
                        IRBuilder<> builder(CB);
                        ArgsV.push_back(builder.CreatePtrToInt(v, int64Ty));
                        if(f_is_not_encompassed && block_is_outside_loop){
                            builder.CreateCall(debrt_protect_indirect_func, ArgsV);

                            // instrument after indirect func call
                            if(CI){
                                IRBuilder<> builder_end(CI);
                                builder_end.SetInsertPoint(CI->getNextNode());
                                builder_end.CreateCall(debrt_protect_indirect_end_func, ArgsV);
                            }else if(II){
                                instrument_after_invoke(II, ArgsV, debrt_protect_indirect_end_func);
                            }else{
                                assert(0);
                            }
                        }else{
                            builder.CreateCall(ics_map_indirect_call_func, ArgsV);
                            // Note: we only instrument after the
                            // indirect call if we are not inside an
                            // encompassed func or a loop block. The
                            // runtime will handle this ICS optimization to
                            // clear the pages at the end of the loop.
                        }

                    }else{
                        // Not sure how to handle this if it happens
                        // would need to investigate the specific case.
                        assert(0 && "Unexpected: calledOperand is NOT a " \
                                    "pointer type for an indirect call.\n");
                    }
                }else{
                    if(cf->hasName() && cf->isDeclaration()){
                        instrument_external_call(I,
                                                 f_is_not_encompassed
                                                   && block_is_outside_loop
                                                );
                    }
                }
            }
        }
    }
}

void WholeProgramDebloat::instrument(void)
{
    errs() << "Instrumenting all other funcs\n";
    int i = 0;
    for(auto f : all_funcs){
        if(i % 100 == 0){
        }
        if(libc_nonstatic_func_names.count(func_id_to_name[func_to_id[f]]) == 0){
            LoopInfo *LI = &getAnalysis<LoopInfoWrapperPass>(*f).getLoopInfo();
            if(toplevel_funcs.find(f) != toplevel_funcs.end()){
                instrument_toplevel_func(f, LI);
            }
            instrument_indirect_and_external(f, LI);
        }
        i++;
    }
}

void WholeProgramDebloat::instrument_toplevel_func(Function *f, LoopInfo *LI)
{
    //for(auto f : toplevel_funcs){

        // Instrument outer loops
        for(auto loop = LI->begin(), e = LI->end(); loop != e; ++loop){
            stats.num_toplevel_loops++;
            if(ENABLE_INSTRUMENTATION_SINKING){
                // TODO
                // TODO If we try to do loop sinking again, then i think we
                // need to agument get_callees_aux() (or somewhere around
                // there) with ENABLE_BASIC_INDIRECT_CALL_STATIC_ANALYSIS
                // support.  (assuming we want to support it for
                // instrumentation-sinking).  Can look at how instrument_loop()
                // does it. Be aware of course that instrument-loop-sink may
                // invoke instrument-loop as a fallback case (not sure if that
                // matters though).
                // TODO
                instrument_loop_sink(func_to_id[f], *loop);
            }else{
                instrument_loop(func_to_id[f], *loop);
            }
        }

        // instrument call sites
        for(auto &b : *f){
            // ignore basic blocks that are part of any loop. already handled.
            if(LI && LI->getLoopFor(&b)){
                continue;
            }
            for(auto &I : b){
                CallBase   *CB = dyn_cast<CallBase>(&I);
                CallInst   *CI = dyn_cast<CallInst>(&I);
                InvokeInst *II = dyn_cast<InvokeInst>(&I);
                if(CB){
                    Function *callee = CB->getCalledFunction();
                    if(func_to_id.count(callee) > 0){
                        set<Function *> temp;
                        temp.insert(callee);
                        if(encompassed_funcs.find(callee) != encompassed_funcs.end()){
                            // Case: callee is no-instrument
                            temp.insert(static_reachability[callee].begin(), static_reachability[callee].end());

                            // instrument before callee
                            vector<Value *> ArgsV;
                            ArgsV.push_back(ConstantInt::get(int32Ty, func_to_id[callee], false));
                            IRBuilder<> builder(CB);
                            builder.CreateCall(debrt_protect_reachable_func, ArgsV);

                            // instrument after callee
                            if(CI){
                                IRBuilder<> builder_end(CI);
                                builder_end.SetInsertPoint(CI->getNextNode());
                                builder_end.CreateCall(debrt_protect_reachable_end_func, ArgsV);
                            }else if(II){
                                instrument_after_invoke(II, ArgsV, debrt_protect_reachable_end_func);
                            }else{
                                assert(0);
                            }

                        }else{
                            // Case: callee can be instrumented.

                            // instrument before callee
                            vector<Value *> ArgsV;
                            ArgsV.push_back(ConstantInt::get(int32Ty, func_to_id[callee], false));
                            IRBuilder<> builder(CB);
                            builder.CreateCall(debrt_protect_single_func, ArgsV);

                            // instrument after callee
                            if(CI){
                                IRBuilder<> builder_end(CI);
                                builder_end.SetInsertPoint(CI->getNextNode());
                                builder_end.CreateCall(debrt_protect_single_end_func, ArgsV);
                            }else if(II){
                                instrument_after_invoke(II, ArgsV, debrt_protect_single_end_func);
                            }else{
                                assert(0);
                            }
                        }
                        // An example of set of functions that will be debloated (Sharjeel)
#ifdef BOTTOM_UP_DISJOINT_SET
                        update_disjoint_sets(temp);
#else
                        instrumented_sets.push_back(temp);
#endif
                    }
                }
            }
        }
    //}


}

void WholeProgramDebloat::instrument_external_call(Instruction &I,
                                                   bool call_is_outside_loop)
{
    CallBase *CB = dyn_cast<CallBase>(&I);
    assert(CB);
    Function *external_func = CB->getCalledFunction();
    assert(external_func);

    // Weird edge case. atexit won't actually invoke the function pointer
    // (because it happens at teardown).
    // Plus, atexit is actually part of libc_nonstatic_func_names and is
    // therefore instrumented elsewhere by this pass as if it were application
    // code. So there's no need for it to have extra instrumentation here.
    if(external_func->getName() == "atexit"){
        // XXX An alternative to all the libc_nonstatic_func_names stuff
        // could be to create a new like isntrument_atexit(), which
        // just instruments atexit() with a debrt-protect-single/end call.
        // One of the only reasons I didn't do it this way was because
        // it's not obvious what func-id to pass. func_to_id[] doesn't have
        // atexit unless we change other places. But to do that we might as
        // well have something like libc_nonstatic_func_names and just
        // use all the other instrumentation stuff that's already there;
        // and thus we don't need some special instrument_atexit() call here.
        //instrument_atexit(&I);
        return;
    }

    bool instrumented = instrument_external_with_callback(I, call_is_outside_loop);
    if(!instrumented){
        if(external_func->getName() == "exit"){
            instrument_debrt_destroy(&I);
        }
    }
}


bool WholeProgramDebloat::instrument_external_with_callback(Instruction &I,
                                                            bool call_is_outside_loop)
{
    CallBase   *CB_external_call = dyn_cast<CallBase>(&I);
    CallInst   *CI_external_call = dyn_cast<CallInst>(&I);
    InvokeInst *II_external_call = dyn_cast<InvokeInst>(&I);


    Function *callback = NULL;
    int num_callbacks = 0;
    int arg_idx = 0;
    for(auto it_arg = CB_external_call->arg_begin();
      it_arg != CB_external_call->arg_end();
      it_arg++){
        //errs() << "arg " << arg_idx <<  "\n";
        Value *s = (*it_arg)->stripPointerCasts();
        if(s == NULL){
            assert(0 && "Unexpected: stripPointerCasts() returned NULL.");
        }
        Function *tmp = dyn_cast<Function>(s);
        if(tmp != NULL){
            if(func_to_id.find(tmp) != func_to_id.end()){
                callback = tmp;
                num_callbacks++;
            }else{
            }
        }
        arg_idx++;
    }

    // nothing to instrument if num_callbacks is 0
    if(num_callbacks == 0){
        return false;
    }

    // Currently there is only support for external calls where 1 application
    // function is passed to the library.
    // See 2021.08.30 notes for details on how this could be supported.
    // It's a weird edge case that should be safe to ignore for now, though.
    assert(num_callbacks == 1 && "Only 1 application function callback " \
                                 "is supported when calling an external library");


    // instrument around the external call()
    if(call_is_outside_loop){
        // Case: the external call is called from a non-encompassed func, and
        // from a block that's not in any loop. So we can just instrument
        // around it, using either single or reachable protection based on the
        // callback.

        vector<Value *> ArgsV;
        IRBuilder<> builder(CB_external_call);
        ArgsV.push_back(ConstantInt::get(int32Ty, func_to_id[callback], false));

        bool callback_is_encompassed
          = encompassed_funcs.find(callback) != encompassed_funcs.end();

        // Instrument before the external call
        Function *end_call;
        if(callback_is_encompassed){
            // reachable
            builder.CreateCall(debrt_protect_reachable_func, ArgsV);
            end_call = debrt_protect_reachable_end_func;
        }else{
            // single
            builder.CreateCall(debrt_protect_single_func, ArgsV);
            end_call = debrt_protect_single_end_func;
        }

        // Instrument after the external call
        if(CI_external_call){
            IRBuilder<> builder_end(CI_external_call);
            builder_end.SetInsertPoint(CI_external_call->getNextNode());
            builder_end.CreateCall(end_call, ArgsV);
        }else if(II_external_call){
            instrument_after_invoke(II_external_call, ArgsV, end_call);
        }else{
            assert(0);
        }

    }else{
        // Case: The external function is called from an encompassed func or
        // from inside a block that's in a loop. Rather than handle the
        // protection at the loop header, we cheat and use the indirect-call
        // inlining support. It could be slower, but external calls with
        // callbacks should be rare, and security could be better by mapping
        // on-the-fly. See also note in build_basic_structs.
        vector<Value *> ArgsV;
        IRBuilder<> builder(CB_external_call);
        ArgsV.push_back(builder.CreatePtrToInt(callback, int64Ty));
        builder.CreateCall(ics_map_indirect_call_func, ArgsV);
        // Note: As with other inlined indirect call instrumentation that
        // is inside some interprocedural loop, we do not instrument after
        // the external call. The runtime will handle the ICS optimization to
        // clear the pages at the end of the loop.
    }

    return true;

}




bool WholeProgramDebloat::instrument_main_start(Module &M)
{
    errs() << "Instrumenting main start\n";
    int found_main = 0;
    for(auto &F : M){
        string func_name = get_demangled_name(F);
        if(func_name == "main"){

            // instrument start of main with debrt-init
            vector<Value *> ArgsV;
            Instruction *I = F.getEntryBlock().getFirstNonPHI();
            assert(I);
            IRBuilder<> builder(I);
            ArgsV.push_back(ConstantInt::get(int32Ty, func_to_id[&F], false));
            ArgsV.push_back(ConstantInt::get(int32Ty, ENABLE_INSTRUMENTATION_SINKING, false));
            builder.CreateCall(debrt_init_func, ArgsV);

            found_main = 1;
            break;
        }
    }
    assert(found_main == 1);
}

bool WholeProgramDebloat::instrument_main_end(Module &M)
{
    errs() << "Instrumenting main end\n";
    int found_main = 0;
    for(auto &F : M){
        string func_name = get_demangled_name(F);
        if(func_name == "main"){

            // instrument any returns with debrt-destroy
            for(auto &B : F){
                if(isa<ReturnInst>(B.getTerminator())){
                    instrument_debrt_destroy(B.getTerminator());
                }
            }

            found_main = 1;
            break;
        }
    }
    assert(found_main == 1);
}


void WholeProgramDebloat::instrument_debrt_destroy(Instruction *I)
{
    assert(I);
    vector<Value *> ArgsV_return;
    IRBuilder<> builder(I);
    ArgsV_return.push_back(ConstantInt::get(int32Ty, 0, false));
    builder.CreateCall(debrt_destroy_func, ArgsV_return);
}


void WholeProgramDebloat::build_basic_structs(Module &M)
{
    LoopInfo *li;
    CallBase *cb;
    for(auto &F : M){
        //if(F.hasName()){
        //    errs() << "build-basic-structs: " << F.getName().str() << "\n";
        //    errs() << "  getLinkage(): " << F.getLinkage() << "\n";
        //}
        if(F.hasName() && !F.isDeclaration()){
            if(ics_func_names.find(F.getName().str()) != ics_func_names.end()){
                //errs() << "ignoring ics func: " << F.getName() << "\n";
                continue;
            }
            // update all_funcs
            all_funcs.insert(&F);
            li = &getAnalysis<LoopInfoWrapperPass>(F).getLoopInfo();
            for(auto &B : F){
                for(auto &I : B){
                    cb = dyn_cast<CallBase>(&I);
                    if(cb){
                        Function *callee = cb->getCalledFunction();
                        if(func_to_id.count(callee) > 0){
                            // update adj_list
                            adj_list[&F].insert(callee);
                            if(li && li->getLoopFor(&B)){
                                // add any functions that are called inside of
                                // a loop to encompassed_funcs
                                encompassed_funcs.insert(callee);
                            }
                        }
                        // Note: if we wanted to handle external calls without
                        // using the indirect inlining support, then this
                        // would be a place to start, I think. Right here
                        // we could check if the callee is a declaration
                        // and takes a callback, and then we could update the
                        // adj-list to include the callback that gets passed
                        // to the external call. I believe other things should
                        // then fall into place, including how the loop
                        // preheader would get instrumented whenever any
                        // external call instances are interprocedurally
                        // reached by a loop. Not 100% sure about all this,
                        // but again, probably the right way to start going
                        // about it.
                    }
                }
            }
        }else if(F.hasName() && (libc_nonstatic_func_names.count(F.getName().str()) > 0)){
            // XXX This is sufficient for atexit(), which is currently the only
            // member of libc_nonstatic_func_names. If we have to handle more
            // libc_nonstatic cases, or if that set gets slightly repurposed,
            // this code may need reconsideration. Notice that we cannot include
            // functions like atexit() in the above analysis (with LoopInfoWrapperPass),
            // because it's an external call with no info. But we don't
            // instrument any callees or anything beyond atexit, so this
            // all_funcs insertion is sufficient for atexit().
            all_funcs.insert(&F);
        }
    }

    // build reverse adjacency list
    for(auto caller_callees : adj_list){
        auto caller  = caller_callees.first;
        auto callees = caller_callees.second;
        for(auto callee : callees){
            rev_adj_list[callee].insert(caller);
        }
    }
}


#ifdef BOTTOM_UP_DISJOINT_SET
void WholeProgramDebloat::update_disjoint_sets(set<Function *> &new_set)
{
    // sharjeel's approach is to do this in places:
    //   instrumented_sets.push_back(new_set)
    // then call this at the end of the pass:
    //   create_disjoint_sets()

    //
    // New approach (bottom-up)
    //
    // General idea: Each time we have a new set of functions that form a
    // deck, we update our disjoint sets. Any completely new functions that
    // we see will go into their own disjoint set. Any functions that intersect
    // with an existing disjoint set will get factored out into new disjoint
    // sets.

    // unique IDs for the all disjoint sets
    static long disjoint_set_id = 0;
    #define DISJOINT_SET_ID_PARENTLESS    (-1)
    #define DISJOINT_SET_ID_UNINITIALIZED (-2)

    // a map from a new disjoint set's parent id to that new, factored-out
    // disjoint set
    map<long, disjoint_set_t> factored_disjoint_sets;

    // a new disjoint set with just elements from new_set, if needed
    disjoint_set_t parentless_disjoint_set;
    parentless_disjoint_set.id = DISJOINT_SET_ID_UNINITIALIZED;
    parentless_disjoint_set.s = NULL;

    // For each function in the new deck set
    for(Function *func : new_set){
        // Check if the function already exists in a disjoint set.
        if(func_to_disjoint_set.find(func) == func_to_disjoint_set.end()){
            // ... it does not
            // It goes into a new parentless disjoint set
            if(parentless_disjoint_set.s == NULL){
                parentless_disjoint_set.s = new set<Function *>;
                parentless_disjoint_set.id = disjoint_set_id;
                disjoint_set_id++;
            }
            parentless_disjoint_set.s->insert(func);
            func_to_disjoint_set[func] = parentless_disjoint_set;
        } else {
            // ... it does
            // Grab the disjoint set where it resides. (this is now the 'parent')
            disjoint_set_t disjoint_set = func_to_disjoint_set[func];
            // Check if we already have a factored-out disjoint set for this parent
            if(factored_disjoint_sets.find(disjoint_set.id) == factored_disjoint_sets.end()){
                // ... we don't
                disjoint_set_t ds; // a new, factored-out disjoint set
                ds.id = disjoint_set_id;
                ds.s = new set<Function *>;
                ds.s->insert(func);
                disjoint_set_id++;
                factored_disjoint_sets[disjoint_set.id] = ds;
                // Update the mapping of function to the disjoint set where it resides
                func_to_disjoint_set[func] = ds;
            } else {
                // ... we do
                // So add to that factored-out disjoint set
                factored_disjoint_sets[disjoint_set.id].s->insert(func);
                // Update the mapping of function to the disjoint set where it resides
                func_to_disjoint_set[func] = factored_disjoint_sets[disjoint_set.id];
            }
            // Irrespective of whether we already had a factored-out set, we
            // still need to remove the function from the parent.
            assert(disjoint_set.s->find(func) != disjoint_set.s->end());
            disjoint_set.s->erase(func);
        }
    }

    // If we actually made a new parentless disjoint set
    if(parentless_disjoint_set.s != NULL){
        factored_disjoint_sets[DISJOINT_SET_ID_PARENTLESS] = parentless_disjoint_set;
    }

    // Last step: Update our global disjoint sets with any new factored-out
    // sets we created. Note that we don't need to do any erasing here, because
    // it's already been handled when we factored out functions.
    // We don't clear out any empty sets in disjoint_sets. We just ignore them
    // when dumping.
    for(auto &it : factored_disjoint_sets){
        int parent_id = it.first;
        disjoint_set_t &ds = it.second;
        disjoint_sets[ds.id] = ds.s;
    }
    // TODO should actually free the memory for the disjoint sets.
    // could do that after dump_disjoint_sets

    //print_disjoint_sets(); // debug
}


void WholeProgramDebloat::finalize_disjoint_sets(void)
{
    // Set of functions that have addresses taken so we take their reachability
    // and consider it as a set (Sharjeel)
    errs() << "Finalizing disjoint sets\n";
    for(auto F : func_has_addr_taken)
    {
        set<Function *> temp;
        temp.insert(F);
        temp.insert(static_reachability[F].begin(), static_reachability[F].end());
        update_disjoint_sets(temp);
    }
}
#else
void WholeProgramDebloat::create_disjoint_sets(void)
{
    errs() << "Creating disjoint sets\n";
    // Set of functions that have addresses taken so we take their reachability and consider it as a set (Sharjeel)
    for(auto F : func_has_addr_taken)
    {
        set<Function *> temp;
        temp.insert(F);
        temp.insert(static_reachability[F].begin(), static_reachability[F].end());
        instrumented_sets.push_back(temp);
    }

    size_t index = 0;
    set<Function *> intersection;
    set<Function *> difference1;
    set<Function *> difference2;
    // While there are non-disjoint sets
    while(!instrumented_sets.empty())
    {
        // Take a set A
        vector<set<Function *>> temp(instrumented_sets.begin() + 1, instrumented_sets.end());
        set<Function *> current(instrumented_sets[0]);
        instrumented_sets.clear();

        // Take a set B
        for(auto setF : temp)
        {
            if(current.size() != 0)
            {   
                intersection.clear();
                difference1.clear();
                difference2.clear();

                if(setF.size() == 0)
                {
                    continue;
                }

                // Take intersection of set A and set B to make set C
                set_intersection(current.begin(), current.end(), setF.begin(), setF.end(), inserter(intersection, intersection.end()));
                if(intersection.size() == 0)
                {
                    // If intersection is empty, we do not need to do any difference and keep set B for next stage
                    instrumented_sets.push_back(setF);
                }
                else
                {
                    // Take difference between set A and set C to get set A-C
                    set_difference(current.begin(), current.end(), intersection.begin(), intersection.end(), inserter(difference1, difference1.end()));

                    // Take difference between set B and set C to get set B-C
                    set_difference(setF.begin(), setF.end(), intersection.begin(), intersection.end(), inserter(difference2, difference2.end()));

                    // If both set A and set B are the same, we remove set B and continue with set A
                    if(difference1.size() == 0 && difference2.size() == 0)
                    {
                        continue;
                    }

                    // If set B is empty, we do not need to consider it for a future step
                    if(difference2.size() != 0)
                    {
                        instrumented_sets.push_back(difference2);
                    }
                    
                    instrumented_sets.push_back(intersection);

                    current.clear();
                    current.insert(difference1.begin(), difference1.end());
                }
            }
            else 
            {
                instrumented_sets.push_back(setF);
            }
        }

        // If set A is not empty, we consider it as a disjoint set
        if(current.size() != 0)
        {
            disjoint_sets[index].insert(current.begin(), current.end());
        }
        index += 1;
    }
}
#endif

///
// XXX Commented out, leaving for posterity. This function is wrong, I think,
// because it doesn't take into account convergence. A better way to do this is
// to just extend adj_list based on func pointers, and then just leverage
// build_static_reachability() with that augmented adj-list.
//
// Extend static reachability based on "simple" function pointer analysis.
// This is not leveraging true pointer analysis. Rather, for any function
// F, we add to its statically reachable set any function pointer that
// could be invoked on some (flow-insensitive) path to F in the callgraph.
// "Could be invoked" is very conservative: It's true if a function has
// its address taken along that path, and false otherwise.
/*void WholeProgramDebloat::extend_static_reachability(void)
{
    for(auto func_parents : func_to_parents){
        auto func    = func_parents.first;
        auto parents = func_parents.second;

        // first take care of the "base" function itself.
        // For any function pointers that it uses, add those function pointers
        // to its statically reachable set.
        auto fps = func_to_fps[func];
        for(auto fp : fps){
            if(fp != func){
                static_reachability[func].insert(
                  static_reachability[fp].begin(),
                  static_reachability[fp].end()
                );
            }
        }

        // now take care of all of its parents. for each parent, grab any
        // function pointers that it uses, and add that to the statically
        // reachable set of our base func.
        for(auto parent : parents){
            auto fps = func_to_fps[parent];
            for(auto fp : fps){
                if(fp != func){
                    static_reachability[func].insert(
                      static_reachability[fp].begin(),
                      static_reachability[fp].end()
                    );
                }
            }

        }
    }
}*/

void WholeProgramDebloat::extend_adj_list(void)
{
    for(auto func_parents : func_to_parents){
        auto func    = func_parents.first;
        auto parents = func_parents.second;

        // First take care of the "base" function itself.
        // For any functions that it takes the address of, add them to
        // its adj-list-fps
        auto fps = func_to_fps[func];
        adj_list_fps[func].insert(fps.begin(), fps.end());

        // Now take care of all of its parents. For each parent, grab any
        // functions that it takes the address of, and add those to the
        // adj-list-fps our base func.
        for(auto parent : parents){
            auto fps = func_to_fps[parent];
            adj_list_fps[func].insert(fps.begin(), fps.end());
        }

        // update the func's adj-list with its adj-list-fps
        adj_list[func].insert(adj_list_fps[func].begin(),
                              adj_list_fps[func].end());
    }
}

void WholeProgramDebloat::build_static_reachability(void)
{
    errs() << "Building static reachability\n";
    int i = 0;
    //errs() << "Size of all_funcs: " << all_funcs.size() << "\n";
    for(auto F : all_funcs){
        if(i % 500 == 0){
        }
        //errs() << i << " " << F->getName() << "\n";
        queue<Function *> q;
        //errs() << "  pushing callees\n";
        for(auto callee : adj_list[F]){
            q.push(callee);
        }
        //errs() << "  updating static reachability\n";
        while(!q.empty()){
            Function *f = q.front();
            q.pop();
            static_reachability[F].insert(f);
            for(auto qcallee : adj_list[f]){
                if(static_reachability[F].find(qcallee) == static_reachability[F].end()){
                    q.push(qcallee);
                }
            }
            // If the function is recursive or part of an SCC, add it to
            // encompassed funcs.
            if(F == f){
                encompassed_funcs.insert(f);
            }
        }
        i++;
    }
}
void WholeProgramDebloat::build_func_to_parents(void)
{
    for(auto F : all_funcs){
        queue<Function *> q;
        for(auto parent : rev_adj_list[F]){
            q.push(parent);
        }
        while(!q.empty()){
            Function *f = q.front();
            q.pop();
            func_to_parents[F].insert(f);
            for(auto qparent : rev_adj_list[f]){
                if(func_to_parents[F].find(qparent) == func_to_parents[F].end()){
                    q.push(qparent);
                }
            }
        }
    }
}

// Can think of this as building a map that tells us where function pointers
// get created -- so for some function, I can tell you which fps are created
// inside of it.  More specifically, we build a map of function -> set of
// functions that it takes the address of.  We do this by first finding all
// points ('uses') where a function has its address taken. If that point is a
// valid instruction, then we add to our map: the key is the instruction's
// function (i.e. the function where we take another function's address); the
// value is the function whose address we take.
void WholeProgramDebloat::build_func_to_fps(Module &M)
{
    int s;
    int f;
    s = 0;
    f = 0;
    for(auto &F : M){
        if( (F.hasName() && !F.isDeclaration())
        ||  (F.hasName() && (libc_nonstatic_func_names.count(F.getName().str()) > 0)) ){
        //if(F.hasName() && !F.isDeclaration()){
            vector<User *> offenders;
            get_address_taken_uses(F, offenders);
            // offenders will be non-empty if F has its address taken
            for(User *user : offenders){
                Instruction *i = dyn_cast<Instruction>(user);
                if(i){
                    Function *f = i->getFunction();
                    //errs() << "function pointer user: " << f->getName() << "\n";
                    func_to_fps[f].insert(&F);
                    s++;
                }else{
                    f++;
                }
            }
        }
    }
    //errs() << "s: " << s << "\n";
    //errs() << "f: " << f << "\n";
}

void WholeProgramDebloat::build_toplevel_funcs(void)
{
    errs() << "Building toplevel funcs\n";
    // toplevel_funcs = all_funcs \ encompassed_funcs
    set_difference(all_funcs.begin(),
                   all_funcs.end(),
                   encompassed_funcs.begin(),
                   encompassed_funcs.end(),
                   inserter(toplevel_funcs, toplevel_funcs.end()));
}

void WholeProgramDebloat::wpd_init(Module &M)
{
    // Init loop count (for handing out IDs)
    loop_id_counter = 0;
    sink_id_counter = 0;

    ENABLE_INSTRUMENTATION_SINKING = EnableInstrumentationSinking;
    errs() << "ENABLE_INSTRUMENTATION_SINKING: " << ENABLE_INSTRUMENTATION_SINKING << "\n";
    ENABLE_INDIRECT_CALL_SINKING = EnableIndirectCallSinking;
    errs() << "ENABLE_INDIRECT_CALL_SINKING: " << ENABLE_INDIRECT_CALL_SINKING << "\n";
    ENABLE_BASIC_INDIRECT_CALL_STATIC_ANALYSIS = EnableBasicIndirectCallStaticAnalysis;
    errs() << "ENABLE_BASIC_INDIRECT_CALL_STATIC_ANALYSIS: " << ENABLE_BASIC_INDIRECT_CALL_STATIC_ANALYSIS << "\n";


    memset(&stats, 0, sizeof(stats));

    // FIXME (see fixme within read_readelf_sections)
    if(ENABLE_INSTRUMENTATION_SINKING){
        read_readelf_sections();
        read_readelf();
    }

    ics_func_names.insert("ics_map_indirect_call");
    ics_func_names.insert("ics_unmap_indirect_calls");

    libc_nonstatic_func_names.insert("atexit");

    // Give each application function an ID
    int count = 0;
    for(auto &F : M){
        if( (F.hasName() && !F.isDeclaration())
        ||  (F.hasName() && (libc_nonstatic_func_names.count(F.getName().str()) > 0)) ){
        //if(F.hasName() && !F.isDeclaration()){
            func_name_to_id[F.getName().str()] = count;
            func_to_id[&F] = count;
            func_id_to_name[count] = F.getName().str();
            func_id_to_func[count] = &F;
            if(F.hasAddressTaken()){
                //errs() << "F.hasAddressTaken() is: " << F.getName() << "\n";
                func_name_has_addr_taken.insert(F.getName().str());
                func_has_addr_taken.insert(&F);
            }
            count++;
        }
    }


    // errs() << "Create library function\n";
    // Create library function
    int32Ty = IntegerType::getInt32Ty(M.getContext());
    int64Ty = IntegerType::getInt64Ty(M.getContext());
    Type *ArgTypes[] = { int32Ty };
    Type *ArgTypes2[] = { int32Ty, int32Ty };
    Type *ArgTypes64[] = { int64Ty };

    debrt_init_func = Function::Create(FunctionType::get(int32Ty, ArgTypes2, false),
            Function::ExternalLinkage,
            "debrt_init",
            M);
    debrt_destroy_func = Function::Create(FunctionType::get(int32Ty, ArgTypes, false),
            Function::ExternalLinkage,
            "debrt_destroy",
            M);
    debrt_protect_single_func = Function::Create(FunctionType::get(int32Ty, ArgTypes, false),
            Function::ExternalLinkage,
            "debrt_protect_single",
            M);
    debrt_protect_single_end_func = Function::Create(FunctionType::get(int32Ty, ArgTypes, false),
            Function::ExternalLinkage,
            "debrt_protect_single_end",
            M);
    debrt_protect_reachable_func = Function::Create(FunctionType::get(int32Ty, ArgTypes, false),
            Function::ExternalLinkage,
            "debrt_protect_reachable",
            M);
    debrt_protect_reachable_end_func = Function::Create(FunctionType::get(int32Ty, ArgTypes, false),
            Function::ExternalLinkage,
            "debrt_protect_reachable_end",
            M);
    debrt_protect_loop_func = Function::Create(FunctionType::get(int32Ty, ArgTypes, false),
            Function::ExternalLinkage,
            "debrt_protect_loop",
            M);
    //debrt_protect_loop_end_func = Function::Create(FunctionType::get(int32Ty, ArgTypes, false),
    //        Function::ExternalLinkage,
    //        "debrt_protect_loop_end",
    //        M);
    debrt_protect_indirect_func = Function::Create(FunctionType::get(int32Ty, ArgTypes64, false),
            Function::ExternalLinkage,
            "debrt_protect_indirect",
            M);
    debrt_protect_indirect_end_func = Function::Create(FunctionType::get(int32Ty, ArgTypes64, false),
            Function::ExternalLinkage,
            "debrt_protect_indirect_end",
            M);
    debrt_protect_sink_func = Function::Create(FunctionType::get(int32Ty, ArgTypes, false),
            Function::ExternalLinkage,
            "debrt_protect_sink",
            M);
    debrt_protect_sink_end_func = Function::Create(FunctionType::get(int32Ty, ArgTypes, false),
            Function::ExternalLinkage,
            "debrt_protect_sink_end",
            M);

    ics_map_indirect_call_func = Function::Create(FunctionType::get(int32Ty, ArgTypes64, false),
            Function::ExternalWeakLinkage,
            "ics_map_indirect_call",
            M);
    ics_wrapper_debrt_protect_loop_end_func
      = Function::Create(FunctionType::get(int32Ty, ArgTypes, false),
            Function::ExternalWeakLinkage,
            "ics_wrapper_debrt_protect_loop_end",
            M);


}



bool WholeProgramDebloat::runOnModule_real(Module &M)
{
    // Initialization
    wpd_init(M);

    // Build all_funcs, adj_list, func_to_loop_info
    // Paritlally build encompassed_funcs
    build_basic_structs(M);

    if(ENABLE_BASIC_INDIRECT_CALL_STATIC_ANALYSIS){
        // Build a map of func -> set of parents that can reach it.
        build_func_to_parents();

        // Build a map of func -> functions that it takes the address of
        build_func_to_fps(M);

        // Add statically reachable functions based on _simple_ function pointer
        // analysis (not true pointer analysis)
        //extend_static_reachability();

        // Extend adj-list based on the func pointers. This augmented adj-list
        // will be picked up (correctly) during build_static_reachability().
        extend_adj_list();
    }

    // Build a map of func -> set of statically reachable funcs
    // (also add funcs that are recursive or part of SCCs to encompassed-funcs)
    build_static_reachability();

    // Extend encompassed_funcs to any functions that are reachable from
    // its members
    extend_encompassed_funcs();

    // Build the set of functions that are "top-level", i.e. not reachable
    // from within any loop
    build_toplevel_funcs();

    // Instrument main with a debrt-init call
    instrument_main_start(M);

    // Instrument all other functions
    instrument();

    // Instrument main with a debrt-destroy call.
    // Doing this AFTER all other instrumentation to to ensure every exit block
    // calls destroy after any other instrumentation. (That is, it's probably a
    // bad idea to relocate this code into instrument_main_start() and
    // before instrument().)
    instrument_main_end(M);

#ifdef BOTTOM_UP_DISJOINT_SET
    // finalize disjoint sets
    finalize_disjoint_sets();
#else
    // create disjoint sets
    create_disjoint_sets();
#endif
}

bool WholeProgramDebloat::runOnModule(Module &M)
{
    runOnModule_real(M);
    return true;
}


/*
void check_postdominance(BasicBlock *B1, BasicBlock *B2)
{
    // Stack of Basicblock
    std::stack<BasicBlock *> stacktemp;

    // Basicblocks already seen
    std::map<BasicBlock *, uint8_t> seen;

    // Add the initial successors nodes to the stack
    Instruction *TI = B1->getTerminator();
    for(uint64_t i = 0; TI && i < TI->getNumSuccessors(); ++i){
        stacktemp.push(TI->getSuccessor(i));
    }

    // While stack is not empty, keep on checking postdominance of all nodes
    while(!stacktemp.empty()){
        BasicBlock *Btemp = stacktemp.top();
        stacktemp.pop();

        // If the last node is B2, it is control dependent on B1
        if(Btemp == B2){
            dart(B2->getName().str() + " is control dependent on " + B1->getName().str());
            break;
        }
        // Else, we check if B2 postdominates this basicblock so we can
        // add the successors
        else if(!seen[Btemp] && PDT->dominates(B2, Btemp)){
            Instruction *TI = Btemp->getTerminator();
            for(uint64_t i = 0; TI && i < TI->getNumSuccessors(); ++i){
                stacktemp.push(TI->getSuccessor(i));
            }
        }
        seen[Btemp] = 1; 
    }
}
*/
/*bool is_reachable(BasicBlock *B1, BasicBlock *B2)
{
    queue<BasicBlock*> bbqueue;
    set<BasicBlock*> bbseen;
    bbqueue.push(B1);
    while(!bbqueue.empty()){
        BasicBlock *B = bbqueue.front();
        bbqueue.pop();

        if(bbseen.count(B) != 0){
            continue;
        }
        bbseen.insert(B);

        if(B == B2){
            return true;
        }

        Instruction *TI = B->getTerminator();
        for(uint64_t i = 0; TI && i < TI->getNumSuccessors(); i++){
            bbqueue.push(TI->getSuccessor(i));
        }
    }
    return false;
}*/

void WholeProgramDebloat::dump_static_reachability(void)
{
    FILE *fp_reachability = fopen("wpd_static_reachability.txt", "w");
    //errs() << "Dumping static reachability\n";
    for(auto p : static_reachability){
        Function *f = p.first;
        set<Function *> &reachable_funcs = p.second;
        //errs() << f->getName() << ": ";
        //fprintf(fp_reachability, "%s ", f->getName().str().c_str());
        fprintf(fp_reachability, "%d ", func_to_id[f]);
        for(auto rf : reachable_funcs){
            //errs() << rf->getName() << " ";
            //fprintf(fp_reachability, "%s,", rf->getName().str().c_str());
            fprintf(fp_reachability, "%d,", func_to_id[rf]);
        }
        //errs() << "\n";
        fprintf(fp_reachability, "\n");
    }
    fclose(fp_reachability);
}
void WholeProgramDebloat::dump_loop_static_reachability(void)
{
    FILE *fp_loop_reachability;
    if(ENABLE_INSTRUMENTATION_SINKING){
        fp_loop_reachability = fopen("wpd_loop_static_reachability_sinkenabled.txt", "w");
    }else{
        fp_loop_reachability = fopen("wpd_loop_static_reachability.txt", "w");
    }
    for(auto p : loop_static_reachability){
        int loop_id = p.first;
        set<Function *> &reachable_funcs = p.second;
        fprintf(fp_loop_reachability, "%d ", loop_id);
        for(auto rf : reachable_funcs){
            fprintf(fp_loop_reachability, "%d,", func_to_id[rf]);
        }
        fprintf(fp_loop_reachability, "\n");
    }
    fclose(fp_loop_reachability);
}
void WholeProgramDebloat::dump_encompassed_funcs(void)
{
    FILE *fp_encompassed = fopen("wpd_encompassed_funcs.txt", "w");
    for(auto ef : encompassed_funcs){
        int func_id = func_to_id[ef];
        fprintf(fp_encompassed, "%d (%s)\n", func_id, func_id_to_name[func_id].c_str());
    }
    fclose(fp_encompassed);
}
void WholeProgramDebloat::dump_loop_id_to_func_id(void)
{
    FILE *fp_loop_to_func = fopen("wpd_loop_to_func.txt", "w");
    for(auto p : loop_id_to_func_id){
        int loop_id = p.first;
        int func_id = p.second;
        //errs() << l->getName() << ": ";
        //fprintf(fp_loop_to_func, "%s ", l->getName().str().c_str());
        fprintf(fp_loop_to_func, "%d: %d (%s)\n", loop_id, func_id, func_id_to_name[func_id].c_str());
    }
    fclose(fp_loop_to_func);
}
void WholeProgramDebloat::dump_sink_id_to_func_id(void)
{
    FILE *fp_sink_to_func = fopen("wpd_sink_to_func.txt", "w");
    for(auto p : sink_id_to_func_id){
        int sink_id = p.first;
        int func_id = p.second;
        //errs() << l->getName() << ": ";
        //fprintf(fp_loop_to_func, "%s ", l->getName().str().c_str());
        fprintf(fp_sink_to_func, "%d: %d (%s)\n", sink_id, func_id, func_id_to_name[func_id].c_str());
    }
    fclose(fp_sink_to_func);
}
void WholeProgramDebloat::dump_sinks(void)
{
    FILE *fp_sinks = fopen("wpd_sinks.txt", "w");
    for(auto p : sinks){
        int sink_id = p.first;
        set<int> &funcs = p.second;
        fprintf(fp_sinks, "%d ", sink_id);
        for(auto f : funcs){
            fprintf(fp_sinks, "%d,", f);
        }
        fprintf(fp_sinks, "\n");
    }
    fclose(fp_sinks);
}
void WholeProgramDebloat::dump_func_ptrs(void)
{
    FILE *fp_funcptrs = fopen("wpd_func_name_has_addr_taken.txt", "w");
    for(auto func_name : func_name_has_addr_taken){
        fprintf(fp_funcptrs, "%s\n", func_name.c_str());
    }
    fclose(fp_funcptrs);
}
void WholeProgramDebloat::dump_func_name_to_id(void)
{
    FILE *fp = fopen("wpd_func_name_to_id.txt", "w");
    for(auto fn2id : func_name_to_id){
        fprintf(fp, "%s %u\n", fn2id.first.c_str(), fn2id.second);
    }
    fclose(fp);
}
#ifdef BOTTOM_UP_DISJOINT_SET
void WholeProgramDebloat::print_disjoint_sets(void)
{
    for(auto set : disjoint_sets){
        if(set.second->size() > 0)
        {
            errs() << set.first << ": ";
            for(auto f : *(set.second))
            {
                errs() << func_to_id[f] << " ";
            }
            errs() << "\n";
        }
    }
}
#endif
void WholeProgramDebloat::dump_disjoint_sets(void)
{
    FILE *fp = fopen("wpd_disjoint_sets.txt", "w");
#ifdef BOTTOM_UP_DISJOINT_SET
    for(auto set : disjoint_sets){
        if(set.second->size() > 0)
        {
            fprintf(fp, "%ld: ", set.first);
            for(auto f : *(set.second))
            {
                fprintf(fp, "%u ", func_to_id[f]);
            }
            fprintf(fp, "\n");
        }
    }
#else
    for(auto set : disjoint_sets){
        fprintf(fp, "%lu: ", set.first);
        for(auto f : set.second)
        {
            fprintf(fp, "%u ", func_to_id[f]);
        }
        fprintf(fp, "\n");
    }
#endif
    fclose(fp);
}
void WholeProgramDebloat::dump_stats(void)
{
    FILE *fp = fopen("wpd_stats.txt", "w");
    fprintf(fp, "Number of toplevel loops: %d\n", stats.num_toplevel_loops);
    fprintf(fp, "Number of instrumented toplevel loops: %d\n",
                stats.num_instrumented_basic_loops + stats.num_instrumented_sunk_loops);
    fprintf(fp, "Number of instrumented toplevel loops without sinking: %d\n",
                stats.num_instrumented_basic_loops);
    fprintf(fp, "Number of instrumented toplevel loops with sinking: %d\n",
                stats.num_instrumented_sunk_loops);
    fprintf(fp, "Number of instrumented toplevel loops with multilevel sinking: %d\n",
                stats.num_instrumented_sunk_multilevel_loops);
    fprintf(fp, "Number of sinking attempts (not necessarily toplevel) that " \
                "failed because:\n");
    fprintf(fp, "  there were no callees: %d\n", stats.sink_fail_no_calles);
    fprintf(fp, "  we revisited a function: %d\n", stats.sink_fail_due_to_visited);
    fprintf(fp, "  the union and intersection threshold check failed: %d\n",
                  stats.sink_fail_thresh_check);
    fclose(fp);
}
string WholeProgramDebloat::get_demangled_name(const Function &F)
{
    ItaniumPartialDemangler IPD;
    string name = F.getName().str();
    if(IPD.partialDemangle(name.c_str())){
        return name;
    }
    if(IPD.isFunction()){
        return IPD.getFunctionBaseName(nullptr, nullptr);
    }
    return IPD.finishDemangle(nullptr, nullptr);
}
// don't insert elements that are empty (so for example split(' ') on
// "a     b" will do the expected thing and return on ['a', 'b'])
template<typename Out>
void split_nonempty(const string &s, char delim, Out result)
{
    stringstream ss(s);
    string item;
    while(getline(ss, item, delim)){
        if(!item.empty()){
            *(result++) = item;
        }
    }
}
vector<string> split_nonempty(const string &s, char delim)
{
    vector<string> elems;
    split_nonempty(s, delim, back_inserter(elems));
    return elems;
}
void WholeProgramDebloat::read_readelf_sections(void)
{
    // FIXME This is a hack to get instrumentation-sinking off the ground.
    // The problem with this function and approach is that it ties this entire
    // pass to the readelf output, which means a successful build has to happen
    // before this pass can even run. But the catch-22 is that the readelf
    // output is from this pass itself.
    // The fix for this, if we're going to keep this approach for calculating
    // thresholds, is to output a separate, uniquely named readelf file after
    // building the baseline, and to enforce users of this pass to build a
    // baseline first. And by using a different name for the baseline's
    // readelf output, we won't collide with the readelf output from this pass,
    // which is used by the runtime for specific offsets and sizes for mapping
    // pages.
    ifstream ifs;
    string line;
    vector<string> elems;
    ifs.open("readelf-sections.out");
    if(!ifs.is_open()){
        perror("Error openening readelf-sections file");
        exit(EXIT_FAILURE);
    }
    while(getline(ifs, line)){
        elems = split_nonempty(line, ' ');
        int text_offset_idx = 0;
        if(elems.size() >= 2 && elems[1].compare(".text") == 0){
            text_offset_idx = 3;
        }else if(elems.size() >= 3 && elems[2].compare(".text") == 0){
            text_offset_idx = 4;
        }
        if(text_offset_idx){
            //text_offset = stoll(elems[text_offset_idx], 0, 16);
            getline(ifs, line);
            elems = split_nonempty(line, ' ');
            text_size = stoll(elems[0], 0, 16);
            //DEBRT_PRINTF("text_offset is: 0x%llx\n", text_offset);
            break;
        }
    }
    ifs.close();
    //if(text_size == 0 || text_offset == 0){
    if(text_size == 0){
        //fprintf(stderr, "ERROR: text size and offset should be non-zero\n");
        fprintf(stderr, "ERROR: text size should be non-zero\n");
        exit(1);
    }
}
void WholeProgramDebloat::read_readelf(void)
{
    string line;
    ifstream ifs;
    int token_start;
    int token_end;
    int token_count;
    string token;

    enum READELF_COLS {
        RELF_NUM = 0,
        RELF_VALUE,
        RELF_SIZE,
        RELF_TYPE,
        RELF_BIND,
        RELF_VIS,
        RELF_NDX,
        RELF_NAME
    };
    int idx;
    int which_token;
    string func_name;
    long long func_addr;
    long func_size;

    ifs.open("readelf.out");
    if(!ifs.is_open()){
        perror("Error opening readelf file");
        exit(EXIT_FAILURE);
    }

    while(getline(ifs, line)){

        token_count = 0;
        idx = 0;
        while(idx < line.size() && line.at(idx) != '\n'){
            //DEBRT_PRINTF("%c", line.at(idx));
            //idx++;
            while(idx < line.size() && line.at(idx) == ' '){
                idx++;
            }
            token_start = idx;
            while(idx < line.size() && line.at(idx) != ' ' && line[idx] != '\n'){
                idx++;
            }
            token_end = idx;
            token = line.substr(token_start, token_end - token_start);

            which_token = token_count;

            // func addr
            if(which_token == RELF_VALUE){
                func_addr = strtoll(token.c_str(), NULL, 16);

            }else if(which_token == RELF_SIZE){
                // infer base by passing "0". almost always 10 but ive seen 16
                // in at least one perlbench function
                func_size = strtol(token.c_str(), NULL, 0);

            // func name
            }else if(which_token == RELF_NAME){
                func_name = token;
                readelf_func_name_to_size[func_name] = func_size;
            }
            token_count++;
        }
        //cout << endl;
    }
    ifs.close();
}

bool WholeProgramDebloat::doFinalization(Module &M)
{
    dump_encompassed_funcs();
    dump_static_reachability();
    dump_loop_static_reachability();
    dump_func_name_to_id();
    dump_func_ptrs();
    dump_loop_id_to_func_id();
    dump_sink_id_to_func_id();
    dump_sinks();
    dump_disjoint_sets();
    dump_stats();
    return false;
}
bool WholeProgramDebloat::doInitialization(Module &M)
{
    // XXX don't use this to initialize shit unless you want it to wig out
    return false;
}

char WholeProgramDebloat::ID = 0;
static RegisterPass<WholeProgramDebloat> Y("WholeProgramDebloat", "Whole program debloat pass");

#ifndef DEBLOAT_RT_H
#define DEBLOAT_RT_H

extern "C" {
int debrt_init(int main_func_id, int sink_is_enabled);
int debrt_destroy(int notused);

int debrt_protect_single(int callee_func_id);
int debrt_protect_single_end(int callee_func_id);

int debrt_protect_reachable(int callee_func_id);
int debrt_protect_reachable_end(int callee_func_id);

int debrt_protect_loop(int loop_id);
int debrt_protect_loop_end(int loop_id);

int debrt_protect_indirect(long long callee_addr);
int debrt_protect_indirect_end(long long callee_addr);

int debrt_protect_sink(int sink_id);
int debrt_protect_sink_end(int sink_id);

int debrt_trace(int func_id);

}

#endif

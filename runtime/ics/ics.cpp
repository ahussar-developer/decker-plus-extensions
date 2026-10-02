#include <stdlib.h>
#include <string.h>

#define MAX_CACHED_FP_ADDRS_SZ (1<<20) // 8 MB

extern "C" {int debrt_protect_indirect(long long);}
extern "C" {int debrt_protect_loop_end(int);}

long long cached_fp_addrs[MAX_CACHED_FP_ADDRS_SZ] = {0};
long long cached_fp_addrs_idx = 0;

extern "C" {
__attribute__((always_inline))
int ics_map_indirect_call(long long fp_addr)
{
    long long x;
    x = fp_addr;
    x = (x ^ (x >> 30)) * (0xbf58476d1ce4e5b9LL);
    x = (x ^ (x >> 27)) * (0x94d049bb133111ebLL);
    x = (x ^ (x >> 31)) % MAX_CACHED_FP_ADDRS_SZ;
    if(cached_fp_addrs[x] == fp_addr){
        return 0;
    }
    if(debrt_protect_indirect(fp_addr) == 0){
        cached_fp_addrs[x] = fp_addr;
    }
    return 0;
}
}

extern "C" {
__attribute__((always_inline))
int ics_wrapper_debrt_protect_loop_end(int loop_id)
{
    debrt_protect_loop_end(loop_id);
    memset(cached_fp_addrs, 0, sizeof(long long) * MAX_CACHED_FP_ADDRS_SZ);
    return 0;
}
}

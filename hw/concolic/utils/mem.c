#include "mem.h"

GPtrArray *mmio_ranges = NULL;
GPtrArray *ram_ranges = NULL;

GPtrArray *symbolize_at_pc_array = NULL;

bool range_contain_addr(GPtrArray *ranges, uint32_t addr) {
    for (guint i = 0; i < ranges->len; i++) {
        MemRange *r = g_ptr_array_index(ranges, i);
        if (addr >= r->start && addr < r->end) {
            return true; 
        }
    }
    return false;
}

bool array_contain_addr(GPtrArray *ranges, uint32_t addr) {
    assert(ranges && "uninitialzied!");
    for (guint i = 0; i < ranges->len; i++) {
        SymbolizeAtPcArray *r = g_ptr_array_index(ranges, i);
        if (addr == r->pc) {
            return true; 
        }
    }
    return false;
}
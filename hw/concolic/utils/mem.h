
#ifndef MMIO_MEM_H
#define MMIO_MEM_H
#include "qemu/osdep.h"


extern GPtrArray *mmio_ranges;
extern GPtrArray *ram_ranges;

extern GPtrArray* symbolize_at_pc_array;

typedef struct MemRange {
    uint32_t start;
    uint32_t end;   // end is exclusive: [start, end)
} MemRange;

typedef struct SymbolizeAtPcArray {
    uint32_t pc;
} SymbolizeAtPcArray;


bool range_contain_addr(GPtrArray *ranges, uint32_t addr);
bool array_contain_addr(GPtrArray *ranges, uint32_t addr);

#endif
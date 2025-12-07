#ifndef FUNCTION_HOOKS_H
#define FUNCTION_HOOKS_H

#define MAX_MSG_LEN 256
#include "qemu/osdep.h"
#include "target/arm/cpu.h"
#include "exec/cpu_ldst.h"
#include "qemu/log.h"
#include <ctype.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

static const char * const arm_reg_names[] =
    { "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
      "r8", "r9", "r10", "r11", "r12", "r13", "r14", "pc" };

extern GHashTable *func_ptr_htable;

void hook_init(void);
void uart_printf(CPUARMState *env);
void delay_hook(CPUARMState *env);


/* reg index */
int return_reg_index_by_name(const char* reg_name);

typedef void (*func_hook_t)(CPUARMState *env);

#endif
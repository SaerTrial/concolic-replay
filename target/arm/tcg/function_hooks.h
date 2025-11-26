#ifndef FUNCTION_HOOKS_H
#define FUNCTION_HOOKS_H

#define MAX_MSG_LEN 256
#include "qemu/osdep.h"
#include "target/arm/cpu.h"
#include "exec/cpu_ldst.h"
#include "qemu/log.h"


#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>


extern GHashTable *func_ptr_htable;

void hook_init(void);
void uart_printf(CPUARMState *env);
void delay_hook(CPUARMState *env);


typedef void (*func_hook_t)(CPUARMState *env);

#endif
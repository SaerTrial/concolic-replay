/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "hooks/arm/hook_backend.h"
#include "exec/cpu_ldst.h"
#include "qemu/log.h"

uint32_t hook_read_register(CPUARMState *env, unsigned index)
{
    assert(index < ARRAY_SIZE(env->regs));
    return env->regs[index];
}

uint8_t hook_read_memory8(CPUARMState *env, uint32_t addr)
{
    return cpu_ldub_data(env, addr);
}

void hook_log_call(const char *name, uint32_t count, const char *suffix)
{
    qemu_log_mask(LOG_CONCOLIC_REPLAY, "[%s_%d]%s", name, count, suffix);
}

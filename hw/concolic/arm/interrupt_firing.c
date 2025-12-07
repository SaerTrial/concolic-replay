
#include "interrupt_firing.h"

NVICState* nvic_intc_firing = NULL;
RoundRobinInterruptFiring* pRoundRobin = NULL;

static bool nvic_enabled_changed(void)
{
    uint8_t cur[NVIC_MAX_VECTORS] = {0};
    uint8_t new_array_len = 0;

    assert (nvic_intc_firing != NULL);
    // trick: count systick in, so start from 15
    // FIXME: may not be applicable to all cases
    for (int i = ARMV7M_EXCP_SYSTICK; i < NVIC_MAX_VECTORS; i++) {
        if (nvic_intc_firing->vectors[i].enabled){
            cur[new_array_len++] = i;
        }
    }

    if (memcmp(cur, pRoundRobin->enabled_snapshot, sizeof(cur)) != 0) {
        memcpy(pRoundRobin->enabled_snapshot, cur, sizeof(cur));
        pRoundRobin->array_len = new_array_len;

        qemu_log_mask(LOG_CONCOLIC_REPLAY,
                       "[%s] new irqs are enabled \n", __func__);

        for (int i = 0; i < new_array_len; i++) 
            qemu_log_mask(LOG_CONCOLIC_REPLAY,
                       "[%s] enabled_irq[%d]=%d \n", __func__, i, pRoundRobin->enabled_snapshot[i]);

        return true;
    }
    return false;
}

static uint8_t round_robin_next_irq(void)
{
    uint8_t next_irq = 0;
    if (pRoundRobin->array_len == 0) {
        return next_irq;
    }

    next_irq = pRoundRobin->enabled_snapshot[pRoundRobin->rr_index++];

    if (pRoundRobin->rr_index >= pRoundRobin->array_len) {
        pRoundRobin->rr_index = 0; 

        // wheneve a round ends, update the array if any change
        nvic_enabled_changed();
    }

    return next_irq;
}

void interrupt_firing(void) {
    // TODO: round robin, or fuzzed, or specified ...
  
    if (!pRoundRobin)  {
        pRoundRobin = g_malloc(sizeof(RoundRobinInterruptFiring));
        pRoundRobin->rr_index = 0;
        pRoundRobin->array_len = 0;
        memset(pRoundRobin->enabled_snapshot, 0, sizeof(pRoundRobin->enabled_snapshot));
        nvic_enabled_changed();
    }

    // TODO: in case of more firing strategies, implement here
    uint8_t next_irq = round_robin_next_irq();    

    //if (nvic_int_firing->vectors[ARMV7M_EXCP_SYSTICK].enabled){
    qemu_log_mask(LOG_CONCOLIC_REPLAY,
                       "[%s] firing irq %d \n", __func__, next_irq);
    armv7m_nvic_set_pending(nvic_intc_firing, next_irq, false);
    //}
}
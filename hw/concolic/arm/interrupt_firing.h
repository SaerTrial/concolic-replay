#ifndef INTERRUPT_FIRING_H
#define INTERRUPT_FIRING_H
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "net/net.h"
#include "hw/char/serial.h"
#include "qemu/cutils.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qnum.h"
#include "qapi/qmp/qlist.h"
#include "qapi/qmp/qnull.h"
#include "qapi/qmp/qstring.h"
#include "qapi/qmp/qjson.h"
#include "qemu/log.h"
#include "hw/intc/armv7m_nvic.h"
#include "target/arm/cpu.h"


void interrupt_firing(void);
extern NVICState* nvic_intc_firing;
extern bool interrupt_firing_enabled;
extern uint32_t firing_frequency;
extern uint8_t firing_mode;

typedef struct RoundRobinInterruptFiring {
    uint8_t array_len;   
    int rr_index;           // Round-robin pointer
    uint8_t enabled_snapshot[NVIC_MAX_VECTORS]; // For change detection
} RoundRobinInterruptFiring;


#endif
#include "function_hooks.h"

GHashTable *func_ptr_htable = NULL;



int return_reg_index_by_name(const char* reg_name) {
    int len = sizeof(arm_reg_names) / sizeof(arm_reg_names[0]);

    char* tmp_reg_name = g_malloc0(strlen(reg_name) + 1);
    strcpy(tmp_reg_name, reg_name);

    for (int i = 0; i < strlen(tmp_reg_name); i++)
        tmp_reg_name[i] = tolower(tmp_reg_name[i]); 

    for (int i = 0; i < len; i++) {
        if (!strcmp(tmp_reg_name, arm_reg_names[i])) {
            g_free(tmp_reg_name);
            return i;
        }
    }

    g_free(tmp_reg_name);
    return -1;
}



static uint32_t hook_cnt = 0;
void delay_hook(CPUARMState *env) {
    printf("[%s_%d]\n", __func__, hook_cnt);
    qemu_log_mask(LOG_CONCOLIC_REPLAY, "[%s_%d]\n", __func__, hook_cnt); 
    hook_cnt++;
}

static inline uint8_t mem_read8(CPUARMState *env, uint32_t addr) {
    return cpu_ldub_data(env, addr);
}

void uart_printf(CPUARMState *env) {
    printf("[%s_%d] ", __func__, hook_cnt);
    qemu_log_mask(LOG_CONCOLIC_REPLAY, "[%s_%d] ", __func__, hook_cnt); 
    hook_cnt++;

    uint32_t ptr = env->regs[0];     // R0: format string pointer
    assert(ptr != 0);

    // Load up to 256 bytes like Python code
    uint8_t msg[MAX_MSG_LEN];
    for (int i = 0; i < MAX_MSG_LEN; i++) {
        msg[i] = mem_read8(env, ptr + i);
    }

    // Trim at first null terminator
    int msg_len = 0;
    while (msg_len < MAX_MSG_LEN && msg[msg_len] != '\0') {
        msg_len++;
    }

    // collect arguments: R1, R2, R3 (reverse order like Python did)
    uint32_t args[3];
    int arg_count = 3;
    args[0] = env->regs[3];  // reversed order
    args[1] = env->regs[2];
    args[2] = env->regs[1];

    int prev_ind = 0;
    int cursor = 0;

    while (arg_count > 0) {
        // find next '%'
        int found = -1;
        for (int i = prev_ind; i < msg_len; i++) {
            if (msg[i] == '%') {
                found = i;
                break;
            }
        }

        if (found == -1)
            break;

        // print literal section before %
        fwrite(msg + prev_ind, 1, found - prev_ind, stdout);

        cursor = found + 1;

        // skip digits (width)
        while (cursor < msg_len && msg[cursor] >= '0' && msg[cursor] <= '9') {
            cursor++;
        }

        // skip 'l' characters
        while (cursor < msg_len && msg[cursor] == 'l') {
            cursor++;
        }

        uint8_t spec = msg[cursor];

        if (spec == 's') {
            // string arg
            uint32_t string_addr = args[arg_count - 1];
            arg_count--;

            // read until null
            char s[512];
            int si = 0;
            uint8_t c = mem_read8(env, string_addr);
            while (c != '\0' && si < 511) {
                s[si++] = (char)c;
                string_addr++;
                c = mem_read8(env, string_addr);
            }
            s[si] = '\0';
            fputs(s, stdout);

        } else if (spec == 'd') {
            uint32_t val = args[arg_count - 1];
            arg_count--;
            printf("%d", (int)val);

        } else if (spec == 'x' || spec == 'p') {
            uint32_t val = args[arg_count - 1];
            arg_count--;
            printf("%x", val);
        } else if (spec == 'c' ) {
            uint32_t val = args[arg_count - 1];
            arg_count--;
            printf("%c", val);
        }

        cursor++;
        prev_ind = cursor;
    }

    // print leftover tail
    if (prev_ind < msg_len) {
        fwrite(msg + prev_ind, 1, msg_len - prev_ind, stdout);
    }

    fflush(stdout);
}


void hook_init(void) {
    if (!func_ptr_htable) func_ptr_htable = g_hash_table_new(g_str_hash, g_str_equal);
    
    char* func_name;

    func_name = g_malloc(strlen("HAL_Delay") + 1);
    strcpy(func_name, "HAL_Delay");
    g_hash_table_insert(func_ptr_htable, (gpointer)func_name, (gpointer)delay_hook);

    // uart_printf
    func_name = g_malloc(strlen("uart_printf") + 1);
    strcpy(func_name, "uart_printf");
    g_hash_table_insert(func_ptr_htable, (gpointer)func_name, (gpointer)uart_printf);
}

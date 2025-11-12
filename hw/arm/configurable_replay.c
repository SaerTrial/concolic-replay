#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/arm/boot.h"
#include "hw/boards.h"
#include "qemu/error-report.h"
#include "exec/address-spaces.h"
#include "net/net.h"
#include "hw/char/serial.h"
#include "sysemu/qtest.h"
#include "sysemu/sysemu.h"
#include "qemu/cutils.h"
#include "hw/qdev-clock.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qnum.h"
#include "qapi/qmp/qlist.h"
#include "qapi/qmp/qnull.h"
#include "qapi/qmp/qstring.h"
#include "qapi/qmp/qjson.h"
#include "qemu/log.h"
#include "hw/arm/armv7m.h"
#define SymExpr void*
#include "RuntimeCommon.h"
#define SYSCLK_FRQ 40000000ULL

extern const char *replayConf;
extern const char *replayFile;
GHashTable *patched_func_htable = NULL;
GHashTable *exit_at_htable = NULL;

uint8_t *fuzz = NULL;
uint32_t fuzz_size = 0;
uint32_t fuzz_cursor = 0;
static bool input_already_given = false;

bool getFuzz(uint8_t *buf, uint32_t size);
static void loadFuzz(void);

void loadFuzz(void) {
        FILE *fp;
        
        fp = fopen(replayFile, "rb");
        if(!fp) {
                perror(replayFile);
                exit(1);
        }

        fseek(fp, 0L, SEEK_END);
        uint32_t _size = ftell(fp);
        fuzz_size = _size;
        fseek(fp, 0L, SEEK_SET); 

        if ( (fuzz = malloc(_size+1)) == NULL ) {
                exit(1);
        }

        if (fread(fuzz, _size, 1, fp) == 0) {
                printf("fread failed\n");
                exit(1);
        }

        qemu_log_mask(LOG_CONCOLIC_REPLAY,
                        "%s: read replay input file successfully, size:0x%x\n", __func__, (uint32_t)_size);

        fclose(fp);
}


/* get fuzzing inputs */
bool getFuzz(uint8_t *buf, uint32_t size) {

        if(!input_already_given){
                loadFuzz();
                input_already_given = true;
        }

        if(size && fuzz_cursor + size <= fuzz_size) {
                qemu_log_mask(LOG_CONCOLIC_REPLAY, "[NATIVE FUZZ] Returning %d fuzz bytes\n", size); 
                memcpy(buf, &fuzz[fuzz_cursor], size);
                fuzz_cursor += size;
                return true;
        }
        else {
                qemu_log_mask(LOG_CONCOLIC_REPLAY, "[NATIVE FUZZ] Running out of inputs \n"); 
                free(fuzz);
                _exit(0);
        }

        return false;
}

static QDict * load_configuration(const char * filename)
{
    int file = open(filename, O_RDONLY);
    off_t filesize = lseek(file, 0, SEEK_END);
    char * filedata = NULL;
    ssize_t err;
    QObject * obj;

    lseek(file, 0, SEEK_SET);

    filedata = g_malloc(filesize + 1);
    memset(filedata, 0, filesize + 1);

    if (!filedata)
    {
        fprintf(stderr, "%ld\n", filesize);
        fprintf(stderr, "Out of memory\n");
        exit(1);
    }

    err = read(file, filedata, filesize);

    if (err != filesize)
    {
        fprintf(stderr, "Reading configuration file failed\n");
        exit(1);
    }

    close(file);

    obj = qobject_from_json(filedata, NULL);
    if (!obj || qobject_type(obj) != QTYPE_QDICT)
    {
        fprintf(stderr, "Error parsing JSON configuration file\n");
        exit(1);
    }

    g_free(filedata);

    return qobject_to(QDict, obj);
}

uint32_t mmio_start, mmio_end;
GHashTable *mmio_visited;

static void load_ram(QDict * ram_dict) {
        Error *err = NULL;
        MemoryRegion *system_memory = get_system_memory();
        MemoryRegion *ram = g_new(MemoryRegion, 1);

        uint32_t ram_addr = strtol( 
                qstring_get_str(qobject_to(QString, qdict_get(ram_dict, "addr"))),
                NULL,
                0);
        
        uint32_t ram_size = strtol( 
                qstring_get_str(qobject_to(QString, qdict_get(ram_dict, "size"))),
                NULL,
                0);

        memory_region_init_ram(ram, NULL, qstring_get_str(qobject_to(QString, qdict_get(ram_dict, "name"))), 
                                ram_size, &err);
        memory_region_add_subregion(system_memory, ram_addr, ram);

        qemu_log_mask(LOG_CONCOLIC_REPLAY,
        "%s: name: %s ram: 0x%x size: 0x%x\n", 
                __func__,
                qstring_get_str(qobject_to(QString, qdict_get(ram_dict, "name"))), 
                ram_addr, 
                ram_size);
}

uint32_t flash_addr;
uint32_t flash_size;

static void load_flash(QDict * flash_dict) {
        MemoryRegion *system_memory = get_system_memory();        
        Error *err = NULL;

        flash_addr = strtol( 
                qstring_get_str(qobject_to(QString, qdict_get(flash_dict, "addr"))),
                NULL,
                0);
        
        flash_size = strtol( 
                qstring_get_str(qobject_to(QString, qdict_get(flash_dict, "size"))),
                NULL,
                0);
        
        MemoryRegion *flash =  g_new(MemoryRegion, 1);

        memory_region_init_rom(flash, NULL, "flash",
                                flash_size, &err);

        memory_region_add_subregion(system_memory, flash_addr, flash);

        if (qdict_haskey(flash_dict, "alias_at")) {
                MemoryRegion *flash_alias =  g_new(MemoryRegion, 1);

                uint32_t alias_addr = strtol( 
                        qstring_get_str(qobject_to(QString, qdict_get(flash_dict, "alias_at"))),
                        NULL,
                        0);

                memory_region_init_alias(flash_alias, NULL,
                        "flash.alias", flash, 0,
                        flash_size);
        
                memory_region_add_subregion(system_memory, alias_addr, flash_alias);
        }
        qemu_log_mask(LOG_CONCOLIC_REPLAY,
        "%s: flash: 0x%x size: 0x%x \n", __func__, flash_addr, flash_size);  
}

static void configure_mmio(QDict * mmio)
{

        /*
        "mmio":{"mmio_start":"0x40000000", "mmio_end": "0x60000000"}
        */
        mmio_start = strtol( 
                qstring_get_str(qobject_to(QString, qdict_get(mmio, "mmio_start"))),
                NULL,
                0);

        mmio_end = strtol( 
                qstring_get_str(qobject_to(QString, qdict_get(mmio, "mmio_end"))),
                NULL,
                0);
        
        qemu_log_mask(LOG_CONCOLIC_REPLAY,
        "%s: mmio_start: 0x%x mmio_end: 0x%x\n", __func__, mmio_start, mmio_end);  

}

static void create_patch(QDict * patch_entry){
        if (!patched_func_htable) patched_func_htable = g_hash_table_new(NULL, NULL);

        uint32_t addr = strtol(
                        qstring_get_str(qobject_to(QString, qdict_get(patch_entry, "addr"))),
                        NULL,
                        0);
        /*
        "patch": [{"addr": "0x800xxxx", "name": "func1"},
                {"addr": "0x800xxxx", "name": "func2"}]
        */
        void* element = NULL;
        if(! (element = g_hash_table_lookup(patched_func_htable, (gpointer)((uint64_t)addr)))) {
                if (qdict_haskey(patch_entry, "name"))
                element = (void*)qstring_get_str(qobject_to(QString, qdict_get(patch_entry, "name")));
                g_hash_table_insert(patched_func_htable, (gpointer)((uint64_t)addr), (gpointer)element);
        }
}

static void create_exit_at(QDict * exit_at_entry) {
        if (!exit_at_htable) exit_at_htable = g_hash_table_new(NULL, NULL);
        
        /*      
         "exit_at": [
         {"addr":"0x08000b20", "name":"Error_Handler"},
         {"addr":"0x080021c8", "name":"HardFault_Handler"}]
        */

        uint32_t addr = strtol(
                        qstring_get_str(qobject_to(QString, qdict_get(exit_at_entry, "addr"))),
                        NULL,
                        0);
        
        void* element = NULL;
        if(! (element = g_hash_table_lookup(exit_at_htable, (gpointer)((uint64_t)addr)))) {
                if (qdict_haskey(exit_at_entry, "name"))
                        element = (void*)qstring_get_str(qobject_to(QString, qdict_get(exit_at_entry, "name")));
                g_hash_table_insert(exit_at_htable, (gpointer)((uint64_t)addr), (gpointer)element);
        }

}


static void print_configuration(void){
    /* patch functions */
    GHashTableIter iter;
    uint32_t addr_iter;
    const char* func_name = NULL;
    g_hash_table_iter_init(&iter, patched_func_htable);
    uint32_t cnt = 0;

    qemu_log_mask(LOG_CONCOLIC_REPLAY,
        "%s: --------------------------patch function----------------------------\n", __func__);

    while (g_hash_table_iter_next(&iter, (gpointer)&addr_iter, (gpointer)&func_name)) {
        qemu_log_mask(LOG_CONCOLIC_REPLAY,
        "%s: [%d] addr: 0x%x (patched func name): %s \n", __func__, cnt, addr_iter, func_name? func_name : "unknown");
        cnt++;
    } 

    cnt = 0;
    qemu_log_mask(LOG_CONCOLIC_REPLAY,
        "%s: --------------------------exit_at function----------------------------\n", __func__);
        g_hash_table_iter_init(&iter, exit_at_htable);
    while (g_hash_table_iter_next(&iter, (gpointer)&addr_iter, (gpointer)&func_name)) {
        qemu_log_mask(LOG_CONCOLIC_REPLAY,
        "%s: [%d] exit_at addr: 0x%x (func_name): %s \n", __func__, cnt, addr_iter, func_name? func_name : "unknown");
        cnt++;
    } 

    // TODO: test if there is the same entry between the patch table and exit_at one.
    // If so, then panic

}

static void configurable_replay_init(MachineState *machine)
{
        Clock *sysclk = NULL;
        QDict * conf = NULL;
        DeviceState* armv7m;
        MemoryRegion *system_memory = get_system_memory();
        
        if (!replayConf) exit(-1);
        conf = load_configuration(replayConf);

        const QDictEntry * entry = qdict_first(conf);
        while (entry) {
                if (!strcmp(entry->key, "ram")) {
                        QList * rams = qobject_to(QList, entry->value);
                        QListEntry *ram;
                        QLIST_FOREACH_ENTRY(rams, ram) {
                                load_ram(qobject_to(QDict, qlist_entry_obj(ram)));
                        }
                }else if (!strcmp(entry->key, "flash")) {
                        load_flash(qobject_to(QDict, entry->value));
                }else if (!strcmp(entry->key, "mmio")) {
                        configure_mmio(qobject_to(QDict, entry->value));
                }else if (!strcmp(entry->key, "patch")) {
                        QList * patches = qobject_to(QList, entry->value);
                        QListEntry *patch;
                        QLIST_FOREACH_ENTRY(patches, patch) {
                                create_patch(qobject_to(QDict, qlist_entry_obj(patch)));
                        }
                }else if (!strcmp(entry->key, "exit_at")) {
                        QList * exit_list = qobject_to(QList, entry->value);
                        QListEntry *exit_entry;
                        QLIST_FOREACH_ENTRY(exit_list, exit_entry) {
                                create_exit_at(qobject_to(QDict, qlist_entry_obj(exit_entry)));
                        }
                }
                entry = qdict_next(conf, entry);
        }

        print_configuration();

        assert(replayFile && "specify an input file");

        /* This clock doesn't need migration because it is fixed-frequency */
        sysclk = clock_new(OBJECT(machine), "SYSCLK");
        clock_set_hz(sysclk, SYSCLK_FRQ);

        /* Initialize a global MMIO-access table and the symbolic backend */
        mmio_visited = g_hash_table_new(NULL, NULL);
        _sym_initialize();

        armv7m = qdev_new(TYPE_ARMV7M);
        qdev_prop_set_uint32(armv7m, "num-irq", 156);
        qdev_prop_set_uint8(armv7m, "num-prio-bits", 4);
        qdev_prop_set_string(armv7m, "cpu-type", ARM_CPU_TYPE_NAME("cortex-m7"));
        qdev_prop_set_bit(armv7m, "enable-bitband", true);
        qdev_connect_clock_in(armv7m, "cpuclk", sysclk);

        object_property_set_link(OBJECT(armv7m), "memory",
                                OBJECT(system_memory), &error_abort);

        if (!sysbus_realize_and_unref(SYS_BUS_DEVICE(armv7m), NULL)) {
                return;
        }

        assert (flash_size != 0);
        armv7m_load_kernel(ARM_CPU(first_cpu),
                        machine->kernel_filename,
                        0, flash_size);
}

static void configurable_replay_machine_init(MachineClass *mc)
{
    static const char * const valid_cpu_types[] = {
        ARM_CPU_TYPE_NAME("cortex-m7"),
        NULL
    };

    mc->desc = "concolic execution for replay (armv7m)";
    mc->init = configurable_replay_init;
    mc->valid_cpu_types = valid_cpu_types;
}

DEFINE_MACHINE("concolic_replay", configurable_replay_machine_init)

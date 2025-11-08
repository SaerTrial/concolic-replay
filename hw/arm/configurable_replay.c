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
uint32_t g_concolic = 0;

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

        printf("name: %s ram: 0x%x size: 0x%x\n", 
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

        printf("flash: 0x%x size: 0x%x \n", flash_addr, flash_size);  
}

static void configure_mmio(QDict * mmio)
{
        mmio_start = strtol( 
                qstring_get_str(qobject_to(QString, qdict_get(mmio, "mmio_start"))),
                NULL,
                0);

        mmio_end = strtol( 
                qstring_get_str(qobject_to(QString, qdict_get(mmio, "mmio_end"))),
                NULL,
                0);
        
        printf("mmio_start: 0x%x mmio_end: 0x%x\n", mmio_start, mmio_end);  
     
}

static void configurable_replay_init(MachineState *machine)
{
        Clock *sysclk = NULL;//, *refclk = NULL;
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
                }else if (!strcmp(entry->key, "concolic")) {
                        g_concolic = qnum_get_int(qobject_to(QNum, entry->value));
                        printf("concolic: %s\n", g_concolic? "on" : "off");
                }
                entry = qdict_next(conf, entry);
        }
        
        /* This clock doesn't need migration because it is fixed-frequency */
        sysclk = clock_new(OBJECT(machine), "SYSCLK");
        clock_set_hz(sysclk, SYSCLK_FRQ);
        // refclk = clock_new(OBJECT(machine), "REFCLK");
        // clock_set_hz(refclk, SYSCLK_FRQ/8);
        // refclk = qdev_init_clock_in(OBJECT(machine), "refclk", NULL, NULL, 0);

        if (g_concolic) {
                mmio_visited = g_hash_table_new(NULL, NULL);
                /* Initialize the symbolic backend */
                _sym_initialize();
        }

        //     clock_set_mul_div(refclk, 8, 1);
        //     clock_set_source(refclk, sysclk);
        armv7m = qdev_new(TYPE_ARMV7M);
        qdev_prop_set_uint32(armv7m, "num-irq", 156);
        qdev_prop_set_uint8(armv7m, "num-prio-bits", 4);
        qdev_prop_set_string(armv7m, "cpu-type", ARM_CPU_TYPE_NAME("cortex-m7"));
        qdev_prop_set_bit(armv7m, "enable-bitband", true);
        qdev_connect_clock_in(armv7m, "cpuclk", sysclk);
        // qdev_connect_clock_in(armv7m, "refclk", refclk);

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

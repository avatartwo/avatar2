/*
 * Avatar2 configurable machine for dynamic creation of emulated boards
 *
 * Copyright (C) 2017-2022 Eurecom
 * Written by Dario Nisi, Marius Muench, Paul Olivier & Jonas Zaddach
 *
 * Updates for MIPS, i386, and x86_64 written by Andrew Fasano for PANDA
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * This code is derived from versatilepb.c:
 *   ARM Versatile Platform/Application Baseboard System emulation.
 *   Copyright (c) 2005-2007 CodeSourcery.
 *   Written by Paul Brook
 */

//general imports
#include "qemu/osdep.h"
#include "sysemu/sysemu.h"
#include "exec/address-spaces.h"
#include "hw/hw.h"
#include "hw/irq.h"
#include "hw/sysbus.h"
#include "hw/boards.h"
#include "hw/qdev-properties.h"

//plattform specific imports
#if defined(TARGET_ARM)
#include "target/arm/cpu.h"
#include "hw/avatar/arm_helper.h"

#if !defined(TARGET_AARCH64)
#include "hw/arm/armv7m.h"
#endif
typedef ARMCPU THISCPU;

#elif defined(TARGET_I386) || defined(TARGET_X86_64)
#include "hw/i386/pc.h"
#include "target/i386/cpu.h"
typedef  X86CPU THISCPU;

#elif defined(TARGET_MIPS)
#include "hw/mips/mips.h"
#include "hw/mips/cpudevs.h"
#include "target/mips/cpu.h"
typedef  MIPSCPU THISCPU;

#elif defined(TARGET_PPC)
#include "hw/ppc/ppc.h"
#include "target/ppc/cpu.h"
typedef PowerPCCPU THISCPU;
#endif



//qapi imports
#include "qapi/error.h"
#include "qapi/qmp/qjson.h"
#include "qapi/qmp/qobject.h"
#include "qapi/qmp/qnum.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qlist.h"



#define QDICT_ASSERT_KEY_TYPE(_dict, _key, _type) \
    g_assert(qdict_haskey(_dict, _key) && qobject_type(qdict_get(_dict, _key)) == _type)

#define RAM_RESIZEABLE (1 << 2)
/* Board init.  */

static QDict * load_configuration(const char * filename)
{
    int file = open(filename, O_RDONLY);
    off_t filesize = lseek(file, 0, SEEK_END);
    char * filedata = NULL;
    ssize_t err;
    Error * qerr = NULL;
    QObject * obj;
    QDict * obj_dict;

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

    obj = qobject_from_json(filedata, &qerr);
    if (!obj || qobject_type(obj) != QTYPE_QDICT)
    {
        fprintf(stderr, "Error parsing JSON configuration file\n");
        exit(1);
    }

    obj_dict = qobject_to(QDict, obj);
    if (!obj_dict) {
        qobject_unref(obj);
        fprintf(stderr, "Invalid JSON object given");
        exit(1);
    }

    g_free(filedata);

    return obj_dict;
}

static QDict *peripherals;

static void set_properties(DeviceState *dev, QList *properties)
{
    QListEntry *entry;
    QLIST_FOREACH_ENTRY(properties, entry)
    {
        QDict *property;
        const char *name;
        const char *type;

        g_assert(qobject_type(entry->value) == QTYPE_QDICT);

        property = qobject_to(QDict, entry->value);
        QDICT_ASSERT_KEY_TYPE(property, "type", QTYPE_QSTRING);
        QDICT_ASSERT_KEY_TYPE(property, "name", QTYPE_QSTRING);

        name = qdict_get_str(property, "name");
        type = qdict_get_str(property, "type");

        if(!strcmp(type, "serial"))
        {
            QDICT_ASSERT_KEY_TYPE(property, "value", QTYPE_QNUM);
            const int value = qdict_get_int(property, "value");
            qdev_prop_set_chr(dev, name, serial_hd(value));
        }
        else if(!strcmp(type, "string"))
        {
            QDICT_ASSERT_KEY_TYPE(property, "value", QTYPE_QSTRING);
            const char *value = qdict_get_str(property, "value");
            qdev_prop_set_string(dev, name, value);
        }
        else if(!strcmp(type, "int32"))
        {
            QDICT_ASSERT_KEY_TYPE(property, "value", QTYPE_QNUM);
            const int value = qdict_get_int(property, "value");
            qdev_prop_set_int32(dev, name, value);
        }
        else if(!strcmp(type, "uint32"))
        {
            QDICT_ASSERT_KEY_TYPE(property, "value", QTYPE_QNUM);
            const int value = qdict_get_int(property, "value");
            qdev_prop_set_uint32(dev, name, value);
        }
        else if(!strcmp(type, "int64"))
        {
            QDICT_ASSERT_KEY_TYPE(property, "value", QTYPE_QNUM);
            const int64_t value = qdict_get_int(property, "value");
            qdev_prop_set_uint64(dev, name, value);
        }
        else if(!strcmp(type, "uint64"))
        {
            QDICT_ASSERT_KEY_TYPE(property, "value", QTYPE_QNUM);
            const uint64_t value = qdict_get_int(property, "value");
            qdev_prop_set_uint64(dev, name, value);
        }
        else if(!strcmp(type, "device"))
        {
            QDICT_ASSERT_KEY_TYPE(property, "value", QTYPE_QSTRING);
            const char *value = qdict_get_str(property, "value");
            QObject *pr = qdict_get(peripherals, value);
            qdev_prop_set_chr(dev, name, (void *) pr);
        }
    }
}

static void dummy_interrupt(void *opaque, int irq, int level)
{}

static SysBusDevice *make_configurable_device(const char *qemu_name,
                                              uint64_t address,
                                              QList *properties)
{
    DeviceState *dev;
    BusState* sysbus;
    SysBusDevice *s;
    qemu_irq irq;

    sysbus = sysbus_get_default();
    /* replace the result of: dev = qdev_create(NULL, qemu_name); */

    dev = qdev_new(qemu_name);
    
    /* this is a sysbus device. 
     * QEMU no longer attaches devices to this automatically; 
     * we will need to give it a helping hand. */
    //qdev_set_parent_bus(dev, sysbus);
    //dev->realized = true;
    if(properties) set_properties(dev, properties);

    qdev_realize_and_unref(dev, sysbus, NULL);

    s = SYS_BUS_DEVICE(dev);
    sysbus_mmio_map(s, 0, address);
    irq = qemu_allocate_irq(dummy_interrupt, dev, 1);
    sysbus_connect_irq(s, 0, irq);

    return s;
}

static off_t get_file_size(const char * path)
{
    struct stat stats;

    if (stat(path, &stats))
    {
        printf("ERROR: Getting file size for file %s\n", path);
        return 0;
    }

    return stats.st_size;
}

static int is_absolute_path(const char * filename)
{
    return filename[0] == '/';
}

static int get_dirname_len(const char * filename)
{
    int i;

    for (i = strlen(filename) - 1; i >= 0; i--)
    {
        //FIXME: This is only Linux-compatible ...
        if (filename[i] == '/')
        {
            return i + 1;
        }
    }

    return 0;
}

static void init_memory_area(QDict *mapping, const char *kernel_filename)
{
    uint64_t size;
    uint64_t data_size;
    char * data = NULL;
    const char * name;
    MemoryRegion * ram;
    uint64_t address, alias_address;
    int is_rom;
    MemoryRegion *sysmem = get_system_memory();

    QDICT_ASSERT_KEY_TYPE(mapping, "name", QTYPE_QSTRING);
    QDICT_ASSERT_KEY_TYPE(mapping, "size", QTYPE_QNUM);
    g_assert((qdict_get_int(mapping, "size") & ((1 << 12) - 1)) == 0);

    if(qdict_haskey(mapping, "is_rom")) {
        QDICT_ASSERT_KEY_TYPE(mapping, "is_rom", QTYPE_QBOOL);
    }

    name = qdict_get_str(mapping, "name");
    is_rom = qdict_haskey(mapping, "is_rom")
          && qdict_get_bool(mapping, "is_rom");
    size = qdict_get_int(mapping, "size");

    ram =  g_new(MemoryRegion, 1);
    g_assert(ram);

    if(!is_rom)
    {
        memory_region_init_ram(ram, NULL, name, size, &error_fatal);
    } else {
        memory_region_init_rom(ram, NULL, name, size, &error_fatal);
    }

    QDICT_ASSERT_KEY_TYPE(mapping, "address", QTYPE_QNUM);
    address = qdict_get_int(mapping, "address");

    printf("Configurable: Adding memory region %s (size: 0x%"
           PRIx64 ") at address 0x%" PRIx64 "\n", name, size, address);
    memory_region_add_subregion(sysmem, address, ram);

    if(qdict_haskey(mapping, "alias_at")) {
        QDICT_ASSERT_KEY_TYPE(mapping, "alias_at", QTYPE_QNUM);
        alias_address = qdict_get_int(mapping, "alias_at");

        printf("Configurable: Adding alias to region %s at address 0x%" PRIx64 "\n", name, alias_address);
        MemoryRegion *alias;
        alias =  g_new(MemoryRegion, 1);
        memory_region_init_alias(alias, NULL, name, ram, 0, size);
        memory_region_add_subregion(sysmem, alias_address, alias);
    }

    if (qdict_haskey(mapping, "file"))
    {
        int file;
        const char * filename;
        int dirname_len = get_dirname_len(kernel_filename);
        ssize_t err;
        uint64_t file_offset = 0;

        g_assert(qobject_type(qdict_get(mapping, "file")) == QTYPE_QSTRING);
        filename = qdict_get_str(mapping, "file");

        if (!is_absolute_path(filename))
        {
            char * relative_filename = g_malloc0(dirname_len +
                                                 strlen(filename) + 1);
            g_assert(relative_filename);
            strncpy(relative_filename, kernel_filename, dirname_len);
            strcat(relative_filename, filename);

            file = open(relative_filename, O_RDONLY | O_BINARY);
            data_size = get_file_size(relative_filename);
            g_free(relative_filename);
        }
        else
        {
            file = open(filename, O_RDONLY | O_BINARY);
            data_size = get_file_size(filename);
        }

        if (qdict_haskey(mapping, "file_offset")) {
          off_t sbytes;
          g_assert(qobject_type(qdict_get(mapping, "file_offset")) == QTYPE_QNUM);
          file_offset = qdict_get_int(mapping, "file_offset");
          sbytes = lseek(file,file_offset,SEEK_SET);
          g_assert(sbytes > 0);
          data_size -= sbytes;

        }

        if (qdict_haskey(mapping,"file_bytes")) {
          ssize_t file_bytes;
          g_assert(qobject_type(qdict_get(mapping, "file_bytes")) == QTYPE_QNUM);
          file_bytes = qdict_get_int(mapping, "file_bytes");
          data_size = file_bytes;
          printf("File bytes: 0x%lx\n",data_size);

        }

        printf("Configurable: Inserting 0x%"
               PRIx64 " bytes of data in memory region %s\n", data_size, name);
        //Size of data to put into a RAM region needs to fit in the RAM region
        g_assert(data_size <= size);

        data = g_malloc(data_size);
        g_assert(data);

        err = read(file, data, data_size);
        g_assert(err == data_size);

        close(file);

        //And copy the data to the memory, if it is initialized
        printf("Configurable: Copying 0x%" PRIx64
               " byte of data from file %s beginning at offset 0x%" PRIx64
               " to address 0x%" PRIx64
               "\n", data_size, filename, file_offset,address);
        address_space_write_rom(&address_space_memory, address,
                                    MEMTXATTRS_UNSPECIFIED,
                                    (uint8_t *) data, data_size);
        g_free(data);
    }

}

static void init_peripheral(QDict *device)
{
    const char * qemu_name;
    const char * bus;
    const char * name;
    uint64_t address;

    QDICT_ASSERT_KEY_TYPE(device, "address", QTYPE_QNUM);
    QDICT_ASSERT_KEY_TYPE(device, "qemu_name", QTYPE_QSTRING);
    QDICT_ASSERT_KEY_TYPE(device, "bus", QTYPE_QSTRING);
    QDICT_ASSERT_KEY_TYPE(device, "name", QTYPE_QSTRING);

    bus = qdict_get_str(device, "bus");
    qemu_name = qdict_get_str(device, "qemu_name");
    address = qdict_get_int(device, "address");
    name = qdict_get_str(device, "name");

    printf("Configurable: Adding peripheral[%s] region %s at address 0x%" PRIx64 "\n", 
            qemu_name, name, address);
    if (strcmp(bus, "sysbus") == 0)
    {
        SysBusDevice *sb;
        QList *properties = NULL;

        if(qdict_haskey(device, "properties") &&
           qobject_type(qdict_get(device, "properties")) == QTYPE_QLIST)
        {
            properties = qobject_to(QList, qdict_get(device, "properties"));
        }

        sb = make_configurable_device(qemu_name, address, properties);
        qdict_put_obj(peripherals, name, (QObject *)sb);
    }
    else
    {
        g_assert(0); //Right now only sysbus devices are supported ...
    }
}



static void set_entry_point(QDict *conf, THISCPU *cpuu)
{
    const char *entry_field = "entry_address";
    uint32_t entry;


    if(!qdict_haskey(conf, entry_field))
        return;

    QDICT_ASSERT_KEY_TYPE(conf, entry_field, QTYPE_QNUM);
    entry = qdict_get_int(conf, entry_field);

#ifdef TARGET_ARM
    cpuu->env.regs[15] = entry & (~1);
    cpuu->env.thumb = (entry & 1) == 1 ? 1 : 0;

#elif defined(TARGET_I386)
    cpuu->env.eip = entry;

#elif defined(TARGET_MIPS)
    cpuu->env.active_tc.PC = entry;

#elif defined(TARGET_PPC)
    //Not implemented yet
    printf("Not yet implemented- can't start execution at 0x%x\n", entry);
#endif


}

static THISCPU *create_cpu(MachineState * ms, QDict *conf)
{
    const char *cpu_type;
    THISCPU *cpuu;
    CPUState *env;

//#if defined(TARGET_ARM) || define(TARGET_AARCH64) || defined(TARGET_I386) || defined(TARGET_MIPS)
#if defined(TARGET_ARM) || defined(TARGET_I386) || defined(TARGET_MIPS)
    ObjectClass *cpu_oc;
    Object *cpuobj;
#endif  /* TARGET_ARM || TARGET_I386 || TARGET_MIPS */

#if defined(TARGET_ARM) && !defined(TARGET_AARCH64)
    DeviceState *dstate; //generic device if CPU can be initiliazed via qdev-API
    BusState* sysbus = sysbus_get_default();
    int num_irq = 64;

#elif defined(TARGET_I386)
    //

#elif defined(TARGET_MIPS)
    Error *err = NULL;
#endif  /* TARGET_ARM */


    cpu_type = ms->cpu_type;

    if (qdict_haskey(conf, "cpu_model")) {
        cpu_type = qdict_get_str(conf, "cpu_model");
        g_assert(cpu_type);
    }


#if defined(TARGET_ARM)

#if !defined(TARGET_AARCH64)
    //create armv7m cpus together with nvic
    if (!strcmp(cpu_type, "cortex-m3")) {

        if (qdict_haskey(conf, "num_irq")) {
            num_irq = qdict_get_int(conf, "num_irq");
            g_assert(num_irq);
        } 

        dstate = qdev_new("armv7m");
        qdev_prop_set_uint32(dstate, "num-irq", num_irq);
        qdev_prop_set_string(dstate, "cpu-type", ARM_CPU_TYPE_NAME("cortex-m3"));
        object_property_set_link(OBJECT(dstate), "memory", 
        OBJECT(get_system_memory()), &error_abort);
        qdev_realize_and_unref(dstate, sysbus, NULL);

        cpuu = ARM_CPU(first_cpu);

    } else {
#endif  /* ! TARGET_AARCH64 */
        cpu_oc = cpu_class_by_name(TYPE_ARM_CPU, cpu_type);
        if (!cpu_oc) {
            fprintf(stderr, "Unable to find CPU definition\n");
            exit(1);
        }

        cpuobj = object_new(object_class_get_name(cpu_oc));

        object_property_set_bool(cpuobj, "realized", true, &error_fatal);
        cpuu = ARM_CPU(cpuobj);

#if !defined(TARGET_AARCH64)
    }
#endif  /* ! TARGET_AARCH64 */

#elif defined(TARGET_I386)
    cpu_oc = cpu_class_by_name(TYPE_X86_CPU, cpu_type);
    if (!cpu_oc) {
        fprintf(stderr, "Unable to find CPU definition\n");
        exit(1);
    }

    cpuobj = object_new(object_class_get_name(cpu_oc));
    cpuu = X86_CPU(cpuobj);

    if (cpuu->apic_state) {
            device_legacy_reset(cpuu->apic_state);
    }

#elif defined(TARGET_MIPS)
    cpu_oc = cpu_class_by_name(TYPE_MIPS_CPU, cpu_type);
    if (!cpu_oc) {
        fprintf(stderr, "Unable to find CPU definition\n");
        exit(1);
    }

    cpuobj = object_new(object_class_get_name(cpu_oc));
    cpuu = MIPS_CPU(cpuobj);

    if (!qdev_realize(DEVICE(cpuu), NULL, &err)) {
        error_report_err(err);
        object_unref(OBJECT(cpuu));
        exit(EXIT_FAILURE);
    }

#elif defined(TARGET_PPC)
    cpuu = cpu_ppc_init(cpu_type);
#endif


    env = (CPUState *) &(cpuu->env);
    if (!env) {
        fprintf(stderr, "Unable to find CPU definition\n");
        exit(1);
    }


#if defined(TARGET_ARM)

#if defined(TARGET_AARCH64)
    set_feature(&cpuu->env, ARM_FEATURE_AARCH64);
    set_feature(&cpuu->env, ARM_FEATURE_CONFIGURABLE);
#else
    avatar_add_banked_registers(cpuu);
    set_feature(&cpuu->env, ARM_FEATURE_CONFIGURABLE);
#endif  /* TARGET_AARCH64 */

#elif defined(TARGET_I386)
    // Ensures CS register is set correctly on x86/x86_64 CPU reset. See target/i386/cpu.c:3063
    int mode =
#if defined(TARGET_X86_64)
          64;
#else
          32;
#endif  /* TARGET_X86_64 */
    set_x86_configurable_machine(mode); // This sets the CPU to be in 32 or 64 bit mode

#elif defined(TARGET_MIPS)
    //
#endif  /* TARGET_ARM */

    assert(cpuu != NULL);
    return cpuu;
}


static void board_init(MachineState * ms)
{
    THISCPU *cpuu;

    const char *kernel_filename = ms->kernel_filename;
    QDict * conf = NULL;

    //Load configuration file
    if (kernel_filename)
    {
        conf = load_configuration(kernel_filename);
    }
    else
    {
        conf = qdict_new();
    }

    cpuu = create_cpu(ms, conf);
    set_entry_point(conf, cpuu);

    if (qdict_haskey(conf, "memory_mapping"))
    {
        peripherals = qdict_new();
        QListEntry * entry;
        QList * memories = qobject_to(QList, qdict_get(conf, "memory_mapping"));
        g_assert(memories);

        QLIST_FOREACH_ENTRY(memories, entry)
        {
            g_assert(qobject_type(entry->value) == QTYPE_QDICT);
            QDict *mapping = qobject_to(QDict, entry->value);

            if((qdict_haskey(mapping, "qemu_name") &&
                qobject_type(qdict_get(mapping, "qemu_name")) == QTYPE_QSTRING))
            {
                init_peripheral(mapping);
                continue;
            } else {
                init_memory_area(mapping, kernel_filename);
            }

        }
    }
}

static void configurable_machine_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->desc = "Machine that can be configured to be whatever you want";
    mc->init = board_init;
    mc->block_default_type = IF_SCSI;

#ifdef TARGET_ARM
    mc->default_cpu_type = "arm926";
#elif defined(TARGET_AARCH64)
    mc->default_cpu_type = "cortex-a57";
#elif defined(TARGET_I386)
    mc->default_cpu_type = "qemu32";
#elif defined(TARGET_MIPS)
    mc->default_cpu_type = "24Kf";
    //mc->default_cpu_type = "mips32r6-generic";
#elif defined(TARGET_PPC)
    mc->default_cpu_type = "e500v2_v30";
#endif
}

static const TypeInfo configurable_machine_type = {
    .name       =  MACHINE_TYPE_NAME("configurable"),
    .parent     = TYPE_MACHINE,
    .class_init = configurable_machine_class_init,
};

static void configurable_machine_init(void)
{
    type_register_static(&configurable_machine_type);
}

type_init(configurable_machine_init);

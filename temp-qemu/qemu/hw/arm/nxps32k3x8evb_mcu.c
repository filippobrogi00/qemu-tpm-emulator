#include "qemu/osdep.h"
#include "hw/qdev-properties.h"
#include "qapi/error.h"
#include "hw/arm/boot.h"
#include "hw/sysbus.h"
#include "hw/qdev-clock.h"
#include "hw/misc/unimp.h"
#include "qemu/log.h"

// this include the TPM
#include "tpm/tpm2_device.h"



#include "hw/arm/nxps32k3x8evb_mcu.h"
#include "hw/arm/nxps32k3x8evb.h"
#include "qom/object.h"

#include <stdio.h>

// TODO: CHANGE THIS!
#define TPM_BASE_ADDRESS (0xF0000000UL)
#define TPM_SIZE (4 * 1024)
#define NXPS32K3X8EVB_TPM_BASE_ADDRESS TPM_BASE_ADDRESS
#define NXPS32K3X8EVB_TPM_SIZE TPM_SIZE

/* poi vediamo */


// This function has the goal of initialize a single instance of the device class
static void nxps32k3x8evb_mcu_init(Object *obj)
{
    NXPS32K3X8EVB_MCUState *s = NXPS32K3X8EVB_MCU(obj);

    memory_region_init(&s->container, obj, "nxps32k3x8evb-container", UINT64_MAX);

    object_initialize_child(OBJECT(s), "armv7m", &s->cpu, TYPE_ARMV7M);
    qdev_prop_set_string(DEVICE(&s->cpu), "cpu-type", ARM_CPU_TYPE_NAME("cortex-m7"));
    qdev_prop_set_uint32(DEVICE(&s->cpu), "num-irq", NXPS32K3X8_IRQ_NUM); // Random number

    s->sysclk = qdev_init_clock_in(DEVICE(s), "sysclk", NULL, NULL, 0);
}

// Defining realize function
// Realizing make the device usable within the simulation
static void nxps32k3x8evb_mcu_realize(DeviceState *dev_mcu, Error **errp)
{
    Error *err = NULL;
    NXPS32K3X8EVB_MCUState *s = NXPS32K3X8EVB_MCU(dev_mcu);

    // Initialize system clock
    clock_set_hz(s->sysclk, NXPS32K3X8_STD_CLK);
    qdev_connect_clock_in(DEVICE(&s->cpu), "cpuclk", s->sysclk);

    // ITCM
    memory_region_init(&s->itcm, OBJECT(s), "nxps32k3x8evb.itcm", ITCM_SIZE);
    for (int i = 0; i < ITCM_NUM; i++)
    {
        MemoryRegion *itcm_block = g_new0(MemoryRegion, 1);
        memory_region_init_ram(itcm_block, OBJECT(s), g_strdup_printf("nxps32k3x8evb.itcm%d", i), ITCM_BLOCK_SIZE, &err);
        if (err)
        {
            error_propagate(errp, err);
            return;
        }
        memory_region_add_subregion(&s->itcm, i * ITCM_BLOCK_SIZE, itcm_block);
    }
    memory_region_add_subregion(&s->container, ITCM_BASE_ADDRESS, &s->itcm);

    // PFLASH
    memory_region_init(&s->pflash, OBJECT(s), "nxps32k3x8evb.pflash", PFLASH_SIZE);
    for (int i = 0; i < PFLASH_NUM; i++)
    {
        MemoryRegion *pflash_block = g_new0(MemoryRegion, 1);
        memory_region_init_rom(pflash_block, OBJECT(s), g_strdup_printf("nxps32k3x8evb.pflash%d", i), PFLASH_BLOCK_SIZE, &err);
        if (err)
        {
            error_propagate(errp, err);
            return;
        }
        memory_region_add_subregion(&s->pflash, i * PFLASH_BASE_ADDRESS, pflash_block);
    }
    memory_region_add_subregion(&s->container, PFLASH_BASE_ADDRESS, &s->pflash);

    // SRAM
    memory_region_init(&s->sram, OBJECT(s), "nxps32k3x8evb.sram", SRAM_SIZE);
    for (int i = 0; i < SRAM_NUM; i++)
    {
        MemoryRegion *sram_block = g_new(MemoryRegion, 1);
        memory_region_init_ram(sram_block, OBJECT(s), g_strdup_printf("nxps32k3x8evb.sram%d", i), SRAM_BLOCK_SIZE, &err);
        if (err)
        {
            error_propagate(errp, err);
            return;
        }
        memory_region_add_subregion(&s->sram, i * SRAM_BLOCK_SIZE, sram_block);
    }
    memory_region_add_subregion(&s->container, SRAM_BASE_ADDRESS, &s->sram);

    // DFLASH
    memory_region_init_rom(&s->dflash, OBJECT(s), "nxps32k3x8evb.dflash", DFLASH_SIZE, &err);
    if (err)
    {
        error_propagate(errp, err);
        return;
    }
    memory_region_add_subregion(&s->container, DFLASH_BASE_ADDRESS, &s->dflash);

    // Connect CPU memory
    object_property_set_link(OBJECT(&s->cpu), "memory", OBJECT(&s->container), &error_abort);

    if (!sysbus_realize(SYS_BUS_DEVICE(&s->cpu), errp))
    {
        printf("MCU realization failed");
        return;
    }

    memory_region_add_subregion_overlap(&s->container, 0, s->board_memory, -1);


    // ========= ADD  TPM 2.0 =========
    DeviceState *tpm = qdev_new("tpm2");
    SysBusDevice *sbd = SYS_BUS_DEVICE(tpm);
    // qdev_prop_set_string(tpm, "tpmdev", "tpm0"); -- Useful for swtpm


    //realize the tpm device


      if (!sysbus_realize_and_unref(sbd, &err)) {
        error_propagate(errp, err);
        return;
    }

    MemoryRegion *tpm_mmio = sysbus_mmio_get_region(sbd, 0);
    if (!tpm_mmio)
    {
        error_setg(errp, "Failed to get TPM MMIO region");
        return;
    }

    // TPM MMIO is added directly to s->container at correct base
    memory_region_add_subregion(&s->container, NXPS32K3X8EVB_TPM_BASE_ADDRESS, tpm_mmio); // <-- FIXED

    /*
    if (!sysbus_realize_and_unref(sbd, errp))
        return;

    memory_region_add_subregion(&s->container, NXPS32K3X8EVB_TPM_BASE_ADDRESS, sysbus_mmio_get_region(sbd, 0));
    memory_region_set_size(sysbus_mmio_get_region(sbd, 0), NXPS32K3X8EVB_TPM_SIZE);

   //memory_region_add_subregion_overlap(&s->container, 0, s->board_memory, -1);


   */
}

//
static Property nxps32k3x8evb_properties[] = {
    DEFINE_PROP_LINK("memory", NXPS32K3X8EVB_MCUState, board_memory, TYPE_MEMORY_REGION, MemoryRegion *),
    DEFINE_PROP_UINT32("itcm-size", NXPS32K3X8EVB_MCUState, itcm_size, ITCM_SIZE),
    DEFINE_PROP_UINT32("pflash-size", NXPS32K3X8EVB_MCUState, pflash_size, PFLASH_SIZE),
    DEFINE_PROP_UINT32("sram-size", NXPS32K3X8EVB_MCUState, sram_size, SRAM_SIZE),
    DEFINE_PROP_UINT32("dflash-size", NXPS32K3X8EVB_MCUState, dflash_size, DFLASH_SIZE),
};

// This function has the goal of define the behavior and capabilities of the deviceclass
static void nxps32k3x8evb_mcu_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    // Setting the realize function
    dc->realize = nxps32k3x8evb_mcu_realize;
    device_class_set_props_n(dc, nxps32k3x8evb_properties, sizeof(nxps32k3x8evb_properties) / sizeof(Property));
}

static const TypeInfo nxps32k3x8evb_mcu_info = {
    .name = TYPE_NXPS32K3X8EVB_MCU,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(NXPS32K3X8EVB_MCUState),
    .instance_init = nxps32k3x8evb_mcu_init,
    .class_init = nxps32k3x8evb_mcu_class_init,
};

static void nxps32k3x8evb_mcu_types(void)
{
    type_register_static(&nxps32k3x8evb_mcu_info);
}

type_init(nxps32k3x8evb_mcu_types);

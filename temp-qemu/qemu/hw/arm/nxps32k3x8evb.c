#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/qdev-properties.h"
#include "hw/boards.h"
#include "hw/arm/boot.h"
#include "qemu/typedefs.h"
#include "system/address-spaces.h"
#include "system/system.h"      /* instead of sysemu/sysemu */
//#include "exec/address-spaces.h"
#include "qom/object.h"
#include "hw/char/nxps32k3x8evb_uart.h"


#include "hw/arm/nxps32k3x8evb.h"
#include "hw/arm/nxps32k3x8evb_mcu.h"


struct nxps32k3x8evbMachineState{
    MachineState parent;
    NXPS32K3X8EVB_MCUState mcu;
};

#define TYPE_NXPS32K3X8EVB_MACHINE MACHINE_TYPE_NAME("nxps32k3x8evb")
OBJECT_DECLARE_SIMPLE_TYPE(nxps32k3x8evbMachineState, NXPS32K3X8EVB_MACHINE)

// Entry point for setting up the system
static void nxps32k3x8evb_init(MachineState *machine){
    nxps32k3x8evbMachineState *s = NXPS32K3X8EVB_MACHINE(machine);

    MemoryRegion *system_memory = get_system_memory();

    object_initialize_child(OBJECT(machine), "NXPS32K3X8EVB_MCUS", &s->mcu, TYPE_NXPS32K3X8EVB_MCU);

    object_property_set_link(OBJECT(&s->mcu), "memory", OBJECT(system_memory), &error_fatal);

    sysbus_realize(SYS_BUS_DEVICE(&s->mcu), &error_fatal);

    if(machine->kernel_filename)
        armv7m_load_kernel(ARM_CPU(first_cpu), machine->kernel_filename, 0, s->mcu.pflash_size);

    //UART Code declaration:
     DeviceState *nvic, *uart;
    SysBusDevice *sbd;
    Object *soc_container;

    nvic = (DeviceState *)&s->mcu.cpu;
    soc_container = OBJECT(&s->mcu);

    /* implementing only LPUART01 */
    uart = qdev_new("nxp_uart");
    object_property_add_child(soc_container, "uart", OBJECT(uart));
    sbd = SYS_BUS_DEVICE(uart);
    qdev_prop_set_chr(uart, "chardev", serial_hd(0));
    sysbus_realize(sbd, &error_fatal);
    sysbus_mmio_map(sbd, 0, LPUART_BASE_ADDRESS);
    memory_region_set_size(sysbus_mmio_get_region(sbd, 0), UART_SIZE);
    sysbus_connect_irq(sbd, 0, qdev_get_gpio_in(nvic, LPUART0_TRANSMIT_INTERRUPT));


}

// Define how this machine behaves
static void nxps32k3x8evb_machine_class_init(ObjectClass *oc, void *data){
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->desc = "automotive class of boards (Cortex-m7)";
    mc->init = nxps32k3x8evb_init;              // Define init function
    mc->max_cpus = 1;
}

// Info to register the machine in QEMU
static const TypeInfo nxps32k3x8evb_info = {
    .name = TYPE_NXPS32K3X8EVB_MACHINE,
    .parent = TYPE_MACHINE,
    .instance_size = sizeof(nxps32k3x8evbMachineState),
    .class_init = nxps32k3x8evb_machine_class_init
};


// Register the machine type at QEMU startup
static void nxps32k3x8evb_machine_init(void){
    type_register_static(&nxps32k3x8evb_info);
}


// QEMU macro to register the machine type
type_init(nxps32k3x8evb_machine_init);

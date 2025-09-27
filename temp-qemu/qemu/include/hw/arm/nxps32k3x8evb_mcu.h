
#include "hw/sysbus.h"
#include "hw/arm/armv7m.h"
#include "hw/clock.h"
#include "qom/object.h"

#define TYPE_NXPS32K3X8EVB_MCU "nxps32k3x8evb-mcu"
OBJECT_DECLARE_SIMPLE_TYPE(NXPS32K3X8EVB_MCUState, NXPS32K3X8EVB_MCU)

struct NXPS32K3X8EVB_MCUState
{
    SysBusDevice parent_obj;

    ARMv7MState cpu;

    MemoryRegion itcm;
    MemoryRegion pflash;
    MemoryRegion sram;
    MemoryRegion dflash;

    uint32_t itcm_size;
    uint32_t pflash_size;
    uint32_t sram_size;
    uint32_t dflash_size;
    MemoryRegion *board_memory;

    MemoryRegion container;

    Clock *sysclk;

    // UART
    S32K3x8UartState uart;
};

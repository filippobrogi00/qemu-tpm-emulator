/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef HW_NXP_UART_H
#define HW_NXP_UART_H

#include "hw/sysbus.h"
#include "chardev/char-fe.h"
#include "qom/object.h"

#define TYPE_NXP_UART "nxp_uart"
OBJECT_DECLARE_SIMPLE_TYPE(NXP_UART_STATE, NXP_UART)

/* Depth of UART FIFO in bytes, when FIFO mode is enabled (else depth == 1) */
#define NXP_UART_FIFO_DEPTH 16

struct NXP_UART_STATE {
    SysBusDevice parent_obj;

    MemoryRegion iomem;
    uint32_t flags;
    uint32_t lcr;
    uint32_t rsr;
    uint32_t cr;
    uint32_t dmacr;
    uint32_t int_enabled;
    uint32_t int_level;
    uint32_t read_fifo[NXP_UART_FIFO_DEPTH];
    uint32_t ilpr;
    uint32_t ibrd;
    uint32_t fbrd;
    uint32_t ifl;
    int read_pos;
    int read_count;
    int read_trigger;
    CharBackend chr;
    qemu_irq irq[6];
    Clock *clk;
    bool migrate_clk;
    const unsigned char *id;
    /*
     * Since some users embed this struct directly, we must
     * ensure that the C struct is at least as big as the Rust one.
     */
    uint8_t padding_for_rust[16];
};

DeviceState *nxp_uart_create(hwaddr addr, qemu_irq irq, Chardev *chr);

#endif

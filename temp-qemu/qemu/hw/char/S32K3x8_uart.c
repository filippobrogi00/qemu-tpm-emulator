#include "qemu/osdep.h"
#include "hw/char/S32K_uart.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-properties-system.h"
#include "qemu/log.h"
#include "qemu/module.h"

#ifndef NXP_USART_ERR_DEBUG
#define NXP_USART_ERR_DEBUG 0
#endif

#define DB_PRINT_L(lvl, fmt, args...) do { \
    if (NXP_USART_ERR_DEBUG >= lvl) { \
        qemu_log("%s: " fmt, __func__, ## args); \
    } \
} while (0)

#define DB_PRINT(fmt, args...) DB_PRINT_L(1, fmt, ## args)

static int s32k3x8_usart_can_receive(void *opaque)
{
    S32K3x8UartState *s = opaque;

    if (!(s->usart_sr & USART_SR_RXNE)) {
        return 1;
    }

    return 0;
}

static void s32k3x8_update_irq(S32K3x8UartState *s)
{
    uint32_t mask = s->usart_sr & s->usart_cr1;

    if (mask & (USART_SR_TXE | USART_SR_TC | USART_SR_RXNE)) {
        qemu_set_irq(s->irq, 1);
    } else {
        qemu_set_irq(s->irq, 0);
    }
}

static void s32k3x8_usart_receive(void *opaque, const uint8_t *buf, int size)
{
    S32K3x8UartState *s = opaque;

    // USART not enabled - drop the chars
    if (!(s->usart_cr1 & USART_CR1_UE && s->usart_cr1 & USART_CR1_RE)) {
        DB_PRINT("Dropping the chars\n");
        return;
    }

    s->usart_dr = *buf;
    s->usart_sr |= USART_SR_RXNE;

    s32k3x8_update_irq(s);

    DB_PRINT("Receiving: %c\n", s->usart_dr);
}

static void s32k3x8_usart_reset(DeviceState *dev)
{
    S32K3x8UartState *s = S32K3x8_UART(dev);

    s->usart_sr = USART_SR_RESET;
    s->usart_dr = 0x00000000;
    s->usart_brr = 0x00000000;
    s->usart_cr1 = 0x00000000;
    s->usart_cr2 = 0x00000000;
    s->usart_cr3 = 0x00000000;
    s->usart_gtpr = 0x00000000;

    s32k3x8_update_irq(s);
}


static uint64_t s32k3x8_usart_read(void *opaque, hwaddr addr,
                                       unsigned int size)
{
    S32K3x8UartState *s = opaque;
    uint64_t retvalue;

    DB_PRINT("Read 0x%"HWADDR_PRIx"\n", addr);

    switch (addr) {
    case USART_SR:
        retvalue = s->usart_sr;
        qemu_chr_fe_accept_input(&s->chr);
        return retvalue;
    case USART_DR:
        DB_PRINT("Value: 0x%" PRIx32 ", %c\n", s->usart_dr, (char) s->usart_dr);
        retvalue = s->usart_dr & 0x3FF;
        s->usart_sr &= ~USART_SR_RXNE;
        qemu_chr_fe_accept_input(&s->chr);
        s32k3x8_update_irq(s);
        return retvalue;
    case USART_BRR:
        return s->usart_brr;
    case USART_CR1:
        return s->usart_cr1;
    case USART_CR2:
        return s->usart_cr2;
    case USART_CR3:
        return s->usart_cr3;
    case USART_GTPR:
        return s->usart_gtpr;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: Bad offset 0x%"HWADDR_PRIx"\n", __func__, addr);
        return 0;
    }

    return 0;
}

static void s32k3x8_usart_write(void *opaque, hwaddr addr,
                                  uint64_t val64, unsigned int size)
{
    S32K3x8UartState *s = opaque;
    uint32_t value = val64;
    unsigned char ch;

    DB_PRINT("Write 0x%" PRIx32 ", 0x%"HWADDR_PRIx"\n", value, addr);

    switch (addr) {
    case USART_SR:
        if (value <= 0x3FF) {
            s->usart_sr = value | USART_SR_TXE;
        } else {
            s->usart_sr &= value;
        }
        s32k3x8_update_irq(s);
        return;
    case USART_DR:
        if (value < 0xF000) {
            ch = value;
            qemu_chr_fe_write_all(&s->chr, &ch, 1);
            s->usart_sr |= USART_SR_TC;
            s32k3x8_update_irq(s);
        }
        return;
    case USART_BRR:
        s->usart_brr = value;
        return;
    case USART_CR1:
        s->usart_cr1 = value;
        s32k3x8_update_irq(s);
        return;
    case USART_CR2:
        s->usart_cr2 = value;
        return;
    case USART_CR3:
        s->usart_cr3 = value;
        return;
    case USART_GTPR:
        s->usart_gtpr = value;
        return;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: Bad offset 0x%"HWADDR_PRIx"\n", __func__, addr);
    }
}


// --------- UART initialization and realization ----------
static const MemoryRegionOps s32k3x8_usart_ops = {
    .read = s32k3x8_usart_read,
    .write = s32k3x8_usart_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static Property s32k3x8_usart_properties[] = {
    DEFINE_PROP_CHR("chardev", S32K3x8UartState, chr),
    DEFINE_PROP_END_OF_LIST(),
};

static void s32k3x8_usart_init(Object *obj)
{
    S32K3x8UartState *s = S32K3x8_UART(obj);

    sysbus_init_irq(SYS_BUS_DEVICE(obj), &s->irq);
    memory_region_init_io(
                            &s->mmio, 
                            obj, 
                            &s32k3x8_usart_ops, 
                            s,
                            TYPE_S32K3x8_UART, 
                            0x400
                        );
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->mmio);
}

static void s32k3x8_usart_realize(DeviceState *dev, Error **errp)
{
    S32K3x8UartState *s = S32K3x8_UART(dev);

    qemu_chr_fe_set_handlers(
                                &s->chr, 
                                s32k3x8_usart_can_receive,
                                s32k3x8_usart_receive, 
                                NULL, 
                                NULL,
                                s, 
                                NULL, 
                                true
                             );
}

static void s32k3x8_usart_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    device_class_set_legacy_reset(dc, s32k3x8_usart_reset);
    device_class_set_props(dc, s32k3x8_usart_properties);
    dc->realize = s32k3x8_usart_realize;
}

static const TypeInfo s32k3x8_usart_info = {
    .name          = TYPE_S32K3x8_UART,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(S32K3x8UartState),
    .instance_init = s32k3x8_usart_init,
    .class_init    = s32k3x8_usart_class_init,
};

static void s32k3x8_usart_register_types(void)
{
    type_register_static(&s32k3x8_usart_info);
}

type_init(s32k3x8_usart_register_types)

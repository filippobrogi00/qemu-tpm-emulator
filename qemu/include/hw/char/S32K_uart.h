#ifndef HW_S32K3x8_USART
#define HW_S32K3x8_USART

#include "qom/object.h"
#include "hw/sysbus.h"
#include "chardev/char-fe.h"

#define USART_SR   0x00
#define USART_DR   0x04
#define USART_BRR  0x08
#define USART_CR1  0x0C
#define USART_CR2  0x10
#define USART_CR3  0x14
#define USART_GTPR 0x18

#define USART_SR_RESET (USART_SR_TXE | USART_SR_TC)

#define USART_SR_TXE  (1 << 7)
#define USART_SR_TC   (1 << 6)
#define USART_SR_RXNE (1 << 5)

#define USART_CR1_UE     (1 << 13)
#define USART_CR1_TXEIE  (1 << 7)
#define USART_CR1_TCEIE  (1 << 6)
#define USART_CR1_RXNEIE (1 << 5)
#define USART_CR1_TE     (1 << 3)
#define USART_CR1_RE     (1 << 2)

#define TYPE_S32K3x8_UART "S32K3x8_UART"
OBJECT_DECLARE_SIMPLE_TYPE(S32K3x8UartState, S32K3x8_UART)

struct S32K3x8UartState {
    SysBusDevice parent_obj;

    MemoryRegion mmio;

    uint32_t usart_sr;
    uint32_t usart_dr;
    uint32_t usart_brr;
    uint32_t usart_cr1;
    uint32_t usart_cr2;
    uint32_t usart_cr3;
    uint32_t usart_gtpr;

    CharBackend chr;
    qemu_irq irq;
};
#endif /* HW_STM32F2XX_USART_H */

#ifndef __UARTH__
#define __UARTH__

#include <stdint.h>

#define UART0_ADDRESS (0x40328000UL)
#define UART0_DATA (*(((volatile uint32_t *)(UART0_ADDRESS + 0UL))))
#define UART0_STATE (*(((volatile uint32_t *)(UART0_ADDRESS + 0x4UL))))
#define UART0_CTRL (*(((volatile uint32_t *)(UART0_ADDRESS + 0x8UL))))
#define UART0_BAUDDIV (*(((volatile uint32_t *)(UART0_ADDRESS + 16UL))))
#define UART0_FLAGREG (*(((volatile uint32_t *)(UART0_ADDRESS + 0x18UL))))

void UART_init(void);
void UART_putc(const char c);
void UART_printf(const char *fmt, ...);

#endif
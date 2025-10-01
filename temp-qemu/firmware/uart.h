#ifndef __PRINTF__
#define __PRINTF__

#include <stdint.h>

#define UART0_ADDRESS (0x40328000UL)
#define UART0_DATA (*(((volatile uint32_t *)(UART0_ADDRESS + 0UL))))
#define UART0_STATE (*(((volatile uint32_t *)(UART0_ADDRESS + 4UL))))
#define UART0_CTRL (*(((volatile uint32_t *)(UART0_ADDRESS + 8UL))))
#define UART0_BAUDDIV (*(((volatile uint32_t *)(UART0_ADDRESS + 16UL))))
#define UART0_FLAGREG (*(((volatile uint32_t *)(UART0_ADDRESS + 0x18UL))))

#define UART_F_RXFE (1 << 4) // Receive FIFO Empty
#define UART_F_RXFF (1 << 5) // Receive FIFO Full

void UART_init(void);
// void UART_printf(const char *s);
void UART_putstr(const char *s);
void UART_printf(const char *fmt, ...);
void UART_putc(const char c);
char UART_getc(void);
void UART_gets(char *s, int maxlen);

#endif

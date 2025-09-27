#include "uart.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

// UART
// UART Initialization
void UART_init(void)
{
    // Set baud rate
    *((uint32_t *)(UART0_BAUDDIV)) = 16;
    // Enable transmitter and receiver
    *((uint32_t *)(UART0_CTRL)) = 1;
}

void uart_printf(const char *fmt, ...)
{
    char buffer[128];
    char *p = buffer;
    va_list args;
    va_start(args, fmt);

    while (*fmt)
    {
        if (*fmt == '%')
        {
            fmt++;
            switch (*fmt)
            {
            case 'c':
            {
                char c = (char)va_arg(args, int);
                *p++ = c;
                break;
            }
            case 's':
            {
                char *str = va_arg(args, char *);
                while (*str)
                    *p++ = *str++;
                break;
            }
            case 'd':
            {
                int val = va_arg(args, int);
                char num[16];
                bool neg = false;
                if (val < 0)
                {
                    neg = true;
                    val = -val;
                }
                int i = 0;
                do
                {
                    num[i++] = (val % 10) + '0';
                    val /= 10;
                } while (val > 0);
                if (neg)
                    *p++ = '-';
                while (i--)
                    *p++ = num[i];
                break;
            }
            case 'x':
            case 'X':
            {
                unsigned val = va_arg(args, unsigned);
                char num[16];
                int i = 0;
                do
                {
                    int digit = val % 16;
                    num[i++] = (digit < 10) ? '0' + digit : ((*fmt == 'x') ? 'a' : 'A') + (digit - 10);
                    val /= 16;
                } while (val > 0);
                *p++ = '0';
                *p++ = 'x';
                while (i--)
                    *p++ = num[i];
                break;
            }
            default:
                *p++ = '%';
                *p++ = *fmt;
            }
        }
        else
        {
            *p++ = *fmt;
        }
        fmt++;
    }
    *p = '\0';

    va_end(args);
    uart_send_string(buffer);
}

void UART_putc(const char c)
{
    while (UART0_FLAGREG & (1 << 5))
    {
        // wait
    }
    UART0_DATA = c;
}
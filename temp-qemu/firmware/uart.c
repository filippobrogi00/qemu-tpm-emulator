#include "uart.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

void UART_init(void)
{
    UART0_BAUDDIV = 16;
    UART0_CTRL = 1;
}

// void UART_printf(const char *s)
// {
//     while (*s != '\0')
//     {
//         UART0_DATA = (unsigned int)(*s);
//         s++;
//     }
// }

void UART_putstr(const char *s)
{
    while (*s != '\0')
    {
        UART0_DATA = (unsigned int)(*s);
        s++;
    }
}

void UART_printf(const char *fmt, ...)
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
            case 'u':
            {
                unsigned val = va_arg(args, unsigned);
                char num[16];
                int i = 0;
                do
                {
                    num[i++] = (val % 10) + '0';
                    val /= 10;
                } while (val > 0);
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
    UART_putstr(buffer);
}

void UART_putc(const char c)
{
    while (UART0_FLAGREG & (1 << 5))
    {
        // wait
    }
    UART0_DATA = c;
}

char UART_getc(void)
{
    while (UART0_FLAGREG & UART_F_RXFE)
        ;
    return (char)(UART0_DATA);
}

void UART_gets(char *s, int maxlen)
{
    int i = 0;
    char c;
    while (i < maxlen - 1)
    {
        c = UART_getc();
        // Echo
        UART_putc(c);

        if (c == '\r' || c == '\n')
        {
            break;
        }

        s[i++] = c;
    }
    s[i] = '\0';
    UART_putc('\n');
}
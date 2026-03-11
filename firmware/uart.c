#include "uart.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

void
UART_init (void)
{
  UART0_BAUDDIV = 16;
  UART0_CTRL    = 1;
}

void
UART_putstr (const char *s)
{
  while (*s != '\0')
    {
      UART0_DATA = (unsigned int)(*s);
      s++;
    }
}

void
UART_printf (const char *fmt, ...)
{
  char    buffer[128];
  char   *p = buffer;
  va_list args;
  va_start (args, fmt);

  while (*fmt)
    {
      if (*fmt == '%')
        {
            fmt++;
            bool zero_pad = false;
            int width = 0;

            // Parse flags
            if (*fmt == '0')
            {
                zero_pad = true;
                fmt++;
            }

            // Parse width (e.g., 4 or 08)
            while (*fmt >= '0' && *fmt <= '9')
            {
                width = width * 10 + (*fmt - '0');
                fmt++;
            }

            switch (*fmt)
            {
            case 'c':
              {
                char c = (char)va_arg (args, int);
                *p++   = c;
                break;
              }
            case 's':
              {
                char *str = va_arg (args, char *);
                while (*str)
                  *p++ = *str++;
                break;
              }
            case 'd':
            case 'u':
            case 'x':
            case 'X':
            {
                unsigned val;
                bool neg = false;
                if (*fmt == 'd')
                {
                    int v = va_arg(args, int);
                    if (v < 0)
                    {
                        neg = true;
                        val = -v;
                    }
                    else
                        val = v;
                }
                else
                    val = va_arg(args, unsigned);

                char num[16];
                int base = (*fmt == 'x' || *fmt == 'X') ? 16 : 10;
                int i = 0;
                do
                {
                    int digit = val % base;
                    num[i++] = (digit < 10) ? '0' + digit
                                            : ((*fmt == 'x') ? 'a' : 'A') + (digit - 10);
                    val /= base;
                } while (val > 0);

                if (neg)
                    *p++ = '-';

                // Add padding if needed
                while (i < width)
                    num[i++] = zero_pad ? '0' : ' ';

                while (i--)
                  *p++ = num[i];
                break;
              }
            default:
                *p++ = '%';
                *p++ = *fmt;
                break;
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

void
UART_putc (const char c)
{
  while (UART0_FLAGREG & UART_F_RXFF)
    {
      // wait
    }
  UART0_DATA = c;
}

char
UART_getc (void)
{
  while (UART0_FLAGREG & UART_F_RXFE)
    ;
  return (char)(UART0_DATA);
}

void
UART_gets (char *s, int maxlen)
{
  int  i = 0;
  char c;
  while (i < maxlen - 1)
    {
      c = UART_getc ();
      // Echo
      UART_putc (c);

      if (c == '\r' || c == '\n')
        {
          break;
        }

      s[i++] = c;
    }
  s[i] = '\0';
  UART_putc ('\n');
}

void
UART_print_hex (const uint8_t *data, uint32_t len)
{
  char hex_digits[] = "0123456789abcdef";

  for (uint32_t i = 0; i < len; i++)
    {
      UART_putc (hex_digits[(data[i] >> 4) & 0x0F]);
      UART_putc (hex_digits[data[i] & 0x0F]);

      if ((i + 1) % 16 == 0)
        {
          UART_putstr ("\n");
        }
      else if ((i + 1) % 4 == 0)
        {
          UART_putstr (" ");
        }
    }
  if (len % 16 != 0)
    {
      UART_printf ("\n");
    }
}
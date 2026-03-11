#ifndef TPM2_TEST_UART_H
#define TPM2_TEST_UART_H

#include "tpm/tpm2_base_types.h"

/******************************
 * MOCKED UART REGISTERS
 ******************************/
extern UINT32 UART0_BAUDDIV;
extern UINT32 UART0_CTRL;
extern UINT32 UART0_DATA;
extern UINT32 UART0_FLAGREG;

/******************************
 * UTILITY MOCK FUNCTIONS
 ******************************/

void reset_uart_output (void);

void set_uart_input (const char *input);

void UART_putc (const char c);

char UART_getc ();

/******************************
 * UART TEST FUNCTIONS
 ******************************/

void TPM2_TEST_UART_init (void);

void TPM2_TEST_UART_putstr (void);

void TPM2_TEST_UART_gets (void);

void TPM2_TEST_UART_printf (void);

void TPM2_TEST_UART_print_hex (void);

void TPM2_TEST_UART (void);

#endif // TPM2_TEST_UART_H

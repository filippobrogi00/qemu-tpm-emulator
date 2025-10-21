#include "test.h"
#include "tpm/tpm2_base_types.h"
#include "uart.h"
#include "uart_test.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/******************************
 * MOCKED UART REGISTERS
 ******************************/
// UART mocked registers
UINT32 UART0_BAUDDIV;
UINT32 UART0_CTRL;
UINT32 UART0_DATA;
UINT32 UART0_FLAGREG;

// Mocked UART TX/RX flags
#define UART_FLAG_TXFULL (1 << 5)
#define UART_FLAG_RXFE   (1 << 4)

/* Buffers to capture and simulate UART data flow */
// Output
static char   uart_out_buffer[1024];
static size_t uart_out_index = 0;
// Input
static const char *uart_in_data  = NULL;
static size_t      uart_in_index = 0;

/******************************
 * UTILITY FUNCTIONS
 ******************************/
/**
 * @brief Resets UART output mock buffer and index.
 */
void
reset_uart_output (void)
{
  memset (uart_out_buffer, 0, sizeof (uart_out_buffer));
  uart_out_index = 0;
}

/**
 * @brief Sets the simulated UART input buffer with a given string.
 * @param input Pointer to input string that UART_getc() and UART_gets() will read from.
 */
void
set_uart_input (const char *input)
{
  uart_in_data  = input;
  uart_in_index = 0;
  UART0_FLAGREG &= ~UART_FLAG_RXFE; // data available
}

/**
 * @brief Stores into the mock buffer uart_out_buffer the specified char
 * @param c character to put into buffer
 */
void
UART_putc (const char c)
{
  // Wait simulation
  while (UART0_FLAGREG & UART_FLAG_TXFULL)
    ;

  // Store written character
  uart_out_buffer[uart_out_index++] = c;
  uart_out_buffer[uart_out_index]   = '\0'; // keep null-terminated
}

/*
 * @brief Returns the next character to read from the mocked (input) buffer
 */
char
UART_getc (void)
{
  // Wait until "data available"
  while (UART0_FLAGREG & UART_FLAG_RXFE)
    ;

  // Return next input character
  char c = uart_in_data[uart_in_index++];
  if (uart_in_data[uart_in_index] == '\0')
    {
      // simulate FIFO empty
      UART0_FLAGREG |= UART_FLAG_RXFE;
    }
  return c;
}

/**************************************
 * UART TESTING FUNCTIONS
 **************************************/
/**
 * @brief Tests UART_putstr() — verifies that a string is correctly written
 *        into the UART output buffer.
 */
void
TPM2_TEST_UART_putstr ()
{
  TEST_START ("UART_putc and UART_putstr");

  // Reset buffer
  reset_uart_output ();
  // Insert test string and compare with hardcoded string
  UART_putstr ("Test String");
  ASSERT (strcmp (uart_out_buffer, "Test String") == 0, "UART_putstr output mismatch");
  TEST_PASS ();
}

/**
 * @brief Tests UART_gets() / UART_getc() — validates correct reception and
 *        echoing of UART input data.
 */
void
TPM2_TEST_UART_gets ()
{
  char line[32];

  TEST_START ("UART_getc / UART_gets");

  // Reset
  reset_uart_output ();
  // Test String
  set_uart_input ("Test String\n");

  // Read value from buffer and check if it matches the hardcoded message
  UART_gets (line, sizeof (line));
  ASSERT (strcmp (line, "Test String") == 0, "UART_gets string mismatch");
  ASSERT (strchr (uart_out_buffer, '\n') != NULL, "UART_gets missing echo newline");
  TEST_PASS ();
}

/**
 * @brief Tests UART_printf() — checks formatted string output for different
 *        format specifiers (%s, %d, %x, %u).
 */
void
TPM2_TEST_UART_printf ()
{
  TEST_START ("UART_printf - %s, %d, %x, %u");

  // Reset
  reset_uart_output ();

  // Checks each string part gets inserted correctly by UART_printf
  UART_printf ("Msg:%s %d %x %u", "OK", -42, 0x1A3F, 1234);
  ASSERT (strstr (uart_out_buffer, "Msg:OK") != NULL, "printf %s failed");
  ASSERT (strstr (uart_out_buffer, "-42") != NULL, "printf %d failed");
  ASSERT (strstr (uart_out_buffer, "0x1a3f") != NULL, "printf %x failed");
  ASSERT (strstr (uart_out_buffer, "1234") != NULL, "printf %u failed");
  TEST_PASS ();
}

/**
 * @brief Tests UART_print_hex() — ensures hexadecimal output formatting.
 */
void
TPM2_TEST_UART_print_hex ()
{
  UINT8 data[8] = { 0x01, 0xAF, 0x10, 0x22, 0xFF, 0x00, 0x7E, 0x3C };

  TEST_START ("UART_print_hex - simple 8 bytes");

  // Reset
  reset_uart_output ();
  // Check message in UART buffer against hardcoded string
  UART_print_hex (data, 8);
  ASSERT (strstr (uart_out_buffer, "01af1022 ff007e3c") != NULL, "UART_print_hex format mismatch");
  TEST_PASS ();
}

/**
 * @brief Tests UART_init() — verifies register initialization (BAUDDIV, CTRL).
 */
void
TPM2_TEST_UART_init ()
{
  TEST_START ("UART_init - register setup");

  UART_init ();
  ASSERT (UART0_BAUDDIV == 16, "UART0_BAUDDIV not set correctly");
  ASSERT (UART0_CTRL == 1, "UART0_CTRL not set correctly");
  TEST_PASS ();
}

/* Main UART test function: Tests every UART functionality */
/**
 * @brief Runs all UART-related tests in sequence.
 */
void
TPM2_TEST_UART ()
{
  printf ("\n===============================\n");
  printf (" TPM2 UART TEST SUITE STARTED\n");
  printf ("===============================\n\n");

  TPM2_TEST_UART_init ();
  TPM2_TEST_UART_gets ();
  TPM2_TEST_UART_putstr ();
  TPM2_TEST_UART_printf ();
  TPM2_TEST_UART_print_hex ();

  printf ("\n===============================\n");
  printf (" TPM2 UART TEST SUITE STARTED\n");
  printf ("===============================\n\n");
}

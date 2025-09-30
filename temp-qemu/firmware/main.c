#include <stdint.h>
#include "uart.h"
#include <stdio.h>

#define TPM2_BASE          0xF0000000
#define TPM2_CTRL_REG      (*(volatile uint32_t *)(TPM2_BASE + 0x00))  // same
#define TPM2_STATUS_REG    (*(volatile uint32_t *)(TPM2_BASE + 0x04))  // swapped
#define TPM2_RANDOM_REG    (*(volatile uint32_t *)(TPM2_BASE + 0x08))  // same
#define TPM2_CMD_REG       (*(volatile uint32_t *)(TPM2_BASE + 0x0C))  // swapped
#define TPM2_DATA_REG      (*(volatile uint32_t *)(TPM2_BASE + 0x10))  // same


#define TPM2_CMD_GEN_RANDOM 0x01
#define TPM2_CMD_GEN_RSA    0x02
#define TPM2_CMD_CLEAR      0x03

void delay() {
    for (volatile int i = 0; i < 100000; i++);
}

void main(void) {
    UART_init();
    char message[] = "TPM2 Example Start\n";
    UART_printf(message);


    // Trigger random number generation
    TPM2_CMD_REG = TPM2_CMD_GEN_RANDOM;

    delay(); // Wait for completion (no IRQ here)

    // Read result
    uint32_t rand_val = TPM2_RANDOM_REG;
    TPM2_CMD_REG = TPM2_CMD_GEN_RSA;

    delay(500); // Wait for RSA key generation

    uint32_t key_generated = TPM2_DATA_REG;
    // Optional: infinite loop with value (good for stepping in debugger)
    while (1) {
        (void)rand_val;
    }
}

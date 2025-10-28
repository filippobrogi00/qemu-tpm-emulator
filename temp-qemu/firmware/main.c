#include "uart.h"
#include <stdint.h>
#include <stdio.h>

#define TPM2_BASE       0xF0000000
#define TPM2_CTRL_REG   (*(volatile uint32_t *)(TPM2_BASE + 0x00))
#define TPM2_STATUS_REG (*(volatile uint32_t *)(TPM2_BASE + 0x04))
#define TPM2_RANDOM_REG (*(volatile uint32_t *)(TPM2_BASE + 0x08))
#define TPM2_CMD_REG    (*(volatile uint32_t *)(TPM2_BASE + 0x0C))
#define TPM2_DATA_REG   (*(volatile uint32_t *)(TPM2_BASE + 0x10))

#define TPM_STATE_IDLE       0
#define TPM_STATE_RECEIVING  2
#define TPM_STATE_PROCESSING 3
#define TPM_STATE_SENDING    4


// Pre-built TPM commands as byte arrays (big-endian)

// TPM2_GetRandom(32 bytes)
static const uint8_t CMD_GET_RANDOM[] = {
  0x80, 0x01,             // Tag: TPM_ST_NO_SESSIONS
  0x00, 0x00, 0x00, 0x0C, // Size: 12 bytes
  0x00, 0x00, 0x01, 0x7B, // Code: TPM_CC_GetRandom
  0x00, 0x20              // bytesRequested: 32
};

// TPM2_CreatePrimary - Minimal RSA 2048 key
static const uint8_t CMD_CREATE_PRIMARY[] = {
  // Header (10 bytes)
  0x80, 0x01,                         // Tag: TPM_ST_NO_SESSIONS
  0x00, 0x00, 0x00, 0x32,             // Size: 50 bytes
  0x00, 0x00, 0x01, 0x31,             // Code: TPM_CC_CreatePrimary

  // Body (40 bytes)
  0x40, 0x00, 0x00, 0x01,             // authHandle: TPM_RH_OWNER

  // inSensitive (TPM2B_SENSITIVE_CREATE)
  0x00, 0x04,                         // size = 4
  0x00, 0x00,                         //   userAuth.size = 0
  0x00, 0x00,                         //   data.size = 0

  // inPublic (TPM2B_PUBLIC)
  0x00, 0x16,                         // size = 22 (TPMS_PUBLIC size below)
  0x00, 0x01,                         //   type: TPM_ALG_RSA
  0x00, 0x0B,                         //   nameAlg: TPM_ALG_SHA256
  0x00, 0x00, 0x00, 0x72,             //   objectAttributes
  0x00, 0x00,                         //   authPolicy.size = 0
  0x00, 0x10,                         //   symmetric: TPM_ALG_NULL
  0x00, 0x10,                         //   scheme: TPM_ALG_NULL
  0x08, 0x00,                         //   keyBits: 2048
  0x00, 0x00, 0x00, 0x00,             //   exponent: 0 (default)
  0x00, 0x00,                         //   unique.size = 0

  // outsideInfo (TPM2B_DATA)
  0x00, 0x00,                         // size = 0

  // creationPCR (TPML_PCR_SELECTION)
  0x00, 0x00, 0x00, 0x00              // count = 0
};


// TPM2_NV_DefineSpace - 32-byte index at 0x01000001
static const uint8_t CMD_NV_DEFINE_SPACE[] = {
  0x80, 0x01,             // Tag: TPM_ST_NO_SESSIONS
  0x00, 0x00, 0x00, 0x20, // Size: 32 bytes
  0x00, 0x00, 0x01, 0x2A, // Code: TPM_CC_NV_DefineSpace
  0x40, 0x00, 0x00, 0x0C, // authHandle: TPM_RH_PLATFORM
  0x00, 0x00,             // auth.size = 0
  0x00, 0x0E,             // publicArea.size = 14
  0x01, 0x00, 0x00, 0x01, // nvIndex: 0x01000001
  0x00, 0x0B,             // nameAlg: TPM_ALG_SHA256
  0x00, 0x00, 0x40, 0x07, // attributes
  0x00, 0x00,             // authPolicy.size = 0
  0x00, 0x20              // dataSize: 32
};

/**
 * @brief Send a TPM command to the device
 * @param cmd_buf Command buffer (big-endian)
 * @param len Command length in bytes
 */
void tpm_send_command(const uint8_t *cmd_buf, uint32_t len)
{
    // 1. Request RECEIVING state
    TPM2_CTRL_REG = 1;
    
    // 2. Poll for state change
    // volatile uint32_t timeout = 100000;
    // while (TPM2_STATUS_REG != TPM_STATE_RECEIVING && timeout > 0) {
    //     timeout--;
    // }
    
    // if (timeout == 0) {
    //     UART_printf("Error: TPM timed out entering RECEIVING state.\n");
    //     return;
    // }

    uint32_t padded_len = (len + 3) & ~3;
    UART_printf("Sending command (size %u, padded to %u)...\n", len, padded_len);

    // 3. Write command data in 4-byte chunks
    // The data is already in big-endian format, so we send it as-is
    for (uint32_t i = 0; i < padded_len; i += 4)
    {
        // Combine 4 bytes into a 32-bit word (big-endian)
        // Use zero padding if we're beyond the actual command length
        uint32_t word = 0;
        
        if (i + 0 < len) word |= ((uint32_t)cmd_buf[i + 0] << 24);
        if (i + 1 < len) word |= ((uint32_t)cmd_buf[i + 1] << 16);
        if (i + 2 < len) word |= ((uint32_t)cmd_buf[i + 2] << 8);
        if (i + 3 < len) word |= ((uint32_t)cmd_buf[i + 3]);
        
        TPM2_DATA_REG = word;
    }
    
    // 4. Execute command
    TPM2_CMD_REG = 1;
}

/**
 * @brief Read TPM response from device
 * @param resp_buf Response buffer
 * @param max_len Maximum buffer size
 * @return Number of bytes read
 */
uint32_t tpm_read_response(uint8_t *resp_buf, uint32_t max_len) {
  
  // 1. Wait for PROCESSING to complete
  while (TPM2_STATUS_REG == TPM_STATE_PROCESSING) {
    // busy wait
  }

  // 2. Check if device is in SENDING state
  if (TPM2_STATUS_REG != TPM_STATE_SENDING) {
      UART_printf("Error: TPM did not enter SENDING state (state=%u)\n", 
                  TPM2_STATUS_REG);
      return 0;
  }

  UART_printf("Reading response...\n");

  // 3. Read first 12 bytes (header) in 4-byte chunks
  for (int i = 0; i < 3; i++) {
    uint32_t word = TPM2_DATA_REG;
    // Convert from device's big-endian to buffer
    resp_buf[i * 4 + 0] = (word >> 24) & 0xFF;
    resp_buf[i * 4 + 1] = (word >> 16) & 0xFF;
    resp_buf[i * 4 + 2] = (word >> 8)  & 0xFF;
    resp_buf[i * 4 + 3] = (word)       & 0xFF;
  }

  uint32_t actual_size = ((uint32_t)resp_buf[2] << 24) |
                           ((uint32_t)resp_buf[3] << 16) |
                           ((uint32_t)resp_buf[4] << 8)  |
                           ((uint32_t)resp_buf[5]);
    
  // Calculate padded size
  uint32_t padded_size = (actual_size + 3) & ~3;
  
  UART_printf("Response size: actual=%u, padded=%u\n", actual_size, padded_size);
    

  // 5. Validate response size
  if (actual_size > max_len) {
    UART_printf("Error: Response buffer too small!\n");
    return 12;
  }
  if (actual_size < 10) {
    UART_printf("Error: Invalid response size!\n");
    return 12;
  }

  // 6. Read remaining data
  uint32_t bytes_read = 12;
  while (bytes_read < padded_size) {
    if (TPM2_STATUS_REG != TPM_STATE_SENDING) {
      UART_printf("Error: TPM stopped sending early!\n");
      return actual_size < bytes_read ? actual_size : bytes_read;
    }

    uint32_t word = TPM2_DATA_REG;
    if (bytes_read < actual_size) {
      resp_buf[bytes_read + 0] = (word >> 24) & 0xFF;
      if (bytes_read + 1 < actual_size) resp_buf[bytes_read + 1] = (word >> 16) & 0xFF;
      if (bytes_read + 2 < actual_size) resp_buf[bytes_read + 2] = (word >> 8) & 0xFF;
      if (bytes_read + 3 < actual_size) resp_buf[bytes_read + 3] = (word) & 0xFF;
    } // else: discard padding bytes 
    bytes_read += 4;
  }

  UART_printf("Response read complete (actual %u bytes, read %u with padding).\n", actual_size, bytes_read);
    return actual_size;  // Return actual size, not padded
}

/**
 * @brief Print menu options
 */
void print_menu(void)
{
    UART_printf("\n--- TPM Command Menu ---\n");
    UART_printf("1: TPM2_GetRandom (32 bytes)\n");
    UART_printf("2: TPM2_CreatePrimary (RSA 2048 key)\n");
    UART_printf("3: TPM2_NV_DefineSpace (32-byte index)\n");
    UART_printf("Select an option: ");
}

/**
 * @brief Parse and display response header
 */
void parse_response_header(const uint8_t *resp_buf)
{
    uint16_t tag = ((uint16_t)resp_buf[0] << 8) | resp_buf[1];
    uint32_t size = ((uint32_t)resp_buf[2] << 24) |
                    ((uint32_t)resp_buf[3] << 16) |
                    ((uint32_t)resp_buf[4] << 8)  |
                    ((uint32_t)resp_buf[5]);
    uint32_t code = ((uint32_t)resp_buf[6] << 24) |
                    ((uint32_t)resp_buf[7] << 16) |
                    ((uint32_t)resp_buf[8] << 8)  |
                    ((uint32_t)resp_buf[9]);
    
    UART_printf("\nResponse Header:\n");
    UART_printf("  Tag:  0x%04X\n", tag);
    UART_printf("  Size: %u bytes\n", size);
    UART_printf("  Code: 0x%08X ", code);
    
    if (code == 0x00000000) {
        UART_printf("(TPM_RC_SUCCESS)\n");
    } else {
        UART_printf("(ERROR)\n");
    }
}

int main(void) {
  UART_init();
  UART_printf("--- TPM Firmware Test Started ---\n");
  UART_printf("All commands are pre-built and properly formatted.\n");

  uint8_t response_buffer[1024];
  const uint8_t *cmd_to_send = NULL;
  uint32_t cmd_size = 0;

  while(1) {
    print_menu();

    char c = UART_getc();
    UART_printf("%c\n", c);

    switch (c) {
      case '1':
        cmd_to_send = CMD_GET_RANDOM;
        cmd_size = sizeof(CMD_GET_RANDOM);
        break;
      
      case '2':
        cmd_to_send = CMD_CREATE_PRIMARY;
        cmd_size = sizeof(CMD_CREATE_PRIMARY);
        break;
      
      case '3':
        cmd_to_send = CMD_NV_DEFINE_SPACE;
        cmd_size = sizeof(CMD_NV_DEFINE_SPACE);
        break;

    default:
        UART_printf("Invalid option '%c'\n", c);
        cmd_to_send = NULL;
        break;
    }

    if (cmd_to_send != NULL) {
      // Send command
      tpm_send_command(cmd_to_send, cmd_size);

      // Read response
      uint32_t resp_size = tpm_read_response(response_buffer, sizeof(response_buffer));

      if (resp_size > 0) {
          parse_response_header(response_buffer);
          
          UART_printf("\nFull Response (Hex):\n");
          UART_print_hex(response_buffer, resp_size);
      } else {
          UART_printf("Failed to get response.\n");
      }
    }
  }
}
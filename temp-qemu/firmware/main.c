#include "uart.h"
#include <stdint.h>
#include <stdio.h>

#define TPM2_BASE       0xF0000000
#define TPM2_CTRL_REG   (*(volatile uint32_t *)(TPM2_BASE + 0x00)) // same
#define TPM2_STATUS_REG (*(volatile uint32_t *)(TPM2_BASE + 0x04)) // swapped
#define TPM2_RANDOM_REG (*(volatile uint32_t *)(TPM2_BASE + 0x08)) // same
#define TPM2_CMD_REG    (*(volatile uint32_t *)(TPM2_BASE + 0x0C)) // swapped
#define TPM2_DATA_REG   (*(volatile uint32_t *)(TPM2_BASE + 0x10)) // same

#define TPM_STATE_IDLE       0
#define TPM_STATE_RECEIVING  2
#define TPM_STATE_PROCESSING 3
#define TPM_STATE_SENDING    4

#define TPM2_CMD_GEN_RANDOM 0x01
#define TPM2_CMD_GEN_RSA    0x02
#define TPM2_CMD_CLEAR      0x03

#define TPM_ST_NO_SESSIONS   0x8001
#define TPM_CC_GetRandom     0x0000017B
#define TPM_CC_CreatePrimary 0x00000131
#define TPM_RH_OWNER         0x40000001
#define TPM_ALG_RSA          0x0001
#define TPM_ALG_SHA256       0x000B
#define TPM_ALG_NULL         0x0010

// Constants for NV_DefineSpace
#define TPM_CC_NV_DefineSpace 0x0000012A
#define TPM_RH_PLATFORM       0x4000000C

#define TPM_CMD_HEADER_SIZE 10

uint32_t Marshal_UINT16_BE(uint8_t *buffer, uint16_t value)
{
    buffer[0] = (value >> 8) & 0xFF;
    buffer[1] = value & 0xFF;
    return 2;
}

uint32_t Marshal_UINT32_BE(uint8_t *buffer, uint32_t value)
{
    buffer[0] = (value >> 24) & 0xFF;
    buffer[1] = (value >> 16) & 0xFF;
    buffer[2] = (value >> 8) & 0xFF;
    buffer[3] = value & 0xFF;
    return 4;
}

uint32_t Build_GetRandom_Command(uint8_t *buffer, uint16_t bytesRequested)
{
    uint32_t offset = TPM_CMD_HEADER_SIZE; // Start writing *after* the header

    // 1. Marshal the command body (parameters)
    offset += Marshal_UINT16_BE(buffer + offset, bytesRequested);

    // 2. Now 'offset' is the total command size
    uint32_t totalSize = offset;

    // 3. Go back and marshal the header
    offset = 0;
    offset += Marshal_UINT16_BE(buffer + offset, TPM_ST_NO_SESSIONS);
    offset += Marshal_UINT32_BE(buffer + offset, totalSize);
    offset += Marshal_UINT32_BE(buffer + offset, TPM_CC_GetRandom);

    // 4. Return the total size
    return totalSize;
}

uint32_t Build_CreatePrimary_Command(uint8_t *buffer)
{
    // This is a pre-built command for a standard 2048-bit RSA key
    // under the Owner hierarchy.
    const uint8_t cmd[] = {
      0x80, 0x01,                         // Tag: NO_SESSIONS
      0x00, 0x00, 0x00, 0x4E,             // Size: 78 bytes (0x4E)
      0x00, 0x00, 0x01, 0x31,             // Code: CreatePrimary
      0x40, 0x00, 0x00, 0x01,             // Handle: TPM_RH_OWNER
      
      // inSensitive (size 4)
      0x00, 0x04,                         // inSensitive.size = 4
      0x00, 0x00, 0x00, 0x00,             // inSensitive.data (empty auth)
      
      // inPublic (size 42)
      0x00, 0x2A,                         // inPublic.size = 42
      0x00, 0x01,                         //   type: TPM_ALG_RSA
      0x00, 0x0B,                         //   nameAlg: TPM_ALG_SHA256
      0x00, 0x00, 0x00, 0x72,             //   objectAttributes (fixed, user, decrypt, sign)
      0x00, 0x00,                         //   authPolicy.size = 0
      0x00, 0x10,                         //   parameters.rsa.symmetric.alg = NULL
      0x00, 0x10,                         //   parameters.rsa.scheme.alg = NULL
      0x08, 0x00,                         //   parameters.rsa.keyBits = 2048
      0x00, 0x00, 0x00, 0x00,             //   parameters.rsa.exponent = 0 (default)
      0x00, 0x00,                         //   unique.rsa.size = 0
      
      // outsideInfo (size 0)
      0x00, 0x00,
      
      // creationPCR (count 0)
      0x00, 0x00
    };
    
    uint32_t cmdSize = sizeof(cmd);
    for(uint32_t i = 0; i < cmdSize; i++) {
        buffer[i] = cmd[i];
    }

    uint32_t paddedSize = (cmdSize + 3) & ~3; // Align to 4 bytes
    for(uint32_t i = cmdSize; i < paddedSize; i++) {
        buffer[i] = 0; // Pad with zeros
    }
    
    Marshal_UINT32_BE(buffer + 2, paddedSize);

    return paddedSize;
}

uint32_t Build_NV_DefineSpace_Command(uint8_t *buffer)
{
    // This is a pre-built, 32-byte command.
    const uint8_t cmd[] = {
        // Header (10 bytes)
        0x80, 0x01,                         // Tag: NO_SESSIONS
        0x00, 0x00, 0x00, 0x20,             // Size: 32 bytes
        0x00, 0x00, 0x01, 0x2A,             // Code: TPM_CC_NV_DefineSpace
        // Body (22 bytes)
        0x40, 0x00, 0x00, 0x0C,             // authHandle: TPM_RH_PLATFORM
        0x00, 0x00,                         // auth.size = 0
        0x00, 0x0E,                         // public.size = 14
        0x01, 0x00, 0x00, 0x01,             //   nvIndex: 0x01000001
        0x00, 0x0B,                         //   nameAlg: SHA256
        0x00, 0x00, 0x40, 0x07,             //   attributes (PPWRITE|PPREAD|PLATFORMCREATE|READ_STCLEAR)
        0x00, 0x00,                         //   authPolicy.size = 0
        0x00, 0x20                          //   dataSize = 32
    };

    uint32_t cmdSize = sizeof(cmd); // 32 bytes
    for(uint32_t i = 0; i < cmdSize; i++) {
        buffer[i] = cmd[i];
    }
    
    // No padding needed, 32 is 4-byte aligned
    return cmdSize;
}


void tpm_send_command(const uint8_t *cmd_buf, uint32_t len)
{
    // 1. Tell TPM we are starting
    TPM2_CTRL_REG = 1; // Request RECEIVING state

    // Poll for the state change
    volatile uint32_t timeout = 100000;
    while (TPM2_STATUS_REG != TPM_STATE_RECEIVING && timeout > 0) {
        timeout--;
    }

    if (timeout == 0) {
        UART_printf("Error: TPM timed out entering RECEIVING state.\n");
        return;
    }

    UART_printf("Sending command (size %u)...\n", len);

    // 2. Write ALL command data to DATA FIFO
    for (uint32_t i = 0; i < len; i += 4)
    {
        // Build the 32-bit word from the Big-Endian array
        uint32_t word_be = ((uint32_t)cmd_buf[i + 0] << 24) |
                           ((uint32_t)cmd_buf[i + 1] << 16) |
                           ((uint32_t)cmd_buf[i + 2] << 8)  |
                           ((uint32_t)cmd_buf[i + 3]);
        
        TPM2_DATA_REG = word_be;
    }

    // 3. Tell TPM to execute *AFTER* the loop is finished
    TPM2_CMD_REG = 1; 
}

static uint32_t tpm_read_data_reg_be(void)
{
    uint32_t val = TPM2_DATA_REG;
    // The device writes BE, so we must swap it for our LE CPU
    return ((val >> 24) & 0x000000FF) |
           ((val >>  8) & 0x0000FF00) |
           ((val <<  8) & 0x00FF0000) |
           ((val << 24) & 0xFF000000);
}

uint32_t tpm_read_response(uint8_t *resp_buf, uint32_t max_len) {
  while (TPM2_STATUS_REG == TPM_STATE_PROCESSING) {
    // wait
  }

  if (TPM2_STATUS_REG != TPM_STATE_SENDING) {
    UART_printf("Error: TPM did not enter SENDING state\n");
    return 0;
  }

  UART_printf("Reading response...\n");

  uint32_t *p_resp32 = (uint32_t *)resp_buf;
    p_resp32[0] = tpm_read_data_reg_be(); // Bytes 0-3 (Tag, Size)
    p_resp32[1] = tpm_read_data_reg_be(); // Bytes 4-7 (Size, Code)
    p_resp32[2] = tpm_read_data_reg_be(); // Bytes 8-11 (Code, Params...)

    // 3. Parse the size from the header (bytes 2-5)
    uint32_t response_size = ((uint32_t)resp_buf[2] << 24) |
                             ((uint32_t)resp_buf[3] << 16) |
                             ((uint32_t)resp_buf[4] << 8)  |
                             ((uint32_t)resp_buf[5]);

    UART_printf("Response size from header: %u bytes.\n", response_size);

    if (response_size > max_len) {
        UART_printf("Error: Response buffer too small!\n");
        return 12; // Return bytes read so far
    }
    if (response_size < 10) {
         UART_printf("Error: Invalid response size!\n");
         return 12;
    }

    // 4. Read the rest of the data (we already read 12 bytes)
    uint32_t bytes_read = 12;
    while (bytes_read < response_size)
    {
        if (TPM2_STATUS_REG != TPM_STATE_SENDING) {
            UART_printf("Error: TPM stopped sending early!\n");
            return bytes_read;
        }
        
        // We only read in 4-byte chunks
        p_resp32[bytes_read / 4] = tpm_read_data_reg_be();
        bytes_read += 4;
    }

    UART_printf("Response read complete (%u bytes).\n", response_size);
    return response_size;
}

void print_menu(void)
{
    UART_printf("\n--- TPM Command Menu ---\n");
    UART_printf("1: TPM2_GetRandom (32 bytes)\n");
    UART_printf("2: TPM2_CreatePrimary (RSA 2048 key)\n");
    UART_printf("3: TPM2_NV_DefineSpace (32-byte index)\n");
    UART_printf("Select an option: ");
}

int main(void) {
  UART_init();
  UART_printf("--- TPM Firmware Test Started ---\n");

  uint8_t command_buffer[256];
  uint8_t response_buffer[1024];
  uint32_t cmd_size = 0, resp_size = 0;

  // uint8_t cmd_get_random[12] = {
  //   0x80, 0x01,             // Tag
  //   0x00, 0x00, 0x00, 0x0C, // Size
  //   0x00, 0x00, 0x01, 0x7B, // Code
  //   // Body
  //   0x00, 0x20              // BytesRequested
  // };

  while(1) {
    print_menu();

    char c = UART_getc();
    UART_printf("\n");

    switch (c) {
      case '1':
        cmd_size = Build_GetRandom_Command(command_buffer, 32);
        break;
      case '2':
        cmd_size = Build_CreatePrimary_Command(command_buffer);
        break;
      case '3':
        cmd_size = Build_NV_DefineSpace_Command(command_buffer);
        break;
      default:
        UART_printf("Invalid option '%c'\n", c);
        cmd_size = 0;
        break;
    }

    if (cmd_size > 0) {
      tpm_send_command(command_buffer, cmd_size);

      resp_size = tpm_read_response(response_buffer, sizeof(response_buffer));

      if (resp_size > 0) {
        UART_printf("Received Response (Hex):\n");
        UART_print_hex(response_buffer, resp_size);
      } else {
        UART_printf("Failed to get response.\n");
      }
    }

    // tpm_send_command(cmd_get_random, sizeof(cmd_get_random));

    // uint32_t resp_len = tpm_read_response(response_buffer, sizeof(response_buffer));

    // if (resp_len > 0) {
    //   UART_printf("Received Response (hex):\n");
    //   UART_print_hex(response_buffer, resp_len);
    //   UART_printf("\n");
    // } else {
    //   UART_printf("Failed to get response.\n");
    // }
    // UART_printf("--- Test Complete ---\n");
    // while (1);
  }
}
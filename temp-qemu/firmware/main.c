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
  0x00, 0x00, 0x00, 0x44,             // Size: 68 bytes
  0x00, 0x00, 0x01, 0x31,             // Code: TPM_CC_CreatePrimary

  // Body (40 bytes)
  0x40, 0x00, 0x00, 0x01,             // authHandle: TPM_RH_OWNER

  // inSensitive (TPM2B_SENSITIVE_CREATE)
  0x00, 0x0A,                         // size = 10
  0x00, 0x06,                         //   userAuth.size = 6
  0x70, 0x61, 0x73, 0x73, 0x77, 0x64, //   "passwd"
  0x00, 0x00,                         //   data.size = 0

  // inPublic (TPM2B_PUBLIC)
  0x00, 0x22,                         // size = 32
  0x00, 0x23,                         //   type: TPM_ALG_ECC
  0x00, 0x0B,                         //   nameAlg: SHA256
  0x00, 0x03, 0x00, 0x72,             //   objectAttributes
  0x00, 0x00,                         //   authPolicy.size = 0
  0x00, 0x10, 0x00, 0x00, 0x00, 0x00, //   symmetric: TPM_ALG_NULL
  0x00, 0x10, 0x00, 0x00, 0x00, 0x00, //   scheme: TPM_ALG_NULL
  0x00, 0x03,                         //   curveID = NIST_P256
  0x00, 0x10, 0x00, 0x00, 0x00, 0x00, //   kdf = TPM_ALG_NULL
  0x00, 0x00,                         //   unique.x.size
  0x00, 0x00,                         //   unique.y.size

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
  0x40, 0x00, 0x00, 0x01, // authHandle: TPM_RH_OWNER
  0x00, 0x00,             // auth.size = 0
  0x00, 0x0E,             // publicArea.size = 14
  0x01, 0x00, 0x00, 0x01, // nvIndex: 0x01000001
  0x00, 0x0B,             // nameAlg: TPM_ALG_SHA256
  0x02, 0x4C, 0x00, 0x06, // attributes
  0x00, 0x00,             // authPolicy.size = 0
  0x00, 0x20              // dataSize: 32
};

// TPM2_NV_Write - Write "TEST" to index 0x01000001
static const uint8_t CMD_NV_WRITE[] = {
  0x80, 0x01,             // Tag: TPM_ST_NO_SESSIONS
  0x00, 0x00, 0x00, 0x1C, // Size: 28 bytes
  0x00, 0x00, 0x01, 0x37, // Code: TPM_CC_NV_Write
  0x40, 0x00, 0x00, 0x0C, // authHandle: TPM_RH_PLATFORM
  0x01, 0x00, 0x00, 0x01, // nvIndex: 0x01000001
  0x00, 0x00,             // authSession.size = 0
  0x00, 0x04,             // data.size = 4
  'T', 'E', 'S', 'T',     // data = "TEST"
  0x00, 0x00              // offset = 0
};

// TPM2_NV_Read - Read 4 bytes from index 0x01000001
static const uint8_t CMD_NV_READ[] = {
  0x80, 0x01,             // Tag: TPM_ST_NO_SESSIONS
  0x00, 0x00, 0x00, 0x18, // Size: 24 bytes
  0x00, 0x00, 0x01, 0x4E, // Code: TPM_CC_NV_Read
  0x40, 0x00, 0x00, 0x0C, // authHandle: TPM_RH_PLATFORM
  0x01, 0x00, 0x00, 0x01, // nvIndex: 0x01000001
  0x00, 0x00,             // authSession.size = 0
  0x00, 0x04,             // sizeToRead = 4
  0x00, 0x00              // offset = 0
};


/* 1) Malformed header: declared size larger than actual payload
 * Tests:
 *  - Boundary/length-check validation (CWE-20)
 *  - Potential out-of-bounds read if parser trusts header (CWE-125)
 * Why:
 *  - Header declares 48 bytes but fewer bytes are actually sent.
 * Expected safe behavior:
 *  - TPM should check received length == header.size and return TPM_RC_COMMAND_SIZE/TPM_RC_INSUFFICIENT.
 */
static const uint8_t CMD_BAD_HDR[] = {
  0x80,0x01,             /* tag: TPM_ST_NO_SESSIONS */
  0x00,0x00,0x00,0x30,  /* size: 48 (deliberately lies) */
  0x00,0x00,0x01,0x7B,  /* TPM_CC_GetRandom */
  0x00,0x04             /* bytesRequested = 4 */
};




/* 2) GetRandom requesting an enormous number of bytes
 * Tests:
 *  - Parameter bounds checks (CWE-20)
 *  - Resource exhaustion / DoS potential (CWE-400)
 * Why:
 *  - Asking for 65535 bytes; code must cap and validate this.
 * Expected safe behavior:
 *  - Return TPM_RC_SIZE or similar; do not allocate/return unsafe amount of data.
 */
static const uint8_t CMD_GET_RANDOM_TOO_BIG[] = {
  0x80,0x01,
  0x00,0x00,0x00,0x0C,   /* size = 12 */
  0x00,0x00,0x01,0x7B,   /* TPM_CC_GetRandom */
  0xFF,0xFF              /* bytesRequested = 65535 (too large) */
};


/* 3) NV_Read specifying sizeToRead larger than NV index data size
 * Tests:
 *  - Out-of-bounds read / info disclosure (CWE-125, CWE-200)
 *  - Return TPM_RC_NV_RANGE and do not leak bytes beyond the NV entry.
 */
static const uint8_t CMD_NV_READ_OVERSIZE[] = {
  0x80,0x01,
  0x00,0x00,0x00,0x18,   /* size = 24 */
  0x00,0x00,0x01,0x4E,   /* TPM_CC_NV_Read */
  0x40,0x00,0x00,0x0C,   /* authHandle: TPM_RH_PLATFORM */
  0x01,0x00,0x00,0x01,   /* nvIndex: 0x01000001 */
  0x00,0x00,             /* authSession.size = 0 */
  0x04,0x00,             /* sizeToRead = 1024 (0x0400) */
  0x00,0x00              /* offset = 0 */
};


/* 4) NV_Write claiming a very large data.size (but array truncated)
 * Tests:
 *  - Out-of-bounds write / buffer overflow (CWE-120, CWE-787)
 *  - Proper validation of declared payload length vs actual input
 * Why:
 *  - Declares data.size = 512 but the packet is truncated.
 * Expected safe behavior:
 *  - Unmarshal fails with TPM_RC_INSUFFICIENT or TPM_RC_SIZE; no write attempted.
 */
static const uint8_t CMD_NV_WRITE_OVERSIZE[] = {
    /* Header */
    0x80, 0x01,             /* tag = TPM_ST_NO_SESSIONS */
    0x00, 0x00, 0x00, 0x3D, /* size = 61 bytes (10 header + 51 body) */
    0x00, 0x00, 0x01, 0x37, /* TPM_CC_NV_Write */
    0x40, 0x00, 0x00, 0x0C, /* authHandle = TPM_RH_PLATFORM (as used previously) */
    0x01, 0x00, 0x00, 0x01, /* nvIndex = 0x01000001 */
    0x00, 0x00,             /* authSession.size = 0 */
    /* TPM2B_MAX_NV_BUFFER: size + data (size = 0x0021 = 33) */
    0x00, 0x21,             /* data.size = 33 (one byte larger than 32) */
    /* 33 bytes of payload (here ASCII 'A' repeated) */
    'A','A','A','A','A','A','A','A','A','A',
    'A','A','A','A','A','A','A','A','A','A',
    'A','A','A','A','A','A','A','A','A','A',
    'A',
    /* offset */
    0x00, 0x00              /* offset = 0 */
};


/* 5) NV_Write with format-style tokens inside user data
 * Tests:
 *  - Format string misuse when printing/writing logs (CWE-134)
 * Why:
 *  - If implementation mistakenly does something like qemu_log(e->data) or printf(e->data),
 *    format tokens could be interpreted.

 */
static const uint8_t CMD_NV_WRITE_FMT_STR[] = {
    0x80,0x01,
    0x00,0x00,0x00,0x2B,   /* total = 43 bytes */
    0x00,0x00,0x01,0x37,   /* TPM_CC_NV_Write */
    0x40,0x00,0x00,0x0C,
    0x01,0x00,0x00,0x01,
    0x00,0x00,
    0x00,0x0B,             /* data.size = 11 */
    '%','x','%','s','%','n','A','B','C',0x00,0x01,
    0x00,0x00              /* offset = 0 */
};
//Test for escape characters

/* 6) NV_Read of unwritten index (uninitialized memory test)
 * Tests:
 *  - Use of uninitialized memory (CWE-457), information disclosure (CWE-200)
 * Why:
 *  - Reading an index that hasn't been written should be rejected.
 * Expected safe behavior:
 *  - Return TPM_RC_NV_UNINITIALIZED; do not return bank contents.
 */
static const uint8_t CMD_NV_READ_UNINIT[] = {
  0x80,0x01,
  0x00,0x00,0x00,0x18,
  0x00,0x00,0x01,0x4E,   /* TPM_CC_NV_Read */
  0x40,0x00,0x00,0x0C,
  0x01,0x00,0x00,0x02,   /* nvIndex: 0x01000002 (avoid one you wrote to) */
  0x00,0x00,
  0x00,0x04,             /* sizeToRead = 4 */
  0x00,0x00              /* offset = 0 */
};


/* 7) Integer overflow attempt (GetRandom with huge size)
 * Tests:
 *  - Integer overflow / arithmetic wrap-around leading to bypass of checks (CWE-190)
 * Why:
 *  - Very large size values can wrap an 'offset + length' check if not handled as unsigned 64/32 with overflow checks.
 * Expected safe behavior:
 *  - Detect overflow / disallow obviously too-large values and return TPM_RC_SIZE.
 */
static const uint8_t CMD_INT_OVERFLOW[] = {
  0x80,0x01,
  0x00,0x00,0x00,0x0C,
  0x00,0x00,0x01,0x7B,   /* TPM_CC_GetRandom */
  0xFF,0xFF              /* bytesRequested = 65535 */
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
    UART_printf("2: TPM2_CreatePrimary (ECC P-256 primary storage key)\n");
    UART_printf("3: TPM2_NV_DefineSpace (32-byte index)\n");
    UART_printf("4: TPM2_NV_Write (\"TEST\" to index)\n");
    UART_printf("5: TPM2_NV_Read (4 bytes from index)\n");
    UART_printf("6: Test: BAD_HDR (header size mismatch)\n");
    UART_printf("7: Test: GetRandom_TOO_BIG (parameter bounds)\n");
    UART_printf("8: Test: NV_READ_OVERSIZE (out-of-bounds read)\n");
    UART_printf("9: Test: NV_WRITE_OVERSIZE (out-of-bounds write)\n");
    UART_printf("a: Test: NV_WRITE_FMT_STR (format-string payload)\n");
    UART_printf("b: Test: NV_READ_UNINIT (uninitialized read)\n");
    UART_printf("c: Test: INT_OVERFLOW (integer overflow attempt)\n");
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

      case '4':
        cmd_to_send = CMD_NV_WRITE;
        cmd_size = sizeof(CMD_NV_WRITE);
        break;

      case '5':
        cmd_to_send = CMD_NV_READ;
        cmd_size = sizeof(CMD_NV_READ);
        break;

      case '6':
      cmd_to_send = CMD_BAD_HDR;
      cmd_size = sizeof(CMD_BAD_HDR);
        break;

      case '7':
      cmd_to_send = CMD_GET_RANDOM_TOO_BIG;
      cmd_size = sizeof(CMD_GET_RANDOM_TOO_BIG);
      break;

      case '8':
      cmd_to_send = CMD_NV_READ_OVERSIZE;
      cmd_size = sizeof(CMD_NV_READ_OVERSIZE);
      break;

      case '9':
      cmd_to_send = CMD_NV_WRITE_OVERSIZE;
      cmd_size = sizeof(CMD_NV_WRITE_OVERSIZE);
      break;

      case 'a':
      case 'A':
      cmd_to_send = CMD_NV_WRITE_FMT_STR;
      cmd_size = sizeof(CMD_NV_WRITE_FMT_STR);
      break;

      case 'b':
      case 'B':
      cmd_to_send = CMD_NV_READ_UNINIT;
      cmd_size = sizeof(CMD_NV_READ_UNINIT);
      break;

      case 'c':
      case 'C':
      cmd_to_send = CMD_INT_OVERFLOW;
      cmd_size = sizeof(CMD_INT_OVERFLOW);
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
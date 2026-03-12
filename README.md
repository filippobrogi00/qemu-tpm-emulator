# QEMU TPM 2.0 Module

## Description
Design and implementation of a generic TPM 2.0 hardware module, emulated using QEMU, with a focus on Command Chain implementation and Cryptographic Key Management.

### Reference Documentation
- TCG TPM 2.0 Library Architecture https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
- TCG TPM 2.0 Library Structures https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-2-Structures.pdf
- TCG TPM 2.0 Library Commands https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-3-Commands.pdf
- TCG TPM 2.0 Library Commands (Code) https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-3-Commands-Code.pdf
- TCG TPM 2.0 Library Supporting Routines https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-4-Supporting-Routines.pdf
- TCG TPM 2.0 Library Supporting Routines (Code) https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-4-Supporting-Routines-Code.pdf
- Tame the QEMU https://github.com/quarkslab/sstic-tame-the-qemu

## Project Structure

- **`firmware/`** — Bare-metal firmware running on the emulated ARM target:
  - `main.c` — Entry point; initializes TPM communication and issues TPM 2.0 commands.
  - `uart.c` / `uart.h` — UART driver for serial I/O between firmware and QEMU.
  - `startup.s` — ARM startup assembly (vector table, stack init, branch to `main`).
  - `linker.ld` — Linker script defining memory layout for the firmware image.
  - `makefile` / `build_and_run.sh` — Build toolchain and launch helpers.
  - `test/` — Unit tests for firmware-level TPM command validation.
- **`qemu/`** — Modified QEMU with TPM device emulation support:
  - Custom TPM 2.0 device model integrated into the QEMU machine.
  - Built via `build.sh` / `configure` / `meson.build`.
- **`Documentation.pdf`** — Detailed technical report with TPM System Architecture, Software Design, Testing, and possible future improvements.

## Implementation Components

### TPM Command Chain Implementation

The command chain follows the TPM 2.0 specification byte-level protocol:

- **Command Preparation** — Construct well-formed TPM 2.0 command buffers (tag, size, command code, and parameter area) according to TCG Part 2 (Structures) and Part 3 (Commands).
- **Command Transmission** — Serialize the command byte stream and deliver it to the simulated TPM device over the QEMU virtual transport (memory-mapped I/O or UART-forwarded channel).
- **Response Handling** — Parse the TPM response buffer, extract the response code, and decode output parameters (handles, digests, key blobs).
- **Error Management** — Interpret TPM 2.0 response codes (TPM_RC), distinguish between format-one and format-zero errors, and propagate meaningful diagnostics to the caller.

### Cryptographic Key Management

- **Asymmetric Key Pair Generation** — Invoke `TPM2_CreatePrimary` / `TPM2_Create` to generate RSA key pairs within the TPM's simulated hierarchy (Storage, Endorsement, Platform).
- **Secure Key Storage** — Persist key objects in the TPM's simulated NV storage; manage parent-child key relationships under the storage hierarchy.
- **Key Lifecycle Management** — Handle key loading (`TPM2_Load`), context save/restore, and flushing of transient objects from the TPM's object slots.
- **Basic Cryptographic Operations** — Perform RSA encrypt/decrypt and signing/verification operations using TPM-resident keys.

## Technical Architecture

1. **Software Simulation Layer**
   - *Command Parsing Mechanism* — Receives the raw byte stream from the guest firmware, decodes the TPM 2.0 command header (tag, commandSize, commandCode), and dispatches to the appropriate command handler.
   - *State Management* — Maintains internal TPM state: active sessions, loaded objects, hierarchy authorizations, and NV indices — mirroring the state machine of a physical TPM.
   - *Simulated Hardware Interaction* — Exposes a device interface (MMIO registers or virtio transport) through which the guest firmware sends commands and receives responses; manages command/response FIFO and status signaling.

2. **Cryptographic Module**
   - *RSA Key Generation* — Software-based RSA key pair generation (2048-bit) using QEMU-hosted cryptographic primitives.
   - *Key Integrity Verification* — Validates key structure consistency, checks integrity HMACs on wrapped key blobs, and verifies authorization values before use.
   - *Secure Storage Simulation* — Emulates TPM NV memory for sealed key storage with access-controlled read/write policies.

3. **Firmware Layer**
   - *TPM Command Builders* — C functions in `firmware/main.c` that construct and marshal TPM 2.0 command structures.
   - *UART Communication* — `firmware/uart.c` provides the low-level byte I/O used to exchange TPM command/response buffers with the QEMU device model.
   - *Board Startup* — `firmware/startup.s` and `firmware/linker.ld` configure the bare-metal execution environment on the emulated ARM platform.

## License
This project is licensed under the GPL-2.0 License - see the LICENSE file for details.

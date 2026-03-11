# QEMU TPM 2.0 Module

## Description
Design and implementation a generic TPM simulation in QEMU, with a focus on practical command chain implementation and a selected module development.

### Reference Documentation
- TCG TPM 2.0 Library Architecture https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
- TCG TPM 2.0 Library Structures https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-2-Structures.pdf
- TCG TPM 2.0 Library Commands https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-3-Commands.pdf
- TCG TPM 2.0 Library Commands (Code) https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-3-Commands-Code.pdf
- TCG TPM 2.0 Library Supporting Routines https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-4-Supporting-Routines.pdf
- TCG TPM 2.0 Library Supporting Routines (Code) https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-4-Supporting-Routines-Code.pdf
- Tame the QEMU https://github.com/quarkslab/sstic-tame-the-qemu

## Implementation Components

### 1. TPM Command Chain Implementation
#### Key Command Structures
- Command Preparation
- Command Transmission
- Response Handling
- Error Management

### 2. Selected TPM Module: Cryptographic Key Management
#### Chosen Module: Key Generation and Storage

#### Specific Implementation Features
- Asymmetric Key Pair Generation
- Secure Key Storage
- Key Lifecycle Management
- Basic Cryptographic Operations

## Technical Architecture
1. **Software Simulation Layer**
   - Command Parsing Mechanism: When the simulator receives a command, this component reads that byte stream. It decodes the command to figure out which TPM command is being requested.
   - State Management: A real TPM maintains internal state.
   - Simulated Hardware Interaction: It defines the API or mechanism through which external software sends commands to the simulator and receives responses from it. It manages the flow of command/response data.

2. **Cryptographic Module**
   - RSA Key Generation
   - Key Integrity Verification
   - Secure Storage Simulation

Complete detailed information can be found inside `Documentation.pdf`.

## License
This project is licensed under the GPL-2.0 License - see the LICENSE file for details.
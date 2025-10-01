# GNU ARM Embedded Toolchain
ARM_GNU ?= arm-none-eabi

# Compiler flags
AARCH = -mcpu=cortex-m7
CFLAGS = -c -Wall $(AARCH) -mthumb
DEBUG_FLAGS = -g3 -O0

# Assembler flags
ASFLAGS = $(AARCH)

# Linker flags
LDFLAGS = -T $(ld_script).ld

# Default target
.DEFAULT_GOAL := all

# Files
ld_script = linker
startup = startup
main = main
uart = uart

# QEMU Configuration
QEMU_FLAGS = -M nxps32k3x8evb -nographic
qemu_exec = ../qemu/build/qemu-system-arm $(QEMU_FLAGS) -kernel $(main).elf

# Object files
OBJS = $(startup).o $(main).o $(uart).o
OBJS_DBG = $(startup)_dbg.o $(main)_dbg.o $(uart)_dbg.o

# Rules
# Compile and link
all: $(OBJS) link

# Compile and link with debug information
debug: $(OBJS_DBG) link_dbg

#init make to initialize dependencies
init:
	@echo "Installing required packages..."
	sudo apt update
	sudo apt install -y \
		build-essential \
		python3 \
		python3-pip \
		git \
		flex \
		bison \
		libglib2.0-dev \
		libpixman-1-dev \
		zlib1g-dev \
		libfdt-dev \
		libtool \
		autoconf \
		automake \
		pkg-config \
		libsdl2-dev \
		libsdl2-image-dev \
		ninja-build \
		python3-sphinx \
		gcc-arm-linux-gnueabi \
		gcc-arm-none-eabi \
		gdb-multiarch \
		virt-what \
		openssl \
		libssl-dev
	pip3 install tomli

# Run QEMU
qemu_start:
	$(qemu_exec)

# Run QEMU to stop at the first instruction and open the localhost:1234
qemu_debug:
	$(qemu_exec) -s -S

# Pattern rules for object files
# Compile all the .c files to .o files
%.o: %.c
	$(ARM_GNU)-gcc $(CFLAGS) $< -o $@

# Compile all the .c files to _dbg.o files (debug information)
%_dbg.o: %.c
	$(ARM_GNU)-gcc $(CFLAGS) $(DEBUG_FLAGS) $< -o $@

# Assemble all the .s files to .o files
%.o: %.s
	$(ARM_GNU)-as $(ASFLAGS) $< -o $@

# Assemble all the .s files to _dbg.o files (debug information)
%_dbg.o: %.s
	$(ARM_GNU)-as $(ASFLAGS) -g $< -o $@

# Linking
# Link all the files defined in OBJS (.o files) to the main.elf file
link:
	$(ARM_GNU)-ld $(LDFLAGS) $(OBJS) -o $(main).elf

# Link all the files defined in OBJS_DBG (_dbg.o files) to the main.elf file
link_dbg:
	$(ARM_GNU)-ld $(LDFLAGS) $(OBJS_DBG) -o $(main).elf

# GDB
gdb_start:
	gdb-multiarch $(main).elf

# Clean up all the .o and .elf files
clean:
	rm -f *.o *.elf
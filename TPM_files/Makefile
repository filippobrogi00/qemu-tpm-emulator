# ------------------------------------------------------------
# TPM2 NV Module Build (Spec 1.84 - DefineSpace)
# ------------------------------------------------------------

# Compiler and flags
CC      := gcc
CFLAGS  := -Wall -std=c11 -I. $(shell pkg-config --cflags glib-2.0)
LDFLAGS := $(shell pkg-config --libs glib-2.0)

# Source files
SRC     := tpm2_nv.c
OBJ     := $(SRC:.c=.o)
BIN     := tpm2_nv

# Default build target
all: $(BIN)

# Build executable (with test main enabled)
$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -DTEST_MAIN -o $@ $^ $(LDFLAGS)

# Compile object file
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean all build artifacts
clean:
	rm -f $(OBJ) $(BIN)

# Run test build directly
run: all
	./$(BIN)

# ------------------------------------------------------------
# Usage:
#   make        -> build executable
#   make run    -> build and run test
#   make clean  -> remove build files
# ------------------------------------------------------------

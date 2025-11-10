# This is a simple Makefile for the p2p-quic project

# Compiler and flags
CC = gcc
CFLAGS = -g -Wall -I./include
LDFLAGS = -lmsquic -lcrypto

# Directories
SRCDIR = src
INCDIR = include
OBJDIR = obj
BINDIR = bin

# Find all .c files in the source directory
SRCS = $(wildcard $(SRCDIR)/*.c)
# Replace the .c extension with .o and put them in the obj directory
OBJS = $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SRCS))

# The final executable name
TARGET = $(BINDIR)/p2p_peer

# Default target
all: $(TARGET)

# Rule to link the final executable
$(TARGET): $(OBJS)
	@mkdir -p $(BINDIR)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)
	@echo "Linking complete: $(TARGET)"

# Rule to compile .c files into .o files
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "Compiled $<"

# Clean up build artifacts
clean:
	rm -rf $(OBJDIR) $(BINDIR)
	@echo "Cleaned up build artifacts."

# Phony targets
.PHONY: all clean

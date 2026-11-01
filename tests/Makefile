# Host (PC) unit tests for the hardware-independent firmware modules.
#
#   make            build and run the tests   (Windows: mingw32-make)
#   make SAN=1      same, with AddressSanitizer + UBSan (Linux/macOS, used by CI):
#                   any read past the end of a frame buffer crashes the test
#   make clean

# make's built-in default is "cc", which does not exist on Windows: use gcc
# unless a compiler was given on the command line (make CC=clang).
ifeq ($(origin CC),default)
CC      := gcc
endif
CFLAGS  := -std=c11 -Wall -Wextra -Werror -O1 -g -I../Core/Inc

ifeq ($(SAN),1)
CFLAGS  += -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all
endif

# Firmware sources under test: the same files the STM32 build compiles.
FW_SRC   := ../Core/Src/pkt_parse.c ../Core/Src/pkt_filter.c ../Core/Src/filter_policy.c
TEST_SRC := test_main.c test_pkt_parse.c test_pkt_filter.c test_filter_policy.c

# Shell commands differ between Windows (cmd.exe) and Linux/macOS (sh).
ifeq ($(OS),Windows_NT)
SHELL    := cmd.exe
BIN      := build/run_tests.exe
MKDIR    := if not exist build mkdir build
RUN      := build\run_tests.exe
RMDIR    := if exist build rmdir /s /q build
else
BIN      := build/run_tests
MKDIR    := mkdir -p build
RUN      := ./build/run_tests
RMDIR    := rm -rf build
endif

.PHONY: all test clean
all: test

$(BIN): $(FW_SRC) $(TEST_SRC) $(wildcard *.h) $(wildcard ../Core/Inc/pkt_*.h) ../Core/Inc/filter_policy.h
	@$(MKDIR)
	$(CC) $(CFLAGS) $(FW_SRC) $(TEST_SRC) -o $@

test: $(BIN)
	$(RUN)

clean:
	$(RMDIR)

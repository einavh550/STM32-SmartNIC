# Host (PC) unit tests for the hardware-independent firmware modules.
#
#   make            build and run the tests   (Windows: mingw32-make)
#   make SAN=1      same, with AddressSanitizer + UBSan (Linux/macOS, used by CI):
#                   any read past the end of a frame buffer crashes the test
#   make tsan       2-thread ring buffer stress test under ThreadSanitizer
#                   (Linux/macOS, used by CI): reports any data race
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
FW_SRC   := ../Core/Src/pkt_parse.c ../Core/Src/pkt_filter.c ../Core/Src/filter_policy.c \
            ../Core/Src/pkt_reflect.c
TEST_SRC := test_main.c test_pkt_parse.c test_pkt_filter.c test_filter_policy.c \
            test_pkt_reflect.c

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

.PHONY: all test tsan clean
all: test

$(BIN): $(FW_SRC) $(TEST_SRC) $(wildcard *.h) $(wildcard ../Core/Inc/pkt_*.h) ../Core/Inc/filter_policy.h
	@$(MKDIR)
	$(CC) $(CFLAGS) $(FW_SRC) $(TEST_SRC) -o $@

test: $(BIN)
	$(RUN)

# Ring buffer under real concurrency: producer and consumer are two threads.
# Own binary because TSan cannot be combined with ASan. halt_on_error makes
# the first race fail the run (exit code != 0), so CI turns red.
TSAN_BIN := build/ring_buffer_threads

$(TSAN_BIN): ../Core/Src/ring_buffer.c test_ring_buffer_threads.c ../Core/Inc/ring_buffer.h ../Core/Inc/pkt_flags.h
	@$(MKDIR)
	$(CC) -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -O1 -g -I../Core/Inc -fsanitize=thread -pthread \
		../Core/Src/ring_buffer.c test_ring_buffer_threads.c -o $@

tsan: $(TSAN_BIN)
	TSAN_OPTIONS=halt_on_error=1 ./$(TSAN_BIN)

clean:
	$(RMDIR)

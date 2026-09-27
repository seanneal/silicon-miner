# Educational silicon-miner — Apple Silicon / arm64 only for the shipping binary.
# Linux hosts can assemble the same Mach-O hash path as ELF and run it under
# qemu-aarch64 (correctness). That is not an Apple Silicon H/s measurement.
AS      ?= as
CC      ?= clang
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)

ARCH    = -arch arm64
# clang driver assembles .s more reliably with +crypto on Apple CLT
ASFLAGS = $(ARCH)
CFLAGS  = $(ARCH) -O2 -Wall -Wextra -std=c11 -pthread
LDFLAGS = $(ARCH) -pthread

OBJS    = sha256d_mine.o harness.o stratum.o
TARGET  = miner_test

.PHONY: all clean run metrics testnet

all: $(TARGET)

# Use clang to assemble so -arch arm64 enables CE instructions cleanly
sha256d_mine.o: sha256d_mine.s
	$(CC) $(ASFLAGS) -c -o $@ $<

harness.o: harness.c stratum.h mono_clock.h
	$(CC) $(CFLAGS) -c -o $@ $<

stratum.o: stratum.c stratum.h mono_clock.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

run: $(TARGET)
	./$(TARGET)

# No-power metrics: .text size + asm H/s + CommonCrypto H/s + easy-target TTFN
metrics: $(TARGET)
	@echo "=== make metrics: sha256d_mine.o sizes ==="
	size -m sha256d_mine.o
	@echo "=== make metrics: harness --metrics ==="
	./$(TARGET) --metrics

# Bitcoin testnet3 via public BTCLab Stratum (throwaway tb1 user; suggest_diff=0.001)
testnet: $(TARGET)
	./$(TARGET) --testnet --seconds 90 --max-shares 1

clean:
	rm -f $(OBJS) $(TARGET)

else

# Linux / cloud VM: Mach-O @PAGE asm is not native. Cross-assemble to ELF and
# run under qemu-user. Requires aarch64-linux-gnu-gcc and qemu-aarch64-static.
CROSS   ?= aarch64-linux-gnu-gcc
QEMU    ?= qemu-aarch64-static
CFLAGS  = -O2 -Wall -Wextra -std=c11 -pthread
LDFLAGS = -static -pthread

OBJS    = sha256d_mine.o harness.o stratum.o
TARGET  = miner_test.aarch64
ELF_ASM = sha256d_mine.elf.s

.PHONY: all clean run metrics testnet qemu-selftest

all: qemu-selftest

$(ELF_ASM): sha256d_mine.s scripts/macho_to_elf_asm.py
	python3 scripts/macho_to_elf_asm.py sha256d_mine.s $(ELF_ASM)

sha256d_mine.o: $(ELF_ASM)
	$(CROSS) -c -o $@ $(ELF_ASM)

harness.o: harness.c stratum.h mono_clock.h
	$(CROSS) $(CFLAGS) -c -o $@ $<

stratum.o: stratum.c stratum.h mono_clock.h
	$(CROSS) $(CFLAGS) -c -o $@ $<

$(TARGET): $(OBJS)
	$(CROSS) $(LDFLAGS) -o $@ $(OBJS)

# Self-test + short multi-thread batch, control then E7 treatment.
# H/s here is qemu, not M1.
qemu-selftest: $(TARGET)
	$(QEMU) -cpu max ./$(TARGET) --threads 2 --dual-job off 20000
	$(QEMU) -cpu max ./$(TARGET) --threads 2 --dual-job on 20000

run: $(TARGET)
	$(QEMU) -cpu max ./$(TARGET) --threads 2 20000

metrics: $(TARGET)
	$(QEMU) -cpu max ./$(TARGET) --metrics --threads 2 50000

testnet:
	@echo "testnet Stratum is for the Apple Silicon miner_test binary (make on macOS)"
	@exit 1

clean:
	rm -f $(OBJS) $(TARGET) $(ELF_ASM)

endif

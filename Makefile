# Educational silicon-miner — Apple Silicon / arm64 only
AS      ?= as
CC      ?= clang
ARCH    = -arch arm64
# clang driver assembles .s more reliably with +crypto on Apple CLT
ASFLAGS = $(ARCH)
CFLAGS  = $(ARCH) -O2 -Wall -Wextra -std=c11
LDFLAGS = $(ARCH)

OBJS    = sha256d_mine.o harness.o stratum.o
TARGET  = miner_test

.PHONY: all clean run metrics testnet

all: $(TARGET)

# Use clang to assemble so -arch arm64 enables CE instructions cleanly
sha256d_mine.o: sha256d_mine.s
	$(CC) $(ASFLAGS) -c -o $@ $<

harness.o: harness.c stratum.h
	$(CC) $(CFLAGS) -c -o $@ $<

stratum.o: stratum.c stratum.h
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

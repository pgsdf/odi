# ODI Makefile
# Zig version: 0.15.2

ZIG ?= zig
BIN ?= odi

.PHONY: all build clean verify fmt

all: build

build:
	$(ZIG) build

clean:
	$(ZIG) build clean

fmt:
	$(ZIG) fmt src/*.zig

# Verify runs the CLI validator over all test vectors.
# Passing vectors must succeed.
# Failing vectors must fail.
verify: build
	@set -e; \
	binpath="./zig-out/bin/$(BIN)"; \
	if [ ! -x "$$binpath" ]; then \
		binpath="./$(BIN)"; \
	fi; \
	if [ ! -x "$$binpath" ]; then \
		echo "error: odi binary not found at ./zig-out/bin/$(BIN) or ./$(BIN)"; \
		exit 1; \
	fi; \
	echo "using $$binpath"; \
	pass=0; fail=0; \
	for f in tests/vectors/*.odi; do \
		base=$$(basename "$$f"); \
		case "$$base" in \
			odi-fail-*|*fail* ) \
				if "$$binpath" validate "$$f" >/dev/null 2>&1; then \
					echo "FAIL (unexpected pass): $$f"; \
					exit 1; \
				else \
					echo "ok (expected fail): $$f"; \
					fail=$$((fail+1)); \
				fi \
				;; \
			* ) \
				if "$$binpath" validate "$$f" >/dev/null 2>&1; then \
					echo "ok: $$f"; \
					pass=$$((pass+1)); \
				else \
					echo "FAIL (unexpected fail): $$f"; \
					exit 1; \
				fi \
				;; \
		esac; \
	done; \
	echo "verify complete: $$pass passing, $$fail failing"

# secator-rs Makefile.
#
# Quick reference:
#   make           build the dev binary at target/debug/secator
#   make dev       build dev + symlink ~/.local/bin/secator-rs → target/debug/secator
#   make test      run the full workspace test suite
#   make release   build the optimised binary at target/release/secator
#   make lint      cargo clippy --workspace --no-deps
#   make fmt       cargo fmt --all
#   make clean     cargo clean
#   make help      print this list

CARGO ?= cargo
BIN_DIR ?= $(HOME)/.local/bin
INSTALL_NAME ?= secator-rs
DEBUG_BIN := target/debug/secator
RELEASE_BIN := target/release/secator

# Workaround for a rustc 1.92 LLVM codegen SIGSEGV under high parallelism
# (`error: rustc interrupted by SIGSEGV`). Documented upstream — bumping
# the codegen thread stack avoids the crash. Harmless on healthy toolchains.
export RUST_MIN_STACK ?= 16777216

.PHONY: all build dev test release lint fmt clean help

all: build

build:
	$(CARGO) build --workspace

dev: build
	@mkdir -p $(BIN_DIR)
	@ln -sf $(CURDIR)/$(DEBUG_BIN) $(BIN_DIR)/$(INSTALL_NAME)
	@echo "Linked $(BIN_DIR)/$(INSTALL_NAME) -> $(CURDIR)/$(DEBUG_BIN)"
	@command -v $(INSTALL_NAME) >/dev/null 2>&1 || \
		echo "Note: $(BIN_DIR) is not on PATH — add it to your shell rc."

test:
	$(CARGO) test --workspace

release:
	$(CARGO) build --workspace --release

lint:
	$(CARGO) clippy --workspace --no-deps

fmt:
	$(CARGO) fmt --all

clean:
	$(CARGO) clean

help:
	@awk 'BEGIN{FS=":.*##"} /^[a-zA-Z_-]+:.*##/{printf "  %-10s %s\n",$$1,$$2}' $(MAKEFILE_LIST) 2>/dev/null || \
		sed -n 's/^# *//p' $(firstword $(MAKEFILE_LIST)) | head -12

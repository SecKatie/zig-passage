.PHONY: all build release install uninstall clean test run

PREFIX ?= $(HOME)/.local
BINDIR := $(PREFIX)/bin

all: build

build:
	zig build

release:
	zig build -Doptimize=ReleaseFast

test:
	zig build test

run:
	zig build run

install: release
	@mkdir -p $(BINDIR)
	@cp zig-out/bin/passage $(BINDIR)/passage
	@echo "Installed passage to $(BINDIR)/passage"
	@if ! echo "$$PATH" | grep -q "$(BINDIR)"; then \
		echo ""; \
		echo "WARNING: $(BINDIR) is not in your PATH"; \
		echo "Add it to your shell config:"; \
		echo "  export PATH=\"$(BINDIR):\$$PATH\""; \
	fi

uninstall:
	@rm -f $(BINDIR)/passage
	@echo "Removed $(BINDIR)/passage"

clean:
	rm -rf zig-out .zig-cache
	rm -rf libs/zxing-cpp/wrappers/zig/zig-out

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build     Build debug binary (default)"
	@echo "  release   Build optimized release binary"
	@echo "  install   Install to ~/.local/bin (or PREFIX=path)"
	@echo "  uninstall Remove from ~/.local/bin"
	@echo "  test      Run tests"
	@echo "  run       Build and run"
	@echo "  clean     Remove build artifacts"
	@echo "  help      Show this help"

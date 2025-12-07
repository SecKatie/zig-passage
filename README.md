# passage

A password manager using [age](https://age-encryption.org/) encryption, written in Zig. Compatible with [passage](https://github.com/FiloSottile/passage) stores.

## Features

- Age encryption (no GPG required)
- QR code display for passwords
- Clipboard integration
- Git integration for syncing
- Tree-style password listing
- Search by name or content

## Requirements

### Build Dependencies

- [Zig](https://ziglang.org/) 0.14.0 or later
- [Rust](https://rustup.rs/) (for age encryption library)
- [CMake](https://cmake.org/) (for zxing-cpp)
- C++ compiler (clang++ or g++)

### Runtime Dependencies

None! All dependencies are statically linked.

## Building & Installing

### 1. Install build dependencies

**macOS:**
```bash
# Xcode Command Line Tools (provides C++ compiler and system frameworks)
xcode-select --install

# Build tools
brew install zig rust cmake
```

**Ubuntu/Debian:**
```bash
# C++ compiler, CMake, and standard library
sudo apt install cmake build-essential libstdc++-12-dev

# Zig - download from https://ziglang.org/download/
# Or use snap: sudo snap install zig --classic --beta

# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

**Fedora:**
```bash
sudo dnf install cmake gcc-c++ libstdc++-devel zig rust cargo
```

**Arch Linux:**
```bash
sudo pacman -S zig rust cmake base-devel
```

### 2. Clone and build

```bash
# Clone with submodules
git clone --recursive https://github.com/SecKatie/zig-passage.git
cd zig-passage

# If you already cloned without --recursive:
git submodule update --init --recursive

# Build and install to ~/.local/bin
make install

# Or install to a custom location
make install PREFIX=/usr/local
```

### Make Targets

| Target | Description |
|--------|-------------|
| `make build` | Build debug binary |
| `make release` | Build optimized release binary |
| `make install` | Build release and install to `~/.local/bin` |
| `make uninstall` | Remove from `~/.local/bin` |
| `make test` | Run tests |
| `make run` | Build and run |
| `make clean` | Remove build artifacts |

## Usage

### Initialize a new store

```bash
passage init
```

This creates `~/.passage/` with a new age keypair.

### Basic commands

```bash
# List all passwords
passage
passage ls
passage ls Email/

# Show a password
passage show Email/gmail
passage show -c Email/gmail     # Copy to clipboard
passage show -q Email/gmail     # Display as QR code
passage show -l 1 Email/gmail   # Show only first line

# Insert a password
passage insert Email/gmail
passage insert -m Email/gmail   # Multiline
passage insert -e Email/gmail   # Echo input (visible)

# Generate a password
passage generate Email/outlook 32
passage generate -n Web/github 16  # No symbols
passage generate -c Email/new      # Copy to clipboard

# Edit in $EDITOR
passage edit Email/gmail

# Delete
passage delete Email/old
passage delete -r Email/         # Delete directory recursively
passage delete -f Email/old      # Force (no confirmation)

# Search
passage find gmail
passage grep "api.*key"

# Copy/Move (re-encrypts with current recipients)
passage copy Email/gmail Email/gmail-backup
passage move Email/old Email/archive/old

# Git operations (runs in store directory)
passage git status
passage git push
passage git log

# Re-encrypt all passwords (after changing recipients)
passage reencrypt
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PASSAGE_DIR` | `~/.passage/store` | Password store location |
| `PASSAGE_IDENTITIES_FILE` | `~/.passage/identities` | Age identity file |
| `PASSAGE_RECIPIENTS_FILE` | `~/.passage/store/.age-recipients` | Recipients for encryption |
| `EDITOR` | `vi` | Editor for `passage edit` |

## Store Structure

```
~/.passage/
├── identities           # Your private age key
└── store/
    ├── .age-recipients  # Public keys for encryption
    ├── Email/
    │   ├── gmail.age
    │   └── outlook.age
    └── Web/
        └── github.age
```

## Migrating from pass

If you're migrating from [pass](https://www.passwordstore.org/), you'll need to:

1. Export passwords from pass
2. Re-encrypt with age

```bash
# Example migration script
for file in ~/.password-store/**/*.gpg; do
    name="${file#$HOME/.password-store/}"
    name="${name%.gpg}"
    gpg -d "$file" | passage insert -m "$name"
done
```

## Comparison with passage (Go)

This is a Zig reimplementation of [FiloSottile/passage](https://github.com/FiloSottile/passage) with:

- Native age encryption via Rust FFI (no external binary needed)
- QR code generation built-in
- Single static binary with no runtime dependencies
- Memory-safe implementation

## License

MIT

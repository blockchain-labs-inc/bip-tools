# bip-tools

A Rust library and CLI tool for Bitcoin address generation and management using extended public keys (xpub). This project implements BIP32 and BIP44 specifications for hierarchical deterministic wallet address derivation.

## Features

- Extended Public Key (xpub) management
- BIP32 hierarchical deterministic address generation
- BIP44 compliant address derivation
- Command-line interface for easy address generation
- Support for legacy Bitcoin addresses (P2PKH)

## Installation

The compiled binary will be available at `target/release/bip-tools`

## Using Cargo
```bash
cargo install --git https://github.com/yigitraphy/biptools.git
```

### Building from Source

#### Prerequisites

- Rust 1.70.0 or higher
- Cargo package manager

```bash
git clone https://github.com/yigitraphy/biptools.git
cd bip-tools
cargo build --release
```

## Library Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
bip-tools = "0.1.0"
```

### Example Code

```rust
use bip_tools::Xpub;

// Parse an xpub from its Base58 string representation
let xpub = Xpub::from_base58("xpub6CUGRUo...").unwrap();

// Generate 5 BIP44 addresses
let addresses = xpub.derive_bip44_addresses(5).unwrap();
for (i, address) in addresses.iter().enumerate() {
    println!("Address {}: {}", i, address);
}
```

## CLI Usage

The CLI tool provides two main commands for address generation:

### BIP32 Address Generation

```bash
bip-tools bip32  
```

Example:
```bash
cargo run bip32 "xpub6CUGRUo..." 5
```

### BIP44 Address Generation

```bash
bip-tools bip44  
```

Example:
```bash
cargo run bip44 "xpub6CUGRUo..." 5
```

### CLI Options

- `<XPUB>`: Your extended public key in Base58 format
- `<COUNT>`: Number of addresses to generate
- `--help`: Display help information
- `--version`: Display version information

## Technical Details

### Implementation Notes

- Uses secp256k1 for elliptic curve operations
- Implements SHA256 and RIPEMD160 for address generation
- Base58 encoding/decoding for xpub and address formats
- HMAC-SHA512 for child key derivation
- Complete BIP32 and BIP44 compliance

### Security Considerations

- Only supports non-hardened key derivation (requires only public keys)
- Implements proper error handling for invalid inputs
- Uses secure cryptographic primitives
- No private key handling - focused on public key operations only

## Project Structure

```
biptools/
|
|── docs/
│ ├── CHANGELOG.md         # Version history and release notes
│ ├── CODE_OF_CONDUCT.md   # Community behavior standards and guidelines
│ ├── CONTRIBUTING.md      # Development workflow and contribution rules
│ └── SECURITY.md          # Security policies and vulnerability reporting
├── src/
│   ├── lib.rs     - Core library implementation (Xpub struct and functionality)
│   └── main.rs    - CLI implementation
├── Cargo.toml     - Project dependencies and metadata
└── README.md      - This file
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup

1. Clone the repository
2. Install Rust and Cargo
3. Run tests: `cargo test`
4. Build project: `cargo build`

## Testing

Run the test suite:

```bash
cargo test
```

## License

[MIT License](LICENSE)

## References

- [BIP32 Specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP44 Specification](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)

## Acknowledgments

- Bitcoin Core developers for BIP specifications
- Rust Crypto community for cryptographic primitives
- Clap developers for the CLI framework

## Support

For support, custom development, and consulting services, please contact:
Email: @

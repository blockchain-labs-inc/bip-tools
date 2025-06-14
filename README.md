# bip-tools

⚠️Notice: This project is currently in the testing phase and is not yet ready for production use.⚠️

A robust Rust library and CLI tool for hierarchical deterministic (HD) wallet operations, supporting multiple cryptocurrencies and address formats. Built for developers and blockchain enthusiasts, bip-tools provides an efficient way to manage extended public keys (xpub) and generate addresses compliant with BIP32 and BIP44 standards.

## Features

- **Extended Public Key (xpub) Management:** Parse, serialize, and derive child keys from xpub strings.
- **BIP32 and BIP44 Compliance:** Generate addresses using standard derivation paths for BIP32 and BIP44.
- **Multi-Cryptocurrency Support:** Supports Bitcoin, Litecoin, Dogecoin, and Bitcoin Cash.
- **Flexible Address Formats:** Generate legacy (P2PKH) addresses and Bitcoin Cash-specific formats (Legacy, CashAddr, CashAddr with prefix).
- **Command-Line Interface (CLI):** User-friendly CLI for generating addresses with customizable options.

## Supported Coins
| Coin | BIP32 Version | Address Formats |
|------|---------------|-----------------|
| Bitcoin | xpub | Legacy |
| Litecoin | xpub | Legacy |
| Dogecoin | xpub | Legacy |
| Bitcoin Cash | xpub | Legacy, CashAddr |

### Address Formats
- Legacy (P2PKH)
- Bitcoin Cash:
  - CashAddr (with/without prefix)
  - Legacy Base58

## Installation

The compiled binary will be available at `target/release/bip-tools`

## Using Cargo
```bash
cargo install --git https://github.com/blockchain-labs-inc/bip-tools.git
```

### Building from Source

#### Prerequisites

- Rust 1.70.0 or higher
- Cargo package manager

```bash
git clone https://github.com/blockchain-labs-inc/bip-tools.git
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
use bip_tools::{CoinType, Xpub};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let xpub_str = "xpub6Dix4qijz1p9XB7eiuYe5anj3qiveYg4UQvqhJcJbMraGEQegMhbt3BcLd5fnmgp6eWRGtjiWcdkck749k5KgYHXH8UY9MDRwDye43ok3Hr";
    let xpub = Xpub::from_base58(xpub_str, CoinType::Bitcoin)?;
    let addresses = xpub.derive_bip32_addresses(3, &None)?;
    
    for (i, addr) in addresses.iter().enumerate() {
        println!("Address {}: {}", i, addr);
    }
    
    Ok(())
}
```

## CLI Usage

The bip-tools CLI provides two main commands for address generation: bip32 and bip44. Each command supports customizable options for coin type, chain type, and address format (for Bitcoin Cash).

### BIP32 Address Generation

Generate BIP32 Addresses:
```bash
cargo run bip32 <XPUB> <COUNT> <COIN> [OPTIONS]
```

Example:
```bash
cargo run bip32 "xpub6CUGRUo..." 5 bitcoin 0
```

### BIP44 Address Generation

```bash
cargo run bip44 <XPUB> <COUNT> <COIN> [OPTIONS] <0|1>
```

Example:
```bash
cargo run bip44 "xpub6CUGRUo..." 5 bitcoin 0
```

Example 2:
```bash
cargo run bip44 "xpub6BtoTpW..." 3 bitcoincash --format cashaddr 0
```
(Example 2) Output:
```bash
Generating 3 BIP-44 addresses for: bitcoincash with chain type 0
Child 0: qzmmuhsacaa...
Child 1: qpmypx075hz...
Child 2: qram84egkfm...
```

### CLI Options

- `<XPUB>`: Your extended public key in Base58 format
- `<COUNT>`: Number of addresses to generate
- `<COIN>`: Specifies which cryptocurrency to generate addresses for (bitcoin, litecoin, dogecoin, bitcoincash).
- `<0|1>`: Determines address type - 0 for receiving addresses, 1 for change addresses
- `--format`:  Selects address format for Bitcoin Cash (legacy for old-style, cashaddr for new format, cashaddr-p for new format with prefix).
- `--help`: Display help information
- `--version`: Display version information

### Using Docker

You can run bip-tools using Docker without installing Rust or any dependencies locally.

#### Building the Docker image

```bash
docker build -t bip-tools .
```

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

### Error Types

- Invalid xpub format
- Base58 decode errors
- Invalid derivation path
- Checksum validation failures

### Performance
Benchmark results on standard hardware (Intel i5, 8GB RAM):

#### BIP32:
- Single address generation: ~0.035ms (34.907 microseconds)
- Batch of 100 addresses: ~3.57ms (3.5683 milliseconds)

#### BIP44:
- Single address generation: ~0.069ms (68.628 microseconds)
- Batch of 100 addresses: ~3.59ms (3.5930 milliseconds)

## Project Structure

biptools/
|
|── docs/
│ ├── CHANGELOG.md         # Version history and release notes
│ ├── CODE_OF_CONDUCT.md   # Community behavior standards and guidelines
│ ├── CONTRIBUTING.md      # Development workflow and contribution rules
│ └── SECURITY.md          # Security policies and vulnerability reporting
├── src/
│ ├── lib.rs               # Core library implementation (Xpub struct and functionality)
│ ├── main.rs              # CLI implementation
| ├── utils.rs             # Handles Bitcoin Cash address formatting and conversions.
├── tests/
│ ├── bip32_vectors.rs     # Test vectors and validation tests for BIP32 standard
│ └── bip44_vectors.rs     # Test vectors and validation tests for BIP44 standard
├── Cargo.toml             # Project dependencies and metadata
└── README.md              # This file
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

[MIT License](https://github.com/blockchain-labs-inc/bip-tools/blob/main/LICENSE)

## References

- [BIP32 Specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP44 Specification](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)

## Acknowledgments

- Bitcoin Core developers for BIP specifications
- Rust Crypto community for cryptographic primitives
- Clap developers for the CLI framework

## Support

For support, custom development, and consulting services, please contact:
Email: william@chainlabs.io

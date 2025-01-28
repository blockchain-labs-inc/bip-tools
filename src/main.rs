use bip_tools::{CoinType, Xpub};
use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "bip_tools",                   // Name of the CLI application
    arg_required_else_help(true),          // Show help if no arguments provided
    version,                               // Enables automatic version flag
    about,                                 // Short description from Cargo.toml
    long_about = None
)]
struct Cli {
    /// Subcommands for different address generation methods
    #[command(subcommand)]
    commands: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Generate public addresses from a BIP32 extended public key
    Bip32(AddressGeneratorArgs),
    /// Generate public addresses from a BIP44 extended public key
    Bip44(AddressGeneratorArgs),
}

/// Common arguments for both BIP32 adn BIP44 address generation
#[derive(Debug, Args)]
#[command(flatten_help = true)]
struct AddressGeneratorArgs {
    /// Extended public key (xpub) in Base58 format
    extended_public_key: String,

    /// Number of addresses to generate
    count: u32,

    /// Coin type (e.g., Bitcoin, Litecoin, Dogecoin)
    coin_type: String,
}

/// Main entry point of the application
/// Parses command line arguments and executes the requested operation
///
/// # Returns
/// * `Result<(), Box<dyn std::error::Error>>` - Success or error message
///
/// # Error
/// Returns error if:
/// - Invalid xpub format
/// - Address derivation fails
/// - Other unexpected errors occur
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Match on the subcommand and execute corresponding functionality
    match cli.commands {
        Commands::Bip32(args) => {
            let coin_type = match args.coin_type.to_lowercase().as_str() {
                "bitcoin" => CoinType::Bitcoin,
                "litecoin" => CoinType::Litecoin,
                "dogecoin" => CoinType::Dogecoin,
                "bitcoincash" => CoinType::BitcoinCash,
                _ => return Err("Unsopported coin type".into()),
            };

            let xpub = Xpub::from_base58(&args.extended_public_key, coin_type)?;
            println!("Generating {} BIP-32 addresses for: {}", args.count, args.coin_type);

            match xpub.derive_bip32_addresses(args.count) {
                Ok(addresses) => {
                    // Print each derived address with its index
                    for (i, address) in addresses.iter().enumerate() {
                        println!("Child {}: {}", i, address);
                    }
                }
                Err(e) => { 
                    eprintln!("Error: {}", e);
                }
            }
        }
        Commands::Bip44(args) => {
            let coin_type = match args.coin_type.to_lowercase().as_str() {
                "bitcoin" => CoinType::Bitcoin,
                "litecoin" => CoinType::Litecoin,
                "dogecoin" => CoinType::Dogecoin,
                "bitcoincash" => CoinType::BitcoinCash,
                _ => return Err("Unsopported coin type".into()),
            };

            let xpub = Xpub::from_base58(&args.extended_public_key, coin_type)?;
            println!("Generating {} BIP-44 addresses for: {}", args.count, args.coin_type);

            match xpub.derive_bip44_addresses(args.count) {
                Ok(addresses) => {
                    // Print each derived address with its index
                    for (i, address) in addresses.iter().enumerate() {
                        println!("Child {}: {}", i, address);
                    }
                }
                Err(e) => { 
                    eprintln!("Error: {}", e);
                }
            }
        }
    };

    Ok(())
}

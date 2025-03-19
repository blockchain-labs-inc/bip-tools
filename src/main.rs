use bip_tools::{utils, CoinType, Xpub};
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
    /// Generate a public address using a custom derivation path and chain type
    Custom(CustomAddressArgs),
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

    /// Chain type: 0 for external chain (normal), 1 for change chain (receiving)
    chain_type: u32,

    /// Address format (optional, only used for Bitcoin Cash)
    #[arg(short, long)]
    format: Option<String>,
}

/// Arguments for generating an address using a custom derivation path and chain type
#[derive(Debug, Args)]
#[command(flatten_help = true)]
struct CustomAddressArgs {
    /// Extended public key (xpub) in Base58 format
    extended_public_key: String,

    /// Coin type (e.g., bitcoin, litecoin, dogecoin, bitcoincash)
    coin_type: String,

    /// Derivation path as comma-separated indices (e.g., "0,1,0")
    path: String,

    /// Chain type: 0 for external chain (normal), 1 for change chain (receiving)
    chain_type: u32,

    /// Address format (optional, only used for Bitcoin Cash)
    #[arg(short, long)]
    format: Option<String>,
}

/// Arguments for BIP44 address generation with chain type
#[derive(Debug, Args)]
#[command(flatten_help = true)]
struct Bip44Args {
    /// Extended public key (xpub) in Base58 format
    extended_public_key: String,

    /// Number of addresses to generate
    count: u32,

    /// Coin type (e.g., bitcoin, litecoin, dogecoin, bitcoincash)
    coin_type: String,

    /// Chain type: 0 for external chain (normal), 1 for change chain (receiving)
    chain_type: u32,

    /// Address format (optional, only used for Bitcoin Cash)
    #[arg(short, long)]
    format: Option<String>,
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
                _ => {
                    eprintln!("Unsupported coin type: {}", args.coin_type); // Added more detailed error reporting
                    return Err("Unsupported coin type".into());
                }
            };

            let xpub = Xpub::from_base58(&args.extended_public_key, coin_type)?;
            println!(
                "Generating {} BIP-32 addresses for: {}",
                args.count, args.coin_type
            );

            let format = match args.format.as_deref() {
                Some("legacy") => Some(utils::AddressFormat::Legacy),
                Some("cashaddr") => Some(utils::AddressFormat::CashAddr),
                Some("cashaddr-p") => Some(utils::AddressFormat::CashAddrWithPrefix),
                _ => None,
            };

            match xpub.derive_bip32_addresses(args.count, &format) {
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
            println!(
                "Generating {} BIP-44 addresses for: {} with chain type {}",
                args.count, args.coin_type, args.chain_type
            );

            let format = match args.format.as_deref() {
                Some("legacy") => Some(utils::AddressFormat::Legacy),
                Some("cashaddr") => Some(utils::AddressFormat::CashAddr),
                Some("cashaddr-p") => Some(utils::AddressFormat::CashAddrWithPrefix),
                _ => None,
            };

            match xpub.derive_bip44_addresses(args.count, args.chain_type, &format) {
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
        Commands::Custom(args) => {
            let coin_type = match args.coin_type.to_lowercase().as_str() {
                "bitcoin" => CoinType::Bitcoin,
                "litecoin" => CoinType::Litecoin,
                "dogecoin" => CoinType::Dogecoin,
                "bitcoincash" => CoinType::BitcoinCash,
                _ => {
                    eprintln!("Unsupported coin type: {}", args.coin_type);
                    return Err("Unsupported coin type".into());
                }
            };

            let xpub = Xpub::from_base58(&args.extended_public_key, coin_type)?;
            println!(
                "Generating custom path address for: {} with path: {} and chain type: {}",
                args.coin_type, args.path, args.chain_type
            );

            let path: Result<Vec<u32>, _> = args
                .path
                .split(',')
                .map(|s| s.trim().parse::<u32>())
                .collect();
            let path = path.map_err(|e| format!("Invalid derivation path: {}", e))?;

            let format = match args.format.as_deref() {
                Some("legacy") => Some(utils::AddressFormat::Legacy),
                Some("cashaddr") => Some(utils::AddressFormat::CashAddr),
                Some("cashaddr-p") => Some(utils::AddressFormat::CashAddrWithPrefix),
                _ => None,
            };

            match xpub.derive_custom_path(&path, args.chain_type, &format) {
                Ok(address) => println!("Custom address: {}", address),
                Err(e) => eprintln!("Error: {}", e),
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;  
    use secp256k1::PublicKey;

    /// Bitcoin (BTC) test module
    mod bitcoin {
        use bip_tools::{CoinType, Xpub};

        use super::*;

        // Coin-spesific constants
        const COIN_TYPE: CoinType = CoinType::Bitcoin;
        const XPUB_BTC_BIP44: &str = "xpub6CY5nbJRNJdaNKydxLZ86MMUfthR2pFGfLtKR2n7YNHrtnJBUNkeSbhnuKLmxZDsnREpnFtLvYxGXQNrTkLNBXHsLe5zror4v2n87tGQZQe";
        const BIP44_EXPECTED_ADDRESS_BTC: [&str; 3] = [
            "1D5SQUFekiv6AadptFx42CKSxQj4Tj18d2",    
            "17h1Qo28H6cZ9iM2aTtFLFUxiRYwPqaybX",
            "1EpEjScdoevQZo6JcaS7f8veWLagqh2RrZ",
        ];

        /// Test generating a single BIP44 address
        #[test]
        fn test_bip44_single_address() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP44, COIN_TYPE).unwrap();
            let addresses = xpub.derive_bip44_addresses(3, &None).expect("BIP44 derivation failed");
            assert_eq!(addresses.len(), 3, "Should generate 3 addresses");
            for (i, addr) in addresses.iter().enumerate() {
                assert_eq!(addr, BIP44_EXPECTED_ADDRESS_BTC[i], "Address at index {} mismatch", i);
            }
        }

        /// Test generating BIP44 addresses
        #[test]
        fn test_bip44_multiple_addresses() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP44, COIN_TYPE).unwrap();
            let addresses = xpub.derive_bip44_addresses(3, &None).expect("BIP44 derivation failed");
            assert_eq!(addresses.len(), 3, "Should generate 3 addresses");
            for (i, addr) in addresses.iter().enumerate() {
                assert_eq!(addr, BIP44_EXPECTED_ADDRESS_BTC[i], "Address at index {} mismatch", i);
            }
        }

        /// Test consisteny of BIP44 derivation
        #[test]
        fn test_bip44_derivation_consistency() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP44, COIN_TYPE).unwrap();
            let addresses1 = xpub.derive_bip44_addresses(2, &None).unwrap();
            let addresses2 = xpub.derive_bip44_addresses(2, &None).unwrap();
            assert_eq!(addresses1, addresses2, "BIP44 addresses should be consistent");
        }

        /// Test generating zero BIP44 addresses
        #[test]
        fn test_bip44_zero_address() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP44, COIN_TYPE).unwrap();
            let addresses = xpub.derive_bip44_addresses(0, &None).unwrap();
            assert!(addresses.is_empty(), "Should return an empty vector for zero addresses");
        }

        /// Test Bitcoin-spesific BIP44 address format
        #[test]
        fn test_bip44_address_format() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP44, COIN_TYPE).unwrap();
            let addresses = xpub.derive_bip44_addresses(3, &None).unwrap();
            for addr in addresses.iter() {
                assert!(addr.starts_with("1") || addr.starts_with("3") || addr.starts_with("bc1"), "Invalid BIP44 address format");
            }
        }
    }
}
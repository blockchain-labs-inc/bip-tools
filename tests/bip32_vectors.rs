#[cfg(test)]
mod tests {
    /// Bitcoin (BTC) BIP32 Test Module
    mod bitcoin {
        use bip_tools::{CoinType, Xpub};

        // Constants 
        const COIN_TYPE: CoinType = CoinType::Bitcoin;
        const XPUB_BTC_BIP32: &str = "xpub6Dix4qijz1p9XB7eiuYe5anj3qiveYg4UQvqhJcJbMraGEQegMhbt3BcLd5fnmgp6eWRGtjiWcdkck749k5KgYHXH8UY9MDRwDye43ok3Hr";
        const BIP32_EXPECTED_ADDRESS_BTC: [&str; 3] = [
            "1Ea7axUseGWah1Y7Mxetmz9P6nRrJVFAA4",
            "1gnuicPb9Jbg8EQamG72ZK3dDyCmjNxZV",
            "15Jz4V68onxWmdRdC2ZR8KDfghY1np1E9w",
        ];

        /// Test generating a multiple BIP32 address
        #[test]
        fn test_bip32_multiple_addresses() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP32, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip32_addresses(3, &None)
                .expect("BIP32 multiple address derivation failed");
            assert_eq!(addresses.len(), 3, "Should generate 3 address");
            assert_eq!(
                addresses[0], BIP32_EXPECTED_ADDRESS_BTC[0],
                "Multiple BIP32 addresses do not match expected"
            );
        }

        /// Test consistency of BIP32 derivation
        #[test]
        fn test_bip32_derivation_consistency() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP32, COIN_TYPE).unwrap();
            let addresses1 = xpub.derive_bip32_addresses(1, &None).unwrap();
            let addresses2 = xpub.derive_bip32_addresses(1, &None).unwrap();
            assert_eq!(addresses1, addresses2, "BIP32 addresses should be consistent across derivations");
        }

        /// Test Bitcoin-spesific BIP32 address format
        #[test]
        fn test_bip32_address_format() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP32, COIN_TYPE).unwrap();
            let addresses = xpub.derive_bip32_addresses(3, &None).unwrap();
            for addr in addresses.iter() {
                assert!(addr.starts_with("1"),
                "BIP32 address should start with '1'");
            }
        }
    }

    /// Litecoin (LTC) BIP32 Test Module
    mod litecoin_bip32 {
        use bip_tools::{CoinType, Xpub};

        // Constants
        const COIN_TYPE: CoinType = CoinType::Litecoin;
        const XPUB_LTC_BIP32: &str = "Ltub2aDBHxW1JQKsKckPrXniDLiu8TG8HRsPMJJzTPbXgNwZVV4ccXoHqXTFxSHMtED518MZP3ukjaoyC71MivCHg3qj2NQAzfP3PcMnx1HxezW";
        const BIP32_EXPECTED_ADDRESS_LTC: [&str; 3] = [
            "LPs2CLDRwQuG6NTaYcqLFCAHseKcpred9m",
            "LZrrce6ZWkfFWKreefxdX862eyuagabgF8",
            "LNwSvqc7uudTKt4Gz8VevVJNJ7hGboxADY",
        ];

        /// Test generating a multiple BIP32 address
        #[test]
        fn test_bip32_multiple_addresses() {
            let xpub = Xpub::from_base58(XPUB_LTC_BIP32, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip32_addresses(3, &None)
                .expect("BIP32 multiple address derivation failed");
            assert_eq!(addresses.len(), 3, "Should generate 3 address");
            assert_eq!(
                addresses[0], BIP32_EXPECTED_ADDRESS_LTC[0],
                "Multiple BIP32 addresses do not match expected"
            );
        }

        /// Test BIP32 derivation consistency
        #[test]
        fn test_bip32_large_index_range() {
            let xpub = Xpub::from_base58(XPUB_LTC_BIP32, COIN_TYPE).unwrap();
            let count = 1000;
            let addresses = xpub.derive_bip32_addresses(count, &None).expect("BIP32 large index derivation failed");
            assert_eq!(addresses.len(), count as usize, "Should generate 1000 addresses");
        }
    }
}
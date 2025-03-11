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
            assert_eq!(
                addresses1, addresses2,
                "BIP32 addresses should be consistent across derivations"
            );
        }

        /// Test Bitcoin-spesific BIP32 address format
        #[test]
        fn test_bip32_address_format() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP32, COIN_TYPE).unwrap();
            let addresses = xpub.derive_bip32_addresses(3, &None).unwrap();
            for addr in addresses.iter() {
                assert!(addr.starts_with("1"), "BIP32 address should start with '1'");
            }
        }

        /// Test BIP44 Bitcoin xpub parsing with a short invalid xpub and checks if an error is returned
        #[test]
        fn test_bip32_btc_short_invalid_xpub() {
            let invalid_xpub = "xpub123";
            let result = Xpub::from_base58(invalid_xpub, CoinType::Bitcoin);
            assert!(result.is_err(), "Short xpub fail for BIP32 Bitcoin");
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
            let addresses = xpub
                .derive_bip32_addresses(count, &None)
                .expect("BIP32 large index derivation failed");
            assert_eq!(
                addresses.len(),
                count as usize,
                "Should generate 1000 addresses"
            );
        }

        /// Test Litecoin-spesific BIP32 address format
        #[test]
        fn test_bip32_address_format() {
            let xpub = Xpub::from_base58(XPUB_LTC_BIP32, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip32_addresses(3, &None)
                .expect("BIP32 address derivation failed");
            for (i, addr) in addresses.iter().enumerate() {
                assert!(
                    addr.starts_with("L"),
                    "BIP32 address {} should start with 'L'",
                    i
                );
            }
        }

        /// Test BIP32 Litecoin xpub parsing with a short invalid xpub and checks if an error is returned
        #[test]
        fn test_bip32_ltc_short_invalid_xpub() {
            let invalid_xpub = "xpub123";
            let result = Xpub::from_base58(invalid_xpub, CoinType::Litecoin);
            assert!(result.is_err(), "Short xpub fail for BIP32 Litecoin");
        }
    }

    mod dogecoin_bip32 {
        use bip_tools::{CoinType, Xpub};

        // Constants
        const COIN_TYPE: CoinType = CoinType::Dogecoin;
        const XPUB_DOGE_BIP32: &str = "dgub8u3NcC3wtwJZFpsVP9Qg6GoTb6ik3i1BQXxCBbogozJk2jkXkMRwg286arkarfL8b998F1PnvkBRwnN5WR7PZcX1ir5yDrKWAMxfE7d4zjg";
        const BIP32_EXPECTED_ADDRESS_DOGE: [&str; 3] = [
            "DP5Hghi5FngxamwXteyb7kckNimUYrnpCX",
            "DCSSfERm2HyRcmHQojPkhqZ9TSqErEctcn",
            "D5nVkhrtA1f2VJhtd2BZLdayiC3zZpsVLx",
        ];

        /// Test BIP32 derivation for multiple addresses (for Dogecoin)
        #[test]
        fn test_bip32_multiple_addresses() {
            let xpub = Xpub::from_base58(XPUB_DOGE_BIP32, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip32_addresses(3, &None)
                .expect("BIP32 Multiple addresses derivation failed");
            assert_eq!(addresses.len(), 3, "Should generate 3 addresses");
            for (i, addr) in addresses.iter().enumerate() {
                assert_eq!(
                    addr, BIP32_EXPECTED_ADDRESS_DOGE[i],
                    "Multiple BIP32 addresses do not match expected"
                );
            }
        }

        /// Test Dogecoin-spesific address format for BIP44 derivation
        #[test]
        fn test_bip32_address_format() {
            let xpub = Xpub::from_base58(XPUB_DOGE_BIP32, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip32_addresses(3, &None)
                .expect("BIP32 address derivation failed");
            for addr in addresses.iter() {
                assert!(addr.starts_with("D"), "BIP32 address should start with 'D'");
            }
        }

        /// Test BIP32 Dogecoin xpub parsing with a short invalid xpub and checks if an error is returned
        #[test]
        fn test_bip32_doge_short_invalid_xpub() {
            let invalid_xpub = "xpub123";
            let result = Xpub::from_base58(invalid_xpub, CoinType::Dogecoin);
            assert!(result.is_err(), "Short xpub fail for BIP32 Dogecoin");
        }
    }

    // Bitcoin Cash (BCH) BIP32 Test Module
    mod bitcoincash_bip32 {
        use bip_tools::{utils, CoinType, Xpub};
        use utils::AddressFormat;

        // Expected addresses for Legacy format (Base58)
        const COIN_TYPE: CoinType = CoinType::BitcoinCash;
        const XPUB_BHC_BIP32: &str = "xpub6DsYunNirm7J62yWYTVR4qKHfzyRwPoxRaJXDdFYLEGQSFFiDe5wpAXf7VcX5XP9A6mHv5b6qpcPrCtuqoJpkjwr45y6LqxHZxBm93akLDC";

        /// Expected addresses for Legacy format (Base58)
        const BIP32_EXPECTED_ADDRESS_BHC_LEGACY: [&str; 3] = [
            "1Cm5tkbJtJnxkFwho3wGhYdLDxgtS6EWRy",
            "123VubGmrM5jQA5QwWnkN3ELwxL97VwDrx",
            "1GbJ3uk8vyGwcxrpBYw2wWQMWGfzYJAPbp",
        ];

        // Expected addresses for CashAddr format (not prefix)
        const BIP32_EXPECTED_ADDRESS_BHC_CASHADDR: [&str; 3] = [
            "qzq0l3g35sh0dkvd4ukwy0xdt4wvnhgx3c5tv36l9w",
            "qq9hz9nujds8l205rvdvtcs480qqcpz0kclfd80zga",
            "qz4svseqjyp72xge6pkwh26nsdna6z77fysuzg7ust",
        ];

        // Expected addresses for CashAddr format (with prefix)
        const BIP32_EXPECTED_ADDRESS_BHC_CASHADDR_PREFIX: [&str; 3] = [
            "bitcoincash:qzq0l3g35sh0dkvd4ukwy0xdt4wvnhgx3c5tv36l9w",
            "bitcoincash:qq9hz9nujds8l205rvdvtcs480qqcpz0kclfd80zga",
            "bitcoincash:qz4svseqjyp72xge6pkwh26nsdna6z77fysuzg7ust",
        ];

        /// Test BIP32 derivation for multiple legacy addresses and verify
        #[test]
        fn test_bip32_multiple_legacy_addresses() {
            let xpub = Xpub::from_base58(XPUB_BHC_BIP32, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip32_addresses(3, &Some(AddressFormat::Legacy))
                .expect("BIP32 Multiple addresses derivation failed");
            assert_eq!(addresses.len(), 3, "Should generate 3 addresses");
            assert_eq!(
                addresses[0], BIP32_EXPECTED_ADDRESS_BHC_LEGACY[0],
                "Multiple BIP32 addresses do not match expected"
            );
        }

        /// Test BIP32 derivation for multiple cashaddr addresses and verify
        #[test]
        fn test_bip32_multiple_cashaddr_addresses() {
            let xpub = Xpub::from_base58(XPUB_BHC_BIP32, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip32_addresses(3, &Some(AddressFormat::CashAddr))
                .expect("BIP32 Multiple addresses derivation failed");
            assert_eq!(addresses.len(), 3, "Should generate 3 addresses");
            assert_eq!(
                addresses[0], BIP32_EXPECTED_ADDRESS_BHC_CASHADDR[0],
                "Multiple BIP32 addresses do not match expected"
            );
        }

        /// Test BIP32 derivation for multiple cashaddr-prefix addresses and verify
        #[test]
        fn test_bip32_multiple_cashaddr_prefix_addresses() {
            let xpub = Xpub::from_base58(XPUB_BHC_BIP32, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip32_addresses(3, &Some(AddressFormat::CashAddrWithPrefix))
                .expect("BIP32 Multiple addresses derivation failed");
            assert_eq!(addresses.len(), 3, "Should generate 3 addresses");
            assert_eq!(
                addresses[0], BIP32_EXPECTED_ADDRESS_BHC_CASHADDR_PREFIX[0],
                "Multiple BIP32 addresses do not match expected"
            );
        }
    }
}

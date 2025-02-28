#[cfg(test)]
mod test {
    /// Bitcoin (BTC) test module
    mod bitcoin {
        use bip_tools::{CoinType, Xpub};

        // Coin-spesific constants
        const COIN_TYPE: CoinType = CoinType::Bitcoin;
        const XPUB_BTC_BIP44: &str = "xpub6CxEMjAQPnBECYbT4pJyfVWqZPb4TaHPcxhacFiVBSBA15NqF7UVfBDLg7Ccf89cQd1qFkJSr7bLVTfrEbBWSBrsNeYM5VaDugpR64PbE1T";
        const BIP44_EXPECTED_ADDRESS_BTC: [&str; 3] = [
            "1Ea7axUseGWah1Y7Mxetmz9P6nRrJVFAA4",
            "1gnuicPb9Jbg8EQamG72ZK3dDyCmjNxZV",
            "15Jz4V68onxWmdRdC2ZR8KDfghY1np1E9w",
        ];

        /// Test generating a single BIP44 address
        #[test]
        fn test_bip44_single_address() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP44, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip44_addresses(3, &None)
                .expect("BIP44 derivation failed");
            assert_eq!(addresses.len(), 3, "Should generate 3 addresses");
            for (i, addr) in addresses.iter().enumerate() {
                assert_eq!(
                    addr, BIP44_EXPECTED_ADDRESS_BTC[i],
                    "Address at index {} mismatch",
                    i
                );
            }
        }

        /// Test generating BIP44 addresses
        #[test]
        fn test_bip44_multiple_addresses() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP44, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip44_addresses(3, &None)
                .expect("BIP44 derivation failed");
            assert_eq!(addresses.len(), 3, "Should generate 3 addresses");
            for (i, addr) in addresses.iter().enumerate() {
                assert_eq!(
                    addr, BIP44_EXPECTED_ADDRESS_BTC[i],
                    "Address at index {} mismatch",
                    i
                );
            }
        }

        /// Test consisteny of BIP44 derivation
        #[test]
        fn test_bip44_derivation_consistency() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP44, COIN_TYPE).unwrap();
            let addresses1 = xpub.derive_bip44_addresses(3, &None).unwrap();
            let addresses2 = xpub.derive_bip44_addresses(3, &None).unwrap();
            assert_eq!(
                addresses1, addresses2,
                "BIP44 addresses should be consistent"
            );
        }

        /// Test generating zero BIP44 addresses
        #[test]
        fn test_bip44_zero_address() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP44, COIN_TYPE).unwrap();
            let addresses = xpub.derive_bip44_addresses(0, &None).unwrap();
            assert!(
                addresses.is_empty(),
                "Should return an empty vector for zero addresses"
            );
        }

        /// Test Bitcoin-spesific BIP44 address format
        #[test]
        fn test_bip44_address_format() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP44, COIN_TYPE).unwrap();
            let addresses = xpub.derive_bip44_addresses(3, &None).unwrap();
            for addr in addresses.iter() {
                assert!(addr.starts_with("1"), "Invalid BIP44 address format");
            }
        }
    }

    /// Litecoin (LTC) BIP44 Tests
    mod litecoin_bip44 {
        use bip_tools::{CoinType, Xpub};

        // Constants
        const COIN_TYPE: CoinType = CoinType::Litecoin;
        const XPUB_LTC_BIP44: &str = "Ltub2YWxAZMZahMWQnqFeUj44MgVGEwpuSyRGt8hPabhGfc2M7EVLFPgww3ZkAfGVFVLmewXezaqEnV21rE9ZEN6iRy77WtNaVu214hWkdAFtix";
        const BIP44_EXPECTED_ADDRESS_LTC: [&str; 3] = [
            "LPs2CLDRwQuG6NTaYcqLFCAHseKcpred9m",
            "LZrrce6ZWkfFWKreefxdX862eyuagabgF8",
            "LNwSvqc7uudTKt4Gz8VevVJNJ7hGboxADY",
        ];

        /// Test BIP44 derivation for a single address
        #[test]
        fn test_bip44_single_address() {
            let xpub = Xpub::from_base58(XPUB_LTC_BIP44, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip44_addresses(3, &None)
                .expect("BIP44 single address derivation failed");
            assert_eq!(addresses.len(), 3, "Should generate 3 addresses");
            assert_eq!(
                addresses[0], BIP44_EXPECTED_ADDRESS_LTC[0],
                "First BIP44 address does not match expected"
            );
        }

        /// Test BIP44 derivation for multiple addresses
        #[test]
        fn test_bip44_multiple_addresses() {
            let xpub = Xpub::from_base58(XPUB_LTC_BIP44, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip44_addresses(3, &None)
                .expect("BIP44 multiple addresses derivation failed");
            assert_eq!(addresses.len(), 3, "Should generate 3 addresses");
            for (i, addr) in addresses.iter().enumerate() {
                assert_eq!(
                    addr, BIP44_EXPECTED_ADDRESS_LTC[i],
                    "BIP44 address at index {} does not match expected",
                    i
                );
            }
        }

        /// Test BIP44 derivation with large index range
        #[test]
        fn test_bip44_large_index_range() {
            let xpub = Xpub::from_base58(XPUB_LTC_BIP44, COIN_TYPE).unwrap();
            let count = 1000;
            let addresses = xpub
                .derive_bip44_addresses(count, &None)
                .expect("BIP44 large index derivation failed");
            assert_eq!(
                addresses.len(),
                count as usize,
                "Should generate 1000 addresses"
            );
            for (i, addr) in addresses.iter().take(3).enumerate() {
                assert_eq!(
                    addr, BIP44_EXPECTED_ADDRESS_LTC[i],
                    "BIP44 address at index {} does not match expected",
                    i
                );
            }
        }

        // Test Litecoin-specific address format for BIP44 derivation
        #[test]
        fn test_bip44_address_format() {
            let xpub = Xpub::from_base58(XPUB_LTC_BIP44, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip44_addresses(3, &None)
                .expect("BIP44 address format derivation failed");
            for (i, addr) in addresses.iter().enumerate() {
                assert!(
                    addr.starts_with("L"),
                    "BIP44 address at index {} should start with 'L'",
                    i
                );
                assert_eq!(
                    addr, BIP44_EXPECTED_ADDRESS_LTC[i],
                    "BIP44 address at index {} does not match expected",
                    i
                );
            }
        }

        /// Test error handling for invalid
        #[test]
        fn test_bip44_invalid_xpub() {
            let invalid_xpub = "invalid_ltc_xpub";
            let result = Xpub::from_base58(invalid_xpub, COIN_TYPE);
            assert!(
                result.is_err(),
                "Invalid xpub should fail for BIP44 derivation"
            );
        }
    }

    /// Dogecoin (DOGE) BIP44 Tests
    mod dogecoin_bip44 {
        use bip_tools::{CoinType, Xpub};

        // Constants
        const COIN_TYPE: CoinType = CoinType::Dogecoin;
        const XPUB_DOGE_BIP44: &str = "dgub8ruYKJZx5Ki82KRujYrp8tvcN5tTYajBKj9sbFeeLqM4xKQGvFcqYntc4BYaXF7WPCY3Y1zdJ1VgdDrcWLyBp5GmobAiGuk672Qn4f4rtms";
        const BIP44_EXPECTED_ADDRESS_DOGE: [&str; 3] = [
            "DJ3U8pgzkU7q349B4kMyhkCH1ZpqnbRHtb",
            "DTHWzjtctfj37pbPxBBdNPMZMHPZ4i7phC",
            "DREHyEz5bwix16FzR3ALP1XYQiZh4MgVk7",
        ];

        /// Test BIP44 derivation for a single address
        #[test]
        fn test_bip44_single_address() {
            let xpub = Xpub::from_base58(XPUB_DOGE_BIP44, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip44_addresses(3, &None)
                .expect("BIP44 single address derivation failed");
            assert_eq!(addresses.len(), 3, "Should generate 3 addresses");
            assert_eq!(
                addresses[0], BIP44_EXPECTED_ADDRESS_DOGE[0],
                "First BIP44 address does not match expected"
            );
        }

        /// Test BIP44 derivation for multiple addresses
        #[test]
        fn test_bip44_multiple_addresses() {
            let xpub = Xpub::from_base58(XPUB_DOGE_BIP44, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip44_addresses(3, &None)
                .expect("BIP44 multiple addresses derivation failed");
            assert_eq!(addresses.len(), 3, "Should generate 3 addresses");
            for (i, addr) in addresses.iter().enumerate() {
                assert_eq!(
                    addr, BIP44_EXPECTED_ADDRESS_DOGE[i],
                    "BIP44 address at index {} does not match expected",
                    i
                );
            }
        }

        /// Test Dogecoin-specific address format for BIP44 derivation
        #[test]
        fn test_bip44_address_format() {
            let xpub = Xpub::from_base58(XPUB_DOGE_BIP44, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip44_addresses(3, &None)
                .expect("BIP44 address format derivation failed");
            for (i, addr) in addresses.iter().enumerate() {
                assert!(
                    addr.starts_with("D"),
                    "Dogecoin BIP44 address at index {} should start with 'D'",
                    i
                );
                assert_eq!(
                    addr, BIP44_EXPECTED_ADDRESS_DOGE[i],
                    "BIP44 address at index {} does not match expected",
                    i
                );
            }
        }
    }

    /// Bitcoin Cash (BCH) BIP44 Tests
    mod bitcoincash_bip44 {
        use bip_tools::{utils, CoinType, Xpub};
        use utils::AddressFormat;

        // Constants
        const COIN_TYPE: CoinType = CoinType::BitcoinCash;
        const XPUB_BCH_BIP44: &str = "xpub6BewxLEmwosTasa2dS9s74Ghiv7oTgTR6RP7kc5Ja4g57orTrZ3PGGfqm1tZTQhM4efmWgaKjJQnSDk6kGaGZufDevBFuajV9tD4tGXASFc";

        /// Expected addresses for Legacy format (Base58)
        const BIP44_EXPECTED_ADDRESS_BCH_LEGACY: [&str; 3] = [
            "1F3XiYNWdoGqmKZR4HkTurx7DjFQt98usy",
            "1JrTBgh3mjAEVLdnieqGkCEx8qjs4Q3pGj",
            "13932dNkDD3ygCtsQopAKQEgPAuQvJdFtr",
        ];

        /// Expected addresses for CashAddr format (not prefix)
        const BIP44_EXPECTED_ADDRESS_BCH_CASHADDR: [&str; 3] = [
            "qzdqcw78ydvlvf3wzl93cshc7ezgz53e6qttgrgm0s",
            "qrpagcxqyy0sdxhge9qpvqu5ly6vjfz7dcw5evy5x9",
            "qqth23dw483yupmp6q97gvv6vukk0qez0c3uqp3zj0",
        ];

        /// Expected addresses for CashAddr format (with prefix)
        const BIP44_EXPECTED_ADDRESS_BCH_CASHADDR_PREFIX: [&str; 3] = [
            "bitcoincash:qzdqcw78ydvlvf3wzl93cshc7ezgz53e6qttgrgm0s",
            "bitcoincash:qrpagcxqyy0sdxhge9qpvqu5ly6vjfz7dcw5evy5x9",
            "bitcoincash:qqth23dw483yupmp6q97gvv6vukk0qez0c3uqp3zj0",
        ];

        /// Test BIP44 derivation for a single legacy address and verify
        #[test]
        fn test_bip44_single_legacy_address() {
            let xpub = Xpub::from_base58(XPUB_BCH_BIP44, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip44_addresses(3, &Some(AddressFormat::Legacy))
                .expect("Failed to derive single Legacy address with BIP44");
            assert_eq!(addresses.len(), 3, "Should generate 3 addresses");
            assert_eq!(
                addresses[0], BIP44_EXPECTED_ADDRESS_BCH_LEGACY[0],
                "First BIP44 Legacy address does not match expected"
            );
        }

        /// Verify BIP44 derivation consistency across format
        #[test]
        fn test_bip44_format_consistency() {
            let xpub = Xpub::from_base58(XPUB_BCH_BIP44, COIN_TYPE).unwrap();
            let addresses_legacy = xpub
                .derive_bip44_addresses(3, &Some(AddressFormat::Legacy))
                .expect("Failed to derive Legacy addresses");
            let legacy_addresses_again = xpub
                .derive_bip44_addresses(3, &Some(AddressFormat::Legacy))
                .expect("Failed to derive Legacy addresses again");
            assert_eq!(
                addresses_legacy, legacy_addresses_again,
                "Legacy BIP44 addresses format be consistent across derivation"
            );
            for (i, addr) in legacy_addresses_again.iter().enumerate() {
                assert_eq!(
                    addr, BIP44_EXPECTED_ADDRESS_BCH_LEGACY[i],
                    "Legacy BIP44 address at index {} does not match expected",
                    i
                );
            }
        }

        /// Test large-scale BIP44 derivation for (1000 addresses, Legacy)
        #[test]
        fn test_bip44_large_scale_legacy_derivation() {
            let xpub = Xpub::from_base58(XPUB_BCH_BIP44, COIN_TYPE).unwrap();
            let count = 1000;
            let addresses = xpub
                .derive_bip44_addresses(count, &Some(AddressFormat::Legacy))
                .expect("Failed to derive large-scale Legacy addresses with BIP44");
            assert_eq!(
                addresses.len(),
                count as usize,
                "Should derive exactly 1000 Legacy addresses"
            );
            // Verify the first 3 addresses
            for (i, addr) in addresses.iter().take(3).enumerate() {
                assert_eq!(
                    addr, BIP44_EXPECTED_ADDRESS_BCH_LEGACY[i],
                    "Legacy BIP44 address at index {} does not match expected",
                    i
                );
            }
        }
    }
}

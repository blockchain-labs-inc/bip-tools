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

        const XPUB_BTC_BIP44_1: &str = "xpub6CB1R3PaHfGja4za4QgTzx7MD3tVDAySVeuBA6B94qNcb4PKSSRo68o6okuRseWgdW5zC9HNm9C5yCVgvVp2gLkFviuNZDAMhJndcN8UPc5";
        const BIP44_EXPECTED_ADDRESS_BTC_1: [&str; 3] = [
            "1FyBjxhfVcsCD93FNgd2d8EVZPVySsbVK5",
            "1PV8Sgnh1ZkFKDG6dJB68mtvNiArUtZfeT",
            "19BSRTWX1H5eEUmDdk4gsku9K3n3yjhZRp",
        ];

        /// Test generating BIP44 addresses
        #[test]
        fn test_bip44_btc_multiple_addresses() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP44, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip44_addresses(3, 0, &None)
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

        /// Test BIP44 address derivation for Bitcoin (BTC) - internal.
        #[test]
        fn test_bip44_btc_multiple_addresses_1() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP44_1, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip44_addresses(3, 1, &None)
                .expect("BIP44 derivation failed");
            assert_eq!(addresses.len(), 3, "Should generate 3 address");
            for (i, addr) in addresses.iter().enumerate() {
                assert_eq!(
                    addr, BIP44_EXPECTED_ADDRESS_BTC_1[i],
                    "Multiple BIP44 addresses do not match expected"
                );
            }
        }

        /// Test consisteny of BIP44 derivation
        #[test]
        fn test_bip44_btc_derivation_consistency() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP44, COIN_TYPE).unwrap();
            let addresses1 = xpub.derive_bip44_addresses(3, 0, &None).unwrap();
            let addresses2 = xpub.derive_bip44_addresses(3, 0, &None).unwrap();
            assert_eq!(
                addresses1, addresses2,
                "BIP44 addresses should be consistent"
            );
        }

        /// Test generating zero BIP44 addresses
        #[test]
        fn test_bip44_btc_zero_address() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP44, COIN_TYPE).unwrap();
            let addresses = xpub.derive_bip44_addresses(0, 0, &None).unwrap();
            assert!(
                addresses.is_empty(),
                "Should return an empty vector for zero addresses"
            );
        }

        /// Test BIP44 Bitcoin xpub parsing with a short invalid xpub and checks if an errors is returned
        #[test]
        fn test_bip44_btc_short_invalid_xpub() {
            let invalid_xpub = "xpub123";
            let result = Xpub::from_base58(invalid_xpub, CoinType::Bitcoin);
            assert!(result.is_err(), "Short xpub fail for BIP44 Bitcoin");
        }

        /// Test BIP44 Bitcoin address format to ensure it start with '1' and has correct length
        #[test]
        fn test_bip44_btc_address_format() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP44, CoinType::Bitcoin).unwrap();
            let addresses = xpub.derive_bip44_addresses(3, 0, &None).unwrap();
            for addr in addresses {
                assert!(
                    addr.starts_with("1"),
                    "BIP44 Bitcoin address should start '1'"
                );
                assert!(
                    addr.len() >= 26 && addr.len() <= 35,
                    "BIP44 Bitcoin address lenght should be 26-35"
                );
            }
        }

        /// Ensure derive_bip44_addresses rejects invalid chain_type values.
        #[test]
        fn test_bip44_btc_invalid_chain_type() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP44, COIN_TYPE).unwrap();
            let result = xpub.derive_bip44_addresses(3, 2, &None);
            assert!(result.is_err(), "Invalid chain_type should fail");
        }

        /// Ensure hardened index derivation with xPub fails as per BIP44 rules.
        #[test]
        fn test_bip44_btc_hardened_index() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP44, COIN_TYPE).unwrap();
            let result = xpub.derive_non_hardened(0x80000000);
            assert!(result.is_err(), "Hardened index derivation should fail");
        }

        /// Derive a child at the maximum non-hardened index (2^31 - 1) and verify the result for Bitcoin (BTC) (chain type = 0)
        #[test]
        fn test_bip44_btc_max_index_chain_0() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP44, COIN_TYPE).unwrap(); // Parse the BIP44 xPub for Bitcoin (assumed to be at m/44'/0'/0')
            let chain_xpub = xpub
                .derive_non_hardened(0)
                .expect("Failed to derive chain xPub"); // Derive the chain xPub for chain_type = 0 (external addresses)
            let max_index = 0x7FFFFFFF;
            let child_xpub = chain_xpub
                .derive_non_hardened(max_index)
                .expect("Failed to derive child max index");
            let address = child_xpub.to_address(&None);
            assert!(
                address.starts_with("1"),
                "Bitcoin address should start with '1'"
            );
        }

        /// Derive a child at the maximum non-hardened index (2^31 - 1) and verify the result for Bitcoin (BTC) (chain type = 1)
        #[test]
        fn test_bip44_btc_max_index_chain_1() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP44, COIN_TYPE).unwrap(); // Parse the BIP44 xPub for Bitcoin (assumed to be at m/44'/0'/0')
            let chain_xpub = xpub
                .derive_non_hardened(1)
                .expect("Failed to derive chain xPub"); // Derive the chain xPub for chain_type = 1 (internal addresses)
            let max_index = 0x7FFFFFFF;
            let child_xpub = chain_xpub
                .derive_non_hardened(max_index)
                .expect("Failed to derive child max index");
            let address = child_xpub.to_address(&None);
            assert!(
                address.starts_with("1"),
                "Bitcoin address should start with '1'"
            );
        }

        // Tests that BIP44 derivation correctly increments depth and sets parent fingerprint
        #[test]
        fn test_bip44_btc_depth_progression() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP44, COIN_TYPE).unwrap();
            let chain = xpub.derive_non_hardened(0).unwrap();
            let child = chain.derive_non_hardened(0).unwrap();
            assert_eq!(child.depth, xpub.depth + 2, "Depth should be 2");
            assert_eq!(
                child.parent_fingerprint,
                chain.fingerprint(),
                "Parent fingerprint missmatch"
            );
        }

        // Tests that serializing and then deserializing a BIP44 xpub preserves its data
        #[test]
        fn test_bip44_btc_serialization() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP44, COIN_TYPE).unwrap();
            let serialized = xpub.to_base58();
            let deserialized = Xpub::from_base58(&serialized, COIN_TYPE).unwrap();
            assert_eq!(
                xpub.to_base58(),
                deserialized.to_base58(),
                "Serialization round-trip failed"
            );
        }

        // Tests that derived BIP44 public keys are in compressed (33-byte) format
        #[test]
        fn test_bip44_btc_compression() {
            let xpub = Xpub::from_base58(XPUB_BTC_BIP44, COIN_TYPE).unwrap();
            let child_xpub = xpub
                .derive_non_hardened(0)
                .expect("Failed to derive child xPub");
            assert_eq!(
                child_xpub.public_key.serialize().len(),
                33,
                "Derived public key should be compressed (33 bytes)"
            );
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

        const XPUB_LTC_BIP44_1: &str = "Ltub2ZRKyakzGNxJqTkH7aPLCxoAKGrwt3r72Kb1AfBc6UEekHq4Y9PM8v4EhD5PPAcJqHARMd2BqJW9cuqSCdnM4LYLJKjSDasRamJg7MxEiVL";
        const BIP44_EXPECTED_ADDRESS_LTC_1: [&str; 3] = [
            "Lbjbea2HnikjZcddSBJjy3vChde9PKF6kD",
            "LX2NBLYsmU4b4BbBKzksvDsbKApLB3sGA4",
            "LgquNMwiqh1pEyqHsnvScU7CRizTwkko6y",
        ];

        /// Test BIP44 derivation for multiple addresses
        #[test]
        fn test_bip44_ltc_multiple_addresses() {
            let xpub = Xpub::from_base58(XPUB_LTC_BIP44, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip44_addresses(3, 0, &None)
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

        /// Test BIP44 address derivation for Litecoin (LTC) - internal.
        #[test]
        fn test_bip44_ltc_multiple_addresses_1() {
            let xpub = Xpub::from_base58(XPUB_LTC_BIP44_1, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip44_addresses(3, 1, &None)
                .expect("BIP44 derivation failed");
            assert_eq!(addresses.len(), 3, "Should generate 3 address");
            for (i, addr) in addresses.iter().enumerate() {
                assert_eq!(
                    addr, BIP44_EXPECTED_ADDRESS_LTC_1[i],
                    "Muliple BIP44 addresses do not match expected"
                )
            }
        }

        /// Test BIP44 derivation with large index range
        #[test]
        fn test_bip44_ltc_large_index_range() {
            let xpub = Xpub::from_base58(XPUB_LTC_BIP44, COIN_TYPE).unwrap();
            let count = 1000;
            let addresses = xpub
                .derive_bip44_addresses(count, 0, &None)
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

        /// Test error handling for invalid
        #[test]
        fn test_bip44_ltc_invalid_xpub() {
            let invalid_xpub = "invalid_ltc_xpub";
            let result = Xpub::from_base58(invalid_xpub, COIN_TYPE);
            assert!(
                result.is_err(),
                "Invalid xpub should fail for BIP44 derivation"
            );
        }

        /// Test BIP44 Litecoin xpub parsing with a short invalid xpub and checks if an error is returned
        #[test]
        fn test_bip44_ltc_short_invalid_xpub() {
            let invalid_xpub = "xpub123";
            let result = Xpub::from_base58(invalid_xpub, CoinType::Litecoin);
            assert!(result.is_err(), "Short xpub fail for BIP32 Litecoin");
        }

        /// Test BIP44 Litecoin address format to ensure it start with 'L' and has correct lenght
        #[test]
        fn test_bip44_ltc_address_format() {
            let xpub = Xpub::from_base58(XPUB_LTC_BIP44, CoinType::Litecoin).unwrap();
            let addresses = xpub.derive_bip44_addresses(3, 0, &None).unwrap();
            for addr in addresses {
                assert!(
                    addr.starts_with("L"),
                    "BIP44 Litecoin address should start with 'L'"
                );
                assert!(
                    addr.len() >= 26 && addr.len() <= 35,
                    "BIP44 Litecoin address lenght should be 26-35"
                );
            }
        }

        /// Ensure derive_bip44_addresses rejects invalid chain_type values.
        #[test]
        fn test_bip44_ltc_invalid_chain_type() {
            let xpub = Xpub::from_base58(XPUB_LTC_BIP44, COIN_TYPE).unwrap();
            let result = xpub.derive_bip44_addresses(3, 2, &None);
            assert!(result.is_err(), "Invalid chain_type should fail");
        }

        /// Ensure hardened index derivation with xPub fails as per BIP44 rules.
        #[test]
        fn test_bip44_ltc_hardened_index() {
            let xpub = Xpub::from_base58(XPUB_LTC_BIP44, COIN_TYPE).unwrap();
            let result = xpub.derive_non_hardened(0x80000000);
            assert!(result.is_err(), "Hardened index derivation should fail");
        }

        /// Derive a child at the maximum non-hardened index (2^31 - 1) and verify the result for Litecoin (LTC) (chain type = 0)
        #[test]
        fn test_bip44_ltc_max_index_chain_0() {
            let xpub = Xpub::from_base58(XPUB_LTC_BIP44, COIN_TYPE).unwrap(); // Parse the BIP44 xPub for Litecoin (assumed to be at m/44'/2'/0')
            let chain_xpub = xpub
                .derive_non_hardened(0)
                .expect("Failed to derive chain xPub"); // Derive the chain xPub for chain_type = 0 (external addresses)
            let max_index = 0x7FFFFFFF;
            let child_xpub = chain_xpub
                .derive_non_hardened(max_index)
                .expect("Failed to derive child max index");
            let address = child_xpub.to_address(&None);
            assert!(
                address.starts_with("L"),
                "Litecoin address should start with 'L'"
            );
        }

        /// Derive a child at the maximum non-hardened index (2^31 - 1) and verify the result for Litecoin (LTC) (chain type = 1)
        #[test]
        fn test_bip44_ltc_max_index_chain_1() {
            let xpub = Xpub::from_base58(XPUB_LTC_BIP44, COIN_TYPE).unwrap(); // Parse the BIP44 xPub for Litecoin (assumed to be at m/44'/2'/0')
            let chain_xpub = xpub
                .derive_non_hardened(1)
                .expect("Failed to derive chain xPub"); // Derive the chain xPub for chain_type = 1 (internal addresses)
            let max_index = 0x7FFFFFFF;
            let child_xpub = chain_xpub
                .derive_non_hardened(max_index)
                .expect("Failed to derive child max index");
            let address = child_xpub.to_address(&None);
            assert!(
                address.starts_with("L"),
                "Litecoin address should start with 'L'"
            );
        }

        // Tests that BIP44 derivation correctly increments depth and sets parent fingerprint
        #[test]
        fn test_bip44_ltc_depth_progression() {
            let xpub = Xpub::from_base58(XPUB_LTC_BIP44, COIN_TYPE).unwrap();
            let chain = xpub.derive_non_hardened(0).unwrap();
            let child = chain.derive_non_hardened(0).unwrap();
            assert_eq!(child.depth, xpub.depth + 2, "Depth should be 2");
            assert_eq!(
                child.parent_fingerprint,
                chain.fingerprint(),
                "Parent fingerprint missmatch"
            );
        }

        // Tests that serializing and then deserializing a BIP44 xpub preserves its data
        #[test]
        fn test_bip44_ltc_serialization() {
            let xpub = Xpub::from_base58(XPUB_LTC_BIP44, COIN_TYPE).unwrap();
            let serialized = xpub.to_base58();
            let deserialized = Xpub::from_base58(&serialized, COIN_TYPE).unwrap();
            assert_eq!(
                xpub.to_base58(),
                deserialized.to_base58(),
                "Serialization round-trip failed"
            );
        }

        // Tests that derived BIP44 public keys are in compressed (33-byte) format
        #[test]
        fn test_bip44_ltc_compression() {
            let xpub = Xpub::from_base58(XPUB_LTC_BIP44, COIN_TYPE).unwrap();
            let child_xpub = xpub
                .derive_non_hardened(0)
                .expect("Failed to derive child xPub");
            assert_eq!(
                child_xpub.public_key.serialize().len(),
                33,
                "Derived public key should be compressed (33 bytes)"
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

        const XPUB_DOGE_BIP44_1: &str = "dgub8rmtrKBGg1ph9NxX1UmDr6sJaUHcwUmHWECHVXQyimyt1Gxkjhh4JaReFgsweqHWphNyEG6n5MtBYCBzfj1Z4FmWiftcUUdc5NTFJB8Sofg";
        const BIP44_EXPECTED_ADDRESS_DOGE_1: [&str; 3] = [
            "DCQRDgEVL55q7CokH86G3gc9YneumK5FDf",
            "D6aNhV59wDSE5jUhe7xX1tgvU64orFP3WB",
            "D811vA68rTcHnEDLEW4Psve7v5BoDNxtX1",
        ];

        /// Test BIP44 derivation for multiple addresses
        #[test]
        fn test_bip44_doge_multiple_addresses() {
            let xpub = Xpub::from_base58(XPUB_DOGE_BIP44, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip44_addresses(3, 0, &None)
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

        /// Test BIP44 address derivation for Dogecoin (DOGE) - internal.
        #[test]
        fn test_bip44_doge_multiple_addresses_1() {
            let xpub = Xpub::from_base58(XPUB_DOGE_BIP44_1, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip44_addresses(3, 1, &None)
                .expect("BIP44 derivaiton failed");
            assert_eq!(addresses.len(), 3, "Should generate address");
            for (i, addr) in addresses.iter().enumerate() {
                assert_eq!(
                    addr, BIP44_EXPECTED_ADDRESS_DOGE_1[i],
                    "Multiple BIP44 addresses do not match expected"
                );
            }
        }

        /// Test BIP44 Dogecoin xpub parsing with a short invalid xpub and checks if an error is returned
        #[test]
        fn test_bip44_doge_short_invalid_xpub() {
            let invalid_xpub = "xpub123";
            let result = Xpub::from_base58(invalid_xpub, CoinType::Dogecoin);
            assert!(result.is_err(), "Short xpub fail for BIP44 Dogecoin");
        }

        /// Test BIP44 Dogecoin address format to ensure it start with 'D' and has correct lenght
        #[test]
        fn test_bip44_doge_address_format() {
            let xpub = Xpub::from_base58(XPUB_DOGE_BIP44, CoinType::Dogecoin).unwrap();
            let addresses = xpub.derive_bip44_addresses(3, 0, &None).unwrap();
            for addr in addresses {
                assert!(
                    addr.starts_with("D"),
                    "BIP44 Dogecoin address should start with 'D'"
                );
                assert!(
                    addr.len() >= 26 && addr.len() <= 35,
                    "BIP44 Dogecoin address lenght should be 26-35"
                );
            }
        }

        /// Ensure derive_bip44_addresses rejects invalid chain_type values.
        #[test]
        fn test_bip44_doge_invalid_chain_type() {
            let xpub = Xpub::from_base58(XPUB_DOGE_BIP44, COIN_TYPE).unwrap();
            let result = xpub.derive_bip44_addresses(3, 2, &None);
            assert!(result.is_err(), "Invalid chain_type should fail");
        }

        /// Ensure hardened index derivation with xPub fails as per BIP44 rules.
        #[test]
        fn test_doge_bip44_hardened_index() {
            let xpub = Xpub::from_base58(XPUB_DOGE_BIP44, COIN_TYPE).unwrap();
            let result = xpub.derive_non_hardened(0x80000000);
            assert!(result.is_err(), "Hardened index derivation should fail");
        }

        /// Derive a child at the maximum non-hardened index (2^31 - 1) and verify the result for Litecoin (LTC) (chain type = 0)
        #[test]
        fn test_bip44_doge_max_index_chain0() {
            let xpub = Xpub::from_base58(XPUB_DOGE_BIP44, COIN_TYPE).unwrap(); // Parse the BIP44 xPub for Dogecoin (assumed to be at m/44'/3'/0')
            let chain_xpub = xpub
                .derive_non_hardened(0)
                .expect("Failed to derive chain xPub"); // Derive the chain xPub for chain_type = 0 (external addresses)
            let max_index = 0x7FFFFFFF;
            let child_xpub = chain_xpub
                .derive_non_hardened(max_index)
                .expect("Failed to derive child max index");
            let address = child_xpub.to_address(&None);
            assert!(
                address.starts_with("D"),
                "Dogecoin address should start with 'D'"
            );
        }

        /// Derive a child at the maximum non-hardened index (2^31 - 1) and verify the result for Litecoin (LTC) (chain type = 1)
        #[test]
        fn test_bip44_doge_max_index_chain1() {
            let xpub = Xpub::from_base58(XPUB_DOGE_BIP44, COIN_TYPE).unwrap(); // Parse the BIP44 xPub for Dogecoin (assumed to be at m/44'/3'/0')
            let chain_xpub = xpub
                .derive_non_hardened(1)
                .expect("Failed to derive chain xPub"); // Derive the chain xPub for chain_type = 1 (internal addresses)
            let max_index = 0x7FFFFFFF;
            let child_xpub = chain_xpub
                .derive_non_hardened(max_index)
                .expect("Failed to derive child max index");
            let address = child_xpub.to_address(&None);
            assert!(
                address.starts_with("D"),
                "Dogecoin address should start with 'D'"
            );
        }

        // Tests that BIP44 derivation correctly increments depth and sets parent fingerprint
        #[test]
        fn test_bip44_doge_depth_progression() {
            let xpub = Xpub::from_base58(XPUB_DOGE_BIP44, COIN_TYPE).unwrap();
            let chain = xpub.derive_non_hardened(0).unwrap();
            let child = chain.derive_non_hardened(0).unwrap();
            assert_eq!(child.depth, xpub.depth + 2, "Depth should be 2");
            assert_eq!(
                child.parent_fingerprint,
                chain.fingerprint(),
                "Parent fingerprint missmatch"
            );
        }

        // Tests that serializing and then deserializing a BIP44 xpub preserves its data
        #[test]
        fn test_bip44_doge_serialization() {
            let xpub = Xpub::from_base58(XPUB_DOGE_BIP44, COIN_TYPE).unwrap();
            let serialized = xpub.to_base58();
            let deserialized = Xpub::from_base58(&serialized, COIN_TYPE).unwrap();
            assert_eq!(
                xpub.to_base58(),
                deserialized.to_base58(),
                "Serialization round-trip failed"
            );
        }

        // Tests that derived BIP44 public keys are in compressed (33-byte) format
        #[test]
        fn test_bip44_doge_compression() {
            let xpub = Xpub::from_base58(XPUB_DOGE_BIP44, COIN_TYPE).unwrap();
            let child_xpub = xpub
                .derive_non_hardened(0)
                .expect("Failed to derive child xPub");
            assert_eq!(
                child_xpub.public_key.serialize().len(),
                33,
                "Derived public key should be compressed (33 bytes)"
            );
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

        /// Test BIP44 derivation for a multiple legacy address and verify
        #[test]
        fn test_bip44_bch_multiple_legacy_address() {
            let xpub = Xpub::from_base58(XPUB_BCH_BIP44, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip44_addresses(3, 0, &Some(AddressFormat::Legacy))
                .expect("Failed to derive single Legacy address with BIP44");
            assert_eq!(addresses.len(), 3, "Should generate 3 addresses");
            assert_eq!(
                addresses[0], BIP44_EXPECTED_ADDRESS_BCH_LEGACY[0],
                "First BIP44 Legacy address does not match expected"
            );
        }

        /// Verify BIP44 derivation consistency across format
        #[test]
        fn test_bip44_bch_format_consistency() {
            let xpub = Xpub::from_base58(XPUB_BCH_BIP44, COIN_TYPE).unwrap();
            let addresses_legacy = xpub
                .derive_bip44_addresses(3, 0, &Some(AddressFormat::Legacy))
                .expect("Failed to derive Legacy addresses");
            let legacy_addresses_again = xpub
                .derive_bip44_addresses(3, 0, &Some(AddressFormat::Legacy))
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
        fn test_bip44_bch_large_scale_legacy_derivation() {
            let xpub = Xpub::from_base58(XPUB_BCH_BIP44, COIN_TYPE).unwrap();
            let count = 1000;
            let addresses = xpub
                .derive_bip44_addresses(count, 0, &Some(AddressFormat::Legacy))
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

        /// Derive a single CashAddr address and verify
        #[test]
        fn test_bip44_bch_multiple_cashaddr_address() {
            let xpub = Xpub::from_base58(XPUB_BCH_BIP44, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip44_addresses(3, 0, &Some(AddressFormat::CashAddr))
                .expect("Failed to derive single CashAddr address with BIP44");
            assert_eq!(addresses.len(), 3, "Should generate 3 addresses");
            assert_eq!(
                addresses[0], BIP44_EXPECTED_ADDRESS_BCH_CASHADDR[0],
                "First BIP44 CashAddr address does not match expected"
            );
        }

        // Derive multiple CashAddrWithPrefix addresses and verify
        #[test]
        fn test_bip44_bch_multiple_cashaddr_prefix_addresses() {
            let xpub = Xpub::from_base58(XPUB_BCH_BIP44, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip44_addresses(3, 0, &Some(AddressFormat::CashAddrWithPrefix))
                .expect("Failed to derive multiple CashAddrWithPrefix addresses with BIP44");
            assert_eq!(addresses.len(), 3, "Should derive exactly 3 addresses");
            for (i, addr) in addresses.iter().enumerate() {
                assert_eq!(
                    addr, BIP44_EXPECTED_ADDRESS_BCH_CASHADDR_PREFIX[i],
                    "CashAddrWithPrefix BIP44 address at index {} does not match expected",
                    i
                )
            }
        }

        /// Test BIP44 Bitcoin Cash xpub parsing with a short invalid xpub and checks if an error is returned
        #[test]
        fn test_bip44_bch_short_invalid_xpub() {
            let invalid_xpub = "xpub123";
            let result = Xpub::from_base58(invalid_xpub, CoinType::BitcoinCash);
            assert!(result.is_err(), " Short xpub fail for BIP44 Bitcoin Cash");
        }

        /// Test BIP44 Bitcoin Cash address format to ensure it start with 'q' (CashAddr)
        #[test]
        fn test_bip44_bch_address_format() {
            let xpub = Xpub::from_base58(XPUB_BCH_BIP44, CoinType::BitcoinCash).unwrap();
            let addresses = xpub
                .derive_bip44_addresses(3, 0, &Some(AddressFormat::CashAddr))
                .unwrap();
            for addr in addresses {
                assert!(
                    addr.starts_with("q"),
                    "BIP44 Bitcoin Cash address should start with 'q' (CashAddr)"
                );
            }
        }

        /// Ensure derive_bip44_addresses rejects invalid chain_type values.
        #[test]
        fn test_bip44_bch_invalid_chain_type() {
            let xpub = Xpub::from_base58(XPUB_BCH_BIP44, COIN_TYPE).unwrap();
            let result = xpub.derive_bip44_addresses(3, 2, &None);
            assert!(result.is_err(), "Invalid chain_type should fail");
        }

        /// Ensure hardened index derivation with xPub fails as per BIP44 rules.
        #[test]
        fn test_bip44_bch_hardened_index() {
            let xpub = Xpub::from_base58(XPUB_BCH_BIP44, COIN_TYPE).unwrap();
            let result = xpub.derive_non_hardened(0x80000000);
            assert!(result.is_err(), "Hardened index derivation should fail");
        }

        /// Derive a child at the maximum non-hardened index (2^31 - 1) and verify the result for Bitcoin Cash (BCH) (chain type = 0) - legacy
        #[test]
        fn test_bip44_bch_max_index_chain_0_legacy() {
            let xpub = Xpub::from_base58(XPUB_BCH_BIP44, COIN_TYPE).unwrap(); // Parse the BIP44 xPub for Bitcoin Cash (assumed to be at m/44'/145'/0')
            let chain_xpub = xpub
                .derive_non_hardened(0)
                .expect("Failed to derive chain xPub"); // Derive the chain xPub for chain_type = 0 (external addresses)
            let max_index = 0x7FFFFFFF;
            let child_xpub = chain_xpub
                .derive_non_hardened(max_index)
                .expect("Failed to derive child max index");
            let address = child_xpub.to_address(&Some(AddressFormat::Legacy));
            assert!(
                address.starts_with("1"),
                "Bitcoin Cash address should start with '1'"
            );
        }

        /// Derive a child at the maximum non-hardened index (2^31 - 1) and verify the result for Bitcoin Cash (BCH) (chain type = 0) - cashaddr
        #[test]
        fn test_bip44_bch_max_index_chain_0_cashaddr() {
            let xpub = Xpub::from_base58(XPUB_BCH_BIP44, COIN_TYPE).unwrap(); // Parse the BIP44 xPub for Bitcoin Cash (assumed to be at m/44'/145'/0')
            let chain_xpub = xpub
                .derive_non_hardened(0)
                .expect("Failed to derive chain xPub"); // Derive the chain xPub for chain_type = 0 (external addresses)
            let max_index = 0x7FFFFFFF;
            let child_xpub = chain_xpub
                .derive_non_hardened(max_index)
                .expect("Failed to derive child max index");
            let address = child_xpub.to_address(&Some(AddressFormat::CashAddr));
            assert!(
                address.starts_with("q"),
                "Bitcoin Cash address should start with 'q'"
            );
        }

        /// Derive a child at the maximum non-hardened index (2^31 - 1) and verify the result for Bitcoin Cash (BCH) (chain type = 0) - cashaddr_prefix
        #[test]
        fn test_bip44_bch_max_index_chain_0_cashaddr_prefix() {
            let xpub = Xpub::from_base58(XPUB_BCH_BIP44, COIN_TYPE).unwrap(); // Parse the BIP44 xPub for Bitcoin Cash (assumed to be at m/44'/145'/0')
            let chain_xpub = xpub
                .derive_non_hardened(0)
                .expect("Failed to derive chain xPub"); // Derive the chain xPub for chain_type = 0 (external addresses)
            let max_index = 0x7FFFFFFF;
            let child_xpub = chain_xpub
                .derive_non_hardened(max_index)
                .expect("Failed to derive child max index");
            let address = child_xpub.to_address(&Some(AddressFormat::CashAddrWithPrefix));
            assert!(
                address.starts_with("bitcoincash:q"),
                "Bitcoin Cash address should start with 'bitcoincash:q'"
            );
        }

        // Tests that BIP44 derivation correctly increments depth and sets parent fingerprint
        #[test]
        fn test_bip44_bch_depth_progression() {
            let xpub = Xpub::from_base58(XPUB_BCH_BIP44, COIN_TYPE).unwrap();
            let chain = xpub.derive_non_hardened(0).unwrap();
            let child = chain.derive_non_hardened(0).unwrap();
            assert_eq!(child.depth, xpub.depth + 2, "Depth should be 2");
            assert_eq!(
                child.parent_fingerprint,
                chain.fingerprint(),
                "Parent fingerprint missmatch"
            );
        }

        // Tests that serializing and then deserializing a BIP44 xpub preserves its data
        #[test]
        fn test_bip44_bch_serialization() {
            let xpub = Xpub::from_base58(XPUB_BCH_BIP44, COIN_TYPE).unwrap();
            let serialized = xpub.to_base58();
            let deserialized = Xpub::from_base58(&serialized, COIN_TYPE).unwrap();
            assert_eq!(
                xpub.to_base58(),
                deserialized.to_base58(),
                "Serialization round-trip failed"
            );
        }

        // Tests that derived BIP44 public keys are in compressed (33-byte) format
        #[test]
        fn test_bip44_bch_compression() {
            let xpub = Xpub::from_base58(XPUB_BCH_BIP44, COIN_TYPE).unwrap();
            let child_xpub = xpub
                .derive_non_hardened(0)
                .expect("Failed to derive child xPub");
            assert_eq!(
                child_xpub.public_key.serialize().len(),
                33,
                "Derived public key should be compressed (33 bytes)"
            );
        }

        const XPUB_BCH_BIP44_1: &str = "xpub6D1S8ySBPc2nQtT6LBcfzGyaxvfBsBdFpy1NmNiHJJdBv68JaTyqKpJv7sNLPkZndjo1UcXZLBGxj2gxPdx6EMygzsR3MCEVoqcnqvN8hi5";

        /// Expected addresses for Legacy format (Base58)
        const BIP44_EXPECTED_ADDRESS_BCH_LEGACY_1: [&str; 3] = [
            "1EsDjnG5bH3eKH9frw6J38v2KScAyA8pHr",
            "19ynvXx1QbNJg6W8YAUe2P32oPGHJHUBEc",
            "1HqNMC9LwhY6vZoPMWuT3hdHY6FEh2yfoJ",
        ];

        /// Expected addresses for CashAddr format (not prefix)
        const BIP44_EXPECTED_ADDRESS_BCH_CASHADDR_1: [&str; 3] = [
            "qzvpjy827tsrevqka9a80uus2nwpcpfnygw45fr34c",
            "qp38agnu540g3q7cyjvd4qev8eyez9tzju0r0lr5n8",
            "qzu20ny6c97hkh9va2u25ngw8sprcdgq7uc4af4z87",
        ];

        /// Expected addresses for CashAddr format (with prefix)
        const BIP44_EXPECTED_ADDRESS_BCH_CASHADDR_PREFIX_1: [&str; 3] = [
            "bitcoincash:qzvpjy827tsrevqka9a80uus2nwpcpfnygw45fr34c",
            "bitcoincash:qp38agnu540g3q7cyjvd4qev8eyez9tzju0r0lr5n8",
            "bitcoincash:qzu20ny6c97hkh9va2u25ngw8sprcdgq7uc4af4z87",
        ];

        /// Test BIP44 address derivation for Bitcoin Cash (BHC / legacy) - internal.
        #[test]
        fn test_bip44_bch_multiple_legacy_address_1() {
            let xpub = Xpub::from_base58(XPUB_BCH_BIP44_1, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip44_addresses(3, 1, &Some(AddressFormat::Legacy))
                .expect("Failed to derive single Legacy address with BIP44");
            assert_eq!(addresses.len(), 3, "Should generate 3 addresses");
            assert_eq!(
                addresses[0], BIP44_EXPECTED_ADDRESS_BCH_LEGACY_1[0],
                "First BIP44 Legacy address does not match expected"
            );
        }

        /// Test BIP44 address derivation for Bitcoin Cash (BHC / cashaddr) - internal.
        #[test]
        fn test_bip44_bch_multiple_cashaddr_address_1() {
            let xpub = Xpub::from_base58(XPUB_BCH_BIP44_1, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip44_addresses(3, 1, &Some(AddressFormat::CashAddr))
                .expect("Failed to derive single Legacy address with BIP44");
            assert_eq!(addresses.len(), 3, "Should generate 3 addresses");
            assert_eq!(
                addresses[0], BIP44_EXPECTED_ADDRESS_BCH_CASHADDR_1[0],
                "First BIP44 Legacy address does not match expected"
            );
        }

        /// Test BIP44 address derivation for Bitcoin Cash (BHC / cashaddr with prefix) - internal.
        #[test]
        fn test_bip44_bch_multiple_cashaddr_prefix_address_1() {
            let xpub = Xpub::from_base58(XPUB_BCH_BIP44_1, COIN_TYPE).unwrap();
            let addresses = xpub
                .derive_bip44_addresses(3, 1, &Some(AddressFormat::CashAddrWithPrefix))
                .expect("Failed to derive single Legacy address with BIP44");
            assert_eq!(addresses.len(), 3, "Should generate 3 addresses");
            assert_eq!(
                addresses[0], BIP44_EXPECTED_ADDRESS_BCH_CASHADDR_PREFIX_1[0],
                "First BIP44 Legacy address does not match expected"
            );
        }

        /// Derive a child at the maximum non-hardened index (2^31 - 1) and verify the result for Bitcoin Cash (BCH) (chain type = 1) - legacy
        #[test]
        fn test_bip44_bch_max_index_chain_1_legacy() {
            let xpub = Xpub::from_base58(XPUB_BCH_BIP44, COIN_TYPE).unwrap(); // Parse the BIP44 xPub for Bitcoin Cash (assumed to be at m/44'/145'/0')
            let chain_xpub = xpub
                .derive_non_hardened(1)
                .expect("Failed to derive chain xPub"); // Derive the chain xPub for chain_type = 1 (internal addresses)
            let max_index = 0x7FFFFFFF;
            let child_xpub = chain_xpub
                .derive_non_hardened(max_index)
                .expect("Failed to derive child max index");
            let address = child_xpub.to_address(&Some(AddressFormat::Legacy));
            assert!(
                address.starts_with("1"),
                "Bitcoin Cash address should start with '1'"
            );
        }

        /// Derive a child at the maximum non-hardened index (2^31 - 1) and verify the result for Bitcoin Cash (BCH) (chain type = 1) - cashaddr
        #[test]
        fn test_bip44_bch_max_index_chain_1_cashaddr() {
            let xpub = Xpub::from_base58(XPUB_BCH_BIP44, COIN_TYPE).unwrap(); // Parse the BIP44 xPub for Bitcoin Cash (assumed to be at m/44'/145'/0')
            let chain_xpub = xpub
                .derive_non_hardened(1)
                .expect("Failed to derive chain xPub"); // Derive the chain xPub for chain_type = 1 (internal addresses)
            let max_index = 0x7FFFFFFF;
            let child_xpub = chain_xpub
                .derive_non_hardened(max_index)
                .expect("Failed to derive child max index");
            let address = child_xpub.to_address(&Some(AddressFormat::CashAddr));
            assert!(
                address.starts_with("q"),
                "Bitcoin Cash address should start with 'q'"
            );
        }

        /// Derive a child at the maximum non-hardened index (2^31 - 1) and verify the result for Bitcoin Cash (BCH) (chain type = 1) - cashaddr_prefix
        #[test]
        fn test_bip44_bch_max_index_chain_1_cashaddr_prefix() {
            let xpub = Xpub::from_base58(XPUB_BCH_BIP44, COIN_TYPE).unwrap(); // Parse the BIP44 xPub for Bitcoin Cash (assumed to be at m/44'/145'/0')
            let chain_xpub = xpub
                .derive_non_hardened(1)
                .expect("Failed to derive chain xPub"); // Derive the chain xPub for chain_type = 1 (internal addresses)
            let max_index = 0x7FFFFFFF;
            let child_xpub = chain_xpub
                .derive_non_hardened(max_index)
                .expect("Failed to derive child max index");
            let address = child_xpub.to_address(&Some(AddressFormat::CashAddrWithPrefix));
            assert!(
                address.starts_with("bitcoincash:q"),
                "Bitcoin Cash address should start with 'bitcoincash:q'"
            );
        }
    }
}

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
                assert!(
                    addr.starts_with("1") || addr.starts_with("3") || addr.starts_with("bc1"),
                    "Invalid BIP44 address format"
                );
            }
        }
    }

    /// Litecoin (LTC) BIP44 Tests
    mod litecoin_bip44 {
        use bip_tools::{CoinType, Xpub};

        use super::*;

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
    }
}
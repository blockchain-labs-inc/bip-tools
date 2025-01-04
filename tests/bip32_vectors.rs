use bip_tools::Xpub;

#[cfg(test)]
mod bip32_tests {
    use crate::Xpub;
    use base58::FromBase58;
    use sha2::{Sha256, Digest};

    const TEST_XPUB: &str = "xpub681vrYy1g8k1xtcNPi2WN9pGiHDejoCvUT4GG2Mbs9rcs98VWvoQXmgT2J1umYQs9p2qp6xdMjJ2AU1rNcCMq9RmtKNhowJKYvVgKwS59xX";

    const EXPECTED_BIP32_ADDRESSES: [&str; 3] = [
        "1FvSF5syVSTnsbNzFpPd4mNFcSvwtTxqLw",
        "175AcMJAwppLkCKAGkazkM9ygTbvPc5Cn5",
        "1GZZ8iuVo1BwfGei132MTRmNoBRDt7Lfvf"
    ];

    const MAINNET_VERSION: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];

    #[test]
    fn test_xpub_from_base58() {
        let xpub = Xpub::from_base58(TEST_XPUB);
        assert!(xpub.is_ok(), "Failed to parse valid xpub");

        let invalid_xpub: &str = "invalid_xpub_string";
        assert!(Xpub::from_base58(invalid_xpub).is_err(), "Should fail with invalid xpub");
    }

    #[test]
    fn test_bip32_address_derivation() {
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        let derived_addresses = xpub.derive_bip32_addresses(3).unwrap();
        
        println!("Base58 Comparison:");
        println!("Expected XPUB: {}", TEST_XPUB);
        println!("Actual XPUB:   {}\n", xpub.to_base58());
        
        assert_eq!(
            derived_addresses[0], 
            EXPECTED_BIP32_ADDRESSES[0],
            "\nExpected address: {}\nGenerated address: {}", 
            EXPECTED_BIP32_ADDRESSES[0],
            derived_addresses[0]
    );
}

    #[test]
    fn test_invalid_derivation_index() {
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        assert!(xpub.derive_non_hardened(0x80000000).is_err(), "Should fail with hardened index");
    }

    #[test]
    fn test_fingerprint_generation() {
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        let fingerprint = xpub.fingerprint();

        assert!(fingerprint > 0, "Fingerprint should be not zero");
    }
    
    #[test]
    fn test_to_base58() {
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        let encoded = xpub.to_base58();

        assert_eq!(encoded, TEST_XPUB, "Base58 encoding should match original");
    }

    #[test]
    fn test_xpub_version_bytes() {
        let decoded = TEST_XPUB.from_base58().unwrap();
        assert_eq!(decoded[0..4], MAINNET_VERSION, "Version bytes should match");
    }

    #[test]
    fn test_xpub_checksum() {
        let decoded = TEST_XPUB.from_base58().unwrap();
        let main_data = &decoded[0..decoded.len() - 4];
        let provided_checksum = &decoded[decoded.len() - 4..];

        let calculated_checksum = &Sha256::digest(&Sha256::digest(main_data))[..4];
        assert_eq!(calculated_checksum, provided_checksum, "Invalid checksum");
    }

    #[test]
    fn test_bitcoin_address_format() {
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        let address = xpub.to_bitcoin_address();

        assert!(address.starts_with('1'), "Invalid P2PKH address format");
        assert!(address.len() >= 26 && address.len() <= 35, "Invalif address length");
    }

    #[test]
    fn test_zero_test_address_derivation() {
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        let result = xpub.derive_bip32_addresses(0);
        assert!(result.is_ok(), "Should handle zero address request");
        assert_eq!(result.unwrap().len(), 0, "Should return empty vector for zero count");
    }

    #[test]
    fn test_consecutive_derivation() {
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        
        let first_address = xpub.derive_non_hardened(1)
            .unwrap()
            .to_bitcoin_address();
        
        let second_address = xpub.derive_non_hardened(1)
            .unwrap()
            .to_bitcoin_address();
        
        assert_eq!(first_address, second_address, "Same index should produce same address");
        
        let different_address = xpub.derive_non_hardened(2)
            .unwrap()
            .to_bitcoin_address();
        assert_ne!(first_address, different_address, "Different index should produce different address");
    }

    #[test]
    fn test_large_index_derivation() {
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        let large_index = 0x7FFFFFFF;

        let result = xpub.derive_non_hardened(large_index);
        assert!(result.is_ok(), "Should handle large non-hardened index");
    }

    #[test]
    fn test_bip32_multiple_addresses_uniqueness() {
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        let addresses = xpub.derive_bip32_addresses(10).unwrap();
        
        for i in 0..addresses.len() {
            for j in i+1..addresses.len() {
                assert_ne!(
                    addresses[i],
                    addresses[j],
                    "BIP32 addresses should be unique"
                );
            }
        }
    }
}
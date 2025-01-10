use bip_tools::Xpub;

#[cfg(test)]
mod bip32_tests {
    use crate::Xpub;
    use base58::FromBase58;
    use secp256k1::PublicKey;
    use sha2::{Sha256, Digest};

    // Test data for mainnet BIP32 derivation
    const TEST_XPUB: &str = "xpub681vrYy1g8k1xtcNPi2WN9pGiHDejoCvUT4GG2Mbs9rcs98VWvoQXmgT2J1umYQs9p2qp6xdMjJ2AU1rNcCMq9RmtKNhowJKYvVgKwS59xX";

    // Known valid addresses for test validation
    const EXPECTED_BIP32_ADDRESSES: [&str; 3] = [
        "1FvSF5syVSTnsbNzFpPd4mNFcSvwtTxqLw",
        "175AcMJAwppLkCKAGkazkM9ygTbvPc5Cn5",
        "1GZZ8iuVo1BwfGei132MTRmNoBRDt7Lfvf"
    ];

    // Version bytes for mainnet xpub
    const MAINNET_VERSION: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];

    // Helper function to get test public key 
    fn get_test_public_key() -> PublicKey {
        let decoded = TEST_XPUB.from_base58().unwrap();
        PublicKey::from_slice(&decoded[45..78]).unwrap()
    }

    #[test]
    fn test_xpub_new() {
        let depth: u8 = 0;
        let parent_fingerprint: u32 = 0;
        let child_number: u32 = 0;
        let chain_code: [u8; 32] = [0; 32];
        let public_key = get_test_public_key();

        let xpub = Xpub::new(depth, parent_fingerprint, child_number, chain_code, public_key);

        assert_eq!(xpub.depth, depth, "Depth should match");
        assert_eq!(xpub.parent_fingerprint, parent_fingerprint, "Parent fingerprint should match");
        assert_eq!(xpub.child_number, child_number, "Child number should match");
        assert_eq!(xpub.chain_code, chain_code, "Chain code should match");
        assert_eq!(xpub.public_key, public_key, "Public key should match");

    }

    #[test]
    fn test_xpub_from_base58() {
        // Test valid and invalid xpub parsing
        let xpub = Xpub::from_base58(TEST_XPUB);
        assert!(xpub.is_ok(), "Failed to parse valid xpub");

        // Test invalid xpub string
        let invalid_xpub: &str = "invalid_xpub_string";
        assert!(Xpub::from_base58(invalid_xpub).is_err(), "Should fail with invalid xpub");

        // Test invalid length
        let short_xpub: &str = "invalid_xpub_string";
        assert!(Xpub::from_base58(short_xpub).is_err(), "Should fail with invalid xpub");
    }

    #[test]
    fn test_bip32_address_derivation() {
        // Verify address derivation matches expected test vectors
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        let derived_addresses = xpub.derive_bip32_addresses(3).unwrap();
        
        for (i, addr) in derived_addresses.iter().enumerate() {
            assert_eq!(
                addr, 
                EXPECTED_BIP32_ADDRESSES[i],
                "Address {} mismatch. Expected: {}, Got: {}", 
                i, EXPECTED_BIP32_ADDRESSES[i], addr
            );
        }
}

    #[test]
    fn test_invalid_derivation_index() {
        // Verify hardened derivation is rejected for xpub
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        // Test hardened index
        assert!(xpub.derive_non_hardened(0x80000000).is_err(), "Should fail with hardened index");
        
        // Test maximum allowed index
        assert!(xpub.derive_non_hardened(0x7FFFFFFF).is_ok(), "Should accept max non-hardened index");
    }

    #[test]
    fn test_fingerprint_generation() {
        // Check fingerprint calculation is non-zero
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        let fingerprint = xpub.fingerprint();
        
        // Test non-zero
        assert!(fingerprint > 0, "Fingerprint should be not zero");
        
        // Test deterministic
        let second_fingerprint = xpub.fingerprint();
        assert_eq!(fingerprint, second_fingerprint, "Fingerprint should be deterministic");
    }
    
    #[test]
    fn test_to_base58() {
        // Verify Base58 encoding is reversible
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        let encoded = xpub.to_base58();

        assert_eq!(encoded, TEST_XPUB, "Base58 encoding should match original");

        // Additional encoding checks
        let decoded = encoded.from_base58().unwrap();
        assert_eq!(decoded[4], xpub.depth, "Depth should match");
        assert_eq!(&decoded[0..4], &MAINNET_VERSION, "Version bytes should match");
    }

    #[test]
    fn test_xpub_version_bytes() {
        // Validate mainnet version bytes
        let decoded = TEST_XPUB.from_base58().unwrap();
        assert_eq!(decoded[0..4], MAINNET_VERSION, "Version bytes should match");
    }

    #[test]
    fn test_xpub_checksum() {
        // Verify checksum calculation is correct
        let decoded = TEST_XPUB.from_base58().unwrap();
        let main_data = &decoded[0..decoded.len() - 4];
        let provided_checksum = &decoded[decoded.len() - 4..];

        let calculated_checksum = &Sha256::digest(&Sha256::digest(main_data))[..4];
        assert_eq!(calculated_checksum, provided_checksum, "Invalid checksum");
    }

    #[test]
    fn test_bitcoin_address_format() {
        // Verify P2PKH address format and length
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        let address = xpub.to_bitcoin_address();

        // Format checks
        assert!(address.starts_with('1'), "Should be P2PKH address");
        assert!(address.len() >= 26 && address.len() <= 35, "Address length should be valid");

        // Decode and verify version byte
        let decoded = address.from_base58().unwrap();
        assert_eq!(decoded[0], 0x00, "Should use P2PKH version byte");
    }

    #[test]
    fn test_zero_test_address_derivation() {
        // Test handling of zero address request
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        let result = xpub.derive_bip32_addresses(0);
        assert!(result.is_ok(), "Should handle zero address request");
        assert_eq!(result.unwrap().len(), 0, "Should return empty vector for zero count");
    }

    #[test]
    fn test_consecutive_derivation() {
        // Verify deterministic derivation with same/different indices
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
        // Test derivation with maximum allowed non-hardened index
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        let large_index = 0x7FFFFFFF;
        let result = xpub.derive_non_hardened(large_index);
        assert!(result.is_ok(), "Should handle large non-hardened index");
    }

    #[test]
    fn test_bip32_multiple_addresses_uniqueness() {
        // Verify all derived addresses are unique
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        let addresses = xpub.derive_bip32_addresses(10).unwrap();
        
        // Check uniqueness of all addresses
        for i in 0..addresses.len() {
            for j in i+1..addresses.len() {
                assert_ne!(
                    addresses[i],
                    addresses[j],
                    "Addresses at indices {} and {} should be unique",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_bip32_max_limit_derivation() {
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        let max_count = 100;

        let result = xpub.derive_bip32_addresses(max_count);
        assert!(result.is_ok(), "Should handle maximum allowed number of addresses");
        assert_eq!(result.unwrap().len(), 100, "Should generate exactly 100 addresses");
    }
}
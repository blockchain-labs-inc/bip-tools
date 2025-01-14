use base58::FromBase58;
use bip_tools::Xpub;
use sha2::{Digest, Sha256};

#[cfg(test)]
mod bip44_test {
    use super::*;

    // Test data for mainnet BIP44 derivation
    const TEST_XPUB: &str = "xpub6CQrEh7fCh2jd4kdgqCxAQ4dpzvLGCmx5PM3GLQH1bQRCLWRUMHqeZ5XWi8QUM39BeFeBJaUA5VS4Vvw5oLaA6tHZBifTetFCxj6keSvfFS";

    // Known valid BIP44 addresses for test verification
    const EXPECTED_BIP44_ADDRESSES: [&str; 3] = [
        "1AkcymbeHtiufKa1EgC1TY4E36ehdKVEDt",
        "1BNedVV6nTX9oN77tMtoToFQ6FGQf8A3sY",
        "176FPbVE5GScCh7jvMcj6TjBwrecs8BeAR",
    ];

    // Version bytes for mainnet xpub
    const MAINNET_VERSION: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];

    // Basic Structure Tests

    #[test]
    fn test_bip44_xpub_from_base58() {
        // Test valid and invalid xpub parsing
        let xpub = Xpub::from_base58(TEST_XPUB);
        assert!(xpub.is_ok(), "Failed to parse valid xpub");

        let invalid_xpub: &str = "invalid_xpub_string";
        assert!(
            Xpub::from_base58(invalid_xpub).is_err(),
            "Should fail with invalid xpub"
        );

        // Test invalid length
        let short_xpub = "xpub6CQrEh7fCh2";
        assert!(
            Xpub::from_base58(short_xpub).is_err(),
            "Should fail with short xpub"
        );
    }

    #[test]
    fn test_bip44_to_base58() {
        // Verify Base58 encoding is reversible
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        let encoded = xpub.to_base58();

        assert_eq!(
            encoded, TEST_XPUB,
            "Base58 encoding should match original xpub"
        );

        // Additional encoding checks
        let decoded = encoded.from_base58().unwrap();
        assert_eq!(
            decoded[4], xpub.depth,
            "Depth should be preserved in encoding"
        );
        assert_eq!(
            &decoded[0..4],
            &MAINNET_VERSION,
            "Version bytes should be preserved"
        );
    }

    // Format and Structural Checks

    #[test]
    fn test_bip44_xpub_version_bytes() {
        // Validate mainnet version bytes
        let decoded = TEST_XPUB.from_base58().unwrap();
        assert_eq!(
            &decoded[0..4],
            &MAINNET_VERSION,
            "Version bytes should match"
        );
    }

    #[test]
    fn test_bip44_xpub_checksum() {
        // Verify checksum calculation is correct
        let decoded = TEST_XPUB.from_base58().unwrap();
        let main_data = &decoded[0..&decoded.len() - 4];
        let provided_checksum = &decoded[&decoded.len() - 4..];

        let calculated_checksum = &Sha256::digest(&Sha256::digest(main_data))[..4];
        assert_eq!(
            calculated_checksum, provided_checksum,
            "Checksum should match"
        );
    }

    #[test]
    fn test_bip44_fingerprint() {
        // Test non-zero fingerprint generation
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        let fingerprint = xpub.fingerprint();
        assert!(fingerprint > 0, "Fingerprint should not be zero");
    }

    #[test]
    fn test_bip44_bitcoin_address_format() {
        // Verify P2PKH address format and length
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        let addresses = xpub.derive_bip44_addresses(1).unwrap();

        assert!(
            addresses[0].starts_with("1"),
            "Invalid P2PKH address format"
        );
        assert!(
            addresses[0].len() >= 26 && addresses[0].len() <= 35,
            "Invalid address length"
        );
    }

    // BIP44 Specific Tests

    #[test]
    fn test_bip44_derivation_paths() {
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();

        // Test external chain (m/0/*)
        let external = xpub.derive_non_hardened(0);
        assert!(external.is_ok(), "Should derive external chain");

        // Test internal chain (m/1/*)
        let internal = xpub.derive_non_hardened(1);
        assert!(internal.is_ok(), "Should derive internal chain");

        // Different chains should produce different addresses
        assert_ne!(
            external.unwrap().to_bitcoin_address(),
            internal.unwrap().to_bitcoin_address(),
            "External and internal chain should produce different addresses"
        );
    }

    #[test]
    fn test_bip44_change_addresses() {
        // Test external and internal chain address differentiation
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        let external_chain = xpub.derive_non_hardened(0).unwrap(); // m/44'/0'/0'/0
        let internal_chain = xpub.derive_non_hardened(1).unwrap(); // m/44'/0'/0'/1

        let external_addr = external_chain.to_bitcoin_address();
        let internal_addr = internal_chain.to_bitcoin_address();

        assert_ne!(
            external_addr, internal_addr,
            "External and internal chain addresses should be different"
        );
    }

    #[test]
    fn test_bip44_account_separation() {
        // Verify different accounts generate different addresses
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();

        let first_account = xpub.derive_bip44_addresses(1).unwrap();
        let second_account = xpub
            .derive_non_hardened(1)
            .unwrap()
            .derive_non_hardened(0)
            .unwrap()
            .to_bitcoin_address();

        assert_ne!(
            first_account[0], second_account,
            "Different accounts should generate different addresses"
        );
    }

    // Advanced Derivation Tests

    #[test]
    fn test_bip44_address_consistency() {
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();

        // Test consecutive derivations
        let first_derivation = xpub.derive_bip44_addresses(2).unwrap();
        let second_derivation = xpub.derive_bip44_addresses(2).unwrap();

        assert_eq!(
            first_derivation[0], second_derivation[0],
            "Same index should produce same address"
        );

        assert_ne!(
            first_derivation[0], first_derivation[1],
            "Different indices should produce different addresses"
        );
    }

    #[test]
    fn test_bip44_zero_address() {
        // Test handling of zero address request
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        let result = xpub.derive_bip44_addresses(0);
        assert!(result.is_ok(), "Should handle zero address request");
        assert_eq!(
            result.unwrap().len(),
            0,
            "Should return empty vector for zero count"
        );
    }

    // Multiple Address Tests

    #[test]
    fn test_bip44_address_limits() {
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        let count = 100;

        if count > 100 {
            eprintln!(
                "Warning: Attempting to generate more than 100 addresses in test environment"
            );
        }

        let result = xpub.derive_bip44_addresses(count);
        assert!(
            result.is_ok(),
            "Should still work for more than 100 addresses"
        );

        let addresses = result.unwrap();
        eprintln!("Generated {} addresses", addresses.len());
        assert_eq!(
            addresses.len(),
            count.try_into().unwrap(),
            "Should generate exactly {count} addresses"
        );

        if count > 100 {
            eprintln!("Warning: Successfully generated more than 100 addresses");
        }
    }

    #[test]
    fn test_bip44_multiple_addresses_uniqueness() {
        // Verify all derived addresses are unique
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        let count = 100;
        let addresses = xpub.derive_bip44_addresses(count).unwrap();

        for i in 0..addresses.len() {
            for j in i + 1..addresses.len() {
                assert_ne!(
                    addresses[i], addresses[j],
                    "BIP44 addresses should be unique"
                );
            }
        }
    }

    #[test]
    fn test_bip44_known_addresses() {
        let xpub = Xpub::from_base58(TEST_XPUB).unwrap();
        let addresses = xpub.derive_bip44_addresses(3).unwrap();

        assert_eq!(
            addresses, EXPECTED_BIP44_ADDRESSES,
            "Derived addresses should match expected values"
        );
    }
}

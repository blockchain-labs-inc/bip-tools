use std::{panic, vec};

use bs58;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

// CashAddr spesific constants
const CASHADDR_CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const CASHADDR_PREFIX: &str = "bitcoincash";

// Bitcoin Cash address format
pub enum AddressFormat {
    Legacy,             // Base58 format
    CashAddr,           // CashAddr (not prefix)
    CashAddrWithPrefix, // CashAddr (with prefix)
}

pub struct CashAddress;

impl CashAddress {
    /// Create an address from a public key in the spesific format
    pub fn from_pubkey(pubkey: &[u8], format: &AddressFormat) -> String {
        // Hash the public key using SHA256 and RIPEMD160
        let hash = Ripemd160::digest(Sha256::digest(pubkey));

        // Format the address based on the requested format
        match format {
            AddressFormat::Legacy => Self::legacy_address(&hash),
            AddressFormat::CashAddr => Self::cashaddr(&hash, false),
            AddressFormat::CashAddrWithPrefix => Self::cashaddr(&hash, true),
            _ => panic!("Unsupported format"),
        }
    }

    /// Legacy Base58 format
    fn legacy_address(hash: &[u8]) -> String {
        let mut address_byte = vec![0x00]; // P2PKH version
        address_byte.extend_from_slice(hash);
        let checksum = Sha256::digest(Sha256::digest(&address_byte));
        address_byte.extend_from_slice(&checksum[..4]);
        bs58::encode(address_byte).into_string()
    }

    // CashAddr Format
    fn cashaddr(hash: &[u8], with_prefix: bool) -> String {
        let payload = Self::build_payload(hash);
        let checksum = Self::compute_checksum(&payload);
        let encoded = Self::encode_payload(&payload, &checksum);
        if with_prefix {
            format!("bitcoincash:{}", encoded)
        } else {
            encoded
        }
    }

    /// Helper Functions

    fn build_payload(hash: &[u8]) -> Vec<u8> {
        let mut payload = vec![0x00];
        payload.extend_from_slice(hash);
        Self::convert_bits(&payload, 8, 5, true).expect("Failed to convert bits")
    }

    fn encode_payload(payload: &[u8], checksum: &[u8]) -> String {
        let full_encoded: Vec<u8> = payload.iter().chain(checksum.iter()).cloned().collect();

        full_encoded
            .iter()
            .map(|&b| CASHADDR_CHARSET.as_bytes()[b as usize] as char)
            .collect::<String>()
    }

    fn hrp_expand(hrp: &str) -> Vec<u8> {
        let mut ret = Vec::with_capacity(hrp.len() * 2 + 1);
        for b in hrp.bytes() {
            ret.push(b & 0x1F);
        }
        ret.push(0); // Separator
        ret
    }

    fn compute_checksum(payload: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend(Self::hrp_expand(CASHADDR_PREFIX));
        data.extend_from_slice(payload);
        data.extend(vec![0u8; 8]); // Checksum placeholder

        let poly = Self::poly_mod(&data);
        (0..8)
            .map(|i| ((poly >> (5 * (7 - i))) & 0x1F) as u8)
            .collect()
    }

    fn poly_mod(data: &[u8]) -> u64 {
        let mut c = 1u64;
        for &d in data {
            let c0 = (c >> 35) as u8;
            c = ((c & 0x07ffffffff) << 5) ^ u64::from(d);

            if c0 & 0x01 != 0 {
                c ^= 0x98f2bc8e61;
            }
            if c0 & 0x02 != 0 {
                c ^= 0x79b76d99e2;
            }
            if c0 & 0x04 != 0 {
                c ^= 0xf33e5fb3c4;
            }
            if c0 & 0x08 != 0 {
                c ^= 0xae2eabe2a8;
            }
            if c0 & 0x10 != 0 {
                c ^= 0x1e4f43e470;
            }
        }
        c ^ 1
    }

    fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Result<Vec<u8>, String> {
        if from >= 32 || to >= 32 {
            return Err("Invalid bit size: from and to must be less than 32".to_string());
        }

        let mut acc: u64 = 0;
        let mut bits: u32 = 0;
        let mut result = Vec::new();
        let maxv = (1 << to) - 1;

        for &value in data {
            if (value as u32) >= (1 << from) {
                return Err(format!("Invalid value {}", value));
            }
            acc = (acc << from) | (value as u64);
            bits += from;

            while bits >= to {
                bits -= to;
                result.push(((acc >> bits) & maxv) as u8);
            }
        }

        if pad && bits > 0 {
            result.push(((acc << (to - bits)) & maxv) as u8);
        }

        Ok(result)
    }
}
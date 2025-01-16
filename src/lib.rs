use base58::{FromBase58, ToBase58};
use ripemd::Ripemd160;
use secp256k1::PublicKey;
use sha2::{Digest, Sha256};

#[derive(Clone)]
/// Represents an extended public key (xpub) following the BIP32 specification
/// This structure contains all necessary components to derive child keys and generate Bitcoin addresses
pub struct Xpub {
    pub depth: u8,               // Depth in the HD tree
    pub parent_fingerprint: u32, // Fingerprint of the parent key
    pub child_number: u32,       // Index of this key
    pub chain_code: [u8; 32],    // Chain code (32 bytes)
    pub public_key: PublicKey,   // Compressed public key (33 bytes)
}

impl Xpub {
    /// Creates a new extended public key with the provided components
    pub fn new(
        depth: u8,
        parent_fingerprint: u32,
        child_number: u32,
        chain_code: [u8; 32],
        public_key: PublicKey,
    ) -> Self {
        Self {
            depth,
            parent_fingerprint,
            child_number,
            chain_code,
            public_key,
        }
    }

    /// Converts a Base58 encoded xpub string into an Xpub instance.
    pub fn from_base58(xpub: &str) -> Result<Self, String> {
        // Decode the xpub from Base58
        let decoded = xpub
            .from_base58()
            .map_err(|e| format!("Base58 decode error: {:?}", e))?;

        if decoded.len() != 82 {
            return Err("Invalid xpub length".to_string());
        }

        // Extract components from the decoded xpub
        // bytes [0..4]: version bytes (not stored)
        // bytes [4]: depth
        // bytes [5..9]: parent fingerprint
        // bytes [9..13]: child number
        // bytes [13..45]: chain cod
        // bytes [45..78]: public key
        let depth = decoded[4];
        let parent_fingerprint = u32::from_be_bytes(decoded[5..9].try_into().unwrap());
        let child_number = u32::from_be_bytes(decoded[9..13].try_into().unwrap());
        let chain_code = decoded[13..45].try_into().unwrap();
        let public_key = PublicKey::from_slice(&decoded[45..78])
            .map_err(|e| format!("Invalid public key: {}", e))?;

        Ok(Self::new(
            depth,
            parent_fingerprint,
            child_number,
            chain_code,
            public_key,
        ))
    }

    /// Serializes the Xpub into its Base58 string representation
    pub fn to_base58(&self) -> String {
        let mut serialized = [0u8; 78];
    
        // Version bytes (4 bytes)
        serialized[0] = 0x04;
        serialized[1] = 0x88;
        serialized[2] = 0xB2;
        serialized[3] = 0x1E;
    
        // Depth (1 byte)
        serialized[4] = self.depth;
        
        // Parent fingerprint (4 bytes)
        serialized[5..9].copy_from_slice(&self.parent_fingerprint.to_be_bytes());
        
        // Child number (4 bytes)
        serialized[9..13].copy_from_slice(&self.child_number.to_be_bytes());  // Bu satır önemli
        
        // Chain code (32 bytes)
        serialized[13..45].copy_from_slice(&self.chain_code);
        
        // Public key (33 bytes)
        serialized[45..78].copy_from_slice(&self.public_key.serialize());
    
        // Calculate checksum and create final data
        let checksum = Sha256::digest(Sha256::digest(serialized));
        let mut final_data = [0u8; 82];
        final_data[..78].copy_from_slice(&serialized);
        final_data[78..82].copy_from_slice(&checksum[..4]);
        
        final_data.to_base58()
    }

    /// Generates a legacy P2PKH (Pay to Public Key Hash) Bitcoin address from the public key
    /// 1. Calculates HASH160 (RIPEMD160(SHA256(public_key)))
    /// 2. Adds version byte (0x00 for mainnet)
    /// 3. Adds double SHA256 checksum
    /// 4. Encodes in Base58Check format
    pub fn to_bitcoin_address(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.public_key.serialize());
        let sha256 = hasher.finalize();

        let pubkey_hash = Ripemd160::digest(sha256);

        let mut address_bytes = [0u8; 25];
        address_bytes[0] = 0x00;
        address_bytes[1..21].copy_from_slice(&pubkey_hash);

        let checksum = &Sha256::digest(Sha256::digest(&address_bytes[..21]))[..4];
        address_bytes[21..].copy_from_slice(checksum);

        address_bytes.to_base58()
    }

    /// Derives a non-hardened child Xpub from the current Xpub
    pub fn derive_non_hardened(&self, index: u32) -> Result<Self, secp256k1::Error> {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;
        type HmacSha512 = Hmac<Sha512>;

        // Verify index is not hardened
        if index >= 0x8000_0000 {
            return Err(secp256k1::Error::InvalidTweak); // Hardened keys are not allowed for Xpub
        }

        // Prepare data for HMAC-SHA512
        // parent_pubkey (33 bytes) || child_index (4 bytes)
        let mut data = [0u8; 37];
        data[..33].copy_from_slice(&self.public_key.serialize());
        data[33..].copy_from_slice(&index.to_be_bytes());

        // Generate child key material using HMAC-SHA512
        let mut mac =
            HmacSha512::new_from_slice(&self.chain_code).expect("HMAC can take a key of any size");
        mac.update(&data);
        let result = mac.finalize().into_bytes();

        // Split the result into two 32-byte halves
        let (i_l, i_r) = result.split_at(32);

        // Compute the child public key
        let secp = secp256k1::Secp256k1::new();
        let tweak = secp256k1::SecretKey::from_slice(i_l)?;
        let child_pubkey = self
            .public_key
            .add_exp_tweak(&secp, &tweak.into())
            .map_err(|_| secp256k1::Error::InvalidTweak)?;

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(i_r);

        // Create the child Xpub
        Ok(Self {
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_number: index,
            chain_code,
            public_key: child_pubkey,
        })
    }

    /// Generates multiple Bitcoin addresses using BIP32 derivation path
    pub fn derive_bip32_addresses(&self, count: u32) -> Result<Vec<String>, String> {
        let mut addresses = Vec::with_capacity(count as usize);
        let current = self.clone();

        // Generate sequential addresses
        for i in 0..count {
            match current.derive_non_hardened(i) {
                Ok(child) => {
                    addresses.push(child.to_bitcoin_address());
                }
                Err(e) => {
                    return Err(format!("Error deriving child {}: {}", i, e));
                }
            }
        }

        Ok(addresses)
    }

    /// Generates multiple Bitcoin addresses using BIP44 derivation path
    /// Follows m/44'/0'/0'/0/i path structure
    pub fn derive_bip44_addresses(&self, count: u32) -> Result<Vec<String>, String> {
        let mut addresses = Vec::with_capacity(count as usize);

        //BIP44 path: m/44'/0'/0'/0/i
        let account = self.derive_non_hardened(0).map_err(|e| format!("Error deriving account: {}", e))?;

        // Generate addresses at m/44'/0'/0'/0/i
        for i in 0..count {
            match account.derive_non_hardened(i) {
                Ok(child) => {
                    addresses.push(child.to_bitcoin_address());
                }
                Err(e) => {
                    return Err(format!("Error deriving child {}: {}", i, e));
                }
            }
        }
        Ok(addresses)
    }

    /// Calculates the fingerprint (first 4 bytes of HASH160) of the current public key.
    /// Used for child key derivation and parent identification.
    pub fn fingerprint(&self) -> u32 {
        let hash = Sha256::digest(self.public_key.serialize());
        let hash160 = Ripemd160::digest(hash);

        u32::from_be_bytes(hash160[0..4].try_into().unwrap())
    }
}

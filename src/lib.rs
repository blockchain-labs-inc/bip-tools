use secp256k1::PublicKey; 
use base58::{FromBase58, ToBase58};
use sha2::{Digest, Sha256};
use ripemd::Ripemd160;

#[derive(Clone)]
/// Represents an extended public key (xpub) following the BIP32 specification
/// This structure contains all necessary components to derive child keys and generate Bitcoin addresses
pub struct Xpub {
    pub depth: u8,                 // Depth in the HD tree
    pub parent_fingerprint: u32,  // Fingerprint of the parent key
    pub child_number: u32,        // Index of this key
    pub chain_code: [u8; 32],     // Chain code (32 bytes)
    pub public_key: PublicKey,    // Compressed public key (33 bytes)
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
        let mut data = Vec::with_capacity(78);

        // Add version (4 bytes for xpub)
        data.extend_from_slice(&[0x04, 0x88, 0xB2, 0x1E]);

        // Add depth (1 byte)
        data.push(self.depth);

        // Add parent fingerprint (4 bytes)
        data.extend_from_slice(&self.parent_fingerprint.to_be_bytes());

        // Add child number (4 bytes)
        data.extend_from_slice(&self.child_number.to_be_bytes());

        // Add chain code (32 bytes)
        data.extend_from_slice(&self.chain_code);

        // Add public key (33 bytes)
        data.extend_from_slice(&self.public_key.serialize());

        // Calculate double SHA256 checksum (first 4 bytes)
        let checksum = &Sha256::digest(Sha256::digest(&data))[..4];
        
        // Append checksum to data
        data.extend_from_slice(checksum);

        // Encode as Base58
        data.to_base58()
    }

    /// Generates a legacy P2PKH (Pay to Public Key Hash) Bitcoin address from the public key
    /// 1. Calculates HASH160 (RIPEMD160(SHA256(public_key)))
    /// 2. Adds version byte (0x00 for mainnet)
    /// 3. Adds double SHA256 checksum
    /// 4. Encodes in Base58Check format
    pub fn to_bitcoin_address(&self) -> String {
        use base58::ToBase58;

        // Generate HASH160 (RIPEMD160(SHA256(public_key)))
        let pubkey_hash = {
            let sha256 = Sha256::digest(self.public_key.serialize());
            Ripemd160::digest(sha256)
        };

        // Create address bytes
        // version (1 byte) + pubkey_hash (20 bytes) + checksum (4 bytes)
        let mut data = Vec::with_capacity(25);
        data.push(0x00);                                    // Version byte for mainnet addresses
        data.extend_from_slice(&pubkey_hash);

        // Add 4-byte chekcsum (first 4 bytes of double SHA256)
        let checksum = &Sha256::digest(Sha256::digest(&data))[..4];
        data.extend_from_slice(checksum);

        // Encode as Base58Check
        data.to_base58()
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
        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&self.public_key.serialize()); // Parent public key (33 bytes)
        data.extend_from_slice(&index.to_be_bytes());         // Child index (4 bytes)

        // Generate child key material using HMAC-SHA512
        let mut mac = HmacSha512::new_from_slice(&self.chain_code).expect("HMAC can take a key of any size");
        mac.update(&data);
        let result = mac.finalize().into_bytes();

        // Split the result into two 32-byte halves
        let (i_l, i_r) = result.split_at(32);

        // Compute the child public key
        let secp = secp256k1::Secp256k1::new();
        let tweak = secp256k1::SecretKey::from_slice(i_l)?;
        let child_pubkey = self.public_key
        .add_exp_tweak(&secp, &tweak.into())
        .map_err(|_| secp256k1::Error::InvalidTweak)?;

        // Create the child Xpub
        Ok(Self {
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_number: index,
            chain_code: i_r.try_into().unwrap(),
            public_key: child_pubkey,
        })
    }

     /// Generates multiple Bitcoin addresses using BIP32 derivation path
    pub fn derive_bip32_addresses(&self, count: u32) -> Result<Vec<String>, String> {
        // Add limit check 
        if count > 100 {
            return Err("Can't generate more than 100 addresses".to_string());
        }

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
        // Add limit check
        if count > 100 {
            return Err("Can't generate more than 100 addresses".to_string());
        }
        let mut addresses = Vec::with_capacity(count as usize);
        
        //BIP44 path: m/44'/0'/0'/0/i
        let account = match self.derive_non_hardened(0) {
            Ok(acc) => acc,
            Err(e) => return Err(format!("Error deriving account: {}", e)),
        };

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
        let hash160 = ripemd::Ripemd160::digest(hash);

        u32::from_be_bytes(hash160[0..4].try_into().unwrap())
    }
}
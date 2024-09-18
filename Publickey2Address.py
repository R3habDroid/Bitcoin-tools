import hashlib
import base58

def public_key_to_address(public_key_hex: str) -> str:
    # Step 1: Perform SHA-256 hashing on the public key
    sha256_bpk = hashlib.sha256(bytes.fromhex(public_key_hex)).digest()

    # Step 2: Perform RIPEMD-160 hashing on the SHA-256 result
    ripemd160_bpk = hashlib.new('ripemd160')
    ripemd160_bpk.update(sha256_bpk)
    public_key_hash = ripemd160_bpk.digest()

    # Step 3: Add version byte (0x00 for Mainnet)
    versioned_public_key_hash = b'\x00' + public_key_hash

    # Step 4: Perform SHA-256 hash twice to get the checksum
    sha256_vpkh_1 = hashlib.sha256(versioned_public_key_hash).digest()
    sha256_vpkh_2 = hashlib.sha256(sha256_vpkh_1).digest()

    # Step 5: Take the first 4 bytes of the second SHA-256 hash as the checksum
    checksum = sha256_vpkh_2[:4]

    # Step 6: Add the checksum to the versioned public key hash
    binary_address = versioned_public_key_hash + checksum

    # Step 7: Encode the result using Base58Check to generate the address
    address = base58.b58encode(binary_address).decode()

    return address

# Test the function with the provided compressed public key
public_key = "02e0a8b039282faf6fe0fd769cfbc4b6b4cf8758ba68220eac420e32b91ddfa673"
bitcoin_address = public_key_to_address(public_key)
print(bitcoin_address)

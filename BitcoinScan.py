from mnemonic import Mnemonic
import bip32utils
import hashlib
from bit import Key  # For Bitcoin address generation, including Bech32
import hashlib
import base58
import bech32

# Function to convert 128-bit binary to a mnemonic
def binary_to_mnemonic(binary_str):
    # Convert binary string to hexadecimal
    hex_str = hex(int(binary_str, 2))[2:].zfill(32)  # Ensure it's padded to 32 hex digits (128 bits)

    # Initialize Mnemonic object
    mnemo = Mnemonic("english")

    # Convert hexadecimal string to mnemonic
    mnemonic_phrase = mnemo.to_mnemonic(bytes.fromhex(hex_str))

    return mnemonic_phrase

# Function to derive addresses for BIP44, BIP49, and BIP84
def derive_addresses(mnemonic):
    # Generate seed from mnemonic
    seed = Mnemonic.to_seed(mnemonic)

    # Master key from seed
    master_key = bip32utils.BIP32Key.fromEntropy(seed)

    # BIP44: m/44'/0'/0'/0/0
    bip44_key = master_key.ChildKey(44 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0).ChildKey(0)
    bip44_address = bip44_key.Address()

    # BIP49: m/49'/0'/0'/0/0 (SegWit-compatible P2SH)
    bip49_key = master_key.ChildKey(49 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0).ChildKey(0)
    bip49_address = bip49_key.P2WPKHoP2SHAddress()

    # BIP84: m/84'/0'/0'/0/0 (Native SegWit P2WPKH)
    bip84_key = master_key.ChildKey(84 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0).ChildKey(0)

    # Use the 'bit' library to generate a Bech32 (P2WPKH) address
    bech32_address = Key(bip84_key.WalletImportFormat()).segwit_address

    return bip44_address, bip49_address, bech32_address



# Function to convert public key to a Bech32 (P2WPKH) address
def pubkey_to_bech32_address(pubkey):
    # Perform SHA256 hashing on the public key
    sha256_hash = hashlib.sha256(pubkey).digest()

    # Perform RIPEMD160 hashing on the SHA256 hash
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()

    # Encode into Bech32 format (P2WPKH witness version is 0)
    return bech32.encode('bc', 0, ripemd160_hash)

# Update the BIP84 address derivation to use the new Bech32 address function
def derive_addresses(mnemonic):
    # Generate seed from mnemonic
    seed = Mnemonic.to_seed(mnemonic)

    # Master key from seed
    master_key = bip32utils.BIP32Key.fromEntropy(seed)

    # BIP44: m/44'/0'/0'/0/0
    bip44_key = master_key.ChildKey(44 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0).ChildKey(0)
    bip44_address = bip44_key.Address()

    # BIP49: m/49'/0'/0'/0/0 (SegWit-compatible P2SH)
    bip49_key = master_key.ChildKey(49 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0).ChildKey(0)
    bip49_address = bip49_key.P2WPKHoP2SHAddress()

    # BIP84: m/84'/0'/0'/0/0 (Native SegWit P2WPKH)
    bip84_key = master_key.ChildKey(84 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0).ChildKey(0)
    pubkey = bip84_key.PublicKey()  # Get the public key
    bech32_address = pubkey_to_bech32_address(pubkey)  # Convert to Bech32 address

    return bip44_address, bip49_address, bech32_address

# Function to generate binary sequence, mnemonic, and wallet addresses for each
def generate_binary_mnemonic_and_addresses(starting_binary, steps):
    # Convert the starting binary string to an integer
    start_int = int(starting_binary, 2)

    # Loop to generate the sequence and corresponding mnemonics and addresses
    for i in range(steps):
        # Convert the current integer to a 128-bit binary string
        current_binary = bin(start_int + i)[2:].zfill(128)

        # Generate mnemonic for the current binary
        mnemonic = binary_to_mnemonic(current_binary)

        # Derive Bitcoin wallet addresses for BIP44, BIP49, BIP84
        bip44_address, bip49_address, bech32_address = derive_addresses(mnemonic)

        # Print the binary, mnemonic, and derived wallet addresses
        print(f"Binary: {current_binary}")
        print(f"Mnemonic: {mnemonic}")
        print(f"BIP44 Address (Legacy): {bip44_address}")
        print(f"BIP49 Address (SegWit Compatible): {bip49_address}")
        print(f"BIP84 Address (Native SegWit): {bech32_address}")
        print()

# Example usage
starting_binary = '11011111111101011110111110001110111101010001000110111010111111001000110101100001010010101100010000111111010100111001000010110011'
steps = 10  # Number of binary numbers, mnemonics, and addresses to generate

generate_binary_mnemonic_and_addresses(starting_binary, steps)
import requests
import time
from mnemonic import Mnemonic
import bip32utils
import hashlib
import bech32

# Function to convert 128-bit binary to a mnemonic
def binary_to_mnemonic(binary_str):
    hex_str = hex(int(binary_str, 2))[2:].zfill(32)  # Ensure it's padded to 32 hex digits (128 bits)
    mnemo = Mnemonic("english")
    mnemonic_phrase = mnemo.to_mnemonic(bytes.fromhex(hex_str))
    return mnemonic_phrase

# Function to derive addresses for BIP44, BIP49, and BIP84
def derive_addresses(mnemonic):
    seed = Mnemonic.to_seed(mnemonic)
    master_key = bip32utils.BIP32Key.fromEntropy(seed)

    bip44_key = master_key.ChildKey(44 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0).ChildKey(0)
    bip44_address = bip44_key.Address()

    bip49_key = master_key.ChildKey(49 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0).ChildKey(0)
    bip49_address = bip49_key.P2WPKHoP2SHAddress()

    bip84_key = master_key.ChildKey(84 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0).ChildKey(0)
    pubkey = bip84_key.PublicKey()
    bech32_address = pubkey_to_bech32_address(pubkey)

    return bip44_address, bip49_address, bech32_address

def pubkey_to_bech32_address(pubkey):
    sha256_hash = hashlib.sha256(pubkey).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    return bech32.encode('bc', 0, ripemd160_hash)

# Function to get transaction count for a given Bitcoin address using blockchain.com API
def get_transaction_count_detailed(address):
    try:
        url = f"https://blockchain.info/address/{address}?format=json"
        response = requests.get(url)

        if response.status_code == 200:
            data = response.json()
            return data.get("n_tx", 0)  # Get the transaction count
        else:
            print(f"Error fetching transaction count: {response.status_code}")
            return 0
    except Exception as e:
        print(f"Exception occurred: {str(e)}")
        return 0

# Function to generate binary sequence, mnemonic, and wallet addresses for each
def generate_binary_mnemonic_and_addresses(starting_binary):
    start_int = int(starting_binary, 2)
    api_call_count = 0  # Counter for API calls
    start_time = time.time()  # Track time for periodic printing

    while True:  # Nonstop loop
        current_binary = bin(start_int)[2:].zfill(128)
        mnemonic = binary_to_mnemonic(current_binary)
        bip44_address, bip49_address, bech32_address = derive_addresses(mnemonic)

        # Delay for 12 seconds before each address check
        time.sleep(2)

        # Check transaction counts for each address
        for address in [bip44_address, bip49_address, bech32_address]:
            transaction_count = get_transaction_count_detailed(address)
            api_call_count += 1  # Increment API call count
            if transaction_count > 0:
                print(f"Binary: {current_binary}")
                print(f"Mnemonic: {mnemonic}")
                print(f"Address: {address}")
                print(f"Number of Transactions: {transaction_count}\n")

        # Increment the integer for the next binary string
        start_int += 1

        # Print the number of API calls made every 30 seconds
        if time.time() - start_time >= 30:  # Check if 30 seconds have passed
            print(f"Number of API calls made: {api_call_count}")
            start_time = time.time()  # Reset timer

# Example usage
starting_binary = '10001100100100010001101000011011010100100100001110101011100100110001010110110011000110100011010100011000101111011100101001110111'

generate_binary_mnemonic_and_addresses(starting_binary)

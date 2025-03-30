import hashlib
import base58
import requests
import time
import random
from ecdsa import SigningKey, SECP256k1
from bech32 import bech32_encode, convertbits


def generate_random_private_key():
    return f"{random.getrandbits(256):064x}"


def private_key_to_wif(private_key_hex, compressed=True):
    private_key_bytes = bytes.fromhex(private_key_hex)
    if compressed:
        private_key_bytes += b'\x01'
    extended_key = b'\x80' + private_key_bytes
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    return base58.b58encode(extended_key + checksum).decode('utf-8')


def private_key_to_public_key(private_key_hex, compressed=True):
    private_key_bytes = bytes.fromhex(private_key_hex)
    sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    vk = sk.get_verifying_key()
    
    x, y = vk.pubkey.point.x(), vk.pubkey.point.y()
    if compressed:
        prefix = b'\x02' if y % 2 == 0 else b'\x03'
        return prefix + x.to_bytes(32, byteorder='big')  
    
    return b'\x04' + vk.to_string()


def public_key_to_legacy_address(public_key):
    public_key_hash = hashlib.new('ripemd160', hashlib.sha256(public_key).digest()).digest()
    address = b'\x00' + public_key_hash
    checksum = hashlib.sha256(hashlib.sha256(address).digest()).digest()[:4]
    return base58.b58encode(address + checksum).decode('utf-8')


def public_key_to_bech32_address(public_key):
    public_key_hash = hashlib.new('ripemd160', hashlib.sha256(public_key).digest()).digest()
    witness_version = 0
    data = [witness_version] + convertbits(public_key_hash, 8, 5, pad=True)  
    return bech32_encode('bc', data)


def get_transaction_count(address):
    try:
        url = f"https://blockstream.info/api/address/{address}"
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        return data.get("chain_stats", {}).get("tx_count", 0)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching transaction count for {address}: {e}")
        return None


def generate_addresses_with_transactions(start_private_key_hex, iterations=10):
    private_key_hex = start_private_key_hex
    api_calls = 0
    start_time = time.time()
    loop_start_time = start_time

    for i in range(iterations):
        try:
            # Generate public keys
            public_key_compressed = private_key_to_public_key(private_key_hex, compressed=True)
            public_key_uncompressed = private_key_to_public_key(private_key_hex, compressed=False)

            # Generate addresses
            legacy_compressed_address = public_key_to_legacy_address(public_key_compressed)
            legacy_uncompressed_address = public_key_to_legacy_address(public_key_uncompressed)
            bech32_address = public_key_to_bech32_address(public_key_compressed)

            # Fetch transaction counts
            legacy_compressed_tx_count = get_transaction_count(legacy_compressed_address)
            legacy_uncompressed_tx_count = get_transaction_count(legacy_uncompressed_address)
            bech32_tx_count = get_transaction_count(bech32_address)

            api_calls += 3 

            
            if (legacy_compressed_tx_count and legacy_compressed_tx_count > 0) or \
               (legacy_uncompressed_tx_count and legacy_uncompressed_tx_count > 0) or \
               (bech32_tx_count and bech32_tx_count > 0):

                print(f"🔑 Private Key: {private_key_hex}")

                if legacy_compressed_tx_count and legacy_compressed_tx_count > 0:
                    print(f"📌 Legacy Compressed Address: {legacy_compressed_address}, Transactions: {legacy_compressed_tx_count}")
                if legacy_uncompressed_tx_count and legacy_uncompressed_tx_count > 0:
                    print(f"📌 Legacy Uncompressed Address: {legacy_uncompressed_address}, Transactions: {legacy_uncompressed_tx_count}")
                if bech32_tx_count and bech32_tx_count > 0:
                    print(f"📌 Bech32 Address: {bech32_address}, Transactions: {bech32_tx_count}")

        except Exception as e:
            print(f"Error processing private key {private_key_hex}: {e}")

      
        private_key_int = int(private_key_hex, 16) + 1
        private_key_hex = f"{private_key_int:064x}"
        
       
        if time.time() - loop_start_time >= 296:
            private_key_hex = generate_random_private_key()
            loop_start_time = time.time()

        
        if time.time() - start_time >= 20:
            print(f" Total API calls made: {api_calls}")
            start_time = time.time()

        time.sleep(1)  


# Run the function with an initial private key #000000000000000000000000000000 Up to here
start_private_key_hex = "eba81430b6f0cef7d0ee4d2b92ec353571705dc0a6fdb06b40b63aa2f903fd18"
generate_addresses_with_transactions(start_private_key_hex, iterations=1300000)

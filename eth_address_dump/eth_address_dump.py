#!/usr/bin/env python3

# Adapted from:
# https://github.com/vergl4s/ethereum-mnemonic-utils/blob/master/mnemonic_utils.py

import binascii
import hashlib
import hmac
import struct

# https://pypi.org/project/pysha3/
from _pysha3 import keccak_256

import ecdsa
import sys
import re

from base58 import b58encode_check
from ecdsa.curves import SECP256k1

BIP39_PBKDF2_ROUNDS = 2048
BIP39_SALT_MODIFIER = "mnemonic"
BIP32_PRIVDEV = 0x80000000
BIP32_CURVE = SECP256k1
BIP32_SEED_MODIFIER = b'Bitcoin seed'

LEDGER_ETH_DERIVATION_PATH = "m/44'/60'/0'/0/0"   # BTC: m/44'/0'/0'/0/0
# bip44 define 5 levels in BIP32 path: m / purpose' / coin_type' / account' / change / address_index
# for bip44, purpose = 44
# for eth, coin_type = 60
# Registered coin types for BIP-0044, see https://github.com/satoshilabs/slips/blob/master/slip-0044.md

def mnemonic_to_bip39seed(mnemonic, passphrase):
    """ BIP39 seed from a mnemonic key.
        Logic adapted from https://github.com/trezor/python-mnemonic. """
    mnemonic = bytes(mnemonic, 'utf8')
    salt = bytes(BIP39_SALT_MODIFIER + passphrase, 'utf8')
    return hashlib.pbkdf2_hmac('sha512', mnemonic, salt, BIP39_PBKDF2_ROUNDS)


def bip39seed_to_bip32masternode(seed):
    """ BIP32 master node derivation from a bip39 seed.
        Logic adapted from https://github.com/satoshilabs/slips/blob/master/slip-0010/testvectors.py. """
    k = seed
    h = hmac.new(BIP32_SEED_MODIFIER, seed, hashlib.sha512).digest()
    key, chain_code = h[:32], h[32:]
    return key, chain_code


def derive_public_key(private_key):
    """ Public key from a private key.
        Logic adapted from https://github.com/satoshilabs/slips/blob/master/slip-0010/testvectors.py. """

    Q = int.from_bytes(private_key, byteorder='big') * BIP32_CURVE.generator
    xstr = Q.x().to_bytes(32, byteorder='big')
    parity = Q.y() & 1
    return (2 + parity).to_bytes(1, byteorder='big') + xstr


def derive_bip32childkey(parent_key, parent_chain_code, i):
    """ Derives a child key from an existing key, i is current derivation parameter.
        Logic adapted from https://github.com/satoshilabs/slips/blob/master/slip-0010/testvectors.py. """

    assert len(parent_key) == 32
    assert len(parent_chain_code) == 32
    k = parent_chain_code
    if (i & BIP32_PRIVDEV) != 0:
        key = b'\x00' + parent_key
    else:
        key = derive_public_key(parent_key)
    d = key + struct.pack('>L', i)
    while True:
        h = hmac.new(k, d, hashlib.sha512).digest()
        key, chain_code = h[:32], h[32:]
        a = int.from_bytes(key, byteorder='big')
        b = int.from_bytes(parent_key, byteorder='big')
        key = (a + b) % BIP32_CURVE.order
        if a < BIP32_CURVE.order and key != 0:
            key = key.to_bytes(32, byteorder='big')
            break
        d = b'\x01' + h[32:] + struct.pack('>L', i)

    return key, chain_code


def fingerprint(public_key):
    """ BIP32 fingerprint formula, used to get b58 serialized key. """

    return hashlib.new('ripemd160', hashlib.sha256(public_key).digest()).digest()[:4]


def b58xprv(parent_fingerprint, private_key, chain, depth, childnr):
    """ Private key b58 serialization format. """

    raw = (
        b'\x04\x88\xad\xe4' +
        bytes(chr(depth), 'utf-8') +
        parent_fingerprint +
        childnr.to_bytes(4, byteorder='big') +
        chain +
        b'\x00' +
        private_key)

    return b58encode_check(raw)


def b58xpub(parent_fingerprint, public_key, chain, depth, childnr):
    """ Public key b58 serialization format. """

    raw = (
        b'\x04\x88\xb2\x1e' +
        bytes(chr(depth), 'utf-8') +
        parent_fingerprint +
        childnr.to_bytes(4, byteorder='big') +
        chain +
        public_key)

    return b58encode_check(raw)


def parse_derivation_path(str_derivation_path):
    """ Parses a derivation path such as "m/44'/60/0'/0" and returns
        list of integers for each element in path. """

    path = []
    if str_derivation_path[0:2] != 'm/':
        raise ValueError("Can't recognize derivation path. It should look like \"m/44'/60/0'/0\".")

    for i in str_derivation_path.lstrip('m/').split('/'):
        if "'" in i:
            path.append(BIP32_PRIVDEV + int(i[:-1]))
        else:
            path.append(int(i))
    return path


def mnemonic_to_private_key(mnemonic, str_derivation_path=LEDGER_ETH_DERIVATION_PATH, passphrase=""):
    """ Performs all convertions to get a private key from a mnemonic sentence, including:

            BIP39 mnemonic to seed
            BIP32 seed to master key
            BIP32 child derivation of a path provided

        Parameters:
            mnemonic -- seed wordlist, usually with 24 words, that is used for ledger wallet backup
            str_derivation_path -- string that directs BIP32 key derivation, defaults to path
                used by ledger ETH wallet

    """

    derivation_path = parse_derivation_path(str_derivation_path)

    bip39seed = mnemonic_to_bip39seed(mnemonic, passphrase)

    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)

    private_key, chain_code = master_private_key, master_chain_code

    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)

    return private_key


def private_key_to_address(private_key):
    key = ecdsa.SigningKey.from_string(private_key, curve=SECP256k1)
    public_key = key.get_verifying_key().to_string()
    keccak = keccak_256()
    keccak.update(public_key)
    address = keccak.hexdigest()[24:]
    return checksum_encode(address)


def checksum_encode(address):
    keccak = keccak_256()
    out = ''
    addr = address.lower().replace('0x', '')
    keccak.update(addr.encode('ascii'))
    hash_addr = keccak.hexdigest()
    for i, c in enumerate(addr):
        if int(hash_addr[i], 16) >= 8:
            out += c.upper()
        else:
            out += c
    return out


def main_entry(argv):
    private_key = ''

    input_content = ' '.join(sys.stdin.read().split('\n')).rstrip().lstrip()
    if re.search("^([a-zA-Z]+\s){11}([a-zA-Z]+).*$", input_content): # 12 mnemonic words
        # For example: olympic wine chicken argue unaware bundle tunnel grid spider slot spell need
        mnemonic = input_content
        private_key = mnemonic_to_private_key(mnemonic)
    elif len(input_content) == 66 and input_content.startswith("0x"):
        # For example: 0x6ee825aafad19a0d759e1e0ba61d0c523b7b23038998a92d7904458b91667105
        private_key_hex = input_content[2:]
        private_key = bytearray.fromhex(private_key_hex)
    elif len(input_content) == 64:
        # For example: 6ee825aafad19a0d759e1e0ba61d0c523b7b23038998a92d7904458b91667105
        private_key_hex = input_content
        private_key = bytearray.fromhex(private_key_hex)
    else:
        print("invalid input")
        sys.exit(1)

    address = private_key_to_address(private_key)
    print("private_key = 0x{}".format(str(binascii.hexlify(private_key), 'utf-8')))
    print("address = 0x{}".format(address))


if __name__ == '__main__':
    main_entry(sys.argv)

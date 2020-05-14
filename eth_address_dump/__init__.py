"""eth-address-dump.
A utility for dump eth address from mnemonic words or private key.
"""
from .eth_address_dump import main_entry

import sys


def run_main():
    main_entry(sys.argv)

================
eth-address-dump
================

eth-address-dump is a utility for dump eth address from mnemonic words or private key.


Example
=======

Dump eth address from mnemonic words::

  $ eth_address_dump "olympic wine chicken argue unaware bundle tunnel grid spider slot spell need"
  mnemonic = olympic wine chicken argue unaware bundle tunnel grid spider slot spell need
  private_key = 0x6ee825aafad19a0d759e1e0ba61d0c523b7b23038998a92d7904458b91667105
  public_key = 0xaa3e0b3f86053c2aaa08d6f6398e18f76100e0d675680228b000c252e4393e9fe85fc162e43d721533736d79c102139d3035d2d9251ccf809bc5bddb81cc6563
  compressed_public_key = 0x03aa3e0b3f86053c2aaa08d6f6398e18f76100e0d675680228b000c252e4393e9f
  address = 0xF7dcf60AebA077461862d51b77d6d804C06E0073
  nonce_zero_contract_address = 0xE861cA8695fEF51Da017D0187bA8C83D22de6708

Dump eth address from private key::

  $ eth_address_dump 0x6ee825aafad19a0d759e1e0ba61d0c523b7b23038998a92d7904458b91667105
  private_key = 0x6ee825aafad19a0d759e1e0ba61d0c523b7b23038998a92d7904458b91667105
  public_key = 0xaa3e0b3f86053c2aaa08d6f6398e18f76100e0d675680228b000c252e4393e9fe85fc162e43d721533736d79c102139d3035d2d9251ccf809bc5bddb81cc6563
  compressed_public_key = 0x03aa3e0b3f86053c2aaa08d6f6398e18f76100e0d675680228b000c252e4393e9f
  address = 0xF7dcf60AebA077461862d51b77d6d804C06E0073
  nonce_zero_contract_address = 0xE861cA8695fEF51Da017D0187bA8C83D22de6708

Dump eth address from public key::

  $ eth_address_dump 0xaa3e0b3f86053c2aaa08d6f6398e18f76100e0d675680228b000c252e4393e9fe85fc162e43d721533736d79c102139d3035d2d9251ccf809bc5bddb81cc6563
  public_key = 0xaa3e0b3f86053c2aaa08d6f6398e18f76100e0d675680228b000c252e4393e9fe85fc162e43d721533736d79c102139d3035d2d9251ccf809bc5bddb81cc6563
  compressed_public_key = 0x03aa3e0b3f86053c2aaa08d6f6398e18f76100e0d675680228b000c252e4393e9f
  address = 0xF7dcf60AebA077461862d51b77d6d804C06E0073
  nonce_zero_contract_address = 0xE861cA8695fEF51Da017D0187bA8C83D22de6708

Dump eth address from compressed public key::

  $ eth_address_dump 0x03aa3e0b3f86053c2aaa08d6f6398e18f76100e0d675680228b000c252e4393e9f
  public_key = 0xaa3e0b3f86053c2aaa08d6f6398e18f76100e0d675680228b000c252e4393e9fe85fc162e43d721533736d79c102139d3035d2d9251ccf809bc5bddb81cc6563
  compressed_public_key = 0x03aa3e0b3f86053c2aaa08d6f6398e18f76100e0d675680228b000c252e4393e9f
  address = 0xF7dcf60AebA077461862d51b77d6d804C06E0073
  nonce_zero_contract_address = 0xE861cA8695fEF51Da017D0187bA8C83D22de6708

Dump checksum encoded address from all lowercase address::

  $ eth_address_dump 0xf7dcf60aeba077461862d51b77d6d804c06e0073
  address = 0xF7dcf60AebA077461862d51b77d6d804C06E0073
  nonce_zero_contract_address = 0xE861cA8695fEF51Da017D0187bA8C83D22de6708

Installation
============

To install eth-address-dump from PyPI::

  $ pip3 install eth-address-dump

================
eth-address-dump
================

eth-address-dump is a utility for dump eth address from mnemonic words or private key.


Example
=======

Dump eth address from mnemonic words::

  $ echo "olympic wine chicken argue unaware bundle tunnel grid spider slot spell need" | eth_address_dump
  mnemonic = olympic wine chicken argue unaware bundle tunnel grid spider slot spell need
  private_key = 0x6ee825aafad19a0d759e1e0ba61d0c523b7b23038998a92d7904458b91667105
  public_key = 0xaa3e0b3f86053c2aaa08d6f6398e18f76100e0d675680228b000c252e4393e9fe85fc162e43d721533736d79c102139d3035d2d9251ccf809bc5bddb81cc6563
  compressed_public_key = 0x03aa3e0b3f86053c2aaa08d6f6398e18f76100e0d675680228b000c252e4393e9f
  address = 0xF7dcf60AebA077461862d51b77d6d804C06E0073

Dump eth address from private key::

  $ echo "0x6ee825aafad19a0d759e1e0ba61d0c523b7b23038998a92d7904458b91667105" | eth_address_dump
  private_key = 0x6ee825aafad19a0d759e1e0ba61d0c523b7b23038998a92d7904458b91667105
  public_key = 0xaa3e0b3f86053c2aaa08d6f6398e18f76100e0d675680228b000c252e4393e9fe85fc162e43d721533736d79c102139d3035d2d9251ccf809bc5bddb81cc6563
  compressed_public_key = 0x03aa3e0b3f86053c2aaa08d6f6398e18f76100e0d675680228b000c252e4393e9f
  address = 0xF7dcf60AebA077461862d51b77d6d804C06E0073

Dump eth address from public key::

  $ echo "0xaa3e0b3f86053c2aaa08d6f6398e18f76100e0d675680228b000c252e4393e9fe85fc162e43d721533736d79c102139d3035d2d9251ccf809bc5bddb81cc6563" | eth_address_dump
  public_key = 0xaa3e0b3f86053c2aaa08d6f6398e18f76100e0d675680228b000c252e4393e9fe85fc162e43d721533736d79c102139d3035d2d9251ccf809bc5bddb81cc6563
  compressed_public_key = 0x03aa3e0b3f86053c2aaa08d6f6398e18f76100e0d675680228b000c252e4393e9f
  address = 0xF7dcf60AebA077461862d51b77d6d804C06E0073

Dump eth address from compressed public key::

  $ echo "0x03aa3e0b3f86053c2aaa08d6f6398e18f76100e0d675680228b000c252e4393e9f" | eth_address_dump
  public_key = 0xaa3e0b3f86053c2aaa08d6f6398e18f76100e0d675680228b000c252e4393e9fe85fc162e43d721533736d79c102139d3035d2d9251ccf809bc5bddb81cc6563
  compressed_public_key = 0x03aa3e0b3f86053c2aaa08d6f6398e18f76100e0d675680228b000c252e4393e9f
  address = 0xF7dcf60AebA077461862d51b77d6d804C06E0073

Installation
============

To install eth-address-dump from PyPI::

  $ pip3 install eth-address-dump

================
eth-address-dump
================

eth-address-dump is a utility for dump eth address from mnemonic words or private key.


Example
=======

Dump eth address from mnemonic words::

  $ echo "olympic wine chicken argue unaware bundle tunnel grid spider slot spell need" | eth_address_dump
  private_key = 0x6ee825aafad19a0d759e1e0ba61d0c523b7b23038998a92d7904458b91667105
  address = 0xF7dcf60AebA077461862d51b77d6d804C06E0073


Dump eth address from private key::

  $ echo "0x6ee825aafad19a0d759e1e0ba61d0c523b7b23038998a92d7904458b91667105" | eth_address_dump
  private_key = 0x6ee825aafad19a0d759e1e0ba61d0c523b7b23038998a92d7904458b91667105
  address = 0xF7dcf60AebA077461862d51b77d6d804C06E0073

Installation
============

To install eth-address-dump from PyPI::

  $ pip3 install eth-address-dump

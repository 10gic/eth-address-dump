#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from setuptools import setup

requirements = [
    "pysha3>=1.0.2",
    "ecdsa>=0.15",
    "base58>=2.0.0",
]

setup(
    name='eth-address-dump',
    version='0.1.6',
    author='cig01',
    author_email='juhani AT 163.com',
    url='https://github.com/10gic/eth-address-dump',
    license='MIT License',
    description='A utility for dump eth address from mnemonic words or private key or public key',
    long_description=open('README.rst').read(),
    install_requires=["pysha3", "ecdsa", "base58"],
    python_requires='>=3',
    packages=['eth_address_dump'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Text Processing',
        'Topic :: Utilities',
    ],
    platforms='any',
    entry_points={'console_scripts': ['eth_address_dump=eth_address_dump:run_main']})

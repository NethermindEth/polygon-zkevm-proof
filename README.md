# Sparse Merkle Tree Verification Library

## Overview

This repository contains a Solidity library `SMTProof` for verifying the state of an account or storage slot given a Sparse Merkle Proof and a state root from a block. The library utilizes Poseidon hashing to ensure the integrity of the proof and verification process.

This library is meant replicate this [Implementation in Go](https://github.com/0xPolygonHermez/cdk-erigon/blob/512790f194d65ec27dc1f67da09aec50689795af/smt/pkg/smt/proof.go#L124)

## Library: `SMTProof`

The `SMTProof` library provides `verifyAndGetVal` function for verifying Sparse Merkle Tree (SMT) proofs and extracting values associated with given keys. It leverages the Poseidon hash function for cryptographic verification.

All constants and configuration values where taken from [vectorized-poseidon-gold](https://github.com/NethermindEth/polygon-zkevm-proof/pull/github.com/gateway-fm/vectorized-poseidon-gold) repositoty

## Contract: `PoseidonHash`

The PoseidonHash contract implements the Poseidon hash function, specifically designed for cryptographic applications using the Goldilocks field.

## Usage

### Installation

Ensure you have Forge installed to manage and compile the Solidity code. Follow the installation instructions provided in the Forge [documentation](https://book.getfoundry.sh/) if needed.

### Build

To build the project, use the following command:

```shell
$ forge build
```

### Test

To run tests and verify functionality, use:

```shell
$ forge test
```

Test cases data was taken from the test suite of Go version of the library [here](https://github.com/0xPolygonHermez/cdk-erigon/blob/512790f194d65ec27dc1f67da09aec50689795af/smt/pkg/smt/proof_test.go)

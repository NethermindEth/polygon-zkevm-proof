// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {PoseidonT2} from "lib/poseidon-solidity/contracts/PoseidonT2.sol";
import {PoseidonT3} from "lib/poseidon-solidity/contracts/PoseidonT3.sol";

library SMTProof {
    uint256 constant MASK = 4294967295; // Equivalent to big.NewInt(4294967295)

    struct NodeKey {
        uint64[4] parts;
    }

    function verifyAndGetVal(NodeKey memory stateRoot, bytes[] memory proof, NodeKey memory key)
        public
        pure
        returns (bytes memory, bool)
    {
        require(proof.length > 0, "Proof cannot be empty");

        uint8[256] memory path = getPath(key);
        uint256 currentRoot = uint256(nodeKeyToBytes32(stateRoot));
        bool foundValue = false;

        for (uint256 i; i < proof.length; i++) {
            bool isFinalNode = proof[i].length == 65;

            bytes32 leftChild = bytesToBytes32(proof[i], 0);
            bytes32 rightChild = bytesToBytes32(proof[i], 32);

            uint256 leftChildNode = uint256(leftChild);
            uint256 rightChildNode = uint256(rightChild);

            uint256 computedHash = PoseidonT3.hash([leftChildNode, rightChildNode]);

            require(currentRoot == computedHash, "Root hash mismatch");

            if (!isFinalNode) {
                currentRoot = (path[i] == 0) ? leftChildNode : rightChildNode;

                if (currentRoot == uint256(bytes32(0))) {
                    return ("", false); // Non-existent value
                }
            } else {
                bytes32 joinedKey = joinKey(path, i, leftChild);
                if (joinedKey == nodeKeyToBytes32(key)) {
                    foundValue = true;
                    currentRoot = rightChildNode;
                    break;
                } else {
                    return ("", false); // Proof shows non-existence
                }
            }
        }

        if (!foundValue) {
            revert("Proof insufficient to verify non-existence");
        }

        // The last proof element holds the value
        bytes memory value = proof[proof.length - 1];

        uint256 finalHash = PoseidonT2.hash([prepareValueForHashing(value)]);
        require(finalHash == currentRoot, "Final root hash mismatch");

        return (value, true);
    }

    // Utility Functions

    // Convert proof part to bytes32
    function bytesToBytes32(bytes memory b, uint256 offset) private pure returns (bytes32) {
        bytes32 out;
        assembly {
            out := mload(add(add(b, 0x20), offset))
        }
        return out;
    }

    // Convert NodeKey to bytes32
    function nodeKeyToBytes32(NodeKey memory nodeKey) internal pure returns (bytes32) {
        return bytes32(
            (uint256(nodeKey.parts[0]) << 192) | (uint256(nodeKey.parts[1]) << 128) | (uint256(nodeKey.parts[2]) << 64)
                | uint256(nodeKey.parts[3])
        );
    }

    // Get the path for a given key
    function getPath(NodeKey memory key) private pure returns (uint8[256] memory path) {
        uint64[4] memory auxKey = key.parts;
        uint256 index;

        for (uint256 j; j < 64; j++) {
            for (uint256 i; i < 4; i++) {
                path[index] = uint8(auxKey[i] & 1);
                auxKey[i] >>= 1;
                index++;
            }
        }
    }

    // Utility to extract 64-bit segments from bytes32
    function extractUint64FromBytes32(bytes32 data, uint256 index) private pure returns (uint64) {
        require(index < 4, "Index out of range"); // index can only be 0, 1, 2, or 3
        return uint64(uint256(data) >> (192 - index * 64));
    }

    // Utility to merge uint64 values into a bytes32
    function mergeUint64ToBytes32(uint64[4] memory parts) private pure returns (bytes32) {
        return bytes32(
            (uint256(parts[0]) << 192) | (uint256(parts[1]) << 128) | (uint256(parts[2]) << 64) | uint256(parts[3])
        );
    }

    // Function to implement the JoinKey logic
    function joinKey(uint8[256] memory usedBits, uint256 index, bytes32 remainingKey) private pure returns (bytes32) {
        uint64[4] memory n = [uint64(0), uint64(0), uint64(0), uint64(0)];
        uint64[4] memory accs = [uint64(0), uint64(0), uint64(0), uint64(0)];
        uint64[4] memory remainingParts;

        // Extract uint64 parts from the bytes32 remainingKey
        for (uint256 i; i < 4; i++) {
            remainingParts[i] = extractUint64FromBytes32(remainingKey, i);
        }

        // Process usedBits
        for (uint256 i = 0; i < index; i++) {
            if (usedBits[i] == 1) {
                accs[i % 4] = accs[i % 4] | (uint64(1) << n[i % 4]);
            }
            n[i % 4]++;
        }

        // Combine remainingKey and accs
        uint64[4] memory auxk;
        for (uint256 i = 0; i < 4; i++) {
            auxk[i] = (remainingParts[i] << n[i]) | accs[i];
        }

        // Convert the result back to bytes32 and return
        return mergeUint64ToBytes32(auxk);
    }

    function prepareValueForHashing(bytes memory proof) private pure returns (uint256) {
        require(proof.length >= 32, "Proof must be at least 32 bytes long");

        // Step 1: Extract the last 32 bytes from the proof array
        bytes32 scalarBytes;
        assembly {
            scalarBytes := mload(add(proof, add(0x20, sub(mload(proof), 32))))
        }

        uint256 scalar = uint256(scalarBytes); // Convert the last 32 bytes to uint256

        // Initialize variables to store the parts and the final result
        uint256[8] memory parts;
        uint256 result = 0;

        // Split the scalar into 8 parts of 32 bits each
        parts[0] = scalar & MASK;
        parts[1] = (scalar >> 32) & MASK;
        parts[2] = (scalar >> 64) & MASK;
        parts[3] = (scalar >> 96) & MASK;
        parts[4] = (scalar >> 128) & MASK;
        parts[5] = (scalar >> 160) & MASK;
        parts[6] = (scalar >> 192) & MASK;
        parts[7] = (scalar >> 224) & MASK;

        // Pack the parts back into a single uint256 value
        result |= (parts[0] << 0);
        result |= (parts[1] << 32);
        result |= (parts[2] << 64);
        result |= (parts[3] << 96);
        result |= (parts[4] << 128);
        result |= (parts[5] << 160);
        result |= (parts[6] << 192);
        result |= (parts[7] << 224);

        return result;
    }
}

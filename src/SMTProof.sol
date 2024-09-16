// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {PoseidonHash} from "./Poseidon.sol";

library SMTProof {
    /**
     * @dev Verifies a Sparse Merkle Tree (SMT) proof and retrieves the value associated with a key, if it exists.
     * @param poseidon Instance of the Poseidon hashing contract.
     * @param stateRoot The root of the Sparse Merkle Tree (in 4 segments of uint256).
     * @param proof An array of SMT trie nodes from the root to the leaf, following the path of the key.
     *        - Each node is encoded as a byte array with the following cases:
     *          1. Length = 64: Binary branch node. First 32 bytes is the root hash of the left child,
     *             second 32 bytes is the root hash of the right child. A child hash of 0 means no child exists.
     *          2. Length = 65: Leaf node. First 32 bytes is the remaining key, second 32 bytes is the hash of the data,
     *             and the last byte is 1.
     *          3. Any other length: Value node containing the actual data, e.g., account balance. This will only appear as the last proof item.
     * @param key The key of the node whose value is being verified in the SMT (in 4 segments of uint256).
     * @return value The value associated with the key if found, otherwise empty.
     * @return exists Boolean indicating whether the value was found.
     */
    function verifyAndGetVal(
        PoseidonHash poseidon,
        uint256[4] calldata stateRoot,
        bytes[] memory proof,
        uint256[4] calldata key
    ) external view returns (bytes memory, bool) {
        require(proof.length > 0, "Proof cannot be empty");

        uint8[256] memory path = getPath(key);
        uint256 currentRoot = uint256(mergeUint64ToBytes32(stateRoot));

        for (uint256 i; i < proof.length; ++i) {
            // Extract the left and right child nodes from the proof
            uint256 leftChildNode = uint256(bytesToBytes32(proof[i], 0));
            uint256 rightChildNode = uint256(bytesToBytes32(proof[i], 32));

            // Hash the two children along with the capacity
            uint256[4] memory computedHash = hash(poseidon, leftChildNode, rightChildNode, proof[i]);

            require(currentRoot == uint256(mergeUint64ToBytes32(computedHash)), "Root hash mismatch");

            // If not the final proof node, update the current root to traverse the SMT path
            if (proof[i].length != 65) {
                // Update the current root based on the path direction (left or right child)
                currentRoot = (path[i] == 0) ? leftChildNode : rightChildNode;

                if (currentRoot == 0) {
                    return ("", false); // Non-existent value
                }
            } else {
                // If final node, check if the key matches and return the corresponding value
                if (joinKey(path, i, bytes32(leftChildNode)) == mergeUint64ToBytes32(key)) {
                    // Value was found
                    // The last proof element holds the value
                    bytes memory value = proof[proof.length - 1];

                    computedHash = hash(poseidon, convertProofValueToUint256(value), 0, bytes(""));
                    require(uint256(mergeUint64ToBytes32(computedHash)) == rightChildNode, "Final root hash mismatch");

                    return (value, true); // Return the value and existence as true
                } else {
                    return ("", false); // Proof shows non-existence
                }
            }
        }
        revert("Proof insufficient to verify non-existence");
    }

    // Utility Functions

    // Hashes two child nodes along with capacity with Poseidon hash function.
    function hash(PoseidonHash poseidon, uint256 leftChildNode, uint256 rightChildNode, bytes memory proof)
        private
        view
        returns (uint256[4] memory inputs)
    {
        uint256[] memory input = prepareInputs(leftChildNode, rightChildNode);
        return poseidon.hashNToMNoPad(input, proof.length == 65);
    }

    // Prepares inputs for Poseidon hashing by splitting the child nodes
    function prepareInputs(uint256 leftChildNode, uint256 rightChildNode)
        private
        pure
        returns (uint256[] memory inputs)
    {
        inputs = new uint256[](12);
        uint256 mask = 0xFFFFFFFFFFFFFFFF;

        inputs[0] = (leftChildNode & mask);
        inputs[1] = (leftChildNode >> 64) & mask;
        inputs[2] = (leftChildNode >> 128) & mask;
        inputs[3] = (leftChildNode >> 192) & mask;

        inputs[4] = (rightChildNode & mask);
        inputs[5] = (rightChildNode >> 64) & mask;
        inputs[6] = (rightChildNode >> 128) & mask;
        inputs[7] = (rightChildNode >> 192) & mask;
    }

    // Converts a segment of a proof part into a bytes32 value.
    function bytesToBytes32(bytes memory b, uint256 offset) private pure returns (bytes32) {
        bytes32 out;
        assembly {
            out := mload(add(add(b, 0x20), offset))
        }
        return out;
    }

    // Generates the binary path corresponding to the key.
    function getPath(uint256[4] memory key) private pure returns (uint8[256] memory path) {
        uint256[4] memory auxKey = key;
        uint256 index;

        for (uint256 j; j < 64; ++j) {
            for (uint256 i; i < 4; ++i) {
                path[index] = uint8(auxKey[i] & 1); // Get the least significant bit
                auxKey[i] >>= 1; // Shift right to get the next bit
                index++;
            }
        }
    }

    // Extracts 64-bit segments from a bytes32 value.
    function extractUint64FromBytes32(bytes32 data, uint256 index) private pure returns (uint64) {
        require(index < 4, "Index out of range"); // Ensure index is within range
        return uint64(uint256(data) >> (192 - index * 64)); // Extract 64 bits based on the index
    }

    // Merges four 64-bit segments into a bytes32 value.
    function mergeUint64ToBytes32(uint256[4] memory parts) private pure returns (bytes32) {
        return bytes32((parts[3] << 192) | (parts[2] << 128) | (parts[1] << 64) | parts[0]);
    }

    // Function to implement the JoinKey logic by combining the path and remaining key to create a merged key
    function joinKey(uint8[256] memory usedBits, uint256 index, bytes32 remainingKey) private pure returns (bytes32) {
        uint64[4] memory n = [uint64(0), uint64(0), uint64(0), uint64(0)];
        uint64[4] memory accs = [uint64(0), uint64(0), uint64(0), uint64(0)];
        uint64[4] memory remainingParts;

        // Extract uint64 parts from the bytes32 remainingKey
        for (uint256 i; i < 4; ++i) {
            remainingParts[i] = extractUint64FromBytes32(remainingKey, i);
        }

        // Process usedBits
        uint256 r = 0;
        for (uint256 i; i < index; ++i) {
            if (usedBits[i] == 1) {
                accs[r] = accs[r] | (uint64(1) << n[r]);
            }
            ++n[r];
            ++r;
            if (r == 4) {
                r = 0;
            }
        }

        // Combine remainingKey and accs
        uint256[4] memory auxk;
        for (uint256 i; i < 4; ++i) {
            require(n[i] < 64, "Shift exceeds uint64 bounds");
            auxk[i] = (remainingParts[3 - i] << n[i]) | accs[i];
        }

        // Convert the result back to bytes32 and return
        return mergeUint64ToBytes32(auxk);
    }

    // Converts the bytes value of the last proof element from the proof into a uint256 representation.
    function convertProofValueToUint256(bytes memory value) private pure returns (uint256) {
        require(value.length <= 32, "Bytes value exceeds 32 bytes");
        uint256 result;

        // Iterate through each byte in the `value` and shift it into the result
        for (uint256 i; i < value.length; ++i) {
            result = result << 8; // Shift left by 8 bits
            result |= uint8(value[i]); // Add the byte to the result
        }

        return result;
    }
}

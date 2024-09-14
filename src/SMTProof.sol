// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {PoseidonHash} from "./Poseidon.sol";

library SMTProof {
    struct NodeKey {
        uint256[4] parts;
    }

    function verifyAndGetVal(
        PoseidonHash poseidon,
        NodeKey calldata stateRoot,
        bytes[] memory proof,
        NodeKey calldata key
    ) external view returns (bytes memory, bool) {
        require(proof.length > 0, "Proof cannot be empty");

        uint8[256] memory path = getPath(key);
        uint256 currentRoot = uint256(mergeUint64ToBytes32(stateRoot.parts));

        for (uint256 i; i < proof.length; ++i) {
            uint256 leftChildNode = uint256(bytesToBytes32(proof[i], 0));
            uint256 rightChildNode = uint256(bytesToBytes32(proof[i], 32));

            // Hash the two children along with the capacity
            uint256[4] memory computedHash = hash(poseidon, leftChildNode, rightChildNode, proof[i]);

            require(currentRoot == uint256(mergeUint64ToBytes32(computedHash)), "Root hash mismatch");

            if (proof[i].length != 65) {
                // not final node
                currentRoot = (path[i] == 0) ? leftChildNode : rightChildNode;
                if (currentRoot == 0) {
                    return ("", false); // Non-existent value
                }
            } else {
                if (joinKey(path, i, bytes32(leftChildNode)) == mergeUint64ToBytes32(key.parts)) {
                    // Value was found
                    // The last proof element holds the value
                    bytes memory value = proof[proof.length - 1];

                    computedHash = hash(poseidon, prepareValueForHashing(value), 0, bytes(""));
                    require(uint256(mergeUint64ToBytes32(computedHash)) == rightChildNode, "Final root hash mismatch");
                    return (value, true);
                } else {
                    return ("", false); // Proof shows non-existence
                }
            }
        }
        revert("Proof insufficient to verify non-existence");
    }

    // Utility Functions

    function hash(PoseidonHash poseidon, uint256 leftChildNode, uint256 rightChildNode, bytes memory proof)
        private
        view
        returns (uint256[4] memory inputs)
    {
        uint256[] memory input = prepareInputs(leftChildNode, rightChildNode);
        uint256[4] memory computedHash = poseidon.hashNToMNoPad(input, proof.length == 65);
        return computedHash;
    }

    function prepareInputs(uint256 leftChildNode, uint256 rightChildNode)
        private
        pure
        returns (uint256[] memory inputs)
    {
        inputs = new uint256[](12);
        uint256 mask = 0xFFFFFFFFFFFFFFFF;
        inputs[0] = (leftChildNode & mask);
        leftChildNode >>= 64;
        inputs[1] = (leftChildNode & mask);
        leftChildNode >>= 64;
        inputs[2] = (leftChildNode & mask);
        leftChildNode >>= 64;
        inputs[3] = leftChildNode;

        inputs[4] = (rightChildNode & mask);
        rightChildNode >>= 64;
        inputs[5] = (rightChildNode & mask);
        rightChildNode >>= 64;
        inputs[6] = (rightChildNode & mask);
        rightChildNode >>= 64;
        inputs[7] = rightChildNode;
    }

    // Convert proof part to bytes32
    function bytesToBytes32(bytes memory b, uint256 offset) private pure returns (bytes32) {
        bytes32 out;
        assembly {
            out := mload(add(add(b, 0x20), offset))
        }
        return out;
    }

    // Get the path for a given key
    function getPath(NodeKey memory key) private pure returns (uint8[256] memory path) {
        uint256[4] memory auxKey = key.parts;
        uint256 index;

        for (uint256 j; j < 64; ++j) {
            for (uint256 i; i < 4; ++i) {
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
    function mergeUint64ToBytes32(uint256[4] memory parts) private pure returns (bytes32) {
        return bytes32((parts[3] << 192) | (parts[2] << 128) | (parts[1] << 64) | parts[0]);
    }

    // Function to implement the JoinKey logic
    function joinKey(uint8[256] memory usedBits, uint256 index, bytes32 remainingKey) private pure returns (bytes32) {
        uint64[4] memory n = [uint64(0), uint64(0), uint64(0), uint64(0)];
        uint64[4] memory accs = [uint64(0), uint64(0), uint64(0), uint64(0)];
        uint64[4] memory remainingParts;

        // Extract uint64 parts from the bytes32 remainingKey
        for (uint256 i; i < 4; ++i) {
            remainingParts[i] = extractUint64FromBytes32(remainingKey, i);
        }

        // Process usedBits
        for (uint256 i = 0; i < index; ++i) {
            // console.log("check", usedBits[i]);
            if (usedBits[i] == 1) {
                accs[i % 4] = accs[i % 4] | (uint64(1) << n[i % 4]);
            }
            n[i % 4]++;
        }

        // Combine remainingKey and accs
        uint256[4] memory auxk;
        for (uint256 i = 0; i < 4; ++i) {
            require(n[i] < 64, "Shift exceeds uint64 bounds");
            auxk[i] = (remainingParts[3 - i] << n[i]) | accs[i];
        }

        // Convert the result back to bytes32 and return
        return mergeUint64ToBytes32(auxk);
    }

    function prepareValueForHashing(bytes memory proof) private pure returns (uint256) {
        require(proof.length <= 32, "Bytes value exceeds 32 bytes");
        uint256 result;

        // Iterate through each byte in the `value` and shift it into the result
        for (uint256 i = 0; i < proof.length; i++) {
            result = result << 8; // Shift left by 8 bits
            result |= uint8(proof[i]); // Add the byte to the result
        }

        return result;
    }
}

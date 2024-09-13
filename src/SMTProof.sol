// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {PoseidonT3} from "lib/poseidon-solidity/contracts/PoseidonT3.sol";
import {PoseidonT4} from "lib/poseidon-solidity/contracts/PoseidonT4.sol";
import {PoseidonHash} from "./test.sol";
// import {Poseidon} from "lib/Solidity-goldilocks-poseidon/contract/Poseidon.sol";

import {console} from "lib/forge-std/src/console.sol";

library SMTProof {
    uint256 constant MASK = 4294967295; // Equivalent to big.NewInt(4294967295)

    struct NodeKey {
        uint64[4] parts;
    }

    function verifyAndGetVal(NodeKey calldata stateRoot, bytes[] memory proof, NodeKey calldata key)
        external
        returns (bytes memory, bool)
    {
        require(proof.length > 0, "Proof cannot be empty");

        uint8[256] memory path = getPath(key);
        uint256 currentRoot = uint256(nodeKeyToBytes32(stateRoot));
        bool foundValue = false;

        for (uint256 i; i < proof.length; ++i) {
            bool isFinalNode = proof[i].length == 65;

            // Use appropriate capacity for the node (branch or leaf)
            uint64[4] memory capacity = isFinalNode ? leafCapacity() : branchCapacity();

            bytes32 leftChild = bytesToBytes32(proof[i], 0);
            bytes32 rightChild = bytesToBytes32(proof[i], 32);

            uint256 leftChildNode = uint256(leftChild);
            uint256 rightChildNode = uint256(rightChild);


            uint256[] memory input = new uint256[](12);
            // leftchild splitted into 64 bytes so 4 elements
            input[0] = 11265828233016354482; //leftchild[0]
            input[1] = 6145866189825516934; //leftchild[1]
            input[2] = 6454953523820324073; //leftchild[2]
            input[3] = 15406202713804987152; //leftchild[3]
            // 4 more from the rightchild

            input[4] = 13344658992737595374; //rightchild[0]
            input[5] = 7043377785056816644; // rightchild[1]
            input[6] = 13680389729288841036; //rightchild[2]
            input[7] = 2382165459469383132; //rightchild[3]
             // ---------------------------------------
             // Second iteration
            // input[0] = 10867043059703570303; //leftchild[0]
            // input[1] = 6231198139502073108; //leftchild[1]
            // input[2] = 5762200655505804382; //leftchild[2]
            // input[3] = 12545797600590860965; //leftchild[3]
            // input[4] = 11742412487727341629; //rightchild[0]
            // input[5] = 8324230513740804769; // rightchild[1]
            // input[6] = 15821162717326743443; //rightchild[2]
            // input[7] = 10805897027267208374; //rightchild[3]

            PoseidonHash poseidon = new PoseidonHash();
            // Poseidon poseidon = new Poseidon();

            // Hash the two children along with the capacity
            uint256[4] memory computedHash = poseidon.hashNToMNoPad(input, 4);
            // uint256[] memory computedHash = poseidon.hash_n_to_m_no_pad(input, 4);

            // uint256 memorycomputedHash2 = PoseidonT4.hash([leftChildNode, rightChildNode, convertCapacityToUint256(capacity)]);
            require(currentRoot == computedHash[0], "Root hash mismatch");
            
            if (!isFinalNode) {
                currentRoot = (path[i] == 0) ? leftChildNode : rightChildNode;

                if (currentRoot == 0) {
                    return ("", false); // Non-existent value
                }
            } else {
                bytes32 joinedKey = joinKey(path, i, leftChild); // Join key logic
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
        // console.log("value");
        // console.logBytes(value);

        // Prepare value for hashing
        // For the final hash we need an inputs of size 12 and assign the 8 elements of it with 64 bytes from the value
        uint256 finalHash = PoseidonT3.hash([prepareValueForHashing(value), convertCapacityToUint256(branchCapacity())]);
        require(finalHash == currentRoot, "Final root hash mismatch");

        return (value, true);
    }

    // Utility Functions

    function leafCapacity() private pure returns (uint64[4] memory) {
        return [uint64(1), uint64(0), uint64(0), uint64(0)];
    }

    function branchCapacity() private pure returns (uint64[4] memory) {
        return [uint64(0), uint64(0), uint64(0), uint64(0)];
    }

    // Convert proof part to bytes32
    function bytesToBytes32(bytes memory b, uint256 offset) private pure returns (bytes32) {
        bytes32 out;
        assembly {
            out := mload(add(add(b, 0x20), offset))
        }
        return out;
    }

    function nodeKeyToBytes32(NodeKey memory nodeKey) private pure returns (bytes32) {
        return bytes32(
            (uint256(nodeKey.parts[3]) << 192) | (uint256(nodeKey.parts[2]) << 128) | (uint256(nodeKey.parts[1]) << 64)
                | uint256(nodeKey.parts[0])
        );
    }

    function breakUint256ToUint64Array(uint256 value) internal pure returns (uint64[4] memory) {
        uint64[4] memory result;

        result[0] = uint64(value & 0xFFFFFFFFFFFFFFFF);
        result[1] = uint64((value >> 64) & 0xFFFFFFFFFFFFFFFF);
        result[2] = uint64((value >> 128) & 0xFFFFFFFFFFFFFFFF);
        result[3] = uint64((value >> 192) & 0xFFFFFFFFFFFFFFFF);

        return result;
    }

    // Function to convert uint64[4] to uint256
    function convertCapacityToUint256(uint64[4] memory capacity) private pure returns (uint256 result) {
        for (uint256 i; i < 4; ++i) {
            result |= uint256(capacity[3 - i]) << (i * 64);
        }
    }

    // Get the path for a given key
    function getPath(NodeKey memory key) private pure returns (uint8[256] memory path) {
        uint64[4] memory auxKey = key.parts;
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
    function mergeUint64ToBytes32(uint64[4] memory parts) private pure returns (bytes32) {
        return bytes32(
            (uint256(parts[3]) << 192) | (uint256(parts[2]) << 128) | (uint256(parts[1]) << 64) | uint256(parts[0])
        );
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
        uint64[4] memory auxk;
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

    function combineUint256Array(uint256[] memory arr) public pure returns (uint256) {
        require(arr.length <= 8, "Array is too large to combine into a single uint256");

        uint256 combinedValue = 0;

        for (uint256 i = 0; i < arr.length; i++) {
            combinedValue |= arr[i] << (i * 32);
        }

        return combinedValue;
    }
}

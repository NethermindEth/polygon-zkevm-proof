// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {SMTProof} from "../src/SMTProof.sol";
import {PoseidonHash} from "../src/Poseidon.sol";

contract SMTProofTest is Test {
    using SMTProof for PoseidonHash;

    struct TestData {
        uint256[4] root;
        bytes[] proof;
        uint256[4] key;
    }

    PoseidonHash poseidon;
    string goTests;

    function setUp() public {
        vm.pauseGasMetering(); // intensive reading
        poseidon = new PoseidonHash();
        goTests = vm.readFile("test/go-implementation-tests.json");
        vm.resumeGasMetering();
    }

    function parseUintArray(uint256[] memory data) internal pure returns (uint256[4] memory output) {
        for (uint256 i; i < 4; i++) {
            output[i] = data[i];
        }
    }

    function readTestData(string memory name, uint256 index) public view returns (TestData memory) {
        return TestData({
            root: parseUintArray(
                vm.parseJsonUintArray(goTests, string(abi.encodePacked(".", name, ".test[", vm.toString(index), "].root")))
            ),
            proof: vm.parseJsonBytesArray(
                goTests, string(abi.encodePacked(".", name, ".test[", vm.toString(index), "].proof"))
            ),
            key: parseUintArray(
                vm.parseJsonUintArray(goTests, string(abi.encodePacked(".", name, ".test[", vm.toString(index), "].key")))
            )
        });
    }

    function runTests(string memory name, function(TestData memory, uint256) internal testLogic) internal {
        uint256 cases = vm.parseJsonUint(goTests, string(abi.encodePacked(".", name, ".cases")));

        for (uint256 i; i < cases; ++i) {
            try this.readTestData(name, i) returns (TestData memory test) {
                testLogic(test, i);
            } catch Error(string memory reason) {
                vm.assertTrue(
                    false,
                    string(
                        abi.encodePacked(
                            "Case #", vm.toString(i), " of test ", name, " failed to be read with reason: ", reason
                        )
                    )
                );
            } catch (bytes memory lowLevelData) {
                vm.assertTrue(
                    false,
                    string(
                        abi.encodePacked(
                            "Case #",
                            vm.toString(i),
                            " of test ",
                            name,
                            " failed to be read with reason: ",
                            vm.toString(lowLevelData)
                        )
                    )
                );
            }
        }
    }

    function validProof(TestData memory test, uint256 index) internal view {
        (bytes memory value, bool success) = poseidon.verifyAndGetVal(test.root, test.proof, test.key);
        vm.assertTrue(success, string(abi.encodePacked("Validation should not fail for test ", vm.toString(index))));
        vm.assertEq(
            value,
            test.proof[test.proof.length - 1],
            string(abi.encodePacked("Proof should be valid for test ", vm.toString(index)))
        );
    }

    function invalidProofRootMismatch(TestData memory test, uint256) internal {
        vm.expectRevert("Root hash mismatch");
        poseidon.verifyAndGetVal(test.root, test.proof, test.key);
    }

    function invalidProofValueMismatch(TestData memory test, uint256) internal {
        vm.expectRevert("Final root hash mismatch");
        poseidon.verifyAndGetVal(test.root, test.proof, test.key);
    }

    function nonExistentValue(TestData memory test, uint256 index) internal view {
        (bytes memory value, bool success) = poseidon.verifyAndGetVal(test.root, test.proof, test.key);
        vm.assertFalse(success, string(abi.encodePacked("Validation should fail for test ", vm.toString(index))));
        vm.assertEq(value, bytes(""), string(abi.encodePacked("Value should be empty for test ", vm.toString(index))));
    }

    function insufficient(TestData memory test, uint256) internal {
        vm.expectRevert("Proof insufficient to verify non-existence");
        poseidon.verifyAndGetVal(test.root, test.proof, test.key);
    }

    function tamperProof(TestData memory test, uint256 index) internal {
        bytes memory p0 = test.proof[0];
        test.proof = new bytes[](1); // tamper the proof
        test.proof[0] = p0;
        insufficient(test, index);
    }

    function test_ValueExistsAndProofIsCorrect() public {
        runTests("Value_exists_and_proof_is_correct", validProof);
    }

    function test_ValueDoesntExistAndNonExistentProofIsCorrect() public {
        vm.pauseGasMetering(); // 1000 test cases
        runTests("Value_doesn't_exist_and_non-existent_proof_is_correct", nonExistentValue);
    }

    function test_ValueDoesntExistButNonExistentProofIsInsufficient() public {
        runTests("Value_doesn't_exist_but_non-existent_proof_is_insufficient", nonExistentValue);
        runTests("Value_doesn't_exist_but_non-existent_proof_is_insufficient", tamperProof);
    }

    function test_ValueExistsButProofIsIncorrect() public {
        runTests("Value_exists_but_proof_is_incorrect_first_value_corrupted", invalidProofRootMismatch);
        runTests("Value_exists_but_proof_is_incorrect_last_value_corrupted", invalidProofValueMismatch);
    }

    function test_ValueExistsButProofIsInsufficient() public {
        runTests("Value_exists_but_proof_is_insufficient", insufficient);
    }
}

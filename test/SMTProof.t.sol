// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {SMTProof} from "../src/SMTProof.sol";
import {PoseidonHash} from "../src/Poseidon.sol";

contract SMTProofTest is Test {
    using SMTProof for PoseidonHash;

    PoseidonHash poseidon;

    function setUp() public {
        poseidon = new PoseidonHash();
    }

    function test_VerifyAndGetVal() public view {
        uint256[4] memory stateRoot = [
            uint256(12261328023350694784),
            uint256(5398999462454257983),
            uint256(3331522115182907380),
            uint256(2118679398451823561)
        ];

        uint256[4] memory key = [
            uint256(6951263719529201853),
            uint256(3182020212305369903),
            uint256(4269708063443223864),
            uint256(10115124450955214537)
        ];

        bytes[] memory proof = new bytes[](12);
        proof[0] =
            hex"d5cdd3be1e015b1059949a07b4f764e9554a80bcc9a225869c584316c981a6b2210f26dd37e0b5dcbdda81fa1b29e74c61bf1ac731306e04b931c0a69ed8afee";
        proof[1] =
            hex"ae1ba0727f2a92a54ff772f77bf24c5e5679a9b18e18951496cf7e1634815f7f95f642181db624b6db900faad3ea179373859b8c6ffcf2a1a2f56df19119603d";
        proof[2] =
            hex"cc2667e17d79073795744814bf9fd6a952b5d815495a604d220f0ee441f74ab2842a613fb538b549b8cc7bf73fe0c3647e4323406850667437da7c052ce948c3";
        proof[3] =
            hex"9f5940ca975270b75b29e9dfc4415e150d237dd5d32bd144e4df79518546d1e5d1f47cc223e0ef6fa10ddb97ef530fba460f39b59b58caf1fe9ea9112abfea47";
        proof[4] =
            hex"05be354700b453f3ba496bc5a13b423c4af36d12a6ca110a9cf7e2bfe9eb29313b02dcf6bc94dbf5fb529ee8341ee6cc93c414b9b5aabbdf9401d3b454c2f513";
        proof[5] =
            hex"6dc335ba8e32b70deecd545b7882cad551fe2983706ed7d76484be2cd64834ea6354b1e159a6685df3c9e62db2ebae9aa62178083e81669a80b2ec4026424d91";
        proof[6] =
            hex"045ad704b7ad9c2defad3d362f05f69a934182499353a21e0d636c3359c69a9cf6ef8bcc9f9c118834a0131af75a3ffffb16009bbcd67cef6744dafb5083d86a";
        proof[7] =
            hex"77d12acd71b2dbd64f6d2cbb2837d8cf8531b844badc5f66423a9490fac3e46f1fc5c5fd4ae17685fd722f46e181f972d0013416470b177f56fb4e86a7a2fabc";
        proof[8] =
            hex"60e4a8ad8271ee43d2913d886f8a5425199979401a5ee7da9c3c351b026e235290e6c7072def936eabc4de48a197634f139e0a29af383066616a2dbf1a111287";
        proof[9] =
            hex"c35a8bce73e48d8b58647782b3fce38dc60c2ae36d075fd7c072b0c6e112d8a997be835b921d23dd29148630a424a999748076bd456dc8d7870438dc4f70a8ea";
        proof[10] =
            hex"2318090623836fb20ed043372809e14e058519d0c4d263650c0efb30c0d32817c434991125e49ef1db08c9f514412365efee1dd3114bed39e5d06cb047f44d4601";
        proof[11] = hex"deadbeef";

        // Call the function to verify and get the value
        (bytes memory value, bool success) = poseidon.verifyAndGetVal(stateRoot, proof, key);
        vm.assertTrue(success, "Validation should not fail");
        vm.assertEq(value, proof[11], "Proof should be valid");
    }
}

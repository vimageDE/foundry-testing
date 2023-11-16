// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import {Voting} from "../src/Voting.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract VotingTest is Test {
    using ECDSA for bytes32;

    Voting public voting;
    uint256 private startAt;

    function setUp() public {
        voting = new Voting();
        startAt = block.timestamp;
    }

    function test_zeroIsEmpty() public {
        (uint256 id, string memory name, uint256 voteCount) = voting.candidates(0);
        assertTrue(id == 0);
        assertTrue(bytes(name).length == 0);
        assertTrue(voteCount == 0);
    }

    function test_setup() public {
        (, string memory name1, uint256 voteCount1) = voting.candidates(1);
        assertEq(name1, "Candidate 1");
        assertEq(voteCount1, 0);
        (, string memory name2, uint256 voteCount2) = voting.candidates(2);
        assertEq(name2, "Candidate 2");
        assertEq(voteCount2, 0);
    }

    function test_addCandidate() public {
        uint256 prevCandidates = voting.candidatesCount();

        string memory _name = "Holger";
        voting.addCandidate(_name);
        uint256 currentCandidate = voting.candidatesCount();
        (, string memory name, uint256 voteCount) = voting.candidates(currentCandidate);
        assertEq(name, _name);
        assertEq(voteCount, 0);
        assertEq(prevCandidates + 1, currentCandidate);
    }

    function test_addCandidate_InvalidName() public {
        // Expected Revert
        vm.expectRevert(bytes("Invalid Name"));
        voting.addCandidate("");
    }

    function test_vote() public {
        uint256 id = 2;

        (,, uint256 prevVotes) = voting.candidates(id);
        bool prevVoted = voting.voters(address(this));
        assertFalse(prevVoted);

        voting.vote(id);
        (,, uint256 newVotes) = voting.candidates(id);
        bool newvVoted = voting.voters(address(this));

        assertEq(prevVotes + 1, newVotes);
        assertTrue(newvVoted);
    }

    function test_vote_InvalidCandidate() public {
        vm.expectRevert(abi.encodeWithSelector(Voting.InvalidCandidate.selector, 3, 2));
        voting.vote(3);
    }

    function test_vote_VoteTimeUp() public {
        // Set time to a specific moment
        vm.warp(startAt + 1 days + 1);
        vm.expectRevert(Voting.VoteTimeUp.selector);
        voting.vote(1);
    }

    function test_vote_AlreadyVoted() public {
        voting.vote(2);

        vm.expectRevert(bytes("Already Voted"));
        voting.vote(2);
    }

    function test_vote_votedEvent() public {
        uint256 candidate = 2;
        vm.expectEmit(address(voting));
        // emit the event expected to see
        emit Voting.votedEvent(candidate);
        // perform the function call resulting in the event
        voting.vote(candidate);
    }

    function test_vote_fromOtherAddress() public {
        voting.vote(2);
        vm.expectRevert(bytes("Already Voted"));
        voting.vote(2);
        vm.prank(address(1));
        voting.vote(2);
    }

    function test_voteWithSignature() public {
        address operator = makeAddr("operator");

        (address civilian, uint256 civilianPK) = makeAddrAndKey("civilian");
        uint256 realChoice = 1;
        uint256 realNonce = 0;

        bytes32 hash = _hashMessage(realChoice, civilian, realNonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(civilianPK, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(operator);
        voting.voteWithSignature(realChoice, civilian, realNonce, signature);
    }

    function test_voteWitSignature_nonceUsed() public {
        address operator = makeAddr("operator");

        (address civilian, uint256 civilianPK) = makeAddrAndKey("civilian");
        uint256 realChoice = 1;
        uint256 realNonce = 0;

        bytes32 hash = _hashMessage(realChoice, civilian, realNonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(civilianPK, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.startPrank(operator);
        voting.voteWithSignature(realChoice, civilian, realNonce, signature);
        vm.expectRevert(bytes("Nonce Used"));
        voting.voteWithSignature(realChoice, civilian, realNonce, signature);
        vm.stopPrank();
    }

    function test_voteWithSignature_invalidSignature() public {
        address operator = makeAddr("operator");

        (address civilian, uint256 civilianPK) = makeAddrAndKey("civilian");
        (, uint256 attackerPK) = makeAddrAndKey("attacker");
        uint256 realChoice = 1;
        uint256 realNonce = 0;

        // Create attacker message wrong votingAddress
        bytes32 hash = _hashMessage(realChoice, civilian, realNonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerPK, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(operator);
        vm.expectRevert("Invalid Signature");
        voting.voteWithSignature(realChoice, civilian, realNonce, signature);

        // Create attacker message wrong choice
        hash = _hashMessage(realChoice, civilian, realNonce);
        (v, r, s) = vm.sign(civilianPK, hash);
        signature = abi.encodePacked(r, s, v);

        uint256 fakeChoice = realChoice + 1;

        vm.prank(operator);
        vm.expectRevert("Invalid Signature");
        voting.voteWithSignature(fakeChoice, civilian, realNonce, signature);
    }

    function _hashMessage(uint256 _candidateId, address _votingAddress, uint256 _nonce)
        internal
        view
        returns (bytes32)
    {
        // EIP712 domain type
        string memory name = "Voting";
        string memory version = "1";
        uint256 chainId = block.chainid;
        address verifyingContract = address(voting);

        // stringified types
        string memory EIP712_DOMAIN_TYPE =
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
        string memory MESSAGE_TYPE = "VotingData(uint256 candidateId,address votingAddress,uint256 nonce,string test)";

        // hash to domain to prevent signature collision
        bytes32 DOMAIN_SEPERATOR = keccak256(
            abi.encode(
                keccak256(bytes(EIP712_DOMAIN_TYPE)),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract
            )
        );

        // hash typed data
        bytes32 hash = keccak256(
            abi.encodePacked(
                "\x19\x01", // backslash is needed to escape the character
                DOMAIN_SEPERATOR,
                keccak256(
                    abi.encode(
                        keccak256(bytes(MESSAGE_TYPE)),
                        _candidateId, // Input candidate
                        _votingAddress, // Input voting address
                        _nonce, // Input nonce
                        keccak256("test") // string example input
                    )
                )
            )
        );
        return hash;
    }
}

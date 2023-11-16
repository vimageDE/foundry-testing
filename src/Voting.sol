// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract Voting is EIP712("Voting", "1") {
    using ECDSA for bytes32;
    
    // structure of a candidate
    struct Candidate {
        uint256 id;
        string name;
        uint256 voteCount;
    }

    // Voting Hash Type
    bytes32 private constant VOTING_TYPE_HASH =
        keccak256("VotingData(uint256 candidateId,address votingAddress,uint256 nonce,string test)");

    // VotingTime
    uint256 public constant VOTE_TIME = 1 days;

    // Store accounts that have voted
    mapping(address => bool) public voters;
    // Store Candidates
    // Fetch Candidate
    mapping(uint256 => Candidate) public candidates;
    // Store Candidates Count
    uint256 public candidatesCount;
    // End of Vote
    uint256 public immutable voteEnd;
    // Signature nonces
    mapping(uint256 => bool) nonces;

    // voted event
    event votedEvent(uint256 indexed _candidateId);

    // invalid candidate error
    error InvalidCandidate(uint256 candidate, uint256 candidatesCount);
    // time up error
    error VoteTimeUp();

    constructor() {
        addCandidate("Candidate 1");
        addCandidate("Candidate 2");
        voteEnd = block.timestamp + VOTE_TIME;
    }

    function addCandidate(string memory _name) public {
        require(bytes(_name).length > 0, "Invalid Name");
        candidatesCount++;
        candidates[candidatesCount] = Candidate(candidatesCount, _name, 0);
    }

    function vote(uint256 _candidateId) public {
        _vote(_candidateId, msg.sender);
    }

    function voteWithSignature(uint256 _candidateId, address _votingAddress, uint256 _nonce, bytes calldata _signature)
        public
    {
        require(!nonces[_nonce], "Nonce Used");
        nonces[_nonce] = true;
        bytes32 message = _hashMessage(_candidateId, _votingAddress, _nonce);
        address signer = message.recover(_signature);
        require(signer == _votingAddress, "Invalid Signature");
        _vote(_candidateId, _votingAddress);
    }

    function _vote(uint256 _candidateId, address _votingAddress) internal {
        // check if vote time is up
        if (voteEnd < block.timestamp) revert VoteTimeUp();
        // require that they haven't voted before
        require(!voters[_votingAddress], "Already Voted");

        // require a valid candidate
        if (_candidateId == 0 || _candidateId > candidatesCount) revert InvalidCandidate(_candidateId, candidatesCount);

        // record that voter has voted
        voters[_votingAddress] = true;

        // update candidate vote Count
        candidates[_candidateId].voteCount++;

        // trigger voted event
        emit votedEvent(_candidateId);
    }

    function _hashMessage(uint256 _candidateId, address _votingAddress, uint256 _nonce)
        internal
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(abi.encode(VOTING_TYPE_HASH, _candidateId, _votingAddress, _nonce, keccak256("test")))
        );
    }
}

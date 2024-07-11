// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ICommunity {
    event Lens_Community_MetadataUriSet(string metadataURI);

    event Lens_Community_RulesSet(address communityRules, bytes initializationData);

    event Lens_Community_MemberJoined(address account, uint256 memberId, bytes data);

    event Lens_Community_MemberLeft(address account, uint256 memberId, bytes data);

    event Lens_Community_MemberRemoved(address account, uint256 memberId, bytes data);

    function setCommunityRules(address communityRules, bytes calldata initializationData) external;

    function setMetadataURI(string calldata metadataURI) external;

    function joinCommunity(address account, bytes calldata data) external;

    function leaveCommunity(address account, bytes calldata data) external;

    function removeMember(address account, bytes calldata data) external;

    function getMetadataURI() external view returns (string memory);

    function getNumberOfMembers() external view returns (uint256);

    function getMembershipTimestamp(address account) external view returns (uint256);

    function getMembershipId(address account) external view returns (uint256);

    function getCommunityRules() external view returns (address);

    function getOwner() external view returns (address);
}

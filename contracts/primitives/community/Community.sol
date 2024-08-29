// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ICommunity} from "./ICommunity.sol";
import {ICommunityRule} from "./ICommunityRule.sol";
import {CommunityCore as Core} from "./CommunityCore.sol";
import {IAccessControl} from "./../access-control/IAccessControl.sol";

contract Community is ICommunity {
    // Resource IDs involved in the contract
    uint256 constant SET_RULES_RID = uint256(keccak256("SET_RULES"));
    uint256 constant SET_METADATA_RID = uint256(keccak256("SET_METADATA"));
    uint256 constant CHANGE_ACCESS_CONTROL_RID =
        uint256(keccak256("CHANGE_ACCESS_CONTROL"));

    constructor(string memory metadataURI, IAccessControl accessControl) {
        Core.$storage().metadataURI = metadataURI;
        Core.$storage().accessControl = address(accessControl);
        emit Lens_Community_MetadataUriSet(metadataURI);
    }

    // Access Controlled functions

    function setCommunityRules(
        ICommunityRule communityRules
    ) external override {
        require(
            IAccessControl(Core.$storage().accessControl).hasAccess({
                account: msg.sender,
                resourceLocation: address(this),
                resourceId: SET_RULES_RID
            })
        );
        Core.$storage().communityRules = address(communityRules);
        emit Lens_Community_RulesSet(address(communityRules));
    }

    function setMetadataURI(string calldata metadataURI) external override {
        require(
            IAccessControl(Core.$storage().accessControl).hasAccess({
                account: msg.sender,
                resourceLocation: address(this),
                resourceId: SET_METADATA_RID
            })
        );
        Core.$storage().metadataURI = metadataURI;
        emit Lens_Community_MetadataUriSet(metadataURI);
    }

    // TODO: This is a 1-step operation, while some of our AC owner transfers are a 2-step, or even 3-step operations.
    function setAccessControl(IAccessControl accessControl) external {
        require(
            IAccessControl(Core.$storage().accessControl).hasAccess({
                account: msg.sender,
                resourceLocation: address(this),
                resourceId: CHANGE_ACCESS_CONTROL_RID
            })
        ); // msg.sender must have permissions to change access control
        accessControl.hasAccess(address(0), address(0), 0); // We expect this to not panic.
        Core.$storage().accessControl = address(accessControl);
    }

    // Public functions

    function joinCommunity(
        address account,
        bytes calldata data
    ) external override {
        require(msg.sender == account);
        ICommunityRule rules = ICommunityRule(Core.$storage().communityRules);
        if (address(rules) != address(0)) {
            rules.processJoining(msg.sender, account, data);
        }
        uint256 membershipId = Core._grantMembership(account);
        emit Lens_Community_MemberJoined(account, membershipId, data);
    }

    function leaveCommunity(
        address account,
        bytes calldata data
    ) external override {
        require(msg.sender == account);
        ICommunityRule rules = ICommunityRule(Core.$storage().communityRules);
        if (address(rules) != address(0)) {
            rules.processLeaving(msg.sender, account, data);
        }
        uint256 membershipId = Core._revokeMembership(account);
        emit Lens_Community_MemberLeft(account, membershipId, data);
    }

    // TODO: Why don't we have addMember? Because we don't want to kidnap someone into the community?

    function removeMember(
        address account,
        bytes calldata data
    ) external override {
        ICommunityRule rules = ICommunityRule(Core.$storage().communityRules);
        require(
            address(rules) != address(0),
            "Community: rules are required to remove members"
        );
        rules.processRemoval(msg.sender, account, data);
        uint256 membershipId = Core._revokeMembership(account);
        emit Lens_Community_MemberRemoved(account, membershipId, data);
    }

    // Getters

    function getMetadataURI() external view override returns (string memory) {
        return Core.$storage().metadataURI;
    }

    function getNumberOfMembers() external view override returns (uint256) {
        return Core.$storage().numberOfMembers;
    }

    function getMembershipTimestamp(
        address account
    ) external view override returns (uint256) {
        return Core.$storage().memberships[account].timestamp;
    }

    function getMembershipId(
        address account
    ) external view override returns (uint256) {
        return Core.$storage().memberships[account].id;
    }

    function getCommunityRules() external view override returns (address) {
        return Core.$storage().communityRules;
    }

    function getAccessControl() external view override returns (address) {
        return Core.$storage().accessControl;
    }
}

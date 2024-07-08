// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ICommunityRules} from './ICommunityRules.sol';

// Two types of modules:
/*
    1. Restrictive [Rules/Settings?]:
        - its functions are invoked on all the actions, like: onJoinCommunity() or what not
    2. Extensive [Extensions]:
        - This module is granted an above-user permissions to call functions without verifying the msg.sender of the user

    // TODO: Modify code to add permissions like in the FollowGraph
    // and also solve the naming convention (Module, Rule, Setting, Extension, etc.)
*/

/**
 * An approach for publishing/feed could be to have the community only as a contract to manage the memberships, and then
 * have a separate Publishing System, which will have a module that restricts the publishing to community
 * members only, by querying if it is a member or not, and add any custom restriction/rule if desired.
 *
 * However, we might need to find a way to link them two-way.
 * So there is no fight for legitimacy of a publishing system within the community.
 * As it makes sense that a community has only a single feed.
 * => NO! A community can have multiple feeds, or not have a feed at all.
 * A community on its essence, as a primitive, is just the rules that let this community be formed.
 * So basically, the memberships.
 *
 */

struct Membership {
    uint256 id;
    uint256 timestamp;
}

struct Permissions {
    bool canJoinOnBehalf;
    bool canLeaveOnBehalf;
}

contract Community {
    address internal _admin; // TODO: Make the proper Ownable pattern
    string internal _metadataURI; // Name/title, description, picture, banner, etc.
    ICommunityRules internal _communityRules;
    uint256 _lastMemberIdAssigned;
    uint256 _numberOfMembers;
    mapping(address account => Membership membership) internal _memberships;
    mapping(address account => Permissions permissions) internal _permissions;

    event MemberJoined(address account, uint256 memberId, bytes data);
    event MemberLeft(address account, uint256 memberId);
    event MemberRemoved(address account, uint256 memberId, bytes data);

    function setCommunityRules(ICommunityRules communityRules, bytes calldata initializationData) external {
        if (_admin != msg.sender) {
            revert();
        }
        _communityRules = communityRules;
        if (address(communityRules) != address(0)) {
            _communityRules.initialize(initializationData);
        }
    }

    function setPermissions(address account, Permissions calldata permissions) external {
        if (_admin != msg.sender) {
            revert();
        }
        _permissions[account] = permissions;
    }

    function joinCommunity(address account, bytes calldata data) external {
        if (msg.sender != account && !_permissions[msg.sender].canJoinOnBehalf) {
            revert();
        }
        _lastMemberIdAssigned++;
        _numberOfMembers++;
        if (_memberships[account].id != 0) {
            // Already a member!
            revert();
        }
        _memberships[account] = Membership(_lastMemberIdAssigned, block.timestamp);
        _communityRules.onMembershipGranted(msg.sender, account, data);
        emit MemberJoined(account, _lastMemberIdAssigned, data);
    }

    function leaveCommunity(address account) external {
        if (msg.sender != account && !_permissions[msg.sender].canLeaveOnBehalf) {
            revert();
        }
        if (_memberships[account].id == 0) {
            // Not a member!
            revert();
        }
        _numberOfMembers--;
        emit MemberLeft(account, _memberships[account].id);
        delete _memberships[account];
    }

    function removeMember(address account, bytes calldata data) external {
        if (_memberships[account].id == 0) {
            // Not a member!
            revert();
        }
        _numberOfMembers--;
        emit MemberRemoved(account, _memberships[account].id, data);
        delete _memberships[account];
        _communityRules.onMembershipRevoked(msg.sender, account, data);
    }
}

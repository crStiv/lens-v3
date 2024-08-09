// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Follow, IGraph} from './IGraph.sol';
import {IFollowRules} from './IFollowRules.sol';
import {IGraphRules} from './IGraphRules.sol';
import {GraphCore as Core} from './GraphCore.sol';
import {IAccessControl} from './../access-control/IAccessControl.sol';

contract Graph is IGraph {
    // Resource IDs involved in the contract
    uint256 constant SET_RULES_RID = uint256(keccak256('SET_RULES'));
    uint256 constant SET_METADATA_RID = uint256(keccak256('SET_METADATA'));

    // Access Controlled functions

    function setGraphRules(IGraphRules graphRules) external override {
        require(
            IAccessControl(Core.$storage().accessControl).hasAccess({
                account: msg.sender,
                resourceLocation: address(this),
                resourceId: SET_RULES_RID
            })
        );
        Core.$storage().graphRules = address(graphRules);
        emit Lens_Graph_RulesSet(address(graphRules));
    }

    // Public user functions

    function setFollowRules(
        address account,
        IFollowRules followRules,
        bytes calldata graphRulesData
    ) external override {
        require(msg.sender == account);
        Core.$storage().followRules[account] = address(followRules);
        if (address(Core.$storage().graphRules) != address(0)) {
            IGraphRules(Core.$storage().graphRules).processFollowRulesChange(account, followRules, graphRulesData);
        }
        emit Lens_Graph_FollowRulesSet(account, address(followRules), graphRulesData);
    }

    function follow(
        address followerAccount,
        address targetAccount,
        uint256 followId,
        bytes calldata graphRulesData,
        bytes calldata followRulesData
    ) public returns (uint256) {
        require(msg.sender == followerAccount);
        uint256 assignedFollowId = Core._follow(followerAccount, targetAccount, followId);
        if (address(Core.$storage().graphRules) != address(0)) {
            IGraphRules(Core.$storage().graphRules).processFollow(
                msg.sender,
                followerAccount,
                targetAccount,
                assignedFollowId,
                graphRulesData
            );
        }
        if (address(Core.$storage().followRules[targetAccount]) != address(0)) {
            IFollowRules(Core.$storage().followRules[targetAccount]).processFollow(
                msg.sender,
                followerAccount,
                assignedFollowId,
                followRulesData
            );
        }
        emit Lens_Graph_Followed(followerAccount, targetAccount, assignedFollowId, graphRulesData, followRulesData);
        return assignedFollowId;
    }

    function unfollow(
        address followerAccount,
        address targetAccount,
        bytes calldata graphRulesData
    ) public returns (uint256) {
        require(msg.sender == followerAccount);
        uint256 followId = Core._unfollow(followerAccount, targetAccount);
        if (address(Core.$storage().graphRules) != address(0)) {
            IGraphRules(Core.$storage().graphRules).processUnfollow(
                msg.sender,
                followerAccount,
                targetAccount,
                followId,
                graphRulesData
            );
        }
        emit Lens_Graph_Unfollowed(followerAccount, targetAccount, followId, graphRulesData);
        return followId;
    }

    // Getters

    function isFollowing(address followerAccount, address targetAccount) external view override returns (bool) {
        return Core.$storage().follows[followerAccount][targetAccount].id != 0;
    }

    function getFollowerById(address account, uint256 followId) external view override returns (address) {
        return Core.$storage().followers[account][followId];
    }

    function getFollow(address followerAccount, address targetAccount) external view override returns (Follow memory) {
        return Core.$storage().follows[followerAccount][targetAccount];
    }

    function getFollowRules(address account) external view override returns (IFollowRules) {
        return IFollowRules(Core.$storage().followRules[account]);
    }

    function getFollowersCount(address account) external view override returns (uint256) {
        return Core.$storage().followersCount[account];
    }

    function getGraphRules() external view override returns (IGraphRules) {
        return IGraphRules(Core.$storage().graphRules);
    }
}

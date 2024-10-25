// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {CreatePostParams, EditPostParams} from "./IFeed.sol";
import {RuleConfiguration} from "./../../types/Types.sol";

interface IFeedRule {
    function configure(bytes calldata data) external;

    function processCreatePost(
        uint256 postId,
        uint256 localSequentialId,
        CreatePostParams calldata postParams,
        bytes calldata data
    ) external returns (bool);

    function processEditPost(
        uint256 postId,
        uint256 localSequentialId,
        EditPostParams calldata editPostParams,
        bytes calldata data
    ) external returns (bool);

    function processDeletePost(uint256 postId, uint256 localSequentialId, bytes calldata data)
        external
        returns (bool);

    function processPostRulesChanged(
        uint256 postId,
        uint256 localSequentialId,
        RuleConfiguration[] calldata newPostRules,
        bytes calldata data
    ) external returns (bool);
}

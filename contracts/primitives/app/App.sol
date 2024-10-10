// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IAccessControl} from "./../access-control/IAccessControl.sol";
import {IApp} from "./IApp.sol";
import {AppCore as Core} from "./AppCore.sol";
import {DataElement, DataElementValue} from "./../../types/Types.sol";
import {AccessControlled} from "./../base/AccessControlled.sol";
import {Events} from "./../../types/Events.sol";

struct AppInitialProperties {
    address graph;
    address[] feeds;
    address username;
    address[] communities;
    address defaultFeed;
    address defaultCommunity;
    address[] signers;
    address paymaster;
    address treasury;
}

contract App is IApp, AccessControlled {
    // Resource IDs involved in the contract
    uint256 constant SET_PRIMITIVES_RID = uint256(keccak256("SET_PRIMITIVES"));
    uint256 constant SET_SIGNERS_RID = uint256(keccak256("SET_SIGNERS"));
    uint256 constant SET_TREASURY_RID = uint256(keccak256("SET_TREASURY"));
    uint256 constant SET_PAYMASTER_RID = uint256(keccak256("SET_PAYMASTER"));
    uint256 constant SET_EXTRA_DATA_RID = uint256(keccak256("SET_EXTRA_DATA"));
    uint256 constant SET_METADATA_RID = uint256(keccak256("SET_METADATA"));

    constructor(
        string memory metadataURI,
        IAccessControl accessControl,
        AppInitialProperties memory initialProps,
        DataElement[] memory extraData
    ) AccessControlled(accessControl) {
        _setMetadataURI(metadataURI);
        _setTreasury(initialProps.treasury);
        _setGraph(initialProps.graph);
        _addFeeds(initialProps.feeds);
        _setUsername(initialProps.username);
        _addCommunities(initialProps.communities);
        _setDefaultFeed(initialProps.defaultFeed);
        _setDefaultCommunity(initialProps.defaultCommunity);
        _addSigners(initialProps.signers);
        _setPaymaster(initialProps.paymaster);
        _setExtraData(extraData);

        _emitRIDs();

        emit Events.Lens_Contract_Deployed("app", "lens.app", "app", "lens.app");
    }

    function _emitRIDs() internal override {
        super._emitRIDs();
        emit Lens_ResourceId_Available(SET_PRIMITIVES_RID, "SET_PRIMITIVES");
        emit Lens_ResourceId_Available(SET_SIGNERS_RID, "SET_SIGNERS");
        emit Lens_ResourceId_Available(SET_TREASURY_RID, "SET_TREASURY");
        emit Lens_ResourceId_Available(SET_PAYMASTER_RID, "SET_PAYMASTER");
        emit Lens_ResourceId_Available(SET_EXTRA_DATA_RID, "SET_EXTRA_DATA");
        emit Lens_ResourceId_Available(SET_METADATA_RID, "SET_METADATA");
    }

    ///////////////// Graph

    function setGraph(address graph) public {
        _requireAccess(msg.sender, SET_PRIMITIVES_RID);
        _setGraph(graph);
    }

    // In this implementation we allow to have a single graph only.
    function _setGraph(address graph) internal {
        if (graph == address(0)) {
            Core._removeGraph(Core.$storage().defaultGraph); // Will fail if no graph was set
            Core._setDefaultGraph(address(0));
            emit Lens_App_DefaultGraphRemoved(graph);
            emit Lens_App_GraphRemoved(graph);
        } else {
            address graphPreviouslySet = Core.$storage().defaultGraph;
            bool wasAValueAlreadySet = Core._setDefaultGraph(graph);
            if (wasAValueAlreadySet) {
                Core._removeGraph(graphPreviouslySet);
                emit Lens_App_GraphRemoved(graphPreviouslySet);
                emit Lens_App_GraphAdded(graph);
                emit Lens_App_DefaultGraphUpdated(graph);
            } else {
                emit Lens_App_DefaultGraphAdded(graph);
            }
            Core._addGraph(graph);
        }
    }

    ///////////////// Feed

    function addFeeds(address[] memory feeds) external override {
        _requireAccess(msg.sender, SET_PRIMITIVES_RID);
        _addFeeds(feeds);
    }

    function removeFeeds(address[] memory feeds) external override {
        _requireAccess(msg.sender, SET_PRIMITIVES_RID);
        _removeFeeds(feeds);
    }

    function setDefaultFeed(address feed) external override {
        _requireAccess(msg.sender, SET_PRIMITIVES_RID);
        _setDefaultFeed(feed);
    }

    function _addFeeds(address[] memory feeds) internal {
        for (uint256 i = 0; i < feeds.length; i++) {
            Core._addFeed(feeds[i]);
            emit Lens_App_FeedAdded(feeds[i]);
        }
    }

    function _removeFeeds(address[] memory feeds) internal {
        address defaultFeed = Core.$storage().defaultFeed;
        for (uint256 i = 0; i < feeds.length; i++) {
            if (feeds[i] == defaultFeed) {
                _setDefaultFeed(address(0));
            }
            Core._removeFeed(feeds[i]);
            emit Lens_App_FeedRemoved(feeds[i]);
        }
    }

    function _setDefaultFeed(address feed) internal {
        bool wasAValueAlreadySet = Core._setDefaultFeed(feed);
        if (feed == address(0)) {
            require(wasAValueAlreadySet, "DEFAULT_ALREADY_UNSET");
            emit Lens_App_DefaultFeedRemoved(feed);
        } else if (wasAValueAlreadySet) {
            emit Lens_App_DefaultFeedUpdated(feed);
        } else {
            emit Lens_App_DefaultFeedAdded(feed);
        }
    }

    ///////////////// Username

    function setUsername(address username) public {
        _requireAccess(msg.sender, SET_PRIMITIVES_RID);
        _setUsername(username);
    }

    // In this implementation we allow to have a single graph only.
    function _setUsername(address username) internal {
        if (username == address(0)) {
            Core._removeUsername(Core.$storage().defaultUsername); // Will fail if no username was set
            Core._setDefaultUsername(address(0));
            emit Lens_App_DefaultUsernameRemoved(username);
            emit Lens_App_UsernameRemoved(username);
        } else {
            address usernamePreviouslySet = Core.$storage().defaultUsername;
            bool wasAValueAlreadySet = Core._setDefaultUsername(username);
            if (wasAValueAlreadySet) {
                Core._removeUsername(usernamePreviouslySet);
                emit Lens_App_UsernameRemoved(usernamePreviouslySet);
                emit Lens_App_UsernameAdded(username);
                emit Lens_App_DefaultUsernameUpdated(username);
            } else {
                emit Lens_App_DefaultUsernameAdded(username);
            }
            Core._addUsername(username);
        }
    }

    ///////////////// Community

    function addCommunities(address[] memory communities) external {
        _requireAccess(msg.sender, SET_PRIMITIVES_RID);
        _addCommunities(communities);
    }

    function removeCommunities(address[] memory communities) external {
        _requireAccess(msg.sender, SET_PRIMITIVES_RID);
        _removeCommunities(communities);
    }

    function setDefaultCommunity(address community) external {
        _requireAccess(msg.sender, SET_PRIMITIVES_RID);
        _setDefaultCommunity(community);
    }

    function _addCommunities(address[] memory communities) internal {
        for (uint256 i = 0; i < communities.length; i++) {
            Core._addCommunity(communities[i]);
            emit Lens_App_CommunityAdded(communities[i]);
        }
    }

    function _removeCommunities(address[] memory communities) internal {
        address defaultCommunity = Core.$storage().defaultCommunity;
        for (uint256 i = 0; i < communities.length; i++) {
            if (communities[i] == defaultCommunity) {
                _setDefaultCommunity(address(0));
            }
            Core._removeCommunity(communities[i]);
            emit Lens_App_CommunityRemoved(communities[i]);
        }
    }

    function _setDefaultCommunity(address community) internal {
        bool wasAValueAlreadySet = Core._setDefaultCommunity(community);
        if (community == address(0)) {
            require(wasAValueAlreadySet, "DEFAULT_ALREADY_UNSET");
            emit Lens_App_DefaultCommunityRemoved(community);
        } else if (wasAValueAlreadySet) {
            emit Lens_App_DefaultCommunityUpdated(community);
        } else {
            emit Lens_App_DefaultCommunityAdded(community);
        }
    }

    ///////////////// Signers

    function addSigners(address[] memory signers) external {
        _requireAccess(msg.sender, SET_SIGNERS_RID);
        _addSigners(signers);
    }

    function removeSigners(address[] memory signers) external {
        _requireAccess(msg.sender, SET_SIGNERS_RID);
        _removeSigners(signers);
    }

    function _addSigners(address[] memory signers) internal {
        for (uint256 i = 0; i < signers.length; i++) {
            Core._addSigner(signers[i]);
            emit Lens_App_SignerAdded(signers[i]);
        }
    }

    function _removeSigners(address[] memory signers) internal {
        for (uint256 i = 0; i < signers.length; i++) {
            Core._removeSigner(signers[i]);
            emit Lens_App_SignerRemoved(signers[i]);
        }
    }

    ///////////////// Paymaster

    function setPaymaster(address paymaster) public {
        _requireAccess(msg.sender, SET_PRIMITIVES_RID);
        _setPaymaster(paymaster);
    }

    // In this implementation we allow to have a single paymaster only.
    function _setPaymaster(address paymaster) internal {
        if (paymaster == address(0)) {
            Core._removePaymaster(Core.$storage().defaultPaymaster); // Will fail if no paymaster was set
            Core._setDefaultPaymaster(address(0));
            emit Lens_App_DefaultPaymasterRemoved(paymaster);
            emit Lens_App_PaymasterRemoved(paymaster);
        } else {
            address paymasterPreviouslySet = Core.$storage().defaultPaymaster;
            bool wasAValueAlreadySet = Core._setDefaultPaymaster(paymaster);
            if (wasAValueAlreadySet) {
                Core._removePaymaster(paymasterPreviouslySet);
                emit Lens_App_PaymasterRemoved(paymasterPreviouslySet);
                emit Lens_App_PaymasterAdded(paymaster);
                emit Lens_App_DefaultPaymasterUpdated(paymaster);
            } else {
                emit Lens_App_DefaultPaymasterAdded(paymaster);
            }
            Core._addPaymaster(paymaster);
        }
    }

    ///////////////// Treasury

    function setTreasury(address treasury) public {
        _requireAccess(msg.sender, SET_TREASURY_RID);
        _setTreasury(treasury);
    }

    function _setTreasury(address treasury) internal {
        Core._setTreasury(treasury);
        emit Lens_App_TreasurySet(treasury);
    }

    ///////////////// Metadata URI

    function setMetadataURI(string calldata metadataURI) public override {
        _requireAccess(msg.sender, SET_METADATA_RID);
        _setMetadataURI(metadataURI);
    }

    function _setMetadataURI(string memory metadataURI) internal {
        Core._setMetadataURI(metadataURI);
        emit Lens_App_MetadataURISet(metadataURI);
    }

    ///////////////// Extra Data

    function setExtraData(DataElement[] calldata extraDataToSet) external override {
        _requireAccess(msg.sender, SET_EXTRA_DATA_RID);
        _setExtraData(extraDataToSet);
    }

    function _setExtraData(DataElement[] memory extraDataToSet) internal {
        _requireAccess(msg.sender, SET_EXTRA_DATA_RID);
        for (uint256 i = 0; i < extraDataToSet.length; i++) {
            bool wasExtraDataAlreadySet = Core._setExtraData(extraDataToSet[i]);
            if (wasExtraDataAlreadySet) {
                emit Lens_App_ExtraDataUpdated(extraDataToSet[i].key, extraDataToSet[i].value, extraDataToSet[i].value);
            } else {
                emit Lens_App_ExtraDataAdded(extraDataToSet[i].key, extraDataToSet[i].value, extraDataToSet[i].value);
            }
        }
    }

    function removeExtraData(bytes32[] calldata extraDataKeysToRemove) external override {
        _requireAccess(msg.sender, SET_EXTRA_DATA_RID);
        for (uint256 i = 0; i < extraDataKeysToRemove.length; i++) {
            Core._removeExtraData(extraDataKeysToRemove[i]);
            emit Lens_App_ExtraDataRemoved(extraDataKeysToRemove[i]);
        }
    }

    //////////////////////////////////////////////////////////////////////////
    // Getters
    //////////////////////////////////////////////////////////////////////////

    function getGraphs() public view returns (address[] memory) {
        return Core.$storage().graphs;
    }

    function getFeeds() public view returns (address[] memory) {
        return Core.$storage().feeds;
    }

    function getUsernames() public view returns (address[] memory) {
        return Core.$storage().usernames;
    }

    function getCommunities() public view returns (address[] memory) {
        return Core.$storage().communities;
    }

    function getDefaultGraph() public view returns (address) {
        return Core.$storage().defaultGraph;
    }

    function getDefaultFeed() public view returns (address) {
        return Core.$storage().defaultFeed;
    }

    function getDefaultUsername() public view returns (address) {
        return Core.$storage().defaultUsername;
    }

    function getDefaultCommunity() public view returns (address) {
        return Core.$storage().defaultCommunity;
    }

    function getSigners() public view returns (address[] memory) {
        return Core.$storage().signers;
    }

    function getExtraData(bytes32 key) external view override returns (DataElementValue memory) {
        return Core.$storage().extraData[key];
    }

    function getMetadataURI() external view override returns (string memory) {
        return Core.$storage().metadataURI;
    }
}

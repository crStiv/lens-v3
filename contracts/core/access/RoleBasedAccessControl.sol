// SPDX-License-Identifier: UNLICENSED
// Copyright (C) 2024 Lens Labs. All Rights Reserved.
pragma solidity ^0.8.0;

import {Access, IRoleBasedAccessControl} from "./../interfaces/IRoleBasedAccessControl.sol";
import {Events} from "./../types/Events.sol";

/**
 * @title RoleBasedAccessControl
 * @notice Implementation of a role-based access control system with hierarchical permissions
 * @dev This contract implements a flexible access control system with the following features:
 * - Single owner role with full permissions
 * - Support for multiple custom roles
 * - Hierarchical permission system with wildcards
 * - Granular permission control per contract and action
 * - Permission inheritance and override mechanisms
 *
 * Security considerations:
 * - Owner role has unlimited permissions and should be assigned carefully
 * - Role assignments should be monitored as they can grant significant permissions
 * - Permission changes are only allowed by the owner
 */
contract RoleBasedAccessControl is IRoleBasedAccessControl {
    event Lens_OwnershipTransferred(address indexed previousOwner, address indexed newOwner); // TODO: Do we need it?

    address internal constant ANY_CONTRACT_ADDRESS = address(0);
    uint256 internal constant ANY_PERMISSION_ID = uint256(0);
    uint256 constant OWNER_ROLE_ID = uint256(keccak256("OWNER"));

    address internal _owner;
    mapping(address => uint256[]) internal _roles;
    mapping(uint256 => mapping(address => mapping(uint256 => Access))) internal _access;

    constructor(address owner) {
        _emitLensContractDeployedEvent();
        _owner = owner;
        _grantRole(owner, OWNER_ROLE_ID);
        _setAccess(OWNER_ROLE_ID, ANY_CONTRACT_ADDRESS, ANY_PERMISSION_ID, Access.GRANTED);
    }

    function transferOwnership(address newOwner) external virtual {
        address oldOwner = _owner;
        require(msg.sender == oldOwner, "Only owner can transfer ownership");
        _owner = newOwner;
        _revokeRole(oldOwner, OWNER_ROLE_ID);
        _grantRole(newOwner, OWNER_ROLE_ID);
        emit Lens_OwnershipTransferred(oldOwner, newOwner);
    }

    function getType() external pure virtual override returns (bytes32) {
        return keccak256("lens.access-control.role-based-access-control");
    }

    function canChangeAccessControl(address account, address /* contractAddress */ )
        external
        view
        virtual
        override
        returns (bool)
    {
        return account == _owner;
    }

    function hasAccess(address account, address contractAddress, uint256 permissionId)
        external
        view
        virtual
        override
        returns (bool)
    {
        return _hasAccess(account, contractAddress, permissionId);
    }

    function grantRole(address account, uint256 roleId) external virtual override {
        _beforeGrantingRole(account, roleId);
        _grantRole(account, roleId);
    }

    function _beforeGrantingRole(address, /* account */ uint256 roleId) internal virtual {
        require(msg.sender == _owner, "Only owner can assign roles");
        require(roleId != OWNER_ROLE_ID, "Cannot grant owner role");
    }

    function _grantRole(address account, uint256 roleId) internal virtual {
        require(account != address(0), "Cannot grant role to zero address");
        require(!_hasRole(account, roleId), "Role already granted");
        _roles[account].push(roleId);
        emit Lens_AccessControl_RoleGranted(account, roleId);
    }

    function revokeRole(address account, uint256 roleId) external virtual override {
        _beforeRevokingRole(account, roleId);
        _revokeRole(account, roleId);
    }

    function _beforeRevokingRole(address, /* account */ uint256 roleId) internal virtual {
        require(msg.sender == _owner, "Only owner can revoke roles");
        require(roleId != OWNER_ROLE_ID, "Cannot revoke owner role");
    }

    function _revokeRole(address account, uint256 roleId) internal virtual {
        uint256 accountRolesLength = _roles[account].length;
        require(accountRolesLength > 0, "Account has no roles");
        
        for (uint256 i = 0; i < accountRolesLength; i++) {
            if (_roles[account][i] == roleId) {
                // Move the last element to the position being deleted
                _roles[account][i] = _roles[account][accountRolesLength - 1];
                _roles[account].pop();
                emit Lens_AccessControl_RoleRevoked(account, roleId);
                return;
            }
        }
        revert("Role not found");
    }

    function hasRole(address account, uint256 roleId) external view override returns (bool) {
        return _hasRole(account, roleId);
    }

    function setAccess(uint256 roleId, address contractAddress, uint256 permissionId, Access access)
        external
        virtual
        override
    {
        _beforeSettingAccess(roleId, contractAddress, permissionId, access);
        _setAccess(roleId, contractAddress, permissionId, access);
    }

    function _beforeSettingAccess(
        uint256 roleId,
        address, /* contractAddress */
        uint256, /* permissionId */
        Access /* access */
    ) internal virtual {
        require(msg.sender == _owner, "Only owner can set access");
        require(roleId != OWNER_ROLE_ID, "Cannot set access for owner role");
    }

    function _setAccess(uint256 roleId, address contractAddress, uint256 permissionId, Access access)
        internal
        virtual
    {
        Access perviousAccess = _access[roleId][contractAddress][permissionId];
        _access[roleId][contractAddress][permissionId] = access;
        if (perviousAccess == Access.UNDEFINED) {
            require(access != Access.UNDEFINED);
            emit Lens_AccessControl_AccessAdded(roleId, contractAddress, permissionId, access == Access.GRANTED);
        } else if (access == Access.UNDEFINED) {
            emit Lens_AccessControl_AccessRemoved(roleId, contractAddress, permissionId);
        } else {
            emit Lens_AccessControl_AccessUpdated(roleId, contractAddress, permissionId, access == Access.GRANTED);
        }
    }

    function _hasAccess(address account, address contractAddress, uint256 permissionId)
        internal
        view
        virtual
        returns (bool)
    {
        for (uint256 i = 0; i < _roles[account].length; i++) {
            if (_hasAccess(_roles[account][i], contractAddress, permissionId)) {
                // GRANTED-overrides strategy
                return true;
            }
        }
        return false;
    }

    function _hasAccess(uint256 roleId, address contractAddress, uint256 permissionId)
        internal
        view
        virtual
        returns (bool)
    {
        require(contractAddress != ANY_CONTRACT_ADDRESS, "Invalid contract address");
        require(permissionId != ANY_PERMISSION_ID, "Invalid permission ID");

        // Check fully specified access first
        Access fullySpecifiedAccess = _access[roleId][contractAddress][permissionId];
        if (fullySpecifiedAccess != Access.UNDEFINED) {
            return fullySpecifiedAccess == Access.GRANTED;
        }

        // Check partial wildcards
        Access anyPermissionAccess = _access[roleId][contractAddress][ANY_PERMISSION_ID];
        Access anyAddressAccess = _access[roleId][ANY_CONTRACT_ADDRESS][permissionId];

        // If both partial wildcards are undefined, check full wildcard
        if (anyPermissionAccess == Access.UNDEFINED && anyAddressAccess == Access.UNDEFINED) {
            return _access[roleId][ANY_CONTRACT_ADDRESS][ANY_PERMISSION_ID] == Access.GRANTED;
        }

        // Apply DENIED-overrides strategy for partial wildcards
        return anyPermissionAccess != Access.DENIED && anyAddressAccess != Access.DENIED;
    }

    function getAccess(uint256 roleId, address contractAddress, uint256 permissionId)
        external
        view
        virtual
        override
        returns (Access)
    {
        return _access[roleId][contractAddress][permissionId];
    }

    function _hasRole(address account, uint256 roleId) internal view virtual returns (bool) {
        for (uint256 i = 0; i < _roles[account].length; i++) {
            if (_roles[account][i] == roleId) {
                return true;
            }
        }
        return false;
    }

    function _emitLensContractDeployedEvent() internal virtual {
        emit Events.Lens_Contract_Deployed(
            "access-control",
            "lens.access-control.role-based-access-control",
            "access-control",
            "lens.access-control.role-based-access-control"
        );
    }
}

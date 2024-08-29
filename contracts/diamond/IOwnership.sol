// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IOwnership {
    function getOwner() external view returns (address);
}

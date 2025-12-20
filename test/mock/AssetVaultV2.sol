// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {AssetVault} from "../../src/AssetVault.sol";

contract AssetVaultV2 is AssetVault {
    uint256 public newVariable;

    function setNewVariable(uint256 value) external {
        newVariable = value;
    }
}

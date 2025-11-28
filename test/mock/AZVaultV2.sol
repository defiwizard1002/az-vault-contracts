// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {AZVault} from "../../src/AZVault.sol";

contract AZVaultV2 is AZVault {
    uint256 public newVariable;

    function setNewVariable(uint256 value) external {
        newVariable = value;
    }
}

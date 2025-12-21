// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {AssetVault} from "../../src/AssetVault.sol";

contract AssetVaultV2 is AssetVault {
    uint256 public newVariable;

    function refillWithdrawHotAmount(address token) external {
        _refillWithdrawHotAmount(token);
    }

    function mockIncreaseUsedWithdrawHotAmount(
        address token,
        uint256 amount
    ) external returns (bool forcePending) {
        return _increaseUsedWithdrawHotAmount(supportedTokens[token], amount);
    }
}

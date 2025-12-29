// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {AssetVault, ValidatorInfo, WithdrawAction, TokenInfo} from "../src/AssetVault.sol";
import {AssetVaultV2} from "./mock/AssetVaultV2.sol";
import {MockERC20} from "./mock/MockERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract AssetVaultTest is Test {
    AssetVault public vault;
    AssetVault public implementation;
    AssetVaultV2 public implementationV2;
    MockERC20 public token1;
    MockERC20 public token2;

    address public admin = address(0x1);
    address public operator = address(0x2);
    address public tokenRole = address(0x3);
    address public pauseRole = address(0x4);
    address public user = address(0x5);
    address public upgradeRole = address(0x7);

    // 0x103530DbAE2A5c82a9bCE16f568A972F1C3AA54f
    address public validator1;
    // 0x68bF386105c6De29A9cBe64f87D5864Cdc657cE3
    address public validator2;
    // 0xEa83E5c9Ab85Ae63eb50cE88dB44dd9b9e58120F
    address public validator3;

    uint256 private validator1Key = 0xaff81bf6f5d18dfae8a2b94fb06a55d4360e6f05a934f8aec61cf4dee86e2991;
    uint256 private validator2Key = 0xf0e85c9dc8a15fb716f9ffd63822e97a5d611a2e63a1f9441f75bfc86da24c6f;
    uint256 private validator3Key = 0x40c8c2113fe3bf523638b61aba6d83ad93488479e16f9d18d64a9556c428f098;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant TOKEN_ROLE = keccak256("TOKEN_ROLE");
    bytes32 public constant PAUSE_ROLE = keccak256("PAUSE_ROLE");
    bytes32 public constant UPGRADE_ROLE = keccak256("UPGRADE_ROLE");

    uint256 public constant CHALLENGE_PERIOD = 1 days;

    function setUp() public {
        validator1 = vm.addr(validator1Key);
        validator2 = vm.addr(validator2Key);
        validator3 = vm.addr(validator3Key);

        implementation = new AssetVault();
        bytes memory initData = abi.encodeWithSelector(
            AssetVault.initialize.selector,
            CHALLENGE_PERIOD
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        vault = AssetVault(payable(address(proxy)));

        vm.startPrank(address(this));
        vault.grantRole(ADMIN_ROLE, admin);
        vault.grantRole(OPERATOR_ROLE, operator);
        vault.grantRole(TOKEN_ROLE, tokenRole);
        vault.grantRole(PAUSE_ROLE, pauseRole);
        vault.grantRole(UPGRADE_ROLE, upgradeRole);
        vm.stopPrank();

        token1 = new MockERC20("Token1", "T1");
        token2 = new MockERC20("Token2", "T2");

        vm.prank(tokenRole);
        vault.addToken(address(token1), 5000, 1000);
        vm.prank(tokenRole);
        vault.addToken(address(token2), 5000, 1000);
        vm.prank(tokenRole);
        vault.addToken(address(0), 5000, 1000);

        ValidatorInfo[] memory validators = new ValidatorInfo[](3);
        validators[0] = ValidatorInfo({signer: validator1, power: 10});
        validators[1] = ValidatorInfo({signer: validator2, power: 20});
        validators[2] = ValidatorInfo({signer: validator3, power: 30});

        vm.prank(admin);
        vault.addValidators(validators);

        token1.mint(user, 10000e18);
        token2.mint(user, 10000e18);
    }

    function test_Setup() public {
        assertTrue(vault.hasRole(ADMIN_ROLE, admin));
        assertTrue(vault.hasRole(OPERATOR_ROLE, operator));
        assertTrue(vault.hasRole(TOKEN_ROLE, tokenRole));
        assertTrue(vault.hasRole(PAUSE_ROLE, pauseRole));
        assertTrue(vault.hasRole(UPGRADE_ROLE, upgradeRole));
        assertEq(vault.pendingWithdrawChallengePeriod(), CHALLENGE_PERIOD);
    }

    function test_AddToken_OnlyTokenRole() public {
        MockERC20 newToken = new MockERC20("NewToken", "NT");

        vm.expectRevert();
        vm.prank(user);
        vault.addToken(address(newToken), 5000, 1000);

        vm.expectEmit(true, false, false, true);
        emit AssetVault.TokenAdded(address(newToken), 5000, 1000);
        vm.prank(tokenRole);
        vault.addToken(address(newToken), 5000, 1000);
        (address tokenAddr, , , , ) = vault.supportedTokens(address(newToken));
        assertTrue(tokenAddr != address(0));
    }

    function test_AddToken_AlreadyExists_Reverts() public {
        vm.expectRevert(AssetVault.TokenAlreadyExists.selector);
        vm.prank(tokenRole);
        vault.addToken(address(token1), 5000, 1000);
    }

    function test_RemoveToken_OnlyAdmin() public {
        vm.expectRevert();
        vm.prank(user);
        vault.removeToken(address(token1));

        vm.expectEmit(true, false, false, true);
        emit AssetVault.TokenRemoved(address(token1));
        vm.prank(admin);
        vault.removeToken(address(token1));
        (address tokenAddr, , , , ) = vault.supportedTokens(address(token1));
        assertTrue(tokenAddr == address(0));
    }

    function test_RemoveToken_NotSupported_Reverts() public {
        MockERC20 unsupported = new MockERC20("Unsupported", "U");
        vm.expectRevert(AssetVault.TokenNotSupported.selector);
        vm.prank(admin);
        vault.removeToken(address(unsupported));
    }

    function test_UpdateToken_OnlyAdmin() public {
        vm.expectRevert();
        vm.prank(user);
        vault.updateToken(address(token1), 6000, 2000);

        vm.expectEmit(true, false, false, true);
        emit AssetVault.TokenUpdated(address(token1), 6000, 2000);
        vm.prank(admin);
        vault.updateToken(address(token1), 6000, 2000);
        (, uint256 hardCapRatioBps, uint256 refillRateMps, , ) = vault.supportedTokens(address(token1));
        assertEq(hardCapRatioBps, 6000);
        assertEq(refillRateMps, 2000);
    }

    function test_UpdateToken_NotSupported_Reverts() public {
        MockERC20 unsupported = new MockERC20("Unsupported", "U");
        vm.expectRevert(AssetVault.TokenNotSupported.selector);
        vm.prank(admin);
        vault.updateToken(address(unsupported), 6000, 2000);
    }

    function test_Deposit_OnlySupportedToken() public {
        MockERC20 unsupported = new MockERC20("Unsupported", "U");
        vm.startPrank(user);
        unsupported.mint(user, 100e18);
        unsupported.approve(address(vault), 100e18);
        vm.expectRevert(AssetVault.TokenNotSupported.selector);
        vault.deposit(address(unsupported), 100e18);
        vm.stopPrank();
    }

    function test_Deposit_ERC20() public {
        vm.startPrank(user);
        token1.approve(address(vault), 100e18);
        vm.expectEmit(true, true, false, true);
        emit AssetVault.Deposit(user, address(token1), 100e18);
        vault.deposit(address(token1), 100e18);
        vm.stopPrank();
        assertEq(token1.balanceOf(address(vault)), 100e18);
    }

    function test_Deposit_ETH() public {
        vm.deal(user, 10e18);
        vm.expectEmit(true, true, false, true);
        emit AssetVault.Deposit(user, address(0), 10e18);
        vm.prank(user);
        vault.deposit{value: 10e18}(address(0), 10e18);
        assertEq(address(vault).balance, 10e18);
    }

    function test_Deposit_WhenPaused_Reverts() public {
        vm.prank(pauseRole);
        vault.pause();
        vm.startPrank(user);
        token1.approve(address(vault), 100e18);
        vm.expectRevert();
        vault.deposit(address(token1), 100e18);
        vm.stopPrank();
    }

    function test_AddValidators_OnlyAdmin() public {
        ValidatorInfo[] memory newValidators = new ValidatorInfo[](2);
        newValidators[0] = ValidatorInfo({signer: address(0x20), power: 5});
        newValidators[1] = ValidatorInfo({signer: address(0x21), power: 15});

        vm.expectRevert();
        vm.prank(user);
        vault.addValidators(newValidators);

        vm.prank(admin);
        vault.addValidators(newValidators);
    }

    function test_AddValidators_NotOrdered_Reverts() public {
        ValidatorInfo[] memory invalidValidators = new ValidatorInfo[](2);
        invalidValidators[0] = ValidatorInfo({signer: address(0x21), power: 15});
        invalidValidators[1] = ValidatorInfo({signer: address(0x20), power: 5});

        vm.expectRevert(AssetVault.ValidatorsNotOrdered.selector);
        vm.prank(admin);
        vault.addValidators(invalidValidators);
    }

    function test_AddValidators_AlreadySet_Reverts() public {
        ValidatorInfo[] memory validators = new ValidatorInfo[](3);
        validators[0] = ValidatorInfo({signer: validator1, power: 10});
        validators[1] = ValidatorInfo({signer: validator2, power: 20});
        validators[2] = ValidatorInfo({signer: validator3, power: 30});

        vm.expectRevert(AssetVault.ValidatorsAlreadySet.selector);
        vm.prank(admin);
        vault.addValidators(validators);
    }

    function test_RemoveValidators_OnlyAdmin() public {
        ValidatorInfo[] memory validators = new ValidatorInfo[](3);
        validators[0] = ValidatorInfo({signer: validator1, power: 10});
        validators[1] = ValidatorInfo({signer: validator2, power: 20});
        validators[2] = ValidatorInfo({signer: validator3, power: 30});
        bytes32 validatorHash = keccak256(abi.encode(validators));

        vm.expectRevert();
        vm.prank(user);
        vault.removeValidators(validators);

        vm.expectEmit(true, false, false, true);
        emit AssetVault.ValidatorsRemoved(validatorHash, 3);
        vm.prank(admin);
        vault.removeValidators(validators);
    }

    function test_UpdatePendingWithdrawChallengePeriod_OnlyAdmin() public {
        vm.expectRevert();
        vm.prank(user);
        vault.updatePendingWithdrawChallengePeriod(2 days);

        vm.expectEmit(false, false, false, true);
        emit AssetVault.PendingWithdrawChallengePeriodUpdated(CHALLENGE_PERIOD, 2 days);
        vm.prank(admin);
        vault.updatePendingWithdrawChallengePeriod(2 days);
        assertEq(vault.pendingWithdrawChallengePeriod(), 2 days);
    }

    function test_RefillWithdrawHotAmount() public {
        vm.startPrank(user);
        token1.approve(address(vault), 1000e18);
        vault.deposit(address(token1), 1000e18);
        vm.stopPrank();

        uint256 id = 1;
        uint256 withdrawAmount = 100e18;
        address receiver = address(0x100);

        WithdrawTestData memory data = _prepareRequestWithdrawData(
            id,
            address(token1),
            withdrawAmount,
            0,
            receiver,
            false
        );

        vm.prank(operator);
        vault.requestWithdraw(id, false, data.validators, data.action, data.signatures);

        implementationV2 = new AssetVaultV2();
        vm.prank(upgradeRole);
        vault.upgradeToAndCall(address(implementationV2), "");

        AssetVaultV2 vaultV2 = AssetVaultV2(payable(address(vault)));
        
        (address token, uint256 hardCapRatioBps, uint256 refillRateMps, uint256 lastRefillBefore, uint256 usedBefore) = vault.supportedTokens(address(token1));
        
        uint256 balance = token1.balanceOf(address(vault));
        uint256 hardCap = (balance * hardCapRatioBps) / 10000;
        uint256 timePassed = 100;
        // 100 * (5000 / 10000) * (1000 / 1000000) * 900 = 45e18
        uint256 expectedRefillAmount = (hardCap * refillRateMps * timePassed) / 1000000;
        
        vm.warp(block.timestamp + timePassed);
        vaultV2.refillWithdrawHotAmount(address(token1));
        
        (, , , uint256 lastRefillAfter, uint256 usedAfter) = vault.supportedTokens(address(token1));
        
        uint256 expectedUsedAfter = usedBefore >= expectedRefillAmount ? usedBefore - expectedRefillAmount : 0;
        
        assertEq(usedAfter, expectedUsedAfter);
        assertEq(lastRefillAfter, block.timestamp);
        assertEq(hardCap, 450e18);
        assertEq(expectedRefillAmount, 45e18);
        assertEq(usedBefore, 100e18);
        assertEq(usedAfter, 55e18);

        vm.warp(block.timestamp + 10000 days);
        vaultV2.refillWithdrawHotAmount(address(token1));
        (, , , uint256 lastRefillAfter2, uint256 usedAfter2) = vault.supportedTokens(address(token1));
        assertEq(lastRefillAfter2, block.timestamp);
        assertEq(usedAfter2, 0);
    }

    function test_IncreaseUsedWithdrawHotAmount() public {
        vm.startPrank(user);
        token1.approve(address(vault), 1000e18);
        vault.deposit(address(token1), 1000e18);
        vm.stopPrank();

        implementationV2 = new AssetVaultV2();
        vm.prank(upgradeRole);
        vault.upgradeToAndCall(address(implementationV2), "");

        AssetVaultV2 vaultV2 = AssetVaultV2(payable(address(vault)));
        (, , , , uint256 usedBefore) = vault.supportedTokens(address(token1));
        uint256 hardCap = (1000e18 * 5000) / 10000;
        uint256 smallAmount = hardCap / 2;
        bool forcePending = vaultV2.mockIncreaseUsedWithdrawHotAmount(address(token1), smallAmount);
        assertFalse(forcePending);
        (, , , , uint256 usedAfter1) = vault.supportedTokens(address(token1));
        assertEq(usedAfter1, usedBefore + smallAmount);

        uint256 largeAmount = hardCap + 1;
        forcePending = vaultV2.mockIncreaseUsedWithdrawHotAmount(address(token1), largeAmount);
        assertTrue(forcePending);
        (, , , , uint256 usedAfter2) = vault.supportedTokens(address(token1));
        assertEq(usedAfter2, usedBefore + smallAmount);
    }

    function test_Upgrade_OnlyUpgradeRole() public {
        implementationV2 = new AssetVaultV2();
        vm.expectRevert();
        vm.prank(user);
        vault.upgradeToAndCall(address(implementationV2), "");

        vm.prank(upgradeRole);
        vault.upgradeToAndCall(address(implementationV2), "");
        AssetVaultV2 vaultV2 = AssetVaultV2(payable(address(vault)));
        assertEq(vaultV2.newVariable(), 0);
    }

    function test_NormalWithdraw_Success() public {
        vm.startPrank(user);
        token1.approve(address(vault), 1000e18);
        vault.deposit(address(token1), 1000e18);
        vm.stopPrank();

        uint256 id = 1;
        address receiver = address(0x100);
        uint256 amount = 50e18;
        uint256 fee = 1e18;

        WithdrawTestData memory data = _prepareRequestWithdrawData(
            id,
            address(token1),
            amount,
            fee,
            receiver,
            false
        );

        (, , , , uint256 usedBefore) = vault.supportedTokens(address(token1));
        vm.expectEmit(true, true, true, true);
        emit AssetVault.WithdrawExecuted(id, receiver, address(token1), amount, fee, false, false, false);

        vm.prank(operator);
        vault.requestWithdraw(id, false, data.validators, data.action, data.signatures);

        assertEq(token1.balanceOf(receiver), amount - fee);
        assertEq(vault.fees(address(token1)), fee);
        (bool paused, bool pending, bool executed, , , , , ) = vault.withdrawals(id);
        assertTrue(executed);
        assertFalse(pending);
        (, , , , uint256 usedAfter) = vault.supportedTokens(address(token1));
        assertEq(usedAfter, usedBefore + amount);
    }

    function test_PendingWithdraw_Triggered() public {
        vm.startPrank(user);
        token1.approve(address(vault), 1000e18);
        vault.deposit(address(token1), 1000e18);
        vm.stopPrank();

        uint256 hardCap = (1000e18 * 5000) / 10000;
        uint256 id = 1;
        uint256 amount = hardCap + 1e18;
        address receiver = address(0x100);

        WithdrawTestData memory data = _prepareRequestWithdrawData(
            id,
            address(token1),
            amount,
            0,
            receiver,
            false
        );
        (, , , , uint256 usedBefore) = vault.supportedTokens(address(token1));
        vm.expectEmit(true, true, true, true);
        emit AssetVault.WithdrawalAdded(id, address(token1), amount, 0, receiver, true, false);

        vm.prank(operator);
        vault.requestWithdraw(id, false, data.validators, data.action, data.signatures);

        (, , , , uint256 usedAfter) = vault.supportedTokens(address(token1));
        assertEq(usedAfter, usedBefore);
        (bool paused, bool pending, bool executed, uint256 withdrawalAmount, , , , ) = vault.withdrawals(id);
        assertTrue(pending);
        assertFalse(executed);
        assertEq(withdrawalAmount, amount);

        (ValidatorInfo[] memory execValidators, bytes[] memory execSignatures) = _prepareExecuteWithdrawalData(id);
        vm.expectRevert(AssetVault.ChallengePeriodNotExpired.selector);
        vm.prank(operator);
        vault.executePendingWithdrawal(id, execValidators, execSignatures);
    }

    function test_ForcePendingWithdraw() public {
        vm.startPrank(user);
        token1.approve(address(vault), 1000e18);
        vault.deposit(address(token1), 1000e18);
        vm.stopPrank();

        uint256 id = 1;
        uint256 amount = 50e18;
        address receiver = address(0x100);

        WithdrawTestData memory data = _prepareRequestWithdrawData(
            id,
            address(token1),
            amount,
            0,
            receiver,
            true
        );

        (, , , , uint256 usedBefore) = vault.supportedTokens(address(token1));
        vm.expectEmit(true, true, true, true);
        emit AssetVault.WithdrawalAdded(id, address(token1), amount, 0, receiver, true, true);

        vm.prank(operator);
        vault.requestWithdraw(id, true, data.validators, data.action, data.signatures);

        (, , , , uint256 usedAfter) = vault.supportedTokens(address(token1));
        assertEq(usedAfter, usedBefore);
        (bool paused, bool pending, bool executed, , , , , ) = vault.withdrawals(id);
        assertTrue(pending);
        assertFalse(executed);

        (ValidatorInfo[] memory execValidators, bytes[] memory execSignatures) = _prepareExecuteWithdrawalData(id);
        vm.expectRevert(AssetVault.ChallengePeriodNotExpired.selector);
        vm.prank(operator);
        vault.executePendingWithdrawal(id, execValidators, execSignatures);
    }

    function test_PauseWithdraw_OnlyPendingNotExpired() public {
        vm.startPrank(user);
        token1.approve(address(vault), 1000e18);
        vault.deposit(address(token1), 1000e18);
        vm.stopPrank();

        uint256 hardCap = (1000e18 * 5000) / 10000;
        uint256 id = 1;
        uint256 amount = hardCap + 1e18;
        address receiver = address(0x100);

        WithdrawTestData memory data = _prepareRequestWithdrawData(
            id,
            address(token1),
            amount,
            0,
            receiver,
            false
        );

        vm.prank(operator);
        vault.requestWithdraw(id, false, data.validators, data.action, data.signatures);

        uint256[] memory ids = new uint256[](1);
        ids[0] = id;
        (ValidatorInfo[] memory pauseValidators, bytes[] memory pauseSignatures) = _prepareBatchTogglePendingWithdrawalData(ids, true);

        vm.expectEmit(true, false, false, true);
        emit AssetVault.PendingWithdrawalToggled(id, true);
        vm.prank(operator);
        vault.batchTogglePendingWithdrawal(ids, true, pauseValidators, pauseSignatures);

        (bool paused, , , , , , , ) = vault.withdrawals(id);
        assertTrue(paused);

        (ValidatorInfo[] memory unpauseValidators, bytes[] memory unpauseSignatures) = _prepareBatchTogglePendingWithdrawalData(ids, false);

        vm.expectEmit(true, false, false, true);
        emit AssetVault.PendingWithdrawalToggled(id, false);
        vm.prank(operator);
        vault.batchTogglePendingWithdrawal(ids, false, unpauseValidators, unpauseSignatures);

        (bool paused2, , , , , , , ) = vault.withdrawals(id);
        assertFalse(paused2);
    }

    function test_PauseWithdraw_Executed_Reverts() public {
        vm.startPrank(user);
        token1.approve(address(vault), 1000e18);
        vault.deposit(address(token1), 1000e18);
        vm.stopPrank();

        uint256 id = 1;
        uint256 amount = 50e18;
        address receiver = address(0x100);

        WithdrawTestData memory data = _prepareRequestWithdrawData(
            id,
            address(token1),
            amount,
            0,
            receiver,
            false
        );

        vm.prank(operator);
        vault.requestWithdraw(id, false, data.validators, data.action, data.signatures);

        (, , bool executed, , , , , ) = vault.withdrawals(id);
        assertTrue(executed);

        uint256[] memory ids = new uint256[](1);
        ids[0] = id;
        (ValidatorInfo[] memory pauseValidators, bytes[] memory pauseSignatures) = _prepareBatchTogglePendingWithdrawalData(ids, true);

        vm.expectRevert(AssetVault.WithdrawalAlreadyExecuted.selector);
        vm.prank(operator);
        vault.batchTogglePendingWithdrawal(ids, true, pauseValidators, pauseSignatures);
    }

    function test_PendingWithdraw_ExecuteAfterChallengePeriod() public {
        vm.startPrank(user);
        token1.approve(address(vault), 1000e18);
        vault.deposit(address(token1), 1000e18);
        vm.stopPrank();

        uint256 hardCap = (1000e18 * 5000) / 10000;
        uint256 id = 1;
        uint256 amount = hardCap + 1e18;
        uint256 fee = 1e18;
        address receiver = address(0x100);

        WithdrawTestData memory data = _prepareRequestWithdrawData(
            id,
            address(token1),
            amount,
            fee,
            receiver,
            false
        );

        vm.prank(operator);
        vault.requestWithdraw(id, false, data.validators, data.action, data.signatures);

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);

        (ValidatorInfo[] memory execValidators, bytes[] memory execSignatures) = _prepareExecuteWithdrawalData(id);

        vm.expectEmit(true, true, true, true);
        emit AssetVault.WithdrawExecuted(id, receiver, address(token1), amount, fee, true, false, false);

        vm.prank(operator);
        vault.executePendingWithdrawal(id, execValidators, execSignatures);

        assertEq(token1.balanceOf(receiver), amount - fee);
        assertEq(vault.fees(address(token1)), fee);
        (, , bool executed, , , , , ) = vault.withdrawals(id);
        assertTrue(executed);
    }

    function test_PendingWithdraw_RevertExecuteBeforeChallengePeriod() public {
        vm.startPrank(user);
        token1.approve(address(vault), 1000e18);
        vault.deposit(address(token1), 1000e18);
        vm.stopPrank();

        uint256 hardCap = (1000e18 * 5000) / 10000;
        uint256 id = 1;
        uint256 amount = hardCap + 1e18;
        address receiver = address(0x100);

        WithdrawTestData memory data = _prepareRequestWithdrawData(
            id,
            address(token1),
            amount,
            0,
            receiver,
            false
        );

        vm.prank(operator);
        vault.requestWithdraw(id, false, data.validators, data.action, data.signatures);

        (bool paused, bool pending, bool executed, , , , , ) = vault.withdrawals(id);
        assertTrue(pending && !executed && !paused);

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);

        uint256[] memory ids = new uint256[](1);
        ids[0] = id;
        (ValidatorInfo[] memory pauseValidators, bytes[] memory pauseSignatures) = _prepareBatchTogglePendingWithdrawalData(ids, true);
        vm.expectRevert(AssetVault.ChallengePeriodExpired.selector);
        vm.prank(operator);
        vault.batchTogglePendingWithdrawal(ids, true, pauseValidators, pauseSignatures);
    }

    function test_FlushWithdraw_PendingNotExpired_Success() public {
        vm.startPrank(user);
        token1.approve(address(vault), 1000e18);
        vault.deposit(address(token1), 1000e18);
        vm.stopPrank();

        FlushTestData memory testData;
        testData.hardCap = (1000e18 * 5000) / 10000;
        testData.id = 1;
        testData.amount = testData.hardCap + 1e18;
        testData.fee = 1e18;
        testData.receiver = address(0x100);

        WithdrawTestData memory data = _prepareRequestWithdrawData(
            testData.id,
            address(token1),
            testData.amount,
            testData.fee,
            testData.receiver,
            false
        );

        vm.prank(operator);
        vault.requestWithdraw(testData.id, false, data.validators, data.action, data.signatures);

        (testData.paused, testData.pending, testData.executed, , , , , ) = vault.withdrawals(testData.id);
        assertTrue(testData.pending);
        assertFalse(testData.executed);
        assertFalse(testData.paused);

        testData.balanceBefore = token1.balanceOf(testData.receiver);
        testData.vaultBalanceBefore = token1.balanceOf(address(vault));

        testData.ids = new uint256[](1);
        testData.ids[0] = testData.id;
        (ValidatorInfo[] memory flushValidators, bytes[] memory flushSignatures) = _prepareBatchFlushWithdrawalsData(testData.ids);

        vm.expectEmit(true, true, true, true);
        emit AssetVault.WithdrawExecuted(testData.id, testData.receiver, address(token1), testData.amount, testData.fee, true, true, false);

        vm.prank(operator);
        vault.batchFlushWithdrawals(testData.ids, flushValidators, flushSignatures);

        assertEq(token1.balanceOf(testData.receiver), testData.balanceBefore + testData.amount - testData.fee);
        assertEq(token1.balanceOf(address(vault)), testData.vaultBalanceBefore - testData.amount + testData.fee);
        assertEq(vault.fees(address(token1)), testData.fee);
        (testData.pausedAfter, testData.pendingAfter, testData.executedAfter, , , , , ) = vault.withdrawals(testData.id);
        assertTrue(testData.executedAfter);
        assertTrue(testData.pendingAfter);
        assertFalse(testData.pausedAfter);
    }

    function test_FlushWithdraw_Paused_Success() public {
        vm.startPrank(user);
        token1.approve(address(vault), 1000e18);
        vault.deposit(address(token1), 1000e18);
        vm.stopPrank();

        FlushTestData memory testData;
        testData.id = 1;
        testData.amount = (1000e18 * 5000) / 10000 + 1e18;
        testData.fee = 1e18;
        testData.receiver = address(0x100);

        WithdrawTestData memory data = _prepareRequestWithdrawData(
            testData.id,
            address(token1),
            testData.amount,
            testData.fee,
            testData.receiver,
            false
        );

        vm.prank(operator);
        vault.requestWithdraw(testData.id, false, data.validators, data.action, data.signatures);

        testData.ids = new uint256[](1);
        testData.ids[0] = testData.id;
        (ValidatorInfo[] memory pauseValidators, bytes[] memory pauseSignatures) = _prepareBatchTogglePendingWithdrawalData(testData.ids, true);
        vm.prank(operator);
        vault.batchTogglePendingWithdrawal(testData.ids, true, pauseValidators, pauseSignatures);

        (testData.paused, testData.pending, testData.executed, , , , , ) = vault.withdrawals(testData.id);
        assertTrue(testData.pending && !testData.executed && testData.paused);

        testData.balanceBefore = token1.balanceOf(testData.receiver);
        testData.vaultBalanceBefore = token1.balanceOf(address(vault));

        (ValidatorInfo[] memory flushValidators, bytes[] memory flushSignatures) = _prepareBatchFlushWithdrawalsData(testData.ids);
        vm.expectEmit(true, true, true, true);
        emit AssetVault.WithdrawExecuted(testData.id, testData.receiver, address(token1), testData.amount, testData.fee, true, true, true);

        vm.prank(operator);
        vault.batchFlushWithdrawals(testData.ids, flushValidators, flushSignatures);

        assertEq(token1.balanceOf(testData.receiver), testData.balanceBefore + testData.amount - testData.fee);
        assertEq(token1.balanceOf(address(vault)), testData.vaultBalanceBefore - testData.amount + testData.fee);
        assertEq(vault.fees(address(token1)), testData.fee);
        (testData.pausedAfter, testData.pendingAfter, testData.executedAfter, , , , , ) = vault.withdrawals(testData.id);
        assertTrue(testData.executedAfter && testData.pendingAfter && testData.pausedAfter);
    }

    function test_Withdraw_WrongSignature_ModifiedSignature_Reverts() public {
        vm.startPrank(user);
        token1.approve(address(vault), 1000e18);
        vault.deposit(address(token1), 1000e18);
        vm.stopPrank();

        uint256 id = 1;
        uint256 amount = 50e18;
        address receiver = address(0x100);

        WithdrawTestData memory data = _prepareRequestWithdrawData(
            id,
            address(token1),
            amount,
            0,
            receiver,
            false
        );

        bytes memory correctSig = data.signatures[0];
        bytes memory wrongSig = new bytes(correctSig.length);
        for (uint256 i = 0; i < correctSig.length; i++) {
            wrongSig[i] = correctSig[i];
        }
        wrongSig[0] = bytes1(uint8(wrongSig[0]) ^ 1);
        data.signatures[0] = wrongSig;

        vm.expectRevert(AssetVault.NotEnoughValidatorPower.selector);
        vm.prank(operator);
        vault.requestWithdraw(id, false, data.validators, data.action, data.signatures);
    }

    function test_Withdraw_WrongSignature_ModifiedAction_Reverts() public {
        vm.startPrank(user);
        token1.approve(address(vault), 1000e18);
        vault.deposit(address(token1), 1000e18);
        vm.stopPrank();

        uint256 id = 1;
        uint256 amount = 50e18;
        address receiver = address(0x100);

        WithdrawTestData memory data = _prepareRequestWithdrawData(
            id,
            address(token1),
            amount + 1,
            0,
            receiver,
            false
        );

        bytes32 correctDigest = _createRequestWithdrawDigest(
            id,
            address(token1),
            amount,
            0,
            receiver,
            false
        );
        data.signatures[0] = _signDigest(correctDigest, validator2Key);
        data.signatures[1] = _signDigest(correctDigest, validator3Key);

        vm.expectRevert(AssetVault.NotEnoughValidatorPower.selector);
        vm.prank(operator);
        vault.requestWithdraw(id, false, data.validators, data.action, data.signatures);
    }

    function test_Withdraw_WrongSignature_WrongId_Reverts() public {
        vm.startPrank(user);
        token1.approve(address(vault), 1000e18);
        vault.deposit(address(token1), 1000e18);
        vm.stopPrank();

        uint256 id = 1;
        uint256 wrongId = 2;
        uint256 amount = 50e18;
        address receiver = address(0x100);

        WithdrawTestData memory data = _prepareRequestWithdrawData(
            id,
            address(token1),
            amount,
            0,
            receiver,
            false
        );

        vm.expectRevert(AssetVault.NotEnoughValidatorPower.selector);
        vm.prank(operator);
        vault.requestWithdraw(wrongId, false, data.validators, data.action, data.signatures);
    }

    struct WithdrawTestData {
        ValidatorInfo[] validators;
        bytes[] signatures;
        WithdrawAction action;
        bytes32 digest;
    }

    struct FlushTestData {
        uint256 hardCap;
        uint256 id;
        uint256 amount;
        uint256 fee;
        address receiver;
        bool paused;
        bool pending;
        bool executed;
        uint256 balanceBefore;
        uint256 vaultBalanceBefore;
        uint256[] ids;
        bool pausedAfter;
        bool pendingAfter;
        bool executedAfter;
    }

    struct BatchFlushTestData {
        uint256 id1;
        uint256 id2;
        uint256 amount1;
        uint256 amount2;
        uint256 fee1;
        uint256 fee2;
        address receiver1;
        address receiver2;
        uint256 balance1Before;
        uint256 balance2Before;
        uint256 vaultBalanceBefore;
        uint256 hardCap;
        bool paused1;
        bool pending1;
        bool executed1;
        bool paused2;
        bool pending2;
        bool executed2;
        bool paused1After;
        bool pending1After;
        bool executed1After;
        bool paused2After;
        bool pending2After;
        bool executed2After;
        ValidatorInfo[] validators;
        bytes[] signatures;
        uint256[] ids;
        bytes32 digest;
        bytes32 ethSignedMessageHash;
    }

    function _prepareRequestWithdrawData(
        uint256 id,
        address token,
        uint256 amount,
        uint256 fee,
        address receiver,
        bool isForcePending
    ) internal view returns (WithdrawTestData memory data) {
        data.digest = _createRequestWithdrawDigest(id, token, amount, fee, receiver, isForcePending);
        data.validators = new ValidatorInfo[](3);
        data.validators[0] = ValidatorInfo({signer: validator1, power: 10});
        data.validators[1] = ValidatorInfo({signer: validator2, power: 20});
        data.validators[2] = ValidatorInfo({signer: validator3, power: 30});
        data.signatures = new bytes[](3);
        data.signatures[0] = _signDigest(data.digest, validator1Key);
        data.signatures[1] = _signDigest(data.digest, validator2Key);
        data.signatures[2] = _signDigest(data.digest, validator3Key);
        data.action = WithdrawAction({
            token: token,
            amount: amount,
            fee: fee,
            receiver: receiver
        });
    }

    function _prepareExecuteWithdrawalData(
        uint256 id
    ) internal view returns (ValidatorInfo[] memory validators, bytes[] memory signatures) {
        bytes32 digest = _createExecuteWithdrawalDigest(id);
        validators = new ValidatorInfo[](3);
        validators[0] = ValidatorInfo({signer: validator1, power: 10});
        validators[1] = ValidatorInfo({signer: validator2, power: 20});
        validators[2] = ValidatorInfo({signer: validator3, power: 30});
        signatures = new bytes[](2);
        signatures[0] = _signDigest(digest, validator2Key);
        signatures[1] = _signDigest(digest, validator3Key);
    }

    function _prepareBatchTogglePendingWithdrawalData(
        uint256[] memory ids,
        bool shouldPause
    ) internal view returns (ValidatorInfo[] memory validators, bytes[] memory signatures) {
        bytes32 digest = _createBatchTogglePendingWithdrawalDigest(ids, shouldPause);
        validators = new ValidatorInfo[](3);
        validators[0] = ValidatorInfo({signer: validator1, power: 10});
        validators[1] = ValidatorInfo({signer: validator2, power: 20});
        validators[2] = ValidatorInfo({signer: validator3, power: 30});
        signatures = new bytes[](2);
        signatures[0] = _signDigest(digest, validator2Key);
        signatures[1] = _signDigest(digest, validator3Key);
    }

    function _prepareBatchFlushWithdrawalsData(
        uint256[] memory ids
    ) internal view returns (ValidatorInfo[] memory validators, bytes[] memory signatures) {
        bytes32 digest = _createBatchFlushWithdrawalsDigest(ids);
        validators = new ValidatorInfo[](3);
        validators[0] = ValidatorInfo({signer: validator1, power: 10});
        validators[1] = ValidatorInfo({signer: validator2, power: 20});
        validators[2] = ValidatorInfo({signer: validator3, power: 30});
        signatures = new bytes[](2);
        signatures[0] = _signDigest(digest, validator2Key);
        signatures[1] = _signDigest(digest, validator3Key);
    }

    function _prepareBatchResetWithdrawHotAmountData(
        address[] memory tokens
    ) internal view returns (ValidatorInfo[] memory validators, bytes[] memory signatures) {
        bytes32 digest = _createBatchResetWithdrawHotAmountDigest(tokens);
        validators = new ValidatorInfo[](3);
        validators[0] = ValidatorInfo({signer: validator1, power: 10});
        validators[1] = ValidatorInfo({signer: validator2, power: 20});
        validators[2] = ValidatorInfo({signer: validator3, power: 30});
        signatures = new bytes[](2);
        signatures[0] = _signDigest(digest, validator2Key);
        signatures[1] = _signDigest(digest, validator3Key);
    }

    function _createRequestWithdrawDigest(
        uint256 id,
        address token,
        uint256 amount,
        uint256 fee,
        address receiver,
        bool isForcePending
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                "requestWithdraw",
                id,
                block.chainid,
                address(vault),
                token,
                amount,
                fee,
                receiver,
                isForcePending
            )
        );
    }

    function _createExecuteWithdrawalDigest(
        uint256 id
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                "executePendingWithdrawal",
                id,
                block.chainid,
                address(vault)
            )
        );
    }

    function _createBatchTogglePendingWithdrawalDigest(
        uint256[] memory ids,
        bool shouldPause
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                "batchTogglePendingWithdrawal",
                ids,
                block.chainid,
                address(vault),
                shouldPause
            )
        );
    }

    function _createBatchFlushWithdrawalsDigest(
        uint256[] memory ids
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                "batchFlushWithdrawals",
                ids,
                block.chainid,
                address(vault)
            )
        );
    }

    function _createBatchResetWithdrawHotAmountDigest(
        address[] memory tokens
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                "batchResetWithdrawHotAmount",
                tokens,
                block.chainid,
                address(vault)
            )
        );
    }
    

    function _signDigest(bytes32 digest, uint256 privateKey) internal pure returns (bytes memory) {
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(digest);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, ethSignedMessageHash);
        return abi.encodePacked(r, s, v);
    }

    function test_BatchFlushWithdrawals_Success() public {
        vm.startPrank(user);
        token1.approve(address(vault), 2000e18);
        vault.deposit(address(token1), 2000e18);
        vm.stopPrank();

        BatchFlushTestData memory testData;
        testData.hardCap = (2000e18 * 5000) / 10000;
        testData.id1 = 1;
        testData.id2 = 2;
        testData.amount1 = testData.hardCap + 1e18;
        testData.amount2 = testData.hardCap + 2e18;
        testData.fee1 = 1e18;
        testData.fee2 = 2e18;
        testData.receiver1 = address(0x100);
        testData.receiver2 = address(0x200);

        WithdrawTestData memory data1 = _prepareRequestWithdrawData(
            testData.id1,
            address(token1),
            testData.amount1,
            testData.fee1,
            testData.receiver1,
            false
        );

        WithdrawTestData memory data2 = _prepareRequestWithdrawData(
            testData.id2,
            address(token1),
            testData.amount2,
            testData.fee2,
            testData.receiver2,
            false
        );

        vm.prank(operator);
        vault.requestWithdraw(testData.id1, false, data1.validators, data1.action, data1.signatures);
        vm.prank(operator);
        vault.requestWithdraw(testData.id2, false, data2.validators, data2.action, data2.signatures);

        (testData.paused1, testData.pending1, testData.executed1, , , , , ) = vault.withdrawals(testData.id1);
        (testData.paused2, testData.pending2, testData.executed2, , , , , ) = vault.withdrawals(testData.id2);
        assertTrue(testData.pending1 && !testData.executed1);
        assertTrue(testData.pending2 && !testData.executed2);

        testData.balance1Before = token1.balanceOf(testData.receiver1);
        testData.balance2Before = token1.balanceOf(testData.receiver2);
        testData.vaultBalanceBefore = token1.balanceOf(address(vault));

        testData.validators = new ValidatorInfo[](3);
        testData.validators[0] = ValidatorInfo({signer: validator1, power: 10});
        testData.validators[1] = ValidatorInfo({signer: validator2, power: 20});
        testData.validators[2] = ValidatorInfo({signer: validator3, power: 30});

        testData.ids = new uint256[](2);
        testData.ids[0] = testData.id1;
        testData.ids[1] = testData.id2;
        (testData.validators, testData.signatures) = _prepareBatchFlushWithdrawalsData(testData.ids);

        vm.expectEmit(true, true, true, true);
        emit AssetVault.WithdrawExecuted(testData.id1, testData.receiver1, address(token1), testData.amount1, testData.fee1, true, true, false);
        vm.expectEmit(true, true, true, true);
        emit AssetVault.WithdrawExecuted(testData.id2, testData.receiver2, address(token1), testData.amount2, testData.fee2, true, true, false);

        vm.prank(operator);
        vault.batchFlushWithdrawals(testData.ids, testData.validators, testData.signatures);

        assertEq(token1.balanceOf(testData.receiver1), testData.balance1Before + testData.amount1 - testData.fee1);
        assertEq(token1.balanceOf(testData.receiver2), testData.balance2Before + testData.amount2 - testData.fee2);
        assertEq(token1.balanceOf(address(vault)), testData.vaultBalanceBefore - testData.amount1 + testData.fee1 + testData.fee2 - testData.amount2);
        assertEq(vault.fees(address(token1)), testData.fee1 + testData.fee2);

        (testData.paused1After, testData.pending1After, testData.executed1After, , , , , ) = vault.withdrawals(testData.id1);
        (testData.paused2After, testData.pending2After, testData.executed2After, , , , , ) = vault.withdrawals(testData.id2);
        assertTrue(testData.executed1After && testData.pending1After && !testData.paused1After);
        assertTrue(testData.executed2After && testData.pending2After && !testData.paused2After);
    }

    function test_BatchResetWithdrawHotAmount_Success() public {
        vm.startPrank(user);
        token1.approve(address(vault), 1000e18);
        token2.approve(address(vault), 1000e18);
        vault.deposit(address(token1), 1000e18);
        vault.deposit(address(token2), 1000e18);
        vm.stopPrank();

        uint256 id1 = 1;
        uint256 id2 = 2;
        uint256 amount1 = 100e18;
        uint256 amount2 = 200e18;
        address receiver = address(0x100);

        WithdrawTestData memory data1 = _prepareRequestWithdrawData(
            id1,
            address(token1),
            amount1,
            0,
            receiver,
            false
        );

        WithdrawTestData memory data2 = _prepareRequestWithdrawData(
            id2,
            address(token2),
            amount2,
            0,
            receiver,
            false
        );

        vm.prank(operator);
        vault.requestWithdraw(id1, false, data1.validators, data1.action, data1.signatures);
        vm.prank(operator);
        vault.requestWithdraw(id2, false, data2.validators, data2.action, data2.signatures);

        (, , , , uint256 used1Before) = vault.supportedTokens(address(token1));
        (, , , , uint256 used2Before) = vault.supportedTokens(address(token2));
        assertGt(used1Before, 0);
        assertGt(used2Before, 0);

        vm.expectEmit(true, true, true, true);
        emit AssetVault.WithdrawHotAmountRefilled(address(token1), 0, 0);

        vm.expectEmit(true, true, true, true);
        emit AssetVault.WithdrawHotAmountRefilled(address(token2), 0, 0);

        address[] memory tokens = new address[](2);
        tokens[0] = address(token1);
        tokens[1] = address(token2);
        (ValidatorInfo[] memory resetValidators, bytes[] memory resetSignatures) = _prepareBatchResetWithdrawHotAmountData(tokens);

        vm.prank(operator);
        vault.batchResetWithdrawHotAmount(tokens, resetValidators, resetSignatures);

        (, , , , uint256 used1After) = vault.supportedTokens(address(token1));
        (, , , , uint256 used2After) = vault.supportedTokens(address(token2));
        assertEq(used1After, 0);
        assertEq(used2After, 0);
    }

    function test_BatchResetWithdrawHotAmount_OnlyOperator() public {
        address[] memory tokens = new address[](1);
        tokens[0] = address(token1);
        (ValidatorInfo[] memory resetValidators, bytes[] memory resetSignatures) = _prepareBatchResetWithdrawHotAmountData(tokens);
        vm.expectRevert();
        vm.prank(admin);
        vault.batchResetWithdrawHotAmount(tokens, resetValidators, resetSignatures);
    }

    function test_BatchResetWithdrawHotAmount_UnsupportedToken_Reverts() public {
        address unsupportedToken = address(0x999);
        address[] memory tokens = new address[](1);
        tokens[0] = unsupportedToken;
        (ValidatorInfo[] memory resetValidators, bytes[] memory resetSignatures) = _prepareBatchResetWithdrawHotAmountData(tokens);
        vm.expectRevert(AssetVault.TokenNotSupported.selector);
        vm.prank(operator);
        vault.batchResetWithdrawHotAmount(tokens, resetValidators, resetSignatures);
    }

    function test_BatchFlushWithdrawals_EmptyIds_Reverts() public {
        ValidatorInfo[] memory validators = new ValidatorInfo[](3);
        validators[0] = ValidatorInfo({signer: validator1, power: 10});
        validators[1] = ValidatorInfo({signer: validator2, power: 20});
        validators[2] = ValidatorInfo({signer: validator3, power: 30});

        vm.expectRevert(AssetVault.EmptyIds.selector);
        vm.prank(operator);
        uint256[] memory ids = new uint256[](0);
        bytes[] memory signatures = new bytes[](0);
        vault.batchFlushWithdrawals(ids, validators, signatures);
    }
}


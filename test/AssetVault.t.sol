// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {AssetVault, ValidatorInfo, WithdrawAction, WithdrawType, TokenInfo} from "../src/AssetVault.sol";
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
        vm.expectRevert("token already exists");
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
        vm.expectRevert("token not supported");
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
        vm.expectRevert("token not supported");
        vm.prank(admin);
        vault.updateToken(address(unsupported), 6000, 2000);
    }

    function test_Deposit_OnlySupportedToken() public {
        MockERC20 unsupported = new MockERC20("Unsupported", "U");
        vm.startPrank(user);
        unsupported.mint(user, 100e18);
        unsupported.approve(address(vault), 100e18);
        vm.expectRevert("token not supported");
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

        vm.expectRevert("validators not ordered");
        vm.prank(admin);
        vault.addValidators(invalidValidators);
    }

    function test_AddValidators_AlreadySet_Reverts() public {
        ValidatorInfo[] memory validators = new ValidatorInfo[](3);
        validators[0] = ValidatorInfo({signer: validator1, power: 10});
        validators[1] = ValidatorInfo({signer: validator2, power: 20});
        validators[2] = ValidatorInfo({signer: validator3, power: 30});

        vm.expectRevert("validators already set");
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

        WithdrawTestData memory data = _prepareWithdrawData(
            id,
            address(token1),
            withdrawAmount,
            0,
            receiver,
            WithdrawType.NORMAL
        );

        vm.prank(operator);
        vault.withdraw(id, data.validators, data.action, data.signatures);

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

        WithdrawTestData memory data = _prepareWithdrawData(
            id,
            address(token1),
            amount,
            fee,
            receiver,
            WithdrawType.NORMAL
        );

        (, , , , uint256 usedBefore) = vault.supportedTokens(address(token1));
        vm.expectEmit(true, true, true, true);
        emit AssetVault.WithdrawExecuted(id, receiver, address(token1), amount, fee, WithdrawType.NORMAL);

        vm.prank(operator);
        vault.withdraw(id, data.validators, data.action, data.signatures);

        assertEq(token1.balanceOf(receiver), amount - fee);
        assertEq(vault.fees(address(token1)), fee);
        (bool paused, bool pending, bool executed, , , , , , ) = vault.withdrawals(id);
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

        WithdrawTestData memory data = _prepareWithdrawData(
            id,
            address(token1),
            amount,
            0,
            receiver,
            WithdrawType.NORMAL
        );
        (, , , , uint256 usedBefore) = vault.supportedTokens(address(token1));
        vm.expectEmit(true, true, true, true);
        emit AssetVault.WithdrawalAdded(id, address(token1), amount, 0, receiver, WithdrawType.NORMAL, true);

        vm.prank(operator);
        vault.withdraw(id, data.validators, data.action, data.signatures);

        (, , , , uint256 usedAfter) = vault.supportedTokens(address(token1));
        assertEq(usedAfter, usedBefore);
        (bool paused, bool pending, bool executed, uint256 withdrawalAmount, , , , , ) = vault.withdrawals(id);
        assertTrue(pending);
        assertFalse(executed);
        assertEq(withdrawalAmount, amount);

        vm.expectRevert("challenge period not expired");
        vm.prank(operator);
        vault.executeWithdrawal(id);
    }

    function test_ForcePendingWithdraw() public {
        vm.startPrank(user);
        token1.approve(address(vault), 1000e18);
        vault.deposit(address(token1), 1000e18);
        vm.stopPrank();

        uint256 id = 1;
        uint256 amount = 50e18;
        address receiver = address(0x100);

        WithdrawTestData memory data = _prepareWithdrawData(
            id,
            address(token1),
            amount,
            0,
            receiver,
            WithdrawType.FORCE_PENDING
        );

        (, , , , uint256 usedBefore) = vault.supportedTokens(address(token1));
        vm.expectEmit(true, true, true, true);
        emit AssetVault.WithdrawalAdded(id, address(token1), amount, 0, receiver, WithdrawType.FORCE_PENDING, true);

        vm.prank(operator);
        vault.withdraw(id, data.validators, data.action, data.signatures);

        (, , , , uint256 usedAfter) = vault.supportedTokens(address(token1));
        assertEq(usedAfter, usedBefore);
        (bool paused, bool pending, bool executed, , , , , , ) = vault.withdrawals(id);
        assertTrue(pending);
        assertFalse(executed);

        vm.expectRevert("challenge period not expired");
        vm.prank(operator);
        vault.executeWithdrawal(id);
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

        WithdrawTestData memory data = _prepareWithdrawData(
            id,
            address(token1),
            amount,
            0,
            receiver,
            WithdrawType.NORMAL
        );

        vm.prank(operator);
        vault.withdraw(id, data.validators, data.action, data.signatures);

        WithdrawTestData memory pauseData = _prepareWithdrawData(
            id,
            address(token1),
            0,
            0,
            receiver,
            WithdrawType.PAUSE_WITHDRAW
        );

        vm.expectEmit(true, false, false, true);
        emit AssetVault.PendingWithdrawalToggled(id, true);
        vm.prank(operator);
        vault.withdraw(id, pauseData.validators, pauseData.action, pauseData.signatures);

        (bool paused, , , , , , , , ) = vault.withdrawals(id);
        assertTrue(paused);

        WithdrawTestData memory unpauseData = _prepareWithdrawData(
            id,
            address(token1),
            0,
            0,
            receiver,
            WithdrawType.UNPAUSE_WITHDRAW
        );

        vm.expectEmit(true, false, false, true);
        emit AssetVault.PendingWithdrawalToggled(id, false);
        vm.prank(operator);
        vault.withdraw(id, unpauseData.validators, unpauseData.action, unpauseData.signatures);

        (bool paused2, , , , , , , , ) = vault.withdrawals(id);
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

        WithdrawTestData memory data = _prepareWithdrawData(
            id,
            address(token1),
            amount,
            0,
            receiver,
            WithdrawType.NORMAL
        );

        vm.prank(operator);
        vault.withdraw(id, data.validators, data.action, data.signatures);

        (, , bool executed, , , , , , ) = vault.withdrawals(id);
        assertTrue(executed);

        WithdrawTestData memory pauseData = _prepareWithdrawData(
            id,
            address(token1),
            0,
            0,
            receiver,
            WithdrawType.PAUSE_WITHDRAW
        );

        vm.expectRevert("withdraw executed or challenge period expired");
        vm.prank(operator);
        vault.withdraw(id, pauseData.validators, pauseData.action, pauseData.signatures);
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

        WithdrawTestData memory data = _prepareWithdrawData(
            id,
            address(token1),
            amount,
            fee,
            receiver,
            WithdrawType.NORMAL
        );

        vm.prank(operator);
        vault.withdraw(id, data.validators, data.action, data.signatures);

        vm.warp(block.timestamp + CHALLENGE_PERIOD + 1);

        vm.expectEmit(true, true, true, true);
        emit AssetVault.WithdrawExecuted(id, receiver, address(token1), amount, fee, WithdrawType.NORMAL);

        vm.prank(operator);
        vault.executeWithdrawal(id);

        assertEq(token1.balanceOf(receiver), amount - fee);
        assertEq(vault.fees(address(token1)), fee);
        (, , bool executed, , , , , , ) = vault.withdrawals(id);
        assertTrue(executed);
    }

    function test_Withdraw_WrongSignature_ModifiedSignature_Reverts() public {
        vm.startPrank(user);
        token1.approve(address(vault), 1000e18);
        vault.deposit(address(token1), 1000e18);
        vm.stopPrank();

        uint256 id = 1;
        uint256 amount = 50e18;
        address receiver = address(0x100);

        WithdrawTestData memory data = _prepareWithdrawData(
            id,
            address(token1),
            amount,
            0,
            receiver,
            WithdrawType.NORMAL
        );

        bytes memory correctSig = data.signatures[0];
        bytes memory wrongSig = new bytes(correctSig.length);
        for (uint256 i = 0; i < correctSig.length; i++) {
            wrongSig[i] = correctSig[i];
        }
        wrongSig[0] = bytes1(uint8(wrongSig[0]) ^ 1);
        data.signatures[0] = wrongSig;

        vm.expectRevert("not enough validator power");
        vm.prank(operator);
        vault.withdraw(id, data.validators, data.action, data.signatures);
    }

    function test_Withdraw_WrongSignature_ModifiedAction_Reverts() public {
        vm.startPrank(user);
        token1.approve(address(vault), 1000e18);
        vault.deposit(address(token1), 1000e18);
        vm.stopPrank();

        uint256 id = 1;
        uint256 amount = 50e18;
        address receiver = address(0x100);

        WithdrawTestData memory data = _prepareWithdrawData(
            id,
            address(token1),
            amount + 1,
            0,
            receiver,
            WithdrawType.NORMAL
        );

        bytes32 correctDigest = _createWithdrawDigest(
            id,
            address(token1),
            amount,
            0,
            receiver,
            WithdrawType.NORMAL
        );
        data.signatures[0] = _signDigest(correctDigest, validator2Key);
        data.signatures[1] = _signDigest(correctDigest, validator3Key);

        vm.expectRevert("not enough validator power");
        vm.prank(operator);
        vault.withdraw(id, data.validators, data.action, data.signatures);
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

        WithdrawTestData memory data = _prepareWithdrawData(
            id,
            address(token1),
            amount,
            0,
            receiver,
            WithdrawType.NORMAL
        );

        vm.expectRevert("not enough validator power");
        vm.prank(operator);
        vault.withdraw(wrongId, data.validators, data.action, data.signatures);
    }

    struct WithdrawTestData {
        ValidatorInfo[] validators;
        bytes[] signatures;
        WithdrawAction action;
        bytes32 digest;
    }

    function _prepareWithdrawData(
        uint256 id,
        address token,
        uint256 amount,
        uint256 fee,
        address receiver,
        WithdrawType withdrawType
    ) internal view returns (WithdrawTestData memory data) {
        data.digest = _createWithdrawDigest(id, token, amount, fee, receiver, withdrawType);
        data.validators = new ValidatorInfo[](3);
        data.validators[0] = ValidatorInfo({signer: validator1, power: 10});
        data.validators[1] = ValidatorInfo({signer: validator2, power: 20});
        data.validators[2] = ValidatorInfo({signer: validator3, power: 30});
        data.signatures = new bytes[](2);
        data.signatures[0] = _signDigest(data.digest, validator2Key);
        data.signatures[1] = _signDigest(data.digest, validator3Key);
        data.action = WithdrawAction({
            token: token,
            amount: amount,
            fee: fee,
            receiver: receiver,
            withdrawType: withdrawType
        });
    }

    function _createWithdrawDigest(
        uint256 id,
        address token,
        uint256 amount,
        uint256 fee,
        address receiver,
        WithdrawType withdrawType
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                "withdraw",
                id,
                block.chainid,
                address(vault),
                token,
                amount,
                fee,
                receiver,
                withdrawType
            )
        );
    }

    function _signDigest(bytes32 digest, uint256 privateKey) internal pure returns (bytes memory) {
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(digest);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, ethSignedMessageHash);
        return abi.encodePacked(r, s, v);
    }
}


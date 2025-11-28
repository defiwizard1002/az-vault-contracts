// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {AZVault, ValidatorInfo, WithdrawAction, TokenInfo} from "../src/AZVault.sol";
import {AZVaultV2} from "./mock/AZVaultV2.sol";
import {MockERC20} from "./mock/MockERC20.sol";
import {MockPriceFeed} from "./mock/MockPriceFeed.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract AZVaultTest is Test {
    AZVault public vault;
    AZVault public implementation;
    MockERC20 public token1;
    MockERC20 public token2;
    MockPriceFeed public priceFeed1;
    MockPriceFeed public priceFeed2;
    MockPriceFeed public priceFeedETH;

    address public admin = address(0x1);
    address public operator = address(0x2);
    address public tokenRole = address(0x3);
    address public pauseRole = address(0x4);
    address public user = address(0x5);
    address public timelock = address(0x6);
    address public upgradeRole = address(0x7);

    address public validator1 = address(0x10);
    address public validator2 = address(0x11);
    address public validator3 = address(0x12);

    uint256 private validator1Key;
    uint256 private validator2Key;
    uint256 private validator3Key;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant TOKEN_ROLE = keccak256("TOKEN_ROLE");
    bytes32 public constant PAUSE_ROLE = keccak256("PAUSE_ROLE");
    bytes32 public constant UPGRADE_ROLE = keccak256("UPGRADE_ROLE");

    function setUp() public {
        // 0x103530DbAE2A5c82a9bCE16f568A972F1C3AA54f
        validator1Key = 0xaff81bf6f5d18dfae8a2b94fb06a55d4360e6f05a934f8aec61cf4dee86e2991;
        // 0x68bF386105c6De29A9cBe64f87D5864Cdc657cE3
        validator2Key = 0xf0e85c9dc8a15fb716f9ffd63822e97a5d611a2e63a1f9441f75bfc86da24c6f;
        // 0xEa83E5c9Ab85Ae63eb50cE88dB44dd9b9e58120F
        validator3Key = 0x40c8c2113fe3bf523638b61aba6d83ad93488479e16f9d18d64a9556c428f098;
        validator1 = vm.addr(validator1Key);
        validator2 = vm.addr(validator2Key);
        validator3 = vm.addr(validator3Key);

        console.log("validator1", validator1);
        console.log("validator2", validator2);
        console.log("validator3", validator3);

        // Deploy implementation
        implementation = new AZVault();

        // Deploy proxy with initialization
        bytes memory initData = abi.encodeWithSelector(AZVault.initialize.selector);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        vault = AZVault(payable(address(proxy)));

        // Setup roles
        vm.startPrank(address(this));
        vault.grantRole(ADMIN_ROLE, admin);
        vault.grantRole(OPERATOR_ROLE, operator);
        vault.grantRole(TOKEN_ROLE, tokenRole);
        vault.grantRole(PAUSE_ROLE, pauseRole);
        vault.grantRole(UPGRADE_ROLE, upgradeRole);
        vm.stopPrank();

        // Deploy mock tokens and price feeds
        token1 = new MockERC20("Token1", "T1");
        token2 = new MockERC20("Token2", "T2");
        priceFeed1 = new MockPriceFeed(8, 2000e8); // $2000 per token
        priceFeed2 = new MockPriceFeed(8, 1e8); // $1 per token
        priceFeedETH = new MockPriceFeed(8, 2000e8); // $2000 per ETH

        // Setup tokens
        vm.prank(tokenRole);
        vault.addToken(
            address(token1),
            address(priceFeed1),
            0,
            false,
            8,
            18
        );
        vm.prank(tokenRole);
        vault.addToken(
            address(token2),
            address(priceFeed2),
            0,
            false,
            8,
            18
        );
        // add ETH
        vm.prank(tokenRole);
        vault.addToken(
            address(0),
            address(priceFeedETH),
            0,
            false,
            8,
            18
        );

        // Setup validators (ordered by address)
        ValidatorInfo[] memory validators = new ValidatorInfo[](3);
        validators[0] = ValidatorInfo({signer: validator1, power: 10});
        validators[1] = ValidatorInfo({signer: validator2, power: 20});
        validators[2] = ValidatorInfo({signer: validator3, power: 30});

        vm.prank(admin);
        vault.addValidators(validators);

        // Setup withdraw limit
        vm.prank(admin);
        vault.updateHourlyWithdrawLimit(100000e8); // $100,000

        // Mint tokens to user
        token1.mint(user, 1000e18);
        token2.mint(user, 10000e18);
    }

    // ==================== Setup Tests ====================

    function test_Setup() public {
        assertTrue(vault.hasRole(ADMIN_ROLE, admin));
        assertTrue(vault.hasRole(OPERATOR_ROLE, operator));
        assertTrue(vault.hasRole(TOKEN_ROLE, tokenRole));
        assertTrue(vault.hasRole(PAUSE_ROLE, pauseRole));
        assertTrue(vault.hasRole(UPGRADE_ROLE, upgradeRole));
        assertEq(vault.hourlyWithdrawLimit(), 100000e8);
    }

    // ==================== Setter Tests ====================

    function test_AddToken_OnlyTokenRole() public {
        MockERC20 newToken = new MockERC20("NewToken", "NT");
        MockPriceFeed newFeed = new MockPriceFeed(8, 100e8);

        vm.expectRevert();
        vm.prank(user);
        vault.addToken(address(newToken), address(newFeed), 0, false, 8, 18);

        vm.prank(tokenRole);
        vault.addToken(address(newToken), address(newFeed), 0, false, 8, 18);
        (, , , , , uint8 tokenDecimals) = vault.supportedTokens(address(newToken));
        assertTrue(tokenDecimals == 18);
    }

    function test_RemoveToken_OnlyAdmin() public {
        vm.expectRevert();
        vm.prank(user);
        vault.removeToken(address(token1));

        vm.prank(admin);
        vault.removeToken(address(token1));
        (, , , , , uint8 tokenDecimals) = vault.supportedTokens(address(token1));
        assertTrue(tokenDecimals == 0);
    }

    function test_AddValidators_Ordered() public {
        ValidatorInfo[] memory newValidators = new ValidatorInfo[](2);
        newValidators[0] = ValidatorInfo({signer: address(0x20), power: 5});
        newValidators[1] = ValidatorInfo({signer: address(0x21), power: 15});

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

    function test_AddValidators_OnlyAdmin() public {
        ValidatorInfo[] memory newValidators = new ValidatorInfo[](1);
        newValidators[0] = ValidatorInfo({signer: address(0x20), power: 5});

        vm.expectRevert();
        vm.prank(user);
        vault.addValidators(newValidators);
    }

    function test_RemoveValidators_OnlyAdmin() public {
        ValidatorInfo[] memory validators = new ValidatorInfo[](3);
        validators[0] = ValidatorInfo({signer: validator1, power: 10});
        validators[1] = ValidatorInfo({signer: validator2, power: 20});
        validators[2] = ValidatorInfo({signer: validator3, power: 30});

        vm.expectRevert();
        vm.prank(user);
        vault.removeValidators(validators);

        vm.prank(admin);
        vault.removeValidators(validators);
    }

    function test_UpdateHourlyWithdrawLimit_OnlyAdmin() public {
        vm.expectRevert();
        vm.prank(user);
        vault.updateHourlyWithdrawLimit(200000e8);

        vm.prank(admin);
        vault.updateHourlyWithdrawLimit(200000e8);
        assertEq(vault.hourlyWithdrawLimit(), 200000e8);
    }

    function test_Pause_OnlyPauseRole() public {
        vm.expectRevert();
        vm.prank(user);
        vault.pause();

        vm.prank(pauseRole);
        vault.pause();
        assertTrue(vault.paused());
    }

    function test_Unpause_OnlyPauseRole() public {
        vm.prank(pauseRole);
        vault.pause();

        vm.expectRevert();
        vm.prank(user);
        vault.unpause();

        vm.prank(pauseRole);
        vault.unpause();
        assertFalse(vault.paused());
    }

    // ==================== Upgrade Tests ====================

    function test_Upgrade_Success() public {
        // Store some state before upgrade
        uint256 limitBefore = vault.hourlyWithdrawLimit();
        
        // Deploy new implementation
        AZVaultV2 implementationV2 = new AZVaultV2();
        
        // Upgrade
        vm.prank(upgradeRole);
        vault.upgradeToAndCall(address(implementationV2), "");
        
        // Cast to V2
        AZVaultV2 vaultV2 = AZVaultV2(payable(address(vault)));
        
        // Verify state preserved
        assertEq(vaultV2.hourlyWithdrawLimit(), limitBefore);
        
        // Test new functionality
        vaultV2.setNewVariable(123);
        assertEq(vaultV2.newVariable(), 123);
    }

    function test_Upgrade_OnlyUpgradeRole() public {
        AZVaultV2 implementationV2 = new AZVaultV2();
        
        vm.expectRevert();
        vm.prank(user);
        vault.upgradeToAndCall(address(implementationV2), "");
    }

    // ==================== Deposit Tests ====================

    function test_Deposit_ERC20() public {
        vm.startPrank(user);
        token1.approve(address(vault), 100e18);

        vm.expectEmit(true, true, false, true);
        emit AZVault.Deposit(user, address(token1), 100e18);

        vault.deposit(address(token1), 100e18);
        vm.stopPrank();

        assertEq(token1.balanceOf(address(vault)), 100e18);
    }

    function test_Deposit_ETH() public {
        vm.deal(user, 10e18);
        
        vm.expectEmit(true, true, false, true, address(vault));
        emit AZVault.Deposit(user, address(0), 10e18);
        
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

    function test_Deposit_UnsupportedToken_Reverts() public {
        MockERC20 unsupported = new MockERC20("Unsupported", "U");
        vm.startPrank(user);
        unsupported.mint(user, 100e18);
        unsupported.approve(address(vault), 100e18);
        vm.expectRevert("token not supported");
        vault.deposit(address(unsupported), 100e18);
        vm.stopPrank();
    }

    // ==================== Withdraw Tests ====================

    function _createWithdrawDigest(
        uint256 id,
        address token,
        uint256 amount,
        uint256 fee,
        address receiver
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
                receiver
            )
        );
    }

    function _signDigest(bytes32 digest, uint256 privateKey) internal pure returns (bytes memory) {
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(digest);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, ethSignedMessageHash);
        return abi.encodePacked(r, s, v);
    }

    function test_Withdraw_Success() public {
        // Setup: deposit tokens
        vm.startPrank(user);
        token1.approve(address(vault), 100e18);
        vault.deposit(address(token1), 100e18);
        vm.stopPrank();

        // Prepare withdraw
        uint256 id = 1;
        address receiver = address(0x100);
        uint256 amount = 50e18;
        uint256 fee = 1e18;

        bytes32 digest = _createWithdrawDigest(
            id,
            address(token1),
            amount,
            fee,
            receiver
        );

        // Get validators (need 2/3 power = 40/60)
        ValidatorInfo[] memory validators = new ValidatorInfo[](3);
        validators[0] = ValidatorInfo({signer: validator1, power: 10});
        validators[1] = ValidatorInfo({signer: validator2, power: 20});
        validators[2] = ValidatorInfo({signer: validator3, power: 30});

        // Sign with validator2 and validator3 (power 20 + 30 = 50 >= 40)
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _signDigest(digest, validator2Key);
        signatures[1] = _signDigest(digest, validator3Key);

        WithdrawAction memory action = WithdrawAction({
            token: address(token1),
            amount: amount,
            fee: fee,
            receiver: receiver
        });

        vm.expectEmit(true, true, true, true);
        emit AZVault.Withdraw(id, receiver, address(token1), amount, fee);

        vm.prank(operator);
        vault.withdraw(id, validators, action, signatures);

        assertEq(token1.balanceOf(receiver), amount - fee);
        assertEq(vault.fees(address(token1)), fee);
        assertTrue(vault.withdrawHistory(id));
    }

    function test_Withdraw_OnlyOperator_Reverts() public {
        vm.startPrank(user);
        token1.approve(address(vault), 100e18);
        vault.deposit(address(token1), 100e18);
        vm.stopPrank();

        uint256 id = 1;
        bytes32 digest = _createWithdrawDigest(id, address(token1), 50e18, 0, user);

        ValidatorInfo[] memory validators = new ValidatorInfo[](3);
        validators[0] = ValidatorInfo({signer: validator1, power: 10});
        validators[1] = ValidatorInfo({signer: validator2, power: 20});
        validators[2] = ValidatorInfo({signer: validator3, power: 30});

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _signDigest(digest, validator2Key);
        signatures[1] = _signDigest(digest, validator3Key);

        WithdrawAction memory action = WithdrawAction({
            token: address(token1),
            amount: 50e18,
            fee: 0,
            receiver: user
        });

        vm.expectRevert();
        vm.prank(user);
        vault.withdraw(id, validators, action, signatures);
    }

    function test_Withdraw_WhenPaused_Reverts() public {
        vm.prank(pauseRole);
        vault.pause();

        uint256 id = 1;
        bytes32 digest = _createWithdrawDigest(id, address(token1), 50e18, 0, user);

        ValidatorInfo[] memory validators = new ValidatorInfo[](3);
        validators[0] = ValidatorInfo({signer: validator1, power: 10});
        validators[1] = ValidatorInfo({signer: validator2, power: 20});
        validators[2] = ValidatorInfo({signer: validator3, power: 30});

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _signDigest(digest, validator2Key);
        signatures[1] = _signDigest(digest, validator3Key);

        WithdrawAction memory action = WithdrawAction({
            token: address(token1),
            amount: 50e18,
            fee: 0,
            receiver: user
        });

        vm.expectRevert();
        vm.prank(operator);
        vault.withdraw(id, validators, action, signatures);
    }

    function test_Withdraw_InvalidSignature_Reverts() public {
        vm.startPrank(user);
        token1.approve(address(vault), 100e18);
        vault.deposit(address(token1), 100e18);
        vm.stopPrank();

        uint256 id = 1;
        bytes32 digest = _createWithdrawDigest(id, address(token1), 50e18, 0, user);

        ValidatorInfo[] memory validators = new ValidatorInfo[](3);
        validators[0] = ValidatorInfo({signer: validator1, power: 10});
        validators[1] = ValidatorInfo({signer: validator2, power: 20});
        validators[2] = ValidatorInfo({signer: validator3, power: 30});

        // Wrong signature (sign with wrong key)
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signDigest(digest, validator1Key); // Only validator1, power 10 < 40

        WithdrawAction memory action = WithdrawAction({
            token: address(token1),
            amount: 50e18,
            fee: 0,
            receiver: user
        });

        vm.expectRevert("not enough validator power");
        vm.prank(operator);
        vault.withdraw(id, validators, action, signatures);
    }

    function test_Withdraw_ExceedLimit_Pauses() public {
        vm.startPrank(user);
        token1.approve(address(vault), 1000e18);
        vault.deposit(address(token1), 1000e18);
        vm.stopPrank();

        // Withdraw limit is 100000e8 USD
        // Token1 price is 2000e8 USD per token
        // So limit is 100000e8 / 2000e8 = 50 tokens
        // Try to withdraw 60 tokens (exceeds limit)

        uint256 id = 1;
        uint256 amount = 60e18; // Exceeds limit
        bytes32 digest = _createWithdrawDigest(id, address(token1), amount, 0, user);

        ValidatorInfo[] memory validators = new ValidatorInfo[](3);
        validators[0] = ValidatorInfo({signer: validator1, power: 10});
        validators[1] = ValidatorInfo({signer: validator2, power: 20});
        validators[2] = ValidatorInfo({signer: validator3, power: 30});

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _signDigest(digest, validator2Key);
        signatures[1] = _signDigest(digest, validator3Key);

        WithdrawAction memory action = WithdrawAction({
            token: address(token1),
            amount: amount,
            fee: 0,
            receiver: user
        });

        vm.expectEmit(true, true, false, true);
        emit AZVault.WithdrawPaused(operator, address(token1), amount, 120000e8);

        vm.prank(operator);
        vault.withdraw(id, validators, action, signatures);

        assertTrue(vault.paused());
        assertFalse(vault.withdrawHistory(id));
    }

    function test_Withdraw_DuplicateId_Reverts() public {
        vm.startPrank(user);
        token1.approve(address(vault), 200e18);
        vault.deposit(address(token1), 200e18);
        vm.stopPrank();

        uint256 id = 1;
        bytes32 digest = _createWithdrawDigest(id, address(token1), 50e18, 0, user);

        ValidatorInfo[] memory validators = new ValidatorInfo[](3);
        validators[0] = ValidatorInfo({signer: validator1, power: 10});
        validators[1] = ValidatorInfo({signer: validator2, power: 20});
        validators[2] = ValidatorInfo({signer: validator3, power: 30});

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _signDigest(digest, validator2Key);
        signatures[1] = _signDigest(digest, validator3Key);

        WithdrawAction memory action = WithdrawAction({
            token: address(token1),
            amount: 50e18,
            fee: 0,
            receiver: user
        });

        // First withdraw succeeds
        vm.prank(operator);
        vault.withdraw(id, validators, action, signatures);

        // Second withdraw with same id fails
        vm.expectRevert("used withdraw id");
        vm.prank(operator);
        vault.withdraw(id, validators, action, signatures);
    }

    function test_Withdraw_NotEnoughPower_Reverts() public {
        vm.startPrank(user);
        token1.approve(address(vault), 100e18);
        vault.deposit(address(token1), 100e18);
        vm.stopPrank();

        uint256 id = 1;
        bytes32 digest = _createWithdrawDigest(id, address(token1), 50e18, 0, user);

        ValidatorInfo[] memory validators = new ValidatorInfo[](3);
        validators[0] = ValidatorInfo({signer: validator1, power: 10});
        validators[1] = ValidatorInfo({signer: validator2, power: 20});
        validators[2] = ValidatorInfo({signer: validator3, power: 30});

        // Only validator1 (power 10), need at least 40 (2/3 of 60)
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signDigest(digest, validator1Key);

        WithdrawAction memory action = WithdrawAction({
            token: address(token1),
            amount: 50e18,
            fee: 0,
            receiver: user
        });

        vm.expectRevert("not enough validator power");
        vm.prank(operator);
        vault.withdraw(id, validators, action, signatures);
    }
}


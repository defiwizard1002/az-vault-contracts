// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script, console} from "forge-std/Script.sol";
import {AssetVault, ValidatorInfo} from "../src/AssetVault.sol";
import {MockERC20} from "../test/mock/MockERC20.sol";

contract SetupAssetVault is Script {
    // Challenge period: 2 minutes = 120 seconds
    uint256 public constant CHALLENGE_PERIOD = 120;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        address vaultAddress = vm.envAddress("VAULT_ADDRESS");

        AssetVault vault = AssetVault(payable(vaultAddress));

        vm.startBroadcast(deployerPrivateKey);

        // Setup roles first (optional - if roles need to be granted)
        _setupRoles(vault);

        // Ensure deployer has TOKEN_ROLE to add tokens
        if (!vault.hasRole(vault.TOKEN_ROLE(), deployer)) {
            vault.grantRole(vault.TOKEN_ROLE(), deployer);
            console.log("Granted TOKEN_ROLE to deployer:", deployer);
        }

        // Setup challenge period
        _setupChallengePeriod(vault);

        // Deploy mock tokens
        (address token1, address token2) = _deployMockTokens();

        // Add tokens to vault
        _addTokensToVault(vault, token1, token2);

        // Setup validators
        _setupValidators(vault);

        vm.stopBroadcast();
    }

    function _setupChallengePeriod(AssetVault vault) internal {
        uint256 currentPeriod = vault.pendingWithdrawChallengePeriod();
        if (currentPeriod == CHALLENGE_PERIOD) {
            console.log("Challenge period already set to 2 minutes");
            return;
        }
        vault.updatePendingWithdrawChallengePeriod(CHALLENGE_PERIOD);
        console.log("Challenge period set to 2 minutes (120 seconds)");
    }

    function _deployMockTokens() internal returns (address token1, address token2) {
        console.log("Deploying MockERC20 tokens...");
        
        MockERC20 mockToken1 = new MockERC20("Mock Token 1", "MTK1");
        MockERC20 mockToken2 = new MockERC20("Mock Token 2", "MTK2");
        
        token1 = address(mockToken1);
        token2 = address(mockToken2);
        
        console.log("Mock Token 1 deployed at:", token1);
        console.log("Mock Token 2 deployed at:", token2);
    }

    function _addTokensToVault(
        AssetVault vault,
        address token1,
        address token2
    ) internal {
        // Default token parameters: hardCapRatioBps = 5000 (50%), refillRateMps = 2000 (0.2% per second)
        uint256 hardCapRatioBps = 5000;
        uint256 refillRateMps = 2000;

        // Check if tokens are already added
        if (vault.supportedTokens(token1).hardCapRatioBps > 0) {
            console.log("Token 1 already added to vault");
        } else {
            vault.addToken(token1, hardCapRatioBps, refillRateMps);
            console.log("Added Token 1 to vault:", token1);
        }

        if (vault.supportedTokens(token2).hardCapRatioBps > 0) {
            console.log("Token 2 already added to vault");
        } else {
            vault.addToken(token2, hardCapRatioBps, refillRateMps);
            console.log("Added Token 2 to vault:", token2);
        }
    }

    function _setupRoles(AssetVault vault) internal {
        // Grant roles if addresses are provided in environment
        try vm.envAddress("ADMIN_ADDRESS") returns (address admin) {
            if (vault.hasRole(vault.ADMIN_ROLE(), admin)) {
                console.log("ADMIN_ROLE already granted to:", admin);
                return;
            }
            if (admin != address(0)) {
                vault.grantRole(vault.ADMIN_ROLE(), admin);
                console.log("Granted ADMIN_ROLE to:", admin);
            }
        } catch {}
        try vm.envAddress("OPERATOR_ADDRESS") returns (address operator) {
            if (vault.hasRole(vault.OPERATOR_ROLE(), operator)) {
                console.log("OPERATOR_ROLE already granted to:", operator);
                return;
            }
            if (operator != address(0)) {
                vault.grantRole(vault.OPERATOR_ROLE(), operator);
                console.log("Granted OPERATOR_ROLE to:", operator);
            }
        } catch {}
        try vm.envAddress("TOKEN_ROLE_ADDRESS") returns (address tokenRole) {
            if (vault.hasRole(vault.TOKEN_ROLE(), tokenRole)) {
                console.log("TOKEN_ROLE already granted to:", tokenRole);
                return;
            }
            if (tokenRole != address(0)) {
                vault.grantRole(vault.TOKEN_ROLE(), tokenRole);
                console.log("Granted TOKEN_ROLE to:", tokenRole);
            }
        } catch {}
        try vm.envAddress("PAUSE_ROLE_ADDRESS") returns (address pauseRole) {
            if (vault.hasRole(vault.PAUSE_ROLE(), pauseRole)) {
                console.log("PAUSE_ROLE already granted to:", pauseRole);
                return;
            }
            if (pauseRole != address(0)) {
                vault.grantRole(vault.PAUSE_ROLE(), pauseRole);
                console.log("Granted PAUSE_ROLE to:", pauseRole);
            }
        } catch {}
        try vm.envAddress("UPGRADE_ROLE_ADDRESS") returns (
            address upgradeRole
        ) {
            if (vault.hasRole(vault.UPGRADE_ROLE(), upgradeRole)) {
                console.log("UPGRADE_ROLE already granted to:", upgradeRole);
                return;
            }
            if (upgradeRole != address(0)) {
                vault.grantRole(vault.UPGRADE_ROLE(), upgradeRole);
                console.log("Granted UPGRADE_ROLE to:", upgradeRole);
            }
        } catch {}
    }

    function _setupValidators(AssetVault vault) internal {
        // Read validators from environment
        // Validators must be sorted by address (ascending)

        ValidatorInfo[] memory validators = new ValidatorInfo[](3);

        try vm.envAddress("VALIDATOR1_ADDRESS") returns (address addr1) {
            validators[0] = ValidatorInfo({signer: addr1, power: 1});
        } catch {}
        try vm.envAddress("VALIDATOR2_ADDRESS") returns (address addr2) {
            validators[1] = ValidatorInfo({signer: addr2, power: 1});
        } catch {}
        try vm.envAddress("VALIDATOR3_ADDRESS") returns (address addr3) {
            validators[2] = ValidatorInfo({signer: addr3, power: 1});
        } catch {}
        // Ensure validators are sorted by address
        for (uint256 i = 1; i < validators.length; i++) {
            require(
                validators[i].signer > validators[i - 1].signer,
                "Validators must be sorted by address"
            );
        }

        vault.addValidators(validators);
        console.log("Added validators:");
    }
}

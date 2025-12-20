// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script, console} from "forge-std/Script.sol";
import {AssetVault, ValidatorInfo} from "../src/AssetVault.sol";

contract SetupAssetVault is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address vaultAddress = vm.envAddress("VAULT_ADDRESS");

        AssetVault vault = AssetVault(payable(vaultAddress));

        vm.startBroadcast(deployerPrivateKey);

        // Setup roles (optional - if roles need to be granted)
        _setupRoles(vault);

        // Setup tokens
        _setupTokens(vault);

        // Setup validators
        // _setupValidators(vault);

        vault.updateHourlyWithdrawLimit(100000000000e8);

        vm.stopBroadcast();
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

    function _setupTokens(AssetVault vault) internal {
        // Add ETH (address(0)) with fixed price if configured
        try vm.envBool("ADD_ETH_TOKEN") returns (bool addEth) {
            if (addEth) {
                (, , , , , uint8 currentTokenDecimals) = vault.supportedTokens(address(0));
                if (currentTokenDecimals != 0) {
                    console.log("ETH token already exists, skipping token setup");
                    return;
                }
                console.log("Added ETH token with price feed");
                vault.addToken(
                    address(0), // ETH
                    address(0x694AA1769357215DE4FAC081bf1f309aDC325306), // priceFeed (not used for fixed price)
                    0, // price
                    false, // fixedPrice
                    8, // priceDecimals
                    18 // tokenDecimals
                );
            }
        } catch {}
        // Add ERC20 token with price feed if configured
        try vm.envAddress("TOKEN_ADDRESS") returns (address tokenAddress) {
            address priceFeedAddress = vm.envAddress("PRICE_FEED_ADDRESS");
            uint8 priceDecimals = uint8(vm.envUint("PRICE_DECIMALS"));
            uint8 tokenDecimals = uint8(vm.envUint("TOKEN_DECIMALS"));

            (, , , , , uint8 currentTokenDecimals) = vault.supportedTokens(tokenAddress);
            if (currentTokenDecimals != 0) {
                console.log("Token already exists, skipping token setup");
                return;
            }

            vault.addToken(
                tokenAddress,
                priceFeedAddress,
                0, // price (not used for oracle)
                false, // fixedPrice
                priceDecimals,
                tokenDecimals
            );
            console.log(
                "Added token:",
                tokenAddress,
                "with price feed:",
                priceFeedAddress
            );
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

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script, console} from "forge-std/Script.sol";
import {AssetVault, ValidatorInfo} from "../src/AssetVault.sol";

contract AddValidators is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("AZ_DEPLOYER_PRIVATE_KEY");
        address vaultAddress = vm.envAddress("VAULT_ADDRESS");

        AssetVault vault = AssetVault(payable(vaultAddress));

        vm.startBroadcast(deployerPrivateKey);

        ValidatorInfo[] memory validators = _getValidators();

        bytes32 validatorHash = keccak256(abi.encode(validators));
        uint256 existingPower = vault.availableValidators(validatorHash);

        if (existingPower > 0) {
            console.log("Validators already added with hash:");
            console.logBytes32(validatorHash);
            console.log("Total power:", existingPower);
        } else {
            vault.addValidators(validators);
            console.log("Successfully added validators:");
            console.log("Validator hash:");
            console.logBytes32(validatorHash);
            console.log("Total validators:", validators.length);
            uint256 totalPower = 0;
            for (uint256 i = 0; i < validators.length; i++) {
                totalPower += validators[i].power;
                console.log("Validator added", i);
            }
            console.log("Total power:", totalPower);
        }

        vm.stopBroadcast();
    }

    function _getValidators() internal pure returns (ValidatorInfo[] memory) {
        ValidatorInfo[] memory validators = new ValidatorInfo[](3);
        
        validators[0] = ValidatorInfo({
            signer: address(0x0915e8a61e4578E25bB0C1d3d7a3cF6CEE524664),
            power: 2
        });
        
        validators[1] = ValidatorInfo({
            signer: address(0x258673247216C14798BEEB85e7ab8bd9470305a1),
            power: 2
        });
        
        validators[2] = ValidatorInfo({
            signer: address(0x6E2B56556d0a45EF2aD0D8B5b2D4374849478Bde),
            power: 2
        });
        
        return validators;
    }
}


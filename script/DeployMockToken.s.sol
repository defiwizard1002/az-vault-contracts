// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script, console} from "forge-std/Script.sol";
import {MockERC20} from "../test/mock/MockERC20.sol";
import {MockPriceFeed} from "../test/mock/MockPriceFeed.sol";

contract DeployMockToken is Script {
    function run() external returns (address tokenAddress, address priceFeedAddress) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        vm.startBroadcast(deployerPrivateKey);


        console.log("Deploying MockERC20...");
        MockERC20 token = new MockERC20("Mock LINK Token", "MOCK LINK");
        console.log("Token deployed at:", address(token));

        // Mint tokens to deployer or specified address
        address mintTo = deployer;
        uint256 mintAmount = 1000000e18; // Default: 1M tokens
        token.mint(mintTo, mintAmount);
        console.log("Minted", mintAmount, "tokens to:", mintTo);

        vm.stopBroadcast();

        return (address(token), address(0));
    }
}


// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";
import {MockERC20} from "../test/mock/MockERC20.sol";

contract DepositTestToken is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("AZ_DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        // 0xbf757e944600d1E740a8b3F95eAA320DF25B16Ef,0xB1C6dC25dBDB0C3584C2552A9659DdBB1d6Db2D7
        address tokenAddress = 0xB1C6dC25dBDB0C3584C2552A9659DdBB1d6Db2D7;
        address vaultAddress = 0x5DE4C4B3ADCd59104DA8BB610e49202993207Ad0;
        uint256 amount = 1234 ether;

        vm.startBroadcast(deployerPrivateKey);

        MockERC20 token = MockERC20(tokenAddress);
        token.mint(deployer, amount);
        token.transfer(vaultAddress, amount);

        vm.stopBroadcast();
    }
}


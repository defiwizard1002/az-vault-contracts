// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {
    MessageHashUtils
} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {
    UUPSUpgradeable
} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {
    ReentrancyGuard
} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {
    PausableUpgradeable
} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {
    AccessControlUpgradeable
} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {IAggregatorV3Interface} from "./interfaces/IAggregatorV3Interface.sol";

struct TokenInfo {
    address token;
    address priceFeed;
    uint256 price;
    bool fixedPrice;
    uint8 priceDecimals;
    uint8 tokenDecimals;
}

struct ValidatorInfo {
    address signer;
    uint256 power;
}

struct WithdrawAction {
    address token;
    uint256 amount;
    uint256 fee;
    address receiver;
}

contract AssetVault is
    PausableUpgradeable,
    AccessControlUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuard
{
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant TOKEN_ROLE = keccak256("TOKEN_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant PAUSE_ROLE = keccak256("PAUSE_ROLE");
    bytes32 public constant UPGRADE_ROLE = keccak256("UPGRADE_ROLE");
    
    uint8 public constant USD_DECIMALS = 8;

    address public immutable TIMELOCK_ADDRESS;

    uint256 public hourlyWithdrawLimit;

    mapping(address => TokenInfo) public supportedTokens;

    mapping(uint256 => bool) public withdrawHistory;

    mapping(uint256 => uint256) public withdrawAmounts;

    mapping(bytes32 => uint256) public availableValidators;

    mapping(address => uint256) public fees;

    event Deposit(
        address indexed account,
        address indexed token,
        uint256 amount
    );
    event WithdrawPaused(
        address indexed trigger,
        address indexed token,
        uint256 amount,
        uint256 amountUsd
    );
    event Withdraw(
        uint256 indexed id,
        address indexed to,
        address indexed token,
        uint256 amount,
        uint256 fee
    );
    event TokenInfoAdded(
        address indexed token,
        address indexed priceFeed,
        bool fixedPrice
    );
    event TokenInfoRemoved(address indexed token);

    event ValidatorsAdded(
        bytes32 indexed hash,
        uint256 count,
        uint256 totalPower
    );

    event ValidatorsRemoved(bytes32 indexed hash, uint256 count);

    event UpdateHourlyWithdrawLimit(uint256 oldHourlyWithdrawLimit, uint256 newHourlyWithdrawLimit);

    event FeesWithdrawn(address[] tokens, uint256[] amounts, address to);

    constructor() {
        _disableInitializers();
    }

    function initialize() public initializer {
        __Pausable_init();
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADE_ROLE) {
    }

    function pause() external onlyRole(PAUSE_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSE_ROLE) {
        _unpause();
    }

    function addValidators(
        ValidatorInfo[] calldata validators
    ) external onlyRole(ADMIN_ROLE) {
        bytes32 validatorHash = keccak256(abi.encode(validators));
        require(
            availableValidators[validatorHash] == 0,
            "validators already set"
        );
        uint256 totalPower = 0;
        address lastValidator = address(0);
        for (uint256 i = 0; i < validators.length; i++) {
            require(
                validators[i].signer > lastValidator,
                "validators not ordered"
            );
            totalPower += validators[i].power;
            lastValidator = validators[i].signer;
        }
        availableValidators[validatorHash] = totalPower;
        emit ValidatorsAdded(validatorHash, validators.length, totalPower);
    }

    function removeValidators(
        ValidatorInfo[] calldata validators
    ) external onlyRole(ADMIN_ROLE) {
        bytes32 validatorHash = keccak256(abi.encode(validators));
        require(availableValidators[validatorHash] != 0, "validators not set");
        delete availableValidators[validatorHash];
        emit ValidatorsRemoved(validatorHash, validators.length);
    }

    function updateHourlyWithdrawLimit(uint256 newHourlyWithdrawLimit) external onlyRole(ADMIN_ROLE) {
        require(newHourlyWithdrawLimit > 0, "zero amount");
        uint256 oldHourlyWithdrawLimit = hourlyWithdrawLimit;
        hourlyWithdrawLimit = newHourlyWithdrawLimit;
        emit UpdateHourlyWithdrawLimit(oldHourlyWithdrawLimit, newHourlyWithdrawLimit);
    }

    function withdrawFees(
        address[] calldata tokens,
        uint256[] calldata amounts,
        address to
    ) external onlyRole(ADMIN_ROLE) {
        require(
            tokens.length == amounts.length,
            "tokens and amounts length mismatch"
        );
        for (uint256 i = 0; i < tokens.length; i++) {
            address token = tokens[i];
            uint256 fee = fees[token];
            uint256 amount = amounts[i];
            if (fee < amount) {
                amount = fee;
            }
            _transfer(payable(to), token, amount, 0);
            fees[token] -= amount;
        }
        emit FeesWithdrawn(tokens, amounts, to);
    }

    function addToken(
        address token,
        address priceFeed,
        uint256 price,
        bool fixedPrice,
        uint8 priceDecimals,
        uint8 tokenDecimals
    ) external onlyRole(TOKEN_ROLE) {
        require(priceFeed != address(0), "zero address");
        TokenInfo storage tokenInfo = supportedTokens[token];
        require(!_isTokenSupported(token), "token already exist");
        tokenInfo.token = token;
        tokenInfo.fixedPrice = fixedPrice;
        tokenInfo.priceDecimals = priceDecimals;
        tokenInfo.tokenDecimals = tokenDecimals;
        if (fixedPrice) {
            tokenInfo.price = price;
        } else {
            IAggregatorV3Interface oracle = IAggregatorV3Interface(priceFeed);
            require(
                oracle.decimals() == priceDecimals,
                "invalid price decimals"
            );
            tokenInfo.priceFeed = priceFeed;
        }
        emit TokenInfoAdded(token, priceFeed, fixedPrice);
    }

    function removeToken(address token) external onlyRole(ADMIN_ROLE) {
        require(token != address(0), "zero address");
        require(_isTokenSupported(token), "token not supported");
        delete supportedTokens[token];
        emit TokenInfoRemoved(token);
    }


    function deposit(
        address token,
        uint256 amount
    ) external payable whenNotPaused nonReentrant {
        require(_isTokenSupported(token), "token not supported");
        require(amount > 0, "zero amount");
        if (token == address(0)) {
            require(amount == msg.value, "value mismatch");
        } else {
            require(msg.value == 0, "value not zero");
            uint256 balanceBefore = IERC20(token).balanceOf(address(this));
            SafeERC20.safeTransferFrom(
                IERC20(token),
                msg.sender,
                address(this),
                amount
            );
            uint256 balanceAfter = IERC20(token).balanceOf(address(this));
            require(amount == balanceAfter - balanceBefore, "amount mismatch");
        }
        
        emit Deposit(msg.sender, token, amount);
    }

    function withdraw(
        uint256 id,
        ValidatorInfo[] calldata validators,
        WithdrawAction calldata action,
        bytes[] calldata validatorSignatures
    ) external payable whenNotPaused onlyRole(OPERATOR_ROLE) nonReentrant {
        require(!withdrawHistory[id], "used withdraw id");
        require(_isTokenSupported(action.token), "token not supported");
        bytes32 digest = keccak256(
            abi.encode(
                "withdraw",
                id,
                block.chainid,
                address(this),
                action.token,
                action.amount,
                action.fee,
                action.receiver
            )
        );
        _verifyValidatorSignature(validators, digest, validatorSignatures);
        if (!_checkLimit(action.token, action.amount)) {
            return;
        } else {
            withdrawHistory[id] = true;
            _transfer(
                payable(action.receiver),
                action.token,
                action.amount,
                action.fee
            );
            emit Withdraw(
                id,
                action.receiver,
                action.token,
                action.amount,
                action.fee
            );
        }
    }

    // ================================ Internal Functions ================================

    function _isTokenSupported(address token) internal view returns (bool) {
        return supportedTokens[token].tokenDecimals != 0;
    }

    // validators must be sorted
    function _verifyValidatorSignature(
        ValidatorInfo[] calldata validators,
        bytes32 digest,
        bytes[] calldata validatorSignatures
    ) internal view {
        bytes32 validatorHash = keccak256(abi.encode(validators));
        uint256 totalPower = availableValidators[validatorHash];
        require(totalPower > 0, "invalid validators");
        uint256 power = 0;
        uint256 validatorIndex = 0;
        bytes32 validatorDigest = MessageHashUtils.toEthSignedMessageHash(
            digest
        );
        for (
            uint256 i = 0;
            i < validatorSignatures.length &&
                validatorIndex < validators.length;
            i++
        ) {
            address recovered = ECDSA.recover(
                validatorDigest,
                validatorSignatures[i]
            );
            if (recovered == address(0)) {
                continue;
            }
            while (validatorIndex < validators.length) {
                address validator = validators[validatorIndex].signer;
                validatorIndex++;
                if (validator == recovered) {
                    power += validators[validatorIndex - 1].power;
                    break;
                }
            }
        }
        require(power >= (totalPower * 2) / 3, "not enough validator power");
    }

    function _checkLimit(
        address token,
        uint256 amount
    ) internal returns (bool) {
        uint256 amountUsd = _amountUsd(token, amount);
        require(amountUsd > 0, "zero usd amount");
        uint256 cursor = block.timestamp / 1 hours;
        if (withdrawAmounts[cursor] + amountUsd > hourlyWithdrawLimit) {
            _pause();
            emit WithdrawPaused(msg.sender, token, amount, amountUsd);
            return false;
        } else {
            withdrawAmounts[cursor] += amountUsd;
            return true;
        }
    }

    bytes32 internal constant PERMIT_TYPEHASH =
        keccak256(
            "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
        );

    function _transfer(
        address payable to,
        address token,
        uint256 amount,
        uint256 fee
    ) private {
        require(amount > 0, "zero amount");
        if (token == address(0)) {
            Address.sendValue(payable(to), amount);
        } else {
            SafeERC20.safeTransfer(IERC20(token), to, amount - fee);
            if (fee > 0) {
                fees[token] += fee;
            }
        }
    }

    function _amountUsd(
        address token,
        uint256 amount
    ) private view returns (uint256) {
        TokenInfo memory tokenInfo = supportedTokens[token];
        uint256 price = tokenInfo.price;
        if (!tokenInfo.fixedPrice) {
            IAggregatorV3Interface oracle = IAggregatorV3Interface(
                tokenInfo.priceFeed
            );
            (, int256 oraclePrice, , , ) = oracle.latestRoundData();
            price = uint256(oraclePrice);
        }
        return
            (price * amount * (10 ** USD_DECIMALS)) /
            (10 ** (tokenInfo.priceDecimals + tokenInfo.tokenDecimals));
    }
}

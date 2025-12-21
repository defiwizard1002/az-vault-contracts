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

struct TokenInfo {
    address token;
    // when usedWithdrawHotAmount < hardCap (=totalLockedTokenAmount * hardCapRatioBps / 10000),
    // pending mode will be activated
    uint256 hardCapRatioBps;
    // Every second, the usedWithdrawHotAmount will be decreased by refillRateMps / 1000000 * hardCap
    uint256 refillRateMps;
    // The timestamp of the last refill
    uint256 lastRefillTimestamp;
    // Every time user withdraw in fast mode, this amount will be deducted
    uint256 usedWithdrawHotAmount;
}

struct ValidatorInfo {
    address signer;
    uint256 power;
}

enum WithdrawType {
    NORMAL,
    FORCE_PENDING,
    PAUSE_WITHDRAW,
    UNPAUSE_WITHDRAW,
    FLUSH
}

struct WithdrawAction {
    address token;
    uint256 amount;
    uint256 fee;
    address receiver;
    WithdrawType withdrawType;
}

struct Withdrawal {
    bool paused;
    bool pending;
    bool executed;
    uint256 amount;
    address token;
    uint256 fee;
    address receiver;
    uint256 timestamp;
    WithdrawType withdrawType;
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

    mapping(address => TokenInfo) public supportedTokens;

    mapping(uint256 => Withdrawal) public withdrawals;

    uint256[] public pendingWithdrawalIds;

    // After challenge period, the pending withdraw can be withdrawn unconditionally
    uint256 public pendingWithdrawChallengePeriod;

    mapping(bytes32 => uint256) public availableValidators;

    mapping(address => uint256) public fees;

    event Deposit(address account, address token, uint256 amount);

    event TokenAdded(
        address token,
        uint256 hardCapRatioBps,
        uint256 refillRateMps
    );
    event TokenRemoved(address token);
    event TokenUpdated(
        address token,
        uint256 hardCapRatioBps,
        uint256 refillRateMps
    );

    event WithdrawHotAmountRefilled(
        address token,
        uint256 refillAmount,
        uint256 usedWithdrawHotAmount
    );
    event WithdrawHotAmountUsed(
        address token,
        uint256 amount,
        uint256 updateUsedWithdrawHotAmount,
        bool forcePending
    );
    event WithdrawalAdded(
        uint256 id,
        address token,
        uint256 amount,
        uint256 fee,
        address receiver,
        WithdrawType withdrawType,
        bool isPending
    );
    event WithdrawExecuted(
        uint256 id,
        address to,
        address token,
        uint256 amount,
        uint256 fee,
        WithdrawType withdrawType
    );
    event PendingWithdrawalToggled(uint256 id, bool paused);

    event ValidatorsAdded(bytes32 hash, uint256 count, uint256 totalPower);
    event ValidatorsRemoved(bytes32 hash, uint256 count);

    event PendingWithdrawChallengePeriodUpdated(
        uint256 oldValue,
        uint256 newValue
    );

    // Fee events
    event FeesWithdrawn(address[] tokens, uint256[] amounts, address to);

    modifier onlySupportedToken(address token) {
        require(
            supportedTokens[token].hardCapRatioBps > 0,
            "token not supported"
        );
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(
        uint256 _pendingWithdrawChallengePeriod
    ) public initializer {
        __Pausable_init();
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        pendingWithdrawChallengePeriod = _pendingWithdrawChallengePeriod;
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override(UUPSUpgradeable) onlyRole(UPGRADE_ROLE) {}

    function pause() external onlyRole(PAUSE_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSE_ROLE) {
        _unpause();
    }

    function updatePendingWithdrawChallengePeriod(
        uint256 newValue
    ) external onlyRole(ADMIN_ROLE) {
        uint256 oldValue = pendingWithdrawChallengePeriod;
        pendingWithdrawChallengePeriod = newValue;
        emit PendingWithdrawChallengePeriodUpdated(oldValue, newValue);
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
        uint256 hardCapRatioBps,
        uint256 refillRateMps
    ) external onlyRole(TOKEN_ROLE) {
        TokenInfo storage tokenInfo = supportedTokens[token];
        require(tokenInfo.hardCapRatioBps == 0, "token already exists");
        _validateToken(hardCapRatioBps, refillRateMps);
        tokenInfo.token = token;
        tokenInfo.hardCapRatioBps = hardCapRatioBps;
        tokenInfo.refillRateMps = refillRateMps;
        emit TokenAdded(token, hardCapRatioBps, refillRateMps);
    }

    function removeToken(
        address token
    ) external onlyRole(ADMIN_ROLE) onlySupportedToken(token) {
        delete supportedTokens[token];
        emit TokenRemoved(token);
    }

    function updateToken(
        address token,
        uint256 hardCapRatioBps,
        uint256 refillRateMps
    ) external onlyRole(ADMIN_ROLE) onlySupportedToken(token) {
        _validateToken(hardCapRatioBps, refillRateMps);
        supportedTokens[token].hardCapRatioBps = hardCapRatioBps;
        supportedTokens[token].refillRateMps = refillRateMps;
        emit TokenUpdated(token, hardCapRatioBps, refillRateMps);
    }

    function deposit(
        address token,
        uint256 amount
    ) external payable whenNotPaused onlySupportedToken(token) nonReentrant {
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
    )
        external
        payable
        whenNotPaused
        onlyRole(OPERATOR_ROLE)
        onlySupportedToken(action.token)
        nonReentrant
    {
        _refillWithdrawHotAmount(action.token);

        bytes32 digest = keccak256(
            abi.encode(
                "withdraw",
                id,
                block.chainid,
                address(this),
                action.token,
                action.amount,
                action.fee,
                action.receiver,
                action.withdrawType
            )
        );

        _verifyValidatorSignature(validators, digest, validatorSignatures);

        if (action.withdrawType == WithdrawType.PAUSE_WITHDRAW) {
            _togglePendingWithdrawal(id, true);
        } else if (action.withdrawType == WithdrawType.UNPAUSE_WITHDRAW) {
            _togglePendingWithdrawal(id, false);
        } else if (action.withdrawType == WithdrawType.FLUSH) {
            // todo: flush
        } else if (action.withdrawType == WithdrawType.NORMAL) {
            // when normal withdrawal triggers hard cap exceeded, fallback to pending mode
            bool shouldPending = _increaseUsedWithdrawHotAmount(
                supportedTokens[action.token],
                action.amount
            );
            _addWithdrawal(
                id,
                action.token,
                action.amount,
                action.fee,
                action.receiver,
                action.withdrawType,
                shouldPending
            );
            if (!shouldPending) {
                // directly execute the withdrawal
                executeWithdrawal(id);
            }
        } else if (action.withdrawType == WithdrawType.FORCE_PENDING) {
            _addWithdrawal(
                id,
                action.token,
                action.amount,
                action.fee,
                action.receiver,
                action.withdrawType,
                true
            );
        }
    }

    function executeWithdrawal(uint256 id) public onlyRole(OPERATOR_ROLE) {
        _checkWithdrawalExists(id, true);
        Withdrawal storage withdrawal = withdrawals[id];
        require(!withdrawal.executed, "withdrawal executed");
        require(!withdrawal.paused, "withdrawal paused");
        // pending withdrawal can only be executed if challenge period is expired
        if (withdrawal.pending) {
            require(
                block.timestamp >=
                    withdrawal.timestamp + pendingWithdrawChallengePeriod,
                "challenge period not expired"
            );
        }
        _transfer(
            payable(withdrawal.receiver),
            withdrawal.token,
            withdrawal.amount,
            withdrawal.fee
        );
        withdrawal.executed = true;
        emit WithdrawExecuted(
            id,
            withdrawal.receiver,
            withdrawal.token,
            withdrawal.amount,
            withdrawal.fee,
            WithdrawType.NORMAL
        );
    }

    // ================================ Internal Functions ================================

    function _validateToken(
        uint256 hardCapRatioBps,
        uint256 refillRateMps
    ) internal pure {
        require(hardCapRatioBps > 0 && hardCapRatioBps <= 10000 && refillRateMps > 0 && refillRateMps <= 1000000, "invalid parameters");
    }

    // validators must be sorted by address
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

    function _refillWithdrawHotAmount(address token) internal {
        TokenInfo storage tokenInfo = supportedTokens[token];
        uint256 refillPeriod = block.timestamp - tokenInfo.lastRefillTimestamp;
        uint256 hardCap = (IERC20(token).balanceOf(address(this)) *
            tokenInfo.hardCapRatioBps) / 10000;
        uint256 refillAmount = (hardCap *
            tokenInfo.refillRateMps *
            refillPeriod) / 1000000;
        if (tokenInfo.usedWithdrawHotAmount < refillAmount) {
            tokenInfo.usedWithdrawHotAmount = 0;
        } else {
            tokenInfo.usedWithdrawHotAmount -= refillAmount;
        }
        tokenInfo.lastRefillTimestamp = block.timestamp;
        emit WithdrawHotAmountRefilled(
            tokenInfo.token,
            refillAmount,
            tokenInfo.usedWithdrawHotAmount
        );
    }

    function _increaseUsedWithdrawHotAmount(
        TokenInfo storage tokenInfo,
        uint256 amount
    ) internal returns (bool forcePending) {
        uint256 hardCap = (IERC20(tokenInfo.token).balanceOf(address(this)) *
            tokenInfo.hardCapRatioBps) / 10000;
        // hard cap exceeded
        if (tokenInfo.usedWithdrawHotAmount + amount > hardCap) {
            forcePending = true;
        } else {
            tokenInfo.usedWithdrawHotAmount += amount;
        }
        emit WithdrawHotAmountUsed(
            tokenInfo.token,
            amount,
            tokenInfo.usedWithdrawHotAmount,
            forcePending
        );
    }

    function _addWithdrawal(
        uint256 id,
        address token,
        uint256 amount,
        uint256 fee,
        address receiver,
        WithdrawType withdrawType,
        bool isPending
    ) internal {
        _checkWithdrawalExists(id, false);
        withdrawals[id] = Withdrawal(
            false,
            isPending,
            false,
            amount,
            token,
            fee,
            receiver,
            block.timestamp,
            withdrawType
        );
        emit WithdrawalAdded(
            id,
            token,
            amount,
            fee,
            receiver,
            withdrawType,
            isPending
        );
    }

    function _togglePendingWithdrawal(uint256 id, bool shouldPause) internal {
        Withdrawal storage withdrawal = withdrawals[id];
        // 1. executed withdrawal cannot be paused/unpaused
        // 2. pending withdrawal cannot be paused/unpaused if challenge period is expired
        require(
            !withdrawal.executed ||
                (block.timestamp <
                    withdrawal.timestamp + pendingWithdrawChallengePeriod &&
                    withdrawal.pending),
            "withdraw executed or challenge period expired"
        );
        require(
            withdrawal.paused != shouldPause,
            "withdraw already in desired state"
        );
        withdrawal.paused = shouldPause;
        emit PendingWithdrawalToggled(id, shouldPause);
    }

    function _checkWithdrawalExists(uint256 id, bool shouldExist) internal {
        bool isExisting = withdrawals[id].timestamp > 0;
        require(isExisting == shouldExist, "withdrawal existance check failed");
    }

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
}

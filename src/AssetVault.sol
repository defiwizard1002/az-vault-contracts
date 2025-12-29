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

struct WithdrawAction {
    address token;
    uint256 amount;
    uint256 fee;
    address receiver;
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
}

contract AssetVault is
    PausableUpgradeable,
    AccessControlUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuard
{
    error ValidatorsAlreadySet();
    error ValidatorsNotOrdered();
    error ValidatorsNotSet();
    error TokensAndAmountsLengthMismatch();
    error TokenAlreadyExists();
    error ZeroAmount();
    error ValueMismatch();
    error ValueNotZero();
    error AmountMismatch();
    error EmptyIds();
    error ChallengePeriodNotExpired();
    error ChallengePeriodExpired();
    error WithdrawAlreadyInDesiredState();
    error WithdrawalPaused();
    error WithdrawalMustBePending();
    error EmptyTokens();
    error InvalidParameters();
    error InvalidValidators();
    error NotEnoughValidatorPower();
    error TokenNotSupported();
    error WithdrawalExistenceCheckFailed();
    error WithdrawalAlreadyExecuted();

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
        bool isPending,
        bool isForcePending
    );

    event WithdrawExecuted(
        uint256 id,
        address to,
        address token,
        uint256 amount,
        uint256 fee,
        // Whether the withdrawal is pending when executed
        bool isPending,
        // Whether the withdrawal is flushed
        bool isFlushed,
        // Whether the withdrawal is paused when executed
        bool isPaused
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
        if (availableValidators[validatorHash] != 0) {
            revert ValidatorsAlreadySet();
        }
        uint256 totalPower = 0;
        address lastValidator = address(0);
        for (uint256 i = 0; i < validators.length; i++) {
            if (validators[i].signer <= lastValidator) {
                revert ValidatorsNotOrdered();
            }
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
        if (availableValidators[validatorHash] == 0) {
            revert ValidatorsNotSet();
        }
        delete availableValidators[validatorHash];
        emit ValidatorsRemoved(validatorHash, validators.length);
    }

    function withdrawFees(
        address[] calldata tokens,
        uint256[] calldata amounts,
        address to
    ) external whenNotPaused onlyRole(ADMIN_ROLE) nonReentrant {
        if (tokens.length != amounts.length) {
            revert TokensAndAmountsLengthMismatch();
        }
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
        if (tokenInfo.hardCapRatioBps != 0) {
            revert TokenAlreadyExists();
        }
        _validateToken(hardCapRatioBps, refillRateMps);
        tokenInfo.token = token;
        tokenInfo.hardCapRatioBps = hardCapRatioBps;
        tokenInfo.refillRateMps = refillRateMps;
        emit TokenAdded(token, hardCapRatioBps, refillRateMps);
    }

    function removeToken(address token) external onlyRole(ADMIN_ROLE) {
        _ensureTokenSupported(token);
        delete supportedTokens[token];
        emit TokenRemoved(token);
    }

    function updateToken(
        address token,
        uint256 hardCapRatioBps,
        uint256 refillRateMps
    ) external onlyRole(ADMIN_ROLE) {
        _ensureTokenSupported(token);
        _validateToken(hardCapRatioBps, refillRateMps);
        supportedTokens[token].hardCapRatioBps = hardCapRatioBps;
        supportedTokens[token].refillRateMps = refillRateMps;
        emit TokenUpdated(token, hardCapRatioBps, refillRateMps);
    }

    function deposit(
        address token,
        uint256 amount
    ) external payable whenNotPaused nonReentrant {
        _ensureTokenSupported(token);
        if (amount == 0) {
            revert ZeroAmount();
        }
        if (token == address(0)) {
            if (amount != msg.value) {
                revert ValueMismatch();
            }
        } else {
            if (msg.value != 0) {
                revert ValueNotZero();
            }
            uint256 balanceBefore = IERC20(token).balanceOf(address(this));
            SafeERC20.safeTransferFrom(
                IERC20(token),
                msg.sender,
                address(this),
                amount
            );
            uint256 balanceAfter = IERC20(token).balanceOf(address(this));
            if (amount != balanceAfter - balanceBefore) {
                revert AmountMismatch();
            }
        }

        emit Deposit(msg.sender, token, amount);
    }

    function requestWithdraw(
        uint256 id,
        bool isForcePending,
        ValidatorInfo[] calldata validators,
        WithdrawAction calldata action,
        bytes[] calldata validatorSignatures
    ) external payable whenNotPaused onlyRole(OPERATOR_ROLE) nonReentrant {
        _ensureTokenSupported(action.token);
        _refillWithdrawHotAmount(action.token);
        _checkWithdrawalExists(id, false);

        bytes32 digest = keccak256(
            abi.encode(
                "requestWithdraw",
                id,
                block.chainid,
                address(this),
                action.token,
                action.amount,
                action.fee,
                action.receiver,
                isForcePending
            )
        );

        _verifyValidatorSignature(validators, digest, validatorSignatures);

        bool isPending = isForcePending;
        if (!isForcePending) {
            // when normal withdrawal triggers hard cap exceeded, fallback to pending mode
            isPending = _increaseUsedWithdrawHotAmount(
                supportedTokens[action.token],
                action.amount
            );
        }
        withdrawals[id] = Withdrawal(
            false,
            isPending,
            false,
            action.amount,
            action.token,
            action.fee,
            action.receiver,
            block.timestamp
        );
        emit WithdrawalAdded(
            id,
            action.token,
            action.amount,
            action.fee,
            action.receiver,
            isPending,
            isForcePending
        );
        if (!isPending) {
            _executeWithdrawal(id, isPending, false, false);
        }
    }

    function batchTogglePendingWithdrawal(
        uint256[] calldata ids,
        bool shouldPause,
        ValidatorInfo[] calldata validators,
        bytes[] calldata validatorSignatures
    ) external whenNotPaused onlyRole(OPERATOR_ROLE) nonReentrant {
        if (ids.length == 0) {
            revert EmptyIds();
        }
        bytes32 digest = keccak256(
            abi.encode(
                "batchTogglePendingWithdrawal",
                ids,
                block.chainid,
                address(this),
                shouldPause
            )
        );

        _verifyValidatorSignature(validators, digest, validatorSignatures);

        for (uint256 i = 0; i < ids.length; i++) {
            Withdrawal storage withdrawal = withdrawals[ids[i]];
            _refillWithdrawHotAmount(withdrawal.token);
            // 1. executed withdrawal cannot be paused/unpaused
            // 2. pending withdrawal cannot be paused/unpaused if challenge period is expired
            _checkWithdrawalNotExecuted(ids[i]);
            _checkWithdrawalPending(ids[i]);
            if (block.timestamp >= withdrawal.timestamp + pendingWithdrawChallengePeriod) {
                revert ChallengePeriodExpired();
            }
            if (withdrawal.paused == shouldPause) {
                revert WithdrawAlreadyInDesiredState();
            }
            withdrawal.paused = shouldPause;
            emit PendingWithdrawalToggled(ids[i], shouldPause);
        }
    }

    function executePendingWithdrawal(
        uint256 id,
        ValidatorInfo[] calldata validators,
        bytes[] calldata validatorSignatures
    ) external whenNotPaused onlyRole(OPERATOR_ROLE) nonReentrant {
        bytes32 digest = keccak256(
            abi.encode(
                "executePendingWithdrawal",
                id,
                block.chainid,
                address(this)
            )
        );
        _verifyValidatorSignature(validators, digest, validatorSignatures);
        _checkWithdrawalExists(id, true);
        _checkWithdrawalNotExecuted(id);
        Withdrawal storage withdrawal = withdrawals[id];
        _refillWithdrawHotAmount(withdrawal.token);
        if (withdrawal.paused) {
            revert WithdrawalPaused();
        }
        if (!withdrawal.pending) {
            revert WithdrawalMustBePending();
        }
        if (block.timestamp < withdrawal.timestamp + pendingWithdrawChallengePeriod) {
            revert ChallengePeriodNotExpired();
        }
        _executeWithdrawal(id, withdrawal.pending, false, withdrawal.paused);
    }

    // No matter the withdrawal is pending or not, paused or not, it will be executed when flushing
    function batchFlushWithdrawals(
        uint256[] calldata ids,
        ValidatorInfo[] calldata validators,
        bytes[] calldata validatorSignatures
    ) external whenNotPaused onlyRole(OPERATOR_ROLE) nonReentrant {
        if (ids.length == 0) {
            revert EmptyIds();
        }
        bytes32 digest = keccak256(
            abi.encode(
                "batchFlushWithdrawals",
                ids,
                block.chainid,
                address(this)
            )
        );
        _verifyValidatorSignature(validators, digest, validatorSignatures);
        for (uint256 i = 0; i < ids.length; i++) {
            uint256 id = ids[i];
            _checkWithdrawalExists(id, true);
            _checkWithdrawalNotExecuted(id);
            Withdrawal storage withdrawal = withdrawals[id];
            _refillWithdrawHotAmount(withdrawal.token);
            _executeWithdrawal(id, withdrawal.pending, true, withdrawal.paused);
        }
    }

    function batchResetWithdrawHotAmount(
        address[] calldata tokens,
        ValidatorInfo[] calldata validators,
        bytes[] calldata validatorSignatures
    ) external whenNotPaused onlyRole(OPERATOR_ROLE) nonReentrant {
        if (tokens.length == 0) {
            revert EmptyTokens();
        }
        bytes32 digest = keccak256(
            abi.encode(
                "batchResetWithdrawHotAmount",
                tokens,
                block.chainid,
                address(this)
            )
        );
        _verifyValidatorSignature(validators, digest, validatorSignatures);
        for (uint256 i = 0; i < tokens.length; i++) {
            _ensureTokenSupported(tokens[i]);
            _refillWithdrawHotAmount(tokens[i]);
            supportedTokens[tokens[i]].usedWithdrawHotAmount = 0;
            supportedTokens[tokens[i]].lastRefillTimestamp = block.timestamp;
            emit WithdrawHotAmountRefilled(tokens[i], 0, 0);
        }
    }

    // ================================ Internal Functions ================================

    function _validateToken(
        uint256 hardCapRatioBps,
        uint256 refillRateMps
    ) internal pure {
        if (
            hardCapRatioBps == 0 ||
            hardCapRatioBps > 10000 ||
            refillRateMps == 0 ||
            refillRateMps > 1000000
        ) {
            revert InvalidParameters();
        }
    }

    // validators must be sorted by address
    function _verifyValidatorSignature(
        ValidatorInfo[] calldata validators,
        bytes32 digest,
        bytes[] calldata validatorSignatures
    ) internal view {
        bytes32 validatorHash = keccak256(abi.encode(validators));
        uint256 totalPower = availableValidators[validatorHash];
        if (totalPower == 0) {
            revert InvalidValidators();
        }
        uint256 power = 0;
        uint256 validatorIndex = 0;
        bytes32 validatorDigest = MessageHashUtils.toEthSignedMessageHash(
            digest
        );
        for (
            uint256 signatureIndex = 0;
            signatureIndex < validatorSignatures.length &&
                validatorIndex < validators.length;
            signatureIndex++
        ) {
            address recovered = ECDSA.recover(
                validatorDigest,
                validatorSignatures[signatureIndex]
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
        if (power < (totalPower * 2) / 3) {
            revert NotEnoughValidatorPower();
        }
    }

    function _refillWithdrawHotAmount(address token) internal {
        TokenInfo storage tokenInfo = supportedTokens[token];
        uint256 refillPeriod = block.timestamp - tokenInfo.lastRefillTimestamp;
        if (refillPeriod == 0) {
            return;
        }
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
    ) internal returns (bool pendingTriggered) {
        uint256 hardCap = (IERC20(tokenInfo.token).balanceOf(address(this)) *
            tokenInfo.hardCapRatioBps) / 10000;
        // hard cap exceeded
        if (tokenInfo.usedWithdrawHotAmount + amount > hardCap) {
            pendingTriggered = true;
        } else {
            tokenInfo.usedWithdrawHotAmount += amount;
        }
        emit WithdrawHotAmountUsed(
            tokenInfo.token,
            amount,
            tokenInfo.usedWithdrawHotAmount,
            pendingTriggered
        );
    }

    function _executeWithdrawal(
        uint256 id,
        bool isPending,
        bool isFlushed,
        bool isPaused
    ) internal {
        Withdrawal storage withdrawal = withdrawals[id];
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
            isPending,
            isFlushed,
            isPaused
        );
    }

    function _ensureTokenSupported(address token) internal view {
        if (supportedTokens[token].hardCapRatioBps == 0) {
            revert TokenNotSupported();
        }
    }

    function _checkWithdrawalExists(
        uint256 id,
        bool shouldExist
    ) internal view {
        bool isExisting = withdrawals[id].timestamp > 0;
        if (isExisting != shouldExist) {
            revert WithdrawalExistenceCheckFailed();
        }
    }

    function _checkWithdrawalNotExecuted(uint256 id) internal view {
        if (withdrawals[id].executed) {
            revert WithdrawalAlreadyExecuted();
        }
    }

    function _checkWithdrawalPending(uint256 id) internal view {
        if (!withdrawals[id].pending) {
            revert WithdrawalMustBePending();
        }
    }

    function _transfer(
        address payable to,
        address token,
        uint256 amount,
        uint256 fee
    ) private {
        if (amount == 0) {
            revert ZeroAmount();
        }
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

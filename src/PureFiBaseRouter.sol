// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;


import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {BalanceDelta} from "v4-core/types/BalanceDelta.sol";
import {IUnlockCallback} from "v4-core/interfaces/callback/IUnlockCallback.sol";
import {CurrencyLibrary, Currency} from "v4-core/types/Currency.sol";
import {CustomRevert} from "v4-core/libraries/CustomRevert.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {PureFiMMWhitelist} from "./PureFiMMWhitelist.sol";
import {StateLibrary} from "v4-core/libraries/StateLibrary.sol";
import {TransientStateLibrary} from "v4-core/libraries/TransientStateLibrary.sol";
import "@purefi/sdk-solidity/interfaces/IPureFiVerifier.sol";

abstract contract PureFiBaseRouter is IUnlockCallback, Ownable {
    using StateLibrary for IPoolManager;
    using CustomRevert for bytes4;
    using TransientStateLibrary for IPoolManager;


    IPoolManager public immutable manager;
    IPureFiVerifier public immutable verifier;
    PureFiMMWhitelist internal immutable whitelist;

    IERC20 immutable tokenA;
    IERC20 immutable tokenB;

    // Packed array of booleans
    mapping(uint256 => uint256) private expectedRuleIDsBitMap;

    error UnexpectedRule();
    error MessageSenderMismatch();

    constructor(
        IPoolManager _poolManager,
        IPureFiVerifier _verifier,
        IERC20 _tokenA,
        IERC20 _tokenB,
        PureFiMMWhitelist _whitelist
    ) Ownable(msg.sender) {
        manager = _poolManager;
        verifier = _verifier;
        tokenA = _tokenA;
        tokenB = _tokenB;
        whitelist = _whitelist;
    }

    // Hook checks: rule, from (=msg.sender), token, amount
    // Verifier checks: package length, issuer/signature, AML gracetime, session, to (=hook)

    modifier purified(bytes memory purefidata) {
        _validatePureFiData(purefidata);
        _;
    }

    function isExpectedRule(uint256 ruleId) public view returns (bool) {
        uint256 expectedRuleWordIndex = ruleId / 256;
        uint256 expectedRuleBitIndex = ruleId % 256;
        uint256 expectedRuleWord = expectedRuleIDsBitMap[expectedRuleWordIndex];
        uint256 mask = (1 << expectedRuleBitIndex);
        return expectedRuleWord & mask == mask;
    }

    function setExpectedRuleIds(uint256[] calldata ruleIds) external onlyOwner {
        for (uint i = 0; i < ruleIds.length; i++) {
            uint256 expectedRuleWordIndex = ruleIds[i] / 256;
            uint256 expectedRuleBitIndex = ruleIds[i] % 256;
            expectedRuleIDsBitMap[expectedRuleWordIndex] =
                expectedRuleIDsBitMap[expectedRuleWordIndex] |
                (1 << expectedRuleBitIndex);
        }
    }

    function unsetExpectedRuleId(uint256[] calldata ruleIds) external onlyOwner {
        for (uint i = 0; i < ruleIds.length; i++) {
            uint256 expectedRuleWordIndex = ruleIds[i] / 256;
            uint256 expectedRuleBitIndex = ruleIds[i] % 256;
            expectedRuleIDsBitMap[expectedRuleWordIndex] =
                expectedRuleIDsBitMap[expectedRuleWordIndex] &
                ~(1 << expectedRuleBitIndex);
        }
    }

    /// @notice Settle (pay) a currency to the PoolManager
    /// @param currency Currency to settle
    /// @param payer Address of the payer, the token sender
    /// @param amount Amount to send
    /// @param burn If true, burn the ERC-6909 token, otherwise ERC20-transfer to the PoolManager
    function settle(Currency currency, address payer, uint256 amount, bool burn) internal {
        // for native currencies or burns, calling sync is not required
        // short circuit for ERC-6909 burns to support ERC-6909-wrapped native tokens
        if (burn) {
            manager.burn(payer, currency.toId(), amount);
        } else if (currency.isNative()) {
            manager.settle{value: amount}();
        } else {
            manager.sync(currency);
            if (payer != address(this)) {
                IERC20(Currency.unwrap(currency)).transferFrom(payer, address(manager), amount);
            } else {
                IERC20(Currency.unwrap(currency)).transfer(address(manager), amount);
            }
            manager.settle();
        }
    }

    /// @notice Take (receive) a currency from the PoolManager
    /// @param currency Currency to take
    /// @param recipient Address of the recipient, the token receiver
    /// @param amount Amount to receive
    /// @param claims If true, mint the ERC-6909 token, otherwise ERC20-transfer from the PoolManager to recipient
    function take(Currency currency, address recipient, uint256 amount, bool claims) internal {
        claims ? manager.mint(recipient, currency.toId(), amount) : manager.take(currency, recipient, amount);
    }


    function _fetchBalances(Currency currency, address user, address deltaHolder)
    internal
    view
    returns (uint256 userBalance, uint256 poolBalance, int256 delta)
    {
        userBalance = currency.balanceOf(user);
        poolBalance = currency.balanceOf(address(manager));
        delta = manager.currencyDelta(deltaHolder, currency);
    }


    function _validatePureFiData(
        bytes memory pureFiData
    ) internal virtual returns (VerificationPackage memory package) {
        if (whitelist.isAuthorized(msg.sender)) return package;
        package = verifier.validateAndDecode(pureFiData);
        if (!isExpectedRule(package.rule)) {
            UnexpectedRule.selector.revertWith();
        }
        if (package.from != msg.sender) {
            MessageSenderMismatch.selector.revertWith();
        }
    }
}

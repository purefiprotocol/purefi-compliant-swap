// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {BalanceDelta} from "v4-core/types/BalanceDelta.sol";
import {IUnlockCallback} from "v4-core/interfaces/callback/IUnlockCallback.sol";
import {CurrencyLibrary} from "v4-core/types/Currency.sol";
import {TickMath} from "v4-core/libraries/TickMath.sol";
import {StateLibrary} from "v4-core/libraries/StateLibrary.sol";
import {TransientStateLibrary} from "v4-core/libraries/TransientStateLibrary.sol";
import {PoolIdLibrary} from "v4-core/types/PoolId.sol";
import "v4-core/libraries/Pool.sol";
import "v4-core/libraries/CustomRevert.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {PureFiBaseRouter} from "./PureFiBaseRouter.sol";
import {PureFiMMWhitelist} from "./PureFiMMWhitelist.sol";
import "@purefi/sdk-solidity/interfaces/IPureFiVerifier.sol";


contract PureFiSwapRouter is PureFiBaseRouter {
    using TickBitmap for mapping(int16 => uint256);
    using CustomRevert for bytes4;
    using StateLibrary for IPoolManager;
    using PoolIdLibrary for PoolKey;
    using TransientStateLibrary for IPoolManager;
    using SafeCast for *;

    uint160 public constant MIN_PRICE_LIMIT = TickMath.MIN_SQRT_PRICE + 1;
    uint160 public constant MAX_PRICE_LIMIT = TickMath.MAX_SQRT_PRICE - 1;

    error InvalidTokenAddress();
    error WrongPureFiPackage(uint8 packageType);

    error WrongAmountSpecifiedExactInput(uint160 input, uint160 packageAmount);
    error WrongAmountSpecifiedExactOutput(uint160 input, uint160 packageAmount);

    constructor(
        IPoolManager _poolManager,
        IPureFiVerifier _verifier,
        IERC20 _tokenA,
        IERC20 _tokenB,
        PureFiMMWhitelist _whitelist
    ) PureFiBaseRouter(_poolManager, _verifier, _tokenA, _tokenB, _whitelist) {}

    error NoSwapOccurred();

    struct CallbackData {
        address sender;
        TestSettings testSettings;
        PoolKey key;
        IPoolManager.SwapParams params;
        bytes hookData;
    }

    struct TestSettings {
        bool takeClaims;
        bool settleUsingBurn;
    }


    modifier purifiedSwap(
        IPoolManager.SwapParams memory params,
        PoolKey memory key,
        bytes memory pureFiData
    ) {
        _validatePureFiData(params, pureFiData);
        _;
    }

    function swap(
        PoolKey memory key,
        IPoolManager.SwapParams memory params,
        TestSettings memory testSettings,
        bytes memory hookData
    )
    purifiedSwap(params, key, hookData)
    external payable returns (BalanceDelta delta) {
        delta = abi.decode(
            manager.unlock(abi.encode(CallbackData(msg.sender, testSettings, key, params, hookData))), (BalanceDelta)
        );

        uint256 ethBalance = address(this).balance;
        if (ethBalance > 0) CurrencyLibrary.ADDRESS_ZERO.transfer(msg.sender, ethBalance);
    }

    function unlockCallback(bytes calldata rawData) external returns (bytes memory) {
        require(msg.sender == address(manager));

        CallbackData memory data = abi.decode(rawData, (CallbackData));

        (,, int256 deltaBefore0) = _fetchBalances(data.key.currency0, data.sender, address(this));
        (,, int256 deltaBefore1) = _fetchBalances(data.key.currency1, data.sender, address(this));

        require(deltaBefore0 == 0, "deltaBefore0 is not equal to 0");
        require(deltaBefore1 == 0, "deltaBefore1 is not equal to 0");

        BalanceDelta delta = manager.swap(data.key, data.params, data.hookData);

        (,, int256 deltaAfter0) = _fetchBalances(data.key.currency0, data.sender, address(this));
        (,, int256 deltaAfter1) = _fetchBalances(data.key.currency1, data.sender, address(this));

        if (data.params.zeroForOne) {
            if (data.params.amountSpecified < 0) {
                // exact input, 0 for 1
                require(
                    deltaAfter0 >= data.params.amountSpecified,
                    "deltaAfter0 is not greater than or equal to data.params.amountSpecified"
                );
                require(delta.amount0() == deltaAfter0, "delta.amount0() is not equal to deltaAfter0");
                require(deltaAfter1 >= 0, "deltaAfter1 is not greater than or equal to 0");
            } else {
                // exact output, 0 for 1
                require(deltaAfter0 <= 0, "deltaAfter0 is not less than or equal to zero");
                require(delta.amount1() == deltaAfter1, "delta.amount1() is not equal to deltaAfter1");
                require(
                    deltaAfter1 <= data.params.amountSpecified,
                    "deltaAfter1 is not less than or equal to data.params.amountSpecified"
                );
            }
        } else {
            if (data.params.amountSpecified < 0) {
                // exact input, 1 for 0
                require(
                    deltaAfter1 >= data.params.amountSpecified,
                    "deltaAfter1 is not greater than or equal to data.params.amountSpecified"
                );
                require(delta.amount1() == deltaAfter1, "delta.amount1() is not equal to deltaAfter1");
                require(deltaAfter0 >= 0, "deltaAfter0 is not greater than or equal to 0");
            } else {
                // exact output, 1 for 0
                require(deltaAfter1 <= 0, "deltaAfter1 is not less than or equal to 0");
                require(delta.amount0() == deltaAfter0, "delta.amount0() is not equal to deltaAfter0");
                require(
                    deltaAfter0 <= data.params.amountSpecified,
                    "deltaAfter0 is not less than or equal to data.params.amountSpecified"
                );
            }
        }

        if (deltaAfter0 < 0) {
            settle(data.key.currency0, data.sender, uint256(- deltaAfter0), data.testSettings.settleUsingBurn);
        }
        if (deltaAfter1 < 0) {
            settle(data.key.currency1, data.sender, uint256(- deltaAfter1), data.testSettings.settleUsingBurn);
        }
        if (deltaAfter0 > 0) {
            take(data.key.currency0, data.sender, uint256(deltaAfter0), data.testSettings.takeClaims);
        }
        if (deltaAfter1 > 0) {
            take(data.key.currency1, data.sender, uint256(deltaAfter1), data.testSettings.takeClaims);
        }

        return abi.encode(delta);
    }

    function _validatePureFiData(
        IPoolManager.SwapParams memory params,
        bytes memory pureFiData
    ) internal returns (VerificationPackage memory package) {
        package = super._validatePureFiData(pureFiData);
        if (package.packagetype == 0) return package; // authorized MM
        if (package.packagetype != 2) WrongPureFiPackage.selector.revertWith(package.packagetype);

        IERC20 tokenToSwap = params.zeroForOne ? tokenA : tokenB;

        uint256 amountToSwap = uint(
            params.amountSpecified < 0
                ? - params.amountSpecified
                : params.amountSpecified
        );
        if (package.token != address(tokenToSwap)) InvalidTokenAddress.selector.revertWith();


        if (package.amount < amountToSwap && (params.amountSpecified < 0)) {
            WrongAmountSpecifiedExactInput.selector.revertWith();
        }
    }
}

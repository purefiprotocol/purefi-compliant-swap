// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {BalanceDelta} from "v4-core/types/BalanceDelta.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {IHooks} from "v4-core/interfaces/IHooks.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {LPFeeLibrary} from "v4-core/libraries/LPFeeLibrary.sol";
import {CurrencySettler} from "v4-core/../test/utils/CurrencySettler.sol";
import {StateLibrary} from "v4-core/libraries/StateLibrary.sol";
import {CurrencyLibrary} from "v4-core/types/Currency.sol";
import "v4-core/../test/utils/LiquidityAmounts.sol";
import "v4-core/libraries/TickMath.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {PureFiBaseRouter} from "./PureFiBaseRouter.sol";
import {PureFiMMWhitelist} from "./PureFiMMWhitelist.sol";
import "@purefi/sdk-solidity/interfaces/IPureFiVerifier.sol";

contract PureFiModifyLiquidityRouter is PureFiBaseRouter {
    using Hooks for IHooks;
    using LPFeeLibrary for uint24;
    using PoolIdLibrary for PoolKey;
    using StateLibrary for IPoolManager;

    constructor(
        IPoolManager _poolManager,
        IPureFiVerifier _verifier,
        IERC20 _tokenA,
        IERC20 _tokenB,
        PureFiMMWhitelist _whitelist
    ) PureFiBaseRouter(_poolManager, _verifier, _tokenA, _tokenB, _whitelist) {

    }

    struct CallbackData {
        address sender;
        PoolKey key;
        IPoolManager.ModifyLiquidityParams params;
        bytes hookData;
        bool settleUsingBurn;
        bool takeClaims;
    }


    function modifyLiquidity(
        PoolKey memory key,
        IPoolManager.ModifyLiquidityParams memory params,
        bytes memory hookData
    ) external payable returns (BalanceDelta delta) {
        delta = modifyLiquidity(key, params, hookData, false, false);
    }

    function modifyLiquidity(
        PoolKey memory key,
        IPoolManager.ModifyLiquidityParams memory params,
        bytes memory hookData,
        bool settleUsingBurn,
        bool takeClaims
    ) public
    purified(hookData)
    payable returns (BalanceDelta delta) {
        delta = abi.decode(
            manager.unlock(abi.encode(CallbackData(msg.sender, key, params, hookData, settleUsingBurn, takeClaims))),
            (BalanceDelta)
        );

        uint256 ethBalance = address(this).balance;
        if (ethBalance > 0) {
            CurrencyLibrary.NATIVE.transfer(msg.sender, ethBalance);
        }
    }

    function unlockCallback(bytes calldata rawData) external returns (bytes memory) {
        require(msg.sender == address(manager));

        CallbackData memory data = abi.decode(rawData, (CallbackData));

        (uint128 liquidityBefore,,) = manager.getPositionInfo(
            data.key.toId(), address(this), data.params.tickLower, data.params.tickUpper, data.params.salt
        );

        (BalanceDelta delta,) = manager.modifyLiquidity(data.key, data.params, data.hookData);

        (uint128 liquidityAfter,,) = manager.getPositionInfo(
            data.key.toId(), address(this), data.params.tickLower, data.params.tickUpper, data.params.salt
        );

        (,, int256 delta0) = _fetchBalances(data.key.currency0, data.sender, address(this));
        (,, int256 delta1) = _fetchBalances(data.key.currency1, data.sender, address(this));

        require(
            int128(liquidityBefore) + data.params.liquidityDelta == int128(liquidityAfter), "liquidity change incorrect"
        );

        if (data.params.liquidityDelta < 0) {
            assert(delta0 > 0 || delta1 > 0);
            assert(!(delta0 < 0 || delta1 < 0));
        } else if (data.params.liquidityDelta > 0) {
            assert(delta0 < 0 || delta1 < 0);
            assert(!(delta0 > 0 || delta1 > 0));
        }

        if (delta0 < 0) settle(data.key.currency0, data.sender, uint256(- delta0), data.settleUsingBurn);
        if (delta1 < 0) settle(data.key.currency1, data.sender, uint256(- delta1), data.settleUsingBurn);
        if (delta0 > 0) take(data.key.currency0, data.sender, uint256(delta0), data.takeClaims);
        if (delta1 > 0) take(data.key.currency1, data.sender, uint256(delta1), data.takeClaims);

        return abi.encode(delta);
    }


    function calculateLiquidityDelta(PoolKey memory key, int24 tickLower, int24 tickUpper, uint256 amount0, uint256 amount1) public view returns (uint128) {
        (uint160 sqrtPriceX96,,,) = StateLibrary.getSlot0(manager, key.toId());
        uint128 liquidityDelta = LiquidityAmounts.getLiquidityForAmounts(
            sqrtPriceX96,
            TickMath.getSqrtPriceAtTick(tickLower),
            TickMath.getSqrtPriceAtTick(tickUpper),
            amount0,
            amount1
        );

        return liquidityDelta;
    }

}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {BaseHook} from "v4-periphery/src/base/hooks/BaseHook.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "v4-core/types/BeforeSwapDelta.sol";
import "v4-core/types/BalanceDelta.sol";
import "v4-core/libraries/CustomRevert.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {PureFiMMWhitelist} from "./PureFiMMWhitelist.sol";
import "@purefi/sdk-solidity/interfaces/IPureFiVerifier.sol";

contract VerifierHook is BaseHook, Ownable {
    using BalanceDeltaLibrary for BalanceDelta;
    using CustomRevert for bytes4;

    IPureFiVerifier internal immutable verifier;
    PureFiMMWhitelist internal immutable whitelist;

    IERC20 immutable tokenA;
    IERC20 immutable tokenB;

    mapping(uint256 => uint256) private expectedRuleIDsBitMap;
    mapping(address => bool) private routersWhitelist;
    mapping(address => bool) public quoterWhitelist;

    event RouterWhitelisted(address);
    event RouterDelisted(address);

    event QuoterWhitelisted(address);
    event QuoterDelisted(address);

    error WrongAmountSpecifiedExactInput(uint160 input, uint160 packageAmount);
    error WrongTypeOfPackage(uint160 specified, uint160 expected);
    error WrongTokenAddress(address given, address packageTokenAddress);
    error UnexpectedPackageRule(uint160 specified);
    error SenderPackageMismatch(address msgSender, address packageFrom);

    constructor(
        IPoolManager _poolManager,
        IPureFiVerifier _verifier,
        IERC20 _tokenA,
        IERC20 _tokenB,
        PureFiMMWhitelist _whitelist,
        address _owner
    ) BaseHook(_poolManager) Ownable(_owner) {
        verifier = _verifier;
        tokenA = _tokenA;
        tokenB = _tokenB;
        whitelist = _whitelist;
    }

    modifier purified(bytes calldata purefidata, address sender) {
        if (!routersWhitelist[sender]) _validatePureFiData(purefidata, sender);
        _;
    }

    function getHookPermissions()
    public
    pure
    override
    returns (Hooks.Permissions memory)
    {
        return
            Hooks.Permissions({
            beforeInitialize: true,
            afterInitialize: false,
            beforeAddLiquidity: true,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: true,
            afterRemoveLiquidity: false,
            beforeSwap: true,
            afterSwap: true,
            beforeDonate: true,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }


    function beforeInitialize(
        address,
        PoolKey calldata,
        uint160,
        bytes calldata
    ) external override
    returns (bytes4) {
        return BaseHook.beforeInitialize.selector;
    }


    function beforeAddLiquidity(
        address sender,
        PoolKey calldata,
        IPoolManager.ModifyLiquidityParams calldata,
        bytes calldata purefidata
    ) external override purified(purefidata, sender) returns (bytes4) {
        return BaseHook.beforeAddLiquidity.selector;
    }


    function version() public pure returns (uint32){
        // 000.000.000 - Major.minor.internal
        return 1010001;
    }


    function beforeRemoveLiquidity(
        address sender,
        PoolKey calldata,
        IPoolManager.ModifyLiquidityParams calldata,
        bytes calldata purefidata
    ) external override purified(purefidata, sender) returns (bytes4) {
        return BaseHook.beforeRemoveLiquidity.selector;
    }


    function afterInitialize(address, PoolKey calldata, uint160, int24, bytes calldata)
    external
    override
    returns (bytes4)
    {
        return BaseHook.afterInitialize.selector;
    }

    /// @dev No purified modifier, _validatePureFiData is called as a regular function
    function beforeSwap(
        address sender,
        PoolKey calldata,
        IPoolManager.SwapParams calldata params,
        bytes calldata purefidata
    ) external override returns (bytes4, BeforeSwapDelta, uint24) {
        if (!routersWhitelist[sender] && !quoterWhitelist[sender]) {
            VerificationPackage memory package = _validatePureFiData(purefidata, sender);
            if (package.packagetype != 2) {
                WrongTypeOfPackage.selector.revertWith(package.packagetype, 2);
            }

            IERC20 tokenToSwap = params.zeroForOne ? tokenA : tokenB;
            uint256 amountToSwap = uint(
                params.amountSpecified < 0
                    ? - params.amountSpecified
                    : params.amountSpecified
            );
            if (package.token != address(tokenToSwap)) {
                WrongTokenAddress.selector.revertWith(address(tokenToSwap), package.token);
            }
            if (package.amount < amountToSwap) {
                WrongAmountSpecifiedExactInput.selector.revertWith(uint160(amountToSwap), uint160(package.amount));
            }
        }
        return (BaseHook.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
    }


    function afterSwap(address sender, PoolKey calldata, IPoolManager.SwapParams calldata params, BalanceDelta delta, bytes calldata pureFiData)
    external
    override
    returns (bytes4, int128)
    {
        if (params.amountSpecified > 0 && !quoterWhitelist[sender]) {
            (,, bytes memory encodedPackage) = abi.decode(pureFiData, (uint64, bytes, bytes));
            VerificationPackage memory package = verifier.decodePureFiPackage(encodedPackage);
            int128 amount;
            if (params.zeroForOne) {
                amount = delta.amount0();
            } else {
                amount = delta.amount1();
            }

            uint256 amountIn = uint128(amount > 0 ? amount : - amount);

            if (package.amount < amountIn) {
                WrongAmountSpecifiedExactInput.selector.revertWith(uint160(amountIn), uint160(package.amount));
            }
        }

        return (this.afterSwap.selector, 0);
    }

    function beforeDonate(
        address sender,
        PoolKey calldata,
        uint256,
        uint256,
        bytes calldata pureFiData
    ) external override purified(pureFiData, sender) returns (bytes4) {
        return BaseHook.beforeDonate.selector;
    }

    function enlistRouter(address router) external onlyOwner {
        routersWhitelist[router] = true;
        emit RouterWhitelisted(router);
    }

    function delistRouter(address router) external onlyOwner {
        delete routersWhitelist[router];
        emit RouterDelisted(router);
    }

    function enlistQuoter(address quoter) external onlyOwner {
        quoterWhitelist[quoter] = true;
        emit QuoterWhitelisted(quoter);
    }

    function delistQuoter(address quoter) external onlyOwner {
        delete quoterWhitelist[quoter];
        emit QuoterDelisted(quoter);
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


    function _validatePureFiData(
        bytes calldata pureFiData,
        address sender
    ) internal returns (VerificationPackage memory package) {
        package = verifier.validateAndDecode(pureFiData);
        if (whitelist.isAuthorized(package.from)) return package;
        if (!isExpectedRule(package.rule)) {
            UnexpectedPackageRule.selector.revertWith(uint160(package.rule));
        }
        if (package.from != sender) {
            SenderPackageMismatch.selector.revertWith(sender, package.from);
        }
    }
}

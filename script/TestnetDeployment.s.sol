// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolManager} from "v4-core/PoolManager.sol";
import {IHooks} from "v4-core/interfaces/IHooks.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {PoolModifyLiquidityTest} from "v4-core/test/PoolModifyLiquidityTest.sol";
import {CurrencyLibrary, Currency} from "v4-core/types/Currency.sol";
import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {PoolSwapTest} from "v4-core/test/PoolSwapTest.sol";
import {TickMath} from "v4-core/libraries/TickMath.sol";
import {PureFiSwapRouter} from "../src/PureFiSwapRouter.sol";
import {VerifierHook} from "../src/VerifierHook.sol";
import {PureFiMMWhitelist} from "../src/PureFiMMWhitelist.sol";
import "../src/PureFiModifyLiquidityRouter.sol";
import "./mock/MockCoin.sol";
import "./utils/HookMiner.sol";
import "@purefi/sdk-solidity/interfaces/IPureFiVerifier.sol";

import {CreateFactory} from "../src/utils/CreateFactory.sol";
import "v4-periphery/src/lens/Quoter.sol";

contract TestnetDeployment is Script {
    using CurrencyLibrary for Currency;

    // slippage tolerance to allow for unlimited price impact
    uint160 public constant MIN_PRICE_LIMIT = TickMath.MIN_SQRT_PRICE + 1;
    uint160 public constant MAX_PRICE_LIMIT = TickMath.MAX_SQRT_PRICE - 1;
    uint256 constant AMOUNT = 10e9;
    uint[] public expectedRuleIDs = [1, 631, 777, 778, 77];
    uint160 public constant startingPrice = 79228162514264337593543950336;
    uint24 public constant swapFee = 100;
    int24 public constant tickSpacing = 10;

    function run() external {
        address pureFiVerifier = 0x33962E4b101dd947ef35200c151B0fa56Fb6670E;
        vm.startBroadcast();

        //(MockCoin tokenA, MockCoin tokenB, IPoolManager manager,) = deployTokensAndPoolManager();

        //mint some balance
       // tokenA.mint(msg.sender, AMOUNT);
       // tokenB.mint(msg.sender, AMOUNT);

        MockCoin tokenA = MockCoin(0xb97CBF42B59Ab198c76876C380D47b6734f9fe2B);
        MockCoin tokenB = MockCoin(0x8B2B5c60A45E1b3A32f6431689b94BC3E87738C5);
        IPoolManager manager = IPoolManager(0x2F81C3A3BbB6580Ca9B588Cc8Adf5590aBe7a7B7);

        (address pureFiModifyLiquidityRouter, address pureFiSwapRouter,address token0,address token1,address verifierHook) = deployPureFiRouterAndHook(pureFiVerifier, tokenA, tokenB, manager);

        vm.stopBroadcast();
    }

    function deployVerifierHook(IPoolManager manager, address _pureFiVerifier, MockCoin token0, MockCoin token1, address PureFiRouterWhitelist) internal returns (VerifierHook){
        address deployedHook;
        {
            CreateFactory createFactory = new CreateFactory();
            console.log("CreateFactory:", address(createFactory));
            // Deploy the hook to an address with the correct flags
            uint160 flags = uint160(
                Hooks.BEFORE_INITIALIZE_FLAG |
                Hooks.BEFORE_ADD_LIQUIDITY_FLAG |
                Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG |
                Hooks.BEFORE_SWAP_FLAG |
                Hooks.BEFORE_DONATE_FLAG |
                Hooks.AFTER_SWAP_FLAG
            );

            console.log("msg.sender:", msg.sender);
            console.log("address(this):", address(this));

            (address hookAddress, bytes32 salt) = HookMiner.find(
                address(createFactory),
                flags,
                type(VerifierHook).creationCode,
                abi.encode(
                    manager,
                    _pureFiVerifier,
                    address(token0),
                    address(token1),
                    PureFiRouterWhitelist,
                    address(msg.sender)
                )
            );

            bytes memory creationCodeWithArgs = abi.encodePacked(type(VerifierHook).creationCode,
                abi.encode(
                    address(manager),
                    _pureFiVerifier,
                    address(token0),
                    address(token1),
                    PureFiRouterWhitelist,
                    address(msg.sender)
                ));

            deployedHook = createFactory.deploy(salt, creationCodeWithArgs);

            require(deployedHook == hookAddress, "hook address mismatch");
            console.log("VerifierHook:", deployedHook);
            console.log("CreateFactory:", address(createFactory));
        }
        VerifierHook verifierHook = VerifierHook(deployedHook);

        verifierHook.setExpectedRuleIds(expectedRuleIDs);

        return verifierHook;
    }

    function deployPureFiRouterAndHook(address pureFiVerifier, MockCoin _token0, MockCoin _token1, IPoolManager manager) internal returns (address, address, address, address, address) {
        IPureFiVerifier PureFiVerifier = IPureFiVerifier(pureFiVerifier);
        PureFiMMWhitelist pureFiMMWhitelist = new PureFiMMWhitelist(PureFiVerifier);
        console.log("PureFiVerifier:", address(PureFiVerifier));
        console.log("PureFiMMWhitelist:", address(pureFiMMWhitelist));

        // sort the tokens!
        address token0 = address(uint160(address(_token1)) < uint160(address(_token0)) ? _token1 : _token0);
        address token1 = address(uint160(address(_token1)) < uint160(address(_token0)) ? _token0 : _token1);

        PureFiModifyLiquidityRouter pureFiModifyLiquidityRouter = new PureFiModifyLiquidityRouter(
            manager,
            IPureFiVerifier(PureFiVerifier),
            IERC20(address(token0)),
            IERC20(address(token1)),
            (pureFiMMWhitelist)
        );

        console.log("PureFiModifyLiquidityRouter:", address(pureFiModifyLiquidityRouter));

        PureFiSwapRouter pureFiSwapRouter = new PureFiSwapRouter(
            manager,
            IPureFiVerifier(PureFiVerifier),
            IERC20(address(token0)),
            IERC20(address(token1)),
            (pureFiMMWhitelist)
        );
        console.log("PureFiSwapRouter:", address(pureFiSwapRouter));

        address[2] memory toApprove = [
                        address(pureFiModifyLiquidityRouter),
                        address(pureFiSwapRouter)
            ];

        for (uint256 i = 0; i < toApprove.length; i++) {
            MockCoin(token0).approve(toApprove[i], type(uint256).max);
            MockCoin(token1).approve(toApprove[i], type(uint256).max);
        }


        pureFiModifyLiquidityRouter.setExpectedRuleIds(expectedRuleIDs);
        pureFiSwapRouter.setExpectedRuleIds(expectedRuleIDs);

        VerifierHook verifierHook = deployVerifierHook(
            manager,
            address(PureFiVerifier),
            MockCoin(token0),
            MockCoin(token1),
            address(pureFiMMWhitelist)
        );

        verifierHook.enlistRouter(address(pureFiModifyLiquidityRouter));
        verifierHook.enlistRouter(address(pureFiSwapRouter));

        PoolKey memory pool = PoolKey({
            currency0: Currency.wrap(token0),
            currency1: Currency.wrap(token1),
            fee: swapFee,
            tickSpacing: tickSpacing,
            hooks: IHooks(address(verifierHook))
        });

        PoolId id = PoolIdLibrary.toId(pool);
        bytes32 idBytes = PoolId.unwrap(id);

        console.log("PureFi Pool ID Below");
        console.logBytes32(bytes32(idBytes));

        manager.initialize(pool, startingPrice, abi.encode(block.timestamp));

        return (address(pureFiModifyLiquidityRouter), address(pureFiSwapRouter), address(token0), address(token1), address(verifierHook));
    }


    function makeLiquidityMakeSwapWithoutHook(MockCoin Aur, MockCoin Zel, IPoolManager manager, PoolKey memory pool) internal {
        bytes memory hookData = new bytes(0);

        PoolSwapTest swapRouter = new PoolSwapTest(manager);
        console.log("swapRouter:", address(swapRouter));

        PoolModifyLiquidityTest lpRouter = new PoolModifyLiquidityTest(manager);

        console.log("lpRouter:", address(lpRouter));
        //approve to manager
        Aur.approve(address(manager), UINT256_MAX);
        Zel.approve(address(manager), UINT256_MAX);

        Aur.approve(address(swapRouter), UINT256_MAX);
        Zel.approve(address(swapRouter), UINT256_MAX);

        Aur.approve(address(lpRouter), UINT256_MAX);
        Zel.approve(address(lpRouter), UINT256_MAX);

        lpRouter.modifyLiquidity(pool, IPoolManager.ModifyLiquidityParams(- 600, 600, 10_000e18, 0x0), hookData);

        bool zeroForOne = true;

        IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
            zeroForOne: zeroForOne,
            amountSpecified: 10e18,
            sqrtPriceLimitX96: zeroForOne ? MIN_PRICE_LIMIT : MAX_PRICE_LIMIT // unlimited impact
        });

        PoolSwapTest.TestSettings memory testSettings = PoolSwapTest.TestSettings({takeClaims: true, settleUsingBurn: false});

        swapRouter.swap(pool, params, testSettings, hookData);
    }

    function deployTokensAndPoolManager() internal returns (MockCoin, MockCoin, IPoolManager, PoolKey memory){
        // deploy pool manager
        IPoolManager manager = IPoolManager(new PoolManager(500_000));
        console.log("PoolManager:", address(manager));

//        MockCoin Aur = MockCoin(0xa948e9A874a62430f4c2F74C4D7bff393Ce7F234);
//        MockCoin Zel = MockCoin(0x8800172fAC306510d5d3E116Af793DCA7BA73c4C);
        // deploy token0
        MockCoin tokenA = new MockCoin();

        tokenA.initialize("Tether USD", "USDT");
        console.log("USDT:", address(tokenA));

        // deploy token
        MockCoin tokenB = new MockCoin();

        tokenB.initialize("USD Coin", "USDC");
        console.log("USDC:", address(tokenB));

        // sort the tokens!
        address token0 = address(uint160(address(tokenB)) < uint160(address(tokenA)) ? tokenB : tokenA);
        address token1 = address(uint160(address(tokenB)) < uint160(address(tokenA)) ? tokenA : tokenB);

        bytes memory hookData = abi.encode(0);

        PoolKey memory pool = PoolKey({
            currency0: Currency.wrap(token0),
            currency1: Currency.wrap(token1),
            fee: swapFee,
            tickSpacing: tickSpacing,
            hooks: IHooks(address(0))
        });

        //Turn the Pool into an ID so you can use it for modifying positions, swapping, etc.
        PoolId id = PoolIdLibrary.toId(pool);
        bytes32 idBytes = PoolId.unwrap(id);

        console.log("Pool ID Below");
        console.logBytes32(bytes32(idBytes));
        manager.initialize(pool, startingPrice, hookData);

        return (tokenA, tokenB, manager, pool);
    }

    function pureFiModifyLiquidityAndSwap(address pureFiModifyLiquidityRouter, address pureFiSwapRouter, MockCoin token0, MockCoin token1, address verifierHook) internal {
        // make approve to lp router
        token0.approve(address(pureFiModifyLiquidityRouter), UINT256_MAX);
        token1.approve(address(pureFiModifyLiquidityRouter), UINT256_MAX);

        // make approve to swap router
        token0.approve(address(pureFiSwapRouter), UINT256_MAX);
        token1.approve(address(pureFiSwapRouter), UINT256_MAX);

        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(address(token0)),
            currency1: Currency.wrap(address(token1)),
            fee: swapFee,
            tickSpacing: tickSpacing,
            hooks: IHooks(address(verifierHook))
        });

        IPoolManager.ModifyLiquidityParams memory liquidityParams = IPoolManager.ModifyLiquidityParams({
            tickLower: - 60,
            tickUpper: 60,
            liquidityDelta: 10 ether,
            salt: bytes32(0)
        });

        PureFiSwapRouter.TestSettings memory testSettings = PureFiSwapRouter.TestSettings({takeClaims: true, settleUsingBurn: false});

        PureFiModifyLiquidityRouter(pureFiModifyLiquidityRouter).modifyLiquidity(
            key,
            liquidityParams,
            abi.encode(bytes32(0))
        );

        IPoolManager.SwapParams memory swapParams = IPoolManager.SwapParams({
            zeroForOne: false,
            amountSpecified: - 0.1 ether,
            sqrtPriceLimitX96: TickMath.MAX_SQRT_PRICE - 1
        });

        PureFiSwapRouter(pureFiSwapRouter).swap(key, swapParams, testSettings, abi.encode(bytes32(0)));
    }
}
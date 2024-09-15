// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";

import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";

import {IHooks} from "v4-core/interfaces/IHooks.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {TickMath} from "v4-core/libraries/TickMath.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {BalanceDelta} from "v4-core/types/BalanceDelta.sol";
import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {CurrencyLibrary, Currency} from "v4-core/types/Currency.sol";
import {PoolSwapTest} from "v4-core/test/PoolSwapTest.sol";
import {Deployers} from "v4-core/../test/utils/Deployers.sol";
import {VerifierHook} from "../src/VerifierHook.sol";
import {HookMiner} from "../script/utils/HookMiner.sol";
import {TestERC20} from "v4-core/test/TestERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {console2} from "forge-std/console2.sol";

import {PureFiIssuerRegistry} from "@purefi/sdk-solidity/PureFiIssuerRegistry.sol";
import {PureFiSwapRouter} from "../src/PureFiSwapRouter.sol";
import {ParamStorage} from "@purefi/sdk-solidity/utils/ParamStorage.sol";
import {PureFiMMWhitelist} from "../src/PureFiMMWhitelist.sol";
import "v4-core/../test/utils/Constants.sol";
import "@purefi/sdk-solidity/libraries/SignLib.sol";
import "@purefi/sdk-solidity/interfaces/IPureFiVerifier.sol";
import {PureFiModifyLiquidityRouter} from "../src/PureFiModifyLiquidityRouter.sol";

contract VerifierHookTest is Test, Deployers, SignLib {
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;

    PoolId poolId;
    VerifierHook verifierHook;
    PureFiModifyLiquidityRouter pureFiModifyLiquidityRouter;
    PureFiSwapRouter pureFiSwapRouter;
    PureFiMMWhitelist pureFiWhitelist;

    bytes[6] PUREFI_DATA = [
    bytes(hex"0000000000000000000000000000000000000000000000000000000066853363000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000041ece078e80bb00a56306e9d727e67fb2a167386763fe8d6ce4e77602d159d01242963879ba46cd64ccf1d38f64e48c4daea1973bffa9654dc0d827cb9c057b29e1c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000003090000000000000000000000000000000028b2fe1538644e3e8dab9d4a5d9d3e06000000000000000000000000979379a368af8ee40f6ef47e08aa2f976da1c9ed000000000000000000000000aa8e41504e42cd700a7a9e5dbeedfabf4da318d7"),
    hex"00000000000000000000000000000000000000000000000000000000666c1e83000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000004131761e992c1b692f2a86fe9ef47bbe3ff4f3ab30069be1f497dc18977b2eca184fc5d01c8c731b614690d0b8adf6c1ad29c231d43948f5b798d458f2e408947e1c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000030900000000000000000000000000000000edb77c63aa8c48d89a14d4f48773b462000000000000000000000000979379a368af8ee40f6ef47e08aa2f976da1c9ed000000000000000000000000361c5e6d78ca904634ebc47cac6060e226a5c270",
    hex"00000000000000000000000000000000000000000000000000000000666c1ead000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000000414df93ccb21d67e7ced38d08550274929555aaa0563a412a5a3d9113844de871d7f3ed7e7f95d4b4649b9bdcc58a50a22b7016e8ecdeb398f25b8c44d52eeecb31c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000030900000000000000000000000000000000f1a6317e817b42baab930018875f192a000000000000000000000000979379a368af8ee40f6ef47e08aa2f976da1c9ed000000000000000000000000361c5e6d78ca904634ebc47cac6060e226a5c270",
    hex"00000000000000000000000000000000000000000000000000000000666c1ed8000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000041901892d7b88873470fadca3a57892a9e0e79bf78005f19167bf4cacd0455bf9f73c1a792e8e10150fd50d098fdee0a913008831cc1a87aa03dd17ffce5977c0a1c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000030900000000000000000000000000000000c3d12d02293f41088f633e092fbfedcf000000000000000000000000979379a368af8ee40f6ef47e08aa2f976da1c9ed000000000000000000000000361c5e6d78ca904634ebc47cac6060e226a5c270",
    hex"00000000000000000000000000000000000000000000000000000000666c2330000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000041a1549723f73227bc38b6f56d5214d8e370b510c004d8ed7f0ce155d29ff3916d269cb16ff9f0c091a0af38fcde9824c015c12d261f12cdb117c02fa7a2a5cbab1b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000027700000000000000000000000000000000002650b010b24a5cba1883a7462117b2000000000000000000000000979379a368af8ee40f6ef47e08aa2f976da1c9ed000000000000000000000000c6e6feec46a75cb7584d0b8798b13593984a36690000000000000000000000001f3eb96662cc1abfad02d32a37a24abce7263c4a0000000000000000000000000000000000000000000000000de0b6b3a7640000",
    hex"00000000000000000000000000000000000000000000000000000000666c2a42000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000041a110cf86a3d9df260b71a068064201c0ff60d51f81a7cd4e425156b44ef381fd4519fb4d71eebe77f6c76f315dd0f370c84dd791a10c765fbca049a2c95b6bc51c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000002770000000000000000000000000000000081734a147ddd4afaa485ed5f81d46a09000000000000000000000000ddd9cfdcc836e38418774d1155cb0722fa63854a000000000000000000000000747b3086c31b43f63e2bb1588d559af2efd75e940000000000000000000000001f3eb96662cc1abfad02d32a37a24abce7263c4a000000000000000000000000000000000000000000000000000000000000000a"
    ];
    uint[] expectedRuleIDs = [1, 631, 777];

    // test 11155111 0x7eeDf8da787eC15049368150B2D4AbE792B9b471 / prod 1 0xBa8bFC223Cb1BCDcdd042494FF2C07b167DDC6CA
    address verifier = 0x7eeDf8da787eC15049368150B2D4AbE792B9b471;
    address EOA = 0x979379a368aF8eE40f6eF47E08aA2f976da1c9eD;
    address MM = 0xDDd9CFDCC836E38418774d1155cB0722fA63854a;

    error WrongIssuer();
    error WrongTimestamp();
    error WrongLength();
    error WrongTo();

    // set Verifier address from Mainnet ✅
    // deploy fresh pool manager ✅
    // deploy routers ✅
    // deploy PureFiModifyLiquidityRouter ✅
    // deploy PureFiSwapRouter ✅
    // deployMintAndApprove2Currencies ✅
    // deploy hook ✅
    // initalize pool ✅
    // add liquidity ✅
    // swap ✅

    function setUp() public {
        vm.deal(EOA, 500 ether);
        vm.startPrank(EOA);

        console.log("Starting setup..");

        // creates the pool manager, utility routers, and test tokens
        Deployers.deployFreshManagerAndRouters();

        Deployers.deployMintAndApprove2Currencies();
        console2.log("Basic test contracts deployed");

        IPureFiVerifier pureFiVerifier = IPureFiVerifier(verifier);
        pureFiWhitelist = new PureFiMMWhitelist(pureFiVerifier);

        console2.log("Whitelist address: ");
        console2.log(address(pureFiWhitelist));

        IERC20 tokenZero = IERC20(abi.decode(abi.encode((currency0)), (address)));
        IERC20 tokenOne = IERC20(abi.decode(abi.encode((currency1)), (address)));

        pureFiModifyLiquidityRouter = new PureFiModifyLiquidityRouter(
            IPoolManager(address(manager)),
            IPureFiVerifier(verifier),
            tokenZero,
            tokenOne,
            pureFiWhitelist
        );

        console2.log("pureFiModifyLiquidityRouter address:");
        console2.log(address(pureFiModifyLiquidityRouter));

        pureFiSwapRouter = new PureFiSwapRouter(
            IPoolManager(address(manager)),
            IPureFiVerifier(verifier),
            tokenZero,
            tokenOne,
            pureFiWhitelist
        );

        console2.log("pureFiSwapRouter address:");
        console2.log(address(pureFiSwapRouter));

        console2.log("Approving tokens from EOA to Routers:");

        address[2] memory toApprove = [
                        address(pureFiModifyLiquidityRouter),
                        address(pureFiSwapRouter)
            ];


        for (uint256 i = 0; i < toApprove.length; i++) {
            tokenZero.approve(toApprove[i], type(uint256).max);
            tokenOne.approve(toApprove[i], type(uint256).max);
        }

        vm.stopPrank();

        console2.log("Balances of test contract:");
        console2.log(tokenZero.balanceOf(address(this)));
        console2.log(tokenOne.balanceOf(address(this)));

        console2.log("Balances of EOA:");
        console2.log(tokenZero.balanceOf(EOA));
        console2.log(tokenOne.balanceOf(EOA));

        console2.log("Balances of MM:");
        console2.log(tokenZero.balanceOf(MM));
        console2.log(tokenOne.balanceOf(MM));

        console2.log("Sending currency to EOA...");
        tokenZero.transfer(EOA, type(uint256).max / 1000);
        tokenOne.transfer(EOA, type(uint256).max / 1000);

        console2.log("Sending currency to MM...");
        tokenZero.transfer(MM, 1e18);
        tokenOne.transfer(MM, 1e18);

        console2.log("New balances of EOA:");
        console2.log(tokenZero.balanceOf(EOA));
        console2.log(tokenOne.balanceOf(EOA));

        console2.log("New balances of MM:");
        console2.log(tokenZero.balanceOf(MM));
        console2.log(tokenOne.balanceOf(MM));

        vm.startPrank(EOA);

        console2.log("Deploying the hook...");

        // Deploy the hook to an address with the correct flags
        uint160 flags = uint160(
            Hooks.BEFORE_INITIALIZE_FLAG |
            Hooks.BEFORE_SWAP_FLAG |
            Hooks.BEFORE_ADD_LIQUIDITY_FLAG |
            Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG |
            Hooks.BEFORE_DONATE_FLAG
        );

        // DO NOT FORGET TO SET ARGUMENTS IF YOU UPDATE THE HOOK
        (address hookAddress, bytes32 salt) = HookMiner.find(
            EOA, // SET VALID DEPLOYER
            flags,
            type(VerifierHook).creationCode,
            abi.encode(
                address(manager),
                verifier,
                address(tokenZero),
                address(tokenOne),
                pureFiWhitelist
            )
        );

        verifierHook = new VerifierHook{salt: salt}(
            manager,
            (pureFiVerifier),
            tokenZero,
            tokenOne,
            (pureFiWhitelist),
            msg.sender
        );

        require(
            address(verifierHook) == hookAddress,
            "CounterTest: hook address mismatch"
        );

        console2.log("Hook Address:");
        console2.log(hookAddress);

        console2.log("This (test contract) Address:");
        console2.log(address(this));

        console2.log("Setting expected rule IDs and enlisting routers!");

        pureFiModifyLiquidityRouter.setExpectedRuleIds(expectedRuleIDs);
        pureFiSwapRouter.setExpectedRuleIds(expectedRuleIDs);

        verifierHook.setExpectedRuleIds(expectedRuleIDs);
        verifierHook.enlistRouter(address(pureFiModifyLiquidityRouter));
        verifierHook.enlistRouter(address(pureFiSwapRouter));

        // Create the pool

        key = PoolKey({
            currency0: currency0,
            currency1: currency1,
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(0xad716E4c709006C3D050ae42E980a22d070c6AA0)
        });
//        key.currency0 = currency0;
//        key.currency1 = currency1;
//        key.fee = 3000;
//        key.tickSpacing = 60;
//        key.hooks = IHooks(0xad716E4c709006C3D050ae42E980a22d070c6AA0);

        poolId = key.toId();

        console2.log("Start initializing the pool..");

        // Uncomment to simulate verifier decoding & validation
        // _validateAndDecode(PUREFI_DATA[0], issuerRegistry, hookAddress);

        manager.initialize(key, Constants.SQRT_PRICE_1_1(), PUREFI_DATA[0]);

        console2.log("Start modifying liquidity..");

        // Provide liquidity to the pool
        pureFiModifyLiquidityRouter.modifyLiquidity(
            key,
            IPoolManager.ModifyLiquidityParams(- 60, 60, 10 ether),
            PUREFI_DATA[1]
        );
        pureFiModifyLiquidityRouter.modifyLiquidity(
            key,
            IPoolManager.ModifyLiquidityParams(- 120, 120, 10 ether),
            PUREFI_DATA[2]
        );
        pureFiModifyLiquidityRouter.modifyLiquidity(
            key,
            IPoolManager.ModifyLiquidityParams(
                TickMath.minUsableTick(60),
                TickMath.maxUsableTick(60),
                10 ether
            ),
            PUREFI_DATA[3]
        );

        console2.log("Setup completed!");
    }

    function testBeforeSwapHook() public {
        bool zeroForOne = true;
        int256 amountSpecified = - 1e18; // negative number indicates exact input swap!
        uint160 sqrtPriceLimitX96 = 1e20; // TODO: SET!
        BalanceDelta swapDelta = pureFiSwapRouter.swap(
            key,
            IPoolManager.SwapParams(zeroForOne, amountSpecified, sqrtPriceLimitX96),
            PUREFI_DATA[4]
        );

        assertEq(int256(swapDelta.amount0()), amountSpecified);
        console2.log("Received amount after swap:");
        console2.log(swapDelta.amount1());
    }

    function testBeforeSwapHookForAuthorizedMarketMaker() public {
        vm.startPrank(MM);
        bool zeroForOne = true;
        int256 amountSpecified = - 1e18; // negative number indicates exact input swap!
        uint160 sqrtPriceLimitX96 = 1e20; // TODO: SET!

        // CHANGE currency0 IF zeroForOne IS CHANGED
        address token0 = Currency.unwrap(currency0);
        IERC20(token0).approve(address(pureFiSwapRouter), 1e18);

        vm.expectRevert();
        pureFiSwapRouter.swap(
            key,
            IPoolManager.SwapParams(zeroForOne, amountSpecified, sqrtPriceLimitX96),
            ZERO_BYTES
        );

        pureFiWhitelist.enlistMe(PUREFI_DATA[5]);

        BalanceDelta swapDelta = pureFiSwapRouter.swap(
            key,
            IPoolManager.SwapParams(zeroForOne, amountSpecified, sqrtPriceLimitX96),
            ZERO_BYTES
        );

        assertEq(int256(swapDelta.amount0()), amountSpecified);
        console2.log("Received amount after Market Maker's swap:");
        console2.log(swapDelta.amount1());
    }

    // TODO: for testing purposes, to be removed later
    function _validateAndDecode(
        bytes memory _purefidata, address issuerRegistry, address hook
    ) private returns (VerificationPackage memory, bytes memory) {

        console2.log("_validateAndDecode start, package:");
        console2.logBytes(_purefidata);

        //min package size = 8+65 +1+32
        if (
            _purefidata.length < (8 + 65 + 1 + 32)
        ) revert WrongLength();

        console2.log("7");

        (uint64 timestamp, bytes memory signature, bytes memory encodedpackage)
        = abi.decode(_purefidata, (uint64, bytes, bytes));

        console2.log("8");

        //get issuer address from the signature
        address issuer = recoverSigner(
            keccak256(abi.encodePacked(timestamp, encodedpackage)),
            signature
        );
        console2.log("9");

        if (!
            PureFiIssuerRegistry(issuerRegistry)
            .isValidIssuer(issuer)
        ) revert WrongIssuer();
        console2.log("10");

        // grace time recommended:
        // Ethereum: 10 min
        // BSC: 3 min
        if (
            timestamp + 600 <= block.timestamp
        ) revert WrongTimestamp();
        console2.log("11");

        // check for the caller contract to match package data
        VerificationPackage memory package = _decodePureFiPackage(
            encodedpackage
        );
        console2.log("12");

        // check for package re-use
        // require(
        //   requestsProcessed[package.session] == 0,
        //   "PureFi Verifier : This package is already processed by verifier."
        // );
        console2.log("before caller check");
        //check that a contract caller matches the data in the package
        require(
            (package.to == hook) ||
            ((package.packagetype == 2 || package.packagetype == 3) &&
                package.from == msg.sender),
            "PureFi Verifier : Contract caller invalid"
        );
        console2.log("after caller check");

        //store requestID to avoid replay
        // requestsProcessed[package.session] = block.timestamp;
        // emit PureFiPackageProcessed(msg.sender, package.session);

        return (package, encodedpackage);
    }

    // TODO: for testing purposes, to be removed later
    function _decodePureFiPackage(
        bytes memory _purefipackage
    ) private pure returns (VerificationPackage memory package) {
        uint8 packagetype = uint8(_purefipackage[31]);
        if (packagetype == 1) {
            (
                ,
                uint256 ruleID,
                uint256 sessionID,
                address sender,
                address receiver
            ) = abi.decode(
                _purefipackage,
                (uint8, uint256, uint256, address, address)
            );
            package = VerificationPackage({
                packagetype: 1,
                session: sessionID,
                rule: ruleID,
                from: sender,
                to: receiver,
                token: address(0),
                amount: 0,
                payload: ""
            });
        } else if (packagetype == 2) {
            (
                ,
                uint256 ruleID,
                uint256 sessionID,
                address sender,
                address receiver,
                address token_addr,
                uint256 tx_amount
            ) = abi.decode(
                _purefipackage,
                (
                    uint8,
                    uint256,
                    uint256,
                    address,
                    address,
                    address,
                    uint256
                )
            );
            package = VerificationPackage({
                packagetype: 2,
                rule: ruleID,
                session: sessionID,
                from: sender,
                to: receiver,
                token: token_addr,
                amount: tx_amount,
                payload: ""
            });
        } else if (packagetype == 3) {
            (
                ,
                uint256 ruleID,
                uint256 sessionID,
                address sender,
                address receiver,
                bytes memory payload_data
            ) = abi.decode(
                _purefipackage,
                (uint8, uint256, uint256, address, address, bytes)
            );
            package = VerificationPackage({
                packagetype: 3,
                rule: ruleID,
                session: sessionID,
                from: sender,
                to: receiver,
                token: address(0),
                amount: 0,
                payload: payload_data
            });
        } else {
            require(false, "PureFiVerifier : invalid package data");
        }
    }
}

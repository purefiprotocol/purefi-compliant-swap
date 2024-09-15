// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/Create2.sol";

contract CreateFactory {
    event Deploy(address addr);

    function deploy(bytes32 salt, bytes memory bytecode) external returns(address addr) {
        addr = Create2.deploy(0, salt, bytecode);
        emit Deploy(addr);
    }

    function computeAddress(bytes32 salt, bytes32 bytecodeHash) public view returns (address) {
        return Create2.computeAddress(salt, bytecodeHash, address(this));
    }
}
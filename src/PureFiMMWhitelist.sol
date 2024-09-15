// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@purefi/sdk-solidity/interfaces/IPureFiVerifier.sol";

contract PureFiMMWhitelist is AccessControl {
    bytes32 public constant ISSUER = keccak256("ISSUER");

    mapping(address => bool) public authorizedMarketMakers;
    IPureFiVerifier verifier;

    event AddressEnlisted(address);
    event AddressDelisted(address);

    constructor(IPureFiVerifier _verifier) {
        verifier = _verifier;
    }

    modifier purified(bytes calldata pureFiData) {
        _validatePureFiData(pureFiData);
        _;
    }

    function isAuthorized(address user) external view returns (bool) {
        return authorizedMarketMakers[user];
    }

    function enlistMe(bytes calldata pureFiData) external purified(pureFiData) {
        authorizedMarketMakers[msg.sender] = true;
        emit AddressEnlisted(msg.sender);
    }

    function delistMe(bytes calldata pureFiData) external purified(pureFiData) {
        delete authorizedMarketMakers[msg.sender];
        emit AddressDelisted(msg.sender);
    }

    function delist(address user) external {
        require(hasRole(ISSUER, msg.sender));
        delete authorizedMarketMakers[user];
        emit AddressDelisted(user);
    }

    function _validatePureFiData(
        bytes calldata pureFiData
    ) internal {
        VerificationPackage memory package = verifier.validateAndDecode(pureFiData);
        require(package.from == msg.sender, "Wrong sender");
    }
}

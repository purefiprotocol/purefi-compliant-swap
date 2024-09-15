// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {ERC20BurnableUpgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20BurnableUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";

contract MockCoin is ERC20BurnableUpgradeable, AccessControlUpgradeable
{
    function initialize(string memory name, string memory symbol) initializer external {
        __AccessControl_init_unchained();
        __ERC20_init_unchained(name, symbol);
        __ERC20Burnable_init_unchained();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function mint(address to, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _mint(to, amount);
    }

    function burn(address to, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _burn(to, amount);
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }
}
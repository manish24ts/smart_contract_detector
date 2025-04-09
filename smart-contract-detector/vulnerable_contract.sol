// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No funds");

        // Vulnerable: sending Ether before setting balance to zero
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Failed to send Ether");

        balances[msg.sender] = 0;
    }

    // Dangerous fallback, can be abused
    fallback() external payable {}

    // No owner restriction – anyone can destroy the contract
    function destroy() public {
        selfdestruct(payable(msg.sender));
    }
}

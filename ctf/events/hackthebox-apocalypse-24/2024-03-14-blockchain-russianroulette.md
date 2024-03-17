---
layout: post
title: "blockchain russianroulette"
date: 2024-03-14 17:18:49 -0700
categories: ctfs
description: The "Russian Roulette" challenge in the blockchain category involves interacting with a smart contract deployed on the Ethereum blockchain. Participants utilize a provided NC endpoint to authenticate using a private key and execute functions with a target address. The challenge objective is to trigger the flag function in the contract by meeting specific conditions, such as a blockchain count divisible by ten.
parent: HackTheBox - Apocalypse '24
grand_parent: CTF Events
event: "hackthebox-apocalypse"
tags:
- "blockchain"
- "smart contract"
- "Ethereum"
- "function execution"
---

## Russian Roulette - Blockchain Challenge
The "Russian Roulette" challenge tasks participants with interacting with a smart contract deployed on the Ethereum blockchain. Participants are provided with an NC endpoint to generate connection information, including a private key for authentication and a target address for function execution within the contract.

### Understanding the Challenge Objective:
The challenge source code indicates that accessing the flag function in the contract requires meeting specific conditions. Specifically, the flag becomes available when the blockchain count is a number that, when multiplied divided (modulus) by 10, is equal to 7. Participants must run a specific function in the contract at least 70 times to ensure the condition is met and trigger the flag function.
```c
pragma solidity 0.8.23;

contract RussianRoulette {

    constructor() payable {
        // i need more bullets
    }

    function pullTrigger() public returns (string memory) {
        if (uint256(blockhash(block.number - 1)) % 10 == 7) {
            selfdestruct(payable(msg.sender)); //         } else {
                return "im SAFU ... for now";
            }
    }
}
```

### Leveraging Cast for Interaction:
To interact with the smart contract and execute the necessary function multiple times, participants utilize Cast, a function provided by [Foundry-rs](https://github.com/foundry-rs/foundry). Foundry-rs offers a suite of tools for interacting with and creating contracts on the Ethereum blockchain. Participants leverage Cast to automate the execution of the required function, incrementing the blockchain count with each iteration until the condition for accessing the flag function is met.

```sh
 8385  for i in {1..70}; do cast send --rpc-url "http://83.136.249.138:42431/" --private-key "<generated from NC endpoint>" <contract address generated from NC endpoint> "pullTrigger()"\n; done
```

### Conclusion:
The "Russian Roulette" challenge introduces participants to the complexities of interacting with smart contracts on the Ethereum blockchain. By leveraging provided tools and understanding the contract's conditions, participants can automate the execution of functions to achieve their objectives. This experience underscores the importance of familiarity with blockchain technologies and smart contract development in solving blockchain challenges effectively.

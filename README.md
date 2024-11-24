# Starknet Context Contract

## Overview
The **Context Contract** is a critical component in the governance system for managing **Calimero contexts**. It facilitates the creation and management of contexts, user roles, and privileges. The contract integrates with the Proxy Contract to enable interaction with other smart contracts, wallets, adjusting its own configuration variables, and creating/updating strong consistency variables within Calimero contexts based on proposal mechanisms. Additionally, the Context Contract is responsible for the deployment and upgrade of Proxy Contracts, automatically deploying them when a new Calimero context is created.

## Features
- **Calimero Context Creation**: Allows users to create new Calimero contexts.
- **Role Management**: Enables adding or editing user privileges within a context.
- **Proxy Contract Deployment and Upgrade**: Automatically deploys Proxy Contracts for new contexts and manages their upgrades.

## Setup Instructions

### Prerequisites
1. Install the required tools using `asdf`. Follow the instructions from the [asdf documentation](https://asdf-vm.com/) to install `asdf` and its plugins.
2. Add the following dependencies using `asdf`:
   - `scarb`
   - `starknet-devnet`
   - `starknet-foundry`
3. Current Dependecies Versions:
   ```
   scarb - 2.8.4
   starknet-devnet - 0.2.0-rc.3
   starknet-foundry - 0.31.0
   ```

### Note
Currently devnet enviroment is setup with seed value of 12344, variables such as wallets, address etc. are placed in tests counting on that seed value

4. Start the `starknet-devnet` environment:

   ```bash
   starknet-devnet --seed 12344
   ```

### Declaring Contract
1. Declare the Context Contract:
   ```bash
   sncast --account devnet declare --url http://127.0.0.1:5050/rpc --fee-token strk --contract-name ContextConfig
   ```

### Deploying Contract
1. Deploy the Context Contract with the owner's wallet address as constructor calldata:
   ```bash
   sncast --account devnet deploy --url http://127.0.0.1:5050/rpc --fee-token strk --class-hash <context-class-hash> --constructor-calldata <owner-address>
   ```

### Note
Before linking with the Proxy Contract, Proxy contract must be declared. For detailed instructions, refer to the [Proxy Contract repository](https://github.com/calimero-network/starknet-proxy-contract).

### Linking with Proxy Contract
1. Set the Proxy Contract's class hash and the STRK token address in the Context Contract:
   ```bash
   sncast --account devnet invoke --url http://127.0.0.1:5050/rpc --fee-token strk --contract-address <context-address> --function set_proxy_contract_class_hash --calldata <proxy-class-hash> <strk-token-address>
   ```

## Testing Instructions

### Running Tests
1. Start the `starknet-devnet` environment:
   ```bash
   starknet-devnet --seed 12344
   ```
2. Declare and deploy the Context Contract as described in the setup steps.
3. Run the tests:
   ```bash
   snforge test
   ```

### Test Coverage
Tests are located in the `tests/test_contract.cairo` file and cover:
- Creation of the Context Contract.
- Creation of Calimero contexts.
- User management and privilege management within contexts.
- Deployment and upgrade of Proxy Contracts.

### Notes
- User keys and necessary data are retrieved from the `starknet-devnet` environment.
- Ensure all dependencies and the devnet environment are properly configured before running the tests.

## Example Addresses
- **STRK Token Address (Devnet)**: `0x04718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D`
- **Proxy Contract Example Class Hash**: Replace `<proxy-class-hash>` with the declared Proxy Contract class hash.

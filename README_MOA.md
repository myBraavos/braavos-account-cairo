# Braavos Multi Owner Account Contract v1.0.0

#### Class Hash

`0x041bf1e71792aecb9df3e9d04e1540091c5e13122a731e02bec588f71dc1a5c3`

## Architecture

The Multi Owner Account (henceforth, MOA) harnesses Starknet's built-in Account Abstraction (AA) to enable
a Multisig that each signer, or more correctly, owner, experience as if it was a native personal Account, namely:
- The MOA pays for its own gas. Owners are not burdened with signing and execution gas fees as they invoke transactions
directly on the MOA and not via a dApp as if it was their own native account
- The MOA can seamlessly connect and interact with dApps with no need for plugins as it is a native Account on its own.
- The MOA dynamically uses the current owner's personal account signer to approve transactions via `is_valid_signature` standard account entrypoint

An important security benefit of this approach is that each signer signs with his own Account signer, so if
all owners in a MOA have Braavos Hardware Signer (HWS) enabled, that MOA will provide an unprecedented level
of security as each Hardware Signer in its own is a 2FA.

### Deployment

Multi owner accounts (MOA) are expected to be deployed via the deploy syscall, e.g. via UDC. Therefore,
the implementation's __validate_deploy__ panics.

Deployment params:
1. `signers: Array<(ContractAddress, felt252)>` - the array of account addresses and public keys that correspond to signers
2. `threshold: usize` - multi signature threshold



### Signers (`src/signers/`)

The MOA is built upon the infrastructure of the Braavos Account and shares the signer list management logic with it.
An external owner is comprised of 2 parameters:
- `address` - The owner's Account Address
- `public_key` - The owner's stark public key (The native public key in Starknet)

#### Signature Format

The signature format is as follows:
```[ signer #1 sig, signer #2 sig, signer #3 sig, ... ]```

Where each instance of a _signer sig_ is:
```[ signature type, address, public key, r, s, external signature length, external signature, ... ]```

- `signature type` - currently must be `0`
- `address` - owner's account address
- `public key` - owner's stark public key
- `r, s` - the `preamble` - owner's stark signature on a `MOA.signature_preamble_hash` message
- `external signature length` - length in felts of the external signature which follows
- `external signature` - the custom external signature which will be approved via the owner account's `is_valid_signature` entrypoint. For example, this could be a Braavos HWS signature if owner is a Braavos account.

#### Transaction Signing Process

The transaction signing process is comprised of three steps:
- A transaction is _proposed_ by one of the account's owners. We call this account the _proposer_
- Verifying signatures are being sent by other account owners. We call these accounts the _verifiers_
- Once the _threshold_ is reached by a _verifier_ account the pending transaction is executed

Several important notes concerning the signing process:
- The _proposer_ must sign the new transaction's hash
- The _proposer_ may append additional signatures, but in this scenario the transaction must execute and not left pending meaning the number of attached signatures must amount to the MOA threshold
- The _proposer_ must prefix the list of calls with a special call to the entrypoint `assert_max_fee` which accepts 4 parameters which set fee limits:
    - `expected_max_fee_in_eth` - upper limit on the max fee when executing the transaction as a V1 transaction
    - `expected_max_fee_in_stark` - upper limit on the max fee when executing the transaction as a V3 transaction
    - `signer_max_fee_in_eth` - upper limit on max fee when signing a pending V1 transaction
    - `expected_max_fee_in_stark` - upper limit on max fee when signing a pending V3 transaction
- To verify a transaction, a _verifier_ must call the entrypoint `sign_pending_multisig_transaction`, with the identifier of the _proposer_, the nonce of the pending transaction and list of proposed calls. This transaction must adhere to fee limitations set in `assert_max_fee`
- There must be only one pending transaction at a given moment

#### Hash Format

A MOA transaction hash is calculated based on the message hashing defined in [SNIP-12](https://github.com/starknet-io/SNIPs/blob/main/SNIPS/snip-12.md). The message has the following parameters:
- Domain name is set to `MOA.transaction_hash`
- Version is set to `1`
- Message struct to hash is `MOATransaction` and has the following list of properties:
    - Proposer Guid - the unique identifier of the signer
    - Nonce - nonce of the pending transaction
    - Calls - list of calls based on the corelib `Call` struct
    - Num Signers - The number of signers in a specific approval - currently can be either 1 or enough signers to execute the transaction

In addition, we define the Signature preamble hash to be signed in the owner's signature preamble as the following SNIP-12 compatible message:
- Domain name is set to `MOA.signature_preamble_hash`
- Version is set to `1`
- Message struct to hash is 'MOASignaturePreambleHash` and has the following list of properties:
    - Moa Transaction Hash - The `MOATransaction` hash as defined above
    - External Signature - The owner's external signature to be verified with his account's `is_valid_signature`


### Transactions (`src/transactions/`)
Several limitations are imposed on pending transactions:
- There may only be one transaction at a given moment
- Account owners may override existing pending transactions with a new one
- There is a daily limit on the amount of signatures an account owner may send
- Fee of transactions sent be _verifiers_ are limited by the value set in `assert_max_fee`, however this value cannot be greater than `0.03 ETH` or `30 STRK`

## Building and Testing

### Build

This repo is built using [Scarb v2.5.1](https://docs.swmansion.com/scarb/). After installation, run:
> scarb build

### Tests

Prerequisites:
1. Install Python requirements
> pip install -r requirements.txt
2. Setup [starknet-devnet-rs](https://github.com/0xSpaceShard/starknet-devnet-rs)
3. Define `STARKNET_DEVNET` env variable to point to `starknet-devnet-rs` executable

To run tests:
>
> pytest

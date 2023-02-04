# Braavos Account Contract

## MAINNET ALPHA DISCLAIMER

The Braavos Account is in alpha stage, as well as the StarkNet network itself.

Things can break and in extreme cases can lead to loss of funds. The contract code have
not yet been audited, the wallet code as well as the contracts themselves can be upgraded
without a timelock.

## Design

The Braavos account contract is comprised of 3 main modules:

1. Basic account functionality - validation and execution of Multicall based on
   OpenZeppelin's implementation. Can be found under `src/account`.
2. Signer management - adding / removing of additional signers, namely the secp256r1-based
   Hardware Signer. Can be found under `src/signers`
3. Multisig - implementation of M of N signers for transaction execution. Currently
   supports 2 of 2. Can be found under `src/multisig`

This account contract is intended to be used as an implementation of a Proxy contract.
We've used OpenZeppelin's Proxy implementation for this purpose.

### Signer Management

When adding an additional signer, a _Hardware Signer_ or _Protected Signer_, the basic
seed-based signer cannot sign transactions anymore besides a request to remove the
additional signer and revert back to seed-based signer. The request is time-delayed
(currently for 4 days).

### Multisig

The account can be moved into Multisig mode (currently supports 2 of 2) and it will not
execute any transaction before the 2 signers defined in the account sign the transaction.
The seed can request to disable multisig with a time-delay (currently 4 days). 

## Building

### Account Contract

> nile compile --directory src/account

### Proxy Contract

> nile compile --directory lib/openzeppelin/upgrades/

## Testing

### Running End-to-End tests

> pytest -n auto tests/

## Credits
1. Thanks to the OpenZeppelin team for providing reference implementations for both the basic account functionality and the Proxy pattern at https://github.com/OpenZeppelin/cairo-contracts
2. Thanks to EulerSmile for providing the reference `secp256k1` implementation - https://github.com/EulerSmile/common-ec-cairo
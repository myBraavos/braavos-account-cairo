# Braavos Account Contract v1.0.0

For the Braavos Multi Owner Account (MOA) please refer to [README_MOA.md](./README_MOA.md)

#### Class Hashes
*Braavos Account* - `0x00816dd0297efc55dc1e7559020a3a825e81ef734b558f03c83325d4da7e6253`

*Braavos Base Account* - `0x013bfe114fb1cf405bfc3a7f8dbe2d91db146c17521d40dcf57e16d6b59fa8e6`

## Architecture

### Deployment

Braavos account deployment enables account addresses to be dependent only on the Stark public key while still supporting additional initialization parameters and using the most up-to-date
account implementation class hash. This is achieved by:

1. Having a base implementation class hash that rarely changes (`src/presets/braavos_base_account.cairo`). Account deployments should always use this class hash.
2. Send additional initialization parameters via the deployment signature instead of constructor params.
3. Additional initialization parameters are signed and verified in the base implementation (see `assert_valid_deploy_base`).
4. After validation, the base implementation replaces the underlying implementation to the latest one via a `replace_class_syscall` (`src/presets/braavos_account.cairo`) and the actual implementation initializer is called.

NOTE: The actual account implementation is not expected to be directly deployed and therefore its constructor panics.

### Signers (`src/signers/`)

The Braavos account supports 3 different types of signers:

1. _Stark Signer_ - the native signer based on the Stark friendly curve.
2. _Hardware Signer_ - Uses the physical device secure enclave to sign - based on the secp256r1 curve.
3. _Webauthn Signer_ - Uses the physical device [Webauthn protocol](https://w3.org/TR/webauthn/) (aka Passkeys) implementation to sign - also based on the secp256r1 curve with a webauthn compatible signature format.

The native Stark signer is added by default on account deployment and is usually derived from the seed phrase.

The _Hardware Signer_ and _Webauthn Signer_  are considered to be _Strong Signers_ as they facilitate 2FA.
When a _Strong Signer_ is added to the account the default _Stark Signer_ is disabled and not allowed to issue transactions. Only a _Strong Signer_ can.

Note that an account can have both _Hardware Signer_ and _Webauthn Signer_ defined, in which case, any of them can sign as a 'Strong Signer' in the account.

#### Multisig

In addition, a multisig threshold can be enabled and support _m-of-n_ signer threshold in order to execute a transaction.
When an account have both _Hardware signer_ and _Webauthn signer_ defined, then both of them MUST be present in the multisig.

#### Deferred Removal of _Strong Signers_ and _Multisig_

When there is a _Strong Signer_ defined in the account, the _Stark Signer_ role is reduced to removing all _Strong Signers_ and _Multisig_ with a time lock.
The purpose of this mechanism is to allow the user to recover access to his account even if he lost access to the device containing his _Strong Signer_.
The time-lock guarantees that the user have ample time to respond in case his seed phrase was stolen and an attacker tries to remove _Strong Signer_ protection
and take over the account.

The default time lock is defined to be 4 days.

#### Signature Format

The signature format is as follows:
```[ signer #1 sig #1, signer #2 sig, signer #3 sig, ... ]```

Where each instance of a _signer sig_ is:
```[ signer type, signer pub key, ...actual signature fields]```

Some important details to note here:

1. We send the `signer pub key` since each signer is saved in the account as a single `felt252` - _guid_. When verifying a signature, the _guid_ is
calculated from the public key and we verify that it matches one of the guids that are saved in the account.
For the _Hardware Signer_ and _Webauthn Signer_ the guid is `poseidon(secp256r1 pub key)`
2. `Signer type` indicates in which signer list we should look for the computed _guid_. The applicable types are:
_Stark Signer_: *1*, _Hardware Signer_: *2*, _Webauthn Signer_: *5*

3. Since currently only the default _Stark Signer_ is supported, when sending a Stark signature there is no need to send the `pub key` together with the signature. In this scenario there are 2 possible formats:
    - The native `(r, s)` format for compatibility with tooling and SDKs
    - ```[ signer type (==1), r, s]```

4. More than one signer can be sent in the signature array to allow for `m-of-n` signers in _Multisig_ mode.

### Daily Withdrawal Limit (`src/dwl/`)

The Daily Withdrawal Limit is a feature that allows relaxation of _Strong Signer_ and _Multisig_ requirements
for certain types of transactions. All applicable transactions are analyzed for their value (actual token value + gas) and are accumulated per calendar day. While the
accumulated amount is under a certain threshold, a weaker signer can be used to validate enabling lower fees and simpler User Experience for lower value transactions.

The Withdrawal Limit thresholds are set in USDC. For example, to set a low withdrawal limit of 100$, withdrawal limit should be set to `100 * 10**6`. We use
MySwap-CL's TWAP pricing to determine the value of an applicable transaction in USDC terms.

Applicable transactions are either `transfer` or `approve` transactions on the most commonly used tokens (ETH, USDC, USDT, DAI, WBTC) or a whitelisted set of protocol entrypoints.
This whitelist for both tokens and contract entrypoints  can be configured manually using the `update_rate_config` entrypoint

Two thresholds can be set as part of the daily withdrawal limit:

1. Low Limit - controls under which accumulated daily transaction value the _Stark Signer_ can sign even if there are _Strong Signers_ or _Multisig_ defined in the account.
2. High Limit - Defines under which accumulated daily transaction value a _Strong Signer_ can be used even if _Multisig_ is defined

When a transaction is validated without utilizing the Daily Withdrawal Limit's use of a weaker signer,
i.e. using  _Strong Signer_ even though Daily Withdrawal Limit allows usage of _Stark Signer_ for that  transaction
then the transaction value is not accumulated towards the Withdraw Limit.

### Outside Execution (`src/outside_execution/`)
This feature is intended to allow different protocols to submit transactions on behalf of the user, given the user had signed the appropriate transactions beforehand. This contract implements [SNIP-9 version 2](https://github.com/starknet-io/SNIPs/blob/main/SNIPS/snip-9.md).

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

## Acknowledgements
- This project utilizes 2 separate implementations of SHA256 for pre/post regenesis support:
    - Cairo 0 implementation (as a library call) by the Cartridge team: [cairo-sha256](https://github.com/cartridge-gg/cairo-sha256)
    - Cairo implementation from the [Alexandria](https://github.com/keep-starknet-strange/alexandria) project


# [0.1.0](https://github.com/myBraavos/braavos-account-cairo/compare/v0.0.9...v0.1.0) (2023-04-11)


### Bug Fixes

* allow cancel_deferred_remove_signer_req -> set_multisig multicall ([da42ba6](https://github.com/myBraavos/braavos-account-cairo/commit/da42ba65272f0c920efbd32865c754c2b709abb4))
* remove deprecated signer type 3 (SWS) and migrate existing testnet accounts ([d1f2523](https://github.com/myBraavos/braavos-account-cairo/commit/d1f25239cda0f7874c24e9f09563f8b2b111ece6))


### Features

* use efficient-secp256r1 lib ([c380aec](https://github.com/myBraavos/braavos-account-cairo/commit/c380aecc72bae1bc394f68dc9f71f40240b2352d))

## [0.0.9](https://github.com/myBraavos/braavos-account-cairo/compare/v0.0.8...v0.0.9) (2023-02-18)


### Bug Fixes

* allow seed signer to initiate or sign a pending swap_signers in multisig mode ([dabec5c](https://github.com/myBraavos/braavos-account-cairo/commit/dabec5ce1d4a3a0ba41a6b6146717b5175206ca6))
* est fee passes validation by default - client side should account for sig validation gas ([9966a25](https://github.com/myBraavos/braavos-account-cairo/commit/9966a253a5765086351276be2e4d872997624c17))

## [0.0.8](https://github.com/myBraavos/braavos-account-cairo/compare/v0.0.7...v0.0.8) (2023-02-08)


### Bug Fixes

* disable multisig after remove signer with etd expires ([d131587](https://github.com/myBraavos/braavos-account-cairo/commit/d13158768b718c3262393f39d559538363aab689))

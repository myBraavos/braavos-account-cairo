use starknet::ClassHash;
use starknet::ContractAddress;
use starknet::account::Call;

use braavos_account::signers::signers::{Secp256r1PubKey, SignerType, StarkPubKey};

const ISRC6_ID: felt252 = 0x2ceccef7f994940b3962a6c67e0ba4fcd37df7d131417c604f91e03caecc1cd;
const IACCOUNT_ID_LEGACY_OZ_1: felt252 = 0xf10dbd44;
const IACCOUNT_ID_LEGACY_OZ_2: felt252 = 0xa66bd575;

#[derive(Copy, Drop, PartialEq, Serde)]
enum RequiredSigner {
    #[default]
    NA,
    Stark,
    Strong,
    Multisig,
}

/// AdditionalDeploymentParams represents deployment parameters that should not participate
/// in address computation
/// @param account_implementation - chash of the account we're deploying
/// @param signer_type - type of strong signer which can be added during init
/// @param secp256r1_signer - pub key of the strong signer
/// @param multisig_threshold - requested multisig threshold
/// @param withdrawal_limit_low
/// @param fee_rate - if dwl limit is set, eth fee rate must be attached
/// @param stark_fee_rate - if dwl limit is set, stark fee rate must be attached
/// @param chain_id - the chain id for deployment
/// @param deployment_params_signature - The stark sig on the poseidon hash over all members
#[derive(Copy, Drop, Serde)]
struct AdditionalDeploymentParams {
    account_implementation: ClassHash,
    signer_type: SignerType,
    secp256r1_signer: Secp256r1PubKey,
    multisig_threshold: usize,
    withdrawal_limit_low: u128,
    fee_rate: u128,
    stark_fee_rate: u128,
    chain_id: felt252,
    deployment_params_signature: (felt252, felt252),
}

#[starknet::interface]
trait IBraavosAccount<TState> {
    // ISRC6
    fn __validate__(ref self: TState, calls: Span<Call>) -> felt252;
    fn __execute__(ref self: TState, calls: Span<Call>) -> Array<Span<felt252>>;
    fn is_valid_signature(self: @TState, hash: felt252, signature: Span<felt252>) -> felt252;

    // Declare / Deploy validation
    fn __validate_deploy__(
        self: @TState, class_hash: felt252, salt: felt252, stark_pub_key: StarkPubKey,
    ) -> felt252;
    fn __validate_declare__(self: @TState, class_hash: felt252) -> felt252;

    // Initializer from BraavosBaseAccount
    fn initializer(ref self: TState, stark_pub_key: StarkPubKey) -> ();

    // Initializer from Braavos Account Factory
    fn initializer_from_factory(
        ref self: TState, stark_pub_key: StarkPubKey, deployment_params: AdditionalDeploymentParams
    );

    fn get_required_signer(
        ref self: TState, calls: Span<Call>, fee_amount: u128, tx_version: felt252
    ) -> RequiredSigner;
}

#[starknet::interface]
trait IBraavosAccountInternal<TState> {
    fn _get_signer_type_in_account(self: @TState) -> RequiredSigner;
    fn _is_valid_signature_common(
        self: @TState,
        hash: felt252,
        signature: Span<felt252>,
        block_timestamp: u64,
        transaction_ver: felt252,
    ) -> felt252;
}


#[starknet::interface]
trait IBraavosMOA<TState> {
    // ISRC6
    fn __validate__(ref self: TState, calls: Span<Call>) -> felt252;
    fn __execute__(ref self: TState, calls: Span<Call>) -> Array<Span<felt252>>;
    fn is_valid_signature(self: @TState, hash: felt252, signature: Span<felt252>) -> felt252;

    // Declare / Deploy validation
    fn __validate_deploy__(
        self: @TState, signers: Array<(ContractAddress, felt252)>, threshold: usize
    ) -> felt252;
    fn __validate_declare__(self: @TState, class_hash: felt252) -> felt252;
}

#[starknet::interface]
trait IGetVersion<TState> {
    fn get_version(self: @TState) -> felt252;
}

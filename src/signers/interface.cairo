use starknet::ContractAddress;
use super::signer_management::SignerManagementComponent::{DeferredRemoveSignerRequest};
use super::signer_type::SignerType;
use super::signers::{Secp256r1PubKey, StarkPubKey, MoaSigner};

#[derive(Drop, PartialEq, Serde)]
struct GetSignersResponse {
    stark: Array<felt252>,
    secp256r1: Array<felt252>,
    webauthn: Array<felt252>,
}

#[derive(Drop, starknet::Event)]
struct OwnerAdded {
    #[key]
    new_owner_guid: felt252,
    signer_type: SignerType,
    signer_data: Span<felt252>,
}

#[derive(Drop, starknet::Event)]
struct OwnerRemoved {
    #[key]
    removed_owner_guid: felt252,
    removed_signer_type: SignerType,
}

#[starknet::interface]
trait ISignerManagement<TState> {
    fn get_public_key(self: @TState) -> felt252;
    fn get_signers(self: @TState) -> GetSignersResponse;
    fn add_secp256r1_signer(
        ref self: TState,
        secp256r1_signer: Secp256r1PubKey,
        signer_type: SignerType,
        multisig_threshold: usize
    );
    fn remove_secp256r1_signer(
        ref self: TState, guid: felt252, signer_type: SignerType, multisig_threshold: usize
    );
    fn change_secp256r1_signer(
        ref self: TState,
        secp256r1_signer: Secp256r1PubKey,
        existing_guid: felt252,
        signer_type: SignerType
    );
    fn deferred_remove_signers(ref self: TState);
    fn cancel_deferred_remove_signers(ref self: TState);
    fn get_deferred_remove_signers(self: @TState) -> DeferredRemoveSignerRequest;
    fn set_execution_time_delay(ref self: TState, time_delay: u64);
    fn get_execution_time_delay(self: @TState) -> u64;
}

#[starknet::interface]
trait ISignerManagementInternal<TState> {
    fn _add_stark_signer_unsafe(ref self: TState, stark_pub_key: StarkPubKey,);

    fn _add_secp256r1_signer_unsafe(
        ref self: TState, secp256r1_signer: Secp256r1PubKey, signer_type: SignerType
    );

    fn _handle_deferred_request_when_signer_removal(ref self: TState, expired_etd: bool);

    fn _remove_secp256r1_signer_common_unsafe(
        ref self: TState, expired_etd: bool, existing_guid: felt252, signer_type: SignerType
    );

    fn _remove_all_secp256r1_signers_unsafe(ref self: TState, expired_etd: bool);

    fn _apply_deferred_remove_signers_req(ref self: TState, block_timestamp: u64);
}

#[starknet::interface]
trait IMultisig<TState> {
    fn set_multisig_threshold(ref self: TState, multisig_threshold: usize);
    fn get_multisig_threshold(self: @TState) -> usize;
}

#[starknet::interface]
trait IMultisigInternal<TState> {
    fn _set_multisig_threshold_inner(
        ref self: TState, multisig_threshold: usize, num_signers: usize
    );
}

#[derive(Drop, PartialEq, Serde)]
struct GetMoaSignersResponse {
    moa: Array<felt252>,
}

#[starknet::interface]
trait IMoaSignManagementExternal<TState> {
    fn get_signers(self: @TState) -> GetMoaSignersResponse;
    fn is_signer(self: @TState, signer: MoaSigner) -> bool;
    fn get_signers_len(self: @TState) -> usize;
    fn add_external_signers(
        ref self: TState, signers: Array<(ContractAddress, felt252)>, threshold: usize
    );
    fn remove_external_signers(ref self: TState, signer_guids: Span<felt252>, threshold: usize);
}

#[starknet::interface]
trait IMoaSignManagementInternal<TState> {
    fn _update_threshold(ref self: TState, threshold: usize, num_signers: usize);
    fn _add_signers(ref self: TState, signers: Array<(ContractAddress, felt252)>, threshold: usize);
}

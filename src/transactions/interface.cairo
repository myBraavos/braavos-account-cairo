use braavos_account::signers::signers::{MoaSigner, MoaExtSigner, MoaSignerMethods};
use starknet::account::Call;
use starknet::ContractAddress;

#[derive(Copy, Drop, Serde, starknet::Store)]
struct Transaction {
    pending_tx_hash: felt252,
    confirmations: usize,
}

#[starknet::interface]
trait IPendingTxnExternalTrait<TState> {
    fn get_pending_multisig_transaction(self: @TState) -> Transaction;
    fn sign_pending_multisig_transaction(
        ref self: TState, proposer_guid: felt252, pending_nonce: felt252, calls: Span<Call>
    ) -> Array<Span<felt252>>;
    fn is_confirmed(self: @TState, tx_hash: felt252, signer_guid: felt252) -> bool;
    fn assert_max_fee(
        self: @TState,
        expected_max_fee_in_eth: u128,
        expected_max_fee_in_stark: u128,
        signer_max_fee_in_eth: u128,
        signer_max_fee_in_stark: u128
    );
}

#[starknet::interface]
trait IPendingTxnInternalTrait<TState> {
    fn _assert_new_unique_signers(self: @TState, tx_hash: felt252, signers: Span<MoaExtSigner>);
    fn _apply_confirmations(ref self: TState, confirmations: Array<felt252>);
    fn _execute_transaction(ref self: TState, calls: Span::<Call>) -> Array<Span<felt252>>;
    fn _assert_valid_max_fee(self: @TState, fee_limit_eth: u128, fee_limit_stark: u128);
    fn _confirm_and_execute_if_ready(
        ref self: TState,
        pending_tx_hash: felt252,
        calls: Span<Call>,
        signers_guids: Array<felt252>,
        sign_pending: bool
    ) -> Array<Span<felt252>>;
    fn _get_adjusted_threshold(self: @TState) -> usize;
}

#[starknet::interface]
trait DailyTxnLimitInternalTrait<TState> {
    fn _assert_and_update_daily_txn_limit(ref self: TState, signer_guid: felt252);
}

#[starknet::interface]
trait DailyTxnLimitExternalTrait<TState> {
    fn get_tx_count(self: @TState, signer_guid: felt252, days_since_epoch: u64) -> usize;
}

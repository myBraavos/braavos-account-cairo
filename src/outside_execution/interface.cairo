use starknet::ContractAddress;
use starknet::account::Call;

// IOutsideExecution_V2
// execute_from_outside_v2((ContractAddress,felt252,u64,u64,(@Array<(ContractAddress,felt252,(@Array<felt252>))>)),(@Array<felt252>))->Array<(@Array<felt252>)>
// is_valid_outside_execution_nonce(felt252)->E((),())
const SRC5_OUTSIDE_EXECUTION_V2_INTERFACE_ID: felt252 =
    0x1d1144bb2138366ff28d8e9ab57456b1d332ac42196230c3a602003c89872;

#[derive(Copy, Drop, Serde)]
struct OutsideExecution {
    caller: ContractAddress,
    nonce: felt252,
    execute_after: u64,
    execute_before: u64,
    calls: Span<Call>,
}

#[starknet::interface]
trait IOutsideExecution_V2<TContractState> {
    /// @notice This method allows anyone to submit a transaction on behalf of the account as long
    /// as they have the relevant signatures @param outside_execution The parameters of the
    /// transaction to execute @param signature A valid signature on the ERC-712 message encoding of
    /// `outside_execution`
    /// @notice This method allows reentrancy. A call to `__execute__` or `execute_from_outside` can
    /// trigger another nested transaction to `execute_from_outside`.
    fn execute_from_outside_v2(
        ref self: TContractState, outside_execution: OutsideExecution, signature: Span<felt252>,
    ) -> Array<Span<felt252>>;

    /// Get the status of a given nonce, true if the nonce is available to use
    fn is_valid_outside_execution_nonce(self: @TContractState, nonce: felt252) -> bool;
}

use starknet::account::Call;
use starknet::ContractAddress;
use starknet::TxInfo;


#[derive(Copy, Drop, Serde)]
struct TokenAmount {
    token_address: ContractAddress,
    amount: u256,
}

#[derive(Copy, Drop, Serde)]
struct SessionExecute {
    owner_pub_key: felt252,
    execute_after: u64,
    execute_before: u64,
    allowed_method_guids: Span<felt252>,
    v3_gas_limit: u128,
    spending_limits: Span<TokenAmount>,
}

#[derive(Copy, Drop, Serde)]
struct SessionExecuteV2 {
    owner_pub_key: felt252,
    execute_after: u64,
    execute_before: u64,
    allowed_method_guids: Span<felt252>,
    v3_gas_limit: u128,
    spending_limits: Span<TokenAmount>,
    allowed_method_calldata_validations: Span<CalldataValidationSpan>,
}

#[derive(Copy, Drop, Serde)]
struct SessionExecuteRequest {
    session_request: SessionExecute,
    call_hints: Span<u32>,
    session_request_signature: Span<felt252>,
}

#[derive(Copy, Drop, Serde)]
struct SessionExecuteRequestV2 {
    session_request: SessionExecuteV2,
    call_hints: Span<u32>,
    session_request_signature: Span<felt252>,
}

#[derive(Copy, Drop, Serde)]
struct GasSponsoredSessionExecutionRequest {
    execute_after: u64,
    execute_before: u64,
    allowed_method_guids: Span<felt252>,
    spending_limits: Span<TokenAmount>,
    calls: Span<Call>,
    call_hints: Span<u32>,
}

#[derive(Copy, Drop, Serde)]
struct GasSponsoredSessionExecutionRequestV2 {
    execute_after: u64,
    execute_before: u64,
    allowed_method_guids: Span<felt252>,
    spending_limits: Span<TokenAmount>,
    allowed_method_calldata_validations: Span<CalldataValidationSpan>,
    calls: Span<Call>,
    call_hints: Span<u32>,
}

#[derive(Copy, Drop, Serde)]
struct CalldataValidation {
    offset: u32,
    value: felt252,
    validation_type: CalldataValidationType,
}

#[derive(Copy, Drop, PartialEq, Serde)]
enum CalldataValidationType {
    #[default]
    Eq,
}

impl CalldataValidationTypeIntoFelt252 of Into<CalldataValidationType, felt252> {
    fn into(self: CalldataValidationType) -> felt252 {
        match self {
            CalldataValidationType::Eq(_) => 0,
            _ => 10001,
        }
    }
}

type CalldataValidationSpan = Span<CalldataValidation>;

#[starknet::interface]
trait ISessionExecute<TContractState> {
    fn session_execute(self: @TContractState, session_execute_request: SessionExecuteRequest);
    fn session_execute_v2(self: @TContractState, session_execute_request: SessionExecuteRequestV2);
}

#[starknet::interface]
trait ISessionExecuteInternal<TContractState> {
    fn _validate_session_execute(
        ref self: TContractState, tx_info: TxInfo, timestamp: u64, calls: Span<Call>,
    ) -> felt252;
    fn _execute_session_calls(ref self: TContractState, calls: Span<Call>) -> Array<Span<felt252>>;
}

#[starknet::interface]
trait ISessionManagement<TContractState> {
    fn revoke_session(ref self: TContractState, session_hash: felt252);
    fn is_session_revoked(self: @TContractState, session_hash: felt252) -> bool;
    fn get_spending_limit_amount_spent(
        self: @TContractState, session_hash: felt252, token_address: ContractAddress
    ) -> u256;
    fn is_session_validated(self: @TContractState, session_hash: felt252) -> bool;
    fn get_session_gas_spent(self: @TContractState, session_hash: felt252) -> u128;
}

#[starknet::interface]
trait ISessionHelper<TContractState> {
    fn _validate_spending_limits(
        ref self: TContractState,
        session_hash: felt252,
        calls: Span<Call>,
        spending_limits: Span<TokenAmount>,
    );

    fn _validate_gas_spending(
        ref self: TContractState, session_hash: felt252, fee: u128, request_gas_limit: u128
    );
    fn _cache_session(ref self: TContractState, session_hash: felt252);
    fn _get_signer_state_hash(self: @TContractState) -> felt252;
}

#[derive(Drop, starknet::Event)]
struct GasSponsoredSessionStarted {
    #[key]
    session_hash: felt252,
    caller: ContractAddress,
    execute_after: u64,
    execute_before: u64,
    tx_hash: felt252,
}

#[derive(Drop, starknet::Event)]
struct SessionStarted {
    #[key]
    session_hash: felt252,
    owner_pub_key: felt252,
    execute_after: u64,
    execute_before: u64,
    tx_hash: felt252,
    v3_gas_limit: u128,
}

#[derive(Drop, starknet::Event)]
struct SessionRevoked {
    #[key]
    session_hash: felt252,
}

#[starknet::interface]
trait IGasSponsoredSessionExecute<TContractState> {
    fn execute_gas_sponsored_session_tx(
        ref self: TContractState,
        gas_sponsored_session_request: GasSponsoredSessionExecutionRequest,
        signature: Span<felt252>
    ) -> Array<Span<felt252>>;

    fn execute_gas_sponsored_session_tx_v2(
        ref self: TContractState,
        gas_sponsored_session_request: GasSponsoredSessionExecutionRequestV2,
        signature: Span<felt252>,
    ) -> Array<Span<felt252>>;
}

#[starknet::interface]
trait IGasSponsoredSessionExecuteInternal<TContractState> {
    fn _execute_gas_sponsored_session_tx_internal(
        ref self: TContractState,
        gas_sponsored_session_request: GasSponsoredSessionExecutionRequestV2,
        signature: Span<felt252>,
        session_key_version: SessionKeyVersion,
    ) -> Array<Span<felt252>>;
}

#[derive(Copy, Drop, PartialEq, Serde)]
enum SessionKeyVersion {
    V1,
    V2,
}

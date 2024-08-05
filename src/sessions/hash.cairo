use braavos_account::utils::snip12::{calculate_snip12_hash, hash_call};
use braavos_account::sessions::interface::{
    SessionExecute, GasSponsoredSessionExecutionRequest, TokenAmount
};
use poseidon::poseidon_hash_span;
use starknet::ContractAddress;

const U256_TYPE_HASH: felt252 = selector!("\"u256\"(\"low\":\"u128\",\"high\":\"u128\")");

const ALLOWED_METHOD_TYPE_HASH: felt252 =
    selector!(
        "\"AllowedMethod\"(\"Contract Address\":\"ContractAddress\",\"Selector\":\"selector\")"
    );

const TOKEN_AMOUNT_TYPE_HASH: felt252 =
    selector!(
        "\"TokenAmount\"(\"token_address\":\"ContractAddress\",\"amount\":\"u256\")\"u256\"(\"low\":\"u128\",\"high\":\"u128\")"
    );

const GAS_SPONSORED_SESSION_EXECUTION_TYPE_HASH: felt252 =
    selector!(
        "\"GasSponsoredSessionExecution\"(\"Caller\":\"ContractAddress\",\"Execute After\":\"timestamp\",\"Execute Before\":\"timestamp\",\"Allowed Methods\":\"AllowedMethod*\",\"Spending Limits\":\"TokenAmount*\")\"AllowedMethod\"(\"Contract Address\":\"ContractAddress\",\"Selector\":\"selector\")\"TokenAmount\"(\"token_address\":\"ContractAddress\",\"amount\":\"u256\")\"u256\"(\"low\":\"u128\",\"high\":\"u128\")"
    );

const SESSION_EXECUTION_TYPE_HASH: felt252 =
    selector!(
        "\"SessionExecution\"(\"Owner Public Key\":\"felt\",\"Execute After\":\"timestamp\",\"Execute Before\":\"timestamp\",\"STRK Gas Limit\":\"u128\",\"Allowed Methods\":\"AllowedMethod*\",\"Spending Limits\":\"TokenAmount*\")\"AllowedMethod\"(\"Contract Address\":\"ContractAddress\",\"Selector\":\"selector\")\"TokenAmount\"(\"token_address\":\"ContractAddress\",\"amount\":\"u256\")\"u256\"(\"low\":\"u128\",\"high\":\"u128\")"
    );

fn calculate_gas_sponsored_session_execution_hash(
    gas_sponsored_execution: @GasSponsoredSessionExecutionRequest, caller: ContractAddress
) -> felt252 {
    calculate_snip12_hash(
        'Account.execute_gs_session',
        2,
        hash_gas_sponsored_session_execution(gas_sponsored_execution, caller)
    )
}

fn hash_gas_sponsored_session_execution(
    execution: @GasSponsoredSessionExecutionRequest, caller: ContractAddress
) -> felt252 {
    poseidon_hash_span(
        array![
            GAS_SPONSORED_SESSION_EXECUTION_TYPE_HASH,
            (caller).into(),
            (*execution.execute_after).into(),
            (*execution.execute_before).into(),
            hash_allowed_methods_guids(*execution.allowed_method_guids),
            hash_spending_limits(*execution.spending_limits),
        ]
            .span()
    )
}


fn calculate_session_execute_hash(session_execute_request: @SessionExecute) -> felt252 {
    calculate_snip12_hash(
        'Account.execute_session', 2, hash_session_execute(session_execute_request)
    )
}

fn hash_session_execute(request: @SessionExecute) -> felt252 {
    poseidon_hash_span(
        array![
            SESSION_EXECUTION_TYPE_HASH,
            *request.owner_pub_key,
            (*request.execute_after).into(),
            (*request.execute_before).into(),
            (*request.v3_gas_limit).into(),
            hash_allowed_methods_guids(*request.allowed_method_guids),
            hash_spending_limits(*request.spending_limits),
        ]
            .span()
    )
}

fn hash_allowed_methods_guids(mut allowed_methods_guids: Span<felt252>) -> felt252 {
    poseidon_hash_span(allowed_methods_guids)
}

fn hash_spending_limits(mut spending_limits: Span<TokenAmount>) -> felt252 {
    let mut hashed_token_amounts: Array<felt252> = array![];

    loop {
        match spending_limits.pop_front() {
            Option::Some(spending_limit) => {
                hashed_token_amounts.append(hash_token_amount(spending_limit));
            },
            Option::None(_) => { break; },
        };
    };
    poseidon_hash_span(hashed_token_amounts.span())
}

#[inline(always)]
fn hash_token_amount(token_amount: @TokenAmount) -> felt252 {
    poseidon_hash_span(
        array![
            TOKEN_AMOUNT_TYPE_HASH,
            (*token_amount.token_address).into(),
            hash_u256(*token_amount.amount)
        ]
            .span()
    )
}

#[inline(always)]
fn hash_allowed_method(to: ContractAddress, selector: felt252) -> felt252 {
    poseidon_hash_span(array![ALLOWED_METHOD_TYPE_HASH, to.into(), selector].span())
}

#[inline(always)]
fn hash_u256(amount: u256) -> felt252 {
    poseidon_hash_span(array![U256_TYPE_HASH, amount.low.into(), amount.high.into()].span())
}


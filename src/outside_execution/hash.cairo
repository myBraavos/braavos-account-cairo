use braavos_account::outside_execution::interface::OutsideExecution;
use braavos_account::utils::snip12::{calculate_snip12_hash, hash_call};
use poseidon::poseidon_hash_span;

const OUTSIDE_EXECUTION_TYPE_HASH: felt252 = selector!(
    "\"OutsideExecution\"(\"Caller\":\"ContractAddress\",\"Nonce\":\"felt\",\"Execute After\":\"u128\",\"Execute Before\":\"u128\",\"Calls\":\"Call*\")\"Call\"(\"To\":\"ContractAddress\",\"Selector\":\"selector\",\"Calldata\":\"felt*\")",
);


fn calculate_outside_execution_hash(outside_execution: @OutsideExecution) -> felt252 {
    calculate_snip12_hash(
        'Account.execute_from_outside', 2, hash_outside_execution(outside_execution),
    )
}

fn hash_outside_execution(outside_execution: @OutsideExecution) -> felt252 {
    let mut calls_span = *outside_execution.calls;
    let mut hashed_calls: Array<felt252> = array![];

    loop {
        match calls_span.pop_front() {
            Option::Some(call) => { hashed_calls.append(hash_call(call)); },
            Option::None(_) => { break; },
        };
    }
    poseidon_hash_span(
        array![
            OUTSIDE_EXECUTION_TYPE_HASH,
            (*outside_execution.caller).into(),
            *outside_execution.nonce,
            (*outside_execution.execute_after).into(),
            (*outside_execution.execute_before).into(),
            poseidon_hash_span(hashed_calls.span()),
        ]
            .span(),
    )
}

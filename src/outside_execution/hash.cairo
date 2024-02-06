use braavos_account::outside_execution::interface::OutsideExecution;
use starknet::{ContractAddress, get_tx_info, get_contract_address, account::Call};
use poseidon::poseidon_hash_span;

const STARKNET_DOMAIN_TYPE_HASH: felt252 =
    selector!(
        "\"StarknetDomain\"(\"name\":\"shortstring\",\"version\":\"shortstring\",\"chainId\":\"shortstring\",\"revision\":\"shortstring\")"
    );

const OUTSIDE_EXECUTION_TYPE_HASH: felt252 =
    selector!(
        "\"OutsideExecution\"(\"Caller\":\"ContractAddress\",\"Nonce\":\"felt\",\"Execute After\":\"u128\",\"Execute Before\":\"u128\",\"Calls\":\"Call*\")\"Call\"(\"To\":\"ContractAddress\",\"Selector\":\"selector\",\"Calldata\":\"felt*\")"
    );

const CALL_TYPE_HASH: felt252 =
    selector!(
        "\"Call\"(\"To\":\"ContractAddress\",\"Selector\":\"selector\",\"Calldata\":\"felt*\")"
    );


fn calculate_outside_execution_hash(outside_execution: @OutsideExecution) -> felt252 {
    poseidon_hash_span(
        array![
            'StarkNet Message',
            hash_domain(),
            get_contract_address().into(),
            hash_outside_execution(outside_execution)
        ]
            .span()
    )
}

#[inline(always)]
fn hash_domain() -> felt252 {
    poseidon_hash_span(
        array![
            STARKNET_DOMAIN_TYPE_HASH,
            'Account.execute_from_outside',
            2,
            get_tx_info().unbox().chain_id,
            1
        ]
            .span()
    )
}

fn hash_outside_call(outside_call: @Call) -> felt252 {
    poseidon_hash_span(
        array![
            CALL_TYPE_HASH,
            (*outside_call.to).into(),
            *outside_call.selector,
            poseidon_hash_span(*outside_call.calldata)
        ]
            .span()
    )
}

fn hash_outside_execution(outside_execution: @OutsideExecution) -> felt252 {
    let mut calls_span = *outside_execution.calls;
    let mut hashed_calls: Array<felt252> = array![];

    loop {
        match calls_span.pop_front() {
            Option::Some(call) => { hashed_calls.append(hash_outside_call(call)); },
            Option::None(_) => { break; },
        };
    };
    poseidon_hash_span(
        array![
            OUTSIDE_EXECUTION_TYPE_HASH,
            (*outside_execution.caller).into(),
            *outside_execution.nonce,
            (*outside_execution.execute_after).into(),
            (*outside_execution.execute_before).into(),
            poseidon_hash_span(hashed_calls.span())
        ]
            .span()
    )
}

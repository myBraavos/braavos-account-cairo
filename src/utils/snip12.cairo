use starknet::{ContractAddress, get_tx_info, get_contract_address, account::Call};
use poseidon::poseidon_hash_span;

const STARKNET_DOMAIN_TYPE_HASH: felt252 =
    selector!(
        "\"StarknetDomain\"(\"name\":\"shortstring\",\"version\":\"shortstring\",\"chainId\":\"shortstring\",\"revision\":\"shortstring\")"
    );

const CALL_TYPE_HASH: felt252 =
    selector!(
        "\"Call\"(\"To\":\"ContractAddress\",\"Selector\":\"selector\",\"Calldata\":\"felt*\")"
    );


fn calculate_snip12_hash(domain_name: felt252, version: felt252, message_hash: felt252) -> felt252 {
    poseidon_hash_span(
        array![
            'StarkNet Message',
            hash_domain(domain_name, version),
            get_contract_address().into(),
            message_hash
        ]
            .span()
    )
}

#[inline(always)]
fn hash_domain(domain_name: felt252, version: felt252) -> felt252 {
    poseidon_hash_span(
        array![STARKNET_DOMAIN_TYPE_HASH, domain_name, version, get_tx_info().unbox().chain_id, 1]
            .span()
    )
}

fn hash_call(call: @Call) -> felt252 {
    poseidon_hash_span(
        array![
            CALL_TYPE_HASH, (*call.to).into(), *call.selector, poseidon_hash_span(*call.calldata)
        ]
            .span()
    )
}

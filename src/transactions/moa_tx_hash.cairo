use braavos_account::utils::snip12::{calculate_snip12_hash, hash_call};
use poseidon::poseidon_hash_span;
use starknet::account::Call;

const MOA_TX_TYPE_HASH: felt252 = selector!(
    "\"MOATransaction\"(\"Proposer Guid\":\"felt\",\"Nonce\":\"felt\",\"Calls\":\"Call*\",\"Num Signers\":\"u128\")\"Call\"(\"To\":\"ContractAddress\",\"Selector\":\"selector\",\"Calldata\":\"felt*\")",
);

const MOA_SIG_PREAMBLE_TYPE_HASH: felt252 = selector!(
    "\"MOASignaturePreambleHash\"(\"Moa Transaction Hash\":\"felt\",\"External Signature\":\"felt*\")",
);

fn calculate_moa_preamble_hash(moa_tx_hash: felt252, ext_sig: Span<felt252>) -> felt252 {
    calculate_snip12_hash('MOA.signature_preamble_hash', 1, hash_moa_preamble(moa_tx_hash, ext_sig))
}

fn hash_moa_preamble(moa_tx_hash: felt252, ext_sig: Span<felt252>) -> felt252 {
    poseidon_hash_span(
        array![MOA_SIG_PREAMBLE_TYPE_HASH, moa_tx_hash, poseidon_hash_span(ext_sig)].span(),
    )
}

fn calculate_moa_tx_hash(
    proposer_guid: felt252, nonce: felt252, calls: Span<Call>, signers_len: usize,
) -> felt252 {
    calculate_snip12_hash(
        'MOA.transaction_hash', 1, hash_moa_tx(proposer_guid, nonce, calls, signers_len),
    )
}

fn hash_moa_tx(
    proposer_guid: felt252, nonce: felt252, mut calls: Span<Call>, signers_len: usize,
) -> felt252 {
    let mut hashed_calls: Array<felt252> = array![];

    loop {
        match calls.pop_front() {
            Option::Some(call) => { hashed_calls.append(hash_call(call)); },
            Option::None(_) => { break; },
        };
    }
    poseidon_hash_span(
        array![
            MOA_TX_TYPE_HASH,
            proposer_guid,
            nonce,
            poseidon_hash_span(hashed_calls.span()),
            signers_len.into(),
        ]
            .span(),
    )
}

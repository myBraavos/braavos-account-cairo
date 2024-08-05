use core::dict::Felt252DictTrait;
use starknet::account::Call;
use starknet::get_contract_address;
use core::dict::Felt252Dict;
use braavos_account::sessions::hash::hash_allowed_method;


mod Errors {
    const BAD_CALL_HINT: felt252 = 'BAD_CALL_HINT';
    const BAD_CALL: felt252 = 'BAD_CALL';
}

mod Consts {
    const SESSION_EXECUTE_SELECTOR: felt252 = selector!("session_execute");
    const SESSION_REVOKE_SELECTOR: felt252 = selector!("revoke_session");
    const TRANSFER_CALL_SELECTOR: felt252 = selector!("transfer");
    const APPROVE_CALL_SELECTOR: felt252 = selector!("approve");
    const INCREASE_ALLOWANCE_CALL_SELECTOR: felt252 = selector!("increase_allowance");
    const INCREASE_ALLOWANCE_CAMEL_CALL_SELECTOR: felt252 = selector!("increaseAllowance");
}

fn validate_allowed_methods(
    allowed_method_guids: Span<felt252>, calls: Span<Call>, calls_hint: Span<u32>
) {
    assert(calls.len() == calls_hint.len(), Errors::BAD_CALL_HINT);

    let mut index = 0;
    loop {
        if (index >= calls.len()) {
            break;
        }
        let call = calls.at(index);
        let call_index = *calls_hint.at(index);
        assert(
            call_index < allowed_method_guids.len()
                && hash_allowed_method(*call.to, *call.selector) == *allowed_method_guids
                    .at(call_index),
            Errors::BAD_CALL
        );
        index += 1;
    };
}

fn is_session_execute(calls: Span<Call>) -> bool {
    calls.len() > 1
        && *calls.at(0).to == get_contract_address()
        && *calls.at(0).selector == Consts::SESSION_EXECUTE_SELECTOR
}

fn is_erc20_token_removal_call(call: @Call) -> bool {
    (*call.selector == Consts::TRANSFER_CALL_SELECTOR
        || *call.selector == Consts::APPROVE_CALL_SELECTOR
        || *call.selector == Consts::INCREASE_ALLOWANCE_CALL_SELECTOR
        || *call.selector == Consts::INCREASE_ALLOWANCE_CAMEL_CALL_SELECTOR)
        && (*call.calldata).len() == 3
}

fn is_session_revoke_transaction(calls: Span<Call>) -> bool {
    if calls.len() == 1 {
        let call = calls.at(0);
        *call.to == get_contract_address() && *call.selector == Consts::SESSION_REVOKE_SELECTOR
    } else {
        false
    }
}

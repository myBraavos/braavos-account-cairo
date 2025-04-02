use starknet::account::Call;
use starknet::{get_block_timestamp, get_caller_address, get_contract_address};

mod Consts {
    const OUTSIDE_EXECUTION_SELECTOR: felt252 = selector!("execute_from_outside_v2");
    const GAS_SPONSORED_SESSION_EXECUTION_SELECTOR: felt252 = selector!(
        "execute_gas_sponsored_session_tx",
    );
    const GAS_SPONSORED_SESSION_EXECUTION_V2_SELECTOR: felt252 = selector!(
        "execute_gas_sponsored_session_tx_v2",
    );
}

fn assert_self_caller() {
    assert(get_contract_address() == get_caller_address(), 'INVALID_CALLER');
}

fn assert_no_self_calls(mut calls: Span<Call>) {
    let self_address = get_contract_address();
    loop {
        match calls.pop_front() {
            Option::Some(call) => { assert(*call.to != self_address, 'SELF_CALL'); },
            Option::None(_) => { break; },
        };
    };
}

fn is_oe_self_call_selector(selector: felt252) -> bool {
    selector == Consts::OUTSIDE_EXECUTION_SELECTOR
        || selector == Consts::GAS_SPONSORED_SESSION_EXECUTION_SELECTOR
        || selector == Consts::GAS_SPONSORED_SESSION_EXECUTION_V2_SELECTOR
}

fn assert_no_oe_self_calls(mut calls: Span<Call>) {
    let self_address = get_contract_address();
    loop {
        match calls.pop_front() {
            Option::Some(call) => {
                assert(
                    *call.to != self_address || !is_oe_self_call_selector(*call.selector),
                    'SELF_CALL',
                );
            },
            Option::None(_) => { break; },
        };
    };
}

fn assert_timestamp(execute_after: u64, execute_before: u64) -> u64 {
    let timestamp = get_block_timestamp();
    assert_timestamp_2(execute_after, execute_before, timestamp);
    timestamp
}


fn assert_timestamp_2(execute_after: u64, execute_before: u64, timestamp: u64) {
    assert(execute_after < timestamp && timestamp < execute_before, 'INVALID_TIMESTAMP');
}
